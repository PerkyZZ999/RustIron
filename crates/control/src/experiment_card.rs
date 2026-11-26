//! W617 (P22): Controlled Experiment Card evaluator with preregistered
//! meaningful-effect and confidence criteria, randomized repeat verification,
//! correctness/error/resource budgets, honest no-benefit reporting, and hard
//! refusals for invalid comparisons, unsafe private caching, and automatic DB
//! changes. Strictly read-only: evaluates exported trial data and emits a
//! retain/revert evidence artifact.

use rustiron_contracts::escape_human;
use serde_json::{Value, json};
use std::collections::BTreeSet;

/// Output schema for `rustiron-control --evaluate-experiment`.
pub(crate) const SCHEMA: &str = "rustiron-experiment-result/1";
/// Expected input schema for a preregistered experiment card.
pub(crate) const INPUT_SCHEMA: &str = "rustiron-experiment-card/1";

/// Evidence-backed hypothesis categories allowed by P22.
const ALLOWED_CATEGORIES: [&str; 5] = [
    "lscache_invalidation",
    "php_pool",
    "opcache",
    "app_workers",
    "uncached_path",
];

struct ParsedTrial {
    arm: Arm,
    workload_digest: String,
    primary_value: f64,
    http_requests: u64,
    http_errors: u64,
    correctness_passed: bool,
    private_cache_safe: bool,
    peak_rss_mib: f64,
    peak_cpu_percent: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arm {
    Baseline,
    Candidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    LowerIsBetter,
    HigherIsBetter,
}

struct ArmStats {
    n: usize,
    mean: f64,
    median: f64,
    variance: f64,
    stddev: f64,
    total_requests: u64,
    total_errors: u64,
    max_rss_mib: f64,
    max_cpu_percent: f64,
}

/// Evaluates one preregistered Experiment Card JSON document and produces a
/// complete retain/revert evidence report.
pub(crate) fn evaluate(card: &Value) -> Value {
    let card_id = escape_human(card["card_id"].as_str().unwrap_or("unknown"));
    let site_id = escape_human(card["site_id"].as_str().unwrap_or("unknown"));
    let title = escape_human(card["title"].as_str().unwrap_or(""));
    let category_raw = card["change"]["category"].as_str().unwrap_or("");
    let category = escape_human(category_raw);

    // Hard stop 1: automatic database changes are forbidden under P22.
    if card["change"]["automatic_db_change"].as_bool() == Some(true) || is_db_category(category_raw)
    {
        return refused_report(
            &card_id,
            &site_id,
            &title,
            &category,
            "refused_automatic_db_change",
            "revert",
            "Automatic database tuning or schema/engine changes are forbidden by P22.",
        );
    }

    // Hard stop 2: unsafe private/auth/cart/checkout caching is forbidden.
    if card["change"]["caches_private_auth_or_cart"].as_bool() == Some(true)
        || card["change"]["private_cache_leak_detected"].as_bool() == Some(true)
    {
        return refused_report(
            &card_id,
            &site_id,
            &title,
            &category,
            "refused_unsafe_private_caching",
            "revert",
            "Caching private, authenticated, cart, or checkout responses is forbidden by P22.",
        );
    }

    if card["schema"].as_str() != Some(INPUT_SCHEMA) {
        return invalid_report(
            &card_id,
            &site_id,
            &title,
            &category,
            "Input card schema must be rustiron-experiment-card/1.",
        );
    }

    if !ALLOWED_CATEGORIES.contains(&category_raw) {
        return invalid_report(
            &card_id,
            &site_id,
            &title,
            &category,
            "Change category is not in the P22 evidence-backed allowlist (lscache_invalidation, php_pool, opcache, app_workers, uncached_path).",
        );
    }

    let Some(direction) = parse_direction(card["preregistered_criteria"]["direction"].as_str())
    else {
        return invalid_report(
            &card_id,
            &site_id,
            &title,
            &category,
            "Preregistered direction must be lower_is_better or higher_is_better.",
        );
    };

    let min_effect_pct = card["preregistered_criteria"]["min_meaningful_effect_percent"]
        .as_f64()
        .filter(|v| v.is_finite() && *v > 0.0);
    let confidence_level = card["preregistered_criteria"]["confidence_level"]
        .as_f64()
        .filter(|v| v.is_finite() && (0.80..=0.99).contains(v));
    let min_repeats = card["preregistered_criteria"]["min_randomized_repeats"]
        .as_u64()
        .filter(|n| *n >= 3)
        .and_then(|n| usize::try_from(n).ok());

    let (Some(min_effect_pct), Some(confidence_level), Some(min_repeats)) =
        (min_effect_pct, confidence_level, min_repeats)
    else {
        return invalid_report(
            &card_id,
            &site_id,
            &title,
            &category,
            "Preregistered criteria require finite min_meaningful_effect_percent > 0, confidence_level in [0.80, 0.99], and min_randomized_repeats >= 3.",
        );
    };

    let max_error_rate = card["budget"]["max_error_rate"]
        .as_f64()
        .filter(|v| v.is_finite() && (0.0..=1.0).contains(v));
    let max_rss_mib = card["budget"]["max_memory_rss_mib"]
        .as_f64()
        .filter(|v| v.is_finite() && *v > 0.0);
    let max_cpu_pct = card["budget"]["max_cpu_percent"]
        .as_f64()
        .filter(|v| v.is_finite() && *v > 0.0);

    let (Some(max_error_rate), Some(max_rss_mib), Some(max_cpu_pct)) =
        (max_error_rate, max_rss_mib, max_cpu_pct)
    else {
        return invalid_report(
            &card_id,
            &site_id,
            &title,
            &category,
            "Budget must declare valid max_error_rate, max_memory_rss_mib, and max_cpu_percent.",
        );
    };

    let Some(trials) = parse_trials(&card["trials"]) else {
        return invalid_report(
            &card_id,
            &site_id,
            &title,
            &category,
            "Trials array is missing or contains malformed/non-finite entries.",
        );
    };

    // Check private cache safety on every trial before anything else.
    if trials.iter().any(|t| !t.private_cache_safe) {
        return refused_report(
            &card_id,
            &site_id,
            &title,
            &category,
            "refused_unsafe_private_caching",
            "revert",
            "One or more trials reported an unsafe private/auth/cart cache behavior; immediate revert required.",
        );
    }

    // Check workload equivalence across every trial.
    let digests: BTreeSet<&str> = trials.iter().map(|t| t.workload_digest.as_str()).collect();
    if digests.len() != 1 || digests.contains("") {
        return invalid_report(
            &card_id,
            &site_id,
            &title,
            &category,
            "Invalid comparison: baseline and candidate trials did not share one identical workload_digest.",
        );
    }

    let baseline_trials: Vec<&ParsedTrial> =
        trials.iter().filter(|t| t.arm == Arm::Baseline).collect();
    let candidate_trials: Vec<&ParsedTrial> =
        trials.iter().filter(|t| t.arm == Arm::Candidate).collect();

    if baseline_trials.len() < min_repeats || candidate_trials.len() < min_repeats {
        return invalid_report(
            &card_id,
            &site_id,
            &title,
            &category,
            "Invalid comparison: fewer trials than preregistered min_randomized_repeats.",
        );
    }

    let interleaved = is_interleaved(&trials);
    let declared_randomized = card["preregistered_criteria"]["randomized_order"]
        .as_bool()
        .unwrap_or(false);
    if !declared_randomized || !interleaved {
        return invalid_report(
            &card_id,
            &site_id,
            &title,
            &category,
            "Invalid comparison: trials must be randomized and interleaved across arms to prevent time-drift confounding.",
        );
    }

    let base_stats = compute_arm_stats(&baseline_trials);
    let cand_stats = compute_arm_stats(&candidate_trials);

    let baseline_error_rate = error_rate(base_stats.total_errors, base_stats.total_requests);
    let candidate_error_rate = error_rate(cand_stats.total_errors, cand_stats.total_requests);
    let correctness_ok = candidate_trials.iter().all(|t| t.correctness_passed);
    let error_budget_ok = candidate_error_rate <= max_error_rate;
    let memory_budget_ok = cand_stats.max_rss_mib <= max_rss_mib;
    let cpu_budget_ok = cand_stats.max_cpu_percent <= max_cpu_pct;

    let effect_percent = match direction {
        Direction::LowerIsBetter => ((base_stats.mean - cand_stats.mean) / base_stats.mean) * 100.0,
        Direction::HigherIsBetter => {
            ((cand_stats.mean - base_stats.mean) / base_stats.mean) * 100.0
        }
    };

    let (welch_t, welch_df, critical_t, significant) =
        welch_test(&base_stats, &cand_stats, direction, confidence_level);
    let meaningful_effect_met = effect_percent >= min_effect_pct;

    let (verdict, recommendation, benefit_proven, reason) = if !correctness_ok {
        (
            "revert_correctness_failure",
            "revert",
            false,
            "Candidate failed one or more correctness checks; revert change.",
        )
    } else if !error_budget_ok {
        (
            "revert_error_budget_exceeded",
            "revert",
            false,
            "Candidate HTTP error rate exceeded the preregistered error budget; revert change.",
        )
    } else if !memory_budget_ok || !cpu_budget_ok {
        (
            "revert_resource_budget_exceeded",
            "revert",
            false,
            "Candidate exceeded preregistered memory or CPU resource ceilings; revert change.",
        )
    } else if !significant || !meaningful_effect_met {
        (
            "no_benefit_revert",
            "revert",
            false,
            "No statistically significant meaningful benefit over baseline; revert unnecessary complexity. Performance equivalence does not falsify proven recovery value.",
        )
    } else {
        (
            "retain",
            "retain",
            true,
            "Candidate met preregistered meaningful-effect, confidence, correctness, error-budget, and resource criteria.",
        )
    };

    json!({
        "schema": SCHEMA,
        "card_id": card_id,
        "site_id": site_id,
        "title": title,
        "category": category,
        "verdict": verdict,
        "recommendation": recommendation,
        "benefit_proven": benefit_proven,
        "reason": reason,
        "automatic_db_changes_allowed": false,
        "unsafe_private_caching_allowed": false,
        "blast_radius_envelope_id": card["budget"]["blast_radius_envelope_id"].as_str().map(escape_human),
        "validity": {
            "comparison_valid": true,
            "workload_digest": digests.into_iter().next().map(escape_human),
            "randomized_order_declared": declared_randomized,
            "arms_interleaved": interleaved,
            "baseline_repeats": base_stats.n,
            "candidate_repeats": cand_stats.n,
            "min_randomized_repeats": min_repeats,
        },
        "safety": {
            "private_cache_safe": true,
            "correctness_passed": correctness_ok,
            "error_budget_passed": error_budget_ok,
            "memory_budget_passed": memory_budget_ok,
            "cpu_budget_passed": cpu_budget_ok,
        },
        "error_budget": {
            "max_error_rate": max_error_rate,
            "baseline_error_rate": round6(baseline_error_rate),
            "candidate_error_rate": round6(candidate_error_rate),
            "baseline_errors": base_stats.total_errors,
            "baseline_requests": base_stats.total_requests,
            "candidate_errors": cand_stats.total_errors,
            "candidate_requests": cand_stats.total_requests,
        },
        "resources": {
            "max_memory_rss_mib": max_rss_mib,
            "baseline_peak_rss_mib": round3(base_stats.max_rss_mib),
            "candidate_peak_rss_mib": round3(cand_stats.max_rss_mib),
            "max_cpu_percent": max_cpu_pct,
            "baseline_peak_cpu_percent": round3(base_stats.max_cpu_percent),
            "candidate_peak_cpu_percent": round3(cand_stats.max_cpu_percent),
        },
        "statistics": {
            "primary_metric": card["preregistered_criteria"]["primary_metric"].as_str().map(escape_human),
            "direction": card["preregistered_criteria"]["direction"],
            "confidence_level": confidence_level,
            "min_meaningful_effect_percent": min_effect_pct,
            "baseline_mean": round4(base_stats.mean),
            "baseline_median": round4(base_stats.median),
            "baseline_stddev": round4(base_stats.stddev),
            "candidate_mean": round4(cand_stats.mean),
            "candidate_median": round4(cand_stats.median),
            "candidate_stddev": round4(cand_stats.stddev),
            "effect_percent": round3(effect_percent),
            "welch_t": round4(welch_t),
            "welch_df": round3(welch_df),
            "critical_t": round4(critical_t),
            "statistically_significant": significant,
            "meaningful_effect_met": meaningful_effect_met,
        },
    })
}

fn refused_report(
    card_id: &str,
    site_id: &str,
    title: &str,
    category: &str,
    verdict: &'static str,
    recommendation: &'static str,
    reason: &'static str,
) -> Value {
    json!({
        "schema": SCHEMA,
        "card_id": card_id,
        "site_id": site_id,
        "title": title,
        "category": category,
        "verdict": verdict,
        "recommendation": recommendation,
        "benefit_proven": false,
        "reason": reason,
        "automatic_db_changes_allowed": false,
        "unsafe_private_caching_allowed": false,
        "validity": { "comparison_valid": false },
    })
}

fn invalid_report(
    card_id: &str,
    site_id: &str,
    title: &str,
    category: &str,
    reason: &'static str,
) -> Value {
    refused_report(
        card_id,
        site_id,
        title,
        category,
        "invalid_comparison",
        "revert",
        reason,
    )
}

fn is_db_category(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    lower.contains("db")
        || lower.contains("database")
        || lower.contains("mariadb")
        || lower.contains("mysql")
}

fn parse_direction(raw: Option<&str>) -> Option<Direction> {
    match raw? {
        "lower_is_better" => Some(Direction::LowerIsBetter),
        "higher_is_better" => Some(Direction::HigherIsBetter),
        _ => None,
    }
}

fn parse_trials(raw: &Value) -> Option<Vec<ParsedTrial>> {
    let arr = raw.as_array()?;
    if arr.is_empty() || arr.len() > 256 {
        return None;
    }
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let arm = match item["arm"].as_str()? {
            "baseline" => Arm::Baseline,
            "candidate" => Arm::Candidate,
            _ => return None,
        };
        let workload_digest = item["workload_digest"].as_str()?.to_owned();
        let primary_value = item["primary_value"].as_f64()?;
        if !primary_value.is_finite() || primary_value <= 0.0 {
            return None;
        }
        let http_requests = item["http_requests"].as_u64()?;
        let http_errors = item["http_errors"].as_u64()?;
        if http_requests == 0 || http_errors > http_requests {
            return None;
        }
        let correctness_passed = item["correctness_passed"].as_bool()?;
        let private_cache_safe = item["private_cache_safe"].as_bool()?;
        let peak_rss_mib = item["peak_rss_mib"].as_f64()?;
        let peak_cpu_percent = item["peak_cpu_percent"].as_f64()?;
        if !peak_rss_mib.is_finite()
            || peak_rss_mib < 0.0
            || !peak_cpu_percent.is_finite()
            || peak_cpu_percent < 0.0
        {
            return None;
        }
        out.push(ParsedTrial {
            arm,
            workload_digest,
            primary_value,
            http_requests,
            http_errors,
            correctness_passed,
            private_cache_safe,
            peak_rss_mib,
            peak_cpu_percent,
        });
    }
    Some(out)
}

/// Ensures arms alternate at least twice (not a single baseline block followed
/// by a single candidate block, which confounds time-of-day load drift).
fn is_interleaved(trials: &[ParsedTrial]) -> bool {
    let transitions = trials
        .windows(2)
        .filter(|pair| pair[0].arm != pair[1].arm)
        .count();
    transitions >= 2
}

fn compute_arm_stats(trials: &[&ParsedTrial]) -> ArmStats {
    let n = trials.len();
    let mut vals: Vec<f64> = trials.iter().map(|t| t.primary_value).collect();
    vals.sort_by(f64::total_cmp);
    let mean = vals.iter().sum::<f64>() / n as f64;
    let median = if n.is_multiple_of(2) {
        (vals[n / 2 - 1] + vals[n / 2]) / 2.0
    } else {
        vals[n / 2]
    };
    let variance = if n > 1 {
        vals.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1) as f64
    } else {
        0.0
    };
    let stddev = variance.sqrt();
    let total_requests = trials
        .iter()
        .fold(0_u64, |acc, t| acc.saturating_add(t.http_requests));
    let total_errors = trials
        .iter()
        .fold(0_u64, |acc, t| acc.saturating_add(t.http_errors));
    let max_rss_mib = trials
        .iter()
        .map(|t| t.peak_rss_mib)
        .fold(0.0_f64, f64::max);
    let max_cpu_percent = trials
        .iter()
        .map(|t| t.peak_cpu_percent)
        .fold(0.0_f64, f64::max);

    ArmStats {
        n,
        mean,
        median,
        variance,
        stddev,
        total_requests,
        total_errors,
        max_rss_mib,
        max_cpu_percent,
    }
}

fn error_rate(errors: u64, requests: u64) -> f64 {
    if requests == 0 {
        1.0
    } else {
        errors as f64 / requests as f64
    }
}

/// Welch's two-sample t-test (signed positive when candidate improves over
/// baseline in the preregistered direction) against a two-sided critical t
/// value at `confidence_level`.
fn welch_test(
    base: &ArmStats,
    cand: &ArmStats,
    direction: Direction,
    confidence_level: f64,
) -> (f64, f64, f64, bool) {
    let diff = match direction {
        Direction::LowerIsBetter => base.mean - cand.mean,
        Direction::HigherIsBetter => cand.mean - base.mean,
    };
    let sb = base.variance / base.n as f64;
    let sc = cand.variance / cand.n as f64;
    let se_sq = sb + sc;
    let df_min = (base.n.min(cand.n).saturating_sub(1)).max(1) as f64;
    if se_sq <= 1e-12 {
        let crit = two_sided_t_critical(df_min, confidence_level);
        let t = if diff > 0.0 {
            f64::INFINITY
        } else if diff < 0.0 {
            f64::NEG_INFINITY
        } else {
            0.0
        };
        return (
            if t.is_infinite() {
                t.signum() * 999.0
            } else {
                t
            },
            df_min,
            crit,
            diff > 0.0,
        );
    }
    let t = diff / se_sq.sqrt();
    let denom = (sb * sb) / (base.n - 1) as f64 + (sc * sc) / (cand.n - 1) as f64;
    let df = if denom > 0.0 {
        (se_sq * se_sq / denom).max(1.0)
    } else {
        df_min
    };
    let crit = two_sided_t_critical(df, confidence_level);
    (t, df, crit, t >= crit)
}

/// Cornish-Fisher approximation for the two-sided Student's t critical value
/// (Abramowitz & Stegun 26.7.5) with conservative floor for small df.
fn two_sided_t_critical(df: f64, confidence_level: f64) -> f64 {
    let z: f64 = if confidence_level >= 0.99 {
        2.5758
    } else if confidence_level >= 0.95 {
        1.9600
    } else if confidence_level >= 0.90 {
        1.6449
    } else {
        1.2816
    };
    let v = df.max(1.0);
    let g1 = (z.powi(3) + z) / (4.0 * v);
    let g2 = (5.0 * z.powi(5) + 16.0 * z.powi(3) + 3.0 * z) / (96.0 * v * v);
    let g3 =
        (3.0 * z.powi(7) + 19.0 * z.powi(5) + 17.0 * z.powi(3) - 15.0 * z) / (384.0 * v * v * v);
    z + g1 + g2 + g3
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

fn round4(v: f64) -> f64 {
    (v * 10_000.0).round() / 10_000.0
}

fn round6(v: f64) -> f64 {
    (v * 1_000_000.0).round() / 1_000_000.0
}

/// Concise human-readable operator summary of an Experiment Card verdict.
pub(crate) fn human(report: &Value) -> String {
    let mut out = String::new();
    let card_id = report["card_id"].as_str().unwrap_or("unknown");
    let site_id = report["site_id"].as_str().unwrap_or("unknown");
    let verdict = report["verdict"].as_str().unwrap_or("unknown");
    let rec = report["recommendation"].as_str().unwrap_or("revert");
    let benefit = report["benefit_proven"].as_bool().unwrap_or(false);

    out.push_str(&format!(
        "Rustiron Experiment Card ({card_id} on {site_id}): verdict={verdict} recommendation={rec} benefit_proven={benefit} auto_db=false unsafe_private_cache=false\n"
    ));
    if let Some(reason) = report["reason"].as_str() {
        out.push_str(&format!("  reason: {reason}\n"));
    }
    if let Some(effect) = report["statistics"]["effect_percent"].as_f64() {
        let t = report["statistics"]["welch_t"].as_f64().unwrap_or(0.0);
        let crit = report["statistics"]["critical_t"].as_f64().unwrap_or(0.0);
        out.push_str(&format!(
            "  effect: {effect:+.2}% (welch_t={t:.3}, critical_t={crit:.3})\n"
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trial(arm: &str, val: f64, digest: &str) -> Value {
        json!({
            "arm": arm,
            "workload_digest": digest,
            "primary_value": val,
            "http_requests": 2000,
            "http_errors": 0,
            "correctness_passed": true,
            "private_cache_safe": true,
            "peak_rss_mib": 140.0,
            "peak_cpu_percent": 52.0
        })
    }

    fn base_card(trials: Vec<Value>) -> Value {
        json!({
            "schema": INPUT_SCHEMA,
            "card_id": "exp-opcache-001",
            "site_id": "cp02",
            "title": "Raise OPcache interned strings buffer from 8 MiB to 16 MiB",
            "hypothesis": "Reducing OPcache string buffer evictions lowers p95 PHP response latency by >= 10%.",
            "risks": ["Slightly higher per-pool memory usage (+8 MiB)."],
            "change": {
                "category": "opcache",
                "automatic_db_change": false,
                "caches_private_auth_or_cart": false
            },
            "budget": {
                "blast_radius_envelope_id": "env_op_1",
                "max_error_rate": 0.005,
                "max_memory_rss_mib": 256.0,
                "max_cpu_percent": 85.0
            },
            "preregistered_criteria": {
                "primary_metric": "p95_latency_ms",
                "direction": "lower_is_better",
                "min_meaningful_effect_percent": 10.0,
                "confidence_level": 0.95,
                "min_randomized_repeats": 5,
                "randomized_order": true
            },
            "trials": trials
        })
    }

    #[test]
    fn proven_meaningful_improvement_returns_retain() {
        let d = "sha256:workload_v1";
        let trials = vec![
            trial("baseline", 210.0, d),
            trial("candidate", 162.0, d),
            trial("candidate", 165.0, d),
            trial("baseline", 206.0, d),
            trial("baseline", 214.0, d),
            trial("candidate", 160.0, d),
            trial("candidate", 164.0, d),
            trial("baseline", 209.0, d),
            trial("baseline", 212.0, d),
            trial("candidate", 163.0, d),
        ];
        let rep = evaluate(&base_card(trials));
        assert_eq!(rep["schema"], SCHEMA);
        assert_eq!(rep["verdict"], "retain");
        assert_eq!(rep["recommendation"], "retain");
        assert_eq!(rep["benefit_proven"], true);
        assert_eq!(rep["statistics"]["statistically_significant"], true);
        assert_eq!(rep["statistics"]["meaningful_effect_met"], true);
        assert_eq!(rep["automatic_db_changes_allowed"], false);
        assert_eq!(rep["unsafe_private_caching_allowed"], false);
    }

    #[test]
    fn no_meaningful_benefit_is_reported_honestly_as_revert() {
        let d = "sha256:workload_v1";
        let trials = vec![
            trial("baseline", 200.0, d),
            trial("candidate", 198.0, d),
            trial("candidate", 201.0, d),
            trial("baseline", 202.0, d),
            trial("baseline", 199.0, d),
            trial("candidate", 197.0, d),
            trial("candidate", 200.0, d),
            trial("baseline", 201.0, d),
            trial("baseline", 200.0, d),
            trial("candidate", 199.0, d),
        ];
        let rep = evaluate(&base_card(trials));
        assert_eq!(rep["verdict"], "no_benefit_revert");
        assert_eq!(rep["recommendation"], "revert");
        assert_eq!(rep["benefit_proven"], false);
        assert!(
            rep["reason"]
                .as_str()
                .unwrap()
                .contains("Performance equivalence does not falsify proven recovery value")
        );
    }

    #[test]
    fn blocked_non_interleaved_or_mismatched_workload_is_invalid_comparison() {
        let d = "sha256:workload_v1";
        let blocked = vec![
            trial("baseline", 210.0, d),
            trial("baseline", 212.0, d),
            trial("baseline", 208.0, d),
            trial("baseline", 211.0, d),
            trial("baseline", 209.0, d),
            trial("candidate", 150.0, d),
            trial("candidate", 151.0, d),
            trial("candidate", 149.0, d),
            trial("candidate", 152.0, d),
            trial("candidate", 150.0, d),
        ];
        let rep = evaluate(&base_card(blocked));
        assert_eq!(rep["verdict"], "invalid_comparison");
        assert_eq!(rep["recommendation"], "revert");

        let mismatched = vec![
            trial("baseline", 210.0, "sha256:a"),
            trial("candidate", 150.0, "sha256:b"),
            trial("baseline", 212.0, "sha256:a"),
            trial("candidate", 151.0, "sha256:b"),
            trial("baseline", 208.0, "sha256:a"),
            trial("candidate", 149.0, "sha256:b"),
            trial("baseline", 211.0, "sha256:a"),
            trial("candidate", 152.0, "sha256:b"),
            trial("baseline", 209.0, "sha256:a"),
            trial("candidate", 150.0, "sha256:b"),
        ];
        let rep2 = evaluate(&base_card(mismatched));
        assert_eq!(rep2["verdict"], "invalid_comparison");
    }

    #[test]
    fn automatic_db_changes_and_unsafe_private_caching_are_hard_refused() {
        let d = "sha256:workload_v1";
        let mut db_card = base_card(vec![trial("baseline", 100.0, d)]);
        db_card["change"]["automatic_db_change"] = json!(true);
        assert_eq!(evaluate(&db_card)["verdict"], "refused_automatic_db_change");

        let mut priv_card = base_card(vec![trial("baseline", 100.0, d)]);
        priv_card["change"]["caches_private_auth_or_cart"] = json!(true);
        assert_eq!(
            evaluate(&priv_card)["verdict"],
            "refused_unsafe_private_caching"
        );
    }

    #[test]
    fn error_and_resource_budget_breaches_force_revert() {
        let d = "sha256:workload_v1";
        let mut bad_err = trial("candidate", 150.0, d);
        bad_err["http_errors"] = json!(200);
        let trials = vec![
            trial("baseline", 210.0, d),
            bad_err,
            trial("baseline", 208.0, d),
            trial("candidate", 152.0, d),
            trial("baseline", 211.0, d),
            trial("candidate", 151.0, d),
            trial("baseline", 209.0, d),
            trial("candidate", 150.0, d),
            trial("baseline", 212.0, d),
            trial("candidate", 149.0, d),
        ];
        assert_eq!(
            evaluate(&base_card(trials))["verdict"],
            "revert_error_budget_exceeded"
        );

        let mut bad_rss = trial("candidate", 150.0, d);
        bad_rss["peak_rss_mib"] = json!(400.0);
        let trials_rss = vec![
            trial("baseline", 210.0, d),
            bad_rss,
            trial("baseline", 208.0, d),
            trial("candidate", 152.0, d),
            trial("baseline", 211.0, d),
            trial("candidate", 151.0, d),
            trial("baseline", 209.0, d),
            trial("candidate", 150.0, d),
            trial("baseline", 212.0, d),
            trial("candidate", 149.0, d),
        ];
        assert_eq!(
            evaluate(&base_card(trials_rss))["verdict"],
            "revert_resource_budget_exceeded"
        );
    }
}
