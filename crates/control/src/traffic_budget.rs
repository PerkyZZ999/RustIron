//! W616 (P25): Traffic-aware background work budget gate over a merged host
//! observation. Strictly read-only and deterministic: evaluates whether due
//! background work (`site_cron`, `backup_capture`, `maintenance`) should run
//! now or defer during measured busy windows within explicit site, resource,
//! starvation, and D-010 RPO constraints. Never hides missed jobs and never
//! performs autonomous database tuning.

use rustiron_contracts::escape_human;
use serde_json::{Value, json};

/// Output schema for `rustiron-control --background-budget`.
pub(crate) const SCHEMA: &str = "rustiron-background-budget/1";

/// Metrics older than 5 minutes are stale; dead telemetry must not silently
/// suppress scheduled jobs.
const MAX_METRIC_AGE_SECS: u64 = 300;
/// Future timestamps beyond 60 s indicate clock skew and are treated as stale.
const MAX_CLOCK_SKEW_SECS: u64 = 60;
/// 1-minute load/CPU ratio signaling an acute traffic burst.
const LOAD1_RATIO_BUSY: f64 = 0.85;
/// 5-minute load/CPU ratio signaling sustained busy traffic.
const LOAD5_RATIO_BUSY: f64 = 0.75;
/// Available memory percentage below which background work defers.
const MEM_AVAILABLE_MIN_PERCENT: u64 = 20;
/// Available disk percentage below which non-urgent work defers.
const DISK_AVAILABLE_WARN_PERCENT: u64 = 15;
/// Available disk percentage below which backup captures are blocked unless
/// explicitly forced by the operator.
const DISK_AVAILABLE_CRITICAL_PERCENT: u64 = 10;
/// Optional observed request-rate threshold (requests/sec).
const TRAFFIC_RPS_BUSY: f64 = 50.0;
/// Optional observed active-connection threshold.
const TRAFFIC_CONNS_BUSY: u64 = 64;
/// Sample-buffer spike threshold: newest CPU sample >= 70% and >= 25 points
/// above the recent median within the last 15 minutes.
const BURST_MIN_CPU_PERCENT: u64 = 70;
const BURST_DELTA_CPU_POINTS: u64 = 25;
const BURST_WINDOW_SECS: u64 = 15 * 60;

/// D-010 recovery point objective (24 h) and pre-deadline guard (22 h).
const RPO_OBJECTIVE_SECS: u64 = 24 * 3600;
const RPO_GUARD_SECS: u64 = 22 * 3600;
/// W505: a capture stuck in `running` longer than 15 min blocks new captures.
const UNSETTLED_CAPTURE_SECS: u64 = 15 * 60;

/// Background job classes managed by the P25 budget gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JobKind {
    SiteCron,
    BackupCapture,
    Maintenance,
}

impl JobKind {
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        match raw {
            "site_cron" => Some(Self::SiteCron),
            "backup_capture" => Some(Self::BackupCapture),
            "maintenance" => Some(Self::Maintenance),
            _ => None,
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::SiteCron => "site_cron",
            Self::BackupCapture => "backup_capture",
            Self::Maintenance => "maintenance",
        }
    }

    const fn max_backlog_secs(self) -> u64 {
        match self {
            Self::SiteCron => 1800,      // 30 minutes
            Self::BackupCapture => 7200, // 2 hours (still bounded by RPO guard)
            Self::Maintenance => 7200,   // 2 hours
        }
    }

    const fn max_consecutive_deferrals(self) -> u32 {
        match self {
            Self::SiteCron => 6,
            Self::BackupCapture => 8,
            Self::Maintenance => 12,
        }
    }

    const fn retry_after_secs(self) -> u64 {
        match self {
            Self::SiteCron => 120,
            Self::BackupCapture => 300,
            Self::Maintenance => 300,
        }
    }
}

/// Operator override mode for traffic-budgeted scheduling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OverrideMode {
    Auto,
    ForceRun,
    Disable,
}

impl OverrideMode {
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        match raw {
            "auto" => Some(Self::Auto),
            "force_run" => Some(Self::ForceRun),
            "disable" => Some(Self::Disable),
            _ => None,
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::ForceRun => "force_run",
            Self::Disable => "disable",
        }
    }
}

/// Evaluation inputs for one scheduling tick.
pub(crate) struct BudgetInput<'a> {
    pub(crate) job: JobKind,
    pub(crate) site: Option<&'a str>,
    pub(crate) override_mode: OverrideMode,
    pub(crate) backlog_seconds: u64,
    pub(crate) consecutive_deferrals: u32,
    pub(crate) now: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetricsFreshness {
    Fresh,
    Stale,
    Missing,
}

impl MetricsFreshness {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Stale => "stale",
            Self::Missing => "missing",
        }
    }
}

struct RpoAssessment {
    at_risk_sites: Vec<String>,
    breached_sites: Vec<String>,
    unsettled_captures: Vec<String>,
    tightest_margin_secs: Option<i64>,
}

struct TrafficSnapshot {
    freshness: MetricsFreshness,
    metric_age_secs: Option<i64>,
    load1_ratio: Option<f64>,
    load5_ratio: Option<f64>,
    mem_available_percent: Option<u64>,
    disk_available_percent: Option<u64>,
    burst_spike_detected: bool,
    busy_reasons: Vec<String>,
    low_disk_critical: bool,
}

/// Pure, deterministic P25 traffic-budget evaluation.
pub(crate) fn evaluate(merged: &Value, input: &BudgetInput<'_>) -> Value {
    let machine = &merged["machine"];
    let snapshot = inspect_traffic(machine, input.now);
    let rpo = assess_rpo(merged, input.site, input.now);

    let max_backlog = input.job.max_backlog_secs();
    let max_deferrals = input.job.max_consecutive_deferrals();
    let starvation_reached =
        input.backlog_seconds >= max_backlog || input.consecutive_deferrals >= max_deferrals;
    let starvation_remaining_secs = max_backlog.saturating_sub(input.backlog_seconds);

    let mut missed_jobs = collect_missed_jobs(input, &rpo, &snapshot);

    let (decision, allow_run, reason, retry_after_seconds) =
        decide(input, &snapshot, &rpo, starvation_reached, &mut missed_jobs);

    let traffic_gating_active =
        input.override_mode == OverrideMode::Auto && snapshot.freshness == MetricsFreshness::Fresh;

    json!({
        "schema": SCHEMA,
        "evaluated_at": input.now,
        "observed_at": machine["observed_at"],
        "job": input.job.as_str(),
        "site": input.site.map(escape_human),
        "override_mode": input.override_mode.as_str(),
        "decision": decision,
        "allow_run": allow_run,
        "reason": reason,
        "retry_after_seconds": retry_after_seconds,
        "traffic_gating_active": traffic_gating_active,
        "autonomous_db_tuning": false,
        "hides_missed_jobs": false,
        "metrics": {
            "state": snapshot.freshness.as_str(),
            "age_seconds": snapshot.metric_age_secs,
            "max_age_seconds": MAX_METRIC_AGE_SECS,
            "load1_per_cpu": snapshot.load1_ratio,
            "load5_per_cpu": snapshot.load5_ratio,
            "memory_available_percent": snapshot.mem_available_percent,
            "disk_available_percent": snapshot.disk_available_percent,
            "burst_spike_detected": snapshot.burst_spike_detected,
            "busy": !snapshot.busy_reasons.is_empty(),
            "busy_reasons": snapshot.busy_reasons,
        },
        "backlog": {
            "backlog_seconds": input.backlog_seconds,
            "max_backlog_seconds": max_backlog,
            "consecutive_deferrals": input.consecutive_deferrals,
            "max_consecutive_deferrals": max_deferrals,
            "starvation_reached": starvation_reached,
            "starvation_remaining_seconds": starvation_remaining_secs,
        },
        "rpo": {
            "objective_seconds": RPO_OBJECTIVE_SECS,
            "guard_seconds": RPO_GUARD_SECS,
            "tightest_margin_seconds": rpo.tightest_margin_secs,
            "at_risk_sites": rpo.at_risk_sites.iter().map(|s| escape_human(s)).collect::<Vec<_>>(),
            "breached_sites": rpo.breached_sites.iter().map(|s| escape_human(s)).collect::<Vec<_>>(),
            "unsettled_captures": rpo.unsettled_captures.iter().map(|s| escape_human(s)).collect::<Vec<_>>(),
        },
        "missed_job_count": missed_jobs.len(),
        "missed_jobs": missed_jobs,
        "policy": {
            "load1_per_cpu_busy": LOAD1_RATIO_BUSY,
            "load5_per_cpu_busy": LOAD5_RATIO_BUSY,
            "memory_available_min_percent": MEM_AVAILABLE_MIN_PERCENT,
            "disk_available_warn_percent": DISK_AVAILABLE_WARN_PERCENT,
            "disk_available_critical_percent": DISK_AVAILABLE_CRITICAL_PERCENT,
            "traffic_rps_busy": TRAFFIC_RPS_BUSY,
            "traffic_connections_busy": TRAFFIC_CONNS_BUSY,
            "burst_min_cpu_percent": BURST_MIN_CPU_PERCENT,
            "burst_delta_cpu_points": BURST_DELTA_CPU_POINTS,
        },
    })
}

fn decide(
    input: &BudgetInput<'_>,
    snapshot: &TrafficSnapshot,
    rpo: &RpoAssessment,
    starvation_reached: bool,
    missed_jobs: &mut Vec<Value>,
) -> (&'static str, bool, &'static str, Option<u64>) {
    match input.override_mode {
        OverrideMode::Disable => {
            return (
                "run_operator_gate_disabled",
                true,
                "Operator disabled traffic-budget gating; running on the explicit schedule.",
                None,
            );
        }
        OverrideMode::ForceRun => {
            return (
                "run_operator_forced",
                true,
                "Operator forced an immediate run; busy-window deferral bypassed explicitly.",
                None,
            );
        }
        OverrideMode::Auto => {}
    }

    if input.job == JobKind::BackupCapture && snapshot.low_disk_critical {
        missed_jobs.push(json!({
            "kind": "backup_blocked_low_disk",
            "job": input.job.as_str(),
            "site": input.site.map(escape_human),
            "reason": "Available root disk is below 10%; refusing automatic backup capture to protect host storage.",
            "action": "Free disk space or grow the filesystem, or pass --budget-override force_run after verifying staging space.",
        }));
        return (
            "block_low_disk",
            false,
            "Root filesystem has less than 10% free space; automatic backup capture is blocked and surfaced as missed.",
            Some(input.job.retry_after_secs()),
        );
    }

    if input.job == JobKind::BackupCapture && !rpo.at_risk_sites.is_empty() {
        return (
            "run_rpo_override",
            true,
            "One or more managed sites are within 2 hours of (or past) the 24 h D-010 RPO objective; running immediately despite observed load.",
            None,
        );
    }

    if starvation_reached {
        return (
            "run_starvation_override",
            true,
            "Backlog or consecutive deferral ceiling reached; running now to prevent job starvation.",
            None,
        );
    }

    if snapshot.freshness != MetricsFreshness::Fresh {
        return (
            "run_stale_metrics_fallback",
            true,
            "Host telemetry is missing or stale (> 300 s); falling back to scheduled execution so dead telemetry never hides missed jobs.",
            None,
        );
    }

    if !snapshot.busy_reasons.is_empty() {
        return (
            "defer",
            false,
            "Host or traffic load exceeds the configured busy-window threshold; deferring within starvation and RPO bounds.",
            Some(input.job.retry_after_secs()),
        );
    }

    (
        "run",
        true,
        "Observed host and traffic metrics are within budget; running scheduled background work.",
        None,
    )
}

fn inspect_traffic(machine: &Value, now: u64) -> TrafficSnapshot {
    let observed_at = machine["observed_at"].as_u64();
    let (freshness, metric_age_secs) = match observed_at {
        None => (MetricsFreshness::Missing, None),
        Some(ts) => {
            if ts > now {
                let skew = ts - now;
                let age = -i64::try_from(skew).unwrap_or(i64::MAX);
                let state = if skew > MAX_CLOCK_SKEW_SECS {
                    MetricsFreshness::Stale
                } else {
                    MetricsFreshness::Fresh
                };
                (state, Some(age))
            } else {
                let age = now - ts;
                let state = if age > MAX_METRIC_AGE_SECS {
                    MetricsFreshness::Stale
                } else {
                    MetricsFreshness::Fresh
                };
                (state, Some(i64::try_from(age).unwrap_or(i64::MAX)))
            }
        }
    };

    let cpus = machine["cpu"]["count"]
        .as_f64()
        .filter(|count| *count > 0.0);
    let load1_ratio = cpus.and_then(|c| machine["cpu"]["load"][0].as_f64().map(|l| l / c));
    let load5_ratio = cpus.and_then(|c| machine["cpu"]["load"][1].as_f64().map(|l| l / c));

    let mem_available_percent = match (
        machine["memory"]["total_bytes"].as_u64(),
        machine["memory"]["available_bytes"].as_u64(),
    ) {
        (Some(total), Some(avail)) if total > 0 => {
            Some(avail.saturating_mul(100).checked_div(total).unwrap_or(0))
        }
        _ => None,
    };

    let disk_available_percent = match (
        machine["disk"]["total_bytes"].as_u64(),
        machine["disk"]["available_bytes"].as_u64(),
    ) {
        (Some(total), Some(avail)) if total > 0 => {
            Some(avail.saturating_mul(100).checked_div(total).unwrap_or(0))
        }
        _ => None,
    };

    let low_disk_critical =
        disk_available_percent.is_some_and(|pct| pct < DISK_AVAILABLE_CRITICAL_PERCENT);
    let burst_spike_detected = detect_cpu_burst(machine, now);

    let mut busy_reasons = Vec::new();
    if let Some(r1) = load1_ratio
        && r1 > LOAD1_RATIO_BUSY
    {
        busy_reasons.push(format!(
            "load1_per_cpu={r1:.2} exceeds {LOAD1_RATIO_BUSY:.2}"
        ));
    }
    if let Some(r5) = load5_ratio
        && r5 > LOAD5_RATIO_BUSY
    {
        busy_reasons.push(format!(
            "load5_per_cpu={r5:.2} exceeds {LOAD5_RATIO_BUSY:.2}"
        ));
    }
    if let Some(mem_pct) = mem_available_percent
        && mem_pct < MEM_AVAILABLE_MIN_PERCENT
    {
        busy_reasons.push(format!(
            "memory_available={mem_pct}% below {MEM_AVAILABLE_MIN_PERCENT}%"
        ));
    }
    if let Some(disk_pct) = disk_available_percent
        && disk_pct < DISK_AVAILABLE_WARN_PERCENT
    {
        busy_reasons.push(format!(
            "disk_available={disk_pct}% below {DISK_AVAILABLE_WARN_PERCENT}%"
        ));
    }
    if burst_spike_detected {
        busy_reasons.push(format!(
            "cpu_burst_spike>=+{BURST_DELTA_CPU_POINTS}pp above recent median"
        ));
    }
    if let Some(rps) = machine["traffic"]["req_per_sec"].as_f64()
        && rps >= TRAFFIC_RPS_BUSY
    {
        busy_reasons.push(format!(
            "traffic_req_per_sec={rps:.1} exceeds {TRAFFIC_RPS_BUSY:.1}"
        ));
    }
    if let Some(conns) = machine["traffic"]["active_connections"].as_u64()
        && conns >= TRAFFIC_CONNS_BUSY
    {
        busy_reasons.push(format!(
            "traffic_active_connections={conns} exceeds {TRAFFIC_CONNS_BUSY}"
        ));
    }

    TrafficSnapshot {
        freshness,
        metric_age_secs,
        load1_ratio,
        load5_ratio,
        mem_available_percent,
        disk_available_percent,
        burst_spike_detected,
        busy_reasons,
        low_disk_critical,
    }
}

fn detect_cpu_burst(machine: &Value, now: u64) -> bool {
    let Some(samples) = machine["samples"].as_array() else {
        return false;
    };
    let cutoff = now.saturating_sub(BURST_WINDOW_SECS);
    let mut recent: Vec<(u64, u64)> = samples
        .iter()
        .filter_map(|s| {
            let t = s["t"].as_u64()?;
            let cpu = s["cpu"].as_u64()?;
            (t >= cutoff && t <= now.saturating_add(MAX_CLOCK_SKEW_SECS)).then_some((t, cpu))
        })
        .collect();
    if recent.len() < 3 {
        return false;
    }
    recent.sort_by_key(|(t, _)| *t);
    let Some((_, latest_cpu)) = recent.pop() else {
        return false;
    };
    if latest_cpu < BURST_MIN_CPU_PERCENT {
        return false;
    }
    let mut prior: Vec<u64> = recent.into_iter().map(|(_, c)| c).collect();
    prior.sort_unstable();
    let median = prior[prior.len() / 2];
    latest_cpu.saturating_sub(median) >= BURST_DELTA_CPU_POINTS
}

fn is_proxy(site: &Value) -> bool {
    site["kind"].as_str() == Some("proxy")
        || site["proxy_upstream_port"].as_u64().is_some()
        || site["site_kind"].as_str() == Some("proxy")
}

fn assess_rpo(merged: &Value, site_filter: Option<&str>, now: u64) -> RpoAssessment {
    let empty = Vec::new();
    let sites = merged["sites"].as_array().unwrap_or(&empty);
    let captures = merged["captures"].as_array().unwrap_or(&empty);
    let now_i64 = i64::try_from(now).unwrap_or(i64::MAX);

    let mut at_risk_sites = Vec::new();
    let mut breached_sites = Vec::new();
    let mut tightest_margin_secs: Option<i64> = None;

    for site in sites {
        let (Some(id), Some("succeeded")) = (site["site_id"].as_str(), site["state"].as_str())
        else {
            continue;
        };
        if site["ejected"] == true || is_proxy(site) {
            continue;
        }
        if let Some(filter) = site_filter
            && filter != id
        {
            continue;
        }
        let newest = captures
            .iter()
            .filter(|c| c["site_id"] == id && c["state"] == "succeeded")
            .filter_map(|c| c["finished_at"].as_i64())
            .max();

        match newest {
            Some(finished_at) => {
                let age = now_i64.saturating_sub(finished_at).max(0);
                let margin = (RPO_OBJECTIVE_SECS as i64).saturating_sub(age);
                tightest_margin_secs = Some(match tightest_margin_secs {
                    Some(prev) => prev.min(margin),
                    None => margin,
                });
                if age as u64 >= RPO_GUARD_SECS {
                    at_risk_sites.push(id.to_owned());
                }
                if age as u64 > RPO_OBJECTIVE_SECS {
                    breached_sites.push(id.to_owned());
                }
            }
            None => {
                tightest_margin_secs = Some(match tightest_margin_secs {
                    Some(prev) => prev.min(-(RPO_OBJECTIVE_SECS as i64)),
                    None => -(RPO_OBJECTIVE_SECS as i64),
                });
                at_risk_sites.push(id.to_owned());
                breached_sites.push(id.to_owned());
            }
        }
    }

    let mut unsettled_captures = Vec::new();
    for capture in captures {
        if capture["state"].as_str() != Some("running") {
            continue;
        }
        let started_at = capture["started_at"]
            .as_i64()
            .or_else(|| capture["created_at"].as_i64());
        if let Some(started) = started_at
            && now_i64.saturating_sub(started) >= UNSETTLED_CAPTURE_SECS as i64
        {
            let cid = capture["capture_id"]
                .as_str()
                .or_else(|| capture["site_id"].as_str())
                .unwrap_or("unknown");
            unsettled_captures.push(cid.to_owned());
        }
    }

    RpoAssessment {
        at_risk_sites,
        breached_sites,
        unsettled_captures,
        tightest_margin_secs,
    }
}

fn collect_missed_jobs(
    input: &BudgetInput<'_>,
    rpo: &RpoAssessment,
    snapshot: &TrafficSnapshot,
) -> Vec<Value> {
    let mut missed = Vec::new();

    for site_id in &rpo.breached_sites {
        missed.push(json!({
            "kind": "rpo_objective_missed",
            "site": escape_human(site_id),
            "objective_seconds": RPO_OBJECTIVE_SECS,
            "reason": "Site has no succeeded backup capture within the 24 h D-010 RPO objective.",
            "action": "Run backup_capture immediately and inspect capture journal outcomes.",
        }));
    }

    for cid in &rpo.unsettled_captures {
        missed.push(json!({
            "kind": "unsettled_capture_blocking",
            "capture": escape_human(cid),
            "reason": "A capture has remained in running state for > 15 min and blocks subsequent host captures.",
            "action": "Inspect and explicitly settle the running capture before relying on scheduled captures.",
        }));
    }

    let max_backlog = input.job.max_backlog_secs();
    if input.backlog_seconds > max_backlog {
        missed.push(json!({
            "kind": "schedule_backlog_exceeded",
            "job": input.job.as_str(),
            "site": input.site.map(escape_human),
            "backlog_seconds": input.backlog_seconds,
            "max_backlog_seconds": max_backlog,
            "reason": "Background job waited longer than its configured starvation ceiling.",
            "action": "Verify scheduler timer execution and inspect recurring load spikes.",
        }));
    }

    if snapshot.freshness != MetricsFreshness::Fresh {
        missed.push(json!({
            "kind": "telemetry_stale_or_missing",
            "job": input.job.as_str(),
            "metrics_state": snapshot.freshness.as_str(),
            "age_seconds": snapshot.metric_age_secs,
            "reason": "Observed host metrics are stale or missing; traffic-aware gating fell back so jobs are not silently dropped.",
            "action": "Check rustiron-host-status timer and observation export freshness.",
        }));
    }

    missed
}

/// Concise human-readable operator summary of a traffic-budget decision.
pub(crate) fn human(report: &Value) -> String {
    let mut out = String::new();
    let job = report["job"].as_str().unwrap_or("unknown");
    let decision = report["decision"].as_str().unwrap_or("unknown");
    let allow = report["allow_run"].as_bool().unwrap_or(false);
    let ov = report["override_mode"].as_str().unwrap_or("auto");
    let mstate = report["metrics"]["state"].as_str().unwrap_or("unknown");
    let missed = report["missed_job_count"].as_u64().unwrap_or(0);

    out.push_str(&format!(
        "Rustiron background budget ({job}): decision={decision} allow_run={allow} override={ov} metrics={mstate} missed_jobs={missed} autonomous_db_tuning=false\n"
    ));
    if let Some(reason) = report["reason"].as_str() {
        out.push_str(&format!("  reason: {reason}\n"));
    }
    if let Some(retry) = report["retry_after_seconds"].as_u64() {
        out.push_str(&format!("  retry_after_seconds: {retry}\n"));
    }
    if let Some(reasons) = report["metrics"]["busy_reasons"].as_array()
        && !reasons.is_empty()
    {
        let joined: Vec<&str> = reasons.iter().filter_map(Value::as_str).collect();
        out.push_str(&format!("  busy_reasons: {}\n", joined.join("; ")));
    }
    if let Some(items) = report["missed_jobs"].as_array() {
        for item in items {
            let kind = item["kind"].as_str().unwrap_or("missed");
            let r = item["reason"].as_str().unwrap_or("");
            out.push_str(&format!("  [MISSED/{kind}] {r}\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_795_600_000;

    fn calm_observation() -> Value {
        json!({
            "schema": "rustiron-lab-observation/1",
            "sites": [
                { "site_id": "cp02", "state": "succeeded", "ejected": false },
                { "site_id": "ej01", "state": "succeeded", "ejected": true },
                { "site_id": "px01", "state": "succeeded", "ejected": false, "kind": "proxy" }
            ],
            "captures": [
                { "capture_id": "cap_1", "site_id": "cp02", "state": "succeeded", "finished_at": NOW - 3600 }
            ],
            "machine": {
                "observed_at": NOW - 30,
                "cpu": { "count": 4, "load": [0.8, 0.7, 0.6] },
                "memory": { "total_bytes": 8_000_000_000_u64, "available_bytes": 5_000_000_000_u64 },
                "disk": { "total_bytes": 100_000_000_000_u64, "available_bytes": 50_000_000_000_u64 },
                "samples": [
                    { "t": NOW - 600, "cpu": 18, "mem": 35, "disk": 50 },
                    { "t": NOW - 300, "cpu": 20, "mem": 36, "disk": 50 },
                    { "t": NOW - 30, "cpu": 22, "mem": 37, "disk": 50 }
                ]
            }
        })
    }

    #[test]
    fn calm_host_runs_scheduled_work() {
        let obs = calm_observation();
        let rep = evaluate(
            &obs,
            &BudgetInput {
                job: JobKind::SiteCron,
                site: Some("cp02"),
                override_mode: OverrideMode::Auto,
                backlog_seconds: 0,
                consecutive_deferrals: 0,
                now: NOW,
            },
        );
        assert_eq!(rep["schema"], SCHEMA);
        assert_eq!(rep["decision"], "run");
        assert_eq!(rep["allow_run"], true);
        assert_eq!(rep["autonomous_db_tuning"], false);
        assert_eq!(rep["hides_missed_jobs"], false);
        assert_eq!(rep["missed_job_count"], 0);
    }

    #[test]
    fn bursty_traffic_defers_non_urgent_cron_with_explicit_reason() {
        let mut obs = calm_observation();
        obs["machine"]["samples"] = json!([
            { "t": NOW - 600, "cpu": 20, "mem": 40, "disk": 50 },
            { "t": NOW - 300, "cpu": 24, "mem": 41, "disk": 50 },
            { "t": NOW - 120, "cpu": 22, "mem": 42, "disk": 50 },
            { "t": NOW - 20, "cpu": 82, "mem": 48, "disk": 50 }
        ]);
        obs["machine"]["traffic"] = json!({ "req_per_sec": 74.5, "active_connections": 90 });

        let rep = evaluate(
            &obs,
            &BudgetInput {
                job: JobKind::SiteCron,
                site: Some("cp02"),
                override_mode: OverrideMode::Auto,
                backlog_seconds: 120,
                consecutive_deferrals: 1,
                now: NOW,
            },
        );
        assert_eq!(rep["decision"], "defer");
        assert_eq!(rep["allow_run"], false);
        assert_eq!(rep["metrics"]["burst_spike_detected"], true);
        assert_eq!(rep["retry_after_seconds"], 120);
        let reasons = rep["metrics"]["busy_reasons"].as_array().unwrap();
        assert!(reasons.len() >= 3);
    }

    #[test]
    fn stale_metrics_fall_back_safely_without_hiding_jobs() {
        let mut obs = calm_observation();
        obs["machine"]["observed_at"] = json!(NOW - 900);
        obs["machine"]["cpu"]["load"] = json!([8.0, 8.0, 8.0]);

        let rep = evaluate(
            &obs,
            &BudgetInput {
                job: JobKind::SiteCron,
                site: Some("cp02"),
                override_mode: OverrideMode::Auto,
                backlog_seconds: 0,
                consecutive_deferrals: 0,
                now: NOW,
            },
        );
        assert_eq!(rep["decision"], "run_stale_metrics_fallback");
        assert_eq!(rep["allow_run"], true);
        assert_eq!(rep["traffic_gating_active"], false);
        assert_eq!(rep["metrics"]["state"], "stale");
        assert_eq!(rep["missed_job_count"], 1);
        assert_eq!(rep["missed_jobs"][0]["kind"], "telemetry_stale_or_missing");
    }

    #[test]
    fn starvation_ceiling_overrides_busy_deferral() {
        let mut obs = calm_observation();
        obs["machine"]["cpu"]["load"] = json!([6.0, 5.0, 4.0]);

        let rep = evaluate(
            &obs,
            &BudgetInput {
                job: JobKind::SiteCron,
                site: Some("cp02"),
                override_mode: OverrideMode::Auto,
                backlog_seconds: 1800,
                consecutive_deferrals: 6,
                now: NOW,
            },
        );
        assert_eq!(rep["decision"], "run_starvation_override");
        assert_eq!(rep["allow_run"], true);
        assert_eq!(rep["backlog"]["starvation_reached"], true);
        assert_eq!(rep["backlog"]["starvation_remaining_seconds"], 0);
    }

    #[test]
    fn rpo_deadline_overrides_busy_traffic_and_surfaces_breach() {
        let mut obs = calm_observation();
        obs["machine"]["cpu"]["load"] = json!([6.0, 5.0, 4.0]);
        obs["captures"] = json!([
            { "capture_id": "cap_old", "site_id": "cp02", "state": "succeeded", "finished_at": NOW - (25 * 3600) }
        ]);

        let rep = evaluate(
            &obs,
            &BudgetInput {
                job: JobKind::BackupCapture,
                site: None,
                override_mode: OverrideMode::Auto,
                backlog_seconds: 600,
                consecutive_deferrals: 2,
                now: NOW,
            },
        );
        assert_eq!(rep["decision"], "run_rpo_override");
        assert_eq!(rep["allow_run"], true);
        assert_eq!(rep["rpo"]["at_risk_sites"], json!(["cp02"]));
        assert_eq!(rep["rpo"]["breached_sites"], json!(["cp02"]));
        assert!(
            rep["missed_jobs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m["kind"] == "rpo_objective_missed" && m["site"] == "cp02")
        );
    }

    #[test]
    fn critical_low_disk_blocks_auto_backup_and_surfaces_missed_job() {
        let mut obs = calm_observation();
        obs["machine"]["disk"]["available_bytes"] = json!(5_000_000_000_u64); // 5%

        let rep = evaluate(
            &obs,
            &BudgetInput {
                job: JobKind::BackupCapture,
                site: Some("cp02"),
                override_mode: OverrideMode::Auto,
                backlog_seconds: 0,
                consecutive_deferrals: 0,
                now: NOW,
            },
        );
        assert_eq!(rep["decision"], "block_low_disk");
        assert_eq!(rep["allow_run"], false);
        assert!(
            rep["missed_jobs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m["kind"] == "backup_blocked_low_disk")
        );
    }

    #[test]
    fn operator_disable_and_force_overrides_work_explicitly() {
        let mut obs = calm_observation();
        obs["machine"]["cpu"]["load"] = json!([8.0, 7.0, 6.0]);

        let disabled = evaluate(
            &obs,
            &BudgetInput {
                job: JobKind::Maintenance,
                site: None,
                override_mode: OverrideMode::Disable,
                backlog_seconds: 0,
                consecutive_deferrals: 0,
                now: NOW,
            },
        );
        assert_eq!(disabled["decision"], "run_operator_gate_disabled");
        assert_eq!(disabled["allow_run"], true);
        assert_eq!(disabled["traffic_gating_active"], false);

        let forced = evaluate(
            &obs,
            &BudgetInput {
                job: JobKind::BackupCapture,
                site: Some("cp02"),
                override_mode: OverrideMode::ForceRun,
                backlog_seconds: 0,
                consecutive_deferrals: 0,
                now: NOW,
            },
        );
        assert_eq!(forced["decision"], "run_operator_forced");
        assert_eq!(forced["allow_run"], true);
    }

    #[test]
    fn unsettled_running_capture_is_never_hidden() {
        let mut obs = calm_observation();
        obs["captures"] = json!([
            { "capture_id": "cap_ok", "site_id": "cp02", "state": "succeeded", "finished_at": NOW - 3600 },
            { "capture_id": "cap_stuck", "site_id": "cp02", "state": "running", "started_at": NOW - 1800 }
        ]);

        let rep = evaluate(
            &obs,
            &BudgetInput {
                job: JobKind::BackupCapture,
                site: Some("cp02"),
                override_mode: OverrideMode::Auto,
                backlog_seconds: 0,
                consecutive_deferrals: 0,
                now: NOW,
            },
        );
        assert_eq!(rep["rpo"]["unsettled_captures"], json!(["cap_stuck"]));
        assert!(
            rep["missed_jobs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m["kind"] == "unsettled_capture_blocking" && m["capture"] == "cap_stuck")
        );
    }
}
