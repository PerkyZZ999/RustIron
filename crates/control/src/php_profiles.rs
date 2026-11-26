//! W621 (P20 Slice 1): Deliberate second PHP profile contract verifier.
//! Enforces a closed two-profile allowlist (`php84_wp_v1`, `php85_wp_v1`),
//! upstream security EOL enforcement, strict per-site socket/UID/MCS/cgroup/
//! OPcache/private-state isolation (zero shared isolation shortcuts), extension
//! compatibility, and mandatory pre-switch backup + rollback preconditions.

use rustiron_contracts::escape_human;
use serde_json::{Value, json};
use std::collections::BTreeSet;

/// Output schema for `rustiron-control --verify-php-profile`.
pub(crate) const SCHEMA: &str = "rustiron-php-profile-check/1";
/// Expected input schema.
pub(crate) const INPUT_SCHEMA: &str = "rustiron-php-profile-plan/1";

const WARN_BEFORE_EOL_SECS: u64 = 180 * 24 * 3600;
const MAX_PRE_SWITCH_BACKUP_AGE_SECS: u64 = 24 * 3600;

struct ProfileSpec {
    id: &'static str,
    series: &'static str,
    package: &'static str,
    binary: &'static str,
    eol_date: &'static str,
    eol_unix: u64,
    extra_idle_rss_mib: u64,
}

const PROFILES: [ProfileSpec; 2] = [
    ProfileSpec {
        id: "php84_wp_v1",
        series: "8.4",
        package: "lsphp84",
        binary: "/usr/local/lsws/lsphp84/bin/lsphp",
        eol_date: "2028-12-31",
        eol_unix: 1_861_833_600,
        extra_idle_rss_mib: 0,
    },
    ProfileSpec {
        id: "php85_wp_v1",
        series: "8.5",
        package: "lsphp85",
        binary: "/usr/local/lsws/lsphp85/bin/lsphp",
        eol_date: "2029-12-31",
        eol_unix: 1_893_369_600,
        extra_idle_rss_mib: 38,
    },
];

fn lookup_profile(id: &str) -> Option<&'static ProfileSpec> {
    PROFILES.iter().find(|p| p.id == id)
}

/// Evaluates a P20 multi-profile site placement or version-switch plan at `now`.
pub(crate) fn verify(doc: &Value, now: u64) -> Value {
    if doc["schema"].as_str() != Some(INPUT_SCHEMA) {
        return refused(
            now,
            "INVALID_SCHEMA",
            "Input schema must be rustiron-php-profile-plan/1.",
        );
    }

    let Some(sites) = doc["sites"].as_array() else {
        return refused(now, "INVALID_SITES", "sites array is required.");
    };
    if sites.is_empty() || sites.len() > 64 {
        return refused(now, "INVALID_SITES", "sites must contain 1..=64 entries.");
    }

    let mut seen_site_ids = BTreeSet::new();
    let mut seen_uids = BTreeSet::new();
    let mut seen_mcs = BTreeSet::new();
    let mut seen_sockets = BTreeSet::new();
    let mut seen_private_dirs = BTreeSet::new();
    let mut seen_opcache_dirs = BTreeSet::new();

    let mut site_reports = Vec::new();
    let mut failures = Vec::new();
    let mut warnings = Vec::new();
    let mut used_profiles = BTreeSet::new();

    for site in sites {
        let site_id = site["site_id"].as_str().unwrap_or("");
        let profile_id = site["target_profile"].as_str().unwrap_or("");
        let prev_profile_id = site["current_profile"].as_str();

        if site_id.is_empty() || !seen_site_ids.insert(site_id.to_owned()) {
            failures.push(format!(
                "DUPLICATE_OR_EMPTY_SITE_ID: site_id `{}` invalid or repeated.",
                escape_human(site_id)
            ));
            continue;
        }

        let Some(spec) = lookup_profile(profile_id) else {
            failures.push(format!(
                "UNSUPPORTED_PHP_PROFILE: `{}` on site `{}` is outside the closed P20 allowlist (php84_wp_v1, php85_wp_v1); 'all PHP versions' is forbidden.",
                escape_human(profile_id),
                escape_human(site_id)
            ));
            continue;
        };
        used_profiles.insert(spec.id);

        if now >= spec.eol_unix {
            failures.push(format!(
                "PROFILE_EOL_EXCEEDED: profile `{}` reached upstream EOL on {}.",
                spec.id, spec.eol_date
            ));
        } else if spec.eol_unix.saturating_sub(now) <= WARN_BEFORE_EOL_SECS {
            warnings.push(format!(
                "PROFILE_EOL_SOON: profile `{}` reaches EOL on {} (within 180 days).",
                spec.id, spec.eol_date
            ));
        }

        // Strict isolation checks (no shared UID, MCS, socket, OPcache, private tmp, or missing cgroup/SELinux).
        let uid = site["isolation"]["uid"].as_u64();
        let mcs = site["isolation"]["mcs_category"].as_str().unwrap_or("");
        let socket = site["isolation"]["socket_path"].as_str().unwrap_or("");
        let priv_dir = site["isolation"]["private_tmp_dir"].as_str().unwrap_or("");
        let opcache_dir = site["isolation"]["opcache_dir"].as_str().unwrap_or("");
        let mem_max_mib = site["isolation"]["cgroup_memory_max_mib"]
            .as_u64()
            .unwrap_or(0);
        let cpu_quota_pct = site["isolation"]["cgroup_cpu_quota_percent"]
            .as_u64()
            .unwrap_or(0);
        let selinux_domain = site["isolation"]["selinux_domain"].as_str().unwrap_or("");

        if uid.is_none_or(|u| u < 1000 || !seen_uids.insert(u)) {
            failures.push(format!(
                "SHARED_ISOLATION_REFUSED: site `{}` lacks a unique non-root UID.",
                escape_human(site_id)
            ));
        }
        if mcs.is_empty() || !seen_mcs.insert(mcs.to_owned()) {
            failures.push(format!(
                "SHARED_ISOLATION_REFUSED: site `{}` lacks a unique SELinux MCS category.",
                escape_human(site_id)
            ));
        }
        if selinux_domain != "rustiron_php_t" {
            failures.push(format!(
                "SHARED_ISOLATION_REFUSED: site `{}` must run in confined domain rustiron_php_t.",
                escape_human(site_id)
            ));
        }
        if socket.is_empty()
            || !socket.starts_with("/run/rustiron-site-php/")
            || !seen_sockets.insert(socket.to_owned())
        {
            failures.push(format!(
                "SHARED_ISOLATION_REFUSED: site `{}` lacks a unique private socket under /run/rustiron-site-php/.",
                escape_human(site_id)
            ));
        }
        if priv_dir.is_empty() || !seen_private_dirs.insert(priv_dir.to_owned()) {
            failures.push(format!(
                "SHARED_ISOLATION_REFUSED: site `{}` lacks a unique private tmp/session directory.",
                escape_human(site_id)
            ));
        }
        if opcache_dir.is_empty() || !seen_opcache_dirs.insert(opcache_dir.to_owned()) {
            failures.push(format!(
                "SHARED_ISOLATION_REFUSED: site `{}` lacks a unique per-site OPcache directory.",
                escape_human(site_id)
            ));
        }
        if mem_max_mib == 0 || cpu_quota_pct == 0 {
            failures.push(format!(
                "MISSING_CGROUP_LIMITS: site `{}` must set explicit cgroup MemoryMax and CPUQuota.",
                escape_human(site_id)
            ));
        }

        // Mixed-version switch checks: require fresh <24h backup capture, compatibility pass, and rollback plan.
        let is_switch = prev_profile_id.is_some_and(|prev| prev != spec.id);
        if is_switch {
            if let Some(prev) = prev_profile_id
                && lookup_profile(prev).is_none()
            {
                failures.push(format!(
                    "ROLLBACK_PRECONDITION_MISSING: site `{}` previous profile `{}` is not a known rollback profile.",
                    escape_human(site_id),
                    escape_human(prev)
                ));
            }
            let backup_at = site["switch"]["latest_backup_finished_at"].as_u64();
            if backup_at.is_none_or(|ts| now.saturating_sub(ts) > MAX_PRE_SWITCH_BACKUP_AGE_SECS) {
                failures.push(format!(
                    "ROLLBACK_PRECONDITION_MISSING: site `{}` profile switch requires a succeeded P03 backup within 24 h.",
                    escape_human(site_id)
                ));
            }
            if site["switch"]["extensions_compatible"].as_bool() != Some(true) {
                failures.push(format!(
                    "COMPATIBILITY_NOT_VERIFIED: site `{}` profile switch requires verified extension compatibility.",
                    escape_human(site_id)
                ));
            }
            if site["switch"]["rollback_plan_ready"].as_bool() != Some(true) {
                failures.push(format!(
                    "ROLLBACK_PRECONDITION_MISSING: site `{}` profile switch requires a tested rollback or forward-repair plan.",
                    escape_human(site_id)
                ));
            }
        }

        site_reports.push(json!({
            "site_id": escape_human(site_id),
            "target_profile": spec.id,
            "series": spec.series,
            "package": spec.package,
            "binary": spec.binary,
            "eol_date": spec.eol_date,
            "version_switch": is_switch,
            "rollback_profile": prev_profile_id.map(escape_human),
            "selinux_domain": escape_human(selinux_domain),
        }));
    }

    let extra_memory_cost_mib: u64 = PROFILES
        .iter()
        .filter(|p| used_profiles.contains(p.id))
        .map(|p| p.extra_idle_rss_mib)
        .sum();

    let passed = failures.is_empty();
    json!({
        "schema": SCHEMA,
        "evaluated_at": now,
        "passed": passed,
        "all_php_versions_supported": false,
        "shared_isolation_shortcuts_allowed": false,
        "supported_profiles": PROFILES.iter().map(|p| json!({
            "id": p.id,
            "series": p.series,
            "package": p.package,
            "eol_date": p.eol_date,
            "extra_idle_rss_mib": p.extra_idle_rss_mib,
        })).collect::<Vec<_>>(),
        "active_profiles_used": used_profiles.into_iter().collect::<Vec<_>>(),
        "estimated_extra_profile_memory_mib": extra_memory_cost_mib,
        "failure_count": failures.len(),
        "failures": failures,
        "warnings": warnings,
        "sites": site_reports,
    })
}

fn refused(now: u64, code: &'static str, reason: &'static str) -> Value {
    json!({
        "schema": SCHEMA,
        "evaluated_at": now,
        "passed": false,
        "all_php_versions_supported": false,
        "shared_isolation_shortcuts_allowed": false,
        "failure_count": 1,
        "failures": [format!("{code}: {reason}")],
        "warnings": [],
        "sites": [],
    })
}

/// Concise human-readable operator summary of a P20 PHP profile verification.
pub(crate) fn human(report: &Value) -> String {
    let passed = report["passed"].as_bool().unwrap_or(false);
    let fails = report["failure_count"].as_u64().unwrap_or(0);
    let cost = report["estimated_extra_profile_memory_mib"]
        .as_u64()
        .unwrap_or(0);
    let mut out = format!(
        "Rustiron PHP profile check (P20): passed={passed} failures={fails} extra_idle_rss_mib={cost} all_versions=false shared_isolation=false\n"
    );
    if let Some(items) = report["failures"].as_array() {
        for f in items {
            if let Some(s) = f.as_str() {
                out.push_str(&format!("  [FAIL] {s}\n"));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_795_900_000;

    fn site_entry(
        id: &str,
        current: &str,
        target: &str,
        uid: u64,
        mcs: &str,
        backup_at: u64,
    ) -> Value {
        json!({
            "site_id": id,
            "current_profile": current,
            "target_profile": target,
            "isolation": {
                "uid": uid,
                "mcs_category": mcs,
                "selinux_domain": "rustiron_php_t",
                "socket_path": format!("/run/rustiron-site-php/{target}_rs_{id}.sock"),
                "private_tmp_dir": format!("/srv/sites/rs_{id}/private/tmp"),
                "opcache_dir": format!("/srv/sites/rs_{id}/private/opcache_{target}"),
                "cgroup_memory_max_mib": 256,
                "cgroup_cpu_quota_percent": 100
            },
            "switch": {
                "latest_backup_finished_at": backup_at,
                "extensions_compatible": true,
                "rollback_plan_ready": true
            }
        })
    }

    #[test]
    fn allows_isolated_mixed_php84_and_php85_sites_with_rollback_preconditions() {
        let doc = json!({
            "schema": INPUT_SCHEMA,
            "sites": [
                site_entry("cp02", "php84_wp_v1", "php84_wp_v1", 2001, "c1,c2", NOW - 3600),
                site_entry("blog85", "php84_wp_v1", "php85_wp_v1", 2002, "c3,c4", NOW - 1800)
            ]
        });
        let rep = verify(&doc, NOW);
        assert_eq!(rep["passed"], true);
        assert_eq!(rep["all_php_versions_supported"], false);
        assert_eq!(rep["shared_isolation_shortcuts_allowed"], false);
        assert_eq!(rep["estimated_extra_profile_memory_mib"], 38);
        assert_eq!(rep["failure_count"], 0);
    }

    #[test]
    fn refuses_unsupported_php_versions_shared_isolation_and_missing_backup_rollback() {
        let mut s1 = site_entry(
            "cp02",
            "php84_wp_v1",
            "php74_legacy",
            2001,
            "c1,c2",
            NOW - 60,
        );
        s1["isolation"]["socket_path"] = json!("/run/rustiron-site-php/shared.sock");
        let rep = verify(&json!({ "schema": INPUT_SCHEMA, "sites": [s1] }), NOW);
        assert_eq!(rep["passed"], false);
        assert!(
            rep["failures"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f.as_str().unwrap().contains("UNSUPPORTED_PHP_PROFILE"))
        );

        // Shared socket + shared MCS + stale backup on switch
        let a = site_entry("s1", "php84_wp_v1", "php84_wp_v1", 2001, "c1,c2", NOW - 60);
        let mut b = site_entry(
            "s2",
            "php84_wp_v1",
            "php85_wp_v1",
            2001,
            "c1,c2",
            NOW - (30 * 3600),
        );
        b["isolation"]["socket_path"] = a["isolation"]["socket_path"].clone();
        let rep2 = verify(&json!({ "schema": INPUT_SCHEMA, "sites": [a, b] }), NOW);
        assert_eq!(rep2["passed"], false);
        let joined = rep2["failures"].to_string();
        assert!(joined.contains("SHARED_ISOLATION_REFUSED"));
        assert!(joined.contains("ROLLBACK_PRECONDITION_MISSING"));
    }
}
