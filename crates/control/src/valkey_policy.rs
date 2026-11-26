//! W622 (P21 Slice 1): Optional per-site Valkey object-cache contract verifier.
//! Enforces workload-justified repeatable benefit over a tuned baseline,
//! private Unix socket (zero TCP), per-site credentials/UID/MCS/namespace
//! isolation, explicit maxmemory & safe eviction policy, graceful outage
//! bypass, staleness invalidation, clean disable, and strict private/auth/
//! cart/checkout safety.

use rustiron_contracts::escape_human;
use serde_json::{Value, json};
use std::collections::BTreeSet;

/// Output schema for `rustiron-control --verify-valkey-plan`.
pub(crate) const SCHEMA: &str = "rustiron-valkey-check/1";
/// Expected input schema.
pub(crate) const INPUT_SCHEMA: &str = "rustiron-valkey-plan/1";

const MIN_MATERIAL_BENEFIT_PCT: f64 = 10.0;
const MIN_EVIDENCE_REPEATS: u64 = 5;
const MIN_MEMORY_MIB: u64 = 16;
const MAX_SITE_MEMORY_MIB: u64 = 512;

/// Evaluates an optional per-site Valkey deployment plan against P21 rules.
pub(crate) fn verify(doc: &Value) -> Value {
    if doc["schema"].as_str() != Some(INPUT_SCHEMA) {
        return refused(
            "INVALID_SCHEMA",
            "Input schema must be rustiron-valkey-plan/1.",
        );
    }

    let host_budget_mib = doc["host_valkey_memory_budget_mib"].as_u64().unwrap_or(0);
    if host_budget_mib == 0 {
        return refused(
            "MISSING_RESOURCE_BUDGET",
            "Explicit host_valkey_memory_budget_mib > 0 is required.",
        );
    }

    let Some(sites) = doc["sites"].as_array() else {
        return refused("INVALID_SITES", "sites array is required.");
    };
    if sites.is_empty() || sites.len() > 32 {
        return refused("INVALID_SITES", "sites must contain 1..=32 entries.");
    }

    let mut seen_sites = BTreeSet::new();
    let mut seen_uids = BTreeSet::new();
    let mut seen_mcs = BTreeSet::new();
    let mut seen_sockets = BTreeSet::new();
    let mut seen_namespaces = BTreeSet::new();
    let mut seen_cred_files = BTreeSet::new();

    let mut failures = Vec::new();
    let mut site_reports = Vec::new();
    let mut total_mem_mib = 0_u64;

    for site in sites {
        let site_id = site["site_id"].as_str().unwrap_or("");
        if site_id.is_empty() || !seen_sites.insert(site_id.to_owned()) {
            failures.push(format!(
                "INVALID_SITE_ID: site_id `{}` missing or duplicated.",
                escape_human(site_id)
            ));
            continue;
        }
        let esc = escape_human(site_id);

        // 1. Workload justification (STOP: no material benefit)
        let ev = &site["workload_evidence"];
        let benefit_pct = ev["measured_benefit_percent"].as_f64().unwrap_or(0.0);
        let repeats = ev["randomized_repeats"].as_u64().unwrap_or(0);
        let tuned_baseline = ev["compared_against_tuned_baseline"].as_bool() == Some(true);
        if !tuned_baseline
            || !benefit_pct.is_finite()
            || benefit_pct < MIN_MATERIAL_BENEFIT_PCT
            || repeats < MIN_EVIDENCE_REPEATS
        {
            failures.push(format!(
                "NO_MATERIAL_BENEFIT_STOP: site `{esc}` lacks repeatable >= {MIN_MATERIAL_BENEFIT_PCT:.0}% benefit (>= {MIN_EVIDENCE_REPEATS} repeats) against a tuned baseline; do not add Valkey."
            ));
        }

        // 2. Private socket, credentials, identity, MCS, and namespace isolation
        let iso = &site["isolation"];
        let tcp_port = iso["tcp_port"].as_u64().unwrap_or(6379);
        let socket = iso["unix_socket"].as_str().unwrap_or("");
        let uid = iso["uid"].as_u64();
        let mcs = iso["mcs_category"].as_str().unwrap_or("");
        let ns = iso["namespace_prefix"].as_str().unwrap_or("");
        let cred_file = iso["acl_credentials_path"].as_str().unwrap_or("");
        let cred_mode = iso["acl_credentials_mode"].as_str().unwrap_or("");

        if tcp_port != 0 {
            failures.push(format!(
                "IDENTITY_ISOLATION_REGRESSION: site `{esc}` must set tcp_port=0 (private Unix socket only)."
            ));
        }
        if socket.is_empty()
            || !socket.starts_with("/run/rustiron-site-valkey/")
            || !seen_sockets.insert(socket.to_owned())
        {
            failures.push(format!(
                "IDENTITY_ISOLATION_REGRESSION: site `{esc}` lacks a unique private socket under /run/rustiron-site-valkey/."
            ));
        }
        if uid.is_none_or(|u| u < 1000 || !seen_uids.insert(u)) {
            failures.push(format!(
                "IDENTITY_ISOLATION_REGRESSION: site `{esc}` lacks a unique non-root UID."
            ));
        }
        if mcs.is_empty() || !seen_mcs.insert(mcs.to_owned()) {
            failures.push(format!(
                "IDENTITY_ISOLATION_REGRESSION: site `{esc}` lacks a unique SELinux MCS category."
            ));
        }
        if ns.is_empty()
            || !ns.starts_with(&format!("rs_{site_id}:"))
            || !seen_namespaces.insert(ns.to_owned())
        {
            failures.push(format!(
                "IDENTITY_ISOLATION_REGRESSION: site `{esc}` must use a unique site-scoped namespace_prefix starting with `rs_{esc}:`."
            ));
        }
        if cred_file.is_empty()
            || !seen_cred_files.insert(cred_file.to_owned())
            || !matches!(cred_mode, "0600" | "0400")
        {
            failures.push(format!(
                "IDENTITY_ISOLATION_REGRESSION: site `{esc}` requires a unique mode 0400/0600 per-site ACL credentials file."
            ));
        }

        // 3. Explicit memory & safe eviction policy
        let mem = site["limits"]["maxmemory_mib"].as_u64().unwrap_or(0);
        let eviction = site["limits"]["eviction_policy"].as_str().unwrap_or("");
        if !(MIN_MEMORY_MIB..=MAX_SITE_MEMORY_MIB).contains(&mem) {
            failures.push(format!(
                "MEMORY_ISOLATION_REGRESSION: site `{esc}` maxmemory_mib must be in {MIN_MEMORY_MIB}..={MAX_SITE_MEMORY_MIB}."
            ));
        }
        total_mem_mib = total_mem_mib.saturating_add(mem);
        if !matches!(eviction, "allkeys-lru" | "volatile-lru" | "allkeys-lfu") {
            failures.push(format!(
                "UNSAFE_EVICTION_POLICY: site `{esc}` eviction_policy `{}` must be allkeys-lru, volatile-lru, or allkeys-lfu (never noeviction).",
                escape_human(eviction)
            ));
        }

        // 4. Operational safety checks: outage fallback, staleness, clean disable, private/auth/cart/checkout safety
        let beh = &site["behavior"];
        if beh["outage_graceful_bypass"].as_bool() != Some(true) {
            failures.push(format!(
                "OUTAGE_BEHAVIOR_UNVERIFIED: site `{esc}` must gracefully bypass Valkey on outage without fatal errors."
            ));
        }
        if beh["staleness_invalidation_verified"].as_bool() != Some(true) {
            failures.push(format!(
                "STALENESS_BEHAVIOR_UNVERIFIED: site `{esc}` must verify object-cache invalidation and data-staleness bounds."
            ));
        }
        if beh["clean_disable_verified"].as_bool() != Some(true) {
            failures.push(format!(
                "CLEAN_DISABLE_UNVERIFIED: site `{esc}` must verify clean disable without residual drop-in failure."
            ));
        }
        if beh["private_auth_cart_checkout_safe"].as_bool() != Some(true) {
            failures.push(format!(
                "PRIVATE_CACHE_SAFETY_FAILED: site `{esc}` must verify private, auth, cart, and checkout routes remain uncached/isolated."
            ));
        }

        site_reports.push(json!({
            "site_id": esc,
            "measured_benefit_percent": benefit_pct,
            "maxmemory_mib": mem,
            "eviction_policy": escape_human(eviction),
            "unix_socket": escape_human(socket),
            "namespace_prefix": escape_human(ns),
        }));
    }

    if total_mem_mib > host_budget_mib {
        failures.push(format!(
            "MEMORY_ISOLATION_REGRESSION: total per-site Valkey memory ({total_mem_mib} MiB) exceeds host_valkey_memory_budget_mib ({host_budget_mib} MiB)."
        ));
    }

    let passed = failures.is_empty();
    json!({
        "schema": SCHEMA,
        "passed": passed,
        "mandatory_for_all_sites": false,
        "shared_multi_tenant_instance_allowed": false,
        "tcp_listener_allowed": false,
        "host_valkey_memory_budget_mib": host_budget_mib,
        "total_allocated_memory_mib": total_mem_mib,
        "failure_count": failures.len(),
        "failures": failures,
        "sites": site_reports,
    })
}

fn refused(code: &'static str, reason: &'static str) -> Value {
    json!({
        "schema": SCHEMA,
        "passed": false,
        "mandatory_for_all_sites": false,
        "shared_multi_tenant_instance_allowed": false,
        "tcp_listener_allowed": false,
        "failure_count": 1,
        "failures": [format!("{code}: {reason}")],
        "sites": [],
    })
}

/// Concise human-readable operator summary for P21 Valkey verification.
pub(crate) fn human(report: &Value) -> String {
    let passed = report["passed"].as_bool().unwrap_or(false);
    let fails = report["failure_count"].as_u64().unwrap_or(0);
    let alloc = report["total_allocated_memory_mib"].as_u64().unwrap_or(0);
    let budget = report["host_valkey_memory_budget_mib"]
        .as_u64()
        .unwrap_or(0);
    let mut out = format!(
        "Rustiron per-site Valkey check (P21): passed={passed} failures={fails} memory={alloc}/{budget}MiB mandatory=false shared_instance=false\n"
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

    fn valid_site(id: &str, uid: u64, mcs: &str, mem: u64) -> Value {
        json!({
            "site_id": id,
            "workload_evidence": {
                "compared_against_tuned_baseline": true,
                "measured_benefit_percent": 22.5,
                "randomized_repeats": 5
            },
            "isolation": {
                "tcp_port": 0,
                "unix_socket": format!("/run/rustiron-site-valkey/rs_{id}/valkey.sock"),
                "uid": uid,
                "mcs_category": mcs,
                "namespace_prefix": format!("rs_{id}:wp:"),
                "acl_credentials_path": format!("/srv/sites/rs_{id}/private/valkey.acl"),
                "acl_credentials_mode": "0600"
            },
            "limits": {
                "maxmemory_mib": mem,
                "eviction_policy": "allkeys-lru"
            },
            "behavior": {
                "outage_graceful_bypass": true,
                "staleness_invalidation_verified": true,
                "clean_disable_verified": true,
                "private_auth_cart_checkout_safe": true
            }
        })
    }

    #[test]
    fn allows_workload_justified_isolated_per_site_valkey() {
        let doc = json!({
            "schema": INPUT_SCHEMA,
            "host_valkey_memory_budget_mib": 256,
            "sites": [valid_site("shop1", 2101, "c20,c21", 128)]
        });
        let rep = verify(&doc);
        assert_eq!(rep["passed"], true);
        assert_eq!(rep["mandatory_for_all_sites"], false);
        assert_eq!(rep["shared_multi_tenant_instance_allowed"], false);
        assert_eq!(rep["tcp_listener_allowed"], false);
    }

    #[test]
    fn refuses_no_benefit_tcp_shared_isolation_unsafe_eviction_and_over_budget() {
        let mut s = valid_site("shop1", 2101, "c20,c21", 200);
        s["workload_evidence"]["measured_benefit_percent"] = json!(2.0);
        s["isolation"]["tcp_port"] = json!(6379);
        s["limits"]["eviction_policy"] = json!("noeviction");
        s["behavior"]["private_auth_cart_checkout_safe"] = json!(false);

        let doc = json!({
            "schema": INPUT_SCHEMA,
            "host_valkey_memory_budget_mib": 128,
            "sites": [s]
        });
        let rep = verify(&doc);
        assert_eq!(rep["passed"], false);
        let text = rep["failures"].to_string();
        assert!(text.contains("NO_MATERIAL_BENEFIT_STOP"));
        assert!(text.contains("IDENTITY_ISOLATION_REGRESSION"));
        assert!(text.contains("UNSAFE_EVICTION_POLICY"));
        assert!(text.contains("PRIVATE_CACHE_SAFETY_FAILED"));
        assert!(text.contains("MEMORY_ISOLATION_REGRESSION"));
    }
}
