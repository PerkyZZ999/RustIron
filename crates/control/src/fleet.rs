//! W618 (P28 Slice 1): Read-only multi-host inventory aggregation without
//! distributed implicit authority. Inspects independent per-host observations
//! and verifies host identity, signer epoch, cross-host grant isolation,
//! network partition / no-blind-replay boundaries, credential revocation,
//! observation staleness, and version skew. Never performs mutations or
//! claims a fleet-wide transaction.

use rustiron_contracts::escape_human;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// Output schema for `rustiron-control --aggregate-hosts`.
pub(crate) const SCHEMA: &str = "rustiron-fleet-inventory/1";
/// Expected input manifest schema for multi-host read-only aggregation.
pub(crate) const INPUT_SCHEMA: &str = "rustiron-fleet-observations/1";

/// Observations older than 5 minutes are flagged as stale.
const MAX_OBSERVATION_AGE_SECS: u64 = 300;
const MAX_CLOCK_SKEW_SECS: u64 = 60;
const MAX_HOSTS: usize = 128;

/// Aggregates independent per-host observations into a strictly read-only
/// multi-host inventory report at Unix timestamp `now`.
pub(crate) fn aggregate(manifest: &Value, now: u64) -> Value {
    if manifest["schema"].as_str() != Some(INPUT_SCHEMA) {
        return json!({
            "schema": SCHEMA,
            "evaluated_at": now,
            "valid_manifest": false,
            "error": "Manifest schema must be rustiron-fleet-observations/1.",
            "read_only": true,
            "distributed_implicit_authority": false,
            "fleet_wide_transaction": false,
            "blind_replay_on_partition": false,
            "single_host_standalone_preserved": true,
        });
    }

    let empty = Vec::new();
    let entries = manifest["hosts"].as_array().unwrap_or(&empty);
    let truncated = entries.len() > MAX_HOSTS;

    let mut seen_host_ids = BTreeSet::new();
    let mut duplicate_host_ids = BTreeSet::new();
    for entry in entries.iter().take(MAX_HOSTS) {
        if let Some(hid) = entry["host_id"].as_str()
            && !hid.is_empty()
            && !seen_host_ids.insert(hid.to_owned())
        {
            duplicate_host_ids.insert(hid.to_owned());
        }
    }

    let mut journal_versions: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut host_reports = Vec::new();

    let mut reachable_hosts = 0_usize;
    let mut partitioned_hosts = 0_usize;
    let mut revoked_hosts = 0_usize;
    let mut error_hosts = 0_usize;
    let mut identity_conflicts = 0_usize;
    let mut stale_hosts = 0_usize;
    let mut cross_host_grant_refusals = 0_usize;
    let mut total_sites = 0_usize;

    for entry in entries.iter().take(MAX_HOSTS) {
        let declared_id_raw = entry["host_id"].as_str().unwrap_or("");
        let declared_id = escape_human(declared_id_raw);
        let transport_state = entry["transport_state"].as_str().unwrap_or("error");
        let obs = &entry["observation"];

        let mut warnings = Vec::new();
        let mut identity_ok = !declared_id_raw.is_empty();
        if declared_id_raw.is_empty() {
            warnings.push("Missing declared host_id.".to_owned());
        }
        if duplicate_host_ids.contains(declared_id_raw) {
            identity_ok = false;
            warnings.push(format!(
                "duplicate_host_id_conflict: host_id `{declared_id}` appears more than once in fleet manifest."
            ));
        }

        let observed_id_raw = obs["host"]["host_id"].as_str();
        let observed_epoch_raw = obs["host"]["signer_epoch"]
            .as_str()
            .or_else(|| obs["host"]["epoch"].as_str());

        if let Some(obs_id) = observed_id_raw
            && !declared_id_raw.is_empty()
            && obs_id != declared_id_raw
        {
            identity_ok = false;
            warnings.push(format!(
                "host_identity_mismatch: manifest declared `{declared_id}` but observation reported `{}`.",
                escape_human(obs_id)
            ));
        }

        let (reachability, outcome_certainty, safe_to_blind_replay, credential_revoked) =
            match transport_state {
                "reachable" => {
                    reachable_hosts += 1;
                    ("reachable", "observed", false, false)
                }
                "partitioned" | "timeout" => {
                    partitioned_hosts += 1;
                    warnings.push(
                        "network_partition: host unreachable; do NOT blindly replay mutations. Reconcile by operation_id after connectivity returns."
                            .to_owned(),
                    );
                    ("partitioned", "unknown_partitioned", false, false)
                }
                "revoked_credential" => {
                    revoked_hosts += 1;
                    warnings.push(
                        "credential_revoked: remote access credential is revoked; re-issue scoped credential through operator approval."
                            .to_owned(),
                    );
                    ("revoked", "denied_revoked", false, true)
                }
                _ => {
                    error_hosts += 1;
                    warnings.push(
                        "transport_error: host observation failed; treat host state as unknown."
                            .to_owned(),
                    );
                    ("error", "unknown_error", false, false)
                }
            };

        if reachability == "reachable" && observed_epoch_raw.is_none() {
            identity_ok = false;
            warnings.push(
                "missing_host_epoch: reachable host observation lacks signer_epoch.".to_owned(),
            );
        }

        if !identity_ok {
            identity_conflicts += 1;
        }

        let (freshness, age_secs) = if reachability == "reachable" {
            let (f, age) = check_freshness(obs["machine"]["observed_at"].as_u64(), now);
            if f != "fresh" {
                stale_hosts += 1;
                warnings.push(format!(
                    "observation_{f}: host observation is not fresh (age={age:?}s)."
                ));
            }
            (f, age)
        } else {
            ("unavailable", None)
        };

        let journal_version = obs["host"]["journal_version"]
            .as_u64()
            .map(|v| v.to_string())
            .or_else(|| obs["host"]["journal_version"].as_str().map(escape_human));

        if reachability == "reachable"
            && let Some(ref jv) = journal_version
        {
            journal_versions
                .entry(jv.clone())
                .or_default()
                .push(declared_id.clone());
        }

        let site_count = obs["sites"].as_array().map_or(0, Vec::len);
        if reachability == "reachable" {
            total_sites += site_count;
        }

        let grant_checks = check_pending_grants(
            entry["pending_approval_grants"].as_array(),
            declared_id_raw,
            observed_epoch_raw,
            reachability,
        );
        let refused_here = grant_checks
            .iter()
            .filter(|g| g["eligible_for_host"].as_bool() != Some(true))
            .count();
        cross_host_grant_refusals += refused_here;

        host_reports.push(json!({
            "host_id": declared_id,
            "observed_host_id": observed_id_raw.map(escape_human),
            "host_epoch": observed_epoch_raw.map(escape_human),
            "identity_verified": identity_ok,
            "reachability": reachability,
            "outcome_certainty": outcome_certainty,
            "credential_revoked": credential_revoked,
            "safe_to_blind_replay": safe_to_blind_replay,
            "observation_freshness": freshness,
            "observation_age_seconds": age_secs,
            "journal_version": journal_version,
            "site_count": site_count,
            "per_host_lock_scope": "local_executor_journal_only",
            "independent_restore_authority": true,
            "pending_grant_checks": grant_checks,
            "warnings": warnings,
        }));
    }

    let skew_detected = journal_versions.len() > 1;
    let total_hosts = host_reports.len();

    json!({
        "schema": SCHEMA,
        "evaluated_at": now,
        "valid_manifest": true,
        "read_only": true,
        "distributed_implicit_authority": false,
        "fleet_wide_transaction": false,
        "blind_replay_on_partition": false,
        "single_host_standalone_preserved": true,
        "truncated": truncated,
        "summary": {
            "total_hosts": total_hosts,
            "reachable_hosts": reachable_hosts,
            "partitioned_hosts": partitioned_hosts,
            "revoked_hosts": revoked_hosts,
            "error_hosts": error_hosts,
            "identity_conflicts": identity_conflicts,
            "stale_hosts": stale_hosts,
            "cross_host_grant_refusals": cross_host_grant_refusals,
            "total_sites_observed": total_sites,
        },
        "version_skew": {
            "detected": skew_detected,
            "journal_versions": journal_versions,
        },
        "hosts": host_reports,
    })
}

fn check_freshness(observed_at: Option<u64>, now: u64) -> (&'static str, Option<i64>) {
    let Some(ts) = observed_at else {
        return ("missing", None);
    };
    if ts > now {
        let skew = ts - now;
        let age = -i64::try_from(skew).unwrap_or(i64::MAX);
        if skew > MAX_CLOCK_SKEW_SECS {
            ("stale", Some(age))
        } else {
            ("fresh", Some(age))
        }
    } else {
        let age = now - ts;
        let state = if age > MAX_OBSERVATION_AGE_SECS {
            "stale"
        } else {
            "fresh"
        };
        (state, Some(i64::try_from(age).unwrap_or(i64::MAX)))
    }
}

fn check_pending_grants(
    grants: Option<&Vec<Value>>,
    host_id: &str,
    observed_epoch: Option<&str>,
    reachability: &str,
) -> Vec<Value> {
    let Some(grants) = grants else {
        return Vec::new();
    };
    grants
        .iter()
        .take(64)
        .map(|g| {
            let grant_id = escape_human(g["grant_id"].as_str().unwrap_or("unknown"));
            let target_host = g["target_host_id"].as_str().unwrap_or("");
            let target_epoch = g["target_epoch"].as_str().unwrap_or("");
            let op_id = g["operation_id"].as_str().map(escape_human);

            let (eligible, refusal_reason) = if reachability != "reachable" {
                (false, Some("host_not_reachable_no_blind_replay"))
            } else if target_host.is_empty() || target_host != host_id {
                (false, Some("cross_host_approval_refused"))
            } else if observed_epoch.is_none_or(|ep| ep != target_epoch) {
                (false, Some("epoch_mismatch_refused"))
            } else {
                (true, None)
            };

            json!({
                "grant_id": grant_id,
                "operation_id": op_id,
                "target_host_id": escape_human(target_host),
                "target_epoch": escape_human(target_epoch),
                "eligible_for_host": eligible,
                "refusal_reason": refusal_reason,
            })
        })
        .collect()
}

/// Concise human-readable operator summary for multi-host inventory.
pub(crate) fn human(report: &Value) -> String {
    let mut out = String::new();
    let total = report["summary"]["total_hosts"].as_u64().unwrap_or(0);
    let reach = report["summary"]["reachable_hosts"].as_u64().unwrap_or(0);
    let part = report["summary"]["partitioned_hosts"].as_u64().unwrap_or(0);
    let rev = report["summary"]["revoked_hosts"].as_u64().unwrap_or(0);
    let skew = report["version_skew"]["detected"]
        .as_bool()
        .unwrap_or(false);
    let refused = report["summary"]["cross_host_grant_refusals"]
        .as_u64()
        .unwrap_or(0);

    out.push_str(&format!(
        "Rustiron multi-host inventory (read_only=true, fleet_wide_transaction=false, implicit_authority=false): hosts={total} reachable={reach} partitioned={part} revoked={rev} version_skew={skew} refused_grants={refused}\n"
    ));
    if let Some(hosts) = report["hosts"].as_array() {
        for h in hosts {
            let hid = h["host_id"].as_str().unwrap_or("unknown");
            let r = h["reachability"].as_str().unwrap_or("unknown");
            let ep = h["host_epoch"].as_str().unwrap_or("none");
            let jv = h["journal_version"].as_str().unwrap_or("?");
            let sites = h["site_count"].as_u64().unwrap_or(0);
            out.push_str(&format!(
                "  - {hid}: reachability={r} epoch={ep} journal_v={jv} sites={sites}\n"
            ));
            if let Some(warnings) = h["warnings"].as_array() {
                for w in warnings {
                    if let Some(text) = w.as_str() {
                        out.push_str(&format!("      [WARN] {text}\n"));
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_795_700_000;

    fn host_obs(id: &str, epoch: &str, jv: u64, obs_at: u64, sites: usize) -> Value {
        let site_arr: Vec<Value> = (0..sites)
            .map(|i| json!({ "site_id": format!("s{i}"), "state": "succeeded" }))
            .collect();
        json!({
            "host": {
                "host_id": id,
                "signer_epoch": epoch,
                "journal_version": jv
            },
            "machine": { "observed_at": obs_at },
            "sites": site_arr
        })
    }

    #[test]
    fn enforces_host_binding_partitions_revocation_skew_and_cross_host_grant_refusal() {
        let manifest = json!({
            "schema": INPUT_SCHEMA,
            "hosts": [
                {
                    "host_id": "host-a",
                    "transport_state": "reachable",
                    "observation": host_obs("host-a", "policy_3", 44, NOW - 15, 3),
                    "pending_approval_grants": [
                        { "grant_id": "g_ok", "operation_id": "op_1", "target_host_id": "host-a", "target_epoch": "policy_3" },
                        { "grant_id": "g_cross", "operation_id": "op_2", "target_host_id": "host-b", "target_epoch": "policy_3" },
                        { "grant_id": "g_epoch", "operation_id": "op_3", "target_host_id": "host-a", "target_epoch": "policy_2" }
                    ]
                },
                {
                    "host_id": "host-b",
                    "transport_state": "reachable",
                    "observation": host_obs("host-b", "policy_4", 43, NOW - 600, 2),
                    "pending_approval_grants": []
                },
                {
                    "host_id": "host-c",
                    "transport_state": "partitioned",
                    "observation": null,
                    "pending_approval_grants": [
                        { "grant_id": "g_part", "operation_id": "op_4", "target_host_id": "host-c", "target_epoch": "policy_1" }
                    ]
                },
                {
                    "host_id": "host-d",
                    "transport_state": "revoked_credential",
                    "observation": null,
                    "pending_approval_grants": []
                }
            ]
        });

        let rep = aggregate(&manifest, NOW);
        assert_eq!(rep["schema"], SCHEMA);
        assert_eq!(rep["valid_manifest"], true);
        assert_eq!(rep["read_only"], true);
        assert_eq!(rep["distributed_implicit_authority"], false);
        assert_eq!(rep["fleet_wide_transaction"], false);
        assert_eq!(rep["blind_replay_on_partition"], false);
        assert_eq!(rep["single_host_standalone_preserved"], true);

        assert_eq!(rep["summary"]["total_hosts"], 4);
        assert_eq!(rep["summary"]["reachable_hosts"], 2);
        assert_eq!(rep["summary"]["partitioned_hosts"], 1);
        assert_eq!(rep["summary"]["revoked_hosts"], 1);
        assert_eq!(rep["summary"]["stale_hosts"], 1);
        assert_eq!(rep["summary"]["total_sites_observed"], 5);
        assert_eq!(rep["summary"]["cross_host_grant_refusals"], 3);
        assert_eq!(rep["version_skew"]["detected"], true);

        // Verify host-a grant isolation details
        let g = rep["hosts"][0]["pending_grant_checks"].as_array().unwrap();
        assert_eq!(g[0]["eligible_for_host"], true);
        assert_eq!(g[1]["eligible_for_host"], false);
        assert_eq!(g[1]["refusal_reason"], "cross_host_approval_refused");
        assert_eq!(g[2]["eligible_for_host"], false);
        assert_eq!(g[2]["refusal_reason"], "epoch_mismatch_refused");

        // Verify partitioned host never allows blind replay
        assert_eq!(rep["hosts"][2]["outcome_certainty"], "unknown_partitioned");
        assert_eq!(rep["hosts"][2]["safe_to_blind_replay"], false);
        assert_eq!(
            rep["hosts"][2]["pending_grant_checks"][0]["refusal_reason"],
            "host_not_reachable_no_blind_replay"
        );
    }

    #[test]
    fn detects_spoofed_host_identity_and_duplicate_host_ids() {
        let manifest = json!({
            "schema": INPUT_SCHEMA,
            "hosts": [
                {
                    "host_id": "host-a",
                    "transport_state": "reachable",
                    "observation": host_obs("host-evil", "policy_3", 44, NOW - 10, 1)
                },
                {
                    "host_id": "host-a",
                    "transport_state": "reachable",
                    "observation": host_obs("host-a", "policy_3", 44, NOW - 10, 1)
                }
            ]
        });
        let rep = aggregate(&manifest, NOW);
        assert_eq!(rep["summary"]["identity_conflicts"], 2);
        assert_eq!(rep["hosts"][0]["identity_verified"], false);
        assert_eq!(rep["hosts"][1]["identity_verified"], false);
    }
}
