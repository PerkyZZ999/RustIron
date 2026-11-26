//! W379: display facts for the read-only observation (`observe`) that the
//! console needs: capture consistency labels, unclaimed snapshots, probe
//! refusal codes, page-cache state, recorded quota limits and page-cache
//! operation kinds. Every value comes from the journal; nothing here reads
//! the host. Grant ids, nonce columns and secrets stay out.
//!
//! W396 (D-045) adds the signed bytes: per admission the recorded plan and
//! grant digests, and the exact canonical plan and grant the journal stored
//! with the verified issuer and signer-policy epoch. A grant's own bytes
//! carry its nonce; a nonce is a signed, single-use replay identity that the
//! journal has already consumed, not a secret. The detached signature, keys
//! and secrets are never stored or shown.
use rustiron_journal::{
    ObservedAdmission, ObservedCapture, ObservedOperation, ObservedProvision, PLAN_NAMESPACE,
};
use serde_json::{Map, Value, json};

use crate::quota::RecordedQuota;

/// W396: each admission with its recorded digests and, when stored, its
/// signer facts and the SHA-256 and length of its plan and grant. The bytes
/// themselves are in [`signed_objects`], keyed by that SHA-256, so the runs
/// of one standing grant carry one copy. `signed` is null for an admission
/// recorded before journal v20.
pub(crate) fn admissions(admissions: &[ObservedAdmission]) -> Value {
    admissions
        .iter()
        .map(|admission| {
            let signed = admission.signed.as_ref().map(|signed| {
                json!({
                    "issuer": signed.issuer,
                    "signer_policy_epoch": signed.signer_policy_epoch,
                    "verification": signed.verification,
                    "namespace": PLAN_NAMESPACE,
                    "plan": {
                        "sha256": signed.plan_sha256, "bytes": signed.plan_bytes,
                        "stored": signed.plan.is_some(),
                    },
                    "grant": {
                        "sha256": signed.grant_sha256, "bytes": signed.grant_bytes,
                        "stored": signed.grant.is_some(),
                    },
                })
            });
            json!({
                "operation_id": admission.operation_id,
                "kind": admission.source,
                "plan_digest": admission.plan_digest,
                "grant_digest": admission.grant_digest,
                "signed": signed,
            })
        })
        .collect()
}

/// W396: every stored canonical object once, keyed by its SHA-256.
pub(crate) fn signed_objects(admissions: &[ObservedAdmission]) -> Value {
    let mut objects = Map::new();
    for signed in admissions.iter().filter_map(|a| a.signed.as_ref()) {
        for (sha256, text) in [
            (&signed.plan_sha256, &signed.plan),
            (&signed.grant_sha256, &signed.grant),
        ] {
            if let Some(text) = text {
                objects.insert(sha256.clone(), Value::from(text.as_str()));
            }
        }
    }
    Value::Object(objects)
}

fn lower_hex64(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// The D-021 option E label of a succeeded capture, as its receipt states
/// it: an unlabelled success reads `unmatched` / `not_checked`. Null for a
/// capture that did not succeed.
pub(crate) fn capture_consistency(capture: &ObservedCapture) -> Value {
    if capture.state != "succeeded" {
        return Value::Null;
    }
    let (label, reason) = match &capture.consistency {
        Some((label, reason)) => (label.as_str(), reason.as_deref()),
        None => ("unmatched", Some("not_checked")),
    };
    json!({"label": label, "reason": reason})
}

/// The snapshot a settled `failed` capture keeps only as unclaimed evidence
/// (W366). Null on any other row or a malformed id.
pub(crate) fn unclaimed_snapshot(capture: &ObservedCapture) -> Value {
    match capture.unclaimed_snapshot_id.as_deref() {
        Some(id) if capture.state == "failed" && lower_hex64(id) => Value::from(id),
        _ => Value::Null,
    }
}

/// The stored `refused` code of a probe receipt (W371, W373), when it is a
/// stable upper-case code. Null otherwise.
pub(crate) fn probe_refusal(receipt: Option<&str>) -> Value {
    let Some(value) = receipt.and_then(|text| serde_json::from_str::<Value>(text).ok()) else {
        return Value::Null;
    };
    match value["refused"].as_str() {
        Some(code)
            if (1..=64).contains(&code.len())
                && code.starts_with(|c: char| c.is_ascii_uppercase())
                && code
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_') =>
        {
            Value::from(code)
        }
        _ => Value::Null,
    }
}

/// Display kind and site of a recorded operation.
pub(crate) fn operation_kind(operation: &ObservedOperation) -> (&'static str, Option<&str>) {
    if let Some(site) = operation.ejected_site.as_deref() {
        return ("site_eject", Some(site));
    }
    match &operation.page_cache {
        Some((site, true)) => ("page_cache_opt_in", Some(site.as_str())),
        Some((site, false)) => ("page_cache_opt_out", Some(site.as_str())),
        None => ("config_activate", None),
    }
}

/// The site's latest succeeded page-cache change, or null when none succeeded.
/// W395: an opt-in with the cache-on recipe reads `cache_on`.
pub(crate) fn page_cache_state(provision: &ObservedProvision) -> Value {
    match provision.page_cache {
        Some(true)
            if provision.page_cache_recipe.as_deref()
                == Some("litespeed_cache_793_cache_on_v1") =>
        {
            Value::from("cache_on")
        }
        Some(true) => Value::from("opted_in"),
        Some(false) => Value::from("opted_out"),
        None => Value::Null,
    }
}

/// The quota the journal recorded for a site: the newest signed change
/// (W534), else the limits a re-adoption verified, else the Directories step
/// plan (W335). Live usage is not read
/// here; `export SITE` reads it.
pub(crate) fn recorded_quota(provision: &ObservedProvision) -> Value {
    // W534 (D-088): a signed quota change replaces the earlier limits.
    if let Some((kib, inodes)) = provision.changed_quota {
        return json!({
            "state": "enforced",
            "source": "quota_change",
            "block_hard_kib": kib,
            "inode_hard": inodes,
        });
    }
    if let Some((kib, inodes)) = provision.adopted_quota {
        return json!({
            "state": "enforced",
            "source": "readoption",
            "block_hard_kib": kib,
            "inode_hard": inodes,
        });
    }
    crate::quota::recorded_json(
        provision
            .directories_resource
            .as_deref()
            .map(RecordedQuota::parse),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SNAPSHOT: &str = "a50c8b74e3c0f1d2a50c8b74e3c0f1d2a50c8b74e3c0f1d2a50c8b74e3c0f1d2";

    fn capture(state: &str) -> ObservedCapture {
        ObservedCapture {
            operation_id: "op_cap".to_owned(),
            site_id: "blog13".to_owned(),
            state: state.to_owned(),
            snapshot_id: (state == "succeeded").then(|| SNAPSHOT.to_owned()),
            started_at: 1,
            finished_at: (state != "running").then_some(2),
            method: Some("site_files_db_v1".to_owned()),
            retention_days: Some(30),
            files: None,
            bytes: None,
            manifest_sha256: None,
            manifest_entries: None,
            manifest_regular_bytes: None,
            manifest_truncated: None,
            consistency: None,
            unclaimed_snapshot_id: None,
            retention: None,
            refusal: None,
        }
    }

    fn provision() -> ObservedProvision {
        ObservedProvision {
            operation_id: "prov_blog1".to_owned(),
            site_id: "blog1".to_owned(),
            hostname: "blog1.example.test".to_owned(),
            state: "succeeded".to_owned(),
            steps_done: 8,
            steps_recorded: 8,
            failed_step: None,
            page_cache: None,
            page_cache_recipe: None,
            directories_resource: None,
            adopted_quota: None,
            changed_quota: None,
            proxy_ports: Vec::new(),
            alias_hostname: None,
            app_runtime: None,
            app_active_release: None,
        }
    }

    fn operation() -> ObservedOperation {
        ObservedOperation {
            operation_id: "op_act".to_owned(),
            resource_id: "ols_lab_listener".to_owned(),
            target_generation: "generation_2".to_owned(),
            state: "succeeded".to_owned(),
            effect_attempted: true,
            expires_at: 10,
            ejected_site: None,
            page_cache: None,
        }
    }

    #[test]
    fn a_succeeded_capture_states_its_label_and_an_unlabelled_one_reads_not_checked() {
        let mut matched = capture("succeeded");
        matched.consistency = Some(("matched".to_owned(), None));
        assert_eq!(
            capture_consistency(&matched),
            json!({"label": "matched", "reason": null})
        );
        assert_eq!(
            capture_consistency(&capture("succeeded")),
            json!({"label": "unmatched", "reason": "not_checked"})
        );
        assert_eq!(capture_consistency(&capture("failed")), Value::Null);
        assert_eq!(capture_consistency(&capture("running")), Value::Null);
    }

    #[test]
    fn only_a_failed_capture_names_a_well_formed_unclaimed_snapshot() {
        let mut settled = capture("failed");
        settled.unclaimed_snapshot_id = Some(SNAPSHOT.to_owned());
        assert_eq!(unclaimed_snapshot(&settled), Value::from(SNAPSHOT));
        settled.unclaimed_snapshot_id = Some(SNAPSHOT.to_uppercase());
        assert_eq!(unclaimed_snapshot(&settled), Value::Null);
        let mut succeeded = capture("succeeded");
        succeeded.unclaimed_snapshot_id = Some(SNAPSHOT.to_owned());
        assert_eq!(unclaimed_snapshot(&succeeded), Value::Null);
        assert_eq!(unclaimed_snapshot(&capture("failed")), Value::Null);
    }

    #[test]
    fn a_probe_refusal_is_the_stored_code_or_nothing() {
        let refused =
            r#"{"receipt_schema":"rustiron-restore-probe/2","refused":"NOT_ADMITTED_FOR_EFFECT"}"#;
        assert_eq!(
            probe_refusal(Some(refused)),
            Value::from("NOT_ADMITTED_FOR_EFFECT")
        );
        assert_eq!(
            probe_refusal(Some(r#"{"refused":"rm -rf /"}"#)),
            Value::Null
        );
        assert_eq!(probe_refusal(Some(r#"{"refused":"_X"}"#)), Value::Null);
        assert_eq!(probe_refusal(Some(r#"{"fields":{}}"#)), Value::Null);
        assert_eq!(probe_refusal(Some("not json")), Value::Null);
        assert_eq!(probe_refusal(None), Value::Null);
        let long = format!(r#"{{"refused":"{}"}}"#, "A".repeat(65));
        assert_eq!(probe_refusal(Some(&long)), Value::Null);
    }

    #[test]
    fn page_cache_operations_have_their_own_kind_and_site() {
        assert_eq!(operation_kind(&operation()), ("config_activate", None));
        let mut opt_in = operation();
        opt_in.page_cache = Some(("blog1".to_owned(), true));
        assert_eq!(
            operation_kind(&opt_in),
            ("page_cache_opt_in", Some("blog1"))
        );
        let mut opt_out = operation();
        opt_out.page_cache = Some(("blog1".to_owned(), false));
        assert_eq!(
            operation_kind(&opt_out),
            ("page_cache_opt_out", Some("blog1"))
        );
        let mut eject = operation();
        eject.ejected_site = Some("blog9".to_owned());
        assert_eq!(operation_kind(&eject), ("site_eject", Some("blog9")));
    }

    #[test]
    fn page_cache_state_is_the_latest_succeeded_change_or_null() {
        let mut site = provision();
        assert_eq!(page_cache_state(&site), Value::Null);
        site.page_cache = Some(true);
        assert_eq!(page_cache_state(&site), Value::from("opted_in"));
        site.page_cache = Some(false);
        assert_eq!(page_cache_state(&site), Value::from("opted_out"));
        // W395: the cache-on recipe.
        site.page_cache_recipe = Some("litespeed_cache_793_cache_on_v1".to_owned());
        assert_eq!(page_cache_state(&site), Value::from("opted_out"));
        site.page_cache = Some(true);
        assert_eq!(page_cache_state(&site), Value::from("cache_on"));
        site.page_cache_recipe = Some("litespeed_cache_793_v1".to_owned());
        assert_eq!(page_cache_state(&site), Value::from("opted_in"));
    }

    #[test]
    fn recorded_quota_follows_the_journal_and_never_guesses() {
        let mut site = provision();
        assert_eq!(recorded_quota(&site), json!({"state": "not_attempted"}));
        site.directories_resource = Some("dirs".to_owned());
        assert_eq!(recorded_quota(&site), json!({"state": "not_recorded"}));
        site.directories_resource =
            Some("dirs quota=enforced kib=5242880 inodes=500000".to_owned());
        assert_eq!(
            recorded_quota(&site),
            json!({"state": "enforced", "source": "policy", "block_hard_kib": 5_242_880, "inode_hard": 500_000})
        );
        site.directories_resource = Some("dirs quota=bogus".to_owned());
        assert_eq!(recorded_quota(&site), json!({"state": "malformed"}));
        site.adopted_quota = Some((262_144, 20_000));
        assert_eq!(
            recorded_quota(&site),
            json!({"state": "enforced", "source": "readoption", "block_hard_kib": 262_144, "inode_hard": 20_000})
        );
        // W534 (D-088): a signed change replaces both.
        site.changed_quota = Some((524_288, 40_000));
        assert_eq!(
            recorded_quota(&site),
            json!({"state": "enforced", "source": "quota_change", "block_hard_kib": 524_288, "inode_hard": 40_000})
        );
    }
}
