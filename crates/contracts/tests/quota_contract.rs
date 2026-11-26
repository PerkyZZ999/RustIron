//! D-088 `site_quota` plan/grant checks; no signer, executor or host effects.

use rustiron_contracts::{
    Id, Timestamp,
    approval::{
        ApprovalError, PlanKind, PreparedPlan, QuotaBindingContext, QuotaGrant, QuotaPlan,
        Sha256Digest, check_quota_binding,
    },
};
use serde_json::{Value, json};

const PLAN: &[u8] = include_bytes!("fixtures/quota-plan.json");
const GRANT: &[u8] = include_bytes!("fixtures/quota-grant.json");
/// Computed independently with Python's json/hashlib when the fixture was made.
const PLAN_DIGEST: &str = "a4f38a576425e41b070679af6d51e3e390941bdb2f4b0556112b79bc9f735df1";

fn edited(bytes: &[u8], pointer: &str, new: Option<Value>) -> Vec<u8> {
    let mut record: Value = serde_json::from_slice(bytes).unwrap();
    match new {
        Some(new) => match record.pointer_mut(pointer) {
            Some(slot) => *slot = new,
            None => {
                record
                    .as_object_mut()
                    .unwrap()
                    .insert(pointer.trim_start_matches('/').to_owned(), new);
            }
        },
        None => {
            let (parent, member) = pointer.rsplit_once('/').unwrap();
            let object = if parent.is_empty() {
                &mut record
            } else {
                record.pointer_mut(parent).unwrap()
            };
            object.as_object_mut().unwrap().remove(member);
        }
    }
    serde_json::to_vec(&record).unwrap()
}

fn id(text: &str) -> Id {
    Id::try_from(text.to_owned()).unwrap()
}

fn check(plan: &QuotaPlan, grant: &QuotaGrant, now: Option<u64>) -> Result<(), ApprovalError> {
    check_quota_binding(
        plan,
        grant,
        &QuotaBindingContext {
            host_id: &id("host_lab"),
            host_epoch: &id("epoch_1"),
            profile_digest: &Sha256Digest::try_from("a".repeat(64)).unwrap(),
            requester: &id("agent_1"),
            issuer: &id("operator_1"),
            signer_policy_epoch: &id("policy_1"),
            now: now.map(|t| Timestamp::try_from(t).unwrap()),
        },
    )
}

#[test]
fn fixture_decodes_with_independently_computed_digest_and_binds() {
    let plan = QuotaPlan::decode(PLAN).unwrap();
    let grant = QuotaGrant::decode(GRANT).unwrap();
    assert_eq!(plan.digest().as_str(), PLAN_DIGEST);
    assert_eq!(plan.site_id().as_str(), "blog1");
    assert_eq!(plan.quota_limits().block_hard_kib(), 524_288);
    assert_eq!(plan.quota_limits().inode_hard(), 40_000);
    assert_eq!(grant.grant_id().as_str(), "grant_quota");
    assert_eq!(grant.nonce().as_str(), "nonce_quota");
    assert_eq!(check(&plan, &grant, Some(1500)), Ok(()));
    let prepared = PreparedPlan::decode(PLAN).unwrap();
    assert_eq!(prepared.kind(), PlanKind::SiteQuota);
    assert_eq!(prepared.kind().as_str(), "site_quota");
    assert_eq!(prepared.digest().as_str(), PLAN_DIGEST);
}

#[test]
fn plan_semantics_are_closed() {
    for (pointer, new) in [
        ("/schema_version", Some(json!(2))),
        ("/verb", Some(json!("site_delete"))),
        ("/site_id", Some(json!("Blog1"))),
        ("/quota_limits/block_hard_kib", Some(json!(1024))),
        ("/quota_limits/block_hard_kib", Some(json!(u64::MAX))),
        ("/quota_limits/inode_hard", Some(json!(10))),
        ("/quota_limits/inode_hard", Some(json!(1_000_000_000_u64))),
        ("/quota_limits/block_soft_kib", Some(json!(0))),
        ("/quota_limits", None),
        ("/expected_effects/sets_quota", Some(json!(false))),
        ("/expected_effects/changes_files", Some(json!(true))),
        ("/expected_effects/traffic_activation", Some(json!(true))),
        ("/expected_effects/network_access", Some(json!(true))),
        ("/expected_effects/extra", Some(json!(true))),
        ("/expires_at", Some(json!(1000))),
        ("/limitations", Some(json!(vec!["x"; 9]))),
        ("/uid", Some(json!(3019))),
        ("/command", Some(json!("setquota"))),
        ("/site_id", None),
    ] {
        assert!(
            QuotaPlan::decode(&edited(PLAN, pointer, new.clone())).is_err(),
            "{pointer} {new:?}"
        );
    }
}

#[test]
fn grant_semantics_are_closed() {
    for (pointer, new) in [
        ("/schema_version", Some(json!(2))),
        ("/verbs", Some(json!(["import_scrub"]))),
        ("/verbs", Some(json!(["site_quota", "site_quota"]))),
        ("/verbs", Some(json!(["site_retire"]))),
        ("/site_ids", Some(json!(["blog1", "blog2"]))),
        ("/site_ids", Some(json!([]))),
        ("/max_operations", Some(json!(2))),
        ("/issuer", Some(json!("agent_1"))),
        ("/expires_at", Some(json!(1100))),
        ("/extra", Some(json!(1))),
    ] {
        assert!(
            QuotaGrant::decode(&edited(GRANT, pointer, new.clone())).is_err(),
            "{pointer} {new:?}"
        );
    }
}

#[test]
fn binding_and_time_are_checked() {
    let plan = QuotaPlan::decode(PLAN).unwrap();
    for (pointer, new) in [
        ("/plan_digest", json!("c".repeat(64))),
        ("/plan_id", json!("plan_other")),
        ("/host_id", json!("host_other")),
        ("/host_epoch", json!("epoch_2")),
        ("/requester", json!("agent_2")),
        ("/issuer", json!("operator_2")),
        ("/signer_policy_epoch", json!("policy_2")),
        ("/site_ids", json!(["blog2"])),
        ("/risk_class", json!("production_candidate")),
        ("/valid_from", json!(900)),
        ("/expires_at", json!(2100)),
    ] {
        let grant = QuotaGrant::decode(&edited(GRANT, pointer, Some(new.clone())));
        if let Ok(grant) = grant {
            assert_eq!(
                check(&plan, &grant, Some(1500)),
                Err(ApprovalError::BindingMismatch),
                "{pointer} {new}"
            );
        }
    }
    let grant = QuotaGrant::decode(GRANT).unwrap();
    assert_eq!(
        check(&plan, &grant, None),
        Err(ApprovalError::ClockUncertain)
    );
    for now in [1099, 1900] {
        assert_eq!(
            check(&plan, &grant, Some(now)),
            Err(ApprovalError::OutsideValidity),
            "{now}"
        );
    }
}
