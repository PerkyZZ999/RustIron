//! The D-078 clone plan has a closed and independently digest-bound scope.

use rustiron_contracts::{
    Id, Timestamp,
    approval::{
        ApprovalError, PlanKind, PreparedPlan, ProductBackupBindingContext, Sha256Digest,
        SiteCloneGrant, SiteClonePlan, check_site_clone_binding,
    },
};
use serde_json::{Value, json};

const PLAN: &[u8] = include_bytes!("fixtures/site-clone-plan.json");
const GRANT: &[u8] = include_bytes!("fixtures/site-clone-grant.json");

fn id(value: &str) -> Id {
    Id::try_from(value.to_owned()).unwrap()
}

fn binding(
    plan: &SiteClonePlan,
    grant: &SiteCloneGrant,
    now: Option<u64>,
) -> Result<(), ApprovalError> {
    check_site_clone_binding(
        plan,
        grant,
        &ProductBackupBindingContext {
            host_id: &id("host_lab"),
            host_epoch: &id("epoch_1"),
            profile_digest: &Sha256Digest::try_from("a".repeat(64)).unwrap(),
            requester: &id("agent_1"),
            issuer: &id("operator_1"),
            signer_policy_epoch: &id("policy_1"),
            now: now.map(|time| Timestamp::try_from(time).unwrap()),
        },
    )
}

fn with(bytes: &[u8], path: &str, value: Value) -> Vec<u8> {
    let mut record: Value = serde_json::from_slice(bytes).unwrap();
    *record.pointer_mut(path).unwrap() = value;
    serde_json::to_vec(&record).unwrap()
}

#[test]
fn the_prepared_plan_and_exact_grant_bind_during_the_signed_window() {
    let plan = SiteClonePlan::decode(PLAN).unwrap();
    let grant = SiteCloneGrant::decode(GRANT).unwrap();
    let prepared = PreparedPlan::decode(PLAN).unwrap();
    assert_eq!(prepared.kind(), PlanKind::SiteClone);
    assert_eq!(prepared.as_bytes(), PLAN);
    assert_eq!(prepared.digest(), plan.digest());
    assert_eq!(grant.as_bytes(), GRANT);
    assert_eq!(binding(&plan, &grant, Some(1100)), Ok(()));
    assert_eq!(
        binding(&plan, &grant, Some(1099)),
        Err(ApprovalError::OutsideValidity)
    );
    assert_eq!(
        binding(&plan, &grant, Some(1350)),
        Err(ApprovalError::OutsideValidity)
    );
    assert_eq!(
        binding(&plan, &grant, None),
        Err(ApprovalError::ClockUncertain)
    );
}

#[test]
fn the_grant_cannot_be_reused_for_a_different_capture_repository_or_target() {
    let grant = SiteCloneGrant::decode(GRANT).unwrap();
    for (path, value) in [
        ("/source/site_id", json!("other")),
        ("/source/hostname", json!("other.example.test")),
        ("/source/capture_operation_id", json!("op_capture2")),
        ("/source/snapshot_id", json!("f".repeat(64))),
        ("/source/manifest_sha256", json!("f".repeat(64))),
        ("/source/destination_id", json!("other_store")),
        ("/source/destination_policy_digest", json!("f".repeat(64))),
        ("/source/repository_id", json!("f".repeat(64))),
        ("/target/site_id", json!("another")),
        ("/target/hostname", json!("another.example.test")),
    ] {
        let plan = SiteClonePlan::decode(&with(PLAN, path, value)).unwrap();
        assert_eq!(
            binding(&plan, &grant, Some(1200)),
            Err(ApprovalError::BindingMismatch),
            "{path}"
        );
    }
}

#[test]
fn the_plan_requires_a_distinct_lab_target_without_activation() {
    for (path, value) in [
        ("/target/site_id", json!("source")),
        ("/target/hostname", json!("source.example.test")),
        ("/source/destination_id", json!("lab_pc_store")),
        ("/expected_effects/modifies_source", json!(true)),
        ("/expected_effects/traffic_activation", json!(true)),
    ] {
        assert_eq!(
            SiteClonePlan::decode(&with(PLAN, path, value)).unwrap_err(),
            ApprovalError::InvalidPlan,
            "{path}"
        );
    }
    assert_eq!(
        SiteClonePlan::decode(&with(PLAN, "/risk_class", json!("production"))).unwrap_err(),
        ApprovalError::InvalidMessage
    );
    let mut plan: Value = serde_json::from_slice(PLAN).unwrap();
    plan["source"]["path"] = json!("/somewhere");
    assert_eq!(
        SiteClonePlan::decode(&serde_json::to_vec(&plan).unwrap()).unwrap_err(),
        ApprovalError::InvalidMessage
    );
}

#[test]
fn the_grant_requires_exactly_one_clone_operation() {
    for (path, value) in [
        ("/verbs", json!(["site_clone", "site_clone"])),
        ("/max_operations", json!(2)),
        ("/target_site_id", json!("source")),
    ] {
        assert_eq!(
            SiteCloneGrant::decode(&with(GRANT, path, value)).unwrap_err(),
            ApprovalError::InvalidGrant,
            "{path}"
        );
    }
}

#[test]
fn the_grant_scope_must_agree_even_when_the_plan_digest_matches() {
    let plan = SiteClonePlan::decode(PLAN).unwrap();
    let changed = with(GRANT, "/snapshot_id", json!("f".repeat(64)));
    let grant = SiteCloneGrant::decode(&changed).unwrap();
    assert_eq!(
        binding(&plan, &grant, Some(1200)),
        Err(ApprovalError::BindingMismatch)
    );
}
