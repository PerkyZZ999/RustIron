//! Public lab `restore_probe` checks; no host effects.

use rustiron_contracts::{
    Id, Timestamp,
    approval::{
        ApprovalError, CapturePlan, ProbeBindingContext, ProbeGrant, ProbePlan, ProbeProfile,
        Sha256Digest, check_probe_binding,
    },
};
use serde_json::{Value, json};

const PLAN: &[u8] = include_bytes!("fixtures/probe-plan.json");
const GRANT: &[u8] = include_bytes!("fixtures/probe-grant.json");
/// Computed independently with Python's json/hashlib when the fixture was made.
const PLAN_DIGEST: &str = "38d7827be2d1c72f470a71fe34a0172f0b9fdd877ac9ea1532a7e48aa795caf9";

fn with(bytes: &[u8], pointer: &str, new: Value) -> Vec<u8> {
    let mut record: Value = serde_json::from_slice(bytes).unwrap();
    *record.pointer_mut(pointer).unwrap() = new;
    serde_json::to_vec(&record).unwrap()
}

fn id(text: &str) -> Id {
    Id::try_from(text.to_owned()).unwrap()
}

fn check(plan: &ProbePlan, grant: &ProbeGrant, now: Option<u64>) -> Result<(), ApprovalError> {
    check_probe_binding(
        plan,
        grant,
        &ProbeBindingContext {
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
fn fixture_binds_with_independently_computed_digest() {
    let plan = ProbePlan::decode(PLAN).unwrap();
    let grant = ProbeGrant::decode(GRANT).unwrap();
    assert_eq!(plan.digest().as_str(), PLAN_DIGEST);
    assert_eq!(plan.site_id().as_str(), "blog13");
    assert_eq!(plan.snapshot_id().as_str().len(), 64);
    assert_eq!(plan.profile(), ProbeProfile::LocalNoEgressV1);
    assert_eq!(check(&plan, &grant, Some(1200)), Ok(()));
    assert!(CapturePlan::decode(PLAN).is_err(), "no cross-verb decoding");
}

#[test]
fn no_path_image_or_unknown_profile_is_representable() {
    for (pointer, new) in [
        ("/snapshot_id", json!("latest")),
        ("/snapshot_id", json!("A".repeat(64))),
        ("/profile_id", json!("host_mount")),
        ("/verb", json!("backup_capture")),
        ("/site_id", json!("../blog9")),
    ] {
        assert!(
            ProbePlan::decode(&with(PLAN, pointer, new)).is_err(),
            "{pointer}"
        );
    }
    let mut record: Value = serde_json::from_slice(PLAN).unwrap();
    record["image"] = json!("docker.io/anything");
    assert!(ProbePlan::decode(&serde_json::to_vec(&record).unwrap()).is_err());
    for (pointer, new) in [
        ("/site_ids", json!(["blog9", "blog10"])),
        ("/snapshot_ids", json!([])),
        ("/max_operations", json!(2)),
        ("/issuer", json!("agent_1")),
    ] {
        assert!(
            ProbeGrant::decode(&with(GRANT, pointer, new)).is_err(),
            "{pointer}"
        );
    }
}

#[test]
fn every_bound_field_change_is_a_binding_mismatch() {
    let plan = ProbePlan::decode(PLAN).unwrap();
    for (pointer, new) in [
        ("/plan_digest", json!("e".repeat(64))),
        ("/site_ids", json!(["blog9"])),
        ("/snapshot_ids", json!(["f".repeat(64)])),
        ("/host_epoch", json!("epoch_2")),
        ("/issuer", json!("operator_2")),
        ("/expires_at", json!(2001)),
    ] {
        let grant = ProbeGrant::decode(&with(GRANT, pointer, new)).unwrap();
        assert_eq!(
            check(&plan, &grant, Some(1200)),
            Err(ApprovalError::BindingMismatch),
            "{pointer}"
        );
    }
    let grant = ProbeGrant::decode(GRANT).unwrap();
    assert_eq!(
        check(&plan, &grant, None),
        Err(ApprovalError::ClockUncertain)
    );
    assert_eq!(
        check(&plan, &grant, Some(1900)),
        Err(ApprovalError::OutsideValidity)
    );
}
