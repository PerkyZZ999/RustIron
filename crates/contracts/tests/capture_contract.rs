//! Public lab `backup_capture` checks; no host effects.

use rustiron_contracts::{
    Id, Timestamp,
    approval::{
        ApprovalError, CaptureBindingContext, CaptureDestination, CaptureGrant, CapturePlan,
        CaptureRecipe, EjectPlan, Sha256Digest, check_capture_binding,
    },
};
use serde_json::{Value, json};

const PLAN: &[u8] = include_bytes!("fixtures/capture-plan.json");
const GRANT: &[u8] = include_bytes!("fixtures/capture-grant.json");
/// Computed independently with Python's json/hashlib when the fixture was made.
const PLAN_DIGEST: &str = "31441613f3d96fe2b9cbdafa8dceea164405fa09d877d63ccdda3d06f3e28135";

fn with(bytes: &[u8], pointer: &str, new: Value) -> Vec<u8> {
    let mut record: Value = serde_json::from_slice(bytes).unwrap();
    *record.pointer_mut(pointer).unwrap() = new;
    serde_json::to_vec(&record).unwrap()
}

fn id(text: &str) -> Id {
    Id::try_from(text.to_owned()).unwrap()
}

fn check(plan: &CapturePlan, grant: &CaptureGrant, now: Option<u64>) -> Result<(), ApprovalError> {
    check_capture_binding(
        plan,
        grant,
        &CaptureBindingContext {
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
    let plan = CapturePlan::decode(PLAN).unwrap();
    let grant = CaptureGrant::decode(GRANT).unwrap();
    assert_eq!(plan.digest().as_str(), PLAN_DIGEST);
    assert_eq!(plan.site_id().as_str(), "blog9");
    assert_eq!(
        plan.target(),
        (CaptureDestination::LabPcStore, CaptureRecipe::SiteFilesDbV1)
    );
    assert_eq!(check(&plan, &grant, Some(1200)), Ok(()));
    assert!(EjectPlan::decode(PLAN).is_err(), "no cross-verb decoding");
}

/// W256 (D-021 A1): the opt-in frozen recipe is a closed, signed value.
#[test]
fn the_opt_in_frozen_recipe_decodes_and_nothing_near_it_does() {
    let plan =
        CapturePlan::decode(&with(PLAN, "/recipe_id", json!("site_files_db_frozen_v1"))).unwrap();
    assert_eq!(plan.target().1, CaptureRecipe::SiteFilesDbFrozenV1);
    assert_ne!(plan.digest(), CapturePlan::decode(PLAN).unwrap().digest());
    for near in [
        "site_files_db_frozen",
        "site_files_db_frozen_v2",
        "SiteFilesDbFrozenV1",
        "frozen",
    ] {
        assert!(
            CapturePlan::decode(&with(PLAN, "/recipe_id", json!(near))).is_err(),
            "{near}"
        );
    }
}

#[test]
fn no_path_address_or_unknown_recipe_is_representable() {
    for (pointer, new) in [
        ("/destination_id", json!("s3://elsewhere")),
        ("/recipe_id", json!("full_disk")),
        ("/verb", json!("site_eject")),
        ("/site_id", json!("../blog9")),
    ] {
        assert!(
            CapturePlan::decode(&with(PLAN, pointer, new)).is_err(),
            "{pointer}"
        );
    }
    let mut record: Value = serde_json::from_slice(PLAN).unwrap();
    record["repository"] = json!("s3:http://attacker/x");
    assert!(CapturePlan::decode(&serde_json::to_vec(&record).unwrap()).is_err());
    for (pointer, new) in [
        ("/site_ids", json!(["blog9", "blog10"])),
        ("/destinations", json!([])),
        ("/max_operations", json!(2)),
        ("/issuer", json!("agent_1")),
    ] {
        assert!(
            CaptureGrant::decode(&with(GRANT, pointer, new)).is_err(),
            "{pointer}"
        );
    }
}

#[test]
fn every_bound_field_change_is_a_binding_mismatch() {
    let plan = CapturePlan::decode(PLAN).unwrap();
    for (pointer, new) in [
        ("/plan_digest", json!("e".repeat(64))),
        ("/site_ids", json!(["blog10"])),
        ("/host_epoch", json!("epoch_2")),
        ("/issuer", json!("operator_2")),
        ("/expires_at", json!(2001)),
    ] {
        let grant = CaptureGrant::decode(&with(GRANT, pointer, new)).unwrap();
        assert_eq!(
            check(&plan, &grant, Some(1200)),
            Err(ApprovalError::BindingMismatch),
            "{pointer}"
        );
    }
    let grant = CaptureGrant::decode(GRANT).unwrap();
    assert_eq!(
        check(&plan, &grant, None),
        Err(ApprovalError::ClockUncertain)
    );
    assert_eq!(
        check(&plan, &grant, Some(1900)),
        Err(ApprovalError::OutsideValidity)
    );
}
