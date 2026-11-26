//! D-089 `site_restore` plan/grant checks; no signer, executor or host effects.

use rustiron_contracts::{
    Id, Timestamp,
    approval::{
        ApprovalError, PlanKind, PreparedPlan, ProductBackupBindingContext, RestoreGrant,
        RestorePlan, RestoreScope, Sha256Digest, check_restore_binding,
    },
};
use serde_json::{Value, json};

const PLAN: &[u8] = include_bytes!("fixtures/restore-plan.json");
const GRANT: &[u8] = include_bytes!("fixtures/restore-grant.json");
/// Computed independently with Python's json/hashlib when the fixture was made.
const PLAN_DIGEST: &str = "45854e066de823f7960e4dbda990837490f15b2101da6e8f64d3585ff0e8cd8b";

fn edited(bytes: &[u8], pointer: &str, new: Option<Value>) -> Vec<u8> {
    let mut record: Value = serde_json::from_slice(bytes).unwrap();
    match new {
        Some(new) => match record.pointer_mut(pointer) {
            Some(slot) => *slot = new,
            None => {
                let (parent, member) = pointer.rsplit_once('/').unwrap();
                let object = if parent.is_empty() {
                    &mut record
                } else {
                    record.pointer_mut(parent).unwrap()
                };
                object
                    .as_object_mut()
                    .unwrap()
                    .insert(member.to_owned(), new);
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

fn edits(bytes: &[u8], changes: &[(&str, Value)]) -> Vec<u8> {
    changes.iter().fold(bytes.to_vec(), |acc, (pointer, new)| {
        edited(&acc, pointer, Some(new.clone()))
    })
}

fn id(text: &str) -> Id {
    Id::try_from(text.to_owned()).unwrap()
}

fn check(plan: &RestorePlan, grant: &RestoreGrant, now: Option<u64>) -> Result<(), ApprovalError> {
    check_restore_binding(
        plan,
        grant,
        &ProductBackupBindingContext {
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
    let plan = RestorePlan::decode(PLAN).unwrap();
    let grant = RestoreGrant::decode(GRANT).unwrap();
    assert_eq!(plan.digest().as_str(), PLAN_DIGEST);
    assert_eq!(plan.site_id().as_str(), "blog1");
    assert_eq!(plan.hostname().as_str(), "blog1.example.test");
    assert_eq!(plan.scope(), RestoreScope::FilesAndDatabase);
    assert_eq!(plan.scope().as_str(), "files_and_database");
    let source = plan.source();
    assert_eq!(source.capture_operation_id.as_str(), "op_capture_old");
    assert_eq!(source.snapshot_id.as_str(), "b".repeat(64));
    assert_eq!(source.manifest_sha256.as_str(), "c".repeat(64));
    assert_eq!(source.destination_id.as_str(), "isolated_store");
    assert_eq!(
        plan.safety_capture_operation_id().as_str(),
        "op_capture_safety"
    );
    assert_eq!(grant.grant_id().as_str(), "grant_restore");
    assert_eq!(grant.nonce().as_str(), "nonce_restore");
    assert_eq!(check(&plan, &grant, Some(1500)), Ok(()));
    let prepared = PreparedPlan::decode(PLAN).unwrap();
    assert_eq!(prepared.kind(), PlanKind::SiteRestore);
    assert_eq!(prepared.kind().as_str(), "site_restore");
    assert_eq!(prepared.digest().as_str(), PLAN_DIGEST);
}

#[test]
fn a_database_restore_must_not_claim_to_replace_files() {
    let database = edits(
        PLAN,
        &[
            ("/scope", json!("database")),
            ("/expected_effects/replaces_files", json!(false)),
        ],
    );
    assert_eq!(
        RestorePlan::decode(&database).unwrap().scope(),
        RestoreScope::Database
    );
    for wrong in [
        edited(PLAN, "/scope", Some(json!("database"))),
        edited(PLAN, "/expected_effects/replaces_files", Some(json!(false))),
    ] {
        assert!(RestorePlan::decode(&wrong).is_err());
    }
}

#[test]
fn plan_semantics_are_closed() {
    for (pointer, new) in [
        ("/schema_version", Some(json!(2))),
        ("/verb", Some(json!("site_delete"))),
        ("/scope", Some(json!("files"))),
        ("/scope", Some(json!("Database"))),
        ("/site_id", Some(json!("Blog1"))),
        ("/hostname", Some(json!("Blog1.example.test"))),
        ("/hostname", Some(json!("blog1"))),
        (
            "/safety_capture_operation_id",
            Some(json!("op_capture_old")),
        ),
        ("/safety_capture_operation_id", Some(json!("../op"))),
        (
            "/source/capture_operation_id",
            Some(json!("op_capture_safety")),
        ),
        ("/source/snapshot_id", Some(json!("B".repeat(64)))),
        ("/source/snapshot_id", Some(json!("b".repeat(63)))),
        ("/source/manifest_sha256", Some(json!("c".repeat(63)))),
        ("/source/destination_id", Some(json!("lab_pc_store"))),
        ("/source/repository_id", None),
        ("/source/path", Some(json!("/srv/sites/rs_blog1"))),
        ("/expected_effects/fetches_snapshot", Some(json!(false))),
        ("/expected_effects/replaces_database", Some(json!(false))),
        ("/expected_effects/deletes_backups", Some(json!(true))),
        ("/expected_effects/traffic_activation", Some(json!(true))),
        ("/expected_effects/network_access", Some(json!(false))),
        ("/expected_effects/deletes_backups", None),
        ("/expires_at", Some(json!(1000))),
        ("/limitations", Some(json!(vec!["x"; 9]))),
        ("/sql", Some(json!("DROP DATABASE x"))),
        ("/command", Some(json!("rm -rf /"))),
        ("/scope", None),
        ("/source", None),
        ("/safety_capture_operation_id", None),
        ("/hostname", None),
        ("/site_id", None),
    ] {
        assert!(
            RestorePlan::decode(&edited(PLAN, pointer, new.clone())).is_err(),
            "{pointer} {new:?}"
        );
    }
}

#[test]
fn grant_semantics_are_closed() {
    for (pointer, new) in [
        ("/schema_version", Some(json!(2))),
        ("/verbs", Some(json!(["site_delete"]))),
        ("/verbs", Some(json!(["site_restore", "site_restore"]))),
        ("/site_ids", Some(json!(["blog1", "blog2"]))),
        ("/site_ids", Some(json!([]))),
        ("/snapshot_id", Some(json!("b".repeat(63)))),
        ("/snapshot_id", None),
        ("/max_operations", Some(json!(2))),
        ("/issuer", Some(json!("agent_1"))),
        ("/expires_at", Some(json!(1100))),
        ("/extra", Some(json!(1))),
    ] {
        assert!(
            RestoreGrant::decode(&edited(GRANT, pointer, new.clone())).is_err(),
            "{pointer} {new:?}"
        );
    }
}

#[test]
fn binding_and_time_are_checked() {
    let plan = RestorePlan::decode(PLAN).unwrap();
    for (pointer, new) in [
        ("/plan_digest", json!("c".repeat(64))),
        ("/plan_id", json!("plan_other")),
        ("/host_id", json!("host_other")),
        ("/host_epoch", json!("epoch_2")),
        ("/requester", json!("agent_2")),
        ("/issuer", json!("operator_2")),
        ("/signer_policy_epoch", json!("policy_2")),
        ("/site_ids", json!(["blog2"])),
        ("/snapshot_id", json!("f".repeat(64))),
        ("/risk_class", json!("production_candidate")),
        ("/valid_from", json!(900)),
        ("/expires_at", json!(2100)),
    ] {
        let grant = RestoreGrant::decode(&edited(GRANT, pointer, Some(new.clone())));
        if let Ok(grant) = grant {
            assert_eq!(
                check(&plan, &grant, Some(1500)),
                Err(ApprovalError::BindingMismatch),
                "{pointer} {new}"
            );
        }
    }
    let grant = RestoreGrant::decode(GRANT).unwrap();
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
