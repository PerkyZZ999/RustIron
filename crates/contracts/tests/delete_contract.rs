//! D-085 `site_delete` plan/grant checks; no signer, executor or host effects.

use rustiron_contracts::{
    Id, Timestamp,
    approval::{
        ApprovalError, DeleteBindingContext, DeleteGrant, DeletePlan, PlanKind, PreparedPlan,
        Sha256Digest, check_delete_binding,
    },
};
use serde_json::{Value, json};

const PLAN: &[u8] = include_bytes!("fixtures/delete-plan.json");
const GRANT: &[u8] = include_bytes!("fixtures/delete-grant.json");
/// Computed independently with Python's json/hashlib when the fixture was made.
const PLAN_DIGEST: &str = "3d6a6e7d58be6f59d99700d40933543d13a1ea3f51bc96eb4ff959070f3b7c86";

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

fn check(plan: &DeletePlan, grant: &DeleteGrant, now: Option<u64>) -> Result<(), ApprovalError> {
    check_delete_binding(
        plan,
        grant,
        &DeleteBindingContext {
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
    let plan = DeletePlan::decode(PLAN).unwrap();
    let grant = DeleteGrant::decode(GRANT).unwrap();
    assert_eq!(plan.digest().as_str(), PLAN_DIGEST);
    assert_eq!(plan.site_id().as_str(), "blog1");
    assert_eq!(plan.hostname().as_str(), "blog1.example.test");
    assert_eq!(
        plan.capture_operation_id().map(Id::as_str),
        Some("op_capture")
    );
    assert_eq!(grant.grant_id().as_str(), "grant_delete");
    assert_eq!(grant.nonce().as_str(), "nonce_delete");
    assert_eq!(check(&plan, &grant, Some(1500)), Ok(()));
    let prepared = PreparedPlan::decode(PLAN).unwrap();
    assert_eq!(prepared.kind(), PlanKind::SiteDelete);
    assert_eq!(prepared.kind().as_str(), "site_delete");
    assert_eq!(prepared.digest().as_str(), PLAN_DIGEST);
}

#[test]
fn plan_semantics_are_closed() {
    for (pointer, new) in [
        ("/schema_version", Some(json!(2))),
        ("/verb", Some(json!("import_scrub"))),
        ("/capture_operation_id", Some(json!("../op"))),
        ("/hostname", Some(json!("Blog1.example.test"))),
        ("/hostname", Some(json!("blog1"))),
        (
            "/expected_effects/removes_certificate_keys",
            Some(json!(false)),
        ),
        ("/provision_operation_id", Some(json!("op_provision"))),
        ("/site_id", Some(json!("Blog1"))),
        ("/expected_effects/deletes_backups", Some(json!(true))),
        (
            "/expected_effects/removes_site_resources",
            Some(json!(false)),
        ),
        ("/expected_effects/traffic_activation", Some(json!(true))),
        ("/expected_effects/network_access", Some(json!(true))),
        ("/expected_effects/extra", Some(json!(true))),
        ("/expected_effects/deletes_backups", None),
        ("/expires_at", Some(json!(1000))),
        ("/limitations", Some(json!(vec!["x"; 9]))),
        ("/path", Some(json!("/srv/sites/rs_blog1"))),
        ("/command", Some(json!("rm -rf /"))),
        ("/capture_operation_id", None),
        ("/hostname", None),
        ("/site_id", None),
    ] {
        assert!(
            DeletePlan::decode(&edited(PLAN, pointer, new.clone())).is_err(),
            "{pointer} {new:?}"
        );
    }
}

/// W576 (D-095): schema 2 names no capture, for a proxy site; schema 1
/// must name one, and schema 2 must not, not even as `null`.
#[test]
fn schema_2_names_no_capture() {
    let mut record: Value = serde_json::from_slice(PLAN).unwrap();
    record["schema_version"] = json!(2);
    record
        .as_object_mut()
        .unwrap()
        .remove("capture_operation_id");
    let bytes = serde_json::to_vec(&record).unwrap();
    let plan = DeletePlan::decode(&bytes).unwrap();
    assert_eq!(plan.capture_operation_id(), None);
    assert_ne!(plan.digest().as_str(), PLAN_DIGEST);
    let prepared = PreparedPlan::decode(&bytes).unwrap();
    assert_eq!(prepared.kind(), PlanKind::SiteDelete);
    assert_eq!(prepared.digest(), plan.digest());
    for (pointer, new) in [
        ("/capture_operation_id", Some(json!(null))),
        ("/capture_operation_id", Some(json!("op_capture"))),
        ("/schema_version", Some(json!(3))),
        ("/schema_version", Some(json!(1))),
    ] {
        assert!(
            DeletePlan::decode(&edited(&bytes, pointer, new.clone())).is_err(),
            "{pointer} {new:?}"
        );
    }
    assert!(DeletePlan::decode(&edited(PLAN, "/capture_operation_id", Some(json!(null)))).is_err());
}

#[test]
fn grant_semantics_are_closed() {
    for (pointer, new) in [
        ("/schema_version", Some(json!(2))),
        ("/verbs", Some(json!(["import_scrub"]))),
        ("/verbs", Some(json!(["site_delete", "site_delete"]))),
        ("/verbs", Some(json!(["site_retire"]))),
        ("/site_ids", Some(json!(["blog1", "blog2"]))),
        ("/site_ids", Some(json!([]))),
        ("/max_operations", Some(json!(2))),
        ("/issuer", Some(json!("agent_1"))),
        ("/expires_at", Some(json!(1100))),
        ("/extra", Some(json!(1))),
    ] {
        assert!(
            DeleteGrant::decode(&edited(GRANT, pointer, new.clone())).is_err(),
            "{pointer} {new:?}"
        );
    }
}

#[test]
fn binding_and_time_are_checked() {
    let plan = DeletePlan::decode(PLAN).unwrap();
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
        let grant = DeleteGrant::decode(&edited(GRANT, pointer, Some(new.clone())));
        if let Ok(grant) = grant {
            assert_eq!(
                check(&plan, &grant, Some(1500)),
                Err(ApprovalError::BindingMismatch),
                "{pointer} {new}"
            );
        }
    }
    let grant = DeleteGrant::decode(GRANT).unwrap();
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
