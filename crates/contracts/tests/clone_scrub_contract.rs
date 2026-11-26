//! D-078 `clone_scrub` plan/grant checks; no signer, executor or host effects.

use rustiron_contracts::{
    Id, Timestamp,
    approval::{
        ApprovalError, CloneScrubBindingContext, CloneScrubGrant, CloneScrubPlan, PlanKind,
        PreparedPlan, Sha256Digest, check_clone_scrub_binding,
    },
};
use serde_json::{Value, json};

const PLAN: &[u8] = include_bytes!("fixtures/clone-scrub-plan.json");
const GRANT: &[u8] = include_bytes!("fixtures/clone-scrub-grant.json");
/// Computed independently with Python's json/hashlib when the fixture was made.
const PLAN_DIGEST: &str = "67dfa302da0e85bda6cd500a1a737ea0712cb8213a356b6f03502a336a0b2276";

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

fn check(
    plan: &CloneScrubPlan,
    grant: &CloneScrubGrant,
    now: Option<u64>,
) -> Result<(), ApprovalError> {
    check_clone_scrub_binding(
        plan,
        grant,
        &CloneScrubBindingContext {
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
    let plan = CloneScrubPlan::decode(PLAN).unwrap();
    let grant = CloneScrubGrant::decode(GRANT).unwrap();
    assert_eq!(plan.digest().as_str(), PLAN_DIGEST);
    assert_eq!(plan.site_id().as_str(), "blog2");
    assert_eq!(plan.clone_operation_id().as_str(), "op_clone");
    assert_eq!(grant.grant_id().as_str(), "grant_clone_scrub");
    assert_eq!(grant.nonce().as_str(), "nonce_clone_scrub");
    assert_eq!(check(&plan, &grant, Some(1500)), Ok(()));
    let prepared = PreparedPlan::decode(PLAN).unwrap();
    assert_eq!(prepared.kind(), PlanKind::CloneScrub);
    assert_eq!(prepared.kind().as_str(), "clone_scrub");
    assert_eq!(prepared.digest().as_str(), PLAN_DIGEST);
}

#[test]
fn plan_semantics_are_closed() {
    for (pointer, new) in [
        ("/schema_version", Some(json!(2))),
        ("/verb", Some(json!("import_scrub"))),
        ("/site_id", Some(json!("Blog2"))),
        ("/clone_operation_id", Some(json!("../op"))),
        (
            "/expected_effects/removes_clone_leftovers",
            Some(json!(false)),
        ),
        ("/expected_effects/deletes_site", Some(json!(true))),
        ("/expected_effects/traffic_activation", Some(json!(true))),
        ("/expected_effects/network_access", Some(json!(true))),
        ("/expected_effects/extra", Some(json!(true))),
        ("/expires_at", Some(json!(1000))),
        ("/limitations", Some(json!(vec!["x"; 9]))),
        ("/path", Some(json!("/srv/sites/rs_blog2/tmp/clone"))),
        ("/archive_sha256", Some(json!("a".repeat(64)))),
        ("/clone_operation_id", None),
        ("/site_id", None),
    ] {
        assert!(
            CloneScrubPlan::decode(&edited(PLAN, pointer, new.clone())).is_err(),
            "{pointer} {new:?}"
        );
    }
}

#[test]
fn grant_semantics_are_closed() {
    for (pointer, new) in [
        ("/schema_version", Some(json!(2))),
        ("/verbs", Some(json!(["import_scrub"]))),
        ("/verbs", Some(json!(["clone_scrub", "clone_scrub"]))),
        ("/verbs", Some(json!(["import_scrub"]))),
        ("/site_ids", Some(json!(["blog2", "blog3"]))),
        ("/site_ids", Some(json!([]))),
        ("/max_operations", Some(json!(2))),
        ("/issuer", Some(json!("agent_1"))),
        ("/expires_at", Some(json!(1100))),
        ("/extra", Some(json!(1))),
    ] {
        assert!(
            CloneScrubGrant::decode(&edited(GRANT, pointer, new.clone())).is_err(),
            "{pointer} {new:?}"
        );
    }
}

#[test]
fn binding_and_time_are_checked() {
    let plan = CloneScrubPlan::decode(PLAN).unwrap();
    for (pointer, new) in [
        ("/plan_digest", json!("c".repeat(64))),
        ("/plan_id", json!("plan_other")),
        ("/host_id", json!("host_other")),
        ("/host_epoch", json!("epoch_2")),
        ("/requester", json!("agent_2")),
        ("/issuer", json!("operator_2")),
        ("/signer_policy_epoch", json!("policy_2")),
        ("/site_ids", json!(["blog3"])),
        ("/risk_class", json!("production_candidate")),
        ("/valid_from", json!(900)),
        ("/expires_at", json!(2100)),
    ] {
        let grant = CloneScrubGrant::decode(&edited(GRANT, pointer, Some(new.clone())));
        if let Ok(grant) = grant {
            assert_eq!(
                check(&plan, &grant, Some(1500)),
                Err(ApprovalError::BindingMismatch),
                "{pointer} {new}"
            );
        }
    }
    let grant = CloneScrubGrant::decode(GRANT).unwrap();
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
