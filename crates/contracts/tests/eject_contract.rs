//! Public lab `site_eject` checks; no host effects.

use rustiron_contracts::{
    Id, Timestamp,
    approval::{
        ApprovalError, EjectBindingContext, EjectGrant, EjectPlan, OlsPlan, Sha256Digest,
        check_eject_binding,
    },
};
use serde_json::{Value, json};

const PLAN: &[u8] = include_bytes!("fixtures/eject-plan.json");
const GRANT: &[u8] = include_bytes!("fixtures/eject-grant.json");
const STATIC_PLAN: &[u8] = include_bytes!("fixtures/eject-plan-v3.json");
/// Computed independently with Python's json/hashlib when the fixture was made.
const PLAN_DIGEST: &str = "ca015fc46a331406c894bff50a4de8314d65e67c7f8834574520e651ba830727";

fn with(bytes: &[u8], pointer: &str, new: Value) -> Vec<u8> {
    let mut record: Value = serde_json::from_slice(bytes).unwrap();
    *record.pointer_mut(pointer).unwrap() = new;
    serde_json::to_vec(&record).unwrap()
}

fn id(text: &str) -> Id {
    Id::try_from(text.to_owned()).unwrap()
}

fn check(plan: &EjectPlan, grant: &EjectGrant, now: Option<u64>) -> Result<(), ApprovalError> {
    check_eject_binding(
        plan,
        grant,
        &EjectBindingContext {
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
    let plan = EjectPlan::decode(PLAN).unwrap();
    let grant = EjectGrant::decode(GRANT).unwrap();
    assert_eq!(plan.digest().as_str(), PLAN_DIGEST);
    assert_eq!(plan.site_id().as_str(), "blog5");
    assert_eq!(plan.expected().0.as_str(), "g1");
    assert_eq!(check(&plan, &grant, Some(1200)), Ok(()));
}

#[test]
fn the_exact_name_pair_changes_the_signed_scope() {
    let mut pair: Value = serde_json::from_slice(PLAN).unwrap();
    pair["schema_version"] = json!(2);
    pair["hostname"] = json!("primary.example.test");
    pair["alias_hostname"] = json!("alias.example.test");
    let plan = EjectPlan::decode(&serde_json::to_vec(&pair).unwrap()).unwrap();
    let (primary, alias) = plan.names().unwrap();
    assert_eq!(primary.as_str(), "primary.example.test");
    assert_eq!(alias.as_str(), "alias.example.test");
    assert!(check(&plan, &EjectGrant::decode(GRANT).unwrap(), Some(1200)).is_err());
    pair["alias_hostname"] = json!("primary.example.test");
    assert_eq!(
        EjectPlan::decode(&serde_json::to_vec(&pair).unwrap()).unwrap_err(),
        ApprovalError::InvalidPlan,
    );
}

#[test]
fn static_eject_binds_the_single_hostname_and_a_fresh_plan_digest() {
    let plan = EjectPlan::decode(STATIC_PLAN).unwrap();
    let digest = "475e58d19b1c073f9d5a142b666a05f34206dcfece033db1482e9cd8315a96ab";
    assert_eq!(plan.digest().as_str(), digest);
    assert!(plan.names().is_none());
    assert_eq!(
        plan.static_hostname().unwrap().as_str(),
        "static.example.test"
    );
    let previous = EjectGrant::decode(GRANT).unwrap();
    assert_eq!(
        check(&plan, &previous, Some(1200)),
        Err(ApprovalError::BindingMismatch)
    );
    let signed_scope = EjectGrant::decode(&with(GRANT, "/plan_digest", json!(digest))).unwrap();
    assert_eq!(check(&plan, &signed_scope, Some(1200)), Ok(()));
    let substituted =
        EjectPlan::decode(&with(STATIC_PLAN, "/hostname", json!("other.example.test"))).unwrap();
    assert_eq!(
        check(&substituted, &signed_scope, Some(1200)),
        Err(ApprovalError::BindingMismatch)
    );
}

#[test]
fn static_eject_requires_one_exact_name_and_the_new_schema() {
    let mut plan: Value = serde_json::from_slice(STATIC_PLAN).unwrap();
    plan["alias_hostname"] = json!("alias.example.test");
    assert!(EjectPlan::decode(&serde_json::to_vec(&plan).unwrap()).is_err());
    plan["alias_hostname"] = Value::Null;
    assert!(EjectPlan::decode(&serde_json::to_vec(&plan).unwrap()).is_err());
    plan.as_object_mut().unwrap().remove("alias_hostname");
    for schema in [1, 2] {
        plan["schema_version"] = json!(schema);
        assert!(EjectPlan::decode(&serde_json::to_vec(&plan).unwrap()).is_err());
    }
    plan["schema_version"] = json!(3);
    plan.as_object_mut().unwrap().remove("hostname");
    assert!(EjectPlan::decode(&serde_json::to_vec(&plan).unwrap()).is_err());
}

#[test]
fn eject_and_activation_plans_never_decode_as_each_other() {
    assert!(OlsPlan::decode(PLAN).is_err());
    assert!(EjectPlan::decode(include_bytes!("fixtures/ols-plan.json")).is_err());
}

#[test]
fn plan_and_grant_are_closed() {
    for (pointer, new) in [
        ("/verb", json!("config_activate")),
        ("/site_id", json!("Blog5")),
        ("/observations/0/generation", json!("g2")),
        ("/compensation/max_attempts", json!(2)),
    ] {
        assert!(
            EjectPlan::decode(&with(PLAN, pointer, new)).is_err(),
            "{pointer}"
        );
    }
    for (pointer, new) in [
        ("/verbs", json!(["config_activate"])),
        ("/site_ids", json!(["blog5", "blog6"])),
        ("/site_ids", json!([])),
        ("/max_operations", json!(2)),
        ("/issuer", json!("agent_1")),
    ] {
        assert!(
            EjectGrant::decode(&with(GRANT, pointer, new)).is_err(),
            "{pointer}"
        );
    }
}

#[test]
fn every_bound_field_change_is_a_binding_mismatch() {
    let plan = EjectPlan::decode(PLAN).unwrap();
    for (pointer, new) in [
        ("/plan_digest", json!("e".repeat(64))),
        ("/plan_id", json!("plan_other")),
        ("/host_epoch", json!("epoch_2")),
        ("/requester", json!("agent_2")),
        ("/site_ids", json!(["blog6"])),
        ("/issuer", json!("operator_2")),
        ("/signer_policy_epoch", json!("policy_2")),
        ("/valid_from", json!(999)),
        ("/expires_at", json!(2001)),
    ] {
        let grant = EjectGrant::decode(&with(GRANT, pointer, new)).unwrap();
        assert_eq!(
            check(&plan, &grant, Some(1200)),
            Err(ApprovalError::BindingMismatch),
            "{pointer}"
        );
    }
    let grant = EjectGrant::decode(GRANT).unwrap();
    assert_eq!(
        check(&plan, &grant, None),
        Err(ApprovalError::ClockUncertain)
    );
    assert_eq!(
        check(&plan, &grant, Some(1900)),
        Err(ApprovalError::OutsideValidity)
    );
}
