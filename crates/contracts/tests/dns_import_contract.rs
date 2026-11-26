//! D-091 `dns_zone_import` plan/grant checks (W551); no signer, executor or host effects.

use rustiron_contracts::{
    Id, Timestamp,
    approval::{
        ApprovalError, DnsBindingContext, DnsImportGrant, DnsImportPlan, PlanKind, PreparedPlan,
        Sha256Digest, check_dns_import_binding,
    },
};
use serde_json::{Value, json};

const PLAN: &[u8] = include_bytes!("fixtures/dns-import-plan.json");
const GRANT: &[u8] = include_bytes!("fixtures/dns-import-grant.json");
/// Computed independently with Python's json/hashlib when the fixture was made.
const PLAN_DIGEST: &str = "5c0bd1a59dadf79c81966dd8b334d54dd2d6572692c1a8443c3c6aee49ce9a60";

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
    plan: &DnsImportPlan,
    grant: &DnsImportGrant,
    now: Option<u64>,
) -> Result<(), ApprovalError> {
    check_dns_import_binding(
        plan,
        grant,
        &DnsBindingContext {
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
    let plan = DnsImportPlan::decode(PLAN).unwrap();
    let grant = DnsImportGrant::decode(GRANT).unwrap();
    assert_eq!(plan.digest().as_str(), PLAN_DIGEST);
    assert_eq!(plan.zone().as_str(), "example.test");
    assert_eq!(plan.zone_sha256().as_str(), "b".repeat(64));
    assert_eq!(plan.record_sets(), 12);
    assert_eq!(grant.grant_id().as_str(), "grant_dns_import");
    assert_eq!(grant.nonce().as_str(), "nonce_dns_import");
    assert_eq!(check(&plan, &grant, Some(1500)), Ok(()));
    let prepared = PreparedPlan::decode(PLAN).unwrap();
    assert_eq!(prepared.kind(), PlanKind::DnsZoneImport);
    assert_eq!(prepared.kind().as_str(), "dns_zone_import");
    assert_eq!(prepared.digest().as_str(), PLAN_DIGEST);
}

#[test]
fn plan_semantics_are_closed() {
    for (pointer, new) in [
        ("/schema_version", Some(json!(2))),
        ("/verb", Some(json!("site_delete"))),
        ("/zone", Some(json!("Example.test"))),
        ("/zone", Some(json!("example.test."))),
        ("/zone", Some(json!("test"))),
        ("/zone", None),
        ("/zone_sha256", Some(json!("b".repeat(63)))),
        ("/record_sets", Some(json!(0))),
        ("/record_sets", Some(json!(20_001))),
        ("/expected_effects/creates_zone", Some(json!(false))),
        ("/expected_effects/answers_queries", Some(json!(false))),
        ("/expected_effects/changes_other_zones", Some(json!(true))),
        ("/expected_effects/changes_delegation", Some(json!(true))),
        ("/expected_effects/extra", Some(json!(true))),
        ("/expires_at", Some(json!(1000))),
        ("/limitations", Some(json!(vec!["x"; 9]))),
        ("/zone_text", Some(json!("example.test. 3600 IN A 1.2.3.4"))),
        ("/path", Some(json!("/etc/passwd"))),
    ] {
        assert!(
            DnsImportPlan::decode(&edited(PLAN, pointer, new.clone())).is_err(),
            "{pointer} {new:?}"
        );
    }
}

#[test]
fn grant_semantics_are_closed() {
    for (pointer, new) in [
        ("/schema_version", Some(json!(2))),
        ("/verbs", Some(json!(["import_scrub"]))),
        (
            "/verbs",
            Some(json!(["dns_zone_import", "dns_zone_import"])),
        ),
        ("/verbs", Some(json!(["site_restore"]))),
        ("/zones", Some(json!(["example.test", "example.org"]))),
        ("/zones", Some(json!([]))),
        ("/zone_sha256", None),
        ("/max_operations", Some(json!(2))),
        ("/issuer", Some(json!("agent_1"))),
        ("/expires_at", Some(json!(1100))),
        ("/extra", Some(json!(1))),
    ] {
        assert!(
            DnsImportGrant::decode(&edited(GRANT, pointer, new.clone())).is_err(),
            "{pointer} {new:?}"
        );
    }
}

#[test]
fn binding_and_time_are_checked() {
    let plan = DnsImportPlan::decode(PLAN).unwrap();
    for (pointer, new) in [
        ("/plan_digest", json!("c".repeat(64))),
        ("/plan_id", json!("plan_other")),
        ("/host_id", json!("host_other")),
        ("/host_epoch", json!("epoch_2")),
        ("/requester", json!("agent_2")),
        ("/issuer", json!("operator_2")),
        ("/signer_policy_epoch", json!("policy_2")),
        ("/zones", json!(["example.org"])),
        ("/zone_sha256", json!("c".repeat(64))),
        ("/risk_class", json!("production_candidate")),
        ("/valid_from", json!(900)),
        ("/expires_at", json!(2100)),
    ] {
        let grant = DnsImportGrant::decode(&edited(GRANT, pointer, Some(new.clone())));
        if let Ok(grant) = grant {
            assert_eq!(
                check(&plan, &grant, Some(1500)),
                Err(ApprovalError::BindingMismatch),
                "{pointer} {new}"
            );
        }
    }
    let grant = DnsImportGrant::decode(GRANT).unwrap();
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
