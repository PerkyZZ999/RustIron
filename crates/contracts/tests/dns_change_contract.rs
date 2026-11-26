//! D-091 `dns_change` plan/grant checks (W553); no signer, executor or host effects.

use rustiron_contracts::{
    Id, Timestamp,
    approval::{
        ApprovalError, ChangeAction, DnsBindingContext, DnsChangeGrant, DnsChangePlan, Expected,
        PlanKind, PreparedPlan, RecordType, Sha256Digest, check_dns_change_binding,
    },
};
use serde_json::{Value, json};

const PLAN: &[u8] = include_bytes!("fixtures/dns-change-plan.json");
const GRANT: &[u8] = include_bytes!("fixtures/dns-change-grant.json");
/// Computed independently with Python's json/hashlib when the fixture was made.
const PLAN_DIGEST: &str = "314fb7e2c2325c30df93f5c9993a8953851e1630485e2eda54c64230dfe03be8";
/// SHA-256 of `example.test. 3600 IN TXT "v=spf1 mx ~all"\n`, from Python.
const OLD_SPF: &str = "479d745e964aacff8f713b28f2894091470192b67cf152a0229a2185676464e6";
/// SHA-256 of `www.example.test. 300 IN A 203.0.113.30\n`, from Python.
const NEW_WWW: &str = "d7fbcbc06773ac6c165a8efa67057d19e09f8812710fc943be7eddb9a0734835";

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

fn id(text: &str) -> Id {
    Id::try_from(text.to_owned()).unwrap()
}

fn check(
    plan: &DnsChangePlan,
    grant: &DnsChangeGrant,
    now: Option<u64>,
) -> Result<(), ApprovalError> {
    check_dns_change_binding(
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
fn fixture_decodes_with_independently_computed_digests_and_binds() {
    let plan = DnsChangePlan::decode(PLAN).unwrap();
    let grant = DnsChangeGrant::decode(GRANT).unwrap();
    assert_eq!(plan.digest().as_str(), PLAN_DIGEST);
    assert_eq!(plan.zone().as_str(), "example.test");
    let operations = plan.operations();
    assert_eq!(operations.len(), 3);
    assert_eq!(
        operations[0].expected,
        Expected::Digest(Sha256Digest::try_from(OLD_SPF.to_owned()).unwrap())
    );
    assert!(operations[0].is_mail(plan.zone()));
    assert!(!operations[1].is_mail(plan.zone()));
    assert_eq!(operations[1].expected, Expected::Absent);
    assert_eq!(operations[1].new_set().unwrap().digest().as_str(), NEW_WWW);
    assert_eq!(operations[2].kind, RecordType::Cname);
    assert_eq!(operations[2].action, ChangeAction::Remove);
    assert!(operations[2].new_set().is_none());
    assert_eq!(grant.grant_id().as_str(), "grant_dns_change");
    assert_eq!(check(&plan, &grant, Some(1500)), Ok(()));
    let prepared = PreparedPlan::decode(PLAN).unwrap();
    assert_eq!(prepared.kind(), PlanKind::DnsChange);
    assert_eq!(prepared.kind().as_str(), "dns_change");
    assert_eq!(prepared.digest().as_str(), PLAN_DIGEST);
}

#[test]
fn plan_semantics_are_closed() {
    let many: Vec<Value> = (0..17)
        .map(|n| {
            json!({"owner": format!("h{n}.example.test."), "type": "A", "expected": "absent",
                   "action": "replace", "ttl": 300, "records": ["203.0.113.1"]})
        })
        .collect();
    let a_records: Vec<String> = (1..=33).map(|n| format!("203.0.113.{n}")).collect();
    for (pointer, new) in [
        ("/schema_version", Some(json!(2))),
        ("/zone", Some(json!("Example.test"))),
        ("/zone", None),
        ("/operations", Some(json!([]))),
        ("/operations", Some(json!(many))),
        ("/operations/1/type", Some(json!("SOA"))),
        ("/operations/1/type", Some(json!("NS"))),
        ("/operations/1/type", Some(json!("PTR"))),
        ("/operations/1/owner", Some(json!("www.example.org."))),
        ("/operations/1/owner", Some(json!("www.example.test"))),
        ("/operations/1/owner", Some(json!("WWW.example.test."))),
        (
            "/operations/1/records",
            Some(json!(["203.0.113.31", "203.0.113.30"])),
        ),
        (
            "/operations/1/records",
            Some(json!(["203.0.113.30", "203.0.113.30"])),
        ),
        ("/operations/1/records", Some(json!(a_records))),
        ("/operations/1/records", Some(json!(["203.0.113.300"]))),
        ("/operations/1/records", Some(json!([]))),
        ("/operations/1/records", None),
        ("/operations/1/ttl", Some(json!(30))),
        ("/operations/1/ttl", None),
        ("/operations/1/expected", Some(json!("abc"))),
        ("/operations/1/action", Some(json!("remove"))),
        ("/operations/1/extra", Some(json!(1))),
        ("/operations/2/ttl", Some(json!(300))),
        ("/operations/2/expected", Some(json!("absent"))),
        ("/operations/2/owner", Some(json!("example.test."))),
        ("/operations/2/action", Some(json!("replace"))),
        ("/operations/2/ttl", Some(json!(null))),
        ("/operations/1", Some(json!(["www.example.test.", "A"]))),
        ("/expected_effects/changes_records", Some(json!(false))),
        ("/expected_effects/changes_soa_or_ns", Some(json!(true))),
        ("/expected_effects/changes_other_zones", Some(json!(true))),
        ("/expected_effects/changes_delegation", Some(json!(true))),
        ("/expires_at", Some(json!(1000))),
        ("/limitations", Some(json!(vec!["x"; 9]))),
        ("/zone_text", Some(json!("example.test. 3600 IN A 1.2.3.4"))),
    ] {
        assert!(
            DnsChangePlan::decode(&edited(PLAN, pointer, new.clone())).is_err(),
            "{pointer} {new:?}"
        );
    }
    // Two operations on one owner and type.
    let mut record: Value = serde_json::from_slice(PLAN).unwrap();
    let first = record["operations"][1].clone();
    record["operations"].as_array_mut().unwrap().push(first);
    assert!(DnsChangePlan::decode(&serde_json::to_vec(&record).unwrap()).is_err());
    // A CNAME replacement holds exactly one target, never at the apex.
    let mut record: Value = serde_json::from_slice(PLAN).unwrap();
    record["operations"][2] = json!({"owner": "old.example.test.", "type": "CNAME",
        "expected": "absent", "action": "replace", "ttl": 300,
        "records": ["a.example.test.", "b.example.test."]});
    assert!(DnsChangePlan::decode(&serde_json::to_vec(&record).unwrap()).is_err());
}

#[test]
fn grant_semantics_are_closed() {
    for (pointer, new) in [
        ("/schema_version", Some(json!(2))),
        ("/verbs", Some(json!(["dns_zone_import"]))),
        ("/verbs", Some(json!(["dns_change", "dns_change"]))),
        ("/zones", Some(json!(["example.test", "example.org"]))),
        ("/zones", Some(json!([]))),
        ("/max_operations", Some(json!(2))),
        ("/issuer", Some(json!("agent_1"))),
        ("/expires_at", Some(json!(1100))),
        ("/extra", Some(json!(1))),
    ] {
        assert!(
            DnsChangeGrant::decode(&edited(GRANT, pointer, new.clone())).is_err(),
            "{pointer} {new:?}"
        );
    }
}

#[test]
fn binding_and_time_are_checked() {
    let plan = DnsChangePlan::decode(PLAN).unwrap();
    for (pointer, new) in [
        ("/plan_digest", json!("c".repeat(64))),
        ("/plan_id", json!("plan_other")),
        ("/host_id", json!("host_other")),
        ("/host_epoch", json!("epoch_2")),
        ("/requester", json!("agent_2")),
        ("/issuer", json!("operator_2")),
        ("/signer_policy_epoch", json!("policy_2")),
        ("/zones", json!(["example.org"])),
        ("/risk_class", json!("production_candidate")),
        ("/valid_from", json!(900)),
        ("/expires_at", json!(2100)),
    ] {
        if let Ok(grant) = DnsChangeGrant::decode(&edited(GRANT, pointer, Some(new.clone()))) {
            assert_eq!(
                check(&plan, &grant, Some(1500)),
                Err(ApprovalError::BindingMismatch),
                "{pointer} {new}"
            );
        }
    }
    let grant = DnsChangeGrant::decode(GRANT).unwrap();
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
