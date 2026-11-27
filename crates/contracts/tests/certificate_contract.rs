//! D-059 `certificate_issue` plan/grant checks; no signer, executor or host effects.

use rustiron_contracts::{
    Id, Timestamp,
    approval::{
        ApprovalError, CertificateBindingContext, CertificateGrant, CertificatePlan, PlanKind,
        PreparedPlan, Sha256Digest, check_certificate_binding,
    },
};
use serde_json::{Value, json};

const PLAN: &[u8] = include_bytes!("fixtures/certificate-plan.json");
const ALIAS_PLAN: &[u8] = include_bytes!("fixtures/certificate-plan-alias.json");
const GRANT: &[u8] = include_bytes!("fixtures/certificate-grant.json");
/// Computed independently with Python's json/hashlib when the fixture was made.
const PLAN_DIGEST: &str = "2a77e6b6cb8b921320606ce1254d703905ef16af70529ec4533f788bb1dbcc1f";

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
    plan: &CertificatePlan,
    grant: &CertificateGrant,
    now: Option<u64>,
) -> Result<(), ApprovalError> {
    check_certificate_binding(
        plan,
        grant,
        &CertificateBindingContext {
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
    let plan = CertificatePlan::decode(PLAN).unwrap();
    let grant = CertificateGrant::decode(GRANT).unwrap();
    assert_eq!(plan.digest().as_str(), PLAN_DIGEST);
    assert_eq!(plan.site_id().as_str(), "blog1");
    assert_eq!(plan.hostname().as_str(), "blog1.example.test");
    assert_eq!(grant.grant_id().as_str(), "grant_cert");
    assert_eq!(grant.nonce().as_str(), "nonce_cert");
    assert_eq!(check(&plan, &grant, Some(1500)), Ok(()));
    let prepared = PreparedPlan::decode(PLAN).unwrap();
    assert_eq!(prepared.kind(), PlanKind::CertificateIssue);
    assert_eq!(prepared.kind().as_str(), "certificate_issue");
    assert_eq!(prepared.digest().as_str(), PLAN_DIGEST);
}

#[test]
fn schema_three_binds_the_alias_and_renewal_to_the_grant() {
    let plan = CertificatePlan::decode(ALIAS_PLAN).unwrap();
    assert_eq!(
        plan.alias_hostname()
            .map(rustiron_contracts::approval::Hostname::as_str),
        Some("alternate.example.test")
    );
    assert_eq!(
        plan.digest().as_str(),
        "f5ae0756218526a09471b97f4ca1b11a8fed449212a0d164a2991d80db4df8b4"
    );
    let grant = CertificateGrant::decode(&edited(
        GRANT,
        "/plan_digest",
        Some(json!(plan.digest().as_str())),
    ))
    .unwrap();
    assert_eq!(check(&plan, &grant, Some(1500)), Ok(()));
    for (pointer, new) in [
        ("/alias_hostname", json!("different.example.test")),
        ("/renew_until", json!(3700)),
    ] {
        let changed = CertificatePlan::decode(&edited(ALIAS_PLAN, pointer, Some(new))).unwrap();
        assert_eq!(
            check(&changed, &grant, Some(1500)),
            Err(ApprovalError::BindingMismatch)
        );
    }
}

#[test]
fn schema_three_requires_one_distinct_dns_alias() {
    for (pointer, new) in [
        ("/schema_version", Some(json!(1))),
        ("/schema_version", Some(json!(2))),
        ("/alias_hostname", None),
        ("/alias_hostname", Some(json!(null))),
        ("/alias_hostname", Some(json!("blog1.example.test"))),
        ("/alias_hostname", Some(json!("*.example.test"))),
        ("/renew_until", Some(json!(999))),
        ("/renew_until", Some(json!(1000 + 367 * 24 * 3600))),
    ] {
        assert!(
            CertificatePlan::decode(&edited(ALIAS_PLAN, pointer, new)).is_err(),
            "{pointer}"
        );
    }
    let once = CertificatePlan::decode(&edited(ALIAS_PLAN, "/renew_until", None)).unwrap();
    assert_eq!(once.renew_until(), None);
}

#[test]
fn plan_semantics_are_closed() {
    for (pointer, new) in [
        ("/schema_version", Some(json!(2))),
        ("/verb", Some(json!("site_import"))),
        ("/hostname", Some(json!("*.example.test"))),
        ("/hostname", Some(json!("Blog1.Example.Test"))),
        ("/site_id", Some(json!("Blog1"))),
        (
            "/ca_directory",
            Some(json!("https://acme.example/directory")),
        ),
        ("/expected_effects/traffic_activation", Some(json!(true))),
        ("/expected_effects/dns_change", Some(json!(true))),
        ("/expected_effects/installs_certificate", Some(json!(false))),
        ("/expected_effects/contacts_enrolled_ca", Some(json!(false))),
        (
            "/expected_effects/creates_challenge_webroot",
            Some(json!(false)),
        ),
        ("/expected_effects/extra", Some(json!(true))),
        ("/expected_effects/dns_change", None),
        ("/expires_at", Some(json!(1000))),
        ("/limitations", Some(json!(vec!["x"; 9]))),
        ("/path", Some(json!("/srv/sites/rs_blog1"))),
        ("/command", Some(json!("rm -rf /"))),
        ("/hostname", None),
    ] {
        assert!(
            CertificatePlan::decode(&edited(PLAN, pointer, new.clone())).is_err(),
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
            Some(json!(["certificate_issue", "certificate_issue"])),
        ),
        ("/site_ids", Some(json!(["blog1", "blog2"]))),
        ("/site_ids", Some(json!([]))),
        ("/max_operations", Some(json!(2))),
        ("/issuer", Some(json!("agent_1"))),
        ("/expires_at", Some(json!(1100))),
        ("/extra", Some(json!(1))),
    ] {
        assert!(
            CertificateGrant::decode(&edited(GRANT, pointer, new.clone())).is_err(),
            "{pointer} {new:?}"
        );
    }
}

#[test]
fn binding_and_time_are_checked() {
    let plan = CertificatePlan::decode(PLAN).unwrap();
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
        let grant = CertificateGrant::decode(&edited(GRANT, pointer, Some(new.clone())));
        if let Ok(grant) = grant {
            assert_eq!(
                check(&plan, &grant, Some(1500)),
                Err(ApprovalError::BindingMismatch),
                "{pointer} {new}"
            );
        }
    }
    let grant = CertificateGrant::decode(GRANT).unwrap();
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

/// W464 (D-060): schema 2 grants renewal until a time at most 366 days
/// after `valid_from`; schema 1 grants none.
#[test]
fn schema_two_grants_a_bounded_renewal_window() {
    let v2 = |until: Option<u64>| {
        let mut bytes = edited(PLAN, "/schema_version", Some(json!(2)));
        if let Some(until) = until {
            bytes = edited(&bytes, "/renew_until", Some(json!(until)));
        }
        CertificatePlan::decode(&bytes)
    };
    let plan = v2(Some(1000 + 366 * 24 * 3600)).unwrap();
    assert_eq!(plan.renew_until().unwrap().get(), 1000 + 366 * 24 * 3600);
    assert_eq!(CertificatePlan::decode(PLAN).unwrap().renew_until(), None);
    for until in [
        None,
        Some(1000),
        Some(999),
        Some(1000 + 366 * 24 * 3600 + 1),
    ] {
        assert!(v2(until).is_err(), "{until:?}");
    }
    assert!(
        CertificatePlan::decode(&edited(PLAN, "/renew_until", Some(json!(5000)))).is_err(),
        "schema 1 with a renewal window"
    );
    let prepared = PreparedPlan::decode(&edited(
        &edited(PLAN, "/schema_version", Some(json!(2))),
        "/renew_until",
        Some(json!(5000)),
    ))
    .unwrap();
    assert_eq!(prepared.kind(), PlanKind::CertificateIssue);
}
