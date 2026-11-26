//! Plan identity and bytes are derived from validated semantic content.

use rustiron_contracts::approval::{ApprovalError, PlanKind, PreparedPlan};

#[test]
fn five_closed_plans_produce_their_validated_id_digest_and_canonical_bytes() {
    for (input, id, kind, digest) in [
        (
            include_bytes!("fixtures/site-plan.json").as_slice(),
            "plan_site",
            PlanKind::SiteProvision,
            "c33d38f7e35973b5dfb88846d667b06ee9f1d2544fe1fcfa35354797553b2ccf",
        ),
        (
            include_bytes!("fixtures/ols-plan.json").as_slice(),
            "plan_ols",
            PlanKind::ConfigActivate,
            "00d79e742240c6626d1c5fb3e4415cf158bca560e7c71bbdf0fcae33eb9eb88f",
        ),
        (
            include_bytes!("fixtures/eject-plan.json").as_slice(),
            "plan_eject",
            PlanKind::SiteEject,
            "ca015fc46a331406c894bff50a4de8314d65e67c7f8834574520e651ba830727",
        ),
        (
            include_bytes!("fixtures/capture-plan.json").as_slice(),
            "plan_capture",
            PlanKind::BackupCapture,
            "31441613f3d96fe2b9cbdafa8dceea164405fa09d877d63ccdda3d06f3e28135",
        ),
        (
            include_bytes!("fixtures/probe-plan.json").as_slice(),
            "plan_probe",
            PlanKind::RestoreProbe,
            "38d7827be2d1c72f470a71fe34a0172f0b9fdd877ac9ea1532a7e48aa795caf9",
        ),
    ] {
        let plan = PreparedPlan::decode(input).unwrap();
        assert_eq!(plan.id().as_str(), id);
        assert_eq!(plan.kind(), kind);
        assert_eq!(plan.digest().as_str(), digest);
        let expected: serde_json::Value = serde_json::from_slice(input).unwrap();
        let actual: serde_json::Value = serde_json::from_slice(plan.as_bytes()).unwrap();
        assert_eq!(actual, expected);
        let roundtrip = PreparedPlan::decode(plan.as_bytes()).unwrap();
        assert_eq!(roundtrip.digest(), plan.digest());
        assert_eq!(roundtrip.id(), plan.id());
    }
}

#[test]
fn rejects_grants_unknown_verbs_duplicate_keys_and_semantically_invalid_plans() {
    let grant = include_bytes!("fixtures/site-grant.json");
    assert!(PreparedPlan::decode(grant).is_err());
    let fixture_switch = include_bytes!("fixtures/fixture-plan.json");
    assert_eq!(
        PreparedPlan::decode(fixture_switch).err(),
        Some(ApprovalError::InvalidMessage)
    );
    let bytes = include_bytes!("fixtures/site-plan.json");
    let mut plan: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    plan["verb"] = "unknown_verb".into();
    assert_eq!(
        PreparedPlan::decode(&serde_json::to_vec(&plan).unwrap()).err(),
        Some(ApprovalError::InvalidMessage)
    );
    plan["verb"] = "site_provision".into();
    plan["expected_effects"]["traffic_activation"] = true.into();
    assert_eq!(
        PreparedPlan::decode(&serde_json::to_vec(&plan).unwrap()).err(),
        Some(ApprovalError::InvalidPlan)
    );
    let duplicate = String::from_utf8(bytes.to_vec()).unwrap().replace(
        "\"plan_id\": \"plan_site\"",
        "\"plan_id\": \"plan_site\", \"plan_id\": \"other\"",
    );
    assert_eq!(
        PreparedPlan::decode(duplicate.as_bytes()).err(),
        Some(ApprovalError::InvalidMessage)
    );
}

#[test]
fn changing_the_plan_id_changes_the_canonical_digest() {
    let input = include_bytes!("fixtures/site-plan.json");
    let original = PreparedPlan::decode(input).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(input).unwrap();
    value["plan_id"] = "another_plan".into();
    let changed = PreparedPlan::decode(&serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(changed.id().as_str(), "another_plan");
    assert_ne!(changed.digest(), original.digest());
}
