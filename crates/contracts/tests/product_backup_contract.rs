//! Pure product backup contract tests, with independently encoded vectors.

use rustiron_contracts::{
    Id, Timestamp,
    approval::{
        ApprovalError, CaptureGrant, CapturePlan, CaptureRecipe, ProbeGrant, ProbePlan,
        ProbeProfile, ProductBackupBindingContext, ProductBackupGrant, ProductBackupPlan,
        ProductBackupTarget, Sha256Digest, check_product_backup_binding,
    },
};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
struct Vector {
    name: String,
    plan_input: String,
    plan_canonical: String,
    plan_digest: String,
    grant_input: String,
    grant_canonical: String,
}

fn vectors() -> Vec<Vector> {
    serde_json::from_str(include_str!("fixtures/product-backup-vectors.json")).unwrap()
}

fn vector(name: &str) -> Vector {
    vectors()
        .into_iter()
        .find(|vector| vector.name == name)
        .unwrap()
}

fn with(input: &str, field: &str, value: Value) -> String {
    let mut changed: Value = serde_json::from_str(input).unwrap();
    changed[field] = value;
    changed.to_string()
}

fn id(value: &str) -> Id {
    Id::try_from(value.to_owned()).unwrap()
}

fn bind(
    plan: &ProductBackupPlan,
    grant: &ProductBackupGrant,
    now: Option<u64>,
) -> Result<(), ApprovalError> {
    check_product_backup_binding(
        plan,
        grant,
        &ProductBackupBindingContext {
            host_id: &id("host_lab"),
            host_epoch: &id("epoch_1"),
            profile_digest: &Sha256Digest::try_from("a".repeat(64)).unwrap(),
            requester: &id("agent_1"),
            issuer: &id("operator_1"),
            signer_policy_epoch: &id("policy_1"),
            now: now.map(|value| Timestamp::try_from(value).unwrap()),
        },
    )
}

#[test]
fn both_verbs_match_independent_plan_digest_and_grant_bytes() {
    for vector in vectors() {
        let plan = ProductBackupPlan::decode(vector.plan_input.as_bytes()).unwrap();
        let grant = ProductBackupGrant::decode(vector.grant_input.as_bytes()).unwrap();
        assert_eq!(plan.as_bytes(), vector.plan_canonical.as_bytes());
        assert_eq!(plan.digest().as_str(), vector.plan_digest);
        assert_eq!(grant.as_bytes(), vector.grant_canonical.as_bytes());
        assert_eq!(
            grant.grant_id().as_str(),
            format!("grant_product_{}", vector.name)
        );
        assert_eq!(
            grant.nonce().as_str(),
            format!("nonce_product_{}", vector.name)
        );
        assert_eq!(grant.expires_at().get(), 1900);
        assert_eq!(plan.destination_id().as_str(), "offsite_fixture");
        assert_eq!(plan.destination_policy_digest().as_str(), "b".repeat(64));
        match (vector.name.as_str(), plan.target()) {
            (
                "capture",
                ProductBackupTarget::BackupCapture {
                    recipe_id: CaptureRecipe::SiteFilesDbV1,
                },
            ) => {
                assert_eq!(plan.site_id().as_str(), "blog9");
            }
            (
                "probe",
                ProductBackupTarget::RestoreProbe {
                    snapshot_id,
                    profile_id: ProbeProfile::LocalNoEgressV1,
                },
            ) => {
                assert_eq!(plan.site_id().as_str(), "blog13");
                assert_eq!(
                    snapshot_id.as_str(),
                    "63ba950462d475de22f0f9f73449dfc311db71a2036352a86f8e38b155590409"
                );
            }
            other => panic!("unexpected target: {other:?}"),
        }
        assert_eq!(bind(&plan, &grant, Some(1100)), Ok(()));
        assert_eq!(
            bind(&plan, &grant, Some(1099)),
            Err(ApprovalError::OutsideValidity)
        );
        assert_eq!(
            bind(&plan, &grant, Some(1900)),
            Err(ApprovalError::OutsideValidity)
        );
        assert_eq!(
            bind(&plan, &grant, None),
            Err(ApprovalError::ClockUncertain)
        );
    }
}

#[test]
fn product_records_cannot_decode_as_lab_or_the_other_way_round() {
    let capture = vector("capture");
    let probe = vector("probe");
    assert!(CapturePlan::decode(capture.plan_input.as_bytes()).is_err());
    assert!(CaptureGrant::decode(capture.grant_input.as_bytes()).is_err());
    assert!(ProbePlan::decode(probe.plan_input.as_bytes()).is_err());
    assert!(ProbeGrant::decode(probe.grant_input.as_bytes()).is_err());
    for plan in [
        include_bytes!("fixtures/capture-plan.json").as_slice(),
        include_bytes!("fixtures/probe-plan.json").as_slice(),
    ] {
        assert!(ProductBackupPlan::decode(plan).is_err());
    }
    for grant in [
        include_bytes!("fixtures/capture-grant.json").as_slice(),
        include_bytes!("fixtures/probe-grant.json").as_slice(),
    ] {
        assert!(ProductBackupGrant::decode(grant).is_err());
    }
}

#[test]
fn product_plan_refuses_unbounded_or_ambiguous_target_fields() {
    let capture = vector("capture");
    for (field, value) in [
        ("schema_version", json!(1)),
        ("risk_class", json!("lab_only")),
        ("destination_id", json!("lab_pc_store")),
        ("destination_id", json!("s3://host/store")),
        ("destination_policy_digest", json!("B".repeat(64))),
        ("destination_policy_digest", json!("b".repeat(63))),
        ("expires_at", json!(4601)),
        ("limitations", json!(vec!["x"; 9])),
        ("recipe_id", json!("arbitrary")),
        ("profile_id", Value::Null),
        ("snapshot_id", json!("f".repeat(64))),
        ("repository_base", json!("s3://elsewhere")),
    ] {
        assert!(
            ProductBackupPlan::decode(with(&capture.plan_input, field, value).as_bytes()).is_err(),
            "{field}"
        );
    }
    let duplicate = format!(
        r#"{{"\u0076erb":"backup_capture",{}"#,
        &capture.plan_input[1..]
    );
    assert!(ProductBackupPlan::decode(duplicate.as_bytes()).is_err());
    let probe = vector("probe");
    for (field, value) in [
        ("snapshot_id", json!("latest")),
        ("profile_id", json!("host_mount")),
        ("recipe_id", json!("site_files_db_v1")),
    ] {
        assert!(
            ProductBackupPlan::decode(with(&probe.plan_input, field, value).as_bytes()).is_err(),
            "{field}"
        );
    }
}

#[test]
fn product_grant_refuses_expanded_scope_and_wrong_verb_shape() {
    let capture = vector("capture");
    for (field, value) in [
        ("schema_version", json!(1)),
        ("risk_class", json!("lab_only")),
        ("issuer", json!("agent_1")),
        ("max_operations", json!(2)),
        ("destinations", json!([])),
        ("destinations", json!(["offsite_fixture", "other"])),
        ("destinations", json!(["lab_pc_store"])),
        ("site_ids", json!(["blog9", "blog13"])),
        ("verbs", json!(["backup_capture", "restore_probe"])),
        ("snapshot_ids", Value::Null),
        ("snapshot_ids", json!(["f".repeat(64)])),
        ("destination_policy_digest", json!("b".repeat(64))),
    ] {
        assert!(
            ProductBackupGrant::decode(with(&capture.grant_input, field, value).as_bytes())
                .is_err(),
            "{field}"
        );
    }
    let probe = vector("probe");
    for value in [
        Value::Null,
        json!([]),
        json!(["1".repeat(64), "2".repeat(64)]),
    ] {
        assert!(
            ProductBackupGrant::decode(with(&probe.grant_input, "snapshot_ids", value).as_bytes())
                .is_err()
        );
    }
}

#[test]
fn product_binding_refuses_digest_and_exact_scope_substitution() {
    let probe = vector("probe");
    let plan = ProductBackupPlan::decode(probe.plan_input.as_bytes()).unwrap();
    let original_grant = ProductBackupGrant::decode(probe.grant_input.as_bytes()).unwrap();
    let changed_policy = with(
        &probe.plan_input,
        "destination_policy_digest",
        json!("c".repeat(64)),
    );
    let changed_policy = ProductBackupPlan::decode(changed_policy.as_bytes()).unwrap();
    assert_ne!(changed_policy.digest(), plan.digest());
    assert_eq!(
        bind(&changed_policy, &original_grant, Some(1200)),
        Err(ApprovalError::BindingMismatch)
    );
    for (field, value) in [
        ("destinations", json!(["other_destination"])),
        ("site_ids", json!(["blog9"])),
        ("snapshot_ids", json!(["f".repeat(64)])),
        ("expires_at", json!(2001)),
        ("valid_from", json!(999)),
        ("profile_digest", json!("b".repeat(64))),
        ("issuer", json!("operator_2")),
        ("signer_policy_epoch", json!("policy_2")),
    ] {
        let changed = with(&probe.grant_input, field, value);
        let grant = ProductBackupGrant::decode(changed.as_bytes()).unwrap();
        assert_eq!(
            bind(&plan, &grant, Some(1200)),
            Err(ApprovalError::BindingMismatch),
            "{field}"
        );
    }
    let mut wrong_verb: Value = serde_json::from_str(&probe.grant_input).unwrap();
    wrong_verb["verbs"] = json!(["backup_capture"]);
    wrong_verb.as_object_mut().unwrap().remove("snapshot_ids");
    let grant = ProductBackupGrant::decode(wrong_verb.to_string().as_bytes()).unwrap();
    assert_eq!(
        bind(&plan, &grant, Some(1200)),
        Err(ApprovalError::BindingMismatch)
    );
}
