//! D-053 `site_import` plan/grant checks; no signer, executor or host effects.

use rustiron_contracts::{
    Id, Timestamp,
    approval::{
        ApprovalError, ImportBindingContext, ImportGrant, ImportPlan, Sha256Digest,
        SiteQuotaLimits, check_import_binding,
    },
    migration::PhpVersion,
};
use serde_json::{Value, json};

const PLAN: &[u8] = include_bytes!("fixtures/import-plan.json");
const ALIAS_PLAN: &[u8] = include_bytes!("fixtures/import-plan-alias.json");
const GRANT: &[u8] = include_bytes!("fixtures/import-grant.json");
/// Computed independently with Python's json/hashlib when the fixture was made.
const PLAN_DIGEST: &str = "1895f25c6f844fe2d4bbd366846581b9a47d2daa753a51c19688923ace660e8c";

fn value(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

/// Replaces the member at `pointer`, or adds a missing top-level member.
fn set(record: &mut Value, pointer: &str, new: Value) {
    match record.pointer_mut(pointer) {
        Some(slot) => *slot = new,
        None => {
            record
                .as_object_mut()
                .unwrap()
                .insert(pointer.trim_start_matches('/').to_owned(), new);
        }
    }
}

fn plan_with(pointer: &str, new: Value) -> Result<ImportPlan, ApprovalError> {
    let mut record = value(PLAN);
    set(&mut record, pointer, new);
    ImportPlan::decode(&serde_json::to_vec(&record).unwrap())
}

fn plan_without(object: &str, member: &str) -> Result<ImportPlan, ApprovalError> {
    let mut record = value(PLAN);
    record
        .pointer_mut(object)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove(member);
    ImportPlan::decode(&serde_json::to_vec(&record).unwrap())
}

fn grant_with(pointer: &str, new: Value) -> Result<ImportGrant, ApprovalError> {
    let mut record = value(GRANT);
    set(&mut record, pointer, new);
    ImportGrant::decode(&serde_json::to_vec(&record).unwrap())
}

fn id(text: &str) -> Id {
    Id::try_from(text.to_owned()).unwrap()
}

fn php(text: &str) -> PhpVersion {
    PhpVersion::try_from(text.to_owned()).unwrap()
}

fn cap() -> SiteQuotaLimits {
    SiteQuotaLimits::new(5_242_880, 500_000).unwrap()
}

fn check_with(
    plan: &ImportPlan,
    grant: &ImportGrant,
    now: Option<u64>,
    php_versions: &[PhpVersion],
    quota_cap: Option<SiteQuotaLimits>,
) -> Result<(), ApprovalError> {
    check_import_binding(
        plan,
        grant,
        &ImportBindingContext {
            host_id: &id("host_lab"),
            host_epoch: &id("epoch_1"),
            profile_digest: &Sha256Digest::try_from("a".repeat(64)).unwrap(),
            requester: &id("agent_1"),
            issuer: &id("operator_1"),
            signer_policy_epoch: &id("policy_1"),
            php_versions,
            now: now.map(|t| Timestamp::try_from(t).unwrap()),
            quota_cap,
        },
    )
}

fn check(plan: &ImportPlan, grant: &ImportGrant, now: Option<u64>) -> Result<(), ApprovalError> {
    check_with(plan, grant, now, &[php("8.2"), php("8.3")], Some(cap()))
}

#[test]
fn fixture_decodes_with_independently_computed_digest_and_binds() {
    let plan = ImportPlan::decode(PLAN).unwrap();
    let grant = ImportGrant::decode(GRANT).unwrap();
    assert_eq!(plan.digest().as_str(), PLAN_DIGEST);
    assert_eq!(plan.site_id().as_str(), "blog1");
    assert_eq!(plan.hostname().as_str(), "blog1.example.test");
    assert_eq!(plan.archive_sha256().as_str(), "b".repeat(64));
    assert_eq!(plan.manifest_sha256().as_str(), "c".repeat(64));
    assert_eq!(
        (plan.file_entries(), plan.file_bytes(), plan.dump_bytes()),
        (4200, 90_000_000, 12_000_000)
    );
    assert_eq!(plan.target_php().as_str(), "8.2");
    assert_eq!(plan.quota_limits(), cap());
    assert_eq!(grant.grant_id().as_str(), "grant_import");
    assert_eq!(grant.nonce().as_str(), "nonce_import");
    assert_eq!(check(&plan, &grant, Some(1500)), Ok(()));
}

#[test]
fn plan_semantics_are_closed() {
    for (pointer, new) in [
        ("/schema_version", json!(2)),
        ("/verb", json!("site_provision")),
        ("/recipe_id", json!("wordpress713_v1")),
        ("/target_php", json!("8")),
        ("/archive_sha256", json!("B".repeat(64))),
        ("/expected_effects/imports_foreign_content", json!(false)),
        ("/expected_effects/traffic_activation", json!(true)),
        ("/expected_effects/network_access", json!(true)),
        ("/expected_effects/sets_quota", json!(false)),
        ("/expected_effects/creates_database", json!(false)),
        ("/observations", json!([])),
        ("/observations/0/state", json!("present")),
        ("/observations/0/site_id", json!("blog2")),
        ("/observations/0/hostname", json!("blog2.example.test")),
        ("/observations/0/observed_at", json!(1001)),
        ("/observations/0/observed_at", json!(699)),
        ("/expires_at", json!(1000)),
        ("/expires_at", json!(4601)),
        ("/limitations", json!(vec!["x"; 9])),
        ("/quota_limits/block_hard_kib", json!(1)),
        ("/quota_limits", json!(null)),
        ("/file_entries", json!(0)),
        ("/file_entries", json!(200_001)),
        ("/dump_bytes", json!(0)),
        ("/dump_bytes", json!(2_147_483_649_u64)),
        ("/file_bytes", json!(5_242_880_u64 * 1024 + 1)),
        // W452-F1: twice the files and dump must fit the block limit.
        ("/file_bytes", json!(5_242_880_u64 * 512 - 12_000_000 + 1)),
        ("/file_entries", json!(500_000)),
        ("/extra", json!(1)),
    ] {
        assert!(
            plan_with(pointer, new.clone()).is_err(),
            "{pointer} = {new}"
        );
    }
    for (object, member) in [
        ("", "archive_sha256"),
        ("", "manifest_sha256"),
        ("", "quota_limits"),
        ("", "target_php"),
        ("/expected_effects", "imports_foreign_content"),
    ] {
        assert!(
            plan_without(object, member).is_err(),
            "without {object}/{member}"
        );
    }
}

#[test]
fn grant_semantics_are_closed() {
    for (pointer, new) in [
        ("/schema_version", json!(2)),
        ("/verbs", json!(["site_provision"])),
        ("/verbs", json!(["site_import", "site_import"])),
        ("/site_ids", json!(["blog1", "blog2"])),
        ("/max_operations", json!(2)),
        ("/issuer", json!("agent_1")),
        ("/expires_at", json!(1100)),
        ("/extra", json!(1)),
    ] {
        assert!(
            grant_with(pointer, new.clone()).is_err(),
            "{pointer} = {new}"
        );
    }
}

#[test]
fn every_bound_field_change_is_a_binding_mismatch() {
    let grant = ImportGrant::decode(GRANT).unwrap();
    // Any plan change moves its digest away from the grant's.
    for (pointer, new) in [
        ("/archive_sha256", json!("e".repeat(64))),
        ("/manifest_sha256", json!("e".repeat(64))),
        ("/file_entries", json!(4201)),
        ("/file_bytes", json!(90_000_001)),
        ("/dump_bytes", json!(12_000_001)),
        ("/target_php", json!("8.3")),
    ] {
        let plan = plan_with(pointer, new.clone()).unwrap();
        assert_eq!(
            check(&plan, &grant, Some(1500)),
            Err(ApprovalError::BindingMismatch),
            "{pointer}"
        );
    }
    let plan = ImportPlan::decode(PLAN).unwrap();
    for (pointer, new) in [
        ("/plan_id", json!("plan_other")),
        ("/host_id", json!("host_other")),
        ("/host_epoch", json!("epoch_2")),
        ("/profile_digest", json!("f".repeat(64))),
        ("/requester", json!("agent_2")),
        ("/site_ids", json!(["blog2"])),
        ("/signer_policy_epoch", json!("policy_2")),
        ("/issuer", json!("operator_2")),
        ("/valid_from", json!(999)),
        ("/expires_at", json!(2001)),
    ] {
        let grant = grant_with(pointer, new.clone()).unwrap();
        assert_eq!(
            check(&plan, &grant, Some(1500)),
            Err(ApprovalError::BindingMismatch),
            "{pointer}"
        );
    }
}

#[test]
fn the_enrolled_profile_bounds_php_and_quota() {
    let plan = ImportPlan::decode(PLAN).unwrap();
    let grant = ImportGrant::decode(GRANT).unwrap();
    assert_eq!(
        check_with(&plan, &grant, Some(1500), &[php("8.3")], Some(cap())),
        Err(ApprovalError::BindingMismatch),
        "a PHP version the host lacks"
    );
    assert_eq!(
        check_with(&plan, &grant, Some(1500), &[php("8.2")], None),
        Err(ApprovalError::BindingMismatch),
        "no enrolled quota cap"
    );
    let small = SiteQuotaLimits::new(5_242_879, 500_000).unwrap();
    assert_eq!(
        check_with(&plan, &grant, Some(1500), &[php("8.2")], Some(small)),
        Err(ApprovalError::BindingMismatch),
        "limits above the cap"
    );
}

#[test]
fn time_must_be_known_and_inside_the_grant_window() {
    let plan = ImportPlan::decode(PLAN).unwrap();
    let grant = ImportGrant::decode(GRANT).unwrap();
    assert_eq!(
        check(&plan, &grant, None),
        Err(ApprovalError::ClockUncertain)
    );
    assert_eq!(
        check(&plan, &grant, Some(1099)),
        Err(ApprovalError::OutsideValidity)
    );
    assert_eq!(
        check(&plan, &grant, Some(1900)),
        Err(ApprovalError::OutsideValidity)
    );
    assert_eq!(check(&plan, &grant, Some(1100)), Ok(()));
}

/// D-074: the static recipe signs no dump and keeps its source hostname;
/// the WordPress recipe still needs one dump.
#[test]
fn the_static_recipe_has_no_dump_and_no_rename() {
    let with = |recipe: &str, dump: u64, schema: u64, source: Option<&str>| {
        let mut record = value(PLAN);
        record["recipe_id"] = json!(recipe);
        record["dump_bytes"] = json!(dump);
        record["schema_version"] = json!(schema);
        if let Some(source) = source {
            record["source_hostname"] = json!(source);
        }
        ImportPlan::decode(&serde_json::to_vec(&record).unwrap())
    };
    let plan = with("import_static_v1", 0, 1, None).unwrap();
    assert!(plan.is_static());
    assert_eq!(plan.dump_bytes(), 0);
    assert!(!ImportPlan::decode(PLAN).unwrap().is_static());
    for (recipe, dump, schema, source, why) in [
        ("import_static_v1", 1, 1, None, "a static plan with a dump"),
        (
            "import_static_v1",
            0,
            2,
            Some("blog1.example.org"),
            "a renamed static plan",
        ),
        ("import_v1", 0, 1, None, "a WordPress plan without a dump"),
    ] {
        assert_eq!(
            with(recipe, dump, schema, source).err(),
            Some(ApprovalError::InvalidPlan),
            "{why}"
        );
    }
}

/// D-070: schema 2 signs a source hostname other than the served one.
#[test]
fn schema_two_signs_a_different_source_hostname() {
    let rename = |schema: u64, source: Value| {
        let mut record = value(PLAN);
        record["schema_version"] = json!(schema);
        record["source_hostname"] = source;
        ImportPlan::decode(&serde_json::to_vec(&record).unwrap())
    };
    let plan = rename(2, json!("blog1.example.org")).unwrap();
    assert_eq!(plan.hostname().as_str(), "blog1.example.test");
    assert_eq!(
        plan.source_hostname().map(|h| h.as_str()),
        Some("blog1.example.org")
    );
    assert_ne!(plan.digest().as_str(), PLAN_DIGEST);
    assert_eq!(ImportPlan::decode(PLAN).unwrap().source_hostname(), None);
    for (schema, source, why) in [
        (2, json!("blog1.example.test"), "the same hostname"),
        (2, json!(null), "schema 2 without a source"),
        (1, json!("blog1.example.org"), "schema 1 with a source"),
    ] {
        assert_eq!(
            rename(schema, source).err(),
            Some(ApprovalError::InvalidPlan),
            "{why}"
        );
    }
    assert_eq!(
        rename(2, json!("Blog1..bad")).err(),
        Some(ApprovalError::InvalidMessage)
    );
    // The absent observation still names the served hostname.
    let mut record = value(PLAN);
    record["schema_version"] = json!(2);
    record["source_hostname"] = json!("blog1.example.org");
    record["observations"][0]["hostname"] = json!("blog1.example.org");
    assert!(ImportPlan::decode(&serde_json::to_vec(&record).unwrap()).is_err());
}

#[test]
fn schema_three_binds_one_exact_static_alias() {
    let plan = ImportPlan::decode(ALIAS_PLAN).unwrap();
    assert!(plan.is_static());
    assert_eq!(
        plan.alias_hostname().map(|hostname| hostname.as_str()),
        Some("alternate.example.test")
    );
    assert_eq!(
        plan.digest().as_str(),
        "a68de5a45f006d6566126b853eb8f1c7d375903f17e6e5ff3d661ba0cbf95d76"
    );
    let grant = grant_with("/plan_digest", json!(plan.digest().as_str())).unwrap();
    assert_eq!(check(&plan, &grant, Some(1500)), Ok(()));

    let mut changed = value(ALIAS_PLAN);
    changed["alias_hostname"] = json!("different.example.test");
    let changed = ImportPlan::decode(&serde_json::to_vec(&changed).unwrap()).unwrap();
    assert_eq!(
        check(&changed, &grant, Some(1500)),
        Err(ApprovalError::BindingMismatch)
    );
}

#[test]
fn other_import_shapes_cannot_reserve_an_alias() {
    let mut missing = value(ALIAS_PLAN);
    missing.as_object_mut().unwrap().remove("alias_hostname");
    assert_eq!(
        ImportPlan::decode(&serde_json::to_vec(&missing).unwrap()).err(),
        Some(ApprovalError::InvalidPlan)
    );

    let mut wordpress = value(PLAN);
    wordpress["schema_version"] = json!(3);
    wordpress["alias_hostname"] = json!("alternate.example.test");
    assert_eq!(
        ImportPlan::decode(&serde_json::to_vec(&wordpress).unwrap()).err(),
        Some(ApprovalError::InvalidPlan)
    );

    for (member, input, error) in [
        ("schema_version", json!(1), ApprovalError::InvalidPlan),
        ("schema_version", json!(2), ApprovalError::InvalidPlan),
        (
            "alias_hostname",
            json!("blog1.example.test"),
            ApprovalError::InvalidPlan,
        ),
        (
            "alias_hostname",
            json!("*.example.test"),
            ApprovalError::InvalidMessage,
        ),
        ("alias_hostname", json!(null), ApprovalError::InvalidMessage),
        (
            "source_hostname",
            json!("source.example.test"),
            ApprovalError::InvalidPlan,
        ),
        ("dump_bytes", json!(1), ApprovalError::InvalidPlan),
    ] {
        let mut rejected = value(ALIAS_PLAN);
        rejected[member] = input;
        assert_eq!(
            ImportPlan::decode(&serde_json::to_vec(&rejected).unwrap()).err(),
            Some(error),
            "{member} = {}",
            rejected[member]
        );
    }
}

#[test]
fn twice_the_content_fits_the_quota_exactly() {
    // 5 GiB block limit: files plus dump may be at most half of it.
    let half = 5_242_880_u64 * 512;
    assert!(plan_with("/file_bytes", json!(half - 12_000_000)).is_ok());
    assert!(plan_with("/file_bytes", json!(half - 12_000_000 + 1)).is_err());
}

#[test]
fn a_prepared_import_plan_keeps_its_kind_id_and_digest() {
    use rustiron_contracts::approval::{PlanKind, PreparedPlan};
    let prepared = PreparedPlan::decode(PLAN).unwrap();
    assert_eq!(prepared.kind(), PlanKind::SiteImport);
    assert_eq!(PlanKind::SiteImport.as_str(), "site_import");
    assert_eq!(prepared.id().as_str(), "plan_import");
    assert_eq!(prepared.digest().as_str(), PLAN_DIGEST);
    let mut record = value(PLAN);
    record["schema_version"] = json!(4);
    assert_eq!(
        PreparedPlan::decode(&serde_json::to_vec(&record).unwrap()).err(),
        Some(ApprovalError::UnsupportedVersion)
    );
    let alias_prepared = PreparedPlan::decode(ALIAS_PLAN).unwrap();
    assert_eq!(alias_prepared.kind(), PlanKind::SiteImport);
    let mut record = value(PLAN);
    record["schema_version"] = json!(3);
    assert_eq!(
        PreparedPlan::decode(&serde_json::to_vec(&record).unwrap()).err(),
        Some(ApprovalError::InvalidPlan)
    );
    let mut record = value(PLAN);
    record["schema_version"] = json!(2);
    record["source_hostname"] = json!("blog1.example.org");
    let prepared = PreparedPlan::decode(&serde_json::to_vec(&record).unwrap()).unwrap();
    assert_eq!(prepared.kind(), PlanKind::SiteImport);
    let mut record = value(PLAN);
    record["file_entries"] = json!(0);
    assert_eq!(
        PreparedPlan::decode(&serde_json::to_vec(&record).unwrap()).err(),
        Some(ApprovalError::InvalidPlan)
    );
}
