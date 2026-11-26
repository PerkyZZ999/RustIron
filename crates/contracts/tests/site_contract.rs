//! Public `site_provision` plan/grant checks; no signer, executor or host effects.

use rustiron_contracts::{
    Id, Timestamp,
    approval::{
        ApprovalError, PreparedPlan, Sha256Digest, SiteBindingContext, SiteGrant, SitePlan,
        SiteQuotaLimits, SiteRecipe, check_site_binding,
    },
};
use serde::Deserialize;
use serde_json::{Value, json};

const PLAN: &[u8] = include_bytes!("fixtures/site-plan.json");
const GRANT: &[u8] = include_bytes!("fixtures/site-grant.json");
/// Computed independently with Python's json/hashlib when the fixture was made.
const PLAN_DIGEST: &str = "c33d38f7e35973b5dfb88846d667b06ee9f1d2544fe1fcfa35354797553b2ccf";

fn value(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

fn plan_with(pointer: &str, new: Value) -> Result<SitePlan, ApprovalError> {
    let mut record = value(PLAN);
    *record.pointer_mut(pointer).unwrap() = new;
    SitePlan::decode(&serde_json::to_vec(&record).unwrap())
}

fn grant_with(pointer: &str, new: Value) -> Result<SiteGrant, ApprovalError> {
    let mut record = value(GRANT);
    *record.pointer_mut(pointer).unwrap() = new;
    SiteGrant::decode(&serde_json::to_vec(&record).unwrap())
}

fn id(text: &str) -> Id {
    Id::try_from(text.to_owned()).unwrap()
}

fn check(plan: &SitePlan, grant: &SiteGrant, now: Option<u64>) -> Result<(), ApprovalError> {
    check_with_recipe(plan, grant, now, &"d".repeat(64))
}

fn check_with_recipe(
    plan: &SitePlan,
    grant: &SiteGrant,
    now: Option<u64>,
    recipe: &str,
) -> Result<(), ApprovalError> {
    check_with(plan, grant, now, recipe, Some(default_cap()))
}

fn default_cap() -> SiteQuotaLimits {
    SiteQuotaLimits::new(5_242_880, 500_000).unwrap()
}

fn check_with(
    plan: &SitePlan,
    grant: &SiteGrant,
    now: Option<u64>,
    recipe: &str,
    quota_cap: Option<SiteQuotaLimits>,
) -> Result<(), ApprovalError> {
    check_site_binding(
        plan,
        grant,
        &SiteBindingContext {
            host_id: &id("host_lab"),
            host_epoch: &id("epoch_1"),
            profile_digest: &Sha256Digest::try_from("a".repeat(64)).unwrap(),
            requester: &id("agent_1"),
            issuer: &id("operator_1"),
            signer_policy_epoch: &id("policy_1"),
            wordpress_713_digest: &Sha256Digest::try_from(recipe.to_owned()).unwrap(),
            now: now.map(|t| Timestamp::try_from(t).unwrap()),
            quota_cap,
        },
    )
}

#[test]
fn fixture_decodes_with_independently_computed_digest_and_binds() {
    let plan = SitePlan::decode(PLAN).unwrap();
    let grant = SiteGrant::decode(GRANT).unwrap();
    assert_eq!(plan.digest().as_str(), PLAN_DIGEST);
    assert_eq!(plan.site_id().as_str(), "blog1");
    assert_eq!(plan.hostname().as_str(), "blog1.example.test");
    assert_eq!(
        SitePlan::decode(plan.as_bytes()).unwrap().digest(),
        plan.digest()
    );
    assert_eq!(check(&plan, &grant, Some(1200)), Ok(()));
}

#[test]
fn invalid_site_ids_are_refused() {
    for bad in [
        "Blog1",
        "1blog",
        "ab",
        "abcdefghijklmnopq",
        "blog-1",
        "blog_1",
        "../x",
        "blog1 ",
        "",
    ] {
        assert_eq!(
            plan_with("/site_id", json!(bad)).err(),
            Some(ApprovalError::InvalidMessage),
            "{bad:?}"
        );
    }
}

#[test]
fn invalid_hostnames_are_refused() {
    let long = format!("{}.test", "a".repeat(250));
    let label = format!("{}.test", "a".repeat(64));
    for bad in [
        "localhost",
        "-a.test",
        "a-.test",
        "Blog1.example.test",
        "a..test",
        "ex ample.test",
        "bl\u{f6}g.test",
        "blog1.example.test.",
        long.as_str(),
        label.as_str(),
    ] {
        assert_eq!(
            plan_with("/hostname", json!(bad)).err(),
            Some(ApprovalError::InvalidMessage),
            "{bad:?}"
        );
    }
}

#[test]
fn plan_semantics_are_closed() {
    for (pointer, new) in [
        ("/expected_effects/traffic_activation", json!(true)),
        ("/expected_effects/network_access", json!(true)),
        ("/observations/0/site_id", json!("blog2")),
        ("/observations/0/hostname", json!("other.example.test")),
        ("/observations/0/observed_at", json!(1001)),
        ("/observations/0/observed_at", json!(699)),
        ("/expires_at", json!(4601)),
    ] {
        assert_eq!(
            plan_with(pointer, new).err(),
            Some(ApprovalError::InvalidPlan),
            "{pointer}"
        );
    }
    for (pointer, new) in [
        ("/verb", json!("config_activate")),
        ("/recipe_id", json!("wordpress_latest")),
        ("/observations/0/state", json!("observed")),
    ] {
        assert_eq!(
            plan_with(pointer, new).err(),
            Some(ApprovalError::InvalidMessage),
            "{pointer}"
        );
    }
    let mut extra = value(PLAN);
    extra["uid"] = json!(0);
    assert_eq!(
        SitePlan::decode(&serde_json::to_vec(&extra).unwrap()).err(),
        Some(ApprovalError::InvalidMessage)
    );
    assert_eq!(
        plan_with("/schema_version", json!(3)).err(),
        Some(ApprovalError::UnsupportedVersion)
    );
}

#[test]
fn grant_semantics_are_closed() {
    for (pointer, new) in [
        ("/issuer", json!("agent_1")),
        ("/site_ids", json!(["blog1", "blog2"])),
        ("/max_operations", json!(2)),
        ("/verbs", json!(["site_provision", "site_provision"])),
        ("/expires_at", json!(4701)),
    ] {
        assert_eq!(
            grant_with(pointer, new).err(),
            Some(ApprovalError::InvalidGrant),
            "{pointer}"
        );
    }
    assert_eq!(
        grant_with("/verbs", json!(["config_activate"])).err(),
        Some(ApprovalError::InvalidMessage)
    );
}

#[test]
fn every_bound_field_change_is_a_binding_mismatch() {
    let plan = SitePlan::decode(PLAN).unwrap();
    for (pointer, new) in [
        ("/plan_digest", json!("e".repeat(64))),
        ("/plan_id", json!("plan_other")),
        ("/host_id", json!("host_other")),
        ("/host_epoch", json!("epoch_2")),
        ("/profile_digest", json!("b".repeat(64))),
        ("/requester", json!("agent_2")),
        ("/site_ids", json!(["blog2"])),
        ("/issuer", json!("operator_2")),
        ("/signer_policy_epoch", json!("policy_2")),
        ("/valid_from", json!(999)),
        ("/expires_at", json!(2001)),
    ] {
        let grant = grant_with(pointer, new).unwrap();
        assert_eq!(
            check(&plan, &grant, Some(1200)),
            Err(ApprovalError::BindingMismatch),
            "{pointer}"
        );
    }
    let grant = SiteGrant::decode(GRANT).unwrap();
    assert_eq!(
        check_with_recipe(&plan, &grant, Some(1200), &"f".repeat(64)),
        Err(ApprovalError::BindingMismatch)
    );
    let other_site = plan_with("/site_id", json!("blog2")).err();
    assert_eq!(other_site, Some(ApprovalError::InvalidPlan));
}

#[test]
fn time_must_be_known_and_inside_the_grant_window() {
    let plan = SitePlan::decode(PLAN).unwrap();
    let grant = SiteGrant::decode(GRANT).unwrap();
    assert_eq!(
        check(&plan, &grant, None),
        Err(ApprovalError::ClockUncertain)
    );
    for now in [1099, 1900] {
        assert_eq!(
            check(&plan, &grant, Some(now)),
            Err(ApprovalError::OutsideValidity)
        );
    }
}

#[test]
fn install_recipe_uses_the_same_enrolled_artifact_and_is_signed_distinctly() {
    let plan = plan_with("/recipe_id", json!("wordpress713_install_v1")).unwrap();
    assert_eq!(plan.recipe().0, SiteRecipe::Wordpress713InstallV1);
    assert_ne!(plan.digest().as_str(), PLAN_DIGEST);
    let old_grant = SiteGrant::decode(GRANT).unwrap();
    assert_eq!(
        check(&plan, &old_grant, Some(1200)),
        Err(ApprovalError::BindingMismatch),
        "a grant for the unpack-only recipe never covers the install"
    );
    let grant = grant_with("/plan_digest", json!(plan.digest().as_str())).unwrap();
    assert_eq!(check(&plan, &grant, Some(1200)), Ok(()));
    assert_eq!(
        check_with_recipe(&plan, &grant, Some(1200), &"f".repeat(64)),
        Err(ApprovalError::BindingMismatch)
    );
}

// ---- W341: schema v2 carries per-site quota limits (D-028 item 3) ----

/// Encoded independently with Python's json/hashlib; see check_canonical_vectors.py.
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
    serde_json::from_str(include_str!("fixtures/site-plan-v2-vectors.json")).unwrap()
}

fn v2_value() -> Value {
    serde_json::from_str(&vectors()[0].plan_input).unwrap()
}

fn v2_with(pointer: &str, new: Value) -> Result<SitePlan, ApprovalError> {
    let mut record = v2_value();
    *record.pointer_mut(pointer).unwrap() = new;
    SitePlan::decode(&serde_json::to_vec(&record).unwrap())
}

fn v2_without(object: &str, member: &str) -> Result<SitePlan, ApprovalError> {
    let mut record = v2_value();
    record
        .pointer_mut(object)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove(member);
    SitePlan::decode(&serde_json::to_vec(&record).unwrap())
}

fn cap(block_hard_kib: u64, inode_hard: u64) -> SiteQuotaLimits {
    SiteQuotaLimits::new(block_hard_kib, inode_hard).unwrap()
}

#[test]
fn v2_vectors_match_independent_bytes_digest_and_grant() {
    for vector in vectors() {
        let plan = SitePlan::decode(vector.plan_input.as_bytes()).unwrap();
        let grant = SiteGrant::decode(vector.grant_input.as_bytes()).unwrap();
        assert_eq!(plan.as_bytes(), vector.plan_canonical.as_bytes());
        assert_eq!(plan.digest().as_str(), vector.plan_digest);
        assert_eq!(grant.as_bytes(), vector.grant_canonical.as_bytes());
        assert_eq!(plan.schema_version(), 2);
        let prepared = PreparedPlan::decode(vector.plan_input.as_bytes()).unwrap();
        assert_eq!(prepared.digest(), plan.digest(), "{}", vector.name);
        assert_eq!(prepared.kind().as_str(), "site_provision");
        assert_eq!(
            check(&plan, &grant, Some(1200)),
            Ok(()),
            "{} binds under the default cap",
            vector.name
        );
    }
    let default = SitePlan::decode(vectors()[0].plan_input.as_bytes()).unwrap();
    assert_eq!(default.quota_limits(), Some(default_cap()));
    let minimum = SitePlan::decode(vectors()[1].plan_input.as_bytes()).unwrap();
    assert_eq!(minimum.quota_limits(), Some(cap(65_536, 1_000)));
    assert_eq!(minimum.recipe().0, SiteRecipe::Wordpress713InstallV1);
}

#[test]
fn v1_keeps_its_meaning_and_never_carries_limits() {
    let plan = SitePlan::decode(PLAN).unwrap();
    assert_eq!(plan.schema_version(), 1);
    assert_eq!(plan.quota_limits(), None, "v1 limits come from policy");
    assert_eq!(plan.digest().as_str(), PLAN_DIGEST);
    let grant = SiteGrant::decode(GRANT).unwrap();
    let small = cap(65_536, 1_000);
    for quota_cap in [None, Some(default_cap()), Some(small)] {
        assert_eq!(
            check_with(&plan, &grant, Some(1200), &"d".repeat(64), quota_cap),
            Ok(()),
            "{quota_cap:?}"
        );
    }
    let mut with_limits = value(PLAN);
    with_limits["quota_limits"] = json!({"block_hard_kib": 5_242_880, "inode_hard": 500_000});
    assert_eq!(
        SitePlan::decode(&serde_json::to_vec(&with_limits).unwrap()).err(),
        Some(ApprovalError::InvalidPlan),
        "v1 with limits"
    );
    assert_eq!(
        plan_with(
            "/expected_effects",
            json!({
                "creates_account": true, "creates_database": true,
                "traffic_activation": false, "network_access": false, "sets_quota": true,
            })
        )
        .err(),
        Some(ApprovalError::InvalidPlan),
        "v1 with sets_quota"
    );
}

#[test]
fn v2_limits_have_strict_bounds() {
    let max_kib = 16 * 1024 * 1024 * 1024_u64;
    for (kib, inodes) in [(65_536, 1_000), (max_kib, 100_000_000)] {
        let limits = json!({"block_hard_kib": kib, "inode_hard": inodes});
        let plan = v2_with("/quota_limits", limits).unwrap();
        assert_eq!(plan.quota_limits(), Some(cap(kib, inodes)));
    }
    for (kib, inodes) in [
        (0, 500_000),
        (65_535, 500_000),
        (max_kib + 1, 500_000),
        (5_242_880, 0),
        (5_242_880, 999),
        (5_242_880, 100_000_001),
    ] {
        let limits = json!({"block_hard_kib": kib, "inode_hard": inodes});
        assert_eq!(
            v2_with("/quota_limits", limits).err(),
            Some(ApprovalError::InvalidPlan),
            "{kib} {inodes}"
        );
        assert_eq!(
            SiteQuotaLimits::new(kib, inodes).err(),
            Some(ApprovalError::InvalidPlan)
        );
    }
}

#[test]
fn v2_shape_is_closed() {
    for (pointer, new) in [
        ("/expected_effects/sets_quota", json!(false)),
        ("/expected_effects/traffic_activation", json!(true)),
    ] {
        assert_eq!(
            v2_with(pointer, new).err(),
            Some(ApprovalError::InvalidPlan),
            "{pointer}"
        );
    }
    assert_eq!(
        v2_without("", "quota_limits").err(),
        Some(ApprovalError::InvalidPlan),
        "v2 without limits"
    );
    assert_eq!(
        v2_without("/expected_effects", "sets_quota").err(),
        Some(ApprovalError::InvalidPlan),
        "v2 without sets_quota"
    );
    for (pointer, new) in [
        ("/quota_limits", json!(null)),
        ("/quota_limits", json!([5_242_880, 500_000])),
        ("/quota_limits", json!({"block_hard_kib": 5_242_880})),
        (
            "/quota_limits",
            json!({"block_hard_kib": 5_242_880, "inode_hard": 500_000, "soft": 0}),
        ),
        ("/quota_limits/block_hard_kib", json!("5242880")),
        ("/expected_effects/sets_quota", json!(null)),
    ] {
        assert_eq!(
            v2_with(pointer, new.clone()).err(),
            Some(ApprovalError::InvalidMessage),
            "{pointer} = {new}"
        );
    }
    assert_eq!(
        v2_with("/schema_version", json!(3)).err(),
        Some(ApprovalError::UnsupportedVersion)
    );
}

#[test]
fn v2_limits_above_the_enrolled_cap_or_without_a_cap_do_not_bind() {
    let vector = &vectors()[0];
    let plan = SitePlan::decode(vector.plan_input.as_bytes()).unwrap();
    let grant = SiteGrant::decode(vector.grant_input.as_bytes()).unwrap();
    let recipe = "d".repeat(64);
    for (quota_cap, expected) in [
        (Some(default_cap()), Ok(())),
        (Some(cap(16 * 1024 * 1024 * 1024, 100_000_000)), Ok(())),
        (
            Some(cap(5_242_879, 500_000)),
            Err(ApprovalError::BindingMismatch),
        ),
        (
            Some(cap(5_242_880, 499_999)),
            Err(ApprovalError::BindingMismatch),
        ),
        (
            Some(cap(65_536, 1_000)),
            Err(ApprovalError::BindingMismatch),
        ),
        (None, Err(ApprovalError::BindingMismatch)),
    ] {
        assert_eq!(
            check_with(&plan, &grant, Some(1200), &recipe, quota_cap),
            expected,
            "{quota_cap:?}"
        );
    }
}

#[test]
fn the_grant_binds_the_limits_through_the_plan_digest() {
    let vector = &vectors()[0];
    let grant = SiteGrant::decode(vector.grant_input.as_bytes()).unwrap();
    let lower = v2_with(
        "/quota_limits",
        json!({"block_hard_kib": 1_048_576, "inode_hard": 500_000}),
    )
    .unwrap();
    assert_ne!(lower.digest().as_str(), vector.plan_digest);
    assert_eq!(
        check(&lower, &grant, Some(1200)),
        Err(ApprovalError::BindingMismatch),
        "a grant for other limits never covers these"
    );
    let v1_grant = SiteGrant::decode(GRANT).unwrap();
    let v2 = SitePlan::decode(vector.plan_input.as_bytes()).unwrap();
    assert_eq!(
        check(&v2, &v1_grant, Some(1200)),
        Err(ApprovalError::BindingMismatch),
        "a grant for the v1 plan never covers the v2 plan"
    );
}
