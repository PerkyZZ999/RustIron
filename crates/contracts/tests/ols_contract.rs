//! Public lab `config_activate` (OLS listener) checks; no host effects.

use rustiron_contracts::{
    Id, Timestamp,
    approval::{
        ApprovalError, OlsBindingContext, OlsGrant, OlsPlan, PageCacheRecipe, PreparedPlan,
        Sha256Digest, check_ols_binding,
    },
};
use serde_json::{Value, json};

const PLAN: &[u8] = include_bytes!("fixtures/ols-plan.json");
const GRANT: &[u8] = include_bytes!("fixtures/ols-grant.json");
/// Computed independently with Python's json/hashlib when the fixture was made.
const PLAN_DIGEST: &str = "00d79e742240c6626d1c5fb3e4415cf158bca560e7c71bbdf0fcae33eb9eb88f";

fn with(bytes: &[u8], pointer: &str, new: Value) -> Vec<u8> {
    let mut record: Value = serde_json::from_slice(bytes).unwrap();
    *record.pointer_mut(pointer).unwrap() = new;
    serde_json::to_vec(&record).unwrap()
}

fn id(text: &str) -> Id {
    Id::try_from(text.to_owned()).unwrap()
}

fn check(plan: &OlsPlan, grant: &OlsGrant, now: Option<u64>) -> Result<(), ApprovalError> {
    check_ols_binding(
        plan,
        grant,
        &OlsBindingContext {
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
    let plan = OlsPlan::decode(PLAN).unwrap();
    let grant = OlsGrant::decode(GRANT).unwrap();
    assert_eq!(plan.digest().as_str(), PLAN_DIGEST);
    assert_eq!(plan.site_ids().len(), 2);
    assert_eq!(plan.expected().0.as_str(), "g1");
    assert_eq!(check(&plan, &grant, Some(1200)), Ok(()));
}

#[test]
fn plan_is_closed() {
    for (pointer, new, error) in [
        (
            "/site_ids",
            json!(["blog6", "blog5"]),
            ApprovalError::InvalidPlan,
        ),
        (
            "/site_ids",
            json!(["blog5", "blog5"]),
            ApprovalError::InvalidPlan,
        ),
        ("/site_ids", json!([]), ApprovalError::InvalidPlan),
        (
            "/observations/0/generation",
            json!("g2"),
            ApprovalError::InvalidPlan,
        ),
        (
            "/observations/0/content_digest",
            json!("c".repeat(64)),
            ApprovalError::InvalidPlan,
        ),
        (
            "/observations/0/observed_at",
            json!(1001),
            ApprovalError::InvalidPlan,
        ),
        (
            "/compensation/valid_until",
            json!(2301),
            ApprovalError::InvalidPlan,
        ),
        (
            "/compensation/max_attempts",
            json!(2),
            ApprovalError::InvalidPlan,
        ),
        (
            "/target",
            json!("ols_all_listeners"),
            ApprovalError::InvalidMessage,
        ),
        (
            "/verb",
            json!("site_provision"),
            ApprovalError::InvalidMessage,
        ),
        (
            "/site_ids",
            json!(["../etc"]),
            ApprovalError::InvalidMessage,
        ),
        // W368: schema 2 needs the page-cache opt-in.
        ("/schema_version", json!(2), ApprovalError::InvalidPlan),
        (
            "/schema_version",
            json!(4),
            ApprovalError::UnsupportedVersion,
        ),
        // W370: schema 3 is the opt-out and needs `page_cache_opt_out` alone.
        ("/schema_version", json!(3), ApprovalError::InvalidPlan),
    ] {
        assert_eq!(
            OlsPlan::decode(&with(PLAN, pointer, new.clone())).err(),
            Some(error),
            "{pointer} {new}"
        );
    }
    let mut extra: Value = serde_json::from_slice(PLAN).unwrap();
    extra["directives"] = json!("listener x {}");
    assert_eq!(
        OlsPlan::decode(&serde_json::to_vec(&extra).unwrap()).err(),
        Some(ApprovalError::InvalidMessage)
    );
}

#[test]
fn grant_is_closed_and_every_bound_field_matters() {
    for (pointer, new) in [
        ("/issuer", json!("agent_1")),
        ("/max_operations", json!(2)),
        ("/targets", json!(["ols_lab_listener", "ols_lab_listener"])),
    ] {
        assert_eq!(
            OlsGrant::decode(&with(GRANT, pointer, new)).err(),
            Some(ApprovalError::InvalidGrant),
            "{pointer}"
        );
    }
    let plan = OlsPlan::decode(PLAN).unwrap();
    for (pointer, new) in [
        ("/plan_digest", json!("e".repeat(64))),
        ("/plan_id", json!("plan_x")),
        ("/host_epoch", json!("epoch_2")),
        ("/site_ids", json!(["blog5"])),
        ("/compensation/valid_until", json!(2050)),
        ("/requester", json!("agent_2")),
        ("/issuer", json!("operator_2")),
        ("/signer_policy_epoch", json!("policy_2")),
        ("/expires_at", json!(2001)),
    ] {
        let grant = OlsGrant::decode(&with(GRANT, pointer, new)).unwrap();
        assert_eq!(
            check(&plan, &grant, Some(1200)),
            Err(ApprovalError::BindingMismatch),
            "{pointer}"
        );
    }
    let grant = OlsGrant::decode(GRANT).unwrap();
    assert_eq!(
        check(&plan, &grant, None),
        Err(ApprovalError::ClockUncertain)
    );
    assert_eq!(
        check(&plan, &grant, Some(1900)),
        Err(ApprovalError::OutsideValidity)
    );
}

// ---- W368: schema v2 adds the page-cache opt-in (D-028 item 2, B08) ----

/// Encoded independently with Python's json/hashlib; see check_canonical_vectors.py.
#[derive(serde::Deserialize)]
struct Vector {
    name: String,
    plan_input: String,
    plan_canonical: String,
    plan_digest: String,
    grant_input: String,
    grant_canonical: String,
}

fn vectors() -> Vec<Vector> {
    serde_json::from_str(include_str!("fixtures/ols-plan-v2-vectors.json")).unwrap()
}

fn v2_with(pointer: &str, new: Value) -> Result<OlsPlan, ApprovalError> {
    let mut record: Value = serde_json::from_str(&vectors()[0].plan_input).unwrap();
    *record.pointer_mut(pointer).unwrap() = new;
    OlsPlan::decode(&serde_json::to_vec(&record).unwrap())
}

fn v2_without(object: &str, member: &str) -> Result<OlsPlan, ApprovalError> {
    let mut record: Value = serde_json::from_str(&vectors()[0].plan_input).unwrap();
    record
        .pointer_mut(object)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove(member);
    OlsPlan::decode(&serde_json::to_vec(&record).unwrap())
}

#[test]
fn v2_vectors_match_independent_bytes_digest_and_grant() {
    for vector in vectors() {
        let plan = OlsPlan::decode(vector.plan_input.as_bytes()).unwrap();
        let grant = OlsGrant::decode(vector.grant_input.as_bytes()).unwrap();
        assert_eq!(
            plan.digest().as_str(),
            vector.plan_digest,
            "{}",
            vector.name
        );
        assert_eq!(grant.as_bytes(), vector.grant_canonical.as_bytes());
        assert_eq!(plan.schema_version(), 2);
        let prepared = PreparedPlan::decode(vector.plan_input.as_bytes()).unwrap();
        assert_eq!(prepared.as_bytes(), vector.plan_canonical.as_bytes());
        assert_eq!(prepared.digest(), plan.digest());
        assert_eq!(prepared.kind().as_str(), "config_activate");
        assert_eq!(check(&plan, &grant, Some(1200)), Ok(()), "{}", vector.name);
        let opt_in = plan.page_cache().unwrap();
        assert!(plan.site_ids().contains(opt_in.site_id()));
        assert_eq!(opt_in.recipe(), PageCacheRecipe::LitespeedCache793V1);
        assert_eq!(opt_in.recipe_digest().as_str(), "e".repeat(64));
    }
    let single = OlsPlan::decode(vectors()[1].plan_input.as_bytes()).unwrap();
    assert_eq!(single.page_cache().unwrap().site_id().as_str(), "blog6");
}

#[test]
fn v1_keeps_its_meaning_and_never_carries_a_page_cache() {
    let plan = OlsPlan::decode(PLAN).unwrap();
    assert_eq!(plan.schema_version(), 1);
    assert!(plan.page_cache().is_none());
    assert_eq!(plan.digest().as_str(), PLAN_DIGEST);
    let mut with_cache: Value = serde_json::from_slice(PLAN).unwrap();
    with_cache["page_cache"] = json!({
        "site_id": "blog5", "recipe_id": "litespeed_cache_793_v1", "recipe_digest": "e".repeat(64),
    });
    assert_eq!(
        OlsPlan::decode(&serde_json::to_vec(&with_cache).unwrap()).err(),
        Some(ApprovalError::InvalidPlan),
        "v1 with a page cache"
    );
}

#[test]
fn v2_shape_is_closed() {
    for (pointer, new, error) in [
        (
            "/page_cache/site_id",
            json!("blog7"),
            ApprovalError::InvalidPlan,
        ),
        (
            "/page_cache/site_id",
            json!("../x"),
            ApprovalError::InvalidMessage,
        ),
        (
            "/page_cache/recipe_id",
            json!("litespeed_cache_latest"),
            ApprovalError::InvalidMessage,
        ),
        (
            "/page_cache/recipe_digest",
            json!("E".repeat(64)),
            ApprovalError::InvalidMessage,
        ),
        ("/page_cache", Value::Null, ApprovalError::InvalidMessage),
        (
            "/page_cache",
            json!("wp plugin install litespeed-cache"),
            ApprovalError::InvalidMessage,
        ),
        (
            "/schema_version",
            json!(4),
            ApprovalError::UnsupportedVersion,
        ),
        // W370: schema 3 is the opt-out and needs `page_cache_opt_out` alone.
        ("/schema_version", json!(3), ApprovalError::InvalidPlan),
    ] {
        assert_eq!(
            v2_with(pointer, new.clone()).err(),
            Some(error),
            "{pointer} {new}"
        );
    }
    assert_eq!(
        v2_without("", "page_cache").err(),
        Some(ApprovalError::InvalidPlan),
        "v2 without a page cache"
    );
    for member in ["site_id", "recipe_id", "recipe_digest"] {
        assert_eq!(
            v2_without("/page_cache", member).err(),
            Some(ApprovalError::InvalidMessage),
            "{member}"
        );
    }
    let mut extra: Value = serde_json::from_str(&vectors()[0].plan_input).unwrap();
    extra["page_cache"]["settings"] = json!({"cache": 1});
    assert_eq!(
        OlsPlan::decode(&serde_json::to_vec(&extra).unwrap()).err(),
        Some(ApprovalError::InvalidMessage),
        "no settings, commands or paths in the opt-in"
    );
}

#[test]
fn the_v1_grant_binds_the_page_cache_through_the_plan_digest() {
    let grant = OlsGrant::decode(vectors()[0].grant_input.as_bytes()).unwrap();
    for (pointer, new) in [
        ("/page_cache/site_id", json!("blog6")),
        ("/page_cache/recipe_digest", json!("f".repeat(64))),
    ] {
        let plan = v2_with(pointer, new).unwrap();
        assert_eq!(
            check(&plan, &grant, Some(1200)),
            Err(ApprovalError::BindingMismatch),
            "{pointer}"
        );
    }
}

#[derive(serde::Deserialize)]
struct V3Vector {
    name: String,
    plan_input: String,
    plan_canonical: String,
    plan_digest: String,
    grant_input: String,
    grant_canonical: String,
}

/// W370: schema 3 (page-cache opt-out) vectors, made with Python's
/// json/hashlib only (`docs/validation/S10-W370/make-v3-vectors.py`).
fn v3_vectors() -> Vec<V3Vector> {
    serde_json::from_str(include_str!("fixtures/ols-plan-v3-vectors.json")).unwrap()
}

fn v3_edit(edit: impl FnOnce(&mut Value)) -> Result<OlsPlan, ApprovalError> {
    let mut record: Value = serde_json::from_str(&v3_vectors()[0].plan_input).unwrap();
    edit(&mut record);
    OlsPlan::decode(&serde_json::to_vec(&record).unwrap())
}

#[test]
fn v3_vectors_match_independent_bytes_digest_and_grant() {
    let vectors = v3_vectors();
    assert_eq!(
        vectors.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(),
        ["page_cache_opt_out", "single_site_opt_out"]
    );
    for vector in &vectors {
        let plan = OlsPlan::decode(vector.plan_input.as_bytes()).unwrap();
        let grant = OlsGrant::decode(vector.grant_input.as_bytes()).unwrap();
        assert_eq!(
            plan.digest().as_str(),
            vector.plan_digest,
            "{}",
            vector.name
        );
        assert_eq!(grant.as_bytes(), vector.grant_canonical.as_bytes());
        assert_eq!(plan.schema_version(), 3);
        assert!(plan.page_cache().is_none(), "an opt-out is never an opt-in");
        let prepared = PreparedPlan::decode(vector.plan_input.as_bytes()).unwrap();
        assert_eq!(prepared.as_bytes(), vector.plan_canonical.as_bytes());
        assert_eq!(prepared.digest(), plan.digest());
        assert_eq!(prepared.kind().as_str(), "config_activate");
        assert_eq!(check(&plan, &grant, Some(1200)), Ok(()), "{}", vector.name);
        let opt_out = plan.page_cache_opt_out().unwrap();
        assert!(plan.site_ids().contains(opt_out.site_id()));
        assert_eq!(opt_out.recipe(), PageCacheRecipe::LitespeedCache793V1);
    }
    let single = OlsPlan::decode(vectors[1].plan_input.as_bytes()).unwrap();
    assert_eq!(
        single.page_cache_opt_out().unwrap().site_id().as_str(),
        "blog6"
    );
    // Schemas 1 and 2 never carry an opt-out.
    assert!(
        OlsPlan::decode(PLAN)
            .unwrap()
            .page_cache_opt_out()
            .is_none()
    );
    let v2 = OlsPlan::decode(self::vectors()[0].plan_input.as_bytes()).unwrap();
    assert!(v2.page_cache_opt_out().is_none());
}

#[test]
fn v3_shape_is_closed() {
    type Edit = Box<dyn FnOnce(&mut Value)>;
    let cases: Vec<(&str, Edit, ApprovalError)> = vec![
        (
            "site not served",
            Box::new(|r| r["page_cache_opt_out"]["site_id"] = json!("blog7")),
            ApprovalError::InvalidPlan,
        ),
        (
            "site path",
            Box::new(|r| r["page_cache_opt_out"]["site_id"] = json!("../x")),
            ApprovalError::InvalidMessage,
        ),
        (
            "unknown recipe",
            Box::new(|r| r["page_cache_opt_out"]["recipe_id"] = json!("any")),
            ApprovalError::InvalidMessage,
        ),
        (
            "no storage path, command or setting",
            Box::new(|r| {
                r["page_cache_opt_out"]["storage_path"] = json!("/usr/local/lsws/cachedata")
            }),
            ApprovalError::InvalidMessage,
        ),
        (
            "null",
            Box::new(|r| r["page_cache_opt_out"] = Value::Null),
            ApprovalError::InvalidMessage,
        ),
        (
            "missing",
            Box::new(|r| {
                r.as_object_mut().unwrap().remove("page_cache_opt_out");
            }),
            ApprovalError::InvalidPlan,
        ),
        (
            "opt-in and opt-out together",
            Box::new(|r| {
                r["page_cache"] = json!({
                    "site_id": "blog5", "recipe_id": "litespeed_cache_793_v1",
                    "recipe_digest": "e".repeat(64),
                })
            }),
            ApprovalError::InvalidPlan,
        ),
        (
            "schema 2 with an opt-out",
            Box::new(|r| r["schema_version"] = json!(2)),
            ApprovalError::InvalidPlan,
        ),
        (
            "schema 1 with an opt-out",
            Box::new(|r| r["schema_version"] = json!(1)),
            ApprovalError::InvalidPlan,
        ),
        (
            "schema 4",
            Box::new(|r| r["schema_version"] = json!(4)),
            ApprovalError::UnsupportedVersion,
        ),
    ];
    for (name, edit, error) in cases {
        assert_eq!(v3_edit(edit).err(), Some(error), "{name}");
    }
    for member in ["site_id", "recipe_id"] {
        assert_eq!(
            v3_edit(|r| {
                r["page_cache_opt_out"]
                    .as_object_mut()
                    .unwrap()
                    .remove(member);
            })
            .err(),
            Some(ApprovalError::InvalidMessage),
            "{member}"
        );
    }
}

#[test]
fn the_v1_grant_binds_the_opt_out_through_the_plan_digest() {
    let grant = OlsGrant::decode(v3_vectors()[0].grant_input.as_bytes()).unwrap();
    let other = v3_edit(|r| r["page_cache_opt_out"]["site_id"] = json!("blog6")).unwrap();
    assert_eq!(
        check(&other, &grant, Some(1200)),
        Err(ApprovalError::BindingMismatch)
    );
}

/// W395 (D-044): the cache-on recipe under schemas 2 and 3, made with
/// Python's json/hashlib only (`docs/validation/S10-W395/make-cache-on-vectors.py`).
/// The opt-in's `recipe_digest` is the Python-computed recipe manifest digest.
fn cache_on_vectors() -> Vec<V3Vector> {
    serde_json::from_str(include_str!("fixtures/ols-plan-cache-on-vectors.json")).unwrap()
}

#[test]
fn cache_on_vectors_match_independent_bytes_digest_and_grant() {
    let vectors = cache_on_vectors();
    assert_eq!(
        vectors.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(),
        ["cache_on_opt_in", "cache_on_opt_out"]
    );
    for vector in &vectors {
        let plan = OlsPlan::decode(vector.plan_input.as_bytes()).unwrap();
        let grant = OlsGrant::decode(vector.grant_input.as_bytes()).unwrap();
        assert_eq!(
            plan.digest().as_str(),
            vector.plan_digest,
            "{}",
            vector.name
        );
        assert_eq!(grant.as_bytes(), vector.grant_canonical.as_bytes());
        let prepared = PreparedPlan::decode(vector.plan_input.as_bytes()).unwrap();
        assert_eq!(prepared.as_bytes(), vector.plan_canonical.as_bytes());
        assert_eq!(prepared.digest(), plan.digest());
        assert_eq!(check(&plan, &grant, Some(1200)), Ok(()), "{}", vector.name);
    }
    let opt_in = OlsPlan::decode(vectors[0].plan_input.as_bytes()).unwrap();
    assert_eq!(opt_in.schema_version(), 2);
    let cache = opt_in.page_cache().unwrap();
    assert_eq!(cache.recipe(), PageCacheRecipe::LitespeedCache793CacheOnV1);
    assert_eq!(
        cache.recipe_digest().as_str(),
        "3665c57f288174dddba0be23a5b43a554c11a226ec681171f79334e5c1dad767"
    );
    let opt_out = OlsPlan::decode(vectors[1].plan_input.as_bytes()).unwrap();
    assert_eq!(opt_out.schema_version(), 3);
    assert_eq!(
        opt_out.page_cache_opt_out().unwrap().recipe(),
        PageCacheRecipe::LitespeedCache793CacheOnV1
    );
    // Only the two approved recipe names decode.
    for name in [
        "litespeed_cache_793_cache_on_v2",
        "litespeed_cache_793_cache_on",
        "cache_on",
    ] {
        let mut record: Value = serde_json::from_str(&vectors[0].plan_input).unwrap();
        record["page_cache"]["recipe_id"] = json!(name);
        assert_eq!(
            OlsPlan::decode(&serde_json::to_vec(&record).unwrap()).err(),
            Some(ApprovalError::InvalidMessage),
            "{name}"
        );
    }
}

#[test]
fn the_v1_grant_binds_the_cache_on_recipe_through_the_plan_digest() {
    let vectors = cache_on_vectors();
    let grant = OlsGrant::decode(vectors[0].grant_input.as_bytes()).unwrap();
    let mut record: Value = serde_json::from_str(&vectors[0].plan_input).unwrap();
    record["page_cache"]["recipe_id"] = json!("litespeed_cache_793_v1");
    let other = OlsPlan::decode(&serde_json::to_vec(&record).unwrap()).unwrap();
    assert_eq!(
        check(&other, &grant, Some(1200)),
        Err(ApprovalError::BindingMismatch),
        "the W368 recipe under the cache-on grant"
    );
}
