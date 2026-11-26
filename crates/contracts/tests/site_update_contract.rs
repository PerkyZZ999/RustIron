//! D-084 `site_update` plan/grant checks; no signer, executor or host effects.

use rustiron_contracts::{
    Id, Timestamp,
    approval::{
        ApprovalError, PlanKind, PreparedPlan, Sha256Digest, SiteUpdateGrant, SiteUpdatePlan,
        UpdateBindingContext, UpdateKind, check_update_binding,
    },
};
use serde_json::{Value, json};

const PLAN: &[u8] = include_bytes!("fixtures/update-plan.json");
const GRANT: &[u8] = include_bytes!("fixtures/update-grant.json");
/// Computed independently with Python's json/hashlib when the fixture was made.
const PLAN_DIGEST: &str = "1008422dc14d15fcbc24f7d07de1695e0cd338c21c2882bb701350d8b1eb542f";

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
    plan: &SiteUpdatePlan,
    grant: &SiteUpdateGrant,
    now: Option<u64>,
) -> Result<(), ApprovalError> {
    check_update_binding(
        plan,
        grant,
        &UpdateBindingContext {
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
    let plan = SiteUpdatePlan::decode(PLAN).unwrap();
    let grant = SiteUpdateGrant::decode(GRANT).unwrap();
    assert_eq!(plan.digest().as_str(), PLAN_DIGEST);
    assert_eq!(plan.site_id().as_str(), "blog1");
    assert_eq!(plan.recipe_digest().as_str(), "b".repeat(64));
    assert_eq!(plan.capture_operation_id().as_str(), "op_capture");
    let components = plan.components();
    assert_eq!(components.len(), 2);
    assert_eq!(components[0].kind, UpdateKind::Plugin);
    assert_eq!(components[0].slug.as_str(), "hello-dolly");
    assert_eq!(components[0].from_version.as_str(), "1.7.1");
    assert_eq!(components[0].to_version.as_str(), "1.7.2");
    assert_eq!(components[1].kind.as_str(), "theme");
    assert_eq!(grant.grant_id().as_str(), "grant_update");
    assert_eq!(grant.nonce().as_str(), "nonce_update");
    assert_eq!(check(&plan, &grant, Some(1500)), Ok(()));
    let prepared = PreparedPlan::decode(PLAN).unwrap();
    assert_eq!(prepared.kind(), PlanKind::SiteUpdate);
    assert_eq!(prepared.kind().as_str(), "site_update");
    assert_eq!(prepared.digest().as_str(), PLAN_DIGEST);
}

#[test]
fn plan_semantics_are_closed() {
    let component = |kind: &str, slug: &str, from: &str, to: &str| json!({"kind": kind, "slug": slug, "from_version": from, "to_version": to});
    let many: Vec<Value> = (0..9)
        .map(|n| component("plugin", &format!("p{n}"), "1.0", "1.1"))
        .collect();
    for (pointer, new) in [
        ("/schema_version", Some(json!(2))),
        ("/verb", Some(json!("site_retire"))),
        ("/site_id", Some(json!("Blog1"))),
        ("/recipe_digest", Some(json!("B".repeat(64)))),
        ("/capture_operation_id", Some(json!("../op"))),
        ("/components", Some(json!([]))),
        ("/components", Some(json!(many))),
        // The same folder twice, and an update to the installed version.
        (
            "/components",
            Some(json!([
                component("plugin", "a", "1.0", "1.1"),
                component("plugin", "a", "1.1", "1.2")
            ])),
        ),
        ("/components/0/to_version", Some(json!("1.7.1"))),
        ("/components/0/kind", Some(json!("core"))),
        ("/components/0/kind", Some(json!("mu_plugin"))),
        // A slug or version that could name another path or hide text.
        ("/components/0/slug", Some(json!("../wp-config"))),
        ("/components/0/slug", Some(json!("a/b"))),
        ("/components/0/slug", Some(json!("Hello"))),
        ("/components/0/slug", Some(json!(".hidden"))),
        ("/components/0/slug", Some(json!("-x"))),
        ("/components/0/slug", Some(json!("x".repeat(65)))),
        ("/components/0/slug", Some(json!(""))),
        ("/components/0/to_version", Some(json!("v2"))),
        ("/components/0/to_version", Some(json!("1..2"))),
        ("/components/0/to_version", Some(json!("1.0 beta"))),
        ("/components/0/to_version", Some(json!("1/2"))),
        ("/components/0/to_version", Some(json!("1".repeat(33)))),
        (
            "/components/0/url",
            Some(json!("https://example.test/x.zip")),
        ),
        ("/components/0/from_version", None),
        ("/expected_effects/changes_site_code", Some(json!(false))),
        (
            "/expected_effects/restores_site_database_on_failure",
            Some(json!(false)),
        ),
        ("/expected_effects/deletes_backups", Some(json!(true))),
        ("/expected_effects/traffic_activation", Some(json!(true))),
        ("/expected_effects/network_access", Some(json!(true))),
        ("/expected_effects/extra", Some(json!(true))),
        ("/expires_at", Some(json!(1000))),
        ("/limitations", Some(json!(vec!["x"; 9]))),
        ("/path", Some(json!("/srv/sites/rs_blog1"))),
        ("/command", Some(json!("wp plugin update --all"))),
        ("/recipe_digest", None),
        ("/capture_operation_id", None),
        ("/components", None),
    ] {
        assert!(
            SiteUpdatePlan::decode(&edited(PLAN, pointer, new.clone())).is_err(),
            "{pointer} {new:?}"
        );
    }
    // Eight components are accepted; a plugin and a theme may share a slug.
    let mut eight = vec![
        component("plugin", "same", "1.0", "2.0"),
        component("theme", "same", "1.0", "2.0"),
    ];
    eight.extend((0..6).map(|n| component("plugin", &format!("p_{n}"), "1.0-rc1", "1.0")));
    assert!(SiteUpdatePlan::decode(&edited(PLAN, "/components", Some(json!(eight)))).is_ok());
}

#[test]
fn grant_semantics_are_closed() {
    for (pointer, new) in [
        ("/schema_version", Some(json!(2))),
        ("/verbs", Some(json!(["site_retire"]))),
        ("/verbs", Some(json!(["site_update", "site_update"]))),
        ("/site_ids", Some(json!(["blog1", "blog2"]))),
        ("/site_ids", Some(json!([]))),
        ("/max_operations", Some(json!(2))),
        ("/issuer", Some(json!("agent_1"))),
        ("/expires_at", Some(json!(1100))),
        ("/extra", Some(json!(1))),
    ] {
        assert!(
            SiteUpdateGrant::decode(&edited(GRANT, pointer, new.clone())).is_err(),
            "{pointer} {new:?}"
        );
    }
}

#[test]
fn binding_and_time_are_checked() {
    let plan = SiteUpdatePlan::decode(PLAN).unwrap();
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
        let grant = SiteUpdateGrant::decode(&edited(GRANT, pointer, Some(new.clone())));
        if let Ok(grant) = grant {
            assert_eq!(
                check(&plan, &grant, Some(1500)),
                Err(ApprovalError::BindingMismatch),
                "{pointer} {new}"
            );
        }
    }
    let grant = SiteUpdateGrant::decode(GRANT).unwrap();
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

#[test]
fn a_core_update_names_core_only_as_wordpress() {
    // W525 (D-086).
    let core = |slug: &str| json!({"kind": "core", "slug": slug, "from_version": "7.0.9", "to_version": "7.1.5"});
    let plugin = json!({"kind": "plugin", "slug": "hello-dolly", "from_version": "1.7.1", "to_version": "1.7.2"});
    let plan = SiteUpdatePlan::decode(&edited(
        PLAN,
        "/components",
        Some(json!([core("wordpress")])),
    ))
    .unwrap();
    assert_eq!(plan.components()[0].kind, UpdateKind::Core);
    assert_eq!(plan.components()[0].kind.as_str(), "core");
    for components in [
        json!([core("wordpress"), plugin.clone()]),
        json!([plugin, core("wordpress")]),
        json!([core("hello-dolly")]),
        json!([core("wordpress"), core("wordpress")]),
    ] {
        assert!(
            SiteUpdatePlan::decode(&edited(PLAN, "/components", Some(components.clone()))).is_err(),
            "{components}"
        );
    }
}
