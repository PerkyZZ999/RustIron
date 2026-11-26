//! P27 (D-099) closed contracts for `app_provision`, `app_deploy`, and
//! `app_lifecycle`: schema validation, grant binding, `PreparedPlan`, and
//! D-098 `BlastRadiusEnvelope`. No signer, executor, or host effects.

use rustiron_contracts::{
    CanonicalObject, Id, Timestamp,
    approval::{
        AppBindingContext, AppDeployGrant, AppDeployPlan, AppLifecycleAction, AppLifecycleGrant,
        AppLifecyclePlan, AppProvisionGrant, AppProvisionPlan, AppRuntime, ApprovalError,
        ImpactScope, PlanKind, PreparedPlan, Sha256Digest, check_app_deploy_binding,
        check_app_lifecycle_binding, check_app_provision_binding, envelope_for_plan,
        valid_entrypoint, valid_env_key, valid_env_keys, valid_health_path, valid_manifest_path,
        valid_release_id,
    },
};
use serde_json::{Value, json};

fn id(text: &str) -> Id {
    Id::try_from(text.to_owned()).unwrap()
}

fn sha(ch: char) -> String {
    std::iter::repeat_n(ch, 64).collect()
}

fn canonical(value: &Value) -> Vec<u8> {
    CanonicalObject::decode(value.to_string().as_bytes())
        .unwrap()
        .as_bytes()
        .to_vec()
}

fn context<'a>(
    host_id: &'a Id,
    host_epoch: &'a Id,
    profile_digest: &'a Sha256Digest,
    requester: &'a Id,
    issuer: &'a Id,
    signer_policy_epoch: &'a Id,
    now: Option<u64>,
) -> AppBindingContext<'a> {
    AppBindingContext {
        host_id,
        host_epoch,
        profile_digest,
        requester,
        issuer,
        signer_policy_epoch,
        now: now.map(|t| Timestamp::try_from(t).unwrap()),
    }
}

fn provision_plan_json() -> Value {
    json!({
        "schema_version": 1,
        "plan_id": "plan_app_prov_1",
        "host_id": "host_lab",
        "host_epoch": "epoch_1",
        "profile_digest": sha('a'),
        "requester": "agent_1",
        "verb": "app_provision",
        "site_id": "emdash1",
        "hostname": "emdash.example.test",
        "runtime": "node_22_v1",
        "port": 43187,
        "routes": [{"prefix": "/", "port": 43187}],
        "websockets": [{"prefix": "/_emdash/api/content/", "port": 43187}],
        "entrypoint": "dist/server/entry.mjs",
        "worker_entrypoint": "dist/worker.mjs",
        "health_path": "/health",
        "env_keys": ["EMDASH_ENCRYPTION_KEY", "EMDASH_SITE_URL"],
        "memory_max_mib": 512,
        "tasks_max": 64,
        "quota_mib": 2048,
        "expected_effects": {
            "creates_account": true,
            "forwards_to_loopback": true,
            "installs_app_unit": true,
            "traffic_activation": false,
            "runs_package_scripts": false
        },
        "risk_class": "lab_only",
        "valid_from": 1000,
        "expires_at": 2000,
        "limitations": ["lab contract check"]
    })
}

fn deploy_plan_json() -> Value {
    json!({
        "schema_version": 1,
        "plan_id": "plan_app_dep_1",
        "host_id": "host_lab",
        "host_epoch": "epoch_1",
        "profile_digest": sha('a'),
        "requester": "agent_1",
        "verb": "app_deploy",
        "site_id": "emdash1",
        "release_id": "rel-2026.11.23-01",
        "runtime": "node_22_v1",
        "artifact_sha256": sha('b'),
        "manifest_sha256": sha('c'),
        "file_count": 420,
        "total_bytes": 12_582_912,
        "migration_entrypoint": "scripts/migrate.mjs",
        "capture_operation_id": "op_cap_1",
        "health_path": "/health",
        "expected_effects": {
            "unpacks_as_site": true,
            "switches_release": true,
            "restarts_app_unit": true,
            "rolls_back_on_failed_health": true,
            "runs_package_scripts": false,
            "traffic_activation": false
        },
        "risk_class": "lab_only",
        "valid_from": 1000,
        "expires_at": 2000,
        "limitations": ["lab contract check"]
    })
}

fn lifecycle_plan_json() -> Value {
    json!({
        "schema_version": 1,
        "plan_id": "plan_app_life_1",
        "host_id": "host_lab",
        "host_epoch": "epoch_1",
        "profile_digest": sha('a'),
        "requester": "agent_1",
        "verb": "app_lifecycle",
        "site_id": "emdash1",
        "action": "restart",
        "expected_effects": {
            "changes_app_unit_state": true,
            "reloads_ols": false,
            "changes_files": false
        },
        "risk_class": "lab_only",
        "valid_from": 1000,
        "expires_at": 2000,
        "limitations": ["lab contract check"]
    })
}

fn grant_json(plan_id: &str, plan_digest: &str, verb: &str) -> Value {
    json!({
        "schema_version": 1,
        "grant_id": format!("grant_{verb}"),
        "nonce": format!("nonce_{verb}"),
        "plan_id": plan_id,
        "plan_digest": plan_digest,
        "host_id": "host_lab",
        "host_epoch": "epoch_1",
        "profile_digest": sha('a'),
        "issuer": "operator_1",
        "requester": "agent_1",
        "signer_policy_epoch": "policy_1",
        "site_ids": ["emdash1"],
        "verbs": [verb],
        "risk_class": "lab_only",
        "valid_from": 1100,
        "expires_at": 1900,
        "max_operations": 1
    })
}

#[test]
fn validators_enforce_strict_grammars_and_forbid_host_env_keys() {
    for good in [
        "dist/server.js",
        "src/index.ts",
        "scripts/serve-production.ts",
        "entry.mjs",
    ] {
        assert!(valid_entrypoint(good), "{good}");
    }
    for bad in [
        "",
        "/abs/path.js",
        "dir/",
        "../escape.js",
        "a/../b.js",
        "./index.js",
        "a//b.js",
        "a b.js",
        "a;id.js",
        "node_modules/@emdash-cms/blocks/index.mjs",
    ] {
        assert!(!valid_entrypoint(bad), "{bad}");
    }

    for good in [
        "dist/server/entry.mjs",
        "node_modules/@emdash-cms/blocks/dist/index.mjs",
        "node_modules/emdash/src/astro/routes/sitemap-[collection].xml.ts",
    ] {
        assert!(valid_manifest_path(good), "{good}");
    }
    for bad in [
        "",
        "/abs/path.js",
        "dir/",
        "../escape.js",
        "node_modules/@scope/../evil.js",
        "a b.js",
        "a;id.js",
        "a$b.js",
    ] {
        assert!(!valid_manifest_path(bad), "{bad}");
    }

    for good in ["/", "/health", "/api/health", "/_emdash/health/"] {
        assert!(valid_health_path(good), "{good}");
    }
    for bad in [
        "",
        "health",
        "//",
        "/health?ok=1",
        "/health#top",
        "/../etc/passwd",
        "/a b",
    ] {
        assert!(!valid_health_path(bad), "{bad}");
    }

    for good in ["DATABASE_URL", "EMDASH_SITE_URL", "API_TOKEN_1"] {
        assert!(valid_env_key(good), "{good}");
    }
    for bad in [
        "",
        "lowercase",
        "1STARTS_DIGIT",
        "KEY=SECRET",
        "PATH",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "PORT",
        "HOST",
        "TMPDIR",
        "RUSTIRON_APP_DATA",
    ] {
        assert!(!valid_env_key(bad), "{bad}");
    }
    assert!(valid_env_keys(&["A".to_owned(), "B".to_owned()]));
    assert!(!valid_env_keys(&["B".to_owned(), "A".to_owned()]));
    assert!(!valid_env_keys(&["A".to_owned(), "A".to_owned()]));

    assert!(valid_release_id("rel-2026.11.23_01"));
    for bad in ["", "Upper", "../rel", "rel..2", "-leading", "rel/1"] {
        assert!(!valid_release_id(bad), "{bad}");
    }
}

#[test]
fn app_provision_decodes_binds_and_builds_envelope_for_node_and_bun() {
    let bytes = canonical(&provision_plan_json());
    let plan = AppProvisionPlan::decode(&bytes).unwrap();
    assert_eq!(plan.runtime(), AppRuntime::Node22V1);
    assert_eq!(plan.port(), 43187);
    assert_eq!(plan.worker_entrypoint(), Some("dist/worker.mjs"));
    assert_eq!(
        plan.env_keys(),
        ["EMDASH_ENCRYPTION_KEY", "EMDASH_SITE_URL"]
    );

    let prepared = PreparedPlan::decode(&bytes).unwrap();
    assert_eq!(prepared.kind(), PlanKind::AppProvision);
    assert_eq!(prepared.kind().as_str(), "app_provision");
    assert_eq!(prepared.digest(), plan.digest());

    let env = envelope_for_plan(&bytes).unwrap();
    assert_eq!(env.verb, "app_provision");
    assert_eq!(env.scope, ImpactScope::SingleSite);
    assert!(!env.all_served_sites);
    assert_eq!(env.ols_reloads, 0);
    assert!(env.resource_budget.contains("node_22_v1"));
    assert!(env.resource_budget.contains("companion worker"));

    let grant_bytes = canonical(&grant_json(
        "plan_app_prov_1",
        plan.digest().as_str(),
        "app_provision",
    ));
    let grant = AppProvisionGrant::decode(&grant_bytes).unwrap();
    let (h, e, p, r, i, s) = (
        id("host_lab"),
        id("epoch_1"),
        Sha256Digest::try_from(sha('a')).unwrap(),
        id("agent_1"),
        id("operator_1"),
        id("policy_1"),
    );
    assert_eq!(
        check_app_provision_binding(&plan, &grant, &context(&h, &e, &p, &r, &i, &s, Some(1500))),
        Ok(())
    );
    assert_eq!(
        check_app_provision_binding(&plan, &grant, &context(&h, &e, &p, &r, &i, &s, None)),
        Err(ApprovalError::ClockUncertain)
    );
    assert_eq!(
        check_app_provision_binding(&plan, &grant, &context(&h, &e, &p, &r, &i, &s, Some(1900))),
        Err(ApprovalError::OutsideValidity)
    );

    // Bun profile without companion worker also decodes cleanly.
    let mut bun = provision_plan_json();
    bun["runtime"] = json!("bun_1_v1");
    bun["entrypoint"] = json!("src/index.ts");
    bun.as_object_mut().unwrap().remove("worker_entrypoint");
    let bun_plan = AppProvisionPlan::decode(&canonical(&bun)).unwrap();
    assert_eq!(bun_plan.runtime(), AppRuntime::Bun1V1);
    assert_eq!(bun_plan.worker_entrypoint(), None);
}

#[test]
fn app_provision_refuses_unsafe_ports_env_keys_effects_and_extra_fields() {
    type Mutator = fn(&mut Value);
    let base = provision_plan_json();
    let cases: [(&str, Mutator); 16] = [
        ("port mismatch in route", |v| {
            v["routes"][0]["port"] = json!(5000);
        }),
        ("port mismatch in ws", |v| {
            v["websockets"][0]["port"] = json!(5000);
        }),
        ("mariadb port", |v| {
            v["port"] = json!(3306);
            v["routes"][0]["port"] = json!(3306);
            v["websockets"][0]["port"] = json!(3306);
        }),
        ("privileged port", |v| {
            v["port"] = json!(443);
            v["routes"][0]["port"] = json!(443);
            v["websockets"][0]["port"] = json!(443);
        }),
        ("missing root route", |v| {
            v["routes"] = json!([{"prefix": "/api/", "port": 43187}]);
        }),
        ("traversal entrypoint", |v| {
            v["entrypoint"] = json!("../pwn.js");
        }),
        ("traversal worker", |v| {
            v["worker_entrypoint"] = json!("/bin/sh");
        }),
        ("forbidden env key", |v| {
            v["env_keys"] = json!(["LD_PRELOAD"]);
        }),
        ("secret value in env key", |v| {
            v["env_keys"] = json!(["SECRET=abc"]);
        }),
        ("unsorted env keys", |v| {
            v["env_keys"] = json!(["Z_KEY", "A_KEY"]);
        }),
        ("package scripts true", |v| {
            v["expected_effects"]["runs_package_scripts"] = json!(true);
        }),
        ("traffic activation true", |v| {
            v["expected_effects"]["traffic_activation"] = json!(true);
        }),
        ("memory too low", |v| {
            v["memory_max_mib"] = json!(32);
        }),
        ("tasks too high", |v| {
            v["tasks_max"] = json!(2048);
        }),
        ("unknown runtime", |v| {
            v["runtime"] = json!("python_3");
        }),
        ("unknown field", |v| {
            v["env_values"] = json!({"A": "secret"});
        }),
    ];
    for (label, mutate) in cases {
        let mut candidate = base.clone();
        mutate(&mut candidate);
        assert!(
            AppProvisionPlan::decode(candidate.to_string().as_bytes()).is_err(),
            "{label}"
        );
    }
}

#[test]
fn app_deploy_requires_capture_for_migration_and_binds_strictly() {
    let bytes = canonical(&deploy_plan_json());
    let plan = AppDeployPlan::decode(&bytes).unwrap();
    assert_eq!(plan.release_id(), "rel-2026.11.23-01");
    assert_eq!(plan.migration_entrypoint(), Some("scripts/migrate.mjs"));
    assert_eq!(
        plan.capture_operation_id().map(Id::as_str),
        Some("op_cap_1")
    );
    assert_eq!(
        PreparedPlan::decode(&bytes).unwrap().kind(),
        PlanKind::AppDeploy
    );

    let env = envelope_for_plan(&bytes).unwrap();
    assert_eq!(env.verb, "app_deploy");
    assert_eq!(env.ols_reloads, 0);
    assert!(
        env.resource_budget
            .contains("migration with capture rollback")
    );

    // Without migration, capture_operation_id is optional.
    let mut no_mig = deploy_plan_json();
    no_mig
        .as_object_mut()
        .unwrap()
        .remove("migration_entrypoint");
    no_mig
        .as_object_mut()
        .unwrap()
        .remove("capture_operation_id");
    assert!(AppDeployPlan::decode(&canonical(&no_mig)).is_ok());

    // With migration and NO capture_operation_id -> MUST refuse!
    let mut missing_cap = deploy_plan_json();
    missing_cap
        .as_object_mut()
        .unwrap()
        .remove("capture_operation_id");
    assert_eq!(
        AppDeployPlan::decode(&canonical(&missing_cap)).unwrap_err(),
        ApprovalError::InvalidPlan
    );

    // Oversized bundle or package scripts -> MUST refuse!
    let mut huge = deploy_plan_json();
    huge["total_bytes"] = json!(1024_u64 * 1024 * 1024);
    assert!(AppDeployPlan::decode(&canonical(&huge)).is_err());

    let mut scripts = deploy_plan_json();
    scripts["expected_effects"]["runs_package_scripts"] = json!(true);
    assert!(AppDeployPlan::decode(&canonical(&scripts)).is_err());

    let grant_bytes = canonical(&grant_json(
        "plan_app_dep_1",
        plan.digest().as_str(),
        "app_deploy",
    ));
    let grant = AppDeployGrant::decode(&grant_bytes).unwrap();
    let (h, e, p, r, i, s) = (
        id("host_lab"),
        id("epoch_1"),
        Sha256Digest::try_from(sha('a')).unwrap(),
        id("agent_1"),
        id("operator_1"),
        id("policy_1"),
    );
    assert_eq!(
        check_app_deploy_binding(&plan, &grant, &context(&h, &e, &p, &r, &i, &s, Some(1500))),
        Ok(())
    );
}

#[test]
fn app_lifecycle_decodes_binds_and_refuses_unknown_actions() {
    let bytes = canonical(&lifecycle_plan_json());
    let plan = AppLifecyclePlan::decode(&bytes).unwrap();
    assert_eq!(plan.action(), AppLifecycleAction::Restart);
    assert_eq!(
        PreparedPlan::decode(&bytes).unwrap().kind(),
        PlanKind::AppLifecycle
    );

    let env = envelope_for_plan(&bytes).unwrap();
    assert_eq!(env.verb, "app_lifecycle");
    assert_eq!(env.ols_reloads, 0);
    assert!(!env.all_served_sites);

    for action in ["start", "stop", "restart"] {
        let mut p = lifecycle_plan_json();
        p["action"] = json!(action);
        assert!(AppLifecyclePlan::decode(&canonical(&p)).is_ok(), "{action}");
    }
    for bad in ["reload", "kill", "exec", ""] {
        let mut p = lifecycle_plan_json();
        p["action"] = json!(bad);
        assert!(
            AppLifecyclePlan::decode(p.to_string().as_bytes()).is_err(),
            "{bad}"
        );
    }

    let grant_bytes = canonical(&grant_json(
        "plan_app_life_1",
        plan.digest().as_str(),
        "app_lifecycle",
    ));
    let grant = AppLifecycleGrant::decode(&grant_bytes).unwrap();
    let (h, e, p, r, i, s) = (
        id("host_lab"),
        id("epoch_1"),
        Sha256Digest::try_from(sha('a')).unwrap(),
        id("agent_1"),
        id("operator_1"),
        id("policy_1"),
    );
    assert_eq!(
        check_app_lifecycle_binding(&plan, &grant, &context(&h, &e, &p, &r, &i, &s, Some(1500))),
        Ok(())
    );
}
