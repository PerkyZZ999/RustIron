//! P27 (D-099) closed contracts for `app_provision`, `app_deploy`, and
//! `app_lifecycle`: schema validation, grant binding, `PreparedPlan`, and
//! D-098 `BlastRadiusEnvelope`. No signer, executor, or host effects.

use rustiron_contracts::{
    CanonicalObject, Id, Timestamp,
    approval::{
        AppBindingContext, AppDatabase, AppDeployGrant, AppDeployPlan, AppLifecycleAction,
        AppLifecycleGrant, AppLifecyclePlan, AppProvisionGrant, AppProvisionPlan, AppRuntime,
        AppTopology, ApprovalError, CredentialRotatePlan, CredentialTarget, ImpactScope,
        IngressEngine, PlanKind, PreparedPlan, Sha256Digest, app_routable_port,
        check_app_deploy_binding, check_app_lifecycle_binding, check_app_provision_binding,
        envelope_for_plan, valid_entrypoint, valid_env_key, valid_env_keys, valid_frontend_dir,
        valid_health_path, valid_manifest_path, valid_release_id,
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

#[test]
fn d102_schema_v2_covers_all_four_topologies_databases_blue_green_and_rejects_invalid_combos() {
    assert!(!app_routable_port(3306));
    assert!(!app_routable_port(5432));
    assert!(!app_routable_port(2019));
    assert!(app_routable_port(4100));
    assert!(valid_frontend_dir("frontend"));
    assert!(valid_frontend_dir("web/dist"));
    assert!(!valid_frontend_dir("../dist"));

    // 1. static_spa (Caddy only, zero daemon port, no DB)
    let static_spa = json!({
        "schema_version": 2,
        "plan_id": "plan_spa_1",
        "host_id": "host_lab",
        "host_epoch": "epoch_1",
        "profile_digest": sha('a'),
        "requester": "agent_1",
        "verb": "app_provision",
        "site_id": "docsapp",
        "hostname": "docs.example.test",
        "runtime": "static_v1",
        "port": 0,
        "routes": [],
        "websockets": [],
        "entrypoint": "",
        "health_path": "/",
        "env_keys": [],
        "memory_max_mib": 128,
        "tasks_max": 32,
        "quota_mib": 512,
        "ingress": "caddy",
        "topology": "static_spa",
        "database": "none",
        "blue_green": false,
        "spa_fallback": true,
        "frontend_dir": "frontend",
        "expected_effects": {
            "creates_account": true,
            "forwards_to_loopback": false,
            "installs_app_unit": false,
            "creates_database": false,
            "traffic_activation": false,
            "runs_package_scripts": false
        },
        "risk_class": "lab_only",
        "valid_from": 1000,
        "expires_at": 2000,
        "limitations": ["v2 static spa"]
    });
    let spa_bytes = canonical(&static_spa);
    let spa = AppProvisionPlan::decode(&spa_bytes).unwrap();
    assert_eq!(spa.schema_version(), 2);
    assert_eq!(spa.runtime(), AppRuntime::StaticV1);
    assert_eq!(spa.ingress(), IngressEngine::Caddy);
    assert_eq!(spa.topology(), AppTopology::StaticSpa);
    assert_eq!(spa.database(), AppDatabase::None);
    assert!(spa.spa_fallback());
    assert_eq!(spa.frontend_dir(), Some("frontend"));
    assert!(spa.all_ports().is_empty());
    assert_eq!(
        PreparedPlan::decode(&spa_bytes).unwrap().kind(),
        PlanKind::AppProvision
    );

    // 2. fullstack_split (Caddy static `/` + Bun API `/api/` + PostgreSQL 18 + blue/green + SSE + strip)
    let split = json!({
        "schema_version": 2,
        "plan_id": "plan_split_1",
        "host_id": "host_lab",
        "host_epoch": "epoch_1",
        "profile_digest": sha('a'),
        "requester": "agent_1",
        "verb": "app_provision",
        "site_id": "saas1",
        "hostname": "saas.example.test",
        "runtime": "bun_1_v1",
        "port": 4101,
        "routes": [{"prefix": "/api/", "port": 4101}],
        "websockets": [{"prefix": "/ws/", "port": 4101}],
        "entrypoint": "backend/index.ts",
        "health_path": "/api/health",
        "env_keys": ["DATABASE_URL", "JWT_SECRET"],
        "memory_max_mib": 1024,
        "tasks_max": 128,
        "quota_mib": 4096,
        "ingress": "caddy",
        "topology": "fullstack_split",
        "database": "postgresql_18",
        "blue_green": true,
        "standby_port": 4102,
        "spa_fallback": true,
        "frontend_dir": "frontend",
        "sse_prefixes": ["/api/events/"],
        "strip_api_prefixes": ["/api/"],
        "expected_effects": {
            "creates_account": true,
            "forwards_to_loopback": true,
            "installs_app_unit": true,
            "creates_database": true,
            "traffic_activation": false,
            "runs_package_scripts": false
        },
        "risk_class": "lab_only",
        "valid_from": 1000,
        "expires_at": 2000,
        "limitations": ["v2 fullstack split"]
    });
    let split_bytes = canonical(&split);
    let split_plan = AppProvisionPlan::decode(&split_bytes).unwrap();
    assert_eq!(split_plan.database(), AppDatabase::Postgresql18);
    assert_eq!(split_plan.standby_port(), Some(4102));
    assert_eq!(split_plan.sse_prefixes(), ["/api/events/"]);
    assert_eq!(split_plan.strip_api_prefixes(), ["/api/"]);
    assert_eq!(split_plan.all_ports(), vec![4101, 4102]);
    let split_env = envelope_for_plan(&split_bytes).unwrap();
    assert!(split_env.resource_budget.contains("postgresql_18"));
    assert!(split_env.resource_budget.contains("blue/green"));

    // 3. fullstack_dual_ssr (Node SSR on `/` + Bun API on `/api/` + MariaDB + blue/green 4 ports)
    let dual = json!({
        "schema_version": 2,
        "plan_id": "plan_dual_1",
        "host_id": "host_lab",
        "host_epoch": "epoch_1",
        "profile_digest": sha('a'),
        "requester": "agent_1",
        "verb": "app_provision",
        "site_id": "ssr1",
        "hostname": "ssr.example.test",
        "runtime": "bun_1_v1",
        "port": 4201,
        "routes": [
            {"prefix": "/", "port": 4203},
            {"prefix": "/api/", "port": 4201}
        ],
        "websockets": [{"prefix": "/ws/", "port": 4201}],
        "entrypoint": "api/server.ts",
        "health_path": "/health",
        "env_keys": ["DATABASE_URL"],
        "memory_max_mib": 1024,
        "tasks_max": 128,
        "quota_mib": 4096,
        "ingress": "caddy",
        "topology": "fullstack_dual_ssr",
        "database": "mariadb",
        "blue_green": true,
        "standby_port": 4202,
        "spa_fallback": false,
        "frontend_runtime": "node_22_v1",
        "frontend_entrypoint": "web/server.mjs",
        "frontend_port": 4203,
        "frontend_standby_port": 4204,
        "expected_effects": {
            "creates_account": true,
            "forwards_to_loopback": true,
            "installs_app_unit": true,
            "creates_database": true,
            "traffic_activation": false,
            "runs_package_scripts": false
        },
        "risk_class": "lab_only",
        "valid_from": 1000,
        "expires_at": 2000,
        "limitations": ["v2 dual ssr"]
    });
    let dual_bytes = canonical(&dual);
    let dual_plan = AppProvisionPlan::decode(&dual_bytes).unwrap();
    assert_eq!(dual_plan.topology(), AppTopology::FullstackDualSsr);
    assert_eq!(dual_plan.frontend_runtime(), Some(AppRuntime::Node22V1));
    assert_eq!(dual_plan.frontend_port(), Some(4203));
    assert_eq!(dual_plan.frontend_standby_port(), Some(4204));
    assert_eq!(dual_plan.all_ports(), vec![4201, 4202, 4203, 4204]);

    // Refusals: Postgres 5432, Caddy 2019, duplicate standby port, v2 field in v1, OLS on fullstack_split, wrong creates_database.
    let mut bad_pg_port = split.clone();
    bad_pg_port["standby_port"] = json!(5432);
    assert!(AppProvisionPlan::decode(&canonical(&bad_pg_port)).is_err());

    let mut bad_caddy_port = split.clone();
    bad_caddy_port["standby_port"] = json!(2019);
    assert!(AppProvisionPlan::decode(&canonical(&bad_caddy_port)).is_err());

    let mut bad_dup_port = split.clone();
    bad_dup_port["standby_port"] = json!(4101);
    assert!(AppProvisionPlan::decode(&canonical(&bad_dup_port)).is_err());

    let mut bad_ols_split = split.clone();
    bad_ols_split["ingress"] = json!("ols");
    assert!(AppProvisionPlan::decode(&canonical(&bad_ols_split)).is_err());

    let mut bad_db_effect = split;
    bad_db_effect["expected_effects"]["creates_database"] = json!(false);
    assert!(AppProvisionPlan::decode(&canonical(&bad_db_effect)).is_err());

    let mut bad_v1_with_v2 = provision_plan_json();
    bad_v1_with_v2["ingress"] = json!("caddy");
    assert!(AppProvisionPlan::decode(&canonical(&bad_v1_with_v2)).is_err());

    // 4. app_deploy schema v2 (blue/green + static_v1)
    let mut dep_bg = deploy_plan_json();
    dep_bg["schema_version"] = json!(2);
    dep_bg["blue_green_cutover"] = json!(true);
    dep_bg["expected_effects"]["reloads_caddy"] = json!(true);
    let dep_bg_bytes = canonical(&dep_bg);
    let dep_bg_plan = AppDeployPlan::decode(&dep_bg_bytes).unwrap();
    assert_eq!(dep_bg_plan.schema_version(), 2);
    assert!(dep_bg_plan.blue_green_cutover());
    assert!(
        envelope_for_plan(&dep_bg_bytes)
            .unwrap()
            .resource_budget
            .contains("blue/green Caddy cutover")
    );

    // 5. site_credential_rotate schema v2 (app_postgresql_18_password + app_mariadb_password)
    for (target, expected) in [
        ("app_mariadb_password", CredentialTarget::AppMariadbPassword),
        (
            "app_postgresql_18_password",
            CredentialTarget::AppPostgresql18Password,
        ),
    ] {
        let rot = json!({
            "schema_version": 2,
            "plan_id": "plan_rot_app_1",
            "host_id": "host_lab",
            "host_epoch": "epoch_1",
            "profile_digest": sha('a'),
            "requester": "agent_1",
            "verb": "site_credential_rotate",
            "site_id": "saas1",
            "hostname": "saas.example.test",
            "target": target,
            "expected_effects": {
                "rotates_db_password": true,
                "updates_db_cnf": false,
                "restarts_site_php": false,
                "updates_app_env": true,
                "restarts_app_unit": true,
                "traffic_activation": false,
                "network_access": false,
                "secret_in_plan": false
            },
            "risk_class": "lab_only",
            "valid_from": 1000,
            "expires_at": 2000,
            "limitations": ["v2 app db rotate"]
        });
        let rot_bytes = canonical(&rot);
        let decoded = CredentialRotatePlan::decode(&rot_bytes).unwrap();
        assert_eq!(decoded.schema_version(), 2);
        assert_eq!(decoded.target(), expected);
        assert_eq!(
            PreparedPlan::decode(&rot_bytes).unwrap().kind(),
            PlanKind::SiteCredentialRotate
        );
    }
}
