//! P27 (D-099) journal v43 tests: `apps`, `app_releases`, `app_release_steps`,
//! `app_lifecycles`, v42->v43 migration, replay safety, and observation.

use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

use rustiron_contracts::{
    Timestamp,
    approval::{
        AppDatabase, AppLifecycleAction, AppRuntime, AppTopology, Hostname, IngressEngine,
        ProxyRoute, SiteId,
    },
};
use rustiron_journal::{
    Admitted, AppFacts, AppFullstackSpec, AppLifecycleIntent, AppReleaseIntent, AppReleaseState,
    AppReleaseStep, AppSlot, CaddyGeneration, CaddyGenerationState, CaddyIngressMode,
    CaptureIntent, CaptureMethod, DeleteIntent, FixtureJournal, JournalError, ProvisionIntent,
    ProvisionStep, ProxyFacts, StepState,
};

#[expect(
    dead_code,
    reason = "shared helpers; this suite needs no fixture operation"
)]
mod support;
use support::*;

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct State(PathBuf);
impl State {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "ri-app-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn init(&self) -> FixtureJournal {
        FixtureJournal::initialize(&self.0, id("host_fixture"), id("epoch_fixture")).unwrap()
    }
    fn open(&self) -> Result<FixtureJournal, JournalError> {
        FixtureJournal::open(&self.0, id("host_fixture"), id("epoch_fixture"))
    }
    fn sql(&self, sql: &str) {
        rusqlite::Connection::open(self.0.join("fixture-journal.sqlite"))
            .unwrap()
            .execute_batch(sql)
            .unwrap();
    }
}
impl Drop for State {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn ts(seconds: u64) -> Timestamp {
    Timestamp::try_from(seconds).unwrap()
}

fn site(name: &str) -> SiteId {
    SiteId::try_from(name.to_owned()).unwrap()
}

fn host(name: &str) -> Hostname {
    Hostname::try_from(name.to_owned()).unwrap()
}

fn app_facts(runtime: AppRuntime, port: u16) -> AppFacts {
    AppFacts {
        runtime,
        port,
        entrypoint: "dist/server/entry.mjs".to_owned(),
        worker_entrypoint: Some("dist/worker.mjs".to_owned()),
        health_path: "/health".to_owned(),
        env_keys: vec![
            "EMDASH_ENCRYPTION_KEY".to_owned(),
            "EMDASH_SITE_URL".to_owned(),
        ],
        memory_max_mib: 512,
        tasks_max: 64,
        quota_mib: 2048,
        routes: ProxyFacts {
            routes: vec![ProxyRoute {
                prefix: "/".to_owned(),
                port,
            }],
            websockets: vec![ProxyRoute {
                prefix: "/_emdash/api/content/".to_owned(),
                port,
            }],
        },
    }
}

fn provision_intent(op: &str, site_id: &str, hostname: &str) -> ProvisionIntent {
    ProvisionIntent {
        operation_id: id(op),
        idempotency_key: id(&format!("key_{op}")),
        grant_id: id(&format!("grant_{op}")),
        nonce: id(&format!("nonce_{op}")),
        plan_digest: digest('a'),
        grant_digest: digest('b'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: site(site_id),
        hostname: host(hostname),
        expires_at: ts(5000),
    }
}

fn finish_provision(journal: &mut FixtureJournal, op: &str) {
    let op_id = id(op);
    for step in ProvisionStep::ALL {
        journal.begin_step(&op_id, step, "ok").unwrap();
        journal.finish_step(&op_id, step, true).unwrap();
    }
}

fn release_intent(
    op: &str,
    site_id: &str,
    release_id: &str,
    runtime: AppRuntime,
    migration: Option<&str>,
    capture: Option<&str>,
) -> AppReleaseIntent {
    AppReleaseIntent {
        operation_id: id(op),
        idempotency_key: id(&format!("key_{op}")),
        grant_id: id(&format!("grant_{op}")),
        nonce: id(&format!("nonce_{op}")),
        plan_digest: digest('c'),
        grant_digest: digest('d'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: site(site_id),
        release_id: release_id.to_owned(),
        runtime,
        artifact_sha256: digest('e'),
        manifest_sha256: digest('f'),
        file_count: 100,
        total_bytes: 1_048_576,
        migration_entrypoint: migration.map(str::to_owned),
        capture_operation_id: capture.map(id),
        health_path: "/health".to_owned(),
        expires_at: ts(5000),
    }
}

fn lifecycle_intent(op: &str, site_id: &str, action: AppLifecycleAction) -> AppLifecycleIntent {
    AppLifecycleIntent {
        operation_id: id(op),
        idempotency_key: id(&format!("key_{op}")),
        grant_id: id(&format!("grant_{op}")),
        nonce: id(&format!("nonce_{op}")),
        plan_digest: digest('1'),
        grant_digest: digest('2'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: site(site_id),
        action,
        expires_at: ts(5000),
    }
}

fn record_succeeded_capture(journal: &mut FixtureJournal, op: &str, site_id: &str, at: u64) {
    let intent = CaptureIntent {
        operation_id: id(op),
        idempotency_key: id(&format!("key_{op}")),
        grant_id: id(&format!("grant_{op}")),
        nonce: id(&format!("nonce_{op}")),
        plan_digest: digest('3'),
        grant_digest: digest('4'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: site(site_id),
        expires_at: ts(at + 600),
    };
    let policy = digest('9');
    journal
        .record_capture(
            &intent,
            ts(at),
            CaptureMethod::SiteFilesDbV1,
            Some(30),
            &policy,
        )
        .unwrap();
    let snap = "9".repeat(64);
    journal
        .finish_capture(&id(op), Some(&snap), ts(at + 5), Some((10, 2048)), None)
        .unwrap();
}

#[test]
fn app_provision_records_app_and_proxy_routes_and_enforces_port_uniqueness() {
    let state = State::new("prov");
    let mut journal = state.init();
    let facts = app_facts(AppRuntime::Node22V1, 43187);
    let intent = provision_intent("op_app1", "emdash1", "emdash.example.test");

    let Admitted::New(prov) = journal
        .record_app_provision(&intent, &facts, ts(1000))
        .unwrap()
    else {
        panic!("expected new provision");
    };
    assert_eq!(prov.intent.site_id.as_str(), "emdash1");
    assert_eq!(
        journal.app_facts(&id("op_app1")).unwrap(),
        Some(facts.clone())
    );
    assert_eq!(
        journal.proxy_facts(&id("op_app1")).unwrap(),
        Some(facts.routes.clone())
    );

    // Exact idempotent retry returns Existing.
    assert!(matches!(
        journal
            .record_app_provision(&intent, &facts, ts(1001))
            .unwrap(),
        Admitted::Existing(_)
    ));
    // Retry with altered port is a Conflict.
    assert_eq!(
        journal.record_app_provision(&intent, &app_facts(AppRuntime::Node22V1, 43188), ts(1002)),
        Err(JournalError::Conflict)
    );

    finish_provision(&mut journal, "op_app1");

    // Second app on the SAME port is refused as Consumed.
    let intent2 = provision_intent("op_app2", "serpapi", "api.example.test");
    assert_eq!(
        journal.record_app_provision(&intent2, &app_facts(AppRuntime::Bun1V1, 43187), ts(1005)),
        Err(JournalError::Consumed)
    );
    // Second app on a FREE port succeeds.
    assert!(matches!(
        journal
            .record_app_provision(&intent2, &app_facts(AppRuntime::Bun1V1, 43188), ts(1006))
            .unwrap(),
        Admitted::New(_)
    ));
    finish_provision(&mut journal, "op_app2");

    // Reopening validates all rows cleanly.
    drop(journal);
    let reopened = state.open().unwrap();
    assert_eq!(
        reopened.app_facts_by_site(&site("emdash1")).unwrap(),
        Some(facts)
    );
    assert_eq!(reopened.admission_count().unwrap(), 2);
}

#[test]
fn app_release_steps_rollback_migration_capture_and_lifecycle_work_durably() {
    let state = State::new("rel");
    let mut journal = state.init();
    let facts = app_facts(AppRuntime::Node22V1, 43187);
    let prov = provision_intent("op_app1", "emdash1", "emdash.example.test");
    journal
        .record_app_provision(&prov, &facts, ts(1000))
        .unwrap();
    finish_provision(&mut journal, "op_app1");

    // Wrong runtime is refused before recording.
    let wrong_rt = release_intent(
        "op_rel_bad",
        "emdash1",
        "rel-bad",
        AppRuntime::Bun1V1,
        None,
        None,
    );
    assert_eq!(
        journal.record_app_release(&wrong_rt, ts(1010)),
        Err(JournalError::SourceChanged)
    );

    // 1. Successful release without migration.
    let rel1 = release_intent(
        "op_rel1",
        "emdash1",
        "rel-1.0.0",
        AppRuntime::Node22V1,
        None,
        None,
    );
    let Admitted::New(r) = journal.record_app_release(&rel1, ts(1010)).unwrap() else {
        panic!("expected new release");
    };
    assert_eq!(r.state, AppReleaseState::Intent);
    assert!(matches!(
        journal.record_app_release(&rel1, ts(1011)).unwrap(),
        Admitted::Existing(_)
    ));
    assert_eq!(
        journal.record_app_lifecycle(
            &lifecycle_intent("op_lc_blocked", "emdash1", AppLifecycleAction::Restart),
            ts(1012),
        ),
        Err(JournalError::SourceChanged)
    );

    for step in [
        AppReleaseStep::Unpack,
        AppReleaseStep::Activate,
        AppReleaseStep::Health,
    ] {
        journal
            .begin_app_release_step(&id("op_rel1"), step)
            .unwrap();
        journal
            .finish_app_release_step(&id("op_rel1"), step, true)
            .unwrap();
    }
    let done = journal
        .finish_app_release(&id("op_rel1"), AppReleaseState::Done)
        .unwrap();
    assert_eq!(done.state, AppReleaseState::Done);
    assert_eq!(
        journal
            .latest_app_release(&site("emdash1"))
            .unwrap()
            .map(|r| r.release_id),
        Some("rel-1.0.0".to_owned())
    );

    // Duplicate release_id is refused.
    let dup = release_intent(
        "op_rel_dup",
        "emdash1",
        "rel-1.0.0",
        AppRuntime::Node22V1,
        None,
        None,
    );
    assert_eq!(
        journal.record_app_release(&dup, ts(1020)),
        Err(JournalError::SourceChanged)
    );

    // 2. Migrating release requires a fresh capture (within 24h) and rolls back cleanly.
    record_succeeded_capture(&mut journal, "op_cap1", "emdash1", 1030);
    let rel2 = release_intent(
        "op_rel2",
        "emdash1",
        "rel-1.1.0",
        AppRuntime::Node22V1,
        Some("scripts/migrate.mjs"),
        Some("op_cap1"),
    );
    journal.record_app_release(&rel2, ts(1050)).unwrap();
    for (step, ok) in [
        (AppReleaseStep::Unpack, true),
        (AppReleaseStep::Migrate, true),
        (AppReleaseStep::Activate, true),
        (AppReleaseStep::Health, false),
        (AppReleaseStep::Rollback, true),
    ] {
        journal
            .begin_app_release_step(&id("op_rel2"), step)
            .unwrap();
        journal
            .finish_app_release_step(&id("op_rel2"), step, ok)
            .unwrap();
    }
    let rb = journal
        .finish_app_release(&id("op_rel2"), AppReleaseState::RolledBack)
        .unwrap();
    assert_eq!(rb.state, AppReleaseState::RolledBack);
    assert_eq!(
        journal
            .latest_app_release(&site("emdash1"))
            .unwrap()
            .map(|r| r.release_id),
        Some("rel-1.0.0".to_owned())
    );

    // 3. Lifecycle operation works after release settles.
    let lc = lifecycle_intent("op_lc1", "emdash1", AppLifecycleAction::Restart);
    assert!(matches!(
        journal.record_app_lifecycle(&lc, ts(1060)).unwrap(),
        Admitted::New(_)
    ));
    assert!(matches!(
        journal.record_app_lifecycle(&lc, ts(1061)).unwrap(),
        Admitted::Existing(_)
    ));
    let lc_done = journal.finish_app_lifecycle(&id("op_lc1"), true).unwrap();
    assert_eq!(lc_done.state, StepState::Done);

    // 4. Deployed app cannot be deleted without a capture, CAN be deleted with a fresh capture.
    let del_no_cap = DeleteIntent {
        operation_id: id("op_del_bad"),
        idempotency_key: id("key_del_bad"),
        grant_id: id("grant_del_bad"),
        nonce: id("nonce_del_bad"),
        plan_digest: digest('7'),
        grant_digest: digest('8'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: site("emdash1"),
        hostname: host("emdash.example.test"),
        capture_operation_id: None,
        expires_at: ts(5000),
    };
    assert_eq!(
        journal.record_deletion(&del_no_cap, ts(1070)),
        Err(JournalError::Consumed)
    );
    let del_with_cap = DeleteIntent {
        operation_id: id("op_del1"),
        idempotency_key: id("key_del1"),
        grant_id: id("grant_del1"),
        nonce: id("nonce_del1"),
        capture_operation_id: Some(id("op_cap1")),
        ..del_no_cap
    };
    assert!(matches!(
        journal.record_deletion(&del_with_cap, ts(1075)).unwrap(),
        Admitted::New(_)
    ));

    // Port 43187 is now freed after emdash1 is deleted!
    let prov_reuse = provision_intent("op_app_reuse", "emdash2", "emdash2.example.test");
    assert!(matches!(
        journal
            .record_app_provision(&prov_reuse, &facts, ts(1080))
            .unwrap(),
        Admitted::New(_)
    ));

    let usage = journal.authority_usage(0).unwrap();
    assert_eq!(usage.total_admissions, journal.admission_count().unwrap());
    drop(journal);
    let obs = FixtureJournal::observe(&state.0, &id("host_fixture"), &id("epoch_fixture")).unwrap();
    let em1 = obs
        .provisions
        .iter()
        .find(|p| p.site_id == "emdash1")
        .unwrap();
    assert_eq!(em1.app_runtime.as_deref(), Some("node_22_v1"));
    assert_eq!(em1.app_active_release.as_deref(), Some("rel-1.0.0"));
}

#[test]
fn a_v42_journal_migrates_cleanly_to_v43_and_preserves_records() {
    let state = State::new("v42");
    let mut journal = state.init();
    let prov = provision_intent("op_site1", "blog1", "blog1.example.test");
    journal.record_provision(&prov, ts(1000)).unwrap();
    finish_provision(&mut journal, "op_site1");
    drop(journal);

    state.sql(
        "DROP TABLE caddy_generations; DROP TABLE app_fullstack_specs; DROP TABLE credential_rotations; DROP TABLE app_lifecycles; DROP TABLE app_release_steps; \
         DROP TABLE app_releases; DROP TABLE apps; PRAGMA user_version=42;",
    );
    assert!(matches!(state.open(), Err(JournalError::Unavailable)));

    let mut migrated =
        FixtureJournal::migrate(&state.0, id("host_fixture"), id("epoch_fixture")).unwrap();
    assert_eq!(migrated.admission_count().unwrap(), 1);
    let app = provision_intent("op_app1", "serpapi", "api.example.test");
    assert!(matches!(
        migrated
            .record_app_provision(&app, &app_facts(AppRuntime::Bun1V1, 43187), ts(1010))
            .unwrap(),
        Admitted::New(_)
    ));
}

#[test]
fn d102_v45_fullstack_specs_blue_green_slots_port_collisions_caddy_generations_and_v44_migration() {
    let state = State::new("v45-fullstack");
    let mut journal = state.init();

    // 1. static_spa (Caddy, port 0, zero proxy routes, no DB)
    let spa_intent = provision_intent("op_spa1", "docs1", "docs.example.test");
    let spa_facts = AppFacts {
        runtime: AppRuntime::StaticV1,
        port: 0,
        entrypoint: String::new(),
        worker_entrypoint: None,
        health_path: "/".to_owned(),
        env_keys: Vec::new(),
        memory_max_mib: 128,
        tasks_max: 32,
        quota_mib: 512,
        routes: ProxyFacts {
            routes: Vec::new(),
            websockets: Vec::new(),
        },
    };
    let spa_spec = AppFullstackSpec {
        ingress: IngressEngine::Caddy,
        topology: AppTopology::StaticSpa,
        database: AppDatabase::None,
        blue_green: false,
        active_slot: AppSlot::A,
        standby_port: None,
        spa_fallback: true,
        frontend_dir: Some("frontend".to_owned()),
        frontend_runtime: None,
        frontend_entrypoint: None,
        frontend_port: None,
        frontend_standby_port: None,
        sse_prefixes: Vec::new(),
        strip_api_prefixes: Vec::new(),
    };
    assert!(matches!(
        journal
            .record_fullstack_app_provision(&spa_intent, &spa_facts, &spa_spec, ts(1000))
            .unwrap(),
        Admitted::New(_)
    ));
    finish_provision(&mut journal, "op_spa1");
    assert_eq!(
        journal.app_fullstack_spec(&id("op_spa1")).unwrap(),
        Some(spa_spec.clone())
    );
    // A second static_spa (also port 0) succeeds without port collision.
    let spa2 = provision_intent("op_spa2", "docs2", "docs2.example.test");
    assert!(matches!(
        journal
            .record_fullstack_app_provision(&spa2, &spa_facts, &spa_spec, ts(1005))
            .unwrap(),
        Admitted::New(_)
    ));
    finish_provision(&mut journal, "op_spa2");

    // 2. fullstack_split (Caddy static `/` + Bun API `/api/` + PostgreSQL 18 + blue/green slot)
    let split_intent = provision_intent("op_split1", "saas1", "saas.example.test");
    let split_facts = AppFacts {
        runtime: AppRuntime::Bun1V1,
        port: 4101,
        entrypoint: "backend/index.ts".to_owned(),
        worker_entrypoint: None,
        health_path: "/api/health".to_owned(),
        env_keys: vec!["DATABASE_URL".to_owned()],
        memory_max_mib: 1024,
        tasks_max: 128,
        quota_mib: 4096,
        routes: ProxyFacts {
            routes: vec![ProxyRoute {
                prefix: "/api/".to_owned(),
                port: 4101,
            }],
            websockets: vec![ProxyRoute {
                prefix: "/ws/".to_owned(),
                port: 4101,
            }],
        },
    };
    let split_spec = AppFullstackSpec {
        ingress: IngressEngine::Caddy,
        topology: AppTopology::FullstackSplit,
        database: AppDatabase::Postgresql18,
        blue_green: true,
        active_slot: AppSlot::A,
        standby_port: Some(4102),
        spa_fallback: true,
        frontend_dir: Some("frontend".to_owned()),
        frontend_runtime: None,
        frontend_entrypoint: None,
        frontend_port: None,
        frontend_standby_port: None,
        sse_prefixes: vec!["/api/events/".to_owned()],
        strip_api_prefixes: vec!["/api/".to_owned()],
    };
    assert!(matches!(
        journal
            .record_fullstack_app_provision(&split_intent, &split_facts, &split_spec, ts(1010))
            .unwrap(),
        Admitted::New(_)
    ));
    // Exact retry returns Existing; mismatching spec returns Conflict.
    assert!(matches!(
        journal
            .record_fullstack_app_provision(&split_intent, &split_facts, &split_spec, ts(1011))
            .unwrap(),
        Admitted::Existing(_)
    ));
    finish_provision(&mut journal, "op_split1");

    // Another app colliding with standby port 4102 is refused with Consumed.
    let collide = provision_intent("op_col1", "col1", "col1.example.test");
    assert_eq!(
        journal.record_app_provision(&collide, &app_facts(AppRuntime::Node22V1, 4102), ts(1015)),
        Err(JournalError::Consumed)
    );

    // Flip blue/green slot A -> B and confirm persistence across reopen.
    let flipped = journal
        .set_app_active_slot(&id("op_split1"), AppSlot::B)
        .unwrap();
    assert_eq!(flipped.active_slot, AppSlot::B);

    // 3. Caddy generation ledger: stage -> activate -> stage second -> activate -> rollback to first.
    let g1 = CaddyGeneration {
        generation_id: id("caddy_gen_1"),
        operation_id: id("op_cfg_1"),
        ingress_mode: CaddyIngressMode::CaddyEdgeOverOls,
        config_sha256: digest('1'),
        site_count: 3,
        created_at: ts(1020),
        state: CaddyGenerationState::Staged,
    };
    let g2 = CaddyGeneration {
        generation_id: id("caddy_gen_2"),
        operation_id: id("op_cfg_2"),
        ingress_mode: CaddyIngressMode::CaddyEdgeOverOls,
        config_sha256: digest('2'),
        site_count: 3,
        created_at: ts(1025),
        state: CaddyGenerationState::Staged,
    };
    journal.record_caddy_generation(&g1).unwrap();
    assert_eq!(
        journal
            .activate_caddy_generation(&id("caddy_gen_1"))
            .unwrap()
            .state,
        CaddyGenerationState::Active
    );
    journal.record_caddy_generation(&g2).unwrap();
    journal
        .activate_caddy_generation(&id("caddy_gen_2"))
        .unwrap();
    assert_eq!(
        journal
            .active_caddy_generation()
            .unwrap()
            .unwrap()
            .generation_id,
        id("caddy_gen_2")
    );
    journal
        .rollback_caddy_generation(&id("caddy_gen_2"), Some(&id("caddy_gen_1")))
        .unwrap();
    assert_eq!(
        journal
            .active_caddy_generation()
            .unwrap()
            .unwrap()
            .generation_id,
        id("caddy_gen_1")
    );
    assert_eq!(journal.caddy_generations().unwrap().len(), 2);

    // Reopen validates all v45 invariants cleanly.
    drop(journal);
    let reopened = state.open().unwrap();
    assert_eq!(
        reopened
            .app_fullstack_spec_by_site(&SiteId::try_from("saas1".to_owned()).unwrap())
            .unwrap()
            .unwrap()
            .active_slot,
        AppSlot::B
    );
    assert_eq!(
        reopened
            .active_caddy_generation()
            .unwrap()
            .unwrap()
            .generation_id,
        id("caddy_gen_1")
    );
}

#[test]
fn a_v44_journal_migrates_cleanly_to_v45_and_preserves_apps() {
    let state = State::new("v44-to-v45");
    let mut journal = state.init();
    let app = provision_intent("op_app_v44", "legacy1", "legacy1.example.test");
    journal
        .record_app_provision(&app, &app_facts(AppRuntime::Node22V1, 43187), ts(1000))
        .unwrap();
    finish_provision(&mut journal, "op_app_v44");
    drop(journal);

    // Downgrade to exact v44 schema (old CHECKs on apps, app_releases, credential_rotations).
    state.sql(
        "PRAGMA foreign_keys=OFF; \
         DROP TABLE caddy_generations; DROP TABLE app_fullstack_specs; \
         CREATE TEMP TABLE a44 AS SELECT * FROM apps; DROP TABLE apps; \
         CREATE TABLE apps (operation_id TEXT PRIMARY KEY REFERENCES provisions(operation_id), runtime TEXT NOT NULL CHECK(runtime IN ('node_22_v1','bun_1_v1')), port INTEGER NOT NULL CHECK(port BETWEEN 1024 AND 65535 AND port<>3306), entrypoint TEXT NOT NULL CHECK(length(entrypoint) BETWEEN 1 AND 128), worker_entrypoint TEXT CHECK(worker_entrypoint IS NULL OR length(worker_entrypoint) BETWEEN 1 AND 128), health_path TEXT NOT NULL CHECK(length(health_path) BETWEEN 1 AND 128 AND health_path GLOB '/*'), env_keys TEXT NOT NULL CHECK(length(env_keys)<=4200 AND env_keys NOT GLOB '*[^A-Z0-9_,]*'), memory_max_mib INTEGER NOT NULL CHECK(memory_max_mib BETWEEN 64 AND 8192), tasks_max INTEGER NOT NULL CHECK(tasks_max BETWEEN 16 AND 1024), quota_mib INTEGER NOT NULL CHECK(quota_mib BETWEEN 128 AND 65536)) STRICT; \
         INSERT INTO apps SELECT * FROM temp.a44; DROP TABLE temp.a44; \
         CREATE TEMP TABLE r44 AS SELECT * FROM app_releases; DROP TABLE app_releases; \
         CREATE TABLE app_releases (operation_id TEXT PRIMARY KEY, site_id TEXT NOT NULL REFERENCES provisions(site_id), release_id TEXT NOT NULL CHECK(length(release_id) BETWEEN 1 AND 64), runtime TEXT NOT NULL CHECK(runtime IN ('node_22_v1','bun_1_v1')), artifact_sha256 TEXT NOT NULL CHECK(length(artifact_sha256)=64 AND artifact_sha256 NOT GLOB '*[^0-9a-f]*'), manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256)=64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'), file_count INTEGER NOT NULL CHECK(file_count BETWEEN 1 AND 50000), total_bytes INTEGER NOT NULL CHECK(total_bytes BETWEEN 1 AND 536870912), migration_entrypoint TEXT CHECK(migration_entrypoint IS NULL OR length(migration_entrypoint) BETWEEN 1 AND 128), capture_operation_id TEXT REFERENCES captures(operation_id), health_path TEXT NOT NULL CHECK(length(health_path) BETWEEN 1 AND 128 AND health_path GLOB '/*'), idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL CHECK(length(plan_digest)=64 AND plan_digest NOT GLOB '*[^0-9a-f]*'), grant_digest TEXT NOT NULL CHECK(length(grant_digest)=64 AND grant_digest NOT GLOB '*[^0-9a-f]*'), expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('intent','done','rolled_back')), UNIQUE(site_id, release_id)) STRICT; \
         CREATE UNIQUE INDEX one_open_app_release ON app_releases(site_id) WHERE state='intent'; \
         INSERT INTO app_releases SELECT * FROM temp.r44; DROP TABLE temp.r44; \
         CREATE TEMP TABLE c44 AS SELECT * FROM credential_rotations; DROP TABLE credential_rotations; \
         CREATE TABLE credential_rotations (operation_id TEXT PRIMARY KEY, site_id TEXT NOT NULL REFERENCES provisions(site_id), hostname TEXT NOT NULL CHECK(length(hostname) BETWEEN 1 AND 253 AND hostname NOT GLOB '*[^a-z0-9.-]*'), target TEXT NOT NULL CHECK(target='mariadb_user_password'), idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL CHECK(length(plan_digest)=64 AND plan_digest NOT GLOB '*[^0-9a-f]*'), grant_digest TEXT NOT NULL CHECK(length(grant_digest)=64 AND grant_digest NOT GLOB '*[^0-9a-f]*'), expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('intent','done','failed_compensated','needs_attention','failed'))) STRICT; \
         CREATE UNIQUE INDEX one_open_credential_rotation ON credential_rotations(site_id) WHERE state IN ('intent','needs_attention'); \
         INSERT INTO credential_rotations SELECT * FROM temp.c44; DROP TABLE temp.c44; \
         PRAGMA user_version=44;",
    );
    assert!(matches!(state.open(), Err(JournalError::Unavailable)));

    let migrated =
        FixtureJournal::migrate(&state.0, id("host_fixture"), id("epoch_fixture")).unwrap();
    assert_eq!(migrated.admission_count().unwrap(), 1);
    assert_eq!(
        migrated.app_facts(&id("op_app_v44")).unwrap().unwrap().port,
        43187
    );
    assert_eq!(
        migrated.app_fullstack_spec(&id("op_app_v44")).unwrap(),
        None
    );
}
