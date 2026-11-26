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
    approval::{AppLifecycleAction, AppRuntime, Hostname, ProxyRoute, SiteId},
};
use rustiron_journal::{
    AppFacts, AppLifecycleIntent, AppLifecycleResult, AppReleaseIntent, AppReleaseResult,
    AppReleaseState, AppReleaseStep, CaptureIntent, CaptureMethod, DeleteIntent, DeleteResult,
    FixtureJournal, JournalError, ProvisionIntent, ProvisionResult, ProvisionStep, ProxyFacts,
    StepState,
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

    let ProvisionResult::New(prov) = journal
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
        ProvisionResult::Existing(_)
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
        ProvisionResult::New(_)
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
    let AppReleaseResult::New(r) = journal.record_app_release(&rel1, ts(1010)).unwrap() else {
        panic!("expected new release");
    };
    assert_eq!(r.state, AppReleaseState::Intent);
    assert!(matches!(
        journal.record_app_release(&rel1, ts(1011)).unwrap(),
        AppReleaseResult::Existing(_)
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
        AppLifecycleResult::New(_)
    ));
    assert!(matches!(
        journal.record_app_lifecycle(&lc, ts(1061)).unwrap(),
        AppLifecycleResult::Existing(_)
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
        DeleteResult::New(_)
    ));

    // Port 43187 is now freed after emdash1 is deleted!
    let prov_reuse = provision_intent("op_app_reuse", "emdash2", "emdash2.example.test");
    assert!(matches!(
        journal
            .record_app_provision(&prov_reuse, &facts, ts(1080))
            .unwrap(),
        ProvisionResult::New(_)
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
        "DROP TABLE credential_rotations; DROP TABLE app_lifecycles; DROP TABLE app_release_steps; \
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
        ProvisionResult::New(_)
    ));
}
