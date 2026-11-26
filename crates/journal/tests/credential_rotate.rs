//! W608 (journal v44, D-100): signed per-site credential rotations.
//!
//! Verifies intent recording, exact replay, conflict refusal, mutual exclusion
//! for `intent` and `needs_attention`, operator reconciliation, non-WordPress
//! site refusals (static, proxy, app, deleted, quarantined, hostname mismatch),
//! v43 -> v44 migration, and signed-admission observability. Real SQLite; no
//! host effects and no secret values stored.

use rustiron_contracts::{
    CanonicalObject,
    approval::{AppRuntime, CredentialTarget, Hostname, ProxyRoute, Sha256Digest, SiteId},
    migration::PhpVersion,
};
use rustiron_journal::{
    AppFacts, CredentialRotateIntent, CredentialRotateResult, CredentialRotateState,
    FixtureJournal, ImportFacts, ImportStep, JournalError, ProvisionIntent, ProvisionStep,
    ProxyFacts, QuotaChangeIntent, SignedAdmission,
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

#[expect(
    dead_code,
    reason = "shared helpers; this suite needs no fixture operation"
)]
mod support;
use support::*;

const DAY: u64 = 24 * 3600;

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct State(PathBuf);
impl State {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ri-credrot-{}-{}",
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
    fn migrate(&self) -> Result<FixtureJournal, JournalError> {
        FixtureJournal::migrate(&self.0, id("host_fixture"), id("epoch_fixture"))
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
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn site_id(name: &str) -> SiteId {
    SiteId::try_from(name.to_owned()).unwrap()
}

fn hostname(name: &str) -> Hostname {
    Hostname::try_from(format!("{name}.example.test")).unwrap()
}

fn prov_intent(name: &str) -> ProvisionIntent {
    ProvisionIntent {
        operation_id: id(&format!("prov_{name}")),
        idempotency_key: id(&format!("prov_key_{name}")),
        grant_id: id(&format!("prov_grant_{name}")),
        nonce: id(&format!("prov_nonce_{name}")),
        plan_digest: digest('a'),
        grant_digest: digest('b'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: site_id(name),
        hostname: hostname(name),
        expires_at: time(10 * DAY),
    }
}

fn finish_provision(ledger: &mut FixtureJournal, operation_id: &rustiron_contracts::Id) {
    for step in ProvisionStep::ALL {
        ledger.begin_step(operation_id, step, "r").unwrap();
        ledger.finish_step(operation_id, step, true).unwrap();
    }
}

fn finish_import_provision(ledger: &mut FixtureJournal, operation_id: &rustiron_contracts::Id) {
    for step in ProvisionStep::ALL {
        ledger.begin_step(operation_id, step, "r").unwrap();
        if step == ProvisionStep::Recipe {
            for import_step in ImportStep::ALL {
                ledger.begin_import_step(operation_id, import_step).unwrap();
                ledger
                    .finish_import_step(operation_id, import_step, true)
                    .unwrap();
            }
        }
        ledger.finish_step(operation_id, step, true).unwrap();
    }
}

fn served_wp(ledger: &mut FixtureJournal, name: &str) {
    let intent = prov_intent(name);
    ledger.record_provision(&intent, time(900)).unwrap();
    finish_provision(ledger, &intent.operation_id);
}

fn rot(n: u32, name: &str) -> CredentialRotateIntent {
    CredentialRotateIntent {
        operation_id: id(&format!("credrot_{n}")),
        idempotency_key: id(&format!("credrot_key_{n}")),
        grant_id: id(&format!("credrot_grant_{n}")),
        nonce: id(&format!("credrot_nonce_{n}")),
        plan_digest: digest('5'),
        grant_digest: digest('6'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: site_id(name),
        hostname: hostname(name),
        target: CredentialTarget::MariadbUserPassword,
        expires_at: time(10 * DAY),
    }
}

#[test]
fn lifecycle_replay_mutual_exclusion_and_reconcile() {
    let state = State::new();
    let mut ledger = state.init();
    served_wp(&mut ledger, "blog1");

    let first = rot(1, "blog1");
    let CredentialRotateResult::New(open) = ledger
        .record_credential_rotation(&first, time(1000))
        .unwrap()
    else {
        panic!("expected new rotation");
    };
    assert_eq!(open.state, CredentialRotateState::Intent);
    assert!(open.state.is_open());

    // Exact replay returns Existing; mismatched field returns Conflict.
    assert_eq!(
        ledger
            .record_credential_rotation(&first, time(1001))
            .unwrap(),
        CredentialRotateResult::Existing(open.clone())
    );
    let mut mismatch = first.clone();
    mismatch.nonce = id("other_nonce");
    assert_eq!(
        ledger
            .record_credential_rotation(&mismatch, time(1001))
            .err(),
        Some(JournalError::Conflict)
    );

    // Open rotation blocks a second rotation and a quota change on the same site.
    assert_eq!(
        ledger
            .record_credential_rotation(&rot(2, "blog1"), time(1002))
            .err(),
        Some(JournalError::Consumed)
    );
    assert_eq!(
        ledger
            .record_quota_change(
                &QuotaChangeIntent {
                    operation_id: id("q1"),
                    idempotency_key: id("qk1"),
                    grant_id: id("qg1"),
                    nonce: id("qn1"),
                    plan_digest: digest('7'),
                    grant_digest: digest('8'),
                    host_id: id("host_fixture"),
                    host_epoch: id("epoch_fixture"),
                    site_id: site_id("blog1"),
                    block_hard_kib: 524_288,
                    inode_hard: 40_000,
                    expires_at: time(10 * DAY),
                },
                time(1002),
            )
            .err(),
        Some(JournalError::Consumed)
    );

    // Finishing as Done unlocks the site for a later rotation.
    let done = ledger
        .finish_credential_rotation(&first.operation_id, CredentialRotateState::Done)
        .unwrap();
    assert_eq!(done.state, CredentialRotateState::Done);
    assert!(done.state.is_terminal());

    // Second rotation hits NeedsAttention and stays locked until reconciled.
    let second = rot(2, "blog1");
    ledger
        .record_credential_rotation(&second, time(1100))
        .unwrap();
    let attn = ledger
        .finish_credential_rotation(&second.operation_id, CredentialRotateState::NeedsAttention)
        .unwrap();
    assert_eq!(attn.state, CredentialRotateState::NeedsAttention);
    assert!(attn.state.is_open());
    assert_eq!(
        ledger
            .record_credential_rotation(&rot(3, "blog1"), time(1101))
            .err(),
        Some(JournalError::Consumed)
    );

    // Reconcile NeedsAttention -> FailedCompensated unlocks the site.
    let settled = ledger
        .reconcile_credential_rotation(
            &second.operation_id,
            CredentialRotateState::FailedCompensated,
        )
        .unwrap();
    assert_eq!(settled.state, CredentialRotateState::FailedCompensated);

    // Third rotation can now be recorded and settled Failed.
    let third = rot(3, "blog1");
    ledger
        .record_credential_rotation(&third, time(1200))
        .unwrap();
    ledger
        .finish_credential_rotation(&third.operation_id, CredentialRotateState::Failed)
        .unwrap();

    drop(ledger);
    let reopened = state.open().unwrap();
    assert_eq!(reopened.admission_count().unwrap(), 4);
    assert_eq!(
        reopened
            .credential_rotation_status(&first.operation_id)
            .unwrap(),
        Some(done)
    );
}

#[test]
fn non_wordpress_and_mismatched_sites_are_refused_before_intent() {
    let state = State::new();
    let mut ledger = state.init();

    // 1. Live WordPress site (for hostname mismatch check)
    served_wp(&mut ledger, "wp1");

    // 2. Static import site (dump_bytes == 0)
    let static_prov = prov_intent("stat1");
    ledger
        .record_import(
            &static_prov,
            &ImportFacts {
                archive_sha256: digest('1'),
                manifest_sha256: digest('2'),
                file_entries: 4,
                file_bytes: 1024,
                dump_bytes: 0,
                target_php: PhpVersion::try_from("8.3".to_owned()).unwrap(),
                source_hostname: None,
                alias_hostname: None,
            },
            time(910),
        )
        .unwrap();
    finish_import_provision(&mut ledger, &static_prov.operation_id);

    // 3. Proxy site
    let proxy_prov = prov_intent("prox1");
    ledger
        .record_proxy_provision(
            &proxy_prov,
            &ProxyFacts {
                routes: vec![ProxyRoute {
                    prefix: "/".to_owned(),
                    port: 3000,
                }],
                websockets: Vec::new(),
            },
            time(920),
        )
        .unwrap();
    finish_provision(&mut ledger, &proxy_prov.operation_id);

    // 4. Modern app site
    let app_prov = prov_intent("app1");
    ledger
        .record_app_provision(
            &app_prov,
            &AppFacts {
                runtime: AppRuntime::Node22V1,
                port: 3001,
                entrypoint: "server.mjs".to_owned(),
                worker_entrypoint: None,
                health_path: "/health".to_owned(),
                env_keys: vec!["NODE_ENV".to_owned()],
                memory_max_mib: 256,
                tasks_max: 64,
                quota_mib: 512,
                routes: ProxyFacts {
                    routes: vec![ProxyRoute {
                        prefix: "/".to_owned(),
                        port: 3001,
                    }],
                    websockets: Vec::new(),
                },
            },
            time(930),
        )
        .unwrap();
    finish_provision(&mut ledger, &app_prov.operation_id);

    let before = ledger.admission_count().unwrap();

    let mut wrong_host = rot(1, "wp1");
    wrong_host.hostname = hostname("other");

    for intent in [
        wrong_host,
        rot(2, "stat1"),
        rot(3, "prox1"),
        rot(4, "app1"),
        rot(5, "nosuch"),
    ] {
        assert_eq!(
            ledger.record_credential_rotation(&intent, time(1000)).err(),
            Some(JournalError::Consumed),
            "expected refusal for {intent:?}"
        );
    }
    assert_eq!(ledger.admission_count().unwrap(), before);
}

#[test]
fn v43_migrates_to_v44_and_signed_rotation_stays_openable() {
    const PLAN: &str = r#"{"hostname":"blog1.example.test","plan_id":"plan_credrot","schema_version":1,"site_id":"blog1","target":"mariadb_user_password"}"#;
    const GRANT: &str = r#"{"grant_id":"grant_credrot","issuer":"lab_agent","nonce":"nonce_credrot","signer_policy_epoch":"policy_3"}"#;
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();

    let state = State::new();
    let mut ledger = state.init();
    served_wp(&mut ledger, "blog1");
    drop(ledger);

    // Downgrade to v43 and confirm open fails, migrate succeeds.
    state.sql("DROP TABLE credential_rotations; PRAGMA user_version=43;");
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let mut ledger = state.migrate().unwrap();

    let mut intent = rot(1, "blog1");
    intent.plan_digest = Sha256Digest::try_from(hex(&CanonicalObject::decode(PLAN.as_bytes())
        .unwrap()
        .plan_domain_digest()))
    .unwrap();
    intent.grant_digest = Sha256Digest::try_from(hex(&Sha256::digest(GRANT.as_bytes()))).unwrap();
    ledger.stage_signed(SignedAdmission {
        plan: PLAN.as_bytes().to_vec(),
        grant: GRANT.as_bytes().to_vec(),
        issuer: id("lab_agent"),
        signer_policy_epoch: id("policy_3"),
    });
    ledger
        .record_credential_rotation(&intent, time(1000))
        .unwrap();
    ledger
        .finish_credential_rotation(&intent.operation_id, CredentialRotateState::Done)
        .unwrap();
    drop(ledger);

    // Reopen + observe succeeds.
    let reopened = state.open().unwrap();
    assert_eq!(reopened.admission_count().unwrap(), 2);
    drop(reopened);
    let observed =
        FixtureJournal::observe(&state.0, &id("host_fixture"), &id("epoch_fixture")).unwrap();
    assert!(
        observed
            .admissions
            .iter()
            .any(|row| row.operation_id == "credrot_1" && row.source == "credential_rotation")
    );

    // Tampered hostname fails open validation.
    state.sql("UPDATE credential_rotations SET hostname='evil.example.test'");
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
}
