//! W508 (journal v31, D-080): the signed retirement of a quarantined site.
//! Real SQLite; no host effects.
use rustiron_contracts::approval::{Hostname, SiteId};
use rustiron_journal::{
    FixtureJournal, JournalError, ProvisionIntent, ProvisionStep, RetireIntent, RetireResult,
    StepState,
};
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

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct State(PathBuf);
impl State {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ri-retire-{}-{}",
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

fn site(name: &str) -> ProvisionIntent {
    ProvisionIntent {
        operation_id: id(&format!("prov_{name}")),
        idempotency_key: id(&format!("prov_key_{name}")),
        grant_id: id(&format!("prov_grant_{name}")),
        nonce: id(&format!("prov_nonce_{name}")),
        plan_digest: digest('a'),
        grant_digest: digest('b'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: SiteId::try_from(name.to_owned()).unwrap(),
        hostname: Hostname::try_from(format!("{name}.example.test")).unwrap(),
        expires_at: time(10000),
    }
}

/// A provision whose Account step is done and whose Directories step failed.
fn quarantined(ledger: &mut FixtureJournal, name: &str) -> ProvisionIntent {
    let intent = site(name);
    ledger.record_provision(&intent, time(900)).unwrap();
    let op = &intent.operation_id;
    ledger.begin_step(op, ProvisionStep::Account, "a").unwrap();
    ledger
        .finish_step(op, ProvisionStep::Account, true)
        .unwrap();
    ledger
        .begin_step(op, ProvisionStep::Directories, "d")
        .unwrap();
    ledger
        .finish_step(op, ProvisionStep::Directories, false)
        .unwrap();
    intent
}

fn retire(n: u32, provision: &ProvisionIntent) -> RetireIntent {
    RetireIntent {
        operation_id: id(&format!("retire_{n}")),
        idempotency_key: id(&format!("retire_key_{n}")),
        grant_id: id(&format!("retire_grant_{n}")),
        nonce: id(&format!("retire_nonce_{n}")),
        plan_digest: digest('c'),
        grant_digest: digest('d'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        provision_operation_id: provision.operation_id.clone(),
        site_id: provision.site_id.clone(),
        expires_at: time(10000),
    }
}

#[test]
fn a_quarantined_provision_takes_one_retirement_that_replays_exactly() {
    let state = State::new();
    let mut ledger = state.init();
    let failed = quarantined(&mut ledger, "blog1");
    let before = ledger.admission_count().unwrap();
    let intent = retire(1, &failed);
    let RetireResult::New(row) = ledger.record_retirement(&intent, time(1000)).unwrap() else {
        panic!("expected a new retirement");
    };
    assert_eq!(row.state, StepState::Intent);
    assert_eq!(ledger.admission_count().unwrap(), before + 1);
    assert!(matches!(
        ledger.record_retirement(&intent, time(1001)),
        Ok(RetireResult::Existing(_))
    ));
    // The same key with another provision is a conflict; a second
    // retirement of the provision reserves nothing.
    let mut other = intent.clone();
    other.plan_digest = digest('e');
    assert_eq!(
        ledger.record_retirement(&other, time(1002)).err(),
        Some(JournalError::Conflict)
    );
    assert_eq!(
        ledger
            .record_retirement(&retire(2, &failed), time(1002))
            .err(),
        Some(JournalError::Consumed)
    );
    // A failed retirement may be retried by a new signed request.
    ledger
        .finish_retirement(&intent.operation_id, false)
        .unwrap();
    let retry = retire(3, &failed);
    ledger.record_retirement(&retry, time(1003)).unwrap();
    assert_eq!(
        ledger
            .record_retirement(&retire(4, &failed), time(1004))
            .err(),
        Some(JournalError::Consumed)
    );
    let done = ledger.finish_retirement(&retry.operation_id, true).unwrap();
    assert_eq!(done.state, StepState::Done);
    assert_eq!(
        ledger.finish_retirement(&retry.operation_id, false).err(),
        Some(JournalError::Conflict)
    );
    assert_eq!(
        ledger
            .retirement_status(&intent.operation_id)
            .unwrap()
            .unwrap()
            .state,
        StepState::Failed
    );
    drop(ledger);
    let ledger = state.open().unwrap();
    assert_eq!(
        ledger
            .retirement_of_provision(&failed.operation_id)
            .unwrap()
            .unwrap()
            .state,
        StepState::Done
    );
    // The names stay consumed.
    assert_eq!(
        ledger
            .provision_status(&failed.operation_id)
            .unwrap()
            .unwrap()
            .intent
            .site_id
            .as_str(),
        "blog1"
    );
}

#[test]
fn only_a_quarantined_provision_of_the_signed_site_is_retired() {
    let state = State::new();
    let mut ledger = state.init();
    let running = site("blog2");
    ledger.record_provision(&running, time(900)).unwrap();
    assert_eq!(
        ledger
            .record_retirement(&retire(1, &running), time(1000))
            .err(),
        Some(JournalError::Consumed)
    );
    ledger.quarantine_provision(&running.operation_id).unwrap();
    let mut wrong_site = retire(2, &running);
    wrong_site.site_id = SiteId::try_from("blog3".to_owned()).unwrap();
    assert_eq!(
        ledger.record_retirement(&wrong_site, time(1000)).err(),
        Some(JournalError::Consumed)
    );
    let mut missing = retire(3, &running);
    missing.provision_operation_id = id("prov_none");
    assert_eq!(
        ledger.record_retirement(&missing, time(1000)).err(),
        Some(JournalError::Consumed)
    );
    ledger
        .record_retirement(&retire(4, &running), time(1000))
        .unwrap();
}

#[test]
fn a_v30_journal_migrates_to_v31_and_a_retired_served_site_is_refused() {
    let state = State::new();
    let mut ledger = state.init();
    let failed = quarantined(&mut ledger, "blog4");
    drop(ledger);
    state.sql("PRAGMA foreign_keys=OFF; DROP TABLE caddy_generations; DROP TABLE app_fullstack_specs; DROP TABLE credential_rotations; DROP TABLE app_lifecycles; DROP TABLE app_release_steps; DROP TABLE app_releases; DROP TABLE apps; DROP TABLE static_ejections; DROP TABLE proxy_routes; DROP TABLE dns_change_sets; DROP TABLE dns_changes; DROP TABLE dns_imports; DROP TABLE restore_steps; DROP TABLE restore_attempts; DROP TABLE site_restores; DROP TABLE clone_scrub_grants; DROP TABLE quota_changes; DROP TABLE deletions; CREATE TEMP TABLE p32 AS SELECT * FROM provisions; DROP TABLE provisions; CREATE TABLE provisions (operation_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL, grant_digest TEXT NOT NULL, host_id TEXT NOT NULL, host_epoch TEXT NOT NULL, site_id TEXT NOT NULL UNIQUE, hostname TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('running','succeeded','quarantined','adopted'))) STRICT; INSERT INTO provisions SELECT * FROM temp.p32; DROP TABLE temp.p32; CREATE UNIQUE INDEX one_running_provision ON provisions((1)) WHERE state='running'; DROP TABLE update_rollbacks; DROP TABLE update_steps; DROP TABLE update_components; DROP INDEX one_open_update; DROP TABLE updates; DROP INDEX one_retirement; DROP TABLE retirements; PRAGMA user_version=30;");
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let mut ledger = state.migrate().unwrap();
    ledger
        .record_retirement(&retire(1, &failed), time(1000))
        .unwrap();
    drop(ledger);
    state.sql("UPDATE provisions SET state='succeeded' WHERE operation_id='prov_blog4'");
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
}

/// W508 finding: a journal that holds a signed retirement must open again.
/// The signed admission's link row needs its intent in the signed intents.
#[test]
fn a_signed_retirement_keeps_the_journal_openable_and_observed() {
    use rustiron_contracts::{CanonicalObject, approval::Sha256Digest};
    use rustiron_journal::SignedAdmission;
    use sha2::{Digest, Sha256};
    const PLAN: &str = r#"{"plan_id":"plan_retire","schema_version":1,"site_id":"blog5"}"#;
    const GRANT: &str = r#"{"grant_id":"grant_retire","issuer":"lab_agent","nonce":"nonce_retire","signer_policy_epoch":"policy_3"}"#;
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let state = State::new();
    let mut ledger = state.init();
    let failed = quarantined(&mut ledger, "blog5");
    let mut intent = retire(1, &failed);
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
    ledger.record_retirement(&intent, time(1000)).unwrap();
    drop(ledger);
    let ledger = state.open().unwrap();
    assert!(
        ledger
            .retirement_status(&intent.operation_id)
            .unwrap()
            .is_some()
    );
    let observed =
        FixtureJournal::observe(&state.0, &id("host_fixture"), &id("epoch_fixture")).unwrap();
    assert!(
        observed
            .admissions
            .iter()
            .any(|admission| admission.operation_id == intent.operation_id.as_str())
    );
}
