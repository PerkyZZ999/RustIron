//! W542 (journal v37, D-089): a signed restore of a live site from its own
//! capture. Its intent rechecks the site and both captures in one
//! transaction; its attempts and steps are recorded before and after each
//! effect, and an open restore holds back the site's other verbs. Real
//! SQLite; no host effects.
use rustiron_contracts::approval::{
    ComponentSlug, ComponentVersion, Hostname, RestoreScope, SiteId, SnapshotId, UpdateComponent,
    UpdateKind,
};
use rustiron_journal::{
    CaptureConsistency, CaptureIntent, CaptureManifest, CaptureMethod, DeleteIntent,
    FixtureJournal, JournalError, MAX_RESTORE_ATTEMPTS, ProvisionIntent, ProvisionStep,
    QuotaChangeIntent, RestoreFrom, RestoreIntent, RestoreResult, RestoreState, RestoreStep,
    SiteRestore, StepState, UpdateIntent,
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

const OLD_SNAPSHOT: &str = "89f5ad054604acf1033adc33725d0a96c5b609225525bda3bff495d4cc61f3ad";
const NEW_SNAPSHOT: &str = "1cf67916aa0b5c3e5d1f9b8e7c6d5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d674b";
/// The safety capture finishes at 5001.
const NOW: u64 = 5100;

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct State(PathBuf);
impl State {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ri-restore-{}-{}",
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

/// A served site whose every provision step is done.
fn served(ledger: &mut FixtureJournal, name: &str) {
    let intent = ProvisionIntent {
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
        expires_at: time(200_000),
    };
    ledger.record_provision(&intent, time(900)).unwrap();
    for step in ProvisionStep::ALL {
        ledger.begin_step(&intent.operation_id, step, "r").unwrap();
        ledger
            .finish_step(&intent.operation_id, step, true)
            .unwrap();
    }
}

fn capture_intent(name: &str, operation: &str) -> CaptureIntent {
    CaptureIntent {
        operation_id: id(operation),
        idempotency_key: id(&format!("{operation}_key")),
        grant_id: id(&format!("{operation}_grant")),
        nonce: id(&format!("{operation}_nonce")),
        plan_digest: digest('c'),
        grant_digest: digest('d'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: site_id(name),
        expires_at: time(200_000),
    }
}

/// A capture of the site started at `at` and succeeded one second later,
/// with `snapshot` and a manifest of `manifest` characters.
fn capture(
    ledger: &mut FixtureJournal,
    name: &str,
    operation: &str,
    at: u64,
    snapshot: &str,
    manifest: char,
    truncated: bool,
) {
    let intent = capture_intent(name, operation);
    ledger
        .record_capture(
            &intent,
            time(at),
            CaptureMethod::SiteFilesDbV1,
            None,
            &digest('e'),
        )
        .unwrap();
    ledger
        .finish_capture_labelled(
            &intent.operation_id,
            Some(snapshot),
            time(at + 1),
            None,
            Some(&CaptureManifest {
                sha256: manifest.to_string().repeat(64),
                entries: 2,
                regular_bytes: 16,
                truncated,
            }),
            Some(&CaptureConsistency::Matched),
        )
        .unwrap();
}

/// A served `blog1` with an older capture `cap_old` and the safety capture
/// `cap_safe`, finished at 1001 and 5001.
fn site_with_captures(ledger: &mut FixtureJournal, truncated: bool) {
    served(ledger, "blog1");
    capture(
        ledger,
        "blog1",
        "cap_old",
        1000,
        OLD_SNAPSHOT,
        '1',
        truncated,
    );
    capture(ledger, "blog1", "cap_safe", 5000, NEW_SNAPSHOT, '2', false);
}

fn restore(n: u32, scope: RestoreScope) -> RestoreIntent {
    RestoreIntent {
        operation_id: id(&format!("restore_{n}")),
        idempotency_key: id(&format!("restore_key_{n}")),
        grant_id: id(&format!("restore_grant_{n}")),
        nonce: id(&format!("restore_nonce_{n}")),
        plan_digest: digest('a'),
        grant_digest: digest('b'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: site_id("blog1"),
        hostname: hostname("blog1"),
        scope,
        capture_operation_id: id("cap_old"),
        snapshot_id: SnapshotId::try_from(OLD_SNAPSHOT.to_owned()).unwrap(),
        manifest_sha256: digest('1'),
        safety_capture_operation_id: id("cap_safe"),
        expires_at: time(200_000),
    }
}

fn new_restore(result: RestoreResult) -> SiteRestore {
    match result {
        RestoreResult::New(restore) => restore,
        RestoreResult::Existing(_) => panic!("expected a new restore"),
    }
}

fn run_steps(ledger: &mut FixtureJournal, op: &rustiron_contracts::Id, scope: RestoreScope) {
    for step in RestoreStep::sequence(scope) {
        ledger.begin_restore_step(op, *step).unwrap();
        ledger.finish_restore_step(op, *step, true).unwrap();
    }
}

#[test]
fn a_restore_records_its_first_attempt_and_replays_exactly() {
    let state = State::new();
    let mut ledger = state.init();
    site_with_captures(&mut ledger, false);
    let before = ledger.admission_count().unwrap();
    let intent = restore(1, RestoreScope::FilesAndDatabase);
    let recorded = new_restore(ledger.record_site_restore(&intent, time(NOW)).unwrap());
    assert_eq!(recorded.state, RestoreState::Intent);
    assert_eq!(recorded.scope, RestoreScope::FilesAndDatabase);
    assert_eq!(recorded.attempts.len(), 1);
    let first = recorded.current().unwrap();
    assert_eq!(
        (first.from, first.state, first.steps.len()),
        (RestoreFrom::Signed, StepState::Intent, 0)
    );
    assert_eq!(ledger.admission_count().unwrap(), before + 1);
    assert!(matches!(
        ledger.record_site_restore(&intent, time(NOW + 1)),
        Ok(RestoreResult::Existing(_))
    ));
    // The same key with another scope is a conflict.
    let mut other = intent.clone();
    other.scope = RestoreScope::Database;
    assert_eq!(
        ledger.record_site_restore(&other, time(NOW + 1)).err(),
        Some(JournalError::Conflict)
    );
    // A new operation reusing the consumed nonce is a conflict.
    let mut reused = restore(2, RestoreScope::Database);
    reused.nonce = intent.nonce.clone();
    assert_eq!(
        ledger.record_site_restore(&reused, time(NOW + 1)).err(),
        Some(JournalError::Conflict)
    );
    // A second restore of the site waits for the open one.
    assert_eq!(
        ledger
            .record_site_restore(&restore(3, RestoreScope::Database), time(NOW + 1))
            .err(),
        Some(JournalError::SourceChanged)
    );
    assert_eq!(ledger.admission_count().unwrap(), before + 1);
    drop(ledger);
    let ledger = state.open().unwrap();
    assert_eq!(
        ledger.site_restore_status(&intent.operation_id).unwrap(),
        Some(recorded)
    );
}

#[test]
fn each_basis_check_refuses_before_intent() {
    let state = State::new();
    let mut ledger = state.init();
    site_with_captures(&mut ledger, true);
    let before = ledger.admission_count().unwrap();
    let refused = |ledger: &mut FixtureJournal, intent: RestoreIntent, now: u64| {
        assert!(!ledger.site_restore_basis_holds(&intent, time(now)).unwrap());
        assert_eq!(
            ledger.record_site_restore(&intent, time(now)).err(),
            Some(JournalError::SourceChanged)
        );
    };
    let base = || restore(1, RestoreScope::Database);
    let mut wrong = base();
    wrong.hostname = hostname("other");
    refused(&mut ledger, wrong, NOW);
    let mut wrong = base();
    wrong.snapshot_id = SnapshotId::try_from(NEW_SNAPSHOT.to_owned()).unwrap();
    refused(&mut ledger, wrong, NOW);
    let mut wrong = base();
    wrong.manifest_sha256 = digest('2');
    refused(&mut ledger, wrong, NOW);
    // The capture to restore must be older than the safety capture.
    let mut wrong = base();
    wrong.capture_operation_id = id("cap_safe");
    wrong.safety_capture_operation_id = id("cap_old");
    refused(&mut ledger, wrong, NOW);
    let mut wrong = base();
    wrong.safety_capture_operation_id = id("cap_missing");
    refused(&mut ledger, wrong, NOW);
    // A files restore needs the whole manifest; `cap_old`'s is truncated.
    refused(&mut ledger, restore(1, RestoreScope::FilesAndDatabase), NOW);
    // The safety capture is at most 24 hours old.
    refused(&mut ledger, base(), 5001 + 24 * 3600 + 1);
    assert!(
        ledger
            .site_restore_basis_holds(&base(), time(5001 + 24 * 3600))
            .unwrap()
    );
    // A newer capture means the safety capture is no longer the newest.
    capture(
        &mut ledger,
        "blog1",
        "cap_newer",
        6000,
        NEW_SNAPSHOT,
        '3',
        false,
    );
    refused(&mut ledger, base(), 6100);
    // A running capture of the site is refused.
    let mut fresh = base();
    fresh.safety_capture_operation_id = id("cap_newer");
    assert!(ledger.site_restore_basis_holds(&fresh, time(6100)).unwrap());
    ledger
        .record_capture(
            &capture_intent("blog1", "cap_running"),
            time(6200),
            CaptureMethod::SiteFilesDbV1,
            None,
            &digest('e'),
        )
        .unwrap();
    refused(&mut ledger, fresh.clone(), 6300);
    let before_running = before + 2;
    assert_eq!(ledger.admission_count().unwrap(), before_running);
    // An expired grant records nothing.
    ledger
        .finish_capture(&id("cap_running"), None, time(6301), None, None)
        .unwrap();
    fresh.expires_at = time(6400);
    assert_eq!(
        ledger.record_site_restore(&fresh, time(6400)).err(),
        Some(JournalError::Expired)
    );
    assert_eq!(ledger.admission_count().unwrap(), before_running);
}

#[test]
fn steps_follow_the_scope_and_the_health_step_finishes_the_restore() {
    let state = State::new();
    let mut ledger = state.init();
    site_with_captures(&mut ledger, false);
    let intent = restore(1, RestoreScope::Database);
    ledger.record_site_restore(&intent, time(NOW)).unwrap();
    let op = &intent.operation_id;
    // Steps run in order; a database restore has no Files step.
    assert_eq!(
        ledger.begin_restore_step(op, RestoreStep::Fetch).err(),
        Some(JournalError::Conflict)
    );
    for step in [
        RestoreStep::Maintenance,
        RestoreStep::Fetch,
        RestoreStep::Database,
    ] {
        ledger.begin_restore_step(op, step).unwrap();
        // The open step must finish before the next begins.
        assert_eq!(
            ledger.begin_restore_step(op, RestoreStep::Reopen).err(),
            Some(JournalError::Conflict)
        );
        ledger.finish_restore_step(op, step, true).unwrap();
    }
    assert_eq!(
        ledger.begin_restore_step(op, RestoreStep::Files).err(),
        Some(JournalError::Conflict)
    );
    for step in [RestoreStep::Reopen, RestoreStep::Health] {
        ledger.begin_restore_step(op, step).unwrap();
        ledger.finish_restore_step(op, step, true).unwrap();
    }
    let done = ledger.site_restore_status(op).unwrap().unwrap();
    assert_eq!(done.state, RestoreState::Done);
    assert_eq!(done.current().unwrap().state, StepState::Done);
    assert_eq!(done.current().unwrap().steps.len(), 5);
    // A finished restore takes no further step or attempt.
    assert_eq!(
        ledger.begin_restore_attempt(op, RestoreFrom::Safety).err(),
        Some(JournalError::Conflict)
    );
    // The site's other verbs are free again.
    capture(
        &mut ledger,
        "blog1",
        "cap_after",
        5200,
        NEW_SNAPSHOT,
        '4',
        false,
    );
    drop(ledger);
    state.open().unwrap();
}

#[test]
fn a_failed_step_holds_the_site_until_the_safety_capture_reverts_it() {
    let state = State::new();
    let mut ledger = state.init();
    site_with_captures(&mut ledger, false);
    let intent = restore(1, RestoreScope::FilesAndDatabase);
    ledger.record_site_restore(&intent, time(NOW)).unwrap();
    let op = &intent.operation_id;
    for step in [RestoreStep::Maintenance, RestoreStep::Fetch] {
        ledger.begin_restore_step(op, step).unwrap();
        ledger.finish_restore_step(op, step, true).unwrap();
    }
    ledger
        .begin_restore_step(op, RestoreStep::Database)
        .unwrap();
    let failed = ledger
        .finish_restore_step(op, RestoreStep::Database, false)
        .unwrap();
    assert_eq!(failed.state, RestoreState::Intent);
    assert_eq!(failed.current().unwrap().state, StepState::Failed);
    assert_eq!(
        ledger.begin_restore_step(op, RestoreStep::Files).err(),
        Some(JournalError::Conflict)
    );
    // The open restore holds back the site's other verbs.
    assert_eq!(
        ledger
            .record_capture(
                &capture_intent("blog1", "cap_blocked"),
                time(NOW + 10),
                CaptureMethod::SiteFilesDbV1,
                None,
                &digest('e'),
            )
            .err(),
        Some(JournalError::Busy)
    );
    let update = UpdateIntent {
        operation_id: id("update_1"),
        idempotency_key: id("update_key_1"),
        grant_id: id("update_grant_1"),
        nonce: id("update_nonce_1"),
        plan_digest: digest('a'),
        grant_digest: digest('b'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: site_id("blog1"),
        capture_operation_id: id("cap_safe"),
        recipe_digest: digest('9'),
        components: vec![UpdateComponent {
            kind: UpdateKind::Plugin,
            slug: ComponentSlug::try_from("hello-dolly".to_owned()).unwrap(),
            from_version: ComponentVersion::try_from("1.7.1".to_owned()).unwrap(),
            to_version: ComponentVersion::try_from("1.7.2".to_owned()).unwrap(),
        }],
        expires_at: time(200_000),
    };
    assert_eq!(
        ledger.record_update(&update, time(NOW + 10)).err(),
        Some(JournalError::Busy)
    );
    assert!(!ledger.update_basis_holds(&update, time(NOW + 10)).unwrap());
    let quota = QuotaChangeIntent {
        operation_id: id("quota_1"),
        idempotency_key: id("quota_key_1"),
        grant_id: id("quota_grant_1"),
        nonce: id("quota_nonce_1"),
        plan_digest: digest('a'),
        grant_digest: digest('b'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: site_id("blog1"),
        block_hard_kib: 1_048_576,
        inode_hard: 100_000,
        expires_at: time(200_000),
    };
    assert_eq!(
        ledger.record_quota_change(&quota, time(NOW + 10)).err(),
        Some(JournalError::Consumed)
    );
    let delete = DeleteIntent {
        operation_id: id("delete_1"),
        idempotency_key: id("delete_key_1"),
        grant_id: id("delete_grant_1"),
        nonce: id("delete_nonce_1"),
        plan_digest: digest('a'),
        grant_digest: digest('b'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: site_id("blog1"),
        hostname: hostname("blog1"),
        capture_operation_id: Some(id("cap_safe")),
        expires_at: time(200_000),
    };
    assert_eq!(
        ledger.record_deletion(&delete, time(NOW + 10)).err(),
        Some(JournalError::Consumed)
    );
    // The operator restores the safety capture.
    let second = ledger
        .begin_restore_attempt(op, RestoreFrom::Safety)
        .unwrap();
    assert_eq!(second.attempts.len(), 2);
    assert_eq!(second.capture_of(RestoreFrom::Safety), &id("cap_safe"));
    assert_eq!(
        ledger.begin_restore_attempt(op, RestoreFrom::Signed).err(),
        Some(JournalError::Conflict)
    );
    run_steps(&mut ledger, op, RestoreScope::FilesAndDatabase);
    let reverted = ledger.site_restore_status(op).unwrap().unwrap();
    assert_eq!(reverted.state, RestoreState::Reverted);
    assert_eq!(reverted.attempts[0].state, StepState::Failed);
    assert_eq!(reverted.attempts[1].steps.len(), 6);
    assert!(ledger.record_quota_change(&quota, time(NOW + 20)).is_ok());
    drop(ledger);
    state.open().unwrap();
}

#[test]
fn an_interrupted_attempt_is_settled_failed_and_attempts_are_bounded() {
    let state = State::new();
    let mut ledger = state.init();
    site_with_captures(&mut ledger, false);
    let intent = restore(1, RestoreScope::Database);
    ledger.record_site_restore(&intent, time(NOW)).unwrap();
    let op = &intent.operation_id;
    // An open attempt takes no new attempt.
    assert_eq!(
        ledger.begin_restore_attempt(op, RestoreFrom::Signed).err(),
        Some(JournalError::Conflict)
    );
    ledger
        .begin_restore_step(op, RestoreStep::Maintenance)
        .unwrap();
    let settled = ledger.settle_restore_attempt(op).unwrap();
    let first = settled.current().unwrap();
    assert_eq!(first.state, StepState::Failed);
    assert_eq!(first.steps[0].state, StepState::Failed);
    assert_eq!(
        ledger.settle_restore_attempt(op).err(),
        Some(JournalError::Conflict)
    );
    for _ in 1..MAX_RESTORE_ATTEMPTS {
        ledger
            .begin_restore_attempt(op, RestoreFrom::Signed)
            .unwrap();
        // Settled between steps: no step is open, nothing is claimed done.
        ledger.settle_restore_attempt(op).unwrap();
    }
    assert_eq!(
        ledger.begin_restore_attempt(op, RestoreFrom::Safety).err(),
        Some(JournalError::Capacity)
    );
    let held = ledger.site_restore_status(op).unwrap().unwrap();
    assert_eq!(held.attempts.len(), MAX_RESTORE_ATTEMPTS);
    assert_eq!(held.state, RestoreState::Intent);
    drop(ledger);
    state.open().unwrap();
}

#[test]
fn a_v36_journal_migrates_and_an_inconsistent_restore_is_refused() {
    let state = State::new();
    let mut ledger = state.init();
    site_with_captures(&mut ledger, false);
    drop(ledger);
    state.sql(&format!("DROP TABLE caddy_generations; DROP TABLE app_fullstack_specs; DROP TABLE credential_rotations; DROP TABLE app_lifecycles; DROP TABLE app_release_steps; DROP TABLE app_releases; DROP TABLE apps; DROP TABLE static_ejections; DROP TABLE proxy_routes; DROP TABLE dns_change_sets; DROP TABLE dns_changes; DROP TABLE dns_imports; DROP TABLE restore_steps; DROP TABLE restore_attempts; DROP TABLE site_restores; {TO_V40_DELETIONS} PRAGMA user_version=36;"));
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let mut ledger = state.migrate().unwrap();
    let intent = restore(1, RestoreScope::Database);
    ledger.record_site_restore(&intent, time(NOW)).unwrap();
    drop(ledger);
    state.open().unwrap();
    // A restore marked done whose attempt never ran is refused on open.
    state.sql("UPDATE site_restores SET state='done' WHERE operation_id='restore_1';");
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    state.sql("UPDATE site_restores SET state='intent' WHERE operation_id='restore_1';");
    state.open().unwrap();
    // A step out of the scope's order is refused on open.
    state.sql("INSERT INTO restore_steps VALUES('restore_1',0,0,'fetch','done');");
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
}

#[test]
fn a_files_restore_needs_a_complete_safety_manifest_too() {
    let state = State::new();
    let mut ledger = state.init();
    served(&mut ledger, "blog1");
    capture(
        &mut ledger,
        "blog1",
        "cap_old",
        1000,
        OLD_SNAPSHOT,
        '1',
        false,
    );
    capture(
        &mut ledger,
        "blog1",
        "cap_safe",
        5000,
        NEW_SNAPSHOT,
        '2',
        true,
    );
    let files = restore(1, RestoreScope::FilesAndDatabase);
    assert!(!ledger.site_restore_basis_holds(&files, time(NOW)).unwrap());
    assert_eq!(
        ledger.record_site_restore(&files, time(NOW)).err(),
        Some(JournalError::SourceChanged)
    );
    // A database restore does not compare files.
    let database = restore(2, RestoreScope::Database);
    assert!(matches!(
        ledger.record_site_restore(&database, time(NOW)),
        Ok(RestoreResult::New(_))
    ));
}
