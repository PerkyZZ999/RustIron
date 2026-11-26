//! W257 (D-021 option A, A2) frozen captures (schema v12) on real SQLite; no host effects.
use rustiron_contracts::approval::{Hostname, SiteId};
use rustiron_journal::{
    CaptureConsistency, CaptureIntent, CaptureMethod, CaptureState, FixtureJournal, JournalError,
    ProvisionIntent, ProvisionStep, UnmatchedReason,
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

const SNAPSHOT: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const DDL: &str = "CREATE TABLE capture_freeze (operation_id TEXT PRIMARY KEY REFERENCES captures(operation_id), held INTEGER CHECK(held IS NULL OR held IN (0,1))) STRICT";

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct State(PathBuf);
impl State {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ri-freeze-{}-{}",
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
    fn conn(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.0.join("fixture-journal.sqlite")).unwrap()
    }
    fn sql(&self, sql: &str) {
        self.conn().execute_batch(sql).unwrap();
    }
}
impl Drop for State {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn provisioned(ledger: &mut FixtureJournal, site: &str) {
    let intent = ProvisionIntent {
        operation_id: id(&format!("prov_{site}")),
        idempotency_key: id(&format!("prov_key_{site}")),
        grant_id: id(&format!("prov_grant_{site}")),
        nonce: id(&format!("prov_nonce_{site}")),
        plan_digest: digest('a'),
        grant_digest: digest('b'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: SiteId::try_from(site.to_owned()).unwrap(),
        hostname: Hostname::try_from(format!("{site}.example.test")).unwrap(),
        expires_at: time(10000),
    };
    ledger.record_provision(&intent, time(900)).unwrap();
    for step in ProvisionStep::ALL {
        ledger.begin_step(&intent.operation_id, step, "r").unwrap();
        ledger
            .finish_step(&intent.operation_id, step, true)
            .unwrap();
    }
}

fn started(ledger: &mut FixtureJournal, n: u32) -> CaptureIntent {
    let intent = CaptureIntent {
        operation_id: id(&format!("cap_{n}")),
        idempotency_key: id(&format!("cap_key_{n}")),
        grant_id: id(&format!("cap_grant_{n}")),
        nonce: id(&format!("cap_nonce_{n}")),
        plan_digest: digest('c'),
        grant_digest: digest('d'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: SiteId::try_from("blog9".to_owned()).unwrap(),
        expires_at: time(10000),
    };
    ledger
        .record_capture(
            &intent,
            time(1000),
            CaptureMethod::SiteFilesDbV1,
            None,
            &digest('e'),
        )
        .unwrap();
    intent
}

fn finish(
    ledger: &mut FixtureJournal,
    intent: &CaptureIntent,
    snapshot: Option<&str>,
    label: Option<&CaptureConsistency>,
) -> Result<rustiron_journal::Capture, JournalError> {
    ledger.finish_capture_labelled(
        &intent.operation_id,
        snapshot,
        time(1001),
        None,
        None,
        label,
    )
}

fn frozen(ledger: &mut FixtureJournal, n: u32) -> CaptureIntent {
    let intent = CaptureIntent {
        operation_id: id(&format!("fz_{n}")),
        idempotency_key: id(&format!("fz_key_{n}")),
        grant_id: id(&format!("fz_grant_{n}")),
        nonce: id(&format!("fz_nonce_{n}")),
        plan_digest: digest('c'),
        grant_digest: digest('d'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: SiteId::try_from("blog9".to_owned()).unwrap(),
        expires_at: time(10000),
    };
    ledger
        .record_capture(
            &intent,
            time(1000),
            CaptureMethod::SiteFilesDbFrozenV1,
            None,
            &digest('e'),
        )
        .unwrap();
    intent
}

fn held(state: &State, op: &str) -> Option<Option<i64>> {
    state
        .conn()
        .query_row(
            "SELECT held FROM capture_freeze WHERE operation_id=?1",
            [op],
            |r| r.get(0),
        )
        .ok()
}

#[test]
fn a_fresh_journal_has_the_exact_v12_freeze_table() {
    let state = State::new();
    drop(state.init());
    let c = state.conn();
    let version: i64 = c
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(version, 44);
    let sql: String = c
        .query_row(
            "SELECT sql FROM sqlite_master WHERE name='capture_freeze'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(sql, DDL);
}

#[test]
fn a_frozen_capture_records_its_method_and_a_held_label_round_trips() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let a = frozen(&mut ledger, 1);
    let running = ledger.capture_status(&a.operation_id).unwrap().unwrap();
    assert_eq!(running.method, Some(CaptureMethod::SiteFilesDbFrozenV1));
    assert_eq!(held(&state, "fz_1"), Some(None));
    let done = finish(
        &mut ledger,
        &a,
        Some(SNAPSHOT),
        Some(&CaptureConsistency::Matched),
    )
    .unwrap();
    assert_eq!(done.method, Some(CaptureMethod::SiteFilesDbFrozenV1));
    assert_eq!(done.consistency, Some(CaptureConsistency::Matched));
    assert_eq!(held(&state, "fz_1"), Some(Some(1)));
    let b = frozen(&mut ledger, 2);
    let changed = CaptureConsistency::Unmatched(UnmatchedReason::DatabaseChanged);
    let done = finish(&mut ledger, &b, Some(SNAPSHOT), Some(&changed)).unwrap();
    assert_eq!(done.consistency, Some(changed));
    assert_eq!(held(&state, "fz_2"), Some(Some(1)));
    drop(ledger);
    let reopened = state.open().unwrap();
    assert_eq!(
        reopened
            .capture_status(&b.operation_id)
            .unwrap()
            .unwrap()
            .consistency,
        Some(changed)
    );
}

#[test]
fn a_freeze_that_did_not_hold_reads_as_freeze_not_held() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let a = frozen(&mut ledger, 1);
    let label = CaptureConsistency::Unmatched(UnmatchedReason::FreezeNotHeld);
    assert_eq!(label.label(), "unmatched");
    assert_eq!(label.reason(), Some("freeze_not_held"));
    let done = finish(&mut ledger, &a, Some(SNAPSHOT), Some(&label)).unwrap();
    assert_eq!(done.state, CaptureState::Succeeded);
    assert_eq!(done.consistency, Some(label));
    assert_eq!(held(&state, "fz_1"), Some(Some(0)));
    let rows: i64 = state
        .conn()
        .query_row("SELECT count(*) FROM capture_consistency", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 0);
    drop(ledger);
    assert_eq!(
        state
            .open()
            .unwrap()
            .capture_status(&a.operation_id)
            .unwrap()
            .unwrap()
            .consistency,
        Some(label)
    );
}

#[test]
fn freeze_labels_are_refused_where_they_do_not_belong() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let plain = started(&mut ledger, 1);
    let not_held = CaptureConsistency::Unmatched(UnmatchedReason::FreezeNotHeld);
    assert_eq!(
        finish(&mut ledger, &plain, Some(SNAPSHOT), Some(&not_held)).err(),
        Some(JournalError::Conflict)
    );
    finish(&mut ledger, &plain, None, None).unwrap();
    let a = frozen(&mut ledger, 2);
    // A succeeded frozen capture must say whether the freeze held.
    assert_eq!(
        finish(&mut ledger, &a, Some(SNAPSHOT), None).err(),
        Some(JournalError::Conflict)
    );
    // A failed frozen capture carries no freeze verdict.
    let failed = finish(&mut ledger, &a, None, None).unwrap();
    assert_eq!(failed.method, Some(CaptureMethod::SiteFilesDbFrozenV1));
    assert_eq!(failed.consistency, None);
    assert_eq!(held(&state, "fz_2"), Some(None));
}

#[test]
fn contradictory_freeze_rows_make_the_journal_unavailable() {
    for tamper in [
        "UPDATE capture_freeze SET held=0",
        "INSERT INTO capture_methods VALUES('fz_1','site_files_db_v1')",
        "UPDATE capture_freeze SET held=1 WHERE operation_id='fz_2'",
        "PRAGMA foreign_keys=OFF; INSERT INTO capture_freeze VALUES('cap_9',NULL)",
        "DELETE FROM capture_consistency",
    ] {
        let state = State::new();
        let mut ledger = state.init();
        provisioned(&mut ledger, "blog9");
        let a = frozen(&mut ledger, 1);
        finish(
            &mut ledger,
            &a,
            Some(SNAPSHOT),
            Some(&CaptureConsistency::Matched),
        )
        .unwrap();
        let _running = frozen(&mut ledger, 2);
        drop(ledger);
        state.open().unwrap();
        state.sql(tamper);
        assert_eq!(
            state.open().err(),
            Some(JournalError::Unavailable),
            "{tamper}"
        );
    }
}

#[test]
fn a_v11_journal_migrates_to_v13_with_captures_unchanged() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let intent = started(&mut ledger, 1);
    let mut before = finish(
        &mut ledger,
        &intent,
        Some(SNAPSHOT),
        Some(&CaptureConsistency::Matched),
    )
    .unwrap();
    before.backup_policy_digest = None;
    drop(ledger);
    state.sql(&format!("{TO_V16} DROP TABLE page_cache_optouts; DROP TABLE page_cache_optins; DROP TABLE capture_unclaimed; DROP TABLE capture_backup_policy; DROP TABLE probe_backup_policy; DROP TABLE capture_freeze; PRAGMA user_version=11;"));
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let migrated =
        FixtureJournal::migrate(&state.0, id("host_fixture"), id("epoch_fixture")).unwrap();
    assert_eq!(
        migrated
            .capture_status(&intent.operation_id)
            .unwrap()
            .unwrap(),
        before
    );
    drop(migrated);
    assert!(FixtureJournal::migrate(&state.0, id("host_fixture"), id("epoch_fixture")).is_err());
}

/// W261: operator reconcile of an interrupted capture cannot know whether a
/// freeze held, so a frozen capture found in the repository reads
/// `freeze_not_held` (never matched, never stuck `running`); an unfrozen one
/// keeps no label; nothing found is `failed` with no freeze verdict.
#[test]
fn a_reconciled_frozen_capture_reads_freeze_not_held_and_never_stays_running() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let a = frozen(&mut ledger, 1);
    let done = ledger
        .reconcile_finish_capture(&a.operation_id, Some(SNAPSHOT), time(1001))
        .unwrap();
    assert_eq!(done.state, CaptureState::Succeeded);
    assert_eq!(
        done.consistency,
        Some(CaptureConsistency::Unmatched(
            UnmatchedReason::FreezeNotHeld
        ))
    );
    assert_eq!(held(&state, "fz_1"), Some(Some(0)));
    let b = frozen(&mut ledger, 2);
    let gone = ledger
        .reconcile_finish_capture(&b.operation_id, None, time(1001))
        .unwrap();
    assert_eq!(gone.state, CaptureState::Failed);
    assert_eq!(held(&state, "fz_2"), Some(None));
    let c = started(&mut ledger, 3);
    let plain = ledger
        .reconcile_finish_capture(&c.operation_id, Some(SNAPSHOT), time(1001))
        .unwrap();
    assert_eq!(plain.state, CaptureState::Succeeded);
    assert_eq!(plain.consistency, None);
    drop(ledger);
    assert!(
        state.open().is_ok(),
        "the reconciled journal stays consistent"
    );
}

/// W379: a frozen capture whose freeze did not hold is observed as
/// `unmatched` with reason `freeze_not_held`, as the capture status reads it.
#[test]
fn the_observation_reads_a_freeze_that_did_not_hold() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let a = frozen(&mut ledger, 1);
    let label = CaptureConsistency::Unmatched(UnmatchedReason::FreezeNotHeld);
    finish(&mut ledger, &a, Some(SNAPSHOT), Some(&label)).unwrap();
    drop(ledger);
    let seen =
        FixtureJournal::observe(&state.0, &id("host_fixture"), &id("epoch_fixture")).unwrap();
    assert_eq!(
        seen.captures[0].consistency,
        Some(("unmatched".to_owned(), Some("freeze_not_held".to_owned())))
    );
}
