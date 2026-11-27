//! W366 (journal v14): an operator settles a capture left `running` whose
//! tagged snapshot cannot be claimed. The capture becomes `failed` and keeps
//! the snapshot ID only as unclaimed evidence. Real SQLite; no host effects.
use rustiron_contracts::approval::{Hostname, SiteId};
use rustiron_journal::{
    Admitted, CaptureIntent, CaptureMethod, CaptureState, FixtureJournal, JournalError,
    ProvisionIntent, ProvisionStep,
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
            "ri-unclaimed-{}-{}",
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
        fs::remove_dir_all(&self.0).unwrap();
    }
}

const SNAPSHOT: &str = "a50c8b74e3c0f1d2a50c8b74e3c0f1d2a50c8b74e3c0f1d2a50c8b74e3c0f1d2";
const DDL: &str = "CREATE TABLE capture_unclaimed (operation_id TEXT PRIMARY KEY REFERENCES captures(operation_id), snapshot_id TEXT NOT NULL CHECK(length(snapshot_id)=64 AND snapshot_id NOT GLOB '*[^0-9a-f]*')) STRICT";

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

fn capture(n: u32) -> CaptureIntent {
    CaptureIntent {
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
    }
}

fn running(ledger: &mut FixtureJournal, n: u32, method: CaptureMethod) -> CaptureIntent {
    let intent = capture(n);
    ledger
        .record_capture(
            &intent,
            time(1000 + u64::from(n)),
            method,
            Some(30),
            &digest('e'),
        )
        .unwrap();
    intent
}

#[test]
fn a_fresh_journal_has_the_exact_unclaimed_table() {
    let state = State::new();
    drop(state.init());
    let c = rusqlite::Connection::open(state.0.join("fixture-journal.sqlite")).unwrap();
    let version: i64 = c
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(
        version, 45,
        "W368 and W370 append the page-cache tables after v14; W372 adds re-adoption (v17); W391 adds retention evidence (v18); W395 adds the page-cache recipe (v19); W396 adds signed admission bytes (v20); W442 adds site imports (v21); W457 adds import scrubs (v22); W462 adds certificates (v23); W464 adds certificate renewals (v24); D-070 adds import sources (v25); D-074 lets an import have no dump (v26); D-075 adds import aliases (v27); D-077 adds certificate aliases (v28); D-078 adds clones (v29) and their scrubs (v30); D-080 adds retirements (v31); D-084 adds updates (v32); D-085 adds deletions and the deleted provision state (v33); D-086 admits the update kind core (v34); D-088 adds quota changes (v35); D-078 adds signed clone scrubs (v36); D-089 adds restores (v37); D-091 adds DNS imports (v38) and changes (v39); D-095 adds proxy routes (v40) and deletions without a capture (v41)"
    );
    let sql: String = c
        .query_row(
            "SELECT sql FROM sqlite_master WHERE name='capture_unclaimed'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(sql, DDL);
}

/// Lost reply after a write: the settlement records `failed`, never a
/// snapshot on the capture, keeps the tagged snapshot as unclaimed
/// evidence, survives a reopen, and frees the site for a new capture.
#[test]
fn a_settled_capture_is_failed_keeps_the_snapshot_unclaimed_and_frees_admission() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let first = running(&mut ledger, 1, CaptureMethod::SiteFilesDbV1);
    assert_eq!(
        ledger
            .record_capture(
                &capture(2),
                time(1002),
                CaptureMethod::SiteFilesDbV1,
                Some(30),
                &digest('e')
            )
            .err(),
        Some(JournalError::Busy),
        "a running capture blocks admission"
    );
    let settled = ledger
        .settle_capture_unclaimed(&first.operation_id, SNAPSHOT, time(1005))
        .unwrap();
    assert_eq!(settled.state, CaptureState::Failed);
    assert_eq!(settled.snapshot_id, None);
    assert_eq!(settled.unclaimed_snapshot_id.as_deref(), Some(SNAPSHOT));
    assert_eq!(settled.finished_at, Some(time(1005)));
    assert_eq!(settled.consistency, None);
    assert_eq!(settled.manifest, None);
    assert_eq!(settled.files, None);
    drop(ledger);
    let mut ledger = state.open().unwrap();
    assert_eq!(
        ledger.capture_status(&first.operation_id).unwrap(),
        Some(settled.clone())
    );
    // Replay: a finished capture never changes again.
    assert_eq!(
        ledger
            .settle_capture_unclaimed(&first.operation_id, SNAPSHOT, time(1006))
            .err(),
        Some(JournalError::Conflict)
    );
    assert_eq!(
        ledger
            .reconcile_finish_capture(&first.operation_id, Some(SNAPSHOT), time(1006))
            .err(),
        Some(JournalError::Conflict)
    );
    assert_eq!(
        ledger.capture_status(&first.operation_id).unwrap(),
        Some(settled)
    );
    // The original admission replays as stored status, never a new run.
    assert!(matches!(
        ledger.record_capture(&first, time(1007), CaptureMethod::SiteFilesDbV1, Some(30), &digest('e')),
        Ok(Admitted::Existing(existing)) if existing.state == CaptureState::Failed
    ));
    assert!(matches!(
        ledger.record_capture(
            &capture(2),
            time(1008),
            CaptureMethod::SiteFilesDbV1,
            Some(30),
            &digest('e')
        ),
        Ok(Admitted::New(_))
    ));
}

#[test]
fn a_frozen_capture_settles_without_a_freeze_verdict() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let intent = running(&mut ledger, 1, CaptureMethod::SiteFilesDbFrozenV1);
    let settled = ledger
        .settle_capture_unclaimed(&intent.operation_id, SNAPSHOT, time(1005))
        .unwrap();
    assert_eq!(settled.state, CaptureState::Failed);
    assert_eq!(settled.method, Some(CaptureMethod::SiteFilesDbFrozenV1));
    assert_eq!(settled.consistency, None);
    drop(ledger);
    state.open().unwrap();
}

#[test]
fn settlement_refuses_bad_ids_finished_captures_and_time_before_start() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let intent = running(&mut ledger, 1, CaptureMethod::SiteFilesDbV1);
    let operation = &intent.operation_id;
    for bad in [
        "short".to_owned(),
        SNAPSHOT.to_uppercase(),
        format!("{}g", &SNAPSHOT[..63]),
    ] {
        assert_eq!(
            ledger
                .settle_capture_unclaimed(operation, &bad, time(1005))
                .err(),
            Some(JournalError::Conflict),
            "{bad}"
        );
    }
    assert_eq!(
        ledger
            .settle_capture_unclaimed(operation, SNAPSHOT, time(999))
            .err(),
        Some(JournalError::Conflict)
    );
    assert_eq!(
        ledger
            .settle_capture_unclaimed(&id("cap_unknown"), SNAPSHOT, time(1005))
            .err(),
        Some(JournalError::Conflict)
    );
    let unchanged = ledger.capture_status(operation).unwrap().unwrap();
    assert_eq!(unchanged.state, CaptureState::Running);
    assert_eq!(unchanged.unclaimed_snapshot_id, None);
    ledger
        .finish_capture(operation, Some(SNAPSHOT), time(1005), None, None)
        .unwrap();
    assert_eq!(
        ledger
            .settle_capture_unclaimed(operation, SNAPSHOT, time(1006))
            .err(),
        Some(JournalError::Conflict),
        "a succeeded capture is never settled again"
    );
}

#[test]
fn an_unclaimed_row_that_contradicts_its_capture_is_refused_on_open() {
    for tamper in [
        // Only a failed capture may keep an unclaimed snapshot.
        "UPDATE captures SET state='succeeded', snapshot_id=(SELECT snapshot_id FROM capture_unclaimed) WHERE operation_id='cap_1'",
        "INSERT INTO capture_unclaimed VALUES ('cap_2','a50c8b74e3c0f1d2a50c8b74e3c0f1d2a50c8b74e3c0f1d2a50c8b74e3c0f1d2')",
        "INSERT INTO capture_unclaimed VALUES ('cap_3','a50c8b74e3c0f1d2a50c8b74e3c0f1d2a50c8b74e3c0f1d2a50c8b74e3c0f1d2')",
        // An orphan.
        "PRAGMA foreign_keys=OFF; INSERT INTO capture_unclaimed VALUES ('cap_9','a50c8b74e3c0f1d2a50c8b74e3c0f1d2a50c8b74e3c0f1d2a50c8b74e3c0f1d2')",
    ] {
        let state = State::new();
        let mut ledger = state.init();
        provisioned(&mut ledger, "blog9");
        let first = running(&mut ledger, 1, CaptureMethod::SiteFilesDbV1);
        ledger
            .settle_capture_unclaimed(&first.operation_id, SNAPSHOT, time(1003))
            .unwrap();
        let second = running(&mut ledger, 2, CaptureMethod::SiteFilesDbV1);
        ledger
            .finish_capture(&second.operation_id, Some(SNAPSHOT), time(1004), None, None)
            .unwrap();
        let _third = running(&mut ledger, 3, CaptureMethod::SiteFilesDbV1);
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

/// The lab journal is v13 (W301). The in-place migration appends the table
/// and keeps every capture row unchanged, the running one included.
#[test]
fn a_v13_journal_migrates_to_v14_with_captures_unchanged() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let finished = running(&mut ledger, 1, CaptureMethod::SiteFilesDbV1);
    ledger
        .finish_capture(
            &finished.operation_id,
            Some(SNAPSHOT),
            time(1003),
            Some((3, 9)),
            None,
        )
        .unwrap();
    let left = running(&mut ledger, 2, CaptureMethod::SiteFilesDbFrozenV1);
    let before: Vec<_> = [&finished, &left]
        .iter()
        .map(|i| ledger.capture_status(&i.operation_id).unwrap().unwrap())
        .collect();
    let count = ledger.admission_count().unwrap();
    drop(ledger);
    state
        .sql(&format!("{TO_V16} DROP TABLE page_cache_optouts; DROP TABLE page_cache_optins; DROP TABLE capture_unclaimed; PRAGMA user_version=13;"));
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let mut migrated =
        FixtureJournal::migrate(&state.0, id("host_fixture"), id("epoch_fixture")).unwrap();
    assert_eq!(migrated.admission_count().unwrap(), count);
    for capture in &before {
        assert_eq!(
            migrated
                .capture_status(&capture.intent.operation_id)
                .unwrap()
                .as_ref(),
            Some(capture)
        );
    }
    // The migrated running capture can now be settled.
    let settled = migrated
        .settle_capture_unclaimed(&left.operation_id, SNAPSHOT, time(1010))
        .unwrap();
    assert_eq!(settled.state, CaptureState::Failed);
    drop(migrated);
    assert!(FixtureJournal::migrate(&state.0, id("host_fixture"), id("epoch_fixture")).is_err());
}

/// W379: the read-only observation names the unclaimed snapshot of a
/// settled capture, never as its snapshot, and carries no label.
#[test]
fn the_observation_names_the_unclaimed_snapshot_only_as_unclaimed() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let first = running(&mut ledger, 1, CaptureMethod::SiteFilesDbV1);
    let seen =
        FixtureJournal::observe(&state.0, &id("host_fixture"), &id("epoch_fixture")).unwrap();
    assert_eq!(seen.captures[0].state, "running");
    assert_eq!(seen.captures[0].unclaimed_snapshot_id, None);
    ledger
        .settle_capture_unclaimed(&first.operation_id, SNAPSHOT, time(1005))
        .unwrap();
    drop(ledger);
    let seen =
        FixtureJournal::observe(&state.0, &id("host_fixture"), &id("epoch_fixture")).unwrap();
    let capture = &seen.captures[0];
    assert_eq!(capture.state, "failed");
    assert_eq!(capture.snapshot_id, None);
    assert_eq!(capture.unclaimed_snapshot_id.as_deref(), Some(SNAPSHOT));
    assert_eq!(capture.consistency, None);
}
