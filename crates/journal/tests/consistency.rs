//! W252 (B09, D-021 option E) capture consistency labels (schema v11) on real SQLite; no host effects.
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
const DDL: &str = "CREATE TABLE capture_consistency (operation_id TEXT PRIMARY KEY REFERENCES captures(operation_id), label TEXT NOT NULL CHECK(label IN ('matched','unmatched')), reason TEXT CHECK((label='matched' AND reason IS NULL) OR (label='unmatched' AND reason IS NOT NULL AND reason IN ('database_changed','marker_unavailable')))) STRICT";

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct State(PathBuf);
impl State {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ri-consistency-{}-{}",
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

#[test]
fn a_fresh_journal_has_the_exact_v11_consistency_table() {
    let state = State::new();
    drop(state.init());
    let c = state.conn();
    let version: i64 = c
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(version, 45);
    let sql: String = c
        .query_row(
            "SELECT sql FROM sqlite_master WHERE name='capture_consistency'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(sql, DDL);
}

#[test]
fn each_label_round_trips_and_an_unlabelled_capture_reads_as_not_checked() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let labels = [
        Some(CaptureConsistency::Matched),
        Some(CaptureConsistency::Unmatched(
            UnmatchedReason::DatabaseChanged,
        )),
        Some(CaptureConsistency::Unmatched(
            UnmatchedReason::MarkerUnavailable,
        )),
        None,
    ];
    for (n, label) in labels.iter().enumerate() {
        let intent = started(&mut ledger, n as u32);
        let done = finish(&mut ledger, &intent, Some(SNAPSHOT), label.as_ref()).unwrap();
        assert_eq!(done.state, CaptureState::Succeeded);
        assert_eq!(&done.consistency, label);
        assert_eq!(
            &ledger
                .capture_status(&intent.operation_id)
                .unwrap()
                .unwrap()
                .consistency,
            label
        );
    }
    drop(ledger);
    // The label survives reopening.
    let reopened = state.open().unwrap();
    assert_eq!(
        reopened
            .capture_status(&id("cap_0"))
            .unwrap()
            .unwrap()
            .consistency,
        Some(CaptureConsistency::Matched)
    );
}

#[test]
fn a_failed_capture_cannot_carry_a_label() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let intent = started(&mut ledger, 1);
    assert_eq!(
        finish(
            &mut ledger,
            &intent,
            None,
            Some(&CaptureConsistency::Matched)
        )
        .err(),
        Some(JournalError::Conflict)
    );
    // Still running: nothing was written.
    assert_eq!(
        ledger
            .capture_status(&intent.operation_id)
            .unwrap()
            .unwrap()
            .state,
        CaptureState::Running
    );
}

#[test]
fn malformed_stored_labels_are_refused() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let intent = started(&mut ledger, 1);
    finish(&mut ledger, &intent, Some(SNAPSHOT), None).unwrap();
    drop(ledger);
    let c = state.conn();
    for row in [
        "('cap_1','matched','database_changed')",
        "('cap_1','unmatched',NULL)",
        "('cap_1','unmatched','freeze_missed')",
        "('cap_1','maybe',NULL)",
        "('nope','matched',NULL)",
    ] {
        let inserted = c.execute_batch(&format!(
            "PRAGMA foreign_keys=ON; INSERT INTO capture_consistency VALUES{row};"
        ));
        assert!(inserted.is_err(), "{row}");
    }
}

#[test]
fn a_label_on_a_failed_row_makes_the_journal_unavailable() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let intent = started(&mut ledger, 1);
    finish(&mut ledger, &intent, None, None).unwrap();
    drop(ledger);
    state.sql("INSERT INTO capture_consistency VALUES('cap_1','matched',NULL);");
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
}

#[test]
fn a_v10_journal_migrates_to_v13_with_captures_unchanged_and_unlabelled() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let intent = started(&mut ledger, 1);
    let mut before = finish(&mut ledger, &intent, Some(SNAPSHOT), None).unwrap();
    before.backup_policy_digest = None;
    drop(ledger);
    state.sql(&format!("{TO_V16} DROP TABLE page_cache_optouts; DROP TABLE page_cache_optins; DROP TABLE capture_unclaimed; DROP TABLE capture_backup_policy; DROP TABLE probe_backup_policy; DROP TABLE capture_freeze; DROP TABLE capture_consistency; PRAGMA user_version=10;"));
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let migrated =
        FixtureJournal::migrate(&state.0, id("host_fixture"), id("epoch_fixture")).unwrap();
    let after = migrated
        .capture_status(&intent.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(after, before);
    assert_eq!(after.consistency, None);
    drop(migrated);
    // A second migrate is refused at the current schema.
    assert!(FixtureJournal::migrate(&state.0, id("host_fixture"), id("epoch_fixture")).is_err());
}

/// W379: the read-only observation carries each stored label, and nothing
/// for an unlabelled capture.
#[test]
fn the_observation_carries_each_label_and_none_when_unlabelled() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let labels = [
        Some(CaptureConsistency::Matched),
        Some(CaptureConsistency::Unmatched(
            UnmatchedReason::DatabaseChanged,
        )),
        None,
    ];
    for (n, label) in labels.iter().enumerate() {
        let intent = started(&mut ledger, n as u32);
        finish(&mut ledger, &intent, Some(SNAPSHOT), label.as_ref()).unwrap();
    }
    drop(ledger);
    let seen =
        FixtureJournal::observe(&state.0, &id("host_fixture"), &id("epoch_fixture")).unwrap();
    let got: Vec<_> = seen
        .captures
        .iter()
        .map(|c| c.consistency.clone())
        .collect();
    assert_eq!(
        got,
        [
            Some(("matched".to_owned(), None)),
            Some(("unmatched".to_owned(), Some("database_changed".to_owned()))),
            None,
        ]
    );
    assert!(
        seen.captures
            .iter()
            .all(|c| c.unclaimed_snapshot_id.is_none())
    );
}
