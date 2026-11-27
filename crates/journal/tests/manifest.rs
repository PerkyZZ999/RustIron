//! W203 capture manifest records (schema v10) on real SQLite; no host effects.
use rustiron_contracts::approval::{Hostname, SiteId};
use rustiron_journal::{
    CaptureIntent, CaptureManifest, CaptureMethod, CaptureState, FixtureJournal, JournalError,
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

const SNAPSHOT: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const DDL: &str = "CREATE TABLE capture_manifest (operation_id TEXT PRIMARY KEY REFERENCES captures(operation_id), manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256)=64), entries INTEGER NOT NULL CHECK(entries BETWEEN 0 AND 200000), regular_bytes INTEGER NOT NULL CHECK(regular_bytes>=0), truncated INTEGER NOT NULL CHECK(truncated IN (0,1))) STRICT";

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct State(PathBuf);
impl State {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ri-manifest-{}-{}",
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

fn manifest(entries: u64) -> CaptureManifest {
    CaptureManifest {
        sha256: "ab".repeat(32),
        entries,
        regular_bytes: 4096,
        truncated: false,
    }
}

#[test]
fn a_fresh_journal_has_the_exact_v10_manifest_table_kept_in_v12() {
    let state = State::new();
    drop(state.init());
    let c = state.conn();
    let version: i64 = c
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(version, 45);
    let sql: String = c
        .query_row(
            "SELECT sql FROM sqlite_master WHERE name='capture_manifest'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(sql, DDL);
}

#[test]
fn a_succeeded_capture_records_its_manifest_in_the_same_transaction() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let intent = started(&mut ledger, 1);
    let done = ledger
        .finish_capture(
            &intent.operation_id,
            Some(SNAPSHOT),
            time(1001),
            Some((3, 4096)),
            Some(&manifest(3)),
        )
        .unwrap();
    assert_eq!(done.state, CaptureState::Succeeded);
    assert_eq!(done.manifest, Some(manifest(3)));
    drop(ledger);
    assert_eq!(
        state
            .open()
            .unwrap()
            .capture_status(&intent.operation_id)
            .unwrap()
            .unwrap()
            .manifest,
        Some(manifest(3))
    );
    let seen =
        FixtureJournal::observe(&state.0, &id("host_fixture"), &id("epoch_fixture")).unwrap();
    assert_eq!(
        seen.captures[0].manifest_sha256.as_deref(),
        Some("ab".repeat(32).as_str())
    );
    assert_eq!(seen.captures[0].manifest_entries, Some(3));
    assert_eq!(seen.captures[0].manifest_regular_bytes, Some(4096));
    assert_eq!(seen.captures[0].manifest_truncated, Some(false));
}

#[test]
fn a_succeeded_capture_without_a_manifest_stays_succeeded() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let intent = started(&mut ledger, 1);
    let done = ledger
        .finish_capture(&intent.operation_id, Some(SNAPSHOT), time(1001), None, None)
        .unwrap();
    assert_eq!(done.state, CaptureState::Succeeded);
    assert_eq!(done.manifest, None);
}

#[test]
fn a_manifest_for_a_failed_capture_is_refused_and_changes_nothing() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let intent = started(&mut ledger, 1);
    assert_eq!(
        ledger
            .finish_capture(
                &intent.operation_id,
                None,
                time(1001),
                None,
                Some(&manifest(3))
            )
            .err(),
        Some(JournalError::Conflict)
    );
    let still = ledger
        .capture_status(&intent.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(still.state, CaptureState::Running);
    assert_eq!(still.manifest, None);
}

#[test]
fn a_manifest_row_on_a_running_or_failed_capture_is_refused_on_open() {
    for finish in [false, true] {
        let state = State::new();
        let mut ledger = state.init();
        provisioned(&mut ledger, "blog9");
        let intent = started(&mut ledger, 1);
        if finish {
            ledger
                .finish_capture(&intent.operation_id, None, time(1001), None, None)
                .unwrap();
        }
        drop(ledger);
        state.sql(&format!(
            "INSERT INTO capture_manifest VALUES('cap_1','{}',1,1,0);",
            "ab".repeat(32)
        ));
        assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    }
}

#[test]
fn an_orphaned_manifest_row_is_refused_on_open() {
    let state = State::new();
    drop(state.init());
    state.sql(&format!(
        "PRAGMA foreign_keys=OFF; INSERT INTO capture_manifest VALUES('missing_operation','{}',1,1,0);",
        "ab".repeat(32)
    ));
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
}

#[test]
fn out_of_range_manifest_values_are_refused() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let intent = started(&mut ledger, 1);
    let mut short = manifest(1);
    short.sha256 = "ab".repeat(31);
    let mut upper = manifest(1);
    upper.sha256 = "AB".repeat(32);
    for bad in [manifest(200_001), short, upper] {
        assert_eq!(
            ledger
                .finish_capture(
                    &intent.operation_id,
                    Some(SNAPSHOT),
                    time(1001),
                    None,
                    Some(&bad)
                )
                .err(),
            Some(JournalError::Conflict)
        );
    }
    assert_eq!(
        ledger
            .capture_status(&intent.operation_id)
            .unwrap()
            .unwrap()
            .state,
        CaptureState::Running
    );
    // The table itself refuses what the API would not write.
    let c = state.conn();
    for row in [
        format!("('cap_1','{}',200001,1,0)", "ab".repeat(32)),
        "('cap_1','short',1,1,0)".to_owned(),
        format!("('cap_1','{}',1,-1,0)", "ab".repeat(32)),
        format!("('cap_1','{}',1,1,2)", "ab".repeat(32)),
    ] {
        assert!(
            c.execute_batch(&format!("INSERT INTO capture_manifest VALUES{row};"))
                .is_err()
        );
    }
}

#[test]
fn a_v9_journal_migrates_to_v13_with_captures_unchanged_and_no_manifest_rows() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let intent = started(&mut ledger, 1);
    let mut before = ledger
        .finish_capture(
            &intent.operation_id,
            Some(SNAPSHOT),
            time(1001),
            Some((3, 9)),
            None,
        )
        .unwrap();
    before.backup_policy_digest = None;
    drop(ledger);
    state
        .sql(&format!("{TO_V16} DROP TABLE page_cache_optouts; DROP TABLE page_cache_optins; DROP TABLE capture_unclaimed; DROP TABLE capture_backup_policy; DROP TABLE probe_backup_policy; DROP TABLE capture_freeze; DROP TABLE capture_consistency; DROP TABLE capture_manifest; PRAGMA user_version=9;"));
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let migrated =
        FixtureJournal::migrate(&state.0, id("host_fixture"), id("epoch_fixture")).unwrap();
    let after = migrated
        .capture_status(&intent.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(after, before);
    assert_eq!(after.manifest, None);
    drop(migrated);
    let rows: i64 = state
        .conn()
        .query_row("SELECT count(*) FROM capture_manifest", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 0);
    let seen =
        FixtureJournal::observe(&state.0, &id("host_fixture"), &id("epoch_fixture")).unwrap();
    assert_eq!(seen.captures[0].manifest_sha256, None);
}

#[test]
fn a_v10_journal_is_not_read_as_v9() {
    let state = State::new();
    drop(state.init());
    // What a v9 reader checks: version 9 and exactly the v9 tables.
    state.sql(&format!("{TO_V16} DROP TABLE page_cache_optouts; DROP TABLE page_cache_optins; DROP TABLE capture_unclaimed; DROP TABLE capture_backup_policy; DROP TABLE probe_backup_policy; DROP TABLE capture_freeze; DROP TABLE capture_consistency; PRAGMA user_version=9;"));
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    assert!(FixtureJournal::migrate(&state.0, id("host_fixture"), id("epoch_fixture")).is_err());
}
