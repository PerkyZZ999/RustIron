//! Backup capture journal behavior on real SQLite; no host effects.
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
mod support;
use support::*;

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct State(PathBuf);
impl State {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ri-capture-{}-{}",
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

fn capture(n: u32, site: &str) -> CaptureIntent {
    CaptureIntent {
        operation_id: id(&format!("cap_{n}")),
        idempotency_key: id(&format!("cap_key_{n}")),
        grant_id: id(&format!("cap_grant_{n}")),
        nonce: id(&format!("cap_nonce_{n}")),
        plan_digest: digest('c'),
        grant_digest: digest('d'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: SiteId::try_from(site.to_owned()).unwrap(),
        expires_at: time(10000),
    }
}

const SNAPSHOT: &str = "89f5ad054604acf1033adc33725d0a96c5b609225525bda3bff495d4cc61f3ad";

#[test]
fn backup_policy_binding_survives_reopen_and_is_absent_after_v12_migration() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let finished = capture(1, "blog9");
    let running = capture(2, "blog9");
    let binding = digest('e');
    ledger
        .record_capture(
            &finished,
            time(1000),
            CaptureMethod::SiteFilesDbV1,
            None,
            &binding,
        )
        .unwrap();
    ledger
        .finish_capture(
            &finished.operation_id,
            Some(SNAPSHOT),
            time(1001),
            None,
            None,
        )
        .unwrap();
    ledger
        .record_capture(
            &running,
            time(1002),
            CaptureMethod::SiteFilesDbV1,
            None,
            &binding,
        )
        .unwrap();
    drop(ledger);
    let mut ledger = state.open().unwrap();
    let status = ledger
        .capture_status(&running.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(status.backup_policy_digest, Some(binding.clone()));
    assert_eq!(
        ledger
            .record_capture(
                &running,
                time(1003),
                CaptureMethod::SiteFilesDbV1,
                None,
                &digest('f')
            )
            .unwrap(),
        Admitted::Existing(status)
    );
    let count = ledger.admission_count().unwrap();
    drop(ledger);

    state.sql(&format!("{TO_V16} DROP TABLE page_cache_optouts; DROP TABLE page_cache_optins; DROP TABLE capture_unclaimed; DROP TABLE capture_backup_policy; DROP TABLE probe_backup_policy; PRAGMA user_version=12;"));
    FixtureJournal::migrate(&state.0, id("host_fixture"), id("epoch_fixture")).unwrap();
    let ledger = state.open().unwrap();
    assert_eq!(ledger.admission_count().unwrap(), count);
    for (operation, expected_state) in [
        (finished.operation_id, CaptureState::Succeeded),
        (running.operation_id, CaptureState::Running),
    ] {
        let capture = ledger.capture_status(&operation).unwrap().unwrap();
        assert_eq!(capture.state, expected_state);
        assert_eq!(capture.backup_policy_digest, None);
    }
}

#[test]
fn a_capture_needs_a_succeeded_provision_and_runs_one_at_a_time() {
    let state = State::new();
    let mut ledger = state.init();
    assert_eq!(
        ledger
            .record_capture(
                &capture(1, "blog9"),
                time(1000),
                CaptureMethod::SiteFilesDbV1,
                None,
                &digest('e'),
            )
            .err(),
        Some(JournalError::Conflict),
        "no provision"
    );
    provisioned(&mut ledger, "blog9");
    let first = capture(1, "blog9");
    assert!(matches!(
        ledger
            .record_capture(
                &first,
                time(1000),
                CaptureMethod::SiteFilesDbV1,
                None,
                &digest('e')
            )
            .unwrap(),
        Admitted::New(_)
    ));
    assert!(matches!(
        ledger
            .record_capture(
                &first,
                time(1000),
                CaptureMethod::SiteFilesDbV1,
                None,
                &digest('e')
            )
            .unwrap(),
        Admitted::Existing(_)
    ));
    assert_eq!(
        ledger
            .record_capture(
                &capture(2, "blog9"),
                time(1001),
                CaptureMethod::SiteFilesDbV1,
                None,
                &digest('e'),
            )
            .err(),
        Some(JournalError::Busy)
    );
    let done = ledger
        .finish_capture(
            &first.operation_id,
            Some(SNAPSHOT),
            time(1002),
            Some((4, 100)),
            None,
        )
        .unwrap();
    assert_eq!(done.state, CaptureState::Succeeded);
    assert_eq!(done.files, Some(4));
    assert_eq!(done.bytes, Some(100));
    assert_eq!(
        ledger
            .finish_capture(&first.operation_id, None, time(1003), None, None)
            .err(),
        Some(JournalError::Conflict),
        "a finished capture never changes"
    );
    let second = capture(2, "blog9");
    ledger
        .record_capture(
            &second,
            time(1004),
            CaptureMethod::SiteFilesDbV1,
            None,
            &digest('e'),
        )
        .unwrap();
    assert_eq!(
        ledger
            .finish_capture(
                &second.operation_id,
                Some("not-a-snapshot"),
                time(1005),
                None,
                None
            )
            .err(),
        Some(JournalError::Conflict)
    );
    assert_eq!(
        ledger
            .finish_capture(&second.operation_id, None, time(1005), None, None)
            .unwrap()
            .state,
        CaptureState::Failed
    );
    drop(ledger);
    let ledger = state.open().unwrap();
    assert_eq!(
        ledger
            .capture_status(&first.operation_id)
            .unwrap()
            .unwrap()
            .snapshot_id
            .as_deref(),
        Some(SNAPSHOT)
    );
}

#[test]
fn ids_consumed_anywhere_cannot_start_a_capture() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let mut reused = capture(1, "blog9");
    reused.nonce = id("prov_nonce_blog9");
    assert_eq!(
        ledger
            .record_capture(
                &reused,
                time(1000),
                CaptureMethod::SiteFilesDbV1,
                None,
                &digest('e')
            )
            .err(),
        Some(JournalError::Conflict)
    );
}

#[test]
fn a_running_capture_survives_restart_and_contradictions_are_refused() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let first = capture(1, "blog9");
    ledger
        .record_capture(
            &first,
            time(1000),
            CaptureMethod::SiteFilesDbV1,
            None,
            &digest('e'),
        )
        .unwrap();
    drop(ledger);
    let mut ledger = state.open().unwrap();
    assert_eq!(
        ledger
            .capture_status(&first.operation_id)
            .unwrap()
            .unwrap()
            .state,
        CaptureState::Running
    );
    assert_eq!(
        ledger
            .record_capture(
                &capture(2, "blog9"),
                time(1001),
                CaptureMethod::SiteFilesDbV1,
                None,
                &digest('e'),
            )
            .err(),
        Some(JournalError::Busy)
    );
    drop(ledger);
    state.sql("UPDATE captures SET state='succeeded';");
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
}

#[test]
fn a_fixture_operation_nonce_cannot_start_a_capture() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let fixture = intent(7);
    ledger.record_intent(&fixture, time(1000)).unwrap();
    let mut reused = capture(1, "blog9");
    reused.nonce = fixture.nonce.clone();
    assert_eq!(
        ledger
            .record_capture(
                &reused,
                time(1001),
                CaptureMethod::SiteFilesDbV1,
                None,
                &digest('e')
            )
            .err(),
        Some(JournalError::Conflict)
    );
}

#[test]
fn observing_reads_every_record_beside_a_live_writer_and_changes_nothing() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let first = capture(1, "blog9");
    ledger
        .record_capture(
            &first,
            time(1000),
            CaptureMethod::SiteFilesDbV1,
            None,
            &digest('e'),
        )
        .unwrap();
    ledger
        .finish_capture(&first.operation_id, Some(SNAPSHOT), time(1002), None, None)
        .unwrap();
    ledger
        .record_capture(
            &capture(2, "blog9"),
            time(1003),
            CaptureMethod::SiteFilesDbV1,
            None,
            &digest('e'),
        )
        .unwrap();
    let before = fs::read(state.0.join("fixture-journal.sqlite")).unwrap();

    // The writer still holds its lease: a second writer is refused, an observer is not.
    assert_eq!(state.open().err(), Some(JournalError::AccessDenied));
    let seen =
        FixtureJournal::observe(&state.0, &id("host_fixture"), &id("epoch_fixture")).unwrap();
    assert_eq!(seen.last_time, 1003);
    assert_eq!(seen.provisions.len(), 1);
    assert_eq!(seen.provisions[0].hostname, "blog9.example.test");
    assert_eq!(seen.provisions[0].state, "succeeded");
    assert_eq!(
        seen.provisions[0].steps_done,
        seen.provisions[0].steps_recorded
    );
    assert_eq!(seen.provisions[0].failed_step, None);
    let states: Vec<_> = seen.captures.iter().map(|c| c.state.as_str()).collect();
    assert_eq!(states, ["succeeded", "running"]);
    assert_eq!(seen.captures[0].snapshot_id.as_deref(), Some(SNAPSHOT));
    assert_eq!(seen.captures[0].method.as_deref(), Some("site_files_db_v1"));
    assert_eq!(seen.captures[1].finished_at, None);
    assert_eq!(
        fs::read(state.0.join("fixture-journal.sqlite")).unwrap(),
        before
    );

    assert_eq!(
        FixtureJournal::observe(&state.0, &id("host_fixture"), &id("other_epoch")).err(),
        Some(JournalError::Conflict),
        "a journal of another epoch is not shown as this host"
    );
    drop(ledger);
}

#[test]
fn migration_refuses_an_inconsistent_capture_without_advancing_the_schema() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    ledger
        .record_capture(
            &capture(1, "blog9"),
            time(1000),
            CaptureMethod::SiteFilesDbV1,
            None,
            &digest('e'),
        )
        .unwrap();
    drop(ledger);
    state.sql(&format!("{TO_V16} DROP TABLE page_cache_optouts; DROP TABLE page_cache_optins; DROP TABLE capture_unclaimed; DROP TABLE capture_backup_policy; DROP TABLE probe_backup_policy; DROP TABLE capture_freeze; DROP TABLE capture_consistency; DROP TABLE capture_manifest; DROP TABLE capture_extent; DROP TABLE capture_retention; DROP TABLE capture_methods; DROP TABLE restore_probes; PRAGMA user_version=5; UPDATE captures SET state='succeeded';"));

    assert_eq!(
        FixtureJournal::migrate(&state.0, id("host_fixture"), id("epoch_fixture")).err(),
        Some(JournalError::Unavailable)
    );
    let connection = rusqlite::Connection::open(state.0.join("fixture-journal.sqlite")).unwrap();
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, 5, "a refused source must not be migrated");
    let probe_tables: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE name='restore_probes'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(probe_tables, 0, "the new table must roll back too");
}

#[test]
fn new_capture_method_survives_restart_and_replay() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let intent = capture(1, "blog9");
    ledger
        .record_capture(
            &intent,
            time(1000),
            CaptureMethod::SiteFilesDbV1,
            None,
            &digest('e'),
        )
        .unwrap();
    drop(ledger);
    let mut ledger = state.open().unwrap();
    let Admitted::Existing(existing) = ledger
        .record_capture(
            &intent,
            time(1001),
            CaptureMethod::SiteFilesDbV1,
            None,
            &digest('e'),
        )
        .unwrap()
    else {
        panic!("replay must return existing status");
    };
    assert_eq!(existing.method, Some(CaptureMethod::SiteFilesDbV1));
}

#[test]
fn migration_preserves_legacy_capture_without_inventing_its_method() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let intent = capture(1, "blog9");
    ledger
        .record_capture(
            &intent,
            time(1000),
            CaptureMethod::SiteFilesDbV1,
            None,
            &digest('e'),
        )
        .unwrap();
    ledger
        .finish_capture(&intent.operation_id, Some(SNAPSHOT), time(1002), None, None)
        .unwrap();
    drop(ledger);
    state.sql(&format!("{TO_V16} DROP TABLE page_cache_optouts; DROP TABLE page_cache_optins; DROP TABLE capture_unclaimed; DROP TABLE capture_backup_policy; DROP TABLE probe_backup_policy; DROP TABLE capture_freeze; DROP TABLE capture_consistency; DROP TABLE capture_manifest; DROP TABLE capture_extent; DROP TABLE capture_retention; DROP TABLE capture_methods; PRAGMA user_version=6;"));
    let mut migrated =
        FixtureJournal::migrate(&state.0, id("host_fixture"), id("epoch_fixture")).unwrap();
    let Admitted::Existing(existing) = migrated
        .record_capture(
            &intent,
            time(1003),
            CaptureMethod::SiteFilesDbV1,
            None,
            &digest('e'),
        )
        .unwrap()
    else {
        panic!("migration must preserve replay history");
    };
    assert_eq!(existing.snapshot_id.as_deref(), Some(SNAPSHOT));
    assert_eq!(existing.method, None);
    assert_eq!(existing.retention_days, None);
    drop(migrated);
    let seen =
        FixtureJournal::observe(&state.0, &id("host_fixture"), &id("epoch_fixture")).unwrap();
    assert_eq!(seen.captures[0].method, None);
    assert_eq!(seen.captures[0].retention_days, None);
}

#[test]
fn an_orphaned_capture_method_is_refused_on_open() {
    let state = State::new();
    drop(state.init());
    state.sql("PRAGMA foreign_keys=OFF; INSERT INTO capture_methods VALUES('missing_operation','site_files_db_v1');");
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
}

#[test]
fn method_write_failure_rolls_back_capture_intent_and_nonce() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let intent = capture(1, "blog9");
    state.sql("CREATE TRIGGER fail_capture_method BEFORE INSERT ON capture_methods BEGIN SELECT RAISE(ABORT, 'injected'); END;");
    assert_eq!(
        ledger
            .record_capture(
                &intent,
                time(1000),
                CaptureMethod::SiteFilesDbV1,
                None,
                &digest('e')
            )
            .err(),
        Some(JournalError::Unavailable)
    );
    assert_eq!(ledger.capture_status(&intent.operation_id).unwrap(), None);
    state.sql("DROP TRIGGER fail_capture_method;");
    assert!(matches!(
        ledger.record_capture(
            &intent,
            time(1000),
            CaptureMethod::SiteFilesDbV1,
            None,
            &digest('e')
        ),
        Ok(Admitted::New(_))
    ));
}

#[test]
fn a_new_capture_stores_retention_and_a_legacy_row_does_not_gain_it() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let intent = capture(1, "blog9");
    assert_eq!(
        ledger
            .record_capture(
                &intent,
                time(1000),
                CaptureMethod::SiteFilesDbV1,
                Some(0),
                &digest('e')
            )
            .err(),
        Some(JournalError::Conflict)
    );
    assert_eq!(
        ledger
            .record_capture(
                &intent,
                time(1000),
                CaptureMethod::SiteFilesDbV1,
                Some(3651),
                &digest('e')
            )
            .err(),
        Some(JournalError::Conflict)
    );
    let Admitted::New(created) = ledger
        .record_capture(
            &intent,
            time(1000),
            CaptureMethod::SiteFilesDbV1,
            Some(30),
            &digest('e'),
        )
        .unwrap()
    else {
        panic!("enrolled retention must be stored");
    };
    assert_eq!(created.retention_days, Some(30));
    assert_eq!(
        ledger
            .record_capture(
                &intent,
                time(1001),
                CaptureMethod::SiteFilesDbV1,
                Some(7),
                &digest('e')
            )
            .err(),
        Some(JournalError::Conflict)
    );
    ledger
        .finish_capture(&intent.operation_id, Some(SNAPSHOT), time(1002), None, None)
        .unwrap();
    drop(ledger);
    state.sql(&format!("{TO_V16} DROP TABLE page_cache_optouts; DROP TABLE page_cache_optins; DROP TABLE capture_unclaimed; DROP TABLE capture_backup_policy; DROP TABLE probe_backup_policy; DROP TABLE capture_freeze; DROP TABLE capture_consistency; DROP TABLE capture_manifest; DROP TABLE capture_extent; DROP TABLE capture_retention; PRAGMA user_version=7;"));
    let mut migrated =
        FixtureJournal::migrate(&state.0, id("host_fixture"), id("epoch_fixture")).unwrap();
    let Admitted::Existing(existing) = migrated
        .record_capture(
            &intent,
            time(1003),
            CaptureMethod::SiteFilesDbV1,
            Some(30),
            &digest('e'),
        )
        .unwrap()
    else {
        panic!("replay must not rewrite a legacy capture");
    };
    assert_eq!(existing.retention_days, None);
    assert_eq!(existing.method, Some(CaptureMethod::SiteFilesDbV1));
    let seen =
        FixtureJournal::observe(&state.0, &id("host_fixture"), &id("epoch_fixture")).unwrap();
    assert_eq!(seen.captures[0].retention_days, None);
}
