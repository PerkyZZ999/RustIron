//! W552 (journal v38, D-091): signed DNS zone imports. One live import per
//! zone; a done import owns the zone; a failed one frees it. Real SQLite;
//! no host effects.
use rustiron_contracts::approval::ZoneName;
use rustiron_journal::{DnsImportIntent, DnsImportResult, FixtureJournal, JournalError, StepState};
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
            "ri-dns-{}-{}",
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

fn zone(name: &str) -> ZoneName {
    ZoneName::try_from(name.to_owned()).unwrap()
}

fn import(n: u32, name: &str) -> DnsImportIntent {
    DnsImportIntent {
        operation_id: id(&format!("dns_import_{n}")),
        idempotency_key: id(&format!("dns_key_{n}")),
        grant_id: id(&format!("dns_grant_{n}")),
        nonce: id(&format!("dns_nonce_{n}")),
        plan_digest: digest('a'),
        grant_digest: digest('b'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        zone: zone(name),
        zone_sha256: digest('c'),
        record_sets: 12,
        expires_at: time(100_000),
    }
}

fn new_import(result: DnsImportResult) -> rustiron_journal::DnsImport {
    match result {
        DnsImportResult::New(row) => row,
        DnsImportResult::Existing(_) => panic!("expected a new import"),
    }
}

#[test]
fn an_import_records_once_and_replays_exactly() {
    let state = State::new();
    let mut ledger = state.init();
    let before = ledger.admission_count().unwrap();
    let intent = import(1, "example.test");
    let recorded = new_import(ledger.record_dns_import(&intent, time(1000)).unwrap());
    assert_eq!(recorded.state, StepState::Intent);
    assert_eq!(recorded.record_sets, 12);
    assert_eq!(ledger.admission_count().unwrap(), before + 1);
    assert!(matches!(
        ledger.record_dns_import(&intent, time(1001)),
        Ok(DnsImportResult::Existing(_))
    ));
    // The same key with another digest or count is a conflict.
    let mut other = intent.clone();
    other.zone_sha256 = digest('d');
    assert_eq!(
        ledger.record_dns_import(&other, time(1001)).err(),
        Some(JournalError::Conflict)
    );
    let mut other = intent.clone();
    other.record_sets = 13;
    assert_eq!(
        ledger.record_dns_import(&other, time(1001)).err(),
        Some(JournalError::Conflict)
    );
    // A new operation reusing the consumed nonce is a conflict.
    let mut reused = import(2, "example.org");
    reused.nonce = intent.nonce.clone();
    assert_eq!(
        ledger.record_dns_import(&reused, time(1001)).err(),
        Some(JournalError::Conflict)
    );
    // Another host epoch is a conflict.
    let mut foreign = import(3, "example.org");
    foreign.host_epoch = id("epoch_other");
    assert_eq!(
        ledger.record_dns_import(&foreign, time(1001)).err(),
        Some(JournalError::Conflict)
    );
    assert_eq!(ledger.admission_count().unwrap(), before + 1);
    drop(ledger);
    let ledger = state.open().unwrap();
    assert_eq!(
        ledger.dns_import_status(&intent.operation_id).unwrap(),
        Some(recorded)
    );
}

#[test]
fn one_live_import_per_zone_and_a_failed_one_frees_it() {
    let state = State::new();
    let mut ledger = state.init();
    let first = import(1, "example.test");
    ledger.record_dns_import(&first, time(1000)).unwrap();
    // An open import holds the zone.
    assert_eq!(
        ledger
            .record_dns_import(&import(2, "example.test"), time(1001))
            .err(),
        Some(JournalError::Consumed)
    );
    let failed = ledger
        .finish_dns_import(&first.operation_id, false)
        .unwrap();
    assert_eq!(failed.state, StepState::Failed);
    assert!(ledger.owned_dns_zones().unwrap().is_empty());
    assert_eq!(
        ledger.finish_dns_import(&first.operation_id, true).err(),
        Some(JournalError::Conflict)
    );
    // A new signed import may name the zone again; done owns it.
    let second = import(2, "example.test");
    ledger.record_dns_import(&second, time(1002)).unwrap();
    let done = ledger
        .finish_dns_import(&second.operation_id, true)
        .unwrap();
    assert_eq!(done.state, StepState::Done);
    assert_eq!(ledger.owned_dns_zones().unwrap(), [zone("example.test")]);
    // An owned zone takes no further import.
    assert_eq!(
        ledger
            .record_dns_import(&import(3, "example.test"), time(1003))
            .err(),
        Some(JournalError::Consumed)
    );
    // Another zone is independent.
    ledger
        .record_dns_import(&import(4, "example.org"), time(1004))
        .unwrap();
    ledger.finish_dns_import(&id("dns_import_4"), true).unwrap();
    assert_eq!(
        ledger.owned_dns_zones().unwrap(),
        [zone("example.org"), zone("example.test")]
    );
    drop(ledger);
    state.open().unwrap();
}

#[test]
fn an_expired_grant_records_nothing() {
    let state = State::new();
    let mut ledger = state.init();
    let mut intent = import(1, "example.test");
    intent.expires_at = time(1000);
    assert_eq!(
        ledger.record_dns_import(&intent, time(1000)).err(),
        Some(JournalError::Expired)
    );
    assert_eq!(
        ledger.dns_import_status(&intent.operation_id).unwrap(),
        None
    );
}

#[test]
fn a_v37_journal_migrates_and_a_bad_row_is_refused() {
    let state = State::new();
    let ledger = state.init();
    drop(ledger);
    state.sql(&format!("DROP TABLE caddy_generations; DROP TABLE app_fullstack_specs; DROP TABLE credential_rotations; DROP TABLE app_lifecycles; DROP TABLE app_release_steps; DROP TABLE app_releases; DROP TABLE apps; DROP TABLE static_ejections; DROP TABLE proxy_routes; DROP TABLE dns_change_sets; DROP TABLE dns_changes; DROP TABLE dns_imports; {TO_V40_DELETIONS} PRAGMA user_version=37;"));
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let mut ledger = state.migrate().unwrap();
    ledger
        .record_dns_import(&import(1, "example.test"), time(1000))
        .unwrap();
    drop(ledger);
    state.open().unwrap();
    // A second live import of one zone breaks the schema's own rule.
    let refused = rusqlite::Connection::open(state.0.join("fixture-journal.sqlite"))
        .unwrap()
        .execute_batch(
            "INSERT INTO dns_imports SELECT 'dns_import_9', zone, zone_sha256, 'k9', 'g9', 'n9', plan_digest, grant_digest, record_sets, expires_at, 'done' FROM dns_imports",
        );
    assert!(refused.is_err());
    // A zone name the grammar refuses makes the journal unavailable.
    state.sql("UPDATE dns_imports SET zone='a-.test' WHERE operation_id='dns_import_1';");
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
}

/// W554: an owned zone `example.test`.
fn owned(ledger: &mut FixtureJournal) {
    ledger
        .record_dns_import(&import(1, "example.test"), time(1000))
        .unwrap();
    ledger.finish_dns_import(&id("dns_import_1"), true).unwrap();
}

const SPF: &str = "example.test. 3600 IN TXT \"v=spf1 mx ~all\"\n";

fn sha(text: &str) -> rustiron_contracts::approval::Sha256Digest {
    use sha2::Digest;
    rustiron_contracts::approval::Sha256Digest::from_bytes(sha2::Sha256::digest(text).into())
}

fn change(n: u32, zone_name: &str) -> rustiron_journal::DnsChangeIntent {
    use rustiron_contracts::approval::{Expected, RecordType};
    rustiron_journal::DnsChangeIntent {
        operation_id: id(&format!("dns_change_{n}")),
        idempotency_key: id(&format!("dns_change_key_{n}")),
        grant_id: id(&format!("dns_change_grant_{n}")),
        nonce: id(&format!("dns_change_nonce_{n}")),
        plan_digest: digest('a'),
        grant_digest: digest('b'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        zone: zone(zone_name),
        sets: vec![
            rustiron_journal::DnsChangeSet {
                owner: "example.test.".to_owned(),
                kind: RecordType::Txt,
                expected: Expected::Digest(sha(SPF)),
                before: Some(SPF.to_owned()),
                after: None,
            },
            rustiron_journal::DnsChangeSet {
                owner: "www.example.test.".to_owned(),
                kind: RecordType::A,
                expected: Expected::Absent,
                before: None,
                after: None,
            },
        ],
        expires_at: time(100_000),
    }
}

#[test]
fn a_change_needs_an_owned_zone_and_the_expected_sets() {
    use rustiron_journal::DnsChangeResult;
    let state = State::new();
    let mut ledger = state.init();
    // An unowned zone takes no change.
    assert_eq!(
        ledger
            .record_dns_change(&change(1, "example.test"), time(1000))
            .err(),
        Some(JournalError::Consumed)
    );
    owned(&mut ledger);
    let before = ledger.admission_count().unwrap();
    // A set read that differs from what the operation expects.
    let mut drifted = change(1, "example.test");
    drifted.sets[0].before = Some(SPF.replace("~all", "-all"));
    assert_eq!(
        ledger.record_dns_change(&drifted, time(1001)).err(),
        Some(JournalError::SourceChanged)
    );
    let mut present = change(1, "example.test");
    present.sets[1].before = Some("www.example.test. 300 IN A 203.0.113.9\n".to_owned());
    assert_eq!(
        ledger.record_dns_change(&present, time(1001)).err(),
        Some(JournalError::SourceChanged)
    );
    assert_eq!(ledger.admission_count().unwrap(), before);
    let intent = change(1, "example.test");
    let recorded = match ledger.record_dns_change(&intent, time(1001)).unwrap() {
        DnsChangeResult::New(row) => row,
        DnsChangeResult::Existing(_) => panic!("expected a new change"),
    };
    assert_eq!(recorded.state, StepState::Intent);
    assert_eq!(recorded.sets.len(), 2);
    assert_eq!(ledger.admission_count().unwrap(), before + 1);
    assert!(matches!(
        ledger.record_dns_change(&intent, time(1002)),
        Ok(DnsChangeResult::Existing(_))
    ));
    let mut other = intent.clone();
    other.sets.pop();
    assert_eq!(
        ledger.record_dns_change(&other, time(1002)).err(),
        Some(JournalError::Conflict)
    );
    // One open change per zone.
    assert_eq!(
        ledger
            .record_dns_change(&change(2, "example.test"), time(1002))
            .err(),
        Some(JournalError::Consumed)
    );
    drop(ledger);
    state.open().unwrap();
}

/// W565: the done import that owns a zone authorizes its read; a change
/// admitted without staged signed bytes has no plan to give the helper.
#[test]
fn the_owning_import_and_the_change_plan_are_found_by_zone_and_operation() {
    let state = State::new();
    let mut ledger = state.init();
    assert_eq!(
        ledger.owning_dns_import(&zone("example.test")).unwrap(),
        None
    );
    ledger
        .record_dns_import(&import(1, "example.test"), time(1000))
        .unwrap();
    // An open import owns nothing yet.
    assert_eq!(
        ledger.owning_dns_import(&zone("example.test")).unwrap(),
        None
    );
    ledger.finish_dns_import(&id("dns_import_1"), true).unwrap();
    assert_eq!(
        ledger.owning_dns_import(&zone("example.test")).unwrap(),
        Some(id("dns_import_1"))
    );
    assert_eq!(ledger.owning_dns_import(&zone("other.test")).unwrap(), None);
    ledger
        .record_dns_change(&change(1, "example.test"), time(1001))
        .unwrap();
    assert_eq!(ledger.dns_change_plan(&id("dns_change_1")).unwrap(), None);
    assert_eq!(ledger.dns_change_plan(&id("dns_change_9")).unwrap(), None);
}

#[test]
fn a_change_finishes_with_its_sets_read_back() {
    let state = State::new();
    let mut ledger = state.init();
    owned(&mut ledger);
    ledger
        .record_dns_change(&change(1, "example.test"), time(1001))
        .unwrap();
    let operation = id("dns_change_1");
    let new_spf = SPF.replace("mx ~all", "mx include:spf.example.net ~all");
    let www = "www.example.test. 300 IN A 203.0.113.30\n".to_owned();
    // A done change reads back every set.
    assert_eq!(
        ledger
            .finish_dns_change(&operation, true, &[Some(new_spf.clone())])
            .err(),
        Some(JournalError::Conflict)
    );
    let done = ledger
        .finish_dns_change(
            &operation,
            true,
            &[Some(new_spf.clone()), Some(www.clone())],
        )
        .unwrap();
    assert_eq!(done.state, StepState::Done);
    assert_eq!(done.sets[0].after.as_deref(), Some(new_spf.as_str()));
    assert_eq!(
        ledger.finish_dns_change(&operation, false, &[]).err(),
        Some(JournalError::Conflict)
    );
    // The zone takes the next change; a failed one may hold fewer reads.
    let mut next = change(3, "example.test");
    next.sets[0].before = Some(new_spf.clone());
    next.sets[0].expected = rustiron_contracts::approval::Expected::Digest(sha(&new_spf));
    next.sets[1].before = Some(www.clone());
    next.sets[1].expected = rustiron_contracts::approval::Expected::Digest(sha(&www));
    ledger.record_dns_change(&next, time(1003)).unwrap();
    let failed = ledger
        .finish_dns_change(&id("dns_change_3"), false, &[Some(new_spf)])
        .unwrap();
    assert_eq!(failed.state, StepState::Failed);
    drop(ledger);
    state.open().unwrap();
}

#[test]
fn a_v38_journal_migrates_and_an_inconsistent_change_is_refused() {
    let state = State::new();
    let mut ledger = state.init();
    owned(&mut ledger);
    drop(ledger);
    state.sql(&format!("DROP TABLE caddy_generations; DROP TABLE app_fullstack_specs; DROP TABLE credential_rotations; DROP TABLE app_lifecycles; DROP TABLE app_release_steps; DROP TABLE app_releases; DROP TABLE apps; DROP TABLE static_ejections; DROP TABLE proxy_routes; DROP TABLE dns_change_sets; DROP TABLE dns_changes; {TO_V40_DELETIONS} PRAGMA user_version=38;"));
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let mut ledger = state.migrate().unwrap();
    ledger
        .record_dns_change(&change(1, "example.test"), time(1001))
        .unwrap();
    drop(ledger);
    state.open().unwrap();
    // A recorded before set that does not match its expected digest.
    state.sql(
        "UPDATE dns_change_sets SET before='example.test. 3600 IN TXT \"x\"\n' WHERE position=0;",
    );
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
}
