//! W442 (journal v21, D-053): a site import is a provision whose Recipe step
//! holds the import steps. W457 (v22, D-057): the scrub of an import's
//! leftover secrets. Real SQLite; no host effects.
use rustiron_contracts::{
    approval::{Hostname, SiteId},
    migration::PhpVersion,
};
use rustiron_journal::{
    Admitted, CertificateIntent, FixtureJournal, ImportFacts, ImportStep, JournalError,
    ProvisionIntent, ProvisionState, ProvisionStep, ScrubIntent, ScrubOrigin, StepState,
};
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
mod support;
use support::*;

/// The exact v21 and v22 tables.
const DDL_V22: [(&str, &str); 4] = [
    (
        "imports",
        "CREATE TABLE imports (operation_id TEXT PRIMARY KEY REFERENCES provisions(operation_id), archive_sha256 TEXT NOT NULL CHECK(length(archive_sha256)=64 AND archive_sha256 NOT GLOB '*[^0-9a-f]*'), manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256)=64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'), file_entries INTEGER NOT NULL CHECK(file_entries BETWEEN 1 AND 200000), file_bytes INTEGER NOT NULL CHECK(file_bytes>=0), dump_bytes INTEGER NOT NULL CHECK(dump_bytes BETWEEN 0 AND 2147483648), target_php TEXT NOT NULL CHECK(length(target_php) BETWEEN 3 AND 4 AND target_php GLOB '[5-9].[0-9]*' AND substr(target_php,3) NOT GLOB '*[^0-9]*')) STRICT",
    ),
    (
        "import_steps",
        "CREATE TABLE import_steps (operation_id TEXT NOT NULL REFERENCES imports(operation_id), position INTEGER NOT NULL CHECK(position BETWEEN 0 AND 5), state TEXT NOT NULL CHECK(state IN ('intent','done','failed')), PRIMARY KEY(operation_id, position)) STRICT",
    ),
    (
        "import_scrubs",
        "CREATE TABLE import_scrubs (operation_id TEXT PRIMARY KEY, import_operation_id TEXT NOT NULL REFERENCES imports(operation_id), origin TEXT NOT NULL CHECK(origin IN ('failed_step','signed')), idempotency_key TEXT UNIQUE, grant_id TEXT UNIQUE, nonce TEXT UNIQUE, plan_digest TEXT CHECK(plan_digest IS NULL OR (length(plan_digest)=64 AND plan_digest NOT GLOB '*[^0-9a-f]*')), grant_digest TEXT CHECK(grant_digest IS NULL OR (length(grant_digest)=64 AND grant_digest NOT GLOB '*[^0-9a-f]*')), expires_at INTEGER CHECK(expires_at IS NULL OR expires_at>=0), state TEXT NOT NULL CHECK(state IN ('intent','done','failed')), CHECK((origin='failed_step' AND operation_id=import_operation_id AND idempotency_key IS NULL AND grant_id IS NULL AND nonce IS NULL AND plan_digest IS NULL AND grant_digest IS NULL AND expires_at IS NULL) OR (origin='signed' AND operation_id<>import_operation_id AND idempotency_key IS NOT NULL AND grant_id IS NOT NULL AND nonce IS NOT NULL AND plan_digest IS NOT NULL AND grant_digest IS NOT NULL AND expires_at IS NOT NULL))) STRICT",
    ),
    (
        "one_open_scrub",
        "CREATE UNIQUE INDEX one_open_scrub ON import_scrubs(import_operation_id) WHERE state='intent'",
    ),
];

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct State(PathBuf);
impl State {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ri-import-{}-{}",
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
    fn connection(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.0.join("fixture-journal.sqlite")).unwrap()
    }
    fn sql(&self, sql: &str) {
        self.connection().execute_batch(sql).unwrap();
    }
}
impl Drop for State {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn site(n: u32) -> ProvisionIntent {
    ProvisionIntent {
        operation_id: id(&format!("import_op_{n}")),
        idempotency_key: id(&format!("import_key_{n}")),
        grant_id: id(&format!("import_grant_{n}")),
        nonce: id(&format!("import_nonce_{n}")),
        plan_digest: digest('a'),
        grant_digest: digest('b'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: SiteId::try_from(format!("blog{n}")).unwrap(),
        hostname: Hostname::try_from(format!("blog{n}.example.test")).unwrap(),
        expires_at: time(10000),
    }
}

fn facts() -> ImportFacts {
    ImportFacts {
        archive_sha256: digest('c'),
        manifest_sha256: digest('d'),
        file_entries: 4200,
        file_bytes: 90_000_000,
        dump_bytes: 12_000_000,
        target_php: PhpVersion::try_from("8.2".to_owned()).unwrap(),
        source_hostname: None,
        alias_hostname: None,
    }
}

/// D-070: the facts of an import that serves the site under another name.
fn renamed_facts() -> ImportFacts {
    ImportFacts {
        source_hostname: Some(Hostname::try_from("blog.example.org".to_owned()).unwrap()),
        ..facts()
    }
}

/// Runs the provision steps before Recipe, then begins Recipe.
fn reach_recipe(ledger: &mut FixtureJournal, intent: &ProvisionIntent) {
    for step in &ProvisionStep::ALL[..5] {
        ledger
            .begin_step(&intent.operation_id, *step, "resource")
            .unwrap();
        ledger
            .finish_step(&intent.operation_id, *step, true)
            .unwrap();
    }
    ledger
        .begin_step(&intent.operation_id, ProvisionStep::Recipe, "import_v1")
        .unwrap();
}

#[test]
fn a_fresh_journal_has_the_exact_import_tables() {
    let state = State::new();
    drop(state.init());
    let c = state.connection();
    let version: i64 = c
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, 45);
    for (name, sql) in DDL_V22 {
        let actual: String = c
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name=?1",
                [name],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(actual, sql, "{name}");
    }
}

#[test]
fn an_import_is_recorded_with_its_facts_and_replays_as_status() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    assert!(matches!(
        ledger.record_import(&one, &facts(), time(1000)).unwrap(),
        Admitted::New(provision) if provision.state == ProvisionState::Running
    ));
    let import = ledger.import_status(&one.operation_id).unwrap().unwrap();
    assert_eq!(import.facts, facts());
    assert!(import.steps.is_empty());
    assert!(import.scrubs.is_empty());
    assert!(matches!(
        ledger.record_import(&one, &facts(), time(1001)).unwrap(),
        Admitted::Existing(_)
    ));
    let mut other = facts();
    other.dump_bytes += 1;
    assert_eq!(
        ledger.record_import(&one, &other, time(1002)).err(),
        Some(JournalError::Conflict),
        "the same key with other facts"
    );
    assert_eq!(
        ledger.record_provision(&one, time(1003)).err(),
        Some(JournalError::Conflict),
        "the same key as a plain provision"
    );
    drop(ledger);
    let ledger = state.open().unwrap();
    assert_eq!(
        ledger
            .import_status(&one.operation_id)
            .unwrap()
            .unwrap()
            .facts,
        facts()
    );
    assert_eq!(ledger.import_status(&id("missing")).unwrap(), None);
}

#[test]
fn an_import_shares_the_site_and_hostname_reservation() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    ledger.record_import(&one, &facts(), time(1000)).unwrap();
    ledger.quarantine_provision(&one.operation_id).unwrap();
    let mut again = site(2);
    again.hostname = one.hostname.clone();
    assert_eq!(
        ledger.record_provision(&again, time(1001)).err(),
        Some(JournalError::Consumed)
    );
    let mut again = site(3);
    again.site_id = one.site_id.clone();
    assert_eq!(
        ledger.record_import(&again, &facts(), time(1002)).err(),
        Some(JournalError::Consumed)
    );
}

#[test]
fn import_steps_run_in_order_inside_the_recipe_step() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    ledger.record_import(&one, &facts(), time(1000)).unwrap();
    let op = &one.operation_id;
    assert_eq!(
        ledger.begin_import_step(op, ImportStep::Intake).err(),
        Some(JournalError::Conflict),
        "before the Recipe step"
    );
    reach_recipe(&mut ledger, &one);
    assert_eq!(
        ledger.begin_import_step(op, ImportStep::Extract).err(),
        Some(JournalError::Conflict),
        "out of order"
    );
    for step in ImportStep::ALL {
        let import = ledger.begin_import_step(op, step).unwrap();
        assert_eq!(import.steps.last().unwrap().state, StepState::Intent);
        assert_eq!(
            ledger.begin_import_step(op, step).err(),
            Some(JournalError::Conflict),
            "{step:?} twice"
        );
        if step != ImportStep::Config {
            assert_eq!(
                ledger.finish_step(op, ProvisionStep::Recipe, true).err(),
                Some(JournalError::Conflict),
                "Recipe done before every import step"
            );
        }
        ledger.finish_import_step(op, step, true).unwrap();
    }
    let import = ledger.import_status(op).unwrap().unwrap();
    assert_eq!(import.steps.len(), 6);
    assert!(
        import
            .steps
            .iter()
            .all(|record| record.state == StepState::Done)
    );
    ledger.finish_step(op, ProvisionStep::Recipe, true).unwrap();
    for step in [ProvisionStep::PhpUnits, ProvisionStep::Verify] {
        ledger.begin_step(op, step, "resource").unwrap();
        ledger.finish_step(op, step, true).unwrap();
    }
    assert_eq!(
        ledger.provision_status(op).unwrap().unwrap().state,
        ProvisionState::Succeeded
    );
    assert_eq!(
        ledger.begin_import_step(op, ImportStep::Intake).err(),
        Some(JournalError::Conflict),
        "after success"
    );
}

#[test]
fn a_failed_import_step_quarantines_the_import() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    ledger.record_import(&one, &facts(), time(1000)).unwrap();
    reach_recipe(&mut ledger, &one);
    let op = &one.operation_id;
    ledger.begin_import_step(op, ImportStep::Intake).unwrap();
    assert_eq!(
        ledger
            .finish_import_step(op, ImportStep::Extract, true)
            .err(),
        Some(JournalError::Conflict),
        "finishing a step that is not the open one"
    );
    let import = ledger
        .finish_import_step(op, ImportStep::Intake, false)
        .unwrap();
    assert_eq!(import.steps[0].state, StepState::Failed);
    let provision = ledger.provision_status(op).unwrap().unwrap();
    assert_eq!(provision.state, ProvisionState::Quarantined);
    assert_eq!(
        provision.steps.last().unwrap().state,
        StepState::Failed,
        "the Recipe step"
    );
    assert_eq!(
        ledger.begin_import_step(op, ImportStep::Extract).err(),
        Some(JournalError::Conflict)
    );
}

#[test]
fn a_plain_provision_has_no_import_steps() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    ledger.record_provision(&one, time(1000)).unwrap();
    reach_recipe(&mut ledger, &one);
    assert_eq!(ledger.import_status(&one.operation_id).unwrap(), None);
    assert_eq!(
        ledger
            .begin_import_step(&one.operation_id, ImportStep::Intake)
            .err(),
        Some(JournalError::Conflict)
    );
    ledger
        .finish_step(&one.operation_id, ProvisionStep::Recipe, true)
        .unwrap();
}

#[test]
fn a_v20_journal_migrates_to_v21_and_keeps_its_provisions() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    ledger.record_provision(&one, time(1000)).unwrap();
    drop(ledger);
    state.sql(TO_V20);
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let mut ledger = state.migrate().unwrap();
    assert!(
        ledger
            .provision_status(&one.operation_id)
            .unwrap()
            .is_some()
    );
    ledger.quarantine_provision(&one.operation_id).unwrap();
    assert!(matches!(
        ledger
            .record_import(&site(2), &facts(), time(1001))
            .unwrap(),
        Admitted::New(_)
    ));
    drop(ledger);
    assert!(state.open().is_ok());
}

#[test]
fn a_v21_journal_migrates_to_v22_and_keeps_its_imports() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    ledger.record_import(&one, &facts(), time(1000)).unwrap();
    drop(ledger);
    state.sql(&legacy_import_schema(21));
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let ledger = state.migrate().unwrap();
    let import = ledger.import_status(&one.operation_id).unwrap().unwrap();
    assert_eq!(import.facts, facts());
    assert!(import.scrubs.is_empty());
    drop(ledger);
    assert!(state.open().is_ok());
}

/// D-070: a renamed import keeps its source hostname across a reopen; an
/// import under the same name has none, and its source is its own hostname.
#[test]
fn a_renamed_import_keeps_its_source_hostname() {
    let state = State::new();
    let mut ledger = state.init();
    let (one, two) = (site(1), site(2));
    let _ = &two;
    ledger
        .record_import(&one, &renamed_facts(), time(1000))
        .unwrap();
    drop(ledger);
    let ledger = state.open().unwrap();
    let import = ledger.import_status(&one.operation_id).unwrap().unwrap();
    assert_eq!(import.facts, renamed_facts());
    assert_eq!(
        import.facts.source_or(&one.hostname).as_str(),
        "blog.example.org"
    );
    // A repeat with other facts is not this import.
    assert_ne!(import.facts, facts());
    drop(ledger);
    let state2 = State::new();
    let mut ledger = state2.init();
    ledger.record_import(&two, &facts(), time(1000)).unwrap();
    let import = ledger.import_status(&two.operation_id).unwrap().unwrap();
    assert_eq!(import.facts.source_hostname, None);
    assert_eq!(import.facts.source_or(&two.hostname), &two.hostname);
    let rows: i64 = state2
        .connection()
        .query_row("SELECT count(*) FROM import_sources", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, 0);
}

/// D-070: the v25 table is exact, and a v24 journal migrates in place with
/// its imports read as unrenamed.
#[test]
fn a_v24_journal_migrates_to_v25_and_keeps_its_imports() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    ledger.record_import(&one, &facts(), time(1000)).unwrap();
    drop(ledger);
    let sql: String = state
        .connection()
        .query_row(
            "SELECT sql FROM sqlite_master WHERE name='import_sources'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        sql,
        "CREATE TABLE import_sources (operation_id TEXT PRIMARY KEY REFERENCES imports(operation_id), source_hostname TEXT NOT NULL CHECK(length(source_hostname) BETWEEN 1 AND 253 AND source_hostname NOT GLOB '*[^a-z0-9.-]*')) STRICT"
    );
    state.sql(&legacy_import_schema(24));
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let ledger = state.migrate().unwrap();
    let import = ledger.import_status(&one.operation_id).unwrap().unwrap();
    assert_eq!(import.facts, facts());
    drop(ledger);
    assert!(state.open().is_ok());
    // A migrated journal records a renamed import.
    let empty = State::new();
    drop(empty.init());
    empty.sql(&legacy_import_schema(24));
    let mut ledger = empty.migrate().unwrap();
    ledger
        .record_import(&one, &renamed_facts(), time(1100))
        .unwrap();
    drop(ledger);
    let ledger = empty.open().unwrap();
    assert_eq!(
        ledger
            .import_status(&one.operation_id)
            .unwrap()
            .unwrap()
            .facts,
        renamed_facts()
    );
}

/// Fails the import at `failing`, after the steps before it are done.
fn fail_at(ledger: &mut FixtureJournal, intent: &ProvisionIntent, failing: ImportStep) {
    reach_recipe(ledger, intent);
    let op = &intent.operation_id;
    for step in ImportStep::ALL {
        ledger.begin_import_step(op, step).unwrap();
        let done = step != failing;
        ledger.finish_import_step(op, step, done).unwrap();
        if !done {
            return;
        }
    }
}

#[test]
fn a_failed_import_step_allows_one_automatic_scrub() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    let op = &one.operation_id;
    ledger.record_import(&one, &facts(), time(1000)).unwrap();
    assert_eq!(
        ledger.begin_failed_step_scrub(op).err(),
        Some(JournalError::Conflict),
        "before any failure"
    );
    fail_at(&mut ledger, &one, ImportStep::Database);
    let import = ledger.begin_failed_step_scrub(op).unwrap();
    assert_eq!(import.scrubs.len(), 1);
    assert_eq!(import.scrubs[0].operation_id, *op);
    assert_eq!(import.scrubs[0].origin, ScrubOrigin::FailedStep);
    assert_eq!(import.scrubs[0].state, StepState::Intent);
    assert_eq!(
        ledger.begin_failed_step_scrub(op).err(),
        Some(JournalError::Conflict),
        "twice"
    );
    let import = ledger.finish_import_scrub(op, false).unwrap();
    assert_eq!(import.scrubs[0].state, StepState::Failed, "never done");
    assert_eq!(
        ledger.finish_import_scrub(op, true).err(),
        Some(JournalError::Conflict),
        "a settled scrub is not finished again"
    );
    assert_eq!(
        ledger.begin_failed_step_scrub(op).err(),
        Some(JournalError::Conflict),
        "a failed automatic scrub is not retried automatically"
    );
    drop(ledger);
    let ledger = state.open().unwrap();
    let import = ledger.import_status(op).unwrap().unwrap();
    assert_eq!(import.scrubs[0].state, StepState::Failed);
    assert_eq!(
        ledger.provision_status(op).unwrap().unwrap().state,
        ProvisionState::Quarantined
    );
}

#[test]
fn a_succeeded_or_running_import_has_no_automatic_scrub() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    let op = &one.operation_id;
    ledger.record_import(&one, &facts(), time(1000)).unwrap();
    reach_recipe(&mut ledger, &one);
    ledger.begin_import_step(op, ImportStep::Intake).unwrap();
    assert_eq!(
        ledger.begin_failed_step_scrub(op).err(),
        Some(JournalError::Conflict),
        "an open step"
    );
    // A plain quarantine without a failed import step is not a failed step.
    let two = site(2);
    ledger.quarantine_provision(op).unwrap();
    ledger.record_import(&two, &facts(), time(1001)).unwrap();
    assert_eq!(
        ledger.begin_failed_step_scrub(&two.operation_id).err(),
        Some(JournalError::Conflict)
    );
    assert_eq!(
        ledger.finish_import_scrub(&id("missing"), true).err(),
        Some(JournalError::Conflict)
    );
}

#[test]
fn the_scrub_rows_are_closed_by_the_schema() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    ledger.record_import(&one, &facts(), time(1000)).unwrap();
    drop(ledger);
    let c = state.connection();
    for sql in [
        // An automatic scrub under another operation.
        "INSERT INTO import_scrubs(operation_id, import_operation_id, origin, state) VALUES('other','import_op_1','failed_step','intent')",
        // A signed scrub without its admission facts.
        "INSERT INTO import_scrubs(operation_id, import_operation_id, origin, state) VALUES('other','import_op_1','signed','intent')",
        // An unknown import.
        "INSERT INTO import_scrubs(operation_id, import_operation_id, origin, state) VALUES('import_op_9','import_op_9','failed_step','intent')",
    ] {
        assert!(c.execute(sql, []).is_err(), "{sql}");
    }
}

fn scrub_of(import: &ProvisionIntent, n: u32) -> ScrubIntent {
    ScrubIntent {
        operation_id: id(&format!("scrub_op_{n}")),
        idempotency_key: id(&format!("scrub_key_{n}")),
        grant_id: id(&format!("scrub_grant_{n}")),
        nonce: id(&format!("scrub_nonce_{n}")),
        plan_digest: digest('e'),
        grant_digest: digest('f'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        import_operation_id: import.operation_id.clone(),
        site_id: import.site_id.clone(),
        archive_sha256: facts().archive_sha256,
        expires_at: time(10000),
    }
}

#[test]
fn a_signed_scrub_of_an_ended_import_is_admitted_once_and_replays() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    ledger.record_import(&one, &facts(), time(1000)).unwrap();
    fail_at(&mut ledger, &one, ImportStep::Files);
    ledger.begin_failed_step_scrub(&one.operation_id).unwrap();
    ledger
        .finish_import_scrub(&one.operation_id, false)
        .unwrap();
    let before = ledger.admission_count().unwrap();
    let scrub = scrub_of(&one, 1);
    let Admitted::New(recorded) = ledger.record_scrub(&scrub, time(1100)).unwrap() else {
        panic!("not new");
    };
    assert_eq!(
        (recorded.origin, recorded.state),
        (ScrubOrigin::Signed, StepState::Intent)
    );
    assert_eq!(ledger.admission_count().unwrap(), before + 1);
    assert!(matches!(
        ledger.record_scrub(&scrub, time(1101)).unwrap(),
        Admitted::Existing(_)
    ));
    let mut other = scrub.clone();
    other.plan_digest = digest('9');
    assert_eq!(
        ledger.record_scrub(&other, time(1102)).err(),
        Some(JournalError::Conflict),
        "the same key with another plan"
    );
    assert_eq!(
        ledger.record_scrub(&scrub_of(&one, 2), time(1103)).err(),
        Some(JournalError::Busy),
        "an open scrub blocks another"
    );
    let import = ledger
        .finish_import_scrub(&scrub.operation_id, true)
        .unwrap();
    assert_eq!(
        import
            .scrubs
            .iter()
            .map(|row| (row.origin, row.state))
            .collect::<Vec<_>>(),
        [
            (ScrubOrigin::FailedStep, StepState::Failed),
            (ScrubOrigin::Signed, StepState::Done)
        ]
    );
    // A later signed scrub of the same import may run again.
    assert!(matches!(
        ledger.record_scrub(&scrub_of(&one, 3), time(1104)).unwrap(),
        Admitted::New(_)
    ));
    let (stored, import_op) = ledger
        .signed_scrub_status(&scrub.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        (stored.state, import_op),
        (StepState::Done, one.operation_id.clone())
    );
    assert_eq!(ledger.signed_scrub_status(&one.operation_id).unwrap(), None);
    drop(ledger);
    assert!(state.open().is_ok());
}

#[test]
fn a_signed_scrub_needs_the_signed_import_in_an_ended_state() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    ledger.record_import(&one, &facts(), time(1000)).unwrap();
    assert_eq!(
        ledger.record_scrub(&scrub_of(&one, 1), time(1001)).err(),
        Some(JournalError::Busy),
        "a running import is unresolved"
    );
    fail_at(&mut ledger, &one, ImportStep::Observe);
    let mut wrong = scrub_of(&one, 2);
    wrong.site_id = SiteId::try_from("blog9".to_owned()).unwrap();
    assert_eq!(
        ledger.record_scrub(&wrong, time(1002)).err(),
        Some(JournalError::Conflict)
    );
    let mut wrong = scrub_of(&one, 3);
    wrong.archive_sha256 = digest('0');
    assert_eq!(
        ledger.record_scrub(&wrong, time(1003)).err(),
        Some(JournalError::Conflict)
    );
    let mut wrong = scrub_of(&one, 4);
    wrong.import_operation_id = id("import_op_9");
    assert_eq!(
        ledger.record_scrub(&wrong, time(1004)).err(),
        Some(JournalError::Conflict)
    );
    let mut wrong = scrub_of(&one, 5);
    wrong.host_epoch = id("epoch_other");
    assert_eq!(
        ledger.record_scrub(&wrong, time(1005)).err(),
        Some(JournalError::Conflict)
    );
    let mut reused = scrub_of(&one, 6);
    reused.nonce = one.nonce.clone();
    assert_eq!(
        ledger.record_scrub(&reused, time(1006)).err(),
        Some(JournalError::Conflict),
        "the import's nonce"
    );
    let mut late = scrub_of(&one, 7);
    late.expires_at = time(1007);
    assert_eq!(
        ledger.record_scrub(&late, time(1007)).err(),
        Some(JournalError::Expired)
    );
    // A plain provision is not an import.
    let two = site(2);
    ledger.record_provision(&two, time(1008)).unwrap();
    ledger.quarantine_provision(&two.operation_id).unwrap();
    let mut plain = scrub_of(&two, 8);
    plain.archive_sha256 = facts().archive_sha256;
    assert_eq!(
        ledger.record_scrub(&plain, time(1009)).err(),
        Some(JournalError::Conflict)
    );
}

/// D-067 (W478): a successful scrub of a quarantined import releases its
/// hostname, so the same site can be imported again under a new site ID; the
/// old site ID stays taken. A failed scrub keeps the hostname.
#[test]
fn a_scrubbed_failed_import_releases_its_hostname() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    ledger.record_import(&one, &facts(), time(1000)).unwrap();
    fail_at(&mut ledger, &one, ImportStep::Database);
    ledger.begin_failed_step_scrub(&one.operation_id).unwrap();
    ledger.finish_import_scrub(&one.operation_id, true).unwrap();
    let released = ledger.provision_status(&one.operation_id).unwrap().unwrap();
    assert_eq!(released.state, ProvisionState::Quarantined);
    assert!(
        released.intent.hostname.as_str().starts_with("released-")
            && released.intent.hostname.as_str().ends_with(".invalid"),
        "{}",
        released.intent.hostname.as_str()
    );
    let mut again = site(2);
    again.hostname = one.hostname.clone();
    ledger.record_import(&again, &facts(), time(1100)).unwrap();
    let mut same_id = site(3);
    same_id.site_id = one.site_id.clone();
    assert!(
        ledger
            .record_import(&same_id, &facts(), time(1200))
            .is_err(),
        "the site ID stays taken"
    );

    let state = State::new();
    let mut ledger = state.init();
    ledger.record_import(&one, &facts(), time(1000)).unwrap();
    fail_at(&mut ledger, &one, ImportStep::Database);
    ledger.begin_failed_step_scrub(&one.operation_id).unwrap();
    ledger
        .finish_import_scrub(&one.operation_id, false)
        .unwrap();
    assert_eq!(
        ledger
            .provision_status(&one.operation_id)
            .unwrap()
            .unwrap()
            .intent
            .hostname,
        one.hostname,
        "a failed scrub keeps the hostname"
    );
    let mut again = site(2);
    again.hostname = one.hostname.clone();
    assert!(ledger.record_import(&again, &facts(), time(1100)).is_err());
}

/// D-067: an import scrubbed before D-067 (its row still holds the hostname)
/// gives the hostname up when a new import asks for it.
#[test]
fn an_earlier_scrubbed_import_gives_its_hostname_to_a_new_import() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    ledger.record_import(&one, &facts(), time(1000)).unwrap();
    fail_at(&mut ledger, &one, ImportStep::Database);
    ledger.begin_failed_step_scrub(&one.operation_id).unwrap();
    ledger.finish_import_scrub(&one.operation_id, true).unwrap();
    drop(ledger);
    // As a pre-D-067 journal would hold it.
    state.sql(&format!(
        "UPDATE provisions SET hostname='{}' WHERE operation_id='{}'",
        one.hostname.as_str(),
        one.operation_id.as_str()
    ));
    let mut ledger = state.open().unwrap();
    let mut again = site(2);
    again.hostname = one.hostname.clone();
    ledger.record_import(&again, &facts(), time(1100)).unwrap();
    assert!(
        ledger
            .provision_status(&one.operation_id)
            .unwrap()
            .unwrap()
            .intent
            .hostname
            .as_str()
            .starts_with("released-")
    );
}

/// D-074: the facts of a static site: no database dump.
fn static_facts() -> ImportFacts {
    ImportFacts {
        dump_bytes: 0,
        ..facts()
    }
}

fn finish_import(ledger: &mut FixtureJournal, provision: &ProvisionIntent) {
    reach_recipe(ledger, provision);
    let operation = &provision.operation_id;
    for step in ImportStep::ALL {
        ledger.begin_import_step(operation, step).unwrap();
        ledger.finish_import_step(operation, step, true).unwrap();
    }
    ledger
        .finish_step(operation, ProvisionStep::Recipe, true)
        .unwrap();
    for step in [ProvisionStep::PhpUnits, ProvisionStep::Verify] {
        ledger.begin_step(operation, step, "resource").unwrap();
        ledger.finish_step(operation, step, true).unwrap();
    }
}

#[test]
fn static_ejection_requires_the_exact_completed_single_name_import() {
    let state = State::new();
    let mut ledger = state.init();
    let [wordpress, aliased, single] = [site(1), site(2), site(3)];
    let alias = Hostname::try_from("alias.example.test".to_owned()).unwrap();
    let aliased_facts = ImportFacts {
        alias_hostname: Some(alias),
        ..static_facts()
    };
    for (provision, facts) in [(&wordpress, facts()), (&aliased, aliased_facts)] {
        ledger.record_import(provision, &facts, time(1000)).unwrap();
        finish_import(&mut ledger, provision);
    }
    ledger
        .record_import(&single, &static_facts(), time(1000))
        .unwrap();
    let ejection = intent(1);
    let admissions = ledger.admission_count().unwrap();
    for provision in [&wordpress, &aliased, &single] {
        assert_eq!(
            ledger.record_static_ejection_intent(
                &ejection,
                &provision.site_id,
                &provision.hostname,
                time(1001),
            ),
            Err(JournalError::Conflict)
        );
    }
    finish_import(&mut ledger, &single);
    assert_eq!(
        ledger.record_static_ejection_intent(
            &ejection,
            &single.site_id,
            &aliased.hostname,
            time(1001),
        ),
        Err(JournalError::Conflict)
    );
    assert_eq!(ledger.admission_count().unwrap(), admissions);
    assert_eq!(ledger.status(&ejection.operation_id).unwrap(), None);
    assert_eq!(ledger.ejection_site(&ejection.operation_id).unwrap(), None);
    assert!(matches!(
        ledger
            .record_static_ejection_intent(&ejection, &single.site_id, &single.hostname, time(1001))
            .unwrap(),
        Admitted::New(_)
    ));
    drop(ledger);

    let mut ledger = state.open().unwrap();
    assert_eq!(
        ledger
            .static_ejection_hostname(&ejection.operation_id)
            .unwrap(),
        Some(single.hostname.clone())
    );
    assert_eq!(ledger.admission_count().unwrap(), admissions + 1);
    assert!(matches!(
        ledger
            .record_static_ejection_intent(&ejection, &single.site_id, &single.hostname, time(1001))
            .unwrap(),
        Admitted::Existing(_)
    ));
    assert_eq!(
        ledger.record_ejection_intent(&ejection, &single.site_id, time(1001)),
        Err(JournalError::Conflict)
    );
    assert_eq!(
        ledger.record_static_ejection_intent(
            &ejection,
            &aliased.site_id,
            &single.hostname,
            time(1001),
        ),
        Err(JournalError::Conflict)
    );
    drop(ledger);

    state.sql("DELETE FROM import_steps WHERE operation_id='import_op_3' AND position=5");
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    state.sql("INSERT INTO import_steps VALUES('import_op_3',5,'done')");
    drop(state.open().unwrap());
    state.sql("UPDATE static_ejections SET hostname='different.example.test'");
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
}

#[test]
fn v41_migration_keeps_the_existing_ejection_and_admission_count() {
    let state = State::new();
    let mut ledger = state.init();
    let wordpress = site(1);
    ledger
        .record_import(&wordpress, &facts(), time(1000))
        .unwrap();
    finish_import(&mut ledger, &wordpress);
    let ejection = intent(1);
    ledger
        .record_ejection_intent(&ejection, &wordpress.site_id, time(1001))
        .unwrap();
    let recorded = ledger
        .record_observation(
            &ejection.operation_id,
            Some(&ejection.target_generation),
            Some(&ejection.target_digest),
        )
        .unwrap();
    let admissions = ledger.admission_count().unwrap();
    drop(ledger);

    state.sql("DROP TABLE caddy_generations; DROP TABLE app_fullstack_specs; DROP TABLE credential_rotations; DROP TABLE app_lifecycles; DROP TABLE app_release_steps; DROP TABLE app_releases; DROP TABLE apps; DROP TABLE static_ejections; PRAGMA user_version=41;");
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let mut ledger = state.migrate().unwrap();
    assert_eq!(
        ledger.status(&ejection.operation_id).unwrap(),
        Some(recorded)
    );
    assert_eq!(ledger.admission_count().unwrap(), admissions);
    assert_eq!(
        ledger.ejected_sites().unwrap(),
        std::slice::from_ref(&wordpress.site_id)
    );
    assert_eq!(
        ledger
            .static_ejection_hostname(&ejection.operation_id)
            .unwrap(),
        None
    );
    assert!(matches!(
        ledger
            .record_ejection_intent(&ejection, &wordpress.site_id, time(1001))
            .unwrap(),
        Admitted::Existing(_)
    ));
}

/// D-074: a v25 journal migrates to v26 by a rebuild of `imports` that keeps
/// every import and its steps; it then records a static import, never one
/// that is also renamed.
#[test]
fn a_v25_journal_migrates_and_records_a_static_import() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    ledger.record_import(&one, &facts(), time(1000)).unwrap();
    reach_recipe(&mut ledger, &one);
    ledger
        .begin_import_step(&one.operation_id, ImportStep::Intake)
        .unwrap();
    let before = ledger.import_status(&one.operation_id).unwrap().unwrap();
    drop(ledger);
    state.sql(&legacy_import_schema(25));
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let ledger = state.migrate().unwrap();
    assert_eq!(
        ledger.import_status(&one.operation_id).unwrap().unwrap(),
        before
    );
    drop(ledger);
    // A migrated journal without a running provision records a static import.
    let empty = State::new();
    drop(empty.init());
    empty.sql(&legacy_import_schema(25));
    drop(empty.migrate().unwrap());
    let state = empty;
    let mut ledger = state.open().unwrap();
    let two = site(2);
    assert!(static_facts().is_static() && !facts().is_static());
    assert_eq!(
        ledger
            .record_import(
                &two,
                &ImportFacts {
                    dump_bytes: 0,
                    ..renamed_facts()
                },
                time(1100)
            )
            .err(),
        Some(JournalError::Conflict)
    );
    ledger
        .record_import(&two, &static_facts(), time(1101))
        .unwrap();
    drop(ledger);
    let ledger = state.open().unwrap();
    assert_eq!(
        ledger
            .import_status(&two.operation_id)
            .unwrap()
            .unwrap()
            .facts,
        static_facts()
    );
}

#[test]
fn a_v26_journal_preserves_existing_static_imports_and_reserves_an_alias() {
    let state = State::new();
    let mut ledger = state.init();
    let first = site(1);
    ledger
        .record_import(&first, &static_facts(), time(1000))
        .unwrap();
    fail_at(&mut ledger, &first, ImportStep::Observe);
    let saved = ledger.import_status(&first.operation_id).unwrap().unwrap();
    drop(ledger);

    state.sql("PRAGMA foreign_keys=OFF; DROP TABLE caddy_generations; DROP TABLE app_fullstack_specs; DROP TABLE credential_rotations; DROP TABLE app_lifecycles; DROP TABLE app_release_steps; DROP TABLE app_releases; DROP TABLE apps; DROP TABLE static_ejections; DROP TABLE proxy_routes; DROP TABLE dns_change_sets; DROP TABLE dns_changes; DROP TABLE dns_imports; DROP TABLE restore_steps; DROP TABLE restore_attempts; DROP TABLE site_restores; DROP TABLE clone_scrub_grants; DROP TABLE quota_changes; DROP TABLE deletions; CREATE TEMP TABLE p32 AS SELECT * FROM provisions; DROP TABLE provisions; CREATE TABLE provisions (operation_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL, grant_digest TEXT NOT NULL, host_id TEXT NOT NULL, host_epoch TEXT NOT NULL, site_id TEXT NOT NULL UNIQUE, hostname TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('running','succeeded','quarantined','adopted'))) STRICT; INSERT INTO provisions SELECT * FROM temp.p32; DROP TABLE temp.p32; CREATE UNIQUE INDEX one_running_provision ON provisions((1)) WHERE state='running'; DROP TABLE update_rollbacks; DROP TABLE update_steps; DROP TABLE update_components; DROP INDEX one_open_update; DROP TABLE updates; DROP INDEX one_retirement; DROP TABLE retirements; DROP TABLE clone_scrubs; DROP TABLE clone_steps; DROP TABLE clones; DROP TABLE certificate_aliases; DROP TABLE import_aliases; PRAGMA user_version=26;");
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let mut ledger = state.migrate().unwrap();
    assert_eq!(
        ledger.import_status(&first.operation_id).unwrap(),
        Some(saved)
    );

    let second = site(2);
    let mut alias = ImportFacts {
        alias_hostname: Some(first.hostname.clone()),
        ..static_facts()
    };
    assert_eq!(
        ledger.record_import(&second, &alias, time(1100)).err(),
        Some(JournalError::Consumed)
    );
    let other = site(3);
    alias.alias_hostname = Some(other.hostname.clone());
    ledger.record_import(&second, &alias, time(1101)).unwrap();
    drop(ledger);

    let mut ledger = state.open().unwrap();
    assert_eq!(
        ledger
            .import_status(&second.operation_id)
            .unwrap()
            .unwrap()
            .facts,
        alias
    );
    assert_eq!(
        ledger.record_provision(&other, time(1102)).err(),
        Some(JournalError::Consumed)
    );
    assert_eq!(
        ledger.record_import(&site(4), &alias, time(1103)).err(),
        Some(JournalError::Consumed)
    );
}

#[test]
fn the_alias_stays_reserved_until_a_scrub_succeeds() {
    let state = State::new();
    let mut ledger = state.init();
    let old = site(1);
    let next = site(2);
    let alias = ImportFacts {
        alias_hostname: Some(next.hostname.clone()),
        ..static_facts()
    };
    ledger.record_import(&old, &alias, time(1000)).unwrap();
    fail_at(&mut ledger, &old, ImportStep::Observe);
    ledger.begin_failed_step_scrub(&old.operation_id).unwrap();
    ledger
        .finish_import_scrub(&old.operation_id, false)
        .unwrap();
    assert_eq!(
        ledger.record_provision(&next, time(1100)).err(),
        Some(JournalError::Consumed)
    );

    let scrub = scrub_of(&old, 1);
    ledger.record_scrub(&scrub, time(1101)).unwrap();
    ledger
        .finish_import_scrub(&scrub.operation_id, true)
        .unwrap();
    drop(ledger);

    let mut ledger = state.open().unwrap();
    let same_import = ledger.import_status(&old.operation_id).unwrap().unwrap();
    assert_eq!(same_import.facts, alias);
    ledger.record_provision(&next, time(1102)).unwrap();
}

#[test]
fn a_v27_static_alias_keeps_its_exact_certificate_scope_through_renewal() {
    let state = State::new();
    let mut ledger = state.init();
    let primary = site(1);
    let alias = site(2).hostname;
    ledger
        .record_import(
            &primary,
            &ImportFacts {
                alias_hostname: Some(alias.clone()),
                ..static_facts()
            },
            time(1000),
        )
        .unwrap();
    reach_recipe(&mut ledger, &primary);
    let op = &primary.operation_id;
    for step in ImportStep::ALL {
        ledger.begin_import_step(op, step).unwrap();
        ledger.finish_import_step(op, step, true).unwrap();
    }
    ledger.finish_step(op, ProvisionStep::Recipe, true).unwrap();
    for step in [ProvisionStep::PhpUnits, ProvisionStep::Verify] {
        ledger.begin_step(op, step, "resource").unwrap();
        ledger.finish_step(op, step, true).unwrap();
    }
    drop(ledger);
    state.sql("PRAGMA foreign_keys=OFF; DROP TABLE caddy_generations; DROP TABLE app_fullstack_specs; DROP TABLE credential_rotations; DROP TABLE app_lifecycles; DROP TABLE app_release_steps; DROP TABLE app_releases; DROP TABLE apps; DROP TABLE static_ejections; DROP TABLE proxy_routes; DROP TABLE dns_change_sets; DROP TABLE dns_changes; DROP TABLE dns_imports; DROP TABLE restore_steps; DROP TABLE restore_attempts; DROP TABLE site_restores; DROP TABLE clone_scrub_grants; DROP TABLE quota_changes; DROP TABLE deletions; CREATE TEMP TABLE p32 AS SELECT * FROM provisions; DROP TABLE provisions; CREATE TABLE provisions (operation_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL, grant_digest TEXT NOT NULL, host_id TEXT NOT NULL, host_epoch TEXT NOT NULL, site_id TEXT NOT NULL UNIQUE, hostname TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('running','succeeded','quarantined','adopted'))) STRICT; INSERT INTO provisions SELECT * FROM temp.p32; DROP TABLE temp.p32; CREATE UNIQUE INDEX one_running_provision ON provisions((1)) WHERE state='running'; DROP TABLE update_rollbacks; DROP TABLE update_steps; DROP TABLE update_components; DROP INDEX one_open_update; DROP TABLE updates; DROP INDEX one_retirement; DROP TABLE retirements; DROP TABLE clone_scrubs; DROP TABLE clone_steps; DROP TABLE clones; DROP TABLE certificate_aliases; PRAGMA user_version=27;");
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let mut ledger = state.migrate().unwrap();

    let mut intent = CertificateIntent {
        operation_id: id("cert_pair"),
        idempotency_key: id("cert_pair_idem"),
        grant_id: id("cert_pair_grant"),
        nonce: id("cert_pair_nonce"),
        plan_digest: digest('c'),
        grant_digest: digest('d'),
        host_id: primary.host_id,
        host_epoch: primary.host_epoch,
        site_id: primary.site_id,
        hostname: primary.hostname,
        alias_hostname: Some(site(3).hostname),
        expires_at: time(2000),
        renew_until: Some(time(10000)),
    };
    let before = ledger.admission_count().unwrap();
    assert_eq!(
        ledger.record_certificate(&intent, time(1100)).err(),
        Some(JournalError::Consumed)
    );
    assert_eq!(ledger.admission_count().unwrap(), before);
    intent.alias_hostname = Some(alias.clone());
    ledger.record_certificate(&intent, time(1101)).unwrap();
    ledger
        .finish_certificate(&intent.operation_id, Some((&digest('e'), time(9000))))
        .unwrap();
    drop(ledger);
    let mut ledger = state.open().unwrap();
    assert!(matches!(
        ledger.record_certificate(&intent, time(1102)),
        Ok(Admitted::Existing(_))
    ));
    let due = ledger.due_renewals(time(1103)).unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].alias_hostname, Some(alias.clone()));
    let renewal = ledger
        .begin_renewal(&due[0], &id("pair_renewal"), time(1103))
        .unwrap();
    ledger
        .finish_renewal(&renewal.renewal_id, Some((&digest('f'), time(9500))))
        .unwrap();
    assert_eq!(
        ledger.installed_certificate_alias(&intent.site_id).unwrap(),
        Some(alias)
    );

    intent.operation_id = id("cert_single");
    intent.idempotency_key = id("cert_single_idem");
    intent.grant_id = id("cert_single_grant");
    intent.nonce = id("cert_single_nonce");
    intent.alias_hostname = None;
    assert_eq!(
        ledger.record_certificate(&intent, time(1104)).err(),
        Some(JournalError::Consumed)
    );
    assert_eq!(ledger.admission_count().unwrap(), before + 1);
}

#[test]
fn static_ejected_sites_and_operation_records_track_single_name_static_ejections() {
    let state = State::new();
    let mut ledger = state.init();
    let static_site = site(1);
    ledger
        .record_import(&static_site, &static_facts(), time(1000))
        .unwrap();
    reach_recipe(&mut ledger, &static_site);
    for step in ImportStep::ALL {
        ledger
            .begin_import_step(&static_site.operation_id, step)
            .unwrap();
        ledger
            .finish_import_step(&static_site.operation_id, step, true)
            .unwrap();
    }
    ledger
        .finish_step(&static_site.operation_id, ProvisionStep::Recipe, true)
        .unwrap();
    for step in [ProvisionStep::PhpUnits, ProvisionStep::Verify] {
        ledger
            .begin_step(&static_site.operation_id, step, "resource")
            .unwrap();
        ledger
            .finish_step(&static_site.operation_id, step, true)
            .unwrap();
    }

    let intent = rustiron_journal::Intent {
        operation_id: id("op_static_eject_1"),
        idempotency_key: id("key_static_eject_1"),
        grant_id: id("grant_static_eject_1"),
        nonce: id("nonce_static_eject_1"),
        plan_digest: digest('1'),
        grant_digest: digest('2'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        resource_id: id("ols_lab_listener"),
        predecessor_generation: id("g1"),
        predecessor_digest: digest('3'),
        target_generation: id("g2"),
        target_digest: digest('4'),
        expires_at: time(2000),
        compensation_valid_until: time(2100),
    };
    ledger
        .record_static_ejection_intent(
            &intent,
            &static_site.site_id,
            &static_site.hostname,
            time(1200),
        )
        .unwrap();
    // Not succeeded yet, so static_ejected_sites is still empty, while
    // records_as_process_owner exposes the open static_ejection hostname.
    assert!(ledger.static_ejected_sites().unwrap().is_empty());
    let open_records = FixtureJournal::records_as_process_owner(
        &state.0,
        &id("host_fixture"),
        &id("epoch_fixture"),
        &intent.operation_id,
        None,
    )
    .unwrap();
    assert_eq!(open_records.ejection, Some(static_site.site_id.clone()));
    assert_eq!(
        open_records.static_ejection,
        Some(static_site.hostname.clone())
    );
    ledger.mark_effect_attempted(&intent.operation_id).unwrap();
    ledger
        .record_observation(
            &intent.operation_id,
            Some(&intent.target_generation),
            Some(&intent.target_digest),
        )
        .unwrap();
    assert_eq!(
        ledger.static_ejected_sites().unwrap(),
        vec![static_site.site_id]
    );
}

#[test]
fn observe_reports_unreleased_import_alias_hostname_and_omits_released() {
    let state = State::new();
    let mut ledger = state.init();
    let plain = site(2);
    ledger
        .record_import(&plain, &static_facts(), time(1000))
        .unwrap();
    finish_import(&mut ledger, &plain);
    let aliased = site(1);
    let alias = Hostname::try_from("www.site1.example.test".to_owned()).unwrap();
    let aliased_facts = ImportFacts {
        alias_hostname: Some(alias.clone()),
        ..static_facts()
    };
    ledger
        .record_import(&aliased, &aliased_facts, time(1001))
        .unwrap();
    let seen =
        FixtureJournal::observe(&state.0, &id("host_fixture"), &id("epoch_fixture")).unwrap();
    assert_eq!(seen.provisions.len(), 2);
    assert_eq!(seen.provisions[0].alias_hostname, None);
    assert_eq!(
        seen.provisions[1].alias_hostname.as_deref(),
        Some(alias.as_str())
    );

    // Scrubbing a failed import releases its alias, so observe no longer reports it.
    fail_at(&mut ledger, &aliased, ImportStep::Observe);
    ledger
        .begin_failed_step_scrub(&aliased.operation_id)
        .unwrap();
    ledger
        .finish_import_scrub(&aliased.operation_id, true)
        .unwrap();
    let after =
        FixtureJournal::observe(&state.0, &id("host_fixture"), &id("epoch_fixture")).unwrap();
    assert_eq!(after.provisions[1].alias_hostname, None);
}
