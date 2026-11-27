//! Multi-step provision journal behavior on real SQLite; no host effects.
use rustiron_contracts::approval::{Hostname, SiteId};
use rustiron_journal::{
    Admitted, FixtureJournal, JournalError, ProvisionIntent, ProvisionState, ProvisionStep,
    StepState,
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
            "ri-provision-{}-{}",
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

fn site(n: u32) -> ProvisionIntent {
    ProvisionIntent {
        operation_id: id(&format!("prov_op_{n}")),
        idempotency_key: id(&format!("prov_key_{n}")),
        grant_id: id(&format!("prov_grant_{n}")),
        nonce: id(&format!("prov_nonce_{n}")),
        plan_digest: digest('a'),
        grant_digest: digest('b'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: SiteId::try_from(format!("blog{n}")).unwrap(),
        hostname: Hostname::try_from(format!("blog{n}.example.test")).unwrap(),
        expires_at: time(10000),
    }
}

fn run_all(ledger: &mut FixtureJournal, intent: &ProvisionIntent) {
    for step in ProvisionStep::ALL {
        ledger
            .begin_step(&intent.operation_id, step, "resource")
            .unwrap();
        ledger
            .finish_step(&intent.operation_id, step, true)
            .unwrap();
    }
}

#[test]
fn steps_run_in_order_and_complete() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    assert!(matches!(
        ledger.record_provision(&one, time(1000)).unwrap(),
        Admitted::New(_)
    ));
    assert_eq!(
        ledger
            .begin_step(&one.operation_id, ProvisionStep::Directories, "dirs")
            .unwrap_err(),
        JournalError::Conflict,
        "out of order"
    );
    run_all(&mut ledger, &one);
    let done = ledger.provision_status(&one.operation_id).unwrap().unwrap();
    assert_eq!(done.state, ProvisionState::Succeeded);
    assert_eq!(done.steps.len(), 8);
    assert!(matches!(
        ledger.record_provision(&one, time(1001)).unwrap(),
        Admitted::Existing(_)
    ));
    drop(ledger);
    let ledger = state.open().unwrap();
    assert_eq!(
        ledger
            .provision_status(&one.operation_id)
            .unwrap()
            .unwrap()
            .state,
        ProvisionState::Succeeded
    );
}

#[test]
fn a_step_cannot_begin_twice_and_failure_quarantines() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    ledger.record_provision(&one, time(1000)).unwrap();
    ledger
        .begin_step(&one.operation_id, ProvisionStep::Account, "uid=3001")
        .unwrap();
    assert_eq!(
        ledger
            .begin_step(&one.operation_id, ProvisionStep::Account, "uid=3001")
            .unwrap_err(),
        JournalError::Conflict
    );
    assert_eq!(
        ledger
            .begin_step(&one.operation_id, ProvisionStep::Directories, "dirs")
            .unwrap_err(),
        JournalError::Conflict,
        "previous step still in intent"
    );
    let failed = ledger
        .finish_step(&one.operation_id, ProvisionStep::Account, false)
        .unwrap();
    assert_eq!(failed.state, ProvisionState::Quarantined);
    assert_eq!(failed.steps[0].state, StepState::Failed);
    let seen =
        FixtureJournal::observe(&state.0, &id("host_fixture"), &id("epoch_fixture")).unwrap();
    assert_eq!(seen.provisions[0].failed_step, Some(0));
    assert_eq!(
        ledger
            .begin_step(&one.operation_id, ProvisionStep::Directories, "dirs")
            .unwrap_err(),
        JournalError::Conflict
    );
    // A quarantined provision no longer blocks others.
    assert!(matches!(
        ledger.record_provision(&site(2), time(1001)).unwrap(),
        Admitted::New(_)
    ));
}

#[test]
fn restart_mid_step_keeps_intent_and_quarantine_infers_nothing() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    ledger.record_provision(&one, time(1000)).unwrap();
    ledger
        .begin_step(&one.operation_id, ProvisionStep::Account, "uid=3001")
        .unwrap();
    drop(ledger);
    let mut ledger = state.open().unwrap();
    let stored = ledger.provision_status(&one.operation_id).unwrap().unwrap();
    assert_eq!(stored.state, ProvisionState::Running);
    assert_eq!(stored.steps[0].state, StepState::Intent);
    assert_eq!(stored.steps[0].resource, "uid=3001");
    let quarantined = ledger.quarantine_provision(&one.operation_id).unwrap();
    assert_eq!(quarantined.state, ProvisionState::Quarantined);
    assert_eq!(quarantined.steps[0].state, StepState::Intent);
}

#[test]
fn admission_refusals() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    ledger.record_provision(&one, time(1000)).unwrap();
    assert_eq!(
        ledger.record_provision(&site(2), time(1001)).unwrap_err(),
        JournalError::Busy,
        "one running provision at a time"
    );
    let mut changed = one.clone();
    changed.plan_digest = digest('c');
    assert_eq!(
        ledger.record_provision(&changed, time(1001)).unwrap_err(),
        JournalError::Conflict
    );
    ledger.quarantine_provision(&one.operation_id).unwrap();
    // W190: a consumed site id or hostname is its own refusal, not a replay.
    for (mutate, refused) in [
        (
            (|i: &mut ProvisionIntent| i.site_id = SiteId::try_from("blog1".to_owned()).unwrap())
                as fn(&mut ProvisionIntent),
            JournalError::Consumed,
        ),
        (
            |i: &mut ProvisionIntent| {
                i.hostname = Hostname::try_from("blog1.example.test".to_owned()).unwrap()
            },
            JournalError::Consumed,
        ),
        (
            |i: &mut ProvisionIntent| i.nonce = id("prov_nonce_1"),
            JournalError::Conflict,
        ),
        (
            |i: &mut ProvisionIntent| i.grant_id = id("prov_grant_1"),
            JournalError::Conflict,
        ),
    ] {
        let mut reused = site(3);
        mutate(&mut reused);
        assert_eq!(
            ledger.record_provision(&reused, time(1002)).unwrap_err(),
            refused
        );
    }
    assert_eq!(
        ledger.record_provision(&site(4), time(999)).unwrap_err(),
        JournalError::ClockRollback
    );
    let mut late = site(5);
    late.expires_at = time(1003);
    assert_eq!(
        ledger.record_provision(&late, time(1003)).unwrap_err(),
        JournalError::Expired
    );
    let mut other_epoch = site(6);
    other_epoch.host_epoch = id("epoch_other");
    assert_eq!(
        ledger
            .record_provision(&other_epoch, time(1004))
            .unwrap_err(),
        JournalError::Conflict
    );
}

#[test]
fn fixture_nonce_cannot_be_reused_for_a_provision() {
    let state = State::new();
    let mut ledger = state.init();
    ledger.record_intent(&intent(1), time(1000)).unwrap();
    let mut reused = site(1);
    reused.nonce = intent(1).nonce;
    assert_eq!(
        ledger.record_provision(&reused, time(1001)).unwrap_err(),
        JournalError::Conflict
    );
}

#[test]
fn contradictory_rows_are_refused_on_open() {
    for sql in [
        "UPDATE provisions SET state='succeeded'",
        "UPDATE provision_steps SET state='failed' WHERE position=0",
        "DELETE FROM provision_steps WHERE position=0",
        "INSERT INTO provision_steps VALUES('ghost',0,'done','x')",
        "UPDATE provisions SET host_epoch='epoch_other'",
    ] {
        let state = State::new();
        let mut ledger = state.init();
        let one = site(1);
        ledger.record_provision(&one, time(1000)).unwrap();
        for step in [ProvisionStep::Account, ProvisionStep::Directories] {
            ledger.begin_step(&one.operation_id, step, "r").unwrap();
            ledger.finish_step(&one.operation_id, step, true).unwrap();
        }
        drop(ledger);
        state.sql("PRAGMA foreign_keys=OFF");
        state.sql(&format!("PRAGMA foreign_keys=OFF; {sql}"));
        assert_eq!(state.open().err(), Some(JournalError::Unavailable), "{sql}");
    }
}

#[test]
fn resource_descriptions_are_bounded_printable_ascii() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    ledger.record_provision(&one, time(1000)).unwrap();
    for bad in ["", "line\nbreak", &"x".repeat(257), "n\u{f6}"] {
        assert_eq!(
            ledger
                .begin_step(&one.operation_id, ProvisionStep::Account, bad)
                .unwrap_err(),
            JournalError::Conflict
        );
    }
}

#[test]
fn recorded_resources_cover_every_provision_state_and_survive_reopen() {
    let state = State::new();
    let mut ledger = state.init();
    let (one, two) = (site(1), site(2));
    ledger.record_provision(&one, time(1000)).unwrap();
    ledger
        .begin_step(
            &one.operation_id,
            ProvisionStep::Account,
            "Account rs_blog1 uid=3001",
        )
        .unwrap();
    ledger
        .finish_step(&one.operation_id, ProvisionStep::Account, false)
        .unwrap();
    ledger.record_provision(&two, time(1001)).unwrap();
    ledger
        .begin_step(
            &two.operation_id,
            ProvisionStep::Account,
            "Account rs_blog2 uid=3002",
        )
        .unwrap();
    drop(ledger);
    let ledger = state.open().unwrap();
    let mut accounts = ledger.recorded_resources(ProvisionStep::Account).unwrap();
    accounts.sort();
    assert_eq!(
        accounts,
        ["Account rs_blog1 uid=3001", "Account rs_blog2 uid=3002"]
    );
    assert!(
        ledger
            .recorded_resources(ProvisionStep::Labels)
            .unwrap()
            .is_empty()
    );
}

fn as_v3(state: &State) {
    state.sql(&format!("{TO_V16} DROP TABLE page_cache_optouts; DROP TABLE page_cache_optins; DROP TABLE capture_unclaimed; DROP TABLE capture_backup_policy; DROP TABLE probe_backup_policy; DROP TABLE capture_freeze; DROP TABLE capture_consistency; DROP TABLE capture_manifest; DROP TABLE capture_extent; DROP TABLE capture_retention; DROP TABLE capture_methods; DROP TABLE restore_probes; DROP TABLE captures; DROP TABLE ejections; PRAGMA user_version=3;"));
}

#[test]
fn a_valid_v3_journal_migrates_once_in_place_and_keeps_its_history() {
    // v3 → v5 in one step (v4 tables appended too).
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    ledger.record_provision(&one, time(1000)).unwrap();
    run_all(&mut ledger, &one);
    drop(ledger);
    as_v3(&state);
    assert_eq!(
        state.open().err(),
        Some(JournalError::Unavailable),
        "a v3 journal is never opened as v4"
    );
    let ledger =
        FixtureJournal::migrate(&state.0, id("host_fixture"), id("epoch_fixture")).unwrap();
    assert_eq!(
        ledger
            .provision_status(&one.operation_id)
            .unwrap()
            .unwrap()
            .state,
        ProvisionState::Succeeded
    );
    drop(ledger);
    assert!(state.open().is_ok());
    assert_eq!(
        FixtureJournal::migrate(&state.0, id("host_fixture"), id("epoch_fixture")).err(),
        Some(JournalError::Unavailable),
        "the current schema is not a migration source"
    );
}

#[test]
fn migration_refuses_a_wrong_identity_or_an_unexpected_shape() {
    let state = State::new();
    drop(state.init());
    as_v3(&state);
    assert!(FixtureJournal::migrate(&state.0, id("host_fixture"), id("epoch_other")).is_err());
    state.sql("CREATE TABLE extra (x INTEGER) STRICT;");
    assert_eq!(
        FixtureJournal::migrate(&state.0, id("host_fixture"), id("epoch_fixture")).err(),
        Some(JournalError::Unavailable)
    );
    state.sql("DROP TABLE extra; PRAGMA user_version=2;");
    assert_eq!(
        FixtureJournal::migrate(&state.0, id("host_fixture"), id("epoch_fixture")).err(),
        Some(JournalError::Unavailable)
    );
}

#[test]
fn succeeded_sites_omit_a_provision_that_has_not_finished() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    ledger.record_provision(&one, time(1000)).unwrap();
    assert!(ledger.succeeded_sites().unwrap().is_empty());
    run_all(&mut ledger, &one);
    assert_eq!(ledger.succeeded_sites().unwrap(), vec![one.site_id]);
}

fn eject_intent(n: u32) -> rustiron_journal::Intent {
    let mut intent = intent(n);
    intent.resource_id = id("ols_lab_listener");
    intent
}

#[test]
fn an_ejection_needs_a_succeeded_provision_and_happens_once() {
    let state = State::new();
    let mut ledger = state.init();
    let (one, two) = (site(1), site(2));
    ledger.record_provision(&one, time(1000)).unwrap();
    run_all(&mut ledger, &one);
    let blog1 = one.site_id.clone();
    assert_eq!(
        ledger
            .record_ejection_intent(&eject_intent(1), &two.site_id, time(1001))
            .err(),
        Some(JournalError::Conflict),
        "no provision"
    );
    let first = eject_intent(2);
    assert!(matches!(
        ledger
            .record_ejection_intent(&first, &blog1, time(1001))
            .unwrap(),
        Admitted::New(_)
    ));
    assert!(matches!(
        ledger
            .record_ejection_intent(&first, &blog1, time(1001))
            .unwrap(),
        Admitted::Existing(_)
    ));
    assert_eq!(
        ledger.ejection_site(&first.operation_id).unwrap(),
        Some(blog1.clone())
    );
    assert!(
        ledger.ejected_sites().unwrap().is_empty(),
        "not yet succeeded"
    );
    ledger
        .record_observation(
            &first.operation_id,
            Some(&first.target_generation),
            Some(&first.target_digest),
        )
        .unwrap();
    assert_eq!(
        ledger.ejected_sites().unwrap(),
        std::slice::from_ref(&blog1)
    );
    let mut again = eject_intent(3);
    again.predecessor_generation = id("new_generation");
    again.target_generation = id("third_generation");
    assert_eq!(
        ledger
            .record_ejection_intent(&again, &blog1, time(1002))
            .err(),
        Some(JournalError::Conflict),
        "already ejected"
    );
    drop(ledger);
    let ledger = state.open().unwrap();
    assert_eq!(ledger.ejected_sites().unwrap(), [blog1]);
}

/// W387: the admin helper reads which site an OLS operation ejects, so the
/// eject steps act only for an ejection and only on its own site.
#[test]
fn the_records_name_the_site_that_an_operation_ejects() {
    let state = State::new();
    let mut ledger = state.init();
    let (one, two) = (site(1), site(2));
    for provision in [&one, &two] {
        ledger.record_provision(provision, time(1000)).unwrap();
        run_all(&mut ledger, provision);
    }
    let first = eject_intent(3);
    ledger
        .record_ejection_intent(&first, &one.site_id, time(1001))
        .unwrap();
    ledger
        .record_observation(
            &first.operation_id,
            Some(&first.target_generation),
            Some(&first.target_digest),
        )
        .unwrap();
    let mut second = eject_intent(4);
    second.predecessor_generation = first.target_generation.clone();
    second.target_generation = id("third_generation");
    ledger
        .record_ejection_intent(&second, &two.site_id, time(1002))
        .unwrap();
    let records = |operation: &rustiron_contracts::Id| {
        FixtureJournal::records_as_process_owner(
            &state.0,
            &id("host_fixture"),
            &id("epoch_fixture"),
            operation,
            None,
        )
        .unwrap()
    };
    let current = records(&second.operation_id);
    assert_eq!(current.ejection, Some(two.site_id.clone()));
    assert_eq!(current.ejected, [one.site_id.clone(), two.site_id.clone()]);
    assert_eq!(
        records(&first.operation_id).ejection,
        Some(one.site_id.clone())
    );
    assert_eq!(
        records(&one.operation_id).ejection,
        None,
        "not an OLS operation"
    );
}

#[test]
fn an_ejection_row_without_a_succeeded_provision_is_refused_on_open() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    ledger.record_provision(&one, time(1000)).unwrap();
    run_all(&mut ledger, &one);
    let two = site(2);
    ledger.record_provision(&two, time(1001)).unwrap();
    ledger
        .begin_step(
            &two.operation_id,
            ProvisionStep::Account,
            "Account rs_blog2",
        )
        .unwrap();
    ledger
        .finish_step(&two.operation_id, ProvisionStep::Account, false)
        .unwrap();
    ledger
        .record_ejection_intent(&eject_intent(3), &one.site_id, time(1002))
        .unwrap();
    drop(ledger);
    // Foreign keys already refuse a row for an unknown site; a quarantined one
    // is caught by the open-time check.
    state.sql("UPDATE ejections SET site_id='blog2';");
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
}

#[test]
fn a_valid_v4_journal_migrates_to_v5() {
    let state = State::new();
    drop(state.init());
    state.sql(&format!("{TO_V16} DROP TABLE page_cache_optouts; DROP TABLE page_cache_optins; DROP TABLE capture_unclaimed; DROP TABLE capture_backup_policy; DROP TABLE probe_backup_policy; DROP TABLE capture_freeze; DROP TABLE capture_consistency; DROP TABLE capture_manifest; DROP TABLE capture_extent; DROP TABLE capture_retention; DROP TABLE capture_methods; DROP TABLE restore_probes; DROP TABLE captures; PRAGMA user_version=4;"));
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    drop(FixtureJournal::migrate(&state.0, id("host_fixture"), id("epoch_fixture")).unwrap());
    assert!(state.open().is_ok());
}

#[test]
fn a_valid_v5_journal_migrates_to_v6() {
    let state = State::new();
    drop(state.init());
    state.sql(&format!("{TO_V16} DROP TABLE page_cache_optouts; DROP TABLE page_cache_optins; DROP TABLE capture_unclaimed; DROP TABLE capture_backup_policy; DROP TABLE probe_backup_policy; DROP TABLE capture_freeze; DROP TABLE capture_consistency; DROP TABLE capture_manifest; DROP TABLE capture_extent; DROP TABLE capture_retention; DROP TABLE capture_methods; DROP TABLE restore_probes; PRAGMA user_version=5;"));
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    drop(FixtureJournal::migrate(&state.0, id("host_fixture"), id("epoch_fixture")).unwrap());
    assert!(state.open().is_ok());
}
