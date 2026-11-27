//! Real SQLite/process-lease fixture tests; no grant authority or host effects.
use rustiron_journal::{FixtureJournal, JournalError, RecordResult, RecordedState};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
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
            "ri-journal-{}-{}",
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
#[test]
fn explicit_init_reads_back_required_settings() {
    let state = State::new();
    let ledger = state.init();
    let settings = ledger.settings().unwrap();
    assert_eq!(settings.journal_mode, "delete");
    assert_eq!(settings.synchronous, 3);
    assert!(settings.foreign_keys);
    assert!(!settings.trusted_schema);
}
#[test]
fn missing_history_is_not_initialized_on_open() {
    let state = State::new();
    assert_eq!(state.open().err().unwrap(), JournalError::Unavailable);
    assert_eq!(fs::read_dir(&state.0).unwrap().count(), 0);
}
#[test]
fn init_refuses_any_existing_artifact() {
    let state = State::new();
    fs::write(state.0.join("unrecognized"), "INPUT_CANARY").unwrap();
    assert_eq!(
        FixtureJournal::initialize(&state.0, id("host_fixture"), id("epoch_fixture"))
            .err()
            .unwrap(),
        JournalError::Conflict
    );
    assert_eq!(
        fs::read(state.0.join("unrecognized")).unwrap(),
        b"INPUT_CANARY"
    );
}
#[test]
fn second_writer_cannot_open_same_lease() {
    let state = State::new();
    let _ledger = state.init();
    assert_eq!(state.open().err().unwrap(), JournalError::AccessDenied);
}

#[test]
fn an_exclusive_reader_and_a_writer_cannot_overlap() {
    let state = State::new();
    let ledger = state.init();
    let host = id("host_fixture");
    let epoch = id("epoch_fixture");
    let database = state.0.join("fixture-journal.sqlite");
    let before = fs::read(&database).unwrap();
    assert_eq!(
        FixtureJournal::with_exclusive_read_as_process_owner(&state.0, &host, &epoch, |_| {
            panic!("read ran while the writer held the lease")
        })
        .unwrap_err(),
        JournalError::AccessDenied
    );

    drop(ledger);
    FixtureJournal::with_exclusive_read_as_process_owner(&state.0, &host, &epoch, |locked| {
        assert_eq!(locked.admission_count().unwrap(), 0);
        assert_eq!(state.open().err(), Some(JournalError::AccessDenied));
    })
    .unwrap();

    assert_eq!(fs::read(database).unwrap(), before);
    assert!(state.open().is_ok());
}
#[test]
fn new_intent_and_exact_retry_are_distinct() {
    let state = State::new();
    let mut ledger = state.init();
    let intent = intent(1);
    assert!(matches!(
        ledger.record_intent(&intent, time(1000)).unwrap(),
        RecordResult::New(_)
    ));
    assert!(matches!(
        ledger.record_intent(&intent, time(1000)).unwrap(),
        RecordResult::Existing(_)
    ));
    assert_eq!(
        ledger.status(&intent.operation_id).unwrap().unwrap().state,
        RecordedState::Intent
    );
}
#[test]
fn restart_keeps_uncertain_intent_and_expired_exact_replay_is_status_only() {
    let state = State::new();
    let mut ledger = state.init();
    let first = intent(1);
    ledger.record_intent(&first, time(1000)).unwrap();
    drop(ledger);
    let mut ledger = state.open().unwrap();
    assert!(matches!(
        ledger.record_intent(&first, time(20000)).unwrap(),
        RecordResult::Existing(_)
    ));
    assert_eq!(
        ledger.status(&first.operation_id).unwrap().unwrap().state,
        RecordedState::Intent
    );
    assert_eq!(
        ledger.record_intent(&intent(2), time(1001)).unwrap_err(),
        JournalError::Busy
    );
}
#[test]
fn same_key_with_different_digest_is_conflict() {
    let state = State::new();
    let mut ledger = state.init();
    let first = intent(1);
    ledger.record_intent(&first, time(1000)).unwrap();
    let mut changed = first;
    changed.plan_digest = digest('e');
    assert_eq!(
        ledger.record_intent(&changed, time(1001)).unwrap_err(),
        JournalError::Conflict
    );
}
#[test]
fn same_key_with_different_signed_grant_bytes_is_conflict() {
    let state = State::new();
    let mut ledger = state.init();
    let first = intent(1);
    ledger.record_intent(&first, time(1000)).unwrap();
    let mut changed = first;
    changed.grant_digest = digest('e');
    assert_eq!(
        ledger.record_intent(&changed, time(1001)).unwrap_err(),
        JournalError::Conflict
    );
}
#[test]
fn reused_nonce_cannot_create_another_operation() {
    let state = State::new();
    let mut ledger = state.init();
    let first = intent(1);
    ledger.record_intent(&first, time(1000)).unwrap();
    ledger
        .record_observation(
            &first.operation_id,
            Some(&first.target_generation),
            Some(&first.target_digest),
        )
        .unwrap();
    let mut second = intent(2);
    second.nonce = first.nonce;
    assert_eq!(
        ledger.record_intent(&second, time(1001)).unwrap_err(),
        JournalError::Conflict
    );
}
#[test]
fn reused_grant_id_cannot_create_another_operation() {
    let state = State::new();
    let mut ledger = state.init();
    let first = intent(1);
    ledger.record_intent(&first, time(1000)).unwrap();
    ledger
        .record_observation(
            &first.operation_id,
            Some(&first.target_generation),
            Some(&first.target_digest),
        )
        .unwrap();
    let mut second = intent(2);
    second.grant_id = first.grant_id;
    assert_eq!(
        ledger.record_intent(&second, time(1001)).unwrap_err(),
        JournalError::Conflict
    );
}
#[test]
fn correct_generation_with_wrong_bytes_is_not_success() {
    let state = State::new();
    let mut ledger = state.init();
    let first = intent(1);
    ledger.record_intent(&first, time(1000)).unwrap();
    assert_eq!(
        ledger
            .record_observation(
                &first.operation_id,
                Some(&first.target_generation),
                Some(&digest('e'))
            )
            .unwrap()
            .state,
        RecordedState::NeedsAttention
    );
    assert_eq!(
        ledger.record_intent(&intent(2), time(1001)).unwrap_err(),
        JournalError::Busy
    );
}
#[test]
fn missing_observation_blocks_new_work() {
    let state = State::new();
    let mut ledger = state.init();
    let first = intent(1);
    ledger.record_intent(&first, time(1000)).unwrap();
    assert_eq!(
        ledger
            .record_observation(&first.operation_id, None, None)
            .unwrap()
            .state,
        RecordedState::NeedsAttention
    );
    drop(ledger);
    let mut ledger = state.open().unwrap();
    assert_eq!(
        ledger.record_intent(&intent(2), time(1001)).unwrap_err(),
        JournalError::Busy
    );
}
#[test]
fn complete_target_report_can_be_recorded_but_not_overwritten() {
    let state = State::new();
    let mut ledger = state.init();
    let first = intent(1);
    ledger.record_intent(&first, time(1000)).unwrap();
    assert_eq!(
        ledger
            .record_observation(
                &first.operation_id,
                Some(&first.target_generation),
                Some(&first.target_digest)
            )
            .unwrap()
            .state,
        RecordedState::Succeeded
    );
    assert_eq!(
        ledger
            .record_observation(&first.operation_id, None, None)
            .unwrap_err(),
        JournalError::Conflict
    );
    assert!(matches!(
        ledger.record_intent(&intent(2), time(1001)).unwrap(),
        RecordResult::New(_)
    ));
}
#[test]
fn proven_predecessor_is_untouched_and_does_not_reuse_old_grant() {
    let state = State::new();
    let mut ledger = state.init();
    let first = intent(1);
    ledger.record_intent(&first, time(1000)).unwrap();
    assert_eq!(
        ledger
            .record_observation(
                &first.operation_id,
                Some(&first.predecessor_generation),
                Some(&first.predecessor_digest)
            )
            .unwrap()
            .state,
        RecordedState::Untouched
    );
    assert!(matches!(
        ledger.record_intent(&first, time(20000)).unwrap(),
        RecordResult::Existing(_)
    ));
}
#[test]
fn clock_rollback_blocks_new_admission() {
    let state = State::new();
    let mut ledger = state.init();
    let first = intent(1);
    ledger.record_intent(&first, time(1000)).unwrap();
    ledger
        .record_observation(
            &first.operation_id,
            Some(&first.target_generation),
            Some(&first.target_digest),
        )
        .unwrap();
    assert_eq!(
        ledger.record_intent(&intent(2), time(999)).unwrap_err(),
        JournalError::ClockRollback
    );
    assert_eq!(ledger.status(&id("operation_2")).unwrap(), None);
}
#[test]
fn exact_expiry_does_not_record_new_intent() {
    let state = State::new();
    let mut ledger = state.init();
    assert_eq!(
        ledger.record_intent(&intent(1), time(10000)).unwrap_err(),
        JournalError::Expired
    );
    assert_eq!(ledger.status(&id("operation_1")).unwrap(), None);
}
#[test]
fn different_host_epoch_is_denied_before_recording() {
    let state = State::new();
    let mut ledger = state.init();
    let mut first = intent(1);
    first.host_epoch = id("other_epoch");
    assert_eq!(
        ledger.record_intent(&first, time(1000)).unwrap_err(),
        JournalError::Conflict
    );
    assert_eq!(ledger.status(&id("operation_1")).unwrap(), None);
}
#[test]
fn wrong_expected_host_identity_cannot_open_ledger() {
    let state = State::new();
    drop(state.init());
    assert_eq!(
        FixtureJournal::open(&state.0, id("other"), id("epoch_fixture"))
            .err()
            .unwrap(),
        JournalError::Conflict
    );
}
#[test]
fn newer_schema_is_refused_without_rewriting_database() {
    let state = State::new();
    drop(state.init());
    state.sql("PRAGMA user_version=46");
    let path = state.0.join("fixture-journal.sqlite");
    let before = fs::read(&path).unwrap();
    assert_eq!(state.open().err().unwrap(), JournalError::Unavailable);
    assert_eq!(fs::read(path).unwrap(), before);
}
#[test]
fn corrupt_ledger_is_not_recreated_or_echoed() {
    let state = State::new();
    drop(state.init());
    let path = state.0.join("fixture-journal.sqlite");
    fs::write(&path, "INPUT_CANARY").unwrap();
    let error = state.open().err().unwrap();
    assert_eq!(error, JournalError::Unavailable);
    assert!(!error.to_string().contains("INPUT_CANARY"));
    assert_eq!(fs::read(path).unwrap(), b"INPUT_CANARY");
}
#[test]
fn deleted_ledger_is_not_recreated() {
    let state = State::new();
    drop(state.init());
    let path = state.0.join("fixture-journal.sqlite");
    fs::remove_file(&path).unwrap();
    assert_eq!(state.open().err().unwrap(), JournalError::Unavailable);
    assert!(!path.exists());
}
#[test]
fn foreign_application_is_refused() {
    let state = State::new();
    drop(state.init());
    state.sql("PRAGMA application_id=0");
    assert_eq!(state.open().err().unwrap(), JournalError::Unavailable);
}
#[test]
fn changed_schema_is_refused() {
    let state = State::new();
    drop(state.init());
    state.sql("CREATE TABLE extension_bag (payload TEXT)");
    assert_eq!(state.open().err().unwrap(), JournalError::Unavailable);
}
#[test]
fn invalid_stored_state_is_not_invented_as_success() {
    let state = State::new();
    let mut ledger = state.init();
    ledger.record_intent(&intent(1), time(1000)).unwrap();
    drop(ledger);
    state.sql("PRAGMA ignore_check_constraints=ON; UPDATE operations SET state='complete'");
    assert_eq!(state.open().err().unwrap(), JournalError::Unavailable);
}
#[test]
fn symlink_database_is_not_followed() {
    let state = State::new();
    drop(state.init());
    let path = state.0.join("fixture-journal.sqlite");
    fs::rename(&path, state.0.join("real.sqlite")).unwrap();
    std::os::unix::fs::symlink(state.0.join("real.sqlite"), &path).unwrap();
    assert_eq!(state.open().err().unwrap(), JournalError::AccessDenied);
}
#[test]
fn hardlinked_database_is_refused() {
    let state = State::new();
    drop(state.init());
    fs::hard_link(
        state.0.join("fixture-journal.sqlite"),
        state.0.join("alias"),
    )
    .unwrap();
    assert_eq!(state.open().err().unwrap(), JournalError::AccessDenied);
}
#[test]
fn public_database_mode_is_refused() {
    let state = State::new();
    drop(state.init());
    fs::set_permissions(
        state.0.join("fixture-journal.sqlite"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert_eq!(state.open().err().unwrap(), JournalError::AccessDenied);
}
#[test]
fn transaction_abort_after_insert_rolls_back_nonce_and_intent() {
    let state = State::new();
    let mut ledger = state.init();
    state.sql("CREATE TRIGGER abort_clock BEFORE UPDATE ON metadata BEGIN SELECT RAISE(ABORT,'INPUT_CANARY'); END");
    let first = intent(1);
    let error = ledger.record_intent(&first, time(1000)).unwrap_err();
    assert_eq!(error, JournalError::Unavailable);
    assert!(!error.to_string().contains("INPUT_CANARY"));
    assert_eq!(ledger.status(&first.operation_id).unwrap(), None);
    state.sql("DROP TRIGGER abort_clock");
    assert!(matches!(
        ledger.record_intent(&first, time(999)).unwrap(),
        RecordResult::New(_)
    ));
}

#[test]
fn fixture_history_capacity_never_prunes_consumed_nonces() {
    let state = State::new();
    let mut ledger = state.init();
    let first = intent(1);
    ledger.record_intent(&first, time(1000)).unwrap();
    ledger
        .record_observation(
            &first.operation_id,
            Some(&first.target_generation),
            Some(&first.target_digest),
        )
        .unwrap();
    state.sql("WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n<999) INSERT INTO operations SELECT 'history_op_'||n,'history_key_'||n,'history_grant_'||n,'history_nonce_'||n,plan_digest,grant_digest,host_id,host_epoch,resource_id,predecessor_generation,predecessor_digest,target_generation,target_digest,expires_at,compensation_valid_until,'succeeded',effect_attempted,compensation_attempts FROM seq CROSS JOIN operations WHERE operation_id='operation_1'");
    assert_eq!(
        ledger.record_intent(&intent(2), time(1001)).unwrap_err(),
        JournalError::Capacity
    );
    assert!(matches!(
        ledger.record_intent(&first, time(20000)).unwrap(),
        RecordResult::Existing(_)
    ));
}

#[test]
fn invalid_clock_metadata_is_unavailable_not_empty_history() {
    let state = State::new();
    drop(state.init());
    state.sql("UPDATE metadata SET last_time=9007199254740992");
    assert_eq!(state.open().err().unwrap(), JournalError::Unavailable);
}

#[test]
fn invalid_stored_identifier_is_not_a_resource_path() {
    let state = State::new();
    let mut ledger = state.init();
    ledger.record_intent(&intent(1), time(1000)).unwrap();
    drop(ledger);
    state.sql("UPDATE operations SET resource_id='../INPUT_CANARY'");
    assert_eq!(state.open().err().unwrap(), JournalError::Unavailable);
}

#[test]
fn failed_observation_write_cannot_record_success() {
    let state = State::new();
    let mut ledger = state.init();
    let first = intent(1);
    ledger.record_intent(&first, time(1000)).unwrap();
    state.sql("CREATE TRIGGER abort_observation AFTER UPDATE ON operations BEGIN SELECT RAISE(ABORT,'INPUT_CANARY'); END");
    assert_eq!(
        ledger
            .record_observation(
                &first.operation_id,
                Some(&first.target_generation),
                Some(&first.target_digest)
            )
            .unwrap_err(),
        JournalError::Unavailable
    );
    assert_eq!(
        ledger.status(&first.operation_id).unwrap().unwrap().state,
        RecordedState::Intent
    );
    assert_eq!(
        ledger.record_intent(&intent(2), time(1001)).unwrap_err(),
        JournalError::Busy
    );
}

#[test]
fn effect_attempt_mark_is_single_and_only_from_intent() {
    let state = State::new();
    let mut ledger = state.init();
    let first = intent(1);
    ledger.record_intent(&first, time(1000)).unwrap();
    let marked = ledger.mark_effect_attempted(&first.operation_id).unwrap();
    assert!(marked.effect_attempted && !marked.compensation_attempted);
    assert_eq!(
        ledger
            .mark_effect_attempted(&first.operation_id)
            .unwrap_err(),
        JournalError::Conflict
    );
    drop(ledger);
    let ledger = state.open().unwrap();
    assert!(
        ledger
            .status(&first.operation_id)
            .unwrap()
            .unwrap()
            .effect_attempted
    );
}

#[test]
fn compensation_needs_attempted_needs_attention_and_runs_once() {
    let state = State::new();
    let mut ledger = state.init();
    let first = intent(1);
    ledger.record_intent(&first, time(1000)).unwrap();
    ledger
        .record_observation(&first.operation_id, None, None)
        .unwrap();
    assert_eq!(
        ledger
            .begin_compensation(&first.operation_id, time(1001))
            .unwrap_err(),
        JournalError::Conflict,
        "no attempted effect"
    );
    let state2 = State::new();
    let mut ledger = state2.init();
    ledger.record_intent(&first, time(1000)).unwrap();
    ledger.mark_effect_attempted(&first.operation_id).unwrap();
    ledger
        .record_observation(&first.operation_id, None, None)
        .unwrap();
    assert_eq!(
        ledger
            .begin_compensation(&first.operation_id, time(999))
            .unwrap_err(),
        JournalError::ClockRollback
    );
    assert_eq!(
        ledger
            .begin_compensation(&first.operation_id, first.compensation_valid_until)
            .unwrap_err(),
        JournalError::Expired
    );
    let compensating = ledger
        .begin_compensation(&first.operation_id, time(1001))
        .unwrap();
    assert_eq!(compensating.state, RecordedState::Compensating);
    assert_eq!(
        ledger.record_intent(&intent(2), time(1002)).unwrap_err(),
        JournalError::Busy
    );
    let restored = ledger
        .record_observation(
            &first.operation_id,
            Some(&first.predecessor_generation),
            Some(&first.predecessor_digest),
        )
        .unwrap();
    assert_eq!(restored.state, RecordedState::FailedCompensated);
    assert_eq!(
        ledger
            .record_observation(
                &first.operation_id,
                Some(&first.target_generation),
                Some(&first.target_digest),
            )
            .unwrap_err(),
        JournalError::Conflict
    );
    assert_eq!(
        ledger
            .begin_compensation(&first.operation_id, time(1003))
            .unwrap_err(),
        JournalError::Conflict
    );
}

#[test]
fn inconsistent_compensation_flags_are_refused_on_open() {
    let state = State::new();
    let mut ledger = state.init();
    ledger.record_intent(&intent(1), time(1000)).unwrap();
    drop(ledger);
    state.sql("UPDATE operations SET compensation_attempts=1");
    assert_eq!(state.open().err().unwrap(), JournalError::Unavailable);
    state.sql("UPDATE operations SET compensation_attempts=0, state='compensating'");
    assert_eq!(state.open().err().unwrap(), JournalError::Unavailable);
}

#[test]
fn older_journal_versions_are_refused_not_migrated() {
    for version in [1, 2] {
        let state = State::new();
        drop(state.init());
        state.sql(&format!("PRAGMA user_version={version}"));
        assert_eq!(state.open().err().unwrap(), JournalError::Unavailable);
    }
}

#[test]
fn expected_generation_follows_the_latest_finished_operation_per_resource() {
    let state = State::new();
    let mut ledger = state.init();
    let resource = id("resource_fixture");
    assert_eq!(ledger.expected_generation(&resource, None).unwrap(), None);
    let first = intent(1);
    ledger.record_intent(&first, time(1000)).unwrap();
    assert_eq!(
        ledger.expected_generation(&resource, None).unwrap(),
        None,
        "an unresolved operation establishes nothing"
    );
    ledger
        .record_observation(
            &first.operation_id,
            Some(&first.target_generation),
            Some(&first.target_digest),
        )
        .unwrap();
    assert_eq!(
        ledger.expected_generation(&resource, None).unwrap(),
        Some((id("new_generation"), digest('d')))
    );
    let second = step(2, ("new_generation", 'd'), ("third_generation", 'f'));
    ledger.record_intent(&second, time(1001)).unwrap();
    ledger
        .record_observation(
            &second.operation_id,
            Some(&second.predecessor_generation),
            Some(&second.predecessor_digest),
        )
        .unwrap();
    assert_eq!(
        ledger.expected_generation(&resource, None).unwrap(),
        Some((id("new_generation"), digest('d'))),
        "an untouched operation keeps the generation it found established"
    );
    drop(ledger);
    let ledger = state.open().unwrap();
    assert_eq!(
        ledger.expected_generation(&resource, None).unwrap(),
        Some((id("new_generation"), digest('d')))
    );
    assert_eq!(
        ledger.expected_generation(&id("other"), None).unwrap(),
        None
    );
}

#[test]
fn resource_history_before_an_operation_excludes_it_and_later_ones() {
    use rustiron_journal::ResourceHistory as H;
    let state = State::new();
    let mut ledger = state.init();
    let resource = id("resource_fixture");
    let baseline = (id("old_generation"), digest('c'));
    let baseline = Some(&baseline);
    assert_eq!(
        ledger.resource_history(&resource, None, baseline).unwrap(),
        H::Empty
    );
    let first = intent(1);
    ledger.record_intent(&first, time(1000)).unwrap();
    assert_eq!(
        ledger.resource_history(&resource, None, baseline).unwrap(),
        H::Unresolved,
        "an unresolved operation is not an empty history"
    );
    assert_eq!(
        ledger
            .resource_history(&resource, Some(&first.operation_id), baseline)
            .unwrap(),
        H::Empty,
        "nothing came before the first operation"
    );
    ledger
        .record_observation(
            &first.operation_id,
            Some(&first.predecessor_generation),
            Some(&first.predecessor_digest),
        )
        .unwrap();
    let second = intent(2);
    ledger.record_intent(&second, time(1001)).unwrap();
    assert_eq!(
        ledger
            .resource_history(&resource, Some(&second.operation_id), baseline)
            .unwrap(),
        H::Established(id("old_generation"), digest('c')),
        "an untouched first operation re-establishes the baseline"
    );
    // W357: after the new intent, the latest-only query sees the unresolved
    // operation itself, so a check made after intent must use the history
    // before that operation instead.
    assert_eq!(
        ledger.expected_generation(&resource, baseline).unwrap(),
        None
    );
    assert_eq!(
        ledger.resource_history(&resource, Some(&id("operation_9")), baseline),
        Err(JournalError::Conflict),
        "an unknown operation is never an empty history"
    );
    assert_eq!(
        ledger.resource_history(&id("other"), Some(&second.operation_id), baseline),
        Err(JournalError::Conflict),
        "the operation must belong to the resource"
    );
    drop(ledger);
    // The helper rereads the same history for the operation it serves.
    let records = |operation: &rustiron_contracts::Id| {
        FixtureJournal::records_as_process_owner(
            &state.0,
            &id("host_fixture"),
            &id("epoch_fixture"),
            operation,
            baseline,
        )
        .unwrap()
        .ols_history
    };
    assert_eq!(records(&first.operation_id), Some(H::Empty));
    assert_eq!(
        records(&second.operation_id),
        Some(H::Established(id("old_generation"), digest('c')))
    );
    assert_eq!(
        records(&id("operation_9")),
        None,
        "no operation, no history"
    );
}

/// `intent(number)` moving the resource from `from` to `to`.
fn step(number: u32, from: (&str, char), to: (&str, char)) -> rustiron_journal::Intent {
    let mut intent = intent(number);
    intent.predecessor_generation = id(from.0);
    intent.predecessor_digest = digest(from.1);
    intent.target_generation = id(to.0);
    intent.target_digest = digest(to.1);
    intent
}

/// How a recorded operation ends, in the order the executor records it.
#[derive(Clone, Copy, Debug)]
enum End {
    /// Verified activation: the complete target observed.
    Succeeded,
    /// No effect: a refusal after intent records the plan predecessor.
    Refused,
    /// Reconcile of an interrupted operation found the predecessor.
    Reconciled,
    /// The single compensation restored the predecessor.
    Compensated,
}

fn finish(ledger: &mut FixtureJournal, intent: &rustiron_journal::Intent, at: u64, end: End) {
    let operation = &intent.operation_id;
    let predecessor = (
        Some(&intent.predecessor_generation),
        Some(&intent.predecessor_digest),
    );
    ledger.record_intent(intent, time(at)).unwrap();
    let state = match end {
        End::Succeeded => {
            ledger.mark_effect_attempted(operation).unwrap();
            ledger
                .record_observation(
                    operation,
                    Some(&intent.target_generation),
                    Some(&intent.target_digest),
                )
                .unwrap()
                .state
        }
        End::Refused => {
            ledger
                .record_observation(operation, predecessor.0, predecessor.1)
                .unwrap()
                .state
        }
        End::Reconciled => {
            ledger.mark_effect_attempted(operation).unwrap();
            ledger
                .record_observation(operation, predecessor.0, predecessor.1)
                .unwrap()
                .state
        }
        End::Compensated => {
            ledger.mark_effect_attempted(operation).unwrap();
            ledger.record_observation(operation, None, None).unwrap();
            ledger.begin_compensation(operation, time(at)).unwrap();
            ledger
                .record_observation(operation, predecessor.0, predecessor.1)
                .unwrap()
                .state
        }
    };
    let expected = match end {
        End::Succeeded => RecordedState::Succeeded,
        End::Refused | End::Reconciled => RecordedState::Untouched,
        End::Compensated => RecordedState::FailedCompensated,
    };
    assert_eq!(state, expected, "{end:?}");
}

/// W360 (B06/B08): a refusal, reconcile or compensation records its
/// predecessor, but only a verified activation establishes a generation.
/// W359 found a drift refusal after intent (`op_w359d1`) that made the
/// planted predecessor the established generation; the next activation
/// over the same drift then passed.
#[test]
fn only_a_verified_activation_establishes_a_generation() {
    let resource = id("resource_fixture");
    let established = || Some((id("gen_e"), digest('e')));
    for end in [End::Refused, End::Reconciled, End::Compensated] {
        let state = State::new();
        let mut ledger = state.init();
        finish(
            &mut ledger,
            &step(1, ("gen_0", '0'), ("gen_e", 'e')),
            1000,
            End::Succeeded,
        );
        assert_eq!(
            ledger.expected_generation(&resource, None).unwrap(),
            established()
        );
        // The predecessor the journal established: the history is unchanged.
        finish(
            &mut ledger,
            &step(2, ("gen_e", 'e'), ("gen_t", '1')),
            1001,
            end,
        );
        assert_eq!(
            ledger.expected_generation(&resource, None).unwrap(),
            established(),
            "{end:?} over the established generation"
        );
        // A predecessor the journal never established (a planted
        // generation): it stays unexplained.
        finish(
            &mut ledger,
            &step(3, ("gen_x", '2'), ("gen_t", '1')),
            1002,
            end,
        );
        assert_eq!(
            ledger.expected_generation(&resource, None).unwrap(),
            established(),
            "{end:?} over an unexplained generation must not explain it"
        );
        // Not even when it is the baseline: a host that served a real
        // generation is not back at the start.
        let baseline = (id("gen_0"), digest('0'));
        finish(
            &mut ledger,
            &step(4, ("gen_0", '0'), ("gen_t", '1')),
            1003,
            end,
        );
        assert_eq!(
            ledger
                .expected_generation(&resource, Some(&baseline))
                .unwrap(),
            established(),
            "{end:?} over the baseline after a real generation"
        );
        drop(ledger);
        let ledger = state.open().unwrap();
        assert_eq!(
            ledger
                .expected_generation(&resource, Some(&baseline))
                .unwrap(),
            established()
        );
        // The history before each operation, as the recheck after intent
        // and the helper read it.
        for operation in ["operation_2", "operation_3", "operation_4"] {
            assert_eq!(
                ledger
                    .resource_history(&resource, Some(&id(operation)), Some(&baseline))
                    .unwrap(),
                rustiron_journal::ResourceHistory::Established(id("gen_e"), digest('e')),
                "{end:?} before {operation}"
            );
        }
        // A later verified activation establishes its target as before.
        drop(ledger);
        let mut ledger = state.open().unwrap();
        finish(
            &mut ledger,
            &step(5, ("gen_e", 'e'), ("gen_t", '1')),
            1004,
            End::Succeeded,
        );
        assert_eq!(
            ledger.expected_generation(&resource, None).unwrap(),
            Some((id("gen_t"), digest('1')))
        );
    }
}

/// W360: before any verified activation, only the baseline (the empty OLS
/// bootstrap generation) can be re-established, so a failed bootstrap still
/// leaves the host at its start. Any other predecessor leaves the history
/// empty: the journal has established nothing.
#[test]
fn an_empty_history_re_establishes_only_the_baseline() {
    use rustiron_journal::ResourceHistory as H;
    let resource = id("resource_fixture");
    let baseline = (id("gen_0"), digest('0'));
    for end in [End::Refused, End::Reconciled, End::Compensated] {
        let state = State::new();
        let mut ledger = state.init();
        finish(
            &mut ledger,
            &step(1, ("gen_x", '2'), ("gen_t", '1')),
            1000,
            end,
        );
        assert_eq!(
            ledger
                .resource_history(&resource, None, Some(&baseline))
                .unwrap(),
            H::Empty,
            "{end:?} over a generation the journal never established"
        );
        finish(
            &mut ledger,
            &step(2, ("gen_0", '0'), ("gen_t", '1')),
            1001,
            end,
        );
        assert_eq!(
            ledger
                .resource_history(&resource, None, Some(&baseline))
                .unwrap(),
            H::Established(id("gen_0"), digest('0')),
            "{end:?} over the baseline"
        );
        assert_eq!(
            ledger.resource_history(&resource, None, None).unwrap(),
            H::Empty,
            "{end:?} with no baseline"
        );
        // Once the baseline is re-established, another predecessor still
        // does not replace it.
        finish(
            &mut ledger,
            &step(3, ("gen_x", '2'), ("gen_t", '1')),
            1002,
            end,
        );
        assert_eq!(
            ledger
                .expected_generation(&resource, Some(&baseline))
                .unwrap(),
            Some(baseline.clone()),
            "{end:?}"
        );
    }
}

/// W360: an unresolved operation is still the end of the history, and the
/// history before it skips nothing that came before.
#[test]
fn an_unresolved_operation_still_blocks_the_history() {
    use rustiron_journal::ResourceHistory as H;
    let state = State::new();
    let mut ledger = state.init();
    let resource = id("resource_fixture");
    finish(
        &mut ledger,
        &step(1, ("gen_0", '0'), ("gen_e", 'e')),
        1000,
        End::Succeeded,
    );
    finish(
        &mut ledger,
        &step(2, ("gen_x", '2'), ("gen_t", '1')),
        1001,
        End::Refused,
    );
    let third = step(3, ("gen_e", 'e'), ("gen_t", '1'));
    ledger.record_intent(&third, time(1002)).unwrap();
    assert_eq!(
        ledger.resource_history(&resource, None, None).unwrap(),
        H::Unresolved
    );
    assert_eq!(
        ledger
            .resource_history(&resource, Some(&third.operation_id), None)
            .unwrap(),
        H::Established(id("gen_e"), digest('e'))
    );
}

/// W381 (D-032): the boot guard reads the one unresolved operation of the
/// OLS resource. A settled row or a row of another resource is not pending.
/// A journal with two unresolved rows, which the schema index forbids, is
/// never resolved by choosing one.
#[test]
fn the_unresolved_operation_of_one_resource_is_read_without_choosing() {
    let state = State::new();
    let mut ledger = state.init();
    let resource = id("resource_fixture");
    assert_eq!(ledger.unresolved_operation(&resource).unwrap(), None);
    let first = intent(1);
    ledger.record_intent(&first, time(1000)).unwrap();
    let pending = ledger.unresolved_operation(&resource).unwrap().unwrap();
    assert_eq!(pending.intent, first);
    assert_eq!(pending.state, RecordedState::Intent);
    assert!(!pending.effect_attempted);
    assert_eq!(
        ledger.unresolved_operation(&id("other_resource")).unwrap(),
        None
    );
    ledger.mark_effect_attempted(&first.operation_id).unwrap();
    ledger
        .record_observation(&first.operation_id, None, None)
        .unwrap();
    let attention = ledger.unresolved_operation(&resource).unwrap().unwrap();
    assert_eq!(attention.state, RecordedState::NeedsAttention);
    assert!(attention.effect_attempted);
    ledger
        .begin_compensation(&first.operation_id, time(1001))
        .unwrap();
    assert_eq!(
        ledger
            .unresolved_operation(&resource)
            .unwrap()
            .unwrap()
            .state,
        RecordedState::Compensating
    );
    ledger
        .record_observation(
            &first.operation_id,
            Some(&first.predecessor_generation),
            Some(&first.predecessor_digest),
        )
        .unwrap();
    assert_eq!(ledger.unresolved_operation(&resource).unwrap(), None);
    drop(ledger);
    // A forged journal: the index dropped and two unresolved rows.
    state.sql(
        "DROP INDEX one_unresolved; \
         WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n<2) \
         INSERT INTO operations SELECT 'forged_op_'||n,'forged_key_'||n,'forged_grant_'||n,\
         'forged_nonce_'||n,plan_digest,grant_digest,host_id,host_epoch,resource_id,\
         predecessor_generation,predecessor_digest,target_generation,target_digest,expires_at,\
         compensation_valid_until,'intent',1,0 FROM seq CROSS JOIN operations \
         WHERE operation_id='operation_1'",
    );
    match state.open() {
        Ok(ledger) => assert_eq!(
            ledger.unresolved_operation(&resource).unwrap_err(),
            JournalError::Conflict
        ),
        Err(error) => assert_eq!(error, JournalError::Unavailable),
    }
}
