//! W381 (D-032, B10/B08): the decisions of the OLS boot guard.
//!
//! After a power cut between the switch and the verification, `current`
//! names the unverified target. The guard runs once per boot before OLS
//! starts. It puts `current` back on the journaled predecessor, or removes
//! it for a bootstrap activation, only when the journal holds an OLS
//! operation with its effect mark recorded and not settled, and `current`
//! is exactly that operation's target. Every other case changes nothing.
//! The guard records nothing in the journal.
//!
//! The include directory is fixed (`/etc/rustiron-ols`), so each live
//! `current` here is the finding each decision is given. The journal cases
//! use a real journal and the history rule of each build profile.

use std::{
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

use rustiron_contracts::{Id, Timestamp, approval::Sha256Digest};
use rustiron_executor::ols::{
    boot_guard::{
        GuardDecision, JournalFinding, KeepReason, LinkFinding, PendingActivation, decide,
        pending_activation, restored,
    },
    bootstrap_generation, generation_id,
};
use rustiron_journal::{FixtureJournal, Intent, RecordedState};
use sha2::{Digest, Sha256};

type Generation = (Id, Sha256Digest);

fn id(text: &str) -> Id {
    Id::try_from(text.to_owned()).unwrap()
}

fn sha(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn time(seconds: u64) -> Timestamp {
    Timestamp::try_from(seconds).unwrap()
}

/// A content-addressed generation (`r` + 16 hex of its digest).
fn generation(seed: &[u8]) -> Generation {
    let digest = sha(seed);
    (generation_id(&digest), digest)
}

fn pending(predecessor: Generation, target: Generation) -> PendingActivation {
    PendingActivation {
        operation_id: id("op_w381_1"),
        state: RecordedState::Intent,
        effect_attempted: true,
        established_before: Some(predecessor.clone()),
        predecessor,
        target,
    }
}

fn running() -> PendingActivation {
    pending(generation(b"predecessor"), generation(b"target"))
}

fn bootstrap() -> PendingActivation {
    let mut activation = pending(bootstrap_generation(), generation(b"first"));
    activation.established_before = Some(bootstrap_generation());
    activation
}

fn names(generation: &Generation) -> LinkFinding {
    LinkFinding::Names(generation.clone())
}

fn keep(reason: KeepReason) -> GuardDecision {
    GuardDecision::Keep(reason)
}

#[test]
fn a_running_activation_cut_after_the_switch_goes_back_to_its_predecessor() {
    let activation = running();
    let journal = JournalFinding::Pending(activation.clone());
    assert_eq!(
        decide(&journal, &names(&activation.target), true),
        GuardDecision::RestorePredecessor
    );
    // Every unresolved state with the effect mark: the cut can come after
    // the failed verification or during the inline compensation too.
    for state in [RecordedState::NeedsAttention, RecordedState::Compensating] {
        let journal = JournalFinding::Pending(PendingActivation {
            state,
            ..activation.clone()
        });
        assert_eq!(
            decide(&journal, &names(&activation.target), true),
            GuardDecision::RestorePredecessor,
            "{state:?}"
        );
    }
}

#[test]
fn a_bootstrap_activation_cut_after_the_switch_removes_current() {
    let activation = bootstrap();
    let journal = JournalFinding::Pending(activation.clone());
    // The bootstrap predecessor has no stored directory, so its stored
    // bytes are never a condition.
    for stored in [true, false] {
        assert_eq!(
            decide(&journal, &names(&activation.target), stored),
            GuardDecision::RemoveCurrent
        );
    }
}

#[test]
fn no_unsettled_activation_or_no_effect_mark_changes_nothing() {
    let activation = running();
    assert_eq!(
        decide(&JournalFinding::Settled, &names(&activation.target), true),
        keep(KeepReason::Settled)
    );
    let unmarked = JournalFinding::Pending(PendingActivation {
        effect_attempted: false,
        ..activation.clone()
    });
    for link in [
        names(&activation.target),
        names(&activation.predecessor),
        LinkFinding::Absent,
    ] {
        assert_eq!(
            decide(&unmarked, &link, true),
            keep(KeepReason::EffectNotAttempted),
            "{link:?}"
        );
    }
}

#[test]
fn a_link_already_on_the_predecessor_changes_nothing() {
    let activation = running();
    assert_eq!(
        decide(
            &JournalFinding::Pending(activation.clone()),
            &names(&activation.predecessor),
            true
        ),
        keep(KeepReason::OnPredecessor)
    );
    assert_eq!(
        decide(
            &JournalFinding::Pending(bootstrap()),
            &LinkFinding::Absent,
            false
        ),
        keep(KeepReason::OnPredecessor),
        "for a bootstrap, no `current` is the predecessor"
    );
}

#[test]
fn an_unknown_or_forged_journal_changes_nothing() {
    let activation = running();
    for code in [
        "EXECUTOR_DEPENDENCY_UNAVAILABLE",
        "JOURNAL_IDENTITY_MISMATCH",
        "JOURNAL_ROLLBACK",
        "EXECUTOR_ACCESS_DENIED",
    ] {
        assert_eq!(
            decide(
                &JournalFinding::Unknown(code),
                &names(&activation.target),
                true
            ),
            keep(KeepReason::JournalUnknown),
            "{code}"
        );
    }
}

#[test]
fn a_link_the_operation_does_not_explain_changes_nothing() {
    let activation = running();
    let journal = JournalFinding::Pending(activation.clone());
    let planted = generation(b"planted");
    // The target id with other bytes is not the target.
    let altered = (activation.target.0, sha(b"other bytes"));
    for link in [
        names(&planted),
        names(&altered),
        LinkFinding::Unreadable,
        LinkFinding::Absent,
    ] {
        assert_eq!(
            decide(&journal, &link, true),
            keep(KeepReason::LinkUnexplained),
            "{link:?}"
        );
    }
    let first = JournalFinding::Pending(bootstrap());
    for link in [names(&planted), LinkFinding::Unreadable] {
        assert_eq!(
            decide(&first, &link, false),
            keep(KeepReason::LinkUnexplained),
            "{link:?}"
        );
    }
}

#[test]
fn a_predecessor_the_history_or_its_bytes_do_not_explain_is_not_restored() {
    let activation = running();
    // W362: the history before the operation established another generation.
    let unexplained = JournalFinding::Pending(PendingActivation {
        established_before: Some(generation(b"established")),
        ..activation.clone()
    });
    assert_eq!(
        decide(&unexplained, &names(&activation.target), true),
        keep(KeepReason::PredecessorRefused)
    );
    // The stored predecessor no longer hashes to its journaled digest.
    assert_eq!(
        decide(
            &JournalFinding::Pending(activation.clone()),
            &names(&activation.target),
            false
        ),
        keep(KeepReason::PredecessorRefused)
    );
    // A predecessor that is not content-addressed and not established.
    let adopted = (id("adopted_generation"), sha(b"adopted"));
    let not_addressed = JournalFinding::Pending(PendingActivation {
        established_before: None,
        ..pending(adopted, activation.target.clone())
    });
    assert_eq!(
        decide(&not_addressed, &names(&activation.target), true),
        keep(KeepReason::PredecessorRefused)
    );
    // A bootstrap whose history established a real generation (W360).
    let late = JournalFinding::Pending(PendingActivation {
        established_before: Some(generation(b"real")),
        ..bootstrap()
    });
    assert_eq!(
        decide(&late, &names(&bootstrap().target), false),
        keep(KeepReason::PredecessorRefused)
    );
}

#[test]
fn only_the_intended_link_counts_as_restored() {
    let activation = running();
    let first = bootstrap();
    assert_eq!(
        restored(
            &GuardDecision::RestorePredecessor,
            &activation,
            &names(&activation.predecessor)
        ),
        Some(true)
    );
    for link in [
        names(&activation.target),
        LinkFinding::Absent,
        LinkFinding::Unreadable,
    ] {
        assert_eq!(
            restored(&GuardDecision::RestorePredecessor, &activation, &link),
            Some(false),
            "{link:?}"
        );
    }
    assert_eq!(
        restored(&GuardDecision::RemoveCurrent, &first, &LinkFinding::Absent),
        Some(true)
    );
    for link in [names(&first.target), LinkFinding::Unreadable] {
        assert_eq!(
            restored(&GuardDecision::RemoveCurrent, &first, &link),
            Some(false),
            "{link:?}"
        );
    }
    assert_eq!(
        restored(
            &keep(KeepReason::Settled),
            &activation,
            &names(&activation.target)
        ),
        None
    );
}

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Journal {
    path: PathBuf,
    ledger: FixtureJournal,
}

impl Drop for Journal {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn journal() -> Journal {
    let path = std::env::temp_dir().join(format!(
        "ri-w381-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .unwrap();
    let ledger =
        FixtureJournal::initialize(&path, id("host_fixture"), id("epoch_fixture")).unwrap();
    Journal { path, ledger }
}

fn intent(n: u32, from: &Generation, to: &Generation) -> Intent {
    Intent {
        operation_id: id(&format!("op_w381_{n}")),
        idempotency_key: id(&format!("idem_w381_{n}")),
        grant_id: id(&format!("grant_w381_{n}")),
        nonce: id(&format!("nonce_w381_{n}")),
        plan_digest: sha(b"plan"),
        grant_digest: sha(b"grant"),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        resource_id: id("ols_lab_listener"),
        predecessor_generation: from.0.clone(),
        predecessor_digest: from.1.clone(),
        target_generation: to.0.clone(),
        target_digest: to.1.clone(),
        expires_at: time(10_000),
        compensation_valid_until: time(10_300),
    }
}

/// The finding the executor builds from its own journal, for the OLS
/// resource and its bootstrap baseline.
fn finding(journal: &Journal) -> JournalFinding {
    let resource = id("ols_lab_listener");
    match journal.ledger.unresolved_operation(&resource).unwrap() {
        None => JournalFinding::Settled,
        Some(operation) => {
            let history = journal
                .ledger
                .resource_history(
                    &resource,
                    Some(&operation.intent.operation_id),
                    Some(&bootstrap_generation()),
                )
                .unwrap();
            JournalFinding::Pending(pending_activation(&operation, history))
        }
    }
}

/// The two W376-shaped journals: a first activation (bootstrap) cut after
/// its switch, and a second (running) activation cut after its switch.
#[test]
fn the_journal_rows_of_an_interrupted_activation_lead_to_the_guard_effect() {
    let mut journal = journal();
    let empty = bootstrap_generation();
    let first = generation(b"first");
    let second = generation(b"second");
    let bootstrap = intent(1, &empty, &first);
    journal
        .ledger
        .record_intent(&bootstrap, time(1000))
        .unwrap();
    assert_eq!(
        decide(&finding(&journal), &LinkFinding::Absent, false),
        keep(KeepReason::EffectNotAttempted),
        "before the effect mark nothing was switched"
    );
    journal
        .ledger
        .mark_effect_attempted(&bootstrap.operation_id)
        .unwrap();
    // W362: the product profile establishes the bootstrap generation for an
    // empty history; the lab profile establishes nothing. Both remove.
    assert_eq!(
        decide(&finding(&journal), &names(&first), false),
        GuardDecision::RemoveCurrent
    );
    assert_eq!(
        decide(&finding(&journal), &LinkFinding::Absent, false),
        keep(KeepReason::OnPredecessor)
    );
    // The first activation verified: settled.
    journal
        .ledger
        .record_observation(&bootstrap.operation_id, Some(&first.0), Some(&first.1))
        .unwrap();
    assert_eq!(
        decide(&finding(&journal), &names(&first), true),
        keep(KeepReason::Settled)
    );
    let running = intent(2, &first, &second);
    journal.ledger.record_intent(&running, time(1010)).unwrap();
    journal
        .ledger
        .mark_effect_attempted(&running.operation_id)
        .unwrap();
    let JournalFinding::Pending(activation) = finding(&journal) else {
        panic!("the running activation is pending");
    };
    assert_eq!(activation.established_before, Some(first.clone()));
    assert_eq!(activation.state, RecordedState::Intent);
    assert_eq!(
        decide(&JournalFinding::Pending(activation), &names(&second), true),
        GuardDecision::RestorePredecessor
    );
    // The guard records nothing: the row stays `intent` for reconcile.
    let row = journal
        .ledger
        .status(&running.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(row.state, RecordedState::Intent);
    assert!(row.effect_attempted);
}
