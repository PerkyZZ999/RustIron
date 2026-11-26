//! W360 (B06/B08): a refusal, reconcile or compensation never establishes an
//! OLS generation. Each case records the journal rows `activate_ols`,
//! `reconcile_ols` and `compensate_ols` record, then makes the generation
//! decisions the executor makes before the next activation. The include
//! directory is fixed (`/etc/rustiron-ols`), so the switch itself is
//! simulated by the generation each check observes.

use std::{
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

use rustiron_contracts::{Id, Timestamp, approval::Sha256Digest};
use rustiron_executor::ols::{
    ActivationMode, activation_mode, bootstrap_generation, bootstrap_history_admits,
    generation_checks, generation_id, generation_refusal,
};
use rustiron_journal::{FixtureJournal, Intent, RecordedState, ResourceHistory};
use sha2::{Digest, Sha256};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Journal {
    path: PathBuf,
    ledger: Option<FixtureJournal>,
}

impl Journal {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ri-w360-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        let ledger =
            FixtureJournal::initialize(&path, id("host_fixture"), id("epoch_fixture")).unwrap();
        Self {
            path,
            ledger: Some(ledger),
        }
    }

    fn ledger(&mut self) -> &mut FixtureJournal {
        self.ledger.as_mut().unwrap()
    }

    /// The generation the pre-intent checks compare with.
    fn established(&mut self) -> Option<(Id, Sha256Digest)> {
        self.ledger()
            .expected_generation(&resource(), Some(&bootstrap_generation()))
            .unwrap()
    }

    /// The history before `operation`, as the recheck after intent and the
    /// admin helper read it.
    fn before(&mut self, operation: &Id) -> ResourceHistory {
        self.ledger()
            .resource_history(&resource(), Some(operation), Some(&bootstrap_generation()))
            .unwrap()
    }

    fn intent(&mut self, n: u32, from: &Generation, to: &Generation) -> Intent {
        let intent = Intent {
            operation_id: id(&format!("op_w360_{n}")),
            idempotency_key: id(&format!("idem_w360_{n}")),
            grant_id: id(&format!("grant_w360_{n}")),
            nonce: id(&format!("nonce_w360_{n}")),
            plan_digest: sha(b"plan"),
            grant_digest: sha(b"grant"),
            host_id: id("host_fixture"),
            host_epoch: id("epoch_fixture"),
            resource_id: resource(),
            predecessor_generation: from.0.clone(),
            predecessor_digest: from.1.clone(),
            target_generation: to.0.clone(),
            target_digest: to.1.clone(),
            expires_at: time(10_000),
            compensation_valid_until: time(10_300),
        };
        self.ledger()
            .record_intent(&intent, time(1000 + 10 * u64::from(n)))
            .unwrap();
        intent
    }

    /// `activate_ols` after a verified activation.
    fn succeed(&mut self, intent: &Intent) {
        let ledger = self.ledger();
        ledger.mark_effect_attempted(&intent.operation_id).unwrap();
        let state = ledger
            .record_observation(
                &intent.operation_id,
                Some(&intent.target_generation),
                Some(&intent.target_digest),
            )
            .unwrap()
            .state;
        assert_eq!(state, RecordedState::Succeeded);
    }

    /// `activate_ols` after a refusal or a staging failure after intent: the
    /// plan predecessor is recorded, whatever is live.
    fn refuse(&mut self, intent: &Intent) {
        let state = self
            .ledger()
            .record_observation(
                &intent.operation_id,
                Some(&intent.predecessor_generation),
                Some(&intent.predecessor_digest),
            )
            .unwrap()
            .state;
        assert_eq!(state, RecordedState::Untouched);
    }

    /// `reconcile_ols` of an interrupted operation that finds the
    /// predecessor after a reload and the identity probes.
    fn reconcile(&mut self, intent: &Intent) {
        let ledger = self.ledger();
        ledger.mark_effect_attempted(&intent.operation_id).unwrap();
        let state = ledger
            .record_observation(
                &intent.operation_id,
                Some(&intent.predecessor_generation),
                Some(&intent.predecessor_digest),
            )
            .unwrap()
            .state;
        assert_eq!(state, RecordedState::Untouched);
    }

    /// `activate_ols` or `compensate_ols`: the verification failed and the
    /// single compensation restored the predecessor.
    fn compensate(&mut self, intent: &Intent) {
        let ledger = self.ledger();
        let operation = &intent.operation_id;
        ledger.mark_effect_attempted(operation).unwrap();
        ledger.record_observation(operation, None, None).unwrap();
        let at = 1001 + 10 * Self::number(operation);
        ledger.begin_compensation(operation, time(at)).unwrap();
        let state = ledger
            .record_observation(
                operation,
                Some(&intent.predecessor_generation),
                Some(&intent.predecessor_digest),
            )
            .unwrap()
            .state;
        assert_eq!(state, RecordedState::FailedCompensated);
    }
}

impl Drop for Journal {
    fn drop(&mut self) {
        drop(self.ledger.take());
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

type Generation = (Id, Sha256Digest);

fn id(text: &str) -> Id {
    Id::try_from(text.to_owned()).unwrap()
}

fn time(seconds: u64) -> Timestamp {
    Timestamp::try_from(seconds).unwrap()
}

fn sha(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn resource() -> Id {
    id("ols_lab_listener")
}

fn generation(tag: &[u8]) -> Generation {
    let digest = sha(tag);
    (generation_id(&digest), digest)
}

/// The pre-intent decision for a running host whose `current` is `live`
/// and whose plan names `live` as predecessor (W355 mode, W359 check).
fn admitted(journal: &mut Journal, live: &Generation) -> bool {
    assert_eq!(
        activation_mode(Some(live), live),
        Ok(ActivationMode::Running)
    );
    generation_refusal(live, journal.established().as_ref()).is_none()
}

/// A served generation `e`, established by a verified bootstrap activation.
fn served() -> (Journal, Generation) {
    let mut journal = Journal::new();
    let e = generation(b"e");
    let first = journal.intent(1, &bootstrap_generation(), &e);
    journal.succeed(&first);
    assert_eq!(journal.established(), Some(e.clone()));
    (journal, e)
}

/// The open W359 race: `current` changes between the check before intent
/// and the recheck after it. The recheck refuses and records the plan
/// predecessor, which the journal had already established; the changed
/// generation stays unexplained and the next activation over it is refused
/// before intent.
#[test]
fn a_change_between_the_check_and_the_recheck_explains_nothing() {
    let (mut journal, e) = served();
    let target = generation(b"t");
    let planted = generation(b"planted");
    assert!(admitted(&mut journal, &e), "before intent, current is e");
    let second = journal.intent(2, &e, &target);
    // Root switches `current` to the planted generation now.
    let recheck = generation_checks(
        &planted,
        match journal.before(&second.operation_id) {
            ResourceHistory::Established(id, digest) => Some((id, digest)),
            other => panic!("{other:?}"),
        }
        .as_ref(),
    );
    assert_eq!(recheck, (true, Some(false)), "the recheck refuses");
    journal.refuse(&second);
    assert_eq!(journal.established(), Some(e.clone()));
    assert!(
        !admitted(&mut journal, &planted),
        "the next activation over the planted generation is refused before intent"
    );
}

/// The W359 regression (`op_w359d1`): an operation whose plan predecessor
/// was a planted generation, refused after intent by the W357 build. The
/// same shape covers a predecessor read by a second, later observation
/// before intent. Under the W360 rule the refusal, a reconcile and a
/// compensation over that predecessor all leave it unexplained.
#[test]
fn a_finished_operation_over_a_planted_predecessor_does_not_explain_it() {
    type End = fn(&mut Journal, &Intent);
    let ends: [(&str, End); 3] = [
        ("refused", Journal::refuse),
        ("reconciled", Journal::reconcile),
        ("compensated", Journal::compensate),
    ];
    for (name, end) in ends {
        let (mut journal, e) = served();
        let planted = generation(b"planted");
        let target = generation(b"t");
        let second = journal.intent(2, &planted, &target);
        end(&mut journal, &second);
        assert_eq!(journal.established(), Some(e.clone()), "{name}");
        assert!(
            !admitted(&mut journal, &planted),
            "{name}: drift stays refused"
        );
        assert!(admitted(&mut journal, &e), "{name}: e still passes");
        // The next operation's recheck reads the same history.
        let third = journal.intent(3, &e, &target);
        assert_eq!(
            journal.before(&third.operation_id),
            ResourceHistory::Established(e.0.clone(), e.1.clone()),
            "{name}"
        );
        journal.succeed(&third);
        assert_eq!(journal.established(), Some(target.clone()), "{name}");
    }
}

/// W355 bootstrap: a failed and compensated (or refused) first activation
/// leaves the host at its start, so the bootstrap may be retried and a
/// planted running `current` is still drift. After a real generation, a
/// refused bootstrap does not take the host back to the start.
#[test]
fn only_the_bootstrap_baseline_is_re_established_and_only_from_the_start() {
    let bootstrap = bootstrap_generation();
    let target = generation(b"t");
    let planted = generation(b"planted");
    type End = fn(&mut Journal, &Intent);
    let ends: [(&str, End); 3] = [
        ("refused", Journal::refuse),
        ("reconciled", Journal::reconcile),
        ("compensated", Journal::compensate),
    ];
    for (name, end) in ends {
        let mut journal = Journal::new();
        assert!(bootstrap_history_admits(&journal.before_new()), "{name}");
        let first = journal.intent(1, &bootstrap, &target);
        end(&mut journal, &first);
        assert_eq!(journal.established(), Some(bootstrap.clone()), "{name}");
        assert!(bootstrap_history_admits(&journal.before_new()), "{name}");
        assert!(
            !admitted(&mut journal, &planted),
            "{name}: a planted running generation after a failed bootstrap"
        );

        let (mut journal, e) = served();
        assert!(!bootstrap_history_admits(&journal.before_new()), "{name}");
        let second = journal.intent(2, &bootstrap, &target);
        end(&mut journal, &second);
        assert_eq!(journal.established(), Some(e), "{name}");
        assert!(
            !bootstrap_history_admits(&journal.before_new()),
            "{name}: a refused bootstrap after a real generation is not the start"
        );
    }
}

impl Journal {
    /// `n` of `op_w360_<n>`: compensation is recorded just after its intent.
    fn number(operation: &Id) -> u64 {
        operation.as_str()["op_w360_".len()..].parse().unwrap()
    }

    /// The history a new operation would find.
    fn before_new(&mut self) -> ResourceHistory {
        self.ledger()
            .resource_history(&resource(), None, Some(&bootstrap_generation()))
            .unwrap()
    }
}

/// W360 lab evidence, not a gate: replays the history rule over a copy of a
/// lab journal and prints, for each OLS operation, the history before it
/// under the W360 rule and under the earlier rule (the latest finished
/// operation decides). Reads only; needs `RUSTIRON_W360_JOURNAL` (a 0700
/// directory owned by the caller holding a copy of `fixture-journal.sqlite`),
/// `RUSTIRON_W360_HOST` and `RUSTIRON_W360_EPOCH`.
#[test]
#[ignore = "lab evidence over a journal copy"]
fn replay_a_journal_copy() {
    let var = |name| std::env::var(name).unwrap();
    let directory = PathBuf::from(var("RUSTIRON_W360_JOURNAL"));
    let host = id(&var("RUSTIRON_W360_HOST"));
    let epoch = id(&var("RUSTIRON_W360_EPOCH"));
    let baseline = bootstrap_generation();
    let observed = FixtureJournal::observe_as_process_owner(&directory, &host, &epoch).unwrap();
    let show = |history: &ResourceHistory| match history {
        ResourceHistory::Established(id, _) => id.as_str().to_owned(),
        other => format!("{other:?}"),
    };
    let mut earlier = ResourceHistory::Empty;
    let mut differ = 0;
    let ols = observed
        .operations
        .iter()
        .filter(|o| o.resource_id == resource().as_str());
    for listed in ols {
        let operation = id(&listed.operation_id);
        let records = FixtureJournal::records_as_process_owner(
            &directory,
            &host,
            &epoch,
            &operation,
            Some(&baseline),
        )
        .unwrap();
        let now = records.ols_history.unwrap();
        let recorded = records.operation.unwrap();
        let mark = if now == earlier { "" } else { " DIFFERS" };
        differ += usize::from(now != earlier);
        println!(
            "{} {:?} pred={} target={} before_w360={} before_earlier={}{mark}",
            listed.operation_id,
            recorded.state,
            recorded.intent.predecessor_generation.as_str(),
            recorded.intent.target_generation.as_str(),
            show(&now),
            show(&earlier),
        );
        let intent = recorded.intent;
        earlier = match recorded.state {
            RecordedState::Succeeded => {
                ResourceHistory::Established(intent.target_generation, intent.target_digest)
            }
            RecordedState::Untouched | RecordedState::FailedCompensated => {
                ResourceHistory::Established(
                    intent.predecessor_generation,
                    intent.predecessor_digest,
                )
            }
            _ => ResourceHistory::Unresolved,
        };
    }
    let ledger = FixtureJournal::open_as_process_owner(&directory, host, epoch).unwrap();
    let now = ledger
        .resource_history(&resource(), None, Some(&baseline))
        .unwrap();
    println!(
        "whole history: w360={} earlier={} operations_differing={differ}",
        show(&now),
        show(&earlier)
    );
}
