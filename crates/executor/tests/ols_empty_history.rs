//! W362 (B01/B06/B08): what an empty OLS history establishes.
//!
//! A product host starts with no `current` (W348, W355), so in the product
//! profile an empty history establishes the bootstrap generation, and a
//! `current` found on such a host is unexplained drift. The lab profile
//! keeps the W021 rule: with nothing established, any content-addressed
//! `current` passes. Each case records the journal rows the executor
//! records and makes the decisions that `activate_ols` (before intent and
//! the recheck after it), `ols-status`, `reconcile_ols` and `compensate`
//! make. The include directory is fixed (`/etc/rustiron-ols`), so the live
//! `current` is the generation each decision is given.
//!
//! The default build runs the lab cases. `--test product_profile` and
//! `--test ols_empty_history` in a build with
//! `--cfg rustiron_profile="product"` run the product cases.

use std::{
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

use rustiron_contracts::{Id, Timestamp, approval::Sha256Digest};
use rustiron_executor::ols::{
    ActivationMode, activation_mode, bootstrap_generation, current_checks, established_generation,
    generation_id, generation_refusal, restore_refusal,
};
use rustiron_journal::{FixtureJournal, Intent, RecordedState, ResourceHistory};
use sha2::{Digest, Sha256};

static NEXT: AtomicUsize = AtomicUsize::new(0);

type Generation = (Id, Sha256Digest);

struct Journal {
    path: PathBuf,
    ledger: Option<FixtureJournal>,
}

impl Journal {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ri-w362-{}-{}",
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

    fn history(&mut self, before: Option<&Id>) -> ResourceHistory {
        self.ledger()
            .resource_history(&resource(), before, Some(&bootstrap_generation()))
            .unwrap()
    }

    /// `ols_established`: what the checks before intent and `ols-status`
    /// compare `current` with.
    fn established(&mut self) -> Option<Generation> {
        established_generation(self.history(None))
    }

    /// `established_before`: what the recheck after intent, `reconcile_ols`
    /// and `compensate` compare with.
    fn established_before(&mut self, operation: &Id) -> Option<Generation> {
        established_generation(self.history(Some(operation)))
    }

    fn intent(&mut self, n: u32, from: &Generation, to: &Generation) -> Intent {
        let intent = Intent {
            operation_id: id(&format!("op_w362_{n}")),
            idempotency_key: id(&format!("idem_w362_{n}")),
            grant_id: id(&format!("grant_w362_{n}")),
            nonce: id(&format!("nonce_w362_{n}")),
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

    /// An interrupted operation: the effect was attempted and nothing
    /// verified was recorded, so `reconcile` and `compensate` apply.
    fn interrupt(&mut self, intent: &Intent) {
        let ledger = self.ledger();
        ledger.mark_effect_attempted(&intent.operation_id).unwrap();
        let state = ledger
            .record_observation(&intent.operation_id, None, None)
            .unwrap()
            .state;
        assert_eq!(state, RecordedState::NeedsAttention);
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

    /// `activate_ols` after a failed bootstrap whose compensation stopped
    /// OLS and removed `current` (W355).
    #[cfg(rustiron_profile = "product")]
    fn compensate(&mut self, intent: &Intent, at: u64) {
        let ledger = self.ledger();
        let operation = &intent.operation_id;
        ledger.mark_effect_attempted(operation).unwrap();
        ledger.record_observation(operation, None, None).unwrap();
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

/// The check before intent for a running host whose `current` is `live`
/// and whose plan names `live` as predecessor.
fn activation_admitted(journal: &mut Journal, live: &Generation) -> bool {
    assert_eq!(
        activation_mode(Some(live), live),
        Ok(ActivationMode::Running)
    );
    generation_refusal(live, journal.established().as_ref()).is_none()
}

/// `reconcile_ols` reloads only over a `current` equal to the predecessor
/// that the history before the operation explains.
fn reconcile_admitted(journal: &mut Journal, intent: &Intent) -> bool {
    let live = (
        intent.predecessor_generation.clone(),
        intent.predecessor_digest.clone(),
    );
    let established = journal.established_before(&intent.operation_id);
    generation_refusal(&live, established.as_ref()).is_none()
}

/// `compensate` restores only a predecessor that the history before the
/// operation explains; it checks before the compensation mark.
fn compensation_admitted(journal: &mut Journal, intent: &Intent) -> bool {
    let predecessor = (
        intent.predecessor_generation.clone(),
        intent.predecessor_digest.clone(),
    );
    let established = journal.established_before(&intent.operation_id);
    restore_refusal(&predecessor, established.as_ref()).is_none()
}

/// The present-`current` cases that hold in both profiles.
#[test]
fn a_present_bootstrap_generation_is_never_explained() {
    // An empty planted directory hashes to the bootstrap generation, which
    // stands for "no `current`".
    let empty = bootstrap_generation();
    assert_eq!(
        activation_mode(Some(&empty), &empty),
        Ok(ActivationMode::Running)
    );
    for established in [None, Some(&empty)] {
        assert_eq!(
            generation_refusal(&empty, established),
            Some((false, established.map(|_| false))),
            "{established:?}"
        );
        assert!(!current_checks(Some(&empty), established).0);
    }
    let mut journal = Journal::new();
    assert!(!activation_admitted(&mut journal, &empty));
    let target = generation(b"t");
    let first = journal.intent(1, &empty, &target);
    journal.interrupt(&first);
    assert!(
        !reconcile_admitted(&mut journal, &first),
        "a present empty directory is not reloaded"
    );
    assert!(
        compensation_admitted(&mut journal, &first),
        "the bootstrap compensation restores the absence of `current`"
    );
}

/// The generation that the next product VM run plants before its first
/// activation (`docs/validation/S10-W362/next-vm-plant.sh`) has these
/// values under the executor's digest rule.
#[test]
fn the_next_vm_planted_generation_is_content_addressed() {
    let planted = rustiron_executor::ols::Generation::from([(
        "w362.conf".to_owned(),
        b"# W362 planted generation, never journaled\n".to_vec(),
    )]);
    let digest = rustiron_executor::ols::digest(&planted);
    assert_eq!(
        digest.as_str(),
        "8e009a49dce77fecbb4379f515e0205b14c0c1b2818ad72a172fad6aae6fcbb9"
    );
    assert_eq!(generation_id(&digest).as_str(), "r8e009a49dce77fec");
    assert_eq!(bootstrap_generation().0.as_str(), "re3b0c44298fc1c14");
}

#[cfg(rustiron_profile = "product")]
mod product {
    use rustiron_executor::ols::bootstrap_history_admits;

    use super::*;

    /// The W360 open issue: a content-addressed `current` planted before the
    /// first activation of a product host.
    #[test]
    fn an_empty_history_is_the_bootstrap_generation() {
        let mut journal = Journal::new();
        let empty = bootstrap_generation();
        assert_eq!(
            established_generation(ResourceHistory::Empty),
            Some(empty.clone())
        );
        assert_eq!(journal.established(), Some(empty));
        assert_eq!(
            established_generation(ResourceHistory::Unresolved),
            None,
            "an unresolved operation still establishes nothing"
        );

        let planted = generation(b"planted");
        assert!(
            !activation_admitted(&mut journal, &planted),
            "refused before intent"
        );
        assert_eq!(
            generation_refusal(&planted, journal.established().as_ref()),
            Some((true, Some(false)))
        );
        assert_eq!(
            current_checks(Some(&planted), journal.established().as_ref()),
            (true, Some(false)),
            "ols-status: explained is false"
        );
        assert_eq!(
            current_checks(None, journal.established().as_ref()),
            (true, Some(true)),
            "ols-status: no `current` is the established start"
        );

        // A row an earlier build recorded over the planted generation.
        let target = generation(b"t");
        let first = journal.intent(1, &planted, &target);
        journal.interrupt(&first);
        assert!(!reconcile_admitted(&mut journal, &first), "reconcile");
        assert!(!compensation_admitted(&mut journal, &first), "compensate");
        // The recheck after intent judges the same history.
        assert_eq!(
            current_checks(
                Some(&planted),
                journal.established_before(&first.operation_id).as_ref()
            ),
            (true, Some(false))
        );
    }

    /// The bootstrap path is unchanged: with no `current`, the first
    /// activation names the bootstrap predecessor, and a failed bootstrap
    /// leaves the host at its start.
    #[test]
    fn the_bootstrap_still_starts_a_fresh_host() {
        let mut journal = Journal::new();
        let empty = bootstrap_generation();
        let target = generation(b"t");
        assert!(bootstrap_history_admits(&journal.history(None)));
        assert_eq!(activation_mode(None, &empty), Ok(ActivationMode::Bootstrap));
        let first = journal.intent(1, &empty, &target);
        assert!(compensation_admitted(&mut journal, &first));
        journal.compensate(&first, 1011);
        assert!(bootstrap_history_admits(&journal.history(None)));
        assert_eq!(journal.established(), Some(empty.clone()));
        assert!(
            !activation_admitted(&mut journal, &generation(b"planted")),
            "after a failed bootstrap, a planted `current` is still drift"
        );
        let second = journal.intent(2, &empty, &target);
        journal.succeed(&second);
        assert_eq!(journal.established(), Some(target));
    }

    /// After a verified activation, the W360 rule decides.
    #[test]
    fn after_a_verified_activation_the_w360_rule_decides() {
        let mut journal = Journal::new();
        let empty = bootstrap_generation();
        let e = generation(b"e");
        let first = journal.intent(1, &empty, &e);
        journal.succeed(&first);
        assert_eq!(journal.established(), Some(e.clone()));
        assert!(activation_admitted(&mut journal, &e));
        assert!(!activation_admitted(&mut journal, &generation(b"planted")));
        assert_eq!(
            current_checks(Some(&e), journal.established().as_ref()),
            (true, Some(true))
        );
        assert_eq!(
            current_checks(None, journal.established().as_ref()),
            (true, Some(false)),
            "a missing `current` after a real generation is drift"
        );
        let second = journal.intent(2, &e, &generation(b"t"));
        journal.interrupt(&second);
        assert!(reconcile_admitted(&mut journal, &second));
        assert!(compensation_admitted(&mut journal, &second));
        // A bootstrap row over a real generation (an older build): its
        // compensation would stop OLS and remove `current`.
        let mut journal = Journal::new();
        let first = journal.intent(1, &empty, &e);
        journal.succeed(&first);
        let late = journal.intent(2, &empty, &generation(b"t"));
        journal.interrupt(&late);
        assert!(!compensation_admitted(&mut journal, &late));
    }
}

#[cfg(not(rustiron_profile = "product"))]
mod lab {
    use super::*;

    /// The lab keeps the W021 rule: an empty history establishes nothing,
    /// so any content-addressed `current` passes, and an adopted id that is
    /// not content-addressed passes only as an established generation.
    #[test]
    fn an_empty_history_keeps_the_w021_rule() {
        let mut journal = Journal::new();
        assert_eq!(established_generation(ResourceHistory::Empty), None);
        assert_eq!(journal.established(), None);
        let adopted_first = generation(b"adopted");
        assert!(activation_admitted(&mut journal, &adopted_first));
        assert_eq!(
            current_checks(Some(&adopted_first), None),
            (true, None),
            "ols-status: explained is unknown"
        );
        assert_eq!(current_checks(None, None), (true, None));
        let g1 = (id("g1"), sha(b"g1"));
        assert_eq!(generation_refusal(&g1, None), Some((false, None)));

        let target = generation(b"t");
        let first = journal.intent(1, &adopted_first, &target);
        journal.interrupt(&first);
        assert!(reconcile_admitted(&mut journal, &first), "reconcile");
        assert!(compensation_admitted(&mut journal, &first), "compensate");

        let mut journal = Journal::new();
        let second = journal.intent(1, &adopted_first, &target);
        journal.succeed(&second);
        assert!(activation_admitted(&mut journal, &target));
        assert!(!activation_admitted(&mut journal, &adopted_first));
    }
}
