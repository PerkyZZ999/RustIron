//! W372 (D-030): what a generation adoption establishes, and that every
//! W359 to W362 refusal still holds around it. Each case records the
//! journal rows the executor records and makes the decisions that
//! `activate_ols`, `ols-status`, `reconcile_ols` and `compensate` make with
//! [`ols::with_adoption`]. Runs in both profiles; `--test product_profile`
//! includes it.

use std::{
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

use rustiron_contracts::{
    Id, Timestamp,
    approval::{ReadoptPlan, Sha256Digest},
};
use rustiron_executor::ols::{
    bootstrap_generation, bootstrap_history_admits, established_generation, generation_id,
    generation_refusal, restore_refusal, with_adoption,
};
use rustiron_journal::{
    FixtureJournal, Intent, ReadoptOutcome, ReadoptionIntent, RecordedState, ResourceHistory,
};
use sha2::{Digest, Sha256};

static NEXT: AtomicUsize = AtomicUsize::new(0);

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

fn generation(tag: &[u8]) -> Generation {
    let digest = sha(tag);
    (generation_id(&digest), digest)
}

fn resource() -> Id {
    id("ols_lab_listener")
}

struct Journal {
    path: PathBuf,
    ledger: Option<FixtureJournal>,
}

impl Drop for Journal {
    fn drop(&mut self) {
        drop(self.ledger.take());
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

impl Journal {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ri-w372-ols-{}-{}",
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

    /// The generation form, recorded `adopted` for `live`.
    fn adopt(&mut self, live: &Generation) {
        let plan = format!(
            r#"{{"schema_version":1,"plan_id":"plan_gen","host_id":"host_fixture","host_epoch":"epoch_fixture","profile_digest":"{a}","requester":"agent_1","verb":"site_readopt","previous_epoch":"epoch_old","risk_class":"lab_only","valid_from":1000,"expires_at":2000,"limitations":[],"form":"generation","target":"ols_lab_listener","expected_generation":"{g}","expected_digest":"{d}","site_ids":["blog1"],"evidence_sha256":"{e}","observations":[{{"state":"observed","generation":"{g}","content_digest":"{d}","observed_at":990,"source":"reported_registry"}}],"expected_effects":{{"creates_account":false,"creates_database":false,"traffic_activation":false,"network_access":false,"sets_quota":false,"records_generation":true}}}}"#,
            a = "a".repeat(64),
            g = live.0.as_str(),
            d = live.1.as_str(),
            e = "e".repeat(64),
        );
        let plan = ReadoptPlan::decode(plan.as_bytes()).unwrap();
        let intent = ReadoptionIntent {
            operation_id: id("readopt_gen"),
            idempotency_key: id("readopt_gen_key"),
            grant_id: id("readopt_gen_grant"),
            nonce: id("readopt_gen_nonce"),
            plan_digest: plan.digest(),
            grant_digest: sha(b"grant"),
            host_id: id("host_fixture"),
            host_epoch: id("epoch_fixture"),
            form: plan.form(),
            site: None,
            previous_epoch: plan.previous_epoch().clone(),
            evidence_sha256: plan.evidence_sha256().clone(),
            expires_at: time(10_000),
            plan: String::from_utf8(plan.as_bytes().to_vec()).unwrap(),
        };
        let ledger = self.ledger();
        ledger.record_readoption(&intent, time(900)).unwrap();
        ledger
            .finish_readoption(
                &intent.operation_id,
                ReadoptOutcome::Adopted {
                    facts: "{}",
                    site: None,
                    generation: Some(live.clone()),
                    floor: None,
                },
            )
            .unwrap();
    }

    /// `ols_history` as the executor computes it.
    fn history(&mut self, before: Option<&Id>) -> ResourceHistory {
        let adoption = self.ledger().ols_adoption().unwrap();
        let baseline = adoption.clone().unwrap_or_else(bootstrap_generation);
        let history = self
            .ledger()
            .resource_history(&resource(), before, Some(&baseline))
            .unwrap();
        with_adoption(history, adoption)
    }

    fn established(&mut self) -> Option<Generation> {
        established_generation(self.history(None))
    }

    fn established_before(&mut self, operation: &Id) -> Option<Generation> {
        established_generation(self.history(Some(operation)))
    }

    fn intent(&mut self, n: u32, from: &Generation, to: &Generation) -> Intent {
        let intent = Intent {
            operation_id: id(&format!("op_w372_{n}")),
            idempotency_key: id(&format!("idem_w372_{n}")),
            grant_id: id(&format!("grant_w372_{n}")),
            nonce: id(&format!("nonce_w372_{n}")),
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

    fn succeed(&mut self, intent: &Intent) {
        let ledger = self.ledger();
        ledger.mark_effect_attempted(&intent.operation_id).unwrap();
        ledger
            .record_observation(
                &intent.operation_id,
                Some(&intent.target_generation),
                Some(&intent.target_digest),
            )
            .unwrap();
    }

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

#[test]
fn the_adopted_generation_is_established_and_the_live_current_is_explained() {
    let mut journal = Journal::new();
    let live = generation(b"live");
    journal.adopt(&live);
    assert_eq!(journal.established(), Some(live.clone()));
    assert_eq!(
        generation_refusal(&live, journal.established().as_ref()),
        None
    );
}

#[test]
fn a_planted_or_bootstrap_current_is_still_refused_after_an_adoption() {
    let mut journal = Journal::new();
    let live = generation(b"live");
    journal.adopt(&live);
    let planted = generation(b"planted");
    assert!(generation_refusal(&planted, journal.established().as_ref()).is_some());
    // A present `current` that names the bootstrap generation is never explained.
    assert!(generation_refusal(&bootstrap_generation(), journal.established().as_ref()).is_some());
    // A non-content-addressed id is refused too.
    let forged = (id("rffffffffffffffff"), live.1.clone());
    assert!(generation_refusal(&forged, journal.established().as_ref()).is_some());
}

#[test]
fn a_bootstrap_plan_is_refused_after_an_adoption() {
    let mut journal = Journal::new();
    journal.adopt(&generation(b"live"));
    assert!(!bootstrap_history_admits(&journal.history(None)));
}

#[test]
fn an_activation_from_the_adopted_predecessor_establishes_its_target() {
    let mut journal = Journal::new();
    let live = generation(b"live");
    journal.adopt(&live);
    let next = generation(b"next");
    let activation = journal.intent(1, &live, &next);
    // While it is unresolved nothing is established (W360).
    assert_eq!(journal.established(), None);
    // `reconcile` and `compensate` judge against the adopted generation.
    assert_eq!(
        journal.established_before(&activation.operation_id),
        Some(live.clone())
    );
    assert_eq!(
        restore_refusal(
            &live,
            journal
                .established_before(&activation.operation_id)
                .as_ref()
        ),
        None
    );
    journal.succeed(&activation);
    assert_eq!(journal.established(), Some(next.clone()));
    assert!(generation_refusal(&live, journal.established().as_ref()).is_some());
}

#[test]
fn a_compensated_activation_keeps_the_adopted_generation() {
    let mut journal = Journal::new();
    let live = generation(b"live");
    journal.adopt(&live);
    let next = generation(b"next");
    let activation = journal.intent(1, &live, &next);
    journal.compensate(&activation, 1100);
    assert_eq!(journal.established(), Some(live.clone()));
    assert_eq!(
        generation_refusal(&live, journal.established().as_ref()),
        None
    );
}

#[test]
fn without_an_adoption_the_w362_rule_is_unchanged() {
    let mut journal = Journal::new();
    let live = generation(b"live");
    let empty = journal.established();
    if cfg!(rustiron_profile = "product") {
        assert_eq!(empty, Some(bootstrap_generation()));
        assert!(generation_refusal(&live, empty.as_ref()).is_some());
    } else {
        assert_eq!(empty, None);
    }
    assert!(bootstrap_history_admits(&journal.history(None)));
}
