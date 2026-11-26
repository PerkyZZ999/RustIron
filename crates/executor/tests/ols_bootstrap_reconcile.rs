//! W382 (D-033, B10/B08): `reconcile` of an interrupted bootstrap activation.
//!
//! Before W382, `reconcile` recorded no observation for a bootstrap
//! operation (W355). A crash after the intent and before the effect mark,
//! or after the restore mark, then left the OLS resource blocked until an
//! epoch rotation (W380 B1). Now `reconcile` asks the admin helper for the
//! read-only `ols_bootstrap_confirm` step. Only a bare `ok` records the
//! bootstrap predecessor; the journal then records `untouched` (no restore
//! mark) or `failed_compensated` (restore mark). A refused confirmation
//! records `needs_attention`, and a helper binding refusal is an error that
//! records nothing.
//!
//! The rows are the journal states of the four W380 crash points of a
//! bootstrap activation. A stub helper gives the reply that the real helper
//! gives for each live state; the real helper's decision is in the
//! `admin_helper` unit tests and in `ols_bootstrap.rs`. No test here reads
//! the include folder or runs `systemctl`.

use std::{
    fs,
    io::{Read, Write},
    os::unix::net::UnixListener,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use rustiron_contracts::{Id, Timestamp, approval::Sha256Digest};
use rustiron_executor::{Executor, ExecutorError, TrustAnchor, ols};
use rustiron_journal::{FixtureJournal, Intent, RecordedState, ResourceHistory};
use serde_json::json;
use sha2::{Digest, Sha256};
#[allow(dead_code, reason = "this suite signs no request")]
mod support;
use support::{KEYGEN, hex, new_key, private_dir, private_file};

const CONFIRM: &str = "ols_bootstrap_confirm";

/// Labs run one at a time (see `admission.rs`).
static SERIAL: Mutex<()> = Mutex::new(());

fn id(value: &str) -> Id {
    Id::try_from(value.to_owned()).unwrap()
}

fn time(seconds: u64) -> Timestamp {
    Timestamp::try_from(seconds).unwrap()
}

fn sha(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

/// The first generation the bootstrap activation names as its target.
fn target() -> (Id, Sha256Digest) {
    let digest = sha(b"w382 first generation");
    (ols::generation_id(&digest), digest)
}

/// The crash points of W380 (`ols_activation_faults.rs`), as the journal
/// records them after the crash.
#[derive(Clone, Copy, Debug)]
enum Crash {
    /// `AfterOlsIntent`: intent only.
    Intent,
    /// `AfterOlsEffectMark` and `AfterOlsServing`: intent and the effect
    /// mark. The two differ only on the host (`current`, OLS running).
    EffectMark,
    /// `AfterOlsRestoreMark`: `compensating`, both marks.
    RestoreMark,
}

#[derive(Default)]
struct Script {
    reply: String,
    seen: Vec<String>,
}

struct Lab {
    _serial: std::sync::MutexGuard<'static, ()>,
    root: PathBuf,
    anchor: TrustAnchor,
    script: Arc<Mutex<Script>>,
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl Lab {
    fn new(name: &str, crash: Crash) -> Self {
        let serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        let root = std::env::temp_dir().join(format!("ri-w382-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        private_dir(&root);
        for dir in ["policy", "registry", "scratch", "journal", "mark", "keys"] {
            private_dir(&root.join(dir));
        }
        new_key(&root.join("keys/key"));
        let socket = root.join("helper.sock");
        let anchor = TrustAnchor {
            owner_uid: rustix::process::getuid().as_raw(),
            policy_dir: root.join("policy"),
            registry_dir: root.join("registry"),
            scratch_dir: root.join("scratch"),
            journal_dir: root.join("journal"),
            mark_dir: root.join("mark"),
            recipes_dir: root.join("journal"),
            admin_socket: Some(socket.clone()),
        };
        let script = Arc::new(Mutex::new(Script::default()));
        stub_helper(&socket, Arc::clone(&script));
        let lab = Self {
            _serial: serial,
            root,
            anchor,
            script,
        };
        lab.write_policy();
        drop(Executor::initialize(lab.anchor.clone()).unwrap());
        lab.crash(crash);
        lab
    }

    fn write_policy(&self) {
        let policy = json!({
            "schema_version": 1, "host_id": "host_lab", "host_epoch": "epoch_1",
            "profile_digest": "a".repeat(64), "requester": "agent_1", "requester_uid": 4242,
            "issuer": "operator_1", "signer_policy_epoch": "policy_1",
            "verifier_sha256": hex(&fs::read(KEYGEN).unwrap()),
            "provisioning": {
                "wordpress_713_sha256": "e".repeat(64),
                "uid_min": 3001, "uid_max": 3099, "category_min": 201, "category_max": 299,
                "quota": {"block_hard_kib": 262144, "inode_hard": 20000},
            },
            "ols": {
                "listener": "W382", "address": "127.0.0.1:8090", "adopted": [],
                "parent_sha256": "b".repeat(64), "webadmin_port": 7080,
            },
        });
        let policy_dir = &self.anchor.policy_dir;
        private_file(
            &policy_dir.join("policy.json"),
            &serde_json::to_vec(&policy).unwrap(),
        );
        let public = fs::read_to_string(self.root.join("keys/key.pub")).unwrap();
        let public: Vec<_> = public.split_whitespace().take(2).collect();
        private_file(
            &policy_dir.join("allowed_signers"),
            format!(
                "operator_1 namespaces=\"rustiron-plan-v1\" {}\n",
                public.join(" ")
            )
            .as_bytes(),
        );
        private_file(&policy_dir.join("revocations"), b"");
    }

    fn journal(&self) -> FixtureJournal {
        FixtureJournal::open_as_process_owner(
            &self.anchor.journal_dir,
            id("host_lab"),
            id("epoch_1"),
        )
        .unwrap()
    }

    /// The row a bootstrap activation leaves at `crash`, recorded the way
    /// `apply_generation` records it.
    fn crash(&self, crash: Crash) {
        let (empty, empty_digest) = ols::bootstrap_generation();
        let (first, first_digest) = target();
        let intent = Intent {
            operation_id: id("op_boot"),
            idempotency_key: id("key_boot"),
            grant_id: id("grant_boot"),
            nonce: id("nonce_boot"),
            plan_digest: sha(b"plan"),
            grant_digest: sha(b"grant"),
            host_id: id("host_lab"),
            host_epoch: id("epoch_1"),
            resource_id: id("ols_lab_listener"),
            predecessor_generation: empty,
            predecessor_digest: empty_digest,
            target_generation: first,
            target_digest: first_digest,
            expires_at: time(10_000),
            compensation_valid_until: time(10_300),
        };
        let mut journal = self.journal();
        journal.record_intent(&intent, time(1000)).unwrap();
        if matches!(crash, Crash::Intent) {
            return;
        }
        journal.mark_effect_attempted(&intent.operation_id).unwrap();
        if matches!(crash, Crash::EffectMark) {
            return;
        }
        // The unverified activation blocks, then marks its one restore.
        journal
            .record_observation(&intent.operation_id, None, None)
            .unwrap();
        journal
            .begin_compensation(&intent.operation_id, time(1001))
            .unwrap();
    }

    /// The reply the stub helper gives to the confirmation.
    fn answer(&self, reply: &str) {
        self.script.lock().unwrap().reply = format!("{reply}\n");
    }

    /// The steps the stub saw since the last call, in order.
    fn steps(&self) -> Vec<String> {
        std::mem::take(&mut self.script.lock().unwrap().seen)
    }

    fn open(&self) -> Executor {
        Executor::open(self.anchor.clone()).unwrap()
    }

    fn state(&self) -> RecordedState {
        self.open().status(&id("op_boot")).unwrap().unwrap().state
    }

    /// The OLS history after the settlement: nothing unresolved, and the
    /// bootstrap predecessor re-established, so a new bootstrap activation
    /// is admitted without an epoch rotation.
    fn history_admits_a_new_bootstrap(&self) -> bool {
        let journal = self.journal();
        let history = journal
            .resource_history(
                &id("ols_lab_listener"),
                None,
                Some(&ols::bootstrap_generation()),
            )
            .unwrap();
        journal
            .unresolved_operation(&id("ols_lab_listener"))
            .unwrap()
            .is_none()
            && ols::bootstrap_history_admits(&history)
            && history != ResourceHistory::Unresolved
    }
}

/// A stub admin helper: it records each step and answers with the scripted
/// reply, or `FIXTURE_BINDING_DENIED` when nothing is scripted.
fn stub_helper(socket: &Path, script: Arc<Mutex<Script>>) {
    let listener = UnixListener::bind(socket).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut request = String::new();
            let _ = stream.read_to_string(&mut request);
            let step = request
                .trim_end()
                .rsplit(' ')
                .next()
                .unwrap_or("")
                .to_owned();
            let reply = {
                let mut script = script.lock().unwrap();
                script.seen.push(step);
                if script.reply.is_empty() {
                    "FIXTURE_BINDING_DENIED\n".to_owned()
                } else {
                    script.reply.clone()
                }
            };
            let _ = stream.write_all(reply.as_bytes());
        }
    });
}

fn drift() -> String {
    ExecutorError::Drift.code().to_owned()
}

/// `AfterOlsIntent`: nothing changed on the host. The helper confirms the
/// bootstrap state, and `reconcile` records `untouched`. No restore exists.
#[test]
fn a_bootstrap_crash_after_the_intent_reconciles_untouched() {
    let lab = Lab::new("intent", Crash::Intent);
    assert_eq!(lab.state(), RecordedState::Intent);
    lab.answer("ok");
    let mut executor = lab.open();
    let settled = executor.reconcile(&id("op_boot")).unwrap();
    assert_eq!(settled.state, RecordedState::Untouched);
    assert_eq!(lab.steps(), [CONFIRM]);
    assert_eq!(
        executor.compensate(&id("op_boot"), Some(time(1200))).err(),
        Some(ExecutorError::CompensationDenied),
        "no effect was attempted"
    );
    assert!(lab.steps().is_empty());
    drop(executor);
    assert!(lab.history_admits_a_new_bootstrap());
}

/// `AfterOlsEffectMark`: the switch never ran, so `current` is absent and
/// OLS is stopped. `AfterOlsServing` after a boot: the boot guard removed
/// `current` and OLS stayed down. Both are the bootstrap predecessor, so
/// `reconcile` records `untouched`, as the running activation does.
#[test]
fn a_bootstrap_crash_after_the_effect_mark_reconciles_untouched_when_confirmed() {
    let lab = Lab::new("effect-mark", Crash::EffectMark);
    lab.answer("ok");
    let mut executor = lab.open();
    let settled = executor.reconcile(&id("op_boot")).unwrap();
    assert_eq!(settled.state, RecordedState::Untouched);
    assert_eq!(lab.steps(), [CONFIRM]);
    assert_eq!(
        executor.compensate(&id("op_boot"), Some(time(1200))).err(),
        Some(ExecutorError::CompensationDenied),
        "an untouched operation has nothing to restore"
    );
    drop(executor);
    assert!(lab.history_admits_a_new_bootstrap());
}

/// `AfterOlsServing` without a boot: `current` is the target and OLS
/// serves it. The helper refuses, so `reconcile` records `needs_attention`
/// and the single signed restore stays. After the boot guard (or the
/// restore) brings back the bootstrap state, a second `reconcile` asks
/// again: the confirmation is read-only, so it is not a run-once step.
#[test]
fn a_bootstrap_crash_after_serving_stays_needs_attention_until_confirmed() {
    let lab = Lab::new("serving", Crash::EffectMark);
    lab.answer(&drift());
    let mut executor = lab.open();
    let blocked = executor.reconcile(&id("op_boot")).unwrap();
    assert_eq!(blocked.state, RecordedState::NeedsAttention);
    assert_eq!(lab.steps(), [CONFIRM]);
    let again = executor.reconcile(&id("op_boot")).unwrap();
    assert_eq!(again.state, RecordedState::NeedsAttention);
    assert_eq!(lab.steps(), [CONFIRM]);
    drop(executor);
    assert!(!lab.history_admits_a_new_bootstrap());
    lab.answer("ok");
    let settled = lab.open().reconcile(&id("op_boot")).unwrap();
    assert_eq!(settled.state, RecordedState::Untouched);
    assert_eq!(lab.steps(), [CONFIRM]);
    assert!(lab.history_admits_a_new_bootstrap());
}

/// `AfterOlsRestoreMark`: the one restore was spent at the mark. While OLS
/// still serves the target, the helper refuses and the row stays
/// `needs_attention`. After the operator stops OLS and the boot guard
/// removes `current`, the helper confirms, and `reconcile` records
/// `failed_compensated`.
#[test]
fn a_bootstrap_crash_after_the_restore_mark_settles_failed_compensated_when_confirmed() {
    let lab = Lab::new("restore-mark", Crash::RestoreMark);
    assert_eq!(lab.state(), RecordedState::Compensating);
    lab.answer(&drift());
    let mut executor = lab.open();
    let blocked = executor.reconcile(&id("op_boot")).unwrap();
    assert_eq!(blocked.state, RecordedState::NeedsAttention);
    assert_eq!(lab.steps(), [CONFIRM]);
    assert_eq!(
        executor.compensate(&id("op_boot"), Some(time(1200))).err(),
        Some(ExecutorError::CompensationDenied),
        "the one restore was spent at the mark"
    );
    assert!(lab.steps().is_empty());
    lab.answer("ok");
    let settled = executor.reconcile(&id("op_boot")).unwrap();
    assert_eq!(settled.state, RecordedState::FailedCompensated);
    assert_eq!(lab.steps(), [CONFIRM]);
    drop(executor);
    assert!(lab.history_admits_a_new_bootstrap());
}

/// A helper that refuses the binding (wrong peer, wrong journal state) or
/// answers with a payload records nothing: the binding refusal is an
/// error, and an `ok` with a payload is not a confirmation.
#[test]
fn a_refused_or_unexpected_confirmation_never_records_the_predecessor() {
    for crash in [Crash::Intent, Crash::EffectMark, Crash::RestoreMark] {
        let lab = Lab::new(&format!("refused-{crash:?}").to_lowercase(), crash);
        let before = lab.state();
        lab.answer(ExecutorError::BindingDenied.code());
        assert_eq!(
            lab.open().reconcile(&id("op_boot")).err(),
            Some(ExecutorError::BindingDenied),
            "{crash:?}"
        );
        assert_eq!(lab.state(), before, "{crash:?}: a refusal recorded a state");
        lab.answer("ok facts");
        let row = lab.open().reconcile(&id("op_boot")).unwrap();
        assert_eq!(row.state, RecordedState::NeedsAttention, "{crash:?}");
        lab.answer("garbled reply");
        let row = lab.open().reconcile(&id("op_boot")).unwrap();
        assert_eq!(row.state, RecordedState::NeedsAttention, "{crash:?}");
        assert!(!lab.history_admits_a_new_bootstrap(), "{crash:?}");
    }
}

/// A settled row is never reconciled again: no step, the same state.
#[test]
fn a_settled_bootstrap_row_is_not_asked_again() {
    let lab = Lab::new("settled", Crash::Intent);
    lab.answer("ok");
    let mut executor = lab.open();
    assert_eq!(
        executor.reconcile(&id("op_boot")).unwrap().state,
        RecordedState::Untouched
    );
    lab.steps();
    lab.answer(&drift());
    assert_eq!(
        executor.reconcile(&id("op_boot")).unwrap().state,
        RecordedState::Untouched
    );
    assert!(lab.steps().is_empty());
}

/// Raises the admission mark count by one; returns the previous bytes.
fn raise_mark(lab: &Lab) -> Vec<u8> {
    let path = lab.anchor.mark_dir.join("admission-mark");
    let before = fs::read(&path).unwrap();
    let text = String::from_utf8(before.clone()).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let count: u64 = lines.last().unwrap().parse().unwrap();
    *lines.last_mut().unwrap() = (count + 1).to_string();
    private_file(&path, format!("{}\n", lines.join("\n")).as_bytes());
    before
}

/// W394 (B06): the boot guard (W381) and the bootstrap `reconcile` (W382)
/// never act on a journal they cannot trust. For a journal behind its mark,
/// a missing mark, an emptied, truncated, or missing journal, a policy of
/// another epoch, and a journal lease held by a running executor, the guard
/// reports the journal as unknown and keeps `current`, writes neither the
/// journal nor the mark, and sends no helper step. `reconcile` cannot open
/// the journal, so it sends no `ols_bootstrap_confirm` either. The control
/// is the same row with the trusted journal: the guard finds it pending.
#[test]
fn w394_the_boot_guard_and_reconcile_never_act_on_an_untrusted_journal() {
    use rustiron_executor::ols::boot_guard::{GuardDecision, JournalFinding, KeepReason};

    let lab = Lab::new("w394-guard", Crash::EffectMark);
    // The rows were written straight into the journal; an executor open
    // fences them, so the mark holds the journal's admission count.
    drop(lab.open());
    let journal = lab.anchor.journal_dir.join("fixture-journal.sqlite");
    let mark_path = lab.anchor.mark_dir.join("admission-mark");
    let real = fs::read(&journal).unwrap();
    let mark = fs::read(&mark_path).unwrap();
    let spare = lab.root.join("spare");
    private_dir(&spare);
    drop(FixtureJournal::initialize(&spare, id("host_lab"), id("epoch_1")).unwrap());
    let empty = fs::read(spare.join("fixture-journal.sqlite")).unwrap();
    lab.answer("ok");

    let control = Executor::ols_boot_guard(lab.anchor.clone());
    assert!(
        matches!(&control.journal, JournalFinding::Pending(activation)
            if activation.operation_id == id("op_boot") && activation.effect_attempted),
        "{control:?}"
    );
    assert_eq!(control.json()["journal_written"], false);
    assert_eq!(fs::read(&journal).unwrap(), real);

    let unknown = |case: &str, expected: Option<&str>, reconcile: bool| {
        let state = (fs::read(&journal).ok(), fs::read(&mark_path).ok());
        let report = Executor::ols_boot_guard(lab.anchor.clone());
        let JournalFinding::Unknown(code) = report.journal else {
            panic!("{case}: the guard trusted the journal: {report:?}");
        };
        if let Some(expected) = expected {
            assert_eq!(code, expected, "{case}");
        }
        assert_eq!(
            report.decision,
            GuardDecision::Keep(KeepReason::JournalUnknown),
            "{case}"
        );
        assert_eq!(report.json()["journal_written"], false, "{case}");
        assert_eq!(report.restored, None, "{case}");
        if reconcile {
            assert!(
                Executor::open(lab.anchor.clone()).is_err(),
                "{case}: reconcile opened"
            );
        }
        assert_eq!(
            (fs::read(&journal).ok(), fs::read(&mark_path).ok()),
            state,
            "{case} wrote state"
        );
        assert!(lab.steps().is_empty(), "{case} sent a helper step");
    };

    raise_mark(&lab);
    unknown("journal behind the mark", Some("JOURNAL_ROLLBACK"), true);
    fs::remove_file(&mark_path).unwrap();
    unknown("missing mark", Some("JOURNAL_ROLLBACK"), true);
    private_file(&mark_path, &mark);

    private_file(&journal, &empty);
    unknown("emptied journal", Some("JOURNAL_ROLLBACK"), true);
    private_file(&journal, &real[..real.len() / 2]);
    unknown("truncated journal", None, true);
    fs::remove_file(&journal).unwrap();
    unknown("missing journal", None, true);
    private_file(&journal, &real);

    let policy_path = lab.anchor.policy_dir.join("policy.json");
    let policy = fs::read(&policy_path).unwrap();
    let mut rotated: serde_json::Value = serde_json::from_slice(&policy).unwrap();
    rotated["host_epoch"] = json!("epoch_2");
    private_file(&policy_path, &serde_json::to_vec(&rotated).unwrap());
    unknown("policy of another epoch", None, true);
    private_file(&policy_path, &policy);

    let running = lab.open();
    unknown("journal lease held", None, false);
    drop(running);

    // The trusted journal again: pending, with nothing written.
    let report = Executor::ols_boot_guard(lab.anchor.clone());
    assert!(matches!(report.journal, JournalFinding::Pending(_)));
    assert_eq!(fs::read(&journal).unwrap(), real);
    assert_eq!(fs::read(&mark_path).unwrap(), mark);
}
