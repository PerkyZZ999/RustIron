//! W329 (B06): crash points and abuse cases for product v2 capture and
//! restore probe admission, against the stub helper.
//!
//! Each crash point stops the executor after a durable step. A restarted
//! executor must keep the intent `running`, answer an exact replay from
//! stored status, refuse the consumed grant and any new work of the verb,
//! and never run the helper again.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use rustiron_contracts::{
    Id,
    execution::{OutcomeState, SubmissionReply},
};
use rustiron_executor::{Executor, ExecutorError, Fault};
use rustiron_journal::{CaptureState, ProbeState};
use serde_json::{Value, json};

use super::{
    BackupFixture, PROJECTION,
    admission::{capture_vector, id, probe_vector, provision, stub_helper_for},
    private_file,
    verification::{SignedBackup, enroll},
};

const REFUSED: &str = "NOT_ADMITTED_FOR_EFFECT\n";

#[derive(Clone, Copy, Debug)]
enum Verb {
    Capture,
    Probe,
}

impl Verb {
    fn step(self) -> &'static str {
        match self {
            Self::Capture => "capture_run",
            Self::Probe => "probe_run",
        }
    }

    fn site(self) -> &'static str {
        match self {
            Self::Capture => "blog9",
            Self::Probe => "blog13",
        }
    }

    /// W381 (D-032): the reply state of a recorded failure: `failed` for a
    /// capture, `untouched` for a probe whose sandbox is gone.
    fn failed_reply(self) -> OutcomeState {
        match self {
            Self::Capture => OutcomeState::Failed,
            Self::Probe => OutcomeState::Untouched,
        }
    }

    fn vector(self) -> (Value, Value) {
        match self {
            Self::Capture => capture_vector(),
            Self::Probe => probe_vector(),
        }
    }

    /// Whether the journal holds the operation, and whether it is `running`.
    fn recorded(self, executor: &Executor, operation: &Id) -> Option<bool> {
        match self {
            Self::Capture => executor
                .capture_status(operation)
                .unwrap()
                .map(|capture| capture.state == CaptureState::Running),
            Self::Probe => executor
                .probe_status(operation)
                .unwrap()
                .map(|probe| probe.state == ProbeState::Running),
        }
    }
}

/// The same signed scope under a new grant ID and nonce.
fn fresh(grant: &Value, name: &str) -> Value {
    let mut grant = grant.clone();
    grant["grant_id"] = json!(format!("grant_{name}"));
    grant["nonce"] = json!(format!("nonce_{name}"));
    grant
}

/// One enrolled, provisioned fixture with a counting stub helper. The
/// executor is declared first so that it closes before the fixture goes.
struct Setup {
    executor: Option<Executor>,
    calls: Arc<AtomicUsize>,
    policy: Value,
    plan: Value,
    grant: Value,
    fixture: BackupFixture,
}

impl Setup {
    fn new(verb: Verb, reply: &'static str) -> Self {
        let mut fixture = BackupFixture::new();
        let policy = enroll(&fixture);
        let calls = stub_helper_for(&mut fixture.anchor, verb.step(), reply);
        provision(&fixture.anchor, verb.site());
        let executor = Some(Executor::open(fixture.anchor.clone()).unwrap());
        let (plan, grant) = verb.vector();
        Self {
            executor,
            calls,
            policy,
            plan,
            grant,
            fixture,
        }
    }

    fn executor(&mut self) -> &mut Executor {
        self.executor.as_mut().unwrap()
    }

    /// A crash ends the process: the next executor opens the same state.
    fn restart(&mut self) {
        drop(self.executor.take());
        self.executor = Some(Executor::open(self.fixture.anchor.clone()).unwrap());
    }

    fn helper_runs(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// Submits and checks the refusal code, that the journal and admission
    /// mark are byte-identical, and that the helper did not run.
    fn refuse(
        &mut self,
        signed: &SignedBackup,
        operation: &Id,
        key: &Id,
        error: ExecutorError,
    ) -> SubmissionReply {
        let (state, runs) = (self.fixture.replay_state(), self.helper_runs());
        let reply = signed.submit(self.executor(), operation, key);
        assert_eq!(reply.error.as_deref(), Some(error.code()), "{reply:?}");
        assert!(!reply.replay, "{reply:?}");
        assert!(
            self.fixture.replay_state() == state,
            "{error:?} wrote state"
        );
        assert_eq!(self.helper_runs(), runs, "{error:?} ran the helper");
        reply
    }
}

/// Stops at `fault` during a first admission, restarts the executor, and
/// checks what the journal holds. `helper_runs` is how many helper requests
/// the crash allowed (0 before the request, 1 after the reply).
fn crash_at(verb: Verb, fault: Fault, helper_runs: usize) -> (Setup, Id) {
    let mut setup = Setup::new(verb, REFUSED);
    let (_, mark_before) = setup.fixture.replay_state();
    let signed = SignedBackup::new(&setup.fixture, &setup.plan, setup.grant.clone());
    let (operation, key) = (id("op_w329_crash"), id("key_w329_crash"));

    setup.executor().inject_fault(fault);
    let reply = signed.submit(setup.executor(), &operation, &key);
    assert_eq!(reply.state, Some(OutcomeState::Intent), "{reply:?}");
    assert_eq!(
        reply.error.as_deref(),
        Some(ExecutorError::Unavailable.code())
    );
    assert_eq!(setup.helper_runs(), helper_runs);

    // Restart: the intent and the advanced admission mark are durable.
    setup.restart();
    assert_eq!(verb.recorded(setup.executor(), &operation), Some(true));
    let (journal, mark) = setup.fixture.replay_state();
    assert_ne!(mark, mark_before, "the admission mark did not advance");

    // An exact replay answers stored status and starts no helper run.
    let replay = signed.submit(setup.executor(), &operation, &key);
    assert!(replay.replay);
    assert_eq!(replay.state, Some(OutcomeState::Intent));
    assert_eq!(replay.error, None);
    assert_eq!(setup.helper_runs(), helper_runs);
    assert!(setup.fixture.replay_state() == (journal, mark));

    // The consumed grant cannot start another operation.
    let other = id("op_w329_other");
    let refused = setup.refuse(
        &signed,
        &other,
        &id("key_w329_other"),
        ExecutorError::ReplayDenied,
    );
    assert_eq!(refused.state, None);
    assert_eq!(verb.recorded(setup.executor(), &other), None);

    // A new grant for the same verb waits for the `running` one.
    let next = SignedBackup::new(
        &setup.fixture,
        &setup.plan,
        fresh(&setup.grant, "w329_next"),
    );
    let blocked = id("op_w329_next");
    let refused = setup.refuse(&next, &blocked, &id("key_w329_next"), ExecutorError::Busy);
    assert_eq!(refused.error.as_deref(), Some("UNRESOLVED_OPERATION"));
    assert_eq!(refused.state, None);
    assert_eq!(verb.recorded(setup.executor(), &blocked), None);

    assert_eq!(verb.recorded(setup.executor(), &operation), Some(true));
    (setup, operation)
}

/// Capture recovery re-binds the journaled destination digest. After a
/// re-enrollment it refuses before any host command, and the capture stays
/// `running` (the unchanged-destination recovery is the W321 root test).
fn capture_stays_running_until_recovery(setup: &mut Setup, operation: &Id) {
    let mut projection: Value = serde_json::from_slice(PROJECTION).unwrap();
    projection["retention_days"] = json!(31);
    let changed = serde_json::to_vec(&projection).unwrap();
    let mut changed_policy = setup.policy.clone();
    changed_policy["product_backup"]["destination_policy_digest"] = json!(
        rustiron_contracts::approval::ProductBackupPolicy::decode(&changed)
            .unwrap()
            .digest()
    );
    private_file(&setup.fixture.projection_path(), &changed);
    setup.fixture.write_policy(&changed_policy);
    let state = setup.fixture.replay_state();
    assert_eq!(
        setup.executor().reconcile_capture(operation).err(),
        Some(ExecutorError::PreconditionChanged)
    );
    assert!(setup.fixture.replay_state() == state);
    // W366: the unclaimed settlement re-binds the same digest first, so a
    // failed re-verification records nothing and the capture stays
    // `running`.
    assert_eq!(
        setup.executor().settle_capture_unclaimed(operation).err(),
        Some(ExecutorError::PreconditionChanged)
    );
    assert!(setup.fixture.replay_state() == state);
    private_file(&setup.fixture.projection_path(), PROJECTION);
    setup.fixture.write_policy(&setup.policy);
    assert_eq!(
        Verb::Capture.recorded(setup.executor(), operation),
        Some(true)
    );
}

#[test]
fn crash_after_product_capture_admission_keeps_the_intent_running() {
    let (mut setup, operation) = crash_at(Verb::Capture, Fault::AfterProductAdmission, 0);
    capture_stays_running_until_recovery(&mut setup, &operation);
}

#[test]
fn crash_after_the_capture_helper_reply_keeps_the_intent_running() {
    // The helper refused, but the crash lost that known failure: the
    // capture stays `running` rather than becoming `failed` unrecorded.
    let (mut setup, operation) = crash_at(Verb::Capture, Fault::AfterProductHelperReply, 1);
    capture_stays_running_until_recovery(&mut setup, &operation);
}

/// W366: settling a capture that is not `running` is a replay. It returns
/// the stored status without the binding, the store or a write, even after
/// a re-enrollment that a real settlement would refuse. An unknown
/// operation is `NOT_ADMITTED`.
#[test]
fn settling_a_finished_capture_returns_its_stored_status_without_writes() {
    let mut setup = Setup::new(Verb::Capture, REFUSED);
    let signed = SignedBackup::new(&setup.fixture, &setup.plan, setup.grant.clone());
    let operation = id("op_w366_finished");
    let reply = signed.submit(setup.executor(), &operation, &id("key_w366_finished"));
    assert_eq!(reply.error.as_deref(), Some("NOT_ADMITTED_FOR_EFFECT"));
    let stored = setup
        .executor()
        .capture_status(&operation)
        .unwrap()
        .unwrap();
    assert_eq!(stored.state, CaptureState::Failed);
    assert_eq!(stored.unclaimed_snapshot_id, None);
    let mut projection: Value = serde_json::from_slice(PROJECTION).unwrap();
    projection["retention_days"] = json!(31);
    private_file(
        &setup.fixture.projection_path(),
        &serde_json::to_vec(&projection).unwrap(),
    );
    let state = setup.fixture.replay_state();
    for _ in 0..2 {
        assert_eq!(
            setup.executor().settle_capture_unclaimed(&operation),
            Ok(stored.clone())
        );
    }
    assert!(setup.fixture.replay_state() == state);
    assert_eq!(setup.helper_runs(), 1);
    assert_eq!(
        setup
            .executor()
            .settle_capture_unclaimed(&id("op_w366_unknown"))
            .err(),
        Some(ExecutorError::NotAdmitted)
    );
}

#[test]
fn crash_after_product_probe_admission_keeps_the_intent_running() {
    crash_at(Verb::Probe, Fault::AfterProductAdmission, 0);
}

#[test]
fn crash_after_the_probe_helper_reply_keeps_the_intent_running() {
    crash_at(Verb::Probe, Fault::AfterProductHelperReply, 1);
}

/// `cleanup_probe` runs `systemctl`, `semanage`, `mariadb`, `userdel` and
/// `rm` on the host, so it needs root on the lab host. Unprivileged, the
/// observations fail and the probe would end `cleanup_incomplete`.
#[test]
#[ignore = "root lab test: cleanup_probe runs host administration commands"]
fn crashed_product_probe_is_settled_failed_by_cleanup_as_root() {
    for (fault, runs) in [
        (Fault::AfterProductAdmission, 0),
        (Fault::AfterProductHelperReply, 1),
    ] {
        let (mut setup, operation) = crash_at(Verb::Probe, fault, runs);
        let probe = setup.executor().cleanup_probe(&operation).unwrap();
        assert_eq!(probe.state, ProbeState::Failed);
        let receipt: Value = serde_json::from_str(probe.receipt.as_deref().unwrap()).unwrap();
        assert_eq!(receipt["admin_cleanup"], true);
        assert_eq!(receipt["cleanup"]["status"], "complete");
        assert_eq!(receipt["cleanup"]["leftover_resources"], 0);
        // Settled: a new grant for the verb is admitted again.
        let next = SignedBackup::new(
            &setup.fixture,
            &setup.plan,
            fresh(&setup.grant, "w329_after_cleanup"),
        );
        let reply = next.submit(
            setup.executor(),
            &id("op_w329_after_cleanup"),
            &id("key_w329_after_cleanup"),
        );
        assert_eq!(reply.error.as_deref(), Some("NOT_ADMITTED_FOR_EFFECT"));
        assert_eq!(setup.helper_runs(), runs + 1);
    }
}

/// Abuse of an otherwise valid request on a provisioned site with a helper:
/// each is refused with its code, and the journal and admission mark stay
/// byte-identical. A final unmodified request is admitted, so each refusal
/// comes from the abuse and not from the setup.
fn abuse_is_refused_without_writes(verb: Verb) {
    let mut setup = Setup::new(verb, REFUSED);
    let first = SignedBackup::new(&setup.fixture, &setup.plan, setup.grant.clone());
    let admitted = id("op_w329_admitted");
    let reply = first.submit(setup.executor(), &admitted, &id("key_w329_admitted"));
    assert_eq!(reply.error.as_deref(), Some("NOT_ADMITTED_FOR_EFFECT"));
    assert_eq!(setup.helper_runs(), 1);

    let grant = fresh(&setup.grant, "w329_abuse");
    let valid = SignedBackup::new(&setup.fixture, &setup.plan, grant.clone());
    let (operation, key) = (id("op_w329_abuse"), id("key_w329_abuse"));
    let copy = |signed: &SignedBackup| SignedBackup {
        plan: signed.plan.clone(),
        grant: signed.grant.clone(),
        signature: signed.signature.clone(),
    };

    // A tampered signature over the exact grant bytes.
    let mut tampered = copy(&valid);
    let text = String::from_utf8(tampered.signature.clone()).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let body = lines.len() - 2;
    let flipped = if lines[body].starts_with('A') {
        "B"
    } else {
        "A"
    };
    lines[body].replace_range(0..1, flipped);
    tampered.signature = format!("{}\n", lines.join("\n")).into_bytes();
    assert_ne!(tampered.signature, valid.signature);
    let reply = setup.refuse(&tampered, &operation, &key, ExecutorError::SignatureDenied);
    assert_eq!(reply.state, None);

    // The kernel peer is not the enrolled requester. Naming an existing
    // operation must not disclose its stored status either.
    let mut other_peer = setup.policy.clone();
    other_peer["requester_uid"] = json!(rustix::process::getuid().as_raw().wrapping_add(1));
    setup.fixture.write_policy(&other_peer);
    let reply = setup.refuse(&valid, &operation, &key, ExecutorError::PeerDenied);
    assert_eq!(reply.state, None);
    let reply = setup.refuse(&first, &admitted, &key, ExecutorError::PeerDenied);
    assert_eq!(reply.state, None, "a wrong peer saw stored status");
    let policy = setup.policy.clone();
    setup.fixture.write_policy(&policy);

    // An expired grant and plan.
    let (mut expired_plan, mut expired_grant) = (setup.plan.clone(), grant.clone());
    for record in [&mut expired_plan, &mut expired_grant] {
        record["valid_from"] = json!(1100);
        record["expires_at"] = json!(1200);
    }
    let expired = SignedBackup::new(&setup.fixture, &expired_plan, expired_grant);
    let reply = setup.refuse(&expired, &operation, &key, ExecutorError::TimeDenied);
    assert_eq!(reply.state, None);

    // A validly signed grant presented with a plan it does not digest.
    let mut substituted = copy(&valid);
    let mut plan = setup.plan.clone();
    plan["expires_at"] = json!(plan["expires_at"].as_u64().unwrap() - 1);
    substituted.plan = serde_json::to_vec(&plan).unwrap();
    let reply = setup.refuse(&substituted, &operation, &key, ExecutorError::BindingDenied);
    assert_eq!(reply.state, None);

    // W377: a well-formed signature by a key the allowlist does not name,
    // and the enrolled key revoked after it signed.
    super::new_key(&setup.fixture.root.join("other"));
    let mut forged = copy(&valid);
    forged.signature = super::sign(
        &setup.fixture.root.join("other"),
        &setup.fixture.root.join("message"),
        rustiron_contracts::CanonicalObject::decode(&valid.grant)
            .unwrap()
            .as_bytes(),
        "rustiron-plan-v1",
    );
    let reply = setup.refuse(&forged, &operation, &key, ExecutorError::SignatureDenied);
    assert_eq!(reply.state, None);
    let revocations = setup.fixture.anchor.policy_dir.join("revocations");
    private_file(
        &revocations,
        &std::fs::read(setup.fixture.root.join("key.pub")).unwrap(),
    );
    let reply = setup.refuse(&valid, &operation, &key, ExecutorError::SignatureDenied);
    assert_eq!(reply.state, None);
    private_file(&revocations, b"");

    // W377: signed for another host; and a policy re-enrolled to another
    // epoch while this journal is open, with a grant for that epoch.
    let (mut other_plan, mut other_grant) = (setup.plan.clone(), grant.clone());
    for record in [&mut other_plan, &mut other_grant] {
        record["host_id"] = json!("host_other");
    }
    let other_host = SignedBackup::new(&setup.fixture, &other_plan, other_grant);
    let reply = setup.refuse(&other_host, &operation, &key, ExecutorError::BindingDenied);
    assert_eq!(reply.state, None);
    let (mut rotated_plan, mut rotated_grant) = (setup.plan.clone(), grant.clone());
    for record in [&mut rotated_plan, &mut rotated_grant] {
        record["host_epoch"] = json!("epoch_2");
    }
    let rotated = SignedBackup::new(&setup.fixture, &rotated_plan, rotated_grant);
    let mut rotated_policy = setup.policy.clone();
    rotated_policy["host_epoch"] = json!("epoch_2");
    setup.fixture.write_policy(&rotated_policy);
    let reply = setup.refuse(&rotated, &operation, &key, ExecutorError::IdentityMismatch);
    assert_eq!(reply.state, None);
    let policy = setup.policy.clone();
    setup.fixture.write_policy(&policy);

    // W377: the consumed grant under a new operation, and the admitted
    // idempotency key on a new operation with other bytes.
    let reply = setup.refuse(&first, &operation, &key, ExecutorError::ReplayDenied);
    assert_eq!(reply.state, None);
    let reply = setup.refuse(
        &valid,
        &operation,
        &id("key_w329_admitted"),
        ExecutorError::ReplayDenied,
    );
    assert_eq!(reply.state, None);

    // W377: the journal behind the admission mark. No fallback admission,
    // and the refusal carries no stored status.
    let mark_path = setup.fixture.anchor.mark_dir.join("admission-mark");
    let mark = std::fs::read(&mark_path).unwrap();
    let text = String::from_utf8(mark.clone()).unwrap();
    let count: u64 = text.lines().last().unwrap().parse().unwrap();
    let raised = text.replace(&format!("\n{count}\n"), &format!("\n{}\n", count + 1));
    private_file(&mark_path, raised.as_bytes());
    let reply = setup.refuse(&valid, &operation, &key, ExecutorError::JournalRollback);
    assert_eq!(reply.state, None);
    // The replay check reads the journal before the fence, so a changed
    // key under the admitted ID is still a replay refusal; the stored
    // status needs the fence, as a status query does, and is withheld.
    let reply = setup.refuse(
        &first,
        &admitted,
        &id("key_w329_changed"),
        ExecutorError::ReplayDenied,
    );
    assert_eq!(reply.state, None, "a fenced journal gave stored status");
    private_file(&mark_path, &mark);

    // The admitted operation ID under another idempotency key, with its own
    // grant or a new one: a replay refusal, never stored status as a replay.
    for signed in [&first, &valid] {
        let reply = setup.refuse(
            signed,
            &admitted,
            &id("key_w329_changed"),
            ExecutorError::ReplayDenied,
        );
        assert_eq!(reply.state, Some(verb.failed_reply()));
    }
    assert_eq!(verb.recorded(setup.executor(), &operation), None);

    // Control: the unmodified request is admitted.
    let before = setup.fixture.replay_state();
    let reply = valid.submit(setup.executor(), &operation, &key);
    assert_eq!(reply.error.as_deref(), Some("NOT_ADMITTED_FOR_EFFECT"));
    assert_eq!(reply.state, Some(verb.failed_reply()));
    assert_eq!(setup.helper_runs(), 2);
    assert!(setup.fixture.replay_state() != before);
}

#[test]
fn product_capture_abuse_is_refused_without_writes() {
    abuse_is_refused_without_writes(Verb::Capture);
}

#[test]
fn product_probe_abuse_is_refused_without_writes() {
    abuse_is_refused_without_writes(Verb::Probe);
}
