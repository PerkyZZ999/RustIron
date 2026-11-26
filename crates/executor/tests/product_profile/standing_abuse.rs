//! W394 (B06): the abuse matrix of a standing capture run (D-035, W386).
//!
//! W386 tested the window, the run identity, the destination and the plan
//! digest. These cases add the peer, the signature, the signer, the signer
//! epoch, the host and epoch, the time, a cross-site scope, a swapped grant
//! or run, the journal behind its admission mark, and an emptied or
//! truncated journal. Each refusal has its code, leaves the journal and the
//! admission mark byte-identical, records no capture row, and starts no
//! helper run. A final unmodified run is admitted, so each refusal comes
//! from the abuse and not from the setup.

use std::{
    fs,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use rustiron_contracts::{
    CanonicalObject, Id,
    approval::{SiteId, StandingCaptureGrant},
    execution::{OutcomeState, SubmissionReply},
};
use rustiron_executor::{AdmissionRequest, Executor, ExecutorError};
use rustiron_journal::FixtureJournal;
use serde_json::{Value, json};

use super::{
    BackupFixture,
    admission::{capture_vector, id, provision, provision_in, stub_helper_for},
    new_key, private_dir, private_file, sign,
    standing_capture::{run, standing},
    verification::{SignedBackup, enroll},
};

const JOURNAL: &str = "fixture-journal.sqlite";
const MARK: &str = "admission-mark";

struct Matrix {
    executor: Executor,
    calls: Arc<AtomicUsize>,
    policy: Value,
    fixture: BackupFixture,
}

impl Matrix {
    /// Enrolled, `blog9` and `blog13` provisioned, a counting stub helper.
    fn new() -> Self {
        let mut fixture = BackupFixture::new();
        let policy = enroll(&fixture);
        let calls = stub_helper_for(
            &mut fixture.anchor,
            "capture_run",
            "NOT_ADMITTED_FOR_EFFECT\n",
        );
        provision(&fixture.anchor, "blog9");
        provision_in(&fixture.anchor, "blog13");
        let executor = Executor::open(fixture.anchor.clone()).unwrap();
        Self {
            executor,
            calls,
            policy,
            fixture,
        }
    }

    fn runs(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// Submits the run that `signed` derives for `site` in window 0.
    fn submit(&mut self, signed: &SignedBackup, site: &str) -> SubmissionReply {
        let run = run(signed, site, 0);
        signed.submit(&mut self.executor, &run.operation_id, &run.idempotency_key)
    }

    /// One refusal before intent: its code, no replay, no state change, no
    /// row for a fresh operation, no helper run.
    fn refuse(
        &mut self,
        signed: &SignedBackup,
        operation: &Id,
        key: &Id,
        error: ExecutorError,
        case: &str,
    ) -> SubmissionReply {
        let fresh = self.executor.capture_status(operation).unwrap().is_none();
        let (state, runs) = (self.fixture.replay_state(), self.runs());
        let reply = signed.submit(&mut self.executor, operation, key);
        assert_eq!(
            reply.error.as_deref(),
            Some(error.code()),
            "{case}: {reply:?}"
        );
        assert!(!reply.replay, "{case}: {reply:?}");
        assert!(self.fixture.replay_state() == state, "{case} wrote state");
        assert_eq!(self.runs(), runs, "{case} ran the helper");
        if fresh {
            assert!(
                self.executor.capture_status(operation).unwrap().is_none(),
                "{case} left a row"
            );
        }
        reply
    }

    /// [`Self::refuse`] for the window 0 run of `site` under `signed`.
    fn refuse_run(
        &mut self,
        signed: &SignedBackup,
        site: &str,
        error: ExecutorError,
        case: &str,
    ) -> SubmissionReply {
        let run = run(signed, site, 0);
        self.refuse(signed, &run.operation_id, &run.idempotency_key, error, case)
    }

    fn sign(&self, plan: &Value, grant: Value) -> SignedBackup {
        SignedBackup::new(&self.fixture, plan, grant)
    }
}

/// A second standing grant for `sites`, with its own grant ID and nonce.
fn second(sites: &[&str], edit: impl FnOnce(&mut Value, &mut Value)) -> (Value, Value) {
    let (mut plan, mut grant) = standing(30, sites);
    grant["grant_id"] = json!("grant_w394_second");
    grant["nonce"] = json!("nonce_w394_second");
    edit(&mut plan, &mut grant);
    (plan, grant)
}

fn copy(signed: &SignedBackup) -> SignedBackup {
    SignedBackup {
        plan: signed.plan.clone(),
        grant: signed.grant.clone(),
        signature: signed.signature.clone(),
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one matrix over one fixture, in the W377 form"
)]
fn w394_standing_run_abuse_is_refused_before_any_record() {
    let mut m = Matrix::new();
    // The admitted run: grant G1, site blog9, window 0.
    let (plan, grant) = standing(30, &["blog9"]);
    let first = m.sign(&plan, grant);
    let admitted = run(&first, "blog9", 0);
    let reply = m.submit(&first, "blog9");
    assert_eq!(reply.state, Some(OutcomeState::Failed), "{reply:?}");
    assert_eq!(m.runs(), 1);

    // The run under test: grant G2, site blog13, window 0.
    let (plan2, grant2) = second(&["blog13"], |_, _| {});
    let valid = m.sign(&plan2, grant2.clone());
    let target = run(&valid, "blog13", 0);
    let (operation, key) = (target.operation_id.clone(), target.idempotency_key.clone());

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
    m.refuse(
        &tampered,
        &operation,
        &key,
        ExecutorError::SignatureDenied,
        "tampered",
    );

    // The kernel peer is not the enrolled requester. Naming the admitted
    // run must not disclose its stored status.
    let mut other_peer = m.policy.clone();
    other_peer["requester_uid"] = json!(rustix::process::getuid().as_raw().wrapping_add(1));
    m.fixture.write_policy(&other_peer);
    m.refuse(&valid, &operation, &key, ExecutorError::PeerDenied, "peer");
    let reply = m.refuse(
        &first,
        &admitted.operation_id,
        &admitted.idempotency_key,
        ExecutorError::PeerDenied,
        "peer, admitted run",
    );
    assert_eq!(reply.state, None, "a wrong peer saw stored status");
    let policy = m.policy.clone();
    m.fixture.write_policy(&policy);

    // A well-formed signature by a key the allowlist does not name.
    new_key(&m.fixture.root.join("other"));
    let mut forged = copy(&valid);
    forged.signature = sign(
        &m.fixture.root.join("other"),
        &m.fixture.root.join("message"),
        CanonicalObject::decode(&valid.grant).unwrap().as_bytes(),
        "rustiron-plan-v1",
    );
    m.refuse(
        &forged,
        &operation,
        &key,
        ExecutorError::SignatureDenied,
        "unlisted signer",
    );

    // The enrolled key, revoked after it signed.
    let revocations = m.fixture.anchor.policy_dir.join("revocations");
    private_file(
        &revocations,
        &fs::read(m.fixture.root.join("key.pub")).unwrap(),
    );
    m.refuse(
        &valid,
        &operation,
        &key,
        ExecutorError::SignatureDenied,
        "revoked signer",
    );
    private_file(&revocations, b"");

    // Another signer epoch, another issuer, another requester.
    for (field, value) in [
        ("signer_policy_epoch", "policy_9"),
        ("issuer", "operator_9"),
    ] {
        let (plan, grant) = second(&["blog13"], |_, grant| grant[field] = json!(value));
        let signed = m.sign(&plan, grant);
        m.refuse_run(&signed, "blog13", ExecutorError::BindingDenied, field);
    }
    let (plan, grant) = second(&["blog13"], |plan, grant| {
        plan["requester"] = json!("agent_9");
        grant["requester"] = json!("agent_9");
    });
    let signed = m.sign(&plan, grant);
    m.refuse_run(&signed, "blog13", ExecutorError::BindingDenied, "requester");

    // Signed for another host.
    let (plan, grant) = second(&["blog13"], |plan, grant| {
        plan["host_id"] = json!("host_other");
        grant["host_id"] = json!("host_other");
    });
    let signed = m.sign(&plan, grant);
    m.refuse_run(
        &signed,
        "blog13",
        ExecutorError::BindingDenied,
        "other host",
    );

    // A policy re-enrolled to another epoch while this journal is open,
    // with a grant for that epoch.
    let (plan, grant) = second(&["blog13"], |plan, grant| {
        plan["host_epoch"] = json!("epoch_2");
        grant["host_epoch"] = json!("epoch_2");
    });
    let rotated = m.sign(&plan, grant);
    let mut rotated_policy = m.policy.clone();
    rotated_policy["host_epoch"] = json!("epoch_2");
    m.fixture.write_policy(&rotated_policy);
    m.refuse_run(
        &rotated,
        "blog13",
        ExecutorError::IdentityMismatch,
        "re-enrolled epoch",
    );
    m.fixture.write_policy(&policy);

    // An expired grant and plan.
    let (plan, grant) = second(&["blog13"], |plan, grant| {
        for record in [plan, grant] {
            record["valid_from"] = json!(1100);
            record["first_window_start"] = json!(1100);
            record["expires_at"] = json!(1100 + 3_600);
        }
    });
    let signed = m.sign(&plan, grant);
    m.refuse_run(&signed, "blog13", ExecutorError::TimeDenied, "expired");

    // No reliable time at the executor.
    let request = AdmissionRequest {
        peer_uid: rustix::process::getuid().as_raw(),
        plan: &valid.plan,
        grant: &valid.grant,
        signature: &valid.signature,
        operation_id: operation.clone(),
        idempotency_key: key.clone(),
        now: None,
    };
    let state = m.fixture.replay_state();
    assert_eq!(
        m.executor.product_standing_capture(&request).err(),
        Some(ExecutorError::TimeDenied)
    );
    assert!(m.fixture.replay_state() == state, "no time wrote state");

    // Cross-site scope: a plan for blog13 under a grant signed for blog9.
    let (plan, _) = second(&["blog13"], |_, _| {});
    let (_, grant) = second(&["blog9"], |_, _| {});
    let signed = m.sign(&plan, grant);
    m.refuse_run(
        &signed,
        "blog9",
        ExecutorError::BindingDenied,
        "cross-site plan",
    );
    // A site the grant does not name (blog13 under G1).
    let foreign = rustiron_contracts::approval::standing_run(
        &StandingCaptureGrant::decode(&first.grant).unwrap().sha256(),
        &SiteId::try_from("blog13".to_owned()).unwrap(),
        0,
    );
    m.refuse(
        &first,
        &foreign.operation_id,
        &foreign.idempotency_key,
        ExecutorError::RunMismatch,
        "site not named",
    );

    // Swapped grants: G2's bytes under G1's signature; G1's signed grant
    // with G2's plan; G2's run identity under G1's grant.
    let swapped = SignedBackup {
        plan: valid.plan.clone(),
        grant: valid.grant.clone(),
        signature: first.signature.clone(),
    };
    m.refuse(
        &swapped,
        &operation,
        &key,
        ExecutorError::SignatureDenied,
        "grant bytes swapped",
    );
    let swapped = SignedBackup {
        plan: valid.plan.clone(),
        grant: first.grant.clone(),
        signature: first.signature.clone(),
    };
    m.refuse(
        &swapped,
        &operation,
        &key,
        ExecutorError::BindingDenied,
        "plan swapped",
    );
    m.refuse(
        &first,
        &operation,
        &key,
        ExecutorError::RunMismatch,
        "run swapped",
    );
    // The admitted run's identity under G2: G2 does not derive it.
    m.refuse(
        &valid,
        &admitted.operation_id,
        &admitted.idempotency_key,
        ExecutorError::RunMismatch,
        "admitted run under another grant",
    );
    // A schema 2 capture grant presented with the standing plan.
    let (_, capture_grant) = capture_vector();
    let mut schema2 = m.sign(&plan2, capture_grant);
    schema2.plan.clone_from(&valid.plan);
    m.refuse(
        &schema2,
        &operation,
        &key,
        ExecutorError::InvalidRequest,
        "schema 2 grant",
    );

    // The next window's run while window 0 is open.
    let next = run(&valid, "blog13", 1);
    m.refuse(
        &valid,
        &next.operation_id,
        &next.idempotency_key,
        ExecutorError::WindowClosed,
        "next window",
    );

    // The journal behind the admission mark: no fallback admission.
    let mark_path = m.fixture.anchor.mark_dir.join(MARK);
    let mark = fs::read(&mark_path).unwrap();
    let text = String::from_utf8(mark.clone()).unwrap();
    let count: u64 = text.lines().last().unwrap().parse().unwrap();
    let raised = text.replace(&format!("\n{count}\n"), &format!("\n{}\n", count + 1));
    private_file(&mark_path, raised.as_bytes());
    let reply = m.refuse(
        &valid,
        &operation,
        &key,
        ExecutorError::JournalRollback,
        "fenced",
    );
    assert_eq!(reply.state, None);
    private_file(&mark_path, &mark);

    // Control: the unmodified run is admitted once.
    let before = m.fixture.replay_state();
    let reply = valid.submit(&mut m.executor, &operation, &key);
    assert_eq!(reply.state, Some(OutcomeState::Failed), "{reply:?}");
    assert_eq!(m.runs(), 2);
    assert!(m.fixture.replay_state() != before);
}

/// The exact replay of an admitted operation with the journal behind its
/// admission mark. Under the W380 decision on O1 of W377, the replay is
/// answered from the journal before the fence: stored status, no write, no
/// helper run. A changed key under the same ID is refused, and the refusal
/// carries no stored status, because `stored_for_peer` checks the fence.
fn fenced_replay(
    m: &mut Matrix,
    signed: &SignedBackup,
    (operation, key): (&Id, &Id),
    changed_key: ExecutorError,
) {
    let runs = m.runs();
    let mark_path = m.fixture.anchor.mark_dir.join(MARK);
    let mark = fs::read(&mark_path).unwrap();
    let text = String::from_utf8(mark.clone()).unwrap();
    let count: u64 = text.lines().last().unwrap().parse().unwrap();
    let raised = text.replace(&format!("\n{count}\n"), &format!("\n{}\n", count + 1));
    private_file(&mark_path, raised.as_bytes());
    let state = m.fixture.replay_state();
    let reply = signed.submit(&mut m.executor, operation, key);
    assert!(m.fixture.replay_state() == state, "{reply:?}");
    assert_eq!(m.runs(), runs);
    assert!(reply.replay, "{reply:?}");
    assert_eq!(reply.state, Some(OutcomeState::Failed));
    assert_eq!(reply.error, None);
    let reply = m.refuse(
        signed,
        operation,
        &id("key_w394_changed"),
        changed_key,
        "changed key, fenced",
    );
    assert_eq!(reply.state, None, "a fenced refusal gave stored status");
    private_file(&mark_path, &mark);
}

/// O1 of W377 for the standing run (schema 3) and the product capture
/// (schema 2), as W380 decided it.
#[test]
fn w394_an_exact_replay_under_a_fenced_journal_is_status_only() {
    let mut m = Matrix::new();
    let (plan, grant) = standing(30, &["blog9"]);
    let first = m.sign(&plan, grant);
    let admitted = run(&first, "blog9", 0);
    assert_eq!(m.submit(&first, "blog9").state, Some(OutcomeState::Failed));
    fenced_replay(
        &mut m,
        &first,
        (&admitted.operation_id, &admitted.idempotency_key),
        ExecutorError::RunMismatch,
    );

    let (plan, grant) = capture_vector();
    let capture = m.sign(&plan, grant);
    let (operation, key) = (id("op_w394_capture"), id("key_w394_capture"));
    let reply = capture.submit(&mut m.executor, &operation, &key);
    assert_eq!(reply.state, Some(OutcomeState::Failed), "{reply:?}");
    fenced_replay(
        &mut m,
        &capture,
        (&operation, &key),
        ExecutorError::ReplayDenied,
    );
}

/// No empty-ledger fallback: an emptied, truncated, or missing journal is
/// refused at `open`, and `initialize` does not replace it while the
/// admission mark exists. The mark is never lowered.
#[test]
fn w394_an_emptied_truncated_or_missing_journal_refuses_standing_runs() {
    let m = Matrix::new();
    let (plan, grant) = standing(30, &["blog9"]);
    let first = m.sign(&plan, grant);
    let Matrix {
        mut executor,
        fixture,
        calls,
        ..
    } = m;
    let admitted = run(&first, "blog9", 0);
    let reply = first.submit(
        &mut executor,
        &admitted.operation_id,
        &admitted.idempotency_key,
    );
    assert_eq!(reply.state, Some(OutcomeState::Failed));
    drop(executor);
    let anchor = fixture.anchor.clone();
    let path = anchor.journal_dir.join(JOURNAL);
    let real = fs::read(&path).unwrap();
    let mark = fs::read(anchor.mark_dir.join(MARK)).unwrap();

    // An empty journal of the same host and epoch.
    let spare = fixture.root.join("spare");
    private_dir(&spare);
    drop(FixtureJournal::initialize(&spare, id("host_lab"), id("epoch_1")).unwrap());
    let empty = fs::read(spare.join(JOURNAL)).unwrap();
    // The first half of the real journal.
    let truncated = real[..real.len() / 2].to_vec();
    for (case, bytes) in [
        ("emptied", Some(&empty)),
        ("truncated", Some(&truncated)),
        ("missing", None),
    ] {
        match bytes {
            Some(bytes) => private_file(&path, bytes),
            None => fs::remove_file(&path).unwrap(),
        }
        let opened = Executor::open(anchor.clone());
        assert!(opened.is_err(), "{case} journal opened");
        if case == "emptied" {
            assert_eq!(opened.err(), Some(ExecutorError::JournalRollback), "{case}");
        }
        assert!(
            Executor::initialize(anchor.clone()).is_err(),
            "{case} reinitialized"
        );
        assert_eq!(
            fs::read(anchor.mark_dir.join(MARK)).unwrap(),
            mark,
            "{case} mark"
        );
        match bytes {
            Some(bytes) => assert_eq!(&fs::read(&path).unwrap(), bytes, "{case} rewritten"),
            None => assert!(!path.exists(), "{case} journal created"),
        }
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // The real journal restores the history; the run is a replay.
    private_file(&path, &real);
    let mut executor = Executor::open(anchor).unwrap();
    let replay = first.submit(
        &mut executor,
        &admitted.operation_id,
        &admitted.idempotency_key,
    );
    assert!(replay.replay);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
