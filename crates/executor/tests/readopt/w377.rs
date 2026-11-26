//! W377 (B06): the `site_readopt` abuse matrix. Every refusal before intent
//! has its own code, records no row and leaves the journal and admission
//! mark byte-identical. Each matrix ends with a control that is admitted,
//! so a refusal comes from the abuse and not from the setup.

use std::{
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use rustiron_contracts::{
    ErrorCode, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
    approval::Sha256Digest,
    execution::{OutcomeState, SubmissionReply, decode_submission_reply, encode_submission},
    local::{self, DEADLINE},
};
use rustiron_executor::serve;
use rustiron_journal::{FixtureJournal, ProvisionIntent};

use super::*;

pub(super) const JOURNAL: &str = "fixture-journal.sqlite";
pub(super) const MARK: &str = "admission-mark";

pub(super) fn replay_state(lab: &Lab) -> (Vec<u8>, Vec<u8>) {
    (
        fs::read(lab.anchor.journal_dir.join(JOURNAL)).unwrap(),
        fs::read(lab.anchor.mark_dir.join(MARK)).unwrap(),
    )
}

/// One refusal: its code, and the journal and mark byte-identical. An
/// operation with no row before has no row after.
pub(super) fn refused(
    lab: &Lab,
    executor: &mut Executor,
    request: &AdmissionRequest<'_>,
    error: ExecutorError,
    case: &str,
) {
    let before = replay_state(lab);
    let fresh = executor
        .readoption_status(&request.operation_id)
        .unwrap()
        .is_none();
    assert_eq!(executor.readopt(request).err(), Some(error), "{case}");
    assert!(replay_state(lab) == before, "{case} wrote state");
    if fresh {
        assert_eq!(
            executor.readoption_status(&request.operation_id).unwrap(),
            None,
            "{case} left a row"
        );
    }
}

pub(super) fn write_policy(lab: &Lab, edit: impl FnOnce(&mut Value)) {
    let path = lab.anchor.policy_dir.join("policy.json");
    let mut policy: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    edit(&mut policy);
    private_file(&path, &serde_json::to_vec(&policy).unwrap());
}

/// Raises the admission mark count by one, so the journal is behind it as
/// an older copy of itself would be. Returns the previous mark bytes.
pub(super) fn raise_mark(lab: &Lab) -> Vec<u8> {
    let path = lab.anchor.mark_dir.join(MARK);
    let before = fs::read(&path).unwrap();
    let text = String::from_utf8(before.clone()).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let count: u64 = lines.last().unwrap().parse().unwrap();
    *lines.last_mut().unwrap() = (count + 1).to_string();
    private_file(&path, format!("{}\n", lines.join("\n")).as_bytes());
    before
}

#[test]
fn w377_readopt_abuse_is_refused_before_any_record() {
    let lab = Lab::new("w377-abuse");
    new_key(&lab.root.join("keys/other"));
    let mut executor = Executor::initialize(lab.anchor()).unwrap();
    adopt_site(&mut executor, &lab, "blog1", 3001, 201, "w377a");
    let admitted = lab.site("blog1", "w377a", |_| {});
    let valid = lab.site("blog2", "w377b", |_| {});
    let operation = "op_w377b";

    // The kernel peer is not the enrolled requester.
    let mut request = valid.request(operation);
    request.peer_uid = 4243;
    refused(
        &lab,
        &mut executor,
        &request,
        ExecutorError::PeerDenied,
        "peer",
    );

    // A tampered signature over the exact grant bytes.
    let mut signature = valid.signature.clone();
    signature[40] ^= 1;
    let tampered = Signed {
        plan: valid.plan.clone(),
        grant: valid.grant.clone(),
        signature,
    };
    refused(
        &lab,
        &mut executor,
        &tampered.request(operation),
        ExecutorError::SignatureDenied,
        "tampered signature",
    );

    // A well-formed signature by a key that the allowlist does not name.
    let forged = lab.signed_with(
        site_plan("blog2", |_| {}),
        "site",
        "w377b",
        json!(["blog2"]),
        "other",
        |_| {},
    );
    refused(
        &lab,
        &mut executor,
        &forged.request(operation),
        ExecutorError::SignatureDenied,
        "forged signer",
    );

    // The enrolled signer key, revoked after it signed.
    let public = fs::read(lab.root.join("keys/key.pub")).unwrap();
    private_file(&lab.anchor.policy_dir.join("revocations"), &public);
    refused(
        &lab,
        &mut executor,
        &valid.request(operation),
        ExecutorError::SignatureDenied,
        "revoked signer",
    );
    private_file(&lab.anchor.policy_dir.join("revocations"), b"");

    // Time: at the grant expiry, and unknown.
    for now in [Timestamp::try_from(1900).ok(), None] {
        let mut request = valid.request(operation);
        request.now = now;
        refused(
            &lab,
            &mut executor,
            &request,
            ExecutorError::TimeDenied,
            "time",
        );
    }

    // A validly signed grant presented with a plan it does not digest.
    let substituted = Signed {
        plan: serde_json::to_vec(&site_plan("blog2", |plan| {
            plan["allocation_floor"]["uid"] = json!(3003);
        }))
        .unwrap(),
        grant: valid.grant.clone(),
        signature: valid.signature.clone(),
    };
    refused(
        &lab,
        &mut executor,
        &substituted.request(operation),
        ExecutorError::BindingDenied,
        "plan digest",
    );

    // Signed for another host, or for another epoch.
    for (field, value) in [("host_id", "host_other"), ("host_epoch", "epoch_9")] {
        let other = lab.signed_with(
            site_plan("blog2", |plan| plan[field] = json!(value)),
            "site",
            "w377b",
            json!(["blog2"]),
            "key",
            |grant| grant[field] = json!(value),
        );
        refused(
            &lab,
            &mut executor,
            &other.request(operation),
            ExecutorError::BindingDenied,
            field,
        );
    }

    // The exact admitted request is status only.
    let before = replay_state(&lab);
    assert!(matches!(
        executor.readopt(&admitted.request("op_w377a")).unwrap(),
        ReadoptResult::Existing(row) if row.state == ReadoptState::Adopted
    ));
    assert!(replay_state(&lab) == before, "an exact replay wrote state");

    // The admitted operation ID with another idempotency key, or with
    // another grant under its own key: a replay refusal.
    let mut other_key = admitted.request("op_w377a");
    other_key.idempotency_key = id("key_w377_other");
    refused(
        &lab,
        &mut executor,
        &other_key,
        ExecutorError::ReplayDenied,
        "operation ID, other key",
    );
    let mut other_grant = valid.request("op_w377a");
    other_grant.idempotency_key = id("key_op_w377a");
    refused(
        &lab,
        &mut executor,
        &other_grant,
        ExecutorError::ReplayDenied,
        "operation ID, other bytes",
    );

    // The admitted idempotency key on a new operation with other bytes.
    let mut reused_key = valid.request(operation);
    reused_key.idempotency_key = id("key_op_w377a");
    refused(
        &lab,
        &mut executor,
        &reused_key,
        ExecutorError::ReplayDenied,
        "idempotency key, other bytes",
    );

    // The consumed grant ID and nonce, signed again over another site.
    let consumed = lab.site("blog2", "w377a", |_| {});
    refused(
        &lab,
        &mut executor,
        &consumed.request(operation),
        ExecutorError::ReplayDenied,
        "consumed nonce",
    );

    // An owned site, and a hostname that an owned site holds.
    let owned = lab.site("blog1", "w377c", |_| {});
    refused(
        &lab,
        &mut executor,
        &owned.request("op_w377c"),
        ExecutorError::PreconditionChanged,
        "owned site",
    );
    let held = lab.site("blog2", "w377d", |plan| {
        plan["hostname"] = json!("blog1.example.test");
        plan["observations"][0]["hostname"] = json!("blog1.example.test");
    });
    refused(
        &lab,
        &mut executor,
        &held.request("op_w377d"),
        ExecutorError::PreconditionChanged,
        "held hostname",
    );

    // The journal behind the admission mark: no fallback admission.
    let mark = raise_mark(&lab);
    refused(
        &lab,
        &mut executor,
        &valid.request(operation),
        ExecutorError::JournalRollback,
        "journal behind the mark",
    );
    private_file(&lab.anchor.mark_dir.join(MARK), &mark);

    // Control: the unmodified request is adopted.
    executor.inject_readopt_observation(ReadoptObservation::Site(Box::new(site_facts(
        "blog2", 3002, 202,
    ))));
    let ReadoptResult::New(row) = executor.readopt(&valid.request(operation)).unwrap() else {
        panic!("new re-adoption expected");
    };
    assert_eq!(row.state, ReadoptState::Adopted);
}

/// W377 finding F1: a policy re-enrolled to another epoch while the
/// executor keeps the old journal open is a journal identity mismatch,
/// refused before intent, not a replay of a consumed grant.
#[test]
fn w377_a_re_enrolled_epoch_is_an_identity_mismatch_not_a_replay() {
    let lab = Lab::new("w377-identity");
    let mut executor = Executor::initialize(lab.anchor()).unwrap();
    write_policy(&lab, |policy| policy["host_epoch"] = json!("epoch_2"));
    let rotated = lab.signed_with(
        site_plan("blog1", |plan| plan["host_epoch"] = json!("epoch_2")),
        "site",
        "w377i",
        json!(["blog1"]),
        "key",
        |grant| grant["host_epoch"] = json!("epoch_2"),
    );
    refused(
        &lab,
        &mut executor,
        &rotated.request("op_w377i"),
        ExecutorError::IdentityMismatch,
        "re-enrolled epoch",
    );
}

/// Records a `running` provision of `site` directly in the journal.
fn running_provision(lab: &Lab, site: &str) {
    let mut journal = FixtureJournal::open_as_process_owner(
        &lab.anchor.journal_dir,
        id("host_lab"),
        id("epoch_1"),
    )
    .unwrap();
    let intent = ProvisionIntent {
        operation_id: id(&format!("op_provision_{site}")),
        idempotency_key: id(&format!("key_provision_{site}")),
        grant_id: id(&format!("grant_provision_{site}")),
        nonce: id(&format!("nonce_provision_{site}")),
        plan_digest: Sha256Digest::from_bytes([4; 32]),
        grant_digest: Sha256Digest::from_bytes([5; 32]),
        host_id: id("host_lab"),
        host_epoch: id("epoch_1"),
        site_id: site.to_owned().try_into().unwrap(),
        hostname: format!("{site}.example.test").try_into().unwrap(),
        expires_at: Timestamp::try_from(4_000_000_000).unwrap(),
    };
    journal
        .record_provision(&intent, Timestamp::try_from(1100).unwrap())
        .unwrap();
}

#[test]
fn w377_an_unresolved_provision_blocks_a_readoption_before_intent() {
    let lab = Lab::new("w377-busy");
    drop(Executor::initialize(lab.anchor()).unwrap());
    running_provision(&lab, "blog9");
    let mut executor = Executor::open(lab.anchor()).unwrap();
    let request = lab.site("blog2", "w377busy", |_| {});
    refused(
        &lab,
        &mut executor,
        &request.request("op_w377busy"),
        ExecutorError::Busy,
        "running provision",
    );
}

/// No empty-ledger fallback: a missing journal, or a fresh empty one of
/// the same host and epoch, is refused at open and is never initialized
/// over the mark. The admitted history comes back with the real file.
#[test]
fn w377_a_missing_or_emptied_journal_is_refused_never_reinitialized() {
    let lab = Lab::new("w377-ledger");
    let journal = lab.anchor.journal_dir.join(JOURNAL);
    let mut executor = Executor::initialize(lab.anchor()).unwrap();
    let empty = fs::read(&journal).unwrap();
    adopt_site(&mut executor, &lab, "blog1", 3001, 201, "w377l");
    drop(executor);
    let admitted = fs::read(&journal).unwrap();
    let mark = fs::read(lab.anchor.mark_dir.join(MARK)).unwrap();

    fs::remove_file(&journal).unwrap();
    assert!(Executor::open(lab.anchor()).is_err(), "a missing journal");
    assert_eq!(
        Executor::initialize(lab.anchor()).err(),
        Some(ExecutorError::JournalRollback),
        "a fresh journal would forget the consumed grant"
    );
    assert!(!journal.exists(), "an empty journal was created");

    private_file(&journal, &empty);
    assert_eq!(
        Executor::open(lab.anchor()).err(),
        Some(ExecutorError::JournalRollback),
        "an empty journal behind the mark"
    );
    assert_eq!(
        Executor::seal_admission_mark(lab.anchor()).err(),
        Some(ExecutorError::StateExists),
        "the mark is never lowered"
    );
    assert_eq!(fs::read(lab.anchor.mark_dir.join(MARK)).unwrap(), mark);

    private_file(&journal, &admitted);
    let mut executor = Executor::open(lab.anchor()).unwrap();
    // The consumed grant stays consumed: its exact repeat is status only.
    assert!(matches!(
        executor
            .readopt(&lab.site("blog1", "w377l", |_| {}).request("op_w377l"))
            .unwrap(),
        ReadoptResult::Existing(row) if row.state == ReadoptState::Adopted
    ));
}

/// A stub admin helper: `Some(line)` answers every request with that line,
/// `None` closes without a reply. Counts the requests.
fn stub_helper(
    lab: &Lab,
    name: &str,
    reply: Option<&'static str>,
) -> (TrustAnchor, Arc<AtomicUsize>) {
    let path = lab.root.join(format!("{name}.sock"));
    let listener = UnixListener::bind(&path).unwrap();
    let mut anchor = lab.anchor();
    anchor.admin_socket = Some(path);
    let count = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&count);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut request = String::new();
            let _ = stream.read_to_string(&mut request);
            assert!(request.contains("readopt_observe"), "{request}");
            seen.fetch_add(1, Ordering::SeqCst);
            if let Some(reply) = reply {
                let _ = stream.write_all(reply.as_bytes());
            }
        }
    });
    (anchor, count)
}

/// A row left `verifying` blocks new work and its exact repeat is status
/// only; a `reconcile` with a complete observation then adopts it.
fn settles_by_reconcile(lab: &Lab, executor: &mut Executor, request: &Signed, operation: &str) {
    let row = executor.readoption_status(&id(operation)).unwrap().unwrap();
    assert_eq!(row.state, ReadoptState::Verifying);
    let next = format!("{operation}_next");
    let other = lab.site("blog7", &next, |_| {});
    refused(
        lab,
        executor,
        &other.request(&next),
        ExecutorError::Busy,
        "verifying row",
    );
    assert!(matches!(
        executor.readopt(&request.request(operation)).unwrap(),
        ReadoptResult::Existing(row) if row.state == ReadoptState::Verifying
    ));
    executor.inject_readopt_observation(ReadoptObservation::Site(Box::new(site_facts(
        "blog1", 3001, 201,
    ))));
    assert_eq!(
        executor.reconcile_readoption(&id(operation)).unwrap().state,
        ReadoptState::Adopted
    );
}

/// The one helper step, `readopt_observe`. A refusal is recorded under
/// the `observation` rule. An unreachable helper or a lost reply leaves the
/// row `verifying` (unknown, never adopted) until `reconcile` settles it.
#[test]
fn w377_readopt_helper_refusal_unreachable_and_lost_reply() {
    let lab = Lab::new("w377-helper");
    drop(Executor::initialize(lab.anchor()).unwrap());
    let (anchor, runs) = stub_helper(&lab, "refusing", Some("FIXTURE_BINDING_DENIED\n"));
    let mut executor = Executor::open(anchor).unwrap();
    let request = lab.site("blog1", "w377h1", |_| {});
    assert_eq!(
        executor.readopt(&request.request("op_w377h1")).err(),
        Some(ExecutorError::ReadoptMismatch)
    );
    let row = executor
        .readoption_status(&id("op_w377h1"))
        .unwrap()
        .unwrap();
    assert_eq!(row.state, ReadoptState::Refused);
    assert_eq!(row.refusal.unwrap().1, "observation");
    assert_eq!(executor.provision_for_site(&site("blog1")).unwrap(), None);
    assert_eq!(runs.load(Ordering::SeqCst), 1);
    drop(executor);
    // Each lab holds the serial lock; release it before the next.
    drop(lab);

    // An unreachable helper, a helper that answers nothing, and a reply
    // with an unknown code: each outcome is unknown.
    let cases: [(&str, Option<&'static str>, ExecutorError); 3] = [
        ("gone", Some("ok\n"), ExecutorError::HelperUnreachable),
        ("silent", None, ExecutorError::Unavailable),
        (
            "garbled",
            Some("BINDING_DENIED\n"),
            ExecutorError::Unavailable,
        ),
    ];
    for (name, reply, error) in cases {
        let lab = Lab::new(&format!("w377-helper-{name}"));
        drop(Executor::initialize(lab.anchor()).unwrap());
        let (anchor, runs) = stub_helper(&lab, name, reply);
        if name == "gone" {
            // A socket with no listener: nothing is sent.
            let path = anchor.admin_socket.clone().unwrap();
            fs::remove_file(&path).unwrap();
            drop(UnixListener::bind(&path).unwrap());
        }
        let mut executor = Executor::open(anchor).unwrap();
        let request = lab.site("blog1", "w377h2", |_| {});
        assert_eq!(
            executor.readopt(&request.request("op_w377h2")).err(),
            Some(error),
            "{name}"
        );
        let sent = usize::from(name != "gone");
        assert_eq!(runs.load(Ordering::SeqCst), sent, "{name}");
        settles_by_reconcile(&lab, &mut executor, &request, "op_w377h2");
        assert_eq!(runs.load(Ordering::SeqCst), sent, "{name}: reconcile");
    }
}

/// W377 fault point: a crash after the observation and the decision,
/// before the outcome transaction, leaves the row `verifying` with no
/// facts; `reconcile` observes again and records once.
#[test]
fn w377_a_crash_after_the_readopt_observation_records_nothing() {
    let lab = Lab::new("w377-observed");
    let mut executor = Executor::initialize(lab.anchor()).unwrap();
    let request = lab.site("blog1", "w377o", |_| {});
    executor.inject_readopt_observation(ReadoptObservation::Site(Box::new(site_facts(
        "blog1", 3001, 201,
    ))));
    executor.inject_fault(Fault::AfterReadoptObservation);
    assert_eq!(
        executor.readopt(&request.request("op_w377o")).err(),
        Some(ExecutorError::Unavailable)
    );
    drop(executor);
    let mut executor = Executor::open(lab.anchor()).unwrap();
    let row = executor
        .readoption_status(&id("op_w377o"))
        .unwrap()
        .unwrap();
    assert_eq!(row.state, ReadoptState::Verifying);
    assert_eq!(row.facts, None);
    assert_eq!(executor.provision_for_site(&site("blog1")).unwrap(), None);
    settles_by_reconcile(&lab, &mut executor, &request, "op_w377o");
    assert_eq!(
        executor
            .provision_for_site(&site("blog1"))
            .unwrap()
            .unwrap()
            .state,
        ProvisionState::Adopted
    );
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A site-form request that is valid now, for the socket handler.
pub(super) fn current(lab: &Lab, site: &str, nonce: &str) -> Signed {
    let now = now();
    lab.signed_with(
        site_plan(site, |plan| {
            plan["valid_from"] = json!(now - 60);
            plan["expires_at"] = json!(now + 600);
            plan["observations"][0]["observed_at"] = json!(now - 90);
        }),
        "site",
        nonce,
        json!([site]),
        "key",
        |grant| {
            grant["valid_from"] = json!(now - 30);
            grant["expires_at"] = json!(now + 300);
        },
    )
}

fn round_trip(executor: &mut Executor, frame: &[u8]) -> Vec<u8> {
    let (mut client, server) = UnixStream::pair().unwrap();
    local::write_frame(
        &mut client,
        frame,
        MAX_REQUEST_BYTES,
        ErrorCode::RequestTooLarge,
        Instant::now() + DEADLINE,
    )
    .unwrap();
    assert!(serve::handle(executor, server));
    local::read_frame(
        &mut client,
        MAX_RESPONSE_BYTES,
        ErrorCode::ResponseTooLarge,
        Instant::now() + DEADLINE,
    )
    .unwrap()
}

pub(super) fn submit(
    executor: &mut Executor,
    signed: &Signed,
    operation: &str,
    key: &str,
) -> SubmissionReply {
    let operation = id(operation);
    let bytes = encode_submission(
        &operation,
        &id(key),
        &signed.plan,
        &signed.grant,
        std::str::from_utf8(&signed.signature).unwrap(),
    )
    .unwrap();
    decode_submission_reply(&round_trip(executor, &bytes), &operation).unwrap()
}

/// The W329/W332 rule for W372: a refused `site_readopt` submission that
/// names an admitted re-adoption gives a peer outside the enrolled
/// requester no stored status, and a status query from it gets none.
#[test]
fn w377_a_refused_readoption_shows_no_stored_status_to_another_peer() {
    let lab = Lab::new("w377-peer");
    let uid = rustix::process::getuid().as_raw();
    write_policy(&lab, |policy| policy["requester_uid"] = json!(uid));
    let mut executor = Executor::initialize(lab.anchor()).unwrap();
    let admitted = current(&lab, "blog1", "w377p");
    executor.inject_readopt_observation(ReadoptObservation::Site(Box::new(site_facts(
        "blog1", 3001, 201,
    ))));
    let reply = submit(&mut executor, &admitted, "op_w377p", "key_op_w377p");
    assert_eq!(reply.state, Some(OutcomeState::Succeeded), "{reply:?}");
    assert_eq!(reply.error, None);

    // The enrolled requester sees stored status with a replay refusal.
    let other = current(&lab, "blog2", "w377q");
    let reply = submit(&mut executor, &other, "op_w377p", "key_w377q");
    assert_eq!(reply.error.as_deref(), Some("REPLAY_DENIED"));
    assert_eq!(reply.state, Some(OutcomeState::Succeeded));

    write_policy(&lab, |policy| {
        policy["requester_uid"] = json!(uid.wrapping_add(1));
    });
    let before = replay_state(&lab);
    for (signed, key) in [(&admitted, "key_op_w377p"), (&other, "key_w377q")] {
        let reply = submit(&mut executor, signed, "op_w377p", key);
        assert_eq!(reply.error.as_deref(), Some("PEER_DENIED"), "{reply:?}");
        assert_eq!(reply.state, None, "a wrong peer saw stored status");
        assert!(!reply.replay);
    }
    let query = br#"{"schema_version":1,"request_id":"q_w377","method":"operation_status","params":{"operation_id":"op_w377p"}}"#;
    let status: Value = serde_json::from_slice(&round_trip(&mut executor, query)).unwrap();
    assert_eq!(status["error"]["code"], "UNAUTHORIZED_PEER");
    assert!(status["data"].is_null());
    assert!(replay_state(&lab) == before);
}
