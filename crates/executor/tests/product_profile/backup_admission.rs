//! W319/W320: durable admission of product v2 captures and restore probes,
//! against a stub helper.
//!
//! The stub stands in for the admin helper's `capture_run` reply only; the
//! helper's own projection re-binding and repository check need root and
//! the store namespace (lab evidence S10-W319).

use std::{
    io::{Read, Write},
    os::unix::net::UnixListener,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
};

use rustiron_contracts::{
    Id, Timestamp,
    approval::{ProductBackupPolicy, Sha256Digest},
    execution::OutcomeState,
};
use rustiron_executor::{Executor, ExecutorError, TrustAnchor};
use rustiron_journal::{CaptureState, FixtureJournal, ProbeState, ProvisionIntent, ProvisionStep};
use serde_json::{Value, json};

use super::{
    BackupFixture, PROJECTION, PROJECTION_DIGEST, private_file,
    verification::{SignedBackup, enroll, vectors},
};

pub(super) fn id(text: &str) -> Id {
    Id::try_from(text.to_owned()).unwrap()
}

/// W374: runs `scripts/check_receipt.py` on an exported receipt and fails
/// the test with its output when the checker refuses it.
pub(super) fn assert_checker_accepts(document: &Value) {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "rustiron-product-receipt-{}-{}.json",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::File::create_new(&path)
        .and_then(|mut file| file.write_all(document.to_string().as_bytes()))
        .unwrap();
    let script =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/check_receipt.py");
    let output = std::process::Command::new("python3")
        .arg(script)
        .arg(&path)
        .output()
        .expect("python3");
    std::fs::remove_file(&path).ok();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Answers every helper request with one fixed reply line and counts them.
fn stub_helper(anchor: &mut TrustAnchor, reply: &'static str) -> Arc<AtomicUsize> {
    stub_helper_for(anchor, "capture_run", reply)
}

pub(super) fn stub_helper_for(
    anchor: &mut TrustAnchor,
    step: &'static str,
    reply: &'static str,
) -> Arc<AtomicUsize> {
    let path = anchor.journal_dir.with_file_name("helper.sock");
    let listener = UnixListener::bind(&path).unwrap();
    anchor.admin_socket = Some(path);
    let count = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&count);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut request = String::new();
            let _ = stream.read_to_string(&mut request);
            assert!(request.contains(step), "{request}");
            seen.fetch_add(1, Ordering::SeqCst);
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    count
}

/// Records a succeeded provision of `site` the way the journal requires.
pub(super) fn provision(anchor: &TrustAnchor, site: &str) {
    drop(Executor::initialize(anchor.clone()).unwrap());
    provision_in(anchor, site);
}

/// Records a succeeded provision of `site` in an initialized journal.
pub(super) fn provision_in(anchor: &TrustAnchor, site: &str) {
    let mut journal =
        FixtureJournal::open_as_process_owner(&anchor.journal_dir, id("host_lab"), id("epoch_1"))
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
    for step in ProvisionStep::ALL {
        journal
            .begin_step(&intent.operation_id, step, "synthetic")
            .unwrap();
        journal
            .finish_step(&intent.operation_id, step, true)
            .unwrap();
    }
}

pub(super) fn probe_vector() -> (Value, Value) {
    vectors()
        .into_iter()
        .find(|(plan, _)| plan["verb"] == "restore_probe")
        .unwrap()
}

pub(super) fn capture_vector() -> (Value, Value) {
    vectors()
        .into_iter()
        .find(|(plan, _)| plan["verb"] == "backup_capture")
        .unwrap()
}

#[test]
fn product_capture_is_admitted_with_its_digest_and_replays_status_only() {
    let mut fixture = BackupFixture::new();
    let policy = enroll(&fixture);
    let calls = stub_helper(&mut fixture.anchor, "NOT_ADMITTED_FOR_EFFECT\n");
    provision(&fixture.anchor, "blog9");
    let mut executor = Executor::open(fixture.anchor.clone()).unwrap();
    let (_, mark_before) = fixture.replay_state();
    let (plan, grant) = capture_vector();
    let signed = SignedBackup::new(&fixture, &plan, grant);
    let (operation, key) = (id("op_w319_capture"), id("key_w319_capture"));

    let reply = signed.submit(&mut executor, &operation, &key);
    assert_eq!(reply.state, Some(OutcomeState::Failed));
    assert_eq!(reply.error.as_deref(), Some("NOT_ADMITTED_FOR_EFFECT"));
    assert!(!reply.replay);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let recorded = executor.capture_status(&operation).unwrap().unwrap();
    assert_eq!(recorded.state, CaptureState::Failed);
    assert_eq!(recorded.snapshot_id, None);
    assert_eq!(recorded.retention_days, Some(30));
    assert_eq!(
        recorded
            .backup_policy_digest
            .as_ref()
            .map(Sha256Digest::as_str),
        Some(PROJECTION_DIGEST.trim_end())
    );
    assert_ne!(fixture.replay_state().1, mark_before);

    // Exact replay: stored status, no second helper run.
    let replay = signed.submit(&mut executor, &operation, &key);
    assert_eq!(replay.state, Some(OutcomeState::Failed));
    assert!(replay.replay);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // A changed destination does not hide stored status from an exact replay.
    let mut projection: Value = serde_json::from_slice(PROJECTION).unwrap();
    projection["transport"]["endpoint_ipv4"] = json!("198.51.100.24");
    let changed = serde_json::to_vec(&projection).unwrap();
    let mut changed_policy = policy.clone();
    changed_policy["product_backup"]["destination_policy_digest"] =
        json!(ProductBackupPolicy::decode(&changed).unwrap().digest());
    private_file(&fixture.projection_path(), &changed);
    fixture.write_policy(&changed_policy);
    let replay = signed.submit(&mut executor, &operation, &key);
    assert!(replay.replay);
    assert_eq!(replay.state, Some(OutcomeState::Failed));
    private_file(&fixture.projection_path(), PROJECTION);
    fixture.write_policy(&policy);

    // The consumed grant cannot start another operation.
    let state = fixture.replay_state();
    let other = id("op_w319_again");
    let refused = signed.submit(&mut executor, &other, &id("key_w319_again"));
    assert_eq!(
        refused.error.as_deref(),
        Some(ExecutorError::ReplayDenied.code())
    );
    assert!(executor.capture_status(&other).unwrap().is_none());
    assert_eq!(fixture.replay_state(), state);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn product_capture_preconditions_refuse_before_intent() {
    let mut fixture = BackupFixture::new();
    enroll(&fixture);
    let (plan, grant) = capture_vector();
    let signed = SignedBackup::new(&fixture, &plan, grant);
    let (operation, key) = (id("op_w319_pre"), id("key_w319_pre"));

    // No helper: nothing could run, so the grant is not consumed.
    provision(&fixture.anchor, "blog9");
    let mut executor = Executor::open(fixture.anchor.clone()).unwrap();
    let before = fixture.replay_state();
    let reply = signed.submit(&mut executor, &operation, &key);
    assert_eq!(
        reply.error.as_deref(),
        Some(ExecutorError::Unavailable.code())
    );
    assert_eq!(reply.state, None);
    assert_eq!(fixture.replay_state(), before);
    drop(executor);

    // A helper that cannot be reached: admitted, then a known failure.
    fixture.anchor.admin_socket = Some(fixture.anchor.journal_dir.with_file_name("absent.sock"));
    let mut executor = Executor::open(fixture.anchor.clone()).unwrap();
    let reply = signed.submit(&mut executor, &operation, &key);
    assert_eq!(reply.state, Some(OutcomeState::Failed));
    assert_eq!(
        reply.error.as_deref(),
        Some(ExecutorError::HelperUnreachable.code())
    );
}

#[test]
fn product_capture_needs_a_succeeded_provision() {
    let mut fixture = BackupFixture::new();
    enroll(&fixture);
    let calls = stub_helper(&mut fixture.anchor, "NOT_ADMITTED_FOR_EFFECT\n");
    let mut executor = Executor::initialize(fixture.anchor.clone()).unwrap();
    let before = fixture.replay_state();
    let (plan, grant) = capture_vector();
    let reply = SignedBackup::new(&fixture, &plan, grant).submit(
        &mut executor,
        &id("op_w319_unprovisioned"),
        &id("key_w319_unprovisioned"),
    );
    assert_eq!(
        reply.error.as_deref(),
        Some(ExecutorError::PreconditionChanged.code())
    );
    assert_eq!(reply.state, None);
    assert_eq!(fixture.replay_state(), before);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn an_unknown_helper_reply_leaves_the_capture_running() {
    let mut fixture = BackupFixture::new();
    enroll(&fixture);
    let calls = stub_helper(&mut fixture.anchor, "garbled\n");
    provision(&fixture.anchor, "blog9");
    let mut executor = Executor::open(fixture.anchor.clone()).unwrap();
    let (plan, grant) = capture_vector();
    let operation = id("op_w319_unknown");
    let reply = SignedBackup::new(&fixture, &plan, grant).submit(
        &mut executor,
        &operation,
        &id("key_w319_unknown"),
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(reply.state, Some(OutcomeState::Intent));
    assert_eq!(
        reply.error.as_deref(),
        Some(ExecutorError::Unavailable.code())
    );
    assert_eq!(
        executor.capture_status(&operation).unwrap().unwrap().state,
        CaptureState::Running
    );
}

#[test]
fn product_probe_is_admitted_with_its_digest_and_replays_status_only() {
    let mut fixture = BackupFixture::new();
    enroll(&fixture);
    let calls = stub_helper_for(
        &mut fixture.anchor,
        "probe_run",
        "NOT_ADMITTED_FOR_EFFECT\n",
    );
    provision(&fixture.anchor, "blog13");
    let mut executor = Executor::open(fixture.anchor.clone()).unwrap();
    let (_, mark_before) = fixture.replay_state();
    let (plan, grant) = probe_vector();
    let signed = SignedBackup::new(&fixture, &plan, grant);
    let (operation, key) = (id("op_w320_probe"), id("key_w320_probe"));

    let reply = signed.submit(&mut executor, &operation, &key);
    assert_eq!(reply.state, Some(OutcomeState::Untouched));
    assert_eq!(reply.error.as_deref(), Some("NOT_ADMITTED_FOR_EFFECT"));
    assert!(!reply.replay);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let recorded = executor.probe_status(&operation).unwrap().unwrap();
    assert_eq!(recorded.state, ProbeState::Failed);
    assert_eq!(
        recorded
            .backup_policy_digest
            .as_ref()
            .map(Sha256Digest::as_str),
        Some(PROJECTION_DIGEST.trim_end())
    );
    let receipt: Value = serde_json::from_str(recorded.receipt.as_deref().unwrap()).unwrap();
    assert_eq!(receipt["refused"], "NOT_ADMITTED_FOR_EFFECT");
    assert_eq!(receipt["cleanup"]["leftover_resources"], 0);
    assert_ne!(fixture.replay_state().1, mark_before);
    // W374: the export of the refusal is a complete receipt with no check
    // claimed (W371 exported null fields and limitations).
    let exported = rustiron_executor::receipt::recovery_receipt(&recorded, receipt).unwrap();
    let fields = exported["body"]["fields"].as_object().unwrap();
    assert_eq!(fields.len(), 7);
    assert!(fields.values().all(|field| field["status"] == "not_run"));
    assert!(
        exported["body"]["limitations"][1]
            .as_str()
            .unwrap()
            .contains("refused with NOT_ADMITTED_FOR_EFFECT")
    );
    assert_checker_accepts(&exported);

    let replay = signed.submit(&mut executor, &operation, &key);
    assert!(replay.replay);
    assert_eq!(replay.state, Some(OutcomeState::Untouched));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let state = fixture.replay_state();
    let other = id("op_w320_again");
    let refused = signed.submit(&mut executor, &other, &id("key_w320_again"));
    assert_eq!(
        refused.error.as_deref(),
        Some(ExecutorError::ReplayDenied.code())
    );
    assert!(executor.probe_status(&other).unwrap().is_none());
    assert_eq!(fixture.replay_state(), state);
}

#[test]
fn an_unknown_helper_reply_leaves_the_probe_running() {
    let mut fixture = BackupFixture::new();
    enroll(&fixture);
    let calls = stub_helper_for(&mut fixture.anchor, "probe_run", "garbled\n");
    provision(&fixture.anchor, "blog13");
    let mut executor = Executor::open(fixture.anchor.clone()).unwrap();
    let (plan, grant) = probe_vector();
    let operation = id("op_w320_unknown");
    let reply = SignedBackup::new(&fixture, &plan, grant).submit(
        &mut executor,
        &operation,
        &id("key_w320_unknown"),
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(reply.state, Some(OutcomeState::Intent));
    assert_eq!(
        executor.probe_status(&operation).unwrap().unwrap().state,
        ProbeState::Running
    );
}

/// D-031 (W373): submits one product probe against a stub helper that
/// answers `reply`, and returns the CLI reply state and the journaled probe.
fn probe_with_reply(
    reply: &'static str,
    name: &str,
) -> (Option<OutcomeState>, rustiron_journal::Probe) {
    let mut fixture = BackupFixture::new();
    enroll(&fixture);
    let calls = stub_helper_for(&mut fixture.anchor, "probe_run", reply);
    provision(&fixture.anchor, "blog13");
    let mut executor = Executor::open(fixture.anchor.clone()).unwrap();
    let (plan, grant) = probe_vector();
    let operation = id(&format!("op_w373_{name}"));
    let submitted = SignedBackup::new(&fixture, &plan, grant).submit(
        &mut executor,
        &operation,
        &id(&format!("key_w373_{name}")),
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let recorded = executor.probe_status(&operation).unwrap().unwrap();
    (submitted.state, recorded)
}

#[test]
fn a_reported_product_probe_outcome_is_journaled_with_its_receipt() {
    let (state, recorded) = probe_with_reply(
        "ok {\"state\":\"passed\",\"receipt\":{\"receipt_schema\":\"rustiron-restore-probe/2\",\"fields\":{},\"cleanup\":{\"status\":\"complete\",\"leftover_resources\":0}}}\n",
        "passed",
    );
    assert_eq!(state, Some(OutcomeState::Succeeded));
    assert_eq!(recorded.state, ProbeState::Passed);
    let receipt: Value = serde_json::from_str(recorded.receipt.as_deref().unwrap()).unwrap();
    assert_eq!(receipt["receipt_schema"], "rustiron-restore-probe/2");
    assert!(recorded.finished_at.is_some());

    let (state, recorded) = probe_with_reply(
        "ok {\"state\":\"failed\",\"receipt\":{\"receipt_schema\":\"rustiron-restore-probe/2\",\"cleanup\":{\"status\":\"complete\",\"leftover_resources\":0}}}\n",
        "failed",
    );
    assert_eq!(state, Some(OutcomeState::Untouched));
    assert_eq!(recorded.state, ProbeState::Failed);

    // Leftover sandbox resources need attention and block new probes.
    let (state, recorded) = probe_with_reply(
        "ok {\"state\":\"cleanup_incomplete\",\"receipt\":{\"cleanup\":{\"status\":\"incomplete\",\"leftover_resources\":1}}}\n",
        "incomplete",
    );
    assert_eq!(state, Some(OutcomeState::NeedsAttention));
    assert_eq!(recorded.state, ProbeState::CleanupIncomplete);
}

#[test]
fn a_product_probe_outcome_that_is_not_final_or_has_no_receipt_stays_running() {
    for (name, reply) in [
        ("running", "ok {\"state\":\"running\",\"receipt\":{}}\n"),
        ("no_receipt", "ok {\"state\":\"passed\"}\n"),
        (
            "array_receipt",
            "ok {\"state\":\"passed\",\"receipt\":[]}\n",
        ),
        ("empty", "ok\n"),
    ] {
        let (state, recorded) = probe_with_reply(reply, name);
        assert_eq!(state, Some(OutcomeState::Intent), "{name}");
        assert_eq!(recorded.state, ProbeState::Running, "{name}");
        assert!(recorded.receipt.is_none(), "{name}");
    }
}

fn store_requests() -> usize {
    std::fs::read_to_string(std::env::var("W319_REQUESTS").unwrap())
        .unwrap()
        .lines()
        .count()
}

/// W319 root lab test: the real helper decision and store check for an
/// admitted product capture. Run through docs/validation/S10-W319/probe_admission.sh.
#[test]
#[ignore = "root lab test: needs the store namespace, relay and synthetic store"]
fn product_capture_through_the_helper_as_root() {
    use std::time::Duration;

    use rustiron_executor::admin_helper;

    let env = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"));
    let mut fixture = BackupFixture::new();
    let mut policy = enroll(&fixture);
    let projection = std::fs::read(env("W319_PROJECTION")).unwrap();
    let digest = ProductBackupPolicy::decode(&projection).unwrap().digest();
    policy["product_backup"]["destination_policy_digest"] = json!(digest);
    fixture.write_policy(&policy);
    private_file(&fixture.projection_path(), &projection);
    let dir = &fixture.anchor.policy_dir;
    private_file(
        &dir.join("backup-ca.pem"),
        &std::fs::read(env("W319_CA")).unwrap(),
    );
    let site = dir.join("credentials/sites/rs_blog9");
    private_file(
        &site.join("fetch-aws"),
        &std::fs::read(env("W319_FETCH")).unwrap(),
    );
    private_file(
        &site.join("repo.password"),
        &std::fs::read(env("W319_PASSWORD")).unwrap(),
    );
    std::fs::write(
        dir.join("store-network.env"),
        std::fs::read(env("W319_NETWORK_FILE")).unwrap(),
    )
    .unwrap();

    let socket = fixture.anchor.journal_dir.with_file_name("helper.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    fixture.anchor.admin_socket = Some(socket);
    provision(&fixture.anchor, "blog9");
    // The helper refuses work journaled in or before its start second (W177).
    let mut helper = admin_helper::Helper::new(fixture.anchor.clone(), None);
    thread::sleep(Duration::from_millis(1100));
    let (plan, grant) = capture_vector();
    let mut plan = plan;
    plan["destination_policy_digest"] = json!(digest);
    let mut drift_grant = grant.clone();
    drift_grant["grant_id"] = json!("grant_w319_drift");
    drift_grant["nonce"] = json!("nonce_w319_drift");
    let bound = SignedBackup::new(&fixture, &plan, grant);
    let drifted = SignedBackup::new(&fixture, &plan, drift_grant);
    let mut executor = Executor::open(fixture.anchor.clone()).unwrap();

    // 1. Policy changes after intent: the submission is admitted, then the
    // helper re-binds the journaled digest and refuses before the store.
    let projection_path = fixture.projection_path();
    let (operation, key) = (id("op_w319_drift"), id("key_w319_drift"));
    let before = store_requests();
    let submitter = thread::spawn(move || {
        let reply = drifted.submit(&mut executor, &operation, &key);
        (executor, reply)
    });
    thread::sleep(Duration::from_millis(1500));
    // A consistent re-enrollment: new projection and its pin. (Changing the
    // projection alone fails policy loading itself; first lab run.)
    let mut changed: Value = serde_json::from_slice(&projection).unwrap();
    changed["retention_days"] = json!(31);
    let changed = serde_json::to_vec(&changed).unwrap();
    let mut changed_policy = policy.clone();
    changed_policy["product_backup"]["destination_policy_digest"] =
        json!(ProductBackupPolicy::decode(&changed).unwrap().digest());
    private_file(&projection_path, &changed);
    fixture.write_policy(&changed_policy);
    let helper_thread = thread::spawn(move || {
        let _ = admin_helper::serve_helper(&mut helper, &listener, 4);
    });
    let (mut executor, reply) = submitter.join().unwrap();
    println!(
        "w319_case=drift_after_intent state={:?} error={:?} store_requests={}",
        reply.state,
        reply.error,
        store_requests() - before
    );
    assert_eq!(reply.state, Some(OutcomeState::Failed));
    assert_eq!(reply.error.as_deref(), Some("PRECONDITION_CHANGED"));
    assert_eq!(store_requests(), before);
    private_file(&projection_path, &projection);
    fixture.write_policy(&policy);

    // 2. Unchanged policy: the helper binds the digest. W356: the closed
    // write gate then refuses before the store check (W319 ran the bound
    // repository check here first).
    let (operation, key) = (id("op_w319_bound"), id("key_w319_bound"));
    let before = store_requests();
    let reply = bound.submit(&mut executor, &operation, &key);
    let used = store_requests() - before;
    println!(
        "w319_case=bound_closed_gate state={:?} error={:?} store_requests={used}",
        reply.state, reply.error
    );
    assert_eq!(reply.state, Some(OutcomeState::Failed));
    assert_eq!(reply.error.as_deref(), Some("NOT_ADMITTED_FOR_EFFECT"));
    assert_eq!(used, 0);
    let recorded = executor.capture_status(&operation).unwrap().unwrap();
    assert_eq!(recorded.snapshot_id, None);
    assert_eq!(recorded.backup_policy_digest, Some(digest.clone()));

    // 3. Exact replay: stored status only, no job.
    let before = store_requests();
    let replay = bound.submit(&mut executor, &operation, &key);
    println!(
        "w319_case=exact_replay replay={} state={:?} store_requests={}",
        replay.replay,
        replay.state,
        store_requests() - before
    );
    assert!(replay.replay);
    assert_eq!(store_requests(), before);

    // 4. W320: a restore probe for the same site runs the same bound check
    // with the fetch credential. D-031 (W373): the probe phases then run;
    // the synthetic store holds no snapshot, so the fetch fails, the probe
    // is `failed`, and cleanup leaves no sandbox.
    let (mut probe_plan, mut probe_grant) = probe_vector();
    probe_plan["site_id"] = json!("blog9");
    probe_plan["destination_policy_digest"] = json!(digest);
    probe_grant["site_ids"] = json!(["blog9"]);
    let probe = SignedBackup::new(&fixture, &probe_plan, probe_grant);
    let operation = id("op_w320_probe");
    let before = store_requests();
    let reply = probe.submit(&mut executor, &operation, &id("key_w320_probe"));
    let used = store_requests() - before;
    println!(
        "w320_case=bound_probe_check state={:?} error={:?} store_requests={used}",
        reply.state, reply.error
    );
    assert_eq!(reply.state, Some(OutcomeState::Untouched));
    assert_eq!(reply.error, None);
    assert!(used > 0);
    let recorded = executor.probe_status(&operation).unwrap().unwrap();
    assert_eq!(recorded.state, ProbeState::Failed);
    let receipt: Value = serde_json::from_str(recorded.receipt.as_deref().unwrap()).unwrap();
    assert_eq!(receipt["fields"]["decryption_tested"]["status"], "fail");
    assert_eq!(receipt["cleanup"]["status"], "complete");
    assert!(
        !std::path::Path::new("/srv/restore-probes")
            .join(&recorded.intent.probe_account)
            .exists()
    );
    drop(helper_thread);
}

/// W321 root lab test: admin recovery of product captures left `running`
/// against the real store namespace and a planted tagged snapshot. Run
/// through docs/validation/S10-W321/probe_recovery.sh.
#[test]
#[ignore = "root lab test: needs the store namespace, relay and synthetic store"]
fn product_capture_recovery_as_root() {
    let env = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"));
    let mut fixture = BackupFixture::new();
    let mut policy = enroll(&fixture);
    let projection = std::fs::read(env("W319_PROJECTION")).unwrap();
    let digest = ProductBackupPolicy::decode(&projection).unwrap().digest();
    policy["product_backup"]["destination_policy_digest"] = json!(digest);
    fixture.write_policy(&policy);
    private_file(&fixture.projection_path(), &projection);
    let dir = &fixture.anchor.policy_dir;
    private_file(
        &dir.join("backup-ca.pem"),
        &std::fs::read(env("W319_CA")).unwrap(),
    );
    let site = dir.join("credentials/sites/rs_blog9");
    private_file(
        &site.join("fetch-aws"),
        &std::fs::read(env("W319_FETCH")).unwrap(),
    );
    private_file(
        &site.join("repo.password"),
        &std::fs::read(env("W319_PASSWORD")).unwrap(),
    );
    std::fs::write(
        dir.join("store-network.env"),
        std::fs::read(env("W319_NETWORK_FILE")).unwrap(),
    )
    .unwrap();
    // A garbled helper reply leaves each admitted capture `running`.
    let calls = stub_helper(&mut fixture.anchor, "garbled\n");
    provision(&fixture.anchor, "blog9");
    let mut executor = Executor::open(fixture.anchor.clone()).unwrap();
    let (plan, grant) = capture_vector();
    let mut plan = plan;
    plan["destination_policy_digest"] = json!(digest);
    let leave_running = |executor: &mut Executor, name: &str| {
        let mut grant = grant.clone();
        grant["grant_id"] = json!(format!("grant_{name}"));
        grant["nonce"] = json!(format!("nonce_{name}"));
        let operation = id(name);
        let reply = SignedBackup::new(&fixture, &plan, grant).submit(
            executor,
            &operation,
            &id(&format!("key_{name}")),
        );
        assert_eq!(reply.state, Some(OutcomeState::Intent));
        operation
    };

    // 1. No snapshot carries the tag: recovery records `failed`.
    let operation = leave_running(&mut executor, "op_w321_none");
    let before = store_requests();
    let result = executor.reconcile_capture(&operation);
    let used = store_requests() - before;
    let state = executor.capture_status(&operation).unwrap().unwrap().state;
    println!(
        "w321_case=no_tagged_snapshot result={:?} state={state:?} store_requests={used}",
        result.as_ref().map(|c| c.state)
    );
    assert_eq!(state, CaptureState::Failed);
    assert!(used > 0);

    // 2. The destination is re-enrolled after intent: recovery refuses
    // before any store use, and the capture stays `running`.
    let operation = leave_running(&mut executor, "op_w321_found");
    let mut changed: Value = serde_json::from_slice(&projection).unwrap();
    changed["retention_days"] = json!(31);
    let changed = serde_json::to_vec(&changed).unwrap();
    let mut changed_policy = policy.clone();
    changed_policy["product_backup"]["destination_policy_digest"] =
        json!(ProductBackupPolicy::decode(&changed).unwrap().digest());
    private_file(&fixture.projection_path(), &changed);
    fixture.write_policy(&changed_policy);
    let before = store_requests();
    let result = executor.reconcile_capture(&operation);
    let used = store_requests() - before;
    let state = executor.capture_status(&operation).unwrap().unwrap().state;
    println!(
        "w321_case=drift_after_intent result={result:?} state={state:?} store_requests={used}"
    );
    assert_eq!(result.err(), Some(ExecutorError::PreconditionChanged));
    assert_eq!(state, CaptureState::Running);
    assert_eq!(used, 0);
    private_file(&fixture.projection_path(), &projection);
    fixture.write_policy(&policy);

    // 3. A snapshot carries the operation's tag, but product snapshot
    // effects are not enabled: unexplained, so the capture stays `running`.
    let before = store_requests();
    let result = executor.reconcile_capture(&operation);
    let used = store_requests() - before;
    let state = executor.capture_status(&operation).unwrap().unwrap().state;
    println!(
        "w321_case=unexplained_tagged_snapshot result={result:?} state={state:?} store_requests={used}"
    );
    assert_eq!(result.err(), Some(ExecutorError::PreconditionChanged));
    assert_eq!(state, CaptureState::Running);
    assert!(used > 0);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}
