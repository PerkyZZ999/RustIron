//! W356 (B09): the product capture write path as the executor sees it.
//!
//! D-029 (W371) opens the write gate in every product build. The real
//! helper passes the gate after the bind, and the first capture step
//! refuses when the host has no site or store. The stub helper stands in for
//! the helper's outcome line, so the executor's journaling of each outcome
//! is tested without a store. The write itself is lab evidence
//! (docs/validation/S10-W356, S10-W371).

use std::{os::unix::net::UnixListener, sync::atomic::Ordering, thread, time::Duration};

use rustiron_contracts::execution::OutcomeState;
use rustiron_executor::{Executor, ExecutorError, admin_helper, write_gate};
use rustiron_journal::{CaptureConsistency, CaptureState};

use super::{
    BackupFixture,
    admission::{assert_checker_accepts, capture_vector, id, provision, stub_helper_for},
    verification::{SignedBackup, enroll},
};

const SNAPSHOT: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn the_product_write_gate_is_open() {
    // D-029: a product build may write capture snapshots. The lab build
    // keeps the gate closed (the `write_gate` unit test).
    assert!(std::hint::black_box(write_gate::PRODUCT_WRITES_ENABLED));
}

#[test]
fn the_product_staging_build_sets_only_the_product_profile() {
    let script = include_str!("../../../../packaging/stage-product.sh");
    // The staging build sets its own flags and ignores encoded ones. The
    // product profile alone opens the write gate (D-029).
    let flags: Vec<&str> = script
        .lines()
        .filter(|line| line.contains("RUSTFLAGS"))
        .collect();
    assert_eq!(
        flags,
        [
            "unset CARGO_ENCODED_RUSTFLAGS",
            "RUSTFLAGS='--cfg rustiron_profile=\"product\"' cargo build --release --locked --offline \\",
        ]
    );
}

#[test]
fn the_real_helper_passes_the_open_gate_and_refuses_before_the_write() {
    let mut fixture = BackupFixture::new();
    enroll(&fixture);
    // No site root, store network file, namespace or capture key pair exists
    // here. The helper passes the gate after the bind, and the first capture
    // step refuses with its own error, before any store use.
    let socket = fixture.anchor.journal_dir.with_file_name("helper.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    fixture.anchor.admin_socket = Some(socket);
    provision(&fixture.anchor, "blog9");
    // The helper refuses work journaled in or before its start second (W177).
    let mut helper = admin_helper::Helper::new(fixture.anchor.clone(), None);
    thread::sleep(Duration::from_millis(1100));
    let helper_thread = thread::spawn(move || {
        let _ = admin_helper::serve_helper(&mut helper, &listener, 4);
    });
    let mut executor = Executor::open(fixture.anchor.clone()).unwrap();
    let (plan, grant) = capture_vector();
    let operation = id("op_w356_gate");
    let reply = SignedBackup::new(&fixture, &plan, grant).submit(
        &mut executor,
        &operation,
        &id("key_w356_gate"),
    );
    assert_ne!(
        reply.error.as_deref(),
        Some(ExecutorError::NotAdmitted.code()),
        "the helper refused at the gate: {reply:?}"
    );
    // The site's label read (the first step after the gate) finds no site
    // root, so the capture never started.
    assert_eq!(reply.state, Some(OutcomeState::Failed));
    assert_eq!(
        reply.error.as_deref(),
        Some(ExecutorError::StepFailed.code())
    );
    let recorded = executor.capture_status(&operation).unwrap().unwrap();
    assert_eq!(recorded.state, CaptureState::Failed);
    assert_eq!(recorded.snapshot_id, None);
    drop(helper_thread);
}

/// Submits one capture against a stub helper that answers `payload`.
fn capture_with(payload: &str, name: &str) -> (BackupFixture, Executor, rustiron_contracts::Id) {
    let mut fixture = BackupFixture::new();
    enroll(&fixture);
    let reply: &'static str = Box::leak(format!("ok {payload}\n").into_boxed_str());
    let calls = stub_helper_for(&mut fixture.anchor, "capture_run", reply);
    provision(&fixture.anchor, "blog9");
    let mut executor = Executor::open(fixture.anchor.clone()).unwrap();
    let (plan, grant) = capture_vector();
    let operation = id(name);
    SignedBackup::new(&fixture, &plan, grant).submit(
        &mut executor,
        &operation,
        &id(&format!("key_{name}")),
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    (fixture, executor, operation)
}

#[test]
fn a_verified_write_is_recorded_with_its_snapshot_counts_and_label() {
    let payload = format!(
        r#"{{"outcome":"succeeded","id":"{SNAPSHOT}","files":3,"bytes":9,"consistency":{{"label":"matched","reason":null}}}}"#
    );
    let (_fixture, executor, operation) = capture_with(&payload, "op_w356_done");
    let recorded = executor.capture_status(&operation).unwrap().unwrap();
    assert_eq!(recorded.state, CaptureState::Succeeded);
    assert_eq!(recorded.snapshot_id.as_deref(), Some(SNAPSHOT));
    assert_eq!((recorded.files, recorded.bytes), (Some(3), Some(9)));
    assert_eq!(recorded.consistency, Some(CaptureConsistency::Matched));
    assert_eq!(recorded.retention_days, Some(30));
    // A manifest that does not verify against the site is dropped; none
    // was sent here.
    assert_eq!(recorded.manifest, None);
    let receipt = rustiron_executor::receipt::capture_receipt(&recorded).unwrap();
    assert_eq!(receipt["body"]["retention"]["status"], "not_recorded");
    assert_ne!(
        receipt["body"]["fields"]["independent_copy_confirmed"]["status"],
        "pass"
    );
}

#[test]
fn a_refusal_before_the_write_is_recorded_failed() {
    let payload = format!(
        r#"{{"outcome":"not_started","error":"{}"}}"#,
        ExecutorError::RetentionUnverified.code()
    );
    let (_fixture, executor, operation) = capture_with(&payload, "op_w356_refused");
    let recorded = executor.capture_status(&operation).unwrap().unwrap();
    assert_eq!(recorded.state, CaptureState::Failed);
    assert_eq!(recorded.snapshot_id, None);
    // W374: the product export of a refused capture passes the offline
    // checker and claims no checked snapshot or independent copy.
    let receipt = rustiron_executor::receipt::capture_receipt(&recorded).unwrap();
    let fields = &receipt["body"]["fields"];
    assert_eq!(fields["repository_integrity_checked"]["status"], "not_run");
    assert_eq!(fields["independent_copy_confirmed"]["status"], "unknown");
    assert_checker_accepts(&receipt);
}

#[test]
fn every_failure_after_the_write_start_stays_running() {
    for (name, payload) in [
        (
            "op_w356_check",
            format!(
                r#"{{"outcome":"uncertain","error":"{}","snapshot":"{SNAPSHOT}"}}"#,
                ExecutorError::StepFailed.code()
            ),
        ),
        (
            "op_w356_lost",
            format!(
                r#"{{"outcome":"uncertain","error":"{}","snapshot":null}}"#,
                ExecutorError::Unavailable.code()
            ),
        ),
        // A succeeded line without a full snapshot ID is unreadable.
        (
            "op_w356_short",
            r#"{"outcome":"succeeded","id":"0123","files":3,"bytes":9}"#.to_owned(),
        ),
        ("op_w356_unknown", r#"{"outcome":"maybe"}"#.to_owned()),
    ] {
        let (_fixture, executor, operation) = capture_with(&payload, name);
        let recorded = executor.capture_status(&operation).unwrap().unwrap();
        assert_eq!(recorded.state, CaptureState::Running, "{name}");
        assert_eq!(recorded.snapshot_id, None, "{name}");
    }
}

/// The `rustiron-store-check-<account>-*` unit that runs first within
/// `limit`, killed with SIGKILL once it is seen.
fn kill_first_check_unit(account: &str, limit: Duration) -> Option<String> {
    let pattern = format!("rustiron-store-check-{account}-*");
    let deadline = std::time::Instant::now() + limit;
    while std::time::Instant::now() < deadline {
        let listed = std::process::Command::new("/usr/bin/systemctl")
            .args(["list-units", "--plain", "--no-legend", "--", &pattern])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&listed.stdout);
        if let Some(unit) = text.split_whitespace().next() {
            let killed = std::process::Command::new("/usr/bin/systemctl")
                .args(["kill", "--signal=SIGKILL", "--", unit])
                .status()
                .ok()?;
            return killed.success().then(|| unit.to_owned());
        }
        thread::sleep(Duration::from_millis(20));
    }
    None
}

pub(super) fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
}

/// The W356 fixture for a real product write: a fixture journal (never the
/// live one) whose policy directory holds the enrolled projection, CA, site
/// credentials and store network file that the `W356_*` variables name.
/// Returns the fixture and the bound destination.
pub(super) fn lab_write_fixture() -> (
    BackupFixture,
    rustiron_contracts::approval::ProductBackupPolicy,
) {
    use rustiron_contracts::approval::ProductBackupPolicy;
    use serde_json::json;

    use super::{super::support::private_dir, private_file};

    let fixture = BackupFixture::new();
    let mut policy = enroll(&fixture);
    let projection = std::fs::read(env("W356_PROJECTION")).unwrap();
    let destination = ProductBackupPolicy::decode(&projection).unwrap();
    let digest = destination.digest();
    policy["product_backup"]["destination_id"] = json!(destination.destination_id().as_str());
    policy["product_backup"]["destination_policy_digest"] = json!(digest);
    fixture.write_policy(&policy);
    private_file(&fixture.projection_path(), &projection);
    let dir = fixture.anchor.policy_dir.clone();
    private_file(
        &dir.join("backup-ca.pem"),
        &std::fs::read(env("W356_CA")).unwrap(),
    );
    let credentials = dir.join("credentials/sites/rs_w344a");
    private_dir(&credentials);
    for (leaf, source) in [
        ("aws", "W356_CAPTURE"),
        ("fetch-aws", "W356_FETCH"),
        ("repo.password", "W356_PASSWORD"),
    ] {
        private_file(
            &credentials.join(leaf),
            &std::fs::read(env(source)).unwrap(),
        );
    }
    std::fs::write(
        dir.join("store-network.env"),
        std::fs::read(env("W356_NETWORK_FILE")).unwrap(),
    )
    .unwrap();
    (fixture, destination)
}

/// The signed capture of site `w344a` to `destination`, with its own grant
/// for the operation `name`.
pub(super) fn lab_capture(
    fixture: &BackupFixture,
    destination: &rustiron_contracts::approval::ProductBackupPolicy,
    name: &str,
) -> SignedBackup {
    use serde_json::json;

    let (mut plan, mut grant) = capture_vector();
    plan["site_id"] = json!("w344a");
    plan["destination_id"] = json!(destination.destination_id().as_str());
    plan["destination_policy_digest"] = json!(destination.digest());
    grant["grant_id"] = json!(format!("grant_{name}"));
    grant["nonce"] = json!(format!("nonce_{name}"));
    grant["site_ids"] = json!(["w344a"]);
    grant["destinations"] = json!([destination.destination_id().as_str()]);
    SignedBackup::new(fixture, &plan, grant)
}

/// W356 root lab test: recovery of product captures left `running` after a
/// real product write, on a fixture journal (never the live one). Run
/// through docs/validation/S10-W356/probe_write.sh with a product-profile
/// build (D-029; W356 used the retired lab write-proof flag). Killing the structure check after the write leaves the capture
/// running. Recovery must refuse both a single tagged snapshot and an
/// ambiguous tag.
#[test]
#[ignore = "root lab test: run through docs/validation/S10-W356/probe_write.sh"]
fn product_write_recovery_as_root() {
    use rustiron_contracts::approval::SiteId;

    let (mut fixture, destination) = lab_write_fixture();
    // A garbled helper reply leaves each admitted capture `running`.
    let calls = stub_helper_for(&mut fixture.anchor, "capture_run", "garbled\n");
    provision(&fixture.anchor, "w344a");
    let mut executor = Executor::open(fixture.anchor.clone()).unwrap();
    let site = SiteId::try_from("w344a".to_owned()).unwrap();
    let leave_running = |executor: &mut Executor, name: &str| {
        let operation = id(name);
        let reply = lab_capture(&fixture, &destination, name).submit(
            executor,
            &operation,
            &id(&format!("key_{name}")),
        );
        assert_eq!(reply.state, Some(OutcomeState::Intent), "{reply:?}");
        operation
    };
    let effects = |operation: &rustiron_contracts::Id| {
        let line = admin_helper::product_capture_effects(
            &fixture.anchor,
            &destination,
            &site,
            operation,
            false,
        )
        .unwrap();
        serde_json::from_str::<serde_json::Value>(&line).unwrap()
    };

    // 1. Killed check: the tag alone cannot settle the journal.
    let operation = leave_running(&mut executor, &env("W356_OPERATION"));
    let killer = thread::spawn(|| kill_first_check_unit("rs_w344a", Duration::from_secs(120)));
    let outcome = effects(&operation);
    let killed = killer.join().unwrap();
    println!(
        "w356_case=kill_during_check killed={killed:?} outcome={} error={} snapshot={}",
        outcome["outcome"], outcome["error"], outcome["snapshot"]
    );
    assert!(killed.is_some());
    assert_eq!(outcome["outcome"], "uncertain");
    assert!(outcome["snapshot"].is_string());
    let running = executor.capture_status(&operation).unwrap().unwrap();
    assert_eq!(running.state, CaptureState::Running);
    let recovered = executor.reconcile_capture(&operation);
    let recorded = executor.capture_status(&operation).unwrap().unwrap();
    println!(
        "w356_case=recover_killed result={:?} state={:?} snapshot={:?}",
        recovered.as_ref().map(|c| c.state),
        recorded.state,
        recorded.snapshot_id,
    );
    assert_eq!(recovered.unwrap_err(), ExecutorError::PreconditionChanged);
    assert_eq!(recorded.state, CaptureState::Running);
    assert_eq!(recorded.snapshot_id, None);
    assert_eq!(
        rustiron_executor::receipt::capture_receipt(&recorded).unwrap_err(),
        ExecutorError::NotAdmitted,
    );

    // 2. Inject a second write directly through the fixture. The unresolved
    // journal intent still prevents a new capture admission for this site.
    let second = effects(&operation);
    println!(
        "w356_case=two_tagged second={} error={} snapshot={}",
        second["outcome"], second["error"], second["snapshot"]
    );
    assert_eq!(second["outcome"], "uncertain");
    assert!(second["snapshot"].is_string());
    assert_ne!(outcome["snapshot"], second["snapshot"]);
    let refused = executor.reconcile_capture(&operation);
    let recorded = executor.capture_status(&operation).unwrap().unwrap();
    println!(
        "w356_case=recover_two_tagged result={refused:?} state={:?}",
        recorded.state
    );
    assert_eq!(refused.unwrap_err(), ExecutorError::Unavailable);
    assert_eq!(recorded.state, CaptureState::Running);
    assert_eq!(recorded.snapshot_id, None);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
