use rustiron_contracts::approval::{ProductBackupPolicy, SiteClonePlan};
use rustiron_journal::{CaptureConsistency, CaptureManifest};

use super::*;

fn time(seconds: u64) -> Timestamp {
    Timestamp::try_from(seconds).unwrap()
}

fn identifier(value: &str) -> rustiron_contracts::Id {
    value.to_owned().try_into().unwrap()
}

fn seed_capture(fixture: &BackupFixture, destination: &ProductBackupPolicy) {
    drop(Executor::initialize(fixture.anchor.clone()).unwrap());
    let mut journal = FixtureJournal::open_as_process_owner(
        &fixture.anchor.journal_dir,
        identifier("host_lab"),
        identifier("epoch_1"),
    )
    .unwrap();
    let provision = ProvisionIntent {
        operation_id: identifier("op_clone_source"),
        idempotency_key: identifier("key_clone_source"),
        grant_id: identifier("grant_clone_source"),
        nonce: identifier("nonce_clone_source"),
        plan_digest: Sha256Digest::from_bytes([1; 32]),
        grant_digest: Sha256Digest::from_bytes([2; 32]),
        host_id: identifier("host_lab"),
        host_epoch: identifier("epoch_1"),
        site_id: "blog9".to_owned().try_into().unwrap(),
        hostname: "blog9.example.test".to_owned().try_into().unwrap(),
        expires_at: time(1400),
    };
    journal.record_provision(&provision, time(1000)).unwrap();
    for step in ProvisionStep::ALL {
        let resource = if step == ProvisionStep::Recipe {
            "Recipe rs_blog9 recipe=wordpress713_install_v1"
        } else {
            "synthetic"
        };
        journal
            .begin_step(&provision.operation_id, step, resource)
            .unwrap();
        journal
            .finish_step(&provision.operation_id, step, true)
            .unwrap();
    }
    let capture = CaptureIntent {
        operation_id: identifier("op_capture1"),
        idempotency_key: identifier("key_clone_capture"),
        grant_id: identifier("grant_clone_capture"),
        nonce: identifier("nonce_clone_capture"),
        plan_digest: Sha256Digest::from_bytes([3; 32]),
        grant_digest: Sha256Digest::from_bytes([4; 32]),
        host_id: provision.host_id,
        host_epoch: provision.host_epoch,
        site_id: provision.site_id,
        expires_at: time(1400),
    };
    journal
        .record_capture(
            &capture,
            time(1050),
            CaptureMethod::SiteFilesDbV1,
            Some(30),
            &destination.digest(),
        )
        .unwrap();
    journal
        .finish_capture_labelled(
            &capture.operation_id,
            Some(&"b".repeat(64)),
            time(1100),
            None,
            Some(&CaptureManifest {
                sha256: "c".repeat(64),
                entries: 2,
                regular_bytes: 16,
                truncated: false,
            }),
            Some(&CaptureConsistency::Matched),
        )
        .unwrap();
}

#[test]
fn signed_native_clone_checks_recorded_capture_without_admitting_an_effect() {
    let fixture = BackupFixture::new();
    let mut policy = fixture.product_policy();
    policy["ols"] = json!({
        "listener": "CloneLab", "address": "127.0.0.1:8090", "adopted": [],
        "parent_sha256": "e".repeat(64), "webadmin_port": 7080,
    });
    fixture.write_policy(&policy);
    private_file(&fixture.projection_path(), PROJECTION);
    let destination = ProductBackupPolicy::decode(PROJECTION).unwrap();
    seed_capture(&fixture, &destination);
    let executor = Executor::open(fixture.anchor.clone()).unwrap();
    let before = fixture.replay_state();
    let mut plan: Value = serde_json::from_slice(include_bytes!(
        "../../../contracts/tests/fixtures/site-clone-plan.json"
    ))
    .unwrap();
    let blog9 = "blog9".to_owned().try_into().unwrap();
    plan["source"]["site_id"] = json!("blog9");
    plan["source"]["hostname"] = json!("blog9.example.test");
    plan["source"]["destination_id"] = json!(destination.destination_id());
    plan["source"]["destination_policy_digest"] = json!(destination.digest());
    plan["source"]["repository_id"] = json!(destination.repository_id(&blog9).unwrap());
    for (member, value, expected) in [
        (
            "manifest_sha256",
            "c".repeat(64),
            ExecutorError::NotAdmitted,
        ),
        (
            "manifest_sha256",
            "f".repeat(64),
            ExecutorError::PreconditionChanged,
        ),
        (
            "snapshot_id",
            "a".repeat(64),
            ExecutorError::PreconditionChanged,
        ),
        (
            "repository_id",
            "f".repeat(64),
            ExecutorError::PreconditionChanged,
        ),
        (
            "hostname",
            "other.example.test".to_owned(),
            ExecutorError::PreconditionChanged,
        ),
    ] {
        let mut changed = plan.clone();
        changed["source"][member] = json!(value);
        let bytes = changed.to_string();
        let parsed = SiteClonePlan::decode(bytes.as_bytes()).unwrap();
        let mut grant: Value = serde_json::from_slice(include_bytes!(
            "../../../contracts/tests/fixtures/site-clone-grant.json"
        ))
        .unwrap();
        grant["source_site_id"] = changed["source"]["site_id"].clone();
        grant["destination_id"] = changed["source"]["destination_id"].clone();
        grant["snapshot_id"] = changed["source"]["snapshot_id"].clone();
        grant["plan_digest"] = json!(parsed.digest());
        let grant = grant.to_string();
        let signature = fixture.sign(grant.as_bytes());
        let request = AdmissionRequest {
            peer_uid: 4242,
            plan: bytes.as_bytes(),
            grant: grant.as_bytes(),
            signature: &signature,
            operation_id: identifier("op_site_clone"),
            idempotency_key: identifier("key_site_clone"),
            now: Some(time(1200)),
        };
        assert_eq!(
            executor.preflight_site_clone(&request),
            Err(expected),
            "{member}"
        );
    }
    assert_eq!(fixture.replay_state(), before);
}

/// The exact signed clone of `blog9`'s recorded capture as the fixture target.
fn exact_clone(
    fixture: &BackupFixture,
    destination: &ProductBackupPolicy,
) -> (String, String, Vec<u8>) {
    let mut plan: Value = serde_json::from_slice(include_bytes!(
        "../../../contracts/tests/fixtures/site-clone-plan.json"
    ))
    .unwrap();
    let blog9 = "blog9".to_owned().try_into().unwrap();
    plan["source"]["site_id"] = json!("blog9");
    plan["source"]["hostname"] = json!("blog9.example.test");
    plan["source"]["manifest_sha256"] = json!("c".repeat(64));
    plan["source"]["destination_id"] = json!(destination.destination_id());
    plan["source"]["destination_policy_digest"] = json!(destination.digest());
    plan["source"]["repository_id"] = json!(destination.repository_id(&blog9).unwrap());
    let bytes = plan.to_string();
    let parsed = SiteClonePlan::decode(bytes.as_bytes()).unwrap();
    let mut grant: Value = serde_json::from_slice(include_bytes!(
        "../../../contracts/tests/fixtures/site-clone-grant.json"
    ))
    .unwrap();
    grant["source_site_id"] = plan["source"]["site_id"].clone();
    grant["destination_id"] = plan["source"]["destination_id"].clone();
    grant["snapshot_id"] = plan["source"]["snapshot_id"].clone();
    grant["plan_digest"] = json!(parsed.digest());
    let grant = grant.to_string();
    let signature = fixture.sign(grant.as_bytes());
    (bytes, grant, signature)
}

#[test]
fn an_exact_clone_records_its_reservation_and_source_before_any_effect() {
    use rustiron_executor::Fault;
    use rustiron_journal::{ProvisionState, StepState};
    let fixture = BackupFixture::new();
    let mut policy = fixture.product_policy();
    policy["ols"] = json!({
        "listener": "CloneLab", "address": "127.0.0.1:8090", "adopted": [],
        "parent_sha256": "e".repeat(64), "webadmin_port": 7080,
    });
    fixture.write_policy(&policy);
    private_file(&fixture.projection_path(), PROJECTION);
    let destination = ProductBackupPolicy::decode(PROJECTION).unwrap();
    seed_capture(&fixture, &destination);
    let (plan, grant, signature) = exact_clone(&fixture, &destination);
    let request = AdmissionRequest {
        peer_uid: 4242,
        plan: plan.as_bytes(),
        grant: grant.as_bytes(),
        signature: &signature,
        operation_id: identifier("op_site_clone"),
        idempotency_key: identifier("key_site_clone"),
        now: Some(time(1200)),
    };
    let mut executor = Executor::open(fixture.anchor.clone()).unwrap();
    let before = fixture.replay_state();
    // A crash right after the first step's intent: nothing ran on the host.
    executor.inject_fault(Fault::AfterProvisionStepBegin);
    assert_eq!(
        executor.site_clone(&request).err(),
        Some(ExecutorError::Unavailable)
    );
    assert_ne!(fixture.replay_state(), before);
    let running = executor
        .provision_status(&identifier("op_site_clone"))
        .unwrap()
        .unwrap();
    assert_eq!(running.state, ProvisionState::Running);
    assert_eq!(running.intent.site_id.as_str(), "staging");
    assert_eq!(running.steps.len(), 1);
    assert_eq!(running.steps[0].state, StepState::Intent);
    drop(executor);
    let journal = FixtureJournal::open_as_process_owner(
        &fixture.anchor.journal_dir,
        identifier("host_lab"),
        identifier("epoch_1"),
    )
    .unwrap();
    let clone = journal
        .clone_status(&identifier("op_site_clone"))
        .unwrap()
        .unwrap();
    assert_eq!(clone.facts.source_site_id.as_str(), "blog9");
    assert_eq!(clone.facts.snapshot_id.as_str(), "b".repeat(64));
    assert!(clone.steps.is_empty());
    drop(journal);
    // An exact repeat is status only; the reserved target refuses another.
    let mut executor = Executor::open(fixture.anchor.clone()).unwrap();
    assert!(matches!(
        executor.site_clone(&request),
        Ok(rustiron_journal::ProvisionResult::Existing(_))
    ));
    let other = AdmissionRequest {
        operation_id: identifier("op_site_clone2"),
        idempotency_key: identifier("key_site_clone2"),
        ..request
    };
    assert_eq!(
        executor.site_clone(&other).err(),
        Some(ExecutorError::PreconditionChanged)
    );
}
