use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    sync::{Mutex, MutexGuard},
};

use rustiron_contracts::{
    CanonicalObject, Timestamp,
    approval::{MAX_PRODUCT_BACKUP_POLICY_BYTES, Sha256Digest},
};
use rustiron_executor::{AdmissionRequest, Executor, ExecutorError, TrustAnchor};
use rustiron_journal::{
    CaptureIntent, CaptureMethod, FixtureJournal, ProvisionIntent, ProvisionStep,
};
use serde_json::{Value, json};

use super::support::{KEYGEN, hex, new_key, private_dir, private_file, sign};

#[path = "backup_admission.rs"]
mod admission;
#[path = "clone_preflight.rs"]
mod clone_preflight;
#[path = "delete_admission.rs"]
mod delete_admission;
#[path = "backup_faults.rs"]
mod faults;
#[path = "proxy_refusal.rs"]
mod proxy_refusal;
#[path = "quota_admission.rs"]
mod quota_admission;
#[path = "site_quota.rs"]
mod site_quota;
#[path = "standing_abuse.rs"]
mod standing_abuse;
#[path = "standing_capture.rs"]
mod standing_capture;
#[path = "update_admission.rs"]
mod update_admission;
#[path = "backup_verification.rs"]
mod verification;
#[path = "backup_write.rs"]
mod write;
#[path = "backup_write_faults.rs"]
mod write_faults;

// Keep SSHSIG child processes from inheriting another fixture's journal lease.
static BACKUP_TESTS: Mutex<()> = Mutex::new(());
const PROJECTION: &[u8] = include_bytes!("../../../../docs/validation/S10-W307/projection.json");
const PROJECTION_DIGEST: &str =
    include_str!("../../../../docs/validation/S10-W307/projection-digest.txt");

struct BackupFixture {
    _serial: MutexGuard<'static, ()>,
    root: PathBuf,
    anchor: TrustAnchor,
}

impl BackupFixture {
    fn new() -> Self {
        let serial = BACKUP_TESTS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut random = [0; 16];
        rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty()).unwrap();
        // W319 root lab test: PID 1 reads credential sources, which it may
        // not from tmp labels, so that test places the fixture under /run.
        // W633 (M-15): keep Unix socket paths well below SUN_LEN (108 bytes)
        // even when the caller exports a long TMPDIR.
        let parent = std::env::var_os("W319_FIXTURE_PARENT").map_or_else(
            || {
                let candidate = std::env::temp_dir();
                if candidate.as_os_str().len() > 32 && PathBuf::from("/tmp").is_dir() {
                    PathBuf::from("/tmp")
                } else {
                    candidate
                }
            },
            PathBuf::from,
        );
        let root = parent.join(format!("ri-pb-{}", hex(&random[..8])));
        let anchor = TrustAnchor {
            owner_uid: rustix::process::getuid().as_raw(),
            policy_dir: root.join("policy"),
            registry_dir: root.join("registry"),
            scratch_dir: root.join("scratch"),
            journal_dir: root.join("journal"),
            mark_dir: root.join("mark"),
            recipes_dir: root.join("recipes"),
            admin_socket: None,
        };
        for dir in [
            &anchor.policy_dir,
            &anchor.scratch_dir,
            &anchor.journal_dir,
            &anchor.mark_dir,
        ] {
            private_dir(dir);
        }
        new_key(&root.join("key"));
        let public_key = fs::read_to_string(root.join("key.pub")).unwrap();
        let key_fields = public_key.split_whitespace().take(2).collect::<Vec<_>>();
        private_file(
            &anchor.policy_dir.join("allowed_signers"),
            format!(
                "operator_1 namespaces=\"rustiron-plan-v1\" {}\n",
                key_fields.join(" ")
            )
            .as_bytes(),
        );
        private_file(&anchor.policy_dir.join("revocations"), b"");
        let policy = json!({
            "schema_version": 1,
            "host_id": "host_lab",
            "host_epoch": "epoch_1",
            "profile_digest": "a".repeat(64),
            "requester": "agent_1",
            "requester_uid": 4242,
            "issuer": "operator_1",
            "signer_policy_epoch": "policy_1",
            "verifier_sha256": hex(&fs::read(KEYGEN).unwrap()),
            "provisioning": {
                "wordpress_713_sha256": "d".repeat(64), "uid_min": 3001, "uid_max": 3099,
                "category_min": 201, "category_max": 299,
                // W335: the product profile requires an enrolled site quota.
                "quota": {"block_hard_kib": 5_242_880, "inode_hard": 500_000},
            },
            "backup": {
                "destination_id": "lab_pc_store", "retention_days": 30,
                "repository_base": "s3:http://127.0.0.1:9000/synthetic/sites", "store_address": "127.0.0.1",
            },
        });
        private_file(
            &anchor.policy_dir.join("policy.json"),
            &serde_json::to_vec(&policy).unwrap(),
        );
        Self {
            _serial: serial,
            root,
            anchor,
        }
    }

    fn sign(&self, grant: &[u8]) -> Vec<u8> {
        sign(
            &self.root.join("key"),
            &self.root.join("message"),
            CanonicalObject::decode(grant).unwrap().as_bytes(),
            "rustiron-plan-v1",
        )
    }

    fn replay_state(&self) -> (Vec<u8>, Vec<u8>) {
        (
            fs::read(self.anchor.journal_dir.join("fixture-journal.sqlite")).unwrap(),
            fs::read(self.anchor.mark_dir.join("admission-mark")).unwrap(),
        )
    }

    fn product_policy(&self) -> Value {
        let bytes = fs::read(self.anchor.policy_dir.join("policy.json")).unwrap();
        let mut policy: Value = serde_json::from_slice(&bytes).unwrap();
        policy.as_object_mut().unwrap().remove("backup");
        policy["schema_version"] = json!(2);
        policy["product_backup"] = json!({
            "destination_id": "offsite_fixture",
            "destination_policy_digest": PROJECTION_DIGEST.trim_end(),
        });
        policy
    }

    fn write_policy(&self, policy: &Value) {
        private_file(
            &self.anchor.policy_dir.join("policy.json"),
            &serde_json::to_vec(policy).unwrap(),
        );
    }

    fn projection_path(&self) -> PathBuf {
        self.anchor.policy_dir.join("backup-destination.json")
    }
}

impl Drop for BackupFixture {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.root) {
            eprintln!("synthetic backup cleanup failed: {error}");
            assert!(std::thread::panicking());
        }
    }
}

#[test]
fn product_refuses_signed_lab_backups_before_intent() {
    let fixture = BackupFixture::new();
    fixture.write_policy(&fixture.product_policy());
    private_file(&fixture.projection_path(), PROJECTION);
    let mut executor = Executor::initialize(fixture.anchor.clone()).unwrap();
    let before = fixture.replay_state();
    let capture_grant = include_bytes!("../../../contracts/tests/fixtures/capture-grant.json");
    let capture_signature = fixture.sign(capture_grant);
    let capture = AdmissionRequest {
        peer_uid: 4242,
        plan: include_bytes!("../../../contracts/tests/fixtures/capture-plan.json"),
        grant: capture_grant,
        signature: &capture_signature,
        operation_id: "op_product_capture".to_owned().try_into().unwrap(),
        idempotency_key: "key_product_capture".to_owned().try_into().unwrap(),
        now: Some(Timestamp::try_from(1200).unwrap()),
    };
    let probe_grant = include_bytes!("../../../contracts/tests/fixtures/probe-grant.json");
    let probe_signature = fixture.sign(probe_grant);
    let probe = AdmissionRequest {
        plan: include_bytes!("../../../contracts/tests/fixtures/probe-plan.json"),
        grant: probe_grant,
        signature: &probe_signature,
        operation_id: "op_product_probe".to_owned().try_into().unwrap(),
        idempotency_key: "key_product_probe".to_owned().try_into().unwrap(),
        ..capture
    };
    let capture_refusal = executor.backup_capture(&capture).unwrap_err();
    let probe_refusal = executor.restore_probe(&probe).unwrap_err();
    assert_eq!(
        (capture_refusal, probe_refusal),
        (ExecutorError::InvalidRequest, ExecutorError::InvalidRequest)
    );
    assert!(
        executor
            .capture_status(&capture.operation_id)
            .unwrap()
            .is_none()
    );
    assert!(
        executor
            .probe_status(&probe.operation_id)
            .unwrap()
            .is_none()
    );
    assert_eq!(fixture.replay_state(), before);
}

#[test]
fn product_observation_reports_only_the_validated_destination_pin() {
    let fixture = BackupFixture::new();
    let path = fixture.projection_path();
    // A loose file with no pin is not enrollment under the historical schema.
    private_file(&path, b"{}");
    drop(Executor::initialize(fixture.anchor.clone()).unwrap());
    let before = fixture.replay_state();
    let historical = Executor::observe(&fixture.anchor).unwrap();
    assert!(
        historical["host"]
            .get("product_backup_enrollment")
            .is_none()
    );

    let policy = fixture.product_policy();
    private_file(&path, PROJECTION);
    fixture.write_policy(&policy);
    let observation = Executor::observe(&fixture.anchor).unwrap();
    assert_eq!(
        observation["host"]["product_backup_enrollment"],
        policy["product_backup"]
    );
    // W364: the product executor never runs rpm (its domain may not), so
    // the package facts are reported as not observed, not as a failed query.
    assert!(observation["host"]["packages"].is_null());
    assert_eq!(observation["host"]["package_source"], "not_observed");
    assert!(observation["host"]["backup_destination"].is_null());
    assert_eq!(
        observation["journal_last_time"],
        historical["journal_last_time"]
    );
    assert_eq!(fixture.replay_state(), before);
}

/// W374: `packaging/enrollment-policy.py` writes the schema 2 policy that
/// W371 wrote by hand. The product executor loads it with the reviewed
/// projection and refuses it when the pinned digest is not the projection's.
#[test]
fn the_enrollment_tool_writes_a_schema_2_policy_the_product_executor_loads() {
    let fixture = BackupFixture::new();
    private_file(&fixture.projection_path(), PROJECTION);
    let path = fixture.anchor.policy_dir.join("policy.json");
    let enrolled: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let text = |key: &str| enrolled[key].as_str().unwrap().to_owned();
    let tool = |digest: &str| {
        fs::remove_file(&path).unwrap();
        let output = std::process::Command::new("python3")
            .arg("-I")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../packaging/enrollment-policy.py"
            ))
            .args(["policy", "--out"])
            .arg(&path)
            .args([
                "--host-id",
                &text("host_id"),
                "--host-epoch",
                &text("host_epoch"),
            ])
            .args(["--profile-digest", &text("profile_digest")])
            .args(["--requester", &text("requester"), "--requester-uid", "4242"])
            .args(["--issuer", &text("issuer")])
            .args(["--signer-policy-epoch", &text("signer_policy_epoch")])
            .args(["--verifier-sha256", &text("verifier_sha256")])
            .args(["--wordpress-sha256", &"d".repeat(64)])
            .args(["--uid-range", "3001-3099", "--category-range", "201-299"])
            .args([
                "--quota-block-hard-kib",
                "5242880",
                "--quota-inode-hard",
                "500000",
            ])
            .args(["--product-backup-destination-id", "offsite_fixture"])
            .args(["--product-backup-digest", digest])
            .output()
            .expect("python3");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    tool(PROJECTION_DIGEST.trim_end());
    let written: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(written["schema_version"], 2);
    drop(Executor::initialize(fixture.anchor.clone()).unwrap());
    let observation = Executor::observe(&fixture.anchor).unwrap();
    assert_eq!(
        observation["host"]["product_backup_enrollment"],
        json!({
            "destination_id": "offsite_fixture",
            "destination_policy_digest": PROJECTION_DIGEST.trim_end(),
        })
    );
    drop(Executor::open(fixture.anchor.clone()).unwrap());

    // A pin that is not the projection's digest is refused at load. The
    // journal exists, so the refusal is the policy's.
    tool(&"0".repeat(64));
    assert_eq!(
        Executor::observe(&fixture.anchor).err(),
        Some(ExecutorError::Unavailable)
    );
    assert_eq!(
        Executor::open(fixture.anchor.clone()).err(),
        Some(ExecutorError::Unavailable)
    );
}

#[test]
fn product_refuses_unsafe_or_unpinned_destination_before_initializing_state() {
    let fixture = BackupFixture::new();
    let policy = fixture.product_policy();
    let path = fixture.projection_path();
    fixture.write_policy(&policy);
    let refused = |expected, case| {
        assert_eq!(
            Executor::initialize(fixture.anchor.clone()).err(),
            Some(expected),
            "{case}"
        );
        assert_eq!(
            fs::read_dir(&fixture.anchor.journal_dir).unwrap().count(),
            0
        );
        assert_eq!(fs::read_dir(&fixture.anchor.mark_dir).unwrap().count(), 0);
    };

    refused(ExecutorError::AccessDenied, "missing projection");
    let alias = fixture.root.join("projection");
    private_file(&alias, PROJECTION);
    symlink(&alias, &path).unwrap();
    refused(ExecutorError::AccessDenied, "symlink projection");
    fs::remove_file(&path).unwrap();
    fs::hard_link(&alias, &path).unwrap();
    refused(ExecutorError::AccessDenied, "hard-linked projection");
    fs::remove_file(&path).unwrap();

    private_file(&path, PROJECTION);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    refused(ExecutorError::AccessDenied, "group-readable projection");

    private_file(&path, &vec![b' '; MAX_PRODUCT_BACKUP_POLICY_BYTES + 1]);
    refused(ExecutorError::InvalidRequest, "oversized projection");
    private_file(&path, b"{}");
    refused(ExecutorError::Unavailable, "malformed projection");
    let mut drift: Value = serde_json::from_slice(PROJECTION).unwrap();
    drift["transport"]["endpoint_ipv4"] = json!("198.51.100.24");
    private_file(&path, drift.to_string().as_bytes());
    refused(ExecutorError::Unavailable, "projection digest drift");

    private_file(&path, PROJECTION);
    let mut wrong_id = policy.clone();
    wrong_id["product_backup"]["destination_id"] = json!("other_destination");
    fixture.write_policy(&wrong_id);
    refused(ExecutorError::Unavailable, "pinned ID mismatch");

    let mut wrong_version = policy.clone();
    wrong_version["schema_version"] = json!(1);
    fixture.write_policy(&wrong_version);
    refused(ExecutorError::Unavailable, "pin in host schema v1");

    let mut missing_pin = policy.clone();
    missing_pin
        .as_object_mut()
        .unwrap()
        .remove("product_backup");
    fixture.write_policy(&missing_pin);
    refused(ExecutorError::Unavailable, "missing v2 pin");
    missing_pin["product_backup"] = Value::Null;
    fixture.write_policy(&missing_pin);
    refused(ExecutorError::Unavailable, "null pin");

    let mut mixed_policy = policy;
    mixed_policy["backup"] = json!({
        "destination_id": "lab_pc_store", "retention_days": 30,
        "repository_base": "s3:http://127.0.0.1:9000/synthetic/sites", "store_address": "127.0.0.1",
    });
    fixture.write_policy(&mixed_policy);
    refused(
        ExecutorError::Unavailable,
        "mixed lab and product enrollment",
    );
}

#[test]
fn product_reads_historical_capture_without_reconciling_it() {
    let fixture = BackupFixture::new();
    drop(Executor::initialize(fixture.anchor.clone()).unwrap());
    let host = "host_lab".to_owned().try_into().unwrap();
    let epoch = "epoch_1".to_owned().try_into().unwrap();
    let intent = CaptureIntent {
        operation_id: "op_lab_history".to_owned().try_into().unwrap(),
        idempotency_key: "key_lab_history".to_owned().try_into().unwrap(),
        grant_id: "grant_lab_history".to_owned().try_into().unwrap(),
        nonce: "nonce_lab_history".to_owned().try_into().unwrap(),
        plan_digest: Sha256Digest::from_bytes([1; 32]),
        grant_digest: Sha256Digest::from_bytes([2; 32]),
        host_id: host,
        host_epoch: epoch,
        site_id: "blog9".to_owned().try_into().unwrap(),
        expires_at: Timestamp::try_from(1900).unwrap(),
    };
    let mut journal = FixtureJournal::open_as_process_owner(
        &fixture.anchor.journal_dir,
        intent.host_id.clone(),
        intent.host_epoch.clone(),
    )
    .unwrap();
    let provision = ProvisionIntent {
        operation_id: "op_lab_provision".to_owned().try_into().unwrap(),
        idempotency_key: "key_lab_provision".to_owned().try_into().unwrap(),
        grant_id: "grant_lab_provision".to_owned().try_into().unwrap(),
        nonce: "nonce_lab_provision".to_owned().try_into().unwrap(),
        plan_digest: Sha256Digest::from_bytes([4; 32]),
        grant_digest: Sha256Digest::from_bytes([5; 32]),
        host_id: intent.host_id.clone(),
        host_epoch: intent.host_epoch.clone(),
        site_id: intent.site_id.clone(),
        hostname: "blog9.example.test".to_owned().try_into().unwrap(),
        expires_at: intent.expires_at,
    };
    journal
        .record_provision(&provision, Timestamp::try_from(1100).unwrap())
        .unwrap();
    for step in ProvisionStep::ALL {
        journal
            .begin_step(&provision.operation_id, step, "synthetic")
            .unwrap();
        journal
            .finish_step(&provision.operation_id, step, true)
            .unwrap();
    }
    journal
        .record_capture(
            &intent,
            Timestamp::try_from(1200).unwrap(),
            CaptureMethod::SiteFilesDbV1,
            Some(30),
            &Sha256Digest::from_bytes([3; 32]),
        )
        .unwrap();
    drop(journal);
    let mut executor = Executor::open(fixture.anchor.clone()).unwrap();
    let before = fixture.replay_state();
    let recorded = executor
        .capture_status(&intent.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(recorded.intent, intent);
    assert_eq!(
        executor
            .reconcile_capture(&intent.operation_id)
            .unwrap_err(),
        ExecutorError::InvalidRequest
    );
    assert_eq!(
        executor.capture_status(&intent.operation_id).unwrap(),
        Some(recorded)
    );
    assert_eq!(fixture.replay_state(), before);
}
