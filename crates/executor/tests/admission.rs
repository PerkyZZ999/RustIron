//! Admission behavior against synthetic keys and a real on-disk fixture registry.
//! Keys are disposable SYNTHETIC_ONLY material; they prove crypto behavior only.

use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    process::Command,
    time::{Duration, Instant},
};

use rustiron_contracts::{
    ErrorCode, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
    execution::{OutcomeState, SubmissionReply, encode_submission},
    local,
};
use rustiron_contracts::{
    Id, Timestamp,
    approval::{FixtureGrant, FixturePlan},
};
use rustiron_executor::{
    AdmissionRequest, Executor, ExecutorError, Fault, TrustAnchor, admit, serve,
};
use rustiron_journal::{ProvisionState, ProvisionStep, RecordResult, RecordedState, StepState};
use serde_json::{Value, json};
mod support;
use support::{KEYGEN, hex, new_key, private_dir, private_file, sign};

const PLAN: &str = include_str!("../../contracts/tests/fixtures/fixture-plan.json");
const GRANT: &str = include_str!("../../contracts/tests/fixtures/fixture-grant.json");
const OLD_CONTENT: &[u8] = b"alpha fixture\n";
const NEW_CONTENT: &[u8] = b"beta fixture\n";

/// Labs run one at a time: a child spawned by one test thread briefly inherits
/// another thread's journal lease descriptor between fork and exec, which makes
/// an immediate reopen see the writer lock as held. The executor itself is
/// single-threaded, so this is a harness constraint, not a product race.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Lab {
    _serial: std::sync::MutexGuard<'static, ()>,
    root: PathBuf,
    anchor: TrustAnchor,
    plan: Vec<u8>,
    grant: Vec<u8>,
    grant_value: Value,
    signature: Vec<u8>,
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl Lab {
    fn new(name: &str) -> Self {
        let serial = SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let root = std::env::temp_dir().join(format!("ri-executor-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        private_dir(&root);
        let (policy_dir, registry_dir, scratch_dir, journal_dir, mark_dir) = (
            root.join("policy"),
            root.join("registry"),
            root.join("scratch"),
            root.join("journal"),
            root.join("mark"),
        );
        for dir in [
            &policy_dir,
            &registry_dir,
            &scratch_dir,
            &journal_dir,
            &mark_dir,
            &root.join("keys"),
        ] {
            private_dir(dir);
        }
        for key in ["key", "other"] {
            new_key(&root.join("keys").join(key));
        }
        let mut plan: Value = serde_json::from_str(PLAN).unwrap();
        plan["observations"][0]["content_digest"] = json!(hex(OLD_CONTENT));
        plan["artifact_digests"][0]["digest"] = json!(hex(NEW_CONTENT));
        let plan = serde_json::to_vec(&plan).unwrap();
        let mut grant: Value = serde_json::from_str(GRANT).unwrap();
        grant["plan_digest"] = json!(FixturePlan::decode(&plan).unwrap().digest().as_str());
        let lab = Self {
            _serial: serial,
            anchor: TrustAnchor {
                owner_uid: rustix::process::getuid().as_raw(),
                policy_dir,
                registry_dir,
                scratch_dir,
                journal_dir: journal_dir.clone(),
                mark_dir,
                recipes_dir: journal_dir,
                admin_socket: None,
            },
            root,
            plan,
            grant: Vec::new(),
            grant_value: grant,
            signature: Vec::new(),
        };
        let mut lab = lab;
        lab.write_policy(json!({}));
        lab.allow("key");
        private_file(&lab.anchor.policy_dir.join("revocations"), b"");
        lab.write_registry();
        lab.resign("key");
        lab
    }

    fn write_policy(&self, overrides: Value) {
        let grant = &self.grant_value;
        let mut policy = json!({
            "schema_version": 1, "host_id": grant["host_id"], "host_epoch": grant["host_epoch"],
            "profile_digest": grant["profile_digest"], "requester": grant["requester"],
            "requester_uid": 4242, "issuer": grant["issuer"],
            "signer_policy_epoch": grant["signer_policy_epoch"],
            "verifier_sha256": hex(&fs::read(KEYGEN).unwrap()),
        });
        for (key, value) in overrides.as_object().unwrap() {
            policy[key] = value.clone();
        }
        private_file(
            &self.anchor.policy_dir.join("policy.json"),
            &serde_json::to_vec(&policy).unwrap(),
        );
    }

    fn allow(&self, key: &str) {
        let public = fs::read_to_string(self.root.join("keys").join(format!("{key}.pub"))).unwrap();
        let public: Vec<_> = public.split_whitespace().take(2).collect();
        let line = format!(
            "operator_1 namespaces=\"rustiron-plan-v1\" {}\n",
            public.join(" ")
        );
        private_file(
            &self.anchor.policy_dir.join("allowed_signers"),
            line.as_bytes(),
        );
    }

    fn write_registry(&self) {
        let resource = self.anchor.registry_dir.join("fixture_1");
        for generation in ["gen_old", "gen_new"] {
            let dir = resource.join("generations").join(generation);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("content"), format!("{generation} placeholder\n")).unwrap();
        }
        fs::write(resource.join("generations/gen_old/content"), OLD_CONTENT).unwrap();
        fs::write(resource.join("generations/gen_new/content"), NEW_CONTENT).unwrap();
        symlink("generations/gen_old", resource.join("current")).unwrap();
    }

    fn resign(&mut self, key: &str) {
        self.grant = serde_json::to_vec(&self.grant_value).unwrap();
        self.signature = sign(
            &self.root.join("keys").join(key),
            &self.root.join("message"),
            FixtureGrant::decode(&self.grant).unwrap().as_bytes(),
            "rustiron-plan-v1",
        );
    }

    fn request(&self) -> AdmissionRequest<'_> {
        AdmissionRequest {
            peer_uid: 4242,
            plan: &self.plan,
            grant: &self.grant,
            signature: &self.signature,
            operation_id: id("operation_1"),
            idempotency_key: id("retry_1"),
            now: Some(Timestamp::try_from(1200).unwrap()),
        }
    }

    fn admit(&self) -> Result<rustiron_journal::Intent, ExecutorError> {
        admit(&self.anchor, &self.request())
    }

    fn current(&self) -> PathBuf {
        self.anchor.registry_dir.join("fixture_1/current")
    }
}

fn id(value: &str) -> Id {
    Id::try_from(value.to_owned()).unwrap()
}

#[test]
fn admits_signed_bound_plan_with_live_predecessor_and_cleans_scratch() {
    let lab = Lab::new("ok");
    let intent = lab.admit().unwrap();
    assert_eq!(intent.predecessor_generation.as_str(), "gen_old");
    assert_eq!(intent.predecessor_digest.as_str(), hex(OLD_CONTENT));
    assert_eq!(intent.target_generation.as_str(), "gen_new");
    assert_eq!(intent.nonce.as_str(), "nonce_fixture");
    let canonical = FixtureGrant::decode(&lab.grant).unwrap();
    assert_eq!(intent.grant_digest.as_str(), hex(canonical.as_bytes()));
    assert_eq!(fs::read_dir(&lab.anchor.scratch_dir).unwrap().count(), 0);
}

#[test]
fn peer_identity_comes_from_enrollment_not_request() {
    let lab = Lab::new("peer");
    let mut request = lab.request();
    request.peer_uid = 4243;
    assert_eq!(admit(&lab.anchor, &request), Err(ExecutorError::PeerDenied));
}

#[test]
fn signature_failures_deny() {
    let mut lab = Lab::new("sig");
    lab.resign("other");
    assert_eq!(lab.admit(), Err(ExecutorError::SignatureDenied));
    lab.resign("key");
    let signed = lab.grant.clone();
    lab.grant_value["nonce"] = json!("nonce_changed");
    lab.grant = serde_json::to_vec(&lab.grant_value).unwrap();
    assert_eq!(lab.admit(), Err(ExecutorError::SignatureDenied));
    lab.grant = signed;
    let public = fs::read(lab.root.join("keys/key.pub")).unwrap();
    private_file(&lab.anchor.policy_dir.join("revocations"), &public);
    assert_eq!(lab.admit(), Err(ExecutorError::SignatureDenied));
    assert_eq!(fs::read_dir(&lab.anchor.scratch_dir).unwrap().count(), 0);
}

#[test]
fn time_must_be_known_and_inside_grant_window() {
    let lab = Lab::new("time");
    for now in [None, Some(1099), Some(1900)] {
        let mut request = lab.request();
        request.now = now.map(|value| Timestamp::try_from(value).unwrap());
        assert_eq!(admit(&lab.anchor, &request), Err(ExecutorError::TimeDenied));
    }
}

#[test]
fn enrolled_policy_binding_mismatch_denies() {
    let lab = Lab::new("binding");
    lab.write_policy(json!({"host_epoch": "epoch_2"}));
    assert_eq!(lab.admit(), Err(ExecutorError::BindingDenied));
}

#[test]
fn verifier_hash_must_match_enrollment() {
    let lab = Lab::new("verifier");
    lab.write_policy(json!({"verifier_sha256": "0".repeat(64)}));
    assert_eq!(lab.admit(), Err(ExecutorError::Unavailable));
}

#[test]
fn live_registry_must_match_reported_predecessor() {
    let lab = Lab::new("live");
    fs::remove_file(lab.current()).unwrap();
    symlink("generations/gen_new", lab.current()).unwrap();
    assert_eq!(lab.admit(), Err(ExecutorError::PreconditionChanged));
    fs::remove_file(lab.current()).unwrap();
    symlink("generations/gen_old", lab.current()).unwrap();
    let content = lab
        .anchor
        .registry_dir
        .join("fixture_1/generations/gen_old/content");
    fs::write(&content, b"drifted\n").unwrap();
    assert_eq!(lab.admit(), Err(ExecutorError::PreconditionChanged));
}

#[test]
fn registry_links_and_shapes_are_refused() {
    let lab = Lab::new("links");
    for target in [
        "/etc/passwd",
        "generations/../../x",
        "generations/gen_old/content",
        "gen_old",
    ] {
        fs::remove_file(lab.current()).unwrap();
        symlink(target, lab.current()).unwrap();
        assert_eq!(
            lab.admit(),
            Err(ExecutorError::RegistryUnavailable),
            "{target}"
        );
    }
    fs::remove_file(lab.current()).unwrap();
    symlink("generations/gen_old", lab.current()).unwrap();
    let generations = lab.anchor.registry_dir.join("fixture_1/generations");
    fs::rename(generations.join("gen_old"), generations.join("real_old")).unwrap();
    symlink("real_old", generations.join("gen_old")).unwrap();
    assert_eq!(lab.admit(), Err(ExecutorError::AccessDenied));
    fs::remove_file(generations.join("gen_old")).unwrap();
    fs::rename(generations.join("real_old"), generations.join("gen_old")).unwrap();
    let content = generations.join("gen_old/content");
    fs::hard_link(&content, lab.root.join("extra-link")).unwrap();
    assert_eq!(lab.admit(), Err(ExecutorError::AccessDenied));
    fs::remove_file(lab.root.join("extra-link")).unwrap();
    fs::set_permissions(&content, fs::Permissions::from_mode(0o666)).unwrap();
    assert_eq!(lab.admit(), Err(ExecutorError::AccessDenied));
}

#[test]
fn trusted_policy_location_must_be_private_and_unlinked() {
    let mut lab = Lab::new("policy");
    let policy = lab.anchor.policy_dir.join("policy.json");
    fs::set_permissions(&policy, fs::Permissions::from_mode(0o640)).unwrap();
    assert_eq!(lab.admit(), Err(ExecutorError::AccessDenied));
    fs::set_permissions(&policy, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&lab.anchor.policy_dir, fs::Permissions::from_mode(0o750)).unwrap();
    assert_eq!(lab.admit(), Err(ExecutorError::AccessDenied));
    fs::set_permissions(&lab.anchor.policy_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let alias = lab.root.join("policy-alias");
    symlink(&lab.anchor.policy_dir, &alias).unwrap();
    lab.anchor.policy_dir = alias;
    assert_eq!(lab.admit(), Err(ExecutorError::AccessDenied));
    lab.anchor.policy_dir = PathBuf::from("relative/policy");
    assert_eq!(lab.admit(), Err(ExecutorError::AccessDenied));
}

#[test]
fn ancestors_writable_by_others_are_refused() {
    let lab = Lab::new("ancestry");
    fs::set_permissions(&lab.root, fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(lab.admit(), Err(ExecutorError::AccessDenied));
    fs::set_permissions(&lab.root, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(lab.admit().is_ok());
}

#[test]
fn generation_identity_matters_even_with_identical_content() {
    let lab = Lab::new("identity");
    let generations = lab.anchor.registry_dir.join("fixture_1/generations");
    fs::write(generations.join("gen_new/content"), OLD_CONTENT).unwrap();
    fs::remove_file(lab.current()).unwrap();
    symlink("generations/gen_new", lab.current()).unwrap();
    assert_eq!(lab.admit(), Err(ExecutorError::PreconditionChanged));
}

#[test]
fn allowlist_must_name_only_the_enrolled_issuer() {
    let lab = Lab::new("principal");
    let path = lab.anchor.policy_dir.join("allowed_signers");
    let line = fs::read_to_string(&path).unwrap();
    private_file(
        &path,
        line.replacen("operator_1", "operator_2", 1).as_bytes(),
    );
    assert_eq!(lab.admit(), Err(ExecutorError::Unavailable));
    private_file(&path, format!("{line}{line}").as_bytes());
    assert_eq!(lab.admit(), Err(ExecutorError::Unavailable));
}

fn anchor(lab: &Lab) -> TrustAnchor {
    TrustAnchor {
        owner_uid: lab.anchor.owner_uid,
        policy_dir: lab.anchor.policy_dir.clone(),
        registry_dir: lab.anchor.registry_dir.clone(),
        scratch_dir: lab.anchor.scratch_dir.clone(),
        journal_dir: lab.anchor.journal_dir.clone(),
        mark_dir: lab.anchor.mark_dir.clone(),
        recipes_dir: lab.anchor.recipes_dir.clone(),
        admin_socket: None,
    }
}

#[test]
fn submit_consumes_nonce_once_and_repeats_are_status_only() {
    let lab = Lab::new("durable");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    let RecordResult::New(operation) = executor.submit(&lab.request()).unwrap() else {
        panic!("first submission must be new");
    };
    assert_eq!(operation.state, RecordedState::Intent);
    assert!(matches!(
        executor.submit(&lab.request()).unwrap(),
        RecordResult::Existing(_)
    ));
    let mut reused = lab.request();
    reused.operation_id = id("operation_2");
    reused.idempotency_key = id("retry_2");
    assert_eq!(executor.submit(&reused), Err(ExecutorError::ReplayDenied));
    drop(executor);
    let executor = Executor::open(anchor(&lab)).unwrap();
    let stored = executor.status(&id("operation_1")).unwrap().unwrap();
    assert_eq!(stored.state, RecordedState::Intent);
    assert_eq!(stored.intent.nonce.as_str(), "nonce_fixture");
}

#[test]
fn unresolved_intent_blocks_a_fresh_grant() {
    let mut lab = Lab::new("busy");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    executor.submit(&lab.request()).unwrap();
    lab.grant_value["grant_id"] = json!("grant_second");
    lab.grant_value["nonce"] = json!("nonce_second");
    lab.resign("key");
    let mut fresh = lab.request();
    fresh.operation_id = id("operation_2");
    fresh.idempotency_key = id("retry_2");
    assert_eq!(executor.submit(&fresh), Err(ExecutorError::Busy));
}

#[test]
fn denied_admission_records_nothing() {
    let mut lab = Lab::new("nothing");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    lab.resign("other");
    assert_eq!(
        executor.submit(&lab.request()),
        Err(ExecutorError::SignatureDenied)
    );
    assert_eq!(executor.status(&id("operation_1")).unwrap(), None);
    lab.resign("key");
    assert!(matches!(
        executor.submit(&lab.request()).unwrap(),
        RecordResult::New(_)
    ));
}

#[test]
fn clock_rollback_after_intent_is_refused() {
    let mut lab = Lab::new("clock");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    let mut later = lab.request();
    later.now = Some(Timestamp::try_from(1500).unwrap());
    executor.submit(&later).unwrap();
    lab.grant_value["grant_id"] = json!("grant_second");
    lab.grant_value["nonce"] = json!("nonce_second");
    lab.resign("key");
    let mut earlier = lab.request();
    earlier.operation_id = id("operation_2");
    earlier.idempotency_key = id("retry_2");
    assert_eq!(executor.submit(&earlier), Err(ExecutorError::ClockRollback));
}

#[test]
fn journal_lifecycle_refusals() {
    let lab = Lab::new("lifecycle");
    assert_eq!(
        Executor::open(anchor(&lab)).err(),
        Some(ExecutorError::Unavailable)
    );
    drop(Executor::initialize(anchor(&lab)).unwrap());
    assert_eq!(
        Executor::initialize(anchor(&lab)).err(),
        Some(ExecutorError::StateExists)
    );
    lab.write_policy(json!({"host_epoch": "epoch_2"}));
    assert_eq!(
        Executor::open(anchor(&lab)).err(),
        Some(ExecutorError::IdentityMismatch)
    );
    lab.write_policy(json!({}));
    let mut other_owner = anchor(&lab);
    other_owner.owner_uid += 1;
    assert_eq!(
        Executor::open(other_owner).err(),
        Some(ExecutorError::AccessDenied)
    );
    let held = Executor::open(anchor(&lab)).unwrap();
    assert_eq!(
        Executor::open(anchor(&lab)).err(),
        Some(ExecutorError::AccessDenied)
    );
    drop(held);
    fs::set_permissions(&lab.anchor.journal_dir, fs::Permissions::from_mode(0o750)).unwrap();
    assert_eq!(
        Executor::open(anchor(&lab)).err(),
        Some(ExecutorError::AccessDenied)
    );
}

#[test]
fn journal_directory_ancestry_is_checked_by_the_executor() {
    let lab = Lab::new("journal-ancestry");
    let exposed = lab.root.join("exposed");
    private_dir(&exposed.join("journal"));
    fs::set_permissions(&exposed, fs::Permissions::from_mode(0o777)).unwrap();
    let mut misplaced = anchor(&lab);
    misplaced.journal_dir = exposed.join("journal");
    assert_eq!(
        Executor::initialize(misplaced).err(),
        Some(ExecutorError::AccessDenied)
    );
}

/// Run as root on the lab VM: `cargo test -p rustiron-executor -- --ignored`.
#[test]
#[ignore = "requires root; run on the lab VM"]
fn root_executor_records_while_ordinary_journal_refuses_root() {
    assert!(rustix::process::getuid().is_root(), "must run as root");
    let lab = Lab::new("root");
    assert_eq!(lab.anchor.owner_uid, 0);
    let ordinary = lab.root.join("ordinary");
    private_dir(&ordinary);
    assert_eq!(
        rustiron_journal::FixtureJournal::initialize(&ordinary, id("host_lab"), id("epoch_1"))
            .err(),
        Some(rustiron_journal::JournalError::AccessDenied)
    );
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    assert!(matches!(
        executor.submit(&lab.request()).unwrap(),
        RecordResult::New(_)
    ));
    let operation = executor
        .execute(&id("operation_1"), lab.request().now)
        .unwrap();
    assert_eq!(operation.state, RecordedState::Succeeded);
    drop(executor);
    assert_eq!(
        rustiron_journal::FixtureJournal::open(
            &lab.anchor.journal_dir,
            id("host_lab"),
            id("epoch_1")
        )
        .err(),
        Some(rustiron_journal::JournalError::AccessDenied)
    );
    let mut non_root = anchor(&lab);
    non_root.owner_uid = 2003;
    assert_eq!(
        Executor::open(non_root).err(),
        Some(ExecutorError::AccessDenied)
    );
}

fn executed(lab: &Lab) -> (Executor, rustiron_journal::Operation) {
    let mut executor = Executor::initialize(anchor(lab)).unwrap();
    executor.submit(&lab.request()).unwrap();
    let operation = executor
        .execute(&id("operation_1"), lab.request().now)
        .unwrap();
    (executor, operation)
}

fn current_target(lab: &Lab) -> String {
    fs::read_link(lab.current())
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
}

#[test]
fn execute_switches_atomically_and_records_observed_success() {
    let lab = Lab::new("switch");
    let (mut executor, operation) = executed(&lab);
    assert_eq!(operation.state, RecordedState::Succeeded);
    assert_eq!(current_target(&lab), "generations/gen_new");
    let names: Vec<_> = fs::read_dir(lab.anchor.registry_dir.join("fixture_1"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names.len(), 2, "{names:?}");
    assert_eq!(
        executor.execute(&id("operation_1"), lab.request().now),
        Err(ExecutorError::NotAdmitted)
    );
    assert_eq!(current_target(&lab), "generations/gen_new");
}

#[test]
fn restarted_executor_never_executes_and_reconcile_only_observes() {
    let lab = Lab::new("restart");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    executor.submit(&lab.request()).unwrap();
    drop(executor);
    let mut executor = Executor::open(anchor(&lab)).unwrap();
    assert_eq!(
        executor.execute(&id("operation_1"), lab.request().now),
        Err(ExecutorError::NotAdmitted)
    );
    assert_eq!(current_target(&lab), "generations/gen_old");
    let operation = executor.reconcile(&id("operation_1")).unwrap();
    assert_eq!(operation.state, RecordedState::Untouched);
    assert_eq!(current_target(&lab), "generations/gen_old");
}

#[test]
fn reconcile_after_crash_mid_effect_records_reality() {
    let lab = Lab::new("crash");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    executor.submit(&lab.request()).unwrap();
    drop(executor);
    // Simulates a crash after the rename: the effect happened, no outcome recorded.
    fs::remove_file(lab.current()).unwrap();
    symlink("generations/gen_new", lab.current()).unwrap();
    let mut executor = Executor::open(anchor(&lab)).unwrap();
    let operation = executor.reconcile(&id("operation_1")).unwrap();
    assert_eq!(operation.state, RecordedState::Succeeded);
}

#[test]
fn drift_after_admission_blocks_without_effect() {
    let lab = Lab::new("drift");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    executor.submit(&lab.request()).unwrap();
    let old = lab
        .anchor
        .registry_dir
        .join("fixture_1/generations/gen_old/content");
    fs::write(&old, b"drifted\n").unwrap();
    assert_eq!(
        executor.execute(&id("operation_1"), lab.request().now),
        Err(ExecutorError::PreconditionChanged)
    );
    assert_eq!(current_target(&lab), "generations/gen_old");
    let stored = executor.status(&id("operation_1")).unwrap().unwrap();
    assert_eq!(stored.state, RecordedState::NeedsAttention);
}

#[test]
fn target_content_mismatch_refuses_switch_and_records_untouched() {
    let lab = Lab::new("target");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    executor.submit(&lab.request()).unwrap();
    let new = lab
        .anchor
        .registry_dir
        .join("fixture_1/generations/gen_new/content");
    fs::write(&new, b"tampered\n").unwrap();
    assert_eq!(
        executor.execute(&id("operation_1"), lab.request().now),
        Err(ExecutorError::PreconditionChanged)
    );
    assert_eq!(current_target(&lab), "generations/gen_old");
    let stored = executor.status(&id("operation_1")).unwrap().unwrap();
    assert_eq!(stored.state, RecordedState::Untouched);
}

#[test]
fn expired_or_unknown_time_at_effect_records_without_switching() {
    for now in [None, Some(1900)] {
        let lab = Lab::new(&format!("late-{}", now.is_some()));
        let mut executor = Executor::initialize(anchor(&lab)).unwrap();
        executor.submit(&lab.request()).unwrap();
        let now = now.map(|value| Timestamp::try_from(value).unwrap());
        assert_eq!(
            executor.execute(&id("operation_1"), now),
            Err(ExecutorError::TimeDenied)
        );
        assert_eq!(current_target(&lab), "generations/gen_old");
        let stored = executor.status(&id("operation_1")).unwrap().unwrap();
        assert_eq!(stored.state, RecordedState::Untouched);
    }
}

#[test]
fn repointed_predecessor_with_same_content_blocks_switch() {
    let lab = Lab::new("repoint");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    executor.submit(&lab.request()).unwrap();
    let alternate = lab
        .anchor
        .registry_dir
        .join("fixture_1/generations/gen_alt");
    fs::create_dir(&alternate).unwrap();
    fs::write(alternate.join("content"), OLD_CONTENT).unwrap();
    fs::remove_file(lab.current()).unwrap();
    symlink("generations/gen_alt", lab.current()).unwrap();
    assert_eq!(
        executor.execute(&id("operation_1"), lab.request().now),
        Err(ExecutorError::PreconditionChanged)
    );
    assert_eq!(current_target(&lab), "generations/gen_alt");
}

fn socket_round_trip(lab: &Lab, executor: &mut Executor, frame: &[u8]) -> SubmissionReply {
    let path = lab.root.join("run/executor.sock");
    let listener = serve::bind(&path, lab.anchor.owner_uid).unwrap();
    let client_frame = frame.to_vec();
    let client = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + local::DEADLINE;
        let mut stream = std::os::unix::net::UnixStream::connect(&path).unwrap();
        local::write_frame(
            &mut stream,
            &client_frame,
            MAX_REQUEST_BYTES,
            ErrorCode::RequestTooLarge,
            deadline,
        )
        .unwrap();
        let reply = local::read_frame(
            &mut stream,
            MAX_RESPONSE_BYTES,
            ErrorCode::ResponseTooLarge,
            deadline,
        )
        .unwrap();
        fs::remove_file(&path).unwrap();
        serde_json::from_slice(&reply).unwrap()
    });
    let (stream, _) = listener.accept().unwrap();
    assert!(serve::handle(executor, stream));
    client.join().unwrap()
}

fn socket_status_round_trip(lab: &Lab, executor: &mut Executor, frame: &[u8]) -> Value {
    let path = lab.root.join("run/executor.sock");
    let listener = serve::bind(&path, lab.anchor.owner_uid).unwrap();
    let client_frame = frame.to_vec();
    let client = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + local::DEADLINE;
        let mut stream = std::os::unix::net::UnixStream::connect(&path).unwrap();
        local::write_frame(
            &mut stream,
            &client_frame,
            MAX_REQUEST_BYTES,
            ErrorCode::RequestTooLarge,
            deadline,
        )
        .unwrap();
        let reply = local::read_frame(
            &mut stream,
            MAX_RESPONSE_BYTES,
            ErrorCode::ResponseTooLarge,
            deadline,
        )
        .unwrap();
        fs::remove_file(&path).unwrap();
        serde_json::from_slice(&reply).unwrap()
    });
    let (stream, _) = listener.accept().unwrap();
    assert!(serve::handle(executor, stream));
    client.join().unwrap()
}

fn socket_lab(name: &str) -> Lab {
    let lab = Lab::new(name);
    fs::create_dir(lab.root.join("run")).unwrap();
    fs::set_permissions(lab.root.join("run"), fs::Permissions::from_mode(0o755)).unwrap();
    lab
}

/// Real system time is far past the fixture window; re-sign for a fresh one.
fn use_current_window(lab: &mut Lab) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut plan: Value = serde_json::from_slice(&lab.plan).unwrap();
    plan["valid_from"] = json!(now - 10);
    plan["expires_at"] = json!(now + 600);
    plan["compensation"]["valid_until"] = json!(now + 600);
    plan["observations"][0]["observed_at"] = json!(now - 20);
    lab.plan = serde_json::to_vec(&plan).unwrap();
    lab.grant_value["plan_digest"] =
        json!(FixturePlan::decode(&lab.plan).unwrap().digest().as_str());
    lab.grant_value["valid_from"] = json!(now - 10);
    lab.grant_value["expires_at"] = json!(now + 600);
    lab.grant_value["compensation"]["valid_until"] = json!(now + 600);
    lab.resign("key");
}

fn frame(lab: &Lab) -> Vec<u8> {
    encode_submission(
        &id("operation_1"),
        &id("retry_1"),
        &lab.plan,
        &lab.grant,
        std::str::from_utf8(&lab.signature).unwrap(),
    )
    .unwrap()
}

#[test]
fn socket_submission_from_enrolled_peer_executes_and_replays_as_status() {
    let lab = socket_lab("socket");
    let uid = rustix::process::getuid().as_raw();
    lab.write_policy(json!({"requester_uid": uid}));
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    let mut lab = lab;
    use_current_window(&mut lab);
    let first = socket_round_trip(&lab, &mut executor, &frame(&lab));
    assert_eq!(first.error, None, "{first:?}");
    assert_eq!(first.state, Some(OutcomeState::Succeeded));
    assert!(!first.replay);
    assert_eq!(current_target(&lab), "generations/gen_new");
    let again = socket_round_trip(&lab, &mut executor, &frame(&lab));
    assert_eq!(again.state, Some(OutcomeState::Succeeded), "{again:?}");
    assert!(again.replay);
}

#[test]
fn socket_peer_not_enrolled_is_denied_and_records_nothing() {
    let lab = socket_lab("socket-peer");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    let reply = socket_round_trip(&lab, &mut executor, &frame(&lab));
    assert_eq!(reply.error.as_deref(), Some("PEER_DENIED"));
    assert_eq!(reply.state, None);
    assert_eq!(executor.status(&id("operation_1")).unwrap(), None);
}

#[test]
fn socket_malformed_submission_is_invalid() {
    let lab = socket_lab("socket-bad");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    let reply = socket_round_trip(&lab, &mut executor, br#"{"schema_version":1}"#);
    assert_eq!(reply.error.as_deref(), Some("INVALID_REQUEST"));
    assert_eq!(reply.operation_id, None);
}

#[test]
fn socket_status_returns_recorded_intent_without_executing() {
    let lab = socket_lab("status-intent");
    let uid = rustix::process::getuid().as_raw();
    lab.write_policy(json!({"requester_uid": uid}));
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    let mut request = lab.request();
    request.peer_uid = uid;
    executor.submit(&request).unwrap();
    let journal_path = lab.anchor.journal_dir.join("fixture-journal.sqlite");
    let mark_path = lab.anchor.mark_dir.join("admission-mark");
    let journal_before = fs::read(&journal_path).unwrap();
    let mark_before = fs::read(&mark_path).unwrap();
    let query = br#"{"schema_version":1,"request_id":"q1","method":"operation_status","params":{"operation_id":"operation_1"}}"#;
    let response = socket_status_round_trip(&lab, &mut executor, query);
    assert_eq!(response["request_id"], "q1");
    assert_eq!(response["data"]["value"]["operation_id"], "operation_1");
    assert_eq!(response["data"]["value"]["state"], "intent");
    let query = rustiron_contracts::execution::StatusQuery {
        request_id: id("q1"),
        operation_id: id("operation_1"),
    };
    let decoded = rustiron_contracts::execution::decode_status_response(
        &serde_json::to_vec(&response).unwrap(),
        &query,
    )
    .unwrap();
    assert_eq!(decoded.result.unwrap().state, OutcomeState::Intent);
    assert_eq!(current_target(&lab), "generations/gen_old");
    assert_eq!(
        executor.status(&id("operation_1")).unwrap().unwrap().state,
        RecordedState::Intent
    );
    assert_eq!(fs::read(journal_path).unwrap(), journal_before);
    assert_eq!(fs::read(mark_path).unwrap(), mark_before);
}

#[test]
fn socket_status_refuses_unenrolled_peer_without_disclosing_history() {
    let lab = socket_lab("status-peer");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    let query = br#"{"schema_version":1,"request_id":"q1","method":"operation_status","params":{"operation_id":"operation_1"}}"#;
    let response = socket_status_round_trip(&lab, &mut executor, query);
    assert_eq!(response["status"], "error");
    assert_eq!(response["error"]["code"], "UNAUTHORIZED_PEER");
    assert!(response["data"].is_null());
}

#[test]
fn socket_status_reports_absent_operation_as_not_found() {
    let lab = socket_lab("status-missing");
    lab.write_policy(json!({"requester_uid": rustix::process::getuid().as_raw()}));
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    let query = br#"{"schema_version":1,"request_id":"q1","method":"operation_status","params":{"operation_id":"missing"}}"#;
    let response = socket_status_round_trip(&lab, &mut executor, query);
    assert_eq!(response["error"]["code"], "NOT_FOUND");
    assert_eq!(
        response["error"]["message"],
        "Operation not found in the journal."
    );
    assert!(response["data"].is_null());
}

#[test]
fn socket_status_rejects_unsupported_version_with_correlated_error() {
    let lab = socket_lab("status-version");
    lab.write_policy(json!({"requester_uid": rustix::process::getuid().as_raw()}));
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    let query = br#"{"schema_version":2,"request_id":"q1","method":"operation_status","params":{"operation_id":"missing"}}"#;
    let response = socket_status_round_trip(&lab, &mut executor, query);
    assert_eq!(response["request_id"], "q1");
    assert_eq!(response["error"]["code"], "UNSUPPORTED_VERSION");
    let expected = rustiron_contracts::execution::StatusQuery {
        request_id: id("q1"),
        operation_id: id("missing"),
    };
    let decoded = rustiron_contracts::execution::decode_status_response(
        &serde_json::to_vec(&response).unwrap(),
        &expected,
    )
    .unwrap();
    assert_eq!(
        decoded.result.unwrap_err().code(),
        ErrorCode::UnsupportedVersion
    );
}

#[test]
fn socket_status_rechecks_current_enrollment_and_host_epoch() {
    let lab = socket_lab("status-policy");
    let uid = rustix::process::getuid().as_raw();
    lab.write_policy(json!({"requester_uid": uid}));
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    let query = br#"{"schema_version":1,"request_id":"q1","method":"operation_status","params":{"operation_id":"missing"}}"#;
    lab.write_policy(json!({"requester_uid": 4242}));
    let refused = socket_status_round_trip(&lab, &mut executor, query);
    assert_eq!(refused["error"]["code"], "UNAUTHORIZED_PEER");
    lab.write_policy(json!({"requester_uid": uid, "host_epoch": "other_epoch"}));
    let stale = socket_status_round_trip(&lab, &mut executor, query);
    assert_eq!(stale["error"]["code"], "DEPENDENCY_UNAVAILABLE");
}

#[test]
fn socket_status_refuses_a_missing_admission_mark() {
    let lab = socket_lab("status-mark");
    lab.write_policy(json!({"requester_uid": rustix::process::getuid().as_raw()}));
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    fs::remove_file(lab.anchor.mark_dir.join("admission-mark")).unwrap();
    let query = br#"{"schema_version":1,"request_id":"q1","method":"operation_status","params":{"operation_id":"missing"}}"#;
    let response = socket_status_round_trip(&lab, &mut executor, query);
    assert_eq!(response["error"]["code"], "DEPENDENCY_UNAVAILABLE");
    assert!(response["data"].is_null());
}

#[test]
fn malformed_status_query_never_reads_or_mutates_history() {
    let lab = socket_lab("status-malformed");
    lab.write_policy(json!({"requester_uid": rustix::process::getuid().as_raw()}));
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    let query = br#"{"schema_version":1,"request_id":"q1","method":"operation_status","params":{"operation_id":"one","operation_id":"two"}}"#;
    let reply = socket_round_trip(&lab, &mut executor, query);
    assert_eq!(reply.error.as_deref(), Some("INVALID_REQUEST"));
    assert_eq!(executor.status(&id("one")).unwrap(), None);
}

#[test]
fn socket_status_reports_a_quarantined_provision() {
    if rustix::process::getuid().is_root() {
        return;
    }
    let lab = socket_lab("status-provision");
    enroll_provisioning(&lab);
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    let parts = site_request(&lab, "key", "status_provision_nonce");
    assert_eq!(
        executor.provision(&site_admission(&lab, &parts)).err(),
        Some(ExecutorError::StepFailed)
    );
    lab.write_policy(json!({"requester_uid": rustix::process::getuid().as_raw()}));
    let query = br#"{"schema_version":1,"request_id":"q1","method":"operation_status","params":{"operation_id":"site_op_1"}}"#;
    let response = socket_status_round_trip(&lab, &mut executor, query);
    assert_eq!(response["data"]["value"]["state"], "quarantined");
}

#[test]
fn socket_bind_refuses_existing_entries_and_writable_directories() {
    let lab = socket_lab("socket-bind");
    let path = lab.root.join("run/executor.sock");
    fs::write(&path, b"").unwrap();
    assert!(serve::bind(&path, lab.anchor.owner_uid).is_err());
    fs::remove_file(&path).unwrap();
    fs::set_permissions(lab.root.join("run"), fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(
        serve::bind(&path, lab.anchor.owner_uid).err(),
        Some(ExecutorError::AccessDenied)
    );
}

#[test]
fn retry_key_reuse_with_other_bindings_is_replay_denied() {
    let lab = Lab::new("retry-key");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    executor.submit(&lab.request()).unwrap();
    let mut changed = lab.request();
    changed.operation_id = id("operation_other");
    assert_eq!(executor.submit(&changed), Err(ExecutorError::ReplayDenied));
}

#[test]
fn submit_rechecks_live_registry_before_recording() {
    let lab = Lab::new("submit-live");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    fs::remove_file(lab.current()).unwrap();
    symlink("generations/gen_new", lab.current()).unwrap();
    assert_eq!(
        executor.submit(&lab.request()),
        Err(ExecutorError::PreconditionChanged)
    );
    assert_eq!(executor.status(&id("operation_1")).unwrap(), None);
}

/// Run as root on the lab VM with RUSTIRON_SUBMIT_BIN and
/// RUSTIRON_REQUESTER_USER/UID/GID naming an unprivileged requester account.
#[test]
#[ignore = "requires root and a second account; run on the lab VM"]
fn root_executor_serves_distinct_uid_requester_over_socket() {
    assert!(rustix::process::getuid().is_root(), "must run as root");
    let binary = PathBuf::from(std::env::var("RUSTIRON_SUBMIT_BIN").unwrap());
    let user = std::env::var("RUSTIRON_REQUESTER_USER").unwrap();
    let uid: u32 = std::env::var("RUSTIRON_REQUESTER_UID")
        .unwrap()
        .parse()
        .unwrap();
    let mut lab = socket_lab("distinct");
    fs::set_permissions(&lab.root, fs::Permissions::from_mode(0o711)).unwrap();
    lab.write_policy(json!({"requester_uid": uid}));
    use_current_window(&mut lab);
    let run = lab.root.join("run");
    for (name, bytes) in [
        ("plan.json", &lab.plan),
        ("grant.json", &lab.grant),
        ("grant.sig", &lab.signature),
    ] {
        fs::write(run.join(name), bytes).unwrap();
        fs::set_permissions(run.join(name), fs::Permissions::from_mode(0o644)).unwrap();
    }
    fs::copy(&binary, run.join("rustiron-submit")).unwrap();
    fs::set_permissions(
        run.join("rustiron-submit"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    let socket = run.join("executor.sock");
    let listener = serve::bind(&socket, 0).unwrap();
    let gid: u32 = std::env::var("RUSTIRON_REQUESTER_GID")
        .unwrap()
        .parse()
        .unwrap();
    std::os::unix::fs::chown(&socket, None, Some(gid)).unwrap();
    // `nobody` is outside the socket group, so it cannot connect at all.
    let submit_as = |account: &str, operation: &str| {
        Command::new("/usr/sbin/runuser")
            .args(["-u", account, "--"])
            .arg(run.join("rustiron-submit"))
            .arg("--socket")
            .arg(&socket)
            .arg("--plan")
            .arg(run.join("plan.json"))
            .arg("--grant")
            .arg(run.join("grant.json"))
            .arg("--signature")
            .arg(run.join("grant.sig"))
            .args(["--operation-id", operation, "--idempotency-key", operation])
            .env_clear()
            .output()
            .unwrap()
    };
    // `nobody` is outside the socket group, so it cannot connect at all.
    let refused = submit_as("nobody", "operation_nobody");
    assert_eq!(refused.status.code(), Some(7), "{refused:?}");
    assert!(refused.stdout.is_empty());
    let output = std::thread::scope(|scope| {
        let client = scope.spawn(|| submit_as(&user, "operation_1"));
        let (stream, _) = listener.accept().unwrap();
        assert!(serve::handle(&mut executor, stream));
        client.join().unwrap()
    });
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("succeeded"), "{stdout}");
    assert_eq!(current_target(&lab), "generations/gen_new");
    fs::remove_file(&socket).unwrap();
}

fn time(value: u64) -> Option<Timestamp> {
    Some(Timestamp::try_from(value).unwrap())
}

fn repoint(lab: &Lab, target: &str) {
    fs::remove_file(lab.current()).unwrap();
    symlink(target, lab.current()).unwrap();
}

/// Crash after the switch, then the target link is corrupted externally.
fn needs_attention_after_attempt(lab: &Lab) -> Executor {
    let mut executor = Executor::initialize(anchor(lab)).unwrap();
    executor.submit(&lab.request()).unwrap();
    executor.inject_fault(Fault::AfterSwitch);
    assert_eq!(
        executor.execute(&id("operation_1"), lab.request().now),
        Err(ExecutorError::Unavailable)
    );
    drop(executor);
    repoint(lab, "generations/gen_missing");
    let mut executor = Executor::open(anchor(lab)).unwrap();
    let operation = executor.reconcile(&id("operation_1")).unwrap();
    assert_eq!(operation.state, RecordedState::NeedsAttention);
    assert!(operation.effect_attempted);
    executor
}

#[test]
fn crash_before_any_write_reconciles_untouched_and_cannot_compensate() {
    let lab = Lab::new("crash-mark");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    executor.submit(&lab.request()).unwrap();
    executor.inject_fault(Fault::AfterAttemptMark);
    assert_eq!(
        executor.execute(&id("operation_1"), lab.request().now),
        Err(ExecutorError::Unavailable)
    );
    drop(executor);
    let mut executor = Executor::open(anchor(&lab)).unwrap();
    let stored = executor.status(&id("operation_1")).unwrap().unwrap();
    assert_eq!(stored.state, RecordedState::Intent);
    assert!(stored.effect_attempted);
    let operation = executor.reconcile(&id("operation_1")).unwrap();
    assert_eq!(operation.state, RecordedState::Untouched);
    assert_eq!(
        executor.compensate(&id("operation_1"), time(1950)),
        Err(ExecutorError::CompensationDenied)
    );
    assert_eq!(current_target(&lab), "generations/gen_old");
}

#[test]
fn compensation_restores_predecessor_once() {
    let lab = Lab::new("compensate");
    let mut executor = needs_attention_after_attempt(&lab);
    let operation = executor.compensate(&id("operation_1"), time(1950)).unwrap();
    assert_eq!(operation.state, RecordedState::FailedCompensated);
    assert!(operation.compensation_attempted);
    assert_eq!(current_target(&lab), "generations/gen_old");
    assert_eq!(
        executor.compensate(&id("operation_1"), time(1960)),
        Err(ExecutorError::CompensationDenied)
    );
}

#[test]
fn compensation_respects_signed_deadline_and_needs_known_time() {
    let lab = Lab::new("compensate-late");
    let mut executor = needs_attention_after_attempt(&lab);
    assert_eq!(
        executor.compensate(&id("operation_1"), None),
        Err(ExecutorError::TimeDenied)
    );
    assert_eq!(
        executor.compensate(&id("operation_1"), time(2200)),
        Err(ExecutorError::TimeDenied)
    );
    assert_eq!(
        executor.compensate(&id("operation_1"), time(1100)),
        Err(ExecutorError::ClockRollback)
    );
    assert_eq!(current_target(&lab), "generations/gen_missing");
}

#[test]
fn crash_after_the_compensation_switch_is_not_recorded_as_success() {
    let lab = Lab::new("compensate-switched");
    let mut executor = needs_attention_after_attempt(&lab);
    executor.inject_fault(Fault::AfterCompensationSwitch);
    assert_eq!(
        executor.compensate(&id("operation_1"), time(1950)),
        Err(ExecutorError::Unavailable)
    );
    assert_eq!(current_target(&lab), "generations/gen_old");
    drop(executor);
    let mut executor = Executor::open(anchor(&lab)).unwrap();
    assert_eq!(
        executor.status(&id("operation_1")).unwrap().unwrap().state,
        RecordedState::Compensating
    );
    let operation = executor.reconcile(&id("operation_1")).unwrap();
    assert_eq!(operation.state, RecordedState::FailedCompensated);
    assert_ne!(operation.state, RecordedState::Succeeded);
    assert_eq!(
        executor.compensate(&id("operation_1"), time(1960)),
        Err(ExecutorError::CompensationDenied)
    );
}

#[test]
fn crash_during_compensation_never_allows_a_second_attempt() {
    let lab = Lab::new("compensate-crash");
    let mut executor = needs_attention_after_attempt(&lab);
    executor.inject_fault(Fault::AfterCompensationMark);
    assert_eq!(
        executor.compensate(&id("operation_1"), time(1950)),
        Err(ExecutorError::Unavailable)
    );
    drop(executor);
    let mut executor = Executor::open(anchor(&lab)).unwrap();
    assert_eq!(
        executor.status(&id("operation_1")).unwrap().unwrap().state,
        RecordedState::Compensating
    );
    let operation = executor.reconcile(&id("operation_1")).unwrap();
    assert_eq!(operation.state, RecordedState::NeedsAttention);
    assert_eq!(
        executor.compensate(&id("operation_1"), time(1960)),
        Err(ExecutorError::CompensationDenied)
    );
    assert_eq!(current_target(&lab), "generations/gen_missing");
}

#[test]
fn drift_without_attempted_effect_cannot_compensate() {
    let lab = Lab::new("compensate-drift");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    executor.submit(&lab.request()).unwrap();
    repoint(&lab, "generations/gen_missing");
    assert_eq!(
        executor.execute(&id("operation_1"), lab.request().now),
        Err(ExecutorError::PreconditionChanged)
    );
    assert_eq!(
        executor.compensate(&id("operation_1"), time(1950)),
        Err(ExecutorError::CompensationDenied)
    );
    assert_eq!(current_target(&lab), "generations/gen_missing");
}

#[test]
fn compensating_operation_blocks_new_work() {
    let mut lab = Lab::new("compensate-busy");
    let mut executor = needs_attention_after_attempt(&lab);
    executor.inject_fault(Fault::AfterCompensationMark);
    let _ = executor.compensate(&id("operation_1"), time(1850));
    lab.grant_value["grant_id"] = json!("grant_second");
    lab.grant_value["nonce"] = json!("nonce_second");
    lab.resign("key");
    repoint(&lab, "generations/gen_old");
    let mut fresh = lab.request();
    fresh.operation_id = id("operation_2");
    fresh.idempotency_key = id("retry_2");
    fresh.now = time(1860);
    assert_eq!(executor.submit(&fresh), Err(ExecutorError::Busy));
}

#[test]
fn consumed_grant_is_replay_denied_even_after_the_effect_moved_state() {
    let lab = Lab::new("consumed");
    let (mut executor, _) = executed(&lab);
    let mut reused = lab.request();
    reused.operation_id = id("operation_2");
    reused.idempotency_key = id("retry_2");
    assert_eq!(executor.submit(&reused), Err(ExecutorError::ReplayDenied));
}

const SITE_PLAN: &str = include_str!("../../contracts/tests/fixtures/site-plan.json");
const SITE_GRANT: &str = include_str!("../../contracts/tests/fixtures/site-grant.json");

/// A signed site_provision request bound to this lab's enrolled policy.
fn site_request(lab: &Lab, key: &str, nonce: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    site_request_from(lab, SITE_PLAN, key, nonce)
}

/// W341: the default v2 vector (signed 5 GiB / 500,000 inode limits).
fn site_v2_plan() -> String {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../contracts/tests/fixtures/site-plan-v2-vectors.json"
    ))
    .unwrap();
    vectors[0]["plan_input"].as_str().unwrap().to_owned()
}

/// [`site_request`] from another plan template.
fn site_request_from(
    lab: &Lab,
    template: &str,
    key: &str,
    nonce: &str,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut plan: Value = serde_json::from_str(template).unwrap();
    for (field, value) in [
        ("host_id", lab.grant_value["host_id"].clone()),
        ("host_epoch", lab.grant_value["host_epoch"].clone()),
        ("profile_digest", lab.grant_value["profile_digest"].clone()),
        ("requester", lab.grant_value["requester"].clone()),
    ] {
        plan[field] = value;
    }
    plan["recipe_digest"] = json!("e".repeat(64));
    // A site id no host account can already use, so the unprivileged test
    // fails on privilege, not on a collision with real lab sites.
    let site = format!("u{}", std::process::id());
    let host = format!("{site}.example.test");
    plan["site_id"] = json!(site);
    plan["hostname"] = json!(host);
    plan["observations"][0]["site_id"] = json!(site);
    plan["observations"][0]["hostname"] = json!(host);
    let plan_id = plan["plan_id"].clone();
    let plan = serde_json::to_vec(&plan).unwrap();
    let mut grant: Value = serde_json::from_str(SITE_GRANT).unwrap();
    for field in [
        "host_id",
        "host_epoch",
        "profile_digest",
        "requester",
        "issuer",
        "signer_policy_epoch",
    ] {
        grant[field] = lab.grant_value[field].clone();
    }
    grant["plan_digest"] = json!(
        rustiron_contracts::approval::SitePlan::decode(&plan)
            .unwrap()
            .digest()
            .as_str()
    );
    grant["plan_id"] = plan_id;
    grant["nonce"] = json!(nonce);
    grant["site_ids"] = json!([site]);
    grant["grant_id"] = json!(format!("grant_{nonce}"));
    let grant = serde_json::to_vec(&grant).unwrap();
    let canonical = rustiron_contracts::approval::SiteGrant::decode(&grant).unwrap();
    let signature = sign(
        &lab.root.join("keys").join(key),
        &lab.root.join("site-message"),
        canonical.as_bytes(),
        "rustiron-plan-v1",
    );
    (plan, grant, signature)
}

fn enroll_provisioning(lab: &Lab) {
    lab.write_policy(json!({"provisioning": {
        "wordpress_713_sha256": "e".repeat(64),
        "uid_min": 3001, "uid_max": 3099, "category_min": 201, "category_max": 299,
    }}));
}

fn site_admission<'a>(
    lab: &'a Lab,
    parts: &'a (Vec<u8>, Vec<u8>, Vec<u8>),
) -> AdmissionRequest<'a> {
    let mut request = lab.request();
    request.plan = &parts.0;
    request.grant = &parts.1;
    request.signature = &parts.2;
    request.operation_id = id("site_op_1");
    request.idempotency_key = id("site_key_1");
    request
}

#[test]
fn a_crash_after_the_step_intent_does_not_record_the_account_as_done() {
    let lab = Lab::new("site-crash");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    enroll_provisioning(&lab);
    let parts = site_request(&lab, "key", "site_nonce_crash");
    executor.inject_fault(Fault::AfterProvisionStepBegin);
    assert_eq!(
        executor.provision(&site_admission(&lab, &parts)).err(),
        Some(ExecutorError::Unavailable)
    );
    let running = executor
        .provision_status(&id("site_op_1"))
        .unwrap()
        .unwrap();
    assert_eq!(running.state, ProvisionState::Running);
    assert_eq!(running.steps.len(), 1);
    assert_eq!(running.steps[0].state, StepState::Intent);
    drop(executor);
    let mut executor = Executor::open(anchor(&lab)).unwrap();
    let quarantined = executor.quarantine_provision(&id("site_op_1")).unwrap();
    assert_eq!(quarantined.state, ProvisionState::Quarantined);
    assert_eq!(quarantined.steps[0].state, StepState::Intent);
}

/// W190: a new, valid request for a site id or hostname an earlier provision
/// already consumed is a changed precondition, not a replay; an exact repeat
/// of the earlier request still returns its status.
#[test]
fn provision_of_a_consumed_site_is_a_changed_precondition_not_a_replay() {
    let lab = Lab::new("site-consumed");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    enroll_provisioning(&lab);
    let first = site_request(&lab, "key", "site_nonce_first");
    executor.inject_fault(Fault::AfterProvisionStepBegin);
    assert!(executor.provision(&site_admission(&lab, &first)).is_err());
    drop(executor);
    let mut executor = Executor::open(anchor(&lab)).unwrap();
    executor.quarantine_provision(&id("site_op_1")).unwrap();
    let second = site_request(&lab, "key", "site_nonce_second");
    let mut request = site_admission(&lab, &second);
    request.operation_id = id("site_op_2");
    request.idempotency_key = id("site_key_2");
    assert_eq!(
        executor.provision(&request).err(),
        Some(ExecutorError::PreconditionChanged)
    );
    assert_eq!(executor.provision_status(&id("site_op_2")).unwrap(), None);
    assert!(matches!(
        executor.provision(&site_admission(&lab, &first)),
        Ok(rustiron_journal::ProvisionResult::Existing(_))
    ));
    let mut other_op = site_admission(&lab, &first);
    other_op.operation_id = id("site_op_3");
    other_op.idempotency_key = id("site_key_3");
    assert_eq!(
        executor.provision(&other_op).err(),
        Some(ExecutorError::ReplayDenied),
        "the same grant under a new operation is still a replay"
    );
}

#[test]
fn site_provision_requires_enrollment_peer_binding_and_signature() {
    let lab = Lab::new("site-admit");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    let parts = site_request(&lab, "key", "site_nonce_1");
    assert_eq!(
        executor.provision(&site_admission(&lab, &parts)).err(),
        Some(ExecutorError::Unavailable),
        "no provisioning enrollment"
    );
    enroll_provisioning(&lab);
    let mut other_peer = site_admission(&lab, &parts);
    other_peer.peer_uid = 4243;
    assert_eq!(
        executor.provision(&other_peer).err(),
        Some(ExecutorError::PeerDenied)
    );
    let wrong_key = site_request(&lab, "other", "site_nonce_1");
    assert_eq!(
        executor.provision(&site_admission(&lab, &wrong_key)).err(),
        Some(ExecutorError::SignatureDenied)
    );
    lab.write_policy(json!({"provisioning": {
        "wordpress_713_sha256": "f".repeat(64),
        "uid_min": 3001, "uid_max": 3099, "category_min": 201, "category_max": 299,
    }}));
    assert_eq!(
        executor.provision(&site_admission(&lab, &parts)).err(),
        Some(ExecutorError::BindingDenied),
        "recipe digest must match enrollment"
    );
    lab.write_policy(json!({"provisioning": {
        "wordpress_713_sha256": "e".repeat(64),
        "uid_min": 10, "uid_max": 20, "category_min": 201, "category_max": 299,
    }}));
    assert_eq!(
        executor.provision(&site_admission(&lab, &parts)).err(),
        Some(ExecutorError::Unavailable),
        "system id ranges are refused"
    );
    // W335: enrolled quota limits outside the fixed bounds, or with an
    // unknown member, refuse the enrollment before any intent.
    for quota in [
        json!({"block_hard_kib": 1, "inode_hard": 500_000}),
        json!({"block_hard_kib": 5_242_880, "inode_hard": 1}),
        json!({"block_hard_kib": 5_242_880, "inode_hard": 500_000, "soft": 1}),
    ] {
        lab.write_policy(json!({"provisioning": {
            "wordpress_713_sha256": "e".repeat(64),
            "uid_min": 3001, "uid_max": 3099, "category_min": 201, "category_max": 299,
            "quota": quota,
        }}));
        assert_eq!(
            executor.provision(&site_admission(&lab, &parts)).err(),
            Some(ExecutorError::Unavailable),
            "quota {quota} is refused"
        );
    }
    assert_eq!(executor.provision_status(&id("site_op_1")).unwrap(), None);
}

/// W341: a v2 plan's signed limits bind only under an enrolled quota that
/// is at least as large; every refusal comes before any intent.
#[test]
fn v2_site_limits_bind_only_within_the_enrolled_quota() {
    let lab = Lab::new("site-v2-quota");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    let parts = site_request_from(&lab, &site_v2_plan(), "key", "site_nonce_v2");
    let provisioning = |quota: Option<Value>| {
        let mut enrolled = json!({
            "wordpress_713_sha256": "e".repeat(64),
            "uid_min": 3001, "uid_max": 3099, "category_min": 201, "category_max": 299,
        });
        if let Some(quota) = quota {
            enrolled["quota"] = quota;
        }
        lab.write_policy(json!({ "provisioning": enrolled }));
    };
    for (quota, why) in [
        (None, "no enrolled quota"),
        (
            Some(json!({"block_hard_kib": 5_242_879, "inode_hard": 500_000})),
            "block limit above the cap",
        ),
        (
            Some(json!({"block_hard_kib": 5_242_880, "inode_hard": 499_999})),
            "inode limit above the cap",
        ),
    ] {
        provisioning(quota);
        assert_eq!(
            executor.provision(&site_admission(&lab, &parts)).err(),
            Some(ExecutorError::BindingDenied),
            "{why}"
        );
        assert_eq!(executor.provision_status(&id("site_op_1")).unwrap(), None);
    }
    provisioning(Some(
        json!({"block_hard_kib": 5_242_880, "inode_hard": 500_000}),
    ));
    executor.inject_fault(Fault::AfterProvisionStepBegin);
    assert_eq!(
        executor.provision(&site_admission(&lab, &parts)).err(),
        Some(ExecutorError::Unavailable),
        "admitted; the fault stops after the first intent"
    );
    let running = executor
        .provision_status(&id("site_op_1"))
        .unwrap()
        .unwrap();
    assert_eq!(running.state, ProvisionState::Running);
    assert_eq!(running.steps[0].step, ProvisionStep::Account);
}

#[test]
fn unprivileged_provision_fails_at_the_first_step_and_is_quarantined() {
    if rustix::process::getuid().is_root() {
        return;
    }
    let lab = Lab::new("site-quarantine");
    enroll_provisioning(&lab);
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    let parts = site_request(&lab, "key", "site_nonce_2");
    assert_eq!(
        executor.provision(&site_admission(&lab, &parts)).err(),
        Some(ExecutorError::StepFailed)
    );
    let stored = executor
        .provision_status(&id("site_op_1"))
        .unwrap()
        .unwrap();
    assert_eq!(stored.state, rustiron_journal::ProvisionState::Quarantined);
    assert_eq!(stored.steps.len(), 1, "nothing after the failed step ran");
    assert_eq!(stored.steps[0].state, rustiron_journal::StepState::Failed);
    let rustiron_journal::ProvisionResult::Existing(again) =
        executor.provision(&site_admission(&lab, &parts)).unwrap()
    else {
        panic!("an exact repeat must be status only");
    };
    assert_eq!(again.state, rustiron_journal::ProvisionState::Quarantined);
    assert_eq!(again.steps.len(), 1);
}

// Review F-01: an admission high-water mark outside the journal directory.

const JOURNAL_FILE: &str = "fixture-journal.sqlite";

fn mark_text(lab: &Lab) -> String {
    fs::read_to_string(lab.anchor.mark_dir.join("admission-mark")).unwrap()
}

#[test]
fn a_restored_older_journal_is_refused_before_any_replay() {
    let lab = Lab::new("rollback");
    drop(Executor::initialize(anchor(&lab)).unwrap());
    let journal = lab.anchor.journal_dir.join(JOURNAL_FILE);
    let before = fs::read(&journal).unwrap();
    let mut executor = Executor::open(anchor(&lab)).unwrap();
    executor.submit(&lab.request()).unwrap();
    let operation = executor
        .execute(&id("operation_1"), lab.request().now)
        .unwrap();
    assert_eq!(operation.state, RecordedState::Succeeded);
    drop(executor);
    assert!(mark_text(&lab).ends_with("\n1\n"), "{}", mark_text(&lab));
    private_file(&journal, &before);
    assert_eq!(
        Executor::open(anchor(&lab)).err(),
        Some(ExecutorError::JournalRollback)
    );
    assert_eq!(
        Executor::seal_admission_mark(anchor(&lab)).err(),
        Some(ExecutorError::StateExists),
        "an existing mark is never lowered"
    );
    assert_eq!(
        Executor::initialize(anchor(&lab)).err(),
        Some(ExecutorError::JournalRollback),
        "a fresh journal in the same epoch would forget consumed grants"
    );
}

#[test]
fn a_crash_between_the_journal_commit_and_the_mark_update_is_accepted() {
    let lab = Lab::new("mark-gap");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    let zero = mark_text(&lab);
    assert!(matches!(
        executor.submit(&lab.request()).unwrap(),
        RecordResult::New(_)
    ));
    drop(executor);
    // The journal committed the admission; the mark still says 0.
    private_file(&lab.anchor.mark_dir.join("admission-mark"), zero.as_bytes());
    let executor = Executor::open(anchor(&lab)).unwrap();
    assert!(mark_text(&lab).ends_with("\n1\n"), "the mark caught up");
    assert_eq!(
        executor.status(&id("operation_1")).unwrap().unwrap().state,
        RecordedState::Intent
    );
}

#[test]
fn a_missing_mark_is_refused_until_sealed_once() {
    let lab = Lab::new("mark-missing");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    executor.submit(&lab.request()).unwrap();
    drop(executor);
    fs::remove_file(lab.anchor.mark_dir.join("admission-mark")).unwrap();
    assert_eq!(
        Executor::open(anchor(&lab)).err(),
        Some(ExecutorError::JournalRollback)
    );
    assert_eq!(Executor::seal_admission_mark(anchor(&lab)), Ok(1));
    assert_eq!(
        Executor::seal_admission_mark(anchor(&lab)).err(),
        Some(ExecutorError::StateExists)
    );
    Executor::open(anchor(&lab)).unwrap();
    let mut exposed = fs::metadata(lab.anchor.mark_dir.join("admission-mark"))
        .unwrap()
        .permissions();
    assert_eq!(exposed.mode() & 0o777, 0o600);
    exposed.set_mode(0o644);
    fs::set_permissions(lab.anchor.mark_dir.join("admission-mark"), exposed).unwrap();
    assert_eq!(
        Executor::open(anchor(&lab)).err(),
        Some(ExecutorError::AccessDenied)
    );
}

#[test]
fn epoch_rotation_clears_the_fence_and_old_grants_stay_refused() {
    let lab = Lab::new("mark-rotation");
    drop(Executor::initialize(anchor(&lab)).unwrap());
    let journal = lab.anchor.journal_dir.join(JOURNAL_FILE);
    let before = fs::read(&journal).unwrap();
    let mut executor = Executor::open(anchor(&lab)).unwrap();
    executor.submit(&lab.request()).unwrap();
    drop(executor);
    private_file(&journal, &before);
    assert_eq!(
        Executor::open(anchor(&lab)).err(),
        Some(ExecutorError::JournalRollback)
    );
    // Rotation: archive the journal directory's contents, re-enroll, initialize.
    let archive = lab.root.join("archive");
    private_dir(&archive);
    for entry in fs::read_dir(&lab.anchor.journal_dir).unwrap() {
        let entry = entry.unwrap();
        fs::rename(entry.path(), archive.join(entry.file_name())).unwrap();
    }
    lab.write_policy(json!({"host_epoch": "epoch_2"}));
    let mut rotated = Executor::initialize(anchor(&lab)).unwrap();
    assert!(mark_text(&lab).contains("\nepoch_2\n0\n"));
    assert_eq!(
        rotated.submit(&lab.request()).err(),
        Some(ExecutorError::BindingDenied),
        "a grant for the old epoch is refused"
    );
}

// W184: concurrent reading under limits, with one processing thread.

fn spawn_server(lab: &Lab, executor: Executor, limits: serve::Limits) -> PathBuf {
    let path = lab.root.join("run/executor.sock");
    let listener = serve::bind(&path, lab.anchor.owner_uid).unwrap();
    std::thread::spawn(move || {
        let mut executor = executor;
        let _ = serve::serve_with(&mut executor, &listener, limits);
    });
    path
}

fn ask(path: &std::path::Path, frame: &[u8]) -> Value {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut stream = std::os::unix::net::UnixStream::connect(path).unwrap();
    // A refused connection may already be closed for writing.
    let _ = local::write_frame(
        &mut stream,
        frame,
        MAX_REQUEST_BYTES,
        ErrorCode::RequestTooLarge,
        deadline,
    );
    let reply = local::read_frame(
        &mut stream,
        MAX_RESPONSE_BYTES,
        ErrorCode::ResponseTooLarge,
        deadline,
    )
    .unwrap();
    serde_json::from_slice(&reply).unwrap()
}

fn idle(path: &std::path::Path, count: usize) -> Vec<std::os::unix::net::UnixStream> {
    let streams: Vec<_> = (0..count)
        .map(|_| std::os::unix::net::UnixStream::connect(path).unwrap())
        .collect();
    std::thread::sleep(std::time::Duration::from_millis(200));
    streams
}

const STATUS_Q: &[u8] = br#"{"schema_version":1,"request_id":"q1","method":"operation_status","params":{"operation_id":"operation_1"}}"#;

fn status_lab(name: &str) -> (Lab, Executor) {
    let lab = socket_lab(name);
    let uid = rustix::process::getuid().as_raw();
    lab.write_policy(json!({"requester_uid": uid}));
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    let mut request = lab.request();
    request.peer_uid = uid;
    executor.submit(&request).unwrap();
    (lab, executor)
}

#[test]
fn idle_connections_ahead_do_not_delay_a_request() {
    let (lab, executor) = status_lab("idle-ahead");
    let path = spawn_server(
        &lab,
        executor,
        serve::Limits {
            total: 32,
            per_peer: 4,
        },
    );
    let _idle = idle(&path, 3);
    let started = std::time::Instant::now();
    let reply = ask(&path, STATUS_Q);
    let took = started.elapsed();
    assert_eq!(reply["data"]["value"]["state"], "intent", "{reply}");
    assert!(took < std::time::Duration::from_secs(1), "took {took:?}");
}

#[test]
fn per_peer_read_limit_refuses_at_once_and_frees_on_close() {
    let (lab, executor) = status_lab("per-peer");
    let path = spawn_server(
        &lab,
        executor,
        serve::Limits {
            total: 32,
            per_peer: 2,
        },
    );
    let held = idle(&path, 2);
    let started = std::time::Instant::now();
    let refused = ask(&path, STATUS_Q);
    assert_eq!(
        refused["error"], "EXECUTOR_DEPENDENCY_UNAVAILABLE",
        "{refused}"
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    drop(held);
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert_eq!(ask(&path, STATUS_Q)["data"]["value"]["state"], "intent");
}

#[test]
fn global_read_limit_refuses_at_once_and_frees_on_close() {
    let (lab, executor) = status_lab("global");
    let path = spawn_server(
        &lab,
        executor,
        serve::Limits {
            total: 2,
            per_peer: 8,
        },
    );
    let held = idle(&path, 2);
    let started = std::time::Instant::now();
    let refused = ask(&path, STATUS_Q);
    assert_eq!(
        refused["error"], "EXECUTOR_DEPENDENCY_UNAVAILABLE",
        "{refused}"
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    drop(held);
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert_eq!(ask(&path, STATUS_Q)["data"]["value"]["state"], "intent");
}

#[test]
fn concurrent_identical_submissions_execute_once() {
    let lab = socket_lab("one-writer");
    let uid = rustix::process::getuid().as_raw();
    lab.write_policy(json!({"requester_uid": uid}));
    let executor = Executor::initialize(anchor(&lab)).unwrap();
    let mut lab = lab;
    use_current_window(&mut lab);
    let submission = frame(&lab);
    let path = spawn_server(
        &lab,
        executor,
        serve::Limits {
            total: 32,
            per_peer: 16,
        },
    );
    let replies: Vec<Value> = (0..8)
        .map(|_| {
            let (path, submission) = (path.clone(), submission.clone());
            std::thread::spawn(move || ask(&path, &submission))
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|client| client.join().unwrap())
        .collect();
    let fresh = replies.iter().filter(|r| r["replay"] == false).count();
    assert_eq!(fresh, 1, "{replies:?}");
    for reply in &replies {
        assert_eq!(reply["state"], "succeeded", "{reply}");
    }
    assert_eq!(current_target(&lab), "generations/gen_new");
}

/// W187: a correctly signed capture for a site this journal never provisioned
/// (or did not provision successfully) is refused as a changed precondition
/// before credentials or any effect are looked at, exactly like a restore
/// probe; nothing is journaled, and it is not reported as a retryable outage.
#[test]
fn capture_of_a_site_without_a_succeeded_provision_is_refused_before_intent() {
    let mut lab = Lab::new("capture-unprovisioned");
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/tests/fixtures");
    lab.plan = fs::read(fixtures.join("capture-plan.json")).unwrap();
    lab.grant_value =
        serde_json::from_slice(&fs::read(fixtures.join("capture-grant.json")).unwrap()).unwrap();
    lab.write_policy(
        json!({"provisioning": {"wordpress_713_sha256": "d".repeat(64),
        "uid_min": 3001, "uid_max": 3099, "category_min": 201, "category_max": 299},
        "backup": {"destination_id": "lab_pc_store",
        "repository_base": "s3:http://127.0.0.1:9000/synthetic/sites",
        "store_address": "127.0.0.1", "retention_days": 30}}),
    );
    lab.grant = serde_json::to_vec(&lab.grant_value).unwrap();
    lab.signature = sign(
        &lab.root.join("keys/key"),
        &lab.root.join("message"),
        rustiron_contracts::CanonicalObject::decode(&lab.grant)
            .unwrap()
            .as_bytes(),
        "rustiron-plan-v1",
    );
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    assert_eq!(
        executor.backup_capture(&lab.request()).map(|_| ()),
        Err(ExecutorError::PreconditionChanged)
    );
    assert_eq!(executor.capture_status(&id("operation_1")).unwrap(), None);
    assert_eq!(fs::read_dir(&lab.anchor.scratch_dir).unwrap().count(), 0);
    // W366: the lab build has no unclaimed settlement; its reconcile
    // already records a found tag. The product build names no capture.
    assert_eq!(
        executor.settle_capture_unclaimed(&id("operation_1")).err(),
        Some(if cfg!(rustiron_profile = "product") {
            ExecutorError::NotAdmitted
        } else {
            ExecutorError::InvalidRequest
        })
    );
}

// ---- W214 (B10): real power-loss cut points (SIGKILL of a child process) ----

const CUT_ROOT: &str = "RI_W214_CUT_ROOT";

fn anchor_at(root: &std::path::Path) -> TrustAnchor {
    TrustAnchor {
        owner_uid: rustix::process::getuid().as_raw(),
        policy_dir: root.join("policy"),
        registry_dir: root.join("registry"),
        scratch_dir: root.join("scratch"),
        journal_dir: root.join("journal"),
        mark_dir: root.join("mark"),
        recipes_dir: root.join("journal"),
        admin_socket: None,
    }
}

/// Child half: submit, execute and compensate one operation against the lab
/// at `$RI_W214_CUT_ROOT`, reading the signed request the parent wrote.
#[test]
#[ignore = "child process of power_loss_at_any_point_never_replays_or_misreports"]
fn w214_power_loss_child() {
    let Ok(root) = std::env::var(CUT_ROOT) else {
        return;
    };
    let root = PathBuf::from(root);
    let read = |name: &str| fs::read(root.join(name)).unwrap();
    let (plan, grant, signature) = (read("req.plan"), read("req.grant"), read("req.sig"));
    let request = AdmissionRequest {
        peer_uid: 4242,
        plan: &plan,
        grant: &grant,
        signature: &signature,
        operation_id: id("operation_1"),
        idempotency_key: id("retry_1"),
        now: time(1200),
    };
    let mut executor = Executor::open(anchor_at(&root)).unwrap();
    executor.submit(&request).unwrap();
    executor.execute(&id("operation_1"), time(1200)).unwrap();
    let _ = executor.compensate(&id("operation_1"), time(1950));
    fs::write(root.join("child.done"), b"").unwrap();
}

fn run_child(root: &std::path::Path, kill_after: Option<std::time::Duration>) -> bool {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "w214_power_loss_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CUT_ROOT, root)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    if let Some(delay) = kill_after {
        let start = std::time::Instant::now();
        while start.elapsed() < delay {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::hint::spin_loop();
        }
        let _ = child.kill(); // SIGKILL: no destructors, no journal close
    }
    child.wait().unwrap();
    root.join("child.done").exists()
}

fn wait_for_writer_lease(lab: &Lab, cut: u32) {
    let lock = fs::File::open(lab.anchor.journal_dir.join("writer.lock")).unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return,
            Err(rustix::io::Errno::AGAIN) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("cut {cut}: writer lease did not clear: {error}"),
        }
    }
}

#[test]
fn power_loss_at_any_point_never_replays_or_misreports() {
    let mut seen = std::collections::BTreeMap::<String, u32>::new();
    let mut full = std::time::Duration::ZERO;
    for cut in 0..=72u32 {
        let lab = Lab::new("w214cut");
        drop(Executor::initialize(anchor(&lab)).unwrap());
        fs::write(lab.root.join("req.plan"), &lab.plan).unwrap();
        fs::write(lab.root.join("req.grant"), &lab.grant).unwrap();
        fs::write(lab.root.join("req.sig"), &lab.signature).unwrap();
        let kill_after = if cut == 0 {
            None
        } else {
            // Startup dominates the child run; spread the cuts over its last 60%.
            Some(full.mul_f64(0.4 + 0.65 * f64::from(cut) / 72.0))
        };
        let started = std::time::Instant::now();
        let done = run_child(&lab.root, kill_after);
        if cut == 0 {
            assert!(done, "uncut child must finish");
            full = started.elapsed();
        }
        // A verifier fork can hold the lease after SIGKILL until exec closes it.
        wait_for_writer_lease(&lab, cut);
        let mut executor = Executor::open(anchor(&lab))
            .unwrap_or_else(|error| panic!("cut {cut}: reopen refused: {error:?}"));
        let link = current_target(&lab);
        let state = match executor.status(&id("operation_1")).unwrap() {
            None => {
                assert_eq!(
                    link, "generations/gen_old",
                    "cut {cut}: no record but link moved"
                );
                "none".to_owned()
            }
            Some(_) => {
                let operation = executor.reconcile(&id("operation_1")).unwrap();
                let want = match operation.state {
                    RecordedState::Succeeded => "generations/gen_new",
                    RecordedState::Untouched | RecordedState::FailedCompensated => {
                        "generations/gen_old"
                    }
                    other => panic!("cut {cut}: unresolved after reconcile: {other:?} link {link}"),
                };
                assert_eq!(link, want, "cut {cut}: {:?}", operation.state);
                // The consumed grant is never admitted as new again.
                assert!(
                    matches!(
                        executor.submit(&lab.request()),
                        Ok(RecordResult::Existing(_))
                    ),
                    "cut {cut}: replay admitted"
                );
                format!("{:?}", operation.state)
            }
        };
        *seen.entry(state).or_default() += 1;
    }
    eprintln!("w214 cut outcomes: {seen:?} (full run {full:?})");
}

/// W483-F1 (P06): `observe` says whether the installed verifier still has
/// the enrolled digest; after a replacement, signed requests are refused.
#[test]
fn observe_reports_a_changed_signature_verifier() {
    let lab = Lab::new("verifier-fact");
    let (executor, _) = executed(&lab);
    drop(executor);
    let observation = Executor::observe(&lab.anchor).unwrap();
    assert_eq!(
        observation["host"]["signature_verifier"],
        json!({"matches_enrollment": true})
    );
    lab.write_policy(json!({"verifier_sha256": "0".repeat(64)}));
    let observation = Executor::observe(&lab.anchor).unwrap();
    assert_eq!(
        observation["host"]["signature_verifier"],
        json!({"matches_enrollment": false})
    );
}

/// W396 (D-045): `observe` shows the exact canonical plan and grant bytes of
/// each admission as the journal stored them, with the verified signer facts.
/// The plan bytes hash to the recorded plan digest with the domain framing,
/// and the grant bytes hash to the recorded grant digest. The detached
/// signature and the key material never appear.
#[test]
fn observe_shows_the_exact_signed_bytes_of_an_admission() {
    let lab = Lab::new("signed-bytes");
    let (executor, _) = executed(&lab);
    drop(executor);
    let observation = Executor::observe(&lab.anchor).unwrap();
    let admissions = observation["admissions"].as_array().unwrap();
    assert_eq!(admissions.len(), 1);
    let admission = &admissions[0];
    let plan = FixturePlan::decode(&lab.plan).unwrap();
    let grant = FixtureGrant::decode(&lab.grant).unwrap();
    let grant_sha256 = hex(grant.as_bytes());
    assert_eq!(admission["operation_id"], "operation_1");
    assert_eq!(admission["kind"], "operation");
    assert_eq!(admission["plan_digest"], plan.digest().as_str());
    assert_eq!(admission["grant_digest"], grant_sha256.as_str());
    let signed = &admission["signed"];
    assert_eq!(signed["issuer"], "operator_1");
    assert_eq!(
        signed["signer_policy_epoch"],
        lab.grant_value["signer_policy_epoch"]
    );
    assert_eq!(signed["verification"], "sshsig_verified");
    assert_eq!(signed["namespace"], "rustiron-plan-v1");
    assert_eq!(signed["plan"]["sha256"], hex(plan.as_bytes()).as_str());
    assert_eq!(signed["plan"]["bytes"], plan.as_bytes().len());
    assert_eq!(signed["grant"]["sha256"], grant_sha256.as_str());
    assert_eq!(signed["grant"]["bytes"], grant.as_bytes().len());
    let objects = &observation["signed_objects"];
    let text = |sha: &Value| {
        objects[sha.as_str().unwrap()]
            .as_str()
            .unwrap()
            .as_bytes()
            .to_vec()
    };
    assert_eq!(text(&signed["plan"]["sha256"]), plan.as_bytes());
    assert_eq!(text(&signed["grant"]["sha256"]), grant.as_bytes());
    let serialized = observation.to_string();
    assert!(!serialized.contains("SSH SIGNATURE"));
    let public = fs::read_to_string(lab.root.join("keys").join("key.pub")).unwrap();
    let key = public.split_whitespace().nth(1).unwrap();
    assert!(!serialized.contains(key));
}

/// W332: a refused lab-verb submission that names an existing operation
/// gives a peer outside the enrolled requester no stored status (the W329
/// product rule, applied to every verb).
#[test]
fn a_refused_lab_verb_shows_no_stored_status_to_another_peer() {
    let lab = socket_lab("w332-peer");
    let uid = rustix::process::getuid().as_raw();
    lab.write_policy(json!({"requester_uid": uid}));
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    let mut lab = lab;
    use_current_window(&mut lab);
    let stored = socket_round_trip(&lab, &mut executor, &frame(&lab));
    assert_eq!(stored.state, Some(OutcomeState::Succeeded), "{stored:?}");

    lab.write_policy(json!({"requester_uid": uid.wrapping_add(1)}));
    let verbs: [(&str, &str, &str); 5] = [
        ("eject", W332_EJECT_PLAN, W332_EJECT_GRANT),
        ("ols", W332_OLS_PLAN, W332_OLS_GRANT),
        ("capture", W332_CAPTURE_PLAN, W332_CAPTURE_GRANT),
        ("probe", W332_PROBE_PLAN, W332_PROBE_GRANT),
        ("site", SITE_PLAN, SITE_GRANT),
    ];
    for (verb, plan, grant) in verbs {
        let submission = encode_submission(
            &id("operation_1"),
            &id("retry_w332"),
            plan.trim().as_bytes(),
            grant.trim().as_bytes(),
            std::str::from_utf8(&lab.signature).unwrap(),
        )
        .unwrap();
        let reply = socket_round_trip(&lab, &mut executor, &submission);
        assert!(reply.error.is_some(), "{verb}: {reply:?}");
        assert_eq!(reply.state, None, "{verb}: a wrong peer saw stored status");
    }
}

const W332_EJECT_PLAN: &str = include_str!("../../contracts/tests/fixtures/eject-plan.json");
const W332_EJECT_GRANT: &str = include_str!("../../contracts/tests/fixtures/eject-grant.json");
const W332_OLS_PLAN: &str = include_str!("../../contracts/tests/fixtures/ols-plan.json");
const W332_OLS_GRANT: &str = include_str!("../../contracts/tests/fixtures/ols-grant.json");
const W332_CAPTURE_PLAN: &str = include_str!("../../contracts/tests/fixtures/capture-plan.json");
const W332_CAPTURE_GRANT: &str = include_str!("../../contracts/tests/fixtures/capture-grant.json");
const W332_PROBE_PLAN: &str = include_str!("../../contracts/tests/fixtures/probe-plan.json");
const W332_PROBE_GRANT: &str = include_str!("../../contracts/tests/fixtures/probe-grant.json");

/// W377 (B06): `capture-reconcile --settle-unclaimed` (W366) is a product
/// path. A lab build refuses it for an existing capture ID, an unknown ID
/// and a fixture operation alike, and writes nothing.
#[test]
fn w377_a_lab_build_refuses_unclaimed_settlement_without_writes() {
    let lab = Lab::new("w377-settle");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    executor.submit(&lab.request()).unwrap();
    let journal = lab.anchor.journal_dir.join(JOURNAL_FILE);
    let before = (fs::read(&journal).unwrap(), mark_text(&lab));
    for operation in ["operation_1", "op_w377_unknown"] {
        assert_eq!(
            executor.settle_capture_unclaimed(&id(operation)).err(),
            Some(ExecutorError::InvalidRequest),
            "{operation}"
        );
    }
    assert_eq!((fs::read(&journal).unwrap(), mark_text(&lab)), before);
}

// ---- W380 (B06, F1): the remaining verbs under a re-enrolled epoch ----

/// The journal bytes and the admission mark, for a byte-identical check.
fn w380_state(lab: &Lab) -> (Vec<u8>, String) {
    (
        fs::read(lab.anchor.journal_dir.join(JOURNAL_FILE)).unwrap(),
        mark_text(lab),
    )
}

/// Moves the plan and the grant of `lab` to `epoch` and signs again.
/// `digest` is the plan digest of the verb's plan type.
type W380Digest = fn(&[u8]) -> String;

fn w380_epoch(lab: &mut Lab, epoch: &str, digest: W380Digest) {
    let mut plan: Value = serde_json::from_slice(&lab.plan).unwrap();
    plan["host_epoch"] = json!(epoch);
    lab.plan = serde_json::to_vec(&plan).unwrap();
    lab.grant_value["host_epoch"] = json!(epoch);
    lab.grant_value["plan_digest"] = json!(digest(&lab.plan));
    lab.grant = serde_json::to_vec(&lab.grant_value).unwrap();
    lab.signature = sign(
        &lab.root.join("keys/key"),
        &lab.root.join("message"),
        rustiron_contracts::CanonicalObject::decode(&lab.grant)
            .unwrap()
            .as_bytes(),
        "rustiron-plan-v1",
    );
}

fn w380_fixture_digest(plan: &[u8]) -> String {
    FixturePlan::decode(plan)
        .unwrap()
        .digest()
        .as_str()
        .to_owned()
}

fn w380_capture_digest(plan: &[u8]) -> String {
    rustiron_contracts::approval::CapturePlan::decode(plan)
        .unwrap()
        .digest()
        .as_str()
        .to_owned()
}

fn w380_probe_digest(plan: &[u8]) -> String {
    rustiron_contracts::approval::ProbePlan::decode(plan)
        .unwrap()
        .digest()
        .as_str()
        .to_owned()
}

/// F1 for the fixture verb: a policy re-enrolled to another epoch while the
/// executor keeps the epoch_1 journal open is `JOURNAL_IDENTITY_MISMATCH`
/// before intent, not the journal's `REPLAY_DENIED`. The journal and the
/// mark stay byte-identical. Control: the epoch_1 request is admitted.
#[test]
fn w380_the_fixture_verb_under_a_re_enrolled_epoch_is_an_identity_mismatch() {
    let mut lab = Lab::new("w380-fixture-epoch");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    let before = w380_state(&lab);
    w380_epoch(&mut lab, "epoch_2", w380_fixture_digest);
    lab.write_policy(json!({}));
    assert_eq!(
        executor.submit(&lab.request()).err(),
        Some(ExecutorError::IdentityMismatch)
    );
    assert_eq!(executor.status(&id("operation_1")).unwrap(), None);
    assert_eq!(w380_state(&lab), before);
    w380_epoch(&mut lab, "epoch_1", w380_fixture_digest);
    lab.write_policy(json!({}));
    assert!(matches!(
        executor.submit(&lab.request()),
        Ok(RecordResult::New(_))
    ));
}

/// F1 for `site_provision`: the same refusal before intent, with no
/// provision row and no step.
#[test]
fn w380_a_provision_under_a_re_enrolled_epoch_is_an_identity_mismatch() {
    let mut lab = Lab::new("w380-site-epoch");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    let before = w380_state(&lab);
    lab.grant_value["host_epoch"] = json!("epoch_2");
    enroll_provisioning(&lab);
    let parts = site_request(&lab, "key", "site_nonce_w380");
    assert_eq!(
        executor.provision(&site_admission(&lab, &parts)).err(),
        Some(ExecutorError::IdentityMismatch)
    );
    assert_eq!(executor.provision_status(&id("site_op_1")).unwrap(), None);
    assert_eq!(w380_state(&lab), before);
    // Control: the epoch_1 request passes the identity check and is
    // admitted. An unprivileged test then fails at the first step.
    lab.grant_value["host_epoch"] = json!("epoch_1");
    enroll_provisioning(&lab);
    let parts = site_request(&lab, "key", "site_nonce_w380");
    let _ = executor.provision(&site_admission(&lab, &parts));
    assert!(
        executor
            .provision_status(&id("site_op_1"))
            .unwrap()
            .is_some()
    );
}

/// F1 for the lab `backup_capture` and `restore_probe`: the same refusal
/// before intent, before the site, destination and credential checks.
/// Control: the epoch_1 request reaches the site check (W187).
#[test]
fn w380_lab_capture_and_probe_under_a_re_enrolled_epoch_are_an_identity_mismatch() {
    if cfg!(rustiron_profile = "product") {
        return; // The product profile refuses the lab backup verbs first.
    }
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/tests/fixtures");
    let verbs: [(&str, W380Digest); 2] = [
        ("capture", w380_capture_digest),
        ("probe", w380_probe_digest),
    ];
    let enroll = |lab: &Lab| {
        lab.write_policy(
            json!({"provisioning": {"wordpress_713_sha256": "d".repeat(64),
            "uid_min": 3001, "uid_max": 3099, "category_min": 201, "category_max": 299},
            "backup": {"destination_id": "lab_pc_store",
            "repository_base": "s3:http://127.0.0.1:9000/synthetic/sites",
            "store_address": "127.0.0.1", "retention_days": 30}}),
        );
    };
    for (verb, digest) in verbs {
        let mut lab = Lab::new(&format!("w380-{verb}-epoch"));
        lab.plan = fs::read(fixtures.join(format!("{verb}-plan.json"))).unwrap();
        lab.grant_value =
            serde_json::from_slice(&fs::read(fixtures.join(format!("{verb}-grant.json"))).unwrap())
                .unwrap();
        enroll(&lab);
        let mut executor = Executor::initialize(anchor(&lab)).unwrap();
        let before = w380_state(&lab);
        let submit = |executor: &mut Executor, lab: &Lab| match verb {
            "capture" => executor.backup_capture(&lab.request()).map(drop),
            _ => executor.restore_probe(&lab.request()).map(drop),
        };
        w380_epoch(&mut lab, "epoch_2", digest);
        enroll(&lab);
        assert_eq!(
            submit(&mut executor, &lab),
            Err(ExecutorError::IdentityMismatch),
            "{verb}"
        );
        assert_eq!(executor.capture_status(&id("operation_1")).unwrap(), None);
        assert_eq!(executor.probe_status(&id("operation_1")).unwrap(), None);
        assert_eq!(w380_state(&lab), before, "{verb}");
        assert_eq!(fs::read_dir(&lab.anchor.scratch_dir).unwrap().count(), 0);
        w380_epoch(&mut lab, "epoch_1", digest);
        enroll(&lab);
        assert_eq!(
            submit(&mut executor, &lab),
            Err(ExecutorError::PreconditionChanged),
            "{verb} control"
        );
        assert_eq!(w380_state(&lab), before, "{verb} control");
    }
}

/// W386 (D-035): the standing capture is a product path. A lab build
/// refuses a schema 3 standing plan at the socket and writes nothing.
#[test]
fn w386_a_lab_build_refuses_a_standing_capture_without_writes() {
    let lab = socket_lab("w386-standing");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    let journal = lab.anchor.journal_dir.join(JOURNAL_FILE);
    let before = (fs::read(&journal).unwrap(), mark_text(&lab));
    let vectors: Vec<Value> = serde_json::from_str(include_str!(
        "../../contracts/tests/fixtures/standing-capture-vectors.json"
    ))
    .unwrap();
    let vector = &vectors[1];
    let run = &vector["runs"][0];
    let frame = rustiron_contracts::execution::encode_submission(
        &id(run["operation_id"].as_str().unwrap()),
        &id(run["idempotency_key"].as_str().unwrap()),
        vector["plan_canonical"].as_str().unwrap().as_bytes(),
        vector["grant_canonical"].as_str().unwrap().as_bytes(),
        "-----BEGIN SSH SIGNATURE-----\n-----END SSH SIGNATURE-----\n",
    )
    .unwrap();
    let reply = socket_round_trip(&lab, &mut executor, &frame);
    assert_eq!(reply.state, None);
    assert!(reply.error.is_some());
    assert_ne!(
        reply.error.as_deref(),
        Some(ExecutorError::WindowClosed.code())
    );
    assert_eq!((fs::read(&journal).unwrap(), mark_text(&lab)), before);
}

const IMPORT_PLAN: &str = include_str!("../../contracts/tests/fixtures/import-plan.json");
const IMPORT_GRANT: &str = include_str!("../../contracts/tests/fixtures/import-grant.json");

/// W446 (D-053): a signed `site_import` for a site id no host account uses.
fn import_request(lab: &Lab, key: &str, nonce: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    import_request_from(lab, key, nonce, None)
}

/// D-070: as [`import_request`], renamed from `source` when given.
fn import_request_from(
    lab: &Lab,
    key: &str,
    nonce: &str,
    source: Option<&str>,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    import_request_with(lab, key, nonce, |plan| {
        if let Some(source) = source {
            plan["schema_version"] = json!(2);
            plan["source_hostname"] = json!(source);
        }
    })
}

/// A signed `site_import` whose plan `edit` changes before signing.
fn import_request_with(
    lab: &Lab,
    key: &str,
    nonce: &str,
    edit: impl Fn(&mut Value),
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut plan: Value = serde_json::from_str(IMPORT_PLAN).unwrap();
    edit(&mut plan);
    for field in ["host_id", "host_epoch", "profile_digest", "requester"] {
        plan[field] = lab.grant_value[field].clone();
    }
    let site = format!("i{}", std::process::id());
    let host = format!("{site}.example.test");
    plan["site_id"] = json!(site);
    plan["hostname"] = json!(host);
    plan["observations"][0]["site_id"] = json!(site);
    plan["observations"][0]["hostname"] = json!(host);
    let plan_bytes = serde_json::to_vec(&plan).unwrap();
    let mut grant: Value = serde_json::from_str(IMPORT_GRANT).unwrap();
    for field in [
        "host_id",
        "host_epoch",
        "profile_digest",
        "requester",
        "issuer",
        "signer_policy_epoch",
    ] {
        grant[field] = lab.grant_value[field].clone();
    }
    grant["plan_digest"] = json!(
        rustiron_contracts::approval::ImportPlan::decode(&plan_bytes)
            .unwrap()
            .digest()
            .as_str()
    );
    grant["nonce"] = json!(nonce);
    grant["site_ids"] = json!([site]);
    grant["grant_id"] = json!(format!("grant_{nonce}"));
    let grant = serde_json::to_vec(&grant).unwrap();
    let canonical = rustiron_contracts::approval::ImportGrant::decode(&grant).unwrap();
    let signature = sign(
        &lab.root.join("keys").join(key),
        &lab.root.join("import-message"),
        canonical.as_bytes(),
        "rustiron-plan-v1",
    );
    (plan_bytes, grant, signature)
}

fn enroll_import(lab: &Lab) {
    lab.write_policy(json!({
        "provisioning": {
            "wordpress_713_sha256": "e".repeat(64),
            "uid_min": 3001, "uid_max": 3099, "category_min": 201, "category_max": 299,
            "quota": {"block_hard_kib": 5_242_880, "inode_hard": 500_000},
        },
        "migration": {"php_versions": ["8.2"]},
    }));
}

/// W446: the intake check runs before intent. Without the intake archive
/// (this test host has no intake folder) nothing is recorded: no account,
/// no database, and the nonce stays unused.
#[test]
fn an_import_without_its_intake_archive_records_nothing() {
    let lab = Lab::new("import-intake");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    enroll_import(&lab);
    let parts = import_request(&lab, "key", "import_nonce_1");
    assert_eq!(
        executor.import(&site_admission(&lab, &parts)).err(),
        Some(ExecutorError::AccessDenied)
    );
    assert_eq!(executor.provision_status(&id("site_op_1")).unwrap(), None);
    assert_eq!(
        executor.provision(&site_admission(&lab, &parts)).err(),
        Some(ExecutorError::InvalidRequest),
        "an import plan is not a site plan"
    );
}

#[test]
fn site_import_requires_enrollment_peer_and_signature() {
    let lab = Lab::new("import-admit");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    let parts = import_request(&lab, "key", "import_nonce_2");
    enroll_provisioning(&lab);
    assert_eq!(
        executor.import(&site_admission(&lab, &parts)).err(),
        Some(ExecutorError::Unavailable),
        "no migration enrollment"
    );
    enroll_import(&lab);
    let mut other_peer = site_admission(&lab, &parts);
    other_peer.peer_uid = 4243;
    assert_eq!(
        executor.import(&other_peer).err(),
        Some(ExecutorError::PeerDenied)
    );
    let wrong_key = import_request(&lab, "other", "import_nonce_2");
    assert_eq!(
        executor.import(&site_admission(&lab, &wrong_key)).err(),
        Some(ExecutorError::SignatureDenied)
    );
    assert_eq!(executor.provision_status(&id("site_op_1")).unwrap(), None);
}

#[test]
fn a_signed_static_alias_is_refused_with_no_executor_intent() {
    let lab = Lab::new("import-alias-review");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    enroll_import(&lab);
    let parts = import_request_with(&lab, "key", "import_alias_nonce", |plan| {
        plan["schema_version"] = json!(3);
        plan["recipe_id"] = json!("import_static_v1");
        plan["dump_bytes"] = json!(0);
        plan["alias_hostname"] = json!("alternate.example.test");
    });
    let before = mark_text(&lab);
    assert_eq!(
        executor.import(&site_admission(&lab, &parts)).err(),
        Some(ExecutorError::Unavailable)
    );
    assert_eq!(executor.provision_status(&id("site_op_1")).unwrap(), None);
    assert_eq!(mark_text(&lab), before);
}

/// D-070: a signed renamed import passes every admission check and reaches
/// the intake check before intent, as an unrenamed one does; schema 2
/// naming the same hostname as its source is refused before any of it.
#[test]
fn a_renamed_import_is_admitted_up_to_the_intake_check() {
    let lab = Lab::new("import-rename");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    enroll_import(&lab);
    let parts = import_request_from(&lab, "key", "import_nonce_3", Some("shop.example.org"));
    assert_eq!(
        executor.import(&site_admission(&lab, &parts)).err(),
        Some(ExecutorError::AccessDenied),
        "the missing intake archive, after the signature"
    );
    let wrong_key = import_request_from(&lab, "other", "import_nonce_3", Some("shop.example.org"));
    assert_eq!(
        executor.import(&site_admission(&lab, &wrong_key)).err(),
        Some(ExecutorError::SignatureDenied)
    );
    let mut same: Value = serde_json::from_slice(&parts.0).unwrap();
    same["source_hostname"] = same["hostname"].clone();
    let same = (
        serde_json::to_vec(&same).unwrap(),
        parts.1.clone(),
        parts.2.clone(),
    );
    assert_eq!(
        executor.import(&site_admission(&lab, &same)).err(),
        Some(ExecutorError::InvalidRequest)
    );
    assert_eq!(executor.provision_status(&id("site_op_1")).unwrap(), None);
}

/// D-074: a signed static import (recipe `import_static_v1`, no dump)
/// passes every admission check and reaches the intake check before intent;
/// a static plan that still names a dump is refused before any of it.
#[test]
fn a_static_import_is_admitted_up_to_the_intake_check() {
    let lab = Lab::new("import-static");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    enroll_import(&lab);
    let parts = import_request_with(&lab, "key", "import_nonce_4", |plan| {
        plan["recipe_id"] = json!("import_static_v1");
        plan["dump_bytes"] = json!(0);
    });
    assert_eq!(
        executor.import(&site_admission(&lab, &parts)).err(),
        Some(ExecutorError::AccessDenied),
        "the missing intake archive, after the signature"
    );
    let mut plan: Value = serde_json::from_slice(&parts.0).unwrap();
    plan["dump_bytes"] = json!(1);
    let with_dump = (
        serde_json::to_vec(&plan).unwrap(),
        parts.1.clone(),
        parts.2.clone(),
    );
    assert_eq!(
        executor.import(&site_admission(&lab, &with_dump)).err(),
        Some(ExecutorError::InvalidRequest)
    );
    assert_eq!(executor.provision_status(&id("site_op_1")).unwrap(), None);
}

const SCRUB_PLAN: &str = include_str!("../../contracts/tests/fixtures/scrub-plan.json");
const SCRUB_GRANT: &str = include_str!("../../contracts/tests/fixtures/scrub-grant.json");

/// W459 (D-057): a signed `import_scrub` for an import this journal lacks.
fn scrub_request(lab: &Lab, key: &str, nonce: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut plan: Value = serde_json::from_str(SCRUB_PLAN).unwrap();
    for field in ["host_id", "host_epoch", "profile_digest", "requester"] {
        plan[field] = lab.grant_value[field].clone();
    }
    let plan_bytes = serde_json::to_vec(&plan).unwrap();
    let mut grant: Value = serde_json::from_str(SCRUB_GRANT).unwrap();
    for field in [
        "host_id",
        "host_epoch",
        "profile_digest",
        "requester",
        "issuer",
        "signer_policy_epoch",
    ] {
        grant[field] = lab.grant_value[field].clone();
    }
    grant["plan_digest"] = json!(
        rustiron_contracts::approval::ScrubPlan::decode(&plan_bytes)
            .unwrap()
            .digest()
            .as_str()
    );
    grant["nonce"] = json!(nonce);
    grant["grant_id"] = json!(format!("grant_{nonce}"));
    let grant = serde_json::to_vec(&grant).unwrap();
    let canonical = rustiron_contracts::approval::ScrubGrant::decode(&grant).unwrap();
    let signature = sign(
        &lab.root.join("keys").join(key),
        &lab.root.join("scrub-message"),
        canonical.as_bytes(),
        "rustiron-plan-v1",
    );
    (plan_bytes, grant, signature)
}

#[test]
fn import_scrub_requires_enrollment_peer_signature_and_a_recorded_import() {
    let lab = Lab::new("scrub-admit");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    let parts = scrub_request(&lab, "key", "scrub_nonce_1");
    enroll_provisioning(&lab);
    assert_eq!(
        executor.scrub(&site_admission(&lab, &parts)).err(),
        Some(ExecutorError::Unavailable),
        "no migration enrollment"
    );
    enroll_import(&lab);
    let mut other_peer = site_admission(&lab, &parts);
    other_peer.peer_uid = 4243;
    assert_eq!(
        executor.scrub(&other_peer).err(),
        Some(ExecutorError::PeerDenied)
    );
    let wrong_key = scrub_request(&lab, "other", "scrub_nonce_1");
    assert_eq!(
        executor.scrub(&site_admission(&lab, &wrong_key)).err(),
        Some(ExecutorError::SignatureDenied)
    );
    let journal = lab.anchor.journal_dir.join("fixture-journal.sqlite");
    let before = (fs::read(&journal).unwrap(), mark_text(&lab));
    assert!(
        executor.scrub(&site_admission(&lab, &parts)).is_err(),
        "the journal holds no import op_import"
    );
    assert_eq!(executor.scrub_status(&id("site_op_1")).unwrap(), None);
    assert_eq!((fs::read(&journal).unwrap(), mark_text(&lab)), before);
}

const CERT_PLAN: &str = include_str!("../../contracts/tests/fixtures/certificate-plan.json");
const CERT_GRANT: &str = include_str!("../../contracts/tests/fixtures/certificate-grant.json");

/// W462 (D-059): a signed `certificate_issue` for a site this journal lacks.
fn certificate_request(lab: &Lab, key: &str, nonce: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    certificate_request_with(lab, key, nonce, |_| {})
}

fn certificate_request_with(
    lab: &Lab,
    key: &str,
    nonce: &str,
    edit: impl Fn(&mut Value),
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut plan: Value = serde_json::from_str(CERT_PLAN).unwrap();
    edit(&mut plan);
    for field in ["host_id", "host_epoch", "profile_digest", "requester"] {
        plan[field] = lab.grant_value[field].clone();
    }
    let plan_bytes = serde_json::to_vec(&plan).unwrap();
    let mut grant: Value = serde_json::from_str(CERT_GRANT).unwrap();
    for field in [
        "host_id",
        "host_epoch",
        "profile_digest",
        "requester",
        "issuer",
        "signer_policy_epoch",
    ] {
        grant[field] = lab.grant_value[field].clone();
    }
    grant["plan_digest"] = json!(
        rustiron_contracts::approval::CertificatePlan::decode(&plan_bytes)
            .unwrap()
            .digest()
            .as_str()
    );
    grant["nonce"] = json!(nonce);
    grant["grant_id"] = json!(format!("grant_{nonce}"));
    let grant = serde_json::to_vec(&grant).unwrap();
    let canonical = rustiron_contracts::approval::CertificateGrant::decode(&grant).unwrap();
    let signature = sign(
        &lab.root.join("keys").join(key),
        &lab.root.join("certificate-message"),
        canonical.as_bytes(),
        "rustiron-plan-v1",
    );
    (plan_bytes, grant, signature)
}

#[test]
fn a_reviewable_alias_certificate_records_no_issuance() {
    let lab = Lab::new("cert-alias-review");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    enroll_certificates(&lab);
    let parts = certificate_request_with(&lab, "key", "cert_alias_nonce", |plan| {
        plan["schema_version"] = json!(3);
        plan["alias_hostname"] = json!("alternate.example.test");
        plan["renew_until"] = json!(3600);
    });
    let before = mark_text(&lab);
    assert_eq!(
        executor.certificate(&site_admission(&lab, &parts)).err(),
        Some(ExecutorError::Unavailable)
    );
    assert_eq!(executor.certificate_status(&id("site_op_1")).unwrap(), None);
    assert_eq!(mark_text(&lab), before);
}

#[test]
fn certificate_issue_requires_acme_tls_enrollment_peer_signature_and_a_site() {
    let lab = Lab::new("cert-admit");
    let mut executor = Executor::initialize(anchor(&lab)).unwrap();
    let parts = certificate_request(&lab, "key", "cert_nonce_1");
    enroll_provisioning(&lab);
    assert_eq!(
        executor.certificate(&site_admission(&lab, &parts)).err(),
        Some(ExecutorError::Unavailable),
        "no ACME or TLS enrollment"
    );
    enroll_certificates(&lab);
    let mut other_peer = site_admission(&lab, &parts);
    other_peer.peer_uid = 4243;
    assert_eq!(
        executor.certificate(&other_peer).err(),
        Some(ExecutorError::PeerDenied)
    );
    let wrong_key = certificate_request(&lab, "other", "cert_nonce_1");
    assert_eq!(
        executor
            .certificate(&site_admission(&lab, &wrong_key))
            .err(),
        Some(ExecutorError::SignatureDenied)
    );
    let journal = lab.anchor.journal_dir.join("fixture-journal.sqlite");
    let before = (fs::read(&journal).unwrap(), mark_text(&lab));
    // W480 (W479-F2): a missing site is a precondition, not a replay.
    assert_eq!(
        executor.certificate(&site_admission(&lab, &parts)).err(),
        Some(ExecutorError::PreconditionChanged),
        "the journal holds no site blog1"
    );
    assert_eq!(executor.certificate_status(&id("site_op_1")).unwrap(), None);
    assert_eq!((fs::read(&journal).unwrap(), mark_text(&lab)), before);
}

fn enroll_certificates(lab: &Lab) {
    lab.write_policy(json!({
        "provisioning": {
            "wordpress_713_sha256": "e".repeat(64),
            "uid_min": 3001, "uid_max": 3099, "category_min": 201, "category_max": 299,
            "quota": {"block_hard_kib": 5_242_880, "inode_hard": 500_000},
        },
        "ols": {"listener": "G0", "address": "127.0.0.1:8090", "adopted": [],
                "parent_sha256": "a".repeat(64), "webadmin_port": 7080,
                "tls_address": "127.0.0.1:8443"},
        "acme": {"directory": "https://acme.lab.test:8009/acme/local/directory"},
    }));
}
