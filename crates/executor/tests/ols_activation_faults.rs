//! W380 (B06, B08): crash points inside the OLS activation
//! (`config_activate`), after the include folder is opened.
//!
//! The include folder is fixed (`/etc/rustiron-ols`). These root tests run
//! only in a private mount namespace with an empty tmpfs over that folder,
//! through `docs/validation/S10-W380/run_faults.sh`. They refuse to start
//! otherwise, so they never touch a live include. The journal and the
//! admission mark are fixtures under `/run`. A stub admin helper answers the
//! OLS steps; no step reaches `systemctl` or the live server. The helper's
//! own decisions for each journal state are unit tests (`admin_helper_tests`).
//!
//! Each test crashes at one `Fault`, opens a new executor, and shows that
//! `reconcile` and the single signed `compensate` record only what the
//! executor observes: never `succeeded` without a verified target.

use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    os::unix::{fs::MetadataExt, net::UnixListener},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use rustiron_contracts::{
    Id, Timestamp,
    approval::{OlsGrant, OlsPlan, Sha256Digest},
};
use rustiron_executor::{
    AdmissionRequest, Executor, ExecutorError, Fault, TrustAnchor, admin_helper::AdminStep, ols,
};
use serde_json::{Value, json};
mod support;
use rustiron_journal::{Admitted, FixtureJournal, ProvisionIntent, ProvisionStep, RecordedState};
use support::{KEYGEN, hex, new_key, private_dir, private_file, sign};

const INCLUDE: &str = "/etc/rustiron-ols";
const FIXTURE_ENV: &str = "RUSTIRON_W380_FIXTURE_OLS";
const PLAN: &str = include_str!("../../contracts/tests/fixtures/ols-plan.json");
const GRANT: &str = include_str!("../../contracts/tests/fixtures/ols-grant.json");
const NOW: u64 = 1200;

static SERIAL: Mutex<()> = Mutex::new(());

fn id(value: &str) -> Id {
    Id::try_from(value.to_owned()).unwrap()
}

fn now() -> Option<Timestamp> {
    Some(Timestamp::try_from(NOW).unwrap())
}

/// Whether `/etc/rustiron-ols` is a mount of its own, not the folder on
/// the `/etc` file system.
fn include_is_fixture_mount() -> bool {
    match (fs::metadata(INCLUDE), fs::metadata("/etc")) {
        (Ok(include), Ok(etc)) => include.dev() != etc.dev(),
        _ => false,
    }
}

/// Refuses to run outside the fixture: root, the fixture variable, and an
/// empty include folder that is a separate mount.
fn require_fixture() {
    assert_eq!(rustix::process::geteuid().as_raw(), 0, "root only");
    assert_eq!(
        std::env::var(FIXTURE_ENV).as_deref(),
        Ok("1"),
        "run through docs/validation/S10-W380/run_faults.sh"
    );
    assert!(
        include_is_fixture_mount(),
        "{INCLUDE} must be a fixture mount, never the live include"
    );
    assert_eq!(
        fs::read_dir(INCLUDE).unwrap().count(),
        0,
        "the fixture include must start empty"
    );
}

/// Steps the stub helper saw, and the reply it gives for each step.
#[derive(Default)]
struct Script {
    replies: HashMap<&'static str, String>,
    seen: Vec<String>,
}

struct Lab {
    _serial: std::sync::MutexGuard<'static, ()>,
    root: PathBuf,
    anchor: TrustAnchor,
    script: Arc<Mutex<Script>>,
    name: String,
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
        // Never empties a folder that is not the fixture mount.
        if include_is_fixture_mount()
            && let Ok(entries) = fs::read_dir(INCLUDE)
        {
            for entry in entries.flatten() {
                let path = entry.path();
                let _ = if path.is_dir() && !path.is_symlink() {
                    fs::remove_dir_all(&path)
                } else {
                    fs::remove_file(&path)
                };
            }
        }
    }
}

#[derive(Clone)]
struct Signed {
    plan: Vec<u8>,
    grant: Vec<u8>,
    signature: Vec<u8>,
}

impl Signed {
    fn request(&self, operation: &str) -> AdmissionRequest<'_> {
        AdmissionRequest {
            peer_uid: 4242,
            plan: &self.plan,
            grant: &self.grant,
            signature: &self.signature,
            operation_id: id(operation),
            idempotency_key: id(&format!("key_{operation}")),
            now: now(),
        }
    }
}

impl Lab {
    fn new(name: &str) -> Self {
        let serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        require_fixture();
        let include = Path::new(INCLUDE).join("generations");
        fs::create_dir(&include).unwrap();
        fs::set_permissions(
            &include,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();
        let root = PathBuf::from(format!("/run/rustiron-w380-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        private_dir(&root);
        for dir in ["policy", "registry", "scratch", "journal", "mark", "keys"] {
            private_dir(&root.join(dir));
        }
        new_key(&root.join("keys/key"));
        let socket = root.join("helper.sock");
        let anchor = TrustAnchor {
            owner_uid: 0,
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
            name: name.to_owned(),
        };
        lab.write_policy();
        drop(Executor::initialize(lab.anchor.clone()).unwrap());
        lab.provision(&["blog5", "blog6"]);
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
                "listener": "W380", "address": "127.0.0.1:8090", "adopted": [],
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

    /// Succeeded provisions of `sites`, recorded the way the journal requires.
    fn provision(&self, sites: &[&str]) {
        let mut journal = FixtureJournal::open_as_process_owner(
            &self.anchor.journal_dir,
            id("host_lab"),
            id("epoch_1"),
        )
        .unwrap();
        for site in sites {
            let intent = ProvisionIntent {
                operation_id: id(&format!("op_provision_{site}")),
                idempotency_key: id(&format!("key_provision_{site}")),
                grant_id: id(&format!("grant_provision_{site}")),
                nonce: id(&format!("nonce_provision_{site}")),
                plan_digest: Sha256Digest::from_bytes([4; 32]),
                grant_digest: Sha256Digest::from_bytes([5; 32]),
                host_id: id("host_lab"),
                host_epoch: id("epoch_1"),
                site_id: (*site).to_owned().try_into().unwrap(),
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
    }

    /// A signed v1 plan from `predecessor` for `sites`, with its own nonce.
    fn signed(&self, predecessor: &(Id, Sha256Digest), sites: &[&str], nonce: &str) -> Signed {
        let mut plan: Value = serde_json::from_str(PLAN).unwrap();
        plan["site_ids"] = json!(sites);
        plan["expected_generation"] = json!(predecessor.0.as_str());
        plan["expected_digest"] = json!(predecessor.1.as_str());
        plan["observations"][0]["generation"] = json!(predecessor.0.as_str());
        plan["observations"][0]["content_digest"] = json!(predecessor.1.as_str());
        let plan = serde_json::to_vec(&plan).unwrap();
        let mut grant: Value = serde_json::from_str(GRANT).unwrap();
        grant["plan_digest"] = json!(OlsPlan::decode(&plan).unwrap().digest().as_str());
        grant["site_ids"] = json!(sites);
        grant["grant_id"] = json!(format!("grant_{nonce}"));
        grant["nonce"] = json!(nonce);
        let grant = serde_json::to_vec(&grant).unwrap();
        let signature = sign(
            &self.root.join("keys/key"),
            &self.root.join("message"),
            OlsGrant::decode(&grant).unwrap().as_bytes(),
            "rustiron-plan-v1",
        );
        Signed {
            plan,
            grant,
            signature,
        }
    }

    /// Sets the stub reply for each step; every other step is refused.
    fn answer(&self, replies: &[(AdminStep, String)]) {
        let mut script = self.script.lock().unwrap();
        script.replies = replies
            .iter()
            .map(|(step, reply)| (step.name(), reply.clone()))
            .collect();
    }

    /// The steps the stub saw since the last call, in order.
    fn steps(&self) -> Vec<String> {
        std::mem::take(&mut self.script.lock().unwrap().seen)
    }

    fn open(&self) -> Executor {
        Executor::open(self.anchor.clone()).unwrap()
    }

    /// One evidence line for the run log.
    fn log(&self, event: &str, detail: impl std::fmt::Debug) {
        eprintln!("w380 {} {event} {detail:?}", self.name);
    }
}

/// A stub admin helper on `socket`: it answers each step with the scripted
/// reply, or refuses it with `FIXTURE_BINDING_DENIED`, and records it.
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
                script.seen.push(step.clone());
                script
                    .replies
                    .get(step.as_str())
                    .cloned()
                    .unwrap_or_else(|| "FIXTURE_BINDING_DENIED\n".to_owned())
            };
            let _ = stream.write_all(reply.as_bytes());
        }
    });
}

fn ok() -> String {
    "ok\n".to_owned()
}

/// The preflight reply of a clean running host.
fn clean_preflight() -> String {
    let checks = ols::ServerChecks {
        parent_reviewed: true,
        webadmin_closed: true,
        adopted_vhosts_pinned: true,
        php_capacity: true,
        page_cache_ols_tested: true,
    };
    format!("ok {}\n", checks.encode())
}

/// Every step of a running activation, its restore and a reconcile.
fn running_host() -> Vec<(AdminStep, String)> {
    vec![
        (AdminStep::OlsPreflight, clean_preflight()),
        (AdminStep::OlsConfigTest, ok()),
        (AdminStep::OlsReload, ok()),
        (AdminStep::OlsVerify, ok()),
    ]
}

/// Every step of a bootstrap activation and its restore.
fn bootstrap_host() -> Vec<(AdminStep, String)> {
    vec![
        (AdminStep::OlsPreflight, ok()),
        (AdminStep::OlsConfigTest, ok()),
        (AdminStep::OlsStart, ok()),
        (AdminStep::OlsVerify, ok()),
        (AdminStep::OlsStop, ok()),
    ]
}

/// `current` as the executor reads it: `None` when absent.
fn current() -> Option<(Id, Sha256Digest)> {
    ols::observe_current(&ols::open_include().unwrap()).unwrap()
}

fn staged(generation: &Id) -> bool {
    Path::new(INCLUDE)
        .join("generations")
        .join(generation.as_str())
        .is_dir()
}

fn generation_of(operation: &rustiron_journal::Operation) -> (Id, Sha256Digest) {
    (
        operation.intent.target_generation.clone(),
        operation.intent.target_digest.clone(),
    )
}

/// The bootstrap activation through the stub: the first generation, A,
/// for blog5. Returns A.
fn bootstrap(lab: &Lab, executor: &mut Executor) -> (Id, Sha256Digest) {
    lab.answer(&bootstrap_host());
    let signed = lab.signed(&ols::bootstrap_generation(), &["blog5"], "nonce_boot");
    let Admitted::New(operation) = executor.activate_ols(&signed.request("op_boot")).unwrap()
    else {
        panic!("the bootstrap activation must be new");
    };
    assert_eq!(operation.state, RecordedState::Succeeded);
    let first = generation_of(&operation);
    assert_eq!(current(), Some(first.clone()));
    lab.log("bootstrap", (&first.0, lab.steps()));
    first
}

/// A fresh grant from `predecessor` must be admitted and succeed: the
/// history explains `current` again (W359 to W362).
fn next_activation_succeeds(lab: &Lab, executor: &mut Executor, predecessor: &(Id, Sha256Digest)) {
    lab.answer(&running_host());
    let signed = lab.signed(predecessor, &["blog5", "blog6"], "nonce_next");
    let Admitted::New(operation) = executor.activate_ols(&signed.request("op_next")).unwrap()
    else {
        panic!("the next activation must be new");
    };
    assert_eq!(operation.state, RecordedState::Succeeded);
    assert_eq!(current(), Some(generation_of(&operation)));
    lab.log("next activation", (operation.state, lab.steps()));
}

/// New work is refused while `operation` is unresolved, and its exact
/// repeat is status only: no helper step, no write.
fn blocks_new_work(lab: &Lab, executor: &mut Executor, signed: &Signed, operation: &str) {
    let live = current().unwrap_or_else(ols::bootstrap_generation);
    let other = lab.signed(&live, &["blog6"], "nonce_blocked");
    assert_eq!(
        executor.activate_ols(&other.request("op_blocked")).err(),
        Some(ExecutorError::Busy)
    );
    assert!(matches!(
        executor.activate_ols(&signed.request(operation)),
        Ok(Admitted::Existing(_))
    ));
    assert!(
        lab.steps().is_empty(),
        "a refused or repeated request ran a step"
    );
}

/// The running activation from A to B (blog5 and blog6) that crashes at
/// `fault`. Returns the signed request, A, and B.
fn crash_running(
    lab: &Lab,
    fault: Fault,
    verify: String,
) -> (Signed, (Id, Sha256Digest), (Id, Sha256Digest)) {
    let mut executor = lab.open();
    let first = bootstrap(lab, &mut executor);
    let mut replies = running_host();
    replies.retain(|(step, _)| *step != AdminStep::OlsVerify);
    replies.push((AdminStep::OlsVerify, verify));
    lab.answer(&replies);
    let signed = lab.signed(&first, &["blog5", "blog6"], "nonce_run");
    executor.inject_fault(fault);
    assert_eq!(
        executor.activate_ols(&signed.request("op_run")).err(),
        Some(ExecutorError::Unavailable),
        "the crash point {fault:?} was not reached"
    );
    drop(executor);
    let row = lab.open().status(&id("op_run")).unwrap().unwrap();
    let second = generation_of(&row);
    lab.log("crash", (fault, lab.steps()));
    (signed, first, second)
}

/// The row after a restart, with the include as found.
fn after_restart(lab: &Lab, executor: &Executor) -> rustiron_journal::Operation {
    let row = executor.status(&id("op_run")).unwrap().unwrap();
    lab.log(
        "after restart",
        (
            row.state,
            row.effect_attempted,
            row.compensation_attempted,
            current().map(|(id, _)| id),
        ),
    );
    row
}

#[test]
#[ignore = "root lab test: run through docs/validation/S10-W380/run_faults.sh"]
fn w380_a_crash_after_the_ols_intent_reconciles_untouched_as_root() {
    let lab = Lab::new("intent");
    let (signed, first, second) = crash_running(&lab, Fault::AfterOlsIntent, ok());
    let mut executor = lab.open();
    let row = after_restart(&lab, &executor);
    assert_eq!(row.state, RecordedState::Intent);
    assert!(!row.effect_attempted && !row.compensation_attempted);
    assert_eq!(current(), Some(first.clone()));
    assert!(!staged(&second.0), "nothing is staged before the preflight");
    blocks_new_work(&lab, &mut executor, &signed, "op_run");
    // No effect was attempted, so no restore exists.
    assert_eq!(
        executor.compensate(&id("op_run"), now()).err(),
        Some(ExecutorError::CompensationDenied)
    );
    no_serving_step_before_the_effect_mark(&row);
    let settled = executor.reconcile(&id("op_run")).unwrap();
    assert_eq!(settled.state, RecordedState::Untouched);
    assert!(
        lab.steps().is_empty(),
        "no helper step without the effect mark"
    );
    assert_eq!(current(), Some(first.clone()));
    lab.log("reconcile", settled.state);
    next_activation_succeeds(&lab, &mut executor, &first);
}

/// W384: the real admin helper refuses every serving step for a running
/// activation without the effect mark (only the preflight belongs to that
/// state). Before W384, `reconcile` asked for the reload, which the stub
/// answered but the helper refused (`FIXTURE_BINDING_DENIED`), so the row
/// stayed `intent` on a real host.
fn no_serving_step_before_the_effect_mark(row: &rustiron_journal::Operation) {
    assert!(!row.effect_attempted);
    for step in [
        AdminStep::OlsReload,
        AdminStep::OlsVerify,
        AdminStep::OlsConfigTest,
    ] {
        assert!(
            !rustiron_executor::admin_helper::ols_step_current(row, step),
            "{step:?}"
        );
    }
}

#[test]
#[ignore = "root lab test: run through docs/validation/S10-W380/run_faults.sh"]
fn w380_a_crash_after_the_ols_effect_mark_reconciles_untouched_as_root() {
    let lab = Lab::new("effect-mark");
    let (signed, first, second) = crash_running(&lab, Fault::AfterOlsEffectMark, ok());
    let mut executor = lab.open();
    let row = after_restart(&lab, &executor);
    assert_eq!(row.state, RecordedState::Intent);
    assert!(row.effect_attempted && !row.compensation_attempted);
    assert_eq!(current(), Some(first.clone()), "the switch never ran");
    assert!(staged(&second.0), "the target is staged before the mark");
    blocks_new_work(&lab, &mut executor, &signed, "op_run");
    let settled = executor.reconcile(&id("op_run")).unwrap();
    assert_eq!(settled.state, RecordedState::Untouched);
    assert_eq!(lab.steps(), ["ols_reload", "ols_verify"]);
    lab.log("reconcile", settled.state);
    assert_eq!(
        executor.compensate(&id("op_run"), now()).err(),
        Some(ExecutorError::CompensationDenied),
        "an untouched operation has nothing to restore"
    );
    // The staged target is content-addressed: the next activation reuses it.
    next_activation_succeeds(&lab, &mut executor, &first);
}

#[test]
#[ignore = "root lab test: run through docs/validation/S10-W380/run_faults.sh"]
fn w380_a_crash_after_ols_serving_is_never_succeeded_and_restores_once_as_root() {
    let lab = Lab::new("serving");
    let (signed, first, second) = crash_running(&lab, Fault::AfterOlsServing, ok());
    let mut executor = lab.open();
    let row = after_restart(&lab, &executor);
    assert_eq!(row.state, RecordedState::Intent);
    assert!(row.effect_attempted && !row.compensation_attempted);
    assert_eq!(current(), Some(second), "the target is current");
    blocks_new_work(&lab, &mut executor, &signed, "op_run");
    // `current` is the target, but nothing verified it: never `succeeded`.
    let settled = executor.reconcile(&id("op_run")).unwrap();
    assert_eq!(settled.state, RecordedState::NeedsAttention);
    assert!(
        lab.steps().is_empty(),
        "reconcile runs no step on the target"
    );
    lab.log("reconcile", settled.state);
    blocks_new_work(&lab, &mut executor, &signed, "op_run");
    let restored = executor.compensate(&id("op_run"), now()).unwrap();
    assert_eq!(restored.state, RecordedState::FailedCompensated);
    assert_eq!(lab.steps(), ["ols_reload", "ols_verify"]);
    assert_eq!(current(), Some(first.clone()));
    lab.log("compensate", restored.state);
    assert_eq!(
        executor.compensate(&id("op_run"), now()).err(),
        Some(ExecutorError::CompensationDenied),
        "the restore runs once"
    );
    next_activation_succeeds(&lab, &mut executor, &first);
}

#[test]
#[ignore = "root lab test: run through docs/validation/S10-W380/run_faults.sh"]
fn w380_a_crash_after_the_ols_restore_mark_never_restores_twice_as_root() {
    let lab = Lab::new("restore-mark");
    let refused = format!("{}\n", ExecutorError::ProbeFailed.code());
    let (signed, first, second) = crash_running(&lab, Fault::AfterOlsRestoreMark, refused);
    let mut executor = lab.open();
    let row = after_restart(&lab, &executor);
    assert_eq!(row.state, RecordedState::Compensating);
    assert!(row.effect_attempted && row.compensation_attempted);
    assert_eq!(current(), Some(second.clone()), "the restore never ran");
    blocks_new_work(&lab, &mut executor, &signed, "op_run");
    let settled = executor.reconcile(&id("op_run")).unwrap();
    assert_eq!(settled.state, RecordedState::NeedsAttention);
    assert!(
        lab.steps().is_empty(),
        "reconcile runs no step on the target"
    );
    assert_eq!(
        executor.compensate(&id("op_run"), now()).err(),
        Some(ExecutorError::CompensationDenied),
        "the one restore was spent at the mark"
    );
    assert!(lab.steps().is_empty());
    assert_eq!(current(), Some(second));
    lab.log("reconcile and compensate", settled.state);
    blocks_new_work(&lab, &mut executor, &signed, "op_run");
    // The operator restores the predecessor outside Rustiron. While the
    // verification still fails, reconcile records nothing verified.
    ols::switch(&ols::open_include().unwrap(), &first.0).unwrap();
    let settled = executor.reconcile(&id("op_run")).unwrap();
    assert_eq!(settled.state, RecordedState::NeedsAttention);
    assert_eq!(lab.steps(), ["ols_reload", "ols_verify"]);
    lab.log("operator restore, verify refused, reconcile", settled.state);
    // Only after the reload and a passing verification does reconcile
    // record the restored predecessor.
    lab.answer(&running_host());
    let settled = executor.reconcile(&id("op_run")).unwrap();
    assert_eq!(settled.state, RecordedState::FailedCompensated);
    assert_eq!(lab.steps(), ["ols_reload", "ols_verify"]);
    lab.log("operator restore, reconcile", settled.state);
    next_activation_succeeds(&lab, &mut executor, &first);
}

/// W382 (D-033): the bootstrap activation at the four points. Its restore
/// is the stop and the removal of `current` (W355). `reconcile` asks the
/// helper for the read-only `ols_bootstrap_confirm` step and records the
/// bootstrap predecessor only when the helper confirms it. The stub gives
/// the reply that the real helper gives for the live state of each step:
/// `DRIFT` while `current` names the target (OLS was started), `ok` once
/// `current` is absent. Before W382, the intent and restore-mark rows
/// stayed `needs_attention` and blocked OLS until an epoch rotation (W380
/// B1). Now every row settles, and a new bootstrap activation succeeds in
/// the same epoch.
#[test]
#[ignore = "root lab test: run through docs/validation/S10-W380/run_faults.sh"]
fn w382_bootstrap_crashes_settle_by_reconcile_as_root() {
    let points = [
        (Fault::AfterOlsIntent, ok()),
        (Fault::AfterOlsEffectMark, ok()),
        (Fault::AfterOlsServing, ok()),
        (
            Fault::AfterOlsRestoreMark,
            format!("{}\n", ExecutorError::ProbeFailed.code()),
        ),
    ];
    let drift = format!("{}\n", ExecutorError::Drift.code());
    for (fault, verify) in points {
        let lab = Lab::new(&format!("bootstrap-{fault:?}").to_lowercase());
        let mut executor = lab.open();
        let mut replies = bootstrap_host();
        replies.retain(|(step, _)| *step != AdminStep::OlsVerify);
        replies.push((AdminStep::OlsVerify, verify));
        lab.answer(&replies);
        let signed = lab.signed(&ols::bootstrap_generation(), &["blog5"], "nonce_boot");
        executor.inject_fault(fault);
        assert_eq!(
            executor.activate_ols(&signed.request("op_boot")).err(),
            Some(ExecutorError::Unavailable),
            "{fault:?}"
        );
        drop(executor);
        lab.log("crash", (fault, lab.steps()));
        let mut executor = lab.open();
        let row = executor.status(&id("op_boot")).unwrap().unwrap();
        let target = generation_of(&row);
        lab.log(
            "after restart",
            (
                row.state,
                row.effect_attempted,
                row.compensation_attempted,
                current().map(|(id, _)| id),
            ),
        );
        still_blocked(&lab, &mut executor);
        let confirmed = |reply: &str| vec![(AdminStep::OlsBootstrapConfirm, reply.to_owned())];
        let settled = match fault {
            // Nothing switched: `current` is absent and OLS never started.
            // No effect, or no switch, so no restore: `untouched`.
            Fault::AfterOlsIntent | Fault::AfterOlsEffectMark => {
                assert_eq!(current(), None, "{fault:?}");
                lab.answer(&confirmed(&ok()));
                let settled = executor.reconcile(&id("op_boot")).unwrap();
                assert_eq!(settled.state, RecordedState::Untouched, "{fault:?}");
                assert_eq!(lab.steps(), ["ols_bootstrap_confirm"]);
                assert_eq!(
                    executor.compensate(&id("op_boot"), now()).err(),
                    Some(ExecutorError::CompensationDenied),
                    "{fault:?}: nothing to restore"
                );
                settled
            }
            // `current` is the unverified target and OLS was started: the
            // helper refuses, and the row stays for the signed restore. At
            // the next boot the guard removes `current` before OLS starts
            // (D-032); then the helper confirms and the row is `untouched`.
            Fault::AfterOlsServing => {
                assert_eq!(current(), Some(target.clone()));
                lab.answer(&confirmed(&drift));
                let blocked = executor.reconcile(&id("op_boot")).unwrap();
                assert_eq!(blocked.state, RecordedState::NeedsAttention);
                assert_eq!(lab.steps(), ["ols_bootstrap_confirm"]);
                still_blocked(&lab, &mut executor);
                ols::clear_current(&ols::open_include().unwrap()).unwrap();
                lab.answer(&confirmed(&ok()));
                let settled = executor.reconcile(&id("op_boot")).unwrap();
                assert_eq!(settled.state, RecordedState::Untouched);
                assert_eq!(lab.steps(), ["ols_bootstrap_confirm"]);
                lab.log("boot guard removal, reconcile", settled.state);
                settled
            }
            // The one restore was spent at the mark, and OLS still serves
            // the target: the helper refuses. After the operator stops OLS
            // and the boot guard removes `current`, the helper confirms and
            // the row is `failed_compensated`.
            _ => {
                assert_eq!(current(), Some(target.clone()));
                lab.answer(&confirmed(&drift));
                let blocked = executor.reconcile(&id("op_boot")).unwrap();
                assert_eq!(blocked.state, RecordedState::NeedsAttention);
                assert_eq!(lab.steps(), ["ols_bootstrap_confirm"]);
                assert_eq!(
                    executor.compensate(&id("op_boot"), now()).err(),
                    Some(ExecutorError::CompensationDenied),
                    "the one restore was spent at the mark"
                );
                assert!(lab.steps().is_empty());
                still_blocked(&lab, &mut executor);
                ols::clear_current(&ols::open_include().unwrap()).unwrap();
                lab.answer(&confirmed(&ok()));
                let settled = executor.reconcile(&id("op_boot")).unwrap();
                assert_eq!(settled.state, RecordedState::FailedCompensated);
                assert_eq!(lab.steps(), ["ols_bootstrap_confirm"]);
                lab.log(
                    "operator stop, boot guard removal, reconcile",
                    settled.state,
                );
                settled
            }
        };
        lab.log("reconcile", settled.state);
        assert_eq!(current(), None, "{fault:?}");
        // The same epoch: a new bootstrap activation is admitted and succeeds.
        lab.answer(&bootstrap_host());
        let again = lab.signed(&ols::bootstrap_generation(), &["blog5"], "nonce_again");
        let Admitted::New(operation) = executor.activate_ols(&again.request("op_again")).unwrap()
        else {
            panic!("{fault:?}: the new bootstrap activation must be new");
        };
        assert_eq!(operation.state, RecordedState::Succeeded, "{fault:?}");
        assert_eq!(current(), Some(target), "{fault:?}");
        lab.log("new bootstrap activation", (operation.state, lab.steps()));
    }
}

/// The OLS resource stays blocked: a new activation from the live `current`
/// (the bootstrap generation when absent) is refused as unresolved before
/// intent.
fn still_blocked(lab: &Lab, executor: &mut Executor) {
    let live = current().unwrap_or_else(ols::bootstrap_generation);
    let other = lab.signed(&live, &["blog6"], "nonce_blocked");
    assert_eq!(
        executor.activate_ols(&other.request("op_blocked")).err(),
        Some(ExecutorError::Busy)
    );
    assert!(lab.steps().is_empty());
    lab.log("new activation", ExecutorError::Busy.code());
}

/// `names` in name order, as [`generation_entries`] lists them.
fn sorted(names: &[&str]) -> Vec<String> {
    let mut names: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
    names.sort();
    names
}

/// Names in `generations`, in name order.
fn generation_entries() -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(Path::new(INCLUDE).join("generations"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// W384 reproduction: before W384, a power cut during the staging could
/// leave the content-addressed target folder with only some of its files.
/// Simulated here after an effect-mark crash and its `untouched` reconcile:
/// one file is cut short and the last one is removed. Before W384, the next
/// activation to the same target found the folder, failed the digest check
/// and failed, every time. W384 moves the folder aside, never deletes it,
/// and stages the target again.
#[test]
#[ignore = "root lab test: run through docs/validation/S10-W380/run_faults.sh"]
fn w384_a_partial_target_folder_is_quarantined_and_staged_again_as_root() {
    let lab = Lab::new("partial-target");
    let (_, first, second) = crash_running(&lab, Fault::AfterOlsEffectMark, ok());
    let mut executor = lab.open();
    let settled = executor.reconcile(&id("op_run")).unwrap();
    assert_eq!(settled.state, RecordedState::Untouched);
    lab.steps();
    let folder = Path::new(INCLUDE)
        .join("generations")
        .join(second.0.as_str());
    let mut files: Vec<String> = fs::read_dir(&folder)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    files.sort();
    assert!(files.len() >= 2, "the target has at least two files");
    let short = folder.join(&files[0]);
    let length = fs::metadata(&short).unwrap().len();
    fs::OpenOptions::new()
        .write(true)
        .open(&short)
        .unwrap()
        .set_len(length / 2)
        .unwrap();
    fs::remove_file(folder.join(files.last().unwrap())).unwrap();
    lab.log("partial target", (&second.0, &files, length));
    // Before W384, a second try failed the same way.
    for attempt in ["first", "second"] {
        let probe = lab.signed(&first, &["blog5", "blog6"], &format!("nonce_{attempt}"));
        lab.answer(&running_host());
        let result = executor.activate_ols(&probe.request(&format!("op_{attempt}")));
        lab.log(
            "activation to the partial target",
            (attempt, result.as_ref().map(|_| ()).err(), lab.steps()),
        );
        if result.is_ok() {
            break;
        }
    }
    assert_eq!(current(), Some(second.clone()), "the target is served");
    let quarantined = format!("{}.quarantine-op_first", second.0.as_str());
    assert_eq!(
        generation_entries(),
        sorted(&[first.0.as_str(), second.0.as_str(), quarantined.as_str()]),
        "the partial folder is kept aside, never deleted"
    );
    let kept = Path::new(INCLUDE).join("generations").join(&quarantined);
    assert_eq!(
        fs::metadata(kept.join(&files[0])).unwrap().len(),
        length / 2
    );
    assert!(!kept.join(files.last().unwrap()).exists());
    lab.log("quarantined", &quarantined);
}

/// W384: a crash inside the staging, after the temporary folder is written
/// and before its rename to the target id. Nothing has the target id, the
/// row has no effect mark, and `reconcile` records `untouched`. The next
/// activation to the same target stages it again and succeeds; the
/// temporary folder of the crash stays as it was (never read, never
/// deleted).
#[test]
#[ignore = "root lab test: run through docs/validation/S10-W380/run_faults.sh"]
fn w384_a_crash_inside_the_staging_leaves_no_target_folder_as_root() {
    let lab = Lab::new("staging");
    let (signed, first, second) = crash_running(&lab, Fault::DuringOlsStaging, ok());
    let mut executor = lab.open();
    let row = after_restart(&lab, &executor);
    assert_eq!(row.state, RecordedState::Intent);
    assert!(!row.effect_attempted && !row.compensation_attempted);
    assert_eq!(current(), Some(first.clone()));
    assert!(!staged(&second.0), "nothing has the target id");
    let leftovers = ols::leftovers(&ols::open_include().unwrap()).unwrap();
    assert_eq!(leftovers.len(), 1, "{leftovers:?}");
    let temporary = leftovers[0].clone();
    assert!(temporary.starts_with(&format!("{}{}", second.0.as_str(), ols::STAGING_MARK)));
    lab.log("leftover", (&temporary, generation_entries()));
    blocks_new_work(&lab, &mut executor, &signed, "op_run");
    assert_eq!(
        executor.compensate(&id("op_run"), now()).err(),
        Some(ExecutorError::CompensationDenied),
        "no effect, no restore"
    );
    no_serving_step_before_the_effect_mark(&row);
    let settled = executor.reconcile(&id("op_run")).unwrap();
    assert_eq!(settled.state, RecordedState::Untouched);
    assert!(
        lab.steps().is_empty(),
        "no helper step without the effect mark"
    );
    lab.log("reconcile", settled.state);
    next_activation_succeeds(&lab, &mut executor, &first);
    assert_eq!(current(), Some(second.clone()));
    assert_eq!(
        generation_entries(),
        sorted(&[first.0.as_str(), second.0.as_str(), temporary.as_str()]),
        "the temporary folder stays; nothing is quarantined"
    );
    lab.log("after the next activation", generation_entries());
}
