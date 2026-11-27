//! W377 (B06): the admission abuse matrix for `config_activate` plan v1,
//! the bootstrap activation (W355), the page-cache opt-in plan v2 (W368)
//! and the opt-out plan v3 (W370).
//!
//! Every case is refused before any journal row, with the journal and the
//! admission mark byte-identical. The include directory is fixed
//! (`/etc/rustiron-ols`), so on a host without it the unmodified control
//! request stops where the executor first opens that directory. That still
//! proves each abuse is refused by its own check, earlier. The checks after
//! the include (drift, opt-in and opt-out rules, intent, the helper steps
//! and the restore) need the lab host; see S10-W377.

use std::{fs, path::PathBuf};

use rustiron_contracts::{
    Id, Timestamp,
    approval::{OlsGrant, OlsPlan, Sha256Digest},
};
use rustiron_executor::{AdmissionRequest, Executor, ExecutorError, TrustAnchor, ols};
use rustiron_journal::{FixtureJournal, Intent, ProvisionIntent, ProvisionStep, RecordedState};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
mod support;
use support::{KEYGEN, hex, new_key, private_dir, private_file, sign};

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

const JOURNAL: &str = "fixture-journal.sqlite";
const MARK: &str = "admission-mark";
const PLAN_V1: &str = include_str!("../../contracts/tests/fixtures/ols-plan.json");
const GRANT_V1: &str = include_str!("../../contracts/tests/fixtures/ols-grant.json");
const V2: &str = include_str!("../../contracts/tests/fixtures/ols-plan-v2-vectors.json");
const V3: &str = include_str!("../../contracts/tests/fixtures/ols-plan-v3-vectors.json");
/// The executor's pin for `litespeed_cache_793_v1` (W368, `page_cache.rs`).
const RECIPE_SHA256: &str = "0db968c7e9ae8a17023f2db3fef1134ba006e1e3f104c3fe715b7f46534e20a9";

fn id(value: &str) -> Id {
    Id::try_from(value.to_owned()).unwrap()
}

fn time(value: u64) -> Timestamp {
    Timestamp::try_from(value).unwrap()
}

#[derive(Clone, Copy, Debug)]
enum Form {
    V1,
    Bootstrap,
    PageCacheOptIn,
    PageCacheOptOut,
}

impl Form {
    const ALL: [Self; 4] = [
        Self::V1,
        Self::Bootstrap,
        Self::PageCacheOptIn,
        Self::PageCacheOptOut,
    ];

    fn inputs(self) -> (Value, Value) {
        let vector = |all: &str| {
            let all: Vec<Value> = serde_json::from_str(all).unwrap();
            let first = &all[0];
            (
                serde_json::from_str::<Value>(first["plan_input"].as_str().unwrap()).unwrap(),
                serde_json::from_str::<Value>(first["grant_input"].as_str().unwrap()).unwrap(),
            )
        };
        let v1 = || {
            (
                serde_json::from_str(PLAN_V1).unwrap(),
                serde_json::from_str(GRANT_V1).unwrap(),
            )
        };
        match self {
            Self::V1 => v1(),
            Self::Bootstrap => {
                let (mut plan, grant): (Value, Value) = v1();
                let (generation, digest) = ols::bootstrap_generation();
                plan["expected_generation"] = json!(generation.as_str());
                plan["expected_digest"] = json!(digest.as_str());
                plan["observations"][0]["generation"] = json!(generation.as_str());
                plan["observations"][0]["content_digest"] = json!(digest.as_str());
                (plan, grant)
            }
            Self::PageCacheOptIn => {
                let (mut plan, grant) = vector(V2);
                plan["page_cache"]["recipe_digest"] = json!(RECIPE_SHA256);
                (plan, grant)
            }
            Self::PageCacheOptOut => vector(V3),
        }
    }
}

struct Lab {
    _serial: std::sync::MutexGuard<'static, ()>,
    root: PathBuf,
    anchor: TrustAnchor,
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
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
            now: Some(time(1200)),
        }
    }
}

impl Lab {
    fn new(name: &str) -> Self {
        let serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let root = std::env::temp_dir().join(format!("ri-w377-ols-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        private_dir(&root);
        for dir in ["policy", "registry", "scratch", "journal", "mark", "keys"] {
            private_dir(&root.join(dir));
        }
        for key in ["key", "other"] {
            new_key(&root.join("keys").join(key));
        }
        let anchor = TrustAnchor {
            owner_uid: rustix::process::getuid().as_raw(),
            policy_dir: root.join("policy"),
            registry_dir: root.join("registry"),
            scratch_dir: root.join("scratch"),
            journal_dir: root.join("journal"),
            mark_dir: root.join("mark"),
            recipes_dir: root.join("journal"),
            admin_socket: None,
        };
        let lab = Self {
            _serial: serial,
            root,
            anchor,
        };
        lab.write_policy(|_| {});
        let public = fs::read_to_string(lab.root.join("keys/key.pub")).unwrap();
        let public: Vec<_> = public.split_whitespace().take(2).collect();
        private_file(
            &lab.anchor.policy_dir.join("allowed_signers"),
            format!(
                "operator_1 namespaces=\"rustiron-plan-v1\" {}\n",
                public.join(" ")
            )
            .as_bytes(),
        );
        private_file(&lab.anchor.policy_dir.join("revocations"), b"");
        drop(Executor::initialize(lab.anchor.clone()).unwrap());
        lab.provision(&["blog5", "blog6", "blog7"]);
        lab
    }

    fn write_policy(&self, edit: impl FnOnce(&mut Value)) {
        let mut policy = json!({
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
                "listener": "W377", "address": "127.0.0.1:8090", "adopted": [],
                "parent_sha256": "b".repeat(64), "webadmin_port": 7080,
            },
        });
        edit(&mut policy);
        private_file(
            &self.anchor.policy_dir.join("policy.json"),
            &serde_json::to_vec(&policy).unwrap(),
        );
    }

    fn journal(&self) -> FixtureJournal {
        FixtureJournal::open_as_process_owner(
            &self.anchor.journal_dir,
            id("host_lab"),
            id("epoch_1"),
        )
        .unwrap()
    }

    /// Succeeded provisions of `sites`, recorded the way the journal requires.
    fn provision(&self, sites: &[&str]) {
        let mut journal = self.journal();
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
                expires_at: time(4_000_000_000),
            };
            journal.record_provision(&intent, time(1100)).unwrap();
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

    /// A signed request of `form` with `plan_edit` and `grant_edit`, by `key`.
    fn signed_with(
        &self,
        form: Form,
        nonce: &str,
        key: &str,
        plan_edit: impl FnOnce(&mut Value),
        grant_edit: impl FnOnce(&mut Value),
    ) -> Signed {
        let (mut plan, mut grant) = form.inputs();
        plan_edit(&mut plan);
        let plan = serde_json::to_vec(&plan).unwrap();
        grant["plan_digest"] = json!(OlsPlan::decode(&plan).unwrap().digest().as_str());
        grant["grant_id"] = json!(format!("grant_{nonce}"));
        grant["nonce"] = json!(nonce);
        grant_edit(&mut grant);
        let grant = serde_json::to_vec(&grant).unwrap();
        let signature = sign(
            &self.root.join("keys").join(key),
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

    fn signed(&self, form: Form, nonce: &str) -> Signed {
        self.signed_with(form, nonce, "key", |_| {}, |_| {})
    }

    fn replay_state(&self) -> (Vec<u8>, Vec<u8>) {
        (
            fs::read(self.anchor.journal_dir.join(JOURNAL)).unwrap(),
            fs::read(self.anchor.mark_dir.join(MARK)).unwrap(),
        )
    }

    /// A finished OLS operation for exactly `signed` under `operation`.
    fn record_finished(&self, signed: &Signed, operation: &str) {
        let plan = OlsPlan::decode(&signed.plan).unwrap();
        let grant = OlsGrant::decode(&signed.grant).unwrap();
        let (expected, expected_digest) = plan.expected();
        let target = Sha256Digest::from_bytes([7; 32]);
        let intent = Intent {
            operation_id: id(operation),
            idempotency_key: id(&format!("key_{operation}")),
            grant_id: grant.grant_id().clone(),
            nonce: grant.nonce().clone(),
            plan_digest: plan.digest(),
            grant_digest: Sha256Digest::from_bytes(Sha256::digest(grant.as_bytes()).into()),
            host_id: id("host_lab"),
            host_epoch: id("epoch_1"),
            resource_id: id("ols_lab_listener"),
            predecessor_generation: expected.clone(),
            predecessor_digest: expected_digest.clone(),
            target_generation: ols::generation_id(&target),
            target_digest: target.clone(),
            expires_at: grant.expires_at(),
            compensation_valid_until: grant.compensation_valid_until(),
        };
        let mut journal = self.journal();
        journal.record_intent(&intent, time(1150)).unwrap();
        journal.mark_effect_attempted(&intent.operation_id).unwrap();
        let state = journal
            .record_observation(
                &intent.operation_id,
                Some(&intent.target_generation),
                Some(&intent.target_digest),
            )
            .unwrap()
            .state;
        assert_eq!(state, RecordedState::Succeeded);
    }
}

/// One refusal: its code, no row for the operation, and the journal and
/// admission mark byte-identical.
fn refused(
    lab: &Lab,
    executor: &mut Executor,
    request: &AdmissionRequest<'_>,
    error: ExecutorError,
    case: &str,
) {
    let before = lab.replay_state();
    let fresh = executor.status(&request.operation_id).unwrap().is_none();
    assert_eq!(executor.activate_ols(request).err(), Some(error), "{case}");
    assert!(lab.replay_state() == before, "{case} wrote state");
    if fresh {
        assert_eq!(
            executor.status(&request.operation_id).unwrap(),
            None,
            "{case} left a row"
        );
    }
}

fn admission_abuse_is_refused_before_any_row(form: Form) {
    let lab = Lab::new(&format!("{form:?}").to_lowercase());
    let valid = lab.signed(form, "w377");
    let admitted = lab.signed(form, "w377_admitted");
    lab.record_finished(&admitted, "op_w377_admitted");
    let mut executor = Executor::open(lab.anchor.clone()).unwrap();
    let operation = "op_w377";
    let case = |name: &str| format!("{form:?}: {name}");

    let mut request = valid.request(operation);
    request.peer_uid = 4243;
    refused(
        &lab,
        &mut executor,
        &request,
        ExecutorError::PeerDenied,
        &case("peer"),
    );

    let mut tampered = valid.clone();
    tampered.signature[40] ^= 1;
    refused(
        &lab,
        &mut executor,
        &tampered.request(operation),
        ExecutorError::SignatureDenied,
        &case("tampered signature"),
    );

    let forged = lab.signed_with(form, "w377", "other", |_| {}, |_| {});
    refused(
        &lab,
        &mut executor,
        &forged.request(operation),
        ExecutorError::SignatureDenied,
        &case("forged signer"),
    );

    let public = fs::read(lab.root.join("keys/key.pub")).unwrap();
    private_file(&lab.anchor.policy_dir.join("revocations"), &public);
    refused(
        &lab,
        &mut executor,
        &valid.request(operation),
        ExecutorError::SignatureDenied,
        &case("revoked signer"),
    );
    private_file(&lab.anchor.policy_dir.join("revocations"), b"");

    for now in [Some(time(1900)), None] {
        let mut request = valid.request(operation);
        request.now = now;
        refused(
            &lab,
            &mut executor,
            &request,
            ExecutorError::TimeDenied,
            &case("time"),
        );
    }

    let other_plan = lab.signed_with(
        form,
        "w377",
        "key",
        |plan| plan["expires_at"] = json!(1999),
        |_| {},
    );
    let substituted = Signed {
        plan: other_plan.plan,
        grant: valid.grant.clone(),
        signature: valid.signature.clone(),
    };
    refused(
        &lab,
        &mut executor,
        &substituted.request(operation),
        ExecutorError::BindingDenied,
        &case("plan digest"),
    );

    for (field, value) in [("host_id", "host_other"), ("host_epoch", "epoch_9")] {
        let other = lab.signed_with(
            form,
            "w377",
            "key",
            |plan| plan[field] = json!(value),
            |grant| grant[field] = json!(value),
        );
        refused(
            &lab,
            &mut executor,
            &other.request(operation),
            ExecutorError::BindingDenied,
            &case(field),
        );
    }

    // The admitted operation: the exact request is status only; another
    // idempotency key or other bytes under its ID are a replay refusal.
    let before = lab.replay_state();
    assert!(matches!(
        executor.activate_ols(&admitted.request("op_w377_admitted")),
        Ok(rustiron_journal::Admitted::Existing(operation))
            if operation.state == RecordedState::Succeeded
    ));
    assert!(lab.replay_state() == before, "an exact replay wrote state");
    let mut other_key = admitted.request("op_w377_admitted");
    other_key.idempotency_key = id("key_w377_other");
    refused(
        &lab,
        &mut executor,
        &other_key,
        ExecutorError::ReplayDenied,
        &case("operation ID, other key"),
    );
    let mut other_bytes = valid.request("op_w377_admitted");
    other_bytes.idempotency_key = id("key_op_w377_admitted");
    refused(
        &lab,
        &mut executor,
        &other_bytes,
        ExecutorError::ReplayDenied,
        &case("operation ID, other bytes"),
    );

    // A site this journal never provisioned.
    let unprovisioned = lab.signed_with(
        form,
        "w377",
        "key",
        |plan| plan["site_ids"] = json!(["blog5", "blog8"]),
        |grant| grant["site_ids"] = json!(["blog5", "blog8"]),
    );
    refused(
        &lab,
        &mut executor,
        &unprovisioned.request(operation),
        ExecutorError::PreconditionChanged,
        &case("unprovisioned site"),
    );

    // F1: a policy re-enrolled to another epoch while this journal is open.
    lab.write_policy(|policy| policy["host_epoch"] = json!("epoch_2"));
    let rotated = lab.signed_with(
        form,
        "w377",
        "key",
        |plan| plan["host_epoch"] = json!("epoch_2"),
        |grant| grant["host_epoch"] = json!("epoch_2"),
    );
    refused(
        &lab,
        &mut executor,
        &rotated.request(operation),
        ExecutorError::IdentityMismatch,
        &case("re-enrolled epoch"),
    );
    // No OLS enrollment.
    lab.write_policy(|policy| {
        policy.as_object_mut().unwrap().remove("ols");
    });
    refused(
        &lab,
        &mut executor,
        &valid.request(operation),
        ExecutorError::Unavailable,
        &case("no OLS enrollment"),
    );
    lab.write_policy(|_| {});

    // Control: the unmodified request passes every check above and stops
    // only where the host's include directory is first opened.
    if let Err(include) = ols::open_include() {
        refused(
            &lab,
            &mut executor,
            &valid.request(operation),
            include,
            &case("control without the include directory"),
        );
    }
}

#[test]
fn w377_config_activate_v1_abuse_is_refused_before_any_row() {
    admission_abuse_is_refused_before_any_row(Form::V1);
}

#[test]
fn w377_bootstrap_activation_abuse_is_refused_before_any_row() {
    admission_abuse_is_refused_before_any_row(Form::Bootstrap);
}

#[test]
fn w377_page_cache_opt_in_abuse_is_refused_before_any_row() {
    admission_abuse_is_refused_before_any_row(Form::PageCacheOptIn);
}

#[test]
fn w377_page_cache_opt_out_abuse_is_refused_before_any_row() {
    admission_abuse_is_refused_before_any_row(Form::PageCacheOptOut);
}

/// W368: an opt-in plan must name the executor's own recipe pin.
#[test]
fn w377_an_opt_in_with_another_recipe_digest_is_a_binding_refusal() {
    let lab = Lab::new("recipe");
    let mut executor = Executor::open(lab.anchor.clone()).unwrap();
    let other = lab.signed_with(
        Form::PageCacheOptIn,
        "w377r",
        "key",
        |plan| plan["page_cache"]["recipe_digest"] = json!("e".repeat(64)),
        |_| {},
    );
    refused(
        &lab,
        &mut executor,
        &other.request("op_w377r"),
        ExecutorError::BindingDenied,
        "recipe digest",
    );
}

/// W395: the cache-on recipe must name its own manifest digest. The W368
/// archive digest, the settings pin or any other value is a binding refusal
/// before any row.
#[test]
fn w395_a_cache_on_opt_in_with_another_recipe_digest_is_a_binding_refusal() {
    let lab = Lab::new("cache-on");
    let mut executor = Executor::open(lab.anchor.clone()).unwrap();
    for (tag, digest) in [
        ("w395a", RECIPE_SHA256.to_owned()),
        (
            "w395b",
            "fec9698019115ae148051642af24ca9f26b0e9d70703e7d1aee1a90c28ab30f7".to_owned(),
        ),
        ("w395c", "e".repeat(64)),
    ] {
        let other = lab.signed_with(
            Form::PageCacheOptIn,
            tag,
            "key",
            |plan| {
                plan["page_cache"]["recipe_id"] = json!("litespeed_cache_793_cache_on_v1");
                plan["page_cache"]["recipe_digest"] = json!(digest);
            },
            |_| {},
        );
        refused(
            &lab,
            &mut executor,
            &other.request(&format!("op_{tag}")),
            ExecutorError::BindingDenied,
            "cache-on recipe digest",
        );
    }
}

/// The W370 single restore of a page-cache change (`compensate`, also
/// with `--admin-helper`) crashes after its durable compensation mark: the
/// row stays `compensating` with its journaled site, a second restore is
/// refused, and nothing else is written. The crash points inside the OLS
/// activation itself need the host include directory (lab gap, S10-W377).
#[test]
fn w377_a_crash_after_the_page_cache_restore_mark_never_restores_twice() {
    for opt_in in [true, false] {
        let lab = Lab::new(if opt_in { "restore-in" } else { "restore-out" });
        let change = |name: &str, from: u8, to: u8| {
            let (predecessor, target) = (
                Sha256Digest::from_bytes([from; 32]),
                Sha256Digest::from_bytes([to; 32]),
            );
            Intent {
                operation_id: id(&format!("op_{name}")),
                idempotency_key: id(&format!("key_{name}")),
                grant_id: id(&format!("grant_{name}")),
                nonce: id(&format!("nonce_{name}")),
                plan_digest: Sha256Digest::from_bytes([1; 32]),
                grant_digest: Sha256Digest::from_bytes([2; 32]),
                host_id: id("host_lab"),
                host_epoch: id("epoch_1"),
                resource_id: id("ols_lab_listener"),
                predecessor_generation: ols::generation_id(&predecessor),
                predecessor_digest: predecessor,
                target_generation: ols::generation_id(&target),
                target_digest: target,
                expires_at: time(1900),
                compensation_valid_until: time(2100),
            }
        };
        let intent = if opt_in {
            change("w377_cache", 3, 7)
        } else {
            change("w377_cache", 7, 8)
        };
        let site = "blog5".to_owned().try_into().unwrap();
        {
            let mut journal = lab.journal();
            // A verified activation from the bootstrap generation, so the
            // journal explains generation 3 in both profiles (W362).
            let mut base = change("w377_base", 0, 3);
            let (bootstrap, empty) = ols::bootstrap_generation();
            base.predecessor_generation = bootstrap;
            base.predecessor_digest = empty;
            journal.record_intent(&base, time(1130)).unwrap();
            journal.mark_effect_attempted(&base.operation_id).unwrap();
            journal
                .record_observation(
                    &base.operation_id,
                    Some(&base.target_generation),
                    Some(&base.target_digest),
                )
                .unwrap();
            if !opt_in {
                // An opt-out needs a verified opt-in of the site first.
                let opted = change("w377_cache_in", 3, 7);
                journal
                    .record_page_cache_intent(&opted, &site, "litespeed_cache_793_v1", time(1140))
                    .unwrap();
                journal.mark_effect_attempted(&opted.operation_id).unwrap();
                journal
                    .record_observation(
                        &opted.operation_id,
                        Some(&opted.target_generation),
                        Some(&opted.target_digest),
                    )
                    .unwrap();
            }
            if opt_in {
                journal
                    .record_page_cache_intent(&intent, &site, "litespeed_cache_793_v1", time(1150))
                    .unwrap();
            } else {
                journal
                    .record_page_cache_opt_out_intent(
                        &intent,
                        &site,
                        "litespeed_cache_793_v1",
                        time(1150),
                    )
                    .unwrap();
            }
            journal.mark_effect_attempted(&intent.operation_id).unwrap();
            let state = journal
                .record_observation(&intent.operation_id, None, None)
                .unwrap()
                .state;
            assert_eq!(state, RecordedState::NeedsAttention);
        }
        let mut anchor = lab.anchor.clone();
        anchor.admin_socket = Some(lab.root.join("helper.sock"));
        let mut executor = Executor::open(anchor.clone()).unwrap();
        executor.inject_fault(rustiron_executor::Fault::AfterCompensationMark);
        assert_eq!(
            executor
                .compensate(&intent.operation_id, Some(time(1300)))
                .err(),
            Some(ExecutorError::Unavailable)
        );
        drop(executor);
        let mut executor = Executor::open(anchor).unwrap();
        let row = executor.status(&intent.operation_id).unwrap().unwrap();
        assert_eq!(row.state, RecordedState::Compensating);
        assert!(row.compensation_attempted);
        let before = lab.replay_state();
        assert_eq!(
            executor
                .compensate(&intent.operation_id, Some(time(1310)))
                .err(),
            Some(ExecutorError::CompensationDenied),
            "a second restore"
        );
        assert!(lab.replay_state() == before);
        drop(executor);
        let journal = lab.journal();
        let recorded = if opt_in {
            journal.page_cache_site(&intent.operation_id).unwrap()
        } else {
            journal
                .page_cache_opt_out_site(&intent.operation_id)
                .unwrap()
        };
        assert_eq!(recorded, Some(site));
    }
}

/// F1 for `site_eject`, which shares the activation path: a re-enrolled
/// epoch is a journal identity mismatch before the include is read.
#[test]
fn w377_an_eject_under_a_re_enrolled_epoch_is_an_identity_mismatch() {
    let lab = Lab::new("eject-identity");
    let mut executor = Executor::open(lab.anchor.clone()).unwrap();
    lab.write_policy(|policy| policy["host_epoch"] = json!("epoch_2"));
    let mut plan: Value = serde_json::from_str(include_str!(
        "../../contracts/tests/fixtures/eject-plan.json"
    ))
    .unwrap();
    plan["host_epoch"] = json!("epoch_2");
    let plan = serde_json::to_vec(&plan).unwrap();
    let mut grant: Value = serde_json::from_str(include_str!(
        "../../contracts/tests/fixtures/eject-grant.json"
    ))
    .unwrap();
    grant["host_epoch"] = json!("epoch_2");
    grant["plan_digest"] = json!(
        rustiron_contracts::approval::EjectPlan::decode(&plan)
            .unwrap()
            .digest()
            .as_str()
    );
    let grant = serde_json::to_vec(&grant).unwrap();
    let signature = sign(
        &lab.root.join("keys/key"),
        &lab.root.join("message"),
        rustiron_contracts::approval::EjectGrant::decode(&grant)
            .unwrap()
            .as_bytes(),
        "rustiron-plan-v1",
    );
    let signed = Signed {
        plan,
        grant,
        signature,
    };
    let before = lab.replay_state();
    assert_eq!(
        executor.eject_site(&signed.request("op_w377_eject")).err(),
        Some(ExecutorError::IdentityMismatch)
    );
    assert!(lab.replay_state() == before);
    assert_eq!(executor.status(&id("op_w377_eject")).unwrap(), None);
}

/// An activation that names an ejected site is refused before the include
/// is read, for every form.
#[test]
fn w377_an_ejected_site_is_refused_for_every_form() {
    let lab = Lab::new("ejected");
    let ejected = Sha256Digest::from_bytes([9; 32]);
    let intent = Intent {
        operation_id: id("op_eject_blog6"),
        idempotency_key: id("key_eject_blog6"),
        grant_id: id("grant_eject_blog6"),
        nonce: id("nonce_eject_blog6"),
        plan_digest: Sha256Digest::from_bytes([1; 32]),
        grant_digest: Sha256Digest::from_bytes([2; 32]),
        host_id: id("host_lab"),
        host_epoch: id("epoch_1"),
        resource_id: id("ols_lab_listener"),
        predecessor_generation: id("g1"),
        predecessor_digest: Sha256Digest::from_bytes([3; 32]),
        target_generation: ols::generation_id(&ejected),
        target_digest: ejected.clone(),
        expires_at: time(1900),
        compensation_valid_until: time(2100),
    };
    {
        let mut journal = lab.journal();
        journal
            .record_ejection_intent(&intent, &"blog6".to_owned().try_into().unwrap(), time(1150))
            .unwrap();
        journal.mark_effect_attempted(&intent.operation_id).unwrap();
        journal
            .record_observation(
                &intent.operation_id,
                Some(&intent.target_generation),
                Some(&ejected),
            )
            .unwrap();
        assert_eq!(journal.ejected_sites().unwrap().len(), 1);
    }
    let mut executor = Executor::open(lab.anchor.clone()).unwrap();
    for form in Form::ALL {
        let signed = lab.signed(form, &format!("w377e_{form:?}").to_lowercase());
        refused(
            &lab,
            &mut executor,
            &signed.request("op_w377e"),
            ExecutorError::PreconditionChanged,
            &format!("{form:?}: ejected site"),
        );
    }
}
