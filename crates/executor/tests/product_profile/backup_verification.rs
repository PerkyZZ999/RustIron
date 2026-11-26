//! Product backup verification through the kernel-credentialed socket handler.

use std::{
    fs,
    os::unix::fs::symlink,
    os::unix::net::UnixStream,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use rustiron_contracts::{
    CanonicalObject, ErrorCode, Id, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
    approval::{ProductBackupPolicy, Sha256Digest},
    execution::{SubmissionReply, decode_submission_reply, encode_submission},
    local::{self, DEADLINE},
};
use rustiron_executor::{Executor, ExecutorError, serve};
use serde_json::{Value, json};

use super::{BackupFixture, PROJECTION, PROJECTION_DIGEST, private_dir, private_file};

const VECTORS: &str = include_str!("../../../contracts/tests/fixtures/product-backup-vectors.json");

pub(super) struct SignedBackup {
    pub(super) plan: Vec<u8>,
    pub(super) grant: Vec<u8>,
    pub(super) signature: Vec<u8>,
}

impl SignedBackup {
    pub(super) fn new(fixture: &BackupFixture, plan: &Value, mut grant: Value) -> Self {
        let plan = serde_json::to_vec(plan).unwrap();
        let canonical = CanonicalObject::decode(&plan).unwrap();
        grant["plan_digest"] = json!(Sha256Digest::from_bytes(canonical.plan_domain_digest()));
        let grant = serde_json::to_vec(&grant).unwrap();
        let signature = fixture.sign(&grant);
        Self {
            plan,
            grant,
            signature,
        }
    }

    /// Sends one submission through the socket handler and decodes the reply.
    pub(super) fn submit(
        &self,
        executor: &mut Executor,
        operation_id: &Id,
        idempotency_key: &Id,
    ) -> SubmissionReply {
        let bytes = encode_submission(
            operation_id,
            idempotency_key,
            &self.plan,
            &self.grant,
            std::str::from_utf8(&self.signature).unwrap(),
        )
        .unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        local::write_frame(
            &mut client,
            &bytes,
            MAX_REQUEST_BYTES,
            ErrorCode::RequestTooLarge,
            Instant::now() + DEADLINE,
        )
        .unwrap();
        assert!(serve::handle(executor, server));
        let response = local::read_frame(
            &mut client,
            MAX_RESPONSE_BYTES,
            ErrorCode::ResponseTooLarge,
            Instant::now() + DEADLINE,
        )
        .unwrap();
        decode_submission_reply(&response, operation_id).unwrap()
    }

    fn expect(&self, executor: &mut Executor, error: ExecutorError) {
        let operation_id = Id::try_from("op_w311_verify".to_owned()).unwrap();
        let idempotency_key = Id::try_from("key_w311_verify".to_owned()).unwrap();
        let reply = self.submit(executor, &operation_id, &idempotency_key);
        assert_eq!(reply.operation_id, Some(operation_id.clone()));
        assert_eq!(reply.error.as_deref(), Some(error.code()));
        assert_eq!(reply.state, None);
        assert!(!reply.replay);
        assert!(executor.capture_status(&operation_id).unwrap().is_none());
        assert!(executor.probe_status(&operation_id).unwrap().is_none());
    }
}

pub(super) fn vectors() -> Vec<(Value, Value)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    vectors
        .into_iter()
        .map(|vector| {
            let mut plan: Value =
                serde_json::from_str(vector["plan_input"].as_str().unwrap()).unwrap();
            let mut grant: Value =
                serde_json::from_str(vector["grant_input"].as_str().unwrap()).unwrap();
            plan["destination_policy_digest"] = json!(PROJECTION_DIGEST.trim_end());
            for record in [&mut plan, &mut grant] {
                record["valid_from"] = json!(now - 30);
                record["expires_at"] = json!(now + 120);
            }
            (plan, grant)
        })
        .collect()
}

/// A verified request's refusal without admission: a capture or probe for
/// a site this journal never provisioned stops at the W319/W320 admission
/// precondition, before intent.
fn verified_outcome(_plan: &Value) -> ExecutorError {
    ExecutorError::PreconditionChanged
}

pub(super) fn enroll(fixture: &BackupFixture) -> Value {
    let mut policy = fixture.product_policy();
    policy["requester_uid"] = json!(rustix::process::getuid().as_raw());
    fixture.write_policy(&policy);
    private_file(&fixture.projection_path(), PROJECTION);
    private_file(
        &fixture.anchor.policy_dir.join("backup-ca.pem"),
        b"synthetic CA",
    );
    for account in ["rs_blog9", "rs_blog13"] {
        let directory = fixture
            .anchor
            .policy_dir
            .join("credentials/sites")
            .join(account);
        private_dir(&directory);
        private_file(&directory.join("fetch-aws"), b"synthetic fetch");
        private_file(&directory.join("repo.password"), b"synthetic password");
    }
    policy
}

#[test]
fn product_socket_refuses_missing_or_linked_fetch_credentials() {
    let fixture = BackupFixture::new();
    enroll(&fixture);
    let mut executor = Executor::initialize(fixture.anchor.clone()).unwrap();
    let before = fixture.replay_state();
    let (plan, grant) = vectors().into_iter().next().unwrap();
    let signed = SignedBackup::new(&fixture, &plan, grant);
    let directory = fixture.anchor.policy_dir.join("credentials/sites/rs_blog9");
    let fetch = directory.join("fetch-aws");
    let upload = directory.join("aws");
    private_file(&upload, b"synthetic upload");
    fs::remove_file(&fetch).unwrap();
    signed.expect(&mut executor, ExecutorError::AccessDenied);
    symlink("aws", &fetch).unwrap();
    signed.expect(&mut executor, ExecutorError::AccessDenied);
    fs::remove_file(&fetch).unwrap();
    private_file(&fetch, b"synthetic fetch");
    signed.expect(&mut executor, verified_outcome(&plan));
    assert_eq!(fixture.replay_state(), before);
}

#[test]
fn product_socket_verifies_both_verbs_without_admitting() {
    let fixture = BackupFixture::new();
    let policy = enroll(&fixture);
    let mut executor = Executor::initialize(fixture.anchor.clone()).unwrap();
    let before = fixture.replay_state();
    for (plan, grant) in vectors() {
        let signed = SignedBackup::new(&fixture, &plan, grant.clone());
        signed.expect(&mut executor, verified_outcome(&plan));

        let mut other_peer = policy.clone();
        other_peer["requester_uid"] = json!(rustix::process::getuid().as_raw().wrapping_add(1));
        fixture.write_policy(&other_peer);
        signed.expect(&mut executor, ExecutorError::PeerDenied);
        let mut other_epoch = policy.clone();
        other_epoch["host_epoch"] = json!("epoch_2");
        fixture.write_policy(&other_epoch);
        signed.expect(&mut executor, ExecutorError::IdentityMismatch);
        fixture.write_policy(&policy);

        let mut tampered: Value = serde_json::from_slice(&signed.grant).unwrap();
        tampered["nonce"] = json!("changed_nonce");
        SignedBackup {
            grant: serde_json::to_vec(&tampered).unwrap(),
            ..signed
        }
        .expect(&mut executor, ExecutorError::SignatureDenied);

        let mut wrong_scope = grant.clone();
        wrong_scope["site_ids"] = json!(["other1"]);
        SignedBackup::new(&fixture, &plan, wrong_scope)
            .expect(&mut executor, ExecutorError::BindingDenied);

        let mut expired_plan = plan;
        let mut expired_grant = grant;
        for record in [&mut expired_plan, &mut expired_grant] {
            record["valid_from"] = json!(1100);
            record["expires_at"] = json!(1200);
        }
        SignedBackup::new(&fixture, &expired_plan, expired_grant)
            .expect(&mut executor, ExecutorError::TimeDenied);
    }
    assert_eq!(fixture.replay_state(), before);
    assert_eq!(
        fs::read_dir(&fixture.anchor.scratch_dir).unwrap().count(),
        0
    );
}

#[test]
fn product_socket_checks_current_destination_and_site_after_authentication() {
    let fixture = BackupFixture::new();
    let policy = enroll(&fixture);
    let mut executor = Executor::initialize(fixture.anchor.clone()).unwrap();
    let before = fixture.replay_state();
    let mut projection: Value = serde_json::from_slice(PROJECTION).unwrap();
    projection["transport"]["endpoint_ipv4"] = json!("198.51.100.24");
    let changed_projection = serde_json::to_vec(&projection).unwrap();
    let changed_digest = ProductBackupPolicy::decode(&changed_projection)
        .unwrap()
        .digest();
    let mut changed_policy = policy.clone();
    changed_policy["product_backup"]["destination_policy_digest"] = json!(changed_digest);

    for (mut plan, mut grant) in vectors() {
        let signed = SignedBackup::new(&fixture, &plan, grant.clone());
        private_file(&fixture.projection_path(), &changed_projection);
        fixture.write_policy(&changed_policy);
        signed.expect(&mut executor, ExecutorError::PreconditionChanged);

        private_file(&fixture.projection_path(), PROJECTION);
        fixture.write_policy(&policy);
        let mut wrong_destination_plan = plan.clone();
        let mut wrong_destination_grant = grant.clone();
        wrong_destination_plan["destination_id"] = json!("other_store");
        wrong_destination_grant["destinations"] = json!(["other_store"]);
        SignedBackup::new(&fixture, &wrong_destination_plan, wrong_destination_grant)
            .expect(&mut executor, ExecutorError::PreconditionChanged);

        plan["site_id"] = json!("other1");
        grant["site_ids"] = json!(["other1"]);
        SignedBackup::new(&fixture, &plan, grant)
            .expect(&mut executor, ExecutorError::PreconditionChanged);
    }
    assert_eq!(fixture.replay_state(), before);
    assert_eq!(
        fs::read_dir(&fixture.anchor.scratch_dir).unwrap().count(),
        0
    );
}
