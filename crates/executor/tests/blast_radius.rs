//! W594 (P23, D-098): durable blast-radius envelope enforcement across
//! admissions, restarts/resumes, exact replays, and `Executor::observe`.

use std::{fs, os::unix::fs::symlink, path::PathBuf};

use rustiron_contracts::{
    Id, Timestamp,
    approval::{FixtureGrant, FixturePlan},
};
use rustiron_executor::{AdmissionRequest, Executor, ExecutorError, TrustAnchor};
use rustiron_journal::RecordResult;
use serde_json::{Value, json};

mod support;
use support::{KEYGEN, hex, new_key, private_dir, private_file, sign};

const PLAN: &str = include_str!("../../contracts/tests/fixtures/fixture-plan.json");
const GRANT: &str = include_str!("../../contracts/tests/fixtures/fixture-grant.json");
const OLD_CONTENT: &[u8] = b"alpha fixture\n";
const NEW_CONTENT: &[u8] = b"beta fixture\n";

struct EnvelopeLab {
    root: PathBuf,
    anchor: TrustAnchor,
}

impl Drop for EnvelopeLab {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl EnvelopeLab {
    fn new(name: &str, blast_radius: Value) -> Self {
        let root = std::env::temp_dir().join(format!("ri-p23-{name}-{}", std::process::id()));
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
        new_key(&root.join("keys/key"));
        let grant_tpl: Value = serde_json::from_str(GRANT).unwrap();
        let uid = rustix::process::getuid().as_raw();
        let verifier = hex(&fs::read(KEYGEN).unwrap());
        let policy = json!({
            "schema_version": 1,
            "host_id": grant_tpl["host_id"],
            "host_epoch": grant_tpl["host_epoch"],
            "profile_digest": grant_tpl["profile_digest"],
            "requester": grant_tpl["requester"],
            "requester_uid": uid,
            "issuer": grant_tpl["issuer"],
            "signer_policy_epoch": grant_tpl["signer_policy_epoch"],
            "verifier_sha256": verifier,
            "blast_radius": blast_radius,
        });
        private_file(
            &policy_dir.join("policy.json"),
            &serde_json::to_vec(&policy).unwrap(),
        );
        let pub_line = fs::read_to_string(root.join("keys/key.pub")).unwrap();
        let pub_key = pub_line
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        private_file(
            &policy_dir.join("allowed_signers"),
            format!("operator_1 namespaces=\"rustiron-plan-v1\" {pub_key}\n").as_bytes(),
        );
        private_file(&policy_dir.join("revocations"), b"");

        let resource = registry_dir.join("fixture_1");
        for generation in ["gen_old", "gen_new"] {
            let dir = resource.join("generations").join(generation);
            fs::create_dir_all(&dir).unwrap();
        }
        fs::write(resource.join("generations/gen_old/content"), OLD_CONTENT).unwrap();
        fs::write(resource.join("generations/gen_new/content"), NEW_CONTENT).unwrap();
        symlink("generations/gen_old", resource.join("current")).unwrap();

        let anchor = TrustAnchor {
            policy_dir,
            registry_dir,
            scratch_dir,
            journal_dir: journal_dir.clone(),
            mark_dir,
            recipes_dir: journal_dir,
            owner_uid: uid,
            admin_socket: None,
        };
        Self { root, anchor }
    }

    fn reset_current_to_old(&self) {
        let current = self.anchor.registry_dir.join("fixture_1/current");
        let _ = fs::remove_file(&current);
        symlink("generations/gen_old", current).unwrap();
    }

    fn make_request(
        &self,
        op_id: &str,
        nonce: &str,
        valid_from: u64,
        expires_at: u64,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut plan: Value = serde_json::from_str(PLAN).unwrap();
        plan["plan_id"] = json!(format!("plan_{op_id}"));
        plan["valid_from"] = json!(valid_from);
        plan["expires_at"] = json!(expires_at);
        plan["compensation"]["valid_until"] = json!(expires_at + 120);
        plan["observations"][0]["observed_at"] = json!(valid_from);
        plan["observations"][0]["content_digest"] = json!(hex(OLD_CONTENT));
        plan["artifact_digests"][0]["digest"] = json!(hex(NEW_CONTENT));
        let plan_bytes = serde_json::to_vec(&plan).unwrap();

        let mut grant: Value = serde_json::from_str(GRANT).unwrap();
        grant["grant_id"] = json!(format!("grant_{op_id}"));
        grant["nonce"] = json!(nonce);
        grant["plan_id"] = json!(format!("plan_{op_id}"));
        grant["plan_digest"] = json!(FixturePlan::decode(&plan_bytes).unwrap().digest().as_str());
        grant["valid_from"] = json!(valid_from);
        grant["expires_at"] = json!(expires_at);
        grant["compensation"]["valid_until"] = json!(expires_at + 120);
        let grant_bytes = serde_json::to_vec(&grant).unwrap();
        let canonical = FixtureGrant::decode(&grant_bytes)
            .unwrap()
            .as_bytes()
            .to_vec();
        let signature = sign(
            &self.root.join("keys/key"),
            &self.root.join(format!("keys/{op_id}.grant")),
            &canonical,
            "rustiron-plan-v1",
        );
        (plan_bytes, canonical, signature)
    }
}

#[test]
fn blast_radius_envelope_enforces_durably_across_restart_and_allows_exact_replay() {
    let lab = EnvelopeLab::new(
        "durable",
        json!({
            "window_seconds": 3600,
            "max_admissions_per_window": 1,
            "max_ols_reloads_per_window": 1,
            "max_served_sites_per_activation": 4,
            "max_total_admissions": 1,
            "max_total_ols_reloads": 1,
        }),
    );

    let mut executor = Executor::initialize(lab.anchor.clone()).unwrap();

    // Before any admission, observe reports 0 consumed and 1 remaining durably.
    let before = Executor::observe(&lab.anchor).unwrap();
    assert_eq!(before["authority_budget"]["enrolled"], true);
    assert_eq!(
        before["authority_budget"]["consumed"]["total_admissions"],
        0
    );
    assert_eq!(
        before["authority_budget"]["remaining"]["recent_admissions"],
        1
    );
    assert_eq!(
        before["authority_budget"]["remaining"]["total_admissions"],
        1
    );
    assert!(
        before["authority_budget"]["all_site_ols_impact"]
            .as_str()
            .unwrap()
            .contains("Global OLS reload")
    );

    let now = Timestamp::try_from(1200).unwrap();
    let (plan1, grant1, sig1) = lab.make_request("op_p23_1", "nonce_p23_1", 1100, 1900);
    let op1_id = Id::try_from("op_p23_1".to_owned()).unwrap();
    let key1 = Id::try_from("idem_p23_1".to_owned()).unwrap();
    let req1 = AdmissionRequest {
        operation_id: op1_id.clone(),
        idempotency_key: key1,
        plan: &plan1,
        grant: &grant1,
        signature: &sig1,
        peer_uid: lab.anchor.owner_uid,
        now: Some(now),
    };
    let first = executor
        .submit(&req1)
        .expect("first admission within budget");
    assert!(matches!(first, RecordResult::New(_)));
    executor.execute(&op1_id, Some(now)).expect("execute first");

    // Observe reports exact durable consumption and 0 remaining.
    let after = Executor::observe(&lab.anchor).unwrap();
    assert_eq!(after["authority_budget"]["consumed"]["total_admissions"], 1);
    assert_eq!(
        after["authority_budget"]["remaining"]["total_admissions"],
        0
    );

    // Close and reopen executor (simulating process restart / resume).
    drop(executor);
    let mut resumed = Executor::open(lab.anchor.clone()).unwrap();

    // Exact replay of op1 still returns Existing even with 0 remaining authority.
    let replay = resumed
        .submit(&req1)
        .expect("exact replay stays idempotent");
    assert!(matches!(replay, RecordResult::Existing(_)));

    // Reset fixture symlink so live precondition passes, then submit a 2nd new
    // operation: durable blast-radius budget MUST reject it after resume!
    lab.reset_current_to_old();
    let (plan2, grant2, sig2) = lab.make_request("op_p23_2", "nonce_p23_2", 1150, 1950);
    let op2_id = Id::try_from("op_p23_2".to_owned()).unwrap();
    let key2 = Id::try_from("idem_p23_2".to_owned()).unwrap();
    let req2 = AdmissionRequest {
        operation_id: op2_id,
        idempotency_key: key2,
        plan: &plan2,
        grant: &grant2,
        signature: &sig2,
        peer_uid: lab.anchor.owner_uid,
        now: Some(Timestamp::try_from(1250).unwrap()),
    };
    assert_eq!(
        resumed.submit(&req2).err(),
        Some(ExecutorError::PreconditionChanged)
    );

    // Total admissions in durable observation stay at 1 (rejected before intent).
    let final_obs = Executor::observe(&lab.anchor).unwrap();
    assert_eq!(
        final_obs["authority_budget"]["consumed"]["total_admissions"],
        1
    );
    assert_eq!(
        final_obs["authority_budget"]["remaining"]["total_admissions"],
        0
    );
}
