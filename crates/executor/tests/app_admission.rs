//! W598 (P27 Slice 3, D-099): executor admission checks for `app_provision`,
//! `app_deploy`, and `app_lifecycle` (SSHSIG, reserved ports, quota cap,
//! unknown site preflight, and D-098 blast-radius enforcement). No root host
//! mutations run here.

use std::{fs, path::PathBuf};

use rustiron_contracts::{
    CanonicalObject, Id, Timestamp,
    approval::{AppDeployPlan, AppLifecyclePlan, AppProvisionPlan},
};
use rustiron_executor::{AdmissionRequest, Executor, ExecutorError, TrustAnchor};
use serde_json::{Value, json};

mod support;
use support::{KEYGEN, hex, new_key, private_dir, private_file, sign};

struct AppLab {
    root: PathBuf,
    anchor: TrustAnchor,
}

impl Drop for AppLab {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl AppLab {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("ri-p27-adm-{name}-{}", std::process::id()));
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
        let uid = rustix::process::getuid().as_raw();
        let verifier = hex(&fs::read(KEYGEN).unwrap());
        let policy = json!({
            "schema_version": 1,
            "host_id": "host_lab",
            "host_epoch": "epoch_1",
            "profile_digest": "a".repeat(64),
            "requester": "agent_1",
            "requester_uid": uid,
            "issuer": "operator_1",
            "signer_policy_epoch": "policy_1",
            "verifier_sha256": verifier,
            "provisioning": {
                "wordpress_713_sha256": "e".repeat(64),
                "uid_min": 20000,
                "uid_max": 20999,
                "category_min": 200,
                "category_max": 299,
                "quota": {
                    "block_hard_kib": 1_048_576,
                    "inode_hard": 10000
                }
            },
            "ols": {
                "listener": "lab_http",
                "address": "127.0.0.1:8088",
                "adopted": [],
                "parent_sha256": "f".repeat(64),
                "webadmin_port": 7080
            }
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

        let anchor = TrustAnchor {
            owner_uid: uid,
            policy_dir,
            registry_dir,
            scratch_dir,
            journal_dir,
            mark_dir,
            recipes_dir: root.join("recipes"),
            admin_socket: None,
        };
        Executor::initialize(anchor.clone()).unwrap();
        Self { root, anchor }
    }

    fn sign_grant(&self, grant: &Value) -> (Vec<u8>, Vec<u8>) {
        let canonical = CanonicalObject::decode(grant.to_string().as_bytes())
            .unwrap()
            .as_bytes()
            .to_vec();
        let msg = self.root.join("msg.json");
        let sig = sign(
            &self.root.join("keys/key"),
            &msg,
            &canonical,
            "rustiron-plan-v1",
        );
        (canonical, sig)
    }
}

fn id(text: &str) -> Id {
    Id::try_from(text.to_owned()).unwrap()
}

fn canonical(value: &Value) -> Vec<u8> {
    CanonicalObject::decode(value.to_string().as_bytes())
        .unwrap()
        .as_bytes()
        .to_vec()
}

fn grant_for(plan_id: &str, plan_digest: &str, verb: &str, idx: u64) -> Value {
    json!({
        "schema_version": 1,
        "grant_id": format!("grant_{verb}_{idx}"),
        "nonce": format!("nonce_{verb}_{idx}"),
        "plan_id": plan_id,
        "plan_digest": plan_digest,
        "host_id": "host_lab",
        "host_epoch": "epoch_1",
        "profile_digest": "a".repeat(64),
        "issuer": "operator_1",
        "requester": "agent_1",
        "signer_policy_epoch": "policy_1",
        "site_ids": ["emdash1"],
        "verbs": [verb],
        "risk_class": "lab_only",
        "valid_from": 1100,
        "expires_at": 1900,
        "max_operations": 1
    })
}

#[test]
fn app_provision_refuses_reserved_ols_port_and_over_cap_quota_before_intent() {
    let lab = AppLab::new("prov-refuse");
    let mut exec = Executor::open(lab.anchor.clone()).unwrap();
    let uid = lab.anchor.owner_uid;

    // 1. Enrolled OLS listener port 8088 is refused before intent.
    let bad_port_plan = canonical(&json!({
        "schema_version": 1,
        "plan_id": "plan_ap_badport",
        "host_id": "host_lab",
        "host_epoch": "epoch_1",
        "profile_digest": "a".repeat(64),
        "requester": "agent_1",
        "verb": "app_provision",
        "site_id": "emdash1",
        "hostname": "emdash.example.test",
        "runtime": "node_22_v1",
        "port": 8088,
        "routes": [{"prefix": "/", "port": 8088}],
        "websockets": [],
        "entrypoint": "dist/server.js",
        "health_path": "/health",
        "env_keys": [],
        "memory_max_mib": 512,
        "tasks_max": 64,
        "quota_mib": 512,
        "expected_effects": {
            "creates_account": true,
            "forwards_to_loopback": true,
            "installs_app_unit": true,
            "traffic_activation": false,
            "runs_package_scripts": false
        },
        "risk_class": "lab_only",
        "valid_from": 1000,
        "expires_at": 2000,
        "limitations": ["test"]
    }));
    let decoded = AppProvisionPlan::decode(&bad_port_plan).unwrap();
    let (grant, sig) = lab.sign_grant(&grant_for(
        "plan_ap_badport",
        decoded.digest().as_str(),
        "app_provision",
        1,
    ));
    let req = AdmissionRequest {
        peer_uid: uid,
        plan: &bad_port_plan,
        grant: &grant,
        signature: &sig,
        operation_id: id("op_ap_1"),
        idempotency_key: id("key_ap_1"),
        now: Some(Timestamp::try_from(1500).unwrap()),
    };
    assert_eq!(exec.provision_app(&req), Err(ExecutorError::BindingDenied));

    // 2. Quota exceeding enrolled 1024 MiB cap (2048 MiB) is refused before intent.
    let over_quota_plan = canonical(&json!({
        "schema_version": 1,
        "plan_id": "plan_ap_quota",
        "host_id": "host_lab",
        "host_epoch": "epoch_1",
        "profile_digest": "a".repeat(64),
        "requester": "agent_1",
        "verb": "app_provision",
        "site_id": "emdash1",
        "hostname": "emdash.example.test",
        "runtime": "node_22_v1",
        "port": 43187,
        "routes": [{"prefix": "/", "port": 43187}],
        "websockets": [],
        "entrypoint": "dist/server.js",
        "health_path": "/health",
        "env_keys": [],
        "memory_max_mib": 512,
        "tasks_max": 64,
        "quota_mib": 2048,
        "expected_effects": {
            "creates_account": true,
            "forwards_to_loopback": true,
            "installs_app_unit": true,
            "traffic_activation": false,
            "runs_package_scripts": false
        },
        "risk_class": "lab_only",
        "valid_from": 1000,
        "expires_at": 2000,
        "limitations": ["test"]
    }));
    let decoded_q = AppProvisionPlan::decode(&over_quota_plan).unwrap();
    let (grant_q, sig_q) = lab.sign_grant(&grant_for(
        "plan_ap_quota",
        decoded_q.digest().as_str(),
        "app_provision",
        2,
    ));
    let req_q = AdmissionRequest {
        peer_uid: uid,
        plan: &over_quota_plan,
        grant: &grant_q,
        signature: &sig_q,
        operation_id: id("op_ap_2"),
        idempotency_key: id("key_ap_2"),
        now: Some(Timestamp::try_from(1500).unwrap()),
    };
    assert_eq!(
        exec.provision_app(&req_q),
        Err(ExecutorError::BindingDenied)
    );

    // 3. Signed app_deploy & app_lifecycle for an unprovisioned site fail closed with zero intent committed.
    let deploy_plan = canonical(&json!({
        "schema_version": 1,
        "plan_id": "plan_ad_1",
        "host_id": "host_lab",
        "host_epoch": "epoch_1",
        "profile_digest": "a".repeat(64),
        "requester": "agent_1",
        "verb": "app_deploy",
        "site_id": "emdash1",
        "release_id": "rel-1",
        "runtime": "node_22_v1",
        "artifact_sha256": "b".repeat(64),
        "manifest_sha256": "c".repeat(64),
        "file_count": 10,
        "total_bytes": 1024,
        "health_path": "/health",
        "expected_effects": {
            "unpacks_as_site": true,
            "switches_release": true,
            "restarts_app_unit": true,
            "rolls_back_on_failed_health": true,
            "runs_package_scripts": false,
            "traffic_activation": false
        },
        "risk_class": "lab_only",
        "valid_from": 1000,
        "expires_at": 2000,
        "limitations": ["test"]
    }));
    let decoded_d = AppDeployPlan::decode(&deploy_plan).unwrap();
    let (grant_d, sig_d) = lab.sign_grant(&grant_for(
        "plan_ad_1",
        decoded_d.digest().as_str(),
        "app_deploy",
        3,
    ));
    let req_d = AdmissionRequest {
        peer_uid: uid,
        plan: &deploy_plan,
        grant: &grant_d,
        signature: &sig_d,
        operation_id: id("op_ad_1"),
        idempotency_key: id("key_ad_1"),
        now: Some(Timestamp::try_from(1500).unwrap()),
    };
    assert_eq!(
        exec.deploy_app(&req_d),
        Err(ExecutorError::PreconditionChanged)
    );

    let lc_plan = canonical(&json!({
        "schema_version": 1,
        "plan_id": "plan_al_1",
        "host_id": "host_lab",
        "host_epoch": "epoch_1",
        "profile_digest": "a".repeat(64),
        "requester": "agent_1",
        "verb": "app_lifecycle",
        "site_id": "emdash1",
        "action": "restart",
        "expected_effects": {
            "changes_app_unit_state": true,
            "reloads_ols": false,
            "changes_files": false
        },
        "risk_class": "lab_only",
        "valid_from": 1000,
        "expires_at": 2000,
        "limitations": ["test"]
    }));
    let decoded_l = AppLifecyclePlan::decode(&lc_plan).unwrap();
    let (grant_l, sig_l) = lab.sign_grant(&grant_for(
        "plan_al_1",
        decoded_l.digest().as_str(),
        "app_lifecycle",
        4,
    ));
    let req_l = AdmissionRequest {
        peer_uid: uid,
        plan: &lc_plan,
        grant: &grant_l,
        signature: &sig_l,
        operation_id: id("op_al_1"),
        idempotency_key: id("key_al_1"),
        now: Some(Timestamp::try_from(1500).unwrap()),
    };
    assert_eq!(
        exec.app_lifecycle(&req_l),
        Err(ExecutorError::PreconditionChanged)
    );

    // Zero admissions were committed by any refusal.
    let obs = Executor::observe(&lab.anchor).unwrap();
    assert_eq!(obs["authority_budget"]["consumed"]["total_admissions"], 0);
}

#[test]
fn w659_schema_v2_fullstack_caddy_enrollment_and_blue_green_admission_guards() {
    // 1. Without a `caddy` section enrolled, a schema v2 Caddy app_provision is
    // refused fail-closed with Unavailable before committing any intent.
    let lab_no_caddy = AppLab::new("v2-no-caddy");
    let mut exec_no_caddy = Executor::open(lab_no_caddy.anchor.clone()).unwrap();
    let uid = lab_no_caddy.anchor.owner_uid;

    let caddy_plan = canonical(&json!({
        "schema_version": 2,
        "plan_id": "plan_v2_split",
        "host_id": "host_lab",
        "host_epoch": "epoch_1",
        "profile_digest": "a".repeat(64),
        "requester": "agent_1",
        "verb": "app_provision",
        "site_id": "emdash1",
        "hostname": "shop.example.test",
        "ingress": "caddy",
        "topology": "fullstack_split",
        "database": "postgresql_18",
        "runtime": "bun_1_v1",
        "port": 43210,
        "blue_green": true,
        "standby_port": 43211,
        "spa_fallback": true,
        "frontend_dir": "frontend",
        "routes": [{"prefix": "/api/", "port": 43210}],
        "websockets": [],
        "sse_prefixes": ["/api/events/"],
        "entrypoint": "backend/server.ts",
        "health_path": "/api/health",
        "env_keys": ["DATABASE_URL"],
        "memory_max_mib": 512,
        "tasks_max": 64,
        "quota_mib": 512,
        "expected_effects": {
            "creates_account": true,
            "forwards_to_loopback": true,
            "installs_app_unit": true,
            "creates_database": true,
            "traffic_activation": false,
            "runs_package_scripts": false
        },
        "risk_class": "lab_only",
        "valid_from": 1000,
        "expires_at": 2000,
        "limitations": ["test"]
    }));
    let decoded = AppProvisionPlan::decode(&caddy_plan).unwrap();
    let (grant, sig) = lab_no_caddy.sign_grant(&grant_for(
        "plan_v2_split",
        decoded.digest().as_str(),
        "app_provision",
        10,
    ));
    let req = AdmissionRequest {
        peer_uid: uid,
        plan: &caddy_plan,
        grant: &grant,
        signature: &sig,
        operation_id: id("op_v2_nocaddy"),
        idempotency_key: id("key_v2_nocaddy"),
        now: Some(Timestamp::try_from(1500).unwrap()),
    };
    assert_eq!(
        exec_no_caddy.provision_app(&req),
        Err(ExecutorError::Unavailable)
    );

    // 2. With Caddy enrolled (caddy_edge_over_ols), colliding with Caddy's HTTP/HTTPS
    // or OLS upstream port on ANY blue/green standby port is refused with BindingDenied
    // before committing any intent.
    let lab_caddy = AppLab::new("v2-with-caddy");
    let policy_path = lab_caddy.anchor.policy_dir.join("policy.json");
    let mut pol: Value = serde_json::from_slice(&fs::read(&policy_path).unwrap()).unwrap();
    pol["caddy"] = json!({
        "mode": "caddy_edge_over_ols",
        "http_address": "127.0.0.1:8080",
        "https_address": "127.0.0.1:8443",
        "ols_upstream": "127.0.0.1:8088",
        "binary_sha256": "d".repeat(64)
    });
    fs::remove_file(&policy_path).unwrap();
    private_file(&policy_path, &serde_json::to_vec(&pol).unwrap());
    let mut exec_caddy = Executor::open(lab_caddy.anchor.clone()).unwrap();

    let collide_standby = canonical(&json!({
        "schema_version": 2,
        "plan_id": "plan_v2_collide",
        "host_id": "host_lab",
        "host_epoch": "epoch_1",
        "profile_digest": "a".repeat(64),
        "requester": "agent_1",
        "verb": "app_provision",
        "site_id": "emdash1",
        "hostname": "shop.example.test",
        "ingress": "caddy",
        "topology": "fullstack_split",
        "database": "postgresql_18",
        "runtime": "bun_1_v1",
        "port": 43210,
        "blue_green": true,
        "standby_port": 8443,
        "spa_fallback": true,
        "frontend_dir": "frontend",
        "routes": [{"prefix": "/api/", "port": 43210}],
        "websockets": [],
        "entrypoint": "backend/server.ts",
        "health_path": "/api/health",
        "env_keys": ["DATABASE_URL"],
        "memory_max_mib": 512,
        "tasks_max": 64,
        "quota_mib": 512,
        "expected_effects": {
            "creates_account": true,
            "forwards_to_loopback": true,
            "installs_app_unit": true,
            "creates_database": true,
            "traffic_activation": false,
            "runs_package_scripts": false
        },
        "risk_class": "lab_only",
        "valid_from": 1000,
        "expires_at": 2000,
        "limitations": ["test"]
    }));
    let dec_c = AppProvisionPlan::decode(&collide_standby).unwrap();
    let (grant_c, sig_c) = lab_caddy.sign_grant(&grant_for(
        "plan_v2_collide",
        dec_c.digest().as_str(),
        "app_provision",
        11,
    ));
    let req_c = AdmissionRequest {
        peer_uid: uid,
        plan: &collide_standby,
        grant: &grant_c,
        signature: &sig_c,
        operation_id: id("op_v2_collide"),
        idempotency_key: id("key_v2_collide"),
        now: Some(Timestamp::try_from(1500).unwrap()),
    };
    assert_eq!(
        exec_caddy.provision_app(&req_c),
        Err(ExecutorError::BindingDenied)
    );

    // 3. Schema v2 app_deploy with blue_green_cutover on an unprovisioned site fails
    // closed with PreconditionChanged before intent (zero budget consumed).
    let bg_deploy = canonical(&json!({
        "schema_version": 2,
        "plan_id": "plan_ad_v2_bg",
        "host_id": "host_lab",
        "host_epoch": "epoch_1",
        "profile_digest": "a".repeat(64),
        "requester": "agent_1",
        "verb": "app_deploy",
        "site_id": "emdash1",
        "release_id": "rel-2",
        "runtime": "bun_1_v1",
        "artifact_sha256": "b".repeat(64),
        "manifest_sha256": "c".repeat(64),
        "file_count": 5,
        "total_bytes": 512,
        "health_path": "/api/health",
        "blue_green_cutover": true,
        "expected_effects": {
            "unpacks_as_site": true,
            "switches_release": true,
            "restarts_app_unit": true,
            "reloads_caddy": true,
            "rolls_back_on_failed_health": true,
            "runs_package_scripts": false,
            "traffic_activation": false
        },
        "risk_class": "lab_only",
        "valid_from": 1000,
        "expires_at": 2000,
        "limitations": ["test"]
    }));
    let dec_bg = AppDeployPlan::decode(&bg_deploy).unwrap();
    let (grant_bg, sig_bg) = lab_caddy.sign_grant(&grant_for(
        "plan_ad_v2_bg",
        dec_bg.digest().as_str(),
        "app_deploy",
        12,
    ));
    let req_bg = AdmissionRequest {
        peer_uid: uid,
        plan: &bg_deploy,
        grant: &grant_bg,
        signature: &sig_bg,
        operation_id: id("op_ad_v2_bg"),
        idempotency_key: id("key_ad_v2_bg"),
        now: Some(Timestamp::try_from(1500).unwrap()),
    };
    assert_eq!(
        exec_caddy.deploy_app(&req_bg),
        Err(ExecutorError::PreconditionChanged)
    );
    let obs = Executor::observe(&lab_caddy.anchor).unwrap();
    assert_eq!(obs["authority_budget"]["consumed"]["total_admissions"], 0);
}
