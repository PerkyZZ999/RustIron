//! Actual pre-journal verification only; never call a durable effect entrypoint.
use crate::{
    AdmissionRequest, ExecutorError, TrustAnchor,
    test_support::{KEYGEN, hex, new_key, private_dir, private_file, sign},
};
use rustiron_contracts::{CanonicalObject, Id, Timestamp};
use serde_json::{Value, json};
use std::{fs, path::PathBuf};

#[derive(Clone, Copy)]
enum Verb {
    #[cfg(not(rustiron_profile = "product"))]
    Site,
    Import,
    Ols,
    Eject,
    /// W572 (D-095).
    Proxy,
    #[cfg(not(rustiron_profile = "product"))]
    Capture,
    #[cfg(not(rustiron_profile = "product"))]
    Probe,
}
impl Verb {
    fn name(self) -> &'static str {
        match self {
            #[cfg(not(rustiron_profile = "product"))]
            Self::Site => "site",
            Self::Import => "import",
            Self::Ols => "ols",
            Self::Eject => "eject",
            Self::Proxy => "proxy-site",
            #[cfg(not(rustiron_profile = "product"))]
            Self::Capture => "capture",
            #[cfg(not(rustiron_profile = "product"))]
            Self::Probe => "probe",
        }
    }
    fn verify(
        self,
        anchor: &TrustAnchor,
        request: &AdmissionRequest<'_>,
    ) -> Result<(), ExecutorError> {
        match self {
            #[cfg(not(rustiron_profile = "product"))]
            Self::Site => crate::verified_site(anchor, request).map(|_| ()),
            Self::Import => crate::verified_import(anchor, request).map(|_| ()),
            Self::Ols => crate::verified_ols(anchor, request).map(|_| ()),
            Self::Eject => crate::verified_eject(anchor, request).map(|_| ()),
            Self::Proxy => crate::verified_proxy(anchor, request).map(|_| ()),
            #[cfg(not(rustiron_profile = "product"))]
            Self::Capture => crate::verified_capture(anchor, request).map(|_| ()),
            #[cfg(not(rustiron_profile = "product"))]
            Self::Probe => crate::verified_probe(anchor, request).map(|_| ()),
        }
    }
    fn section(self) -> &'static str {
        match self {
            #[cfg(not(rustiron_profile = "product"))]
            Self::Site => "provisioning",
            Self::Import => "migration",
            Self::Ols | Self::Eject | Self::Proxy => "ols",
            #[cfg(not(rustiron_profile = "product"))]
            Self::Capture | Self::Probe => "backup",
        }
    }
}
struct Fixture {
    root: PathBuf,
    anchor: TrustAnchor,
    policy: Value,
    plan: Vec<u8>,
    grant: Vec<u8>,
    signature: Vec<u8>,
    verb: Verb,
}
impl Fixture {
    fn new(verb: Verb) -> Self {
        let mut random = [0; 16];
        rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty()).unwrap();
        let root =
            std::env::temp_dir().join(format!("ri-verify-{}-{}", std::process::id(), hex(&random)));
        private_dir(&root);
        private_dir(&root.join("keys"));
        private_dir(&root.join("policy"));
        private_dir(&root.join("scratch"));
        new_key(&root.join("keys/key"));
        new_key(&root.join("keys/other"));
        let fixtures =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/tests/fixtures");
        let plan = fs::read(fixtures.join(format!("{}-plan.json", verb.name()))).unwrap();
        let grant = fs::read(fixtures.join(format!("{}-grant.json", verb.name()))).unwrap();
        let policy = json!({"schema_version":1,"host_id":"host_lab","host_epoch":"epoch_1","profile_digest":"a".repeat(64),"requester":"agent_1","requester_uid":4242,"issuer":"operator_1","signer_policy_epoch":"policy_1","verifier_sha256":hex(&fs::read(KEYGEN).unwrap()),
            "provisioning":{"wordpress_713_sha256":"d".repeat(64),"uid_min":3001,"uid_max":3099,"category_min":201,"category_max":299,"quota":{"block_hard_kib":5_242_880,"inode_hard":500_000}},
            "migration":{"php_versions":["8.2","8.3"]},
            "ols":{"listener":"LabListener","address":"127.0.0.1:8080","adopted":[],"parent_sha256":"a".repeat(64),"webadmin_port":7080},
            "backup":{"destination_id":"lab_pc_store","repository_base":"s3:http://127.0.0.1:9000/synthetic/sites","store_address":"127.0.0.1","retention_days":30}});
        let anchor = TrustAnchor {
            owner_uid: rustix::process::getuid().as_raw(),
            policy_dir: root.join("policy"),
            scratch_dir: root.join("scratch"),
            registry_dir: root.join("never-registry"),
            journal_dir: root.join("never-journal"),
            mark_dir: root.join("never-mark"),
            recipes_dir: root.join("never-recipes"),
            admin_socket: None,
        };
        let mut fixture = Self {
            root,
            anchor,
            policy,
            plan,
            grant,
            signature: Vec::new(),
            verb,
        };
        fixture.write_policy();
        fixture.allow("key");
        private_file(&fixture.anchor.policy_dir.join("revocations"), b"");
        fixture.resign("key", "rustiron-plan-v1");
        assert_eq!(
            fixture.verify(&fixture.request()),
            Ok(()),
            "matching verification baseline"
        );
        fixture
    }
    fn write_policy(&self) {
        private_file(
            &self.anchor.policy_dir.join("policy.json"),
            &serde_json::to_vec(&self.policy).unwrap(),
        );
    }
    fn allow(&self, key: &str) {
        let text = fs::read_to_string(self.root.join(format!("keys/{key}.pub"))).unwrap();
        let public = text
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        private_file(
            &self.anchor.policy_dir.join("allowed_signers"),
            format!(
                "{} namespaces=\"rustiron-plan-v1\" {public}\n",
                self.policy["issuer"].as_str().unwrap()
            )
            .as_bytes(),
        );
    }
    fn resign(&mut self, key: &str, namespace: &str) {
        self.signature = sign(
            &self.root.join(format!("keys/{key}")),
            &self.root.join("message"),
            CanonicalObject::decode(&self.grant).unwrap().as_bytes(),
            namespace,
        );
    }
    fn request(&self) -> AdmissionRequest<'_> {
        AdmissionRequest {
            peer_uid: 4242,
            plan: &self.plan,
            grant: &self.grant,
            signature: &self.signature,
            operation_id: Id::try_from("operation_1".to_owned()).unwrap(),
            idempotency_key: Id::try_from("retry_1".to_owned()).unwrap(),
            now: Some(Timestamp::try_from(1200).unwrap()),
        }
    }
    fn verify(&self, request: &AdmissionRequest<'_>) -> Result<(), ExecutorError> {
        let before = fs::read(self.anchor.policy_dir.join("policy.json")).unwrap();
        let result = self.verb.verify(&self.anchor, request);
        assert_eq!(
            fs::read(self.anchor.policy_dir.join("policy.json")).unwrap(),
            before
        );
        assert_eq!(
            fs::read_dir(&self.anchor.scratch_dir).unwrap().count(),
            0,
            "verifier scratch leaked"
        );
        for path in [
            &self.anchor.registry_dir,
            &self.anchor.journal_dir,
            &self.anchor.mark_dir,
            &self.anchor.recipes_dir,
        ] {
            assert!(!path.exists(), "verification reached effect storage");
        }
        result
    }
}

#[cfg(not(rustiron_profile = "product"))]
#[test]
fn lab_profile_refuses_product_destination_enrollment() {
    let mut fixture = Fixture::new(Verb::Site);
    fixture.policy.as_object_mut().unwrap().remove("backup");
    fixture.policy["schema_version"] = json!(2);
    fixture.policy["product_backup"] = json!({
        "destination_id": "offsite_fixture",
        "destination_policy_digest":
            include_str!("../../../docs/validation/S10-W307/projection-digest.txt").trim_end(),
    });
    fixture.write_policy();
    private_file(
        &fixture
            .anchor
            .policy_dir
            .join(crate::policy::PRODUCT_BACKUP_PROJECTION_FILE),
        include_bytes!("../../../docs/validation/S10-W307/projection.json"),
    );
    assert_eq!(
        fixture.verify(&fixture.request()),
        Err(ExecutorError::Unavailable)
    );
}

/// W368: a `config_activate` v2 page-cache opt-in passes only with the
/// executor's own recipe pin; any other digest is refused before a journal.
#[test]
fn ols_v2_page_cache_must_name_the_executor_recipe_pin() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../contracts/tests/fixtures/ols-plan-v2-vectors.json"
    ))
    .unwrap();
    for (digest, want) in [
        (crate::page_cache::TAR_SHA256.to_owned(), Ok(())),
        ("e".repeat(64), Err(ExecutorError::BindingDenied)),
    ] {
        let mut fixture = Fixture::new(Verb::Ols);
        let mut plan: Value =
            serde_json::from_str(vectors[0]["plan_input"].as_str().unwrap()).unwrap();
        plan["page_cache"]["recipe_digest"] = json!(digest);
        fixture.plan = serde_json::to_vec(&plan).unwrap();
        let mut grant: Value =
            serde_json::from_str(vectors[0]["grant_input"].as_str().unwrap()).unwrap();
        grant["plan_digest"] = json!(
            rustiron_contracts::approval::OlsPlan::decode(&fixture.plan)
                .unwrap()
                .digest()
                .as_str()
        );
        fixture.grant = serde_json::to_vec(&grant).unwrap();
        fixture.resign("key", "rustiron-plan-v1");
        assert_eq!(fixture.verify(&fixture.request()), want, "{digest}");
    }
}

#[test]
fn signed_static_single_name_eject_verifies_exact_binding() {
    let mut fixture = Fixture::new(Verb::Eject);
    fixture.plan = include_bytes!("../../contracts/tests/fixtures/eject-plan-v3.json").to_vec();
    let plan = CanonicalObject::decode(&fixture.plan).unwrap();
    let digest = rustiron_contracts::approval::Sha256Digest::from_bytes(plan.plan_domain_digest());
    let mut grant: Value = serde_json::from_slice(&fixture.grant).unwrap();
    grant["plan_digest"] = json!(digest.as_str());
    fixture.grant = serde_json::to_vec(&grant).unwrap();
    fixture.resign("key", "rustiron-plan-v1");
    assert_eq!(fixture.verify(&fixture.request()), Ok(()));

    let mut tampered: Value = serde_json::from_slice(&fixture.plan).unwrap();
    tampered["hostname"] = json!("other.example.test");
    fixture.plan = serde_json::to_vec(&tampered).unwrap();
    assert_eq!(
        fixture.verify(&fixture.request()),
        Err(ExecutorError::BindingDenied)
    );
}

/// W370: a `config_activate` v3 page-cache opt-out names no digest; it
/// passes the signed binding like any activation, and a changed site is a
/// binding mismatch. The journal decides later whether the site is opted in.
#[test]
fn ols_v3_page_cache_opt_out_verifies_through_the_plan_digest() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../contracts/tests/fixtures/ols-plan-v3-vectors.json"
    ))
    .unwrap();
    for (site, want) in [
        ("blog5", Ok(())),
        ("blog6", Err(ExecutorError::BindingDenied)),
    ] {
        let mut fixture = Fixture::new(Verb::Ols);
        let mut plan: Value =
            serde_json::from_str(vectors[0]["plan_input"].as_str().unwrap()).unwrap();
        plan["page_cache_opt_out"]["site_id"] = json!(site);
        fixture.plan = serde_json::to_vec(&plan).unwrap();
        fixture.grant = vectors[0]["grant_input"]
            .as_str()
            .unwrap()
            .as_bytes()
            .to_vec();
        fixture.resign("key", "rustiron-plan-v1");
        assert_eq!(fixture.verify(&fixture.request()), want, "{site}");
    }
}

#[cfg(not(rustiron_profile = "product"))]
#[test]
fn journaled_backup_policy_refuses_repository_drift_before_use() {
    let mut fixture = Fixture::new(Verb::Capture);
    let (_, _, admitted) = crate::verified_capture(&fixture.anchor, &fixture.request()).unwrap();
    let expected = admitted.backup.unwrap().digest().unwrap();
    let load = |expected| {
        crate::policy::load_bound_backup(
            &fixture.anchor,
            &admitted.host_id,
            &admitted.host_epoch,
            expected,
        )
    };
    assert_eq!(
        load(Some(&expected)).unwrap().repository_base,
        "s3:http://127.0.0.1:9000/synthetic/sites"
    );
    assert_eq!(load(None).unwrap_err(), ExecutorError::PreconditionChanged);
    fixture.policy["backup"]["repository_base"] = json!("s3:http://127.0.0.1:9000/other/sites");
    fixture.write_policy();
    assert_eq!(
        load(Some(&expected)).unwrap_err(),
        ExecutorError::PreconditionChanged
    );
}
/// W441 (D-053): import admission returns the signed dry-run facts and
/// needs the provisioning enrollment, an enrolled quota cap, and an enrolled
/// LSPHP version, besides its own `migration` section.
#[test]
fn import_admission_returns_the_signed_facts_and_needs_its_enrollment() {
    let fixture = Fixture::new(Verb::Import);
    let verified = crate::verified_import(&fixture.anchor, &fixture.request()).unwrap();
    assert_eq!(verified.intent.site_id.as_str(), "blog1");
    assert_eq!(verified.intent.hostname.as_str(), "blog1.example.test");
    assert_eq!(verified.intent.operation_id.as_str(), "operation_1");
    assert_eq!(verified.archive_sha256.as_str(), "b".repeat(64));
    assert_eq!(verified.manifest_sha256.as_str(), "c".repeat(64));
    assert_eq!(
        (
            verified.file_entries,
            verified.file_bytes,
            verified.dump_bytes
        ),
        (4200, 90_000_000, 12_000_000)
    );
    assert_eq!(verified.target_php.as_str(), "8.2");
    assert_eq!(
        verified.quota_limits,
        crate::quota::QuotaLimits {
            block_hard_kib: 5_242_880,
            inode_hard: 500_000
        }
    );
    assert_eq!(verified.enrolled.uid_min, 3001);

    for (change, want) in [
        (
            json!({"remove": "provisioning"}),
            ExecutorError::Unavailable,
        ),
        (json!({"php": ["8.3"]}), ExecutorError::BindingDenied),
        (json!({"php": []}), ExecutorError::Unavailable),
        (json!({"php": ["8.2", "8.2"]}), ExecutorError::Unavailable),
        // The product profile refuses a provisioning policy without a quota.
        (
            json!({"quota": null}),
            if cfg!(rustiron_profile = "product") {
                ExecutorError::Unavailable
            } else {
                ExecutorError::BindingDenied
            },
        ),
        (
            json!({"quota": {"block_hard_kib": 5_242_879, "inode_hard": 500_000}}),
            ExecutorError::BindingDenied,
        ),
    ] {
        let mut fixture = Fixture::new(Verb::Import);
        if let Some(section) = change.get("remove") {
            fixture
                .policy
                .as_object_mut()
                .unwrap()
                .remove(section.as_str().unwrap());
        }
        if let Some(versions) = change.get("php") {
            fixture.policy["migration"]["php_versions"] = versions.clone();
        }
        if let Some(quota) = change.get("quota") {
            let provisioning = fixture.policy["provisioning"].as_object_mut().unwrap();
            if quota.is_null() {
                provisioning.remove("quota");
            } else {
                provisioning.insert("quota".to_owned(), quota.clone());
            }
        }
        fixture.write_policy();
        assert_eq!(fixture.verify(&fixture.request()), Err(want), "{change}");
    }
}

/// W572 (D-095): proxy site admission returns the signed routes, needs the
/// provisioning enrollment, and refuses a route to a port that the host
/// serves or reserves: the OLS listener, WebAdmin and TLS listener ports,
/// and the enrolled SSH port.
#[test]
fn proxy_admission_returns_the_routes_and_refuses_enrolled_ports() {
    let fixture = Fixture::new(Verb::Proxy);
    let verified = crate::verified_proxy(&fixture.anchor, &fixture.request()).unwrap();
    assert_eq!(verified.intent.site_id.as_str(), "ytproxy");
    assert_eq!(verified.intent.hostname.as_str(), "yt.example.test");
    assert_eq!(verified.facts.ports(), [3100, 3101]);
    assert_eq!(verified.facts.websockets[0].prefix, "/ws/");
    assert_eq!(verified.enrolled.uid_min, 3001);
    for (pointer, value, want) in [
        ("/provisioning", None, ExecutorError::Unavailable),
        (
            "/ols/address",
            Some(json!("127.0.0.1:3100")),
            ExecutorError::BindingDenied,
        ),
        (
            "/ols/webadmin_port",
            Some(json!(3101)),
            ExecutorError::BindingDenied,
        ),
        (
            "/ols/tls_address",
            Some(json!("0.0.0.0:3101")),
            ExecutorError::BindingDenied,
        ),
        (
            "/firewall",
            Some(json!({"ssh_port": 3100, "dhcpv6_client": false})),
            ExecutorError::BindingDenied,
        ),
    ] {
        let mut fixture = Fixture::new(Verb::Proxy);
        let (parent, member) = pointer.rsplit_once('/').unwrap();
        let object = if parent.is_empty() {
            &mut fixture.policy
        } else {
            fixture.policy.pointer_mut(parent).unwrap()
        };
        match value {
            Some(value) => {
                object
                    .as_object_mut()
                    .unwrap()
                    .insert(member.to_owned(), value);
            }
            None => {
                object.as_object_mut().unwrap().remove(member);
            }
        }
        fixture.write_policy();
        assert_eq!(fixture.verify(&fixture.request()), Err(want), "{pointer}");
    }
    // Other ports, an SSH port, and a TLS listener elsewhere are admitted.
    let mut fixture = Fixture::new(Verb::Proxy);
    fixture.policy["ols"]["tls_address"] = json!("0.0.0.0:8443");
    fixture.policy["firewall"] = json!({"ssh_port": 2222, "dhcpv6_client": false});
    fixture.write_policy();
    assert_eq!(fixture.verify(&fixture.request()), Ok(()));
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.root) {
            eprintln!("synthetic verification cleanup failed: {error}");
            assert!(std::thread::panicking(), "synthetic cleanup failed");
        }
    }
}

macro_rules! matrix {
    ($module:ident,$verb:expr) => {
        mod $module {
            use super::*;
            #[test]
            fn matching_baseline() {
                let f = Fixture::new($verb);
                assert_eq!(f.verify(&f.request()), Ok(()));
            }
            #[test]
            fn rejects_foreign_peer() {
                let f = Fixture::new($verb);
                let mut r = f.request();
                r.peer_uid = 4243;
                assert_eq!(f.verify(&r), Err(ExecutorError::PeerDenied));
            }
            #[test]
            fn rejects_unknown_clock() {
                let f = Fixture::new($verb);
                let mut r = f.request();
                r.now = None;
                assert_eq!(f.verify(&r), Err(ExecutorError::TimeDenied));
            }
            #[test]
            fn rejects_expiry() {
                let f = Fixture::new($verb);
                let mut r = f.request();
                r.now = Some(Timestamp::try_from(1900).unwrap());
                assert_eq!(f.verify(&r), Err(ExecutorError::TimeDenied));
            }
            #[test]
            fn accepts_inclusive_start() {
                let f = Fixture::new($verb);
                let mut r = f.request();
                r.now = Some(Timestamp::try_from(1100).unwrap());
                assert_eq!(f.verify(&r), Ok(()));
            }
            #[test]
            fn rejects_missing_enrollment() {
                let mut f = Fixture::new($verb);
                f.policy.as_object_mut().unwrap().remove(f.verb.section());
                f.write_policy();
                assert_eq!(f.verify(&f.request()), Err(ExecutorError::Unavailable));
            }
            #[test]
            fn rejects_rotated_epoch() {
                let mut f = Fixture::new($verb);
                f.policy["signer_policy_epoch"] = json!("policy_2");
                f.write_policy();
                assert_eq!(f.verify(&f.request()), Err(ExecutorError::BindingDenied));
            }
            #[test]
            fn rejects_foreign_host() {
                let mut f = Fixture::new($verb);
                f.policy["host_id"] = json!("other_host");
                f.write_policy();
                assert_eq!(f.verify(&f.request()), Err(ExecutorError::BindingDenied));
            }
            #[test]
            fn rejects_wrong_key() {
                let mut f = Fixture::new($verb);
                f.resign("other", "rustiron-plan-v1");
                assert_eq!(f.verify(&f.request()), Err(ExecutorError::SignatureDenied));
            }
            #[test]
            fn rejects_wrong_namespace() {
                let mut f = Fixture::new($verb);
                f.resign("key", "wrong-namespace");
                assert_eq!(f.verify(&f.request()), Err(ExecutorError::SignatureDenied));
            }
            #[test]
            fn rejects_changed_grant_without_resigning() {
                let mut f = Fixture::new($verb);
                let mut g: Value = serde_json::from_slice(&f.grant).unwrap();
                g["nonce"] = json!("changed_nonce");
                f.grant = serde_json::to_vec(&g).unwrap();
                assert_eq!(f.verify(&f.request()), Err(ExecutorError::SignatureDenied));
            }
            #[test]
            fn accepts_equivalent_grant_formatting() {
                let mut f = Fixture::new($verb);
                let g: Value = serde_json::from_slice(&f.grant).unwrap();
                f.grant = serde_json::to_vec_pretty(&g).unwrap();
                assert_eq!(f.verify(&f.request()), Ok(()));
            }
            #[test]
            fn rejects_revoked_key() {
                let f = Fixture::new($verb);
                private_file(
                    &f.anchor.policy_dir.join("revocations"),
                    &fs::read(f.root.join("keys/key.pub")).unwrap(),
                );
                assert_eq!(f.verify(&f.request()), Err(ExecutorError::SignatureDenied));
            }
            #[test]
            fn rejects_verifier_hash_drift() {
                let mut f = Fixture::new($verb);
                f.policy["verifier_sha256"] = json!("0".repeat(64));
                f.write_policy();
                assert_eq!(f.verify(&f.request()), Err(ExecutorError::Unavailable));
            }
            #[test]
            fn rejects_oversized_plan() {
                let f = Fixture::new($verb);
                let bytes = vec![b' '; rustiron_contracts::MAX_REQUEST_BYTES + 1];
                let mut r = f.request();
                r.plan = &bytes;
                assert_eq!(f.verify(&r), Err(ExecutorError::InvalidRequest));
            }
            #[test]
            fn rejects_oversized_grant() {
                let f = Fixture::new($verb);
                let bytes = vec![b' '; rustiron_contracts::MAX_REQUEST_BYTES + 1];
                let mut r = f.request();
                r.grant = &bytes;
                assert_eq!(f.verify(&r), Err(ExecutorError::InvalidRequest));
            }
            #[test]
            fn rejects_oversized_signature() {
                let f = Fixture::new($verb);
                let bytes = vec![b'x'; crate::MAX_SIGNATURE_BYTES + 1];
                let mut r = f.request();
                r.signature = &bytes;
                assert_eq!(f.verify(&r), Err(ExecutorError::InvalidRequest));
            }
        }
    };
}
// The site fixture is a v1 plan, which the product profile refuses (W341);
// `tests/product_profile` covers product site admission.
#[cfg(not(rustiron_profile = "product"))]
matrix!(site, Verb::Site);
matrix!(import, Verb::Import);
matrix!(ols, Verb::Ols);
matrix!(eject, Verb::Eject);
matrix!(proxy, Verb::Proxy);
#[cfg(not(rustiron_profile = "product"))]
matrix!(capture, Verb::Capture);
#[cfg(not(rustiron_profile = "product"))]
matrix!(probe, Verb::Probe);
