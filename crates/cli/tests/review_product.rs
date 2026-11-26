//! Product grant review uses disposable files and synthetic signing keys.

use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const KEYGEN: &str = "/usr/bin/ssh-keygen";
const NAMESPACE: &str = "rustiron-plan-v1";
const VECTORS: &str = include_str!("../../contracts/tests/fixtures/product-backup-vectors.json");
const PROJECTION: &str = include_str!("../../../docs/validation/S10-W307/projection.json");
const PROJECTION_DIGEST: &str =
    include_str!("../../../docs/validation/S10-W307/projection-digest.txt");

struct ReviewFixture(PathBuf);

impl ReviewFixture {
    fn new() -> Self {
        let mut random = [0; 16];
        rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty()).unwrap();
        let root = std::env::temp_dir().join(format!("ri-review-product-{}", hex(&random)));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        Self(root)
    }

    fn write(&self, name: &str, bytes: impl AsRef<[u8]>) {
        fs::write(self.0.join(name), bytes).unwrap();
    }

    fn load(&self, vector: &Value) {
        self.write("plan", vector["plan_input"].as_str().unwrap());
        self.write("grant", vector["grant_input"].as_str().unwrap());
        self.write("policy", policy().to_string());
        self.write("projection", PROJECTION);
    }

    fn review(&self, format: &str, now: &str) -> Command {
        let mut command = self.review_without_projection(format, now);
        command.args(["--destination-policy", "projection"]);
        command
    }

    fn review_without_projection(&self, format: &str, now: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rustiron-review"));
        command
            .env_clear()
            .current_dir(&self.0)
            .args(["--plan", "plan", "--grant", "grant", "--policy", "policy"])
            .args(["--synthetic-time", now, "--output", format]);
        command
    }
}

impl Drop for ReviewFixture {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("synthetic review cleanup failed: {error}");
            assert!(std::thread::panicking());
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn plan_digest(canonical: &str) -> String {
    sha256(format!("rustiron/plan/v1\0{canonical}").as_bytes())
}

fn policy() -> Value {
    json!({
        "schema_version": 2,
        "host_id": "host_lab",
        "host_epoch": "epoch_1",
        "profile_digest": "a".repeat(64),
        "requester": "agent_1",
        "issuer": "operator_1",
        "signer_policy_epoch": "policy_1",
        "verifier_sha256": sha256(&fs::read(KEYGEN).unwrap()),
        "backup_destination": {
            "destination_id": "offsite_fixture",
            "destination_policy_digest": PROJECTION_DIGEST.trim_end(),
        },
    })
}

fn vectors() -> Vec<Value> {
    let mut vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    for vector in &mut vectors {
        // Both original byte strings contain the same ASCII destination digest.
        // Reuse their independently prepared key order and whitespace.
        for field in ["plan_input", "plan_canonical"] {
            let original = vector[field].as_str().unwrap();
            vector[field] = json!(original.replace(&"b".repeat(64), PROJECTION_DIGEST.trim_end()));
        }
        let previous_digest = vector["plan_digest"].as_str().unwrap().to_owned();
        let current_digest = plan_digest(vector["plan_canonical"].as_str().unwrap());
        for field in ["grant_input", "grant_canonical"] {
            let original = vector[field].as_str().unwrap();
            vector[field] = json!(original.replace(&previous_digest, &current_digest));
        }
        vector["plan_digest"] = json!(current_digest);
    }
    vectors
}

fn success(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn refusal(command: &mut Command, exit: i32, code: &str) {
    let output = command.output().unwrap();
    assert_eq!(output.status.code(), Some(exit), "{output:?}");
    assert!(output.stderr.is_empty());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["error"], code);
    assert!(report.get("grant").is_none());
}

#[test]
fn offline_product_review_exports_the_independent_bytes_for_both_verbs() {
    let fixture = ReviewFixture::new();
    for vector in vectors() {
        fixture.load(&vector);
        let expected = vector["grant_canonical"].as_str().unwrap().as_bytes();
        let payload = success(&mut fixture.review("grant-bytes", "1200"));
        assert_eq!(payload.stdout, expected);
        let output = success(&mut fixture.review("json", "1200"));
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        let plan: Value = serde_json::from_str(vector["plan_input"].as_str().unwrap()).unwrap();
        let grant: Value = serde_json::from_str(vector["grant_input"].as_str().unwrap()).unwrap();
        assert_eq!(report["scope"], "offline_product_backup_review");
        assert_eq!(report["destination_policy_binding"], "matched");
        let expected_repository = match vector["name"].as_str().unwrap() {
            "capture" => "c".repeat(64),
            "probe" => "b".repeat(64),
            other => panic!("unexpected vector {other}"),
        };
        assert_eq!(report["repository_id"], expected_repository);
        let site = plan["site_id"].as_str().unwrap();
        let (capture_digest, fetch_digest) = match site {
            "blog9" => ("e", "0"),
            "blog13" => ("d", "f"),
            other => panic!("unexpected site {other}"),
        };
        assert_eq!(
            report["repository"],
            json!({
                "url": format!("s3:https://198.51.100.23:443/rustiron-proof/sites/rs_{site}"),
                "endpoint": "198.51.100.23:443",
                "region": "fixture-1",
                "ca_sha256": "a".repeat(64),
                "retention_days": 30,
                "password_relative_path": format!("rs_{site}/repo.password"),
                "capture_credential": {
                    "relative_path": format!("rs_{site}/aws"),
                    "profile_id": "fixture_capture",
                    "principal_id": format!("capture_{site}"),
                    "authorization_sha256": capture_digest.repeat(64),
                },
                "fetch_credential": {
                    "relative_path": format!("rs_{site}/fetch-aws"),
                    "profile_id": "fixture_fetch",
                    "principal_id": format!("fetch_{site}"),
                    "authorization_sha256": fetch_digest.repeat(64),
                },
            })
        );
        assert_eq!(report["plan_digest"], vector["plan_digest"]);
        assert_eq!(report["canonical_grant_sha256"], sha256(expected));
        assert_eq!(report["plan"], plan);
        assert_eq!(report["grant"], grant);
        assert_eq!(report["signature_status"], "not_checked");
        assert_eq!(report["execution_authority"], false);
        assert_eq!(report["synthetic_time"], true);
        let output = success(&mut fixture.review("human", "1200"));
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("Offline product backup review"));
        assert!(text.contains("\"destination_id\": \"offsite_fixture\""));
        assert!(text.contains(&format!(
            "\"destination_policy_digest\": \"{}\"",
            PROJECTION_DIGEST.trim_end()
        )));
        assert!(text.contains(&format!("\"repository_id\": \"{expected_repository}\"")));
    }
}

#[test]
fn product_review_refuses_policy_drift_scope_and_version_mismatch_before_export() {
    let fixture = ReviewFixture::new();
    for vector in vectors() {
        fixture.load(&vector);
        for (field, value) in [
            ("destination_id", json!("other_store")),
            ("destination_policy_digest", json!("c".repeat(64))),
        ] {
            let mut drift = policy();
            drift["backup_destination"][field] = value;
            fixture.write("policy", drift.to_string());
            refusal(
                &mut fixture.review("grant-bytes", "1200"),
                4,
                "DESTINATION_POLICY_MISMATCH",
            );
        }
        fixture.load(&vector);
        let mut grant: Value =
            serde_json::from_str(vector["grant_input"].as_str().unwrap()).unwrap();
        grant["destinations"] = json!(["other_store"]);
        fixture.write("grant", grant.to_string());
        refusal(
            &mut fixture.review("grant-bytes", "1200"),
            4,
            "PRODUCT_BACKUP_BINDING_DENIED",
        );

        // A matching plan and grant can still disagree with independent policy.
        let mut plan: Value = serde_json::from_str(vector["plan_input"].as_str().unwrap()).unwrap();
        plan["destination_policy_digest"] = json!("c".repeat(64));
        let bytes = plan.to_string();
        let canonical = rustiron_contracts::CanonicalObject::decode(bytes.as_bytes()).unwrap();
        grant["plan_digest"] = json!(hex(&canonical.plan_domain_digest()));
        grant["destinations"] = json!(["offsite_fixture"]);
        fixture.write("plan", bytes);
        fixture.write("grant", grant.to_string());
        refusal(
            &mut fixture.review("grant-bytes", "1200"),
            4,
            "DESTINATION_POLICY_MISMATCH",
        );

        fixture.load(&vector);
        refusal(
            &mut fixture.review("grant-bytes", "1900"),
            3,
            "GRANT_TIME_DENIED",
        );
        let mut wrong_version = policy();
        wrong_version["schema_version"] = json!(1);
        wrong_version
            .as_object_mut()
            .unwrap()
            .remove("backup_destination");
        fixture.write("policy", wrong_version.to_string());
        refusal(
            &mut fixture.review("grant-bytes", "1200"),
            2,
            "INVALID_REVIEW_INPUT",
        );

        let mut null_destination = policy();
        null_destination["backup_destination"] = Value::Null;
        fixture.write("policy", null_destination.to_string());
        refusal(
            &mut fixture.review("grant-bytes", "1200"),
            2,
            "INVALID_REVIEW_INPUT",
        );
    }

    fixture.write(
        "plan",
        include_bytes!("../../contracts/tests/fixtures/fixture-plan.json"),
    );
    fixture.write(
        "grant",
        include_bytes!("../../contracts/tests/fixtures/fixture-grant.json"),
    );
    fixture.write("policy", policy().to_string());
    refusal(
        &mut fixture.review("grant-bytes", "1200"),
        2,
        "INVALID_REVIEW_INPUT",
    );
    let mut fixture_policy = policy();
    fixture_policy["schema_version"] = json!(1);
    fixture_policy["backup_destination"] = Value::Null;
    fixture.write("policy", fixture_policy.to_string());
    refusal(
        &mut fixture.review("grant-bytes", "1200"),
        2,
        "INVALID_REVIEW_INPUT",
    );
    fixture_policy
        .as_object_mut()
        .unwrap()
        .remove("backup_destination");
    fixture.write("policy", fixture_policy.to_string());
    refusal(
        &mut fixture.review("grant-bytes", "1200"),
        2,
        "INVALID_REVIEW_INPUT",
    );
    success(&mut fixture.review_without_projection("grant-bytes", "1200"));
}

#[test]
fn product_review_requires_a_matching_projection_and_an_enrolled_signed_site() {
    let fixture = ReviewFixture::new();
    for vector in vectors() {
        fixture.load(&vector);
        refusal(
            &mut fixture.review_without_projection("grant-bytes", "1200"),
            2,
            "INVALID_REVIEW_INPUT",
        );
        fixture.write("projection", "{}");
        refusal(
            &mut fixture.review("grant-bytes", "1200"),
            2,
            "INVALID_REVIEW_INPUT",
        );

        let drift = PROJECTION.replace("198.51.100.23", "198.51.100.24");
        fixture.write("projection", drift);
        refusal(
            &mut fixture.review("grant-bytes", "1200"),
            4,
            "DESTINATION_POLICY_MISMATCH",
        );

        fixture.write("projection", PROJECTION);
        let mut plan: Value = serde_json::from_str(vector["plan_input"].as_str().unwrap()).unwrap();
        let mut grant: Value =
            serde_json::from_str(vector["grant_input"].as_str().unwrap()).unwrap();
        plan["site_id"] = json!("unenrolled");
        let plan = plan.to_string();
        grant["plan_digest"] = json!(plan_digest(&plan));
        grant["site_ids"] = json!(["unenrolled"]);
        fixture.write("plan", plan);
        fixture.write("grant", grant.to_string());
        refusal(
            fixture.review("grant-bytes", "1200").args([
                "--signature",
                "unavailable.sig",
                "--allowed-signers",
                "unavailable.allowed",
                "--revocations",
                "unavailable.revoked",
            ]),
            4,
            "DESTINATION_SITE_NOT_ENROLLED",
        );
    }
}

fn keygen(directory: &Path) -> Command {
    let mut command = Command::new(KEYGEN);
    command.env_clear().current_dir(directory);
    command
}

#[test]
fn the_same_product_grant_bytes_verify_with_a_disposable_sshsig() {
    let fixture = ReviewFixture::new();
    success(keygen(&fixture.0).args([
        "-q",
        "-t",
        "ed25519",
        "-N",
        "",
        "-C",
        "SYNTHETIC_ONLY",
        "-f",
        "key",
    ]));
    let public = fs::read_to_string(fixture.0.join("key.pub")).unwrap();
    let public = public
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    fixture.write(
        "allowed",
        format!("operator_1 namespaces=\"{NAMESPACE}\" {public}\n"),
    );
    fixture.write("revoked", "");
    for (index, vector) in vectors().into_iter().enumerate() {
        fixture.load(&vector);
        let message = format!("canonical-{index}");
        let signature = format!("{message}.sig");
        fixture.write(&message, vector["grant_canonical"].as_str().unwrap());
        success(
            keygen(&fixture.0).args(["-q", "-Y", "sign", "-f", "key", "-n", NAMESPACE, &message]),
        );
        let flags = [
            "--signature",
            &signature,
            "--allowed-signers",
            "allowed",
            "--revocations",
            "revoked",
        ];
        let output = success(fixture.review("json", "1200").args(flags));
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["signature_status"], "verified");
        assert_eq!(report["destination_policy_binding"], "matched");
        assert_eq!(report["execution_authority"], false);

        let mut changed: Value =
            serde_json::from_str(vector["grant_input"].as_str().unwrap()).unwrap();
        changed["nonce"] = json!("changed_nonce");
        fixture.write("grant", changed.to_string());
        refusal(
            fixture.review("grant-bytes", "1200").args(flags),
            3,
            "INVALID_SIGNATURE",
        );
    }
}

/// W386 (D-035): a standing capture grant reviews under the same policy and
/// projection; the review lists each site's repository and every window.
#[test]
fn a_standing_capture_grant_reviews_with_its_windows_and_repositories() {
    let vectors: Vec<Value> = serde_json::from_str(include_str!(
        "../../contracts/tests/fixtures/standing-capture-vectors.json"
    ))
    .unwrap();
    let vector = &vectors[0];
    let fixture = ReviewFixture::new();
    fixture.load(vector);
    let start = "1799996100";
    let output = fixture.review("json", start).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let review: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(review["execution_authority"], false);
    assert_eq!(review["plan_digest"], vector["plan_digest"]);
    assert_eq!(review["canonical_grant_sha256"], vector["grant_sha256"]);
    assert_eq!(review["destination_policy_binding"], "matched");
    let standing = &review["standing_capture"];
    assert_eq!(standing["windows"].as_array().unwrap().len(), 35);
    assert_eq!(standing["max_captures"], 70);
    for site in ["blog13", "blog9"] {
        assert!(
            standing["repositories"][site]["repository_id"].is_string(),
            "{site}"
        );
    }
    let bytes = fixture.review("grant-bytes", start).output().unwrap();
    assert_eq!(
        bytes.stdout,
        vector["grant_canonical"].as_str().unwrap().as_bytes()
    );
    let late = fixture.review("json", "1803020100").output().unwrap();
    assert_eq!(late.status.code(), Some(3));
    let late: Value = serde_json::from_slice(&late.stdout).unwrap();
    assert_eq!(late["error"], "GRANT_TIME_DENIED");
}
