//! Offline plan review uses closed plans and never grants authority.

use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../contracts/tests/fixtures");

fn review(path: &std::path::Path, format: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rustiron"))
        .args(["plan", "review-file"])
        .arg(path)
        .args(["--output", format])
        .output()
        .unwrap()
}

struct Temp(PathBuf);

/// W720: a folder-name part that no other test in this process uses. The
/// clock alone can repeat across parallel tests.
fn unique_suffix() -> String {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_nanos());
    let next = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{nanos}-{next}")
}

impl Temp {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "ri-review-file-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        Self(directory)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn create_dns(verb: &str, input_flag: &str, path: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rustiron"))
        .args([
            "plan",
            "create",
            verb,
            "--plan-id",
            "plan_dns",
            "--host-id",
            "host_lab",
            "--host-epoch",
            "epoch_1",
            "--profile-digest",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--requester",
            "agent_1",
            "--zone",
            "w566.test",
            "--valid-from",
            "1000",
            "--expires-at",
            "1900",
            input_flag,
        ])
        .arg(path)
        .output()
        .unwrap()
}

#[test]
fn dns_import_binds_exact_zone_bytes_for_offline_review() {
    use rustiron_contracts::approval::DnsImportPlan;

    let zone = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/validation/S10-W566/lab/zone.txt");
    let output = create_dns("dns-zone-import", "--zone-file", &zone);
    assert!(output.status.success(), "{output:?}");
    let plan = DnsImportPlan::decode(&output.stdout).unwrap();
    assert_eq!(plan.as_bytes(), output.stdout);
    assert_eq!(plan.zone().as_str(), "w566.test");
    assert_eq!(plan.record_sets(), 13);
    assert_eq!(
        plan.zone_sha256().as_str(),
        "9d84d607b4483d565ffc0fd89eae23fa7f46bd2eb245b51499f41669e2cc9694"
    );
}

#[test]
fn dns_change_preserves_operation_order_and_review_marks_mail() {
    use rustiron_contracts::approval::DnsChangePlan;

    let dir = Temp::new();
    let operations = dir.0.join("operations.json");
    let reviewed = json!([
        {"owner":"new.w566.test.","type":"A","expected":"absent",
         "action":"replace","ttl":300,"records":["203.0.113.10"]},
        {"owner":"w566.test.","type":"MX","expected":"b".repeat(64),"action":"remove"}
    ]);
    fs::write(&operations, reviewed.to_string()).unwrap();
    let output = create_dns("dns-change", "--operations-file", &operations);
    assert!(output.status.success(), "{output:?}");
    let plan = DnsChangePlan::decode(&output.stdout).unwrap();
    assert_eq!(plan.as_bytes(), output.stdout);
    assert_eq!(serde_json::to_value(plan.operations()).unwrap(), reviewed);

    let path = dir.0.join("plan.json");
    fs::write(&path, output.stdout).unwrap();
    let inspected = Command::new(env!("CARGO_BIN_EXE_rustiron-plan"))
        .arg("inspect")
        .arg(&path)
        .output()
        .unwrap();
    assert!(inspected.status.success(), "{inspected:?}");
    assert!(
        String::from_utf8_lossy(&inspected.stdout).contains("operation: w566.test. MX [MAIL];")
    );
}

#[test]
fn dns_builders_refuse_invalid_input_without_plan_bytes() {
    let dir = Temp::new();
    let input = dir.0.join("input");
    for (verb, flag, bytes, error) in [
        (
            "dns-zone-import",
            "--zone-file",
            "$ORIGIN .\n",
            "INVALID_ZONE_FILE",
        ),
        (
            "dns-change",
            "--operations-file",
            r#"[{"owner":"w566.test.","type":"MX","expected":"absent","expected":"absent","action":"remove"}]"#,
            "INVALID_DNS_OPERATIONS",
        ),
        (
            "dns-change",
            "--operations-file",
            r#"[{"owner":"example.test.","type":"A","expected":"absent","action":"replace","ttl":300,"records":["203.0.113.10"]}]"#,
            "INVALID_PLAN",
        ),
    ] {
        fs::write(&input, bytes).unwrap();
        let output = create_dns(verb, flag, &input);
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(error),
            "{output:?}"
        );
    }
}

#[test]
fn destination_digest_validates_the_projection_offline_and_redacts_invalid_input() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/validation/S10-W307/projection.json");
    let temp = Temp::new();
    let invoke = |path: &std::path::Path| {
        Command::new(env!("CARGO_BIN_EXE_rustiron"))
            .env_clear()
            .current_dir(&temp.0)
            .args(["--socket", "missing.sock", "--output", "json"])
            .args(["plan", "destination-digest"])
            .arg(path)
            .output()
            .unwrap()
    };
    let success = invoke(&fixture);
    assert!(success.status.success(), "{success:?}");
    assert_eq!(
        serde_json::from_slice::<Value>(&success.stdout).unwrap(),
        json!({
            "destination_id": "offsite_fixture",
            "destination_policy_digest": include_str!("../../../docs/validation/S10-W307/projection-digest.txt").trim_end(),
        })
    );

    let mut invalid: Value = serde_json::from_slice(&fs::read(fixture).unwrap()).unwrap();
    invalid["transport"]["unexpected"] = json!("synthetic-private-value");
    let path = temp.0.join("projection.json");
    fs::write(&path, invalid.to_string()).unwrap();
    let refused = invoke(&path);
    assert_eq!(refused.status.code(), Some(2), "{refused:?}");
    assert!(refused.stderr.is_empty());
    let report: Value = serde_json::from_slice(&refused.stdout).unwrap();
    assert_eq!(report["error"]["code"], "INVALID_REQUEST");
    assert!(report.get("destination_policy_digest").is_none());
    assert!(
        !String::from_utf8(refused.stdout)
            .unwrap()
            .contains("synthetic-private-value")
    );
}

#[test]
fn json_review_contains_the_entire_plan_and_known_digest_without_a_socket() {
    for (file, verb, digest) in [
        (
            "site-plan.json",
            "site_provision",
            "c33d38f7e35973b5dfb88846d667b06ee9f1d2544fe1fcfa35354797553b2ccf",
        ),
        (
            "ols-plan.json",
            "config_activate",
            "00d79e742240c6626d1c5fb3e4415cf158bca560e7c71bbdf0fcae33eb9eb88f",
        ),
        (
            "eject-plan.json",
            "site_eject",
            "ca015fc46a331406c894bff50a4de8314d65e67c7f8834574520e651ba830727",
        ),
        (
            "capture-plan.json",
            "backup_capture",
            "31441613f3d96fe2b9cbdafa8dceea164405fa09d877d63ccdda3d06f3e28135",
        ),
        (
            "probe-plan.json",
            "restore_probe",
            "38d7827be2d1c72f470a71fe34a0172f0b9fdd877ac9ea1532a7e48aa795caf9",
        ),
    ] {
        let path = PathBuf::from(FIXTURES).join(file);
        let output = review(&path, "json");
        assert!(
            output.status.success(),
            "{file}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let original: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(result["plan"], original);
        assert_eq!(result["verb"], verb);
        assert_eq!(result["plan_digest"], digest);
        assert_eq!(result["authority"], "none");
    }
}

#[test]
fn product_plan_create_review_and_store_preserve_the_independent_bytes() {
    let temp = Temp::new();
    let store = temp.0.join("store");
    fs::DirBuilder::new().mode(0o700).create(&store).unwrap();
    for vector in product_vectors() {
        let plan: Value = serde_json::from_str(vector["plan_input"].as_str().unwrap()).unwrap();
        let expected = vector["plan_canonical"].as_str().unwrap().as_bytes();
        let digest = vector["plan_digest"].as_str().unwrap();
        let id = plan["plan_id"].as_str().unwrap();
        let created = product_create(&plan, None);
        assert!(
            created.status.success(),
            "{}",
            String::from_utf8_lossy(&created.stderr)
        );
        assert_eq!(created.stdout, expected);
        let path = temp.0.join(format!("{id}.json"));
        fs::write(&path, vector["plan_input"].as_str().unwrap()).unwrap();

        let output = review(&path, "json");
        assert!(output.status.success());
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["plan"], plan);
        assert_eq!(report["plan_digest"], digest);
        assert_eq!(report["authority"], "none");

        let output = Command::new(env!("CARGO_BIN_EXE_rustiron-plan"))
            .arg("inspect")
            .arg(&path)
            .output()
            .unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        for (label, field) in [
            ("plan digest", None),
            ("site", Some("site_id")),
            ("destination", Some("destination_id")),
            (
                "destination policy sha256",
                Some("destination_policy_digest"),
            ),
            ("recipe", Some("recipe_id")),
            ("snapshot", Some("snapshot_id")),
            ("profile", Some("profile_id")),
        ] {
            let value = field.map_or(Some(digest), |field| plan[field].as_str());
            if let Some(value) = value {
                let expected = format!("{label}: {value}");
                assert!(text.lines().any(|line| line == expected), "{text}");
            }
        }
        assert!(text.contains("authority: none"));

        let imported = Command::new(env!("CARGO_BIN_EXE_rustiron"))
            .args(["plan", "import-file", "--plan-dir"])
            .arg(&store)
            .arg(&path)
            .args(["--output", "json"])
            .output()
            .unwrap();
        assert!(imported.status.success());
        let inspected = Command::new(env!("CARGO_BIN_EXE_rustiron"))
            .args(["plan", "inspect", "--plan-dir"])
            .arg(&store)
            .arg(id)
            .args(["--output", "json"])
            .output()
            .unwrap();
        assert!(inspected.status.success());
        let stored: Value = serde_json::from_slice(&inspected.stdout).unwrap();
        assert_eq!(stored["plan"], report["plan"]);
        assert_eq!(stored["plan_digest"], report["plan_digest"]);
        let exported = Command::new(env!("CARGO_BIN_EXE_rustiron"))
            .args(["plan", "export", "--plan-dir"])
            .arg(&store)
            .arg(id)
            .output()
            .unwrap();
        assert!(exported.status.success());
        assert_eq!(exported.stdout, expected);
    }
}

#[test]
fn product_creation_requires_destination_fields_and_review_refuses_lab_version() {
    let temp = Temp::new();
    for vector in product_vectors() {
        let mut plan: Value = serde_json::from_str(vector["plan_input"].as_str().unwrap()).unwrap();
        for field in ["destination_id", "destination_policy_digest"] {
            let refused = product_create(&plan, Some(field));
            assert_eq!(refused.status.code(), Some(2));
            let error: Value = serde_json::from_slice(&refused.stdout).unwrap();
            assert_eq!(error["error"]["code"], "INVALID_REQUEST");
        }
        let mut invalid = plan.clone();
        invalid["destination_policy_digest"] = json!("CANARY_INVALID_DIGEST");
        let refused = product_create(&invalid, None);
        assert_eq!(refused.status.code(), Some(2));
        assert!(refused.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&refused.stderr).contains("CANARY"));
        plan["schema_version"] = json!(1);
        let path = temp.0.join("wrong-version.json");
        fs::write(&path, plan.to_string()).unwrap();
        assert_eq!(review(&path, "json").status.code(), Some(2));
    }
}

fn product_vectors() -> Vec<Value> {
    serde_json::from_str(
        &fs::read_to_string(PathBuf::from(FIXTURES).join("product-backup-vectors.json")).unwrap(),
    )
    .unwrap()
}

fn product_create(plan: &Value, omitted: Option<&str>) -> std::process::Output {
    let (verb, fields) = match plan["verb"].as_str().unwrap() {
        "backup_capture" => ("product-backup-capture", ["recipe_id"].as_slice()),
        "restore_probe" => (
            "product-restore-probe",
            ["snapshot_id", "profile_id"].as_slice(),
        ),
        _ => panic!("expected a product backup fixture"),
    };
    let mut command = Command::new(env!("CARGO_BIN_EXE_rustiron"));
    command.args(["plan", "create", verb, "--output", "json"]);
    for field in [
        "plan_id",
        "host_id",
        "host_epoch",
        "profile_digest",
        "requester",
        "site_id",
        "destination_id",
        "destination_policy_digest",
        "valid_from",
        "expires_at",
    ]
    .into_iter()
    .chain(fields.iter().copied())
    .filter(|field| Some(*field) != omitted)
    {
        let value = &plan[field];
        let argument = value
            .as_str()
            .map_or_else(|| value.to_string(), str::to_owned);
        command
            .arg(format!("--{}", field.replace('_', "-")))
            .arg(argument);
    }
    for limitation in plan["limitations"].as_array().unwrap() {
        command.args(["--limitation", limitation.as_str().unwrap()]);
    }
    command.output().unwrap()
}

#[test]
fn human_review_shows_all_fields_and_escapes_terminal_and_bidi_controls() {
    let temp = Temp::new();
    let mut plan: serde_json::Value =
        serde_json::from_slice(&fs::read(PathBuf::from(FIXTURES).join("site-plan.json")).unwrap())
            .unwrap();
    plan["limitations"][0] = serde_json::Value::String("untrusted\u{202e}\u{1b}[31m".into());
    let path = temp.0.join("plan.json");
    fs::write(&path, serde_json::to_vec(&plan).unwrap()).unwrap();
    let output = review(&path, "human");
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("plan_id"));
    assert!(text.contains("expected_effects"));
    assert!(text.contains("limitations"));
    assert!(text.contains("\\u{202e}"));
    assert!(!text.contains('\u{202e}'));
    assert!(!text.contains('\u{1b}'));
    assert!(text.contains("authority: none"));
}

#[test]
fn invalid_and_unsafe_files_are_refused_without_echo() {
    let temp = Temp::new();
    let bad = temp.0.join("canary.json");
    fs::write(&bad, br#"{"secret":"CANARY_REJECTED"}"#).unwrap();
    let link = temp.0.join("link.json");
    std::os::unix::fs::symlink(PathBuf::from(FIXTURES).join("site-plan.json"), &link).unwrap();
    for path in [&bad, &link, &PathBuf::from("/dev/null")] {
        let output = review(path, "json");
        assert_eq!(output.status.code(), Some(2));
        assert!(!String::from_utf8_lossy(&output.stdout).contains("CANARY_REJECTED"));
        assert!(!String::from_utf8_lossy(&output.stdout).contains(temp.0.to_str().unwrap()));
    }
}

#[test]
fn oversized_review_input_is_refused_before_parsing() {
    let temp = Temp::new();
    let path = temp.0.join("large.json");
    fs::write(&path, vec![b' '; rustiron_contracts::MAX_REQUEST_BYTES + 1]).unwrap();
    let output = review(&path, "json");
    assert_eq!(output.status.code(), Some(2));
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["error"]["code"], "REQUEST_TOO_LARGE");
}

#[test]
fn network_commands_still_require_an_explicit_socket() {
    let output = Command::new(env!("CARGO_BIN_EXE_rustiron"))
        .args(["doctor", "--output", "json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}
