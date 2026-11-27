//! Plan import stores canonical bytes and does not submit them.

use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../contracts/tests/fixtures/site-plan.json"
);

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
            "ri-plan-cli-{}-{}",
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

fn rustiron() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rustiron"))
}

#[test]
fn import_then_export_roundtrips_and_a_changed_plan_conflicts() {
    let temp = Temp::new();
    let first = rustiron()
        .args(["plan", "import-file", "--plan-dir"])
        .arg(&temp.0)
        .arg(FIXTURE)
        .args(["--output", "json"])
        .output()
        .unwrap();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(report["plan_id"], "plan_site");
    assert_eq!(report["stored"], "new");
    assert_eq!(report["authority"], "none");
    let again = rustiron()
        .args(["plan", "import-file", "--plan-dir"])
        .arg(&temp.0)
        .arg(FIXTURE)
        .args(["--output", "json"])
        .output()
        .unwrap();
    assert!(again.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&again.stdout).unwrap()["stored"],
        "existing"
    );
    let exported = rustiron()
        .args(["plan", "export", "--plan-dir"])
        .arg(&temp.0)
        .arg("plan_site")
        .output()
        .unwrap();
    assert!(exported.status.success());
    let original = fs::read(FIXTURE).unwrap();
    let exported_value: serde_json::Value = serde_json::from_slice(&exported.stdout).unwrap();
    let original_value: serde_json::Value = serde_json::from_slice(&original).unwrap();
    assert_eq!(exported_value, original_value);
    let mut changed: serde_json::Value = original_value;
    changed["expires_at"] = 2001.into();
    let path = temp.0.join("changed.json");
    fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
    let conflict = rustiron()
        .args(["plan", "import-file", "--plan-dir"])
        .arg(&temp.0)
        .arg(&path)
        .args(["--output", "json"])
        .output()
        .unwrap();
    assert_eq!(conflict.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&conflict.stdout).contains("PLAN_ID_CONFLICT"));
}

#[test]
fn inspect_shows_the_stored_plan_and_does_not_grant_authority() {
    let temp = Temp::new();
    let imported = rustiron()
        .args(["plan", "import-file", "--plan-dir"])
        .arg(&temp.0)
        .arg(FIXTURE)
        .args(["--output", "json"])
        .output()
        .unwrap();
    assert!(imported.status.success());
    let human = rustiron()
        .args(["plan", "inspect", "--plan-dir"])
        .arg(&temp.0)
        .arg("plan_site")
        .args(["--output", "human"])
        .output()
        .unwrap();
    assert!(human.status.success());
    let text = String::from_utf8(human.stdout).unwrap();
    assert!(text.contains("verb: site_provision"));
    assert!(
        text.contains(
            "plan digest: c33d38f7e35973b5dfb88846d667b06ee9f1d2544fe1fcfa35354797553b2ccf"
        )
    );
    assert!(text.contains("authority: none"));
    assert!(text.contains("blog1.example.test"));
    let json = rustiron()
        .args(["plan", "inspect", "--plan-dir"])
        .arg(&temp.0)
        .arg("plan_site")
        .args(["--output", "json"])
        .output()
        .unwrap();
    assert!(json.status.success());
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    let original: serde_json::Value = serde_json::from_slice(&fs::read(FIXTURE).unwrap()).unwrap();
    assert_eq!(report["scope"], "plan_inspect");
    assert_eq!(report["plan"], original);
    assert_eq!(report["authority"], "none");
    let missing = rustiron()
        .args(["plan", "inspect", "--plan-dir"])
        .arg(&temp.0)
        .arg("canary_plan_id")
        .args(["--output", "json"])
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(4));
    let body = String::from_utf8(missing.stdout).unwrap();
    assert!(body.contains("PLAN_NOT_FOUND"));
    assert!(!body.contains("canary_plan_id"));
}

#[test]
fn apply_uses_the_stored_plan_and_refuses_a_different_grant_before_sending() {
    let temp = Temp::new();
    let imported = rustiron()
        .args(["plan", "import-file", "--plan-dir"])
        .arg(&temp.0)
        .arg(FIXTURE)
        .args(["--output", "json"])
        .output()
        .unwrap();
    assert!(imported.status.success());
    let grant = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../contracts/tests/fixtures/site-grant.json"
    );
    let signature = temp.0.join("signature");
    fs::write(&signature, b"synthetic_signature").unwrap();
    let socket = temp.0.join("missing.sock");
    let matching = rustiron()
        .arg("--socket")
        .arg(&socket)
        .args(["plan", "apply", "--plan-dir"])
        .arg(&temp.0)
        .args(["plan_site", "--grant-file", grant, "--signature-file"])
        .arg(&signature)
        .args([
            "--operation-id",
            "operation_1",
            "--idempotency-key",
            "retry_1",
            "--output",
            "json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        matching.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&matching.stdout)
    );
    let sent: serde_json::Value = serde_json::from_slice(&matching.stdout).unwrap();
    assert_eq!(sent["data"]["value"]["outcome"]["kind"], "not_sent");
    let mut wrong: serde_json::Value = serde_json::from_slice(&fs::read(grant).unwrap()).unwrap();
    wrong["plan_digest"] = "ab".repeat(32).into();
    let wrong_path = temp.0.join("wrong-grant.json");
    fs::write(&wrong_path, serde_json::to_vec(&wrong).unwrap()).unwrap();
    let refused = rustiron()
        .arg("--socket")
        .arg(&socket)
        .args(["plan", "apply", "--plan-dir"])
        .arg(&temp.0)
        .arg("plan_site")
        .arg("--grant-file")
        .arg(&wrong_path)
        .arg("--signature-file")
        .arg(&signature)
        .args([
            "--operation-id",
            "operation_1",
            "--idempotency-key",
            "retry_1",
            "--output",
            "json",
        ])
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(4));
    let body: serde_json::Value = serde_json::from_slice(&refused.stdout).unwrap();
    assert_eq!(body["error"], "PLAN_DIGEST_MISMATCH");
    assert_eq!(body["attempt"], "not_sent");
}
