//! Coordinator export and journal identity comparison do not grant authority.

use rustiron_contracts::decode_inventory_snapshot;
use rustiron_core::InventoryStore;
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const REPORT: &[u8] = br#"{"schema_version":1,"report":{"reported_at":42,"source":"operator_report"},"complete":true,"sites":[{"site_id":"blog5","name":"blog5.example.test","configuration_generation":null},{"site_id":"blog9","name":"blog9.example.test","configuration_generation":"recorded"}]}"#;

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
            "ri-state-{}-{}",
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

fn filled(directory: &Path) {
    let mut store = InventoryStore::initialize(directory).unwrap();
    store
        .replace(&decode_inventory_snapshot(REPORT).unwrap())
        .unwrap();
}

fn rustiron() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rustiron"))
}

#[test]
fn export_round_trips_the_sorted_report() {
    let temp = Temp::new();
    filled(&temp.0);
    let output = rustiron()
        .args(["state", "export", "--state-dir"])
        .arg(&temp.0)
        .args(["--output", "json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let mut stdout = output.stdout;
    if stdout.last() == Some(&b'\n') {
        stdout.pop();
    }
    let parsed = decode_inventory_snapshot(&stdout).unwrap();
    assert_eq!(parsed.sites.len(), 2);
    assert_eq!(parsed.sites[0].site_id.as_str(), "blog5");
    assert_eq!(parsed.sites[1].site_id.as_str(), "blog9");
}

#[test]
fn compare_matches_journal_identities_and_reports_a_difference() {
    let temp = Temp::new();
    filled(&temp.0);
    let observation = temp.0.join("observe.json");
    fs::write(
        &observation,
        br#"{"schema":"rustiron-lab-observation/1","sites":[{"site_id":"blog9","hostname":"blog9.example.test","state":"succeeded"},{"site_id":"blog5","hostname":"blog5.example.test"}]}"#,
    )
    .unwrap();
    let matched = rustiron()
        .args(["state", "compare", "--state-dir"])
        .arg(&temp.0)
        .args(["--observation"])
        .arg(&observation)
        .args(["--output", "json"])
        .output()
        .unwrap();
    assert!(
        matched.status.success(),
        "{}",
        String::from_utf8_lossy(&matched.stdout)
    );
    let body: serde_json::Value = serde_json::from_slice(&matched.stdout).unwrap();
    assert_eq!(body["consistent"], true);
    assert_eq!(body["matched"], 2);
    assert_eq!(body["authority"], "none");
    fs::write(
        &observation,
        br#"{"schema":"rustiron-lab-observation/1","sites":[{"site_id":"blog5","hostname":"other.example.test"},{"site_id":"blog1","hostname":"blog1.example.test"}]}"#,
    )
    .unwrap();
    let drifted = rustiron()
        .args(["state", "compare", "--state-dir"])
        .arg(&temp.0)
        .args(["--observation"])
        .arg(&observation)
        .args(["--output", "json"])
        .output()
        .unwrap();
    assert_eq!(drifted.status.code(), Some(4));
    let body: serde_json::Value = serde_json::from_slice(&drifted.stdout).unwrap();
    assert_eq!(body["consistent"], false);
    assert_eq!(body["only_coordinator"][0], "blog9");
    assert_eq!(body["only_journal"][0], "blog1");
    assert_eq!(body["name_mismatch"][0]["site_id"], "blog5");
    fs::write(&observation, br#"{"schema":"other","sites":[]}"#).unwrap();
    let refused = rustiron()
        .args(["state", "compare", "--state-dir"])
        .arg(&temp.0)
        .args(["--observation"])
        .arg(&observation)
        .args(["--output", "json"])
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&refused.stdout).contains("INVALID_REQUEST"));
}
