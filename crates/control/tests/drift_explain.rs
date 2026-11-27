//! W615 (P24): CLI integration tests for `rustiron-control --explain-drift`.

use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::symlink,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

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

fn tmp_dir() -> PathBuf {
    let suffix = unique_suffix();
    let dir = PathBuf::from("/tmp").join(format!("ri-p24-{}-{suffix}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn explain_drift_cli_outputs_json_and_human_without_mutating_input() {
    let dir = tmp_dir();
    let obs_path = dir.join("merged.json");
    let doc = json!({
        "host": {
            "signature_verifier": { "matches": false, "package_verified": true }
        },
        "ols": {
            "parent_reviewed": true,
            "explained_by_journal": false,
            "clean": false,
            "current": "gen_manual"
        },
        "sites": [
            { "site_id": "cp02", "hostname": "cp02.example.test", "state": "succeeded", "ejected": false },
            { "site_id": "ej01", "hostname": "ej01.example.test", "state": "succeeded", "ejected": true }
        ],
        "machine": {
            "observed_at": 1_795_500_000,
            "firewall": { "readable": false },
            "ols_map": { "readable": true, "hosts": ["cp02.example.test", "ej01.example.test", "unknown.example.test"] },
            "packages": { "duplicate_count": 0 },
            "failed_units": { "readable": true, "units": ["foreign-worker.service"] }
        }
    });
    let raw = serde_json::to_vec(&doc).unwrap();
    fs::write(&obs_path, &raw).unwrap();

    // JSON mode
    let out = Command::new(env!("CARGO_BIN_EXE_rustiron-control"))
        .arg("--explain-drift")
        .arg(&obs_path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["schema"], "rustiron-drift-explanation/1");
    assert_eq!(report["auto_reset"], false);
    assert_eq!(report["preserves_foreign_state"], true);
    assert_eq!(report["ejected_sites_preserved"], 1);
    assert_eq!(report["summary"], "drift_blocks_mutations");

    // Human mode
    let human_out = Command::new(env!("CARGO_BIN_EXE_rustiron-control"))
        .arg("--explain-drift")
        .arg(&obs_path)
        .arg("--human")
        .output()
        .unwrap();
    assert!(human_out.status.success());
    let human_text = String::from_utf8(human_out.stdout).unwrap();
    assert!(human_text.contains("auto_reset=false"));
    assert!(human_text.contains("unknown.example.test"));
    assert!(human_text.contains("foreign-worker.service"));

    // Input file untouched byte-for-byte
    assert_eq!(fs::read(&obs_path).unwrap(), raw);

    // Symlink input refused (O_NOFOLLOW)
    let link = dir.join("link.json");
    symlink(&obs_path, &link).unwrap();
    let link_out = Command::new(env!("CARGO_BIN_EXE_rustiron-control"))
        .arg("--explain-drift")
        .arg(&link)
        .output()
        .unwrap();
    assert!(!link_out.status.success());

    let _ = fs::remove_dir_all(&dir);
}
