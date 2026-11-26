//! W616 (P25): CLI integration tests for `rustiron-control --background-budget`.

use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::symlink,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const NOW: u64 = 1_795_600_000;

fn tmp_dir() -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = PathBuf::from("/tmp").join(format!("ri-p25-{}-{suffix}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn background_budget_cli_handles_burst_rpo_override_and_symlink_refusal() {
    let dir = tmp_dir();
    let obs_path = dir.join("merged.json");
    let doc = json!({
        "schema": "rustiron-lab-observation/1",
        "sites": [
            { "site_id": "cp02", "state": "succeeded", "ejected": false }
        ],
        "captures": [
            { "capture_id": "cap_old", "site_id": "cp02", "state": "succeeded", "finished_at": NOW - (23 * 3600) }
        ],
        "machine": {
            "observed_at": NOW - 20,
            "cpu": { "count": 4, "load": [4.4, 3.6, 2.0] },
            "memory": { "total_bytes": 8_000_000_000_u64, "available_bytes": 4_000_000_000_u64 },
            "disk": { "total_bytes": 100_000_000_000_u64, "available_bytes": 50_000_000_000_u64 }
        }
    });
    let raw = serde_json::to_vec(&doc).unwrap();
    fs::write(&obs_path, &raw).unwrap();

    // 1. Busy host defers site_cron
    let defer_out = Command::new(env!("CARGO_BIN_EXE_rustiron-control"))
        .args(["--background-budget"])
        .arg(&obs_path)
        .args(["--job", "site_cron", "--site", "cp02", "--now"])
        .arg(NOW.to_string())
        .output()
        .unwrap();
    assert!(
        defer_out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&defer_out.stderr)
    );
    let defer_json: Value = serde_json::from_slice(&defer_out.stdout).unwrap();
    assert_eq!(defer_json["schema"], "rustiron-background-budget/1");
    assert_eq!(defer_json["decision"], "defer");
    assert_eq!(defer_json["allow_run"], false);
    assert_eq!(defer_json["autonomous_db_tuning"], false);

    // 2. Same busy host overrides deferral for backup_capture nearing RPO (23 h >= 22 h guard)
    let rpo_out = Command::new(env!("CARGO_BIN_EXE_rustiron-control"))
        .args(["--background-budget"])
        .arg(&obs_path)
        .args(["--job", "backup_capture", "--site", "cp02", "--now"])
        .arg(NOW.to_string())
        .output()
        .unwrap();
    assert!(rpo_out.status.success());
    let rpo_json: Value = serde_json::from_slice(&rpo_out.stdout).unwrap();
    assert_eq!(rpo_json["decision"], "run_rpo_override");
    assert_eq!(rpo_json["allow_run"], true);

    // 3. Operator override (--budget-override disable) and --human mode
    let human_out = Command::new(env!("CARGO_BIN_EXE_rustiron-control"))
        .args(["--background-budget"])
        .arg(&obs_path)
        .args([
            "--job",
            "site_cron",
            "--budget-override",
            "disable",
            "--now",
            &NOW.to_string(),
            "--human",
        ])
        .output()
        .unwrap();
    assert!(human_out.status.success());
    let human_text = String::from_utf8(human_out.stdout).unwrap();
    assert!(human_text.contains("decision=run_operator_gate_disabled"));
    assert!(human_text.contains("autonomous_db_tuning=false"));

    // 4. Input observation untouched byte-for-byte
    assert_eq!(fs::read(&obs_path).unwrap(), raw);

    // 5. Symlink input refused (O_NOFOLLOW)
    let link = dir.join("link.json");
    symlink(&obs_path, &link).unwrap();
    let link_out = Command::new(env!("CARGO_BIN_EXE_rustiron-control"))
        .arg("--background-budget")
        .arg(&link)
        .output()
        .unwrap();
    assert!(!link_out.status.success());

    let _ = fs::remove_dir_all(&dir);
}
