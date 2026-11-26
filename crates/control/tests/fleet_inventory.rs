//! W618 (P28 Slice 1): CLI integration tests for `rustiron-control --aggregate-hosts`.

use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::symlink,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const NOW: u64 = 1_795_700_000;

fn tmp_dir() -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = PathBuf::from("/tmp").join(format!("ri-p28-{}-{suffix}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn aggregate_hosts_cli_reports_skew_partitions_and_refuses_symlinks() {
    let dir = tmp_dir();
    let manifest_path = dir.join("fleet.json");
    let doc = json!({
        "schema": "rustiron-fleet-observations/1",
        "hosts": [
            {
                "host_id": "vps-alpha",
                "transport_state": "reachable",
                "observation": {
                    "host": { "host_id": "vps-alpha", "signer_epoch": "policy_3", "journal_version": 44 },
                    "machine": { "observed_at": NOW - 10 },
                    "sites": [{ "site_id": "cp02", "state": "succeeded" }]
                },
                "pending_approval_grants": [
                    { "grant_id": "g_wrong_host", "operation_id": "op_9", "target_host_id": "vps-beta", "target_epoch": "policy_3" }
                ]
            },
            {
                "host_id": "vps-beta",
                "transport_state": "partitioned",
                "observation": null
            }
        ]
    });
    let raw = serde_json::to_vec(&doc).unwrap();
    fs::write(&manifest_path, &raw).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_rustiron-control"))
        .arg("--aggregate-hosts")
        .arg(&manifest_path)
        .arg("--now")
        .arg(NOW.to_string())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rep: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rep["schema"], "rustiron-fleet-inventory/1");
    assert_eq!(rep["read_only"], true);
    assert_eq!(rep["fleet_wide_transaction"], false);
    assert_eq!(rep["distributed_implicit_authority"], false);
    assert_eq!(rep["summary"]["partitioned_hosts"], 1);
    assert_eq!(rep["summary"]["cross_host_grant_refusals"], 1);

    let human_out = Command::new(env!("CARGO_BIN_EXE_rustiron-control"))
        .arg("--aggregate-hosts")
        .arg(&manifest_path)
        .args(["--now", &NOW.to_string(), "--human"])
        .output()
        .unwrap();
    assert!(human_out.status.success());
    let text = String::from_utf8(human_out.stdout).unwrap();
    assert!(text.contains("fleet_wide_transaction=false"));
    assert!(text.contains("vps-alpha"));
    assert!(text.contains("vps-beta"));

    assert_eq!(fs::read(&manifest_path).unwrap(), raw);

    let link = dir.join("link.json");
    symlink(&manifest_path, &link).unwrap();
    let link_out = Command::new(env!("CARGO_BIN_EXE_rustiron-control"))
        .arg("--aggregate-hosts")
        .arg(&link)
        .output()
        .unwrap();
    assert!(!link_out.status.success());

    let _ = fs::remove_dir_all(&dir);
}
