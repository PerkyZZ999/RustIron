//! W619 (P18 Slice 1): CLI integration tests for `rustiron-control --verify-gateway-request`.

use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::symlink,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const NOW: u64 = 1_795_800_000;

fn tmp_dir() -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = PathBuf::from("/tmp").join(format!("ri-p18-{}-{suffix}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn verify_gateway_request_cli_allows_valid_and_denies_escalation_and_symlinks() {
    let dir = tmp_dir();
    let ok_path = dir.join("req_ok.json");
    let bad_path = dir.join("req_bad.json");

    let ok_doc = json!({
        "schema": "rustiron-gateway-request/1",
        "request_nonce": "nonce_cli_1",
        "session": {
            "ssh_original_command": "operation-status op_42",
            "ssh_auth_sock_present": false,
            "pty_allocated": false,
            "authorized_key_restrict": true,
            "host_key_pinned": true
        },
        "gateway": {
            "host_id": "host-alpha",
            "host_epoch": "policy_3",
            "environment": "staging",
            "human_operator_id": "charles",
            "revoked_capabilities": [],
            "revoked_agents": [],
            "seen_nonces": []
        },
        "capability": {
            "capability_id": "cap_cli_1",
            "agent_id": "agent_reader",
            "host_id": "host-alpha",
            "host_epoch": "policy_3",
            "environment": "staging",
            "allowed_verbs": ["operation-status"],
            "allowed_sites": [],
            "max_risk_tier": "read",
            "issued_at": NOW - 30,
            "expires_at": NOW + 300
        }
    });
    let mut bad_doc = ok_doc.clone();
    bad_doc["session"]["ssh_original_command"] = json!("sudo /bin/sh");

    let raw_ok = serde_json::to_vec(&ok_doc).unwrap();
    fs::write(&ok_path, &raw_ok).unwrap();
    fs::write(&bad_path, serde_json::to_vec(&bad_doc).unwrap()).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_rustiron-control"))
        .arg("--verify-gateway-request")
        .arg(&ok_path)
        .args(["--now", &NOW.to_string()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rep: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rep["schema"], "rustiron-gateway-decision/1");
    assert_eq!(rep["allowed"], true);
    assert_eq!(rep["reconcile_by_operation_id"], "op_42");
    assert_eq!(rep["invariants"]["can_mint_approval"], false);

    let bad_out = Command::new(env!("CARGO_BIN_EXE_rustiron-control"))
        .arg("--verify-gateway-request")
        .arg(&bad_path)
        .args(["--now", &NOW.to_string(), "--human"])
        .output()
        .unwrap();
    assert!(bad_out.status.success());
    let text = String::from_utf8(bad_out.stdout).unwrap();
    assert!(text.contains("allowed=false"));
    assert!(text.contains("GENERIC_SUDO_DENIED"));

    assert_eq!(fs::read(&ok_path).unwrap(), raw_ok);

    let link = dir.join("link.json");
    symlink(&ok_path, &link).unwrap();
    let link_out = Command::new(env!("CARGO_BIN_EXE_rustiron-control"))
        .arg("--verify-gateway-request")
        .arg(&link)
        .output()
        .unwrap();
    assert!(!link_out.status.success());

    let _ = fs::remove_dir_all(&dir);
}
