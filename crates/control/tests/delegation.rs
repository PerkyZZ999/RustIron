//! W623 (CP07 Slice 1): CLI integration tests for `rustiron-control --verify-delegation`.

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
    let dir = PathBuf::from("/tmp").join(format!("ri-cp07-{}-{suffix}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn verify_delegation_cli_passes_clean_policy_and_refuses_symlinks() {
    let dir = tmp_dir();
    let policy_path = dir.join("delegation.json");
    let doc = json!({
        "schema": "rustiron-delegation-policy/1",
        "built_in_billing_engine": false,
        "host_disk_budget_mib": 10_000,
        "accounts": [
            { "account_id": "admin1", "role": "admin", "disk_quota_mib": 10_000 },
            { "account_id": "t1", "role": "tenant_user", "disk_quota_mib": 3_000, "allowed_service_controls": ["site_php_restart"] },
            { "account_id": "t2", "role": "tenant_user", "disk_quota_mib": 3_000, "allowed_service_controls": ["site_php_restart"] }
        ],
        "sites": [
            { "site_id": "alpha", "owner_account_id": "t1", "unix_uid": 3101, "disk_quota_mib": 1_500 },
            { "site_id": "beta", "owner_account_id": "t2", "unix_uid": 3102, "disk_quota_mib": 1_500 }
        ],
        "access_checks": [
            { "actor_account_id": "t1", "target_site_id": "beta", "action": "site_php_restart", "expect_denied": true }
        ]
    });
    let raw = serde_json::to_vec(&doc).unwrap();
    fs::write(&policy_path, &raw).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_rustiron-control"))
        .arg("--verify-delegation")
        .arg(&policy_path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rep: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rep["schema"], "rustiron-delegation-check/1");
    assert_eq!(rep["passed"], true);
    assert_eq!(rep["built_in_billing_engine"], false);
    assert_eq!(rep["access_results"][0]["allowed"], false);

    let human_out = Command::new(env!("CARGO_BIN_EXE_rustiron-control"))
        .arg("--verify-delegation")
        .arg(&policy_path)
        .arg("--human")
        .output()
        .unwrap();
    assert!(human_out.status.success());
    let text = String::from_utf8(human_out.stdout).unwrap();
    assert!(text.contains("passed=true"));
    assert!(text.contains("billing_engine=false"));

    assert_eq!(fs::read(&policy_path).unwrap(), raw);

    let link = dir.join("link.json");
    symlink(&policy_path, &link).unwrap();
    let link_out = Command::new(env!("CARGO_BIN_EXE_rustiron-control"))
        .arg("--verify-delegation")
        .arg(&link)
        .output()
        .unwrap();
    assert!(!link_out.status.success());

    let _ = fs::remove_dir_all(&dir);
}
