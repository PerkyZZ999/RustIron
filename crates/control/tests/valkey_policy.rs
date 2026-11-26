//! W622 (P21 Slice 1): CLI integration tests for `rustiron-control --verify-valkey-plan`.

use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::symlink,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn tmp_dir() -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = PathBuf::from("/tmp").join(format!("ri-p21-{}-{suffix}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn verify_valkey_plan_cli_enforces_p21_and_refuses_symlinks() {
    let dir = tmp_dir();
    let plan_path = dir.join("valkey.json");
    let doc = json!({
        "schema": "rustiron-valkey-plan/1",
        "host_valkey_memory_budget_mib": 256,
        "sites": [
            {
                "site_id": "woo1",
                "workload_evidence": {
                    "compared_against_tuned_baseline": true,
                    "measured_benefit_percent": 18.4,
                    "randomized_repeats": 5
                },
                "isolation": {
                    "tcp_port": 0,
                    "unix_socket": "/run/rustiron-site-valkey/rs_woo1/valkey.sock",
                    "uid": 2201,
                    "mcs_category": "c30,c31",
                    "namespace_prefix": "rs_woo1:obj:",
                    "acl_credentials_path": "/srv/sites/rs_woo1/private/valkey.acl",
                    "acl_credentials_mode": "0600"
                },
                "limits": {
                    "maxmemory_mib": 128,
                    "eviction_policy": "volatile-lru"
                },
                "behavior": {
                    "outage_graceful_bypass": true,
                    "staleness_invalidation_verified": true,
                    "clean_disable_verified": true,
                    "private_auth_cart_checkout_safe": true
                }
            }
        ]
    });
    let raw = serde_json::to_vec(&doc).unwrap();
    fs::write(&plan_path, &raw).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_rustiron-control"))
        .arg("--verify-valkey-plan")
        .arg(&plan_path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rep: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rep["schema"], "rustiron-valkey-check/1");
    assert_eq!(rep["passed"], true);
    assert_eq!(rep["mandatory_for_all_sites"], false);
    assert_eq!(rep["shared_multi_tenant_instance_allowed"], false);

    let human_out = Command::new(env!("CARGO_BIN_EXE_rustiron-control"))
        .arg("--verify-valkey-plan")
        .arg(&plan_path)
        .arg("--human")
        .output()
        .unwrap();
    assert!(human_out.status.success());
    let text = String::from_utf8(human_out.stdout).unwrap();
    assert!(text.contains("passed=true"));
    assert!(text.contains("shared_instance=false"));

    assert_eq!(fs::read(&plan_path).unwrap(), raw);

    let link = dir.join("link.json");
    symlink(&plan_path, &link).unwrap();
    let link_out = Command::new(env!("CARGO_BIN_EXE_rustiron-control"))
        .arg("--verify-valkey-plan")
        .arg(&link)
        .output()
        .unwrap();
    assert!(!link_out.status.success());

    let _ = fs::remove_dir_all(&dir);
}
