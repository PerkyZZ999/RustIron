//! W621 (P20 Slice 1): CLI integration tests for `rustiron-control --verify-php-profile`.

use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::symlink,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const NOW: u64 = 1_795_900_000;

fn tmp_dir() -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = PathBuf::from("/tmp").join(format!("ri-p20-{}-{suffix}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn verify_php_profile_cli_validates_isolation_and_refuses_symlinks() {
    let dir = tmp_dir();
    let plan_path = dir.join("php-plan.json");
    let doc = json!({
        "schema": "rustiron-php-profile-plan/1",
        "sites": [
            {
                "site_id": "cp02",
                "current_profile": "php84_wp_v1",
                "target_profile": "php85_wp_v1",
                "isolation": {
                    "uid": 2010,
                    "mcs_category": "c10,c11",
                    "selinux_domain": "rustiron_php_t",
                    "socket_path": "/run/rustiron-site-php/php85_wp_v1_rs_cp02.sock",
                    "private_tmp_dir": "/srv/sites/rs_cp02/private/tmp",
                    "opcache_dir": "/srv/sites/rs_cp02/private/opcache_php85",
                    "cgroup_memory_max_mib": 256,
                    "cgroup_cpu_quota_percent": 100
                },
                "switch": {
                    "latest_backup_finished_at": NOW - 1200,
                    "extensions_compatible": true,
                    "rollback_plan_ready": true
                }
            }
        ]
    });
    let raw = serde_json::to_vec(&doc).unwrap();
    fs::write(&plan_path, &raw).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_rustiron-control"))
        .arg("--verify-php-profile")
        .arg(&plan_path)
        .args(["--now", &NOW.to_string()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rep: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rep["schema"], "rustiron-php-profile-check/1");
    assert_eq!(rep["passed"], true);
    assert_eq!(rep["all_php_versions_supported"], false);
    assert_eq!(rep["shared_isolation_shortcuts_allowed"], false);

    let human_out = Command::new(env!("CARGO_BIN_EXE_rustiron-control"))
        .arg("--verify-php-profile")
        .arg(&plan_path)
        .args(["--now", &NOW.to_string(), "--human"])
        .output()
        .unwrap();
    assert!(human_out.status.success());
    let text = String::from_utf8(human_out.stdout).unwrap();
    assert!(text.contains("passed=true"));
    assert!(text.contains("all_versions=false"));

    assert_eq!(fs::read(&plan_path).unwrap(), raw);

    let link = dir.join("link.json");
    symlink(&plan_path, &link).unwrap();
    let link_out = Command::new(env!("CARGO_BIN_EXE_rustiron-control"))
        .arg("--verify-php-profile")
        .arg(&link)
        .output()
        .unwrap();
    assert!(!link_out.status.success());

    let _ = fs::remove_dir_all(&dir);
}
