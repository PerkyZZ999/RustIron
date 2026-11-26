//! W617 (P22): CLI integration tests for `rustiron-control --evaluate-experiment`.

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
    let dir = PathBuf::from("/tmp").join(format!("ri-p22-{}-{suffix}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn trial(arm: &str, val: f64) -> Value {
    json!({
        "arm": arm,
        "workload_digest": "sha256:p22_cli_test",
        "primary_value": val,
        "http_requests": 1000,
        "http_errors": 0,
        "correctness_passed": true,
        "private_cache_safe": true,
        "peak_rss_mib": 120.0,
        "peak_cpu_percent": 45.0
    })
}

#[test]
fn evaluate_experiment_cli_outputs_retain_revert_and_refuses_symlinks() {
    let dir = tmp_dir();
    let card_path = dir.join("card.json");
    let doc = json!({
        "schema": "rustiron-experiment-card/1",
        "card_id": "exp-lscache-01",
        "site_id": "cp02",
        "title": "Targeted tag-based LSCache invalidation on post update",
        "hypothesis": "Targeted tag invalidation increases cache-hit RPS by >= 15%.",
        "risks": ["Stale archive widgets if tag map misses a taxonomy."],
        "change": {
            "category": "lscache_invalidation",
            "automatic_db_change": false,
            "caches_private_auth_or_cart": false
        },
        "budget": {
            "blast_radius_envelope_id": "env_p22_1",
            "max_error_rate": 0.005,
            "max_memory_rss_mib": 256.0,
            "max_cpu_percent": 80.0
        },
        "preregistered_criteria": {
            "primary_metric": "rps",
            "direction": "higher_is_better",
            "min_meaningful_effect_percent": 15.0,
            "confidence_level": 0.95,
            "min_randomized_repeats": 5,
            "randomized_order": true
        },
        "trials": [
            trial("baseline", 120.0),
            trial("candidate", 165.0),
            trial("candidate", 162.0),
            trial("baseline", 118.0),
            trial("baseline", 122.0),
            trial("candidate", 168.0),
            trial("candidate", 164.0),
            trial("baseline", 119.0),
            trial("baseline", 121.0),
            trial("candidate", 166.0)
        ]
    });
    let raw = serde_json::to_vec(&doc).unwrap();
    fs::write(&card_path, &raw).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_rustiron-control"))
        .arg("--evaluate-experiment")
        .arg(&card_path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["schema"], "rustiron-experiment-result/1");
    assert_eq!(report["verdict"], "retain");
    assert_eq!(report["recommendation"], "retain");
    assert_eq!(report["benefit_proven"], true);
    assert_eq!(report["automatic_db_changes_allowed"], false);

    let human_out = Command::new(env!("CARGO_BIN_EXE_rustiron-control"))
        .arg("--evaluate-experiment")
        .arg(&card_path)
        .arg("--human")
        .output()
        .unwrap();
    assert!(human_out.status.success());
    let human_text = String::from_utf8(human_out.stdout).unwrap();
    assert!(human_text.contains("verdict=retain"));
    assert!(human_text.contains("auto_db=false"));

    // Input file untouched byte-for-byte
    assert_eq!(fs::read(&card_path).unwrap(), raw);

    // Symlink refused (O_NOFOLLOW)
    let link = dir.join("link.json");
    symlink(&card_path, &link).unwrap();
    let link_out = Command::new(env!("CARGO_BIN_EXE_rustiron-control"))
        .arg("--evaluate-experiment")
        .arg(&link)
        .output()
        .unwrap();
    assert!(!link_out.status.success());

    let _ = fs::remove_dir_all(&dir);
}
