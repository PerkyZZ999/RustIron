//! W372: `plan create site-readopt` and `site-readopt-generation` emit the
//! independently encoded vectors, and `plan review-file` shows every field.
//! Nothing is observed, signed or submitted.

use std::process::Command;

fn vector(name: &str) -> serde_json::Value {
    let all: serde_json::Value = serde_json::from_str(include_str!(
        "../../contracts/tests/fixtures/readopt-plan-vectors.json"
    ))
    .unwrap();
    all.as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap()
        .clone()
}

const COMMON: [&str; 18] = [
    "--host-id",
    "host_lab",
    "--host-epoch",
    "epoch_2",
    "--profile-digest",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "--requester",
    "agent_1",
    "--previous-epoch",
    "epoch_1",
    "--observed-at",
    "990",
    "--valid-from",
    "1000",
    "--expires-at",
    "2000",
    "--limitation",
    "SYNTHETIC re-adoption fixture",
];

fn create(command: &str, extra: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rustiron"))
        .args(["plan", "create", command])
        .args(COMMON)
        .args(extra)
        .output()
        .unwrap()
}

#[test]
fn the_site_form_matches_the_independent_vector() {
    let output = create(
        "site-readopt",
        &[
            "--plan-id",
            "plan_readopt_site",
            "--evidence-sha256",
            &"c".repeat(64),
            "--site-id",
            "blog1",
            "--hostname",
            "blog1.example.test",
            "--quota-block-hard-kib",
            "262144",
            "--quota-inode-hard",
            "20000",
            "--floor-uid",
            "3002",
            "--floor-category",
            "202",
        ],
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        vector("site")["plan_canonical"].as_str().unwrap()
    );
}

#[test]
fn the_generation_form_matches_the_independent_vector() {
    let output = create(
        "site-readopt-generation",
        &[
            "--plan-id",
            "plan_readopt_generation",
            "--evidence-sha256",
            &"d".repeat(64),
            "--site-id",
            "blog2",
            "--site-id",
            "blog1",
            "--expected-generation",
            "rbc7e46957fb865b0",
            "--expected-digest",
            &"b".repeat(64),
        ],
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        vector("generation")["plan_canonical"].as_str().unwrap()
    );
}

#[test]
fn a_floor_needs_both_values_and_a_repeated_site_is_refused() {
    let output = create(
        "site-readopt",
        &[
            "--plan-id",
            "plan_x",
            "--evidence-sha256",
            &"c".repeat(64),
            "--site-id",
            "blog1",
            "--hostname",
            "blog1.example.test",
            "--quota-block-hard-kib",
            "262144",
            "--quota-inode-hard",
            "20000",
            "--floor-uid",
            "3002",
        ],
    );
    assert!(!output.status.success());
    let output = create(
        "site-readopt-generation",
        &[
            "--plan-id",
            "plan_x",
            "--evidence-sha256",
            &"d".repeat(64),
            "--site-id",
            "blog1",
            "--site-id",
            "blog1",
            "--expected-generation",
            "rbc7e46957fb865b0",
            "--expected-digest",
            &"b".repeat(64),
        ],
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("INVALID_PLAN"));
}

#[test]
fn review_shows_the_form_previous_epoch_and_evidence() {
    let directory = std::env::temp_dir().join(format!("ri-readopt-review-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("plan.json");
    std::fs::write(&path, vector("site")["plan_canonical"].as_str().unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_rustiron-plan"))
        .arg("inspect")
        .arg(&path)
        .output()
        .unwrap();
    let review = Command::new(env!("CARGO_BIN_EXE_rustiron"))
        .args(["plan", "review-file"])
        .arg(&path)
        .args(["--output", "json"])
        .output()
        .unwrap();
    std::fs::remove_dir_all(&directory).unwrap();
    assert!(review.status.success(), "{review:?}");
    let review: serde_json::Value = serde_json::from_slice(&review.stdout).unwrap();
    assert_eq!(review["verb"], "site_readopt");
    assert_eq!(review["plan"]["previous_epoch"], "epoch_1");
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "site_readopt",
        "previous epoch",
        "epoch_1",
        &"c".repeat(64),
        "uid 3002, category 202",
        "creates, changes and deletes nothing",
    ] {
        assert!(text.contains(expected), "{expected} missing in {text}");
    }
}
