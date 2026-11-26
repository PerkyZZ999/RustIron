//! `plan create` emits a closed plan and does not observe or sign.

use rustiron_contracts::approval::PreparedPlan;
use std::{fs, process::Command};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../contracts/tests/fixtures/site-plan.json"
);

fn create(observed_at: &str, hostname: &str) -> std::process::Output {
    create_with("plan_site", "SYNTHETIC fixture", observed_at, hostname, &[])
}

fn create_with(
    plan_id: &str,
    limitation: &str,
    observed_at: &str,
    hostname: &str,
    extra: &[&str],
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rustiron"))
        .args([
            "plan",
            "create",
            "site-provision",
            "--plan-id",
            plan_id,
            "--host-id",
            "host_lab",
            "--host-epoch",
            "epoch_1",
            "--profile-digest",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--requester",
            "agent_1",
            "--site-id",
            "blog1",
            "--hostname",
            hostname,
            "--recipe",
            "wordpress713_v1",
            "--recipe-digest",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "--observed-at",
            observed_at,
            "--valid-from",
            "1000",
            "--expires-at",
            "2000",
            "--limitation",
            limitation,
        ])
        .args(extra)
        .output()
        .unwrap()
}

/// W341: both quota flags make a schema v2 plan with the signed limits; it
/// matches the independently encoded vector byte for byte.
#[test]
fn site_provision_with_quota_matches_the_independent_v2_vector() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../contracts/tests/fixtures/site-plan-v2-vectors.json"
    ))
    .unwrap();
    let output = create_with(
        "plan_site_default",
        "SYNTHETIC v2 fixture",
        "990",
        "blog1.example.test",
        &[
            "--quota-block-hard-kib",
            "5242880",
            "--quota-inode-hard",
            "500000",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout,
        vectors[0]["plan_canonical"].as_str().unwrap().as_bytes()
    );
    let created = PreparedPlan::decode(&output.stdout).unwrap();
    assert_eq!(
        created.digest().as_str(),
        vectors[0]["plan_digest"].as_str().unwrap()
    );
}

#[test]
fn a_partial_or_out_of_bounds_quota_is_refused_without_a_plan() {
    for (flags, invalid_plan) in [
        (&["--quota-block-hard-kib", "5242880"][..], false),
        (&["--quota-inode-hard", "500000"][..], false),
        (
            &[
                "--quota-block-hard-kib",
                "65535",
                "--quota-inode-hard",
                "500000",
            ][..],
            true,
        ),
        (
            &[
                "--quota-block-hard-kib",
                "5242880",
                "--quota-inode-hard",
                "100000001",
            ][..],
            true,
        ),
    ] {
        let output = create_with(
            "plan_site",
            "SYNTHETIC fixture",
            "990",
            "blog1.example.test",
            flags,
        );
        assert_eq!(output.status.code(), Some(2), "{flags:?}");
        assert!(PreparedPlan::decode(&output.stdout).is_err(), "{flags:?}");
        assert_eq!(
            String::from_utf8_lossy(&output.stderr).contains("INVALID_PLAN"),
            invalid_plan,
            "{flags:?}"
        );
    }
}

#[test]
fn site_provision_matches_the_closed_fixture_digest_and_does_not_grant_authority() {
    let output = create("990", "blog1.example.test");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let created = PreparedPlan::decode(&output.stdout).unwrap();
    let fixture = PreparedPlan::decode(&fs::read(FIXTURE).unwrap()).unwrap();
    assert_eq!(created.digest(), fixture.digest());
    assert_eq!(created.kind().as_str(), "site_provision");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("signature"));
}

fn eject(observed_at: &str, digest: &str, compensation_until: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rustiron"))
        .args([
            "plan",
            "create",
            "site-eject",
            "--plan-id",
            "plan_eject",
            "--host-id",
            "host_lab",
            "--host-epoch",
            "epoch_1",
            "--profile-digest",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--requester",
            "agent_1",
            "--site-id",
            "blog5",
            "--expected-generation",
            "g1",
            "--expected-digest",
            digest,
            "--observed-at",
            observed_at,
            "--valid-from",
            "1000",
            "--expires-at",
            "2000",
            "--compensation-until",
            compensation_until,
            "--limitation",
            "SYNTHETIC fixture",
        ])
        .output()
        .unwrap()
}

#[test]
fn site_eject_matches_the_closed_fixture_and_does_not_eject() {
    let output = eject(
        "990",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "2100",
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let created = PreparedPlan::decode(&output.stdout).unwrap();
    let fixture = PreparedPlan::decode(
        &fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../contracts/tests/fixtures/eject-plan.json"
        ))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(created.digest(), fixture.digest());
    assert_eq!(created.kind().as_str(), "site_eject");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("signature"));
}

#[test]
fn site_eject_with_hostname_alone_matches_the_closed_v3_static_fixture() {
    let output = Command::new(env!("CARGO_BIN_EXE_rustiron"))
        .args([
            "plan",
            "create",
            "site-eject",
            "--plan-id",
            "plan_eject",
            "--host-id",
            "host_lab",
            "--host-epoch",
            "epoch_1",
            "--profile-digest",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--requester",
            "agent_1",
            "--site-id",
            "blog5",
            "--hostname",
            "static.example.test",
            "--expected-generation",
            "g1",
            "--expected-digest",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "--observed-at",
            "990",
            "--valid-from",
            "1000",
            "--expires-at",
            "2000",
            "--compensation-until",
            "2100",
            "--limitation",
            "SYNTHETIC fixture",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let created = PreparedPlan::decode(&output.stdout).unwrap();
    let fixture = PreparedPlan::decode(
        &fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../contracts/tests/fixtures/eject-plan-v3.json"
        ))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(created.digest(), fixture.digest());
    assert_eq!(created.kind().as_str(), "site_eject");
}

#[test]
fn site_eject_without_a_limitation_says_the_generation_was_not_observed() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rustiron"));
    child.args([
        "plan",
        "create",
        "site-eject",
        "--plan-id",
        "plan_eject",
        "--host-id",
        "host_lab",
        "--host-epoch",
        "epoch_1",
        "--profile-digest",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--requester",
        "agent_1",
        "--site-id",
        "blog5",
        "--expected-generation",
        "g1",
        "--expected-digest",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "--observed-at",
        "990",
        "--valid-from",
        "1000",
        "--expires-at",
        "2000",
        "--compensation-until",
        "2100",
    ]);
    let output = child.output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("Rustiron did not observe the host"));
}

#[test]
fn a_stale_or_malformed_eject_is_refused_without_a_plan() {
    let stale = eject(
        "100",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "2100",
    );
    assert_eq!(stale.status.code(), Some(2));
    assert!(stale.stdout.is_empty());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("INVALID_PLAN"));
    let wide = eject(
        "990",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "2500",
    );
    assert_eq!(wide.status.code(), Some(2));
    assert!(wide.stdout.is_empty());
}

#[test]
fn a_stale_or_malformed_create_is_refused_without_a_plan() {
    let stale = create("100", "blog1.example.test");
    assert_eq!(stale.status.code(), Some(2));
    assert!(PreparedPlan::decode(&stale.stdout).is_err());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("INVALID_PLAN"));
    let bad = create("990", "NOT A HOST");
    assert_eq!(bad.status.code(), Some(2));
    assert!(bad.stdout.is_empty());
}

fn activate(sites: &[&str], observed_at: &str) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rustiron"));
    command.args([
        "plan",
        "create",
        "config-activate",
        "--plan-id",
        "plan_ols",
        "--host-id",
        "host_lab",
        "--host-epoch",
        "epoch_1",
        "--profile-digest",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--requester",
        "agent_1",
        "--expected-generation",
        "g1",
        "--expected-digest",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "--observed-at",
        observed_at,
        "--valid-from",
        "1000",
        "--expires-at",
        "2000",
        "--compensation-until",
        "2100",
        "--limitation",
        "SYNTHETIC fixture",
    ]);
    for site in sites {
        command.args(["--site-id", site]);
    }
    command.output().unwrap()
}

#[test]
fn config_activate_matches_the_closed_fixture_and_does_not_reload() {
    let output = activate(&["blog5", "blog6"], "990");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let created = PreparedPlan::decode(&output.stdout).unwrap();
    let fixture = PreparedPlan::decode(
        &fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../contracts/tests/fixtures/ols-plan.json"
        ))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(created.digest(), fixture.digest());
    assert_eq!(created.kind().as_str(), "config_activate");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("signature"));
}

#[test]
fn an_unsorted_or_stale_activation_is_refused_without_a_plan() {
    let unsorted = activate(&["blog6", "blog5"], "990");
    assert_eq!(unsorted.status.code(), Some(2));
    assert!(unsorted.stdout.is_empty());
    assert!(String::from_utf8_lossy(&unsorted.stderr).contains("INVALID_PLAN"));
    let stale = activate(&["blog5", "blog6"], "100");
    assert_eq!(stale.status.code(), Some(2));
    assert!(stale.stdout.is_empty());
    let empty = activate(&[], "990");
    assert_eq!(empty.status.code(), Some(2));
    assert!(empty.stdout.is_empty());
}

#[test]
fn config_activate_without_a_limitation_says_the_generation_was_not_observed() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rustiron"));
    command.args([
        "plan",
        "create",
        "config-activate",
        "--plan-id",
        "plan_ols",
        "--host-id",
        "host_lab",
        "--host-epoch",
        "epoch_1",
        "--profile-digest",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--requester",
        "agent_1",
        "--site-id",
        "blog5",
        "--site-id",
        "blog6",
        "--expected-generation",
        "g1",
        "--expected-digest",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "--observed-at",
        "990",
        "--valid-from",
        "1000",
        "--expires-at",
        "2000",
        "--compensation-until",
        "2100",
    ]);
    let output = command.output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Rustiron did not observe the host"));
}

fn capture(site: &str, expires_at: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rustiron"))
        .args([
            "plan",
            "create",
            "backup-capture",
            "--plan-id",
            "plan_capture",
            "--host-id",
            "host_lab",
            "--host-epoch",
            "epoch_1",
            "--profile-digest",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--requester",
            "agent_1",
            "--site-id",
            site,
            "--valid-from",
            "1000",
            "--expires-at",
            expires_at,
            "--limitation",
            "SYNTHETIC fixture",
        ])
        .output()
        .unwrap()
}

#[test]
fn backup_capture_matches_the_closed_fixture_and_does_not_copy() {
    let output = capture("blog9", "2000");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let created = PreparedPlan::decode(&output.stdout).unwrap();
    let fixture = PreparedPlan::decode(
        &fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../contracts/tests/fixtures/capture-plan.json"
        ))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(created.digest(), fixture.digest());
    assert_eq!(created.kind().as_str(), "backup_capture");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("lab_pc_store"));
    assert!(text.contains("site_files_db_v1"));
    assert!(!text.contains("signature"));
}

#[test]
fn backup_capture_without_a_limitation_says_the_site_was_not_captured() {
    let output = Command::new(env!("CARGO_BIN_EXE_rustiron"))
        .args([
            "plan",
            "create",
            "backup-capture",
            "--plan-id",
            "plan_capture",
            "--host-id",
            "host_lab",
            "--host-epoch",
            "epoch_1",
            "--profile-digest",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--requester",
            "agent_1",
            "--site-id",
            "blog9",
            "--valid-from",
            "1000",
            "--expires-at",
            "2000",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("did not observe the host or capture")
    );
}

#[test]
fn a_wide_or_malformed_capture_is_refused_without_a_plan() {
    let wide = capture("blog9", "5000");
    assert_eq!(wide.status.code(), Some(2));
    assert!(wide.stdout.is_empty());
    assert!(String::from_utf8_lossy(&wide.stderr).contains("INVALID_PLAN"));
    let bad = capture("NOT A SITE", "2000");
    assert_eq!(bad.status.code(), Some(2));
    assert!(bad.stdout.is_empty());
}

const SNAPSHOT: &str = "63ba950462d475de22f0f9f73449dfc311db71a2036352a86f8e38b155590409";

fn probe(snapshot: &str, expires_at: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rustiron"))
        .args([
            "plan",
            "create",
            "restore-probe",
            "--plan-id",
            "plan_probe",
            "--host-id",
            "host_lab",
            "--host-epoch",
            "epoch_1",
            "--profile-digest",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--requester",
            "agent_1",
            "--site-id",
            "blog13",
            "--snapshot-id",
            snapshot,
            "--valid-from",
            "1000",
            "--expires-at",
            expires_at,
            "--limitation",
            "SYNTHETIC fixture",
        ])
        .output()
        .unwrap()
}

#[test]
fn restore_probe_matches_the_closed_fixture_and_does_not_restore() {
    let output = probe(SNAPSHOT, "2000");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let created = PreparedPlan::decode(&output.stdout).unwrap();
    let fixture = PreparedPlan::decode(
        &fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../contracts/tests/fixtures/probe-plan.json"
        ))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(created.digest(), fixture.digest());
    assert_eq!(created.kind().as_str(), "restore_probe");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("local_no_egress_v1"));
    assert!(text.contains(SNAPSHOT));
    assert!(!text.contains("signature"));
}

#[test]
fn restore_probe_without_a_limitation_says_the_source_was_not_touched() {
    let output = Command::new(env!("CARGO_BIN_EXE_rustiron"))
        .args([
            "plan",
            "create",
            "restore-probe",
            "--plan-id",
            "plan_probe",
            "--host-id",
            "host_lab",
            "--host-epoch",
            "epoch_1",
            "--profile-digest",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--requester",
            "agent_1",
            "--site-id",
            "blog13",
            "--snapshot-id",
            SNAPSHOT,
            "--valid-from",
            "1000",
            "--expires-at",
            "2000",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("did not restore it or touch the source")
    );
}

#[test]
fn a_wide_or_malformed_probe_is_refused_without_a_plan() {
    let wide = probe(SNAPSHOT, "5000");
    assert_eq!(wide.status.code(), Some(2));
    assert!(wide.stdout.is_empty());
    assert!(String::from_utf8_lossy(&wide.stderr).contains("INVALID_PLAN"));
    let bad = probe("NOT-A-SNAPSHOT", "2000");
    assert_eq!(bad.status.code(), Some(2));
    assert!(bad.stdout.is_empty());
}
