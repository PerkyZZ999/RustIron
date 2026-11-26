//! Execute the real unprivileged inventory binary on benign metadata fixtures.
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};
/// A site below a restore target: `.0` is the site directory, `.1` the
/// restore target (W378: the worker takes both).
struct Site(PathBuf, PathBuf);
const SITE: &str = "srv/sites/rs_fixture";
impl Site {
    fn new() -> Self {
        assert_ne!(rustix::process::geteuid().as_raw(), 0);
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let restore = std::env::temp_dir().join(format!(
            "ri-worker-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&restore).unwrap();
        let path = restore.join(SITE);
        fs::create_dir_all(path.join("html")).unwrap();
        fs::create_dir(path.join("tmp")).unwrap();
        fs::write(path.join("html/benign-file"), b"BENIGN_FIXTURE").unwrap();
        fs::write(
            path.join("tmp/rustiron-capture.sql"),
            b"BENIGN_METADATA_FIXTURE",
        )
        .unwrap();
        Self(path, restore)
    }
    fn run(&self) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_rustiron-restore-inventory"))
            .env_clear()
            .arg(&self.1)
            .arg(SITE)
            .output()
            .unwrap()
    }
}
impl Drop for Site {
    fn drop(&mut self) {
        let sub = self.0.join("html/unreadable");
        if sub.exists() {
            fs::set_permissions(sub, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::remove_dir_all(&self.1).unwrap();
    }
}
#[test]
fn real_worker_reports_complete_bounded_metadata_without_paths() {
    let site = Site::new();
    let output = site.run();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(output.stdout.len() <= 4096);
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains("benign-file"));
    assert!(!text.contains(site.0.to_str().unwrap()));
    let report: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(report["status"], "complete");
    assert_eq!(report["schema_version"], 3);
    assert_eq!(report["files"], 1);
    assert_eq!(report["dump"], true);
    assert_eq!(report["extra_paths"], 0);
}
#[test]
fn real_worker_counts_extra_snapshot_paths_without_names() {
    // W378 (W328 c4b): an extra top-level snapshot path.
    let site = Site::new();
    fs::create_dir_all(site.1.join("mnt/w378-extra")).unwrap();
    fs::write(site.1.join("mnt/w378-extra/outside"), b"BENIGN_FIXTURE").unwrap();
    let output = site.run();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains("w378-extra") && !text.contains("mnt"));
    let report: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(report["status"], "complete");
    assert_eq!(report["extra_paths"], 1);
}
#[test]
fn real_worker_does_not_report_partial_count_as_complete() {
    let site = Site::new();
    fs::create_dir(site.0.join("html/unreadable")).unwrap();
    fs::set_permissions(
        site.0.join("html/unreadable"),
        fs::Permissions::from_mode(0o000),
    )
    .unwrap();
    let output = site.run();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "error");
    assert_eq!(report["files"], serde_json::Value::Null);
    assert_eq!(report["dump"], serde_json::Value::Null);
}
#[test]
fn real_worker_missing_argument_refuses_without_echo() {
    // W378: the single site-root argument of version 2 is refused too.
    let site = Site::new();
    for arguments in [vec![], vec![site.0.clone()]] {
        let output = Command::new(env!("CARGO_BIN_EXE_rustiron-restore-inventory"))
            .env_clear()
            .args(&arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap().trim(),
            "{\"error\":\"INVENTORY_ARGUMENTS\"}"
        );
    }
}
