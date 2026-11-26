//! Uninstall moves a closed management set and leaves site data.

use std::{
    fs,
    os::unix::fs::{DirBuilderExt, symlink},
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "ri-uninstall-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        Self(directory)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn rustiron() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rustiron"))
}

fn write_observation(path: &Path, ejected: bool) {
    let flag = if ejected { "true" } else { "false" };
    fs::write(
        path,
        format!(
            r#"{{"schema":"rustiron-lab-observation/1","sites":[{{"site_id":"blog5","ejected":{flag}}},{{"site_id":"blog9","ejected":true}}]}}"#
        ),
    )
    .unwrap();
}

#[test]
fn a_managed_site_blocks_removal_and_site_data_stays() {
    let temp = Temp::new();
    let observation = temp.0.join("observe.json");
    write_observation(&observation, false);
    let prefix = temp.0.join("rootfs");
    fs::create_dir_all(prefix.join("srv/sites/blog5")).unwrap();
    fs::write(prefix.join("srv/sites/blog5/index.html"), b"keep").unwrap();
    fs::create_dir_all(prefix.join("etc/rustiron-ols")).unwrap();
    fs::write(prefix.join("etc/rustiron-ols/marker"), b"management").unwrap();
    let planned = rustiron()
        .args(["uninstall", "plan", "--observation"])
        .arg(&observation)
        .args(["--output", "json"])
        .output()
        .unwrap();
    assert_eq!(planned.status.code(), Some(4));
    let body: serde_json::Value = serde_json::from_slice(&planned.stdout).unwrap();
    assert_eq!(body["actionable"], false);
    assert_eq!(body["deletes_site_data"], false);
    assert_eq!(body["still_managed"][0], "blog5");
    assert!(
        body["move_paths"]
            .as_array()
            .unwrap()
            .iter()
            .all(|path| !path.as_str().unwrap().contains("srv/sites"))
    );
    let applied = rustiron()
        .args(["uninstall", "apply", "--prefix"])
        .arg(&prefix)
        .args(["--observation"])
        .arg(&observation)
        .args(["--output", "json"])
        .output()
        .unwrap();
    assert_eq!(applied.status.code(), Some(4));
    assert_eq!(
        fs::read(prefix.join("srv/sites/blog5/index.html")).unwrap(),
        b"keep"
    );
    assert!(prefix.join("etc/rustiron-ols/marker").is_file());
    assert!(!prefix.join("root/rustiron-uninstalled").exists());
}

#[test]
fn ejected_sites_move_management_only_and_a_symlink_is_refused() {
    let temp = Temp::new();
    let observation = temp.0.join("observe.json");
    write_observation(&observation, true);
    let prefix = temp.0.join("rootfs");
    fs::create_dir_all(prefix.join("srv/sites/blog5")).unwrap();
    fs::write(prefix.join("srv/sites/blog5/index.html"), b"keep").unwrap();
    fs::create_dir_all(prefix.join("etc/rustiron-ejected")).unwrap();
    fs::create_dir_all(prefix.join("etc/rustiron-ols")).unwrap();
    fs::write(prefix.join("etc/rustiron-ols/marker"), b"management").unwrap();
    fs::create_dir_all(prefix.join("var/lib/mysql")).unwrap();
    fs::write(prefix.join("var/lib/mysql/ibdata"), b"db").unwrap();
    let applied = rustiron()
        .args(["uninstall", "apply", "--prefix"])
        .arg(&prefix)
        .args(["--observation"])
        .arg(&observation)
        .args(["--output", "json"])
        .output()
        .unwrap();
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stdout)
    );
    let body: serde_json::Value = serde_json::from_slice(&applied.stdout).unwrap();
    assert_eq!(body["actionable"], true);
    assert_eq!(body["deletes_site_data"], false);
    assert!(!prefix.join("etc/rustiron-ols").exists());
    assert_eq!(
        fs::read(prefix.join("root/rustiron-uninstalled/etc_rustiron-ols/marker")).unwrap(),
        b"management"
    );
    assert_eq!(
        fs::read(prefix.join("srv/sites/blog5/index.html")).unwrap(),
        b"keep"
    );
    assert!(prefix.join("etc/rustiron-ejected").is_dir());
    assert_eq!(
        fs::read(prefix.join("var/lib/mysql/ibdata")).unwrap(),
        b"db"
    );

    let linked = temp.0.join("linked");
    fs::create_dir_all(linked.join("srv/sites/blog5")).unwrap();
    fs::write(linked.join("srv/sites/blog5/index.html"), b"keep").unwrap();
    fs::create_dir_all(linked.join("etc")).unwrap();
    symlink(
        linked.join("srv/sites/blog5"),
        linked.join("etc/rustiron-ols"),
    )
    .unwrap();
    let refused = rustiron()
        .args(["uninstall", "apply", "--prefix"])
        .arg(&linked)
        .args(["--observation"])
        .arg(&observation)
        .args(["--output", "json"])
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(2));
    assert_eq!(
        fs::read(linked.join("srv/sites/blog5/index.html")).unwrap(),
        b"keep"
    );
    assert!(
        linked
            .join("etc/rustiron-ols")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink()
    );
}
