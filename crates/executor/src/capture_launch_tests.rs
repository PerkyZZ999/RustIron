//! Inspect the actual production launch arguments without starting systemd.
use super::*;

fn site_credential(name: &str, filename: &str) -> String {
    format!(
        "LoadCredential={name}:{}/rs_blog13/{filename}",
        crate::layout::JOB_CREDENTIALS_DIR
    )
}

fn credential_mask() -> String {
    format!(
        "InaccessiblePaths=-{} -/run/credentials",
        crate::layout::JOB_CREDENTIALS_DIR
    )
}

fn args(phase: Phase) -> Vec<String> {
    let site = rustiron_contracts::approval::SiteId::try_from("blog13".to_owned()).unwrap();
    let layout = SiteLayout::derive(&site);
    let destination = Destination {
        repository_base: "s3:http://127.0.0.1:9000/synthetic/sites",
        store_address: "127.0.0.1",
    };
    let path = format!(
        "{BIN}/{}",
        match phase {
            Phase::Dump => "mariadb-dump",
            Phase::Marker => "mariadb",
            Phase::AppDump | Phase::AppMarker | Phase::Manifest => "capture-manifest",
            _ => "restic",
        }
    );
    let subcommand = match phase {
        Phase::Dump | Phase::Marker => "--defaults-file=/srv/sites/rs_blog13/private/db.cnf",
        Phase::AppDump => "app-sqlite-backup",
        Phase::AppMarker => "app-sqlite-marker",
        Phase::Snapshot => "backup",
        Phase::Check => "check",
        Phase::Find => "snapshots",
        Phase::Manifest => "dump",
        Phase::Lock => "lock",
    };
    let snapshot = "a".repeat(64);
    let third = match phase {
        Phase::Manifest => snapshot.as_str(),
        Phase::AppDump | Phase::AppMarker => "rs_blog13",
        _ => "--fixture",
    };
    launch_arguments(
        &layout,
        "s0:c201",
        &destination,
        phase,
        "rustiron-capture-rs_blog13-test-fixed",
        &[&path, subcommand, third],
    )
    .unwrap()
}

fn marker_launch(command: &[String]) -> Result<Vec<String>, ExecutorError> {
    let site = rustiron_contracts::approval::SiteId::try_from("blog13".to_owned()).unwrap();
    let destination = Destination {
        repository_base: "s3:http://127.0.0.1:9000/synthetic/sites",
        store_address: "127.0.0.1",
    };
    let borrowed: Vec<&str> = command.iter().map(String::as_str).collect();
    launch_arguments(
        &SiteLayout::derive(&site),
        "s0:c201",
        &destination,
        Phase::Marker,
        "rustiron-capture-rs_blog13-test-fixed",
        &borrowed,
    )
}

#[test]
fn app_dump_and_marker_run_capture_manifest_without_network_and_reject_foreign_account() {
    let site = rustiron_contracts::approval::SiteId::try_from("blog13".to_owned()).unwrap();
    let layout = SiteLayout::derive(&site);
    let worker = format!("{BIN}/capture-manifest");
    for (phase, action) in [
        (Phase::AppDump, "app-sqlite-backup"),
        (Phase::AppMarker, "app-sqlite-marker"),
    ] {
        let a = launch_arguments_for(
            &layout,
            "s0:c201",
            None,
            phase,
            "rustiron-capture-rs_blog13-app-fixed",
            &[&worker, action, "rs_blog13"],
        )
        .unwrap();
        let p = properties(&a);
        assert!(p.contains(&"PrivateNetwork=yes"));
        assert!(p.contains(&"IPAddressDeny=any"));
        assert!(!p.iter().any(|s| s.starts_with("LoadCredential=")));
        assert_eq!(
            launch_arguments_for(
                &layout,
                "s0:c201",
                None,
                phase,
                "rustiron-capture-rs_blog13-app-fixed",
                &[&worker, action, "rs_other"],
            ),
            Err(ExecutorError::InvalidRequest)
        );
    }
}

#[test]
fn the_marker_runs_like_the_dump_without_credentials_or_network() {
    let args = marker_launch(&marker_command("/srv/sites/rs_blog13", "rs_blog13")).unwrap();
    let p = properties(&args);
    assert!(!p.iter().any(|s| s.starts_with("LoadCredential=")));
    assert!(p.contains(&credential_mask().as_str()));
    assert!(p.contains(&"PrivateNetwork=yes"));
    assert!(p.contains(&"SELinuxContext=system_u:system_r:rustiron_capture_t:s0:c201"));
}

#[test]
fn only_the_fixed_marker_query_for_the_site_may_run() {
    let good = marker_command("/srv/sites/rs_blog13", "rs_blog13");
    let n = good.len();
    let mut other_sql = good.clone();
    other_sql[n - 2] = "DROP DATABASE rs_blog13".to_owned();
    let mut other_db = good.clone();
    other_db[n - 1] = "rs_blog5".to_owned();
    let mut extra = good.clone();
    extra.push("--execute=SELECT 1".to_owned());
    for bad in [other_sql, other_db, extra] {
        assert_eq!(
            marker_launch(&bad).err(),
            Some(ExecutorError::InvalidRequest)
        );
    }
}

fn properties(args: &[String]) -> Vec<&str> {
    let end = args.iter().position(|s| s == "--").unwrap();
    args[..end]
        .windows(2)
        .filter_map(|pair| (pair[0] == "--property").then_some(pair[1].as_str()))
        .collect()
}

#[test]
fn dump_receives_no_repository_credentials() {
    let args = args(Phase::Dump);
    let p = properties(&args);
    assert!(!p.iter().any(|s| s.starts_with("LoadCredential=")));
    assert_eq!(
        p.iter()
            .filter(|s| s.starts_with("Environment="))
            .copied()
            .collect::<Vec<_>>(),
        ["Environment=TMPDIR=/srv/sites/rs_blog13/tmp"]
    );
}
#[test]
fn dump_hides_credential_paths() {
    let args = args(Phase::Dump);
    let p = properties(&args);
    assert!(p.contains(&credential_mask().as_str()));
}
#[test]
fn dump_unsets_inherited_repository_variables() {
    let args = args(Phase::Dump);
    let p = properties(&args);
    let unset = p
        .iter()
        .find_map(|s| s.strip_prefix("UnsetEnvironment="))
        .unwrap();
    let names: Vec<_> = unset.split_whitespace().collect();
    assert!(names.contains(&"AWS_SHARED_CREDENTIALS_FILE"));
    assert!(names.contains(&"AWS_ACCESS_KEY_ID"));
    assert!(names.contains(&"AWS_SECRET_ACCESS_KEY"));
    assert!(names.contains(&"RESTIC_PASSWORD_FILE"));
    assert!(names.contains(&"RESTIC_PASSWORD"));
    assert!(names.contains(&"RESTIC_REPOSITORY"));
}
#[test]
fn dump_has_no_network_allowance() {
    let args = args(Phase::Dump);
    let p = properties(&args);
    assert!(p.contains(&"PrivateNetwork=yes"));
    assert!(p.contains(&"IPAddressDeny=any"));
    assert!(!p.iter().any(|s| s.starts_with("IPAddressAllow=")));
}
macro_rules! repository_phase {
    ($test:ident, $phase:ident) => {
        #[test] fn $test() {
            let args = args(Phase::$phase); let p = properties(&args);
            assert_eq!(p.iter().filter(|s| s.starts_with("LoadCredential=")).count(), 2);
            let expected_key = if Phase::$phase == Phase::Snapshot { "aws" } else { "fetch-aws" };
            assert!(p.contains(&site_credential("aws", expected_key).as_str()));
            assert!(p.contains(&site_credential("password", "repo.password").as_str()));
            let env = p.iter().find(|s| s.starts_with("Environment=")).unwrap();
            assert!(env.contains("AWS_SHARED_CREDENTIALS_FILE=/run/credentials/rustiron-capture-rs_blog13-test-fixed.service/aws"));
            assert!(env.contains("RESTIC_PASSWORD_FILE=/run/credentials/rustiron-capture-rs_blog13-test-fixed.service/password"));
            assert!(env.contains("RESTIC_REPOSITORY=s3:http://127.0.0.1:9000/synthetic/sites/rs_blog13"));
            assert!(p.contains(&"IPAddressDeny=any")); assert!(p.contains(&"IPAddressAllow=127.0.0.1/32"));
            assert!(!p.contains(&"PrivateNetwork=yes"));
            assert!(!p.iter().any(|s| s.starts_with("InaccessiblePaths=")));
            let unset = p.iter().find_map(|s| s.strip_prefix("UnsetEnvironment=")).expect("repository phase must clear ambient identities");
            let names: Vec<_> = unset.split_whitespace().collect();
            assert!(names.contains(&"AWS_ACCESS_KEY_ID"));
            assert!(names.contains(&"AWS_SECRET_ACCESS_KEY"));
            assert!(names.contains(&"AWS_SESSION_TOKEN"));
            assert!(names.contains(&"RESTIC_PASSWORD"));
            assert!(!names.contains(&"AWS_SHARED_CREDENTIALS_FILE"));
            assert!(!names.contains(&"RESTIC_PASSWORD_FILE"));
            assert!(!names.contains(&"RESTIC_REPOSITORY"));
        }
    }
}
repository_phase!(snapshot_has_scoped_repository_access, Snapshot);
repository_phase!(check_has_scoped_repository_access, Check);
repository_phase!(find_has_scoped_repository_access, Find);
repository_phase!(manifest_has_scoped_read_only_repository_access, Manifest);

macro_rules! budgets {
    ($test:ident, $phase:ident) => {
        #[test]
        fn $test() {
            let args = args(Phase::$phase);
            let p = properties(&args);
            assert!(p.contains(&"User=rs_blog13"));
            assert!(p.contains(&"Group=rs_blog13"));
            assert!(p.contains(&"SELinuxContext=system_u:system_r:rustiron_capture_t:s0:c201"));
            assert!(p.contains(&"NoNewPrivileges=yes"));
            assert!(p.contains(&"CapabilityBoundingSet="));
            assert!(p.contains(&"ProtectSystem=strict"));
            assert!(p.contains(&"ReadWritePaths=/srv/sites/rs_blog13/tmp"));
            assert!(p.contains(&"PrivateTmp=yes"));
            assert!(p.contains(&"PrivateDevices=yes"));
            assert!(p.contains(&"ProtectHome=yes"));
            // W207: every capture unit ends before the helper command deadline.
            assert!(p.contains(&"RuntimeMaxSec=100"));
            assert!(p.contains(&"MemoryMax=512M"));
            assert!(p.contains(&"MemorySwapMax=0"));
            assert!(p.contains(&"TasksMax=32"));
            // W280: background work yields CPU to the site pools.
            assert!(p.contains(&"CPUWeight=20"));
        }
    };
}
budgets!(dump_preserves_identity_and_budgets, Dump);
budgets!(snapshot_preserves_identity_and_budgets, Snapshot);
budgets!(check_preserves_identity_and_budgets, Check);
budgets!(find_preserves_identity_and_budgets, Find);
budgets!(manifest_preserves_identity_and_budgets, Manifest);

#[test]
fn manifest_launches_only_the_fixed_worker_for_one_snapshot() {
    let snapshot = "a".repeat(64);
    let worker = format!("{BIN}/capture-manifest");
    let args = args(Phase::Manifest);
    let end = args.iter().position(|s| s == "--").unwrap();
    assert_eq!(
        &args[end + 1..],
        [worker.as_str(), "dump", snapshot.as_str()]
    );
    for command in [
        vec![format!("{BIN}/restic"), "dump".to_owned(), snapshot.clone()],
        vec![worker.clone(), "backup".to_owned(), snapshot.clone()],
        vec![worker.clone(), "dump".to_owned()],
        vec![worker.clone(), "dump".to_owned(), "A".repeat(64)],
        vec![
            worker.clone(),
            "dump".to_owned(),
            snapshot.clone(),
            "--repo=s3:http://x/other".to_owned(),
        ],
    ] {
        let borrowed: Vec<&str> = command.iter().map(String::as_str).collect();
        assert_eq!(
            mismatched(Phase::Manifest, &borrowed),
            Err(ExecutorError::InvalidRequest),
            "{command:?}"
        );
    }
}

#[test]
fn manifest_uses_only_its_own_sites_repository_and_read_identity() {
    let p_args = args(Phase::Manifest);
    let p = properties(&p_args);
    assert!(p.iter().all(|s| !s.contains("rs_other")));
    assert!(!p.iter().any(|s| s.ends_with("/rs_blog13/aws")));
    assert!(p.contains(&site_credential("aws", "fetch-aws").as_str()));
}
#[test]
fn executable_and_arguments_remain_separate_from_properties() {
    let args = args(Phase::Snapshot);
    let end = args.iter().position(|s| s == "--").unwrap();
    assert_eq!(
        &args[end + 1..],
        [
            format!("{BIN}/restic"),
            "backup".to_owned(),
            "--fixture".to_owned()
        ]
    );
    assert_eq!(
        &args[..5],
        [
            "--unit",
            "rustiron-capture-rs_blog13-test-fixed",
            "--wait",
            "--quiet",
            "--collect"
        ]
    );
}

fn mismatched(phase: Phase, command: &[&str]) -> Result<Vec<String>, ExecutorError> {
    let site = rustiron_contracts::approval::SiteId::try_from("blog13".to_owned()).unwrap();
    launch_arguments(
        &SiteLayout::derive(&site),
        "s0:c201",
        &Destination {
            repository_base: "synthetic",
            store_address: "127.0.0.1",
        },
        phase,
        "fixture-unit",
        command,
    )
}
#[test]
fn dump_cannot_launch_repository_program() {
    assert_eq!(
        mismatched(Phase::Dump, &[&format!("{BIN}/restic"), "backup"]),
        Err(ExecutorError::InvalidRequest)
    );
}
#[test]
fn snapshot_cannot_launch_database_dump() {
    assert_eq!(
        mismatched(Phase::Snapshot, &[&format!("{BIN}/mariadb-dump"), "backup"]),
        Err(ExecutorError::InvalidRequest)
    );
}
#[test]
fn check_cannot_launch_backup_action() {
    assert_eq!(
        mismatched(Phase::Check, &[&format!("{BIN}/restic"), "backup"]),
        Err(ExecutorError::InvalidRequest)
    );
}
#[test]
fn find_cannot_launch_backup_action() {
    assert_eq!(
        mismatched(Phase::Find, &[&format!("{BIN}/restic"), "backup"]),
        Err(ExecutorError::InvalidRequest)
    );
}
#[test]
fn empty_command_is_refused() {
    assert_eq!(
        mismatched(Phase::Dump, &[]),
        Err(ExecutorError::InvalidRequest)
    );
}
#[test]
fn missing_action_is_refused() {
    assert_eq!(
        mismatched(Phase::Check, &[&format!("{BIN}/restic")]),
        Err(ExecutorError::InvalidRequest)
    );
}
#[test]
fn dump_cannot_use_another_sites_database_config() {
    assert_eq!(
        mismatched(
            Phase::Dump,
            &[
                &format!("{BIN}/mariadb-dump"),
                "--defaults-file=/srv/sites/rs_other/private/db.cnf"
            ]
        ),
        Err(ExecutorError::InvalidRequest)
    );
}

fn real_phase_arguments(phase: Phase, command: &[&str]) -> Vec<String> {
    let layout = SiteLayout::derive(
        &rustiron_contracts::approval::SiteId::try_from("blog13".to_owned()).unwrap(),
    );
    launch_arguments(
        &layout,
        "s0:c201",
        &Destination {
            repository_base: "synthetic",
            store_address: "127.0.0.1",
        },
        phase,
        "fixture-unit",
        command,
    )
    .unwrap()
}
#[test]
fn capture_sequence_builds_the_real_dump_snapshot_and_readonly_check() {
    let mut phases = Vec::new();
    let snapshot = "a".repeat(64);
    let result = capture_steps(
        "/srv/sites/rs_blog13",
        "rs_blog13",
        "op_fixture",
        |phase, command| {
            let args = real_phase_arguments(phase, command);
            let p = properties(&args);
            phases.push(phase);
            match phase {
                Phase::Marker => {
                    assert!(!p.iter().any(|s| s.starts_with("LoadCredential=")));
                    Ok("wp_posts\t42\n".to_owned())
                }
                Phase::Dump => {
                    assert!(!p.iter().any(|s| s.starts_with("LoadCredential=")));
                    assert!(command.contains(&"--single-transaction"));
                    Ok(String::new())
                }
                Phase::Snapshot => {
                    assert!(p.contains(&site_credential("aws", "aws").as_str()));
                    assert!(command.contains(&"--tag=rustiron-op-op_fixture"));
                    Ok(format!(
                        "{{\"message_type\":\"summary\",\"snapshot_id\":\"{snapshot}\"}}"
                    ))
                }
                Phase::Check => {
                    assert!(p.contains(&site_credential("aws", "fetch-aws").as_str()));
                    assert!(command.contains(&"--no-lock"));
                    Ok(String::new())
                }
                Phase::Manifest => {
                    assert!(p.contains(&site_credential("aws", "fetch-aws").as_str()));
                    assert_eq!(
                        command,
                        [
                            format!("{BIN}/capture-manifest").as_str(),
                            "dump",
                            snapshot.as_str()
                        ]
                    );
                    Ok(String::new())
                }
                Phase::Lock => {
                    assert!(p.contains(&site_credential("aws", "aws").as_str()));
                    assert_eq!(
                        command,
                        [format!("{BIN}/capture-manifest").as_str(), "lock"]
                    );
                    Ok(format!("{}\n", crate::manifest::lock::pass_line(30)))
                }
                Phase::Find | Phase::AppDump | Phase::AppMarker => {
                    panic!("not part of a WordPress capture")
                }
            }
        },
        || Ok(()),
    );
    let CaptureOutcome::Succeeded(snapshot) = result else {
        panic!("capture must succeed");
    };
    assert_eq!(
        snapshot.consistency,
        rustiron_journal::CaptureConsistency::Matched
    );
    assert_eq!(
        phases,
        [
            Phase::Lock,
            Phase::Marker,
            Phase::Dump,
            Phase::Snapshot,
            Phase::Marker,
            Phase::Check,
            Phase::Lock,
            Phase::Manifest
        ]
    );
}
#[test]
fn reconcile_sequence_builds_readonly_lookup_and_check() {
    let mut phases = Vec::new();
    let id = "a".repeat(64);
    let result = find_steps(
        "op_fixture",
        false,
        |phase, command| {
            let args = real_phase_arguments(phase, command);
            let p = properties(&args);
            assert!(p.contains(&site_credential("aws", "fetch-aws").as_str()));
            assert!(command.contains(&"--no-lock"));
            phases.push(phase);
            match phase {
                Phase::Find => Ok(format!("[{{\"id\":\"{id}\"}}]")),
                Phase::Check => Ok(String::new()),
                _ => panic!("reconciliation must not upload or dump"),
            }
        },
        || Ok(()),
    );
    assert_eq!(result, Ok(Some(id)));
    assert_eq!(phases, [Phase::Find, Phase::Check]);
}

struct Credentials(std::path::PathBuf);
impl Credentials {
    fn new() -> Self {
        use std::{
            os::unix::fs::DirBuilderExt,
            sync::atomic::{AtomicUsize, Ordering},
        };
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "rustiron-capture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        for name in ["aws", "fetch-aws", "repo.password"] {
            crate::test_support::private_file(&path.join(name), b"SYNTHETIC_ONLY");
        }
        Self(path)
    }
    fn enrolled(&self) -> bool {
        credentials_in(&self.0, rustix::process::geteuid().as_raw())
    }
}
impl Drop for Credentials {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
#[test]
fn all_private_synthetic_credentials_are_enrolled() {
    assert!(Credentials::new().enrolled());
}
macro_rules! missing_credential {
    ($name:ident, $file:literal) => {
        #[test]
        fn $name() {
            let fixture = Credentials::new();
            assert!(fixture.enrolled());
            std::fs::remove_file(fixture.0.join($file)).unwrap();
            assert!(!fixture.enrolled());
        }
    };
}
missing_credential!(missing_readonly_key_is_refused, "fetch-aws");
missing_credential!(missing_upload_key_is_refused, "aws");
missing_credential!(missing_repository_password_is_refused, "repo.password");
#[test]
fn symlink_readonly_key_is_refused() {
    let fixture = Credentials::new();
    assert!(fixture.enrolled());
    std::fs::remove_file(fixture.0.join("fetch-aws")).unwrap();
    std::os::unix::fs::symlink("aws", fixture.0.join("fetch-aws")).unwrap();
    assert!(!fixture.enrolled());
}
#[test]
fn exposed_readonly_key_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Credentials::new();
    assert!(fixture.enrolled());
    std::fs::set_permissions(
        fixture.0.join("fetch-aws"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(!fixture.enrolled());
}
#[test]
fn oversized_readonly_key_is_refused() {
    let fixture = Credentials::new();
    assert!(fixture.enrolled());
    std::fs::write(fixture.0.join("fetch-aws"), vec![b'x'; 4097]).unwrap();
    assert!(!fixture.enrolled());
}
#[test]
fn hardlinked_readonly_key_is_refused() {
    let fixture = Credentials::new();
    assert!(fixture.enrolled());
    std::fs::hard_link(fixture.0.join("fetch-aws"), fixture.0.join("extra-link")).unwrap();
    assert!(!fixture.enrolled());
}
#[test]
fn directory_as_readonly_key_is_refused() {
    let fixture = Credentials::new();
    assert!(fixture.enrolled());
    std::fs::remove_file(fixture.0.join("fetch-aws")).unwrap();
    std::fs::create_dir(fixture.0.join("fetch-aws")).unwrap();
    assert!(!fixture.enrolled());
}
#[test]
fn unreadable_readonly_key_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Credentials::new();
    assert!(fixture.enrolled());
    std::fs::set_permissions(
        fixture.0.join("fetch-aws"),
        std::fs::Permissions::from_mode(0o000),
    )
    .unwrap();
    assert!(!fixture.enrolled());
}

#[test]
fn capture_units_end_before_the_helper_deadline() {
    // W207: a snapshot unit retrying an unreachable store outlived the
    // helper's 120 s deadline (600 s ceiling), leaving the capture uncertain
    // with its unit still running.
    for phase in [
        Phase::Dump,
        Phase::Snapshot,
        Phase::Check,
        Phase::Find,
        Phase::Manifest,
    ] {
        let args = args(phase);
        let secs: u64 = properties(&args)
            .iter()
            .find_map(|p| p.strip_prefix("RuntimeMaxSec="))
            .unwrap()
            .parse()
            .unwrap();
        // W207 p1: restic held SIGTERM for 21 s, so the stop must be bounded.
        let stop: u64 = properties(&args)
            .iter()
            .find_map(|p| p.strip_prefix("TimeoutStopSec="))
            .unwrap()
            .parse()
            .unwrap();
        assert!(secs + stop + 10 <= crate::provision::COMMAND_TIMEOUT.as_secs());
    }
}

#[test]
fn the_lock_check_runs_the_worker_with_the_capture_identity_only() {
    let site = rustiron_contracts::approval::SiteId::try_from("blog13".to_owned()).unwrap();
    let layout = SiteLayout::derive(&site);
    let destination = Destination {
        repository_base: "s3:http://127.0.0.1:9000/synthetic/sites",
        store_address: "127.0.0.1",
    };
    let worker = format!("{BIN}/capture-manifest");
    let launch = |command: &[&str]| {
        launch_arguments(
            &layout,
            "s0:c201",
            &destination,
            Phase::Lock,
            "rustiron-capture-rs_blog13-lock-fixed",
            command,
        )
    };
    let args = launch(&[&worker, "lock"]).unwrap();
    let p = properties(&args);
    assert!(p.contains(&site_credential("aws", "aws").as_str()));
    assert!(!p.iter().any(|s| s.contains("fetch-aws")));
    assert!(p.contains(&"IPAddressAllow=127.0.0.1/32"));
    assert_eq!(&args[args.len() - 2..], [worker.as_str(), "lock"]);
    for bad in [
        vec![worker.as_str(), "lock", "x"],
        vec![worker.as_str(), "dump"],
        vec!["/usr/bin/curl", "lock"],
    ] {
        assert_eq!(launch(&bad), Err(ExecutorError::InvalidRequest), "{bad:?}");
    }
}
