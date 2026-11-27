//! No SystemCleanup is instantiated: all administrative effects remain out of process.
use super::*;
use rustiron_journal::Admitted;
use std::io::ErrorKind;

#[derive(Default)]
struct Host {
    failure: Option<&'static str>,
    stop_failed: bool,
    units: bool,
    post_units: bool,
    removals: u32,
    polls: u32,
    settles: u32,
    databases: Option<&'static str>,
    present: Option<&'static str>,
    removal_failures: u32,
    passwd_text: Option<&'static str>,
    large_rules: bool,
}

impl CleanupHost for Host {
    fn stop(&mut self) -> Result<(), ExecutorError> {
        if self.stop_failed {
            Err(ExecutorError::Unavailable)
        } else {
            Ok(())
        }
    }
    fn settle(&mut self) {
        self.settles += 1;
    }
    fn units_absent(&mut self) -> Result<bool, ExecutorError> {
        self.polls += 1;
        if self.failure == Some("units") || (self.failure == Some("post_units") && self.polls > 1) {
            Err(ExecutorError::Unavailable)
        } else {
            Ok(!(self.units || (self.post_units && self.polls > 1)))
        }
    }
    fn remove(&mut self) -> u32 {
        self.removals += 1;
        self.removal_failures
    }
    fn passwd(&mut self) -> Result<String, ExecutorError> {
        if let Some(text) = self.passwd_text {
            return Ok(text.to_owned());
        }
        if self.failure == Some("passwd") {
            Err(ExecutorError::Unavailable)
        } else if self.present == Some("account") {
            Ok(
                "root:x:0:0:root:/root:/bin/sh\nrp_abcdef:x:3000:3000::/:/sbin/nologin\n"
                    .to_owned(),
            )
        } else {
            Ok("root:x:0:0:root:/root:/bin/sh\n".to_owned())
        }
    }
    fn rules(&mut self) -> Result<String, ExecutorError> {
        if self.large_rules {
            return Ok(" ".repeat(1 << 20));
        }
        if self.failure == Some("rules") {
            Err(ExecutorError::Unavailable)
        } else {
            Ok(if self.present == Some("rules") {
                "/srv/restore-probes/rp_abcdef(/.*)?"
            } else {
                ""
            }
            .to_owned())
        }
    }
    fn exists(&mut self, path: &str) -> std::io::Result<bool> {
        let kind = if path.starts_with("/var/spool") {
            "spool"
        } else {
            "root"
        };
        if self.failure == Some(kind) {
            Err(ErrorKind::PermissionDenied.into())
        } else if self.present == Some(kind) {
            Ok(true)
        } else {
            Err(ErrorKind::NotFound.into())
        }
    }
    fn databases(&mut self) -> Result<String, ExecutorError> {
        if self.failure == Some("databases") {
            Err(ExecutorError::Unavailable)
        } else {
            Ok(self.databases.unwrap_or("0\n0\n").to_owned())
        }
    }
}

fn run(host: &mut Host) -> CleanupReport {
    cleanup_with(host, "rp_abcdef")
}
fn unknown(mut host: Host, check: &str) {
    let report = run(&mut host);
    assert!(!report.is_clean());
    assert_eq!(
        report.receipt()["leftover_resources"],
        serde_json::Value::Null
    );
    assert_eq!(report.receipt()["status"], "unknown");
    assert!(report.unverified.contains(&check));
}

#[test]
fn matching_absent_resources_are_clean() {
    let mut host = Host::default();
    let report = run(&mut host);
    assert!(report.is_clean());
    assert_eq!(report.receipt()["leftover_resources"], 0);
    assert_eq!(host.removals, 1);
    assert_eq!(host.polls, 2);
}
#[test]
fn failed_stop_blocks_deletion_while_units_remain() {
    let mut host = Host {
        stop_failed: true,
        units: true,
        ..Host::default()
    };
    assert!(!run(&mut host).is_clean());
    assert_eq!(host.removals, 0);
    assert_eq!(host.settles, STOP_POLLS);
}
#[test]
fn failed_stop_of_an_already_unloaded_unit_still_cleans() {
    // W179 h2: the stop raced `--collect` on a failed fetch unit.
    let mut host = Host {
        stop_failed: true,
        ..Host::default()
    };
    assert!(run(&mut host).is_clean());
    assert_eq!(host.removals, 1);
    assert_eq!(host.settles, 1);
}
#[test]
fn running_units_block_deletion() {
    let mut host = Host {
        units: true,
        ..Host::default()
    };
    assert!(!run(&mut host).is_clean());
    assert_eq!(host.removals, 0);
}
#[test]
fn unknown_units_block_deletion() {
    let mut host = Host {
        failure: Some("units"),
        ..Host::default()
    };
    assert!(!run(&mut host).is_clean());
    assert_eq!(host.removals, 0);
}
#[test]
fn failed_passwd_read_is_unknown() {
    unknown(
        Host {
            failure: Some("passwd"),
            ..Host::default()
        },
        "account",
    );
}
#[test]
fn failed_rule_read_is_unknown() {
    unknown(
        Host {
            failure: Some("rules"),
            ..Host::default()
        },
        "policy",
    );
}
#[test]
fn inaccessible_tree_is_unknown() {
    unknown(
        Host {
            failure: Some("root"),
            ..Host::default()
        },
        "root",
    );
}
#[test]
fn inaccessible_spool_is_unknown() {
    unknown(
        Host {
            failure: Some("spool"),
            ..Host::default()
        },
        "spool",
    );
}
#[test]
fn failed_database_read_is_unknown() {
    unknown(
        Host {
            failure: Some("databases"),
            ..Host::default()
        },
        "database",
    );
}
#[test]
fn empty_database_output_is_unknown() {
    unknown(
        Host {
            databases: Some(""),
            ..Host::default()
        },
        "database",
    );
}
#[test]
fn missing_database_count_is_unknown() {
    unknown(
        Host {
            databases: Some("0"),
            ..Host::default()
        },
        "database",
    );
}
#[test]
fn excess_database_counts_are_unknown() {
    unknown(
        Host {
            databases: Some("0 0 0"),
            ..Host::default()
        },
        "database",
    );
}
#[test]
fn malformed_database_counts_are_unknown() {
    unknown(
        Host {
            databases: Some("bad 0"),
            ..Host::default()
        },
        "database",
    );
}
#[test]
fn overflowing_database_counts_are_unknown() {
    unknown(
        Host {
            databases: Some("18446744073709551615 1"),
            ..Host::default()
        },
        "database",
    );
}
#[test]
fn post_removal_unit_failure_is_unknown() {
    unknown(
        Host {
            failure: Some("post_units"),
            ..Host::default()
        },
        "units",
    );
}
#[test]
fn post_removal_units_are_unverified() {
    unknown(
        Host {
            post_units: true,
            ..Host::default()
        },
        "units",
    );
}
macro_rules! remaining {
    ($name:ident, $resource:literal) => {
        #[test]
        fn $name() {
            let report = run(&mut Host {
                present: Some($resource),
                ..Host::default()
            });
            assert!(!report.is_clean());
            assert_eq!(report.receipt()["leftover_resources"], 1);
            assert_eq!(report.receipt()["status"], "incomplete");
        }
    };
}
remaining!(remaining_account_blocks_clean, "account");
remaining!(remaining_rules_block_clean, "rules");
remaining!(remaining_tree_blocks_clean, "root");
remaining!(remaining_spool_blocks_clean, "spool");
#[test]
fn remaining_database_records_block_clean() {
    let report = run(&mut Host {
        databases: Some("2 1"),
        ..Host::default()
    });
    assert!(!report.is_clean());
    assert_eq!(report.receipt()["leftover_resources"], 3);
}
#[test]
fn failed_idempotent_removal_is_visible_with_verified_absence() {
    let report = run(&mut Host {
        removal_failures: 4,
        ..Host::default()
    });
    assert!(report.is_clean());
    assert_eq!(report.receipt()["removal_failures"], 4);
}

#[test]
fn truncated_rule_listing_is_unknown() {
    unknown(
        Host {
            large_rules: true,
            ..Host::default()
        },
        "policy",
    );
}
#[test]
fn empty_passwd_file_is_unknown() {
    unknown(
        Host {
            passwd_text: Some(""),
            ..Host::default()
        },
        "account",
    );
}
#[test]
fn malformed_passwd_file_is_unknown() {
    unknown(
        Host {
            passwd_text: Some(
                "root:x:0:0:root:/root:/bin/sh\nrp_abcdef:x:bad:0::/:/sbin/nologin\n",
            ),
            ..Host::default()
        },
        "account",
    );
}
#[test]
fn negative_database_count_is_unknown() {
    unknown(
        Host {
            databases: Some("-1 0"),
            ..Host::default()
        },
        "database",
    );
}
#[test]
fn signed_database_count_is_unknown() {
    unknown(
        Host {
            databases: Some("+0 0"),
            ..Host::default()
        },
        "database",
    );
}
#[test]
fn aggregate_resource_count_overflow_is_unknown() {
    unknown(
        Host {
            databases: Some("18446744073709551615 0"),
            present: Some("account"),
            ..Host::default()
        },
        "resource_count",
    );
}
#[test]
fn unknown_cleanup_overrides_successful_health() {
    let report = run(&mut Host {
        failure: Some("passwd"),
        ..Host::default()
    });
    assert_eq!(
        report.probe_state(true),
        rustiron_journal::ProbeState::CleanupIncomplete
    );
    assert_eq!(
        report.probe_state(false),
        rustiron_journal::ProbeState::CleanupIncomplete
    );
}
#[test]
fn complete_cleanup_preserves_health_outcome() {
    let report = run(&mut Host::default());
    assert_eq!(
        report.probe_state(true),
        rustiron_journal::ProbeState::Passed
    );
    assert_eq!(
        report.probe_state(false),
        rustiron_journal::ProbeState::Failed
    );
}

struct Directory(std::path::PathBuf);
impl Directory {
    fn new() -> Self {
        use std::{
            os::unix::fs::DirBuilderExt,
            sync::atomic::{AtomicUsize, Ordering},
        };
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "rustiron-cleanup-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
}
/// Reopen after a drop. Another test thread's forked child can hold a copy
/// of the writer-lock fd until it execs, so an immediate non-blocking re-lock
/// may briefly be refused (`AccessDenied`); the product refusal is correct,
/// the test waits it out (bounded).
fn reopen(
    dir: &std::path::Path,
    host: rustiron_contracts::Id,
    epoch: rustiron_contracts::Id,
) -> rustiron_journal::FixtureJournal {
    for _ in 0..100 {
        match rustiron_journal::FixtureJournal::open(dir, host.clone(), epoch.clone()) {
            Err(rustiron_journal::JournalError::AccessDenied) => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            other => return other.unwrap(),
        }
    }
    panic!("journal lock still held after 1 s");
}
impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
#[test]
fn real_metadata_distinguishes_absent_file_and_dangling_link() {
    let dir = Directory::new();
    let path = dir.0.join("entry");
    let name = path.to_str().unwrap();
    assert_eq!(path_count(path_exists(name)), Ok(0));
    std::fs::write(&path, b"fixture").unwrap();
    assert_eq!(path_count(path_exists(name)), Ok(1));
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink("missing-target", &path).unwrap();
    assert_eq!(path_count(path_exists(name)), Ok(1));
}
#[test]
fn real_non_directory_ancestor_is_unknown() {
    let dir = Directory::new();
    let path = dir.0.join("entry");
    std::fs::write(&path, b"fixture").unwrap();
    assert_eq!(
        path_count(path_exists(path.join("child").to_str().unwrap())),
        Err(ExecutorError::Unavailable)
    );
}

#[test]
fn unknown_cleanup_persists_blocks_and_only_verified_cleanup_releases() {
    use rustiron_contracts::{
        Id, Timestamp,
        approval::{Hostname, Sha256Digest, SiteId, SnapshotId},
    };
    use rustiron_journal::{
        FixtureJournal, JournalError, ProbeIntent, ProbeState, ProvisionIntent, ProvisionStep,
    };
    let id = |s: &str| Id::try_from(s.to_owned()).unwrap();
    let time = |n| Timestamp::try_from(n).unwrap();
    let dir = Directory::new();
    let mut journal =
        FixtureJournal::initialize(&dir.0, id("host_fixture"), id("epoch_fixture")).unwrap();
    let provision = ProvisionIntent {
        operation_id: id("provision"),
        idempotency_key: id("provision_key"),
        grant_id: id("provision_grant"),
        nonce: id("provision_nonce"),
        plan_digest: Sha256Digest::try_from("a".repeat(64)).unwrap(),
        grant_digest: Sha256Digest::try_from("b".repeat(64)).unwrap(),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: SiteId::try_from("blog13".to_owned()).unwrap(),
        hostname: Hostname::try_from("blog13.example.test".to_owned()).unwrap(),
        expires_at: time(10000),
    };
    journal.record_provision(&provision, time(900)).unwrap();
    for step in ProvisionStep::ALL {
        journal
            .begin_step(&provision.operation_id, step, "fixture")
            .unwrap();
        journal
            .finish_step(&provision.operation_id, step, true)
            .unwrap();
    }
    let first = ProbeIntent {
        operation_id: id("probe_first"),
        idempotency_key: id("probe_key_first"),
        grant_id: id("probe_grant_first"),
        nonce: id("probe_nonce_first"),
        plan_digest: Sha256Digest::try_from("c".repeat(64)).unwrap(),
        grant_digest: Sha256Digest::try_from("d".repeat(64)).unwrap(),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: provision.site_id,
        snapshot_id: SnapshotId::try_from("a".repeat(64)).unwrap(),
        probe_account: "rp_abcdef".to_owned(),
        expires_at: time(10000),
    };
    journal
        .record_probe(&first, time(1000), &first.plan_digest)
        .unwrap();
    let running = journal.probe_status(&first.operation_id).unwrap().unwrap();
    let unknown = run(&mut Host {
        failure: Some("passwd"),
        ..Host::default()
    });
    let incomplete =
        crate::durable::finish_probe_cleanup(&mut journal, &running, &unknown, time(1001)).unwrap();
    assert_eq!(incomplete.state, ProbeState::CleanupIncomplete);
    let receipt: serde_json::Value =
        serde_json::from_str(incomplete.receipt.as_deref().unwrap()).unwrap();
    assert_eq!(
        receipt["cleanup"]["leftover_resources"],
        serde_json::Value::Null
    );
    assert_eq!(receipt["cleanup"]["status"], "unknown");
    let exported = crate::receipt::recovery_receipt(&incomplete, receipt).unwrap();
    assert!(crate::redaction::secret_shapes(&exported.to_string()).is_empty());
    assert_eq!(exported["body"]["cleanup"], unknown.receipt());
    drop(journal);
    let mut journal = reopen(&dir.0, id("host_fixture"), id("epoch_fixture"));
    let stored = journal.probe_status(&first.operation_id).unwrap().unwrap();
    assert_eq!(stored.state, ProbeState::CleanupIncomplete);
    let second = ProbeIntent {
        operation_id: id("probe_second"),
        idempotency_key: id("probe_key_second"),
        grant_id: id("probe_grant_second"),
        nonce: id("probe_nonce_second"),
        probe_account: "rp_abcdee".to_owned(),
        ..first
    };
    assert_eq!(
        journal
            .record_probe(&second, time(1002), &second.plan_digest)
            .err(),
        Some(JournalError::Busy)
    );
    let again =
        crate::durable::finish_probe_cleanup(&mut journal, &stored, &unknown, time(1003)).unwrap();
    assert_eq!(again.state, ProbeState::CleanupIncomplete);
    assert_eq!(again.receipt, stored.receipt);
    let clean = run(&mut Host::default());
    let finished =
        crate::durable::finish_probe_cleanup(&mut journal, &again, &clean, time(1004)).unwrap();
    assert_eq!(finished.state, ProbeState::Failed);
    assert!(matches!(
        journal
            .record_probe(&second, time(1005), &second.plan_digest)
            .unwrap(),
        Admitted::New(_)
    ));
}
