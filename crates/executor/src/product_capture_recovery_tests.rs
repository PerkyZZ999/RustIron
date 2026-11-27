//! W366: capture recovery over a real fixture journal and a given tag
//! lookup. No store, systemd or helper.
use std::{
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

use rustiron_contracts::{
    Id, Timestamp,
    approval::{Hostname, Sha256Digest, SiteId},
};
use rustiron_journal::{
    Admitted, CaptureIntent, CaptureMethod, CaptureState, FixtureJournal, ProvisionIntent,
    ProvisionStep,
};

use super::{Recovery, record_recovery};
use crate::ExecutorError;

const SNAPSHOT: &str = "a50c8b74e3c0f1d2a50c8b74e3c0f1d2a50c8b74e3c0f1d2a50c8b74e3c0f1d2";

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "rustiron-recovery-{}-{}",
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

impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

fn id(text: &str) -> Id {
    Id::try_from(text.to_owned()).unwrap()
}

fn time(seconds: u64) -> Timestamp {
    Timestamp::try_from(seconds).unwrap()
}

fn digest(c: char) -> Sha256Digest {
    Sha256Digest::try_from(c.to_string().repeat(64)).unwrap()
}

fn intent(n: u32) -> CaptureIntent {
    CaptureIntent {
        operation_id: id(&format!("op_w366_{n}")),
        idempotency_key: id(&format!("key_w366_{n}")),
        grant_id: id(&format!("grant_w366_{n}")),
        nonce: id(&format!("nonce_w366_{n}")),
        plan_digest: digest('c'),
        grant_digest: digest('d'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: SiteId::try_from("blog9".to_owned()).unwrap(),
        expires_at: time(10_000),
    }
}

/// A journal with a provisioned site and capture 1 left `running`.
fn running(directory: &Directory) -> (FixtureJournal, Id) {
    let mut journal =
        FixtureJournal::initialize(&directory.0, id("host_fixture"), id("epoch_fixture")).unwrap();
    let provision = ProvisionIntent {
        operation_id: id("prov_w366"),
        idempotency_key: id("prov_key_w366"),
        grant_id: id("prov_grant_w366"),
        nonce: id("prov_nonce_w366"),
        plan_digest: digest('a'),
        grant_digest: digest('b'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: SiteId::try_from("blog9".to_owned()).unwrap(),
        hostname: Hostname::try_from("blog9.example.test".to_owned()).unwrap(),
        expires_at: time(10_000),
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
    let first = intent(1);
    journal
        .record_capture(
            &first,
            time(1000),
            CaptureMethod::SiteFilesDbV1,
            Some(30),
            &digest('e'),
        )
        .unwrap();
    (journal, first.operation_id)
}

fn admits_next(journal: &mut FixtureJournal) -> bool {
    matches!(
        journal.record_capture(
            &intent(2),
            time(1100),
            CaptureMethod::SiteFilesDbV1,
            Some(30),
            &digest('e'),
        ),
        Ok(Admitted::New(_))
    )
}

/// Lost reply after a complete write: the one tagged snapshot is kept
/// unclaimed and the capture is `failed`, never `succeeded`. The site then
/// admits a new capture.
#[test]
fn a_lost_reply_after_a_complete_write_settles_failed_with_the_snapshot_unclaimed() {
    let directory = Directory::new();
    let (mut journal, operation) = running(&directory);
    assert!(!admits_next(&mut journal), "a running capture blocks");
    let settled = record_recovery(
        &mut journal,
        &operation,
        Recovery::SettleUnclaimed,
        Ok(Some(SNAPSHOT.to_owned())),
        time(1050),
    )
    .unwrap();
    assert_eq!(settled.state, CaptureState::Failed);
    assert_eq!(settled.snapshot_id, None);
    assert_eq!(settled.unclaimed_snapshot_id.as_deref(), Some(SNAPSHOT));
    assert_eq!(settled.manifest, None);
    assert_eq!(settled.consistency, None);
    assert_eq!(journal.capture_status(&operation).unwrap(), Some(settled));
    assert!(
        admits_next(&mut journal),
        "the settled site admits a capture"
    );
}

/// Lost reply after a partial write: a tagged partial snapshot settles the
/// same way (never `succeeded`). No tag at all is `failed` with nothing
/// kept, in either mode.
#[test]
fn a_partial_write_never_records_succeeded() {
    for (mode, found, unclaimed) in [
        (
            Recovery::SettleUnclaimed,
            Some(SNAPSHOT.to_owned()),
            Some(SNAPSHOT),
        ),
        (Recovery::SettleUnclaimed, None, None),
        (Recovery::Reconcile, None, None),
    ] {
        let directory = Directory::new();
        let (mut journal, operation) = running(&directory);
        let settled =
            record_recovery(&mut journal, &operation, mode, Ok(found), time(1050)).unwrap();
        assert_eq!(settled.state, CaptureState::Failed, "{mode:?}");
        assert_eq!(settled.snapshot_id, None);
        assert_eq!(settled.unclaimed_snapshot_id.as_deref(), unclaimed);
        assert!(admits_next(&mut journal));
    }
}

/// W321 reconcile keeps its rule: a tagged snapshot is unexplained and the
/// capture stays `running`.
#[test]
fn plain_reconcile_leaves_a_tagged_snapshot_running() {
    let directory = Directory::new();
    let (mut journal, operation) = running(&directory);
    let refused = record_recovery(
        &mut journal,
        &operation,
        Recovery::Reconcile,
        Ok(Some(SNAPSHOT.to_owned())),
        time(1050),
    );
    assert_eq!(refused.err(), Some(ExecutorError::PreconditionChanged));
    let recorded = journal.capture_status(&operation).unwrap().unwrap();
    assert_eq!(recorded.state, CaptureState::Running);
    assert_eq!(recorded.unclaimed_snapshot_id, None);
    assert!(!admits_next(&mut journal));
}

/// A failed re-verification now (store checks, repository identity, two
/// snapshots with one tag, a refused worker) records nothing in either
/// mode: the capture stays `running`.
#[test]
fn a_failed_lookup_now_keeps_the_capture_running() {
    for mode in [Recovery::Reconcile, Recovery::SettleUnclaimed] {
        for error in [
            ExecutorError::Unavailable,
            ExecutorError::PreconditionChanged,
            ExecutorError::StepFailed,
        ] {
            let directory = Directory::new();
            let (mut journal, operation) = running(&directory);
            let refused = record_recovery(&mut journal, &operation, mode, Err(error), time(1050));
            assert_eq!(refused.err(), Some(error), "{mode:?}");
            let recorded = journal.capture_status(&operation).unwrap().unwrap();
            assert_eq!(recorded.state, CaptureState::Running);
            assert_eq!(recorded.finished_at, None);
            assert!(!admits_next(&mut journal));
        }
    }
}

/// A lookup that names something other than one snapshot ID is never
/// recorded, and a finished capture is never settled again.
#[test]
fn a_malformed_id_or_a_finished_capture_is_refused() {
    let directory = Directory::new();
    let (mut journal, operation) = running(&directory);
    for bad in ["", "ABCD", &SNAPSHOT.to_uppercase()] {
        assert!(
            record_recovery(
                &mut journal,
                &operation,
                Recovery::SettleUnclaimed,
                Ok(Some(bad.to_owned())),
                time(1050),
            )
            .is_err()
        );
    }
    assert_eq!(
        journal.capture_status(&operation).unwrap().unwrap().state,
        CaptureState::Running
    );
    let settled = record_recovery(
        &mut journal,
        &operation,
        Recovery::SettleUnclaimed,
        Ok(Some(SNAPSHOT.to_owned())),
        time(1050),
    )
    .unwrap();
    let replay = record_recovery(
        &mut journal,
        &operation,
        Recovery::SettleUnclaimed,
        Ok(Some(SNAPSHOT.to_owned())),
        time(1060),
    );
    assert_eq!(replay.err(), Some(ExecutorError::ReplayDenied));
    assert_eq!(journal.capture_status(&operation).unwrap(), Some(settled));
}
