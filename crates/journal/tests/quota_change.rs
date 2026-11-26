//! W534 (journal v35, D-088): a signed change of a site's quota. Its intent
//! rechecks the owned site and its open changes; the newest done change is
//! the site's recorded limits. Real SQLite; no host effects.
use rustiron_contracts::approval::{Hostname, SiteId};
use rustiron_journal::{
    CaptureConsistency, CaptureIntent, CaptureManifest, CaptureMethod, DeleteIntent,
    FixtureJournal, JournalError, ProvisionIntent, ProvisionStep, QuotaChangeIntent,
    QuotaChangeResult, StepState,
};
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
#[expect(
    dead_code,
    reason = "shared helpers; this suite needs no fixture operation"
)]
mod support;
use support::*;

const SNAPSHOT: &str = "89f5ad054604acf1033adc33725d0a96c5b609225525bda3bff495d4cc61f3ad";
const DAY: u64 = 24 * 3600;

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct State(PathBuf);
impl State {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ri-quota-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn init(&self) -> FixtureJournal {
        FixtureJournal::initialize(&self.0, id("host_fixture"), id("epoch_fixture")).unwrap()
    }
    fn open(&self) -> Result<FixtureJournal, JournalError> {
        FixtureJournal::open(&self.0, id("host_fixture"), id("epoch_fixture"))
    }
    fn migrate(&self) -> Result<FixtureJournal, JournalError> {
        FixtureJournal::migrate(&self.0, id("host_fixture"), id("epoch_fixture"))
    }
    fn sql(&self, sql: &str) {
        rusqlite::Connection::open(self.0.join("fixture-journal.sqlite"))
            .unwrap()
            .execute_batch(sql)
            .unwrap();
    }
}
impl Drop for State {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn site_id(name: &str) -> SiteId {
    SiteId::try_from(name.to_owned()).unwrap()
}

fn hostname(name: &str) -> Hostname {
    Hostname::try_from(format!("{name}.example.test")).unwrap()
}

/// A served site whose every provision step is done.
fn served(ledger: &mut FixtureJournal, name: &str) {
    let intent = ProvisionIntent {
        operation_id: id(&format!("prov_{name}")),
        idempotency_key: id(&format!("prov_key_{name}")),
        grant_id: id(&format!("prov_grant_{name}")),
        nonce: id(&format!("prov_nonce_{name}")),
        plan_digest: digest('a'),
        grant_digest: digest('b'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: site_id(name),
        hostname: hostname(name),
        expires_at: time(10 * DAY),
    };
    ledger.record_provision(&intent, time(900)).unwrap();
    for step in ProvisionStep::ALL {
        ledger.begin_step(&intent.operation_id, step, "r").unwrap();
        ledger
            .finish_step(&intent.operation_id, step, true)
            .unwrap();
    }
}

fn capture_intent(name: &str, operation: &str) -> CaptureIntent {
    CaptureIntent {
        operation_id: id(operation),
        idempotency_key: id(&format!("{operation}_key")),
        grant_id: id(&format!("{operation}_grant")),
        nonce: id(&format!("{operation}_nonce")),
        plan_digest: digest('c'),
        grant_digest: digest('d'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: site_id(name),
        expires_at: time(10 * DAY),
    }
}

/// A capture of the site started at `at`; succeeded one second later
/// unless `running`.
fn capture(ledger: &mut FixtureJournal, name: &str, operation: &str, at: u64, running: bool) {
    let intent = capture_intent(name, operation);
    ledger
        .record_capture(
            &intent,
            time(at),
            CaptureMethod::SiteFilesDbV1,
            None,
            &digest('e'),
        )
        .unwrap();
    if running {
        return;
    }
    ledger
        .finish_capture_labelled(
            &intent.operation_id,
            Some(SNAPSHOT),
            time(at + 1),
            None,
            Some(&CaptureManifest {
                sha256: "f".repeat(64),
                entries: 2,
                regular_bytes: 16,
                truncated: false,
            }),
            Some(&CaptureConsistency::Matched),
        )
        .unwrap();
}

fn change(n: u32, name: &str, kib: u64, inodes: u64) -> QuotaChangeIntent {
    QuotaChangeIntent {
        operation_id: id(&format!("quota_{n}")),
        idempotency_key: id(&format!("quota_key_{n}")),
        grant_id: id(&format!("quota_grant_{n}")),
        nonce: id(&format!("quota_nonce_{n}")),
        plan_digest: digest('5'),
        grant_digest: digest('6'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: site_id(name),
        block_hard_kib: kib,
        inode_hard: inodes,
        expires_at: time(10 * DAY),
    }
}

#[test]
fn the_newest_done_change_is_the_sites_recorded_limits() {
    let state = State::new();
    let mut ledger = state.init();
    served(&mut ledger, "blog1");
    served(&mut ledger, "blog2");
    assert_eq!(ledger.latest_quota_limits(&site_id("blog1")).unwrap(), None);
    let first = change(1, "blog1", 524_288, 40_000);
    let QuotaChangeResult::New(open) = ledger.record_quota_change(&first, time(1000)).unwrap()
    else {
        panic!("a new change");
    };
    assert_eq!(open.state, StepState::Intent);
    // One open change per site; an open change is not yet the record.
    assert_eq!(
        ledger
            .record_quota_change(&change(2, "blog1", 600_000, 40_000), time(1000))
            .err(),
        Some(JournalError::Consumed)
    );
    assert_eq!(ledger.latest_quota_limits(&site_id("blog1")).unwrap(), None);
    let done = ledger
        .finish_quota_change(&first.operation_id, true)
        .unwrap();
    assert_eq!(done.state, StepState::Done);
    assert_eq!(
        ledger.latest_quota_limits(&site_id("blog1")).unwrap(),
        Some((524_288, 40_000))
    );
    assert_eq!(
        ledger.record_quota_change(&first, time(1100)).unwrap(),
        QuotaChangeResult::Existing(done.clone())
    );
    let mut other = first.clone();
    other.inode_hard = 50_000;
    assert_eq!(
        ledger.record_quota_change(&other, time(1100)).err(),
        Some(JournalError::Conflict)
    );
    // A failed change does not replace the record.
    let failed = change(3, "blog1", 700_000, 40_000);
    ledger.record_quota_change(&failed, time(1200)).unwrap();
    ledger
        .finish_quota_change(&failed.operation_id, false)
        .unwrap();
    assert_eq!(
        ledger.latest_quota_limits(&site_id("blog1")).unwrap(),
        Some((524_288, 40_000))
    );
    assert_eq!(ledger.latest_quota_limits(&site_id("blog2")).unwrap(), None);
    drop(ledger);
    let ledger = state.open().unwrap();
    assert_eq!(
        ledger.quota_change_status(&first.operation_id).unwrap(),
        Some(done)
    );
    assert_eq!(ledger.admission_count().unwrap(), 4);
    let observed =
        FixtureJournal::observe(&state.0, &id("host_fixture"), &id("epoch_fixture")).unwrap();
    let site = |name: &str| {
        observed
            .provisions
            .iter()
            .find(|provision| provision.site_id == name)
            .unwrap()
            .changed_quota
    };
    assert_eq!(site("blog1"), Some((524_288, 40_000)));
    assert_eq!(site("blog2"), None);
}

#[test]
fn only_an_owned_site_takes_a_change() {
    let state = State::new();
    let mut ledger = state.init();
    served(&mut ledger, "blog1");
    served(&mut ledger, "blog2");
    capture(&mut ledger, "blog2", "cap_2", 1000, false);
    // A deleted site is not owned.
    ledger
        .record_deletion(
            &DeleteIntent {
                operation_id: id("delete_1"),
                idempotency_key: id("delete_key_1"),
                grant_id: id("delete_grant_1"),
                nonce: id("delete_nonce_1"),
                plan_digest: digest('7'),
                grant_digest: digest('8'),
                host_id: id("host_fixture"),
                host_epoch: id("epoch_fixture"),
                site_id: site_id("blog2"),
                hostname: hostname("blog2"),
                capture_operation_id: Some(id("cap_2")),
                expires_at: time(10 * DAY),
            },
            time(1100),
        )
        .unwrap();
    for intent in [
        change(1, "blog2", 524_288, 40_000),
        change(2, "nosuch", 524_288, 40_000),
    ] {
        assert_eq!(
            ledger.record_quota_change(&intent, time(1200)).err(),
            Some(JournalError::Consumed),
            "{intent:?}"
        );
    }
    drop(ledger);
    state.sql("UPDATE provisions SET state='quarantined' WHERE site_id='blog1'");
    let mut ledger = state.open().unwrap();
    assert_eq!(
        ledger
            .record_quota_change(&change(3, "blog1", 524_288, 40_000), time(1200))
            .err(),
        Some(JournalError::Consumed)
    );
}

#[test]
fn a_v34_journal_migrates_and_a_change_of_an_unknown_site_is_refused() {
    let state = State::new();
    let mut ledger = state.init();
    served(&mut ledger, "blog1");
    drop(ledger);
    state.sql(&format!("DROP TABLE credential_rotations; DROP TABLE app_lifecycles; DROP TABLE app_release_steps; DROP TABLE app_releases; DROP TABLE apps; DROP TABLE static_ejections; DROP TABLE proxy_routes; DROP TABLE dns_change_sets; DROP TABLE dns_changes; DROP TABLE dns_imports; DROP TABLE restore_steps; DROP TABLE restore_attempts; DROP TABLE site_restores; DROP TABLE clone_scrub_grants; DROP TABLE quota_changes; {TO_V40_DELETIONS} PRAGMA user_version=34;"));
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let mut ledger = state.migrate().unwrap();
    ledger
        .record_quota_change(&change(1, "blog1", 524_288, 40_000), time(1000))
        .unwrap();
    drop(ledger);
    state.open().unwrap();
    state.sql("PRAGMA foreign_keys=OFF; UPDATE quota_changes SET site_id='blog9'");
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
}

/// The W508-F1 lesson: a journal that holds a signed quota change must open
/// again, and the admission must be observed.
#[test]
fn a_signed_change_keeps_the_journal_openable_and_observed() {
    use rustiron_contracts::{CanonicalObject, approval::Sha256Digest};
    use rustiron_journal::SignedAdmission;
    use sha2::{Digest, Sha256};
    const PLAN: &str = r#"{"plan_id":"plan_quota","schema_version":1,"site_id":"blog1"}"#;
    const GRANT: &str = r#"{"grant_id":"grant_quota","issuer":"lab_agent","nonce":"nonce_quota","signer_policy_epoch":"policy_3"}"#;
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let state = State::new();
    let mut ledger = state.init();
    served(&mut ledger, "blog1");
    let mut intent = change(1, "blog1", 524_288, 40_000);
    intent.plan_digest = Sha256Digest::try_from(hex(&CanonicalObject::decode(PLAN.as_bytes())
        .unwrap()
        .plan_domain_digest()))
    .unwrap();
    intent.grant_digest = Sha256Digest::try_from(hex(&Sha256::digest(GRANT.as_bytes()))).unwrap();
    ledger.stage_signed(SignedAdmission {
        plan: PLAN.as_bytes().to_vec(),
        grant: GRANT.as_bytes().to_vec(),
        issuer: id("lab_agent"),
        signer_policy_epoch: id("policy_3"),
    });
    ledger.record_quota_change(&intent, time(1100)).unwrap();
    drop(ledger);
    state.open().unwrap();
    let observed =
        FixtureJournal::observe(&state.0, &id("host_fixture"), &id("epoch_fixture")).unwrap();
    assert!(
        observed
            .admissions
            .iter()
            .any(|admission| admission.operation_id == intent.operation_id.as_str())
    );
}
