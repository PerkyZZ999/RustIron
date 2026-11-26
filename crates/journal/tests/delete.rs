//! W521 (journal v33, D-085): a signed deletion of a live site. Its intent
//! rechecks the site and its capture and sets the provision to `deleted` in
//! one transaction, so no later check treats the site as served. Real
//! SQLite; no host effects.
use rustiron_contracts::approval::{Hostname, SiteId};
use rustiron_journal::{
    CaptureConsistency, CaptureIntent, CaptureManifest, CaptureMethod, DeleteIntent, DeleteResult,
    FixtureJournal, JournalError, ProvisionIntent, ProvisionState, ProvisionStep, StepState,
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
/// `update_components` as versions 32 and 33 created it.
const V32_UPDATE_COMPONENTS: &str = "CREATE TABLE update_components (operation_id TEXT NOT NULL REFERENCES updates(operation_id), position INTEGER NOT NULL CHECK(position BETWEEN 0 AND 7), kind TEXT NOT NULL CHECK(kind IN ('plugin','theme')), slug TEXT NOT NULL CHECK(length(slug) BETWEEN 1 AND 64 AND slug NOT GLOB '*[^a-z0-9_-]*' AND slug NOT GLOB '[-_]*'), from_version TEXT NOT NULL CHECK(length(from_version) BETWEEN 1 AND 32 AND from_version NOT GLOB '*[^0-9A-Za-z.-]*' AND from_version GLOB '[0-9]*'), to_version TEXT NOT NULL CHECK(length(to_version) BETWEEN 1 AND 32 AND to_version NOT GLOB '*[^0-9A-Za-z.-]*' AND to_version GLOB '[0-9]*' AND to_version<>from_version), PRIMARY KEY(operation_id, position), UNIQUE(operation_id, kind, slug)) STRICT";
/// `provisions` as versions 17 to 32 created it.
const V32_PROVISIONS: &str = "CREATE TABLE provisions (operation_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL, grant_digest TEXT NOT NULL, host_id TEXT NOT NULL, host_epoch TEXT NOT NULL, site_id TEXT NOT NULL UNIQUE, hostname TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('running','succeeded','quarantined','adopted'))) STRICT";

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct State(PathBuf);
impl State {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ri-delete-{}-{}",
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

fn deletion(n: u32, name: &str, capture: &str) -> DeleteIntent {
    DeleteIntent {
        operation_id: id(&format!("delete_{n}")),
        idempotency_key: id(&format!("delete_key_{n}")),
        grant_id: id(&format!("delete_grant_{n}")),
        nonce: id(&format!("delete_nonce_{n}")),
        plan_digest: digest('7'),
        grant_digest: digest('8'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: site_id(name),
        hostname: hostname(name),
        capture_operation_id: Some(id(capture)),
        expires_at: time(10 * DAY),
    }
}

fn provision_state(ledger: &FixtureJournal, name: &str) -> ProvisionState {
    ledger
        .provision_for_site(&site_id(name))
        .unwrap()
        .unwrap()
        .state
}

#[test]
fn a_deletion_marks_the_site_deleted_in_its_intent_and_replays() {
    let state = State::new();
    let mut ledger = state.init();
    served(&mut ledger, "blog1");
    served(&mut ledger, "blog2");
    capture(&mut ledger, "blog1", "cap_1", 1000, false);
    let intent = deletion(1, "blog1", "cap_1");
    let DeleteResult::New(recorded) = ledger.record_deletion(&intent, time(1100)).unwrap() else {
        panic!("a new deletion");
    };
    assert_eq!(recorded.state, StepState::Intent);
    assert_eq!(recorded.provision_operation_id.as_str(), "prov_blog1");
    assert_eq!(provision_state(&ledger, "blog1"), ProvisionState::Deleted);
    assert_eq!(
        ledger.succeeded_sites().unwrap(),
        vec![site_id("blog2")],
        "a deleted site is never served"
    );
    // No served-site verb accepts the deleted site.
    assert!(
        ledger
            .record_capture(
                &capture_intent("blog1", "cap_2"),
                time(1200),
                CaptureMethod::SiteFilesDbV1,
                None,
                &digest('e'),
            )
            .is_err()
    );
    let done = ledger.finish_deletion(&intent.operation_id, true).unwrap();
    assert_eq!(done.state, StepState::Done);
    assert_eq!(
        ledger.finish_deletion(&intent.operation_id, true).err(),
        Some(JournalError::Conflict)
    );
    assert_eq!(
        ledger.record_deletion(&intent, time(1300)).unwrap(),
        DeleteResult::Existing(done.clone())
    );
    let mut other = intent.clone();
    other.nonce = id("delete_nonce_other");
    assert_eq!(
        ledger.record_deletion(&other, time(1300)).err(),
        Some(JournalError::Conflict)
    );
    // A done deletion is final: no second deletion of the site.
    assert_eq!(
        ledger
            .record_deletion(&deletion(2, "blog1", "cap_1"), time(1300))
            .err(),
        Some(JournalError::Consumed)
    );
    drop(ledger);
    let ledger = state.open().unwrap();
    assert_eq!(
        ledger.deletion_status(&intent.operation_id).unwrap(),
        Some(done)
    );
    assert_eq!(
        ledger.admission_count().unwrap(),
        4,
        "two provisions, one capture, and one deletion"
    );
}

#[test]
fn the_site_and_its_capture_are_rechecked_before_intent() {
    let state = State::new();
    let mut ledger = state.init();
    served(&mut ledger, "blog1");
    served(&mut ledger, "blog2");
    capture(&mut ledger, "blog1", "cap_1", 1000, false);
    capture(&mut ledger, "blog2", "cap_2", 1000, false);
    let refused = |ledger: &mut FixtureJournal, intent: DeleteIntent, at: u64| {
        assert_eq!(
            ledger.record_deletion(&intent, time(at)).err(),
            Some(JournalError::Consumed),
            "{intent:?}"
        );
    };
    // The capture is older than 24 hours.
    refused(&mut ledger, deletion(1, "blog1", "cap_1"), 1001 + DAY + 1);
    // The capture is another site's, or does not exist.
    refused(&mut ledger, deletion(2, "blog1", "cap_2"), 1100);
    refused(&mut ledger, deletion(3, "blog1", "cap_none"), 1100);
    // The hostname is not the site's.
    let mut wrong = deletion(4, "blog1", "cap_1");
    wrong.hostname = hostname("blog2");
    refused(&mut ledger, wrong, 1100);
    // A newer succeeded capture exists.
    capture(&mut ledger, "blog1", "cap_3", 1050, false);
    refused(&mut ledger, deletion(5, "blog1", "cap_1"), 1100);
    // A capture of the site is running.
    capture(&mut ledger, "blog1", "cap_4", 1060, true);
    refused(&mut ledger, deletion(6, "blog1", "cap_3"), 1100);
    // Nothing was recorded, and the site is still served.
    assert_eq!(provision_state(&ledger, "blog1"), ProvisionState::Succeeded);
    assert_eq!(ledger.admission_count().unwrap(), 6);
}

#[test]
fn a_failed_deletion_is_retried_with_its_capture_only() {
    let state = State::new();
    let mut ledger = state.init();
    served(&mut ledger, "blog1");
    capture(&mut ledger, "blog1", "cap_1", 1000, false);
    let first = deletion(1, "blog1", "cap_1");
    ledger.record_deletion(&first, time(1100)).unwrap();
    // One open deletion per site.
    assert_eq!(
        ledger
            .record_deletion(&deletion(2, "blog1", "cap_1"), time(1100))
            .err(),
        Some(JournalError::Consumed)
    );
    let failed = ledger.finish_deletion(&first.operation_id, false).unwrap();
    assert_eq!(failed.state, StepState::Failed);
    assert_eq!(provision_state(&ledger, "blog1"), ProvisionState::Deleted);
    // The retry names the failed deletion's capture, even after 24 hours.
    let later = 1001 + 3 * DAY;
    assert_eq!(
        ledger
            .record_deletion(&deletion(3, "blog1", "cap_other"), time(later))
            .err(),
        Some(JournalError::Consumed)
    );
    let DeleteResult::New(retry) = ledger
        .record_deletion(&deletion(4, "blog1", "cap_1"), time(later))
        .unwrap()
    else {
        panic!("a retry");
    };
    assert_eq!(retry.state, StepState::Intent);
    drop(ledger);
    state.open().unwrap();
}

#[test]
fn a_quarantined_site_is_retired_not_deleted() {
    let state = State::new();
    let mut ledger = state.init();
    served(&mut ledger, "blog1");
    capture(&mut ledger, "blog1", "cap_1", 1000, false);
    drop(ledger);
    state.sql("UPDATE provisions SET state='quarantined' WHERE site_id='blog1'");
    let mut ledger = state.open().unwrap();
    assert_eq!(
        ledger
            .record_deletion(&deletion(1, "blog1", "cap_1"), time(1100))
            .err(),
        Some(JournalError::Consumed)
    );
}

#[test]
fn a_v32_journal_migrates_and_inconsistent_rows_are_refused() {
    let state = State::new();
    let mut ledger = state.init();
    served(&mut ledger, "blog1");
    capture(&mut ledger, "blog1", "cap_1", 1000, false);
    drop(ledger);
    state.sql(&format!(
        "PRAGMA foreign_keys=OFF; DROP TABLE credential_rotations; DROP TABLE app_lifecycles; DROP TABLE app_release_steps; DROP TABLE app_releases; DROP TABLE apps; DROP TABLE static_ejections; DROP TABLE proxy_routes; DROP TABLE dns_change_sets; DROP TABLE dns_changes; DROP TABLE dns_imports; DROP TABLE restore_steps; DROP TABLE restore_attempts; DROP TABLE site_restores; DROP TABLE clone_scrub_grants; DROP TABLE quota_changes; DROP TABLE deletions; \
         CREATE TEMP TABLE p AS SELECT * FROM provisions; DROP TABLE provisions; {V32_PROVISIONS}; \
         INSERT INTO provisions SELECT * FROM temp.p; DROP TABLE temp.p; \
         CREATE UNIQUE INDEX one_running_provision ON provisions((1)) WHERE state='running'; \
         CREATE TEMP TABLE c AS SELECT * FROM update_components; DROP TABLE update_components; \
         {V32_UPDATE_COMPONENTS}; INSERT INTO update_components SELECT * FROM temp.c; DROP TABLE temp.c; \
         PRAGMA user_version=32;"
    ));
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let mut ledger = state.migrate().unwrap();
    assert_eq!(provision_state(&ledger, "blog1"), ProvisionState::Succeeded);
    ledger
        .record_deletion(&deletion(1, "blog1", "cap_1"), time(1100))
        .unwrap();
    drop(ledger);
    state.open().unwrap();
    // A deleted site without its deletion is not a recorded outcome.
    state.sql("DELETE FROM deletions");
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
}

/// The W508-F1 lesson: a journal that holds a signed deletion must open
/// again, and the admission must be observed.
#[test]
fn a_signed_deletion_keeps_the_journal_openable_and_observed() {
    use rustiron_contracts::{CanonicalObject, approval::Sha256Digest};
    use rustiron_journal::SignedAdmission;
    use sha2::{Digest, Sha256};
    const PLAN: &str = r#"{"plan_id":"plan_delete","schema_version":1,"site_id":"blog1"}"#;
    const GRANT: &str = r#"{"grant_id":"grant_delete","issuer":"lab_agent","nonce":"nonce_delete","signer_policy_epoch":"policy_3"}"#;
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let state = State::new();
    let mut ledger = state.init();
    served(&mut ledger, "blog1");
    capture(&mut ledger, "blog1", "cap_1", 1000, false);
    let mut intent = deletion(1, "blog1", "cap_1");
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
    ledger.record_deletion(&intent, time(1100)).unwrap();
    drop(ledger);
    let ledger = state.open().unwrap();
    assert!(
        ledger
            .deletion_status(&intent.operation_id)
            .unwrap()
            .is_some()
    );
    let observed =
        FixtureJournal::observe(&state.0, &id("host_fixture"), &id("epoch_fixture")).unwrap();
    assert!(
        observed
            .admissions
            .iter()
            .any(|admission| admission.operation_id == intent.operation_id.as_str())
    );
}

/// D-085: a deleted site's certificate is no longer observed, so its
/// expiry never alerts, and it is never due for renewal.
#[test]
fn a_deleted_sites_certificate_is_neither_observed_nor_renewed() {
    let state = State::new();
    let mut ledger = state.init();
    served(&mut ledger, "blog1");
    capture(&mut ledger, "blog1", "cap_1", 1000, false);
    drop(ledger);
    let row = |operation: &str, site: &str| {
        format!(
            "INSERT INTO certificates VALUES('{operation}','{operation}_key','{operation}_grant','{operation}_nonce','{a}','{b}','{site}','{site}.example.test',100000,'installed','{c}',2000)",
            a = "a".repeat(64),
            b = "b".repeat(64),
            c = "c".repeat(64)
        )
    };
    state.sql(&row("cert_1", "blog1"));
    let mut ledger = state.open().unwrap();
    let observed = || {
        FixtureJournal::observe(&state.0, &id("host_fixture"), &id("epoch_fixture"))
            .unwrap()
            .certificates
            .len()
    };
    assert_eq!(observed(), 1);
    ledger
        .record_deletion(&deletion(1, "blog1", "cap_1"), time(1100))
        .unwrap();
    assert_eq!(observed(), 0);
    assert!(ledger.due_renewals(time(1500)).unwrap().is_empty());
}
