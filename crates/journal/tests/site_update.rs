//! W514 (journal v32, D-084): a signed plugin and theme update. Its intent
//! rechecks the served site and its capture in one transaction; its steps
//! and rollback are recorded before and after each effect. Real SQLite; no
//! host effects.
use rustiron_contracts::approval::{
    ComponentSlug, ComponentVersion, Hostname, SiteId, UpdateComponent, UpdateKind,
};
use rustiron_journal::{
    Admitted, CaptureConsistency, CaptureIntent, CaptureManifest, CaptureMethod, FixtureJournal,
    JournalError, ProvisionIntent, ProvisionStep, SiteUpdate, StepState, UpdateIntent, UpdateState,
    UpdateStep,
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

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct State(PathBuf);
impl State {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ri-update-{}-{}",
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
        hostname: Hostname::try_from(format!("{name}.example.test")).unwrap(),
        expires_at: time(100_000),
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
        expires_at: time(100_000),
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

fn component(kind: UpdateKind, slug: &str, from: &str, to: &str) -> UpdateComponent {
    UpdateComponent {
        kind,
        slug: ComponentSlug::try_from(slug.to_owned()).unwrap(),
        from_version: ComponentVersion::try_from(from.to_owned()).unwrap(),
        to_version: ComponentVersion::try_from(to.to_owned()).unwrap(),
    }
}

fn update(n: u32, name: &str, capture: &str) -> UpdateIntent {
    UpdateIntent {
        operation_id: id(&format!("update_{n}")),
        idempotency_key: id(&format!("update_key_{n}")),
        grant_id: id(&format!("update_grant_{n}")),
        nonce: id(&format!("update_nonce_{n}")),
        plan_digest: digest('a'),
        grant_digest: digest('b'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: site_id(name),
        capture_operation_id: id(capture),
        recipe_digest: digest('9'),
        components: vec![
            component(UpdateKind::Plugin, "hello-dolly", "1.7.1", "1.7.2"),
            component(UpdateKind::Theme, "twentytwentyfour", "1.2", "1.3"),
        ],
        expires_at: time(100_000),
    }
}

fn new_update(result: Admitted<SiteUpdate>) -> rustiron_journal::SiteUpdate {
    match result {
        Admitted::New(update) => update,
        Admitted::Existing(_) => panic!("expected a new update"),
    }
}

#[test]
fn an_update_records_its_components_and_replays_exactly() {
    let state = State::new();
    let mut ledger = state.init();
    served(&mut ledger, "blog1");
    capture(&mut ledger, "blog1", "cap_1", 1000, false);
    let before = ledger.admission_count().unwrap();
    let intent = update(1, "blog1", "cap_1");
    let recorded = new_update(ledger.record_update(&intent, time(1100)).unwrap());
    assert_eq!(recorded.state, UpdateState::Intent);
    assert_eq!(recorded.components, intent.components);
    assert!(recorded.steps.is_empty() && recorded.rollback.is_none());
    assert_eq!(ledger.admission_count().unwrap(), before + 1);
    assert!(matches!(
        ledger.record_update(&intent, time(1101)),
        Ok(Admitted::Existing(_))
    ));
    // The same key with another component or recipe is a conflict.
    let mut other = intent.clone();
    other.components.pop();
    assert_eq!(
        ledger.record_update(&other, time(1101)).err(),
        Some(JournalError::Conflict)
    );
    let mut other = intent.clone();
    other.recipe_digest = digest('8');
    assert_eq!(
        ledger.record_update(&other, time(1101)).err(),
        Some(JournalError::Conflict)
    );
    // One open update per site.
    assert_eq!(
        ledger
            .record_update(&update(2, "blog1", "cap_1"), time(1102))
            .err(),
        Some(JournalError::Busy)
    );
    drop(ledger);
    let records = FixtureJournal::records_as_process_owner(
        &state.0,
        &id("host_fixture"),
        &id("epoch_fixture"),
        &id("update_1"),
        None,
    )
    .unwrap();
    // W518-F3: the helper finds the site's served provision in the records.
    assert!(
        records
            .served
            .iter()
            .any(|provision| provision.intent.site_id.as_str() == "blog1")
    );
    assert_eq!(records.site_update.unwrap().components, intent.components);
}

#[test]
fn the_site_and_capture_are_rechecked_with_the_intent() {
    let state = State::new();
    let mut ledger = state.init();
    served(&mut ledger, "blog1");
    served(&mut ledger, "blog2");
    capture(&mut ledger, "blog1", "cap_old", 1000, false);
    capture(&mut ledger, "blog1", "cap_new", 1100, false);
    capture(&mut ledger, "blog2", "cap_other", 1200, false);
    let refused = |ledger: &mut FixtureJournal, intent: &UpdateIntent, now: u64| {
        let error = ledger.record_update(intent, time(now)).err();
        assert!(
            ledger
                .update_status(&intent.operation_id)
                .unwrap()
                .is_none()
        );
        error
    };
    // Not the newest capture; another site's capture; an unknown capture.
    assert_eq!(
        refused(&mut ledger, &update(1, "blog1", "cap_old"), 1300),
        Some(JournalError::SourceChanged)
    );
    assert_eq!(
        refused(&mut ledger, &update(2, "blog1", "cap_other"), 1300),
        Some(JournalError::SourceChanged)
    );
    assert_eq!(
        refused(&mut ledger, &update(3, "blog1", "cap_none"), 1300),
        Some(JournalError::SourceChanged)
    );
    // Older than an hour.
    assert_eq!(
        refused(&mut ledger, &update(4, "blog1", "cap_new"), 1101 + 3601),
        Some(JournalError::SourceChanged)
    );
    // A site with no served provision.
    assert_eq!(
        refused(&mut ledger, &update(5, "blog3", "cap_new"), 4702),
        Some(JournalError::SourceChanged)
    );
    // A running capture of the site blocks the update.
    let mut ledger_two = {
        drop(ledger);
        state.open().unwrap()
    };
    capture(&mut ledger_two, "blog2", "cap_running", 4710, true);
    assert_eq!(
        refused(&mut ledger_two, &update(6, "blog2", "cap_other"), 4711),
        Some(JournalError::SourceChanged)
    );
    // Expired grant.
    let mut expired = update(7, "blog1", "cap_new");
    expired.expires_at = time(4712);
    assert_eq!(
        refused(&mut ledger_two, &expired, 4712),
        Some(JournalError::Expired)
    );
}

#[test]
fn steps_run_in_order_and_health_ends_the_update() {
    let state = State::new();
    let mut ledger = state.init();
    served(&mut ledger, "blog1");
    capture(&mut ledger, "blog1", "cap_1", 1000, false);
    let op = id("update_1");
    ledger
        .record_update(&update(1, "blog1", "cap_1"), time(1100))
        .unwrap();
    assert_eq!(
        ledger.begin_update_step(&op, UpdateStep::Swap).err(),
        Some(JournalError::Conflict)
    );
    assert_eq!(
        ledger.begin_update_rollback(&op).err(),
        Some(JournalError::Conflict)
    );
    for step in UpdateStep::ALL {
        ledger.begin_update_step(&op, step).unwrap();
        assert_eq!(
            ledger.begin_update_step(&op, step).err(),
            Some(JournalError::Conflict)
        );
        let after = ledger.finish_update_step(&op, step, true).unwrap();
        let done = step == UpdateStep::Health;
        assert_eq!(
            after.state,
            if done {
                UpdateState::Done
            } else {
                UpdateState::Intent
            }
        );
    }
    assert_eq!(
        ledger
            .finish_update_step(&op, UpdateStep::Health, false)
            .err(),
        Some(JournalError::Conflict)
    );
    // A done update no longer blocks the next one of the site.
    capture(&mut ledger, "blog1", "cap_2", 1200, false);
    ledger
        .record_update(&update(2, "blog1", "cap_2"), time(1300))
        .unwrap();
    drop(ledger);
    state.open().unwrap();
}

#[test]
fn a_failed_step_is_rolled_back_or_left_open() {
    let state = State::new();
    let mut ledger = state.init();
    served(&mut ledger, "blog1");
    served(&mut ledger, "blog2");
    capture(&mut ledger, "blog1", "cap_1", 1000, false);
    capture(&mut ledger, "blog2", "cap_2", 1001, false);
    let first = id("update_1");
    ledger
        .record_update(&update(1, "blog1", "cap_1"), time(1100))
        .unwrap();
    ledger
        .begin_update_step(&first, UpdateStep::Unpack)
        .unwrap();
    ledger
        .finish_update_step(&first, UpdateStep::Unpack, true)
        .unwrap();
    ledger.begin_update_step(&first, UpdateStep::Swap).unwrap();
    ledger
        .finish_update_step(&first, UpdateStep::Swap, false)
        .unwrap();
    assert_eq!(
        ledger.begin_update_step(&first, UpdateStep::Script).err(),
        Some(JournalError::Conflict)
    );
    let open = ledger.begin_update_rollback(&first).unwrap();
    assert_eq!(open.rollback, Some(StepState::Intent));
    assert_eq!(
        ledger.begin_update_rollback(&first).err(),
        Some(JournalError::Conflict)
    );
    let rolled = ledger.finish_update_rollback(&first, true).unwrap();
    assert_eq!(rolled.state, UpdateState::RolledBack);
    // An unverified rollback leaves the update open, and the site blocked.
    let second = id("update_2");
    ledger
        .record_update(&update(2, "blog2", "cap_2"), time(1101))
        .unwrap();
    ledger
        .begin_update_step(&second, UpdateStep::Unpack)
        .unwrap();
    ledger
        .finish_update_step(&second, UpdateStep::Unpack, false)
        .unwrap();
    ledger.begin_update_rollback(&second).unwrap();
    let failed = ledger.finish_update_rollback(&second, false).unwrap();
    assert_eq!(failed.state, UpdateState::Intent);
    assert_eq!(failed.rollback, Some(StepState::Failed));
    // W518-F2: the operator's reconcile may begin the failed rollback again.
    let again = ledger.begin_update_rollback(&second).unwrap();
    assert_eq!(again.rollback, Some(StepState::Intent));
    assert_eq!(
        ledger.begin_update_rollback(&second).err(),
        Some(JournalError::Conflict)
    );
    ledger.finish_update_rollback(&second, false).unwrap();
    assert_eq!(
        ledger
            .record_update(&update(3, "blog2", "cap_2"), time(1102))
            .err(),
        Some(JournalError::Busy)
    );
    drop(ledger);
    state.open().unwrap();
}

#[test]
fn a_v31_journal_migrates_and_inconsistent_rows_are_refused() {
    let state = State::new();
    let mut ledger = state.init();
    served(&mut ledger, "blog1");
    capture(&mut ledger, "blog1", "cap_1", 1000, false);
    drop(ledger);
    state.sql("PRAGMA foreign_keys=OFF; DROP TABLE caddy_generations; DROP TABLE app_fullstack_specs; DROP TABLE credential_rotations; DROP TABLE app_lifecycles; DROP TABLE app_release_steps; DROP TABLE app_releases; DROP TABLE apps; DROP TABLE static_ejections; DROP TABLE proxy_routes; DROP TABLE dns_change_sets; DROP TABLE dns_changes; DROP TABLE dns_imports; DROP TABLE restore_steps; DROP TABLE restore_attempts; DROP TABLE site_restores; DROP TABLE clone_scrub_grants; DROP TABLE quota_changes; DROP TABLE deletions; CREATE TEMP TABLE p32 AS SELECT * FROM provisions; DROP TABLE provisions; CREATE TABLE provisions (operation_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL, grant_digest TEXT NOT NULL, host_id TEXT NOT NULL, host_epoch TEXT NOT NULL, site_id TEXT NOT NULL UNIQUE, hostname TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('running','succeeded','quarantined','adopted'))) STRICT; INSERT INTO provisions SELECT * FROM temp.p32; DROP TABLE temp.p32; CREATE UNIQUE INDEX one_running_provision ON provisions((1)) WHERE state='running'; DROP TABLE update_rollbacks; DROP TABLE update_steps; DROP TABLE update_components; DROP INDEX one_open_update; DROP TABLE updates; PRAGMA user_version=31;");
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let mut ledger = state.migrate().unwrap();
    ledger
        .record_update(&update(1, "blog1", "cap_1"), time(1100))
        .unwrap();
    drop(ledger);
    // A done update without its steps is not a recorded outcome.
    state.sql("UPDATE updates SET state='done' WHERE operation_id='update_1'");
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    state.sql("UPDATE updates SET state='intent' WHERE operation_id='update_1'; DELETE FROM update_components WHERE operation_id='update_1';");
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
}

/// The W508-F1 lesson: a journal that holds a signed update must open
/// again, and the admission must be observed.
#[test]
fn a_signed_update_keeps_the_journal_openable_and_observed() {
    use rustiron_contracts::{CanonicalObject, approval::Sha256Digest};
    use rustiron_journal::SignedAdmission;
    use sha2::{Digest, Sha256};
    const PLAN: &str = r#"{"plan_id":"plan_update","schema_version":1,"site_id":"blog1"}"#;
    const GRANT: &str = r#"{"grant_id":"grant_update","issuer":"lab_agent","nonce":"nonce_update","signer_policy_epoch":"policy_3"}"#;
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let state = State::new();
    let mut ledger = state.init();
    served(&mut ledger, "blog1");
    capture(&mut ledger, "blog1", "cap_1", 1000, false);
    let mut intent = update(1, "blog1", "cap_1");
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
    ledger.record_update(&intent, time(1100)).unwrap();
    drop(ledger);
    let ledger = state.open().unwrap();
    assert!(
        ledger
            .update_status(&intent.operation_id)
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

/// W526 (D-086): a v33 journal keeps its update rows through the v34
/// rebuild of `update_components`, which then admits a core update; a core
/// update that also holds a plugin is not a recorded outcome.
#[test]
fn a_v33_journal_migrates_and_records_a_core_update() {
    const V33_UPDATE_COMPONENTS: &str = "CREATE TABLE update_components (operation_id TEXT NOT NULL REFERENCES updates(operation_id), position INTEGER NOT NULL CHECK(position BETWEEN 0 AND 7), kind TEXT NOT NULL CHECK(kind IN ('plugin','theme')), slug TEXT NOT NULL CHECK(length(slug) BETWEEN 1 AND 64 AND slug NOT GLOB '*[^a-z0-9_-]*' AND slug NOT GLOB '[-_]*'), from_version TEXT NOT NULL CHECK(length(from_version) BETWEEN 1 AND 32 AND from_version NOT GLOB '*[^0-9A-Za-z.-]*' AND from_version GLOB '[0-9]*'), to_version TEXT NOT NULL CHECK(length(to_version) BETWEEN 1 AND 32 AND to_version NOT GLOB '*[^0-9A-Za-z.-]*' AND to_version GLOB '[0-9]*' AND to_version<>from_version), PRIMARY KEY(operation_id, position), UNIQUE(operation_id, kind, slug)) STRICT";
    let state = State::new();
    let mut ledger = state.init();
    served(&mut ledger, "blog1");
    capture(&mut ledger, "blog1", "cap_1", 1000, false);
    ledger
        .record_update(&update(1, "blog1", "cap_1"), time(1100))
        .unwrap();
    drop(ledger);
    state.sql(&format!(
        "PRAGMA foreign_keys=OFF; DROP TABLE caddy_generations; DROP TABLE app_fullstack_specs; DROP TABLE credential_rotations; DROP TABLE app_lifecycles; DROP TABLE app_release_steps; DROP TABLE app_releases; DROP TABLE apps; DROP TABLE static_ejections; DROP TABLE proxy_routes; DROP TABLE dns_change_sets; DROP TABLE dns_changes; DROP TABLE dns_imports; DROP TABLE restore_steps; DROP TABLE restore_attempts; DROP TABLE site_restores; DROP TABLE clone_scrub_grants; DROP TABLE quota_changes; CREATE TEMP TABLE c AS SELECT * FROM update_components; \
         DROP TABLE update_components; {V33_UPDATE_COMPONENTS}; \
         INSERT INTO update_components SELECT * FROM temp.c; DROP TABLE temp.c; {TO_V40_DELETIONS} PRAGMA user_version=33;"
    ));
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let mut ledger = state.migrate().unwrap();
    assert_eq!(
        ledger
            .update_status(&id("update_1"))
            .unwrap()
            .unwrap()
            .components,
        update(1, "blog1", "cap_1").components
    );
    // The open update keeps the site busy; it rolls back first.
    ledger
        .begin_update_step(&id("update_1"), UpdateStep::Unpack)
        .unwrap();
    ledger
        .finish_update_step(&id("update_1"), UpdateStep::Unpack, false)
        .unwrap();
    ledger.begin_update_rollback(&id("update_1")).unwrap();
    ledger
        .finish_update_rollback(&id("update_1"), true)
        .unwrap();
    capture(&mut ledger, "blog1", "cap_2", 1200, false);
    let mut core = update(2, "blog1", "cap_2");
    core.components = vec![component(UpdateKind::Core, "wordpress", "7.0.9", "7.1.5")];
    ledger.record_update(&core, time(1300)).unwrap();
    assert_eq!(
        ledger
            .update_status(&core.operation_id)
            .unwrap()
            .unwrap()
            .components,
        core.components
    );
    drop(ledger);
    state.open().unwrap();
    state.sql(
        "INSERT INTO update_components VALUES('update_2',1,'plugin','hello-dolly','1.7.1','1.7.2')",
    );
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
}
