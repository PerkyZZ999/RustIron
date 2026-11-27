//! W498 (journal v29, D-078): a staging clone is a provision whose Recipe
//! step holds the clone steps. Its reservation rechecks the source capture
//! in the same transaction. W501 (v30): the scrub after a failed clone
//! step. Real SQLite; no host effects.
use rustiron_contracts::approval::{Hostname, SiteId, SnapshotId};
use rustiron_journal::{
    CaptureConsistency, CaptureIntent, CaptureManifest, CaptureMethod, CloneFacts,
    CloneScrubIntent, CloneScrubResult, CloneStep, FixtureJournal, JournalError, ProvisionIntent,
    ProvisionResult, ProvisionState, ProvisionStep, StepState,
};
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
mod support;
use support::*;

/// The exact v29 and v30 tables.
const DDL_V30: [(&str, &str); 3] = [
    (
        "clones",
        "CREATE TABLE clones (operation_id TEXT PRIMARY KEY REFERENCES provisions(operation_id), source_site_id TEXT NOT NULL REFERENCES provisions(site_id), source_hostname TEXT NOT NULL CHECK(length(source_hostname) BETWEEN 1 AND 253 AND source_hostname NOT GLOB '*[^a-z0-9.-]*'), capture_operation_id TEXT NOT NULL REFERENCES captures(operation_id), snapshot_id TEXT NOT NULL CHECK(length(snapshot_id)=64 AND snapshot_id NOT GLOB '*[^0-9a-f]*'), manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256)=64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'), destination_policy_digest TEXT NOT NULL CHECK(length(destination_policy_digest)=64 AND destination_policy_digest NOT GLOB '*[^0-9a-f]*'), repository_id TEXT NOT NULL CHECK(length(repository_id)=64 AND repository_id NOT GLOB '*[^0-9a-f]*')) STRICT",
    ),
    (
        "clone_steps",
        "CREATE TABLE clone_steps (operation_id TEXT NOT NULL REFERENCES clones(operation_id), position INTEGER NOT NULL CHECK(position BETWEEN 0 AND 4), state TEXT NOT NULL CHECK(state IN ('intent','done','failed')), PRIMARY KEY(operation_id, position)) STRICT",
    ),
    (
        "clone_scrubs",
        "CREATE TABLE clone_scrubs (operation_id TEXT PRIMARY KEY REFERENCES clones(operation_id), state TEXT NOT NULL CHECK(state IN ('intent','done','failed'))) STRICT",
    ),
];

const SNAPSHOT: &str = "89f5ad054604acf1033adc33725d0a96c5b609225525bda3bff495d4cc61f3ad";

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct State(PathBuf);
impl State {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ri-clone-{}-{}",
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
    fn connection(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.0.join("fixture-journal.sqlite")).unwrap()
    }
    fn sql(&self, sql: &str) {
        self.connection().execute_batch(sql).unwrap();
    }
}
impl Drop for State {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn site(name: &str, operation: &str) -> ProvisionIntent {
    ProvisionIntent {
        operation_id: id(operation),
        idempotency_key: id(&format!("{operation}_key")),
        grant_id: id(&format!("{operation}_grant")),
        nonce: id(&format!("{operation}_nonce")),
        plan_digest: digest('a'),
        grant_digest: digest('b'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: SiteId::try_from(name.to_owned()).unwrap(),
        hostname: Hostname::try_from(format!("{name}.example.test")).unwrap(),
        expires_at: time(10000),
    }
}

fn target() -> ProvisionIntent {
    site("stage9", "clone_op")
}

/// A served native source with one succeeded, complete, `matched` capture.
fn source(ledger: &mut FixtureJournal) {
    let intent = site("blog9", "source_op");
    ledger.record_provision(&intent, time(900)).unwrap();
    for step in ProvisionStep::ALL {
        ledger.begin_step(&intent.operation_id, step, "r").unwrap();
        ledger
            .finish_step(&intent.operation_id, step, true)
            .unwrap();
    }
    let capture = CaptureIntent {
        operation_id: id("capture_op"),
        idempotency_key: id("capture_key"),
        grant_id: id("capture_grant"),
        nonce: id("capture_nonce"),
        plan_digest: digest('c'),
        grant_digest: digest('d'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: intent.site_id,
        expires_at: time(10000),
    };
    ledger
        .record_capture(
            &capture,
            time(1000),
            CaptureMethod::SiteFilesDbV1,
            None,
            &digest('e'),
        )
        .unwrap();
    ledger
        .finish_capture_labelled(
            &capture.operation_id,
            Some(SNAPSHOT),
            time(1001),
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

fn facts() -> CloneFacts {
    CloneFacts {
        source_site_id: SiteId::try_from("blog9".to_owned()).unwrap(),
        source_hostname: Hostname::try_from("blog9.example.test".to_owned()).unwrap(),
        capture_operation_id: id("capture_op"),
        snapshot_id: SnapshotId::try_from(SNAPSHOT.to_owned()).unwrap(),
        manifest_sha256: digest('f'),
        destination_policy_digest: digest('e'),
        repository_id: digest('1'),
    }
}

/// Runs the provision steps before Recipe, then begins Recipe.
fn reach_recipe(ledger: &mut FixtureJournal, intent: &ProvisionIntent) {
    for step in &ProvisionStep::ALL[..5] {
        ledger
            .begin_step(&intent.operation_id, *step, "resource")
            .unwrap();
        ledger
            .finish_step(&intent.operation_id, *step, true)
            .unwrap();
    }
    ledger
        .begin_step(&intent.operation_id, ProvisionStep::Recipe, "site_clone_v1")
        .unwrap();
}

#[test]
fn a_fresh_journal_has_the_exact_clone_tables() {
    let state = State::new();
    drop(state.init());
    let c = state.connection();
    let version: i64 = c
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, 45);
    for (name, sql) in DDL_V30 {
        let stored: String = c
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE name=?1",
                [name],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, sql, "{name}");
    }
}

#[test]
fn a_clone_reserves_its_target_with_the_recorded_capture_and_replays_exactly() {
    let state = State::new();
    let mut ledger = state.init();
    source(&mut ledger);
    let intent = target();
    let created = ledger.record_clone(&intent, &facts(), time(1100)).unwrap();
    let ProvisionResult::New(provision) = created else {
        panic!("expected a new clone provision");
    };
    assert_eq!(provision.state, ProvisionState::Running);
    let stored = ledger.clone_status(&intent.operation_id).unwrap().unwrap();
    assert_eq!(stored.facts, facts());
    assert!(stored.steps.is_empty());
    assert!(matches!(
        ledger.record_clone(&intent, &facts(), time(1101)),
        Ok(ProvisionResult::Existing(_))
    ));
    // The same retry key with other facts, or as a plain provision, is a conflict.
    let other = CloneFacts {
        repository_id: digest('2'),
        ..facts()
    };
    assert_eq!(
        ledger.record_clone(&intent, &other, time(1102)).err(),
        Some(JournalError::Conflict)
    );
    assert_eq!(
        ledger.record_provision(&intent, time(1102)).err(),
        Some(JournalError::Conflict)
    );
    drop(ledger);
    assert_eq!(
        state
            .open()
            .unwrap()
            .clone_status(&intent.operation_id)
            .unwrap(),
        Some(stored)
    );
}

#[test]
fn a_substituted_or_unqualified_source_reserves_nothing() {
    let state = State::new();
    let mut ledger = state.init();
    source(&mut ledger);
    let substitutions = [
        CloneFacts {
            source_hostname: Hostname::try_from("other.example.test".to_owned()).unwrap(),
            ..facts()
        },
        CloneFacts {
            capture_operation_id: id("capture_other"),
            ..facts()
        },
        CloneFacts {
            snapshot_id: SnapshotId::try_from("a".repeat(64)).unwrap(),
            ..facts()
        },
        CloneFacts {
            manifest_sha256: digest('9'),
            ..facts()
        },
        CloneFacts {
            destination_policy_digest: digest('8'),
            ..facts()
        },
        CloneFacts {
            source_site_id: SiteId::try_from("blog8".to_owned()).unwrap(),
            ..facts()
        },
    ];
    for changed in &substitutions {
        assert_eq!(
            ledger.record_clone(&target(), changed, time(1100)).err(),
            Some(JournalError::SourceChanged),
            "{changed:?}"
        );
    }
    // A truncated manifest or an unmatched label disqualifies the capture.
    state.sql("UPDATE capture_manifest SET truncated=1");
    assert_eq!(
        ledger.record_clone(&target(), &facts(), time(1100)).err(),
        Some(JournalError::SourceChanged)
    );
    state.sql("UPDATE capture_manifest SET truncated=0; UPDATE capture_consistency SET label='unmatched', reason='database_changed'");
    assert_eq!(
        ledger.record_clone(&target(), &facts(), time(1100)).err(),
        Some(JournalError::SourceChanged)
    );
    state.sql("UPDATE capture_consistency SET label='matched', reason=NULL");
    // A target that names the source, or any reserved name, is consumed.
    for (name, operation) in [("blog9", "clone_same"), ("stage9", "clone_ok")] {
        let mut intent = site(name, operation);
        if name == "stage9" {
            intent.hostname = Hostname::try_from("blog9.example.test".to_owned()).unwrap();
        }
        assert_eq!(
            ledger.record_clone(&intent, &facts(), time(1100)).err(),
            Some(JournalError::Consumed)
        );
    }
    assert!(ledger.clone_status(&id("clone_op")).unwrap().is_none());
    ledger
        .record_clone(&target(), &facts(), time(1101))
        .unwrap();
}

#[test]
fn clone_steps_run_in_order_inside_the_recipe_and_a_failure_quarantines() {
    let state = State::new();
    let mut ledger = state.init();
    source(&mut ledger);
    let intent = target();
    let op = &intent.operation_id;
    ledger.record_clone(&intent, &facts(), time(1100)).unwrap();
    // No clone step before the Recipe step is open.
    assert_eq!(
        ledger.begin_clone_step(op, CloneStep::Fetch).err(),
        Some(JournalError::Conflict)
    );
    reach_recipe(&mut ledger, &intent);
    assert_eq!(
        ledger.begin_clone_step(op, CloneStep::Observe).err(),
        Some(JournalError::Conflict)
    );
    for step in &CloneStep::ALL[..2] {
        ledger.begin_clone_step(op, *step).unwrap();
        ledger.finish_clone_step(op, *step, true).unwrap();
    }
    // The Recipe step cannot finish with clone steps missing.
    assert_eq!(
        ledger.finish_step(op, ProvisionStep::Recipe, true).err(),
        Some(JournalError::Conflict)
    );
    ledger.begin_clone_step(op, CloneStep::Files).unwrap();
    let failed = ledger
        .finish_clone_step(op, CloneStep::Files, false)
        .unwrap();
    assert_eq!(failed.steps.last().unwrap().state, StepState::Failed);
    let provision = ledger.provision_status(op).unwrap().unwrap();
    assert_eq!(provision.state, ProvisionState::Quarantined);
    assert_eq!(provision.steps.last().unwrap().state, StepState::Failed);
    // A quarantined clone keeps its names.
    assert_eq!(
        ledger
            .record_clone(&site("stage9", "clone_again"), &facts(), time(1200))
            .err(),
        Some(JournalError::Consumed)
    );
}

#[test]
fn a_complete_clone_finishes_its_recipe_and_cannot_be_a_clone_source() {
    let state = State::new();
    let mut ledger = state.init();
    source(&mut ledger);
    let intent = target();
    let op = &intent.operation_id;
    ledger.record_clone(&intent, &facts(), time(1100)).unwrap();
    reach_recipe(&mut ledger, &intent);
    for step in CloneStep::ALL {
        ledger.begin_clone_step(op, step).unwrap();
        ledger.finish_clone_step(op, step, true).unwrap();
    }
    ledger.finish_step(op, ProvisionStep::Recipe, true).unwrap();
    for step in [ProvisionStep::PhpUnits, ProvisionStep::Verify] {
        ledger.begin_step(op, step, "resource").unwrap();
        ledger.finish_step(op, step, true).unwrap();
    }
    assert_eq!(
        ledger.provision_status(op).unwrap().unwrap().state,
        ProvisionState::Succeeded
    );
    // The served clone's own capture does not make it a clone source.
    let capture = CaptureIntent {
        operation_id: id("stage_capture"),
        idempotency_key: id("stage_capture_key"),
        grant_id: id("stage_capture_grant"),
        nonce: id("stage_capture_nonce"),
        plan_digest: digest('c'),
        grant_digest: digest('d'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: intent.site_id.clone(),
        expires_at: time(10000),
    };
    ledger
        .record_capture(
            &capture,
            time(1300),
            CaptureMethod::SiteFilesDbV1,
            None,
            &digest('e'),
        )
        .unwrap();
    ledger
        .finish_capture_labelled(
            &capture.operation_id,
            Some(SNAPSHOT),
            time(1301),
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
    let second = CloneFacts {
        source_site_id: intent.site_id.clone(),
        source_hostname: intent.hostname.clone(),
        capture_operation_id: capture.operation_id,
        ..facts()
    };
    assert_eq!(
        ledger
            .record_clone(&site("stage8", "clone_of_clone"), &second, time(1400))
            .err(),
        Some(JournalError::SourceChanged)
    );
}

#[test]
fn a_v28_journal_migrates_to_v30_and_an_invalid_clone_row_is_refused() {
    let state = State::new();
    let mut ledger = state.init();
    source(&mut ledger);
    drop(ledger);
    state.sql(
        "PRAGMA foreign_keys=OFF; DROP TABLE caddy_generations; DROP TABLE app_fullstack_specs; DROP TABLE credential_rotations; DROP TABLE app_lifecycles; DROP TABLE app_release_steps; DROP TABLE app_releases; DROP TABLE apps; DROP TABLE static_ejections; DROP TABLE proxy_routes; DROP TABLE dns_change_sets; DROP TABLE dns_changes; DROP TABLE dns_imports; DROP TABLE restore_steps; DROP TABLE restore_attempts; DROP TABLE site_restores; DROP TABLE clone_scrub_grants; DROP TABLE quota_changes; DROP TABLE deletions; CREATE TEMP TABLE p32 AS SELECT * FROM provisions; DROP TABLE provisions; CREATE TABLE provisions (operation_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL, grant_digest TEXT NOT NULL, host_id TEXT NOT NULL, host_epoch TEXT NOT NULL, site_id TEXT NOT NULL UNIQUE, hostname TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('running','succeeded','quarantined','adopted'))) STRICT; INSERT INTO provisions SELECT * FROM temp.p32; DROP TABLE temp.p32; CREATE UNIQUE INDEX one_running_provision ON provisions((1)) WHERE state='running'; DROP TABLE update_rollbacks; DROP TABLE update_steps; DROP TABLE update_components; DROP INDEX one_open_update; DROP TABLE updates; DROP INDEX one_retirement; DROP TABLE retirements; DROP TABLE clone_scrubs; DROP TABLE clone_steps; DROP TABLE clones; PRAGMA user_version=28;",
    );
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let mut ledger = state.migrate().unwrap();
    ledger
        .record_clone(&target(), &facts(), time(1100))
        .unwrap();
    drop(ledger);
    assert!(state.open().is_ok());
    // A clone row whose target is its own source fails validation at open.
    state.sql("PRAGMA foreign_keys=OFF; UPDATE clones SET source_site_id='stage9';");
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
}

#[test]
fn a_source_with_an_ejection_that_could_succeed_is_not_cloned() {
    let state = State::new();
    let mut ledger = state.init();
    source(&mut ledger);
    let mut eject = intent(1);
    eject.resource_id = id("ols_lab_listener");
    let blog9 = SiteId::try_from("blog9".to_owned()).unwrap();
    ledger
        .record_ejection_intent(&eject, &blog9, time(1050))
        .unwrap();
    assert_eq!(
        ledger.record_clone(&target(), &facts(), time(1100)).err(),
        Some(JournalError::SourceChanged)
    );
    assert!(ledger.clone_status(&id("clone_op")).unwrap().is_none());
}

#[test]
fn only_a_clone_quarantined_by_a_failed_step_takes_one_scrub() {
    let state = State::new();
    let mut ledger = state.init();
    source(&mut ledger);
    let intent = target();
    let op = &intent.operation_id;
    ledger.record_clone(&intent, &facts(), time(1100)).unwrap();
    // Not before a failed step: running, then a step still open.
    assert_eq!(
        ledger.begin_clone_scrub(op).err(),
        Some(JournalError::Conflict)
    );
    reach_recipe(&mut ledger, &intent);
    ledger.begin_clone_step(op, CloneStep::Fetch).unwrap();
    assert_eq!(
        ledger.begin_clone_scrub(op).err(),
        Some(JournalError::Conflict)
    );
    ledger
        .finish_clone_step(op, CloneStep::Fetch, true)
        .unwrap();
    ledger.begin_clone_step(op, CloneStep::Observe).unwrap();
    ledger
        .finish_clone_step(op, CloneStep::Observe, false)
        .unwrap();
    assert_eq!(
        ledger.finish_clone_scrub(op, true).err(),
        Some(JournalError::Conflict)
    );
    let open = ledger.begin_clone_scrub(op).unwrap();
    assert_eq!(open.scrub, Some(StepState::Intent));
    assert_eq!(
        ledger.begin_clone_scrub(op).err(),
        Some(JournalError::Conflict)
    );
    let done = ledger.finish_clone_scrub(op, true).unwrap();
    assert_eq!(done.scrub, Some(StepState::Done));
    assert_eq!(
        ledger.finish_clone_scrub(op, false).err(),
        Some(JournalError::Conflict)
    );
    drop(ledger);
    assert_eq!(
        state
            .open()
            .unwrap()
            .clone_status(op)
            .unwrap()
            .unwrap()
            .scrub,
        Some(StepState::Done)
    );
    // A scrub row of a clone that is not quarantined fails validation.
    state.sql("UPDATE provisions SET state='succeeded' WHERE operation_id='clone_op'");
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
}

#[test]
fn a_v29_journal_keeps_its_clones_and_migrates_to_v30() {
    let state = State::new();
    let mut ledger = state.init();
    source(&mut ledger);
    let intent = target();
    ledger.record_clone(&intent, &facts(), time(1100)).unwrap();
    reach_recipe(&mut ledger, &intent);
    ledger
        .begin_clone_step(&intent.operation_id, CloneStep::Fetch)
        .unwrap();
    ledger
        .finish_clone_step(&intent.operation_id, CloneStep::Fetch, false)
        .unwrap();
    let saved = ledger.clone_status(&intent.operation_id).unwrap().unwrap();
    drop(ledger);
    state.sql("PRAGMA foreign_keys=OFF; DROP TABLE caddy_generations; DROP TABLE app_fullstack_specs; DROP TABLE credential_rotations; DROP TABLE app_lifecycles; DROP TABLE app_release_steps; DROP TABLE app_releases; DROP TABLE apps; DROP TABLE static_ejections; DROP TABLE proxy_routes; DROP TABLE dns_change_sets; DROP TABLE dns_changes; DROP TABLE dns_imports; DROP TABLE restore_steps; DROP TABLE restore_attempts; DROP TABLE site_restores; DROP TABLE clone_scrub_grants; DROP TABLE quota_changes; DROP TABLE deletions; CREATE TEMP TABLE p32 AS SELECT * FROM provisions; DROP TABLE provisions; CREATE TABLE provisions (operation_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL, grant_digest TEXT NOT NULL, host_id TEXT NOT NULL, host_epoch TEXT NOT NULL, site_id TEXT NOT NULL UNIQUE, hostname TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('running','succeeded','quarantined','adopted'))) STRICT; INSERT INTO provisions SELECT * FROM temp.p32; DROP TABLE temp.p32; CREATE UNIQUE INDEX one_running_provision ON provisions((1)) WHERE state='running'; DROP TABLE update_rollbacks; DROP TABLE update_steps; DROP TABLE update_components; DROP INDEX one_open_update; DROP TABLE updates; DROP INDEX one_retirement; DROP TABLE retirements; DROP TABLE clone_scrubs; PRAGMA user_version=29;");
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let mut ledger = state.migrate().unwrap();
    assert_eq!(
        ledger.clone_status(&intent.operation_id).unwrap(),
        Some(saved)
    );
    ledger.begin_clone_scrub(&intent.operation_id).unwrap();
}

fn signed_scrub(n: u32, site: &str) -> CloneScrubIntent {
    CloneScrubIntent {
        operation_id: id(&format!("cscrub_{n}")),
        idempotency_key: id(&format!("cscrub_key_{n}")),
        grant_id: id(&format!("cscrub_grant_{n}")),
        nonce: id(&format!("cscrub_nonce_{n}")),
        plan_digest: digest('3'),
        grant_digest: digest('4'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: SiteId::try_from(site.to_owned()).unwrap(),
        clone_operation_id: id("clone_op"),
        expires_at: time(10000),
    }
}

/// W538 (v36, D-078 signed clone scrub): an interrupted clone that the
/// operator quarantined keeps its Fetch step at `intent`; a signed scrub
/// opens its scrub, and its outcome closes both. A failed one may be retried
/// by a new signed request; a done scrub takes no other.
#[test]
fn a_signed_scrub_opens_the_scrub_of_an_interrupted_clone() {
    let state = State::new();
    let mut ledger = state.init();
    source(&mut ledger);
    let intent = target();
    let op = &intent.operation_id;
    ledger.record_clone(&intent, &facts(), time(1100)).unwrap();
    reach_recipe(&mut ledger, &intent);
    ledger.begin_clone_step(op, CloneStep::Fetch).unwrap();
    // Still running: refused.
    assert_eq!(
        ledger
            .record_clone_scrub(&signed_scrub(1, "stage9"), time(1200))
            .err(),
        Some(JournalError::Consumed)
    );
    ledger.quarantine_provision(op).unwrap();
    let status = ledger.clone_status(op).unwrap().unwrap();
    assert_eq!(status.steps.last().unwrap().state, StepState::Intent);
    assert_eq!(status.scrub, None);
    // Another site than the clone's target: refused.
    assert_eq!(
        ledger
            .record_clone_scrub(&signed_scrub(2, "blog9"), time(1200))
            .err(),
        Some(JournalError::Consumed)
    );
    let first = signed_scrub(3, "stage9");
    let CloneScrubResult::New(open) = ledger.record_clone_scrub(&first, time(1200)).unwrap() else {
        panic!("a new signed scrub");
    };
    assert_eq!(open.state, StepState::Intent);
    let clone = ledger.clone_status(op).unwrap().unwrap();
    assert_eq!(
        (clone.scrub, clone.signed_scrub),
        (Some(StepState::Intent), Some(StepState::Intent))
    );
    // One open scrub.
    assert_eq!(
        ledger
            .record_clone_scrub(&signed_scrub(4, "stage9"), time(1200))
            .err(),
        Some(JournalError::Consumed)
    );
    let failed = ledger
        .finish_signed_clone_scrub(&first.operation_id, false)
        .unwrap();
    assert_eq!(failed.state, StepState::Failed);
    assert_eq!(
        ledger.clone_status(op).unwrap().unwrap().scrub,
        Some(StepState::Failed)
    );
    assert_eq!(
        ledger.record_clone_scrub(&first, time(1300)).unwrap(),
        CloneScrubResult::Existing(failed)
    );
    // A retry opens the failed scrub again; done closes both.
    let retry = signed_scrub(5, "stage9");
    ledger.record_clone_scrub(&retry, time(1300)).unwrap();
    let done = ledger
        .finish_signed_clone_scrub(&retry.operation_id, true)
        .unwrap();
    assert_eq!(done.state, StepState::Done);
    let clone = ledger.clone_status(op).unwrap().unwrap();
    assert_eq!(
        (clone.scrub, clone.signed_scrub),
        (Some(StepState::Done), Some(StepState::Done))
    );
    assert_eq!(
        ledger
            .record_clone_scrub(&signed_scrub(6, "stage9"), time(1400))
            .err(),
        Some(JournalError::Consumed)
    );
    drop(ledger);
    let ledger = state.open().unwrap();
    assert_eq!(
        ledger.clone_scrub_status(&retry.operation_id).unwrap(),
        Some(done)
    );
}

#[test]
fn a_v35_journal_migrates_to_v36() {
    let state = State::new();
    let mut ledger = state.init();
    source(&mut ledger);
    drop(ledger);
    state.sql(&format!("DROP TABLE caddy_generations; DROP TABLE app_fullstack_specs; DROP TABLE credential_rotations; DROP TABLE app_lifecycles; DROP TABLE app_release_steps; DROP TABLE app_releases; DROP TABLE apps; DROP TABLE static_ejections; DROP TABLE proxy_routes; DROP TABLE dns_change_sets; DROP TABLE dns_changes; DROP TABLE dns_imports; DROP TABLE restore_steps; DROP TABLE restore_attempts; DROP TABLE site_restores; DROP TABLE clone_scrub_grants; {TO_V40_DELETIONS} PRAGMA user_version=35;"));
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    drop(state.migrate().unwrap());
    state.open().unwrap();
}
