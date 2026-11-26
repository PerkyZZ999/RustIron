//! W391 (journal v18, B09): a succeeded product capture keeps the retention
//! evidence its lock reader read back (the bucket default before and after,
//! and each written object version with its mode and retain-until time), and
//! a refused capture keeps its refusal code. Real SQLite; no host effects.
use rustiron_contracts::approval::{Hostname, SiteId};
use rustiron_journal::{
    CaptureConsistency, CaptureIntent, CaptureMethod, CaptureState, CaptureSuccess, FixtureJournal,
    JournalError, ObjectRetention, ProvisionIntent, ProvisionStep, RetainedObjectKind,
    RetentionEvidence,
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

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct State(PathBuf);
impl State {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ri-retention-{}-{}",
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

const SNAPSHOT: &str = "a50c8b74e3c0f1d2a50c8b74e3c0f1d2a50c8b74e3c0f1d2a50c8b74e3c0f1d2";
const INDEX: &str = "1b2c3d4e5f60718293a4b5c6d7e8f9001b2c3d4e5f60718293a4b5c6d7e8f900";
const PACK: &str = "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0";
const DDL: [(&str, &str); 3] = [
    (
        "capture_refusals",
        "CREATE TABLE capture_refusals (operation_id TEXT PRIMARY KEY REFERENCES captures(operation_id), code TEXT NOT NULL CHECK(length(code) BETWEEN 1 AND 64 AND code NOT GLOB '*[^A-Z0-9_]*')) STRICT",
    ),
    (
        "capture_lock_checks",
        "CREATE TABLE capture_lock_checks (operation_id TEXT PRIMARY KEY REFERENCES captures(operation_id), before_mode TEXT NOT NULL CHECK(before_mode='COMPLIANCE'), before_days INTEGER NOT NULL CHECK(before_days BETWEEN 1 AND 36500), after_mode TEXT NOT NULL CHECK(after_mode='COMPLIANCE'), after_days INTEGER NOT NULL CHECK(after_days BETWEEN 1 AND 36500), objects INTEGER NOT NULL CHECK(objects BETWEEN 1 AND 1024)) STRICT",
    ),
    (
        "capture_object_retention",
        "CREATE TABLE capture_object_retention (operation_id TEXT NOT NULL REFERENCES capture_lock_checks(operation_id), position INTEGER NOT NULL CHECK(position BETWEEN 0 AND 1023), kind TEXT NOT NULL CHECK(kind IN ('snapshot','index','pack')), object_id TEXT NOT NULL CHECK(length(object_id)=64 AND object_id NOT GLOB '*[^0-9a-f]*'), version_id TEXT NOT NULL CHECK(length(version_id) BETWEEN 1 AND 128 AND version_id NOT GLOB '*[^A-Za-z0-9._-]*' AND version_id<>'null'), mode TEXT NOT NULL CHECK(mode='COMPLIANCE'), retain_until INTEGER NOT NULL CHECK(retain_until>=0), PRIMARY KEY(operation_id, position)) STRICT, WITHOUT ROWID",
    ),
];

fn provisioned(ledger: &mut FixtureJournal, site: &str) {
    let intent = ProvisionIntent {
        operation_id: id(&format!("prov_{site}")),
        idempotency_key: id(&format!("prov_key_{site}")),
        grant_id: id(&format!("prov_grant_{site}")),
        nonce: id(&format!("prov_nonce_{site}")),
        plan_digest: digest('a'),
        grant_digest: digest('b'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: SiteId::try_from(site.to_owned()).unwrap(),
        hostname: Hostname::try_from(format!("{site}.example.test")).unwrap(),
        expires_at: time(10000),
    };
    ledger.record_provision(&intent, time(900)).unwrap();
    for step in ProvisionStep::ALL {
        ledger.begin_step(&intent.operation_id, step, "r").unwrap();
        ledger
            .finish_step(&intent.operation_id, step, true)
            .unwrap();
    }
}

fn running(ledger: &mut FixtureJournal, n: u32) -> CaptureIntent {
    let intent = CaptureIntent {
        operation_id: id(&format!("cap_{n}")),
        idempotency_key: id(&format!("cap_key_{n}")),
        grant_id: id(&format!("cap_grant_{n}")),
        nonce: id(&format!("cap_nonce_{n}")),
        plan_digest: digest('c'),
        grant_digest: digest('d'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: SiteId::try_from("blog9".to_owned()).unwrap(),
        expires_at: time(10000),
    };
    ledger
        .record_capture(
            &intent,
            time(1000 + u64::from(n)),
            CaptureMethod::SiteFilesDbV1,
            Some(30),
            &digest('e'),
        )
        .unwrap();
    intent
}

fn object(kind: RetainedObjectKind, id: &str, version: &str, until: i64) -> ObjectRetention {
    ObjectRetention {
        kind,
        object_id: id.to_owned(),
        version_id: version.to_owned(),
        retain_until: until,
    }
}

fn evidence() -> RetentionEvidence {
    RetentionEvidence {
        before_days: 30,
        after_days: 30,
        objects: vec![
            object(
                RetainedObjectKind::Snapshot,
                SNAPSHOT,
                "76b01aea-db7c-4b38-b41d-3c031085d108",
                1_000_000,
            ),
            object(
                RetainedObjectKind::Index,
                INDEX,
                "a35c148c-0e42-4b7a-8dec-a9532b0c4471",
                1_000_001,
            ),
            object(
                RetainedObjectKind::Pack,
                PACK,
                "3HL4kqtJlcpXroDTDmJ+rmSpXd3dIbrHY",
                999_999,
            ),
        ],
    }
}

fn succeed(
    ledger: &mut FixtureJournal,
    intent: &CaptureIntent,
    retention: Option<&RetentionEvidence>,
) -> Result<rustiron_journal::Capture, JournalError> {
    ledger.finish_capture_succeeded(
        &intent.operation_id,
        time(1100),
        CaptureSuccess {
            snapshot_id: SNAPSHOT,
            extent: Some((3, 9)),
            manifest: None,
            consistency: Some(&CaptureConsistency::Matched),
            retention,
        },
    )
}

#[test]
fn a_fresh_journal_has_the_exact_v18_evidence_tables() {
    let state = State::new();
    drop(state.init());
    let c = rusqlite::Connection::open(state.0.join("fixture-journal.sqlite")).unwrap();
    let version: i64 = c
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(version, 44);
    for (name, ddl) in DDL {
        let sql: String = c
            .query_row("SELECT sql FROM sqlite_master WHERE name=?1", [name], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(sql, ddl, "{name}");
    }
}

/// The evidence is written in the success transaction and read back
/// unchanged after a reopen; the observation carries its summary only.
#[test]
fn a_succeeded_capture_keeps_its_retention_evidence() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let intent = running(&mut ledger, 1);
    // A version id with `+` is not in the accepted character set.
    assert_eq!(
        succeed(&mut ledger, &intent, Some(&evidence())).err(),
        Some(JournalError::Conflict)
    );
    let mut good = evidence();
    good.objects[2].version_id = "3HL4kqtJlcpXroDTDmJ.rmSpXd3dIbrHY".to_owned();
    let done = succeed(&mut ledger, &intent, Some(&good)).unwrap();
    assert_eq!(done.state, CaptureState::Succeeded);
    assert_eq!(done.retention_evidence.as_ref(), Some(&good));
    assert_eq!(done.refusal, None);
    drop(ledger);
    let reopened = state.open().unwrap();
    assert_eq!(
        reopened
            .capture_status(&intent.operation_id)
            .unwrap()
            .unwrap()
            .retention_evidence,
        Some(good)
    );
    drop(reopened);
    let seen =
        FixtureJournal::observe(&state.0, &id("host_fixture"), &id("epoch_fixture")).unwrap();
    let observed = seen.captures[0].retention.as_ref().unwrap();
    assert_eq!(
        (observed.before_days, observed.after_days, observed.objects),
        (30, 30, 3)
    );
    assert_eq!(
        (observed.earliest_retain_until, observed.latest_retain_until),
        (999_999, 1_000_001)
    );
    assert_eq!(seen.captures[0].refusal, None);
}

#[test]
fn evidence_that_does_not_name_the_snapshot_once_is_refused() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let intent = running(&mut ledger, 1);
    let mut cases = Vec::new();
    let mut other = evidence();
    other.objects[0].object_id = INDEX.to_owned();
    cases.push(("snapshot object names another id", other));
    let mut two = evidence();
    two.objects[1].kind = RetainedObjectKind::Snapshot;
    two.objects[1].object_id = SNAPSHOT.to_owned();
    cases.push(("two snapshot objects", two));
    let mut none = evidence();
    none.objects.remove(0);
    cases.push(("no snapshot object", none));
    let mut empty = evidence();
    empty.objects.clear();
    cases.push(("no object", empty));
    let mut null = evidence();
    null.objects[1].version_id = "null".to_owned();
    cases.push(("unversioned object", null));
    let mut long = evidence();
    long.objects[1].version_id = "v".repeat(129);
    cases.push(("version id too long", long));
    let mut upper = evidence();
    upper.objects[1].object_id = INDEX.to_uppercase();
    cases.push(("upper-case id", upper));
    let mut days = evidence();
    days.before_days = 0;
    cases.push(("zero days", days));
    let mut negative = evidence();
    negative.objects[1].retain_until = -1;
    cases.push(("negative retain-until", negative));
    let mut many = evidence();
    many.objects = (0..1025)
        .map(|n| {
            if n == 0 {
                evidence().objects[0].clone()
            } else {
                object(RetainedObjectKind::Pack, &format!("{n:064x}"), "v1", 1)
            }
        })
        .collect();
    cases.push(("more than 1024 objects", many));
    for (name, case) in cases {
        assert_eq!(
            succeed(&mut ledger, &intent, Some(&case)).err(),
            Some(JournalError::Conflict),
            "{name}"
        );
    }
    // Evidence on a failure is refused; the capture is still running.
    assert_eq!(
        ledger
            .capture_status(&intent.operation_id)
            .unwrap()
            .unwrap()
            .state,
        CaptureState::Running
    );
    // 1024 objects fit.
    let mut full = evidence();
    full.objects = (0..1024)
        .map(|n| {
            if n == 0 {
                evidence().objects[0].clone()
            } else {
                object(
                    RetainedObjectKind::Pack,
                    &format!("{n:064x}"),
                    "76b01aea-db7c-4b38-b41d-3c031085d108",
                    1,
                )
            }
        })
        .collect();
    let done = succeed(&mut ledger, &intent, Some(&full)).unwrap();
    assert_eq!(done.retention_evidence.unwrap().objects.len(), 1024);
}

#[test]
fn a_success_without_evidence_records_none() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let intent = running(&mut ledger, 1);
    let done = succeed(&mut ledger, &intent, None).unwrap();
    assert_eq!(done.retention_evidence, None);
    let seen =
        FixtureJournal::observe(&state.0, &id("host_fixture"), &id("epoch_fixture")).unwrap();
    assert_eq!(seen.captures[0].retention, None);
}

/// A refused capture keeps its bounded code; the code is never stored on a
/// success, and an unbounded code is refused before anything is written.
#[test]
fn a_refused_capture_keeps_its_refusal_code() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let intent = running(&mut ledger, 1);
    for bad in ["", "lower", "WITH SPACE", "DASH-ED", &"A".repeat(65)] {
        assert_eq!(
            ledger
                .refuse_capture(&intent.operation_id, time(1100), bad)
                .err(),
            Some(JournalError::Conflict),
            "{bad:?}"
        );
    }
    let refused = ledger
        .refuse_capture(
            &intent.operation_id,
            time(1100),
            "RETENTION_LOCK_UNVERIFIED",
        )
        .unwrap();
    assert_eq!(refused.state, CaptureState::Failed);
    assert_eq!(refused.snapshot_id, None);
    assert_eq!(
        refused.refusal.as_deref(),
        Some("RETENTION_LOCK_UNVERIFIED")
    );
    assert_eq!(refused.retention_evidence, None);
    // A finished capture never changes.
    assert_eq!(
        ledger
            .refuse_capture(&intent.operation_id, time(1101), "OTHER")
            .err(),
        Some(JournalError::Conflict)
    );
    drop(ledger);
    let seen =
        FixtureJournal::observe(&state.0, &id("host_fixture"), &id("epoch_fixture")).unwrap();
    assert_eq!(
        seen.captures[0].refusal.as_deref(),
        Some("RETENTION_LOCK_UNVERIFIED")
    );
    // `finish_capture` without a code still records a failure with none.
    let mut ledger = state.open().unwrap();
    let second = running(&mut ledger, 2);
    let failed = ledger
        .finish_capture(&second.operation_id, None, time(1200), None, None)
        .unwrap();
    assert_eq!(failed.refusal, None);
}

#[test]
fn evidence_rows_that_contradict_their_capture_are_refused_on_open() {
    let cases = [
        // A refusal code on a succeeded capture.
        "INSERT INTO capture_refusals VALUES ('cap_1','STEP_FAILED');",
        // Fewer object rows than the check row counts.
        "DELETE FROM capture_object_retention WHERE position=2;",
        // The snapshot object names another snapshot.
        "UPDATE capture_object_retention SET object_id='1b2c3d4e5f60718293a4b5c6d7e8f9001b2c3d4e5f60718293a4b5c6d7e8f900' WHERE kind='snapshot';",
        // Evidence on a failed capture.
        "UPDATE captures SET state='failed', snapshot_id=NULL WHERE operation_id='cap_1';",
        // A refusal beside an unclaimed snapshot.
        "INSERT INTO capture_refusals VALUES ('cap_2','STEP_FAILED'); INSERT INTO capture_unclaimed VALUES ('cap_2','a50c8b74e3c0f1d2a50c8b74e3c0f1d2a50c8b74e3c0f1d2a50c8b74e3c0f1d2');",
        // Positions with a gap.
        "UPDATE capture_object_retention SET position=7 WHERE position=2;",
    ];
    for tamper in cases {
        let state = State::new();
        let mut ledger = state.init();
        provisioned(&mut ledger, "blog9");
        let intent = running(&mut ledger, 1);
        let mut good = evidence();
        good.objects[2].version_id = "v2".to_owned();
        succeed(&mut ledger, &intent, Some(&good)).unwrap();
        let second = running(&mut ledger, 2);
        ledger
            .finish_capture(&second.operation_id, None, time(1200), None, None)
            .unwrap();
        drop(ledger);
        assert!(state.open().is_ok());
        state.sql(&format!("PRAGMA foreign_keys=OFF; {tamper}"));
        assert_eq!(
            state.open().err(),
            Some(JournalError::Unavailable),
            "{tamper}"
        );
    }
}

/// A v17 journal (the W375 lab journal) migrates in place to v18. Every
/// capture row reads back unchanged and old rows carry no evidence and no
/// refusal code. A second migration is refused.
#[test]
fn a_v17_journal_migrates_to_v18_with_captures_unchanged() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let finished = running(&mut ledger, 1);
    ledger
        .finish_capture_labelled(
            &finished.operation_id,
            Some(SNAPSHOT),
            time(1003),
            Some((3, 9)),
            None,
            Some(&CaptureConsistency::Matched),
        )
        .unwrap();
    let failed = running(&mut ledger, 2);
    ledger
        .finish_capture(&failed.operation_id, None, time(1004), None, None)
        .unwrap();
    let left = running(&mut ledger, 3);
    let before: Vec<_> = [&finished, &failed, &left]
        .iter()
        .map(|i| ledger.capture_status(&i.operation_id).unwrap().unwrap())
        .collect();
    let count = ledger.admission_count().unwrap();
    drop(ledger);
    state.sql(TO_V17);
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let mut migrated =
        FixtureJournal::migrate(&state.0, id("host_fixture"), id("epoch_fixture")).unwrap();
    assert_eq!(migrated.admission_count().unwrap(), count);
    for capture in &before {
        let after = migrated
            .capture_status(&capture.intent.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(&after, capture);
        assert_eq!(after.retention_evidence, None);
        assert_eq!(after.refusal, None);
    }
    // The migrated running capture can now record evidence.
    let mut good = evidence();
    good.objects[2].version_id = "v2".to_owned();
    let done = succeed(&mut migrated, &left, Some(&good)).unwrap();
    assert_eq!(done.retention_evidence, Some(good));
    drop(migrated);
    assert!(FixtureJournal::migrate(&state.0, id("host_fixture"), id("epoch_fixture")).is_err());
}
