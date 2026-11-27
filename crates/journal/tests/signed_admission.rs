//! W396 (journal v20, D-045): each admission keeps the exact canonical plan
//! and grant bytes with the verified signer facts, in the same transaction
//! as its intent. Real SQLite; no host effects.
use rustiron_contracts::{
    CanonicalObject,
    approval::{Hostname, Sha256Digest, SiteId},
};
use rustiron_journal::{
    CaptureIntent, CaptureMethod, FixtureJournal, JournalError, ProvisionIntent, ProvisionStep,
    SignedAdmission,
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
mod support;
use support::*;

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct State(PathBuf);
impl State {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ri-signed-{}-{}",
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
    fn observe(&self) -> rustiron_journal::Observation {
        FixtureJournal::observe(&self.0, &id("host_fixture"), &id("epoch_fixture")).unwrap()
    }
}
impl Drop for State {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

const PLAN: &str = r#"{"plan_id":"plan_w396","schema_version":1,"site_id":"blog9"}"#;
const GRANT: &str = r#"{"grant_id":"grant_w396","issuer":"lab_agent","nonce":"nonce_w396","signer_policy_epoch":"policy_3"}"#;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn plan_digest(plan: &str) -> Sha256Digest {
    let object = CanonicalObject::decode(plan.as_bytes()).unwrap();
    Sha256Digest::try_from(hex(&object.plan_domain_digest())).unwrap()
}
fn grant_digest(grant: &str) -> Sha256Digest {
    Sha256Digest::try_from(hex(&Sha256::digest(grant.as_bytes()))).unwrap()
}
fn signed(plan: &str, grant: &str) -> SignedAdmission {
    SignedAdmission {
        plan: plan.as_bytes().to_vec(),
        grant: grant.as_bytes().to_vec(),
        issuer: id("lab_agent"),
        signer_policy_epoch: id("policy_3"),
    }
}
fn signed_intent(number: u32) -> rustiron_journal::Intent {
    let mut intent = intent(number);
    intent.plan_digest = plan_digest(PLAN);
    intent.grant_digest = grant_digest(GRANT);
    intent
}
fn provision(ledger: &mut FixtureJournal, site: &str) -> ProvisionIntent {
    let intent = ProvisionIntent {
        operation_id: id(&format!("prov_{site}")),
        idempotency_key: id(&format!("prov_key_{site}")),
        grant_id: id(&format!("prov_grant_{site}")),
        nonce: id(&format!("prov_nonce_{site}")),
        plan_digest: plan_digest(PLAN),
        grant_digest: grant_digest(GRANT),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: SiteId::try_from(site.to_owned()).unwrap(),
        hostname: Hostname::try_from(format!("{site}.example.test")).unwrap(),
        expires_at: time(10000),
    };
    ledger.stage_signed(signed(PLAN, GRANT));
    ledger.record_provision(&intent, time(900)).unwrap();
    for step in ProvisionStep::ALL {
        ledger.begin_step(&intent.operation_id, step, "r").unwrap();
        ledger
            .finish_step(&intent.operation_id, step, true)
            .unwrap();
    }
    intent
}
fn capture(n: u32, site: &str) -> CaptureIntent {
    CaptureIntent {
        operation_id: id(&format!("cap_{n}")),
        idempotency_key: id(&format!("cap_key_{n}")),
        grant_id: id(&format!("cap_grant_{n}")),
        nonce: id(&format!("cap_nonce_{n}")),
        plan_digest: plan_digest(PLAN),
        grant_digest: grant_digest(GRANT),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: SiteId::try_from(site.to_owned()).unwrap(),
        expires_at: time(10000),
    }
}

#[test]
fn a_fresh_journal_is_v20_with_the_exact_signed_tables() {
    let state = State::new();
    drop(state.init());
    let c = rusqlite::Connection::open(state.0.join("fixture-journal.sqlite")).unwrap();
    let version: i64 = c
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(version, 45);
    for (name, sql) in DDL_V20 {
        let actual: String = c
            .query_row("SELECT sql FROM sqlite_master WHERE name=?1", [name], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(actual, sql);
    }
}

#[test]
fn a_new_intent_keeps_its_exact_signed_bytes_and_signer_facts() {
    let state = State::new();
    let mut ledger = state.init();
    ledger.stage_signed(signed(PLAN, GRANT));
    ledger.record_intent(&signed_intent(1), time(1000)).unwrap();
    drop(ledger);
    let seen = state.observe();
    assert_eq!(seen.admissions.len(), 1);
    let admission = &seen.admissions[0];
    assert_eq!(admission.operation_id, "operation_1");
    assert_eq!(admission.source, "operation");
    assert_eq!(admission.plan_digest, plan_digest(PLAN).as_str());
    assert_eq!(admission.grant_digest, grant_digest(GRANT).as_str());
    let stored = admission.signed.as_ref().unwrap();
    assert_eq!(stored.plan.as_deref(), Some(PLAN));
    assert_eq!(stored.grant.as_deref(), Some(GRANT));
    assert_eq!(stored.plan_bytes, PLAN.len() as u64);
    assert_eq!(stored.grant_bytes, GRANT.len() as u64);
    assert_eq!(stored.plan_sha256, hex(&Sha256::digest(PLAN.as_bytes())));
    assert_eq!(stored.grant_sha256, grant_digest(GRANT).as_str());
    assert_eq!(
        (stored.issuer.as_str(), stored.signer_policy_epoch.as_str()),
        ("lab_agent", "policy_3")
    );
    assert_eq!(stored.verification, "sshsig_verified");
    // Reopened by the writer: the stored rows pass the open checks.
    state.open().unwrap();
}

#[test]
fn an_admission_without_staged_bytes_reads_as_not_recorded() {
    let state = State::new();
    let mut ledger = state.init();
    ledger.record_intent(&intent(1), time(1000)).unwrap();
    drop(ledger);
    let seen = state.observe();
    assert_eq!(seen.admissions.len(), 1);
    assert_eq!(seen.admissions[0].signed, None);
}

#[test]
fn bytes_that_do_not_hash_to_the_intent_digests_are_refused_and_nothing_is_recorded() {
    let state = State::new();
    let mut ledger = state.init();
    let other_plan = r#"{"plan_id":"plan_other","schema_version":1}"#;
    ledger.stage_signed(signed(other_plan, GRANT));
    assert_eq!(
        ledger.record_intent(&signed_intent(1), time(1000)),
        Err(JournalError::Conflict)
    );
    let other_grant = r#"{"grant_id":"grant_other"}"#;
    ledger.stage_signed(signed(PLAN, other_grant));
    assert_eq!(
        ledger.record_intent(&signed_intent(1), time(1000)),
        Err(JournalError::Conflict)
    );
    // Bytes that are not in canonical form are refused even with a matching digest.
    let spaced = r#"{ "plan_id":"plan_w396","schema_version":1,"site_id":"blog9"}"#;
    let mut intent = signed_intent(1);
    intent.plan_digest = plan_digest(PLAN);
    ledger.stage_signed(signed(spaced, GRANT));
    assert_eq!(
        ledger.record_intent(&intent, time(1000)),
        Err(JournalError::Conflict)
    );
    drop(ledger);
    assert!(state.observe().admissions.is_empty());
}

#[test]
fn a_staged_admission_is_taken_by_one_record_call_only() {
    let state = State::new();
    let mut ledger = state.init();
    ledger.stage_signed(signed(PLAN, GRANT));
    let mut wrong_host = signed_intent(1);
    wrong_host.host_id = id("host_other");
    assert_eq!(
        ledger.record_intent(&wrong_host, time(1000)),
        Err(JournalError::Conflict)
    );
    ledger.record_intent(&signed_intent(1), time(1000)).unwrap();
    drop(ledger);
    assert_eq!(state.observe().admissions[0].signed, None);
}

#[test]
fn runs_with_the_same_plan_and_grant_share_one_stored_copy_of_each() {
    let state = State::new();
    let mut ledger = state.init();
    provision(&mut ledger, "blog9");
    for n in 1..=3 {
        ledger.stage_signed(signed(PLAN, GRANT));
        ledger
            .record_capture(
                &capture(n, "blog9"),
                time(1000 + u64::from(n)),
                CaptureMethod::SiteFilesDbV1,
                Some(30),
                &digest('e'),
            )
            .unwrap();
        ledger
            .finish_capture(&id(&format!("cap_{n}")), None, time(1100), None, None)
            .unwrap();
    }
    drop(ledger);
    let c = rusqlite::Connection::open(state.0.join("fixture-journal.sqlite")).unwrap();
    let objects: i64 = c
        .query_row("SELECT count(*) FROM signed_objects", [], |r| r.get(0))
        .unwrap();
    let links: i64 = c
        .query_row("SELECT count(*) FROM admission_signatures", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!((objects, links), (2, 4));
    let seen = state.observe();
    let sources: Vec<_> = seen
        .admissions
        .iter()
        .map(|a| {
            (
                a.source.as_str(),
                a.signed.as_ref().unwrap().plan.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        sources,
        [
            ("capture", Some(PLAN)),
            ("capture", Some(PLAN)),
            ("capture", Some(PLAN)),
            ("provision", Some(PLAN)),
        ]
    );
}

#[test]
fn an_object_over_the_bound_keeps_its_digest_and_length_only() {
    let state = State::new();
    let mut ledger = state.init();
    let note = "x".repeat(rustiron_journal::MAX_OBJECT_BYTES);
    let plan = format!(r#"{{"note":"{note}","plan_id":"plan_big"}}"#);
    let mut intent = intent(1);
    intent.plan_digest = plan_digest(&plan);
    intent.grant_digest = grant_digest(GRANT);
    ledger.stage_signed(signed(&plan, GRANT));
    ledger.record_intent(&intent, time(1000)).unwrap();
    drop(ledger);
    let stored = state.observe().admissions[0].signed.clone().unwrap();
    assert_eq!(stored.plan, None);
    assert_eq!(stored.plan_bytes, plan.len() as u64);
    assert_eq!(stored.plan_sha256, hex(&Sha256::digest(plan.as_bytes())));
    assert_eq!(stored.grant.as_deref(), Some(GRANT));
    state.open().unwrap();
}

#[test]
fn stored_rows_that_contradict_their_intent_are_refused_on_open() {
    for tamper in [
        // A kept plan that no longer hashes to its key.
        r#"PRAGMA foreign_keys=OFF; UPDATE signed_objects SET canonical='{"plan_id":"plan_x","schema_version":1,"site_id":"blog9"}' WHERE canonical LIKE '%plan_w396%';"#,
        // A link row whose grant digest is not the intent's.
        "UPDATE admission_signatures SET grant_sha256='0000000000000000000000000000000000000000000000000000000000000000';",
        // A link row for no recorded intent.
        "UPDATE admission_signatures SET operation_id='operation_9';",
        // A stored object that no link row names.
        r#"INSERT INTO signed_objects VALUES('44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a','{}');"#,
        // A recorded length that is not the stored length.
        "UPDATE admission_signatures SET plan_bytes=plan_bytes+1;",
    ] {
        let state = State::new();
        let mut ledger = state.init();
        ledger.stage_signed(signed(PLAN, GRANT));
        ledger.record_intent(&signed_intent(1), time(1000)).unwrap();
        drop(ledger);
        state.sql(tamper);
        assert_eq!(
            state.open().err(),
            Some(JournalError::Unavailable),
            "{tamper}"
        );
    }
}

#[test]
fn a_v18_journal_migrates_through_v19_to_v20_and_reads_as_not_recorded() {
    migrates_to_v20(TO_V18, 18);
}

#[test]
fn a_v19_journal_migrates_to_v20_and_reads_as_not_recorded() {
    migrates_to_v20(TO_V19, 19);
}

/// A journal of `version` refuses to open, migrates once through v20 (to the
/// current v21) with every
/// v19 (W395) and v20 table, keeps its admissions, and reads them as not
/// recorded. A second migration is refused.
fn migrates_to_v20(downgrade: &str, version: i64) {
    let state = State::new();
    let mut ledger = state.init();
    ledger.record_intent(&intent(1), time(1000)).unwrap();
    let count = ledger.admission_count().unwrap();
    drop(ledger);
    state.sql(downgrade);
    let c = rusqlite::Connection::open(state.0.join("fixture-journal.sqlite")).unwrap();
    let read = |c: &rusqlite::Connection| -> (i64, i64) {
        let version = c
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        let tables = c
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name IN \
                 ('page_cache_recipes','signed_objects','admission_signatures')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        (version, tables)
    };
    assert_eq!(read(&c), (version, if version == 19 { 1 } else { 0 }));
    drop(c);
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let migrated =
        FixtureJournal::migrate(&state.0, id("host_fixture"), id("epoch_fixture")).unwrap();
    assert_eq!(migrated.admission_count().unwrap(), count);
    drop(migrated);
    let c = rusqlite::Connection::open(state.0.join("fixture-journal.sqlite")).unwrap();
    assert_eq!(read(&c), (45, 3));
    for (name, sql) in DDL_V20 {
        let actual: String = c
            .query_row("SELECT sql FROM sqlite_master WHERE name=?1", [name], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(actual, sql);
    }
    drop(c);
    let seen = state.observe();
    assert_eq!(seen.admissions.len(), 1);
    assert_eq!(seen.admissions[0].signed, None);
    state.open().unwrap();
    assert_eq!(
        FixtureJournal::migrate(&state.0, id("host_fixture"), id("epoch_fixture")).err(),
        Some(JournalError::Unavailable)
    );
}
