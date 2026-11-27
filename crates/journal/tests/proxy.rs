//! W572 (journal v40, D-095): proxy site provisions. The signed routes are
//! stored with the reservation and replay exactly; the steps are the
//! provision's. Real SQLite; no host effects.
use rustiron_contracts::approval::{Hostname, ProxyRoute, SiteId};
use rustiron_journal::{
    Admitted, DeleteIntent, FixtureJournal, JournalError, ProvisionIntent, ProvisionState,
    ProvisionStep, ProxyFacts, StepState,
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
            "ri-proxy-{}-{}",
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

fn route(prefix: &str, port: u16) -> ProxyRoute {
    ProxyRoute {
        prefix: prefix.to_owned(),
        port,
    }
}

fn routes() -> ProxyFacts {
    ProxyFacts {
        routes: vec![
            route("/", 3100),
            route("/api/", 3101),
            route("/downloads/", 3101),
        ],
        websockets: vec![route("/ws/", 3100)],
    }
}

fn finish(ledger: &mut FixtureJournal, intent: &ProvisionIntent) {
    for step in ProvisionStep::ALL {
        ledger
            .begin_step(&intent.operation_id, step, "proxy")
            .unwrap();
        ledger
            .finish_step(&intent.operation_id, step, true)
            .unwrap();
    }
}

#[test]
fn a_proxy_provision_records_its_routes_and_replays_exactly() {
    let state = State::new();
    let mut ledger = state.init();
    let intent = site("ytproxy", "proxy_op");
    let facts = routes();
    assert_eq!(facts.ports(), [3100, 3101]);
    let recorded = ledger
        .record_proxy_provision(&intent, &facts, time(1000))
        .unwrap();
    assert!(matches!(recorded, Admitted::New(_)));
    assert_eq!(
        ledger.proxy_facts(&intent.operation_id).unwrap(),
        Some(facts.clone())
    );
    assert!(matches!(
        ledger.record_proxy_provision(&intent, &facts, time(1001)),
        Ok(Admitted::Existing(_))
    ));
    // The same key with other routes, or as a recipe provision, conflicts.
    let mut other = facts.clone();
    other.routes[1].port = 3102;
    assert_eq!(
        ledger
            .record_proxy_provision(&intent, &other, time(1001))
            .err(),
        Some(JournalError::Conflict)
    );
    let mut other = facts.clone();
    other.websockets.clear();
    assert_eq!(
        ledger
            .record_proxy_provision(&intent, &other, time(1001))
            .err(),
        Some(JournalError::Conflict)
    );
    assert_eq!(
        ledger.record_provision(&intent, time(1001)).err(),
        Some(JournalError::Conflict)
    );
    // A recipe provision has no routes.
    finish(&mut ledger, &intent);
    let plain = site("blog1", "plain_op");
    ledger.record_provision(&plain, time(1002)).unwrap();
    assert_eq!(ledger.proxy_facts(&plain.operation_id).unwrap(), None);
    finish(&mut ledger, &plain);
    let records = FixtureJournal::records_as_process_owner(
        &state.0,
        &id("host_fixture"),
        &id("epoch_fixture"),
        &intent.operation_id,
        None,
    )
    .unwrap();
    assert_eq!(records.proxy, Some(facts));
    // W575: the observation lists a proxy site's distinct ports only.
    let observed =
        FixtureJournal::observe(&state.0, &id("host_fixture"), &id("epoch_fixture")).unwrap();
    let ports: Vec<_> = observed
        .provisions
        .iter()
        .map(|site| (site.site_id.as_str(), site.proxy_ports.clone()))
        .collect();
    assert_eq!(ports, [("ytproxy", vec![3100, 3101]), ("blog1", vec![])]);
    assert_eq!(
        records.provision.map(|provision| provision.state),
        Some(ProvisionState::Succeeded)
    );
    drop(ledger);
    state.open().unwrap();
}

#[test]
fn routes_outside_the_contract_are_refused_before_any_record() {
    let state = State::new();
    let mut ledger = state.init();
    let before = ledger.admission_count().unwrap();
    let intent = site("ytproxy", "proxy_op");
    let mut bad = Vec::new();
    let mut facts = routes();
    facts.routes.remove(0);
    bad.push(facts);
    let mut facts = routes();
    facts.routes[1].port = 3306;
    bad.push(facts);
    let mut facts = routes();
    facts.routes[1].prefix = "/api".to_owned();
    bad.push(facts);
    let mut facts = routes();
    facts.websockets.push(route("/ws/", 3101));
    bad.push(facts);
    let mut facts = routes();
    facts.routes = (0..9).map(|n| route(&format!("/p{n}/"), 3000)).collect();
    facts.routes[0].prefix = "/".to_owned();
    bad.push(facts);
    for facts in bad {
        assert_eq!(
            ledger
                .record_proxy_provision(&intent, &facts, time(1000))
                .err(),
            Some(JournalError::Conflict),
            "{facts:?}"
        );
    }
    assert_eq!(ledger.admission_count().unwrap(), before);
    // A taken hostname is refused as for any provision.
    ledger
        .record_provision(&site("ytproxy", "plain_op"), time(1000))
        .unwrap();
    let mut other = site("ytproxy", "proxy_op");
    other.site_id = SiteId::try_from("other1".to_owned()).unwrap();
    assert_eq!(
        ledger
            .record_proxy_provision(&other, &routes(), time(1001))
            .err(),
        Some(JournalError::Consumed)
    );
}

#[test]
fn a_v39_journal_migrates_and_inconsistent_routes_are_refused() {
    let state = State::new();
    let mut ledger = state.init();
    let plain = site("blog1", "plain_op");
    ledger.record_provision(&plain, time(1000)).unwrap();
    finish(&mut ledger, &plain);
    drop(ledger);
    state.sql(&format!(
        "DROP TABLE caddy_generations; DROP TABLE app_fullstack_specs; DROP TABLE credential_rotations; DROP TABLE app_lifecycles; DROP TABLE app_release_steps; DROP TABLE app_releases; DROP TABLE apps; DROP TABLE static_ejections; DROP TABLE proxy_routes; {TO_V40_DELETIONS} PRAGMA user_version=39;"
    ));
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let mut ledger = state.migrate().unwrap();
    let intent = site("ytproxy", "proxy_op");
    ledger
        .record_proxy_provision(&intent, &routes(), time(1001))
        .unwrap();
    drop(ledger);
    state.open().unwrap();
    for (tamper, undo) in [
        // A gap in the positions.
        (
            "UPDATE proxy_routes SET position=5 WHERE kind='route' AND position=2;",
            "UPDATE proxy_routes SET position=2 WHERE kind='route' AND position=5;",
        ),
        // No `/` route.
        (
            "UPDATE proxy_routes SET prefix='/x/' WHERE kind='route' AND position=0;",
            "UPDATE proxy_routes SET prefix='/' WHERE kind='route' AND position=0;",
        ),
        // A prefix outside the grammar that the table check admits.
        (
            "UPDATE proxy_routes SET prefix='/../' WHERE kind='websocket';",
            "UPDATE proxy_routes SET prefix='/ws/' WHERE kind='websocket';",
        ),
        // Routes of no provision.
        (
            "INSERT INTO proxy_routes VALUES('nobody','route',0,'/',3000);",
            "DELETE FROM proxy_routes WHERE operation_id='nobody';",
        ),
    ] {
        state.sql(&format!("PRAGMA foreign_keys=OFF; {tamper}"));
        assert_eq!(
            state.open().err(),
            Some(JournalError::Unavailable),
            "{tamper}"
        );
        state.sql(&format!("PRAGMA foreign_keys=OFF; {undo}"));
        state.open().unwrap();
    }
}

fn deletion(site: &str, number: u32, capture: Option<&str>) -> DeleteIntent {
    DeleteIntent {
        operation_id: id(&format!("delete_op_{number}")),
        idempotency_key: id(&format!("delete_key_{number}")),
        grant_id: id(&format!("delete_grant_{number}")),
        nonce: id(&format!("delete_nonce_{number}")),
        plan_digest: digest('a'),
        grant_digest: digest('b'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: SiteId::try_from(site.to_owned()).unwrap(),
        hostname: Hostname::try_from(format!("{site}.example.test")).unwrap(),
        capture_operation_id: capture.map(id),
        expires_at: time(10000),
    }
}

/// W576 (journal v41, D-095): a proxy site is deleted without a capture;
/// any other site still needs one, and a proxy site cannot name one.
#[test]
fn a_proxy_site_is_deleted_without_a_capture_and_only_it() {
    let state = State::new();
    let mut ledger = state.init();
    let proxy = site("ytproxy", "proxy_op");
    ledger
        .record_proxy_provision(&proxy, &routes(), time(1000))
        .unwrap();
    finish(&mut ledger, &proxy);
    let plain = site("blog1", "plain_op");
    ledger.record_provision(&plain, time(1001)).unwrap();
    finish(&mut ledger, &plain);
    let before = ledger.admission_count().unwrap();
    // A recipe site without a capture, and a proxy site naming one.
    for intent in [
        deletion("blog1", 1, None),
        deletion("ytproxy", 2, Some("cap_1")),
    ] {
        assert_eq!(
            ledger.record_deletion(&intent, time(1100)).err(),
            Some(JournalError::Consumed),
            "{}",
            intent.site_id.as_str()
        );
    }
    assert_eq!(ledger.admission_count().unwrap(), before);
    let intent = deletion("ytproxy", 3, None);
    let Admitted::New(recorded) = ledger.record_deletion(&intent, time(1100)).unwrap() else {
        panic!("expected a new deletion");
    };
    assert_eq!(recorded.capture_operation_id, None);
    assert_eq!(recorded.state, StepState::Intent);
    assert!(matches!(
        ledger.record_deletion(&intent, time(1101)),
        Ok(Admitted::Existing(_))
    ));
    let failed = ledger.finish_deletion(&intent.operation_id, false).unwrap();
    assert_eq!(failed.state, StepState::Failed);
    // The retry after a failed removal names no capture either.
    let retry = deletion("ytproxy", 4, None);
    assert!(matches!(
        ledger.record_deletion(&retry, time(1102)),
        Ok(Admitted::New(_))
    ));
    ledger.finish_deletion(&retry.operation_id, true).unwrap();
    drop(ledger);
    state.open().unwrap();
    // A deletion without a capture of a site that is not a proxy site is
    // refused on open.
    state.sql(
        "PRAGMA foreign_keys=OFF; UPDATE provisions SET state='deleted' WHERE operation_id='plain_op'; \
         INSERT INTO deletions VALUES('delete_op_9','plain_op',NULL,'delete_key_9','delete_grant_9','delete_nonce_9','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',10000,'done');",
    );
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
}

/// W576: a v40 journal's deletions are rebuilt with the nullable capture,
/// rows kept.
#[test]
fn a_v40_journal_migrates_with_its_deletions() {
    let state = State::new();
    let mut ledger = state.init();
    let proxy = site("ytproxy", "proxy_op");
    ledger
        .record_proxy_provision(&proxy, &routes(), time(1000))
        .unwrap();
    finish(&mut ledger, &proxy);
    drop(ledger);
    state.sql(&format!(
        "DROP TABLE caddy_generations; DROP TABLE app_fullstack_specs; DROP TABLE credential_rotations; DROP TABLE app_lifecycles; DROP TABLE app_release_steps; DROP TABLE app_releases; DROP TABLE apps; DROP TABLE static_ejections; {TO_V40_DELETIONS} PRAGMA user_version=40;"
    ));
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let mut ledger = state.migrate().unwrap();
    ledger
        .record_deletion(&deletion("ytproxy", 1, None), time(1100))
        .unwrap();
    drop(ledger);
    state.open().unwrap();
}
