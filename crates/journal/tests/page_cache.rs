//! W368 (journal v15): a `config_activate` v2 records its page-cache opt-in
//! site with the intent, in one transaction. A site counts as opted in only
//! after that activation succeeded. Real SQLite; no host effects.
//!
//! W370 (journal v16): a `config_activate` v3 records its page-cache
//! opt-out site the same way. A site is opted in while its latest succeeded
//! page-cache change is an opt-in; a later opt-in re-enables it.
//!
//! W395 (journal v19, D-044): a change with the cache-on recipe
//! `litespeed_cache_793_cache_on_v1` adds one `page_cache_recipes` row in the
//! same transaction. The opt-out must name the recipe of the site's opt-in.
use rustiron_contracts::approval::{Hostname, SiteId};
use rustiron_journal::{
    Admitted, FixtureJournal, JournalError, ProvisionIntent, ProvisionStep, RecordedState,
};
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
            "ri-page-cache-{}-{}",
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

const DDL: &str = "CREATE TABLE page_cache_optins (operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id), site_id TEXT NOT NULL REFERENCES provisions(site_id), recipe TEXT NOT NULL CHECK(recipe='litespeed_cache_793_v1')) STRICT";
const DDL_OUT: &str = "CREATE TABLE page_cache_optouts (operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id), site_id TEXT NOT NULL REFERENCES provisions(site_id), recipe TEXT NOT NULL CHECK(recipe='litespeed_cache_793_v1')) STRICT";
const DDL_RECIPES: &str = "CREATE TABLE page_cache_recipes (operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id), recipe TEXT NOT NULL CHECK(recipe='litespeed_cache_793_cache_on_v1')) STRICT";
const RECIPE: &str = "litespeed_cache_793_v1";
const CACHE_ON: &str = "litespeed_cache_793_cache_on_v1";

fn site(name: &str) -> SiteId {
    SiteId::try_from(name.to_owned()).unwrap()
}

fn provisioned(ledger: &mut FixtureJournal, name: &str) {
    let intent = ProvisionIntent {
        operation_id: id(&format!("prov_{name}")),
        idempotency_key: id(&format!("prov_key_{name}")),
        grant_id: id(&format!("prov_grant_{name}")),
        nonce: id(&format!("prov_nonce_{name}")),
        plan_digest: digest('a'),
        grant_digest: digest('b'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: site(name),
        hostname: Hostname::try_from(format!("{name}.example.test")).unwrap(),
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

fn activation(n: u32) -> rustiron_journal::Intent {
    let mut intent = intent(n);
    intent.resource_id = id("ols_lab_listener");
    intent.predecessor_generation = id(&format!("generation_{n}"));
    intent.target_generation = id(&format!("generation_{}", n + 1));
    intent
}

#[test]
fn a_fresh_journal_has_the_exact_page_cache_tables() {
    let state = State::new();
    drop(state.init());
    let c = rusqlite::Connection::open(state.0.join("fixture-journal.sqlite")).unwrap();
    let version: i64 = c
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(version, 45);
    for (table, ddl) in [
        ("page_cache_optins", DDL),
        ("page_cache_optouts", DDL_OUT),
        ("page_cache_recipes", DDL_RECIPES),
    ] {
        let sql: String = c
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name=?1",
                [table],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(sql, ddl);
    }
}

#[test]
fn a_v14_journal_migrates_and_keeps_its_operations() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog1");
    let first = activation(1);
    ledger.record_intent(&first, time(1000)).unwrap();
    drop(ledger);
    state.sql(&format!("{TO_V16} DROP TABLE page_cache_optouts; DROP TABLE page_cache_optins; PRAGMA user_version=14;"));
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let mut migrated =
        FixtureJournal::migrate(&state.0, id("host_fixture"), id("epoch_fixture")).unwrap();
    assert!(matches!(
        migrated.record_intent(&first, time(1001)).unwrap(),
        Admitted::Existing(existing) if existing.state == RecordedState::Intent
    ));
    assert_eq!(migrated.admission_count().unwrap(), 2);
    assert!(migrated.page_cache_sites().unwrap().is_empty());
}

#[test]
fn an_opt_in_needs_a_succeeded_provision_and_counts_only_after_success() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog1");
    let blog1 = site("blog1");
    assert_eq!(
        ledger
            .record_page_cache_intent(&activation(1), &site("blog2"), RECIPE, time(1000))
            .err(),
        Some(JournalError::Conflict),
        "no provision"
    );
    assert_eq!(
        ledger
            .record_page_cache_intent(&activation(1), &blog1, "litespeed_cache_latest", time(1000))
            .err(),
        Some(JournalError::Conflict),
        "unknown recipe"
    );
    let first = activation(1);
    assert!(matches!(
        ledger
            .record_page_cache_intent(&first, &blog1, RECIPE, time(1000))
            .unwrap(),
        Admitted::New(_)
    ));
    assert!(matches!(
        ledger
            .record_page_cache_intent(&first, &blog1, RECIPE, time(1000))
            .unwrap(),
        Admitted::Existing(_)
    ));
    assert_eq!(
        ledger.page_cache_site(&first.operation_id).unwrap(),
        Some(blog1.clone())
    );
    assert_eq!(ledger.page_cache_site(&id("prov_blog1")).unwrap(), None);
    assert!(
        ledger.page_cache_sites().unwrap().is_empty(),
        "not yet succeeded"
    );
    ledger
        .record_observation(
            &first.operation_id,
            Some(&first.target_generation),
            Some(&first.target_digest),
        )
        .unwrap();
    assert_eq!(
        ledger.page_cache_sites().unwrap(),
        std::slice::from_ref(&blog1)
    );
    assert_eq!(
        ledger
            .record_page_cache_intent(&activation(2), &blog1, RECIPE, time(1002))
            .err(),
        Some(JournalError::Conflict),
        "a site opts in once"
    );
    drop(ledger);
    let reopened = state.open().unwrap();
    assert_eq!(reopened.page_cache_sites().unwrap(), vec![blog1]);
}

#[test]
fn a_compensated_opt_in_does_not_count_and_does_not_block_a_new_plan() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog1");
    let blog1 = site("blog1");
    let first = activation(1);
    ledger
        .record_page_cache_intent(&first, &blog1, RECIPE, time(1000))
        .unwrap();
    ledger.mark_effect_attempted(&first.operation_id).unwrap();
    ledger
        .record_observation(&first.operation_id, None, None)
        .unwrap();
    ledger
        .begin_compensation(&first.operation_id, time(1001))
        .unwrap();
    let compensated = ledger
        .record_observation(
            &first.operation_id,
            Some(&first.predecessor_generation),
            Some(&first.predecessor_digest),
        )
        .unwrap();
    assert_eq!(compensated.state, RecordedState::FailedCompensated);
    assert!(ledger.page_cache_sites().unwrap().is_empty());
    let mut second = activation(1);
    second.operation_id = id("operation_again");
    second.idempotency_key = id("retry_again");
    second.grant_id = id("grant_again");
    second.nonce = id("nonce_again");
    assert!(matches!(
        ledger
            .record_page_cache_intent(&second, &blog1, RECIPE, time(1002))
            .unwrap(),
        Admitted::New(_)
    ));
}

#[test]
fn opening_refuses_an_opt_in_row_without_its_operation_or_provision() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog1");
    drop(ledger);
    state.sql(
        "PRAGMA foreign_keys=OFF; INSERT INTO page_cache_optins VALUES('operation_9','blog1','litespeed_cache_793_v1');",
    );
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
}

fn other(n: u32, tag: &str) -> rustiron_journal::Intent {
    let mut intent = activation(n);
    intent.operation_id = id(&format!("operation_{tag}"));
    intent.idempotency_key = id(&format!("retry_{tag}"));
    intent.grant_id = id(&format!("grant_{tag}"));
    intent.nonce = id(&format!("nonce_{tag}"));
    intent
}

fn succeed(ledger: &mut FixtureJournal, intent: &rustiron_journal::Intent) {
    ledger
        .record_observation(
            &intent.operation_id,
            Some(&intent.target_generation),
            Some(&intent.target_digest),
        )
        .unwrap();
}

fn opted_in(state: &State, name: &str) -> FixtureJournal {
    let mut ledger = state.init();
    provisioned(&mut ledger, name);
    let first = activation(1);
    ledger
        .record_page_cache_intent(&first, &site(name), RECIPE, time(1000))
        .unwrap();
    succeed(&mut ledger, &first);
    ledger
}

#[test]
fn a_v15_journal_migrates_in_place_and_keeps_its_opt_ins() {
    let state = State::new();
    drop(opted_in(&state, "blog1"));
    state.sql(&format!(
        "{TO_V16} DROP TABLE page_cache_optouts; PRAGMA user_version=15;"
    ));
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let mut migrated =
        FixtureJournal::migrate(&state.0, id("host_fixture"), id("epoch_fixture")).unwrap();
    assert_eq!(migrated.page_cache_sites().unwrap(), vec![site("blog1")]);
    assert_eq!(migrated.admission_count().unwrap(), 2);
    assert!(matches!(
        migrated
            .record_page_cache_opt_out_intent(&other(2, "out"), &site("blog1"), RECIPE, time(1002))
            .unwrap(),
        Admitted::New(_)
    ));
}

#[test]
fn an_opt_out_needs_the_site_opted_in_and_a_later_opt_in_re_enables_it() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog1");
    let blog1 = site("blog1");
    assert_eq!(
        ledger
            .record_page_cache_opt_out_intent(&activation(1), &blog1, RECIPE, time(1000))
            .err(),
        Some(JournalError::Conflict),
        "never opted in"
    );
    let first = activation(1);
    ledger
        .record_page_cache_intent(&first, &blog1, RECIPE, time(1000))
        .unwrap();
    assert_eq!(
        ledger
            .record_page_cache_opt_out_intent(&other(2, "early"), &blog1, RECIPE, time(1000))
            .err(),
        Some(JournalError::Conflict),
        "the opt-in has not succeeded"
    );
    succeed(&mut ledger, &first);
    let out = other(2, "out");
    assert_eq!(
        ledger
            .record_page_cache_opt_out_intent(&out, &blog1, "litespeed_cache_latest", time(1001))
            .err(),
        Some(JournalError::Conflict),
        "unknown recipe"
    );
    assert!(matches!(
        ledger
            .record_page_cache_opt_out_intent(&out, &blog1, RECIPE, time(1001))
            .unwrap(),
        Admitted::New(_)
    ));
    assert!(matches!(
        ledger
            .record_page_cache_opt_out_intent(&out, &blog1, RECIPE, time(1001))
            .unwrap(),
        Admitted::Existing(_)
    ));
    assert_eq!(
        ledger.page_cache_opt_out_site(&out.operation_id).unwrap(),
        Some(blog1.clone())
    );
    assert_eq!(
        ledger.page_cache_opt_out_site(&first.operation_id).unwrap(),
        None
    );
    assert_eq!(ledger.page_cache_site(&out.operation_id).unwrap(), None);
    assert_eq!(
        ledger.page_cache_sites().unwrap(),
        std::slice::from_ref(&blog1),
        "opted in until the opt-out succeeds"
    );
    succeed(&mut ledger, &out);
    assert!(ledger.page_cache_sites().unwrap().is_empty());
    assert_eq!(
        ledger
            .record_page_cache_opt_out_intent(&other(3, "twice"), &blog1, RECIPE, time(1002))
            .err(),
        Some(JournalError::Conflict),
        "already opted out"
    );
    let again = other(3, "again");
    assert!(matches!(
        ledger
            .record_page_cache_intent(&again, &blog1, RECIPE, time(1003))
            .unwrap(),
        Admitted::New(_)
    ));
    succeed(&mut ledger, &again);
    assert_eq!(ledger.page_cache_sites().unwrap(), vec![blog1.clone()]);
    drop(ledger);
    assert_eq!(
        state.open().unwrap().page_cache_sites().unwrap(),
        vec![blog1]
    );
}

#[test]
fn a_compensated_opt_out_keeps_the_site_opted_in() {
    let state = State::new();
    let mut ledger = opted_in(&state, "blog1");
    let out = other(2, "out");
    ledger
        .record_page_cache_opt_out_intent(&out, &site("blog1"), RECIPE, time(1001))
        .unwrap();
    ledger.mark_effect_attempted(&out.operation_id).unwrap();
    ledger
        .record_observation(&out.operation_id, None, None)
        .unwrap();
    ledger
        .begin_compensation(&out.operation_id, time(1002))
        .unwrap();
    let compensated = ledger
        .record_observation(
            &out.operation_id,
            Some(&out.predecessor_generation),
            Some(&out.predecessor_digest),
        )
        .unwrap();
    assert_eq!(compensated.state, RecordedState::FailedCompensated);
    assert_eq!(ledger.page_cache_sites().unwrap(), vec![site("blog1")]);
    assert!(matches!(
        ledger
            .record_page_cache_opt_out_intent(
                &other(3, "retry"),
                &site("blog1"),
                RECIPE,
                time(1003)
            )
            .unwrap(),
        Admitted::New(_)
    ));
}

#[test]
fn the_records_name_the_opt_out_of_an_operation() {
    let state = State::new();
    let mut ledger = opted_in(&state, "blog1");
    let out = other(2, "out");
    ledger
        .record_page_cache_opt_out_intent(&out, &site("blog1"), RECIPE, time(1001))
        .unwrap();
    let records = |operation: &rustiron_contracts::Id| {
        FixtureJournal::records_as_process_owner(
            &state.0,
            &id("host_fixture"),
            &id("epoch_fixture"),
            operation,
            None,
        )
        .unwrap()
    };
    let records_out = records(&out.operation_id);
    assert_eq!(records_out.page_cache_opt_out, Some(site("blog1")));
    assert_eq!(records_out.page_cache, None);
    let records_in = records(&activation(1).operation_id);
    assert_eq!(records_in.page_cache, Some(site("blog1")));
    assert_eq!(records_in.page_cache_opt_out, None);
}

#[test]
fn opening_refuses_page_cache_history_that_does_not_alternate() {
    for sql in [
        // An opt-out row without its operation.
        "PRAGMA foreign_keys=OFF; INSERT INTO page_cache_optouts VALUES('operation_9','blog1','litespeed_cache_793_v1');",
        // The opt-in operation also recorded as an opt-out.
        "INSERT INTO page_cache_optouts VALUES('operation_1','blog1','litespeed_cache_793_v1');",
    ] {
        let state = State::new();
        drop(opted_in(&state, "blog1"));
        state.sql(sql);
        assert_eq!(state.open().err(), Some(JournalError::Unavailable), "{sql}");
    }
    // Two succeeded opt-ins in a row.
    let state = State::new();
    let mut ledger = opted_in(&state, "blog1");
    let second = other(2, "second");
    ledger.record_intent(&second, time(1001)).unwrap();
    succeed(&mut ledger, &second);
    drop(ledger);
    state.sql("INSERT INTO page_cache_optins VALUES('operation_second','blog1','litespeed_cache_793_v1');");
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    // A succeeded opt-out first.
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog1");
    let first = activation(1);
    ledger.record_intent(&first, time(1000)).unwrap();
    succeed(&mut ledger, &first);
    drop(ledger);
    state.sql(
        "INSERT INTO page_cache_optouts VALUES('operation_1','blog1','litespeed_cache_793_v1');",
    );
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
}

/// W379: the read-only observation names each page-cache operation and its
/// site, and gives each provision its latest succeeded page-cache change.
/// An admitted change that has not succeeded does not move the site.
#[test]
fn the_observation_names_page_cache_operations_and_each_site_state() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog1");
    provisioned(&mut ledger, "blog2");
    let blog1 = site("blog1");
    let first = activation(1);
    ledger
        .record_page_cache_intent(&first, &blog1, RECIPE, time(1000))
        .unwrap();
    let observe =
        || FixtureJournal::observe(&state.0, &id("host_fixture"), &id("epoch_fixture")).unwrap();
    assert_eq!(
        observe().provisions[0].page_cache,
        None,
        "not succeeded yet"
    );
    succeed(&mut ledger, &first);
    let seen = observe();
    assert_eq!(seen.provisions[0].page_cache, Some(true));
    assert_eq!(seen.provisions[1].page_cache, None, "never changed");
    assert_eq!(
        seen.operations[0].page_cache,
        Some(("blog1".to_owned(), true))
    );
    let out = other(2, "out");
    ledger
        .record_page_cache_opt_out_intent(&out, &blog1, RECIPE, time(1001))
        .unwrap();
    succeed(&mut ledger, &out);
    drop(ledger);
    let seen = observe();
    assert_eq!(seen.provisions[0].page_cache, Some(false));
    assert_eq!(
        seen.operations[1].page_cache,
        Some(("blog1".to_owned(), false))
    );
}

fn opted_in_with(state: &State, name: &str, recipe: &str) -> FixtureJournal {
    let mut ledger = state.init();
    provisioned(&mut ledger, name);
    let first = activation(1);
    ledger
        .record_page_cache_intent(&first, &site(name), recipe, time(1000))
        .unwrap();
    succeed(&mut ledger, &first);
    ledger
}

/// W395: a v18 journal migrates in place to v19; every earlier opt-in keeps
/// the W368 recipe.
#[test]
fn a_v18_journal_migrates_in_place_and_keeps_its_recipe() {
    let state = State::new();
    drop(opted_in(&state, "blog1"));
    state.sql(TO_V18);
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let migrated =
        FixtureJournal::migrate(&state.0, id("host_fixture"), id("epoch_fixture")).unwrap();
    assert_eq!(migrated.page_cache_sites().unwrap(), vec![site("blog1")]);
    assert_eq!(
        migrated.page_cache_site_recipe(&site("blog1")).unwrap(),
        Some(RECIPE)
    );
    drop(migrated);
    let c = rusqlite::Connection::open(state.0.join("fixture-journal.sqlite")).unwrap();
    let version: i64 = c
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(version, 45);
}

/// W395: the cache-on recipe is journaled with its opt-in and named by the
/// records; the opt-out must name it. A later opt-in may use either recipe.
#[test]
fn a_cache_on_opt_in_records_its_recipe_and_its_opt_out_must_name_it() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog1");
    let blog1 = site("blog1");
    let first = activation(1);
    assert!(matches!(
        ledger
            .record_page_cache_intent(&first, &blog1, CACHE_ON, time(1000))
            .unwrap(),
        Admitted::New(_)
    ));
    assert!(matches!(
        ledger
            .record_page_cache_intent(&first, &blog1, CACHE_ON, time(1000))
            .unwrap(),
        Admitted::Existing(_)
    ));
    assert_eq!(
        ledger.page_cache_site_recipe(&blog1).unwrap(),
        None,
        "not succeeded yet"
    );
    succeed(&mut ledger, &first);
    assert_eq!(ledger.page_cache_sites().unwrap(), vec![blog1.clone()]);
    assert_eq!(
        ledger.page_cache_site_recipe(&blog1).unwrap(),
        Some(CACHE_ON)
    );
    let records = |operation: &rustiron_contracts::Id| {
        FixtureJournal::records_as_process_owner(
            &state.0,
            &id("host_fixture"),
            &id("epoch_fixture"),
            operation,
            None,
        )
        .unwrap()
    };
    assert_eq!(
        records(&first.operation_id).page_cache_recipe,
        Some(CACHE_ON)
    );
    let out = other(2, "out");
    assert_eq!(
        ledger
            .record_page_cache_opt_out_intent(&out, &blog1, RECIPE, time(1001))
            .err(),
        Some(JournalError::Conflict),
        "the opt-out names another recipe"
    );
    assert!(matches!(
        ledger
            .record_page_cache_opt_out_intent(&out, &blog1, CACHE_ON, time(1001))
            .unwrap(),
        Admitted::New(_)
    ));
    assert_eq!(records(&out.operation_id).page_cache_recipe, Some(CACHE_ON));
    succeed(&mut ledger, &out);
    assert!(ledger.page_cache_sites().unwrap().is_empty());
    assert_eq!(ledger.page_cache_site_recipe(&blog1).unwrap(), None);
    let again = other(3, "again");
    ledger
        .record_page_cache_intent(&again, &blog1, RECIPE, time(1002))
        .unwrap();
    assert_eq!(records(&again.operation_id).page_cache_recipe, Some(RECIPE));
    succeed(&mut ledger, &again);
    assert_eq!(ledger.page_cache_site_recipe(&blog1).unwrap(), Some(RECIPE));
    drop(ledger);
    assert_eq!(
        state
            .open()
            .unwrap()
            .page_cache_site_recipe(&blog1)
            .unwrap(),
        Some(RECIPE)
    );
}

/// W395: a cache-on opt-in that was compensated does not count.
#[test]
fn a_compensated_cache_on_opt_in_does_not_count() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog1");
    let first = activation(1);
    ledger
        .record_page_cache_intent(&first, &site("blog1"), CACHE_ON, time(1000))
        .unwrap();
    ledger.mark_effect_attempted(&first.operation_id).unwrap();
    ledger
        .record_observation(&first.operation_id, None, None)
        .unwrap();
    ledger
        .begin_compensation(&first.operation_id, time(1001))
        .unwrap();
    ledger
        .record_observation(
            &first.operation_id,
            Some(&first.predecessor_generation),
            Some(&first.predecessor_digest),
        )
        .unwrap();
    assert!(ledger.page_cache_sites().unwrap().is_empty());
    assert_eq!(ledger.page_cache_site_recipe(&site("blog1")).unwrap(), None);
}

/// W395: opening refuses a recipe row that names no page-cache change, and
/// an opt-out whose recipe is not the recipe of the opt-in before it.
#[test]
fn opening_refuses_a_recipe_row_without_its_change_or_with_another_recipe() {
    // A recipe row on an activation that is no page-cache change.
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog1");
    let plain = activation(1);
    ledger.record_intent(&plain, time(1000)).unwrap();
    drop(ledger);
    state.sql(&format!(
        "INSERT INTO page_cache_recipes VALUES('{}','{CACHE_ON}');",
        plain.operation_id.as_str()
    ));
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    // A recipe row without its operation.
    let state = State::new();
    drop(opted_in(&state, "blog1"));
    state.sql(&format!(
        "PRAGMA foreign_keys=OFF; INSERT INTO page_cache_recipes VALUES('operation_9','{CACHE_ON}');"
    ));
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    // A succeeded W368-recipe opt-out of a cache-on opt-in.
    let state = State::new();
    let mut ledger = opted_in_with(&state, "blog1", CACHE_ON);
    let out = other(2, "out");
    ledger
        .record_page_cache_opt_out_intent(&out, &site("blog1"), CACHE_ON, time(1001))
        .unwrap();
    succeed(&mut ledger, &out);
    drop(ledger);
    state.open().unwrap();
    state.sql("DELETE FROM page_cache_recipes WHERE operation_id='operation_out';");
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
}

/// W395: the observation gives each provision the recipe of its latest
/// succeeded page-cache change.
#[test]
fn the_observation_names_the_recipe_of_each_site_state() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog1");
    provisioned(&mut ledger, "blog2");
    let first = activation(1);
    ledger
        .record_page_cache_intent(&first, &site("blog1"), CACHE_ON, time(1000))
        .unwrap();
    succeed(&mut ledger, &first);
    let observe =
        || FixtureJournal::observe(&state.0, &id("host_fixture"), &id("epoch_fixture")).unwrap();
    let seen = observe();
    assert_eq!(seen.provisions[0].page_cache, Some(true));
    assert_eq!(
        seen.provisions[0].page_cache_recipe.as_deref(),
        Some(CACHE_ON)
    );
    assert_eq!(seen.provisions[1].page_cache_recipe, None);
    let out = other(2, "out");
    ledger
        .record_page_cache_opt_out_intent(&out, &site("blog1"), CACHE_ON, time(1001))
        .unwrap();
    succeed(&mut ledger, &out);
    drop(ledger);
    let seen = observe();
    assert_eq!(seen.provisions[0].page_cache, Some(false));
    assert_eq!(
        seen.provisions[0].page_cache_recipe.as_deref(),
        Some(CACHE_ON)
    );
    let plain = State::new();
    drop(opted_in(&plain, "blog3"));
    let seen =
        FixtureJournal::observe(&plain.0, &id("host_fixture"), &id("epoch_fixture")).unwrap();
    assert_eq!(
        seen.provisions[0].page_cache_recipe.as_deref(),
        Some(RECIPE)
    );
}
