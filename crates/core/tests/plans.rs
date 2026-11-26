//! Plan bytes can be stored and read back. Storage is not admission.

use rustiron_contracts::{Id, approval::PreparedPlan};
use rustiron_core::{PlanStore, PlanStoreError};
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct State(PathBuf);
impl State {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ri-plans-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for State {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn plan() -> Vec<u8> {
    include_bytes!("../../contracts/tests/fixtures/site-plan.json").to_vec()
}

#[test]
fn an_identical_plan_is_stored_once_and_a_different_plan_cannot_reuse_its_id() {
    let state = State::new();
    let mut store = PlanStore::initialize(&state.0).unwrap();
    let first = store.put(&plan()).unwrap();
    assert!(first.inserted);
    assert_eq!(first.id.as_str(), "plan_site");
    let again = store.put(&plan()).unwrap();
    assert!(!again.inserted);
    assert_eq!(again.digest, first.digest);
    let changed = String::from_utf8(plan())
        .unwrap()
        .replace("\"expires_at\": 2000", "\"expires_at\": 2001");
    assert_eq!(
        store.put(changed.as_bytes()).unwrap_err(),
        PlanStoreError::Conflict
    );
    let stored = store.get(&first.id).unwrap();
    let prepared = PreparedPlan::decode(&stored).unwrap();
    assert_eq!(prepared.digest(), first.digest);
    assert_eq!(prepared.as_bytes(), stored.as_slice());
    drop(store);
    let mut reopened = PlanStore::open(&state.0).unwrap();
    assert_eq!(reopened.get(&first.id).unwrap(), stored);
}

#[test]
fn a_grant_is_not_stored_and_a_second_opener_is_refused() {
    let state = State::new();
    let mut store = PlanStore::initialize(&state.0).unwrap();
    let grant = include_bytes!("../../contracts/tests/fixtures/site-grant.json");
    assert_eq!(store.put(grant).unwrap_err(), PlanStoreError::InvalidPlan);
    assert_eq!(
        PlanStore::open(&state.0).err(),
        Some(PlanStoreError::Unavailable)
    );
    assert_eq!(
        store
            .get(&Id::try_from("missing".to_owned()).unwrap())
            .unwrap_err(),
        PlanStoreError::NotFound
    );
}

#[test]
fn altered_stored_bytes_are_refused_on_open() {
    let state = State::new();
    let mut store = PlanStore::initialize(&state.0).unwrap();
    store.put(&plan()).unwrap();
    drop(store);
    let connection = rusqlite::Connection::open(state.0.join("plans.sqlite")).unwrap();
    connection
        .execute(
            "UPDATE plans SET bytes=?1 WHERE plan_id='plan_site'",
            [b"{}".as_slice()],
        )
        .unwrap();
    drop(connection);
    assert_eq!(
        PlanStore::open(&state.0).err(),
        Some(PlanStoreError::Unavailable)
    );
}
