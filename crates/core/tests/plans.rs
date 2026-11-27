//! Plan bytes can be stored and read back. Storage is not admission.

use rustiron_contracts::{Id, approval::PreparedPlan};
use rustiron_core::{PlanStore, PlanStoreError};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
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

/// W676: a row the store already decoded and accepted is still refused when
/// its bytes change behind the open store; only an unchanged row skips the
/// decode.
#[test]
fn a_row_changed_after_it_was_validated_is_refused_on_the_next_call() {
    let state = State::new();
    let mut store = PlanStore::initialize(&state.0).unwrap();
    let first = store.put(&plan()).unwrap();
    store.get(&first.id).unwrap();
    let other = String::from_utf8(plan())
        .unwrap()
        .replace("\"plan_site\"", "\"plan_other\"");
    store.put(other.as_bytes()).unwrap();
    let connection = rusqlite::Connection::open(state.0.join("plans.sqlite")).unwrap();
    connection
        .execute(
            "UPDATE plans SET bytes=?1 WHERE plan_id='plan_site'",
            [b"{\"changed\":true}".as_slice()],
        )
        .unwrap();
    drop(connection);
    let other_id = Id::try_from("plan_other".to_owned()).unwrap();
    assert_eq!(
        store.get(&other_id).unwrap_err(),
        PlanStoreError::Unavailable
    );
}

/// W690: opens a store whose one row had `assignment` applied behind it.
fn open_after(assignment: &str) -> Option<PlanStoreError> {
    let state = State::new();
    let mut store = PlanStore::initialize(&state.0).unwrap();
    store.put(&plan()).unwrap();
    drop(store);
    let connection = rusqlite::Connection::open(state.0.join("plans.sqlite")).unwrap();
    connection
        .execute(&format!("UPDATE plans SET {assignment}"), [])
        .unwrap();
    drop(connection);
    PlanStore::open(&state.0).err()
}

/// W690 (mutation gap): each indexed column must match the plan on its own;
/// changing only one is refused.
#[test]
fn a_changed_plan_id_column_alone_is_refused() {
    assert_eq!(
        open_after("plan_id='plan_alias'"),
        Some(PlanStoreError::Unavailable)
    );
}

#[test]
fn a_changed_kind_column_alone_is_refused() {
    assert_eq!(
        open_after("kind='site_eject'"),
        Some(PlanStoreError::Unavailable)
    );
}

#[test]
fn a_changed_digest_column_alone_is_refused() {
    assert_eq!(
        open_after(&format!("digest='{}'", "0".repeat(64))),
        Some(PlanStoreError::Unavailable)
    );
}

/// W690 (mutation gap): store files must be owner-only regular files with
/// one link; anything else is refused before SQLite opens them.
fn open_with(change: impl FnOnce(&std::path::Path)) -> Option<PlanStoreError> {
    let state = State::new();
    drop(PlanStore::initialize(&state.0).unwrap());
    change(&state.0);
    PlanStore::open(&state.0).err()
}

#[test]
fn a_group_readable_database_is_refused() {
    let refused = open_with(|dir| {
        fs::set_permissions(dir.join("plans.sqlite"), fs::Permissions::from_mode(0o640)).unwrap();
    });
    assert_eq!(refused, Some(PlanStoreError::Unauthorized));
}

#[test]
fn a_hard_linked_database_is_refused() {
    let refused = open_with(|dir| {
        fs::hard_link(dir.join("plans.sqlite"), dir.join("plans.link")).unwrap();
    });
    assert_eq!(refused, Some(PlanStoreError::Unauthorized));
}

#[test]
fn a_symlinked_wal_file_is_refused() {
    let refused = open_with(|dir| {
        let _ = fs::remove_file(dir.join("plans.sqlite-wal"));
        std::os::unix::fs::symlink("/dev/null", dir.join("plans.sqlite-wal")).unwrap();
    });
    assert_eq!(refused, Some(PlanStoreError::Unauthorized));
}

/// W690 (mutation gap): the schema version is checked on its own, not only
/// together with the application ID.
#[test]
fn a_changed_schema_version_alone_is_refused() {
    let refused = open_with(|dir| {
        let connection = rusqlite::Connection::open(dir.join("plans.sqlite")).unwrap();
        connection.pragma_update(None, "user_version", 2).unwrap();
    });
    assert_eq!(refused, Some(PlanStoreError::Unavailable));
}

/// W706 (fault injection, W690 misses): a lock file that is not owner-only
/// is refused as unauthorized, not as unavailable.
#[test]
fn a_group_writable_lock_file_is_refused_as_unauthorized() {
    let state = State::new();
    let lock = state.0.join("plans.lock");
    fs::write(&lock, b"").unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o660)).unwrap();
    assert_eq!(
        PlanStore::initialize(&state.0).err(),
        Some(PlanStoreError::Unauthorized)
    );
    assert_eq!(fs::read_dir(&state.0).unwrap().count(), 1);
}

/// W706 (fault injection, W690 misses): a relative store path is refused as
/// an invalid request before any file is touched.
#[test]
fn a_relative_store_path_is_refused_as_invalid() {
    assert_eq!(
        PlanStore::open(std::path::Path::new("relative-plan-store")).err(),
        Some(PlanStoreError::InvalidPlan)
    );
    assert!(!std::path::Path::new("relative-plan-store/plans.lock").exists());
}
