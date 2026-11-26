//! Medium tests: real SQLite/filesystem, isolated private state, no host adoption.

use rustiron_contracts::*;
use rustiron_core::InventoryStore;
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
            "ri-store-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn initialized(&self) -> InventoryStore {
        InventoryStore::initialize(&self.0).unwrap()
    }
    fn sql(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.0.join("control.sqlite")).unwrap()
    }
}
impl Drop for State {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn id(value: &str) -> Id {
    Id::try_from(value.to_owned()).unwrap()
}
fn limit(value: u16) -> PageLimit {
    PageLimit::try_from(value).unwrap()
}
fn reported(site_id: &str) -> ReportedSite {
    ReportedSite {
        site_id: id(site_id),
        name: Text::try_from(format!("Name {site_id}")).unwrap(),
        configuration_generation: Some(id("gen-1")),
    }
}
fn snapshot(sites: Vec<ReportedSite>) -> InventorySnapshot {
    InventorySnapshot {
        schema_version: SchemaVersion::V1,
        report: InventoryProvenance {
            reported_at: Timestamp::try_from(42).unwrap(),
            source: InventorySource::OperatorReport,
        },
        complete: true,
        sites,
    }
}

#[test]
fn initialized_but_unobserved_inventory_is_not_empty_success() {
    let state = State::new();
    let mut store = state.initialized();
    assert_eq!(
        store.list(None, limit(20)),
        Err(ErrorCode::DependencyUnavailable)
    );
    assert_eq!(
        store.inspect(&id("missing")),
        Err(ErrorCode::DependencyUnavailable)
    );
}

#[test]
fn explicit_empty_report_and_missing_site_are_distinct() {
    let state = State::new();
    let mut store = state.initialized();
    store.replace(&snapshot(vec![])).unwrap();
    assert_eq!(
        store.list(None, limit(20)).unwrap(),
        SitePage {
            items: vec![],
            next_cursor: None
        }
    );
    assert_eq!(store.inspect(&id("missing")), Err(ErrorCode::NotFound));
}

#[test]
fn a_current_generation_stays_inferred_and_an_old_one_is_stale() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let state = State::new();
    let mut store = state.initialized();
    let mut current = snapshot(vec![reported("site-a")]);
    current.report.reported_at = Timestamp::try_from(now).unwrap();
    store.replace(&current).unwrap();
    assert!(matches!(
        store
            .inspect(&id("site-a"))
            .unwrap()
            .configuration_generation,
        Observation::Inferred { .. }
    ));
    let mut old = current.clone();
    old.report.reported_at = Timestamp::try_from(now - 301).unwrap();
    store.replace(&old).unwrap();
    match store
        .inspect(&id("site-a"))
        .unwrap()
        .configuration_generation
    {
        Observation::Stale { observed_at, .. } => assert_eq!(observed_at.get(), now - 301),
        other => panic!("expected stale, got {other:?}"),
    }
}

#[test]
fn reported_sites_preserve_provenance_without_adoption_authority() {
    let state = State::new();
    let mut store = state.initialized();
    let input = snapshot(vec![reported("site-b"), reported("site-a")]);
    store.replace(&input).unwrap();
    let site = store.inspect(&id("site-a")).unwrap();
    assert_eq!(site.site.ownership, Ownership::ObservedOnly);
    assert_eq!(site.site.inventory, Some(input.report));
    assert_eq!(
        site.configuration_generation,
        Observation::Stale {
            value: id("gen-1"),
            observed_at: Timestamp::try_from(42).unwrap(),
            source: ObservationSource::Inventory
        }
    );
    assert_eq!(
        store
            .list(None, limit(20))
            .unwrap()
            .items
            .into_iter()
            .map(|s| s.site_id)
            .collect::<Vec<_>>(),
        vec![id("site-a"), id("site-b")]
    );
}

#[test]
fn restart_preserves_snapshot_and_continuation_without_duplicates() {
    let state = State::new();
    let mut store = state.initialized();
    store
        .replace(&snapshot(vec![
            reported("site-c"),
            reported("site-a"),
            reported("site-b"),
        ]))
        .unwrap();
    let first = store.list(None, limit(2)).unwrap();
    let cursor = first.next_cursor.unwrap();
    assert_eq!(first.items.len(), 2);
    drop(store);
    let mut reopened = InventoryStore::open(&state.0).unwrap();
    let last = reopened.list(Some(&cursor), limit(2)).unwrap();
    assert_eq!(
        last.items
            .into_iter()
            .map(|s| s.site_id)
            .collect::<Vec<_>>(),
        vec![id("site-c")]
    );
    assert_eq!(last.next_cursor, None);
}

#[test]
fn changed_revision_expires_previous_cursor() {
    let state = State::new();
    let mut store = state.initialized();
    let input = snapshot(vec![reported("a"), reported("b")]);
    store.replace(&input).unwrap();
    let cursor = store.list(None, limit(1)).unwrap().next_cursor.unwrap();
    store.replace(&input).unwrap();
    assert_eq!(
        store.list(Some(&cursor), limit(1)),
        Err(ErrorCode::CursorExpired)
    );
}

#[test]
fn cursor_cannot_cross_database_or_change_page_size() {
    let first = State::new();
    let second = State::new();
    let mut a = first.initialized();
    let mut b = second.initialized();
    let input = snapshot(vec![reported("a"), reported("b")]);
    a.replace(&input).unwrap();
    b.replace(&input).unwrap();
    let cursor = a.list(None, limit(1)).unwrap().next_cursor.unwrap();
    assert_eq!(
        a.list(Some(&cursor), limit(2)),
        Err(ErrorCode::CursorExpired)
    );
    assert_eq!(
        b.list(Some(&cursor), limit(1)),
        Err(ErrorCode::CursorExpired)
    );
}

#[test]
fn incomplete_or_duplicate_report_does_not_replace_last_snapshot() {
    let state = State::new();
    let mut store = state.initialized();
    let original = snapshot(vec![reported("a")]);
    store.replace(&original).unwrap();
    let mut incomplete = snapshot(vec![]);
    incomplete.complete = false;
    assert_eq!(store.replace(&incomplete), Err(ErrorCode::InvalidRequest));
    assert_eq!(
        store.replace(&snapshot(vec![reported("b"), reported("b")])),
        Err(ErrorCode::InvalidRequest)
    );
    assert_eq!(store.export().unwrap(), original);
}

#[test]
fn export_is_a_consistent_sorted_snapshot_not_an_authority_manifest() {
    let state = State::new();
    let mut store = state.initialized();
    store
        .replace(&snapshot(vec![reported("b"), reported("a")]))
        .unwrap();
    assert_eq!(
        store.export().unwrap(),
        snapshot(vec![reported("a"), reported("b")])
    );
}

#[test]
fn startup_proves_effective_coordinator_durability_settings() {
    let state = State::new();
    let store = state.initialized();
    let status = store.status().unwrap();
    println!("linked SQLite version: {}", status.sqlite_version);
    assert_eq!(status.journal_mode, "wal");
    assert_eq!(status.synchronous, 2);
    assert!(status.foreign_keys);
    assert_eq!(status.schema_version, 1);
}

#[test]
fn second_writer_is_denied_until_original_store_closes() {
    let state = State::new();
    let store = state.initialized();
    assert_eq!(
        InventoryStore::open(&state.0).err(),
        Some(ErrorCode::DependencyUnavailable)
    );
    drop(store);
    assert!(InventoryStore::open(&state.0).is_ok());
}

#[test]
fn missing_database_is_not_initialized_implicitly() {
    let state = State::new();
    assert_eq!(
        InventoryStore::open(&state.0).err(),
        Some(ErrorCode::DependencyUnavailable)
    );
    assert!(!state.0.join("control.sqlite").exists());
}

#[test]
fn newer_schema_is_refused_without_replacing_database() {
    let state = State::new();
    drop(state.initialized());
    state.sql().pragma_update(None, "user_version", 2).unwrap();
    let before = fs::read(state.0.join("control.sqlite")).unwrap();
    assert_eq!(
        InventoryStore::open(&state.0).err(),
        Some(ErrorCode::DependencyUnavailable)
    );
    assert_eq!(fs::read(state.0.join("control.sqlite")).unwrap(), before);
}

#[test]
fn corrupt_database_is_refused_without_empty_fallback() {
    let state = State::new();
    drop(state.initialized());
    fs::write(
        state.0.join("control.sqlite"),
        b"CANARY_NOT_A_SECRET_CORRUPT",
    )
    .unwrap();
    assert_eq!(
        InventoryStore::open(&state.0).err(),
        Some(ErrorCode::DependencyUnavailable)
    );
    assert_eq!(
        fs::read(state.0.join("control.sqlite")).unwrap(),
        b"CANARY_NOT_A_SECRET_CORRUPT"
    );
}

#[test]
fn unsafe_state_directory_is_denied() {
    let state = State::new();
    fs::set_permissions(&state.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        InventoryStore::initialize(&state.0).err(),
        Some(ErrorCode::UnauthorizedPeer)
    );
}

#[test]
fn database_symlink_is_denied() {
    let state = State::new();
    std::os::unix::fs::symlink("missing", state.0.join("control.sqlite")).unwrap();
    assert_eq!(
        InventoryStore::open(&state.0).err(),
        Some(ErrorCode::UnauthorizedPeer)
    );
}

#[test]
fn sql_and_terminal_text_remain_data() {
    let state = State::new();
    let mut store = state.initialized();
    let mut site = reported("a");
    let name = "'; DROP TABLE sites; --\u{001b}[31m";
    site.name = Text::try_from(name.to_owned()).unwrap();
    store.replace(&snapshot(vec![site])).unwrap();
    assert_eq!(store.inspect(&id("a")).unwrap().site.name.as_str(), name);
    assert_eq!(store.export().unwrap().sites.len(), 1);
}

#[test]
fn busy_writer_refuses_replacement_preserving_last_snapshot() {
    let state = State::new();
    let mut store = state.initialized();
    let original = snapshot(vec![reported("a")]);
    store.replace(&original).unwrap();
    let mut other = state.sql();
    let lock = other
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    assert_eq!(
        store.replace(&snapshot(vec![reported("b")])),
        Err(ErrorCode::DependencyUnavailable)
    );
    drop(lock);
    assert_eq!(store.export().unwrap(), original);
}

#[test]
fn invalid_persisted_site_is_not_skipped_or_exposed() {
    let state = State::new();
    let mut store = state.initialized();
    store.replace(&snapshot(vec![reported("a")])).unwrap();
    state
        .sql()
        .execute("UPDATE sites SET site_id='CANARY/invalid'", [])
        .unwrap();
    assert_eq!(
        store.list(None, limit(20)),
        Err(ErrorCode::DependencyUnavailable)
    );
    assert_eq!(store.export(), Err(ErrorCode::DependencyUnavailable));
}

#[test]
fn malformed_continuation_is_an_explicit_cursor_error() {
    let state = State::new();
    let mut store = state.initialized();
    store.replace(&snapshot(vec![reported("a")])).unwrap();
    assert_eq!(
        store.list(Some(&id("bogus")), limit(1)),
        Err(ErrorCode::CursorExpired)
    );
}

#[test]
fn unexportable_report_is_refused_without_replacing_snapshot() {
    let state = State::new();
    let mut store = state.initialized();
    let original = snapshot(vec![reported("a")]);
    store.replace(&original).unwrap();
    let sites = (0..MAX_INVENTORY_SITES)
        .map(|index| ReportedSite {
            site_id: id(&format!("site-{index}")),
            name: Text::try_from("\0".repeat(512)).unwrap(),
            configuration_generation: None,
        })
        .collect();
    assert_eq!(
        store.replace(&snapshot(sites)),
        Err(ErrorCode::InvalidRequest)
    );
    assert_eq!(store.export().unwrap(), original);
}

#[test]
fn initialization_refuses_existing_sidecar_without_creating_database() {
    let state = State::new();
    let sidecar = state.0.join("control.sqlite-wal");
    fs::write(&sidecar, b"foreign-sidecar").unwrap();
    assert_eq!(
        InventoryStore::initialize(&state.0).err(),
        Some(ErrorCode::DependencyUnavailable)
    );
    assert!(!state.0.join("control.sqlite").exists());
    assert_eq!(fs::read(sidecar).unwrap(), b"foreign-sidecar");
}
