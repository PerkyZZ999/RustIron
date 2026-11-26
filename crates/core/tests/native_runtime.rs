//! The actual linked native dependency must match the reviewed upstream patch.

#[test]
fn runtime_uses_reviewed_sqlite_patch_and_source_identity() {
    assert_eq!(rusqlite::version(), "3.54.1");
    let connection = rusqlite::Connection::open_in_memory().unwrap();
    let source: String = connection
        .query_row("SELECT sqlite_source_id()", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        source,
        "2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76"
    );
}
