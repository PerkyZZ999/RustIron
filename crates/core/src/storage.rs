use rusqlite::{Connection, OpenFlags, params};
use rustiron_contracts::{ErrorCode, local};
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::Duration,
};

pub(crate) const DATABASE: &str = "control.sqlite";
const APPLICATION_ID: i64 = 0x5249524e;
const SCHEMA: [(&str, &str); 3] = [
    (
        "schema_version",
        "CREATE TABLE schema_version (singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL CHECK(version=1)) STRICT",
    ),
    (
        "inventory_meta",
        "CREATE TABLE inventory_meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), instance TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>=0), reported_at INTEGER, source TEXT, has_snapshot INTEGER NOT NULL CHECK(has_snapshot IN (0,1))) STRICT",
    ),
    (
        "sites",
        "CREATE TABLE sites (site_id TEXT PRIMARY KEY, name TEXT NOT NULL, generation TEXT) STRICT",
    ),
];

pub(crate) fn unavailable<T>(_: T) -> ErrorCode {
    ErrorCode::DependencyUnavailable
}

pub(crate) fn acquire(directory: &Path) -> Result<File, ErrorCode> {
    acquire_lock(directory, DATABASE, "writer.lock")
}

pub(crate) fn acquire_lock(
    directory: &Path,
    database: &str,
    lock_name: &str,
) -> Result<File, ErrorCode> {
    verify_native_runtime()?;
    let uid = local::operator_uid()?;
    local::check_parent(&directory.join(database), uid)?;
    let path = directory.join(lock_name);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(
            rustix::fs::OFlags::NOFOLLOW
                .bits()
                .try_into()
                .map_err(unavailable)?,
        )
        .open(path)
        .map_err(local::io_code)?;
    let metadata = file.metadata().map_err(local::io_code)?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(ErrorCode::UnauthorizedPeer);
    }
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(unavailable)?;
    Ok(file)
}

pub(crate) fn verify_native_runtime() -> Result<(), ErrorCode> {
    let connection = Connection::open_in_memory().map_err(unavailable)?;
    let source: String = connection
        .query_row("SELECT sqlite_source_id()", [], |row| row.get(0))
        .map_err(unavailable)?;
    require_native_identity(rusqlite::version(), &source)
}

fn require_native_identity(version: &str, source: &str) -> Result<(), ErrorCode> {
    if version != "3.54.1"
        || source
            != "2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76"
    {
        return Err(ErrorCode::DependencyUnavailable);
    }
    Ok(())
}

fn check_files(directory: &Path) -> Result<(), ErrorCode> {
    let uid = local::operator_uid()?;
    for name in [DATABASE, "control.sqlite-wal", "control.sqlite-shm"] {
        match fs::symlink_metadata(directory.join(name)) {
            Ok(metadata)
                if metadata.is_file()
                    && metadata.uid() == uid
                    && metadata.mode() & 0o7777 == 0o600
                    && metadata.nlink() == 1 => {}
            Ok(_) => return Err(ErrorCode::UnauthorizedPeer),
            Err(error) if error.kind() == io::ErrorKind::NotFound && name != DATABASE => {}
            Err(error) => return Err(local::io_code(error)),
        }
    }
    Ok(())
}

pub(crate) fn initialize(directory: &Path) -> Result<Connection, ErrorCode> {
    for name in [
        DATABASE,
        "control.sqlite-wal",
        "control.sqlite-shm",
        "control.sqlite-journal",
    ] {
        match fs::symlink_metadata(directory.join(name)) {
            Ok(_) => return Err(ErrorCode::DependencyUnavailable),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(local::io_code(error)),
        }
    }
    let path = directory.join(DATABASE);
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(local::io_code)?;
    let mut connection = Connection::open_with_flags(&path, flags(false)).map_err(unavailable)?;
    configure(&connection)?;
    let transaction = connection.transaction().map_err(unavailable)?;
    for (_, sql) in SCHEMA {
        transaction.execute_batch(sql).map_err(unavailable)?;
    }
    transaction
        .execute("INSERT INTO schema_version VALUES(1,1)", [])
        .map_err(unavailable)?;
    transaction
        .execute(
            "INSERT INTO inventory_meta VALUES(1,?1,0,NULL,NULL,0)",
            params![instance()?],
        )
        .map_err(unavailable)?;
    transaction
        .pragma_update(None, "application_id", APPLICATION_ID)
        .map_err(unavailable)?;
    transaction
        .pragma_update(None, "user_version", 1)
        .map_err(unavailable)?;
    transaction.commit().map_err(unavailable)?;
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(local::io_code)?;
    Ok(connection)
}

pub(crate) fn open(directory: &Path) -> Result<Connection, ErrorCode> {
    check_files(directory)?;
    let path = directory.join(DATABASE);
    let probe = Connection::open_with_flags(&path, flags(true)).map_err(unavailable)?;
    probe
        .pragma_update(None, "trusted_schema", false)
        .map_err(unavailable)?;
    validate_schema(&probe)?;
    let integrity: String = probe
        .pragma_query_value(None, "quick_check", |row| row.get(0))
        .map_err(unavailable)?;
    if integrity != "ok" {
        return Err(ErrorCode::DependencyUnavailable);
    }
    drop(probe);
    let connection = Connection::open_with_flags(path, flags(false)).map_err(unavailable)?;
    configure(&connection)?;
    validate_schema(&connection)?;
    Ok(connection)
}

fn flags(read_only: bool) -> OpenFlags {
    (if read_only {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    } else {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    }) | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW
}

pub(crate) fn configure(connection: &Connection) -> Result<(), ErrorCode> {
    connection
        .busy_timeout(Duration::from_millis(250))
        .map_err(unavailable)?;
    connection
        .pragma_update(None, "trusted_schema", false)
        .map_err(unavailable)?;
    connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(unavailable)?;
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .map_err(unavailable)?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(unavailable)?;
    let journal: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(unavailable)?;
    let sync: i64 = connection
        .pragma_query_value(None, "synchronous", |row| row.get(0))
        .map_err(unavailable)?;
    let foreign: i64 = connection
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .map_err(unavailable)?;
    if journal != "wal" || sync != 2 || foreign != 1 {
        return Err(ErrorCode::DependencyUnavailable);
    }
    Ok(())
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), ErrorCode> {
    let application: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(unavailable)?;
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(unavailable)?;
    if application != APPLICATION_ID || version != 1 {
        return Err(ErrorCode::DependencyUnavailable);
    }
    let mut statement = connection
        .prepare("SELECT name,sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY name")
        .map_err(unavailable)?;
    let actual = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(unavailable)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(unavailable)?;
    let mut expected = SCHEMA.map(|(name, sql)| (name.to_owned(), sql.to_owned()));
    expected.sort();
    if actual != expected {
        return Err(ErrorCode::DependencyUnavailable);
    }
    let version: i64 = connection
        .query_row(
            "SELECT version FROM schema_version WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(unavailable)?;
    if version != 1 {
        return Err(ErrorCode::DependencyUnavailable);
    }
    Ok(())
}

fn instance() -> Result<String, ErrorCode> {
    let mut bytes = [0u8; 16];
    let mut position = 0;
    while position < bytes.len() {
        let count = rustix::rand::getrandom(
            &mut bytes[position..],
            rustix::rand::GetRandomFlags::empty(),
        )
        .map_err(unavailable)?;
        if count == 0 {
            return Err(ErrorCode::DependencyUnavailable);
        }
        position += count;
    }
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(test)]
mod native_tests {
    use super::*;

    #[test]
    fn unreviewed_native_version_is_refused() {
        assert_eq!(
            require_native_identity(
                "3.54.0",
                "2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76"
            ),
            Err(ErrorCode::DependencyUnavailable)
        );
    }

    #[test]
    fn different_source_with_same_version_is_refused() {
        assert_eq!(
            require_native_identity("3.54.1", "unreviewed source"),
            Err(ErrorCode::DependencyUnavailable)
        );
    }
}
