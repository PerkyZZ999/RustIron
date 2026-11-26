//! Canonical plan bytes for the five lab plan kinds.
//!
//! A stored plan is not a signature, a grant, or permission to execute.

use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use rustiron_contracts::{
    ErrorCode, Id, MAX_REQUEST_BYTES,
    approval::{PlanKind, PreparedPlan, Sha256Digest},
    local,
};
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

use crate::storage;

const DATABASE: &str = "plans.sqlite";
const APPLICATION_ID: i64 = 0x5249504c;
const MAX_PLANS: i64 = 1000;
const SCHEMA: [(&str, &str); 2] = [
    (
        "plans",
        "CREATE TABLE plans (plan_id TEXT PRIMARY KEY, kind TEXT NOT NULL, digest TEXT NOT NULL, bytes BLOB NOT NULL) STRICT",
    ),
    (
        "schema_version",
        "CREATE TABLE schema_version (singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL CHECK(version=1)) STRICT",
    ),
];

/// One accepted store result. `inserted` is false when the same bytes were already stored.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredPlan {
    /// Identity taken from the validated plan.
    pub id: Id,
    /// Closed lab plan kind.
    pub kind: PlanKind,
    /// Digest of the stored canonical bytes.
    pub digest: Sha256Digest,
    /// False when this call found the identical plan already stored.
    pub inserted: bool,
}

/// Store refusal. None of these outcomes is an executor admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanStoreError {
    /// The bytes are not one validated operation plan.
    InvalidPlan,
    /// That plan id already holds different bytes.
    Conflict,
    /// No plan is stored under that id.
    NotFound,
    /// The directory, lock, or database cannot be used.
    Unavailable,
    /// The directory or database is not a private regular file owned by this user.
    Unauthorized,
}

/// Single-writer store of canonical plan bytes.
pub struct PlanStore {
    connection: Connection,
    _lock: File,
}

impl PlanStore {
    /// Creates an empty store. Refuses a directory that already has plan database files.
    pub fn initialize(directory: &Path) -> Result<Self, PlanStoreError> {
        let lock = storage::acquire_lock(directory, DATABASE, "plans.lock").map_err(store_error)?;
        let connection = initialize(directory)?;
        Ok(Self {
            connection,
            _lock: lock,
        })
    }

    /// Opens a valid store. A second opener in another process is refused.
    pub fn open(directory: &Path) -> Result<Self, PlanStoreError> {
        let lock = storage::acquire_lock(directory, DATABASE, "plans.lock").map_err(store_error)?;
        let connection = open(directory)?;
        Ok(Self {
            connection,
            _lock: lock,
        })
    }

    /// Stores one validated plan. The same bytes may be stored again. Different bytes may not reuse its id.
    pub fn put(&mut self, bytes: &[u8]) -> Result<StoredPlan, PlanStoreError> {
        let prepared = PreparedPlan::decode(bytes).map_err(|_| PlanStoreError::InvalidPlan)?;
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| PlanStoreError::Unavailable)?;
        validate(&transaction)?;
        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT bytes FROM plans WHERE plan_id=?1",
                [prepared.id().as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| PlanStoreError::Unavailable)?;
        if let Some(existing) = existing {
            if existing.as_slice() != prepared.as_bytes() {
                return Err(PlanStoreError::Conflict);
            }
            return Ok(stored(&prepared, false));
        }
        let count: i64 = transaction
            .query_row("SELECT count(*) FROM plans", [], |row| row.get(0))
            .map_err(|_| PlanStoreError::Unavailable)?;
        if count >= MAX_PLANS {
            return Err(PlanStoreError::Unavailable);
        }
        transaction
            .execute(
                "INSERT INTO plans(plan_id,kind,digest,bytes) VALUES(?1,?2,?3,?4)",
                params![
                    prepared.id().as_str(),
                    prepared.kind().as_str(),
                    prepared.digest().as_str(),
                    prepared.as_bytes()
                ],
            )
            .map_err(|_| PlanStoreError::Unavailable)?;
        transaction
            .commit()
            .map_err(|_| PlanStoreError::Unavailable)?;
        Ok(stored(&prepared, true))
    }

    /// Returns the stored canonical bytes after checking them again.
    pub fn get(&mut self, id: &Id) -> Result<Vec<u8>, PlanStoreError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| PlanStoreError::Unavailable)?;
        validate(&transaction)?;
        let bytes: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT bytes FROM plans WHERE plan_id=?1",
                [id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| PlanStoreError::Unavailable)?;
        let Some(bytes) = bytes else {
            return Err(PlanStoreError::NotFound);
        };
        let prepared = PreparedPlan::decode(&bytes).map_err(|_| PlanStoreError::Unavailable)?;
        if prepared.id() != id {
            return Err(PlanStoreError::Unavailable);
        }
        Ok(bytes)
    }
}

fn stored(plan: &PreparedPlan, inserted: bool) -> StoredPlan {
    StoredPlan {
        id: plan.id().clone(),
        kind: plan.kind(),
        digest: plan.digest(),
        inserted,
    }
}

fn store_error(error: ErrorCode) -> PlanStoreError {
    match error {
        ErrorCode::UnauthorizedPeer => PlanStoreError::Unauthorized,
        ErrorCode::InvalidRequest => PlanStoreError::InvalidPlan,
        _ => PlanStoreError::Unavailable,
    }
}

fn initialize(directory: &Path) -> Result<Connection, PlanStoreError> {
    for name in [
        DATABASE,
        "plans.sqlite-wal",
        "plans.sqlite-shm",
        "plans.sqlite-journal",
    ] {
        match fs::symlink_metadata(directory.join(name)) {
            Ok(_) => return Err(PlanStoreError::Unavailable),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(PlanStoreError::Unavailable),
        }
    }
    let path = directory.join(DATABASE);
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|_| PlanStoreError::Unavailable)?;
    let mut connection = Connection::open_with_flags(&path, flags(false))
        .map_err(|_| PlanStoreError::Unavailable)?;
    storage::configure(&connection).map_err(|_| PlanStoreError::Unavailable)?;
    let transaction = connection
        .transaction()
        .map_err(|_| PlanStoreError::Unavailable)?;
    for (_, sql) in SCHEMA {
        transaction
            .execute_batch(sql)
            .map_err(|_| PlanStoreError::Unavailable)?;
    }
    transaction
        .execute("INSERT INTO schema_version VALUES(1,1)", [])
        .map_err(|_| PlanStoreError::Unavailable)?;
    transaction
        .pragma_update(None, "application_id", APPLICATION_ID)
        .map_err(|_| PlanStoreError::Unavailable)?;
    transaction
        .pragma_update(None, "user_version", 1)
        .map_err(|_| PlanStoreError::Unavailable)?;
    transaction
        .commit()
        .map_err(|_| PlanStoreError::Unavailable)?;
    Ok(connection)
}

fn open(directory: &Path) -> Result<Connection, PlanStoreError> {
    check_files(directory)?;
    let path = directory.join(DATABASE);
    let probe =
        Connection::open_with_flags(&path, flags(true)).map_err(|_| PlanStoreError::Unavailable)?;
    probe
        .pragma_update(None, "trusted_schema", false)
        .map_err(|_| PlanStoreError::Unavailable)?;
    validate(&probe)?;
    drop(probe);
    let connection =
        Connection::open_with_flags(path, flags(false)).map_err(|_| PlanStoreError::Unavailable)?;
    storage::configure(&connection).map_err(|_| PlanStoreError::Unavailable)?;
    validate(&connection)?;
    Ok(connection)
}

fn check_files(directory: &Path) -> Result<(), PlanStoreError> {
    let uid = local::operator_uid().map_err(|_| PlanStoreError::Unauthorized)?;
    for name in [DATABASE, "plans.sqlite-wal", "plans.sqlite-shm"] {
        match fs::symlink_metadata(directory.join(name)) {
            Ok(metadata)
                if metadata.is_file()
                    && metadata.uid() == uid
                    && metadata.mode() & 0o7777 == 0o600
                    && metadata.nlink() == 1 => {}
            Ok(_) => return Err(PlanStoreError::Unauthorized),
            Err(error) if error.kind() == io::ErrorKind::NotFound && name != DATABASE => {}
            Err(_) => return Err(PlanStoreError::Unavailable),
        }
    }
    Ok(())
}

fn validate(connection: &Connection) -> Result<(), PlanStoreError> {
    let application: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(|_| PlanStoreError::Unavailable)?;
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| PlanStoreError::Unavailable)?;
    if application != APPLICATION_ID || version != 1 {
        return Err(PlanStoreError::Unavailable);
    }
    let mut statement = connection
        .prepare("SELECT name,sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY name")
        .map_err(|_| PlanStoreError::Unavailable)?;
    let actual = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|_| PlanStoreError::Unavailable)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| PlanStoreError::Unavailable)?;
    let mut expected = SCHEMA.map(|(name, sql)| (name.to_owned(), sql.to_owned()));
    expected.sort();
    if actual != expected {
        return Err(PlanStoreError::Unavailable);
    }
    let count: i64 = connection
        .query_row("SELECT count(*) FROM plans", [], |row| row.get(0))
        .map_err(|_| PlanStoreError::Unavailable)?;
    if !(0..=MAX_PLANS).contains(&count) {
        return Err(PlanStoreError::Unavailable);
    }
    let mut rows = connection
        .prepare("SELECT plan_id,kind,digest,bytes FROM plans")
        .map_err(|_| PlanStoreError::Unavailable)?;
    let records = rows
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })
        .map_err(|_| PlanStoreError::Unavailable)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| PlanStoreError::Unavailable)?;
    for (id, kind, digest, bytes) in records {
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(PlanStoreError::Unavailable);
        }
        let prepared = PreparedPlan::decode(&bytes).map_err(|_| PlanStoreError::Unavailable)?;
        if prepared.id().as_str() != id
            || prepared.kind().as_str() != kind
            || prepared.digest().as_str() != digest
            || prepared.as_bytes() != bytes
        {
            return Err(PlanStoreError::Unavailable);
        }
    }
    Ok(())
}

fn flags(read_only: bool) -> OpenFlags {
    (if read_only {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    } else {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    }) | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW
}
