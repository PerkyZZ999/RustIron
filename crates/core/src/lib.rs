//! Coordinator inventory state, without privileged ownership or execution authority.
#![warn(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "W672: production code returns errors; tests may unwrap (clippy.toml)"
)]

use rusqlite::{Connection, OptionalExtension, params};
use rustiron_contracts::{approval::MAX_OBSERVATION_AGE_SECONDS, *};
use std::{
    fs::File,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use storage::unavailable;
mod cursor;
mod plans;
mod storage;

pub use plans::{PlanStore, PlanStoreError, StoredPlan};

/// Effective coordinator settings, not proof of crash/power-loss durability.
#[derive(Debug)]
pub struct StoreStatus {
    /// SQLite WAL journal mode.
    pub journal_mode: String,
    /// SQLite numeric synchronization level (FULL=2).
    pub synchronous: i64,
    /// Effective foreign-key enforcement.
    pub foreign_keys: bool,
    /// Accepted schema version.
    pub schema_version: u16,
    /// Exact linked SQLite implementation version.
    pub sqlite_version: String,
}

/// Single-writer local coordinator inventory. Its records confer no root authority.
pub struct InventoryStore {
    connection: Connection,
    _lock: File,
}

struct Meta {
    instance: String,
    revision: i64,
    report: Option<InventoryProvenance>,
}

impl InventoryStore {
    /// Explicitly creates schema v1 in a private directory; never overwrites a DB.
    pub fn initialize(directory: &Path) -> Result<Self, ErrorCode> {
        let lock = storage::acquire(directory)?;
        let connection = storage::initialize(directory)?;
        Ok(Self {
            connection,
            _lock: lock,
        })
    }
    /// Opens only a valid existing store and verifies schema, settings and records.
    pub fn open(directory: &Path) -> Result<Self, ErrorCode> {
        let lock = storage::acquire(directory)?;
        let connection = storage::open(directory)?;
        let meta = read_meta(&connection)?;
        let records = read_sites(&connection, MAX_INVENTORY_SITES + 1, 0)?;
        if records.len() > MAX_INVENTORY_SITES || (meta.report.is_none() && !records.is_empty()) {
            return Err(ErrorCode::DependencyUnavailable);
        }
        Ok(Self {
            connection,
            _lock: lock,
        })
    }
    /// Returns effective read-back settings without raw database contents.
    pub fn status(&self) -> Result<StoreStatus, ErrorCode> {
        storage::validate_schema(&self.connection)?;
        Ok(StoreStatus {
            journal_mode: self
                .connection
                .pragma_query_value(None, "journal_mode", |row| row.get(0))
                .map_err(unavailable)?,
            synchronous: self
                .connection
                .pragma_query_value(None, "synchronous", |row| row.get(0))
                .map_err(unavailable)?,
            foreign_keys: self
                .connection
                .pragma_query_value::<i64, _>(None, "foreign_keys", |row| row.get(0))
                .map_err(unavailable)?
                == 1,
            schema_version: 1,
            sqlite_version: rusqlite::version().to_owned(),
        })
    }
    /// Atomically replaces one explicit complete report; never adopts host resources.
    pub fn replace(&mut self, snapshot: &InventorySnapshot) -> Result<(), ErrorCode> {
        encode_inventory_snapshot(snapshot).map_err(|_| ErrorCode::InvalidRequest)?;
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(unavailable)?;
        storage::validate_schema(&transaction)?;
        let meta = read_meta(&transaction)?;
        let revision = meta
            .revision
            .checked_add(1)
            .ok_or(ErrorCode::DependencyUnavailable)?;
        transaction
            .execute("DELETE FROM sites", [])
            .map_err(unavailable)?;
        for site in &snapshot.sites {
            transaction
                .execute(
                    "INSERT INTO sites(site_id,name,generation) VALUES(?1,?2,?3)",
                    params![
                        site.site_id.as_str(),
                        site.name.as_str(),
                        site.configuration_generation.as_ref().map(Id::as_str)
                    ],
                )
                .map_err(unavailable)?;
        }
        transaction.execute("UPDATE inventory_meta SET revision=?1,reported_at=?2,source='operator_report',has_snapshot=1 WHERE singleton=1",params![revision,i64::try_from(snapshot.report.reported_at.get()).map_err(unavailable)?]).map_err(unavailable)?;
        transaction.commit().map_err(unavailable)
    }
    /// Reads a stable bounded page; stale/cross-store/rebound tokens are errors.
    pub fn list(&mut self, token: Option<&Id>, limit: PageLimit) -> Result<SitePage, ErrorCode> {
        let transaction = self.connection.transaction().map_err(unavailable)?;
        storage::validate_schema(&transaction)?;
        let meta = read_meta(&transaction)?;
        let report = meta.report.ok_or(ErrorCode::DependencyUnavailable)?;
        let count: i64 = transaction
            .query_row("SELECT count(*) FROM sites", [], |row| row.get(0))
            .map_err(unavailable)?;
        let count = usize::try_from(count).map_err(unavailable)?;
        if count > MAX_INVENTORY_SITES {
            return Err(ErrorCode::DependencyUnavailable);
        }
        let offset = cursor::offset(token, &meta.instance, meta.revision, limit, count)?;
        let sites = read_sites(&transaction, usize::from(limit.get()), offset)?;
        let next = offset + sites.len();
        let next_cursor = if next < count {
            Some(cursor::create(&meta.instance, meta.revision, next, limit)?)
        } else {
            None
        };
        let items = sites
            .into_iter()
            .map(|site| summary(site, report.clone()))
            .collect();
        transaction.commit().map_err(unavailable)?;
        Ok(SitePage { items, next_cursor })
    }
    /// Reads one reported site and an explicitly inferred generation reference.
    pub fn inspect(&mut self, site_id: &Id) -> Result<SiteDetail, ErrorCode> {
        let transaction = self.connection.transaction().map_err(unavailable)?;
        storage::validate_schema(&transaction)?;
        let report = read_meta(&transaction)?
            .report
            .ok_or(ErrorCode::DependencyUnavailable)?;
        let raw = transaction
            .query_row(
                "SELECT site_id,name,generation FROM sites WHERE site_id=?1",
                params![site_id.as_str()],
                raw_site,
            )
            .optional()
            .map_err(unavailable)?
            .ok_or(ErrorCode::NotFound)?;
        let site = decode_site(raw)?;
        let configuration_generation = match &site.configuration_generation {
            Some(value) => generation_label(value.clone(), report.reported_at),
            None => Observation::Unknown {
                reason: UnknownReason::NotChecked,
            },
        };
        transaction.commit().map_err(unavailable)?;
        Ok(SiteDetail {
            site: summary(site, report),
            configuration_generation,
        })
    }
    /// Exports a consistent metadata snapshot, not an executor ownership manifest.
    pub fn export(&mut self) -> Result<InventorySnapshot, ErrorCode> {
        let transaction = self.connection.transaction().map_err(unavailable)?;
        storage::validate_schema(&transaction)?;
        let report = read_meta(&transaction)?
            .report
            .ok_or(ErrorCode::DependencyUnavailable)?;
        let sites = read_sites(&transaction, MAX_INVENTORY_SITES + 1, 0)?;
        let snapshot = InventorySnapshot {
            schema_version: SchemaVersion::V1,
            report,
            complete: true,
            sites,
        };
        snapshot.validate().map_err(unavailable)?;
        transaction.commit().map_err(unavailable)?;
        Ok(snapshot)
    }
}

fn generation_label(value: Id, reported_at: Timestamp) -> Observation<Id> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| Timestamp::try_from(elapsed.as_secs()).ok());
    let Some(now) = now else {
        return Observation::Unknown {
            reason: UnknownReason::Unavailable,
        };
    };
    if reported_at.get() > now.get()
        || now.get().saturating_sub(reported_at.get()) > MAX_OBSERVATION_AGE_SECONDS
    {
        return Observation::Stale {
            value,
            observed_at: reported_at,
            source: ObservationSource::Inventory,
        };
    }
    Observation::Inferred {
        value,
        observed_at: reported_at,
        source: ObservationSource::Inventory,
    }
}

fn summary(site: ReportedSite, report: InventoryProvenance) -> SiteSummary {
    SiteSummary {
        site_id: site.site_id,
        name: site.name,
        ownership: Ownership::ObservedOnly,
        inventory: Some(report),
    }
}

fn read_meta(connection: &Connection) -> Result<Meta, ErrorCode> {
    let (instance,revision,time,source,present):(String,i64,Option<i64>,Option<String>,i64)=connection.query_row("SELECT instance,revision,reported_at,source,has_snapshot FROM inventory_meta WHERE singleton=1",[],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?))).map_err(unavailable)?;
    if instance.len() != 32 || !instance.bytes().all(|b| b.is_ascii_hexdigit()) || revision < 0 {
        return Err(ErrorCode::DependencyUnavailable);
    }
    let report = match (present, time, source.as_deref()) {
        (0, None, None) => None,
        (1, Some(time), Some("operator_report")) => Some(InventoryProvenance {
            reported_at: Timestamp::try_from(u64::try_from(time).map_err(unavailable)?)
                .map_err(unavailable)?,
            source: InventorySource::OperatorReport,
        }),
        _ => return Err(ErrorCode::DependencyUnavailable),
    };
    Ok(Meta {
        instance,
        revision,
        report,
    })
}

type RawSite = (String, String, Option<String>);
fn raw_site(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawSite> {
    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
}
fn decode_site((id, name, generation): RawSite) -> Result<ReportedSite, ErrorCode> {
    Ok(ReportedSite {
        site_id: Id::try_from(id).map_err(unavailable)?,
        name: Text::try_from(name).map_err(unavailable)?,
        configuration_generation: generation
            .map(Id::try_from)
            .transpose()
            .map_err(unavailable)?,
    })
}
fn read_sites(
    connection: &Connection,
    limit: usize,
    offset: usize,
) -> Result<Vec<ReportedSite>, ErrorCode> {
    let mut statement=connection.prepare("SELECT site_id,name,generation FROM sites ORDER BY site_id COLLATE BINARY LIMIT ?1 OFFSET ?2").map_err(unavailable)?;
    let raw = statement
        .query_map(params![limit as i64, offset as i64], raw_site)
        .map_err(unavailable)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(unavailable)?;
    raw.into_iter().map(decode_site).collect()
}
