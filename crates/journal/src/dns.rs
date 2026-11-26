//! Signed DNS zone imports (schema v38, W552, D-091).
//!
//! A signed import records its intent before the admin helper creates the
//! zone, in the transaction that rechecks that no import of the zone is
//! open or done. A zone is owned once its import is done. A failed import
//! leaves the zone unowned, and a new signed import may name it again.
//! Nothing here touches a host.

use rusqlite::{OptionalExtension, params};
use rustiron_contracts::{
    Id, Timestamp,
    approval::{Expected, MAX_CHANGE_OPERATIONS, RecordType, Sha256Digest, ZoneName},
};
use sha2::Digest;

use crate::{FixtureJournal, JournalError, StepState, storage};

/// An admitted signed zone import; built by the executor from verified
/// inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsImportIntent {
    /// The import's operation.
    pub operation_id: Id,
    /// Retry key bound to every field.
    pub idempotency_key: Id,
    /// Signed grant identity.
    pub grant_id: Id,
    /// Single-use signed nonce.
    pub nonce: Id,
    /// Complete plan digest.
    pub plan_digest: Sha256Digest,
    /// Complete canonical grant digest.
    pub grant_digest: Sha256Digest,
    /// Enrolled host identity.
    pub host_id: Id,
    /// Enrolled host epoch.
    pub host_epoch: Id,
    /// The zone, as signed.
    pub zone: ZoneName,
    /// The canonical zone file's SHA-256, as signed.
    pub zone_sha256: Sha256Digest,
    /// The file's record-set count, as signed.
    pub record_sets: u32,
    /// Normal grant deadline.
    pub expires_at: Timestamp,
}

/// One recorded zone import.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsImport {
    /// The import's operation.
    pub operation_id: Id,
    /// The zone.
    pub zone: ZoneName,
    /// The canonical zone file's SHA-256.
    pub zone_sha256: Sha256Digest,
    /// The file's record-set count.
    pub record_sets: u32,
    /// `intent` until its outcome is observed.
    pub state: StepState,
}

/// A new or an exactly repeated zone import.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsImportResult {
    /// Recorded now, in `intent`.
    New(DnsImport),
    /// The same request was recorded before; its stored state.
    Existing(DnsImport),
}

const COLUMNS: &str = "operation_id, zone, zone_sha256, idempotency_key, grant_id, nonce, plan_digest, grant_digest, record_sets, expires_at, state";

fn state_of(text: &str) -> Result<StepState, JournalError> {
    match text {
        "intent" => Ok(StepState::Intent),
        "done" => Ok(StepState::Done),
        "failed" => Ok(StepState::Failed),
        _ => Err(JournalError::Unavailable),
    }
}

type Row = (Vec<String>, [i64; 2], String);

fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    let texts = (0..8)
        .map(|index| row.get::<_, String>(index))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((texts, [row.get(8)?, row.get(9)?], row.get(10)?))
}

fn import(texts: &[String], numbers: [i64; 2], state: &str) -> Result<DnsImport, JournalError> {
    fn bad<E>(_: E) -> JournalError {
        JournalError::Unavailable
    }
    Ok(DnsImport {
        operation_id: Id::try_from(texts[0].clone()).map_err(bad)?,
        zone: ZoneName::try_from(texts[1].clone()).map_err(bad)?,
        zone_sha256: Sha256Digest::try_from(texts[2].clone()).map_err(bad)?,
        record_sets: u32::try_from(numbers[0]).map_err(|_| JournalError::Unavailable)?,
        state: state_of(state)?,
    })
}

fn select(
    c: &rusqlite::Connection,
    filter: &str,
    value: &str,
) -> Result<Option<Row>, JournalError> {
    c.query_row(
        &format!("SELECT {COLUMNS} FROM dns_imports WHERE {filter} ORDER BY rowid DESC LIMIT 1"),
        [value],
        read_row,
    )
    .optional()
    .map_err(storage::unavailable)
}

/// W563: the import an operation id names, for the admin helper.
pub(crate) fn import_by_operation(
    c: &rusqlite::Connection,
    operation_id: &Id,
) -> Result<Option<DnsImport>, JournalError> {
    select(c, "operation_id=?1", operation_id.as_str())?
        .map(|(texts, numbers, state)| import(&texts, numbers, &state))
        .transpose()
}

/// W565: the done import that owns `zone`, if any.
pub(crate) fn owning_import(
    c: &rusqlite::Connection,
    zone: &ZoneName,
) -> Result<Option<Id>, JournalError> {
    c.query_row(
        "SELECT operation_id FROM dns_imports WHERE zone=?1 AND state='done'",
        [zone.as_str()],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(storage::unavailable)?
    .map(|text| Id::try_from(text).map_err(storage::unavailable))
    .transpose()
}

/// W565: the change an operation id names, for the admin helper.
pub(crate) fn change_by_operation(
    c: &rusqlite::Connection,
    operation_id: &Id,
) -> Result<Option<DnsChange>, JournalError> {
    Ok(load_change(c, operation_id.as_str())?.map(|(change, _, _)| change))
}

/// W565: a change's signed plan bytes as stored at admission, only when
/// they hash to the change's recorded plan digest.
pub(crate) fn change_plan(
    c: &rusqlite::Connection,
    operation_id: &Id,
) -> Result<Option<Vec<u8>>, JournalError> {
    let row: Option<(String, String)> = c
        .query_row(
            "SELECT o.canonical, d.plan_digest FROM dns_changes d \
             JOIN admission_signatures a ON a.operation_id=d.operation_id \
             JOIN signed_objects o ON o.sha256=a.plan_sha256 WHERE d.operation_id=?1",
            [operation_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(storage::unavailable)?;
    match row {
        Some((plan, digest)) if crate::signed::plan_matches(plan.as_bytes(), &digest) => {
            Ok(Some(plan.into_bytes()))
        }
        Some(_) => Err(JournalError::Unavailable),
        None => Ok(None),
    }
}

/// The zones whose import is done, in name order.
pub(crate) fn owned_zones(c: &rusqlite::Connection) -> Result<Vec<ZoneName>, JournalError> {
    let mut statement = c
        .prepare("SELECT zone FROM dns_imports WHERE state='done' ORDER BY zone")
        .map_err(storage::unavailable)?;
    let zones = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(storage::unavailable)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage::unavailable)?;
    zones
        .into_iter()
        .map(|zone| ZoneName::try_from(zone).map_err(|_| JournalError::Unavailable))
        .collect()
}

/// Every zone name in the table parses, and each row's zone and digest
/// decode. The schema keeps at most one live import per zone.
pub(crate) fn validate(c: &rusqlite::Connection) -> Result<(), JournalError> {
    let mut statement = c
        .prepare(&format!("SELECT {COLUMNS} FROM dns_imports"))
        .map_err(storage::unavailable)?;
    let rows = statement
        .query_map([], read_row)
        .map_err(storage::unavailable)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage::unavailable)?;
    for (texts, numbers, state) in rows {
        import(&texts, numbers, &state)?;
    }
    validate_changes(c)
}

impl FixtureJournal {
    /// Records a new zone import, or returns the exact earlier one. The
    /// zone must have no open or done import.
    pub fn record_dns_import(
        &mut self,
        intent: &DnsImportIntent,
        now: Timestamp,
    ) -> Result<DnsImportResult, JournalError> {
        let signed = self.take_signed(&crate::signed::Expected {
            plan_digest: &intent.plan_digest,
            grant_digest: &intent.grant_digest,
        })?;
        if intent.host_id != self.host_id || intent.host_epoch != self.host_epoch {
            return Err(JournalError::Conflict);
        }
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let found = match select(
            &transaction,
            "operation_id=?1",
            intent.operation_id.as_str(),
        )? {
            Some(row) => Some(row),
            None => select(
                &transaction,
                "idempotency_key=?1",
                intent.idempotency_key.as_str(),
            )?,
        };
        if let Some((texts, numbers, state)) = found {
            let exact = texts[..]
                == [
                    intent.operation_id.as_str(),
                    intent.zone.as_str(),
                    intent.zone_sha256.as_str(),
                    intent.idempotency_key.as_str(),
                    intent.grant_id.as_str(),
                    intent.nonce.as_str(),
                    intent.plan_digest.as_str(),
                    intent.grant_digest.as_str(),
                ]
                && numbers
                    == [
                        i64::from(intent.record_sets),
                        intent.expires_at.get() as i64,
                    ];
            return if exact {
                Ok(DnsImportResult::Existing(import(&texts, numbers, &state)?))
            } else {
                Err(JournalError::Conflict)
            };
        }
        if storage::consumed_ids(
            &transaction,
            &intent.operation_id,
            &intent.grant_id,
            &intent.nonce,
        )? {
            return Err(JournalError::Conflict);
        }
        let live: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM dns_imports WHERE zone=?1 AND state<>'failed')",
                [intent.zone.as_str()],
                |row| row.get(0),
            )
            .map_err(storage::unavailable)?;
        if live {
            return Err(JournalError::Consumed);
        }
        storage::check_clock(&transaction, now)?;
        if now.get() >= intent.expires_at.get() {
            return Err(JournalError::Expired);
        }
        transaction
            .execute(
                &format!(
                    "INSERT INTO dns_imports ({COLUMNS}) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'intent')"
                ),
                params![
                    intent.operation_id.as_str(),
                    intent.zone.as_str(),
                    intent.zone_sha256.as_str(),
                    intent.idempotency_key.as_str(),
                    intent.grant_id.as_str(),
                    intent.nonce.as_str(),
                    intent.plan_digest.as_str(),
                    intent.grant_digest.as_str(),
                    i64::from(intent.record_sets),
                    intent.expires_at.get() as i64,
                ],
            )
            .map_err(storage::unavailable)?;
        crate::signed::insert(&transaction, &intent.operation_id, signed.as_ref())?;
        storage::set_clock(&transaction, now)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(DnsImportResult::New(DnsImport {
            operation_id: intent.operation_id.clone(),
            zone: intent.zone.clone(),
            zone_sha256: intent.zone_sha256.clone(),
            record_sets: intent.record_sets,
            state: StepState::Intent,
        }))
    }

    /// Records the observed outcome of an open zone import.
    pub fn finish_dns_import(
        &mut self,
        operation_id: &Id,
        done: bool,
    ) -> Result<DnsImport, JournalError> {
        let changed = self
            .connection
            .execute(
                "UPDATE dns_imports SET state=?1 WHERE operation_id=?2 AND state='intent'",
                params![if done { "done" } else { "failed" }, operation_id.as_str()],
            )
            .map_err(storage::unavailable)?;
        if changed != 1 {
            return Err(JournalError::Conflict);
        }
        self.dns_import_status(operation_id)?
            .ok_or(JournalError::Unavailable)
    }

    /// A recorded zone import by its own operation.
    pub fn dns_import_status(&self, operation_id: &Id) -> Result<Option<DnsImport>, JournalError> {
        import_by_operation(&self.connection, operation_id)
    }

    /// The zones Rustiron owns: each one's import is done.
    pub fn owned_dns_zones(&self) -> Result<Vec<ZoneName>, JournalError> {
        owned_zones(&self.connection)
    }

    /// W565: a change's signed plan bytes, checked against its digest.
    pub fn dns_change_plan(&self, operation_id: &Id) -> Result<Option<Vec<u8>>, JournalError> {
        change_plan(&self.connection, operation_id)
    }

    /// W565: the done import that owns `zone`, if any.
    pub fn owning_dns_import(&self, zone: &ZoneName) -> Result<Option<Id>, JournalError> {
        owning_import(&self.connection, zone)
    }
}

/// W554 (v39): one record-set operation of an admitted change, with the
/// set the executor read before intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsChangeSet {
    /// The absolute owner name.
    pub owner: String,
    /// The set's type.
    pub kind: RecordType,
    /// The set the signed operation expects.
    pub expected: Expected,
    /// The set's canonical lines read before intent, or `None` when absent.
    pub before: Option<String>,
    /// The set's canonical lines read back after the effect, or `None`
    /// when absent; unset while the change is open.
    pub after: Option<String>,
}

/// W554: an admitted signed record change; built by the executor from
/// verified inputs and the sets it read before intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsChangeIntent {
    /// The change's operation.
    pub operation_id: Id,
    /// Retry key bound to every field.
    pub idempotency_key: Id,
    /// Signed grant identity.
    pub grant_id: Id,
    /// Single-use signed nonce.
    pub nonce: Id,
    /// Complete plan digest.
    pub plan_digest: Sha256Digest,
    /// Complete canonical grant digest.
    pub grant_digest: Sha256Digest,
    /// Enrolled host identity.
    pub host_id: Id,
    /// Enrolled host epoch.
    pub host_epoch: Id,
    /// The owned zone, as signed.
    pub zone: ZoneName,
    /// The operations in plan order; `after` is `None` here.
    pub sets: Vec<DnsChangeSet>,
    /// Normal grant deadline.
    pub expires_at: Timestamp,
}

/// W554: one recorded record change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsChange {
    /// The change's operation.
    pub operation_id: Id,
    /// The zone.
    pub zone: ZoneName,
    /// The operations in plan order.
    pub sets: Vec<DnsChangeSet>,
    /// `intent` until its outcome is observed.
    pub state: StepState,
}

/// W554: a new or an exactly repeated record change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsChangeResult {
    /// Recorded now, in `intent`.
    New(DnsChange),
    /// The same request was recorded before; its stored state.
    Existing(DnsChange),
}

fn expected_text(expected: &Expected) -> String {
    match expected {
        Expected::Absent => "absent".to_owned(),
        Expected::Digest(digest) => digest.as_str().to_owned(),
    }
}

fn set_digest(text: &str) -> Sha256Digest {
    Sha256Digest::from_bytes(sha2::Sha256::digest(text.as_bytes()).into())
}

/// The before set agrees with what the operation expected: absent, or the
/// canonical lines with the expected digest.
fn before_fits(set: &DnsChangeSet) -> bool {
    match (&set.expected, &set.before) {
        (Expected::Absent, None) => true,
        (Expected::Digest(digest), Some(text)) => set_digest(text) == *digest,
        _ => false,
    }
}

fn load_change(
    c: &rusqlite::Connection,
    operation_id: &str,
) -> Result<Option<(DnsChange, [String; 5], i64)>, JournalError> {
    let row = c
        .query_row(
            "SELECT zone, idempotency_key, grant_id, nonce, plan_digest, grant_digest, expires_at, state \
             FROM dns_changes WHERE operation_id=?1",
            [operation_id],
            |row| {
                Ok((
                    (0..6)
                        .map(|index| row.get::<_, String>(index))
                        .collect::<Result<Vec<_>, _>>()?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                ))
            },
        )
        .optional()
        .map_err(storage::unavailable)?;
    let Some((texts, expires_at, state)) = row else {
        return Ok(None);
    };
    let bad = |_| JournalError::Unavailable;
    let mut statement = c
        .prepare(
            "SELECT position, owner, type, expected, before, after FROM dns_change_sets \
             WHERE operation_id=?1 ORDER BY position",
        )
        .map_err(storage::unavailable)?;
    let rows = statement
        .query_map([operation_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
            ))
        })
        .map_err(storage::unavailable)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage::unavailable)?;
    let sets = rows
        .into_iter()
        .enumerate()
        .map(
            |(index, (position, owner, kind, expected, before, after))| {
                if position != index as i64 {
                    return Err(JournalError::Unavailable);
                }
                let kind = [
                    RecordType::A,
                    RecordType::Aaaa,
                    RecordType::Cname,
                    RecordType::Mx,
                    RecordType::Txt,
                    RecordType::Srv,
                    RecordType::Caa,
                ]
                .into_iter()
                .find(|candidate| candidate.as_str() == kind)
                .ok_or(JournalError::Unavailable)?;
                Ok(DnsChangeSet {
                    owner,
                    kind,
                    expected: Expected::try_from(expected)
                        .map_err(|_| JournalError::Unavailable)?,
                    before,
                    after,
                })
            },
        )
        .collect::<Result<Vec<_>, _>>()?;
    let change = DnsChange {
        operation_id: Id::try_from(operation_id.to_owned()).map_err(bad)?,
        zone: ZoneName::try_from(texts[0].clone()).map_err(|_| JournalError::Unavailable)?,
        sets,
        state: state_of(&state)?,
    };
    let keys = [
        texts[1].clone(),
        texts[2].clone(),
        texts[3].clone(),
        texts[4].clone(),
        texts[5].clone(),
    ];
    Ok(Some((change, keys, expires_at)))
}

/// Every change has 1 to 16 sets whose before set agrees with what was
/// expected, and names a zone whose import is done. A null `after` is an
/// absent set, or, for a failed change, a set not read back.
pub(crate) fn validate_changes(c: &rusqlite::Connection) -> Result<(), JournalError> {
    let mut statement = c
        .prepare("SELECT operation_id FROM dns_changes")
        .map_err(storage::unavailable)?;
    let operations = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(storage::unavailable)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage::unavailable)?;
    for operation in operations {
        let (change, _, _) = load_change(c, &operation)?.ok_or(JournalError::Unavailable)?;
        let owned: bool = c
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM dns_imports WHERE zone=?1 AND state='done')",
                [change.zone.as_str()],
                |row| row.get(0),
            )
            .map_err(storage::unavailable)?;
        if !owned
            || !(1..=MAX_CHANGE_OPERATIONS).contains(&change.sets.len())
            || !change.sets.iter().all(before_fits)
        {
            return Err(JournalError::Unavailable);
        }
    }
    Ok(())
}

impl FixtureJournal {
    /// W554: records a new record change with the sets read before intent,
    /// or returns the exact earlier one. The zone must be owned, have no
    /// open change, and each set read must agree with what the operation
    /// expects.
    pub fn record_dns_change(
        &mut self,
        intent: &DnsChangeIntent,
        now: Timestamp,
    ) -> Result<DnsChangeResult, JournalError> {
        let signed = self.take_signed(&crate::signed::Expected {
            plan_digest: &intent.plan_digest,
            grant_digest: &intent.grant_digest,
        })?;
        if intent.host_id != self.host_id
            || intent.host_epoch != self.host_epoch
            || !(1..=MAX_CHANGE_OPERATIONS).contains(&intent.sets.len())
            || intent.sets.iter().any(|set| set.after.is_some())
        {
            return Err(JournalError::Conflict);
        }
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let found: Option<String> = transaction
            .query_row(
                "SELECT operation_id FROM dns_changes WHERE operation_id=?1 OR idempotency_key=?2",
                params![
                    intent.operation_id.as_str(),
                    intent.idempotency_key.as_str()
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage::unavailable)?;
        if let Some(operation) = found {
            let (stored, keys, expires_at) =
                load_change(&transaction, &operation)?.ok_or(JournalError::Unavailable)?;
            let exact = stored.operation_id == intent.operation_id
                && stored.zone == intent.zone
                && keys
                    == [
                        intent.idempotency_key.as_str().to_owned(),
                        intent.grant_id.as_str().to_owned(),
                        intent.nonce.as_str().to_owned(),
                        intent.plan_digest.as_str().to_owned(),
                        intent.grant_digest.as_str().to_owned(),
                    ]
                && expires_at == intent.expires_at.get() as i64
                && stored.sets.len() == intent.sets.len()
                && stored.sets.iter().zip(&intent.sets).all(|(a, b)| {
                    a.owner == b.owner && a.kind == b.kind && a.expected == b.expected
                });
            return if exact {
                Ok(DnsChangeResult::Existing(stored))
            } else {
                Err(JournalError::Conflict)
            };
        }
        if storage::consumed_ids(
            &transaction,
            &intent.operation_id,
            &intent.grant_id,
            &intent.nonce,
        )? {
            return Err(JournalError::Conflict);
        }
        let (owned, open): (bool, bool) = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM dns_imports WHERE zone=?1 AND state='done'), \
                 EXISTS(SELECT 1 FROM dns_changes WHERE zone=?1 AND state='intent')",
                [intent.zone.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(storage::unavailable)?;
        if !owned || open {
            return Err(JournalError::Consumed);
        }
        if !intent.sets.iter().all(before_fits) {
            return Err(JournalError::SourceChanged);
        }
        storage::check_clock(&transaction, now)?;
        if now.get() >= intent.expires_at.get() {
            return Err(JournalError::Expired);
        }
        transaction
            .execute(
                "INSERT INTO dns_changes (operation_id, zone, idempotency_key, grant_id, nonce, \
                 plan_digest, grant_digest, expires_at, state) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'intent')",
                params![
                    intent.operation_id.as_str(),
                    intent.zone.as_str(),
                    intent.idempotency_key.as_str(),
                    intent.grant_id.as_str(),
                    intent.nonce.as_str(),
                    intent.plan_digest.as_str(),
                    intent.grant_digest.as_str(),
                    intent.expires_at.get() as i64,
                ],
            )
            .map_err(storage::unavailable)?;
        for (position, set) in intent.sets.iter().enumerate() {
            transaction
                .execute(
                    "INSERT INTO dns_change_sets VALUES(?1,?2,?3,?4,?5,?6,NULL)",
                    params![
                        intent.operation_id.as_str(),
                        position as i64,
                        set.owner,
                        set.kind.as_str(),
                        expected_text(&set.expected),
                        set.before,
                    ],
                )
                .map_err(storage::unavailable)?;
        }
        crate::signed::insert(&transaction, &intent.operation_id, signed.as_ref())?;
        storage::set_clock(&transaction, now)?;
        let (recorded, _, _) = load_change(&transaction, intent.operation_id.as_str())?
            .ok_or(JournalError::Unavailable)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(DnsChangeResult::New(recorded))
    }

    /// W554: records the outcome of an open change with each set read
    /// back, in plan order. A failed change may hold fewer reads.
    pub fn finish_dns_change(
        &mut self,
        operation_id: &Id,
        done: bool,
        after: &[Option<String>],
    ) -> Result<DnsChange, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let (change, _, _) =
            load_change(&transaction, operation_id.as_str())?.ok_or(JournalError::Conflict)?;
        if change.state != StepState::Intent
            || after.len() > change.sets.len()
            || (done && after.len() != change.sets.len())
        {
            return Err(JournalError::Conflict);
        }
        for (position, text) in after.iter().enumerate() {
            transaction
                .execute(
                    "UPDATE dns_change_sets SET after=?1 WHERE operation_id=?2 AND position=?3",
                    params![text, operation_id.as_str(), position as i64],
                )
                .map_err(storage::unavailable)?;
        }
        transaction
            .execute(
                "UPDATE dns_changes SET state=?1 WHERE operation_id=?2",
                params![if done { "done" } else { "failed" }, operation_id.as_str()],
            )
            .map_err(storage::unavailable)?;
        let (recorded, _, _) =
            load_change(&transaction, operation_id.as_str())?.ok_or(JournalError::Unavailable)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(recorded)
    }

    /// W554: a recorded change by its own operation.
    pub fn dns_change_status(&self, operation_id: &Id) -> Result<Option<DnsChange>, JournalError> {
        Ok(load_change(&self.connection, operation_id.as_str())?.map(|(change, _, _)| change))
    }
}
