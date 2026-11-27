//! Signed changes of a site's quota (schema v35, W534, D-088).
//!
//! A signed change records its intent before the admin helper sets the
//! limits, in the same transaction that rechecks the site: it must be
//! owned (`succeeded` or `adopted`), not ejected, and have no open change.
//! The site's recorded limits are then the newest done change, or the
//! provision's when there is none. Nothing here touches a host.

use rusqlite::{OptionalExtension, params};
use rustiron_contracts::{
    Id, Timestamp,
    approval::{Sha256Digest, SiteId},
};

use crate::{Admitted, FixtureJournal, JournalError, StepState, provision, storage};

/// An admitted signed quota change; built by the executor from verified
/// inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotaChangeIntent {
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
    /// The site, as signed.
    pub site_id: SiteId,
    /// The new hard block limit in KiB, as signed.
    pub block_hard_kib: u64,
    /// The new hard inode limit, as signed.
    pub inode_hard: u64,
    /// Normal grant deadline.
    pub expires_at: Timestamp,
}

/// One recorded quota change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotaChange {
    /// The change's operation.
    pub operation_id: Id,
    /// The site.
    pub site_id: SiteId,
    /// The signed hard block limit in KiB.
    pub block_hard_kib: u64,
    /// The signed hard inode limit.
    pub inode_hard: u64,
    /// `intent` until its outcome is observed.
    pub state: StepState,
}

const COLUMNS: &str = "operation_id, site_id, idempotency_key, grant_id, nonce, plan_digest, grant_digest, block_hard_kib, inode_hard, expires_at, state";

fn state_of(text: &str) -> Result<StepState, JournalError> {
    match text {
        "intent" => Ok(StepState::Intent),
        "done" => Ok(StepState::Done),
        "failed" => Ok(StepState::Failed),
        _ => Err(JournalError::Unavailable),
    }
}

type Row = (Vec<String>, [i64; 3], String);

fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    let texts = (0..7)
        .map(|index| row.get::<_, String>(index))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((texts, [row.get(7)?, row.get(8)?, row.get(9)?], row.get(10)?))
}

fn change(texts: &[String], numbers: [i64; 3], state: &str) -> Result<QuotaChange, JournalError> {
    Ok(QuotaChange {
        operation_id: Id::try_from(texts[0].clone()).map_err(|_| JournalError::Unavailable)?,
        site_id: SiteId::try_from(texts[1].clone()).map_err(|_| JournalError::Unavailable)?,
        block_hard_kib: u64::try_from(numbers[0]).map_err(|_| JournalError::Unavailable)?,
        inode_hard: u64::try_from(numbers[1]).map_err(|_| JournalError::Unavailable)?,
        state: state_of(state)?,
    })
}

fn select(
    c: &rusqlite::Connection,
    filter: &str,
    value: &str,
) -> Result<Option<Row>, JournalError> {
    c.query_row(
        &format!("SELECT {COLUMNS} FROM quota_changes WHERE {filter} ORDER BY rowid DESC LIMIT 1"),
        [value],
        read_row,
    )
    .optional()
    .map_err(storage::unavailable)
}

/// The open change of a site, if one is recorded.
pub(crate) fn open_for_site(
    c: &rusqlite::Connection,
    site: &str,
) -> Result<Option<QuotaChange>, JournalError> {
    let row = c
        .query_row(
            &format!("SELECT {COLUMNS} FROM quota_changes WHERE site_id=?1 AND state='intent'"),
            [site],
            read_row,
        )
        .optional()
        .map_err(storage::unavailable)?;
    row.map(|(texts, numbers, state)| change(&texts, numbers, &state))
        .transpose()
}

/// The newest done change of a site: its hard limits (KiB, inodes).
pub(crate) fn latest_limits(
    c: &rusqlite::Connection,
    site: &str,
) -> Result<Option<(u64, u64)>, JournalError> {
    let row = c
        .query_row(
            "SELECT block_hard_kib, inode_hard FROM quota_changes WHERE site_id=?1 AND state='done' \
             ORDER BY rowid DESC LIMIT 1",
            [site],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(storage::unavailable)?;
    row.map(|(kib, inodes)| {
        Ok((
            u64::try_from(kib).map_err(|_| JournalError::Unavailable)?,
            u64::try_from(inodes).map_err(|_| JournalError::Unavailable)?,
        ))
    })
    .transpose()
}

/// Every change belongs to a provision that is owned or was deleted after
/// it.
pub(crate) fn validate(c: &rusqlite::Connection) -> Result<(), JournalError> {
    let invalid: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM quota_changes q LEFT JOIN provisions p ON p.site_id=q.site_id \
             WHERE p.state IS NULL OR p.state NOT IN ('succeeded','adopted','deleted'))",
            [],
            |row| row.get(0),
        )
        .map_err(storage::unavailable)?;
    if invalid {
        return Err(JournalError::Unavailable);
    }
    Ok(())
}

impl FixtureJournal {
    /// Records a new quota change, or returns the exact earlier one. The
    /// site must be owned, not ejected, and have no open change.
    pub fn record_quota_change(
        &mut self,
        intent: &QuotaChangeIntent,
        now: Timestamp,
    ) -> Result<Admitted<QuotaChange>, JournalError> {
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
                    intent.site_id.as_str(),
                    intent.idempotency_key.as_str(),
                    intent.grant_id.as_str(),
                    intent.nonce.as_str(),
                    intent.plan_digest.as_str(),
                    intent.grant_digest.as_str(),
                ]
                && numbers
                    == [
                        intent.block_hard_kib as i64,
                        intent.inode_hard as i64,
                        intent.expires_at.get() as i64,
                    ];
            return if exact {
                Ok(Admitted::Existing(change(&texts, numbers, &state)?))
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
        let owned = provision::by_site(&transaction, &intent.site_id)?
            .is_some_and(|provision| provision.state.is_owned());
        let ejected = provision::ejected(&transaction)?.contains(&intent.site_id);
        let open: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM quota_changes WHERE site_id=?1 AND state='intent') \
                 OR EXISTS(SELECT 1 FROM site_restores WHERE site_id=?1 AND state='intent') \
                 OR EXISTS(SELECT 1 FROM credential_rotations WHERE site_id=?1 AND state IN ('intent','needs_attention'))",
                [intent.site_id.as_str()],
                |row| row.get(0),
            )
            .map_err(storage::unavailable)?;
        if !owned || ejected || open {
            return Err(JournalError::Consumed);
        }
        storage::check_clock(&transaction, now)?;
        if now.get() >= intent.expires_at.get() {
            return Err(JournalError::Expired);
        }
        transaction
            .execute(
                &format!("INSERT INTO quota_changes ({COLUMNS}) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'intent')"),
                params![
                    intent.operation_id.as_str(),
                    intent.site_id.as_str(),
                    intent.idempotency_key.as_str(),
                    intent.grant_id.as_str(),
                    intent.nonce.as_str(),
                    intent.plan_digest.as_str(),
                    intent.grant_digest.as_str(),
                    intent.block_hard_kib as i64,
                    intent.inode_hard as i64,
                    intent.expires_at.get() as i64,
                ],
            )
            .map_err(storage::unavailable)?;
        crate::signed::insert(&transaction, &intent.operation_id, signed.as_ref())?;
        storage::set_clock(&transaction, now)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(Admitted::New(QuotaChange {
            operation_id: intent.operation_id.clone(),
            site_id: intent.site_id.clone(),
            block_hard_kib: intent.block_hard_kib,
            inode_hard: intent.inode_hard,
            state: StepState::Intent,
        }))
    }

    /// Records the observed outcome of an open quota change.
    pub fn finish_quota_change(
        &mut self,
        operation_id: &Id,
        done: bool,
    ) -> Result<QuotaChange, JournalError> {
        let changed = self
            .connection
            .execute(
                "UPDATE quota_changes SET state=?1 WHERE operation_id=?2 AND state='intent'",
                params![if done { "done" } else { "failed" }, operation_id.as_str()],
            )
            .map_err(storage::unavailable)?;
        if changed != 1 {
            return Err(JournalError::Conflict);
        }
        self.quota_change_status(operation_id)?
            .ok_or(JournalError::Unavailable)
    }

    /// A recorded quota change by its own operation.
    pub fn quota_change_status(
        &self,
        operation_id: &Id,
    ) -> Result<Option<QuotaChange>, JournalError> {
        select(&self.connection, "operation_id=?1", operation_id.as_str())?
            .map(|(texts, numbers, state)| change(&texts, numbers, &state))
            .transpose()
    }

    /// The site's newest done quota change: its hard limits (KiB, inodes).
    pub fn latest_quota_limits(&self, site: &SiteId) -> Result<Option<(u64, u64)>, JournalError> {
        latest_limits(&self.connection, site.as_str())
    }
}
