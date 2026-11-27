//! Signed per-site credential rotation ledger (schema v44, W608, D-100).
//!
//! Records durable intent and observed outcome for closed `site_credential_rotate`
//! operations (`mariadb_user_password`) on owned, live, non-ejected WordPress
//! sites. Secret password values are never passed to or stored in the journal.
//!
//! An unresolved rotation (`intent` or `needs_attention`) blocks further
//! rotations and conflicting site mutations until settled or reconciled.

use rusqlite::{OptionalExtension, params};
use rustiron_contracts::{
    Id, Timestamp,
    approval::{CredentialTarget, Hostname, Sha256Digest, SiteId},
};

use crate::{Admitted, FixtureJournal, JournalError, app, import, provision, proxy, storage};

/// An admitted signed credential rotation; built by the executor from verified
/// inputs. Contains no secret material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRotateIntent {
    /// The rotation's operation id.
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
    /// Target site, as signed.
    pub site_id: SiteId,
    /// Target hostname, as signed.
    pub hostname: Hostname,
    /// Closed credential target, as signed.
    pub target: CredentialTarget,
    /// Normal grant deadline.
    pub expires_at: Timestamp,
}

/// Durable recorded state of a credential rotation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialRotateState {
    /// Intent recorded; host rotation may have begun.
    Intent,
    /// New password verified in MariaDB + `private/db.cnf`, PHP restarted, old
    /// password rejected, site healthy.
    Done,
    /// Rotation failed after MariaDB password change; bounded 1-attempt
    /// compensation restored the prior password and `private/db.cnf` and
    /// verified site health.
    FailedCompensated,
    /// Host database password vs `private/db.cnf` state is uncertain after a
    /// failure or interrupted run; blocks the site until operator reconcile.
    NeedsAttention,
    /// Failed before changing the host database password or settled as
    /// unchanged by operator reconciliation.
    Failed,
}

impl CredentialRotateState {
    /// Stable SQLite/wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::Done => "done",
            Self::FailedCompensated => "failed_compensated",
            Self::NeedsAttention => "needs_attention",
            Self::Failed => "failed",
        }
    }

    /// Whether this rotation still blocks conflicting mutations on the site.
    pub const fn is_open(self) -> bool {
        matches!(self, Self::Intent | Self::NeedsAttention)
    }

    /// Whether this state is terminal (settled).
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Done | Self::FailedCompensated | Self::Failed)
    }
}

/// One recorded credential rotation (contains no password material).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRotation {
    /// The rotation's operation id.
    pub operation_id: Id,
    /// Target site.
    pub site_id: SiteId,
    /// Target hostname bound to the site.
    pub hostname: Hostname,
    /// Closed credential target.
    pub target: CredentialTarget,
    /// Durable state.
    pub state: CredentialRotateState,
}

const COLUMNS: &str = "operation_id, site_id, hostname, target, idempotency_key, grant_id, nonce, plan_digest, grant_digest, expires_at, state";

fn state_of(text: &str) -> Result<CredentialRotateState, JournalError> {
    match text {
        "intent" => Ok(CredentialRotateState::Intent),
        "done" => Ok(CredentialRotateState::Done),
        "failed_compensated" => Ok(CredentialRotateState::FailedCompensated),
        "needs_attention" => Ok(CredentialRotateState::NeedsAttention),
        "failed" => Ok(CredentialRotateState::Failed),
        _ => Err(JournalError::Unavailable),
    }
}

fn target_of(text: &str) -> Result<CredentialTarget, JournalError> {
    match text {
        "mariadb_user_password" => Ok(CredentialTarget::MariadbUserPassword),
        "app_mariadb_password" => Ok(CredentialTarget::AppMariadbPassword),
        "app_postgresql_18_password" => Ok(CredentialTarget::AppPostgresql18Password),
        _ => Err(JournalError::Unavailable),
    }
}

type Row = (Vec<String>, i64, String);

fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    let texts = (0..9)
        .map(|index| row.get::<_, String>(index))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((texts, row.get(9)?, row.get(10)?))
}

fn rotation(texts: &[String], state: &str) -> Result<CredentialRotation, JournalError> {
    Ok(CredentialRotation {
        operation_id: Id::try_from(texts[0].clone()).map_err(|_| JournalError::Unavailable)?,
        site_id: SiteId::try_from(texts[1].clone()).map_err(|_| JournalError::Unavailable)?,
        hostname: Hostname::try_from(texts[2].clone()).map_err(|_| JournalError::Unavailable)?,
        target: target_of(&texts[3])?,
        state: state_of(state)?,
    })
}

fn select(
    c: &rusqlite::Connection,
    filter: &str,
    value: &str,
) -> Result<Option<Row>, JournalError> {
    c.query_row(
        &format!(
            "SELECT {COLUMNS} FROM credential_rotations WHERE {filter} ORDER BY rowid DESC LIMIT 1"
        ),
        [value],
        read_row,
    )
    .optional()
    .map_err(storage::unavailable)
}

/// Loads one credential rotation by operation id, if any.
pub(crate) fn by_operation(
    c: &rusqlite::Connection,
    operation_id: &Id,
) -> Result<Option<CredentialRotation>, JournalError> {
    select(c, "operation_id=?1", operation_id.as_str())?
        .map(|(texts, _, state)| rotation(&texts, &state))
        .transpose()
}

/// On open: every rotation belongs to a provision that is owned or was deleted
/// after it, and its hostname matches that provision's hostname.
pub(crate) fn validate(c: &rusqlite::Connection) -> Result<(), JournalError> {
    let invalid: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM credential_rotations r \
             LEFT JOIN provisions p ON p.site_id=r.site_id \
             WHERE p.state IS NULL OR p.state NOT IN ('succeeded','adopted','deleted') \
             OR p.hostname<>r.hostname)",
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
    /// Records a new credential rotation intent, or returns the exact earlier
    /// one. Refuses non-owned, ejected, static, proxy, app, or hostname-mismatched
    /// sites and sites with an open conflicting operation before inserting any row.
    pub fn record_credential_rotation(
        &mut self,
        intent: &CredentialRotateIntent,
        now: Timestamp,
    ) -> Result<Admitted<CredentialRotation>, JournalError> {
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
        if let Some((texts, expires_at, state)) = found {
            let exact = texts[..]
                == [
                    intent.operation_id.as_str(),
                    intent.site_id.as_str(),
                    intent.hostname.as_str(),
                    intent.target.as_str(),
                    intent.idempotency_key.as_str(),
                    intent.grant_id.as_str(),
                    intent.nonce.as_str(),
                    intent.plan_digest.as_str(),
                    intent.grant_digest.as_str(),
                ]
                && expires_at == intent.expires_at.get() as i64;
            return if exact {
                Ok(Admitted::Existing(rotation(&texts, &state)?))
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
        if storage::readoption_verifying(&transaction)? {
            return Err(JournalError::Consumed);
        }
        let Some(provision) = provision::by_site(&transaction, &intent.site_id)? else {
            return Err(JournalError::Consumed);
        };
        if !provision.state.is_owned() || provision.intent.hostname != intent.hostname {
            return Err(JournalError::Consumed);
        }
        let ejected = provision::ejected(&transaction)?.contains(&intent.site_id);
        let is_proxy = proxy::facts(&transaction, &provision.intent.operation_id)?.is_some();
        let is_app = app::facts(&transaction, &provision.intent.operation_id)?.is_some();
        let is_static = import::load(&transaction, &provision.intent.operation_id)?
            .is_some_and(|imp| imp.facts.is_static());
        if ejected || is_proxy || is_app || is_static {
            return Err(JournalError::Consumed);
        }
        let open: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM credential_rotations WHERE site_id=?1 AND state IN ('intent','needs_attention')) \
                 OR EXISTS(SELECT 1 FROM site_restores WHERE site_id=?1 AND state='intent') \
                 OR EXISTS(SELECT 1 FROM updates WHERE site_id=?1 AND state='intent') \
                 OR EXISTS(SELECT 1 FROM captures WHERE site_id=?1 AND state='running') \
                 OR EXISTS(SELECT 1 FROM deletions WHERE provision_operation_id=?2 AND state='intent')",
                params![
                    intent.site_id.as_str(),
                    provision.intent.operation_id.as_str()
                ],
                |row| row.get(0),
            )
            .map_err(storage::unavailable)?;
        if open {
            return Err(JournalError::Consumed);
        }
        storage::check_clock(&transaction, now)?;
        if now.get() >= intent.expires_at.get() {
            return Err(JournalError::Expired);
        }
        transaction
            .execute(
                &format!(
                    "INSERT INTO credential_rotations ({COLUMNS}) \
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'intent')"
                ),
                params![
                    intent.operation_id.as_str(),
                    intent.site_id.as_str(),
                    intent.hostname.as_str(),
                    intent.target.as_str(),
                    intent.idempotency_key.as_str(),
                    intent.grant_id.as_str(),
                    intent.nonce.as_str(),
                    intent.plan_digest.as_str(),
                    intent.grant_digest.as_str(),
                    intent.expires_at.get() as i64,
                ],
            )
            .map_err(storage::unavailable)?;
        crate::signed::insert(&transaction, &intent.operation_id, signed.as_ref())?;
        storage::set_clock(&transaction, now)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(Admitted::New(CredentialRotation {
            operation_id: intent.operation_id.clone(),
            site_id: intent.site_id.clone(),
            hostname: intent.hostname.clone(),
            target: intent.target,
            state: CredentialRotateState::Intent,
        }))
    }

    /// Records the observed outcome of an open (`intent`) credential rotation.
    /// Accepts `Done`, `FailedCompensated`, `NeedsAttention`, or `Failed`.
    pub fn finish_credential_rotation(
        &mut self,
        operation_id: &Id,
        outcome: CredentialRotateState,
    ) -> Result<CredentialRotation, JournalError> {
        if outcome == CredentialRotateState::Intent {
            return Err(JournalError::Conflict);
        }
        let changed = self
            .connection
            .execute(
                "UPDATE credential_rotations SET state=?1 WHERE operation_id=?2 AND state='intent'",
                params![outcome.as_str(), operation_id.as_str()],
            )
            .map_err(storage::unavailable)?;
        if changed != 1 {
            return Err(JournalError::Conflict);
        }
        self.credential_rotation_status(operation_id)?
            .ok_or(JournalError::Unavailable)
    }

    /// Operator reconciliation of an unresolved (`intent` or `needs_attention`)
    /// credential rotation into a terminal state (`Done`, `FailedCompensated`,
    /// or `Failed`).
    pub fn reconcile_credential_rotation(
        &mut self,
        operation_id: &Id,
        outcome: CredentialRotateState,
    ) -> Result<CredentialRotation, JournalError> {
        if !outcome.is_terminal() {
            return Err(JournalError::Conflict);
        }
        let changed = self
            .connection
            .execute(
                "UPDATE credential_rotations SET state=?1 \
                 WHERE operation_id=?2 AND state IN ('intent','needs_attention')",
                params![outcome.as_str(), operation_id.as_str()],
            )
            .map_err(storage::unavailable)?;
        if changed != 1 {
            return Err(JournalError::Conflict);
        }
        self.credential_rotation_status(operation_id)?
            .ok_or(JournalError::Unavailable)
    }

    /// Reads one recorded credential rotation by operation id.
    pub fn credential_rotation_status(
        &self,
        operation_id: &Id,
    ) -> Result<Option<CredentialRotation>, JournalError> {
        by_operation(&self.connection, operation_id)
    }
}
