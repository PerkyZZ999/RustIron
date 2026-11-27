//! Site retirements (schema v31, W508, D-080).
//!
//! A signed retirement removes what a quarantined provision's recorded steps
//! made. Its intent is committed before any removal, in the same
//! transaction that rechecks the provision: it must still be `quarantined`
//! and have no retirement yet. The provision row stays, so its site ID and
//! hostname stay consumed. Nothing here touches a host.

use rusqlite::{OptionalExtension, params};
use rustiron_contracts::{
    Id, Timestamp,
    approval::{Sha256Digest, SiteId},
};

use crate::{
    Admitted, FixtureJournal, JournalError, ProvisionState, StepState, provision, storage,
};

/// An admitted signed retirement; built by the executor from verified inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetireIntent {
    /// The retirement's operation.
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
    /// The quarantined provision's operation.
    pub provision_operation_id: Id,
    /// Its site, as signed.
    pub site_id: SiteId,
    /// Normal grant deadline.
    pub expires_at: Timestamp,
}

/// One recorded retirement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Retirement {
    /// The retirement's operation.
    pub operation_id: Id,
    /// The retired provision's operation.
    pub provision_operation_id: Id,
    /// `intent` until its outcome is observed.
    pub state: StepState,
}

const COLUMNS: &str = "operation_id, provision_operation_id, idempotency_key, grant_id, nonce, plan_digest, grant_digest, expires_at, state";

fn state_of(text: &str) -> Result<StepState, JournalError> {
    match text {
        "intent" => Ok(StepState::Intent),
        "done" => Ok(StepState::Done),
        "failed" => Ok(StepState::Failed),
        _ => Err(JournalError::Unavailable),
    }
}

/// The stored row under the intent's operation or retry key, and whether it
/// is exactly this intent.
fn stored(
    c: &rusqlite::Connection,
    intent: &RetireIntent,
) -> Result<Option<(bool, Retirement)>, JournalError> {
    let row = c
        .query_row(
            &format!(
                "SELECT {COLUMNS} FROM retirements WHERE operation_id=?1 OR idempotency_key=?2"
            ),
            params![
                intent.operation_id.as_str(),
                intent.idempotency_key.as_str()
            ],
            |row| {
                let texts = [0, 1, 2, 3, 4, 5, 6]
                    .map(|index| row.get::<_, String>(index))
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()?;
                Ok((texts, row.get::<_, i64>(7)?, row.get::<_, String>(8)?))
            },
        )
        .optional()
        .map_err(storage::unavailable)?;
    let Some((texts, expires_at, state)) = row else {
        return Ok(None);
    };
    let exact = texts
        == [
            intent.operation_id.as_str(),
            intent.provision_operation_id.as_str(),
            intent.idempotency_key.as_str(),
            intent.grant_id.as_str(),
            intent.nonce.as_str(),
            intent.plan_digest.as_str(),
            intent.grant_digest.as_str(),
        ]
        && expires_at == intent.expires_at.get() as i64;
    let id = |text: &str| Id::try_from(text.to_owned()).map_err(|_| JournalError::Unavailable);
    Ok(Some((
        exact,
        Retirement {
            operation_id: id(&texts[0])?,
            provision_operation_id: id(&texts[1])?,
            state: state_of(&state)?,
        },
    )))
}

/// The latest retirement of a provision, if one is recorded.
pub(crate) fn of_provision(
    c: &rusqlite::Connection,
    provision_operation: &Id,
) -> Result<Option<Retirement>, JournalError> {
    let row = c
        .query_row(
            "SELECT operation_id, state FROM retirements WHERE provision_operation_id=?1 \
             ORDER BY rowid DESC LIMIT 1",
            [provision_operation.as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(storage::unavailable)?;
    row.map(|(operation, state)| {
        Ok(Retirement {
            operation_id: Id::try_from(operation).map_err(|_| JournalError::Unavailable)?,
            provision_operation_id: provision_operation.clone(),
            state: state_of(&state)?,
        })
    })
    .transpose()
}

/// Every retirement belongs to a quarantined provision.
pub(crate) fn validate(c: &rusqlite::Connection) -> Result<(), JournalError> {
    let invalid: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM retirements r LEFT JOIN provisions p \
             ON p.operation_id=r.provision_operation_id WHERE p.state IS NOT 'quarantined')",
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
    /// Records a new retirement, or returns the exact earlier one. The
    /// provision must be the signed site's, still `quarantined`, and have no
    /// retirement that is open or done; a failed one may be retried by a new
    /// signed request. Otherwise nothing is recorded.
    pub fn record_retirement(
        &mut self,
        intent: &RetireIntent,
        now: Timestamp,
    ) -> Result<Admitted<Retirement>, JournalError> {
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
        if let Some((exact, existing)) = stored(&transaction, intent)? {
            return if exact {
                Ok(Admitted::Existing(existing))
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
        let provision = provision::by_operation(&transaction, &intent.provision_operation_id)?
            .ok_or(JournalError::Consumed)?;
        if provision.intent.site_id != intent.site_id
            || provision.state != ProvisionState::Quarantined
            || of_provision(&transaction, &intent.provision_operation_id)?
                .is_some_and(|row| row.state != StepState::Failed)
        {
            return Err(JournalError::Consumed);
        }
        storage::check_clock(&transaction, now)?;
        if now.get() >= intent.expires_at.get() {
            return Err(JournalError::Expired);
        }
        transaction
            .execute(
                &format!(
                    "INSERT INTO retirements ({COLUMNS}) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'intent')"
                ),
                params![
                    intent.operation_id.as_str(),
                    intent.provision_operation_id.as_str(),
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
        Ok(Admitted::New(Retirement {
            operation_id: intent.operation_id.clone(),
            provision_operation_id: intent.provision_operation_id.clone(),
            state: StepState::Intent,
        }))
    }

    /// Records the observed outcome of an open retirement.
    pub fn finish_retirement(
        &mut self,
        operation_id: &Id,
        done: bool,
    ) -> Result<Retirement, JournalError> {
        let changed = self
            .connection
            .execute(
                "UPDATE retirements SET state=?1 WHERE operation_id=?2 AND state='intent'",
                params![if done { "done" } else { "failed" }, operation_id.as_str()],
            )
            .map_err(storage::unavailable)?;
        if changed != 1 {
            return Err(JournalError::Conflict);
        }
        self.retirement_status(operation_id)?
            .ok_or(JournalError::Unavailable)
    }

    /// A recorded retirement by its own operation.
    pub fn retirement_status(&self, operation_id: &Id) -> Result<Option<Retirement>, JournalError> {
        let row = self
            .connection
            .query_row(
                "SELECT provision_operation_id, state FROM retirements WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(storage::unavailable)?;
        row.map(|(provision, state)| {
            Ok(Retirement {
                operation_id: operation_id.clone(),
                provision_operation_id: Id::try_from(provision)
                    .map_err(|_| JournalError::Unavailable)?,
                state: state_of(&state)?,
            })
        })
        .transpose()
    }

    /// The retirement of a provision, if one is recorded.
    pub fn retirement_of_provision(
        &self,
        provision_operation: &Id,
    ) -> Result<Option<Retirement>, JournalError> {
        of_provision(&self.connection, provision_operation)
    }
}
