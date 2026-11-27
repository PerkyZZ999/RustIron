//! Live-site deletions (schema v33, W521, D-085).
//!
//! A signed deletion removes an offline site from the host. Its intent is
//! committed before any removal, in the same transaction that rechecks the
//! site and its capture and sets the provision to `deleted`, so no later
//! check treats the site as served. The provision row stays, so the site ID
//! and hostname stay consumed. Nothing here touches a host.

use rusqlite::{OptionalExtension, params};
use rustiron_contracts::{
    Id, Timestamp,
    approval::{Hostname, Sha256Digest, SiteId},
};

use crate::{
    Admitted, FixtureJournal, JournalError, ProvisionState, StepState, provision, storage,
};

/// D-081: the capture that a deletion names finished at most this long ago.
pub const DELETE_CAPTURE_MAX_AGE_SECONDS: u64 = 24 * 3600;

/// An admitted signed deletion; built by the executor from verified inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeleteIntent {
    /// The deletion's operation.
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
    /// The site to delete, as signed.
    pub site_id: SiteId,
    /// Its hostname, as signed.
    pub hostname: Hostname,
    /// The site's succeeded capture, as signed; `None` only for a proxy
    /// site (W576, D-095).
    pub capture_operation_id: Option<Id>,
    /// Normal grant deadline.
    pub expires_at: Timestamp,
}

/// One recorded deletion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Deletion {
    /// The deletion's operation.
    pub operation_id: Id,
    /// The deleted site's provision.
    pub provision_operation_id: Id,
    /// The deleted site.
    pub site_id: SiteId,
    /// The capture that the deletion named; `None` for a proxy site.
    pub capture_operation_id: Option<Id>,
    /// `intent` until its outcome is observed.
    pub state: StepState,
}

const COLUMNS: &str = "d.operation_id, d.provision_operation_id, p.site_id, d.capture_operation_id, d.idempotency_key, d.grant_id, d.nonce, d.plan_digest, d.grant_digest, d.expires_at, d.state";

fn state_of(text: &str) -> Result<StepState, JournalError> {
    match text {
        "intent" => Ok(StepState::Intent),
        "done" => Ok(StepState::Done),
        "failed" => Ok(StepState::Failed),
        _ => Err(JournalError::Unavailable),
    }
}

/// The text columns but the capture, the capture (W576: absent for a proxy
/// site), the deadline, and the state.
type Row = (Vec<String>, Option<String>, i64, String);

fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    let texts = [0, 1, 2, 4, 5, 6, 7, 8]
        .into_iter()
        .map(|index| row.get::<_, String>(index))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((texts, row.get(3)?, row.get(9)?, row.get(10)?))
}

fn deletion(
    texts: &[String],
    capture: Option<&str>,
    state: &str,
) -> Result<Deletion, JournalError> {
    let id = |text: &str| Id::try_from(text.to_owned()).map_err(|_| JournalError::Unavailable);
    Ok(Deletion {
        operation_id: id(&texts[0])?,
        provision_operation_id: id(&texts[1])?,
        site_id: SiteId::try_from(texts[2].clone()).map_err(|_| JournalError::Unavailable)?,
        capture_operation_id: capture.map(id).transpose()?,
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
            "SELECT {COLUMNS} FROM deletions d JOIN provisions p ON p.operation_id=d.provision_operation_id \
             WHERE {filter} ORDER BY d.rowid DESC LIMIT 1"
        ),
        [value],
        read_row,
    )
    .optional()
    .map_err(storage::unavailable)
}

/// The stored row under the intent's operation or retry key, and whether it
/// is exactly this intent.
fn stored(
    c: &rusqlite::Connection,
    intent: &DeleteIntent,
) -> Result<Option<(bool, Deletion)>, JournalError> {
    let row = match select(c, "d.operation_id=?1", intent.operation_id.as_str())? {
        Some(row) => Some(row),
        None => select(c, "d.idempotency_key=?1", intent.idempotency_key.as_str())?,
    };
    let Some((texts, capture, expires_at, state)) = row else {
        return Ok(None);
    };
    let exact = texts[0] == intent.operation_id.as_str()
        && texts[2] == intent.site_id.as_str()
        && capture.as_deref() == intent.capture_operation_id.as_ref().map(Id::as_str)
        && texts[3..]
            == [
                intent.idempotency_key.as_str(),
                intent.grant_id.as_str(),
                intent.nonce.as_str(),
                intent.plan_digest.as_str(),
                intent.grant_digest.as_str(),
            ]
        && expires_at == intent.expires_at.get() as i64;
    Ok(Some((exact, deletion(&texts, capture.as_deref(), &state)?)))
}

/// The latest deletion of a provision, if one is recorded.
pub(crate) fn of_provision(
    c: &rusqlite::Connection,
    provision_operation: &Id,
) -> Result<Option<Deletion>, JournalError> {
    select(
        c,
        "d.provision_operation_id=?1",
        provision_operation.as_str(),
    )?
    .map(|(texts, capture, _, state)| deletion(&texts, capture.as_deref(), &state))
    .transpose()
}

/// D-085 step 3, read in the recording transaction: nothing is open on the
/// site, and the capture is its newest succeeded capture, finished at most
/// 24 hours before `now`. A retry after a failed deletion names that
/// deletion's capture instead; the site is already `deleted`.
fn basis_holds(
    c: &rusqlite::Connection,
    intent: &DeleteIntent,
    provision: &provision::Provision,
    now: Timestamp,
) -> Result<bool, JournalError> {
    let site = intent.site_id.as_str();
    let open: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM captures WHERE site_id=?1 AND state='running') \
             OR EXISTS(SELECT 1 FROM restore_probes WHERE site_id=?1 AND state='running') \
             OR EXISTS(SELECT 1 FROM updates WHERE site_id=?1 AND state='intent') \
             OR EXISTS(SELECT 1 FROM site_restores WHERE site_id=?1 AND state='intent') \
             OR EXISTS(SELECT 1 FROM certificates WHERE site_id=?1 AND state='intent') \
             OR EXISTS(SELECT 1 FROM certificate_renewals r JOIN certificates c ON c.operation_id=r.operation_id \
                WHERE c.site_id=?1 AND r.state='intent') \
             OR EXISTS(SELECT 1 FROM app_releases WHERE site_id=?1 AND state='intent') \
             OR EXISTS(SELECT 1 FROM app_lifecycles WHERE site_id=?1 AND state='intent') \
             OR EXISTS(SELECT 1 FROM credential_rotations WHERE site_id=?1 AND state IN ('intent','needs_attention')) \
             OR EXISTS(SELECT 1 FROM ejections e JOIN operations o ON o.operation_id=e.operation_id \
                WHERE e.site_id=?1 AND o.state IN ('succeeded','intent','needs_attention','compensating'))",
            [site],
            |row| row.get(0),
        )
        .map_err(storage::unavailable)?;
    if open || provision.intent.hostname != intent.hostname {
        return Ok(false);
    }
    // W576 (D-095): a deletion names no capture for a proxy site, or (W597,
    // D-099) for an app site that has never deployed a release; a deployed app
    // site requires a fresh capture, just like WordPress.
    let is_app = crate::app::facts(c, &provision.intent.operation_id)?.is_some();
    let proxy = crate::proxy::facts(c, &provision.intent.operation_id)?.is_some();
    if is_app {
        let deployed = crate::app::has_done_release(c, &provision.intent.site_id)?;
        if deployed && intent.capture_operation_id.is_none() {
            return Ok(false);
        }
    } else if proxy != intent.capture_operation_id.is_none() {
        return Ok(false);
    }
    match provision.state {
        ProvisionState::Succeeded => {}
        ProvisionState::Deleted => {
            let latest = of_provision(c, &provision.intent.operation_id)?;
            return Ok(latest.is_some_and(|row| {
                row.state == StepState::Failed
                    && row.capture_operation_id == intent.capture_operation_id
            }));
        }
        _ => return Ok(false),
    }
    let Some(capture_operation) = &intent.capture_operation_id else {
        return Ok(true);
    };
    let capture = c
        .query_row(
            "SELECT site_id, state, finished_at FROM captures WHERE operation_id=?1",
            [capture_operation.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            },
        )
        .optional()
        .map_err(storage::unavailable)?;
    let Some((capture_site, state, Some(finished))) = capture else {
        return Ok(false);
    };
    let newer: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM captures WHERE site_id=?1 AND state='succeeded' \
             AND operation_id<>?2 AND finished_at>=?3)",
            params![site, capture_operation.as_str(), finished],
            |row| row.get(0),
        )
        .map_err(storage::unavailable)?;
    let now = now.get() as i64;
    Ok(capture_site == site
        && state == "succeeded"
        && !newer
        && finished <= now
        && now - finished <= DELETE_CAPTURE_MAX_AGE_SECONDS as i64)
}

/// Every deletion belongs to a `deleted` provision and names a capture of
/// that site, or (W576) names none and belongs to a proxy site; every
/// `deleted` provision has a deletion, at most one of them not failed.
pub(crate) fn validate(c: &rusqlite::Connection) -> Result<(), JournalError> {
    let invalid: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM deletions d LEFT JOIN provisions p ON p.operation_id=d.provision_operation_id \
                LEFT JOIN captures k ON k.operation_id=d.capture_operation_id \
                WHERE p.state IS NOT 'deleted' \
                OR (d.capture_operation_id IS NULL AND NOT EXISTS(SELECT 1 FROM proxy_routes r \
                    WHERE r.operation_id=d.provision_operation_id)) \
                OR (d.capture_operation_id IS NOT NULL AND k.site_id IS NOT p.site_id)) \
             OR EXISTS(SELECT 1 FROM provisions p WHERE p.state='deleted' \
                AND NOT EXISTS(SELECT 1 FROM deletions d WHERE d.provision_operation_id=p.operation_id))",
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
    /// Records a new deletion and sets the provision to `deleted`, or
    /// returns the exact earlier one. Otherwise nothing is recorded.
    pub fn record_deletion(
        &mut self,
        intent: &DeleteIntent,
        now: Timestamp,
    ) -> Result<Admitted<Deletion>, JournalError> {
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
        let provision =
            provision::by_site(&transaction, &intent.site_id)?.ok_or(JournalError::Consumed)?;
        if !basis_holds(&transaction, intent, &provision, now)? {
            return Err(JournalError::Consumed);
        }
        storage::check_clock(&transaction, now)?;
        if now.get() >= intent.expires_at.get() {
            return Err(JournalError::Expired);
        }
        transaction
            .execute(
                "INSERT INTO deletions (operation_id, provision_operation_id, capture_operation_id, \
                 idempotency_key, grant_id, nonce, plan_digest, grant_digest, expires_at, state) \
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,'intent')",
                params![
                    intent.operation_id.as_str(),
                    provision.intent.operation_id.as_str(),
                    intent.capture_operation_id.as_ref().map(Id::as_str),
                    intent.idempotency_key.as_str(),
                    intent.grant_id.as_str(),
                    intent.nonce.as_str(),
                    intent.plan_digest.as_str(),
                    intent.grant_digest.as_str(),
                    intent.expires_at.get() as i64,
                ],
            )
            .map_err(storage::unavailable)?;
        provision::set_state(
            &transaction,
            &provision.intent.operation_id,
            ProvisionState::Deleted,
        )?;
        crate::signed::insert(&transaction, &intent.operation_id, signed.as_ref())?;
        storage::set_clock(&transaction, now)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(Admitted::New(Deletion {
            operation_id: intent.operation_id.clone(),
            provision_operation_id: provision.intent.operation_id,
            site_id: intent.site_id.clone(),
            capture_operation_id: intent.capture_operation_id.clone(),
            state: StepState::Intent,
        }))
    }

    /// Records the observed outcome of an open deletion. The site stays
    /// `deleted` either way.
    pub fn finish_deletion(
        &mut self,
        operation_id: &Id,
        done: bool,
    ) -> Result<Deletion, JournalError> {
        let changed = self
            .connection
            .execute(
                "UPDATE deletions SET state=?1 WHERE operation_id=?2 AND state='intent'",
                params![if done { "done" } else { "failed" }, operation_id.as_str()],
            )
            .map_err(storage::unavailable)?;
        if changed != 1 {
            return Err(JournalError::Conflict);
        }
        self.deletion_status(operation_id)?
            .ok_or(JournalError::Unavailable)
    }

    /// A recorded deletion by its own operation.
    pub fn deletion_status(&self, operation_id: &Id) -> Result<Option<Deletion>, JournalError> {
        select(&self.connection, "d.operation_id=?1", operation_id.as_str())?
            .map(|(texts, capture, _, state)| deletion(&texts, capture.as_deref(), &state))
            .transpose()
    }

    /// The latest deletion of a provision, if one is recorded.
    pub fn deletion_of_provision(
        &self,
        provision_operation: &Id,
    ) -> Result<Option<Deletion>, JournalError> {
        of_provision(&self.connection, provision_operation)
    }
}
