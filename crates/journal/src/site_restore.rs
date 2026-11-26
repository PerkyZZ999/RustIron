//! Signed restores of a live site from its own capture (schema v37, W542,
//! D-089).
//!
//! A restore's intent is committed before any effect, in the transaction
//! that rechecks the site and both captures: the site is served by its own
//! `succeeded` provision with the signed hostname and is not ejected,
//! nothing else is open on it, the safety capture is its newest succeeded
//! capture, finished within the last 24 hours, and the capture to restore
//! is an older succeeded capture of the site with the signed snapshot and
//! manifest. The intent opens attempt 0, which restores the signed capture.
//! A failed or settled attempt may be followed by another attempt, from the
//! signed capture or from the safety capture, at most 8 in all. Each step
//! is recorded before and after its effect. Nothing here touches a host.

use rusqlite::{OptionalExtension, params};
use rustiron_contracts::{
    Id, Timestamp,
    approval::{Hostname, RestoreScope, Sha256Digest, SiteId, SnapshotId},
};

use crate::{FixtureJournal, JournalError, ProvisionState, StepState, provision, storage};

/// D-089: the safety capture finished at most this long before the intent.
pub const RESTORE_SAFETY_MAX_AGE_SECONDS: u64 = 24 * 3600;

/// The most attempts one restore may record.
pub const MAX_RESTORE_ATTEMPTS: usize = 8;

/// An admitted signed restore; built by the executor from verified inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreIntent {
    /// The restore's operation.
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
    /// The served site, as signed.
    pub site_id: SiteId,
    /// Its hostname, as signed.
    pub hostname: Hostname,
    /// What the restore replaces, as signed.
    pub scope: RestoreScope,
    /// The site's older succeeded capture to restore, as signed.
    pub capture_operation_id: Id,
    /// That capture's snapshot, as signed.
    pub snapshot_id: SnapshotId,
    /// That capture's manifest digest, as signed.
    pub manifest_sha256: Sha256Digest,
    /// The site's newest succeeded capture, as signed.
    pub safety_capture_operation_id: Id,
    /// Normal grant deadline.
    pub expires_at: Timestamp,
}

/// The recorded outcome of a restore.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreState {
    /// Open: an attempt may be running, unverified, or failed.
    Intent,
    /// An attempt from the signed capture finished every step.
    Done,
    /// An attempt from the safety capture finished every step: the site is
    /// back at the state the restore replaced.
    Reverted,
}

impl RestoreState {
    fn from_name(name: &str) -> Result<Self, JournalError> {
        match name {
            "intent" => Ok(Self::Intent),
            "done" => Ok(Self::Done),
            "reverted" => Ok(Self::Reverted),
            _ => Err(JournalError::Unavailable),
        }
    }
}

/// Which capture an attempt restores.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreFrom {
    /// The signed capture to restore.
    Signed,
    /// The signed safety capture, to undo a failed restore.
    Safety,
}

impl RestoreFrom {
    /// The fixed lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Signed => "signed",
            Self::Safety => "safety",
        }
    }

    fn from_name(name: &str) -> Result<Self, JournalError> {
        match name {
            "signed" => Ok(Self::Signed),
            "safety" => Ok(Self::Safety),
            _ => Err(JournalError::Unavailable),
        }
    }
}

/// The ordered steps of one attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreStep {
    /// Put the site in WordPress maintenance mode.
    Maintenance,
    /// Fetch the snapshot into the site's `tmp` as the site.
    Fetch,
    /// Remove every table of the site's database and import the dump.
    Database,
    /// Compare the fetched tree with the manifest and swap the document root.
    Files,
    /// Restore the labels and remove the maintenance file.
    Reopen,
    /// The site's marker and PHP health.
    Health,
}

const DATABASE_STEPS: [RestoreStep; 5] = [
    RestoreStep::Maintenance,
    RestoreStep::Fetch,
    RestoreStep::Database,
    RestoreStep::Reopen,
    RestoreStep::Health,
];

const FILES_STEPS: [RestoreStep; 6] = [
    RestoreStep::Maintenance,
    RestoreStep::Fetch,
    RestoreStep::Database,
    RestoreStep::Files,
    RestoreStep::Reopen,
    RestoreStep::Health,
];

impl RestoreStep {
    /// The steps of an attempt of this scope, in order.
    pub fn sequence(scope: RestoreScope) -> &'static [Self] {
        match scope {
            RestoreScope::Database => &DATABASE_STEPS,
            RestoreScope::FilesAndDatabase => &FILES_STEPS,
        }
    }

    /// The fixed lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Maintenance => "maintenance",
            Self::Fetch => "fetch",
            Self::Database => "database",
            Self::Files => "files",
            Self::Reopen => "reopen",
            Self::Health => "health",
        }
    }

    fn from_name(name: &str) -> Result<Self, JournalError> {
        FILES_STEPS
            .into_iter()
            .find(|step| step.as_str() == name)
            .ok_or(JournalError::Unavailable)
    }
}

/// One recorded step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestoreStepRecord {
    /// Which step.
    pub step: RestoreStep,
    /// `intent` until its outcome is observed.
    pub state: StepState,
}

/// One recorded attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreAttempt {
    /// Which capture it restores.
    pub from: RestoreFrom,
    /// `intent` while open; `failed` after a failed or settled step.
    pub state: StepState,
    /// Its steps so far, in order.
    pub steps: Vec<RestoreStepRecord>,
}

/// One recorded restore with its signed facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SiteRestore {
    /// The restore's operation.
    pub operation_id: Id,
    /// The restored site.
    pub site_id: SiteId,
    /// What the restore replaces.
    pub scope: RestoreScope,
    /// The capture to restore.
    pub capture_operation_id: Id,
    /// Its snapshot.
    pub snapshot_id: SnapshotId,
    /// Its manifest digest.
    pub manifest_sha256: Sha256Digest,
    /// The safety capture.
    pub safety_capture_operation_id: Id,
    /// The attempts, in order; attempt 0 restores the signed capture.
    pub attempts: Vec<RestoreAttempt>,
    /// The restore's outcome.
    pub state: RestoreState,
}

impl SiteRestore {
    /// The latest attempt; every recorded restore has one.
    pub fn current(&self) -> Option<&RestoreAttempt> {
        self.attempts.last()
    }

    /// The capture an attempt restores.
    pub fn capture_of(&self, from: RestoreFrom) -> &Id {
        match from {
            RestoreFrom::Signed => &self.capture_operation_id,
            RestoreFrom::Safety => &self.safety_capture_operation_id,
        }
    }
}

/// A new or an exactly repeated restore.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RestoreResult {
    /// Recorded now, in `intent`.
    New(SiteRestore),
    /// The same request was recorded before; its stored state.
    Existing(SiteRestore),
}

const COLUMNS: &str = "operation_id, site_id, scope, capture_operation_id, snapshot_id, manifest_sha256, safety_capture_operation_id, idempotency_key, grant_id, nonce, plan_digest, grant_digest, expires_at, state";

fn scope_of(name: &str) -> Result<RestoreScope, JournalError> {
    match name {
        "database" => Ok(RestoreScope::Database),
        "files_and_database" => Ok(RestoreScope::FilesAndDatabase),
        _ => Err(JournalError::Unavailable),
    }
}

fn step_state(text: &str) -> Result<StepState, JournalError> {
    match text {
        "intent" => Ok(StepState::Intent),
        "done" => Ok(StepState::Done),
        "failed" => Ok(StepState::Failed),
        _ => Err(JournalError::Unavailable),
    }
}

fn bad<E>(_: E) -> JournalError {
    JournalError::Unavailable
}

fn attempts(
    c: &rusqlite::Connection,
    operation_id: &str,
) -> Result<Vec<RestoreAttempt>, JournalError> {
    let mut statement = c
        .prepare(
            "SELECT attempt, source, state FROM restore_attempts WHERE operation_id=?1 \
             ORDER BY attempt",
        )
        .map_err(storage::unavailable)?;
    let rows = statement
        .query_map([operation_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(storage::unavailable)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage::unavailable)?;
    let mut steps = c
        .prepare(
            "SELECT position, step, state FROM restore_steps WHERE operation_id=?1 AND attempt=?2 \
             ORDER BY position",
        )
        .map_err(storage::unavailable)?;
    rows.into_iter()
        .enumerate()
        .map(|(index, (attempt, source, state))| {
            if attempt != index as i64 {
                return Err(JournalError::Unavailable);
            }
            let records = steps
                .query_map(params![operation_id, attempt], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .map_err(storage::unavailable)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(storage::unavailable)?
                .into_iter()
                .enumerate()
                .map(|(index, (position, step, state))| {
                    if position != index as i64 {
                        return Err(JournalError::Unavailable);
                    }
                    Ok(RestoreStepRecord {
                        step: RestoreStep::from_name(&step)?,
                        state: step_state(&state)?,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(RestoreAttempt {
                from: RestoreFrom::from_name(&source)?,
                state: step_state(&state)?,
                steps: records,
            })
        })
        .collect()
}

type Row = (Vec<String>, i64, String);

fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    let texts = (0..12)
        .map(|index| row.get::<_, String>(index))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((texts, row.get(12)?, row.get(13)?))
}

fn select(
    c: &rusqlite::Connection,
    filter: &str,
    value: &str,
) -> Result<Option<Row>, JournalError> {
    c.query_row(
        &format!("SELECT {COLUMNS} FROM site_restores WHERE {filter} ORDER BY rowid DESC LIMIT 1"),
        [value],
        read_row,
    )
    .optional()
    .map_err(storage::unavailable)
}

fn restore(
    c: &rusqlite::Connection,
    texts: &[String],
    state: &str,
) -> Result<SiteRestore, JournalError> {
    let id = |text: &str| Id::try_from(text.to_owned()).map_err(bad);
    Ok(SiteRestore {
        operation_id: id(&texts[0])?,
        site_id: SiteId::try_from(texts[1].clone()).map_err(bad)?,
        scope: scope_of(&texts[2])?,
        capture_operation_id: id(&texts[3])?,
        snapshot_id: SnapshotId::try_from(texts[4].clone()).map_err(bad)?,
        manifest_sha256: Sha256Digest::try_from(texts[5].clone()).map_err(bad)?,
        safety_capture_operation_id: id(&texts[6])?,
        attempts: attempts(c, &texts[0])?,
        state: RestoreState::from_name(state)?,
    })
}

/// The stored restore with this operation, if any.
pub(crate) fn load(
    c: &rusqlite::Connection,
    operation_id: &Id,
) -> Result<Option<SiteRestore>, JournalError> {
    select(c, "operation_id=?1", operation_id.as_str())?
        .map(|(texts, _, state)| restore(c, &texts, &state))
        .transpose()
}

/// Whether a restore of the site is open. Other verbs on the site refuse
/// while one is.
pub(crate) fn open_on_site(c: &rusqlite::Connection, site: &str) -> Result<bool, JournalError> {
    c.query_row(
        "SELECT EXISTS(SELECT 1 FROM site_restores WHERE site_id=?1 AND state='intent')",
        [site],
        |row| row.get(0),
    )
    .map_err(storage::unavailable)
}

/// The stored row under the intent's operation or retry key, and whether it
/// is exactly this intent.
fn stored(
    c: &rusqlite::Connection,
    intent: &RestoreIntent,
) -> Result<Option<(bool, SiteRestore)>, JournalError> {
    let row = match select(c, "operation_id=?1", intent.operation_id.as_str())? {
        Some(row) => Some(row),
        None => select(c, "idempotency_key=?1", intent.idempotency_key.as_str())?,
    };
    let Some((texts, expires_at, state)) = row else {
        return Ok(None);
    };
    let exact = texts[..]
        == [
            intent.operation_id.as_str(),
            intent.site_id.as_str(),
            intent.scope.as_str(),
            intent.capture_operation_id.as_str(),
            intent.snapshot_id.as_str(),
            intent.manifest_sha256.as_str(),
            intent.safety_capture_operation_id.as_str(),
            intent.idempotency_key.as_str(),
            intent.grant_id.as_str(),
            intent.nonce.as_str(),
            intent.plan_digest.as_str(),
            intent.grant_digest.as_str(),
        ]
        && expires_at == intent.expires_at.get() as i64;
    Ok(Some((exact, restore(c, &texts, &state)?)))
}

/// One capture's recorded facts: site, state, finished time, snapshot, and
/// manifest digest with its truncation flag.
type CaptureFacts = (
    String,
    String,
    Option<i64>,
    Option<String>,
    Option<String>,
    Option<i64>,
);

fn capture_facts(
    c: &rusqlite::Connection,
    operation: &Id,
) -> Result<Option<CaptureFacts>, JournalError> {
    c.query_row(
        "SELECT k.site_id, k.state, k.finished_at, k.snapshot_id, m.manifest_sha256, m.truncated \
         FROM captures k LEFT JOIN capture_manifest m ON m.operation_id=k.operation_id \
         WHERE k.operation_id=?1",
        [operation.as_str()],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        },
    )
    .optional()
    .map_err(storage::unavailable)
}

/// D-089 step 3, read in the recording transaction.
fn basis_holds(
    c: &rusqlite::Connection,
    intent: &RestoreIntent,
    now: Timestamp,
) -> Result<bool, JournalError> {
    let site = intent.site_id.as_str();
    let Some(provision) = provision::by_site(c, &intent.site_id)? else {
        return Ok(false);
    };
    if provision.state != ProvisionState::Succeeded
        || provision.intent.hostname != intent.hostname
        || provision::ejected(c)?.contains(&intent.site_id)
    {
        return Ok(false);
    }
    let open: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM captures WHERE site_id=?1 AND state='running') \
             OR EXISTS(SELECT 1 FROM restore_probes WHERE site_id=?1 AND state='running') \
             OR EXISTS(SELECT 1 FROM updates WHERE site_id=?1 AND state='intent') \
             OR EXISTS(SELECT 1 FROM quota_changes WHERE site_id=?1 AND state='intent') \
             OR EXISTS(SELECT 1 FROM site_restores WHERE site_id=?1 AND state='intent') \
             OR EXISTS(SELECT 1 FROM credential_rotations WHERE site_id=?1 AND state IN ('intent','needs_attention')) \
             OR EXISTS(SELECT 1 FROM certificates WHERE site_id=?1 AND state='intent') \
             OR EXISTS(SELECT 1 FROM certificate_renewals r JOIN certificates c ON c.operation_id=r.operation_id \
                WHERE c.site_id=?1 AND r.state='intent') \
             OR EXISTS(SELECT 1 FROM ejections e JOIN operations o ON o.operation_id=e.operation_id \
                WHERE e.site_id=?1 AND o.state IN ('succeeded','intent','needs_attention','compensating'))",
            [site],
            |row| row.get(0),
        )
        .map_err(storage::unavailable)?;
    if open {
        return Ok(false);
    }
    let Some((safety_site, safety_state, Some(safety_finished), _, _, safety_truncated)) =
        capture_facts(c, &intent.safety_capture_operation_id)?
    else {
        return Ok(false);
    };
    let Some((source_site, source_state, Some(source_finished), snapshot, manifest, truncated)) =
        capture_facts(c, &intent.capture_operation_id)?
    else {
        return Ok(false);
    };
    let newer: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM captures WHERE site_id=?1 AND state='succeeded' \
             AND operation_id<>?2 AND finished_at>=?3)",
            params![
                site,
                intent.safety_capture_operation_id.as_str(),
                safety_finished
            ],
            |row| row.get(0),
        )
        .map_err(storage::unavailable)?;
    // A files restore compares the fetched tree with the whole manifest,
    // for the signed capture and for the safety capture that may undo it.
    let complete = intent.scope == RestoreScope::Database
        || (truncated == Some(0) && safety_truncated == Some(0));
    let now = now.get() as i64;
    Ok(safety_site == site
        && safety_state == "succeeded"
        && !newer
        && safety_finished <= now
        && now - safety_finished <= RESTORE_SAFETY_MAX_AGE_SECONDS as i64
        && source_site == site
        && source_state == "succeeded"
        && source_finished < safety_finished
        && snapshot.as_deref() == Some(intent.snapshot_id.as_str())
        && manifest.as_deref() == Some(intent.manifest_sha256.as_str())
        && complete)
}

/// Every restore names two captures of its own site and a served or later
/// deleted provision; attempt 0 restores the signed capture; every attempt
/// before the last failed; each attempt's steps follow its scope's
/// sequence, every step before the last done; and the restore's state
/// matches its last attempt.
pub(crate) fn validate(c: &rusqlite::Connection) -> Result<(), JournalError> {
    let invalid: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM site_restores r LEFT JOIN provisions p ON p.site_id=r.site_id \
                LEFT JOIN captures a ON a.operation_id=r.capture_operation_id \
                LEFT JOIN captures b ON b.operation_id=r.safety_capture_operation_id \
                WHERE p.state IS NULL OR p.state NOT IN ('succeeded','deleted') \
                OR a.site_id IS NOT r.site_id OR b.site_id IS NOT r.site_id)",
            [],
            |row| row.get(0),
        )
        .map_err(storage::unavailable)?;
    if invalid {
        return Err(JournalError::Unavailable);
    }
    let mut statement = c
        .prepare("SELECT operation_id FROM site_restores")
        .map_err(storage::unavailable)?;
    let operations = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(storage::unavailable)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage::unavailable)?;
    for operation in operations {
        let id = Id::try_from(operation).map_err(bad)?;
        let restore = load(c, &id)?.ok_or(JournalError::Unavailable)?;
        if !consistent(&restore) {
            return Err(JournalError::Unavailable);
        }
    }
    Ok(())
}

fn consistent(restore: &SiteRestore) -> bool {
    let sequence = RestoreStep::sequence(restore.scope);
    let Some(last) = restore.attempts.last() else {
        return false;
    };
    let earlier_failed = restore.attempts[..restore.attempts.len() - 1]
        .iter()
        .all(|attempt| attempt.state == StepState::Failed);
    let attempts_hold = restore.attempts.iter().all(|attempt| {
        let in_order = attempt.steps.len() <= sequence.len()
            && attempt
                .steps
                .iter()
                .zip(sequence)
                .all(|(record, step)| record.step == *step);
        let open_before_last = attempt
            .steps
            .iter()
            .rev()
            .skip(1)
            .any(|record| record.state != StepState::Done);
        let all_done = attempt.steps.len() == sequence.len()
            && attempt.steps.iter().all(|r| r.state == StepState::Done);
        let fits = match attempt.state {
            StepState::Intent => attempt
                .steps
                .last()
                .is_none_or(|r| r.state != StepState::Failed),
            StepState::Done => all_done,
            StepState::Failed => !all_done,
        };
        in_order && !open_before_last && fits
    });
    let state_fits = match restore.state {
        RestoreState::Intent => last.state != StepState::Done,
        RestoreState::Done => last.state == StepState::Done && last.from == RestoreFrom::Signed,
        RestoreState::Reverted => last.state == StepState::Done && last.from == RestoreFrom::Safety,
    };
    restore.attempts.len() <= MAX_RESTORE_ATTEMPTS
        && restore.attempts[0].from == RestoreFrom::Signed
        && earlier_failed
        && attempts_hold
        && state_fits
}

fn reload(c: &rusqlite::Connection, operation_id: &Id) -> Result<SiteRestore, JournalError> {
    load(c, operation_id)?.ok_or(JournalError::Unavailable)
}

impl FixtureJournal {
    /// Records a new restore with its first attempt, or returns the exact
    /// earlier one. The site and capture checks share the intent's
    /// transaction. Nothing is recorded when a check fails.
    pub fn record_site_restore(
        &mut self,
        intent: &RestoreIntent,
        now: Timestamp,
    ) -> Result<RestoreResult, JournalError> {
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
                Ok(RestoreResult::Existing(existing))
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
        storage::check_clock(&transaction, now)?;
        if now.get() >= intent.expires_at.get() {
            return Err(JournalError::Expired);
        }
        if !basis_holds(&transaction, intent, now)? {
            return Err(JournalError::SourceChanged);
        }
        transaction
            .execute(
                &format!(
                    "INSERT INTO site_restores ({COLUMNS}) \
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,'intent')"
                ),
                params![
                    intent.operation_id.as_str(),
                    intent.site_id.as_str(),
                    intent.scope.as_str(),
                    intent.capture_operation_id.as_str(),
                    intent.snapshot_id.as_str(),
                    intent.manifest_sha256.as_str(),
                    intent.safety_capture_operation_id.as_str(),
                    intent.idempotency_key.as_str(),
                    intent.grant_id.as_str(),
                    intent.nonce.as_str(),
                    intent.plan_digest.as_str(),
                    intent.grant_digest.as_str(),
                    intent.expires_at.get() as i64,
                ],
            )
            .map_err(storage::unavailable)?;
        transaction
            .execute(
                "INSERT INTO restore_attempts VALUES(?1,0,'signed','intent')",
                [intent.operation_id.as_str()],
            )
            .map_err(storage::unavailable)?;
        crate::signed::insert(&transaction, &intent.operation_id, signed.as_ref())?;
        storage::set_clock(&transaction, now)?;
        let recorded = reload(&transaction, &intent.operation_id)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(RestoreResult::New(recorded))
    }

    /// Commits a step's intent before its effect. The restore and its
    /// latest attempt must be open, the attempt's earlier steps done, and
    /// this step next in the scope's sequence.
    pub fn begin_restore_step(
        &mut self,
        operation_id: &Id,
        step: RestoreStep,
    ) -> Result<SiteRestore, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let restore = load(&transaction, operation_id)?.ok_or(JournalError::Conflict)?;
        let attempt = restore.current().ok_or(JournalError::Unavailable)?;
        let position = attempt.steps.len();
        if restore.state != RestoreState::Intent
            || attempt.state != StepState::Intent
            || RestoreStep::sequence(restore.scope).get(position) != Some(&step)
            || attempt.steps.iter().any(|r| r.state != StepState::Done)
        {
            return Err(JournalError::Conflict);
        }
        transaction
            .execute(
                "INSERT INTO restore_steps VALUES(?1,?2,?3,?4,'intent')",
                params![
                    operation_id.as_str(),
                    (restore.attempts.len() - 1) as i64,
                    position as i64,
                    step.as_str()
                ],
            )
            .map_err(storage::unavailable)?;
        let recorded = reload(&transaction, operation_id)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(recorded)
    }

    /// Records the open step's observed outcome. A failed step fails its
    /// attempt; the site stays in maintenance mode. After the Health step
    /// is done, the attempt is done and the restore is `done`, or
    /// `reverted` for an attempt from the safety capture, in the same
    /// transaction.
    pub fn finish_restore_step(
        &mut self,
        operation_id: &Id,
        step: RestoreStep,
        done: bool,
    ) -> Result<SiteRestore, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let restore = load(&transaction, operation_id)?.ok_or(JournalError::Conflict)?;
        let attempt = restore.current().ok_or(JournalError::Unavailable)?;
        let last = attempt.steps.last().ok_or(JournalError::Conflict)?;
        if restore.state != RestoreState::Intent
            || attempt.state != StepState::Intent
            || last.step != step
            || last.state != StepState::Intent
        {
            return Err(JournalError::Conflict);
        }
        let index = (restore.attempts.len() - 1) as i64;
        transaction
            .execute(
                "UPDATE restore_steps SET state=?1 WHERE operation_id=?2 AND attempt=?3 AND position=?4",
                params![
                    if done { "done" } else { "failed" },
                    operation_id.as_str(),
                    index,
                    (attempt.steps.len() - 1) as i64
                ],
            )
            .map_err(storage::unavailable)?;
        let finished = done && step == RestoreStep::Health;
        if !done || finished {
            transaction
                .execute(
                    "UPDATE restore_attempts SET state=?1 WHERE operation_id=?2 AND attempt=?3",
                    params![
                        if done { "done" } else { "failed" },
                        operation_id.as_str(),
                        index
                    ],
                )
                .map_err(storage::unavailable)?;
        }
        if finished {
            let outcome = match attempt.from {
                RestoreFrom::Signed => "done",
                RestoreFrom::Safety => "reverted",
            };
            transaction
                .execute(
                    "UPDATE site_restores SET state=?1 WHERE operation_id=?2",
                    params![outcome, operation_id.as_str()],
                )
                .map_err(storage::unavailable)?;
        }
        let recorded = reload(&transaction, operation_id)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(recorded)
    }

    /// Operator settlement of an interrupted attempt: its step left at
    /// `intent`, if any, and the attempt become `failed`. Nothing is claimed
    /// done; the next attempt runs every step again.
    pub fn settle_restore_attempt(
        &mut self,
        operation_id: &Id,
    ) -> Result<SiteRestore, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let restore = load(&transaction, operation_id)?.ok_or(JournalError::Conflict)?;
        let attempt = restore.current().ok_or(JournalError::Unavailable)?;
        if restore.state != RestoreState::Intent || attempt.state != StepState::Intent {
            return Err(JournalError::Conflict);
        }
        let index = (restore.attempts.len() - 1) as i64;
        transaction
            .execute(
                "UPDATE restore_steps SET state='failed' WHERE operation_id=?1 AND attempt=?2 AND state='intent'",
                params![operation_id.as_str(), index],
            )
            .map_err(storage::unavailable)?;
        transaction
            .execute(
                "UPDATE restore_attempts SET state='failed' WHERE operation_id=?1 AND attempt=?2",
                params![operation_id.as_str(), index],
            )
            .map_err(storage::unavailable)?;
        let recorded = reload(&transaction, operation_id)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(recorded)
    }

    /// D-089 step 5: opens the next attempt of an open restore whose latest
    /// attempt failed, from the signed capture or from the safety capture.
    pub fn begin_restore_attempt(
        &mut self,
        operation_id: &Id,
        from: RestoreFrom,
    ) -> Result<SiteRestore, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let restore = load(&transaction, operation_id)?.ok_or(JournalError::Conflict)?;
        let attempt = restore.current().ok_or(JournalError::Unavailable)?;
        if restore.state != RestoreState::Intent || attempt.state != StepState::Failed {
            return Err(JournalError::Conflict);
        }
        if restore.attempts.len() >= MAX_RESTORE_ATTEMPTS {
            return Err(JournalError::Capacity);
        }
        transaction
            .execute(
                "INSERT INTO restore_attempts VALUES(?1,?2,?3,'intent')",
                params![
                    operation_id.as_str(),
                    restore.attempts.len() as i64,
                    from.as_str()
                ],
            )
            .map_err(storage::unavailable)?;
        let recorded = reload(&transaction, operation_id)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(recorded)
    }

    /// A recorded restore by its operation.
    pub fn site_restore_status(
        &self,
        operation_id: &Id,
    ) -> Result<Option<SiteRestore>, JournalError> {
        load(&self.connection, operation_id)
    }

    /// The site and capture rule of [`Self::record_site_restore`], read
    /// only, for the executor's checks before intent. The same rule runs
    /// again in the transaction that records the intent.
    pub fn site_restore_basis_holds(
        &self,
        intent: &RestoreIntent,
        now: Timestamp,
    ) -> Result<bool, JournalError> {
        basis_holds(&self.connection, intent, now)
    }
}
