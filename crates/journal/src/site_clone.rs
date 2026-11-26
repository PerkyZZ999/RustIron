//! Staging clones (schema v29, W498, D-078).
//!
//! A clone is a provision: it reserves its new site ID and hostname in
//! `provisions` and runs the provision steps. Its Recipe step holds the
//! clone steps, in a fixed order, each with a durable intent before its
//! effect. The transaction that reserves the target also rechecks that the
//! signed capture is still the succeeded, complete and `matched` capture of
//! the named native source site. Nothing here reads the store or a host.

use rusqlite::{OptionalExtension, params};
use rustiron_contracts::{
    Id, Timestamp,
    approval::{Hostname, Sha256Digest, SiteId, SnapshotId},
};

use crate::{
    FixtureJournal, JournalError, ProvisionState, ProvisionStep, StepState, provision, storage,
};

/// The signed source facts of one clone (D-078 plan `source`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloneFacts {
    /// Managed site that owns the capture.
    pub source_site_id: SiteId,
    /// The source site's hostname, for the bounded URL rewrite.
    pub source_hostname: Hostname,
    /// The completed capture operation.
    pub capture_operation_id: Id,
    /// Full snapshot ID the capture recorded.
    pub snapshot_id: SnapshotId,
    /// Digest of the capture's file manifest.
    pub manifest_sha256: Sha256Digest,
    /// Digest of the destination projection the capture used.
    pub destination_policy_digest: Sha256Digest,
    /// Repository configuration ID pinned for the source site.
    pub repository_id: Sha256Digest,
}

/// The fixed clone steps, in the only order they may run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloneStep {
    /// Fetch the snapshot into the target's private area as the target.
    Fetch,
    /// Observe the fetched tree and compare it with the manifest.
    Observe,
    /// Move the application tree into place.
    Files,
    /// Import the dump as the target's database user.
    Database,
    /// Write the target credentials and rewrite the source URLs.
    Config,
}

impl CloneStep {
    /// Every step in order.
    pub const ALL: [Self; 5] = [
        Self::Fetch,
        Self::Observe,
        Self::Files,
        Self::Database,
        Self::Config,
    ];

    fn position(self) -> i64 {
        Self::ALL.iter().position(|step| *step == self).unwrap_or(0) as i64
    }
}

/// One recorded clone step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloneStepRecord {
    /// Which step.
    pub step: CloneStep,
    /// Its state.
    pub state: StepState,
}

/// A stored clone: its source facts and the steps recorded so far.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SiteClone {
    /// Signed source facts.
    pub facts: CloneFacts,
    /// Steps recorded so far, in order.
    pub steps: Vec<CloneStepRecord>,
    /// W501 (v30): the scrub after a failed clone step, if recorded.
    pub scrub: Option<StepState>,
    /// W538 (v36, D-078 signed clone scrub): the latest signed scrub of this
    /// clone, if one is recorded.
    pub signed_scrub: Option<StepState>,
}

/// W538: an admitted signed clone scrub; built by the executor from
/// verified inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloneScrubIntent {
    /// The scrub's own operation.
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
    /// The clone target, as signed.
    pub site_id: SiteId,
    /// The clone's operation, as signed.
    pub clone_operation_id: Id,
    /// Normal grant deadline.
    pub expires_at: Timestamp,
}

/// W538: one recorded signed clone scrub.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloneScrubGrant {
    /// The scrub's own operation.
    pub operation_id: Id,
    /// The clone's operation.
    pub clone_operation_id: Id,
    /// `intent` until its outcome is observed.
    pub state: StepState,
}

/// W538: a new or an exactly repeated signed clone scrub.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CloneScrubResult {
    /// Recorded now, in `intent`.
    New(CloneScrubGrant),
    /// The same request was recorded before; its stored state.
    Existing(CloneScrubGrant),
}

pub(crate) fn insert(
    c: &rusqlite::Connection,
    operation_id: &Id,
    facts: &CloneFacts,
) -> Result<(), JournalError> {
    c.execute(
        "INSERT INTO clones VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            operation_id.as_str(),
            facts.source_site_id.as_str(),
            facts.source_hostname.as_str(),
            facts.capture_operation_id.as_str(),
            facts.snapshot_id.as_str(),
            facts.manifest_sha256.as_str(),
            facts.destination_policy_digest.as_str(),
            facts.repository_id.as_str(),
        ],
    )
    .map_err(storage::unavailable)?;
    Ok(())
}

/// D-078 step 2, inside the reserving transaction: the source is a served
/// provision of its own (not an import or a clone) with no ejection that
/// could have succeeded, and the capture is its succeeded capture of the
/// signed snapshot with an untruncated manifest of the signed digest, the
/// `matched` consistency label and the signed destination projection.
pub(crate) fn source_holds(
    c: &rusqlite::Connection,
    facts: &CloneFacts,
) -> Result<bool, JournalError> {
    c.query_row(
        "SELECT EXISTS(SELECT 1 FROM provisions p \
         JOIN captures k ON k.site_id=p.site_id \
         JOIN capture_manifest m ON m.operation_id=k.operation_id \
         JOIN capture_consistency x ON x.operation_id=k.operation_id \
         JOIN capture_backup_policy b ON b.operation_id=k.operation_id \
         WHERE p.site_id=?1 AND p.hostname=?2 AND p.state='succeeded' \
         AND k.operation_id=?3 AND k.state='succeeded' AND k.snapshot_id=?4 \
         AND m.manifest_sha256=?5 AND m.truncated=0 AND x.label='matched' AND b.digest=?6 \
         AND NOT EXISTS(SELECT 1 FROM imports i WHERE i.operation_id=p.operation_id) \
         AND NOT EXISTS(SELECT 1 FROM clones l WHERE l.operation_id=p.operation_id) \
         AND NOT EXISTS(SELECT 1 FROM ejections e JOIN operations o ON o.operation_id=e.operation_id \
             WHERE e.site_id=p.site_id AND o.state NOT IN ('untouched','failed_compensated')))",
        params![
            facts.source_site_id.as_str(),
            facts.source_hostname.as_str(),
            facts.capture_operation_id.as_str(),
            facts.snapshot_id.as_str(),
            facts.manifest_sha256.as_str(),
            facts.destination_policy_digest.as_str(),
        ],
        |row| row.get(0),
    )
    .map_err(storage::unavailable)
}

/// Every clone belongs to a provision of another site, no provision is
/// both an import and a clone, and a scrub (W501) belongs to a quarantined
/// clone.
pub(crate) fn validate(c: &rusqlite::Connection) -> Result<(), JournalError> {
    let invalid: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM clones l LEFT JOIN provisions p USING(operation_id) \
             WHERE p.operation_id IS NULL OR p.site_id=l.source_site_id \
             OR EXISTS(SELECT 1 FROM imports i WHERE i.operation_id=l.operation_id)) \
             OR EXISTS(SELECT 1 FROM clone_scrubs s JOIN provisions p USING(operation_id) \
             WHERE p.state<>'quarantined') \
             OR EXISTS(SELECT 1 FROM clone_scrub_grants g LEFT JOIN clone_scrubs s \
             ON s.operation_id=g.clone_operation_id WHERE s.operation_id IS NULL)",
            [],
            |row| row.get(0),
        )
        .map_err(storage::unavailable)?;
    if invalid {
        return Err(JournalError::Unavailable);
    }
    Ok(())
}

pub(crate) fn facts(
    c: &rusqlite::Connection,
    operation_id: &Id,
) -> Result<Option<CloneFacts>, JournalError> {
    let row = c
        .query_row(
            "SELECT source_site_id, source_hostname, capture_operation_id, snapshot_id, manifest_sha256, destination_policy_digest, repository_id FROM clones WHERE operation_id=?1",
            [operation_id.as_str()],
            |row| {
                [0, 1, 2, 3, 4, 5, 6]
                    .map(|index| row.get::<_, String>(index))
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()
            },
        )
        .optional()
        .map_err(storage::unavailable)?;
    let Some(texts) = row else {
        return Ok(None);
    };
    let [
        site,
        hostname,
        capture,
        snapshot,
        manifest,
        policy,
        repository,
    ] = <[String; 7]>::try_from(texts).map_err(|_| JournalError::Unavailable)?;
    let digest = |text: String| Sha256Digest::try_from(text).map_err(|_| JournalError::Unavailable);
    Ok(Some(CloneFacts {
        source_site_id: SiteId::try_from(site).map_err(|_| JournalError::Unavailable)?,
        source_hostname: Hostname::try_from(hostname).map_err(|_| JournalError::Unavailable)?,
        capture_operation_id: Id::try_from(capture).map_err(|_| JournalError::Unavailable)?,
        snapshot_id: SnapshotId::try_from(snapshot).map_err(|_| JournalError::Unavailable)?,
        manifest_sha256: digest(manifest)?,
        destination_policy_digest: digest(policy)?,
        repository_id: digest(repository)?,
    }))
}

fn state_of(text: &str) -> Result<StepState, JournalError> {
    match text {
        "intent" => Ok(StepState::Intent),
        "done" => Ok(StepState::Done),
        "failed" => Ok(StepState::Failed),
        _ => Err(JournalError::Unavailable),
    }
}

fn scrub(c: &rusqlite::Connection, operation_id: &Id) -> Result<Option<StepState>, JournalError> {
    c.query_row(
        "SELECT state FROM clone_scrubs WHERE operation_id=?1",
        [operation_id.as_str()],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(storage::unavailable)?
    .map(|text| state_of(&text))
    .transpose()
}

fn signed_scrub(
    c: &rusqlite::Connection,
    operation_id: &Id,
) -> Result<Option<StepState>, JournalError> {
    c.query_row(
        "SELECT state FROM clone_scrub_grants WHERE clone_operation_id=?1 ORDER BY rowid DESC LIMIT 1",
        [operation_id.as_str()],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(storage::unavailable)?
    .map(|text| state_of(&text))
    .transpose()
}

const GRANT_COLUMNS: &str = "operation_id, clone_operation_id, idempotency_key, grant_id, nonce, plan_digest, grant_digest, expires_at, state";

fn grant_row(
    c: &rusqlite::Connection,
    filter: &str,
    value: &str,
) -> Result<Option<(Vec<String>, i64, String)>, JournalError> {
    c.query_row(
        &format!("SELECT {GRANT_COLUMNS} FROM clone_scrub_grants WHERE {filter}"),
        [value],
        |row| {
            let texts = (0..7)
                .map(|index| row.get::<_, String>(index))
                .collect::<Result<Vec<_>, _>>()?;
            Ok((texts, row.get(7)?, row.get(8)?))
        },
    )
    .optional()
    .map_err(storage::unavailable)
}

fn grant_of(texts: &[String], state: &str) -> Result<CloneScrubGrant, JournalError> {
    Ok(CloneScrubGrant {
        operation_id: Id::try_from(texts[0].clone()).map_err(|_| JournalError::Unavailable)?,
        clone_operation_id: Id::try_from(texts[1].clone())
            .map_err(|_| JournalError::Unavailable)?,
        state: state_of(state)?,
    })
}

fn steps(
    c: &rusqlite::Connection,
    operation_id: &Id,
) -> Result<Vec<CloneStepRecord>, JournalError> {
    let mut query = c
        .prepare("SELECT position, state FROM clone_steps WHERE operation_id=?1 ORDER BY position")
        .map_err(storage::unavailable)?;
    let rows = query
        .query_map([operation_id.as_str()], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(storage::unavailable)?;
    let mut records = Vec::new();
    for (index, row) in rows.enumerate() {
        let (position, state) = row.map_err(storage::unavailable)?;
        let step = usize::try_from(position)
            .ok()
            .and_then(|position| CloneStep::ALL.get(position).copied())
            .filter(|_| position == index as i64)
            .ok_or(JournalError::Unavailable)?;
        let state = state_of(&state)?;
        records.push(CloneStepRecord { step, state });
    }
    Ok(records)
}

pub(crate) fn load(
    c: &rusqlite::Connection,
    operation_id: &Id,
) -> Result<Option<SiteClone>, JournalError> {
    match facts(c, operation_id)? {
        Some(facts) => Ok(Some(SiteClone {
            facts,
            steps: steps(c, operation_id)?,
            scrub: scrub(c, operation_id)?,
            signed_scrub: signed_scrub(c, operation_id)?,
        })),
        None => Ok(None),
    }
}

/// True for a provision without clone facts, or a clone whose five steps
/// are all done.
pub(crate) fn complete_or_absent(
    c: &rusqlite::Connection,
    operation_id: &Id,
) -> Result<bool, JournalError> {
    Ok(match load(c, operation_id)? {
        None => true,
        Some(clone) => {
            clone.steps.len() == CloneStep::ALL.len()
                && clone
                    .steps
                    .iter()
                    .all(|record| record.state == StepState::Done)
        }
    })
}

/// The provision is running with its Recipe step open (intent recorded).
fn in_recipe(c: &rusqlite::Connection, operation_id: &Id) -> Result<bool, JournalError> {
    let provision = provision::by_operation(c, operation_id)?.ok_or(JournalError::Conflict)?;
    let last = provision.steps.last();
    Ok(provision.state == ProvisionState::Running
        && last.is_some_and(|record| {
            record.step == ProvisionStep::Recipe && record.state == StepState::Intent
        }))
}

impl FixtureJournal {
    /// Records a new clone provision with its source facts, or the exact
    /// earlier status. The target reservation and the source recheck share
    /// one transaction.
    pub fn record_clone(
        &mut self,
        intent: &crate::ProvisionIntent,
        facts: &CloneFacts,
        now: rustiron_contracts::Timestamp,
    ) -> Result<crate::ProvisionResult, JournalError> {
        self.admit_provision(intent, provision::Origin::Clone(facts), now)
    }

    /// Commits a clone step's intent before its effect. The provision's
    /// Recipe step must be open, the earlier clone steps done, and this
    /// step not recorded before.
    pub fn begin_clone_step(
        &mut self,
        operation_id: &Id,
        step: CloneStep,
    ) -> Result<SiteClone, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let clone = load(&transaction, operation_id)?.ok_or(JournalError::Conflict)?;
        if !in_recipe(&transaction, operation_id)?
            || clone.steps.len() as i64 != step.position()
            || clone
                .steps
                .iter()
                .any(|record| record.state != StepState::Done)
        {
            return Err(JournalError::Conflict);
        }
        transaction
            .execute(
                "INSERT INTO clone_steps VALUES(?1,?2,'intent')",
                params![operation_id.as_str(), step.position()],
            )
            .map_err(storage::unavailable)?;
        transaction.commit().map_err(storage::unavailable)?;
        self.clone_status(operation_id)?
            .ok_or(JournalError::Unavailable)
    }

    /// Records a clone step's observed outcome. A failure fails the open
    /// Recipe step and quarantines the provision in the same transaction.
    pub fn finish_clone_step(
        &mut self,
        operation_id: &Id,
        step: CloneStep,
        done: bool,
    ) -> Result<SiteClone, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let clone = load(&transaction, operation_id)?.ok_or(JournalError::Conflict)?;
        let last = clone.steps.last().ok_or(JournalError::Conflict)?;
        if !in_recipe(&transaction, operation_id)?
            || last.step != step
            || last.state != StepState::Intent
        {
            return Err(JournalError::Conflict);
        }
        transaction
            .execute(
                "UPDATE clone_steps SET state=?1 WHERE operation_id=?2 AND position=?3",
                params![
                    if done { "done" } else { "failed" },
                    operation_id.as_str(),
                    step.position()
                ],
            )
            .map_err(storage::unavailable)?;
        if !done {
            transaction
                .execute(
                    "UPDATE provision_steps SET state='failed' WHERE operation_id=?1 AND position=?2",
                    params![operation_id.as_str(), ProvisionStep::Recipe.position()],
                )
                .map_err(storage::unavailable)?;
            provision::set_state(&transaction, operation_id, ProvisionState::Quarantined)?;
        }
        transaction.commit().map_err(storage::unavailable)?;
        self.clone_status(operation_id)?
            .ok_or(JournalError::Unavailable)
    }

    /// W501 (D-078): commits the intent of the scrub after a failed clone
    /// step, before its effect. The clone must be quarantined by that
    /// failure (its last clone step failed) and have no scrub yet. The scrub
    /// runs under the clone's own operation.
    pub fn begin_clone_scrub(&mut self, operation_id: &Id) -> Result<SiteClone, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let clone = load(&transaction, operation_id)?.ok_or(JournalError::Conflict)?;
        let provision =
            provision::by_operation(&transaction, operation_id)?.ok_or(JournalError::Conflict)?;
        if provision.state != ProvisionState::Quarantined
            || clone.steps.last().map(|record| record.state) != Some(StepState::Failed)
            || clone.scrub.is_some()
        {
            return Err(JournalError::Conflict);
        }
        transaction
            .execute(
                "INSERT INTO clone_scrubs VALUES(?1,'intent')",
                [operation_id.as_str()],
            )
            .map_err(storage::unavailable)?;
        transaction.commit().map_err(storage::unavailable)?;
        self.clone_status(operation_id)?
            .ok_or(JournalError::Unavailable)
    }

    /// W538 (D-078 signed clone scrub): records a signed scrub of a
    /// quarantined clone and opens the clone's scrub in one transaction, or
    /// returns the exact earlier one. The clone must have no open or done
    /// scrub; a failed scrub is opened again.
    pub fn record_clone_scrub(
        &mut self,
        intent: &CloneScrubIntent,
        now: Timestamp,
    ) -> Result<CloneScrubResult, JournalError> {
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
        let found = match grant_row(
            &transaction,
            "operation_id=?1",
            intent.operation_id.as_str(),
        )? {
            Some(row) => Some(row),
            None => grant_row(
                &transaction,
                "idempotency_key=?1",
                intent.idempotency_key.as_str(),
            )?,
        };
        if let Some((texts, expires_at, state)) = found {
            let exact = texts[..]
                == [
                    intent.operation_id.as_str(),
                    intent.clone_operation_id.as_str(),
                    intent.idempotency_key.as_str(),
                    intent.grant_id.as_str(),
                    intent.nonce.as_str(),
                    intent.plan_digest.as_str(),
                    intent.grant_digest.as_str(),
                ]
                && expires_at == intent.expires_at.get() as i64;
            return if exact {
                Ok(CloneScrubResult::Existing(grant_of(&texts, &state)?))
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
        let clone =
            load(&transaction, &intent.clone_operation_id)?.ok_or(JournalError::Consumed)?;
        let provision = provision::by_operation(&transaction, &intent.clone_operation_id)?
            .ok_or(JournalError::Consumed)?;
        if provision.intent.site_id != intent.site_id
            || provision.state != ProvisionState::Quarantined
            || matches!(clone.scrub, Some(StepState::Intent | StepState::Done))
            || clone.signed_scrub == Some(StepState::Intent)
        {
            return Err(JournalError::Consumed);
        }
        storage::check_clock(&transaction, now)?;
        if now.get() >= intent.expires_at.get() {
            return Err(JournalError::Expired);
        }
        transaction
            .execute(
                &format!("INSERT INTO clone_scrub_grants ({GRANT_COLUMNS}) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'intent')"),
                params![
                    intent.operation_id.as_str(),
                    intent.clone_operation_id.as_str(),
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
                "INSERT INTO clone_scrubs VALUES(?1,'intent') \
                 ON CONFLICT(operation_id) DO UPDATE SET state='intent' WHERE state='failed'",
                [intent.clone_operation_id.as_str()],
            )
            .map_err(storage::unavailable)?;
        crate::signed::insert(&transaction, &intent.operation_id, signed.as_ref())?;
        storage::set_clock(&transaction, now)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(CloneScrubResult::New(CloneScrubGrant {
            operation_id: intent.operation_id.clone(),
            clone_operation_id: intent.clone_operation_id.clone(),
            state: StepState::Intent,
        }))
    }

    /// W538: records the outcome of an open signed clone scrub and of the
    /// clone's scrub that it opened.
    pub fn finish_signed_clone_scrub(
        &mut self,
        operation_id: &Id,
        done: bool,
    ) -> Result<CloneScrubGrant, JournalError> {
        let state = if done { "done" } else { "failed" };
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let (texts, _, _) = grant_row(&transaction, "operation_id=?1", operation_id.as_str())?
            .ok_or(JournalError::Conflict)?;
        let changed = transaction
            .execute(
                "UPDATE clone_scrub_grants SET state=?1 WHERE operation_id=?2 AND state='intent'",
                params![state, operation_id.as_str()],
            )
            .map_err(storage::unavailable)?
            + transaction
                .execute(
                    "UPDATE clone_scrubs SET state=?1 WHERE operation_id=?2 AND state='intent'",
                    params![state, texts[1].as_str()],
                )
                .map_err(storage::unavailable)?;
        if changed != 2 {
            return Err(JournalError::Conflict);
        }
        transaction.commit().map_err(storage::unavailable)?;
        self.clone_scrub_status(operation_id)?
            .ok_or(JournalError::Unavailable)
    }

    /// W538: a recorded signed clone scrub by its own operation.
    pub fn clone_scrub_status(
        &self,
        operation_id: &Id,
    ) -> Result<Option<CloneScrubGrant>, JournalError> {
        grant_row(&self.connection, "operation_id=?1", operation_id.as_str())?
            .map(|(texts, _, state)| grant_of(&texts, &state))
            .transpose()
    }

    /// W501: records the observed outcome of the open clone scrub.
    pub fn finish_clone_scrub(
        &mut self,
        operation_id: &Id,
        done: bool,
    ) -> Result<SiteClone, JournalError> {
        let changed = self
            .connection
            .execute(
                "UPDATE clone_scrubs SET state=?1 WHERE operation_id=?2 AND state='intent'",
                params![if done { "done" } else { "failed" }, operation_id.as_str()],
            )
            .map_err(storage::unavailable)?;
        if changed != 1 {
            return Err(JournalError::Conflict);
        }
        self.clone_status(operation_id)?
            .ok_or(JournalError::Unavailable)
    }

    /// Recorded clone status only.
    pub fn clone_status(&self, operation_id: &Id) -> Result<Option<SiteClone>, JournalError> {
        load(&self.connection, operation_id)
    }
}
