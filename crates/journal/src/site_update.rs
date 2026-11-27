//! Signed WordPress plugin and theme updates (schema v32, W514, D-084).
//!
//! An update's intent, its signed components, and its capture are committed
//! in one transaction that rechecks the site and the capture: the site is
//! served and not ejected, has no open update and no running capture, and
//! the capture is its newest succeeded one, finished within the last hour.
//! The steps (unpack, swap, script, health) and the rollback after a failure
//! are recorded before and after each effect. Nothing here touches a host.

use rusqlite::{OptionalExtension, params};
use rustiron_contracts::{
    Id, Timestamp,
    approval::{
        ComponentSlug, ComponentVersion, MAX_UPDATE_COMPONENTS, Sha256Digest, SiteId,
        UpdateComponent, UpdateKind,
    },
};

use crate::{Admitted, FixtureJournal, JournalError, StepState, storage};

/// How old the update's capture may be when the intent is recorded.
pub const UPDATE_CAPTURE_MAX_AGE_SECONDS: u64 = 3600;

/// An admitted signed update; built by the executor from verified inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateIntent {
    /// The update's operation.
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
    /// The site's succeeded capture taken for the update.
    pub capture_operation_id: Id,
    /// SHA-256 of the recipe manifest.
    pub recipe_digest: Sha256Digest,
    /// The signed components, in plan order.
    pub components: Vec<UpdateComponent>,
    /// Normal grant deadline.
    pub expires_at: Timestamp,
}

/// The recorded outcome of an update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateState {
    /// Open: steps or a rollback may still be running or unverified.
    Intent,
    /// Every step done and the site healthy on the new versions.
    Done,
    /// A step failed and the rollback put the old code and the captured
    /// database back, verified.
    RolledBack,
}

impl UpdateState {
    fn from_name(name: &str) -> Result<Self, JournalError> {
        match name {
            "intent" => Ok(Self::Intent),
            "done" => Ok(Self::Done),
            "rolled_back" => Ok(Self::RolledBack),
            _ => Err(JournalError::Unavailable),
        }
    }
}

/// The ordered steps of an update after its intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateStep {
    /// Unpack the recipe as the site and check every file.
    Unpack,
    /// Rename each installed folder aside and the new one into place.
    Swap,
    /// The fixed PHP script as the site: clear caches, report versions.
    Script,
    /// The site's marker, PHP health, login, home page, and versions.
    Health,
}

impl UpdateStep {
    /// Every step, in order.
    pub const ALL: [Self; 4] = [Self::Unpack, Self::Swap, Self::Script, Self::Health];

    /// The step's fixed position.
    pub fn position(self) -> i64 {
        match self {
            Self::Unpack => 0,
            Self::Swap => 1,
            Self::Script => 2,
            Self::Health => 3,
        }
    }

    fn from_position(position: i64) -> Result<Self, JournalError> {
        Self::ALL
            .into_iter()
            .find(|step| step.position() == position)
            .ok_or(JournalError::Unavailable)
    }
}

/// One recorded step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpdateStepRecord {
    /// Which step.
    pub step: UpdateStep,
    /// `intent` until its outcome is observed.
    pub state: StepState,
}

/// One recorded update with its signed facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SiteUpdate {
    /// The update's operation.
    pub operation_id: Id,
    /// The updated site.
    pub site_id: SiteId,
    /// The capture taken for the update.
    pub capture_operation_id: Id,
    /// SHA-256 of the recipe manifest.
    pub recipe_digest: Sha256Digest,
    /// The signed components, in plan order.
    pub components: Vec<UpdateComponent>,
    /// The steps recorded so far, in order.
    pub steps: Vec<UpdateStepRecord>,
    /// The rollback after a failure, if begun.
    pub rollback: Option<StepState>,
    /// The update's outcome.
    pub state: UpdateState,
}

const COLUMNS: &str = "operation_id, site_id, capture_operation_id, recipe_digest, idempotency_key, grant_id, nonce, plan_digest, grant_digest, expires_at, state";

fn step_state(text: &str) -> Result<StepState, JournalError> {
    match text {
        "intent" => Ok(StepState::Intent),
        "done" => Ok(StepState::Done),
        "failed" => Ok(StepState::Failed),
        _ => Err(JournalError::Unavailable),
    }
}

fn components(
    c: &rusqlite::Connection,
    operation_id: &str,
) -> Result<Vec<UpdateComponent>, JournalError> {
    let mut statement = c
        .prepare(
            "SELECT position, kind, slug, from_version, to_version FROM update_components \
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
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(storage::unavailable)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage::unavailable)?;
    rows.into_iter()
        .enumerate()
        .map(|(index, (position, kind, slug, from, to))| {
            if position != index as i64 {
                return Err(JournalError::Unavailable);
            }
            let kind = match kind.as_str() {
                "plugin" => UpdateKind::Plugin,
                "theme" => UpdateKind::Theme,
                "core" => UpdateKind::Core,
                _ => return Err(JournalError::Unavailable),
            };
            Ok(UpdateComponent {
                kind,
                slug: ComponentSlug::try_from(slug).map_err(|_| JournalError::Unavailable)?,
                from_version: ComponentVersion::try_from(from)
                    .map_err(|_| JournalError::Unavailable)?,
                to_version: ComponentVersion::try_from(to)
                    .map_err(|_| JournalError::Unavailable)?,
            })
        })
        .collect()
}

fn steps(
    c: &rusqlite::Connection,
    operation_id: &str,
) -> Result<Vec<UpdateStepRecord>, JournalError> {
    let mut statement = c
        .prepare("SELECT position, state FROM update_steps WHERE operation_id=?1 ORDER BY position")
        .map_err(storage::unavailable)?;
    let rows = statement
        .query_map([operation_id], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(storage::unavailable)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage::unavailable)?;
    rows.into_iter()
        .enumerate()
        .map(|(index, (position, state))| {
            if position != index as i64 {
                return Err(JournalError::Unavailable);
            }
            Ok(UpdateStepRecord {
                step: UpdateStep::from_position(position)?,
                state: step_state(&state)?,
            })
        })
        .collect()
}

/// The stored update with this operation, if any.
pub(crate) fn load(
    c: &rusqlite::Connection,
    operation_id: &Id,
) -> Result<Option<SiteUpdate>, JournalError> {
    let row = c
        .query_row(
            "SELECT site_id, capture_operation_id, recipe_digest, state FROM updates \
             WHERE operation_id=?1",
            [operation_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()
        .map_err(storage::unavailable)?;
    let Some((site, capture, recipe, state)) = row else {
        return Ok(None);
    };
    let rollback = c
        .query_row(
            "SELECT state FROM update_rollbacks WHERE operation_id=?1",
            [operation_id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(storage::unavailable)?
        .map(|text| step_state(&text))
        .transpose()?;
    Ok(Some(SiteUpdate {
        operation_id: operation_id.clone(),
        site_id: SiteId::try_from(site).map_err(|_| JournalError::Unavailable)?,
        capture_operation_id: Id::try_from(capture).map_err(|_| JournalError::Unavailable)?,
        recipe_digest: Sha256Digest::try_from(recipe).map_err(|_| JournalError::Unavailable)?,
        components: components(c, operation_id.as_str())?,
        steps: steps(c, operation_id.as_str())?,
        rollback,
        state: UpdateState::from_name(&state)?,
    }))
}

/// The stored row under the intent's operation or retry key, and whether
/// it is exactly this intent.
fn stored(
    c: &rusqlite::Connection,
    intent: &UpdateIntent,
) -> Result<Option<(bool, SiteUpdate)>, JournalError> {
    let row = c
        .query_row(
            &format!("SELECT {COLUMNS} FROM updates WHERE operation_id=?1 OR idempotency_key=?2"),
            params![
                intent.operation_id.as_str(),
                intent.idempotency_key.as_str()
            ],
            |row| {
                let texts = [0, 1, 2, 3, 4, 5, 6, 7, 8]
                    .map(|index| row.get::<_, String>(index))
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()?;
                Ok((texts, row.get::<_, i64>(9)?))
            },
        )
        .optional()
        .map_err(storage::unavailable)?;
    let Some((texts, expires_at)) = row else {
        return Ok(None);
    };
    let operation = Id::try_from(texts[0].clone()).map_err(|_| JournalError::Unavailable)?;
    let existing = load(c, &operation)?.ok_or(JournalError::Unavailable)?;
    let exact = texts
        == [
            intent.operation_id.as_str(),
            intent.site_id.as_str(),
            intent.capture_operation_id.as_str(),
            intent.recipe_digest.as_str(),
            intent.idempotency_key.as_str(),
            intent.grant_id.as_str(),
            intent.nonce.as_str(),
            intent.plan_digest.as_str(),
            intent.grant_digest.as_str(),
        ]
        && expires_at == intent.expires_at.get() as i64
        && existing.components == intent.components;
    Ok(Some((exact, existing)))
}

/// The site is served by its own succeeded or adopted provision and is not
/// ejected; the capture is the site's newest succeeded capture, finished at
/// most an hour before `now`; and no capture of the site is running.
fn basis_holds(
    c: &rusqlite::Connection,
    intent: &UpdateIntent,
    now: Timestamp,
) -> Result<bool, JournalError> {
    let site = intent.site_id.as_str();
    let served: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM provisions WHERE site_id=?1 AND state IN ('succeeded','adopted'))",
            [site],
            |row| row.get(0),
        )
        .map_err(storage::unavailable)?;
    let ejected = crate::provision::ejected(c)?
        .iter()
        .any(|ejected| ejected == &intent.site_id);
    let capture = c
        .query_row(
            "SELECT site_id, state, finished_at FROM captures WHERE operation_id=?1",
            [intent.capture_operation_id.as_str()],
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
    let (newer, running): (bool, bool) = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM captures WHERE site_id=?1 AND state='succeeded' \
             AND operation_id<>?2 AND finished_at>=?3), \
             EXISTS(SELECT 1 FROM captures WHERE site_id=?1 AND state='running')",
            params![site, intent.capture_operation_id.as_str(), finished],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(storage::unavailable)?;
    let now = now.get() as i64;
    Ok(served
        && !ejected
        && capture_site == site
        && state == "succeeded"
        && !newer
        && !running
        && finished <= now
        && now - finished <= UPDATE_CAPTURE_MAX_AGE_SECONDS as i64)
}

/// Every update has 1 to 8 contiguous components and contiguous steps, a
/// done update has every step done and no rollback, and a rolled-back
/// update has a done rollback after a failed step.
pub(crate) fn validate(c: &rusqlite::Connection) -> Result<(), JournalError> {
    let mut statement = c
        .prepare("SELECT operation_id FROM updates")
        .map_err(storage::unavailable)?;
    let operations = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(storage::unavailable)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage::unavailable)?;
    for operation in operations {
        let id = Id::try_from(operation).map_err(|_| JournalError::Unavailable)?;
        let update = load(c, &id)?.ok_or(JournalError::Unavailable)?;
        let all_done = update.steps.len() == UpdateStep::ALL.len()
            && update
                .steps
                .iter()
                .all(|record| record.state == StepState::Done);
        let failed = update
            .steps
            .last()
            .is_some_and(|record| record.state == StepState::Failed);
        let open_before_last = update
            .steps
            .iter()
            .rev()
            .skip(1)
            .any(|record| record.state != StepState::Done);
        let consistent = match update.state {
            UpdateState::Intent => true,
            UpdateState::Done => all_done && update.rollback.is_none(),
            UpdateState::RolledBack => failed && update.rollback == Some(StepState::Done),
        };
        // W526 (D-086): a core update holds core only, as `wordpress`.
        let core_alone = update.components.iter().all(|c| c.kind != UpdateKind::Core)
            || (update.components.len() == 1
                && update.components[0].slug.as_str() == rustiron_contracts::approval::CORE_SLUG);
        if update.components.is_empty()
            || update.components.len() > MAX_UPDATE_COMPONENTS
            || !core_alone
            || open_before_last
            || (update.rollback.is_some() && !failed)
            || !consistent
        {
            return Err(JournalError::Unavailable);
        }
    }
    Ok(())
}

impl FixtureJournal {
    /// Records a new update with its components, or returns the exact
    /// earlier one. The site and capture checks share the intent's
    /// transaction. Nothing is recorded when a check fails.
    pub fn record_update(
        &mut self,
        intent: &UpdateIntent,
        now: Timestamp,
    ) -> Result<Admitted<SiteUpdate>, JournalError> {
        let signed = self.take_signed(&crate::signed::Expected {
            plan_digest: &intent.plan_digest,
            grant_digest: &intent.grant_digest,
        })?;
        if intent.host_id != self.host_id || intent.host_epoch != self.host_epoch {
            return Err(JournalError::Conflict);
        }
        if intent.components.is_empty() || intent.components.len() > MAX_UPDATE_COMPONENTS {
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
        let open: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM updates WHERE site_id=?1 AND state='intent') \
                 OR EXISTS(SELECT 1 FROM site_restores WHERE site_id=?1 AND state='intent') \
                 OR EXISTS(SELECT 1 FROM credential_rotations WHERE site_id=?1 AND state IN ('intent','needs_attention'))",
                [intent.site_id.as_str()],
                |row| row.get(0),
            )
            .map_err(storage::unavailable)?;
        if open {
            return Err(JournalError::Busy);
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
                    "INSERT INTO updates ({COLUMNS}) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'intent')"
                ),
                params![
                    intent.operation_id.as_str(),
                    intent.site_id.as_str(),
                    intent.capture_operation_id.as_str(),
                    intent.recipe_digest.as_str(),
                    intent.idempotency_key.as_str(),
                    intent.grant_id.as_str(),
                    intent.nonce.as_str(),
                    intent.plan_digest.as_str(),
                    intent.grant_digest.as_str(),
                    intent.expires_at.get() as i64,
                ],
            )
            .map_err(storage::unavailable)?;
        for (position, component) in intent.components.iter().enumerate() {
            transaction
                .execute(
                    "INSERT INTO update_components VALUES(?1,?2,?3,?4,?5,?6)",
                    params![
                        intent.operation_id.as_str(),
                        position as i64,
                        component.kind.as_str(),
                        component.slug.as_str(),
                        component.from_version.as_str(),
                        component.to_version.as_str(),
                    ],
                )
                .map_err(storage::unavailable)?;
        }
        crate::signed::insert(&transaction, &intent.operation_id, signed.as_ref())?;
        storage::set_clock(&transaction, now)?;
        let recorded =
            load(&transaction, &intent.operation_id)?.ok_or(JournalError::Unavailable)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(Admitted::New(recorded))
    }

    /// Commits a step's intent before its effect. The update must be open
    /// with no rollback, the earlier steps done, and this step next.
    pub fn begin_update_step(
        &mut self,
        operation_id: &Id,
        step: UpdateStep,
    ) -> Result<SiteUpdate, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let update = load(&transaction, operation_id)?.ok_or(JournalError::Conflict)?;
        if update.state != UpdateState::Intent
            || update.rollback.is_some()
            || update.steps.len() as i64 != step.position()
            || update
                .steps
                .iter()
                .any(|record| record.state != StepState::Done)
        {
            return Err(JournalError::Conflict);
        }
        transaction
            .execute(
                "INSERT INTO update_steps VALUES(?1,?2,'intent')",
                params![operation_id.as_str(), step.position()],
            )
            .map_err(storage::unavailable)?;
        transaction.commit().map_err(storage::unavailable)?;
        self.update_status(operation_id)?
            .ok_or(JournalError::Unavailable)
    }

    /// Records the open step's observed outcome. After the Health step is
    /// done, the update is done in the same transaction.
    pub fn finish_update_step(
        &mut self,
        operation_id: &Id,
        step: UpdateStep,
        done: bool,
    ) -> Result<SiteUpdate, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let update = load(&transaction, operation_id)?.ok_or(JournalError::Conflict)?;
        let last = update.steps.last().ok_or(JournalError::Conflict)?;
        if update.state != UpdateState::Intent
            || last.step != step
            || last.state != StepState::Intent
        {
            return Err(JournalError::Conflict);
        }
        transaction
            .execute(
                "UPDATE update_steps SET state=?1 WHERE operation_id=?2 AND position=?3",
                params![
                    if done { "done" } else { "failed" },
                    operation_id.as_str(),
                    step.position()
                ],
            )
            .map_err(storage::unavailable)?;
        if done && step == UpdateStep::Health {
            transaction
                .execute(
                    "UPDATE updates SET state='done' WHERE operation_id=?1",
                    [operation_id.as_str()],
                )
                .map_err(storage::unavailable)?;
        }
        transaction.commit().map_err(storage::unavailable)?;
        self.update_status(operation_id)?
            .ok_or(JournalError::Unavailable)
    }

    /// Commits the rollback's intent before its effect. The update must be
    /// open and its last step failed. W518-F2: a rollback that failed may be
    /// begun again by the operator's reconcile; an open one may not.
    pub fn begin_update_rollback(&mut self, operation_id: &Id) -> Result<SiteUpdate, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let update = load(&transaction, operation_id)?.ok_or(JournalError::Conflict)?;
        if update.state != UpdateState::Intent
            || update.rollback == Some(StepState::Intent)
            || update.steps.last().map(|record| record.state) != Some(StepState::Failed)
        {
            return Err(JournalError::Conflict);
        }
        transaction
            .execute(
                "INSERT INTO update_rollbacks VALUES(?1,'intent') \
                 ON CONFLICT(operation_id) DO UPDATE SET state='intent' WHERE state='failed'",
                [operation_id.as_str()],
            )
            .map_err(storage::unavailable)?;
        transaction.commit().map_err(storage::unavailable)?;
        self.update_status(operation_id)?
            .ok_or(JournalError::Unavailable)
    }

    /// Records the rollback's observed outcome. A verified rollback ends the
    /// update as `rolled_back`; a failed one leaves it open for the operator.
    pub fn finish_update_rollback(
        &mut self,
        operation_id: &Id,
        done: bool,
    ) -> Result<SiteUpdate, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let changed = transaction
            .execute(
                "UPDATE update_rollbacks SET state=?1 WHERE operation_id=?2 AND state='intent'",
                params![if done { "done" } else { "failed" }, operation_id.as_str()],
            )
            .map_err(storage::unavailable)?;
        if changed != 1 {
            return Err(JournalError::Conflict);
        }
        if done {
            transaction
                .execute(
                    "UPDATE updates SET state='rolled_back' WHERE operation_id=?1 AND state='intent'",
                    [operation_id.as_str()],
                )
                .map_err(storage::unavailable)?;
        }
        transaction.commit().map_err(storage::unavailable)?;
        self.update_status(operation_id)?
            .ok_or(JournalError::Unavailable)
    }

    /// A recorded update by its operation.
    pub fn update_status(&self, operation_id: &Id) -> Result<Option<SiteUpdate>, JournalError> {
        load(&self.connection, operation_id)
    }

    /// W515: the site and capture rule of [`Self::record_update`], read
    /// only, for the executor's checks before intent. The same rule runs
    /// again in the transaction that records the intent.
    pub fn update_basis_holds(
        &self,
        intent: &UpdateIntent,
        now: Timestamp,
    ) -> Result<bool, JournalError> {
        let open: bool = self
            .connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM updates WHERE site_id=?1 AND state='intent') \
                 OR EXISTS(SELECT 1 FROM site_restores WHERE site_id=?1 AND state='intent') \
                 OR EXISTS(SELECT 1 FROM credential_rotations WHERE site_id=?1 AND state IN ('intent','needs_attention'))",
                [intent.site_id.as_str()],
                |row| row.get(0),
            )
            .map_err(storage::unavailable)?;
        Ok(!open && basis_holds(&self.connection, intent, now)?)
    }
}
