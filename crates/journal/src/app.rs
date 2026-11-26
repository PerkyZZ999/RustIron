//! Modern app hosting journal tables (schema v43, W597, D-099).
//!
//! An app site is a provision with an `apps` row and matching `proxy_routes`
//! rows committed in the same transaction. Releases (`app_releases` +
//! `app_release_steps`) and unit lifecycle transitions (`app_lifecycles`)
//! record durable intent before host effects, preserve exact idempotent
//! retries, enforce one open release/lifecycle per site, and validate every
//! invariant on open. Nothing here touches a host.

use rusqlite::{Connection, OptionalExtension, params};
use rustiron_contracts::{
    Id, Timestamp,
    approval::{
        AppLifecycleAction, AppRuntime, MAX_APP_MEMORY_MIB, MAX_APP_QUOTA_MIB,
        MAX_APP_RELEASE_BYTES, MAX_APP_RELEASE_FILES, MAX_APP_TASKS_MAX, MIN_APP_MEMORY_MIB,
        MIN_APP_QUOTA_MIB, MIN_APP_TASKS_MAX, Sha256Digest, SiteId, routable_port,
        valid_entrypoint, valid_env_keys, valid_health_path, valid_release_id,
    },
};

use crate::{
    FixtureJournal, JournalError, ProvisionIntent, ProvisionResult, ProxyFacts, StepState,
    provision::Origin, storage,
};

/// Maximum age of a capture bound to a migrating `app_deploy` (24 hours).
pub const APP_MIGRATION_CAPTURE_MAX_AGE_SECONDS: u64 = 24 * 3600;

/// Signed runtime, port, entrypoint, resource, and proxy-route facts of one app site.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppFacts {
    /// Pinned runtime profile (`node_22_v1` or `bun_1_v1`).
    pub runtime: AppRuntime,
    /// Loopback port on `127.0.0.1`.
    pub port: u16,
    /// Relative release entrypoint for the HTTP app unit.
    pub entrypoint: String,
    /// Optional relative release entrypoint for a companion worker unit.
    pub worker_entrypoint: Option<String>,
    /// Loopback HTTP health check path.
    pub health_path: String,
    /// Sorted, unique declared environment variable key names (never values).
    pub env_keys: Vec<String>,
    /// Cgroup `MemoryMax` in MiB.
    pub memory_max_mib: u64,
    /// Cgroup `TasksMax`.
    pub tasks_max: u64,
    /// Site filesystem quota in MiB.
    pub quota_mib: u64,
    /// CP08 proxy routes and WebSocket paths, all targeting `port`.
    pub routes: ProxyFacts,
}

impl AppFacts {
    /// Validates every intrinsic invariant against the D-099 contract.
    pub fn is_valid(&self) -> bool {
        routable_port(self.port)
            && valid_entrypoint(&self.entrypoint)
            && self
                .worker_entrypoint
                .as_deref()
                .is_none_or(valid_entrypoint)
            && valid_health_path(&self.health_path)
            && valid_env_keys(&self.env_keys)
            && (MIN_APP_MEMORY_MIB..=MAX_APP_MEMORY_MIB).contains(&self.memory_max_mib)
            && (MIN_APP_TASKS_MAX..=MAX_APP_TASKS_MAX).contains(&self.tasks_max)
            && (MIN_APP_QUOTA_MIB..=MAX_APP_QUOTA_MIB).contains(&self.quota_mib)
            && self.routes.is_valid()
            && self
                .routes
                .routes
                .iter()
                .chain(&self.routes.websockets)
                .all(|route| route.port == self.port)
    }
}

/// Admitted signed app release deployment intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppReleaseIntent {
    /// Release deployment operation ID.
    pub operation_id: Id,
    /// Retry key bound to every field.
    pub idempotency_key: Id,
    /// Signed grant ID.
    pub grant_id: Id,
    /// Single-use signed nonce.
    pub nonce: Id,
    /// Complete plan digest.
    pub plan_digest: Sha256Digest,
    /// Complete canonical grant digest.
    pub grant_digest: Sha256Digest,
    /// Enrolled host ID.
    pub host_id: Id,
    /// Enrolled host epoch.
    pub host_epoch: Id,
    /// Target app site ID.
    pub site_id: SiteId,
    /// Unique release identifier for this site.
    pub release_id: String,
    /// Runtime profile matching the app site.
    pub runtime: AppRuntime,
    /// SHA-256 of the prepared release archive.
    pub artifact_sha256: Sha256Digest,
    /// SHA-256 of the sorted per-file manifest.
    pub manifest_sha256: Sha256Digest,
    /// File count in the release archive.
    pub file_count: u64,
    /// Total unpacked bytes in the release archive.
    pub total_bytes: u64,
    /// Optional bounded migration entrypoint run as `rs_<site_id>`.
    pub migration_entrypoint: Option<String>,
    /// Capture operation ID (required when `migration_entrypoint` is `Some`).
    pub capture_operation_id: Option<Id>,
    /// Loopback HTTP health check path.
    pub health_path: String,
    /// Normal grant deadline.
    pub expires_at: Timestamp,
}

impl AppReleaseIntent {
    fn is_valid(&self) -> bool {
        let migration_ok = match (&self.migration_entrypoint, &self.capture_operation_id) {
            (Some(entry), Some(_)) => valid_entrypoint(entry),
            (Some(_), None) => false,
            (None, _) => true,
        };
        valid_release_id(&self.release_id)
            && (1..=MAX_APP_RELEASE_FILES).contains(&self.file_count)
            && (1..=MAX_APP_RELEASE_BYTES).contains(&self.total_bytes)
            && migration_ok
            && valid_health_path(&self.health_path)
    }
}

/// Recorded outcome of an app release deployment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppReleaseState {
    /// Open: steps or rollback may still be in progress or unverified.
    Intent,
    /// Activated and verified healthy on loopback.
    Done,
    /// Failed and rolled back cleanly to the previous release.
    RolledBack,
}

impl AppReleaseState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::Done => "done",
            Self::RolledBack => "rolled_back",
        }
    }

    fn from_name(name: &str) -> Result<Self, JournalError> {
        match name {
            "intent" => Ok(Self::Intent),
            "done" => Ok(Self::Done),
            "rolled_back" => Ok(Self::RolledBack),
            _ => Err(JournalError::Unavailable),
        }
    }
}

/// Ordered steps of an `app_deploy` execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppReleaseStep {
    /// Unpack archive as site account and verify file manifest.
    Unpack,
    /// Run optional bounded migration as site account (with pre-migration snapshot).
    Migrate,
    /// Atomically switch `current` symlink and restart unit(s).
    Activate,
    /// Bounded loopback HTTP health check and systemd active check.
    Health,
    /// Automatic or reconciled rollback to previous release on failure.
    Rollback,
}

impl AppReleaseStep {
    /// Every step in fixed position order.
    pub const ALL: [Self; 5] = [
        Self::Unpack,
        Self::Migrate,
        Self::Activate,
        Self::Health,
        Self::Rollback,
    ];

    /// Numeric column position in `app_release_steps`.
    pub fn position(self) -> i64 {
        match self {
            Self::Unpack => 0,
            Self::Migrate => 1,
            Self::Activate => 2,
            Self::Health => 3,
            Self::Rollback => 4,
        }
    }

    fn from_position(position: i64) -> Result<Self, JournalError> {
        Self::ALL
            .into_iter()
            .find(|step| step.position() == position)
            .ok_or(JournalError::Unavailable)
    }
}

/// One recorded release step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppReleaseStepRecord {
    /// Which step.
    pub step: AppReleaseStep,
    /// Step state (`intent`, `done`, or `failed`).
    pub state: StepState,
}

/// One recorded app release deployment with its steps.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppRelease {
    /// Deployment operation ID.
    pub operation_id: Id,
    /// Target app site ID.
    pub site_id: SiteId,
    /// Release identifier.
    pub release_id: String,
    /// Runtime profile.
    pub runtime: AppRuntime,
    /// Archive SHA-256.
    pub artifact_sha256: Sha256Digest,
    /// Manifest SHA-256.
    pub manifest_sha256: Sha256Digest,
    /// File count.
    pub file_count: u64,
    /// Total unpacked bytes.
    pub total_bytes: u64,
    /// Optional migration entrypoint.
    pub migration_entrypoint: Option<String>,
    /// Optional capture operation ID.
    pub capture_operation_id: Option<Id>,
    /// Health path.
    pub health_path: String,
    /// Steps recorded so far.
    pub steps: Vec<AppReleaseStepRecord>,
    /// Overall deployment outcome.
    pub state: AppReleaseState,
}

/// Result of recording an `app_deploy` intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AppReleaseResult {
    /// Newly recorded in `intent`.
    New(AppRelease),
    /// Exact idempotent retry returning existing state.
    Existing(AppRelease),
}

/// Admitted signed `app_lifecycle` intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppLifecycleIntent {
    /// Lifecycle operation ID.
    pub operation_id: Id,
    /// Retry key bound to every field.
    pub idempotency_key: Id,
    /// Signed grant ID.
    pub grant_id: Id,
    /// Single-use signed nonce.
    pub nonce: Id,
    /// Complete plan digest.
    pub plan_digest: Sha256Digest,
    /// Complete canonical grant digest.
    pub grant_digest: Sha256Digest,
    /// Enrolled host ID.
    pub host_id: Id,
    /// Enrolled host epoch.
    pub host_epoch: Id,
    /// Target app site ID.
    pub site_id: SiteId,
    /// Requested action (`start`, `stop`, `restart`).
    pub action: AppLifecycleAction,
    /// Normal grant deadline.
    pub expires_at: Timestamp,
}

/// One recorded app lifecycle operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppLifecycle {
    /// Lifecycle operation ID.
    pub operation_id: Id,
    /// Target app site ID.
    pub site_id: SiteId,
    /// Action requested.
    pub action: AppLifecycleAction,
    /// Current state (`intent`, `done`, or `failed`).
    pub state: StepState,
}

/// Result of recording an `app_lifecycle` intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AppLifecycleResult {
    /// Newly recorded in `intent`.
    New(AppLifecycle),
    /// Exact idempotent retry returning existing state.
    Existing(AppLifecycle),
}

fn runtime_from_str(text: &str) -> Result<AppRuntime, JournalError> {
    match text {
        "node_22_v1" => Ok(AppRuntime::Node22V1),
        "bun_1_v1" => Ok(AppRuntime::Bun1V1),
        _ => Err(JournalError::Unavailable),
    }
}

fn action_from_str(text: &str) -> Result<AppLifecycleAction, JournalError> {
    match text {
        "start" => Ok(AppLifecycleAction::Start),
        "stop" => Ok(AppLifecycleAction::Stop),
        "restart" => Ok(AppLifecycleAction::Restart),
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

impl FixtureJournal {
    /// Records a new app site provision with its runtime facts and proxy routes
    /// in one transaction, or returns the exact earlier status.
    pub fn record_app_provision(
        &mut self,
        intent: &ProvisionIntent,
        facts: &AppFacts,
        now: Timestamp,
    ) -> Result<ProvisionResult, JournalError> {
        if !facts.is_valid() {
            return Err(JournalError::Conflict);
        }
        self.admit_provision(intent, Origin::App(facts), now)
    }

    /// Reads the app facts of a provision operation, if it is an app site.
    pub fn app_facts(&self, operation_id: &Id) -> Result<Option<AppFacts>, JournalError> {
        facts(&self.connection, operation_id)
    }

    /// Reads the app facts of a site ID, if it is an app site.
    pub fn app_facts_by_site(&self, site_id: &SiteId) -> Result<Option<AppFacts>, JournalError> {
        facts_by_site(&self.connection, site_id)
    }

    /// Reads one app release record by operation ID, if recorded.
    pub fn app_release(&self, operation_id: &Id) -> Result<Option<AppRelease>, JournalError> {
        load_release(&self.connection, operation_id)
    }

    /// Reads one app lifecycle record by operation ID, if recorded.
    pub fn app_lifecycle(&self, operation_id: &Id) -> Result<Option<AppLifecycle>, JournalError> {
        load_lifecycle(&self.connection, operation_id)
    }

    /// Records a new signed `app_deploy` release intent in one transaction, or
    /// returns the exact earlier state on idempotent retry.
    pub fn record_app_release(
        &mut self,
        intent: &AppReleaseIntent,
        now: Timestamp,
    ) -> Result<AppReleaseResult, JournalError> {
        let signed = self.take_signed(&crate::signed::Expected {
            plan_digest: &intent.plan_digest,
            grant_digest: &intent.grant_digest,
        })?;
        if intent.host_id != self.host_id
            || intent.host_epoch != self.host_epoch
            || !intent.is_valid()
        {
            return Err(JournalError::Conflict);
        }
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        if let Some((exact, existing)) = stored_release(&transaction, intent)? {
            return if exact {
                Ok(AppReleaseResult::Existing(existing))
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
        if storage::readoption_verifying(&transaction)? {
            return Err(JournalError::Busy);
        }
        if !release_basis_holds(&transaction, intent, now)? {
            return Err(JournalError::SourceChanged);
        }
        transaction
            .execute(
                "INSERT INTO app_releases VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,'intent')",
                params![
                    intent.operation_id.as_str(),
                    intent.site_id.as_str(),
                    intent.release_id,
                    intent.runtime.as_str(),
                    intent.artifact_sha256.as_str(),
                    intent.manifest_sha256.as_str(),
                    intent.file_count as i64,
                    intent.total_bytes as i64,
                    intent.migration_entrypoint.as_deref(),
                    intent.capture_operation_id.as_ref().map(Id::as_str),
                    intent.health_path,
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
        let recorded =
            load_release(&transaction, &intent.operation_id)?.ok_or(JournalError::Unavailable)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(AppReleaseResult::New(recorded))
    }

    /// Records the durable `intent` of one release step before its host effect.
    pub fn begin_app_release_step(
        &mut self,
        operation_id: &Id,
        step: AppReleaseStep,
    ) -> Result<AppRelease, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let current = load_release(&transaction, operation_id)?.ok_or(JournalError::Conflict)?;
        if current.state != AppReleaseState::Intent
            || current.steps.iter().any(|s| s.state == StepState::Intent)
            || current.steps.iter().any(|s| s.step == step)
        {
            return Err(JournalError::Conflict);
        }
        let can_begin = match step {
            AppReleaseStep::Unpack => current.steps.is_empty(),
            AppReleaseStep::Migrate => {
                current.migration_entrypoint.is_some()
                    && step_is_done(&current.steps, AppReleaseStep::Unpack)
            }
            AppReleaseStep::Activate => {
                step_is_done(&current.steps, AppReleaseStep::Unpack)
                    && (current.migration_entrypoint.is_none()
                        || step_is_done(&current.steps, AppReleaseStep::Migrate))
            }
            AppReleaseStep::Health => step_is_done(&current.steps, AppReleaseStep::Activate),
            AppReleaseStep::Rollback => current.steps.iter().any(|s| s.state == StepState::Failed),
        };
        if !can_begin {
            return Err(JournalError::Conflict);
        }
        transaction
            .execute(
                "INSERT INTO app_release_steps VALUES(?1,?2,'intent')",
                params![operation_id.as_str(), step.position()],
            )
            .map_err(storage::unavailable)?;
        let updated = load_release(&transaction, operation_id)?.ok_or(JournalError::Unavailable)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(updated)
    }

    /// Records the outcome (`done` or `failed`) of an in-progress release step.
    pub fn finish_app_release_step(
        &mut self,
        operation_id: &Id,
        step: AppReleaseStep,
        done: bool,
    ) -> Result<AppRelease, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let current = load_release(&transaction, operation_id)?.ok_or(JournalError::Conflict)?;
        if current.state != AppReleaseState::Intent
            || !current
                .steps
                .iter()
                .any(|s| s.step == step && s.state == StepState::Intent)
        {
            return Err(JournalError::Conflict);
        }
        let state = if done { "done" } else { "failed" };
        transaction
            .execute(
                "UPDATE app_release_steps SET state=?1 WHERE operation_id=?2 AND position=?3",
                params![state, operation_id.as_str(), step.position()],
            )
            .map_err(storage::unavailable)?;
        let updated = load_release(&transaction, operation_id)?.ok_or(JournalError::Unavailable)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(updated)
    }

    /// Settles an open app release deployment to `Done` or `RolledBack`.
    pub fn finish_app_release(
        &mut self,
        operation_id: &Id,
        state: AppReleaseState,
    ) -> Result<AppRelease, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let current = load_release(&transaction, operation_id)?.ok_or(JournalError::Conflict)?;
        if current.state != AppReleaseState::Intent {
            return Err(JournalError::Conflict);
        }
        let allowed = match state {
            AppReleaseState::Intent => false,
            AppReleaseState::Done => step_is_done(&current.steps, AppReleaseStep::Health),
            AppReleaseState::RolledBack => step_is_done(&current.steps, AppReleaseStep::Rollback),
        };
        if !allowed {
            return Err(JournalError::Conflict);
        }
        transaction
            .execute(
                "UPDATE app_releases SET state=?1 WHERE operation_id=?2",
                params![state.as_str(), operation_id.as_str()],
            )
            .map_err(storage::unavailable)?;
        let updated = load_release(&transaction, operation_id)?.ok_or(JournalError::Unavailable)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(updated)
    }

    /// Returns the newest `done` release for an app site, if any.
    pub fn latest_app_release(&self, site_id: &SiteId) -> Result<Option<AppRelease>, JournalError> {
        let operation_id: Option<String> = self
            .connection
            .query_row(
                "SELECT operation_id FROM app_releases WHERE site_id=?1 AND state='done' \
                 ORDER BY rowid DESC LIMIT 1",
                [site_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage::unavailable)?;
        let Some(operation_id) = operation_id else {
            return Ok(None);
        };
        let id = Id::try_from(operation_id).map_err(|_| JournalError::Unavailable)?;
        load_release(&self.connection, &id)
    }

    /// Records a new signed `app_lifecycle` intent in one transaction, or
    /// returns the exact earlier state on idempotent retry.
    pub fn record_app_lifecycle(
        &mut self,
        intent: &AppLifecycleIntent,
        now: Timestamp,
    ) -> Result<AppLifecycleResult, JournalError> {
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
        if let Some((exact, existing)) = stored_lifecycle(&transaction, intent)? {
            return if exact {
                Ok(AppLifecycleResult::Existing(existing))
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
        if storage::readoption_verifying(&transaction)? {
            return Err(JournalError::Busy);
        }
        if !lifecycle_basis_holds(&transaction, &intent.site_id)? {
            return Err(JournalError::SourceChanged);
        }
        transaction
            .execute(
                "INSERT INTO app_lifecycles VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,'intent')",
                params![
                    intent.operation_id.as_str(),
                    intent.site_id.as_str(),
                    intent.action.as_str(),
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
        let recorded =
            load_lifecycle(&transaction, &intent.operation_id)?.ok_or(JournalError::Unavailable)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(AppLifecycleResult::New(recorded))
    }

    /// Settles an open `app_lifecycle` operation to `done` or `failed`.
    pub fn finish_app_lifecycle(
        &mut self,
        operation_id: &Id,
        done: bool,
    ) -> Result<AppLifecycle, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let current = load_lifecycle(&transaction, operation_id)?.ok_or(JournalError::Conflict)?;
        if current.state != StepState::Intent {
            return Err(JournalError::Conflict);
        }
        let state = if done { "done" } else { "failed" };
        transaction
            .execute(
                "UPDATE app_lifecycles SET state=?1 WHERE operation_id=?2",
                params![state, operation_id.as_str()],
            )
            .map_err(storage::unavailable)?;
        let updated =
            load_lifecycle(&transaction, operation_id)?.ok_or(JournalError::Unavailable)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(updated)
    }
}

fn step_is_done(steps: &[AppReleaseStepRecord], target: AppReleaseStep) -> bool {
    steps
        .iter()
        .any(|s| s.step == target && s.state == StepState::Done)
}

/// Whether `port` is already reserved by any active (non-deleted, non-quarantined) app.
pub(crate) fn port_taken(c: &Connection, port: u16) -> Result<bool, JournalError> {
    c.query_row(
        "SELECT EXISTS(SELECT 1 FROM apps a JOIN provisions p ON p.operation_id=a.operation_id \
         WHERE a.port=?1 AND p.state IN ('running','succeeded','adopted'))",
        [i64::from(port)],
        |row| row.get(0),
    )
    .map_err(storage::unavailable)
}

pub(crate) fn insert(
    c: &Connection,
    operation_id: &Id,
    facts: &AppFacts,
) -> Result<(), JournalError> {
    let env_keys = facts.env_keys.join(",");
    c.execute(
        "INSERT INTO apps VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![
            operation_id.as_str(),
            facts.runtime.as_str(),
            i64::from(facts.port),
            facts.entrypoint,
            facts.worker_entrypoint.as_deref(),
            facts.health_path,
            env_keys,
            facts.memory_max_mib as i64,
            facts.tasks_max as i64,
            facts.quota_mib as i64,
        ],
    )
    .map_err(storage::unavailable)?;
    crate::proxy::insert(c, operation_id, &facts.routes)?;
    Ok(())
}

pub(crate) fn facts(c: &Connection, operation_id: &Id) -> Result<Option<AppFacts>, JournalError> {
    let row = c
        .query_row(
            "SELECT runtime, port, entrypoint, worker_entrypoint, health_path, env_keys, \
             memory_max_mib, tasks_max, quota_mib FROM apps WHERE operation_id=?1",
            [operation_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                ))
            },
        )
        .optional()
        .map_err(storage::unavailable)?;
    let Some((
        runtime,
        port,
        entrypoint,
        worker_entrypoint,
        health_path,
        env_keys,
        memory_max_mib,
        tasks_max,
        quota_mib,
    )) = row
    else {
        return Ok(None);
    };
    let routes = crate::proxy::facts(c, operation_id)?.ok_or(JournalError::Unavailable)?;
    let env_keys: Vec<String> = if env_keys.is_empty() {
        Vec::new()
    } else {
        env_keys.split(',').map(str::to_owned).collect()
    };
    let app = AppFacts {
        runtime: runtime_from_str(&runtime)?,
        port: u16::try_from(port).map_err(|_| JournalError::Unavailable)?,
        entrypoint,
        worker_entrypoint,
        health_path,
        env_keys,
        memory_max_mib: u64::try_from(memory_max_mib).map_err(|_| JournalError::Unavailable)?,
        tasks_max: u64::try_from(tasks_max).map_err(|_| JournalError::Unavailable)?,
        quota_mib: u64::try_from(quota_mib).map_err(|_| JournalError::Unavailable)?,
        routes,
    };
    if !app.is_valid() {
        return Err(JournalError::Unavailable);
    }
    Ok(Some(app))
}

pub(crate) fn facts_by_site(
    c: &Connection,
    site_id: &SiteId,
) -> Result<Option<AppFacts>, JournalError> {
    let op: Option<String> = c
        .query_row(
            "SELECT operation_id FROM provisions WHERE site_id=?1",
            [site_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage::unavailable)?;
    let Some(op) = op else {
        return Ok(None);
    };
    let id = Id::try_from(op).map_err(|_| JournalError::Unavailable)?;
    facts(c, &id)
}

pub(crate) fn has_done_release(c: &Connection, site_id: &SiteId) -> Result<bool, JournalError> {
    c.query_row(
        "SELECT EXISTS(SELECT 1 FROM app_releases WHERE site_id=?1 AND state='done')",
        [site_id.as_str()],
        |row| row.get(0),
    )
    .map_err(storage::unavailable)
}

pub(crate) fn load_release(
    c: &Connection,
    operation_id: &Id,
) -> Result<Option<AppRelease>, JournalError> {
    let row = c
        .query_row(
            "SELECT operation_id, site_id, release_id, runtime, artifact_sha256, manifest_sha256, \
             file_count, total_bytes, migration_entrypoint, capture_operation_id, health_path, state \
             FROM app_releases WHERE operation_id=?1",
            [operation_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                ))
            },
        )
        .optional()
        .map_err(storage::unavailable)?;
    let Some((
        op_id,
        site_id,
        release_id,
        runtime,
        artifact_sha256,
        manifest_sha256,
        file_count,
        total_bytes,
        migration_entrypoint,
        capture_operation_id,
        health_path,
        state,
    )) = row
    else {
        return Ok(None);
    };
    let mut stmt = c
        .prepare(
            "SELECT position, state FROM app_release_steps WHERE operation_id=?1 ORDER BY position",
        )
        .map_err(storage::unavailable)?;
    let steps = stmt
        .query_map([operation_id.as_str()], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(storage::unavailable)?
        .map(|row| {
            let (position, state) = row.map_err(storage::unavailable)?;
            Ok(AppReleaseStepRecord {
                step: AppReleaseStep::from_position(position)?,
                state: step_state(&state)?,
            })
        })
        .collect::<Result<Vec<_>, JournalError>>()?;
    Ok(Some(AppRelease {
        operation_id: Id::try_from(op_id).map_err(|_| JournalError::Unavailable)?,
        site_id: SiteId::try_from(site_id).map_err(|_| JournalError::Unavailable)?,
        release_id,
        runtime: runtime_from_str(&runtime)?,
        artifact_sha256: Sha256Digest::try_from(artifact_sha256)
            .map_err(|_| JournalError::Unavailable)?,
        manifest_sha256: Sha256Digest::try_from(manifest_sha256)
            .map_err(|_| JournalError::Unavailable)?,
        file_count: u64::try_from(file_count).map_err(|_| JournalError::Unavailable)?,
        total_bytes: u64::try_from(total_bytes).map_err(|_| JournalError::Unavailable)?,
        migration_entrypoint,
        capture_operation_id: capture_operation_id
            .map(|id| Id::try_from(id).map_err(|_| JournalError::Unavailable))
            .transpose()?,
        health_path,
        steps,
        state: AppReleaseState::from_name(&state)?,
    }))
}

struct StoredReleaseRow {
    operation_id: String,
    site_id: String,
    release_id: String,
    runtime: String,
    artifact_sha256: String,
    manifest_sha256: String,
    file_count: i64,
    total_bytes: i64,
    migration_entrypoint: Option<String>,
    capture_operation_id: Option<String>,
    health_path: String,
    idempotency_key: String,
    grant_id: String,
    nonce: String,
    plan_digest: String,
    grant_digest: String,
    expires_at: i64,
}

fn stored_release(
    c: &Connection,
    intent: &AppReleaseIntent,
) -> Result<Option<(bool, AppRelease)>, JournalError> {
    let key_row = c
        .query_row(
            "SELECT operation_id, site_id, release_id, runtime, artifact_sha256, manifest_sha256, \
             file_count, total_bytes, migration_entrypoint, capture_operation_id, health_path, \
             idempotency_key, grant_id, nonce, plan_digest, grant_digest, expires_at \
             FROM app_releases WHERE operation_id=?1 OR idempotency_key=?2 LIMIT 1",
            params![
                intent.operation_id.as_str(),
                intent.idempotency_key.as_str()
            ],
            |row| {
                Ok(StoredReleaseRow {
                    operation_id: row.get(0)?,
                    site_id: row.get(1)?,
                    release_id: row.get(2)?,
                    runtime: row.get(3)?,
                    artifact_sha256: row.get(4)?,
                    manifest_sha256: row.get(5)?,
                    file_count: row.get(6)?,
                    total_bytes: row.get(7)?,
                    migration_entrypoint: row.get(8)?,
                    capture_operation_id: row.get(9)?,
                    health_path: row.get(10)?,
                    idempotency_key: row.get(11)?,
                    grant_id: row.get(12)?,
                    nonce: row.get(13)?,
                    plan_digest: row.get(14)?,
                    grant_digest: row.get(15)?,
                    expires_at: row.get(16)?,
                })
            },
        )
        .optional()
        .map_err(storage::unavailable)?;
    let Some(row) = key_row else {
        return Ok(None);
    };
    let op_id = Id::try_from(row.operation_id.clone()).map_err(|_| JournalError::Unavailable)?;
    let release = load_release(c, &op_id)?.ok_or(JournalError::Unavailable)?;
    let exact = row.operation_id == intent.operation_id.as_str()
        && row.site_id == intent.site_id.as_str()
        && row.release_id == intent.release_id
        && row.runtime == intent.runtime.as_str()
        && row.artifact_sha256 == intent.artifact_sha256.as_str()
        && row.manifest_sha256 == intent.manifest_sha256.as_str()
        && row.file_count == intent.file_count as i64
        && row.total_bytes == intent.total_bytes as i64
        && row.migration_entrypoint == intent.migration_entrypoint
        && row.capture_operation_id.as_deref()
            == intent.capture_operation_id.as_ref().map(Id::as_str)
        && row.health_path == intent.health_path
        && row.idempotency_key == intent.idempotency_key.as_str()
        && row.grant_id == intent.grant_id.as_str()
        && row.nonce == intent.nonce.as_str()
        && row.plan_digest == intent.plan_digest.as_str()
        && row.grant_digest == intent.grant_digest.as_str()
        && row.expires_at == intent.expires_at.get() as i64;
    Ok(Some((exact, release)))
}

fn release_basis_holds(
    c: &Connection,
    intent: &AppReleaseIntent,
    now: Timestamp,
) -> Result<bool, JournalError> {
    let site = intent.site_id.as_str();
    let app_runtime: Option<String> = c
        .query_row(
            "SELECT a.runtime FROM apps a JOIN provisions p ON p.operation_id=a.operation_id \
             WHERE p.site_id=?1 AND p.state='succeeded'",
            [site],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage::unavailable)?;
    if app_runtime.as_deref() != Some(intent.runtime.as_str()) {
        return Ok(false);
    }
    let blocked: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM app_releases WHERE site_id=?1 AND (state='intent' OR release_id=?2)) \
             OR EXISTS(SELECT 1 FROM app_lifecycles WHERE site_id=?1 AND state='intent') \
             OR EXISTS(SELECT 1 FROM captures WHERE site_id=?1 AND state='running') \
             OR EXISTS(SELECT 1 FROM ejections e JOIN operations o ON o.operation_id=e.operation_id \
                WHERE e.site_id=?1 AND o.state IN ('succeeded','intent','needs_attention','compensating'))",
            params![site, intent.release_id],
            |row| row.get(0),
        )
        .map_err(storage::unavailable)?;
    if blocked {
        return Ok(false);
    }
    if let Some(capture_id) = &intent.capture_operation_id {
        let capture: Option<(String, String, Option<i64>)> = c
            .query_row(
                "SELECT site_id, state, finished_at FROM captures WHERE operation_id=?1",
                [capture_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(storage::unavailable)?;
        let Some((cap_site, cap_state, Some(finished))) = capture else {
            return Ok(false);
        };
        let now_i = now.get() as i64;
        if cap_site != site
            || cap_state != "succeeded"
            || finished > now_i
            || now_i - finished > APP_MIGRATION_CAPTURE_MAX_AGE_SECONDS as i64
        {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn load_lifecycle(
    c: &Connection,
    operation_id: &Id,
) -> Result<Option<AppLifecycle>, JournalError> {
    let row = c
        .query_row(
            "SELECT operation_id, site_id, action, state FROM app_lifecycles WHERE operation_id=?1",
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
    let Some((op_id, site_id, action, state)) = row else {
        return Ok(None);
    };
    Ok(Some(AppLifecycle {
        operation_id: Id::try_from(op_id).map_err(|_| JournalError::Unavailable)?,
        site_id: SiteId::try_from(site_id).map_err(|_| JournalError::Unavailable)?,
        action: action_from_str(&action)?,
        state: step_state(&state)?,
    }))
}

struct StoredLifecycleRow {
    operation_id: String,
    site_id: String,
    action: String,
    idempotency_key: String,
    grant_id: String,
    nonce: String,
    plan_digest: String,
    grant_digest: String,
    expires_at: i64,
    state: String,
}

fn stored_lifecycle(
    c: &Connection,
    intent: &AppLifecycleIntent,
) -> Result<Option<(bool, AppLifecycle)>, JournalError> {
    let row = c
        .query_row(
            "SELECT operation_id, site_id, action, idempotency_key, grant_id, nonce, \
             plan_digest, grant_digest, expires_at, state \
             FROM app_lifecycles WHERE operation_id=?1 OR idempotency_key=?2 LIMIT 1",
            params![
                intent.operation_id.as_str(),
                intent.idempotency_key.as_str()
            ],
            |row| {
                Ok(StoredLifecycleRow {
                    operation_id: row.get(0)?,
                    site_id: row.get(1)?,
                    action: row.get(2)?,
                    idempotency_key: row.get(3)?,
                    grant_id: row.get(4)?,
                    nonce: row.get(5)?,
                    plan_digest: row.get(6)?,
                    grant_digest: row.get(7)?,
                    expires_at: row.get(8)?,
                    state: row.get(9)?,
                })
            },
        )
        .optional()
        .map_err(storage::unavailable)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let lifecycle = AppLifecycle {
        operation_id: Id::try_from(row.operation_id.clone())
            .map_err(|_| JournalError::Unavailable)?,
        site_id: SiteId::try_from(row.site_id.clone()).map_err(|_| JournalError::Unavailable)?,
        action: action_from_str(&row.action)?,
        state: step_state(&row.state)?,
    };
    let exact = row.operation_id == intent.operation_id.as_str()
        && row.site_id == intent.site_id.as_str()
        && row.action == intent.action.as_str()
        && row.idempotency_key == intent.idempotency_key.as_str()
        && row.grant_id == intent.grant_id.as_str()
        && row.nonce == intent.nonce.as_str()
        && row.plan_digest == intent.plan_digest.as_str()
        && row.grant_digest == intent.grant_digest.as_str()
        && row.expires_at == intent.expires_at.get() as i64;
    Ok(Some((exact, lifecycle)))
}

fn lifecycle_basis_holds(c: &Connection, site_id: &SiteId) -> Result<bool, JournalError> {
    let site = site_id.as_str();
    let eligible: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM apps a JOIN provisions p ON p.operation_id=a.operation_id \
                WHERE p.site_id=?1 AND p.state='succeeded') \
             AND NOT EXISTS(SELECT 1 FROM app_releases WHERE site_id=?1 AND state='intent') \
             AND NOT EXISTS(SELECT 1 FROM app_lifecycles WHERE site_id=?1 AND state='intent') \
             AND NOT EXISTS(SELECT 1 FROM ejections e JOIN operations o ON o.operation_id=e.operation_id \
                WHERE e.site_id=?1 AND o.state IN ('succeeded','intent','needs_attention','compensating'))",
            [site],
            |row| row.get(0),
        )
        .map_err(storage::unavailable)?;
    Ok(eligible)
}

/// Validates every `apps`, `app_releases`, `app_release_steps`, and
/// `app_lifecycles` invariant on journal open.
pub(crate) fn validate(c: &Connection) -> Result<(), JournalError> {
    let invalid_apps: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM apps a LEFT JOIN provisions p USING(operation_id) \
                WHERE p.operation_id IS NULL \
                OR EXISTS(SELECT 1 FROM imports i WHERE i.operation_id=a.operation_id) \
                OR EXISTS(SELECT 1 FROM clones l WHERE l.operation_id=a.operation_id)) \
             OR EXISTS(SELECT a.port FROM apps a JOIN provisions p ON p.operation_id=a.operation_id \
                WHERE p.state IN ('running','succeeded','adopted') \
                GROUP BY a.port HAVING count(*)>1)",
            [],
            |row| row.get(0),
        )
        .map_err(storage::unavailable)?;
    if invalid_apps {
        return Err(JournalError::Unavailable);
    }
    let mut stmt = c
        .prepare("SELECT operation_id FROM apps")
        .map_err(storage::unavailable)?;
    let app_ops = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(storage::unavailable)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage::unavailable)?;
    for op in app_ops {
        let id = Id::try_from(op).map_err(|_| JournalError::Unavailable)?;
        if facts(c, &id)?.is_none() {
            return Err(JournalError::Unavailable);
        }
    }

    let invalid_rel: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM app_releases r \
                LEFT JOIN provisions p ON p.site_id=r.site_id \
                LEFT JOIN apps a ON a.operation_id=p.operation_id \
                LEFT JOIN captures k ON k.operation_id=r.capture_operation_id \
                WHERE a.operation_id IS NULL OR a.runtime<>r.runtime \
                OR (r.migration_entrypoint IS NOT NULL AND r.capture_operation_id IS NULL) \
                OR (r.capture_operation_id IS NOT NULL AND k.site_id IS NOT r.site_id)) \
             OR EXISTS(SELECT 1 FROM app_lifecycles l \
                LEFT JOIN provisions p ON p.site_id=l.site_id \
                LEFT JOIN apps a ON a.operation_id=p.operation_id \
                WHERE a.operation_id IS NULL)",
            [],
            |row| row.get(0),
        )
        .map_err(storage::unavailable)?;
    if invalid_rel {
        return Err(JournalError::Unavailable);
    }
    let mut rel_stmt = c
        .prepare("SELECT operation_id FROM app_releases")
        .map_err(storage::unavailable)?;
    let rel_ops = rel_stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(storage::unavailable)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage::unavailable)?;
    for op in rel_ops {
        let id = Id::try_from(op).map_err(|_| JournalError::Unavailable)?;
        let rel = load_release(c, &id)?.ok_or(JournalError::Unavailable)?;
        if !valid_release_id(&rel.release_id)
            || !valid_health_path(&rel.health_path)
            || rel
                .migration_entrypoint
                .as_deref()
                .is_some_and(|e| !valid_entrypoint(e))
        {
            return Err(JournalError::Unavailable);
        }
        if rel.state == AppReleaseState::Done && !step_is_done(&rel.steps, AppReleaseStep::Health) {
            return Err(JournalError::Unavailable);
        }
        if rel.state == AppReleaseState::RolledBack
            && !step_is_done(&rel.steps, AppReleaseStep::Rollback)
        {
            return Err(JournalError::Unavailable);
        }
    }
    Ok(())
}
