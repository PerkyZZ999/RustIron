//! Modern app hosting journal tables (schema v43, W597, D-099).
//!
//! An app site is a provision with an `apps` row and matching `proxy_routes`
//! rows committed in the same transaction. Releases (`app_releases` +
//! `app_release_steps`) and unit lifecycle transitions (`app_lifecycles`)
//! record durable intent before host effects, preserve exact idempotent
//! retries, enforce one open release/lifecycle per site, and validate every
//! invariant on open. Nothing here touches a host.

use std::collections::BTreeSet;

use rusqlite::{Connection, OptionalExtension, params};
use rustiron_contracts::{
    Id, Timestamp,
    approval::{
        AppDatabase, AppLifecycleAction, AppRuntime, AppTopology, IngressEngine,
        MAX_APP_MEMORY_MIB, MAX_APP_QUOTA_MIB, MAX_APP_RELEASE_BYTES, MAX_APP_RELEASE_FILES,
        MAX_APP_TASKS_MAX, MAX_PROXY_ROUTES, MIN_APP_MEMORY_MIB, MIN_APP_QUOTA_MIB,
        MIN_APP_TASKS_MAX, Sha256Digest, SiteId, app_routable_port, routable_port,
        valid_entrypoint, valid_env_keys, valid_frontend_dir, valid_health_path, valid_prefix,
        valid_release_id,
    },
};

use crate::{
    FixtureJournal, JournalError, ProvisionIntent, ProvisionResult, ProxyFacts, StepState,
    provision::Origin, storage,
};

/// Maximum age of a capture bound to a migrating `app_deploy` (24 hours).
pub const APP_MIGRATION_CAPTURE_MAX_AGE_SECONDS: u64 = 24 * 3600;

/// Active blue/green runtime slot for a D-102 app (`a` or `b`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppSlot {
    /// Primary slot (`port` / `frontend_port`).
    A,
    /// Standby slot (`standby_port` / `frontend_standby_port`).
    B,
}

impl AppSlot {
    /// Closed wire/column identifier (`"a"` or `"b"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::A => "a",
            Self::B => "b",
        }
    }

    /// The opposite slot for blue/green cutover.
    pub const fn opposite(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }

    fn from_name(name: &str) -> Result<Self, JournalError> {
        match name {
            "a" => Ok(Self::A),
            "b" => Ok(Self::B),
            _ => Err(JournalError::Unavailable),
        }
    }
}

/// D-102 full-stack metadata stored alongside an `apps` row (journal v45).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppFullstackSpec {
    /// Edge ingress engine (`ols` or `caddy`).
    pub ingress: IngressEngine,
    /// Deployment topology (`static_spa`, `backend_api`, `fullstack_split`, `fullstack_dual_ssr`).
    pub topology: AppTopology,
    /// Selected per-app database engine (`none`, `sqlite`, `mariadb`, `postgresql_18`).
    pub database: AppDatabase,
    /// Whether zero-downtime blue/green slot cutover is enabled.
    pub blue_green: bool,
    /// Currently active blue/green slot (`a` by default).
    pub active_slot: AppSlot,
    /// Standby loopback port for blue/green cutover.
    pub standby_port: Option<u16>,
    /// Whether Caddy enables SPA `try_files {path} /index.html`.
    pub spa_fallback: bool,
    /// Relative static frontend directory (`static_spa` / `fullstack_split`).
    pub frontend_dir: Option<String>,
    /// SSR frontend runtime (`fullstack_dual_ssr`).
    pub frontend_runtime: Option<AppRuntime>,
    /// SSR frontend entrypoint (`fullstack_dual_ssr`).
    pub frontend_entrypoint: Option<String>,
    /// SSR frontend loopback port (`fullstack_dual_ssr`).
    pub frontend_port: Option<u16>,
    /// SSR frontend standby loopback port (`fullstack_dual_ssr` + `blue_green`).
    pub frontend_standby_port: Option<u16>,
    /// Sorted unique unbuffered SSE prefixes (Caddy only).
    pub sse_prefixes: Vec<String>,
    /// Sorted unique API prefixes stripped before upstream forwarding (Caddy only).
    pub strip_api_prefixes: Vec<String>,
}

impl AppFullstackSpec {
    /// Returns every non-zero loopback port reserved by `(facts, self)`.
    pub fn all_ports(&self, facts: &AppFacts) -> Vec<u16> {
        let mut ports = Vec::new();
        if facts.port != 0 {
            ports.push(facts.port);
        }
        if let Some(p) = self.standby_port {
            ports.push(p);
        }
        if let Some(p) = self.frontend_port {
            ports.push(p);
        }
        if let Some(p) = self.frontend_standby_port {
            ports.push(p);
        }
        ports
    }

    /// Validates `(facts, self)` against the closed D-102 full-stack contract.
    pub fn is_valid_with(&self, facts: &AppFacts) -> bool {
        let common_ok = facts
            .worker_entrypoint
            .as_deref()
            .is_none_or(valid_entrypoint)
            && valid_health_path(&facts.health_path)
            && valid_env_keys(&facts.env_keys)
            && (MIN_APP_MEMORY_MIB..=MAX_APP_MEMORY_MIB).contains(&facts.memory_max_mib)
            && (MIN_APP_TASKS_MAX..=MAX_APP_TASKS_MAX).contains(&facts.tasks_max)
            && (MIN_APP_QUOTA_MIB..=MAX_APP_QUOTA_MIB).contains(&facts.quota_mib);
        if !common_ok {
            return false;
        }
        let prefixes_ok = |list: &[String], allow_root: bool| -> bool {
            list.len() <= MAX_PROXY_ROUTES
                && list
                    .iter()
                    .all(|p| valid_prefix(p) && (allow_root || p != "/"))
                && list.windows(2).all(|w| w[0] < w[1])
        };
        if !self.sse_prefixes.is_empty()
            && (self.ingress != IngressEngine::Caddy
                || self.topology == AppTopology::StaticSpa
                || !prefixes_ok(&self.sse_prefixes, true))
        {
            return false;
        }
        if !self.strip_api_prefixes.is_empty() {
            let route_set: BTreeSet<&str> = facts
                .routes
                .routes
                .iter()
                .map(|r| r.prefix.as_str())
                .collect();
            if self.ingress != IngressEngine::Caddy
                || !prefixes_ok(&self.strip_api_prefixes, false)
                || !self
                    .strip_api_prefixes
                    .iter()
                    .all(|p| route_set.contains(p.as_str()))
            {
                return false;
            }
        }
        match self.topology {
            AppTopology::StaticSpa => {
                self.ingress == IngressEngine::Caddy
                    && facts.runtime == AppRuntime::StaticV1
                    && facts.port == 0
                    && !self.blue_green
                    && self.active_slot == AppSlot::A
                    && self.standby_port.is_none()
                    && facts.routes.routes.is_empty()
                    && facts.routes.websockets.is_empty()
                    && facts.entrypoint.is_empty()
                    && facts.worker_entrypoint.is_none()
                    && self.frontend_dir.as_deref().is_some_and(valid_frontend_dir)
                    && self.frontend_runtime.is_none()
                    && self.frontend_entrypoint.is_none()
                    && self.frontend_port.is_none()
                    && self.frontend_standby_port.is_none()
                    && self.database == AppDatabase::None
                    && facts.health_path == "/"
            }
            AppTopology::BackendApi => {
                let single_ports_ok = if self.blue_green {
                    self.standby_port
                        .is_some_and(|sp| app_routable_port(sp) && sp != facts.port)
                } else {
                    self.standby_port.is_none() && self.active_slot == AppSlot::A
                };
                facts.runtime.is_process_runtime()
                    && app_routable_port(facts.port)
                    && facts.is_valid()
                    && !self.spa_fallback
                    && self.frontend_dir.is_none()
                    && self.frontend_runtime.is_none()
                    && self.frontend_entrypoint.is_none()
                    && self.frontend_port.is_none()
                    && self.frontend_standby_port.is_none()
                    && single_ports_ok
            }
            AppTopology::FullstackSplit => {
                let single_ports_ok = if self.blue_green {
                    self.standby_port
                        .is_some_and(|sp| app_routable_port(sp) && sp != facts.port)
                } else {
                    self.standby_port.is_none() && self.active_slot == AppSlot::A
                };
                self.ingress == IngressEngine::Caddy
                    && facts.runtime.is_process_runtime()
                    && app_routable_port(facts.port)
                    && valid_entrypoint(&facts.entrypoint)
                    && self.frontend_dir.as_deref().is_some_and(valid_frontend_dir)
                    && facts.routes.is_valid_app_split()
                    && facts
                        .routes
                        .routes
                        .iter()
                        .chain(&facts.routes.websockets)
                        .all(|r| r.port == facts.port)
                    && self.frontend_runtime.is_none()
                    && self.frontend_entrypoint.is_none()
                    && self.frontend_port.is_none()
                    && self.frontend_standby_port.is_none()
                    && single_ports_ok
            }
            AppTopology::FullstackDualSsr => {
                let (Some(fr), Some(fe), Some(fp)) = (
                    self.frontend_runtime,
                    self.frontend_entrypoint.as_deref(),
                    self.frontend_port,
                ) else {
                    return false;
                };
                if self.ingress != IngressEngine::Caddy
                    || !facts.runtime.is_process_runtime()
                    || !fr.is_process_runtime()
                    || !app_routable_port(facts.port)
                    || !app_routable_port(fp)
                    || !valid_entrypoint(&facts.entrypoint)
                    || !valid_entrypoint(fe)
                    || self.frontend_dir.is_some()
                    || self.spa_fallback
                    || !facts.routes.is_valid()
                    || !facts
                        .routes
                        .routes
                        .iter()
                        .chain(&facts.routes.websockets)
                        .all(|r| r.port == facts.port || r.port == fp)
                    || !facts
                        .routes
                        .routes
                        .iter()
                        .any(|r| r.prefix == "/" && r.port == fp)
                    || !facts
                        .routes
                        .routes
                        .iter()
                        .any(|r| r.prefix != "/" && r.port == facts.port)
                {
                    return false;
                }
                let mut ports = BTreeSet::from([facts.port, fp]);
                if self.blue_green {
                    let (Some(sp), Some(fsp)) = (self.standby_port, self.frontend_standby_port)
                    else {
                        return false;
                    };
                    if !app_routable_port(sp) || !app_routable_port(fsp) {
                        return false;
                    }
                    ports.insert(sp);
                    ports.insert(fsp);
                    ports.len() == 4
                } else {
                    self.standby_port.is_none()
                        && self.frontend_standby_port.is_none()
                        && self.active_slot == AppSlot::A
                        && ports.len() == 2
                }
            }
        }
    }
}

/// Host-level Caddy ingress mode (D-102 owner choice A1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaddyIngressMode {
    /// Dedicated app host where Caddy directly owns TCP 80/443 and UDP 443.
    CaddyOnly,
    /// Multi-IP mixed host where Caddy binds its own enrolled IP.
    CaddyMultiIp,
    /// Single-IP mixed host where Caddy owns `:80/:443` and proxies WordPress to OLS on `127.0.0.1:8080`.
    CaddyEdgeOverOls,
}

impl CaddyIngressMode {
    /// Closed wire/column identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CaddyOnly => "caddy_only",
            Self::CaddyMultiIp => "caddy_multi_ip",
            Self::CaddyEdgeOverOls => "caddy_edge_over_ols",
        }
    }

    fn from_name(name: &str) -> Result<Self, JournalError> {
        match name {
            "caddy_only" => Ok(Self::CaddyOnly),
            "caddy_multi_ip" => Ok(Self::CaddyMultiIp),
            "caddy_edge_over_ols" => Ok(Self::CaddyEdgeOverOls),
            _ => Err(JournalError::Unavailable),
        }
    }
}

/// Lifecycle state of a journaled Caddy generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaddyGenerationState {
    /// Validated candidate written before reload.
    Staged,
    /// Live active Caddy generation.
    Active,
    /// Superseded or reverted after failed reload.
    RolledBack,
}

impl CaddyGenerationState {
    /// Closed wire/column identifier (`"staged"`, `"active"`, or `"rolled_back"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::Active => "active",
            Self::RolledBack => "rolled_back",
        }
    }

    fn from_name(name: &str) -> Result<Self, JournalError> {
        match name {
            "staged" => Ok(Self::Staged),
            "active" => Ok(Self::Active),
            "rolled_back" => Ok(Self::RolledBack),
            _ => Err(JournalError::Unavailable),
        }
    }
}

/// One journaled Caddy configuration generation (journal v45, D-102).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaddyGeneration {
    /// Unique generation identifier.
    pub generation_id: Id,
    /// Associated operation ID (`config_activate` or blue/green `app_deploy`).
    pub operation_id: Id,
    /// Enrolled host Caddy ingress mode.
    pub ingress_mode: CaddyIngressMode,
    /// SHA-256 of the rendered canonical `Caddyfile` bundle.
    pub config_sha256: Sha256Digest,
    /// Number of rendered sites in this generation.
    pub site_count: u64,
    /// Creation timestamp (Unix seconds).
    pub created_at: Timestamp,
    /// Current state (`staged`, `active`, or `rolled_back`).
    pub state: CaddyGenerationState,
}

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
        "static_v1" => Ok(AppRuntime::StaticV1),
        _ => Err(JournalError::Unavailable),
    }
}

fn ingress_from_str(text: &str) -> Result<IngressEngine, JournalError> {
    match text {
        "ols" => Ok(IngressEngine::Ols),
        "caddy" => Ok(IngressEngine::Caddy),
        _ => Err(JournalError::Unavailable),
    }
}

fn topology_from_str(text: &str) -> Result<AppTopology, JournalError> {
    match text {
        "static_spa" => Ok(AppTopology::StaticSpa),
        "backend_api" => Ok(AppTopology::BackendApi),
        "fullstack_split" => Ok(AppTopology::FullstackSplit),
        "fullstack_dual_ssr" => Ok(AppTopology::FullstackDualSsr),
        _ => Err(JournalError::Unavailable),
    }
}

fn database_from_str(text: &str) -> Result<AppDatabase, JournalError> {
    match text {
        "none" => Ok(AppDatabase::None),
        "sqlite" => Ok(AppDatabase::Sqlite),
        "mariadb" => Ok(AppDatabase::Mariadb),
        "postgresql_18" => Ok(AppDatabase::Postgresql18),
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
        self.admit_provision(intent, Origin::App(facts, None), now)
    }

    /// W656 (D-102): records a schema v2 full-stack app provision (`static_spa`,
    /// `backend_api`, `fullstack_split`, or `fullstack_dual_ssr`) with Caddy/OLS
    /// ingress, optional blue/green slots, and selectable DB engine in one transaction.
    pub fn record_fullstack_app_provision(
        &mut self,
        intent: &ProvisionIntent,
        facts: &AppFacts,
        spec: &AppFullstackSpec,
        now: Timestamp,
    ) -> Result<ProvisionResult, JournalError> {
        if !spec.is_valid_with(facts) {
            return Err(JournalError::Conflict);
        }
        self.admit_provision(intent, Origin::App(facts, Some(spec)), now)
    }

    /// Reads the D-102 full-stack spec of a provision operation, if present.
    pub fn app_fullstack_spec(
        &self,
        operation_id: &Id,
    ) -> Result<Option<AppFullstackSpec>, JournalError> {
        fullstack_spec(&self.connection, operation_id)
    }

    /// Reads the D-102 full-stack spec for a site ID, if present.
    pub fn app_fullstack_spec_by_site(
        &self,
        site_id: &SiteId,
    ) -> Result<Option<AppFullstackSpec>, JournalError> {
        let op: Option<String> = self
            .connection
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
        fullstack_spec(&self.connection, &id)
    }

    /// Switches the recorded active blue/green slot (`a` <-> `b`) of an app.
    pub fn set_app_active_slot(
        &mut self,
        operation_id: &Id,
        slot: AppSlot,
    ) -> Result<AppFullstackSpec, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let Some(current) = fullstack_spec(&transaction, operation_id)? else {
            return Err(JournalError::Conflict);
        };
        if !current.blue_green {
            return Err(JournalError::Conflict);
        }
        transaction
            .execute(
                "UPDATE app_fullstack_specs SET active_slot=?1 WHERE operation_id=?2",
                params![slot.as_str(), operation_id.as_str()],
            )
            .map_err(storage::unavailable)?;
        let updated =
            fullstack_spec(&transaction, operation_id)?.ok_or(JournalError::Unavailable)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(updated)
    }

    /// Stages a validated Caddy configuration generation (journal v45, D-102).
    pub fn record_caddy_generation(
        &mut self,
        generation: &CaddyGeneration,
    ) -> Result<(), JournalError> {
        if generation.state != CaddyGenerationState::Staged {
            return Err(JournalError::Conflict);
        }
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let exists: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM caddy_generations WHERE generation_id=?1)",
                [generation.generation_id.as_str()],
                |row| row.get(0),
            )
            .map_err(storage::unavailable)?;
        if exists {
            return Err(JournalError::Conflict);
        }
        transaction
            .execute(
                "INSERT INTO caddy_generations VALUES(?1,?2,?3,?4,?5,?6,'staged')",
                params![
                    generation.generation_id.as_str(),
                    generation.operation_id.as_str(),
                    generation.ingress_mode.as_str(),
                    generation.config_sha256.as_str(),
                    generation.site_count as i64,
                    generation.created_at.get() as i64,
                ],
            )
            .map_err(storage::unavailable)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(())
    }

    /// Atomically promotes a staged Caddy generation to `active` (retiring any prior active row).
    pub fn activate_caddy_generation(
        &mut self,
        generation_id: &Id,
    ) -> Result<CaddyGeneration, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let current =
            load_caddy_generation(&transaction, generation_id)?.ok_or(JournalError::Conflict)?;
        if current.state != CaddyGenerationState::Staged {
            return Err(JournalError::Conflict);
        }
        transaction
            .execute(
                "UPDATE caddy_generations SET state='rolled_back' WHERE state='active'",
                [],
            )
            .map_err(storage::unavailable)?;
        transaction
            .execute(
                "UPDATE caddy_generations SET state='active' WHERE generation_id=?1",
                [generation_id.as_str()],
            )
            .map_err(storage::unavailable)?;
        let updated =
            load_caddy_generation(&transaction, generation_id)?.ok_or(JournalError::Unavailable)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(updated)
    }

    /// W659 (D-102): records or reactivates a validated Caddy generation as the
    /// single `active` generation, supporting repeated blue/green `A <-> B`
    /// transitions that reuse an identical content-addressed `generation_id`.
    /// Refuses with `Conflict` if an existing `generation_id` has a different
    /// `config_sha256`.
    pub fn record_active_caddy_generation(
        &mut self,
        generation: &CaddyGeneration,
    ) -> Result<CaddyGeneration, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        transaction
            .execute(
                "UPDATE caddy_generations SET state='rolled_back' WHERE state='active'",
                [],
            )
            .map_err(storage::unavailable)?;
        if let Some(existing) = load_caddy_generation(&transaction, &generation.generation_id)? {
            if existing.config_sha256 != generation.config_sha256 {
                return Err(JournalError::Conflict);
            }
            transaction
                .execute(
                    "UPDATE caddy_generations \
                     SET operation_id=?1, ingress_mode=?2, site_count=?3, created_at=?4, state='active' \
                     WHERE generation_id=?5",
                    params![
                        generation.operation_id.as_str(),
                        generation.ingress_mode.as_str(),
                        generation.site_count as i64,
                        generation.created_at.get() as i64,
                        generation.generation_id.as_str(),
                    ],
                )
                .map_err(storage::unavailable)?;
        } else {
            transaction
                .execute(
                    "INSERT INTO caddy_generations VALUES(?1,?2,?3,?4,?5,?6,'active')",
                    params![
                        generation.generation_id.as_str(),
                        generation.operation_id.as_str(),
                        generation.ingress_mode.as_str(),
                        generation.config_sha256.as_str(),
                        generation.site_count as i64,
                        generation.created_at.get() as i64,
                    ],
                )
                .map_err(storage::unavailable)?;
        }
        let updated = load_caddy_generation(&transaction, &generation.generation_id)?
            .ok_or(JournalError::Unavailable)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(updated)
    }

    /// Marks a staged or active Caddy generation `rolled_back` (and optionally restores `restore_id` to `active`).
    pub fn rollback_caddy_generation(
        &mut self,
        generation_id: &Id,
        restore_id: Option<&Id>,
    ) -> Result<CaddyGeneration, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let current =
            load_caddy_generation(&transaction, generation_id)?.ok_or(JournalError::Conflict)?;
        if current.state == CaddyGenerationState::RolledBack {
            return Err(JournalError::Conflict);
        }
        transaction
            .execute(
                "UPDATE caddy_generations SET state='rolled_back' WHERE generation_id=?1",
                [generation_id.as_str()],
            )
            .map_err(storage::unavailable)?;
        if let Some(prev) = restore_id {
            let prev_row =
                load_caddy_generation(&transaction, prev)?.ok_or(JournalError::Conflict)?;
            if prev_row.generation_id == current.generation_id {
                return Err(JournalError::Conflict);
            }
            transaction
                .execute(
                    "UPDATE caddy_generations SET state='rolled_back' WHERE state='active'",
                    [],
                )
                .map_err(storage::unavailable)?;
            transaction
                .execute(
                    "UPDATE caddy_generations SET state='active' WHERE generation_id=?1",
                    [prev.as_str()],
                )
                .map_err(storage::unavailable)?;
        }
        let updated =
            load_caddy_generation(&transaction, generation_id)?.ok_or(JournalError::Unavailable)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(updated)
    }

    /// Returns the currently active Caddy generation, if any.
    pub fn active_caddy_generation(&self) -> Result<Option<CaddyGeneration>, JournalError> {
        let id: Option<String> = self
            .connection
            .query_row(
                "SELECT generation_id FROM caddy_generations WHERE state='active'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage::unavailable)?;
        let Some(id) = id else {
            return Ok(None);
        };
        let gen_id = Id::try_from(id).map_err(|_| JournalError::Unavailable)?;
        load_caddy_generation(&self.connection, &gen_id)
    }

    /// Lists all recorded Caddy generations ordered by creation time.
    pub fn caddy_generations(&self) -> Result<Vec<CaddyGeneration>, JournalError> {
        let mut stmt = self
            .connection
            .prepare(
                "SELECT generation_id FROM caddy_generations ORDER BY created_at, generation_id",
            )
            .map_err(storage::unavailable)?;
        let ids = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(storage::unavailable)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage::unavailable)?;
        let mut out = Vec::with_capacity(ids.len());
        for raw in ids {
            let id = Id::try_from(raw).map_err(|_| JournalError::Unavailable)?;
            if let Some(row) = load_caddy_generation(&self.connection, &id)? {
                out.push(row);
            }
        }
        Ok(out)
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

/// Whether any non-zero port in `ports` is already reserved by an active
/// (non-deleted, non-quarantined) app across primary, standby, and frontend slots.
pub(crate) fn ports_taken(c: &Connection, ports: &[u16]) -> Result<bool, JournalError> {
    for &port in ports {
        if port == 0 {
            continue;
        }
        let taken: bool = c
            .query_row(
                "SELECT EXISTS( \
                    SELECT 1 FROM apps a JOIN provisions p ON p.operation_id=a.operation_id \
                    WHERE p.state IN ('running','succeeded','adopted') AND a.port=?1 \
                 ) OR EXISTS( \
                    SELECT 1 FROM app_fullstack_specs s JOIN provisions p ON p.operation_id=s.operation_id \
                    WHERE p.state IN ('running','succeeded','adopted') \
                    AND (s.standby_port=?1 OR s.frontend_port=?1 OR s.frontend_standby_port=?1) \
                 )",
                [i64::from(port)],
                |row| row.get(0),
            )
            .map_err(storage::unavailable)?;
        if taken {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn insert(
    c: &Connection,
    operation_id: &Id,
    facts: &AppFacts,
    spec: Option<&AppFullstackSpec>,
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
    if let Some(fs) = spec {
        let sse = fs.sse_prefixes.join(",");
        let strip = fs.strip_api_prefixes.join(",");
        c.execute(
            "INSERT INTO app_fullstack_specs VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
            params![
                operation_id.as_str(),
                fs.ingress.as_str(),
                fs.topology.as_str(),
                fs.database.as_str(),
                i64::from(fs.blue_green),
                fs.active_slot.as_str(),
                fs.standby_port.map(i64::from),
                i64::from(fs.spa_fallback),
                fs.frontend_dir.as_deref(),
                fs.frontend_runtime.map(AppRuntime::as_str),
                fs.frontend_entrypoint.as_deref(),
                fs.frontend_port.map(i64::from),
                fs.frontend_standby_port.map(i64::from),
                sse,
                strip,
            ],
        )
        .map_err(storage::unavailable)?;
    }
    if !facts.routes.routes.is_empty() || !facts.routes.websockets.is_empty() {
        crate::proxy::insert(c, operation_id, &facts.routes)?;
    }
    Ok(())
}

pub(crate) fn fullstack_spec_by_site(
    c: &Connection,
    site_id: &SiteId,
) -> Result<Option<AppFullstackSpec>, JournalError> {
    let op_id: Option<String> = c
        .query_row(
            "SELECT a.operation_id FROM apps a JOIN provisions p ON p.operation_id=a.operation_id \
             WHERE p.site_id=?1 ORDER BY p.rowid DESC LIMIT 1",
            [site_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage::unavailable)?;
    let Some(op_id) = op_id else {
        return Ok(None);
    };
    let id = Id::try_from(op_id).map_err(storage::unavailable)?;
    fullstack_spec(c, &id)
}

pub(crate) fn fullstack_spec(
    c: &Connection,
    operation_id: &Id,
) -> Result<Option<AppFullstackSpec>, JournalError> {
    let row = c
        .query_row(
            "SELECT ingress, topology, database_engine, blue_green, active_slot, standby_port, \
             spa_fallback, frontend_dir, frontend_runtime, frontend_entrypoint, frontend_port, \
             frontend_standby_port, sse_prefixes, strip_api_prefixes \
             FROM app_fullstack_specs WHERE operation_id=?1",
            [operation_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<i64>>(10)?,
                    row.get::<_, Option<i64>>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, String>(13)?,
                ))
            },
        )
        .optional()
        .map_err(storage::unavailable)?;
    let Some((
        ingress,
        topology,
        database,
        blue_green,
        active_slot,
        standby_port,
        spa_fallback,
        frontend_dir,
        frontend_runtime,
        frontend_entrypoint,
        frontend_port,
        frontend_standby_port,
        sse_raw,
        strip_raw,
    )) = row
    else {
        return Ok(None);
    };
    let split_csv = |s: String| -> Vec<String> {
        if s.is_empty() {
            Vec::new()
        } else {
            s.split(',').map(str::to_owned).collect()
        }
    };
    let to_u16 = |opt: Option<i64>| -> Result<Option<u16>, JournalError> {
        opt.map(|n| u16::try_from(n).map_err(|_| JournalError::Unavailable))
            .transpose()
    };
    Ok(Some(AppFullstackSpec {
        ingress: ingress_from_str(&ingress)?,
        topology: topology_from_str(&topology)?,
        database: database_from_str(&database)?,
        blue_green: blue_green != 0,
        active_slot: AppSlot::from_name(&active_slot)?,
        standby_port: to_u16(standby_port)?,
        spa_fallback: spa_fallback != 0,
        frontend_dir,
        frontend_runtime: frontend_runtime
            .as_deref()
            .map(runtime_from_str)
            .transpose()?,
        frontend_entrypoint,
        frontend_port: to_u16(frontend_port)?,
        frontend_standby_port: to_u16(frontend_standby_port)?,
        sse_prefixes: split_csv(sse_raw),
        strip_api_prefixes: split_csv(strip_raw),
    }))
}

fn load_caddy_generation(
    c: &Connection,
    generation_id: &Id,
) -> Result<Option<CaddyGeneration>, JournalError> {
    let row = c
        .query_row(
            "SELECT generation_id, operation_id, ingress_mode, config_sha256, site_count, created_at, state \
             FROM caddy_generations WHERE generation_id=?1",
            [generation_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .optional()
        .map_err(storage::unavailable)?;
    let Some((gen_id, op_id, mode, sha, site_count, created_at, state)) = row else {
        return Ok(None);
    };
    Ok(Some(CaddyGeneration {
        generation_id: Id::try_from(gen_id).map_err(|_| JournalError::Unavailable)?,
        operation_id: Id::try_from(op_id).map_err(|_| JournalError::Unavailable)?,
        ingress_mode: CaddyIngressMode::from_name(&mode)?,
        config_sha256: Sha256Digest::try_from(sha).map_err(|_| JournalError::Unavailable)?,
        site_count: u64::try_from(site_count).map_err(|_| JournalError::Unavailable)?,
        created_at: Timestamp::try_from(
            u64::try_from(created_at).map_err(|_| JournalError::Unavailable)?,
        )
        .map_err(|_| JournalError::Unavailable)?,
        state: CaddyGenerationState::from_name(&state)?,
    }))
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
    let spec = fullstack_spec(c, operation_id)?;
    let routes = match crate::proxy::facts(c, operation_id)? {
        Some(r) => r,
        None if spec
            .as_ref()
            .is_some_and(|s| s.topology == AppTopology::StaticSpa) =>
        {
            ProxyFacts {
                routes: Vec::new(),
                websockets: Vec::new(),
            }
        }
        None => return Err(JournalError::Unavailable),
    };
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
    let valid = match spec.as_ref() {
        Some(fs) => fs.is_valid_with(&app),
        None => app.is_valid(),
    };
    if !valid {
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

/// Validates every `apps`, `app_fullstack_specs`, `caddy_generations`,
/// `app_releases`, `app_release_steps`, and `app_lifecycles` invariant on open.
pub(crate) fn validate(c: &Connection) -> Result<(), JournalError> {
    let invalid_apps: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM apps a LEFT JOIN provisions p USING(operation_id) \
                WHERE p.operation_id IS NULL \
                OR EXISTS(SELECT 1 FROM imports i WHERE i.operation_id=a.operation_id) \
                OR EXISTS(SELECT 1 FROM clones l WHERE l.operation_id=a.operation_id)) \
             OR EXISTS(SELECT a.port FROM apps a JOIN provisions p ON p.operation_id=a.operation_id \
                WHERE a.port>0 AND p.state IN ('running','succeeded','adopted') \
                GROUP BY a.port HAVING count(*)>1)",
            [],
            |row| row.get(0),
        )
        .map_err(storage::unavailable)?;
    if invalid_apps {
        return Err(JournalError::Unavailable);
    }
    let mut stmt = c
        .prepare("SELECT a.operation_id, p.state FROM apps a JOIN provisions p ON p.operation_id=a.operation_id")
        .map_err(storage::unavailable)?;
    let app_ops = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(storage::unavailable)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage::unavailable)?;
    let mut active_ports = BTreeSet::new();
    for (op, state) in app_ops {
        let id = Id::try_from(op).map_err(|_| JournalError::Unavailable)?;
        let Some(app_facts) = facts(c, &id)? else {
            return Err(JournalError::Unavailable);
        };
        let active = matches!(state.as_str(), "running" | "succeeded" | "adopted");
        if active {
            let ports = match fullstack_spec(c, &id)? {
                Some(spec) => spec.all_ports(&app_facts),
                None if app_facts.port > 0 => vec![app_facts.port],
                None => Vec::new(),
            };
            for port in ports {
                if !active_ports.insert(port) {
                    return Err(JournalError::Unavailable);
                }
            }
        }
    }
    let mut caddy_stmt = c
        .prepare("SELECT generation_id FROM caddy_generations")
        .map_err(storage::unavailable)?;
    let caddy_ids = caddy_stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(storage::unavailable)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage::unavailable)?;
    for raw in caddy_ids {
        let id = Id::try_from(raw).map_err(|_| JournalError::Unavailable)?;
        load_caddy_generation(c, &id)?.ok_or(JournalError::Unavailable)?;
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
