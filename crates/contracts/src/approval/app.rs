//! Closed P27 modern app hosting plan/grant contracts (W596, D-099).
//!
//! Three closed verbs cover Node.js (`node_22_v1`) and Bun (`bun_1_v1`) apps
//! managed as confined per-site systemd services behind CP08 OLS proxy sites:
//!
//! - `app_provision`: creates one app site, reserves its hostname, loopback
//!   port, routes, resource limits, entrypoint(s), and allowed env var key
//!   names (never secret values). Does not reload OLS or run package scripts.
//! - `app_deploy`: activates one prebuilt, signed release archive and manifest
//!   as the unprivileged site account with bounded loopback health probing and
//!   automatic rollback. Requires a recent capture ID when running a migration.
//! - `app_lifecycle`: explicit signed `start`, `stop`, or `restart` of an
//!   enrolled app's service(s).
//!
//! Decoding and binding checks confer no signature verification or authority.
//! See `docs/decisions/D-099-modern-app-hosting.md` and `docs/technical/MODERN-APPS.md`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{CanonicalObject, Id, Text, Timestamp};

use super::{
    ApprovalError, Hostname, MAX_PROXY_ROUTES, ProxyRoute, Sha256Digest, SiteId, routable_port,
    types::*, valid_prefix,
};

/// Maximum environment variable key names declared by one app plan.
pub const MAX_APP_ENV_KEYS: usize = 64;
/// Maximum byte length of one environment variable key name.
pub const MAX_APP_ENV_KEY_BYTES: usize = 64;
/// Maximum byte length of a relative entrypoint path inside a release bundle.
pub const MAX_APP_ENTRYPOINT_BYTES: usize = 128;
/// Maximum byte length of a passive relative file path inside `manifest.sha256`.
pub const MAX_APP_MANIFEST_PATH_BYTES: usize = 256;
/// Maximum byte length of a loopback HTTP health check path.
pub const MAX_APP_HEALTH_PATH_BYTES: usize = 128;
/// Minimum memory limit in MiB.
pub const MIN_APP_MEMORY_MIB: u64 = 64;
/// Maximum memory limit in MiB.
pub const MAX_APP_MEMORY_MIB: u64 = 8192;
/// Minimum `TasksMax` cgroup limit.
pub const MIN_APP_TASKS_MAX: u64 = 16;
/// Maximum `TasksMax` cgroup limit.
pub const MAX_APP_TASKS_MAX: u64 = 1024;
/// Minimum filesystem quota in MiB.
pub const MIN_APP_QUOTA_MIB: u64 = 128;
/// Maximum filesystem quota in MiB.
pub const MAX_APP_QUOTA_MIB: u64 = 65_536;
/// Maximum file entries in one prepared app release bundle.
pub const MAX_APP_RELEASE_FILES: u64 = 50_000;
/// Maximum total unpacked bytes in one prepared app release bundle (512 MiB).
pub const MAX_APP_RELEASE_BYTES: u64 = 512 * 1024 * 1024;
/// Maximum byte length of a release identifier.
pub const MAX_APP_RELEASE_ID_BYTES: usize = 64;

/// Environment keys reserved by the host/systemd runtime that an app plan
/// may never declare in `env_keys`.
const FORBIDDEN_ENV_KEYS: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    "TMPDIR",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "PORT",
    "HOST",
    "RUSTIRON_APP_DATA",
];

/// Closed pinned runtime profile for a P27 app site.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum AppRuntime {
    /// Node.js 22 LTS (`>= 22.23.4`, SQLite FTS5; required by D-096 EmDash).
    #[serde(rename = "node_22_v1")]
    Node22V1,
    /// Bun 1.x pinned release binary.
    #[serde(rename = "bun_1_v1")]
    Bun1V1,
}

impl AppRuntime {
    /// Closed wire identifier for this runtime profile.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Node22V1 => "node_22_v1",
            Self::Bun1V1 => "bun_1_v1",
        }
    }
}

/// Closed bounded unit action for `app_lifecycle`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppLifecycleAction {
    /// Start the app service (and companion worker if configured).
    Start,
    /// Stop the app service (and companion worker if configured).
    Stop,
    /// Restart the app service (and companion worker if configured).
    Restart,
}

impl AppLifecycleAction {
    /// Closed wire identifier for this lifecycle action.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
        }
    }
}

/// Whether `path` is a safe relative entrypoint inside a release tree:
/// no leading/trailing `/`, no `.` or `..`, only ASCII `[A-Za-z0-9._-/]`.
pub fn valid_entrypoint(path: &str) -> bool {
    if path.is_empty()
        || path.len() > MAX_APP_ENTRYPOINT_BYTES
        || path.starts_with('/')
        || path.ends_with('/')
    {
        return false;
    }
    path.split('/').all(|segment| {
        !segment.is_empty()
            && segment != "."
            && segment != ".."
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    })
}

/// W641 (H-13): whether `path` is a safe passive relative file path inside a
/// release `manifest.sha256`. Extends [`valid_entrypoint`] only for passive
/// data/dependency paths (up to 256 bytes, allowing `@` for scoped npm packages
/// like `@emdash-cms/*` and `[`/`]` for Astro/framework route files) while
/// still rejecting absolute paths, traversal, whitespace, control characters,
/// and shell metacharacters.
pub fn valid_manifest_path(path: &str) -> bool {
    if path.is_empty()
        || path.len() > MAX_APP_MANIFEST_PATH_BYTES
        || path.starts_with('/')
        || path.ends_with('/')
    {
        return false;
    }
    path.split('/').all(|segment| {
        !segment.is_empty()
            && segment != "."
            && segment != ".."
            && segment.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b'_' | b'-' | b'@' | b'[' | b']')
            })
    })
}

/// Whether `path` is a safe absolute HTTP health check path on `127.0.0.1`:
/// `/` or `/segment(/segment)*` with no query, fragment, whitespace, or `..`.
pub fn valid_health_path(path: &str) -> bool {
    if path == "/" {
        return true;
    }
    if path.len() > MAX_APP_HEALTH_PATH_BYTES || !path.starts_with('/') {
        return false;
    }
    let trimmed = path.strip_prefix('/').unwrap_or("");
    let trimmed = trimmed.strip_suffix('/').unwrap_or(trimmed);
    !trimmed.is_empty()
        && trimmed.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
}

/// Whether `key` is a valid uppercase POSIX env variable name not reserved by the host.
pub fn valid_env_key(key: &str) -> bool {
    if key.is_empty() || key.len() > MAX_APP_ENV_KEY_BYTES || FORBIDDEN_ENV_KEYS.contains(&key) {
        return false;
    }
    let bytes = key.as_bytes();
    (bytes[0].is_ascii_uppercase() || bytes[0] == b'_')
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
}

/// Whether `keys` is a sorted, unique list of valid env var names within the cap.
pub fn valid_env_keys(keys: &[String]) -> bool {
    keys.len() <= MAX_APP_ENV_KEYS
        && keys.iter().all(|key| valid_env_key(key))
        && keys.windows(2).all(|pair| pair[0] < pair[1])
}

/// Whether `id` is a strict release identifier `[a-z0-9][a-z0-9._-]{0,63}` with no `..`.
pub fn valid_release_id(id: &str) -> bool {
    if id.is_empty() || id.len() > MAX_APP_RELEASE_ID_BYTES || id.contains("..") {
        return false;
    }
    let bytes = id.as_bytes();
    (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn valid_app_routes(routes: &[ProxyRoute], low: usize, expected_port: u16) -> bool {
    let prefixes: BTreeSet<&str> = routes.iter().map(|route| route.prefix.as_str()).collect();
    (low..=MAX_PROXY_ROUTES).contains(&routes.len())
        && prefixes.len() == routes.len()
        && routes.iter().all(|route| {
            valid_prefix(&route.prefix) && routable_port(route.port) && route.port == expected_port
        })
}

/// Independently enrolled facts for P27 app binding checks; never taken from
/// the submitted plan or grant.
pub struct AppBindingContext<'a> {
    /// Enrolled host identity.
    pub host_id: &'a Id,
    /// Enrolled host/recovery epoch.
    pub host_epoch: &'a Id,
    /// Enrolled profile digest.
    pub profile_digest: &'a Sha256Digest,
    /// Requester identity resolved from the kernel peer.
    pub requester: &'a Id,
    /// Verified signer principal.
    pub issuer: &'a Id,
    /// Current signer/revocation policy epoch.
    pub signer_policy_epoch: &'a Id,
    /// Reliable current Unix seconds; `None` denies.
    pub now: Option<Timestamp>,
}

// ============================================================================
// 1. app_provision
// ============================================================================

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum AppProvisionVerb {
    AppProvision,
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct AppProvisionEffects {
    creates_account: bool,
    forwards_to_loopback: bool,
    installs_app_unit: bool,
    traffic_activation: bool,
    runs_package_scripts: bool,
}

const PROVISION_EFFECTS: AppProvisionEffects = AppProvisionEffects {
    creates_account: true,
    forwards_to_loopback: true,
    installs_app_unit: true,
    traffic_activation: false,
    runs_package_scripts: false,
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AppProvisionPlanRecord {
    schema_version: u16,
    plan_id: Id,
    host_id: Id,
    host_epoch: Id,
    profile_digest: Sha256Digest,
    requester: Id,
    verb: AppProvisionVerb,
    site_id: SiteId,
    hostname: Hostname,
    runtime: AppRuntime,
    port: u16,
    #[serde(deserialize_with = "crate::codec::object_list")]
    routes: Vec<ProxyRoute>,
    #[serde(deserialize_with = "crate::codec::object_list")]
    websockets: Vec<ProxyRoute>,
    entrypoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    worker_entrypoint: Option<String>,
    health_path: String,
    env_keys: Vec<String>,
    memory_max_mib: u64,
    tasks_max: u64,
    quota_mib: u64,
    #[serde(deserialize_with = "crate::codec::object")]
    expected_effects: AppProvisionEffects,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    limitations: Vec<Text>,
}

impl AppProvisionPlanRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        let worker_ok = self
            .worker_entrypoint
            .as_deref()
            .is_none_or(valid_entrypoint);
        if self.expected_effects != PROVISION_EFFECTS
            || !routable_port(self.port)
            || !valid_app_routes(&self.routes, 1, self.port)
            || !self.routes.iter().any(|route| route.prefix == "/")
            || !valid_app_routes(&self.websockets, 0, self.port)
            || !valid_entrypoint(&self.entrypoint)
            || !worker_ok
            || !valid_health_path(&self.health_path)
            || !valid_env_keys(&self.env_keys)
            || !(MIN_APP_MEMORY_MIB..=MAX_APP_MEMORY_MIB).contains(&self.memory_max_mib)
            || !(MIN_APP_TASKS_MAX..=MAX_APP_TASKS_MAX).contains(&self.tasks_max)
            || !(MIN_APP_QUOTA_MIB..=MAX_APP_QUOTA_MIB).contains(&self.quota_mib)
            || self.limitations.len() > 8
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidPlan);
        }
        Ok(())
    }
}

/// Closed `app_provision` plan retaining its canonical original semantic bytes.
#[derive(Debug)]
pub struct AppProvisionPlan {
    record: AppProvisionPlanRecord,
    canonical: CanonicalObject,
}

impl AppProvisionPlan {
    /// Decodes schema v1 and its intrinsic constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, AppProvisionPlanRecord::validate)?;
        Ok(Self { record, canonical })
    }

    /// Complete immutable semantic bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.canonical.as_bytes()
    }

    /// Domain-separated SHA-256 of the complete validated object.
    pub fn digest(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(self.canonical.plan_domain_digest())
    }

    /// New app site ID.
    pub fn site_id(&self) -> &SiteId {
        &self.record.site_id
    }

    /// Hostname served by the app's proxy vhost.
    pub fn hostname(&self) -> &Hostname {
        &self.record.hostname
    }

    /// Pinned runtime profile.
    pub fn runtime(&self) -> AppRuntime {
        self.record.runtime
    }

    /// Reserved loopback port on `127.0.0.1`.
    pub fn port(&self) -> u16 {
        self.record.port
    }

    /// Path routes forwarded to `127.0.0.1:<port>`.
    pub fn routes(&self) -> &[ProxyRoute] {
        &self.record.routes
    }

    /// WebSocket paths forwarded to `127.0.0.1:<port>`.
    pub fn websockets(&self) -> &[ProxyRoute] {
        &self.record.websockets
    }

    /// Relative release entrypoint for the HTTP app service.
    pub fn entrypoint(&self) -> &str {
        &self.record.entrypoint
    }

    /// Optional relative release entrypoint for a companion background worker.
    pub fn worker_entrypoint(&self) -> Option<&str> {
        self.record.worker_entrypoint.as_deref()
    }

    /// Loopback HTTP health check path.
    pub fn health_path(&self) -> &str {
        &self.record.health_path
    }

    /// Declared environment variable key names (never secret values).
    pub fn env_keys(&self) -> &[String] {
        &self.record.env_keys
    }

    /// Cgroup `MemoryMax` in MiB.
    pub fn memory_max_mib(&self) -> u64 {
        self.record.memory_max_mib
    }

    /// Cgroup `TasksMax`.
    pub fn tasks_max(&self) -> u64 {
        self.record.tasks_max
    }

    /// Site filesystem quota in MiB.
    pub fn quota_mib(&self) -> u64 {
        self.record.quota_mib
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AppProvisionGrantRecord {
    schema_version: u16,
    grant_id: Id,
    nonce: Id,
    plan_id: Id,
    plan_digest: Sha256Digest,
    host_id: Id,
    host_epoch: Id,
    profile_digest: Sha256Digest,
    issuer: Id,
    requester: Id,
    signer_policy_epoch: Id,
    site_ids: Vec<SiteId>,
    verbs: Vec<AppProvisionVerb>,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    max_operations: u64,
}

impl AppProvisionGrantRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.issuer == self.requester
            || self.site_ids.len() != 1
            || self.verbs != [AppProvisionVerb::AppProvision]
            || self.max_operations != 1
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidGrant);
        }
        Ok(())
    }
}

/// Closed `app_provision` grant envelope; no verified signature or replay authority.
#[derive(Debug)]
pub struct AppProvisionGrant {
    record: AppProvisionGrantRecord,
    canonical: CanonicalObject,
}

impl AppProvisionGrant {
    /// Decodes the bounded schema and intrinsic grant constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, AppProvisionGrantRecord::validate)?;
        Ok(Self { record, canonical })
    }

    /// Complete canonical envelope bytes that the signature must cover.
    pub fn as_bytes(&self) -> &[u8] {
        self.canonical.as_bytes()
    }

    /// Signed grant identity.
    pub fn grant_id(&self) -> &Id {
        &self.record.grant_id
    }

    /// Signed single-use nonce.
    pub fn nonce(&self) -> &Id {
        &self.record.nonce
    }

    /// Normal signed deadline.
    pub fn expires_at(&self) -> Timestamp {
        self.record.expires_at
    }
}

/// Pure consistency check for `app_provision`; success confers no authority.
pub fn check_app_provision_binding(
    plan: &AppProvisionPlan,
    grant: &AppProvisionGrant,
    context: &AppBindingContext<'_>,
) -> Result<(), ApprovalError> {
    let p = &plan.record;
    let g = &grant.record;
    if g.plan_id != p.plan_id
        || g.plan_digest != plan.digest()
        || p.host_id != *context.host_id
        || g.host_id != *context.host_id
        || p.host_epoch != *context.host_epoch
        || g.host_epoch != *context.host_epoch
        || p.profile_digest != *context.profile_digest
        || g.profile_digest != *context.profile_digest
        || p.requester != *context.requester
        || g.requester != *context.requester
        || g.issuer != *context.issuer
        || g.signer_policy_epoch != *context.signer_policy_epoch
        || g.site_ids.as_slice() != std::slice::from_ref(&p.site_id)
        || g.risk_class != p.risk_class
        || g.valid_from.get() < p.valid_from.get()
        || g.expires_at.get() > p.expires_at.get()
    {
        return Err(ApprovalError::BindingMismatch);
    }
    let now = context.now.ok_or(ApprovalError::ClockUncertain)?;
    if now.get() < g.valid_from.get() || now.get() >= g.expires_at.get() {
        return Err(ApprovalError::OutsideValidity);
    }
    Ok(())
}

// ============================================================================
// 2. app_deploy
// ============================================================================

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum AppDeployVerb {
    AppDeploy,
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct AppDeployEffects {
    unpacks_as_site: bool,
    switches_release: bool,
    restarts_app_unit: bool,
    rolls_back_on_failed_health: bool,
    runs_package_scripts: bool,
    traffic_activation: bool,
}

const DEPLOY_EFFECTS: AppDeployEffects = AppDeployEffects {
    unpacks_as_site: true,
    switches_release: true,
    restarts_app_unit: true,
    rolls_back_on_failed_health: true,
    runs_package_scripts: false,
    traffic_activation: false,
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AppDeployPlanRecord {
    schema_version: u16,
    plan_id: Id,
    host_id: Id,
    host_epoch: Id,
    profile_digest: Sha256Digest,
    requester: Id,
    verb: AppDeployVerb,
    site_id: SiteId,
    release_id: String,
    runtime: AppRuntime,
    artifact_sha256: Sha256Digest,
    manifest_sha256: Sha256Digest,
    file_count: u64,
    total_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    migration_entrypoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    capture_operation_id: Option<Id>,
    health_path: String,
    #[serde(deserialize_with = "crate::codec::object")]
    expected_effects: AppDeployEffects,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    limitations: Vec<Text>,
}

impl AppDeployPlanRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        let migration_ok = match (&self.migration_entrypoint, &self.capture_operation_id) {
            (Some(entry), Some(_)) => valid_entrypoint(entry),
            // A migration MUST bind a recent capture for atomic rollback.
            (Some(_), None) => false,
            (None, _) => true,
        };
        if self.expected_effects != DEPLOY_EFFECTS
            || !valid_release_id(&self.release_id)
            || !(1..=MAX_APP_RELEASE_FILES).contains(&self.file_count)
            || !(1..=MAX_APP_RELEASE_BYTES).contains(&self.total_bytes)
            || !migration_ok
            || !valid_health_path(&self.health_path)
            || self.limitations.len() > 8
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidPlan);
        }
        Ok(())
    }
}

/// Closed `app_deploy` plan retaining its canonical original semantic bytes.
#[derive(Debug)]
pub struct AppDeployPlan {
    record: AppDeployPlanRecord,
    canonical: CanonicalObject,
}

impl AppDeployPlan {
    /// Decodes schema v1 and its intrinsic constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, AppDeployPlanRecord::validate)?;
        Ok(Self { record, canonical })
    }

    /// Complete immutable semantic bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.canonical.as_bytes()
    }

    /// Domain-separated SHA-256 of the complete validated object.
    pub fn digest(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(self.canonical.plan_domain_digest())
    }

    /// Target app site ID.
    pub fn site_id(&self) -> &SiteId {
        &self.record.site_id
    }

    /// Unique release identifier for this deployment.
    pub fn release_id(&self) -> &str {
        &self.record.release_id
    }

    /// Runtime profile matching the target app.
    pub fn runtime(&self) -> AppRuntime {
        self.record.runtime
    }

    /// SHA-256 of the prepared release intake archive.
    pub fn artifact_sha256(&self) -> &Sha256Digest {
        &self.record.artifact_sha256
    }

    /// SHA-256 of the sorted per-file manifest inside the release intake.
    pub fn manifest_sha256(&self) -> &Sha256Digest {
        &self.record.manifest_sha256
    }

    /// Expected file count in the release archive.
    pub fn file_count(&self) -> u64 {
        self.record.file_count
    }

    /// Expected total unpacked bytes in the release archive.
    pub fn total_bytes(&self) -> u64 {
        self.record.total_bytes
    }

    /// Optional bounded migration entrypoint run as `rs_<site_id>` before cutover.
    pub fn migration_entrypoint(&self) -> Option<&str> {
        self.record.migration_entrypoint.as_deref()
    }

    /// Optional (required with migration) recent capture operation ID for rollback.
    pub fn capture_operation_id(&self) -> Option<&Id> {
        self.record.capture_operation_id.as_ref()
    }

    /// Loopback HTTP health check path probed after switch.
    pub fn health_path(&self) -> &str {
        &self.record.health_path
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AppDeployGrantRecord {
    schema_version: u16,
    grant_id: Id,
    nonce: Id,
    plan_id: Id,
    plan_digest: Sha256Digest,
    host_id: Id,
    host_epoch: Id,
    profile_digest: Sha256Digest,
    issuer: Id,
    requester: Id,
    signer_policy_epoch: Id,
    site_ids: Vec<SiteId>,
    verbs: Vec<AppDeployVerb>,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    max_operations: u64,
}

impl AppDeployGrantRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.issuer == self.requester
            || self.site_ids.len() != 1
            || self.verbs != [AppDeployVerb::AppDeploy]
            || self.max_operations != 1
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidGrant);
        }
        Ok(())
    }
}

/// Closed `app_deploy` grant envelope; no verified signature or replay authority.
#[derive(Debug)]
pub struct AppDeployGrant {
    record: AppDeployGrantRecord,
    canonical: CanonicalObject,
}

impl AppDeployGrant {
    /// Decodes the bounded schema and intrinsic grant constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, AppDeployGrantRecord::validate)?;
        Ok(Self { record, canonical })
    }

    /// Complete canonical envelope bytes that the signature must cover.
    pub fn as_bytes(&self) -> &[u8] {
        self.canonical.as_bytes()
    }

    /// Signed grant identity.
    pub fn grant_id(&self) -> &Id {
        &self.record.grant_id
    }

    /// Signed single-use nonce.
    pub fn nonce(&self) -> &Id {
        &self.record.nonce
    }

    /// Normal signed deadline.
    pub fn expires_at(&self) -> Timestamp {
        self.record.expires_at
    }
}

/// Pure consistency check for `app_deploy`; success confers no authority.
pub fn check_app_deploy_binding(
    plan: &AppDeployPlan,
    grant: &AppDeployGrant,
    context: &AppBindingContext<'_>,
) -> Result<(), ApprovalError> {
    let p = &plan.record;
    let g = &grant.record;
    if g.plan_id != p.plan_id
        || g.plan_digest != plan.digest()
        || p.host_id != *context.host_id
        || g.host_id != *context.host_id
        || p.host_epoch != *context.host_epoch
        || g.host_epoch != *context.host_epoch
        || p.profile_digest != *context.profile_digest
        || g.profile_digest != *context.profile_digest
        || p.requester != *context.requester
        || g.requester != *context.requester
        || g.issuer != *context.issuer
        || g.signer_policy_epoch != *context.signer_policy_epoch
        || g.site_ids.as_slice() != std::slice::from_ref(&p.site_id)
        || g.risk_class != p.risk_class
        || g.valid_from.get() < p.valid_from.get()
        || g.expires_at.get() > p.expires_at.get()
    {
        return Err(ApprovalError::BindingMismatch);
    }
    let now = context.now.ok_or(ApprovalError::ClockUncertain)?;
    if now.get() < g.valid_from.get() || now.get() >= g.expires_at.get() {
        return Err(ApprovalError::OutsideValidity);
    }
    Ok(())
}

// ============================================================================
// 3. app_lifecycle
// ============================================================================

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum AppLifecycleVerb {
    AppLifecycle,
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct AppLifecycleEffects {
    changes_app_unit_state: bool,
    reloads_ols: bool,
    changes_files: bool,
}

const LIFECYCLE_EFFECTS: AppLifecycleEffects = AppLifecycleEffects {
    changes_app_unit_state: true,
    reloads_ols: false,
    changes_files: false,
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AppLifecyclePlanRecord {
    schema_version: u16,
    plan_id: Id,
    host_id: Id,
    host_epoch: Id,
    profile_digest: Sha256Digest,
    requester: Id,
    verb: AppLifecycleVerb,
    site_id: SiteId,
    action: AppLifecycleAction,
    #[serde(deserialize_with = "crate::codec::object")]
    expected_effects: AppLifecycleEffects,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    limitations: Vec<Text>,
}

impl AppLifecyclePlanRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.expected_effects != LIFECYCLE_EFFECTS
            || self.limitations.len() > 8
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidPlan);
        }
        Ok(())
    }
}

/// Closed `app_lifecycle` plan retaining its canonical original semantic bytes.
#[derive(Debug)]
pub struct AppLifecyclePlan {
    record: AppLifecyclePlanRecord,
    canonical: CanonicalObject,
}

impl AppLifecyclePlan {
    /// Decodes schema v1 and its intrinsic constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, AppLifecyclePlanRecord::validate)?;
        Ok(Self { record, canonical })
    }

    /// Complete immutable semantic bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.canonical.as_bytes()
    }

    /// Domain-separated SHA-256 of the complete validated object.
    pub fn digest(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(self.canonical.plan_domain_digest())
    }

    /// Target app site ID.
    pub fn site_id(&self) -> &SiteId {
        &self.record.site_id
    }

    /// Requested unit state transition (`start`, `stop`, or `restart`).
    pub fn action(&self) -> AppLifecycleAction {
        self.record.action
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AppLifecycleGrantRecord {
    schema_version: u16,
    grant_id: Id,
    nonce: Id,
    plan_id: Id,
    plan_digest: Sha256Digest,
    host_id: Id,
    host_epoch: Id,
    profile_digest: Sha256Digest,
    issuer: Id,
    requester: Id,
    signer_policy_epoch: Id,
    site_ids: Vec<SiteId>,
    verbs: Vec<AppLifecycleVerb>,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    max_operations: u64,
}

impl AppLifecycleGrantRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.issuer == self.requester
            || self.site_ids.len() != 1
            || self.verbs != [AppLifecycleVerb::AppLifecycle]
            || self.max_operations != 1
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidGrant);
        }
        Ok(())
    }
}

/// Closed `app_lifecycle` grant envelope; no verified signature or replay authority.
#[derive(Debug)]
pub struct AppLifecycleGrant {
    record: AppLifecycleGrantRecord,
    canonical: CanonicalObject,
}

impl AppLifecycleGrant {
    /// Decodes the bounded schema and intrinsic grant constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, AppLifecycleGrantRecord::validate)?;
        Ok(Self { record, canonical })
    }

    /// Complete canonical envelope bytes that the signature must cover.
    pub fn as_bytes(&self) -> &[u8] {
        self.canonical.as_bytes()
    }

    /// Signed grant identity.
    pub fn grant_id(&self) -> &Id {
        &self.record.grant_id
    }

    /// Signed single-use nonce.
    pub fn nonce(&self) -> &Id {
        &self.record.nonce
    }

    /// Normal signed deadline.
    pub fn expires_at(&self) -> Timestamp {
        self.record.expires_at
    }
}

/// Pure consistency check for `app_lifecycle`; success confers no authority.
pub fn check_app_lifecycle_binding(
    plan: &AppLifecyclePlan,
    grant: &AppLifecycleGrant,
    context: &AppBindingContext<'_>,
) -> Result<(), ApprovalError> {
    let p = &plan.record;
    let g = &grant.record;
    if g.plan_id != p.plan_id
        || g.plan_digest != plan.digest()
        || p.host_id != *context.host_id
        || g.host_id != *context.host_id
        || p.host_epoch != *context.host_epoch
        || g.host_epoch != *context.host_epoch
        || p.profile_digest != *context.profile_digest
        || g.profile_digest != *context.profile_digest
        || p.requester != *context.requester
        || g.requester != *context.requester
        || g.issuer != *context.issuer
        || g.signer_policy_epoch != *context.signer_policy_epoch
        || g.site_ids.as_slice() != std::slice::from_ref(&p.site_id)
        || g.risk_class != p.risk_class
        || g.valid_from.get() < p.valid_from.get()
        || g.expires_at.get() > p.expires_at.get()
    {
        return Err(ApprovalError::BindingMismatch);
    }
    let now = context.now.ok_or(ApprovalError::ClockUncertain)?;
    if now.get() < g.valid_from.get() || now.get() >= g.expires_at.get() {
        return Err(ApprovalError::OutsideValidity);
    }
    Ok(())
}
