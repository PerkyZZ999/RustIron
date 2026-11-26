//! Closed, unprivileged contracts for signed operation plans and grants.
//!
//! Successful decoding/binding is not signature verification, human approval,
//! trusted observation, replay admission or permission to execute an effect.

use std::{error::Error, fmt};

use serde::{Serialize, de::DeserializeOwned};

use crate::{CanonicalObject, ProtocolError, codec::validate_canonical_json};

mod app;
mod capture;
mod certificate;
mod clone_scrub;
mod credential_rotate;
mod delete;
mod destination;
mod dns_change;
mod dns_import;
mod eject;
mod envelope;
mod grant;
mod import;
mod ols;
mod plan;
mod prepared;
mod probe;
mod product_backup;
mod proxy_site;
mod quota;
mod readopt;
mod restore;
mod retire;
mod scrub;
mod site;
mod site_clone;
mod site_update;
mod standing_capture;
mod types;
mod zone;

pub use app::{
    AppBindingContext, AppDeployGrant, AppDeployPlan, AppLifecycleAction, AppLifecycleGrant,
    AppLifecyclePlan, AppProvisionGrant, AppProvisionPlan, AppRuntime, MAX_APP_ENTRYPOINT_BYTES,
    MAX_APP_ENV_KEY_BYTES, MAX_APP_ENV_KEYS, MAX_APP_HEALTH_PATH_BYTES, MAX_APP_MEMORY_MIB,
    MAX_APP_QUOTA_MIB, MAX_APP_RELEASE_BYTES, MAX_APP_RELEASE_FILES, MAX_APP_RELEASE_ID_BYTES,
    MAX_APP_TASKS_MAX, MIN_APP_MEMORY_MIB, MIN_APP_QUOTA_MIB, MIN_APP_TASKS_MAX,
    check_app_deploy_binding, check_app_lifecycle_binding, check_app_provision_binding,
    valid_entrypoint, valid_env_key, valid_env_keys, valid_health_path, valid_manifest_path,
    valid_release_id,
};
pub use capture::{
    CaptureBindingContext, CaptureDestination, CaptureGrant, CapturePlan, CaptureRecipe,
    check_capture_binding,
};
pub use certificate::{
    CertificateBindingContext, CertificateGrant, CertificatePlan, check_certificate_binding,
};
pub use clone_scrub::{
    CloneScrubBindingContext, CloneScrubGrant, CloneScrubPlan, check_clone_scrub_binding,
};
pub use credential_rotate::{
    CredentialRotateBindingContext, CredentialRotateGrant, CredentialRotatePlan, CredentialTarget,
    check_credential_rotate_binding,
};
pub use delete::{DeleteBindingContext, DeleteGrant, DeletePlan, check_delete_binding};
pub use destination::{
    MAX_PRODUCT_BACKUP_CA_BYTES, MAX_PRODUCT_BACKUP_POLICY_BYTES, MAX_PRODUCT_BACKUP_SECRET_BYTES,
    ProductBackupCredential, ProductBackupPolicy, ProductBackupSite,
};
pub use dns_change::{
    ChangeAction, DnsChangeGrant, DnsChangePlan, Expected, MAX_CHANGE_OPERATIONS, MAX_SET_RECORDS,
    SetOperation, check_dns_change_binding,
};
pub use dns_import::{
    DnsBindingContext, DnsImportGrant, DnsImportPlan, MAX_IMPORT_RECORD_SETS,
    check_dns_import_binding,
};
pub use eject::{EjectBindingContext, EjectGrant, EjectPlan, check_eject_binding};
pub use envelope::{
    ALL_SITE_OLS_IMPACT_EXPLANATION, AuthorityBudgetReport, AuthorityRemaining, AuthorityUsage,
    BlastRadiusEnvelope, BlastRadiusLimits, EnvelopeRefusal, ImpactScope, check_envelope_budget,
    envelope_for_plan, plan_window_bounds,
};
pub use grant::{FixtureBindingContext, FixtureGrant, check_fixture_binding};
pub use import::{ImportBindingContext, ImportGrant, ImportPlan, check_import_binding};
pub use ols::{
    OlsBindingContext, OlsGrant, OlsPlan, PageCacheOptIn, PageCacheOptOut, PageCacheRecipe,
    check_ols_binding,
};
pub use plan::{FixtureActivation, FixturePlan};
pub use prepared::{PlanKind, PreparedPlan};
pub use probe::{
    ProbeBindingContext, ProbeGrant, ProbePlan, ProbeProfile, SnapshotId, check_probe_binding,
};
pub use product_backup::{
    ProductBackupBindingContext, ProductBackupGrant, ProductBackupPlan, ProductBackupTarget,
    check_product_backup_binding,
};
pub use proxy_site::{
    MAX_PROXY_PREFIX_BYTES, MAX_PROXY_ROUTES, MIN_PROXY_PORT, ProxyBindingContext, ProxyGrant,
    ProxyPlan, ProxyRoute, check_proxy_binding, routable_port, valid_prefix,
};
pub use quota::{QuotaBindingContext, QuotaGrant, QuotaPlan, check_quota_binding};
pub use readopt::{
    AllocationFloor, MAX_FLOOR_CATEGORY, MAX_READOPT_SITES, ReadoptBindingContext, ReadoptForm,
    ReadoptGrant, ReadoptPlan, check_readopt_binding,
};
pub use restore::{RestoreGrant, RestorePlan, RestoreScope, RestoreSource, check_restore_binding};
pub use retire::{RetireBindingContext, RetireGrant, RetirePlan, check_retire_binding};
pub use scrub::{ScrubBindingContext, ScrubGrant, ScrubPlan, check_scrub_binding};
pub use site::{
    Hostname, SiteBindingContext, SiteGrant, SiteId, SitePlan, SiteQuotaLimits, SiteRecipe,
    check_site_binding,
};
pub use site_clone::{
    CloneSource, CloneTarget, SiteCloneGrant, SiteClonePlan, check_site_clone_binding,
};
pub use site_update::{
    CORE_SLUG, ComponentSlug, ComponentVersion, MAX_UPDATE_COMPONENTS, SiteUpdateGrant,
    SiteUpdatePlan, UpdateBindingContext, UpdateComponent, UpdateKind, check_update_binding,
};
pub use standing_capture::{
    MAX_STANDING_PERIOD_SECONDS, MAX_STANDING_RUNS, MAX_STANDING_SITES, MAX_STANDING_SPAN_SECONDS,
    MAX_STANDING_WINDOW_SECONDS, MIN_STANDING_PERIOD_SECONDS, MIN_STANDING_WINDOW_SECONDS,
    STANDING_RUN_DOMAIN, StandingCaptureBindingContext, StandingCaptureGrant, StandingCapturePlan,
    StandingRun, StandingSchedule, WindowPosition, check_standing_capture_binding, standing_run,
};
pub use types::{MAX_OBSERVATION_AGE_SECONDS, Sha256Digest};
pub use zone::{
    MAX_TTL, MAX_ZONE_BYTES, MAX_ZONE_LINE_BYTES, MAX_ZONE_LINES, MIN_TTL, ParsedZone, RecordSet,
    RecordType, ZoneError, ZoneName, parse_zone,
};

/// Redacted failures for the fixture contract; no rejected values are retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalError {
    /// Malformed, ambiguous, unknown-field or otherwise invalid record shape.
    InvalidMessage,
    /// Unsupported numeric schema version.
    UnsupportedVersion,
    /// Complete JSON exceeds the existing request byte ceiling.
    RequestTooLarge,
    /// Plan contradicts the fixed fixture profile or its own preconditions.
    InvalidPlan,
    /// A required precondition is explicitly unknown or incomplete.
    UnknownPrecondition,
    /// Grant contradicts the bounded fixture contract.
    InvalidGrant,
    /// Plan, grant or independently supplied policy context disagree.
    BindingMismatch,
    /// Reliable supplied time is outside the normal execution window.
    OutsideValidity,
    /// No reliable clock was supplied; new work cannot be considered valid.
    ClockUncertain,
}

impl fmt::Display for ApprovalError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::InvalidMessage => "invalid fixture JSON or closed schema",
            Self::UnsupportedVersion => "unsupported fixture schema version",
            Self::RequestTooLarge => "fixture record exceeds its byte limit",
            Self::InvalidPlan => "fixture plan violates profile or consistency requirements",
            Self::UnknownPrecondition => {
                "fixture preconditions require complete known observations"
            }
            Self::InvalidGrant => "fixture grant violates scope or validity requirements",
            Self::BindingMismatch => "fixture plan, grant and policy bindings disagree",
            Self::OutsideValidity => "fixture execution window is not currently valid",
            Self::ClockUncertain => "reliable time is required for fixture validity checks",
        })
    }
}

impl Error for ApprovalError {}

impl From<ProtocolError> for ApprovalError {
    fn from(error: ProtocolError) -> Self {
        match error {
            ProtocolError::RequestTooLarge => Self::RequestTooLarge,
            _ => Self::InvalidMessage,
        }
    }
}

fn decode<T: DeserializeOwned + Serialize>(
    input: &[u8],
    validate: impl FnOnce(&T) -> Result<(), ApprovalError>,
) -> Result<(T, CanonicalObject), ApprovalError> {
    validate_canonical_json(input)?;
    let record = serde_json::from_slice(input).map_err(|_| ApprovalError::InvalidMessage)?;
    validate(&record)?;
    // Refuse lossy interpretations; only the original object is hashed below.
    let interpreted = serde_json::to_value(&record).map_err(|_| ApprovalError::InvalidMessage)?;
    let original: serde_json::Value =
        serde_json::from_slice(input).map_err(|_| ApprovalError::InvalidMessage)?;
    if interpreted != original {
        return Err(ApprovalError::InvalidMessage);
    }
    // Hash the complete original object only after typed/semantic validation.
    Ok((record, CanonicalObject::decode(input)?))
}
