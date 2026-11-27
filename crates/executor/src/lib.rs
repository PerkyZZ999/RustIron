//! Candidate executor admission checks for the isolated S02 lab fixture.
//!
//! [`admit`] composes independent checks: trusted policy ancestry, enrolled
//! kernel peer, closed plan/grant binding, reliable time, SSHSIG verification of
//! exact grant bytes and a live registry re-observation. Success yields a
//! journal [`Intent`] only. It records nothing, consumes no nonce, reserves no
//! resource and performs no effect. [`Executor::submit`] adds the durable step:
//! one journal transaction that consumes the grant/nonce and records intent.

use std::path::PathBuf;

use rustiron_contracts::{
    Id, MAX_REQUEST_BYTES, Timestamp,
    approval::ApprovalError,
    approval::{
        CaptureBindingContext, CaptureGrant, CapturePlan, CertificateBindingContext,
        CertificateGrant, CertificatePlan, EjectBindingContext, EjectGrant, EjectPlan,
        FixtureBindingContext, FixtureGrant, FixturePlan, ImportBindingContext, ImportGrant,
        ImportPlan, OlsBindingContext, OlsGrant, OlsPlan, ProbeBindingContext, ProbeGrant,
        ProbePlan, ReadoptBindingContext, ReadoptGrant, ReadoptPlan, ScrubBindingContext,
        ScrubGrant, ScrubPlan, Sha256Digest, SiteBindingContext, SiteGrant, SitePlan, SiteRecipe,
        check_capture_binding, check_certificate_binding, check_eject_binding,
        check_fixture_binding, check_import_binding, check_ols_binding, check_probe_binding,
        check_readopt_binding, check_scrub_binding, check_site_binding,
    },
};
use rustiron_journal::{Intent, JournalError, ProvisionIntent};
use sha2::{Digest, Sha256};

pub mod admin_helper;
mod app_site;
pub mod caddy;
mod capture;
mod census;
mod certificate;
pub mod credential_rotate;
mod dns;
mod dns_change;
mod dns_import;
mod durable;
pub mod ejection;
mod files;
mod import;
pub mod layout;
mod manifest;
mod mark;
mod observed;
pub mod ols;
mod packages;
mod page_cache;
pub mod peer_label;
mod policy;
mod postgres;
mod product_capture;
pub mod provision;
mod proxy_site;
pub mod quota;
pub mod readopt;
pub mod receipt;
pub mod receipt_key;
pub mod redaction;
mod registry;
mod restore;
pub mod retention_evidence;
pub mod serve;
mod signature;
mod signer;
mod site_delete;
mod site_restore;
mod site_retire;
mod site_update;
mod staging_clone;
pub mod store_network;
pub mod write_gate;

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod test_support;
#[cfg(test)]
mod verification_tests;

pub use durable::{Executor, Fault, ReadoptObservation};

const MAX_SIGNATURE_BYTES: usize = 16 * 1024;

/// Stable redacted admission outcomes; no rejected value is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutorError {
    /// Untrusted ownership, mode, link or ancestry on a trusted location.
    AccessDenied,
    /// Policy, verifier or scratch state is missing, corrupt or unusable.
    Unavailable,
    /// Kernel peer identity is not the enrolled requester.
    PeerDenied,
    /// Malformed, oversized or closed-schema-violating request.
    InvalidRequest,
    /// Plan, grant and enrolled policy disagree.
    BindingDenied,
    /// No reliable time, or outside the grant's normal window.
    TimeDenied,
    /// Signature, key, namespace or revocation check failed.
    SignatureDenied,
    /// The fixture registry cannot be observed completely.
    RegistryUnavailable,
    /// Live registry state differs from the plan's reported predecessor.
    PreconditionChanged,
    /// Grant, nonce, operation or retry key already used with other bindings,
    /// or the enrolled host/epoch changed since the journal was opened.
    ReplayDenied,
    /// One unresolved operation already blocks new work.
    Busy,
    /// Reliable time moved backwards since the last recorded intent.
    ClockRollback,
    /// Bounded replay history is full; history is never pruned silently.
    Capacity,
    /// Initialization found existing journal artifacts; nothing was repaired.
    StateExists,
    /// Stored journal host/epoch differs from current enrollment.
    IdentityMismatch,
    /// Not an intent newly recorded by this executor instance; use reconcile.
    NotAdmitted,
    /// Compensation needs an attempted effect in `needs_attention` and no
    /// earlier compensation attempt.
    CompensationDenied,
    /// A resource the provision would create already exists; nothing touched.
    Collision,
    /// A provisioning step's command or verification failed; resources kept.
    StepFailed,
    /// Live OLS state differs from what the journal and enrollment explain
    /// (edited generation, unpinned parent, WebAdmin listening); nothing changed.
    Drift,
    /// A pinned recipe artifact is absent from the trusted store.
    ArtifactUnavailable,
    /// After a switch and reload, a site's identity or health probe did not
    /// pass; the single restore of the previous generation follows.
    ProbeFailed,
    /// The journal holds fewer admissions than the external high-water mark
    /// (an older copy was restored), the mark is missing, or this epoch
    /// already admitted work and a fresh journal was requested. Nothing is
    /// admitted until an epoch rotation (archive, re-enroll, initialize).
    JournalRollback,
    /// W222: the admin helper socket was absent for the whole bounded wait
    /// (helper stopped, or still restarting); nothing was sent.
    HelperUnreachable,
    /// W228: the store's default retention lock was not verified as
    /// COMPLIANCE for at least 30 days before or after a capture.
    RetentionUnverified,
    /// The activation would render the generation that is already current:
    /// nothing to apply, refused before intent (W289; was `INVALID_REQUEST`).
    GenerationCurrent,
    /// W335: the sites filesystem cannot enforce the enrolled per-site user
    /// quota (no `usrquota`, not enforced, ambiguous mount); nothing set.
    QuotaUnavailable,
    /// W347: the trusted policy directory holds no `policy.json`: the host
    /// is installed but not enrolled. Any other policy read failure stays
    /// `EXECUTOR_ACCESS_DENIED`.
    NotEnrolled,
    /// W372: a fact a re-adoption verified does not match the signed plan
    /// or the enrolled policy; the re-adoption is recorded `refused` and
    /// nothing else is recorded or changed.
    ReadoptMismatch,
    /// D-035 (W386): no window of the standing grant is open at the
    /// executor clock, or the open window is not the requested run's
    /// window; refused before intent.
    WindowClosed,
    /// D-035 (W386): the operation ID and idempotency key are not a run
    /// that the standing grant derives for a site it names; refused
    /// before intent.
    RunMismatch,
}

impl ExecutorError {
    /// Stable machine code for receipts and logs.
    pub fn code(self) -> &'static str {
        match self {
            Self::AccessDenied => "EXECUTOR_ACCESS_DENIED",
            Self::Unavailable => "EXECUTOR_DEPENDENCY_UNAVAILABLE",
            Self::PeerDenied => "PEER_DENIED",
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::BindingDenied => "FIXTURE_BINDING_DENIED",
            Self::TimeDenied => "GRANT_TIME_DENIED",
            Self::SignatureDenied => "INVALID_SIGNATURE",
            Self::RegistryUnavailable => "REGISTRY_UNAVAILABLE",
            Self::PreconditionChanged => "PRECONDITION_CHANGED",
            Self::ReplayDenied => "REPLAY_DENIED",
            Self::Busy => "UNRESOLVED_OPERATION",
            Self::ClockRollback => "CLOCK_ROLLBACK",
            Self::Capacity => "JOURNAL_CAPACITY",
            Self::StateExists => "JOURNAL_STATE_EXISTS",
            Self::IdentityMismatch => "JOURNAL_IDENTITY_MISMATCH",
            Self::NotAdmitted => "NOT_ADMITTED_FOR_EFFECT",
            Self::CompensationDenied => "COMPENSATION_DENIED",
            Self::Collision => "PROVISION_COLLISION",
            Self::StepFailed => "PROVISION_STEP_FAILED",
            Self::Drift => "OLS_DRIFT",
            Self::ArtifactUnavailable => "RECIPE_ARTIFACT_UNAVAILABLE",
            Self::ProbeFailed => "ACTIVATION_PROBE_FAILED",
            Self::JournalRollback => "JOURNAL_ROLLBACK",
            Self::HelperUnreachable => "ADMIN_HELPER_UNREACHABLE",
            Self::RetentionUnverified => "RETENTION_LOCK_UNVERIFIED",
            Self::GenerationCurrent => "OLS_GENERATION_CURRENT",
            Self::QuotaUnavailable => "SITE_QUOTA_UNAVAILABLE",
            Self::NotEnrolled => "EXECUTOR_NOT_ENROLLED",
            Self::ReadoptMismatch => "READOPT_MISMATCH",
            Self::WindowClosed => "STANDING_WINDOW_CLOSED",
            Self::RunMismatch => "STANDING_RUN_MISMATCH",
        }
    }

    /// Every error, for mapping a stable code back (admin helper replies).
    pub const ALL: [Self; 31] = [
        Self::AccessDenied,
        Self::Unavailable,
        Self::PeerDenied,
        Self::InvalidRequest,
        Self::BindingDenied,
        Self::TimeDenied,
        Self::SignatureDenied,
        Self::RegistryUnavailable,
        Self::PreconditionChanged,
        Self::ReplayDenied,
        Self::Busy,
        Self::ClockRollback,
        Self::Capacity,
        Self::StateExists,
        Self::IdentityMismatch,
        Self::NotAdmitted,
        Self::CompensationDenied,
        Self::Collision,
        Self::StepFailed,
        Self::Drift,
        Self::ArtifactUnavailable,
        Self::ProbeFailed,
        Self::JournalRollback,
        Self::HelperUnreachable,
        Self::RetentionUnverified,
        Self::GenerationCurrent,
        Self::QuotaUnavailable,
        Self::NotEnrolled,
        Self::ReadoptMismatch,
        Self::WindowClosed,
        Self::RunMismatch,
    ];

    /// The error whose stable code is `code`.
    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|error| error.code() == code)
    }
}

impl std::fmt::Display for ExecutorError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str(self.code())
    }
}

impl std::error::Error for ExecutorError {}

impl From<ApprovalError> for ExecutorError {
    fn from(error: ApprovalError) -> Self {
        match error {
            ApprovalError::OutsideValidity | ApprovalError::ClockUncertain => Self::TimeDenied,
            ApprovalError::BindingMismatch => Self::BindingDenied,
            _ => Self::InvalidRequest,
        }
    }
}

impl From<JournalError> for ExecutorError {
    fn from(error: JournalError) -> Self {
        match error {
            JournalError::Unavailable => Self::Unavailable,
            JournalError::AccessDenied => Self::AccessDenied,
            JournalError::Conflict => Self::ReplayDenied,
            JournalError::Busy => Self::Busy,
            JournalError::ClockRollback => Self::ClockRollback,
            JournalError::Expired => Self::TimeDenied,
            JournalError::Capacity => Self::Capacity,
            JournalError::Consumed | JournalError::SourceChanged => Self::PreconditionChanged,
        }
    }
}

/// Fixed trusted locations and their owner. The lab binary must construct this
/// from compiled constants with `owner_uid` 0; it is never request data.
#[derive(Clone)]
pub struct TrustAnchor {
    /// Owner of every trusted directory and file (root for the lab executor).
    pub owner_uid: u32,
    /// Root-admin policy directory (`policy.json`, `allowed_signers`, `revocations`).
    pub policy_dir: PathBuf,
    /// Fixture registry root.
    pub registry_dir: PathBuf,
    /// Private scratch directory for verifier inputs.
    pub scratch_dir: PathBuf,
    /// Canonical owner-only directory holding the executor's own journal.
    pub journal_dir: PathBuf,
    /// Owner-only directory outside `journal_dir` holding the admission
    /// high-water mark, so restoring the journal directory leaves it behind.
    pub mark_dir: PathBuf,
    /// Root-owned store of pinned provisioning recipes.
    pub recipes_dir: PathBuf,
    /// Administration helper socket. When set, routed provision steps go
    /// through the helper instead of running in the executor process.
    pub admin_socket: Option<PathBuf>,
}

impl TrustAnchor {
    /// Fixed lab locations; no helper socket.
    pub fn lab() -> Self {
        use layout::lab;
        Self {
            owner_uid: 0,
            policy_dir: PathBuf::from(lab::POLICY_DIR),
            registry_dir: PathBuf::from(lab::FIXTURE_REGISTRY_DIR.unwrap_or_default()),
            scratch_dir: PathBuf::from(lab::SCRATCH_DIR),
            journal_dir: PathBuf::from(lab::JOURNAL_DIR),
            mark_dir: PathBuf::from(lab::MARK_DIR),
            recipes_dir: PathBuf::from(lab::RECIPES_DIR),
            admin_socket: None,
        }
    }

    /// The compiled profile's locations; no helper socket. In the product
    /// profile the fixture registry is the empty path, which no trusted
    /// open accepts, and [`verified_intent`] refuses the fixture verb first.
    pub fn host() -> Self {
        Self {
            owner_uid: 0,
            policy_dir: PathBuf::from(layout::POLICY_DIR),
            registry_dir: PathBuf::from(layout::FIXTURE_REGISTRY_DIR.unwrap_or_default()),
            scratch_dir: PathBuf::from(layout::SCRATCH_DIR),
            journal_dir: PathBuf::from(layout::JOURNAL_DIR),
            mark_dir: PathBuf::from(layout::MARK_DIR),
            recipes_dir: PathBuf::from(layout::RECIPES_DIR),
            admin_socket: None,
        }
    }
}

/// One submission. Everything here is untrusted except `peer_uid`, which the
/// caller must take from kernel socket credentials, and `now`.
pub struct AdmissionRequest<'a> {
    /// Kernel-reported peer UID of the submitting connection.
    pub peer_uid: u32,
    /// Submitted plan bytes.
    pub plan: &'a [u8],
    /// Submitted grant bytes; only their canonical form is verified.
    pub grant: &'a [u8],
    /// Detached SSHSIG over the canonical grant bytes.
    pub signature: &'a [u8],
    /// Requested operation identity.
    pub operation_id: Id,
    /// Requested retry key; the journal binds it to every intent field.
    pub idempotency_key: Id,
    /// Reliable current time; `None` denies new work.
    pub now: Option<Timestamp>,
}

/// Runs every pre-journal check in a fixed order and returns the bound intent.
pub fn admit(
    anchor: &TrustAnchor,
    request: &AdmissionRequest<'_>,
) -> Result<Intent, ExecutorError> {
    let intent = verified_intent(anchor, request)?;
    check_live(anchor, &intent)?;
    Ok(intent)
}

/// Every check except the live registry; the predecessor fields hold the plan's
/// reported values, which [`check_live`] must confirm before any new record.
pub(crate) fn verified_intent(
    anchor: &TrustAnchor,
    request: &AdmissionRequest<'_>,
) -> Result<Intent, ExecutorError> {
    // The fixture switch is a lab path, not a catalogue verb (SPEC). A
    // profile without a fixture registry refuses it before any state is read.
    if layout::FIXTURE_REGISTRY_DIR.is_none() {
        return Err(ExecutorError::InvalidRequest);
    }
    let owner = anchor.owner_uid;
    let loaded = policy::load(
        &files::open_trusted_directory(&anchor.policy_dir, owner)?,
        owner,
    )?;
    let enrolled = &loaded.policy;
    if request.peer_uid != enrolled.requester_uid {
        return Err(ExecutorError::PeerDenied);
    }
    if request.plan.len() > MAX_REQUEST_BYTES
        || request.grant.len() > MAX_REQUEST_BYTES
        || request.signature.len() > MAX_SIGNATURE_BYTES
    {
        return Err(ExecutorError::InvalidRequest);
    }
    let plan = FixturePlan::decode(request.plan)?;
    let grant = FixtureGrant::decode(request.grant)?;
    check_fixture_binding(
        &plan,
        &grant,
        &FixtureBindingContext {
            host_id: &enrolled.host_id,
            host_epoch: &enrolled.host_epoch,
            profile_digest: &enrolled.profile_digest,
            requester: &enrolled.requester,
            issuer: &enrolled.issuer,
            signer_policy_epoch: &enrolled.signer_policy_epoch,
            now: request.now,
        },
    )?;
    let scratch = files::open_trusted_directory(&anchor.scratch_dir, owner)?;
    signature::verify(
        grant.as_bytes(),
        request.signature,
        &loaded,
        &anchor.scratch_dir,
        &scratch,
    )?;
    let activation = plan.activation();
    Ok(Intent {
        operation_id: request.operation_id.clone(),
        idempotency_key: request.idempotency_key.clone(),
        grant_id: grant.grant_id().clone(),
        nonce: grant.nonce().clone(),
        plan_digest: plan.digest(),
        grant_digest: Sha256Digest::from_bytes(Sha256::digest(grant.as_bytes()).into()),
        host_id: enrolled.host_id.clone(),
        host_epoch: enrolled.host_epoch.clone(),
        resource_id: activation.resource_id.clone(),
        predecessor_generation: activation.expected_generation.clone(),
        predecessor_digest: activation.expected_digest.clone(),
        target_generation: activation.target_generation.clone(),
        target_digest: activation.target_digest.clone(),
        expires_at: grant.expires_at(),
        compensation_valid_until: grant.compensation_valid_until(),
    })
}

/// A verified `site_provision`: the journal intent, the enrolled provisioning
/// policy, the recipe and the signed v2 quota limits (`None` for a v1 plan).
pub(crate) struct VerifiedSite {
    pub intent: ProvisionIntent,
    pub enrolled: policy::ProvisioningPolicy,
    pub recipe: SiteRecipe,
    pub quota_limits: Option<quota::QuotaLimits>,
}

/// Every `site_provision` admission check: enrolled policy and peer, closed
/// plan/grant binding (including the enrolled recipe digest and, for a v2
/// plan, signed quota limits at most the enrolled quota), time and SSHSIG.
/// The product profile requires a v2 plan (W341) and the install recipe (W399).
pub(crate) fn verified_site(
    anchor: &TrustAnchor,
    request: &AdmissionRequest<'_>,
) -> Result<VerifiedSite, ExecutorError> {
    let owner = anchor.owner_uid;
    let loaded = policy::load(
        &files::open_trusted_directory(&anchor.policy_dir, owner)?,
        owner,
    )?;
    let enrolled = &loaded.policy;
    if request.peer_uid != enrolled.requester_uid {
        return Err(ExecutorError::PeerDenied);
    }
    let provisioning = enrolled
        .provisioning
        .clone()
        .ok_or(ExecutorError::Unavailable)?;
    if request.plan.len() > MAX_REQUEST_BYTES
        || request.grant.len() > MAX_REQUEST_BYTES
        || request.signature.len() > MAX_SIGNATURE_BYTES
    {
        return Err(ExecutorError::InvalidRequest);
    }
    let plan = SitePlan::decode(request.plan)?;
    let grant = SiteGrant::decode(request.grant)?;
    // The product profile enrolls a quota (policy::ProvisioningPolicy::valid)
    // and takes the limits only from the signed plan.
    if cfg!(rustiron_profile = "product") && plan.quota_limits().is_none() {
        return Err(ExecutorError::BindingDenied);
    }
    // W399 (D-047): the product profile admits only the install recipe. The
    // unpack-only recipe leaves the site at the WordPress installer, where
    // the first visitor would set the administrator login.
    if cfg!(rustiron_profile = "product") && plan.recipe().0 != SiteRecipe::Wordpress713InstallV1 {
        return Err(ExecutorError::BindingDenied);
    }
    let quota_cap = match provisioning.quota {
        Some(limits) => Some(limits.cap().ok_or(ExecutorError::Unavailable)?),
        None => None,
    };
    check_site_binding(
        &plan,
        &grant,
        &SiteBindingContext {
            host_id: &enrolled.host_id,
            host_epoch: &enrolled.host_epoch,
            profile_digest: &enrolled.profile_digest,
            requester: &enrolled.requester,
            issuer: &enrolled.issuer,
            signer_policy_epoch: &enrolled.signer_policy_epoch,
            wordpress_713_digest: &provisioning.wordpress_713_sha256,
            now: request.now,
            quota_cap,
        },
    )?;
    let scratch = files::open_trusted_directory(&anchor.scratch_dir, owner)?;
    signature::verify(
        grant.as_bytes(),
        request.signature,
        &loaded,
        &anchor.scratch_dir,
        &scratch,
    )?;
    Ok(VerifiedSite {
        intent: ProvisionIntent {
            operation_id: request.operation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            grant_id: grant.grant_id().clone(),
            nonce: grant.nonce().clone(),
            plan_digest: plan.digest(),
            grant_digest: Sha256Digest::from_bytes(Sha256::digest(grant.as_bytes()).into()),
            host_id: enrolled.host_id.clone(),
            host_epoch: enrolled.host_epoch.clone(),
            site_id: plan.site_id().clone(),
            hostname: plan.hostname().clone(),
            expires_at: grant.expires_at(),
        },
        enrolled: provisioning,
        recipe: plan.recipe().0,
        quota_limits: plan.quota_limits().map(quota::QuotaLimits::from),
    })
}

/// W572 (D-095): a verified `proxy_site_provision`: the journal intent,
/// the enrolled provisioning policy, and the signed routes.
pub(crate) struct VerifiedProxy {
    pub intent: ProvisionIntent,
    pub enrolled: policy::ProvisioningPolicy,
    pub facts: rustiron_journal::ProxyFacts,
}

/// Every `proxy_site_provision` admission check: enrolled policy and peer,
/// the provisioning and OLS enrollments, closed plan/grant binding, no
/// route to a port the host serves or reserves (the enrolled OLS listener,
/// TLS listener and WebAdmin ports, and the enrolled SSH port), time and
/// SSHSIG. Nothing is read from a port here.
pub(crate) fn verified_proxy(
    anchor: &TrustAnchor,
    request: &AdmissionRequest<'_>,
) -> Result<VerifiedProxy, ExecutorError> {
    let owner = anchor.owner_uid;
    let loaded = policy::load(
        &files::open_trusted_directory(&anchor.policy_dir, owner)?,
        owner,
    )?;
    let enrolled = &loaded.policy;
    if request.peer_uid != enrolled.requester_uid {
        return Err(ExecutorError::PeerDenied);
    }
    let provisioning = enrolled
        .provisioning
        .clone()
        .ok_or(ExecutorError::Unavailable)?;
    let ols = enrolled.ols.as_ref().ok_or(ExecutorError::Unavailable)?;
    if request.plan.len() > MAX_REQUEST_BYTES
        || request.grant.len() > MAX_REQUEST_BYTES
        || request.signature.len() > MAX_SIGNATURE_BYTES
    {
        return Err(ExecutorError::InvalidRequest);
    }
    let plan = rustiron_contracts::approval::ProxyPlan::decode(request.plan)?;
    let grant = rustiron_contracts::approval::ProxyGrant::decode(request.grant)?;
    rustiron_contracts::approval::check_proxy_binding(
        &plan,
        &grant,
        &rustiron_contracts::approval::ProxyBindingContext {
            host_id: &enrolled.host_id,
            host_epoch: &enrolled.host_epoch,
            profile_digest: &enrolled.profile_digest,
            requester: &enrolled.requester,
            issuer: &enrolled.issuer,
            signer_policy_epoch: &enrolled.signer_policy_epoch,
            now: request.now,
        },
    )?;
    let mut reserved = ols.reserved_ports()?;
    reserved.extend(enrolled.firewall.as_ref().map(|firewall| firewall.ssh_port));
    if !proxy_site::ports_free(&reserved, &plan.ports()) {
        return Err(ExecutorError::BindingDenied);
    }
    let scratch = files::open_trusted_directory(&anchor.scratch_dir, owner)?;
    signature::verify(
        grant.as_bytes(),
        request.signature,
        &loaded,
        &anchor.scratch_dir,
        &scratch,
    )?;
    Ok(VerifiedProxy {
        intent: ProvisionIntent {
            operation_id: request.operation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            grant_id: grant.grant_id().clone(),
            nonce: grant.nonce().clone(),
            plan_digest: plan.digest(),
            grant_digest: Sha256Digest::from_bytes(Sha256::digest(grant.as_bytes()).into()),
            host_id: enrolled.host_id.clone(),
            host_epoch: enrolled.host_epoch.clone(),
            site_id: plan.site_id().clone(),
            hostname: plan.hostname().clone(),
            expires_at: grant.expires_at(),
        },
        enrolled: provisioning,
        facts: rustiron_journal::ProxyFacts {
            routes: plan.routes().to_vec(),
            websockets: plan.websockets().to_vec(),
        },
    })
}

/// W598 (D-099) & W659 (D-102): a verified `app_provision`.
pub(crate) struct VerifiedAppProvision {
    pub intent: ProvisionIntent,
    pub enrolled: policy::ProvisioningPolicy,
    pub facts: rustiron_journal::AppFacts,
    pub fullstack: Option<rustiron_journal::AppFullstackSpec>,
}

/// W659 (D-102): a verified `app_deploy` (v1 or v2 with optional blue/green cutover).
pub(crate) struct VerifiedAppDeploy {
    pub intent: rustiron_journal::AppReleaseIntent,
    pub blue_green_cutover: bool,
}

/// Every `app_provision` admission check: enrolled policy, peer, provisioning
/// and ingress enrollments, closed plan/grant binding, reserved ports, time, and SSHSIG.
pub(crate) fn verified_app_provision(
    anchor: &TrustAnchor,
    request: &AdmissionRequest<'_>,
) -> Result<VerifiedAppProvision, ExecutorError> {
    let owner = anchor.owner_uid;
    let loaded = policy::load(
        &files::open_trusted_directory(&anchor.policy_dir, owner)?,
        owner,
    )?;
    let enrolled = &loaded.policy;
    if request.peer_uid != enrolled.requester_uid {
        return Err(ExecutorError::PeerDenied);
    }
    let provisioning = enrolled
        .provisioning
        .clone()
        .ok_or(ExecutorError::Unavailable)?;
    let ols = enrolled.ols.as_ref().ok_or(ExecutorError::Unavailable)?;
    if request.plan.len() > MAX_REQUEST_BYTES
        || request.grant.len() > MAX_REQUEST_BYTES
        || request.signature.len() > MAX_SIGNATURE_BYTES
    {
        return Err(ExecutorError::InvalidRequest);
    }
    let plan = rustiron_contracts::approval::AppProvisionPlan::decode(request.plan)?;
    if plan.ingress() == rustiron_contracts::approval::IngressEngine::Caddy
        && enrolled.caddy.is_none()
    {
        return Err(ExecutorError::Unavailable);
    }
    let grant = rustiron_contracts::approval::AppProvisionGrant::decode(request.grant)?;
    rustiron_contracts::approval::check_app_provision_binding(
        &plan,
        &grant,
        &rustiron_contracts::approval::AppBindingContext {
            host_id: &enrolled.host_id,
            host_epoch: &enrolled.host_epoch,
            profile_digest: &enrolled.profile_digest,
            requester: &enrolled.requester,
            issuer: &enrolled.issuer,
            signer_policy_epoch: &enrolled.signer_policy_epoch,
            now: request.now,
        },
    )?;
    let mut reserved = ols.reserved_ports()?;
    reserved.extend(enrolled.firewall.as_ref().map(|firewall| firewall.ssh_port));
    if let Some(caddy) = &enrolled.caddy {
        reserved.push(caddy::CADDY_ADMIN_PORT);
        if let Ok(addr) = caddy.http_address.parse::<std::net::SocketAddr>() {
            reserved.push(addr.port());
        }
        if let Ok(addr) = caddy.https_address.parse::<std::net::SocketAddr>() {
            reserved.push(addr.port());
        }
        if let Some(ols_up) = &caddy.ols_upstream
            && let Ok(addr) = ols_up.parse::<std::net::SocketAddr>()
        {
            reserved.push(addr.port());
        }
    }
    let plan_ports = plan.all_ports();
    if !plan_ports.is_empty() && !proxy_site::ports_free(&reserved, &plan_ports) {
        return Err(ExecutorError::BindingDenied);
    }
    let scratch = files::open_trusted_directory(&anchor.scratch_dir, owner)?;
    signature::verify(
        grant.as_bytes(),
        request.signature,
        &loaded,
        &anchor.scratch_dir,
        &scratch,
    )?;
    let fullstack = (plan.schema_version() == 2).then(|| rustiron_journal::AppFullstackSpec {
        ingress: plan.ingress(),
        topology: plan.topology(),
        database: plan.database(),
        blue_green: plan.blue_green(),
        active_slot: rustiron_journal::AppSlot::A,
        standby_port: plan.standby_port(),
        spa_fallback: plan.spa_fallback(),
        frontend_dir: plan.frontend_dir().map(str::to_owned),
        frontend_runtime: plan.frontend_runtime(),
        frontend_entrypoint: plan.frontend_entrypoint().map(str::to_owned),
        frontend_port: plan.frontend_port(),
        frontend_standby_port: plan.frontend_standby_port(),
        sse_prefixes: plan.sse_prefixes().to_vec(),
        strip_api_prefixes: plan.strip_api_prefixes().to_vec(),
    });
    Ok(VerifiedAppProvision {
        intent: ProvisionIntent {
            operation_id: request.operation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            grant_id: grant.grant_id().clone(),
            nonce: grant.nonce().clone(),
            plan_digest: plan.digest(),
            grant_digest: Sha256Digest::from_bytes(Sha256::digest(grant.as_bytes()).into()),
            host_id: enrolled.host_id.clone(),
            host_epoch: enrolled.host_epoch.clone(),
            site_id: plan.site_id().clone(),
            hostname: plan.hostname().clone(),
            expires_at: grant.expires_at(),
        },
        enrolled: provisioning,
        facts: rustiron_journal::AppFacts {
            runtime: plan.runtime(),
            port: plan.port(),
            entrypoint: plan.entrypoint().to_owned(),
            worker_entrypoint: plan.worker_entrypoint().map(str::to_owned),
            health_path: plan.health_path().to_owned(),
            env_keys: plan.env_keys().to_vec(),
            memory_max_mib: plan.memory_max_mib(),
            tasks_max: plan.tasks_max(),
            quota_mib: plan.quota_mib(),
            routes: rustiron_journal::ProxyFacts {
                routes: plan.routes().to_vec(),
                websockets: plan.websockets().to_vec(),
            },
        },
        fullstack,
    })
}

/// Every `app_deploy` admission check: enrolled policy, peer, closed plan/grant
/// binding, time, and SSHSIG.
pub(crate) fn verified_app_deploy(
    anchor: &TrustAnchor,
    request: &AdmissionRequest<'_>,
) -> Result<VerifiedAppDeploy, ExecutorError> {
    let owner = anchor.owner_uid;
    let loaded = policy::load(
        &files::open_trusted_directory(&anchor.policy_dir, owner)?,
        owner,
    )?;
    let enrolled = &loaded.policy;
    if request.peer_uid != enrolled.requester_uid {
        return Err(ExecutorError::PeerDenied);
    }
    if request.plan.len() > MAX_REQUEST_BYTES
        || request.grant.len() > MAX_REQUEST_BYTES
        || request.signature.len() > MAX_SIGNATURE_BYTES
    {
        return Err(ExecutorError::InvalidRequest);
    }
    let plan = rustiron_contracts::approval::AppDeployPlan::decode(request.plan)?;
    let grant = rustiron_contracts::approval::AppDeployGrant::decode(request.grant)?;
    rustiron_contracts::approval::check_app_deploy_binding(
        &plan,
        &grant,
        &rustiron_contracts::approval::AppBindingContext {
            host_id: &enrolled.host_id,
            host_epoch: &enrolled.host_epoch,
            profile_digest: &enrolled.profile_digest,
            requester: &enrolled.requester,
            issuer: &enrolled.issuer,
            signer_policy_epoch: &enrolled.signer_policy_epoch,
            now: request.now,
        },
    )?;
    let scratch = files::open_trusted_directory(&anchor.scratch_dir, owner)?;
    signature::verify(
        grant.as_bytes(),
        request.signature,
        &loaded,
        &anchor.scratch_dir,
        &scratch,
    )?;
    Ok(VerifiedAppDeploy {
        intent: rustiron_journal::AppReleaseIntent {
            operation_id: request.operation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            grant_id: grant.grant_id().clone(),
            nonce: grant.nonce().clone(),
            plan_digest: plan.digest(),
            grant_digest: Sha256Digest::from_bytes(Sha256::digest(grant.as_bytes()).into()),
            host_id: enrolled.host_id.clone(),
            host_epoch: enrolled.host_epoch.clone(),
            site_id: plan.site_id().clone(),
            release_id: plan.release_id().to_owned(),
            runtime: plan.runtime(),
            artifact_sha256: plan.artifact_sha256().clone(),
            manifest_sha256: plan.manifest_sha256().clone(),
            file_count: plan.file_count(),
            total_bytes: plan.total_bytes(),
            migration_entrypoint: plan.migration_entrypoint().map(str::to_owned),
            capture_operation_id: plan.capture_operation_id().cloned(),
            health_path: plan.health_path().to_owned(),
            expires_at: grant.expires_at(),
        },
        blue_green_cutover: plan.blue_green_cutover(),
    })
}

/// Every `app_lifecycle` admission check: enrolled policy, peer, closed
/// plan/grant binding, time, and SSHSIG.
pub(crate) fn verified_app_lifecycle(
    anchor: &TrustAnchor,
    request: &AdmissionRequest<'_>,
) -> Result<rustiron_journal::AppLifecycleIntent, ExecutorError> {
    let owner = anchor.owner_uid;
    let loaded = policy::load(
        &files::open_trusted_directory(&anchor.policy_dir, owner)?,
        owner,
    )?;
    let enrolled = &loaded.policy;
    if request.peer_uid != enrolled.requester_uid {
        return Err(ExecutorError::PeerDenied);
    }
    if request.plan.len() > MAX_REQUEST_BYTES
        || request.grant.len() > MAX_REQUEST_BYTES
        || request.signature.len() > MAX_SIGNATURE_BYTES
    {
        return Err(ExecutorError::InvalidRequest);
    }
    let plan = rustiron_contracts::approval::AppLifecyclePlan::decode(request.plan)?;
    let grant = rustiron_contracts::approval::AppLifecycleGrant::decode(request.grant)?;
    rustiron_contracts::approval::check_app_lifecycle_binding(
        &plan,
        &grant,
        &rustiron_contracts::approval::AppBindingContext {
            host_id: &enrolled.host_id,
            host_epoch: &enrolled.host_epoch,
            profile_digest: &enrolled.profile_digest,
            requester: &enrolled.requester,
            issuer: &enrolled.issuer,
            signer_policy_epoch: &enrolled.signer_policy_epoch,
            now: request.now,
        },
    )?;
    let scratch = files::open_trusted_directory(&anchor.scratch_dir, owner)?;
    signature::verify(
        grant.as_bytes(),
        request.signature,
        &loaded,
        &anchor.scratch_dir,
        &scratch,
    )?;
    Ok(rustiron_journal::AppLifecycleIntent {
        operation_id: request.operation_id.clone(),
        idempotency_key: request.idempotency_key.clone(),
        grant_id: grant.grant_id().clone(),
        nonce: grant.nonce().clone(),
        plan_digest: plan.digest(),
        grant_digest: Sha256Digest::from_bytes(Sha256::digest(grant.as_bytes()).into()),
        host_id: enrolled.host_id.clone(),
        host_epoch: enrolled.host_epoch.clone(),
        site_id: plan.site_id().clone(),
        action: plan.action(),
        expires_at: grant.expires_at(),
    })
}

/// W441 (D-053): a verified `site_import`. The intent is the provisioning
/// intent of its first step; the other fields are the signed dry-run facts
/// that the import steps recheck against what they observe.
pub(crate) struct VerifiedImport {
    pub intent: ProvisionIntent,
    pub enrolled: policy::ProvisioningPolicy,
    pub quota_limits: quota::QuotaLimits,
    pub archive_sha256: Sha256Digest,
    pub manifest_sha256: Sha256Digest,
    pub file_entries: u64,
    pub file_bytes: u64,
    pub dump_bytes: u64,
    pub target_php: rustiron_contracts::migration::PhpVersion,
    /// D-070: the signed source hostname of a renamed import.
    pub source_hostname: Option<rustiron_contracts::approval::Hostname>,
    pub alias_hostname: Option<rustiron_contracts::approval::Hostname>,
}

/// Every `site_import` admission check: enrolled policy and peer, both the
/// provisioning and the migration enrollment, closed plan/grant binding
/// (signed limits at most the enrolled quota, an enrolled LSPHP version),
/// time and SSHSIG. Nothing is read from the intake or the host here.
pub(crate) fn verified_import(
    anchor: &TrustAnchor,
    request: &AdmissionRequest<'_>,
) -> Result<VerifiedImport, ExecutorError> {
    let owner = anchor.owner_uid;
    let loaded = policy::load(
        &files::open_trusted_directory(&anchor.policy_dir, owner)?,
        owner,
    )?;
    let enrolled = &loaded.policy;
    if request.peer_uid != enrolled.requester_uid {
        return Err(ExecutorError::PeerDenied);
    }
    let (Some(provisioning), Some(migration)) =
        (enrolled.provisioning.clone(), enrolled.migration.as_ref())
    else {
        return Err(ExecutorError::Unavailable);
    };
    if request.plan.len() > MAX_REQUEST_BYTES
        || request.grant.len() > MAX_REQUEST_BYTES
        || request.signature.len() > MAX_SIGNATURE_BYTES
    {
        return Err(ExecutorError::InvalidRequest);
    }
    let plan = ImportPlan::decode(request.plan)?;
    let grant = ImportGrant::decode(request.grant)?;
    let quota_cap = match provisioning.quota {
        Some(limits) => Some(limits.cap().ok_or(ExecutorError::Unavailable)?),
        None => None,
    };
    check_import_binding(
        &plan,
        &grant,
        &ImportBindingContext {
            host_id: &enrolled.host_id,
            host_epoch: &enrolled.host_epoch,
            profile_digest: &enrolled.profile_digest,
            requester: &enrolled.requester,
            issuer: &enrolled.issuer,
            signer_policy_epoch: &enrolled.signer_policy_epoch,
            php_versions: &migration.php_versions,
            now: request.now,
            quota_cap,
        },
    )?;
    let scratch = files::open_trusted_directory(&anchor.scratch_dir, owner)?;
    signature::verify(
        grant.as_bytes(),
        request.signature,
        &loaded,
        &anchor.scratch_dir,
        &scratch,
    )?;
    if let Some(alias) = plan.alias_hostname() {
        let ols = enrolled
            .ols
            .as_ref()
            .filter(|ols| migration.static_alias_http && ols.http_is_loopback())
            .ok_or(ExecutorError::Unavailable)?;
        if ols
            .adopted
            .iter()
            .any(|site| &site.hostname == alias || &site.hostname == plan.hostname())
        {
            return Err(ExecutorError::PreconditionChanged);
        }
    }
    Ok(VerifiedImport {
        intent: ProvisionIntent {
            operation_id: request.operation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            grant_id: grant.grant_id().clone(),
            nonce: grant.nonce().clone(),
            plan_digest: plan.digest(),
            grant_digest: Sha256Digest::from_bytes(Sha256::digest(grant.as_bytes()).into()),
            host_id: enrolled.host_id.clone(),
            host_epoch: enrolled.host_epoch.clone(),
            site_id: plan.site_id().clone(),
            hostname: plan.hostname().clone(),
            expires_at: grant.expires_at(),
        },
        enrolled: provisioning,
        quota_limits: plan.quota_limits().into(),
        archive_sha256: plan.archive_sha256().clone(),
        manifest_sha256: plan.manifest_sha256().clone(),
        file_entries: plan.file_entries(),
        file_bytes: plan.file_bytes(),
        dump_bytes: plan.dump_bytes(),
        target_php: plan.target_php().clone(),
        source_hostname: plan.source_hostname().cloned(),
        alias_hostname: plan.alias_hostname().cloned(),
    })
}

/// W462 (D-059): every signed `certificate_issue` admission check: enrolled
/// policy and peer, the ACME and OLS TLS enrollment, closed plan/grant
/// binding, time and SSHSIG. The journal then checks the site and hostname.
pub(crate) fn verified_certificate(
    anchor: &TrustAnchor,
    request: &AdmissionRequest<'_>,
) -> Result<rustiron_journal::CertificateIntent, ExecutorError> {
    let owner = anchor.owner_uid;
    let loaded = policy::load(
        &files::open_trusted_directory(&anchor.policy_dir, owner)?,
        owner,
    )?;
    let enrolled = &loaded.policy;
    if request.peer_uid != enrolled.requester_uid {
        return Err(ExecutorError::PeerDenied);
    }
    let tls_enrolled = enrolled
        .ols
        .as_ref()
        .is_some_and(|ols| ols.tls_address.is_some());
    if enrolled.acme.is_none() || !tls_enrolled {
        return Err(ExecutorError::Unavailable);
    }
    if request.plan.len() > MAX_REQUEST_BYTES
        || request.grant.len() > MAX_REQUEST_BYTES
        || request.signature.len() > MAX_SIGNATURE_BYTES
    {
        return Err(ExecutorError::InvalidRequest);
    }
    let plan = CertificatePlan::decode(request.plan)?;
    let grant = CertificateGrant::decode(request.grant)?;
    check_certificate_binding(
        &plan,
        &grant,
        &CertificateBindingContext {
            host_id: &enrolled.host_id,
            host_epoch: &enrolled.host_epoch,
            profile_digest: &enrolled.profile_digest,
            requester: &enrolled.requester,
            issuer: &enrolled.issuer,
            signer_policy_epoch: &enrolled.signer_policy_epoch,
            now: request.now,
        },
    )?;
    let scratch = files::open_trusted_directory(&anchor.scratch_dir, owner)?;
    signature::verify(
        grant.as_bytes(),
        request.signature,
        &loaded,
        &anchor.scratch_dir,
        &scratch,
    )?;
    if plan.alias_hostname().is_some() && !enrolled.alias_certificate_enabled() {
        return Err(ExecutorError::Unavailable);
    }
    Ok(rustiron_journal::CertificateIntent {
        operation_id: request.operation_id.clone(),
        idempotency_key: request.idempotency_key.clone(),
        grant_id: grant.grant_id().clone(),
        nonce: grant.nonce().clone(),
        plan_digest: plan.digest(),
        grant_digest: Sha256Digest::from_bytes(Sha256::digest(grant.as_bytes()).into()),
        host_id: enrolled.host_id.clone(),
        host_epoch: enrolled.host_epoch.clone(),
        site_id: plan.site_id().clone(),
        hostname: plan.hostname().clone(),
        alias_hostname: plan.alias_hostname().cloned(),
        expires_at: grant.expires_at(),
        renew_until: plan.renew_until(),
    })
}

/// W459 (D-057): every signed `import_scrub` admission check: enrolled
/// policy and peer, the migration enrollment, closed plan/grant binding,
/// time and SSHSIG. The journal then checks the import itself.
pub(crate) fn verified_scrub(
    anchor: &TrustAnchor,
    request: &AdmissionRequest<'_>,
) -> Result<rustiron_journal::ScrubIntent, ExecutorError> {
    let owner = anchor.owner_uid;
    let loaded = policy::load(
        &files::open_trusted_directory(&anchor.policy_dir, owner)?,
        owner,
    )?;
    let enrolled = &loaded.policy;
    if request.peer_uid != enrolled.requester_uid {
        return Err(ExecutorError::PeerDenied);
    }
    if enrolled.migration.is_none() {
        return Err(ExecutorError::Unavailable);
    }
    if request.plan.len() > MAX_REQUEST_BYTES
        || request.grant.len() > MAX_REQUEST_BYTES
        || request.signature.len() > MAX_SIGNATURE_BYTES
    {
        return Err(ExecutorError::InvalidRequest);
    }
    let plan = ScrubPlan::decode(request.plan)?;
    let grant = ScrubGrant::decode(request.grant)?;
    check_scrub_binding(
        &plan,
        &grant,
        &ScrubBindingContext {
            host_id: &enrolled.host_id,
            host_epoch: &enrolled.host_epoch,
            profile_digest: &enrolled.profile_digest,
            requester: &enrolled.requester,
            issuer: &enrolled.issuer,
            signer_policy_epoch: &enrolled.signer_policy_epoch,
            now: request.now,
        },
    )?;
    let scratch = files::open_trusted_directory(&anchor.scratch_dir, owner)?;
    signature::verify(
        grant.as_bytes(),
        request.signature,
        &loaded,
        &anchor.scratch_dir,
        &scratch,
    )?;
    Ok(rustiron_journal::ScrubIntent {
        operation_id: request.operation_id.clone(),
        idempotency_key: request.idempotency_key.clone(),
        grant_id: grant.grant_id().clone(),
        nonce: grant.nonce().clone(),
        plan_digest: plan.digest(),
        grant_digest: Sha256Digest::from_bytes(Sha256::digest(grant.as_bytes()).into()),
        host_id: enrolled.host_id.clone(),
        host_epoch: enrolled.host_epoch.clone(),
        import_operation_id: plan.import_operation_id().clone(),
        site_id: plan.site_id().clone(),
        archive_sha256: plan.archive_sha256().clone(),
        expires_at: grant.expires_at(),
    })
}

/// W508 (D-080): the verified signed retirement of a quarantined site.
pub(crate) fn verified_retire(
    anchor: &TrustAnchor,
    request: &AdmissionRequest<'_>,
) -> Result<rustiron_journal::RetireIntent, ExecutorError> {
    let owner = anchor.owner_uid;
    let loaded = policy::load(
        &files::open_trusted_directory(&anchor.policy_dir, owner)?,
        owner,
    )?;
    let enrolled = &loaded.policy;
    if request.peer_uid != enrolled.requester_uid {
        return Err(ExecutorError::PeerDenied);
    }
    if enrolled.provisioning.is_none() {
        return Err(ExecutorError::Unavailable);
    }
    if request.plan.len() > MAX_REQUEST_BYTES
        || request.grant.len() > MAX_REQUEST_BYTES
        || request.signature.len() > MAX_SIGNATURE_BYTES
    {
        return Err(ExecutorError::InvalidRequest);
    }
    let plan = rustiron_contracts::approval::RetirePlan::decode(request.plan)?;
    let grant = rustiron_contracts::approval::RetireGrant::decode(request.grant)?;
    rustiron_contracts::approval::check_retire_binding(
        &plan,
        &grant,
        &rustiron_contracts::approval::RetireBindingContext {
            host_id: &enrolled.host_id,
            host_epoch: &enrolled.host_epoch,
            profile_digest: &enrolled.profile_digest,
            requester: &enrolled.requester,
            issuer: &enrolled.issuer,
            signer_policy_epoch: &enrolled.signer_policy_epoch,
            now: request.now,
        },
    )?;
    let scratch = files::open_trusted_directory(&anchor.scratch_dir, owner)?;
    signature::verify(
        grant.as_bytes(),
        request.signature,
        &loaded,
        &anchor.scratch_dir,
        &scratch,
    )?;
    Ok(rustiron_journal::RetireIntent {
        operation_id: request.operation_id.clone(),
        idempotency_key: request.idempotency_key.clone(),
        grant_id: grant.grant_id().clone(),
        nonce: grant.nonce().clone(),
        plan_digest: plan.digest(),
        grant_digest: Sha256Digest::from_bytes(Sha256::digest(grant.as_bytes()).into()),
        host_id: enrolled.host_id.clone(),
        host_epoch: enrolled.host_epoch.clone(),
        provision_operation_id: plan.provision_operation_id().clone(),
        site_id: plan.site_id().clone(),
        expires_at: grant.expires_at(),
    })
}

/// W522 (D-085): the verified signed deletion of a live site.
pub(crate) fn verified_delete(
    anchor: &TrustAnchor,
    request: &AdmissionRequest<'_>,
) -> Result<rustiron_journal::DeleteIntent, ExecutorError> {
    let owner = anchor.owner_uid;
    let loaded = policy::load(
        &files::open_trusted_directory(&anchor.policy_dir, owner)?,
        owner,
    )?;
    let enrolled = &loaded.policy;
    if request.peer_uid != enrolled.requester_uid {
        return Err(ExecutorError::PeerDenied);
    }
    if enrolled.provisioning.is_none() {
        return Err(ExecutorError::Unavailable);
    }
    if request.plan.len() > MAX_REQUEST_BYTES
        || request.grant.len() > MAX_REQUEST_BYTES
        || request.signature.len() > MAX_SIGNATURE_BYTES
    {
        return Err(ExecutorError::InvalidRequest);
    }
    let plan = rustiron_contracts::approval::DeletePlan::decode(request.plan)?;
    let grant = rustiron_contracts::approval::DeleteGrant::decode(request.grant)?;
    rustiron_contracts::approval::check_delete_binding(
        &plan,
        &grant,
        &rustiron_contracts::approval::DeleteBindingContext {
            host_id: &enrolled.host_id,
            host_epoch: &enrolled.host_epoch,
            profile_digest: &enrolled.profile_digest,
            requester: &enrolled.requester,
            issuer: &enrolled.issuer,
            signer_policy_epoch: &enrolled.signer_policy_epoch,
            now: request.now,
        },
    )?;
    let scratch = files::open_trusted_directory(&anchor.scratch_dir, owner)?;
    signature::verify(
        grant.as_bytes(),
        request.signature,
        &loaded,
        &anchor.scratch_dir,
        &scratch,
    )?;
    Ok(rustiron_journal::DeleteIntent {
        operation_id: request.operation_id.clone(),
        idempotency_key: request.idempotency_key.clone(),
        grant_id: grant.grant_id().clone(),
        nonce: grant.nonce().clone(),
        plan_digest: plan.digest(),
        grant_digest: Sha256Digest::from_bytes(Sha256::digest(grant.as_bytes()).into()),
        host_id: enrolled.host_id.clone(),
        host_epoch: enrolled.host_epoch.clone(),
        site_id: plan.site_id().clone(),
        hostname: plan.hostname().clone(),
        capture_operation_id: plan.capture_operation_id().cloned(),
        expires_at: grant.expires_at(),
    })
}

/// W550 (D-091): the `pdns.conf` rendered from the enrolled `dns`
/// section, for the operator's review. Read only; a host without the
/// section is not enrolled for DNS.
pub fn dns_config(anchor: &TrustAnchor) -> Result<String, ExecutorError> {
    let owner = anchor.owner_uid;
    let loaded = policy::load(
        &files::open_trusted_directory(&anchor.policy_dir, owner)?,
        owner,
    )?;
    loaded
        .policy
        .dns
        .as_ref()
        .map(dns::DnsPolicy::render)
        .ok_or(ExecutorError::NotEnrolled)
}

/// W538 (D-078): the verified signed scrub of a quarantined clone.
pub(crate) fn verified_clone_scrub(
    anchor: &TrustAnchor,
    request: &AdmissionRequest<'_>,
) -> Result<rustiron_journal::CloneScrubIntent, ExecutorError> {
    let owner = anchor.owner_uid;
    let loaded = policy::load(
        &files::open_trusted_directory(&anchor.policy_dir, owner)?,
        owner,
    )?;
    let enrolled = &loaded.policy;
    if request.peer_uid != enrolled.requester_uid {
        return Err(ExecutorError::PeerDenied);
    }
    if enrolled.provisioning.is_none() {
        return Err(ExecutorError::Unavailable);
    }
    if request.plan.len() > MAX_REQUEST_BYTES
        || request.grant.len() > MAX_REQUEST_BYTES
        || request.signature.len() > MAX_SIGNATURE_BYTES
    {
        return Err(ExecutorError::InvalidRequest);
    }
    let plan = rustiron_contracts::approval::CloneScrubPlan::decode(request.plan)?;
    let grant = rustiron_contracts::approval::CloneScrubGrant::decode(request.grant)?;
    rustiron_contracts::approval::check_clone_scrub_binding(
        &plan,
        &grant,
        &rustiron_contracts::approval::CloneScrubBindingContext {
            host_id: &enrolled.host_id,
            host_epoch: &enrolled.host_epoch,
            profile_digest: &enrolled.profile_digest,
            requester: &enrolled.requester,
            issuer: &enrolled.issuer,
            signer_policy_epoch: &enrolled.signer_policy_epoch,
            now: request.now,
        },
    )?;
    let scratch = files::open_trusted_directory(&anchor.scratch_dir, owner)?;
    signature::verify(
        grant.as_bytes(),
        request.signature,
        &loaded,
        &anchor.scratch_dir,
        &scratch,
    )?;
    Ok(rustiron_journal::CloneScrubIntent {
        operation_id: request.operation_id.clone(),
        idempotency_key: request.idempotency_key.clone(),
        grant_id: grant.grant_id().clone(),
        nonce: grant.nonce().clone(),
        plan_digest: plan.digest(),
        grant_digest: Sha256Digest::from_bytes(Sha256::digest(grant.as_bytes()).into()),
        host_id: enrolled.host_id.clone(),
        host_epoch: enrolled.host_epoch.clone(),
        site_id: plan.site_id().clone(),
        clone_operation_id: plan.clone_operation_id().clone(),
        expires_at: grant.expires_at(),
    })
}

/// W543 (D-089): the verified signed restore of a live site, with the
/// digest of the enrolled destination that its pins name.
pub(crate) fn verified_restore(
    anchor: &TrustAnchor,
    request: &AdmissionRequest<'_>,
) -> Result<(rustiron_journal::RestoreIntent, Sha256Digest), ExecutorError> {
    let owner = anchor.owner_uid;
    let loaded = policy::load(
        &files::open_trusted_directory(&anchor.policy_dir, owner)?,
        owner,
    )?;
    let enrolled = &loaded.policy;
    if request.peer_uid != enrolled.requester_uid {
        return Err(ExecutorError::PeerDenied);
    }
    if enrolled.provisioning.is_none() {
        return Err(ExecutorError::Unavailable);
    }
    if request.plan.len() > MAX_REQUEST_BYTES
        || request.grant.len() > MAX_REQUEST_BYTES
        || request.signature.len() > MAX_SIGNATURE_BYTES
    {
        return Err(ExecutorError::InvalidRequest);
    }
    let plan = rustiron_contracts::approval::RestorePlan::decode(request.plan)?;
    let grant = rustiron_contracts::approval::RestoreGrant::decode(request.grant)?;
    rustiron_contracts::approval::check_restore_binding(
        &plan,
        &grant,
        &rustiron_contracts::approval::ProductBackupBindingContext {
            host_id: &enrolled.host_id,
            host_epoch: &enrolled.host_epoch,
            profile_digest: &enrolled.profile_digest,
            requester: &enrolled.requester,
            issuer: &enrolled.issuer,
            signer_policy_epoch: &enrolled.signer_policy_epoch,
            now: request.now,
        },
    )?;
    let scratch = files::open_trusted_directory(&anchor.scratch_dir, owner)?;
    signature::verify(
        grant.as_bytes(),
        request.signature,
        &loaded,
        &anchor.scratch_dir,
        &scratch,
    )?;
    // The pins name the destination as it is enrolled now.
    let source = plan.source();
    let destination = loaded
        .product_backup
        .as_ref()
        .ok_or(ExecutorError::Unavailable)?;
    if destination.destination_id() != &source.destination_id
        || destination.digest() != source.destination_policy_digest
        || destination.repository_id(plan.site_id()) != Some(&source.repository_id)
    {
        return Err(ExecutorError::PreconditionChanged);
    }
    Ok((
        rustiron_journal::RestoreIntent {
            operation_id: request.operation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            grant_id: grant.grant_id().clone(),
            nonce: grant.nonce().clone(),
            plan_digest: plan.digest(),
            grant_digest: Sha256Digest::from_bytes(Sha256::digest(grant.as_bytes()).into()),
            host_id: enrolled.host_id.clone(),
            host_epoch: enrolled.host_epoch.clone(),
            site_id: plan.site_id().clone(),
            hostname: plan.hostname().clone(),
            scope: plan.scope(),
            capture_operation_id: source.capture_operation_id.clone(),
            snapshot_id: source.snapshot_id.clone(),
            manifest_sha256: source.manifest_sha256.clone(),
            safety_capture_operation_id: plan.safety_capture_operation_id().clone(),
            expires_at: grant.expires_at(),
        },
        destination.digest(),
    ))
}

/// W535 (D-088): the verified signed change of a site's quota.
pub(crate) fn verified_quota(
    anchor: &TrustAnchor,
    request: &AdmissionRequest<'_>,
) -> Result<rustiron_journal::QuotaChangeIntent, ExecutorError> {
    let owner = anchor.owner_uid;
    let loaded = policy::load(
        &files::open_trusted_directory(&anchor.policy_dir, owner)?,
        owner,
    )?;
    let enrolled = &loaded.policy;
    if request.peer_uid != enrolled.requester_uid {
        return Err(ExecutorError::PeerDenied);
    }
    if enrolled.provisioning.is_none() {
        return Err(ExecutorError::Unavailable);
    }
    if request.plan.len() > MAX_REQUEST_BYTES
        || request.grant.len() > MAX_REQUEST_BYTES
        || request.signature.len() > MAX_SIGNATURE_BYTES
    {
        return Err(ExecutorError::InvalidRequest);
    }
    let plan = rustiron_contracts::approval::QuotaPlan::decode(request.plan)?;
    let grant = rustiron_contracts::approval::QuotaGrant::decode(request.grant)?;
    rustiron_contracts::approval::check_quota_binding(
        &plan,
        &grant,
        &rustiron_contracts::approval::QuotaBindingContext {
            host_id: &enrolled.host_id,
            host_epoch: &enrolled.host_epoch,
            profile_digest: &enrolled.profile_digest,
            requester: &enrolled.requester,
            issuer: &enrolled.issuer,
            signer_policy_epoch: &enrolled.signer_policy_epoch,
            now: request.now,
        },
    )?;
    let scratch = files::open_trusted_directory(&anchor.scratch_dir, owner)?;
    signature::verify(
        grant.as_bytes(),
        request.signature,
        &loaded,
        &anchor.scratch_dir,
        &scratch,
    )?;
    Ok(rustiron_journal::QuotaChangeIntent {
        operation_id: request.operation_id.clone(),
        idempotency_key: request.idempotency_key.clone(),
        grant_id: grant.grant_id().clone(),
        nonce: grant.nonce().clone(),
        plan_digest: plan.digest(),
        grant_digest: Sha256Digest::from_bytes(Sha256::digest(grant.as_bytes()).into()),
        host_id: enrolled.host_id.clone(),
        host_epoch: enrolled.host_epoch.clone(),
        site_id: plan.site_id().clone(),
        block_hard_kib: plan.quota_limits().block_hard_kib(),
        inode_hard: plan.quota_limits().inode_hard(),
        expires_at: grant.expires_at(),
    })
}

/// W609 (D-100): verifies peer identity, closed `site_credential_rotate`
/// plan/grant binding, validity window, and SSHSIG grant signature.
pub(crate) fn verified_credential_rotate(
    anchor: &TrustAnchor,
    request: &AdmissionRequest<'_>,
) -> Result<rustiron_journal::CredentialRotateIntent, ExecutorError> {
    let owner = anchor.owner_uid;
    let loaded = policy::load(
        &files::open_trusted_directory(&anchor.policy_dir, owner)?,
        owner,
    )?;
    let enrolled = &loaded.policy;
    if request.peer_uid != enrolled.requester_uid {
        return Err(ExecutorError::PeerDenied);
    }
    if request.plan.len() > MAX_REQUEST_BYTES
        || request.grant.len() > MAX_REQUEST_BYTES
        || request.signature.len() > MAX_SIGNATURE_BYTES
    {
        return Err(ExecutorError::InvalidRequest);
    }
    let plan = rustiron_contracts::approval::CredentialRotatePlan::decode(request.plan)?;
    let grant = rustiron_contracts::approval::CredentialRotateGrant::decode(request.grant)?;
    rustiron_contracts::approval::check_credential_rotate_binding(
        &plan,
        &grant,
        &rustiron_contracts::approval::CredentialRotateBindingContext {
            host_id: &enrolled.host_id,
            host_epoch: &enrolled.host_epoch,
            profile_digest: &enrolled.profile_digest,
            expected_requester: &enrolled.requester,
            expected_issuer: &enrolled.issuer,
            expected_signer_policy_epoch: &enrolled.signer_policy_epoch,
            now: request.now,
        },
    )?;
    let scratch = files::open_trusted_directory(&anchor.scratch_dir, owner)?;
    signature::verify(
        grant.as_bytes(),
        request.signature,
        &loaded,
        &anchor.scratch_dir,
        &scratch,
    )?;
    Ok(rustiron_journal::CredentialRotateIntent {
        operation_id: request.operation_id.clone(),
        idempotency_key: request.idempotency_key.clone(),
        grant_id: grant.grant_id().clone(),
        nonce: grant.nonce().clone(),
        plan_digest: plan.digest(),
        grant_digest: grant.digest(),
        host_id: enrolled.host_id.clone(),
        host_epoch: enrolled.host_epoch.clone(),
        site_id: plan.site_id().clone(),
        hostname: plan.hostname().clone(),
        target: plan.target(),
        expires_at: grant.expires_at(),
    })
}

/// W563 (D-091): the verified signed zone import, with the enrolled `dns`
/// section it runs under.
pub(crate) fn verified_dns_import(
    anchor: &TrustAnchor,
    request: &AdmissionRequest<'_>,
) -> Result<(rustiron_journal::DnsImportIntent, dns::DnsPolicy), ExecutorError> {
    let owner = anchor.owner_uid;
    let loaded = policy::load(
        &files::open_trusted_directory(&anchor.policy_dir, owner)?,
        owner,
    )?;
    let enrolled = &loaded.policy;
    if request.peer_uid != enrolled.requester_uid {
        return Err(ExecutorError::PeerDenied);
    }
    let dns = enrolled.dns.clone().ok_or(ExecutorError::Unavailable)?;
    if request.plan.len() > MAX_REQUEST_BYTES
        || request.grant.len() > MAX_REQUEST_BYTES
        || request.signature.len() > MAX_SIGNATURE_BYTES
    {
        return Err(ExecutorError::InvalidRequest);
    }
    let plan = rustiron_contracts::approval::DnsImportPlan::decode(request.plan)?;
    let grant = rustiron_contracts::approval::DnsImportGrant::decode(request.grant)?;
    rustiron_contracts::approval::check_dns_import_binding(
        &plan,
        &grant,
        &rustiron_contracts::approval::DnsBindingContext {
            host_id: &enrolled.host_id,
            host_epoch: &enrolled.host_epoch,
            profile_digest: &enrolled.profile_digest,
            requester: &enrolled.requester,
            issuer: &enrolled.issuer,
            signer_policy_epoch: &enrolled.signer_policy_epoch,
            now: request.now,
        },
    )?;
    let scratch = files::open_trusted_directory(&anchor.scratch_dir, owner)?;
    signature::verify(
        grant.as_bytes(),
        request.signature,
        &loaded,
        &anchor.scratch_dir,
        &scratch,
    )?;
    Ok((
        rustiron_journal::DnsImportIntent {
            operation_id: request.operation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            grant_id: grant.grant_id().clone(),
            nonce: grant.nonce().clone(),
            plan_digest: plan.digest(),
            grant_digest: Sha256Digest::from_bytes(Sha256::digest(grant.as_bytes()).into()),
            host_id: enrolled.host_id.clone(),
            host_epoch: enrolled.host_epoch.clone(),
            zone: plan.zone().clone(),
            zone_sha256: plan.zone_sha256().clone(),
            record_sets: plan.record_sets(),
            expires_at: grant.expires_at(),
        },
        dns,
    ))
}

/// W565 (D-091): the verified signed record change: its plan, and its
/// intent without the sets read before intent.
pub(crate) fn verified_dns_change(
    anchor: &TrustAnchor,
    request: &AdmissionRequest<'_>,
) -> Result<
    (
        rustiron_contracts::approval::DnsChangePlan,
        rustiron_journal::DnsChangeIntent,
    ),
    ExecutorError,
> {
    let owner = anchor.owner_uid;
    let loaded = policy::load(
        &files::open_trusted_directory(&anchor.policy_dir, owner)?,
        owner,
    )?;
    let enrolled = &loaded.policy;
    if request.peer_uid != enrolled.requester_uid {
        return Err(ExecutorError::PeerDenied);
    }
    if enrolled.dns.is_none() {
        return Err(ExecutorError::Unavailable);
    }
    if request.plan.len() > MAX_REQUEST_BYTES
        || request.grant.len() > MAX_REQUEST_BYTES
        || request.signature.len() > MAX_SIGNATURE_BYTES
    {
        return Err(ExecutorError::InvalidRequest);
    }
    let plan = rustiron_contracts::approval::DnsChangePlan::decode(request.plan)?;
    let grant = rustiron_contracts::approval::DnsChangeGrant::decode(request.grant)?;
    rustiron_contracts::approval::check_dns_change_binding(
        &plan,
        &grant,
        &rustiron_contracts::approval::DnsBindingContext {
            host_id: &enrolled.host_id,
            host_epoch: &enrolled.host_epoch,
            profile_digest: &enrolled.profile_digest,
            requester: &enrolled.requester,
            issuer: &enrolled.issuer,
            signer_policy_epoch: &enrolled.signer_policy_epoch,
            now: request.now,
        },
    )?;
    let scratch = files::open_trusted_directory(&anchor.scratch_dir, owner)?;
    signature::verify(
        grant.as_bytes(),
        request.signature,
        &loaded,
        &anchor.scratch_dir,
        &scratch,
    )?;
    let intent = rustiron_journal::DnsChangeIntent {
        operation_id: request.operation_id.clone(),
        idempotency_key: request.idempotency_key.clone(),
        grant_id: grant.grant_id().clone(),
        nonce: grant.nonce().clone(),
        plan_digest: plan.digest(),
        grant_digest: Sha256Digest::from_bytes(Sha256::digest(grant.as_bytes()).into()),
        host_id: enrolled.host_id.clone(),
        host_epoch: enrolled.host_epoch.clone(),
        zone: plan.zone().clone(),
        sets: Vec::new(),
        expires_at: grant.expires_at(),
    };
    Ok((plan, intent))
}

/// W515 (D-084): the verified signed WordPress plugin and theme update.
pub(crate) fn verified_update(
    anchor: &TrustAnchor,
    request: &AdmissionRequest<'_>,
) -> Result<rustiron_journal::UpdateIntent, ExecutorError> {
    let owner = anchor.owner_uid;
    let loaded = policy::load(
        &files::open_trusted_directory(&anchor.policy_dir, owner)?,
        owner,
    )?;
    let enrolled = &loaded.policy;
    if request.peer_uid != enrolled.requester_uid {
        return Err(ExecutorError::PeerDenied);
    }
    if enrolled.provisioning.is_none() {
        return Err(ExecutorError::Unavailable);
    }
    if request.plan.len() > MAX_REQUEST_BYTES
        || request.grant.len() > MAX_REQUEST_BYTES
        || request.signature.len() > MAX_SIGNATURE_BYTES
    {
        return Err(ExecutorError::InvalidRequest);
    }
    let plan = rustiron_contracts::approval::SiteUpdatePlan::decode(request.plan)?;
    let grant = rustiron_contracts::approval::SiteUpdateGrant::decode(request.grant)?;
    rustiron_contracts::approval::check_update_binding(
        &plan,
        &grant,
        &rustiron_contracts::approval::UpdateBindingContext {
            host_id: &enrolled.host_id,
            host_epoch: &enrolled.host_epoch,
            profile_digest: &enrolled.profile_digest,
            requester: &enrolled.requester,
            issuer: &enrolled.issuer,
            signer_policy_epoch: &enrolled.signer_policy_epoch,
            now: request.now,
        },
    )?;
    let scratch = files::open_trusted_directory(&anchor.scratch_dir, owner)?;
    signature::verify(
        grant.as_bytes(),
        request.signature,
        &loaded,
        &anchor.scratch_dir,
        &scratch,
    )?;
    Ok(rustiron_journal::UpdateIntent {
        operation_id: request.operation_id.clone(),
        idempotency_key: request.idempotency_key.clone(),
        grant_id: grant.grant_id().clone(),
        nonce: grant.nonce().clone(),
        plan_digest: plan.digest(),
        grant_digest: Sha256Digest::from_bytes(Sha256::digest(grant.as_bytes()).into()),
        host_id: enrolled.host_id.clone(),
        host_epoch: enrolled.host_epoch.clone(),
        site_id: plan.site_id().clone(),
        capture_operation_id: plan.capture_operation_id().clone(),
        recipe_digest: plan.recipe_digest().clone(),
        components: plan.components().to_vec(),
        expires_at: grant.expires_at(),
    })
}

/// Admission for the lab OLS `config_activate`: enrolled policy and peer,
/// closed plan/grant binding, time and SSHSIG. Returns the plan, the grant
/// digests/ids and the enrolled listener policy; no host state is read here.
pub(crate) fn verified_ols(
    anchor: &TrustAnchor,
    request: &AdmissionRequest<'_>,
) -> Result<(OlsPlan, OlsGrant, policy::Policy), ExecutorError> {
    let owner = anchor.owner_uid;
    let loaded = policy::load(
        &files::open_trusted_directory(&anchor.policy_dir, owner)?,
        owner,
    )?;
    let enrolled = &loaded.policy;
    if request.peer_uid != enrolled.requester_uid {
        return Err(ExecutorError::PeerDenied);
    }
    if enrolled.ols.is_none() {
        return Err(ExecutorError::Unavailable);
    }
    if request.plan.len() > MAX_REQUEST_BYTES
        || request.grant.len() > MAX_REQUEST_BYTES
        || request.signature.len() > MAX_SIGNATURE_BYTES
    {
        return Err(ExecutorError::InvalidRequest);
    }
    let plan = OlsPlan::decode(request.plan)?;
    let grant = OlsGrant::decode(request.grant)?;
    // W368: a page-cache opt-in names the executor's own recipe pin.
    if plan
        .page_cache()
        .is_some_and(|opt_in| opt_in.recipe_digest() != &page_cache::recipe_digest(opt_in.recipe()))
    {
        return Err(ExecutorError::BindingDenied);
    }
    check_ols_binding(
        &plan,
        &grant,
        &OlsBindingContext {
            host_id: &enrolled.host_id,
            host_epoch: &enrolled.host_epoch,
            profile_digest: &enrolled.profile_digest,
            requester: &enrolled.requester,
            issuer: &enrolled.issuer,
            signer_policy_epoch: &enrolled.signer_policy_epoch,
            now: request.now,
        },
    )?;
    let scratch = files::open_trusted_directory(&anchor.scratch_dir, owner)?;
    signature::verify(
        grant.as_bytes(),
        request.signature,
        &loaded,
        &anchor.scratch_dir,
        &scratch,
    )?;
    Ok((plan, grant, loaded.policy))
}

/// Admission for the lab `backup_capture`: enrolled policy and peer, the
/// enrolled destination, closed binding, time and SSHSIG.
pub(crate) fn verified_capture(
    anchor: &TrustAnchor,
    request: &AdmissionRequest<'_>,
) -> Result<(CapturePlan, CaptureGrant, policy::Policy), ExecutorError> {
    policy::require_lab_backup()?;
    let owner = anchor.owner_uid;
    let loaded = policy::load(
        &files::open_trusted_directory(&anchor.policy_dir, owner)?,
        owner,
    )?;
    let enrolled = &loaded.policy;
    if request.peer_uid != enrolled.requester_uid {
        return Err(ExecutorError::PeerDenied);
    }
    if enrolled.backup.is_none() || enrolled.provisioning.is_none() {
        return Err(ExecutorError::Unavailable);
    }
    if request.plan.len() > MAX_REQUEST_BYTES
        || request.grant.len() > MAX_REQUEST_BYTES
        || request.signature.len() > MAX_SIGNATURE_BYTES
    {
        return Err(ExecutorError::InvalidRequest);
    }
    let plan = CapturePlan::decode(request.plan)?;
    let grant = CaptureGrant::decode(request.grant)?;
    check_capture_binding(
        &plan,
        &grant,
        &CaptureBindingContext {
            host_id: &enrolled.host_id,
            host_epoch: &enrolled.host_epoch,
            profile_digest: &enrolled.profile_digest,
            requester: &enrolled.requester,
            issuer: &enrolled.issuer,
            signer_policy_epoch: &enrolled.signer_policy_epoch,
            now: request.now,
        },
    )?;
    let scratch = files::open_trusted_directory(&anchor.scratch_dir, owner)?;
    signature::verify(
        grant.as_bytes(),
        request.signature,
        &loaded,
        &anchor.scratch_dir,
        &scratch,
    )?;
    Ok((plan, grant, loaded.policy))
}

/// Admission for the lab `restore_probe`: enrolled policy and peer, the
/// enrolled destination, closed binding, time and SSHSIG.
pub(crate) fn verified_probe(
    anchor: &TrustAnchor,
    request: &AdmissionRequest<'_>,
) -> Result<(ProbePlan, ProbeGrant, policy::Policy), ExecutorError> {
    policy::require_lab_backup()?;
    let owner = anchor.owner_uid;
    let loaded = policy::load(
        &files::open_trusted_directory(&anchor.policy_dir, owner)?,
        owner,
    )?;
    let enrolled = &loaded.policy;
    if request.peer_uid != enrolled.requester_uid {
        return Err(ExecutorError::PeerDenied);
    }
    if enrolled.backup.is_none() || enrolled.provisioning.is_none() {
        return Err(ExecutorError::Unavailable);
    }
    if request.plan.len() > MAX_REQUEST_BYTES
        || request.grant.len() > MAX_REQUEST_BYTES
        || request.signature.len() > MAX_SIGNATURE_BYTES
    {
        return Err(ExecutorError::InvalidRequest);
    }
    let plan = ProbePlan::decode(request.plan)?;
    let grant = ProbeGrant::decode(request.grant)?;
    check_probe_binding(
        &plan,
        &grant,
        &ProbeBindingContext {
            host_id: &enrolled.host_id,
            host_epoch: &enrolled.host_epoch,
            profile_digest: &enrolled.profile_digest,
            requester: &enrolled.requester,
            issuer: &enrolled.issuer,
            signer_policy_epoch: &enrolled.signer_policy_epoch,
            now: request.now,
        },
    )?;
    let scratch = files::open_trusted_directory(&anchor.scratch_dir, owner)?;
    signature::verify(
        grant.as_bytes(),
        request.signature,
        &loaded,
        &anchor.scratch_dir,
        &scratch,
    )?;
    Ok((plan, grant, loaded.policy))
}

/// Admission for the lab `site_eject`: the same enrolled policy, peer, closed
/// binding, time and SSHSIG checks as `config_activate`.
pub(crate) fn verified_eject(
    anchor: &TrustAnchor,
    request: &AdmissionRequest<'_>,
) -> Result<(EjectPlan, EjectGrant, policy::Policy), ExecutorError> {
    let owner = anchor.owner_uid;
    let loaded = policy::load(
        &files::open_trusted_directory(&anchor.policy_dir, owner)?,
        owner,
    )?;
    let enrolled = &loaded.policy;
    if request.peer_uid != enrolled.requester_uid {
        return Err(ExecutorError::PeerDenied);
    }
    if enrolled.ols.is_none() || enrolled.provisioning.is_none() {
        return Err(ExecutorError::Unavailable);
    }
    if request.plan.len() > MAX_REQUEST_BYTES
        || request.grant.len() > MAX_REQUEST_BYTES
        || request.signature.len() > MAX_SIGNATURE_BYTES
    {
        return Err(ExecutorError::InvalidRequest);
    }
    let plan = EjectPlan::decode(request.plan)?;
    let grant = EjectGrant::decode(request.grant)?;
    check_eject_binding(
        &plan,
        &grant,
        &EjectBindingContext {
            host_id: &enrolled.host_id,
            host_epoch: &enrolled.host_epoch,
            profile_digest: &enrolled.profile_digest,
            requester: &enrolled.requester,
            issuer: &enrolled.issuer,
            signer_policy_epoch: &enrolled.signer_policy_epoch,
            now: request.now,
        },
    )?;
    let scratch = files::open_trusted_directory(&anchor.scratch_dir, owner)?;
    signature::verify(
        grant.as_bytes(),
        request.signature,
        &loaded,
        &anchor.scratch_dir,
        &scratch,
    )?;
    Ok((plan, grant, loaded.policy))
}

/// Admission for `site_readopt` (W372, D-030): enrolled policy and peer,
/// enrolled provisioning (and OLS for the generation form), closed binding
/// (a site form's signed limits at most the enrolled quota), time and
/// SSHSIG. Reads no host state.
pub(crate) fn verified_readopt(
    anchor: &TrustAnchor,
    request: &AdmissionRequest<'_>,
) -> Result<(ReadoptPlan, ReadoptGrant, policy::Policy), ExecutorError> {
    let owner = anchor.owner_uid;
    let loaded = policy::load(
        &files::open_trusted_directory(&anchor.policy_dir, owner)?,
        owner,
    )?;
    let enrolled = &loaded.policy;
    if request.peer_uid != enrolled.requester_uid {
        return Err(ExecutorError::PeerDenied);
    }
    let provisioning = enrolled
        .provisioning
        .as_ref()
        .ok_or(ExecutorError::Unavailable)?;
    if request.plan.len() > MAX_REQUEST_BYTES
        || request.grant.len() > MAX_REQUEST_BYTES
        || request.signature.len() > MAX_SIGNATURE_BYTES
    {
        return Err(ExecutorError::InvalidRequest);
    }
    let plan = ReadoptPlan::decode(request.plan)?;
    let grant = ReadoptGrant::decode(request.grant)?;
    if plan.generation().is_some() && enrolled.ols.is_none() {
        return Err(ExecutorError::Unavailable);
    }
    let quota_cap = match provisioning.quota {
        Some(limits) => Some(limits.cap().ok_or(ExecutorError::Unavailable)?),
        None => None,
    };
    check_readopt_binding(
        &plan,
        &grant,
        &ReadoptBindingContext {
            host_id: &enrolled.host_id,
            host_epoch: &enrolled.host_epoch,
            profile_digest: &enrolled.profile_digest,
            requester: &enrolled.requester,
            issuer: &enrolled.issuer,
            signer_policy_epoch: &enrolled.signer_policy_epoch,
            quota_cap,
            now: request.now,
        },
    )?;
    let scratch = files::open_trusted_directory(&anchor.scratch_dir, owner)?;
    signature::verify(
        grant.as_bytes(),
        request.signature,
        &loaded,
        &anchor.scratch_dir,
        &scratch,
    )?;
    Ok((plan, grant, loaded.policy))
}

/// Live re-observation must equal the intent's predecessor exactly.
pub(crate) fn check_live(anchor: &TrustAnchor, intent: &Intent) -> Result<(), ExecutorError> {
    let owner = anchor.owner_uid;
    let registry = files::open_trusted_directory(&anchor.registry_dir, owner)?;
    let live = registry::observe(&registry, &intent.resource_id, owner)?;
    if live.generation != intent.predecessor_generation || live.digest != intent.predecessor_digest
    {
        return Err(ExecutorError::PreconditionChanged);
    }
    Ok(())
}
