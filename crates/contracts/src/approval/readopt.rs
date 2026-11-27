//! Closed `site_readopt` contract (plan schema v1, D-030 option C, W372).
//!
//! After an epoch rotation the new journal owns nothing. A re-adoption
//! records, in the current journal, ownership of a resource that already
//! exists: one site (the site form) or the live OLS generation (the
//! generation form). Neither form names a path, an account, a UID, a
//! category, a file, a command or SQL; the executor derives every one of
//! them from the site ID and its compiled layout. Neither form has an effect
//! on the host, and neither has a compensation.
//!
//! `previous_epoch` and `evidence_sha256` are evidence for the offline
//! review only (the pre-rotation `export` or `ols-status` output). The
//! executor never reads the archived journal. Decoding is not signature
//! verification, observation or authority.

use serde::{Deserialize, Serialize};

use crate::{CanonicalObject, Id, Text, Timestamp};

use super::{
    ApprovalError, Hostname, Sha256Digest, SiteId, SiteQuotaLimits,
    header::Enrolled,
    ols::{OlsReportSource, OlsTarget},
    types::*,
};

/// Most sites one generation form may name (the OLS plan bound).
pub const MAX_READOPT_SITES: usize = 32;
/// Highest SELinux category an allocation floor may name.
pub const MAX_FLOOR_CATEGORY: u32 = 1023;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReadoptVerb {
    SiteReadopt,
}

/// Which closed form a `site_readopt` plan has.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadoptForm {
    /// Re-adopt one existing site.
    Site,
    /// Adopt the live OLS generation.
    Generation,
}

impl ReadoptForm {
    /// The closed wire and journal name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Site => "site",
            Self::Generation => "generation",
        }
    }
}

/// Optional signed lower bound for later allocations: the highest UID and
/// SELinux category the previous epoch recorded. It can only move the next
/// allocation up; it never names a value to use.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AllocationFloor {
    uid: u32,
    category: u32,
}

impl AllocationFloor {
    /// Highest UID the previous epoch recorded.
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// Highest category the previous epoch recorded.
    pub fn category(&self) -> u32 {
        self.category
    }

    fn valid(&self) -> bool {
        self.uid > 0 && self.uid < u32::MAX && self.category <= MAX_FLOOR_CATEGORY
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum ReadoptObservation {
    /// The site exists on the host and the current journal does not own it.
    PresentUnowned {
        site_id: SiteId,
        hostname: Hostname,
        observed_at: Timestamp,
        source: OlsReportSource,
    },
    /// The live generation the plan names.
    Observed {
        generation: Id,
        content_digest: Sha256Digest,
        observed_at: Timestamp,
        source: OlsReportSource,
    },
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ReadoptEffects {
    creates_account: bool,
    creates_database: bool,
    traffic_activation: bool,
    network_access: bool,
    sets_quota: bool,
    /// Site form only, and then exactly `true`; never `null`.
    #[serde(
        default,
        deserialize_with = "crate::codec::present",
        skip_serializing_if = "Option::is_none"
    )]
    records_ownership: Option<bool>,
    /// Generation form only, and then exactly `true`; never `null`.
    #[serde(
        default,
        deserialize_with = "crate::codec::present",
        skip_serializing_if = "Option::is_none"
    )]
    records_generation: Option<bool>,
}

impl ReadoptEffects {
    fn fixed(form: ReadoptForm) -> Self {
        Self {
            creates_account: false,
            creates_database: false,
            traffic_activation: false,
            network_access: false,
            sets_quota: false,
            records_ownership: (form == ReadoptForm::Site).then_some(true),
            records_generation: (form == ReadoptForm::Generation).then_some(true),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReadoptPlanRecord {
    schema_version: u16,
    plan_id: Id,
    host_id: Id,
    host_epoch: Id,
    profile_digest: Sha256Digest,
    requester: Id,
    verb: ReadoptVerb,
    form: ReadoptForm,
    // Site form only; never `null`.
    #[serde(
        default,
        deserialize_with = "crate::codec::present",
        skip_serializing_if = "Option::is_none"
    )]
    site_id: Option<SiteId>,
    #[serde(
        default,
        deserialize_with = "crate::codec::present",
        skip_serializing_if = "Option::is_none"
    )]
    hostname: Option<Hostname>,
    #[serde(
        default,
        deserialize_with = "crate::codec::present_object",
        skip_serializing_if = "Option::is_none"
    )]
    quota_limits: Option<SiteQuotaLimits>,
    // Generation form only; never `null`.
    #[serde(
        default,
        deserialize_with = "crate::codec::present",
        skip_serializing_if = "Option::is_none"
    )]
    target: Option<OlsTarget>,
    #[serde(
        default,
        deserialize_with = "crate::codec::present",
        skip_serializing_if = "Option::is_none"
    )]
    expected_generation: Option<Id>,
    #[serde(
        default,
        deserialize_with = "crate::codec::present",
        skip_serializing_if = "Option::is_none"
    )]
    expected_digest: Option<Sha256Digest>,
    #[serde(
        default,
        deserialize_with = "crate::codec::present",
        skip_serializing_if = "Option::is_none"
    )]
    site_ids: Option<Vec<SiteId>>,
    // Both forms.
    previous_epoch: Id,
    evidence_sha256: Sha256Digest,
    #[serde(
        default,
        deserialize_with = "crate::codec::present_object",
        skip_serializing_if = "Option::is_none"
    )]
    allocation_floor: Option<AllocationFloor>,
    #[serde(deserialize_with = "crate::codec::object_list")]
    observations: Vec<ReadoptObservation>,
    #[serde(deserialize_with = "crate::codec::object")]
    expected_effects: ReadoptEffects,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    limitations: Vec<Text>,
}

fn fresh(observed_at: Timestamp, valid_from: Timestamp) -> bool {
    observed_at.get() <= valid_from.get()
        && valid_from.get() - observed_at.get() <= MAX_OBSERVATION_AGE_SECONDS
}

impl ReadoptPlanRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.previous_epoch == self.host_epoch
            || self.observations.len() != 1
            || self.expected_effects != ReadoptEffects::fixed(self.form)
            || self.limitations.len() > 8
            || !valid_window(self.valid_from, self.expires_at)
            || self.allocation_floor.is_some_and(|floor| !floor.valid())
        {
            return Err(ApprovalError::InvalidPlan);
        }
        let consistent = match (self.form, &self.observations[0]) {
            (
                ReadoptForm::Site,
                ReadoptObservation::PresentUnowned {
                    site_id,
                    hostname,
                    observed_at,
                    ..
                },
            ) => {
                self.target.is_none()
                    && self.expected_generation.is_none()
                    && self.expected_digest.is_none()
                    && self.site_ids.is_none()
                    && self.site_id.as_ref() == Some(site_id)
                    && self.hostname.as_ref() == Some(hostname)
                    && self.quota_limits.is_some()
                    && fresh(*observed_at, self.valid_from)
            }
            (
                ReadoptForm::Generation,
                ReadoptObservation::Observed {
                    generation,
                    content_digest,
                    observed_at,
                    ..
                },
            ) => {
                let sites = self.site_ids.as_deref().unwrap_or_default();
                self.site_id.is_none()
                    && self.hostname.is_none()
                    && self.quota_limits.is_none()
                    && self.target == Some(OlsTarget::OlsLabListener)
                    && self.expected_generation.as_ref() == Some(generation)
                    && self.expected_digest.as_ref() == Some(content_digest)
                    && (1..=MAX_READOPT_SITES).contains(&sites.len())
                    && sites
                        .windows(2)
                        .all(|pair| pair[0].as_str() < pair[1].as_str())
                    && fresh(*observed_at, self.valid_from)
            }
            _ => false,
        };
        if !consistent {
            return Err(ApprovalError::InvalidPlan);
        }
        Ok(())
    }

    /// The site IDs the grant must name, in plan order.
    fn granted_sites(&self) -> Vec<SiteId> {
        match self.form {
            ReadoptForm::Site => self.site_id.iter().cloned().collect(),
            ReadoptForm::Generation => self.site_ids.clone().unwrap_or_default(),
        }
    }
}

/// A closed `site_readopt` plan retaining its canonical bytes.
#[derive(Debug)]
pub struct ReadoptPlan {
    record: ReadoptPlanRecord,
    canonical: CanonicalObject,
}

impl ReadoptPlan {
    /// Decodes schema v1 of either form and its intrinsic constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, ReadoptPlanRecord::validate)?;
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

    /// The plan's form.
    pub fn form(&self) -> ReadoptForm {
        self.record.form
    }

    /// Site form: the site, its hostname and the signed quota limits.
    pub fn site(&self) -> Option<(&SiteId, &Hostname, SiteQuotaLimits)> {
        match (
            &self.record.site_id,
            &self.record.hostname,
            self.record.quota_limits,
        ) {
            (Some(site), Some(hostname), Some(limits)) => Some((site, hostname, limits)),
            _ => None,
        }
    }

    /// Generation form: the live generation, its digest and the sites it
    /// serves (sorted, no repeats).
    pub fn generation(&self) -> Option<(&Id, &Sha256Digest, &[SiteId])> {
        match (
            &self.record.expected_generation,
            &self.record.expected_digest,
            &self.record.site_ids,
        ) {
            (Some(generation), Some(digest), Some(sites)) => Some((generation, digest, sites)),
            _ => None,
        }
    }

    /// The epoch of the archived journal; evidence only.
    pub fn previous_epoch(&self) -> &Id {
        &self.record.previous_epoch
    }

    /// SHA-256 of the pre-rotation `export` or `ols-status` output.
    pub fn evidence_sha256(&self) -> &Sha256Digest {
        &self.record.evidence_sha256
    }

    /// The optional signed allocation floor.
    pub fn allocation_floor(&self) -> Option<AllocationFloor> {
        self.record.allocation_floor
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReadoptGrantRecord {
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
    verbs: Vec<ReadoptVerb>,
    site_ids: Vec<SiteId>,
    /// Generation form only: the OLS resource; never `null`.
    #[serde(
        default,
        deserialize_with = "crate::codec::present",
        skip_serializing_if = "Option::is_none"
    )]
    targets: Option<Vec<OlsTarget>>,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    max_operations: u64,
}

impl ReadoptGrantRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        let targets_ok = match &self.targets {
            None => true,
            Some(targets) => targets == &[OlsTarget::OlsLabListener],
        };
        if self.issuer == self.requester
            || self.verbs != [ReadoptVerb::SiteReadopt]
            || !(1..=MAX_READOPT_SITES).contains(&self.site_ids.len())
            || !targets_ok
            || self.max_operations != 1
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidGrant);
        }
        Ok(())
    }
}

/// A closed `site_readopt` grant; no verified signature or replay authority.
#[derive(Debug)]
pub struct ReadoptGrant {
    record: ReadoptGrantRecord,
    canonical: CanonicalObject,
}

impl ReadoptGrant {
    /// Decodes the bounded schema and intrinsic grant constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, ReadoptGrantRecord::validate)?;
        Ok(Self { record, canonical })
    }

    /// Canonical bytes the signature must cover.
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

/// Independently enrolled facts for [`check_readopt_binding`].
pub struct ReadoptBindingContext<'a> {
    /// Enrolled host identity.
    pub host_id: &'a Id,
    /// Enrolled host epoch.
    pub host_epoch: &'a Id,
    /// Enrolled profile digest.
    pub profile_digest: &'a Sha256Digest,
    /// Requester resolved from the kernel peer.
    pub requester: &'a Id,
    /// Verified signer principal.
    pub issuer: &'a Id,
    /// Current signer/revocation policy epoch.
    pub signer_policy_epoch: &'a Id,
    /// Enrolled per-site quota cap. A site form needs one, and its signed
    /// limits must be at most the cap; the generation form ignores it.
    pub quota_cap: Option<SiteQuotaLimits>,
    /// Reliable current Unix seconds; `None` denies.
    pub now: Option<Timestamp>,
}

/// Pure consistency check; success confers no authority.
pub fn check_readopt_binding(
    plan: &ReadoptPlan,
    grant: &ReadoptGrant,
    context: &ReadoptBindingContext<'_>,
) -> Result<(), ApprovalError> {
    let p = &plan.record;
    let g = &grant.record;
    let quota_bound = match (p.form, p.quota_limits, context.quota_cap) {
        (ReadoptForm::Generation, _, _) => true,
        (ReadoptForm::Site, Some(limits), Some(cap)) => limits.within(&cap),
        (ReadoptForm::Site, _, _) => false,
    };
    let targets = match p.form {
        ReadoptForm::Site => None,
        ReadoptForm::Generation => Some(vec![OlsTarget::OlsLabListener]),
    };
    if g.site_ids != p.granted_sites()
        || g.targets != targets
        || g.risk_class != p.risk_class
        || !quota_bound
    {
        return Err(ApprovalError::BindingMismatch);
    }
    check_signed_header!(
        plan,
        grant,
        Enrolled {
            host_id: context.host_id,
            host_epoch: context.host_epoch,
            profile_digest: context.profile_digest,
            requester: context.requester,
            issuer: context.issuer,
            signer_policy_epoch: context.signer_policy_epoch,
            now: context.now
        }
    )
}
