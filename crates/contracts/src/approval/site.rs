//! Closed `site_provision` plan/grant contract for the lab host.
//!
//! The requester names only the site, hostname and an approved recipe. UID,
//! GID, paths, database names, SELinux level and credentials are derived by
//! the executor from enrolled policy and are deliberately not representable
//! here. Decoding is not signature verification or authority.
//!
//! Plan schema v1 carries no quota: the executor applies the enrolled policy
//! limits. Plan schema v2 (W341, D-028 item 3) adds `quota_limits` and
//! `expected_effects.sets_quota`; the binding check refuses limits above the
//! enrolled cap. The grant stays schema v1 and binds the limits through
//! `plan_digest`.

use serde::{Deserialize, Serialize};

use crate::{CanonicalObject, Id, Text, Timestamp};

use super::{ApprovalError, Sha256Digest, header::Enrolled, types::*};

const MAX_HOSTNAME: usize = 253;
/// Plan schema without quota limits (policy limits apply).
const V1: u16 = 1;
/// Plan schema with signed quota limits.
const V2: u16 = 2;

/// Hard per-site user quota limits signed in a v2 plan. Soft limits are
/// always 0. Values are inside fixed bounds; this is not authority to set them.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiteQuotaLimits {
    block_hard_kib: u64,
    inode_hard: u64,
}

impl SiteQuotaLimits {
    /// Smallest hard block limit: 64 MiB in KiB.
    pub const MIN_BLOCK_HARD_KIB: u64 = 64 * 1024;
    /// Largest hard block limit: 16 TiB in KiB.
    pub const MAX_BLOCK_HARD_KIB: u64 = 16 * 1024 * 1024 * 1024;
    /// Smallest hard inode limit.
    pub const MIN_INODE_HARD: u64 = 1_000;
    /// Largest hard inode limit.
    pub const MAX_INODE_HARD: u64 = 100_000_000;

    /// Bounded limits; any value outside the fixed bounds is refused.
    pub fn new(block_hard_kib: u64, inode_hard: u64) -> Result<Self, ApprovalError> {
        let limits = Self {
            block_hard_kib,
            inode_hard,
        };
        if limits.in_bounds() {
            Ok(limits)
        } else {
            Err(ApprovalError::InvalidPlan)
        }
    }

    /// Hard block limit in KiB.
    pub fn block_hard_kib(&self) -> u64 {
        self.block_hard_kib
    }

    /// Hard inode limit.
    pub fn inode_hard(&self) -> u64 {
        self.inode_hard
    }

    /// Both limits are at most the given cap's limits.
    pub fn within(&self, cap: &Self) -> bool {
        self.block_hard_kib <= cap.block_hard_kib && self.inode_hard <= cap.inode_hard
    }

    pub(super) fn in_bounds(&self) -> bool {
        (Self::MIN_BLOCK_HARD_KIB..=Self::MAX_BLOCK_HARD_KIB).contains(&self.block_hard_kib)
            && (Self::MIN_INODE_HARD..=Self::MAX_INODE_HARD).contains(&self.inode_hard)
    }
}

/// `[a-z][a-z0-9]{2,15}`: safe as an account suffix, path component and SQL identifier.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(try_from = "String")]
pub struct SiteId(String);

impl SiteId {
    /// The validated site identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Fixed Unix account and group name for this site.
    pub fn account_name(&self) -> String {
        format!("rs_{}", self.as_str())
    }
}

impl TryFrom<String> for SiteId {
    type Error = ApprovalError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let bytes = value.as_bytes();
        if !(3..=16).contains(&bytes.len())
            || !bytes[0].is_ascii_lowercase()
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        {
            return Err(ApprovalError::InvalidMessage);
        }
        Ok(Self(value))
    }
}

/// Lowercase ASCII DNS name; internationalized names must be converted first.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(try_from = "String")]
pub struct Hostname(String);

impl Hostname {
    /// The validated hostname.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Hostname {
    type Error = ApprovalError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let label_ok = |label: &str| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        };
        let labels: Vec<_> = value.split('.').collect();
        if value.len() > MAX_HOSTNAME || labels.len() < 2 || !labels.iter().all(|l| label_ok(l)) {
            return Err(ApprovalError::InvalidMessage);
        }
        Ok(Self(value))
    }
}

/// Approved install recipes; each maps to one enrolled artifact digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SiteRecipe {
    /// WordPress 7.1.3 (en_US) unpacked by the site account.
    Wordpress713V1,
    /// The same artifact, then installed by the site account with a generated
    /// administrator password handed over root-only.
    Wordpress713InstallV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum SiteVerb {
    SiteProvision,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum SiteObservation {
    Absent {
        site_id: SiteId,
        hostname: Hostname,
        observed_at: Timestamp,
        source: SiteReportSource,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum SiteReportSource {
    ReportedRegistry,
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct SiteEffects {
    creates_account: bool,
    creates_database: bool,
    traffic_activation: bool,
    network_access: bool,
    /// Schema v2 only, and then exactly `true`; never `null`.
    #[serde(
        default,
        deserialize_with = "crate::codec::present",
        skip_serializing_if = "Option::is_none"
    )]
    sets_quota: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SitePlanRecord {
    schema_version: u16,
    plan_id: Id,
    host_id: Id,
    host_epoch: Id,
    profile_digest: Sha256Digest,
    requester: Id,
    verb: SiteVerb,
    site_id: SiteId,
    hostname: Hostname,
    recipe_id: SiteRecipe,
    recipe_digest: Sha256Digest,
    #[serde(deserialize_with = "crate::codec::object_list")]
    observations: Vec<SiteObservation>,
    #[serde(deserialize_with = "crate::codec::object")]
    expected_effects: SiteEffects,
    /// Schema v2 only; never `null`.
    #[serde(
        default,
        deserialize_with = "crate::codec::present_object",
        skip_serializing_if = "Option::is_none"
    )]
    quota_limits: Option<SiteQuotaLimits>,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    limitations: Vec<Text>,
}

impl SitePlanRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        let quota_shape = match (self.schema_version, self.quota_limits) {
            (V1, None) => None,
            (V2, Some(limits)) if limits.in_bounds() => Some(true),
            (V1 | V2, _) => return Err(ApprovalError::InvalidPlan),
            _ => return Err(ApprovalError::UnsupportedVersion),
        };
        let effects = SiteEffects {
            creates_account: true,
            creates_database: true,
            traffic_activation: false,
            network_access: false,
            sets_quota: quota_shape,
        };
        if self.observations.len() != 1
            || self.expected_effects != effects
            || self.limitations.len() > 8
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidPlan);
        }
        let SiteObservation::Absent {
            site_id,
            hostname,
            observed_at,
            ..
        } = &self.observations[0];
        if site_id != &self.site_id
            || hostname != &self.hostname
            || observed_at.get() > self.valid_from.get()
            || self.valid_from.get() - observed_at.get() > MAX_OBSERVATION_AGE_SECONDS
        {
            return Err(ApprovalError::InvalidPlan);
        }
        Ok(())
    }
}

/// A closed site plan retaining its canonical original semantic bytes.
#[derive(Debug)]
pub struct SitePlan {
    record: SitePlanRecord,
    canonical: CanonicalObject,
}

impl SitePlan {
    /// Decodes schema v1 or v2 and its intrinsic constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, SitePlanRecord::validate)?;
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

    /// Requested site identifier.
    pub fn site_id(&self) -> &SiteId {
        &self.record.site_id
    }

    /// Requested hostname.
    pub fn hostname(&self) -> &Hostname {
        &self.record.hostname
    }

    /// Approved recipe and the artifact digest the plan claims for it.
    pub fn recipe(&self) -> (SiteRecipe, &Sha256Digest) {
        (self.record.recipe_id, &self.record.recipe_digest)
    }

    /// Plan schema version: 1 (policy limits) or 2 (signed limits).
    pub fn schema_version(&self) -> u16 {
        self.record.schema_version
    }

    /// Signed quota limits of a v2 plan; `None` for v1, whose limits are the
    /// enrolled policy values.
    pub fn quota_limits(&self) -> Option<SiteQuotaLimits> {
        self.record.quota_limits
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SiteGrantRecord {
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
    verbs: Vec<SiteVerb>,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    max_operations: u64,
}

impl SiteGrantRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.issuer == self.requester
            || self.site_ids.len() != 1
            || self.verbs != [SiteVerb::SiteProvision]
            || self.max_operations != 1
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidGrant);
        }
        Ok(())
    }
}

/// A closed site grant envelope; no verified signature or replay authority.
#[derive(Debug)]
pub struct SiteGrant {
    record: SiteGrantRecord,
    canonical: CanonicalObject,
}

impl SiteGrant {
    /// Decodes the bounded schema and intrinsic grant constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, SiteGrantRecord::validate)?;
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

    /// Signed single-use nonce; this accessor consumes nothing.
    pub fn nonce(&self) -> &Id {
        &self.record.nonce
    }

    /// Normal signed deadline.
    pub fn expires_at(&self) -> Timestamp {
        self.record.expires_at
    }
}

/// Independently enrolled facts for [`check_site_binding`]; never taken from
/// the submitted plan or grant.
pub struct SiteBindingContext<'a> {
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
    /// Enrolled artifact digest for `Wordpress713V1`.
    pub wordpress_713_digest: &'a Sha256Digest,
    /// Reliable current Unix seconds; `None` denies.
    pub now: Option<Timestamp>,
    /// Enrolled per-site quota limits, the ceiling for v2 plan limits.
    /// `None` (no enrolled quota) refuses every v2 plan; v1 plans ignore it.
    pub quota_cap: Option<SiteQuotaLimits>,
}

/// Pure consistency check; success confers no authority.
pub fn check_site_binding(
    plan: &SitePlan,
    grant: &SiteGrant,
    context: &SiteBindingContext<'_>,
) -> Result<(), ApprovalError> {
    let p = &plan.record;
    let g = &grant.record;
    let enrolled_recipe = match p.recipe_id {
        SiteRecipe::Wordpress713V1 | SiteRecipe::Wordpress713InstallV1 => {
            context.wordpress_713_digest
        }
    };
    let quota_bound = match (p.quota_limits, context.quota_cap) {
        (None, _) => true,
        (Some(limits), Some(cap)) => limits.within(&cap),
        (Some(_), None) => false,
    };
    if g.site_ids != [p.site_id.clone()]
        || g.risk_class != p.risk_class
        || &p.recipe_digest != enrolled_recipe
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
