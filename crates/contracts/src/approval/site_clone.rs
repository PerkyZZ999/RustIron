//! D-078's closed lab contract for a clone from one native capture.

use serde::{Deserialize, Serialize};

use crate::{CanonicalObject, Id, Text, Timestamp};

use super::{
    ApprovalError, Hostname, ProductBackupBindingContext, Sha256Digest, SiteId, SnapshotId,
    product_backup::LAB_DESTINATION,
    types::{Risk, valid_window},
};

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Verb {
    SiteClone,
}

/// The source site and the exact backup evidence required by the plan.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloneSource {
    /// Managed site that owns the capture.
    pub site_id: SiteId,
    /// Source hostname for the bounded WordPress URL rewrite.
    pub hostname: Hostname,
    /// Operation that recorded the completed capture.
    pub capture_operation_id: Id,
    /// Full restic snapshot ID.
    pub snapshot_id: SnapshotId,
    /// Digest of the capture's canonical file manifest.
    pub manifest_sha256: Sha256Digest,
    /// Enrolled product backup destination.
    pub destination_id: Id,
    /// Digest of the enrolled destination projection.
    pub destination_policy_digest: Sha256Digest,
    /// Repository configuration ID pinned for the source site.
    pub repository_id: Sha256Digest,
}

/// The distinct target of a clone. The executor derives all local resources.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloneTarget {
    /// New staging site's managed identity.
    pub site_id: SiteId,
    /// Exact staging hostname.
    pub hostname: Hostname,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Effects {
    fetches_snapshot: bool,
    creates_staging_site: bool,
    modifies_source: bool,
    traffic_activation: bool,
}

const EFFECTS: Effects = Effects {
    fetches_snapshot: true,
    creates_staging_site: true,
    modifies_source: false,
    traffic_activation: false,
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PlanRecord {
    schema_version: u16,
    plan_id: Id,
    host_id: Id,
    host_epoch: Id,
    profile_digest: Sha256Digest,
    requester: Id,
    verb: Verb,
    #[serde(deserialize_with = "crate::codec::object")]
    source: CloneSource,
    #[serde(deserialize_with = "crate::codec::object")]
    target: CloneTarget,
    #[serde(deserialize_with = "crate::codec::object")]
    expected_effects: Effects,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    limitations: Vec<Text>,
}

impl PlanRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.source.site_id == self.target.site_id
            || self.source.hostname == self.target.hostname
            || self.source.destination_id.as_str() == LAB_DESTINATION
            || self.expected_effects != EFFECTS
            || self.limitations.len() > 8
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidPlan);
        }
        Ok(())
    }
}

/// Validated clone plan and its complete canonical bytes.
#[derive(Debug)]
pub struct SiteClonePlan {
    record: PlanRecord,
    canonical: CanonicalObject,
}

impl SiteClonePlan {
    /// Decodes the closed schema 1 plan and checks its intrinsic constraints.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, PlanRecord::validate)?;
        Ok(Self { record, canonical })
    }

    /// Canonical bytes used for review and identity.
    pub fn as_bytes(&self) -> &[u8] {
        self.canonical.as_bytes()
    }

    /// Domain-separated digest of the complete plan.
    pub fn digest(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(self.canonical.plan_domain_digest())
    }

    /// Capture, source site and repository references.
    pub fn source(&self) -> &CloneSource {
        &self.record.source
    }

    /// New site and hostname.
    pub fn target(&self) -> &CloneTarget {
        &self.record.target
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GrantRecord {
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
    verbs: Vec<Verb>,
    source_site_id: SiteId,
    target_site_id: SiteId,
    destination_id: Id,
    snapshot_id: SnapshotId,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    max_operations: u64,
}

impl GrantRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.issuer == self.requester
            || self.verbs != [Verb::SiteClone]
            || self.source_site_id == self.target_site_id
            || self.destination_id.as_str() == LAB_DESTINATION
            || self.max_operations != 1
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidGrant);
        }
        Ok(())
    }
}

/// Validated clone envelope before signature verification or replay admission.
#[derive(Debug)]
pub struct SiteCloneGrant {
    record: GrantRecord,
    canonical: CanonicalObject,
}

impl SiteCloneGrant {
    /// Decodes the closed schema 1 grant.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, GrantRecord::validate)?;
        Ok(Self { record, canonical })
    }

    /// Canonical bytes covered by the detached signature.
    pub fn as_bytes(&self) -> &[u8] {
        self.canonical.as_bytes()
    }

    /// Signed grant ID.
    pub fn grant_id(&self) -> &Id {
        &self.record.grant_id
    }

    /// Signed single-use nonce.
    pub fn nonce(&self) -> &Id {
        &self.record.nonce
    }

    /// Signed exclusive execution deadline.
    pub fn expires_at(&self) -> Timestamp {
        self.record.expires_at
    }
}

/// Checks plan, grant, enrollment and time bindings without I/O.
pub fn check_site_clone_binding(
    plan: &SiteClonePlan,
    grant: &SiteCloneGrant,
    context: &ProductBackupBindingContext<'_>,
) -> Result<(), ApprovalError> {
    let p = &plan.record;
    let g = &grant.record;
    if g.plan_digest != plan.digest()
        || g.plan_id != p.plan_id
        || g.host_id != p.host_id
        || g.host_epoch != p.host_epoch
        || g.profile_digest != p.profile_digest
        || g.requester != p.requester
        || g.risk_class != p.risk_class
        || g.source_site_id != p.source.site_id
        || g.target_site_id != p.target.site_id
        || g.destination_id != p.source.destination_id
        || g.snapshot_id != p.source.snapshot_id
        || &p.host_id != context.host_id
        || &p.host_epoch != context.host_epoch
        || &p.profile_digest != context.profile_digest
        || &p.requester != context.requester
        || &g.issuer != context.issuer
        || &g.signer_policy_epoch != context.signer_policy_epoch
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
