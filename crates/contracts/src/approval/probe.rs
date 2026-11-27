//! Closed lab `restore_probe` contract (schema v1).
//!
//! The requester names one provisioned site, one snapshot id and a fixed
//! sandbox profile. The executor fetches with the site's read-only key into a
//! throwaway sandbox, probes the restored application without network or
//! credentials, removes only what it created and records a receipt. The
//! source site is never touched; no path, image or command is representable.

use serde::{Deserialize, Serialize};

use crate::{CanonicalObject, Id, Text, Timestamp};

use super::{ApprovalError, Sha256Digest, SiteId, header::Enrolled, types::*};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ProbeVerb {
    RestoreProbe,
}

/// Fixed restore sandbox profiles.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeProfile {
    /// Throwaway account and SELinux level, no network or credentials for the
    /// probe, WordPress health check, full cleanup.
    LocalNoEgressV1,
}

/// A restic snapshot id: 64 lowercase hex.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(try_from = "String")]
pub struct SnapshotId(String);

impl TryFrom<String> for SnapshotId {
    type Error = ApprovalError;

    fn try_from(value: String) -> Result<Self, ApprovalError> {
        if value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            Ok(Self(value))
        } else {
            Err(ApprovalError::InvalidMessage)
        }
    }
}

impl SnapshotId {
    /// The validated id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProbePlanRecord {
    schema_version: u16,
    plan_id: Id,
    host_id: Id,
    host_epoch: Id,
    profile_digest: Sha256Digest,
    requester: Id,
    verb: ProbeVerb,
    site_id: SiteId,
    snapshot_id: SnapshotId,
    profile_id: ProbeProfile,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    limitations: Vec<Text>,
}

impl ProbePlanRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.limitations.len() > 8 || !valid_window(self.valid_from, self.expires_at) {
            return Err(ApprovalError::InvalidPlan);
        }
        Ok(())
    }
}

/// A closed restore probe plan retaining its canonical bytes.
#[derive(Debug)]
pub struct ProbePlan {
    record: ProbePlanRecord,
    canonical: CanonicalObject,
}

impl ProbePlan {
    /// Decodes schema v1 and intrinsic constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, ProbePlanRecord::validate)?;
        Ok(Self { record, canonical })
    }

    /// Domain-separated SHA-256 of the complete validated object.
    pub fn digest(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(self.canonical.plan_domain_digest())
    }

    /// The site whose snapshot is restored.
    pub fn site_id(&self) -> &SiteId {
        &self.record.site_id
    }

    /// The snapshot to restore.
    pub fn snapshot_id(&self) -> &SnapshotId {
        &self.record.snapshot_id
    }

    /// The fixed sandbox profile.
    pub fn profile(&self) -> ProbeProfile {
        self.record.profile_id
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProbeGrantRecord {
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
    verbs: Vec<ProbeVerb>,
    site_ids: Vec<SiteId>,
    snapshot_ids: Vec<SnapshotId>,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    max_operations: u64,
}

impl ProbeGrantRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.issuer == self.requester
            || self.verbs != [ProbeVerb::RestoreProbe]
            || self.site_ids.len() != 1
            || self.snapshot_ids.len() != 1
            || self.max_operations != 1
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidGrant);
        }
        Ok(())
    }
}

/// A closed restore probe grant; no verified signature or replay authority.
#[derive(Debug)]
pub struct ProbeGrant {
    record: ProbeGrantRecord,
    canonical: CanonicalObject,
}

impl ProbeGrant {
    /// Decodes the bounded schema and intrinsic grant constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, ProbeGrantRecord::validate)?;
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

    /// Normal signed deadline for starting the probe.
    pub fn expires_at(&self) -> Timestamp {
        self.record.expires_at
    }
}

/// Independently enrolled facts for [`check_probe_binding`].
pub struct ProbeBindingContext<'a> {
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
    /// Reliable current Unix seconds; `None` denies.
    pub now: Option<Timestamp>,
}

/// Pure consistency check; success confers no authority.
pub fn check_probe_binding(
    plan: &ProbePlan,
    grant: &ProbeGrant,
    context: &ProbeBindingContext<'_>,
) -> Result<(), ApprovalError> {
    let p = &plan.record;
    let g = &grant.record;
    if g.site_ids != [p.site_id.clone()]
        || g.snapshot_ids != [p.snapshot_id.clone()]
        || g.risk_class != p.risk_class
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
