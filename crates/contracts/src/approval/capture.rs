//! Closed lab `backup_capture` contract (schema v1).
//!
//! The requester names one provisioned site, an enrolled destination and a
//! fixed capture recipe. Repository paths, store addresses, keys and the dump
//! method come from enrolled policy and the executor; none is representable
//! here. A capture adds an encrypted snapshot and deletes nothing.

use serde::{Deserialize, Serialize};

use crate::{CanonicalObject, Id, Text, Timestamp};

use super::{ApprovalError, Sha256Digest, SiteId, header::Enrolled, types::*};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum CaptureVerb {
    BackupCapture,
}

/// Enrolled backup destinations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureDestination {
    /// The object-locked lab store on the operator PC (not independent off-host).
    LabPcStore,
}

/// Fixed capture recipes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureRecipe {
    /// Single-transaction database dump plus the site's `html/`, run as the site.
    SiteFilesDbV1,
    /// D-021 option A (amendment A1): `SiteFilesDbV1` with the site's PHP pool
    /// stopped for the dump-to-walk window, after an unfreeze timer (at most
    /// 10 s) is armed. Opt-in; it takes the site's PHP offline (stock 503).
    SiteFilesDbFrozenV1,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CapturePlanRecord {
    schema_version: u16,
    plan_id: Id,
    host_id: Id,
    host_epoch: Id,
    profile_digest: Sha256Digest,
    requester: Id,
    verb: CaptureVerb,
    site_id: SiteId,
    destination_id: CaptureDestination,
    recipe_id: CaptureRecipe,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    limitations: Vec<Text>,
}

impl CapturePlanRecord {
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

/// A closed capture plan retaining its canonical bytes.
#[derive(Debug)]
pub struct CapturePlan {
    record: CapturePlanRecord,
    canonical: CanonicalObject,
}

impl CapturePlan {
    /// Decodes schema v1 and intrinsic constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, CapturePlanRecord::validate)?;
        Ok(Self { record, canonical })
    }

    /// Domain-separated SHA-256 of the complete validated object.
    pub fn digest(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(self.canonical.plan_domain_digest())
    }

    /// The one site to capture.
    pub fn site_id(&self) -> &SiteId {
        &self.record.site_id
    }

    /// Destination and recipe the plan names.
    pub fn target(&self) -> (CaptureDestination, CaptureRecipe) {
        (self.record.destination_id, self.record.recipe_id)
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CaptureGrantRecord {
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
    verbs: Vec<CaptureVerb>,
    site_ids: Vec<SiteId>,
    destinations: Vec<CaptureDestination>,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    max_operations: u64,
}

impl CaptureGrantRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.issuer == self.requester
            || self.verbs != [CaptureVerb::BackupCapture]
            || self.site_ids.len() != 1
            || self.destinations.len() != 1
            || self.max_operations != 1
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidGrant);
        }
        Ok(())
    }
}

/// A closed capture grant; no verified signature or replay authority.
#[derive(Debug)]
pub struct CaptureGrant {
    record: CaptureGrantRecord,
    canonical: CanonicalObject,
}

impl CaptureGrant {
    /// Decodes the bounded schema and intrinsic grant constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, CaptureGrantRecord::validate)?;
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

    /// Normal signed deadline for starting the capture.
    pub fn expires_at(&self) -> Timestamp {
        self.record.expires_at
    }
}

/// Independently enrolled facts for [`check_capture_binding`].
pub struct CaptureBindingContext<'a> {
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
pub fn check_capture_binding(
    plan: &CapturePlan,
    grant: &CaptureGrant,
    context: &CaptureBindingContext<'_>,
) -> Result<(), ApprovalError> {
    let p = &plan.record;
    let g = &grant.record;
    if g.site_ids != [p.site_id.clone()]
        || g.destinations != [p.destination_id]
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
