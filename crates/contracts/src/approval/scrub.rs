//! Closed D-057 `import_scrub` plan/grant contract.
//!
//! The plan names one site, the operation of its import, and that import's
//! archive digest. The executor checks them against its own journal, derives
//! every path from the journaled site, and removes only the import's
//! leftovers: the extracted export and the archive copy in the site's `tmp`,
//! and the intake archive. It deletes no site. Decoding is not signature
//! verification or authority.

use serde::{Deserialize, Serialize};

use crate::{CanonicalObject, Id, Text, Timestamp};

use super::{ApprovalError, Sha256Digest, SiteId, types::*};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ScrubVerb {
    ImportScrub,
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ScrubEffects {
    removes_import_leftovers: bool,
    removes_intake_archive: bool,
    deletes_site: bool,
    traffic_activation: bool,
    network_access: bool,
}

const EFFECTS: ScrubEffects = ScrubEffects {
    removes_import_leftovers: true,
    removes_intake_archive: true,
    deletes_site: false,
    traffic_activation: false,
    network_access: false,
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScrubPlanRecord {
    schema_version: u16,
    plan_id: Id,
    host_id: Id,
    host_epoch: Id,
    profile_digest: Sha256Digest,
    requester: Id,
    verb: ScrubVerb,
    site_id: SiteId,
    import_operation_id: Id,
    archive_sha256: Sha256Digest,
    #[serde(deserialize_with = "crate::codec::object")]
    expected_effects: ScrubEffects,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    limitations: Vec<Text>,
}

impl ScrubPlanRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.expected_effects != EFFECTS
            || self.limitations.len() > 8
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidPlan);
        }
        Ok(())
    }
}

/// A closed scrub plan retaining its canonical original semantic bytes.
#[derive(Debug)]
pub struct ScrubPlan {
    record: ScrubPlanRecord,
    canonical: CanonicalObject,
}

impl ScrubPlan {
    /// Decodes schema v1 and its intrinsic constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, ScrubPlanRecord::validate)?;
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

    /// The site whose import is scrubbed.
    pub fn site_id(&self) -> &SiteId {
        &self.record.site_id
    }

    /// The operation of the scrubbed import.
    pub fn import_operation_id(&self) -> &Id {
        &self.record.import_operation_id
    }

    /// The archive digest that the import signed.
    pub fn archive_sha256(&self) -> &Sha256Digest {
        &self.record.archive_sha256
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScrubGrantRecord {
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
    verbs: Vec<ScrubVerb>,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    max_operations: u64,
}

impl ScrubGrantRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.issuer == self.requester
            || self.site_ids.len() != 1
            || self.verbs != [ScrubVerb::ImportScrub]
            || self.max_operations != 1
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidGrant);
        }
        Ok(())
    }
}

/// A closed scrub grant envelope; no verified signature or replay authority.
#[derive(Debug)]
pub struct ScrubGrant {
    record: ScrubGrantRecord,
    canonical: CanonicalObject,
}

impl ScrubGrant {
    /// Decodes the bounded schema and intrinsic grant constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, ScrubGrantRecord::validate)?;
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

/// Independently enrolled facts for [`check_scrub_binding`]; never taken
/// from the submitted plan or grant.
pub struct ScrubBindingContext<'a> {
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

/// Pure consistency check; success confers no authority.
pub fn check_scrub_binding(
    plan: &ScrubPlan,
    grant: &ScrubGrant,
    context: &ScrubBindingContext<'_>,
) -> Result<(), ApprovalError> {
    let p = &plan.record;
    let g = &grant.record;
    if g.plan_digest != plan.digest()
        || g.plan_id != p.plan_id
        || g.host_id != p.host_id
        || g.host_epoch != p.host_epoch
        || g.profile_digest != p.profile_digest
        || g.requester != p.requester
        || g.site_ids != [p.site_id.clone()]
        || g.risk_class != p.risk_class
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
