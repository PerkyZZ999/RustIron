//! Closed D-080 `site_retire` plan/grant contract.
//!
//! The plan names one site and the operation of its quarantined provision.
//! The executor checks them against its own journal, derives every resource
//! from the provision's recorded steps, and removes only what those steps
//! made. It retires no served site and deletes no backup. Decoding is not
//! signature verification or authority.

use serde::{Deserialize, Serialize};

use crate::{CanonicalObject, Id, Text, Timestamp};

use super::{ApprovalError, Sha256Digest, SiteId, header::Enrolled, types::*};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RetireVerb {
    SiteRetire,
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct RetireEffects {
    removes_site_resources: bool,
    deletes_backups: bool,
    traffic_activation: bool,
    network_access: bool,
}

const EFFECTS: RetireEffects = RetireEffects {
    removes_site_resources: true,
    deletes_backups: false,
    traffic_activation: false,
    network_access: false,
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RetirePlanRecord {
    schema_version: u16,
    plan_id: Id,
    host_id: Id,
    host_epoch: Id,
    profile_digest: Sha256Digest,
    requester: Id,
    verb: RetireVerb,
    site_id: SiteId,
    provision_operation_id: Id,
    #[serde(deserialize_with = "crate::codec::object")]
    expected_effects: RetireEffects,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    limitations: Vec<Text>,
}

impl RetirePlanRecord {
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

/// A closed retirement plan retaining its canonical original semantic bytes.
#[derive(Debug)]
pub struct RetirePlan {
    record: RetirePlanRecord,
    canonical: CanonicalObject,
}

impl RetirePlan {
    /// Decodes schema v1 and its intrinsic constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, RetirePlanRecord::validate)?;
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

    /// The quarantined site to retire.
    pub fn site_id(&self) -> &SiteId {
        &self.record.site_id
    }

    /// The operation of the site's quarantined provision.
    pub fn provision_operation_id(&self) -> &Id {
        &self.record.provision_operation_id
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RetireGrantRecord {
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
    verbs: Vec<RetireVerb>,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    max_operations: u64,
}

impl RetireGrantRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.issuer == self.requester
            || self.site_ids.len() != 1
            || self.verbs != [RetireVerb::SiteRetire]
            || self.max_operations != 1
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidGrant);
        }
        Ok(())
    }
}

/// A closed retirement grant envelope; no verified signature or replay authority.
#[derive(Debug)]
pub struct RetireGrant {
    record: RetireGrantRecord,
    canonical: CanonicalObject,
}

impl RetireGrant {
    /// Decodes the bounded schema and intrinsic grant constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, RetireGrantRecord::validate)?;
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

/// Independently enrolled facts for [`check_retire_binding`]; never taken
/// from the submitted plan or grant.
pub struct RetireBindingContext<'a> {
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
pub fn check_retire_binding(
    plan: &RetirePlan,
    grant: &RetireGrant,
    context: &RetireBindingContext<'_>,
) -> Result<(), ApprovalError> {
    let p = &plan.record;
    let g = &grant.record;
    if g.site_ids != [p.site_id.clone()] || g.risk_class != p.risk_class {
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
