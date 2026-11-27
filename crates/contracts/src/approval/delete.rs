//! Closed D-085 `site_delete` plan/grant contract.
//!
//! The plan names one live site that a signed activation already took
//! offline, its hostname for the signer, and the operation of a succeeded
//! capture of the site from the last 24 hours. Schema 2 (W576, D-095)
//! names no capture: the executor admits it only for a proxy site, whose
//! only file is its identity file and which Rustiron never captures. The executor checks them
//! against its own journal, derives every resource from the site ID, and
//! removes the site from the host, certificate keys included. It deletes no
//! backup and activates no traffic. Decoding is not signature verification
//! or authority.

use serde::{Deserialize, Serialize};

use crate::{CanonicalObject, Id, Text, Timestamp};

use super::{ApprovalError, Hostname, Sha256Digest, SiteId, header::Enrolled, types::*};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum DeleteVerb {
    SiteDelete,
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct DeleteEffects {
    removes_site_resources: bool,
    removes_certificate_keys: bool,
    deletes_backups: bool,
    traffic_activation: bool,
    network_access: bool,
}

const EFFECTS: DeleteEffects = DeleteEffects {
    removes_site_resources: true,
    removes_certificate_keys: true,
    deletes_backups: false,
    traffic_activation: false,
    network_access: false,
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DeletePlanRecord {
    schema_version: u16,
    plan_id: Id,
    host_id: Id,
    host_epoch: Id,
    profile_digest: Sha256Digest,
    requester: Id,
    verb: DeleteVerb,
    site_id: SiteId,
    hostname: Hostname,
    /// Schema 1 only; never `null`.
    #[serde(
        default,
        deserialize_with = "crate::codec::present",
        skip_serializing_if = "Option::is_none"
    )]
    capture_operation_id: Option<Id>,
    #[serde(deserialize_with = "crate::codec::object")]
    expected_effects: DeleteEffects,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    limitations: Vec<Text>,
}

impl DeletePlanRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        // Schema 1 names a capture; schema 2 (a proxy site) names none.
        let capture_ok = match self.schema_version {
            1 => self.capture_operation_id.is_some(),
            2 => self.capture_operation_id.is_none(),
            _ => return Err(ApprovalError::UnsupportedVersion),
        };
        if !capture_ok
            || self.expected_effects != EFFECTS
            || self.limitations.len() > 8
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidPlan);
        }
        Ok(())
    }
}

/// A closed deletion plan retaining its canonical original semantic bytes.
#[derive(Debug)]
pub struct DeletePlan {
    record: DeletePlanRecord,
    canonical: CanonicalObject,
}

impl DeletePlan {
    /// Decodes schema v1 or v2 and its intrinsic constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, DeletePlanRecord::validate)?;
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

    /// The offline site to delete.
    pub fn site_id(&self) -> &SiteId {
        &self.record.site_id
    }

    /// The site's hostname, shown to the signer; the executor compares it
    /// with its journal.
    pub fn hostname(&self) -> &Hostname {
        &self.record.hostname
    }

    /// The operation of the site's succeeded capture that a schema 1
    /// deletion requires; `None` for a schema 2 (proxy site) deletion.
    pub fn capture_operation_id(&self) -> Option<&Id> {
        self.record.capture_operation_id.as_ref()
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DeleteGrantRecord {
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
    verbs: Vec<DeleteVerb>,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    max_operations: u64,
}

impl DeleteGrantRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.issuer == self.requester
            || self.site_ids.len() != 1
            || self.verbs != [DeleteVerb::SiteDelete]
            || self.max_operations != 1
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidGrant);
        }
        Ok(())
    }
}

/// A closed deletion grant envelope; no verified signature or replay authority.
#[derive(Debug)]
pub struct DeleteGrant {
    record: DeleteGrantRecord,
    canonical: CanonicalObject,
}

impl DeleteGrant {
    /// Decodes the bounded schema and intrinsic grant constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, DeleteGrantRecord::validate)?;
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

/// Independently enrolled facts for [`check_delete_binding`]; never taken
/// from the submitted plan or grant.
pub struct DeleteBindingContext<'a> {
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
pub fn check_delete_binding(
    plan: &DeletePlan,
    grant: &DeleteGrant,
    context: &DeleteBindingContext<'_>,
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
