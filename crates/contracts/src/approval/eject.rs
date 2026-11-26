//! Closed lab `site_eject` contract.
//!
//! The requester names one provisioned site and the OLS generation it expects
//! to replace. The executor hands that site's vhost over to a copy outside
//! the Rustiron include, renders the next generation itself and stops
//! managing the site; no configuration text, path or directive is
//! representable here. Nothing is deleted.

use serde::{Deserialize, Serialize};

use crate::{CanonicalObject, Id, Text, Timestamp};

use super::{
    ApprovalError, Hostname, Sha256Digest, SiteId,
    ols::{OlsCompensation, OlsObservation, OlsTarget},
    types::*,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum EjectVerb {
    SiteEject,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EjectPlanRecord {
    schema_version: u16,
    plan_id: Id,
    host_id: Id,
    host_epoch: Id,
    profile_digest: Sha256Digest,
    requester: Id,
    verb: EjectVerb,
    target: OlsTarget,
    site_id: SiteId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hostname: Option<Hostname>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    alias_hostname: Option<Hostname>,
    expected_generation: Id,
    expected_digest: Sha256Digest,
    #[serde(deserialize_with = "crate::codec::object_list")]
    observations: Vec<OlsObservation>,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    #[serde(deserialize_with = "crate::codec::object")]
    compensation: OlsCompensation,
    limitations: Vec<Text>,
}

impl EjectPlanRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        match (self.schema_version, &self.hostname, &self.alias_hostname) {
            (1, None, None) | (3, Some(_), None) => {}
            (2, Some(primary), Some(alias)) if primary != alias => {}
            (1..=3, _, _) => return Err(ApprovalError::InvalidPlan),
            _ => return Err(ApprovalError::UnsupportedVersion),
        }
        if self.observations.len() != 1
            || self.limitations.len() > 8
            || !valid_window(self.valid_from, self.expires_at)
            || !self.compensation.valid(self.expires_at)
        {
            return Err(ApprovalError::InvalidPlan);
        }
        let OlsObservation::Observed {
            generation,
            content_digest,
            observed_at,
            ..
        } = &self.observations[0];
        if generation != &self.expected_generation
            || content_digest != &self.expected_digest
            || observed_at.get() > self.valid_from.get()
            || self.valid_from.get() - observed_at.get() > MAX_OBSERVATION_AGE_SECONDS
        {
            return Err(ApprovalError::InvalidPlan);
        }
        Ok(())
    }
}

/// A closed site eject plan retaining its canonical bytes.
#[derive(Debug)]
pub struct EjectPlan {
    record: EjectPlanRecord,
    canonical: CanonicalObject,
}

impl EjectPlan {
    /// Decodes the supported eject forms and validates their intrinsic constraints.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, EjectPlanRecord::validate)?;
        Ok(Self { record, canonical })
    }

    /// Domain-separated SHA-256 of the complete validated object.
    pub fn digest(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(self.canonical.plan_domain_digest())
    }

    /// The one provisioned site being ejected.
    pub fn site_id(&self) -> &SiteId {
        &self.record.site_id
    }

    /// The exact primary and alias in a schema 2 plan.
    pub fn names(&self) -> Option<(&Hostname, &Hostname)> {
        self.record
            .hostname
            .as_ref()
            .zip(self.record.alias_hostname.as_ref())
    }

    /// D-097: the single hostname for a schema 3 static handover.
    pub fn static_hostname(&self) -> Option<&Hostname> {
        if self.record.schema_version == 3 {
            self.record.hostname.as_ref()
        } else {
            None
        }
    }

    /// Generation and digest the plan reports as current (re-observed live).
    pub fn expected(&self) -> (&Id, &Sha256Digest) {
        (
            &self.record.expected_generation,
            &self.record.expected_digest,
        )
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EjectGrantRecord {
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
    targets: Vec<OlsTarget>,
    verbs: Vec<EjectVerb>,
    site_ids: Vec<SiteId>,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    #[serde(deserialize_with = "crate::codec::object")]
    compensation: OlsCompensation,
    max_operations: u64,
}

impl EjectGrantRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.issuer == self.requester
            || self.targets != [OlsTarget::OlsLabListener]
            || self.verbs != [EjectVerb::SiteEject]
            || self.site_ids.len() != 1
            || self.max_operations != 1
            || !valid_window(self.valid_from, self.expires_at)
            || !self.compensation.valid(self.expires_at)
        {
            return Err(ApprovalError::InvalidGrant);
        }
        Ok(())
    }
}

/// A closed site eject grant; no verified signature or replay authority.
#[derive(Debug)]
pub struct EjectGrant {
    record: EjectGrantRecord,
    canonical: CanonicalObject,
}

impl EjectGrant {
    /// Decodes the bounded schema and intrinsic grant constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, EjectGrantRecord::validate)?;
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

    /// Signed deadline for the single restore-last-known-good compensation.
    pub fn compensation_valid_until(&self) -> Timestamp {
        self.record.compensation.valid_until
    }
}

/// Independently enrolled facts for [`check_eject_binding`].
pub struct EjectBindingContext<'a> {
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
pub fn check_eject_binding(
    plan: &EjectPlan,
    grant: &EjectGrant,
    context: &EjectBindingContext<'_>,
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
        || g.compensation != p.compensation
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
