use serde::{Deserialize, Serialize};

use crate::{CanonicalObject, Id, Timestamp};

use super::{ApprovalError, FixturePlan, Sha256Digest, types::*};

/// A closed grant envelope; it has no verified signature or replay authority.
#[derive(Debug)]
pub struct FixtureGrant {
    record: GrantRecord,
    canonical: CanonicalObject,
}

impl FixtureGrant {
    /// Decodes the bounded schema and intrinsic grant constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, GrantRecord::validate)?;
        Ok(Self { record, canonical })
    }

    /// Returns the complete canonical envelope that a future verifier must check.
    pub fn as_bytes(&self) -> &[u8] {
        self.canonical.as_bytes()
    }

    /// Claimed issuer; must match a separately verified signer/principal policy.
    pub fn issuer(&self) -> &Id {
        &self.record.issuer
    }

    /// Signed grant identity; uniqueness is enforced only by a durable journal.
    pub fn grant_id(&self) -> &Id {
        &self.record.grant_id
    }

    /// Signed single-use nonce; this accessor consumes nothing.
    pub fn nonce(&self) -> &Id {
        &self.record.nonce
    }

    /// Normal signed deadline; never extended by storage or retries.
    pub fn expires_at(&self) -> Timestamp {
        self.record.expires_at
    }

    /// Signed deadline for the single restore compensation (at or after expiry).
    pub fn compensation_valid_until(&self) -> Timestamp {
        self.record.compensation.valid_until
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
    resource_ids: Vec<Id>,
    verbs: Vec<Verb>,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    #[serde(deserialize_with = "crate::codec::object")]
    budgets: Budgets,
    #[serde(deserialize_with = "crate::codec::object")]
    compensation: Compensation,
    max_operations: u64,
}

impl GrantRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.issuer == self.requester
            || self.resource_ids.len() != 1
            || self.verbs != [Verb::ConfigActivate]
            || self.max_operations != 1
            || !valid_window(self.valid_from, self.expires_at)
            || !self.budgets.valid()
            || !self.compensation.valid(self.expires_at)
        {
            return Err(ApprovalError::InvalidGrant);
        }
        Ok(())
    }
}

/// Independently supplied policy facts for a pure consistency check.
///
/// Never derive these expected values from the submitted plan/grant. This type
/// does not load root policy, verify signatures, prove clock monotonicity or
/// consume a nonce. The actual executor must do all of those before effects.
pub struct FixtureBindingContext<'a> {
    /// Independently enrolled host identity.
    pub host_id: &'a Id,
    /// Independently enrolled host/recovery epoch.
    pub host_epoch: &'a Id,
    /// Independently enrolled fixture profile digest.
    pub profile_digest: &'a Sha256Digest,
    /// Authorized requesting identity from peer/policy, not claimed input.
    pub requester: &'a Id,
    /// Externally verified signer principal permitted by independent policy.
    pub issuer: &'a Id,
    /// Current independent signer/revocation policy epoch.
    pub signer_policy_epoch: &'a Id,
    /// Reliable current Unix seconds; None denies consideration of new work.
    pub now: Option<Timestamp>,
}

/// Checks fixture plan/grant/policy consistency; success confers no authority.
///
/// Replay, signatures, live registry observations, ownership, clock rollback,
/// resource limits and durable admission remain separate required checks.
pub fn check_fixture_binding(
    plan: &FixturePlan,
    grant: &FixtureGrant,
    context: &FixtureBindingContext<'_>,
) -> Result<(), ApprovalError> {
    let p = &plan.record;
    let g = &grant.record;
    if g.plan_digest != plan.digest()
        || g.plan_id != p.plan_id
        || g.host_id != p.host_id
        || g.host_epoch != p.host_epoch
        || g.profile_digest != p.profile_digest
        || g.requester != p.requester
        || g.resource_ids != p.resource_ids
        || g.risk_class != p.risk_class
        || &p.host_id != context.host_id
        || &p.host_epoch != context.host_epoch
        || &p.profile_digest != context.profile_digest
        || &p.requester != context.requester
        || &g.issuer != context.issuer
        || &g.signer_policy_epoch != context.signer_policy_epoch
        || g.budgets != p.budgets
        || g.valid_from.get() < p.valid_from.get()
        || g.expires_at.get() > p.expires_at.get()
        || g.compensation.recipe != p.compensation.recipe
        || g.compensation.generation != p.compensation.generation
        || g.compensation.max_attempts > p.compensation.max_attempts
        || g.compensation.valid_until.get() > p.compensation.valid_until.get()
    {
        return Err(ApprovalError::BindingMismatch);
    }
    let now = context.now.ok_or(ApprovalError::ClockUncertain)?;
    if now.get() < g.valid_from.get() || now.get() >= g.expires_at.get() {
        return Err(ApprovalError::OutsideValidity);
    }
    Ok(())
}
