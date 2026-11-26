//! Closed D-091 `dns_zone_import` plan/grant contract (W551).
//!
//! The plan names one zone, the SHA-256 of its canonical zone file, and the
//! file's record-set count. A zone exceeds the bound on signed plan bytes,
//! so the file itself waits in a root-owned intake folder; the executor
//! parses it with [`super::parse_zone`] and checks the digest and count
//! before intent. The import creates the zone on the host's PowerDNS and
//! changes no other zone, no delegation, and no website. Decoding is not
//! signature verification or authority.

use serde::{Deserialize, Serialize};

use crate::{CanonicalObject, Id, Text, Timestamp};

use super::{ApprovalError, Sha256Digest, ZoneName, types::*};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum DnsImportVerb {
    DnsZoneImport,
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct DnsImportEffects {
    creates_zone: bool,
    answers_queries: bool,
    changes_other_zones: bool,
    changes_delegation: bool,
}

const EFFECTS: DnsImportEffects = DnsImportEffects {
    creates_zone: true,
    answers_queries: true,
    changes_other_zones: false,
    changes_delegation: false,
};

/// The most record sets one zone import may hold.
pub const MAX_IMPORT_RECORD_SETS: u32 = super::MAX_ZONE_LINES as u32;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DnsImportPlanRecord {
    schema_version: u16,
    plan_id: Id,
    host_id: Id,
    host_epoch: Id,
    profile_digest: Sha256Digest,
    requester: Id,
    verb: DnsImportVerb,
    zone: ZoneName,
    zone_sha256: Sha256Digest,
    record_sets: u32,
    #[serde(deserialize_with = "crate::codec::object")]
    expected_effects: DnsImportEffects,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    limitations: Vec<Text>,
}

impl DnsImportPlanRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.expected_effects != EFFECTS
            || !(1..=MAX_IMPORT_RECORD_SETS).contains(&self.record_sets)
            || self.limitations.len() > 8
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidPlan);
        }
        Ok(())
    }
}

/// A closed zone-import plan retaining its canonical original semantic bytes.
#[derive(Debug)]
pub struct DnsImportPlan {
    record: DnsImportPlanRecord,
    canonical: CanonicalObject,
}

impl DnsImportPlan {
    /// Decodes schema v1 and its intrinsic constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, DnsImportPlanRecord::validate)?;
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

    /// The zone to create.
    pub fn zone(&self) -> &ZoneName {
        &self.record.zone
    }

    /// The SHA-256 of the canonical zone file.
    pub fn zone_sha256(&self) -> &Sha256Digest {
        &self.record.zone_sha256
    }

    /// The number of record sets in the zone file.
    pub fn record_sets(&self) -> u32 {
        self.record.record_sets
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DnsImportGrantRecord {
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
    zones: Vec<ZoneName>,
    verbs: Vec<DnsImportVerb>,
    zone_sha256: Sha256Digest,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    max_operations: u64,
}

impl DnsImportGrantRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.issuer == self.requester
            || self.zones.len() != 1
            || self.verbs != [DnsImportVerb::DnsZoneImport]
            || self.max_operations != 1
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidGrant);
        }
        Ok(())
    }
}

/// A closed zone-import grant envelope; no verified signature or replay authority.
#[derive(Debug)]
pub struct DnsImportGrant {
    record: DnsImportGrantRecord,
    canonical: CanonicalObject,
}

impl DnsImportGrant {
    /// Decodes the bounded schema and intrinsic grant constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, DnsImportGrantRecord::validate)?;
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

/// Independently enrolled facts for [`check_dns_import_binding`]; never
/// taken from the submitted plan or grant.
pub struct DnsBindingContext<'a> {
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
pub fn check_dns_import_binding(
    plan: &DnsImportPlan,
    grant: &DnsImportGrant,
    context: &DnsBindingContext<'_>,
) -> Result<(), ApprovalError> {
    let p = &plan.record;
    let g = &grant.record;
    if g.plan_digest != plan.digest()
        || g.plan_id != p.plan_id
        || g.host_id != p.host_id
        || g.host_epoch != p.host_epoch
        || g.profile_digest != p.profile_digest
        || g.requester != p.requester
        || g.zones != [p.zone.clone()]
        || g.zone_sha256 != p.zone_sha256
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
