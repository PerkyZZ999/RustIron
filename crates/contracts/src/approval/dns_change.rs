//! Closed D-091 `dns_change` plan/grant contract (W553).
//!
//! The plan names one owned zone and at most 16 record-set operations.
//! Each operation names an owner inside the zone, a changeable type, the
//! SHA-256 of the record set it expects now (or `absent`), and either the
//! set's new TTL and records in canonical order or its removal. The
//! executor compares every expected digest before intent and refuses the
//! whole change when one differs. SOA and NS sets are never changed here.
//! Decoding is not signature verification or authority.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{CanonicalObject, Id, Text, Timestamp};

use super::{
    ApprovalError, DnsBindingContext, MAX_TTL, MIN_TTL, RecordSet, RecordType, Sha256Digest,
    ZoneName, types::*,
};

/// The most record-set operations in one change.
pub const MAX_CHANGE_OPERATIONS: usize = 16;
/// The most records in one replaced set.
pub const MAX_SET_RECORDS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum DnsChangeVerb {
    DnsChange,
}

/// What an operation expects the set to be now.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
pub enum Expected {
    /// No set of this owner and type exists.
    Absent,
    /// The set's canonical lines have this SHA-256.
    Digest(Sha256Digest),
}

impl TryFrom<String> for Expected {
    type Error = ApprovalError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value == "absent" {
            return Ok(Self::Absent);
        }
        Sha256Digest::try_from(value).map(Self::Digest)
    }
}

impl From<Expected> for String {
    fn from(value: Expected) -> Self {
        match value {
            Expected::Absent => "absent".to_owned(),
            Expected::Digest(digest) => digest.as_str().to_owned(),
        }
    }
}

/// What an operation does to its set.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeAction {
    /// Replace the set with the given TTL and records (or create it).
    Replace,
    /// Remove the set.
    Remove,
}

/// One record-set operation, as signed.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetOperation {
    /// Absolute owner name inside the zone.
    pub owner: String,
    /// The set's type; never SOA or NS.
    #[serde(rename = "type")]
    pub kind: RecordType,
    /// The set the operation expects now.
    pub expected: Expected,
    /// Replace or remove.
    pub action: ChangeAction,
    /// The new TTL, for a replacement only; never `null`.
    #[serde(
        default,
        deserialize_with = "crate::codec::present",
        skip_serializing_if = "Option::is_none"
    )]
    pub ttl: Option<u32>,
    /// The new records in canonical order, for a replacement only; never
    /// `null`.
    #[serde(
        default,
        deserialize_with = "crate::codec::present",
        skip_serializing_if = "Option::is_none"
    )]
    pub records: Option<Vec<String>>,
}

impl SetOperation {
    fn valid(&self, zone: &ZoneName) -> bool {
        let shape = match (self.action, self.ttl, &self.records) {
            (ChangeAction::Remove, None, None) => true,
            (ChangeAction::Replace, Some(ttl), Some(records)) => {
                (MIN_TTL..=MAX_TTL).contains(&ttl)
                    && (1..=MAX_SET_RECORDS).contains(&records.len())
                    && records.windows(2).all(|pair| pair[0] < pair[1])
                    && records
                        .iter()
                        .all(|rdata| super::zone::rdata_ok(self.kind, rdata))
                    && (self.kind != RecordType::Cname || records.len() == 1)
            }
            _ => false,
        };
        // A removal of an absent set changes nothing and is refused.
        let meaningful =
            !(self.action == ChangeAction::Remove && self.expected == Expected::Absent);
        let placed = self.kind != RecordType::Cname || self.owner != zone.apex();
        self.kind.changeable()
            && super::zone::owner_in(&self.owner, zone)
            && placed
            && shape
            && meaningful
    }

    /// The set this operation leaves, or `None` for a removal.
    pub fn new_set(&self) -> Option<RecordSet> {
        match (self.action, self.ttl, &self.records) {
            (ChangeAction::Replace, Some(ttl), Some(records)) => Some(RecordSet {
                owner: self.owner.clone(),
                kind: self.kind,
                ttl,
                records: records.clone(),
            }),
            _ => None,
        }
    }

    /// Whether the operation touches a mail record set.
    pub fn is_mail(&self, zone: &ZoneName) -> bool {
        RecordSet {
            owner: self.owner.clone(),
            kind: self.kind,
            ttl: 0,
            records: Vec::new(),
        }
        .is_mail(zone)
    }
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct DnsChangeEffects {
    changes_records: bool,
    changes_soa_or_ns: bool,
    changes_other_zones: bool,
    changes_delegation: bool,
}

const EFFECTS: DnsChangeEffects = DnsChangeEffects {
    changes_records: true,
    changes_soa_or_ns: false,
    changes_other_zones: false,
    changes_delegation: false,
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DnsChangePlanRecord {
    schema_version: u16,
    plan_id: Id,
    host_id: Id,
    host_epoch: Id,
    profile_digest: Sha256Digest,
    requester: Id,
    verb: DnsChangeVerb,
    zone: ZoneName,
    #[serde(deserialize_with = "crate::codec::object_list")]
    operations: Vec<SetOperation>,
    #[serde(deserialize_with = "crate::codec::object")]
    expected_effects: DnsChangeEffects,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    limitations: Vec<Text>,
}

impl DnsChangePlanRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        let keys: BTreeSet<_> = self
            .operations
            .iter()
            .map(|operation| (operation.owner.as_str(), operation.kind))
            .collect();
        if self.expected_effects != EFFECTS
            || !(1..=MAX_CHANGE_OPERATIONS).contains(&self.operations.len())
            || keys.len() != self.operations.len()
            || !self
                .operations
                .iter()
                .all(|operation| operation.valid(&self.zone))
            || self.limitations.len() > 8
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidPlan);
        }
        Ok(())
    }
}

/// A closed record-change plan retaining its canonical original semantic bytes.
#[derive(Debug)]
pub struct DnsChangePlan {
    record: DnsChangePlanRecord,
    canonical: CanonicalObject,
}

impl DnsChangePlan {
    /// Decodes schema v1 and its intrinsic constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, DnsChangePlanRecord::validate)?;
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

    /// The zone the change applies to.
    pub fn zone(&self) -> &ZoneName {
        &self.record.zone
    }

    /// The record-set operations, in plan order.
    pub fn operations(&self) -> &[SetOperation] {
        &self.record.operations
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DnsChangeGrantRecord {
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
    verbs: Vec<DnsChangeVerb>,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    max_operations: u64,
}

impl DnsChangeGrantRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.issuer == self.requester
            || self.zones.len() != 1
            || self.verbs != [DnsChangeVerb::DnsChange]
            || self.max_operations != 1
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidGrant);
        }
        Ok(())
    }
}

/// A closed record-change grant envelope; no verified signature or replay authority.
#[derive(Debug)]
pub struct DnsChangeGrant {
    record: DnsChangeGrantRecord,
    canonical: CanonicalObject,
}

impl DnsChangeGrant {
    /// Decodes the bounded schema and intrinsic grant constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, DnsChangeGrantRecord::validate)?;
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

/// Pure consistency check; success confers no authority.
pub fn check_dns_change_binding(
    plan: &DnsChangePlan,
    grant: &DnsChangeGrant,
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
