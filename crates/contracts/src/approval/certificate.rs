//! Closed D-059 `certificate_issue` plan/grant contract.
//!
//! The plan names one managed site and its hostname. Schema 3 also names
//! one exact alias for offline review (D-077). The CA comes from the
//! enrolled policy, never from the plan. The executor checks the site and
//! hostname against its journal; the admin helper creates the site's HTTP-01
//! webroot, runs certbot as `rustiron-acme`, checks the chain, and installs it
//! under `/etc/rustiron-tls`. Serving it is a separate `config_activate`.
//! Decoding is not signature verification or authority.

use serde::{Deserialize, Serialize};

use crate::{CanonicalObject, Id, Text, Timestamp};

use super::{ApprovalError, Hostname, Sha256Digest, SiteId, header::Enrolled, types::*};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum CertificateVerb {
    CertificateIssue,
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct CertificateEffects {
    creates_challenge_webroot: bool,
    contacts_enrolled_ca: bool,
    installs_certificate: bool,
    traffic_activation: bool,
    dns_change: bool,
}

const EFFECTS: CertificateEffects = CertificateEffects {
    creates_challenge_webroot: true,
    contacts_enrolled_ca: true,
    installs_certificate: true,
    traffic_activation: false,
    dns_change: false,
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CertificatePlanRecord {
    schema_version: u16,
    plan_id: Id,
    host_id: Id,
    host_epoch: Id,
    profile_digest: Sha256Digest,
    requester: Id,
    verb: CertificateVerb,
    site_id: SiteId,
    hostname: Hostname,
    #[serde(
        default,
        deserialize_with = "crate::codec::present",
        skip_serializing_if = "Option::is_none"
    )]
    alias_hostname: Option<Hostname>,
    #[serde(deserialize_with = "crate::codec::object")]
    expected_effects: CertificateEffects,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    limitations: Vec<Text>,
    /// D-060 (schemas 2 and 3): renewal stays authorized until this time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    renew_until: Option<Timestamp>,
}

/// D-060: the longest standing renewal one issuance may grant.
const MAX_RENEWAL_SECONDS: u64 = 366 * 24 * 3600;

impl CertificatePlanRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        let valid_renewal = |until: Timestamp| {
            until.get() > self.valid_from.get()
                && until.get() - self.valid_from.get() <= MAX_RENEWAL_SECONDS
        };
        let scope_ok = match (self.schema_version, &self.alias_hostname, self.renew_until) {
            (1, None, None) => true,
            (2, None, Some(until)) => valid_renewal(until),
            (3, Some(alias), until) => alias != &self.hostname && until.is_none_or(valid_renewal),
            (1..=3, _, _) => false,
            _ => return Err(ApprovalError::UnsupportedVersion),
        };
        if !scope_ok
            || self.expected_effects != EFFECTS
            || self.limitations.len() > 8
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidPlan);
        }
        Ok(())
    }
}

/// A closed certificate plan retaining its canonical original semantic bytes.
#[derive(Debug)]
pub struct CertificatePlan {
    record: CertificatePlanRecord,
    canonical: CanonicalObject,
}

impl CertificatePlan {
    /// Decodes schemas 1 to 3 and checks their intrinsic constraints.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, CertificatePlanRecord::validate)?;
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

    /// The managed site.
    pub fn site_id(&self) -> &SiteId {
        &self.record.site_id
    }

    /// The site's primary hostname and certificate lineage name.
    pub fn hostname(&self) -> &Hostname {
        &self.record.hostname
    }

    /// D-077: the exact additional DNS name in a schema 3 plan.
    pub fn alias_hostname(&self) -> Option<&Hostname> {
        self.record.alias_hostname.as_ref()
    }

    /// D-060: until when renewal is authorized. `None` is one-time issuance.
    pub fn renew_until(&self) -> Option<Timestamp> {
        self.record.renew_until
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CertificateGrantRecord {
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
    verbs: Vec<CertificateVerb>,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    max_operations: u64,
}

impl CertificateGrantRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.issuer == self.requester
            || self.site_ids.len() != 1
            || self.verbs != [CertificateVerb::CertificateIssue]
            || self.max_operations != 1
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidGrant);
        }
        Ok(())
    }
}

/// A closed certificate grant envelope; no verified signature or replay authority.
#[derive(Debug)]
pub struct CertificateGrant {
    record: CertificateGrantRecord,
    canonical: CanonicalObject,
}

impl CertificateGrant {
    /// Decodes the bounded schema and intrinsic grant constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, CertificateGrantRecord::validate)?;
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

/// Independently enrolled facts for [`check_certificate_binding`]; never taken
/// from the submitted plan or grant.
pub struct CertificateBindingContext<'a> {
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
pub fn check_certificate_binding(
    plan: &CertificatePlan,
    grant: &CertificateGrant,
    context: &CertificateBindingContext<'_>,
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
