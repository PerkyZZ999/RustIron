//! Closed D-100 `site_credential_rotate` plan/grant contract (P13, W608).
//!
//! Rotates one managed WordPress site's MariaDB user password and updates its
//! host-only `0400 private/db.cnf` without ever placing any secret value in a
//! plan, grant, journal row, log, or argv. Decoding is not signature
//! verification or authority.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{CanonicalObject, Id, Text, Timestamp};

use super::{ApprovalError, Hostname, Sha256Digest, SiteId, types::*};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum CredentialRotateVerb {
    SiteCredentialRotate,
}

/// Closed credential target supported by `site_credential_rotate`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialTarget {
    /// Rotate the site's MariaDB user password and `0400 private/db.cnf`.
    MariadbUserPassword,
}

impl CredentialTarget {
    /// Stable wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MariadbUserPassword => "mariadb_user_password",
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct CredentialRotateEffects {
    rotates_db_password: bool,
    updates_db_cnf: bool,
    restarts_site_php: bool,
    traffic_activation: bool,
    network_access: bool,
    secret_in_plan: bool,
}

const EFFECTS: CredentialRotateEffects = CredentialRotateEffects {
    rotates_db_password: true,
    updates_db_cnf: true,
    restarts_site_php: true,
    traffic_activation: false,
    network_access: false,
    secret_in_plan: false,
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialRotatePlanRecord {
    schema_version: u16,
    plan_id: Id,
    host_id: Id,
    host_epoch: Id,
    profile_digest: Sha256Digest,
    requester: Id,
    verb: CredentialRotateVerb,
    site_id: SiteId,
    hostname: Hostname,
    target: CredentialTarget,
    #[serde(deserialize_with = "crate::codec::object")]
    expected_effects: CredentialRotateEffects,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    limitations: Vec<Text>,
}

impl CredentialRotatePlanRecord {
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

/// A closed per-site credential rotation plan retaining canonical semantic bytes.
#[derive(Debug)]
pub struct CredentialRotatePlan {
    record: CredentialRotatePlanRecord,
    canonical: CanonicalObject,
}

impl CredentialRotatePlan {
    /// Decodes schema v1 and its intrinsic constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, CredentialRotatePlanRecord::validate)?;
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

    /// The site whose database credentials are rotated.
    pub fn site_id(&self) -> &SiteId {
        &self.record.site_id
    }

    /// The exact hostname bound to the site.
    pub fn hostname(&self) -> &Hostname {
        &self.record.hostname
    }

    /// The closed credential target.
    pub const fn target(&self) -> CredentialTarget {
        self.record.target
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialRotateGrantRecord {
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
    verbs: Vec<CredentialRotateVerb>,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    max_operations: u64,
}

impl CredentialRotateGrantRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.issuer == self.requester
            || self.site_ids.len() != 1
            || self.verbs != [CredentialRotateVerb::SiteCredentialRotate]
            || self.max_operations != 1
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidGrant);
        }
        Ok(())
    }
}

/// A closed credential-rotation grant envelope; no verified signature or replay authority.
#[derive(Debug)]
pub struct CredentialRotateGrant {
    record: CredentialRotateGrantRecord,
    canonical: CanonicalObject,
}

impl CredentialRotateGrant {
    /// Decodes the bounded schema and intrinsic grant constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, CredentialRotateGrantRecord::validate)?;
        Ok(Self { record, canonical })
    }

    /// Complete immutable semantic bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.canonical.as_bytes()
    }

    /// Plain SHA-256 of the canonical grant bytes.
    pub fn digest(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(Sha256::digest(self.canonical.as_bytes()).into())
    }

    /// Grant identity.
    pub fn grant_id(&self) -> &Id {
        &self.record.grant_id
    }

    /// Single-use replay nonce.
    pub fn nonce(&self) -> &Id {
        &self.record.nonce
    }

    /// Declared issuer identity; not verified here.
    pub fn issuer(&self) -> &Id {
        &self.record.issuer
    }

    /// Declared signer policy epoch; not verified here.
    pub fn signer_policy_epoch(&self) -> &Id {
        &self.record.signer_policy_epoch
    }

    /// Grant expiry timestamp.
    pub const fn expires_at(&self) -> Timestamp {
        self.record.expires_at
    }
}

/// Independently supplied policy context for credential-rotation binding.
#[derive(Debug)]
pub struct CredentialRotateBindingContext<'a> {
    /// Enrolled host identity.
    pub host_id: &'a Id,
    /// Enrolled host epoch.
    pub host_epoch: &'a Id,
    /// Enrolled profile digest.
    pub profile_digest: &'a Sha256Digest,
    /// Expected signer identity.
    pub expected_issuer: &'a Id,
    /// Expected requester identity.
    pub expected_requester: &'a Id,
    /// Expected signer policy epoch.
    pub expected_signer_policy_epoch: &'a Id,
    /// Reliable wall-clock time; `None` fails closed with `ClockUncertain`.
    pub now: Option<Timestamp>,
}

/// Verifies exact plan/grant/context binding for `site_credential_rotate`.
/// Does not check signatures, replay, or host state.
pub fn check_credential_rotate_binding(
    plan: &CredentialRotatePlan,
    grant: &CredentialRotateGrant,
    context: &CredentialRotateBindingContext<'_>,
) -> Result<(), ApprovalError> {
    let now = context.now.ok_or(ApprovalError::ClockUncertain)?;
    let p = &plan.record;
    let g = &grant.record;
    if p.plan_id != g.plan_id
        || plan.digest() != g.plan_digest
        || &p.host_id != context.host_id
        || &g.host_id != context.host_id
        || &p.host_epoch != context.host_epoch
        || &g.host_epoch != context.host_epoch
        || &p.profile_digest != context.profile_digest
        || &g.profile_digest != context.profile_digest
        || &p.requester != context.expected_requester
        || &g.requester != context.expected_requester
        || &g.issuer != context.expected_issuer
        || &g.signer_policy_epoch != context.expected_signer_policy_epoch
        || g.site_ids.as_slice() != [p.site_id.clone()]
        || p.risk_class != g.risk_class
        || g.valid_from.get() < p.valid_from.get()
        || g.expires_at.get() > p.expires_at.get()
    {
        return Err(ApprovalError::BindingMismatch);
    }
    if now.get() < g.valid_from.get() || now.get() >= g.expires_at.get() {
        return Err(ApprovalError::OutsideValidity);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::{PlanKind, PreparedPlan, envelope_for_plan};

    fn sample_plan_json() -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1,
            "plan_id": "plan_rot1",
            "host_id": "host_1",
            "host_epoch": "epoch_1",
            "profile_digest": "a".repeat(64),
            "requester": "rustiron_coordinator",
            "verb": "site_credential_rotate",
            "site_id": "cp02",
            "hostname": "cp02.example.test",
            "target": "mariadb_user_password",
            "expected_effects": {
                "rotates_db_password": true,
                "updates_db_cnf": true,
                "restarts_site_php": true,
                "traffic_activation": false,
                "network_access": false,
                "secret_in_plan": false
            },
            "risk_class": "lab_only",
            "valid_from": 1_000,
            "expires_at": 1_900,
            "limitations": ["lab signer; host generates random password locally"]
        })
    }

    #[test]
    fn decodes_binds_and_builds_envelope() {
        let plan_bytes = sample_plan_json().to_string();
        let plan = CredentialRotatePlan::decode(plan_bytes.as_bytes()).expect("valid plan");
        assert_eq!(plan.site_id().as_str(), "cp02");
        assert_eq!(plan.hostname().as_str(), "cp02.example.test");
        assert_eq!(plan.target(), CredentialTarget::MariadbUserPassword);

        let prepared = PreparedPlan::decode(plan.as_bytes()).expect("prepared");
        assert_eq!(prepared.kind(), PlanKind::SiteCredentialRotate);
        let env = envelope_for_plan(plan.as_bytes()).expect("envelope");
        assert_eq!(env.verb, "site_credential_rotate");
        assert!(!env.all_served_sites);
        assert_eq!(env.ols_reloads, 0);

        let grant_json = serde_json::json!({
            "schema_version": 1,
            "grant_id": "grant_rot1",
            "nonce": "nonce_rot1",
            "plan_id": "plan_rot1",
            "plan_digest": plan.digest().as_str(),
            "host_id": "host_1",
            "host_epoch": "epoch_1",
            "profile_digest": "a".repeat(64),
            "issuer": "lab_agent",
            "requester": "rustiron_coordinator",
            "signer_policy_epoch": "policy_3",
            "site_ids": ["cp02"],
            "verbs": ["site_credential_rotate"],
            "risk_class": "lab_only",
            "valid_from": 1_000,
            "expires_at": 1_900,
            "max_operations": 1
        });
        let grant =
            CredentialRotateGrant::decode(grant_json.to_string().as_bytes()).expect("valid grant");
        let ctx = CredentialRotateBindingContext {
            host_id: &Id::try_from("host_1".to_owned()).unwrap(),
            host_epoch: &Id::try_from("epoch_1".to_owned()).unwrap(),
            profile_digest: &Sha256Digest::try_from("a".repeat(64)).unwrap(),
            expected_issuer: &Id::try_from("lab_agent".to_owned()).unwrap(),
            expected_requester: &Id::try_from("rustiron_coordinator".to_owned()).unwrap(),
            expected_signer_policy_epoch: &Id::try_from("policy_3".to_owned()).unwrap(),
            now: Some(Timestamp::try_from(1_500).unwrap()),
        };
        check_credential_rotate_binding(&plan, &grant, &ctx).expect("binding ok");
    }

    #[test]
    fn refuses_secret_in_plan_or_unknown_fields() {
        let mut bad = sample_plan_json();
        bad["expected_effects"]["secret_in_plan"] = serde_json::json!(true);
        assert_eq!(
            CredentialRotatePlan::decode(bad.to_string().as_bytes()).unwrap_err(),
            ApprovalError::InvalidPlan
        );

        let mut extra = sample_plan_json();
        extra["password"] = serde_json::json!("leaked");
        assert_eq!(
            CredentialRotatePlan::decode(extra.to_string().as_bytes()).unwrap_err(),
            ApprovalError::InvalidMessage
        );
    }
}
