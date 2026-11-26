//! Product capture and restore probe plans and grants (schema v2).

use serde::{Deserialize, Serialize};

use crate::{CanonicalObject, Id, Text, Timestamp};

use super::{
    ApprovalError, CaptureRecipe, ProbeProfile, Sha256Digest, SiteId, SnapshotId,
    types::valid_window,
};

const VERSION: u16 = 2;
pub(super) const LAB_DESTINATION: &str = "lab_pc_store";

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Risk {
    Production,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Verb {
    BackupCapture,
    RestoreProbe,
}

/// The closed, verb-specific fields in a product backup plan.
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum ProductBackupTarget {
    /// Capture files and database through one fixed recipe.
    BackupCapture {
        /// Selected capture recipe.
        recipe_id: CaptureRecipe,
    },
    /// Fetch one snapshot for a contained restore probe.
    RestoreProbe {
        /// Full snapshot ID in the signed site's repository.
        snapshot_id: SnapshotId,
        /// Selected sandbox profile.
        profile_id: ProbeProfile,
    },
}

impl ProductBackupTarget {
    fn matches(&self, grant: &GrantRecord) -> bool {
        match self {
            Self::BackupCapture { .. } => grant.verbs == [Verb::BackupCapture],
            Self::RestoreProbe { snapshot_id, .. } => {
                grant.verbs == [Verb::RestoreProbe]
                    && grant.snapshot_ids.as_deref() == Some(std::slice::from_ref(snapshot_id))
            }
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct PlanRecord {
    schema_version: u16,
    plan_id: Id,
    host_id: Id,
    host_epoch: Id,
    profile_digest: Sha256Digest,
    requester: Id,
    site_id: SiteId,
    destination_id: Id,
    destination_policy_digest: Sha256Digest,
    // The shared decoder's exact value roundtrip rejects extra fields in
    // the flattened target, including fields from the other verb.
    #[serde(flatten)]
    target: ProductBackupTarget,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    limitations: Vec<Text>,
}

impl PlanRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != VERSION {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.destination_id.as_str() == LAB_DESTINATION
            || self.limitations.len() > 8
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidPlan);
        }
        Ok(())
    }
}

/// A validated product backup plan with its original canonical bytes.
#[derive(Debug)]
pub struct ProductBackupPlan {
    record: PlanRecord,
    canonical: CanonicalObject,
}

impl ProductBackupPlan {
    /// Decodes the exact schema v2 plan and its intrinsic constraints.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, PlanRecord::validate)?;
        Ok(Self { record, canonical })
    }

    /// Complete canonical plan bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.canonical.as_bytes()
    }

    /// Domain-separated digest of the complete canonical plan.
    pub fn digest(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(self.canonical.plan_domain_digest())
    }

    /// The one site named by this plan.
    pub fn site_id(&self) -> &SiteId {
        &self.record.site_id
    }

    /// The one destination named by this plan.
    pub fn destination_id(&self) -> &Id {
        &self.record.destination_id
    }

    /// The expected digest of the destination's enrolled policy.
    pub fn destination_policy_digest(&self) -> &Sha256Digest {
        &self.record.destination_policy_digest
    }

    /// The fixed verb and its target fields.
    pub fn target(&self) -> &ProductBackupTarget {
        &self.record.target
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
    verbs: Vec<Verb>,
    site_ids: Vec<SiteId>,
    destinations: Vec<Id>,
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot_ids: Option<Vec<SnapshotId>>,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    max_operations: u64,
}

impl GrantRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != VERSION {
            return Err(ApprovalError::UnsupportedVersion);
        }
        let exact_verb = matches!(
            (self.verbs.as_slice(), self.snapshot_ids.as_deref()),
            ([Verb::BackupCapture], None) | ([Verb::RestoreProbe], Some([_]))
        );
        let one_product_destination = matches!(
            self.destinations.as_slice(),
            [destination] if destination.as_str() != LAB_DESTINATION
        );
        if self.issuer == self.requester
            || !exact_verb
            || self.site_ids.len() != 1
            || !one_product_destination
            || self.max_operations != 1
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidGrant);
        }
        Ok(())
    }
}

/// A validated product backup grant before signature or authority checks.
#[derive(Debug)]
pub struct ProductBackupGrant {
    record: GrantRecord,
    canonical: CanonicalObject,
}

impl ProductBackupGrant {
    /// Decodes the exact schema v2 grant and its intrinsic constraints.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, GrantRecord::validate)?;
        Ok(Self { record, canonical })
    }

    /// Canonical bytes covered by the detached signature.
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

    /// Signed exclusive execution deadline.
    pub fn expires_at(&self) -> Timestamp {
        self.record.expires_at
    }
}

/// Independent host and signer facts for product backup binding.
pub struct ProductBackupBindingContext<'a> {
    /// Enrolled host identity.
    pub host_id: &'a Id,
    /// Enrolled host epoch.
    pub host_epoch: &'a Id,
    /// Enrolled host profile digest.
    pub profile_digest: &'a Sha256Digest,
    /// Requester resolved from the kernel peer.
    pub requester: &'a Id,
    /// Enrolled signer principal.
    pub issuer: &'a Id,
    /// Current signer and revocation policy epoch.
    pub signer_policy_epoch: &'a Id,
    /// Reliable Unix seconds, if available.
    pub now: Option<Timestamp>,
}

/// Checks pure binding. Signature, replay and destination policy checks belong
/// to the caller. Current destination policy is checked only for new admission.
pub fn check_product_backup_binding(
    plan: &ProductBackupPlan,
    grant: &ProductBackupGrant,
    context: &ProductBackupBindingContext<'_>,
) -> Result<(), ApprovalError> {
    let p = &plan.record;
    let g = &grant.record;
    if g.plan_digest != plan.digest()
        || g.plan_id != p.plan_id
        || g.host_id != p.host_id
        || g.host_epoch != p.host_epoch
        || g.profile_digest != p.profile_digest
        || g.requester != p.requester
        || g.site_ids != std::slice::from_ref(&p.site_id)
        || g.destinations != std::slice::from_ref(&p.destination_id)
        || !p.target.matches(g)
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
