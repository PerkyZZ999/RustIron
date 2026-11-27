//! Closed D-089 `site_restore` plan/grant contract.
//!
//! The plan names one served site, its hostname for the signer, the
//! restore scope, one of the site's own succeeded captures with its exact
//! snapshot, manifest, and destination, and the operation of a newer
//! safety capture of the site. The executor checks them against its own
//! journal and enrolled destination, derives every resource from the site
//! ID, and replaces the site's database, and for `files_and_database` its
//! document root. It deletes no backup and activates no traffic. Decoding
//! is not signature verification or authority.

use serde::{Deserialize, Serialize};

use crate::{CanonicalObject, Id, Text, Timestamp};

use super::{
    ApprovalError, Hostname, ProductBackupBindingContext, Sha256Digest, SiteId, SnapshotId,
    header::Enrolled,
    product_backup::LAB_DESTINATION,
    types::{Risk, valid_window},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RestoreVerb {
    SiteRestore,
}

/// What a restore replaces.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreScope {
    /// The site's database only.
    Database,
    /// The site's document root and its database.
    FilesAndDatabase,
}

impl RestoreScope {
    /// The fixed lowercase name, as in the plan.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Database => "database",
            Self::FilesAndDatabase => "files_and_database",
        }
    }
}

/// The capture a restore brings back, with its exact backup evidence.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreSource {
    /// Operation that recorded the site's succeeded capture.
    pub capture_operation_id: Id,
    /// Full restic snapshot ID.
    pub snapshot_id: SnapshotId,
    /// Digest of the capture's canonical file manifest.
    pub manifest_sha256: Sha256Digest,
    /// Enrolled product backup destination.
    pub destination_id: Id,
    /// Digest of the enrolled destination projection.
    pub destination_policy_digest: Sha256Digest,
    /// Repository configuration ID pinned for the site.
    pub repository_id: Sha256Digest,
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct RestoreEffects {
    fetches_snapshot: bool,
    replaces_database: bool,
    replaces_files: bool,
    deletes_backups: bool,
    traffic_activation: bool,
}

impl RestoreEffects {
    fn fixed(scope: RestoreScope) -> Self {
        Self {
            fetches_snapshot: true,
            replaces_database: true,
            replaces_files: scope == RestoreScope::FilesAndDatabase,
            deletes_backups: false,
            traffic_activation: false,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RestorePlanRecord {
    schema_version: u16,
    plan_id: Id,
    host_id: Id,
    host_epoch: Id,
    profile_digest: Sha256Digest,
    requester: Id,
    verb: RestoreVerb,
    site_id: SiteId,
    hostname: Hostname,
    scope: RestoreScope,
    #[serde(deserialize_with = "crate::codec::object")]
    source: RestoreSource,
    safety_capture_operation_id: Id,
    #[serde(deserialize_with = "crate::codec::object")]
    expected_effects: RestoreEffects,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    limitations: Vec<Text>,
}

impl RestorePlanRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.expected_effects != RestoreEffects::fixed(self.scope)
            || self.safety_capture_operation_id == self.source.capture_operation_id
            || self.source.destination_id.as_str() == LAB_DESTINATION
            || self.limitations.len() > 8
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidPlan);
        }
        Ok(())
    }
}

/// A closed restore plan retaining its canonical original semantic bytes.
#[derive(Debug)]
pub struct RestorePlan {
    record: RestorePlanRecord,
    canonical: CanonicalObject,
}

impl RestorePlan {
    /// Decodes schema v1 and its intrinsic constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, RestorePlanRecord::validate)?;
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

    /// The served site to restore.
    pub fn site_id(&self) -> &SiteId {
        &self.record.site_id
    }

    /// The site's hostname, shown to the signer; the executor compares it
    /// with its journal.
    pub fn hostname(&self) -> &Hostname {
        &self.record.hostname
    }

    /// What the restore replaces.
    pub fn scope(&self) -> RestoreScope {
        self.record.scope
    }

    /// The capture to bring back and its exact backup evidence.
    pub fn source(&self) -> &RestoreSource {
        &self.record.source
    }

    /// The operation of the site's newest succeeded capture, which keeps
    /// the state the restore replaces.
    pub fn safety_capture_operation_id(&self) -> &Id {
        &self.record.safety_capture_operation_id
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RestoreGrantRecord {
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
    verbs: Vec<RestoreVerb>,
    snapshot_id: SnapshotId,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    max_operations: u64,
}

impl RestoreGrantRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.issuer == self.requester
            || self.site_ids.len() != 1
            || self.verbs != [RestoreVerb::SiteRestore]
            || self.max_operations != 1
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidGrant);
        }
        Ok(())
    }
}

/// A closed restore grant envelope; no verified signature or replay authority.
#[derive(Debug)]
pub struct RestoreGrant {
    record: RestoreGrantRecord,
    canonical: CanonicalObject,
}

impl RestoreGrant {
    /// Decodes the bounded schema and intrinsic grant constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, RestoreGrantRecord::validate)?;
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

/// Pure consistency check; success confers no authority. The caller
/// checks the signature, replay, the journal, and the enrolled destination.
pub fn check_restore_binding(
    plan: &RestorePlan,
    grant: &RestoreGrant,
    context: &ProductBackupBindingContext<'_>,
) -> Result<(), ApprovalError> {
    let p = &plan.record;
    let g = &grant.record;
    if g.site_ids != [p.site_id.clone()]
        || g.snapshot_id != p.source.snapshot_id
        || g.risk_class != p.risk_class
    {
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
