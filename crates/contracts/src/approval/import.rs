//! Closed D-053 `site_import` plan/grant contract.
//!
//! Schema 2 (D-070) also signs the source hostname, for an import that serves
//! the site under another hostname. D-074 adds the recipe `import_static_v1`
//! for a static site with a dump size of 0. Schema 3 (D-075) also signs
//! one exact alias for offline review of a static import.
//!
//! The plan binds the exact export archive and the results of the W433 dry
//! run: the manifest digest, file count and bytes, dump size, and target PHP
//! version. The executor derives every path, account, database, and level from
//! `site_id` and enrolled policy, as for `site_provision`. Quota limits are
//! always signed and must fit the enrolled cap. Decoding is not signature
//! verification or authority.

use serde::{Deserialize, Serialize};

use crate::migration::PhpVersion;
use crate::{CanonicalObject, Id, Text, Timestamp};

use super::{ApprovalError, Hostname, Sha256Digest, SiteId, SiteQuotaLimits, types::*};

/// The export worker's entry limit (W435).
const MAX_FILE_ENTRIES: u64 = 200_000;
/// The D-034 dump ceiling.
const MAX_DUMP_BYTES: u64 = 2 << 30;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ImportVerb {
    SiteImport,
}

/// The import recipes: a site identity without an application, with its
/// database dump (`import_v1`) or with none (D-074, `import_static_v1`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ImportRecipeId {
    ImportV1,
    ImportStaticV1,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ImportReportSource {
    ReportedRegistry,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum ImportObservation {
    Absent {
        site_id: SiteId,
        hostname: Hostname,
        observed_at: Timestamp,
        source: ImportReportSource,
    },
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ImportEffects {
    creates_account: bool,
    creates_database: bool,
    imports_foreign_content: bool,
    traffic_activation: bool,
    network_access: bool,
    sets_quota: bool,
}

const EFFECTS: ImportEffects = ImportEffects {
    creates_account: true,
    creates_database: true,
    imports_foreign_content: true,
    traffic_activation: false,
    network_access: false,
    sets_quota: true,
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ImportPlanRecord {
    schema_version: u16,
    plan_id: Id,
    host_id: Id,
    host_epoch: Id,
    profile_digest: Sha256Digest,
    requester: Id,
    verb: ImportVerb,
    site_id: SiteId,
    hostname: Hostname,
    /// D-070: schema 2 only. The source site's hostname when the import
    /// serves the site under another one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_hostname: Option<Hostname>,
    /// D-075: one additional serving name in a schema 3 static plan.
    #[serde(
        default,
        deserialize_with = "crate::codec::present",
        skip_serializing_if = "Option::is_none"
    )]
    alias_hostname: Option<Hostname>,
    recipe_id: ImportRecipeId,
    archive_sha256: Sha256Digest,
    manifest_sha256: Sha256Digest,
    file_entries: u64,
    file_bytes: u64,
    dump_bytes: u64,
    target_php: PhpVersion,
    #[serde(deserialize_with = "crate::codec::object")]
    quota_limits: SiteQuotaLimits,
    #[serde(deserialize_with = "crate::codec::object_list")]
    observations: Vec<ImportObservation>,
    #[serde(deserialize_with = "crate::codec::object")]
    expected_effects: ImportEffects,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    limitations: Vec<Text>,
}

impl ImportPlanRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        let hostname_scope_ok = match (
            self.schema_version,
            &self.source_hostname,
            &self.alias_hostname,
        ) {
            (1, None, None) => true,
            (2, Some(source), None) => source != &self.hostname,
            (3, None, Some(alias)) => {
                alias != &self.hostname && self.recipe_id == ImportRecipeId::ImportStaticV1
            }
            (1..=3, _, _) => false,
            _ => return Err(ApprovalError::UnsupportedVersion),
        };
        if !hostname_scope_ok {
            return Err(ApprovalError::InvalidPlan);
        }
        // D-074: a static import has no dump and keeps its source hostname;
        // a WordPress import has one dump within the D-034 ceiling.
        let dump_ok = match self.recipe_id {
            ImportRecipeId::ImportV1 => (1..=MAX_DUMP_BYTES).contains(&self.dump_bytes),
            ImportRecipeId::ImportStaticV1 => {
                self.dump_bytes == 0 && self.source_hostname.is_none()
            }
        };
        let limits = self.quota_limits;
        // W452-F1: during the import the site holds the archive copy (at most
        // about the file and dump bytes) next to the extracted tree or the
        // installed one, so the limits must hold twice the content.
        let content = self.file_bytes.saturating_add(self.dump_bytes);
        let fits_quota = content.saturating_mul(2) <= limits.block_hard_kib().saturating_mul(1024)
            && self.file_entries < limits.inode_hard();
        if !limits.in_bounds()
            || !(1..=MAX_FILE_ENTRIES).contains(&self.file_entries)
            || !dump_ok
            || !fits_quota
            || self.expected_effects != EFFECTS
            || self.observations.len() != 1
            || self.limitations.len() > 8
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidPlan);
        }
        let ImportObservation::Absent {
            site_id,
            hostname,
            observed_at,
            ..
        } = &self.observations[0];
        if site_id != &self.site_id
            || hostname != &self.hostname
            || observed_at.get() > self.valid_from.get()
            || self.valid_from.get() - observed_at.get() > MAX_OBSERVATION_AGE_SECONDS
        {
            return Err(ApprovalError::InvalidPlan);
        }
        Ok(())
    }
}

/// A closed import plan retaining its canonical original semantic bytes.
#[derive(Debug)]
pub struct ImportPlan {
    record: ImportPlanRecord,
    canonical: CanonicalObject,
}

impl ImportPlan {
    /// Decodes schemas 1 to 3 and checks their intrinsic constraints.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, ImportPlanRecord::validate)?;
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

    /// Requested site identifier.
    pub fn site_id(&self) -> &SiteId {
        &self.record.site_id
    }

    /// Requested hostname: the one the imported site is served under.
    pub fn hostname(&self) -> &Hostname {
        &self.record.hostname
    }

    /// D-070: the source site's hostname when it differs from
    /// [`Self::hostname`] (schema 2).
    pub fn source_hostname(&self) -> Option<&Hostname> {
        self.record.source_hostname.as_ref()
    }

    /// D-075: the additional exact serving name (schema 3).
    pub fn alias_hostname(&self) -> Option<&Hostname> {
        self.record.alias_hostname.as_ref()
    }

    /// SHA-256 of the intake archive.
    pub fn archive_sha256(&self) -> &Sha256Digest {
        &self.record.archive_sha256
    }

    /// Manifest digest the extracted tree must match.
    pub fn manifest_sha256(&self) -> &Sha256Digest {
        &self.record.manifest_sha256
    }

    /// Entries the extracted home tree must hold.
    pub fn file_entries(&self) -> u64 {
        self.record.file_entries
    }

    /// Regular-file bytes the extracted home tree must hold.
    pub fn file_bytes(&self) -> u64 {
        self.record.file_bytes
    }

    /// Size of the one database dump; 0 for a static site (D-074).
    pub fn dump_bytes(&self) -> u64 {
        self.record.dump_bytes
    }

    /// D-074: whether the plan imports a static site (no database content).
    pub fn is_static(&self) -> bool {
        self.record.recipe_id == ImportRecipeId::ImportStaticV1
    }

    /// LSPHP version for the site.
    pub fn target_php(&self) -> &PhpVersion {
        &self.record.target_php
    }

    /// Signed quota limits.
    pub fn quota_limits(&self) -> SiteQuotaLimits {
        self.record.quota_limits
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ImportGrantRecord {
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
    verbs: Vec<ImportVerb>,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    max_operations: u64,
}

impl ImportGrantRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.issuer == self.requester
            || self.site_ids.len() != 1
            || self.verbs != [ImportVerb::SiteImport]
            || self.max_operations != 1
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidGrant);
        }
        Ok(())
    }
}

/// A closed import grant envelope; no verified signature or replay authority.
#[derive(Debug)]
pub struct ImportGrant {
    record: ImportGrantRecord,
    canonical: CanonicalObject,
}

impl ImportGrant {
    /// Decodes the bounded schema and intrinsic grant constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, ImportGrantRecord::validate)?;
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

/// Independently enrolled facts for [`check_import_binding`]; never taken
/// from the submitted plan or grant.
pub struct ImportBindingContext<'a> {
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
    /// LSPHP versions installed in the enrolled profile.
    pub php_versions: &'a [PhpVersion],
    /// Reliable current Unix seconds; `None` denies.
    pub now: Option<Timestamp>,
    /// Enrolled per-site quota cap; `None` refuses every import.
    pub quota_cap: Option<SiteQuotaLimits>,
}

/// Pure consistency check; success confers no authority.
pub fn check_import_binding(
    plan: &ImportPlan,
    grant: &ImportGrant,
    context: &ImportBindingContext<'_>,
) -> Result<(), ApprovalError> {
    let p = &plan.record;
    let g = &grant.record;
    let quota_bound = context
        .quota_cap
        .is_some_and(|cap| p.quota_limits.within(&cap));
    if g.plan_digest != plan.digest()
        || g.plan_id != p.plan_id
        || g.host_id != p.host_id
        || g.host_epoch != p.host_epoch
        || g.profile_digest != p.profile_digest
        || g.requester != p.requester
        || g.site_ids != [p.site_id.clone()]
        || g.risk_class != p.risk_class
        || &p.host_id != context.host_id
        || &p.host_epoch != context.host_epoch
        || &p.profile_digest != context.profile_digest
        || &p.requester != context.requester
        || &g.issuer != context.issuer
        || &g.signer_policy_epoch != context.signer_policy_epoch
        || !context.php_versions.contains(&p.target_php)
        || !quota_bound
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
