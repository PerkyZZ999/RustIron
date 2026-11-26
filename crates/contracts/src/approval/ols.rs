//! Closed lab `config_activate` contract (schema v1) for the OLS listener.
//!
//! The requester names only which provisioned sites the lab listener serves
//! and the generation it expects to replace. The executor renders the
//! generation itself from enrolled policy and its own provision records; no
//! configuration text, path or directive is representable here.
//!
//! Plan schema v2 (W368, D-028 item 2) adds `page_cache`: one served site
//! opts in to the plugin-driven page cache with one approved plugin recipe.
//! The opt-in names no file, command, option text or path; the executor
//! derives every effect from the recipe. The grant stays schema v1 and binds
//! the opt-in through `plan_digest`.
//!
//! Plan schema v3 (W370) adds `page_cache_opt_out`: one opted-in site turns
//! the page cache off. It names the site and the recipe only; the executor
//! renders the site without cache storage, deactivates the plugin as the site
//! and empties the site's own cache storage. A later v2 plan re-enables it.

use serde::{Deserialize, Serialize};

use crate::{CanonicalObject, Id, Text, Timestamp};

use super::{ApprovalError, Sha256Digest, SiteId, types::*};

const MAX_SITES: usize = 32;
/// Plan schema without a page-cache opt-in.
const V1: u16 = 1;
/// Plan schema with one page-cache opt-in.
const V2: u16 = 2;
/// Plan schema with one page-cache opt-out (W370).
const V3: u16 = 3;

/// Approved page-cache plugin recipes; each maps to pins the executor
/// compiles in (plugin archive, per-file checksum list, fixed settings).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PageCacheRecipe {
    /// LiteSpeed Cache 7.9.3 from WordPress.org, installed and activated as
    /// the site identity with the fixed settings (page cache still off).
    #[serde(rename = "litespeed_cache_793_v1")]
    LitespeedCache793V1,
    /// W395 (D-044): the same pinned plugin with the fixed settings and lock
    /// that turn the page cache on (`cache` 1). Its `recipe_digest` is the
    /// SHA-256 of the executor's recipe manifest, which names the plugin
    /// archive, the checksum list, the settings and the lock by digest.
    #[serde(rename = "litespeed_cache_793_cache_on_v1")]
    LitespeedCache793CacheOnV1,
}

/// One site's opt-in to the plugin-driven page cache (schema v2 only).
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PageCacheOptIn {
    site_id: SiteId,
    recipe_id: PageCacheRecipe,
    recipe_digest: Sha256Digest,
}

impl PageCacheOptIn {
    /// The opted-in site; always one of the plan's served sites.
    pub fn site_id(&self) -> &SiteId {
        &self.site_id
    }

    /// The approved plugin recipe.
    pub fn recipe(&self) -> PageCacheRecipe {
        self.recipe_id
    }

    /// The recipe artifact digest the plan claims; the executor compares it
    /// with its own pin.
    pub fn recipe_digest(&self) -> &Sha256Digest {
        &self.recipe_digest
    }
}

/// One opted-in site's opt-out of the page cache (schema v3 only, W370).
/// No path, command or setting: the executor derives the storage to empty
/// and the plugin to deactivate from the site and the recipe.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PageCacheOptOut {
    site_id: SiteId,
    recipe_id: PageCacheRecipe,
}

impl PageCacheOptOut {
    /// The site that turns the page cache off; always one of the plan's
    /// served sites.
    pub fn site_id(&self) -> &SiteId {
        &self.site_id
    }

    /// The recipe the site opted in with; the executor compares it with the
    /// journaled opt-in.
    pub fn recipe(&self) -> PageCacheRecipe {
        self.recipe_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum OlsVerb {
    ConfigActivate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum OlsTarget {
    OlsLabListener,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum OlsRecipe {
    OlsRestoreLkgV1,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum OlsObservation {
    Observed {
        generation: Id,
        content_digest: Sha256Digest,
        observed_at: Timestamp,
        source: OlsReportSource,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum OlsReportSource {
    ReportedRegistry,
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct OlsCompensation {
    recipe: OlsRecipe,
    max_attempts: u64,
    pub(super) valid_until: Timestamp,
}

impl OlsCompensation {
    pub(super) fn valid(&self, expires_at: Timestamp) -> bool {
        self.max_attempts == 1
            && self.valid_until.get() >= expires_at.get()
            && self.valid_until.get() - expires_at.get() <= 300
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OlsPlanRecord {
    schema_version: u16,
    plan_id: Id,
    host_id: Id,
    host_epoch: Id,
    profile_digest: Sha256Digest,
    requester: Id,
    verb: OlsVerb,
    target: OlsTarget,
    site_ids: Vec<SiteId>,
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
    /// Schema v2 only; never `null`.
    #[serde(
        default,
        deserialize_with = "crate::codec::present_object",
        skip_serializing_if = "Option::is_none"
    )]
    page_cache: Option<PageCacheOptIn>,
    /// Schema v3 only; never `null` (W370).
    #[serde(
        default,
        deserialize_with = "crate::codec::present_object",
        skip_serializing_if = "Option::is_none"
    )]
    page_cache_opt_out: Option<PageCacheOptOut>,
}

fn sorted_unique(sites: &[SiteId]) -> bool {
    !sites.is_empty()
        && sites.len() <= MAX_SITES
        && sites
            .windows(2)
            .all(|pair| pair[0].as_str() < pair[1].as_str())
}

impl OlsPlanRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        match (
            self.schema_version,
            &self.page_cache,
            &self.page_cache_opt_out,
        ) {
            (V1, None, None) => {}
            (V2, Some(opt_in), None) if self.site_ids.contains(&opt_in.site_id) => {}
            (V3, None, Some(opt_out)) if self.site_ids.contains(&opt_out.site_id) => {}
            (V1 | V2 | V3, _, _) => return Err(ApprovalError::InvalidPlan),
            _ => return Err(ApprovalError::UnsupportedVersion),
        }
        if !sorted_unique(&self.site_ids)
            || self.observations.len() != 1
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

/// A closed OLS activation plan retaining its canonical bytes.
#[derive(Debug)]
pub struct OlsPlan {
    record: OlsPlanRecord,
    canonical: CanonicalObject,
}

impl OlsPlan {
    /// Decodes schema v1, v2 or v3 and intrinsic constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, OlsPlanRecord::validate)?;
        Ok(Self { record, canonical })
    }

    /// Plan schema version: 1, 2 with a page-cache opt-in, or 3 with a
    /// page-cache opt-out.
    pub fn schema_version(&self) -> u16 {
        self.record.schema_version
    }

    /// The page-cache opt-in of a v2 plan; `None` for v1.
    pub fn page_cache(&self) -> Option<&PageCacheOptIn> {
        self.record.page_cache.as_ref()
    }

    /// The page-cache opt-out of a v3 plan; `None` for v1 and v2 (W370).
    pub fn page_cache_opt_out(&self) -> Option<&PageCacheOptOut> {
        self.record.page_cache_opt_out.as_ref()
    }

    /// Domain-separated SHA-256 of the complete validated object.
    pub fn digest(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(self.canonical.plan_domain_digest())
    }

    /// Sites the listener must serve besides the enrolled adopted ones, sorted.
    pub fn site_ids(&self) -> &[SiteId] {
        &self.record.site_ids
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
struct OlsGrantRecord {
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
    verbs: Vec<OlsVerb>,
    site_ids: Vec<SiteId>,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    #[serde(deserialize_with = "crate::codec::object")]
    compensation: OlsCompensation,
    max_operations: u64,
}

impl OlsGrantRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.issuer == self.requester
            || self.targets != [OlsTarget::OlsLabListener]
            || self.verbs != [OlsVerb::ConfigActivate]
            || !sorted_unique(&self.site_ids)
            || self.max_operations != 1
            || !valid_window(self.valid_from, self.expires_at)
            || !self.compensation.valid(self.expires_at)
        {
            return Err(ApprovalError::InvalidGrant);
        }
        Ok(())
    }
}

/// A closed OLS activation grant; no verified signature or replay authority.
#[derive(Debug)]
pub struct OlsGrant {
    record: OlsGrantRecord,
    canonical: CanonicalObject,
}

impl OlsGrant {
    /// Decodes the bounded schema and intrinsic grant constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, OlsGrantRecord::validate)?;
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

/// Independently enrolled facts for [`check_ols_binding`].
pub struct OlsBindingContext<'a> {
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
pub fn check_ols_binding(
    plan: &OlsPlan,
    grant: &OlsGrant,
    context: &OlsBindingContext<'_>,
) -> Result<(), ApprovalError> {
    let p = &plan.record;
    let g = &grant.record;
    if g.plan_digest != plan.digest()
        || g.plan_id != p.plan_id
        || g.host_id != p.host_id
        || g.host_epoch != p.host_epoch
        || g.profile_digest != p.profile_digest
        || g.requester != p.requester
        || g.site_ids != p.site_ids
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
