//! Closed D-084 `site_update` plan/grant contract.
//!
//! The plan names one managed site, the digest of a pinned update recipe,
//! the plugins and themes it updates (each from an installed version to a
//! new one), and the operation of a succeeded capture of the site. The
//! executor checks every name against its own journal, the recipe in the
//! root-owned intake, and the installed code. The plan carries no file,
//! path, URL, command, or option. Decoding is not signature verification or
//! authority.

use serde::{Deserialize, Serialize};

use crate::{CanonicalObject, Id, Text, Timestamp};

use super::{ApprovalError, Sha256Digest, SiteId, header::Enrolled, types::*};

/// The most components one update may name.
pub const MAX_UPDATE_COMPONENTS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum UpdateVerb {
    SiteUpdate,
}

/// What a component is: a plugin or a theme folder of the site, or
/// WordPress core (W525, D-086).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateKind {
    /// `wp-content/plugins/<slug>`.
    Plugin,
    /// `wp-content/themes/<slug>`.
    Theme,
    /// W525 (D-086): WordPress core, slug `wordpress`: `wp-admin`,
    /// `wp-includes`, and the core files of the site root. A core update
    /// names core only.
    Core,
}

/// The one slug of a core component.
pub const CORE_SLUG: &str = "wordpress";

impl UpdateKind {
    /// The fixed lowercase name, as in the recipe manifest.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Plugin => "plugin",
            Self::Theme => "theme",
            Self::Core => "core",
        }
    }
}

/// A WordPress.org plugin or theme slug: 1 to 64 bytes of lowercase ASCII
/// letters, digits, `-` and `_`, starting with a letter or digit. It names a
/// folder below the site's `wp-content`, so it never holds `/` or `.`.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
#[serde(try_from = "String")]
pub struct ComponentSlug(String);

impl ComponentSlug {
    /// The validated slug.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ComponentSlug {
    type Error = ApprovalError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let bytes = value.as_bytes();
        let valid = (1..=64).contains(&bytes.len())
            && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
            && bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'));
        if valid {
            Ok(Self(value))
        } else {
            Err(ApprovalError::InvalidMessage)
        }
    }
}

/// A release version as WordPress headers state it: 1 to 32 bytes of ASCII
/// letters, digits, `.` and `-`, starting with a digit, with no `..`.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(try_from = "String")]
pub struct ComponentVersion(String);

impl ComponentVersion {
    /// The validated version text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ComponentVersion {
    type Error = ApprovalError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let bytes = value.as_bytes();
        let valid = (1..=32).contains(&bytes.len())
            && bytes[0].is_ascii_digit()
            && bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
            && !value.contains("..");
        if valid {
            Ok(Self(value))
        } else {
            Err(ApprovalError::InvalidMessage)
        }
    }
}

/// One plugin or theme the update replaces, in plan order.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateComponent {
    /// Plugin or theme.
    pub kind: UpdateKind,
    /// Its folder name below `wp-content/plugins` or `wp-content/themes`.
    pub slug: ComponentSlug,
    /// The version that must be installed before the update.
    pub from_version: ComponentVersion,
    /// The version the recipe holds.
    pub to_version: ComponentVersion,
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct UpdateEffects {
    changes_site_code: bool,
    restores_site_database_on_failure: bool,
    deletes_backups: bool,
    traffic_activation: bool,
    network_access: bool,
}

const EFFECTS: UpdateEffects = UpdateEffects {
    changes_site_code: true,
    restores_site_database_on_failure: true,
    deletes_backups: false,
    traffic_activation: false,
    network_access: false,
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UpdatePlanRecord {
    schema_version: u16,
    plan_id: Id,
    host_id: Id,
    host_epoch: Id,
    profile_digest: Sha256Digest,
    requester: Id,
    verb: UpdateVerb,
    site_id: SiteId,
    recipe_digest: Sha256Digest,
    capture_operation_id: Id,
    components: Vec<UpdateComponent>,
    #[serde(deserialize_with = "crate::codec::object")]
    expected_effects: UpdateEffects,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    limitations: Vec<Text>,
}

impl UpdatePlanRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        let mut names: Vec<_> = self
            .components
            .iter()
            .map(|component| (component.kind, &component.slug))
            .collect();
        names.sort();
        names.dedup();
        // W525 (D-086): a core update names core only, as `wordpress`.
        let core = self
            .components
            .iter()
            .any(|component| component.kind == UpdateKind::Core);
        let core_alone =
            !core || (self.components.len() == 1 && self.components[0].slug.as_str() == CORE_SLUG);
        if self.components.is_empty()
            || !core_alone
            || self.components.len() > MAX_UPDATE_COMPONENTS
            || names.len() != self.components.len()
            || self
                .components
                .iter()
                .any(|component| component.from_version == component.to_version)
            || self.expected_effects != EFFECTS
            || self.limitations.len() > 8
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidPlan);
        }
        Ok(())
    }
}

/// A closed update plan retaining its canonical original semantic bytes.
#[derive(Debug)]
pub struct SiteUpdatePlan {
    record: UpdatePlanRecord,
    canonical: CanonicalObject,
}

impl SiteUpdatePlan {
    /// Decodes schema v1 and its intrinsic constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, UpdatePlanRecord::validate)?;
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

    /// The managed site to update.
    pub fn site_id(&self) -> &SiteId {
        &self.record.site_id
    }

    /// SHA-256 of the recipe manifest.
    pub fn recipe_digest(&self) -> &Sha256Digest {
        &self.record.recipe_digest
    }

    /// The operation of the site's succeeded capture taken for the update.
    pub fn capture_operation_id(&self) -> &Id {
        &self.record.capture_operation_id
    }

    /// The components, in the order the update applies them.
    pub fn components(&self) -> &[UpdateComponent] {
        &self.record.components
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UpdateGrantRecord {
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
    verbs: Vec<UpdateVerb>,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    max_operations: u64,
}

impl UpdateGrantRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.issuer == self.requester
            || self.site_ids.len() != 1
            || self.verbs != [UpdateVerb::SiteUpdate]
            || self.max_operations != 1
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidGrant);
        }
        Ok(())
    }
}

/// A closed update grant envelope; no verified signature or replay authority.
#[derive(Debug)]
pub struct SiteUpdateGrant {
    record: UpdateGrantRecord,
    canonical: CanonicalObject,
}

impl SiteUpdateGrant {
    /// Decodes the bounded schema and intrinsic grant constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, UpdateGrantRecord::validate)?;
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

/// Independently enrolled facts for [`check_update_binding`]; never taken
/// from the submitted plan or grant.
pub struct UpdateBindingContext<'a> {
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
pub fn check_update_binding(
    plan: &SiteUpdatePlan,
    grant: &SiteUpdateGrant,
    context: &UpdateBindingContext<'_>,
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
