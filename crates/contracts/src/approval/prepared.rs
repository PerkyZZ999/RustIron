//! Validated plan identity and canonical bytes; no authority or persistence.

use super::{
    AppDeployPlan, AppLifecyclePlan, AppProvisionPlan, ApprovalError, CapturePlan, CertificatePlan,
    CloneScrubPlan, CredentialRotatePlan, DeletePlan, DnsChangePlan, DnsImportPlan, EjectPlan,
    ImportPlan, OlsPlan, ProbePlan, ProductBackupPlan, ProxyPlan, QuotaPlan, ReadoptPlan,
    RestorePlan, RetirePlan, ScrubPlan, Sha256Digest, SiteClonePlan, SitePlan, SiteUpdatePlan,
    StandingCapturePlan,
};
use crate::{CanonicalObject, Id};
use serde::Deserialize;

/// A supported operation plan kind.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PlanKind {
    /// Provision one site.
    SiteProvision,
    /// Activate an OLS generation.
    ConfigActivate,
    /// Eject one managed site.
    SiteEject,
    /// Capture a site backup.
    BackupCapture,
    /// Probe a restored snapshot.
    RestoreProbe,
    /// Re-adopt one site or the live OLS generation after an epoch
    /// rotation (D-030); records ownership only.
    SiteReadopt,
    /// Import one site from an incumbent export (D-053).
    SiteImport,
    /// Remove an ended import's leftover secrets (D-057).
    ImportScrub,
    /// Issue and install one site's certificate (D-059).
    CertificateIssue,
    /// Clone one completed capture into a fresh staging site (D-078).
    SiteClone,
    /// Retire one quarantined site (D-080).
    SiteRetire,
    /// Update one site's plugins and themes from a pinned recipe (D-084).
    SiteUpdate,
    /// Delete one live site that is offline (D-085).
    SiteDelete,
    /// Change one site's hard quota limits (D-088).
    SiteQuota,
    /// Remove a quarantined clone's leftovers (D-078 signed clone scrub).
    CloneScrub,
    /// Restore one served site from one of its own captures (D-089).
    SiteRestore,
    /// Create one DNS zone from a canonical zone file (D-091).
    DnsZoneImport,
    /// Change record sets of one owned DNS zone (D-091).
    DnsChange,
    /// Provision one site that forwards to loopback ports (D-095).
    ProxySiteProvision,
    /// Provision one confined Node.js or Bun app site behind a loopback proxy (D-099).
    AppProvision,
    /// Activate one signed prebuilt release bundle for an app site (D-099).
    AppDeploy,
    /// Start, stop, or restart an enrolled app's systemd unit(s) (D-099).
    AppLifecycle,
    /// Rotate one managed WordPress site's MariaDB credentials (D-100).
    SiteCredentialRotate,
}

impl PlanKind {
    /// The closed wire name for this kind.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SiteProvision => "site_provision",
            Self::ConfigActivate => "config_activate",
            Self::SiteEject => "site_eject",
            Self::BackupCapture => "backup_capture",
            Self::RestoreProbe => "restore_probe",
            Self::SiteReadopt => "site_readopt",
            Self::SiteImport => "site_import",
            Self::ImportScrub => "import_scrub",
            Self::CertificateIssue => "certificate_issue",
            Self::SiteClone => "site_clone",
            Self::SiteRetire => "site_retire",
            Self::SiteUpdate => "site_update",
            Self::SiteDelete => "site_delete",
            Self::SiteQuota => "site_quota",
            Self::CloneScrub => "clone_scrub",
            Self::SiteRestore => "site_restore",
            Self::DnsZoneImport => "dns_zone_import",
            Self::DnsChange => "dns_change",
            Self::ProxySiteProvision => "proxy_site_provision",
            Self::AppProvision => "app_provision",
            Self::AppDeploy => "app_deploy",
            Self::AppLifecycle => "app_lifecycle",
            Self::SiteCredentialRotate => "site_credential_rotate",
        }
    }
}

#[derive(Deserialize)]
struct Header {
    schema_version: u16,
    plan_id: Id,
    verb: PlanKind,
}

/// A plan's intrinsically validated semantic content and identity.
/// This does not verify host state, signatures, policy or admission.
pub struct PreparedPlan {
    id: Id,
    kind: PlanKind,
    canonical: CanonicalObject,
}

impl PreparedPlan {
    /// Validate the bounded object against its exact closed plan kind.
    pub fn decode(bytes: &[u8]) -> Result<Self, ApprovalError> {
        let canonical = CanonicalObject::decode(bytes).map_err(ApprovalError::from)?;
        let header: Header = serde_json::from_slice(canonical.as_bytes())
            .map_err(|_| ApprovalError::InvalidMessage)?;
        match (header.verb, header.schema_version) {
            (PlanKind::SiteProvision, 1 | 2) => {
                SitePlan::decode(canonical.as_bytes())?;
            }
            (PlanKind::ConfigActivate, 1..=3) => {
                OlsPlan::decode(canonical.as_bytes())?;
            }
            (PlanKind::SiteEject, 1..=3) => {
                EjectPlan::decode(canonical.as_bytes())?;
            }
            (PlanKind::BackupCapture, 1) => {
                CapturePlan::decode(canonical.as_bytes())?;
            }
            (PlanKind::RestoreProbe, 1) => {
                ProbePlan::decode(canonical.as_bytes())?;
            }
            (PlanKind::SiteReadopt, 1) => {
                ReadoptPlan::decode(canonical.as_bytes())?;
            }
            (PlanKind::SiteImport, 1..=3) => {
                ImportPlan::decode(canonical.as_bytes())?;
            }
            (PlanKind::ImportScrub, 1) => {
                ScrubPlan::decode(canonical.as_bytes())?;
            }
            (PlanKind::CertificateIssue, 1..=3) => {
                CertificatePlan::decode(canonical.as_bytes())?;
            }
            (PlanKind::BackupCapture | PlanKind::RestoreProbe, 2) => {
                ProductBackupPlan::decode(canonical.as_bytes())?;
            }
            // D-035 (W386): the standing capture plan.
            (PlanKind::BackupCapture, 3) => {
                StandingCapturePlan::decode(canonical.as_bytes())?;
            }
            (PlanKind::SiteClone, 1) => {
                SiteClonePlan::decode(canonical.as_bytes())?;
            }
            (PlanKind::SiteRetire, 1) => {
                RetirePlan::decode(canonical.as_bytes())?;
            }
            (PlanKind::SiteUpdate, 1) => {
                SiteUpdatePlan::decode(canonical.as_bytes())?;
            }
            (PlanKind::SiteDelete, 1 | 2) => {
                DeletePlan::decode(canonical.as_bytes())?;
            }
            (PlanKind::SiteQuota, 1) => {
                QuotaPlan::decode(canonical.as_bytes())?;
            }
            (PlanKind::CloneScrub, 1) => {
                CloneScrubPlan::decode(canonical.as_bytes())?;
            }
            (PlanKind::SiteRestore, 1) => {
                RestorePlan::decode(canonical.as_bytes())?;
            }
            (PlanKind::DnsZoneImport, 1) => {
                DnsImportPlan::decode(canonical.as_bytes())?;
            }
            (PlanKind::DnsChange, 1) => {
                DnsChangePlan::decode(canonical.as_bytes())?;
            }
            (PlanKind::ProxySiteProvision, 1) => {
                ProxyPlan::decode(canonical.as_bytes())?;
            }
            (PlanKind::AppProvision, 1) => {
                AppProvisionPlan::decode(canonical.as_bytes())?;
            }
            (PlanKind::AppDeploy, 1) => {
                AppDeployPlan::decode(canonical.as_bytes())?;
            }
            (PlanKind::AppLifecycle, 1) => {
                AppLifecyclePlan::decode(canonical.as_bytes())?;
            }
            (PlanKind::SiteCredentialRotate, 1) => {
                CredentialRotatePlan::decode(canonical.as_bytes())?;
            }
            _ => return Err(ApprovalError::UnsupportedVersion),
        }
        Ok(Self {
            id: header.plan_id,
            kind: header.verb,
            canonical,
        })
    }

    /// ID read from the validated plan, never a caller-selected storage key.
    pub fn id(&self) -> &Id {
        &self.id
    }

    /// Fixed validated plan kind.
    pub const fn kind(&self) -> PlanKind {
        self.kind
    }

    /// Complete immutable canonical semantic bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.canonical.as_bytes()
    }

    /// Domain-separated digest of those complete semantic bytes.
    pub fn digest(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(self.canonical.plan_domain_digest())
    }
}
