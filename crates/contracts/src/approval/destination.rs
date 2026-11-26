//! Offline validation of the closed HTTPS S3 product destination projection.

use std::{
    collections::HashSet,
    net::{Ipv4Addr, SocketAddrV4},
    path::PathBuf,
};

use serde::{Deserialize, Serialize};

use crate::{CanonicalObject, Id};

use super::{ApprovalError, Sha256Digest, SiteId, product_backup::LAB_DESTINATION};

/// Maximum complete product destination JSON, within the root policy input bound.
pub const MAX_PRODUCT_BACKUP_POLICY_BYTES: usize = 16 * 1024;
/// Maximum size of the enrolled CA bundle passed to a product store job.
pub const MAX_PRODUCT_BACKUP_CA_BYTES: usize = 256 * 1024;
/// Maximum size of one credential or password passed to a product store job.
pub const MAX_PRODUCT_BACKUP_SECRET_BYTES: usize = 4 * 1024;
const POLICY_DIGEST_DOMAIN: &[u8] = b"rustiron/backup-policy/v2\0";

/// A structurally validated product destination with canonical bytes.
///
/// Decoding establishes no host, route, repository, or credential authority.
#[derive(Debug)]
pub struct ProductBackupPolicy {
    record: PolicyRecord,
    canonical: CanonicalObject,
}

impl ProductBackupPolicy {
    /// Validates the complete projection before making its canonical bytes available.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        if input.len() > MAX_PRODUCT_BACKUP_POLICY_BYTES {
            return Err(ApprovalError::RequestTooLarge);
        }
        let (record, canonical) = super::decode(input, PolicyRecord::validate)?;
        Ok(Self { record, canonical })
    }

    /// Validated destination ID used in v2 plans and grant scope.
    pub fn destination_id(&self) -> &Id {
        &self.record.destination_id
    }

    /// Expected configuration ID of the enrolled repository for this site.
    pub fn repository_id(&self, site: &SiteId) -> Option<&Sha256Digest> {
        let index = self.repository_index(site)?;
        Some(&self.record.transport.repositories[index].repository_id)
    }

    /// Resolves repository and credential settings from the same validated site row.
    pub fn resolve_site(&self, site: &SiteId) -> Option<ProductBackupSite<'_>> {
        let index = self.repository_index(site)?;
        let record = &self.record;
        Some(ProductBackupSite {
            transport: &record.transport,
            repository: &record.transport.repositories[index],
            retention_days: record.retention_days,
            capture: record.capture_credential_profile.credential_at(index),
            fetch: record.fetch_credential_profile.credential_at(index),
        })
    }

    fn repository_index(&self, site: &SiteId) -> Option<usize> {
        self.record
            .transport
            .repositories
            .binary_search_by(|repository| repository.site_id.as_str().cmp(site.as_str()))
            .ok()
    }

    /// Complete canonical policy JSON, with no trailing newline.
    pub fn as_bytes(&self) -> &[u8] {
        self.canonical.as_bytes()
    }

    /// Domain-separated digest of the complete canonical policy.
    pub fn digest(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(self.canonical.domain_digest(POLICY_DIGEST_DOMAIN))
    }
}

/// One site's HTTPS S3 settings from the validated destination projection.
///
/// These are enrollment data. The resolver performs no I/O and verifies no
/// live repository, credential, or network state.
pub struct ProductBackupSite<'a> {
    transport: &'a S3Transport,
    repository: &'a Repository,
    retention_days: u16,
    capture: ProductBackupCredential<'a>,
    fetch: ProductBackupCredential<'a>,
}

impl<'a> ProductBackupSite<'a> {
    /// The fixed restic URL with a path-style bucket and derived site account.
    pub fn repository_url(&self) -> String {
        format!(
            "s3:https://{}/{}/{}",
            self.endpoint(),
            self.bucket(),
            self.repository_prefix()
        )
    }

    /// Enrolled bucket name, addressed path-style.
    pub fn bucket(&self) -> &'a str {
        &self.transport.bucket
    }

    /// Object key prefix of this site's repository in the bucket, with no
    /// leading or trailing slash.
    pub fn repository_prefix(&self) -> String {
        format!(
            "{}/{}",
            self.transport.repository_root,
            self.repository.site_id.account_name()
        )
    }

    /// The sole IPv4 endpoint and TCP port enrolled for store access.
    pub fn endpoint(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.transport.endpoint_ipv4, self.transport.port)
    }

    /// Expected restic configuration ID for this site.
    pub fn repository_id(&self) -> &'a Sha256Digest {
        &self.repository.repository_id
    }

    /// Enrolled S3 request signing region.
    pub fn region(&self) -> &'a str {
        &self.transport.region
    }

    /// Expected digest of the exact CA bundle bytes.
    pub fn ca_sha256(&self) -> &'a Sha256Digest {
        &self.transport.ca_sha256
    }

    /// Enrolled default COMPLIANCE retention in days.
    pub fn retention_days(&self) -> u16 {
        self.retention_days
    }

    /// Repository password path relative to the trusted site credential root.
    pub fn password_path(&self) -> PathBuf {
        PathBuf::from(self.repository.site_id.account_name()).join("repo.password")
    }

    /// Capture upload credential enrollment.
    pub fn capture_credential(&self) -> ProductBackupCredential<'a> {
        self.capture
    }

    /// Read-only fetch credential enrollment.
    pub fn fetch_credential(&self) -> ProductBackupCredential<'a> {
        self.fetch
    }
}

/// One site's credential enrollment for one store phase. Contains no secret bytes.
#[derive(Clone, Copy)]
pub struct ProductBackupCredential<'a> {
    profile: &'a CredentialProfile,
    principal: &'a Principal,
}

impl<'a> ProductBackupCredential<'a> {
    /// Credential file path relative to the trusted site credential root.
    pub fn relative_path(&self) -> PathBuf {
        PathBuf::from(self.principal.site_id.account_name()).join(&self.profile.credential_slot)
    }

    /// Enrolled profile for this phase.
    pub fn profile_id(&self) -> &'a Id {
        &self.profile.profile_id
    }

    /// Enrolled backend principal for this phase and site.
    pub fn principal_id(&self) -> &'a Id {
        &self.principal.principal_id
    }

    /// Digest of the independent review artifact for this principal's scope.
    pub fn authorization_sha256(&self) -> &'a Sha256Digest {
        &self.principal.authorization_sha256
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyRecord {
    schema_version: u16,
    destination_id: Id,
    transport_id: String,
    transport: S3Transport,
    retention_days: u16,
    capture_credential_profile: CredentialProfile,
    fetch_credential_profile: CredentialProfile,
}

impl PolicyRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 2 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.destination_id.as_str() == LAB_DESTINATION
            || self.transport_id != "s3_https_ipv4_v1"
            || !(30..=3650).contains(&self.retention_days)
        {
            return Err(ApprovalError::InvalidMessage);
        }
        self.transport.validate()?;

        let mut principal_ids = HashSet::new();
        let repositories = &self.transport.repositories;
        for (profile, scope, slot) in [
            (&self.capture_credential_profile, "site_capture_v1", "aws"),
            (&self.fetch_credential_profile, "site_fetch_v1", "fetch-aws"),
        ] {
            if profile.scope != scope
                || profile.credential_slot != slot
                || profile.principals.len() != repositories.len()
                || !profile
                    .principals
                    .iter()
                    .zip(repositories)
                    .all(|(principal, repo)| {
                        principal.site_id == repo.site_id
                            && principal_ids.insert(principal.principal_id.as_str())
                    })
            {
                return Err(ApprovalError::InvalidMessage);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct S3Transport {
    store_id: Id,
    endpoint_ipv4: Ipv4Addr,
    port: u16,
    region: String,
    bucket: String,
    repository_root: String,
    ca_sha256: Sha256Digest,
    egress_profile: String,
    retention_mode: String,
    repositories: Vec<Repository>,
}

impl S3Transport {
    fn validate(&self) -> Result<(), ApprovalError> {
        if !candidate_peer(self.endpoint_ipv4)
            || self.port == 0
            || self.egress_profile != egress_profile(self.port)
            || !lowercase_label(&self.region, 1)
            || !lowercase_label(&self.bucket, 3)
            || self.repository_root != "sites"
            || self.retention_mode != "compliance"
            || self.repositories.is_empty()
        {
            return Err(ApprovalError::InvalidMessage);
        }
        let mut repository_ids = HashSet::new();
        if self
            .repositories
            .windows(2)
            .any(|pair| pair[0].site_id.as_str() >= pair[1].site_id.as_str())
            || !self
                .repositories
                .iter()
                .all(|repo| repository_ids.insert(repo.repository_id.as_str()))
        {
            return Err(ApprovalError::InvalidMessage);
        }
        Ok(())
    }
}

/// The one egress profile literal for an enrolled TCP port (W352, D-027).
///
/// Port 443 keeps the W307 literal, so every earlier projection keeps its
/// exact canonical bytes and digest. Any other port uses the port-neutral
/// literal. Each port has exactly one spelling, so one effect has one digest.
fn egress_profile(port: u16) -> &'static str {
    if port == 443 {
        "ipv4_tcp_443_v1"
    } else {
        "ipv4_tcp_port_v1"
    }
}

fn candidate_peer(address: Ipv4Addr) -> bool {
    // A route and local-address check needs live host facts.
    (1..224).contains(&address.octets()[0]) && !address.is_loopback() && !address.is_link_local()
}

fn lowercase_label(value: &str, min_len: usize) -> bool {
    (min_len..=63).contains(&value.len())
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Repository {
    site_id: SiteId,
    repository_id: Sha256Digest,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialProfile {
    profile_id: Id,
    scope: String,
    credential_slot: String,
    principals: Vec<Principal>,
}

impl CredentialProfile {
    fn credential_at(&self, index: usize) -> ProductBackupCredential<'_> {
        // Validation aligns both principal arrays with the repository array.
        ProductBackupCredential {
            profile: self,
            principal: &self.principals[index],
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Principal {
    site_id: SiteId,
    principal_id: Id,
    authorization_sha256: Sha256Digest,
}
