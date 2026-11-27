//! Root-admin enrollment records, loaded only from the trusted policy directory.

use std::os::fd::OwnedFd;

use rustiron_contracts::{
    CanonicalObject, Id,
    approval::{MAX_PRODUCT_BACKUP_POLICY_BYTES, ProductBackupPolicy, Sha256Digest},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{
    ExecutorError, TrustAnchor,
    files::{Exposure, open_trusted_directory, read_child},
};

const MAX_POLICY_BYTES: usize = 16 * 1024;
const MAX_KEY_POLICY_BYTES: usize = 64 * 1024;
pub(crate) const PRODUCT_BACKUP_PROJECTION_FILE: &str = "backup-destination.json";

/// Enrolled host/profile/signer facts. Never derived from plans, grants,
/// coordinator inventory or offline review receipts.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Policy {
    schema_version: u16,
    pub host_id: Id,
    pub host_epoch: Id,
    pub profile_digest: Sha256Digest,
    pub requester: Id,
    /// Kernel peer UID enrolled for `requester`; the request cannot claim it.
    pub requester_uid: u32,
    pub issuer: Id,
    pub signer_policy_epoch: Id,
    pub verifier_sha256: Sha256Digest,
    /// Site provisioning enrollment; absent means `site_provision` is refused.
    #[serde(default)]
    pub provisioning: Option<ProvisioningPolicy>,
    /// W441 (D-053): site import enrollment; absent means `site_import` is refused.
    #[serde(default)]
    pub migration: Option<MigrationPolicy>,
    /// Lab OLS listener enrollment; absent means `config_activate` is refused.
    #[serde(default)]
    pub ols: Option<OlsPolicy>,
    /// W657 (D-102, Decision A1): enrolled Caddy edge ingress; absent means OLS-only host.
    #[serde(default)]
    pub caddy: Option<CaddyPolicy>,
    /// W462 (D-059): the ACME CA; absent means `certificate_issue` is refused.
    #[serde(default)]
    pub acme: Option<AcmePolicy>,
    /// W550 (D-091): the PowerDNS enrollment; absent means DNS is not enrolled.
    #[serde(default)]
    pub dns: Option<crate::dns::DnsPolicy>,
    /// W559 (D-095): the host firewall zone; absent means the operator has
    /// not enrolled one. Only `packaging/firewall-zone.py` applies it.
    #[serde(default)]
    pub firewall: Option<FirewallPolicy>,
    /// W594 (P23, D-098): durable blast-radius envelope limits; absent means
    /// only per-grant limits apply.
    #[serde(default)]
    pub blast_radius: Option<rustiron_contracts::approval::BlastRadiusLimits>,
    /// Lab backup destination enrollment; absent means `backup_capture` is refused.
    #[serde(default)]
    pub backup: Option<BackupPolicy>,
    /// Pin for the product-only v2 destination file.
    #[serde(default, deserialize_with = "ProductBackupPin::present")]
    product_backup: Option<ProductBackupPin>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductBackupPin {
    destination_id: Id,
    destination_policy_digest: Sha256Digest,
}

impl ProductBackupPin {
    fn present<'de, D: serde::Deserializer<'de>>(input: D) -> Result<Option<Self>, D::Error> {
        Self::deserialize(input).map(Some)
    }
}

/// The one enrolled lab backup destination.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupPolicy {
    /// Must be `lab_pc_store` (the only contract destination).
    pub destination_id: String,
    /// `s3:http://<address>:<port>/<bucket>/sites`.
    pub repository_base: String,
    /// The store's IPv4 address; snapshot units may reach only it.
    pub store_address: std::net::Ipv4Addr,
    /// Days the operator enrolled for this destination. D-010's lab target
    /// is 30. This is the product record. It is not proof that the bucket
    /// lock matches it. A new capture copies the number onto its own row.
    /// Existing rows stay without one. Absent refuses the backup section
    /// until a count is enrolled.
    #[serde(default)]
    pub retention_days: Option<u32>,
}

impl BackupPolicy {
    /// Stable digest of the complete enrolled backup policy used for effects.
    pub(crate) fn digest(&self) -> Result<Sha256Digest, ExecutorError> {
        let object = serde_json::json!({
            "destination_id": self.destination_id,
            "repository_base": self.repository_base,
            "store_address": self.store_address,
            "retention_days": self.retention_days,
        });
        let canonical = CanonicalObject::decode(object.to_string().as_bytes())
            .map_err(|_| ExecutorError::Unavailable)?;
        let mut digest = Sha256::new();
        digest.update(b"rustiron/backup-policy/v1\0");
        digest.update(canonical.as_bytes());
        Ok(Sha256Digest::from_bytes(digest.finalize().into()))
    }

    pub fn valid(&self) -> bool {
        let expected = format!("s3:http://{}:", self.store_address);
        self.destination_id == "lab_pc_store"
            && self.repository_base.starts_with(&expected)
            && self.repository_base.len() <= 128
            && self.repository_base.ends_with("/sites")
            && self
                .repository_base
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b":/.-_".contains(&b))
            && self
                .retention_days
                .is_some_and(|days| (1..=3650).contains(&days))
    }
}

/// The implemented backup contract is lab-only, including helper execution
/// and reconciliation of old intents.
pub(crate) fn require_lab_backup() -> Result<(), ExecutorError> {
    if cfg!(rustiron_profile = "product") {
        return Err(ExecutorError::InvalidRequest);
    }
    Ok(())
}

pub(crate) fn load_bound_backup(
    anchor: &TrustAnchor,
    host_id: &Id,
    host_epoch: &Id,
    expected: Option<&Sha256Digest>,
) -> Result<BackupPolicy, ExecutorError> {
    require_lab_backup()?;
    let expected = expected.ok_or(ExecutorError::PreconditionChanged)?;
    let owner = anchor.owner_uid;
    let loaded = load(&open_trusted_directory(&anchor.policy_dir, owner)?, owner)?.policy;
    if &loaded.host_id != host_id || &loaded.host_epoch != host_epoch {
        return Err(ExecutorError::PreconditionChanged);
    }
    let backup = loaded.backup.ok_or(ExecutorError::PreconditionChanged)?;
    if &backup.digest()? != expected {
        return Err(ExecutorError::PreconditionChanged);
    }
    Ok(backup)
}

/// W319: the product projection for repository use after admission. Loads
/// the trusted host policy again, requires the journaled host and epoch,
/// and compares the enrolled projection's digest with the journaled one. A
/// changed or missing destination refuses before any repository use.
pub(crate) fn load_bound_product_backup(
    anchor: &TrustAnchor,
    host_id: &Id,
    host_epoch: &Id,
    expected: Option<&Sha256Digest>,
) -> Result<ProductBackupPolicy, ExecutorError> {
    if !cfg!(rustiron_profile = "product") {
        return Err(ExecutorError::InvalidRequest);
    }
    let expected = expected.ok_or(ExecutorError::PreconditionChanged)?;
    let owner = anchor.owner_uid;
    let loaded = load(&open_trusted_directory(&anchor.policy_dir, owner)?, owner)?;
    // A lab backup enrollment is never a product destination (W303).
    if loaded.policy.backup.is_some() {
        return Err(ExecutorError::InvalidRequest);
    }
    if &loaded.policy.host_id != host_id || &loaded.policy.host_epoch != host_epoch {
        return Err(ExecutorError::PreconditionChanged);
    }
    let product = loaded
        .product_backup
        .ok_or(ExecutorError::PreconditionChanged)?;
    if &product.digest() != expected {
        return Err(ExecutorError::PreconditionChanged);
    }
    Ok(product)
}

/// The single lab listener and the pre-existing sites it keeps serving.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OlsPolicy {
    pub listener: String,
    pub address: String,
    pub adopted: Vec<crate::ols::AdoptedSite>,
    /// SHA-256 of the reviewed parent `httpd_config.conf` (WebAdmin disabled,
    /// one Rustiron include); any other parent is drift.
    pub parent_sha256: Sha256Digest,
    /// Port of the configured WebAdmin listener, which must not be listening.
    pub webadmin_port: u16,
    /// Provisioned sites whose vhost gets its own cache storage with the
    /// cache module off (D-028 item 2; lab only, at most 8, no repeats).
    #[serde(default)]
    pub lscache: Vec<rustiron_contracts::approval::SiteId>,
    /// D-059: the address of the SNI listener for sites with a certificate;
    /// absent renders no TLS listener. Another port than `address`.
    #[serde(default)]
    pub tls_address: Option<String>,
}

impl OlsPolicy {
    pub fn http_is_loopback(&self) -> bool {
        loopback_listener(&self.address)
    }

    pub fn valid(&self) -> bool {
        let name = |text: &str, first: fn(u8) -> bool| {
            (1..=32).contains(&text.len())
                && text.bytes().next().is_some_and(first)
                && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        };
        let plain = self.address.parse::<std::net::SocketAddr>();
        let tls_ok = match &self.tls_address {
            None => true,
            Some(tls) => tls.parse::<std::net::SocketAddr>().is_ok_and(|tls| {
                plain.as_ref().is_ok_and(|plain| tls.port() != plain.port())
                    && tls.port() != self.webadmin_port
            }),
        };
        // `<listener>TLS` must still fit the 32-byte name rule.
        name(&self.listener, |b| b.is_ascii_alphabetic())
            && plain.is_ok()
            && tls_ok
            && (self.tls_address.is_none() || self.listener.len() <= 29)
            && self.adopted.len() <= 32
            && self.lscache.len() <= 8
            && self
                .lscache
                .iter()
                .enumerate()
                .all(|(index, site)| !self.lscache[..index].contains(site))
            && self.adopted.iter().all(|site| {
                name(&site.name, |b| b.is_ascii_lowercase()) && !site.name.starts_with("rs_")
            })
    }

    /// The enrolled listener and WebAdmin ports, in that order (W355).
    pub fn ports(&self) -> Result<[u16; 2], crate::ExecutorError> {
        let listener = self
            .address
            .parse::<std::net::SocketAddr>()
            .map_err(|_| crate::ExecutorError::Unavailable)?
            .port();
        Ok([listener, self.webadmin_port])
    }

    /// W572 (D-095): every port OLS serves or reserves: the listener, the
    /// WebAdmin port, and the TLS listener when enrolled.
    pub fn reserved_ports(&self) -> Result<Vec<u16>, crate::ExecutorError> {
        let mut ports = self.ports()?.to_vec();
        if let Some(tls) = &self.tls_address {
            ports.push(
                tls.parse::<std::net::SocketAddr>()
                    .map_err(|_| crate::ExecutorError::Unavailable)?
                    .port(),
            );
        }
        Ok(ports)
    }
}

/// W657 (D-102, Decision A1): closed Caddy host ingress modes in `policy.json`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub(crate) enum CaddyMode {
    /// Dedicated modern app host where Caddy directly owns HTTP/HTTPS/HTTP3.
    #[serde(rename = "caddy_only")]
    Only,
    /// Multi-IP mixed host where OLS binds one IP and Caddy binds another.
    #[serde(rename = "caddy_multi_ip")]
    MultiIp,
    /// Single-IP mixed host where Caddy owns `:80/:443` and bridges WordPress/OLS over loopback.
    #[serde(rename = "caddy_edge_over_ols")]
    EdgeOverOls,
}

/// W657 (D-102, Decision A1): enrolled Caddy edge ingress policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CaddyPolicy {
    /// Enrolled host ingress mode.
    pub mode: CaddyMode,
    /// Enrolled HTTP listener address (`IP:PORT`, e.g. `203.0.113.10:80`).
    pub http_address: String,
    /// Enrolled HTTPS listener address (`IP:PORT`, e.g. `203.0.113.10:443`).
    pub https_address: String,
    /// Loopback OLS upstream (`127.0.0.1:8080`); required iff `mode == CaddyEdgeOverOls`.
    #[serde(default)]
    pub ols_upstream: Option<String>,
    /// Pinned SHA-256 of `/usr/local/bin/caddy`.
    pub binary_sha256: Sha256Digest,
}

impl CaddyPolicy {
    /// Validates listener socket addresses, port separation, forbidden service
    /// ports (`2019` admin API, `3306` MariaDB, `5432` PostgreSQL), and mode
    /// compatibility with any enrolled [`OlsPolicy`].
    pub fn valid(&self, ols: Option<&OlsPolicy>) -> bool {
        let Ok(http) = self.http_address.parse::<std::net::SocketAddr>() else {
            return false;
        };
        let Ok(https) = self.https_address.parse::<std::net::SocketAddr>() else {
            return false;
        };
        let forbidden = |port: u16| matches!(port, 0 | 2019 | 3306 | 5432);
        if http.port() == https.port() || forbidden(http.port()) || forbidden(https.port()) {
            return false;
        }
        match self.mode {
            CaddyMode::EdgeOverOls => {
                let Some(upstream) = self.ols_upstream.as_deref() else {
                    return false;
                };
                let Ok(up) = upstream.parse::<std::net::SocketAddr>() else {
                    return false;
                };
                if !up.ip().is_loopback() || forbidden(up.port()) {
                    return false;
                }
                ols.is_some_and(|ols| ols.http_is_loopback() && ols.address == upstream)
            }
            CaddyMode::Only => self.ols_upstream.is_none(),
            CaddyMode::MultiIp => {
                if self.ols_upstream.is_some() {
                    return false;
                }
                ols.is_none_or(|ols| {
                    ols.address != self.http_address
                        && ols.address != self.https_address
                        && ols.tls_address.as_deref() != Some(self.http_address.as_str())
                        && ols.tls_address.as_deref() != Some(self.https_address.as_str())
                })
            }
        }
    }

    /// Every port Caddy binds directly (`http_address` and `https_address`).
    pub fn reserved_ports(&self) -> Result<[u16; 2], crate::ExecutorError> {
        let http = self
            .http_address
            .parse::<std::net::SocketAddr>()
            .map_err(|_| crate::ExecutorError::Unavailable)?
            .port();
        let https = self
            .https_address
            .parse::<std::net::SocketAddr>()
            .map_err(|_| crate::ExecutorError::Unavailable)?
            .port();
        Ok([http, https])
    }
}

pub(crate) fn loopback_listener(address: &str) -> bool {
    address
        .parse::<std::net::SocketAddr>()
        .is_ok_and(|address| address.ip().is_loopback())
}

impl Policy {
    /// D-077: only the enrolled lab CA and loopback listeners can issue a pair.
    pub fn alias_certificate_enabled(&self) -> bool {
        self.migration
            .as_ref()
            .is_some_and(|migration| migration.static_alias_http)
            && self.ols.as_ref().is_some_and(|ols| {
                ols.http_is_loopback() && ols.tls_address.as_deref().is_some_and(loopback_listener)
            })
            && self.acme.as_ref().is_some_and(|acme| {
                acme.ca_bundle.is_some()
                    && acme.directory == "https://acme.lab.test:8009/acme/local/directory"
            })
    }

    /// D-097: single-name static ejection runs on the disposable lab profile
    /// (loopback listeners, migration enrolled, and for TLS the lab private CA).
    pub fn static_eject_enabled(&self, tls: bool) -> bool {
        self.migration.is_some()
            && self.ols.as_ref().is_some_and(|ols| {
                ols.http_is_loopback()
                    && if tls {
                        ols.tls_address.as_deref().is_some_and(loopback_listener)
                    } else {
                        ols.tls_address.as_deref().is_none_or(loopback_listener)
                    }
            })
            && (!tls
                || self.acme.as_ref().is_some_and(|acme| {
                    acme.ca_bundle.is_some()
                        && acme.directory == "https://acme.lab.test:8009/acme/local/directory"
                }))
    }
}

/// W559 (D-095): the facts of the Rustiron firewalld zone. The zone always
/// allows HTTP and HTTPS, and DNS when the `dns` section is enrolled.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FirewallPolicy {
    /// The port `sshd` listens on; the zone allows it.
    pub ssh_port: u16,
    /// Whether the zone allows DHCPv6 replies.
    #[expect(
        dead_code,
        reason = "packaging/firewall-zone.py reads it; the executor only checks the section's shape"
    )]
    pub dhcpv6_client: bool,
}

impl FirewallPolicy {
    /// A nonzero SSH port that is not one of the served ports.
    pub fn valid(&self) -> bool {
        self.ssh_port != 0 && ![53, 80, 443].contains(&self.ssh_port)
    }
}

/// W462 (D-059): the enrolled ACME CA. The plan never names it.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AcmePolicy {
    /// The CA's ACME directory URL (`https://`).
    pub directory: String,
    /// A lab CA bundle that only certbot trusts; absent uses the system store.
    #[serde(default)]
    pub ca_bundle: Option<String>,
}

impl AcmePolicy {
    /// An `https` URL of printable ASCII without spaces or quotes, and an
    /// absolute normal bundle path under the ACME state folder.
    pub fn valid(&self) -> bool {
        let plain = |text: &str, max: usize| {
            (1..=max).contains(&text.len())
                && text
                    .bytes()
                    .all(|b| b.is_ascii_graphic() && !matches!(b, b'"' | b'\\' | b'\'' | b'`'))
        };
        let url_ok = plain(&self.directory, 256)
            && self
                .directory
                .strip_prefix("https://")
                .is_some_and(|rest| !rest.is_empty() && !rest.starts_with('/'));
        let bundle_ok = self.ca_bundle.as_deref().is_none_or(|bundle| {
            plain(bundle, 128)
                && bundle
                    .strip_prefix(crate::layout::ACME_STATE_DIR)
                    .and_then(|rest| rest.strip_prefix('/'))
                    .is_some_and(|rest| {
                        !rest.is_empty()
                            && rest
                                .split('/')
                                .all(|part| !part.is_empty() && part != "." && part != "..")
                    })
        });
        url_ok && bundle_ok
    }
}

/// W441 (D-053): what `site_import` needs beyond the provisioning policy.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MigrationPolicy {
    /// LSPHP versions installed on this host; a plan's target must be one.
    pub php_versions: Vec<rustiron_contracts::migration::PhpVersion>,
    /// D-075: explicit opt-in to static aliases on an HTTP loopback listener.
    #[serde(default)]
    pub static_alias_http: bool,
}

impl MigrationPolicy {
    /// One to eight distinct versions.
    pub fn valid(&self) -> bool {
        let distinct: std::collections::BTreeSet<_> = self.php_versions.iter().collect();
        (1..=8).contains(&self.php_versions.len()) && distinct.len() == self.php_versions.len()
    }
}

/// Enrolled ranges and the pinned recipe digest for `site_provision`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProvisioningPolicy {
    pub wordpress_713_sha256: Sha256Digest,
    pub uid_min: u32,
    pub uid_max: u32,
    pub category_min: u32,
    pub category_max: u32,
    /// W335 (D-028): hard limits for each site's user quota. Absent means
    /// provision records `quota=not_enforced` (lab only); the product
    /// profile refuses a provisioning policy without it.
    #[serde(default)]
    pub quota: Option<crate::quota::QuotaLimits>,
}

impl ProvisioningPolicy {
    /// Ranges must be ordered, above system ids and below the MCS limit.
    /// Quota limits, when enrolled, must be inside their fixed bounds; the
    /// product profile requires them.
    pub fn valid(&self) -> bool {
        (2000..=self.uid_max).contains(&self.uid_min)
            && self.uid_max < 60000
            && (1..=self.category_max).contains(&self.category_min)
            && self.category_max <= 1023
            && match self.quota {
                Some(limits) => limits.valid(),
                None => !cfg!(rustiron_profile = "product"),
            }
    }
}

/// The complete loaded policy including SSHSIG allowlist and revocations.
pub(crate) struct LoadedPolicy {
    pub policy: Policy,
    pub product_backup: Option<ProductBackupPolicy>,
    pub allowed_signers: Vec<u8>,
    pub revocations: Vec<u8>,
}

pub(crate) fn load(directory: &OwnedFd, owner: u32) -> Result<LoadedPolicy, ExecutorError> {
    let read = |name, limit| read_child(directory, name, owner, Exposure::Private, limit);
    // W347: only an absent file means "not enrolled"; the read below still
    // refuses every other shape (link, mode, owner, size) as access denied.
    if let Err(rustix::io::Errno::NOENT) = rustix::fs::statat(
        directory,
        "policy.json",
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    ) {
        return Err(ExecutorError::NotEnrolled);
    }
    let bytes = read("policy.json", MAX_POLICY_BYTES)?;
    let canonical = CanonicalObject::decode(&bytes).map_err(|_| ExecutorError::Unavailable)?;
    let policy: Policy =
        serde_json::from_slice(canonical.as_bytes()).map_err(|_| ExecutorError::Unavailable)?;
    if policy.issuer == policy.requester
        || policy
            .provisioning
            .as_ref()
            .is_some_and(|provisioning| !provisioning.valid())
        || policy
            .migration
            .as_ref()
            .is_some_and(|migration| !migration.valid())
        || policy.ols.as_ref().is_some_and(|ols| !ols.valid())
        || policy
            .caddy
            .as_ref()
            .is_some_and(|caddy| !caddy.valid(policy.ols.as_ref()))
        || policy.acme.as_ref().is_some_and(|acme| !acme.valid())
        || policy.dns.as_ref().is_some_and(|dns| !dns.valid())
        || policy
            .firewall
            .as_ref()
            .is_some_and(|firewall| !firewall.valid())
        || policy
            .blast_radius
            .as_ref()
            .is_some_and(|limits| !limits.valid())
        || policy.backup.as_ref().is_some_and(|backup| !backup.valid())
    {
        return Err(ExecutorError::Unavailable);
    }
    let product_backup = match (policy.schema_version, &policy.product_backup) {
        (1, None) => None,
        (2, Some(pin)) if cfg!(rustiron_profile = "product") && policy.backup.is_none() => {
            let bytes = read(
                PRODUCT_BACKUP_PROJECTION_FILE,
                MAX_PRODUCT_BACKUP_POLICY_BYTES,
            )?;
            let projection =
                ProductBackupPolicy::decode(&bytes).map_err(|_| ExecutorError::Unavailable)?;
            if projection.destination_id() != &pin.destination_id
                || projection.digest() != pin.destination_policy_digest
            {
                return Err(ExecutorError::Unavailable);
            }
            Some(projection)
        }
        _ => return Err(ExecutorError::Unavailable),
    };
    let allowed_signers = read("allowed_signers", MAX_KEY_POLICY_BYTES)?;
    check_allowed(&allowed_signers, &policy.issuer)?;
    Ok(LoadedPolicy {
        policy,
        product_backup,
        allowed_signers,
        revocations: read("revocations", MAX_KEY_POLICY_BYTES)?,
    })
}

/// Exactly one plain Ed25519 key for the enrolled issuer and fixed namespace.
fn check_allowed(bytes: &[u8], issuer: &Id) -> Result<(), ExecutorError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ExecutorError::Unavailable)?;
    let parts: Vec<_> = text.split_whitespace().collect();
    if parts.len() != 4
        || parts[0] != issuer.as_str()
        || parts[1] != r#"namespaces="rustiron-plan-v1""#
        || parts[2] != "ssh-ed25519"
        || parts[3].len() > 128
        || !parts[3]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+/=".contains(&byte))
    {
        return Err(ExecutorError::Unavailable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{AcmePolicy, BackupPolicy, FirewallPolicy, OlsPolicy, ProvisioningPolicy};

    /// W559 (D-095): the SSH port must be nonzero and not a served port;
    /// unknown fields do not decode.
    #[test]
    fn the_firewall_section_is_closed() {
        let decode = |text: &str| serde_json::from_str::<FirewallPolicy>(text);
        assert!(
            decode(r#"{"ssh_port":22,"dhcpv6_client":true}"#)
                .unwrap()
                .valid()
        );
        assert!(
            decode(r#"{"ssh_port":2222,"dhcpv6_client":false}"#)
                .unwrap()
                .valid()
        );
        for port in [0, 53, 80, 443] {
            let text = format!(r#"{{"ssh_port":{port},"dhcpv6_client":false}}"#);
            assert!(!decode(&text).unwrap().valid(), "{port}");
        }
        assert!(decode(r#"{"ssh_port":22}"#).is_err());
        assert!(decode(r#"{"ssh_port":22,"dhcpv6_client":false,"ports":[3306]}"#).is_err());
        assert!(decode(r#"{"ssh_port":70000,"dhcpv6_client":false}"#).is_err());
    }

    /// W347: a trusted policy directory without `policy.json` is a host
    /// that is not enrolled yet; any other read failure stays access denied.
    #[test]
    fn a_missing_policy_file_means_not_enrolled() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("rustiron-w347-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let owner = rustix::process::getuid().as_raw();
        let open = || crate::files::open_trusted_directory(&root, owner).unwrap();
        assert_eq!(
            super::load(&open(), owner).err(),
            Some(crate::ExecutorError::NotEnrolled)
        );
        let file = root.join("policy.json");
        std::fs::write(&file, b"{}").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            super::load(&open(), owner).err(),
            Some(crate::ExecutorError::AccessDenied)
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    fn provisioning(quota: Option<serde_json::Value>) -> ProvisioningPolicy {
        let mut value = serde_json::json!({
            "wordpress_713_sha256": "d".repeat(64), "uid_min": 3001, "uid_max": 3099,
            "category_min": 201, "category_max": 299,
        });
        if let Some(quota) = quota {
            value["quota"] = quota;
        }
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn quota_enrolment_is_optional_in_the_lab_and_bounded_when_present() {
        let enrolled = provisioning(Some(
            serde_json::json!({"block_hard_kib": 5_242_880, "inode_hard": 500_000}),
        ));
        assert!(enrolled.valid());
        assert_eq!(enrolled.quota, Some(crate::quota::QuotaLimits::DEFAULT));
        assert!(
            !provisioning(Some(
                serde_json::json!({"block_hard_kib": 0, "inode_hard": 500_000})
            ))
            .valid()
        );
        // The lab may run without a quota (recorded as not enforced); the
        // product profile refuses such a provisioning policy.
        assert_eq!(
            provisioning(None).valid(),
            !cfg!(rustiron_profile = "product")
        );
    }

    fn ols(lscache: serde_json::Value) -> serde_json::Result<OlsPolicy> {
        serde_json::from_value(serde_json::json!({
            "listener": "G0", "address": "192.168.122.186:8090", "adopted": [],
            "parent_sha256": "a".repeat(64), "webadmin_port": 7080, "lscache": lscache,
        }))
    }

    /// W460 (D-059): the TLS address is optional, parseable, and on its
    /// own port.
    #[test]
    fn the_tls_address_is_optional_and_on_its_own_port() {
        let with = |tls: serde_json::Value| -> OlsPolicy {
            serde_json::from_value(serde_json::json!({
                "listener": "G0", "address": "192.168.122.186:8090", "adopted": [],
                "parent_sha256": "a".repeat(64), "webadmin_port": 7080, "tls_address": tls,
            }))
            .unwrap()
        };
        assert!(ols(serde_json::json!([])).unwrap().tls_address.is_none());
        assert!(with(serde_json::json!("192.168.122.186:8443")).valid());
        for bad in [
            "192.168.122.186:8090",
            "192.168.122.186:7080",
            "nope",
            "192.168.122.186",
        ] {
            assert!(!with(serde_json::json!(bad)).valid(), "{bad}");
        }
    }

    /// W462 (D-059): the ACME CA is an https URL; a lab bundle lives in the
    /// ACME state folder.
    #[test]
    fn the_acme_section_names_an_https_ca_and_a_contained_bundle() {
        let acme =
            |value: serde_json::Value| -> AcmePolicy { serde_json::from_value(value).unwrap() };
        assert!(
            acme(
                serde_json::json!({"directory": "https://acme-v02.api.letsencrypt.org/directory"})
            )
            .valid()
        );
        assert!(
            acme(
                serde_json::json!({"directory": "https://acme.lab.test:8009/acme/local/directory",
            "ca_bundle": "/var/lib/rustiron-acme/lab-ca.pem"})
            )
            .valid()
        );
        for bad in [
            serde_json::json!({"directory": "http://acme.lab.test/directory"}),
            serde_json::json!({"directory": "https://"}),
            serde_json::json!({"directory": "https://a b"}),
            serde_json::json!({"directory": "https://x", "ca_bundle": "/etc/pki/ca.pem"}),
            serde_json::json!({"directory": "https://x", "ca_bundle": "/var/lib/rustiron-acme/../x"}),
            serde_json::json!({"directory": "https://x", "ca_bundle": "/var/lib/rustiron-acme/"}),
        ] {
            assert!(!acme(bad.clone()).valid(), "{bad}");
        }
        assert!(
            serde_json::from_value::<AcmePolicy>(
                serde_json::json!({"directory": "https://x", "email": "a"})
            )
            .is_err()
        );
    }

    #[test]
    fn lscache_enrolment_is_a_short_list_of_valid_site_ids() {
        let one = ols(serde_json::json!(["w198a"])).unwrap();
        assert!(one.valid());
        assert_eq!(one.lscache.len(), 1);
        let many: Vec<String> = (0..9).map(|i| format!("w198{i}")).collect();
        assert!(!ols(serde_json::json!(many)).unwrap().valid());
        let repeated = ols(serde_json::json!(["w198a", "w198b", "w198a"])).unwrap();
        assert!(!repeated.valid(), "a repeated site is refused");
        for bad in ["../x", "RS_W198", "rs_w198a", ""] {
            assert!(ols(serde_json::json!([bad])).is_err(), "{bad} refused");
        }
    }

    fn policy(days: Option<u32>) -> BackupPolicy {
        let mut value = serde_json::json!({
            "destination_id": "lab_pc_store",
            "repository_base": "s3:http://192.168.122.1:9000/rustiron/sites",
            "store_address": "192.168.122.1",
        });
        if let Some(days) = days {
            value["retention_days"] = serde_json::json!(days);
        }
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn backup_retention_must_be_an_enrolled_day_count() {
        assert!(policy(Some(30)).valid());
        assert!(policy(Some(1)).valid());
        assert!(policy(Some(3650)).valid());
        assert!(!policy(None).valid());
        assert!(!policy(Some(0)).valid());
        assert!(!policy(Some(3651)).valid());
        assert_eq!(policy(Some(30)).retention_days, Some(30));
    }

    #[test]
    fn static_eject_requires_loopback_lab_profile_and_lab_ca_for_tls() {
        let make = |http: &str, tls: Option<&str>, with_migration: bool, with_lab_ca: bool| {
            let mut value = serde_json::json!({
                "schema_version": 1,
                "host_id": "host_lab",
                "host_epoch": "epoch_1",
                "profile_digest": "a".repeat(64),
                "requester": "agent_1",
                "requester_uid": 1000,
                "issuer": "lab_agent",
                "signer_policy_epoch": "policy_3",
                "verifier_sha256": "b".repeat(64),
                "ols": {
                    "listener": "G0",
                    "address": http,
                    "adopted": [],
                    "parent_sha256": "c".repeat(64),
                    "webadmin_port": 7080,
                },
            });
            if let Some(tls) = tls {
                value["ols"]["tls_address"] = serde_json::json!(tls);
            }
            if with_migration {
                value["migration"] = serde_json::json!({"php_versions": ["8.4"]});
            }
            if with_lab_ca {
                value["acme"] = serde_json::json!({
                    "directory": "https://acme.lab.test:8009/acme/local/directory",
                    "ca_bundle": "/var/lib/rustiron-acme/lab-ca.pem"
                });
            }
            serde_json::from_value::<super::Policy>(value).unwrap()
        };

        let http_only_lab = make("127.0.0.1:8090", None, true, false);
        assert!(http_only_lab.static_eject_enabled(false));
        assert!(!http_only_lab.static_eject_enabled(true));

        let full_lab = make("127.0.0.1:8090", Some("127.0.0.1:8443"), true, true);
        assert!(full_lab.static_eject_enabled(false));
        assert!(full_lab.static_eject_enabled(true));

        assert!(!make("192.168.122.10:8090", None, true, false).static_eject_enabled(false));
        assert!(
            !make("127.0.0.1:8090", Some("192.168.122.10:8443"), true, true)
                .static_eject_enabled(false)
        );
        assert!(
            !make("127.0.0.1:8090", Some("192.168.122.10:8443"), true, true)
                .static_eject_enabled(true)
        );
        assert!(
            !make("127.0.0.1:8090", Some("127.0.0.1:8443"), false, true)
                .static_eject_enabled(false)
        );
        assert!(
            !make("127.0.0.1:8090", Some("127.0.0.1:8443"), true, false).static_eject_enabled(true)
        );
    }

    /// W657 (D-102, Decision A1): Caddy policy validates dual-mode bindings,
    /// loopback OLS upstream coupling, and forbidden ports.
    #[test]
    fn caddy_policy_validates_modes_ports_and_ols_coupling() {
        let decode = |value: serde_json::Value| -> super::CaddyPolicy {
            serde_json::from_value(value).unwrap()
        };
        let sha = "a".repeat(64);
        let ols_loopback: OlsPolicy = serde_json::from_value(serde_json::json!({
            "listener": "Edge", "address": "127.0.0.1:8080", "adopted": [],
            "parent_sha256": "c".repeat(64), "webadmin_port": 7080,
        }))
        .unwrap();
        let ols_public: OlsPolicy = serde_json::from_value(serde_json::json!({
            "listener": "Pub", "address": "203.0.113.10:80", "tls_address": "203.0.113.10:443",
            "adopted": [], "parent_sha256": "c".repeat(64), "webadmin_port": 7080,
        }))
        .unwrap();

        let edge = decode(serde_json::json!({
            "mode": "caddy_edge_over_ols",
            "http_address": "203.0.113.10:80",
            "https_address": "203.0.113.10:443",
            "ols_upstream": "127.0.0.1:8080",
            "binary_sha256": sha,
        }));
        assert!(edge.valid(Some(&ols_loopback)));
        assert!(!edge.valid(None));
        assert!(!edge.valid(Some(&ols_public)));
        assert_eq!(edge.reserved_ports().unwrap(), [80, 443]);

        let caddy_only = decode(serde_json::json!({
            "mode": "caddy_only",
            "http_address": "203.0.113.10:80",
            "https_address": "203.0.113.10:443",
            "binary_sha256": sha,
        }));
        assert!(caddy_only.valid(None));

        let multi_ip = decode(serde_json::json!({
            "mode": "caddy_multi_ip",
            "http_address": "203.0.113.11:80",
            "https_address": "203.0.113.11:443",
            "binary_sha256": sha,
        }));
        assert!(multi_ip.valid(Some(&ols_public)));
        let multi_ip_collision = decode(serde_json::json!({
            "mode": "caddy_multi_ip",
            "http_address": "203.0.113.10:80",
            "https_address": "203.0.113.11:443",
            "binary_sha256": sha,
        }));
        assert!(!multi_ip_collision.valid(Some(&ols_public)));

        for bad in [
            serde_json::json!({
                "mode": "caddy_only",
                "http_address": "203.0.113.10:2019",
                "https_address": "203.0.113.10:443",
                "binary_sha256": sha,
            }),
            serde_json::json!({
                "mode": "caddy_only",
                "http_address": "203.0.113.10:80",
                "https_address": "203.0.113.10:80",
                "binary_sha256": sha,
            }),
            serde_json::json!({
                "mode": "caddy_only",
                "http_address": "203.0.113.10:80",
                "https_address": "203.0.113.10:443",
                "ols_upstream": "127.0.0.1:8080",
                "binary_sha256": sha,
            }),
            serde_json::json!({
                "mode": "caddy_edge_over_ols",
                "http_address": "203.0.113.10:80",
                "https_address": "203.0.113.10:443",
                "ols_upstream": "203.0.113.10:8080",
                "binary_sha256": sha,
            }),
        ] {
            assert!(!decode(bad.clone()).valid(Some(&ols_loopback)), "{bad}");
        }
    }
}
