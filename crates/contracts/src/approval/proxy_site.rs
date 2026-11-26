//! Closed CP08 `proxy_site_provision` plan/grant contract (W571, D-095).
//!
//! The plan names one new site, its host name, 1 to 8 path routes, and 0 to
//! 8 WebSocket paths, each to a port on `127.0.0.1`; the address is fixed
//! and never named. The executor refuses a port that the host enrolled for
//! OLS; this contract refuses the ports below 1024 and MariaDB's 3306. The
//! provision creates the site account and folders and serves nothing until
//! a separate `config_activate`. It starts, changes, and backs up no service
//! behind the ports. Decoding is not signature verification or authority.
//! See `docs/technical/PROXY-SITE.md`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{CanonicalObject, Id, Text, Timestamp};

use super::{ApprovalError, Hostname, Sha256Digest, SiteId, types::*};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ProxyVerb {
    ProxySiteProvision,
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ProxyEffects {
    creates_account: bool,
    forwards_to_loopback: bool,
    traffic_activation: bool,
    starts_services: bool,
    backs_up_services: bool,
}

const EFFECTS: ProxyEffects = ProxyEffects {
    creates_account: true,
    forwards_to_loopback: true,
    traffic_activation: false,
    starts_services: false,
    backs_up_services: false,
};

/// The most path routes, and the most WebSocket paths, of one proxy site.
pub const MAX_PROXY_ROUTES: usize = 8;
/// The longest route prefix in bytes.
pub const MAX_PROXY_PREFIX_BYTES: usize = 128;
/// The lowest port a route may name; lower ports are the host's.
pub const MIN_PROXY_PORT: u16 = 1024;
/// MariaDB's port, which no route may name.
const MARIADB_PORT: u16 = 3306;

/// One path prefix and its loopback port.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProxyRoute {
    /// `/` or `/<segment>/…/`: lowercase letters, digits, `-`, `_`, and `.`
    /// in each segment, never `.` or `..`, ending in `/`.
    pub prefix: String,
    /// The port on `127.0.0.1`.
    pub port: u16,
}

/// Whether `prefix` is `/` or slash-separated segments ending in `/`.
pub fn valid_prefix(prefix: &str) -> bool {
    if prefix == "/" {
        return true;
    }
    let Some(inner) = prefix
        .strip_prefix('/')
        .and_then(|rest| rest.strip_suffix('/'))
    else {
        return false;
    };
    prefix.len() <= MAX_PROXY_PREFIX_BYTES
        && inner.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_' | b'.')
                })
        })
}

/// Whether `port` may be a route's: 1024 and above, never 3306.
pub fn routable_port(port: u16) -> bool {
    port >= MIN_PROXY_PORT && port != MARIADB_PORT
}

/// Valid, unique prefixes and routable ports, within the count bounds.
fn valid_routes(routes: &[ProxyRoute], low: usize) -> bool {
    let prefixes: BTreeSet<&str> = routes.iter().map(|route| route.prefix.as_str()).collect();
    (low..=MAX_PROXY_ROUTES).contains(&routes.len())
        && prefixes.len() == routes.len()
        && routes
            .iter()
            .all(|route| valid_prefix(&route.prefix) && routable_port(route.port))
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProxyPlanRecord {
    schema_version: u16,
    plan_id: Id,
    host_id: Id,
    host_epoch: Id,
    profile_digest: Sha256Digest,
    requester: Id,
    verb: ProxyVerb,
    site_id: SiteId,
    hostname: Hostname,
    #[serde(deserialize_with = "crate::codec::object_list")]
    routes: Vec<ProxyRoute>,
    #[serde(deserialize_with = "crate::codec::object_list")]
    websockets: Vec<ProxyRoute>,
    #[serde(deserialize_with = "crate::codec::object")]
    expected_effects: ProxyEffects,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    limitations: Vec<Text>,
}

impl ProxyPlanRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.expected_effects != EFFECTS
            || !valid_routes(&self.routes, 1)
            || !self.routes.iter().any(|route| route.prefix == "/")
            || !valid_routes(&self.websockets, 0)
            || self.limitations.len() > 8
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidPlan);
        }
        Ok(())
    }
}

/// A closed proxy site plan retaining its canonical original semantic bytes.
#[derive(Debug)]
pub struct ProxyPlan {
    record: ProxyPlanRecord,
    canonical: CanonicalObject,
}

impl ProxyPlan {
    /// Decodes schema v1 and its intrinsic constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, ProxyPlanRecord::validate)?;
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

    /// The new site.
    pub fn site_id(&self) -> &SiteId {
        &self.record.site_id
    }

    /// The host name the site serves.
    pub fn hostname(&self) -> &Hostname {
        &self.record.hostname
    }

    /// The path routes, `/` among them.
    pub fn routes(&self) -> &[ProxyRoute] {
        &self.record.routes
    }

    /// The WebSocket paths.
    pub fn websockets(&self) -> &[ProxyRoute] {
        &self.record.websockets
    }

    /// Every distinct port the routes and WebSocket paths name, in order.
    pub fn ports(&self) -> Vec<u16> {
        self.record
            .routes
            .iter()
            .chain(&self.record.websockets)
            .map(|route| route.port)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProxyGrantRecord {
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
    verbs: Vec<ProxyVerb>,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    max_operations: u64,
}

impl ProxyGrantRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.issuer == self.requester
            || self.site_ids.len() != 1
            || self.verbs != [ProxyVerb::ProxySiteProvision]
            || self.max_operations != 1
            || !valid_window(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidGrant);
        }
        Ok(())
    }
}

/// A closed proxy site grant envelope; no verified signature or replay authority.
#[derive(Debug)]
pub struct ProxyGrant {
    record: ProxyGrantRecord,
    canonical: CanonicalObject,
}

impl ProxyGrant {
    /// Decodes the bounded schema and intrinsic grant constraints only.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, ProxyGrantRecord::validate)?;
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

/// Independently enrolled facts for [`check_proxy_binding`]; never taken
/// from the submitted plan or grant.
pub struct ProxyBindingContext<'a> {
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
pub fn check_proxy_binding(
    plan: &ProxyPlan,
    grant: &ProxyGrant,
    context: &ProxyBindingContext<'_>,
) -> Result<(), ApprovalError> {
    let p = &plan.record;
    let g = &grant.record;
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
