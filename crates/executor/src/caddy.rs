//! W657 (D-102, Decisions A1 + B1): deterministic confined Caddy edge ingress
//! renderer, validator, atomic generation publisher, and reload/rollback engine.
//!
//! Every byte of a Caddy generation (`Caddyfile` + per-site `<account>.caddy`)
//! is rendered strictly from enrolled [`CaddyPolicy`](crate::policy::CaddyPolicy)
//! and trusted journal records; no raw config text ever comes from a request.
//!
//! Security invariants enforced on every render & activation:
//! - Admin API only on the `0700` Unix socket [`CADDY_ADMIN_SOCKET`] (never TCP
//!   `:2019`) so `systemctl reload` works without downtime (W662-F4), plus
//!   `persist_config off` so `rustiron_caddy_t` writes no config to disk.
//! - `auto_https disable_certs` (Decision B1): `rustiron-acme` / Certbot stays
//!   the single TLS issuer; Caddy reads `/etc/rustiron-tls/<account>/live/`
//!   read-only and needs zero outbound internet access.
//! - Authentic proxy headers: Caddy's own defaults (no `trusted_proxies`)
//!   replace client `X-Forwarded-For`, `X-Forwarded-Proto`, and
//!   `X-Forwarded-Host`; every `reverse_proxy` also overwrites `X-Real-IP`.
//! - HTTP/3 (`protocols h1 h2 h3`), native WebSockets, and unbuffered SSE
//!   (`flush_interval -1`).
//! - Decision A1 dual-mode ingress: `caddy_only`, `caddy_multi_ip`, and
//!   `caddy_edge_over_ols` (proxying WordPress/PHP domains over loopback to
//!   OLS `127.0.0.1:8080` so `.htaccess`, LSPHP 8.4, and LiteSpeed Cache work
//!   unchanged with zero OLS reloads during modern app deploys).

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read, Write},
    net::{IpAddr, SocketAddr},
    os::fd::OwnedFd,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use rustiron_contracts::{
    Id,
    approval::{
        AppTopology, Hostname, Sha256Digest, app_routable_port, valid_frontend_dir, valid_prefix,
    },
};
use rustiron_journal::{AppFacts, AppFullstackSpec, AppSlot, CaddyIngressMode};
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags};
use sha2::{Digest, Sha256};

use crate::{ExecutorError, files, ols, provision};

/// The Rustiron-owned Caddy configuration root (`generations/` and `current`).
pub const CONFIG_DIR: &str = crate::layout::CADDY_CONFIG_DIR;
/// Managed systemd unit for confined Caddy edge ingress.
pub const CADDY_UNIT: &str = "rustiron-caddy.service";
/// Pinned host binary path for Caddy (verified by SHA-256 against enrolled policy).
pub const CADDY_BINARY: &str = "/usr/local/bin/caddy";
/// Caddy's default TCP admin port, which MUST never listen.
pub const CADDY_ADMIN_PORT: u16 = 2019;
/// Admin API socket, inside the unit's `0700` `RuntimeDirectory=` (W662-F4).
pub const CADDY_ADMIN_SOCKET: &str = crate::layout::CADDY_ADMIN_SOCKET;

const SITES: &str = crate::layout::SITES_ROOT;
const MAX_FILE: usize = 256 * 1024;
const MAX_BINARY_BYTES: u64 = 128 * 1024 * 1024;
const VALIDATE_TIMEOUT: Duration = Duration::from_secs(30);
const STAGING_MARK: &str = ".staging-";
const QUARANTINE_MARK: &str = ".quarantine-";

/// Rendered Caddy generation: file name (`Caddyfile`, `<account>.caddy`) -> UTF-8 bytes.
pub type CaddyGeneration = BTreeMap<String, Vec<u8>>;

/// Enrolled bind configuration passed into the deterministic renderer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaddyRenderConfig {
    /// Host ingress topology (`caddy_only`, `caddy_multi_ip`, `caddy_edge_over_ols`).
    pub mode: CaddyIngressMode,
    /// HTTP bind address (`IP:PORT`, e.g. `203.0.113.10:80`).
    pub http_address: SocketAddr,
    /// HTTPS bind address (`IP:PORT`, e.g. `203.0.113.10:443`).
    pub https_address: SocketAddr,
    /// Loopback OLS upstream (`127.0.0.1:8080`), present iff `mode == CaddyEdgeOverOls`.
    pub ols_upstream: Option<SocketAddr>,
}

impl CaddyRenderConfig {
    /// Validates listener ports and A1 mode invariants before rendering.
    pub fn validate(&self) -> Result<(), ExecutorError> {
        let forbidden = |port: u16| matches!(port, 0 | CADDY_ADMIN_PORT | 3306 | 5432);
        if self.http_address.port() == self.https_address.port()
            || forbidden(self.http_address.port())
            || forbidden(self.https_address.port())
        {
            return Err(ExecutorError::BindingDenied);
        }
        match self.mode {
            CaddyIngressMode::CaddyEdgeOverOls => {
                let upstream = self.ols_upstream.ok_or(ExecutorError::BindingDenied)?;
                if !upstream.ip().is_loopback() || forbidden(upstream.port()) {
                    return Err(ExecutorError::BindingDenied);
                }
            }
            CaddyIngressMode::CaddyOnly | CaddyIngressMode::CaddyMultiIp => {
                if self.ols_upstream.is_some() {
                    return Err(ExecutorError::BindingDenied);
                }
            }
        }
        Ok(())
    }
}

/// What one Caddy-served site proxies or serves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaddySiteKind {
    /// A D-102 modern app site (`static_spa`, `backend_api`, `fullstack_split`, `fullstack_dual_ssr`).
    App {
        /// Core app facts from the journal `apps` row.
        facts: Box<AppFacts>,
        /// Extended full-stack topology/slot/route metadata from `app_fullstack_specs`.
        spec: Box<AppFullstackSpec>,
    },
    /// A WordPress/PHP or OLS-managed site bridged to loopback OLS under Decision A1
    /// (`caddy_edge_over_ols`).
    OlsBridge,
}

/// One trusted site rendered into a Caddy generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaddySite {
    /// Derived site account (`rs_<site_id>`).
    pub account: String,
    /// Primary served hostname.
    pub hostname: Hostname,
    /// Optional alias hostname (e.g. `www.<domain>`).
    pub alias_hostname: Option<Hostname>,
    /// Installed TLS certificate chain digest from `/etc/rustiron-tls/<account>/live`.
    pub tls: Option<Sha256Digest>,
    /// Whether the site has an HTTP-01 ACME webroot (`/srv/sites/<account>/acme`).
    pub acme: bool,
    /// App topology or A1 OLS bridge.
    pub kind: CaddySiteKind,
}

/// Returns true iff `account` is a strict `rs_<site_id>` identifier with safe ASCII characters.
fn valid_account_name(account: &str) -> bool {
    let Some(site_id) = account.strip_prefix("rs_") else {
        return false;
    };
    rustiron_contracts::approval::SiteId::try_from(site_id.to_owned())
        .is_ok_and(|id| id.account_name() == account)
}

/// Active backend loopback port for `facts` + `spec` respecting blue/green `active_slot`.
pub fn active_backend_port(
    facts: &AppFacts,
    spec: &AppFullstackSpec,
) -> Result<u16, ExecutorError> {
    let port = if spec.blue_green && spec.active_slot == AppSlot::B {
        spec.standby_port.ok_or(ExecutorError::InvalidRequest)?
    } else {
        facts.port
    };
    if !app_routable_port(port) {
        return Err(ExecutorError::InvalidRequest);
    }
    Ok(port)
}

/// Active frontend SSR loopback port for `fullstack_dual_ssr` respecting blue/green `active_slot`.
pub fn active_frontend_port(spec: &AppFullstackSpec) -> Result<u16, ExecutorError> {
    let port = if spec.blue_green && spec.active_slot == AppSlot::B {
        spec.frontend_standby_port
            .ok_or(ExecutorError::InvalidRequest)?
    } else {
        spec.frontend_port.ok_or(ExecutorError::InvalidRequest)?
    };
    if !app_routable_port(port) {
        return Err(ExecutorError::InvalidRequest);
    }
    Ok(port)
}

fn format_bind_line(ip: IpAddr) -> String {
    if ip.is_unspecified() {
        String::new()
    } else {
        format!("\tbind {ip}\n")
    }
}

fn format_site_addresses(
    scheme: &str,
    port: u16,
    primary: &Hostname,
    alias: Option<&Hostname>,
) -> String {
    match alias {
        Some(alias) => format!(
            "{scheme}://{}:{port}, {scheme}://{}:{port}",
            primary.as_str(),
            alias.as_str()
        ),
        None => format!("{scheme}://{}:{port}", primary.as_str()),
    }
}

/// Renders one `reverse_proxy` directive to a loopback target with strict
/// spoofing-resistant header sanitization and optional unbuffered SSE flushing.
///
/// W662-F1: with no `trusted_proxies`, Caddy itself replaces any client
/// `X-Forwarded-For`/`-Proto`/`-Host` with authentic values. `header_up -X`
/// deletions run AFTER sets and after those defaults, so they removed the
/// authentic headers too; only `X-Real-IP` needs an explicit overwrite.
fn render_reverse_proxy(upstream: SocketAddr, sse: bool, indent: &str) -> String {
    let inner = format!("{indent}\t");
    let mut out = format!("{indent}reverse_proxy {upstream} {{\n");
    out.push_str(&format!("{inner}header_up X-Real-IP {{remote_host}}\n"));
    if sse {
        out.push_str(&format!("{inner}flush_interval -1\n"));
    }
    out.push_str(&format!("{indent}}}\n"));
    out
}

/// Renders the static SPA handler block for `static_spa` and `fullstack_split`.
fn render_static_spa_block(
    account: &str,
    frontend_dir: &str,
    spa_fallback: bool,
    indent: &str,
) -> Result<String, ExecutorError> {
    if !valid_frontend_dir(frontend_dir) {
        return Err(ExecutorError::InvalidRequest);
    }
    let inner = format!("{indent}\t");
    let root_path = format!("{SITES}/{account}/current/{frontend_dir}");
    let mut out = String::new();
    out.push_str(&format!("{indent}handle {{\n"));
    out.push_str(&format!("{inner}root * {root_path}\n"));
    out.push_str(&format!("{inner}encode zstd gzip\n"));
    out.push_str(&format!(
        "{inner}@hashed_{account} path /assets/* /_astro/* /_next/static/*\n"
    ));
    out.push_str(&format!(
        "{inner}header @hashed_{account} Cache-Control \"public, max-age=31536000, immutable\"\n"
    ));
    if spa_fallback {
        out.push_str(&format!(
            "{inner}try_files {{path}} {{path}}/ /index.html\n"
        ));
    }
    out.push_str(&format!("{inner}file_server\n"));
    out.push_str(&format!("{indent}}}\n"));
    Ok(out)
}

#[derive(Clone, Debug)]
struct ProxyRouteEntry {
    prefix: String,
    port: u16,
    strip_prefix: bool,
    sse: bool,
}

/// Collects and sorts non-root routes (longest prefix first, then lexicographical)
/// so specific paths like `/api/v2/stream` always match before `/api`.
fn collect_non_root_routes(
    facts: &AppFacts,
    spec: &AppFullstackSpec,
    backend_port: u16,
    frontend_port: Option<u16>,
) -> Result<Vec<ProxyRouteEntry>, ExecutorError> {
    let mut by_prefix: BTreeMap<String, ProxyRouteEntry> = BTreeMap::new();
    let sse_set: BTreeSet<&str> = spec.sse_prefixes.iter().map(String::as_str).collect();
    let strip_set: BTreeSet<&str> = spec.strip_api_prefixes.iter().map(String::as_str).collect();

    let resolve_port = |route_port: u16| -> Result<u16, ExecutorError> {
        if route_port == facts.port {
            Ok(backend_port)
        } else if Some(route_port) == spec.frontend_port {
            frontend_port.ok_or(ExecutorError::InvalidRequest)
        } else {
            Err(ExecutorError::InvalidRequest)
        }
    };

    for route in facts.routes.routes.iter().chain(&facts.routes.websockets) {
        if !valid_prefix(&route.prefix) {
            return Err(ExecutorError::InvalidRequest);
        }
        if route.prefix == "/" {
            continue;
        }
        let target_port = resolve_port(route.port)?;
        let entry = ProxyRouteEntry {
            prefix: route.prefix.clone(),
            port: target_port,
            strip_prefix: strip_set.contains(route.prefix.as_str()),
            sse: sse_set.contains(route.prefix.as_str()),
        };
        by_prefix.insert(route.prefix.clone(), entry);
    }

    // Any declared SSE prefix that isn't explicitly listed in routes/websockets still
    // receives an explicit unbuffered route pointing at the active backend port.
    for sse_prefix in &spec.sse_prefixes {
        if !valid_prefix(sse_prefix) {
            return Err(ExecutorError::InvalidRequest);
        }
        if sse_prefix == "/" {
            continue;
        }
        by_prefix
            .entry(sse_prefix.clone())
            .and_modify(|e| e.sse = true)
            .or_insert_with(|| ProxyRouteEntry {
                prefix: sse_prefix.clone(),
                port: backend_port,
                strip_prefix: strip_set.contains(sse_prefix.as_str()),
                sse: true,
            });
    }

    let mut routes: Vec<ProxyRouteEntry> = by_prefix.into_values().collect();
    routes.sort_by(|a, b| {
        b.prefix
            .len()
            .cmp(&a.prefix.len())
            .then_with(|| a.prefix.cmp(&b.prefix))
    });
    Ok(routes)
}

/// Renders one non-root route matcher + `handle` block without prefix bleed
/// (matches exact `/prefix` and `/prefix/*`, never `/prefix2`).
fn render_route_handle(idx: usize, route: &ProxyRouteEntry, indent: &str) -> String {
    let trimmed = route.prefix.trim_end_matches('/');
    let matcher = format!("@route_{idx}");
    let inner = format!("{indent}\t");
    let upstream = SocketAddr::from(([127, 0, 0, 1], route.port));
    let mut out = String::new();
    out.push_str(&format!("{indent}{matcher} path {trimmed} {trimmed}/*\n"));
    out.push_str(&format!("{indent}handle {matcher} {{\n"));
    if route.strip_prefix {
        out.push_str(&format!("{inner}uri strip_prefix {trimmed}\n"));
    }
    if !route.sse {
        out.push_str(&format!("{inner}encode zstd gzip\n"));
    }
    out.push_str(&render_reverse_proxy(upstream, route.sse, &inner));
    out.push_str(&format!("{indent}}}\n"));
    out
}

/// Renders the routing body for one site (shared between HTTP-only and HTTPS blocks).
fn render_site_routes(
    site: &CaddySite,
    config: &CaddyRenderConfig,
    indent: &str,
) -> Result<String, ExecutorError> {
    let mut out = String::new();
    let inner = format!("{indent}\t");

    // Always serve Rustiron's exact site identity marker directly from disk so
    // activation probes verify site routing even when an app backend is busy.
    out.push_str(&format!("{indent}handle /rustiron-site.txt {{\n"));
    out.push_str(&format!("{inner}root * {SITES}/{}/html\n", site.account));
    out.push_str(&format!("{inner}file_server\n"));
    out.push_str(&format!("{indent}}}\n"));

    match &site.kind {
        CaddySiteKind::OlsBridge => {
            if config.mode != CaddyIngressMode::CaddyEdgeOverOls {
                return Err(ExecutorError::BindingDenied);
            }
            let upstream = config.ols_upstream.ok_or(ExecutorError::BindingDenied)?;
            out.push_str(&format!("{indent}handle {{\n"));
            out.push_str(&render_reverse_proxy(upstream, false, &inner));
            out.push_str(&format!("{indent}}}\n"));
        }
        CaddySiteKind::App { facts, spec } => {
            if !spec.is_valid_with(facts) {
                return Err(ExecutorError::InvalidRequest);
            }
            match spec.topology {
                AppTopology::StaticSpa => {
                    let dir = spec
                        .frontend_dir
                        .as_deref()
                        .ok_or(ExecutorError::InvalidRequest)?;
                    out.push_str(&render_static_spa_block(
                        &site.account,
                        dir,
                        spec.spa_fallback,
                        indent,
                    )?);
                }
                AppTopology::BackendApi => {
                    let backend_port = active_backend_port(facts, spec)?;
                    let routes = collect_non_root_routes(facts, spec, backend_port, None)?;
                    for (idx, route) in routes.iter().enumerate() {
                        out.push_str(&render_route_handle(idx, route, indent));
                    }
                    let root_sse = spec.sse_prefixes.iter().any(|p| p == "/");
                    let upstream = SocketAddr::from(([127, 0, 0, 1], backend_port));
                    out.push_str(&format!("{indent}handle {{\n"));
                    if !root_sse {
                        out.push_str(&format!("{inner}encode zstd gzip\n"));
                    }
                    out.push_str(&render_reverse_proxy(upstream, root_sse, &inner));
                    out.push_str(&format!("{indent}}}\n"));
                }
                AppTopology::FullstackSplit => {
                    let backend_port = active_backend_port(facts, spec)?;
                    let dir = spec
                        .frontend_dir
                        .as_deref()
                        .ok_or(ExecutorError::InvalidRequest)?;
                    let routes = collect_non_root_routes(facts, spec, backend_port, None)?;
                    for (idx, route) in routes.iter().enumerate() {
                        out.push_str(&render_route_handle(idx, route, indent));
                    }
                    out.push_str(&render_static_spa_block(
                        &site.account,
                        dir,
                        spec.spa_fallback,
                        indent,
                    )?);
                }
                AppTopology::FullstackDualSsr => {
                    let backend_port = active_backend_port(facts, spec)?;
                    let frontend_port = active_frontend_port(spec)?;
                    let routes =
                        collect_non_root_routes(facts, spec, backend_port, Some(frontend_port))?;
                    for (idx, route) in routes.iter().enumerate() {
                        out.push_str(&render_route_handle(idx, route, indent));
                    }
                    let root_sse = spec.sse_prefixes.iter().any(|p| p == "/");
                    let upstream = SocketAddr::from(([127, 0, 0, 1], frontend_port));
                    out.push_str(&format!("{indent}handle {{\n"));
                    if !root_sse {
                        out.push_str(&format!("{inner}encode zstd gzip\n"));
                    }
                    out.push_str(&render_reverse_proxy(upstream, root_sse, &inner));
                    out.push_str(&format!("{indent}}}\n"));
                }
            }
        }
    }

    Ok(out)
}

/// Renders one per-site `.caddy` file containing its HTTP block (with optional
/// ACME HTTP-01 challenge handler and HTTPS redirect) and optional HTTPS block
/// loading read-only shared `rustiron-acme` certificates (Decision B1).
fn render_site_file(site: &CaddySite, config: &CaddyRenderConfig) -> Result<String, ExecutorError> {
    if !valid_account_name(&site.account) {
        return Err(ExecutorError::InvalidRequest);
    }
    let http_port = config.http_address.port();
    let https_port = config.https_address.port();
    let http_bind = format_bind_line(config.http_address.ip());
    let https_bind = format_bind_line(config.https_address.ip());

    let mut out = format!(
        "# Managed by Rustiron (D-102) for {}; do not edit by hand.\n",
        site.account
    );

    // HTTP site block: always serves ACME HTTP-01 challenges (when webroot exists)
    // and /rustiron-site.txt. Redirects to HTTPS when TLS is installed; otherwise
    // serves the site directly over HTTP.
    let http_addrs = format_site_addresses(
        "http",
        http_port,
        &site.hostname,
        site.alias_hostname.as_ref(),
    );
    out.push_str(&format!("{http_addrs} {{\n"));
    out.push_str(&http_bind);
    if site.acme {
        out.push_str("\thandle /.well-known/acme-challenge/* {\n");
        out.push_str(&format!(
            "\t\troot * {}\n",
            ols::acme_webroot(&site.account)
        ));
        out.push_str("\t\tfile_server\n");
        out.push_str("\t}\n");
    }
    if site.tls.is_some() {
        out.push_str("\thandle /rustiron-site.txt {\n");
        out.push_str(&format!("\t\troot * {SITES}/{}/html\n", site.account));
        out.push_str("\t\tfile_server\n");
        out.push_str("\t}\n");
        let target = if https_port == 443 {
            "https://{host}{uri}".to_owned()
        } else {
            format!("https://{{host}}:{https_port}{{uri}}")
        };
        out.push_str("\thandle {\n");
        out.push_str(&format!("\t\tredir {target} 308\n"));
        out.push_str("\t}\n");
        out.push_str("}\n");

        // HTTPS site block: reads shared rustiron-acme live symlink read-only (Decision B1).
        let https_addrs = format_site_addresses(
            "https",
            https_port,
            &site.hostname,
            site.alias_hostname.as_ref(),
        );
        let tls_live = ols::tls_live(&site.account);
        out.push_str(&format!("\n{https_addrs} {{\n"));
        out.push_str(&https_bind);
        out.push_str(&format!(
            "\ttls {tls_live}/fullchain.pem {tls_live}/key.pem\n"
        ));
        out.push_str(&render_site_routes(site, config, "\t")?);
        out.push_str("}\n");
    } else {
        out.push_str(&render_site_routes(site, config, "\t")?);
        out.push_str("}\n");
    }

    Ok(out)
}

/// Renders a complete, deterministic Caddy generation (`Caddyfile` + sorted
/// per-site `<account>.caddy` files).
///
/// Refuses duplicate accounts, duplicate hostnames, invalid site specs,
/// forbidden ports, or OLS bridge sites outside `caddy_edge_over_ols`.
pub fn render(
    config: &CaddyRenderConfig,
    sites: &[CaddySite],
) -> Result<CaddyGeneration, ExecutorError> {
    config.validate()?;
    let mut ordered: Vec<&CaddySite> = sites.iter().collect();
    ordered.sort_by(|a, b| a.account.cmp(&b.account));

    let mut seen_accounts = BTreeSet::new();
    let mut seen_hosts = BTreeSet::new();
    let mut files = CaddyGeneration::new();

    let mut main_caddyfile = format!(
        "# Managed by Rustiron (D-102, mode={}); do not edit by hand.\n\
         {{\n\
         \tadmin unix/{CADDY_ADMIN_SOCKET}\n\
         \tpersist_config off\n\
         \tauto_https disable_certs\n\
         \thttp_port {}\n\
         \thttps_port {}\n\
         \tservers {{\n\
         \t\tprotocols h1 h2 h3\n\
         \t}}\n\
         }}\n",
        config.mode.as_str(),
        config.http_address.port(),
        config.https_address.port(),
    );

    for site in ordered {
        if !seen_accounts.insert(site.account.as_str()) {
            return Err(ExecutorError::Collision);
        }
        if !seen_hosts.insert(site.hostname.as_str()) {
            return Err(ExecutorError::Collision);
        }
        if let Some(alias) = &site.alias_hostname
            && !seen_hosts.insert(alias.as_str())
        {
            return Err(ExecutorError::Collision);
        }
        let body = render_site_file(site, config)?;
        let filename = format!("{}.caddy", site.account);
        main_caddyfile.push_str(&format!("\nimport {filename}\n"));
        files.insert(filename, body.into_bytes());
    }

    files.insert("Caddyfile".to_owned(), main_caddyfile.into_bytes());
    Ok(files)
}

/// Content-addressed SHA-256 digest of a rendered Caddy generation.
pub fn digest(generation: &CaddyGeneration) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"rustiron/caddy-generation/v1\0");
    for (name, bytes) in generation {
        hasher.update((name.len() as u64).to_be_bytes());
        hasher.update(name.as_bytes());
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

/// Content-addressed generation ID (`c` + first 16 hex chars of [`digest`]).
pub fn generation_id(digest: &Sha256Digest) -> Id {
    let id = format!("c{}", &digest.as_str()[..16]);
    Id::try_from(id).expect("fixed 17-byte ASCII caddy generation identifier")
}

/// Verifies `/usr/local/bin/caddy` (or `binary_path`) is a single-link, root-owned,
/// non-group/world-writable executable regular file matching the enrolled SHA-256.
pub fn verify_caddy_binary(
    binary_path: &Path,
    expected_sha256: &Sha256Digest,
    expected_owner: u32,
) -> Result<(), ExecutorError> {
    let fd = fs::open(
        binary_path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ExecutorError::Unavailable)?;
    let stat = fs::fstat(&fd).map_err(|_| ExecutorError::Unavailable)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_nlink != 1
        || stat.st_uid != expected_owner
        || stat.st_mode & 0o022 != 0
        || stat.st_mode & 0o111 == 0
        || stat.st_size < 0
        || (stat.st_size as u64) > MAX_BINARY_BYTES
    {
        return Err(ExecutorError::AccessDenied);
    }
    let mut file = File::from(fd);
    let mut hasher = Sha256::new();
    let mut buf = [0_u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|_| ExecutorError::Unavailable)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let actual = Sha256Digest::from_bytes(hasher.finalize().into());
    if &actual != expected_sha256 {
        return Err(ExecutorError::Drift);
    }
    Ok(())
}

/// Runs `caddy validate --config <caddyfile> --adapter caddyfile` with a strict
/// timeout and sanitized environment, returning `Err(StepFailed)` if Caddy
/// rejects the generated configuration.
pub fn validate_caddyfile_with(binary: &Path, caddyfile: &Path) -> Result<(), ExecutorError> {
    let mut child = Command::new(binary)
        .args(["validate", "--config"])
        .arg(caddyfile)
        .args(["--adapter", "caddyfile"])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        // W662: never read, so a piped stderr could fill and stall until the timeout.
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ExecutorError::Unavailable)?;
    let deadline = Instant::now() + VALIDATE_TIMEOUT;
    loop {
        match child.try_wait().map_err(|_| ExecutorError::StepFailed)? {
            Some(status) => {
                return if status.success() {
                    Ok(())
                } else {
                    Err(ExecutorError::StepFailed)
                };
            }
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ExecutorError::StepFailed);
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// Opens the trusted Caddy config directory (`CONFIG_DIR`, root-owned, mode 0755).
pub fn open_config_dir() -> Result<OwnedFd, ExecutorError> {
    files::open_traversable_directory(Path::new(CONFIG_DIR), 0)
}

/// Reads back every regular file inside a generation directory, refusing
/// symlinks, subdirectories, non-owner files, writable modes, or oversized files.
fn read_generation_dir(dir: &OwnedFd, owner: u32) -> Result<CaddyGeneration, ExecutorError> {
    let mut names = Vec::new();
    for entry in fs::Dir::read_from(dir).map_err(|_| ExecutorError::Drift)? {
        let name = entry
            .map_err(|_| ExecutorError::Drift)?
            .file_name()
            .to_string_lossy()
            .into_owned();
        if name == "." || name == ".." {
            continue;
        }
        names.push(name);
    }
    names.sort();
    let mut out = CaddyGeneration::new();
    for name in names {
        let bytes = files::read_child(dir, &name, owner, files::Exposure::Readable, MAX_FILE)?;
        out.insert(name, bytes);
    }
    Ok(out)
}

/// Observes the active `current` symlink (`generations/<id>`) inside `config_dir`.
/// Returns `Ok(None)` when `current` is absent (bootstrap state before first activation).
pub fn observe_current_owned(
    config_dir: &OwnedFd,
    owner: u32,
) -> Result<Option<(Id, Sha256Digest)>, ExecutorError> {
    let link = match fs::readlinkat(config_dir, "current", Vec::new()) {
        Ok(bytes) => bytes,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(ExecutorError::Drift),
    };
    let target = link.to_str().map_err(|_| ExecutorError::Drift)?;
    let Some(raw_id) = target.strip_prefix("generations/") else {
        return Err(ExecutorError::Drift);
    };
    let id = Id::try_from(raw_id.to_owned()).map_err(|_| ExecutorError::Drift)?;
    let generations = files::open_child_directory(config_dir, "generations", owner)?;
    let gen_dir = files::open_child_directory(&generations, id.as_str(), owner)?;
    let stored = read_generation_dir(&gen_dir, owner)?;
    let actual_digest = digest(&stored);
    if id != generation_id(&actual_digest) {
        return Err(ExecutorError::Drift);
    }
    Ok(Some((id, actual_digest)))
}

/// Validator callback invoked on a staged `Caddyfile` before publishing.
pub type CaddyfileValidator<'a> = &'a dyn Fn(&Path) -> Result<(), ExecutorError>;

/// Activation callbacks for validating, reloading, and probing a generation.
pub struct ActivationHooks<'a> {
    /// Optional `caddy validate` hook run on the temporary staged `Caddyfile`.
    pub validator: Option<CaddyfileValidator<'a>>,
    /// Reload/start + health probe hook; receives `true` on initial bootstrap start.
    pub reload_and_probe: &'a dyn Fn(bool) -> Result<(), ExecutorError>,
}

/// Crash-safely stages a rendered generation into `<config_dir>/generations/<id>`
/// (write temp -> fsync -> read-back verify -> optional validate -> atomic `RENAME_NOREPLACE`),
/// quarantining any differing pre-existing folder under `<id>`.
pub fn stage_and_validate_owned(
    config_root: &Path,
    config_dir: &OwnedFd,
    id: &Id,
    generation: &CaddyGeneration,
    operation: &Id,
    owner: u32,
    validator: Option<CaddyfileValidator<'_>>,
) -> Result<(), ExecutorError> {
    let generations = files::open_child_directory(config_dir, "generations", owner)?;
    match fs::statat(&generations, id.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => {
            if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
                || stat.st_uid != owner
                || stat.st_mode & 0o022 != 0
            {
                return Err(ExecutorError::Collision);
            }
            let existing_dir = files::open_child_directory(&generations, id.as_str(), owner)
                .map_err(|_| ExecutorError::Collision)?;
            if read_generation_dir(&existing_dir, owner).ok().as_ref() == Some(generation) {
                if let Some(validate) = validator {
                    let caddyfile = config_root
                        .join("generations")
                        .join(id.as_str())
                        .join("Caddyfile");
                    validate(&caddyfile)?;
                }
                return Ok(());
            }
            let quarantine = format!("{}{QUARANTINE_MARK}{}", id.as_str(), operation.as_str());
            fs::renameat_with(
                &generations,
                id.as_str(),
                &generations,
                quarantine.as_str(),
                fs::RenameFlags::NOREPLACE,
            )
            .map_err(|_| ExecutorError::Collision)?;
            fs::fsync(&generations).map_err(|_| ExecutorError::StepFailed)?;
        }
        Err(rustix::io::Errno::NOENT) => {}
        Err(_) => return Err(ExecutorError::StepFailed),
    }

    let temporary = format!("{}{STAGING_MARK}{}", id.as_str(), ols::stage::random_hex()?);
    let temp_path = config_root.join("generations").join(&temporary);
    let write_res = (|| -> Result<(u64, u64), ExecutorError> {
        fs::mkdirat(&generations, &temporary, Mode::from_raw_mode(0o755))
            .map_err(|_| ExecutorError::StepFailed)?;
        let dir = files::open_child_directory(&generations, &temporary, owner)?;
        fs::fchmod(&dir, Mode::from_raw_mode(0o755)).map_err(|_| ExecutorError::StepFailed)?;
        for (name, bytes) in generation {
            let fd = fs::openat(
                &dir,
                name.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o644),
            )
            .map_err(|_| ExecutorError::StepFailed)?;
            fs::fchmod(&fd, Mode::from_raw_mode(0o644)).map_err(|_| ExecutorError::StepFailed)?;
            let mut file = File::from(fd);
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|_| ExecutorError::StepFailed)?;
        }
        fs::fsync(&dir).map_err(|_| ExecutorError::StepFailed)?;
        if read_generation_dir(&dir, owner)? != *generation {
            return Err(ExecutorError::StepFailed);
        }
        if let Some(validate) = validator {
            validate(&temp_path.join("Caddyfile"))?;
        }
        let stat = fs::fstat(&dir).map_err(|_| ExecutorError::StepFailed)?;
        Ok((stat.st_dev, stat.st_ino))
    })();

    let identity = match write_res {
        Ok(id_pair) => id_pair,
        Err(err) => {
            let _ = std::fs::remove_dir_all(&temp_path);
            return Err(err);
        }
    };

    let stat_before = fs::statat(&generations, &temporary, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| ExecutorError::Collision)?;
    if (stat_before.st_dev, stat_before.st_ino) != identity {
        return Err(ExecutorError::Collision);
    }
    fs::renameat_with(
        &generations,
        &temporary,
        &generations,
        id.as_str(),
        fs::RenameFlags::NOREPLACE,
    )
    .map_err(|err| {
        if err == rustix::io::Errno::EXIST {
            ExecutorError::Collision
        } else {
            ExecutorError::StepFailed
        }
    })?;
    fs::fsync(&generations).map_err(|_| ExecutorError::StepFailed)?;
    let stat_after = fs::statat(&generations, id.as_str(), AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| ExecutorError::Collision)?;
    if (stat_after.st_dev, stat_after.st_ino) != identity {
        return Err(ExecutorError::Collision);
    }
    Ok(())
}

/// Atomically swaps `<config_dir>/current` -> `generations/<id>` via a sibling
/// temporary symlink + `renameat` + `fsync`.
pub fn switch_current(config_dir: &OwnedFd, id: &Id) -> Result<(), ExecutorError> {
    let target = format!("generations/{}", id.as_str());
    let tmp_link = format!("current.next-{}", ols::stage::random_hex()?);
    fs::symlinkat(target.as_str(), config_dir, tmp_link.as_str())
        .map_err(|_| ExecutorError::StepFailed)?;
    if fs::renameat(config_dir, tmp_link.as_str(), config_dir, "current").is_err() {
        let _ = fs::unlinkat(config_dir, tmp_link.as_str(), AtFlags::empty());
        return Err(ExecutorError::StepFailed);
    }
    fs::fsync(config_dir).map_err(|_| ExecutorError::StepFailed)
}

/// Removes `<config_dir>/current` (used only when rolling back a bootstrap activation
/// where no previous generation existed).
pub fn clear_current(config_dir: &OwnedFd) -> Result<(), ExecutorError> {
    match fs::unlinkat(config_dir, "current", AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => {
            fs::fsync(config_dir).map_err(|_| ExecutorError::StepFailed)
        }
        Err(_) => Err(ExecutorError::StepFailed),
    }
}

/// Applies a validated generation with atomic symlink swap, reload (or bootstrap
/// start), and automatic rollback to `previous` if `reload_and_probe` fails.
pub fn activate_with_rollback(
    config_root: &Path,
    config_dir: &OwnedFd,
    target_id: &Id,
    generation: &CaddyGeneration,
    operation: &Id,
    owner: u32,
    hooks: &ActivationHooks<'_>,
) -> Result<Option<Id>, ExecutorError> {
    let previous = observe_current_owned(config_dir, owner)?.map(|(id, _)| id);
    stage_and_validate_owned(
        config_root,
        config_dir,
        target_id,
        generation,
        operation,
        owner,
        hooks.validator,
    )?;
    switch_current(config_dir, target_id)?;
    let is_bootstrap = previous.is_none();
    if let Err(err) = (hooks.reload_and_probe)(is_bootstrap) {
        if let Some(prev_id) = &previous {
            let _ = switch_current(config_dir, prev_id);
            let _ = (hooks.reload_and_probe)(false);
        } else {
            let _ = clear_current(config_dir);
        }
        return Err(err);
    }
    Ok(previous)
}

/// Reloads (or starts on bootstrap) `rustiron-caddy.service` via systemd.
pub fn reload_service(is_bootstrap: bool) -> Result<(), ExecutorError> {
    let verb = if is_bootstrap { "start" } else { "reload" };
    provision::run("/usr/bin/systemctl", &[verb, CADDY_UNIT])
}

/// Activates a generation on the live host after verifying the pinned Caddy binary
/// SHA-256 and validating the staged Caddyfile with `caddy validate`.
pub fn activate_live(
    generation: &CaddyGeneration,
    operation: &Id,
    expected_binary_sha256: &Sha256Digest,
    probe: &dyn Fn() -> Result<(), ExecutorError>,
) -> Result<(Id, Sha256Digest, Option<Id>), ExecutorError> {
    let binary = Path::new(CADDY_BINARY);
    verify_caddy_binary(binary, expected_binary_sha256, 0)?;
    let gen_digest = digest(generation);
    let gen_id = generation_id(&gen_digest);
    let config_dir = open_config_dir()?;
    let validator = |caddyfile: &Path| validate_caddyfile_with(binary, caddyfile);
    let reload_and_probe = |is_bootstrap: bool| {
        reload_service(is_bootstrap)?;
        probe()
    };
    let hooks = ActivationHooks {
        validator: Some(&validator),
        reload_and_probe: &reload_and_probe,
    };
    let previous = activate_with_rollback(
        Path::new(CONFIG_DIR),
        &config_dir,
        &gen_id,
        generation,
        operation,
        0,
        &hooks,
    )?;
    Ok((gen_id, gen_digest, previous))
}

/// Resolves the active path of `Caddyfile` inside `CONFIG_DIR/current/Caddyfile`.
#[allow(dead_code)]
pub(crate) fn current_caddyfile_path() -> PathBuf {
    Path::new(CONFIG_DIR).join("current").join("Caddyfile")
}

/// Converts an enrolled [`CaddyPolicy`](crate::policy::CaddyPolicy) into a
/// validated [`CaddyRenderConfig`].
pub(crate) fn render_config_from_policy(
    policy: &crate::policy::CaddyPolicy,
) -> Result<CaddyRenderConfig, ExecutorError> {
    let mode = match policy.mode {
        crate::policy::CaddyMode::Only => CaddyIngressMode::CaddyOnly,
        crate::policy::CaddyMode::MultiIp => CaddyIngressMode::CaddyMultiIp,
        crate::policy::CaddyMode::EdgeOverOls => CaddyIngressMode::CaddyEdgeOverOls,
    };
    let http_address: SocketAddr = policy
        .http_address
        .parse()
        .map_err(|_| ExecutorError::BindingDenied)?;
    let https_address: SocketAddr = policy
        .https_address
        .parse()
        .map_err(|_| ExecutorError::BindingDenied)?;
    let ols_upstream = match &policy.ols_upstream {
        Some(raw) => Some(raw.parse().map_err(|_| ExecutorError::BindingDenied)?),
        None => None,
    };
    let cfg = CaddyRenderConfig {
        mode,
        http_address,
        https_address,
        ols_upstream,
    };
    cfg.validate()?;
    Ok(cfg)
}

/// W659 (D-102): builds the deterministic sorted [`CaddySite`] inventory from
/// trusted [`OperationRecords`](rustiron_journal::OperationRecords) and the
/// enrolled [`CaddyPolicy`](crate::policy::CaddyPolicy).
///
/// - Owned, non-ejected modern apps with `ingress == Caddy` are rendered with
///   their exact `AppFacts`, `AppFullstackSpec`, and live `active_slot`.
/// - Under Decision A1 (`caddy_edge_over_ols`), owned non-ejected WordPress,
///   static, proxy, or OLS-routed sites are rendered as [`CaddySiteKind::OlsBridge`]
///   proxied over loopback to OLS.
pub(crate) fn sites_from_records(
    policy: &crate::policy::CaddyPolicy,
    records: &rustiron_journal::OperationRecords,
) -> Result<Vec<CaddySite>, ExecutorError> {
    use rustiron_contracts::approval::IngressEngine;
    let bridge_ols = policy.mode == crate::policy::CaddyMode::EdgeOverOls;
    let mut sites = Vec::new();
    for prov in &records.served {
        let site_id = &prov.intent.site_id;
        if records.ejected.contains(site_id) {
            continue;
        }
        let account = provision::SiteLayout::derive(site_id).account;
        let alias_hostname = records.served_aliases.get(site_id.as_str()).cloned();
        let tls = records
            .certificates
            .iter()
            .find(|(s, _)| s == site_id)
            .map(|(_, sha)| sha.clone());
        let kind = match records.served_apps.get(site_id.as_str()) {
            Some((facts, Some(spec))) if spec.ingress == IngressEngine::Caddy => {
                CaddySiteKind::App {
                    facts: Box::new(facts.clone()),
                    spec: Box::new(spec.clone()),
                }
            }
            _ if bridge_ols => CaddySiteKind::OlsBridge,
            _ => continue,
        };
        sites.push(CaddySite {
            account,
            hostname: prov.intent.hostname.clone(),
            alias_hostname,
            tls,
            acme: true,
            kind,
        });
    }
    sites.sort_by(|a, b| a.account.cmp(&b.account));
    Ok(sites)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use rustiron_contracts::approval::{AppDatabase, AppRuntime, IngressEngine, ProxyRoute};
    use rustiron_journal::ProxyFacts;

    use super::*;

    fn host(name: &str) -> Hostname {
        Hostname::try_from(name.to_owned()).unwrap()
    }

    fn sha(ch: char) -> Sha256Digest {
        Sha256Digest::try_from(ch.to_string().repeat(64)).unwrap()
    }

    fn edge_config() -> CaddyRenderConfig {
        CaddyRenderConfig {
            mode: CaddyIngressMode::CaddyEdgeOverOls,
            http_address: "203.0.113.10:80".parse().unwrap(),
            https_address: "203.0.113.10:443".parse().unwrap(),
            ols_upstream: Some("127.0.0.1:8080".parse().unwrap()),
        }
    }

    fn caddy_only_config() -> CaddyRenderConfig {
        CaddyRenderConfig {
            mode: CaddyIngressMode::CaddyOnly,
            http_address: "203.0.113.10:80".parse().unwrap(),
            https_address: "203.0.113.10:443".parse().unwrap(),
            ols_upstream: None,
        }
    }

    fn static_spa_site() -> CaddySite {
        CaddySite {
            account: "rs_spa1".to_owned(),
            hostname: host("spa.example.test"),
            alias_hostname: None,
            tls: Some(sha('a')),
            acme: true,
            kind: CaddySiteKind::App {
                facts: Box::new(AppFacts {
                    runtime: AppRuntime::StaticV1,
                    port: 0,
                    entrypoint: String::new(),
                    worker_entrypoint: None,
                    health_path: "/".to_owned(),
                    env_keys: vec![],
                    memory_max_mib: 64,
                    tasks_max: 16,
                    quota_mib: 512,
                    routes: ProxyFacts {
                        routes: vec![],
                        websockets: vec![],
                    },
                }),
                spec: Box::new(AppFullstackSpec {
                    ingress: IngressEngine::Caddy,
                    topology: AppTopology::StaticSpa,
                    database: AppDatabase::None,
                    blue_green: false,
                    active_slot: AppSlot::A,
                    standby_port: None,
                    spa_fallback: true,
                    frontend_dir: Some("frontend".to_owned()),
                    frontend_runtime: None,
                    frontend_entrypoint: None,
                    frontend_port: None,
                    frontend_standby_port: None,
                    sse_prefixes: vec![],
                    strip_api_prefixes: vec![],
                }),
            },
        }
    }

    fn fullstack_split_site(slot: AppSlot) -> CaddySite {
        CaddySite {
            account: "rs_split1".to_owned(),
            hostname: host("app.example.test"),
            alias_hostname: Some(host("www.app.example.test")),
            tls: Some(sha('b')),
            acme: true,
            kind: CaddySiteKind::App {
                facts: Box::new(AppFacts {
                    runtime: AppRuntime::Bun1V1,
                    port: 4101,
                    entrypoint: "backend/server.js".to_owned(),
                    worker_entrypoint: None,
                    health_path: "/api/health".to_owned(),
                    env_keys: vec!["DATABASE_URL".to_owned()],
                    memory_max_mib: 512,
                    tasks_max: 64,
                    quota_mib: 2048,
                    routes: ProxyFacts {
                        routes: vec![
                            ProxyRoute {
                                prefix: "/api/".to_owned(),
                                port: 4101,
                            },
                            ProxyRoute {
                                prefix: "/api/events/".to_owned(),
                                port: 4101,
                            },
                        ],
                        websockets: vec![ProxyRoute {
                            prefix: "/ws/".to_owned(),
                            port: 4101,
                        }],
                    },
                }),
                spec: Box::new(AppFullstackSpec {
                    ingress: IngressEngine::Caddy,
                    topology: AppTopology::FullstackSplit,
                    database: AppDatabase::Postgresql18,
                    blue_green: true,
                    active_slot: slot,
                    standby_port: Some(4102),
                    spa_fallback: true,
                    frontend_dir: Some("frontend".to_owned()),
                    frontend_runtime: None,
                    frontend_entrypoint: None,
                    frontend_port: None,
                    frontend_standby_port: None,
                    sse_prefixes: vec!["/api/events/".to_owned()],
                    strip_api_prefixes: vec!["/api/".to_owned()],
                }),
            },
        }
    }

    fn dual_ssr_site(slot: AppSlot) -> CaddySite {
        CaddySite {
            account: "rs_dual1".to_owned(),
            hostname: host("ssr.example.test"),
            alias_hostname: None,
            tls: None,
            acme: false,
            kind: CaddySiteKind::App {
                facts: Box::new(AppFacts {
                    runtime: AppRuntime::Bun1V1,
                    port: 4201,
                    entrypoint: "api/index.js".to_owned(),
                    worker_entrypoint: None,
                    health_path: "/api/health".to_owned(),
                    env_keys: vec![],
                    memory_max_mib: 512,
                    tasks_max: 64,
                    quota_mib: 2048,
                    routes: ProxyFacts {
                        routes: vec![
                            ProxyRoute {
                                prefix: "/".to_owned(),
                                port: 4203,
                            },
                            ProxyRoute {
                                prefix: "/api/".to_owned(),
                                port: 4201,
                            },
                        ],
                        websockets: vec![],
                    },
                }),
                spec: Box::new(AppFullstackSpec {
                    ingress: IngressEngine::Caddy,
                    topology: AppTopology::FullstackDualSsr,
                    database: AppDatabase::Mariadb,
                    blue_green: true,
                    active_slot: slot,
                    standby_port: Some(4202),
                    spa_fallback: false,
                    frontend_dir: None,
                    frontend_runtime: Some(AppRuntime::Node22V1),
                    frontend_entrypoint: Some("web/server.mjs".to_owned()),
                    frontend_port: Some(4203),
                    frontend_standby_port: Some(4204),
                    sse_prefixes: vec![],
                    strip_api_prefixes: vec![],
                }),
            },
        }
    }

    fn backend_api_site() -> CaddySite {
        CaddySite {
            account: "rs_api1".to_owned(),
            hostname: host("api.example.test"),
            alias_hostname: None,
            tls: Some(sha('d')),
            acme: true,
            kind: CaddySiteKind::App {
                facts: Box::new(AppFacts {
                    runtime: AppRuntime::Node22V1,
                    port: 4301,
                    entrypoint: "dist/index.mjs".to_owned(),
                    worker_entrypoint: None,
                    health_path: "/healthz".to_owned(),
                    env_keys: vec![],
                    memory_max_mib: 512,
                    tasks_max: 64,
                    quota_mib: 1024,
                    routes: ProxyFacts {
                        routes: vec![ProxyRoute {
                            prefix: "/".to_owned(),
                            port: 4301,
                        }],
                        websockets: vec![ProxyRoute {
                            prefix: "/realtime/".to_owned(),
                            port: 4301,
                        }],
                    },
                }),
                spec: Box::new(AppFullstackSpec {
                    ingress: IngressEngine::Caddy,
                    topology: AppTopology::BackendApi,
                    database: AppDatabase::Sqlite,
                    blue_green: false,
                    active_slot: AppSlot::A,
                    standby_port: None,
                    spa_fallback: false,
                    frontend_dir: None,
                    frontend_runtime: None,
                    frontend_entrypoint: None,
                    frontend_port: None,
                    frontend_standby_port: None,
                    sse_prefixes: vec!["/stream/".to_owned()],
                    strip_api_prefixes: vec![],
                }),
            },
        }
    }

    fn ols_bridge_site() -> CaddySite {
        CaddySite {
            account: "rs_wp1".to_owned(),
            hostname: host("blog.example.test"),
            alias_hostname: None,
            tls: Some(sha('c')),
            acme: true,
            kind: CaddySiteKind::OlsBridge,
        }
    }

    #[test]
    fn renders_all_four_topologies_and_a1_ols_bridge_deterministically() {
        let cfg = edge_config();
        let sites = vec![
            ols_bridge_site(),
            dual_ssr_site(AppSlot::A),
            static_spa_site(),
            fullstack_split_site(AppSlot::A),
            backend_api_site(),
        ];
        let rendered = render(&cfg, &sites).unwrap();
        // Order-independent determinism: reversing input yields identical bytes & digest.
        let reversed: Vec<_> = sites.into_iter().rev().collect();
        let gen_rev = render(&cfg, &reversed).unwrap();
        assert_eq!(rendered, gen_rev);
        assert_eq!(digest(&rendered), digest(&gen_rev));

        let main = std::str::from_utf8(&rendered["Caddyfile"]).unwrap();
        assert!(main.contains("admin unix//run/rustiron-caddy/admin.sock\n"));
        assert!(!main.contains(":2019"));
        assert!(main.contains("persist_config off\n"));
        assert!(main.contains("auto_https disable_certs\n"));
        assert!(main.contains("protocols h1 h2 h3\n"));
        // Imports are in strict lexicographical account order.
        let imports: Vec<_> = main.lines().filter(|l| l.starts_with("import ")).collect();
        assert_eq!(
            imports,
            [
                "import rs_api1.caddy",
                "import rs_dual1.caddy",
                "import rs_spa1.caddy",
                "import rs_split1.caddy",
                "import rs_wp1.caddy",
            ]
        );

        // 1. static_spa: zero reverse_proxy, try_files, immutable hashed cache, B1 shared TLS.
        let spa = std::str::from_utf8(&rendered["rs_spa1.caddy"]).unwrap();
        assert!(!spa.contains("reverse_proxy"));
        assert!(spa.contains("root * /srv/sites/rs_spa1/current/frontend\n"));
        assert!(spa.contains("try_files {path} {path}/ /index.html\n"));
        assert!(spa.contains("encode zstd gzip\n"));
        assert!(spa.contains("Cache-Control \"public, max-age=31536000, immutable\""));
        assert!(spa.contains("tls /etc/rustiron-tls/rs_spa1/live/fullchain.pem /etc/rustiron-tls/rs_spa1/live/key.pem"));
        assert!(spa.contains("handle /.well-known/acme-challenge/*"));
        assert!(spa.contains("redir https://{host}{uri} 308"));

        // 2. fullstack_split: longest prefix (/api/events SSE) before /api (strip_prefix),
        //    /ws WebSocket, sanitized X-Forwarded-* headers, SPA fallback on /.
        let split = std::str::from_utf8(&rendered["rs_split1.caddy"]).unwrap();
        let sse_pos = split.find("path /api/events /api/events/*").unwrap();
        let api_pos = split.find("path /api /api/*").unwrap();
        let spa_pos = split
            .find("root * /srv/sites/rs_split1/current/frontend")
            .unwrap();
        assert!(sse_pos < api_pos && api_pos < spa_pos);
        assert!(split.contains("flush_interval -1\n"));
        assert!(split.contains("uri strip_prefix /api\n"));
        assert!(split.contains("reverse_proxy 127.0.0.1:4101 {"));
        // W662-F1: no `header_up -X` deletions (Caddy runs them after its own
        // authentic X-Forwarded-* values); only X-Real-IP is overwritten.
        assert!(split.contains("header_up X-Real-IP {remote_host}\n"));
        assert!(split.contains("path /ws /ws/*"));

        // 3. fullstack_dual_ssr: /api -> backend 4201, / -> SSR frontend 4203.
        let dual = std::str::from_utf8(&rendered["rs_dual1.caddy"]).unwrap();
        assert!(dual.contains("reverse_proxy 127.0.0.1:4201 {"));
        assert!(dual.contains("reverse_proxy 127.0.0.1:4203 {"));
        assert!(!dual.contains("tls /etc/rustiron-tls"));

        // 4. backend_api: /realtime WS + /stream SSE + / root proxy on 4301.
        let api = std::str::from_utf8(&rendered["rs_api1.caddy"]).unwrap();
        assert!(api.contains("path /realtime /realtime/*"));
        assert!(api.contains("path /stream /stream/*"));
        assert!(api.contains("flush_interval -1\n"));
        assert!(api.contains("reverse_proxy 127.0.0.1:4301 {"));

        // 5. A1 OLS bridge: proxies WordPress domain cleanly to loopback OLS 127.0.0.1:8080.
        let wp = std::str::from_utf8(&rendered["rs_wp1.caddy"]).unwrap();
        assert!(wp.contains("reverse_proxy 127.0.0.1:8080 {"));
        assert!(wp.contains("header_up X-Real-IP {remote_host}\n"));
        for (name, bytes) in &rendered {
            let text = std::str::from_utf8(bytes).unwrap();
            assert!(
                !text.contains("header_up -"),
                "{name} deletes a proxy header"
            );
        }
        assert!(wp.contains(
            "tls /etc/rustiron-tls/rs_wp1/live/fullchain.pem /etc/rustiron-tls/rs_wp1/live/key.pem"
        ));
    }

    #[test]
    fn blue_green_slot_b_switches_rendered_ports_atomically() {
        let cfg = caddy_only_config();
        let gen_a = render(
            &cfg,
            &[fullstack_split_site(AppSlot::A), dual_ssr_site(AppSlot::A)],
        )
        .unwrap();
        let gen_b = render(
            &cfg,
            &[fullstack_split_site(AppSlot::B), dual_ssr_site(AppSlot::B)],
        )
        .unwrap();
        assert_ne!(digest(&gen_a), digest(&gen_b));

        let split_b = std::str::from_utf8(&gen_b["rs_split1.caddy"]).unwrap();
        assert!(split_b.contains("reverse_proxy 127.0.0.1:4102 {"));
        assert!(!split_b.contains("127.0.0.1:4101"));

        let dual_b = std::str::from_utf8(&gen_b["rs_dual1.caddy"]).unwrap();
        assert!(dual_b.contains("reverse_proxy 127.0.0.1:4202 {"));
        assert!(dual_b.contains("reverse_proxy 127.0.0.1:4204 {"));
        assert!(!dual_b.contains("127.0.0.1:4201"));
        assert!(!dual_b.contains("127.0.0.1:4203"));
    }

    #[test]
    fn refuses_ols_bridge_outside_edge_mode_duplicate_hosts_and_bad_ports() {
        // OLS bridge is refused in caddy_only mode.
        assert_eq!(
            render(&caddy_only_config(), &[ols_bridge_site()]).unwrap_err(),
            ExecutorError::BindingDenied
        );

        // Duplicate hostname across two sites is refused.
        let mut dup = static_spa_site();
        dup.account = "rs_spa2".to_owned();
        assert_eq!(
            render(&caddy_only_config(), &[static_spa_site(), dup]).unwrap_err(),
            ExecutorError::Collision
        );

        // Forbidden Caddy admin port 2019 in config is refused.
        let mut bad_cfg = caddy_only_config();
        bad_cfg.http_address = "203.0.113.10:2019".parse().unwrap();
        assert_eq!(
            render(&bad_cfg, &[]).unwrap_err(),
            ExecutorError::BindingDenied
        );

        // Non-loopback OLS upstream is refused.
        let mut bad_edge = edge_config();
        bad_edge.ols_upstream = Some("203.0.113.10:8080".parse().unwrap());
        assert_eq!(
            render(&bad_edge, &[ols_bridge_site()]).unwrap_err(),
            ExecutorError::BindingDenied
        );

        // Invalid account name is refused.
        let mut bad_account = static_spa_site();
        bad_account.account = "../evil".to_owned();
        assert_eq!(
            render(&caddy_only_config(), &[bad_account]).unwrap_err(),
            ExecutorError::InvalidRequest
        );
    }

    #[test]
    fn staging_atomic_switch_validation_failure_and_rollback_preserve_previous_generation() {
        let root = std::env::temp_dir().join(format!(
            "rustiron-caddy-stage-{}-{}",
            std::process::id(),
            ols::stage::random_hex().unwrap()
        ));
        std::fs::create_dir_all(root.join("generations")).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(
            root.join("generations"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let owner = rustix::process::getuid().as_raw();
        let dir_fd = files::open_traversable_directory(&root, owner).unwrap();
        assert_eq!(observe_current_owned(&dir_fd, owner).unwrap(), None);

        let cfg = caddy_only_config();
        let gen1 = render(&cfg, &[static_spa_site()]).unwrap();
        let d1 = digest(&gen1);
        let id1 = generation_id(&d1);
        let op1 = Id::try_from("op_caddy_1".to_owned()).unwrap();

        // 1. Bootstrap activation succeeds and sets `current -> generations/<id1>`.
        let prev = activate_with_rollback(
            &root,
            &dir_fd,
            &id1,
            &gen1,
            &op1,
            owner,
            &ActivationHooks {
                validator: Some(&|path| {
                    assert!(path.is_file());
                    Ok(())
                }),
                reload_and_probe: &|is_bootstrap| {
                    assert!(is_bootstrap);
                    Ok(())
                },
            },
        )
        .unwrap();
        assert_eq!(prev, None);
        assert_eq!(
            observe_current_owned(&dir_fd, owner).unwrap(),
            Some((id1.clone(), d1.clone()))
        );

        // 2. Invalid candidate rejected by validator leaves `current` untouched on id1.
        let gen2 = render(&cfg, &[static_spa_site(), fullstack_split_site(AppSlot::A)]).unwrap();
        let d2 = digest(&gen2);
        let id2 = generation_id(&d2);
        let op2 = Id::try_from("op_caddy_2".to_owned()).unwrap();
        let err = activate_with_rollback(
            &root,
            &dir_fd,
            &id2,
            &gen2,
            &op2,
            owner,
            &ActivationHooks {
                validator: Some(&|_path| Err(ExecutorError::StepFailed)),
                reload_and_probe: &|_boot| panic!("reload must not run after validation failure"),
            },
        )
        .unwrap_err();
        assert_eq!(err, ExecutorError::StepFailed);
        assert_eq!(
            observe_current_owned(&dir_fd, owner).unwrap(),
            Some((id1.clone(), d1.clone()))
        );
        assert!(!root.join("generations").join(id2.as_str()).exists());

        // 3. Reload/probe failure automatically rolls `current` back to id1.
        let reload_calls = std::cell::Cell::new(0_usize);
        let err = activate_with_rollback(
            &root,
            &dir_fd,
            &id2,
            &gen2,
            &op2,
            owner,
            &ActivationHooks {
                validator: Some(&|_path| Ok(())),
                reload_and_probe: &|is_bootstrap| {
                    assert!(!is_bootstrap);
                    let n = reload_calls.get();
                    reload_calls.set(n + 1);
                    if n == 0 {
                        Err(ExecutorError::ProbeFailed)
                    } else {
                        Ok(())
                    }
                },
            },
        )
        .unwrap_err();
        assert_eq!(err, ExecutorError::ProbeFailed);
        assert_eq!(reload_calls.get(), 2);
        assert_eq!(
            observe_current_owned(&dir_fd, owner).unwrap(),
            Some((id1, d1))
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn verify_caddy_binary_enforces_exact_sha256_permissions_and_nofollow() {
        let root = std::env::temp_dir().join(format!(
            "rustiron-caddy-bin-{}-{}",
            std::process::id(),
            ols::stage::random_hex().unwrap()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let bin = root.join("caddy");
        let bytes = b"#!/bin/sh\nexit 0\n";
        std::fs::write(&bin, bytes).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let good_sha = Sha256Digest::from_bytes(Sha256::digest(bytes).into());
        let owner = rustix::process::getuid().as_raw();

        verify_caddy_binary(&bin, &good_sha, owner).unwrap();
        assert_eq!(
            verify_caddy_binary(&bin, &sha('f'), owner).unwrap_err(),
            ExecutorError::Drift
        );
        // Group-writable binary is refused.
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert_eq!(
            verify_caddy_binary(&bin, &good_sha, owner).unwrap_err(),
            ExecutorError::AccessDenied
        );
        // Symlink binary is refused.
        let link = root.join("caddy-link");
        std::os::unix::fs::symlink(&bin, &link).unwrap();
        assert_eq!(
            verify_caddy_binary(&link, &good_sha, owner).unwrap_err(),
            ExecutorError::Unavailable
        );

        std::fs::remove_dir_all(&root).unwrap();
    }
}
