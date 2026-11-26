//! Lab OLS listener generations (S04 W017): render, observe, switch and probe.
//!
//! The include directory has the fixture registry's shape: `current` is a
//! symlink to `generations/<id>`. Every byte of a generation is rendered here
//! from enrolled policy and provision records; nothing comes from a request.

use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    os::fd::OwnedFd,
    path::Path,
    time::Duration,
};

use rustiron_contracts::{
    Id,
    approval::{Hostname, Sha256Digest},
};
use rustix::fs::{self, AtFlags, OFlags};
use sha2::{Digest, Sha256};

use crate::{ExecutorError, files};

pub mod boot_guard;
mod bootstrap;
mod ejected;
pub(crate) mod stage;

pub use bootstrap::{
    ActivationMode, BootstrapFacts, BootstrapStage, OLS_UNIT, SHIPPED_KILL_MODE, activation_mode,
    bootstrap_generation, bootstrap_history_admits, bootstrap_restored, clear_current,
    established_generation, is_bootstrap_predecessor, kill_mode, kill_mode_shipped,
    listener_tables, observe_current, ports_closed, stop_and_wait, unit_state, unit_stopped,
};
pub(crate) use ejected::{archive_ejected, has_eject_marker, write_ejected};
#[cfg(test)]
pub(crate) use stage::stage_owned;
pub use stage::{QUARANTINE_MARK, STAGING_MARK, Staged, Staging, leftovers, prepare, publish};

/// The Rustiron-owned include directory. It is deliberately outside the OLS
/// server root: an OLS reload recursively re-owns `conf/` to `lsadm:nobody`
/// (observed, W017), which would make every generation an OLS-writable file.
pub const INCLUDE_DIR: &str = crate::layout::OLS_INCLUDE_DIR;
const SITES: &str = crate::layout::SITES_ROOT;
const SOCKETS: &str = crate::layout::SITE_SOCKETS_DIR;
const MAX_FILE: usize = 256 * 1024;
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// One enrolled, pre-existing (adopted) site and its identity probe.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdoptedSite {
    /// vhost name and account (for example `site_a`).
    pub name: String,
    /// Mapped hostname.
    pub hostname: Hostname,
    /// UID the site's `g0-identity.php` must report.
    pub uid: u32,
}

/// One provisioned site the generation serves: account and hostname.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServedSite {
    /// `rs_<site_id>`, also vhost and PHP socket name.
    pub account: String,
    /// Hostname from the provision record.
    pub hostname: Hostname,
    /// D-075: an alias on the HTTP listener only.
    pub alias_hostname: Option<Hostname>,
    /// Ejected: its vhost lives in [`EJECTED_DIR`], outside the generation.
    pub ejected: bool,
    /// D-097: ejected as a standalone single-name static site (`enableScript 0`).
    pub static_ejected: bool,
    /// Enrolled for per-site cache storage (lab policy `ols.lscache`).
    pub lscache: bool,
    /// D-059: the SHA-256 of the site's installed certificate chain, whose
    /// files are in [`tls_folder`]; `None` serves the site over HTTP only.
    pub tls: Option<rustiron_contracts::approval::Sha256Digest>,
    /// The second name covered by this installed TLS chain.
    pub tls_alias: Option<Hostname>,
    /// D-059: the site has its HTTP-01 webroot, so its vhost may serve it.
    /// OLS refuses a context whose folder is missing (W461).
    pub acme: bool,
    /// W574 (D-095): a proxy site's journaled routes; its vhost forwards
    /// them to loopback ports and runs no PHP.
    pub proxy: Option<rustiron_journal::ProxyFacts>,
}

/// D-059: where an installed certificate's `fullchain.pem` and `key.pem`
/// are, derived from the account and the certificate digest.
pub fn tls_folder(
    account: &str,
    certificate: &rustiron_contracts::approval::Sha256Digest,
) -> String {
    format!(
        "{}/{account}/{}",
        crate::layout::OLS_TLS_DIR,
        certificate.as_str()
    )
}

/// W461: whether the site's webroot exists as a real folder. Until the
/// issuance record of slice 3, this observation decides the context.
pub fn acme_webroot_present(account: &str) -> bool {
    std::fs::symlink_metadata(acme_webroot(account)).is_ok_and(|meta| meta.is_dir())
        && std::fs::symlink_metadata(format!(
            "{}/.well-known/acme-challenge",
            acme_webroot(account)
        ))
        .is_ok_and(|meta| meta.is_dir())
}

/// D-059: the HTTP-01 webroot of a site, inside its root so that the
/// restrained vhost may serve it. `rustiron-acme` owns it; certbot writes
/// tokens to `<webroot>/.well-known/acme-challenge/`.
pub fn acme_webroot(account: &str) -> String {
    format!("{SITES}/{account}/acme")
}

/// D-059: the context that serves only the challenge tokens, with no
/// rewrite, so a site's `.htaccess` cannot answer for it.
fn acme_context(account: &str) -> String {
    format!(
        "context /.well-known/acme-challenge/ {{\n location {}/.well-known/acme-challenge/\n allowBrowse 1\n rewrite {{\n  enable 0\n }}\n}}\n",
        acme_webroot(account)
    )
}

/// D-060: the per-site link to the served certificate folder. Generations
/// name it, so a renewal swaps one link instead of a generation.
pub fn tls_live(account: &str) -> String {
    format!("{}/{account}/live", crate::layout::OLS_TLS_DIR)
}

/// D-059: the vhost SSL block of a site with a certificate. It sets no
/// ciphers or protocols, so the parent's D-039 defaults apply. D-060: it
/// names the site's `live` link; activation checks the link's target.
fn vhssl(account: &str) -> String {
    let folder = tls_live(account);
    format!(
        "vhssl {{\n keyFile {folder}/key.pem\n certFile {folder}/fullchain.pem\n certChain 1\n}}\n"
    )
}

/// Where ejected sites' vhost files live, outside the Rustiron include, so
/// removing Rustiron's include never removes an ejected site's configuration.
pub const EJECTED_DIR: &str = crate::layout::OLS_EJECTED_DIR;

/// Rendered generation: file name → bytes, in name order.
pub type Generation = BTreeMap<String, Vec<u8>>;

/// Renders the complete listener include for adopted plus provisioned sites.
pub fn render(
    listener: &str,
    address: &str,
    adopted: &[AdoptedSite],
    sites: &[ServedSite],
) -> Generation {
    render_with_tls(listener, address, None, adopted, sites)
}

/// D-059: [`render`] with an enrolled TLS listener address. When it is set
/// and a managed site has a certificate, a second listener `<listener>TLS`
/// (`secure 1`) maps exactly those sites; SNI picks each vhost's `vhssl`.
/// The listener's own key and certificate are those of the first such site
/// in account order, for clients without SNI, through its `live` link. It sets no `ciphers` and no
/// `enableQuic`, so the D-039 parent defaults apply. With an enrolled TLS
/// address every managed vhost with a webroot also serves it. Without an
/// enrolled TLS address the output is byte-identical to [`render`].
pub fn render_with_tls(
    listener: &str,
    address: &str,
    tls_address: Option<&str>,
    adopted: &[AdoptedSite],
    sites: &[ServedSite],
) -> Generation {
    let mut vhosts = String::new();
    let mut maps = Vec::new();
    for site in adopted {
        vhosts.push_str(&format!(
            "virtualHost {name} {{\n vhRoot {SITES}/{name}/\n configFile $SERVER_ROOT/conf/vhosts/{name}/vhconf.conf\n allowSymbolLink 0\n enableScript 1\n restrained 1\n setUIDMode 0\n}}\n",
            name = site.name
        ));
        maps.push((site.name.clone(), site.hostname.as_str().to_owned()));
    }
    let mut files = Generation::new();
    for site in sites {
        let account = &site.account;
        let config = if site.ejected {
            format!("{EJECTED_DIR}/{account}/vhost.conf")
        } else {
            format!("{INCLUDE_DIR}/current/{account}.vhost")
        };
        // W574: a proxy site runs no script.
        // D-077 / D-097: an ejected static site runs no script.
        let scripts = u8::from(
            !(site.ejected && (site.alias_hostname.is_some() || site.static_ejected))
                && site.proxy.is_none(),
        );
        vhosts.push_str(&format!(
            "virtualHost {account} {{\n vhRoot {SITES}/{account}/\n configFile {config}\n allowSymbolLink 0\n enableScript {scripts}\n restrained 1\n setUIDMode 0\n}}\n"
        ));
        let http_names = match &site.alias_hostname {
            Some(alias) => format!("{},{}", site.hostname.as_str(), alias.as_str()),
            None => site.hostname.as_str().to_owned(),
        };
        maps.push((account.clone(), http_names));
        if !site.ejected {
            let mut text = match &site.proxy {
                Some(routes) => proxy_vhost(account, site.hostname.as_str(), routes),
                None => vhost(account, site.hostname.as_str(), site.lscache),
            };
            if tls_address.is_some() && site.acme {
                text.push_str(&acme_context(account));
            }
            if site.tls.is_some() {
                text.push_str(&vhssl(account));
            }
            files.insert(format!("{account}.vhost"), text.into_bytes());
        }
    }
    vhosts.push_str(&format!(
        "listener {listener} {{\n address {address}\n secure 0\n"
    ));
    for (name, hostname) in maps {
        vhosts.push_str(&format!(" map {name} {hostname}\n"));
    }
    vhosts.push_str("}\n");
    // D-064: an ejected site keeps HTTPS; its vhssl is in its own vhost.
    let secure: Vec<_> = sites
        .iter()
        .filter_map(|site| site.tls.as_ref().map(|certificate| (site, certificate)))
        .collect();
    if let (Some(tls_address), Some((first, _))) = (tls_address, secure.first()) {
        let folder = tls_live(&first.account);
        vhosts.push_str(&format!(
            "listener {listener}TLS {{\n address {tls_address}\n secure 1\n keyFile {folder}/key.pem\n certFile {folder}/fullchain.pem\n certChain 1\n"
        ));
        for (site, _) in &secure {
            let names = match &site.tls_alias {
                Some(alias) => format!("{},{}", site.hostname.as_str(), alias.as_str()),
                None => site.hostname.as_str().to_owned(),
            };
            vhosts.push_str(&format!(" map {} {}\n", site.account, names));
        }
        vhosts.push_str("}\n");
    }
    files.insert("vhosts.conf".to_owned(), vhosts.into_bytes());
    files
}

/// Checks the exact mapping in a generation rendered by this module.
pub(crate) fn maps_alias_pair(
    generation: &Generation,
    account: &str,
    primary: &Hostname,
    alias: &Hostname,
    secure: bool,
) -> bool {
    let Some(config) = generation
        .get("vhosts.conf")
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
    else {
        return false;
    };
    let listener_mode = if secure { "secure 1" } else { "secure 0" };
    let mapping = format!("map {account} {},{}", primary.as_str(), alias.as_str());
    for block in config.split("\n}\n") {
        let mut lines = block.lines().map(str::trim);
        if lines
            .next()
            .is_some_and(|line| line.starts_with("listener "))
            && lines.any(|line| line == listener_mode)
            && lines.any(|line| line == mapping)
        {
            return true;
        }
    }
    false
}

/// D-097: checks that `vhosts.conf` maps `account` to `hostname` alone on
/// HTTP (`secure 0`), maps `account` to `hostname` alone on TLS (`secure 1`)
/// when `tls` is true or omits it on TLS when `tls` is false, and maps no
/// other account to `hostname` on either checked listener scope.
pub(crate) fn single_static_maps_ok(
    generation: &Generation,
    account: &str,
    hostname: &Hostname,
    tls: bool,
) -> bool {
    let Some(config) = generation
        .get("vhosts.conf")
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
    else {
        return false;
    };
    let mut http_maps = Vec::new();
    let mut tls_maps = Vec::new();
    let mut depth = 0_usize;
    let mut in_listener = false;
    let mut secure: Option<bool> = None;
    let mut current_maps: Vec<(String, String)> = Vec::new();
    for raw in config.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if depth == 0 && line.ends_with('{') {
            in_listener = line.starts_with("listener ");
            secure = None;
            current_maps.clear();
            depth = 1;
            continue;
        }
        if line.ends_with('{') {
            depth += 1;
            continue;
        }
        if line == "}" {
            if depth == 0 {
                return false;
            }
            depth -= 1;
            if depth == 0 && in_listener {
                let Some(is_secure) = secure else {
                    return false;
                };
                for (mapped_account, names) in current_maps.drain(..) {
                    if mapped_account == account {
                        if is_secure {
                            tls_maps.push(names);
                        } else {
                            http_maps.push(names);
                        }
                    } else if names.split(',').any(|name| name == hostname.as_str()) {
                        return false;
                    }
                }
                in_listener = false;
            }
            continue;
        }
        if in_listener && depth == 1 {
            let mut words = line.split_whitespace();
            match words.next() {
                Some("secure") => {
                    let parsed = match (words.next(), words.next()) {
                        (Some("0"), None) => Some(false),
                        (Some("1"), None) => Some(true),
                        _ => None,
                    };
                    if secure.is_some() || parsed.is_none() {
                        return false;
                    }
                    secure = parsed;
                }
                Some("map") => {
                    let (Some(mapped_account), Some(names), None) =
                        (words.next(), words.next(), words.next())
                    else {
                        return false;
                    };
                    current_maps.push((mapped_account.to_owned(), names.to_owned()));
                }
                _ => {}
            }
        }
    }
    if depth != 0 {
        return false;
    }
    let http_ok = http_maps.as_slice() == [hostname.as_str()];
    let tls_ok = if tls {
        tls_maps.as_slice() == [hostname.as_str()]
    } else {
        tls_maps.is_empty()
    };
    http_ok && tls_ok
}

/// D-097: checks the `virtualHost <account>` block and managed vhost file in
/// `generation` for either the managed predecessor (`ejected == false`) or
/// the standalone ejected target (`ejected == true`).
pub(crate) fn single_static_vhost_ok(
    generation: &Generation,
    account: &str,
    tls: bool,
    ejected: bool,
) -> bool {
    let Some(config) = generation
        .get("vhosts.conf")
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
    else {
        return false;
    };
    let wanted_head = format!("virtualHost {account} {{");
    let expected_config = if ejected {
        format!("{EJECTED_DIR}/{account}/vhost.conf")
    } else {
        format!("{INCLUDE_DIR}/current/{account}.vhost")
    };
    let mut matches = 0_usize;
    let mut depth = 0_usize;
    let mut in_target = false;
    let mut config_files = Vec::new();
    let mut enable_scripts = Vec::new();
    for raw in config.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if depth == 0 && line.ends_with('{') {
            let normalized = line.split_whitespace().collect::<Vec<_>>().join(" ");
            in_target = normalized == wanted_head;
            if in_target {
                matches += 1;
            }
            depth = 1;
            continue;
        }
        if line.ends_with('{') {
            depth += 1;
            continue;
        }
        if line == "}" {
            if depth == 0 {
                return false;
            }
            depth -= 1;
            if depth == 0 {
                in_target = false;
            }
            continue;
        }
        if in_target && depth == 1 {
            let mut words = line.split_whitespace();
            match (words.next(), words.next(), words.next()) {
                (Some("configFile"), Some(path), None) => config_files.push(path.to_owned()),
                (Some("configFile"), _, _) => return false,
                (Some("enableScript"), Some(value), None) => {
                    enable_scripts.push(value.to_owned());
                }
                (Some("enableScript"), _, _) => return false,
                _ => {}
            }
        }
    }
    if depth != 0 || matches != 1 || config_files.as_slice() != [expected_config.as_str()] {
        return false;
    }
    let vhost_key = format!("{account}.vhost");
    if ejected {
        enable_scripts.as_slice() == ["0"] && !generation.contains_key(&vhost_key)
    } else {
        let Some(vhost) = generation
            .get(&vhost_key)
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
        else {
            return false;
        };
        let has_vhssl = vhost.contains("\nvhssl {\n");
        let has_live = vhost.contains(&format!(" keyFile {}/key.pem\n", tls_live(account)))
            && vhost.contains(&format!(" certFile {}/fullchain.pem\n", tls_live(account)));
        if tls {
            has_vhssl && has_live
        } else {
            !has_vhssl
        }
    }
}

/// The vhost rewrite block every site renders.
const REWRITE: &str = "rewrite {\n enable 1\n autoLoadHtaccess 1\n}\n";
/// W370: the same block for an opted-in site, with one rule. A GET or HEAD
/// that carries a WordPress post-password cookie and no login cookie turns
/// the cache module off for that request. OLS 1.9.4 reads `modcache` at
/// `URI_MAP`, after the vhost rewrite (1.9.3 read it with a one-byte buffer,
/// which is why W201 saw no effect). Login cookies are not matched, so the
/// plugin's purge headers on those responses still reach the module.
const REWRITE_POSTPASS: &str = concat!(
    "rewrite {\n enable 1\n autoLoadHtaccess 1\n rules <<<END_rules\n",
    "RewriteCond %{REQUEST_METHOD} ^(GET|HEAD)$\n",
    "RewriteCond %{HTTP_COOKIE} (^|;\\s*)wp-postpass_[^=;]*=\n",
    "RewriteCond %{HTTP_COOKIE} !(^|;\\s*)wordpress_logged_in_[^=;]*=\n",
    "RewriteRule .* - [E=modcache:0]\n",
    " END_rules\n}\n",
);
/// W370: the cache module off for a vhost that is not opted in. OLS applies
/// a vhost `ls_enabled 0` to every hook of the module for the vhost's
/// sessions, so nothing is looked up, stored or served for it, and the
/// parent's shared default storage is never used.
const CACHE_OFF: &str = "module cache {\n ls_enabled 0\n}\n";

/// The fixed vhost text for one provisioned site. With `lscache` (D-028
/// item 2), a vhost-level `module cache` block gives the site its own cache
/// storage and keeps the module's own switches off: `enableCache 0` and
/// `enablePrivateCache 0`. Only a response that the site's LiteSpeed Cache
/// plugin marks cacheable is stored, and the post-password rule above
/// applies. Without it, the module is off for the vhost (W370). The lookup
/// settings come from the reviewed parent. Nothing at server scope changes.
/// See `docs/technical/PAGE-CACHE.md`.
pub fn vhost(account: &str, hostname: &str, lscache: bool) -> String {
    let mut text = vhost_base(account, hostname);
    if lscache {
        text = text.replacen(REWRITE, REWRITE_POSTPASS, 1);
    }
    text.push_str(&cache_block(account, lscache));
    text.push_str(&probe_context(account));
    text.push_str(PHP_HEALTH_CONTEXT);
    text
}

/// W574 (D-095): the vhost of a proxy site. It serves the identity file
/// from disk and forwards every route to its port on `127.0.0.1` through
/// one `proxy` external app per port, and each WebSocket path through a
/// `websocket` block (a proxy context alone hangs after the 101, W570). It
/// has no PHP, no rewrite (so no `.htaccess`), no maintenance page (a
/// stopped service answers 503 from OLS, not "paused for a backup"), and
/// the cache module off. OLS picks the longest matching prefix, so the
/// identity and ACME contexts win over `/`. W577-F1: OLS answers a plain
/// request under a `websocket` path 404 unless a context has the same
/// path, so a WebSocket path that is not also a route gets a context to the
/// port of its longest matching route. The address is fixed here; the
/// journal holds only prefixes and ports. See
/// `docs/technical/PROXY-SITE.md`.
pub fn proxy_vhost(account: &str, hostname: &str, routes: &rustiron_journal::ProxyFacts) -> String {
    let mut text = format!("docRoot {SITES}/{account}/html/\nvhDomain {hostname}\n");
    for port in routes.ports() {
        text.push_str(&format!(
            "extprocessor proxy_{port} {{\n type proxy\n address 127.0.0.1:{port}\n maxConns 100\n initTimeout 60\n retryTimeout 0\n respBuffer 0\n}}\n"
        ));
    }
    text.push_str(CACHE_OFF);
    text.push_str(&probe_context(account));
    for route in &routes.routes {
        text.push_str(&format!(
            "context {} {{\n type proxy\n handler proxy_{}\n addDefaultCharset off\n}}\n",
            route.prefix, route.port
        ));
    }
    for path in &routes.websockets {
        let routed = routes
            .routes
            .iter()
            .any(|route| route.prefix == path.prefix);
        let owner = routes
            .routes
            .iter()
            .filter(|route| path.prefix.starts_with(&route.prefix))
            .max_by_key(|route| route.prefix.len());
        if let (false, Some(owner)) = (routed, owner) {
            text.push_str(&format!(
                "context {} {{\n type proxy\n handler proxy_{}\n addDefaultCharset off\n}}\n",
                path.prefix, owner.port
            ));
        }
    }
    for path in &routes.websockets {
        text.push_str(&format!(
            "websocket {} {{\n address 127.0.0.1:{}\n}}\n",
            path.prefix, path.port
        ));
    }
    text
}

/// D-073 (W487): the URI of the PHP health check of a managed site.
pub const PHP_HEALTH_URI: &str = "/rustiron-php-health.php";
/// D-073: the one root-owned file that every managed vhost serves there.
pub const PHP_HEALTH_FILE: &str = "/usr/share/rustiron/ols/php-health.php";
/// D-073: the site's own PHP runs the shared health file, with rewriting off
/// (as D-068), and answers with its account. An ejected vhost has no such
/// context: the file belongs to Rustiron.
const PHP_HEALTH_CONTEXT: &str = "context /rustiron-php-health.php {\n location /usr/share/rustiron/ols/php-health.php\n allowBrowse 1\n rewrite {\n  enable 0\n }\n}\n";

/// D-068 (W478): the identity file that every activation probes is served
/// with rewriting off, so a site's own rules (for example a forced HTTPS
/// redirect in its `.htaccess`) cannot fail the probe. The ACME context
/// relies on the same rule.
fn probe_context(account: &str) -> String {
    format!(
        "context /rustiron-site.txt {{\n location {SITES}/{account}/html/rustiron-site.txt\n allowBrowse 1\n rewrite {{\n  enable 0\n }}\n}}\n"
    )
}

/// The vhost-level cache module block of [`vhost`] and [`ejected_vhost`].
fn cache_block(account: &str, lscache: bool) -> String {
    if lscache {
        format!(
            "module cache {{\n ls_enabled 1\n enableCache 0\n enablePrivateCache 0\n storagePath {}\n}}\n",
            cache_storage(account)
        )
    } else {
        CACHE_OFF.to_owned()
    }
}

/// W387 (D-037): where OpenLiteSpeed keeps the socket of a PHP that it
/// starts itself. The folder belongs to the OLS package, not to Rustiron.
pub const EJECTED_PHP_SOCKET_DIR: &str = "/tmp/lshttpd";
/// PHP children of an ejected site: the value of the site PHP unit template.
pub const PHP_CHILDREN: u32 = 4;
/// Requests per PHP child of an ejected site: the unit template value.
pub const PHP_MAX_REQUESTS: u32 = 500;
/// The PHP binary of the OLS package that every site uses.
pub const LSPHP: &str = "/usr/local/lsws/lsphp84/bin/lsphp";

/// W387 (D-037): the standalone vhost of an ejected site. OpenLiteSpeed
/// starts the site's PHP itself (`autoStart 1`) through its own suEXEC
/// daemon, as the site account (`extUser`, `extGroup`), on a socket in the
/// OLS runtime folder. The text names no Rustiron path, unit, or page, so
/// the site keeps serving after Rustiron is uninstalled.
///
/// The site settings stay those of [`vhost`]: document root, domain, index,
/// PHP capacity and `php.ini` overrides, rewrite, and cache module. The
/// Rustiron maintenance page goes: no capture freezes an ejected site.
/// The isolation changes: OLS processes run in `unconfined_service_t`, so
/// the PHP has the site account's file access and none of the PHP unit's
/// sandbox, network refusal, or cgroup limits. OLS sets only rlimits.
///
/// D-064: a site with a certificate keeps its `vhssl` block, which names the
/// installed chain; Rustiron no longer renews it.
pub fn ejected_vhost(account: &str, hostname: &str, lscache: bool, tls: bool) -> String {
    let rewrite = if lscache { REWRITE_POSTPASS } else { REWRITE };
    let mut text = format!(
        "docRoot {SITES}/{account}/html/\nvhDomain {hostname}\nenableGzip 1\nindex {{\n useServer 0\n indexFiles index.php,index.html\n}}\n\
extprocessor lsphp_{account} {{\n type lsapi\n address uds:/{EJECTED_PHP_SOCKET_DIR}/{account}.sock\n maxConns {LSAPI_MAX_CONNS}\n env PHP_LSAPI_CHILDREN={PHP_CHILDREN}\n env PHP_LSAPI_MAX_REQUESTS={PHP_MAX_REQUESTS}\n env TMPDIR={SITES}/{account}/tmp\n initTimeout 30\n retryTimeout 0\n respBuffer 0\n autoStart 1\n path {LSPHP}\n extUser {account}\n extGroup {account}\n instances 1\n memSoftLimit 2047M\n memHardLimit 2047M\n procSoftLimit 400\n procHardLimit 500\n}}\n\
scripthandler {{\n add lsapi:lsphp_{account} php\n}}\n\
phpIniOverride {{\n php_admin_value session.save_path {SITES}/{account}/tmp\n php_admin_value upload_tmp_dir {SITES}/{account}/tmp\n php_admin_value sys_temp_dir {SITES}/{account}/tmp\n php_admin_value memory_limit 256M\n}}\n\
{rewrite}{cache}",
        cache = cache_block(account, lscache),
    );
    if tls {
        text.push_str(&vhssl(account));
    }
    text
}

/// Standalone vhost for a certified static alias. The parent disables scripts.
pub(crate) fn ejected_static_vhost(account: &str, hostname: &str) -> String {
    format!(
        "# Standalone static vhost\ndocRoot {SITES}/{account}/html/\nvhDomain {hostname}\nenableGzip 1\nindex {{\n useServer 0\n indexFiles index.html\n}}\n\
rewrite {{\n enable 1\n autoLoadHtaccess 1\n rules <<<END_rules\nRewriteRule \\.(php[0-9]*|phtml|phar)(/|$) - [F,NC,L]\n END_rules\n}}\n{ssl}",
        ssl = vhssl(account),
    )
}

/// D-097: standalone vhost for a single-name static import. The parent
/// disables scripts; `tls` appends the site's installed `vhssl` block only
/// when the site is served over HTTPS.
pub fn ejected_single_static_vhost(account: &str, hostname: &str, tls: bool) -> String {
    let mut text = format!(
        "# Standalone single-name static vhost\ndocRoot {SITES}/{account}/html/\nvhDomain {hostname}\nenableGzip 1\nindex {{\n useServer 0\n indexFiles index.html\n}}\n\
rewrite {{\n enable 1\n autoLoadHtaccess 1\n rules <<<END_rules\nRewriteRule \\.(php[0-9]*|phtml|phar)(/|$) - [F,NC,L]\n END_rules\n}}\n"
    );
    if tls {
        text.push_str(&vhssl(account));
    }
    text
}

/// The one cache storage folder of a site, derived from its account.
pub fn cache_storage(account: &str) -> String {
    format!("{CACHE_ROOT}/{account}")
}

/// The OLS cache folder that holds every site's own storage.
pub const CACHE_ROOT: &str = "/usr/local/lsws/cachedata";

fn vhost_base(account: &str, hostname: &str) -> String {
    format!(
        "docRoot {SITES}/{account}/html/\nvhDomain {hostname}\nenableGzip 1\nindex {{\n useServer 0\n indexFiles index.php,index.html\n}}\n\
extprocessor lsphp_{account} {{\n type lsapi\n address uds:/{SOCKETS}/{account}.sock\n maxConns {LSAPI_MAX_CONNS}\n initTimeout 30\n retryTimeout 0\n respBuffer 0\n autoStart 0\n path /usr/local/lsws/lsphp84/bin/lsphp\n instances 1\n}}\n\
scripthandler {{\n add lsapi:lsphp_{account} php\n}}\n\
phpIniOverride {{\n php_admin_value session.save_path {SITES}/{account}/tmp\n php_admin_value upload_tmp_dir {SITES}/{account}/tmp\n php_admin_value sys_temp_dir {SITES}/{account}/tmp\n php_admin_value memory_limit 256M\n}}\n\
rewrite {{\n enable 1\n autoLoadHtaccess 1\n}}\n\
errorpage 503 {{\n url /.rustiron-errors/503.html\n}}\n\
context /.rustiron-errors/ {{\n location {SITES}/{account}/errors/\n allowBrowse 1\n extraHeaders <<<END_extraHeaders\nRetry-After {RETRY_AFTER_SECS}\nCache-Control no-store\n END_extraHeaders\n rewrite {{\n  enable 0\n }}\n}}\n"
    )
}

/// B09-503: seconds a client is told to wait during a capture freeze; the
/// unfreeze timer restores the pool by then at the latest.
pub const RETRY_AFTER_SECS: u64 = 10;

/// The static, root-owned page served for 503 (capture freeze or PHP down).
/// Lives in `<SITES_ROOT>/<account>/errors/`, outside the site web folder.
pub const MAINTENANCE_PAGE: &str = "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>Back in a moment</title></head>\n<body><h1>Back in a moment</h1><p>This site is briefly paused for a backup. Please retry in a few seconds.</p></body></html>\n";

/// Connections each OLS worker process may hold to one site's PHP (W212).
/// OLS keeps one pool per worker process, so a site needs at least
/// `workers × LSAPI_MAX_CONNS` PHP children or idle pooled connections pin
/// them and new requests wait in the socket backlog (W209).
pub const LSAPI_MAX_CONNS: u32 = 1;
/// The installed per-site PHP unit template (systemd starts PHP, not OLS).
pub const PHP_UNIT: &str = crate::layout::SITE_PHP_UNIT;

/// OLS worker processes: the parent's single `httpdWorkers N` (clamped to
/// 1..=16, as OLS does), else one per online CPU capped at 8. `None` when
/// unknown or ambiguous.
pub fn ols_workers(parent: &[u8], online_cpus: Option<u32>) -> Option<u32> {
    let text = std::str::from_utf8(parent).ok()?;
    let mut set = text
        .lines()
        .map(str::split_whitespace)
        .filter_map(|mut words| {
            (words.next() == Some("httpdWorkers")).then(|| words.collect::<Vec<_>>())
        });
    match (set.next(), set.next()) {
        (None, _) => online_cpus.filter(|&cpus| cpus > 0).map(|cpus| cpus.min(8)),
        (Some(value), None) => match value.as_slice() {
            [n] => n.parse::<u32>().ok().map(|n| n.clamp(1, 16)),
            _ => None,
        },
        _ => None,
    }
}

/// The single `PHP_LSAPI_CHILDREN=N` (N > 0) on an `Environment=` line.
pub fn unit_children(unit: &str) -> Option<u32> {
    let mut values = unit
        .lines()
        .filter_map(|line| line.trim().strip_prefix("Environment="))
        .flat_map(str::split_whitespace)
        .filter_map(|word| word.strip_prefix("PHP_LSAPI_CHILDREN="));
    match (values.next(), values.next()) {
        (Some(value), None) => value.parse::<u32>().ok().filter(|&n| n > 0),
        _ => None,
    }
}

/// Whether every OLS worker's pool can hold a PHP child: children ≥
/// workers × [`LSAPI_MAX_CONNS`]. Unknown input or a per-site/runtime
/// override of the PHP environment fails closed.
pub fn php_capacity(
    parent: Option<&[u8]>,
    online_cpus: Option<u32>,
    unit: Option<&str>,
    overridden: bool,
) -> bool {
    let workers = parent.and_then(|bytes| ols_workers(bytes, online_cpus));
    let children = unit.and_then(unit_children);
    match (workers, children) {
        (Some(workers), Some(children)) => {
            !overridden && u64::from(children) >= u64::from(workers) * u64::from(LSAPI_MAX_CONNS)
        }
        _ => false,
    }
}

/// CPUs this process may run on (`sched_getaffinity`), standing in for the
/// online CPUs OLS counts. A syscall, not a sysfs read: the admin helper's
/// domain may not read `sysfs_t` files (W212 live finding). The helper unit
/// sets no CPU affinity, so this is every online CPU.
pub fn online_cpus() -> Option<u32> {
    rustix::thread::sched_getaffinity(None)
        .ok()
        .map(|set| set.count())
        .filter(|&count| count > 0)
}

/// Lab and product roots systemd reads PHP unit drop-ins from
/// (persistent, runtime and `set-property`).
pub const PHP_DROPIN_ROOTS: [&str; 3] = [
    "/etc/systemd/system",
    "/run/systemd/system",
    "/run/systemd/system.control",
];

/// Whether any `rustiron-site-php@*.service.d` drop-in under `roots` can
/// change the PHP worker count ([`dropin_overrides_php`]). An unreadable
/// drop-in file or directory fails closed (counts as an override).
pub fn php_unit_overridden_in(roots: &[&Path]) -> bool {
    roots.iter().any(|root| {
        let Ok(dirs) = std::fs::read_dir(root) else {
            return false;
        };
        dirs.flatten().any(|dir| {
            let name = dir.file_name().to_string_lossy().into_owned();
            name.starts_with("rustiron-site-php@")
                && name.ends_with(".service.d")
                && std::fs::read_dir(dir.path()).map_or(true, |files| {
                    files.flatten().any(|file| {
                        std::fs::read_to_string(file.path())
                            .map_or(true, |text| dropin_overrides_php(&text))
                    })
                })
        })
    })
}

/// [`php_capacity`] from files: the parent config, the unit template and the
/// drop-in roots. Used by the helper's `ols_preflight` with the live paths.
pub fn php_capacity_at(parent: &Path, unit: &Path, roots: &[&Path], cpus: Option<u32>) -> bool {
    let parent = std::fs::read(parent).ok();
    let unit = std::fs::read_to_string(unit).ok();
    php_capacity(
        parent.as_deref(),
        cpus,
        unit.as_deref(),
        php_unit_overridden_in(roots),
    )
}

/// The executor's reading of the helper's `ols_preflight` reply: only a
/// `Done` payload that decodes to exactly [`ServerChecks`] yields a report;
/// anything else (no helper, refusal, empty or forged payload) is `None`,
/// which the caller treats as drift.
pub fn preflight_report(
    reply: Result<crate::admin_helper::Reply, ExecutorError>,
    generation: (bool, Option<bool>),
) -> Option<DriftReport> {
    match reply {
        Ok(crate::admin_helper::Reply::Done(Some(payload))) => {
            ServerChecks::decode(&payload).map(|checks| checks.report(generation))
        }
        _ => None,
    }
}

/// Whether a PHP unit drop-in can change the PHP worker count.
/// Any `PHP_LSAPI` mention, an environment file, unset/pass-through
/// environment, or a replaced `ExecStart` counts; an `Environment=` line that
/// sets only other variables (the provision's site level) does not.
pub fn dropin_overrides_php(text: &str) -> bool {
    text.contains("PHP_LSAPI")
        || text.lines().map(str::trim).any(|line| {
            [
                "EnvironmentFile",
                "UnsetEnvironment",
                "PassEnvironment",
                "ExecStart",
            ]
            .iter()
            .any(|key| line.starts_with(key))
        })
}

/// The live capacity check, read by the admin helper.
pub fn php_capacity_live() -> bool {
    let unit = std::fs::read_to_string(PHP_UNIT).ok();
    let roots = PHP_DROPIN_ROOTS.map(Path::new);
    php_capacity(
        read_parent().ok().as_deref(),
        online_cpus(),
        unit.as_deref(),
        php_unit_overridden_in(&roots),
    )
}

/// Digest over names and bytes of the rendered files only.
pub fn digest(generation: &Generation) -> Sha256Digest {
    let mut hash = Sha256::new();
    for (name, bytes) in generation {
        hash.update(name.as_bytes());
        hash.update([0]);
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    Sha256Digest::from_bytes(hash.finalize().into())
}

/// Content-addressed generation id: `r` + 16 hex of the digest.
pub fn generation_id(digest: &Sha256Digest) -> Id {
    Id::try_from(format!("r{}", &digest.as_str()[..16])).unwrap_or_else(|_| unreachable!())
}

/// Reads `current` and the generation it names (root-owned, single-link files).
pub fn observe(include: &OwnedFd) -> Result<(Id, Sha256Digest), ExecutorError> {
    let unavailable = ExecutorError::RegistryUnavailable;
    let target = fs::readlinkat(include, "current", Vec::new()).map_err(|_| unavailable)?;
    let name = target
        .to_str()
        .ok()
        .and_then(|text| text.strip_prefix("generations/"))
        .ok_or(unavailable)?;
    let id = Id::try_from(name.to_owned()).map_err(|_| unavailable)?;
    let digest = generation_digest(include, &id)?;
    Ok((id, digest))
}

/// Digest of one stored generation, ignoring the copies OLS writes itself.
pub fn generation_digest(include: &OwnedFd, id: &Id) -> Result<Sha256Digest, ExecutorError> {
    stored_generation(include, id).map(|generation| digest(&generation))
}

/// W372: the files of one stored generation, without the copies OLS writes
/// itself, for a byte-for-byte comparison with a render.
pub fn stored_generation(include: &OwnedFd, id: &Id) -> Result<Generation, ExecutorError> {
    let generations = files::open_child_directory(include, "generations", 0)?;
    let directory = files::open_child_directory(&generations, id.as_str(), 0)?;
    read_generation(&directory, 0)
}

/// The files of one generation folder owned by `owner`, without the copies
/// OLS writes itself. W384: also reads a temporary staging folder back.
pub(crate) fn read_generation(
    directory: &OwnedFd,
    owner: u32,
) -> Result<Generation, ExecutorError> {
    let unavailable = ExecutorError::RegistryUnavailable;
    let mut generation = Generation::new();
    let mut entries: Vec<String> = Vec::new();
    for entry in fs::Dir::read_from(directory).map_err(|_| unavailable)? {
        let entry = entry.map_err(|_| unavailable)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name != "." && name != ".." {
            entries.push(name);
        }
    }
    for name in &entries {
        if is_ols_copy(name, &entries) {
            continue;
        }
        let bytes = files::read_child(directory, name, owner, files::Exposure::Readable, MAX_FILE)
            .map_err(|_| unavailable)?;
        generation.insert(name.clone(), bytes);
    }
    Ok(generation)
}

/// W372: the history with a generation adoption applied. An adoption is
/// recorded only while the OLS history is empty, so an empty history then
/// establishes the adopted generation; anything an operation established
/// after it, or an unresolved operation, stands.
pub fn with_adoption(
    history: rustiron_journal::ResourceHistory,
    adoption: Option<(Id, Sha256Digest)>,
) -> rustiron_journal::ResourceHistory {
    match (history, adoption) {
        (rustiron_journal::ResourceHistory::Empty, Some((id, digest))) => {
            rustiron_journal::ResourceHistory::Established(id, digest)
        }
        (history, _) => history,
    }
}

/// Accounts whose vhost the stored generation `id` manages (`<account>.vhost`).
/// A generation that does not exist is a changed precondition (W188), not
/// an access failure; anything else unusable stays refused as before.
pub fn managed_accounts(include: &OwnedFd, id: &Id) -> Result<Vec<String>, ExecutorError> {
    let generations = files::open_child_directory(include, "generations", 0)?;
    if let Err(rustix::io::Errno::NOENT) =
        fs::statat(&generations, id.as_str(), AtFlags::SYMLINK_NOFOLLOW)
    {
        return Err(ExecutorError::PreconditionChanged);
    }
    let directory = files::open_child_directory(&generations, id.as_str(), 0)?;
    let mut accounts = Vec::new();
    for entry in fs::Dir::read_from(&directory).map_err(|_| ExecutorError::RegistryUnavailable)? {
        let entry = entry.map_err(|_| ExecutorError::RegistryUnavailable)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(account) = name.strip_suffix(".vhost") {
            accounts.push(account.to_owned());
        }
    }
    accounts.sort();
    Ok(accounts)
}

/// SHA-256 of an ejected site's vhost copy, if readable and root-owned.
pub fn ejected_digest(account: &str) -> Option<Sha256Digest> {
    let base = files::open_traversable_directory(Path::new(EJECTED_DIR), 0).ok()?;
    let directory = files::open_child_directory(&base, account, 0).ok()?;
    files::read_child(
        &directory,
        "vhost.conf",
        0,
        files::Exposure::Readable,
        MAX_FILE,
    )
    .ok()
    .map(|bytes| Sha256Digest::from_bytes(Sha256::digest(&bytes).into()))
}

/// SHA-256 of `<account>.vhost` in the current generation.
///
/// `Ok(None)` means that name is absent. A present file that is a symlink,
/// an extra hard link, or otherwise unreadable is an error, not absence.
pub fn vhost_digest(
    include: &OwnedFd,
    account: &str,
) -> Result<Option<Sha256Digest>, ExecutorError> {
    let (id, _) = observe(include)?;
    let generations = files::open_child_directory(include, "generations", 0)?;
    let directory = files::open_child_directory(&generations, id.as_str(), 0)?;
    let name = format!("{account}.vhost");
    let mut present = false;
    for entry in fs::Dir::read_from(&directory).map_err(|_| ExecutorError::RegistryUnavailable)? {
        let entry = entry.map_err(|_| ExecutorError::RegistryUnavailable)?;
        if entry.file_name().to_string_lossy() == name {
            present = true;
            break;
        }
    }
    if !present {
        return Ok(None);
    }
    let bytes = files::read_child(&directory, &name, 0, files::Exposure::Readable, MAX_FILE)
        .map_err(|_| ExecutorError::RegistryUnavailable)?;
    Ok(Some(Sha256Digest::from_bytes(
        Sha256::digest(&bytes).into(),
    )))
}

/// OLS writes `<name>0` and `<name>.txt` copies of every config file it loads
/// (observed on the lab VM); they are not part of the rendered generation.
fn is_ols_copy(name: &str, entries: &[String]) -> bool {
    let original = name.strip_suffix(".txt").or_else(|| name.strip_suffix('0'));
    original.is_some_and(|original| entries.iter().any(|entry| entry == original))
}

/// The OLS parent configuration. Left to OLS it is re-owned to `lsadm` on
/// every reload, so the lab parent is root-owned and immutable, and only its
/// exact reviewed bytes are accepted.
pub const PARENT: &str = "/usr/local/lsws/conf/httpd_config.conf";
const INCLUDE_LINE: &str = crate::layout::OLS_INCLUDE_LINE;

/// What an OLS drift observation found; every field must hold to proceed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DriftReport {
    /// A content-addressed `current` whose bytes still hash to its id.
    pub content_addressed: bool,
    /// `current` equals the generation the journal last established
    /// (`None`: the journal has established none yet).
    pub explained: Option<bool>,
    /// The parent is byte-identical to the enrolled review, holds one
    /// `disableWebAdmin 1` and exactly one Rustiron include.
    pub parent_reviewed: bool,
    /// No socket listens on the WebAdmin port (IPv4 or IPv6).
    pub webadmin_closed: bool,
    /// Each adopted `vhconf.conf` is a root-owned, single-link, immutable file
    /// that group and other cannot write.
    pub adopted_vhosts_pinned: bool,
    /// Each site's PHP children cover every OLS worker's LSAPI pool (W212).
    pub php_capacity: bool,
    /// W427 (D-052): the installed OLS is a version on which the cache-on
    /// recipe's post-password bypass was proved. Not part of [`Self::clean`]:
    /// only an activation that serves a cached site requires it.
    pub page_cache_ols_tested: bool,
}

impl DriftReport {
    /// Whether nothing unexplained was observed.
    pub fn clean(&self) -> bool {
        self.content_addressed
            && self.explained != Some(false)
            && self.parent_reviewed
            && self.webadmin_closed
            && self.adopted_vhosts_pinned
            && self.php_capacity
    }
}

/// Observes drift without changing anything. `generation` is the result of
/// [`current_checks`] on `current`.
pub fn observe_drift(
    generation: (bool, Option<bool>),
    parent_sha256: &Sha256Digest,
    webadmin_port: u16,
    adopted: &[&str],
) -> DriftReport {
    let (content_addressed, explained) = generation;
    DriftReport {
        content_addressed,
        explained,
        parent_reviewed: parent_reviewed(parent_sha256),
        webadmin_closed: webadmin_closed(webadmin_port),
        adopted_vhosts_pinned: adopted_vhosts_pinned(adopted),
        php_capacity: php_capacity_live(),
        page_cache_ols_tested: page_cache_ols_tested(read_ols_version().as_deref()),
    }
}

/// The two drift checks on `current` itself, which the executor makes in its
/// own domain: content addressing and agreement with the journal.
pub fn generation_checks(
    current: &(Id, Sha256Digest),
    journal_expected: Option<&(Id, Sha256Digest)>,
) -> (bool, Option<bool>) {
    let (id, digest) = current;
    // Ids that are not content-addressed (the adopted bootstrap generation)
    // are accepted only as the generation the journal established.
    let content_addressed = if id.as_str().starts_with('r') {
        &generation_id(digest) == id
    } else {
        journal_expected == Some(current)
    };
    (
        content_addressed,
        journal_expected.map(|expected| expected == current),
    )
}

/// W362: the generation checks on `current` as observed. `None` is an
/// absent `current`, which is the bootstrap generation (W355). That
/// generation stands for "no `current`", and no stored directory holds it,
/// so a present `current` that names it is never content-addressed (an
/// empty planted directory hashes to it) and never explained.
pub fn current_checks(
    current: Option<&(Id, Sha256Digest)>,
    established: Option<&(Id, Sha256Digest)>,
) -> (bool, Option<bool>) {
    match current {
        None => generation_checks(&bootstrap_generation(), established),
        Some((id, digest)) if is_bootstrap_predecessor(id, digest) => {
            (false, established.map(|_| false))
        }
        Some(live) => generation_checks(live, established),
    }
}

/// W362: the generation checks that refuse a signed restore of
/// `predecessor` (`compensate`), or `None` when they pass. The restore
/// makes `predecessor` the live `current`, or removes `current` for the
/// bootstrap predecessor, so the checks judge that result against the
/// generation the history before the operation established.
pub fn restore_refusal(
    predecessor: &(Id, Sha256Digest),
    established: Option<&(Id, Sha256Digest)>,
) -> Option<(bool, Option<bool>)> {
    let restored =
        (!is_bootstrap_predecessor(&predecessor.0, &predecessor.1)).then_some(predecessor);
    refused(current_checks(restored, established))
}

/// The generation checks as a refusal: `None` when `current` is
/// content-addressed and not contrary to the established generation.
fn refused(checks: (bool, Option<bool>)) -> Option<(bool, Option<bool>)> {
    (!checks.0 || checks.1 == Some(false)).then_some(checks)
}

/// W359: the generation checks that refuse an activation before intent, or
/// `None` when they pass. `established` is the journal as it stands before
/// any new intent. W360: `live` is the `current` that
/// [`activation_mode`] matched to the plan predecessor, never a second
/// read, so the predecessor the intent records is the one checked here.
/// A refusal after intent records the operation `untouched`, which no
/// longer establishes anything, but refusing before intent records nothing.
/// W362: `live` is a present `current`, judged by [`current_checks`];
/// `reconcile_ols` uses the same checks before it reloads.
pub fn generation_refusal(
    live: &(Id, Sha256Digest),
    established: Option<&(Id, Sha256Digest)>,
) -> Option<(bool, Option<bool>)> {
    refused(current_checks(Some(live), established))
}

/// The drift checks that read the OLS server root and `/proc/net`, made by
/// the admin helper in `rustiron_admin_t` (W200); the executor's domain
/// cannot read either.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerChecks {
    /// See [`DriftReport::parent_reviewed`].
    pub parent_reviewed: bool,
    /// See [`DriftReport::webadmin_closed`].
    pub webadmin_closed: bool,
    /// See [`DriftReport::adopted_vhosts_pinned`].
    pub adopted_vhosts_pinned: bool,
    /// See [`DriftReport::php_capacity`].
    pub php_capacity: bool,
    /// See [`DriftReport::page_cache_ols_tested`].
    pub page_cache_ols_tested: bool,
}

impl ServerChecks {
    /// Observes the live server root and listener table.
    /// `ports` is (webadmin, listener).
    pub fn observe(parent_sha256: &Sha256Digest, ports: (u16, u16), adopted: &[&str]) -> Self {
        let checks = Self::from_reads(
            read_parent().ok().as_deref(),
            parent_sha256,
            [
                std::fs::read_to_string("/proc/net/tcp").ok(),
                std::fs::read_to_string("/proc/net/tcp6").ok(),
            ],
            ports,
            adopted_vhosts_pinned(adopted),
            php_capacity_live(),
        );
        Self {
            page_cache_ols_tested: page_cache_ols_tested(read_ols_version().as_deref()),
            ..checks
        }
    }

    /// Pure decision from what was read; anything unreadable fails its check.
    /// `ports` is (webadmin, listener). The listener must be seen listening,
    /// so a private network namespace (an empty table) is not "closed".
    pub fn from_reads(
        parent: Option<&[u8]>,
        parent_sha256: &Sha256Digest,
        tables: [Option<String>; 2],
        (webadmin_port, listener_port): (u16, u16),
        adopted_vhosts_pinned: bool,
        php_capacity: bool,
    ) -> Self {
        Self {
            parent_reviewed: parent.is_some_and(|bytes| parent_is_reviewed(bytes, parent_sha256)),
            webadmin_closed: tables.iter().all(|table| {
                table
                    .as_deref()
                    .is_some_and(|text| !listening(text, webadmin_port))
            }) && tables
                .iter()
                .flatten()
                .any(|text| listening(text, listener_port)),
            adopted_vhosts_pinned,
            php_capacity,
            // Set by [`Self::observe`] from the live version file.
            page_cache_ols_tested: false,
        }
    }

    /// The full report, with the executor's own generation checks.
    pub fn report(self, generation: (bool, Option<bool>)) -> DriftReport {
        DriftReport {
            content_addressed: generation.0,
            explained: generation.1,
            parent_reviewed: self.parent_reviewed,
            webadmin_closed: self.webadmin_closed,
            adopted_vhosts_pinned: self.adopted_vhosts_pinned,
            php_capacity: self.php_capacity,
            page_cache_ols_tested: self.page_cache_ols_tested,
        }
    }

    /// One JSON line for the helper reply.
    pub fn encode(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Exactly the four fields, or `None` (treated as drift by the caller).
    pub fn decode(payload: &str) -> Option<Self> {
        if payload.len() > 256 {
            return None;
        }
        serde_json::from_str(payload).ok()
    }
}

/// W427 (D-052): OLS versions on which the cache-on recipe's post-password
/// bypass (`E=modcache:0` in the vhost rewrite) was proved. OLS 1.9.3-1 read
/// `modcache` before the rewrite and served the cached public page to an
/// unlocked visitor (W426-F1). A new version joins only after the W426 case
/// passes on it.
pub const PAGE_CACHE_OLS_VERSIONS: &[&str] = &["1.9.4"];
/// The version file of the OLS package.
const OLS_VERSION_FILE: &str = "/usr/local/lsws/VERSION";

/// Whether the text of the OLS version file names a tested version: exactly
/// one listed version, with at most one trailing newline.
pub fn page_cache_ols_tested(version: Option<&str>) -> bool {
    version
        .map(|text| text.strip_suffix('\n').unwrap_or(text))
        .is_some_and(|text| PAGE_CACHE_OLS_VERSIONS.contains(&text))
}

/// The OLS version file, read without following a link and bounded; `None`
/// when it is missing, unreadable, or too long.
fn read_ols_version() -> Option<String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::NOFOLLOW | OFlags::CLOEXEC).bits() as i32)
        .open(OLS_VERSION_FILE)
        .ok()?;
    let mut text = String::new();
    file.take(33).read_to_string(&mut text).ok()?;
    (text.len() <= 32).then_some(text)
}

/// Served-site entries for one generation, derived by the admin helper from
/// the generation's own vhost files and the journal (W200): each managed
/// `rs_<site>` must be a succeeded provision, and every ejected site is added
/// as ejected. A managed account the journal does not explain is refused.
pub fn served_from(
    managed: &[String],
    provisions: &[(
        rustiron_contracts::approval::SiteId,
        Hostname,
        Option<Hostname>,
    )],
    ejected: &[rustiron_contracts::approval::SiteId],
) -> Result<Vec<ServedSite>, ExecutorError> {
    let names = |site: &str| {
        provisions
            .iter()
            .find(|(id, _, _)| id.as_str() == site)
            .map(|(_, hostname, alias)| (hostname.clone(), alias.clone()))
            .ok_or(ExecutorError::PreconditionChanged)
    };
    let mut sites = Vec::new();
    for account in managed {
        let site = account
            .strip_prefix("rs_")
            .ok_or(ExecutorError::PreconditionChanged)?;
        let (hostname, alias_hostname) = names(site)?;
        sites.push(ServedSite {
            account: account.clone(),
            hostname,
            alias_hostname,
            ejected: false,
            static_ejected: false,
            lscache: false,
            tls_alias: None,
            tls: None,
            acme: false,
            proxy: None,
        });
    }
    for site in ejected {
        let account = site.account_name();
        if sites.iter().any(|served| served.account == account) {
            continue;
        }
        let (hostname, alias_hostname) = names(site.as_str())?;
        sites.push(ServedSite {
            account,
            hostname,
            alias_hostname,
            ejected: true,
            static_ejected: false,
            lscache: false,
            tls_alias: None,
            tls: None,
            acme: false,
            proxy: None,
        });
    }
    Ok(sites)
}

/// Whether one file meets the adopted-vhost pin: root-owned, one link,
/// immutable, and not writable by group or other.
pub fn file_is_pinned(uid: u32, mode: u32, nlink: u64, regular: bool, immutable: bool) -> bool {
    regular && nlink == 1 && uid == 0 && mode & 0o022 == 0 && immutable
}

/// Adopted vhost files under the lab server root. An empty list is pinned.
pub fn adopted_vhosts_pinned(names: &[&str]) -> bool {
    names.iter().all(|name| {
        let path = format!("/usr/local/lsws/conf/vhosts/{name}/vhconf.conf");
        pinned_path(&path)
    })
}

fn pinned_path(path: &str) -> bool {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::NOFOLLOW | OFlags::CLOEXEC).bits() as i32)
        .open(path)
    {
        Ok(file) => file,
        Err(_) => return false,
    };
    let Ok(metadata) = file.metadata() else {
        return false;
    };
    let immutable =
        fs::ioctl_getflags(&file).is_ok_and(|flags| flags.contains(fs::IFlags::IMMUTABLE));
    file_is_pinned(
        metadata.uid(),
        metadata.mode(),
        metadata.nlink(),
        metadata.is_file(),
        immutable,
    )
}

/// The live parent is the enrolled, reviewed one (see [`parent_is_reviewed`]).
pub fn parent_reviewed(parent_sha256: &Sha256Digest) -> bool {
    read_parent().is_ok_and(|bytes| parent_is_reviewed(&bytes, parent_sha256))
}

/// Nothing listens on the WebAdmin port; an unreadable table is not closed.
pub fn webadmin_closed(port: u16) -> bool {
    ["/proc/net/tcp", "/proc/net/tcp6"]
        .iter()
        .all(|table| std::fs::read_to_string(table).is_ok_and(|text| !listening(&text, port)))
}

/// D-028 item 1 (W338, W346): server limits the reviewed parent must hold,
/// as (block, directive, value). OLS 1.9.3 offers them only at server scope
/// (W194), so the Rustiron include cannot set them. OLS counts the
/// per-client limits in each worker process (W343), so these are per-worker
/// values: about 60 and 120 connections per IP with 4 workers.
pub const PARENT_LIMITS: [(&str, &str, &str); 6] = [
    ("tuning", "connTimeout", "60"),
    ("tuning", "maxReqBodySize", "64M"),
    ("perClientConnLimit", "softLimit", "15"),
    ("perClientConnLimit", "hardLimit", "30"),
    ("perClientConnLimit", "gracePeriod", "10"),
    ("perClientConnLimit", "banPeriod", "60"),
];

/// Each [`PARENT_LIMITS`] directive appears exactly once in the whole
/// parent, inside its top-level block, with the required value.
fn parent_limits_hold(lines: &[String]) -> bool {
    let mut seen: Vec<(String, String, String)> = Vec::new();
    let (mut block, mut depth) = (String::new(), 0_usize);
    for line in lines {
        if let Some(head) = line.strip_suffix('{') {
            if depth == 0 {
                block = head.trim().to_owned();
            }
            depth += 1;
            continue;
        }
        if line == "}" {
            depth = depth.saturating_sub(1);
            continue;
        }
        let mut fields = line.split(' ');
        if let (Some(key), Some(value), None) = (fields.next(), fields.next(), fields.next())
            && PARENT_LIMITS.iter().any(|(_, wanted, _)| *wanted == key)
        {
            let scope = if depth == 1 {
                block.clone()
            } else {
                String::new()
            };
            seen.push((scope, key.to_owned(), value.to_owned()));
        } else if PARENT_LIMITS
            .iter()
            .any(|(_, wanted, _)| line.split(' ').next() == Some(*wanted))
        {
            return false;
        }
    }
    seen.len() == PARENT_LIMITS.len()
        && PARENT_LIMITS.iter().all(|(block, key, value)| {
            seen.iter()
                .filter(|(_, seen_key, _)| seen_key == key)
                .eq([&((*block).to_owned(), (*key).to_owned(), (*value).to_owned())])
        })
}

/// Pure parent check: exact digest, the two required lines, and the D-028
/// server limits.
pub fn parent_is_reviewed(bytes: &[u8], parent_sha256: &Sha256Digest) -> bool {
    let text = String::from_utf8_lossy(bytes);
    let lines: Vec<String> = text
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect();
    let count = |wanted: &str| lines.iter().filter(|line| line.as_str() == wanted).count();
    let includes = lines
        .iter()
        .filter(|line| line.starts_with("include "))
        .count();
    Sha256Digest::from_bytes(Sha256::digest(bytes).into()) == *parent_sha256
        && count("disableWebAdmin 1") == 1
        && count(INCLUDE_LINE) == 1
        && includes == 1
        && parent_limits_hold(&lines)
}

/// Whether a `/proc/net/tcp{,6}` table shows a LISTEN (0A) socket on `port`.
pub fn listening(table: &str, port: u16) -> bool {
    let wanted = format!("{port:04X}");
    table.lines().skip(1).any(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        fields.get(3) == Some(&"0A")
            && fields
                .get(1)
                .and_then(|local| local.rsplit_once(':'))
                .is_some_and(|(_, local_port)| local_port == wanted)
    })
}

/// Reads the parent without following links; refuses a hard-linked,
/// non-root, group/other-writable or mutable file.
fn read_parent() -> Result<Vec<u8>, ExecutorError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::NOFOLLOW | OFlags::CLOEXEC).bits() as i32)
        .open(PARENT)
        .map_err(|_| ExecutorError::Drift)?;
    let metadata = file.metadata().map_err(|_| ExecutorError::Drift)?;
    // OLS re-owns `conf/` to lsadm on reload; a root-owned immutable parent
    // keeps its ownership and bytes (observed, W021). Anything else is drift.
    let immutable =
        fs::ioctl_getflags(&file).is_ok_and(|flags| flags.contains(fs::IFlags::IMMUTABLE));
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || !immutable
        || metadata.len() > MAX_FILE as u64
    {
        return Err(ExecutorError::Drift);
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ExecutorError::Drift)?;
    Ok(bytes)
}

/// W238: the post-switch config test runs as a waited transient unit, in the
/// same SELinux domain as lshttpd.service, not in the caller's domain. Its
/// exit status is the test's (`--wait`).
pub const CONFIG_TEST_ARGV: [&str; 7] = [
    "/usr/bin/systemd-run",
    "--wait",
    "--pipe",
    "--quiet",
    "--collect",
    "/usr/local/lsws/bin/openlitespeed",
    "-t",
];

/// Runs [`CONFIG_TEST_ARGV`].
pub fn config_test() -> Result<(), ExecutorError> {
    crate::provision::run(CONFIG_TEST_ARGV[0], &CONFIG_TEST_ARGV[1..])
}

/// Atomically repoints `current` (temporary symlink + `renameat` + fsync).
pub fn switch(include: &OwnedFd, id: &Id) -> Result<(), ExecutorError> {
    let temporary = format!("current.next-{}", stage::random_hex()?);
    let link = format!("generations/{}", id.as_str());
    fs::symlinkat(link.as_str(), include, temporary.as_str())
        .map_err(|_| ExecutorError::StepFailed)?;
    if fs::renameat(include, temporary.as_str(), include, "current").is_err() {
        let _ = fs::unlinkat(include, temporary.as_str(), AtFlags::empty());
        return Err(ExecutorError::StepFailed);
    }
    fs::fsync(include).map_err(|_| ExecutorError::StepFailed)
}

/// Opens the include directory: root-owned, not group/other-writable.
pub fn open_include() -> Result<OwnedFd, ExecutorError> {
    files::open_traversable_directory(Path::new(INCLUDE_DIR), 0)
}

/// One HTTP/1.0 GET to the lab listener with a Host header; returns status
/// code and body. No redirects are followed and nothing else is sent.
pub fn get(address: &str, hostname: &str, path: &str) -> Result<(u16, String), ExecutorError> {
    get_response(address, hostname, path).map(|(status, _, body)| (status, body))
}

/// [`get`] that also returns the status line and headers (W368).
pub fn get_response(
    address: &str,
    hostname: &str,
    path: &str,
) -> Result<(u16, String, String), ExecutorError> {
    let addr: SocketAddr = address.parse().map_err(|_| ExecutorError::Unavailable)?;
    let mut stream =
        TcpStream::connect_timeout(&addr, PROBE_TIMEOUT).map_err(|_| ExecutorError::StepFailed)?;
    stream
        .set_read_timeout(Some(PROBE_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(PROBE_TIMEOUT)))
        .map_err(|_| ExecutorError::StepFailed)?;
    write!(
        stream,
        "GET {path} HTTP/1.0\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
    )
    .map_err(|_| ExecutorError::StepFailed)?;
    let mut response = Vec::new();
    stream
        .take(1 << 20)
        .read_to_end(&mut response)
        .map_err(|_| ExecutorError::StepFailed)?;
    parse_response(&String::from_utf8_lossy(&response))
}

/// W511-F1 (P08): [`get_response`] through a TLS listener, by `openssl
/// s_client` with the hostname as SNI and `Host`. Nothing is verified: the
/// listener and the name select the site's own vhost, and only its answer
/// is read. For a site whose HTTP answer sends the client to HTTPS.
pub fn get_response_tls(
    tls_address: &str,
    hostname: &str,
    path: &str,
) -> Result<(u16, String, String), ExecutorError> {
    let _: SocketAddr = tls_address
        .parse()
        .map_err(|_| ExecutorError::Unavailable)?;
    let request = format!("GET {path} HTTP/1.0\r\nHost: {hostname}\r\nConnection: close\r\n\r\n");
    // `-ign_eof`: the end of the request on stdin does not close the
    // session; the server closes it after the HTTP/1.0 answer.
    let text = crate::provision::spawn(
        "/usr/bin/openssl",
        &[
            "s_client",
            "-connect",
            tls_address,
            "-servername",
            hostname,
            "-quiet",
            "-ign_eof",
        ],
        true,
        Some(request.as_bytes()),
    )
    .map_err(|_| ExecutorError::StepFailed)?;
    parse_response(&text)
}

/// The status code, headers, and body of one HTTP/1.x answer.
fn parse_response(text: &str) -> Result<(u16, String, String), ExecutorError> {
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or(ExecutorError::StepFailed)?;
    let (headers, body) = text
        .split_once("\r\n\r\n")
        .map(|(headers, body)| (headers.to_owned(), body.to_owned()))
        .unwrap_or_default();
    Ok((status, headers, body))
}

/// Every site must answer with its own identity: adopted sites through
/// `g0-identity.php` (UID), provisioned sites through `rustiron-site.txt`
/// (account name, written during provisioning).
pub fn probe_all(
    address: &str,
    tls_address: Option<&str>,
    adopted: &[AdoptedSite],
    sites: &[ServedSite],
) -> Result<(), ExecutorError> {
    for site in adopted {
        let (status, body) = get(address, site.hostname.as_str(), "/g0-identity.php")?;
        let value: serde_json::Value =
            serde_json::from_str(body.trim()).map_err(|_| ExecutorError::StepFailed)?;
        if status != 200 || value["uid"] != site.uid {
            return Err(ExecutorError::StepFailed);
        }
    }
    for site in sites {
        for name in std::iter::once(&site.hostname).chain(site.alias_hostname.as_ref()) {
            probe_identity_or_https(address, tls_address, &site.account, name)?;
        }
    }
    Ok(())
}

/// The path of every provisioned site's identity marker.
const MARKER_PATH: &str = "/rustiron-site.txt";

/// Whether an HTTP answer sends the client to the same marker over HTTPS
/// with the same name: a 301, 302, 307, or 308 whose `Location` is exactly
/// `https://<name>/rustiron-site.txt`.
fn redirects_to_https(status: u16, headers: &str, name: &str) -> bool {
    let wanted = format!("https://{name}{MARKER_PATH}");
    matches!(status, 301 | 302 | 307 | 308)
        && headers.lines().any(|line| {
            line.split_once(':').is_some_and(|(key, value)| {
                key.trim().eq_ignore_ascii_case("location") && value.trim() == wanted
            })
        })
}

/// W511-F3 (P08): the site's identity through the HTTP listener, or, for a
/// site whose own rules send HTTP to HTTPS, through the TLS listener after
/// exactly that redirect. An ejected vhost has no Rustiron context for the
/// marker, so the site's `.htaccess` applies to it. The TLS listener maps
/// only certified names, and its answer must still be the site's marker.
pub(crate) fn probe_identity_or_https(
    address: &str,
    tls_address: Option<&str>,
    account: &str,
    name: &Hostname,
) -> Result<(), ExecutorError> {
    let (status, headers, body) = get_response(address, name.as_str(), MARKER_PATH)?;
    if status == 200 && body.trim() == account {
        return Ok(());
    }
    let tls = tls_address
        .filter(|_| redirects_to_https(status, &headers, name.as_str()))
        .ok_or(ExecutorError::StepFailed)?;
    let (status, _, body) = get_response_tls(tls, name.as_str(), MARKER_PATH)?;
    if status == 200 && body.trim() == account {
        Ok(())
    } else {
        Err(ExecutorError::StepFailed)
    }
}

pub(crate) fn probe_identity(
    address: &str,
    account: &str,
    name: &Hostname,
) -> Result<(), ExecutorError> {
    let (status, body) = get(address, name.as_str(), MARKER_PATH)?;
    if status != 200 || body.trim() != account {
        return Err(ExecutorError::StepFailed);
    }
    Ok(())
}

/// D-097: requires the site's identity marker over TLS directly (200 with
/// exact account text).
pub(crate) fn probe_identity_tls(
    tls_address: &str,
    account: &str,
    name: &Hostname,
) -> Result<(), ExecutorError> {
    let (status, _, body) = get_response_tls(tls_address, name.as_str(), MARKER_PATH)?;
    if status != 200 || body.trim() != account {
        return Err(ExecutorError::StepFailed);
    }
    Ok(())
}

#[cfg(test)]
mod response_tests {
    use super::parse_response;

    /// W511-F3: only the exact redirect to the same marker over HTTPS.
    #[test]
    fn only_the_exact_https_redirect_of_the_marker_counts() {
        use super::redirects_to_https;
        let to = |location: &str| format!("HTTP/1.1 302 Found\r\nLocation: {location}");
        let name = "testwp.example.test";
        assert!(redirects_to_https(
            302,
            &to("https://testwp.example.test/rustiron-site.txt"),
            name
        ));
        assert!(redirects_to_https(
            301,
            "HTTP/1.1 301\r\nlocation:  https://testwp.example.test/rustiron-site.txt ",
            name
        ));
        assert!(!redirects_to_https(
            200,
            &to("https://testwp.example.test/rustiron-site.txt"),
            name
        ));
        assert!(!redirects_to_https(
            302,
            &to("https://other.example.test/rustiron-site.txt"),
            name
        ));
        assert!(!redirects_to_https(
            302,
            &to("http://testwp.example.test/rustiron-site.txt"),
            name
        ));
        assert!(!redirects_to_https(
            302,
            &to("https://testwp.example.test/"),
            name
        ));
        assert!(!redirects_to_https(302, "HTTP/1.1 302 Found", name));
    }

    /// W511-F1: the `s_client -quiet` answer is the server's bytes only.
    #[test]
    fn an_http_answer_parses_into_status_headers_and_body() {
        let text = "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n<form id=\"loginform\">";
        let (status, headers, body) = parse_response(text).unwrap();
        assert_eq!(status, 200);
        assert_eq!(headers, "HTTP/1.0 200 OK\r\nContent-Type: text/html");
        assert!(body.contains("loginform"));
        assert!(parse_response("").is_err());
        assert!(parse_response("garbage").is_err());
    }

    #[test]
    fn single_static_generation_checks_require_exact_listener_and_vhost_scope() {
        use super::{ServedSite, render_with_tls, single_static_maps_ok, single_static_vhost_ok};
        use rustiron_contracts::approval::{Hostname, Sha256Digest};

        let host = Hostname::try_from("static.example.test".to_owned()).unwrap();
        let other = Hostname::try_from("other.example.test".to_owned()).unwrap();
        let alias = Hostname::try_from("alt.example.test".to_owned()).unwrap();
        let cert = Sha256Digest::from_bytes([0xaa; 32]);
        let make = |ejected: bool, static_ejected: bool, tls: Option<Sha256Digest>| ServedSite {
            account: "rs_static1".to_owned(),
            hostname: host.clone(),
            alias_hostname: None,
            ejected,
            static_ejected,
            lscache: false,
            tls,
            tls_alias: None,
            acme: false,
            proxy: None,
        };

        let plain_managed = render_with_tls(
            "G0",
            "127.0.0.1:8090",
            Some("127.0.0.1:8443"),
            &[],
            &[make(false, false, None)],
        );
        assert!(single_static_maps_ok(
            &plain_managed,
            "rs_static1",
            &host,
            false
        ));
        assert!(!single_static_maps_ok(
            &plain_managed,
            "rs_static1",
            &host,
            true
        ));
        assert!(!single_static_maps_ok(
            &plain_managed,
            "rs_static1",
            &other,
            false
        ));
        assert!(single_static_vhost_ok(
            &plain_managed,
            "rs_static1",
            false,
            false
        ));
        assert!(!single_static_vhost_ok(
            &plain_managed,
            "rs_static1",
            true,
            false
        ));
        assert!(!single_static_vhost_ok(
            &plain_managed,
            "rs_static1",
            false,
            true
        ));

        let plain_ejected = render_with_tls(
            "G0",
            "127.0.0.1:8090",
            Some("127.0.0.1:8443"),
            &[],
            &[make(true, true, None)],
        );
        assert!(single_static_maps_ok(
            &plain_ejected,
            "rs_static1",
            &host,
            false
        ));
        assert!(single_static_vhost_ok(
            &plain_ejected,
            "rs_static1",
            false,
            true
        ));
        // An ejected site without static_ejected keeps enableScript 1 and must fail.
        let non_static_ejected = render_with_tls(
            "G0",
            "127.0.0.1:8090",
            Some("127.0.0.1:8443"),
            &[],
            &[make(true, false, None)],
        );
        assert!(!single_static_vhost_ok(
            &non_static_ejected,
            "rs_static1",
            false,
            true
        ));

        let tls_managed = render_with_tls(
            "G0",
            "127.0.0.1:8090",
            Some("127.0.0.1:8443"),
            &[],
            &[make(false, false, Some(cert.clone()))],
        );
        assert!(single_static_maps_ok(
            &tls_managed,
            "rs_static1",
            &host,
            true
        ));
        assert!(!single_static_maps_ok(
            &tls_managed,
            "rs_static1",
            &host,
            false
        ));
        assert!(single_static_vhost_ok(
            &tls_managed,
            "rs_static1",
            true,
            false
        ));
        assert!(!single_static_vhost_ok(
            &tls_managed,
            "rs_static1",
            false,
            false
        ));

        let tls_ejected = render_with_tls(
            "G0",
            "127.0.0.1:8090",
            Some("127.0.0.1:8443"),
            &[],
            &[make(true, true, Some(cert))],
        );
        assert!(single_static_maps_ok(
            &tls_ejected,
            "rs_static1",
            &host,
            true
        ));
        assert!(single_static_vhost_ok(
            &tls_ejected,
            "rs_static1",
            true,
            true
        ));

        // Alias pair mapping is rejected for single-name static checks.
        let mut with_alias = make(false, false, None);
        with_alias.alias_hostname = Some(alias);
        let alias_gen = render_with_tls("G0", "127.0.0.1:8090", None, &[], &[with_alias]);
        assert!(!single_static_maps_ok(
            &alias_gen,
            "rs_static1",
            &host,
            false
        ));

        // Another site mapping the same hostname on HTTP is rejected.
        let mut duplicate = make(false, false, None);
        duplicate.account = "rs_other".to_owned();
        let dup_gen = render_with_tls(
            "G0",
            "127.0.0.1:8090",
            None,
            &[],
            &[make(false, false, None), duplicate],
        );
        assert!(!single_static_maps_ok(&dup_gen, "rs_static1", &host, false));
    }
}

#[cfg(test)]
#[path = "ols_race_tests.rs"]
mod race_tests;

#[cfg(test)]
#[path = "ols_stage_tests.rs"]
mod stage_tests;
