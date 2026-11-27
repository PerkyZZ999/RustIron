//! W462 (D-059 slice 3): one certificate issuance, run by the admin helper
//! for the journal's open `certificate_issue`. Every path comes from the
//! journaled site and hostname and the enrolled policy.
//!
//! 1. The HTTP-01 webroot inside the site root, owned by `rustiron-acme`.
//! 2. A self-check that the listener serves a token from it for the hostname.
//! 3. certbot as `rustiron-acme` in a fixed sandboxed transient unit.
//! 4. The issued chain and key, read only inside certbot's archive folder,
//!    staged, checked with `openssl` (exactly the hostname in the SAN, valid
//!    now, the key matches), and moved to `/etc/rustiron-tls/<account>/<sha>/`.

use std::{
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use rustiron_contracts::{
    Timestamp,
    approval::{Hostname, Sha256Digest},
};
use sha2::{Digest, Sha256};

use crate::{ExecutorError, ols, provision};

/// The ACME account and its state folder.
pub const ACME_ACCOUNT: &str = "rustiron-acme";
/// certbot's `--config-dir`, `--work-dir`, and `--logs-dir` live here.
pub const ACME_STATE_DIR: &str = crate::layout::ACME_STATE_DIR;
/// The largest chain or key file read back.
const MAX_PEM_BYTES: u64 = 64 * 1024;

/// What one issuance needs, all derived by the caller.
pub(crate) struct Issue<'a> {
    pub account: &'a str,
    pub hostname: &'a Hostname,
    pub alias: Option<&'a Hostname>,
    pub served_pair: Option<&'a Sha256Digest>,
    /// The enrolled plain listener, for the challenge self-check.
    pub listener: &'a str,
    /// The enrolled TLS listener, for the D-060 probe of a served site.
    pub tls_listener: &'a str,
    /// The enrolled ACME directory URL.
    pub directory: &'a str,
    /// A lab CA bundle that certbot alone trusts; `None` uses the system store.
    pub ca_bundle: Option<&'a str>,
    /// Reliable current time, for the validity check.
    pub now: Timestamp,
}

pub(crate) fn require_pair_mapping(
    account: &str,
    primary: &Hostname,
    alias: &Hostname,
    secure: bool,
) -> Result<(rustiron_contracts::Id, Sha256Digest), ExecutorError> {
    let (observed, generation) = current_generation()?;
    if !ols::maps_alias_pair(&generation, account, primary, alias, secure) {
        return Err(ExecutorError::PreconditionChanged);
    }
    Ok(observed)
}

/// D-097: verifies that the live managed generation maps `account` to
/// `hostname` alone on HTTP, matches `tls` on the TLS listener and `<account>.vhost`,
/// and has no ambiguous listener or vhost binding.
pub(crate) fn require_single_static_mapping(
    account: &str,
    hostname: &Hostname,
    tls: bool,
) -> Result<(rustiron_contracts::Id, Sha256Digest), ExecutorError> {
    let (observed, generation) = current_generation()?;
    if !ols::single_static_maps_ok(&generation, account, hostname, tls)
        || !ols::single_static_vhost_ok(&generation, account, tls, false)
    {
        return Err(ExecutorError::PreconditionChanged);
    }
    Ok(observed)
}

fn current_generation()
-> Result<((rustiron_contracts::Id, Sha256Digest), ols::Generation), ExecutorError> {
    let include = ols::open_include()?;
    let (id, digest) = ols::observe(&include)?;
    let generation = ols::stored_generation(&include, &id)?;
    if id != ols::generation_id(&digest) || ols::digest(&generation) != digest {
        return Err(ExecutorError::Drift);
    }
    Ok(((id, digest), generation))
}

pub(crate) fn pair_serves_tls(
    account: &str,
    hostname: &Hostname,
    alias: &Hostname,
) -> Result<bool, ExecutorError> {
    let (_, generation) = current_generation()?;
    let vhost = generation
        .get(&format!("{account}.vhost"))
        .ok_or(ExecutorError::PreconditionChanged)?;
    let vhost = std::str::from_utf8(vhost).map_err(|_| ExecutorError::Drift)?;
    let mapped = ols::maps_alias_pair(&generation, account, hostname, alias, true);
    if vhost.contains("\nvhssl {\n") != mapped {
        return Err(ExecutorError::Drift);
    }
    Ok(mapped)
}

fn failed(what: &'static str) -> ExecutorError {
    eprintln!("{{\"scope\":\"certificate_issue\",\"step_failure\":\"{what}\"}}");
    ExecutorError::StepFailed
}

fn acme_uid() -> Result<u32, ExecutorError> {
    provision::account_uid(&provision::read_etc("passwd")?, ACME_ACCOUNT)
        .ok_or_else(|| failed("no rustiron-acme account"))
}

/// W478-F4: creates the site's ACME webroot when its site is provisioned or
/// imported, so the site's first activation already renders the challenge
/// context and its first issuance can pass the challenge check. A host
/// without the `rustiron-acme` account issues no certificates and gets no
/// webroot.
pub(crate) fn prepare_webroot(account: &str) -> Result<(), ExecutorError> {
    let passwd = provision::read_etc("passwd")?;
    match provision::account_uid(&passwd, ACME_ACCOUNT) {
        Some(uid) => ensure_webroot(Path::new(&ols::acme_webroot(account)), uid),
        None => Ok(()),
    }
}

/// Runs one issuance and returns the installed chain's SHA-256 and expiry.
pub(crate) fn issue(job: &Issue<'_>) -> Result<(Sha256Digest, Timestamp), ExecutorError> {
    let uid = acme_uid()?;
    let webroot = PathBuf::from(ols::acme_webroot(job.account));
    ensure_webroot(&webroot, uid)?;
    challenge_check(job, &webroot, uid)?;
    run_certbot(job, &webroot)?;
    let (chain, key) = read_lineage(job.hostname)?;
    let (sha, not_after) = install(job, &chain, &key)?;
    switch(job, &sha)?;
    Ok((sha, not_after))
}

/// D-060: the site's `live` link must name `sha`.
pub(crate) fn check_live(account: &str, sha: &Sha256Digest) -> Result<(), ExecutorError> {
    match std::fs::read_link(ols::tls_live(account)) {
        Ok(target) if target == Path::new(sha.as_str()) => Ok(()),
        _ => Err(failed("live certificate link is not the installed chain")),
    }
}

/// Points the site's `live` link at `target` (a relative digest folder).
fn point_live(account: &str, target: &str) -> Result<(), ExecutorError> {
    let live = PathBuf::from(ols::tls_live(account));
    let next = live.with_file_name(format!("live.next-{}", crate::ols::stage::random_hex()?));
    std::os::unix::fs::symlink(target, &next).map_err(|_| failed("live link create"))?;
    if std::fs::rename(&next, &live).is_err() {
        let _ = std::fs::remove_file(&next);
        return Err(failed("live link swap"));
    }
    std::fs::File::open(live.parent().ok_or_else(|| failed("live link folder"))?)
        .and_then(|folder| folder.sync_all())
        .map_err(|_| failed("live link sync"))
}

/// D-060: swaps the site's `live` link to the new chain. When the current
/// generation already serves the site over TLS, the switch is checked:
/// `openlitespeed -t`, a graceful reload, and a probe that the listener
/// serves the new leaf for the hostname. Any failure restores the previous
/// link and reloads.
fn switch(job: &Issue<'_>, sha: &Sha256Digest) -> Result<(), ExecutorError> {
    if let Some(alias) = job.alias {
        return switch_pair(job, alias, sha);
    }
    let previous = std::fs::read_link(ols::tls_live(job.account)).ok();
    point_live(job.account, sha.as_str())?;
    if !serves_live_chain(job.account) {
        return Ok(());
    }
    let checked = (|| {
        ols::config_test()?;
        provision::run("/usr/bin/systemctl", &["reload", "lshttpd.service"])?;
        let want = leaf_fingerprint_of_file(&format!(
            "{}/fullchain.pem",
            ols::tls_folder(job.account, sha)
        ))?;
        for _ in 0..20 {
            std::thread::sleep(std::time::Duration::from_millis(500));
            if served_leaf_fingerprint(job.tls_listener, job.hostname).as_deref()
                == Ok(want.as_str())
            {
                return Ok(());
            }
        }
        Err(failed("the listener does not serve the new certificate"))
    })();
    if checked.is_err()
        && let Some(previous) = previous.as_ref().and_then(|path| path.to_str())
    {
        let _ = point_live(job.account, previous);
        let _ = provision::run("/usr/bin/systemctl", &["reload", "lshttpd.service"]);
    }
    checked
}

fn switch_pair(job: &Issue<'_>, alias: &Hostname, sha: &Sha256Digest) -> Result<(), ExecutorError> {
    let Some(previous) = job.served_pair else {
        return point_live(job.account, sha.as_str()).map_err(|_| ExecutorError::Drift);
    };
    require_pair_mapping(job.account, job.hostname, alias, true)?;
    check_live(job.account, previous)?;
    let switch_and_verify = |chain: &Sha256Digest| {
        point_live(job.account, chain.as_str())?;
        ols::config_test()?;
        provision::run("/usr/bin/systemctl", &["reload", "lshttpd.service"])?;
        verify_pair_leaf(job.tls_listener, job.account, job.hostname, alias, chain)
    };
    replace_pair(previous, sha, switch_and_verify)
}

fn replace_pair(
    previous: &Sha256Digest,
    next: &Sha256Digest,
    mut switch_and_verify: impl FnMut(&Sha256Digest) -> Result<(), ExecutorError>,
) -> Result<(), ExecutorError> {
    if switch_and_verify(next).is_err() {
        // Without positive restoration proof the executor keeps the intent open.
        switch_and_verify(previous).map_err(|_| ExecutorError::Drift)?;
        return Err(failed(
            "pair switch rejected; previous leaf verified under both names",
        ));
    }
    Ok(())
}

pub(crate) fn verify_pair_leaf(
    listener: &str,
    account: &str,
    primary: &Hostname,
    alias: &Hostname,
    sha: &Sha256Digest,
) -> Result<(), ExecutorError> {
    check_live(account, sha)?;
    let want =
        leaf_fingerprint_of_file(&format!("{}/fullchain.pem", ols::tls_folder(account, sha)))?;
    for _ in 0..20 {
        if [primary, alias]
            .into_iter()
            .all(|name| served_leaf_fingerprint(listener, name).as_deref() == Ok(want.as_str()))
        {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Err(failed(
        "the TLS listener does not serve the certificate under both names",
    ))
}

/// D-097: verifies the installed single-name chain files on disk (`fullchain.pem`
/// matches `sha`, SAN names only `hostname`, `key.pem` matches leaf public key).
pub(crate) fn verify_single_leaf_files(
    folder: &Path,
    hostname: &Hostname,
    sha: &Sha256Digest,
) -> Result<(), ExecutorError> {
    use std::io::Read;
    let chain_path = folder.join("fullchain.pem");
    let key_path = folder.join("key.pem");
    let chain_file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC).bits() as i32)
        .open(&chain_path)
        .map_err(|_| failed("installed chain unreadable"))?;
    let chain_meta = chain_file
        .metadata()
        .map_err(|_| failed("installed chain stat"))?;
    if !chain_meta.is_file() || chain_meta.len() == 0 || chain_meta.len() > MAX_PEM_BYTES {
        return Err(failed("installed chain size"));
    }
    let mut chain_bytes = Vec::new();
    chain_file
        .take(MAX_PEM_BYTES + 1)
        .read_to_end(&mut chain_bytes)
        .map_err(|_| failed("installed chain read"))?;
    if Sha256Digest::from_bytes(Sha256::digest(&chain_bytes).into()) != *sha {
        return Err(failed("installed chain digest mismatch"));
    }
    let key_meta =
        std::fs::symlink_metadata(&key_path).map_err(|_| failed("installed key missing"))?;
    if !key_meta.is_file() || key_meta.len() == 0 || key_meta.len() > MAX_PEM_BYTES {
        return Err(failed("installed key size"));
    }
    let chain = provision::path_str(&chain_path)?;
    let key = provision::path_str(&key_path)?;
    let openssl = "/usr/bin/openssl";
    let san = provision::output(
        openssl,
        &["x509", "-in", chain, "-noout", "-ext", "subjectAltName"],
    )
    .map_err(|_| failed("installed certificate unreadable"))?;
    if !san_is_exactly(&san, hostname, None) {
        return Err(failed(
            "installed certificate is not single-name for hostname",
        ));
    }
    let leaf_key = provision::output(openssl, &["x509", "-in", chain, "-noout", "-pubkey"])
        .map_err(|_| failed("installed certificate key unreadable"))?;
    let own_key = provision::output(openssl, &["pkey", "-in", key, "-pubout"])
        .map_err(|_| failed("installed private key unreadable"))?;
    if leaf_key.trim().is_empty() || leaf_key != own_key {
        return Err(failed("installed private key does not match"));
    }
    Ok(())
}

/// D-097: verifies a site's installed single-name TLS chain on disk (`live`
/// link, chain digest, exact single-name SAN, matching private key) and that
/// the TLS listener serves that exact leaf for `hostname`.
pub(crate) fn verify_single_leaf(
    listener: &str,
    account: &str,
    hostname: &Hostname,
    sha: &Sha256Digest,
) -> Result<(), ExecutorError> {
    check_live(account, sha)?;
    let folder = PathBuf::from(ols::tls_folder(account, sha));
    verify_single_leaf_files(&folder, hostname, sha)?;
    let want =
        leaf_fingerprint_of_file(&format!("{}/fullchain.pem", ols::tls_folder(account, sha)))?;
    for _ in 0..20 {
        if served_leaf_fingerprint(listener, hostname).as_deref() == Ok(want.as_str()) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Err(failed(
        "the TLS listener does not serve the installed single-name certificate",
    ))
}

/// Whether the current generation serves the site through its `live` link.
/// A generation rendered before D-060 names the digest folder instead; the
/// new link then takes effect at the next activation, with no reload now.
pub(crate) fn serves_live_chain(account: &str) -> bool {
    let live = format!(" keyFile {}/key.pem\n", ols::tls_live(account));
    std::fs::read_to_string(format!(
        "{}/current/{account}.vhost",
        crate::layout::OLS_INCLUDE_DIR
    ))
    .is_ok_and(|text| text.contains("\nvhssl {\n") && text.contains(&live))
}

fn leaf_fingerprint_of_file(chain: &str) -> Result<String, ExecutorError> {
    provision::output(
        "/usr/bin/openssl",
        &["x509", "-in", chain, "-noout", "-fingerprint", "-sha256"],
    )
    .map(|text| text.trim().to_owned())
    .map_err(|_| failed("certificate fingerprint"))
}

/// The SHA-256 fingerprint of the leaf the TLS listener serves for the
/// hostname, by `openssl s_client` (SNI, no verification: only identity).
fn served_leaf_fingerprint(listener: &str, hostname: &Hostname) -> Result<String, ExecutorError> {
    // `s_client` prints the leaf PEM; empty stdin ends the session.
    let shown = provision::spawn(
        "/usr/bin/openssl",
        &[
            "s_client",
            "-connect",
            listener,
            "-servername",
            hostname.as_str(),
        ],
        true,
        Some(b""),
    )
    .map_err(|_| failed("tls probe"))?;
    let begin = shown
        .find("-----BEGIN CERTIFICATE-----")
        .ok_or_else(|| failed("tls probe leaf"))?;
    let end = shown[begin..]
        .find("-----END CERTIFICATE-----")
        .map(|offset| begin + offset + "-----END CERTIFICATE-----".len())
        .ok_or_else(|| failed("tls probe leaf"))?;
    let leaf = format!("{}\n", &shown[begin..end]);
    provision::spawn(
        "/usr/bin/openssl",
        &["x509", "-noout", "-fingerprint", "-sha256"],
        true,
        Some(leaf.as_bytes()),
    )
    .map(|text| text.trim().to_owned())
    .map_err(|_| failed("tls probe fingerprint"))
}

/// Creates `<webroot>/.well-known/acme-challenge/`, owned by `rustiron-acme`,
/// mode 0755. An existing part must be a real folder of that owner.
fn ensure_webroot(webroot: &Path, uid: u32) -> Result<(), ExecutorError> {
    use std::os::unix::fs::MetadataExt;
    let mut path = webroot.to_path_buf();
    for part in ["", ".well-known", "acme-challenge"] {
        if !part.is_empty() {
            path.push(part);
        }
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_dir() && meta.uid() == uid => continue,
            Ok(_) => return Err(failed("webroot is not a rustiron-acme folder")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(failed("webroot unreadable")),
        }
        std::fs::DirBuilder::new()
            .mode(0o755)
            .create(&path)
            .map_err(|_| failed("webroot create"))?;
        // The helper runs with UMask=0077; OLS must traverse the folder.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .map_err(|_| failed("webroot mode"))?;
        std::os::unix::fs::chown(&path, Some(uid), Some(uid))
            .map_err(|_| failed("webroot chown"))?;
        provision::run(
            "/usr/sbin/restorecon",
            &["-F", "--", provision::path_str(&path)?],
        )?;
    }
    Ok(())
}

/// Writes a random token as `rustiron-acme` and requires the listener to
/// answer it for the hostname, then removes it.
fn challenge_check(job: &Issue<'_>, webroot: &Path, uid: u32) -> Result<(), ExecutorError> {
    let token = format!("rustiron-check-{}", crate::ols::stage::random_hex()?);
    let file = webroot.join(".well-known/acme-challenge").join(&token);
    let result = (|| {
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&file)
            .map_err(|_| failed("challenge token write"))?;
        out.write_all(token.as_bytes())
            .map_err(|_| failed("challenge token write"))?;
        // W462: the helper's UMask=0077 would leave the token unreadable to
        // the OLS worker.
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644))
            .map_err(|_| failed("challenge token mode"))?;
        std::os::unix::fs::chown(&file, Some(uid), Some(uid))
            .map_err(|_| failed("challenge token chown"))?;
        let path = format!("/.well-known/acme-challenge/{token}");
        for name in std::iter::once(job.hostname).chain(job.alias) {
            let (status, body) = ols::get(job.listener, name.as_str(), &path)?;
            if status != 200 || body != token {
                return Err(failed("challenge path not served"));
            }
        }
        Ok(())
    })();
    let _ = std::fs::remove_file(&file);
    result
}

fn run_certbot(job: &Issue<'_>, webroot: &Path) -> Result<(), ExecutorError> {
    let webroot = provision::path_str(webroot)?;
    let writable = format!("ReadWritePaths={ACME_STATE_DIR} {webroot}");
    let mut args: Vec<String> = [
        "--wait",
        "--quiet",
        "--collect",
        "--property=User=rustiron-acme",
        "--property=Group=rustiron-acme",
        "--property=NoNewPrivileges=yes",
        "--property=ProtectSystem=strict",
        "--property=ProtectHome=yes",
        "--property=PrivateTmp=yes",
        "--property=PrivateDevices=yes",
        "--property=CapabilityBoundingSet=",
        "--property=RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
        "--property=RuntimeMaxSec=300",
        "--property=StandardOutput=null",
    ]
    .map(String::from)
    .to_vec();
    args.push(format!("--property={writable}"));
    if let Some(bundle) = job.ca_bundle {
        args.push(format!("--setenv=REQUESTS_CA_BUNDLE={bundle}"));
    }
    if job.alias.is_some() {
        args.extend(
            [
                "--property=IPAddressDeny=any",
                "--property=IPAddressAllow=localhost",
            ]
            .map(String::from),
        );
    }
    args.extend(
        [
            "--",
            "/usr/bin/certbot",
            "certonly",
            "--non-interactive",
            "--agree-tos",
            "--register-unsafely-without-email",
            "--no-eff-email",
            "--force-renewal",
            "--key-type",
            "ecdsa",
        ]
        .map(String::from),
    );
    for (flag, value) in [
        ("--server", job.directory.to_owned()),
        ("--config-dir", format!("{ACME_STATE_DIR}/config")),
        ("--work-dir", format!("{ACME_STATE_DIR}/work")),
        ("--logs-dir", format!("{ACME_STATE_DIR}/logs")),
        ("--webroot-path", webroot.to_owned()),
        ("--cert-name", job.hostname.as_str().to_owned()),
        ("--domain", job.hostname.as_str().to_owned()),
    ] {
        args.push(flag.to_owned());
        args.push(value);
    }
    if let Some(alias) = job.alias {
        args.extend(["--domain".to_owned(), alias.as_str().to_owned()]);
    }
    args.push("--webroot".to_owned());
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    provision::run("/usr/bin/systemd-run", &borrowed).map_err(|_| failed("certbot"))
}

/// Reads `live/<hostname>/{fullchain,privkey}.pem`, which certbot links into
/// `archive/<hostname>/`; any other target is refused.
fn read_lineage(hostname: &Hostname) -> Result<(Vec<u8>, Vec<u8>), ExecutorError> {
    let live = PathBuf::from(format!(
        "{ACME_STATE_DIR}/config/live/{}",
        hostname.as_str()
    ));
    let archive = std::fs::canonicalize(format!(
        "{ACME_STATE_DIR}/config/archive/{}",
        hostname.as_str()
    ))
    .map_err(|_| failed("certbot archive missing"))?;
    let read = |name: &str| -> Result<Vec<u8>, ExecutorError> {
        let target = std::fs::canonicalize(live.join(name))
            .map_err(|_| failed("certbot lineage missing"))?;
        if target.parent() != Some(archive.as_path()) {
            return Err(failed("certbot lineage outside its archive"));
        }
        let meta = std::fs::symlink_metadata(&target).map_err(|_| failed("lineage stat"))?;
        if !meta.is_file() || meta.len() == 0 || meta.len() > MAX_PEM_BYTES {
            return Err(failed("lineage file"));
        }
        std::fs::read(&target).map_err(|_| failed("lineage read"))
    };
    Ok((read("fullchain.pem")?, read("privkey.pem")?))
}

/// Stages the files, checks them, and renames the folder into place.
fn install(
    job: &Issue<'_>,
    chain: &[u8],
    key: &[u8],
) -> Result<(Sha256Digest, Timestamp), ExecutorError> {
    let sha = Sha256Digest::from_bytes(Sha256::digest(chain).into());
    let site = PathBuf::from(format!("{}/{}", crate::layout::OLS_TLS_DIR, job.account));
    for folder in [Path::new(crate::layout::OLS_TLS_DIR), site.as_path()] {
        match std::fs::symlink_metadata(folder) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => return Err(failed("tls folder is not a folder")),
            Err(_) => {
                std::fs::DirBuilder::new()
                    .mode(0o711)
                    .create(folder)
                    .map_err(|_| failed("tls folder create"))?;
                std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o711))
                    .map_err(|_| failed("tls folder mode"))?;
                provision::run(
                    "/usr/sbin/restorecon",
                    &["-F", "--", provision::path_str(folder)?],
                )?;
            }
        }
    }
    let target = PathBuf::from(ols::tls_folder(job.account, &sha));
    if std::fs::symlink_metadata(&target).is_ok() {
        // The same chain is already installed; check it again and reuse it.
        let not_after = check(job, &target)?;
        return Ok((sha, not_after));
    }
    let stage = site.join(format!(".stage-{}", crate::ols::stage::random_hex()?));
    std::fs::DirBuilder::new()
        .mode(0o711)
        .create(&stage)
        .map_err(|_| failed("tls stage create"))?;
    std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o711))
        .map_err(|_| failed("tls stage mode"))?;
    let caddy_gid = provision::read_etc("group").ok().and_then(|groups| {
        groups.lines().find_map(|line| {
            let mut fields = line.split(':');
            (fields.next()? == "rustiron-caddy")
                .then(|| fields.nth(1)?.parse::<u32>().ok())
                .flatten()
        })
    });
    let result = (|| {
        let key_mode = if caddy_gid.is_some() { 0o640 } else { 0o600 };
        for (name, bytes, mode) in [("fullchain.pem", chain, 0o644), ("key.pem", key, key_mode)] {
            let file_path = stage.join(name);
            let mut out = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(&file_path)
                .map_err(|_| failed("tls stage write"))?;
            out.write_all(bytes)
                .map_err(|_| failed("tls stage write"))?;
            out.sync_all().map_err(|_| failed("tls stage write"))?;
            if name == "key.pem"
                && let Some(gid) = caddy_gid
            {
                rustix::fs::chown(
                    &file_path,
                    Some(rustix::process::Uid::from_raw(0)),
                    Some(rustix::process::Gid::from_raw(gid)),
                )
                .map_err(|_| failed("tls key group"))?;
            }
            std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(mode))
                .map_err(|_| failed("tls stage mode"))?;
        }
        let not_after = check(job, &stage)?;
        provision::run(
            "/usr/sbin/restorecon",
            &["-RF", "--", provision::path_str(&stage)?],
        )?;
        std::fs::rename(&stage, &target).map_err(|_| failed("tls rename"))?;
        std::fs::File::open(&site)
            .and_then(|folder| folder.sync_all())
            .map_err(|_| failed("tls sync"))?;
        Ok(not_after)
    })();
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&stage);
    }
    result.map(|not_after| (sha, not_after))
}

/// `openssl` checks of a staged or installed folder. Returns the expiry.
fn check(job: &Issue<'_>, folder: &Path) -> Result<Timestamp, ExecutorError> {
    let chain = provision::path_str(&folder.join("fullchain.pem"))?.to_owned();
    let key = provision::path_str(&folder.join("key.pem"))?.to_owned();
    let openssl = "/usr/bin/openssl";
    let san = provision::output(
        openssl,
        &["x509", "-in", &chain, "-noout", "-ext", "subjectAltName"],
    )
    .map_err(|_| failed("certificate unreadable"))?;
    if !san_is_exactly(&san, job.hostname, job.alias) {
        return Err(failed("certificate names another host"));
    }
    let leaf_key = provision::output(openssl, &["x509", "-in", &chain, "-noout", "-pubkey"])
        .map_err(|_| failed("certificate key unreadable"))?;
    let own_key = provision::output(openssl, &["pkey", "-in", &key, "-pubout"])
        .map_err(|_| failed("private key unreadable"))?;
    if leaf_key.trim().is_empty() || leaf_key != own_key {
        return Err(failed("private key does not match"));
    }
    let dates = provision::output(
        openssl,
        &[
            "x509",
            "-in",
            &chain,
            "-noout",
            "-startdate",
            "-enddate",
            "-dateopt",
            "iso_8601",
        ],
    )
    .map_err(|_| failed("certificate dates unreadable"))?;
    let (not_before, not_after) = validity(&dates).ok_or_else(|| failed("certificate dates"))?;
    if job.now.get() < not_before.get() || job.now.get() >= not_after.get() {
        return Err(failed("certificate not valid now"));
    }
    Ok(not_after)
}

/// The leaf text contains exactly the signed DNS names, in either order.
pub(crate) fn san_is_exactly(text: &str, hostname: &Hostname, alias: Option<&Hostname>) -> bool {
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    let header = lines.next();
    if !matches!(
        header,
        Some("X509v3 Subject Alternative Name:" | "X509v3 Subject Alternative Name: critical")
    ) {
        return false;
    }
    let Some(names) = lines.next() else {
        return false;
    };
    if lines.next().is_some() {
        return false;
    }
    let mut names = names
        .split(',')
        .map(str::trim)
        .map(|name| name.strip_prefix("DNS:"));
    let primary = Some(Some(hostname.as_str()));
    let first = names.next();
    let second = names.next();
    match alias {
        None => first == primary && second.is_none(),
        Some(alias) => {
            let alias = Some(Some(alias.as_str()));
            ((first == primary && second == alias) || (first == alias && second == primary))
                && names.next().is_none()
        }
    }
}

/// `notBefore=` and `notAfter=` lines in ISO 8601 (`2026-11-17 14:41:13Z`).
pub(crate) fn validity(text: &str) -> Option<(Timestamp, Timestamp)> {
    let mut before = None;
    let mut after = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("notBefore=") {
            before = Some(iso_seconds(value.trim())?);
        } else if let Some(value) = line.strip_prefix("notAfter=") {
            after = Some(iso_seconds(value.trim())?);
        }
    }
    Some((
        Timestamp::try_from(before?).ok()?,
        Timestamp::try_from(after?).ok()?,
    ))
}

fn iso_seconds(value: &str) -> Option<u64> {
    let value = value.strip_suffix('Z')?;
    let (date, time) = value.split_once(' ')?;
    let mut date = date.split('-').map(str::parse::<i64>);
    let (year, month, day) = (date.next()?.ok()?, date.next()?.ok()?, date.next()?.ok()?);
    let mut time = time.split(':').map(str::parse::<i64>);
    let (hour, minute, second) = (time.next()?.ok()?, time.next()?.ok()?, time.next()?.ok()?);
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..24).contains(&hour)
        || !(0..60).contains(&minute)
        || !(0..61).contains(&second)
    {
        return None;
    }
    // Days from the civil date (Howard Hinnant's algorithm).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + hour * 3600 + minute * 60 + second).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(name: &str) -> Hostname {
        Hostname::try_from(name.to_owned()).unwrap()
    }

    #[test]
    fn the_san_must_name_exactly_the_hostname() {
        let one = "X509v3 Subject Alternative Name: critical\n    DNS:cp02.example.test\n";
        assert!(san_is_exactly(one, &host("cp02.example.test"), None));
        assert!(san_is_exactly(
            "X509v3 Subject Alternative Name: \n    DNS:cp02.example.test\n",
            &host("cp02.example.test"),
            None,
        ));
        for text in [
            "",
            "X509v3 Subject Alternative Name: critical\n    DNS:other.example.test\n",
            "X509v3 Subject Alternative Name: critical\n    DNS:cp02.example.test, DNS:www.cp02.example.test\n",
            "X509v3 Subject Alternative Name: critical\n    DNS:*.example.test\n",
            "X509v3 Subject Alternative Name: critical\n    DNS:cp02.example.test\n    DNS:x\n",
            "X509v3 Key Usage:\n    DNS:cp02.example.test\n",
        ] {
            assert!(
                !san_is_exactly(text, &host("cp02.example.test"), None),
                "{text:?}"
            );
        }
    }

    #[test]
    fn the_san_must_cover_exactly_the_signed_pair() {
        let primary = host("cp02.example.test");
        let alias = host("alt.example.test");
        for (names, expected) in [
            ("DNS:cp02.example.test, DNS:alt.example.test", true),
            ("DNS:alt.example.test, DNS:cp02.example.test", true),
            ("DNS:cp02.example.test", false),
            ("DNS:cp02.example.test, DNS:cp02.example.test", false),
            ("DNS:cp02.example.test, DNS:*.example.test", false),
            ("DNS:cp02.example.test, IP Address:127.0.0.1", false),
            (
                "DNS:cp02.example.test, DNS:alt.example.test, DNS:third.example.test",
                false,
            ),
        ] {
            let text = format!("X509v3 Subject Alternative Name:\n    {names}\n");
            assert_eq!(
                san_is_exactly(&text, &primary, Some(&alias)),
                expected,
                "{names}"
            );
        }
    }

    #[test]
    fn a_failed_pair_switch_requires_positive_restoration() {
        let old = Sha256Digest::from_bytes([1; 32]);
        let new = Sha256Digest::from_bytes([2; 32]);
        for (restore, expected) in [
            (Ok(()), Err(ExecutorError::StepFailed)),
            (Err(ExecutorError::StepFailed), Err(ExecutorError::Drift)),
        ] {
            let mut attempts = Vec::new();
            let result = replace_pair(&old, &new, |sha| {
                attempts.push(sha.clone());
                if sha == &new {
                    Err(ExecutorError::StepFailed)
                } else {
                    restore
                }
            });
            assert_eq!(attempts, [new.clone(), old.clone()]);
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn the_validity_window_is_read_in_utc() {
        let (before, after) =
            validity("notBefore=2026-11-17 02:40:13Z\nnotAfter=2026-11-17 14:41:13Z\n").unwrap();
        assert_eq!(before.get(), 1_794_883_213);
        assert_eq!(after.get(), 1_794_926_473);
        assert_eq!(iso_seconds("1970-01-01 00:00:00Z"), Some(0));
        assert_eq!(iso_seconds("2000-03-01 00:00:00Z"), Some(951_868_800));
        for bad in [
            "2026-13-01 00:00:00Z",
            "2026-11-17 14:41:13",
            "2026-11-17T14:41:13Z",
            "x",
        ] {
            assert_eq!(iso_seconds(bad), None, "{bad}");
        }
        assert!(validity("notAfter=2026-11-17 14:41:13Z\n").is_none());
    }

    #[test]
    fn single_leaf_file_verification_checks_digest_san_and_key() {
        let dir = std::env::temp_dir().join(format!(
            "rustiron-d097-leaf-{}",
            crate::ols::stage::random_hex().unwrap()
        ));
        std::fs::create_dir(&dir).unwrap();
        let make = |sub: &str, san: &str| {
            let folder = dir.join(sub);
            std::fs::create_dir(&folder).unwrap();
            let chain = folder.join("fullchain.pem");
            let key = folder.join("key.pem");
            let status = std::process::Command::new("/usr/bin/openssl")
                .args([
                    "req",
                    "-x509",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:prime256v1",
                    "-nodes",
                    "-subj",
                    "/CN=static.example.test",
                    "-addext",
                    &format!("subjectAltName={san}"),
                    "-days",
                    "1",
                    "-keyout",
                    key.to_str().unwrap(),
                    "-out",
                    chain.to_str().unwrap(),
                ])
                .output()
                .unwrap();
            assert!(
                status.status.success(),
                "{}",
                String::from_utf8_lossy(&status.stderr)
            );
            let bytes = std::fs::read(&chain).unwrap();
            let sha = Sha256Digest::from_bytes(Sha256::digest(&bytes).into());
            (folder, sha)
        };

        let primary = host("static.example.test");
        let (ok_dir, ok_sha) = make("ok", "DNS:static.example.test");
        assert!(verify_single_leaf_files(&ok_dir, &primary, &ok_sha).is_ok());
        assert!(
            verify_single_leaf_files(&ok_dir, &primary, &Sha256Digest::from_bytes([1; 32]))
                .is_err()
        );
        assert!(verify_single_leaf_files(&ok_dir, &host("other.example.test"), &ok_sha).is_err());

        let (pair_dir, pair_sha) = make("pair", "DNS:static.example.test,DNS:alt.example.test");
        assert!(verify_single_leaf_files(&pair_dir, &primary, &pair_sha).is_err());

        // Mismatched private key fails.
        std::fs::copy(pair_dir.join("key.pem"), ok_dir.join("key.pem")).unwrap();
        assert!(verify_single_leaf_files(&ok_dir, &primary, &ok_sha).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
