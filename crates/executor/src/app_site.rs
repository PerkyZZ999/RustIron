//! W598 (P27 Slice 3, D-099): confined modern app hosting runtime for
//! Node.js (`node_22_v1`) and Bun (`bun_1_v1`) sites.
//!
//! Every Rustiron-owned path is derived strictly from [`crate::layout`] and
//! [`SiteLayout`]. No package manager (`npm`/`bun install`) or user script
//! ever executes as root: unpacking and migrations run in confined transient
//! systemd units as `rs_<site_id>` with `PrivateNetwork=yes`.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use rustiron_contracts::approval::{
    AppLifecycleAction, AppRuntime, MAX_APP_RELEASE_BYTES, MAX_APP_RELEASE_FILES,
    valid_manifest_path,
};
use rustiron_journal::{AppFacts, AppRelease, AppReleaseStep, ProvisionStep};
use sha2::{Digest, Sha256};

use crate::{
    ExecutorError,
    provision::{self, SiteLayout},
};

/// Recorded Recipe step name for a P27 app site.
pub(crate) const APP_RECIPE: &str = "app_v1";

/// Maximum size of a `manifest.sha256` file in an app intake directory (8 MiB).
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
/// Maximum size of a `private/app.env` file inspected for key presence (64 KiB).
const MAX_ENV_FILE_BYTES: u64 = 64 * 1024;
/// Startup grace attempts for the loopback HTTP health probe (16 x 250ms = 4.0s;
/// accommodates cold-start migrations of real EmDash 1.6.0 releases while keeping
/// failed health + rollback bounded).
const HEALTH_PROBE_ATTEMPTS: usize = 16;
const HEALTH_PROBE_PAUSE: Duration = Duration::from_millis(250);

/// Pinned host runtime binary for each closed `AppRuntime` profile.
pub(crate) const fn runtime_binary(runtime: AppRuntime) -> &'static str {
    match runtime {
        AppRuntime::Node22V1 => "/usr/bin/node",
        AppRuntime::Bun1V1 => "/usr/local/bin/bun",
    }
}

/// Trusted parent directory that a pinned runtime binary (and any symlink
/// target such as AlmaLinux 10 AppStream `/usr/bin/node -> node-22`) must stay
/// inside.
const fn runtime_trusted_dir(runtime: AppRuntime) -> &'static str {
    match runtime {
        AppRuntime::Node22V1 => "/usr/bin",
        AppRuntime::Bun1V1 => "/usr/local/bin",
    }
}

/// Runtime CLI argument that loads `private/app.env` inside the site account's
/// own process so PID 1 (`init_t:s0`) never reads MCS-labeled tenant secrets
/// (W599-F2).
pub(crate) fn runtime_env_arg(runtime: AppRuntime, root: &Path) -> String {
    let env_path = root.join("private").join("app.env");
    let env_str = env_path.to_string_lossy();
    match runtime {
        AppRuntime::Node22V1 => format!("--env-file-if-exists={env_str}"),
        AppRuntime::Bun1V1 => format!("--env-file={env_str}"),
    }
}

/// Whether an app site journals `step` done without PHP/database effects.
pub(crate) fn skips(step: ProvisionStep) -> bool {
    matches!(
        step,
        ProvisionStep::Database | ProvisionStep::Credentials | ProvisionStep::PhpUnits
    )
}

/// Verifies the pinned host runtime binary is a root-owned, non-world-writable
/// executable regular file inside its trusted binary directory. Allows a
/// root-owned in-directory symlink such as AlmaLinux 10 `/usr/bin/node -> node-22`
/// (W599-F1) while refusing any symlink escape outside the trusted directory.
pub(crate) fn verify_runtime_binary(runtime: AppRuntime) -> Result<&'static str, ExecutorError> {
    let path = runtime_binary(runtime);
    let expected_dir = Path::new(runtime_trusted_dir(runtime));
    let link_meta = fs::symlink_metadata(path).map_err(|_| ExecutorError::Unavailable)?;
    if link_meta.uid() != 0 {
        return Err(ExecutorError::Unavailable);
    }
    let resolved = fs::canonicalize(path).map_err(|_| ExecutorError::Unavailable)?;
    let expected_dir_canon =
        fs::canonicalize(expected_dir).unwrap_or_else(|_| expected_dir.to_path_buf());
    if resolved.parent() != Some(expected_dir_canon.as_path()) {
        return Err(ExecutorError::Unavailable);
    }
    let meta = fs::symlink_metadata(&resolved).map_err(|_| ExecutorError::Unavailable)?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o002 != 0 || meta.mode() & 0o111 == 0 {
        return Err(ExecutorError::Unavailable);
    }
    Ok(path)
}

/// Deterministic systemd drop-in (`10-rustiron-app.conf`) for `rustiron-app@<account>.service`.
pub(crate) fn render_app_dropin(
    root: &Path,
    facts: &AppFacts,
    runtime_bin: &str,
    level: &str,
) -> String {
    let root_str = root.to_string_lossy();
    let env_arg = runtime_env_arg(facts.runtime, root);
    format!(
        "# Managed by Rustiron (D-099, C-01); do not edit by hand.\n\
         [Service]\n\
         SELinuxContext=system_u:system_r:rustiron_app_t:{level}\n\
         Environment=PORT={port} HOST=127.0.0.1 NODE_ENV=production TMPDIR={root_str}/tmp RUSTIRON_APP_DATA={root_str}/data\n\
         MemoryMax={mem}M\n\
         TasksMax={tasks}\n\
         ExecStart=\n\
         ExecStart={runtime_bin} {env_arg} {root_str}/current/{entry}\n",
        port = facts.port,
        mem = facts.memory_max_mib,
        tasks = facts.tasks_max,
        entry = facts.entrypoint,
    )
}

/// Deterministic systemd drop-in (`10-rustiron-app.conf`) for `rustiron-app-worker@<account>.service`.
pub(crate) fn render_worker_dropin(
    root: &Path,
    facts: &AppFacts,
    worker_entrypoint: &str,
    runtime_bin: &str,
    level: &str,
) -> String {
    let root_str = root.to_string_lossy();
    let env_arg = runtime_env_arg(facts.runtime, root);
    format!(
        "# Managed by Rustiron (D-099, C-01); do not edit by hand.\n\
         [Service]\n\
         SELinuxContext=system_u:system_r:rustiron_app_t:{level}\n\
         Environment=NODE_ENV=production TMPDIR={root_str}/tmp RUSTIRON_APP_DATA={root_str}/data\n\
         MemoryMax={mem}M\n\
         TasksMax={tasks}\n\
         ExecStart=\n\
         ExecStart={runtime_bin} {env_arg} {root_str}/current/{worker_entrypoint}\n",
        mem = facts.memory_max_mib,
        tasks = facts.tasks_max,
    )
}

/// Writes `content` to `<dropin_dir>/10-rustiron-app.conf` with mode `0644`.
fn write_dropin(prefix: &str, account: &str, content: &str) -> Result<(), ExecutorError> {
    let dir = PathBuf::from(format!("{prefix}{account}.service.d"));
    fs::create_dir_all(&dir).map_err(|_| ExecutorError::StepFailed)?;
    let path = dir.join("10-rustiron-app.conf");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(&path)
        .map_err(|_| ExecutorError::StepFailed)?;
    file.write_all(content.as_bytes())
        .map_err(|_| ExecutorError::StepFailed)?;
    file.sync_all().map_err(|_| ExecutorError::StepFailed)
}

/// Runs the `Recipe` or `Verify` step of an `app_provision`.
pub(crate) fn run_provision_step(
    step: ProvisionStep,
    layout: &SiteLayout,
    facts: &AppFacts,
) -> Result<(), ExecutorError> {
    match step {
        ProvisionStep::Recipe => {
            provision::write_site_marker(layout)?;
            crate::certificate::prepare_webroot(&layout.account)?;
            let passwd = provision::read_etc("passwd")?;
            let uid = provision::account_uid(&passwd, &layout.account)
                .ok_or(ExecutorError::StepFailed)?;
            for sub in ["releases", "data"] {
                let dir = layout.root.join(sub);
                fs::create_dir_all(&dir).map_err(|_| ExecutorError::StepFailed)?;
                rustix::fs::chown(
                    &dir,
                    Some(rustix::process::Uid::from_raw(uid)),
                    Some(rustix::process::Gid::from_raw(uid)),
                )
                .map_err(|_| ExecutorError::StepFailed)?;
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o750))
                    .map_err(|_| ExecutorError::StepFailed)?;
            }
            let env_path = layout.root.join("private").join("app.env");
            if !env_path.exists() {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o400)
                    .open(&env_path)
                    .map_err(|_| ExecutorError::StepFailed)?;
                file.write_all(
                    b"# Rustiron app runtime environment (0400, secrets never in plans)\n",
                )
                .map_err(|_| ExecutorError::StepFailed)?;
                rustix::fs::chown(
                    &env_path,
                    Some(rustix::process::Uid::from_raw(uid)),
                    Some(rustix::process::Gid::from_raw(uid)),
                )
                .map_err(|_| ExecutorError::StepFailed)?;
            }
            let level = crate::capture::site_level(layout)?;
            let root_str = layout.root.to_string_lossy();
            let data_pattern = format!("{root_str}/data(/.*)?");
            let data_dir = layout.root.join("data");
            let data_str = data_dir.to_string_lossy();
            // W640 (C-01): label app data/ as httpd_sys_rw_content_t at the site's
            // MCS level so rustiron_app_t:s0:c<N> writes only its own data/ and tmp/.
            let existing = provision::output("/usr/sbin/semanage", &["fcontext", "--list", "-C"])?;
            if !existing.contains(&data_pattern) {
                provision::run(
                    "/usr/sbin/semanage",
                    &[
                        "fcontext",
                        "--add",
                        "--type",
                        "httpd_sys_rw_content_t",
                        "--range",
                        &level,
                        "--",
                        &data_pattern,
                    ],
                )?;
            }
            provision::run("/usr/sbin/restorecon", &["-R", "--", &data_str])?;
            let bin = runtime_binary(facts.runtime);
            let dropin = render_app_dropin(&layout.root, facts, bin, &level);
            write_dropin(
                crate::layout::SITE_APP_UNIT_PREFIX,
                &layout.account,
                &dropin,
            )?;
            if let Some(worker) = facts.worker_entrypoint.as_deref() {
                let worker_dropin = render_worker_dropin(&layout.root, facts, worker, bin, &level);
                write_dropin(
                    crate::layout::SITE_APP_WORKER_UNIT_PREFIX,
                    &layout.account,
                    &worker_dropin,
                )?;
            }
            provision::output("/usr/bin/systemctl", &["daemon-reload"]).map(drop)
        }
        ProvisionStep::Verify => {
            crate::proxy_site::run_step(ProvisionStep::Verify, layout)?;
            let dropin = PathBuf::from(format!(
                "{}{}.service.d/10-rustiron-app.conf",
                crate::layout::SITE_APP_UNIT_PREFIX,
                layout.account
            ));
            if !dropin.is_file()
                || !layout.root.join("releases").is_dir()
                || !layout.root.join("data").is_dir()
            {
                return Err(ExecutorError::StepFailed);
            }
            Ok(())
        }
        _ => Err(ExecutorError::BindingDenied),
    }
}

/// Parsed, validated sorted per-file manifest (`<sha256>  <relative-path>`).
pub(crate) fn parse_manifest(text: &str) -> Result<BTreeMap<String, String>, ExecutorError> {
    let mut entries = BTreeMap::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let Some((digest, path)) = line.split_once("  ") else {
            return Err(ExecutorError::PreconditionChanged);
        };
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !valid_manifest_path(path)
        {
            return Err(ExecutorError::PreconditionChanged);
        }
        if entries.insert(path.to_owned(), digest.to_owned()).is_some() {
            return Err(ExecutorError::PreconditionChanged);
        }
        if entries.len() as u64 > MAX_APP_RELEASE_FILES {
            return Err(ExecutorError::PreconditionChanged);
        }
    }
    if entries.is_empty() {
        return Err(ExecutorError::PreconditionChanged);
    }
    Ok(entries)
}

/// Checks that every declared key in `required_keys` appears as a `KEY=...`
/// assignment in `env_path`, without retaining or logging any secret value.
pub(crate) fn verify_env_keys_present(
    env_path: &Path,
    required_keys: &[String],
) -> Result<(), ExecutorError> {
    if required_keys.is_empty() {
        return Ok(());
    }
    let meta = fs::symlink_metadata(env_path).map_err(|_| ExecutorError::PreconditionChanged)?;
    if !meta.is_file() || meta.len() > MAX_ENV_FILE_BYTES || meta.mode() & 0o077 != 0 {
        return Err(ExecutorError::PreconditionChanged);
    }
    let mut text = String::new();
    File::open(env_path)
        .map_err(|_| ExecutorError::PreconditionChanged)?
        .take(MAX_ENV_FILE_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|_| ExecutorError::PreconditionChanged)?;
    let mut present = BTreeSet::new();
    for raw_line in text.lines() {
        let trimmed = raw_line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((key, _value)) = trimmed.split_once('=') {
            present.insert(key.trim().to_owned());
        }
    }
    if required_keys.iter().all(|key| present.contains(key)) {
        Ok(())
    } else {
        Err(ExecutorError::PreconditionChanged)
    }
}

/// W633 (H-21 / M-26): opens `path` without following symlinks and without
/// blocking on FIFOs, then verifies `fstat` invariants on the open descriptor
/// so callers never face a check-then-open TOCTOU race.
fn open_regular_nofollow(
    path: &Path,
    expected_uid: Option<u32>,
    require_single_link: bool,
) -> Result<(File, fs::Metadata), ExecutorError> {
    use rustix::fs::{Mode, OFlags, open};

    let fd = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ExecutorError::PreconditionChanged)?;
    let file = File::from(fd);
    let meta = file
        .metadata()
        .map_err(|_| ExecutorError::PreconditionChanged)?;
    if !meta.is_file() {
        return Err(ExecutorError::PreconditionChanged);
    }
    if require_single_link && meta.nlink() != 1 {
        return Err(ExecutorError::PreconditionChanged);
    }
    if let Some(uid) = expected_uid
        && meta.uid() != uid
    {
        return Err(ExecutorError::PreconditionChanged);
    }
    Ok((file, meta))
}

fn copy_verified_file(
    src_file: &mut File,
    dst: &Path,
    mode: u32,
    chown_uid: Option<u32>,
) -> Result<(), ExecutorError> {
    use rustix::fs::{OFlags, fchown};

    let mut dst_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(dst)
        .map_err(|_| ExecutorError::StepFailed)?;
    std::io::copy(src_file, &mut dst_file).map_err(|_| ExecutorError::StepFailed)?;
    dst_file.sync_all().map_err(|_| ExecutorError::StepFailed)?;
    if let Some(uid) = chown_uid {
        fchown(
            &dst_file,
            Some(rustix::process::Uid::from_raw(uid)),
            Some(rustix::process::Gid::from_raw(uid)),
        )
        .map_err(|_| ExecutorError::StepFailed)?;
    }
    Ok(())
}

/// W633 (H-21): snapshots site-owned SQLite databases from `data_dir` into a
/// root-only `0700` `snap_dir` using `O_NOFOLLOW|O_NONBLOCK` + `fstat` checks.
/// Refuses any symlink, FIFO, hardlink, or foreign-owned file matching a DB name.
fn snapshot_sqlite_for_migration(
    data_dir: &Path,
    snap_dir: &Path,
    site_uid: u32,
) -> Result<(), ExecutorError> {
    fs::create_dir_all(snap_dir).map_err(|_| ExecutorError::StepFailed)?;
    fs::set_permissions(snap_dir, fs::Permissions::from_mode(0o700))
        .map_err(|_| ExecutorError::StepFailed)?;
    let Ok(read) = fs::read_dir(data_dir) else {
        return Ok(());
    };
    for entry in read {
        let entry = entry.map_err(|_| ExecutorError::StepFailed)?;
        let path = entry.path();
        let is_db_name = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| matches!(e, "sqlite" | "sqlite3" | "db"));
        if !is_db_name {
            continue;
        }
        let Some(name) = path.file_name() else {
            continue;
        };
        let (mut src_file, _) = open_regular_nofollow(&path, Some(site_uid), true)
            .map_err(|_| ExecutorError::StepFailed)?;
        let dst = snap_dir.join(name);
        let _ = fs::remove_file(&dst);
        copy_verified_file(&mut src_file, &dst, 0o600, None)?;

        let wal = PathBuf::from(format!("{}-wal", path.display()));
        if fs::symlink_metadata(&wal).is_ok()
            && let Some(wname) = wal.file_name()
        {
            let (mut wal_file, _) = open_regular_nofollow(&wal, Some(site_uid), true)
                .map_err(|_| ExecutorError::StepFailed)?;
            let wal_dst = snap_dir.join(wname);
            let _ = fs::remove_file(&wal_dst);
            copy_verified_file(&mut wal_file, &wal_dst, 0o600, None)?;
        }
    }
    Ok(())
}

/// W633 (H-21): restores a root-owned pre-migration SQLite snapshot back into
/// `data_dir` via `O_NOFOLLOW` temp staging, `fchown`, and atomic rename so
/// site-planted symlinks in `data_dir` are never followed.
fn restore_sqlite_snapshot(
    snap_dir: &Path,
    data_dir: &Path,
    chown_uid: Option<u32>,
) -> Result<(), ExecutorError> {
    let Ok(snap_meta) = fs::symlink_metadata(snap_dir) else {
        return Ok(());
    };
    if !snap_meta.is_dir() {
        return Err(ExecutorError::StepFailed);
    }
    let read = fs::read_dir(snap_dir).map_err(|_| ExecutorError::StepFailed)?;
    let mut saved = Vec::new();
    for entry in read {
        let entry = entry.map_err(|_| ExecutorError::StepFailed)?;
        let src = entry.path();
        let meta = fs::symlink_metadata(&src).map_err(|_| ExecutorError::StepFailed)?;
        if !meta.is_file() {
            return Err(ExecutorError::StepFailed);
        }
        if let Some(name) = src.file_name().map(std::ffi::OsStr::to_os_string) {
            saved.push((src, name));
        }
    }
    // Clear stale -wal/-shm sidecars for every snapshotted DB first.
    for (_, name) in &saved {
        let name_s = name.to_string_lossy();
        if !name_s.ends_with("-wal") {
            let base = data_dir.join(name);
            let _ = fs::remove_file(format!("{}-wal", base.display()));
            let _ = fs::remove_file(format!("{}-shm", base.display()));
        }
    }
    for (src, name) in &saved {
        let (mut src_file, _) =
            open_regular_nofollow(src, None, true).map_err(|_| ExecutorError::StepFailed)?;
        let tmp_dst = data_dir.join(format!(".rustiron-restore-{}.tmp", name.to_string_lossy()));
        let _ = fs::remove_file(&tmp_dst);
        copy_verified_file(&mut src_file, &tmp_dst, 0o600, chown_uid)?;
        let dst = data_dir.join(name);
        fs::rename(&tmp_dst, &dst).map_err(|_| {
            let _ = fs::remove_file(&tmp_dst);
            ExecutorError::StepFailed
        })?;
    }
    Ok(())
}

fn sha256_file(path: &Path, max_bytes: u64) -> Result<(String, u64), ExecutorError> {
    let (mut file, meta) = open_regular_nofollow(path, None, false)?;
    if meta.len() > max_bytes {
        return Err(ExecutorError::PreconditionChanged);
    }
    let mut hasher = Sha256::new();
    let mut buf = [0_u8; 16384];
    let mut total = 0_u64;
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|_| ExecutorError::PreconditionChanged)?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n as u64);
        if total > max_bytes {
            return Err(ExecutorError::PreconditionChanged);
        }
        hasher.update(&buf[..n]);
    }
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok((digest, total))
}

/// Verifies the intake archive and manifest SHA-256 digests and `app.env` keys
/// before committing or executing an `app_deploy`.
pub(crate) fn verify_intake(
    intake_root: &Path,
    release: &AppRelease,
    facts: &AppFacts,
    site_root: &Path,
) -> Result<(PathBuf, BTreeMap<String, String>), ExecutorError> {
    let dir = intake_root
        .join(release.site_id.as_str())
        .join(&release.release_id);
    let bundle = dir.join("bundle.tar.gz");
    let manifest_path = dir.join("manifest.sha256");
    let (bundle_sha, _) = sha256_file(&bundle, MAX_APP_RELEASE_BYTES)?;
    if bundle_sha != release.artifact_sha256.as_str() {
        return Err(ExecutorError::PreconditionChanged);
    }
    let (manifest_sha, _) = sha256_file(&manifest_path, MAX_MANIFEST_BYTES)?;
    if manifest_sha != release.manifest_sha256.as_str() {
        return Err(ExecutorError::PreconditionChanged);
    }
    let manifest_text =
        fs::read_to_string(&manifest_path).map_err(|_| ExecutorError::PreconditionChanged)?;
    let entries = parse_manifest(&manifest_text)?;
    if entries.len() as u64 != release.file_count {
        return Err(ExecutorError::PreconditionChanged);
    }
    if !entries.contains_key(&facts.entrypoint) {
        return Err(ExecutorError::PreconditionChanged);
    }
    if let Some(worker) = facts.worker_entrypoint.as_deref()
        && !entries.contains_key(worker)
    {
        return Err(ExecutorError::PreconditionChanged);
    }
    if let Some(migration) = release.migration_entrypoint.as_deref()
        && !entries.contains_key(migration)
    {
        return Err(ExecutorError::PreconditionChanged);
    }
    verify_env_keys_present(&site_root.join("private").join("app.env"), &facts.env_keys)?;
    Ok((bundle, entries))
}

/// Parses an HTTP/1.x status line and accepts only `2xx` or `3xx`.
#[cfg(test)]
pub(crate) fn health_status_ok(response: &str) -> bool {
    let Some(first) = response.lines().next() else {
        return false;
    };
    let mut parts = first.split_whitespace();
    let Some(version) = parts.next() else {
        return false;
    };
    let Some(code) = parts.next().and_then(|c| c.parse::<u16>().ok()) else {
        return false;
    };
    version.starts_with("HTTP/1.") && (200..400).contains(&code)
}

/// Bounded HTTP health probe against `127.0.0.1:<port><health_path>` executed
/// inside a confined transient unit as `account` with `IPAddressDeny=any` and
/// `IPAddressAllow=127.0.0.1/32` (W599-F3). This keeps `rustiron_admin_t`
/// free of `unreserved_port_t` outbound TCP connect permissions.
pub(crate) fn probe_loopback_http(
    account: &str,
    port: u16,
    health_path: &str,
) -> Result<(), ExecutorError> {
    let url = format!("http://127.0.0.1:{port}{health_path}");
    let user_prop = format!("--property=User={account}");
    let group_prop = format!("--property=Group={account}");
    let args: [&str; 17] = [
        "--wait",
        "--quiet",
        "--collect",
        &user_prop,
        &group_prop,
        "--property=NoNewPrivileges=yes",
        "--property=ProtectSystem=strict",
        "--property=ProtectHome=yes",
        "--property=PrivateTmp=yes",
        "--property=PrivateDevices=yes",
        "--property=CapabilityBoundingSet=",
        "--property=RestrictSUIDSGID=yes",
        "--property=IPAddressDeny=any",
        "--property=IPAddressAllow=127.0.0.1/32",
        "--property=RuntimeMaxSec=10",
        "--",
        "/usr/bin/curl",
    ];
    let mut full: Vec<&str> = args.to_vec();
    full.extend(["-fsS", "--max-time", "2", "-o", "/dev/null", &url]);
    for attempt in 0..HEALTH_PROBE_ATTEMPTS {
        if provision::output("/usr/bin/systemd-run", &full).is_ok() {
            return Ok(());
        }
        if attempt + 1 < HEALTH_PROBE_ATTEMPTS {
            thread::sleep(HEALTH_PROBE_PAUSE);
        }
    }
    Err(ExecutorError::StepFailed)
}

/// Runs one confined command as `account` with zero network access via `systemd-run`,
/// optionally entering a dedicated SELinux MCS context (`domain:level`).
fn run_confined_as_site(
    account: &str,
    selinux_context: Option<&str>,
    rw_paths: &[&str],
    env: &[(&str, &str)],
    memory_mib: u64,
    tasks_max: u64,
    argv: &[&str],
) -> Result<(), ExecutorError> {
    let mut args: Vec<String> = vec![
        "--wait".to_owned(),
        "--quiet".to_owned(),
        "--collect".to_owned(),
        format!("--property=User={account}"),
        format!("--property=Group={account}"),
        "--property=NoNewPrivileges=yes".to_owned(),
        "--property=ProtectSystem=strict".to_owned(),
        "--property=ProtectHome=yes".to_owned(),
        "--property=PrivateTmp=yes".to_owned(),
        "--property=PrivateDevices=yes".to_owned(),
        "--property=PrivateNetwork=yes".to_owned(),
        "--property=CapabilityBoundingSet=".to_owned(),
        "--property=RestrictSUIDSGID=yes".to_owned(),
        "--property=RuntimeMaxSec=120".to_owned(),
        format!("--property=MemoryMax={memory_mib}M"),
        format!("--property=TasksMax={tasks_max}"),
    ];
    if let Some(ctx) = selinux_context {
        args.push(format!("--property=SELinuxContext={ctx}"));
    }
    for path in rw_paths {
        args.push(format!("--property=ReadWritePaths={path}"));
    }
    for (k, v) in env {
        args.push(format!("--property=Environment={k}={v}"));
    }
    args.push("--".to_owned());
    args.extend(argv.iter().map(|s| (*s).to_owned()));
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    provision::output("/usr/bin/systemd-run", &refs).map(drop)
}

/// Walks `dir` verifying every unpacked file is regular, has no setuid/setgid,
/// matches `expected` SHA-256 and counts, and returns total unpacked bytes.
pub(crate) fn verify_unpacked_tree(
    dir: &Path,
    expected: &BTreeMap<String, String>,
    expected_bytes: u64,
) -> Result<(), ExecutorError> {
    let mut seen = BTreeMap::new();
    let mut total_bytes = 0_u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in fs::read_dir(&current).map_err(|_| ExecutorError::StepFailed)? {
            let entry = entry.map_err(|_| ExecutorError::StepFailed)?;
            let path = entry.path();
            let meta = fs::symlink_metadata(&path).map_err(|_| ExecutorError::StepFailed)?;
            if meta.mode() & 0o6000 != 0 {
                return Err(ExecutorError::StepFailed);
            }
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file() {
                if meta.nlink() != 1 {
                    return Err(ExecutorError::StepFailed);
                }
                let rel = path
                    .strip_prefix(dir)
                    .map_err(|_| ExecutorError::StepFailed)?
                    .to_string_lossy()
                    .into_owned();
                let (digest, size) = sha256_file(&path, MAX_APP_RELEASE_BYTES)?;
                total_bytes = total_bytes.saturating_add(size);
                seen.insert(rel, digest);
            } else {
                // Symlinks, FIFOs, sockets, and device nodes are refused.
                return Err(ExecutorError::StepFailed);
            }
        }
    }
    if seen != *expected || total_bytes != expected_bytes {
        return Err(ExecutorError::StepFailed);
    }
    Ok(())
}

fn switch_current_symlink(root: &Path, target: Option<&str>) -> Result<(), ExecutorError> {
    let current = root.join("current");
    match target {
        Some(release_id) => {
            let tmp = root.join(".current.next");
            let _ = fs::remove_file(&tmp);
            symlink(format!("releases/{release_id}"), &tmp)
                .map_err(|_| ExecutorError::StepFailed)?;
            fs::rename(&tmp, &current).map_err(|_| ExecutorError::StepFailed)
        }
        None => match fs::remove_file(&current) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(ExecutorError::StepFailed),
        },
    }
}

/// Runs one journaled step of an open `app_deploy`.
pub(crate) fn run_deploy_step(
    step: AppReleaseStep,
    layout: &SiteLayout,
    facts: &AppFacts,
    release: &AppRelease,
    previous_release_id: Option<&str>,
) -> Result<(), ExecutorError> {
    let release_dir = layout.root.join("releases").join(&release.release_id);
    let release_str = release_dir.to_string_lossy().into_owned();
    let data_dir = layout.root.join("data");
    let data_str = data_dir.to_string_lossy().into_owned();
    let tmp_dir = layout.root.join("tmp");
    let tmp_str = tmp_dir.to_string_lossy().into_owned();
    let app_unit = format!("rustiron-app@{}.service", layout.account);
    let worker_unit = format!("rustiron-app-worker@{}.service", layout.account);
    match step {
        AppReleaseStep::Unpack => {
            let (bundle, entries) = verify_intake(
                Path::new(crate::layout::APP_INTAKE_DIR),
                release,
                facts,
                &layout.root,
            )?;
            let passwd = provision::read_etc("passwd")?;
            let uid = provision::account_uid(&passwd, &layout.account)
                .ok_or(ExecutorError::StepFailed)?;
            if release_dir.exists() {
                return Err(ExecutorError::PreconditionChanged);
            }
            fs::create_dir(&release_dir).map_err(|_| ExecutorError::StepFailed)?;
            rustix::fs::chown(
                &release_dir,
                Some(rustix::process::Uid::from_raw(uid)),
                Some(rustix::process::Gid::from_raw(uid)),
            )
            .map_err(|_| ExecutorError::StepFailed)?;
            let staged_bundle = tmp_dir.join(format!("bundle-{}.tar.gz", release.release_id));
            fs::copy(&bundle, &staged_bundle).map_err(|_| ExecutorError::StepFailed)?;
            rustix::fs::chown(
                &staged_bundle,
                Some(rustix::process::Uid::from_raw(uid)),
                Some(rustix::process::Gid::from_raw(uid)),
            )
            .map_err(|_| ExecutorError::StepFailed)?;
            let level = crate::capture::site_level(layout)?;
            let unpack_ctx = format!("system_u:system_r:rustiron_unpack_t:{level}");
            let staged_str = staged_bundle.to_string_lossy().into_owned();
            let unpack_res = run_confined_as_site(
                &layout.account,
                Some(&unpack_ctx),
                &[&release_str, &tmp_str],
                &[],
                facts.memory_max_mib,
                facts.tasks_max,
                &[
                    "/usr/bin/tar",
                    "-xzf",
                    &staged_str,
                    "-C",
                    &release_str,
                    "--no-same-owner",
                    "--no-same-permissions",
                ],
            );
            let _ = fs::remove_file(&staged_bundle);
            unpack_res?;
            verify_unpacked_tree(&release_dir, &entries, release.total_bytes)?;
            provision::output("/usr/bin/chmod", &["-R", "a-w", "--", &release_str]).map(drop)
        }
        AppReleaseStep::Migrate => {
            let migration = release
                .migration_entrypoint
                .as_deref()
                .ok_or(ExecutorError::BindingDenied)?;
            let bin = verify_runtime_binary(release.runtime)?;
            let env_arg = runtime_env_arg(release.runtime, &layout.root);
            let snap_dir = tmp_dir.join(format!("pre-migrate-{}", release.release_id));
            let passwd = provision::read_etc("passwd")?;
            let uid = provision::account_uid(&passwd, &layout.account)
                .ok_or(ExecutorError::StepFailed)?;
            // W603-F4: stop the running app before pre-migration SQLite copy so
            // WAL frames flush cleanly and rollback restores exact pre-migration state.
            let _ = provision::output("/usr/bin/systemctl", &["stop", "--", &app_unit]);
            if facts.worker_entrypoint.is_some() {
                let _ = provision::output("/usr/bin/systemctl", &["stop", "--", &worker_unit]);
            }
            // W633 (H-21): keep snapshot dir root-owned (0700) and copy only verified
            // site-owned single-link regular DB files via O_NOFOLLOW|O_NONBLOCK.
            snapshot_sqlite_for_migration(&data_dir, &snap_dir, uid)?;
            let level = crate::capture::site_level(layout)?;
            let app_ctx = format!("system_u:system_r:rustiron_app_t:{level}");
            let root_str = layout.root.to_string_lossy().into_owned();
            let script_path = release_dir.join(migration).to_string_lossy().into_owned();
            run_confined_as_site(
                &layout.account,
                Some(&app_ctx),
                &[&data_str, &tmp_str],
                &[
                    ("RUSTIRON_APP_DATA", &data_str),
                    ("RUSTIRON_APP_ROOT", &root_str),
                    ("RUSTIRON_SITE_ACCOUNT", &layout.account),
                ],
                facts.memory_max_mib,
                facts.tasks_max,
                &[bin, &env_arg, &script_path],
            )
        }
        AppReleaseStep::Activate => {
            let bin = verify_runtime_binary(release.runtime)?;
            let level = crate::capture::site_level(layout)?;
            let dropin = render_app_dropin(&layout.root, facts, bin, &level);
            write_dropin(
                crate::layout::SITE_APP_UNIT_PREFIX,
                &layout.account,
                &dropin,
            )?;
            if let Some(worker) = facts.worker_entrypoint.as_deref() {
                let worker_dropin = render_worker_dropin(&layout.root, facts, worker, bin, &level);
                write_dropin(
                    crate::layout::SITE_APP_WORKER_UNIT_PREFIX,
                    &layout.account,
                    &worker_dropin,
                )?;
            }
            provision::run("/usr/sbin/restorecon", &["-R", "--", &data_str])?;
            provision::output("/usr/bin/systemctl", &["daemon-reload"])?;
            switch_current_symlink(&layout.root, Some(&release.release_id))?;
            provision::output("/usr/bin/systemctl", &["enable", "--", &app_unit])?;
            provision::output("/usr/bin/systemctl", &["restart", "--", &app_unit])?;
            if facts.worker_entrypoint.is_some() {
                provision::output("/usr/bin/systemctl", &["enable", "--", &worker_unit])?;
                provision::output("/usr/bin/systemctl", &["restart", "--", &worker_unit])?;
            }
            Ok(())
        }
        AppReleaseStep::Health => {
            let state = provision::output("/usr/bin/systemctl", &["is-active", "--", &app_unit])?;
            if state.trim() != "active" {
                return Err(ExecutorError::StepFailed);
            }
            if facts.worker_entrypoint.is_some() {
                let wstate =
                    provision::output("/usr/bin/systemctl", &["is-active", "--", &worker_unit])?;
                if wstate.trim() != "active" {
                    return Err(ExecutorError::StepFailed);
                }
            }
            probe_loopback_http(&layout.account, facts.port, &release.health_path)
        }
        AppReleaseStep::Rollback => {
            switch_current_symlink(&layout.root, previous_release_id)?;
            if release.migration_entrypoint.is_some() {
                let snap_dir = tmp_dir.join(format!("pre-migrate-{}", release.release_id));
                let passwd = provision::read_etc("passwd")?;
                let uid = provision::account_uid(&passwd, &layout.account)
                    .ok_or(ExecutorError::StepFailed)?;
                restore_sqlite_snapshot(&snap_dir, &data_dir, Some(uid))?;
                provision::run("/usr/sbin/restorecon", &["-R", "--", &data_str])?;
            }
            if previous_release_id.is_some() {
                provision::output("/usr/bin/systemctl", &["restart", "--", &app_unit])?;
                if facts.worker_entrypoint.is_some() {
                    provision::output("/usr/bin/systemctl", &["restart", "--", &worker_unit])?;
                }
                probe_loopback_http(&layout.account, facts.port, &facts.health_path)
            } else {
                let _ = provision::output("/usr/bin/systemctl", &["stop", "--", &app_unit]);
                if facts.worker_entrypoint.is_some() {
                    let _ = provision::output("/usr/bin/systemctl", &["stop", "--", &worker_unit]);
                }
                Ok(())
            }
        }
    }
}

/// Runs a signed `start`, `stop`, or `restart` on the app's systemd unit(s).
pub(crate) fn run_lifecycle(
    account: &str,
    has_worker: bool,
    action: AppLifecycleAction,
) -> Result<(), ExecutorError> {
    let verb = action.as_str();
    let app_unit = format!("rustiron-app@{account}.service");
    provision::output("/usr/bin/systemctl", &[verb, "--", &app_unit])?;
    if has_worker {
        let worker_unit = format!("rustiron-app-worker@{account}.service");
        provision::output("/usr/bin/systemctl", &[verb, "--", &worker_unit])?;
    }
    Ok(())
}

// ============================================================================
// W601 (D-096 / P30): App-data consistent SQLite online backup, marker, freeze,
// and verified restore helpers.
// ============================================================================

/// Consistent SQLite online-backup tar path inside `<site>/tmp`.
pub(crate) fn app_bundle_path(root: &str) -> String {
    format!("{root}/tmp/{}", crate::layout::APP_SQLITE_BUNDLE_FILE)
}

/// Removes the temporary SQLite online-backup bundle after snapshot+check,
/// matching [`crate::capture::remove_dump`] semantics.
pub(crate) fn remove_app_bundle(layout: &SiteLayout) -> Result<(), ExecutorError> {
    let path = layout
        .root
        .join("tmp")
        .join(crate::layout::APP_SQLITE_BUNDLE_FILE);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(ExecutorError::StepFailed),
    }
}

/// Fixed Python 3 script run as `rs_<site>` during app `site_restore` to
/// verify `manifest.json` SHA-256 digests, refuse path traversal/symlinks,
/// remove stale `-wal`/`-shm` sidecars, and place consistent SQLite DBs into
/// the target `data/` directory.
const SQLITE_RESTORE_PY: &str = r#"
import hashlib, json, os, pathlib, sys, tarfile

bundle = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
if not bundle.is_file() or bundle.is_symlink() or not target.is_dir() or target.is_symlink():
    sys.exit(2)

def safe_rel(rel: str) -> pathlib.Path:
    p = pathlib.Path(rel)
    if p.is_absolute() or not p.parts or any(part in ("", ".", "..") for part in p.parts):
        raise ValueError("unsafe path")
    return p

with tarfile.open(bundle, "r") as tf:
    names = tf.getnames()
    if "manifest.json" not in names:
        sys.exit(2)
    m = json.loads(tf.extractfile("manifest.json").read().decode())
    if m.get("schema_version") != 1 or not isinstance(m.get("databases"), list):
        sys.exit(2)
    for item in m["databases"]:
        rel = safe_rel(item["path"])
        member = tf.getmember(f"dbs/{rel.as_posix()}")
        if not member.isfile():
            sys.exit(2)
        raw = tf.extractfile(member).read()
        if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            sys.exit(2)
        dst = target / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        for suffix in ("-wal", "-shm"):
            side = pathlib.Path(str(dst) + suffix)
            if side.exists() and not side.is_symlink():
                side.unlink()
        tmp = pathlib.Path(str(dst) + ".restore.tmp")
        tmp.write_bytes(raw)
        os.chmod(tmp, 0o600)
        os.replace(tmp, dst)
"#;

/// Confined command that creates `{root}/tmp/rustiron-app-sqlite.tar` via
/// SQLite Online Backup API as the site account (tested directly in unit tests;
/// live product captures invoke `capture-manifest app-sqlite-backup`).
#[cfg(test)]
pub(crate) fn sqlite_backup_command(root: &str) -> Vec<String> {
    vec![
        "/usr/bin/python3".to_owned(),
        "-I".to_owned(),
        "-c".to_owned(),
        crate::manifest::app_sqlite::SQLITE_BACKUP_PY.to_owned(),
        format!("{root}/data"),
        app_bundle_path(root),
    ]
}

/// Confined command that reads the SQLite consistency marker across `{root}/data`
/// (tested directly in unit tests; live product captures invoke
/// `capture-manifest app-sqlite-marker`).
#[cfg(test)]
pub(crate) fn sqlite_marker_command(root: &str) -> Vec<String> {
    vec![
        "/usr/bin/python3".to_owned(),
        "-I".to_owned(),
        "-c".to_owned(),
        crate::manifest::app_sqlite::SQLITE_MARKER_PY.to_owned(),
        format!("{root}/data"),
    ]
}

/// Confined command that verifies and restores SQLite databases from `bundle`
/// into `target_data_dir`.
pub(crate) fn sqlite_restore_command(bundle: &str, target_data_dir: &str) -> Vec<String> {
    vec![
        "/usr/bin/python3".to_owned(),
        "-I".to_owned(),
        "-c".to_owned(),
        SQLITE_RESTORE_PY.to_owned(),
        bundle.to_owned(),
        target_data_dir.to_owned(),
    ]
}

/// Confined app-data SQLite restore helper invoked during `site_restore` for
/// P27/EmDash apps.
pub(crate) fn restore_app_sqlite(
    layout: &SiteLayout,
    facts: &AppFacts,
    bundle: &Path,
    target_data_dir: &Path,
) -> Result<(), ExecutorError> {
    let level = crate::capture::site_level(layout)?;
    let app_ctx = format!("system_u:system_r:rustiron_app_t:{level}");
    let bundle_str = bundle.to_string_lossy().into_owned();
    let target_str = target_data_dir.to_string_lossy().into_owned();
    let tmp_str = layout.root.join("tmp").to_string_lossy().into_owned();
    let cmd = sqlite_restore_command(&bundle_str, &target_str);
    let refs: Vec<&str> = cmd.iter().map(String::as_str).collect();
    run_confined_as_site(
        &layout.account,
        Some(&app_ctx),
        &[&target_str, &tmp_str],
        &[],
        facts.memory_max_mib,
        facts.tasks_max,
        &refs,
    )
}

/// D-021 option A freeze for a P27/EmDash app site: arms a 10-second unfreeze
/// timer before stopping `rustiron-app@<acct>.service` (and companion worker).
pub(crate) struct AppFreeze {
    account: String,
    has_worker: bool,
    timer: String,
}

impl AppFreeze {
    pub(crate) fn new(account: &str, has_worker: bool) -> Result<Self, ExecutorError> {
        let mut random = [0_u8; 4];
        rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty())
            .map_err(|_| ExecutorError::Unavailable)?;
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        Ok(Self {
            account: account.to_owned(),
            has_worker,
            timer: format!("rustiron-app-unfreeze-{account}-{suffix}"),
        })
    }

    fn unit_names(&self) -> Vec<String> {
        let mut units = vec![format!("rustiron-app@{}.service", self.account)];
        if self.has_worker {
            units.push(format!("rustiron-app-worker@{}.service", self.account));
        }
        units
    }

    fn active_state(unit: &str) -> Option<String> {
        provision::output(
            "/usr/bin/systemctl",
            &["show", "--property=ActiveState", "--value", "--", unit],
        )
        .ok()
        .map(|s| s.trim().to_owned())
    }

    fn units_down(&self) -> bool {
        self.unit_names().iter().all(|u| {
            matches!(
                Self::active_state(u).as_deref(),
                Some("inactive" | "failed")
            )
        })
    }

    fn timer_waiting(&self) -> bool {
        Self::active_state(&format!("{}.timer", self.timer)).as_deref() == Some("active")
    }
}

impl crate::capture::Freeze for AppFreeze {
    fn arm(&mut self) -> Result<(), ExecutorError> {
        let mut args = vec![
            "--unit".to_owned(),
            self.timer.clone(),
            format!("--on-active={}", crate::capture::FREEZE_CAP_SECS),
            "--timer-property=AccuracySec=100ms".to_owned(),
            "--quiet".to_owned(),
            "--collect".to_owned(),
            "/usr/bin/systemctl".to_owned(),
            "start".to_owned(),
        ];
        args.extend(self.unit_names());
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        provision::run("/usr/bin/systemd-run", &refs)?;
        if self.timer_waiting() {
            Ok(())
        } else {
            Err(ExecutorError::StepFailed)
        }
    }

    fn stop(&mut self) -> Result<(), ExecutorError> {
        let units = self.unit_names();
        let mut args = vec!["stop", "--"];
        args.extend(units.iter().map(String::as_str));
        provision::run("/usr/bin/systemctl", &args)?;
        if self.units_down() {
            Ok(())
        } else {
            Err(ExecutorError::StepFailed)
        }
    }

    fn held(&mut self) -> bool {
        self.units_down() && self.timer_waiting()
    }

    fn thaw(&mut self) {
        let units = self.unit_names();
        let mut args = vec!["start", "--"];
        args.extend(units.iter().map(String::as_str));
        let _ = provision::run("/usr/bin/systemctl", &args);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustiron_contracts::approval::ProxyRoute;
    use rustiron_journal::ProxyFacts;

    fn sample_facts() -> AppFacts {
        AppFacts {
            runtime: AppRuntime::Node22V1,
            port: 43187,
            entrypoint: "dist/server/entry.mjs".to_owned(),
            worker_entrypoint: Some("dist/worker.mjs".to_owned()),
            health_path: "/health".to_owned(),
            env_keys: vec!["EMDASH_SITE_URL".to_owned()],
            memory_max_mib: 512,
            tasks_max: 64,
            quota_mib: 2048,
            routes: ProxyFacts {
                routes: vec![ProxyRoute {
                    prefix: "/".to_owned(),
                    port: 43187,
                }],
                websockets: Vec::new(),
            },
        }
    }

    #[test]
    fn dropin_renders_bound_port_limits_and_pinned_binary() {
        let facts = sample_facts();
        let root = Path::new("/srv/sites/rs_emdash1");
        let app = render_app_dropin(root, &facts, "/usr/bin/node", "s0:c233");
        assert!(app.contains("SELinuxContext=system_u:system_r:rustiron_app_t:s0:c233"));
        assert!(app.contains("PORT=43187 HOST=127.0.0.1 NODE_ENV=production"));
        assert!(app.contains("MemoryMax=512M"));
        assert!(app.contains("TasksMax=64"));
        assert!(app.contains(
            "ExecStart=/usr/bin/node --env-file-if-exists=/srv/sites/rs_emdash1/private/app.env /srv/sites/rs_emdash1/current/dist/server/entry.mjs"
        ));
        let worker =
            render_worker_dropin(root, &facts, "dist/worker.mjs", "/usr/bin/node", "s0:c233");
        assert!(worker.contains("SELinuxContext=system_u:system_r:rustiron_app_t:s0:c233"));
        assert!(!worker.contains("PORT="));
        assert!(worker.contains(
            "ExecStart=/usr/bin/node --env-file-if-exists=/srv/sites/rs_emdash1/private/app.env /srv/sites/rs_emdash1/current/dist/worker.mjs"
        ));
        let mut bun_facts = sample_facts();
        bun_facts.runtime = AppRuntime::Bun1V1;
        let bun_app = render_app_dropin(root, &bun_facts, "/usr/local/bin/bun", "s0:c234");
        assert!(bun_app.contains("SELinuxContext=system_u:system_r:rustiron_app_t:s0:c234"));
        assert!(bun_app.contains(
            "ExecStart=/usr/local/bin/bun --env-file=/srv/sites/rs_emdash1/private/app.env /srv/sites/rs_emdash1/current/dist/server/entry.mjs"
        ));
    }

    #[test]
    fn manifest_and_env_key_checks_reject_traversal_and_world_readable_env() {
        let digest = "a".repeat(64);
        let ok = parse_manifest(&format!(
            "{digest}  dist/server.js\n{digest}  package.json\n"
        ))
        .unwrap();
        assert_eq!(ok.len(), 2);
        assert!(parse_manifest(&format!("{digest}  ../escape.js\n")).is_err());
        assert!(parse_manifest(&format!("{digest}  /abs/path.js\n")).is_err());
        assert!(parse_manifest("").is_err());

        let dir = std::env::temp_dir().join(format!("ri-app-env-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let env_file = dir.join("app.env");
        fs::write(
            &env_file,
            "# comment\nEMDASH_SITE_URL=https://example.test\n",
        )
        .unwrap();
        fs::set_permissions(&env_file, fs::Permissions::from_mode(0o644)).unwrap();
        // World-readable app.env is refused.
        assert!(verify_env_keys_present(&env_file, &["EMDASH_SITE_URL".to_owned()]).is_err());
        fs::set_permissions(&env_file, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(verify_env_keys_present(&env_file, &["EMDASH_SITE_URL".to_owned()]).is_ok());
        assert!(verify_env_keys_present(&env_file, &["MISSING_KEY".to_owned()]).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn health_probe_accepts_2xx_and_rejects_5xx() {
        assert!(health_status_ok("HTTP/1.1 200 OK\r\n\r\n"));
        assert!(health_status_ok("HTTP/1.1 302 Found\r\n\r\n"));
        assert!(!health_status_ok(
            "HTTP/1.1 500 Internal Server Error\r\n\r\n"
        ));
        assert!(!health_status_ok("NOT_HTTP\r\n"));
    }

    #[test]
    fn sqlite_online_backup_marker_and_restore_survive_wal_and_reject_tamper() {
        use std::process::Command;

        let base = std::env::temp_dir().join(format!("ri-app-sqlite-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let data = base.join("data");
        let tmp = base.join("tmp");
        let restored = base.join("restored");
        fs::create_dir_all(data.join("cms")).unwrap();
        fs::create_dir_all(&tmp).unwrap();
        fs::create_dir_all(&restored).unwrap();

        // Seed a WAL-mode FTS5 SQLite DB (EmDash D-096 shape) with uncommitted WAL frames.
        let db = data.join("cms").join("emdash.sqlite");
        let seed = Command::new("/usr/bin/python3")
            .args([
                "-I",
                "-c",
                "import sqlite3, sys; c=sqlite3.connect(sys.argv[1]); c.execute('PRAGMA journal_mode=WAL'); c.execute('CREATE VIRTUAL TABLE posts USING fts5(title, body)'); c.execute(\"INSERT INTO posts VALUES ('Hello EmDash', 'Rustiron P30')\"); c.commit(); c.close()",
                db.to_str().unwrap(),
            ])
            .status()
            .unwrap();
        assert!(seed.success());

        // Read marker before backup.
        let m1_cmd = sqlite_marker_command(base.to_str().unwrap());
        let m1 = Command::new(&m1_cmd[0])
            .args(&m1_cmd[1..])
            .output()
            .unwrap();
        assert!(m1.status.success());
        let marker1 = String::from_utf8(m1.stdout).unwrap();
        assert!(marker1.starts_with("cms/emdash.sqlite\t"));

        // Take atomic SQLite online backup bundle.
        let b_cmd = sqlite_backup_command(base.to_str().unwrap());
        let b_out = Command::new(&b_cmd[0]).args(&b_cmd[1..]).output().unwrap();
        assert!(
            b_out.status.success(),
            "backup stderr: {}",
            String::from_utf8_lossy(&b_out.stderr)
        );
        let bundle = PathBuf::from(app_bundle_path(base.to_str().unwrap()));
        assert!(bundle.is_file());

        // Marker unchanged while idle -> Matched.
        let m2 = Command::new(&m1_cmd[0])
            .args(&m1_cmd[1..])
            .output()
            .unwrap();
        assert_eq!(String::from_utf8(m2.stdout).unwrap(), marker1);

        // Restore into a clean directory and verify FTS5 row survived.
        let r_cmd = sqlite_restore_command(bundle.to_str().unwrap(), restored.to_str().unwrap());
        let r_out = Command::new(&r_cmd[0]).args(&r_cmd[1..]).output().unwrap();
        assert!(
            r_out.status.success(),
            "restore stderr: {}",
            String::from_utf8_lossy(&r_out.stderr)
        );
        let verify = Command::new("/usr/bin/python3")
            .args([
                "-I",
                "-c",
                "import sqlite3, sys; c=sqlite3.connect(sys.argv[1]); rows=c.execute(\"SELECT title FROM posts WHERE posts MATCH 'EmDash'\").fetchall(); assert rows == [('Hello EmDash',)], rows",
                restored.join("cms/emdash.sqlite").to_str().unwrap(),
            ])
            .status()
            .unwrap();
        assert!(verify.success());

        // Tamper a byte in the bundle -> SHA-256 verification must refuse restore.
        let mut bytes = fs::read(&bundle).unwrap();
        if let Some(pos) = bytes.windows(12).position(|w| w == b"Hello EmDash") {
            bytes[pos] = b'X';
        }
        fs::write(&bundle, &bytes).unwrap();
        let bad = Command::new(&r_cmd[0]).args(&r_cmd[1..]).output().unwrap();
        assert!(!bad.status.success(), "tampered sqlite bundle must fail");

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn w633_sha256_and_migration_snapshot_refuse_symlinks_hardlinks_and_fifos() {
        use std::process::Command;

        let base = std::env::temp_dir().join(format!("ri-w633-safe-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let data = base.join("data");
        let snap = base.join("snap");
        fs::create_dir_all(&data).unwrap();
        let secret = base.join("host-secret.txt");
        fs::write(&secret, b"SUPER_SECRET_CREDENTIAL").unwrap();

        // M-26: sha256_file refuses symlinks and FIFOs immediately (no hang).
        let link = base.join("link.bin");
        symlink(&secret, &link).unwrap();
        assert!(sha256_file(&link, 1024).is_err());

        let fifo = base.join("pipe.bin");
        let mk = Command::new("/usr/bin/mkfifo").arg(&fifo).status().unwrap();
        assert!(mk.success());
        assert!(sha256_file(&fifo, 1024).is_err());

        // H-21: migration snapshot refuses a site-planted symlink matching *.db.
        let my_uid = rustix::process::getuid().as_raw();
        let leak_db = data.join("leak.db");
        symlink(&secret, &leak_db).unwrap();
        assert!(snapshot_sqlite_for_migration(&data, &snap, my_uid).is_err());
        fs::remove_file(&leak_db).unwrap();

        // H-21: migration snapshot refuses a hardlink (nlink == 2) to a foreign file.
        let hard_db = data.join("hard.db");
        fs::hard_link(&secret, &hard_db).unwrap();
        assert!(snapshot_sqlite_for_migration(&data, &snap, my_uid).is_err());
        fs::remove_file(&hard_db).unwrap();

        // H-21: genuine single-link regular DB snapshots and restores cleanly,
        // and rollback overwrites a site-planted destination symlink atomically
        // without touching the symlink's target.
        let real_db = data.join("app.sqlite");
        fs::write(&real_db, b"good-v1-bytes").unwrap();
        snapshot_sqlite_for_migration(&data, &snap, my_uid).unwrap();
        fs::remove_file(&real_db).unwrap();
        symlink(&secret, &real_db).unwrap();
        restore_sqlite_snapshot(&snap, &data, None).unwrap();
        assert_eq!(fs::read(&real_db).unwrap(), b"good-v1-bytes");
        assert_eq!(fs::read(&secret).unwrap(), b"SUPER_SECRET_CREDENTIAL");

        let _ = fs::remove_dir_all(&base);
    }
}
