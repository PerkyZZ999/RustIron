//! W658 (D-102 Decision C2): PostgreSQL 18 (18.7+) per-site role/database
//! provisioning, SCRAM-SHA-256 credential management, `pg_dump`/`pg_restore`,
//! site deletion cleanup, and atomic `private/app.env` `DATABASE_URL` helpers.
//!
//! Security invariants:
//! - Every PostgreSQL role and database name is derived strictly from the
//!   journaled `rs_<site>` account identifier and re-validated before any SQL.
//! - Passwords NEVER enter plans, grants, journal rows, argv, logs, or
//!   `/proc/*/environ`. Administrative SQL flows over stdin to PGDG
//!   `/usr/pgsql-18/bin/psql` over the local Unix socket `/run/postgresql` via
//!   `runuser -u postgres` peer authentication. Dumps and restores connect as
//!   the site role instead (W662-F3, W666).
//! - Login and rejection verification write an RAII `0600` `.pgpass` file
//!   inside [`crate::layout::ADMIN_SOCKET`]'s parent directory and pass ONLY
//!   the file path in `PGPASSFILE` (never the password), unlinking it on drop.
//! - `private/app.env` updates use `O_NOFOLLOW`, `O_CREAT|O_EXCL`, mode
//!   `0400`, `fchown(uid, uid)`, `fsync`, and atomic `renameat`, preserving all
//!   non-`DATABASE_URL` user environment keys verbatim.

use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use rustiron_contracts::{Id, approval::AppDatabase};
use rustix::fs::{AtFlags, Mode, OFlags};

use crate::{
    ExecutorError, files,
    provision::{self, SiteLayout},
};

/// Fixed PGDG 18 `psql` binary path.
pub(crate) const PG_PSQL: &str = "/usr/pgsql-18/bin/psql";
/// Fixed PGDG 18 `pg_dump` binary path.
pub(crate) const PG_DUMP: &str = "/usr/pgsql-18/bin/pg_dump";
/// Fixed PGDG 18 `pg_restore` binary path.
pub(crate) const PG_RESTORE: &str = "/usr/pgsql-18/bin/pg_restore";
/// Fixed `runuser` binary used to run peer-authenticated `postgres` commands.
const RUNUSER: &str = "/usr/sbin/runuser";
/// Fixed PostgreSQL local Unix domain socket directory.
pub(crate) const PG_SOCKET_DIR: &str = "/run/postgresql";
/// Maximum size of a `private/app.env` file managed by Rustiron (64 KiB).
const MAX_APP_ENV_BYTES: u64 = 64 * 1024;

/// Validates that `account` is strictly a derived Rustiron site account
/// (`rs_` followed by lowercase ASCII alphanumerics or `_`, max 32 bytes).
pub(crate) fn valid_site_identifier(account: &str) -> bool {
    let Some(suffix) = account.strip_prefix("rs_") else {
        return false;
    };
    !suffix.is_empty()
        && account.len() <= 32
        && suffix
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Validates that a database password is safe for both SQL single-quoted
/// literals and `DATABASE_URL` authority sections (no quotes, backslashes,
/// delimiters, whitespace, control bytes, or URL metacharacters).
pub(crate) fn valid_app_db_password(secret: &str) -> bool {
    !secret.is_empty()
        && secret.len() <= 128
        && secret.bytes().all(|b| {
            b.is_ascii_graphic()
                && !matches!(
                    b,
                    b'\'' | b'\\' | b'"' | b'`' | b';' | b':' | b'@' | b'/' | b'?' | b'#' | b'%'
                )
        })
}

/// Formats the canonical loopback `DATABASE_URL` for a MariaDB or PostgreSQL 18
/// modern app site.
pub(crate) fn format_database_url(
    database: AppDatabase,
    account: &str,
    password: &str,
) -> Result<String, ExecutorError> {
    if !valid_site_identifier(account) || !valid_app_db_password(password) {
        return Err(ExecutorError::StepFailed);
    }
    match database {
        AppDatabase::Mariadb => Ok(format!(
            "mysql://{account}:{password}@127.0.0.1:3306/{account}"
        )),
        AppDatabase::Postgresql18 => Ok(format!(
            "postgresql://{account}:{password}@127.0.0.1:5432/{account}"
        )),
        AppDatabase::None | AppDatabase::Sqlite => Err(ExecutorError::BindingDenied),
    }
}

/// Strictly parses `DATABASE_URL=...` from `private/app.env` bytes for the
/// expected engine and account, returning the stored password.
pub(crate) fn parse_app_env_database_url(
    bytes: &[u8],
    expected_account: &str,
    database: AppDatabase,
) -> Result<String, ExecutorError> {
    if bytes.len() as u64 > MAX_APP_ENV_BYTES || !valid_site_identifier(expected_account) {
        return Err(ExecutorError::StepFailed);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ExecutorError::StepFailed)?;
    let (scheme, port) = match database {
        AppDatabase::Mariadb => ("mysql://", "3306"),
        AppDatabase::Postgresql18 => ("postgresql://", "5432"),
        AppDatabase::None | AppDatabase::Sqlite => return Err(ExecutorError::BindingDenied),
    };
    let mut found = None;
    for raw_line in text.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=')
            && key.trim() == "DATABASE_URL"
        {
            if found.is_some() {
                // Duplicate DATABASE_URL entries are refused fail-closed.
                return Err(ExecutorError::StepFailed);
            }
            found = Some(value.trim());
        }
    }
    let url = found.ok_or(ExecutorError::StepFailed)?;
    let prefix = format!("{scheme}{expected_account}:");
    let suffix = format!("@127.0.0.1:{port}/{expected_account}");
    let rest = url.strip_prefix(&prefix).ok_or(ExecutorError::StepFailed)?;
    let password = rest
        .strip_suffix(&suffix)
        .ok_or(ExecutorError::StepFailed)?;
    if !valid_app_db_password(password) {
        return Err(ExecutorError::StepFailed);
    }
    Ok(password.to_owned())
}

/// Rewrites `app.env` text replacing an existing `DATABASE_URL=...` line (or
/// appending one if absent), preserving every other comment and user variable.
pub(crate) fn upsert_database_url_text(
    existing: &str,
    database_url: &str,
) -> Result<String, ExecutorError> {
    let mut out = String::with_capacity(existing.len() + database_url.len() + 32);
    let mut replaced = false;
    for line in existing.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with('#')
            && let Some((key, _)) = trimmed.split_once('=')
            && key.trim() == "DATABASE_URL"
        {
            if replaced {
                // Duplicate DATABASE_URL entries are refused fail-closed.
                return Err(ExecutorError::StepFailed);
            }
            out.push_str("DATABASE_URL=");
            out.push_str(database_url);
            out.push('\n');
            replaced = true;
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    if !replaced {
        if out.is_empty() {
            out.push_str("# Rustiron app runtime environment (0400, secrets never in plans)\n");
        }
        out.push_str("DATABASE_URL=");
        out.push_str(database_url);
        out.push('\n');
    }
    if out.len() as u64 > MAX_APP_ENV_BYTES {
        return Err(ExecutorError::StepFailed);
    }
    Ok(out)
}

/// Reads `private/app.env` via `O_NOFOLLOW` descriptor, validating ownership,
/// single link, mode (`0o077 == 0`), and size bound. Returns empty bytes when
/// the file does not exist yet (for initial provisioning).
pub(crate) fn read_app_env_verified(
    private_dir: &rustix::fd::OwnedFd,
    uid: u32,
    allow_missing: bool,
) -> Result<Vec<u8>, ExecutorError> {
    let fd = match rustix::fs::openat(
        private_dir,
        "app.env",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) if allow_missing => return Ok(Vec::new()),
        Err(_) => return Err(ExecutorError::StepFailed),
    };
    let file = File::from(fd);
    let meta = file.metadata().map_err(|_| ExecutorError::StepFailed)?;
    if !meta.is_file()
        || meta.uid() != uid
        || meta.gid() != uid
        || meta.nlink() != 1
        || meta.mode() & 0o077 != 0
        || meta.len() > MAX_APP_ENV_BYTES
    {
        return Err(ExecutorError::StepFailed);
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(MAX_APP_ENV_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ExecutorError::StepFailed)?;
    if bytes.len() as u64 > MAX_APP_ENV_BYTES {
        return Err(ExecutorError::StepFailed);
    }
    Ok(bytes)
}

/// Atomically writes `private/app.env` (`0400`, `fchown(uid, uid)`, `fsync`,
/// `renameat`, `fsync(private_dir)`), preserving all non-`DATABASE_URL` lines.
pub(crate) fn atomic_upsert_app_env_database_url(
    private_dir: &rustix::fd::OwnedFd,
    uid: u32,
    database: AppDatabase,
    account: &str,
    password: &str,
    suffix: &str,
    allow_missing: bool,
) -> Result<(), ExecutorError> {
    let existing_bytes = read_app_env_verified(private_dir, uid, allow_missing)?;
    let existing = std::str::from_utf8(&existing_bytes).map_err(|_| ExecutorError::StepFailed)?;
    let url = format_database_url(database, account, password)?;
    let updated = upsert_database_url_text(existing, &url)?;
    atomic_write_app_env_bytes(private_dir, uid, updated.as_bytes(), suffix)
}

/// Atomically writes raw verified bytes to `private/app.env` with mode `0400`.
pub(crate) fn atomic_write_app_env_bytes(
    private_dir: &rustix::fd::OwnedFd,
    uid: u32,
    bytes: &[u8],
    suffix: &str,
) -> Result<(), ExecutorError> {
    if bytes.len() as u64 > MAX_APP_ENV_BYTES {
        return Err(ExecutorError::StepFailed);
    }
    let temp_name = format!(".app.env.tmp.{suffix}");
    let _ = rustix::fs::unlinkat(private_dir, temp_name.as_str(), AtFlags::empty());
    let fd = rustix::fs::openat(
        private_dir,
        temp_name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o400),
    )
    .map_err(|_| ExecutorError::StepFailed)?;
    let write_res = (|| -> Result<(), ExecutorError> {
        rustix::fs::fchown(
            &fd,
            Some(rustix::fs::Uid::from_raw(uid)),
            Some(rustix::fs::Gid::from_raw(uid)),
        )
        .map_err(|_| ExecutorError::StepFailed)?;
        let mut file = File::from(fd);
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| ExecutorError::StepFailed)?;
        rustix::fs::renameat(private_dir, temp_name.as_str(), private_dir, "app.env")
            .map_err(|_| ExecutorError::StepFailed)?;
        rustix::fs::fsync(private_dir).map_err(|_| ExecutorError::StepFailed)?;
        Ok(())
    })();
    if write_res.is_err() {
        let _ = rustix::fs::unlinkat(private_dir, temp_name.as_str(), AtFlags::empty());
    }
    write_res
}

/// W662: session settings sent (as the `postgres` superuser) before any
/// statement that carries a password, so neither `log_statement` nor the
/// failing-statement log line can write the secret to the server log.
const NO_SECRET_LOGGING: &str =
    "SET log_statement = 'none';\nSET log_min_error_statement = 'panic';\n";

/// Fixed SQL statements used to create a per-site PostgreSQL 18 role and
/// database with least privilege (`NOSUPERUSER`, `NOCREATEDB`, `NOCREATEROLE`,
/// `NOREPLICATION`, `REVOKE ALL FROM PUBLIC`).
pub(crate) fn create_role_and_db_sql(
    account: &str,
    password: &str,
) -> Result<String, ExecutorError> {
    if !valid_site_identifier(account) || !valid_app_db_password(password) {
        return Err(ExecutorError::StepFailed);
    }
    Ok(format!(
        "{NO_SECRET_LOGGING}CREATE ROLE {account} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '{password}';\n\
         CREATE DATABASE {account} WITH OWNER = {account} ENCODING = 'UTF8';\n\
         REVOKE ALL ON DATABASE {account} FROM PUBLIC;\n\
         GRANT ALL PRIVILEGES ON DATABASE {account} TO {account};\n"
    ))
}

/// Fixed SQL run inside the newly created database to revoke `PUBLIC` schema
/// creation rights and grant ownership to the site's role.
pub(crate) fn harden_public_schema_sql(account: &str) -> Result<String, ExecutorError> {
    if !valid_site_identifier(account) {
        return Err(ExecutorError::StepFailed);
    }
    Ok(format!(
        "REVOKE CREATE ON SCHEMA public FROM PUBLIC;\n\
         ALTER SCHEMA public OWNER TO {account};\n\
         GRANT ALL ON SCHEMA public TO {account};\n"
    ))
}

/// Fixed SQL to rotate a site role's SCRAM-SHA-256 password.
pub(crate) fn alter_role_password_sql(
    account: &str,
    password: &str,
) -> Result<String, ExecutorError> {
    if !valid_site_identifier(account) || !valid_app_db_password(password) {
        return Err(ExecutorError::StepFailed);
    }
    Ok(format!(
        "{NO_SECRET_LOGGING}ALTER ROLE {account} WITH PASSWORD '{password}';\n"
    ))
}

/// Fixed SQL to terminate active connections and drop the site database and role.
pub(crate) fn drop_role_and_db_sql(account: &str) -> Result<String, ExecutorError> {
    if !valid_site_identifier(account) {
        return Err(ExecutorError::StepFailed);
    }
    Ok(format!(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
         WHERE datname = '{account}' AND pid <> pg_backend_pid();\n\
         DROP DATABASE IF EXISTS {account};\n\
         DROP ROLE IF EXISTS {account};\n"
    ))
}

/// Runs `psql` as local `postgres` superuser over `/run/postgresql` peer socket.
fn psql_admin(database: &str, sql: &str, capture_stdout: bool) -> Result<String, ExecutorError> {
    if !Path::new(PG_PSQL).is_file() {
        return Err(ExecutorError::Unavailable);
    }
    provision::spawn(
        RUNUSER,
        &[
            "-u",
            "postgres",
            "--",
            PG_PSQL,
            "-v",
            "ON_ERROR_STOP=1",
            "-X",
            "-q",
            "-t",
            "-A",
            "-h",
            PG_SOCKET_DIR,
            "-d",
            database,
        ],
        capture_stdout,
        Some(sql.as_bytes()),
    )
}

/// Step 4 (`ProvisionStep::Database`) for a PostgreSQL 18 modern app site:
/// refuses collisions, generates a 48-hex-digit password locally, creates the
/// isolated role + database, and hardens `public` schema permissions.
pub(crate) fn create_database_and_role(
    layout: &SiteLayout,
) -> Result<(String, String), ExecutorError> {
    let name = layout.account.as_str();
    if !valid_site_identifier(name) {
        return Err(ExecutorError::StepFailed);
    }
    let check_sql = format!(
        "SELECT COUNT(*) FROM pg_roles WHERE rolname='{name}';\n\
         SELECT COUNT(*) FROM pg_database WHERE datname='{name}';\n"
    );
    let existing = psql_admin("postgres", &check_sql, true)?;
    if existing.split_whitespace().collect::<Vec<_>>() != ["0", "0"] {
        return Err(ExecutorError::Collision);
    }
    let password = provision::random_secret()?;
    let create_sql = create_role_and_db_sql(name, &password)?;
    psql_admin("postgres", &create_sql, false)?;
    let schema_sql = harden_public_schema_sql(name)?;
    psql_admin(name, &schema_sql, false)?;
    Ok((format!("postgres18 database {name} role {name}"), password))
}

/// Alters the site's PostgreSQL 18 role password via peer-authenticated stdin SQL.
pub(crate) fn alter_role_password(account: &str, password: &str) -> Result<(), ExecutorError> {
    let sql = alter_role_password_sql(account, password)?;
    psql_admin("postgres", &sql, false).map(drop)
}

/// RAII temp `0600` `.pgpass` file so passwords never touch argv or
/// `/proc/*/environ` and are always unlinked on drop.
struct TempPgPass(PathBuf);

impl Drop for TempPgPass {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn write_temp_pgpass(
    account: &str,
    password: &str,
    tag: &str,
) -> Result<TempPgPass, ExecutorError> {
    if !valid_site_identifier(account) || !valid_app_db_password(password) {
        return Err(ExecutorError::StepFailed);
    }
    let check_dir = Path::new(crate::layout::ADMIN_SOCKET)
        .parent()
        .ok_or(ExecutorError::StepFailed)?;
    let dir = files::open_traversable_directory(check_dir, 0)?;
    let file_name = format!("pgpass-{tag}.conf");
    let _ = rustix::fs::unlinkat(&dir, file_name.as_str(), AtFlags::empty());
    let fd = rustix::fs::openat(
        &dir,
        file_name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| ExecutorError::StepFailed)?;
    let full_path = check_dir.join(&file_name);
    let guard = TempPgPass(full_path);
    let mut file = File::from(fd);
    // In libpq, `localhost` matches Unix socket connections at `/run/postgresql`.
    let line = format!("localhost:5432:{account}:{account}:{password}\n");
    file.write_all(line.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| ExecutorError::StepFailed)?;
    Ok(guard)
}

/// Verifies `account` authenticates to PostgreSQL 18 over `/run/postgresql`
/// using `password` via an RAII `0600` `.pgpass` file and sees only its own DB.
pub(crate) fn verify_login(account: &str, password: &str, tag: &str) -> Result<(), ExecutorError> {
    if !Path::new(PG_PSQL).is_file() {
        return Err(ExecutorError::Unavailable);
    }
    let guard = write_temp_pgpass(account, password, tag)?;
    let mut child = Command::new(PG_PSQL)
        .env("PGPASSFILE", &guard.0)
        .env("PGSSLMODE", "disable")
        .args([
            "-w",
            "-X",
            "-t",
            "-A",
            "-F",
            " ",
            "-h",
            PG_SOCKET_DIR,
            "-U",
            account,
            "-d",
            account,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ExecutorError::StepFailed)?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"SELECT current_database(), current_user;\n");
    }
    let output = child
        .wait_with_output()
        .map_err(|_| ExecutorError::StepFailed)?;
    if !output.status.success() {
        return Err(ExecutorError::StepFailed);
    }
    let text = String::from_utf8(output.stdout).map_err(|_| ExecutorError::StepFailed)?;
    let words: Vec<_> = text.split_whitespace().collect();
    if words != [account, account] {
        return Err(ExecutorError::StepFailed);
    }
    Ok(())
}

/// Verifies `old_password` is REJECTED by PostgreSQL 18 after rotation.
pub(crate) fn verify_password_rejected(
    account: &str,
    old_password: &str,
    operation_id: &Id,
) -> Result<(), ExecutorError> {
    if !Path::new(PG_PSQL).is_file() {
        return Err(ExecutorError::Unavailable);
    }
    let tag = format!("old-{}", operation_id.as_str());
    let guard = write_temp_pgpass(account, old_password, &tag)?;
    let mut child = Command::new(PG_PSQL)
        .env("PGPASSFILE", &guard.0)
        .env("PGSSLMODE", "disable")
        .args([
            "-w",
            "-X",
            "-h",
            PG_SOCKET_DIR,
            "-U",
            account,
            "-d",
            account,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ExecutorError::StepFailed)?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"SELECT 1;\n");
    }
    let status = child.wait().map_err(|_| ExecutorError::StepFailed)?;
    if status.success() {
        return Err(ExecutorError::StepFailed);
    }
    Ok(())
}

/// The site role's SCRAM password from its verified `private/app.env`.
fn site_role_password(layout: &SiteLayout) -> Result<String, ExecutorError> {
    let account = layout.account.as_str();
    let passwd = provision::read_etc("passwd")?;
    let uid = provision::account_uid(&passwd, account).ok_or(ExecutorError::StepFailed)?;
    let private_dir = files::open_traversable_directory(&layout.root.join("private"), uid)?;
    let env_bytes = read_app_env_verified(&private_dir, uid, false)?;
    parse_app_env_database_url(&env_bytes, account, AppDatabase::Postgresql18)
}

/// Consistent PostgreSQL 18 custom-format dump (`pg_dump --format=custom`)
/// written safely without following symlinks at `out_path`.
///
/// W666: `pg_dump` connects as the site role, not `postgres`, so no
/// superuser session reads tenant-controlled catalog content. `owner`
/// (W663-E2) is set with `fchown` on the new file's descriptor, never by
/// path, because `out_path` may sit in a site-writable folder.
pub(crate) fn dump_database(
    layout: &SiteLayout,
    out_path: &Path,
    owner: Option<u32>,
) -> Result<(), ExecutorError> {
    let account = layout.account.as_str();
    if !valid_site_identifier(account) {
        return Err(ExecutorError::StepFailed);
    }
    if !Path::new(PG_DUMP).is_file() {
        return Err(ExecutorError::Unavailable);
    }
    if fs::symlink_metadata(out_path).is_ok() {
        let meta = fs::symlink_metadata(out_path).map_err(|_| ExecutorError::StepFailed)?;
        if meta.file_type().is_symlink() {
            return Err(ExecutorError::StepFailed);
        }
        fs::remove_file(out_path).map_err(|_| ExecutorError::StepFailed)?;
    }
    let out_str = provision::path_str(out_path)?;
    let password = site_role_password(layout)?;
    let guard = write_temp_pgpass(account, &password, &format!("dump-{account}"))?;
    // W675: pg_dump writes straight into the O_CREAT|O_EXCL|O_NOFOLLOW 0600 file,
    // so a large database never passes through this process's memory.
    let fd = rustix::fs::open(
        out_str,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| ExecutorError::StepFailed)?;
    if let Some(uid) = owner {
        rustix::fs::fchown(
            &fd,
            Some(rustix::process::Uid::from_raw(uid)),
            Some(rustix::process::Gid::from_raw(uid)),
        )
        .map_err(|_| ExecutorError::StepFailed)?;
    }
    let file = File::from(fd);
    let written = file
        .try_clone()
        .map_err(|_| ExecutorError::StepFailed)
        .and_then(|sink| {
            provision::run_streaming(
                PG_DUMP,
                &[
                    "-w",
                    "--format=custom",
                    "--no-owner",
                    "--no-acl",
                    "-h",
                    PG_SOCKET_DIR,
                    "-U",
                    account,
                    "-d",
                    account,
                ],
                &[
                    ("PGPASSFILE", guard.0.as_os_str()),
                    ("PGSSLMODE", std::ffi::OsStr::new("disable")),
                ],
                None,
                Some(sink),
            )
        })
        .and_then(|()| file.sync_all().map_err(|_| ExecutorError::StepFailed))
        .and_then(|()| match file.metadata() {
            Ok(meta) if meta.len() > 0 => Ok(()),
            _ => Err(ExecutorError::StepFailed),
        });
    if written.is_err() {
        let _ = fs::remove_file(out_path);
    }
    written
}

/// Restores a verified custom-format `pg_dump` file into the site's database.
///
/// W662-F3: `pg_restore` connects AS the site role (SCRAM password from the
/// verified `private/app.env`, passed only through a `0600` `.pgpass`), never
/// as `postgres`. A dump replays tenant code (CHECK constraints, index
/// expressions); run by a superuser it could grant the role `SUPERUSER`.
/// Restored objects are owned by the role, so no `REASSIGN OWNED` is needed.
pub(crate) fn restore_database(layout: &SiteLayout, dump_path: &Path) -> Result<(), ExecutorError> {
    let account = layout.account.as_str();
    if !valid_site_identifier(account) {
        return Err(ExecutorError::StepFailed);
    }
    if !Path::new(PG_RESTORE).is_file() {
        return Err(ExecutorError::Unavailable);
    }
    let password = site_role_password(layout)?;
    let fd = rustix::fs::open(
        dump_path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ExecutorError::StepFailed)?;
    let file = File::from(fd);
    let meta = file.metadata().map_err(|_| ExecutorError::StepFailed)?;
    if !meta.is_file() || meta.nlink() != 1 || meta.len() == 0 {
        return Err(ExecutorError::StepFailed);
    }
    // W675: the verified descriptor is pg_restore's stdin, so the client needs
    // no path into site-owned or root-only snapshot folders and the dump is
    // never buffered here.
    let guard = write_temp_pgpass(account, &password, &format!("restore-{account}"))?;
    provision::run_streaming(
        PG_RESTORE,
        &[
            "-w",
            "--exit-on-error",
            "--clean",
            "--if-exists",
            "--no-owner",
            "--no-acl",
            "-h",
            PG_SOCKET_DIR,
            "-U",
            account,
            "-d",
            account,
        ],
        &[
            ("PGPASSFILE", guard.0.as_os_str()),
            ("PGSSLMODE", std::ffi::OsStr::new("disable")),
        ],
        Some(file),
        None,
    )
}

/// Drops the site's PostgreSQL 18 database and role during `site_delete`.
pub(crate) fn drop_database_and_role(account: &str) -> Result<(), ExecutorError> {
    let sql = drop_role_and_db_sql(account)?;
    psql_admin("postgres", &sql, false).map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn site_identifier_and_password_validators_reject_injection() {
        assert!(valid_site_identifier("rs_app1"));
        assert!(valid_site_identifier("rs_my_app_99"));
        for bad in [
            "",
            "app1",
            "rs_",
            "rs_App",
            "rs_a-b",
            "rs_a;DROP",
            "rs_../x",
        ] {
            assert!(!valid_site_identifier(bad), "{bad:?}");
        }
        let hex_pw = "a1b2c3d4".repeat(6);
        assert!(valid_app_db_password(&hex_pw));
        for bad in [
            "", "abc'def", "abc\\def", "abc:def", "abc@def", "abc/def", "abc def", "abc;def",
        ] {
            assert!(!valid_app_db_password(bad), "{bad:?}");
        }
    }

    #[test]
    fn format_and_parse_database_url_round_trip_for_mariadb_and_postgres18() {
        let pw = "0123456789abcdef".repeat(3);
        let pg_url = format_database_url(AppDatabase::Postgresql18, "rs_pgapp", &pw).unwrap();
        assert_eq!(
            pg_url,
            format!("postgresql://rs_pgapp:{pw}@127.0.0.1:5432/rs_pgapp")
        );
        let env_text = format!("# comment\nAPP_NAME=demo\nDATABASE_URL={pg_url}\nPORT_HINT=1\n");
        assert_eq!(
            parse_app_env_database_url(env_text.as_bytes(), "rs_pgapp", AppDatabase::Postgresql18)
                .unwrap(),
            pw
        );
        // Wrong engine or wrong account rejected fail-closed.
        assert!(
            parse_app_env_database_url(env_text.as_bytes(), "rs_pgapp", AppDatabase::Mariadb)
                .is_err()
        );
        assert!(
            parse_app_env_database_url(env_text.as_bytes(), "rs_other", AppDatabase::Postgresql18)
                .is_err()
        );

        let my_url = format_database_url(AppDatabase::Mariadb, "rs_myapp", &pw).unwrap();
        assert_eq!(
            my_url,
            format!("mysql://rs_myapp:{pw}@127.0.0.1:3306/rs_myapp")
        );
        let my_env = format!("DATABASE_URL={my_url}\n");
        assert_eq!(
            parse_app_env_database_url(my_env.as_bytes(), "rs_myapp", AppDatabase::Mariadb)
                .unwrap(),
            pw
        );
        // Duplicate DATABASE_URL refused.
        let dup = format!("{my_env}{my_env}");
        assert!(
            parse_app_env_database_url(dup.as_bytes(), "rs_myapp", AppDatabase::Mariadb).is_err()
        );
        // None / SQLite refused.
        assert!(format_database_url(AppDatabase::Sqlite, "rs_app1", &pw).is_err());
        assert!(format_database_url(AppDatabase::None, "rs_app1", &pw).is_err());
    }

    #[test]
    fn upsert_app_env_preserves_user_keys_mode_0400_and_refuses_symlinks() {
        let base = std::env::temp_dir().join(format!("ri-pg-env-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let uid = rustix::process::getuid().as_raw();
        let dir = files::open_traversable_directory(&base, uid).unwrap();

        let pw1 = "1111222233334444".repeat(3);
        let pw2 = "5555666677778888".repeat(3);
        // Initial create when app.env is absent.
        atomic_upsert_app_env_database_url(
            &dir,
            uid,
            AppDatabase::Postgresql18,
            "rs_app1",
            &pw1,
            "init",
            true,
        )
        .unwrap();
        let env_path = base.join("app.env");
        assert_eq!(
            fs::metadata(&env_path).unwrap().permissions().mode() & 0o777,
            0o400
        );
        // Append an operator custom key, then rotate DATABASE_URL -> custom key preserved.
        fs::set_permissions(&env_path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut content = fs::read_to_string(&env_path).unwrap();
        content.push_str("CUSTOM_SECRET=keep_me\n");
        fs::write(&env_path, &content).unwrap();
        fs::set_permissions(&env_path, fs::Permissions::from_mode(0o400)).unwrap();

        atomic_upsert_app_env_database_url(
            &dir,
            uid,
            AppDatabase::Postgresql18,
            "rs_app1",
            &pw2,
            "rot1",
            false,
        )
        .unwrap();
        let after = fs::read_to_string(&env_path).unwrap();
        assert!(after.contains("CUSTOM_SECRET=keep_me\n"));
        assert_eq!(
            parse_app_env_database_url(after.as_bytes(), "rs_app1", AppDatabase::Postgresql18)
                .unwrap(),
            pw2
        );
        assert_eq!(
            fs::metadata(&env_path).unwrap().permissions().mode() & 0o777,
            0o400
        );

        // Symlinked app.env is refused fail-closed.
        let decoy = base.join("decoy.env");
        fs::write(&decoy, b"DATABASE_URL=x\n").unwrap();
        fs::remove_file(&env_path).unwrap();
        symlink(&decoy, &env_path).unwrap();
        assert!(
            atomic_upsert_app_env_database_url(
                &dir,
                uid,
                AppDatabase::Postgresql18,
                "rs_app1",
                &pw1,
                "sym",
                false,
            )
            .is_err()
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn sql_builders_enforce_least_privilege_and_public_schema_hardening() {
        let pw = "abcdef0123456789".repeat(3);
        let create = create_role_and_db_sql("rs_shop", &pw).unwrap();
        assert!(create.contains("NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION"));
        assert!(create.contains("REVOKE ALL ON DATABASE rs_shop FROM PUBLIC;"));
        let schema = harden_public_schema_sql("rs_shop").unwrap();
        assert!(schema.contains("REVOKE CREATE ON SCHEMA public FROM PUBLIC;"));
        assert!(schema.contains("ALTER SCHEMA public OWNER TO rs_shop;"));
        let alter = alter_role_password_sql("rs_shop", &pw).unwrap();
        assert!(alter.starts_with(NO_SECRET_LOGGING));
        assert!(alter.contains("\nALTER ROLE rs_shop WITH PASSWORD '"));
        assert!(create.starts_with(NO_SECRET_LOGGING));
        let drop_sql = drop_role_and_db_sql("rs_shop").unwrap();
        assert!(drop_sql.contains("pg_terminate_backend"));
        assert!(drop_sql.contains("DROP DATABASE IF EXISTS rs_shop;"));
        assert!(drop_sql.contains("DROP ROLE IF EXISTS rs_shop;"));
    }
}
