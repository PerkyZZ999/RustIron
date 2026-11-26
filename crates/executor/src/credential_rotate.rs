//! D-100 (P13, W609): host-side WordPress MariaDB credential rotation.
//!
//! Runs inside the privileged root admin helper for a journaled
//! `site_credential_rotate` (`mariadb_user_password`) intent. Secret values
//! never enter plans, grants, journal rows, logs, argv, or `/proc/*/environ`.
//!
//! Sequence:
//! 1. Read and strictly parse `/srv/sites/<account>/private/db.cnf` via
//!    descriptor, confirming owner/mode/regular file/user/database/socket.
//! 2. Verify the existing `private/db.cnf` currently authenticates to MariaDB
//!    before mutating anything.
//! 3. Generate a fresh 48-hex-digit password locally via `getrandom`.
//! 4. Run fixed `ALTER USER '<account>'@'localhost' IDENTIFIED BY '<new>';
//!    FLUSH PRIVILEGES;` over stdin to the local MariaDB socket.
//! 5. Atomically write (`O_CREAT|O_EXCL|O_NOFOLLOW`, `0600`, `fchown`, `fsync`)
//!    and `renameat` the new `private/db.cnf` + `fsync` the `private` directory.
//! 6. Restart `rustiron-site-php@<account>.service`.
//! 7. Verify the NEW password authenticates, verify the OLD password is
//!    REJECTED (using a root-only `0600` temp defaults file immediately
//!    unlinked on drop), and verify site marker + `wp-login.php` + `/` via
//!    `site_update::site_answers`.
//! 8. On any failure after `ALTER USER`, run at most ONE bounded compensation
//!    attempt restoring the prior MariaDB password and `private/db.cnf`,
//!    restarting site PHP, and re-verifying MariaDB + HTTP health:
//!    - compensation + health verified -> `FailedCompensated`
//!    - compensation or verification fails -> `NeedsAttention`

use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use rustiron_contracts::{Id, approval::Hostname};
use rustix::fs::{AtFlags, Mode, OFlags};

use crate::{
    ExecutorError, files,
    provision::{self, DB_SOCKET, MARIADB, SiteLayout},
};

const SYSTEMCTL: &str = "/usr/bin/systemctl";
const MAX_DB_CNF_BYTES: u64 = 4096;

/// Closed wire outcome returned by the root admin helper to the executor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RotateOutcome {
    /// New password verified in MariaDB + `private/db.cnf`, old password
    /// rejected, site PHP restarted, HTTP/WordPress health verified.
    Done,
    /// Post-`ALTER USER` failure recovered by the single bounded compensation
    /// attempt; prior credentials and site HTTP/WordPress health verified.
    FailedCompensated,
    /// Host database password vs `private/db.cnf` state is uncertain after
    /// failure; site remains locked until operator reconciliation.
    NeedsAttention,
    /// Failed before mutating MariaDB (or pre-check refused); site untouched.
    Failed,
}

impl RotateOutcome {
    /// Exact ASCII token returned on the admin-helper reply line.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Done => "done",
            Self::FailedCompensated => "failed_compensated",
            Self::NeedsAttention => "needs_attention",
            Self::Failed => "failed",
        }
    }

    /// Parses the closed admin-helper reply token.
    pub fn parse(token: &str) -> Option<Self> {
        match token {
            "done" => Some(Self::Done),
            "failed_compensated" => Some(Self::FailedCompensated),
            "needs_attention" => Some(Self::NeedsAttention),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }

    /// Maps into the durable journal state.
    pub const fn journal_state(self) -> rustiron_journal::CredentialRotateState {
        use rustiron_journal::CredentialRotateState as S;
        match self {
            Self::Done => S::Done,
            Self::FailedCompensated => S::FailedCompensated,
            Self::NeedsAttention => S::NeedsAttention,
            Self::Failed => S::Failed,
        }
    }
}

/// Strictly parses a Rustiron `private/db.cnf` file and returns the password.
///
/// Refuses unknown keys, mismatched user/database/socket, empty passwords, and
/// any character unsafe for fixed SQL (`'`, `\`, whitespace, control bytes).
pub(crate) fn parse_db_cnf(bytes: &[u8], expected_account: &str) -> Result<String, ExecutorError> {
    if bytes.len() as u64 > MAX_DB_CNF_BYTES {
        return Err(ExecutorError::StepFailed);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ExecutorError::StepFailed)?;
    let mut in_client = false;
    let mut user = None;
    let mut password = None;
    let mut database = None;
    let mut socket = None;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if line == "[client]" {
            if in_client {
                return Err(ExecutorError::StepFailed);
            }
            in_client = true;
            continue;
        }
        if !in_client || line.starts_with('[') {
            return Err(ExecutorError::StepFailed);
        }
        let (key, value) = line.split_once('=').ok_or(ExecutorError::StepFailed)?;
        match key {
            "user" if user.is_none() => user = Some(value),
            "password" if password.is_none() => password = Some(value),
            "database" if database.is_none() => database = Some(value),
            "socket" if socket.is_none() => socket = Some(value),
            _ => return Err(ExecutorError::StepFailed),
        }
    }
    if user != Some(expected_account)
        || database != Some(expected_account)
        || socket != Some(DB_SOCKET)
    {
        return Err(ExecutorError::StepFailed);
    }
    let secret = password.ok_or(ExecutorError::StepFailed)?;
    if !valid_db_password(secret) {
        return Err(ExecutorError::StepFailed);
    }
    Ok(secret.to_owned())
}

fn valid_db_password(secret: &str) -> bool {
    !secret.is_empty()
        && secret.len() <= 128
        && secret.bytes().all(|b| {
            b.is_ascii_graphic() && b != b'\'' && b != b'\\' && b != b'"' && b != b'`' && b != b';'
        })
}

fn read_db_cnf(private_dir: &rustix::fd::OwnedFd, uid: u32) -> Result<Vec<u8>, ExecutorError> {
    let fd = rustix::fs::openat(
        private_dir,
        "db.cnf",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ExecutorError::StepFailed)?;
    let file = File::from(fd);
    let meta = file.metadata().map_err(|_| ExecutorError::StepFailed)?;
    if !meta.is_file()
        || meta.uid() != uid
        || meta.gid() != uid
        || meta.nlink() != 1
        || meta.len() > MAX_DB_CNF_BYTES
    {
        return Err(ExecutorError::StepFailed);
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(MAX_DB_CNF_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ExecutorError::StepFailed)?;
    if bytes.len() as u64 > MAX_DB_CNF_BYTES {
        return Err(ExecutorError::StepFailed);
    }
    Ok(bytes)
}

fn atomic_write_db_cnf(
    private_dir: &rustix::fd::OwnedFd,
    uid: u32,
    account: &str,
    password: &str,
    suffix: &str,
) -> Result<(), ExecutorError> {
    let temp_name = format!(".db.cnf.rot.{suffix}");
    let _ = rustix::fs::unlinkat(private_dir, temp_name.as_str(), AtFlags::empty());
    let fd = rustix::fs::openat(
        private_dir,
        temp_name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| ExecutorError::StepFailed)?;
    let write_res = (|| -> Result<(), ExecutorError> {
        rustix::fs::fchown(
            &fd,
            Some(rustix::fs::Uid::from_raw(uid)),
            Some(rustix::fs::Gid::from_raw(uid)),
        )
        .map_err(|_| ExecutorError::StepFailed)?;
        let text = provision::credentials_text(account, password);
        let mut file = File::from(fd);
        file.write_all(text.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|_| ExecutorError::StepFailed)?;
        rustix::fs::renameat(private_dir, temp_name.as_str(), private_dir, "db.cnf")
            .map_err(|_| ExecutorError::StepFailed)?;
        rustix::fs::fsync(private_dir).map_err(|_| ExecutorError::StepFailed)?;
        Ok(())
    })();
    if write_res.is_err() {
        let _ = rustix::fs::unlinkat(private_dir, temp_name.as_str(), AtFlags::empty());
    }
    write_res
}

fn alter_mariadb_password(account: &str, password: &str) -> Result<(), ExecutorError> {
    if !valid_db_password(password) {
        return Err(ExecutorError::StepFailed);
    }
    let sql = format!(
        "ALTER USER '{account}'@'localhost' IDENTIFIED BY '{password}';\nFLUSH PRIVILEGES;\n"
    );
    provision::spawn(
        MARIADB,
        &["--batch", "--socket", DB_SOCKET],
        false,
        Some(sql.as_bytes()),
    )
    .map(drop)
}

fn verify_db_cnf(cnf_path: &Path, account: &str) -> Result<(), ExecutorError> {
    let defaults = format!("--defaults-file={}", provision::path_str(cnf_path)?);
    let seen = provision::spawn(
        MARIADB,
        &[&defaults, "--batch", "--skip-column-names"],
        true,
        Some(b"SELECT DATABASE(), CURRENT_USER();\nSHOW DATABASES;\n"),
    )?;
    let words: Vec<_> = seen.split_whitespace().collect();
    let user = format!("{account}@localhost");
    if words.first() != Some(&account)
        || words.get(1) != Some(&user.as_str())
        || words[2..]
            .iter()
            .any(|db| *db != account && *db != "information_schema")
    {
        return Err(ExecutorError::StepFailed);
    }
    Ok(())
}

/// RAII temp `0600` root-only defaults file so the old password never touches
/// argv or `/proc/*/environ` and is unlinked even on panic or error.
struct TempCheckCnf(PathBuf);

impl Drop for TempCheckCnf {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn verify_password_rejected(
    account: &str,
    old_password: &str,
    operation_id: &Id,
) -> Result<(), ExecutorError> {
    let check_dir = Path::new(crate::layout::ADMIN_SOCKET)
        .parent()
        .ok_or(ExecutorError::StepFailed)?;
    let dir = files::open_traversable_directory(check_dir, 0)?;
    let file_name = format!("credrot-oldcheck-{}.cnf", operation_id.as_str());
    let _ = rustix::fs::unlinkat(&dir, file_name.as_str(), AtFlags::empty());
    let fd = rustix::fs::openat(
        &dir,
        file_name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| ExecutorError::StepFailed)?;
    let full_path = check_dir.join(&file_name);
    let _guard = TempCheckCnf(full_path.clone());
    let mut file = File::from(fd);
    let text = provision::credentials_text(account, old_password);
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| ExecutorError::StepFailed)?;
    drop(file);

    let defaults = format!("--defaults-file={}", provision::path_str(&full_path)?);
    let mut child = Command::new(MARIADB)
        .args([defaults.as_str(), "--batch", "--skip-column-names"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ExecutorError::StepFailed)?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"SELECT 1;\n");
    }
    let status = child.wait().map_err(|_| ExecutorError::StepFailed)?;
    // Old password MUST be rejected (non-zero exit).
    if status.success() {
        return Err(ExecutorError::StepFailed);
    }
    Ok(())
}

fn restart_site_php(account: &str) -> Result<(), ExecutorError> {
    let unit = format!("rustiron-site-php@{account}.service");
    provision::spawn(SYSTEMCTL, &["restart", "--", unit.as_str()], false, None).map(drop)
}

fn log_outcome(outcome: RotateOutcome, stage: &'static str) {
    eprintln!(
        "{}",
        serde_json::json!({
            "scope": "site_credential_rotate",
            "outcome": outcome.as_str(),
            "stage": stage
        })
    );
}

/// Executes one signed `site_credential_rotate` (`mariadb_user_password`)
/// operation inside the root admin helper, including 1-attempt bounded
/// compensation on post-`ALTER USER` failure.
pub(crate) fn rotate_mariadb_password(
    layout: &SiteLayout,
    hostname: &Hostname,
    operation_id: &Id,
    address: &str,
    tls_address: Option<&str>,
) -> Result<RotateOutcome, ExecutorError> {
    let passwd = provision::read_etc("passwd")?;
    let Some(uid) = provision::account_uid(&passwd, &layout.account) else {
        log_outcome(RotateOutcome::Failed, "account_missing");
        return Ok(RotateOutcome::Failed);
    };
    let private = layout.root.join("private");
    let Ok(private_dir) = files::open_traversable_directory(&private, uid) else {
        log_outcome(RotateOutcome::Failed, "private_dir");
        return Ok(RotateOutcome::Failed);
    };
    let Ok(old_bytes) = read_db_cnf(&private_dir, uid) else {
        log_outcome(RotateOutcome::Failed, "read_db_cnf");
        return Ok(RotateOutcome::Failed);
    };
    let Ok(old_password) = parse_db_cnf(&old_bytes, &layout.account) else {
        log_outcome(RotateOutcome::Failed, "parse_db_cnf");
        return Ok(RotateOutcome::Failed);
    };
    let cnf_path = private.join("db.cnf");
    if verify_db_cnf(&cnf_path, &layout.account).is_err() {
        log_outcome(RotateOutcome::Failed, "precheck_db_login");
        return Ok(RotateOutcome::Failed);
    }

    let mut new_password = provision::random_secret()?;
    if new_password == old_password {
        new_password = provision::random_secret()?;
    }
    if new_password == old_password {
        log_outcome(RotateOutcome::Failed, "entropy_collision");
        return Ok(RotateOutcome::Failed);
    }

    if alter_mariadb_password(&layout.account, &new_password).is_err() {
        let outcome = if verify_db_cnf(&cnf_path, &layout.account).is_ok() {
            RotateOutcome::Failed
        } else {
            RotateOutcome::NeedsAttention
        };
        log_outcome(outcome, "alter_user");
        return Ok(outcome);
    }

    // MariaDB user password is now `new_password`. Any failure below triggers
    // the single bounded compensation attempt back to `old_password`.
    let apply_stage: Result<(), &'static str> = (|| {
        atomic_write_db_cnf(
            &private_dir,
            uid,
            &layout.account,
            &new_password,
            operation_id.as_str(),
        )
        .map_err(|_| "write_db_cnf")?;
        restart_site_php(&layout.account).map_err(|_| "restart_site_php")?;
        verify_db_cnf(&cnf_path, &layout.account).map_err(|_| "verify_new_db")?;
        verify_password_rejected(&layout.account, &old_password, operation_id)
            .map_err(|_| "verify_old_rejected")?;
        crate::site_update::site_answers(address, tls_address, hostname, layout)
            .map_err(|_| "site_health")?;
        Ok(())
    })();

    if apply_stage.is_ok() {
        log_outcome(RotateOutcome::Done, "verified");
        return Ok(RotateOutcome::Done);
    }

    let failed_stage = apply_stage.unwrap_err();
    let comp_ok = (|| -> Result<(), ExecutorError> {
        alter_mariadb_password(&layout.account, &old_password)?;
        let current_bytes = read_db_cnf(&private_dir, uid)?;
        if current_bytes != old_bytes {
            let comp_suffix = format!("{}.comp", operation_id.as_str());
            atomic_write_db_cnf(
                &private_dir,
                uid,
                &layout.account,
                &old_password,
                &comp_suffix,
            )?;
        }
        restart_site_php(&layout.account)?;
        verify_db_cnf(&cnf_path, &layout.account)?;
        crate::site_update::site_answers(address, tls_address, hostname, layout)?;
        Ok(())
    })();

    let outcome = if comp_ok.is_ok() {
        RotateOutcome::FailedCompensated
    } else {
        RotateOutcome::NeedsAttention
    };
    log_outcome(outcome, failed_stage);
    Ok(outcome)
}

/// Read-only live verification used by `credential-rotate-reconcile` before
/// settling an unresolved rotation as `done` or `failed_compensated`.
pub(crate) fn verify_live_credentials(
    layout: &SiteLayout,
    hostname: &Hostname,
    address: &str,
    tls_address: Option<&str>,
) -> Result<(), ExecutorError> {
    let passwd = provision::read_etc("passwd")?;
    let uid = provision::account_uid(&passwd, &layout.account).ok_or(ExecutorError::StepFailed)?;
    let private = layout.root.join("private");
    let private_dir = files::open_traversable_directory(&private, uid)?;
    let bytes = read_db_cnf(&private_dir, uid)?;
    let _ = parse_db_cnf(&bytes, &layout.account)?;
    verify_db_cnf(&private.join("db.cnf"), &layout.account)?;
    crate::site_update::site_answers(address, tls_address, hostname, layout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_db_cnf_accepts_canonical_format_and_rejects_tampering() {
        let valid = provision::credentials_text("rs_cp02", &"a1b2c3d4".repeat(6));
        assert_eq!(
            parse_db_cnf(valid.as_bytes(), "rs_cp02").unwrap(),
            "a1b2c3d4".repeat(6)
        );
        // Wrong account or database
        assert!(parse_db_cnf(valid.as_bytes(), "rs_other").is_err());
        // SQL metacharacters in password refused
        let quoted = provision::credentials_text("rs_cp02", "abc'def");
        assert!(parse_db_cnf(quoted.as_bytes(), "rs_cp02").is_err());
        let backslash = provision::credentials_text("rs_cp02", "abc\\def");
        assert!(parse_db_cnf(backslash.as_bytes(), "rs_cp02").is_err());
        // Extra section or key refused
        let extra = format!("{valid}host=127.0.0.1\n");
        assert!(parse_db_cnf(extra.as_bytes(), "rs_cp02").is_err());
        // Empty password refused
        let empty = provision::credentials_text("rs_cp02", "");
        assert!(parse_db_cnf(empty.as_bytes(), "rs_cp02").is_err());
    }

    #[test]
    fn rotate_outcome_round_trips_wire_tokens() {
        for outcome in [
            RotateOutcome::Done,
            RotateOutcome::FailedCompensated,
            RotateOutcome::NeedsAttention,
            RotateOutcome::Failed,
        ] {
            assert_eq!(RotateOutcome::parse(outcome.as_str()), Some(outcome));
        }
        assert_eq!(RotateOutcome::parse("intent"), None);
        assert_eq!(RotateOutcome::parse("unknown"), None);
    }
}
