//! Runtime recovery of PHP units after the OLS boot guard runs.

use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt, path::Path};

use rustiron_contracts::{Id, approval::SiteId};
use rustiron_journal::{FixtureJournal, JournalError};
use rustix::{
    fs::{FlockOperation, OFlags, flock},
    io::Errno,
};

use crate::{ExecutorError, TrustAnchor, durable, ejection, ols};

/// Outcome of the boot-time PHP recovery check run after `ols-boot-guard`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BootRestoreOutcome {
    /// An interrupted eject's PHP socket and timer were restored.
    Restored(Id, SiteId),
    /// No interrupted eject needed recovery.
    NoPendingEject,
    /// `rustiron-executor.service` already holds the exclusive journal writer
    /// lease (for example during bootstrap `config_activate` when `lshttpd`
    /// starts after the executor is already running), so boot recovery is a
    /// no-op rather than a failed systemd unit.
    SkippedExecutorActive,
}

/// True only when `journal_dir/writer.lock` is an existing regular file owned
/// by the current process owner whose exclusive `flock` is actively held.
pub(crate) fn writer_lease_actively_held(journal_dir: &Path) -> bool {
    let path = journal_dir.join("writer.lock");
    let Ok(file) = OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::NOFOLLOW | OFlags::CLOEXEC).bits() as i32)
        .open(&path)
    else {
        return false;
    };
    let Ok(meta) = file.metadata() else {
        return false;
    };
    use std::os::unix::fs::MetadataExt;
    if !meta.is_file() || meta.uid() != rustix::process::getuid().as_raw() {
        return false;
    }
    matches!(
        flock(&file, FlockOperation::NonBlockingLockExclusive),
        Err(Errno::AGAIN)
    )
}

/// Starts only the socket and timer of an unresolved, attempted eject
/// whose verified managed predecessor is current. Takes no request and
/// holds the writer lease through the actual unit starts.
pub fn boot_restore_ejected_php(anchor: &TrustAnchor) -> Result<BootRestoreOutcome, ExecutorError> {
    let (host, epoch) = durable::prepare(anchor)?;
    let result = FixtureJournal::with_exclusive_read_as_process_owner(
        &anchor.journal_dir,
        &host,
        &epoch,
        |journal| {
            let pending = durable::pending_boot_activation(anchor, &host, &epoch, journal)?;
            let Some(activation) = pending.filter(|activation| activation.effect_attempted) else {
                return Ok(BootRestoreOutcome::NoPendingEject);
            };
            let operation = activation.operation_id;
            let Some(site) = journal.ejection_site(&operation)? else {
                return Ok(BootRestoreOutcome::NoPendingEject);
            };
            let include = ols::open_include()?;
            let live = ols::observe(&include)?;
            if live != activation.predecessor
                || activation.established_before.as_ref() != Some(&live)
                || ols::generation_refusal(&live, activation.established_before.as_ref()).is_some()
            {
                return Err(ExecutorError::Drift);
            }
            let account = site.account_name();
            if !ols::managed_accounts(&include, &live.0)?.contains(&account) {
                return Err(ExecutorError::BindingDenied);
            }
            ejection::start_recovery_php(&account)?;
            Ok(BootRestoreOutcome::Restored(operation, site))
        },
    );
    match result {
        Ok(inner) => inner,
        Err(JournalError::AccessDenied) if writer_lease_actively_held(&anchor.journal_dir) => {
            Ok(BootRestoreOutcome::SkippedExecutorActive)
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn writer_lease_actively_held_distinguishes_live_flock_from_missing_or_unlocked() {
        let dir = std::env::temp_dir().join(format!("rustiron-w646-lease-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        // Missing writer.lock -> false (fails closed in caller).
        assert!(!writer_lease_actively_held(&dir));

        // Unlocked writer.lock -> false (fails closed in caller).
        let lock_path = dir.join("writer.lock");
        let holder = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)
            .unwrap();
        assert!(!writer_lease_actively_held(&dir));

        // Locked writer.lock (simulating live rustiron-executor.service) -> true.
        flock(&holder, FlockOperation::NonBlockingLockExclusive).unwrap();
        assert!(writer_lease_actively_held(&dir));

        drop(holder);
        assert!(!writer_lease_actively_held(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
