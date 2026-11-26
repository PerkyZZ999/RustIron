//! Standalone vhost publication and recovery for ejection.

use std::{os::fd::OwnedFd, path::Path};

use rustiron_contracts::{Id, approval::Sha256Digest};
use rustix::{
    fs::{self, AtFlags, Mode},
    io::Errno,
};
use sha2::{Digest, Sha256};

use super::{EJECTED_DIR, Generation, MAX_FILE, stage};
use crate::{ExecutorError, files};

const VHOST: &str = "vhost.conf";
const OWNER_RECORD: &str = ".eject-owner";
const OWNER_RECORD_LIMIT: usize = 512;

fn eject_base_name() -> &'static str {
    EJECTED_DIR.trim_start_matches("/etc/")
}

fn entry_exists(parent: &OwnedFd, name: &str) -> Result<bool, ExecutorError> {
    match fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(Errno::NOENT) => Ok(false),
        Err(_) => Err(ExecutorError::AccessDenied),
    }
}

fn open_base_if_present() -> Result<Option<OwnedFd>, ExecutorError> {
    let etc = files::open_traversable_directory(Path::new("/etc"), 0)?;
    let name = eject_base_name();
    entry_exists(&etc, name)?
        .then(|| files::open_child_directory(&etc, name, 0))
        .transpose()
}

/// Treats any account entry as an eject marker, including an unreadable one.
pub(crate) fn has_eject_marker(account: &str) -> Result<bool, ExecutorError> {
    match open_base_if_present()? {
        Some(base) => entry_exists(&base, account),
        None => Ok(false),
    }
}

fn owner_prefix(operation: &Id, grant: &Sha256Digest) -> String {
    format!(
        "rustiron-eject/1\n{}\n{}\n",
        operation.as_str(),
        grant.as_str()
    )
}

fn checksum(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

/// Installs a complete standalone vhost after the durable effect mark.
/// A pre-existing account directory collides, even if the bytes match.
pub(crate) fn write_ejected(
    account: &str,
    bytes: &[u8],
    operation: &Id,
    grant: &Sha256Digest,
) -> Result<(), ExecutorError> {
    let etc = files::open_traversable_directory(Path::new("/etc"), 0)?;
    let name = eject_base_name();
    let created = match fs::mkdirat(&etc, name, Mode::from_raw_mode(0o755)) {
        Ok(()) => true,
        Err(Errno::EXIST) => false,
        Err(_) => return Err(ExecutorError::StepFailed),
    };
    let base = files::open_child_directory(&etc, name, 0)?;
    if created {
        fs::fchmod(&base, Mode::from_raw_mode(0o755)).map_err(|_| ExecutorError::StepFailed)?;
        fs::fsync(&etc).map_err(|_| ExecutorError::StepFailed)?;
    }
    publish_candidate(&base, 0, account, bytes, operation, grant)
}

fn publish_candidate(
    base: &OwnedFd,
    owner: u32,
    account: &str,
    bytes: &[u8],
    operation: &Id,
    grant: &Sha256Digest,
) -> Result<(), ExecutorError> {
    if entry_exists(base, account)? {
        return Err(ExecutorError::Collision);
    }
    let record = format!(
        "{}{}\n",
        owner_prefix(operation, grant),
        checksum(bytes).as_str()
    );
    let candidate = Generation::from([
        (VHOST.to_owned(), bytes.to_vec()),
        (OWNER_RECORD.to_owned(), record.into_bytes()),
    ]);
    let temporary = format!("{account}{}{}", stage::STAGING_MARK, stage::random_hex()?);
    let identity = stage::write_temporary(base, &temporary, &candidate, owner)?;
    stage::rename_verified(base, &temporary, account, identity)
}

/// Moves this operation's standalone vhost aside once its managed
/// predecessor serves again. Copies from older builds stay in place.
pub(crate) fn archive_ejected(
    account: &str,
    operation: &Id,
    grant: &Sha256Digest,
) -> Result<(), ExecutorError> {
    let Some(base) = open_base_if_present()? else {
        return Ok(());
    };
    archive_candidate(&base, 0, account, operation, grant)
}

fn archive_candidate(
    base: &OwnedFd,
    owner: u32,
    account: &str,
    operation: &Id,
    grant: &Sha256Digest,
) -> Result<(), ExecutorError> {
    if !entry_exists(base, account)? {
        // A previous recovery might have stopped after the rename, before
        // syncing this directory. Persist the absence before settling.
        return fs::fsync(base).map_err(|_| ExecutorError::StepFailed);
    }
    let directory = files::open_child_directory(base, account, owner)?;
    if !entry_exists(&directory, OWNER_RECORD)? {
        return Ok(());
    }
    let record = files::read_child(
        &directory,
        OWNER_RECORD,
        owner,
        files::Exposure::Readable,
        OWNER_RECORD_LIMIT,
    )?;
    let prefix = owner_prefix(operation, grant);
    let Some(expected) = record.strip_prefix(prefix.as_bytes()) else {
        return Ok(());
    };
    let bytes = files::read_child(
        &directory,
        VHOST,
        owner,
        files::Exposure::Readable,
        MAX_FILE,
    )?;
    if expected.strip_suffix(b"\n") != Some(checksum(&bytes).as_str().as_bytes()) {
        return Err(ExecutorError::Drift);
    }
    let stat = fs::fstat(&directory).map_err(|_| ExecutorError::StepFailed)?;
    let archive = format!("{account}.rollback-{}", grant.as_str());
    stage::rename_verified(base, account, &archive, (stat.st_dev, stat.st_ino))
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::*;
    use crate::files;

    struct Standalone {
        path: PathBuf,
        base: OwnedFd,
        owner: u32,
        operation: Id,
        grant: Sha256Digest,
    }

    impl Standalone {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("rustiron-eject-{}", stage::random_hex().unwrap()));
            fs::create_dir(&path).unwrap();
            let owner = rustix::process::geteuid().as_raw();
            let base = files::open_traversable_directory(&path, owner).unwrap();
            Self {
                path,
                base,
                owner,
                operation: "op_eject_blog9".to_owned().try_into().unwrap(),
                grant: Sha256Digest::from_bytes([7; 32]),
            }
        }

        fn put_vhost(&self, bytes: &[u8]) {
            let folder = self.path.join("rs_blog9");
            fs::create_dir(&folder).unwrap();
            fs::write(folder.join("vhost.conf"), bytes).unwrap();
        }

        fn rollback(&self) -> Result<(), ExecutorError> {
            archive_candidate(
                &self.base,
                self.owner,
                "rs_blog9",
                &self.operation,
                &self.grant,
            )
        }

        fn publish(&self, bytes: &[u8]) -> Result<(), ExecutorError> {
            publish_candidate(
                &self.base,
                self.owner,
                "rs_blog9",
                bytes,
                &self.operation,
                &self.grant,
            )
        }
    }

    impl Drop for Standalone {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn rollback_moves_only_the_vhost_belonging_to_the_failed_eject() {
        let host = Standalone::new();
        let config = b"docRoot /srv/sites/rs_blog9/html/\n";
        host.publish(config).unwrap();
        let copy = host.path.join("rs_blog9/vhost.conf0");
        fs::write(&copy, b"OLS copy").unwrap();
        host.rollback().unwrap();
        assert!(!host.path.join("rs_blog9").exists());
        let archive = host
            .path
            .join(format!("rs_blog9.rollback-{}", host.grant.as_str()));
        assert_eq!(fs::read(archive.join("vhost.conf")).unwrap(), config);
        assert_eq!(fs::read(archive.join("vhost.conf0")).unwrap(), b"OLS copy");
        host.rollback().unwrap();
    }

    #[test]
    fn rollback_leaves_a_legacy_standalone_vhost_in_place() {
        let host = Standalone::new();
        let config = b"docRoot /srv/sites/rs_blog9/html/\n";
        host.put_vhost(config);
        host.rollback().unwrap();
        assert_eq!(
            fs::read(host.path.join("rs_blog9/vhost.conf")).unwrap(),
            config
        );
    }

    #[test]
    fn publication_refuses_to_replace_an_existing_vhost() {
        let host = Standalone::new();
        let config = b"docRoot /srv/sites/rs_blog9/html/\n";
        host.publish(config).unwrap();
        assert_eq!(host.publish(b"foreign"), Err(ExecutorError::Collision));
        let vhost = host.path.join("rs_blog9/vhost.conf");
        assert_eq!(fs::read(&vhost).unwrap(), config);
    }

    #[test]
    fn recovery_refuses_a_changed_vhost_with_a_matching_owner_record() {
        let host = Standalone::new();
        host.publish(b"docRoot /srv/sites/rs_blog9/html/\n")
            .unwrap();
        let vhost = host.path.join("rs_blog9/vhost.conf");
        fs::write(&vhost, b"changed").unwrap();
        assert_eq!(host.rollback(), Err(ExecutorError::Drift));
        assert_eq!(fs::read(vhost).unwrap(), b"changed");
    }
}
