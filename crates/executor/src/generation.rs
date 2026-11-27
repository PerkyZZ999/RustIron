//! W699 (W689 candidate 2): content-addressed generation folders and the
//! `current` link, shared by OLS (`ols::stage`) and Caddy (`caddy`). The two
//! adapters differ only in the [`Reader`] that reads a folder back. The
//! journaled activation order of each server stays with its caller.
//!
//! W384: crash-safe staging of a content-addressed generation folder.
//!
//! A generation is written into a temporary sibling folder
//! (`<id>.staging-<random>`), each file and the folder are synced, the
//! files are read back and compared with the render, and only then the
//! folder is renamed to its id (`RENAME_NOREPLACE`) and `generations` is
//! synced. A power cut can therefore leave a temporary folder, but never a
//! folder under the id with only some of its files.
//!
//! A folder under the id is reused only when its files are exactly the
//! render (W372 comparison, OLS copies ignored). A root-owned folder with
//! other files (a partial staging of an earlier build, or changed bytes) is
//! never trusted and never deleted: it is renamed to
//! `<id>.quarantine-<operation>` and a new folder is staged. Any other entry
//! under the id (a link, a file, another owner, a writable folder, or files
//! that cannot be read as root-owned single-link files) is unexplained and
//! refused (`PROVISION_COLLISION`), as before (W242).
//!
//! W394: the rename takes only the folder that was verified. A link or
//! another folder swapped in under the temporary name is refused before
//! the rename, and a swap that races the rename is refused after it
//! (`PROVISION_COLLISION`), before the effect mark and any switch.
//!
//! Temporary and quarantine names hold a `.`, which no generation id can
//! hold, so no `current` and no plan can name them. Nothing reads them.

use std::{collections::BTreeMap, io::Write, os::fd::OwnedFd};

use rustiron_contracts::Id;
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags};

use crate::{ExecutorError, files};

/// The files of one generation: name to bytes.
pub type Files = BTreeMap<String, Vec<u8>>;

/// Reads one generation folder owned by `owner` back (each server's adapter).
pub type Reader = fn(&OwnedFd, u32) -> Result<Files, ExecutorError>;

/// Marks a temporary staging folder: `<id>.staging-<16 hex>`.
pub const STAGING_MARK: &str = ".staging-";
/// Marks a folder moved aside: `<id>.quarantine-<operation>`.
pub const QUARANTINE_MARK: &str = ".quarantine-";

/// What `prepare` found and wrote; `publish` completes it.
#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub enum Staging {
    /// The folder under the id already holds exactly the render.
    Reused,
    /// A verified temporary folder waits for its rename. `quarantined`
    /// names the folder that held other files under the id.
    Ready {
        /// `<id>.staging-<random>` under `generations`.
        temporary: String,
        /// `<id>.quarantine-<operation>`, when a differing folder had the id.
        quarantined: Option<String>,
        /// W394: the device and inode of the verified temporary folder.
        /// `publish` renames only that folder and checks the id after.
        identity: (u64, u64),
    },
}

/// What the staging did with the folder under the id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Staged {
    /// An earlier staging left exactly these files; nothing was written.
    Reused,
    /// A new folder was written and renamed into place.
    Written,
    /// The folder under the id held other files; it now has this name, and
    /// a new folder was written and renamed into place.
    Quarantined(String),
}

/// Names under `generations` that a staging left: temporary folders and
/// quarantined folders, in name order. Read-only.
pub fn leftovers(parent: &OwnedFd, owner: u32) -> Result<Vec<String>, ExecutorError> {
    let generations = files::open_child_directory(parent, "generations", owner)?;
    leftovers_in(&generations)
}

/// Checks the folder under the id, moves a differing one aside, and writes
/// and verifies a temporary folder. Nothing gets the id here.
pub(crate) fn prepare(
    parent: &OwnedFd,
    id: &Id,
    generation: &Files,
    operation: &Id,
    owner: u32,
    read: Reader,
) -> Result<Staging, ExecutorError> {
    let generations = files::open_child_directory(parent, "generations", owner)?;
    let quarantined = match examine(&generations, id, generation, owner, read)? {
        Existing::Absent => None,
        Existing::Identical => return Ok(Staging::Reused),
        Existing::Differs => Some(quarantine(&generations, id, operation)?),
    };
    let temporary = format!("{}{STAGING_MARK}{}", id.as_str(), random_hex()?);
    let identity = write_temporary(&generations, &temporary, generation, owner, read)?;
    Ok(Staging::Ready {
        temporary,
        quarantined,
        identity,
    })
}

/// Renames the temporary folder of [`prepare`] to the id, never over an
/// existing entry, and syncs `generations`.
pub(crate) fn publish(
    parent: &OwnedFd,
    id: &Id,
    staging: Staging,
    owner: u32,
) -> Result<Staged, ExecutorError> {
    let Staging::Ready {
        temporary,
        quarantined,
        identity,
    } = staging
    else {
        return Ok(Staged::Reused);
    };
    let generations = files::open_child_directory(parent, "generations", owner)?;
    rename_verified(&generations, &temporary, id.as_str(), identity)?;
    Ok(quarantined.map_or(Staged::Written, Staged::Quarantined))
}

/// Renames the verified directory without replacing an existing entry.
pub(crate) fn rename_verified(
    parent: &OwnedFd,
    source: &str,
    destination: &str,
    identity: (u64, u64),
) -> Result<(), ExecutorError> {
    check_identity(parent, source, identity)?;
    match fs::renameat_with(
        parent,
        source,
        parent,
        destination,
        fs::RenameFlags::NOREPLACE,
    ) {
        Ok(()) => {}
        // Something took the id after the check; the temporary folder stays.
        Err(rustix::io::Errno::EXIST) => return Err(ExecutorError::Collision),
        Err(_) => return Err(ExecutorError::StepFailed),
    }
    fs::fsync(parent).map_err(|_| ExecutorError::StepFailed)?;
    // A swap between the check and the rename is refused before any switch.
    check_identity(parent, destination, identity)
}

/// W394: `name` is the verified folder itself (a folder, not followed,
/// with the recorded device and inode), or the staging is a collision.
fn check_identity(
    generations: &OwnedFd,
    name: &str,
    identity: (u64, u64),
) -> Result<(), ExecutorError> {
    let stat = fs::statat(generations, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| ExecutorError::Collision)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || (stat.st_dev, stat.st_ino) != identity
    {
        return Err(ExecutorError::Collision);
    }
    Ok(())
}

/// What is under the id now.
enum Existing {
    Absent,
    Identical,
    Differs,
}

fn examine(
    generations: &OwnedFd,
    id: &Id,
    generation: &Files,
    owner: u32,
    read: Reader,
) -> Result<Existing, ExecutorError> {
    let stat = match fs::statat(generations, id.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) => return Ok(Existing::Absent),
        Err(_) => return Err(ExecutorError::StepFailed),
    };
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != owner
        || stat.st_mode & 0o022 != 0
    {
        return Err(ExecutorError::Collision);
    }
    let directory = files::open_child_directory(generations, id.as_str(), owner)
        .map_err(|_| ExecutorError::Collision)?;
    match read(&directory, owner) {
        Ok(stored) if stored == *generation => Ok(Existing::Identical),
        Ok(_) => Ok(Existing::Differs),
        Err(_) => Err(ExecutorError::Collision),
    }
}

/// Renames the folder under the id to `<id>.quarantine-<operation>`, never
/// over an existing entry, and syncs `generations`. Returns the new name.
fn quarantine(generations: &OwnedFd, id: &Id, operation: &Id) -> Result<String, ExecutorError> {
    let name = format!("{}{QUARANTINE_MARK}{}", id.as_str(), operation.as_str());
    match fs::renameat_with(
        generations,
        id.as_str(),
        generations,
        name.as_str(),
        fs::RenameFlags::NOREPLACE,
    ) {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => return Err(ExecutorError::Collision),
        Err(_) => return Err(ExecutorError::StepFailed),
    }
    fs::fsync(generations).map_err(|_| ExecutorError::StepFailed)?;
    Ok(name)
}

/// Creates the temporary folder exclusively, writes and syncs each file and
/// the folder, and compares the files read back with the render. Returns
/// the device and inode of the folder.
pub(crate) fn write_temporary(
    generations: &OwnedFd,
    temporary: &str,
    generation: &Files,
    owner: u32,
    read: Reader,
) -> Result<(u64, u64), ExecutorError> {
    let failed = |_| ExecutorError::StepFailed;
    fs::mkdirat(generations, temporary, Mode::from_raw_mode(0o755)).map_err(failed)?;
    let directory = files::open_child_directory(generations, temporary, owner)?;
    fs::fchmod(&directory, Mode::from_raw_mode(0o755)).map_err(failed)?;
    for (name, bytes) in generation {
        let fd = fs::openat(
            &directory,
            name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o644),
        )
        .map_err(failed)?;
        fs::fchmod(&fd, Mode::from_raw_mode(0o644)).map_err(failed)?;
        let mut file = std::fs::File::from(fd);
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| ExecutorError::StepFailed)?;
    }
    fs::fsync(&directory).map_err(failed)?;
    if read(&directory, owner)? != *generation {
        return Err(ExecutorError::StepFailed);
    }
    let stat = fs::fstat(&directory).map_err(failed)?;
    Ok((stat.st_dev, stat.st_ino))
}

pub(crate) fn leftovers_in(generations: &OwnedFd) -> Result<Vec<String>, ExecutorError> {
    let unavailable = |_| ExecutorError::RegistryUnavailable;
    let mut names = Vec::new();
    for entry in fs::Dir::read_from(generations).map_err(unavailable)? {
        let name = entry
            .map_err(unavailable)?
            .file_name()
            .to_string_lossy()
            .into_owned();
        if name.contains(STAGING_MARK) || name.contains(QUARANTINE_MARK) {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// 16 hex characters from the kernel's random source.
pub(crate) fn random_hex() -> Result<String, ExecutorError> {
    let mut random = [0_u8; 8];
    rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty())
        .map_err(|_| ExecutorError::Unavailable)?;
    Ok(random.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Atomically repoints `current` at `generations/<id>`: a temporary
/// symlink, `renameat` over `current`, then a directory fsync.
pub fn switch(parent: &OwnedFd, id: &Id) -> Result<(), ExecutorError> {
    let temporary = format!("current.next-{}", random_hex()?);
    let link = format!("generations/{}", id.as_str());
    fs::symlinkat(link.as_str(), parent, temporary.as_str())
        .map_err(|_| ExecutorError::StepFailed)?;
    if fs::renameat(parent, temporary.as_str(), parent, "current").is_err() {
        let _ = fs::unlinkat(parent, temporary.as_str(), AtFlags::empty());
        return Err(ExecutorError::StepFailed);
    }
    fs::fsync(parent).map_err(|_| ExecutorError::StepFailed)
}

/// The restore when no earlier generation existed: removes `current` when it
/// is a symlink. Absent is already restored; any other file type is drift.
pub fn clear_current(parent: &OwnedFd) -> Result<(), ExecutorError> {
    match fs::statat(parent, "current", AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::Symlink => {}
        _ => return Err(ExecutorError::Drift),
    }
    match fs::unlinkat(parent, "current", AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => {}
        Err(_) => return Err(ExecutorError::StepFailed),
    }
    fs::fsync(parent).map_err(|_| ExecutorError::StepFailed)
}
