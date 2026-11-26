//! Descriptor-relative, no-follow reads below an independently trusted owner.

use std::{fs::File, io::Read, os::fd::OwnedFd, path::Path};

use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, Stat};

use crate::ExecutorError;

const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const REGULAR: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);

/// Whether group/other may read a file; neither may ever write it.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Exposure {
    /// Owner-only (0600-style) policy and journal inputs.
    Private,
    /// World-readable, owner-writable fixture content.
    Readable,
}

/// Opens an absolute directory one component at a time without following links.
///
/// Every ancestor must be root- or owner-owned and not group/other-writable,
/// except sticky ancestors such as /tmp, which cannot hold the final directory.
/// The final directory must belong to `owner` with no group/other access.
pub(crate) fn open_trusted_directory(path: &Path, owner: u32) -> Result<OwnedFd, ExecutorError> {
    open_final(path, owner, 0o077)
}

/// Like [`open_trusted_directory`], but others may traverse/list the final
/// directory (never write it). Used only for the connectable socket directory.
pub(crate) fn open_traversable_directory(
    path: &Path,
    owner: u32,
) -> Result<OwnedFd, ExecutorError> {
    open_final(path, owner, 0o022)
}

fn open_final(path: &Path, owner: u32, forbidden: u32) -> Result<OwnedFd, ExecutorError> {
    let deny = ExecutorError::AccessDenied;
    if !path.is_absolute() {
        return Err(deny);
    }
    let mut current = fs::open("/", DIRECTORY, Mode::empty()).map_err(|_| deny)?;
    check_ancestor(&current, owner)?;
    let mut components = path.components().skip(1).peekable();
    if components.peek().is_none() {
        return Err(deny);
    }
    while let Some(component) = components.next() {
        let std::path::Component::Normal(name) = component else {
            return Err(deny);
        };
        current = fs::openat(&current, name, DIRECTORY, Mode::empty()).map_err(|_| deny)?;
        if components.peek().is_some() {
            check_ancestor(&current, owner)?;
        }
    }
    let stat = fs::fstat(&current).map_err(|_| deny)?;
    if stat.st_uid != owner || stat.st_mode & forbidden != 0 {
        return Err(deny);
    }
    Ok(current)
}

fn check_ancestor(directory: &OwnedFd, owner: u32) -> Result<(), ExecutorError> {
    let stat = fs::fstat(directory).map_err(|_| ExecutorError::AccessDenied)?;
    let sticky = stat.st_mode & 0o1000 != 0;
    if (stat.st_uid != 0 && stat.st_uid != owner) || (stat.st_mode & 0o022 != 0 && !sticky) {
        return Err(ExecutorError::AccessDenied);
    }
    Ok(())
}

/// Opens a child directory of a trusted descriptor with the same owner rule.
pub(crate) fn open_child_directory(
    parent: &OwnedFd,
    name: &str,
    owner: u32,
) -> Result<OwnedFd, ExecutorError> {
    let directory = fs::openat(parent, name, DIRECTORY, Mode::empty())
        .map_err(|_| ExecutorError::AccessDenied)?;
    let stat = fs::fstat(&directory).map_err(|_| ExecutorError::AccessDenied)?;
    if stat.st_uid != owner || stat.st_mode & 0o022 != 0 {
        return Err(ExecutorError::AccessDenied);
    }
    Ok(directory)
}

/// Verifies private credential metadata without opening or reading its contents.
pub(crate) fn private_regular_stat(
    directory: &OwnedFd,
    name: &str,
    owner: u32,
) -> Result<Stat, ExecutorError> {
    let stat = fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| ExecutorError::AccessDenied)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != owner
        || stat.st_nlink != 1
        || stat.st_mode & 0o077 != 0
        || stat.st_mode & 0o400 == 0
    {
        return Err(ExecutorError::AccessDenied);
    }
    Ok(stat)
}

/// Reads one bounded single-link regular file owned by `owner`.
pub(crate) fn read_child(
    parent: &OwnedFd,
    name: &str,
    owner: u32,
    exposure: Exposure,
    limit: usize,
) -> Result<Vec<u8>, ExecutorError> {
    let deny = ExecutorError::AccessDenied;
    let fd = fs::openat(parent, name, REGULAR, Mode::empty()).map_err(|_| deny)?;
    let stat = fs::fstat(&fd).map_err(|_| deny)?;
    let forbidden = match exposure {
        Exposure::Private => 0o077,
        Exposure::Readable => 0o022,
    };
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != owner
        || stat.st_nlink != 1
        || stat.st_mode & forbidden != 0
    {
        return Err(deny);
    }
    let mut bytes = Vec::new();
    File::from(fd)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ExecutorError::Unavailable)?;
    if bytes.len() > limit {
        return Err(ExecutorError::InvalidRequest);
    }
    Ok(bytes)
}
