//! Descriptor-relative ownership census of a tenant tree (W210, B02).
//!
//! Replaces the root `find` walks after an unpack: it opens every directory
//! with `O_NOFOLLOW` relative to its parent, never leaves the device, checks
//! that the opened directory is the one just stat'ed (a swap fails closed),
//! and stops at fixed entry/depth bounds instead of walking forever.
use rustix::{
    fd::OwnedFd,
    fs::{self, AtFlags, Dir, FileType, Mode, OFlags},
};

use crate::ExecutorError;

const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// Walk bounds; exceeding one is an error, never a short count.
#[derive(Clone, Copy)]
pub(crate) struct Bounds {
    pub(crate) entries: u64,
    pub(crate) depth: u32,
}

/// Recipe-sized defaults (WordPress is ~3,500 entries, depth < 12).
pub(crate) const BOUNDS: Bounds = Bounds {
    entries: 50_000,
    depth: 32,
};

/// What the walk found below (not including) the start directory.
#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct Census {
    /// Single-link regular files owned by the owner.
    pub(crate) owned_files: u64,
    /// Entries not owned by the owner, or of a kind a recipe never holds
    /// (symlink, device, fifo, socket, multi-link file).
    pub(crate) foreign: u64,
    /// Directories and regular files whose SELinux label is not the expected
    /// one or cannot be read (only counted by [`census_labelled`]).
    pub(crate) mislabelled: u64,
}

/// Reads one entry's `security.selinux` without following it.
pub(crate) type LabelOf<'a> = &'a dyn Fn(&OwnedFd, &std::ffi::CStr) -> Option<Vec<u8>>;

/// The live label reader: `lgetxattr` on `/proc/self/fd/N/NAME`, so the
/// parent is the already-opened directory and the last component is not
/// followed. A trailing NUL is dropped.
pub(crate) fn label_of(dir: &OwnedFd, name: &std::ffi::CStr) -> Option<Vec<u8>> {
    read_attribute(dir, name, "security.selinux")
}

/// One extended attribute of `name` in `dir`, without following it. The
/// name is used as raw bytes: a Linux name need not be UTF-8 (W328 c3e).
fn read_attribute(dir: &OwnedFd, name: &std::ffi::CStr, attribute: &str) -> Option<Vec<u8>> {
    use rustix::fd::AsRawFd;
    let mut path = format!("/proc/self/fd/{}/", dir.as_raw_fd()).into_bytes();
    path.extend_from_slice(name.to_bytes());
    let path = std::ffi::CString::new(path).ok()?;
    let mut buffer = vec![0u8; 256];
    let length = fs::lgetxattr(path.as_c_str(), attribute, &mut buffer).ok()?;
    buffer.truncate(length);
    if buffer.last() == Some(&0) {
        buffer.pop();
    }
    Some(buffer)
}

/// `census` (test builds) that also checks every directory and regular file carries
/// `want` (the label the job's context gives at creation, W213), counting
/// the rest in [`Census::mislabelled`]. Nothing is relabelled.
pub(crate) fn census_labelled(
    dir: &OwnedFd,
    owner: u32,
    want: &[u8],
    label: LabelOf<'_>,
    bounds: Bounds,
) -> Result<Census, ExecutorError> {
    run(
        dir,
        owner,
        bounds,
        Some((want, label)),
        &mut |_: &OwnedFd, _: &str| {},
    )
}

#[cfg(test)]
pub(crate) fn census(dir: &OwnedFd, owner: u32, bounds: Bounds) -> Result<Census, ExecutorError> {
    census_with(dir, owner, bounds, &mut |_: &OwnedFd, _: &str| {})
}

/// `before_open` runs between the stat and the open of each subdirectory, so
/// tests can swap the entry exactly in the race window.
#[cfg(test)]
pub(crate) fn census_with(
    dir: &OwnedFd,
    owner: u32,
    bounds: Bounds,
    before_open: &mut dyn FnMut(&OwnedFd, &str),
) -> Result<Census, ExecutorError> {
    run(dir, owner, bounds, None, before_open)
}

fn run(
    dir: &OwnedFd,
    owner: u32,
    bounds: Bounds,
    labels: Option<(&[u8], LabelOf<'_>)>,
    before_open: &mut dyn FnMut(&OwnedFd, &str),
) -> Result<Census, ExecutorError> {
    let start = fs::fstat(dir).map_err(|_| ExecutorError::StepFailed)?;
    let mut state = State {
        census: Census::default(),
        entries: 0,
        ancestors: vec![(start.st_dev, start.st_ino)],
        labels,
    };
    walk(dir, start.st_dev, 0, owner, bounds, &mut state, before_open)?;
    Ok(state.census)
}

struct State<'a> {
    census: Census,
    entries: u64,
    ancestors: Vec<(u64, u64)>,
    labels: Option<(&'a [u8], LabelOf<'a>)>,
}

fn walk(
    fd: &OwnedFd,
    device: u64,
    depth: u32,
    owner: u32,
    bounds: Bounds,
    state: &mut State<'_>,
    before_open: &mut dyn FnMut(&OwnedFd, &str),
) -> Result<(), ExecutorError> {
    let failed = ExecutorError::StepFailed;
    let dir = Dir::read_from(fd).map_err(|_| failed)?;
    for entry in dir {
        let entry = entry.map_err(|_| failed)?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        state.entries += 1;
        if state.entries > bounds.entries {
            return Err(failed);
        }
        let stat = fs::statat(fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| failed)?;
        if stat.st_dev != device {
            return Err(failed);
        }
        let owned = stat.st_uid == owner;
        let kind = FileType::from_raw_mode(stat.st_mode);
        if state.labels.is_some_and(|(want, label)| {
            matches!(kind, FileType::RegularFile | FileType::Directory)
                && label(fd, name).as_deref() != Some(want)
        }) {
            state.census.mislabelled += 1;
        }
        match kind {
            FileType::RegularFile if owned && stat.st_nlink == 1 => state.census.owned_files += 1,
            FileType::Directory => {
                if !owned {
                    state.census.foreign += 1;
                }
                if depth + 1 > bounds.depth {
                    return Err(failed);
                }
                // The race hook is test-only and takes text; production
                // walks names as raw bytes, UTF-8 or not (W328 c3e).
                if let Ok(text) = name.to_str() {
                    before_open(fd, text);
                }
                let next = fs::openat(fd, name, DIRECTORY, Mode::empty()).map_err(|_| failed)?;
                let opened = fs::fstat(&next).map_err(|_| failed)?;
                let identity = (opened.st_dev, opened.st_ino);
                if identity != (stat.st_dev, stat.st_ino) || state.ancestors.contains(&identity) {
                    return Err(failed);
                }
                state.ancestors.push(identity);
                walk(&next, device, depth + 1, owner, bounds, state, before_open)?;
                state.ancestors.pop();
            }
            _ => state.census.foreign += 1,
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "census_tests.rs"]
mod tests;
