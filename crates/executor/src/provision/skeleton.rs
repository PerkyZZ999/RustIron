//! W274 (B02): provision step 3 labels the exact skeleton step 2 created,
//! through descriptors, instead of a root `restorecon -R` walk over the site;
//! W275 does the same for a restore probe's sandbox before any content.
//!
//! Before the label step no site process exists (PHP units come in step 7),
//! so the tree should still be the root-made skeleton; this module checks
//! that instead of assuming it. Every entry is opened without following
//! links and labelled through that descriptor, so what is labelled is what
//! was checked. The fcontext rules stay: they are what a later `restorecon`
//! or an operator would apply, and the labels written here equal them.

use rustix::{
    fd::OwnedFd,
    fs::{self, Dir, FileType, Mode, OFlags, XattrFlags},
};

use crate::ExecutorError;

const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// Type for everything under the site root (`<root>(/.*)?`).
pub(crate) const CONTENT: &str = "httpd_sys_content_t";
/// Type for the writable directories (`<root>/(tmp|logs)(/.*)?`).
pub(crate) const READ_WRITE: &str = "httpd_sys_rw_content_t";

/// One directory of a skeleton, directly below its root: its type and the
/// only entries it may hold (single-link regular files of the same type).
pub(crate) struct SkeletonDir {
    name: &'static str,
    kind: &'static str,
    files: &'static [&'static str],
}

/// The directories a skeleton root holds, sorted by name; nothing else.
pub(crate) type Layout = &'static [SkeletonDir];

/// What provision step 2 creates below a site root (W274).
pub(crate) const SITE: Layout = &[
    SkeletonDir {
        name: "errors",
        kind: CONTENT,
        files: &["503.html"],
    },
    SkeletonDir {
        name: "html",
        kind: CONTENT,
        files: &[],
    },
    SkeletonDir {
        name: "logs",
        kind: READ_WRITE,
        files: &[],
    },
    SkeletonDir {
        name: "private",
        kind: CONTENT,
        files: &[],
    },
    SkeletonDir {
        name: "tmp",
        kind: READ_WRITE,
        files: &[],
    },
];

/// What a restore probe's sandbox holds before any content (W275).
pub(crate) const PROBE: Layout = &[SkeletonDir {
    name: "tmp",
    kind: READ_WRITE,
    files: &[],
}];

/// One opened skeleton entry below the root and the type it must carry.
pub(crate) struct Entry {
    /// The descriptor that was checked and is labelled.
    pub(crate) fd: OwnedFd,
    /// SELinux type from the step's fcontext rules.
    pub(crate) kind: &'static str,
}

/// Sorted names in `dir`, refusing more than `limit` entries or non-UTF-8.
fn names(dir: &OwnedFd, limit: usize) -> Result<Vec<String>, ExecutorError> {
    let failed = ExecutorError::StepFailed;
    let mut out = Vec::new();
    for entry in Dir::read_from(dir).map_err(|_| failed)? {
        let entry = entry.map_err(|_| failed)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if out.len() == limit {
            return Err(failed);
        }
        out.push(String::from_utf8(name.to_vec()).map_err(|_| failed)?);
    }
    out.sort();
    Ok(out)
}

/// Opens and checks the skeleton below `root`: exactly the layout's
/// directories, each holding only its listed files (single-link regular),
/// nothing else at any depth, and no links followed. Anything else is
/// `StepFailed`. Each directory's files come before it in the result.
pub(crate) fn open_skeleton(root: &OwnedFd, layout: Layout) -> Result<Vec<Entry>, ExecutorError> {
    let failed = ExecutorError::StepFailed;
    if names(root, layout.len())? != layout.iter().map(|d| d.name).collect::<Vec<_>>() {
        return Err(failed);
    }
    let mut entries = Vec::new();
    for dir in layout {
        let fd = fs::openat(root, dir.name, DIRECTORY, Mode::empty()).map_err(|_| failed)?;
        if names(&fd, dir.files.len())? != dir.files {
            return Err(failed);
        }
        for file in dir.files {
            // NONBLOCK: a FIFO here must fail the type check, not hang.
            let file = fs::openat(
                &fd,
                *file,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| failed)?;
            let stat = fs::fstat(&file).map_err(|_| failed)?;
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile || stat.st_nlink != 1
            {
                return Err(failed);
            }
            entries.push(Entry {
                fd: file,
                kind: dir.kind,
            });
        }
        entries.push(Entry { fd, kind: dir.kind });
    }
    Ok(entries)
}

/// W277: after labelling, the tree must still be exactly the skeleton and
/// every entry the same object that was labelled. The fcontext rules take
/// seconds to add, and anything created in that window would otherwise keep
/// its creation label, which no recursive relabel fixes any more.
pub(crate) fn unchanged(
    root: &OwnedFd,
    layout: Layout,
    labelled: &[Entry],
) -> Result<(), ExecutorError> {
    let identities = |entries: &[Entry]| {
        entries
            .iter()
            .map(|entry| fs::fstat(&entry.fd).map(|stat| (stat.st_dev, stat.st_ino)))
            .collect::<Result<Vec<_>, _>>()
    };
    match (
        identities(&open_skeleton(root, layout)?),
        identities(labelled),
    ) {
        (Ok(now), Ok(then)) if now == then => Ok(()),
        _ => Err(ExecutorError::StepFailed),
    }
}

/// Full context the step's fcontext rules give a type at the site level.
pub(crate) fn context(kind: &str, level: &str) -> String {
    format!("system_u:object_r:{kind}:{level}")
}

/// Writes one label through a descriptor.
pub(crate) type SetLabel<'a> = &'a dyn Fn(&OwnedFd, &[u8]) -> Result<(), ExecutorError>;
/// Reads one label through a descriptor; unreadable is `None`.
pub(crate) type GetLabel<'a> = &'a dyn Fn(&OwnedFd) -> Option<Vec<u8>>;

/// Labels the root and every checked entry, then reads each label back.
/// A write or read-back mismatch is `StepFailed`; nothing is retried.
pub(crate) fn label_skeleton(
    root: &OwnedFd,
    entries: &[Entry],
    level: &str,
    set: SetLabel<'_>,
    get: GetLabel<'_>,
) -> Result<(), ExecutorError> {
    let all = || std::iter::once((root, CONTENT)).chain(entries.iter().map(|e| (&e.fd, e.kind)));
    for (fd, kind) in all() {
        set(fd, context(kind, level).as_bytes())?;
    }
    for (fd, kind) in all() {
        if get(fd).as_deref() != Some(context(kind, level).as_bytes()) {
            return Err(ExecutorError::StepFailed);
        }
    }
    Ok(())
}

/// The live writer: `fsetxattr(security.selinux)` on the open descriptor,
/// the same kernel check `restorecon` made in this domain.
pub(crate) fn set_label(fd: &OwnedFd, label: &[u8]) -> Result<(), ExecutorError> {
    fs::fsetxattr(fd, "security.selinux", label, XattrFlags::empty())
        .map_err(|_| ExecutorError::StepFailed)
}

/// The live reader: `fgetxattr(security.selinux)`, trailing NUL dropped.
pub(crate) fn get_label(fd: &OwnedFd) -> Option<Vec<u8>> {
    let mut buffer = vec![0u8; 256];
    let length = fs::fgetxattr(fd, "security.selinux", &mut buffer).ok()?;
    buffer.truncate(length);
    if buffer.last() == Some(&0) {
        buffer.pop();
    }
    Some(buffer)
}

#[cfg(test)]
#[path = "skeleton_tests.rs"]
mod tests;
