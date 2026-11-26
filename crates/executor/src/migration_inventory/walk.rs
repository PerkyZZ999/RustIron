//! Descriptor-relative walk of the exported file tree. It reads file contents
//! only to hash them, never follows a link, and never runs site code.
use rustiron_contracts::{
    approval::Sha256Digest,
    migration::{ExportReason, FileSummary, UploadSummary},
};
use rustix::{
    fd::OwnedFd,
    fs::{self, AtFlags, Dir, FileType, Mode, OFlags},
    io::Errno,
};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

pub(crate) const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const FILE: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NOCTTY)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);
/// WordPress uploads, relative to the exported home tree.
const UPLOADS: &[u8] = b"public_html/wp-content/uploads/";

/// Fixed bounds of one worker run.
pub(crate) struct Limits {
    pub(crate) entries: u64,
    pub(crate) depth: u32,
    pub(crate) time: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            entries: 200_000,
            depth: 64,
            time: Duration::from_secs(120),
        }
    }
}

pub(crate) struct Clock<'a> {
    pub(crate) limits: &'a Limits,
    pub(crate) started: Instant,
}

impl Clock<'_> {
    pub(crate) fn check(&self) -> Result<(), ExportReason> {
        if self.started.elapsed() >= self.limits.time {
            Err(ExportReason::Time)
        } else {
            Ok(())
        }
    }
}

/// One manifest record: the path below the tree root, and the content digest
/// for a regular file or `None` for a directory.
type Record = (Vec<u8>, Option<[u8; 32]>);

struct Walk<'a> {
    clock: &'a Clock<'a>,
    device: u64,
    entries: u64,
    bytes: u64,
    unsafe_entries: u64,
    upload_files: u64,
    upload_bytes: u64,
    records: Vec<Record>,
    ancestors: Vec<(u64, u64)>,
}

/// Walks the opened tree root and returns its file and uploads summaries.
pub(crate) fn tree(
    root: &OwnedFd,
    clock: &Clock<'_>,
) -> Result<(FileSummary, UploadSummary), ExportReason> {
    let stat = fs::fstat(root).map_err(|_| ExportReason::Io)?;
    let mut walk = Walk {
        clock,
        device: stat.st_dev,
        entries: 0,
        bytes: 0,
        unsafe_entries: 0,
        upload_files: 0,
        upload_bytes: 0,
        records: Vec::new(),
        ancestors: vec![(stat.st_dev, stat.st_ino)],
    };
    walk.directory(root, &mut Vec::new(), 0)?;
    walk.records.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    Ok((
        FileSummary {
            entries: walk.entries,
            bytes: walk.bytes,
            manifest_sha256: Sha256Digest::from_bytes(manifest(&walk.records)),
            unsafe_entries: walk.unsafe_entries,
        },
        UploadSummary {
            files: walk.upload_files,
            bytes: walk.upload_bytes,
        },
    ))
}

/// The manifest digest: SHA-256 over the path-sorted records, each a
/// big-endian u32 path length, the path, then `d`, or `f` and the 32-byte
/// content digest. Slice 3 computes the same over the imported tree.
pub(crate) fn manifest(records: &[Record]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for (path, digest) in records {
        let length = u32::try_from(path.len()).unwrap_or(u32::MAX);
        hash.update(length.to_be_bytes());
        hash.update(path);
        match digest {
            Some(digest) => {
                hash.update(b"f");
                hash.update(digest);
            }
            None => hash.update(b"d"),
        }
    }
    hash.finalize().into()
}

impl Walk<'_> {
    fn directory(
        &mut self,
        fd: &OwnedFd,
        path: &mut Vec<u8>,
        depth: u32,
    ) -> Result<(), ExportReason> {
        let dir = Dir::read_from(fd).map_err(|_| ExportReason::Io)?;
        for entry in dir {
            self.clock.check()?;
            let entry = entry.map_err(|_| ExportReason::Io)?;
            let name = entry.file_name();
            let bytes = name.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            if self.entries >= self.clock.limits.entries {
                return Err(ExportReason::Entries);
            }
            self.entries += 1;
            let stat =
                fs::statat(fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| ExportReason::Io)?;
            if stat.st_dev != self.device {
                return Err(ExportReason::Unsupported);
            }
            let start = path.len();
            if start > 0 {
                path.push(b'/');
            }
            path.extend_from_slice(bytes);
            let privileged = stat.st_mode & 0o6000 != 0;
            match FileType::from_raw_mode(stat.st_mode) {
                FileType::RegularFile if stat.st_nlink == 1 && !privileged => {
                    let opened =
                        fs::openat(fd, name, FILE, Mode::empty()).map_err(|_| ExportReason::Io)?;
                    let digest = self.hash(&opened, (stat.st_dev, stat.st_ino), stat.st_size)?;
                    let size = u64::try_from(stat.st_size).map_err(|_| ExportReason::Io)?;
                    self.bytes += size;
                    if path.starts_with(UPLOADS) {
                        self.upload_files += 1;
                        self.upload_bytes += size;
                    }
                    self.records.push((path.clone(), Some(digest)));
                }
                FileType::Directory if !privileged => {
                    if depth >= self.clock.limits.depth {
                        return Err(ExportReason::Depth);
                    }
                    let next = fs::openat(fd, name, DIRECTORY, Mode::empty())
                        .map_err(|_| ExportReason::Io)?;
                    let opened = fs::fstat(&next).map_err(|_| ExportReason::Io)?;
                    let identity = (opened.st_dev, opened.st_ino);
                    if identity != (stat.st_dev, stat.st_ino) || self.ancestors.contains(&identity)
                    {
                        return Err(ExportReason::Changed);
                    }
                    self.records.push((path.clone(), None));
                    self.ancestors.push(identity);
                    self.directory(&next, path, depth + 1)?;
                    self.ancestors.pop();
                }
                // Links, hard-linked files, special files, and setuid or setgid
                // entries are counted and never opened or descended.
                _ => self.unsafe_entries += 1,
            }
            path.truncate(start);
        }
        Ok(())
    }

    fn hash(
        &self,
        fd: &OwnedFd,
        identity: (u64, u64),
        size: i64,
    ) -> Result<[u8; 32], ExportReason> {
        let opened = fs::fstat(fd).map_err(|_| ExportReason::Io)?;
        if (opened.st_dev, opened.st_ino) != identity
            || FileType::from_raw_mode(opened.st_mode) != FileType::RegularFile
        {
            return Err(ExportReason::Changed);
        }
        let mut hash = Sha256::new();
        let mut buffer = vec![0; 64 * 1024];
        let mut total: i64 = 0;
        loop {
            self.clock.check()?;
            match rustix::io::read(fd, &mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    hash.update(&buffer[..read]);
                    total += i64::try_from(read).map_err(|_| ExportReason::Io)?;
                }
                Err(Errno::INTR) => {}
                Err(_) => return Err(ExportReason::Io),
            }
        }
        if total != size {
            return Err(ExportReason::Changed);
        }
        Ok(hash.finalize().into())
    }
}
