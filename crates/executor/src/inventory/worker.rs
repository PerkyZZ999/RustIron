//! Bounded descriptor-relative metadata walk; never executes restored code.
use crate::report::{MAX_DEPTH, MAX_ENTRIES, Reason, Report, Status};
use rustix::{
    fd::OwnedFd,
    fs::{self, AtFlags, Dir, FileType, Mode, OFlags},
};
use std::{
    os::unix::ffi::OsStrExt,
    path::{Component, Path},
    time::{Duration, Instant},
};

pub(super) struct Limits {
    pub(super) entries: u64,
    pub(super) depth: u32,
    pub(super) time: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            entries: MAX_ENTRIES,
            depth: MAX_DEPTH,
            time: Duration::from_secs(30),
        }
    }
}

struct Progress {
    files: u64,
    world_writable: u64,
    extra: u64,
    entries: u64,
    depth: u32,
    started: Instant,
}
const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
/// The capture recipe's two snapshot paths below the site root.
const SITE_PATHS: [&[u8]; 2] = [b"html", b"tmp"];
const DUMP: &str = "rustiron-capture.sql";

/// Walks `site` (relative, below the absolute restore target `restore`).
/// W378: every entry beside the captured paths, from the restore target down
/// to the dump, is counted as an extra path and never descended.
pub(super) fn inventory(restore: &Path, site: &Path, limits: Limits) -> Report {
    inventory_with_identity(
        restore,
        site,
        limits,
        rustix::process::getuid().as_raw(),
        rustix::process::geteuid().as_raw(),
    )
}

fn inventory_with_identity(
    restore: &Path,
    site: &Path,
    limits: Limits,
    real_uid: u32,
    effective_uid: u32,
) -> Report {
    let mut progress = Progress {
        files: 0,
        world_writable: 0,
        extra: 0,
        entries: 0,
        depth: 0,
        started: Instant::now(),
    };
    let result = (|| {
        if real_uid == 0 || effective_uid != real_uid {
            return Err(Reason::Identity);
        }
        if progress.started.elapsed() >= limits.time {
            return Err(Reason::Time);
        }
        let names = relative_names(site)?;
        let mut directory = fs::openat(open_absolute(restore)?, ".", DIRECTORY, Mode::empty())
            .map_err(|_| Reason::Io)?;
        for name in names {
            count_extra(&directory, &[name.as_bytes()], &limits, &mut progress)?;
            directory =
                fs::openat(&directory, name, DIRECTORY, Mode::empty()).map_err(|_| Reason::Io)?;
        }
        let site = directory;
        count_extra(&site, &SITE_PATHS, &limits, &mut progress)?;
        let html = fs::openat(&site, "html", DIRECTORY, Mode::empty()).map_err(|_| Reason::Io)?;
        let stat = fs::fstat(&html).map_err(|_| Reason::Io)?;
        writable_directory(stat.st_mode)?;
        privileged(stat.st_mode)?;
        let mut ancestors = vec![(stat.st_dev, stat.st_ino)];
        walk(
            &html,
            stat.st_dev,
            0,
            &limits,
            &mut progress,
            &mut ancestors,
        )?;
        let tmp = fs::openat(&site, "tmp", DIRECTORY, Mode::empty()).map_err(|_| Reason::Io)?;
        count_extra(&tmp, &[DUMP.as_bytes()], &limits, &mut progress)?;
        match fs::statat(&tmp, DUMP, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat)
                if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
                    && stat.st_nlink == 1 =>
            {
                privileged(stat.st_mode)?;
                Ok(true)
            }
            Ok(_) => Err(Reason::Unsupported),
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(_) => Err(Reason::Io),
        }
    })();
    match result {
        Ok(dump) => Report {
            schema_version: 3,
            status: Status::Complete,
            reason: None,
            files: Some(progress.files),
            dump: Some(dump),
            entries: progress.entries,
            max_depth: progress.depth,
            world_writable: Some(progress.world_writable),
            extra_paths: Some(progress.extra),
        },
        Err(reason) => Report {
            schema_version: 3,
            status: if matches!(reason, Reason::Entries | Reason::Depth | Reason::Time) {
                Status::Limit
            } else {
                Status::Error
            },
            reason: Some(reason),
            files: None,
            dump: None,
            entries: progress.entries,
            max_depth: progress.depth,
            world_writable: None,
            extra_paths: None,
        },
    }
}

/// The site path below the restore target: plain names only, bounded.
fn relative_names(site: &Path) -> Result<Vec<&std::ffi::OsStr>, Reason> {
    let mut names = Vec::new();
    for part in site.components() {
        match part {
            Component::Normal(name) => names.push(name),
            _ => return Err(Reason::Unsupported),
        }
    }
    if names.is_empty() {
        return Err(Reason::Unsupported);
    }
    if names.len() > MAX_DEPTH as usize {
        return Err(Reason::Depth);
    }
    Ok(names)
}

/// Counts the entries of `fd` other than `expected` as extra paths. Their
/// names, types and contents are never read or followed.
fn count_extra(
    fd: &OwnedFd,
    expected: &[&[u8]],
    limits: &Limits,
    progress: &mut Progress,
) -> Result<(), Reason> {
    let dir = Dir::read_from(fd).map_err(|_| Reason::Io)?;
    for entry in dir {
        if progress.started.elapsed() >= limits.time {
            return Err(Reason::Time);
        }
        let entry = entry.map_err(|_| Reason::Io)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." || expected.contains(&name) {
            continue;
        }
        if progress.entries >= limits.entries {
            return Err(Reason::Entries);
        }
        progress.entries += 1;
        progress.extra += 1;
    }
    Ok(())
}

fn open_absolute(path: &Path) -> Result<OwnedFd, Reason> {
    if !path.is_absolute() {
        return Err(Reason::Unsupported);
    }
    let prefix = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut fd = fs::open("/", prefix, Mode::empty()).map_err(|_| Reason::Io)?;
    let mut depth = 0;
    for part in path.components() {
        match part {
            Component::RootDir => {}
            Component::Normal(name) => {
                depth += 1;
                if depth > MAX_DEPTH {
                    return Err(Reason::Depth);
                }
                fd = fs::openat(&fd, name, prefix, Mode::empty()).map_err(|_| Reason::Io)?;
            }
            _ => return Err(Reason::Unsupported),
        }
    }
    Ok(fd)
}

fn walk(
    fd: &OwnedFd,
    device: u64,
    depth: u32,
    limits: &Limits,
    progress: &mut Progress,
    ancestors: &mut Vec<(u64, u64)>,
) -> Result<(), Reason> {
    let dir = Dir::read_from(fd).map_err(|_| Reason::Io)?;
    for entry in dir {
        if progress.started.elapsed() >= limits.time {
            return Err(Reason::Time);
        }
        let entry = entry.map_err(|_| Reason::Io)?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        if progress.entries >= limits.entries {
            return Err(Reason::Entries);
        }
        progress.entries += 1;
        let stat = fs::statat(fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| Reason::Io)?;
        if stat.st_dev != device {
            return Err(Reason::Unsupported);
        }
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::RegularFile if stat.st_nlink == 1 => {
                privileged(stat.st_mode)?;
                progress.files += 1;
                if stat.st_mode & 0o002 != 0 {
                    progress.world_writable += 1;
                }
            }
            FileType::Directory => {
                writable_directory(stat.st_mode)?;
                privileged(stat.st_mode)?;
                if depth >= limits.depth {
                    return Err(Reason::Depth);
                }
                let next =
                    fs::openat(fd, name, DIRECTORY, Mode::empty()).map_err(|_| Reason::Io)?;
                let opened = fs::fstat(&next).map_err(|_| Reason::Io)?;
                let identity = (opened.st_dev, opened.st_ino);
                if identity != (stat.st_dev, stat.st_ino) || ancestors.contains(&identity) {
                    return Err(Reason::Changed);
                }
                progress.depth = progress.depth.max(depth + 1);
                ancestors.push(identity);
                walk(&next, device, depth + 1, limits, progress, ancestors)?;
                ancestors.pop();
            }
            _ => return Err(Reason::Unsupported),
        }
    }
    Ok(())
}

/// W222: setuid and setgid files are refused (owner decision); D-034
/// (W383) refuses setuid and setgid directories too (W378 s6).
/// W232: no restored directory may be writable by others.
fn writable_directory(mode: u32) -> Result<(), Reason> {
    if mode & 0o002 == 0 {
        Ok(())
    } else {
        Err(Reason::WorldWritableDirectory)
    }
}

fn privileged(mode: u32) -> Result<(), Reason> {
    if mode & 0o6000 == 0 {
        Ok(())
    } else {
        Err(Reason::Privileged)
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
