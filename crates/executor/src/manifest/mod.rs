//! W203 capture artifact manifest: the root-side half. The worker's lines are
//! rebuilt into the canonical manifest here, checked against the snapshot's
//! sources and the secret shapes, and stored content-addressed outside
//! SQLite. Any refusal drops the manifest; the capture outcome never changes.
use std::path::Path;

use rustix::fs::{self, Mode, OFlags};

use crate::{ExecutorError, files};

#[expect(
    dead_code,
    reason = "worker actions run in the capture-manifest binary"
)]
pub(crate) mod app_sqlite;
pub(crate) mod format;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the request half runs only in the worker")
)]
pub(crate) mod lock;
// W515 (D-084): the update's recipe check reads its first member as root.
pub(crate) mod tar;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod worker;

pub(crate) use format::Built;

/// The worker program inside the capture binaries directory.
pub(crate) const WORKER: &str = "capture-manifest";

/// The canonical manifest of a capture's worker output, or `None` when the
/// stream is malformed or oversized, lists a path outside the snapshot's two
/// sources (`<root>/html` and the named dump), or carries a secret shape.
pub(crate) fn from_worker(stream: &[u8], root: &str, dump: &str) -> Option<Built> {
    from_worker_for(stream, root, "html", dump)
}

/// As [`from_worker`] with an explicit content subdirectory (`html` for
/// WordPress/static sites, `data` for P27/EmDash apps; W601).
pub(crate) fn from_worker_for(
    stream: &[u8],
    root: &str,
    subdir: &str,
    dump: &str,
) -> Option<Built> {
    let built = format::build(stream)?;
    accept(built, root, subdir, dump)
}

fn accept(built: Built, root: &str, subdir: &str, dump: &str) -> Option<Built> {
    let content = format!("{}/{subdir}", root.trim_start_matches('/'));
    let dump = dump.trim_start_matches('/');
    let text = std::str::from_utf8(&built.bytes).ok()?;
    for line in text.lines() {
        let entry: format::Entry = serde_json::from_str(line).ok()?;
        let raw = format::decode_path(&entry.path)?;
        let inside = |source: &str| {
            raw == source.as_bytes()
                || raw.starts_with(format!("{source}/").as_bytes())
                // Ancestors of a source are archived as directories.
                || (entry.kind == format::Kind::Dir
                    && source.as_bytes().starts_with(&raw)
                    && source.as_bytes().get(raw.len()) == Some(&b'/'))
        };
        if !inside(&content) && raw != dump.as_bytes() && !inside(dump) {
            return None;
        }
    }
    if !crate::redaction::secret_shapes(text).is_empty() {
        return None;
    }
    Some(built)
}

/// Re-checks a manifest the helper relayed: the canonical shape, the digest
/// and counts it claims, and the same source and secret-shape refusals.
#[cfg(test)]
pub(crate) fn from_relay(
    bytes: Vec<u8>,
    sha256: &str,
    truncated: bool,
    root: &str,
    dump: &str,
) -> Option<Built> {
    from_relay_for(bytes, sha256, truncated, root, "html", dump)
}

/// As `from_relay` (test builds) with an explicit content subdirectory (`html` or `data`).
pub(crate) fn from_relay_for(
    bytes: Vec<u8>,
    sha256: &str,
    truncated: bool,
    root: &str,
    subdir: &str,
    dump: &str,
) -> Option<Built> {
    let (entries, regular_bytes) = format::verify(&bytes)?;
    if format::digest_hex(&bytes) != sha256 {
        return None;
    }
    accept(
        Built {
            sha256: sha256.to_owned(),
            entries,
            regular_bytes,
            truncated,
            bytes,
        },
        root,
        subdir,
        dump,
    )
}

/// Stores the canonical bytes as `<dir>/<sha256>.jsonl`, owner-only 0600,
/// with the trusted directory's group rather than the process group (W203
/// follow-up: the unit `Group=` must not be named on a file it cannot read;
/// the installed directory is setgid so that needs no capability, W288):
/// written to an exclusively created temporary name, synced, then renamed
/// without replacing, and the directory synced. A crash leaves at most a
/// temporary file, never a partial file under the digest name. An existing
/// file under that name must hold the same bytes.
pub(crate) fn store(directory: &Path, owner: u32, built: &Built) -> Result<(), ExecutorError> {
    let failed = |_| ExecutorError::StepFailed;
    let dir = files::open_trusted_directory(directory, owner)?;
    let name = format!("{}.jsonl", built.sha256);
    let mut random = [0_u8; 8];
    rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty())
        .map_err(|_| ExecutorError::Unavailable)?;
    let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let temporary = format!(".{}.{suffix}.tmp", built.sha256);
    let fd = fs::openat(
        &dir,
        temporary.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(failed)?;
    // W288: a setgid directory already gives the new file its group, so an
    // executor with no CAP_CHOWN (whose unit `Group=` is not the directory's)
    // needs no chown. Otherwise the group is set here, and a refusal fails.
    let group = fs::fstat(&dir).map_err(failed)?.st_gid;
    let grouped = if fs::fstat(&fd).map_err(failed)?.st_gid == group {
        Ok(())
    } else {
        fs::fchown(&fd, None, Some(rustix::process::Gid::from_raw(group)))
    };
    let mut file = std::fs::File::from(fd);
    let written = grouped
        .map_err(std::io::Error::from)
        .and_then(|()| std::io::Write::write_all(&mut file, &built.bytes))
        .and_then(|()| file.sync_all());
    drop(file);
    let placed = written
        .map_err(|_| ExecutorError::StepFailed)
        .and_then(|()| {
            match fs::renameat_with(
                &dir,
                temporary.as_str(),
                &dir,
                name.as_str(),
                fs::RenameFlags::NOREPLACE,
            ) {
                Ok(()) => Ok(()),
                Err(rustix::io::Errno::EXIST) => {
                    let existing = files::read_child(
                        &dir,
                        &name,
                        owner,
                        files::Exposure::Private,
                        format::MAX_MANIFEST_BYTES,
                    )?;
                    if existing == built.bytes {
                        Ok(())
                    } else {
                        Err(ExecutorError::StepFailed)
                    }
                }
                Err(_) => Err(ExecutorError::StepFailed),
            }
        });
    let _ = fs::unlinkat(&dir, temporary.as_str(), fs::AtFlags::empty());
    placed?;
    fs::fsync(&dir).map_err(failed)
}

/// The journal record for a stored manifest.
pub(crate) fn record(built: &Built) -> rustiron_journal::CaptureManifest {
    rustiron_journal::CaptureManifest {
        sha256: built.sha256.clone(),
        entries: built.entries,
        regular_bytes: built.regular_bytes,
        truncated: built.truncated,
    }
}
