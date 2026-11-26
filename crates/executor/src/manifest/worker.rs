//! In-job manifest walk: reads the archive `restic dump` streams, hashes each
//! regular file's content, and writes one closed line per entry. Runs only as
//! the site account in the capture domain; root reads its lines, never the
//! content.
use std::io::{Read, Write};

use sha2::{Digest, Sha256};

use super::{
    format::{
        self, End, Entry, Kind, MAX_ENTRIES, MAX_PATH_BYTES, MAX_REGULAR_BYTES, MAX_STREAM_BYTES,
    },
    tar::{Archive, Error},
};

/// Room kept for the `end` line.
const END_RESERVE: usize = 256;

/// Bounds the walk stops at (marking the list truncated).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub(crate) entries: u64,
    pub(crate) path_bytes: usize,
    pub(crate) regular_bytes: u64,
    pub(crate) stream_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            entries: MAX_ENTRIES,
            path_bytes: MAX_PATH_BYTES,
            regular_bytes: MAX_REGULAR_BYTES,
            stream_bytes: MAX_STREAM_BYTES,
        }
    }
}

/// The fixed restic argument list for one snapshot (read-only, no lock, no
/// local cache, the whole snapshot as a tar stream on stdout).
pub(crate) fn restic_arguments(snapshot: &str) -> Option<[&str; 7]> {
    (snapshot.len() == 64
        && snapshot
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    .then_some([
        "dump",
        "--no-lock",
        "--no-cache",
        "--archive",
        "tar",
        snapshot,
        "/",
    ])
}

/// Walks the archive, writing entry lines to `out`; returns the summary for
/// the `end` line. An archive error is an error, never a short list.
pub(crate) fn walk(input: impl Read, out: &mut impl Write, limits: Limits) -> Result<End, Error> {
    let mut archive = Archive::new(input);
    let mut end = End {
        entries: 0,
        regular_bytes: 0,
        truncated: false,
    };
    let mut written = 0_usize;
    while let Some(header) = archive.next()? {
        if header.path.is_empty() {
            archive.content(|_| {})?;
            continue;
        }
        let file = header.kind == Kind::File;
        if end.entries >= limits.entries
            || header.path.len() > limits.path_bytes
            || (file
                && end
                    .regular_bytes
                    .checked_add(header.size)
                    .is_none_or(|total| total > limits.regular_bytes))
        {
            end.truncated = true;
            break;
        }
        let mut entry = Entry {
            path: format::encode_path(&header.path),
            kind: header.kind,
            size: if file { header.size } else { 0 },
            sha256: file.then(|| "0".repeat(64)),
            mode: header.mode,
        };
        let length = format::line(&entry).len() + 1;
        if written + length + END_RESERVE > limits.stream_bytes {
            end.truncated = true;
            break;
        }
        if file {
            let mut hasher = Sha256::new();
            archive.content(|chunk| hasher.update(chunk))?;
            let digest: [u8; 32] = hasher.finalize().into();
            entry.sha256 = Some(digest.iter().map(|b| format!("{b:02x}")).collect());
        } else {
            archive.content(|_| {})?;
        }
        let text = format::line(&entry);
        out.write_all(text.as_bytes()).map_err(|_| Error::Io)?;
        out.write_all(b"\n").map_err(|_| Error::Io)?;
        written += length;
        end.entries += 1;
        end.regular_bytes += entry.size;
    }
    Ok(end)
}
