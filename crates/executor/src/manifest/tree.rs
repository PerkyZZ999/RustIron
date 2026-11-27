//! D-078 (W499): the clone's Observe walk. Lists a restored tree in the
//! capture-manifest line format, so root rebuilds the canonical manifest
//! with the same builder ([`super::format::build`]) and compares it with the
//! recorded digest. Runs only as the clone's target account in the capture
//! domain with no network or credentials. It never follows a link, never
//! writes below the tree, and stops at the same bounds as the archive walk.
use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use super::{
    format::{self, End, Entry, Kind},
    tar::Error,
    worker::Limits,
};

/// Deepest directory the walk enters; deeper is an error, not a short list.
const MAX_DEPTH: usize = 64;
/// Room kept for the `end` line.
const END_RESERVE: usize = 256;

/// Walks the tree below `root` (not `root` itself), writing one entry line
/// per member to `out`, and returns the summary for the `end` line.
pub(crate) fn walk(root: &Path, out: &mut impl Write, limits: Limits) -> Result<End, Error> {
    let top = fs::symlink_metadata(root).map_err(|_| Error::Io)?;
    if !top.file_type().is_dir() {
        return Err(Error::Malformed);
    }
    let mut end = End {
        entries: 0,
        regular_bytes: 0,
        truncated: false,
    };
    let mut written = 0_usize;
    let mut pending: Vec<(PathBuf, Vec<u8>, usize)> = vec![(root.to_path_buf(), Vec::new(), 0)];
    while let Some((directory, prefix, depth)) = pending.pop() {
        let mut children: Vec<_> = fs::read_dir(&directory)
            .map_err(|_| Error::Io)?
            .collect::<Result<_, _>>()
            .map_err(|_| Error::Io)?;
        children.sort_by_key(fs::DirEntry::file_name);
        for child in children {
            let name = child.file_name();
            let mut path = prefix.clone();
            if !path.is_empty() {
                path.push(b'/');
            }
            path.extend_from_slice(name.as_bytes());
            let absolute = child.path();
            let meta = fs::symlink_metadata(&absolute).map_err(|_| Error::Io)?;
            let kind = kind_of(&meta.file_type());
            let file = kind == Kind::File;
            if end.entries >= limits.entries
                || path.len() > limits.path_bytes
                || (file
                    && end
                        .regular_bytes
                        .checked_add(meta.len())
                        .is_none_or(|total| total > limits.regular_bytes))
            {
                end.truncated = true;
                return Ok(end);
            }
            let mut entry = Entry {
                path: format::encode_path(&path),
                kind,
                size: if file { meta.len() } else { 0 },
                sha256: file.then(|| "0".repeat(64)),
                mode: meta.mode() & 0o7777,
            };
            let length = format::line(&entry).len() + 1;
            if written + length + END_RESERVE > limits.stream_bytes {
                end.truncated = true;
                return Ok(end);
            }
            if file {
                entry.sha256 = Some(hash_file(&absolute, &meta)?);
            }
            out.write_all(format::line(&entry).as_bytes())
                .and_then(|()| out.write_all(b"\n"))
                .map_err(|_| Error::Io)?;
            written += length;
            end.entries += 1;
            end.regular_bytes += entry.size;
            if kind == Kind::Dir {
                if depth + 1 > MAX_DEPTH {
                    return Err(Error::Malformed);
                }
                pending.push((absolute, path, depth + 1));
            }
        }
    }
    Ok(end)
}

fn kind_of(file_type: &fs::FileType) -> Kind {
    if file_type.is_file() {
        Kind::File
    } else if file_type.is_dir() {
        Kind::Dir
    } else if file_type.is_symlink() {
        Kind::Symlink
    } else {
        debug_assert!(
            file_type.is_fifo()
                || file_type.is_socket()
                || file_type.is_block_device()
                || file_type.is_char_device()
        );
        Kind::Other
    }
}

/// The SHA-256 of one regular file, opened without following a link. The
/// open file must be the listed one and keep its size while it is read.
fn hash_file(path: &Path, listed: &fs::Metadata) -> Result<String, Error> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc_flags())
        .open(path)
        .map_err(|_| Error::Io)?;
    let opened = file.metadata().map_err(|_| Error::Io)?;
    if (opened.dev(), opened.ino(), opened.len()) != (listed.dev(), listed.ino(), listed.len()) {
        return Err(Error::Malformed);
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = file.read(&mut buffer).map_err(|_| Error::Io)?;
        if read == 0 {
            break;
        }
        total += read as u64;
        hasher.update(&buffer[..read]);
    }
    if total != listed.len() {
        return Err(Error::Malformed);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

/// `O_NOFOLLOW | O_NONBLOCK`: a link or a FIFO swapped in is not opened.
fn libc_flags() -> i32 {
    (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// W720: a folder-name part that no other test in this process uses. The
    /// clock alone can repeat across parallel tests.
    fn unique_suffix() -> String {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |time| time.as_nanos());
        let next = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("{nanos}-{next}")
    }

    fn tree() -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "ri-w499-tree-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        fs::create_dir_all(base.join("srv/sites/rs_blog9/html/wp")).unwrap();
        fs::create_dir_all(base.join("srv/sites/rs_blog9/tmp")).unwrap();
        fs::write(base.join("srv/sites/rs_blog9/html/index.php"), b"<?php\n").unwrap();
        fs::write(base.join("srv/sites/rs_blog9/html/wp/a.txt"), b"abc").unwrap();
        fs::write(
            base.join("srv/sites/rs_blog9/tmp/rustiron-capture.sql"),
            b"-- x\n",
        )
        .unwrap();
        std::os::unix::fs::symlink("index.php", base.join("srv/sites/rs_blog9/html/l")).unwrap();
        base
    }

    fn manifest(root: &Path, limits: Limits) -> format::Built {
        let mut out = Vec::new();
        let end = walk(root, &mut out, limits).unwrap();
        out.extend_from_slice(format::end_line(end).as_bytes());
        out.push(b'\n');
        format::build(&out).unwrap()
    }

    #[test]
    fn the_walk_lists_every_member_once_in_the_manifest_format() {
        let root = tree();
        let built = manifest(&root, Limits::default());
        let text = String::from_utf8(built.bytes.clone()).unwrap();
        let paths: Vec<_> = text
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()["path"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(
            paths,
            [
                "srv",
                "srv/sites",
                "srv/sites/rs_blog9",
                "srv/sites/rs_blog9/html",
                "srv/sites/rs_blog9/html/index.php",
                "srv/sites/rs_blog9/html/l",
                "srv/sites/rs_blog9/html/wp",
                "srv/sites/rs_blog9/html/wp/a.txt",
                "srv/sites/rs_blog9/tmp",
                "srv/sites/rs_blog9/tmp/rustiron-capture.sql",
            ]
        );
        assert_eq!(
            (built.entries, built.regular_bytes, built.truncated),
            (10, 14, false)
        );
        // The same tree always gives the same digest; a changed byte does not.
        assert_eq!(manifest(&root, Limits::default()).sha256, built.sha256);
        fs::write(root.join("srv/sites/rs_blog9/html/wp/a.txt"), b"abd").unwrap();
        assert_ne!(manifest(&root, Limits::default()).sha256, built.sha256);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_bound_marks_the_list_truncated_and_a_non_directory_root_is_an_error() {
        let root = tree();
        let small = Limits {
            entries: 3,
            ..Limits::default()
        };
        assert!(manifest(&root, small).truncated);
        let few_bytes = Limits {
            regular_bytes: 5,
            ..Limits::default()
        };
        assert!(manifest(&root, few_bytes).truncated);
        let file = root.join("srv/sites/rs_blog9/html/index.php");
        assert_eq!(
            walk(&file, &mut Vec::new(), Limits::default()),
            Err(Error::Malformed)
        );
        let link = root.join("srv/sites/rs_blog9/html/l");
        assert_eq!(
            walk(&link, &mut Vec::new(), Limits::default()),
            Err(Error::Malformed)
        );
        fs::remove_dir_all(&root).unwrap();
    }
}
