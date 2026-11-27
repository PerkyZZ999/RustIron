//! Admission high-water mark (review F-01). The journal cannot tell a
//! coherent older copy of itself from the current one, so after every
//! committed admission the executor records the journal's admission count
//! in a root-only file outside the journal directory. A journal with fewer
//! admissions than the mark for the same host and epoch is an older copy,
//! and nothing is admitted from it until an epoch rotation. A whole-host
//! revert rolls the mark back too; this does not detect that.

use std::{fs::File, io::Write};

use rustiron_contracts::Id;
use rustix::fs::{self, AtFlags, Mode, OFlags};

use crate::{ExecutorError, TrustAnchor, files};

const FILE: &str = "admission-mark";
const TEMPORARY: &str = "admission-mark.tmp";
const MAGIC: &str = "rustiron-admission-mark/1";

/// The last recorded admission count for one host and epoch.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Mark {
    pub host: String,
    pub epoch: String,
    pub count: u64,
}

/// Reads the mark; `None` only when the file is absent.
pub(crate) fn read(anchor: &TrustAnchor) -> Result<Option<Mark>, ExecutorError> {
    let directory = files::open_trusted_directory(&anchor.mark_dir, anchor.owner_uid)?;
    match fs::statat(&directory, FILE, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(ExecutorError::AccessDenied),
        Ok(_) => {}
    }
    let bytes = files::read_child(
        &directory,
        FILE,
        anchor.owner_uid,
        files::Exposure::Private,
        512,
    )?;
    parse(&bytes).map(Some).ok_or(ExecutorError::Unavailable)
}

fn parse(bytes: &[u8]) -> Option<Mark> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.strip_suffix('\n')?.split('\n');
    let (magic, host, epoch, count) = (lines.next()?, lines.next()?, lines.next()?, lines.next()?);
    if magic != MAGIC || lines.next().is_some() {
        return None;
    }
    let host = Id::try_from(host.to_owned()).ok()?;
    let epoch = Id::try_from(epoch.to_owned()).ok()?;
    let parsed: u64 = count.parse().ok()?;
    // Canonical decimal only: no sign, no leading zero.
    if parsed.to_string() != count {
        return None;
    }
    let count = parsed;
    Some(Mark {
        host: host.as_str().to_owned(),
        epoch: epoch.as_str().to_owned(),
        count,
    })
}

/// Admission is allowed only while the journal is not behind the mark for
/// its own host and epoch. A missing mark, or one for another epoch, is
/// refused too: it is restored by `seal-admission-mark` or an initialize.
pub(crate) fn check(
    mark: Option<&Mark>,
    host: &Id,
    epoch: &Id,
    count: u64,
) -> Result<(), ExecutorError> {
    match mark {
        Some(mark)
            if mark.host == host.as_str()
                && mark.epoch == epoch.as_str()
                && count >= mark.count =>
        {
            Ok(())
        }
        _ => Err(ExecutorError::JournalRollback),
    }
}

/// Replaces the mark atomically: a fresh 0600 temporary file, fsync,
/// rename over the mark, directory fsync. A crash leaves the old or the new
/// mark, never a partial one; the journal is always committed first, so the
/// mark is never ahead of it.
pub(crate) fn write(
    anchor: &TrustAnchor,
    host: &Id,
    epoch: &Id,
    count: u64,
) -> Result<(), ExecutorError> {
    let directory = files::open_trusted_directory(&anchor.mark_dir, anchor.owner_uid)?;
    match fs::unlinkat(&directory, TEMPORARY, AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => {}
        Err(_) => return Err(ExecutorError::Unavailable),
    }
    let mut file = create_temporary(&directory)?;
    file.write_all(
        format!(
            "{MAGIC}\n{}\n{}\n{}\n",
            host.as_str(),
            epoch.as_str(),
            count
        )
        .as_bytes(),
    )
    .map_err(|_| ExecutorError::Unavailable)?;
    file.sync_all().map_err(|_| ExecutorError::Unavailable)?;
    drop(file);
    fs::renameat(&directory, TEMPORARY, &directory, FILE)
        .map_err(|_| ExecutorError::Unavailable)?;
    fs::fsync(&directory).map_err(|_| ExecutorError::Unavailable)
}

/// Creates the temporary mark file. Any entry already at the name, a link
/// included, is refused, never followed or reused.
fn create_temporary(directory: impl rustix::fd::AsFd) -> Result<File, ExecutorError> {
    fs::openat(
        directory,
        TEMPORARY,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map(File::from)
    .map_err(|_| ExecutorError::Unavailable)
}

#[cfg(test)]
mod tests {
    use rustiron_contracts::Id;

    use super::{Mark, TEMPORARY, check, create_temporary, parse};
    use crate::ExecutorError;

    fn id(text: &str) -> Id {
        Id::try_from(text.to_owned()).unwrap()
    }

    fn mark(count: u64) -> Mark {
        Mark {
            host: "host_lab".to_owned(),
            epoch: "epoch_1".to_owned(),
            count,
        }
    }

    #[test]
    fn a_journal_behind_the_mark_is_refused_and_ahead_or_equal_is_accepted() {
        let (host, epoch) = (id("host_lab"), id("epoch_1"));
        assert_eq!(
            check(Some(&mark(3)), &host, &epoch, 2),
            Err(ExecutorError::JournalRollback)
        );
        assert_eq!(check(Some(&mark(3)), &host, &epoch, 3), Ok(()));
        // A crash after the journal commit and before the mark update.
        assert_eq!(check(Some(&mark(3)), &host, &epoch, 4), Ok(()));
    }

    #[test]
    fn a_missing_or_other_epoch_mark_is_refused() {
        let host = id("host_lab");
        assert_eq!(
            check(None, &host, &id("epoch_1"), 0),
            Err(ExecutorError::JournalRollback)
        );
        assert_eq!(
            check(Some(&mark(0)), &host, &id("epoch_2"), 5),
            Err(ExecutorError::JournalRollback)
        );
        assert_eq!(
            check(Some(&mark(0)), &id("host_other"), &id("epoch_1"), 5),
            Err(ExecutorError::JournalRollback)
        );
    }

    /// W705 (mutation campaign): an entry planted at the temporary name
    /// between the unlink and the open is refused: a link is not followed
    /// and an existing file is not reused.
    #[test]
    fn the_temporary_file_is_created_new_and_never_through_a_link() {
        let dir = std::env::temp_dir().join(format!("ri-mark-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let open = || std::fs::File::open(&dir).unwrap();
        let target = dir.join("target");
        std::fs::write(&target, b"").unwrap();
        std::os::unix::fs::symlink(&target, dir.join(TEMPORARY)).unwrap();
        assert_eq!(
            create_temporary(open()).err(),
            Some(ExecutorError::Unavailable)
        );
        std::fs::remove_file(dir.join(TEMPORARY)).unwrap();
        std::fs::write(dir.join(TEMPORARY), b"").unwrap();
        assert_eq!(
            create_temporary(open()).err(),
            Some(ExecutorError::Unavailable)
        );
        std::fs::remove_file(dir.join(TEMPORARY)).unwrap();
        assert!(create_temporary(open()).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_the_exact_format_parses() {
        assert_eq!(
            parse(b"rustiron-admission-mark/1\nhost_lab\nepoch_1\n7\n"),
            Some(mark(7))
        );
        for bad in [
            &b"rustiron-admission-mark/1\nhost_lab\nepoch_1\n7"[..],
            b"rustiron-admission-mark/2\nhost_lab\nepoch_1\n7\n",
            b"rustiron-admission-mark/1\nhost_lab\nepoch_1\n07\n",
            b"rustiron-admission-mark/1\nhost_lab\nepoch_1\n+7\n",
            b"rustiron-admission-mark/1\nhost_lab\nepoch_1\n-1\n",
            b"rustiron-admission-mark/1\nhost_lab\nepoch_1\n7\nextra\n",
            b"rustiron-admission-mark/1\nhost lab\nepoch_1\n7\n",
        ] {
            assert_eq!(parse(bad), None, "{:?}", String::from_utf8_lossy(bad));
        }
    }
}
