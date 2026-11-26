//! D-034 (W383): the restore probe's dump import, `import ACCOUNT PROBE`.
//!
//! W378 q2: the import ran `mariadb --execute="source <dump>"`. A dump
//! without its own sandbox line reached the client shell (`\!`, `system`),
//! and only SELinux stopped it. The client option `--sandbox` refuses those
//! commands for the whole session, but it also refuses `source`. So the
//! client must read the dump on stdin.
//!
//! PID 1 cannot open the dump for the unit (`StandardInput=file:`): it opens
//! as `init_t:s0`, and MCS refuses its read of the probe file at `s0:c950`
//! (W383). This action runs in the probe's own unit, as the probe account in
//! `rustiron_capture_t:s0:c950`. It derives the dump path from the two
//! names, opens each component without following links, accepts only a
//! single-link regular file that the probe owns, and replaces itself with
//! the fixed `mariadb` client that reads the dump on stdin.

use std::{
    fs::File,
    os::unix::ffi::OsStrExt,
    os::unix::process::CommandExt,
    path::{Component, Path},
    process::{Command, Stdio},
};

use rustiron_contracts::approval::SiteId;
use rustix::fs::{self, FileType, Mode, OFlags};

use super::layout;

/// The restored site root of `account` in the sandbox of `probe`, or `None`
/// for a name that is not a site account or a journaled probe account.
pub(super) fn site_root(account: &str, probe: &str) -> Option<String> {
    let id = account.strip_prefix("rs_")?;
    let site = SiteId::try_from(id.to_owned()).ok()?;
    if site.account_name() != account {
        return None;
    }
    let tmp = layout::probe_tmp(probe)?;
    Some(format!(
        "{tmp}/{}{}/{account}",
        layout::PROBE_RESTORE_DIR,
        layout::SITES_ROOT
    ))
}

/// The fixed client arguments. `--sandbox` refuses the client's shell and
/// file commands; `--local-infile=0` refuses `LOAD DATA LOCAL INFILE`
/// (W378 q5a); `--batch` stops at the first failed statement with a nonzero
/// exit (W230 h6). No statement is in argv: the dump is stdin.
pub(super) fn client_arguments(site_root: &str, probe: &str) -> Vec<String> {
    vec![
        format!("--defaults-file={site_root}/private/db.cnf"),
        "--sandbox".to_owned(),
        "--local-infile=0".to_owned(),
        "--batch".to_owned(),
        probe.to_owned(),
    ]
}

/// Opens `<site_root>/tmp/<dump>` one component at a time without following
/// links. Only a single-link regular file owned by `uid` is the dump.
pub(super) fn open_dump(site_root: &str, uid: u32) -> Option<File> {
    let path = Path::new(site_root)
        .join("tmp")
        .join(layout::CAPTURE_DUMP_FILE);
    if !path.is_absolute() {
        return None;
    }
    let names: Vec<_> = path
        .components()
        .filter(|part| *part != Component::RootDir)
        .map(|part| match part {
            Component::Normal(name) => Some(name),
            _ => None,
        })
        .collect::<Option<_>>()?;
    let (last, parents) = names.split_last()?;
    let search = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = fs::open("/", search, Mode::empty()).ok()?;
    for name in parents {
        directory = fs::openat(&directory, *name, search, Mode::empty()).ok()?;
    }
    let dump = fs::openat(
        &directory,
        *last,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NOCTTY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .ok()?;
    let stat = fs::fstat(&dump).ok()?;
    (FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
        && stat.st_nlink == 1
        && stat.st_uid == uid)
        .then(|| File::from(dump))
}

/// Replaces this worker with the fixed client reading the dump on stdin.
/// Returns only when it refuses or the exec fails.
pub(super) fn exec(account: &str, probe: &str) {
    let uid = rustix::process::getuid().as_raw();
    let Some(root) = site_root(account, probe) else {
        return;
    };
    let Some(dump) = open_dump(&root, uid) else {
        return;
    };
    let _ = Command::new(format!("{}/mariadb", layout::JOB_BIN_DIR))
        .args(client_arguments(&root, probe))
        .env_clear()
        .stdin(dump)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .exec();
}

/// W449 (D-053): the site root of a site account, `<SITES_ROOT>/<account>`,
/// or `None` for a name that is not a site account.
pub(super) fn site_import_root(account: &str) -> Option<String> {
    let id = account.strip_prefix("rs_")?;
    let site = SiteId::try_from(id.to_owned()).ok()?;
    (site.account_name() == account).then(|| format!("{}/{account}", layout::SITES_ROOT))
}

/// W449: the one dump of an extracted site import: the `*.sql` entry of
/// `<site_root>/tmp/import` with exactly `bytes` bytes (the signed dump size),
/// a single-link regular file of `uid`. D-066 (W478): an export may hold
/// other dumps the import leaves on the source; exactly one entry may have
/// the signed size, so none or two of that size refuse.
pub(super) fn open_site_dump(site_root: &str, uid: u32, bytes: u64) -> Option<File> {
    let path = Path::new(site_root).join("tmp").join("import");
    if !path.is_absolute() {
        return None;
    }
    let search = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = fs::open("/", search, Mode::empty()).ok()?;
    for part in path.components() {
        match part {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = fs::openat(&directory, name, search, Mode::empty()).ok()?;
            }
            _ => return None,
        }
    }
    let listing = fs::openat(
        &directory,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .ok()?;
    let mut dumps = Vec::new();
    for entry in fs::Dir::read_from(&listing).ok()? {
        let name = entry.ok()?.file_name().to_bytes().to_vec();
        if name.ends_with(b".sql") {
            dumps.push(name);
        }
    }
    let mut chosen = None;
    for name in &dumps {
        // A symlink or another type is never a dump; it refuses.
        let stat = fs::statat(
            &listing,
            std::ffi::OsStr::from_bytes(name),
            fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .ok()?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return None;
        }
        if u64::try_from(stat.st_size).ok() == Some(bytes) && chosen.replace(name).is_some() {
            return None;
        }
    }
    let name = std::ffi::OsStr::from_bytes(chosen?);
    let dump = fs::openat(
        &listing,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NOCTTY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .ok()?;
    let stat = fs::fstat(&dump).ok()?;
    (FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
        && stat.st_nlink == 1
        && stat.st_uid == uid
        && u64::try_from(stat.st_size).ok() == Some(bytes))
    .then(|| File::from(dump))
}

/// W543 (D-089): the fixed statements that remove every view, then every
/// table, sequence, and with them every trigger, of the client's current
/// database. Names come from `information_schema`, quoted with backquotes
/// doubled; nothing comes from a request.
pub(super) const DROP_ALL_SQL: &str = "SET SESSION group_concat_max_len = 16777216;\n\
SET FOREIGN_KEY_CHECKS = 0;\n\
SELECT GROUP_CONCAT(CONCAT('`', REPLACE(table_name, '`', '``'), '`')) INTO @rustiron_views \
FROM information_schema.tables WHERE table_schema = DATABASE() AND table_type = 'VIEW';\n\
SET @rustiron_drop = IF(@rustiron_views IS NULL, 'DO 0', CONCAT('DROP VIEW ', @rustiron_views));\n\
PREPARE rustiron_drop FROM @rustiron_drop;\n\
EXECUTE rustiron_drop;\n\
DEALLOCATE PREPARE rustiron_drop;\n\
SELECT GROUP_CONCAT(CONCAT('`', REPLACE(table_name, '`', '``'), '`')) INTO @rustiron_tables \
FROM information_schema.tables WHERE table_schema = DATABASE() AND table_type <> 'VIEW';\n\
SET @rustiron_drop = IF(@rustiron_tables IS NULL, 'DO 0', CONCAT('DROP TABLE ', @rustiron_tables));\n\
PREPARE rustiron_drop FROM @rustiron_drop;\n\
EXECUTE rustiron_drop;\n\
DEALLOCATE PREPARE rustiron_drop;\n";

/// W543: runs [`DROP_ALL_SQL`] through the fixed client as the site's own
/// database user, in its own database. True only when the client wrote the
/// whole input and exited 0.
pub(super) fn drop_site_tables(account: &str) -> bool {
    use std::io::Write;
    let Some(root) = site_import_root(account) else {
        return false;
    };
    let Ok(mut child) = Command::new(format!("{}/mariadb", layout::JOB_BIN_DIR))
        .args(client_arguments(&root, account))
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
    else {
        return false;
    };
    let written = child
        .stdin
        .take()
        .is_some_and(|mut input| input.write_all(DROP_ALL_SQL.as_bytes()).is_ok());
    let exited = child.wait().is_ok_and(|status| status.success());
    written && exited
}

/// A decimal size in its one canonical spelling (no sign, no leading zero).
pub(super) fn canonical_size(text: &str) -> Option<u64> {
    let value = text.parse::<u64>().ok()?;
    (value.to_string() == text).then_some(value)
}

/// W449: replaces this worker with the fixed client that imports the site
/// dump into the site's own database as its own database user. Returns only
/// when it refuses or the exec fails.
pub(super) fn exec_site(account: &str, bytes: &str) {
    let uid = rustix::process::getuid().as_raw();
    let (Some(root), Some(bytes)) = (site_import_root(account), canonical_size(bytes)) else {
        return;
    };
    let Some(dump) = open_site_dump(&root, uid, bytes) else {
        return;
    };
    let _ = Command::new(format!("{}/mariadb", layout::JOB_BIN_DIR))
        .args(client_arguments(&root, account))
        .env_clear()
        .stdin(dump)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .exec();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn tree(tag: &str) -> (std::path::PathBuf, String) {
        let base =
            std::env::temp_dir().join(format!("ri-w383-import-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("site");
        std::fs::create_dir_all(root.join("tmp")).unwrap();
        (base, root.to_str().unwrap().to_owned())
    }

    fn me() -> u32 {
        rustix::process::getuid().as_raw()
    }

    #[test]
    fn the_table_removal_is_fixed_sql_for_a_site_account_only() {
        // Statements only: no client command, file, or other database.
        for line in DROP_ALL_SQL.lines() {
            assert!(
                ["SET ", "SELECT ", "PREPARE ", "EXECUTE ", "DEALLOCATE "]
                    .iter()
                    .any(|start| line.starts_with(start)),
                "{line}"
            );
            assert!(line.ends_with(';'), "{line}");
        }
        for word in ["\\", "source", "system", "LOAD", "INTO OUTFILE", "USE "] {
            assert!(!DROP_ALL_SQL.contains(word), "{word}");
        }
        assert_eq!(DROP_ALL_SQL.matches("DATABASE()").count(), 2);
        // Another name never reaches the client.
        for account in ["blog9", "rs_", "rs_../x", "rs_Blog9", "root"] {
            assert!(!drop_site_tables(account), "{account}");
        }
    }

    #[test]
    fn the_site_root_comes_only_from_a_site_account_and_a_probe_account() {
        let root = site_root("rs_blog9", "rp_0a9fbc").unwrap();
        assert_eq!(
            root,
            format!(
                "{}/rp_0a9fbc/tmp/restore{}/rs_blog9",
                layout::RESTORE_PROBES_ROOT,
                layout::SITES_ROOT
            )
        );
        for (account, probe) in [
            ("blog9", "rp_0a9fbc"),
            ("rs_", "rp_0a9fbc"),
            ("rs_../x", "rp_0a9fbc"),
            ("rs_Blog9", "rp_0a9fbc"),
            ("rs_blog9", "rp_0A9FBC"),
            ("rs_blog9", "rp_0a9fb"),
            ("rs_blog9", "rs_blog9"),
            ("rs_blog9", "rp_../../x"),
        ] {
            assert_eq!(site_root(account, probe), None, "{account} {probe}");
        }
    }

    #[test]
    fn the_client_runs_in_sandbox_mode_with_no_statement_in_argv() {
        let argv = client_arguments("/r/srv/sites/rs_x", "rp_0a9fbc");
        assert_eq!(
            argv,
            [
                "--defaults-file=/r/srv/sites/rs_x/private/db.cnf",
                "--sandbox",
                "--local-infile=0",
                "--batch",
                "rp_0a9fbc"
            ]
        );
        assert!(
            !argv
                .iter()
                .any(|a| a.starts_with("--execute") || a == "-e" || a == "--force")
        );
    }

    #[test]
    fn only_a_single_link_regular_dump_of_the_caller_opens() {
        let (base, root) = tree("ok");
        let dump = Path::new(&root).join("tmp").join(layout::CAPTURE_DUMP_FILE);
        std::fs::write(&dump, b"SELECT 1;\n").unwrap();
        assert!(open_dump(&root, me()).is_some());
        assert!(
            open_dump(&root, me().wrapping_add(1)).is_none(),
            "another owner"
        );
        std::fs::hard_link(&dump, base.join("second")).unwrap();
        assert!(open_dump(&root, me()).is_none(), "two links");
        std::fs::remove_file(base.join("second")).unwrap();
        std::fs::remove_file(&dump).unwrap();
        assert!(open_dump(&root, me()).is_none(), "missing");
        symlink("/etc/passwd", &dump).unwrap();
        assert!(open_dump(&root, me()).is_none(), "link");
        std::fs::remove_file(&dump).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &dump,
            FileType::Fifo,
            Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        assert!(open_dump(&root, me()).is_none(), "fifo");
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn a_linked_directory_on_the_dump_path_refuses() {
        let (base, root) = tree("dir");
        let real = base.join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(real.join(layout::CAPTURE_DUMP_FILE), b"x").unwrap();
        std::fs::remove_dir(Path::new(&root).join("tmp")).unwrap();
        symlink(&real, Path::new(&root).join("tmp")).unwrap();
        assert!(open_dump(&root, me()).is_none());
        assert!(open_dump("relative/site", me()).is_none());
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn the_site_import_root_comes_only_from_a_site_account() {
        assert_eq!(
            site_import_root("rs_blog9").unwrap(),
            format!("{}/rs_blog9", layout::SITES_ROOT)
        );
        for account in ["blog9", "rs_", "rs_../x", "rs_Blog9", "rp_0a9fbc"] {
            assert_eq!(site_import_root(account), None, "{account}");
        }
    }

    #[test]
    fn only_one_owned_dump_of_the_signed_size_opens() {
        let (base, root) = tree("site");
        let import = Path::new(&root).join("tmp/import");
        std::fs::create_dir(&import).unwrap();
        std::fs::write(import.join("meta.xml"), b"<metaFile/>").unwrap();
        std::fs::write(import.join("p01_wp.sql"), b"SELECT 1;\n").unwrap();
        assert!(open_site_dump(&root, me(), 10).is_some());
        assert!(open_site_dump(&root, me(), 11).is_none(), "another size");
        assert!(
            open_site_dump(&root, me().wrapping_add(1), 10).is_none(),
            "another owner"
        );
        std::fs::write(import.join("second.sql"), b"SELECT 2;\n").unwrap();
        assert!(
            open_site_dump(&root, me(), 10).is_none(),
            "two dumps of the size"
        );
        // D-066: a dump of another size is left alone; the signed one opens.
        std::fs::write(import.join("second.sql"), b"SELECT 22;\n").unwrap();
        assert!(
            open_site_dump(&root, me(), 10).is_some(),
            "the one of the size"
        );
        assert!(open_site_dump(&root, me(), 11).is_some(), "the other one");
        assert!(
            open_site_dump(&root, me(), 12).is_none(),
            "no dump of the size"
        );
        std::fs::remove_file(import.join("second.sql")).unwrap();
        std::fs::hard_link(import.join("p01_wp.sql"), base.join("link")).unwrap();
        assert!(open_site_dump(&root, me(), 10).is_none(), "two links");
        std::fs::remove_file(base.join("link")).unwrap();
        std::fs::rename(import.join("p01_wp.sql"), base.join("real.sql")).unwrap();
        symlink(base.join("real.sql"), import.join("p01_wp.sql")).unwrap();
        assert!(open_site_dump(&root, me(), 10).is_none(), "a symlink");
        std::fs::remove_file(import.join("p01_wp.sql")).unwrap();
        assert!(open_site_dump(&root, me(), 10).is_none(), "no dump");
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn the_dump_size_has_one_spelling() {
        assert_eq!(canonical_size("429"), Some(429));
        for text in [
            "",
            "0429",
            "+429",
            "-1",
            " 429",
            "4.29",
            "18446744073709551616",
        ] {
            assert_eq!(canonical_size(text), None, "{text:?}");
        }
    }
}
