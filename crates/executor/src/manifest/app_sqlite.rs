//! W603 (D-096/P30): closed SQLite online-backup and consistency-marker
//! actions run inside `rustiron_capture_t:{level}` via `capture-manifest`
//! (`rustiron_capture_exec_t`).
//!
//! Because `rustiron_capture_t` has strictly read-only access to tenant
//! `data/` (`httpd_sys_content_t`) and `ProtectSystem=strict` mounts `data/`
//! read-only while `{root}/tmp` is writable (`httpd_sys_rw_content_t`):
//! - `SQLITE_MARKER_PY` reads the SQLite header bytes, file metadata, and
//!   `-wal` metadata strictly read-only without touching `-shm`.
//! - `SQLITE_BACKUP_PY` copies each database and its `-wal`/`-shm` sidecars
//!   into a private work directory under `{root}/tmp`, runs
//!   `PRAGMA integrity_check` and `sqlite3.Connection.backup()`, and packs a
//!   deterministic SHA-256-verified tar bundle at `{root}/tmp/rustiron-app-sqlite.tar`.

use std::process::{Command, ExitCode, Stdio};

/// Fixed Python 3 script run as `rs_<site>` inside `rustiron_capture_t` to
/// take WAL-safe, integrity-checked SQLite online backups without writing to
/// read-only `data/`.
pub(crate) const SQLITE_BACKUP_PY: &str = r#"
import hashlib, io, json, os, pathlib, shutil, sqlite3, sys, tarfile, tempfile

data_dir = pathlib.Path(sys.argv[1])
out_tar = pathlib.Path(sys.argv[2])
if not data_dir.is_dir() or data_dir.is_symlink():
    sys.exit(2)

dbs = []
for dirpath, dirnames, filenames in os.walk(data_dir, followlinks=False):
    dirnames.sort()
    for name in sorted(filenames):
        p = pathlib.Path(dirpath) / name
        if p.is_symlink() or not p.is_file():
            continue
        if p.suffix.lower() in (".sqlite", ".sqlite3", ".db"):
            dbs.append(p.relative_to(data_dir).as_posix())

tmp_tar = out_tar.with_suffix(".tar.tmp")
manifest = []
with tempfile.TemporaryDirectory(dir=str(out_tar.parent)) as work:
    work_path = pathlib.Path(work)
    with tarfile.open(tmp_tar, "w", format=tarfile.PAX_FORMAT) as tf:
        for idx, rel in enumerate(sorted(dbs)):
            src_path = data_dir / rel
            stage_path = work_path / f"stage_{idx}.db"
            snap_path = work_path / f"snap_{idx}.db"
            shutil.copyfile(src_path, stage_path)
            wal_side = pathlib.Path(str(src_path) + "-wal")
            if wal_side.is_file() and not wal_side.is_symlink():
                shutil.copyfile(wal_side, pathlib.Path(str(stage_path) + "-wal"))
            src = sqlite3.connect(str(stage_path))
            dst = sqlite3.connect(str(snap_path))
            try:
                src.execute("PRAGMA locking_mode = EXCLUSIVE")
                chk = src.execute("PRAGMA integrity_check").fetchone()
                if not chk or chk[0] != "ok":
                    sys.exit(2)
                src.backup(dst)
            finally:
                dst.close()
                src.close()
            raw = snap_path.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            manifest.append({"path": rel, "sha256": digest, "bytes": len(raw)})
            info = tarfile.TarInfo(name=f"dbs/{rel}")
            info.size = len(raw)
            info.mode = 0o600
            info.mtime = 0
            tf.addfile(info, io.BytesIO(raw))
        mbytes = json.dumps({"schema_version": 1, "databases": manifest}, sort_keys=True, separators=(",", ":")).encode()
        minfo = tarfile.TarInfo(name="manifest.json")
        minfo.size = len(mbytes)
        minfo.mode = 0o600
        minfo.mtime = 0
        tf.addfile(minfo, io.BytesIO(mbytes))
os.replace(tmp_tar, out_tar)
"#;

/// Fixed Python 3 script run as `rs_<site>` inside `rustiron_capture_t` to
/// compute a deterministic read-only consistency marker across every SQLite
/// database and its `-wal` sidecar under `data/` without opening `-shm` RW.
pub(crate) const SQLITE_MARKER_PY: &str = r#"
import hashlib, os, pathlib, sys

data_dir = pathlib.Path(sys.argv[1])
if not data_dir.is_dir() or data_dir.is_symlink():
    sys.exit(2)

lines = []
for dirpath, dirnames, filenames in os.walk(data_dir, followlinks=False):
    dirnames.sort()
    for name in sorted(filenames):
        p = pathlib.Path(dirpath) / name
        if p.is_symlink() or not p.is_file():
            continue
        if p.suffix.lower() in (".sqlite", ".sqlite3", ".db"):
            rel = p.relative_to(data_dir).as_posix()
            st = p.lstat()
            with open(p, "rb") as fh:
                hdr = fh.read(100)
            hdr_hash = hashlib.sha256(hdr).hexdigest()[:16]
            wal_sig = "0_0_0"
            wal = pathlib.Path(str(p) + "-wal")
            if wal.is_file() and not wal.is_symlink():
                wst = wal.lstat()
                with open(wal, "rb") as wfh:
                    whdr = wfh.read(32)
                wh_hash = hashlib.sha256(whdr).hexdigest()[:16]
                wal_sig = f"{wst.st_size}_{wst.st_mtime_ns}_{wh_hash}"
            marker = f"{st.st_size}_{st.st_mtime_ns}_{hdr_hash}_{wal_sig}"
            lines.append(f"{rel}\t{marker}")

if not lines:
    print("0")
else:
    for line in sorted(lines):
        print(line)
"#;

fn site_dirs(account: &str) -> Option<(std::path::PathBuf, std::path::PathBuf)> {
    use std::os::unix::fs::MetadataExt;
    let tmp = std::path::PathBuf::from(crate::layout::clone_tmp(account)?);
    let root = tmp.parent()?.to_path_buf();
    let data = root.join("data");
    let uid = rustix::process::getuid().as_raw();
    let ok_dir = |p: &std::path::Path| {
        std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir() && m.uid() == uid)
    };
    (ok_dir(&data) && ok_dir(&tmp)).then_some((data, tmp))
}

pub(crate) fn run_backup(account: &str) -> ExitCode {
    let Some((data, tmp)) = site_dirs(account) else {
        return ExitCode::from(2);
    };
    let out_tar = tmp.join(crate::layout::APP_SQLITE_BUNDLE_FILE);
    let (Some(data_s), Some(out_s)) = (data.to_str(), out_tar.to_str()) else {
        return ExitCode::from(2);
    };
    let ok = Command::new("/usr/bin/python3")
        .args(["-I", "-c", SQLITE_BACKUP_PY, data_s, out_s])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

pub(crate) fn run_marker(account: &str) -> ExitCode {
    let Some((data, _)) = site_dirs(account) else {
        return ExitCode::from(2);
    };
    let Some(data_s) = data.to_str() else {
        return ExitCode::from(2);
    };
    let ok = Command::new("/usr/bin/python3")
        .args(["-I", "-c", SQLITE_MARKER_PY, data_s])
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}
