//! Fixed capture-manifest worker (W203). Run only by the capture runner as a
//! site account in `rustiron_capture_t`: `capture-manifest dump <snapshot>`.
//! Starts the one fixed `restic dump` of that snapshot (repository and
//! read-only identity come from the unit environment), hashes the stream and
//! writes closed JSON lines to stdout. Nothing reaches argv or logs.
use std::{
    io::{BufReader, BufWriter, Write},
    process::{Command, ExitCode, Stdio},
};

mod app_sqlite;
#[expect(
    dead_code,
    reason = "the worker writes lines; only the runner builds manifests"
)]
mod format;
mod import;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the runner half is used only by the executor")
)]
mod lock;
#[cfg(rustiron_profile = "product")]
mod repository;
#[cfg_attr(
    not(rustiron_profile = "product"),
    expect(dead_code, reason = "only the product store worker sends S3 requests")
)]
mod s3;
mod tar;
mod tree;
mod worker;
#[cfg(rustiron_profile = "product")]
#[path = "../write_gate.rs"]
mod write_gate;

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the worker uses one location of the shared host layout"
    )
)]
#[path = "../layout.rs"]
mod layout;

const RESTIC: &str = layout::JOB_RESTIC;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let uid = rustix::process::getuid().as_raw();
    if uid == 0 || rustix::process::geteuid().as_raw() != uid {
        return ExitCode::from(2);
    }
    // D-034 (W383): the probe's dump import, both profiles. On success the
    // worker becomes the fixed `mariadb` client; it returns only on refusal.
    if let [action, account, probe] = args.as_slice()
        && action == "import"
    {
        import::exec(account, probe);
        return ExitCode::from(2);
    }
    // W543 (D-089): a restore removes every table and view of the site's
    // database as its own database user; the same client reads the fixed
    // statements on stdin. Both profiles.
    if let [action, account] = args.as_slice()
        && action == "site-drop-tables"
    {
        return if import::drop_site_tables(account) {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        };
    }
    // W449 (D-053): the site import's dump, both profiles; the same client.
    if let [action, account, bytes] = args.as_slice()
        && action == "site-import"
    {
        import::exec_site(account, bytes);
        return ExitCode::from(2);
    }
    #[cfg(rustiron_profile = "product")]
    if let [action, site, digest] = args.as_slice()
        && action == "repo-id"
    {
        return if repository::verify(site, digest).is_some() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        };
    }
    // W323: `restic check` after the repository ID matches. Silent.
    #[cfg(rustiron_profile = "product")]
    if let [action, site, digest] = args.as_slice()
        && action == "check"
    {
        return if repository::check(site, digest).is_some() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        };
    }
    // W323/W356: the snapshot write, refused while the product write gate
    // is closed (D-025). The complete line includes the new index keys.
    // A partial write or an unverified index delta exits 2.
    #[cfg(rustiron_profile = "product")]
    if let [action, site, digest, operation] = args.as_slice()
        && matches!(
            action.as_str(),
            "backup" | "backup-app" | "backup-app-pg" | "backup-app-mariadb"
        )
    {
        let Some(written) = (match action.as_str() {
            "backup-app" => repository::backup_app(site, digest, operation),
            "backup-app-pg" => repository::backup_app_pg(site, digest, operation),
            "backup-app-mariadb" => repository::backup_app_mariadb(site, digest, operation),
            _ => repository::backup(site, digest, operation),
        }) else {
            return ExitCode::from(2);
        };
        let complete = matches!(written, repository::Written::Complete { .. });
        let printed = writeln!(std::io::stdout(), "{}", written.line()).is_ok();
        return if complete && printed {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        };
    }
    // W356: the W203 manifest walk of one snapshot, read with the fetch key
    // pair after the repository ID matches.
    #[cfg(rustiron_profile = "product")]
    if let [action, site, digest, snapshot] = args.as_slice()
        && action == "manifest"
    {
        return match repository::manifest_dump(site, digest, snapshot) {
            Some(child) => stream_manifest(child),
            None => ExitCode::from(2),
        };
    }
    // D-078 (W499): the clone's Observe walk of its own fetched tree,
    // `<target tmp>/clone`, as the target account with no network. It
    // prints the manifest lines and the `end` line; root rebuilds and
    // compares the canonical manifest.
    if let [action, account] = args.as_slice()
        && action == "clone-tree"
    {
        return clone_tree(account);
    }
    // W603 (D-096/P30): closed SQLite online backup and read-only consistency
    // marker for P27/EmDash apps inside `rustiron_capture_t` (no writes to
    // read-only `data/`).
    if let [action, account] = args.as_slice()
        && action == "app-sqlite-backup"
    {
        return app_sqlite::run_backup(account);
    }
    if let [action, account] = args.as_slice()
        && action == "app-sqlite-marker"
    {
        return app_sqlite::run_marker(account);
    }
    // D-031 (W373): the restore probe's two store actions, run as the probe
    // account with the fetch key pair. `restore-size` prints
    // `restore-size <bytes> <files>`; `restore` is silent.
    // D-078 (W499): the clone's two store actions, run as the target site
    // account with the source site's fetch key pair. They write only below
    // the target's own `tmp/clone`.
    #[cfg(rustiron_profile = "product")]
    if let [action, site, digest, snapshot, account] = args.as_slice()
        && (action == "restore-size" || action == "clone-restore-size")
    {
        let into = if action == "restore-size" {
            repository::RestoreInto::Probe(account)
        } else {
            repository::RestoreInto::Clone(account)
        };
        let Some((size, files)) = repository::restore_size(site, digest, snapshot, into) else {
            return ExitCode::from(2);
        };
        return if writeln!(std::io::stdout(), "restore-size {size} {files}").is_ok() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        };
    }
    #[cfg(rustiron_profile = "product")]
    if let [action, site, digest, snapshot, account] = args.as_slice()
        && (action == "restore" || action == "clone-restore")
    {
        let into = if action == "restore" {
            repository::RestoreInto::Probe(account)
        } else {
            repository::RestoreInto::Clone(account)
        };
        return if repository::restore(site, digest, snapshot, into).is_some() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        };
    }
    // W334: the bucket's versioning and default COMPLIANCE retention, and
    // with an operation the retention of each object that capture wrote.
    // Read-only. W391: a pass prints the bucket line and one line per object
    // version read back; a refusal prints nothing.
    #[cfg(rustiron_profile = "product")]
    if let [action, site, digest, written @ ..] = args.as_slice()
        && action == "lock"
    {
        let written = match written {
            [] => None,
            [operation, indexes] => Some((operation.as_str(), indexes.as_str())),
            _ => return ExitCode::from(2),
        };
        let Some(lines) = repository::lock(site, digest, written) else {
            return ExitCode::from(2);
        };
        let mut out = std::io::stdout().lock();
        return if out.write_all(lines.as_bytes()).is_ok() && out.flush().is_ok() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        };
    }
    // W321: snapshots tagged with one operation, for capture recovery.
    // Prints `none` or `found <id>`; more than one is a refusal.
    #[cfg(rustiron_profile = "product")]
    if let [action, site, digest, operation] = args.as_slice()
        && action == "snapshot-tag"
    {
        let line = match repository::tagged_snapshots(site, digest, operation).as_deref() {
            Some([]) => "none".to_owned(),
            Some([id]) => format!("found {id}"),
            _ => return ExitCode::from(2),
        };
        return if writeln!(std::io::stdout(), "{line}").is_ok() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        };
    }
    if let [action] = args.as_slice()
        && action == "lock"
    {
        return check_lock();
    }
    let [action, snapshot] = args.as_slice() else {
        return ExitCode::from(2);
    };
    let Some(restic) = (action == "dump")
        .then(|| worker::restic_arguments(snapshot))
        .flatten()
    else {
        return ExitCode::from(2);
    };
    let Ok(child) = Command::new(RESTIC)
        .args(restic)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return ExitCode::from(2);
    };
    stream_manifest(child)
}

/// Walks the tar stream of a started `restic dump` and writes the closed
/// manifest lines, then the `end` line only after a complete walk.
/// The `clone-tree ACCOUNT` action: the tree must be a directory of the
/// calling account below its own clone fetch directory.
fn clone_tree(account: &str) -> ExitCode {
    use std::os::unix::fs::MetadataExt;
    let Some(tmp) = layout::clone_tmp(account) else {
        return ExitCode::from(2);
    };
    let root = std::path::PathBuf::from(tmp).join(layout::CLONE_RESTORE_DIR);
    let uid = rustix::process::getuid().as_raw();
    if !std::fs::symlink_metadata(&root).is_ok_and(|meta| meta.is_dir() && meta.uid() == uid) {
        return ExitCode::from(2);
    }
    let mut out = BufWriter::new(std::io::stdout().lock());
    let Ok(end) = tree::walk(&root, &mut out, worker::Limits::default()) else {
        return ExitCode::from(2);
    };
    let line = format::end_line(end);
    if out.write_all(line.as_bytes()).is_err()
        || out.write_all(b"\n").is_err()
        || out.flush().is_err()
    {
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}

fn stream_manifest(mut child: std::process::Child) -> ExitCode {
    let Some(stream) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return ExitCode::from(2);
    };
    let mut out = BufWriter::new(std::io::stdout().lock());
    let walked = worker::walk(
        BufReader::with_capacity(256 * 1024, stream),
        &mut out,
        worker::Limits::default(),
    );
    let complete = match &walked {
        Ok(end) if end.truncated => {
            let _ = child.kill();
            let _ = child.wait();
            true
        }
        Ok(_) => child.wait().is_ok_and(|status| status.success()),
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            false
        }
    };
    match walked {
        Ok(end) if complete => {
            let line = format::end_line(end);
            if out.write_all(line.as_bytes()).is_err()
                || out.write_all(b"\n").is_err()
                || out.flush().is_err()
            {
                return ExitCode::from(2);
            }
            ExitCode::SUCCESS
        }
        _ => {
            let _ = out.flush();
            ExitCode::from(2)
        }
    }
}

/// W228 `capture-manifest lock`: one signed GET `?object-lock` to the
/// unit's store with the unit's capture identity. Prints the pass line and
/// exits 0 only for a default COMPLIANCE retention of at least 30 days.
fn check_lock() -> ExitCode {
    use std::io::Read;
    let verdict = (|| {
        let repository = std::env::var("RESTIC_REPOSITORY").ok()?;
        let (host, bucket) = lock::endpoint(&repository)?;
        let file = std::env::var("AWS_SHARED_CREDENTIALS_FILE").ok()?;
        let text = std::fs::read_to_string(file).ok()?;
        let (access, secret) = lock::credentials(&text)?;
        let amz_date = amz_now()?;
        let path = format!("/{bucket}/");
        let auth = lock::authorization(&access, &secret, &host, &path, "object-lock", &amz_date);
        let request = format!(
            "GET {path}?object-lock= HTTP/1.1\r\nHost: {host}\r\nx-amz-content-sha256: {}\r\nx-amz-date: {amz_date}\r\nAuthorization: {auth}\r\nConnection: close\r\n\r\n",
            lock::empty_hash()
        );
        let address = std::net::ToSocketAddrs::to_socket_addrs(&host)
            .ok()?
            .next()?;
        let timeout = std::time::Duration::from_secs(10);
        let mut stream = std::net::TcpStream::connect_timeout(&address, timeout).ok()?;
        stream.set_read_timeout(Some(timeout)).ok()?;
        stream.set_write_timeout(Some(timeout)).ok()?;
        stream.write_all(request.as_bytes()).ok()?;
        let mut response = Vec::new();
        stream.take(64 * 1024).read_to_end(&mut response).ok()?;
        let response = String::from_utf8(response).ok()?;
        let (head, body) = response.split_once("\r\n\r\n")?;
        let status_ok = head.starts_with("HTTP/1.1 200 ");
        let chunked = head
            .to_ascii_lowercase()
            .contains("transfer-encoding: chunked");
        (status_ok && !chunked).then(|| lock::compliance_days(body))?
    })();
    match verdict {
        Some(days) if days >= lock::MIN_DAYS => {
            let mut out = std::io::stdout().lock();
            if writeln!(out, "{}", lock::pass_line(days)).is_err() || out.flush().is_err() {
                return ExitCode::from(2);
            }
            ExitCode::SUCCESS
        }
        _ => ExitCode::from(3),
    }
}

/// Current UTC time as `YYYYMMDDTHHMMSSZ`.
fn amz_now() -> Option<String> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant).
    let z = i64::try_from(days).ok()? + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    Some(format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    ))
}
