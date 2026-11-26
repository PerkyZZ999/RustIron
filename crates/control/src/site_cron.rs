//! W466 (D-061, P07): ask each managed site's own PHP to run its due
//! WordPress jobs. The sites and the plain listener come from the active OLS
//! generation; the request goes to the local listener, so each job runs in
//! the site's confined pool as the site. One request per site per run, one
//! after another, never retried here.

use serde_json::{Value, json};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::{Duration, Instant},
};

/// W474-F1: one run at a time, however it was started. WordPress's own
/// `doing_cron` lock is not atomic: three runs started together ran one job
/// three times on the lab host.
pub(crate) const LOCK: &str = "/var/lib/rustiron-coordinator/site-cron.lock";

/// Why no run happened.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LockError {
    /// Another run holds the lock.
    Busy,
    /// The lock file is missing, foreign, or unsafe.
    Unavailable,
}

/// W474-F1: the lock covers only the requests, but each site's jobs run on
/// after its response. A run that starts sooner than WordPress's own lock
/// timeout (`WP_CRON_LOCK_TIMEOUT`, 60 s) after the last one is busy.
pub(crate) const SPACING_SECONDS: u64 = 60;

/// Takes the exclusive run lock, without waiting, and records `now` as the
/// run's start. The file must be a private regular file of this account with
/// one link. Busy while another run holds it, or within [`SPACING_SECONDS`]
/// of the last recorded start.
pub(crate) fn hold_lock(path: &Path, now: u64) -> Result<File, LockError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|_| LockError::Unavailable)?;
    let metadata = file.metadata().map_err(|_| LockError::Unavailable)?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(LockError::Unavailable);
    }
    match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {}
        Err(rustix::io::Errno::WOULDBLOCK) => return Err(LockError::Busy),
        Err(_) => return Err(LockError::Unavailable),
    }
    let mut file = file;
    let mut text = String::new();
    (&file)
        .take(32)
        .read_to_string(&mut text)
        .map_err(|_| LockError::Unavailable)?;
    // An empty or unreadable record is no recent run.
    if let Ok(last) = text.trim().parse::<u64>()
        && now >= last
        && now - last < SPACING_SECONDS
    {
        return Err(LockError::Busy);
    }
    file.set_len(0).map_err(|_| LockError::Unavailable)?;
    std::io::Seek::rewind(&mut file).map_err(|_| LockError::Unavailable)?;
    writeln!(file, "{now}")
        .and_then(|()| file.sync_all())
        .map_err(|_| LockError::Unavailable)?;
    Ok(file)
}

const CONNECT: Duration = Duration::from_secs(2);
const READ: Duration = Duration::from_secs(60);
/// More sites than this in one generation stops the run.
const MAX_SITES: usize = 256;

/// The plain listener's address and its managed `(vhost, hostname)` maps.
/// The TLS listener (`secure 1`) and adopted vhosts (no `rs_` prefix) are
/// skipped.
pub(crate) fn plain_sites(text: &str) -> Option<(SocketAddr, Vec<(String, String)>)> {
    let mut address = None;
    let mut sites = Vec::new();
    let mut in_listener = false;
    let mut secure = false;
    let mut pending = Vec::new();
    let mut pending_address = None;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("listener ") && line.ends_with('{') {
            in_listener = true;
            secure = false;
            pending.clear();
            pending_address = None;
            continue;
        }
        if !in_listener {
            continue;
        }
        if line == "}" {
            in_listener = false;
            if !secure && address.is_none() {
                address = pending_address.take();
                sites.append(&mut pending);
            }
            continue;
        }
        let mut parts = line.split_whitespace();
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some("address"), Some(value), None, None) => {
                pending_address = value.parse::<SocketAddr>().ok();
            }
            (Some("secure"), Some("1"), None, None) => secure = true,
            (Some("map"), Some(vhost), Some(host), None)
                if vhost.starts_with("rs_") && crate::host::hostname_token(host) =>
            {
                pending.push((vhost.to_owned(), host.to_owned()));
            }
            _ => {}
        }
    }
    let address = address?;
    (sites.len() <= MAX_SITES).then_some((address, sites))
}

/// One site's request; the status code, or `None` when there was no answer.
fn ask(address: SocketAddr, host: &str) -> Option<u16> {
    let mut stream = TcpStream::connect_timeout(&address, CONNECT).ok()?;
    stream.set_read_timeout(Some(READ)).ok()?;
    stream.set_write_timeout(Some(CONNECT)).ok()?;
    // W466-F1: no `doing_wp_cron` key. With a key, wp-cron.php runs only if
    // it equals the stored lock; without one, WordPress takes the lock itself
    // (waiting out a stale one), as for any external scheduler.
    let request = format!(
        "GET /wp-cron.php HTTP/1.0\r\nHost: {host}\r\nUser-Agent: rustiron-site-cron\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).ok()?;
    let mut buffer = [0_u8; 64];
    let read = stream.read(&mut buffer).ok()?;
    let text = std::str::from_utf8(&buffer[..read]).ok()?;
    let code = text.split_whitespace().nth(1)?.parse().ok()?;
    // Drain a short body so the site's PHP finishes its request.
    let mut rest = [0_u8; 4096];
    while matches!(stream.read(&mut rest), Ok(n) if n > 0) {}
    (100..600).contains(&code).then_some(code)
}

/// Runs once over the generation text; one JSON line per site.
pub(crate) fn run(map_text: &str) -> Result<Vec<Value>, ()> {
    let (address, sites) = plain_sites(map_text).ok_or(())?;
    Ok(sites
        .iter()
        .map(|(vhost, host)| {
            let started = Instant::now();
            let status = ask(address, host);
            json!({
                "scope": "site_cron",
                "site": vhost,
                "status": status,
                "ok": status.is_some_and(|code| (200..300).contains(&code)),
                "milliseconds": started.elapsed().as_millis() as u64,
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAP: &str = "virtualHost site_a {\n vhRoot /srv/sites/site_a/\n}\n\
listener W447 {\n address 127.0.0.1:8090\n secure 0\n map site_a site-a.example.test\n map rs_cp02 cp02.example.test\n map rs_p01r p01r.example.test\n}\n\
listener W447TLS {\n address 127.0.0.1:8443\n secure 1\n keyFile /etc/rustiron-tls/rs_cp02/live/key.pem\n map rs_cp02 cp02.example.test\n}\n";

    #[test]
    fn only_the_plain_listener_and_managed_sites_are_asked() {
        let (address, sites) = plain_sites(MAP).unwrap();
        assert_eq!(address, "127.0.0.1:8090".parse().unwrap());
        assert_eq!(
            sites,
            [
                ("rs_cp02".to_owned(), "cp02.example.test".to_owned()),
                ("rs_p01r".to_owned(), "p01r.example.test".to_owned())
            ]
        );
    }

    #[test]
    fn hostile_or_missing_text_asks_nothing() {
        assert!(plain_sites("").is_none());
        assert!(plain_sites("listener X {\n secure 1\n address 127.0.0.1:1\n}\n").is_none());
        let (_, sites) = plain_sites(
            "listener X {\n address 127.0.0.1:8090\n map rs_a a.example.test\r\nX: y\n map rs_b bad/host\n map rs_c c.example.test extra\n}\n",
        )
        .unwrap();
        // The bad hostname and the extra token are refused; the first line
        // is a valid map once its trailing CR is trimmed.
        assert_eq!(sites, [("rs_a".to_owned(), "a.example.test".to_owned())]);
    }

    #[test]
    fn a_second_run_is_busy_while_the_first_holds_the_lock() {
        let folder =
            std::env::temp_dir().join(format!("rustiron-site-cron-{}", std::process::id()));
        std::fs::create_dir_all(&folder).unwrap();
        let path = folder.join("site-cron.lock");
        let first = hold_lock(&path, 1000).unwrap();
        assert_eq!(hold_lock(&path, 1000).err(), Some(LockError::Busy));
        drop(first);
        assert_eq!(
            hold_lock(&path, 1059).err(),
            Some(LockError::Busy),
            "within the spacing after the last start"
        );
        assert!(hold_lock(&path, 1060).is_ok(), "free after the spacing");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "1060\n");
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", &path).unwrap();
        assert_eq!(
            hold_lock(&path, 2000).err(),
            Some(LockError::Unavailable),
            "no link"
        );
        std::fs::remove_dir_all(&folder).unwrap();
    }

    #[test]
    fn an_unreachable_listener_reports_no_answer() {
        let lines =
            run("listener X {\n address 127.0.0.1:9\n map rs_a a.example.test\n}\n").unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["status"], Value::Null);
        assert_eq!(lines[0]["ok"], false);
    }
}
