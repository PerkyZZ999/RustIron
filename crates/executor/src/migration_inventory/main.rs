//! P01 export inventory worker. Run only as an unprivileged import identity.
//!
//! It reads an export that the operator made with the incumbent's own tool and
//! extracted under the import identity: `meta.xml`, the `public_html` home
//! tree, and one `<database>.sql` dump for each database that `meta.xml`
//! names. It writes one `ExportObservation` to stdout. Other top-level entries,
//! such as mailboxes and certificate files, are never opened.
use rustiron_contracts::{
    SchemaVersion, Text,
    migration::{
        ExportObservation, ExportReason, ExportStatus, LeftKind, LeftOnSource,
        MAX_MIGRATION_INVENTORY_BYTES, TreeReport,
    },
};
use rustix::{
    fd::OwnedFd,
    fs::{self, AtFlags, FileType, Mode, OFlags},
    io::Errno,
};
use std::{
    io::Write,
    path::{Component, Path},
    process::ExitCode,
    time::Instant,
};

mod dump;
mod live;
mod meta;
mod tls;
mod walk;

use walk::{Clock, DIRECTORY, Limits};

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().collect();
    // W448: `--tree DIR` reports the manifest of one folder only.
    let (bytes, identity_refused) = match args.as_slice() {
        [_, export] => {
            let observation = observe(Path::new(export), &Limits::default(), identity());
            let refused = observation.reason == Some(ExportReason::Identity);
            (serde_json::to_vec(&observation), refused)
        }
        [_, flag, folder] if flag == "--tree" => {
            let report = tree_report(Path::new(folder), &Limits::default(), identity());
            let refused = report.reason == Some(ExportReason::Identity);
            (serde_json::to_vec(&report), refused)
        }
        _ => {
            eprintln!("{{\"error\":\"MIGRATION_INVENTORY_ARGUMENTS\"}}");
            return ExitCode::from(2);
        }
    };
    let Ok(mut bytes) = bytes else {
        return ExitCode::from(2);
    };
    if bytes.len() >= MAX_MIGRATION_INVENTORY_BYTES {
        return ExitCode::from(2);
    }
    bytes.push(b'\n');
    if std::io::stdout().lock().write_all(&bytes).is_err() {
        return ExitCode::from(2);
    }
    if identity_refused {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

/// W448: the manifest of the absolute `folder` alone, with the same
/// identity rule, walk, and limits as [`observe`].
pub(crate) fn tree_report(
    folder: &Path,
    limits: &Limits,
    (real, effective): (u32, u32),
) -> TreeReport {
    let clock = Clock {
        limits,
        started: Instant::now(),
    };
    let result = if real == 0 || effective != real {
        Err(ExportReason::Identity)
    } else {
        open_absolute(folder).and_then(|root| walk::tree(&root, &clock))
    };
    match result {
        Ok((files, _)) => TreeReport {
            schema_version: SchemaVersion::V1,
            status: ExportStatus::Complete,
            reason: None,
            files: Some(files),
        },
        Err(reason) => TreeReport {
            schema_version: SchemaVersion::V1,
            status: if matches!(
                reason,
                ExportReason::Entries | ExportReason::Depth | ExportReason::Time
            ) {
                ExportStatus::Limit
            } else {
                ExportStatus::Error
            },
            reason: Some(reason),
            files: None,
        },
    }
}

fn identity() -> (u32, u32) {
    (
        rustix::process::getuid().as_raw(),
        rustix::process::geteuid().as_raw(),
    )
}

/// Observes the export at the absolute `root`; a stopped run observes nothing.
pub(crate) fn observe(
    root: &Path,
    limits: &Limits,
    (real, effective): (u32, u32),
) -> ExportObservation {
    let clock = Clock {
        limits,
        started: Instant::now(),
    };
    let result = if real == 0 || effective != real {
        Err(ExportReason::Identity)
    } else {
        observe_export(root, &clock)
    };
    result.unwrap_or_else(|reason| {
        let status = if matches!(
            reason,
            ExportReason::Entries | ExportReason::Depth | ExportReason::Time
        ) {
            ExportStatus::Limit
        } else {
            ExportStatus::Error
        };
        ExportObservation::stopped(status, reason)
    })
}

fn observe_export(root: &Path, clock: &Clock<'_>) -> Result<ExportObservation, ExportReason> {
    let root = open_absolute(root)?;
    let meta_bytes = read_small(&root, "meta.xml", meta::MAX_META_BYTES)?;
    let meta = meta::parse(&meta_bytes)?;
    let home = fs::openat(&root, "public_html", DIRECTORY, Mode::empty())
        .map_err(|_| ExportReason::Unsupported)?;
    let (files, uploads) = walk::tree(&home, clock)?;

    // D-066: with several dumps, the one the live wp-config.php names is the
    // site's database; the others are left on the source.
    let live = if meta.databases.len() > 1 {
        live::live_database(&home, &meta.databases)
    } else {
        None
    };
    let mut left = Vec::new();
    // D-074: an export with no database is a static site only when its live
    // document root has no wp-config.php; else its database is unknown.
    let mut summaries = (!meta.databases.is_empty() || !live::has_wp_config(&home)).then(Vec::new);
    let mut site_url = dump::Seen::None;
    let mut home_url = dump::Seen::None;
    for name in &meta.databases {
        match open_regular(&root, &format!("{name}.sql"))? {
            Some(fd) => {
                let scanned = dump::scan(&fd, clock)?;
                if live.as_ref().is_some_and(|live| live != name) {
                    left.push(LeftOnSource {
                        kind: LeftKind::Database,
                        name: Text::try_from(name.clone()).map_err(|_| ExportReason::Metadata)?,
                        bytes: scanned.summary.as_ref().map(|summary| summary.bytes),
                    });
                    continue;
                }
                merge(&mut site_url, scanned.site_url);
                merge(&mut home_url, scanned.home_url);
                match (scanned.summary, summaries.as_mut()) {
                    (Some(summary), Some(list)) => list.push(summary),
                    _ => summaries = None,
                }
            }
            // A missing or compressed dump leaves the databases unknown.
            None => summaries = None,
        }
    }
    // D-066: CyberPanel's placeholder `mail.<hostname>` child domain is left
    // on the source; any other child domain still counts.
    let mut child_domains = meta.child_domains;
    if let Some(hostname) = &meta.hostname
        && usize::try_from(meta.child_domains).ok() == Some(meta.child_domain_names.len())
    {
        for child in &meta.child_domain_names {
            if live::placeholder_child(&home, hostname.as_str(), child) {
                child_domains -= 1;
                left.push(LeftOnSource {
                    kind: LeftKind::ChildDomain,
                    name: Text::try_from(child.clone()).map_err(|_| ExportReason::Metadata)?,
                    bytes: None,
                });
            }
        }
    }
    Ok(ExportObservation {
        schema_version: SchemaVersion::V1,
        status: ExportStatus::Complete,
        reason: None,
        hostname: meta.hostname.clone(),
        aliases: Some(meta.aliases.clone()),
        child_domains: Some(child_domains),
        files: Some(files),
        uploads: Some(uploads),
        databases: summaries,
        php_version: meta.php_version.clone(),
        site_url: site_url.text(),
        home_url: home_url.text(),
        tls: match &meta.hostname {
            Some(hostname) => tls::observe(&root, hostname)?,
            None => None,
        },
        credentials: Some(meta.credentials()),
        dns_records: Some(meta.dns_records),
        mail_accounts: Some(meta.mail_accounts),
        left_on_source: (!left.is_empty()).then_some(left),
    })
}

fn merge(into: &mut dump::Seen, from: dump::Seen) {
    *into = match (std::mem::take(into), from) {
        (dump::Seen::None, other) | (other, dump::Seen::None) => other,
        (dump::Seen::One(a), dump::Seen::One(b)) if a == b => dump::Seen::One(a),
        _ => dump::Seen::Ambiguous,
    };
}

const FILE: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NOCTTY)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);

/// Opens a top-level single-link regular file; `None` when it is absent.
fn open_regular(root: &OwnedFd, name: &str) -> Result<Option<OwnedFd>, ExportReason> {
    let stat = match fs::statat(root, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(Errno::NOENT) => return Ok(None),
        Err(_) => return Err(ExportReason::Io),
    };
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_nlink != 1
        || stat.st_mode & 0o6000 != 0
    {
        return Err(ExportReason::Unsupported);
    }
    let fd = fs::openat(root, name, FILE, Mode::empty()).map_err(|_| ExportReason::Io)?;
    let opened = fs::fstat(&fd).map_err(|_| ExportReason::Io)?;
    if (opened.st_dev, opened.st_ino) != (stat.st_dev, stat.st_ino) {
        return Err(ExportReason::Changed);
    }
    Ok(Some(fd))
}

fn read_small(root: &OwnedFd, name: &str, limit: usize) -> Result<Vec<u8>, ExportReason> {
    let fd = open_regular(root, name)?.ok_or(ExportReason::Unsupported)?;
    let mut bytes = Vec::new();
    let mut buffer = vec![0; 64 * 1024];
    loop {
        match rustix::io::read(&fd, &mut buffer) {
            Ok(0) => return Ok(bytes),
            Ok(read) => {
                if bytes.len() + read > limit {
                    return Err(ExportReason::Metadata);
                }
                bytes.extend_from_slice(&buffer[..read]);
            }
            Err(Errno::INTR) => {}
            Err(_) => return Err(ExportReason::Io),
        }
    }
}

/// Opens an absolute directory one component at a time, never following a
/// link. W447: the ancestors are opened as `O_PATH`, so a site root that
/// the site account may only traverse (`--x`) does not stop the walk; only
/// the export folder itself is opened for reading.
fn open_absolute(path: &Path) -> Result<OwnedFd, ExportReason> {
    if !path.is_absolute() {
        return Err(ExportReason::Unsupported);
    }
    let prefix = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut fd = fs::open("/", prefix, Mode::empty()).map_err(|_| ExportReason::Io)?;
    for (depth, part) in path.components().enumerate() {
        match part {
            Component::RootDir => {}
            Component::Normal(name) => {
                if depth > 64 {
                    return Err(ExportReason::Depth);
                }
                fd = fs::openat(&fd, name, prefix, Mode::empty()).map_err(|_| ExportReason::Io)?;
            }
            _ => return Err(ExportReason::Unsupported),
        }
    }
    fs::openat(&fd, ".", DIRECTORY, Mode::empty()).map_err(|_| ExportReason::Io)
}

#[cfg(test)]
mod tests;
