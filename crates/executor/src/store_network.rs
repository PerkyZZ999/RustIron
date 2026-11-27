//! W315/W317 (B01/B09): launch the product repository identity worker only
//! inside the verified loopback-only store namespace.
//!
//! Fixed host units, outside the executor, create the named network namespace
//! with the enrolled endpoint address on `lo`, load one nftables table into
//! it, and bind the store relay's listener inside it. The relay
//! (`systemd-socket-proxyd`, W316) forwards each connection from the host
//! namespace to the same endpoint; TLS stays end to end.
//!
//! Before each launch the executor checks that the host endpoint file names
//! the enrolled endpoint address and port, that the name is a namespace
//! handle in a root-owned directory, that the namespace has only `lo` with
//! the endpoint local on it, that its whole ruleset is exactly the endpoint
//! table, and that one listener is bound on the enrolled port (443 by
//! default, W352) in this namespace. Only then does PID 1
//! start the worker there, in the capture domain at the site's level, with
//! the four credential copies. Any observed difference refuses the launch.
//!
//! These checks observe; they do not make the namespace safe against a later
//! change by root. The serving firewall and host routing stay untouched.

use std::{
    net::{Ipv4Addr, SocketAddrV4},
    path::Path,
};

use rustiron_contracts::{
    Id,
    approval::{ProductBackupPolicy, Sha256Digest, SiteId},
};
use rustix::fs::{self, FileType};

use crate::{
    ExecutorError, TrustAnchor, capture,
    durable::repository_preflight::{self, StoreIdentity},
    files, layout, provision,
    retention_evidence::WrittenIndexes,
};

const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
const NFT: &str = "/usr/sbin/nft";
const IP: &str = "/usr/sbin/ip";
const SS: &str = "/usr/sbin/ss";
/// Host endpoint file in the policy directory. The store units read it as
/// `EnvironmentFile=`; the executor requires it to name the enrolled endpoint.
pub const STORE_NETWORK_FILE: &str = "store-network.env";
/// Read bound of the endpoint file; the longest valid file is 66 bytes.
const MAX_NETWORK_FILE_BYTES: usize = 128;
/// `NSFS_MAGIC` from `linux/magic.h`: the namespace filesystem.
const NSFS_MAGIC: u64 = 0x6e73_6673;
/// The worker allows its restic child 15 s; this bounds the whole unit.
const WORKER_RUNTIME_SECS: u64 = 30;
const _: () = assert!(WORKER_RUNTIME_SECS + 15 <= provision::COMMAND_TIMEOUT.as_secs());
/// W356: the snapshot write (its restic child gets 90 s) and the manifest
/// walk. Like the lab capture unit (100 s), with the same 5 s stop bound.
const WRITE_RUNTIME_SECS: u64 = 100;
const _: () = assert!(WRITE_RUNTIME_SECS + 5 + 10 <= provision::COMMAND_TIMEOUT.as_secs());
/// The manifest worker's stdout bound, as the lab capture unit's (W203).
const MAX_MANIFEST_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
/// The snapshot write's one result line, including its reported index keys.
const MAX_WRITE_OUTPUT_BYTES: usize = 256 + WrittenIndexes::MAX_BYTES;

/// Exact `nft -s list ruleset` text of the store namespace for one endpoint
/// (nftables 1.1.5 on the AlmaLinux 10 profile). One table, one output
/// chain, default drop, the endpoint flow and the relay listener's replies.
pub fn expected_ruleset(endpoint: SocketAddrV4) -> String {
    let (address, port) = (endpoint.ip(), endpoint.port());
    format!(
        "table inet rustiron_store {{\n\tchain output {{\n\t\ttype filter hook output priority filter; policy drop;\n\t\tip daddr {address} tcp dport {port} accept\n\t\tip saddr {address} tcp sport {port} accept\n\t}}\n}}\n"
    )
}

/// Exact content of the host endpoint file for one endpoint: the enrolled
/// IPv4 address and TCP port (W352), in this order and nothing else.
pub fn expected_network_file(endpoint: SocketAddrV4) -> String {
    format!(
        "RUSTIRON_STORE_ENDPOINT={}\nRUSTIRON_STORE_PORT={}\n",
        endpoint.ip(),
        endpoint.port()
    )
}

/// Refuses any ruleset other than the exact endpoint-only table.
pub fn check_ruleset(observed: &str, endpoint: SocketAddrV4) -> Result<(), ExecutorError> {
    if observed == expected_ruleset(endpoint) {
        Ok(())
    } else {
        Err(ExecutorError::PreconditionChanged)
    }
}

/// Checks `ip -4 -o route get ENDPOINT` output from inside the namespace:
/// the endpoint is a local address on `lo`, so the only way out is the relay.
pub fn check_route(observed: &str, endpoint: Ipv4Addr) -> Result<(), ExecutorError> {
    let words: Vec<&str> = observed.split_whitespace().collect();
    let address = endpoint.to_string();
    if words.len() >= 4 && words[..4] == ["local", address.as_str(), "dev", "lo"] {
        Ok(())
    } else {
        Err(ExecutorError::PreconditionChanged)
    }
}

/// Checks `ip -o link show` output from inside the namespace: `lo` and no
/// other link, so no veth, tunnel or moved device gives a second path.
pub fn check_links(observed: &str) -> Result<(), ExecutorError> {
    let lines: Vec<&str> = observed.lines().collect();
    match lines.as_slice() {
        [only] if only.split_whitespace().nth(1) == Some("lo:") => Ok(()),
        _ => Err(ExecutorError::PreconditionChanged),
    }
}

/// Checks `ss -Hltn` output from inside the namespace: exactly one TCP
/// listener, on IPv4 port `port`. A namespace replaced after the relay
/// socket started has none (W316), so the launch is refused.
pub fn check_listener(observed: &str, port: u16) -> Result<(), ExecutorError> {
    let lines: Vec<&str> = observed.lines().collect();
    let [only] = lines.as_slice() else {
        return Err(ExecutorError::PreconditionChanged);
    };
    let words: Vec<&str> = only.split_whitespace().collect();
    if words.first() == Some(&"LISTEN") && words.get(3) == Some(&format!("0.0.0.0:{port}").as_str())
    {
        Ok(())
    } else {
        Err(ExecutorError::PreconditionChanged)
    }
}

/// Checks that `path` is a namespace handle owned by `owner` in a directory
/// owned by `owner` that no group or other user can write.
pub fn check_namespace(path: &Path, owner: u32) -> Result<(), ExecutorError> {
    let parent = path.parent().ok_or(ExecutorError::AccessDenied)?;
    let directory = fs::lstat(parent).map_err(|_| ExecutorError::PreconditionChanged)?;
    if FileType::from_raw_mode(directory.st_mode) != FileType::Directory
        || directory.st_uid != owner
        || directory.st_mode & 0o022 != 0
    {
        return Err(ExecutorError::AccessDenied);
    }
    // `lstat` reports the mounted namespace inode, never a symbolic link.
    let handle = fs::lstat(path).map_err(|_| ExecutorError::PreconditionChanged)?;
    let filesystem = fs::statfs(path).map_err(|_| ExecutorError::PreconditionChanged)?;
    if FileType::from_raw_mode(handle.st_mode) == FileType::Symlink
        || handle.st_uid != owner
        || u64::try_from(filesystem.f_type) != Ok(NSFS_MAGIC)
    {
        return Err(ExecutorError::PreconditionChanged);
    }
    Ok(())
}

/// `systemd-run` arguments for one fixed read inside the store namespace.
/// The reader keeps only `CAP_NET_ADMIN` (nft needs it to list) and netlink.
/// It omits `NoNewPrivileges=`: on the guest that blocked PID 1's policy
/// transition into the tools' own domains (`iptables_t`, `ifconfig_t`), and
/// the transition is what confines them (W315 first probe).
///
/// PID 1 writes the reader's stdout to `output` in the admin helper's
/// runtime directory. `--pipe` is not used: it passes the caller's pipes to
/// PID 1 over D-Bus, and the broker may not write to a pipe of the helper
/// domain (W318).
fn namespace_read_arguments(unit: &str, output: &str, command: &[&str]) -> Vec<String> {
    let properties = [
        format!("NetworkNamespacePath={}", layout::STORE_NETNS),
        "CapabilityBoundingSet=CAP_NET_ADMIN".to_owned(),
        "RestrictAddressFamilies=AF_NETLINK".to_owned(),
        "IPAddressDeny=any".to_owned(),
        "ProtectSystem=strict".to_owned(),
        "ProtectHome=yes".to_owned(),
        "PrivateTmp=yes".to_owned(),
        "PrivateDevices=yes".to_owned(),
        "RuntimeMaxSec=10".to_owned(),
        format!("StandardOutput=truncate:{output}"),
    ];
    let mut args = vec![
        "--unit".to_owned(),
        unit.to_owned(),
        "--wait".to_owned(),
        "--quiet".to_owned(),
        "--collect".to_owned(),
    ];
    for property in properties {
        args.extend(["--property".to_owned(), property]);
    }
    args.push("--".to_owned());
    args.extend(command.iter().map(|value| (*value).to_owned()));
    args
}

/// A site's MCS level: `s0:cN` or `s0:cN,cM` with category numbers below 1024.
fn valid_level(level: &str) -> bool {
    let Some(categories) = level.strip_prefix("s0:") else {
        return false;
    };
    let parts: Vec<&str> = categories.split(',').collect();
    (1..=2).contains(&parts.len())
        && parts.iter().all(|part| {
            part.strip_prefix('c').is_some_and(|number| {
                (1..=4).contains(&number.len())
                    && number.bytes().all(|byte| byte.is_ascii_digit())
                    && (number == "0" || !number.starts_with('0'))
                    && number.parse::<u16>().is_ok_and(|value| value < 1024)
            })
        })
}

/// `systemd-run` arguments for the repository identity worker. The worker
/// runs as the site account in the capture domain inside the store
/// namespace, with only the four credential copies and no other secrets.
pub fn repository_check_arguments(
    unit: &str,
    site: &SiteId,
    level: &str,
    policy_digest: &Sha256Digest,
    endpoint: SocketAddrV4,
    credentials: &[String; 4],
) -> Result<Vec<String>, ExecutorError> {
    worker_arguments(
        unit,
        site,
        level,
        policy_digest,
        endpoint,
        credentials,
        WorkerAction::RepositoryId,
    )
}

/// The fixed worker actions a store job may run.
#[derive(Clone, Copy, Debug)]
pub enum WorkerAction<'a> {
    /// `repo-id`: the enrolled repository ID matches. Silent.
    RepositoryId,
    /// `snapshot-tag` (W321): snapshots tagged with this operation. PID 1
    /// writes the one result line to `output`.
    SnapshotTag {
        /// The journaled operation whose tag is listed.
        operation: &'a Id,
        /// Output file in the admin helper's runtime directory.
        output: &'a str,
    },
    /// `check` (W323): `restic check` passes after the repository ID
    /// matches. Silent. The caller passes the fetch credential copies.
    Check,
    /// `backup` (W323, W356): the snapshot write tagged with this operation,
    /// with the capture key pair. The worker's product write gate refuses it
    /// while it is closed. PID 1 writes the one result line to `output`.
    Backup {
        /// The journaled operation whose tag the snapshot carries.
        operation: &'a Id,
        /// Output file in the admin helper's runtime directory.
        output: &'a str,
    },
    /// `backup-app` (W601, D-096/P30): gated restic snapshot of an app site's
    /// `data/` directory and consistent SQLite online-backup bundle in `tmp/`.
    BackupApp {
        /// The journaled operation whose tag the snapshot carries.
        operation: &'a Id,
        /// Output file in the admin helper's runtime directory.
        output: &'a str,
    },
    /// `backup-app-pg` (W658, D-102 C2): gated restic snapshot of a PostgreSQL 18
    /// app site's `data/` directory and custom-format `pg_dump` file in `tmp/`.
    BackupAppPg {
        /// The journaled operation whose tag the snapshot carries.
        operation: &'a Id,
        /// Output file in the admin helper's runtime directory.
        output: &'a str,
    },
    /// `backup-app-mariadb` (W658, D-102 C2): gated restic snapshot of a MariaDB
    /// app site's `data/` directory and SQL dump file in `tmp/`.
    BackupAppMariadb {
        /// The journaled operation whose tag the snapshot carries.
        operation: &'a Id,
        /// Output file in the admin helper's runtime directory.
        output: &'a str,
    },
    /// `manifest` (W356, design step 10): the W203 manifest lines of one
    /// snapshot, read with the fetch key pair. PID 1 writes them to `output`.
    Manifest {
        /// The snapshot the capture wrote (64 lowercase hex).
        snapshot: &'a str,
        /// Output file in the admin helper's runtime directory.
        output: &'a str,
    },
    /// `lock` (W334): read-only. The bucket has versioning enabled and a
    /// default COMPLIANCE retention of at least the enrolled days. With an
    /// operation, each object that capture wrote also has a COMPLIANCE
    /// retention covering the enrolled days. The caller passes the capture
    /// credential copies (design steps 3 and 9). W391: PID 1 writes the
    /// closed evidence lines to `output`.
    Lock {
        /// The operation and new indexes from its write, or `None` for
        /// the bucket default only.
        written: Option<(&'a Id, &'a WrittenIndexes)>,
        /// Output file in the admin helper's runtime directory.
        output: &'a str,
    },
    /// `restore-size` (D-031, W373): the logical restore size of one
    /// snapshot, read with the fetch key pair as the probe account. PID 1
    /// writes the one result line to `output`.
    RestoreSize {
        /// The snapshot the probe restores (64 lowercase hex).
        snapshot: &'a str,
        /// The journaled probe account (`rp_` and six hex digits).
        probe: &'a str,
        /// Output file in the admin helper's runtime directory.
        output: &'a str,
    },
    /// `restore` (D-031, W373): `restic restore` of one snapshot into the
    /// probe sandbox, as the probe account with the fetch key pair. The one
    /// writable path is the sandbox's tmp directory. Silent.
    Restore {
        /// The snapshot the probe restores (64 lowercase hex).
        snapshot: &'a str,
        /// The journaled probe account (`rp_` and six hex digits).
        probe: &'a str,
    },
    /// `clone-restore-size` (D-078, W499): as `restore-size`, run as the
    /// target site account of a journaled clone at the target's level.
    CloneRestoreSize {
        /// The signed snapshot of the source capture (64 lowercase hex).
        snapshot: &'a str,
        /// The target site account (`rs_<site>`).
        account: &'a str,
        /// Output file in the admin helper's runtime directory.
        output: &'a str,
    },
    /// `clone-restore` (D-078, W499): `restic restore` of one snapshot into
    /// the target site's `tmp/clone`, as the target account with the source
    /// site's fetch key pair. The one writable path is the target's tmp
    /// directory. Silent.
    CloneRestore {
        /// The signed snapshot of the source capture (64 lowercase hex).
        snapshot: &'a str,
        /// The target site account (`rs_<site>`).
        account: &'a str,
    },
    /// W518-F5 (D-084): `clone-restore-size` of the site's own capture into
    /// its own `tmp/clone`, for an update's rollback. A clone action never
    /// names the source as its target; this one only ever names the site.
    SiteRestoreSize {
        /// The update's recorded capture snapshot (64 lowercase hex).
        snapshot: &'a str,
        /// Output file in the admin helper's runtime directory.
        output: &'a str,
    },
    /// W518-F5 (D-084): `clone-restore` of the site's own capture into its
    /// own `tmp/clone`, as the site with its fetch key pair. The one
    /// writable path is the site's tmp directory. Silent.
    SiteRestore {
        /// The update's recorded capture snapshot (64 lowercase hex).
        snapshot: &'a str,
    },
}

impl WorkerAction<'_> {
    /// The key pair PID 1 loads into the job's one `aws` slot: the capture
    /// principal only for the lock reads and the snapshot write (design steps
    /// 3, 6 and 9), the fetch principal for every other action.
    pub(crate) fn identity(&self) -> StoreIdentity {
        match self {
            Self::Lock { .. }
            | Self::Backup { .. }
            | Self::BackupApp { .. }
            | Self::BackupAppPg { .. }
            | Self::BackupAppMariadb { .. } => StoreIdentity::Capture,
            Self::RepositoryId
            | Self::SnapshotTag { .. }
            | Self::Check
            | Self::Manifest { .. }
            | Self::RestoreSize { .. }
            | Self::Restore { .. }
            | Self::CloneRestoreSize { .. }
            | Self::CloneRestore { .. }
            | Self::SiteRestoreSize { .. }
            | Self::SiteRestore { .. } => StoreIdentity::Fetch,
        }
    }

    /// The probe account a restore action runs as; `None` for the site
    /// actions, which run as the site account.
    fn probe(&self) -> Option<&str> {
        match self {
            Self::RestoreSize { probe, .. } | Self::Restore { probe, .. } => Some(probe),
            _ => None,
        }
    }

    /// The target site account a clone action runs as (D-078); `None` for
    /// every other action.
    fn clone_account(&self) -> Option<&str> {
        match self {
            Self::CloneRestoreSize { account, .. } | Self::CloneRestore { account, .. } => {
                Some(account)
            }
            _ => None,
        }
    }

    /// W518-F5: the update rollback's restore into the site's own tmp.
    fn own_restore(&self) -> bool {
        matches!(
            self,
            Self::SiteRestoreSize { .. } | Self::SiteRestore { .. }
        )
    }

    /// The worker's action word.
    fn name(&self) -> &'static str {
        match self {
            Self::RepositoryId => "repo-id",
            Self::SnapshotTag { .. } => "snapshot-tag",
            Self::Check => "check",
            Self::Backup { .. } => "backup",
            Self::BackupApp { .. } => "backup-app",
            Self::BackupAppPg { .. } => "backup-app-pg",
            Self::BackupAppMariadb { .. } => "backup-app-mariadb",
            Self::Lock { .. } => "lock",
            Self::Manifest { .. } => "manifest",
            Self::RestoreSize { .. } => "restore-size",
            Self::Restore { .. } => "restore",
            Self::CloneRestoreSize { .. } | Self::SiteRestoreSize { .. } => "clone-restore-size",
            Self::CloneRestore { .. } | Self::SiteRestore { .. } => "clone-restore",
        }
    }

    /// The runtime file PID 1 writes the worker's stdout to, if any.
    fn output(&self) -> Option<&str> {
        match self {
            Self::SnapshotTag { output, .. }
            | Self::Backup { output, .. }
            | Self::BackupApp { output, .. }
            | Self::BackupAppPg { output, .. }
            | Self::BackupAppMariadb { output, .. }
            | Self::Manifest { output, .. }
            | Self::RestoreSize { output, .. }
            | Self::CloneRestoreSize { output, .. }
            | Self::SiteRestoreSize { output, .. }
            | Self::Lock { output, .. } => Some(output),
            Self::RepositoryId
            | Self::Check
            | Self::Restore { .. }
            | Self::CloneRestore { .. }
            | Self::SiteRestore { .. } => None,
        }
    }

    /// The long-running actions: the write, the manifest walk and the
    /// probe's restore.
    fn long(&self) -> bool {
        matches!(
            self,
            Self::Backup { .. }
                | Self::BackupApp { .. }
                | Self::BackupAppPg { .. }
                | Self::BackupAppMariadb { .. }
                | Self::Manifest { .. }
                | Self::Restore { .. }
                | Self::CloneRestore { .. }
                | Self::SiteRestore { .. }
                | Self::Check
        )
    }
}

/// `systemd-run` arguments for one worker action in the store namespace.
pub fn worker_arguments(
    unit: &str,
    site: &SiteId,
    level: &str,
    policy_digest: &Sha256Digest,
    endpoint: SocketAddrV4,
    credentials: &[String; 4],
    action: WorkerAction<'_>,
) -> Result<Vec<String>, ExecutorError> {
    if !valid_level(level) {
        return Err(ExecutorError::InvalidRequest);
    }
    if let WorkerAction::Manifest { snapshot, .. }
    | WorkerAction::RestoreSize { snapshot, .. }
    | WorkerAction::Restore { snapshot, .. }
    | WorkerAction::CloneRestoreSize { snapshot, .. }
    | WorkerAction::CloneRestore { snapshot, .. }
    | WorkerAction::SiteRestoreSize { snapshot, .. }
    | WorkerAction::SiteRestore { snapshot } = action
        && Sha256Digest::try_from(snapshot.to_owned()).is_err()
    {
        return Err(ExecutorError::InvalidRequest);
    }
    // D-031: a restore action runs as the journaled probe account at the
    // probe level only, never as the site or at a site level.
    let probe_tmp = match action.probe() {
        Some(probe) => {
            if level != crate::restore::LEVEL {
                return Err(ExecutorError::InvalidRequest);
            }
            Some(layout::probe_tmp(probe).ok_or(ExecutorError::InvalidRequest)?)
        }
        None => None,
    };
    // D-078 (W499): a clone action runs as the target site account at a
    // site level, never at the probe level, and writes only its own tmp.
    let clone_tmp = match action.clone_account() {
        Some(account) => {
            if level == crate::restore::LEVEL || account == site.account_name() {
                return Err(ExecutorError::InvalidRequest);
            }
            Some(layout::clone_tmp(account).ok_or(ExecutorError::InvalidRequest)?)
        }
        // W518-F5: an update's rollback restores the site into its own tmp,
        // at a site level only.
        None if action.own_restore() => {
            if level == crate::restore::LEVEL {
                return Err(ExecutorError::InvalidRequest);
            }
            Some(layout::clone_tmp(&site.account_name()).ok_or(ExecutorError::InvalidRequest)?)
        }
        None => None,
    };
    let account = action
        .probe()
        .or(action.clone_account())
        .map_or_else(|| site.account_name(), str::to_owned);
    let (runtime, memory) = if action.long() {
        (WRITE_RUNTIME_SECS, "MemoryMax=512M")
    } else {
        (WORKER_RUNTIME_SECS, "MemoryMax=256M")
    };
    let mut properties = vec![
        format!("User={account}"),
        format!("Group={account}"),
        format!("SELinuxContext=system_u:system_r:rustiron_capture_t:{level}"),
        format!("NetworkNamespacePath={}", layout::STORE_NETNS),
        "RestrictAddressFamilies=AF_INET".to_owned(),
        "IPAddressDeny=any".to_owned(),
        format!("IPAddressAllow={}/32", endpoint.ip()),
        "NoNewPrivileges=yes".to_owned(),
        "CapabilityBoundingSet=".to_owned(),
        "ProtectSystem=strict".to_owned(),
        "ProtectHome=yes".to_owned(),
        "PrivateTmp=yes".to_owned(),
        "PrivateDevices=yes".to_owned(),
        "ProtectProc=invisible".to_owned(),
        format!("InaccessiblePaths=-{}", layout::JOB_CREDENTIALS_DIR),
        format!("RuntimeMaxSec={runtime}"),
        "TimeoutStopSec=5".to_owned(),
        memory.to_owned(),
        "MemorySwapMax=0".to_owned(),
        "TasksMax=32".to_owned(),
        provision::JOB_CPU_WEIGHT.to_owned(),
        match action.output() {
            None => "StandardOutput=null".to_owned(),
            Some(output) => format!("StandardOutput=truncate:{output}"),
        },
    ];
    if let WorkerAction::Backup { .. }
    | WorkerAction::BackupApp { .. }
    | WorkerAction::BackupAppPg { .. }
    | WorkerAction::BackupAppMariadb { .. } = action
    {
        // Restic's temporary pack files: the one writable path, the site's
        // own tmp directory, which also holds the dump it reads.
        properties.push(format!(
            "ReadWritePaths={}/{account}/tmp",
            layout::SITES_ROOT
        ));
    }
    if let (WorkerAction::Restore { .. }, Some(tmp)) = (action, &probe_tmp) {
        // The restored tree: the one writable path, the probe's tmp.
        properties.push(format!("ReadWritePaths={tmp}"));
        // D-034 (W378 b4): the page cache of a large restored file counts
        // against the unit. A 1,900 MiB file reached MemoryMax= and the
        // fetch was OOM-killed. Above MemoryHigh= the kernel throttles the
        // writer and reclaims, so the unit stays below MemoryMax=.
        properties.push(RESTORE_MEMORY_HIGH.to_owned());
    }
    if let (WorkerAction::CloneRestore { .. } | WorkerAction::SiteRestore { .. }, Some(tmp)) =
        (action, &clone_tmp)
    {
        // The restored tree: the one writable path, the target's own tmp.
        properties.push(format!("ReadWritePaths={tmp}"));
        properties.push(RESTORE_MEMORY_HIGH.to_owned());
    }
    properties.extend(credentials.iter().cloned());
    let mut args = vec![
        "--unit".to_owned(),
        unit.to_owned(),
        "--wait".to_owned(),
        "--quiet".to_owned(),
        "--collect".to_owned(),
    ];
    for property in properties {
        args.extend(["--property".to_owned(), property]);
    }
    args.extend([
        "--".to_owned(),
        format!("{}/{}", layout::JOB_BIN_DIR, crate::manifest::WORKER),
        action.name().to_owned(),
        site.as_str().to_owned(),
        policy_digest.as_str().to_owned(),
    ]);
    match action {
        WorkerAction::SnapshotTag { operation, .. }
        | WorkerAction::Backup { operation, .. }
        | WorkerAction::BackupApp { operation, .. }
        | WorkerAction::BackupAppPg { operation, .. }
        | WorkerAction::BackupAppMariadb { operation, .. } => {
            args.push(operation.as_str().to_owned())
        }
        WorkerAction::Lock {
            written: Some((operation, indexes)),
            ..
        } => {
            args.extend([operation.as_str().to_owned(), indexes.as_str().to_owned()]);
        }
        WorkerAction::Manifest { snapshot, .. } => args.push(snapshot.to_owned()),
        WorkerAction::RestoreSize {
            snapshot, probe, ..
        }
        | WorkerAction::Restore { snapshot, probe } => {
            args.extend([snapshot.to_owned(), probe.to_owned()]);
        }
        WorkerAction::CloneRestoreSize {
            snapshot, account, ..
        }
        | WorkerAction::CloneRestore { snapshot, account } => {
            args.extend([snapshot.to_owned(), account.to_owned()]);
        }
        WorkerAction::SiteRestoreSize { snapshot, .. } | WorkerAction::SiteRestore { snapshot } => {
            args.extend([snapshot.to_owned(), site.account_name()]);
        }
        WorkerAction::RepositoryId
        | WorkerAction::Check
        | WorkerAction::Lock { written: None, .. } => {}
    }
    Ok(args)
}

/// The throttle point of the probe's `restore` unit, below its 512 MiB
/// `MemoryMax=` (W383).
const RESTORE_MEMORY_HIGH: &str = "MemoryHigh=384M";

fn unit_name(kind: &str, site: &SiteId) -> Result<String, ExecutorError> {
    let mut random = [0_u8; 8];
    rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty())
        .map_err(|_| ExecutorError::Unavailable)?;
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!(
        "rustiron-store-{kind}-{}-{suffix}",
        site.account_name()
    ))
}

fn namespace_read(site: &SiteId, command: &[&str]) -> Result<String, ExecutorError> {
    let unit = unit_name("read", site)?;
    let name = format!("{unit}.out");
    let output = format!("{}/{name}", capture::OUTPUT_DIR);
    let args = namespace_read_arguments(&unit, &output, command);
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    capture::ensure_output_dir()?;
    let ran = provision::run(SYSTEMD_RUN, &borrowed);
    let directory = files::open_traversable_directory(Path::new(capture::OUTPUT_DIR), 0)?;
    let bytes = files::read_child(&directory, &name, 0, files::Exposure::Readable, 64 * 1024);
    let _ = fs::unlinkat(&directory, name.as_str(), fs::AtFlags::empty());
    ran.map_err(|_| ExecutorError::PreconditionChanged)?;
    String::from_utf8(bytes.map_err(|_| ExecutorError::PreconditionChanged)?)
        .map_err(|_| ExecutorError::PreconditionChanged)
}

/// One launched worker: the unit's result and, for an action with output,
/// its bounded stdout (the file is removed after the read).
struct Launched {
    ran: Result<(), ExecutorError>,
    output: Option<Result<Vec<u8>, ExecutorError>>,
}

/// Verifies the store namespace with the key pair of the action
/// ([`WorkerAction::identity`]), then runs the action's unit for `site`.
/// `policy` is the admitted projection; the worker reads the enrolled file
/// again and refuses a different digest. An `Err` means no unit started.
fn launch(
    anchor: &TrustAnchor,
    policy: &ProductBackupPolicy,
    site: &SiteId,
    level: &str,
    job: &Job,
    limit: usize,
    action: WorkerAction<'_>,
) -> Result<Launched, ExecutorError> {
    let (credentials, endpoint) = verify_store(anchor, policy, site, action.identity())?;
    let args = worker_arguments(
        &job.unit,
        site,
        level,
        &policy.digest(),
        endpoint,
        &credentials,
        action,
    )?;
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    if action.output() != Some(job.output.as_str()) {
        return Ok(Launched {
            ran: provision::run(SYSTEMD_RUN, &borrowed),
            output: None,
        });
    }
    capture::ensure_output_dir()?;
    let ran = provision::run(SYSTEMD_RUN, &borrowed);
    let directory = files::open_traversable_directory(Path::new(capture::OUTPUT_DIR), 0)?;
    let bytes = files::read_child(&directory, &job.name, 0, files::Exposure::Readable, limit);
    let _ = fs::unlinkat(&directory, job.name.as_str(), fs::AtFlags::empty());
    Ok(Launched {
        ran,
        output: Some(bytes),
    })
}

/// One store job's unit name and its stdout file in the helper's runtime
/// directory.
struct Job {
    unit: String,
    name: String,
    output: String,
}

impl Job {
    fn new(kind: &str, site: &SiteId) -> Result<Self, ExecutorError> {
        Ok(Self::named(unit_name(kind, site)?))
    }

    /// A job with a unit name the caller derived (a probe unit, D-031).
    fn named(unit: String) -> Self {
        let name = format!("{unit}.out");
        let output = format!("{}/{name}", capture::OUTPUT_DIR);
        Self { unit, name, output }
    }
}

/// The `restore-size` line: `restore-size <bytes> <files>`.
const MAX_RESTORE_SIZE_OUTPUT_BYTES: usize = 64;

/// D-031 (W373): verifies the store namespace, then runs the
/// `restore-size` worker as the probe account at the probe level with the
/// fetch key pair, in the probe unit `unit`. Returns the snapshot's logical
/// restore size and file count; anything else is an error.
pub fn probe_restore_size(
    anchor: &TrustAnchor,
    policy: &ProductBackupPolicy,
    site: &SiteId,
    probe: &str,
    snapshot: &str,
    unit: String,
) -> Result<(u64, u64), ExecutorError> {
    let job = Job::named(unit);
    let action = WorkerAction::RestoreSize {
        snapshot,
        probe,
        output: &job.output,
    };
    let launched = launch(
        anchor,
        policy,
        site,
        crate::restore::LEVEL,
        &job,
        MAX_RESTORE_SIZE_OUTPUT_BYTES,
        action,
    )?;
    launched.ran?;
    let bytes = launched.output.ok_or(ExecutorError::Unavailable)??;
    parse_restore_size(&bytes).ok_or(ExecutorError::StepFailed)
}

/// The worker's one line: `restore-size <u64> <u64>`, canonical decimals.
fn parse_restore_size(bytes: &[u8]) -> Option<(u64, u64)> {
    let text = std::str::from_utf8(bytes).ok()?;
    let line = text.strip_suffix('\n')?;
    let count = |word: &str| {
        (word == "0" || !word.starts_with('0'))
            .then(|| word.parse::<u64>().ok())
            .flatten()
    };
    match line.split(' ').collect::<Vec<_>>().as_slice() {
        ["restore-size", size, files] => Some((count(size)?, count(files)?)),
        _ => None,
    }
}

/// D-031 (W373): verifies the store namespace, then runs the `restore`
/// worker as the probe account at the probe level with the fetch key pair,
/// in the probe unit `unit`. Only a successful unit is a fetch.
pub fn probe_restore(
    anchor: &TrustAnchor,
    policy: &ProductBackupPolicy,
    site: &SiteId,
    probe: &str,
    snapshot: &str,
    unit: String,
) -> Result<(), ExecutorError> {
    let job = Job::named(unit);
    let action = WorkerAction::Restore { snapshot, probe };
    launch(anchor, policy, site, crate::restore::LEVEL, &job, 0, action)?.ran
}

/// D-078 (W499): the logical restore size and file count of the source
/// capture's snapshot, read with the source site's fetch key pair as the
/// clone's target account at its level, in the unit `unit`.
pub fn clone_restore_size(
    anchor: &TrustAnchor,
    policy: &ProductBackupPolicy,
    source: &SiteId,
    account: &str,
    level: &str,
    snapshot: &str,
    unit: String,
) -> Result<(u64, u64), ExecutorError> {
    let job = Job::named(unit);
    let action = WorkerAction::CloneRestoreSize {
        snapshot,
        account,
        output: &job.output,
    };
    let launched = launch(
        anchor,
        policy,
        source,
        level,
        &job,
        MAX_RESTORE_SIZE_OUTPUT_BYTES,
        action,
    )?;
    launched.ran?;
    let bytes = launched.output.ok_or(ExecutorError::Unavailable)??;
    parse_restore_size(&bytes).ok_or(ExecutorError::StepFailed)
}

/// D-078 (W499): verifies the store namespace, then runs the `clone-restore`
/// worker as the clone's target account at its level with the source site's
/// fetch key pair, in the unit `unit`. Only a successful unit is a fetch.
pub fn clone_restore(
    anchor: &TrustAnchor,
    policy: &ProductBackupPolicy,
    source: &SiteId,
    account: &str,
    level: &str,
    snapshot: &str,
    unit: String,
) -> Result<(), ExecutorError> {
    let job = Job::named(unit);
    let action = WorkerAction::CloneRestore { snapshot, account };
    launch(anchor, policy, source, level, &job, 0, action)?.ran
}

/// W518-F5 (D-084): an update rollback's restore size of the site's own
/// capture, as the site at its level with its fetch key pair.
pub fn site_restore_size(
    anchor: &TrustAnchor,
    policy: &ProductBackupPolicy,
    site: &SiteId,
    level: &str,
    snapshot: &str,
    unit: String,
) -> Result<(u64, u64), ExecutorError> {
    let job = Job::named(unit);
    let action = WorkerAction::SiteRestoreSize {
        snapshot,
        output: &job.output,
    };
    let launched = launch(
        anchor,
        policy,
        site,
        level,
        &job,
        MAX_RESTORE_SIZE_OUTPUT_BYTES,
        action,
    )?;
    launched.ran?;
    let bytes = launched.output.ok_or(ExecutorError::Unavailable)??;
    parse_restore_size(&bytes).ok_or(ExecutorError::StepFailed)
}

/// W518-F5 (D-084): an update rollback's restore of the site's own capture
/// into its own `tmp/clone`. Only a successful unit is a fetch.
pub fn site_restore(
    anchor: &TrustAnchor,
    policy: &ProductBackupPolicy,
    site: &SiteId,
    level: &str,
    snapshot: &str,
    unit: String,
) -> Result<(), ExecutorError> {
    let job = Job::named(unit);
    let action = WorkerAction::SiteRestore { snapshot };
    launch(anchor, policy, site, level, &job, 0, action)?.ran
}

/// Verifies the store namespace, then runs the repository identity worker
/// for `site` in it with the fetch key pair (design step 2).
pub fn check_repository(
    anchor: &TrustAnchor,
    policy: &ProductBackupPolicy,
    site: &SiteId,
    level: &str,
) -> Result<(), ExecutorError> {
    let job = Job::new("repo", site)?;
    launch(
        anchor,
        policy,
        site,
        level,
        &job,
        0,
        WorkerAction::RepositoryId,
    )?
    .ran
}

/// W345: verifies the store namespace, then runs the read-only `lock`
/// worker for `site` with the capture credential copies (W334 design steps
/// 3 and 9). Without an operation it checks the bucket's versioning and
/// default COMPLIANCE retention; with one, also the retention of each object
/// that the tagged capture wrote. Any refusal or failed unit is an error.
///
/// W391: a pass returns what the worker read back: the bucket default and,
/// with an operation, each written object version. Output that is not the
/// closed line set is an error, as a refusal is.
pub fn check_lock(
    anchor: &TrustAnchor,
    policy: &ProductBackupPolicy,
    site: &SiteId,
    level: &str,
    written: Option<(&Id, &WrittenIndexes)>,
) -> Result<crate::retention_evidence::LockReading, ExecutorError> {
    let job = Job::new("lock", site)?;
    let action = WorkerAction::Lock {
        written,
        output: &job.output,
    };
    let launched = launch(
        anchor,
        policy,
        site,
        level,
        &job,
        crate::retention_evidence::MAX_LOCK_OUTPUT_BYTES,
        action,
    )?;
    launched.ran?;
    let bytes = launched
        .output
        .ok_or(ExecutorError::RetentionUnverified)??;
    crate::retention_evidence::parse_lock(&bytes, written.is_some())
        .ok_or(ExecutorError::RetentionUnverified)
}

/// W356: verifies the store namespace, then runs `restic check` (structure,
/// no lock) through the worker with the fetch key pair (design step 7).
pub fn check_structure(
    anchor: &TrustAnchor,
    policy: &ProductBackupPolicy,
    site: &SiteId,
    level: &str,
) -> Result<(), ExecutorError> {
    let job = Job::new("check", site)?;
    launch(anchor, policy, site, level, &job, 0, WorkerAction::Check)?.ran
}

/// A snapshot the write reported complete.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WrittenSnapshot {
    /// 64 lowercase hex.
    pub id: String,
    /// Restic's `total_files_processed`.
    pub files: u64,
    /// Restic's `total_bytes_processed`.
    pub bytes: u64,
    /// New index keys from the write worker's before and after listings.
    pub indexes: WrittenIndexes,
}

/// Why a snapshot write has no complete result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WriteFailure {
    /// The store checks refused before any unit started: nothing was sent.
    NotLaunched(ExecutorError),
    /// The unit started. The store may hold a snapshot, named here when the
    /// worker reported one (`partial <id>`).
    Launched {
        /// The unit's error, or `StepFailed` for an unreadable result.
        error: ExecutorError,
        /// The snapshot the worker named, if any.
        snapshot: Option<String>,
    },
}

/// W356 (design step 6): verifies the store namespace, then runs the gated
/// `backup` worker with the capture key pair. Only a successful unit with
/// the one `snapshot` line is complete.
pub fn write_snapshot(
    anchor: &TrustAnchor,
    policy: &ProductBackupPolicy,
    site: &SiteId,
    level: &str,
    operation: &Id,
) -> Result<WrittenSnapshot, WriteFailure> {
    write_snapshot_kind(anchor, policy, site, level, operation, None)
}

/// W601 (D-096/P30): as [`write_snapshot`] for a P27/EmDash app site (`data/`
/// + consistent SQLite bundle in `tmp/`).
pub fn write_app_snapshot(
    anchor: &TrustAnchor,
    policy: &ProductBackupPolicy,
    site: &SiteId,
    level: &str,
    operation: &Id,
) -> Result<WrittenSnapshot, WriteFailure> {
    write_snapshot_kind(
        anchor,
        policy,
        site,
        level,
        operation,
        Some(rustiron_contracts::approval::AppDatabase::Sqlite),
    )
}

/// W658 (D-102 C2): as [`write_app_snapshot`] selecting the exact closed worker
/// action matching the app's enrolled database engine.
pub fn write_app_snapshot_for_db(
    anchor: &TrustAnchor,
    policy: &ProductBackupPolicy,
    site: &SiteId,
    level: &str,
    operation: &Id,
    database: rustiron_contracts::approval::AppDatabase,
) -> Result<WrittenSnapshot, WriteFailure> {
    write_snapshot_kind(anchor, policy, site, level, operation, Some(database))
}

fn write_snapshot_kind(
    anchor: &TrustAnchor,
    policy: &ProductBackupPolicy,
    site: &SiteId,
    level: &str,
    operation: &Id,
    app_db: Option<rustiron_contracts::approval::AppDatabase>,
) -> Result<WrittenSnapshot, WriteFailure> {
    use rustiron_contracts::approval::AppDatabase;
    let job = Job::new("write", site).map_err(WriteFailure::NotLaunched)?;
    let action = match app_db {
        None => WorkerAction::Backup {
            operation,
            output: &job.output,
        },
        Some(AppDatabase::None | AppDatabase::Sqlite) => WorkerAction::BackupApp {
            operation,
            output: &job.output,
        },
        Some(AppDatabase::Postgresql18) => WorkerAction::BackupAppPg {
            operation,
            output: &job.output,
        },
        Some(AppDatabase::Mariadb) => WorkerAction::BackupAppMariadb {
            operation,
            output: &job.output,
        },
    };
    let launched = launch(
        anchor,
        policy,
        site,
        level,
        &job,
        MAX_WRITE_OUTPUT_BYTES,
        action,
    )
    .map_err(WriteFailure::NotLaunched)?;
    let bytes = launched.output.and_then(Result::ok).unwrap_or_default();
    parse_write_result(launched.ran, &bytes)
}

/// The write's result from the unit status and its one line.
fn parse_write_result(
    ran: Result<(), ExecutorError>,
    bytes: &[u8],
) -> Result<WrittenSnapshot, WriteFailure> {
    let text = std::str::from_utf8(bytes).unwrap_or_default();
    let line = text.strip_suffix('\n').unwrap_or(text);
    let words: Vec<&str> = if line.contains('\n') {
        Vec::new()
    } else {
        line.split(' ').collect()
    };
    let full_id = |word: &str| {
        Sha256Digest::try_from(word.to_owned())
            .ok()
            .map(|_| word.to_owned())
    };
    let count = |word: &str| {
        (word == "0" || !word.starts_with('0'))
            .then(|| word.parse::<u64>().ok())
            .flatten()
    };
    let named = match words.as_slice() {
        ["snapshot", id, ..] | ["partial" | "index-unverified", id] => full_id(id),
        _ => None,
    };
    let read_complete = || {
        let ["snapshot", _, files, total, indexes] = words.as_slice() else {
            return None;
        };
        Some(WrittenSnapshot {
            id: named.clone()?,
            files: count(files)?,
            bytes: count(total)?,
            indexes: WrittenIndexes::parse(indexes)?,
        })
    };
    if ran.is_ok()
        && let Some(complete) = read_complete()
    {
        return Ok(complete);
    }
    let error = if matches!(words.as_slice(), ["index-unverified", _]) && named.is_some() {
        ExecutorError::RetentionUnverified
    } else {
        ran.err().unwrap_or(ExecutorError::StepFailed)
    };
    Err(WriteFailure::Launched {
        error,
        snapshot: named,
    })
}

/// W356 (design step 10): verifies the store namespace, then runs the
/// `manifest` worker with the fetch key pair. Returns its bounded W203
/// lines; the caller rebuilds and checks the manifest.
pub fn snapshot_manifest(
    anchor: &TrustAnchor,
    policy: &ProductBackupPolicy,
    site: &SiteId,
    level: &str,
    snapshot: &str,
) -> Result<Vec<u8>, ExecutorError> {
    let job = Job::new("manifest", site)?;
    let action = WorkerAction::Manifest {
        snapshot,
        output: &job.output,
    };
    let launched = launch(
        anchor,
        policy,
        site,
        level,
        &job,
        MAX_MANIFEST_OUTPUT_BYTES,
        action,
    )?;
    launched.ran?;
    launched.output.ok_or(ExecutorError::Unavailable)?
}

/// W321: verifies the store namespace, then lists the snapshots of `site`
/// tagged with `operation`, after the worker matched the repository ID.
/// `Ok(None)` is no snapshot; `Ok(Some(id))` exactly one. A refusal, a
/// failed unit or any other output is an error, so the caller keeps an
/// unresolved capture unresolved.
pub fn find_tagged_snapshot(
    anchor: &TrustAnchor,
    policy: &ProductBackupPolicy,
    site: &SiteId,
    level: &str,
    operation: &Id,
) -> Result<Option<String>, ExecutorError> {
    let job = Job::new("tag", site)?;
    let action = WorkerAction::SnapshotTag {
        operation,
        output: &job.output,
    };
    let launched = launch(anchor, policy, site, level, &job, 256, action)?;
    launched.ran.map_err(|_| ExecutorError::Unavailable)?;
    let bytes = launched.output.ok_or(ExecutorError::Unavailable)?;
    parse_tag_result(&bytes.map_err(|_| ExecutorError::Unavailable)?)
}

/// The worker's one line: `none` or `found <64 lowercase hex>`.
fn parse_tag_result(bytes: &[u8]) -> Result<Option<String>, ExecutorError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ExecutorError::Unavailable)?;
    match text.strip_suffix('\n').unwrap_or(text) {
        "none" => Ok(None),
        line => line
            .strip_prefix("found ")
            .filter(|id| Sha256Digest::try_from((*id).to_owned()).is_ok())
            .map(|id| Some(id.to_owned()))
            .ok_or(ExecutorError::Unavailable),
    }
}

/// Every check before a store job: credential sources, the endpoint file,
/// and the namespace, its links, route, ruleset and relay listener.
fn verify_store(
    anchor: &TrustAnchor,
    policy: &ProductBackupPolicy,
    site: &SiteId,
    identity: StoreIdentity,
) -> Result<([String; 4], SocketAddrV4), ExecutorError> {
    let enrolled = policy
        .resolve_site(site)
        .ok_or(ExecutorError::PreconditionChanged)?;
    let directory = files::open_trusted_directory(&anchor.policy_dir, anchor.owner_uid)?;
    let credentials =
        repository_preflight::credential_properties(anchor, &directory, &enrolled, identity)?;
    let endpoint = enrolled.endpoint();
    let file = files::read_child(
        &directory,
        STORE_NETWORK_FILE,
        anchor.owner_uid,
        files::Exposure::Readable,
        MAX_NETWORK_FILE_BYTES,
    )?;
    if file != expected_network_file(endpoint).as_bytes() {
        return Err(ExecutorError::PreconditionChanged);
    }
    check_namespace(Path::new(layout::STORE_NETNS), anchor.owner_uid)?;
    check_links(&namespace_read(site, &[IP, "-o", "link", "show"])?)?;
    let address = endpoint.ip().to_string();
    check_route(
        &namespace_read(site, &[IP, "-4", "-o", "route", "get", &address])?,
        *endpoint.ip(),
    )?;
    check_ruleset(
        &namespace_read(site, &[NFT, "-s", "list", "ruleset"])?,
        endpoint,
    )?;
    check_listener(&namespace_read(site, &[SS, "-Hltn"])?, endpoint.port())?;
    Ok((credentials, endpoint))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 23), 443);

    /// Byte-for-byte `nft -s list ruleset` from the AlmaLinux guest (W316).
    const GUEST: &str = "table inet rustiron_store {\n\tchain output {\n\t\ttype filter hook output priority filter; policy drop;\n\t\tip daddr 198.51.100.23 tcp dport 443 accept\n\t\tip saddr 198.51.100.23 tcp sport 443 accept\n\t}\n}\n";

    #[test]
    fn only_the_exact_endpoint_table_passes() {
        assert_eq!(expected_ruleset(PEER), GUEST);
        assert_eq!(check_ruleset(GUEST, PEER), Ok(()));
        let refused = [
            String::new(),
            GUEST.replace("443 accept", "8443 accept"),
            GUEST.replace("policy drop", "policy accept"),
            GUEST.replace(".23 ", ".24 "),
            GUEST.replace(
                "accept\n",
                "accept\n\t\tip daddr 198.51.100.23 tcp dport 8443 accept\n",
            ),
            format!("{GUEST}table ip extra {{\n}}\n"),
            GUEST.trim_end().to_owned(),
            GUEST.replace("\t\tip saddr 198.51.100.23 tcp sport 443 accept\n", ""),
        ];
        for ruleset in refused {
            assert_eq!(
                check_ruleset(&ruleset, PEER),
                Err(ExecutorError::PreconditionChanged),
                "{ruleset:?}"
            );
        }
        assert_eq!(
            check_ruleset(GUEST, SocketAddrV4::new(*PEER.ip(), 8443)),
            Err(ExecutorError::PreconditionChanged)
        );
    }

    #[test]
    fn only_the_endpoint_local_on_lo_passes() {
        // Byte-for-byte from the AlmaLinux guest (W317).
        let guest = "local 198.51.100.23 dev lo src 198.51.100.23 uid 0 \\    cache <local> ";
        assert_eq!(check_route(guest, *PEER.ip()), Ok(()));
        let refused = [
            "",
            "198.51.100.23 dev rs-store src 198.51.100.22 uid 0 \\    cache ",
            "198.51.100.23 via 10.0.0.1 dev eth0 src 10.0.0.2 uid 0",
            "local 198.51.100.24 dev lo src 198.51.100.24 uid 0",
            "local 198.51.100.23 dev dummy0 src 198.51.100.23 uid 0",
            "broadcast 198.51.100.23 dev lo src 198.51.100.23",
            "local 198.51.100.23",
        ];
        for route in refused {
            assert_eq!(
                check_route(route, *PEER.ip()),
                Err(ExecutorError::PreconditionChanged),
                "{route}"
            );
        }
    }

    #[test]
    fn only_loopback_may_exist_in_the_namespace() {
        let guest = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n";
        assert_eq!(check_links(guest), Ok(()));
        let veth = format!(
            "{guest}2: rs-store@if3: <BROADCAST,UP> mtu 1500\\    link/ether 00:11:22:33:44:55\n"
        );
        for links in ["", veth.as_str(), "2: eth0: <UP> mtu 1500\n"] {
            assert_eq!(
                check_links(links),
                Err(ExecutorError::PreconditionChanged),
                "{links}"
            );
        }
    }

    #[test]
    fn exactly_one_ipv4_listener_on_the_endpoint_port_passes() {
        // Byte-for-byte `ss -Hltn` from the AlmaLinux guest (W317).
        let guest = "LISTEN 0      128    0.0.0.0:443 0.0.0.0:*\n";
        assert_eq!(check_listener(guest, 443), Ok(()));
        let refused = [
            String::new(),
            "LISTEN 0      128    0.0.0.0:8443 0.0.0.0:*\n".to_owned(),
            "LISTEN 0      128    127.0.0.1:443 0.0.0.0:*\n".to_owned(),
            format!("{guest}LISTEN 0      128    0.0.0.0:8443 0.0.0.0:*\n"),
            "ESTAB 0      0    0.0.0.0:443 0.0.0.0:*\n".to_owned(),
        ];
        for listeners in refused {
            assert_eq!(
                check_listener(&listeners, 443),
                Err(ExecutorError::PreconditionChanged),
                "{listeners}"
            );
        }
    }

    #[test]
    fn the_network_file_names_only_the_endpoint_and_port() {
        assert_eq!(
            expected_network_file(PEER),
            "RUSTIRON_STORE_ENDPOINT=198.51.100.23\nRUSTIRON_STORE_PORT=443\n"
        );
        let other = SocketAddrV4::new(*PEER.ip(), 9443);
        assert_eq!(
            expected_network_file(other),
            "RUSTIRON_STORE_ENDPOINT=198.51.100.23\nRUSTIRON_STORE_PORT=9443\n"
        );
        // The longest file fits the bounded read.
        let longest = SocketAddrV4::new(Ipv4Addr::new(255, 255, 255, 255), 65535);
        assert!(expected_network_file(longest).len() <= MAX_NETWORK_FILE_BYTES);
    }

    #[test]
    fn an_enrolled_non_443_port_is_checked_everywhere() {
        // W352: byte-for-byte `nft -s list ruleset` and `ss -Hltn` from the
        // AlmaLinux guest with the endpoint enrolled on port 9443.
        let peer = SocketAddrV4::new(Ipv4Addr::new(192, 168, 122, 1), 9443);
        let ruleset = "table inet rustiron_store {\n\tchain output {\n\t\ttype filter hook output priority filter; policy drop;\n\t\tip daddr 192.168.122.1 tcp dport 9443 accept\n\t\tip saddr 192.168.122.1 tcp sport 9443 accept\n\t}\n}\n";
        assert_eq!(check_ruleset(ruleset, peer), Ok(()));
        let at_443 = SocketAddrV4::new(*peer.ip(), 443);
        assert_eq!(
            check_ruleset(ruleset, at_443),
            Err(ExecutorError::PreconditionChanged)
        );
        let listener = "LISTEN 0      4096   0.0.0.0:9443 0.0.0.0:*\n";
        assert_eq!(check_listener(listener, 9443), Ok(()));
        for port in [443, 944, 943] {
            assert_eq!(
                check_listener(listener, port),
                Err(ExecutorError::PreconditionChanged),
                "{port}"
            );
        }
    }

    #[test]
    fn a_plain_file_or_magic_link_is_not_a_namespace_handle() {
        let owner = rustix::process::getuid().as_raw();
        let file = std::env::temp_dir().join(format!("ri-w315-{}", std::process::id()));
        std::fs::write(&file, b"").unwrap();
        let plain = check_namespace(&file, owner);
        std::fs::remove_file(&file).unwrap();
        assert!(plain.is_err());
        // The nsfs magic link itself is a symbolic link to lstat.
        let link = Path::new("/proc/self/ns/net");
        assert!(check_namespace(link, owner).is_err());
        assert!(check_namespace(Path::new("/nonexistent/rustiron-store"), owner).is_err());
    }

    #[test]
    fn levels_are_one_or_two_bounded_categories() {
        for level in ["s0:c0", "s0:c12,c900", "s0:c1023"] {
            assert!(valid_level(level), "{level}");
        }
        for level in [
            "",
            "s0",
            "s0:",
            "s0:c1024",
            "s0:c01",
            "s0:c1,c2,c3",
            "s1:c1",
            "s0:c1 ",
            "s0:c1;x",
            "s0-s0:c1",
            "s0:c",
        ] {
            assert!(!valid_level(level), "{level}");
        }
    }

    #[test]
    fn the_worker_unit_is_bound_to_the_store_namespace_and_capture_domain() {
        let site = SiteId::try_from("blog9".to_owned()).unwrap();
        let digest = Sha256Digest::try_from("ab".repeat(32)).unwrap();
        let credentials = [
            "LoadCredential=destination:/p/backup-destination.json".to_owned(),
            "LoadCredential=ca:/p/backup-ca.pem".to_owned(),
            "LoadCredential=aws:/p/s/rs_blog9/fetch-aws".to_owned(),
            "LoadCredential=password:/p/s/rs_blog9/repo.password".to_owned(),
        ];
        let args = repository_check_arguments(
            "rustiron-store-repo-rs_blog9-00",
            &site,
            "s0:c3,c7",
            &digest,
            PEER,
            &credentials,
        )
        .unwrap();
        let properties: Vec<&str> = args
            .windows(2)
            .filter(|pair| pair[0] == "--property")
            .map(|pair| pair[1].as_str())
            .collect();
        for expected in [
            "User=rs_blog9",
            "Group=rs_blog9",
            "SELinuxContext=system_u:system_r:rustiron_capture_t:s0:c3,c7",
            &format!("NetworkNamespacePath={}", layout::STORE_NETNS),
            "RestrictAddressFamilies=AF_INET",
            "IPAddressDeny=any",
            "IPAddressAllow=198.51.100.23/32",
            "CapabilityBoundingSet=",
            "NoNewPrivileges=yes",
            &format!("InaccessiblePaths=-{}", layout::JOB_CREDENTIALS_DIR),
        ] {
            assert!(properties.contains(&expected), "{expected}");
        }
        for credential in &credentials {
            assert!(properties.contains(&credential.as_str()));
        }
        assert_eq!(
            properties
                .iter()
                .filter(|p| p.starts_with("LoadCredential="))
                .count(),
            4
        );
        assert!(!properties.iter().any(|p| p.starts_with("Environment")
            || p.starts_with("PrivateNetwork")
            || p.starts_with("SetCredential")));
        let separator = args.iter().position(|arg| arg == "--").unwrap();
        assert_eq!(
            &args[separator + 1..],
            [
                format!("{}/capture-manifest", layout::JOB_BIN_DIR),
                "repo-id".to_owned(),
                "blog9".to_owned(),
                "ab".repeat(32),
            ]
        );
        assert_eq!(
            repository_check_arguments("u", &site, "s0:c3,c7 ", &digest, PEER, &credentials),
            Err(ExecutorError::InvalidRequest)
        );
    }

    #[test]
    fn the_tag_worker_writes_one_line_to_the_helper_directory() {
        let site = SiteId::try_from("blog9".to_owned()).unwrap();
        let digest = Sha256Digest::try_from("ab".repeat(32)).unwrap();
        let operation = Id::try_from("op_w321".to_owned()).unwrap();
        let credentials = std::array::from_fn(|n| format!("LoadCredential=c{n}:/p/{n}"));
        let args = worker_arguments(
            "u",
            &site,
            "s0:c3",
            &digest,
            PEER,
            &credentials,
            WorkerAction::SnapshotTag {
                operation: &operation,
                output: "/run/rustiron-admin/u.out",
            },
        )
        .unwrap();
        assert!(args.contains(&"StandardOutput=truncate:/run/rustiron-admin/u.out".to_owned()));
        assert!(!args.contains(&"StandardOutput=null".to_owned()));
        let separator = args.iter().position(|arg| arg == "--").unwrap();
        assert_eq!(
            &args[separator + 2..],
            ["snapshot-tag", "blog9", &"ab".repeat(32), "op_w321"]
        );
    }

    /// The worker argv after `--`, and the one `StandardOutput=` property.
    fn worker_tail(action: WorkerAction<'_>) -> (Vec<String>, Vec<String>) {
        let site = SiteId::try_from("blog9".to_owned()).unwrap();
        let digest = Sha256Digest::try_from("ab".repeat(32)).unwrap();
        let credentials = std::array::from_fn(|n| format!("LoadCredential=c{n}:/p/{n}"));
        let args =
            worker_arguments("u", &site, "s0:c3", &digest, PEER, &credentials, action).unwrap();
        let outputs = args
            .iter()
            .filter(|arg| arg.starts_with("StandardOutput="))
            .cloned()
            .collect();
        let separator = args.iter().position(|arg| arg == "--").unwrap();
        (args[separator + 1..].to_vec(), outputs)
    }

    #[test]
    fn the_check_worker_takes_only_site_and_digest() {
        let (tail, outputs) = worker_tail(WorkerAction::Check);
        assert_eq!(
            tail,
            [
                format!("{}/capture-manifest", layout::JOB_BIN_DIR),
                "check".to_owned(),
                "blog9".to_owned(),
                "ab".repeat(32),
            ]
        );
        assert_eq!(outputs, ["StandardOutput=null"]);
    }

    #[test]
    fn the_backup_worker_takes_the_operation_and_nothing_else() {
        let operation = Id::try_from("op_w323".to_owned()).unwrap();
        let (tail, outputs) = worker_tail(WorkerAction::Backup {
            operation: &operation,
            output: "/run/rustiron-admin/w.out",
        });
        assert_eq!(
            tail,
            [
                format!("{}/capture-manifest", layout::JOB_BIN_DIR),
                "backup".to_owned(),
                "blog9".to_owned(),
                "ab".repeat(32),
                "op_w323".to_owned(),
            ]
        );
        assert_eq!(
            outputs,
            ["StandardOutput=truncate:/run/rustiron-admin/w.out"]
        );
    }

    /// All `--property` values of one worker unit.
    fn worker_properties(action: WorkerAction<'_>) -> Vec<String> {
        let site = SiteId::try_from("blog9".to_owned()).unwrap();
        let digest = Sha256Digest::try_from("ab".repeat(32)).unwrap();
        let credentials = std::array::from_fn(|n| format!("LoadCredential=c{n}:/p/{n}"));
        let args =
            worker_arguments("u", &site, "s0:c3", &digest, PEER, &credentials, action).unwrap();
        args.windows(2)
            .filter(|pair| pair[0] == "--property")
            .map(|pair| pair[1].clone())
            .collect()
    }

    #[test]
    fn only_the_lock_reads_and_the_write_get_the_capture_key_pair() {
        // W356: the design table's credential column, per worker action.
        let operation = Id::try_from("op_w356".to_owned()).unwrap();
        let indexes = WrittenIndexes::parse("-").unwrap();
        let snapshot = "d".repeat(64);
        let cases = [
            (WorkerAction::RepositoryId, StoreIdentity::Fetch),
            (
                WorkerAction::Lock {
                    written: None,
                    output: "o",
                },
                StoreIdentity::Capture,
            ),
            (
                WorkerAction::Backup {
                    operation: &operation,
                    output: "o",
                },
                StoreIdentity::Capture,
            ),
            (WorkerAction::Check, StoreIdentity::Fetch),
            (
                WorkerAction::SnapshotTag {
                    operation: &operation,
                    output: "o",
                },
                StoreIdentity::Fetch,
            ),
            (
                WorkerAction::Lock {
                    written: Some((&operation, &indexes)),
                    output: "o",
                },
                StoreIdentity::Capture,
            ),
            (
                WorkerAction::Manifest {
                    snapshot: &snapshot,
                    output: "o",
                },
                StoreIdentity::Fetch,
            ),
        ];
        for (action, identity) in cases {
            assert_eq!(action.identity(), identity, "{action:?}");
        }
    }

    #[test]
    fn the_write_unit_may_write_only_the_site_tmp_and_runs_longer() {
        let operation = Id::try_from("op_w356".to_owned()).unwrap();
        let write = worker_properties(WorkerAction::Backup {
            operation: &operation,
            output: "o",
        });
        for expected in [
            format!("ReadWritePaths={}/rs_blog9/tmp", layout::SITES_ROOT),
            "RuntimeMaxSec=100".to_owned(),
            "MemoryMax=512M".to_owned(),
            "ProtectSystem=strict".to_owned(),
            "NoNewPrivileges=yes".to_owned(),
            format!("InaccessiblePaths=-{}", layout::JOB_CREDENTIALS_DIR),
        ] {
            assert!(write.contains(&expected), "{expected}");
        }
        assert_eq!(
            write
                .iter()
                .filter(|p| p.starts_with("ReadWritePaths="))
                .count(),
            1
        );
        // Every other action keeps the read-only 30 s unit.
        for action in [
            WorkerAction::RepositoryId,
            WorkerAction::Lock {
                written: None,
                output: "o",
            },
        ] {
            let read = worker_properties(action);
            assert!(read.contains(&"RuntimeMaxSec=30".to_owned()));
            assert!(read.contains(&"MemoryMax=256M".to_owned()));
            assert!(!read.iter().any(|p| p.starts_with("ReadWritePaths=")));
        }
    }

    #[test]
    fn the_repository_check_gets_the_long_read_only_unit() {
        // W378: `restic check` of a repository with 36 snapshots took
        // 7 to 16 s, so a 15 s check failed the integrity field of the probe.
        let read = worker_properties(WorkerAction::Check);
        assert!(read.contains(&format!("RuntimeMaxSec={WRITE_RUNTIME_SECS}")));
        assert!(read.contains(&"MemoryMax=512M".to_owned()));
        assert!(!read.iter().any(|p| p.starts_with("ReadWritePaths=")));
    }

    #[test]
    fn the_manifest_worker_takes_one_full_snapshot_id() {
        let snapshot = "e".repeat(64);
        let (tail, outputs) = worker_tail(WorkerAction::Manifest {
            snapshot: &snapshot,
            output: "/run/rustiron-admin/m.out",
        });
        assert_eq!(
            tail[1..],
            ["manifest", "blog9", &"ab".repeat(32), &snapshot]
        );
        assert_eq!(
            outputs,
            ["StandardOutput=truncate:/run/rustiron-admin/m.out"]
        );
        let properties = worker_properties(WorkerAction::Manifest {
            snapshot: &snapshot,
            output: "o",
        });
        assert!(properties.contains(&"RuntimeMaxSec=100".to_owned()));
        assert!(!properties.iter().any(|p| p.starts_with("ReadWritePaths=")));
        let site = SiteId::try_from("blog9".to_owned()).unwrap();
        let digest = Sha256Digest::try_from("ab".repeat(32)).unwrap();
        let credentials = std::array::from_fn(|n| format!("LoadCredential=c{n}:/p/{n}"));
        for bad in ["e".repeat(63), "E".repeat(64), "latest".to_owned()] {
            assert_eq!(
                worker_arguments(
                    "u",
                    &site,
                    "s0:c3",
                    &digest,
                    PEER,
                    &credentials,
                    WorkerAction::Manifest {
                        snapshot: &bad,
                        output: "o"
                    }
                ),
                Err(ExecutorError::InvalidRequest),
                "{bad}"
            );
        }
    }

    #[test]
    fn only_a_successful_unit_with_one_snapshot_line_is_complete() {
        let id = "c".repeat(64);
        let index = "a".repeat(64);
        assert_eq!(
            parse_write_result(
                Ok(()),
                format!("snapshot {id} 12 3456 {index}\n").as_bytes()
            ),
            Ok(WrittenSnapshot {
                id: id.clone(),
                files: 12,
                bytes: 3456,
                indexes: WrittenIndexes::parse(&index).unwrap(),
            })
        );
        assert_eq!(
            parse_write_result(Ok(()), format!("snapshot {id} 0 0 -").as_bytes()),
            Ok(WrittenSnapshot {
                id: id.clone(),
                files: 0,
                bytes: 0,
                indexes: WrittenIndexes::parse("-").unwrap(),
            })
        );
        let launched = |error, snapshot: Option<&str>| WriteFailure::Launched {
            error,
            snapshot: snapshot.map(str::to_owned),
        };
        // A partial write names its snapshot; the unit failed.
        assert_eq!(
            parse_write_result(
                Err(ExecutorError::StepFailed),
                format!("partial {id}\n").as_bytes()
            ),
            Err(launched(ExecutorError::StepFailed, Some(&id)))
        );
        // A complete line from a failed unit is not complete.
        assert_eq!(
            parse_write_result(
                Err(ExecutorError::Unavailable),
                format!("snapshot {id} 1 2 -\n").as_bytes()
            ),
            Err(launched(ExecutorError::Unavailable, Some(&id)))
        );
        assert_eq!(
            parse_write_result(
                Err(ExecutorError::StepFailed),
                format!("index-unverified {id}\n").as_bytes()
            ),
            Err(launched(ExecutorError::RetentionUnverified, Some(&id)))
        );
        for bad in [
            String::new(),
            format!("snapshot {id} 01 2 -\n"),
            format!("snapshot {id} 1 -2 -\n"),
            format!("snapshot {id} 1 2 3\n"),
            format!("snapshot {id} 1 2\n"),
            format!("snapshot {id} 1 2 {index},{index}\n"),
            format!("snapshot {id} 1\n"),
            format!("snapshot {id} 1 2\nsnapshot {id} 1 2\n"),
            format!("Snapshot {id} 1 2\n"),
        ] {
            assert!(
                matches!(
                    parse_write_result(Ok(()), bad.as_bytes()),
                    Err(WriteFailure::Launched {
                        error: ExecutorError::StepFailed,
                        ..
                    })
                ),
                "{bad:?}"
            );
        }
        assert_eq!(
            parse_write_result(
                Ok(()),
                format!("snapshot {} 1 2\n", "C".repeat(64)).as_bytes()
            ),
            Err(launched(ExecutorError::StepFailed, None))
        );
        assert_eq!(
            parse_write_result(Ok(()), b"none\n"),
            Err(launched(ExecutorError::StepFailed, None))
        );
    }

    /// The `--property` values and the argv after `--` of a probe action
    /// at `level`.
    fn probe_unit(
        action: WorkerAction<'_>,
        level: &str,
    ) -> Result<(Vec<String>, Vec<String>), ExecutorError> {
        let site = SiteId::try_from("blog9".to_owned()).unwrap();
        let digest = Sha256Digest::try_from("ab".repeat(32)).unwrap();
        let credentials = std::array::from_fn(|n| format!("LoadCredential=c{n}:/p/{n}"));
        let args = worker_arguments("u", &site, level, &digest, PEER, &credentials, action)?;
        let properties = args
            .windows(2)
            .filter(|pair| pair[0] == "--property")
            .map(|pair| pair[1].clone())
            .collect();
        let separator = args.iter().position(|arg| arg == "--").unwrap();
        Ok((properties, args[separator + 1..].to_vec()))
    }

    #[test]
    fn the_restore_actions_run_as_the_probe_at_the_probe_level_with_the_fetch_key() {
        // D-031 (W373): the probe's two store actions.
        let snapshot = "e".repeat(64);
        let size = WorkerAction::RestoreSize {
            snapshot: &snapshot,
            probe: "rp_0a9fbc",
            output: "/run/rustiron-admin/s.out",
        };
        let restore = WorkerAction::Restore {
            snapshot: &snapshot,
            probe: "rp_0a9fbc",
        };
        assert_eq!(size.identity(), StoreIdentity::Fetch);
        assert_eq!(restore.identity(), StoreIdentity::Fetch);
        let (properties, tail) = probe_unit(restore, crate::restore::LEVEL).unwrap();
        for expected in [
            "User=rp_0a9fbc".to_owned(),
            "Group=rp_0a9fbc".to_owned(),
            "SELinuxContext=system_u:system_r:rustiron_capture_t:s0:c950".to_owned(),
            format!("NetworkNamespacePath={}", layout::STORE_NETNS),
            "IPAddressDeny=any".to_owned(),
            "IPAddressAllow=198.51.100.23/32".to_owned(),
            "NoNewPrivileges=yes".to_owned(),
            "CapabilityBoundingSet=".to_owned(),
            "ProtectSystem=strict".to_owned(),
            format!("InaccessiblePaths=-{}", layout::JOB_CREDENTIALS_DIR),
            format!(
                "ReadWritePaths={}/rp_0a9fbc/tmp",
                layout::RESTORE_PROBES_ROOT
            ),
            "RuntimeMaxSec=100".to_owned(),
            "StandardOutput=null".to_owned(),
            "MemoryMax=512M".to_owned(),
            "MemoryHigh=384M".to_owned(),
        ] {
            assert!(properties.contains(&expected), "{expected}");
        }
        assert!(!properties.iter().any(|p| p.contains("rs_blog9")));
        assert_eq!(
            properties
                .iter()
                .filter(|p| p.starts_with("ReadWritePaths="))
                .count(),
            1
        );
        assert_eq!(
            tail[1..],
            ["restore", "blog9", &"ab".repeat(32), &snapshot, "rp_0a9fbc"]
        );
        let (properties, tail) = probe_unit(size, crate::restore::LEVEL).unwrap();
        assert!(!properties.iter().any(|p| p.starts_with("MemoryHigh=")));
        assert!(properties.contains(&"User=rp_0a9fbc".to_owned()));
        assert!(properties.contains(&"RuntimeMaxSec=30".to_owned()));
        assert!(
            properties.contains(&"StandardOutput=truncate:/run/rustiron-admin/s.out".to_owned())
        );
        assert!(!properties.iter().any(|p| p.starts_with("ReadWritePaths=")));
        assert_eq!(
            tail[1..],
            [
                "restore-size",
                "blog9",
                &"ab".repeat(32),
                &snapshot,
                "rp_0a9fbc"
            ]
        );
    }

    #[test]
    fn the_clone_actions_run_as_the_target_at_its_level_and_write_only_its_tmp() {
        // D-078 (W499): the source repository (blog9) with the source's
        // fetch key, as the target account `rs_stage9` at the target level.
        let snapshot = "e".repeat(64);
        let size = WorkerAction::CloneRestoreSize {
            snapshot: &snapshot,
            account: "rs_stage9",
            output: "/run/rustiron-admin/s.out",
        };
        let restore = WorkerAction::CloneRestore {
            snapshot: &snapshot,
            account: "rs_stage9",
        };
        assert_eq!(size.identity(), StoreIdentity::Fetch);
        assert_eq!(restore.identity(), StoreIdentity::Fetch);
        let (properties, tail) = probe_unit(restore, "s0:c207").unwrap();
        for expected in [
            "User=rs_stage9".to_owned(),
            "Group=rs_stage9".to_owned(),
            "SELinuxContext=system_u:system_r:rustiron_capture_t:s0:c207".to_owned(),
            format!("NetworkNamespacePath={}", layout::STORE_NETNS),
            "IPAddressAllow=198.51.100.23/32".to_owned(),
            "NoNewPrivileges=yes".to_owned(),
            "ProtectSystem=strict".to_owned(),
            format!("ReadWritePaths={}/rs_stage9/tmp", layout::SITES_ROOT),
            "StandardOutput=null".to_owned(),
            "MemoryMax=512M".to_owned(),
            "MemoryHigh=384M".to_owned(),
        ] {
            assert!(properties.contains(&expected), "{expected}");
        }
        assert!(!properties.iter().any(|p| p.contains("rs_blog9")));
        assert_eq!(
            properties
                .iter()
                .filter(|p| p.starts_with("ReadWritePaths="))
                .count(),
            1
        );
        assert_eq!(
            tail[1..],
            [
                "clone-restore",
                "blog9",
                &"ab".repeat(32),
                &snapshot,
                "rs_stage9"
            ]
        );
        let (properties, tail) = probe_unit(size, "s0:c207").unwrap();
        assert!(!properties.iter().any(|p| p.starts_with("ReadWritePaths=")));
        assert!(properties.contains(&"User=rs_stage9".to_owned()));
        assert_eq!(tail[1], "clone-restore-size");
        // Never the probe level, the source account, or a non-site name.
        let refused = Err(ExecutorError::InvalidRequest);
        let clone = |account| WorkerAction::CloneRestore {
            snapshot: &snapshot,
            account,
        };
        assert_eq!(
            probe_unit(clone("rs_stage9"), crate::restore::LEVEL),
            refused
        );
        for account in ["rs_blog9", "rp_0a9fbc", "rs_", "stage9", "rs_../x", ""] {
            assert_eq!(probe_unit(clone(account), "s0:c207"), refused, "{account}");
        }
    }

    /// W518-F5 (D-084): an update's rollback restores the site's own
    /// capture as the site into its own tmp; the clone rule is unchanged.
    #[test]
    fn the_update_restore_runs_as_the_site_into_its_own_tmp() {
        let snapshot = "e".repeat(64);
        let restore = WorkerAction::SiteRestore {
            snapshot: &snapshot,
        };
        assert_eq!(restore.identity(), StoreIdentity::Fetch);
        let (properties, tail) = probe_unit(restore, "s0:c207").unwrap();
        for expected in [
            "User=rs_blog9".to_owned(),
            "SELinuxContext=system_u:system_r:rustiron_capture_t:s0:c207".to_owned(),
            format!("ReadWritePaths={}/rs_blog9/tmp", layout::SITES_ROOT),
            "MemoryHigh=384M".to_owned(),
        ] {
            assert!(properties.contains(&expected), "{expected}");
        }
        assert_eq!(
            tail[1..],
            [
                "clone-restore",
                "blog9",
                &"ab".repeat(32),
                &snapshot,
                "rs_blog9"
            ]
        );
        let size = WorkerAction::SiteRestoreSize {
            snapshot: &snapshot,
            output: "/run/rustiron-admin/s.out",
        };
        let (properties, tail) = probe_unit(size, "s0:c207").unwrap();
        assert!(!properties.iter().any(|p| p.starts_with("ReadWritePaths=")));
        assert_eq!(tail[1], "clone-restore-size");
        let refused = Err(ExecutorError::InvalidRequest);
        assert_eq!(probe_unit(restore, crate::restore::LEVEL), refused);
        let bad = "x".repeat(64);
        assert_eq!(
            probe_unit(WorkerAction::SiteRestore { snapshot: &bad }, "s0:c207"),
            refused
        );
        // A clone still never targets its source site.
        let clone = WorkerAction::CloneRestore {
            snapshot: &snapshot,
            account: "rs_blog9",
        };
        assert_eq!(probe_unit(clone, "s0:c207"), refused);
    }

    #[test]
    fn a_restore_action_refuses_a_site_level_another_account_or_a_bad_snapshot() {
        let snapshot = "e".repeat(64);
        fn restore<'a>(probe: &'a str, snapshot: &'a str) -> WorkerAction<'a> {
            WorkerAction::Restore { snapshot, probe }
        }
        let level = crate::restore::LEVEL;
        let refused = Err(ExecutorError::InvalidRequest);
        assert_eq!(
            probe_unit(restore("rp_0a9fbc", &snapshot), "s0:c3"),
            refused
        );
        assert_eq!(
            probe_unit(restore("rp_0a9fbc", &snapshot), "s0:c950,c951"),
            refused
        );
        for probe in ["rs_blog9", "rp_0A9FBC", "rp_..%2fx", "root", ""] {
            assert_eq!(
                probe_unit(restore(probe, &snapshot), level),
                refused,
                "{probe}"
            );
        }
        for bad in ["e".repeat(63), "E".repeat(64), "latest".to_owned()] {
            assert_eq!(
                probe_unit(restore("rp_0a9fbc", &bad), level),
                refused,
                "{bad}"
            );
            let size = WorkerAction::RestoreSize {
                snapshot: &bad,
                probe: "rp_0a9fbc",
                output: "o",
            };
            assert_eq!(probe_unit(size, level), refused, "{bad}");
        }
    }

    #[test]
    fn only_one_canonical_size_line_is_a_restore_size() {
        assert_eq!(
            parse_restore_size(b"restore-size 110183745 4258\n"),
            Some((110_183_745, 4258))
        );
        assert_eq!(parse_restore_size(b"restore-size 0 0\n"), Some((0, 0)));
        for bad in [
            &b""[..],
            b"restore-size 1 2",
            b"restore-size 01 2\n",
            b"restore-size 1 -2\n",
            b"restore-size 1 2 3\n",
            b"restore-size 1\n",
            b"restore-size 1 2\nrestore-size 1 2\n",
            b"Restore-size 1 2\n",
            b"restore-size 18446744073709551616 1\n",
        ] {
            assert_eq!(parse_restore_size(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_lock_worker_takes_the_write_operation_and_indexes_together() {
        let base = [
            format!("{}/capture-manifest", layout::JOB_BIN_DIR),
            "lock".to_owned(),
            "blog9".to_owned(),
            "ab".repeat(32),
        ];
        let (tail, outputs) = worker_tail(WorkerAction::Lock {
            written: None,
            output: "o",
        });
        assert_eq!(tail, base);
        assert_eq!(outputs, ["StandardOutput=truncate:o"]);
        let operation = Id::try_from("op_w334".to_owned()).unwrap();
        let indexes = WrittenIndexes::parse(&"e".repeat(64)).unwrap();
        let (tail, outputs) = worker_tail(WorkerAction::Lock {
            written: Some((&operation, &indexes)),
            output: "o",
        });
        assert_eq!(tail[..4], base);
        assert_eq!(tail[4..], ["op_w334", indexes.as_str()]);
        assert_eq!(outputs, ["StandardOutput=truncate:o"]);
    }

    #[test]
    fn only_none_or_one_full_id_is_a_tag_result() {
        let id = "d".repeat(64);
        assert_eq!(parse_tag_result(b"none\n"), Ok(None));
        assert_eq!(
            parse_tag_result(format!("found {id}\n").as_bytes()),
            Ok(Some(id.clone()))
        );
        for bad in [
            "".to_owned(),
            "none\nnone\n".to_owned(),
            format!("found {}\n", &id[..63]),
            format!("found {}\n", "D".repeat(64)),
            format!("found {id} extra\n"),
            "None\n".to_owned(),
        ] {
            assert_eq!(
                parse_tag_result(bad.as_bytes()),
                Err(ExecutorError::Unavailable),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn the_namespace_reader_keeps_only_netlink_and_net_admin() {
        let args = namespace_read_arguments(
            "u",
            "/run/rustiron-admin/u.out",
            &[NFT, "-s", "list", "ruleset"],
        );
        assert!(args.contains(&format!("NetworkNamespacePath={}", layout::STORE_NETNS)));
        assert!(args.contains(&"CapabilityBoundingSet=CAP_NET_ADMIN".to_owned()));
        assert!(args.contains(&"RestrictAddressFamilies=AF_NETLINK".to_owned()));
        assert!(!args.contains(&"--pipe".to_owned()));
        assert!(args.contains(&"StandardOutput=truncate:/run/rustiron-admin/u.out".to_owned()));
        assert!(!args.iter().any(|arg| arg.starts_with("NoNewPrivileges")));
        let separator = args.iter().position(|arg| arg == "--").unwrap();
        assert_eq!(&args[separator + 1..], [NFT, "-s", "list", "ruleset"]);
    }
}
