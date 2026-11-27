//! Lab `backup_capture` (S07 W033): a site's database dump and restic
//! snapshot, each run as the site account in `rustiron_capture_t` at the
//! site's level. Only repository jobs receive credentials through
//! `LoadCredential=`; check/lookup use the read-only fetch identity. Root never reads site content: it starts
//! units, reads their stdout files and removes the one dump it named.

use std::path::Path;

use rustix::fs::{self, AtFlags};

use rustiron_journal::{CaptureConsistency, UnmatchedReason};

use crate::{
    ExecutorError, files,
    provision::{self, SiteLayout},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Phase {
    Dump,
    Marker,
    AppDump,
    AppMarker,
    Snapshot,
    Check,
    Find,
    Manifest,
    Lock,
}

impl Phase {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Dump => "dump",
            Self::Marker => "marker",
            Self::AppDump => "app-dump",
            Self::AppMarker => "app-marker",
            Self::Snapshot => "snapshot",
            Self::Check => "check",
            Self::Find => "find",
            Self::Manifest => "manifest",
            Self::Lock => "lock",
        }
    }

    fn repository(self) -> bool {
        !matches!(
            self,
            Self::Dump | Self::Marker | Self::AppDump | Self::AppMarker
        )
    }
}

/// Root-only per-site upload/read identities and repository password.
const CREDENTIALS_DIR: &str = crate::layout::JOB_CREDENTIALS_DIR;
/// Byte-identical copies of the RPM binaries, labeled as the domain entries.
const BIN: &str = crate::layout::JOB_BIN_DIR;
/// Where PID 1 writes each unit's stdout for the capture's runner to read:
/// the admin helper's runtime directory (W174), since captures run there.
pub(crate) const OUTPUT_DIR: &str = crate::layout::ADMIN_RUNTIME_DIR;
const DUMP: &str = crate::layout::CAPTURE_DUMP_FILE;

/// The enrolled destination (from policy) a capture writes to.
pub struct Destination<'a> {
    /// `s3:http://<store>/<bucket>/sites`; the site's account is appended.
    pub repository_base: &'a str,
    /// The single store address the snapshot units may reach.
    pub store_address: &'a str,
}

/// Whether the site has enrolled store credentials (checked before intent,
/// so a site without a destination identity is refused, not attempted).
pub fn credentials_enrolled(layout: &SiteLayout) -> bool {
    let directory = Path::new(CREDENTIALS_DIR).join(&layout.account);
    credentials_in(&directory, 0)
}

fn credentials_in(directory: &Path, owner_uid: u32) -> bool {
    files::open_trusted_directory(directory, owner_uid).is_ok_and(|fd| {
        ["aws", "fetch-aws", "repo.password"].iter().all(|name| {
            files::private_regular_stat(&fd, name, owner_uid)
                .is_ok_and(|stat| (0..=4096).contains(&stat.st_size))
        })
    })
}

/// A checked restic snapshot and the summary counts, when restic reported both.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedSnapshot {
    /// 64-character snapshot id.
    pub id: String,
    /// Files in the summary.
    pub files: Option<u64>,
    /// Bytes in the summary.
    pub bytes: Option<u64>,
    /// Canonical artifact manifest (W203), when the worker's listing was
    /// accepted. Its absence never changes the capture outcome.
    pub(crate) manifest: Option<crate::manifest::Built>,
    /// D-021 option E label: whether the dump and the file walk are proven
    /// to be a matched pair. Never changes the capture outcome (O1).
    pub consistency: CaptureConsistency,
    /// W391: the product lock reader's per-version retention evidence.
    /// Absent on a lab capture, or when a relayed record was malformed; its
    /// absence never changes the capture outcome.
    pub retention: Option<rustiron_journal::RetentionEvidence>,
}

impl CapturedSnapshot {
    /// Both counts, or nothing. A single count is not stored.
    pub fn extent(&self) -> Option<(u64, u64)> {
        match (self.files, self.bytes) {
            (Some(files), Some(bytes)) => Some((files, bytes)),
            _ => None,
        }
    }
}

/// How a capture ended, by whether the store may now hold its snapshot.
#[derive(Debug, Eq, PartialEq)]
pub enum CaptureOutcome {
    /// Snapshot verified by the repository check; the dump was removed.
    Succeeded(CapturedSnapshot),
    /// Failed before `restic backup` started and the dump was removed: the
    /// store holds nothing new, so this may be recorded as failed.
    NotStarted(ExecutorError),
    /// Failed at or after `restic backup` (restic exit 3 still writes a
    /// snapshot), or the dump was not removed. A snapshot may exist, so the
    /// capture stays `running` until reconciled by its operation tag.
    Uncertain {
        /// The step's error.
        error: ExecutorError,
        /// The snapshot id the summary reported, if one was seen.
        snapshot: Option<String>,
    },
}

/// Dump, snapshot (tagged with the operation id) and check, then removal of
/// the dump. Only a failure before the snapshot step is a known failure.
pub fn capture_site(
    layout: &SiteLayout,
    destination: &Destination<'_>,
    operation: &str,
    frozen: bool,
) -> CaptureOutcome {
    let level = match site_level(layout) {
        Ok(level) => level,
        Err(error) => return CaptureOutcome::NotStarted(error),
    };
    let Some(root) = layout.root.to_str() else {
        return CaptureOutcome::NotStarted(ExecutorError::StepFailed);
    };
    let mut freeze = match frozen.then(|| SystemdFreeze::new(&layout.account)) {
        None => None,
        Some(Ok(freeze)) => Some(freeze),
        Some(Err(error)) => return CaptureOutcome::NotStarted(error),
    };
    capture_steps_with(
        root,
        &layout.account,
        operation,
        |phase, command| run_unit(layout, &level, destination, phase, command),
        || remove_dump(layout),
        freeze.as_mut().map(|f| f as &mut dyn Freeze),
    )
}

/// D-021 option A (W258) unfreeze ceiling: the armed timer restarts the
/// site's PHP socket this long after arming, whatever the capture does.
pub(crate) const FREEZE_CAP_SECS: u64 = 10;

/// The site's PHP pool held stopped for the dump-to-walk window.
pub(crate) trait Freeze {
    /// Arms the unfreeze timer and verifies it is waiting. Nothing is
    /// stopped unless this succeeds.
    fn arm(&mut self) -> Result<(), ExecutorError>;
    /// Stops the pool's socket and service and verifies both are down.
    fn stop(&mut self) -> Result<(), ExecutorError>;
    /// Whether the pool is still down and the timer has not fired.
    fn held(&mut self) -> bool;
    /// Starts the socket, best effort: if this fails the timer still
    /// restarts it within the cap. The timer is left to fire: starting a
    /// listening socket is a no-op, and the lab policy does not let the
    /// helper stop a transient unit (W258 AVC); a frozen capture started
    /// before it fires reads `freeze_not_held`, never a false `matched`.
    fn thaw(&mut self);
}

/// The site's socket-activated PHP units, socket first.
pub(crate) fn pool_units(account: &str) -> [String; 2] {
    [
        format!("rustiron-site-php@{account}.socket"),
        format!("rustiron-site-php@{account}.service"),
    ]
}

/// `systemd-run` arguments for the unfreeze timer.
pub(crate) fn arm_command(account: &str, unit: &str) -> Vec<String> {
    vec![
        "--unit".to_owned(),
        unit.to_owned(),
        format!("--on-active={FREEZE_CAP_SECS}"),
        "--timer-property=AccuracySec=100ms".to_owned(),
        "--quiet".to_owned(),
        "--collect".to_owned(),
        "/usr/bin/systemctl".to_owned(),
        "start".to_owned(),
        pool_units(account)[0].clone(),
    ]
}

/// The real freeze, through PID 1.
pub(crate) struct SystemdFreeze {
    account: String,
    timer: String,
}

impl SystemdFreeze {
    pub(crate) fn new(account: &str) -> Result<Self, ExecutorError> {
        let valid = account.strip_prefix("rs_").is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        });
        if !valid {
            return Err(ExecutorError::InvalidRequest);
        }
        let mut random = [0_u8; 4];
        rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty())
            .map_err(|_| ExecutorError::Unavailable)?;
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(Self {
            account: account.to_owned(),
            timer: format!("rustiron-unfreeze-{account}-{suffix}"),
        })
    }

    fn active_state(unit: &str) -> Option<String> {
        provision::output(
            "/usr/bin/systemctl",
            &["show", "--property=ActiveState", "--value", "--", unit],
        )
        .ok()
        .map(|out| out.trim().to_owned())
    }

    fn pool_down(&self) -> bool {
        pool_units(&self.account).iter().all(|unit| {
            matches!(
                Self::active_state(unit).as_deref(),
                Some("inactive" | "failed")
            )
        })
    }

    fn timer_waiting(&self) -> bool {
        Self::active_state(&format!("{}.timer", self.timer)).as_deref() == Some("active")
    }
}

impl Freeze for SystemdFreeze {
    fn arm(&mut self) -> Result<(), ExecutorError> {
        let args = arm_command(&self.account, &self.timer);
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        provision::run("/usr/bin/systemd-run", &borrowed)
            .map_err(|_| failed("unfreeze timer not armed"))?;
        if self.timer_waiting() {
            Ok(())
        } else {
            Err(failed("unfreeze timer not waiting"))
        }
    }

    fn stop(&mut self) -> Result<(), ExecutorError> {
        let [socket, service] = pool_units(&self.account);
        provision::run("/usr/bin/systemctl", &["stop", "--", &socket, &service])
            .map_err(|_| failed("site pool not stopped"))?;
        if self.pool_down() {
            Ok(())
        } else {
            Err(failed("site pool still running"))
        }
    }

    fn held(&mut self) -> bool {
        self.pool_down() && self.timer_waiting()
    }

    fn thaw(&mut self) {
        let socket = &pool_units(&self.account)[0];
        let _ = provision::run("/usr/bin/systemctl", &["start", "--", socket]);
    }
}

/// The capture sequence over a unit runner, so its outcome classification
/// is tested without systemd.
#[cfg(test)]
fn capture_steps(
    root: &str,
    account: &str,
    operation: &str,
    run: impl FnMut(Phase, &[&str]) -> Result<String, ExecutorError>,
    remove: impl FnOnce() -> Result<(), ExecutorError>,
) -> CaptureOutcome {
    capture_steps_with(root, account, operation, run, remove, None)
}

/// As `capture_steps`, optionally frozen (W258, D-021 option A): the
/// unfreeze timer is armed and verified before the pool is stopped, and the
/// pool is started again right after the second marker; every path after
/// the stop thaws exactly once.
fn capture_steps_with(
    root: &str,
    account: &str,
    operation: &str,
    mut run: impl FnMut(Phase, &[&str]) -> Result<String, ExecutorError>,
    remove: impl FnOnce() -> Result<(), ExecutorError>,
    mut freeze: Option<&mut dyn Freeze>,
) -> CaptureOutcome {
    // W228: refuse before any effect unless the store's default lock holds.
    if let Err(error) = lock_verified(&mut run) {
        return CaptureOutcome::NotStarted(error);
    }
    if let Some(f) = freeze.as_deref_mut()
        && let Err(error) = f.arm().and_then(|()| f.stop())
    {
        f.thaw();
        return CaptureOutcome::NotStarted(error);
    }
    // W252: read before the dump, so an equal reading after the file walk
    // means no committed change in the whole dump-to-walk window.
    let before = read_marker(&mut run, root, account);
    let dump = dump_path(root);
    let command = dump_command(root, account);
    let borrowed: Vec<&str> = command.iter().map(String::as_str).collect();
    let dumped = run(Phase::Dump, &borrowed);
    let outcome = match dumped {
        Err(error) => CaptureOutcome::NotStarted(error),
        Ok(_) => snapshot_and_check(
            &mut run,
            root,
            account,
            operation,
            &dump,
            before,
            &mut freeze,
        ),
    };
    if let Some(f) = freeze.take() {
        f.thaw();
    }
    settle(remove(), outcome)
}

/// The outcome after the dump removal: a dump left behind makes any outcome
/// uncertain, so recovery removes it before it decides.
pub(crate) fn settle(
    removed: Result<(), ExecutorError>,
    outcome: CaptureOutcome,
) -> CaptureOutcome {
    match (removed, outcome) {
        (Ok(()), outcome) => outcome,
        (Err(_), outcome @ CaptureOutcome::Uncertain { .. }) => outcome,
        (Err(error), CaptureOutcome::Succeeded(snapshot)) => CaptureOutcome::Uncertain {
            error,
            snapshot: Some(snapshot.id),
        },
        (Err(error), CaptureOutcome::NotStarted(_)) => CaptureOutcome::Uncertain {
            error,
            snapshot: None,
        },
    }
}

/// W252 (D-021 option E): one checksum per base table of the site's own
/// database (`DATABASE()`, from the positional name), so any committed row
/// change shows. Fixed text: the unit launcher refuses any other query.
const MARKER_SQL: &str = "SET SESSION group_concat_max_len=1048576; SET @rustiron_q=(SELECT IFNULL(CONCAT('CHECKSUM TABLE ',GROUP_CONCAT(CONCAT('`',REPLACE(table_name,'`','``'),'`') ORDER BY table_name SEPARATOR ',')),'SELECT 0') FROM information_schema.tables WHERE table_schema=DATABASE() AND table_type='BASE TABLE'); PREPARE rustiron_m FROM @rustiron_q; EXECUTE rustiron_m; DEALLOCATE PREPARE rustiron_m;";

/// The fixed single-transaction dump of the site's own database into
/// [`dump_path`], as the site's database account (its `db.cnf`).
pub(crate) fn dump_command(root: &str, account: &str) -> Vec<String> {
    vec![
        format!("{BIN}/mariadb-dump"),
        format!("--defaults-file={root}/private/db.cnf"),
        "--single-transaction".to_owned(),
        "--skip-dump-date".to_owned(),
        format!("--result-file={}", dump_path(root)),
        account.to_owned(),
    ]
}

/// The marker query as the site's database account (its `db.cnf`).
pub(crate) fn marker_command(root: &str, account: &str) -> Vec<String> {
    vec![
        format!("{BIN}/mariadb"),
        format!("--defaults-file={root}/private/db.cnf"),
        "--batch".to_owned(),
        "--skip-column-names".to_owned(),
        "--execute".to_owned(),
        MARKER_SQL.to_owned(),
        account.to_owned(),
    ]
}

/// One marker reading: `table<TAB>checksum` lines (or `0` for a database with
/// no tables). Anything else, or a failed unit, is no marker.
pub(crate) fn read_marker(
    run: &mut impl FnMut(Phase, &[&str]) -> Result<String, ExecutorError>,
    root: &str,
    account: &str,
) -> Option<String> {
    let command = marker_command(root, account);
    let borrowed: Vec<&str> = command.iter().map(String::as_str).collect();
    let out = run(Phase::Marker, &borrowed).ok()?;
    let well_formed = out == "0\n"
        || (!out.is_empty()
            && out.ends_with('\n')
            && out.lines().all(|line| {
                line.split_once('\t').is_some_and(|(table, sum)| {
                    !table.is_empty() && !sum.is_empty() && sum.bytes().all(|b| b.is_ascii_digit())
                })
            }));
    well_formed.then_some(out)
}

pub(crate) fn compare(before: Option<&str>, after: Option<&str>) -> CaptureConsistency {
    match (before, after) {
        (Some(before), Some(after)) if before == after => CaptureConsistency::Matched,
        (Some(_), Some(_)) => CaptureConsistency::Unmatched(UnmatchedReason::DatabaseChanged),
        _ => CaptureConsistency::Unmatched(UnmatchedReason::MarkerUnavailable),
    }
}

/// The dump file a capture of the site at `root` writes and snapshots.
pub(crate) fn dump_path(root: &str) -> String {
    format!("{root}/tmp/{DUMP}")
}

fn snapshot_and_check(
    run: &mut impl FnMut(Phase, &[&str]) -> Result<String, ExecutorError>,
    root: &str,
    account: &str,
    operation: &str,
    dump: &str,
    before: Option<String>,
    freeze: &mut Option<&mut dyn Freeze>,
) -> CaptureOutcome {
    let tag = format!("--tag=rustiron-op-{operation}");
    let html = format!("{root}/html");
    let summary = match run(
        Phase::Snapshot,
        &[
            &format!("{BIN}/restic"),
            "backup",
            "--no-cache",
            "--json",
            "--tag=rustiron-lab",
            &tag,
            "--host=rustiron-alma10",
            &html,
            dump,
        ],
    ) {
        Ok(summary) => summary,
        Err(error) => {
            return CaptureOutcome::Uncertain {
                error,
                snapshot: None,
            };
        }
    };
    let Some(summary) = summary
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|value| value["message_type"] == "summary")
    else {
        return CaptureOutcome::Uncertain {
            error: failed("snapshot summary missing"),
            snapshot: None,
        };
    };
    let Some(id) = summary["snapshot_id"]
        .as_str()
        .filter(|id| id.len() == 64)
        .map(str::to_owned)
    else {
        return CaptureOutcome::Uncertain {
            error: failed("snapshot summary missing"),
            snapshot: None,
        };
    };
    let mut snapshot = CapturedSnapshot {
        id,
        files: summary["total_files_processed"].as_u64(),
        bytes: summary["total_bytes_processed"].as_u64(),
        manifest: None,
        consistency: CaptureConsistency::Unmatched(UnmatchedReason::MarkerUnavailable),
        retention: None,
    };
    // W254: read as soon as the file walk ends; the repository check that
    // follows touches neither the database nor the site files, so waiting
    // for it only widened the window (3.2 s -> about 1.2 s on blog13).
    let after = read_marker(run, root, account);
    // W258: judge the freeze, then give the site its PHP back at once.
    let held = freeze.take().map(|f| {
        let held = f.held();
        f.thaw();
        held
    });
    snapshot.consistency = if held == Some(false) {
        CaptureConsistency::Unmatched(UnmatchedReason::FreezeNotHeld)
    } else {
        compare(before.as_deref(), after.as_deref())
    };
    match run(
        Phase::Check,
        &[&format!("{BIN}/restic"), "check", "--no-lock", "--no-cache"],
    ) {
        Ok(_) => {
            // W228: the lock must still hold after the snapshot is written;
            // otherwise its versions may lack retention.
            if let Err(error) = lock_verified(run) {
                return CaptureOutcome::Uncertain {
                    error,
                    snapshot: Some(snapshot.id),
                };
            }
            // W203: a failed, malformed, oversized or refused listing only
            // leaves the manifest unrecorded; the capture has succeeded.
            snapshot.manifest = run(
                Phase::Manifest,
                &[
                    &format!("{BIN}/{}", crate::manifest::WORKER),
                    "dump",
                    &snapshot.id,
                ],
            )
            .ok()
            .and_then(|out| crate::manifest::from_worker(out.as_bytes(), root, dump));
            CaptureOutcome::Succeeded(snapshot)
        }
        Err(error) => CaptureOutcome::Uncertain {
            error,
            snapshot: Some(snapshot.id),
        },
    }
}

/// The store's default retention is COMPLIANCE for at least 30 days (W228).
fn lock_verified(
    run: &mut impl FnMut(Phase, &[&str]) -> Result<String, ExecutorError>,
) -> Result<(), ExecutorError> {
    let worker = format!("{BIN}/{}", crate::manifest::WORKER);
    match run(Phase::Lock, &[&worker, "lock"]) {
        Ok(out) if crate::manifest::lock::verified(&out) => Ok(()),
        _ => Err(ExecutorError::RetentionUnverified),
    }
}

/// Recovery after a crash or an uncertain capture: the snapshot tagged with
/// this operation, if the repository holds exactly one and its check passes.
/// `Ok(None)` (no tagged snapshot) is returned only once no capture unit of
/// the site is still running and the dump is removed; anything else is an
/// error and the capture stays unresolved.
pub fn find_snapshot(
    layout: &SiteLayout,
    destination: &Destination<'_>,
    operation: &str,
) -> Result<Option<String>, ExecutorError> {
    let level = site_level(layout)?;
    let pattern = format!("rustiron-capture-{}-*", layout.account);
    let active = provision::output(
        "/usr/bin/systemctl",
        &["list-units", "--plain", "--no-legend", "--", &pattern],
    )?;
    find_steps(
        operation,
        !active.trim().is_empty(),
        |phase, command| run_unit(layout, &level, destination, phase, command),
        || remove_dump(layout),
    )
}

/// The recovery sequence over a unit runner (tested without systemd).
fn find_steps(
    operation: &str,
    unit_active: bool,
    mut run: impl FnMut(Phase, &[&str]) -> Result<String, ExecutorError>,
    remove: impl FnOnce() -> Result<(), ExecutorError>,
) -> Result<Option<String>, ExecutorError> {
    if unit_active {
        // A crashed executor does not stop its transient units: a restic
        // backup still running may write the snapshot after this lookup.
        return Err(ExecutorError::Busy);
    }
    remove()?;
    let tag = format!("--tag=rustiron-op-{operation}");
    let listing = run(
        Phase::Find,
        &[
            &format!("{BIN}/restic"),
            "snapshots",
            "--no-lock",
            "--no-cache",
            "--json",
            &tag,
        ],
    )?;
    let ids: Vec<String> = serde_json::from_str::<serde_json::Value>(listing.trim())
        .ok()
        .and_then(|value| {
            value.as_array().map(|items| {
                items
                    .iter()
                    .filter_map(|item| item["id"].as_str().map(str::to_owned))
                    .collect()
            })
        })
        .ok_or_else(|| failed("snapshot listing unreadable"))?;
    match ids.as_slice() {
        [] => Ok(None),
        [one] if one.len() == 64 => {
            run(
                Phase::Check,
                &[&format!("{BIN}/restic"), "check", "--no-lock", "--no-cache"],
            )?;
            Ok(Some(one.clone()))
        }
        _ => Err(failed("more than one snapshot carries the operation tag")),
    }
}

pub(crate) fn site_level(layout: &SiteLayout) -> Result<String, ExecutorError> {
    let root = layout.root.to_str().ok_or(ExecutorError::StepFailed)?;
    provision::output("/usr/bin/stat", &["-c", "%C", "--", root])?
        .trim()
        .strip_prefix("system_u:object_r:httpd_sys_content_t:")
        .map(str::to_owned)
        .ok_or_else(|| failed("site has no category"))
}

/// One transient unit as the site; returns its stdout (bounded).
fn run_unit(
    layout: &SiteLayout,
    level: &str,
    destination: &Destination<'_>,
    phase: Phase,
    command: &[&str],
) -> Result<String, ExecutorError> {
    run_unit_for(layout, level, Some(destination), phase, command)
}

/// W356: a dump or marker unit of a product capture. It has no store
/// destination, so a repository phase is refused before any launch; the
/// unit keeps the lab's private network and hidden credential directories.
pub(crate) fn run_local_unit(
    layout: &SiteLayout,
    level: &str,
    phase: Phase,
    command: &[&str],
) -> Result<String, ExecutorError> {
    run_unit_for(layout, level, None, phase, command)
}

fn run_unit_for(
    layout: &SiteLayout,
    level: &str,
    destination: Option<&Destination<'_>>,
    phase: Phase,
    command: &[&str],
) -> Result<String, ExecutorError> {
    let account = layout.account.as_str();
    let mut random = [0_u8; 8];
    rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty())
        .map_err(|_| ExecutorError::Unavailable)?;
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let unit = format!("rustiron-capture-{account}-{}-{suffix}", phase.name());
    let args = launch_arguments_for(layout, level, destination, phase, &unit, command)?;
    ensure_output_dir()?;
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let ran = provision::run("/usr/bin/systemd-run", &borrowed);
    let directory = files::open_traversable_directory(Path::new(OUTPUT_DIR), 0)?;
    let name = format!("{unit}.out");
    let bytes = files::read_child(
        &directory,
        &name,
        0,
        files::Exposure::Readable,
        4 * 1024 * 1024,
    );
    let _ = fs::unlinkat(&directory, name.as_str(), AtFlags::empty());
    ran.map_err(|_| failed("capture unit failed"))?;
    String::from_utf8(bytes.unwrap_or_default()).map_err(|_| failed("capture output not text"))
}

#[cfg(test)]
fn launch_arguments(
    layout: &SiteLayout,
    level: &str,
    destination: &Destination<'_>,
    phase: Phase,
    unit: &str,
    command: &[&str],
) -> Result<Vec<String>, ExecutorError> {
    launch_arguments_for(layout, level, Some(destination), phase, unit, command)
}

/// As `launch_arguments` (test builds); without a destination only the dump and marker
/// phases launch (W356 product dump units).
fn launch_arguments_for(
    layout: &SiteLayout,
    level: &str,
    destination: Option<&Destination<'_>>,
    phase: Phase,
    unit: &str,
    command: &[&str],
) -> Result<Vec<String>, ExecutorError> {
    let destination = match (phase.repository(), destination) {
        (true, None) => return Err(ExecutorError::InvalidRequest),
        (_, destination) => destination,
    };
    let expected_program = format!(
        "{BIN}/{}",
        match phase {
            Phase::Dump => "mariadb-dump",
            Phase::Marker => "mariadb",
            Phase::AppDump | Phase::AppMarker | Phase::Manifest | Phase::Lock => {
                crate::manifest::WORKER
            }
            _ => "restic",
        }
    );
    let expected_action = match phase {
        Phase::Dump | Phase::Marker => format!(
            "--defaults-file={}/private/db.cnf",
            layout.root.to_str().ok_or(ExecutorError::StepFailed)?
        ),
        Phase::AppDump => "app-sqlite-backup".to_owned(),
        Phase::AppMarker => "app-sqlite-marker".to_owned(),
        Phase::Snapshot => "backup".to_owned(),
        Phase::Check => "check".to_owned(),
        Phase::Find => "snapshots".to_owned(),
        Phase::Manifest => "dump".to_owned(),
        Phase::Lock => "lock".to_owned(),
    };
    if command.first().copied() != Some(expected_program.as_str())
        || command.get(1).copied() != Some(expected_action.as_str())
    {
        return Err(ExecutorError::InvalidRequest);
    }
    // W603: app SQLite backup/marker take exactly the site's own derived account.
    if matches!(phase, Phase::AppDump | Phase::AppMarker)
        && (command.len() != 3 || command[2] != layout.account.as_str())
    {
        return Err(ExecutorError::InvalidRequest);
    }
    // The worker takes exactly one snapshot id; the repository and identity
    // come only from this unit's properties.
    if phase == Phase::Manifest
        && !(command.len() == 3
            && command[2].len() == 64
            && command[2]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    {
        return Err(ExecutorError::InvalidRequest);
    }
    if phase == Phase::Lock && command.len() != 2 {
        return Err(ExecutorError::InvalidRequest);
    }
    // W252: only the fixed marker query, for this site's own database.
    if phase == Phase::Marker
        && command
            != marker_command(
                layout.root.to_str().ok_or(ExecutorError::StepFailed)?,
                &layout.account,
            )
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice()
    {
        return Err(ExecutorError::InvalidRequest);
    }
    let account = layout.account.as_str();
    let root = layout.root.to_str().ok_or(ExecutorError::StepFailed)?;
    let output = format!("{OUTPUT_DIR}/{unit}.out");
    let credentials = format!("/run/credentials/{unit}.service");
    let mut properties = vec![
        format!("User={account}"),
        format!("Group={account}"),
        format!("SELinuxContext=system_u:system_r:rustiron_capture_t:{level}"),
        "NoNewPrivileges=yes".to_owned(),
        "CapabilityBoundingSet=".to_owned(),
        "ProtectSystem=strict".to_owned(),
        "ProtectHome=yes".to_owned(),
        "PrivateTmp=yes".to_owned(),
        "PrivateDevices=yes".to_owned(),
        "ProtectProc=invisible".to_owned(),
        format!("ReadWritePaths={root}/tmp"),
        format!("RuntimeMaxSec={UNIT_RUNTIME_SECS}"),
        format!("TimeoutStopSec={UNIT_STOP_SECS}"),
        "MemoryMax=512M".to_owned(),
        "MemorySwapMax=0".to_owned(),
        "TasksMax=32".to_owned(),
        crate::provision::JOB_CPU_WEIGHT.to_owned(),
        format!("StandardOutput=truncate:{output}"),
    ];
    if let Some(destination) = destination.filter(|_| phase.repository()) {
        // The lock read needs the capture identity's
        // GetBucketObjectLockConfiguration; the fetch identity lacks it.
        let key = if matches!(phase, Phase::Snapshot | Phase::Lock) {
            "aws"
        } else {
            "fetch-aws"
        };
        properties.extend([
            format!("LoadCredential=aws:{CREDENTIALS_DIR}/{account}/{key}"),
            format!("LoadCredential=password:{CREDENTIALS_DIR}/{account}/repo.password"),
            format!("Environment=TMPDIR={root}/tmp AWS_SHARED_CREDENTIALS_FILE={credentials}/aws RESTIC_PASSWORD_FILE={credentials}/password RESTIC_REPOSITORY={}/{account}", destination.repository_base),
            "UnsetEnvironment=AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE AWS_CONFIG_FILE RESTIC_PASSWORD RESTIC_PASSWORD_COMMAND RESTIC_REPOSITORY_FILE".to_owned(),
            "IPAddressDeny=any".to_owned(),
            format!("IPAddressAllow={}/32", destination.store_address),
        ]);
    } else {
        properties.extend([
            format!("Environment=TMPDIR={root}/tmp"),
            format!("InaccessiblePaths=-{CREDENTIALS_DIR} -/run/credentials"),
            "UnsetEnvironment=AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE AWS_SHARED_CREDENTIALS_FILE AWS_CONFIG_FILE RESTIC_PASSWORD RESTIC_PASSWORD_FILE RESTIC_PASSWORD_COMMAND RESTIC_REPOSITORY RESTIC_REPOSITORY_FILE CREDENTIALS_DIRECTORY".to_owned(),
            "PrivateNetwork=yes".to_owned(),
            "IPAddressDeny=any".to_owned(),
        ]);
    }
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
    Ok(args)
}

/// Capture unit runtime ceiling. The helper cannot stop units, so a unit
/// still running at its 120 s command deadline leaves the capture uncertain
/// with the unit alive (W207, same class as the probe fix in W181).
const UNIT_RUNTIME_SECS: u64 = 100;
/// Bound on the stop after the ceiling: restic held SIGTERM for 21 s while
/// retrying (W207 p1), so systemd sends SIGKILL after this.
const UNIT_STOP_SECS: u64 = 5;
const _: () =
    assert!(UNIT_RUNTIME_SECS + UNIT_STOP_SECS + 10 <= crate::provision::COMMAND_TIMEOUT.as_secs());

/// The helper's runtime directory is absent while it is stopped (admin
/// recovery or the in-process lab mode); recreate it root-only so PID 1 can
/// write unit stdout there, and give it its policy label. Unlabelled, it
/// stays `var_run_t` and the helper can no longer bind its socket in it on
/// the next start (W175). Only a directory created here is relabelled: the
/// helper's own runs find it present, and running `restorecon` there on
/// every launch was refused a policy-config read (W176).
pub(crate) fn ensure_output_dir() -> Result<(), ExecutorError> {
    let name = OUTPUT_DIR.trim_start_matches("/run/");
    ensure_output_dir_in(Path::new("/run"), 0, name, |path| {
        provision::run("/usr/sbin/restorecon", &["--", path])
    })
}

fn ensure_output_dir_in(
    parent: &Path,
    owner: u32,
    name: &str,
    relabel: impl FnOnce(&str) -> Result<(), ExecutorError>,
) -> Result<(), ExecutorError> {
    let run = files::open_traversable_directory(parent, owner)?;
    match fs::mkdirat(&run, name, rustix::fs::Mode::from_raw_mode(0o700)) {
        Ok(()) => {
            let path = parent.join(name);
            relabel(path.to_str().ok_or(ExecutorError::StepFailed)?)
        }
        Err(rustix::io::Errno::EXIST) => Ok(()),
        Err(_) => Err(failed("output directory unavailable")),
    }
}

/// Removes the named dump from the site's tmp (descriptor-relative, no
/// following links); absent is fine.
pub(crate) fn remove_dump(layout: &SiteLayout) -> Result<(), ExecutorError> {
    let uid = provision::account_uid(&provision::read_etc("passwd")?, &layout.account)
        .ok_or(ExecutorError::StepFailed)?;
    let tmp = files::open_traversable_directory(&layout.root.join("tmp"), uid)?;
    match fs::unlinkat(&tmp, DUMP, AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(_) => Err(failed("capture dump not removed")),
    }
}

fn failed(what: &'static str) -> ExecutorError {
    eprintln!("{{\"scope\":\"backup_capture\",\"step_failure\":\"{what}\"}}");
    ExecutorError::StepFailed
}

#[cfg(test)]
mod tests {
    #[test]
    fn output_dir_is_relabelled_only_when_created() {
        let parent = std::env::temp_dir().join(format!("ri-out-{}", std::process::id()));
        std::fs::create_dir_all(&parent).unwrap();
        let owner = rustix::process::getuid().as_raw();
        for expected in [
            vec![parent.join("out").to_str().unwrap().to_owned()],
            vec![],
        ] {
            let mut seen = Vec::new();
            super::ensure_output_dir_in(&parent, owner, "out", |path| {
                seen.push(path.to_owned());
                Ok(())
            })
            .unwrap();
            assert_eq!(seen, expected);
        }
        std::fs::remove_dir_all(&parent).unwrap();
    }

    use super::{CaptureOutcome, capture_steps, find_steps};
    use crate::ExecutorError;
    use rustiron_journal::{CaptureConsistency, UnmatchedReason};

    const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const MARKER: &str = "rs_blog.wp_posts\t1234\nrs_blog.wp_options\t99\n";

    fn summary() -> String {
        format!(
            "{{\"message_type\":\"status\"}}\n{{\"message_type\":\"summary\",\"snapshot_id\":\"{ID}\",\"total_files_processed\":3,\"total_bytes_processed\":9}}\n"
        )
    }

    fn lock_pass() -> Result<String, ExecutorError> {
        Ok(format!("{}\n", crate::manifest::lock::pass_line(30)))
    }

    /// Runs the capture with `answer(step)` for each unit, recording steps;
    /// the retention-lock checks pass.
    fn capture_with(
        answer: impl Fn(&str) -> Result<String, ExecutorError>,
        removed: Result<(), ExecutorError>,
    ) -> (CaptureOutcome, Vec<String>) {
        capture_locked(|_| lock_pass(), answer, removed)
    }

    /// As `capture_with`, with `lock(n)` answering the n-th lock check.
    fn capture_locked(
        lock: impl Fn(usize) -> Result<String, ExecutorError>,
        answer: impl Fn(&str) -> Result<String, ExecutorError>,
        removed: Result<(), ExecutorError>,
    ) -> (CaptureOutcome, Vec<String>) {
        let mut steps = Vec::new();
        let mut locks = 0;
        let outcome = capture_steps(
            "/srv/sites/blog",
            "rs_blog",
            "op_test",
            |phase, _| {
                let step = phase.name();
                steps.push(step.to_owned());
                if step == "lock" {
                    locks += 1;
                    return lock(locks);
                }
                answer(step)
            },
            || removed,
        );
        (outcome, steps)
    }

    #[test]
    fn a_lock_not_verified_before_the_capture_refuses_without_a_dump() {
        for answer in [
            Err(ExecutorError::StepFailed),
            Ok(String::new()),
            Ok("{\"lock\":\"GOVERNANCE\",\"days\":30}\n".to_owned()),
            Ok(format!("{}\n", crate::manifest::lock::pass_line(7))),
        ] {
            let (outcome, steps) =
                capture_locked(|_| answer.clone(), |_| Ok(String::new()), Ok(()));
            assert_eq!(
                outcome,
                CaptureOutcome::NotStarted(ExecutorError::RetentionUnverified)
            );
            assert_eq!(steps, ["lock"]);
        }
    }

    #[test]
    fn a_lock_lost_during_the_capture_leaves_it_uncertain_with_the_id() {
        let (outcome, steps) = capture_locked(
            |n| {
                if n == 1 {
                    lock_pass()
                } else {
                    Ok(String::new())
                }
            },
            |step| {
                Ok(if step == "snapshot" {
                    summary()
                } else {
                    String::new()
                })
            },
            Ok(()),
        );
        assert_eq!(
            outcome,
            CaptureOutcome::Uncertain {
                error: ExecutorError::RetentionUnverified,
                snapshot: Some(ID.to_owned())
            }
        );
        assert_eq!(
            steps,
            [
                "lock", "marker", "dump", "snapshot", "marker", "check", "lock"
            ]
        );
    }

    #[test]
    fn a_verified_snapshot_succeeds() {
        let (outcome, steps) = capture_with(
            |step| {
                Ok(match step {
                    "snapshot" => summary(),
                    "marker" => MARKER.to_owned(),
                    _ => String::new(),
                })
            },
            Ok(()),
        );
        assert_eq!(
            outcome,
            CaptureOutcome::Succeeded(super::CapturedSnapshot {
                id: ID.to_owned(),
                files: Some(3),
                bytes: Some(9),
                manifest: None,
                consistency: CaptureConsistency::Matched,
                retention: None,
            })
        );
        assert_eq!(
            steps,
            [
                "lock", "marker", "dump", "snapshot", "marker", "check", "lock", "manifest"
            ]
        );
    }

    /// Worker output for one file under the site's html.
    fn worker_lines(path: &str) -> String {
        let digest = crate::manifest::format::digest_hex(b"x");
        format!(
            "{{\"path\":\"{path}\",\"kind\":\"file\",\"size\":1,\"sha256\":\"{digest}\",\"mode\":420}}\n{{\"end\":{{\"entries\":1,\"regular_bytes\":1,\"truncated\":false}}}}\n"
        )
    }

    fn with_manifest(answer: String) -> CaptureOutcome {
        capture_with(
            move |step| match step {
                "snapshot" => Ok(summary()),
                "manifest" => Ok(answer.clone()),
                _ => Ok(String::new()),
            },
            Ok(()),
        )
        .0
    }

    #[test]
    fn a_good_manifest_is_carried_with_the_snapshot() {
        let CaptureOutcome::Succeeded(snapshot) =
            with_manifest(worker_lines("srv/sites/blog/html/index.php"))
        else {
            panic!("capture must succeed");
        };
        let built = snapshot.manifest.expect("manifest");
        assert_eq!(built.entries, 1);
        assert_eq!(built.regular_bytes, 1);
        assert!(!built.truncated);
        assert_eq!(
            built.sha256,
            crate::manifest::format::digest_hex(&built.bytes)
        );
    }

    #[test]
    fn a_failed_malformed_or_refused_manifest_leaves_the_capture_succeeded() {
        let (failed, steps) = capture_with(
            |step| match step {
                "snapshot" => Ok(summary()),
                "manifest" => Err(ExecutorError::StepFailed),
                _ => Ok(String::new()),
            },
            Ok(()),
        );
        assert_eq!(
            steps,
            [
                "lock", "marker", "dump", "snapshot", "marker", "check", "lock", "manifest"
            ]
        );
        for outcome in [
            failed,
            with_manifest("not json\n".to_owned()),
            with_manifest(
                worker_lines("srv/sites/blog/html/index.php")
                    .replace("\"entries\":1", "\"entries\":2"),
            ),
            with_manifest(worker_lines("srv/sites/other/html/index.php")),
            with_manifest(worker_lines("srv/sites/blog/html/password=x.php")),
            with_manifest(format!(
                "{}{}",
                " ".repeat(5 << 20),
                worker_lines("srv/sites/blog/html/a")
            )),
        ] {
            let CaptureOutcome::Succeeded(snapshot) = outcome else {
                panic!("a manifest problem must not change the capture outcome");
            };
            assert_eq!(snapshot.id, ID);
            assert_eq!(snapshot.manifest, None);
        }
    }

    #[test]
    fn no_manifest_runs_when_the_check_fails() {
        let (_, steps) = capture_with(
            |step| match step {
                "snapshot" => Ok(summary()),
                "check" => Err(ExecutorError::StepFailed),
                _ => Ok(String::new()),
            },
            Ok(()),
        );
        assert_eq!(
            steps,
            ["lock", "marker", "dump", "snapshot", "marker", "check"]
        );
    }

    #[test]
    fn a_failure_before_the_snapshot_step_is_a_known_failure() {
        let (outcome, steps) = capture_with(|_| Err(ExecutorError::StepFailed), Ok(()));
        assert_eq!(
            outcome,
            CaptureOutcome::NotStarted(ExecutorError::StepFailed)
        );
        assert_eq!(steps, ["lock", "marker", "dump"]);
    }

    #[test]
    fn a_failed_backup_unit_is_uncertain() {
        // restic exit 3 (some files unreadable) still writes a snapshot.
        let (outcome, steps) = capture_with(
            |step| {
                if step == "snapshot" {
                    Err(ExecutorError::StepFailed)
                } else {
                    Ok(String::new())
                }
            },
            Ok(()),
        );
        assert_eq!(
            outcome,
            CaptureOutcome::Uncertain {
                error: ExecutorError::StepFailed,
                snapshot: None
            }
        );
        assert_eq!(steps, ["lock", "marker", "dump", "snapshot"]);
    }

    #[test]
    fn a_missing_summary_is_uncertain() {
        let (outcome, _) = capture_with(
            |step| {
                Ok(if step == "snapshot" {
                    "{\"message_type\":\"status\"}\n".to_owned()
                } else {
                    String::new()
                })
            },
            Ok(()),
        );
        assert_eq!(
            outcome,
            CaptureOutcome::Uncertain {
                error: ExecutorError::StepFailed,
                snapshot: None
            }
        );
    }

    #[test]
    fn a_failed_check_after_the_snapshot_is_uncertain_and_keeps_the_id() {
        let (outcome, _) = capture_with(
            |step| match step {
                "snapshot" => Ok(summary()),
                "check" => Err(ExecutorError::StepFailed),
                _ => Ok(String::new()),
            },
            Ok(()),
        );
        assert_eq!(
            outcome,
            CaptureOutcome::Uncertain {
                error: ExecutorError::StepFailed,
                snapshot: Some(ID.to_owned())
            }
        );
    }

    #[test]
    fn a_dump_left_behind_is_uncertain_even_after_success_or_early_failure() {
        let (after_success, _) = capture_with(
            |step| {
                Ok(if step == "snapshot" {
                    summary()
                } else {
                    String::new()
                })
            },
            Err(ExecutorError::StepFailed),
        );
        assert_eq!(
            after_success,
            CaptureOutcome::Uncertain {
                error: ExecutorError::StepFailed,
                snapshot: Some(ID.to_owned())
            }
        );
        let (after_dump_failure, _) = capture_with(
            |_| Err(ExecutorError::Unavailable),
            Err(ExecutorError::StepFailed),
        );
        assert!(matches!(
            after_dump_failure,
            CaptureOutcome::Uncertain { snapshot: None, .. }
        ));
    }

    fn find_with(
        active: bool,
        listing: &str,
        check: Result<String, ExecutorError>,
    ) -> (Result<Option<String>, ExecutorError>, Vec<String>) {
        let mut steps = Vec::new();
        let found = find_steps(
            "op_test",
            active,
            |phase, _| {
                let step = phase.name();
                steps.push(step.to_owned());
                if step == "check" {
                    check.clone()
                } else {
                    Ok(listing.to_owned())
                }
            },
            || Ok(()),
        );
        (found, steps)
    }

    #[test]
    fn reconcile_finds_the_tagged_snapshot() {
        let (found, steps) = find_with(false, &format!("[{{\"id\":\"{ID}\"}}]"), Ok(String::new()));
        assert_eq!(found, Ok(Some(ID.to_owned())));
        assert_eq!(steps, ["find", "check"]);
    }

    #[test]
    fn reconcile_never_reports_none_while_a_tagged_snapshot_fails_its_check() {
        let (found, _) = find_with(
            false,
            &format!("[{{\"id\":\"{ID}\"}}]"),
            Err(ExecutorError::StepFailed),
        );
        assert_eq!(found, Err(ExecutorError::StepFailed));
    }

    #[test]
    fn reconcile_waits_while_a_capture_unit_still_runs() {
        let (found, steps) = find_with(true, "[]", Ok(String::new()));
        assert_eq!(found, Err(ExecutorError::Busy));
        assert!(steps.is_empty());
    }

    #[test]
    fn reconcile_reports_none_only_for_an_empty_listing() {
        assert_eq!(find_with(false, "[]", Ok(String::new())).0, Ok(None));
        assert_eq!(
            find_with(false, "not json", Ok(String::new())).0,
            Err(ExecutorError::StepFailed)
        );
        let two = format!("[{{\"id\":\"{ID}\"}},{{\"id\":\"{ID}\"}}]");
        assert_eq!(
            find_with(false, &two, Ok(String::new())).0,
            Err(ExecutorError::StepFailed)
        );
    }

    /// W252 (D-021 option E): the label from the `n`-th marker answer.
    fn labelled(marker: impl Fn(usize) -> Result<String, ExecutorError>) -> CaptureOutcome {
        let markers = std::cell::Cell::new(0);
        capture_with(
            |step| match step {
                "snapshot" => Ok(summary()),
                "marker" => {
                    markers.set(markers.get() + 1);
                    marker(markers.get())
                }
                _ => Ok(String::new()),
            },
            Ok(()),
        )
        .0
    }

    fn label(outcome: CaptureOutcome) -> CaptureConsistency {
        let CaptureOutcome::Succeeded(snapshot) = outcome else {
            panic!("a marker result must never change the capture outcome: {outcome:?}");
        };
        snapshot.consistency
    }

    #[test]
    fn a_quiet_database_is_labelled_matched() {
        assert_eq!(
            label(labelled(|_| Ok(MARKER.to_owned()))),
            CaptureConsistency::Matched
        );
    }

    #[test]
    fn a_database_changed_during_the_window_is_unmatched_but_succeeds() {
        assert_eq!(
            label(labelled(|n| Ok(if n == 1 {
                MARKER.to_owned()
            } else {
                MARKER.replace("1234", "1235")
            }))),
            CaptureConsistency::Unmatched(UnmatchedReason::DatabaseChanged)
        );
    }

    #[test]
    fn an_unreadable_marker_is_unmatched_unavailable_but_succeeds() {
        for first in [true, false] {
            for bad in [
                Err(ExecutorError::StepFailed),
                Ok(String::new()),
                Ok("rs_blog.wp_posts\tNULL\n".to_owned()),
                Ok("not a checksum line\n".to_owned()),
            ] {
                let outcome = labelled(|n| {
                    if (n == 1) == first {
                        bad.clone()
                    } else {
                        Ok(MARKER.to_owned())
                    }
                });
                assert_eq!(
                    label(outcome),
                    CaptureConsistency::Unmatched(UnmatchedReason::MarkerUnavailable),
                    "{bad:?} first={first}"
                );
            }
        }
    }

    #[test]
    fn the_marker_command_is_fixed_and_names_only_the_site_database() {
        let command = super::marker_command("/srv/sites/blog", "rs_blog");
        assert_eq!(command[0], format!("{}/mariadb", super::BIN));
        assert_eq!(command[1], "--defaults-file=/srv/sites/blog/private/db.cnf");
        assert_eq!(command.last().unwrap(), "rs_blog");
        let sql = &command[command.len() - 2];
        assert!(sql.contains("CHECKSUM TABLE"));
        assert!(sql.contains("table_schema=DATABASE()"));
        assert!(!sql.contains("rs_blog"));
    }
}

#[cfg(test)]
#[path = "capture_launch_tests.rs"]
mod launch_tests;

#[cfg(test)]
#[path = "capture_freeze_tests.rs"]
mod freeze_tests;
