//! Lab `restore_probe` (S08 W035): restore one snapshot into a throwaway
//! sandbox and check the restored application, without touching the source
//! site. A throwaway account and tree get their own SELinux level and an
//! empty throwaway database. The fetch runs as that account in
//! `rustiron_capture_t` with the site's read-only store key; the import and
//! the health check run with no network and no credentials. Root never runs
//! restored content; it parses only the bounded output of fixed readers
//! (the unprivileged inventory worker and, D-034, the database facts reader
//! and the page render, whose stdout PID 1 writes outside the sandbox), and
//! removes exactly what it created.
//!
//! D-031 (W373): a product build runs the same phases. Only the store half
//! differs ([`ProbeStore`]): the product fetch runs through the product
//! store worker in the store namespace ([`product::ProductStore`]).

use std::path::Path;

use rustix::fs::{self, AtFlags};

use crate::{ExecutorError, files, provision, provision::skeleton};

mod cleanup;
pub(crate) mod database;
mod health;
mod inventory;
mod inventory_report;
mod product;
pub(crate) use cleanup::{CleanupReport, cleanup};
pub(crate) use product::ProductStore;

pub(crate) const BASE: &str = crate::layout::RESTORE_PROBES_ROOT;
/// The probe level; no site category uses it (sites use c101–c102, c201+).
pub(crate) const LEVEL: &str = "s0:c950";
const CREDENTIALS_DIR: &str = crate::layout::JOB_CREDENTIALS_DIR;
const BIN: &str = crate::layout::JOB_BIN_DIR;
const LSPHP: &str = "/usr/local/lsws/lsphp84/bin/lsphp";
/// D-034 (W383): the fixed render script. It writes no report; its stdout is
/// the restored home page.
const RENDER_SCRIPT: &str = include_str!("restore_assets/render.php");
/// Lab ceiling on the snapshot's logical restore size. The fetch writes
/// into the host root filesystem with no quota, so a larger (or sparse)
/// snapshot is refused before anything is written.
const MAX_RESTORE_BYTES: u64 = 2 << 30;
/// Lab ceiling on restored entries (twice the inventory entry ceiling).
const MAX_RESTORE_FILES: u64 = 200_000;
/// Probe unit runtime ceiling. It must end well before the helper's own
/// command deadline: the helper may not stop units (no `init_t:system stop`),
/// so a unit still running when the helper gives up blocks cleanup (W181).
const UNIT_RUNTIME_SECS: u64 = 100;
/// Margin between the unit ceiling and the helper deadline for stop and
/// collection.
const UNIT_RUNTIME_MARGIN_SECS: u64 = 15;
/// Bound on the stop after the ceiling; systemd sends SIGKILL after this
/// (restic held SIGTERM for 21 s in W207).
const UNIT_STOP_SECS: u64 = 5;
const _: () = assert!(
    UNIT_RUNTIME_SECS + UNIT_STOP_SECS + UNIT_RUNTIME_MARGIN_SECS
        <= crate::provision::COMMAND_TIMEOUT.as_secs()
);
/// Bound on the `restic stats` JSON line.
const MAX_STATS_BYTES: usize = 512;

/// Inputs fixed by the verified plan, journal and enrolled policy.
pub struct ProbeTarget<'a> {
    /// Source site account (`rs_<site_id>`); never written.
    pub account: &'a str,
    /// The source site's hostname (for the restored WordPress request).
    pub hostname: &'a str,
    /// Snapshot to restore (64 hex, validated by the contract).
    pub snapshot: &'a str,
    /// The journaled throwaway account `rp_<6 hex>`.
    pub probe: &'a str,
}

/// The lab store the lab fetch reaches over the host network.
pub struct LabStore<'a> {
    /// `<repository base>/<account>`.
    pub repository: &'a str,
    /// The single store address the fetch may reach.
    pub store_address: &'a str,
}

/// The receipt a probe writes: the lab receipt, or the product receipt of
/// D-031 (schema `rustiron-restore-probe/2`, no independent copy checked).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Profile {
    /// `rustiron-lab-restore-probe/1`.
    Lab,
    /// `rustiron-restore-probe/2`.
    Product,
}

/// The store half of a probe: the snapshot size check, the fetch into
/// `<sandbox>/tmp/restore`, and the repository check, all read-only.
/// Every other phase is the same for each store.
pub(crate) trait ProbeStore {
    /// The snapshot is within [`MAX_RESTORE_BYTES`] and
    /// [`MAX_RESTORE_FILES`]; checked before the fetch writes anything.
    fn within_size(&self, target: &ProbeTarget<'_>) -> Result<(), ExecutorError>;
    /// Restores the snapshot into the sandbox as the probe account.
    fn fetch(&self, target: &ProbeTarget<'_>) -> Result<(), ExecutorError>;
    /// `restic check` (structure) with the read-only key.
    fn check(&self, target: &ProbeTarget<'_>) -> Result<(), ExecutorError>;
    /// The receipt this store's probe writes.
    fn profile(&self) -> Profile;
}

impl ProbeStore for LabStore<'_> {
    fn within_size(&self, target: &ProbeTarget<'_>) -> Result<(), ExecutorError> {
        within_size(target, self)
    }

    fn fetch(&self, target: &ProbeTarget<'_>) -> Result<(), ExecutorError> {
        fetch(target, self, "fetch")
    }

    fn check(&self, target: &ProbeTarget<'_>) -> Result<(), ExecutorError> {
        fetch(target, self, "check")
    }

    fn profile(&self) -> Profile {
        Profile::Lab
    }
}

/// Whether the site has an enrolled read-only fetch key and repository
/// password (metadata only; the executor never reads them).
pub fn fetch_enrolled(account: &str) -> bool {
    let directory = Path::new(CREDENTIALS_DIR).join(account);
    files::open_trusted_directory(&directory, 0).is_ok_and(|fd| {
        ["fetch-aws", "repo.password"].iter().all(|name| {
            fs::statat(&fd, *name, AtFlags::SYMLINK_NOFOLLOW).is_ok_and(|stat| {
                fs::FileType::from_raw_mode(stat.st_mode) == fs::FileType::RegularFile
                    && stat.st_uid == 0
                    && stat.st_mode & 0o077 == 0
            })
        })
    })
}

/// Runs the whole lab probe; see [`run_probe_with`].
pub fn run_probe(
    target: &ProbeTarget<'_>,
    store: &LabStore<'_>,
    window_start: u64,
) -> (serde_json::Value, rustiron_journal::ProbeState) {
    run_probe_with(target, store, window_start)
}

/// Runs the whole probe against `store` and always attempts cleanup.
/// Returns the receipt JSON and the outcome, with incomplete cleanup taking
/// precedence over health.
pub(crate) fn run_probe_with(
    target: &ProbeTarget<'_>,
    store: &impl ProbeStore,
    window_start: u64,
) -> (serde_json::Value, rustiron_journal::ProbeState) {
    let started = std::time::Instant::now();
    let mut phases = serde_json::Map::new();
    let mut lap = |name: &str, since: &mut std::time::Instant| {
        phases.insert(
            name.to_owned(),
            serde_json::json!(since.elapsed().as_millis() as u64),
        );
        *since = std::time::Instant::now();
    };
    let mut since = std::time::Instant::now();
    let checks = (|| -> Result<Checks, ExecutorError> {
        create_sandbox(target)?;
        lap("setup", &mut since);
        let mut checks = Checks {
            fetch: store.within_size(target).is_ok() && store.fetch(target).is_ok(),
            ..Checks::default()
        };
        lap("fetch", &mut since);
        checks.integrity = checks.fetch && store.check(target).is_ok();
        if checks.fetch {
            checks.inventory = inventory::collect(target).ok();
        }
        checks.assess(|| import(target), || Some(health(target)));
        lap("probe", &mut since);
        Ok(checks)
    })();
    let cleanup = cleanup(target);
    lap("cleanup", &mut since);
    let checks = checks.unwrap_or_default();
    let (mut receipt, passed) = probe_receipt(store.profile(), &checks);
    let header = serde_json::json!({
        "site": target.account,
        "snapshot_id": target.snapshot,
        "probe_account": target.probe,
        "window_start": window_start,
        "elapsed_ms": started.elapsed().as_millis() as u64,
        "durations_ms": phases,
        "cleanup": cleanup.receipt(),
    });
    if let (Some(receipt), serde_json::Value::Object(header)) = (receipt.as_object_mut(), header) {
        receipt.extend(header);
    }
    (receipt, cleanup.probe_state(passed))
}

/// The receipt's schema, seven fields, inventory and limitations for one
/// probe's checks, and whether every check passed. The caller adds the
/// identity, timing and cleanup members.
fn probe_receipt(profile: Profile, checks: &Checks) -> (serde_json::Value, bool) {
    let health = checks.health.clone().unwrap_or(serde_json::json!({}));
    let healthy = health::healthy(&health);
    let status = |ok: bool| if ok { "pass" } else { "fail" };
    let product = profile == Profile::Product;
    let fields = serde_json::json!({
        "artifacts_complete": {"status": checks.artifacts_status(),
            "scope": checks.inventory_scope()},
        "repository_integrity_checked": {"status": status(checks.integrity),
            "scope": if product {
                "restic check (structure, no data read) with the fetch key, by the store worker in the store namespace"
            } else {
                "restic check (metadata and structure) with the read-only key"
            }},
        "decryption_tested": {"status": status(checks.fetch),
            "scope": "snapshot decrypted by restore with the site's repository password"},
        "application_consistency_assessed": {"status": match checks.import { Some(result) => status(result), None => "not_run" },
            "scope": "dump imported by a throwaway database user in client sandbox mode, within a database size cap (single-transaction capture); files were not captured atomically",
            "observed": checks.database.map(|watch| watch.observed())},
        "restored_in_isolation": {"status": status(checks.fetch),
            "scope": if product {
                "throwaway account and SELinux level; the fetch reaches only the store relay from the store namespace; the import and health check run with no network and no credentials; enforced by unit settings and SELinux, not a proof of containment"
            } else {
                "throwaway account and SELinux level; the import and health check run with no network and no credentials; enforced by unit settings, not adversarially tested"
            }},
        "health_checks_passed": {"status": if checks.import == Some(true) { status(healthy) } else { "not_run" },
            "scope": "restored database read with fixed SQL by a reader that runs no restored code, before the restored PHP runs: WordPress tables, siteurl, admin user; then the restored WordPress renders a titled home page (the page is the restored code's own output)",
            "observed": health},
        "independent_copy_confirmed": if product {
            serde_json::json!({"status": "not_run",
                "scope": "D-026: the probe restores from the enrolled store only; no independent or off-site copy is checked"})
        } else {
            serde_json::json!({"status": "fail",
                "scope": "local-PC lab destination, not an independent off-host copy"})
        },
    });
    let passed =
        checks.artifacts_complete() && checks.integrity && checks.import == Some(true) && healthy;
    let (schema, limitations) = if product {
        (
            "rustiron-restore-probe/2",
            serde_json::json!([
                "self-attested by the executor on the host it checks",
                "restore on the source host, not on a separate recovery host",
                "confinement by account, SELinux level and unit settings; not a proof of containment against hostile content",
                "no independent copy is checked (D-026)",
            ]),
        )
    } else {
        (
            "rustiron-lab-restore-probe/1",
            serde_json::json!([
                "lab only, synthetic keys",
                "adversarial corpus NOT_RUN",
                "local restore on the source host"
            ]),
        )
    };
    let receipt = serde_json::json!({
        "receipt_schema": schema,
        "fields": fields,
        "inventory": checks.inventory,
        "limitations": limitations,
    });
    (receipt, passed)
}

#[derive(Clone, Default)]
struct Checks {
    fetch: bool,
    integrity: bool,
    inventory: Option<inventory_report::Report>,
    import: Option<bool>,
    database: Option<database::Watch>,
    health: Option<serde_json::Value>,
}

impl Checks {
    fn assess(
        &mut self,
        import: impl FnOnce() -> (bool, Option<database::Watch>),
        health: impl FnOnce() -> Option<serde_json::Value>,
    ) {
        self.import = if self.integrity && self.artifacts_complete() {
            let (imported, watch) = import();
            self.database = watch;
            Some(imported)
        } else {
            None
        };
        self.health = if self.import == Some(true) {
            health()
        } else {
            None
        };
    }

    fn artifacts_complete(&self) -> bool {
        self.fetch
            && self.inventory.as_ref().is_some_and(|r| {
                r.status == inventory_report::Status::Complete
                    && r.files.is_some_and(|n| n > 0)
                    && r.dump == Some(true)
            })
    }

    fn artifacts_status(&self) -> &'static str {
        if !self.fetch {
            return "fail";
        }
        match &self.inventory {
            Some(r) if r.status == inventory_report::Status::Complete => {
                if self.artifacts_complete() {
                    "pass"
                } else {
                    "fail"
                }
            }
            _ => "unknown",
        }
    }

    fn inventory_scope(&self) -> String {
        match &self.inventory {
            Some(r) if r.status == inventory_report::Status::Complete => {
                match (r.files, r.dump, r.extra_paths) {
                    (Some(files), Some(dump), Some(extra)) => format!(
                        "inventory completed: {files} regular html files; dump present={dump}; {extra} snapshot entries outside the site's html and dump paths (restored in the sandbox, not inspected); non-atomic metadata observation"
                    ),
                    _ => "inventory observation invalid; artifact completeness unknown".to_owned(),
                }
            }
            Some(r) => format!(
                "inventory {:?}; artifact completeness unknown; see typed report",
                r.status
            ),
            None => "unprivileged inventory unavailable; artifact completeness unknown".to_owned(),
        }
    }
}

/// The fetch target: `<sandbox>/tmp/restore`.
fn restore_root(target: &ProbeTarget<'_>) -> String {
    format!(
        "{BASE}/{}/tmp/{}",
        target.probe,
        crate::layout::PROBE_RESTORE_DIR
    )
}

/// The site's captured root below the fetch target (`srv/sites/<account>`).
fn site_below_restore(target: &ProbeTarget<'_>) -> String {
    format!(
        "{}/{}",
        crate::layout::SITES_ROOT.trim_start_matches('/'),
        target.account
    )
}

fn site_root(target: &ProbeTarget<'_>) -> String {
    format!("{}/{}", restore_root(target), site_below_restore(target))
}

fn create_sandbox(target: &ProbeTarget<'_>) -> Result<(), ExecutorError> {
    let probe = target.probe;
    let root = format!("{BASE}/{probe}");
    if std::fs::symlink_metadata(BASE).is_err() {
        provision::run(
            "/usr/bin/install",
            &["-d", "-m", "0755", "-o", "root", "-g", "root", "--", BASE],
        )?;
    }
    provision::run(
        "/usr/sbin/useradd",
        &[
            "--system",
            "--no-create-home",
            "--home-dir",
            &root,
            "--shell",
            "/sbin/nologin",
            "--",
            probe,
        ],
    )?;
    provision::run(
        "/usr/bin/install",
        &["-d", "-m", "0751", "-o", "root", "-g", "root", "--", &root],
    )?;
    provision::run(
        "/usr/bin/install",
        &[
            "-d",
            "-m",
            "0750",
            "-o",
            probe,
            "-g",
            probe,
            "--",
            &format!("{root}/tmp"),
        ],
    )?;
    // W275: the sandbox must be exactly the empty `tmp/` just created,
    // checked and labelled through descriptors; no recursive root relabel.
    let base = files::open_traversable_directory(Path::new(BASE), 0)?;
    let sandbox = files::open_child_directory(&base, probe, 0)?;
    let entries = skeleton::open_skeleton(&sandbox, skeleton::PROBE)?;
    for (kind, pattern) in [
        (skeleton::CONTENT, format!("{root}(/.*)?")),
        (skeleton::READ_WRITE, format!("{root}/tmp(/.*)?")),
    ] {
        provision::run(
            "/usr/sbin/semanage",
            &[
                "fcontext", "--add", "--type", kind, "--range", LEVEL, "--", &pattern,
            ],
        )?;
    }
    skeleton::label_skeleton(
        &sandbox,
        &entries,
        LEVEL,
        &skeleton::set_label,
        &skeleton::get_label,
    )?;
    skeleton::unchanged(&sandbox, skeleton::PROBE, &entries)
}

/// Whether `restic stats --mode restore-size` output is within the lab
/// ceilings. Anything unparsable is refused.
fn size_allows(bytes: &[u8]) -> bool {
    let Ok(stats) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return false;
    };
    match (
        stats["total_size"].as_u64(),
        stats["total_file_count"].as_u64(),
    ) {
        (Some(size), Some(files)) => within_ceilings(size, files),
        _ => false,
    }
}

/// Whether a logical restore size and entry count are within the ceilings.
pub(crate) fn within_ceilings(size: u64, files: u64) -> bool {
    size <= MAX_RESTORE_BYTES && files <= MAX_RESTORE_FILES
}

/// Reads the snapshot's logical restore size with the read-only key before
/// the fetch writes anything, and refuses one over the ceilings.
fn within_size(target: &ProbeTarget<'_>, lab: &LabStore<'_>) -> Result<(), ExecutorError> {
    let unit = unit_name(target, "size")?;
    let name = format!("{unit}.size.json");
    let directory = files::open_traversable_directory(Path::new(crate::capture::OUTPUT_DIR), 0)?;
    let output = format!("{}/{name}", crate::capture::OUTPUT_DIR);
    let mut extra = store_properties(target, lab, &unit);
    extra.push(format!("StandardOutput=truncate:{output}"));
    let program = format!("{BIN}/restic");
    let ran = run_unit(
        target,
        &unit,
        &extra,
        &[
            &program,
            "stats",
            "--no-lock",
            "--no-cache",
            "--json",
            "--mode",
            "restore-size",
            target.snapshot,
        ],
    );
    let bytes = files::read_child(
        &directory,
        &name,
        0,
        files::Exposure::Readable,
        MAX_STATS_BYTES,
    );
    let removed = fs::unlinkat(&directory, &name, AtFlags::empty());
    ran?;
    removed.map_err(|_| ExecutorError::Unavailable)?;
    if size_allows(&bytes?) {
        Ok(())
    } else {
        Err(ExecutorError::StepFailed)
    }
}

/// Unit settings shared by every step that reaches the store.
fn store_properties(target: &ProbeTarget<'_>, lab: &LabStore<'_>, unit: &str) -> Vec<String> {
    let tmp = format!("{BASE}/{}/tmp", target.probe);
    let credentials = format!("/run/credentials/{unit}.service");
    vec![
        format!("SELinuxContext=system_u:system_r:rustiron_capture_t:{LEVEL}"),
        "IPAddressDeny=any".to_owned(),
        format!("IPAddressAllow={}/32", lab.store_address),
        format!(
            "LoadCredential=aws:{CREDENTIALS_DIR}/{}/fetch-aws",
            target.account
        ),
        format!(
            "LoadCredential=password:{CREDENTIALS_DIR}/{}/repo.password",
            target.account
        ),
        format!(
            "Environment=TMPDIR={tmp} AWS_SHARED_CREDENTIALS_FILE={credentials}/aws RESTIC_PASSWORD_FILE={credentials}/password RESTIC_REPOSITORY={}",
            lab.repository
        ),
    ]
}

/// `fetch` restores the snapshot; `check` verifies the repository. Both use
/// the read-only key and reach only the store.
fn fetch(target: &ProbeTarget<'_>, lab: &LabStore<'_>, step: &str) -> Result<(), ExecutorError> {
    let tmp = format!("{BASE}/{}/tmp", target.probe);
    let restore_target = format!("--target={tmp}/restore");
    let command: Vec<&str> = if step == "fetch" {
        vec![
            "restic",
            "restore",
            "--no-lock",
            "--no-cache",
            "--exclude-xattr=security.*",
            &restore_target,
            target.snapshot,
        ]
    } else {
        vec!["restic", "check", "--no-lock", "--no-cache"]
    };
    let unit = unit_name(target, step)?;
    let extra = store_properties(target, lab, &unit);
    let program = format!("{BIN}/restic");
    let mut argv = vec![program.as_str()];
    argv.extend(&command[1..]);
    run_unit(target, &unit, &extra, &argv)
}

/// Imports the dump under the D-034 size watch. Returns whether the import
/// passed and, once the import unit started, what the watch saw.
fn import(target: &ProbeTarget<'_>) -> (bool, Option<database::Watch>) {
    let Ok(dump_bytes) = prepare_import(target) else {
        return (false, None);
    };
    let Ok(unit) = unit_name(target, "import") else {
        return (false, None);
    };
    let probe = target.probe;
    let argv = import_argv(target.account, probe);
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    let properties = import_properties();
    let size_sql = database::size_sql(probe);
    let (passed, watch) = database::watch(
        database::cap(dump_bytes),
        database::POLL,
        || run_unit(target, &unit, &properties, &argv),
        || {
            provision::spawn(
                provision::MARIADB,
                &[
                    "--batch",
                    "--skip-column-names",
                    "--socket",
                    provision::DB_SOCKET,
                ],
                true,
                Some(size_sql.as_bytes()),
            )
            .ok()
            .and_then(|text| database::parse_size(&text))
        },
        || {
            // A failed stop still fails the import; the unit runtime ends it.
            let _ = provision::mariadb_admin(&database::stop_sql(probe));
        },
    );
    (passed, Some(watch))
}

/// The throwaway database and user, the sandbox `db.cnf`, and the label
/// census of the restored tree. Returns the dump size in bytes.
fn prepare_import(target: &ProbeTarget<'_>) -> Result<u64, ExecutorError> {
    let probe = target.probe;
    let site = site_root(target);
    let mut random = [0_u8; 24];
    rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty())
        .map_err(|_| ExecutorError::Unavailable)?;
    let password: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    provision::mariadb_admin(&format!(
        "CREATE DATABASE `{probe}`; CREATE USER '{probe}'@'localhost' IDENTIFIED BY '{password}'; GRANT ALL PRIVILEGES ON `{probe}`.* TO '{probe}'@'localhost';\n"
    ))?;
    let passwd = provision::read_etc("passwd")?;
    let uid = provision::account_uid(&passwd, probe).ok_or(ExecutorError::StepFailed)?;
    // The restored wp-config.php reads ../private/db.cnf: give it the
    // throwaway credentials, site-owned 0600.
    let site_dir = files::open_traversable_directory(Path::new(&site), uid)?;
    match fs::mkdirat(&site_dir, "private", rustix::fs::Mode::from_raw_mode(0o750)) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(_) => return Err(ExecutorError::StepFailed),
    }
    let private_fd = fs::openat(
        &site_dir,
        "private",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| ExecutorError::StepFailed)?;
    fs::fchown(
        &private_fd,
        Some(rustix::fs::Uid::from_raw(uid)),
        Some(rustix::fs::Gid::from_raw(uid)),
    )
    .map_err(|_| ExecutorError::StepFailed)?;
    let _ = fs::unlinkat(&private_fd, "db.cnf", AtFlags::empty());
    let cnf = format!(
        "[client]\nuser={probe}\npassword={password}\ndatabase={probe}\nsocket=/var/lib/mysql/mysql.sock\n"
    );
    provision::write_owned(&private_fd, "db.cnf", cnf.as_bytes(), uid, 0o600)?;
    // W265: no root relabel walk over restored content. restic already
    // creates every entry with the probe label (inherited type, job level);
    // only the two helper-written entries are labelled, by descriptor, and
    // the census then verifies the whole tree and fails the probe otherwise.
    let label = restored_label();
    let cnf_fd = fs::openat(
        &private_fd,
        "db.cnf",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| ExecutorError::StepFailed)?;
    for fd in [&private_fd, &cnf_fd] {
        fs::fsetxattr(
            fd,
            "security.selinux",
            label.as_bytes(),
            fs::XattrFlags::empty(),
        )
        .map_err(|_| ExecutorError::StepFailed)?;
    }
    let census = crate::census::census_labelled(
        &site_dir,
        uid,
        label.as_bytes(),
        &crate::census::label_of,
        crate::census::BOUNDS,
    )?;
    if !restored_labels_hold(&census) {
        return Err(ExecutorError::StepFailed);
    }
    // The inventory saw the dump as a single-link regular file.
    let dump_path = format!("tmp/{}", crate::layout::CAPTURE_DUMP_FILE);
    let dump = fs::statat(&site_dir, dump_path.as_str(), AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| ExecutorError::StepFailed)?;
    if fs::FileType::from_raw_mode(dump.st_mode) != fs::FileType::RegularFile || dump.st_nlink != 1
    {
        return Err(ExecutorError::StepFailed);
    }
    u64::try_from(dump.st_size).map_err(|_| ExecutorError::StepFailed)
}

/// The label every restored entry must carry: the probe fcontext type for
/// its tree (all of it lies under the probe's `tmp`) at the probe level.
fn restored_label() -> String {
    format!("system_u:object_r:httpd_sys_rw_content_t:{LEVEL}")
}

/// The restored tree is all probe-owned regular files and directories with
/// the probe label: nothing foreign, nothing mislabelled.
fn restored_labels_hold(census: &crate::census::Census) -> bool {
    census.owned_files > 0 && census.foreign == 0 && census.mislabelled == 0
}

/// The import unit's command. D-034 (W378 q2): the worker's `import`
/// action opens the dump as the probe and becomes the fixed `mariadb`
/// client in sandbox mode, reading the dump on stdin
/// (`manifest/import.rs`). `--sandbox` refuses the client's shell and file
/// commands (`\!`, `system`, `source`, `tee`) for the whole session, also
/// when a dump has no sandbox line of its own. In `--batch` mode the client
/// stops at the first failed statement and exits nonzero (W230 h6).
/// `--local-infile=0` stops a dump's `LOAD DATA LOCAL INFILE` from reading a
/// host file into the throwaway database (W378 q5a).
fn import_argv(account: &str, probe: &str) -> Vec<String> {
    vec![
        format!("{BIN}/{}", crate::manifest::WORKER),
        "import".to_owned(),
        account.to_owned(),
        probe.to_owned(),
    ]
}

/// The import unit: the probe level and no network. PID 1 cannot open the
/// dump for the unit (`init_t:s0` may not read the probe level), so the
/// worker opens it.
fn import_properties() -> Vec<String> {
    vec![
        format!("SELinuxContext=system_u:system_r:rustiron_capture_t:{LEVEL}"),
        "PrivateNetwork=yes".to_owned(),
        "IPAddressDeny=any".to_owned(),
    ]
}

/// D-034 (W383): the facts reader first, then the render. Root judges both.
fn health(target: &ProbeTarget<'_>) -> serde_json::Value {
    health::judge(|| database_facts(target).ok(), || render(target).ok())
}

/// The facts reader: fixed SQL as the probe in the capture domain, before
/// any restored PHP runs.
fn database_facts(target: &ProbeTarget<'_>) -> Result<health::Facts, ExecutorError> {
    let argv = health::facts_argv(BIN, &site_root(target), target.probe);
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    let bytes = run_unit_output(
        target,
        "facts",
        &output_unit_properties("rustiron_capture_t"),
        &argv,
        health::MAX_FACTS_BYTES,
    )?;
    health::parse_facts(&bytes).ok_or(ExecutorError::StepFailed)
}

/// The render: the restored WordPress home page in the site PHP domain.
fn render(target: &ProbeTarget<'_>) -> Result<health::Render, ExecutorError> {
    let probe = target.probe;
    let tmp = format!("{BASE}/{probe}/tmp");
    let passwd = provision::read_etc("passwd")?;
    let uid = provision::account_uid(&passwd, probe).ok_or(ExecutorError::StepFailed)?;
    let tmp_fd = files::open_traversable_directory(Path::new(&tmp), uid)?;
    let _ = fs::unlinkat(&tmp_fd, "render.php", AtFlags::empty());
    provision::write_new(&tmp_fd, "render.php", RENDER_SCRIPT.as_bytes())?;
    let script = format!("{tmp}/render.php");
    provision::run("/usr/sbin/restorecon", &["-F", "--", &script])?;
    let site = site_root(target);
    let bytes = run_unit_output(
        target,
        "render",
        &output_unit_properties("rustiron_php_t"),
        &render_command(&script, &site, target.hostname),
        health::MAX_PAGE_BYTES,
    )?;
    Ok(health::parse_render(&bytes))
}

/// `lsphp` with the fixed render script, the restored site root and the
/// hostname. No report path: the page goes to stdout.
fn render_command<'a>(script: &'a str, site: &'a str, hostname: &'a str) -> [&'a str; 5] {
    [LSPHP, "-q", script, site, hostname]
}

/// The facts and render units: `domain` at the probe level, no network.
fn output_unit_properties(domain: &str) -> Vec<String> {
    vec![
        format!("SELinuxContext=system_u:system_r:{domain}:{LEVEL}"),
        "PrivateNetwork=yes".to_owned(),
        "IPAddressDeny=any".to_owned(),
    ]
}

/// PID 1 writes the unit's stdout to `output`, a root-owned file in the
/// helper's runtime directory. Stderr goes to the journal, not into that
/// file. `LimitFSIZE=` stops any write past `limit`.
fn output_properties(output: &str, limit: usize) -> [String; 3] {
    [
        format!("StandardOutput=truncate:{output}"),
        "StandardError=journal".to_owned(),
        format!("LimitFSIZE={limit}"),
    ]
}

/// Runs one probe unit with [`output_properties`] and returns at most
/// `limit` bytes of its stdout. The file is removed after the read. The
/// restored tree cannot write it except through the unit's own stdout.
fn run_unit_output(
    target: &ProbeTarget<'_>,
    step: &str,
    extra: &[String],
    command: &[&str],
    limit: usize,
) -> Result<Vec<u8>, ExecutorError> {
    let unit = unit_name(target, step)?;
    let name = format!("{unit}.out");
    let output = format!("{}/{name}", crate::capture::OUTPUT_DIR);
    let mut properties = extra.to_vec();
    properties.extend(output_properties(&output, limit));
    crate::capture::ensure_output_dir()?;
    let ran = run_unit(target, &unit, &properties, command);
    let directory = files::open_traversable_directory(Path::new(crate::capture::OUTPUT_DIR), 0)?;
    let bytes = files::read_child(&directory, &name, 0, files::Exposure::Readable, limit);
    let _ = fs::unlinkat(&directory, name.as_str(), AtFlags::empty());
    ran?;
    bytes
}

/// `rustiron-probe-<probe>-<step>-<8 hex>`: every probe unit matches the
/// pattern that [`cleanup`] stops and lists.
pub(crate) fn unit_name(target: &ProbeTarget<'_>, step: &str) -> Result<String, ExecutorError> {
    let mut random = [0_u8; 4];
    rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty())
        .map_err(|_| ExecutorError::Unavailable)?;
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!("rustiron-probe-{}-{step}-{suffix}", target.probe))
}

/// One transient unit as the probe account with the shared sandbox.
fn run_unit(
    target: &ProbeTarget<'_>,
    unit: &str,
    extra: &[String],
    command: &[&str],
) -> Result<(), ExecutorError> {
    let args = unit_arguments(target, unit, extra, command);
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    provision::run("/usr/bin/systemd-run", &borrowed)
}

fn unit_arguments(
    target: &ProbeTarget<'_>,
    unit: &str,
    extra: &[String],
    command: &[&str],
) -> Vec<String> {
    let probe = target.probe;
    let tmp = format!("{BASE}/{probe}/tmp");
    let mut properties = vec![
        format!("User={probe}"),
        format!("Group={probe}"),
        "NoNewPrivileges=yes".to_owned(),
        "CapabilityBoundingSet=".to_owned(),
        "ProtectSystem=strict".to_owned(),
        "ProtectHome=yes".to_owned(),
        "PrivateTmp=yes".to_owned(),
        "PrivateDevices=yes".to_owned(),
        "ProtectProc=invisible".to_owned(),
        format!("ReadWritePaths={tmp}"),
        format!("RuntimeMaxSec={UNIT_RUNTIME_SECS}"),
        format!("TimeoutStopSec={UNIT_STOP_SECS}"),
        "MemoryMax=512M".to_owned(),
        "MemorySwapMax=0".to_owned(),
        "TasksMax=32".to_owned(),
        // W383 r3: no core dump of restored code outside the sandbox.
        "LimitCORE=0".to_owned(),
        provision::JOB_CPU_WEIGHT.to_owned(),
    ];
    properties.extend(extra.iter().cloned());
    if !extra
        .iter()
        .any(|property| property.starts_with("Environment="))
    {
        properties.push(format!("Environment=TMPDIR={tmp}"));
    }
    let mut args = vec![
        "--unit".to_owned(),
        unit.to_owned(),
        "--wait".to_owned(),
        "--quiet".to_owned(),
        "--collect".to_owned(),
    ];
    for property in &properties {
        args.extend(["--property".to_owned(), property.clone()]);
    }
    args.push("--".to_owned());
    args.extend(command.iter().map(|s| (*s).to_owned()));
    args
}

#[cfg(test)]
mod size_tests {
    use super::{MAX_RESTORE_BYTES, MAX_RESTORE_FILES, size_allows};

    fn stats(size: u64, files: u64) -> Vec<u8> {
        format!(r#"{{"total_size":{size},"total_file_count":{files},"snapshots_count":1}}"#)
            .into_bytes()
    }

    #[test]
    fn probe_units_end_before_the_helper_deadline() {
        use super::{UNIT_RUNTIME_MARGIN_SECS, UNIT_RUNTIME_SECS};
        assert!(
            UNIT_RUNTIME_SECS + UNIT_RUNTIME_MARGIN_SECS
                <= crate::provision::COMMAND_TIMEOUT.as_secs()
        );
    }

    #[test]
    fn a_snapshot_within_the_ceilings_is_allowed() {
        assert!(size_allows(&stats(110_183_745, 4_258)));
        assert!(size_allows(&stats(MAX_RESTORE_BYTES, MAX_RESTORE_FILES)));
    }

    #[test]
    fn a_large_or_sparse_snapshot_is_refused() {
        // W180 b3: one 3 GiB sparse file.
        assert!(!size_allows(&stats(3_331_409_217, 4_258)));
        assert!(!size_allows(&stats(MAX_RESTORE_BYTES + 1, 1)));
    }

    #[test]
    fn too_many_entries_are_refused() {
        assert!(!size_allows(&stats(1, MAX_RESTORE_FILES + 1)));
    }

    #[test]
    fn unparsable_or_incomplete_stats_are_refused() {
        for bytes in [
            &b""[..],
            b"not json",
            br#"{"total_size":1}"#,
            br#"{"total_file_count":1}"#,
            br#"{"total_size":-1,"total_file_count":1}"#,
            br#"{"total_size":"1","total_file_count":1}"#,
        ] {
            assert!(!size_allows(bytes));
        }
    }
}

#[cfg(test)]
mod job_tests {
    use super::{ProbeTarget, unit_arguments};

    /// W280: probe jobs yield CPU to the site pools (W279 measured their
    /// tail cost on untouched sites).
    #[test]
    fn probe_jobs_run_at_a_low_cpu_weight() {
        let target = ProbeTarget {
            account: "rs_x",
            hostname: "x.example.test",
            snapshot: "0",
            probe: "rp_abcdef",
        };
        let args = unit_arguments(&target, "u", &[], &["/bin/true"]);
        let properties: Vec<&str> = args
            .windows(2)
            .filter(|pair| pair[0] == "--property")
            .map(|pair| pair[1].as_str())
            .collect();
        assert!(properties.contains(&"CPUWeight=20"), "{properties:?}");
        assert!(properties.contains(&"MemoryMax=512M"));
    }

    #[test]
    fn probe_jobs_leave_no_core_dump() {
        // W383 r3: a render that its file size limit killed (SIGXFSZ) left a
        // core of restored code in /var/lib/systemd/coredump, outside the
        // sandbox and outside cleanup.
        let target = ProbeTarget {
            account: "rs_x",
            hostname: "x.example.test",
            snapshot: "0",
            probe: "rp_abcdef",
        };
        let args = unit_arguments(&target, "u", &[], &["/bin/true"]);
        assert!(
            args.windows(2)
                .any(|pair| pair[0] == "--property" && pair[1] == "LimitCORE=0"),
            "{args:?}"
        );
    }
}

#[cfg(test)]
mod import_tests {
    use super::{import_argv, import_properties};

    #[test]
    fn the_import_unit_runs_the_worker_import_action() {
        // W378 q2 and W230 h6: the worker becomes the fixed sandbox-mode
        // client with the dump on stdin (manifest/import.rs tests the
        // client arguments and the dump checks). No path, statement, or
        // client option comes from here.
        let argv = import_argv("rs_x", "rp_0a9fbc");
        assert_eq!(
            argv,
            [
                format!("{}/capture-manifest", super::BIN),
                "import".to_owned(),
                "rs_x".to_owned(),
                "rp_0a9fbc".to_owned()
            ]
        );
        let properties = import_properties();
        assert!(properties.contains(&"PrivateNetwork=yes".to_owned()));
        assert!(properties.contains(&"IPAddressDeny=any".to_owned()));
        assert!(
            properties.contains(
                &"SELinuxContext=system_u:system_r:rustiron_capture_t:s0:c950".to_owned()
            )
        );
        assert!(!properties.iter().any(|p| p.starts_with("StandardInput")));
    }
}

#[cfg(test)]
mod health_unit_tests {
    use super::{
        BASE, LEVEL, ProbeTarget, health, output_properties, output_unit_properties,
        render_command, unit_arguments,
    };

    fn properties(extra: &[String]) -> Vec<String> {
        let target = ProbeTarget {
            account: "rs_x",
            hostname: "x.example.test",
            snapshot: "0",
            probe: "rp_abcdef",
        };
        let args = unit_arguments(&target, "u", extra, &["/bin/true"]);
        args.windows(2)
            .filter(|pair| pair[0] == "--property")
            .map(|pair| pair[1].clone())
            .collect()
    }

    #[test]
    fn the_verdict_files_are_written_by_pid_1_outside_the_sandbox() {
        // D-034 (W378 f1 to f4): restored code wrote, replaced, or forged the
        // report file in the sandbox. PID 1 now writes each unit's stdout to
        // the helper's root-only runtime directory, bounded by LimitFSIZE.
        let output = format!("{}/u.out", crate::capture::OUTPUT_DIR);
        assert!(!output.starts_with(BASE));
        let [stdout, stderr, limit] = output_properties(&output, health::MAX_PAGE_BYTES);
        assert_eq!(stdout, format!("StandardOutput=truncate:{output}"));
        assert_eq!(stderr, "StandardError=journal");
        assert_eq!(limit, "LimitFSIZE=1048576");
        for (domain, expected) in [
            ("rustiron_capture_t", "rustiron_capture_t"),
            ("rustiron_php_t", "rustiron_php_t"),
        ] {
            let all = properties(&output_unit_properties(domain));
            for property in [
                format!("SELinuxContext=system_u:system_r:{expected}:{LEVEL}"),
                "PrivateNetwork=yes".to_owned(),
                "IPAddressDeny=any".to_owned(),
                "User=rp_abcdef".to_owned(),
                "NoNewPrivileges=yes".to_owned(),
            ] {
                assert!(all.contains(&property), "{domain}: {property}");
            }
            assert!(!all.iter().any(|p| p.starts_with("LoadCredential")));
        }
    }

    #[test]
    fn the_render_takes_no_report_path() {
        let command = render_command(
            "/p/tmp/render.php",
            "/p/tmp/restore/srv/sites/rs_x",
            "x.example.test",
        );
        assert_eq!(
            command,
            [
                "/usr/local/lsws/lsphp84/bin/lsphp",
                "-q",
                "/p/tmp/render.php",
                "/p/tmp/restore/srv/sites/rs_x",
                "x.example.test"
            ]
        );
        let script = include_str!("restore_assets/render.php");
        for word in [
            "file_put_contents",
            "json_encode",
            "register_shutdown_function",
            "fopen",
        ] {
            assert!(!script.contains(word), "{word}");
        }
    }
}

#[cfg(test)]
mod label_tests {
    use super::{restored_label, restored_labels_hold};
    use crate::census::{BOUNDS, census_labelled};
    use std::{fs, path::PathBuf};

    fn tree(tag: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!("ri-w265-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("html/wp-includes")).unwrap();
        fs::create_dir_all(base.join("private")).unwrap();
        fs::write(base.join("html/index.php"), "x").unwrap();
        fs::write(base.join("html/wp-includes/version.php"), "x").unwrap();
        fs::write(base.join("private/db.cnf"), "x").unwrap();
        base
    }

    fn check(tag: &str, low: &str) -> bool {
        let base = tree(tag);
        let dir = rustix::fs::open(
            &base,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let want = restored_label();
        let label = |_: &rustix::fd::OwnedFd, name: &std::ffi::CStr| -> Option<Vec<u8>> {
            // The helper-written entries carry `low` unless labelled at write.
            let n = name.to_bytes();
            Some(if n == b"db.cnf" || n == b"private" {
                low.as_bytes().to_vec()
            } else {
                want.as_bytes().to_vec()
            })
        };
        let me = rustix::process::getuid().as_raw();
        let ok = census_labelled(&dir, me, want.as_bytes(), &label, BOUNDS)
            .is_ok_and(|c| restored_labels_hold(&c));
        let _ = fs::remove_dir_all(&base);
        ok
    }

    #[test]
    fn the_restored_tree_passes_only_when_every_entry_has_the_probe_label() {
        assert!(check("ok", &restored_label()));
        // W265: without walk 2, a helper-written entry left at s0 fails the probe.
        assert!(!check("low", "system_u:object_r:httpd_sys_rw_content_t:s0"));
        assert!(!check(
            "type",
            &restored_label().replace("rw_content", "content")
        ));
    }

    #[test]
    fn the_probe_label_is_the_fcontext_type_at_the_probe_level() {
        assert_eq!(
            restored_label(),
            "system_u:object_r:httpd_sys_rw_content_t:s0:c950"
        );
    }
}

#[cfg(test)]
mod receipt_tests {
    use super::{Checks, Profile, inventory_report, probe_receipt};

    fn checks(fetch: bool, integrity: bool, import: Option<bool>, healthy: bool) -> Checks {
        let report = br#"{"schema_version":3,"status":"complete","reason":null,"files":3784,"dump":true,"entries":4257,"max_depth":9,"world_writable":0,"extra_paths":0}"#;
        Checks {
            fetch,
            integrity,
            inventory: fetch.then(|| inventory_report::decode(report).unwrap()),
            import,
            database: None,
            health: (import == Some(true)).then(|| {
                serde_json::json!({"installed": healthy, "home_title": "W373", "admin_exists": true})
            }),
        }
    }

    fn statuses(receipt: &serde_json::Value) -> Vec<(String, String)> {
        receipt["fields"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, field)| (name.clone(), field["status"].as_str().unwrap().to_owned()))
            .collect()
    }

    #[test]
    fn a_passing_product_probe_claims_no_independent_copy() {
        // D-031 (W373): the product receipt, with D-026's not_run copy field.
        let (receipt, passed) =
            probe_receipt(Profile::Product, &checks(true, true, Some(true), true));
        assert!(passed);
        assert_eq!(receipt["receipt_schema"], "rustiron-restore-probe/2");
        let fields = statuses(&receipt);
        assert_eq!(fields.len(), 7);
        for (name, status) in &fields {
            let expected = if name == "independent_copy_confirmed" {
                "not_run"
            } else {
                "pass"
            };
            assert_eq!(status, expected, "{name}");
        }
        let limitations = receipt["limitations"].as_array().unwrap();
        assert!(
            limitations
                .iter()
                .any(|l| l.as_str().unwrap().contains("D-026"))
        );
        assert!(!receipt.to_string().contains("lab only"));
    }

    #[test]
    fn a_failed_fetch_runs_no_later_check_and_never_passes() {
        let (receipt, passed) = probe_receipt(Profile::Product, &checks(false, false, None, false));
        assert!(!passed);
        let fields: std::collections::BTreeMap<_, _> = statuses(&receipt).into_iter().collect();
        assert_eq!(fields["decryption_tested"], "fail");
        assert_eq!(fields["artifacts_complete"], "fail");
        assert_eq!(fields["application_consistency_assessed"], "not_run");
        assert_eq!(fields["health_checks_passed"], "not_run");
        assert_eq!(fields["independent_copy_confirmed"], "not_run");
        // A failed import, health check or integrity check never passes.
        assert!(!probe_receipt(Profile::Product, &checks(true, true, Some(false), true)).1);
        assert!(!probe_receipt(Profile::Product, &checks(true, true, Some(true), false)).1);
        assert!(!probe_receipt(Profile::Product, &checks(true, false, Some(true), true)).1);
    }

    #[test]
    fn the_receipt_states_extra_snapshot_paths() {
        // W378 (W328 c4b): a snapshot with paths outside the site's html and
        // dump restored inside the sandbox, and the receipt did not say so.
        let report = br#"{"schema_version":3,"status":"complete","reason":null,"files":3784,"dump":true,"entries":4260,"max_depth":9,"world_writable":0,"extra_paths":3}"#;
        let checks = Checks {
            fetch: true,
            integrity: true,
            inventory: Some(inventory_report::decode(report).unwrap()),
            import: None,
            database: None,
            health: None,
        };
        for profile in [Profile::Product, Profile::Lab] {
            let (receipt, _) = probe_receipt(profile, &checks);
            assert_eq!(receipt["inventory"]["extra_paths"], 3);
            let scope = receipt["fields"]["artifacts_complete"]["scope"]
                .as_str()
                .unwrap();
            assert!(
                scope.contains("3 snapshot entries outside the site's html and dump paths"),
                "{scope}"
            );
        }
    }

    #[test]
    fn a_forged_page_with_a_missing_admin_fails_the_probe() {
        // W378 f4 passed: the restored plugin forged the health report. The
        // admin fact now comes from the database reader.
        let mut forged = checks(true, true, Some(true), true);
        forged.health = Some(super::health::judge(
            || super::health::parse_facts(b"3\t1\t0\t999\n"),
            || {
                Some(super::health::parse_render(
                    b"<title>W383 Probe Site</title>",
                ))
            },
        ));
        let (receipt, passed) = probe_receipt(Profile::Product, &forged);
        assert!(!passed);
        assert_eq!(receipt["fields"]["health_checks_passed"]["status"], "fail");
        assert_eq!(
            receipt["fields"]["health_checks_passed"]["observed"]["admin_exists"],
            false
        );
        let mut good = forged.clone();
        good.health = Some(super::health::judge(
            || super::health::parse_facts(b"3\t1\t1\t41\n"),
            || {
                Some(super::health::parse_render(
                    b"<title>W383 Probe Site</title>",
                ))
            },
        ));
        assert!(probe_receipt(Profile::Product, &good).1);
    }

    #[test]
    fn the_receipt_states_the_database_watch() {
        let mut stopped = checks(true, true, Some(false), true);
        stopped.database = Some(super::database::Watch {
            cap: 67_108_864,
            peak: Some(80_000_000),
            stopped: Some(super::database::Stop::OverCap),
        });
        let (receipt, passed) = probe_receipt(Profile::Product, &stopped);
        assert!(!passed);
        let field = &receipt["fields"]["application_consistency_assessed"];
        assert_eq!(field["status"], "fail");
        assert_eq!(field["observed"]["stopped"], "over_cap");
        assert_eq!(field["observed"]["database_cap_bytes"], 67_108_864);
        assert!(field["scope"].as_str().unwrap().contains("size cap"));
    }

    #[test]
    fn the_lab_receipt_is_unchanged() {
        let (receipt, passed) = probe_receipt(Profile::Lab, &checks(true, true, Some(true), true));
        assert!(passed);
        assert_eq!(receipt["receipt_schema"], "rustiron-lab-restore-probe/1");
        assert_eq!(
            receipt["fields"]["independent_copy_confirmed"]["status"],
            "fail"
        );
        assert_eq!(receipt["limitations"][0], "lab only, synthetic keys");
    }
}
