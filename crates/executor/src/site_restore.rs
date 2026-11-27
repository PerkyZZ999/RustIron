//! D-089 (W543): the steps of a signed `site_restore`, run by the admin
//! helper for the open step of the journal's open attempt. Every value
//! comes from the journal, the enrolled policy, and the fixed layout;
//! nothing comes from a request.
//!
//! The store worker fetches the attempt's capture into the site's own
//! `tmp/clone` as the site, and the fetched tree must have the capture's
//! manifest before anything is replaced. The database step removes every
//! table as the site's database user and imports the fetched dump. The
//! files step puts the live `wp-config.php` and `.maintenance` into the
//! fetched `html`, then exchanges it with the live `html` in one rename.

use std::path::PathBuf;

use rustiron_contracts::approval::{AppDatabase, AppLifecycleAction, Hostname, RestoreScope};
use rustiron_journal::{AppFacts, Capture, CaptureState, RestoreFrom, RestoreStep, SiteRestore};
use std::os::fd::OwnedFd;

use rustix::fs::{self, AtFlags, Mode, OFlags};

use crate::{ExecutorError, TrustAnchor, files, provision, provision::SiteLayout};

/// Everything one restore step needs.
pub(crate) struct RestoreContext<'a> {
    /// The journal's restore.
    pub restore: &'a SiteRestore,
    /// The capture of the open attempt, from the journal.
    pub capture: &'a Capture,
    /// The site's hostname, from its provision.
    pub hostname: &'a Hostname,
    /// The enrolled OLS listener.
    pub address: &'a str,
    /// The enrolled TLS listener, if any.
    pub tls_address: Option<&'a str>,
    /// The trust anchor, for the policy and the store jobs.
    pub anchor: &'a TrustAnchor,
    /// W601 (D-096/P30): present when restoring a P27/EmDash app site.
    pub app: Option<&'a AppFacts>,
    /// W658 (D-102 C2): enrolled database engine when restoring a modern app site.
    pub app_database: Option<AppDatabase>,
}

fn failed(what: &'static str) -> ExecutorError {
    eprintln!(
        "{}",
        serde_json::json!({"scope": "site_restore", "step_failure": what})
    );
    ExecutorError::StepFailed
}

/// Runs one recorded restore step.
pub(crate) fn run_step(
    context: &RestoreContext<'_>,
    step: RestoreStep,
) -> Result<(), ExecutorError> {
    let layout = SiteLayout::derive(&context.restore.site_id);
    let uid = crate::import::site_uid(&layout)?;
    let level = crate::capture::site_level(&layout)?;
    if let Some(facts) = context.app {
        return run_app_step(context, facts, &layout, uid, &level, step);
    }
    match step {
        RestoreStep::Maintenance => crate::site_update::enter_maintenance(&layout, uid),
        RestoreStep::Fetch => fetch_step(context, &layout, uid, &level),
        RestoreStep::Database => database_step(&layout, &level),
        RestoreStep::Files => files_step(&layout, uid, &level),
        RestoreStep::Reopen => {
            clear(&layout, &level)?;
            crate::site_update::remove_maintenance(&layout, uid)
        }
        RestoreStep::Health => crate::site_update::site_answers(
            context.address,
            context.tls_address,
            context.hostname,
            &layout,
        ),
    }
}

/// W601 (D-096/P30): restores a P27/EmDash app site's consistent SQLite
/// databases and `data/` uploads from its own verified capture.
fn run_app_step(
    context: &RestoreContext<'_>,
    facts: &AppFacts,
    layout: &SiteLayout,
    uid: u32,
    level: &str,
    step: RestoreStep,
) -> Result<(), ExecutorError> {
    let has_worker = facts.worker_entrypoint.is_some();
    match step {
        RestoreStep::Maintenance => {
            crate::app_site::run_lifecycle(&layout.account, has_worker, AppLifecycleAction::Stop)
        }
        RestoreStep::Fetch => fetch_step(context, layout, uid, level),
        RestoreStep::Database => {
            let fetched = fetched_root(layout)?;
            let database = context.app_database.unwrap_or(AppDatabase::Sqlite);
            match database {
                AppDatabase::None => Ok(()),
                AppDatabase::Sqlite => {
                    let bundle = fetched
                        .join("tmp")
                        .join(crate::layout::APP_SQLITE_BUNDLE_FILE);
                    let target_data = if context.restore.scope == RestoreScope::Database {
                        layout.root.join("data")
                    } else {
                        fetched.join("data")
                    };
                    crate::app_site::restore_app_sqlite(layout, facts, &bundle, &target_data)
                }
                AppDatabase::Mariadb => {
                    let dump = fetched
                        .join("tmp")
                        .join(crate::layout::APP_MARIADB_DUMP_FILE);
                    restore_app_mariadb(layout, level, &dump)
                }
                AppDatabase::Postgresql18 => {
                    let dump = fetched.join("tmp").join(crate::layout::APP_PG_DUMP_FILE);
                    crate::postgres::restore_database(layout, &dump)
                }
            }
        }
        RestoreStep::Files => app_files_step(layout, uid),
        RestoreStep::Reopen => {
            clear(layout, level)?;
            crate::app_site::run_lifecycle(&layout.account, has_worker, AppLifecycleAction::Start)
        }
        RestoreStep::Health => {
            crate::app_site::probe_loopback_http(&layout.account, facts.port, &facts.health_path)
        }
    }
}

/// Atomically exchanges the verified fetched `data/` tree (with consistent
/// SQLite DBs already placed by `Database`) with the live `<site>/data` tree.
fn app_files_step(layout: &SiteLayout, uid: u32) -> Result<(), ExecutorError> {
    let data = layout.root.join("data");
    let fetched_root = fetched_root(layout)?;
    let fetched_data = fetched_root.join("data");
    let parent = files::open_traversable_directory(&fetched_root, uid)?;
    let _fetched = files::open_child_directory(&parent, "data", uid)?;
    let root = files::open_traversable_directory(&layout.root, 0)?;
    fs::renameat_with(&root, "data", &parent, "data", fs::RenameFlags::EXCHANGE)
        .map_err(|_| failed("app data exchange"))?;
    let new = files::open_child_directory(&root, "data", uid)?;
    fs::fchown(
        &new,
        Some(fs::Uid::from_raw(uid)),
        Some(fs::Gid::from_raw(uid)),
    )
    .map_err(|_| failed("app data owner"))?;
    fs::fchmod(&new, Mode::from_raw_mode(0o750)).map_err(|_| failed("app data mode"))?;
    provision::run(
        "/usr/sbin/restorecon",
        &["-R", "-F", "--", provision::path_str(&data)?],
    )?;
    provision::run(
        "/usr/sbin/restorecon",
        &["-R", "-F", "--", provision::path_str(&fetched_data)?],
    )
}

/// The attempt's capture is the journal's: the signed capture with its
/// signed snapshot and manifest, or the safety capture, succeeded and of
/// this site, written to the enrolled destination as it is now.
pub(crate) fn capture_fits(
    restore: &SiteRestore,
    from: RestoreFrom,
    capture: &Capture,
    destination_digest: &rustiron_contracts::approval::Sha256Digest,
) -> bool {
    let signed = from == RestoreFrom::Signed;
    let complete = restore.scope == RestoreScope::Database
        || capture.manifest.as_ref().is_some_and(|m| !m.truncated);
    &capture.intent.operation_id == restore.capture_of(from)
        && capture.intent.site_id == restore.site_id
        && capture.state == CaptureState::Succeeded
        && capture.snapshot_id.is_some()
        && capture.backup_policy_digest.as_ref() == Some(destination_digest)
        && complete
        && (!signed
            || (capture.snapshot_id.as_deref() == Some(restore.snapshot_id.as_str())
                && capture
                    .manifest
                    .as_ref()
                    .is_some_and(|m| m.sha256 == restore.manifest_sha256.as_str())))
}

/// `<site>/tmp/clone/<site root without />`: the fetched site root.
fn fetched_root(layout: &SiteLayout) -> Result<PathBuf, ExecutorError> {
    Ok(layout
        .root
        .join("tmp")
        .join(crate::layout::CLONE_RESTORE_DIR)
        .join(provision::path_str(&layout.root)?.trim_start_matches('/')))
}

/// The fetched tree and the moved dump leave `tmp`, as the site. Root
/// first relabels the fetched tree, which may hold a former `html` with
/// its content label (W518-F4).
fn clear(layout: &SiteLayout, level: &str) -> Result<(), ExecutorError> {
    let fetched = layout
        .root
        .join("tmp")
        .join(crate::layout::CLONE_RESTORE_DIR);
    if std::fs::symlink_metadata(&fetched).is_ok() {
        provision::run(
            "/usr/sbin/restorecon",
            &["-R", "-F", "--", provision::path_str(&fetched)?],
        )?;
    }
    crate::site_update::clear_fetch(layout, level)
}

/// Fetch: the size check and the restore as the site, then the fetched
/// tree's manifest must be the capture's.
fn fetch_step(
    context: &RestoreContext<'_>,
    layout: &SiteLayout,
    uid: u32,
    level: &str,
) -> Result<(), ExecutorError> {
    let restore = context.restore;
    let attempt = restore.current().ok_or_else(|| failed("attempt"))?;
    let owner = context.anchor.owner_uid;
    let loaded = crate::policy::load(
        &files::open_trusted_directory(&context.anchor.policy_dir, owner)?,
        owner,
    )?;
    let destination = loaded.product_backup.ok_or(ExecutorError::Unavailable)?;
    let site = &restore.site_id;
    if !capture_fits(
        restore,
        attempt.from,
        context.capture,
        &destination.digest(),
    ) || destination.repository_id(site).is_none()
    {
        return Err(failed("capture destination"));
    }
    let snapshot = context
        .capture
        .snapshot_id
        .as_deref()
        .ok_or_else(|| failed("capture snapshot"))?;
    clear(layout, level)?;
    let (size, count) = crate::store_network::site_restore_size(
        context.anchor,
        &destination,
        site,
        level,
        snapshot,
        crate::site_update::store_unit("restore", &layout.account, "size")?,
    )?;
    if !crate::restore::within_ceilings(size, count) {
        return Err(failed("restore size"));
    }
    crate::store_network::site_restore(
        context.anchor,
        &destination,
        site,
        level,
        snapshot,
        crate::site_update::store_unit("restore", &layout.account, "fetch")?,
    )?;
    let tmp = files::open_traversable_directory(&layout.root.join("tmp"), uid)?;
    files::open_child_directory(&tmp, crate::layout::CLONE_RESTORE_DIR, uid)?;
    match context.capture.manifest.as_ref() {
        Some(manifest) if !manifest.truncated => {
            let root = provision::path_str(&layout.root)?;
            let app_db = context
                .app
                .map(|_| context.app_database.unwrap_or(AppDatabase::Sqlite));
            let built = crate::staging_clone::fetched_manifest_for_db(layout, level, root, app_db)?;
            if built.is_some_and(|built| !built.truncated && built.sha256 == manifest.sha256) {
                Ok(())
            } else {
                Err(failed("fetched manifest"))
            }
        }
        // A database restore of a capture whose manifest stopped at its
        // bound: restic checked the snapshot's content; the tree is not
        // compared, and its files are never used.
        _ if restore.scope == RestoreScope::Database => Ok(()),
        _ => Err(failed("manifest")),
    }
}

/// Database: every table of the site's database goes, as the site's
/// database user; root reads the schema empty; the fetched dump is imported.
fn database_step(layout: &SiteLayout, level: &str) -> Result<(), ExecutorError> {
    let tmp = layout.root.join("tmp");
    let mut args = provision::job_properties(
        crate::import::OBSERVE_DOMAIN,
        &layout.account,
        level,
        provision::path_str(&tmp)?,
    );
    args.push("--".to_owned());
    args.push(format!(
        "{}/{}",
        crate::layout::JOB_BIN_DIR,
        crate::manifest::WORKER
    ));
    args.push("site-drop-tables".to_owned());
    args.push(layout.account.clone());
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    provision::run("/usr/bin/systemd-run", &borrowed)?;
    let count = provision::spawn(
        provision::MARIADB,
        &[
            "--batch",
            "--skip-column-names",
            "--socket",
            provision::DB_SOCKET,
        ],
        true,
        Some(schema_count_sql(&layout.account).as_bytes()),
    )?;
    if count.trim() != "0" {
        return Err(failed("tables left"));
    }
    crate::site_update::import_fetched_dump(layout, level)
}

/// W658 (D-102 C2): drops tables in a MariaDB modern app site's database as the
/// site user, verifies an empty schema, and imports the fetched app SQL dump.
fn restore_app_mariadb(
    layout: &SiteLayout,
    level: &str,
    dump_path: &std::path::Path,
) -> Result<(), ExecutorError> {
    let tmp = layout.root.join("tmp");
    let mut args = provision::job_properties(
        crate::import::OBSERVE_DOMAIN,
        &layout.account,
        level,
        provision::path_str(&tmp)?,
    );
    args.push("--".to_owned());
    args.push(format!(
        "{}/{}",
        crate::layout::JOB_BIN_DIR,
        crate::manifest::WORKER
    ));
    args.push("site-drop-tables".to_owned());
    args.push(layout.account.clone());
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    provision::run("/usr/bin/systemd-run", &borrowed)?;
    let count = provision::spawn(
        provision::MARIADB,
        &[
            "--batch",
            "--skip-column-names",
            "--socket",
            provision::DB_SOCKET,
        ],
        true,
        Some(schema_count_sql(&layout.account).as_bytes()),
    )?;
    if count.trim() != "0" {
        return Err(failed("tables left"));
    }
    // W663-E3: import as the site's own database user, as WordPress restores do.
    crate::site_update::import_dump_file(layout, level, dump_path)
}

/// The number of tables and views in the site's own database. The name is
/// the derived account name: lowercase letters, digits, and `_` only.
pub(crate) fn schema_count_sql(account: &str) -> String {
    format!("SELECT count(*) FROM information_schema.tables WHERE table_schema='{account}';\n")
}

/// The largest file the Files step carries into the fetched `html`.
const MAX_CARRIED_BYTES: usize = 64 * 1024;

/// W544-F2: root copies one fixed file of the live `html` into the fetched
/// `html` by descriptor. The unpack domain may not read the site's content
/// files. Only a single-link regular file of the site, at most 64 KiB, is
/// carried; the copy replaces the fetched name with the site's owner and
/// the live file's mode.
fn carry_file(
    live: &OwnedFd,
    fetched: &OwnedFd,
    name: &str,
    uid: u32,
) -> Result<(), ExecutorError> {
    let stat = fs::statat(live, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| failed("carry"))?;
    let bytes = files::read_child(
        live,
        name,
        uid,
        files::Exposure::Readable,
        MAX_CARRIED_BYTES,
    )?;
    match fs::unlinkat(fetched, name, AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => {}
        Err(_) => return Err(failed("carry unlink")),
    }
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let file = fs::openat(fetched, name, flags, Mode::from_raw_mode(0o600))
        .map_err(|_| failed("carry create"))?;
    fs::fchown(
        &file,
        Some(fs::Uid::from_raw(uid)),
        Some(fs::Gid::from_raw(uid)),
    )
    .map_err(|_| failed("carry owner"))?;
    let mut file = std::fs::File::from(file);
    std::io::Write::write_all(&mut file, &bytes).map_err(|_| failed("carry write"))?;
    fs::fchmod(&file, Mode::from_raw_mode(stat.st_mode & 0o777))
        .map_err(|_| failed("carry mode"))?;
    file.sync_all().map_err(|_| failed("carry sync"))
}

/// Files: root carries the live `wp-config.php` and `.maintenance` into the
/// fetched `html`, then exchanges the two `html` folders in one rename,
/// gives the new one the owner, group, mode, and labels of the site's
/// `html`, and relabels the former one for its removal.
fn files_step(layout: &SiteLayout, uid: u32, level: &str) -> Result<(), ExecutorError> {
    let html = layout.root.join("html");
    let fetched_root = fetched_root(layout)?;
    let fetched_html = fetched_root.join("html");
    let parent = files::open_traversable_directory(&fetched_root, uid)?;
    let fetched = files::open_child_directory(&parent, "html", uid)?;
    let live = files::open_traversable_directory(&html, uid)?;
    for name in ["wp-config.php", ".maintenance"] {
        carry_file(&live, &fetched, name, uid)?;
    }
    fs::fsync(&fetched).map_err(|_| failed("carry sync"))?;
    drop((live, fetched));
    let ols = provision::group_id(&provision::read_etc("group")?, provision::OLS_GROUP)
        .ok_or_else(|| failed("group"))?;
    let root = files::open_traversable_directory(&layout.root, 0)?;
    fs::renameat_with(&root, "html", &parent, "html", fs::RenameFlags::EXCHANGE)
        .map_err(|_| failed("exchange"))?;
    let new = files::open_child_directory(&root, "html", uid)?;
    fs::fchown(
        &new,
        Some(fs::Uid::from_raw(uid)),
        Some(fs::Gid::from_raw(ols)),
    )
    .map_err(|_| failed("html owner"))?;
    fs::fchmod(&new, Mode::from_raw_mode(0o750)).map_err(|_| failed("html mode"))?;
    provision::run(
        "/usr/sbin/restorecon",
        &["-R", "-F", "--", provision::path_str(&html)?],
    )?;
    crate::staging_clone::html_labels_hold(layout, uid, level)?;
    provision::run(
        "/usr/sbin/restorecon",
        &["-R", "-F", "--", provision::path_str(&fetched_html)?],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustiron_contracts::{
        Id, Timestamp,
        approval::{Sha256Digest, SiteId, SnapshotId},
    };
    use rustiron_journal::{CaptureIntent, CaptureManifest, RestoreAttempt, RestoreState};

    fn id(value: &str) -> Id {
        Id::try_from(value.to_owned()).unwrap()
    }
    fn digest(c: char) -> Sha256Digest {
        Sha256Digest::try_from(c.to_string().repeat(64)).unwrap()
    }

    fn restore(scope: RestoreScope) -> SiteRestore {
        SiteRestore {
            operation_id: id("restore_1"),
            site_id: SiteId::try_from("blog1".to_owned()).unwrap(),
            scope,
            capture_operation_id: id("cap_old"),
            snapshot_id: SnapshotId::try_from("b".repeat(64)).unwrap(),
            manifest_sha256: digest('1'),
            safety_capture_operation_id: id("cap_safe"),
            attempts: vec![RestoreAttempt {
                from: RestoreFrom::Signed,
                state: rustiron_journal::StepState::Intent,
                steps: Vec::new(),
            }],
            state: RestoreState::Intent,
        }
    }

    /// A succeeded capture of `blog1` to the destination `e`.
    fn capture(operation: &str, snapshot: char, manifest: char, truncated: bool) -> Capture {
        let time = Timestamp::try_from(1000).unwrap();
        Capture {
            intent: CaptureIntent {
                operation_id: id(operation),
                idempotency_key: id("k"),
                grant_id: id("g"),
                nonce: id("n"),
                plan_digest: digest('a'),
                grant_digest: digest('a'),
                host_id: id("h"),
                host_epoch: id("e"),
                site_id: SiteId::try_from("blog1".to_owned()).unwrap(),
                expires_at: time,
            },
            started_at: time,
            state: CaptureState::Succeeded,
            snapshot_id: Some(snapshot.to_string().repeat(64)),
            finished_at: Some(time),
            method: None,
            retention_days: None,
            backup_policy_digest: Some(digest('e')),
            files: None,
            bytes: None,
            manifest: Some(CaptureManifest {
                sha256: manifest.to_string().repeat(64),
                entries: 2,
                regular_bytes: 16,
                truncated,
            }),
            consistency: None,
            unclaimed_snapshot_id: None,
            retention_evidence: None,
            refusal: None,
        }
    }

    #[test]
    fn only_the_attempt_s_own_capture_on_the_current_destination_fits() {
        let files = restore(RestoreScope::FilesAndDatabase);
        let enrolled = digest('e');
        let signed = capture("cap_old", 'b', '1', false);
        assert!(capture_fits(
            &files,
            RestoreFrom::Signed,
            &signed,
            &enrolled
        ));
        // The safety capture fits a safety attempt only; its snapshot and
        // manifest are its own.
        let safety = capture("cap_safe", 'c', '2', false);
        assert!(capture_fits(
            &files,
            RestoreFrom::Safety,
            &safety,
            &enrolled
        ));
        assert!(!capture_fits(
            &files,
            RestoreFrom::Signed,
            &safety,
            &enrolled
        ));
        assert!(!capture_fits(
            &files,
            RestoreFrom::Safety,
            &signed,
            &enrolled
        ));
        // Another destination, snapshot, manifest, site, or state.
        assert!(!capture_fits(
            &files,
            RestoreFrom::Signed,
            &signed,
            &digest('f')
        ));
        let mut wrong = capture("cap_old", 'c', '1', false);
        assert!(!capture_fits(
            &files,
            RestoreFrom::Signed,
            &wrong,
            &enrolled
        ));
        wrong = capture("cap_old", 'b', '3', false);
        assert!(!capture_fits(
            &files,
            RestoreFrom::Signed,
            &wrong,
            &enrolled
        ));
        wrong = signed.clone();
        wrong.intent.site_id = SiteId::try_from("blog2".to_owned()).unwrap();
        assert!(!capture_fits(
            &files,
            RestoreFrom::Signed,
            &wrong,
            &enrolled
        ));
        wrong = signed.clone();
        wrong.state = CaptureState::Failed;
        assert!(!capture_fits(
            &files,
            RestoreFrom::Signed,
            &wrong,
            &enrolled
        ));
        wrong = safety.clone();
        wrong.snapshot_id = None;
        assert!(!capture_fits(
            &files,
            RestoreFrom::Safety,
            &wrong,
            &enrolled
        ));
        // A truncated manifest fits a database restore only.
        let truncated = capture("cap_safe", 'c', '2', true);
        assert!(!capture_fits(
            &files,
            RestoreFrom::Safety,
            &truncated,
            &enrolled
        ));
        let database = restore(RestoreScope::Database);
        assert!(capture_fits(
            &database,
            RestoreFrom::Safety,
            &truncated,
            &enrolled
        ));
    }

    /// W544-F2: only a single-link regular file of the site, within the
    /// bound, is carried; the copy replaces the fetched name and keeps the
    /// live mode.
    #[test]
    fn only_the_site_s_own_small_regular_file_is_carried() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let base = std::env::temp_dir().join(format!("ri-w544-carry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (live_path, fetched_path) = (base.join("live"), base.join("fetched"));
        std::fs::create_dir_all(&live_path).unwrap();
        std::fs::create_dir_all(&fetched_path).unwrap();
        let uid = rustix::process::getuid().as_raw();
        let open = |path: &std::path::Path| {
            fs::open(path, OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty()).unwrap()
        };
        let (live, fetched) = (open(&live_path), open(&fetched_path));
        std::fs::write(live_path.join("wp-config.php"), b"live").unwrap();
        std::fs::set_permissions(
            live_path.join("wp-config.php"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        std::fs::write(fetched_path.join("wp-config.php"), b"captured").unwrap();
        carry_file(&live, &fetched, "wp-config.php", uid).unwrap();
        assert_eq!(
            std::fs::read(fetched_path.join("wp-config.php")).unwrap(),
            b"live"
        );
        let mode = std::fs::metadata(fetched_path.join("wp-config.php"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        // A link, a second hard link, another owner's uid, a group-writable
        // file, or a file over the bound is not carried.
        symlink("/etc/passwd", live_path.join("link")).unwrap();
        assert!(carry_file(&live, &fetched, "link", uid).is_err());
        std::fs::hard_link(live_path.join("wp-config.php"), live_path.join("twin")).unwrap();
        assert!(carry_file(&live, &fetched, "twin", uid).is_err());
        std::fs::remove_file(live_path.join("twin")).unwrap();
        assert!(carry_file(&live, &fetched, "wp-config.php", uid + 1).is_err());
        std::fs::write(live_path.join("open"), b"x").unwrap();
        std::fs::set_permissions(
            live_path.join("open"),
            std::fs::Permissions::from_mode(0o664),
        )
        .unwrap();
        assert!(carry_file(&live, &fetched, "open", uid).is_err());
        std::fs::write(live_path.join("big"), vec![b'x'; MAX_CARRIED_BYTES + 1]).unwrap();
        assert!(carry_file(&live, &fetched, "big", uid).is_err());
        assert!(carry_file(&live, &fetched, "absent", uid).is_err());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn the_schema_count_names_only_the_derived_account() {
        assert_eq!(
            schema_count_sql("rs_blog1"),
            "SELECT count(*) FROM information_schema.tables WHERE table_schema='rs_blog1';\n"
        );
    }
}
