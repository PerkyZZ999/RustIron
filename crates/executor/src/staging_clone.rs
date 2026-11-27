//! D-078 (W499): the clone steps of a staging clone, inside the open Recipe
//! step of the target's provision.
//!
//! The target provision has its own account, level, quota, database and
//! credentials before these steps run. Root never runs or walks restored
//! content: each step is a fixed unit as the target account at the target's
//! level, and root reads only its bounded output, the census of labels and
//! the files that it writes itself.
//!
//! 1. Fetch: the product store worker restores the signed snapshot into the
//!    target's `tmp/clone` with the source site's fetch key pair.
//! 2. Observe: an unprivileged walk lists the fetched tree in the capture
//!    manifest format; root rebuilds the canonical manifest with the capture
//!    builder and requires the signed digest, untruncated.
//! 3. Files: an unpack job copies the source `html` into the target's empty
//!    `html`; the two tree reports must match and every entry must carry
//!    the target's content label. The fetched `html` is then removed.
//! 4. Database: the fetched dump moves to `tmp/import` and is imported as
//!    the target's database user under the D-034 size watch.
//! 5. Config: the restored `wp-config.php` must be the native template with
//!    eight salts. It is replaced by a new one with fresh salts, the identity
//!    marker is rewritten for the target, the source hostname is rewritten
//!    in the target's database, and the fetched leftovers are removed.

use std::path::Path;

use rustiron_contracts::approval::{Hostname, ProductBackupPolicy, SiteId};
use rustiron_journal::{CloneFacts, CloneStep};
use rustix::fs::{self, AtFlags, FileType};

use crate::{
    ExecutorError, TrustAnchor, files,
    import::{self, path_text, site_uid},
    provision::{self, SiteLayout},
};

/// The dump's folder for the worker's `site-import` action.
const IMPORT_DIR: &str = "import";
/// Largest restored `wp-config.php` read by root.
const MAX_CONFIG_BYTES: usize = 64 * 1024;
/// Bound on the Observe walk's output: the capture manifest's.
const MAX_TREE_OUTPUT_BYTES: usize = crate::manifest::format::MAX_STREAM_BYTES + 4096;

/// Everything one clone step needs, from the journal, the trust anchor and
/// the fixed layout. Nothing comes from a request.
pub(crate) struct CloneStepContext<'a> {
    pub anchor: &'a TrustAnchor,
    /// The target site.
    pub layout: &'a SiteLayout,
    /// The target hostname.
    pub hostname: &'a Hostname,
    /// The signed source facts.
    pub facts: &'a CloneFacts,
}

/// Runs one clone step.
pub(crate) fn run_clone_step(
    step: CloneStep,
    context: &CloneStepContext<'_>,
) -> Result<(), ExecutorError> {
    match step {
        CloneStep::Fetch => fetch_step(context),
        CloneStep::Observe => observe_step(context),
        CloneStep::Files => files_step(context),
        CloneStep::Database => database_step(context),
        CloneStep::Config => config_step(context),
    }
}

/// The source site's captured root (`<SITES_ROOT>/<account>`), as the
/// capture recorded it.
fn source_root(source: &SiteId) -> String {
    format!("{}/{}", crate::layout::SITES_ROOT, source.account_name())
}

/// `<target>/tmp/clone/<source root without />`: the fetched site root.
fn fetched_root(context: &CloneStepContext<'_>) -> std::path::PathBuf {
    context
        .layout
        .root
        .join("tmp")
        .join(crate::layout::CLONE_RESTORE_DIR)
        .join(source_root(&context.facts.source_site_id).trim_start_matches('/'))
}

/// The enrolled destination, bound again to the signed projection digest
/// and the source's repository pin.
fn bound_destination(context: &CloneStepContext<'_>) -> Result<ProductBackupPolicy, ExecutorError> {
    let owner = context.anchor.owner_uid;
    let directory = files::open_trusted_directory(&context.anchor.policy_dir, owner)?;
    let loaded = crate::policy::load(&directory, owner)?;
    let destination = loaded.product_backup.ok_or(ExecutorError::Unavailable)?;
    let facts = context.facts;
    if destination.digest() != facts.destination_policy_digest
        || destination.repository_id(&facts.source_site_id) != Some(&facts.repository_id)
    {
        return Err(ExecutorError::PreconditionChanged);
    }
    Ok(destination)
}

fn unit(layout: &SiteLayout, step: &str) -> Result<String, ExecutorError> {
    let mut random = [0_u8; 4];
    rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty())
        .map_err(|_| ExecutorError::Unavailable)?;
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!("rustiron-clone-{}-{step}-{suffix}", layout.account))
}

/// Fetch: the size check, then the restore, both as the target.
fn fetch_step(context: &CloneStepContext<'_>) -> Result<(), ExecutorError> {
    let layout = context.layout;
    let destination = bound_destination(context)?;
    let level = crate::capture::site_level(layout)?;
    let snapshot = context.facts.snapshot_id.as_str();
    let source = &context.facts.source_site_id;
    let (size, count) = crate::store_network::clone_restore_size(
        context.anchor,
        &destination,
        source,
        &layout.account,
        &level,
        snapshot,
        unit(layout, "size")?,
    )?;
    if !crate::restore::within_ceilings(size, count) {
        return Err(ExecutorError::StepFailed);
    }
    crate::store_network::clone_restore(
        context.anchor,
        &destination,
        source,
        &layout.account,
        &level,
        snapshot,
        unit(layout, "fetch")?,
    )?;
    let uid = site_uid(layout)?;
    let tmp = files::open_traversable_directory(&layout.root.join("tmp"), uid)?;
    files::open_child_directory(&tmp, crate::layout::CLONE_RESTORE_DIR, uid).map(drop)
}

/// The `systemd-run` arguments of the Observe walk: the target account at
/// its level in the capture domain, with no network, credentials or
/// writable path but its own `tmp`, and stdout to a root-owned file.
fn tree_arguments(account: &str, level: &str, tmp: &str, output: &str) -> Vec<String> {
    let mut args = provision::job_properties(import::OBSERVE_DOMAIN, account, level, tmp);
    for property in [
        format!(
            "InaccessiblePaths=-{} -/run/credentials",
            crate::layout::JOB_CREDENTIALS_DIR
        ),
        format!("StandardOutput=truncate:{output}"),
        "StandardError=journal".to_owned(),
        format!("LimitFSIZE={MAX_TREE_OUTPUT_BYTES}"),
    ] {
        args.push("--property".to_owned());
        args.push(property);
    }
    args.extend([
        "--".to_owned(),
        format!("{}/{}", crate::layout::JOB_BIN_DIR, crate::manifest::WORKER),
        "clone-tree".to_owned(),
        account.to_owned(),
    ]);
    args
}

/// Observe: the fetched tree's manifest is the signed one.
fn observe_step(context: &CloneStepContext<'_>) -> Result<(), ExecutorError> {
    let layout = context.layout;
    let level = crate::capture::site_level(layout)?;
    let root = source_root(&context.facts.source_site_id);
    let built = fetched_manifest(layout, &level, &root)?;
    if manifest_matches(built.as_ref(), context.facts) {
        Ok(())
    } else {
        Err(ExecutorError::StepFailed)
    }
}

/// The manifest of `layout`'s own fetched tree `tmp/clone`, walked by the
/// worker as the site with no network, as if captured at `root`. W543: a
/// restore walks its site's own fetched capture with it.
pub(crate) fn fetched_manifest(
    layout: &SiteLayout,
    level: &str,
    root: &str,
) -> Result<Option<crate::manifest::Built>, ExecutorError> {
    fetched_manifest_for(layout, level, root, false)
}

/// W601 (D-096/P30): as [`fetched_manifest`], validating `data/` +
/// `rustiron-app-sqlite.tar` when `is_app` is `true`.
pub(crate) fn fetched_manifest_for(
    layout: &SiteLayout,
    level: &str,
    root: &str,
    is_app: bool,
) -> Result<Option<crate::manifest::Built>, ExecutorError> {
    let app_db = is_app.then_some(rustiron_contracts::approval::AppDatabase::Sqlite);
    fetched_manifest_for_db(layout, level, root, app_db)
}

/// W658 (D-102 C2): as [`fetched_manifest_for`], selecting the exact app dump
/// file matching the app's enrolled database engine.
pub(crate) fn fetched_manifest_for_db(
    layout: &SiteLayout,
    level: &str,
    root: &str,
    app_db: Option<rustiron_contracts::approval::AppDatabase>,
) -> Result<Option<crate::manifest::Built>, ExecutorError> {
    let name = format!("{}.tree", unit(layout, "tree")?);
    let output = format!("{}/{name}", crate::capture::OUTPUT_DIR);
    let tmp = layout.root.join("tmp");
    let args = tree_arguments(&layout.account, level, path_text(&tmp)?, &output);
    crate::capture::ensure_output_dir()?;
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let ran = provision::run("/usr/bin/systemd-run", &borrowed);
    let directory = files::open_traversable_directory(Path::new(crate::capture::OUTPUT_DIR), 0)?;
    let bytes = files::read_child(
        &directory,
        &name,
        0,
        files::Exposure::Readable,
        MAX_TREE_OUTPUT_BYTES,
    );
    let _ = fs::unlinkat(&directory, name.as_str(), AtFlags::empty());
    ran?;
    let (subdir, dump) = match app_db {
        Some(db) => ("data", crate::app_site::app_db_dump_path(root, db)),
        None => (
            "html",
            format!("{root}/tmp/{}", crate::layout::CAPTURE_DUMP_FILE),
        ),
    };
    Ok(crate::manifest::from_worker_for(
        &bytes?, root, subdir, &dump,
    ))
}

/// The rebuilt manifest is complete and has the signed digest.
fn manifest_matches(built: Option<&crate::manifest::Built>, facts: &CloneFacts) -> bool {
    built.is_some_and(|built| !built.truncated && built.sha256 == facts.manifest_sha256.as_str())
}

/// The `--tree` report of the export worker for `folder`, run as the target
/// in the capture domain with only `tmp` writable.
fn tree_summary(
    layout: &SiteLayout,
    level: &str,
    step: &str,
    folder: &Path,
) -> Result<rustiron_contracts::migration::FileSummary, ExecutorError> {
    let name = format!("{}.out", unit(layout, step)?);
    let output = format!("{}/{name}", crate::capture::OUTPUT_DIR);
    let limit = rustiron_contracts::migration::MAX_MIGRATION_INVENTORY_BYTES;
    let tmp = layout.root.join("tmp");
    let mut args = provision::job_properties(
        import::OBSERVE_DOMAIN,
        &layout.account,
        level,
        path_text(&tmp)?,
    );
    for property in [
        format!("StandardOutput=truncate:{output}"),
        "StandardError=journal".to_owned(),
        format!("LimitFSIZE={limit}"),
    ] {
        args.push("--property".to_owned());
        args.push(property);
    }
    args.push("--".to_owned());
    args.push(crate::layout::JOB_MIGRATION_INVENTORY.to_owned());
    args.push("--tree".to_owned());
    args.push(path_text(folder)?.to_owned());
    crate::capture::ensure_output_dir()?;
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let ran = provision::run("/usr/bin/systemd-run", &borrowed);
    let directory = files::open_traversable_directory(Path::new(crate::capture::OUTPUT_DIR), 0)?;
    let bytes = files::read_child(&directory, &name, 0, files::Exposure::Readable, limit);
    let _ = fs::unlinkat(&directory, name.as_str(), AtFlags::empty());
    ran?;
    let report = rustiron_contracts::migration::decode_tree_report(&bytes?)
        .map_err(|_| ExecutorError::StepFailed)?;
    report.files.ok_or(ExecutorError::StepFailed)
}

/// One unpack job as the target with `writable` its one writable path.
pub(crate) fn unpack_job(
    layout: &SiteLayout,
    level: &str,
    writable: &Path,
    command: &[&str],
) -> Result<(), ExecutorError> {
    let mut args = provision::unpack_properties(&layout.account, level, path_text(writable)?);
    args.push("--".to_owned());
    args.extend(command.iter().map(|part| (*part).to_owned()));
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    provision::run("/usr/bin/systemd-run", &borrowed)
}

/// The census of `html`: owned files, all the target's, all labelled with
/// the target's content label.
pub(crate) fn html_labels_hold(
    layout: &SiteLayout,
    uid: u32,
    level: &str,
) -> Result<(), ExecutorError> {
    let html = files::open_traversable_directory(&layout.root.join("html"), uid)?;
    let want = format!("system_u:object_r:httpd_sys_content_t:{level}");
    let census = crate::census::census_labelled(
        &html,
        uid,
        want.as_bytes(),
        &crate::census::label_of,
        import::TREE_BOUNDS,
    )?;
    if census.owned_files == 0 || census.foreign != 0 || census.mislabelled != 0 {
        return Err(ExecutorError::StepFailed);
    }
    Ok(())
}

/// Files: the source `html` into the target's empty `html`.
fn files_step(context: &CloneStepContext<'_>) -> Result<(), ExecutorError> {
    let layout = context.layout;
    let uid = site_uid(layout)?;
    let level = crate::capture::site_level(layout)?;
    let html = layout.root.join("html");
    let html_dir = files::open_traversable_directory(&html, uid)?;
    if fs::Dir::read_from(&html_dir)
        .map_err(|_| ExecutorError::StepFailed)?
        .filter_map(Result::ok)
        .any(|entry| !matches!(entry.file_name().to_bytes(), b"." | b".."))
    {
        return Err(ExecutorError::Collision);
    }
    let fetched = fetched_root(context).join("html");
    let source = tree_summary(layout, &level, "files-source", &fetched)?;
    unpack_job(
        layout,
        &level,
        &html,
        &[
            "/usr/bin/cp",
            "--recursive",
            "--no-dereference",
            "--preserve=mode,timestamps",
            // W475: no reflink ioctl on the site's content.
            "--reflink=never",
            "--no-target-directory",
            "--",
            path_text(&fetched)?,
            path_text(&html)?,
        ],
    )?;
    html_labels_hold(layout, uid, &level)?;
    let copied = tree_summary(layout, &level, "files-html", &html)?;
    if source != copied || copied.unsafe_entries != 0 {
        return Err(ExecutorError::StepFailed);
    }
    // The fetched copy of `html` leaves the target's quota.
    let tmp = layout.root.join("tmp");
    unpack_job(
        layout,
        &level,
        &tmp,
        &[
            "/usr/bin/rm",
            "-rf",
            "--one-file-system",
            "--",
            path_text(&fetched)?,
        ],
    )
}

/// Database: the fetched dump, moved to `tmp/import`, into the target's
/// own database as its own database user.
fn database_step(context: &CloneStepContext<'_>) -> Result<(), ExecutorError> {
    let layout = context.layout;
    let uid = site_uid(layout)?;
    let level = crate::capture::site_level(layout)?;
    let tmp_path = layout.root.join("tmp");
    let import_path = tmp_path.join(IMPORT_DIR);
    let dump = fetched_root(context)
        .join("tmp")
        .join(crate::layout::CAPTURE_DUMP_FILE);
    unpack_job(
        layout,
        &level,
        &tmp_path,
        &[
            "/usr/bin/mkdir",
            "--mode=0700",
            "--",
            path_text(&import_path)?,
        ],
    )?;
    unpack_job(
        layout,
        &level,
        &tmp_path,
        &[
            "/usr/bin/mv",
            "--no-clobber",
            "--no-target-directory",
            "--",
            path_text(&dump)?,
            path_text(&import_path.join(crate::layout::CAPTURE_DUMP_FILE))?,
        ],
    )?;
    let tmp = files::open_traversable_directory(&tmp_path, uid)?;
    let folder = files::open_child_directory(&tmp, IMPORT_DIR, uid)?;
    let stat = fs::statat(
        &folder,
        crate::layout::CAPTURE_DUMP_FILE,
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|_| ExecutorError::StepFailed)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_nlink != 1
        || stat.st_uid != uid
    {
        return Err(ExecutorError::StepFailed);
    }
    let bytes = u64::try_from(stat.st_size).map_err(|_| ExecutorError::StepFailed)?;
    if bytes == 0 {
        return Err(ExecutorError::StepFailed);
    }
    import::import_dump(layout, bytes)
}

/// Whether `text` is the native recipe's `wp-config.php`: the template with
/// eight salt lines of the fixed shape in place of its salt marker.
pub(crate) fn native_config(text: &str) -> bool {
    let Some((head, tail)) = provision::WP_CONFIG_TEMPLATE.split_once("@SALTS@\n") else {
        return false;
    };
    let Some(salts) = text
        .strip_prefix(head)
        .and_then(|rest| rest.strip_suffix(tail))
    else {
        return false;
    };
    let lines: Vec<&str> = salts.lines().collect();
    salts.ends_with('\n')
        && lines.len() == provision::SALT_NAMES.len()
        && lines.iter().zip(provision::SALT_NAMES).all(|(line, name)| {
            line.strip_prefix(&format!("define('{name}', '"))
                .and_then(|rest| rest.strip_suffix("');"))
                .is_some_and(|value| {
                    value.len() == 64
                        && value
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
        })
}

/// Config: the target's own configuration, identity and URLs.
fn config_step(context: &CloneStepContext<'_>) -> Result<(), ExecutorError> {
    let layout = context.layout;
    let uid = site_uid(layout)?;
    let level = crate::capture::site_level(layout)?;
    let html = files::open_traversable_directory(&layout.root.join("html"), uid)?;
    let restored = files::read_child(
        &html,
        "wp-config.php",
        uid,
        files::Exposure::Readable,
        MAX_CONFIG_BYTES,
    )
    .map_err(|_| ExecutorError::StepFailed)?;
    if !std::str::from_utf8(&restored).is_ok_and(native_config) {
        return Err(ExecutorError::StepFailed);
    }
    // The source's salts and identity marker leave the clone.
    for name in ["wp-config.php", "rustiron-site.txt"] {
        match fs::statat(&html, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile => {
                fs::unlinkat(&html, name, AtFlags::empty())
                    .map_err(|_| ExecutorError::StepFailed)?;
            }
            Err(rustix::io::Errno::NOENT) if name == "rustiron-site.txt" => {}
            _ => return Err(ExecutorError::StepFailed),
        }
    }
    fs::fsync(&html).map_err(|_| ExecutorError::Unavailable)?;
    provision::write_wp_config(layout)?;
    provision::write_site_marker(layout)?;
    crate::certificate::prepare_webroot(&layout.account)?;
    import::rewrite_hostname(layout, &context.facts.source_hostname, context.hostname)?;
    html_labels_hold(layout, uid, &level)?;
    remove_fetched(layout, uid, &level)
}

/// The fetched leftovers in `tmp` (the clone tree and the moved dump), by
/// an unpack job as the target. Root then checks that both names are gone.
/// Absent names are fine, so a repeat removes nothing more.
fn remove_fetched(layout: &SiteLayout, uid: u32, level: &str) -> Result<(), ExecutorError> {
    let tmp_path = layout.root.join("tmp");
    unpack_job(
        layout,
        level,
        &tmp_path,
        &[
            "/usr/bin/rm",
            "-rf",
            "--one-file-system",
            "--",
            path_text(&tmp_path.join(crate::layout::CLONE_RESTORE_DIR))?,
            path_text(&tmp_path.join(IMPORT_DIR))?,
        ],
    )?;
    let tmp = files::open_traversable_directory(&tmp_path, uid)?;
    for name in [crate::layout::CLONE_RESTORE_DIR, IMPORT_DIR] {
        match fs::statat(&tmp, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => {}
            _ => return Err(ExecutorError::StepFailed),
        }
    }
    Ok(())
}

/// W501 (D-078): the scrub of a clone quarantined by a failed clone step.
/// It removes the fetched tree and the moved dump, and the `wp-config.php`
/// in `html`, which holds the source's salts until the Config step replaces
/// it. The copied `html` and the imported database stay with the
/// quarantined target, as an import's do (D-057).
///
/// W501-F1: the unpack domain cannot remove a name in `html`, so root
/// unlinks that one fixed regular file through the target-owned `html`
/// descriptor, as the Config step does.
pub(crate) fn scrub_site(layout: &SiteLayout) -> Result<(), ExecutorError> {
    let uid = site_uid(layout)?;
    let level = crate::capture::site_level(layout)?;
    remove_fetched(layout, uid, &level)?;
    let html = files::open_traversable_directory(&layout.root.join("html"), uid)?;
    match fs::statat(&html, "wp-config.php", AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile => {}
        _ => return Err(ExecutorError::StepFailed),
    }
    fs::unlinkat(&html, "wp-config.php", AtFlags::empty())
        .map_err(|_| ExecutorError::StepFailed)?;
    fs::fsync(&html).map_err(|_| ExecutorError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native() -> String {
        let mut salts = String::new();
        for name in provision::SALT_NAMES {
            salts.push_str(&format!("define('{name}', '{}');\n", "a1".repeat(32)));
        }
        provision::WP_CONFIG_TEMPLATE.replace("@SALTS@\n", &salts)
    }

    #[test]
    fn only_the_native_template_with_eight_fixed_salts_is_a_native_config() {
        assert!(native_config(&native()));
        for changed in [
            native().replace("DISALLOW_FILE_MODS', true", "DISALLOW_FILE_MODS', false"),
            native().replace("define('NONCE_SALT'", "define('OTHER_SALT'"),
            native().replacen(&"a1".repeat(32), &"A1".repeat(32), 1),
            native().replacen(&"a1".repeat(32), &"a1".repeat(31), 1),
            format!("{}\ndefine('WP_HOME', 'http://x');\n", native()),
            native().replace("require_once", "include"),
            String::new(),
            provision::WP_CONFIG_TEMPLATE.to_owned(),
        ] {
            assert!(!native_config(&changed), "{changed}");
        }
    }

    #[test]
    fn the_observe_walk_runs_as_the_target_with_no_network_or_credentials() {
        let args = tree_arguments("rs_stage9", "s0:c207", "/srv/sites/rs_stage9/tmp", "/run/o");
        let properties: Vec<&str> = args
            .windows(2)
            .filter(|pair| pair[0] == "--property")
            .map(|pair| pair[1].as_str())
            .collect();
        for expected in [
            "User=rs_stage9",
            "SELinuxContext=system_u:system_r:rustiron_capture_t:s0:c207",
            "ReadWritePaths=/srv/sites/rs_stage9/tmp",
            "PrivateNetwork=yes",
            "StandardOutput=truncate:/run/o",
        ] {
            assert!(properties.contains(&expected), "{expected}");
        }
        assert!(
            properties
                .iter()
                .any(|p| p.starts_with("InaccessiblePaths="))
        );
        let separator = args.iter().position(|arg| arg == "--").unwrap();
        assert_eq!(
            args[separator + 1..],
            [
                format!("{}/capture-manifest", crate::layout::JOB_BIN_DIR),
                "clone-tree".to_owned(),
                "rs_stage9".to_owned()
            ]
        );
    }

    #[test]
    fn only_a_complete_manifest_of_the_signed_digest_matches() {
        let facts = CloneFacts {
            source_site_id: "blog9".to_owned().try_into().unwrap(),
            source_hostname: "blog9.example.test".to_owned().try_into().unwrap(),
            capture_operation_id: "op_capture".to_owned().try_into().unwrap(),
            snapshot_id: "b".repeat(64).try_into().unwrap(),
            manifest_sha256: "c".repeat(64).try_into().unwrap(),
            destination_policy_digest: "d".repeat(64).try_into().unwrap(),
            repository_id: "e".repeat(64).try_into().unwrap(),
        };
        let built = |sha256: &str, truncated| crate::manifest::Built {
            sha256: sha256.to_owned(),
            entries: 1,
            regular_bytes: 0,
            truncated,
            bytes: Vec::new(),
        };
        assert!(manifest_matches(
            Some(&built(&"c".repeat(64), false)),
            &facts
        ));
        assert!(!manifest_matches(
            Some(&built(&"c".repeat(64), true)),
            &facts
        ));
        assert!(!manifest_matches(
            Some(&built(&"f".repeat(64), false)),
            &facts
        ));
        assert!(!manifest_matches(None, &facts));
        assert_eq!(
            fetched_root(&CloneStepContext {
                anchor: &crate::TrustAnchor::lab(),
                layout: &SiteLayout::derive(&"stage9".to_owned().try_into().unwrap()),
                hostname: &"stage9.example.test".to_owned().try_into().unwrap(),
                facts: &facts,
            }),
            Path::new(&format!(
                "{}/rs_stage9/tmp/clone{}/rs_blog9",
                crate::layout::SITES_ROOT,
                crate::layout::SITES_ROOT
            ))
        );
    }
}
