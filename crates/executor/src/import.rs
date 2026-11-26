//! W443 (D-053): the Intake step of a site import.
//!
//! The operator copies the export to a fixed root-owned intake folder,
//! `<intake>/<site_id>/export.tar.gz`. The path is derived from the admitted
//! site ID, never from a request. The archive holds secrets of the source
//! host (password hashes, a TLS key), so only its owner may read it.
//! Intake checks the file and its SHA-256 against the signed plan and
//! returns the open descriptor, rewound, for the Extract step. It reads the
//! archive bytes only to hash them; it never parses them.
//!
//! W446: [`run_import_step`] runs the open import step of a journaled import
//! provision. Intake, Extract, and Observe follow the W444 step mechanisms.
//! Files, Database, and Config are not implemented yet and fail closed, so
//! an import stops quarantined after Observe.

use std::os::fd::OwnedFd;
use std::path::Path;

use rustiron_contracts::approval::{Hostname, Sha256Digest, SiteId};
use rustiron_contracts::migration::{ExportObservation, ExportStatus};
use rustiron_journal::ImportFacts;
use rustix::fs::{self, AtFlags, Dir, FileType, Mode, OFlags, SeekFrom};
use rustix::io::Errno;
use sha2::{Digest, Sha256};

use crate::provision::{self, SiteLayout};
use crate::{ExecutorError, files};
use rustiron_journal::ImportStep;

/// The one archive name in a site's intake folder.
pub(crate) const ARCHIVE: &str = "export.tar.gz";

const ARCHIVE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NOCTTY)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);

/// Opens and checks the site's intake archive.
///
/// The intake folder and the site folder belong to `owner` with no group or
/// other access. The archive is a single-link regular file of `owner` with
/// no group or other access, at most `max_bytes`, unchanged while it is
/// hashed, and its SHA-256 equals `expected`.
pub(crate) fn intake(
    intake_dir: &Path,
    owner: u32,
    site: &SiteId,
    expected: &Sha256Digest,
    max_bytes: u64,
) -> Result<OwnedFd, ExecutorError> {
    let deny = ExecutorError::AccessDenied;
    let intake = files::open_trusted_directory(intake_dir, owner)?;
    let folder = files::open_child_directory(&intake, site.as_str(), owner)?;
    if fs::fstat(&folder).map_err(|_| deny)?.st_mode & 0o077 != 0 {
        return Err(deny);
    }
    let archive = match fs::openat(&folder, ARCHIVE, ARCHIVE_FLAGS, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Err(ExecutorError::PreconditionChanged),
        Err(_) => return Err(deny),
    };
    let before = fs::fstat(&archive).map_err(|_| deny)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != owner
        || before.st_nlink != 1
        || before.st_mode & 0o077 != 0
    {
        return Err(deny);
    }
    let size = u64::try_from(before.st_size).map_err(|_| deny)?;
    if size == 0 || size > max_bytes {
        return Err(ExecutorError::PreconditionChanged);
    }
    let digest = hash(&archive)?;
    let after = fs::fstat(&archive).map_err(|_| deny)?;
    if (
        after.st_size,
        after.st_mtime,
        after.st_mtime_nsec,
        after.st_ino,
    ) != (
        before.st_size,
        before.st_mtime,
        before.st_mtime_nsec,
        before.st_ino,
    ) {
        return Err(ExecutorError::PreconditionChanged);
    }
    if &Sha256Digest::from_bytes(digest) != expected {
        return Err(ExecutorError::PreconditionChanged);
    }
    fs::seek(&archive, SeekFrom::Start(0)).map_err(|_| ExecutorError::Unavailable)?;
    Ok(archive)
}

/// Largest intake archive. The site quota bounds the copy and the
/// extracted tree as well, because both belong to the site.
pub(crate) const MAX_ARCHIVE_BYTES: u64 = 8 << 30;
/// The extraction folder in the site's `tmp`.
const IMPORT_DIR: &str = "import";
/// The observe job's worker runs in the capture domain, as the restore
/// inventory worker does, at the site's level.
pub(crate) const OBSERVE_DOMAIN: &str = "system_u:system_r:rustiron_capture_t";

/// Everything one import step needs, from the journal and fixed layout.
pub(crate) struct ImportStepContext<'a> {
    pub layout: &'a SiteLayout,
    pub site_id: &'a SiteId,
    pub hostname: &'a Hostname,
    pub facts: &'a ImportFacts,
    /// Owner of the intake folder: the executor's trust anchor owner.
    pub owner: u32,
}

/// Runs one import step. Nothing here comes from a request.
pub(crate) fn run_import_step(
    step: ImportStep,
    context: &ImportStepContext<'_>,
) -> Result<(), ExecutorError> {
    match step {
        ImportStep::Intake => intake_step(context),
        ImportStep::Extract => extract_step(context),
        ImportStep::Observe => observe_step(context),
        ImportStep::Files => files_step(context),
        ImportStep::Database => database_step(context),
        ImportStep::Config => config_step(context),
    }
}

pub(crate) fn site_uid(layout: &SiteLayout) -> Result<u32, ExecutorError> {
    let passwd = provision::read_etc("passwd")?;
    provision::account_uid(&passwd, &layout.account).ok_or(ExecutorError::StepFailed)
}

pub(crate) fn path_text(path: &Path) -> Result<&str, ExecutorError> {
    path.to_str().ok_or(ExecutorError::StepFailed)
}

fn intake_step(context: &ImportStepContext<'_>) -> Result<(), ExecutorError> {
    let archive = intake(
        Path::new(crate::layout::MIGRATION_INTAKE_DIR),
        context.owner,
        context.site_id,
        &context.facts.archive_sha256,
        MAX_ARCHIVE_BYTES,
    )?;
    let uid = site_uid(context.layout)?;
    let tmp_path = context.layout.root.join("tmp");
    let tmp = files::open_traversable_directory(&tmp_path, uid)?;
    copy_archive(
        &archive,
        &tmp,
        uid,
        &context.facts.archive_sha256,
        MAX_ARCHIVE_BYTES,
    )?;
    let copy = tmp_path.join(COPY);
    provision::run("/usr/sbin/restorecon", &["-F", "--", path_text(&copy)?])
}

/// Creates `tmp/import` for the site with the label of `tmp`, then extracts
/// the copy into it in the unpack job.
fn extract_step(context: &ImportStepContext<'_>) -> Result<(), ExecutorError> {
    let layout = context.layout;
    let uid = site_uid(layout)?;
    let level = crate::capture::site_level(layout)?;
    let tmp_path = layout.root.join("tmp");
    let tmp = files::open_traversable_directory(&tmp_path, uid)?;
    let mut label = vec![0; 256];
    let length = fs::fgetxattr(&tmp, "security.selinux", &mut label)
        .map_err(|_| ExecutorError::StepFailed)?;
    label.truncate(length);
    fs::mkdirat(&tmp, IMPORT_DIR, Mode::from_raw_mode(0o700))
        .map_err(|_| ExecutorError::StepFailed)?;
    let import = fs::openat(
        &tmp,
        IMPORT_DIR,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ExecutorError::StepFailed)?;
    fs::fchown(
        &import,
        Some(rustix::fs::Uid::from_raw(uid)),
        Some(rustix::fs::Gid::from_raw(uid)),
    )
    .map_err(|_| ExecutorError::StepFailed)?;
    fs::fsetxattr(&import, "security.selinux", &label, fs::XattrFlags::empty())
        .map_err(|_| ExecutorError::StepFailed)?;
    let import_path = tmp_path.join(IMPORT_DIR);
    let import_text = path_text(&import_path)?;
    let mut args = provision::unpack_properties(&layout.account, &level, import_text);
    args.extend(["--", "/usr/bin/tar", "--extract", "--gzip"].map(String::from));
    args.push(format!("--file={}", path_text(&tmp_path.join(COPY))?));
    args.push(format!("--directory={import_text}"));
    args.extend(
        [
            "--no-same-owner",
            "--numeric-owner",
            "--no-same-permissions",
            "--keep-old-files",
        ]
        .map(String::from),
    );
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    provision::run("/usr/bin/systemd-run", &borrowed)
}

/// Runs the export worker on `tmp/import` as the site, reads its report
/// from a root-owned output file, and compares it with the signed facts.
fn observe_step(context: &ImportStepContext<'_>) -> Result<(), ExecutorError> {
    let import_path = context.layout.root.join("tmp").join(IMPORT_DIR);
    let bytes = run_worker(context, "observe", &[path_text(&import_path)?])?;
    let observation = rustiron_contracts::migration::decode_export_observation(&bytes)
        .map_err(|_| ExecutorError::StepFailed)?;
    // D-070: the export names the source site's hostname.
    let source = context.facts.source_or(context.hostname);
    match observation_mismatch(&observation, context.facts, source) {
        None => Ok(()),
        Some(_) => Err(ExecutorError::StepFailed),
    }
}

/// Runs the export worker with `arguments` as the site, in the capture
/// domain at the site's level, with nothing writable but its own stdout,
/// which PID 1 writes to a root-owned output file. Returns that output.
fn run_worker(
    context: &ImportStepContext<'_>,
    step: &str,
    arguments: &[&str],
) -> Result<Vec<u8>, ExecutorError> {
    let layout = context.layout;
    let level = crate::capture::site_level(layout)?;
    let import_path = layout.root.join("tmp").join(IMPORT_DIR);
    let mut random = [0_u8; 4];
    rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty())
        .map_err(|_| ExecutorError::Unavailable)?;
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let name = format!("rustiron-import-{}-{step}-{suffix}.out", layout.account);
    let output = format!("{}/{name}", crate::capture::OUTPUT_DIR);
    let limit = rustiron_contracts::migration::MAX_MIGRATION_INVENTORY_BYTES;
    let mut args = provision::job_properties(
        OBSERVE_DOMAIN,
        &layout.account,
        &level,
        path_text(&import_path)?,
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
    args.extend(arguments.iter().map(|argument| (*argument).to_owned()));
    crate::capture::ensure_output_dir()?;
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let ran = provision::run("/usr/bin/systemd-run", &borrowed);
    let directory = files::open_traversable_directory(Path::new(crate::capture::OUTPUT_DIR), 0)?;
    let bytes = files::read_child(&directory, &name, 0, files::Exposure::Readable, limit);
    let _ = fs::unlinkat(&directory, name.as_str(), AtFlags::empty());
    ran?;
    bytes
}

/// The document root member of a CyberPanel site export: the home tree's
/// `public_html`, below the archive root `./`.
const DOCUMENT_ROOT_MEMBER: &str = "./public_html/public_html";
/// The census bounds of the imported tree: the export worker's limits.
pub(crate) const TREE_BOUNDS: crate::census::Bounds = crate::census::Bounds {
    entries: 200_000,
    depth: 64,
};

/// W448: extracts the document root member of the copy into the site's
/// empty `html` in the unpack job, so new entries take the site's content
/// label. Root then checks the census of `html` and compares its tree
/// manifest with the extracted document root, both made by the worker.
///
/// W452-F1: the site quota bounds the copy, the extracted tree, and `html`
/// together. So the step first takes the document root's manifest, then
/// removes the extracted home tree (`tmp/import/public_html`; `meta.xml` and
/// the dump stay for the Database step), and only then fills `html`.
fn files_step(context: &ImportStepContext<'_>) -> Result<(), ExecutorError> {
    let layout = context.layout;
    let uid = site_uid(layout)?;
    let level = crate::capture::site_level(layout)?;
    let html = layout.root.join("html");
    let html_text = path_text(&html)?;
    let html_dir = files::open_traversable_directory(&html, uid)?;
    if Dir::read_from(&html_dir)
        .map_err(|_| ExecutorError::StepFailed)?
        .filter_map(Result::ok)
        .any(|entry| !matches!(entry.file_name().to_bytes(), b"." | b".."))
    {
        return Err(ExecutorError::Collision);
    }
    let tmp_path = layout.root.join("tmp");
    let home = tmp_path.join(IMPORT_DIR).join("public_html");
    let tree = |step: &str,
                folder: &Path|
     -> Result<rustiron_contracts::migration::FileSummary, ExecutorError> {
        let bytes = run_worker(context, step, &["--tree", path_text(folder)?])?;
        let report = rustiron_contracts::migration::decode_tree_report(&bytes)
            .map_err(|_| ExecutorError::StepFailed)?;
        report.files.ok_or(ExecutorError::StepFailed)
    };
    let extracted = tree("files-source", &home.join("public_html"))?;
    let mut args = provision::unpack_properties(&layout.account, &level, path_text(&tmp_path)?);
    args.extend(["--", "/usr/bin/rm", "-rf", "--one-file-system", "--"].map(String::from));
    args.push(path_text(&home)?.to_owned());
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    provision::run("/usr/bin/systemd-run", &borrowed)?;
    let copy = tmp_path.join(COPY);
    let mut args = provision::unpack_properties(&layout.account, &level, html_text);
    args.extend(["--", "/usr/bin/tar", "--extract", "--gzip"].map(String::from));
    args.push(format!("--file={}", path_text(&copy)?));
    args.push(format!("--directory={html_text}"));
    args.extend(
        [
            "--strip-components=3",
            "--no-same-owner",
            "--numeric-owner",
            "--no-same-permissions",
            "--keep-old-files",
            DOCUMENT_ROOT_MEMBER,
        ]
        .map(String::from),
    );
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    provision::run("/usr/bin/systemd-run", &borrowed)?;
    let want = format!("system_u:object_r:httpd_sys_content_t:{level}");
    let census = crate::census::census_labelled(
        &html_dir,
        uid,
        want.as_bytes(),
        &crate::census::label_of,
        TREE_BOUNDS,
    )?;
    if census.owned_files == 0 || census.foreign != 0 || census.mislabelled != 0 {
        return Err(ExecutorError::StepFailed);
    }
    let imported = tree("files-html", &html)?;
    if extracted != imported || imported.unsafe_entries != 0 {
        return Err(ExecutorError::StepFailed);
    }
    Ok(())
}

/// W449: imports the one extracted dump into the site's own database as the
/// site's own database user, under the D-034 size watch. The job runs the
/// capture worker's `site-import` action as the site in the capture domain
/// at the site's level; the worker accepts only the single `.sql` entry of
/// `tmp/import` with the signed size and becomes the fixed `mariadb` client
/// (`--sandbox --local-infile=0 --batch`) reading it on stdin. The user has
/// grants on its own database only, so a statement for another database
/// fails the import.
fn database_step(context: &ImportStepContext<'_>) -> Result<(), ExecutorError> {
    if context.facts.is_static() {
        return static_database_step(context.layout);
    }
    import_dump(context.layout, context.facts.dump_bytes)
}

/// W449: the dump import of [`database_step`]; W499 (D-078): also a clone's
/// Database step, after the clone moved its fetched dump into `tmp/import`.
pub(crate) fn import_dump(layout: &SiteLayout, dump_bytes: u64) -> Result<(), ExecutorError> {
    use crate::restore::database;
    let level = crate::capture::site_level(layout)?;
    let import_path = layout.root.join("tmp").join(IMPORT_DIR);
    let mut args = provision::job_properties(
        OBSERVE_DOMAIN,
        &layout.account,
        &level,
        path_text(&import_path)?,
    );
    args.push("--".to_owned());
    args.push(format!(
        "{}/{}",
        crate::layout::JOB_BIN_DIR,
        crate::manifest::WORKER
    ));
    args.push("site-import".to_owned());
    args.push(layout.account.clone());
    args.push(dump_bytes.to_string());
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let size_sql = database::size_sql(&layout.account);
    let (passed, _watch) = database::watch(
        database::cap(dump_bytes),
        database::POLL,
        || provision::run("/usr/bin/systemd-run", &borrowed),
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
            let _ = provision::mariadb_admin(&database::stop_sql(&layout.account));
        },
    );
    if passed {
        Ok(())
    } else {
        Err(ExecutorError::StepFailed)
    }
}

/// D-074: a static import has no dump. The step changes nothing; it checks
/// that the extracted export in `tmp/import` holds no dump entry, so a
/// dump cannot have been added after the Observe step.
fn static_database_step(layout: &SiteLayout) -> Result<(), ExecutorError> {
    let uid = site_uid(layout)?;
    let tmp = files::open_traversable_directory(&layout.root.join("tmp"), uid)?;
    let import = files::open_child_directory(&tmp, IMPORT_DIR, uid)?;
    let entries = Dir::read_from(&import).map_err(|_| ExecutorError::StepFailed)?;
    for (index, entry) in (0..).zip(entries) {
        let entry = entry.map_err(|_| ExecutorError::StepFailed)?;
        if index >= TREE_BOUNDS.entries || is_dump_name(entry.file_name().to_bytes()) {
            return Err(ExecutorError::StepFailed);
        }
    }
    Ok(())
}

/// A CyberPanel export can contain a raw or gzip-compressed dump.
fn is_dump_name(name: &[u8]) -> bool {
    [b".sql".as_slice(), b".sql.gz".as_slice()]
        .iter()
        .any(|suffix| {
            name.len() > suffix.len()
                && name[name.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
        })
}

/// D-074: a static import has no WordPress configuration to rewrite. The
/// step changes nothing; it checks that `html` has no `wp-config.php` entry
/// of any type.
fn static_config_step(layout: &SiteLayout) -> Result<(), ExecutorError> {
    let html = files::open_traversable_directory(&layout.root.join("html"), site_uid(layout)?)?;
    match fs::statat(&html, "wp-config.php", fs::AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(()),
        _ => Err(ExecutorError::StepFailed),
    }
}

/// W450: the fixed Config asset, run by the site PHP CLI as the site.
const CONFIG_SCRIPT: &str = include_str!("import_assets/config.php");
/// The asset's output name in the site's `tmp`.
const CONFIG_NEW: &str = "rustiron-import-config.new";
/// The reader the asset puts in place of the four definitions.
const CONFIG_READER: &str = "$rustiron_db = parse_ini_file(dirname(__DIR__) . '/private/db.cnf', true, INI_SCANNER_RAW)['client'];";
/// Largest new configuration: the asset's input bound plus the reader.
const MAX_CONFIG_BYTES: usize = 1024 * 1024 + 4096;
/// D-069: the asset's input naming the source's document root.
const CONFIG_PATHS_INPUT: &str = "rustiron-import-config.paths";
/// D-069: the prefix of each other file the asset rewrote, in the site's `tmp`.
const CONFIG_PATH_PREFIX: &str = "rustiron-import-path.";
/// D-069: `.htaccess`, `.user.ini`, and at most 64 `wp-content/*.php`.
const MAX_PATH_FILES: usize = 66;
/// D-069: the asset's read bound for each file it rewrites, plus growth.
const MAX_PATH_BYTES: usize = 1024 * 1024 + 64 * 1024;

/// D-069 (W478): a document-root file that the Config asset rewrote.
#[derive(Debug, PartialEq, Eq)]
struct MovedFile {
    /// The parent folder under `html`, or None for `html` itself.
    folder: Option<&'static str>,
    name: String,
    sha256: Sha256Digest,
}

/// D-069: the CyberPanel document root of the signed hostname.
fn source_docroot(hostname: &Hostname) -> String {
    format!("/home/{}/public_html", hostname.as_str())
}

/// D-069: the report's `paths` list, only in the shapes the asset writes:
/// `.htaccess`, `.user.ini`, or `wp-content/<plain name>.php`, each once.
fn moved_files(report: &serde_json::Value) -> Option<Vec<MovedFile>> {
    let list = report.get("paths")?.as_array()?;
    if list.len() > MAX_PATH_FILES {
        return None;
    }
    let mut moved: Vec<MovedFile> = Vec::new();
    for entry in list {
        let name = entry.get("name")?.as_str()?;
        let sha256 = Sha256Digest::try_from(entry.get("sha256")?.as_str()?.to_owned()).ok()?;
        let (folder, file) = match name.strip_prefix("wp-content/") {
            Some(file) => (Some("wp-content"), file),
            None if name == ".htaccess" || name == ".user.ini" => (None, name),
            None => return None,
        };
        let plain = folder.is_none()
            || (file.len() <= 132
                && file.ends_with(".php")
                && !file.starts_with('.')
                && file
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)));
        if !plain || moved.iter().any(|m| m.folder == folder && m.name == file) {
            return None;
        }
        moved.push(MovedFile {
            folder,
            name: file.to_owned(),
            sha256,
        });
    }
    Some(moved)
}

/// W450: replaces the imported `wp-config.php` database definitions with
/// Rustiron's read of `private/db.cnf`, then removes the extracted tree and
/// the archive copy. The site PHP job may write only `tmp`, so it writes the
/// new text there; an unpack job, which may write the site's content type,
/// copies it over `html/wp-config.php`. No site PHP unit runs during the
/// Recipe step. Root checks the report and the text, then that the installed
/// file has exactly that digest, the `html` census, and that the extraction
/// is gone.
fn config_step(context: &ImportStepContext<'_>) -> Result<(), ExecutorError> {
    let layout = context.layout;
    if context.facts.is_static() {
        static_config_step(layout)?;
    } else {
        wordpress_config_step(context)?;
    }
    // Every imported site needs the identity marker and ACME webroot.
    provision::write_site_marker(layout)?;
    crate::certificate::prepare_webroot(&layout.account)?;

    let uid = site_uid(layout)?;
    let level = crate::capture::site_level(layout)?;
    let html = files::open_traversable_directory(&layout.root.join("html"), uid)?;
    let want = format!("system_u:object_r:httpd_sys_content_t:{level}");
    let census = crate::census::census_labelled(
        &html,
        uid,
        want.as_bytes(),
        &crate::census::label_of,
        TREE_BOUNDS,
    )?;
    if census.owned_files == 0 || census.foreign != 0 || census.mislabelled != 0 {
        return Err(ExecutorError::StepFailed);
    }
    let tmp_path = layout.root.join("tmp");
    let tmp = files::open_traversable_directory(&tmp_path, uid)?;
    remove_leftovers(layout, &level, &tmp_path, &tmp)
}

fn wordpress_config_step(context: &ImportStepContext<'_>) -> Result<(), ExecutorError> {
    use sha2::{Digest, Sha256};
    let layout = context.layout;
    let uid = site_uid(layout)?;
    let level = crate::capture::site_level(layout)?;
    let tmp_path = layout.root.join("tmp");
    let html = layout.root.join("html");
    // D-069, D-070: the source site's document root.
    let source = source_docroot(context.facts.source_or(context.hostname));
    let (report, _) = provision::run_site_php(
        layout,
        "rustiron-import-config",
        CONFIG_SCRIPT,
        &[(CONFIG_PATHS_INPUT, source.as_bytes())],
    )?;
    let tmp = files::open_traversable_directory(&tmp_path, uid)?;
    let moved = moved_files(&report);
    let installed = (|| {
        // W450-F1: a refusal leaves no new text; that is a failed step, not
        // an access error.
        if report["ok"] != true || report["replaced"] != 4 {
            return Err(ExecutorError::StepFailed);
        }
        let text = files::read_child(
            &tmp,
            CONFIG_NEW,
            uid,
            files::Exposure::Readable,
            MAX_CONFIG_BYTES,
        )
        .map_err(|_| ExecutorError::StepFailed)?;
        let digest = Sha256Digest::from_bytes(Sha256::digest(&text).into());
        let reader_once =
            std::str::from_utf8(&text).is_ok_and(|text| text.matches(CONFIG_READER).count() == 1);
        if report["sha256"].as_str() != Some(digest.as_str()) || !reader_once {
            return Err(ExecutorError::StepFailed);
        }
        let mut args = provision::unpack_properties(&layout.account, &level, path_text(&html)?);
        args.extend(
            [
                "--",
                "/usr/bin/cp",
                // W475: no reflink ioctl on the site's content.
                "--reflink=never",
                "--no-preserve=all",
                "--no-dereference",
                "--",
            ]
            .map(String::from),
        );
        let copy = |from: &str, to: &Path| -> Result<(), ExecutorError> {
            let mut job = args.clone();
            job.push(path_text(&tmp_path.join(from))?.to_owned());
            job.push(path_text(to)?.to_owned());
            let borrowed: Vec<&str> = job.iter().map(String::as_str).collect();
            provision::run("/usr/bin/systemd-run", &borrowed)
        };
        let moved = moved.as_ref().ok_or(ExecutorError::StepFailed)?;
        for (index, file) in moved.iter().enumerate() {
            let staged = format!("{CONFIG_PATH_PREFIX}{index}");
            let text = files::read_child(
                &tmp,
                &staged,
                uid,
                files::Exposure::Readable,
                MAX_PATH_BYTES,
            )
            .map_err(|_| ExecutorError::StepFailed)?;
            if Sha256Digest::from_bytes(Sha256::digest(&text).into()) != file.sha256 {
                return Err(ExecutorError::StepFailed);
            }
        }
        copy(CONFIG_NEW, &html.join("wp-config.php"))?;
        for (index, file) in moved.iter().enumerate() {
            let folder = file.folder.map_or_else(|| html.clone(), |f| html.join(f));
            copy(
                &format!("{CONFIG_PATH_PREFIX}{index}"),
                &folder.join(&file.name),
            )?;
        }
        Ok(digest)
    })();
    let _ = fs::unlinkat(&tmp, CONFIG_NEW, AtFlags::empty());
    for index in 0..MAX_PATH_FILES {
        let _ = fs::unlinkat(
            &tmp,
            format!("{CONFIG_PATH_PREFIX}{index}"),
            AtFlags::empty(),
        );
    }
    let digest = installed?;
    let html_dir = files::open_traversable_directory(&html, uid)?;
    let now = files::read_child(
        &html_dir,
        "wp-config.php",
        uid,
        files::Exposure::Readable,
        MAX_CONFIG_BYTES,
    )?;
    if Sha256Digest::from_bytes(Sha256::digest(&now).into()) != digest {
        return Err(ExecutorError::StepFailed);
    }
    for file in moved.iter().flatten() {
        let folder = match file.folder {
            Some(folder) => files::open_traversable_directory(&html.join(folder), uid)?,
            None => files::open_traversable_directory(&html, uid)?,
        };
        let now = files::read_child(
            &folder,
            &file.name,
            uid,
            files::Exposure::Readable,
            MAX_PATH_BYTES,
        )?;
        if Sha256Digest::from_bytes(Sha256::digest(&now).into()) != file.sha256 {
            return Err(ExecutorError::StepFailed);
        }
    }
    // D-070: a renamed import moves the site's links to its new hostname.
    if let Some(source) = &context.facts.source_hostname {
        rewrite_hostname(layout, source, context.hostname)?;
    }
    Ok(())
}

/// D-070: the fixed hostname-change asset, run by the site PHP CLI as the site.
const URLS_SCRIPT: &str = include_str!("import_assets/urls.php");
/// D-070: the asset's input: the source and the target hostname.
const URLS_INPUT: &str = "rustiron-import-urls.input";
/// D-070: the counts the asset reports on success.
/// W479-F1: `caches` counts the deleted disposable cache rows.
const URLS_COUNTS: [&str; 7] = [
    "tables",
    "columns",
    "rows",
    "values",
    "serialized",
    "unparsed",
    "caches",
];

/// D-070: the asset's input bytes, both hostnames from the signed plan.
fn urls_input(source: &Hostname, target: &Hostname) -> String {
    format!("{}\n{}\n", source.as_str(), target.as_str())
}

/// D-070: whether the asset's report is a success of the fixed shape.
fn urls_report_ok(report: &serde_json::Value) -> bool {
    report["ok"] == true
        && report["reason"].is_null()
        && report
            .as_object()
            .is_some_and(|fields| fields.len() == 2 + URLS_COUNTS.len())
        && URLS_COUNTS.iter().all(|name| report[*name].is_u64())
}

/// D-070: replaces //`source` with //`target` in the site's own database,
/// as the site in its PHP sandbox, with its own database login. Root sends
/// only the two signed hostnames and accepts only the fixed success report;
/// the import Verify then checks the site URL at `target`.
pub(crate) fn rewrite_hostname(
    layout: &SiteLayout,
    source: &Hostname,
    target: &Hostname,
) -> Result<(), ExecutorError> {
    let input = urls_input(source, target);
    let (report, _) = provision::run_site_php(
        layout,
        "rustiron-import-urls",
        URLS_SCRIPT,
        &[(URLS_INPUT, input.as_bytes())],
    )?;
    if urls_report_ok(&report) {
        Ok(())
    } else {
        Err(ExecutorError::StepFailed)
    }
}

/// W457 (D-057): removes the extracted export and the archive copy from the
/// site's `tmp` by an unpack job as the site at its level, so root never
/// walks the tenant tree. Root then checks that both names are gone. Absent
/// names are fine, so a repeat removes nothing more.
fn remove_leftovers(
    layout: &SiteLayout,
    level: &str,
    tmp_path: &Path,
    tmp: &OwnedFd,
) -> Result<(), ExecutorError> {
    let mut args = provision::unpack_properties(&layout.account, level, path_text(tmp_path)?);
    args.extend(["--", "/usr/bin/rm", "-rf", "--one-file-system", "--"].map(String::from));
    args.push(path_text(&tmp_path.join(IMPORT_DIR))?.to_owned());
    args.push(path_text(&tmp_path.join(COPY))?.to_owned());
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    provision::run("/usr/bin/systemd-run", &borrowed)?;
    for name in [IMPORT_DIR, COPY] {
        match fs::statat(tmp, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => {}
            _ => return Err(ExecutorError::StepFailed),
        }
    }
    Ok(())
}

/// W459 (D-057): removes the site's intake archive and then its empty
/// folder. An absent folder or archive is fine. A present archive must be a
/// single-link regular file of the intake owner whose SHA-256 is the signed
/// value; anything else in the folder stops the removal.
pub(crate) fn remove_intake(
    intake_dir: &Path,
    owner: u32,
    site: &SiteId,
    expected: &Sha256Digest,
) -> Result<(), ExecutorError> {
    let deny = ExecutorError::AccessDenied;
    let intake = files::open_trusted_directory(intake_dir, owner)?;
    match fs::statat(&intake, site.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
        Err(Errno::NOENT) => return Ok(()),
        Err(_) => return Err(deny),
        Ok(_) => {}
    }
    let folder = files::open_child_directory(&intake, site.as_str(), owner)?;
    match fs::openat(&folder, ARCHIVE, ARCHIVE_FLAGS, Mode::empty()) {
        Err(Errno::NOENT) => {}
        Err(_) => return Err(deny),
        Ok(archive) => {
            let stat = fs::fstat(&archive).map_err(|_| deny)?;
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                || stat.st_uid != owner
                || stat.st_nlink != 1
            {
                return Err(deny);
            }
            if &Sha256Digest::from_bytes(hash(&archive)?) != expected {
                return Err(ExecutorError::PreconditionChanged);
            }
            let named =
                fs::statat(&folder, ARCHIVE, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| deny)?;
            if (named.st_dev, named.st_ino) != (stat.st_dev, stat.st_ino) {
                return Err(ExecutorError::PreconditionChanged);
            }
            fs::unlinkat(&folder, ARCHIVE, AtFlags::empty()).map_err(|_| deny)?;
        }
    }
    fs::fsync(&folder).map_err(|_| ExecutorError::Unavailable)?;
    // A folder that still holds anything is not removed.
    fs::unlinkat(&intake, site.as_str(), AtFlags::REMOVEDIR)
        .map_err(|_| ExecutorError::PreconditionChanged)?;
    fs::fsync(&intake).map_err(|_| ExecutorError::Unavailable)
}

/// W457 (D-057): the scrub of a site's import leftovers in `tmp`.
pub(crate) fn scrub_site(layout: &SiteLayout) -> Result<(), ExecutorError> {
    let uid = site_uid(layout)?;
    let level = crate::capture::site_level(layout)?;
    let tmp_path = layout.root.join("tmp");
    let tmp = files::open_traversable_directory(&tmp_path, uid)?;
    remove_leftovers(layout, &level, &tmp_path, &tmp)
}

/// W451: the fixed import Verify asset, run by the site's own PHP.
const VERIFY_SCRIPT: &str = include_str!("import_assets/verify.php");

/// W451 (D-053): the import's Verify step, in place of the S04 Verify (an
/// imported site has no pinned core checksum list). The serving units are
/// enabled at boot, and the site's own PHP reports its account and domain,
/// its own database login with the imported tables, a site URL at the
/// plan's hostname, read-only code, and no readable other site.
pub(crate) fn verify_import(
    layout: &SiteLayout,
    hostname: &Hostname,
    is_static: bool,
) -> Result<(), ExecutorError> {
    provision::serving_survives_boot(layout)?;
    let (report, level) =
        provision::run_site_php(layout, "rustiron-import-verify", VERIFY_SCRIPT, &[])?;
    let matches = if is_static {
        static_verify_matches(&report, &layout.account, &level)
    } else {
        import_verify_matches(&report, &layout.account, &level, hostname)
    };
    if matches {
        Ok(())
    } else {
        Err(ExecutorError::StepFailed)
    }
}

/// D-074: the Verify report of a static site: its own identity and empty
/// database, no WordPress configuration or site URL, read-only code, and no
/// readable other site.
fn static_verify_matches(report: &serde_json::Value, account: &str, level: &str) -> bool {
    report["user"] == account
        && report["context"] == format!("system_u:system_r:rustiron_php_t:{level}")
        && report["database"] == account
        && report["db_user"] == format!("{account}@localhost").as_str()
        && report["tables"] == 0
        && report
            .get("siteurl")
            .is_some_and(serde_json::Value::is_null)
        && report["wp_config"] == false
        && report["can_write_html"] == false
        && others_hidden(report)
}

fn others_hidden(report: &serde_json::Value) -> bool {
    match &report["reads_other_sites"] {
        serde_json::Value::Object(sites) => sites.values().all(|seen| seen == false),
        serde_json::Value::Array(sites) => sites.is_empty(),
        _ => false,
    }
}

/// Whether the Verify report names exactly this site. PHP writes an empty
/// map as `[]`: the first site on a host sees no other site.
pub(crate) fn import_verify_matches(
    report: &serde_json::Value,
    account: &str,
    level: &str,
    hostname: &Hostname,
) -> bool {
    let host = hostname.as_str();
    let siteurl_ok = report["siteurl"].as_str().is_some_and(|url| {
        url.strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .is_some_and(|rest| rest == host || rest.strip_suffix('/') == Some(host))
    });
    report["user"] == account
        && report["context"] == format!("system_u:system_r:rustiron_php_t:{level}")
        && report["database"] == account
        && report["db_user"] == format!("{account}@localhost").as_str()
        && report["tables"].as_u64().is_some_and(|tables| tables > 0)
        && report["wp_config"] == true
        && report["can_write_html"] == false
        && siteurl_ok
        && others_hidden(report)
}

/// The site-owned copy of the archive in the site's `tmp`.
pub(crate) const COPY: &str = "import.tar.gz";

/// W478-F1: after this many bytes, the copy flushes and drops the cached
/// pages of both files. The admin helper runs under `MemoryMax=256M`, and the
/// page cache of a large archive is charged to it: a 740 MB copy was killed
/// by the OOM killer without this.
const CACHE_STEP: u64 = 16 * 1024 * 1024;

/// Drops the cached pages of `fd` up to `end`; a failure only costs memory.
fn drop_cache(fd: &OwnedFd, end: u64) {
    let _ = fs::fadvise(fd, 0, std::num::NonZeroU64::new(end), fs::Advice::DontNeed);
}

/// Copies the rewound `archive` into `tmp/COPY`, a new file of `uid` with
/// mode 0600, hashing while it copies. A digest other than `expected`, or
/// more than `max_bytes`, removes the copy and fails the step.
pub(crate) fn copy_archive(
    archive: &OwnedFd,
    tmp: &OwnedFd,
    uid: u32,
    expected: &Sha256Digest,
    max_bytes: u64,
) -> Result<(), ExecutorError> {
    fs::seek(archive, SeekFrom::Start(0)).map_err(|_| ExecutorError::StepFailed)?;
    let copy = fs::openat(
        tmp,
        COPY,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| ExecutorError::StepFailed)?;
    let written = (|| {
        fs::fchown(
            &copy,
            Some(rustix::fs::Uid::from_raw(uid)),
            Some(rustix::fs::Gid::from_raw(uid)),
        )
        .map_err(|_| ExecutorError::StepFailed)?;
        let mut hash = Sha256::new();
        let mut buffer = vec![0; 256 * 1024];
        let mut total: u64 = 0;
        loop {
            let read = match rustix::io::read(archive, &mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(Errno::INTR) => continue,
                Err(_) => return Err(ExecutorError::StepFailed),
            };
            total += read as u64;
            if total > max_bytes {
                return Err(ExecutorError::StepFailed);
            }
            hash.update(&buffer[..read]);
            let mut rest = &buffer[..read];
            while !rest.is_empty() {
                match rustix::io::write(&copy, rest) {
                    Ok(0) => return Err(ExecutorError::StepFailed),
                    Ok(done) => rest = &rest[done..],
                    Err(Errno::INTR) => {}
                    Err(_) => return Err(ExecutorError::StepFailed),
                }
            }
            if total % CACHE_STEP < read as u64 {
                fs::fdatasync(&copy).map_err(|_| ExecutorError::StepFailed)?;
                drop_cache(&copy, total);
                drop_cache(archive, total);
            }
        }
        fs::fsync(&copy).map_err(|_| ExecutorError::StepFailed)?;
        if &Sha256Digest::from_bytes(hash.finalize().into()) != expected {
            return Err(ExecutorError::StepFailed);
        }
        Ok(())
    })();
    if written.is_err() {
        let _ = fs::unlinkat(tmp, COPY, AtFlags::empty());
    }
    written
}

/// Which signed fact an observation contradicts; fixed text, no data.
pub(crate) fn observation_mismatch(
    observation: &ExportObservation,
    facts: &ImportFacts,
    hostname: &Hostname,
) -> Option<&'static str> {
    if observation.status != ExportStatus::Complete {
        return Some("report not complete");
    }
    let Some(files) = &observation.files else {
        return Some("files unknown");
    };
    if files.manifest_sha256 != facts.manifest_sha256 {
        return Some("manifest");
    }
    if files.entries != facts.file_entries || files.bytes != facts.file_bytes {
        return Some("file count or bytes");
    }
    if files.unsafe_entries != 0 {
        return Some("unsafe entries");
    }
    match observation.databases.as_deref() {
        Some([dump]) if dump.bytes == facts.dump_bytes && !facts.is_static() => {}
        // D-074: a static import's export holds no dump.
        Some([]) if facts.is_static() => {}
        _ => return Some("database dump"),
    }
    if observation.hostname.as_ref() != Some(hostname) {
        return Some("hostname");
    }
    if let Some(alias) = &facts.alias_hostname
        && observation.aliases.as_deref() != Some(std::slice::from_ref(alias))
    {
        return Some("alias hostname");
    }
    None
}

fn hash(fd: &OwnedFd) -> Result<[u8; 32], ExecutorError> {
    let mut hash = Sha256::new();
    let mut buffer = vec![0; 256 * 1024];
    let mut total: u64 = 0;
    loop {
        match rustix::io::read(fd, &mut buffer) {
            Ok(0) => {
                drop_cache(fd, total);
                return Ok(hash.finalize().into());
            }
            Ok(read) => {
                hash.update(&buffer[..read]);
                total += read as u64;
                // W478-F1: keep the archive's cached pages off the helper.
                if total % CACHE_STEP < read as u64 {
                    drop_cache(fd, total);
                }
            }
            Err(Errno::INTR) => {}
            Err(_) => return Err(ExecutorError::Unavailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::path::PathBuf;

    const BYTES: &[u8] = b"synthetic export archive bytes";

    /// D-069 (W478): the report's moved files, only in the asset's shapes.
    #[test]
    fn moved_files_take_only_the_asset_shapes() {
        let sha = "a".repeat(64);
        let report = |names: &[&str]| {
            let paths: Vec<_> = names
                .iter()
                .map(|name| serde_json::json!({"name": name, "sha256": sha}))
                .collect();
            serde_json::json!({ "paths": paths })
        };
        let moved = moved_files(&report(&[
            ".htaccess",
            ".user.ini",
            "wp-content/firewall.php",
        ]))
        .expect("asset shapes");
        assert_eq!(moved.len(), 3);
        assert_eq!(
            (moved[0].folder, moved[0].name.as_str()),
            (None, ".htaccess")
        );
        assert_eq!(
            (moved[2].folder, moved[2].name.as_str()),
            (Some("wp-content"), "firewall.php")
        );
        assert_eq!(moved_files(&report(&[])), Some(Vec::new()));
        for bad in [
            &["wp-config.php"][..],
            &["../x.php"],
            &["wp-content/../x.php"],
            &["wp-content/plugins/x.php"],
            &["wp-content/.hidden.php"],
            &["wp-content/x.txt"],
            &[".htaccess", ".htaccess"],
        ] {
            assert_eq!(moved_files(&report(bad)), None, "{bad:?}");
        }
        assert_eq!(moved_files(&serde_json::json!({})), None, "no list");
        assert_eq!(
            moved_files(&serde_json::json!({"paths": [{"name": ".htaccess", "sha256": "x"}]})),
            None,
            "not a digest"
        );
        let many: Vec<String> = (0..=MAX_PATH_FILES)
            .map(|i| format!("wp-content/f{i}.php"))
            .collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert_eq!(moved_files(&report(&many)), None, "too many");
        let host = Hostname::try_from("blog1.example.test".to_owned()).unwrap();
        assert_eq!(
            source_docroot(&host),
            "/home/blog1.example.test/public_html"
        );
    }

    struct Intake(PathBuf);

    impl Intake {
        fn new() -> Self {
            let mut random = [0; 8];
            rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty()).unwrap();
            let base = std::env::temp_dir().join(format!(
                "ri-intake-{}-{}",
                std::process::id(),
                u64::from_ne_bytes(random)
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&base)
                .unwrap();
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(base.join("blog1"))
                .unwrap();
            let intake = Self(base);
            intake.write(BYTES, 0o600);
            intake
        }

        fn archive(&self) -> PathBuf {
            self.0.join("blog1").join(ARCHIVE)
        }

        fn write(&self, bytes: &[u8], mode: u32) {
            let _ = std::fs::remove_file(self.archive());
            std::fs::write(self.archive(), bytes).unwrap();
            std::fs::set_permissions(self.archive(), std::fs::Permissions::from_mode(mode))
                .unwrap();
        }

        fn run(
            &self,
            site: &str,
            expected: &Sha256Digest,
            max: u64,
        ) -> Result<OwnedFd, ExecutorError> {
            intake(
                &self.0,
                rustix::process::getuid().as_raw(),
                &SiteId::try_from(site.to_owned()).unwrap(),
                expected,
                max,
            )
        }
    }

    impl Drop for Intake {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(
                self.0.join("blog1"),
                std::fs::Permissions::from_mode(0o700),
            );
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn digest(bytes: &[u8]) -> Sha256Digest {
        Sha256Digest::from_bytes(Sha256::digest(bytes).into())
    }

    fn remove(intake: &Intake, expected: &Sha256Digest) -> Result<(), ExecutorError> {
        remove_intake(
            &intake.0,
            rustix::process::getuid().as_raw(),
            &SiteId::try_from("blog1".to_owned()).unwrap(),
            expected,
        )
    }

    /// W459 (D-057): the signed archive and its folder go; a repeat is fine.
    #[test]
    fn the_scrub_removes_the_signed_intake_archive_and_its_folder() {
        let intake = Intake::new();
        remove(&intake, &digest(BYTES)).unwrap();
        assert!(!intake.0.join("blog1").exists());
        remove(&intake, &digest(BYTES)).unwrap();
        // An empty folder without an archive is removed too.
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(intake.0.join("blog1"))
            .unwrap();
        remove(&intake, &digest(BYTES)).unwrap();
        assert!(!intake.0.join("blog1").exists());
    }

    #[test]
    fn the_scrub_keeps_another_archive_a_link_or_extra_files() {
        let intake = Intake::new();
        assert_eq!(
            remove(&intake, &digest(b"other bytes")).err(),
            Some(ExecutorError::PreconditionChanged)
        );
        assert!(intake.archive().exists(), "another digest");
        let link = intake.0.join("second-link");
        std::fs::hard_link(intake.archive(), &link).unwrap();
        assert_eq!(
            remove(&intake, &digest(BYTES)).err(),
            Some(ExecutorError::AccessDenied)
        );
        assert!(intake.archive().exists(), "a second hard link");
        std::fs::remove_file(&link).unwrap();
        std::fs::remove_file(intake.archive()).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", intake.archive()).unwrap();
        assert_eq!(
            remove(&intake, &digest(BYTES)).err(),
            Some(ExecutorError::AccessDenied)
        );
        std::fs::remove_file(intake.archive()).unwrap();
        intake.write(BYTES, 0o600);
        std::fs::write(intake.0.join("blog1").join("note"), b"x").unwrap();
        assert_eq!(
            remove(&intake, &digest(BYTES)).err(),
            Some(ExecutorError::PreconditionChanged),
            "another file in the folder"
        );
        assert!(intake.0.join("blog1").join("note").exists());
    }

    #[test]
    fn the_signed_archive_is_returned_rewound() {
        let intake = Intake::new();
        let fd = intake.run("blog1", &digest(BYTES), 1024).unwrap();
        let mut read = Vec::new();
        std::io::Read::read_to_end(&mut std::fs::File::from(fd), &mut read).unwrap();
        assert_eq!(read, BYTES);
    }

    #[test]
    fn another_archive_or_size_is_a_changed_precondition() {
        let intake = Intake::new();
        assert_eq!(
            intake.run("blog1", &digest(b"other bytes"), 1024).err(),
            Some(ExecutorError::PreconditionChanged),
            "another digest"
        );
        assert_eq!(
            intake
                .run("blog1", &digest(BYTES), BYTES.len() as u64 - 1)
                .err(),
            Some(ExecutorError::PreconditionChanged),
            "over the size bound"
        );
        intake.write(b"", 0o600);
        assert_eq!(
            intake.run("blog1", &digest(b""), 1024).err(),
            Some(ExecutorError::PreconditionChanged),
            "an empty archive"
        );
        std::fs::remove_file(intake.archive()).unwrap();
        assert_eq!(
            intake.run("blog1", &digest(BYTES), 1024).err(),
            Some(ExecutorError::PreconditionChanged),
            "no archive"
        );
        assert_eq!(
            intake.run("blog2", &digest(BYTES), 1024).err(),
            Some(ExecutorError::AccessDenied),
            "another site's folder does not exist"
        );
    }

    #[test]
    fn the_copy_is_site_owned_private_and_checked_while_copied() {
        let intake = Intake::new();
        let uid = rustix::process::getuid().as_raw();
        let fd = intake.run("blog1", &digest(BYTES), 1024).unwrap();
        let tmp_path = intake.0.join("tmp");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&tmp_path)
            .unwrap();
        let tmp = crate::files::open_trusted_directory(&tmp_path, uid).unwrap();
        copy_archive(&fd, &tmp, uid, &digest(BYTES), 1024).unwrap();
        let copy = tmp_path.join(COPY);
        assert_eq!(std::fs::read(&copy).unwrap(), BYTES);
        let meta = std::fs::symlink_metadata(&copy).unwrap();
        assert_eq!(std::os::unix::fs::MetadataExt::mode(&meta) & 0o7777, 0o600);
        assert_eq!(
            copy_archive(&fd, &tmp, uid, &digest(BYTES), 1024).err(),
            Some(ExecutorError::StepFailed),
            "an existing copy is never replaced"
        );
        std::fs::remove_file(&copy).unwrap();
        assert_eq!(
            copy_archive(&fd, &tmp, uid, &digest(b"other"), 1024).err(),
            Some(ExecutorError::StepFailed),
            "another digest"
        );
        assert!(!copy.exists(), "a failed copy is removed");
        assert_eq!(
            copy_archive(&fd, &tmp, uid, &digest(BYTES), 4).err(),
            Some(ExecutorError::StepFailed),
            "over the bound"
        );
        assert!(!copy.exists());
    }

    fn observation() -> ExportObservation {
        serde_json::from_value(serde_json::json!({
            "schema_version": 1, "status": "complete", "reason": null,
            "hostname": "blog1.example.test", "aliases": [], "child_domains": 0,
            "files": {"entries": 10, "bytes": 100, "manifest_sha256": "d".repeat(64), "unsafe_entries": 0},
            "uploads": {"files": 1, "bytes": 1},
            "databases": [{"bytes": 50, "charset": "utf8mb4", "collation": "utf8mb4_unicode_ci"}],
            "php_version": "8.2", "site_url": null, "home_url": null, "tls": "none",
            "credentials": {"database_users": 1, "panel_users": 1, "api_tokens": 0},
            "dns_records": 0, "mail_accounts": 0
        }))
        .unwrap()
    }

    fn facts() -> ImportFacts {
        ImportFacts {
            archive_sha256: digest(BYTES),
            manifest_sha256: Sha256Digest::try_from("d".repeat(64)).unwrap(),
            file_entries: 10,
            file_bytes: 100,
            dump_bytes: 50,
            target_php: rustiron_contracts::migration::PhpVersion::try_from("8.2".to_owned())
                .unwrap(),
            source_hostname: None,
            alias_hostname: None,
        }
    }

    #[test]
    fn an_observation_must_match_every_signed_fact() {
        let host = Hostname::try_from("blog1.example.test".to_owned()).unwrap();
        assert_eq!(observation_mismatch(&observation(), &facts(), &host), None);
        let changed = |edit: &dyn Fn(&mut serde_json::Value)| {
            let mut value = serde_json::to_value(observation()).unwrap();
            edit(&mut value);
            let observation: ExportObservation = serde_json::from_value(value).unwrap();
            observation_mismatch(&observation, &facts(), &host)
        };
        for (want, edit) in [
            (
                "manifest",
                &(|v: &mut serde_json::Value| v["files"]["manifest_sha256"] = "e".repeat(64).into())
                    as &dyn Fn(&mut serde_json::Value),
            ),
            ("file count or bytes", &|v: &mut serde_json::Value| {
                v["files"]["entries"] = 11.into()
            }),
            ("file count or bytes", &|v: &mut serde_json::Value| {
                v["files"]["bytes"] = 101.into()
            }),
            ("unsafe entries", &|v: &mut serde_json::Value| {
                v["files"]["unsafe_entries"] = 1.into()
            }),
            ("database dump", &|v: &mut serde_json::Value| {
                v["databases"][0]["bytes"] = 51.into()
            }),
            ("database dump", &|v: &mut serde_json::Value| {
                v["databases"] = serde_json::Value::Null
            }),
            ("database dump", &|v: &mut serde_json::Value| {
                let dump = v["databases"][0].clone();
                v["databases"] = serde_json::json!([dump.clone(), dump]);
            }),
            ("hostname", &|v: &mut serde_json::Value| {
                v["hostname"] = "blog2.example.test".into()
            }),
            ("hostname", &|v: &mut serde_json::Value| {
                v["hostname"] = serde_json::Value::Null
            }),
            ("files unknown", &|v: &mut serde_json::Value| {
                v["files"] = serde_json::Value::Null
            }),
        ] {
            assert_eq!(changed(edit), Some(want), "{want}");
        }
        let stopped = ExportObservation::stopped(
            ExportStatus::Limit,
            rustiron_contracts::migration::ExportReason::Entries,
        );
        assert_eq!(
            observation_mismatch(&stopped, &facts(), &host),
            Some("report not complete")
        );
    }

    /// D-070: a renamed import checks the export and the document root
    /// against the source hostname, and sends both names to the asset.
    #[test]
    fn a_renamed_import_uses_the_source_hostname_for_the_export() {
        let target = Hostname::try_from("copy.example.net".to_owned()).unwrap();
        let source = Hostname::try_from("blog1.example.test".to_owned()).unwrap();
        let renamed = ImportFacts {
            source_hostname: Some(source.clone()),
            ..facts()
        };
        assert_eq!(renamed.source_or(&target), &source);
        assert_eq!(facts().source_or(&target), &target);
        assert_eq!(
            observation_mismatch(&observation(), &renamed, renamed.source_or(&target)),
            None
        );
        assert_eq!(
            observation_mismatch(&observation(), &facts(), facts().source_or(&target)),
            Some("hostname")
        );
        assert_eq!(
            source_docroot(renamed.source_or(&target)),
            "/home/blog1.example.test/public_html"
        );
        assert_eq!(
            urls_input(&source, &target),
            "blog1.example.test\ncopy.example.net\n"
        );
    }

    /// D-070: only the fixed success report passes; a refusal, a missing or
    /// extra field, or a non-count fails the step.
    #[test]
    fn the_hostname_change_report_must_be_the_fixed_success() {
        let good = serde_json::json!({
            "ok": true, "reason": null, "tables": 12, "columns": 30, "rows": 818,
            "values": 818, "serialized": 4, "unparsed": 0, "caches": 16
        });
        assert!(urls_report_ok(&good));
        let mut cases = vec![
            serde_json::json!({"ok": false, "reason": "database"}),
            serde_json::json!({"ok": false, "reason": "input"}),
        ];
        for (field, value) in [
            ("ok", serde_json::json!(1)),
            ("reason", serde_json::json!("x")),
            ("rows", serde_json::json!(-1)),
            ("rows", serde_json::json!("818")),
            ("extra", serde_json::json!(0)),
        ] {
            let mut bad = good.clone();
            bad[field] = value;
            cases.push(bad);
        }
        let mut missing = good.clone();
        missing.as_object_mut().unwrap().remove("unparsed");
        cases.push(missing);
        for bad in cases {
            assert!(!urls_report_ok(&bad), "{bad}");
        }
    }

    #[test]
    fn the_import_verify_report_must_name_exactly_this_site() {
        let host = Hostname::try_from("blog1.example.test".to_owned()).unwrap();
        let good = serde_json::json!({
            "user": "rs_blog1", "context": "system_u:system_r:rustiron_php_t:s0:c201",
            "database": "rs_blog1", "db_user": "rs_blog1@localhost", "tables": 12,
            "siteurl": "https://blog1.example.test", "wp_config": true,
            "can_write_html": false, "reads_other_sites": {"rs_other": false}
        });
        let check =
            |value: &serde_json::Value| import_verify_matches(value, "rs_blog1", "s0:c201", &host);
        assert!(check(&good));
        let mut first = good.clone();
        first["reads_other_sites"] = serde_json::json!([]);
        assert!(check(&first), "the first site sees no other site");
        let mut slash = good.clone();
        slash["siteurl"] = "http://blog1.example.test/".into();
        assert!(check(&slash));
        for (member, value) in [
            ("user", serde_json::json!("rs_other")),
            (
                "context",
                serde_json::json!("system_u:system_r:rustiron_php_t:s0:c202"),
            ),
            ("database", serde_json::json!("rs_other")),
            ("db_user", serde_json::json!("root@localhost")),
            ("tables", serde_json::json!(0)),
            ("siteurl", serde_json::json!("https://other.example.test")),
            (
                "siteurl",
                serde_json::json!("https://blog1.example.test/sub"),
            ),
            ("siteurl", serde_json::Value::Null),
            ("wp_config", serde_json::json!(false)),
            ("can_write_html", serde_json::json!(true)),
            ("reads_other_sites", serde_json::json!({"rs_other": true})),
            ("reads_other_sites", serde_json::json!(["rs_other"])),
        ] {
            let mut changed = good.clone();
            changed[member] = value.clone();
            assert!(!check(&changed), "{member} = {value}");
        }
    }

    /// D-074: a static import's export holds no dump, and a WordPress
    /// import's export holds exactly its one dump.
    #[test]
    fn a_static_import_accepts_only_an_export_without_a_dump() {
        let host = Hostname::try_from("blog1.example.test".to_owned()).unwrap();
        let static_facts = ImportFacts {
            dump_bytes: 0,
            ..facts()
        };
        let mut value = serde_json::to_value(observation()).unwrap();
        value["databases"] = serde_json::json!([]);
        let without: ExportObservation = serde_json::from_value(value).unwrap();
        assert_eq!(observation_mismatch(&without, &static_facts, &host), None);
        assert_eq!(
            observation_mismatch(&observation(), &static_facts, &host),
            Some("database dump")
        );
        assert_eq!(
            observation_mismatch(&without, &facts(), &host),
            Some("database dump")
        );
        assert!(is_dump_name(b"blog_wp.sql") && is_dump_name(b"X.SQL"));
        assert!(is_dump_name(b"a.sql.gz"));
        assert!(!is_dump_name(b".sql") && !is_dump_name(b"meta.xml"));
    }

    #[test]
    fn a_signed_alias_must_match_the_only_observed_alias() {
        let host = Hostname::try_from("blog1.example.test".to_owned()).unwrap();
        let alias = Hostname::try_from("alias.example.test".to_owned()).unwrap();
        let facts = ImportFacts {
            dump_bytes: 0,
            alias_hostname: Some(alias.clone()),
            ..facts()
        };
        let mut report = observation();
        report.databases = Some(Vec::new());
        report.aliases = None;
        assert_eq!(
            observation_mismatch(&report, &facts, &host),
            Some("alias hostname")
        );
        report.aliases = Some(vec![alias.clone(), host.clone()]);
        assert_eq!(
            observation_mismatch(&report, &facts, &host),
            Some("alias hostname")
        );
        report.aliases = Some(vec![alias]);
        assert_eq!(observation_mismatch(&report, &facts, &host), None);
    }

    /// D-074: the static Verify report: an empty own database, no WordPress.
    #[test]
    fn the_static_verify_report_has_no_wordpress_and_an_empty_database() {
        let good = serde_json::json!({
            "user": "rs_blog1", "context": "system_u:system_r:rustiron_php_t:s0:c201",
            "database": "rs_blog1", "db_user": "rs_blog1@localhost", "tables": 0,
            "siteurl": null, "wp_config": false,
            "can_write_html": false, "reads_other_sites": []
        });
        assert!(static_verify_matches(&good, "rs_blog1", "s0:c201"));
        for (member, value) in [
            ("tables", serde_json::json!(3)),
            ("siteurl", serde_json::json!("https://blog1.example.test")),
            ("wp_config", serde_json::json!(true)),
            ("can_write_html", serde_json::json!(true)),
            ("user", serde_json::json!("rs_other")),
            ("reads_other_sites", serde_json::json!({"rs_other": true})),
        ] {
            let mut changed = good.clone();
            changed[member] = value.clone();
            assert!(
                !static_verify_matches(&changed, "rs_blog1", "s0:c201"),
                "{member} = {value}"
            );
        }
    }

    #[test]
    fn an_exposed_linked_or_special_archive_is_refused() {
        let intake = Intake::new();
        intake.write(BYTES, 0o640);
        assert_eq!(
            intake.run("blog1", &digest(BYTES), 1024).err(),
            Some(ExecutorError::AccessDenied),
            "group-readable"
        );

        let intake = Intake::new();
        std::fs::write(intake.0.join("elsewhere"), BYTES).unwrap();
        std::fs::remove_file(intake.archive()).unwrap();
        std::os::unix::fs::symlink(intake.0.join("elsewhere"), intake.archive()).unwrap();
        assert_eq!(
            intake.run("blog1", &digest(BYTES), 1024).err(),
            Some(ExecutorError::AccessDenied),
            "a symlink"
        );

        let intake = Intake::new();
        std::fs::hard_link(intake.archive(), intake.0.join("second")).unwrap();
        assert_eq!(
            intake.run("blog1", &digest(BYTES), 1024).err(),
            Some(ExecutorError::AccessDenied),
            "a second link"
        );

        let intake = Intake::new();
        std::fs::remove_file(intake.archive()).unwrap();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(intake.archive())
            .unwrap();
        assert_eq!(
            intake.run("blog1", &digest(BYTES), 1024).err(),
            Some(ExecutorError::AccessDenied),
            "a folder"
        );
        std::fs::remove_dir(intake.archive()).unwrap();

        let intake = Intake::new();
        std::fs::set_permissions(
            intake.0.join("blog1"),
            std::fs::Permissions::from_mode(0o750),
        )
        .unwrap();
        assert_eq!(
            intake.run("blog1", &digest(BYTES), 1024).err(),
            Some(ExecutorError::AccessDenied),
            "a group-readable site folder"
        );

        let intake = Intake::new();
        std::fs::set_permissions(&intake.0, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert_eq!(
            intake.run("blog1", &digest(BYTES), 1024).err(),
            Some(ExecutorError::AccessDenied),
            "a group-readable intake folder"
        );
    }
}
