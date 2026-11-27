//! D-084 (W515): the recipe check of a signed WordPress plugin and theme
//! update, before its intent.
//!
//! The operator copies the recipe that `packaging/wordpress-update-recipe.py`
//! wrote to `<UPDATE_INTAKE_DIR>/<site_id>/recipe.tar`. The executor opens it
//! by descriptor from the admitted site ID, reads only its first member, the
//! manifest, and requires that the manifest's SHA-256 is the signed recipe
//! digest and that its lines name the signed components in plan order. The
//! manifest names a per-file list for each component, so the digest binds
//! every file that the later steps unpack and check. Root never unpacks or
//! interprets release content here.

use std::path::Path;

use std::os::fd::OwnedFd;
use std::path::PathBuf;

use rustiron_contracts::Id;
use rustiron_contracts::approval::{
    ComponentVersion, Hostname, Sha256Digest, SiteId, UpdateComponent, UpdateKind,
};
use rustiron_journal::UpdateStep;
use rustix::fs::{self, FileType, Mode, OFlags};
use rustix::io::Errno;
use sha2::{Digest, Sha256};

use crate::manifest::{format::Kind, tar::Archive};
use crate::provision::{self, SiteLayout};
use crate::{ExecutorError, files};

/// The recipe's file name in the site's intake folder.
pub(crate) const RECIPE: &str = "recipe.tar";
/// Largest recipe; the tool refuses a larger one.
pub(crate) const MAX_RECIPE_BYTES: u64 = 256 * 1024 * 1024;
/// Largest manifest: the schema line and eight component lines.
const MAX_MANIFEST_BYTES: u64 = 4096;
/// The manifest's first line.
pub(crate) const MANIFEST_SCHEMA: &str = "rustiron-wordpress-update/1";

const RECIPE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NOCTTY)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);

/// Whether `manifest` is the signed recipe: its SHA-256 is `digest`, its
/// first line is the schema, and each further line is
/// `<kind> <slug> <to-version> <archive sha256> <files sha256>` for the
/// component at the same position, with nothing else.
pub(crate) fn manifest_matches(
    manifest: &[u8],
    digest: &Sha256Digest,
    components: &[UpdateComponent],
) -> bool {
    let hex = |text: &str| {
        text.len() == 64
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let Ok(text) = std::str::from_utf8(manifest) else {
        return false;
    };
    let Some(body) = text.strip_suffix('\n') else {
        return false;
    };
    let mut lines = body.split('\n');
    if Sha256Digest::from_bytes(Sha256::digest(manifest).into()) != *digest
        || lines.next() != Some(MANIFEST_SCHEMA)
    {
        return false;
    }
    let lines: Vec<&str> = lines.collect();
    lines.len() == components.len()
        && lines.iter().zip(components).all(|(line, component)| {
            let fields: Vec<&str> = line.split(' ').collect();
            matches!(fields.as_slice(), [kind, slug, version, archive, listing]
                if *kind == component.kind.as_str()
                    && *slug == component.slug.as_str()
                    && *version == component.to_version.as_str()
                    && hex(archive)
                    && hex(listing))
        })
}

/// Opens the site's intake recipe and returns its manifest bytes. The
/// intake folder, the site folder, and the recipe belong to `owner` with no
/// group or other access; the recipe is a single-link regular file of at
/// most [`MAX_RECIPE_BYTES`] whose first member is a regular `manifest`.
/// An absent recipe is `PreconditionChanged`; anything unsuitable about the
/// files is `AccessDenied`; a recipe that does not read as a tar archive
/// with that first member is `PreconditionChanged`.
pub(crate) fn intake_manifest(
    intake_dir: &Path,
    owner: u32,
    site: &SiteId,
) -> Result<Vec<u8>, ExecutorError> {
    first_manifest(open_recipe(intake_dir, owner, site)?)
}

/// W516: the whole intake recipe, read once by descriptor after the same
/// checks as [`intake_manifest`].
pub(crate) fn intake_recipe(
    intake_dir: &Path,
    owner: u32,
    site: &SiteId,
) -> Result<Vec<u8>, ExecutorError> {
    use std::io::Read;
    let mut bytes = Vec::new();
    open_recipe(intake_dir, owner, site)?
        .take(MAX_RECIPE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ExecutorError::PreconditionChanged)?;
    if bytes.len() as u64 > MAX_RECIPE_BYTES {
        return Err(ExecutorError::PreconditionChanged);
    }
    Ok(bytes)
}

fn open_recipe(
    intake_dir: &Path,
    owner: u32,
    site: &SiteId,
) -> Result<std::fs::File, ExecutorError> {
    let deny = ExecutorError::AccessDenied;
    let intake = files::open_trusted_directory(intake_dir, owner)?;
    let folder = files::open_child_directory(&intake, site.as_str(), owner)?;
    if fs::fstat(&folder).map_err(|_| deny)?.st_mode & 0o077 != 0 {
        return Err(deny);
    }
    let recipe = match fs::openat(&folder, RECIPE, RECIPE_FLAGS, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Err(ExecutorError::PreconditionChanged),
        Err(_) => return Err(deny),
    };
    let stat = fs::fstat(&recipe).map_err(|_| deny)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != owner
        || stat.st_nlink != 1
        || stat.st_mode & 0o077 != 0
    {
        return Err(deny);
    }
    let size = u64::try_from(stat.st_size).map_err(|_| deny)?;
    if size == 0 || size > MAX_RECIPE_BYTES {
        return Err(ExecutorError::PreconditionChanged);
    }
    Ok(std::fs::File::from(recipe))
}

/// The first member of a recipe archive, which must be a regular file
/// named `manifest` of at most [`MAX_MANIFEST_BYTES`].
fn first_manifest(reader: impl std::io::Read) -> Result<Vec<u8>, ExecutorError> {
    let refused = ExecutorError::PreconditionChanged;
    let mut archive = Archive::new(reader);
    let header = archive.next().map_err(|_| refused)?.ok_or(refused)?;
    if header.path != b"manifest" || header.kind != Kind::File || header.size > MAX_MANIFEST_BYTES {
        return Err(refused);
    }
    let mut manifest = Vec::new();
    archive
        .content(|chunk| manifest.extend_from_slice(chunk))
        .map_err(|_| refused)?;
    Ok(manifest)
}

/// Largest file of a component; the page-cache census reads at most this
/// much per file (`page_cache::verify_listed`), and the recipe tool refuses
/// a larger one. W528-F2: WordPress 7.1.4 core ships a 13.4 MB file.
const MAX_COMPONENT_FILE_BYTES: u64 = 32 * 1024 * 1024;
/// Most files of one component, as the recipe tool allows.
const MAX_COMPONENT_FILES: usize = 5000;
/// Largest per-file list member.
const MAX_LIST_BYTES: u64 = 1024 * 1024;

/// One component's verified files: `(path inside the folder, sha256)`.
pub(crate) type ComponentFiles = Vec<(String, String)>;

fn safe_relative(path: &str) -> bool {
    let parts: Vec<&str> = path.split('/').collect();
    (1..=255).contains(&path.len())
        && parts.len() <= 16
        && parts.iter().all(|part| {
            !part.is_empty()
                && *part != "."
                && *part != ".."
                // W518-F1: release files use `@` and `,` (`logo@2x.png`,
                // variable-font names). No space: the list separator.
                && part.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'@' | b',' | b'+' | b'~')
                })
        })
}

/// A component's per-file list: sorted, unique `<sha256>  <path>` lines.
fn parse_list(bytes: &[u8]) -> Option<ComponentFiles> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut files = Vec::new();
    for line in text.strip_suffix('\n')?.split('\n') {
        let (digest, path) = line.split_once("  ")?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !safe_relative(path)
        {
            return None;
        }
        files.push((path.to_owned(), digest.to_owned()));
    }
    let sorted = files.windows(2).all(|pair| pair[0].0 < pair[1].0);
    (sorted && !files.is_empty() && files.len() <= MAX_COMPONENT_FILES).then_some(files)
}

/// Every member of the recipe, checked against the signed manifest: the
/// manifest first, then for each component in plan order its per-file list
/// (whose SHA-256 the manifest names) and exactly its listed files, each
/// with its listed SHA-256, and nothing else. Returns each component's
/// files. The content is only hashed, never interpreted.
pub(crate) fn recipe_files(
    recipe: &[u8],
    digest: &Sha256Digest,
    components: &[UpdateComponent],
) -> Result<Vec<ComponentFiles>, ExecutorError> {
    let refused = ExecutorError::PreconditionChanged;
    let hex = |bytes: &[u8]| Sha256Digest::from_bytes(Sha256::digest(bytes).into());
    let mut archive = Archive::new(recipe);
    let mut member = |name: &str, limit: u64| -> Result<Vec<u8>, ExecutorError> {
        let header = archive.next().map_err(|_| refused)?.ok_or(refused)?;
        if header.path != name.as_bytes() || header.kind != Kind::File || header.size > limit {
            return Err(refused);
        }
        let mut data = Vec::new();
        archive
            .content(|chunk| data.extend_from_slice(chunk))
            .map_err(|_| refused)?;
        Ok(data)
    };
    let manifest = member("manifest", MAX_MANIFEST_BYTES)?;
    if !manifest_matches(&manifest, digest, components) {
        return Err(refused);
    }
    let text = String::from_utf8(manifest).map_err(|_| refused)?;
    let mut result = Vec::new();
    for (line, component) in text.lines().skip(1).zip(components) {
        let listed_digest = line.rsplit(' ').next().ok_or(refused)?;
        let kind = component.kind.as_str();
        let slug = component.slug.as_str();
        let list = member(&format!("{kind}-{slug}.files"), MAX_LIST_BYTES)?;
        if hex(&list).as_str() != listed_digest {
            return Err(refused);
        }
        let files = parse_list(&list).ok_or(refused)?;
        for (path, want) in &files {
            let data = member(&format!("{kind}/{slug}/{path}"), MAX_COMPONENT_FILE_BYTES)?;
            if hex(&data).as_str() != want {
                return Err(refused);
            }
        }
        result.push(files);
    }
    if archive.next().map_err(|_| refused)?.is_some() {
        return Err(refused);
    }
    Ok(result)
}

/// The folder that holds a component: `html/wp-content/plugins`,
/// `html/wp-content/themes`, or, for core (D-086), the site root `html`.
pub(crate) fn parent_folder(layout: &SiteLayout, kind: UpdateKind) -> PathBuf {
    layout.root.join(match kind {
        UpdateKind::Plugin => "html/wp-content/plugins",
        UpdateKind::Theme => "html/wp-content/themes",
        UpdateKind::Core => "html",
    })
}

/// The hidden name of the unpacked new release beside the installed folder.
/// WordPress skips folders whose name starts with a dot.
pub(crate) fn new_name(operation: &Id, slug: &str) -> String {
    format!(".rustiron-new-{}-{slug}", operation.as_str())
}

/// The hidden name the installed folder moves to during the swap.
pub(crate) fn old_name(operation: &Id, slug: &str) -> String {
    format!(".rustiron-old-{}-{slug}", operation.as_str())
}

/// The hidden name a failed new folder moves to during a rollback.
fn failed_name(operation: &Id, slug: &str) -> String {
    format!(".rustiron-failed-{}-{slug}", operation.as_str())
}

/// The fixed version-report script and its input and report names.
const VERSIONS_SCRIPT: &str = include_str!("site_update_assets/versions.php");
const SCRIPT_NAME: &str = "rustiron-update";
const COMPONENTS_INPUT: &str = "rustiron-update.components";

/// W530 (D-087): the fixed read-only inventory script and its name.
const INVENTORY_SCRIPT: &str = include_str!("site_update_assets/inventory.php");
const INVENTORY_NAME: &str = "rustiron-update-inventory";

/// W530 (D-087): the site's installed core, plugins, and themes with their
/// versions, read by the site's own PHP from headers only. The report must
/// be the site's own.
pub(crate) fn inventory(layout: &SiteLayout) -> Result<serde_json::Value, ExecutorError> {
    let (report, _) = provision::run_site_php(layout, INVENTORY_NAME, INVENTORY_SCRIPT, &[])?;
    if report["user"] != layout.account.as_str()
        || !report["core"]["version"].is_string()
        || !report["plugins"].is_array()
        || !report["themes"].is_array()
    {
        return Err(failed("inventory report"));
    }
    Ok(report)
}

/// The `kind slug` lines the version script reads. W527 (D-086): with
/// `upgrade`, a core line ends in ` upgrade`, so the script runs
/// `wp_upgrade()` before it reports.
pub(crate) fn components_input(components: &[UpdateComponent], upgrade: bool) -> String {
    components
        .iter()
        .map(|component| {
            let mode = if upgrade && component.kind == UpdateKind::Core {
                " upgrade"
            } else {
                ""
            };
            format!(
                "{} {}{mode}\n",
                component.kind.as_str(),
                component.slug.as_str()
            )
        })
        .collect()
}

/// Whether the version report is the site's own and states, in order, each
/// component's expected version.
pub(crate) fn versions_match(
    report: &serde_json::Value,
    account: &str,
    components: &[UpdateComponent],
    expected: impl Fn(&UpdateComponent) -> &ComponentVersion,
) -> bool {
    let Some(rows) = report["components"].as_array() else {
        return false;
    };
    report["user"] == account
        && rows.len() == components.len()
        && rows.iter().zip(components).all(|(row, component)| {
            row["kind"] == component.kind.as_str()
                && row["slug"] == component.slug.as_str()
                && row["version"] == expected(component).as_str()
        })
}

/// Runs the version script as the site and checks the versions.
fn check_versions(
    layout: &SiteLayout,
    components: &[UpdateComponent],
    expected: impl Fn(&UpdateComponent) -> &ComponentVersion,
    upgrade: bool,
) -> Result<(), ExecutorError> {
    let input = components_input(components, upgrade);
    let (report, _) = provision::run_site_php(
        layout,
        SCRIPT_NAME,
        VERSIONS_SCRIPT,
        &[(COMPONENTS_INPUT, input.as_bytes())],
    )?;
    if versions_match(&report, &layout.account, components, expected) {
        Ok(())
    } else {
        eprintln!("{{\"scope\":\"site_update\",\"step_failure\":\"versions differ\"}}");
        Err(ExecutorError::StepFailed)
    }
}

/// Everything an update step needs, from the journal, the trust anchor, and
/// the enrolled OLS policy. Nothing comes from a request.
pub(crate) struct UpdateContext<'a> {
    /// The journal's update.
    pub(crate) update: &'a rustiron_journal::SiteUpdate,
    /// The site's served hostname, from its provision.
    pub(crate) hostname: &'a Hostname,
    /// The enrolled HTTP listener.
    pub(crate) address: &'a str,
    /// The enrolled TLS listener, if any.
    pub(crate) tls_address: Option<&'a str>,
    /// The update intake folder.
    pub(crate) intake_dir: &'a Path,
    /// The intake's owner (root).
    pub(crate) owner: u32,
    /// W517: the trust anchor, for the store jobs of the rollback.
    pub(crate) anchor: &'a crate::TrustAnchor,
    /// W517: the update's capture, from the journal.
    pub(crate) capture: Option<&'a rustiron_journal::Capture>,
}

fn failed(what: &'static str) -> ExecutorError {
    eprintln!(
        "{}",
        serde_json::json!({"scope": "site_update", "step_failure": what})
    );
    ExecutorError::StepFailed
}

/// Runs one recorded update step.
pub(crate) fn run_step(context: &UpdateContext<'_>, step: UpdateStep) -> Result<(), ExecutorError> {
    let layout = SiteLayout::derive(&context.update.site_id);
    let uid = provision::account_uid(&provision::read_etc("passwd")?, &layout.account)
        .ok_or(ExecutorError::StepFailed)?;
    match step {
        UpdateStep::Unpack => unpack_step(context, &layout, uid),
        UpdateStep::Swap => swap_step(context, &layout, uid),
        UpdateStep::Script => {
            let checked =
                check_versions(&layout, &context.update.components, |c| &c.to_version, true);
            // W527 (D-086): the maintenance page ends after the upgrade; a
            // failed script leaves it for the rollback, which removes it.
            if checked.is_ok() && is_core(context.update) {
                remove_maintenance(&layout, uid)?;
            }
            checked
        }
        UpdateStep::Health => health_step(context, &layout, uid),
    }
}

/// The site's installed versions are the from-versions; the recipe holds
/// exactly the signed files; each component unpacks as the site beside its
/// installed folder, with the site's content label, and its tree is exactly
/// the listed files with their digests.
fn unpack_step(
    context: &UpdateContext<'_>,
    layout: &SiteLayout,
    uid: u32,
) -> Result<(), ExecutorError> {
    let update = context.update;
    check_versions(layout, &update.components, |c| &c.from_version, false)?;
    let recipe = intake_recipe(context.intake_dir, context.owner, &update.site_id)?;
    let listed = recipe_files(&recipe, &update.recipe_digest, &update.components)?;
    // W528-F3: the recipe copy and the unpacked tree count against the
    // site's quota; a short quota fails here, before anything is written.
    quota_headroom(&recipe, uid)?;
    let level = crate::capture::site_level(layout)?;
    let label = format!("system_u:object_r:httpd_sys_content_t:{level}");
    for (component, files) in update.components.iter().zip(&listed) {
        let parent = parent_folder(layout, component.kind);
        let parent_text = provision::path_str(&parent)?.to_owned();
        let parent_dir = files::open_traversable_directory(&parent, uid)?;
        let slug = component.slug.as_str();
        let new = new_name(&update.operation_id, slug);
        for name in [new.as_str(), &old_name(&update.operation_id, slug)] {
            if fs::statat(&parent_dir, name, fs::AtFlags::SYMLINK_NOFOLLOW).is_ok() {
                return Err(failed("an update folder exists"));
            }
        }
        let member = format!("{}/{slug}/", component.kind.as_str());
        provision::run_unpack_job(
            layout,
            uid,
            &recipe,
            "rustiron-update-recipe.tar",
            |source| {
                let mut args = provision::unpack_properties(&layout.account, &level, &parent_text);
                args.extend(["--", "/usr/bin/tar", "--extract"].map(String::from));
                args.push(format!("--file={source}"));
                args.push(format!("--directory={parent_text}"));
                args.push(format!("--transform=s,^{member},{new}/,"));
                args.extend(
                    [
                        "--no-same-owner",
                        "--numeric-owner",
                        "--no-same-permissions",
                        "--keep-old-files",
                    ]
                    .map(String::from),
                );
                args.push(member.clone());
                args
            },
        )?;
        let folder = files::open_child_directory(&parent_dir, &new, uid)
            .map_err(|_| failed("unpacked folder"))?;
        let census = crate::census::census_labelled(
            &folder,
            uid,
            label.as_bytes(),
            &crate::census::label_of,
            crate::census::BOUNDS,
        )?;
        if !provision::tree_matches(&census, files.len()) {
            return Err(failed("unpacked tree census"));
        }
        crate::page_cache::verify_listed(&folder, uid, files)?;
    }
    Ok(())
}

/// KiB that `bytes` take in 4 KiB blocks.
fn block_kib(bytes: u64) -> u64 {
    bytes.div_ceil(4096) * 4
}

/// W528-F3: the space (KiB) and inodes that an unpack needs in the site's
/// quota: the recipe's copy in the site's `tmp`, and each component member
/// and its folders, in 4 KiB blocks. It errs high: one block per folder.
pub(crate) fn unpack_need(recipe: &[u8]) -> Result<(u64, u64), ExecutorError> {
    let refused = ExecutorError::PreconditionChanged;
    let mut archive = Archive::new(recipe);
    let (mut kib, mut inodes) = (block_kib(recipe.len() as u64), 1_u64);
    let mut folders = std::collections::BTreeSet::new();
    while let Some(header) = archive.next().map_err(|_| refused)? {
        archive.content(|_| ()).map_err(|_| refused)?;
        let path = String::from_utf8(header.path).map_err(|_| refused)?;
        if header.kind != Kind::File || path == "manifest" || path.ends_with(".files") {
            continue;
        }
        kib += block_kib(header.size);
        inodes += 1;
        let mut parent = path.as_str();
        while let Some((folder, _)) = parent.rsplit_once('/') {
            folders.insert(folder.to_owned());
            parent = folder;
        }
    }
    let count = folders.len() as u64;
    Ok((kib + 4 * count, inodes + count))
}

/// Whether a quota row has room for `kib` and `inodes`; a hard limit of 0
/// is no limit. Rustiron sets no soft limits.
pub(crate) fn quota_fits(row: &crate::quota::QuotaRow, kib: u64, inodes: u64) -> bool {
    (row.block_hard_kib == 0 || row.block_used_kib.saturating_add(kib) <= row.block_hard_kib)
        && (row.inode_hard == 0 || row.inode_used.saturating_add(inodes) <= row.inode_hard)
}

/// W528-F3: refuses the unpack when the site's quota has no room for it,
/// and logs the need and the room. A site without a quota entry has no
/// limit.
fn quota_headroom(recipe: &[u8], uid: u32) -> Result<(), ExecutorError> {
    use crate::quota::QuotaHost;
    let (kib, inodes) = unpack_need(recipe)?;
    let mut host = crate::quota::SystemQuota;
    let mount = crate::quota::locate(&mut host).map_err(|_| failed("quota mount"))?;
    let text = host.report(&mount.mount_point)?;
    let Some(row) = crate::quota::report_row(&text, uid).map_err(|_| failed("quota report"))?
    else {
        return Ok(());
    };
    if quota_fits(&row, kib, inodes) {
        return Ok(());
    }
    eprintln!(
        "{}",
        serde_json::json!({
            "scope": "site_update",
            "step_failure": "quota_headroom",
            "need_kib": kib,
            "need_inodes": inodes,
            "free_kib": row.block_hard_kib.saturating_sub(row.block_used_kib),
            "free_inodes": row.inode_hard.saturating_sub(row.inode_used),
        })
    );
    Err(ExecutorError::StepFailed)
}

/// Whether `name` in `parent` is a real directory of the site.
fn site_folder(parent: &OwnedFd, name: &str, uid: u32) -> bool {
    fs::statat(parent, name, fs::AtFlags::SYMLINK_NOFOLLOW).is_ok_and(|stat| {
        FileType::from_raw_mode(stat.st_mode) == FileType::Directory && stat.st_uid == uid
    })
}

fn rename_new(parent: &OwnedFd, from: &str, to: &str) -> Result<(), ExecutorError> {
    fs::renameat_with(parent, from, parent, to, fs::RenameFlags::NOREPLACE)
        .map_err(|_| failed("rename"))
}

/// For each component in plan order, the installed folder moves aside and
/// the unpacked one takes its name. Root renames by descriptor; nothing
/// is copied, followed, or overwritten.
fn swap_step(
    context: &UpdateContext<'_>,
    layout: &SiteLayout,
    uid: u32,
) -> Result<(), ExecutorError> {
    let update = context.update;
    if is_core(update) {
        return swap_core(update, layout, uid);
    }
    for component in &update.components {
        let parent =
            files::open_traversable_directory(&parent_folder(layout, component.kind), uid)?;
        let slug = component.slug.as_str();
        let new = new_name(&update.operation_id, slug);
        let old = old_name(&update.operation_id, slug);
        if !site_folder(&parent, slug, uid) || !site_folder(&parent, &new, uid) {
            return Err(failed("swap folders"));
        }
        rename_new(&parent, slug, &old)?;
        rename_new(&parent, &new, slug)?;
    }
    Ok(())
}

/// W527 (D-086): whether the update is a core update (core is alone).
fn is_core(update: &rustiron_journal::SiteUpdate) -> bool {
    update
        .components
        .iter()
        .any(|component| component.kind == UpdateKind::Core)
}

/// WordPress's maintenance file in the site root; while it exists, visitors
/// get WordPress's maintenance page.
const MAINTENANCE: &str = ".maintenance";

/// The site root, opened as the site's own directory.
fn site_root(layout: &SiteLayout, uid: u32) -> Result<OwnedFd, ExecutorError> {
    files::open_traversable_directory(&parent_folder(layout, UpdateKind::Core), uid)
}

/// Creates the hidden folder `name` in `parent`, owned by the site, with the
/// content label of the site root.
fn site_mkdir(
    layout: &SiteLayout,
    parent: &OwnedFd,
    name: &str,
    uid: u32,
) -> Result<(), ExecutorError> {
    fs::mkdirat(parent, name, Mode::from_raw_mode(0o755)).map_err(|_| failed("mkdir"))?;
    let folder = files::open_child_directory(parent, name, 0).map_err(|_| failed("mkdir"))?;
    fs::fchown(
        &folder,
        Some(fs::Uid::from_raw(uid)),
        Some(fs::Gid::from_raw(uid)),
    )
    .map_err(|_| failed("mkdir owner"))?;
    let path = parent_folder(layout, UpdateKind::Core).join(name);
    provision::run(
        "/usr/sbin/restorecon",
        &["-F", "--", provision::path_str(&path)?],
    )
}

/// Writes `.maintenance` in the site root, owned by the site, with the
/// root's label. An existing one is refused: the site is not ours to touch.
fn write_maintenance(layout: &SiteLayout, root: &OwnedFd, uid: u32) -> Result<(), ExecutorError> {
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let file = fs::openat(root, MAINTENANCE, flags, Mode::from_raw_mode(0o644))
        .map_err(|_| failed("maintenance file"))?;
    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| failed("clock"))?
        .as_secs();
    let text = format!("<?php $upgrading = {started}; ?>\n");
    rustix::io::write(&file, text.as_bytes()).map_err(|_| failed("maintenance file"))?;
    fs::fchown(
        &file,
        Some(fs::Uid::from_raw(uid)),
        Some(fs::Gid::from_raw(uid)),
    )
    .map_err(|_| failed("maintenance owner"))?;
    let path = parent_folder(layout, UpdateKind::Core).join(MAINTENANCE);
    provision::run(
        "/usr/sbin/restorecon",
        &["-F", "--", provision::path_str(&path)?],
    )
}

/// W543 (D-089): a restore's maintenance page. A file left by an earlier
/// attempt of the same restore is replaced.
pub(crate) fn enter_maintenance(layout: &SiteLayout, uid: u32) -> Result<(), ExecutorError> {
    remove_maintenance(layout, uid)?;
    write_maintenance(layout, &site_root(layout, uid)?, uid)
}

/// Removes `.maintenance`; an absent file is not an error.
pub(crate) fn remove_maintenance(layout: &SiteLayout, uid: u32) -> Result<(), ExecutorError> {
    match fs::unlinkat(&site_root(layout, uid)?, MAINTENANCE, fs::AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => Ok(()),
        Err(_) => Err(failed("maintenance removal")),
    }
}

/// The names in a directory, without `.` and `..`, sorted.
fn entries(directory: &OwnedFd) -> Result<Vec<String>, ExecutorError> {
    let mut names = Vec::new();
    for entry in fs::Dir::read_from(directory).map_err(|_| failed("read folder"))? {
        let entry = entry.map_err(|_| failed("read folder"))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name != "." && name != ".." {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// Whether `name` in `parent` is the site's own folder or regular file.
fn site_entry(parent: &OwnedFd, name: &str, uid: u32) -> Option<FileType> {
    let stat = fs::statat(parent, name, fs::AtFlags::SYMLINK_NOFOLLOW).ok()?;
    let kind = FileType::from_raw_mode(stat.st_mode);
    (stat.st_uid == uid && matches!(kind, FileType::Directory | FileType::RegularFile))
        .then_some(kind)
}

/// W527 (D-086): the core swap. `.maintenance` goes in first. Then each
/// top-level entry of the unpacked release (`wp-admin`, `wp-includes`, and
/// the core root files) replaces the installed one by rename; the installed
/// one moves into the hidden old folder first. No other root file moves.
fn swap_core(
    update: &rustiron_journal::SiteUpdate,
    layout: &SiteLayout,
    uid: u32,
) -> Result<(), ExecutorError> {
    let operation = &update.operation_id;
    let slug = rustiron_contracts::approval::CORE_SLUG;
    let root = site_root(layout, uid)?;
    let new = new_name(operation, slug);
    let old = old_name(operation, slug);
    if !site_folder(&root, &new, uid)
        || fs::statat(&root, &old, fs::AtFlags::SYMLINK_NOFOLLOW).is_ok()
    {
        return Err(failed("swap folders"));
    }
    write_maintenance(layout, &root, uid)?;
    site_mkdir(layout, &root, &old, uid)?;
    let new_dir = files::open_child_directory(&root, &new, uid)?;
    let old_dir = files::open_child_directory(&root, &old, uid)?;
    for name in entries(&new_dir)? {
        let incoming = site_entry(&new_dir, &name, uid).ok_or_else(|| failed("release entry"))?;
        if let Some(installed) = site_entry(&root, &name, uid) {
            if installed != incoming {
                return Err(failed("installed entry kind"));
            }
            fs::renameat_with(&root, &name, &old_dir, &name, fs::RenameFlags::NOREPLACE)
                .map_err(|_| failed("rename old"))?;
        } else if fs::statat(&root, &name, fs::AtFlags::SYMLINK_NOFOLLOW).is_ok() {
            return Err(failed("foreign root entry"));
        }
        fs::renameat_with(&new_dir, &name, &root, &name, fs::RenameFlags::NOREPLACE)
            .map_err(|_| failed("rename new"))?;
    }
    Ok(())
}

/// The release names whose root entry is the new release's: the name left
/// the new folder, and the root holds it.
fn new_root_entries(
    top: &[String],
    still_new: impl Fn(&str) -> bool,
    present: impl Fn(&str) -> bool,
) -> Vec<String> {
    top.iter()
        .filter(|name| !still_new(name) && present(name))
        .cloned()
        .collect()
}

/// W527 (D-086): the code half of a core rollback. For each top-level
/// name of the signed release: if it left the new folder, the root entry
/// is new and moves to the failed folder; then each entry of the old
/// folder goes back to the root. A name still in the new folder was never
/// swapped. Returns whether anything had been swapped.
fn rollback_core(
    context: &UpdateContext<'_>,
    layout: &SiteLayout,
    uid: u32,
) -> Result<bool, ExecutorError> {
    let update = context.update;
    let operation = &update.operation_id;
    let slug = rustiron_contracts::approval::CORE_SLUG;
    let root = site_root(layout, uid)?;
    let old = old_name(operation, slug);
    if !site_folder(&root, &old, uid) {
        return Ok(false);
    }
    let recipe = intake_recipe(context.intake_dir, context.owner, &update.site_id)?;
    let listed = recipe_files(&recipe, &update.recipe_digest, &update.components)?;
    let mut top: Vec<String> = listed
        .iter()
        .flatten()
        .filter_map(|(path, _)| path.split('/').next().map(str::to_owned))
        .collect();
    top.sort();
    top.dedup();
    let new = new_name(operation, slug);
    let failed_folder = failed_name(operation, slug);
    let new_dir = files::open_child_directory(&root, &new, uid).ok();
    if !site_folder(&root, &failed_folder, uid) {
        site_mkdir(layout, &root, &failed_folder, uid)?;
    }
    let failed_dir = files::open_child_directory(&root, &failed_folder, uid)?;
    let old_dir = files::open_child_directory(&root, &old, uid)?;
    let still_new = |name: &str| {
        new_dir
            .as_ref()
            .is_some_and(|dir| fs::statat(dir, name, fs::AtFlags::SYMLINK_NOFOLLOW).is_ok())
    };
    let present = |name: &str| site_entry(&root, name, uid).is_some();
    for name in new_root_entries(&top, still_new, present) {
        fs::renameat_with(
            &root,
            name.as_str(),
            &failed_dir,
            name.as_str(),
            fs::RenameFlags::NOREPLACE,
        )
        .map_err(|_| failed("rename failed"))?;
    }
    for name in entries(&old_dir)? {
        fs::renameat_with(
            &old_dir,
            name.as_str(),
            &root,
            name.as_str(),
            fs::RenameFlags::NOREPLACE,
        )
        .map_err(|_| failed("rename back"))?;
    }
    Ok(true)
}

/// The site answers its own marker (over HTTPS after the exact redirect of
/// a site that sends HTTP to HTTPS), its WordPress login through PHP, and
/// its home page with a status under 500. Then the old folders leave
/// `html` for the site's `tmp` and are removed as the site; a failed
/// removal is logged and leaves only hidden folders.
fn health_step(
    context: &UpdateContext<'_>,
    layout: &SiteLayout,
    uid: u32,
) -> Result<(), ExecutorError> {
    site_answers(
        context.address,
        context.tls_address,
        context.hostname,
        layout,
    )?;
    // W527: core leaves its emptied new folder beside the old one.
    let removed = move_out_and_remove(context, layout, uid, &old_name)
        .and_then(|()| move_out_and_remove(context, layout, uid, &new_name));
    eprintln!(
        "{}",
        serde_json::json!({"scope": "site_update", "old_folders_removed": removed.is_ok()})
    );
    Ok(())
}

/// The site's marker, WordPress login, and home page answer.
/// W543: also a restore's Health step.
pub(crate) fn site_answers(
    address: &str,
    tls_address: Option<&str>,
    hostname: &Hostname,
    layout: &SiteLayout,
) -> Result<(), ExecutorError> {
    let name = hostname.as_str();
    crate::ols::probe_identity_or_https(address, tls_address, &layout.account, hostname)
        .map_err(|_| failed("site marker"))?;
    let (login, note) = crate::ejection::wordpress_answers(address, tls_address, hostname);
    if !login {
        eprintln!(
            "{}",
            serde_json::json!({"scope": "site_update", "step_failure": "login", "last": note})
        );
        return Err(ExecutorError::StepFailed);
    }
    let (status, headers, _) = crate::ols::get_response(address, name, "/")?;
    let redirected = (300..400).contains(&status)
        && headers.lines().any(|line| {
            line.split_once(':').is_some_and(|(key, value)| {
                key.trim().eq_ignore_ascii_case("location")
                    && value.trim().starts_with(&format!("https://{name}/"))
            })
        });
    let home = match (redirected, tls_address) {
        (true, Some(tls)) => crate::ols::get_response_tls(tls, name, "/")?.0,
        _ => status,
    };
    if home >= 500 {
        return Err(failed("home page"));
    }
    Ok(())
}

/// Moves each component's `name(...)` folder, when present, from `html`
/// into the site's `tmp` by descriptor, then removes them as the site in
/// the unpack domain with only `tmp` writable.
fn move_out_and_remove(
    context: &UpdateContext<'_>,
    layout: &SiteLayout,
    uid: u32,
    name: &dyn Fn(&Id, &str) -> String,
) -> Result<(), ExecutorError> {
    let tmp = layout.root.join("tmp");
    let tmp_dir = files::open_traversable_directory(&tmp, uid)?;
    let mut moved = Vec::new();
    for component in &context.update.components {
        let parent =
            files::open_traversable_directory(&parent_folder(layout, component.kind), uid)?;
        let folder = name(&context.update.operation_id, component.slug.as_str());
        if !site_folder(&parent, &folder, uid) {
            continue;
        }
        let target = format!("{folder}-{}", component.kind.as_str());
        fs::renameat_with(
            &parent,
            &folder,
            &tmp_dir,
            &target,
            fs::RenameFlags::NOREPLACE,
        )
        .map_err(|_| failed("move to tmp"))?;
        moved.push(provision::path_str(&tmp.join(&target))?.to_owned());
    }
    if moved.is_empty() {
        return Ok(());
    }
    // W518-F4: a moved folder keeps the content label of `html`, where the
    // unpack domain may not remove names (W501-F1). Root relabels it to the
    // site's `tmp` context first; restorecon relabels links, never follows.
    let mut relabel = vec!["-R", "-F", "--"];
    relabel.extend(moved.iter().map(String::as_str));
    provision::run("/usr/sbin/restorecon", &relabel)?;
    let level = crate::capture::site_level(layout)?;
    let mut args =
        provision::unpack_properties(&layout.account, &level, provision::path_str(&tmp)?);
    args.extend(["--", "/usr/bin/rm", "-rf", "--one-file-system", "--"].map(String::from));
    args.extend(moved);
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    provision::run("/usr/bin/systemd-run", &borrowed)
}

/// The code half of the rollback: for each component, a swapped folder
/// moves aside and the old folder takes its name again; every new or failed
/// folder then leaves `html` and is removed as the site. Returns whether
/// any component had been swapped, so new code may have run.
pub(crate) fn rollback_code(context: &UpdateContext<'_>) -> Result<bool, ExecutorError> {
    let layout = SiteLayout::derive(&context.update.site_id);
    let uid = provision::account_uid(&provision::read_etc("passwd")?, &layout.account)
        .ok_or(ExecutorError::StepFailed)?;
    let operation = &context.update.operation_id;
    if is_core(context.update) {
        let swapped = rollback_core(context, &layout, uid)?;
        remove_maintenance(&layout, uid)?;
        move_out_and_remove(context, &layout, uid, &new_name)?;
        move_out_and_remove(context, &layout, uid, &failed_name)?;
        move_out_and_remove(context, &layout, uid, &old_name)?;
        return Ok(swapped);
    }
    let mut swapped = false;
    for component in context.update.components.iter().rev() {
        let parent =
            files::open_traversable_directory(&parent_folder(&layout, component.kind), uid)?;
        let slug = component.slug.as_str();
        let old = old_name(operation, slug);
        if !site_folder(&parent, &old, uid) {
            continue;
        }
        swapped = true;
        if site_folder(&parent, slug, uid) {
            rename_new(&parent, slug, &failed_name(operation, slug))?;
        }
        rename_new(&parent, &old, slug)?;
    }
    move_out_and_remove(context, &layout, uid, &new_name)?;
    move_out_and_remove(context, &layout, uid, &failed_name)?;
    Ok(swapped)
}

/// The rollback after a failed step. The code always goes back first. When
/// a component had been swapped, new code may have run against the
/// database, so the database comes back from the update's capture, and the
/// site's health is checked again.
pub(crate) fn rollback(context: &UpdateContext<'_>) -> Result<(), ExecutorError> {
    let swapped_now = rollback_code(context)?;
    // W518: the journal, not the file system, says whether new code may have
    // run: a rollback run again after its code half finished finds nothing
    // swapped on disk, yet the database must still come back.
    let swap_began = context
        .update
        .steps
        .iter()
        .any(|record| record.step == UpdateStep::Swap);
    if !swapped_now && !swap_began {
        return Ok(());
    }
    restore_database(context)?;
    let layout = SiteLayout::derive(&context.update.site_id);
    site_answers(
        context.address,
        context.tls_address,
        context.hostname,
        &layout,
    )
}

/// The fetched tree and the import folder in the site's `tmp`.
const FETCH_FOLDERS: [&str; 2] = [crate::layout::CLONE_RESTORE_DIR, "import"];

/// Removes `FETCH_FOLDERS` from the site's `tmp` as the site.
pub(crate) fn clear_fetch(layout: &SiteLayout, level: &str) -> Result<(), ExecutorError> {
    let tmp = layout.root.join("tmp");
    let mut args = provision::unpack_properties(&layout.account, level, provision::path_str(&tmp)?);
    args.extend(["--", "/usr/bin/rm", "-rf", "--one-file-system", "--"].map(String::from));
    for folder in FETCH_FOLDERS {
        args.push(provision::path_str(&tmp.join(folder))?.to_owned());
    }
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    provision::run("/usr/bin/systemd-run", &borrowed)
}

/// A store job's unit name: `rustiron-<kind>-<account>-<step>-<random>`.
pub(crate) fn store_unit(kind: &str, account: &str, step: &str) -> Result<String, ExecutorError> {
    let mut random = [0_u8; 4];
    rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty())
        .map_err(|_| ExecutorError::Unavailable)?;
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!("rustiron-{kind}-{account}-{step}-{suffix}"))
}

/// W517 (D-084): the update's capture comes back into the site's own
/// database. The enrolled destination must still be the one the capture
/// wrote to. As for a clone (D-078), the store worker restores the
/// snapshot into the site's `tmp` as the site with the site's fetch key
/// pair, after the size check; the dump moves to `tmp/import` and the
/// worker imports it as the site's database user. The fetched tree is
/// removed before and after.
fn restore_database(context: &UpdateContext<'_>) -> Result<(), ExecutorError> {
    let site = &context.update.site_id;
    let layout = SiteLayout::derive(site);
    let level = crate::capture::site_level(&layout)?;
    let capture = context.capture.ok_or_else(|| failed("capture record"))?;
    let snapshot = capture
        .snapshot_id
        .as_deref()
        .ok_or_else(|| failed("capture snapshot"))?;
    let owner = context.anchor.owner_uid;
    let loaded = crate::policy::load(
        &files::open_trusted_directory(&context.anchor.policy_dir, owner)?,
        owner,
    )?;
    let destination = loaded.product_backup.ok_or(ExecutorError::Unavailable)?;
    if capture.intent.site_id != *site
        || capture.backup_policy_digest.as_ref() != Some(&destination.digest())
        || destination.repository_id(site).is_none()
    {
        return Err(failed("capture destination"));
    }
    clear_fetch(&layout, &level)?;
    let restored = (|| {
        let (size, count) = crate::store_network::site_restore_size(
            context.anchor,
            &destination,
            site,
            &level,
            snapshot,
            store_unit("update", &layout.account, "size")?,
        )?;
        if !crate::restore::within_ceilings(size, count) {
            return Err(failed("restore size"));
        }
        crate::store_network::site_restore(
            context.anchor,
            &destination,
            site,
            &level,
            snapshot,
            store_unit("update", &layout.account, "fetch")?,
        )?;
        import_fetched_dump(&layout, &level)
    })();
    let cleared = clear_fetch(&layout, &level);
    eprintln!(
        "{}",
        serde_json::json!({"scope": "site_update", "database_restored": restored.is_ok(), "fetch_cleared": cleared.is_ok()})
    );
    restored
}

/// The fetched dump of the site's own root moves to `tmp/import` as the
/// site, must be a single-link regular file of the site, and is imported.
pub(crate) fn import_fetched_dump(layout: &SiteLayout, level: &str) -> Result<(), ExecutorError> {
    let fetched_dump = layout
        .root
        .join("tmp")
        .join(crate::layout::CLONE_RESTORE_DIR)
        .join(provision::path_str(&layout.root)?.trim_start_matches('/'))
        .join("tmp")
        .join(crate::layout::CAPTURE_DUMP_FILE);
    import_dump_file(layout, level, &fetched_dump)
}

/// Moves `fetched_dump` (inside the site's `tmp/`) to `tmp/import/` as the site
/// account, checks it, and imports it as the site's own database user
/// (`site-import`). W663-E3: app MariaDB restores use this too, never the
/// MariaDB root socket, because a capture's dump is site-writable before upload.
pub(crate) fn import_dump_file(
    layout: &SiteLayout,
    level: &str,
    fetched_dump: &Path,
) -> Result<(), ExecutorError> {
    let uid = crate::import::site_uid(layout)?;
    let tmp = layout.root.join("tmp");
    let import = tmp.join("import");
    for command in [
        vec![
            "/usr/bin/mkdir".to_owned(),
            "--mode=0700".to_owned(),
            "--".to_owned(),
            provision::path_str(&import)?.to_owned(),
        ],
        vec![
            "/usr/bin/mv".to_owned(),
            "--no-clobber".to_owned(),
            "--no-target-directory".to_owned(),
            "--".to_owned(),
            provision::path_str(fetched_dump)?.to_owned(),
            provision::path_str(&import.join(crate::layout::CAPTURE_DUMP_FILE))?.to_owned(),
        ],
    ] {
        let mut args =
            provision::unpack_properties(&layout.account, level, provision::path_str(&tmp)?);
        args.push("--".to_owned());
        args.extend(command);
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        provision::run("/usr/bin/systemd-run", &borrowed)?;
    }
    let folder = files::open_child_directory(
        &files::open_traversable_directory(&tmp, uid)?,
        "import",
        uid,
    )?;
    let stat = fs::statat(
        &folder,
        crate::layout::CAPTURE_DUMP_FILE,
        fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|_| failed("fetched dump"))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_nlink != 1
        || stat.st_uid != uid
        || stat.st_size <= 0
    {
        return Err(failed("fetched dump"));
    }
    crate::import::import_dump(layout, stat.st_size as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustiron_contracts::approval::{ComponentSlug, ComponentVersion, UpdateKind};

    const LINE_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn component(kind: UpdateKind, slug: &str, from: &str, to: &str) -> UpdateComponent {
        UpdateComponent {
            kind,
            slug: ComponentSlug::try_from(slug.to_owned()).unwrap(),
            from_version: ComponentVersion::try_from(from.to_owned()).unwrap(),
            to_version: ComponentVersion::try_from(to.to_owned()).unwrap(),
        }
    }

    fn components() -> Vec<UpdateComponent> {
        vec![
            component(UpdateKind::Plugin, "hello-dolly", "1.7.1", "1.7.2"),
            component(UpdateKind::Theme, "twentytwentyfour", "1.2", "1.3"),
        ]
    }

    fn manifest(lines: &[&str]) -> Vec<u8> {
        let mut text = format!("{MANIFEST_SCHEMA}\n");
        for line in lines {
            text.push_str(line);
            text.push('\n');
        }
        text.into_bytes()
    }

    fn digest(bytes: &[u8]) -> Sha256Digest {
        Sha256Digest::from_bytes(Sha256::digest(bytes).into())
    }

    fn good() -> Vec<u8> {
        manifest(&[
            &format!("plugin hello-dolly 1.7.2 {LINE_HEX} {LINE_HEX}"),
            &format!("theme twentytwentyfour 1.3 {LINE_HEX} {LINE_HEX}"),
        ])
    }

    #[test]
    fn only_the_signed_manifest_naming_the_plan_components_in_order_matches() {
        let bytes = good();
        assert!(manifest_matches(&bytes, &digest(&bytes), &components()));
        // Another digest, another order, a missing or extra line, another
        // version or slug, a bad hex field, or trailing bytes.
        assert!(!manifest_matches(&bytes, &digest(b"x"), &components()));
        let mut reversed = components();
        reversed.reverse();
        assert!(!manifest_matches(&bytes, &digest(&bytes), &reversed));
        for altered in [
            manifest(&[&format!("plugin hello-dolly 1.7.2 {LINE_HEX} {LINE_HEX}")]),
            manifest(&[
                &format!("plugin hello-dolly 1.7.2 {LINE_HEX} {LINE_HEX}"),
                &format!("theme twentytwentyfour 1.3 {LINE_HEX} {LINE_HEX}"),
                &format!("theme other 1.0 {LINE_HEX} {LINE_HEX}"),
            ]),
            manifest(&[
                &format!("plugin hello-dolly 1.7.1 {LINE_HEX} {LINE_HEX}"),
                &format!("theme twentytwentyfour 1.3 {LINE_HEX} {LINE_HEX}"),
            ]),
            manifest(&[
                &format!("plugin hello_dolly 1.7.2 {LINE_HEX} {LINE_HEX}"),
                &format!("theme twentytwentyfour 1.3 {LINE_HEX} {LINE_HEX}"),
            ]),
            manifest(&[
                &format!(
                    "plugin hello-dolly 1.7.2 {} {LINE_HEX}",
                    LINE_HEX.to_uppercase()
                ),
                &format!("theme twentytwentyfour 1.3 {LINE_HEX} {LINE_HEX}"),
            ]),
            manifest(&[
                &format!("plugin hello-dolly 1.7.2 {LINE_HEX}"),
                &format!("theme twentytwentyfour 1.3 {LINE_HEX} {LINE_HEX}"),
            ]),
            manifest(&[
                &format!("plugin hello-dolly 1.7.2  {LINE_HEX} {LINE_HEX}"),
                &format!("theme twentytwentyfour 1.3 {LINE_HEX} {LINE_HEX}"),
            ]),
            [good(), b"\n".to_vec()].concat(),
            good()[..good().len() - 1].to_vec(),
            good().replace_schema(),
        ] {
            assert!(
                !manifest_matches(&altered, &digest(&altered), &components()),
                "{}",
                String::from_utf8_lossy(&altered)
            );
        }
    }

    trait ReplaceSchema {
        fn replace_schema(self) -> Vec<u8>;
    }
    impl ReplaceSchema for Vec<u8> {
        fn replace_schema(self) -> Vec<u8> {
            String::from_utf8(self)
                .unwrap()
                .replacen(MANIFEST_SCHEMA, "rustiron-wordpress-update/2", 1)
                .into_bytes()
        }
    }

    /// One ustar member with fixed metadata, as the recipe tool writes.
    fn member(name: &str, data: &[u8], kind: u8) -> Vec<u8> {
        let mut header = [0_u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..107].copy_from_slice(b"0000644");
        header[108..115].copy_from_slice(b"0000000");
        header[116..123].copy_from_slice(b"0000000");
        header[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes());
        header[136..147].copy_from_slice(b"00000000000");
        header[156] = kind;
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        header[148..156].copy_from_slice(b"        ");
        let sum: u32 = header.iter().map(|&b| u32::from(b)).sum();
        header[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        let mut out = header.to_vec();
        out.extend_from_slice(data);
        out.resize(out.len() + (512 - data.len() % 512) % 512, 0);
        out
    }

    fn archive(members: &[Vec<u8>]) -> Vec<u8> {
        let mut out = members.concat();
        out.extend_from_slice(&[0_u8; 1024]);
        out
    }

    #[test]
    fn the_manifest_is_the_first_regular_member_only() {
        let bytes = good();
        let recipe = archive(&[
            member("manifest", &bytes, b'0'),
            member("plugin-hello-dolly.files", b"x", b'0'),
        ]);
        assert_eq!(first_manifest(recipe.as_slice()).unwrap(), bytes);
        for refused in [
            archive(&[member("plugin-hello-dolly.files", b"x", b'0')]),
            archive(&[member("manifest", &bytes, b'2')]),
            archive(&[member("manifest", &vec![b'a'; 4097], b'0')]),
            archive(&[member("./manifest2", &bytes, b'0')]),
            archive(&[]),
            b"not a tar archive".to_vec(),
        ] {
            assert_eq!(
                first_manifest(refused.as_slice()).err(),
                Some(ExecutorError::PreconditionChanged)
            );
        }
    }

    fn hexdigest(bytes: &[u8]) -> String {
        Sha256Digest::from_bytes(Sha256::digest(bytes).into())
            .as_str()
            .to_owned()
    }

    /// A recipe as the tool writes it, for `components` with `files` each.
    fn recipe(files: &[&[(&str, &[u8])]]) -> (Vec<u8>, Sha256Digest) {
        let parts = components();
        let mut lines = Vec::new();
        let mut members = Vec::new();
        for (component, files) in parts.iter().zip(files) {
            let mut sorted: Vec<_> = files.to_vec();
            sorted.sort_by(|a, b| a.0.cmp(b.0));
            let listing: String = sorted
                .iter()
                .map(|(path, data)| format!("{}  {path}\n", hexdigest(data)))
                .collect();
            lines.push(format!(
                "{} {} {} {LINE_HEX} {}",
                component.kind.as_str(),
                component.slug.as_str(),
                component.to_version.as_str(),
                hexdigest(listing.as_bytes())
            ));
            let kind = component.kind.as_str();
            let slug = component.slug.as_str();
            members.push(member(
                &format!("{kind}-{slug}.files"),
                listing.as_bytes(),
                b'0',
            ));
            for (path, data) in sorted {
                members.push(member(&format!("{kind}/{slug}/{path}"), data, b'0'));
            }
        }
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let manifest = manifest(&refs);
        let digest = digest(&manifest);
        let mut all = vec![member("manifest", &manifest, b'0')];
        all.extend(members);
        (archive(&all), digest)
    }

    const PLUGIN: &[(&str, &[u8])] = &[("hello.php", b"<?php // 1.7.2\n"), ("readme.txt", b"r\n")];
    const THEME: &[(&str, &[u8])] = &[
        ("style.css", b"/* Version: 1.3 */\n"),
        ("parts/a.html", b"<a/>\n"),
    ];

    #[test]
    fn every_recipe_member_is_checked_against_the_signed_manifest() {
        let (bytes, signed) = recipe(&[PLUGIN, THEME]);
        let files = recipe_files(&bytes, &signed, &components()).unwrap();
        assert_eq!(
            files[0],
            vec![
                ("hello.php".to_owned(), hexdigest(b"<?php // 1.7.2\n")),
                ("readme.txt".to_owned(), hexdigest(b"r\n")),
            ]
        );
        assert_eq!(files[1][0].0, "parts/a.html");
        // Another digest, a changed file, or an extra member is refused.
        assert!(recipe_files(&bytes, &digest(b"x"), &components()).is_err());
        let changed = String::from_utf8_lossy(&bytes).replace("// 1.7.2", "// 1.7.9");
        assert!(recipe_files(changed.as_bytes(), &signed, &components()).is_err());
        let mut extra = bytes[..bytes.len() - 1024].to_vec();
        extra.extend(member("plugin/hello-dolly/extra.php", b"x", b'0'));
        extra.extend_from_slice(&[0_u8; 1024]);
        assert!(recipe_files(&extra, &signed, &components()).is_err());
        let truncated = &bytes[..bytes.len() - 1536];
        assert!(recipe_files(truncated, &signed, &components()).is_err());
    }

    #[test]
    fn a_file_list_is_sorted_unique_and_safe() {
        let line = |path: &str| format!("{LINE_HEX}  {path}\n");
        assert!(parse_list(format!("{}{}", line("a.php"), line("b/c.php")).as_bytes()).is_some());
        // W518-F1: names from real releases.
        assert!(
            parse_list(
                format!(
                    "{}{}",
                    line("_inc/img/logo@2x.png"),
                    line("fonts/Inter-VariableFont_slnt,wght.woff2")
                )
                .as_bytes()
            )
            .is_some()
        );
        for bad in [
            format!("{}{}", line("b.php"), line("a.php")),
            format!("{}{}", line("a.php"), line("a.php")),
            line("../a.php"),
            line("/a.php"),
            line("a b.php"),
            line("a//b.php"),
            format!("{LINE_HEX} a.php\n"),
            line("a.php").trim_end().to_owned(),
            String::new(),
        ] {
            assert!(parse_list(bad.as_bytes()).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn update_folders_are_hidden_and_derived_from_the_journal() {
        let operation = Id::try_from("op_update1".to_owned()).unwrap();
        assert_eq!(
            new_name(&operation, "hello-dolly"),
            ".rustiron-new-op_update1-hello-dolly"
        );
        assert_eq!(
            old_name(&operation, "hello-dolly"),
            ".rustiron-old-op_update1-hello-dolly"
        );
        assert_eq!(
            failed_name(&operation, "x"),
            ".rustiron-failed-op_update1-x"
        );
        let layout = SiteLayout::derive(&SiteId::try_from("blog1".to_owned()).unwrap());
        assert_eq!(
            parent_folder(&layout, UpdateKind::Theme),
            Path::new("/srv/sites/rs_blog1/html/wp-content/themes")
        );
        assert_eq!(
            components_input(&components(), true),
            "plugin hello-dolly\ntheme twentytwentyfour\n"
        );
        // W527 (D-086): core lives in the site root, and only the script
        // step asks for the upgrade.
        assert_eq!(
            parent_folder(&layout, UpdateKind::Core),
            Path::new("/srv/sites/rs_blog1/html")
        );
        let core = [UpdateComponent {
            kind: UpdateKind::Core,
            slug: "wordpress".to_owned().try_into().unwrap(),
            from_version: "7.0.9".to_owned().try_into().unwrap(),
            to_version: "7.1.5".to_owned().try_into().unwrap(),
        }];
        assert_eq!(components_input(&core, false), "core wordpress\n");
        assert_eq!(components_input(&core, true), "core wordpress upgrade\n");
    }

    #[test]
    fn the_unpack_need_counts_the_copy_each_member_and_its_folders() {
        // W528-F3: plugin/hello-dolly/{a.php,inc/b.php} (5000 bytes) and
        // theme/twentytwentyfour/style.css; the manifest and the lists are
        // not unpacked.
        let big = vec![b'x'; 5000];
        let (bytes, _) = recipe(&[
            &[("a.php", b"<?php"), ("inc/b.php", &big)],
            &[("style.css", b"/* */")],
        ]);
        let (kib, inodes) = unpack_need(&bytes).unwrap();
        // Folders: plugin, plugin/hello-dolly, plugin/hello-dolly/inc,
        // theme, theme/twentytwentyfour.
        assert_eq!(inodes, 1 + 3 + 5);
        assert_eq!(kib, block_kib(bytes.len() as u64) + 4 + 8 + 4 + 5 * 4);
        let row = |used_kib, hard_kib, used_inodes, hard_inodes| crate::quota::QuotaRow {
            block_used_kib: used_kib,
            block_soft_kib: 0,
            block_hard_kib: hard_kib,
            inode_used: used_inodes,
            inode_soft: 0,
            inode_hard: hard_inodes,
        };
        assert!(quota_fits(
            &row(100, 100 + kib, 10, 10 + inodes),
            kib,
            inodes
        ));
        assert!(!quota_fits(
            &row(101, 100 + kib, 10, 10 + inodes),
            kib,
            inodes
        ));
        assert!(!quota_fits(
            &row(100, 100 + kib, 11, 10 + inodes),
            kib,
            inodes
        ));
        // A hard limit of 0 is no limit.
        assert!(quota_fits(
            &row(u64::MAX - 1, 0, u64::MAX - 1, 0),
            kib,
            inodes
        ));
    }

    #[test]
    fn a_core_rollback_moves_only_the_entries_that_left_the_new_folder() {
        // W527: `wp-admin` was swapped, `wp-new.php` is new in the release
        // and was moved in, `index.php` is still in the new folder (never
        // swapped), and `gone.php` is absent from the root.
        let top = ["gone.php", "index.php", "wp-admin", "wp-new.php"].map(String::from);
        let still_new = |name: &str| name == "index.php";
        let present = |name: &str| name != "gone.php";
        assert_eq!(
            new_root_entries(&top, still_new, present),
            ["wp-admin", "wp-new.php"]
        );
    }

    #[test]
    fn the_version_report_must_be_the_sites_and_state_each_version_in_order() {
        let report = |user: &str, plugin: Option<&str>| {
            serde_json::json!({"user": user, "components": [
                {"kind": "plugin", "slug": "hello-dolly", "version": plugin},
                {"kind": "theme", "slug": "twentytwentyfour", "version": "1.2"},
            ]})
        };
        fn from(component: &UpdateComponent) -> &ComponentVersion {
            &component.from_version
        }
        assert!(versions_match(
            &report("rs_blog1", Some("1.7.1")),
            "rs_blog1",
            &components(),
            from
        ));
        assert!(!versions_match(
            &report("rs_blog1", Some("1.7.2")),
            "rs_blog1",
            &components(),
            from
        ));
        assert!(!versions_match(
            &report("rs_blog1", None),
            "rs_blog1",
            &components(),
            from
        ));
        assert!(!versions_match(
            &report("rs_blog2", Some("1.7.1")),
            "rs_blog1",
            &components(),
            from
        ));
        assert!(!versions_match(
            &serde_json::json!({"user": "rs_blog1"}),
            "rs_blog1",
            &components(),
            from
        ));
    }
}
