//! Root provisioning steps for one site (S04 W016c): account, directories,
//! SELinux level and PHP units. Every value is derived here from the site id
//! and enrolled ranges; nothing comes from the requester except the site id.
//!
//! Each step refuses to touch anything that already exists. Nothing is ever
//! removed: a failed step leaves what it created for the quarantine review.

use std::{
    io::Write,
    os::fd::OwnedFd,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use rustiron_contracts::approval::{Hostname, SiteId};
use rustix::fs::{self, AtFlags, Mode, OFlags};

use crate::{ExecutorError, files};

pub(crate) mod skeleton;

const SITES_ROOT: &str = crate::layout::SITES_ROOT;
pub(crate) const OLS_GROUP: &str = "nobody";
pub(crate) const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
/// W280: CPU weight of capture and restore-probe job units. They sit in
/// `system.slice` beside the site-PHP slice (default weight 100), so at the
/// default they took an equal share from all pools together (W279). Under
/// contention they now yield; when the host is idle they still run at full
/// speed. No `IOWeight`: it has no effect without an I/O-weighting scheduler.
pub(crate) const JOB_CPU_WEIGHT: &str = "CPUWeight=20";
pub(crate) const MARIADB: &str = "/usr/bin/mariadb";
pub(crate) const DB_SOCKET: &str = "/var/lib/mysql/mysql.sock";
const MAX_RECIPE_BYTES: usize = 64 * 1024 * 1024;

/// Enrolled allocation ranges (root-admin policy, never request data).
#[derive(Clone, Copy, Debug)]
pub struct Ranges {
    /// Inclusive UID/GID range for site accounts.
    pub uid: (u32, u32),
    /// Inclusive SELinux category range for site levels.
    pub category: (u32, u32),
}

/// Names and paths derived from a site id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SiteLayout {
    /// Account, group and PHP unit instance name: `rs_<site_id>`.
    pub account: String,
    /// `/srv/sites/<account>`.
    pub root: PathBuf,
}

impl SiteLayout {
    /// Derives the layout; the site id grammar makes every name safe.
    pub fn derive(site: &SiteId) -> Self {
        let account = site.account_name();
        Self {
            root: Path::new(SITES_ROOT).join(&account),
            account,
        }
    }
}

/// Next id in range above every UID in `passwd`, GID in `group` and id in
/// `retired` (see [`next_above`]).
pub fn allocate_id(
    passwd: &str,
    group: &str,
    range: (u32, u32),
    retired: &[u32],
) -> Result<u32, ExecutorError> {
    let used: Vec<u32> = passwd
        .lines()
        .chain(group.lines())
        .filter_map(|line| line.split(':').nth(2)?.parse().ok())
        .collect();
    next_above(range, &used, retired)
}

/// Whether `name` already exists as an account or group.
pub fn name_taken(passwd: &str, group: &str, name: &str) -> bool {
    passwd
        .lines()
        .chain(group.lines())
        .any(|line| line.split(':').next() == Some(name))
}

/// Next category in range above every one used by a local file-context rule
/// or recorded for an earlier provision (see [`next_above`]).
pub fn allocate_category(
    fcontext_rules: &str,
    range: (u32, u32),
    retired: &[u32],
) -> Result<u32, ExecutorError> {
    let used: Vec<u32> = fcontext_rules
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == ':'))
        .filter_map(|word| word.rsplit_once(":c")?.1.parse().ok())
        .collect();
    next_above(range, &used, retired)
}

/// Allocation is monotonic: the next id above every id in use or recorded
/// earlier inside the range, so an id freed by a removal (even one recorded
/// before ids were journaled) is never handed to a later site.
fn next_above(range: (u32, u32), used: &[u32], retired: &[u32]) -> Result<u32, ExecutorError> {
    let highest = used
        .iter()
        .chain(retired)
        .filter(|id| (range.0..=range.1).contains(id))
        .max();
    match highest {
        None => Ok(range.0),
        Some(&id) if id < range.1 => Ok(id + 1),
        Some(_) => Err(ExecutorError::Capacity),
    }
}

/// Numbers recorded after `key` (e.g. `uid=`) in earlier step resources.
pub fn recorded_numbers(resources: &[String], key: &str) -> Vec<u32> {
    resources
        .iter()
        .filter_map(|text| {
            let rest = text.split_once(key)?.1;
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            digits.parse().ok()
        })
        .collect()
}

/// GID of the OLS worker group from `group`.
pub fn group_id(group: &str, name: &str) -> Option<u32> {
    group.lines().find_map(|line| {
        let mut parts = line.split(':');
        (parts.next() == Some(name)).then(|| parts.nth(1)?.parse().ok())?
    })
}

/// The UID/GID for a new account: free in passwd and group and never
/// recorded by an earlier provision (`retired`), so a removed site's id and
/// anything it left behind never pass to another site.
pub fn choose_uid(ranges: Ranges, retired: &[u32]) -> Result<u32, ExecutorError> {
    allocate_id(
        &read_etc("passwd")?,
        &read_etc("group")?,
        ranges.uid,
        retired,
    )
}

/// Generated copy of the local file-context rules (`semanage fcontext -l -C`).
pub const LOCAL_FCONTEXTS: &str = "/etc/selinux/targeted/contexts/files/file_contexts.local";

/// The category for a new site: unused by local rules and never recorded.
///
/// Reads the generated local rules file rather than running `semanage`, so
/// the steady executor needs only read access to file contexts (W173). An
/// absent file means no local rules; any other read error is refused.
pub fn choose_category(ranges: Ranges, retired: &[u32]) -> Result<u32, ExecutorError> {
    let rules = match std::fs::read_to_string(LOCAL_FCONTEXTS) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(_) => return Err(ExecutorError::Unavailable),
    };
    allocate_category(&rules, ranges.category, retired)
}

/// Step 1: create the site group and account with the id chosen (and
/// journaled) before the effect. Refuses if the name, the id or the site
/// directory already exists.
pub fn create_account(layout: &SiteLayout, uid: u32) -> Result<String, ExecutorError> {
    let (passwd, group) = (read_etc("passwd")?, read_etc("group")?);
    if name_taken(&passwd, &group, &layout.account) || exists(&layout.root) {
        return Err(ExecutorError::Collision);
    }
    if allocate_id(&passwd, &group, (uid, uid), &[]).is_err() {
        return Err(ExecutorError::Collision);
    }
    let id = uid.to_string();
    run("/usr/sbin/groupadd", &["--gid", &id, "--", &layout.account])?;
    run(
        "/usr/sbin/useradd",
        &[
            "--uid",
            &id,
            "--gid",
            &id,
            "--no-create-home",
            "--home-dir",
            path_str(&layout.root)?,
            "--shell",
            "/sbin/nologin",
            "--comment",
            "Rustiron lab site",
            "--",
            &layout.account,
        ],
    )?;
    let (passwd, group) = (read_etc("passwd")?, read_etc("group")?);
    let expected = format!("{}:x:{id}:{id}:", layout.account);
    if !passwd.lines().any(|line| line.starts_with(&expected))
        || group_id(&group, &layout.account).map(|gid| gid.to_string()) != Some(id.clone())
    {
        return Err(ExecutorError::StepFailed);
    }
    Ok(format!("account {} uid={id} gid={id}", layout.account))
}

/// Step 2: create the site tree below the trusted sites root, descriptor-relative.
pub fn create_directories(layout: &SiteLayout) -> Result<String, ExecutorError> {
    let (passwd, group) = (read_etc("passwd")?, read_etc("group")?);
    let uid = account_uid(&passwd, &layout.account).ok_or(ExecutorError::StepFailed)?;
    let ols = group_id(&group, OLS_GROUP).ok_or(ExecutorError::StepFailed)?;
    let sites = files::open_traversable_directory(Path::new(SITES_ROOT), 0)?;
    let name = layout.account.as_str();
    make_directory(&sites, name, 0, 0, 0o751)?;
    let root = fs::openat(
        &sites,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ExecutorError::StepFailed)?;
    make_directory(&root, "errors", 0, 0, 0o755)?;
    write_error_page(&root)?;
    make_directory(&root, "html", uid, ols, 0o750)?;
    for private in ["tmp", "logs", "private"] {
        make_directory(&root, private, uid, uid, 0o750)?;
    }
    Ok(format!(
        "directories {} (errors, html, tmp, logs, private)",
        path_str(&layout.root)?
    ))
}

/// Step 3: give the whole site tree the category chosen (and journaled)
/// before the effect; refuses if any local rule already uses it.
/// W274: the tree must still be step 2's exact skeleton, checked and labelled
/// through descriptors; there is no recursive root relabel over the site.
pub fn apply_labels(layout: &SiteLayout, category: u32) -> Result<String, ExecutorError> {
    let sites = files::open_traversable_directory(Path::new(SITES_ROOT), 0)?;
    let site = files::open_child_directory(&sites, &layout.account, 0)?;
    let entries = skeleton::open_skeleton(&site, skeleton::SITE)?;
    let rules = output("/usr/sbin/semanage", &["fcontext", "--list", "-C"])?;
    let root = path_str(&layout.root)?;
    if rules.contains(&format!("{root}(")) || rules.contains(&format!("{root}/")) {
        return Err(ExecutorError::Collision);
    }
    if allocate_category(&rules, (category, category), &[]).is_err() {
        return Err(ExecutorError::Collision);
    }
    let level = format!("s0:c{category}");
    for (kind, pattern) in [
        (skeleton::CONTENT, format!("{root}(/.*)?")),
        (skeleton::READ_WRITE, format!("{root}/(tmp|logs)(/.*)?")),
    ] {
        run(
            "/usr/sbin/semanage",
            &[
                "fcontext", "--add", "--type", kind, "--range", &level, "--", &pattern,
            ],
        )?;
    }
    skeleton::label_skeleton(
        &site,
        &entries,
        &level,
        &skeleton::set_label,
        &skeleton::get_label,
    )?;
    skeleton::unchanged(&site, skeleton::SITE, &entries)?;
    Ok(format!("labels {root} level={level}"))
}

/// Step 4: per-site PHP drop-in and enabled socket (S03 template units).
pub fn install_php_units(layout: &SiteLayout) -> Result<String, ExecutorError> {
    let root = path_str(&layout.root)?;
    let context = output("/usr/bin/stat", &["-c", "%C", "--", root])?;
    let level = context
        .trim()
        .strip_prefix("system_u:object_r:httpd_sys_content_t:")
        .filter(|level| level.starts_with("s0:c"))
        .ok_or(ExecutorError::StepFailed)?
        .to_owned();
    let units = files::open_traversable_directory(Path::new("/etc/systemd/system"), 0)?;
    for template in ["rustiron-site-php@.service", "rustiron-site-php@.socket"] {
        fs::statat(&units, template, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| ExecutorError::StepFailed)?;
    }
    let dropin = format!("rustiron-site-php@{}.service.d", layout.account);
    make_directory(&units, &dropin, 0, 0, 0o755)?;
    let directory = fs::openat(
        &units,
        dropin.as_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ExecutorError::StepFailed)?;
    let text = format!(
        "[Service]\nSELinuxContext=system_u:system_r:rustiron_php_t:{level}\nEnvironment=RUSTIRON_SITE_LEVEL={level}\n"
    );
    write_new(&directory, "50-selinux.conf", text.as_bytes())?;
    run("/usr/bin/systemctl", &["daemon-reload"])?;
    let socket = format!("rustiron-site-php@{}.socket", layout.account);
    let timer = format!("rustiron-site-sandbox-check@{}.timer", layout.account);
    run(
        "/usr/bin/systemctl",
        &["enable", "--now", "--", &socket, &timer],
    )?;
    let active = output("/usr/bin/systemctl", &["is-active", "--", &socket])?;
    if active.trim() != "active" {
        return Err(ExecutorError::StepFailed);
    }
    Ok(format!("php units {socket} {timer} level={level}"))
}

/// Step 4 of the journal order (Database): a database and a local user that
/// may use only it, named after the account. The password is random, sent on
/// stdin and kept in memory for the Credentials step only.
pub fn create_database(layout: &SiteLayout) -> Result<(String, String), ExecutorError> {
    let name = layout.account.as_str();
    let existing = spawn(
        MARIADB,
        &["--batch", "--skip-column-names", "--socket", DB_SOCKET],
        true,
        Some(
            format!(
                "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='{name}';\n\
                 SELECT COUNT(*) FROM mysql.user WHERE User='{name}';\n"
            )
            .as_bytes(),
        ),
    )?;
    if existing.split_whitespace().collect::<Vec<_>>() != ["0", "0"] {
        return Err(ExecutorError::Collision);
    }
    let password = random_secret()?;
    let sql = format!(
        "CREATE DATABASE `{name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n\
         CREATE USER '{name}'@'localhost' IDENTIFIED BY '{password}';\n\
         GRANT ALL PRIVILEGES ON `{name}`.* TO '{name}'@'localhost';\n"
    );
    spawn(
        MARIADB,
        &["--batch", "--socket", DB_SOCKET],
        false,
        Some(sql.as_bytes()),
    )?;
    Ok((format!("database {name} user {name}@localhost"), password))
}

/// Step 5 (Credentials): `private/db.cnf`, site-owned 0600, created exclusively,
/// then a login with exactly those credentials must reach only its database.
pub fn write_credentials(layout: &SiteLayout, password: &str) -> Result<String, ExecutorError> {
    let passwd = read_etc("passwd")?;
    let uid = account_uid(&passwd, &layout.account).ok_or(ExecutorError::StepFailed)?;
    let private = layout.root.join("private");
    let directory = files::open_traversable_directory(&private, uid)?;
    let name = layout.account.as_str();
    let text = credentials_text(name, password);
    let fd = fs::openat(
        &directory,
        "db.cnf",
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|error| match error {
        rustix::io::Errno::EXIST => ExecutorError::Collision,
        _ => ExecutorError::StepFailed,
    })?;
    fs::fchown(
        &fd,
        Some(rustix::fs::Uid::from_raw(uid)),
        Some(rustix::fs::Gid::from_raw(uid)),
    )
    .map_err(|_| ExecutorError::StepFailed)?;
    let mut file = std::fs::File::from(fd);
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| ExecutorError::StepFailed)?;
    let cnf = private.join("db.cnf");
    let defaults = format!("--defaults-file={}", path_str(&cnf)?);
    let seen = spawn(
        MARIADB,
        &[&defaults, "--batch", "--skip-column-names"],
        true,
        Some(b"SELECT DATABASE(), CURRENT_USER();\nSHOW DATABASES;\n"),
    )?;
    let words: Vec<_> = seen.split_whitespace().collect();
    let user = format!("{name}@localhost");
    if words.first() != Some(&name)
        || words.get(1) != Some(&user.as_str())
        || words[2..]
            .iter()
            .any(|db| *db != name && *db != "information_schema")
    {
        return Err(ExecutorError::StepFailed);
    }
    Ok(format!("credentials {} (0600 {name})", path_str(&cnf)?))
}

/// Step 6 (Recipe): unpack one enrolled tarball into the empty `html` dir as
/// the site account, inside a transient unit that can write only `html` and
/// has no network or capabilities. Root only reads and verifies the artifact.
pub fn unpack_recipe(
    layout: &SiteLayout,
    recipes: &Path,
    file: &str,
    expected_sha256: &rustiron_contracts::approval::Sha256Digest,
    version_marker: &str,
) -> Result<String, ExecutorError> {
    use sha2::{Digest, Sha256};
    let store = files::open_traversable_directory(recipes, 0)?;
    require_present(&store, file)?;
    let artifact = files::read_child(&store, file, 0, files::Exposure::Readable, MAX_RECIPE_BYTES)?;
    let digest =
        rustiron_contracts::approval::Sha256Digest::from_bytes(Sha256::digest(&artifact).into());
    if &digest != expected_sha256 {
        return Err(failed("recipe digest mismatch"));
    }
    let html = layout.root.join("html");
    let html_str = path_str(&html)?;
    if std::fs::read_dir(&html)
        .map_err(|_| ExecutorError::StepFailed)?
        .next()
        .is_some()
    {
        return Err(ExecutorError::Collision);
    }
    let listing = spawn(
        "/usr/bin/tar",
        &["--list", "--verbose", "--gzip", "--file=-"],
        true,
        Some(&artifact),
    )?;
    let members: Vec<_> = listing.lines().collect();
    if members
        .iter()
        .any(|line| !(line.starts_with('-') || line.starts_with('d')))
    {
        return Err(failed("recipe has a non-file member"));
    }
    let regular = members.iter().filter(|line| line.starts_with('-')).count();
    let account = &layout.account;
    let level = crate::capture::site_level(layout)?;
    let passwd = read_etc("passwd")?;
    let uid = account_uid(&passwd, account).ok_or(ExecutorError::StepFailed)?;
    run_unpack_job(layout, uid, &artifact, UNPACK_INPUT, |source| {
        unpack_args(account, &level, html_str, source)
    })?;
    // Labelled at creation (W213): the job runs in rustiron_unpack_t at the
    // site's level, may create only httpd_sys_content_t entries and has no
    // relabel permission, so new entries inherit the html type and take the
    // job's level. No root `restorecon -R` over the tenant-written tree; the
    // descriptor-relative, no-follow, bounded census (W210) verifies labels.
    let html_dir = files::open_traversable_directory(&html, uid)?;
    let want = format!("system_u:object_r:httpd_sys_content_t:{level}");
    let census = crate::census::census_labelled(
        &html_dir,
        uid,
        want.as_bytes(),
        &crate::census::label_of,
        crate::census::BOUNDS,
    )?;
    let version = std::fs::read_to_string(html.join("wp-includes/version.php"))
        .map_err(|_| ExecutorError::StepFailed)?;
    if !tree_matches(&census, regular) || !version.contains(version_marker) {
        return Err(failed("unpacked tree does not match the recipe"));
    }
    Ok(format!(
        "recipe {file} sha256={} files={regular}",
        digest.as_str()
    ))
}

/// Runs one unpack job on verified bytes. The job runs as the site in its
/// own MCS level and the narrow unpack domain, so MAC (not only DAC) keeps it
/// to this site's tree. It reads the bytes from a site-owned copy named
/// `input` in the site's tmp (the domain may not read the root recipe
/// store); the copy is removed. `args` builds the `systemd-run` arguments
/// from the copy's path.
pub(crate) fn run_unpack_job(
    layout: &SiteLayout,
    uid: u32,
    artifact: &[u8],
    input: &str,
    args: impl FnOnce(&str) -> Vec<String>,
) -> Result<(), ExecutorError> {
    let tmp = layout.root.join("tmp");
    let tmp_dir = files::open_traversable_directory(&tmp, uid)?;
    write_owned(&tmp_dir, input, artifact, uid, 0o600)?;
    let copy = tmp.join(input);
    let ran = (|| {
        let copy_str = path_str(&copy)?;
        run("/usr/sbin/restorecon", &["-F", "--", copy_str])?;
        let args = args(copy_str);
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        run("/usr/bin/systemd-run", &borrowed)
    })();
    let removed = match fs::unlinkat(&tmp_dir, input, AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => true,
        Err(_) => false,
    };
    ran?;
    if !removed {
        return Err(failed("recipe copy not removed"));
    }
    Ok(())
}

/// The unpacked tree is exactly the recipe's regular files, all owned by
/// the site, nothing foreign, and every entry already in the site label.
pub(crate) fn tree_matches(census: &crate::census::Census, regular: usize) -> bool {
    census.owned_files == regular as u64 && census.foreign == 0 && census.mislabelled == 0
}

/// Name of the verified recipe copy placed in the site's tmp for the unpack job.
const UNPACK_INPUT: &str = "recipe-unpack.tar.gz";

/// The domain the recipe unpack job runs in (with the site's level).
pub(crate) const UNPACK_DOMAIN: &str = "system_u:system_r:rustiron_unpack_t";

/// `systemd-run` arguments for the unpack job: the site account, its MCS
/// level in the unpack domain, write access to `html` only, no network,
/// capabilities or privilege gain. No `--pipe`: PID 1 refuses fds passed from
/// inside the caller's sandbox, so the unit reads the copy by path.
pub(crate) fn unpack_args(account: &str, level: &str, html: &str, source: &str) -> Vec<String> {
    let mut args = unpack_properties(account, level, html);
    args.extend(["--", "/usr/bin/tar", "--extract", "--gzip"].map(String::from));
    args.push(format!("--file={source}"));
    args.push("--strip-components=1".into());
    args.push(format!("--directory={html}"));
    args.extend(
        [
            "--no-same-owner",
            "--numeric-owner",
            "--no-same-permissions",
            "--keep-old-files",
        ]
        .map(String::from),
    );
    args
}

/// The `systemd-run` options every unpack job shares (W174, W368): the site
/// account at its level in the unpack domain, `writable` the one writable
/// path, and no network, capabilities or privilege gain.
pub(crate) fn unpack_properties(account: &str, level: &str, writable: &str) -> Vec<String> {
    job_properties(UNPACK_DOMAIN, account, level, writable)
}

/// [`unpack_properties`] with another job domain (W446: the site import's
/// observe job runs the export worker in the capture domain).
pub(crate) fn job_properties(
    domain: &str,
    account: &str,
    level: &str,
    writable: &str,
) -> Vec<String> {
    let mut args: Vec<String> = ["--wait", "--quiet", "--collect"]
        .map(String::from)
        .to_vec();
    let properties = [
        format!("User={account}"),
        format!("Group={account}"),
        format!("SELinuxContext={domain}:{level}"),
        format!("ReadWritePaths={writable}"),
        "NoNewPrivileges=yes".into(),
        "CapabilityBoundingSet=".into(),
        "ProtectSystem=strict".into(),
        "ProtectHome=yes".into(),
        "PrivateTmp=yes".into(),
        "PrivateNetwork=yes".into(),
        "PrivateDevices=yes".into(),
        "RestrictSUIDSGID=yes".into(),
        "UMask=0022".into(),
        "MemoryMax=256M".into(),
        "MemorySwapMax=0".into(),
        "TasksMax=8".into(),
        "RuntimeMaxSec=120".into(),
    ];
    for property in properties {
        args.push("--property".into());
        args.push(property);
    }
    args
}

pub(crate) const WP_CONFIG_TEMPLATE: &str = include_str!("provision_assets/wp-config.php.in");
const VERIFY_SCRIPT: &str = include_str!("provision_assets/verify.php");
const INSTALL_SCRIPT: &str = include_str!("provision_assets/install.php");
pub(crate) const SALT_NAMES: [&str; 8] = [
    "AUTH_KEY",
    "SECURE_AUTH_KEY",
    "LOGGED_IN_KEY",
    "NONCE_KEY",
    "AUTH_SALT",
    "SECURE_AUTH_SALT",
    "LOGGED_IN_SALT",
    "NONCE_SALT",
];

/// Reads one root-owned artifact from the recipe store and requires its
/// pinned SHA-256.
pub fn read_pinned(
    recipes: &Path,
    file: &str,
    expected_sha256: &rustiron_contracts::approval::Sha256Digest,
) -> Result<Vec<u8>, ExecutorError> {
    use sha2::{Digest, Sha256};
    let store = files::open_traversable_directory(recipes, 0)?;
    require_present(&store, file)?;
    let bytes = files::read_child(&store, file, 0, files::Exposure::Readable, MAX_RECIPE_BYTES)?;
    if &rustiron_contracts::approval::Sha256Digest::from_bytes(Sha256::digest(&bytes).into())
        != expected_sha256
    {
        return Err(failed("pinned artifact digest mismatch"));
    }
    Ok(bytes)
}

/// An absent artifact gets its own code; any other problem with it (owner,
/// mode, link) stays the trusted-file refusal from `read_child`.
fn require_present(store: &OwnedFd, file: &str) -> Result<(), ExecutorError> {
    match fs::statat(store, file, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => {
            eprintln!(
                "{{\"scope\":\"site_provision\",\"step_failure\":\"pinned artifact absent\"}}"
            );
            Err(ExecutorError::ArtifactUnavailable)
        }
        _ => Ok(()),
    }
}

/// Part of the Recipe step: `rustiron-site.txt` naming the account, the
/// static identity marker the OLS activation probes (0644, site-owned).
pub fn write_site_marker(layout: &SiteLayout) -> Result<String, ExecutorError> {
    let passwd = read_etc("passwd")?;
    let uid = account_uid(&passwd, &layout.account).ok_or(ExecutorError::StepFailed)?;
    let html = layout.root.join("html");
    let directory = files::open_traversable_directory(&html, uid)?;
    write_new(
        &directory,
        "rustiron-site.txt",
        format!("{}\n", layout.account).as_bytes(),
    )?;
    let fd = fs::openat(
        &directory,
        "rustiron-site.txt",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ExecutorError::StepFailed)?;
    fs::fchown(
        &fd,
        Some(rustix::fs::Uid::from_raw(uid)),
        Some(rustix::fs::Gid::from_raw(uid)),
    )
    .map_err(|_| ExecutorError::StepFailed)?;
    let marker = html.join("rustiron-site.txt");
    run("/usr/sbin/restorecon", &["-F", "--", path_str(&marker)?])?;
    Ok(format!("marker {}", path_str(&marker)?))
}

/// Part of the Recipe step: the fixed `wp-config.php`, site-owned 0600,
/// created exclusively, with fresh random salts and no copied credentials.
pub fn write_wp_config(layout: &SiteLayout) -> Result<String, ExecutorError> {
    let passwd = read_etc("passwd")?;
    let uid = account_uid(&passwd, &layout.account).ok_or(ExecutorError::StepFailed)?;
    let html = layout.root.join("html");
    let directory = files::open_traversable_directory(&html, uid)?;
    let mut salts = String::new();
    for name in SALT_NAMES {
        let mut random = [0_u8; 32];
        rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty())
            .map_err(|_| ExecutorError::Unavailable)?;
        let value: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        salts.push_str(&format!("define('{name}', '{value}');\n"));
    }
    let text = WP_CONFIG_TEMPLATE.replace("@SALTS@\n", &salts);
    let fd = fs::openat(
        &directory,
        "wp-config.php",
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|error| match error {
        rustix::io::Errno::EXIST => ExecutorError::Collision,
        _ => ExecutorError::StepFailed,
    })?;
    fs::fchown(
        &fd,
        Some(rustix::fs::Uid::from_raw(uid)),
        Some(rustix::fs::Gid::from_raw(uid)),
    )
    .map_err(|_| ExecutorError::StepFailed)?;
    let mut file = std::fs::File::from(fd);
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| ExecutorError::StepFailed)?;
    let config = html.join("wp-config.php");
    run("/usr/sbin/restorecon", &["-F", "--", path_str(&config)?])?;
    Ok(format!(
        "wp-config {} (0600 {})",
        path_str(&config)?,
        layout.account
    ))
}

/// Step 8 (Verify): run the fixed probe with the site's own PHP binary, user
/// and SELinux level in a sandbox, and require the expected identity, its own
/// database login, readable config, read-only code and no other site reachable.
///
/// `core_checksums` is the pinned upstream per-file MD5 list (JSON
/// `{"checksums":{path: md5}}`); the site's own PHP checks every listed file.
/// `installed` is what the recipe promises (W399, D-047): the install recipe
/// needs an installed WordPress, the unpack-only lab recipe needs none.
pub fn verify_site(
    layout: &SiteLayout,
    core_checksums: &[u8],
    installed: bool,
) -> Result<String, ExecutorError> {
    let account = &layout.account;
    serving_survives_boot(layout)?;
    let listed = serde_json::from_slice::<serde_json::Value>(core_checksums)
        .ok()
        .and_then(|value| value["checksums"].as_object().map(serde_json::Map::len))
        .filter(|count| *count > 0)
        .ok_or_else(|| failed("core checksum list unreadable"))?;
    let (value, level) = run_site_php(
        layout,
        "rustiron-verify",
        VERIFY_SCRIPT,
        &[("rustiron-verify.checksums", core_checksums)],
    )?;
    if value["core"]["checked"] != listed
        || value["core"]["mismatched"] != 0
        || value["core"]["missing"] != 0
    {
        return Err(failed("core files do not match the pinned checksums"));
    }
    if !verify_report_matches(&value, account, &level, installed) {
        return Err(failed("verify report does not match the site"));
    }
    Ok(format!(
        "verified {account} context={level} db={account} core_files={listed} installed={installed}"
    ))
}

/// The Verify report names the site's own account, domain level, database
/// login and config, read-only code, and no readable other site. PHP's
/// `json_encode` writes an empty map as `[]`: the first site on a host sees
/// no other site (W361). Any other array refuses. W399: the report's
/// `installed` must equal what the recipe promises.
fn verify_report_matches(
    value: &serde_json::Value,
    account: &str,
    level: &str,
    installed: bool,
) -> bool {
    let expected_user = format!("{account}@localhost");
    let others_hidden = match &value["reads_other_sites"] {
        serde_json::Value::Object(sites) => sites.values().all(|seen| seen == false),
        serde_json::Value::Array(sites) => sites.is_empty(),
        _ => false,
    };
    value["user"] == account
        && value["context"] == format!("system_u:system_r:rustiron_php_t:{level}")
        && value["database"] == account
        && value["db_user"] == expected_user.as_str()
        && value["wp_config"] == true
        && value["version"] == true
        && value["can_write_html"] == false
        && value["installed"] == installed
        && others_hidden
}

/// Serving must not depend on anyone starting units by hand: the database,
/// OLS and the site's PHP socket and sandbox re-check are enabled at boot
/// (W024 found MariaDB disabled, so every site failed after a reboot).
pub(crate) fn serving_survives_boot(layout: &SiteLayout) -> Result<(), ExecutorError> {
    let account = &layout.account;
    for unit in [
        "mariadb.service".to_owned(),
        "lshttpd.service".to_owned(),
        format!("rustiron-site-php@{account}.socket"),
        format!("rustiron-site-sandbox-check@{account}.timer"),
    ] {
        let state = output("/usr/bin/systemctl", &["is-enabled", "--", &unit])
            .map_err(|_| failed("serving unit not enabled at boot"))?;
        if state.trim() != "enabled" {
            return Err(failed("serving unit not enabled at boot"));
        }
    }
    Ok(())
}

/// Fixed WordPress administrator login created by the install recipe.
pub const WORDPRESS_ADMIN: &str = "rustiron_admin";

/// Part of the Recipe step for `wordpress713_install_v1`: generate the admin
/// password, hand it over root-only (`private/rustiron-admin.txt`, 0600
/// root), then run the fixed install script as the site in its sandbox. The
/// password reaches the site only through a site-owned 0600 file in its own
/// tmp that the script removes; it is never in argv, environment, journal,
/// logs or the reply.
pub fn install_wordpress(layout: &SiteLayout, host: &Hostname) -> Result<String, ExecutorError> {
    let passwd = read_etc("passwd")?;
    let uid = account_uid(&passwd, &layout.account).ok_or(ExecutorError::StepFailed)?;
    let secret = random_secret()?;
    let private = files::open_traversable_directory(&layout.root.join("private"), uid)?;
    let handover = handover_text(host, &secret);
    write_owned(&private, HANDOVER, handover.as_bytes(), 0, 0o600)?;
    let input = serde_json::json!({ "host": host.as_str(), "title": layout.account });
    let (value, _) = run_site_php(
        layout,
        "rustiron-install",
        INSTALL_SCRIPT,
        &[
            ("rustiron-install.secret", secret.as_bytes()),
            ("rustiron-install.input", input.to_string().as_bytes()),
        ],
    )?;
    let siteurl = format!("http://{}", host.as_str());
    if value["user"] != layout.account.as_str()
        || value["already_installed"] != false
        || value["installed"] != true
        || value["admin_is_administrator"] != true
        || value["password_ok"] != true
        || value["secret_removed"] != true
        || value["siteurl"] != siteurl.as_str()
    {
        return Err(failed("install report does not match the site"));
    }
    Ok(format!("installed {siteurl} admin={WORDPRESS_ADMIN}"))
}

const HANDOVER: &str = "rustiron-admin.txt";

/// Read-only ownership facts for a site, observed live (W025 export). Paths
/// and names are derived from the site id; secrets are reported only as
/// present/absent, never read.
pub fn ownership_facts(layout: &SiteLayout) -> serde_json::Value {
    let account = layout.account.as_str();
    let root = layout.root.to_string_lossy().into_owned();
    let passwd = read_etc("passwd").unwrap_or_default();
    let group = read_etc("group").unwrap_or_default();
    let uid = account_uid(&passwd, account);
    let gid = group_id(&group, account);
    let level = output("/usr/bin/stat", &["-c", "%C", "--", &root])
        .ok()
        .and_then(|context| {
            context
                .trim()
                .strip_prefix("system_u:object_r:httpd_sys_content_t:")
                .map(str::to_owned)
        });
    let present = |path: String| exists(Path::new(&path));
    let enabled = |unit: String| {
        let state = output("/usr/bin/systemctl", &["is-enabled", "--", &unit])
            .map(|text| text.trim().to_owned())
            .unwrap_or_else(|_| "not-enabled".to_owned());
        serde_json::json!({ "unit": unit, "enabled": state })
    };
    let database = spawn(
        MARIADB,
        &["--batch", "--skip-column-names", "--socket", DB_SOCKET],
        true,
        Some(
            format!(
                "SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='{account}';\n\
                 SELECT COUNT(*) FROM mysql.user WHERE User='{account}' AND Host='localhost';\n"
            )
            .as_bytes(),
        ),
    )
    .ok()
    .map(|text| {
        text.split_whitespace()
            .map(|word| word == "1")
            .collect::<Vec<_>>()
    });
    serde_json::json!({
        "account": account,
        "uid": uid,
        "gid": gid,
        "selinux_level": level,
        "paths": {
            "root": root,
            "html": format!("{root}/html"),
            "private": format!("{root}/private"),
            "tmp": format!("{root}/tmp"),
            "logs": format!("{root}/logs"),
        },
        "fcontext_rules": [format!("{root}(/.*)?"), format!("{root}/(tmp|logs)(/.*)?")],
        "database": {
            "name": account,
            "user": format!("{account}@localhost"),
            "exists": database.as_ref().and_then(|seen| seen.first().copied()),
            "user_exists": database.as_ref().and_then(|seen| seen.get(1).copied()),
            "credentials_file_present": present(format!("{root}/private/db.cnf")),
        },
        "admin_handover_present": present(format!("{root}/private/{HANDOVER}")),
        "units": [
            enabled(format!("rustiron-site-php@{account}.socket")),
            enabled(format!("rustiron-site-sandbox-check@{account}.timer")),
            enabled("mariadb.service".to_owned()),
            enabled("lshttpd.service".to_owned()),
        ],
        "php_dropin": format!("{}{account}.service.d", crate::layout::SITE_PHP_UNIT_PREFIX),
        "php_dropin_present": present(format!("{}{account}.service.d", crate::layout::SITE_PHP_UNIT_PREFIX)),
    })
}

/// Runs one fixed script with the site's own PHP, user and SELinux level in a
/// transient sandbox (no network, read-only code, its own tmp writable). The
/// script and its inputs are placed in the site's tmp, because the confined
/// domain may not read pipes or /dev/stdin created by root; inputs are
/// site-owned 0600. Every placed file and the report are removed afterwards.
pub(crate) fn run_site_php(
    layout: &SiteLayout,
    name: &str,
    script: &str,
    inputs: &[(&str, &[u8])],
) -> Result<(serde_json::Value, String), ExecutorError> {
    let root = path_str(&layout.root)?;
    let context = output("/usr/bin/stat", &["-c", "%C", "--", root])?;
    let level = context
        .trim()
        .strip_prefix("system_u:object_r:httpd_sys_content_t:")
        .ok_or(ExecutorError::StepFailed)?
        .to_owned();
    let account = &layout.account;
    let selinux = format!("SELinuxContext=system_u:system_r:rustiron_php_t:{level}");
    let user = format!("User={account}");
    let group = format!("Group={account}");
    let tmp_write = format!("ReadWritePaths={root}/tmp");
    let mut args = vec!["--wait", "--quiet", "--collect"];
    for property in [
        user.as_str(),
        group.as_str(),
        selinux.as_str(),
        tmp_write.as_str(),
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "PrivateTmp=yes",
        "PrivateDevices=yes",
        "PrivateNetwork=yes",
        "ProtectProc=invisible",
        "RuntimeMaxSec=60",
        "MemoryMax=256M",
        "MemorySwapMax=0",
        "TasksMax=8",
    ] {
        args.extend(["--property", property]);
    }
    let passwd = read_etc("passwd")?;
    let uid = account_uid(&passwd, account).ok_or(ExecutorError::StepFailed)?;
    let tmp = layout.root.join("tmp");
    let tmp_dir = files::open_traversable_directory(&tmp, uid)?;
    let script_name = format!("{name}.php");
    let report_name = format!("{name}.json");
    let script_path = path_str(&tmp.join(&script_name))?.to_owned();
    let mut placed = vec![script_name.clone()];
    let result = (|| {
        write_new(&tmp_dir, &script_name, script.as_bytes())?;
        for (input, bytes) in inputs {
            placed.push((*input).to_owned());
            write_owned(&tmp_dir, input, bytes, uid, 0o600)?;
        }
        for file in &placed {
            let path = tmp.join(file);
            run("/usr/sbin/restorecon", &["-F", "--", path_str(&path)?])?;
        }
        args.extend([
            "--",
            "/usr/local/lsws/lsphp84/bin/lsphp",
            "-q",
            &script_path,
        ]);
        run("/usr/bin/systemd-run", &args)?;
        let bytes = files::read_child(
            &tmp_dir,
            &report_name,
            uid,
            files::Exposure::Readable,
            64 * 1024,
        )
        .map_err(|_| failed("site php report missing"))?;
        String::from_utf8(bytes).map_err(|_| failed("site php report not text"))
    })();
    let mut removed = true;
    for file in &placed {
        match fs::unlinkat(&tmp_dir, file.as_str(), AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => {}
            Err(_) => removed = false,
        }
    }
    let _ = fs::unlinkat(&tmp_dir, report_name.as_str(), AtFlags::empty());
    let report = result?;
    if !removed {
        return Err(failed("site php inputs not removed"));
    }
    let value = serde_json::from_str(report.trim()).map_err(|_| ExecutorError::StepFailed)?;
    Ok((value, level))
}

/// The `private/db.cnf` text: the only place the database password is written.
pub(crate) fn credentials_text(name: &str, password: &str) -> String {
    format!("[client]\nuser={name}\npassword={password}\ndatabase={name}\nsocket={DB_SOCKET}\n")
}

/// The root-only admin handover text: the only place the admin password is written.
pub(crate) fn handover_text(host: &Hostname, secret: &str) -> String {
    format!(
        "user {WORDPRESS_ADMIN}\npassword {secret}\nlogin http://{}/wp-login.php\n",
        host.as_str()
    )
}

/// 24 random bytes as 48 lowercase hex digits; [`crate::redaction`] keys on this shape.
pub(crate) fn random_secret() -> Result<String, ExecutorError> {
    let mut random = [0_u8; 24];
    rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty())
        .map_err(|_| ExecutorError::Unavailable)?;
    Ok(random.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// A redacted, fixed-text reason on stderr (the service journal) for review;
/// never values, paths from requests or secrets.
fn failed(what: &'static str) -> ExecutorError {
    eprintln!("{{\"scope\":\"site_provision\",\"step_failure\":\"{what}\"}}");
    ExecutorError::StepFailed
}

/// W473-F2: a fixed tool's failure, for any step that runs it; the step logs
/// its own scope beside this line.
fn command_failed(what: &'static str) -> ExecutorError {
    eprintln!("{{\"scope\":\"fixed_command\",\"step_failure\":\"{what}\"}}");
    ExecutorError::StepFailed
}

pub(crate) fn account_uid(passwd: &str, name: &str) -> Option<u32> {
    passwd.lines().find_map(|line| {
        let mut parts = line.split(':');
        (parts.next() == Some(name)).then(|| parts.nth(1)?.parse().ok())?
    })
}

fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

pub(crate) fn path_str(path: &Path) -> Result<&str, ExecutorError> {
    path.to_str().ok_or(ExecutorError::StepFailed)
}

pub(crate) fn read_etc(name: &str) -> Result<String, ExecutorError> {
    let etc = files::open_traversable_directory(Path::new("/etc"), 0)?;
    let fd = fs::openat(
        &etc,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ExecutorError::Unavailable)?;
    let mut text = String::new();
    std::io::Read::read_to_string(&mut std::fs::File::from(fd), &mut text)
        .map_err(|_| ExecutorError::Unavailable)?;
    Ok(text)
}

/// Creates one directory that must not exist yet, then sets owner and mode.
/// B09-503: the root-owned static 503 page, created exclusively (never
/// following or replacing an existing entry). An identical existing page is
/// accepted so a retried provision or an ensure is safe (W269).
fn write_error_page(root: &OwnedFd) -> Result<(), ExecutorError> {
    let dir = fs::openat(
        root,
        "errors",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ExecutorError::StepFailed)?;
    match fs::openat(
        &dir,
        "503.html",
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o644),
    ) {
        Ok(file) => {
            fs::fchmod(&file, Mode::from_raw_mode(0o644)).map_err(|_| ExecutorError::StepFailed)?;
            let mut file = std::fs::File::from(file);
            std::io::Write::write_all(&mut file, crate::ols::MAINTENANCE_PAGE.as_bytes())
                .map_err(|_| ExecutorError::StepFailed)
        }
        Err(rustix::io::Errno::EXIST) => {
            let fd = fs::openat(
                &dir,
                "503.html",
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| ExecutorError::Collision)?;
            let stat = fs::fstat(&fd).map_err(|_| ExecutorError::Collision)?;
            if fs::FileType::from_raw_mode(stat.st_mode) != fs::FileType::RegularFile
                || stat.st_nlink != 1
                || stat.st_mode & 0o022 != 0
            {
                return Err(ExecutorError::Collision);
            }
            let mut existing = Vec::new();
            std::io::Read::read_to_end(&mut std::fs::File::from(fd), &mut existing)
                .map_err(|_| ExecutorError::Collision)?;
            if existing == crate::ols::MAINTENANCE_PAGE.as_bytes() {
                Ok(())
            } else {
                Err(ExecutorError::Collision)
            }
        }
        Err(_) => Err(ExecutorError::StepFailed),
    }
}

/// W269: make sure a site has the W260 error page before its vhost joins a
/// generation. Pre-W260 provisions lack `errors/503.html`, and OLS `-t`
/// then fails with an opaque exit 2. Idempotent; never overwrites a foreign page.
pub fn ensure_error_page(layout: &SiteLayout) -> Result<(), ExecutorError> {
    let sites = files::open_traversable_directory(Path::new(SITES_ROOT), 0)?;
    let root = files::open_child_directory(&sites, &layout.account, 0)?;
    match fs::mkdirat(&root, "errors", Mode::from_raw_mode(0o755)) {
        Ok(()) => {
            let dir = files::open_child_directory(&root, "errors", 0)?;
            fs::fchmod(&dir, Mode::from_raw_mode(0o755)).map_err(|_| ExecutorError::StepFailed)?;
            fs::fchown(
                &dir,
                Some(rustix::fs::Uid::from_raw(0)),
                Some(rustix::fs::Gid::from_raw(0)),
            )
            .map_err(|_| ExecutorError::StepFailed)?;
        }
        Err(rustix::io::Errno::EXIST) => {}
        Err(_) => return Err(ExecutorError::StepFailed),
    }
    write_error_page(&root)
}

fn make_directory(
    parent: &OwnedFd,
    name: &str,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<(), ExecutorError> {
    match fs::mkdirat(parent, name, Mode::from_raw_mode(0o700)) {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => return Err(ExecutorError::Collision),
        Err(_) => return Err(ExecutorError::StepFailed),
    }
    let fd = fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ExecutorError::StepFailed)?;
    fs::fchown(
        &fd,
        Some(rustix::fs::Uid::from_raw(uid)),
        Some(rustix::fs::Gid::from_raw(gid)),
    )
    .map_err(|_| ExecutorError::StepFailed)?;
    fs::fchmod(&fd, Mode::from_raw_mode(mode)).map_err(|_| ExecutorError::StepFailed)?;
    fs::fsync(parent).map_err(|_| ExecutorError::StepFailed)
}

pub(crate) fn write_new(
    directory: &OwnedFd,
    name: &str,
    bytes: &[u8],
) -> Result<(), ExecutorError> {
    let fd = fs::openat(
        directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o644),
    )
    .map_err(|error| match error {
        rustix::io::Errno::EXIST => ExecutorError::Collision,
        _ => ExecutorError::StepFailed,
    })?;
    // The service umask (0077) masks the create mode; set it explicitly.
    fs::fchmod(&fd, Mode::from_raw_mode(0o644)).map_err(|_| ExecutorError::StepFailed)?;
    let mut file = std::fs::File::from(fd);
    file.write_all(bytes)
        .map_err(|_| ExecutorError::StepFailed)?;
    file.sync_all().map_err(|_| ExecutorError::StepFailed)
}

/// Like `write_new`, then owned by `uid` with `mode` before any byte is written.
pub(crate) fn write_owned(
    directory: &OwnedFd,
    name: &str,
    bytes: &[u8],
    uid: u32,
    mode: u32,
) -> Result<(), ExecutorError> {
    let fd = fs::openat(
        directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|error| match error {
        rustix::io::Errno::EXIST => ExecutorError::Collision,
        _ => ExecutorError::StepFailed,
    })?;
    fs::fchown(
        &fd,
        Some(rustix::fs::Uid::from_raw(uid)),
        Some(rustix::fs::Gid::from_raw(uid)),
    )
    .and_then(|()| fs::fchmod(&fd, Mode::from_raw_mode(mode)))
    .map_err(|_| ExecutorError::StepFailed)?;
    let mut file = std::fs::File::from(fd);
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| ExecutorError::StepFailed)
}

/// Runs fixed administrative SQL as the database root over the local socket
/// (identifiers only from executor-derived values; nothing from requests).
pub(crate) fn mariadb_admin(sql: &str) -> Result<(), ExecutorError> {
    spawn(
        MARIADB,
        &["--batch", "--socket", DB_SOCKET],
        false,
        Some(sql.as_bytes()),
    )
    .map(drop)
}

/// Fixed program, derived arguments, empty environment, bounded time.
pub(crate) fn run(program: &str, args: &[&str]) -> Result<(), ExecutorError> {
    spawn(program, args, false, None).map(drop)
}

pub(crate) fn output(program: &str, args: &[&str]) -> Result<String, ExecutorError> {
    spawn(program, args, true, None)
}

/// Like [`output`] for a tool whose fixed exit codes in `success` are all
/// normal results (W335: `quotaon -p` exits with the count of quotas on).
pub(crate) fn output_allowing(
    program: &str,
    args: &[&str],
    success: &[i32],
) -> Result<String, ExecutorError> {
    spawn_with(program, args, true, None, success)
}

pub(crate) fn spawn(
    program: &str,
    args: &[&str],
    capture: bool,
    input: Option<&[u8]>,
) -> Result<String, ExecutorError> {
    spawn_with(program, args, capture, input, &[0])
}

fn spawn_with(
    program: &str,
    args: &[&str],
    capture: bool,
    input: Option<&[u8]>,
    success: &[i32],
) -> Result<String, ExecutorError> {
    check_program(program)?;
    let stdout = if capture {
        Stdio::piped()
    } else {
        Stdio::null()
    };
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(stdout)
        // Tool diagnostics go to the service journal for review, except the
        // database client, whose errors can quote SQL text that carries a secret.
        .stderr(if program == MARIADB {
            Stdio::null()
        } else {
            Stdio::inherit()
        })
        .spawn()
        .map_err(|_| ExecutorError::Unavailable)?;
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    // Read output on a helper thread so the deadline still applies if the
    // tool hangs with its stdout open.
    let reader = child.stdout.take().map(|out| {
        thread::spawn(move || {
            let mut text = String::new();
            std::io::Read::read_to_string(&mut std::io::Read::take(out, 1 << 20), &mut text)
                .map(|_| text)
        })
    });
    // Feed stdin on its own thread too: a tool may emit output before it has
    // consumed all input (tar listing), so a blocking write here deadlocks.
    // Secrets travel only on stdin, never in argv or the environment.
    let writer = match (input, child.stdin.take()) {
        (Some(bytes), Some(mut stdin)) => {
            let bytes = bytes.to_vec();
            Some(thread::spawn(move || stdin.write_all(&bytes)))
        }
        _ => None,
    };
    let collect = |reader: Option<thread::JoinHandle<std::io::Result<String>>>| match reader {
        Some(handle) => handle
            .join()
            .ok()
            .and_then(Result::ok)
            .ok_or(ExecutorError::StepFailed),
        None => Ok(String::new()),
    };
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.code().is_some_and(|code| success.contains(&code)) => {
                let fed = writer.is_none_or(|handle| handle.join().is_ok_and(|r| r.is_ok()));
                let text = collect(reader)?;
                return if fed {
                    Ok(text)
                } else {
                    Err(ExecutorError::StepFailed)
                };
            }
            Ok(Some(_)) => return Err(command_failed(command_label(program, args))),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(command_failed("command deadline"));
            }
        }
    }
}

/// Fixed names for the fixed tools, so the reason text is never caller data.
fn command_name(program: &str) -> &'static str {
    match program {
        "/usr/sbin/groupadd" => "groupadd failed",
        "/usr/sbin/useradd" => "useradd failed",
        "/usr/sbin/semanage" => "semanage failed",
        "/usr/sbin/restorecon" => "restorecon failed",
        "/usr/bin/systemctl" => "systemctl failed",
        "/usr/bin/systemd-run" => "systemd-run failed",
        "/usr/bin/tar" => "tar failed",
        "/usr/bin/mariadb" => "mariadb failed",
        "/usr/bin/stat" => "stat failed",
        "/usr/local/lsws/bin/openlitespeed" => "openlitespeed config test failed",
        "/usr/sbin/setquota" => "setquota failed",
        "/usr/sbin/repquota" => "repquota failed",
        "/usr/sbin/quotaon" => "quotaon failed",
        _ => "command failed",
    }
}

/// W271: the OLS config test is wrapped in systemd-run (W238); name the
/// inner failure so a missing vhost path is not logged as "systemd-run failed".
/// W335: the quota tools also run inside systemd-run and are named the same way.
fn command_label(program: &str, args: &[&str]) -> &'static str {
    const WRAPPED: [&str; 4] = [
        "/usr/local/lsws/bin/openlitespeed",
        "/usr/sbin/setquota",
        "/usr/sbin/repquota",
        "/usr/sbin/quotaon",
    ];
    match WRAPPED.iter().find(|tool| args.contains(tool)) {
        Some(tool) if program == "/usr/bin/systemd-run" => command_name(tool),
        _ => command_name(program),
    }
}

/// Tools must be root-owned regular files that nobody else can modify.
pub(crate) fn check_program(program: &str) -> Result<(), ExecutorError> {
    let stat = fs::stat(program).map_err(|_| ExecutorError::Unavailable)?;
    if fs::FileType::from_raw_mode(stat.st_mode) != fs::FileType::RegularFile
        || stat.st_uid != 0
        || stat.st_mode & 0o022 != 0
    {
        return Err(ExecutorError::Unavailable);
    }
    Ok(())
}

#[cfg(test)]
mod verify_report_tests {
    use super::verify_report_matches;

    fn report(others: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "user": "rs_w361a",
            "context": "system_u:system_r:rustiron_php_t:s0:c201",
            "database": "rs_w361a",
            "db_user": "rs_w361a@localhost",
            "wp_config": true,
            "version": true,
            "can_write_html": false,
            "reads_other_sites": others,
            "core": {"checked": 1, "mismatched": 0, "missing": 0},
            "installed": true,
        })
    }

    /// W361: the first site on a fresh host sees no other site. PHP's
    /// `json_encode` writes that empty map as `[]`, and Verify refused the
    /// site with "verify report does not match the site".
    #[test]
    fn the_first_site_with_no_other_site_matches() {
        let report = report(serde_json::from_str("[]").unwrap());
        assert!(verify_report_matches(&report, "rs_w361a", "s0:c201", true));
    }

    #[test]
    fn another_readable_site_or_a_wrong_identity_does_not_match() {
        let ok = |others| verify_report_matches(&report(others), "rs_w361a", "s0:c201", true);
        assert!(ok(serde_json::json!({})));
        assert!(ok(serde_json::json!({"rs_w361b": false})));
        assert!(!ok(serde_json::json!({"rs_w361b": true})));
        assert!(!ok(
            serde_json::json!({"rs_w361b": false, "rs_w361c": true})
        ));
        assert!(!ok(serde_json::json!(["rs_w361b"])));
        assert!(!ok(serde_json::json!({"rs_w361b": "no"})));
        assert!(!ok(serde_json::Value::Null));
        let mut other_user = report(serde_json::json!({}));
        other_user["user"] = "rs_w361b".into();
        assert!(!verify_report_matches(
            &other_user,
            "rs_w361a",
            "s0:c201",
            true
        ));
        let mut writable = report(serde_json::json!({}));
        writable["can_write_html"] = true.into();
        assert!(!verify_report_matches(
            &writable, "rs_w361a", "s0:c201", true
        ));
        assert!(!verify_report_matches(
            &report(serde_json::json!({})),
            "rs_w361a",
            "s0:c202",
            true
        ));
    }

    /// W399 (D-047): Verify of the install recipe requires an installed
    /// WordPress (the `siteurl` option and the `rustiron_admin` login), so a
    /// provision never succeeds with a site at its installer. The unpack-only
    /// lab recipe requires the opposite: no tables.
    #[test]
    fn the_install_recipe_needs_an_installed_site_and_the_unpack_recipe_none() {
        let installed = report(serde_json::json!({}));
        assert!(verify_report_matches(
            &installed, "rs_w361a", "s0:c201", true
        ));
        assert!(!verify_report_matches(
            &installed, "rs_w361a", "s0:c201", false
        ));
        let mut empty = report(serde_json::json!({}));
        empty["installed"] = false.into();
        assert!(!verify_report_matches(&empty, "rs_w361a", "s0:c201", true));
        assert!(verify_report_matches(&empty, "rs_w361a", "s0:c201", false));
        let mut silent = report(serde_json::json!({}));
        silent.as_object_mut().unwrap().remove("installed");
        assert!(!verify_report_matches(&silent, "rs_w361a", "s0:c201", true));
        assert!(!verify_report_matches(
            &silent, "rs_w361a", "s0:c201", false
        ));
    }
}

#[cfg(test)]
mod unpack_tests {
    use super::unpack_args;

    #[test]
    fn a_mislabelled_entry_fails_the_unpacked_tree() {
        let census = |foreign, mislabelled| crate::census::Census {
            owned_files: 3,
            foreign,
            mislabelled,
        };
        assert!(super::tree_matches(&census(0, 0), 3));
        assert!(!super::tree_matches(&census(1, 0), 3));
        assert!(!super::tree_matches(&census(0, 0), 4));
        assert!(
            !super::tree_matches(&census(0, 1), 3),
            "mislabelled accepted"
        );
    }

    fn properties(args: &[String]) -> Vec<&str> {
        args.windows(2)
            .filter(|pair| pair[0] == "--property")
            .map(|pair| pair[1].as_str())
            .collect()
    }

    #[test]
    fn unpack_job_runs_confined_at_the_site_level() {
        let args = unpack_args(
            "rs_x",
            "s0:c42",
            "/srv/sites/rs_x/html",
            "/srv/sites/rs_x/tmp/r",
        );
        let set = properties(&args);
        assert!(set.contains(&"SELinuxContext=system_u:system_r:rustiron_unpack_t:s0:c42"));
        assert!(set.contains(&"User=rs_x"));
        assert!(set.contains(&"ReadWritePaths=/srv/sites/rs_x/html"));
        assert!(set.contains(&"PrivateNetwork=yes"));
        assert!(set.contains(&"NoNewPrivileges=yes"));
        assert!(set.contains(&"CapabilityBoundingSet="));
        assert_eq!(
            set.iter()
                .filter(|p| p.starts_with("SELinuxContext="))
                .count(),
            1
        );
    }

    #[test]
    fn command_label_names_the_ols_config_test() {
        assert_eq!(
            super::command_label(
                "/usr/bin/systemd-run",
                &["--wait", "/usr/local/lsws/bin/openlitespeed", "-t"],
            ),
            "openlitespeed config test failed"
        );
        assert_eq!(
            super::command_label(
                "/usr/bin/systemd-run",
                &["--wait", "--", "/usr/sbin/setquota", "-u"],
            ),
            "setquota failed"
        );
        assert_eq!(
            super::command_label("/usr/bin/systemd-run", &["--wait", "/bin/true"]),
            "systemd-run failed"
        );
    }

    #[test]
    fn unpack_job_reads_only_the_site_copy() {
        let args = unpack_args(
            "rs_x",
            "s0:c42",
            "/srv/sites/rs_x/html",
            "/srv/sites/rs_x/tmp/r",
        );
        let command = &args[args.iter().position(|a| a == "--").unwrap_or(args.len())..];
        assert_eq!(command.get(1).map(String::as_str), Some("/usr/bin/tar"));
        assert!(command.iter().any(|a| a == "--file=/srv/sites/rs_x/tmp/r"));
        assert!(
            command
                .iter()
                .any(|a| a == "--directory=/srv/sites/rs_x/html")
        );
        assert!(command.iter().any(|a| a == "--no-same-owner"));
        assert!(!args.iter().any(|a| a.contains("/var/lib/rustiron")));
    }
}

#[cfg(test)]
mod error_page_tests {
    use super::*;

    #[test]
    fn write_error_page_is_idempotent_and_refuses_a_foreign_page() {
        let dir = std::env::temp_dir().join(format!("rustiron-w269-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let root = rustix::fs::open(
            &dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        rustix::fs::mkdirat(&root, "errors", Mode::from_raw_mode(0o755)).unwrap();
        write_error_page(&root).unwrap();
        write_error_page(&root).unwrap();
        std::fs::write(dir.join("errors/503.html"), b"foreign").unwrap();
        assert_eq!(write_error_page(&root), Err(ExecutorError::Collision));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
