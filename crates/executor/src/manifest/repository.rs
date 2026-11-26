//! Repository actions of the unprivileged product store worker: the
//! identity check, the tagged snapshot listing, the structure check, the
//! retention-lock check, the gated snapshot write and the manifest stream.

use std::{
    collections::BTreeSet,
    fs::File,
    io::{ErrorKind, Read, Write},
    net::SocketAddrV4,
    os::fd::{AsRawFd, OwnedFd},
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

use rustiron_contracts::{
    Id,
    approval::{
        MAX_PRODUCT_BACKUP_CA_BYTES, MAX_PRODUCT_BACKUP_POLICY_BYTES,
        MAX_PRODUCT_BACKUP_SECRET_BYTES, ProductBackupPolicy, Sha256Digest, SiteId,
    },
};
use rustiron_executor::retention_evidence::WrittenIndexes;
use rustix::{
    fs::{self, FileType, MemfdFlags, Mode, OFlags, SealFlags},
    io::FdFlags,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::s3::{self, Element};

const MAX_CONFIG_BYTES: usize = 4 * 1024;
const MAX_LISTING_BYTES: usize = 64 * 1024;
/// `restic check --json` prints one summary line on stdout (restic v0.19.1).
const MAX_CHECK_BYTES: usize = 4 * 1024;
/// W378: `restic check` reads every index and tree, so its time grows with
/// the repository (7 to 16 s at 36 snapshots on the lab VM). It gets
/// the long deadline of the snapshot write, inside the long unit runtime
/// (`store_network::WRITE_RUNTIME_SECS`).
const CHECK_TIMEOUT: Duration = Duration::from_secs(90);
/// One decrypted restic index file (`restic cat index`).
const MAX_INDEX_BYTES: usize = 8 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(15);
/// `restic backup --json --quiet` prints one summary line on stdout (restic
/// v0.19.1, observed on the lab guest in W356). Errors go to stderr.
const MAX_BACKUP_BYTES: usize = 4 * 1024;
/// The snapshot write's own deadline, inside the unit's longer write
/// runtime (`store_network::WRITE_RUNTIME_SECS`).
const BACKUP_TIMEOUT: Duration = Duration::from_secs(90);
/// The fixed snapshot host name (W356). Restic stores the system host name
/// when `--host` is empty (W323). A fixed name keeps the guest's name out of
/// the snapshot, and restic's parent choice stays with this site's own
/// earlier snapshots of the same two paths.
const BACKUP_HOST: &str = "rustiron-product";
/// Upload connections of the snapshot write, within the relay's limit of
/// eight connections (W316).
const BACKUP_CONNECTIONS: &str = "s3.connections=2";
/// Restic's exit code for a snapshot written while some source file could
/// not be read (restic v0.19.1, observed in W356).
const RESTIC_PARTIAL: i32 = 3;

use super::write_gate::PRODUCT_WRITES_ENABLED;

/// The validated inputs of one store job: the resolved site settings and
/// sealed, nonexecutable snapshots of the CA and the two secrets.
struct Session {
    url: String,
    region: String,
    endpoint: SocketAddrV4,
    bucket: String,
    prefix: String,
    retention_days: u16,
    repository_id: Sha256Digest,
    ca: File,
    aws: File,
    password: File,
}

impl Session {
    /// Checks the projection and CA digests and the credential shapes before
    /// any network use. `None` refuses.
    fn open(site: &str, digest: &str) -> Option<Self> {
        let site = SiteId::try_from(site.to_owned()).ok()?;
        let expected = Sha256Digest::try_from(digest.to_owned()).ok()?;
        let directory = std::env::var_os("CREDENTIALS_DIRECTORY")?;
        let path = Path::new(&directory);
        if !path.is_absolute() {
            return None;
        }
        let directory = fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .ok()?;
        let projection = read_input(&directory, "destination", MAX_PRODUCT_BACKUP_POLICY_BYTES)?;
        let policy = ProductBackupPolicy::decode(&projection).ok()?;
        if policy.digest() != expected {
            return None;
        }
        let site = policy.resolve_site(&site)?;
        let ca = read_input(&directory, "ca", MAX_PRODUCT_BACKUP_CA_BYTES)?;
        if Sha256Digest::from_bytes(Sha256::digest(&ca).into()) != *site.ca_sha256() {
            return None;
        }
        let aws = read_input(&directory, "aws", MAX_PRODUCT_BACKUP_SECRET_BYTES)?;
        let password = read_input(&directory, "password", MAX_PRODUCT_BACKUP_SECRET_BYTES)?;
        if !static_credentials(&aws) || password.iter().all(u8::is_ascii_whitespace) {
            return None;
        }
        Some(Self {
            url: site.repository_url(),
            region: site.region().to_owned(),
            endpoint: site.endpoint(),
            bucket: site.bucket().to_owned(),
            prefix: site.repository_prefix(),
            retention_days: site.retention_days(),
            repository_id: site.repository_id().clone(),
            ca: snapshot(&ca)?,
            aws: snapshot(&aws)?,
            password: snapshot(&password)?,
        })
    }

    /// One fixed restic command: the [`global_arguments`] of `mode`, then
    /// `command`, in an empty environment but for the credential and
    /// password snapshot paths. Stderr is discarded.
    fn restic(&self, mode: Access, command: &[String]) -> Command {
        let mut restic = Command::new(super::RESTIC);
        restic
            .args(global_arguments(
                &self.url,
                &fd_path(&self.ca),
                &self.region,
                mode,
            ))
            .args(command)
            .env_clear()
            .env("HOME", "/dev/null")
            .env("AWS_SHARED_CREDENTIALS_FILE", fd_path(&self.aws))
            .env("RESTIC_PASSWORD_FILE", fd_path(&self.password))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        restic
    }

    /// Starts `restic` with exactly this job's three snapshots inheritable.
    fn spawn(&self, restic: &mut Command) -> Option<Child> {
        spawn_with(restic, &[&self.ca, &self.aws, &self.password])
    }

    /// Runs one fixed read-only restic command with a bounded stdout.
    fn run(&self, command: &[&str], limit: usize) -> Option<Vec<u8>> {
        let command: Vec<String> = command.iter().map(|part| (*part).to_owned()).collect();
        let mut child = self.spawn(&mut self.restic(Access::Read, &command))?;
        collect(&mut child, limit)
    }

    /// Runs one fixed `curl` batch of S3 GET requests with this job's
    /// credential and CA. Each response must be HTTP 200 with one document.
    fn curl(&self, urls: &[String]) -> Option<Vec<Element>> {
        let output = curl_with(s3::CURL, &self.ca, &self.aws, &self.region, urls, false)?;
        s3::batch(&output, urls.len())
    }

    /// W391: one fixed `curl` HEAD batch; the raw write-out lines.
    fn curl_head(&self, urls: &[String]) -> Option<Vec<u8>> {
        curl_with(s3::CURL, &self.ca, &self.aws, &self.region, urls, true)
    }

    fn bucket(&self) -> s3::Bucket<'_> {
        s3::Bucket {
            endpoint: self.endpoint,
            name: &self.bucket,
        }
    }

    fn repository_matches(&self) -> bool {
        self.run(&["cat", "config"], MAX_CONFIG_BYTES)
            .is_some_and(|output| matches_config(&output, &self.repository_id))
    }
}

/// `repo-id SITE DIGEST`: the enrolled repository ID matches.
pub(super) fn verify(site: &str, digest: &str) -> Option<()> {
    Session::open(site, digest)?
        .repository_matches()
        .then_some(())
}

/// `snapshot-tag SITE DIGEST OPERATION` (W321): after the repository ID
/// matches, the IDs of the snapshots tagged `rustiron-op-OPERATION`.
pub(super) fn tagged_snapshots(site: &str, digest: &str, operation: &str) -> Option<Vec<String>> {
    let operation = rustiron_contracts::Id::try_from(operation.to_owned()).ok()?;
    let session = Session::open(site, digest)?;
    if !session.repository_matches() {
        return None;
    }
    let tag = format!("rustiron-op-{}", operation.as_str());
    let listing = session.run(&["snapshots", "--json", "--tag", &tag], MAX_LISTING_BYTES)?;
    snapshot_ids(&listing)
}

/// `check SITE DIGEST` (W323): after the repository ID matches, `restic
/// check` (structure only, no data read, no lock) reports no error. The
/// launcher chooses the credential copy; the worker reads one `aws` slot
/// and cannot tell a fetch identity from a capture identity.
pub(super) fn check(site: &str, digest: &str) -> Option<()> {
    let session = Session::open(site, digest)?;
    if !session.repository_matches() {
        return None;
    }
    let mut child = session
        .spawn(&mut session.restic(Access::Read, &["check".to_owned(), "--json".to_owned()]))?;
    match collect_status(&mut child, MAX_CHECK_BYTES, CHECK_TIMEOUT)? {
        (status, summary) if status.success() => check_passed(&summary).then_some(()),
        _ => None,
    }
}

/// `lock SITE DIGEST [OPERATION INDEXES]` (W334, D-025 items 1 and 2). Passes only
/// when the enrolled bucket has versioning enabled and a default COMPLIANCE
/// retention of at least the enrolled days. With the write's operation and
/// index list, each new object must also carry COMPLIANCE retention that
/// covers the enrolled days from the snapshot start.
///
/// W391: a pass returns the closed lines for the runner: the bucket line,
/// then with an operation one line per object version read back.
pub(super) fn lock(site: &str, digest: &str, written: Option<(&str, &str)>) -> Option<String> {
    let written = match written {
        Some((operation, indexes)) => Some((
            Id::try_from(operation.to_owned()).ok()?,
            WrittenIndexes::parse(indexes)?,
        )),
        None => None,
    };
    let session = Session::open(site, digest)?;
    let bucket = session.bucket();
    let [versioning, lock] =
        <[Element; 2]>::try_from(session.curl(&[bucket.versioning(), bucket.object_lock()])?)
            .ok()?;
    if !s3::bucket_passes(&versioning, &lock, session.retention_days) {
        return None;
    }
    let mut lines = s3::bucket_line(s3::default_retention_days(&lock)?);
    if let Some((operation, indexes)) = written {
        for line in written_retention(&session, &operation, &indexes)? {
            lines.push_str(&line);
        }
    }
    Some(lines)
}

/// The per-object half of `lock`. The written objects are the snapshot
/// file, the index files reported by the write, and the packs in those
/// indexes. Every count is bounded; a larger repository refuses.
///
/// W391: a HEAD read names each object's current version, its lock mode
/// and its retain-until time. The version-pinned `GetObjectRetention` must
/// then return COMPLIANCE with the same time, and that time must cover the
/// enrolled days. The result is one [`s3::object_line`] per object.
fn written_retention(
    session: &Session,
    operation: &Id,
    written: &WrittenIndexes,
) -> Option<Vec<String>> {
    if !session.repository_matches() {
        return None;
    }
    let tag = format!("rustiron-op-{}", operation.as_str());
    let listing = session.run(&["snapshots", "--json", "--tag", &tag], MAX_LISTING_BYTES)?;
    let (snapshot, started) = s3::tagged_snapshot(&listing)?;
    let bucket = session.bucket();
    let indexes: Vec<_> = written.ids().map(str::to_owned).collect();
    let mut packs = BTreeSet::new();
    for id in &indexes {
        let json = session.run(&["cat", "index", id], MAX_INDEX_BYTES)?;
        s3::index_packs(&json, &mut packs)?;
        if packs.len() >= s3::MAX_OBJECTS {
            return None;
        }
    }
    if !indexes.is_empty() && packs.is_empty() {
        return None;
    }
    let objects = s3::written_objects(&session.prefix, &snapshot, &indexes, &packs)?;
    let mut lines = Vec::with_capacity(objects.len());
    for chunk in objects.chunks(s3::BATCH) {
        let heads: Vec<String> = chunk.iter().map(|o| bucket.object(&o.key)).collect();
        let reads = s3::head_batch(&session.curl_head(&heads)?, chunk.len())?;
        let urls: Vec<String> = chunk
            .iter()
            .zip(&reads)
            .map(|(object, read)| bucket.retention_version(&object.key, &read.version))
            .collect();
        let roots = session.curl(&urls)?;
        for ((object, read), root) in chunk.iter().zip(&reads).zip(&roots) {
            let until = s3::compliance_until(root)?;
            if until != read.until || !s3::retention_covers(until, started, session.retention_days)
            {
                return None;
            }
            lines.push(s3::object_line(
                object.kind,
                &object.id,
                &read.version,
                until,
            ));
        }
    }
    Some(lines)
}

/// Complete, bounded listing of the enrolled repository's index keys.
fn index_catalog(session: &Session) -> Option<BTreeSet<String>> {
    let bucket = session.bucket();
    let prefix = format!("{}/index/", session.prefix);
    let mut indexes = BTreeSet::new();
    let mut after: Option<String> = None;
    for _ in 0..s3::MAX_LIST_PAGES {
        let [root] =
            <[Element; 1]>::try_from(session.curl(&[bucket.list(&prefix, after.as_deref())])?)
                .ok()?;
        let page = s3::list_page(&root, &session.bucket, &prefix, after.as_deref())?;
        after = page.entries.last().map(|(id, _)| format!("{prefix}{id}"));
        indexes.extend(page.entries.into_iter().map(|(id, _)| id));
        if !page.truncated {
            return Some(indexes);
        }
    }
    None
}

/// One `curl` batch with `program`: GET, or with `head` the W391 HEAD
/// batch. The key pair goes into a sealed config snapshot that only `curl`
/// inherits, with the CA snapshot. The repository password and the
/// credential file stay close-on-exec. Returns the bounded stdout.
fn curl_with(
    program: &str,
    ca: &File,
    aws: &File,
    region: &str,
    urls: &[String],
    head: bool,
) -> Option<Vec<u8>> {
    let mut text = Vec::new();
    File::open(fd_path(aws))
        .ok()?
        .take(MAX_PRODUCT_BACKUP_SECRET_BYTES as u64)
        .read_to_end(&mut text)
        .ok()?;
    let (access, secret) = super::lock::credentials(std::str::from_utf8(&text).ok()?)?;
    let text = if head {
        s3::curl_head_config(&access, &secret, urls)?
    } else {
        s3::curl_config(&access, &secret, urls)?
    };
    let config = snapshot(text.as_bytes())?;
    let (config_path, ca_path) = (fd_path(&config), fd_path(ca));
    let arguments = if head {
        s3::curl_head_arguments(&config_path, &ca_path, region)?
    } else {
        s3::curl_arguments(&config_path, &ca_path, region)?
    };
    let mut curl = Command::new(program);
    curl.args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = spawn_with(&mut curl, &[ca, &config])?;
    collect(&mut child, s3::MAX_CURL_OUTPUT)
}

/// Spawns `command` with exactly `files` inheritable among the sealed
/// snapshots, which are otherwise close-on-exec. The worker runs no other
/// thread that could spawn while the flag is clear.
fn spawn_with(command: &mut Command, files: &[&File]) -> Option<Child> {
    for file in files {
        rustix::io::fcntl_setfd(file, FdFlags::empty()).ok()?;
    }
    let child = command.spawn();
    let restored = files
        .iter()
        .all(|file| rustix::io::fcntl_setfd(file, FdFlags::CLOEXEC).is_ok());
    let mut child = child.ok()?;
    if !restored {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    }
    Some(child)
}

/// Bounded stdout of a fixed child that must exit 0 in time.
fn collect(child: &mut Child, limit: usize) -> Option<Vec<u8>> {
    match collect_status(child, limit, TIMEOUT)? {
        (status, output) if status.success() => Some(output),
        _ => None,
    }
}

/// Bounded stdout and exit status of a fixed child that ends in time.
fn collect_status(
    child: &mut Child,
    limit: usize,
    timeout: Duration,
) -> Option<(ExitStatus, Vec<u8>)> {
    let output = read_output(child, Instant::now() + timeout, limit);
    if output.is_none() {
        // Always reap the fixed subprocess. It may already have exited.
        let _ = child.kill();
        let _ = child.wait();
    }
    output
}

/// Whether restic's global arguments allow a repository lock. Every read
/// passes `--no-lock`. The snapshot write takes restic's own append lock,
/// which restic writes whatever `--no-lock` says (W323).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Access {
    /// `--no-lock` and restic's default connection count.
    Read,
    /// No `--no-lock`, and [`BACKUP_CONNECTIONS`] upload connections.
    Write,
}

/// The fixed global restic arguments of one store job. `ca` is the sealed
/// snapshot path; `url` and `region` come from the enrolled projection.
fn global_arguments(url: &str, ca: &str, region: &str, mode: Access) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "--repo".to_owned(),
        url.to_owned(),
        "--cacert".to_owned(),
        ca.to_owned(),
        "--no-cache".to_owned(),
    ];
    if mode == Access::Read {
        args.push("--no-lock".to_owned());
    }
    args.extend([
        "-o".to_owned(),
        "s3.bucket-lookup=path".to_owned(),
        "-o".to_owned(),
        format!("s3.region={region}"),
        "-o".to_owned(),
        "s3.retries=1".to_owned(),
    ]);
    if mode == Access::Write {
        args.extend(["-o".to_owned(), BACKUP_CONNECTIONS.to_owned()]);
    }
    args
}

/// The two snapshot sources of a site (W323): its web root and the dump that
/// the capture's dump unit wrote. Never the whole site root, which holds
/// `private/db.cnf`. Both derive from the layout and the validated site ID.
fn backup_sources(site: &SiteId) -> (String, String) {
    let root = format!("{}/{}", super::layout::SITES_ROOT, site.account_name());
    (
        format!("{root}/html"),
        format!("{root}/tmp/{}", super::layout::CAPTURE_DUMP_FILE),
    )
}

/// W601 (D-096/P30): the two sources of a P27/EmDash app capture: persistent
/// uploads/data and the consistent SQLite online-backup bundle in `tmp`.
fn app_backup_sources(site: &SiteId) -> (String, String) {
    let root = format!("{}/{}", super::layout::SITES_ROOT, site.account_name());
    (
        format!("{root}/data"),
        format!("{root}/tmp/{}", super::layout::APP_SQLITE_BUNDLE_FILE),
    )
}

/// The fixed `restic backup` command after the global arguments (W356):
/// JSON output without status lines, the fixed host name, the operation
/// tag, and the two sources. No exclude, no `--skip-if-unchanged` (an
/// unchanged site still gets its tagged snapshot), and no dry run.
fn backup_arguments(operation: &Id, html: &str, dump: &str) -> Vec<String> {
    vec![
        "backup".to_owned(),
        "--json".to_owned(),
        "--quiet".to_owned(),
        "--host".to_owned(),
        BACKUP_HOST.to_owned(),
        "--tag".to_owned(),
        format!("rustiron-op-{}", operation.as_str()),
        html.to_owned(),
        dump.to_owned(),
    ]
}

/// What one snapshot write reports on its one stdout line.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum Written {
    /// Restic exited 0 and the index delta agrees with its summary.
    Complete {
        /// The new snapshot.
        id: String,
        /// `total_files_processed`.
        files: u64,
        /// `total_bytes_processed`.
        bytes: u64,
        /// The new index keys.
        indexes: WrittenIndexes,
    },
    /// Restic exited 3 (some source file was not read) after it wrote this
    /// snapshot: `partial <id>`. The action fails.
    Partial(String),
    /// The snapshot exists but the index delta could not be verified.
    IndexUnverified(String),
}

impl Written {
    /// The one closed line the worker prints.
    pub(super) fn line(&self) -> String {
        match self {
            Self::Complete {
                id,
                files,
                bytes,
                indexes,
            } => {
                format!("snapshot {id} {files} {bytes} {}", indexes.as_str())
            }
            Self::Partial(id) => format!("partial {id}"),
            Self::IndexUnverified(id) => format!("index-unverified {id}"),
        }
    }
}

/// `backup SITE DIGEST OPERATION` (W323, W356): refused while
/// [`PRODUCT_WRITES_ENABLED`] is `false`. D-029 opens it in product builds.
pub(super) fn backup(site: &str, digest: &str, operation: &str) -> Option<Written> {
    backup_with(PRODUCT_WRITES_ENABLED, operation, backup_sources, || {
        let session = Session::open(site, digest)?;
        let site = SiteId::try_from(site.to_owned()).ok()?;
        Some((session, site))
    })
}

/// `backup-app SITE DIGEST OPERATION` (W601, D-096/P30): backs up a P27/EmDash
/// app site's `data/` directory and consistent SQLite bundle in `tmp/`.
pub(super) fn backup_app(site: &str, digest: &str, operation: &str) -> Option<Written> {
    backup_with(
        PRODUCT_WRITES_ENABLED,
        operation,
        app_backup_sources,
        || {
            let session = Session::open(site, digest)?;
            let site = SiteId::try_from(site.to_owned()).ok()?;
            Some((session, site))
        },
    )
}

/// The `backup` decision. The gate comes before `open`, so a closed build
/// reads no secret and starts no restic. With the gate open, the action
/// requires the repository ID and both sources. It then runs the one fixed
/// `restic backup` with the key pair the launcher put in the `aws` slot.
fn backup_with(
    enabled: bool,
    operation: &str,
    sources_for: fn(&SiteId) -> (String, String),
    open: impl FnOnce() -> Option<(Session, SiteId)>,
) -> Option<Written> {
    let operation = Id::try_from(operation.to_owned()).ok()?;
    if !enabled {
        return None;
    }
    let (session, site) = open()?;
    if !session.repository_matches() {
        return None;
    }
    let (content, dump) = sources_for(&site);
    if !sources_present(&content, &dump) {
        return None;
    }
    let before = index_catalog(&session)?;
    let tmp = Path::new(&dump).parent()?.to_owned();
    let mut restic = session.restic(
        Access::Write,
        &backup_arguments(&operation, &content, &dump),
    );
    // Restic assembles packs in temporary files. The unit allows writes only
    // in the site's tmp directory.
    restic.env("TMPDIR", tmp);
    let mut child = session.spawn(&mut restic)?;
    let (status, output) = collect_status(&mut child, MAX_BACKUP_BYTES, BACKUP_TIMEOUT)?;
    backup_result(status.code(), &output, |wrote_packs| {
        let after = index_catalog(&session)?;
        let indexes = s3::written_index_ids(&before, &after, wrote_packs)?;
        if indexes.is_empty() {
            WrittenIndexes::parse("-")
        } else {
            WrittenIndexes::parse(&indexes.join(","))
        }
    })
}

/// Both sources are as the capture left them: the web root a directory, the
/// dump one regular file with one link. A symbolic link refuses.
fn sources_present(html: &str, dump: &str) -> bool {
    let html = fs::lstat(html).ok();
    let dump = fs::lstat(dump).ok();
    html.is_some_and(|stat| FileType::from_raw_mode(stat.st_mode) == FileType::Directory)
        && dump.is_some_and(|stat| {
            FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile && stat.st_nlink == 1
        })
}

/// Checks the index delta only after a complete restic write. Retains the
/// snapshot ID if restic wrote it but the delta could not be established.
fn backup_result(
    code: Option<i32>,
    output: &[u8],
    catalog: impl FnOnce(bool) -> Option<WrittenIndexes>,
) -> Option<Written> {
    let summary = backup_summary(output)?;
    match code {
        Some(0) => Some(match catalog(summary.data_added_packed > 0) {
            Some(indexes) => Written::Complete {
                id: summary.snapshot_id,
                files: summary.total_files_processed,
                bytes: summary.total_bytes_processed,
                indexes,
            },
            None => Written::IndexUnverified(summary.snapshot_id),
        }),
        Some(RESTIC_PARTIAL) => Some(Written::Partial(summary.snapshot_id)),
        _ => None,
    }
}

/// The summary line of `restic backup --json --quiet` (restic v0.19.1,
/// observed on the lab guest in W356). Every field must be present, and no
/// other field may be.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupSummary {
    message_type: String,
    #[serde(rename = "files_new")]
    _files_new: u64,
    #[serde(rename = "files_changed")]
    _files_changed: u64,
    #[serde(rename = "files_unmodified")]
    _files_unmodified: u64,
    #[serde(rename = "dirs_new")]
    _dirs_new: u64,
    #[serde(rename = "dirs_changed")]
    _dirs_changed: u64,
    #[serde(rename = "dirs_unmodified")]
    _dirs_unmodified: u64,
    #[serde(rename = "data_blobs")]
    _data_blobs: u64,
    #[serde(rename = "tree_blobs")]
    _tree_blobs: u64,
    #[serde(rename = "data_added")]
    _data_added: u64,
    data_added_packed: u64,
    total_files_processed: u64,
    total_bytes_processed: u64,
    #[serde(rename = "total_duration")]
    _total_duration: f64,
    #[serde(rename = "backup_start")]
    _backup_start: String,
    #[serde(rename = "backup_end")]
    _backup_end: String,
    snapshot_id: String,
}

/// Exactly one summary line with a full lowercase snapshot ID.
fn backup_summary(output: &[u8]) -> Option<BackupSummary> {
    let text = std::str::from_utf8(output).ok()?;
    let line = text.strip_suffix('\n').unwrap_or(text);
    if line.contains('\n') {
        return None;
    }
    let summary: BackupSummary = serde_json::from_str(line).ok()?;
    (summary.message_type == "summary"
        && Sha256Digest::try_from(summary.snapshot_id.clone()).is_ok())
    .then_some(summary)
}

/// The fixed `restic dump` of one snapshot as a tar stream, after the read
/// global arguments (W356; the lab worker's W203 `dump` uses the same).
fn dump_arguments(snapshot: &str) -> Option<Vec<String>> {
    Sha256Digest::try_from(snapshot.to_owned()).ok()?;
    Some(vec![
        "dump".to_owned(),
        "--archive".to_owned(),
        "tar".to_owned(),
        snapshot.to_owned(),
        "/".to_owned(),
    ])
}

/// `manifest SITE DIGEST SNAPSHOT` (W356, design step 10): after the
/// repository ID matches, the `restic dump` stream of one snapshot for the
/// W203 walk. The caller reads the stream; the unit bounds the run time.
pub(super) fn manifest_dump(site: &str, digest: &str, snapshot: &str) -> Option<Child> {
    let arguments = dump_arguments(snapshot)?;
    let session = Session::open(site, digest)?;
    if !session.repository_matches() {
        return None;
    }
    session.spawn(&mut session.restic(Access::Read, &arguments))
}

/// `restic stats --json` in restore-size mode prints one object (restic
/// v0.19.1).
const MAX_STATS_BYTES: usize = 512;
/// `restic restore --quiet` prints nothing on success. Anything it prints
/// is bounded and discarded.
const MAX_RESTORE_OUTPUT_BYTES: usize = 4 * 1024;
/// The probe fetch's own deadline, inside the unit's longer runtime
/// (`store_network::WRITE_RUNTIME_SECS`), as for the snapshot write.
const RESTORE_TIMEOUT: Duration = Duration::from_secs(90);

/// The probe sandbox's writable directory for `probe` (D-031, W373): the
/// journaled name's [`super::layout::probe_tmp`], when it is a directory of
/// the calling account and holds no restore target yet. Anything else
/// refuses, before any secret is read.
fn probe_sandbox(probe: &str) -> Option<String> {
    let tmp = super::layout::probe_tmp(probe)?;
    let uid = rustix::process::getuid().as_raw();
    sandbox_ready(Path::new(&tmp), uid, super::layout::PROBE_RESTORE_DIR).then_some(tmp)
}

/// D-078 (W499): the clone fetch's writable directory for a target site
/// account: its [`super::layout::clone_tmp`], when it is a directory of the
/// calling account and holds no clone target yet. Anything else refuses,
/// before any secret is read.
fn clone_sandbox(account: &str) -> Option<String> {
    let tmp = super::layout::clone_tmp(account)?;
    let uid = rustix::process::getuid().as_raw();
    sandbox_ready(Path::new(&tmp), uid, super::layout::CLONE_RESTORE_DIR).then_some(tmp)
}

/// `tmp` is a directory (not a link) owned by `uid`, and its restore target
/// `target` does not exist (not even as a dangling link).
fn sandbox_ready(tmp: &Path, uid: u32, target: &str) -> bool {
    let owned = fs::lstat(tmp).is_ok_and(|stat| {
        FileType::from_raw_mode(stat.st_mode) == FileType::Directory && stat.st_uid == uid
    });
    owned && matches!(fs::lstat(tmp.join(target)), Err(rustix::io::Errno::NOENT))
}

/// Where one restore writes: a probe sandbox (D-031) or a clone target's
/// own `tmp` (D-078). Each derives its directory from its account name.
#[derive(Clone, Copy)]
pub(super) enum RestoreInto<'a> {
    /// A journaled probe account.
    Probe(&'a str),
    /// The target site account of a journaled clone.
    Clone(&'a str),
}

impl RestoreInto<'_> {
    /// The ready writable directory and the restore target's name in it.
    fn ready(self) -> Option<(String, &'static str)> {
        match self {
            Self::Probe(probe) => {
                probe_sandbox(probe).map(|tmp| (tmp, super::layout::PROBE_RESTORE_DIR))
            }
            Self::Clone(account) => {
                clone_sandbox(account).map(|tmp| (tmp, super::layout::CLONE_RESTORE_DIR))
            }
        }
    }
}

/// The fixed `restic stats` of one snapshot's logical restore size.
fn stats_arguments(snapshot: &str) -> Option<Vec<String>> {
    Sha256Digest::try_from(snapshot.to_owned()).ok()?;
    Some(vec![
        "stats".to_owned(),
        "--json".to_owned(),
        "--mode".to_owned(),
        "restore-size".to_owned(),
        snapshot.to_owned(),
    ])
}

/// The two counts of a `restic stats --json --mode restore-size` line.
#[derive(Deserialize)]
struct RestoreStats {
    total_size: u64,
    total_file_count: u64,
}

/// One stats object; anything else refuses.
fn restore_stats(output: &[u8]) -> Option<(u64, u64)> {
    let text = std::str::from_utf8(output).ok()?;
    let line = text.strip_suffix('\n').unwrap_or(text);
    if line.contains('\n') {
        return None;
    }
    let stats: RestoreStats = serde_json::from_str(line).ok()?;
    Some((stats.total_size, stats.total_file_count))
}

/// `restore-size SITE DIGEST SNAPSHOT PROBE` (D-031, W373) and
/// `clone-restore-size SITE DIGEST SNAPSHOT ACCOUNT` (D-078, W499): after
/// the sandbox and repository ID checks, the snapshot's logical restore
/// size and file count. The executor applies its ceilings to them.
pub(super) fn restore_size(
    site: &str,
    digest: &str,
    snapshot: &str,
    into: RestoreInto<'_>,
) -> Option<(u64, u64)> {
    let arguments = stats_arguments(snapshot)?;
    into.ready()?;
    let session = Session::open(site, digest)?;
    if !session.repository_matches() {
        return None;
    }
    let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
    restore_stats(&session.run(&arguments, MAX_STATS_BYTES)?)
}

/// The fixed `restic restore` of one snapshot into `target`, after the read
/// global arguments: no extended security attributes (each entry takes the
/// sandbox label at creation, W265), no output, no include or exclude of
/// paths, no verify, no delete.
fn restore_arguments(snapshot: &str, target: &str) -> Option<Vec<String>> {
    Sha256Digest::try_from(snapshot.to_owned()).ok()?;
    Some(vec![
        "restore".to_owned(),
        "--quiet".to_owned(),
        "--exclude-xattr=security.*".to_owned(),
        format!("--target={target}"),
        snapshot.to_owned(),
    ])
}

/// `restore SITE DIGEST SNAPSHOT PROBE` (D-031, W373) and `clone-restore
/// SITE DIGEST SNAPSHOT ACCOUNT` (D-078, W499): after the sandbox and
/// repository ID checks, the one fixed `restic restore` into
/// `<probe tmp>/restore` or `<target site tmp>/clone`. Only restic exit 0
/// within the deadline passes.
pub(super) fn restore(
    site: &str,
    digest: &str,
    snapshot: &str,
    into: RestoreInto<'_>,
) -> Option<()> {
    let (tmp, name) = into.ready()?;
    let target = format!("{tmp}/{name}");
    let arguments = restore_arguments(snapshot, &target)?;
    let session = Session::open(site, digest)?;
    if !session.repository_matches() {
        return None;
    }
    let mut restic = session.restic(Access::Read, &arguments);
    restic.env("TMPDIR", &tmp);
    let mut child = session.spawn(&mut restic)?;
    let (status, _) = collect_status(&mut child, MAX_RESTORE_OUTPUT_BYTES, RESTORE_TIMEOUT)?;
    status.success().then_some(())
}

/// The summary line of `restic check --json` (restic v0.19.1). Errors go to
/// stderr, which the worker discards. Restic leaves `broken_packs` as a nil
/// Go slice when no pack is broken, so a clean check prints `null`. The
/// field must still be present.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckSummary {
    message_type: String,
    num_errors: u64,
    #[serde(deserialize_with = "Option::deserialize")]
    broken_packs: Option<Vec<String>>,
    suggest_repair_index: bool,
    #[serde(rename = "suggest_prune")]
    _suggest_prune: bool,
}

/// A passing check: one summary with no error, no broken pack and no index
/// repair hint. A prune hint alone passes: an interrupted upload can leave
/// unreferenced packs, and no store job may prune.
fn check_passed(output: &[u8]) -> bool {
    serde_json::from_slice::<CheckSummary>(output).is_ok_and(|summary| {
        summary.message_type == "summary"
            && summary.num_errors == 0
            && summary.broken_packs.is_none_or(|packs| packs.is_empty())
            && !summary.suggest_repair_index
    })
}

/// Full snapshot IDs from `restic snapshots --json`; anything else refuses.
fn snapshot_ids(listing: &[u8]) -> Option<Vec<String>> {
    let items: Vec<serde_json::Value> = serde_json::from_slice(listing).ok()?;
    items
        .iter()
        .map(|item| {
            let id = item.get("id")?.as_str()?;
            Sha256Digest::try_from(id.to_owned())
                .ok()
                .map(|_| id.to_owned())
        })
        .collect()
}

fn read_input(directory: &OwnedFd, name: &str, limit: usize) -> Option<Vec<u8>> {
    let fd = fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .ok()?;
    let stat = fs::fstat(&fd).ok()?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile || stat.st_nlink != 1 {
        return None;
    }
    let mut bytes = Vec::new();
    File::from(fd)
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .ok()?;
    (!bytes.is_empty() && bytes.len() <= limit).then_some(bytes)
}

fn static_credentials(bytes: &[u8]) -> bool {
    if !bytes.is_ascii() {
        return false;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    if lines.next() != Some("[default]") {
        return false;
    }
    let key = |line: &str| {
        let (name, value) = line.split_once('=')?;
        let value = value.trim();
        if value.is_empty()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_+-/=".contains(&byte))
        {
            return None;
        }
        match name.trim() {
            "aws_access_key_id" => Some(false),
            "aws_secret_access_key" => Some(true),
            _ => None,
        }
    };
    matches!(
        (
            lines.next().and_then(key),
            lines.next().and_then(key),
            lines.next()
        ),
        (Some(false), Some(true), None) | (Some(true), Some(false), None)
    )
}

fn snapshot(bytes: &[u8]) -> Option<File> {
    // Close-on-exec: `spawn_with` lets each fixed child inherit only the
    // snapshots it reads. Seals prevent any replacement of bytes between
    // validation and the child's read.
    let fd = fs::memfd_create(
        "rustiron-repo-input",
        MemfdFlags::NOEXEC_SEAL | MemfdFlags::ALLOW_SEALING | MemfdFlags::CLOEXEC,
    )
    .ok()?;
    fs::fchmod(&fd, Mode::RUSR | Mode::WUSR).ok()?;
    let mut file = File::from(fd);
    file.write_all(bytes).ok()?;
    fs::fcntl_add_seals(
        &file,
        SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
    )
    .ok()?;
    Some(file)
}

fn fd_path(file: &File) -> String {
    format!("/proc/self/fd/{}", file.as_raw_fd())
}

fn read_output(
    child: &mut Child,
    deadline: Instant,
    limit: usize,
) -> Option<(ExitStatus, Vec<u8>)> {
    let mut stdout = child.stdout.take()?;
    fs::fcntl_setfl(&stdout, OFlags::NONBLOCK).ok()?;
    let mut output = Vec::new();
    let mut eof = false;
    while Instant::now() < deadline {
        if !eof {
            let remaining = limit + 1 - output.len();
            match (&mut stdout)
                .take(remaining as u64)
                .read_to_end(&mut output)
            {
                Ok(_) => eof = true,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(_) => return None,
            }
            if output.len() > limit {
                return None;
            }
        }
        if eof && let Some(status) = child.try_wait().ok()? {
            return Some((status, output));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    None
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResticConfig {
    version: u16,
    id: Sha256Digest,
    #[serde(rename = "chunker_polynomial")]
    _chunker_polynomial: String,
}

fn matches_config(output: &[u8], expected: &Sha256Digest) -> bool {
    serde_json::from_slice::<ResticConfig>(output)
        .is_ok_and(|config| matches!(config.version, 1 | 2) && config.id == *expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CREDENTIAL: &str =
        "[default]\naws_access_key_id = SYNTHETIC_W313\naws_secret_access_key = synthetic+key/=\n";

    #[test]
    fn the_check_deadline_outlasts_the_short_one_and_fits_the_long_unit() {
        // W378: a 15 s check failed on a lab repository of 36 snapshots.
        assert!(CHECK_TIMEOUT > TIMEOUT);
        assert!(CHECK_TIMEOUT <= Duration::from_secs(90));
        assert_eq!(CHECK_TIMEOUT, BACKUP_TIMEOUT);
    }

    #[test]
    fn product_credentials_accept_only_a_static_default_profile() {
        assert!(static_credentials(CREDENTIAL.as_bytes()));
        for extra in [
            "credential_process=/usr/bin/false fixture",
            "aws_session_token=TOKEN",
            "aws_access_key_id=SECOND",
            "[other]",
        ] {
            assert!(
                !static_credentials(format!("{CREDENTIAL}{extra}\n").as_bytes()),
                "{extra}"
            );
        }
        assert!(!static_credentials(b"[default]\naws_access_key_id=ONLY\n"));
        assert!(!static_credentials(
            CREDENTIAL
                .replace("synthetic+key/=", "\"quoted\"")
                .as_bytes()
        ));
    }

    #[test]
    fn snapshot_listing_yields_only_full_ids() {
        let id = "c".repeat(64);
        assert_eq!(snapshot_ids(b"[]"), Some(vec![]));
        let one = format!(r#"[{{"id":"{id}","short_id":"cccccccc","tags":["rustiron-op-op_x"]}}]"#);
        assert_eq!(snapshot_ids(one.as_bytes()), Some(vec![id.clone()]));
        for bad in [
            r#"[{"short_id":"cccccccc"}]"#.to_owned(),
            r#"[{"id":"cccccccc"}]"#.to_owned(),
            format!(r#"[{{"id":"{}"}}]"#, "C".repeat(64)),
            r#"{"id":"x"}"#.to_owned(),
            "not json".to_owned(),
        ] {
            assert_eq!(snapshot_ids(bad.as_bytes()), None, "{bad}");
        }
    }

    /// A clean summary as restic v0.19.1 prints it: `broken_packs` is null.
    const CHECK_PASS: &str = r#"{"message_type":"summary","num_errors":0,"broken_packs":null,"suggest_repair_index":false,"suggest_prune":false}"#;

    #[test]
    fn check_passes_only_a_clean_summary() {
        assert!(check_passed(CHECK_PASS.as_bytes()));
        assert!(check_passed(format!("{CHECK_PASS}\n").as_bytes()));
        assert!(check_passed(CHECK_PASS.replace("null", "[]").as_bytes()));
        assert!(check_passed(
            CHECK_PASS
                .replace("\"suggest_prune\":false", "\"suggest_prune\":true")
                .as_bytes()
        ));
        for bad in [
            CHECK_PASS.replace("\"num_errors\":0", "\"num_errors\":1"),
            CHECK_PASS.replace("null", "[\"0123abcd\"]"),
            CHECK_PASS.replace("\"broken_packs\":null,", ""),
            CHECK_PASS.replace(
                "\"suggest_repair_index\":false",
                "\"suggest_repair_index\":true",
            ),
            CHECK_PASS.replace("\"summary\"", "\"error\""),
            CHECK_PASS.replace(",\"suggest_prune\":false", ""),
            CHECK_PASS.replace('}', ",\"extra\":1}"),
            format!("{CHECK_PASS}\n{CHECK_PASS}"),
            r#"{"message_type":"error","message":"pack 0123: not found"}"#.to_owned(),
            "no errors were found\n".to_owned(),
            String::new(),
        ] {
            assert!(!check_passed(bad.as_bytes()), "{bad}");
        }
    }

    #[test]
    fn the_closed_write_gate_refuses_before_opening_a_session() {
        let opened = std::cell::Cell::new(false);
        let open = || {
            opened.set(true);
            None
        };
        assert_eq!(backup_with(false, "op_w323", backup_sources, open), None);
        assert!(!opened.get(), "the closed gate opened a session");
        // The open gate reaches the session, which refuses here; a bad
        // operation refuses before either.
        assert_eq!(backup_with(true, "op_w323", backup_sources, open), None);
        assert!(opened.get());
        opened.set(false);
        assert_eq!(backup_with(true, "op w323", backup_sources, open), None);
        assert!(!opened.get());
    }

    #[test]
    fn the_product_worker_gate_is_open() {
        // D-029: this module exists only in product builds, and each of them
        // may write capture snapshots.
        assert!(
            std::hint::black_box(PRODUCT_WRITES_ENABLED),
            "the product worker write gate is closed"
        );
    }

    #[test]
    fn reads_take_no_lock_and_the_write_takes_two_connections() {
        let read = global_arguments(
            "s3:https://192.0.2.7:9443/b/sites/rs_x",
            "/proc/self/fd/7",
            "us-east-1",
            Access::Read,
        );
        assert_eq!(
            read,
            [
                "--repo",
                "s3:https://192.0.2.7:9443/b/sites/rs_x",
                "--cacert",
                "/proc/self/fd/7",
                "--no-cache",
                "--no-lock",
                "-o",
                "s3.bucket-lookup=path",
                "-o",
                "s3.region=us-east-1",
                "-o",
                "s3.retries=1",
            ]
        );
        let write = global_arguments("u", "/proc/self/fd/7", "r", Access::Write);
        assert!(!write.contains(&"--no-lock".to_owned()));
        assert!(write.contains(&"--no-cache".to_owned()));
        assert_eq!(write[write.len() - 2..], ["-o", "s3.connections=2"]);
    }

    #[test]
    fn the_backup_command_is_fixed_and_names_only_the_two_sources() {
        let site = SiteId::try_from("w344a".to_owned()).unwrap();
        let (html, dump) = backup_sources(&site);
        assert_eq!(html, "/srv/sites/rs_w344a/html");
        assert_eq!(dump, "/srv/sites/rs_w344a/tmp/rustiron-capture.sql");
        let operation = Id::try_from("op_w356".to_owned()).unwrap();
        assert_eq!(
            backup_arguments(&operation, &html, &dump),
            [
                "backup",
                "--json",
                "--quiet",
                "--host",
                "rustiron-product",
                "--tag",
                "rustiron-op-op_w356",
                "/srv/sites/rs_w344a/html",
                "/srv/sites/rs_w344a/tmp/rustiron-capture.sql",
            ]
        );
    }

    /// Byte-for-byte summary of restic 0.19.1 `backup --json --quiet` on the
    /// lab guest (W356), with a synthetic path set.
    const BACKUP_SUMMARY: &str = r#"{"message_type":"summary","files_new":1,"files_changed":0,"files_unmodified":0,"dirs_new":4,"dirs_changed":0,"dirs_unmodified":0,"data_blobs":1,"tree_blobs":5,"data_added":2399,"data_added_packed":2006,"total_files_processed":1,"total_bytes_processed":3,"total_duration":0.739107161,"backup_start":"2026-11-12T15:47:48.195682548-05:00","backup_end":"2026-11-12T15:47:48.934789709-05:00","snapshot_id":"c1baf7a0755123b3980b981b5312815ca7a3aabd30c038636cc2e3889b79cb0b"}"#;
    const BACKUP_ID: &str = "c1baf7a0755123b3980b981b5312815ca7a3aabd30c038636cc2e3889b79cb0b";

    #[test]
    fn only_one_summary_with_exit_0_or_3_names_the_snapshot() {
        let index_id = "a".repeat(64);
        let indexes = |wrote_packs: bool| {
            assert!(wrote_packs);
            WrittenIndexes::parse(&index_id)
        };
        let complete = Written::Complete {
            id: BACKUP_ID.to_owned(),
            files: 1,
            bytes: 3,
            indexes: WrittenIndexes::parse(&index_id).unwrap(),
        };
        assert_eq!(
            backup_result(Some(0), format!("{BACKUP_SUMMARY}\n").as_bytes(), indexes),
            Some(complete)
        );
        assert_eq!(
            backup_result(Some(0), BACKUP_SUMMARY.as_bytes(), indexes)
                .unwrap()
                .line(),
            format!("snapshot {BACKUP_ID} 1 3 {index_id}")
        );
        let partial = backup_result(Some(3), BACKUP_SUMMARY.as_bytes(), |_| {
            panic!("a partial write must not establish an index delta")
        })
        .unwrap();
        assert_eq!(partial, Written::Partial(BACKUP_ID.to_owned()));
        assert_eq!(partial.line(), format!("partial {BACKUP_ID}"));
        for code in [
            None,
            Some(1),
            Some(2),
            Some(10),
            Some(11),
            Some(12),
            Some(130),
        ] {
            assert_eq!(
                backup_result(code, BACKUP_SUMMARY.as_bytes(), indexes),
                None,
                "{code:?}"
            );
        }
        for bad in [
            String::new(),
            format!("{BACKUP_SUMMARY}\n{BACKUP_SUMMARY}"),
            format!("{{\"message_type\":\"status\"}}\n{BACKUP_SUMMARY}"),
            BACKUP_SUMMARY.replace("\"summary\"", "\"status\""),
            BACKUP_SUMMARY.replace(BACKUP_ID, &BACKUP_ID.to_uppercase()),
            BACKUP_SUMMARY.replace(BACKUP_ID, &BACKUP_ID[..63]),
            BACKUP_SUMMARY.replace(",\"total_files_processed\":1", ""),
            BACKUP_SUMMARY.replace('}', ",\"dry_run\":false}"),
            BACKUP_SUMMARY.replace(
                "\"total_bytes_processed\":3",
                "\"total_bytes_processed\":-3",
            ),
            r#"{"message_type":"exit_error","code":1,"message":"Fatal"}"#.to_owned(),
        ] {
            assert_eq!(
                backup_result(Some(0), bad.as_bytes(), indexes),
                None,
                "{bad}"
            );
        }
    }

    #[test]
    fn a_failed_after_listing_preserves_the_unverified_snapshot_id() {
        let result = backup_result(Some(0), BACKUP_SUMMARY.as_bytes(), |_| None).unwrap();
        assert_eq!(result, Written::IndexUnverified(BACKUP_ID.to_owned()));
        assert_eq!(result.line(), format!("index-unverified {BACKUP_ID}"));
    }

    #[test]
    fn the_probe_restore_command_is_fixed_and_writes_only_the_sandbox_target() {
        // D-031 (W373).
        let id = "a".repeat(64);
        let target = "/srv/restore-probes/rp_0a9fbc/tmp/restore";
        assert_eq!(
            restore_arguments(&id, target).unwrap(),
            [
                "restore",
                "--quiet",
                "--exclude-xattr=security.*",
                "--target=/srv/restore-probes/rp_0a9fbc/tmp/restore",
                id.as_str(),
            ]
        );
        assert_eq!(
            stats_arguments(&id).unwrap(),
            ["stats", "--json", "--mode", "restore-size", id.as_str()]
        );
        for bad in ["a".repeat(63), "A".repeat(64), "latest".to_owned()] {
            assert_eq!(restore_arguments(&bad, target), None, "{bad}");
            assert_eq!(stats_arguments(&bad), None, "{bad}");
        }
        // The worker refuses a name that is not a journaled probe account
        // before it looks at the file system.
        for probe in ["rs_w373a", "rp_0A9FBC", "rp_..", ""] {
            assert_eq!(probe_sandbox(probe), None, "{probe}");
        }
        // W499: likewise a name that is not a site account for a clone.
        for account in ["rp_0a9fbc", "rs_", "rs_../x", "stage9", ""] {
            assert_eq!(clone_sandbox(account), None, "{account}");
        }
    }

    #[test]
    fn only_one_stats_object_gives_the_restore_size() {
        // Byte-for-byte restic 0.19.1 `stats --json --mode restore-size`.
        let line = r#"{"total_size":110183745,"total_file_count":4258,"snapshots_count":1}"#;
        assert_eq!(restore_stats(line.as_bytes()), Some((110_183_745, 4258)));
        assert_eq!(
            restore_stats(format!("{line}\n").as_bytes()),
            Some((110_183_745, 4258))
        );
        for bad in [
            String::new(),
            format!("{line}\n{line}"),
            r#"{"total_size":1}"#.to_owned(),
            r#"{"total_file_count":1}"#.to_owned(),
            r#"{"total_size":-1,"total_file_count":1}"#.to_owned(),
            r#"{"total_size":"1","total_file_count":1}"#.to_owned(),
            "not json".to_owned(),
        ] {
            assert_eq!(restore_stats(bad.as_bytes()), None, "{bad}");
        }
    }

    #[test]
    fn the_sandbox_must_be_the_callers_own_directory_without_a_restore() {
        let uid = rustix::process::getuid().as_raw();
        let base = std::env::temp_dir().join(format!("ri-w373-sandbox-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let tmp = base.join("tmp");
        std::fs::create_dir_all(&tmp).unwrap();
        for name in ["restore", "clone"] {
            assert!(sandbox_ready(&tmp, uid, name));
            // Another owner refuses.
            assert!(!sandbox_ready(&tmp, uid.wrapping_add(1), name));
            // A restore target that exists refuses, even a dangling link.
            std::os::unix::fs::symlink("/nonexistent", tmp.join(name)).unwrap();
            assert!(!sandbox_ready(&tmp, uid, name));
            std::fs::remove_file(tmp.join(name)).unwrap();
            std::fs::create_dir(tmp.join(name)).unwrap();
            assert!(!sandbox_ready(&tmp, uid, name));
            // A link in place of the sandbox directory refuses.
            let link = base.join("link");
            std::os::unix::fs::symlink(&tmp, &link).unwrap();
            std::fs::remove_dir(tmp.join(name)).unwrap();
            assert!(sandbox_ready(&tmp, uid, name));
            assert!(!sandbox_ready(&link, uid, name));
            assert!(!sandbox_ready(&base.join("missing"), uid, name));
            std::fs::remove_file(&link).unwrap();
        }
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn the_manifest_dump_names_one_full_snapshot() {
        let id = "a".repeat(64);
        assert_eq!(
            dump_arguments(&id).unwrap(),
            ["dump", "--archive", "tar", id.as_str(), "/"]
        );
        for bad in [
            "a".repeat(63),
            "A".repeat(64),
            format!("{id} "),
            "latest".to_owned(),
        ] {
            assert_eq!(dump_arguments(&bad), None, "{bad}");
        }
    }

    #[test]
    fn a_missing_or_linked_source_refuses_the_write() {
        let directory =
            std::env::temp_dir().join(format!("rustiron-w356-sources-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(directory.join("html")).unwrap();
        let html = directory.join("html");
        let dump = directory.join("dump.sql");
        let (html, dump) = (html.to_str().unwrap(), dump.to_str().unwrap());
        assert!(!sources_present(html, dump), "missing dump");
        std::fs::write(dump, b"-- dump\n").unwrap();
        assert!(sources_present(html, dump));
        std::fs::hard_link(dump, directory.join("second")).unwrap();
        assert!(!sources_present(html, dump), "second link");
        std::fs::remove_file(directory.join("second")).unwrap();
        let link = directory.join("link");
        std::os::unix::fs::symlink(directory.join("html"), &link).unwrap();
        assert!(
            !sources_present(link.to_str().unwrap(), dump),
            "linked web root"
        );
        assert!(!sources_present(dump, dump), "file as web root");
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn config_requires_the_exact_id_and_supported_shape() {
        let id = "a".repeat(64);
        let expected = Sha256Digest::try_from(id.clone()).unwrap();
        let config =
            format!(r#"{{"version":2,"id":"{id}","chunker_polynomial":"3da3358b4dc173"}}"#);
        assert!(matches_config(config.as_bytes(), &expected));
        for bad in [
            config.replace(&id, &"b".repeat(64)),
            config.replace("\"version\":2", "\"version\":3"),
            config.replace("\"version\":2", "\"version\":2,\"version\":2"),
            format!("{config}{{}}"),
        ] {
            assert!(!matches_config(bad.as_bytes(), &expected));
        }
    }

    #[test]
    fn snapshot_seals_the_bytes_passed_to_the_child() {
        let mut sealed = snapshot(b"synthetic").unwrap();
        assert_eq!(
            sealed.write_all(b"replacement").unwrap_err().kind(),
            ErrorKind::PermissionDenied
        );
        assert_eq!(std::fs::read(fd_path(&sealed)).unwrap(), b"synthetic");
    }

    /// A fake `curl` in a fresh directory: it records its argv, the config
    /// file it was given, and its open memfds, then prints `response` and
    /// exits with `status`.
    fn fake_curl(name: &str, response: &str, status: u8) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let directory =
            std::env::temp_dir().join(format!("rustiron-w334-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join("response"), response).unwrap();
        let program = directory.join("curl");
        std::fs::write(
            &program,
            format!(
                "#!/bin/sh\nd={0}\nprintf '%s\\n' \"$@\" > \"$d/argv\"\n/usr/bin/cat \"$3\" > \"$d/config\"\n/usr/bin/ls -l /proc/$$/fd > \"$d/fds\"\n/usr/bin/cat \"$d/response\"\nexit {status}\n",
                directory.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        program
    }

    /// W466: the fake curl is a script this test just wrote. Another test
    /// thread may fork while its write handle is open, and the exec then
    /// fails with ETXTBSY; a few retries make the harness stable. A real
    /// failure fails every attempt. W523: the HEAD test retries too.
    fn curl_retrying(
        program: &str,
        ca: &File,
        aws: &File,
        region: &str,
        urls: &[String],
        head: bool,
    ) -> Option<Vec<u8>> {
        for _ in 0..5 {
            if let Some(output) = curl_with(program, ca, aws, region, urls, head) {
                return Some(output);
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        None
    }

    fn get_batch(
        program: &str,
        ca: &File,
        aws: &File,
        region: &str,
        urls: &[String],
    ) -> Option<Vec<Element>> {
        s3::batch(
            &curl_retrying(program, ca, aws, region, urls, false)?,
            urls.len(),
        )
    }

    /// W391: the HEAD batch sends `--head`, pairs each URL with an
    /// `output` line, and returns the write-out lines unparsed.
    #[test]
    fn the_head_batch_sends_each_body_to_dev_null() {
        let line = "200 v1 COMPLIANCE 2026-12-13T17:42:56Z\n";
        let program = fake_curl("head", line, 0);
        let directory = program.parent().unwrap();
        let ca = snapshot(b"synthetic CA").unwrap();
        let aws = snapshot(CREDENTIAL.as_bytes()).unwrap();
        let urls = ["https://198.51.100.23/store/sites/rs_a/snapshots/ab".to_owned()];
        let output = curl_retrying(
            program.to_str().unwrap(),
            &ca,
            &aws,
            "lab-east-2",
            &urls,
            true,
        )
        .unwrap();
        assert_eq!(output, line.as_bytes());
        let argv = std::fs::read_to_string(directory.join("argv")).unwrap();
        assert!(argv.ends_with("\n--head\n"), "{argv}");
        assert_eq!(
            std::fs::read_to_string(directory.join("config")).unwrap(),
            format!(
                "user = \"SYNTHETIC_W313:synthetic+key/=\"\nurl = \"{}\"\noutput = \"/dev/null\"\n",
                urls[0]
            )
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    const VERSIONING: &str =
        "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>";
    const LOCK: &str = "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>30</Days></DefaultRetention></Rule></ObjectLockConfiguration>";

    #[test]
    fn curl_gets_the_key_pair_only_in_its_sealed_config() {
        let program = fake_curl("pass", &format!("{VERSIONING}\n200\n{LOCK}\n200\n"), 0);
        let directory = program.parent().unwrap();
        let ca = snapshot(b"synthetic CA").unwrap();
        let aws = snapshot(CREDENTIAL.as_bytes()).unwrap();
        let password = snapshot(b"synthetic password").unwrap();
        let urls = [
            "https://198.51.100.23/store?versioning".to_owned(),
            "https://198.51.100.23/store?object-lock".to_owned(),
        ];
        let documents =
            get_batch(program.to_str().unwrap(), &ca, &aws, "lab-east-2", &urls).unwrap();
        assert!(s3::bucket_passes(&documents[0], &documents[1], 30));

        let argv = std::fs::read_to_string(directory.join("argv")).unwrap();
        assert!(argv.starts_with("-q\n-K\n/proc/self/fd/"), "{argv}");
        assert!(argv.contains("\n--aws-sigv4\naws:amz:lab-east-2:s3\n"));
        assert!(!argv.contains("SYNTHETIC_W313") && !argv.contains("synthetic+key"));
        assert!(!argv.contains("https://"));
        assert_eq!(
            std::fs::read_to_string(directory.join("config")).unwrap(),
            format!(
                "user = \"SYNTHETIC_W313:synthetic+key/=\"\nurl = \"{}\"\nurl = \"{}\"\n",
                urls[0], urls[1]
            )
        );
        // The CA and the config reach curl; the password and the credential
        // file stay close-on-exec. (Parallel tests may add their own.)
        let fds = std::fs::read_to_string(directory.join("fds")).unwrap();
        let inherited = |fd: String| fds.contains(&format!(" {fd} -> /memfd:rustiron-repo-input"));
        let config = argv
            .lines()
            .nth(2)
            .unwrap()
            .trim_start_matches("/proc/self/fd/");
        assert!(inherited(config.to_owned()), "{fds}");
        assert!(inherited(ca.as_raw_fd().to_string()), "{fds}");
        assert!(!inherited(aws.as_raw_fd().to_string()), "{fds}");
        assert!(!inherited(password.as_raw_fd().to_string()), "{fds}");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_failed_or_short_curl_batch_refuses() {
        let ca = snapshot(b"synthetic CA").unwrap();
        let aws = snapshot(CREDENTIAL.as_bytes()).unwrap();
        let urls = [
            "https://198.51.100.23/store?versioning".to_owned(),
            "https://198.51.100.23/store?object-lock".to_owned(),
        ];
        for (name, response, status) in [
            ("exit", format!("{VERSIONING}\n200\n{LOCK}\n200\n"), 22),
            ("status", format!("{VERSIONING}\n200\n\n403\n"), 0),
            ("short", format!("{VERSIONING}\n200\n"), 0),
        ] {
            let program = fake_curl(name, &response, status);
            assert!(
                get_batch(program.to_str().unwrap(), &ca, &aws, "lab-east-2", &urls).is_none(),
                "{name}"
            );
            std::fs::remove_dir_all(program.parent().unwrap()).unwrap();
        }
        let program = fake_curl("region", "", 0);
        assert!(get_batch(program.to_str().unwrap(), &ca, &aws, "Bad Region", &urls).is_none());
        assert!(
            !program.parent().unwrap().join("argv").exists(),
            "refused before spawn"
        );
        std::fs::remove_dir_all(program.parent().unwrap()).unwrap();
    }

    #[test]
    fn stdout_collection_refuses_overflow_and_deadline() {
        let mut oversized = Command::new("/usr/bin/head")
            .args(["-c", "4097", "/dev/zero"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        assert!(
            read_output(
                &mut oversized,
                Instant::now() + Duration::from_secs(2),
                MAX_CONFIG_BYTES
            )
            .is_none()
        );
        oversized.wait().unwrap();

        let mut stalled = Command::new("/usr/bin/sleep")
            .arg("10")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        assert!(
            read_output(
                &mut stalled,
                Instant::now() + Duration::from_millis(50),
                MAX_CONFIG_BYTES
            )
            .is_none()
        );
        assert!(stalled.try_wait().unwrap().is_none());
        stalled.kill().unwrap();
        stalled.wait().unwrap();
    }
}
