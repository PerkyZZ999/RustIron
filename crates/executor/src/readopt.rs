//! W372 (D-030): the facts a `site_readopt` verifies and the rules that
//! judge them. Re-adoption changes nothing on the host: every function here
//! only reads.
//!
//! The admin helper reads what the executor domain cannot ([`HostSiteFacts`],
//! [`HostGenerationFacts`]) as root, deriving every path from the site ID
//! and the compiled layout. The executor reads the account files, the local
//! file-context rules and the OLS include itself, and decides with the pure
//! [`judge_site`] and [`judge_generation`]. A fact that cannot be read is
//! never a match.

use std::{os::fd::OwnedFd, path::Path};

use rustix::fs::{self, AtFlags, FileType, Mode, OFlags};
use serde::{Deserialize, Serialize};

use rustiron_contracts::{Id, approval::Sha256Digest};

use crate::{
    ExecutorError, files,
    ols::{self, Generation, ServerChecks},
    provision::{self, SiteLayout, skeleton},
    quota::{self, QuotaHost, QuotaLimits},
};

/// Most entries one fact listing keeps; more is a mismatch, not truncation.
const MAX_ENTRIES: usize = 16;
/// Longest drop-in file the helper reports.
const MAX_DROPIN: usize = 4096;
/// The required KillMode drop-in (W245).
pub const OLS_DROPIN: &str = "/etc/systemd/system/lshttpd.service.d/50-rustiron-killmode.conf";
/// The additional drop-in required by the product profile (D-032).
pub const OLS_BOOT_GUARD_DROPIN: &str =
    "/etc/systemd/system/lshttpd.service.d/51-rustiron-boot-guard.conf";

/// The first rule a re-adoption failed; its name is journaled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rule {
    /// The account entry is absent, repeated or not the provisioned shape.
    Account,
    /// The UID is outside the enrolled UID range.
    UidRange,
    /// Another account or group holds the UID or GID.
    UidShared,
    /// The group entry is absent, repeated, has members or another GID.
    Group,
    /// The current journal already records the UID.
    UidRecorded,
    /// The site root is not the root-owned 0751 directory on the sites
    /// file system.
    SiteRoot,
    /// The top-level entries are not the provisioned skeleton.
    Skeleton,
    /// The local file-context rules are not exactly the two of the site.
    FileContexts,
    /// The category is outside the enrolled category range.
    CategoryRange,
    /// Another local rule or a journal record uses the category.
    CategoryShared,
    /// A live label is not the rule's type at the site level.
    Labels,
    /// The PHP drop-in, socket or timer differs from the PhpUnits step.
    PhpUnits,
    /// The schema, user, hosts or grants differ from the Database step.
    Database,
    /// The credentials file is not the site-owned 0600 single-link file.
    Credentials,
    /// The user quota is not enforced or differs from the signed limits.
    Quota,
    /// The site was ejected.
    Ejected,
    /// Generation form: no `current`.
    CurrentAbsent,
    /// Generation form: `current` names the bootstrap generation.
    Bootstrap,
    /// Generation form: the stored files do not hash to the id.
    ContentAddress,
    /// Generation form: `current` is not the planned generation.
    Expected,
    /// Generation form: the render from owned sites differs.
    Render,
    /// Generation form: a server check failed (`OLS_DRIFT`).
    ServerChecks,
    /// Generation form: the unit is not active, its `KillMode` is not the
    /// shipped one, or it carries another drop-in.
    Unit,
    /// Generation form: a listed site did not answer with its identity.
    Probes,
    /// The admin helper refused the observation or its reply was not the
    /// closed facts shape.
    Observation,
}

impl Rule {
    /// The journaled rule name, `[a-z_]+`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::UidRange => "uid_range",
            Self::UidShared => "uid_shared",
            Self::Group => "group",
            Self::UidRecorded => "uid_recorded",
            Self::SiteRoot => "site_root",
            Self::Skeleton => "skeleton",
            Self::FileContexts => "file_contexts",
            Self::CategoryRange => "category_range",
            Self::CategoryShared => "category_shared",
            Self::Labels => "labels",
            Self::PhpUnits => "php_units",
            Self::Database => "database",
            Self::Credentials => "credentials",
            Self::Quota => "quota",
            Self::Ejected => "ejected",
            Self::CurrentAbsent => "current_absent",
            Self::Bootstrap => "bootstrap",
            Self::ContentAddress => "content_address",
            Self::Expected => "expected",
            Self::Render => "render",
            Self::ServerChecks => "server_checks",
            Self::Unit => "unit",
            Self::Probes => "probes",
            Self::Observation => "observation",
        }
    }

    /// The stable refusal code: server checks are drift, the rest a mismatch.
    pub fn error(self) -> ExecutorError {
        match self {
            Self::ServerChecks => ExecutorError::Drift,
            _ => ExecutorError::ReadoptMismatch,
        }
    }
}

/// One directory entry as `fstatat(AT_SYMLINK_NOFOLLOW)` saw it.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeFact {
    /// `dir`, `file`, `link` or `other`.
    pub kind: String,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Permission bits (`0o7777`).
    pub mode: u32,
    /// Hard links.
    pub nlink: u64,
    /// On the same device as the sites root.
    pub same_device: bool,
}

/// One named entry and what it is.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NamedNode {
    /// Entry name.
    pub name: String,
    /// What it is.
    pub node: NodeFact,
}

/// One label read through a descriptor; `None` is unreadable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LabelFact {
    /// `root`, `html`, `tmp` or `logs`.
    pub entry: String,
    /// The full context.
    pub context: Option<String>,
}

/// The site facts only root can read, as the admin helper observed them.
/// No secret is read: not the credentials, not the database content.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostSiteFacts {
    /// `/srv/sites/rs_<site>` itself.
    pub root: Option<NodeFact>,
    /// Its top-level entries, sorted by name (at most 16; more is `None`).
    pub skeleton: Option<Vec<NamedNode>>,
    /// Labels of the root, `html`, `tmp` and `logs`.
    pub labels: Vec<LabelFact>,
    /// Entries of the PHP drop-in directory, sorted (`None`: unreadable).
    pub dropin_entries: Option<Vec<String>>,
    /// Text of `50-selinux.conf` (`None`: unreadable).
    pub dropin_text: Option<String>,
    /// `systemctl is-enabled` of the socket (`None`: not enabled).
    pub socket_enabled: Option<String>,
    /// `systemctl is-enabled` of the sandbox timer.
    pub timer_enabled: Option<String>,
    /// `systemctl is-active` of the socket.
    pub socket_active: Option<String>,
    /// The schema exists (`None`: MariaDB did not answer).
    pub schema: Option<bool>,
    /// Hosts of every `rs_<site>` user, sorted.
    pub user_hosts: Option<Vec<String>>,
    /// `user@host` of every schema-, table-, column- or routine-level
    /// privilege on the site schema, sorted.
    pub schema_grantees: Option<Vec<String>>,
    /// `SHOW GRANTS` of `rs_<site>@localhost`, sorted, with any password
    /// hash cut off.
    pub grants: Option<Vec<String>>,
    /// `private/db.cnf`, never opened.
    pub credentials: Option<NodeFact>,
    /// The sites file system enforces user quota.
    pub quota_enforced: bool,
    /// The UID the quota row was read for (from `/etc/passwd`).
    pub quota_uid: Option<u32>,
    /// That UID's hard and soft limits: block hard, inode hard, block soft,
    /// inode soft (`None`: no row or unreadable).
    pub quota: Option<[u64; 4]>,
    /// `/etc/rustiron-ejected/rs_<site>` exists.
    pub ejected: bool,
}

impl HostSiteFacts {
    /// One JSON line for the helper reply.
    pub fn encode(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Exactly this shape, or `None` (never a match).
    pub fn decode(payload: &str) -> Option<Self> {
        if payload.len() > 64 * 1024 {
            return None;
        }
        serde_json::from_str(payload).ok()
    }
}

/// Everything one site-form verification reads.
#[derive(Clone, Debug, Default)]
pub struct SiteInput {
    /// `/etc/passwd`.
    pub passwd: String,
    /// `/etc/group`.
    pub group: String,
    /// `file_contexts.local` (empty when absent).
    pub fcontexts: String,
    /// The helper's facts.
    pub host: HostSiteFacts,
}

/// The enrolled and signed values a site must meet.
pub struct SiteRules<'a> {
    /// Enrolled UID range.
    pub uid_range: (u32, u32),
    /// Enrolled category range.
    pub category_range: (u32, u32),
    /// The plan's signed limits (already at most the enrolled cap).
    pub quota: QuotaLimits,
    /// UIDs the current journal records (steps and adoptions).
    pub recorded_uids: &'a [u32],
    /// Categories the current journal records (steps and adoptions).
    pub recorded_categories: &'a [u32],
}

/// What a verified site holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SiteVerified {
    /// UID and GID.
    pub uid: u32,
    /// Category of the level `s0:cN`.
    pub category: u32,
}

fn node(kind: &str, uid: u32, gid: u32, mode: u32) -> impl Fn(&NodeFact) -> bool + '_ {
    move |fact| {
        fact.kind == kind
            && fact.uid == uid
            && fact.gid == gid
            && fact.mode == mode
            && fact.same_device
    }
}

fn fields(line: &str) -> Vec<&str> {
    line.split(':').collect()
}

fn named<'a>(text: &'a str, name: &str) -> Vec<&'a str> {
    text.lines()
        .filter(|line| line.split(':').next() == Some(name))
        .collect()
}

fn number(text: &str) -> Option<u32> {
    (!text.is_empty()
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text == "0" || !text.starts_with('0')))
    .then(|| text.parse().ok())
    .flatten()
}

/// The account rules: exactly one passwd entry of the provisioned shape and
/// one member-less group with the same id, which no other entry holds.
fn judge_account(
    layout: &SiteLayout,
    input: &SiteInput,
    rules: &SiteRules<'_>,
) -> Result<u32, Rule> {
    let account = layout.account.as_str();
    let home = layout.root.to_str().ok_or(Rule::Account)?;
    let [line] = named(&input.passwd, account)[..] else {
        return Err(Rule::Account);
    };
    let [_, _, uid, gid, _, dir, shell] = fields(line)[..] else {
        return Err(Rule::Account);
    };
    let (Some(uid), Some(gid)) = (number(uid), number(gid)) else {
        return Err(Rule::Account);
    };
    if uid != gid || dir != home || shell != "/sbin/nologin" {
        return Err(Rule::Account);
    }
    if !(rules.uid_range.0..=rules.uid_range.1).contains(&uid) {
        return Err(Rule::UidRange);
    }
    let holds = |text: &str| {
        text.lines().any(|other| {
            let parts = fields(other);
            parts.first() != Some(&account) && parts.get(2).and_then(|id| number(id)) == Some(uid)
        })
    };
    if holds(&input.passwd) || holds(&input.group) {
        return Err(Rule::UidShared);
    }
    let [group] = named(&input.group, account)[..] else {
        return Err(Rule::Group);
    };
    match fields(group)[..] {
        [_, _, id, ""] if number(id) == Some(uid) => {}
        _ => return Err(Rule::Group),
    }
    if rules.recorded_uids.contains(&uid) {
        return Err(Rule::UidRecorded);
    }
    Ok(uid)
}

/// Every category a local rule line names (`...:cN`), as category
/// allocation reads them.
fn categories(line: &str) -> Vec<u32> {
    line.split(|c: char| !(c.is_ascii_alphanumeric() || c == ':'))
        .filter_map(|word| word.rsplit_once(":c")?.1.parse().ok())
        .collect()
}

/// The file-context rules: exactly the Labels step's two rules for this
/// root, at one level `s0:cN`; no other rule or record uses N.
fn judge_fcontexts(
    layout: &SiteLayout,
    input: &SiteInput,
    rules: &SiteRules<'_>,
) -> Result<u32, Rule> {
    let root = layout.root.to_str().ok_or(Rule::FileContexts)?;
    let content = format!("{root}(/.*)?");
    let writable = format!("{root}/(tmp|logs)(/.*)?");
    let mine = |line: &str| {
        line.split_whitespace().next().is_some_and(|pattern| {
            pattern.starts_with(&format!("{root}(")) || pattern.starts_with(&format!("{root}/"))
        })
    };
    let lines: Vec<&str> = input
        .fcontexts
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    let own: Vec<Vec<&str>> = lines
        .iter()
        .filter(|line| mine(line))
        .map(|line| line.split_whitespace().collect())
        .collect();
    let level_of = |context: &str, kind: &str| {
        context
            .strip_prefix(&format!("system_u:object_r:{kind}:s0:c"))
            .and_then(number)
    };
    let category = match &own[..] {
        [first, second] => match (&first[..], &second[..]) {
            ([p1, c1], [p2, c2]) if *p1 == content && *p2 == writable => (
                level_of(c1, skeleton::CONTENT),
                level_of(c2, skeleton::READ_WRITE),
            ),
            ([p1, c1], [p2, c2]) if *p2 == content && *p1 == writable => (
                level_of(c2, skeleton::CONTENT),
                level_of(c1, skeleton::READ_WRITE),
            ),
            _ => (None, None),
        },
        _ => (None, None),
    };
    let category = match category {
        (Some(a), Some(b)) if a == b => a,
        _ => return Err(Rule::FileContexts),
    };
    if !(rules.category_range.0..=rules.category_range.1).contains(&category) {
        return Err(Rule::CategoryRange);
    }
    let shared = lines
        .iter()
        .filter(|line| !mine(line))
        .any(|line| categories(line).contains(&category));
    if shared || rules.recorded_categories.contains(&category) {
        return Err(Rule::CategoryShared);
    }
    Ok(category)
}

/// The exact PHP drop-in the PhpUnits step writes for `level`.
pub fn dropin_text(level: &str) -> String {
    format!(
        "[Service]\nSELinuxContext=system_u:system_r:rustiron_php_t:{level}\nEnvironment=RUSTIRON_SITE_LEVEL={level}\n"
    )
}

/// The exact grants the Database step creates for `account`.
pub fn expected_grants(account: &str) -> Vec<String> {
    let mut grants = vec![
        format!("GRANT ALL PRIVILEGES ON `{account}`.* TO `{account}`@`localhost`"),
        format!("GRANT USAGE ON *.* TO `{account}`@`localhost`"),
    ];
    grants.sort();
    grants
}

/// Judges every site-form rule in the design's order. Pure: the caller
/// supplies everything read.
pub fn judge_site(
    layout: &SiteLayout,
    input: &SiteInput,
    rules: &SiteRules<'_>,
) -> Result<SiteVerified, Rule> {
    let uid = judge_account(layout, input, rules)?;
    let host = &input.host;
    if !host.root.as_ref().is_some_and(node("dir", 0, 0, 0o751)) {
        return Err(Rule::SiteRoot);
    }
    let ols_gid = provision::group_id(&input.group, provision::OLS_GROUP).ok_or(Rule::Skeleton)?;
    let skeleton_ok = host.skeleton.as_ref().is_some_and(|entries| {
        let expected: [(&str, u32, u32, u32); 5] = [
            ("errors", 0, 0, 0o755),
            ("html", uid, ols_gid, 0o750),
            ("logs", uid, uid, 0o750),
            ("private", uid, uid, 0o750),
            ("tmp", uid, uid, 0o750),
        ];
        entries.len() == expected.len()
            && entries
                .iter()
                .zip(expected)
                .all(|(entry, (name, u, g, m))| {
                    entry.name == name && node("dir", u, g, m)(&entry.node)
                })
    });
    if !skeleton_ok {
        return Err(Rule::Skeleton);
    }
    let category = judge_fcontexts(layout, input, rules)?;
    let level = format!("s0:c{category}");
    let want = [
        ("root", skeleton::CONTENT),
        ("html", skeleton::CONTENT),
        ("tmp", skeleton::READ_WRITE),
        ("logs", skeleton::READ_WRITE),
    ];
    let labels_ok = host.labels.len() == want.len()
        && host.labels.iter().zip(want).all(|(fact, (entry, kind))| {
            fact.entry == entry
                && fact.context.as_deref() == Some(skeleton::context(kind, &level).as_str())
        });
    if !labels_ok {
        return Err(Rule::Labels);
    }
    let units_ok = host.dropin_entries.as_deref() == Some(&["50-selinux.conf".to_owned()][..])
        && host.dropin_text.as_deref() == Some(dropin_text(&level).as_str())
        && host.socket_enabled.as_deref() == Some("enabled")
        && host.timer_enabled.as_deref() == Some("enabled")
        && host.socket_active.as_deref() == Some("active");
    if !units_ok {
        return Err(Rule::PhpUnits);
    }
    let account = layout.account.as_str();
    let database_ok = host.schema == Some(true)
        && host.user_hosts.as_deref() == Some(&["localhost".to_owned()][..])
        && host.schema_grantees.as_deref() == Some(&[format!("{account}@localhost")][..])
        && host.grants.as_deref() == Some(&expected_grants(account)[..]);
    if !database_ok {
        return Err(Rule::Database);
    }
    if !host
        .credentials
        .as_ref()
        .is_some_and(|fact| node("file", uid, uid, 0o600)(fact) && fact.nlink == 1)
    {
        return Err(Rule::Credentials);
    }
    let limits = rules.quota;
    if !host.quota_enforced
        || host.quota_uid != Some(uid)
        || host.quota != Some([limits.block_hard_kib, limits.inode_hard, 0, 0])
    {
        return Err(Rule::Quota);
    }
    if host.ejected {
        return Err(Rule::Ejected);
    }
    Ok(SiteVerified { uid, category })
}

/// A compact, secret-free summary of a site observation for the journal
/// (at most 4096 bytes): what was found, not the raw files.
pub fn site_summary(
    layout: &SiteLayout,
    input: &SiteInput,
    verdict: &Result<SiteVerified, Rule>,
) -> String {
    let host = &input.host;
    let account = named(&input.passwd, &layout.account).len();
    let value = serde_json::json!({
        "account_entries": account,
        "uid": verdict.as_ref().ok().map(|v| v.uid),
        "level": verdict.as_ref().ok().map(|v| format!("s0:c{}", v.category)),
        "root": host.root,
        "skeleton": host.skeleton.as_ref().map(|entries| entries.iter().map(|e| e.name.as_str()).collect::<Vec<_>>()),
        "dropin_entries": host.dropin_entries,
        "socket": [host.socket_enabled.as_deref(), host.socket_active.as_deref()],
        "timer": host.timer_enabled.as_deref(),
        "schema": host.schema,
        "user_hosts": host.user_hosts,
        "schema_grantees": host.schema_grantees,
        "grants": host.grants.as_ref().map(Vec::len),
        "credentials": host.credentials,
        "quota_enforced": host.quota_enforced,
        "quota": host.quota,
        "ejected": host.ejected,
        "rule": verdict.as_ref().err().map(|rule| rule.name()),
    });
    bounded(value)
}

fn bounded(value: serde_json::Value) -> String {
    let text = serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_owned());
    if text.len() <= 4096 && text.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        text
    } else {
        "{\"truncated\":true}".to_owned()
    }
}

fn kind(stat: &rustix::fs::Stat) -> &'static str {
    match FileType::from_raw_mode(stat.st_mode) {
        FileType::Directory => "dir",
        FileType::RegularFile => "file",
        FileType::Symlink => "link",
        _ => "other",
    }
}

fn node_fact(stat: &rustix::fs::Stat, device: u64) -> NodeFact {
    NodeFact {
        kind: kind(stat).to_owned(),
        uid: stat.st_uid,
        gid: stat.st_gid,
        mode: stat.st_mode & 0o7777,
        nlink: stat.st_nlink,
        same_device: stat.st_dev == device,
    }
}

fn stat_child(parent: &OwnedFd, name: &str, device: u64) -> Option<NodeFact> {
    fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .ok()
        .map(|stat| node_fact(&stat, device))
}

fn open_dir(parent: &OwnedFd, name: &str) -> Option<OwnedFd> {
    fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .ok()
}

fn entries(dir: &OwnedFd) -> Option<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::Dir::read_from(dir).ok()? {
        let name = entry.ok()?.file_name().to_str().ok()?.to_owned();
        if name != "." && name != ".." {
            names.push(name);
        }
        if names.len() > MAX_ENTRIES {
            return None;
        }
    }
    names.sort();
    Some(names)
}

fn unit_query(verb: &str, unit: &str) -> Option<String> {
    provision::output("/usr/bin/systemctl", &[verb, "--", unit])
        .ok()
        .map(|text| text.trim().to_owned())
}

/// Lines a query printed, or `None` when MariaDB did not answer.
fn mariadb_lines(sql: &str) -> Option<Vec<String>> {
    provision::spawn(
        provision::MARIADB,
        &[
            "--batch",
            "--skip-column-names",
            "--socket",
            provision::DB_SOCKET,
        ],
        true,
        Some(sql.as_bytes()),
    )
    .ok()
    .map(|text| text.lines().map(str::to_owned).collect())
}

/// A `SHOW GRANTS` line without the password hash MariaDB prints.
pub fn without_password(line: &str) -> String {
    match line.find(" IDENTIFIED BY ") {
        Some(at) => line[..at].to_owned(),
        None => line.to_owned(),
    }
}

/// Reads the database facts for `account`. The account name comes from the
/// site ID grammar, so it is a safe SQL literal and identifier.
fn database_facts(account: &str, facts: &mut HostSiteFacts) {
    let Some(lines) = mariadb_lines(&format!(
        "SELECT CONCAT('schema ', COUNT(*)) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='{account}';\n\
         SELECT CONCAT('host ', Host) FROM mysql.user WHERE User='{account}';\n\
         SELECT CONCAT('grantee ', User, '@', Host) FROM mysql.db WHERE Db='{account}' OR Db='{escaped}' \
         UNION ALL SELECT CONCAT('grantee ', User, '@', Host) FROM mysql.tables_priv WHERE Db='{account}' OR Db='{escaped}' \
         UNION ALL SELECT CONCAT('grantee ', User, '@', Host) FROM mysql.columns_priv WHERE Db='{account}' OR Db='{escaped}' \
         UNION ALL SELECT CONCAT('grantee ', User, '@', Host) FROM mysql.procs_priv WHERE Db='{account}' OR Db='{escaped}';\n",
        escaped = account.replace('_', "\\\\_"),
    )) else {
        return;
    };
    let tagged = |tag: &str| {
        let mut values: Vec<String> = lines
            .iter()
            .filter_map(|line| line.strip_prefix(tag).map(str::to_owned))
            .collect();
        values.sort();
        values
    };
    facts.schema = match tagged("schema ")[..] {
        [ref count] => Some(count == "1"),
        _ => None,
    };
    facts.user_hosts = Some(tagged("host "));
    facts.schema_grantees = Some(tagged("grantee "));
    if facts.user_hosts.as_deref() == Some(&["localhost".to_owned()][..]) {
        facts.grants =
            mariadb_lines(&format!("SHOW GRANTS FOR '{account}'@'localhost';\n")).map(|lines| {
                let mut grants: Vec<String> = lines.iter().map(|l| without_password(l)).collect();
                grants.sort();
                grants
            });
    }
}

/// Reads every [`HostSiteFacts`] for `layout` as root (admin helper, or the
/// executor in the D-016 lab mode). Read-only; nothing is created, changed
/// or opened for writing.
pub fn observe_host_site(layout: &SiteLayout) -> HostSiteFacts {
    let mut facts = HostSiteFacts {
        ejected: std::fs::symlink_metadata(
            Path::new(crate::layout::OLS_EJECTED_DIR).join(&layout.account),
        )
        .is_ok(),
        ..HostSiteFacts::default()
    };
    if let Ok(sites) = files::open_traversable_directory(Path::new(crate::layout::SITES_ROOT), 0) {
        let device = fs::fstat(&sites).map_or(u64::MAX, |stat| stat.st_dev);
        facts.root = stat_child(&sites, &layout.account, device);
        let root = facts
            .root
            .as_ref()
            .filter(|root| root.kind == "dir")
            .and_then(|_| open_dir(&sites, &layout.account));
        if let Some(root) = root {
            facts.skeleton = entries(&root).and_then(|names| {
                names
                    .into_iter()
                    .map(|name| {
                        stat_child(&root, &name, device).map(|node| NamedNode { name, node })
                    })
                    .collect()
            });
            let label = |fd: Option<OwnedFd>| {
                fd.and_then(|fd| skeleton::get_label(&fd))
                    .and_then(|bytes| String::from_utf8(bytes).ok())
            };
            facts.labels = vec![
                LabelFact {
                    entry: "root".to_owned(),
                    context: skeleton::get_label(&root).and_then(|b| String::from_utf8(b).ok()),
                },
                LabelFact {
                    entry: "html".to_owned(),
                    context: label(open_dir(&root, "html")),
                },
                LabelFact {
                    entry: "tmp".to_owned(),
                    context: label(open_dir(&root, "tmp")),
                },
                LabelFact {
                    entry: "logs".to_owned(),
                    context: label(open_dir(&root, "logs")),
                },
            ];
            facts.credentials = open_dir(&root, "private")
                .and_then(|private| stat_child(&private, "db.cnf", device));
        }
    }
    let dropin = format!("rustiron-site-php@{}.service.d", layout.account);
    if let Some(dir) = files::open_traversable_directory(Path::new("/etc/systemd/system"), 0)
        .ok()
        .and_then(|units| open_dir(&units, &dropin))
    {
        facts.dropin_entries = entries(&dir);
        facts.dropin_text = files::read_child(
            &dir,
            "50-selinux.conf",
            0,
            files::Exposure::Readable,
            MAX_DROPIN,
        )
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok());
    }
    let socket = format!("rustiron-site-php@{}.socket", layout.account);
    let timer = format!("rustiron-site-sandbox-check@{}.timer", layout.account);
    facts.socket_enabled = unit_query("is-enabled", &socket);
    facts.timer_enabled = unit_query("is-enabled", &timer);
    facts.socket_active = unit_query("is-active", &socket);
    database_facts(&layout.account, &mut facts);
    let mut host = quota::SystemQuota;
    if let Ok(mount) = quota::readiness(&mut host) {
        facts.quota_enforced = true;
        facts.quota_uid = host
            .passwd()
            .ok()
            .and_then(|passwd| provision::account_uid(&passwd, &layout.account));
        facts.quota = facts.quota_uid.and_then(|uid| {
            let text = host.report(&mount.mount_point).ok()?;
            let row = quota::report_row(&text, uid).ok()??;
            Some([
                row.block_hard_kib,
                row.inode_hard,
                row.block_soft_kib,
                row.inode_soft,
            ])
        });
    }
    facts
}

/// The executor's own reads for the site form: the account files and the
/// local file-context rules (an absent file is no rules).
pub fn read_site_inputs() -> Result<(String, String, String), ExecutorError> {
    let fcontexts = match std::fs::read_to_string(provision::LOCAL_FCONTEXTS) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(_) => return Err(ExecutorError::Unavailable),
    };
    Ok((
        provision::read_etc("passwd")?,
        provision::read_etc("group")?,
        fcontexts,
    ))
}

/// W372 precondition of `site_provision` (the W369 quarantine finding): an
/// account or group of the derived name, or an existing site root, is a
/// collision before intent. Pure; the caller reads the files.
pub fn provision_collision(
    passwd: &str,
    group: &str,
    account: &str,
    root_present: bool,
) -> Result<(), ExecutorError> {
    if provision::name_taken(passwd, group, account) || root_present {
        return Err(ExecutorError::Collision);
    }
    Ok(())
}

/// W372 precondition of `site_provision`: whether the derived site root
/// exists. Read-only, as root; any answer but "absent" counts as present.
pub fn site_root_present(layout: &SiteLayout) -> bool {
    match std::fs::symlink_metadata(&layout.root) {
        Err(error) => error.kind() != std::io::ErrorKind::NotFound,
        Ok(_) => true,
    }
}

/// The generation facts only root can read, as the admin helper observed
/// them for the live generation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostGenerationFacts {
    /// The server checks (parent, WebAdmin and listener, adopted vhosts,
    /// PHP capacity).
    pub server: ServerChecks,
    /// `ActiveState` of `lshttpd.service`.
    pub unit_state: Option<String>,
    /// `KillMode` of `lshttpd.service`.
    pub kill_mode: Option<String>,
    /// `DropInPaths` of `lshttpd.service`.
    pub dropins: Option<Vec<String>>,
    /// Every listed site answered with its identity through the listener.
    pub probes: bool,
}

impl HostGenerationFacts {
    /// One JSON line for the helper reply.
    pub fn encode(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Exactly this shape, or `None` (never a match).
    pub fn decode(payload: &str) -> Option<Self> {
        if payload.len() > 16 * 1024 {
            return None;
        }
        serde_json::from_str(payload).ok()
    }
}

/// Reads [`HostGenerationFacts`] as root. Read-only: the identity probes
/// are plain HTTP requests through the enrolled listener.
pub(crate) fn observe_host_generation(
    policy: &crate::policy::OlsPolicy,
    sites: &[ols::ServedSite],
) -> Result<HostGenerationFacts, ExecutorError> {
    Ok(HostGenerationFacts {
        server: crate::admin_helper::server_checks(policy)?,
        unit_state: ols::unit_state(),
        kill_mode: ols::kill_mode(),
        dropins: provision::output(
            "/usr/bin/systemctl",
            &["show", "--property=DropInPaths", "--value", ols::OLS_UNIT],
        )
        .ok()
        .map(|text| text.split_whitespace().map(str::to_owned).collect()),
        probes: crate::durable::probe_with_retry(policy, sites).is_ok(),
    })
}

/// Requires the exact Rustiron drop-in paths for the build profile.
/// The only optional drop-ins are generic vendor service drop-ins.
pub fn dropins_only_rustiron(dropins: &[String]) -> bool {
    let required: &[&str] = if cfg!(rustiron_profile = "product") {
        &[OLS_DROPIN, OLS_BOOT_GUARD_DROPIN]
    } else {
        &[OLS_DROPIN]
    };
    required
        .iter()
        .all(|required_path| dropins.iter().any(|path| path.as_str() == *required_path))
        && dropins.iter().all(|path| {
            required.contains(&path.as_str())
                || path.starts_with("/usr/lib/systemd/system/service.d/")
        })
}

/// Everything one generation-form verification reads.
#[derive(Clone, Debug, Default)]
pub struct GenerationInput {
    /// `current` and its digest (`None`: absent).
    pub current: Option<(Id, Sha256Digest)>,
    /// The stored files of `current`, without the copies OLS writes.
    pub stored: Option<Generation>,
    /// The helper's facts.
    pub host: Option<HostGenerationFacts>,
}

/// Judges every generation-form rule. `rendered` is the executor's render
/// from the enrolled policy and the listed owned sites.
pub fn judge_generation(
    input: &GenerationInput,
    expected: (&Id, &Sha256Digest),
    rendered: &Generation,
) -> Result<(), Rule> {
    let Some((id, digest)) = &input.current else {
        return Err(Rule::CurrentAbsent);
    };
    if ols::is_bootstrap_predecessor(id, digest) {
        return Err(Rule::Bootstrap);
    }
    if &ols::generation_id(digest) != id
        || input.stored.as_ref().map(ols::digest).as_ref() != Some(digest)
    {
        return Err(Rule::ContentAddress);
    }
    if (id, digest) != expected {
        return Err(Rule::Expected);
    }
    if input.stored.as_ref() != Some(rendered) {
        return Err(Rule::Render);
    }
    let host = input.host.as_ref().ok_or(Rule::Observation)?;
    let server = host.server;
    if !(server.parent_reviewed
        && server.webadmin_closed
        && server.adopted_vhosts_pinned
        && server.php_capacity)
    {
        return Err(Rule::ServerChecks);
    }
    if host.unit_state.as_deref() != Some("active")
        || !ols::kill_mode_shipped(host.kill_mode.as_deref())
        || !host.dropins.as_deref().is_some_and(dropins_only_rustiron)
    {
        return Err(Rule::Unit);
    }
    if !host.probes {
        return Err(Rule::Probes);
    }
    Ok(())
}

/// A compact summary of a generation observation for the journal.
pub fn generation_summary(
    input: &GenerationInput,
    rendered: &Generation,
    verdict: &Result<(), Rule>,
) -> String {
    let rendered_digest = ols::digest(rendered);
    bounded(serde_json::json!({
        "current": input.current.as_ref().map(|(id, _)| id.as_str()),
        "digest": input.current.as_ref().map(|(_, digest)| digest.as_str()),
        "stored_files": input.stored.as_ref().map(std::collections::BTreeMap::len),
        "rendered": ols::generation_id(&rendered_digest).as_str(),
        "rendered_digest": rendered_digest.as_str(),
        "server": input.host.as_ref().map(|host| host.server),
        "unit_state": input.host.as_ref().and_then(|host| host.unit_state.as_deref()),
        "kill_mode": input.host.as_ref().and_then(|host| host.kill_mode.as_deref()),
        "dropins": input.host.as_ref().and_then(|host| host.dropins.as_ref()),
        "probes": input.host.as_ref().map(|host| host.probes),
        "rule": verdict.as_ref().err().map(|rule| rule.name()),
    }))
}

#[cfg(test)]
#[path = "readopt_tests.rs"]
mod tests;
