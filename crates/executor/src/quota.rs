//! W335 (D-028 item 3, B07): per-site user quota on the site's own uid.
//!
//! The limits come from the signed site plan (schema v2, W341), bound at
//! admission to at most the enrolled `provisioning.quota`, or from that
//! enrolled policy for a schema v1 plan. The executor journals the limits and
//! their source in the Directories step's intent before any effect. The uid comes from the
//! journaled Account step and must match the live account. The mount comes
//! from `/proc/self/mountinfo` for the fixed sites root. The fixed quota tools
//! get only these derived values as argv; nothing comes from a request.
//!
//! Every effect is read back. An unreadable, unknown or different read-back
//! is a failed step, never a success.

use rustiron_contracts::approval::SiteQuotaLimits;
use rustiron_journal::{Provision, ProvisionState, ProvisionStep};
use serde::Deserialize;

use crate::{ExecutorError, provision};

/// Fixed quota tools (AlmaLinux 10 `quota` package paths).
pub const SETQUOTA: &str = "/usr/sbin/setquota";
/// Read-back of limits and usage for one filesystem.
pub const REPQUOTA: &str = "/usr/sbin/repquota";
/// Kernel quota state (`-p` prints and never changes it).
pub const QUOTAON: &str = "/usr/sbin/quotaon";
/// The executor's own mount table view.
pub const MOUNTINFO: &str = "/proc/self/mountinfo";

// One set of bounds for enrolled and signed limits (the contract owns them).
const MIN_BLOCK_KIB: u64 = SiteQuotaLimits::MIN_BLOCK_HARD_KIB;
const MAX_BLOCK_KIB: u64 = SiteQuotaLimits::MAX_BLOCK_HARD_KIB;
const MIN_INODES: u64 = SiteQuotaLimits::MIN_INODE_HARD;
const MAX_INODES: u64 = SiteQuotaLimits::MAX_INODE_HARD;

/// Hard limits for one site. Soft limits are always 0 (no grace period).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QuotaLimits {
    /// Hard block limit in KiB (quota tools' default unit).
    pub block_hard_kib: u64,
    /// Hard inode limit.
    pub inode_hard: u64,
}

impl QuotaLimits {
    /// D-028 defaults: 5 GiB and 500,000 inodes.
    pub const DEFAULT: Self = Self {
        block_hard_kib: 5 * 1024 * 1024,
        inode_hard: 500_000,
    };

    /// Limits must be inside fixed bounds (64 MiB to 16 TiB; 1,000 to 100 million inodes).
    pub fn valid(&self) -> bool {
        (MIN_BLOCK_KIB..=MAX_BLOCK_KIB).contains(&self.block_hard_kib)
            && (MIN_INODES..=MAX_INODES).contains(&self.inode_hard)
    }

    /// These enrolled limits as the binding ceiling for signed v2 limits;
    /// `None` when outside the fixed bounds.
    pub fn cap(&self) -> Option<SiteQuotaLimits> {
        SiteQuotaLimits::new(self.block_hard_kib, self.inode_hard).ok()
    }

    /// Both limits are at most the cap's limits.
    pub fn within(&self, cap: Self) -> bool {
        self.block_hard_kib <= cap.block_hard_kib && self.inode_hard <= cap.inode_hard
    }
}

impl From<SiteQuotaLimits> for QuotaLimits {
    fn from(signed: SiteQuotaLimits) -> Self {
        Self {
            block_hard_kib: signed.block_hard_kib(),
            inode_hard: signed.inode_hard(),
        }
    }
}

/// What the Directories step does about the quota; journaled before effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotaPlan {
    /// Set and read back these limits for the site uid.
    Enforced(QuotaLimits),
    /// The policy enrolls no quota (lab only): recorded, no quota effect.
    NotEnforced,
}

impl QuotaPlan {
    /// The plan for the enrolled provisioning policy.
    pub fn from_policy(limits: Option<QuotaLimits>) -> Self {
        limits.map_or(Self::NotEnforced, Self::Enforced)
    }
}

/// Where the journaled quota plan came from (W341).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotaSource {
    /// The enrolled `provisioning.quota` (site plan v1; every W335 record).
    Policy,
    /// The signed `quota_limits` of a site plan v2, at most the enrolled cap.
    Plan,
}

impl QuotaSource {
    fn token(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Plan => "plan",
        }
    }
}

/// The quota plan and its source, journaled in the Directories intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotaIntent {
    /// What the Directories step does about the quota.
    pub plan: QuotaPlan,
    /// Where the limits came from.
    pub source: QuotaSource,
}

impl QuotaIntent {
    /// Signed v2 limits when the plan has them; otherwise the enrolled
    /// policy plan. Admission has already refused signed limits above the
    /// enrolled cap or without an enrolled quota.
    pub fn select(signed: Option<QuotaLimits>, enrolled: Option<QuotaLimits>) -> Self {
        match signed {
            Some(limits) => Self {
                plan: QuotaPlan::Enforced(limits),
                source: QuotaSource::Plan,
            },
            None => Self {
                plan: QuotaPlan::from_policy(enrolled),
                source: QuotaSource::Policy,
            },
        }
    }

    /// The admin helper's check against the policy enrolled now: policy
    /// limits must equal it exactly; signed limits must be enforced and at
    /// most the enrolled cap.
    pub fn permitted_by(self, enrolled: Option<QuotaLimits>) -> bool {
        match (self.source, self.plan) {
            (QuotaSource::Policy, plan) => plan == QuotaPlan::from_policy(enrolled),
            (QuotaSource::Plan, QuotaPlan::Enforced(limits)) => {
                enrolled.is_some_and(|cap| limits.within(cap))
            }
            (QuotaSource::Plan, QuotaPlan::NotEnforced) => false,
        }
    }

    /// Journal text, appended to the Directories step resource.
    pub fn resource(self) -> String {
        let source = self.source.token();
        match self.plan {
            QuotaPlan::Enforced(limits) => format!(
                "quota=enforced source={source} kib={} inodes={}",
                limits.block_hard_kib, limits.inode_hard
            ),
            QuotaPlan::NotEnforced => format!("quota=not_enforced source={source}"),
        }
    }
}

/// The quota recorded in a Directories step resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordedQuota {
    /// No `quota=` token: the step was recorded before W335.
    Absent,
    /// A well-formed recorded plan and its source.
    Plan(QuotaIntent),
    /// A `quota=` token that does not parse exactly; never acted on.
    Malformed,
}

impl RecordedQuota {
    /// Parses the tokens [`QuotaIntent::resource`] writes; anything else is
    /// malformed. A record without `source=` is a W335 record, whose limits
    /// came from policy.
    pub fn parse(resource: &str) -> Self {
        let value = |key: &str| -> Vec<&str> {
            resource
                .split(' ')
                .filter_map(|token| token.strip_prefix(key))
                .collect()
        };
        let number = |key: &str| match value(key)[..] {
            [digits] if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) => {
                digits.parse::<u64>().ok()
            }
            _ => None,
        };
        let source = match value("source=")[..] {
            [] | ["policy"] => QuotaSource::Policy,
            ["plan"] => QuotaSource::Plan,
            _ => return Self::Malformed,
        };
        let plan = match value("quota=")[..] {
            [] if value("source=").is_empty() => return Self::Absent,
            ["not_enforced"]
                if source == QuotaSource::Policy
                    && value("kib=").is_empty()
                    && value("inodes=").is_empty() =>
            {
                QuotaPlan::NotEnforced
            }
            ["enforced"] => match (number("kib="), number("inodes=")) {
                (Some(block_hard_kib), Some(inode_hard)) => {
                    let limits = QuotaLimits {
                        block_hard_kib,
                        inode_hard,
                    };
                    if !limits.valid() {
                        return Self::Malformed;
                    }
                    QuotaPlan::Enforced(limits)
                }
                _ => return Self::Malformed,
            },
            _ => return Self::Malformed,
        };
        Self::Plan(QuotaIntent { plan, source })
    }
}

/// Why a host cannot enforce per-site quotas; each has a stable code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// The mount table is unreadable, malformed or has no mount for the sites root.
    MountUnknown,
    /// More than one mount sits at the sites root's mount point.
    MountAmbiguous,
    /// The sites root is on a bind mount of a subtree.
    BindMount,
    /// Another filesystem is mounted below the sites root.
    NestedMount,
    /// The filesystem is not ext4 or XFS.
    UnsupportedFilesystem,
    /// No `usrquota` (ext4) or `usrquota`/`uquota` (XFS) option.
    UserQuotaMissing,
    /// XFS accounts user usage without enforcing limits (`uqnoenforce`).
    NotEnforced,
    /// The kernel quota state does not read as user quota on and enforced.
    StateUnknown,
}

impl Refusal {
    /// Stable refusal code for reports and logs.
    pub fn code(self) -> &'static str {
        match self {
            Self::MountUnknown => "quota_mount_unknown",
            Self::MountAmbiguous => "quota_mount_ambiguous",
            Self::BindMount => "quota_bind_mount",
            Self::NestedMount => "quota_nested_mount",
            Self::UnsupportedFilesystem => "quota_filesystem_unsupported",
            Self::UserQuotaMissing => "quota_usrquota_missing",
            Self::NotEnforced => "quota_not_enforced",
            Self::StateUnknown => "quota_state_unknown",
        }
    }
}

/// Filesystems with user quota support through the quota tools.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Filesystem {
    /// ext4 with the `usrquota` option.
    Ext4,
    /// XFS with user quota accounting and enforcement.
    Xfs,
}

/// The single mount that holds the sites root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SitesMount {
    /// Mount point, unescaped (the quota tools' filesystem argument).
    pub mount_point: String,
    /// Filesystem type.
    pub filesystem: Filesystem,
}

struct MountEntry {
    root: String,
    mount_point: String,
    fs_type: String,
    super_options: String,
}

/// Decodes the octal escapes the kernel writes for space, tab, newline and backslash.
fn unescape(field: &str) -> Option<String> {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            let digits = bytes.get(index + 1..index + 4)?;
            if !digits.iter().all(|d| (b'0'..=b'7').contains(d)) {
                return None;
            }
            let value = digits
                .iter()
                .fold(0_u32, |acc, d| acc * 8 + u32::from(d - b'0'));
            out.push(u8::try_from(value).ok()?);
            index += 4;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// One `/proc/<pid>/mountinfo` line (proc(5)): fields 4 and 5 are the root
/// and mount point; after the `-` separator come type, source and super options.
fn parse_entry(line: &str) -> Option<MountEntry> {
    let fields: Vec<&str> = line.split(' ').collect();
    let separator = fields.iter().position(|field| *field == "-")?;
    if separator < 6 || fields.len() != separator + 4 {
        return None;
    }
    Some(MountEntry {
        root: unescape(fields[3])?,
        mount_point: unescape(fields[4])?,
        fs_type: fields[separator + 1].to_owned(),
        super_options: fields[separator + 3].to_owned(),
    })
}

/// `path` equals `base` or lies below it, compared by whole components.
fn within(path: &str, base: &str) -> bool {
    base == "/" || path == base || path.strip_prefix(base).is_some_and(|r| r.starts_with('/'))
}

/// The mount holding `sites_root`, with a usable user quota option.
/// Refuses anything ambiguous instead of guessing.
pub fn sites_mount(mountinfo: &str, sites_root: &str) -> Result<SitesMount, Refusal> {
    let entries = mountinfo
        .lines()
        .filter(|line| !line.is_empty())
        .map(parse_entry)
        .collect::<Option<Vec<_>>>()
        .ok_or(Refusal::MountUnknown)?;
    if entries
        .iter()
        .any(|e| e.mount_point != sites_root && within(&e.mount_point, sites_root))
    {
        return Err(Refusal::NestedMount);
    }
    let holder = entries
        .iter()
        .filter(|e| within(sites_root, &e.mount_point))
        .max_by_key(|e| e.mount_point.len())
        .ok_or(Refusal::MountUnknown)?;
    if entries
        .iter()
        .filter(|e| e.mount_point == holder.mount_point)
        .count()
        != 1
    {
        return Err(Refusal::MountAmbiguous);
    }
    if holder.root != "/" {
        return Err(Refusal::BindMount);
    }
    let options: Vec<&str> = holder.super_options.split(',').collect();
    let has = |name: &str| options.contains(&name);
    let filesystem = match holder.fs_type.as_str() {
        "ext4" if has("usrquota") => Filesystem::Ext4,
        "ext4" => return Err(Refusal::UserQuotaMissing),
        "xfs" if has("usrquota") || has("uquota") => Filesystem::Xfs,
        "xfs" if has("uqnoenforce") || has("qnoenforce") => return Err(Refusal::NotEnforced),
        "xfs" => return Err(Refusal::UserQuotaMissing),
        _ => return Err(Refusal::UnsupportedFilesystem),
    };
    Ok(SitesMount {
        mount_point: holder.mount_point.clone(),
        filesystem,
    })
}

/// `quotaon -p -u -v` must print exactly one line saying user quota on this
/// mount is on and enforced. Plain "is on" (no enforcement detail) is refused.
pub fn enforced(state: &str, mount_point: &str) -> bool {
    let lines: Vec<&str> = state.lines().filter(|line| !line.is_empty()).collect();
    let prefix = format!("user quota on {mount_point} (");
    matches!(lines[..], [line] if line.starts_with(&prefix) && line.ends_with(") is on (enforced)"))
}

/// `setquota` argv for one uid: soft limits 0, the given hard limits, or all
/// zero to clear. The name is the numeric uid, which setquota treats as an id.
pub fn set_args(uid: u32, limits: Option<QuotaLimits>, mount_point: &str) -> Vec<String> {
    let (blocks, inodes) = limits.map_or((0, 0), |l| (l.block_hard_kib, l.inode_hard));
    [
        "-u".to_owned(),
        "--".to_owned(),
        uid.to_string(),
        "0".to_owned(),
        blocks.to_string(),
        "0".to_owned(),
        inodes.to_string(),
        mount_point.to_owned(),
    ]
    .to_vec()
}

/// `repquota` argv: user quotas, numeric ids, raw grace, every entry, CSV.
pub fn report_args(mount_point: &str) -> Vec<String> {
    ["-u", "-n", "-p", "-v", "--output=csv", "--", mount_point]
        .map(str::to_owned)
        .to_vec()
}

/// `quotaon` argv that only prints the user quota state of one mount.
pub fn state_args(mount_point: &str) -> Vec<String> {
    ["-p", "-u", "-v", "--", mount_point]
        .map(str::to_owned)
        .to_vec()
}

/// One uid's limits and usage, in KiB and inodes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct QuotaRow {
    /// Used space in KiB.
    pub block_used_kib: u64,
    /// Soft space limit in KiB.
    pub block_soft_kib: u64,
    /// Hard space limit in KiB.
    pub block_hard_kib: u64,
    /// Used inodes.
    pub inode_used: u64,
    /// Soft inode limit.
    pub inode_soft: u64,
    /// Hard inode limit.
    pub inode_hard: u64,
}

impl QuotaRow {
    /// Exactly the intended hard limits and no soft limits.
    pub fn matches(&self, limits: QuotaLimits) -> bool {
        self.block_soft_kib == 0
            && self.inode_soft == 0
            && self.block_hard_kib == limits.block_hard_kib
            && self.inode_hard == limits.inode_hard
    }

    /// No limit of any kind.
    pub fn limits_clear(&self) -> bool {
        self.block_soft_kib == 0
            && self.block_hard_kib == 0
            && self.inode_soft == 0
            && self.inode_hard == 0
    }
}

/// A quota report that does not parse exactly; its content is unknown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReportUnknown;

/// The row for `uid` in `repquota --output=csv -n -p` output. `Ok(None)`
/// means the uid has no entry. Any unexpected header, line, status or
/// number, or a repeated entry, is `Err`: the read-back is unknown.
pub fn report_row(csv: &str, uid: u32) -> Result<Option<QuotaRow>, ReportUnknown> {
    let mut lines = csv.lines().filter(|line| !line.is_empty());
    let header = lines.next().ok_or(ReportUnknown)?;
    let expected = |unit: &str| {
        format!(
            "User,{unit}Status,FileStatus,{unit}Used,{unit}SoftLimit,{unit}HardLimit,{unit}Grace,FileUsed,FileSoftLimit,FileHardLimit,FileGrace"
        )
    };
    if header != expected("Block") && header != expected("Space") {
        return Err(ReportUnknown);
    }
    let wanted = format!("#{uid}");
    let mut found = None;
    for line in lines {
        let fields: Vec<&str> = line.split(',').collect();
        let [name, block_status, file_status, ref rest @ ..] = fields[..] else {
            return Err(ReportUnknown);
        };
        let numbers = rest
            .iter()
            .map(|field| {
                (!field.is_empty() && field.bytes().all(|b| b.is_ascii_digit()))
                    .then(|| field.parse::<u64>().ok())
                    .flatten()
            })
            .collect::<Option<Vec<u64>>>()
            .ok_or(ReportUnknown)?;
        let status = |text: &str| matches!(text, "ok" | "soft" | "hard");
        if numbers.len() != 8
            || !status(block_status)
            || !status(file_status)
            || !name.starts_with('#')
        {
            return Err(ReportUnknown);
        }
        if name != wanted {
            continue;
        }
        if found.is_some() {
            return Err(ReportUnknown);
        }
        found = Some(QuotaRow {
            block_used_kib: numbers[0],
            block_soft_kib: numbers[1],
            block_hard_kib: numbers[2],
            inode_used: numbers[4],
            inode_soft: numbers[5],
            inode_hard: numbers[6],
        });
    }
    Ok(found)
}

/// Host access for the quota steps; [`SystemQuota`] runs the fixed tools.
pub(crate) trait QuotaHost {
    /// `/proc/self/mountinfo` text.
    fn mountinfo(&mut self) -> Result<String, ExecutorError>;
    /// `/etc/passwd` text.
    fn passwd(&mut self) -> Result<String, ExecutorError>;
    /// `quotaon -p -u -v` output for one mount.
    fn state(&mut self, mount_point: &str) -> Result<String, ExecutorError>;
    /// `repquota` CSV for one mount.
    fn report(&mut self, mount_point: &str) -> Result<String, ExecutorError>;
    /// `setquota` for one uid; `None` clears every limit.
    fn set(
        &mut self,
        uid: u32,
        limits: Option<QuotaLimits>,
        mount_point: &str,
    ) -> Result<(), ExecutorError>;
}

/// The real host. Each quota tool runs in its own transient unit, because
/// `quotactl` needs `CAP_SYS_ADMIN` and the `@privileged` syscall set, which
/// the administration helper does not hold. The unit gets only that
/// capability, no network and a read-only system; PID 1 writes its stdout to
/// the helper's runtime directory (as for capture units, W174).
pub(crate) struct SystemQuota;

/// Where PID 1 writes a quota unit's stdout.
const OUTPUT_DIR: &str = crate::layout::ADMIN_RUNTIME_DIR;

/// `systemd-run` argv for one quota tool. `success` lists the tool's exit
/// codes that are normal results. No `NoNewPrivileges`: the tools enter
/// their own SELinux domain, which the kernel refuses under no_new_privs.
pub fn job_args(
    unit: &str,
    output: &str,
    program: &str,
    args: &[String],
    success: &[i32],
) -> Vec<String> {
    let mut properties = vec![
        "User=root".to_owned(),
        "CapabilityBoundingSet=CAP_SYS_ADMIN".to_owned(),
        "SystemCallFilter=@system-service quotactl quotactl_fd".to_owned(),
        "SystemCallArchitectures=native".to_owned(),
        "RestrictAddressFamilies=AF_UNIX".to_owned(),
        "PrivateNetwork=yes".to_owned(),
        "PrivateTmp=yes".to_owned(),
        "ProtectSystem=full".to_owned(),
        "ProtectHome=yes".to_owned(),
        "MemoryMax=64M".to_owned(),
        "TasksMax=4".to_owned(),
        "RuntimeMaxSec=60".to_owned(),
        crate::provision::JOB_CPU_WEIGHT.to_owned(),
        format!("StandardOutput=truncate:{output}"),
    ];
    let extra: Vec<String> = success
        .iter()
        .filter(|code| **code != 0)
        .map(i32::to_string)
        .collect();
    if !extra.is_empty() {
        properties.push(format!("SuccessExitStatus={}", extra.join(" ")));
    }
    let mut argv: Vec<String> = ["--wait", "--quiet", "--collect"]
        .map(str::to_owned)
        .to_vec();
    argv.push(format!("--unit={unit}"));
    for property in properties {
        argv.push("--property".to_owned());
        argv.push(property);
    }
    argv.push("--".to_owned());
    argv.push(program.to_owned());
    argv.extend(args.iter().cloned());
    argv
}

impl SystemQuota {
    /// Runs one fixed quota tool in its unit and returns its stdout (bounded).
    /// `systemd-run --wait` passes the tool's exit code on, so the same
    /// `success` codes are accepted from it. An absent or unreadable output
    /// file is an error, never an empty result.
    fn job(
        &mut self,
        program: &'static str,
        args: &[String],
        success: &[i32],
    ) -> Result<String, ExecutorError> {
        use rustix::fs::{AtFlags, unlinkat};
        provision::check_program(program)?;
        let mut random = [0_u8; 8];
        rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty())
            .map_err(|_| ExecutorError::Unavailable)?;
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let unit = format!("rustiron-quota-{suffix}");
        let output = format!("{OUTPUT_DIR}/{unit}.out");
        crate::capture::ensure_output_dir()?;
        let argv = job_args(&unit, &output, program, args, success);
        let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
        let ran = provision::output_allowing("/usr/bin/systemd-run", &borrowed, success);
        let directory =
            crate::files::open_traversable_directory(std::path::Path::new(OUTPUT_DIR), 0)?;
        let name = format!("{unit}.out");
        let bytes = crate::files::read_child(
            &directory,
            &name,
            0,
            crate::files::Exposure::Readable,
            1024 * 1024,
        );
        let _ = unlinkat(&directory, name.as_str(), AtFlags::empty());
        ran?;
        String::from_utf8(bytes?).map_err(|_| ExecutorError::StepFailed)
    }
}

impl QuotaHost for SystemQuota {
    fn mountinfo(&mut self) -> Result<String, ExecutorError> {
        std::fs::read_to_string(MOUNTINFO).map_err(|_| ExecutorError::Unavailable)
    }

    fn passwd(&mut self) -> Result<String, ExecutorError> {
        provision::read_etc("passwd")
    }

    fn state(&mut self, mount_point: &str) -> Result<String, ExecutorError> {
        // quotaon -p exits with the number of quota types that are on.
        self.job(QUOTAON, &state_args(mount_point), &[0, 1])
    }

    fn report(&mut self, mount_point: &str) -> Result<String, ExecutorError> {
        self.job(REPQUOTA, &report_args(mount_point), &[0])
    }

    fn set(
        &mut self,
        uid: u32,
        limits: Option<QuotaLimits>,
        mount_point: &str,
    ) -> Result<(), ExecutorError> {
        self.job(SETQUOTA, &set_args(uid, limits, mount_point), &[0])
            .map(drop)
    }
}

/// A fixed-text reason on stderr (the service journal); never values.
fn failed(what: &'static str, error: ExecutorError) -> ExecutorError {
    eprintln!("{{\"scope\":\"site_quota\",\"step_failure\":\"{what}\"}}");
    error
}

fn refused(refusal: Refusal) -> ExecutorError {
    eprintln!(
        "{{\"scope\":\"site_quota\",\"refusal\":\"{}\"}}",
        refusal.code()
    );
    ExecutorError::QuotaUnavailable
}

/// The sites mount from the live mount table only (no enforcement check).
pub(crate) fn locate(host: &mut impl QuotaHost) -> Result<SitesMount, Refusal> {
    let text = host.mountinfo().map_err(|_| Refusal::MountUnknown)?;
    sites_mount(&text, crate::layout::SITES_ROOT)
}

/// Enrollment readiness: the sites mount has user quota on and enforced.
pub(crate) fn readiness(host: &mut impl QuotaHost) -> Result<SitesMount, Refusal> {
    let mount = locate(host)?;
    let state = host
        .state(&mount.mount_point)
        .map_err(|_| Refusal::StateUnknown)?;
    if !enforced(&state, &mount.mount_point) {
        return Err(Refusal::StateUnknown);
    }
    Ok(mount)
}

/// The readiness report for the `quota-readiness` admin command, and
/// whether the host is ready.
pub(crate) fn readiness_report(host: &mut impl QuotaHost) -> (serde_json::Value, bool) {
    match readiness(host) {
        Ok(mount) => (
            serde_json::json!({
                "sites_root": crate::layout::SITES_ROOT,
                "mount_point": mount.mount_point,
                "filesystem": match mount.filesystem {
                    Filesystem::Ext4 => "ext4",
                    Filesystem::Xfs => "xfs",
                },
                "user_quota": "enforced",
            }),
            true,
        ),
        Err(refusal) => (
            serde_json::json!({
                "sites_root": crate::layout::SITES_ROOT,
                "refusal": refusal.code(),
            }),
            false,
        ),
    }
}

/// Enrollment check on this host (admin command; runs the quota tools).
pub fn host_readiness() -> (serde_json::Value, bool) {
    readiness_report(&mut SystemQuota)
}

fn observed(
    host: &mut impl QuotaHost,
    mount: &SitesMount,
    uid: u32,
) -> Result<Option<QuotaRow>, ExecutorError> {
    let text = host
        .report(&mount.mount_point)
        .map_err(|_| failed("quota read-back unavailable", ExecutorError::StepFailed))?;
    report_row(&text, uid)
        .map_err(|ReportUnknown| failed("quota read-back unknown", ExecutorError::StepFailed))
}

/// Part of the Directories step, before any directory exists: set the
/// journaled limits for the journaled uid and read them back. A uid that
/// already has limits is not this site's to change.
pub(crate) fn apply(
    host: &mut impl QuotaHost,
    plan: QuotaPlan,
    account: &str,
    journaled_uid: Option<u32>,
) -> Result<String, ExecutorError> {
    let QuotaPlan::Enforced(limits) = plan else {
        return Ok("quota not_enforced".to_owned());
    };
    let uid = journaled_uid
        .ok_or_else(|| failed("quota uid not journaled", ExecutorError::StepFailed))?;
    if provision::account_uid(&host.passwd()?, account) != Some(uid) {
        return Err(failed("quota uid mismatch", ExecutorError::StepFailed));
    }
    let mount = readiness(host).map_err(refused)?;
    match observed(host, &mount, uid)? {
        Some(row) if !row.limits_clear() => {
            return Err(failed("quota already set", ExecutorError::Collision));
        }
        _ => {}
    }
    host.set(uid, Some(limits), &mount.mount_point)?;
    match observed(host, &mount, uid)? {
        Some(row) if row.matches(limits) => Ok(format!(
            "quota uid={uid} kib={} inodes={}",
            limits.block_hard_kib, limits.inode_hard
        )),
        _ => Err(failed(
            "quota read-back mismatch",
            ExecutorError::StepFailed,
        )),
    }
}

/// Retire: clear every limit of a removed site's uid. The account must be
/// gone and no other account may hold the uid. Read back: no entry or no limit.
pub(crate) fn clear(
    host: &mut impl QuotaHost,
    uid: u32,
    account: &str,
) -> Result<(), ExecutorError> {
    let passwd = host.passwd()?;
    let uid_text = uid.to_string();
    if provision::account_uid(&passwd, account).is_some()
        || passwd
            .lines()
            .any(|line| line.split(':').nth(2) == Some(uid_text.as_str()))
    {
        return Err(failed(
            "quota uid still in use",
            ExecutorError::PreconditionChanged,
        ));
    }
    let mount = locate(host).map_err(refused)?;
    host.set(uid, None, &mount.mount_point)?;
    match observed(host, &mount, uid)? {
        None => Ok(()),
        Some(row) if row.limits_clear() => Ok(()),
        Some(_) => Err(failed(
            "quota clear read-back mismatch",
            ExecutorError::StepFailed,
        )),
    }
}

/// Read-only usage and limits for an inventory report; unknown is reported, not guessed.
pub(crate) fn observe(host: &mut impl QuotaHost, uid: u32) -> serde_json::Value {
    let mount = match locate(host) {
        Ok(mount) => mount,
        Err(refusal) => {
            return serde_json::json!({"state": "unknown", "reason": refusal.code()});
        }
    };
    let row = host
        .report(&mount.mount_point)
        .ok()
        .and_then(|text| report_row(&text, uid).ok());
    match row {
        Some(Some(row)) => serde_json::json!({
            "state": "observed",
            "mount_point": mount.mount_point,
            "usage": row,
        }),
        Some(None) => serde_json::json!({
            "state": "no_entry",
            "mount_point": mount.mount_point,
        }),
        None => serde_json::json!({"state": "unknown", "reason": "quota_report_unknown"}),
    }
}

/// The quota a provision's Directories step journaled; `None` if that step
/// never began (no quota effect can have happened).
fn recorded(provision: &Provision) -> Option<RecordedQuota> {
    provision
        .steps
        .iter()
        .find(|record| record.step == ProvisionStep::Directories)
        .map(|record| RecordedQuota::parse(&record.resource))
}

/// Retire: clear the limits a provision journaled, for the uid it journaled,
/// once the account is gone. A running provision is refused; a provision
/// without an enforced quota has nothing to clear and says why.
pub(crate) fn retire(
    host: &mut impl QuotaHost,
    provision: &Provision,
) -> Result<serde_json::Value, ExecutorError> {
    if provision.state == ProvisionState::Running {
        return Err(ExecutorError::Busy);
    }
    let account = provision::SiteLayout::derive(&provision.intent.site_id).account;
    let uid = crate::durable::journaled_uid(provision);
    let outcome = match recorded(provision) {
        None => "not_attempted",
        Some(RecordedQuota::Absent) => "not_recorded",
        Some(RecordedQuota::Plan(QuotaIntent {
            plan: QuotaPlan::NotEnforced,
            ..
        })) => "not_enforced",
        Some(RecordedQuota::Malformed) => return Err(ExecutorError::Unavailable),
        Some(RecordedQuota::Plan(QuotaIntent {
            plan: QuotaPlan::Enforced(_),
            ..
        })) => {
            clear(host, uid.ok_or(ExecutorError::Unavailable)?, &account)?;
            "cleared"
        }
    };
    Ok(serde_json::json!({
        "site_id": provision.intent.site_id.as_str(),
        "uid": uid,
        "quota": outcome,
    }))
}

/// W535 (D-088): a signed change of a site's hard limits. The site's UID
/// comes from its account; its quota must be enforced, and each new limit
/// must be above its current use. Sets the limits and reads them back.
pub(crate) fn change(
    host: &mut impl QuotaHost,
    account: &str,
    limits: QuotaLimits,
) -> Result<String, ExecutorError> {
    if !limits.valid() {
        return Err(failed("quota limits", ExecutorError::BindingDenied));
    }
    let uid = provision::account_uid(&host.passwd()?, account)
        .ok_or_else(|| failed("quota uid", ExecutorError::StepFailed))?;
    let mount = readiness(host).map_err(refused)?;
    let row = match observed(host, &mount, uid)? {
        Some(row) if !row.limits_clear() => row,
        _ => return Err(failed("quota not enforced", ExecutorError::StepFailed)),
    };
    if row.block_used_kib >= limits.block_hard_kib || row.inode_used >= limits.inode_hard {
        return Err(failed("quota below current use", ExecutorError::StepFailed));
    }
    host.set(uid, Some(limits), &mount.mount_point)?;
    match observed(host, &mount, uid)? {
        Some(row) if row.matches(limits) => Ok(format!(
            "quota uid={uid} kib={} inodes={}",
            limits.block_hard_kib, limits.inode_hard
        )),
        _ => Err(failed(
            "quota read-back mismatch",
            ExecutorError::StepFailed,
        )),
    }
}

/// Export facts: the journaled quota and, for its uid, the live usage and limits.
pub(crate) fn facts(host: &mut impl QuotaHost, provision: &Provision) -> serde_json::Value {
    let recorded = recorded_json(recorded(provision));
    let observed = crate::durable::journaled_uid(provision).map(|uid| observe(host, uid));
    serde_json::json!({"recorded": recorded, "observed": observed})
}

/// The JSON of a journaled quota record; `None` means the Directories step
/// never began. Shared by the site export and the observation (W379).
pub(crate) fn recorded_json(recorded: Option<RecordedQuota>) -> serde_json::Value {
    match recorded {
        None => serde_json::json!({"state": "not_attempted"}),
        Some(RecordedQuota::Absent) => serde_json::json!({"state": "not_recorded"}),
        Some(RecordedQuota::Malformed) => serde_json::json!({"state": "malformed"}),
        Some(RecordedQuota::Plan(QuotaIntent {
            plan: QuotaPlan::NotEnforced,
            source,
        })) => serde_json::json!({"state": "not_enforced", "source": source.token()}),
        Some(RecordedQuota::Plan(QuotaIntent {
            plan: QuotaPlan::Enforced(limits),
            source,
        })) => serde_json::json!({
            "state": "enforced",
            "source": source.token(),
            "block_hard_kib": limits.block_hard_kib,
            "inode_hard": limits.inode_hard,
        }),
    }
}

/// W372: export facts of an adopted site: the limits its re-adoption
/// verified and, for its uid, the live usage and limits.
pub(crate) fn adopted_facts(
    host: &mut impl QuotaHost,
    uid: u32,
    limits: QuotaLimits,
) -> serde_json::Value {
    enforced_facts(host, uid, limits, "readoption")
}

/// W534 (D-088): export facts with the limits of the newest signed quota
/// change.
pub(crate) fn changed_facts(
    host: &mut impl QuotaHost,
    uid: u32,
    limits: QuotaLimits,
) -> serde_json::Value {
    enforced_facts(host, uid, limits, "quota_change")
}

fn enforced_facts(
    host: &mut impl QuotaHost,
    uid: u32,
    limits: QuotaLimits,
    source: &str,
) -> serde_json::Value {
    serde_json::json!({
        "recorded": {
            "state": "enforced",
            "source": source,
            "block_hard_kib": limits.block_hard_kib,
            "inode_hard": limits.inode_hard,
        },
        "observed": observe(host, uid),
    })
}

/// W372: retire an adopted site's quota: the uid its re-adoption verified,
/// under the same rules as [`retire`] (the account must be gone).
pub(crate) fn retire_adopted(
    host: &mut impl QuotaHost,
    site: &rustiron_contracts::approval::SiteId,
    uid: u32,
) -> Result<serde_json::Value, ExecutorError> {
    let account = provision::SiteLayout::derive(site).account;
    clear(host, uid, &account)?;
    Ok(serde_json::json!({
        "site_id": site.as_str(),
        "uid": uid,
        "quota": "cleared",
    }))
}

#[cfg(test)]
#[path = "quota_tests.rs"]
mod tests;
