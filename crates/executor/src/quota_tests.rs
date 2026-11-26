//! W335 quota steps without root: argv builders, mount-table and report
//! parsing, and step order and failure states against a recorded fake host.

use std::collections::VecDeque;

use rustiron_contracts::{
    Id, Timestamp,
    approval::{Hostname, Sha256Digest, SiteId},
};
use rustiron_journal::{
    Provision, ProvisionIntent, ProvisionState, ProvisionStep, StepRecord, StepState,
};

use super::*;

const ROOT_XFS_NOQUOTA: &str = "22 1 253:0 / / rw,relatime shared:1 - xfs /dev/mapper/almalinux-root rw,seclabel,attr2,inode64,logbufs=8,logbsize=32k,noquota";
const ROOT_XFS: &str =
    "22 1 253:0 / / rw,relatime shared:1 - xfs /dev/vda1 rw,seclabel,attr2,inode64,noquota";
const PROC: &str = "23 22 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:5 - proc proc rw";
const SITES_EXT4: &str =
    "95 22 7:0 / /srv/sites rw,relatime shared:50 - ext4 /dev/loop0 rw,seclabel,quota,usrquota";
const SITES_XFS: &str = "96 22 7:1 / /srv/sites rw,relatime shared:51 - xfs /dev/loop1 rw,seclabel,attr2,inode64,usrquota";
const HEADER: &str = "User,BlockStatus,FileStatus,BlockUsed,BlockSoftLimit,BlockHardLimit,BlockGrace,FileUsed,FileSoftLimit,FileHardLimit,FileGrace";
const PASSWD: &str =
    "root:x:0:0:root:/root:/bin/bash\nrs_blog1:x:3001:3001::/srv/sites/rs_blog1:/sbin/nologin\n";
const ENFORCED: &str = "user quota on /srv/sites (/dev/loop0) is on (enforced)\n";

fn table(lines: &[&str]) -> String {
    lines.join("\n") + "\n"
}

fn report(rows: &[&str]) -> String {
    let mut text = format!("{HEADER}\n");
    for row in rows {
        text.push_str(row);
        text.push('\n');
    }
    text
}

const SET_ROW: &str = "#3001,ok,ok,0,0,5242880,0,0,0,500000,0";
const ROOT_ROW: &str = "#0,ok,ok,20,0,0,0,2,0,0,0";

// ---- mount table ----

#[test]
fn ext4_and_xfs_sites_mounts_with_user_quota_are_accepted() {
    let ext4 = sites_mount(&table(&[ROOT_XFS_NOQUOTA, PROC, SITES_EXT4]), "/srv/sites");
    assert_eq!(
        ext4,
        Ok(SitesMount {
            mount_point: "/srv/sites".to_owned(),
            filesystem: Filesystem::Ext4
        })
    );
    let xfs = sites_mount(&table(&[ROOT_XFS_NOQUOTA, SITES_XFS]), "/srv/sites");
    assert_eq!(xfs.map(|m| m.filesystem), Ok(Filesystem::Xfs));
    let uquota = SITES_XFS.replace("usrquota", "uquota");
    assert_eq!(
        sites_mount(&table(&[ROOT_XFS, &uquota]), "/srv/sites").map(|m| m.filesystem),
        Ok(Filesystem::Xfs)
    );
}

#[test]
fn a_root_filesystem_holding_the_sites_root_is_used_when_it_has_user_quota() {
    let root = ROOT_XFS.replace("noquota", "usrquota");
    assert_eq!(
        sites_mount(&table(&[&root, PROC]), "/srv/sites").map(|m| m.mount_point),
        Ok("/".to_owned())
    );
}

#[test]
fn the_lab_root_with_noquota_is_refused() {
    assert_eq!(
        sites_mount(&table(&[ROOT_XFS_NOQUOTA, PROC]), "/srv/sites"),
        Err(Refusal::UserQuotaMissing)
    );
    let ext4 = SITES_EXT4.replace(",quota,usrquota", "");
    assert_eq!(
        sites_mount(&table(&[ROOT_XFS, &ext4]), "/srv/sites"),
        Err(Refusal::UserQuotaMissing)
    );
    // ext4 takes only usrquota; uquota is an XFS spelling.
    let ext4 = SITES_EXT4.replace(",quota,usrquota", ",uquota");
    assert_eq!(
        sites_mount(&table(&[ROOT_XFS, &ext4]), "/srv/sites"),
        Err(Refusal::UserQuotaMissing)
    );
}

#[test]
fn xfs_accounting_without_enforcement_is_refused() {
    let line = SITES_XFS.replace("usrquota", "uqnoenforce");
    assert_eq!(
        sites_mount(&table(&[ROOT_XFS, &line]), "/srv/sites"),
        Err(Refusal::NotEnforced)
    );
}

#[test]
fn bind_ambiguous_nested_and_foreign_mounts_are_refused() {
    let bind = "97 22 253:16 /data/sites /srv/sites rw,relatime - xfs /dev/vdb rw,usrquota";
    assert_eq!(
        sites_mount(&table(&[ROOT_XFS, bind]), "/srv/sites"),
        Err(Refusal::BindMount)
    );
    let over = SITES_XFS.replace("96 22", "98 96");
    assert_eq!(
        sites_mount(&table(&[ROOT_XFS, SITES_XFS, &over]), "/srv/sites"),
        Err(Refusal::MountAmbiguous)
    );
    let nested = "99 95 7:2 / /srv/sites/rs_x rw - ext4 /dev/loop2 rw,usrquota";
    assert_eq!(
        sites_mount(&table(&[ROOT_XFS, SITES_EXT4, nested]), "/srv/sites"),
        Err(Refusal::NestedMount)
    );
    let tmpfs = "100 22 0:50 / /srv/sites rw - tmpfs tmpfs rw,usrquota";
    assert_eq!(
        sites_mount(&table(&[ROOT_XFS, tmpfs]), "/srv/sites"),
        Err(Refusal::UnsupportedFilesystem)
    );
}

#[test]
fn mount_points_are_compared_by_whole_unescaped_components() {
    // `/srv/sitesx` neither holds nor nests in `/srv/sites`.
    let sibling = "101 22 7:3 / /srv/sitesx rw - ext4 /dev/loop3 rw,usrquota";
    assert_eq!(
        sites_mount(&table(&[ROOT_XFS, sibling]), "/srv/sites"),
        Err(Refusal::UserQuotaMissing),
        "the root filesystem holds /srv/sites, not /srv/sitesx"
    );
    let escaped = "102 22 7:4 / /srv/site\\040s rw - ext4 /dev/loop4 rw,usrquota";
    assert_eq!(
        sites_mount(&table(&[ROOT_XFS, escaped]), "/srv/sites"),
        Err(Refusal::UserQuotaMissing)
    );
    assert_eq!(
        sites_mount(&table(&[ROOT_XFS, escaped]), "/srv/site s").map(|m| m.mount_point),
        Ok("/srv/site s".to_owned())
    );
}

#[test]
fn a_malformed_or_empty_mount_table_is_unknown() {
    assert_eq!(sites_mount("", "/srv/sites"), Err(Refusal::MountUnknown));
    assert_eq!(
        sites_mount(&table(&[ROOT_XFS, "garbage line"]), "/srv/sites"),
        Err(Refusal::MountUnknown)
    );
    let bad_escape = "103 22 7:5 / /srv/\\9xx rw - ext4 /dev/loop5 rw,usrquota";
    assert_eq!(
        sites_mount(&table(&[ROOT_XFS, bad_escape]), "/srv/sites"),
        Err(Refusal::MountUnknown)
    );
    let short = "104 22 7:6 / /srv/sites rw - ext4 /dev/loop6";
    assert_eq!(
        sites_mount(&table(&[ROOT_XFS, short]), "/srv/sites"),
        Err(Refusal::MountUnknown)
    );
}

#[test]
fn only_one_enforced_user_quota_state_line_is_accepted() {
    assert!(enforced(ENFORCED, "/srv/sites"));
    for refused in [
        "",
        "user quota on /srv/sites (/dev/loop0) is on\n",
        "user quota on /srv/sites (/dev/loop0) is on (accounting)\n",
        "user quota on /srv/sites (/dev/loop0) is off\n",
        "user quota on /srv (/dev/loop0) is on (enforced)\n",
        "group quota on /srv/sites (/dev/loop0) is on (enforced)\n",
    ] {
        assert!(!enforced(refused, "/srv/sites"), "{refused:?}");
    }
    assert!(!enforced(&format!("{ENFORCED}{ENFORCED}"), "/srv/sites"));
}

// ---- argv ----

#[test]
fn setquota_argv_is_fixed_with_the_uid_limits_and_mount() {
    assert_eq!(
        set_args(3001, Some(QuotaLimits::DEFAULT), "/srv/sites"),
        [
            "-u",
            "--",
            "3001",
            "0",
            "5242880",
            "0",
            "500000",
            "/srv/sites"
        ]
    );
    assert_eq!(
        set_args(3001, None, "/srv/sites"),
        ["-u", "--", "3001", "0", "0", "0", "0", "/srv/sites"]
    );
    assert_eq!(
        report_args("/srv/sites"),
        ["-u", "-n", "-p", "-v", "--output=csv", "--", "/srv/sites"]
    );
    assert_eq!(
        state_args("/srv/sites"),
        ["-p", "-u", "-v", "--", "/srv/sites"]
    );
}

#[test]
fn quota_jobs_get_only_the_quota_capability_and_fixed_tools() {
    let args = job_args(
        "rustiron-quota-00",
        "/run/rustiron-admin/rustiron-quota-00.out",
        QUOTAON,
        &state_args("/srv/sites"),
        &[0, 1],
    );
    let properties: Vec<&str> = args
        .windows(2)
        .filter(|pair| pair[0] == "--property")
        .map(|pair| pair[1].as_str())
        .collect();
    assert!(properties.contains(&"CapabilityBoundingSet=CAP_SYS_ADMIN"));
    assert!(properties.contains(&"PrivateNetwork=yes"));
    assert!(properties.contains(&"SuccessExitStatus=1"));
    assert!(
        properties.contains(&"StandardOutput=truncate:/run/rustiron-admin/rustiron-quota-00.out")
    );
    let command = &args[args.iter().position(|a| a == "--").unwrap() + 1..];
    assert_eq!(
        command,
        ["/usr/sbin/quotaon", "-p", "-u", "-v", "--", "/srv/sites"]
    );
    let plain = job_args("u", "/o", SETQUOTA, &set_args(1, None, "/"), &[0]);
    assert!(!plain.iter().any(|a| a.starts_with("SuccessExitStatus")));
}

// ---- journal text ----

#[test]
fn the_journaled_plan_round_trips_and_anything_else_is_malformed() {
    let policy = QuotaIntent {
        plan: QuotaPlan::Enforced(QuotaLimits::DEFAULT),
        source: QuotaSource::Policy,
    };
    let resource = format!("Directories rs_blog1 {}", policy.resource());
    assert_eq!(
        resource,
        "Directories rs_blog1 quota=enforced source=policy kib=5242880 inodes=500000"
    );
    assert_eq!(RecordedQuota::parse(&resource), RecordedQuota::Plan(policy));
    let signed = QuotaIntent {
        plan: QuotaPlan::Enforced(SMALL),
        source: QuotaSource::Plan,
    };
    let resource = format!("Directories rs_blog1 {}", signed.resource());
    assert_eq!(
        resource,
        "Directories rs_blog1 quota=enforced source=plan kib=1048576 inodes=20000"
    );
    assert_eq!(RecordedQuota::parse(&resource), RecordedQuota::Plan(signed));
    let lab = QuotaIntent {
        plan: QuotaPlan::NotEnforced,
        source: QuotaSource::Policy,
    };
    assert_eq!(lab.resource(), "quota=not_enforced source=policy");
    assert_eq!(
        RecordedQuota::parse("Directories rs_blog1 quota=not_enforced source=policy"),
        RecordedQuota::Plan(lab)
    );
    // W335 records have no source token; their limits came from policy.
    assert_eq!(
        RecordedQuota::parse("Directories rs_blog1 quota=enforced kib=5242880 inodes=500000"),
        RecordedQuota::Plan(policy)
    );
    assert_eq!(
        RecordedQuota::parse("Directories rs_blog1 quota=not_enforced"),
        RecordedQuota::Plan(lab)
    );
    assert_eq!(
        RecordedQuota::parse("Directories rs_blog1"),
        RecordedQuota::Absent
    );
    for bad in [
        "Directories rs_x quota=enforced kib=5242880",
        "Directories rs_x quota=enforced kib=5242880 inodes=500000 inodes=1",
        "Directories rs_x quota=enforced kib=-1 inodes=500000",
        "Directories rs_x quota=enforced kib=1 inodes=500000",
        "Directories rs_x quota=maybe",
        "Directories rs_x quota=not_enforced kib=1",
        "Directories rs_x quota=enforced quota=enforced kib=5242880 inodes=500000",
        "Directories rs_x quota=not_enforced source=plan",
        "Directories rs_x quota=enforced source=signed kib=5242880 inodes=500000",
        "Directories rs_x quota=enforced source= kib=5242880 inodes=500000",
        "Directories rs_x quota=enforced source=plan source=plan kib=5242880 inodes=500000",
        "Directories rs_x quota=enforced source=policy source=plan kib=5242880 inodes=500000",
        "Directories rs_x source=plan",
    ] {
        assert_eq!(RecordedQuota::parse(bad), RecordedQuota::Malformed, "{bad}");
    }
}

const SMALL: QuotaLimits = QuotaLimits {
    block_hard_kib: 1_048_576,
    inode_hard: 20_000,
};

#[test]
fn signed_v2_limits_are_used_and_v1_uses_the_enrolled_policy() {
    // v1 plan (no signed limits): the enrolled policy, or not enforced.
    assert_eq!(
        QuotaIntent::select(None, Some(QuotaLimits::DEFAULT)),
        QuotaIntent {
            plan: QuotaPlan::Enforced(QuotaLimits::DEFAULT),
            source: QuotaSource::Policy,
        }
    );
    assert_eq!(
        QuotaIntent::select(None, None),
        QuotaIntent {
            plan: QuotaPlan::NotEnforced,
            source: QuotaSource::Policy,
        }
    );
    // v2 plan: the signed limits, never the enrolled ceiling.
    assert_eq!(
        QuotaIntent::select(Some(SMALL), Some(QuotaLimits::DEFAULT)),
        QuotaIntent {
            plan: QuotaPlan::Enforced(SMALL),
            source: QuotaSource::Plan,
        }
    );
    assert_eq!(
        QuotaIntent::select(Some(QuotaLimits::DEFAULT), Some(QuotaLimits::DEFAULT)).plan,
        QuotaPlan::Enforced(QuotaLimits::DEFAULT)
    );
}

#[test]
fn signed_limits_convert_exactly_from_the_contract_type() {
    let signed = rustiron_contracts::approval::SiteQuotaLimits::new(1_048_576, 20_000).unwrap();
    assert_eq!(QuotaLimits::from(signed), SMALL);
    assert_eq!(
        QuotaLimits::DEFAULT.cap(),
        rustiron_contracts::approval::SiteQuotaLimits::new(5_242_880, 500_000).ok()
    );
    let outside = QuotaLimits {
        block_hard_kib: 1,
        inode_hard: 500_000,
    };
    assert_eq!(outside.cap(), None);
}

#[test]
fn enrolled_limits_have_fixed_bounds() {
    assert!(QuotaLimits::DEFAULT.valid());
    let limits = |block_hard_kib, inode_hard| QuotaLimits {
        block_hard_kib,
        inode_hard,
    };
    assert!(!limits(0, 500_000).valid());
    assert!(!limits(65_535, 500_000).valid());
    assert!(limits(65_536, 1_000).valid());
    assert!(!limits(5_242_880, 999).valid());
    assert!(!limits(5_242_880, 100_000_001).valid());
    assert!(!limits(16 * 1024 * 1024 * 1024 + 1, 500_000).valid());
}

// ---- read-back ----

#[test]
fn the_report_row_for_the_uid_is_read_exactly() {
    let text = report(&[ROOT_ROW, SET_ROW, "#30010,ok,ok,1,0,9,0,1,0,9,0"]);
    let row = report_row(&text, 3001).unwrap().unwrap();
    assert!(row.matches(QuotaLimits::DEFAULT));
    assert!(!row.limits_clear());
    assert_eq!(row.block_hard_kib, 5_242_880);
    assert_eq!(report_row(&text, 3002), Ok(None));
    let space = text
        .replacen("User,Block", "User,Space", 1)
        .replace("Block", "Space");
    assert_eq!(report_row(&space, 3001).map(|r| r.is_some()), Ok(true));
}

#[test]
fn an_unexpected_report_is_unknown_never_absent() {
    for bad in [
        String::new(),
        "*** Report for user quotas on device /dev/loop0\n".to_owned(),
        report(&["#3001,ok,ok,0,0,5G,0,0,0,500000,0"]),
        report(&["#3001,ok,ok,0,0,5242880,0,0,0,500000"]),
        report(&["#3001,over,ok,0,0,5242880,0,0,0,500000,0"]),
        report(&["rs_blog1,ok,ok,0,0,5242880,0,0,0,500000,0"]),
        report(&[SET_ROW, SET_ROW]),
    ] {
        assert_eq!(report_row(&bad, 3001), Err(ReportUnknown), "{bad:?}");
    }
}

#[test]
fn soft_limits_or_other_hard_limits_do_not_match() {
    let row = |text: &str| report_row(&report(&[text]), 3001).unwrap().unwrap();
    assert!(!row("#3001,ok,ok,0,1,5242880,0,0,0,500000,0").matches(QuotaLimits::DEFAULT));
    assert!(!row("#3001,ok,ok,0,0,5242880,0,0,1,500000,0").matches(QuotaLimits::DEFAULT));
    assert!(!row("#3001,ok,ok,0,0,5242881,0,0,0,500000,0").matches(QuotaLimits::DEFAULT));
    assert!(!row("#3001,ok,ok,0,0,5242880,0,0,0,500001,0").matches(QuotaLimits::DEFAULT));
    assert!(row("#3001,ok,ok,12,0,0,0,3,0,0,0").limits_clear());
}

// ---- steps against a fake host ----

struct Fake {
    mountinfo: Result<String, ExecutorError>,
    passwd: String,
    state: Result<String, ExecutorError>,
    reports: VecDeque<Result<String, ExecutorError>>,
    set: Result<(), ExecutorError>,
    calls: Vec<String>,
}

impl Fake {
    fn ready(reports: &[Result<String, ExecutorError>]) -> Self {
        Self {
            mountinfo: Ok(table(&[ROOT_XFS_NOQUOTA, PROC, SITES_EXT4])),
            passwd: PASSWD.to_owned(),
            state: Ok(ENFORCED.to_owned()),
            reports: reports.iter().cloned().collect(),
            set: Ok(()),
            calls: Vec::new(),
        }
    }

    fn sets(&self) -> Vec<&String> {
        self.calls.iter().filter(|c| c.starts_with("set")).collect()
    }
}

impl QuotaHost for Fake {
    fn mountinfo(&mut self) -> Result<String, ExecutorError> {
        self.calls.push("mountinfo".to_owned());
        self.mountinfo.clone()
    }
    fn passwd(&mut self) -> Result<String, ExecutorError> {
        self.calls.push("passwd".to_owned());
        Ok(self.passwd.clone())
    }
    fn state(&mut self, mount_point: &str) -> Result<String, ExecutorError> {
        self.calls.push(format!("state {mount_point}"));
        self.state.clone()
    }
    fn report(&mut self, mount_point: &str) -> Result<String, ExecutorError> {
        self.calls.push(format!("report {mount_point}"));
        self.reports
            .pop_front()
            .unwrap_or(Err(ExecutorError::Unavailable))
    }
    fn set(
        &mut self,
        uid: u32,
        limits: Option<QuotaLimits>,
        mount_point: &str,
    ) -> Result<(), ExecutorError> {
        self.calls.push(format!(
            "set {}",
            set_args(uid, limits, mount_point).join(" ")
        ));
        self.set
    }
}

const ENFORCED_PLAN: QuotaPlan = QuotaPlan::Enforced(QuotaLimits::DEFAULT);

#[test]
fn provision_sets_then_reads_back_the_journaled_limits() {
    let mut host = Fake::ready(&[Ok(report(&[ROOT_ROW])), Ok(report(&[ROOT_ROW, SET_ROW]))]);
    let done = apply(&mut host, ENFORCED_PLAN, "rs_blog1", Some(3001));
    assert_eq!(
        done.as_deref(),
        Ok("quota uid=3001 kib=5242880 inodes=500000")
    );
    assert_eq!(
        host.calls,
        [
            "passwd",
            "mountinfo",
            "state /srv/sites",
            "report /srv/sites",
            "set -u -- 3001 0 5242880 0 500000 /srv/sites",
            "report /srv/sites",
        ]
    );
}

#[test]
fn not_enforced_touches_nothing() {
    let mut host = Fake::ready(&[]);
    assert_eq!(
        apply(&mut host, QuotaPlan::NotEnforced, "rs_blog1", Some(3001)).as_deref(),
        Ok("quota not_enforced")
    );
    assert!(host.calls.is_empty());
}

#[test]
fn a_missing_or_different_uid_sets_nothing() {
    let mut host = Fake::ready(&[]);
    assert_eq!(
        apply(&mut host, ENFORCED_PLAN, "rs_blog1", None),
        Err(ExecutorError::StepFailed)
    );
    assert_eq!(
        apply(&mut host, ENFORCED_PLAN, "rs_blog1", Some(3002)),
        Err(ExecutorError::StepFailed)
    );
    assert_eq!(
        apply(&mut host, ENFORCED_PLAN, "rs_other", Some(3001)),
        Err(ExecutorError::StepFailed)
    );
    assert!(host.sets().is_empty());
}

#[test]
fn a_host_without_enforced_user_quota_sets_nothing() {
    let mut noquota = Fake::ready(&[]);
    noquota.mountinfo = Ok(table(&[ROOT_XFS_NOQUOTA, PROC]));
    let mut accounting = Fake::ready(&[]);
    accounting.state = Ok(ENFORCED.replace("(enforced)", "(accounting)"));
    let mut state_failed = Fake::ready(&[]);
    state_failed.state = Err(ExecutorError::StepFailed);
    let mut unreadable = Fake::ready(&[]);
    unreadable.mountinfo = Err(ExecutorError::Unavailable);
    for mut host in [noquota, accounting, state_failed, unreadable] {
        assert_eq!(
            apply(&mut host, ENFORCED_PLAN, "rs_blog1", Some(3001)),
            Err(ExecutorError::QuotaUnavailable)
        );
        assert!(host.sets().is_empty());
    }
}

#[test]
fn a_uid_that_already_has_limits_is_not_changed() {
    let mut host = Fake::ready(&[Ok(report(&["#3001,ok,ok,0,0,1,0,0,0,0,0"]))]);
    assert_eq!(
        apply(&mut host, ENFORCED_PLAN, "rs_blog1", Some(3001)),
        Err(ExecutorError::Collision)
    );
    assert!(host.sets().is_empty());
    let mut unknown = Fake::ready(&[Ok("garbage".to_owned())]);
    assert_eq!(
        apply(&mut unknown, ENFORCED_PLAN, "rs_blog1", Some(3001)),
        Err(ExecutorError::StepFailed)
    );
    assert!(unknown.sets().is_empty());
}

#[test]
fn a_failed_set_or_a_wrong_read_back_is_a_failed_step() {
    let mut set_failed = Fake::ready(&[Ok(report(&[])), Ok(report(&[SET_ROW]))]);
    set_failed.set = Err(ExecutorError::StepFailed);
    assert_eq!(
        apply(&mut set_failed, ENFORCED_PLAN, "rs_blog1", Some(3001)),
        Err(ExecutorError::StepFailed)
    );
    for after in [
        Ok(report(&[])),
        Ok(report(&["#3001,ok,ok,0,0,5242880,0,0,0,1000,0"])),
        Ok("garbage".to_owned()),
        Err(ExecutorError::StepFailed),
    ] {
        let mut host = Fake::ready(&[Ok(report(&[])), after.clone()]);
        assert_eq!(
            apply(&mut host, ENFORCED_PLAN, "rs_blog1", Some(3001)),
            Err(ExecutorError::StepFailed),
            "{after:?}"
        );
        assert_eq!(host.sets().len(), 1);
    }
}

// ---- retire ----

fn removed() -> String {
    "root:x:0:0:root:/root:/bin/bash\n".to_owned()
}

#[test]
fn retire_clears_only_a_removed_uid_and_reads_it_back() {
    for after in [
        report(&[ROOT_ROW]),
        report(&["#3001,ok,ok,8,0,0,0,2,0,0,0"]),
    ] {
        let mut host = Fake::ready(&[Ok(after)]);
        host.passwd = removed();
        assert_eq!(clear(&mut host, 3001, "rs_blog1"), Ok(()));
        assert_eq!(
            host.calls,
            [
                "passwd",
                "mountinfo",
                "set -u -- 3001 0 0 0 0 /srv/sites",
                "report /srv/sites"
            ]
        );
    }
}

#[test]
fn retire_refuses_a_uid_still_in_use() {
    let mut present = Fake::ready(&[]);
    assert_eq!(
        clear(&mut present, 3001, "rs_blog1"),
        Err(ExecutorError::PreconditionChanged)
    );
    let mut reused = Fake::ready(&[]);
    reused.passwd = format!("{}other:x:3001:3001::/:/sbin/nologin\n", removed());
    assert_eq!(
        clear(&mut reused, 3001, "rs_blog1"),
        Err(ExecutorError::PreconditionChanged)
    );
    assert!(present.sets().is_empty() && reused.sets().is_empty());
}

#[test]
fn retire_with_limits_left_or_an_unknown_read_back_fails() {
    for after in [Ok(report(&[SET_ROW])), Ok("garbage".to_owned())] {
        let mut host = Fake::ready(&[after]);
        host.passwd = removed();
        assert_eq!(
            clear(&mut host, 3001, "rs_blog1"),
            Err(ExecutorError::StepFailed)
        );
    }
}

fn provision(steps: &[(ProvisionStep, &str)], state: ProvisionState) -> Provision {
    let id = |value: &str| Id::try_from(value.to_owned()).unwrap();
    let digest = Sha256Digest::try_from("a".repeat(64)).unwrap();
    Provision {
        intent: ProvisionIntent {
            operation_id: id("op_a"),
            idempotency_key: id("k"),
            grant_id: id("g"),
            nonce: id("n"),
            plan_digest: digest.clone(),
            grant_digest: digest,
            host_id: id("h"),
            host_epoch: id("e"),
            site_id: SiteId::try_from("blog1".to_owned()).unwrap(),
            hostname: Hostname::try_from("blog1.example.test".to_owned()).unwrap(),
            expires_at: Timestamp::try_from(1000).unwrap(),
        },
        state,
        steps: steps
            .iter()
            .map(|(step, resource)| StepRecord {
                step: *step,
                state: StepState::Done,
                resource: (*resource).to_owned(),
            })
            .collect(),
    }
}

const ACCOUNT: (ProvisionStep, &str) = (ProvisionStep::Account, "Account rs_blog1 uid=3001");

#[test]
fn retire_uses_the_journaled_uid_and_plan() {
    let directories = (
        ProvisionStep::Directories,
        "Directories rs_blog1 quota=enforced kib=5242880 inodes=500000",
    );
    let record = provision(&[ACCOUNT, directories], ProvisionState::Quarantined);
    let mut host = Fake::ready(&[Ok(report(&[]))]);
    host.passwd = removed();
    let done = retire(&mut host, &record).unwrap();
    assert_eq!(done["quota"], "cleared");
    assert_eq!(done["uid"], 3001);
    assert_eq!(host.sets(), ["set -u -- 3001 0 0 0 0 /srv/sites"]);
    let running = provision(&[ACCOUNT, directories], ProvisionState::Running);
    assert_eq!(retire(&mut host, &running), Err(ExecutorError::Busy));
}

#[test]
fn retire_without_an_enforced_journaled_quota_touches_nothing() {
    for (steps, outcome) in [
        (vec![ACCOUNT], "not_attempted"),
        (
            vec![
                ACCOUNT,
                (ProvisionStep::Directories, "Directories rs_blog1"),
            ],
            "not_recorded",
        ),
        (
            vec![
                ACCOUNT,
                (
                    ProvisionStep::Directories,
                    "Directories rs_blog1 quota=not_enforced",
                ),
            ],
            "not_enforced",
        ),
    ] {
        let mut host = Fake::ready(&[]);
        let done = retire(&mut host, &provision(&steps, ProvisionState::Succeeded)).unwrap();
        assert_eq!(done["quota"], outcome);
        assert!(host.calls.is_empty());
    }
    let malformed = provision(
        &[
            ACCOUNT,
            (ProvisionStep::Directories, "Directories rs_blog1 quota=x"),
        ],
        ProvisionState::Succeeded,
    );
    assert_eq!(
        retire(&mut Fake::ready(&[]), &malformed),
        Err(ExecutorError::Unavailable)
    );
    let no_uid = provision(
        &[
            (ProvisionStep::Account, "Account rs_blog1"),
            (
                ProvisionStep::Directories,
                "Directories rs_blog1 quota=enforced kib=5242880 inodes=500000",
            ),
        ],
        ProvisionState::Quarantined,
    );
    let mut host = Fake::ready(&[]);
    assert_eq!(retire(&mut host, &no_uid), Err(ExecutorError::Unavailable));
    assert!(host.sets().is_empty());
}

#[test]
fn export_facts_report_the_journaled_limit_and_live_usage() {
    let record = provision(
        &[
            ACCOUNT,
            (
                ProvisionStep::Directories,
                "Directories rs_blog1 quota=enforced kib=5242880 inodes=500000",
            ),
        ],
        ProvisionState::Succeeded,
    );
    let mut host = Fake::ready(&[Ok(report(&["#3001,ok,ok,1024,0,5242880,0,40,0,500000,0"]))]);
    let facts = facts(&mut host, &record);
    assert_eq!(facts["recorded"]["state"], "enforced");
    assert_eq!(facts["recorded"]["source"], "policy");
    assert_eq!(facts["recorded"]["block_hard_kib"], 5_242_880);
    assert_eq!(facts["observed"]["state"], "observed");
    assert_eq!(facts["observed"]["usage"]["block_used_kib"], 1024);
    assert_eq!(facts["observed"]["usage"]["inode_hard"], 500_000);
    let mut broken = Fake::ready(&[Ok("garbage".to_owned())]);
    let unknown = super::facts(&mut broken, &record);
    assert_eq!(unknown["observed"]["state"], "unknown");
}

#[test]
fn signed_limits_are_reported_with_their_source_and_cleared_at_retire() {
    let directories = (
        ProvisionStep::Directories,
        "Directories rs_blog1 quota=enforced source=plan kib=1048576 inodes=20000",
    );
    let record = provision(&[ACCOUNT, directories], ProvisionState::Succeeded);
    let mut host = Fake::ready(&[Ok(report(&[]))]);
    let facts = facts(&mut host, &record);
    assert_eq!(facts["recorded"]["state"], "enforced");
    assert_eq!(facts["recorded"]["source"], "plan");
    assert_eq!(facts["recorded"]["block_hard_kib"], 1_048_576);
    assert_eq!(facts["recorded"]["inode_hard"], 20_000);
    let mut host = Fake::ready(&[Ok(report(&[]))]);
    host.passwd = removed();
    assert_eq!(retire(&mut host, &record).unwrap()["quota"], "cleared");
    assert_eq!(host.sets(), ["set -u -- 3001 0 0 0 0 /srv/sites"]);
}

#[test]
fn readiness_reports_the_mount_or_a_refusal_code() {
    let (report, ready) = readiness_report(&mut Fake::ready(&[]));
    assert!(ready);
    assert_eq!(report["filesystem"], "ext4");
    assert_eq!(report["mount_point"], "/srv/sites");
    let mut lab = Fake::ready(&[]);
    lab.mountinfo = Ok(table(&[ROOT_XFS_NOQUOTA, PROC]));
    let (report, ready) = readiness_report(&mut lab);
    assert!(!ready);
    assert_eq!(report["refusal"], "quota_usrquota_missing");
}

#[test]
fn the_helper_runs_only_the_journaled_plan_that_policy_still_enrolls() {
    use crate::admin_helper::journaled_quota;
    let step = |step, resource: &str| StepRecord {
        step,
        state: StepState::Intent,
        resource: resource.to_owned(),
    };
    for resource in [
        "Directories rs_blog1 quota=enforced source=policy kib=5242880 inodes=500000",
        "Directories rs_blog1 quota=enforced kib=5242880 inodes=500000",
    ] {
        let enforced = step(ProvisionStep::Directories, resource);
        assert_eq!(
            journaled_quota(&enforced, Some(QuotaLimits::DEFAULT)),
            Ok(ENFORCED_PLAN)
        );
        let changed = QuotaLimits {
            block_hard_kib: 1024 * 1024,
            inode_hard: 500_000,
        };
        assert_eq!(
            journaled_quota(&enforced, Some(changed)),
            Err(ExecutorError::BindingDenied),
            "policy limits must equal the enrolled policy exactly"
        );
        assert_eq!(
            journaled_quota(&enforced, None),
            Err(ExecutorError::BindingDenied)
        );
    }
    let legacy = step(ProvisionStep::Directories, "Directories rs_blog1");
    assert_eq!(
        journaled_quota(&legacy, None),
        Err(ExecutorError::BindingDenied)
    );
    let lab = step(
        ProvisionStep::Directories,
        "Directories rs_blog1 quota=not_enforced source=policy",
    );
    assert_eq!(journaled_quota(&lab, None), Ok(QuotaPlan::NotEnforced));
    assert_eq!(
        journaled_quota(&lab, Some(QuotaLimits::DEFAULT)),
        Err(ExecutorError::BindingDenied),
        "a quota enrolled since the intent is not skipped"
    );
    let other = step(ProvisionStep::Labels, "Labels rs_blog1 level=s0:c201");
    assert_eq!(
        journaled_quota(&other, Some(QuotaLimits::DEFAULT)),
        Ok(QuotaPlan::NotEnforced)
    );
}

#[test]
fn the_helper_runs_signed_limits_only_within_the_enrolled_cap() {
    use crate::admin_helper::journaled_quota;
    let signed = StepRecord {
        step: ProvisionStep::Directories,
        state: StepState::Intent,
        resource: "Directories rs_blog1 quota=enforced source=plan kib=1048576 inodes=20000"
            .to_owned(),
    };
    for cap in [QuotaLimits::DEFAULT, SMALL] {
        assert_eq!(
            journaled_quota(&signed, Some(cap)),
            Ok(QuotaPlan::Enforced(SMALL)),
            "{cap:?}"
        );
    }
    for cap in [
        Some(QuotaLimits {
            block_hard_kib: 1_048_575,
            inode_hard: 500_000,
        }),
        Some(QuotaLimits {
            block_hard_kib: 5_242_880,
            inode_hard: 19_999,
        }),
        None,
    ] {
        assert_eq!(
            journaled_quota(&signed, cap),
            Err(ExecutorError::BindingDenied),
            "{cap:?}"
        );
    }
}

#[test]
fn the_journaled_uid_comes_only_from_the_account_step() {
    use crate::durable::journaled_uid;
    assert_eq!(
        journaled_uid(&provision(&[ACCOUNT], ProvisionState::Running)),
        Some(3001)
    );
    assert_eq!(
        journaled_uid(&provision(
            &[(ProvisionStep::Account, "Account rs_blog1")],
            ProvisionState::Running
        )),
        None
    );
    assert_eq!(
        journaled_uid(&provision(&[], ProvisionState::Running)),
        None
    );
}

// ---- W535 (D-088): a signed change ----

const USED_ROW: &str = "#3001,ok,ok,200000,0,262144,0,4000,0,20000,0";
const CHANGED_ROW: &str = "#3001,ok,ok,200000,0,524288,0,4000,0,40000,0";
const RAISED: QuotaLimits = QuotaLimits {
    block_hard_kib: 524_288,
    inode_hard: 40_000,
};

#[test]
fn a_change_sets_new_limits_above_the_use_and_reads_them_back() {
    let mut host = Fake::ready(&[Ok(report(&[USED_ROW])), Ok(report(&[CHANGED_ROW]))]);
    assert_eq!(
        change(&mut host, "rs_blog1", RAISED).as_deref(),
        Ok("quota uid=3001 kib=524288 inodes=40000")
    );
    assert_eq!(host.sets(), ["set -u -- 3001 0 524288 0 40000 /srv/sites"]);
    // Read back differently: the change fails.
    let mut host = Fake::ready(&[Ok(report(&[USED_ROW])), Ok(report(&[USED_ROW]))]);
    assert_eq!(
        change(&mut host, "rs_blog1", RAISED),
        Err(ExecutorError::StepFailed)
    );
}

#[test]
fn a_change_below_the_use_or_without_a_quota_sets_nothing() {
    for (row, limits) in [
        // At or below the blocks or inodes in use.
        (
            USED_ROW,
            QuotaLimits {
                block_hard_kib: 200_000,
                inode_hard: 40_000,
            },
        ),
        (
            USED_ROW,
            QuotaLimits {
                block_hard_kib: 524_288,
                inode_hard: 4_000,
            },
        ),
        // No enforced quota for the UID.
        ("#3001,ok,ok,200000,0,0,0,4000,0,0,0", RAISED),
    ] {
        let mut host = Fake::ready(&[Ok(report(&[row]))]);
        assert_eq!(
            change(&mut host, "rs_blog1", limits),
            Err(ExecutorError::StepFailed),
            "{row} {limits:?}"
        );
        assert!(host.sets().is_empty());
    }
    // An unknown account sets nothing either.
    let mut host = Fake::ready(&[Ok(report(&[USED_ROW]))]);
    assert_eq!(
        change(&mut host, "rs_other", RAISED),
        Err(ExecutorError::StepFailed)
    );
    assert!(host.sets().is_empty());
}
