//! Read-only snapshot of the journal for display. Takes no writer lease and
//! opens the database read-only, so it never blocks or changes the executor's
//! records. It reports what is recorded, never live host state.

use rusqlite::Connection;
use rustiron_contracts::{Id, approval::AuthorityUsage};
use std::path::Path;

use crate::{JournalError, storage};

/// One recorded fixture or OLS operation (config activation or ejection).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedOperation {
    /// Durable operation id.
    pub operation_id: String,
    /// Resource the operation changed.
    pub resource_id: String,
    /// Generation the operation aimed for.
    pub target_generation: String,
    /// Recorded state, as stored.
    pub state: String,
    /// Whether the effect could have begun.
    pub effect_attempted: bool,
    /// Grant expiry, Unix seconds.
    pub expires_at: i64,
    /// Ejected site, when this operation is an ejection.
    pub ejected_site: Option<String>,
    /// W379: the site and direction (`true` opt-in, `false` opt-out) when
    /// this operation is a page-cache change (W368, W370).
    pub page_cache: Option<(String, bool)>,
}

/// One recorded site provision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedProvision {
    /// Durable operation id.
    pub operation_id: String,
    /// Site id.
    pub site_id: String,
    /// Hostname the site serves.
    pub hostname: String,
    /// `running`, `succeeded`, `quarantined` or `adopted` (W372).
    pub state: String,
    /// Completed provisioning steps out of the recorded ones.
    pub steps_done: i64,
    /// Recorded provisioning steps.
    pub steps_recorded: i64,
    /// Position of the failed step, when one is recorded. `0` is the account step.
    pub failed_step: Option<i64>,
    /// W379: the latest succeeded page-cache change for this site (`true`
    /// opted in, `false` opted out); absent when none succeeded.
    pub page_cache: Option<bool>,
    /// W395: the recipe of that latest succeeded change; absent when none
    /// succeeded.
    pub page_cache_recipe: Option<String>,
    /// W379: the journaled Directories step resource, which carries the
    /// recorded quota plan (W335). Absent when that step never began.
    pub directories_resource: Option<String>,
    /// W379: the quota limits (KiB, inodes) a re-adoption verified, for an
    /// adopted provision (W372).
    pub adopted_quota: Option<(u64, u64)>,
    /// W534 (D-088): the limits (KiB, inodes) of the newest done signed
    /// quota change; they replace the provision's or re-adoption's.
    pub changed_quota: Option<(u64, u64)>,
    /// W575 (D-095): a proxy site's distinct loopback ports, in order;
    /// empty for any other provision.
    pub proxy_ports: Vec<u16>,
    /// W591: the active (unreleased) D-075 static alias hostname of an import,
    /// when one is recorded.
    pub alias_hostname: Option<String>,
    /// W597: pinned runtime profile (`node_22_v1` or `bun_1_v1`) when this site
    /// is a P27 app site.
    pub app_runtime: Option<String>,
    /// W597: newest `done` release identifier for a P27 app site, if any.
    pub app_active_release: Option<String>,
}

/// One recorded backup capture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedCapture {
    /// Durable operation id.
    pub operation_id: String,
    /// Captured site.
    pub site_id: String,
    /// `running`, `succeeded` or `failed`.
    pub state: String,
    /// Repository snapshot id when recorded.
    pub snapshot_id: Option<String>,
    /// Start, Unix seconds.
    pub started_at: i64,
    /// Finish, Unix seconds, when recorded.
    pub finished_at: Option<i64>,
    /// Admitted recipe, or unknown if not recorded (including legacy captures).
    pub method: Option<String>,
    /// Days copied onto this capture at admission. Absent when the row predates
    /// that copy. Not proof the store kept the objects.
    pub retention_days: Option<u32>,
    /// Files the restic summary reported. Absent when not stored.
    pub files: Option<u64>,
    /// Bytes the restic summary reported. Absent when not stored.
    pub bytes: Option<u64>,
    /// Artifact manifest digest (v10). Absent when not recorded.
    pub manifest_sha256: Option<String>,
    /// Manifest entry count, when recorded.
    pub manifest_entries: Option<u64>,
    /// Sum of regular file sizes in the manifest, when recorded.
    pub manifest_regular_bytes: Option<u64>,
    /// A bound stopped the manifest listing, when recorded.
    pub manifest_truncated: Option<bool>,
    /// W379: the D-021 option E label and reason (v11, v12), as
    /// [`crate::Capture::consistency`] reads them. Absent when not checked.
    pub consistency: Option<(String, Option<String>)>,
    /// W379: on a settled `failed` capture, the snapshot kept only as
    /// unclaimed evidence (v14, W366). Never a backup of record.
    pub unclaimed_snapshot_id: Option<String>,
    /// W391 (v18): a summary of the retention evidence of a succeeded
    /// product capture. The per-object list stays in the capture receipt.
    pub retention: Option<ObservedRetention>,
    /// W391 (v18): the refusal code of a refused `failed` capture.
    pub refusal: Option<String>,
}

/// W391: the retention evidence of one capture, summarised for display.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedRetention {
    /// Bucket default COMPLIANCE days at the lock precheck.
    pub before_days: u32,
    /// Bucket default COMPLIANCE days at the lock postcheck.
    pub after_days: u32,
    /// Object versions the postcheck read back.
    pub objects: u64,
    /// The earliest retain-until time among them, Unix seconds.
    pub earliest_retain_until: i64,
    /// The latest retain-until time among them, Unix seconds.
    pub latest_retain_until: i64,
}

/// One recorded restore probe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedProbe {
    /// Durable operation id.
    pub operation_id: String,
    /// Probed site.
    pub site_id: String,
    /// Restored snapshot.
    pub snapshot_id: String,
    /// `running`, `passed`, `failed` or `cleanup_incomplete`.
    pub state: String,
    /// Start, Unix seconds.
    pub started_at: i64,
    /// Finish, Unix seconds, when recorded.
    pub finished_at: Option<i64>,
    /// The self-attested receipt JSON text, when recorded.
    pub receipt: Option<String>,
}

/// One recorded re-adoption (W372).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedReadoption {
    /// Durable operation id.
    pub operation_id: String,
    /// `site` or `generation`.
    pub form: String,
    /// The site, for the site form.
    pub site_id: Option<String>,
    /// `verifying`, `adopted` or `refused`.
    pub state: String,
    /// The archived journal's epoch the plan names (evidence only).
    pub previous_epoch: String,
    /// SHA-256 of the pre-rotation output the plan names (evidence only).
    pub evidence_sha256: String,
    /// The stable refusal code, for `refused`.
    pub refusal: Option<String>,
    /// The first failed rule, for `refused`.
    pub rule: Option<String>,
}

/// W396 (v20, D-045): the recorded intent digests of one admission and,
/// when stored, its signed bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedAdmission {
    /// Durable operation id.
    pub operation_id: String,
    /// The record kind: `operation`, `provision`, `capture`, `probe`,
    /// `readoption`, `scrub`, `certificate`, `retirement` or `update`.
    pub source: String,
    /// The intent's plan digest (`rustiron/plan/v1` framing), lowercase hex.
    pub plan_digest: String,
    /// The intent's grant digest (plain SHA-256), lowercase hex.
    pub grant_digest: String,
    /// The stored signed bytes and signer facts; absent for an admission
    /// recorded before v20.
    pub signed: Option<ObservedSigned>,
}

/// W396: the signed bytes of one admission as stored.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedSigned {
    /// The canonical plan, when within the stored bound.
    pub plan: Option<String>,
    /// Plain SHA-256 of the plan bytes.
    pub plan_sha256: String,
    /// Plan length in bytes.
    pub plan_bytes: u64,
    /// The canonical grant, when within the stored bound.
    pub grant: Option<String>,
    /// Plain SHA-256 of the grant bytes.
    pub grant_sha256: String,
    /// Grant length in bytes.
    pub grant_bytes: u64,
    /// The issuer principal the signature verified against.
    pub issuer: String,
    /// The signer-policy epoch the grant is bound to.
    pub signer_policy_epoch: String,
    /// Always `sshsig_verified`.
    pub verification: String,
}

/// Everything the journal records, in recorded order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Observation {
    /// Last recorded admission time, Unix seconds.
    pub last_time: i64,
    /// Config activations and ejections.
    pub operations: Vec<ObservedOperation>,
    /// Site provisions.
    pub provisions: Vec<ObservedProvision>,
    /// Backup captures.
    pub captures: Vec<ObservedCapture>,
    /// Restore probes.
    pub probes: Vec<ObservedProbe>,
    /// Re-adoptions (W372).
    pub readoptions: Vec<ObservedReadoption>,
    /// W396: every admission's digests and signed bytes, by kind then id.
    pub admissions: Vec<ObservedAdmission>,
    /// W464 (D-060): every site's served certificate.
    pub certificates: Vec<ObservedCertificate>,
}

/// W464 (D-060): one site's served certificate chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedCertificate {
    /// The site.
    pub site_id: String,
    /// Its hostname.
    pub hostname: String,
    /// The served chain's SHA-256.
    pub certificate_sha256: String,
    /// Its expiry, Unix seconds.
    pub not_after: u64,
    /// The last renewal attempt of the serving issuance failed.
    pub last_renewal_failed: bool,
    /// D-064: the site was ejected; Rustiron no longer renews it.
    pub ejected: bool,
}

/// Opens the journal read-only without a lease and reads every record.
/// Identity, schema and integrity are validated exactly as for the writer.
pub(crate) fn observe(
    directory: &Path,
    uid: u32,
    host: &Id,
    epoch: &Id,
) -> Result<Observation, JournalError> {
    let c = storage::open_read_only(directory, uid, host, epoch)?;
    read(&c)
}

fn observed_days(days: Option<i64>) -> rusqlite::Result<Option<u32>> {
    match days {
        None => Ok(None),
        Some(days) => match u32::try_from(days) {
            Ok(days) if (1..=3650).contains(&days) => Ok(Some(days)),
            _ => Err(rusqlite::Error::IntegralValueOutOfRange(7, days)),
        },
    }
}

fn observed_count(count: Option<i64>) -> rusqlite::Result<Option<u64>> {
    match count {
        None => Ok(None),
        Some(count) => match u64::try_from(count) {
            Ok(count) => Ok(Some(count)),
            Err(_) => Err(rusqlite::Error::IntegralValueOutOfRange(8, count)),
        },
    }
}

/// Every page-cache change (W368 opt-in, W370 opt-out) as one row source.
const PAGE_CACHE_CHANGES: &str = "SELECT operation_id, site_id, 1 AS opt_in FROM page_cache_optins \
     UNION ALL SELECT operation_id, site_id, 0 FROM page_cache_optouts";

/// W575: the comma-separated ports of a proxy site, as SQLite joined them.
fn proxy_ports(text: Option<String>) -> rusqlite::Result<Vec<u16>> {
    let Some(text) = text else {
        return Ok(Vec::new());
    };
    text.split(',')
        .map(|port| {
            port.parse::<u16>()
                .map_err(|_| rusqlite::Error::InvalidQuery)
        })
        .collect()
}

fn read(c: &Connection) -> Result<Observation, JournalError> {
    let u = storage::unavailable;
    let last_time = c
        .query_row(
            "SELECT last_time FROM metadata WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .map_err(u)?;
    let mut statement = c
        .prepare(
            "SELECT o.operation_id,o.resource_id,o.target_generation,o.state,o.effect_attempted,\
             o.expires_at,e.site_id,x.site_id,x.opt_in FROM operations o \
             LEFT JOIN ejections e ON e.operation_id=o.operation_id \
             LEFT JOIN ({PAGE_CACHE_CHANGES}) x ON x.operation_id=o.operation_id \
             ORDER BY o.rowid"
                .replace("{PAGE_CACHE_CHANGES}", PAGE_CACHE_CHANGES)
                .as_str(),
        )
        .map_err(u)?;
    let operations = statement
        .query_map([], |r| {
            let page_cache = match (r.get::<_, Option<String>>(7)?, r.get::<_, Option<i64>>(8)?) {
                (Some(site), Some(opt_in)) => Some((site, opt_in == 1)),
                _ => None,
            };
            Ok(ObservedOperation {
                operation_id: r.get(0)?,
                resource_id: r.get(1)?,
                target_generation: r.get(2)?,
                state: r.get(3)?,
                effect_attempted: r.get::<_, i64>(4)? == 1,
                expires_at: r.get(5)?,
                ejected_site: r.get(6)?,
                page_cache,
            })
        })
        .map_err(u)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(u)?;
    let mut statement = c
        .prepare(
            "SELECT p.operation_id,p.site_id,p.hostname,p.state,\
             (SELECT count(*) FROM provision_steps s WHERE s.operation_id=p.operation_id AND s.state='done'),\
             (SELECT count(*) FROM provision_steps s WHERE s.operation_id=p.operation_id), \
             (SELECT s.position FROM provision_steps s WHERE s.operation_id=p.operation_id AND s.state='failed' ORDER BY s.position LIMIT 1), \
             (SELECT x.opt_in FROM ({PAGE_CACHE_CHANGES}) x JOIN operations o ON o.operation_id=x.operation_id \
              WHERE x.site_id=p.site_id AND o.state='succeeded' ORDER BY o.rowid DESC LIMIT 1), \
             (SELECT s.resource FROM provision_steps s WHERE s.operation_id=p.operation_id AND s.position=1), \
             a.quota_kib, a.quota_inodes, \
             (SELECT COALESCE(r.recipe,'litespeed_cache_793_v1') FROM ({PAGE_CACHE_CHANGES}) x JOIN operations o ON o.operation_id=x.operation_id \
              LEFT JOIN page_cache_recipes r ON r.operation_id=x.operation_id \
              WHERE x.site_id=p.site_id AND o.state='succeeded' ORDER BY o.rowid DESC LIMIT 1), \
             (SELECT q.block_hard_kib FROM quota_changes q WHERE q.site_id=p.site_id AND q.state='done' ORDER BY q.rowid DESC LIMIT 1), \
             (SELECT q.inode_hard FROM quota_changes q WHERE q.site_id=p.site_id AND q.state='done' ORDER BY q.rowid DESC LIMIT 1), \
             (SELECT group_concat(port) FROM (SELECT DISTINCT r.port FROM proxy_routes r WHERE r.operation_id=p.operation_id ORDER BY r.port)), \
             ia.hostname, \
             ap.runtime, \
             (SELECT ar.release_id FROM app_releases ar WHERE ar.site_id=p.site_id AND ar.state='done' ORDER BY ar.rowid DESC LIMIT 1) \
             FROM provisions p LEFT JOIN provision_adoptions a ON a.operation_id=p.operation_id \
             LEFT JOIN import_aliases ia ON ia.operation_id=p.operation_id AND ia.released=0 \
             LEFT JOIN apps ap ON ap.operation_id=p.operation_id \
             ORDER BY p.rowid"
                .replace("{PAGE_CACHE_CHANGES}", PAGE_CACHE_CHANGES)
                .as_str(),
        )
        .map_err(u)?;
    let provisions = statement
        .query_map([], |r| {
            let adopted_quota = match (r.get::<_, Option<i64>>(9)?, r.get::<_, Option<i64>>(10)?) {
                (Some(kib), Some(inodes)) => Some((
                    observed_count(Some(kib))?.unwrap_or_default(),
                    observed_count(Some(inodes))?.unwrap_or_default(),
                )),
                _ => None,
            };
            // W534 (D-088): the newest done signed quota change.
            let changed_quota = match (r.get::<_, Option<i64>>(12)?, r.get::<_, Option<i64>>(13)?) {
                (Some(kib), Some(inodes)) => Some((
                    observed_count(Some(kib))?.unwrap_or_default(),
                    observed_count(Some(inodes))?.unwrap_or_default(),
                )),
                _ => None,
            };
            Ok(ObservedProvision {
                operation_id: r.get(0)?,
                site_id: r.get(1)?,
                hostname: r.get(2)?,
                state: r.get(3)?,
                steps_done: r.get(4)?,
                steps_recorded: r.get(5)?,
                failed_step: r.get(6)?,
                page_cache: r.get::<_, Option<i64>>(7)?.map(|opt_in| opt_in == 1),
                page_cache_recipe: r.get(11)?,
                directories_resource: r.get(8)?,
                adopted_quota,
                changed_quota,
                proxy_ports: proxy_ports(r.get(14)?)?,
                alias_hostname: r.get(15)?,
                app_runtime: r.get(16)?,
                app_active_release: r.get(17)?,
            })
        })
        .map_err(u)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(u)?;
    let mut statement = c
        .prepare(
            "SELECT c.operation_id,c.site_id,c.state,c.snapshot_id,c.started_at,c.finished_at,m.method,r.retention_days,e.files,e.bytes,x.manifest_sha256,x.entries,x.regular_bytes,x.truncated,\
             k.label,k.reason,f.held,n.snapshot_id,z.code,l.before_days,l.after_days,l.objects,\
             (SELECT min(retain_until) FROM capture_object_retention o WHERE o.operation_id=c.operation_id),\
             (SELECT max(retain_until) FROM capture_object_retention o WHERE o.operation_id=c.operation_id) \
             FROM captures c LEFT JOIN capture_methods m USING(operation_id) \
             LEFT JOIN capture_retention r USING(operation_id) \
             LEFT JOIN capture_extent e USING(operation_id) \
             LEFT JOIN capture_manifest x USING(operation_id) \
             LEFT JOIN capture_consistency k ON k.operation_id=c.operation_id \
             LEFT JOIN capture_freeze f ON f.operation_id=c.operation_id \
             LEFT JOIN capture_unclaimed n ON n.operation_id=c.operation_id \
             LEFT JOIN capture_refusals z ON z.operation_id=c.operation_id \
             LEFT JOIN capture_lock_checks l ON l.operation_id=c.operation_id ORDER BY c.rowid",
        )
        .map_err(u)?;
    let captures = statement
        .query_map([], |r| {
            // As `capture::find` reads it: a frozen capture whose freeze did
            // not hold has no label row and reads as `freeze_not_held`.
            let consistency = match (
                r.get::<_, Option<String>>(14)?,
                r.get::<_, Option<String>>(15)?,
                r.get::<_, Option<i64>>(16)?,
            ) {
                (Some(label), reason, _) => Some((label, reason)),
                (None, _, Some(0)) => {
                    Some(("unmatched".to_owned(), Some("freeze_not_held".to_owned())))
                }
                _ => None,
            };
            let retention = match (
                r.get::<_, Option<i64>>(19)?,
                r.get::<_, Option<i64>>(20)?,
                r.get::<_, Option<i64>>(21)?,
                r.get::<_, Option<i64>>(22)?,
                r.get::<_, Option<i64>>(23)?,
            ) {
                (Some(before), Some(after), Some(objects), Some(earliest), Some(latest)) => {
                    let invalid = |_| rusqlite::Error::InvalidQuery;
                    Some(ObservedRetention {
                        before_days: u32::try_from(before).map_err(invalid)?,
                        after_days: u32::try_from(after).map_err(invalid)?,
                        objects: u64::try_from(objects).map_err(invalid)?,
                        earliest_retain_until: earliest,
                        latest_retain_until: latest,
                    })
                }
                _ => None,
            };
            Ok(ObservedCapture {
                consistency,
                unclaimed_snapshot_id: r.get(17)?,
                refusal: r.get(18)?,
                retention,
                operation_id: r.get(0)?,
                site_id: r.get(1)?,
                state: r.get(2)?,
                snapshot_id: r.get(3)?,
                started_at: r.get(4)?,
                finished_at: r.get(5)?,
                method: r.get(6)?,
                retention_days: observed_days(r.get(7)?)?,
                files: observed_count(r.get(8)?)?,
                bytes: observed_count(r.get(9)?)?,
                manifest_sha256: r.get(10)?,
                manifest_entries: observed_count(r.get(11)?)?,
                manifest_regular_bytes: observed_count(r.get(12)?)?,
                manifest_truncated: r.get::<_, Option<i64>>(13)?.map(|t| t == 1),
            })
        })
        .map_err(u)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(u)?;
    let mut statement = c
        .prepare(
            "SELECT operation_id,site_id,snapshot_id,state,started_at,finished_at,receipt \
             FROM restore_probes ORDER BY rowid",
        )
        .map_err(u)?;
    let probes = statement
        .query_map([], |r| {
            Ok(ObservedProbe {
                operation_id: r.get(0)?,
                site_id: r.get(1)?,
                snapshot_id: r.get(2)?,
                state: r.get(3)?,
                started_at: r.get(4)?,
                finished_at: r.get(5)?,
                receipt: r.get(6)?,
            })
        })
        .map_err(u)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(u)?;
    let mut statement = c
        .prepare(
            "SELECT operation_id,form,site_id,state,previous_epoch,evidence_sha256,refusal,rule \
             FROM readoptions ORDER BY rowid",
        )
        .map_err(u)?;
    let readoptions = statement
        .query_map([], |r| {
            Ok(ObservedReadoption {
                operation_id: r.get(0)?,
                form: r.get(1)?,
                site_id: r.get(2)?,
                state: r.get(3)?,
                previous_epoch: r.get(4)?,
                evidence_sha256: r.get(5)?,
                refusal: r.get(6)?,
                rule: r.get(7)?,
            })
        })
        .map_err(u)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(u)?;
    let admissions = admissions(c)?;
    let certificates = crate::certificate::observed(c)?;
    Ok(Observation {
        last_time,
        operations,
        provisions,
        captures,
        probes,
        readoptions,
        admissions,
        certificates,
    })
}

/// P23 (D-098): reads durable authority consumption directly from SQLite.
/// `window_start` is Unix seconds; rows active after `window_start` count
/// toward the rolling-window ceilings.
pub(crate) fn authority_usage(
    c: &Connection,
    window_start: i64,
) -> Result<AuthorityUsage, JournalError> {
    let u = storage::unavailable;
    let total_admissions: i64 = c
        .query_row(
            &format!("SELECT count(*) FROM ({}) i", crate::signed::INTENTS),
            [],
            |row| row.get(0),
        )
        .map_err(u)?;
    let total_ols_reloads: i64 = c
        .query_row("SELECT count(*) FROM operations", [], |row| row.get(0))
        .map_err(u)?;
    let recent_ols_reloads: i64 = c
        .query_row(
            "SELECT count(*) FROM operations WHERE expires_at > ?1",
            [window_start],
            |row| row.get(0),
        )
        .map_err(u)?;
    let recent_admissions: i64 = c
        .query_row(
            "SELECT \
             (SELECT count(*) FROM operations WHERE expires_at > ?1) + \
             (SELECT count(*) FROM provisions WHERE state<>'adopted' AND expires_at > ?1) + \
             (SELECT count(*) FROM captures WHERE started_at >= ?1) + \
             (SELECT count(*) FROM restore_probes WHERE started_at >= ?1) + \
             (SELECT count(*) FROM readoptions WHERE expires_at > ?1) + \
             (SELECT count(*) FROM import_scrubs WHERE origin='signed' AND expires_at > ?1) + \
             (SELECT count(*) FROM certificates WHERE expires_at > ?1) + \
             (SELECT count(*) FROM retirements WHERE expires_at > ?1) + \
             (SELECT count(*) FROM updates WHERE expires_at > ?1) + \
             (SELECT count(*) FROM deletions WHERE expires_at > ?1) + \
             (SELECT count(*) FROM quota_changes WHERE expires_at > ?1) + \
             (SELECT count(*) FROM clone_scrub_grants WHERE expires_at > ?1) + \
             (SELECT count(*) FROM site_restores WHERE expires_at > ?1) + \
             (SELECT count(*) FROM dns_imports WHERE expires_at > ?1) + \
             (SELECT count(*) FROM dns_changes WHERE expires_at > ?1) + \
             (SELECT count(*) FROM app_releases WHERE expires_at > ?1) + \
             (SELECT count(*) FROM app_lifecycles WHERE expires_at > ?1) + \
             (SELECT count(*) FROM credential_rotations WHERE expires_at > ?1)",
            [window_start],
            |row| row.get(0),
        )
        .map_err(u)?;
    let served_sites: i64 = c
        .query_row(
            "SELECT count(*) FROM provisions p WHERE p.state IN ('succeeded','adopted') \
             AND NOT EXISTS (SELECT 1 FROM ejections e JOIN operations o ON o.operation_id=e.operation_id \
             WHERE e.site_id=p.site_id AND o.state='succeeded')",
            [],
            |row| row.get(0),
        )
        .map_err(u)?;
    let as_u64 = |v: i64| u64::try_from(v).map_err(storage::unavailable);
    Ok(AuthorityUsage {
        total_admissions: as_u64(total_admissions)?,
        total_ols_reloads: as_u64(total_ols_reloads)?,
        recent_admissions: as_u64(recent_admissions)?,
        recent_ols_reloads: as_u64(recent_ols_reloads)?,
        served_sites: as_u64(served_sites)?,
    })
}

pub(crate) fn observe_authority_usage(
    directory: &Path,
    uid: u32,
    host: &Id,
    epoch: &Id,
    window_start: i64,
) -> Result<AuthorityUsage, JournalError> {
    let c = storage::open_read_only(directory, uid, host, epoch)?;
    authority_usage(&c, window_start)
}

fn admissions(c: &Connection) -> Result<Vec<ObservedAdmission>, JournalError> {
    let u = storage::unavailable;
    let mut statement = c
        .prepare(&format!(
            "SELECT i.operation_id,i.source,i.plan_digest,i.grant_digest,a.plan_sha256,a.plan_bytes,p.canonical,\
             a.grant_sha256,a.grant_bytes,g.canonical,a.issuer,a.signer_policy_epoch,a.verification \
             FROM ({}) i LEFT JOIN admission_signatures a ON a.operation_id=i.operation_id \
             LEFT JOIN signed_objects p ON p.sha256=a.plan_sha256 \
             LEFT JOIN signed_objects g ON g.sha256=a.grant_sha256 ORDER BY i.source, i.operation_id",
            crate::signed::INTENTS
        ))
        .map_err(u)?;
    statement
        .query_map([], |r| {
            let length = |index| {
                r.get::<_, i64>(index).and_then(|value| {
                    u64::try_from(value)
                        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
                })
            };
            let signed = match r.get::<_, Option<String>>(4)? {
                None => None,
                Some(plan_sha256) => Some(ObservedSigned {
                    plan_sha256,
                    plan_bytes: length(5)?,
                    plan: r.get(6)?,
                    grant_sha256: r.get(7)?,
                    grant_bytes: length(8)?,
                    grant: r.get(9)?,
                    issuer: r.get(10)?,
                    signer_policy_epoch: r.get(11)?,
                    verification: r.get(12)?,
                }),
            };
            Ok(ObservedAdmission {
                operation_id: r.get(0)?,
                source: r.get(1)?,
                plan_digest: r.get(2)?,
                grant_digest: r.get(3)?,
                signed,
            })
        })
        .map_err(u)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(u)
}
