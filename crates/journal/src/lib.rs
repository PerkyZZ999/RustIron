//! Unprivileged fixture intent/replay storage. No signature authority or effects.
//!
//! The future executor must independently verify authorization, ownership, time
//! and live preconditions before using a real authoritative journal. Caller
//! reports to this fixture library are not proof that those checks happened.

use rusqlite::{Connection, OptionalExtension, params};
use rustiron_contracts::{
    Id, Timestamp,
    approval::{Sha256Digest, SiteId},
};
use std::{fs::File, path::Path};

mod app;
mod capture;
mod certificate;
mod credential_rotate;
mod delete;
mod dns;
mod import;
mod observe;
mod probe;
mod provision;
mod proxy;
mod quota_change;
mod readopt;
mod retire;
mod signed;
mod site_clone;
mod site_restore;
mod site_update;
mod storage;

pub use app::{
    APP_MIGRATION_CAPTURE_MAX_AGE_SECONDS, AppFacts, AppLifecycle, AppLifecycleIntent,
    AppLifecycleResult, AppRelease, AppReleaseIntent, AppReleaseResult, AppReleaseState,
    AppReleaseStep, AppReleaseStepRecord,
};
pub use capture::{
    Capture, CaptureConsistency, CaptureIntent, CaptureManifest, CaptureMethod, CaptureResult,
    CaptureState, CaptureSuccess, MAX_LOCK_DAYS, MAX_MANIFEST_ENTRIES, MAX_RETAINED_OBJECTS,
    ObjectRetention, RETENTION_MODE, RetainedObjectKind, RetentionEvidence, UnmatchedReason,
    refusal_code_ok, version_id_ok,
};
pub use observe::{
    Observation, ObservedAdmission, ObservedCapture, ObservedCertificate, ObservedOperation,
    ObservedProbe, ObservedProvision, ObservedReadoption, ObservedRetention, ObservedSigned,
};
pub use signed::{MAX_OBJECT_BYTES, NAMESPACE as PLAN_NAMESPACE, SignedAdmission, VERIFICATION};
/// Records one operation id names, read without a lease.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OperationRecords {
    /// The provision with this id, if any.
    pub provision: Option<Provision>,
    /// W446: for an import provision, its facts and import steps.
    pub import: Option<Import>,
    /// W499: for a clone provision, its source facts and clone steps.
    pub site_clone: Option<SiteClone>,
    /// W572: for a proxy site provision, its signed routes (D-095).
    pub proxy: Option<ProxyFacts>,
    /// W597: for a modern app site provision, its signed runtime facts (D-099).
    pub app: Option<AppFacts>,
    /// W597: for an `app_deploy` operation, its release record and steps (D-099).
    pub app_release: Option<AppRelease>,
    /// W598: newest `done` release ID of that app site prior to this deploy, for rollback.
    pub app_previous_release_id: Option<String>,
    /// W597: for an `app_lifecycle` operation, its unit action record (D-099).
    pub app_lifecycle: Option<AppLifecycle>,
    /// W608: for a `site_credential_rotate` operation, its rotation record (D-100).
    pub credential_rotation: Option<CredentialRotation>,
    /// W508: for a provision, its retirement (D-080), if recorded.
    pub retirement: Option<Retirement>,
    /// W521: for a provision, its latest deletion (D-085), if recorded.
    pub deletion: Option<Deletion>,
    /// W535: for a provision, its site's open quota change (D-088), if any.
    pub quota_change: Option<QuotaChange>,
    /// W514: the update with this operation (D-084), if any.
    pub site_update: Option<SiteUpdate>,
    /// W542: the restore with this operation (D-089), if any.
    pub site_restore: Option<SiteRestore>,
    /// W563: the zone import with this operation (D-091), if any.
    pub dns_import: Option<DnsImport>,
    /// W565: the record change with this operation (D-091), if any.
    pub dns_change: Option<DnsChange>,
    /// W565: that change's signed plan bytes, checked against its digest.
    pub dns_change_plan: Option<Vec<u8>>,
    /// The probe with this id, if any.
    pub probe: Option<Probe>,
    /// The capture with this id, if any.
    pub capture: Option<Capture>,
    /// For a probe: the provision of the site it restores, if any.
    pub probe_source: Option<Provision>,
    /// The OLS activation or ejection with this id, if any (W200).
    pub operation: Option<Operation>,
    /// For an OLS operation or a re-adoption: every owned provision
    /// (succeeded or adopted), by site id.
    pub served: Vec<Provision>,
    /// Static aliases of the owned provisions used for an OLS operation.
    pub served_aliases: std::collections::BTreeMap<String, rustiron_contracts::approval::Hostname>,
    /// W572: routes of the owned proxy sites used for an OLS operation, by
    /// site id.
    pub served_proxies: std::collections::BTreeMap<String, ProxyFacts>,
    /// For an OLS operation: sites whose ejection succeeded, by site id,
    /// plus the site this operation ejects, if it is an ejection.
    pub ejected: Vec<SiteId>,
    /// For an OLS operation: the site it ejects, if it is an ejection (W387).
    pub ejection: Option<SiteId>,
    /// For an OLS operation: the exact hostname recorded for a single-name
    /// static ejection (D-097).
    pub static_ejection: Option<rustiron_contracts::approval::Hostname>,
    /// For an OLS operation: what the journal established for its resource
    /// before it (W355 bootstrap activation, W360 rule).
    pub ols_history: Option<ResourceHistory>,
    /// For an OLS operation: the site it opts in to the page cache, if it is
    /// a `config_activate` v2 (W368).
    pub page_cache: Option<SiteId>,
    /// For an OLS operation: the site it opts out of the page cache, if it
    /// is a `config_activate` v3 (W370).
    pub page_cache_opt_out: Option<SiteId>,
    /// For an OLS operation: the recipe of its page-cache opt-in or opt-out,
    /// if it is one (W395): `litespeed_cache_793_v1` or
    /// `litespeed_cache_793_cache_on_v1`.
    pub page_cache_recipe: Option<&'static str>,
    /// The re-adoption with this id, if any (W372).
    pub readoption: Option<Readoption>,
    /// The adopted OLS generation, if the journal holds one (W372).
    pub ols_adoption: Option<(Id, Sha256Digest)>,
    /// The certificate issuance with this id, if any (W462).
    pub certificate: Option<Certificate>,
    /// For an OLS operation or a certificate issuance: every site's latest
    /// installed chain digest (D-060), which its `live` link must name.
    pub certificates: Vec<(SiteId, Sha256Digest)>,
    /// Exact installed SAN pairs, by site, for live TLS verification.
    pub certificate_pairs: Vec<(SiteId, rustiron_contracts::approval::Hostname, Sha256Digest)>,
    /// The certificate renewal with this id, if any (W464).
    pub renewal: Option<Renewal>,
}

/// What the journal holds for one resource before a point in its history
/// (W355). The bootstrap activation of a fresh host requires that no earlier
/// operation established a real generation.
///
/// W360: only a verified activation (`succeeded`) establishes a generation.
/// An operation that ended without effect (`untouched`) or was compensated
/// (`failed_compensated`) re-establishes nothing of its own: its predecessor
/// is the plan's claim, and a refusal after intent records it without a
/// verified observation. Such an operation keeps what was established
/// before it, and from an empty history it can re-establish only the
/// caller's baseline (the empty OLS bootstrap generation).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceHistory {
    /// The journal established nothing for the resource: no operation is
    /// recorded, or every finished one ended without a verified activation
    /// over a predecessor other than the baseline.
    Empty,
    /// This generation is established: the target of the latest succeeded
    /// operation, or the baseline re-established from an empty history.
    Established(Id, Sha256Digest),
    /// The latest operation is unresolved, so nothing is established.
    Unresolved,
}

/// The history of `resource_id` before `before` (that operation excluded),
/// or of the whole resource. An unknown `before` is a conflict, never an
/// empty history. `baseline` is the generation the resource holds before any
/// operation, when the caller knows one; see [`ResourceHistory`].
fn resource_history(
    connection: &Connection,
    resource_id: &Id,
    before: Option<&Id>,
    baseline: Option<&(Id, Sha256Digest)>,
) -> Result<ResourceHistory, JournalError> {
    let limit = match before {
        Some(operation) => connection
            .query_row(
                "SELECT rowid FROM operations WHERE operation_id=?1 AND resource_id=?2",
                [operation.as_str(), resource_id.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(storage::unavailable)?
            .ok_or(JournalError::Conflict)?,
        None => i64::MAX,
    };
    let mut statement = connection
        .prepare(
            "SELECT operation_id FROM operations WHERE resource_id=?1 AND rowid<?2 ORDER BY rowid DESC",
        )
        .map_err(storage::unavailable)?;
    let ids = statement
        .query_map(params![resource_id.as_str(), limit], |row| {
            row.get::<_, String>(0)
        })
        .map_err(storage::unavailable)?;
    // Newest first: the first succeeded or unresolved operation decides.
    // Every later one ended without effect or was compensated, so it keeps
    // that result; it only records whether it found the baseline.
    let mut restores_baseline = false;
    for id in ids {
        let id = Id::try_from(id.map_err(storage::unavailable)?).map_err(storage::unavailable)?;
        let operation = storage::by_operation(connection, &id)?.ok_or(JournalError::Unavailable)?;
        let intent = operation.intent;
        match operation.state {
            RecordedState::Succeeded => {
                return Ok(ResourceHistory::Established(
                    intent.target_generation,
                    intent.target_digest,
                ));
            }
            RecordedState::Intent | RecordedState::NeedsAttention | RecordedState::Compensating => {
                return Ok(ResourceHistory::Unresolved);
            }
            RecordedState::Untouched | RecordedState::FailedCompensated => {
                restores_baseline |= baseline.is_some_and(|(generation, digest)| {
                    &intent.predecessor_generation == generation
                        && &intent.predecessor_digest == digest
                });
            }
        }
    }
    Ok(match baseline {
        Some((generation, digest)) if restores_baseline => {
            ResourceHistory::Established(generation.clone(), digest.clone())
        }
        _ => ResourceHistory::Empty,
    })
}

pub use certificate::{
    Certificate, CertificateIntent, CertificateResult, CertificateState, RENEW_BEFORE_SECONDS,
    RENEW_RETRY_SECONDS, Renewal, RenewalTarget,
};
pub use credential_rotate::{
    CredentialRotateIntent, CredentialRotateResult, CredentialRotateState, CredentialRotation,
};
pub use delete::{DELETE_CAPTURE_MAX_AGE_SECONDS, DeleteIntent, DeleteResult, Deletion};
pub use dns::{
    DnsChange, DnsChangeIntent, DnsChangeResult, DnsChangeSet, DnsImport, DnsImportIntent,
    DnsImportResult,
};
pub use import::{
    Import, ImportFacts, ImportScrub, ImportStep, ImportStepRecord, ScrubIntent, ScrubOrigin,
    ScrubResult,
};
pub use probe::{Probe, ProbeIntent, ProbeResult, ProbeState};
pub use provision::{
    Provision, ProvisionIntent, ProvisionResult, ProvisionState, ProvisionStep, StepRecord,
    StepState,
};
pub use proxy::ProxyFacts;
pub use quota_change::{QuotaChange, QuotaChangeIntent, QuotaChangeResult};
pub use readopt::{
    ReadoptOutcome, ReadoptResult, ReadoptState, Readoption, ReadoptionIntent, SiteAdoption,
};
pub use retire::{RetireIntent, RetireResult, Retirement};
pub use site_clone::{
    CloneFacts, CloneScrubGrant, CloneScrubIntent, CloneScrubResult, CloneStep, CloneStepRecord,
    SiteClone,
};
pub use site_restore::{
    MAX_RESTORE_ATTEMPTS, RESTORE_SAFETY_MAX_AGE_SECONDS, RestoreAttempt, RestoreFrom,
    RestoreIntent, RestoreResult, RestoreState, RestoreStep, RestoreStepRecord, SiteRestore,
};
pub use site_update::{
    SiteUpdate, UPDATE_CAPTURE_MAX_AGE_SECONDS, UpdateIntent, UpdateResult, UpdateState,
    UpdateStep, UpdateStepRecord,
};

/// Ordinary non-root operator; the original fixture rule.
fn operator_owner() -> Result<u32, JournalError> {
    rustiron_contracts::local::operator_uid().map_err(|_| JournalError::AccessDenied)
}

/// The real process identity (root allowed), never a setuid/setgid mixture.
fn process_owner() -> Result<u32, JournalError> {
    let (uid, euid) = (rustix::process::getuid(), rustix::process::geteuid());
    let (gid, egid) = (rustix::process::getgid(), rustix::process::getegid());
    if uid != euid || gid != egid {
        return Err(JournalError::AccessDenied);
    }
    Ok(uid.as_raw())
}

/// Redacted fixture ledger outcomes, never caller SQL or parser details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalError {
    /// Missing, corrupt, unknown-schema or unusable native/storage dependency.
    Unavailable,
    /// Directory/file identity, mode, links or sole-writer lease is unsuitable.
    AccessDenied,
    /// Immutable binding, host epoch, replay identity or observation conflicts.
    Conflict,
    /// One unresolved operation already blocks mutation admission.
    Busy,
    /// Reliable supplied time moved backwards since the last recorded intent.
    ClockRollback,
    /// A new intent cannot begin at or after normal grant expiry.
    Expired,
    /// The bounded fixture history is full; never prune replay history silently.
    Capacity,
    /// A new provision names a site id or hostname an earlier provision
    /// consumed (W190); not a replay of that provision.
    Consumed,
    /// D-078: a clone's signed source is no longer the recorded, complete
    /// capture of a served native site.
    SourceChanged,
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str(match self {
            Self::Unavailable => "fixture journal unavailable; preserve state for diagnosis",
            Self::AccessDenied => "fixture journal ownership, permissions or writer lease refused",
            Self::Conflict => "fixture journal immutable bindings conflict",
            Self::Busy => "unresolved fixture intent blocks new work",
            Self::ClockRollback => "fixture clock rollback blocks new work",
            Self::Expired => "fixture grant expired before new intent",
            Self::Capacity => "fixture replay history reached its bound",
            Self::Consumed => "site id or hostname already consumed by a provision",
            Self::SourceChanged => "clone source no longer matches its recorded capture",
        })
    }
}
impl std::error::Error for JournalError {}

/// Complete storage binding supplied by a future independently validating caller.
/// This is fixture data, not a capability or a verified signed grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Intent {
    /// Stable operation identity.
    pub operation_id: Id,
    /// Exact retry key, bound to every immutable field below.
    pub idempotency_key: Id,
    /// Signed grant identity.
    pub grant_id: Id,
    /// Single-use signed nonce.
    pub nonce: Id,
    /// Complete canonical plan digest.
    pub plan_digest: Sha256Digest,
    /// Complete canonical grant payload SHA-256.
    pub grant_digest: Sha256Digest,
    /// Independent enrolled host identity (fixture claim here).
    pub host_id: Id,
    /// Independent enrolled host/recovery epoch (fixture claim here).
    pub host_epoch: Id,
    /// Sole affected fixture resource.
    pub resource_id: Id,
    /// Independently observed predecessor generation (fixture claim here).
    pub predecessor_generation: Id,
    /// Independently observed predecessor bytes (fixture claim here).
    pub predecessor_digest: Sha256Digest,
    /// Bound candidate generation.
    pub target_generation: Id,
    /// Bound candidate content hash.
    pub target_digest: Sha256Digest,
    /// Normal grant deadline; storage never extends authority.
    pub expires_at: Timestamp,
    /// Signed deadline for the single restore-to-predecessor compensation.
    pub compensation_valid_until: Timestamp,
}

/// Durable recorded state; a caller report is not independent verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordedState {
    /// Effect may have happened; do not retry automatically.
    Intent,
    /// Caller reported complete matching target generation and hash.
    Succeeded,
    /// Caller reported complete matching predecessor generation and hash.
    Untouched,
    /// Reality is not established; resource remains blocked.
    NeedsAttention,
    /// The one compensation attempt is recorded; its effect may have happened.
    Compensating,
    /// Compensation restored the complete predecessor; the step itself failed.
    FailedCompensated,
}

impl RecordedState {
    /// States that block new work on the fixture.
    pub fn is_unresolved(self) -> bool {
        matches!(
            self,
            Self::Intent | Self::NeedsAttention | Self::Compensating
        )
    }

    fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Untouched | Self::FailedCompensated
        )
    }
}

/// Stored immutable binding plus current reported observation state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Operation {
    /// Immutable admitted fixture data.
    pub intent: Intent,
    /// Current recorded state, never inferred from daemon restart.
    pub state: RecordedState,
    /// Durable mark written before the effect could begin.
    pub effect_attempted: bool,
    /// Whether the single compensation attempt has been recorded.
    pub compensation_attempted: bool,
}

/// Distinguishes a new durable intent from status-only exact replay.
#[derive(Debug, Eq, PartialEq)]
pub enum RecordResult {
    /// Intent transaction committed. Still not permission to execute a host effect.
    New(Operation),
    /// Existing status only, including after expiry; never retry an effect from this.
    Existing(Operation),
}

/// Process-locked fixture ledger. `initialize`/`open` refuse root; only the
/// `*_as_process_owner` constructors used by the executor accept a root owner.
pub struct FixtureJournal {
    connection: Connection,
    _lease: File,
    host_id: Id,
    host_epoch: Id,
    /// W396: the signed inputs of the next admission (see [`SignedAdmission`]).
    staged: Option<SignedAdmission>,
}

/// Effective connection settings, not a physical disk durability attestation.
#[derive(Debug)]
pub struct JournalSettings {
    /// Must be delete for the reviewed rollback-journal profile.
    pub journal_mode: String,
    /// Must be EXTRA=3.
    pub synchronous: i64,
    /// Effective foreign-key enforcement.
    pub foreign_keys: bool,
    /// Must be false for untrusted schema execution.
    pub trusted_schema: bool,
}

impl FixtureJournal {
    /// Number of admitted records of every kind (fixture/OLS/eject
    /// operations, provisions, captures, restore probes, re-adoptions, and
    /// W459 signed import scrubs, W462 certificates). Each
    /// admission inserts exactly one such row and no row is ever deleted, so
    /// the count only grows within an epoch: an older copy of this journal
    /// has a smaller count. The executor fences it against an external mark.
    /// W372: an `adopted` provision row belongs to its re-adoption's
    /// admission and is not counted again.
    pub fn admission_count(&self) -> Result<u64, JournalError> {
        let count: i64 = self
            .connection
            .query_row(
                "SELECT (SELECT count(*) FROM operations) + (SELECT count(*) FROM provisions WHERE state<>'adopted') \
                 + (SELECT count(*) FROM captures) + (SELECT count(*) FROM restore_probes) \
                 + (SELECT count(*) FROM readoptions) \
                 + (SELECT count(*) FROM import_scrubs WHERE origin='signed') \
                 + (SELECT count(*) FROM certificates) + (SELECT count(*) FROM retirements) \
                 + (SELECT count(*) FROM updates) + (SELECT count(*) FROM deletions) \
                 + (SELECT count(*) FROM quota_changes) + (SELECT count(*) FROM clone_scrub_grants) \
                 + (SELECT count(*) FROM site_restores) + (SELECT count(*) FROM dns_imports) \
                 + (SELECT count(*) FROM dns_changes) + (SELECT count(*) FROM app_releases) \
                 + (SELECT count(*) FROM app_lifecycles) \
                 + (SELECT count(*) FROM credential_rotations)",
                [],
                |row| row.get(0),
            )
            .map_err(storage::unavailable)?;
        u64::try_from(count).map_err(storage::unavailable)
    }

    /// Returns actual connection PRAGMA values for evidence and diagnostics.
    pub fn settings(&self) -> Result<JournalSettings, JournalError> {
        let read = |name| {
            self.connection
                .pragma_query_value::<i64, _>(None, name, |row| row.get(0))
                .map_err(storage::unavailable)
        };
        Ok(JournalSettings {
            journal_mode: self
                .connection
                .pragma_query_value(None, "journal_mode", |row| row.get(0))
                .map_err(storage::unavailable)?,
            synchronous: read("synchronous")?,
            foreign_keys: read("foreign_keys")? == 1,
            trusted_schema: read("trusted_schema")? != 0,
        })
    }
    /// Explicit empty-fixture initialization; never repair/recreate existing history.
    pub fn initialize(directory: &Path, host_id: Id, host_epoch: Id) -> Result<Self, JournalError> {
        Self::initialize_owned(directory, host_id, host_epoch, operator_owner()?)
    }

    /// Opens only valid existing fixture state with the independently expected identity.
    pub fn open(directory: &Path, host_id: Id, host_epoch: Id) -> Result<Self, JournalError> {
        Self::open_owned(directory, host_id, host_epoch, operator_owner()?)
    }

    /// Executor-only initialization owned by the current process identity, root
    /// included. The caller must first verify descriptor-safe ancestry of
    /// `directory`; no caller-chosen UID exists, and setuid processes are refused.
    pub fn initialize_as_process_owner(
        directory: &Path,
        host_id: Id,
        host_epoch: Id,
    ) -> Result<Self, JournalError> {
        Self::initialize_owned(directory, host_id, host_epoch, process_owner()?)
    }

    /// Executor-only open of existing state owned by the current process identity.
    /// Same preconditions as [`Self::initialize_as_process_owner`].
    pub fn open_as_process_owner(
        directory: &Path,
        host_id: Id,
        host_epoch: Id,
    ) -> Result<Self, JournalError> {
        Self::open_owned(directory, host_id, host_epoch, process_owner()?)
    }

    /// Reads an existing journal under the same exclusive lease as the
    /// writer. The caller validates directory ancestry as for
    /// `open_as_process_owner`. Neither the connection nor the lock file
    /// can be written through this handle.
    pub fn with_exclusive_read_as_process_owner<T>(
        directory: &Path,
        host_id: &Id,
        host_epoch: &Id,
        read: impl FnOnce(&Self) -> T,
    ) -> Result<T, JournalError> {
        let owner = process_owner()?;
        let lease = storage::open_files(directory, owner)?;
        let connection = storage::open_read_only(directory, owner, host_id, host_epoch)?;
        let journal = Self {
            connection,
            _lease: lease,
            host_id: host_id.clone(),
            host_epoch: host_epoch.clone(),
            staged: None,
        };
        Ok(read(&journal))
    }

    /// Executor-only read-only snapshot of every record, owned by the current
    /// process identity. Takes no writer lease, so it runs beside a serving
    /// executor and never changes state. Same preconditions as
    /// [`Self::open_as_process_owner`].
    pub fn observe_as_process_owner(
        directory: &Path,
        host_id: &Id,
        host_epoch: &Id,
    ) -> Result<Observation, JournalError> {
        observe::observe(directory, process_owner()?, host_id, host_epoch)
    }

    /// P23 (D-098): read-only durable authority consumption snapshot for
    /// `Executor::observe`. Takes no writer lease.
    pub fn observe_authority_usage_as_process_owner(
        directory: &Path,
        host_id: &Id,
        host_epoch: &Id,
        window_start: i64,
    ) -> Result<rustiron_contracts::approval::AuthorityUsage, JournalError> {
        observe::observe_authority_usage(
            directory,
            process_owner()?,
            host_id,
            host_epoch,
            window_start,
        )
    }

    /// Executor-only read-only lookup of one operation's provision, probe and
    /// capture records for the administration helper. Takes no writer lease and
    /// never changes state. Same preconditions as [`Self::open_as_process_owner`].
    /// `ols_baseline` is the baseline of the operation's resource history.
    pub fn records_as_process_owner(
        directory: &Path,
        host_id: &Id,
        host_epoch: &Id,
        operation_id: &Id,
        ols_baseline: Option<&(Id, Sha256Digest)>,
    ) -> Result<OperationRecords, JournalError> {
        let c = storage::open_read_only(directory, process_owner()?, host_id, host_epoch)?;
        let probe = probe::find(&c, "operation_id", operation_id.as_str())?;
        let probe_source = match &probe {
            Some(probe) => provision::by_site(&c, &probe.intent.site_id)?,
            None => None,
        };
        let operation = storage::by_operation(&c, operation_id)?;
        // W372: a generation adoption replaces the caller's OLS baseline.
        let ols_adoption = readopt::ols_adoption(&c)?;
        let ols_baseline = ols_adoption.as_ref().or(ols_baseline);
        let ols_history = match &operation {
            Some(operation) => Some(resource_history(
                &c,
                &operation.intent.resource_id,
                Some(operation_id),
                ols_baseline,
            )?),
            None => None,
        };
        let readoption = readopt::by_operation(&c, operation_id)?;
        // W518-F3: an update's steps need its site's served provision.
        let site_update = site_update::load(&c, operation_id)?;
        let site_restore = site_restore::load(&c, operation_id)?;
        let credential_rotation = credential_rotate::by_operation(&c, operation_id)?;
        let mut ejection = None;
        let mut static_ejection = None;
        let (served, ejected) = match &operation {
            Some(_) => {
                let mut ejected = provision::ejected(&c)?;
                let own = c
                    .query_row(
                        "SELECT site_id FROM ejections WHERE operation_id=?1",
                        [operation_id.as_str()],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()
                    .map_err(storage::unavailable)?;
                if let Some(own) = own {
                    let own = SiteId::try_from(own).map_err(storage::unavailable)?;
                    if !ejected.contains(&own) {
                        ejected.push(own.clone());
                    }
                    ejection = Some(own);
                    static_ejection = provision::static_ejection_of(&c, operation_id)?;
                }
                (provision::succeeded(&c)?, ejected)
            }
            None if readoption.is_some()
                || site_update.is_some()
                || site_restore.is_some()
                || credential_rotation.is_some() =>
            {
                (provision::succeeded(&c)?, provision::ejected(&c)?)
            }
            None => (Vec::new(), Vec::new()),
        };
        let (page_cache, page_cache_opt_out, page_cache_recipe) = match &operation {
            Some(_) => (
                provision::page_cache_site(&c, operation_id)?,
                provision::page_cache_opt_out_site(&c, operation_id)?,
                provision::page_cache_recipe(&c, operation_id)?,
            ),
            None => (None, None, None),
        };
        let certificate = certificate::by_operation(&c, (host_id, host_epoch), operation_id)?;
        let renewal = certificate::renewal(&c, (host_id, host_epoch), operation_id)?;
        let certificates = if operation.is_some() || certificate.is_some() || renewal.is_some() {
            certificate::installed_by_site(&c)?
        } else {
            Vec::new()
        };
        let certificate_pairs = if operation.is_some() {
            certificate::installed_pairs(&c)?
        } else {
            Vec::new()
        };
        let mut served_aliases = std::collections::BTreeMap::new();
        let mut served_proxies = std::collections::BTreeMap::new();
        for provision in &served {
            if let Some(alias) = import::alias_of(&c, &provision.intent.operation_id)? {
                served_aliases.insert(provision.intent.site_id.as_str().to_owned(), alias);
            }
            if let Some(routes) = proxy::facts(&c, &provision.intent.operation_id)? {
                served_proxies.insert(provision.intent.site_id.as_str().to_owned(), routes);
            }
        }
        let capture = capture::find(&c, "operation_id", operation_id.as_str())?;
        let app_release = app::load_release(&c, operation_id)?;
        let app_lifecycle = app::load_lifecycle(&c, operation_id)?;
        let app_for_op = if let Some(found) = app::facts(&c, operation_id)? {
            Some(found)
        } else if let Some(rel) = &app_release {
            app::facts_by_site(&c, &rel.site_id)?
        } else if let Some(lc) = &app_lifecycle {
            app::facts_by_site(&c, &lc.site_id)?
        } else if let Some(cap) = &capture {
            app::facts_by_site(&c, &cap.intent.site_id)?
        } else if let Some(rest) = &site_restore {
            app::facts_by_site(&c, &rest.site_id)?
        } else {
            None
        };
        let app_previous_release_id = match &app_release {
            Some(rel) => c
                .query_row(
                    "SELECT release_id FROM app_releases WHERE site_id=?1 AND state='done' \
                     AND operation_id<>?2 ORDER BY rowid DESC LIMIT 1",
                    params![rel.site_id.as_str(), operation_id.as_str()],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(storage::unavailable)?,
            None => None,
        };
        Ok(OperationRecords {
            renewal,
            certificate,
            certificates,
            certificate_pairs,
            readoption,
            ols_adoption,
            page_cache,
            page_cache_opt_out,
            page_cache_recipe,
            provision: provision::by_operation(&c, operation_id)?,
            import: import::load(&c, operation_id)?,
            site_clone: site_clone::load(&c, operation_id)?,
            proxy: proxy::facts(&c, operation_id)?,
            app: app_for_op,
            app_release,
            app_previous_release_id,
            app_lifecycle,
            credential_rotation,
            retirement: retire::of_provision(&c, operation_id)?,
            deletion: delete::of_provision(&c, operation_id)?,
            quota_change: match provision::by_operation(&c, operation_id)? {
                Some(provision) => {
                    quota_change::open_for_site(&c, provision.intent.site_id.as_str())?
                }
                None => None,
            },
            site_update,
            site_restore,
            dns_import: dns::import_by_operation(&c, operation_id)?,
            dns_change: dns::change_by_operation(&c, operation_id)?,
            dns_change_plan: dns::change_plan(&c, operation_id)?,
            probe,
            capture,
            probe_source,
            operation,
            served,
            served_aliases,
            served_proxies,
            ejected,
            ejection,
            static_ejection,
            ols_history,
        })
    }

    /// Test-only read-only snapshot owned by the operator account (as [`Self::open`]).
    pub fn observe(
        directory: &Path,
        host_id: &Id,
        host_epoch: &Id,
    ) -> Result<Observation, JournalError> {
        observe::observe(directory, operator_owner()?, host_id, host_epoch)
    }

    /// Executor-only one-way migration from a supported older journal,
    /// owned by the current process identity (same preconditions as
    /// [`Self::open_as_process_owner`]). Takes the writer lease first.
    pub fn migrate_as_process_owner(
        directory: &Path,
        host_id: Id,
        host_epoch: Id,
    ) -> Result<Self, JournalError> {
        let lease = storage::open_files(directory, process_owner()?)?;
        let connection = storage::migrate(directory, &host_id, &host_epoch)?;
        Ok(Self {
            connection,
            _lease: lease,
            host_id,
            host_epoch,
            staged: None,
        })
    }

    /// Test-only migration owned by the operator account (as [`Self::open`]).
    pub fn migrate(directory: &Path, host_id: Id, host_epoch: Id) -> Result<Self, JournalError> {
        let lease = storage::open_files(directory, operator_owner()?)?;
        let connection = storage::migrate(directory, &host_id, &host_epoch)?;
        Ok(Self {
            connection,
            _lease: lease,
            host_id,
            host_epoch,
            staged: None,
        })
    }

    fn initialize_owned(
        directory: &Path,
        host_id: Id,
        host_epoch: Id,
        owner: u32,
    ) -> Result<Self, JournalError> {
        let lease = storage::initialize_files(directory, owner)?;
        let connection = storage::initialize(directory, &host_id, &host_epoch)?;
        Ok(Self {
            connection,
            _lease: lease,
            host_id,
            host_epoch,
            staged: None,
        })
    }

    fn open_owned(
        directory: &Path,
        host_id: Id,
        host_epoch: Id,
        owner: u32,
    ) -> Result<Self, JournalError> {
        let lease = storage::open_files(directory, owner)?;
        let connection = storage::open(directory, &host_id, &host_epoch)?;
        Ok(Self {
            connection,
            _lease: lease,
            host_id,
            host_epoch,
            staged: None,
        })
    }

    /// Records one serialized durable intent, or returns status for an exact replay.
    /// No signature, live precondition, custody or effect is verified here.
    pub fn record_intent(
        &mut self,
        intent: &Intent,
        now: Timestamp,
    ) -> Result<RecordResult, JournalError> {
        self.record_intent_with(intent, now, |_| Ok(()))
    }

    /// `record_intent` plus `extra` rows committed in the same transaction,
    /// only when the intent is new.
    pub(crate) fn record_intent_with(
        &mut self,
        intent: &Intent,
        now: Timestamp,
        extra: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<(), JournalError>,
    ) -> Result<RecordResult, JournalError> {
        let signed = self.take_signed(&signed::Expected {
            plan_digest: &intent.plan_digest,
            grant_digest: &intent.grant_digest,
        })?;
        if intent.host_id != self.host_id
            || intent.host_epoch != self.host_epoch
            || intent.predecessor_generation == intent.target_generation
            || intent.compensation_valid_until.get() < intent.expires_at.get()
        {
            return Err(JournalError::Conflict);
        }
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        if let Some(existing) = storage::by_key(&transaction, &intent.idempotency_key)? {
            return if &existing.intent == intent {
                Ok(RecordResult::Existing(existing))
            } else {
                Err(JournalError::Conflict)
            };
        }
        if storage::consumed(&transaction, intent)? {
            return Err(JournalError::Conflict);
        }
        let last: i64 = transaction
            .query_row(
                "SELECT last_time FROM metadata WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(storage::unavailable)?;
        let last = u64::try_from(last)
            .ok()
            .and_then(|value| Timestamp::try_from(value).ok())
            .ok_or(JournalError::Unavailable)?;
        if now.get() < last.get() {
            return Err(JournalError::ClockRollback);
        }
        if now.get() >= intent.expires_at.get() {
            return Err(JournalError::Expired);
        }
        let busy: bool = transaction.query_row("SELECT EXISTS(SELECT 1 FROM operations WHERE state IN ('intent','needs_attention','compensating'))", [], |row| row.get(0)).map_err(storage::unavailable)?;
        if busy || storage::readoption_verifying(&transaction)? {
            return Err(JournalError::Busy);
        }
        let count: i64 = transaction
            .query_row("SELECT count(*) FROM operations", [], |row| row.get(0))
            .map_err(storage::unavailable)?;
        if count >= storage::MAX_OPERATIONS {
            return Err(JournalError::Capacity);
        }
        storage::insert(&transaction, intent)?;
        extra(&transaction)?;
        signed::insert(&transaction, &intent.operation_id, signed.as_ref())?;
        transaction
            .execute(
                "UPDATE metadata SET last_time=?1 WHERE singleton=1",
                [now.get() as i64],
            )
            .map_err(storage::unavailable)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(RecordResult::New(Operation {
            intent: intent.clone(),
            state: RecordedState::Intent,
            effect_attempted: false,
            compensation_attempted: false,
        }))
    }

    /// Status of an exact earlier intent for this retry key; `Conflict` if the
    /// key is bound to different fields or the operation, grant or nonce is
    /// already consumed under another key. Creates nothing.
    pub fn existing(&self, intent: &Intent) -> Result<Option<Operation>, JournalError> {
        match storage::by_key(&self.connection, &intent.idempotency_key)? {
            Some(existing) if &existing.intent == intent => Ok(Some(existing)),
            Some(_) => Err(JournalError::Conflict),
            None if storage::consumed(&self.connection, intent)? => Err(JournalError::Conflict),
            None => Ok(None),
        }
    }

    /// Retrieves existing metadata without creating history or execution authority.
    pub fn status(&self, operation_id: &Id) -> Result<Option<Operation>, JournalError> {
        storage::by_operation(&self.connection, operation_id)
    }

    /// Durably marks that the effect may begin; must commit before any write.
    pub fn mark_effect_attempted(&mut self, operation_id: &Id) -> Result<Operation, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let mut operation =
            storage::by_operation(&transaction, operation_id)?.ok_or(JournalError::Conflict)?;
        if operation.state != RecordedState::Intent || operation.effect_attempted {
            return Err(JournalError::Conflict);
        }
        transaction
            .execute(
                "UPDATE operations SET effect_attempted=1 WHERE operation_id=?1",
                [operation_id.as_str()],
            )
            .map_err(storage::unavailable)?;
        transaction.commit().map_err(storage::unavailable)?;
        operation.effect_attempted = true;
        Ok(operation)
    }

    /// Records the single compensation attempt before its effect. Allowed only
    /// for an attempted effect now in `NeedsAttention`, before the signed
    /// compensation deadline and without clock rollback.
    pub fn begin_compensation(
        &mut self,
        operation_id: &Id,
        now: Timestamp,
    ) -> Result<Operation, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let mut operation =
            storage::by_operation(&transaction, operation_id)?.ok_or(JournalError::Conflict)?;
        if operation.state != RecordedState::NeedsAttention
            || !operation.effect_attempted
            || operation.compensation_attempted
        {
            return Err(JournalError::Conflict);
        }
        let last: i64 = transaction
            .query_row(
                "SELECT last_time FROM metadata WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(storage::unavailable)?;
        if (now.get() as i64) < last {
            return Err(JournalError::ClockRollback);
        }
        if now.get() >= operation.intent.compensation_valid_until.get() {
            return Err(JournalError::Expired);
        }
        transaction
            .execute(
                "UPDATE operations SET compensation_attempts=1, state='compensating' WHERE operation_id=?1",
                [operation_id.as_str()],
            )
            .map_err(storage::unavailable)?;
        transaction
            .execute(
                "UPDATE metadata SET last_time=?1 WHERE singleton=1",
                [now.get() as i64],
            )
            .map_err(storage::unavailable)?;
        transaction.commit().map_err(storage::unavailable)?;
        operation.compensation_attempted = true;
        operation.state = RecordedState::Compensating;
        Ok(operation)
    }

    /// The generation the journal last established for `resource_id`: the
    /// target of the latest succeeded operation, or `baseline` re-established
    /// from an empty history (W360, see [`ResourceHistory`]). `None` when
    /// nothing is established yet (or the latest operation is unresolved).
    /// Live state that differs from this is unexplained drift.
    pub fn expected_generation(
        &self,
        resource_id: &Id,
        baseline: Option<&(Id, Sha256Digest)>,
    ) -> Result<Option<(Id, Sha256Digest)>, JournalError> {
        Ok(
            match resource_history(&self.connection, resource_id, None, baseline)? {
                ResourceHistory::Established(id, digest) => Some((id, digest)),
                ResourceHistory::Empty | ResourceHistory::Unresolved => None,
            },
        )
    }

    /// W381 (D-032): the unresolved operation of `resource_id`, if any. The
    /// schema allows one unresolved operation. A journal that holds more is
    /// a `Conflict`, and no one of them is chosen.
    pub fn unresolved_operation(
        &self,
        resource_id: &Id,
    ) -> Result<Option<Operation>, JournalError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT operation_id FROM operations WHERE resource_id=?1 \
                 AND state IN ('intent','needs_attention','compensating') ORDER BY rowid LIMIT 2",
            )
            .map_err(storage::unavailable)?;
        let ids = statement
            .query_map([resource_id.as_str()], |row| row.get::<_, String>(0))
            .map_err(storage::unavailable)?
            .collect::<Result<Vec<String>, _>>()
            .map_err(storage::unavailable)?;
        match ids.as_slice() {
            [] => Ok(None),
            [only] => {
                let id = Id::try_from(only.clone()).map_err(storage::unavailable)?;
                storage::by_operation(&self.connection, &id)?
                    .ok_or(JournalError::Unavailable)
                    .map(Some)
            }
            _ => Err(JournalError::Conflict),
        }
    }

    /// W372: how many operations the journal records for `resource_id`, in
    /// any state.
    pub fn resource_operations(&self, resource_id: &Id) -> Result<u64, JournalError> {
        let count: i64 = self
            .connection
            .query_row(
                "SELECT count(*) FROM operations WHERE resource_id=?1",
                [resource_id.as_str()],
                |row| row.get(0),
            )
            .map_err(storage::unavailable)?;
        u64::try_from(count).map_err(storage::unavailable)
    }

    /// P23 (D-098): durable authority consumption inside the journal, evaluated
    /// against `window_start` (Unix seconds).
    pub fn authority_usage(
        &self,
        window_start: i64,
    ) -> Result<rustiron_contracts::approval::AuthorityUsage, JournalError> {
        observe::authority_usage(&self.connection, window_start)
    }

    /// Monotonic last-admission timestamp recorded in `metadata.last_time`.
    pub fn last_time(&self) -> Result<i64, JournalError> {
        self.connection
            .query_row(
                "SELECT last_time FROM metadata WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(storage::unavailable)
    }

    /// Whether an exact canonical plan/grant pair was already admitted in this journal.
    pub fn has_signed_admission(
        &self,
        plan_sha256: &str,
        grant_sha256: &str,
    ) -> Result<bool, JournalError> {
        self.connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM admission_signatures WHERE plan_sha256=?1 AND grant_sha256=?2)",
                [plan_sha256, grant_sha256],
                |row| row.get(0),
            )
            .map_err(storage::unavailable)
    }

    /// W633 (M-25): whether this exact `operation_id` was already admitted with
    /// the given canonical plan and grant digests. Standing captures share plan
    /// and grant digests across runs, so checking `operation_id` prevents later
    /// distinct runs from bypassing D-098 blast-radius budgets.
    pub fn has_signed_admission_for_operation(
        &self,
        operation_id: &str,
        plan_sha256: &str,
        grant_sha256: &str,
    ) -> Result<bool, JournalError> {
        self.connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM admission_signatures WHERE operation_id=?1 AND plan_sha256=?2 AND grant_sha256=?3)",
                [operation_id, plan_sha256, grant_sha256],
                |row| row.get(0),
            )
            .map_err(storage::unavailable)
    }

    /// W355: the history of `resource_id`, before `before` when named (that
    /// operation must exist on the resource). `baseline` as for
    /// [`Self::expected_generation`].
    pub fn resource_history(
        &self,
        resource_id: &Id,
        before: Option<&Id>,
        baseline: Option<&(Id, Sha256Digest)>,
    ) -> Result<ResourceHistory, JournalError> {
        resource_history(&self.connection, resource_id, before, baseline)
    }

    /// Records caller-reported generation/hash reality. Unknown/mismatched reports
    /// block resources; only a complete matching target can record succeeded.
    /// While compensating, only the complete predecessor records
    /// `FailedCompensated`; anything else stays `NeedsAttention`.
    /// The future root boundary must supply independently observed facts.
    pub fn record_observation(
        &mut self,
        operation_id: &Id,
        generation: Option<&Id>,
        digest: Option<&Sha256Digest>,
    ) -> Result<Operation, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let mut operation =
            storage::by_operation(&transaction, operation_id)?.ok_or(JournalError::Conflict)?;
        let intent = &operation.intent;
        let is_target =
            generation == Some(&intent.target_generation) && digest == Some(&intent.target_digest);
        let is_predecessor = generation == Some(&intent.predecessor_generation)
            && digest == Some(&intent.predecessor_digest);
        let state = match (operation.compensation_attempted, is_target, is_predecessor) {
            (true, _, true) => RecordedState::FailedCompensated,
            (true, _, false) => RecordedState::NeedsAttention,
            (false, true, _) => RecordedState::Succeeded,
            (false, false, true) => RecordedState::Untouched,
            (false, false, false) => RecordedState::NeedsAttention,
        };
        if operation.state.is_terminal() && state != operation.state {
            return Err(JournalError::Conflict);
        }
        transaction
            .execute(
                "UPDATE operations SET state=?1 WHERE operation_id=?2",
                params![storage::state_text(state), operation_id.as_str()],
            )
            .map_err(storage::unavailable)?;
        transaction.commit().map_err(storage::unavailable)?;
        operation.state = state;
        Ok(operation)
    }
}
