//! Backup captures (schema v5): one durable intent before any effect, then a
//! recorded outcome. A capture only adds an encrypted snapshot, so a crash
//! leaves `running` until reconciled against the repository by operation tag.

use rusqlite::{OptionalExtension, Row, params};
use rustiron_contracts::{
    Id, Timestamp,
    approval::{Sha256Digest, SiteId},
};

use crate::{FixtureJournal, JournalError, storage};

const MAX_CAPTURES: i64 = 1000;

/// Admitted capture recipe, not proof of completed steps or consistency.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureMethod {
    /// Single-transaction dump followed by a file snapshot; no common freeze point.
    SiteFilesDbV1,
    /// As `SiteFilesDbV1` with the site's PHP pool stopped from before the
    /// first marker to after the second (D-021 option A, v12). Stored as a
    /// `capture_freeze` row, not a `capture_methods` row.
    SiteFilesDbFrozenV1,
}

impl CaptureMethod {
    /// Stable representation in the journal and observation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SiteFilesDbV1 => "site_files_db_v1",
            Self::SiteFilesDbFrozenV1 => "site_files_db_frozen_v1",
        }
    }
}

/// Immutable admitted capture; built by the executor from verified inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureIntent {
    /// Operation identity (also the snapshot tag).
    pub operation_id: Id,
    /// Retry key bound to every field.
    pub idempotency_key: Id,
    /// Signed grant identity.
    pub grant_id: Id,
    /// Single-use signed nonce.
    pub nonce: Id,
    /// Complete plan digest.
    pub plan_digest: Sha256Digest,
    /// Complete canonical grant digest.
    pub grant_digest: Sha256Digest,
    /// Enrolled host identity.
    pub host_id: Id,
    /// Enrolled host epoch.
    pub host_epoch: Id,
    /// Site being captured; needs a succeeded provision.
    pub site_id: SiteId,
    /// Normal grant deadline for starting the capture.
    pub expires_at: Timestamp,
}

/// Recorded capture state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureState {
    /// Intent recorded; a snapshot may or may not exist.
    Running,
    /// Snapshot recorded and the repository check passed.
    Succeeded,
    /// No snapshot is claimed. Either no tagged snapshot exists (the capture
    /// stopped before the snapshot step, or reconciliation found none once
    /// no capture unit was running), or an operator settled the capture and
    /// its one tagged snapshot is kept only as unclaimed evidence (v14,
    /// W366; see [`Capture::unclaimed_snapshot_id`]).
    Failed,
}

/// Stored capture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Capture {
    /// Immutable admitted data.
    pub intent: CaptureIntent,
    /// Admission time.
    pub started_at: Timestamp,
    /// Current state.
    pub state: CaptureState,
    /// Restic snapshot id (64 hex) when succeeded.
    pub snapshot_id: Option<String>,
    /// Outcome time.
    pub finished_at: Option<Timestamp>,
    /// Admitted recipe, or unknown if not recorded (including legacy captures).
    pub method: Option<CaptureMethod>,
    /// Days copied from the enrolled policy at admission. Absent on a capture
    /// recorded before that copy, or when no count was supplied. Not proof
    /// the store kept the objects.
    pub retention_days: Option<u32>,
    /// Enrolled backup policy at admission. Absent in pre-v13 records.
    pub backup_policy_digest: Option<Sha256Digest>,
    /// Files the restic summary reported. Absent when that summary was not stored.
    pub files: Option<u64>,
    /// Bytes the restic summary reported. Absent when that summary was not stored.
    pub bytes: Option<u64>,
    /// Artifact manifest digest and counts (v10). Absent on a capture recorded
    /// before schema 10, or when the manifest step failed or was refused.
    pub manifest: Option<CaptureManifest>,
    /// D-021 option E label (v11). Absent on a capture recorded before schema
    /// 11 or finished without the marker check: read as not checked.
    pub consistency: Option<CaptureConsistency>,
    /// v14 (W366): on a `failed` capture that an operator settled, the one
    /// snapshot that carried the operation tag at settlement. It is evidence
    /// that a write happened, never a claim that the capture is complete,
    /// checked or retained. Absent on every other capture.
    pub unclaimed_snapshot_id: Option<String>,
    /// v18 (W391): on a succeeded product capture, the bucket default the
    /// lock precheck and postcheck read and each object version the
    /// postcheck read back. Absent on a capture recorded before v18, on a
    /// lab capture, and on every capture that did not succeed.
    pub retention_evidence: Option<RetentionEvidence>,
    /// v18 (W391): on a `failed` capture refused before its snapshot step,
    /// the stable refusal code (`A-Z`, `0-9`, `_`, 1 to 64 characters).
    /// Absent on a capture recorded before v18 and on every other capture.
    pub refusal: Option<String>,
}

/// The kind of a repository object that a capture wrote (W334 selection).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedObjectKind {
    /// The snapshot file.
    Snapshot,
    /// An index file written at or after the snapshot start.
    Index,
    /// A pack that such an index file lists.
    Pack,
}

impl RetainedObjectKind {
    /// Stored and exported name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Snapshot => "snapshot",
            Self::Index => "index",
            Self::Pack => "pack",
        }
    }

    /// The kind with the stored name `name`.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "snapshot" => Some(Self::Snapshot),
            "index" => Some(Self::Index),
            "pack" => Some(Self::Pack),
            _ => None,
        }
    }
}

/// The only retention mode the lock reader accepts and the journal stores.
pub const RETENTION_MODE: &str = "COMPLIANCE";
/// Objects one retention record holds; the lock reader refuses more.
pub const MAX_RETAINED_OBJECTS: usize = 1024;
/// Largest bucket default, in days, a lock check record holds.
pub const MAX_LOCK_DAYS: u32 = 36_500;

/// One object version as the lock postcheck read it back (W391): a HEAD
/// read named the version, and the version-pinned `GetObjectRetention`
/// returned COMPLIANCE with the same retain-until time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectRetention {
    /// Snapshot, index or pack.
    pub kind: RetainedObjectKind,
    /// The restic object ID, 64 lowercase hex.
    pub object_id: String,
    /// The store's version ID: 1 to 128 of `A-Z`, `a-z`, `0-9`, `.`, `_`
    /// and `-`, never `null`.
    pub version_id: String,
    /// The COMPLIANCE retain-until time, Unix seconds.
    pub retain_until: i64,
}

/// The retention evidence of one succeeded product capture (W391, D-041).
/// It states what the lock reader read at the capture's precheck and
/// postcheck, not that the store still holds the objects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionEvidence {
    /// The bucket's default COMPLIANCE days at the lock precheck (step 3).
    pub before_days: u32,
    /// The bucket's default COMPLIANCE days at the lock postcheck (step 9).
    pub after_days: u32,
    /// Each object version the postcheck read, in the reader's order.
    pub objects: Vec<ObjectRetention>,
}

/// A store version ID the journal accepts.
pub fn version_id_ok(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value != "null"
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// A capture refusal code the journal accepts.
pub fn refusal_code_ok(code: &str) -> bool {
    (1..=64).contains(&code.len())
        && code
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

impl RetentionEvidence {
    /// Within bounds, and the one snapshot object names `snapshot`.
    pub fn valid_for(&self, snapshot: &str) -> bool {
        let days = 1..=MAX_LOCK_DAYS;
        let snapshots: Vec<&ObjectRetention> = self
            .objects
            .iter()
            .filter(|o| o.kind == RetainedObjectKind::Snapshot)
            .collect();
        days.contains(&self.before_days)
            && days.contains(&self.after_days)
            && (1..=MAX_RETAINED_OBJECTS).contains(&self.objects.len())
            && matches!(snapshots.as_slice(), [one] if one.object_id == snapshot)
            && self.objects.iter().all(|o| {
                lower_hex64(&o.object_id) && version_id_ok(&o.version_id) && o.retain_until >= 0
            })
    }
}

/// Whether the database dump and the file walk are proven to be a matched
/// pair (D-021 option E): a write marker read before the dump equals one read
/// after the snapshot was checked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureConsistency {
    /// Both markers were read and are equal.
    Matched,
    /// No matched pair is claimed; the capture still succeeded (D-021 O1).
    Unmatched(UnmatchedReason),
}

/// Why a capture is labelled unmatched.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnmatchedReason {
    /// The markers differ: the database changed during the capture window.
    DatabaseChanged,
    /// A marker could not be read, so no comparison was made.
    MarkerUnavailable,
    /// Frozen recipe only (v12): the freeze was not proved to hold for the
    /// whole window, whatever the markers read. Stored as `capture_freeze.held=0`.
    FreezeNotHeld,
}

impl UnmatchedReason {
    /// Stored and exported name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DatabaseChanged => "database_changed",
            Self::MarkerUnavailable => "marker_unavailable",
            Self::FreezeNotHeld => "freeze_not_held",
        }
    }
}

impl CaptureConsistency {
    /// Stored and exported label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::Unmatched(_) => "unmatched",
        }
    }

    /// The unmatched reason, if any.
    pub fn reason(self) -> Option<&'static str> {
        match self {
            Self::Matched => None,
            Self::Unmatched(reason) => Some(reason.as_str()),
        }
    }
}

/// Digest and counts of the canonical file list of a succeeded snapshot. The
/// list itself is stored outside SQLite under its digest. Describes what the
/// repository returned when hashed, not that a restore will succeed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureManifest {
    /// SHA-256 of the canonical manifest bytes, 64 lowercase hex.
    pub sha256: String,
    /// Entries listed (at most 200000).
    pub entries: u64,
    /// Sum of regular file sizes listed.
    pub regular_bytes: u64,
    /// A bound stopped the listing; the list is a prefix.
    pub truncated: bool,
}

/// Largest manifest entry count the journal accepts.
pub const MAX_MANIFEST_ENTRIES: u64 = 200_000;

fn lower_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl CaptureManifest {
    fn valid(&self) -> bool {
        lower_hex64(&self.sha256)
            && self.entries <= MAX_MANIFEST_ENTRIES
            && i64::try_from(self.regular_bytes).is_ok()
    }
}

/// What a succeeded capture records in one transaction (W391).
#[derive(Clone, Copy, Debug)]
pub struct CaptureSuccess<'a> {
    /// Restic snapshot ID, 64 lowercase hex.
    pub snapshot_id: &'a str,
    /// The restic summary file count and byte count.
    pub extent: Option<(u64, u64)>,
    /// The artifact manifest record.
    pub manifest: Option<&'a CaptureManifest>,
    /// The D-021 consistency label.
    pub consistency: Option<&'a CaptureConsistency>,
    /// The lock reader's retention evidence (v18).
    pub retention: Option<&'a RetentionEvidence>,
}

/// Every record a finished capture can carry.
struct Finish<'a> {
    snapshot_id: Option<&'a str>,
    extent: Option<(u64, u64)>,
    manifest: Option<&'a CaptureManifest>,
    consistency: Option<&'a CaptureConsistency>,
    retention: Option<&'a RetentionEvidence>,
    refusal: Option<&'a str>,
}

fn insert_retention(
    transaction: &rusqlite::Transaction<'_>,
    operation_id: &Id,
    evidence: &RetentionEvidence,
) -> Result<(), JournalError> {
    transaction
        .execute(
            "INSERT INTO capture_lock_checks (operation_id,before_mode,before_days,after_mode,after_days,objects) VALUES (?1,?2,?3,?2,?4,?5)",
            params![
                operation_id.as_str(),
                RETENTION_MODE,
                evidence.before_days,
                evidence.after_days,
                evidence.objects.len() as i64
            ],
        )
        .map_err(storage::unavailable)?;
    let mut insert = transaction
        .prepare(
            "INSERT INTO capture_object_retention (operation_id,position,kind,object_id,version_id,mode,retain_until) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        )
        .map_err(storage::unavailable)?;
    for (position, object) in evidence.objects.iter().enumerate() {
        insert
            .execute(params![
                operation_id.as_str(),
                position as i64,
                object.kind.as_str(),
                object.object_id,
                object.version_id,
                RETENTION_MODE,
                object.retain_until
            ])
            .map_err(storage::unavailable)?;
    }
    Ok(())
}

/// The v18 records of one capture: its retention evidence and refusal code.
fn load_v18(c: &rusqlite::Connection, capture: &mut Capture) -> Result<(), JournalError> {
    let operation = capture.intent.operation_id.as_str();
    capture.refusal = c
        .query_row(
            "SELECT code FROM capture_refusals WHERE operation_id=?1",
            [operation],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(storage::unavailable)?;
    if capture
        .refusal
        .as_deref()
        .is_some_and(|code| !refusal_code_ok(code) || capture.state != CaptureState::Failed)
    {
        return Err(JournalError::Unavailable);
    }
    let checks: Option<(i64, i64, i64)> = c
        .query_row(
            "SELECT before_days,after_days,objects FROM capture_lock_checks WHERE operation_id=?1",
            [operation],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(storage::unavailable)?;
    let Some((before, after, count)) = checks else {
        return Ok(());
    };
    let mut statement = c
        .prepare(
            "SELECT kind,object_id,version_id,retain_until FROM capture_object_retention WHERE operation_id=?1 ORDER BY position",
        )
        .map_err(storage::unavailable)?;
    let rows = statement
        .query_map([operation], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(storage::unavailable)?;
    let mut objects = Vec::new();
    for row in rows {
        let (kind, object_id, version_id, retain_until) = row.map_err(storage::unavailable)?;
        objects.push(ObjectRetention {
            kind: RetainedObjectKind::from_name(&kind).ok_or(JournalError::Unavailable)?,
            object_id,
            version_id,
            retain_until,
        });
    }
    let day = |value: i64| u32::try_from(value).map_err(|_| JournalError::Unavailable);
    let evidence = RetentionEvidence {
        before_days: day(before)?,
        after_days: day(after)?,
        objects,
    };
    let snapshot = capture.snapshot_id.as_deref().unwrap_or_default();
    if capture.state != CaptureState::Succeeded
        || usize::try_from(count).ok() != Some(evidence.objects.len())
        || !evidence.valid_for(snapshot)
    {
        return Err(JournalError::Unavailable);
    }
    capture.retention_evidence = Some(evidence);
    Ok(())
}

/// New durable capture, or status of an exact earlier one.
#[derive(Debug, Eq, PartialEq)]
pub enum CaptureResult {
    /// Intent committed; nonce consumed.
    New(Capture),
    /// Status only; never permission to capture again.
    Existing(Capture),
}

impl FixtureJournal {
    /// Records a capture intent in one transaction, or returns exact status.
    /// The site needs a succeeded provision; one capture runs at a time.
    /// The caller supplies the independently verified recipe; it describes the
    /// intended method, not observed consistency or completed steps.
    /// `retention_days` is the enrolled count, copied only onto this new row.
    /// `None` leaves the row without a count. A count outside 1..=3650 is refused.
    /// The backup policy digest is stored with the intent before any effect.
    pub fn record_capture(
        &mut self,
        intent: &CaptureIntent,
        now: Timestamp,
        method: CaptureMethod,
        retention_days: Option<u32>,
        backup_policy_digest: &Sha256Digest,
    ) -> Result<CaptureResult, JournalError> {
        let signed = self.take_signed(&crate::signed::Expected {
            plan_digest: &intent.plan_digest,
            grant_digest: &intent.grant_digest,
        })?;
        if retention_days.is_some_and(|days| !(1..=3650).contains(&days)) {
            return Err(JournalError::Conflict);
        }
        if intent.host_id != self.host_id || intent.host_epoch != self.host_epoch {
            return Err(JournalError::Conflict);
        }
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        if let Some(existing) = find(
            &transaction,
            "idempotency_key",
            intent.idempotency_key.as_str(),
        )? {
            return if existing.intent == *intent
                && existing.method.is_none_or(|old| old == method)
                && existing
                    .retention_days
                    .is_none_or(|old| retention_days == Some(old))
            {
                Ok(CaptureResult::Existing(existing))
            } else {
                Err(JournalError::Conflict)
            };
        }
        let provisioned: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM provisions WHERE site_id=?1 AND state IN ('succeeded','adopted'))",
                [intent.site_id.as_str()],
                |row| row.get(0),
            )
            .map_err(storage::unavailable)?;
        if !provisioned
            || storage::consumed_ids(
                &transaction,
                &intent.operation_id,
                &intent.grant_id,
                &intent.nonce,
            )?
        {
            return Err(JournalError::Conflict);
        }
        storage::check_clock(&transaction, now)?;
        if now.get() >= intent.expires_at.get() {
            return Err(JournalError::Expired);
        }
        let (running, count): (bool, i64) = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM captures WHERE state='running'), count(*) FROM captures",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(storage::unavailable)?;
        if running
            || storage::readoption_verifying(&transaction)?
            || crate::site_restore::open_on_site(&transaction, intent.site_id.as_str())?
        {
            return Err(JournalError::Busy);
        }
        if count >= MAX_CAPTURES {
            return Err(JournalError::Capacity);
        }
        transaction
            .execute(
                "INSERT INTO captures VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,'running',NULL,NULL)",
                params![
                    intent.operation_id.as_str(),
                    intent.idempotency_key.as_str(),
                    intent.grant_id.as_str(),
                    intent.nonce.as_str(),
                    intent.plan_digest.as_str(),
                    intent.grant_digest.as_str(),
                    intent.host_id.as_str(),
                    intent.host_epoch.as_str(),
                    intent.site_id.as_str(),
                    intent.expires_at.get() as i64,
                    now.get() as i64
                ],
            )
            .map_err(storage::unavailable)?;
        match method {
            CaptureMethod::SiteFilesDbV1 => transaction.execute(
                "INSERT INTO capture_methods (operation_id,method) VALUES (?1,?2)",
                params![intent.operation_id.as_str(), method.as_str()],
            ),
            CaptureMethod::SiteFilesDbFrozenV1 => transaction.execute(
                "INSERT INTO capture_freeze (operation_id,held) VALUES (?1,NULL)",
                params![intent.operation_id.as_str()],
            ),
        }
        .map_err(storage::unavailable)?;
        if let Some(days) = retention_days {
            transaction
                .execute(
                    "INSERT INTO capture_retention (operation_id,retention_days) VALUES (?1,?2)",
                    params![intent.operation_id.as_str(), days],
                )
                .map_err(storage::unavailable)?;
        }
        transaction
            .execute(
                "INSERT INTO capture_backup_policy VALUES (?1,?2)",
                params![intent.operation_id.as_str(), backup_policy_digest.as_str()],
            )
            .map_err(storage::unavailable)?;
        crate::signed::insert(&transaction, &intent.operation_id, signed.as_ref())?;
        storage::set_clock(&transaction, now)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(CaptureResult::New(Capture {
            intent: intent.clone(),
            started_at: now,
            state: CaptureState::Running,
            snapshot_id: None,
            finished_at: None,
            method: Some(method),
            retention_days,
            backup_policy_digest: Some(backup_policy_digest.clone()),
            files: None,
            bytes: None,
            manifest: None,
            consistency: None,
            unclaimed_snapshot_id: None,
            retention_evidence: None,
            refusal: None,
        }))
    }

    /// Records the outcome of a running capture: `Some(id)` (64 lowercase
    /// hex) is success, `None` failure. `extent` is the restic summary file
    /// count and byte count, stored only on success. `manifest` is the
    /// artifact manifest record, written in the same transaction; it is
    /// refused on a failure or when out of range. A finished capture never
    /// changes.
    pub fn finish_capture(
        &mut self,
        operation_id: &Id,
        snapshot_id: Option<&str>,
        now: Timestamp,
        extent: Option<(u64, u64)>,
        manifest: Option<&CaptureManifest>,
    ) -> Result<Capture, JournalError> {
        self.finish_capture_labelled(operation_id, snapshot_id, now, extent, manifest, None)
    }

    /// Operator reconcile of a capture left `running` (W261). Whether a
    /// freeze held cannot be known after an interruption, so a frozen capture
    /// found in the repository is recorded `unmatched(freeze_not_held)`; any
    /// other capture keeps no label. Nothing found records `failed`.
    pub fn reconcile_finish_capture(
        &mut self,
        operation_id: &Id,
        snapshot_id: Option<&str>,
        now: Timestamp,
    ) -> Result<Capture, JournalError> {
        let capture = self
            .capture_status(operation_id)?
            .ok_or(JournalError::Conflict)?;
        let not_held = CaptureConsistency::Unmatched(UnmatchedReason::FreezeNotHeld);
        let label = (capture.method == Some(CaptureMethod::SiteFilesDbFrozenV1)
            && snapshot_id.is_some())
        .then_some(&not_held);
        self.finish_capture_labelled(operation_id, snapshot_id, now, None, None, label)
    }

    /// W366: operator settlement of a capture left `running` whose one tagged
    /// snapshot cannot be claimed (a lost reply, a partial write, or a check
    /// that failed after the write). Records `failed` with no snapshot and
    /// keeps `snapshot_id` (64 lowercase hex) only as unclaimed evidence, in
    /// one transaction. Nothing about the snapshot's completeness, structure
    /// or retention is recorded. A finished capture never changes, so a
    /// replay is a conflict and the caller reads the stored status.
    pub fn settle_capture_unclaimed(
        &mut self,
        operation_id: &Id,
        snapshot_id: &str,
        now: Timestamp,
    ) -> Result<Capture, JournalError> {
        if !lower_hex64(snapshot_id) {
            return Err(JournalError::Conflict);
        }
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let capture = find(&transaction, "operation_id", operation_id.as_str())?
            .ok_or(JournalError::Conflict)?;
        if capture.state != CaptureState::Running || now.get() < capture.started_at.get() {
            return Err(JournalError::Conflict);
        }
        transaction
            .execute(
                "UPDATE captures SET state='failed', snapshot_id=NULL, finished_at=?1 WHERE operation_id=?2",
                params![now.get() as i64, operation_id.as_str()],
            )
            .map_err(storage::unavailable)?;
        transaction
            .execute(
                "INSERT INTO capture_unclaimed (operation_id,snapshot_id) VALUES (?1,?2)",
                params![operation_id.as_str(), snapshot_id],
            )
            .map_err(storage::unavailable)?;
        transaction.commit().map_err(storage::unavailable)?;
        self.capture_status(operation_id)?
            .ok_or(JournalError::Unavailable)
    }

    /// As [`Self::finish_capture`], also storing the D-021 consistency label
    /// in the same transaction. A label is refused on a failure.
    pub fn finish_capture_labelled(
        &mut self,
        operation_id: &Id,
        snapshot_id: Option<&str>,
        now: Timestamp,
        extent: Option<(u64, u64)>,
        manifest: Option<&CaptureManifest>,
        consistency: Option<&CaptureConsistency>,
    ) -> Result<Capture, JournalError> {
        self.finish(
            operation_id,
            now,
            Finish {
                snapshot_id,
                extent,
                manifest,
                consistency,
                retention: None,
                refusal: None,
            },
        )
    }

    /// W391 (v18): records a succeeded capture as
    /// [`Self::finish_capture_labelled`] does, with the retention evidence
    /// the lock reader read back, in the same transaction. Evidence out of
    /// bounds, or whose one snapshot object is not this snapshot, is refused
    /// and nothing is recorded.
    pub fn finish_capture_succeeded(
        &mut self,
        operation_id: &Id,
        now: Timestamp,
        success: CaptureSuccess<'_>,
    ) -> Result<Capture, JournalError> {
        if success
            .retention
            .is_some_and(|evidence| !evidence.valid_for(success.snapshot_id))
        {
            return Err(JournalError::Conflict);
        }
        self.finish(
            operation_id,
            now,
            Finish {
                snapshot_id: Some(success.snapshot_id),
                extent: success.extent,
                manifest: success.manifest,
                consistency: success.consistency,
                retention: success.retention,
                refusal: None,
            },
        )
    }

    /// W391 (v18): records a running capture `failed`, with no snapshot,
    /// and keeps the refusal code that stopped it before its snapshot step,
    /// in one transaction. A code outside `A-Z`, `0-9` and `_`, or longer
    /// than 64 characters, is refused and nothing is recorded.
    pub fn refuse_capture(
        &mut self,
        operation_id: &Id,
        now: Timestamp,
        code: &str,
    ) -> Result<Capture, JournalError> {
        if !refusal_code_ok(code) {
            return Err(JournalError::Conflict);
        }
        self.finish(
            operation_id,
            now,
            Finish {
                snapshot_id: None,
                extent: None,
                manifest: None,
                consistency: None,
                retention: None,
                refusal: Some(code),
            },
        )
    }

    fn finish(
        &mut self,
        operation_id: &Id,
        now: Timestamp,
        finish: Finish<'_>,
    ) -> Result<Capture, JournalError> {
        let Finish {
            snapshot_id,
            extent,
            manifest,
            consistency,
            retention,
            refusal,
        } = finish;
        if snapshot_id.is_some_and(|id| !lower_hex64(id))
            || manifest.is_some_and(|m| snapshot_id.is_none() || !m.valid())
            || (consistency.is_some() && snapshot_id.is_none())
            || (retention.is_some() && snapshot_id.is_none())
            || (refusal.is_some() && snapshot_id.is_some())
        {
            return Err(JournalError::Conflict);
        }
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let capture = find(&transaction, "operation_id", operation_id.as_str())?
            .ok_or(JournalError::Conflict)?;
        if capture.state != CaptureState::Running || now.get() < capture.started_at.get() {
            return Err(JournalError::Conflict);
        }
        let frozen = capture.method == Some(CaptureMethod::SiteFilesDbFrozenV1);
        let not_held = consistency
            == Some(&CaptureConsistency::Unmatched(
                UnmatchedReason::FreezeNotHeld,
            ));
        // A freeze verdict belongs only to a frozen capture, and a succeeded
        // frozen capture must carry one.
        if (not_held && !frozen) || (frozen && snapshot_id.is_some() && consistency.is_none()) {
            return Err(JournalError::Conflict);
        }
        if frozen && snapshot_id.is_some() {
            transaction
                .execute(
                    "UPDATE capture_freeze SET held=?1 WHERE operation_id=?2",
                    params![i64::from(!not_held), operation_id.as_str()],
                )
                .map_err(storage::unavailable)?;
        }
        let consistency = consistency.filter(|_| !not_held);
        transaction
            .execute(
                "UPDATE captures SET state=?1, snapshot_id=?2, finished_at=?3 WHERE operation_id=?4",
                params![
                    if snapshot_id.is_some() { "succeeded" } else { "failed" },
                    snapshot_id,
                    now.get() as i64,
                    operation_id.as_str()
                ],
            )
            .map_err(storage::unavailable)?;
        if let (Some(_), Some((files, bytes))) = (snapshot_id, extent) {
            transaction
                .execute(
                    "INSERT INTO capture_extent (operation_id,files,bytes) VALUES (?1,?2,?3)",
                    params![operation_id.as_str(), files as i64, bytes as i64],
                )
                .map_err(storage::unavailable)?;
        }
        if let Some(m) = manifest {
            transaction
                .execute(
                    "INSERT INTO capture_manifest (operation_id,manifest_sha256,entries,regular_bytes,truncated) VALUES (?1,?2,?3,?4,?5)",
                    params![
                        operation_id.as_str(),
                        m.sha256,
                        m.entries as i64,
                        m.regular_bytes as i64,
                        i64::from(m.truncated)
                    ],
                )
                .map_err(storage::unavailable)?;
        }
        if let Some(label) = consistency {
            transaction
                .execute(
                    "INSERT INTO capture_consistency (operation_id,label,reason) VALUES (?1,?2,?3)",
                    params![operation_id.as_str(), label.label(), label.reason()],
                )
                .map_err(storage::unavailable)?;
        }
        if let Some(evidence) = retention {
            insert_retention(&transaction, operation_id, evidence)?;
        }
        if let Some(code) = refusal {
            transaction
                .execute(
                    "INSERT INTO capture_refusals (operation_id,code) VALUES (?1,?2)",
                    params![operation_id.as_str(), code],
                )
                .map_err(storage::unavailable)?;
        }
        transaction.commit().map_err(storage::unavailable)?;
        self.capture_status(operation_id)?
            .ok_or(JournalError::Unavailable)
    }

    /// Recorded capture status only.
    pub fn capture_status(&self, operation_id: &Id) -> Result<Option<Capture>, JournalError> {
        find(&self.connection, "operation_id", operation_id.as_str())
    }
}

pub(crate) fn find(
    c: &rusqlite::Connection,
    column: &str,
    value: &str,
) -> Result<Option<Capture>, JournalError> {
    let sql = match column {
        "operation_id" => {
            "SELECT captures.*, capture_methods.method, capture_retention.retention_days, capture_extent.files, capture_extent.bytes, capture_manifest.manifest_sha256, capture_manifest.entries, capture_manifest.regular_bytes, capture_manifest.truncated, capture_consistency.label, capture_consistency.reason, capture_freeze.held, capture_freeze.operation_id IS NOT NULL, capture_backup_policy.digest, capture_unclaimed.snapshot_id FROM captures LEFT JOIN capture_methods USING(operation_id) LEFT JOIN capture_retention USING(operation_id) LEFT JOIN capture_extent USING(operation_id) LEFT JOIN capture_manifest USING(operation_id) LEFT JOIN capture_consistency USING(operation_id) LEFT JOIN capture_freeze USING(operation_id) LEFT JOIN capture_backup_policy USING(operation_id) LEFT JOIN capture_unclaimed USING(operation_id) WHERE captures.operation_id=?1"
        }
        _ => {
            "SELECT captures.*, capture_methods.method, capture_retention.retention_days, capture_extent.files, capture_extent.bytes, capture_manifest.manifest_sha256, capture_manifest.entries, capture_manifest.regular_bytes, capture_manifest.truncated, capture_consistency.label, capture_consistency.reason, capture_freeze.held, capture_freeze.operation_id IS NOT NULL, capture_backup_policy.digest, capture_unclaimed.snapshot_id FROM captures LEFT JOIN capture_methods USING(operation_id) LEFT JOIN capture_retention USING(operation_id) LEFT JOIN capture_extent USING(operation_id) LEFT JOIN capture_manifest USING(operation_id) LEFT JOIN capture_consistency USING(operation_id) LEFT JOIN capture_freeze USING(operation_id) LEFT JOIN capture_backup_policy USING(operation_id) LEFT JOIN capture_unclaimed USING(operation_id) WHERE captures.idempotency_key=?1"
        }
    };
    let Some(mut capture) = c
        .query_row(sql, [value], decode)
        .optional()
        .map_err(storage::unavailable)?
        .transpose()?
    else {
        return Ok(None);
    };
    load_v18(c, &mut capture)?;
    Ok(Some(capture))
}

fn decode(row: &Row<'_>) -> rusqlite::Result<Result<Capture, JournalError>> {
    let text = |i: usize| row.get::<_, String>(i);
    let time = |i: usize| row.get::<_, i64>(i);
    let (op, key, grant, nonce, plan, gd, host, epoch, site) = (
        text(0)?,
        text(1)?,
        text(2)?,
        text(3)?,
        text(4)?,
        text(5)?,
        text(6)?,
        text(7)?,
        text(8)?,
    );
    let (expires, started, state) = (time(9)?, time(10)?, text(11)?);
    let snapshot: Option<String> = row.get(12)?;
    let finished: Option<i64> = row.get(13)?;
    let method: Option<String> = row.get(14)?;
    let retention_days: Option<i64> = row.get(15)?;
    let files: Option<i64> = row.get(16)?;
    let bytes: Option<i64> = row.get(17)?;
    let manifest_sha256: Option<String> = row.get(18)?;
    let manifest_entries: Option<i64> = row.get(19)?;
    let manifest_bytes: Option<i64> = row.get(20)?;
    let manifest_truncated: Option<i64> = row.get(21)?;
    let label: Option<String> = row.get(22)?;
    let reason: Option<String> = row.get(23)?;
    let held: Option<i64> = row.get(24)?;
    let frozen: bool = row.get(25)?;
    let backup_policy_digest: Option<String> = row.get(26)?;
    let unclaimed: Option<String> = row.get(27)?;
    let ts = |v: i64| {
        u64::try_from(v)
            .ok()
            .and_then(|v| Timestamp::try_from(v).ok())
            .ok_or(JournalError::Unavailable)
    };
    let id = |v: String| Id::try_from(v).map_err(|_| JournalError::Unavailable);
    let digest = |v: String| Sha256Digest::try_from(v).map_err(|_| JournalError::Unavailable);
    Ok((|| {
        Ok(Capture {
            intent: CaptureIntent {
                operation_id: id(op)?,
                idempotency_key: id(key)?,
                grant_id: id(grant)?,
                nonce: id(nonce)?,
                plan_digest: digest(plan)?,
                grant_digest: digest(gd)?,
                host_id: id(host)?,
                host_epoch: id(epoch)?,
                site_id: SiteId::try_from(site).map_err(|_| JournalError::Unavailable)?,
                expires_at: ts(expires)?,
            },
            started_at: ts(started)?,
            state: match state.as_str() {
                "running" => CaptureState::Running,
                "succeeded" => CaptureState::Succeeded,
                "failed" => CaptureState::Failed,
                _ => return Err(JournalError::Unavailable),
            },
            snapshot_id: snapshot,
            backup_policy_digest: backup_policy_digest.map(digest).transpose()?,
            finished_at: finished.map(ts).transpose()?,
            method: match (frozen, method.as_deref()) {
                (true, None) => Some(CaptureMethod::SiteFilesDbFrozenV1),
                (true, Some(_)) => return Err(JournalError::Unavailable),
                (false, None) => None,
                (false, Some("site_files_db_v1")) => Some(CaptureMethod::SiteFilesDbV1),
                _ => return Err(JournalError::Unavailable),
            },
            retention_days: match retention_days {
                None => None,
                Some(days) => {
                    let days = u32::try_from(days).map_err(|_| JournalError::Unavailable)?;
                    if !(1..=3650).contains(&days) {
                        return Err(JournalError::Unavailable);
                    }
                    Some(days)
                }
            },
            files: match (files, bytes) {
                (None, None) => None,
                (Some(files), Some(_)) => {
                    Some(u64::try_from(files).map_err(|_| JournalError::Unavailable)?)
                }
                _ => return Err(JournalError::Unavailable),
            },
            bytes: match (files, bytes) {
                (None, None) => None,
                (Some(_), Some(bytes)) => {
                    Some(u64::try_from(bytes).map_err(|_| JournalError::Unavailable)?)
                }
                _ => return Err(JournalError::Unavailable),
            },
            manifest: match (
                manifest_sha256,
                manifest_entries,
                manifest_bytes,
                manifest_truncated,
            ) {
                (None, None, None, None) => None,
                (Some(sha256), Some(entries), Some(regular_bytes), Some(truncated)) => {
                    let m = CaptureManifest {
                        sha256,
                        entries: u64::try_from(entries).map_err(|_| JournalError::Unavailable)?,
                        regular_bytes: u64::try_from(regular_bytes)
                            .map_err(|_| JournalError::Unavailable)?,
                        truncated: match truncated {
                            0 => false,
                            1 => true,
                            _ => return Err(JournalError::Unavailable),
                        },
                    };
                    if !m.valid() {
                        return Err(JournalError::Unavailable);
                    }
                    Some(m)
                }
                _ => return Err(JournalError::Unavailable),
            },
            consistency: match (label.as_deref(), reason.as_deref()) {
                (None, None) if frozen && held == Some(0) => Some(CaptureConsistency::Unmatched(
                    UnmatchedReason::FreezeNotHeld,
                )),
                _ if frozen && held == Some(0) => return Err(JournalError::Unavailable),
                (None, None) if frozen && held == Some(1) => return Err(JournalError::Unavailable),
                (None, None) => None,
                (Some("matched"), None) => Some(CaptureConsistency::Matched),
                (Some("unmatched"), Some("database_changed")) => Some(
                    CaptureConsistency::Unmatched(UnmatchedReason::DatabaseChanged),
                ),
                (Some("unmatched"), Some("marker_unavailable")) => Some(
                    CaptureConsistency::Unmatched(UnmatchedReason::MarkerUnavailable),
                ),
                _ => return Err(JournalError::Unavailable),
            },
            unclaimed_snapshot_id: match unclaimed {
                None => None,
                Some(id) if state == "failed" && lower_hex64(&id) => Some(id),
                Some(_) => return Err(JournalError::Unavailable),
            },
            retention_evidence: None,
            refusal: None,
        })
    })())
}

/// Opening refuses captures whose rows contradict their state or identity.
pub(crate) fn validate(
    c: &rusqlite::Connection,
    host: &Id,
    epoch: &Id,
) -> Result<(), JournalError> {
    let broken: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM captures WHERE host_id<>?1 OR host_epoch<>?2 \
             OR (state='succeeded' AND (snapshot_id IS NULL OR finished_at IS NULL)) \
             OR (state='failed' AND (snapshot_id IS NOT NULL OR finished_at IS NULL)) \
             OR (state='running' AND (snapshot_id IS NOT NULL OR finished_at IS NOT NULL)))",
            params![host.as_str(), epoch.as_str()],
            |row| row.get(0),
        )
        .map_err(storage::unavailable)?;
    if broken {
        return Err(JournalError::Unavailable);
    }
    let orphaned: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM capture_methods m LEFT JOIN captures c USING(operation_id) WHERE c.operation_id IS NULL) \
             OR EXISTS(SELECT 1 FROM capture_retention r LEFT JOIN captures c USING(operation_id) WHERE c.operation_id IS NULL) \
             OR EXISTS(SELECT 1 FROM capture_backup_policy b LEFT JOIN captures c USING(operation_id) WHERE c.operation_id IS NULL) \
             OR EXISTS(SELECT 1 FROM capture_extent e LEFT JOIN captures c USING(operation_id) WHERE c.operation_id IS NULL) \
             OR EXISTS(SELECT 1 FROM capture_manifest x LEFT JOIN captures c USING(operation_id) WHERE c.operation_id IS NULL OR c.state<>'succeeded') \
             OR EXISTS(SELECT 1 FROM capture_consistency k LEFT JOIN captures c USING(operation_id) WHERE c.operation_id IS NULL OR c.state<>'succeeded') \
             OR EXISTS(SELECT 1 FROM capture_unclaimed u LEFT JOIN captures c USING(operation_id) WHERE c.operation_id IS NULL OR c.state<>'failed') \
             OR EXISTS(SELECT 1 FROM capture_freeze f LEFT JOIN captures c USING(operation_id) WHERE c.operation_id IS NULL \
                OR EXISTS(SELECT 1 FROM capture_methods m WHERE m.operation_id=f.operation_id) \
                OR (c.state='succeeded' AND f.held IS NULL) OR (c.state<>'succeeded' AND f.held IS NOT NULL) \
                OR (f.held=0) = EXISTS(SELECT 1 FROM capture_consistency k WHERE k.operation_id=f.operation_id AND c.state='succeeded'))",
            [],
            |row| row.get(0),
        )
        .map_err(storage::unavailable)?;
    if orphaned {
        return Err(JournalError::Unavailable);
    }
    // W391 (v18): a refusal code only on a failed capture without an
    // unclaimed snapshot; lock checks only on a succeeded capture, with
    // exactly `objects` rows at positions 0 to objects-1 and exactly one
    // snapshot object that names the capture's snapshot.
    let contradicted: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM capture_refusals r LEFT JOIN captures c USING(operation_id) WHERE c.operation_id IS NULL OR c.state<>'failed' \
                OR EXISTS(SELECT 1 FROM capture_unclaimed u WHERE u.operation_id=r.operation_id)) \
             OR EXISTS(SELECT 1 FROM capture_lock_checks k LEFT JOIN captures c USING(operation_id) WHERE c.operation_id IS NULL OR c.state<>'succeeded' \
                OR k.objects<>(SELECT count(*) FROM capture_object_retention o WHERE o.operation_id=k.operation_id) \
                OR k.objects-1<>(SELECT max(position) FROM capture_object_retention o WHERE o.operation_id=k.operation_id) \
                OR 1<>(SELECT count(*) FROM capture_object_retention o WHERE o.operation_id=k.operation_id AND o.kind='snapshot') \
                OR 1<>(SELECT count(*) FROM capture_object_retention o WHERE o.operation_id=k.operation_id AND o.kind='snapshot' AND o.object_id=c.snapshot_id)) \
             OR EXISTS(SELECT 1 FROM capture_object_retention o LEFT JOIN capture_lock_checks k USING(operation_id) WHERE k.operation_id IS NULL)",
            [],
            |row| row.get(0),
        )
        .map_err(storage::unavailable)?;
    if contradicted {
        return Err(JournalError::Unavailable);
    }
    Ok(())
}
