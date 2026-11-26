//! Restore probes (schema v6): the throwaway probe account is recorded with
//! the intent, before any sandbox resource exists, so a crash always leaves a
//! record of exactly what to clean up. Outcomes: passed, failed (both with
//! complete cleanup) or cleanup_incomplete.

use rusqlite::{OptionalExtension, Row, params};
use rustiron_contracts::{
    Id, Timestamp,
    approval::{Sha256Digest, SiteId, SnapshotId},
};

use crate::{FixtureJournal, JournalError, storage};

const MAX_PROBES: i64 = 1000;

/// Immutable admitted restore probe; built by the executor from verified inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeIntent {
    /// Operation identity.
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
    /// Site whose snapshot is restored; needs a succeeded provision.
    pub site_id: SiteId,
    /// The snapshot to restore.
    pub snapshot_id: SnapshotId,
    /// Throwaway account `rp_<6 hex>`, chosen by the executor; unique.
    pub probe_account: String,
    /// Normal grant deadline for starting the probe.
    pub expires_at: Timestamp,
}

/// Recorded probe state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeState {
    /// Intent recorded; sandbox resources may exist.
    Running,
    /// Every receipt check the profile requires passed; cleanup complete.
    Passed,
    /// A check failed or did not run; cleanup complete.
    Failed,
    /// Sandbox resources may remain; needs admin cleanup.
    CleanupIncomplete,
}

/// Stored restore probe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Probe {
    /// Immutable admitted data.
    pub intent: ProbeIntent,
    /// Admission time.
    pub started_at: Timestamp,
    /// Current state.
    pub state: ProbeState,
    /// Bounded JSON receipt (seven fields kept separate) once finished.
    pub receipt: Option<String>,
    /// Outcome time.
    pub finished_at: Option<Timestamp>,
    /// Enrolled backup policy at admission. Absent in pre-v13 records.
    pub backup_policy_digest: Option<Sha256Digest>,
}

/// New durable probe, or status of an exact earlier one.
#[derive(Debug, Eq, PartialEq)]
pub enum ProbeResult {
    /// Intent committed; nonce consumed.
    New(Probe),
    /// Status only; never permission to probe again.
    Existing(Probe),
}

impl FixtureJournal {
    /// Records a probe intent (with its probe account) in one transaction,
    /// or returns exact status. One probe runs at a time.
    /// The backup policy digest is stored with the intent before any effect.
    pub fn record_probe(
        &mut self,
        intent: &ProbeIntent,
        now: Timestamp,
        backup_policy_digest: &Sha256Digest,
    ) -> Result<ProbeResult, JournalError> {
        let signed = self.take_signed(&crate::signed::Expected {
            plan_digest: &intent.plan_digest,
            grant_digest: &intent.grant_digest,
        })?;
        let account_ok = intent.probe_account.len() == 9
            && intent.probe_account.starts_with("rp_")
            && intent.probe_account[3..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !account_ok || intent.host_id != self.host_id || intent.host_epoch != self.host_epoch {
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
            return if existing.intent == *intent {
                Ok(ProbeResult::Existing(existing))
            } else {
                Err(JournalError::Conflict)
            };
        }
        let account_taken: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM restore_probes WHERE probe_account=?1)",
                [intent.probe_account.as_str()],
                |row| row.get(0),
            )
            .map_err(storage::unavailable)?;
        if account_taken {
            return Err(JournalError::Conflict);
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
                "SELECT EXISTS(SELECT 1 FROM restore_probes WHERE state IN ('running','cleanup_incomplete')), count(*) FROM restore_probes",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(storage::unavailable)?;
        if running || storage::readoption_verifying(&transaction)? {
            return Err(JournalError::Busy);
        }
        if count >= MAX_PROBES {
            return Err(JournalError::Capacity);
        }
        transaction
            .execute(
                "INSERT INTO restore_probes VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,'running',NULL,NULL)",
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
                    intent.snapshot_id.as_str(),
                    intent.probe_account,
                    intent.expires_at.get() as i64,
                    now.get() as i64
                ],
            )
            .map_err(storage::unavailable)?;
        transaction
            .execute(
                "INSERT INTO probe_backup_policy VALUES (?1,?2)",
                params![intent.operation_id.as_str(), backup_policy_digest.as_str()],
            )
            .map_err(storage::unavailable)?;
        crate::signed::insert(&transaction, &intent.operation_id, signed.as_ref())?;
        storage::set_clock(&transaction, now)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(ProbeResult::New(Probe {
            intent: intent.clone(),
            started_at: now,
            state: ProbeState::Running,
            receipt: None,
            finished_at: None,
            backup_policy_digest: Some(backup_policy_digest.clone()),
        }))
    }

    /// Records a running probe's outcome with its bounded receipt. A
    /// finished probe changes only from `cleanup_incomplete` to `failed`
    /// once admin cleanup removed everything.
    pub fn finish_probe(
        &mut self,
        operation_id: &Id,
        state: ProbeState,
        receipt: &str,
        now: Timestamp,
    ) -> Result<Probe, JournalError> {
        if state == ProbeState::Running || receipt.len() > 16384 {
            return Err(JournalError::Conflict);
        }
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let probe = find(&transaction, "operation_id", operation_id.as_str())?
            .ok_or(JournalError::Conflict)?;
        let allowed = match probe.state {
            ProbeState::Running => true,
            ProbeState::CleanupIncomplete => state == ProbeState::Failed,
            _ => false,
        };
        if !allowed || now.get() < probe.started_at.get() {
            return Err(JournalError::Conflict);
        }
        transaction
            .execute(
                "UPDATE restore_probes SET state=?1, receipt=?2, finished_at=?3 WHERE operation_id=?4",
                params![state_text(state), receipt, now.get() as i64, operation_id.as_str()],
            )
            .map_err(storage::unavailable)?;
        transaction.commit().map_err(storage::unavailable)?;
        self.probe_status(operation_id)?
            .ok_or(JournalError::Unavailable)
    }

    /// Recorded probe status only.
    pub fn probe_status(&self, operation_id: &Id) -> Result<Option<Probe>, JournalError> {
        find(&self.connection, "operation_id", operation_id.as_str())
    }
}

fn state_text(state: ProbeState) -> &'static str {
    match state {
        ProbeState::Running => "running",
        ProbeState::Passed => "passed",
        ProbeState::Failed => "failed",
        ProbeState::CleanupIncomplete => "cleanup_incomplete",
    }
}

pub(crate) fn find(
    c: &rusqlite::Connection,
    column: &str,
    value: &str,
) -> Result<Option<Probe>, JournalError> {
    let sql = match column {
        "operation_id" => {
            "SELECT restore_probes.*, probe_backup_policy.digest FROM restore_probes LEFT JOIN probe_backup_policy USING(operation_id) WHERE restore_probes.operation_id=?1"
        }
        _ => {
            "SELECT restore_probes.*, probe_backup_policy.digest FROM restore_probes LEFT JOIN probe_backup_policy USING(operation_id) WHERE restore_probes.idempotency_key=?1"
        }
    };
    c.query_row(sql, [value], decode)
        .optional()
        .map_err(storage::unavailable)?
        .transpose()
}

fn decode(row: &Row<'_>) -> rusqlite::Result<Result<Probe, JournalError>> {
    let text = |i: usize| row.get::<_, String>(i);
    let time = |i: usize| row.get::<_, i64>(i);
    let (op, key, grant, nonce, plan, gd, host, epoch, site, snapshot, account) = (
        text(0)?,
        text(1)?,
        text(2)?,
        text(3)?,
        text(4)?,
        text(5)?,
        text(6)?,
        text(7)?,
        text(8)?,
        text(9)?,
        text(10)?,
    );
    let (expires, started, state) = (time(11)?, time(12)?, text(13)?);
    let receipt: Option<String> = row.get(14)?;
    let finished: Option<i64> = row.get(15)?;
    let backup_policy_digest: Option<String> = row.get(16)?;
    let ts = |v: i64| {
        u64::try_from(v)
            .ok()
            .and_then(|v| Timestamp::try_from(v).ok())
            .ok_or(JournalError::Unavailable)
    };
    let id = |v: String| Id::try_from(v).map_err(|_| JournalError::Unavailable);
    let digest = |v: String| Sha256Digest::try_from(v).map_err(|_| JournalError::Unavailable);
    Ok((|| {
        Ok(Probe {
            intent: ProbeIntent {
                operation_id: id(op)?,
                idempotency_key: id(key)?,
                grant_id: id(grant)?,
                nonce: id(nonce)?,
                plan_digest: digest(plan)?,
                grant_digest: digest(gd)?,
                host_id: id(host)?,
                host_epoch: id(epoch)?,
                site_id: SiteId::try_from(site).map_err(|_| JournalError::Unavailable)?,
                snapshot_id: SnapshotId::try_from(snapshot)
                    .map_err(|_| JournalError::Unavailable)?,
                probe_account: account,
                expires_at: ts(expires)?,
            },
            started_at: ts(started)?,
            state: match state.as_str() {
                "running" => ProbeState::Running,
                "passed" => ProbeState::Passed,
                "failed" => ProbeState::Failed,
                "cleanup_incomplete" => ProbeState::CleanupIncomplete,
                _ => return Err(JournalError::Unavailable),
            },
            receipt,
            finished_at: finished.map(ts).transpose()?,
            backup_policy_digest: backup_policy_digest.map(digest).transpose()?,
        })
    })())
}

/// Opening refuses probes whose rows contradict their state or identity.
pub(crate) fn validate(
    c: &rusqlite::Connection,
    host: &Id,
    epoch: &Id,
) -> Result<(), JournalError> {
    let broken: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM restore_probes WHERE host_id<>?1 OR host_epoch<>?2 \
             OR (state='running' AND (receipt IS NOT NULL OR finished_at IS NOT NULL)) \
             OR (state<>'running' AND (receipt IS NULL OR finished_at IS NULL))) \
             OR EXISTS(SELECT 1 FROM probe_backup_policy b LEFT JOIN restore_probes p USING(operation_id) WHERE p.operation_id IS NULL)",
            params![host.as_str(), epoch.as_str()],
            |row| row.get(0),
        )
        .map_err(storage::unavailable)?;
    if broken {
        return Err(JournalError::Unavailable);
    }
    Ok(())
}
