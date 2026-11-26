//! W356 (B09): the product capture run behind the write gate, design steps
//! 2 to 10 of [product capture effects].
//!
//! The admin helper binds the journaled projection digest (step 1) and
//! checks [`crate::write_gate`] first. Every store phase then runs one fixed
//! worker action in the verified store namespace through
//! [`crate::store_network`], which picks the key pair from the action: the
//! capture principal only for the lock reads and the snapshot write (steps
//! 3, 6 and 9), the fetch principal for the rest (steps 2, 7, 8 and 10).
//! The dump and marker units (steps 4 and 5) are the lab's, with no store
//! destination: private network and hidden credential directories.
//!
//! A refusal before the snapshot worker starts is a known failure. From the
//! start of step 6 any failure is uncertain, so the capture stays `running`
//! for reconciliation.
//!
//! [product capture effects]: ../../../docs/technical/PRODUCT-CAPTURE-EFFECTS.md

use rustiron_contracts::{
    Id, Timestamp,
    approval::{ProductBackupPolicy, SiteId},
};
use rustiron_journal::{Capture, CaptureConsistency, FixtureJournal, UnmatchedReason};

use crate::{
    ExecutorError, TrustAnchor,
    capture::{self, CaptureOutcome, CapturedSnapshot, Freeze, Phase},
    provision::SiteLayout,
    retention_evidence::{self, LockReading, WrittenIndexes},
    store_network::{self, WriteFailure, WrittenSnapshot},
};

/// The store phases of one product capture. Each method is one worker
/// action; the real store is [`EnrolledStore`].
pub(crate) trait Store {
    /// Step 2: `repo-id` with the fetch key pair.
    fn repository(&mut self) -> Result<(), ExecutorError>;
    /// Steps 3 and 9: `lock [OPERATION INDEXES]` with the capture key pair. W391:
    /// a pass returns what the worker read back.
    fn lock(
        &mut self,
        written: Option<(&Id, &WrittenIndexes)>,
    ) -> Result<LockReading, ExecutorError>;
    /// Step 6: the gated `backup` with the capture key pair.
    fn write(&mut self, operation: &Id) -> Result<WrittenSnapshot, WriteFailure>;
    /// Step 7: `check` with the fetch key pair.
    fn check(&mut self) -> Result<(), ExecutorError>;
    /// Step 8: `snapshot-tag OPERATION` with the fetch key pair.
    fn find(&mut self, operation: &Id) -> Result<Option<String>, ExecutorError>;
    /// Step 10: `manifest SNAPSHOT` with the fetch key pair.
    fn manifest(&mut self, snapshot: &str) -> Result<Vec<u8>, ExecutorError>;
}

/// The enrolled store of one site, reached only through the store namespace.
pub(crate) struct EnrolledStore<'a> {
    /// Trust anchor of the policy directory and credential sources.
    pub(crate) anchor: &'a TrustAnchor,
    /// The admitted projection, re-bound to the journaled digest.
    pub(crate) policy: &'a ProductBackupPolicy,
    /// The captured site.
    pub(crate) site: &'a SiteId,
    /// The site's MCS level.
    pub(crate) level: &'a str,
    /// W601 (D-096/P30): `true` for P27/EmDash apps (`data/` + SQLite bundle).
    pub(crate) is_app: bool,
}

impl Store for EnrolledStore<'_> {
    fn repository(&mut self) -> Result<(), ExecutorError> {
        store_network::check_repository(self.anchor, self.policy, self.site, self.level)
    }

    fn lock(
        &mut self,
        written: Option<(&Id, &WrittenIndexes)>,
    ) -> Result<LockReading, ExecutorError> {
        store_network::check_lock(self.anchor, self.policy, self.site, self.level, written)
    }

    fn write(&mut self, operation: &Id) -> Result<WrittenSnapshot, WriteFailure> {
        if self.is_app {
            store_network::write_app_snapshot(
                self.anchor,
                self.policy,
                self.site,
                self.level,
                operation,
            )
        } else {
            store_network::write_snapshot(
                self.anchor,
                self.policy,
                self.site,
                self.level,
                operation,
            )
        }
    }

    fn check(&mut self) -> Result<(), ExecutorError> {
        store_network::check_structure(self.anchor, self.policy, self.site, self.level)
    }

    fn find(&mut self, operation: &Id) -> Result<Option<String>, ExecutorError> {
        store_network::find_tagged_snapshot(
            self.anchor,
            self.policy,
            self.site,
            self.level,
            operation,
        )
    }

    fn manifest(&mut self, snapshot: &str) -> Result<Vec<u8>, ExecutorError> {
        store_network::snapshot_manifest(self.anchor, self.policy, self.site, self.level, snapshot)
    }
}

/// W601 (D-096/P30): runs product capture steps 2 to 10 for the site at
/// `layout`, handling both WordPress/static sites (`app = None`) and
/// P27/EmDash apps (`app = Some(facts)` with SQLite online backup + `data/`
/// uploads).
pub(crate) fn capture_site_for(
    anchor: &TrustAnchor,
    policy: &ProductBackupPolicy,
    site: &SiteId,
    layout: &SiteLayout,
    operation: &Id,
    frozen: bool,
    app: Option<&rustiron_journal::AppFacts>,
) -> CaptureOutcome {
    let level = match capture::site_level(layout) {
        Ok(level) => level,
        Err(error) => return CaptureOutcome::NotStarted(error),
    };
    let Some(root) = layout.root.to_str() else {
        return CaptureOutcome::NotStarted(ExecutorError::StepFailed);
    };
    let mut store = EnrolledStore {
        anchor,
        policy,
        site,
        level: &level,
        is_app: app.is_some(),
    };
    if let Some(facts) = app {
        let mut freeze = match frozen.then(|| {
            crate::app_site::AppFreeze::new(&layout.account, facts.worker_entrypoint.is_some())
        }) {
            None => None,
            Some(Ok(f)) => Some(f),
            Some(Err(error)) => return CaptureOutcome::NotStarted(error),
        };
        return capture_app_steps(
            root,
            &layout.account,
            operation,
            &mut store,
            |phase, command| capture::run_local_unit(layout, &level, phase, command),
            || crate::app_site::remove_app_bundle(layout),
            freeze.as_mut().map(|f| f as &mut dyn Freeze),
        );
    }
    let mut freeze = match frozen.then(|| capture::SystemdFreeze::new(&layout.account)) {
        None => None,
        Some(Ok(freeze)) => Some(freeze),
        Some(Err(error)) => return CaptureOutcome::NotStarted(error),
    };
    capture_steps(
        root,
        &layout.account,
        operation,
        &mut store,
        |phase, command| capture::run_local_unit(layout, &level, phase, command),
        || capture::remove_dump(layout),
        freeze.as_mut().map(|f| f as &mut dyn Freeze),
    )
}

fn read_app_marker(
    account: &str,
    run: &mut impl FnMut(Phase, &[&str]) -> Result<String, ExecutorError>,
) -> Option<String> {
    let worker = format!("{}/{}", crate::layout::JOB_BIN_DIR, crate::manifest::WORKER);
    run(Phase::AppMarker, &[&worker, "app-sqlite-marker", account])
        .ok()
        .filter(|out| !out.is_empty())
}

/// W601 (D-096/P30): product capture sequence for a P27/EmDash app site
/// (SQLite online backup + `data/` uploads, consistency marker, Object Lock
/// precheck/postcheck, and canonical `data/` manifest).
pub(crate) fn capture_app_steps(
    root: &str,
    account: &str,
    operation: &Id,
    store: &mut impl Store,
    mut run: impl FnMut(Phase, &[&str]) -> Result<String, ExecutorError>,
    remove: impl FnOnce() -> Result<(), ExecutorError>,
    mut freeze: Option<&mut dyn Freeze>,
) -> CaptureOutcome {
    if let Err(error) = store.repository() {
        return CaptureOutcome::NotStarted(error);
    }
    let Ok(precheck) = store.lock(None) else {
        return CaptureOutcome::NotStarted(ExecutorError::RetentionUnverified);
    };
    if let Some(f) = freeze.as_deref_mut()
        && let Err(error) = f.arm().and_then(|()| f.stop())
    {
        f.thaw();
        return CaptureOutcome::NotStarted(error);
    }
    let before = read_app_marker(account, &mut run);
    let worker = format!("{}/{}", crate::layout::JOB_BIN_DIR, crate::manifest::WORKER);
    let outcome = match run(Phase::AppDump, &[&worker, "app-sqlite-backup", account]) {
        Err(error) => CaptureOutcome::NotStarted(error),
        Ok(_) => {
            let written = match store.write(operation) {
                Ok(written) => written,
                Err(WriteFailure::NotLaunched(error)) => {
                    return {
                        if let Some(f) = freeze.take() {
                            f.thaw();
                        }
                        capture::settle(remove(), CaptureOutcome::NotStarted(error))
                    };
                }
                Err(WriteFailure::Launched { error, snapshot }) => {
                    return {
                        if let Some(f) = freeze.take() {
                            f.thaw();
                        }
                        capture::settle(remove(), CaptureOutcome::Uncertain { error, snapshot })
                    };
                }
            };
            let mut snapshot = CapturedSnapshot {
                id: written.id,
                files: Some(written.files),
                bytes: Some(written.bytes),
                manifest: None,
                consistency: CaptureConsistency::Unmatched(UnmatchedReason::MarkerUnavailable),
                retention: None,
            };
            let after = read_app_marker(account, &mut run);
            let held = freeze.take().map(|f| {
                let held = f.held();
                f.thaw();
                held
            });
            snapshot.consistency = if held == Some(false) {
                CaptureConsistency::Unmatched(UnmatchedReason::FreezeNotHeld)
            } else {
                capture::compare(before.as_deref(), after.as_deref())
            };
            let uncertain = |error, id: &str| CaptureOutcome::Uncertain {
                error,
                snapshot: Some(id.to_owned()),
            };
            if let Err(error) = store.check() {
                uncertain(error, &snapshot.id)
            } else {
                match store.find(operation) {
                    Ok(Some(found)) if found == snapshot.id => {
                        let evidence = store
                            .lock(Some((operation, &written.indexes)))
                            .ok()
                            .filter(|postcheck| written.indexes.matches(postcheck))
                            .and_then(|postcheck| {
                                retention_evidence::evidence(&precheck, &postcheck, &snapshot.id)
                            });
                        match evidence {
                            None => uncertain(ExecutorError::RetentionUnverified, &snapshot.id),
                            Some(ev) => {
                                snapshot.retention = Some(ev);
                                let bundle = crate::app_site::app_bundle_path(root);
                                snapshot.manifest =
                                    store.manifest(&snapshot.id).ok().and_then(|lines| {
                                        crate::manifest::from_worker_for(
                                            &lines, root, "data", &bundle,
                                        )
                                    });
                                CaptureOutcome::Succeeded(snapshot)
                            }
                        }
                    }
                    Ok(_) => uncertain(ExecutorError::PreconditionChanged, &snapshot.id),
                    Err(error) => uncertain(error, &snapshot.id),
                }
            }
        }
    };
    if let Some(f) = freeze.take() {
        f.thaw();
    }
    capture::settle(remove(), outcome)
}

/// The product sequence over a store and a local unit runner, so its order
/// and outcome mapping are tested without systemd. `run` starts only the
/// dump and marker units.
pub(crate) fn capture_steps(
    root: &str,
    account: &str,
    operation: &Id,
    store: &mut impl Store,
    mut run: impl FnMut(Phase, &[&str]) -> Result<String, ExecutorError>,
    remove: impl FnOnce() -> Result<(), ExecutorError>,
    mut freeze: Option<&mut dyn Freeze>,
) -> CaptureOutcome {
    // Steps 2 and 3 refuse before any dump or write.
    if let Err(error) = store.repository() {
        return CaptureOutcome::NotStarted(error);
    }
    let Ok(precheck) = store.lock(None) else {
        return CaptureOutcome::NotStarted(ExecutorError::RetentionUnverified);
    };
    if let Some(f) = freeze.as_deref_mut()
        && let Err(error) = f.arm().and_then(|()| f.stop())
    {
        f.thaw();
        return CaptureOutcome::NotStarted(error);
    }
    // Step 5 before step 4: an equal reading after the file walk means no
    // committed change in the whole dump-to-walk window (W252).
    let before = capture::read_marker(&mut run, root, account);
    let command = capture::dump_command(root, account);
    let borrowed: Vec<&str> = command.iter().map(String::as_str).collect();
    let outcome = match run(Phase::Dump, &borrowed) {
        Err(error) => CaptureOutcome::NotStarted(error),
        Ok(_) => write_and_verify(
            store,
            &mut run,
            root,
            account,
            operation,
            (before, &precheck),
            &mut freeze,
        ),
    };
    if let Some(f) = freeze.take() {
        f.thaw();
    }
    capture::settle(remove(), outcome)
}

/// Steps 6 to 10. Only a failure of the store checks before the write
/// worker starts is still a known failure. `prior` is the marker read
/// before the dump and the step 3 lock reading.
fn write_and_verify(
    store: &mut impl Store,
    run: &mut impl FnMut(Phase, &[&str]) -> Result<String, ExecutorError>,
    root: &str,
    account: &str,
    operation: &Id,
    prior: (Option<String>, &LockReading),
    freeze: &mut Option<&mut dyn Freeze>,
) -> CaptureOutcome {
    let (before, precheck) = prior;
    let written = match store.write(operation) {
        Ok(written) => written,
        Err(WriteFailure::NotLaunched(error)) => return CaptureOutcome::NotStarted(error),
        Err(WriteFailure::Launched { error, snapshot }) => {
            return CaptureOutcome::Uncertain { error, snapshot };
        }
    };
    let mut snapshot = CapturedSnapshot {
        id: written.id,
        files: Some(written.files),
        bytes: Some(written.bytes),
        manifest: None,
        consistency: CaptureConsistency::Unmatched(UnmatchedReason::MarkerUnavailable),
        retention: None,
    };
    // Read as soon as the file walk ends (W254); then judge the freeze and
    // give the site its PHP back at once (W258).
    let after = capture::read_marker(run, root, account);
    let held = freeze.take().map(|f| {
        let held = f.held();
        f.thaw();
        held
    });
    snapshot.consistency = if held == Some(false) {
        CaptureConsistency::Unmatched(UnmatchedReason::FreezeNotHeld)
    } else {
        capture::compare(before.as_deref(), after.as_deref())
    };
    let uncertain = |error, id: &str| CaptureOutcome::Uncertain {
        error,
        snapshot: Some(id.to_owned()),
    };
    if let Err(error) = store.check() {
        return uncertain(error, &snapshot.id);
    }
    // Step 8: the tag lists exactly the snapshot the write named.
    match store.find(operation) {
        Ok(Some(found)) if found == snapshot.id => {}
        Ok(_) => return uncertain(ExecutorError::PreconditionChanged, &snapshot.id),
        Err(error) => return uncertain(error, &snapshot.id),
    }
    // Step 9: the bucket lock still holds, and every object this capture
    // wrote carries COMPLIANCE retention for the enrolled days. W391: the
    // versions read back are the capture's retention evidence; a reading
    // that does not name this snapshot once is not verified.
    let evidence = store
        .lock(Some((operation, &written.indexes)))
        .ok()
        .filter(|postcheck| written.indexes.matches(postcheck))
        .and_then(|postcheck| retention_evidence::evidence(precheck, &postcheck, &snapshot.id));
    let Some(evidence) = evidence else {
        return uncertain(ExecutorError::RetentionUnverified, &snapshot.id);
    };
    snapshot.retention = Some(evidence);
    // Step 10: a failed, malformed, oversized or refused listing only leaves
    // the manifest unrecorded; the capture has succeeded (W203).
    let dump = capture::dump_path(root);
    snapshot.manifest = store
        .manifest(&snapshot.id)
        .ok()
        .and_then(|lines| crate::manifest::from_worker(&lines, root, &dump));
    CaptureOutcome::Succeeded(snapshot)
}

/// What recovery of a product capture left `running` may record when the
/// operation tag is found (W321, W366). Neither mode records `succeeded`:
/// a tag cannot show that restic read every source file, nor that the
/// check, find and lock postcheck passed for this write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Recovery {
    /// `capture-reconcile OP` (W321): `failed` only when no snapshot
    /// carries the tag; a tagged snapshot leaves the capture `running`.
    Reconcile,
    /// `capture-reconcile OP --settle-unclaimed` (W366): as `Reconcile`,
    /// but the one tagged snapshot settles the capture `failed` and is kept
    /// only as unclaimed evidence.
    SettleUnclaimed,
}

/// Records the result of one fresh tag lookup for the `running` capture
/// `operation`. A failed lookup records nothing, so the capture stays
/// `running`. `now` must not precede the capture's start.
pub(crate) fn record_recovery(
    journal: &mut FixtureJournal,
    operation: &Id,
    mode: Recovery,
    found: Result<Option<String>, ExecutorError>,
    now: Timestamp,
) -> Result<Capture, ExecutorError> {
    match (found?, mode) {
        (None, _) => Ok(journal.reconcile_finish_capture(operation, None, now)?),
        (Some(snapshot), Recovery::SettleUnclaimed) => {
            Ok(journal.settle_capture_unclaimed(operation, &snapshot, now)?)
        }
        (Some(snapshot), Recovery::Reconcile) => {
            // Restic can persist a tagged snapshot even when it exits 3.
            eprintln!(
                "{}",
                serde_json::json!({
                    "scope": "product_capture_reconcile",
                    "operation_id": operation.as_str(),
                    "outcome": "unexplained_snapshot",
                    "snapshot_id": snapshot,
                })
            );
            Err(ExecutorError::PreconditionChanged)
        }
    }
}

#[cfg(test)]
#[path = "product_capture_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "product_capture_recovery_tests.rs"]
mod recovery_tests;
