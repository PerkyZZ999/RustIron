//! D-089 (W543): admission of a signed `site_restore` and its attempts.

use rustiron_contracts::Id;

use super::Executor;
use crate::{
    AdmissionRequest, ExecutorError,
    admin_helper::{self, AdminRequest, AdminStep},
    ols,
    provision::SiteLayout,
};
use rustiron_journal::{Admitted, RestoreFrom, RestoreState, SiteRestore, StepState};

impl Executor {
    /// Admits one signed restore of a live site from its own capture, then
    /// runs attempt 0 through the admin helper, one recorded step at a
    /// time. The journal rechecks the site and both captures in the
    /// transaction that records the intent. A failed step leaves the
    /// restore open, the site in maintenance mode, and the error in the
    /// reply; `restore-reconcile` opens the next attempt. An exact repeat
    /// returns the stored restore and runs nothing.
    pub fn restore_site(
        &mut self,
        request: &AdmissionRequest<'_>,
    ) -> Result<Admitted<SiteRestore>, ExecutorError> {
        let (intent, destination_digest) = crate::verified_restore(&self.anchor, request)?;
        let restore = match self.admit_signed(
            request,
            (&intent.host_id, &intent.host_epoch),
            |journal| Ok(journal.site_restore_status(&intent.operation_id)?.is_some()),
            |executor, now| {
                if !executor.journal.site_restore_basis_holds(&intent, now)? {
                    return Err(ExecutorError::PreconditionChanged);
                }
                // Both captures were written to the destination as it is
                // enrolled now, so the safety capture can always come back.
                for operation in [
                    &intent.capture_operation_id,
                    &intent.safety_capture_operation_id,
                ] {
                    let capture = executor
                        .journal
                        .capture_status(operation)?
                        .ok_or(ExecutorError::PreconditionChanged)?;
                    if capture.backup_policy_digest.as_ref() != Some(&destination_digest) {
                        return Err(ExecutorError::PreconditionChanged);
                    }
                }
                let include = ols::open_include()?;
                let live = ols::observe(&include)?;
                if !ols::managed_accounts(&include, &live.0)?
                    .contains(&SiteLayout::derive(&intent.site_id).account)
                {
                    return Err(ExecutorError::PreconditionChanged);
                }
                // Only the admin helper runs restore steps; without it nothing
                // is recorded.
                if executor.anchor.admin_socket.is_none() {
                    return Err(ExecutorError::Unavailable);
                }
                Ok(())
            },
            |journal, now| journal.record_site_restore(&intent, now),
        )? {
            Admitted::Existing(existing) => return Ok(Admitted::Existing(existing)),
            Admitted::New(restore) => restore,
        };
        self.run_restore(&restore.operation_id).map(Admitted::New)
    }

    /// Runs the open attempt's remaining steps: each step's intent is
    /// recorded before the admin helper runs it and its outcome after. A
    /// lost reply counts as failed. Returns the stored restore after the
    /// Health step, or the step's error after a failed one.
    fn run_restore(&mut self, operation: &Id) -> Result<SiteRestore, ExecutorError> {
        let socket = self.anchor.admin_socket.clone();
        loop {
            let restore = self
                .journal
                .site_restore_status(operation)?
                .ok_or(ExecutorError::Unavailable)?;
            let attempt = restore.current().ok_or(ExecutorError::Unavailable)?;
            if restore.state != RestoreState::Intent
                || attempt.state != StepState::Intent
                || attempt
                    .steps
                    .last()
                    .is_some_and(|last| last.state != StepState::Done)
            {
                return Ok(restore);
            }
            let sequence = rustiron_journal::RestoreStep::sequence(restore.scope);
            let step = *sequence
                .get(attempt.steps.len())
                .ok_or(ExecutorError::Unavailable)?;
            self.journal.begin_restore_step(operation, step)?;
            let outcome = admin_helper::route(
                socket.as_deref(),
                &AdminRequest {
                    operation_id: operation.clone(),
                    step: AdminStep::RestoreStep,
                },
                || Err(ExecutorError::Unavailable),
            );
            self.journal
                .finish_restore_step(operation, step, outcome.is_ok())?;
            outcome?;
        }
    }

    /// W543: the operator's reconcile of an open restore, with the executor
    /// service stopped. An attempt left open is settled `failed` first; the
    /// next attempt then restores the signed capture again, or the safety
    /// capture, through the admin helper. A finished restore is returned
    /// unchanged.
    pub fn reconcile_restore(
        &mut self,
        operation: &Id,
        from: RestoreFrom,
    ) -> Result<SiteRestore, ExecutorError> {
        let restore = self
            .journal
            .site_restore_status(operation)?
            .ok_or(ExecutorError::NotAdmitted)?;
        if restore.state != RestoreState::Intent {
            return Ok(restore);
        }
        if self.anchor.admin_socket.is_none() {
            return Err(ExecutorError::Unavailable);
        }
        if restore
            .current()
            .is_some_and(|attempt| attempt.state == StepState::Intent)
        {
            self.journal.settle_restore_attempt(operation)?;
        }
        self.journal.begin_restore_attempt(operation, from)?;
        self.run_restore(operation)
    }

    /// W543: a stored restore, for status.
    pub fn site_restore_status(
        &self,
        operation: &Id,
    ) -> Result<Option<SiteRestore>, ExecutorError> {
        Ok(self.journal.site_restore_status(operation)?)
    }
}
