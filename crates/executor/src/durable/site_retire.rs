//! D-080 (W508): admission of a signed `site_retire` and its removal.

use rustiron_journal::{ProvisionState, RetireResult, StepState};

use super::{Executor, signed_inputs};
use crate::{
    AdmissionRequest, ExecutorError,
    admin_helper::{self, AdminRequest, AdminStep},
};

impl Executor {
    /// Admits one signed retirement of a quarantined site and asks the
    /// admin helper to remove what its recorded steps made. A readable
    /// outcome is recorded `done` or `failed`; a lost reply leaves the row
    /// `intent` for an operator check. An exact repeat returns the stored
    /// row and runs nothing.
    pub fn retire_site(
        &mut self,
        request: &AdmissionRequest<'_>,
    ) -> Result<RetireResult, ExecutorError> {
        let intent = crate::verified_retire(&self.anchor, request)?;
        self.check_identity(&intent.host_id, &intent.host_epoch)?;
        let now = request.now.ok_or(ExecutorError::TimeDenied)?;
        if self
            .journal
            .retirement_status(&intent.operation_id)?
            .is_none()
        {
            // Fresh preconditions before intent; the journal rechecks the
            // provision in the transaction that records it.
            let provision = self
                .journal
                .provision_status(&intent.provision_operation_id)?
                .ok_or(ExecutorError::PreconditionChanged)?;
            let open_scrub = self
                .journal
                .import_status(&intent.provision_operation_id)?
                .is_some_and(|import| {
                    import
                        .scrubs
                        .iter()
                        .any(|scrub| scrub.state == StepState::Intent)
                })
                || self
                    .journal
                    .clone_status(&intent.provision_operation_id)?
                    .is_some_and(|clone| clone.scrub == Some(StepState::Intent));
            if provision.intent.site_id != intent.site_id
                || provision.state != ProvisionState::Quarantined
                || self.journal.ejected_sites()?.contains(&intent.site_id)
                || open_scrub
            {
                return Err(ExecutorError::PreconditionChanged);
            }
        }
        let retirement = match self.admit(signed_inputs(request)?, |journal| {
            journal.record_retirement(&intent, now)
        })? {
            RetireResult::Existing(existing) => return Ok(RetireResult::Existing(existing)),
            RetireResult::New(retirement) => retirement,
        };
        let outcome = admin_helper::route(
            self.anchor.admin_socket.as_deref(),
            &AdminRequest {
                operation_id: intent.provision_operation_id.clone(),
                step: AdminStep::SiteRetire,
            },
            || {
                let provision = self
                    .journal
                    .provision_status(&intent.provision_operation_id)?
                    .ok_or(ExecutorError::Unavailable)?;
                crate::site_retire::remove(&provision)
            },
        );
        let recorded = self
            .journal
            .finish_retirement(&retirement.operation_id, outcome.is_ok())?;
        outcome?;
        Ok(RetireResult::New(recorded))
    }

    /// W508: a stored retirement, for status.
    pub fn retirement_status(
        &self,
        operation_id: &rustiron_contracts::Id,
    ) -> Result<Option<rustiron_journal::Retirement>, ExecutorError> {
        Ok(self.journal.retirement_status(operation_id)?)
    }
}
