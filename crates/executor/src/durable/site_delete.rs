//! D-085 (W522): admission of a signed `site_delete` and its removal.

use rustiron_journal::{DeleteResult, Deletion, ProvisionState, StepState};

use super::{Executor, signed_inputs};
use crate::{
    AdmissionRequest, ExecutorError,
    admin_helper::{self, AdminRequest, AdminStep},
    ols,
    provision::SiteLayout,
};

impl Executor {
    /// Admits one signed deletion of a live site that a signed activation
    /// already took offline, then asks the admin helper to remove it. The
    /// journal rechecks the site, its open work, and its capture in the
    /// transaction that marks it `deleted`. A readable outcome is recorded
    /// `done` or `failed`; a lost reply leaves the row `intent` for
    /// `delete-reconcile`. An exact repeat returns the stored row and runs
    /// nothing.
    pub fn delete_site(
        &mut self,
        request: &AdmissionRequest<'_>,
    ) -> Result<DeleteResult, ExecutorError> {
        let intent = crate::verified_delete(&self.anchor, request)?;
        self.check_identity(&intent.host_id, &intent.host_epoch)?;
        let now = request.now.ok_or(ExecutorError::TimeDenied)?;
        if self
            .journal
            .deletion_status(&intent.operation_id)?
            .is_none()
        {
            // Fresh preconditions before intent: the site is the journal's,
            // not ejected, and no generation that OLS serves names it.
            let provision = self
                .journal
                .provision_for_site(&intent.site_id)?
                .ok_or(ExecutorError::PreconditionChanged)?;
            if !matches!(
                provision.state,
                ProvisionState::Succeeded | ProvisionState::Deleted
            ) || provision.intent.hostname != intent.hostname
                || self.journal.ejected_sites()?.contains(&intent.site_id)
            {
                return Err(ExecutorError::PreconditionChanged);
            }
            // W576 (D-095) / W603-F5 (D-099): a schema 2 deletion names no
            // capture for a pure proxy site or an undeployed app site; a
            // deployed app site requires a schema 1 capture, enforced in the
            // journal recording transaction.
            let is_app = self.journal.app_facts_by_site(&intent.site_id)?.is_some();
            let proxy = self
                .journal
                .proxy_facts(&provision.intent.operation_id)?
                .is_some();
            if !is_app && proxy != intent.capture_operation_id.is_none() {
                return Err(ExecutorError::PreconditionChanged);
            }
            let include = ols::open_include()?;
            let live = ols::observe(&include)?;
            if ols::managed_accounts(&include, &live.0)?
                .contains(&SiteLayout::derive(&intent.site_id).account)
            {
                return Err(ExecutorError::PreconditionChanged);
            }
            // Only the admin helper removes a site; without it nothing is
            // recorded.
            if self.anchor.admin_socket.is_none() {
                return Err(ExecutorError::Unavailable);
            }
        }
        let deletion = match self.admit(signed_inputs(request)?, |journal| {
            journal.record_deletion(&intent, now)
        })? {
            DeleteResult::Existing(existing) => return Ok(DeleteResult::Existing(existing)),
            DeleteResult::New(deletion) => deletion,
        };
        Ok(DeleteResult::New(self.run_deletion(&deletion)?))
    }

    /// Asks the admin helper to remove the site of an open deletion and
    /// records the readable outcome.
    fn run_deletion(&mut self, deletion: &Deletion) -> Result<Deletion, ExecutorError> {
        let outcome = admin_helper::route(
            self.anchor.admin_socket.as_deref(),
            &AdminRequest {
                operation_id: deletion.provision_operation_id.clone(),
                step: AdminStep::SiteDelete,
            },
            || {
                let provision = self
                    .journal
                    .provision_status(&deletion.provision_operation_id)?
                    .ok_or(ExecutorError::Unavailable)?;
                crate::site_delete::remove(&provision)
            },
        )
        // W523-F2: the executor's own state; the helper only reads it.
        .and_then(|()| {
            crate::site_delete::remove_update_intake(
                std::path::Path::new(crate::layout::UPDATE_INTAKE_DIR),
                &deletion.site_id,
            )
        });
        let recorded = self
            .journal
            .finish_deletion(&deletion.operation_id, outcome.is_ok())?;
        outcome?;
        Ok(recorded)
    }

    /// W522: settles an open deletion (D-085 step 8): runs the removal again
    /// and records its readable outcome. A settled deletion is returned as
    /// it is.
    pub fn reconcile_deletion(
        &mut self,
        operation_id: &rustiron_contracts::Id,
    ) -> Result<Deletion, ExecutorError> {
        let deletion = self
            .journal
            .deletion_status(operation_id)?
            .ok_or(ExecutorError::NotAdmitted)?;
        if deletion.state != StepState::Intent {
            return Ok(deletion);
        }
        self.run_deletion(&deletion)
    }

    /// W522: a stored deletion, for status.
    pub fn deletion_status(
        &self,
        operation_id: &rustiron_contracts::Id,
    ) -> Result<Option<Deletion>, ExecutorError> {
        Ok(self.journal.deletion_status(operation_id)?)
    }
}
