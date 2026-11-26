//! D-084 (W515): admission of a signed `site_update` up to its intent.
//!
//! Every check before intent runs: the signature and binding, the served
//! and managed site, the site's newest succeeded capture from the last
//! hour, and the intake recipe whose manifest is the signed digest and
//! names the signed components in order. W516: then the intent, and the
//! steps through the admin helper, which alone touches the site.

use rustiron_journal::{UpdateResult, UpdateStep};

use super::{Executor, signed_inputs};
use crate::{
    AdmissionRequest, ExecutorError,
    admin_helper::{self, AdminRequest, AdminStep},
    ols,
    provision::SiteLayout,
};

impl Executor {
    /// W530 (D-087): the installed core, plugins, and themes of a site that
    /// the journal owns, read by the admin helper as the site. Read only;
    /// nothing is recorded.
    pub fn update_inventory(
        &self,
        site: &rustiron_contracts::approval::SiteId,
    ) -> Result<serde_json::Value, ExecutorError> {
        let provision = self
            .journal
            .provision_for_site(site)?
            .filter(|provision| provision.state.is_owned())
            .ok_or(ExecutorError::PreconditionChanged)?;
        // W574 (D-095): a proxy site has no WordPress.
        self.refuse_proxy_site(site)?;
        let socket = self
            .anchor
            .admin_socket
            .as_deref()
            .ok_or(ExecutorError::Unavailable)?;
        let request = AdminRequest {
            operation_id: provision.intent.operation_id.clone(),
            step: AdminStep::UpdateInventory,
        };
        match admin_helper::request(socket, &request)? {
            admin_helper::Reply::Done(Some(text)) => {
                serde_json::from_str(&text).map_err(|_| ExecutorError::StepFailed)
            }
            admin_helper::Reply::Done(None) => Err(ExecutorError::StepFailed),
            admin_helper::Reply::Refused(error) => Err(error),
        }
    }

    /// Checks one signed update up to its intent.
    pub fn update_site(
        &mut self,
        request: &AdmissionRequest<'_>,
    ) -> Result<UpdateResult, ExecutorError> {
        let intent = crate::verified_update(&self.anchor, request)?;
        self.check_identity(&intent.host_id, &intent.host_epoch)?;
        let now = request.now.ok_or(ExecutorError::TimeDenied)?;
        if let Some(existing) = self.journal.update_status(&intent.operation_id)? {
            return Ok(UpdateResult::Existing(existing));
        }
        let site = &intent.site_id;
        if !self.journal.succeeded_sites()?.contains(site)
            || self.journal.ejected_sites()?.contains(site)
        {
            return Err(ExecutorError::PreconditionChanged);
        }
        self.refuse_proxy_site(site)?;
        if !self.journal.update_basis_holds(&intent, now)? {
            return Err(ExecutorError::PreconditionChanged);
        }
        // The host checks follow the journal's: the site is in the current
        // generation's managed set, and the intake holds the signed recipe.
        let include = ols::open_include()?;
        let live = ols::observe(&include)?;
        if !ols::managed_accounts(&include, &live.0)?.contains(&SiteLayout::derive(site).account) {
            return Err(ExecutorError::PreconditionChanged);
        }
        let manifest = crate::site_update::intake_manifest(
            std::path::Path::new(crate::layout::UPDATE_INTAKE_DIR),
            self.anchor.owner_uid,
            site,
        )?;
        if !crate::site_update::manifest_matches(
            &manifest,
            &intent.recipe_digest,
            &intent.components,
        ) {
            return Err(ExecutorError::PreconditionChanged);
        }
        // Only the admin helper runs update steps; without it nothing is
        // recorded.
        if self.anchor.admin_socket.is_none() {
            return Err(ExecutorError::Unavailable);
        }
        let update = match self.admit(signed_inputs(request)?, |journal| {
            journal.record_update(&intent, now)
        })? {
            UpdateResult::Existing(existing) => return Ok(UpdateResult::Existing(existing)),
            UpdateResult::New(update) => update,
        };
        Ok(UpdateResult::New(self.run_update(&update.operation_id)?))
    }

    /// W516: each step's intent is recorded before the admin helper runs
    /// it and its outcome after. After a failed step the rollback's intent
    /// is recorded, the helper runs it, and its outcome ends the update
    /// `rolled_back` or leaves it open for an operator check. A step whose
    /// reply is lost counts as failed, so its rollback runs.
    fn run_update(
        &mut self,
        operation: &rustiron_contracts::Id,
    ) -> Result<rustiron_journal::SiteUpdate, ExecutorError> {
        let socket = self.anchor.admin_socket.clone();
        let ask = |step| AdminRequest {
            operation_id: operation.clone(),
            step,
        };
        for step in UpdateStep::ALL {
            self.journal.begin_update_step(operation, step)?;
            let outcome =
                admin_helper::route(socket.as_deref(), &ask(AdminStep::UpdateStep), || {
                    Err(ExecutorError::Unavailable)
                });
            let recorded = self
                .journal
                .finish_update_step(operation, step, outcome.is_ok())?;
            if outcome.is_ok() {
                if recorded.state == rustiron_journal::UpdateState::Done {
                    return Ok(recorded);
                }
                continue;
            }
            return self.roll_back(operation);
        }
        self.journal
            .update_status(operation)?
            .ok_or(ExecutorError::Unavailable)
    }

    /// The rollback's intent, the helper's rollback, and its outcome.
    fn roll_back(
        &mut self,
        operation: &rustiron_contracts::Id,
    ) -> Result<rustiron_journal::SiteUpdate, ExecutorError> {
        self.journal.begin_update_rollback(operation)?;
        let rolled = admin_helper::route(
            self.anchor.admin_socket.as_deref(),
            &AdminRequest {
                operation_id: operation.clone(),
                step: AdminStep::UpdateRollback,
            },
            || Err(ExecutorError::Unavailable),
        );
        Ok(self
            .journal
            .finish_update_rollback(operation, rolled.is_ok())?)
    }

    /// W518-F2: the operator's reconcile of an open update, with the
    /// executor service stopped. A step left open is recorded failed; the
    /// rollback (new, failed before, or left open) runs again through the
    /// admin helper, which restores the code and, if anything was swapped,
    /// the database; its outcome is recorded. A settled update is returned
    /// unchanged.
    pub fn reconcile_update(
        &mut self,
        operation: &rustiron_contracts::Id,
    ) -> Result<rustiron_journal::SiteUpdate, ExecutorError> {
        let update = self
            .journal
            .update_status(operation)?
            .ok_or(ExecutorError::NotAdmitted)?;
        if update.state != rustiron_journal::UpdateState::Intent {
            return Ok(update);
        }
        if self.anchor.admin_socket.is_none() {
            return Err(ExecutorError::Unavailable);
        }
        if update.rollback == Some(rustiron_journal::StepState::Intent) {
            // An interrupted rollback: record it failed, then begin it again.
            self.journal.finish_update_rollback(operation, false)?;
        } else if let Some(last) = update
            .steps
            .last()
            .filter(|last| last.state == rustiron_journal::StepState::Intent)
        {
            self.journal
                .finish_update_step(operation, last.step, false)?;
        }
        self.roll_back(operation)
    }

    /// W515: a stored update, for status.
    pub fn update_status(
        &self,
        operation_id: &rustiron_contracts::Id,
    ) -> Result<Option<rustiron_journal::SiteUpdate>, ExecutorError> {
        Ok(self.journal.update_status(operation_id)?)
    }
}
