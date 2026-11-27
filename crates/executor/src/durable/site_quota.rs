//! D-088 (W535): admission of a signed `site_quota` change and its effect.

use super::Executor;
use crate::{
    AdmissionRequest, ExecutorError,
    admin_helper::{self, AdminRequest, AdminStep},
};
use rustiron_journal::{Admitted, QuotaChange, StepState};

impl Executor {
    /// Admits one signed change of a site's hard quota limits, then asks the
    /// admin helper to set and read them back. The new limits must be within
    /// the enrolled cap; the helper refuses limits at or below the current
    /// use. A readable outcome is recorded `done` or `failed`; a lost reply
    /// leaves the row `intent` for `quota-reconcile`. An exact repeat returns
    /// the stored row and runs nothing.
    pub fn change_quota(
        &mut self,
        request: &AdmissionRequest<'_>,
    ) -> Result<Admitted<QuotaChange>, ExecutorError> {
        let intent = crate::verified_quota(&self.anchor, request)?;
        let change = match self.admit_signed(
            request,
            (&intent.host_id, &intent.host_epoch),
            |journal| Ok(journal.quota_change_status(&intent.operation_id)?.is_some()),
            |executor, _now| {
                let owned = executor
                    .journal
                    .provision_for_site(&intent.site_id)?
                    .is_some_and(|provision| provision.state.is_owned());
                if !owned || executor.journal.ejected_sites()?.contains(&intent.site_id) {
                    return Err(ExecutorError::PreconditionChanged);
                }
                // The enrolled cap bounds every site; without one, the host
                // enforces no quota and there is nothing to change.
                let cap = crate::policy::load(
                    &crate::files::open_trusted_directory(
                        &executor.anchor.policy_dir,
                        executor.anchor.owner_uid,
                    )?,
                    executor.anchor.owner_uid,
                )?
                .policy
                .provisioning
                .and_then(|provisioning| provisioning.quota)
                .ok_or(ExecutorError::QuotaUnavailable)?;
                if intent.block_hard_kib > cap.block_hard_kib || intent.inode_hard > cap.inode_hard
                {
                    return Err(ExecutorError::PreconditionChanged);
                }
                if executor.anchor.admin_socket.is_none() {
                    return Err(ExecutorError::Unavailable);
                }
                Ok(())
            },
            |journal, now| journal.record_quota_change(&intent, now),
        )? {
            Admitted::Existing(existing) => {
                return Ok(Admitted::Existing(existing));
            }
            Admitted::New(change) => change,
        };
        Ok(Admitted::New(self.run_quota_change(&change)?))
    }

    /// Asks the admin helper to set the open change's limits and records the
    /// readable outcome.
    fn run_quota_change(&mut self, change: &QuotaChange) -> Result<QuotaChange, ExecutorError> {
        let provision = self
            .journal
            .provision_for_site(&change.site_id)?
            .ok_or(ExecutorError::Unavailable)?;
        let outcome = admin_helper::route(
            self.anchor.admin_socket.as_deref(),
            &AdminRequest {
                operation_id: provision.intent.operation_id,
                step: AdminStep::SiteQuotaSet,
            },
            || {
                crate::quota::change(
                    &mut crate::quota::SystemQuota,
                    &crate::provision::SiteLayout::derive(&change.site_id).account,
                    crate::quota::QuotaLimits {
                        block_hard_kib: change.block_hard_kib,
                        inode_hard: change.inode_hard,
                    },
                )
                .map(drop)
            },
        );
        let recorded = self
            .journal
            .finish_quota_change(&change.operation_id, outcome.is_ok())?;
        outcome?;
        Ok(recorded)
    }

    /// W535: settles an open quota change: sets its signed limits again and
    /// records the readable outcome. A settled change is returned as it is.
    pub fn reconcile_quota_change(
        &mut self,
        operation_id: &rustiron_contracts::Id,
    ) -> Result<QuotaChange, ExecutorError> {
        let change = self
            .journal
            .quota_change_status(operation_id)?
            .ok_or(ExecutorError::NotAdmitted)?;
        if change.state != StepState::Intent {
            return Ok(change);
        }
        self.run_quota_change(&change)
    }

    /// W535: a stored quota change, for status.
    pub fn quota_change_status(
        &self,
        operation_id: &rustiron_contracts::Id,
    ) -> Result<Option<QuotaChange>, ExecutorError> {
        Ok(self.journal.quota_change_status(operation_id)?)
    }
}
