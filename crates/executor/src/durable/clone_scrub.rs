//! D-078 signed clone scrub (W538): admission of a signed `clone_scrub` of
//! a quarantined clone and its removal through the admin helper.

use super::Executor;
use crate::{
    AdmissionRequest, ExecutorError,
    admin_helper::{self, AdminRequest, AdminStep},
};
use rustiron_journal::{Admitted, CloneScrubGrant, ProvisionState};

impl Executor {
    /// Admits one signed scrub of a quarantined clone and asks the admin
    /// helper to remove the clone's leftovers with the W501 removal. The
    /// journal rechecks the clone in the transaction that records the scrub
    /// and opens the clone's own scrub. A readable outcome is recorded
    /// `done` or `failed`; a failed scrub may be retried by a new signed
    /// request. An exact repeat returns the stored row and runs nothing.
    pub fn scrub_clone(
        &mut self,
        request: &AdmissionRequest<'_>,
    ) -> Result<Admitted<CloneScrubGrant>, ExecutorError> {
        let intent = crate::verified_clone_scrub(&self.anchor, request)?;
        let grant = match self.admit_signed(
            request,
            (&intent.host_id, &intent.host_epoch),
            |journal| Ok(journal.clone_scrub_status(&intent.operation_id)?.is_some()),
            |executor, _now| {
                let quarantined = executor
                    .journal
                    .provision_status(&intent.clone_operation_id)?
                    .is_some_and(|provision| {
                        provision.intent.site_id == intent.site_id
                            && provision.state == ProvisionState::Quarantined
                    });
                let clone = executor.journal.clone_status(&intent.clone_operation_id)?;
                if !quarantined || clone.is_none() {
                    return Err(ExecutorError::PreconditionChanged);
                }
                if executor.anchor.admin_socket.is_none() {
                    return Err(ExecutorError::Unavailable);
                }
                Ok(())
            },
            |journal, now| journal.record_clone_scrub(&intent, now),
        )? {
            Admitted::Existing(existing) => {
                return Ok(Admitted::Existing(existing));
            }
            Admitted::New(grant) => grant,
        };
        let site = intent.site_id.clone();
        let outcome = admin_helper::route(
            self.anchor.admin_socket.as_deref(),
            &AdminRequest {
                operation_id: intent.clone_operation_id.clone(),
                step: AdminStep::CloneScrub,
            },
            || crate::staging_clone::scrub_site(&crate::provision::SiteLayout::derive(&site)),
        );
        let recorded = self
            .journal
            .finish_signed_clone_scrub(&grant.operation_id, outcome.is_ok())?;
        outcome?;
        Ok(Admitted::New(recorded))
    }

    /// W538: a stored signed clone scrub, for status.
    pub fn clone_scrub_status(
        &self,
        operation_id: &rustiron_contracts::Id,
    ) -> Result<Option<CloneScrubGrant>, ExecutorError> {
        Ok(self.journal.clone_scrub_status(operation_id)?)
    }
}
