//! D-091 (W563): admission of a signed `dns_zone_import` and its one step.

use rustiron_contracts::Id;

use super::Executor;
use crate::{
    AdmissionRequest, ExecutorError,
    admin_helper::{self, AdminRequest, AdminStep},
};
use rustiron_journal::{Admitted, DnsImport, StepState};

impl Executor {
    /// Admits one signed zone import, then asks the admin helper to load,
    /// publish, and read back the zone. Before intent, the intake file must
    /// have the signed digest and record-set count and the journal must own
    /// no live import of the zone; the helper refuses a zone that is already
    /// on the server before any effect. The readable outcome is recorded
    /// `done` or `failed`; a lost reply counts as failed. An exact repeat
    /// returns the stored import and runs nothing.
    pub fn import_dns_zone(
        &mut self,
        request: &AdmissionRequest<'_>,
    ) -> Result<Admitted<DnsImport>, ExecutorError> {
        let (intent, _dns) = crate::verified_dns_import(&self.anchor, request)?;
        let import = match self.admit_signed(
            request,
            (&intent.host_id, &intent.host_epoch),
            |journal| Ok(journal.dns_import_status(&intent.operation_id)?.is_some()),
            |executor, _now| {
                crate::dns_import::intake_zone(
                    std::path::Path::new(crate::layout::DNS_INTAKE_DIR),
                    executor.anchor.owner_uid,
                    &intent.zone,
                    &intent.zone_sha256,
                    intent.record_sets,
                )?;
                // Only the admin helper runs the import; without it nothing is
                // recorded.
                if executor.anchor.admin_socket.is_none() {
                    return Err(ExecutorError::Unavailable);
                }
                Ok(())
            },
            |journal, now| journal.record_dns_import(&intent, now),
        )? {
            Admitted::Existing(existing) => return Ok(Admitted::Existing(existing)),
            Admitted::New(import) => import,
        };
        Ok(Admitted::New(self.run_dns_import(&import)?))
    }

    /// Asks the admin helper to run the open import and records the
    /// readable outcome.
    fn run_dns_import(&mut self, import: &DnsImport) -> Result<DnsImport, ExecutorError> {
        let outcome = admin_helper::route(
            self.anchor.admin_socket.as_deref(),
            &AdminRequest {
                operation_id: import.operation_id.clone(),
                step: AdminStep::DnsImport,
            },
            || Err(ExecutorError::Unavailable),
        );
        let recorded = self
            .journal
            .finish_dns_import(&import.operation_id, outcome.is_ok())?;
        outcome?;
        Ok(recorded)
    }

    /// W563: settles an import left `intent` by a stopped executor: the
    /// helper runs the step again, which refuses before any effect when the
    /// zone is already on the server. A settled import is returned as it is.
    pub fn reconcile_dns_import(&mut self, operation_id: &Id) -> Result<DnsImport, ExecutorError> {
        let import = self
            .journal
            .dns_import_status(operation_id)?
            .ok_or(ExecutorError::NotAdmitted)?;
        if import.state != StepState::Intent {
            return Ok(import);
        }
        self.run_dns_import(&import)
    }

    /// W563: a stored zone import, for status.
    pub fn dns_import_status(&self, operation_id: &Id) -> Result<Option<DnsImport>, ExecutorError> {
        Ok(self.journal.dns_import_status(operation_id)?)
    }
}
