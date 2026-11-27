//! D-100 (P13, W609): admission and execution of signed `site_credential_rotate`.

use rustiron_contracts::{
    Id,
    approval::{AppDatabase, CredentialTarget},
};

use super::Executor;
use crate::{
    AdmissionRequest, ExecutorError,
    admin_helper::{self, AdminRequest, AdminStep, Reply},
    credential_rotate::RotateOutcome,
};
use rustiron_journal::{Admitted, CredentialRotateState, CredentialRotation};

impl Executor {
    /// Admits one signed `site_credential_rotate` (`mariadb_user_password`)
    /// request for a live, owned, non-ejected WordPress site, then asks the
    /// root admin helper to rotate MariaDB + `private/db.cnf`, restart site
    /// PHP, verify new login & old rejection, and compensate once on failure.
    ///
    /// Non-WordPress sites (static, proxy, app), ejected/deleted/quarantined
    /// sites, and hostname mismatches are refused BEFORE intent so the
    /// admission mark is untouched. Exact replays return the stored row
    /// status-only and never rotate again.
    pub fn rotate_site_credentials(
        &mut self,
        request: &AdmissionRequest<'_>,
    ) -> Result<Admitted<CredentialRotation>, ExecutorError> {
        let intent = crate::verified_credential_rotate(&self.anchor, request)?;
        let rotation = match self.admit_signed(
            request,
            (&intent.host_id, &intent.host_epoch),
            |journal| {
                Ok(journal
                    .credential_rotation_status(&intent.operation_id)?
                    .is_some())
            },
            |executor, _now| {
                let Some(provision) = executor.journal.provision_for_site(&intent.site_id)? else {
                    return Err(ExecutorError::PreconditionChanged);
                };
                let is_proxy = executor
                    .journal
                    .proxy_facts(&provision.intent.operation_id)?
                    .is_some();
                let is_app = executor
                    .journal
                    .app_facts(&provision.intent.operation_id)?
                    .is_some();
                let is_static = executor
                    .journal
                    .import_status(&provision.intent.operation_id)?
                    .is_some_and(|imp| imp.facts.is_static());
                let app_db = executor
                    .journal
                    .app_fullstack_spec(&provision.intent.operation_id)?
                    .map(|spec| spec.database);
                let target_matches_site = match intent.target {
                    CredentialTarget::MariadbUserPassword => !is_proxy && !is_app && !is_static,
                    CredentialTarget::AppMariadbPassword => {
                        is_app && app_db == Some(AppDatabase::Mariadb)
                    }
                    CredentialTarget::AppPostgresql18Password => {
                        is_app && app_db == Some(AppDatabase::Postgresql18)
                    }
                };
                if !provision.state.is_owned()
                    || provision.intent.hostname != intent.hostname
                    || executor.journal.ejected_sites()?.contains(&intent.site_id)
                    || !target_matches_site
                {
                    return Err(ExecutorError::PreconditionChanged);
                }
                if executor.anchor.admin_socket.is_none() {
                    return Err(ExecutorError::Unavailable);
                }
                Ok(())
            },
            |journal, now| journal.record_credential_rotation(&intent, now),
        )? {
            Admitted::Existing(existing) => {
                return Ok(Admitted::Existing(existing));
            }
            Admitted::New(rotation) => rotation,
        };

        let socket = self
            .anchor
            .admin_socket
            .as_deref()
            .ok_or(ExecutorError::Unavailable)?;
        let reply = admin_helper::request(
            socket,
            &AdminRequest {
                operation_id: rotation.operation_id.clone(),
                step: AdminStep::SiteCredentialRotate,
            },
        )?;
        match reply {
            Reply::Done(Some(token)) => {
                let Some(outcome) = RotateOutcome::parse(token.trim()) else {
                    return Err(ExecutorError::Unavailable);
                };
                let recorded = self
                    .journal
                    .finish_credential_rotation(&rotation.operation_id, outcome.journal_state())?;
                match outcome {
                    RotateOutcome::Done => Ok(Admitted::New(recorded)),
                    RotateOutcome::FailedCompensated
                    | RotateOutcome::NeedsAttention
                    | RotateOutcome::Failed => Err(ExecutorError::StepFailed),
                }
            }
            Reply::Done(None) => Err(ExecutorError::Unavailable),
            Reply::Refused(error) => {
                // Helper refused before starting (e.g. unreachable or binding);
                // keep `intent` when unknown, or mark `failed` only when helper
                // explicitly refused before any effect.
                if error == ExecutorError::HelperUnreachable {
                    let _ = self.journal.finish_credential_rotation(
                        &rotation.operation_id,
                        CredentialRotateState::Failed,
                    )?;
                }
                Err(error)
            }
        }
    }

    /// Operator reconciliation of an unresolved (`intent` or `needs_attention`)
    /// credential rotation. Before settling as `done` or `failed_compensated`,
    /// asks the admin helper to verify live `private/db.cnf` login and
    /// WordPress HTTP health. A settled rotation is returned unchanged.
    pub fn reconcile_credential_rotation(
        &mut self,
        operation_id: &Id,
        outcome: CredentialRotateState,
    ) -> Result<CredentialRotation, ExecutorError> {
        let row = self
            .journal
            .credential_rotation_status(operation_id)?
            .ok_or(ExecutorError::NotAdmitted)?;
        if row.state.is_terminal() {
            return Ok(row);
        }
        if !outcome.is_terminal() {
            return Err(ExecutorError::InvalidRequest);
        }
        if matches!(
            outcome,
            CredentialRotateState::Done | CredentialRotateState::FailedCompensated
        ) {
            let socket = self
                .anchor
                .admin_socket
                .as_deref()
                .ok_or(ExecutorError::Unavailable)?;
            match admin_helper::request(
                socket,
                &AdminRequest {
                    operation_id: row.operation_id,
                    step: AdminStep::SiteCredentialVerify,
                },
            )? {
                Reply::Done(None) => {}
                Reply::Done(Some(_)) => return Err(ExecutorError::Unavailable),
                Reply::Refused(error) => return Err(error),
            }
        }
        Ok(self
            .journal
            .reconcile_credential_rotation(operation_id, outcome)?)
    }

    /// Reads one recorded credential rotation, for status queries.
    pub fn credential_rotation_status(
        &self,
        operation_id: &Id,
    ) -> Result<Option<CredentialRotation>, ExecutorError> {
        Ok(self.journal.credential_rotation_status(operation_id)?)
    }
}
