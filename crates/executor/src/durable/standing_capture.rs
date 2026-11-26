//! D-035 (W386): admission of one run of a standing capture grant (plan
//! and grant schema 3).
//!
//! The order is in [D-035](docs/decisions/D-035-scheduled-capture.md):
//! authenticate the exact grant, find the run that the grant derives for
//! the requested operation ID, answer an exact replay from stored status,
//! check the window with the executor clock, then admit and run the capture
//! as a schema 2 capture. The requester never chooses the run identity: the
//! journal records the derived run grant ID and nonce, so the existing
//! replay ledger consumes each site's run in each window once.

use rustiron_contracts::approval::{
    CaptureRecipe, StandingCaptureBindingContext, StandingCaptureGrant, StandingCapturePlan,
    WindowPosition, check_standing_capture_binding,
};
use rustiron_journal::{CaptureIntent, CaptureMethod, CaptureResult};

use super::{Executor, signed_inputs};
use crate::{AdmissionRequest, ExecutorError};

impl Executor {
    /// D-035: one run of a standing capture grant.
    pub fn product_standing_capture(
        &mut self,
        request: &AdmissionRequest<'_>,
    ) -> Result<CaptureResult, ExecutorError> {
        let plan = StandingCapturePlan::decode(request.plan)?;
        let method = match plan.recipe_id() {
            CaptureRecipe::SiteFilesDbV1 => CaptureMethod::SiteFilesDbV1,
            CaptureRecipe::SiteFilesDbFrozenV1 => CaptureMethod::SiteFilesDbFrozenV1,
        };
        // Step 1: peer, journal identity, exact binding, validity, SSHSIG.
        let authenticated = self.authenticate_enrolled(
            request.peer_uid,
            request.signature,
            |enrolled| {
                let grant = StandingCaptureGrant::decode(request.grant)?;
                check_standing_capture_binding(
                    &plan,
                    &grant,
                    &StandingCaptureBindingContext {
                        host_id: &enrolled.host_id,
                        host_epoch: &enrolled.host_epoch,
                        profile_digest: &enrolled.profile_digest,
                        requester: &enrolled.requester,
                        issuer: &enrolled.issuer,
                        signer_policy_epoch: &enrolled.signer_policy_epoch,
                        now: request.now,
                    },
                )?;
                Ok(grant)
            },
            StandingCaptureGrant::as_bytes,
        )?;
        let grant = &authenticated.grant;
        // Step 2: the requested identity must be a run that this grant
        // derives for a site it names.
        let (site_id, run) = grant
            .find_run(&request.operation_id)
            .filter(|(_, run)| run.idempotency_key == request.idempotency_key)
            .ok_or(ExecutorError::RunMismatch)?;
        let schedule = grant.schedule();
        let (_, closes_at) = schedule
            .window(run.window)
            .ok_or(ExecutorError::RunMismatch)?;
        let expires_at = closes_at.min(grant.expires_at().get());
        let intent = CaptureIntent {
            operation_id: run.operation_id,
            idempotency_key: run.idempotency_key,
            grant_id: run.grant_id,
            nonce: run.nonce,
            plan_digest: plan.digest(),
            grant_digest: grant.sha256(),
            host_id: authenticated.host_id.clone(),
            host_epoch: authenticated.host_epoch.clone(),
            site_id,
            expires_at: expires_at
                .try_into()
                .map_err(|_| ExecutorError::InvalidRequest)?,
        };
        // Step 3: an authenticated exact replay gets stored status, also
        // after its window closed; anything else under this ID is refused.
        if let Some(existing) = self.journal.capture_status(&intent.operation_id)? {
            return if existing.intent == intent {
                Ok(CaptureResult::Existing(existing))
            } else {
                Err(ExecutorError::ReplayDenied)
            };
        }
        // Step 4: only the run of the window open at the executor clock.
        let now = request.now.ok_or(ExecutorError::TimeDenied)?;
        if !matches!(
            schedule.position(now.get()),
            WindowPosition::Open { index, .. } if index == run.window
        ) {
            return Err(ExecutorError::WindowClosed);
        }
        // Steps 5 and 6: the schema 2 destination check, admission and run.
        let destination = self.check_destination_for(
            plan.destination_id(),
            plan.destination_policy_digest(),
            &intent.site_id,
            authenticated.destination.as_ref(),
        )?;
        self.admit_and_run_product_capture(
            &intent,
            signed_inputs(request)?,
            method,
            destination,
            now,
        )
    }
}
