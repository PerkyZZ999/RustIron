//! D-078 clone admission. W497 verifies the signed scope and the recorded
//! native capture; W499 records the clone in the journal (W498) and runs the
//! provision steps with the clone steps inside the Recipe step. A lab
//! profile build keeps the W497 preflight, which stops before intent.

use rustiron_contracts::approval::{
    CloneSource, ProductBackupBindingContext, SiteCloneGrant, SiteClonePlan,
    check_site_clone_binding,
};
use rustiron_journal::{
    Admitted, Capture, CaptureConsistency, CaptureState, CloneFacts, Provision, ProvisionIntent,
    ProvisionState, ProvisionStep, StepState,
};
use sha2::{Digest, Sha256};

use super::{Executor, StepRecipe, signed_inputs};
use crate::{AdmissionRequest, ExecutorError, files, policy, provision};

/// A clone request whose signature, scope and source capture are verified.
struct VerifiedClone {
    intent: ProvisionIntent,
    facts: CloneFacts,
    enrolled: policy::ProvisioningPolicy,
}

impl Executor {
    /// Checks the signed clone scope and native capture provenance. A
    /// qualifying clone returns `NotAdmitted` before recording intent. The
    /// lab profile answers every clone request with it.
    pub fn preflight_site_clone(
        &self,
        request: &AdmissionRequest<'_>,
    ) -> Result<(), ExecutorError> {
        let verified = self.verify_site_clone(request)?;
        self.check_clone_target(&verified)?;
        Err(ExecutorError::NotAdmitted)
    }

    /// W499 (D-078): admits one signed `site_clone` and runs the provision
    /// steps with the clone steps inside the Recipe step, in journal order.
    /// The journal reserves the target and rechecks the source capture in
    /// one transaction. An exact verified repeat returns stored status.
    pub fn site_clone(
        &mut self,
        request: &AdmissionRequest<'_>,
    ) -> Result<Admitted<Provision>, ExecutorError> {
        let verified = self.verify_site_clone(request)?;
        let now = request.now.ok_or(ExecutorError::TimeDenied)?;
        let VerifiedClone {
            intent,
            facts,
            enrolled,
        } = &verified;
        if let Some(existing) = self.journal.provision_status(&intent.operation_id)? {
            let recorded = self.journal.clone_status(&intent.operation_id)?;
            return if existing.intent == *intent
                && recorded.is_some_and(|clone| clone.facts == *facts)
            {
                Ok(Admitted::Existing(existing))
            } else {
                Err(ExecutorError::ReplayDenied)
            };
        }
        self.check_clone_target(&verified)?;
        let operation = match self.admit(signed_inputs(request)?, |journal| {
            journal.record_clone(intent, facts, now)
        })? {
            Admitted::Existing(existing) => return Ok(Admitted::Existing(existing)),
            Admitted::New(created) => created.intent.operation_id,
        };
        // D-078 signs no limits: the enrolled policy limits apply.
        let quota = crate::quota::QuotaIntent::select(None, enrolled.quota);
        self.run_provision_steps(
            &operation,
            intent,
            enrolled,
            quota,
            StepRecipe::Clone(facts),
        )
    }

    /// The target is free: no journal claim, enrolled adopted name, or
    /// existing account, group or site root.
    fn check_clone_target(&self, verified: &VerifiedClone) -> Result<(), ExecutorError> {
        let owner = self.anchor.owner_uid;
        let directory = files::open_trusted_directory(&self.anchor.policy_dir, owner)?;
        let loaded = policy::load(&directory, owner)?;
        let intent = &verified.intent;
        if self
            .journal
            .site_identity_is_reserved(&intent.site_id, &intent.hostname)?
            || loaded.policy.ols.as_ref().is_some_and(|ols| {
                ols.adopted
                    .iter()
                    .any(|site| site.hostname == intent.hostname)
            })
        {
            return Err(ExecutorError::PreconditionChanged);
        }
        self.provision_collision(&provision::SiteLayout::derive(&intent.site_id))
    }

    /// The signed binding, the enrolled loopback profile and destination,
    /// and the recorded native capture of the source.
    fn verify_site_clone(
        &self,
        request: &AdmissionRequest<'_>,
    ) -> Result<VerifiedClone, ExecutorError> {
        let loaded = crate::open_signed(&self.anchor, request)?;
        let enrolled = &loaded.policy;
        self.check_identity(&enrolled.host_id, &enrolled.host_epoch)?;
        let plan = SiteClonePlan::decode(request.plan)?;
        let grant = SiteCloneGrant::decode(request.grant)?;
        check_site_clone_binding(
            &plan,
            &grant,
            &ProductBackupBindingContext {
                host_id: &enrolled.host_id,
                host_epoch: &enrolled.host_epoch,
                profile_digest: &enrolled.profile_digest,
                requester: &enrolled.requester,
                issuer: &enrolled.issuer,
                signer_policy_epoch: &enrolled.signer_policy_epoch,
                now: request.now,
            },
        )?;
        crate::verify_grant(&self.anchor, &loaded, grant.as_bytes(), request.signature)?;

        enrolled
            .ols
            .as_ref()
            .filter(|ols| {
                ols.http_is_loopback()
                    && ols
                        .tls_address
                        .as_deref()
                        .is_none_or(policy::loopback_listener)
            })
            .ok_or(ExecutorError::Unavailable)?;
        let provisioning = enrolled
            .provisioning
            .clone()
            .ok_or(ExecutorError::Unavailable)?;
        let source = plan.source();
        let destination = loaded
            .product_backup
            .as_ref()
            .ok_or(ExecutorError::Unavailable)?;
        if destination.destination_id() != &source.destination_id
            || destination.digest() != source.destination_policy_digest
            || destination.repository_id(&source.site_id) != Some(&source.repository_id)
        {
            return Err(ExecutorError::PreconditionChanged);
        }
        let capture = self
            .journal
            .capture_status(&source.capture_operation_id)?
            .ok_or(ExecutorError::PreconditionChanged)?;
        let provision = self
            .journal
            .provision_for_site(&source.site_id)?
            .ok_or(ExecutorError::PreconditionChanged)?;
        if !native_capture_matches(&capture, &provision, source)
            || capture.intent.host_id != enrolled.host_id
            || capture.intent.host_epoch != enrolled.host_epoch
            || self.journal.ejected_sites()?.contains(&source.site_id)
        {
            return Err(ExecutorError::PreconditionChanged);
        }
        let target = plan.target();
        Ok(VerifiedClone {
            intent: ProvisionIntent {
                operation_id: request.operation_id.clone(),
                idempotency_key: request.idempotency_key.clone(),
                grant_id: grant.grant_id().clone(),
                nonce: grant.nonce().clone(),
                plan_digest: plan.digest(),
                grant_digest: rustiron_contracts::approval::Sha256Digest::from_bytes(
                    Sha256::digest(grant.as_bytes()).into(),
                ),
                host_id: enrolled.host_id.clone(),
                host_epoch: enrolled.host_epoch.clone(),
                site_id: target.site_id.clone(),
                hostname: target.hostname.clone(),
                expires_at: grant.expires_at(),
            },
            facts: CloneFacts {
                source_site_id: source.site_id.clone(),
                source_hostname: source.hostname.clone(),
                capture_operation_id: source.capture_operation_id.clone(),
                snapshot_id: source.snapshot_id.clone(),
                manifest_sha256: source.manifest_sha256.clone(),
                destination_policy_digest: source.destination_policy_digest.clone(),
                repository_id: source.repository_id.clone(),
            },
            enrolled: provisioning,
        })
    }
}

fn native_capture_matches(capture: &Capture, provision: &Provision, source: &CloneSource) -> bool {
    let native_recipe = format!(
        "Recipe {} recipe={}",
        source.site_id.account_name(),
        super::recipe_name(rustiron_contracts::approval::SiteRecipe::Wordpress713InstallV1),
    );
    provision.state == ProvisionState::Succeeded
        && provision.intent.site_id == source.site_id
        && provision.intent.hostname == source.hostname
        && provision.steps.iter().any(|step| {
            step.step == ProvisionStep::Recipe
                && step.state == StepState::Done
                && step.resource == native_recipe
        })
        && capture.state == CaptureState::Succeeded
        && capture.intent.site_id == source.site_id
        && capture.snapshot_id.as_deref() == Some(source.snapshot_id.as_str())
        && capture.backup_policy_digest.as_ref() == Some(&source.destination_policy_digest)
        && capture.consistency == Some(CaptureConsistency::Matched)
        && capture.manifest.as_ref().is_some_and(|manifest| {
            !manifest.truncated && manifest.sha256 == source.manifest_sha256.as_str()
        })
}
