//! Product v2 backup submissions: capture admission (W319) and restore
//! probe admission (W320), after the W311 verification steps.
//!
//! The order follows the [binding contract](docs/technical/PRODUCT-BACKUP-BINDING.md):
//! authenticate the exact grant, answer an exact replay from stored status,
//! then check the current destination and credentials before recording
//! intent with the matched projection digest. The admin helper re-binds that
//! digest before repository use. D-031 (W373): after the bound repository
//! check the helper runs the probe phases and reports the outcome; a refusal
//! before the sandbox ends `failed` with no sandbox. A capture writes only
//! behind the product write gate (W356). D-029
//! opens the gate in product builds; in a lab build the gate stays closed,
//! and a capture there would end `failed` with `NOT_ADMITTED_FOR_EFFECT` and
//! no snapshot.

use rustiron_contracts::{
    Id, Timestamp,
    approval::{
        CaptureRecipe, ProductBackupBindingContext, ProductBackupGrant, ProductBackupPlan,
        ProductBackupPolicy, ProductBackupTarget, check_product_backup_binding,
    },
};

use super::{Executor, Fault, grant_digest, repository_preflight, signed_inputs, system_now};
use crate::{
    AdmissionRequest, ExecutorError, MAX_SIGNATURE_BYTES,
    admin_helper::{self, AdminRequest, AdminStep},
    files, policy,
    product_capture::{Recovery, record_recovery},
};
use rustiron_journal::{
    Admitted, Capture, CaptureIntent, CaptureMethod, Probe, ProbeIntent, ProbeState,
};

/// What step 1 established: the exact grant, verified against enrollment.
pub(super) struct Authenticated<G> {
    pub(super) grant: G,
    pub(super) host_id: Id,
    pub(super) host_epoch: Id,
    pub(super) destination: Option<ProductBackupPolicy>,
}

impl Executor {
    /// Step 1 for every product backup form: peer, journal identity, the
    /// form's exact binding and validity (`bind`), and the SSHSIG over the
    /// canonical grant bytes (`signed`).
    pub(super) fn authenticate_enrolled<G>(
        &self,
        peer_uid: u32,
        signature_bytes: &[u8],
        bind: impl FnOnce(&policy::Policy) -> Result<G, ExecutorError>,
        signed: impl FnOnce(&G) -> &[u8],
    ) -> Result<Authenticated<G>, ExecutorError> {
        let owner = self.anchor.owner_uid;
        let directory = files::open_trusted_directory(&self.anchor.policy_dir, owner)?;
        let loaded = policy::load(&directory, owner)?;
        let enrolled = &loaded.policy;
        if peer_uid != enrolled.requester_uid {
            return Err(ExecutorError::PeerDenied);
        }
        self.check_enrolled_identity(enrolled)?;
        if signature_bytes.len() > MAX_SIGNATURE_BYTES {
            return Err(ExecutorError::InvalidRequest);
        }
        let grant = bind(enrolled)?;
        crate::verify_grant(&self.anchor, &loaded, signed(&grant), signature_bytes)?;
        Ok(Authenticated {
            grant,
            host_id: enrolled.host_id.clone(),
            host_epoch: enrolled.host_epoch.clone(),
            destination: loaded.product_backup,
        })
    }

    /// Step 1: peer, journal identity, exact binding, validity and SSHSIG.
    fn authenticate_product_backup(
        &self,
        peer_uid: u32,
        plan: &ProductBackupPlan,
        grant_bytes: &[u8],
        signature_bytes: &[u8],
        now: Option<Timestamp>,
    ) -> Result<Authenticated<ProductBackupGrant>, ExecutorError> {
        self.authenticate_enrolled(
            peer_uid,
            signature_bytes,
            |enrolled| {
                let grant = ProductBackupGrant::decode(grant_bytes)?;
                check_product_backup_binding(
                    plan,
                    &grant,
                    &ProductBackupBindingContext {
                        host_id: &enrolled.host_id,
                        host_epoch: &enrolled.host_epoch,
                        profile_digest: &enrolled.profile_digest,
                        requester: &enrolled.requester,
                        issuer: &enrolled.issuer,
                        signer_policy_epoch: &enrolled.signer_policy_epoch,
                        now,
                    },
                )?;
                Ok(grant)
            },
            ProductBackupGrant::as_bytes,
        )
    }

    /// Step 3: the signed destination is the current enrollment, the signed
    /// site has a repository, and its four credential sources are present.
    fn check_product_destination<'a>(
        &self,
        plan: &ProductBackupPlan,
        destination: Option<&'a ProductBackupPolicy>,
    ) -> Result<&'a ProductBackupPolicy, ExecutorError> {
        self.check_destination_for(
            plan.destination_id(),
            plan.destination_policy_digest(),
            plan.site_id(),
            destination,
        )
    }

    /// Step 3 for one signed destination and site, shared with the
    /// standing capture (D-035).
    pub(super) fn check_destination_for<'a>(
        &self,
        destination_id: &Id,
        destination_policy_digest: &rustiron_contracts::approval::Sha256Digest,
        site_id: &rustiron_contracts::approval::SiteId,
        destination: Option<&'a ProductBackupPolicy>,
    ) -> Result<&'a ProductBackupPolicy, ExecutorError> {
        let destination = destination.ok_or(ExecutorError::PreconditionChanged)?;
        if destination_id != destination.destination_id()
            || destination_policy_digest != &destination.digest()
        {
            return Err(ExecutorError::PreconditionChanged);
        }
        let site = destination
            .resolve_site(site_id)
            .ok_or(ExecutorError::PreconditionChanged)?;
        let owner = self.anchor.owner_uid;
        let directory = files::open_trusted_directory(&self.anchor.policy_dir, owner)?;
        repository_preflight::credential_properties(
            &self.anchor,
            &directory,
            &site,
            repository_preflight::StoreIdentity::Fetch,
        )?;
        Ok(destination)
    }

    /// Admission preconditions shared by both verbs: a succeeded provision
    /// of the site, not ejected, and a configured admin helper.
    pub(super) fn product_site_ready(
        &self,
        site: &rustiron_contracts::approval::SiteId,
    ) -> Result<std::path::PathBuf, ExecutorError> {
        // Like the lab path (W187): only a site this journal provisioned
        // successfully and has not ejected is captured or probed.
        if self.journal.ejected_sites()?.contains(site)
            || !self
                .journal
                .provision_for_site(site)?
                .is_some_and(|provision| provision.state.is_owned())
        {
            return Err(ExecutorError::PreconditionChanged);
        }
        // W574 (D-095): a proxy site has no files or database to capture.
        self.refuse_proxy_site(site)?;
        // The product runner is the admin helper; without it nothing could
        // run, so refuse before consuming the grant.
        self.anchor
            .admin_socket
            .clone()
            .ok_or(ExecutorError::Unavailable)
    }

    /// Recover a product capture left running using its enrolled store.
    /// Re-bind the journaled projection digest, then, with no active
    /// capture or store unit, remove a possible dump and look up the
    /// operation tag afresh. An empty result settles the capture as failed.
    /// A tag cannot prove restic read every source file, so a found tag
    /// stays `running` under [`Recovery::Reconcile`] and settles `failed`
    /// with the snapshot unclaimed under [`Recovery::SettleUnclaimed`]
    /// (W366). Any failed check records nothing.
    pub(crate) fn reconcile_product_capture(
        &mut self,
        existing: rustiron_journal::Capture,
        mode: Recovery,
    ) -> Result<rustiron_journal::Capture, ExecutorError> {
        let destination = policy::load_bound_product_backup(
            &self.anchor,
            &existing.intent.host_id,
            &existing.intent.host_epoch,
            existing.backup_policy_digest.as_ref(),
        )?;
        let site = &existing.intent.site_id;
        let layout = crate::provision::SiteLayout::derive(site);
        for kind in ["capture", "store"] {
            let pattern = format!("rustiron-{kind}-*{}-*", layout.account);
            let active = crate::provision::output(
                "/usr/bin/systemctl",
                &["list-units", "--plain", "--no-legend", "--", &pattern],
            )?;
            if !active.trim().is_empty() {
                return Err(ExecutorError::Busy);
            }
        }
        let level = crate::capture::site_level(&layout)?;
        let operation = &existing.intent.operation_id;
        if crate::write_gate::PRODUCT_WRITES_ENABLED {
            crate::capture::remove_dump(&layout)?;
        }
        let found = crate::store_network::find_tagged_snapshot(
            &self.anchor,
            &destination,
            site,
            &level,
            operation,
        )?;
        let now = system_now().ok_or(ExecutorError::TimeDenied)?;
        let now = if now.get() >= existing.started_at.get() {
            now
        } else {
            existing.started_at
        };
        record_recovery(&mut self.journal, operation, mode, Ok(found), now)
    }

    /// W320: durable admission of a product v2 restore probe, then the
    /// helper's bound repository check and, under D-031 (W373), the probe
    /// phases. The journal records the helper's outcome and receipt.
    pub fn product_restore_probe(
        &mut self,
        request: &AdmissionRequest<'_>,
    ) -> Result<Admitted<Probe>, ExecutorError> {
        let plan = ProductBackupPlan::decode(request.plan)?;
        let ProductBackupTarget::RestoreProbe { snapshot_id, .. } = plan.target() else {
            return Err(ExecutorError::InvalidRequest);
        };
        let authenticated = self.authenticate_product_backup(
            request.peer_uid,
            &plan,
            request.grant,
            request.signature,
            request.now,
        )?;
        let grant = &authenticated.grant;
        let (plan_digest, grant_digest) = (plan.digest(), grant_digest(grant.as_bytes()));
        // Step 2: status-only exact replay before the destination check.
        if let Some(existing) = self.journal.probe_status(&request.operation_id)? {
            return if existing.intent.idempotency_key == request.idempotency_key
                && existing.intent.plan_digest == plan_digest
                && existing.intent.grant_digest == grant_digest
            {
                Ok(Admitted::Existing(existing))
            } else {
                Err(ExecutorError::ReplayDenied)
            };
        }
        let destination =
            self.check_product_destination(&plan, authenticated.destination.as_ref())?;
        let digest = destination.digest();
        let socket = self.product_site_ready(plan.site_id())?;
        let now = request.now.ok_or(ExecutorError::TimeDenied)?;
        let mut random = [0_u8; 3];
        rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty())
            .map_err(|_| ExecutorError::Unavailable)?;
        let probe_account = random.iter().fold("rp_".to_owned(), |mut name, byte| {
            name.push_str(&format!("{byte:02x}"));
            name
        });
        let intent = ProbeIntent {
            operation_id: request.operation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            grant_id: grant.grant_id().clone(),
            nonce: grant.nonce().clone(),
            plan_digest,
            grant_digest,
            host_id: authenticated.host_id.clone(),
            host_epoch: authenticated.host_epoch.clone(),
            site_id: plan.site_id().clone(),
            snapshot_id: snapshot_id.clone(),
            probe_account,
            expires_at: grant.expires_at(),
        };
        let Admitted::New(_) = self.admit(signed_inputs(request)?, |journal| {
            journal.record_probe(&intent, now, &digest)
        })?
        else {
            return Err(ExecutorError::ReplayDenied);
        };
        self.fault(Fault::AfterProductAdmission)?;
        let reply = admin_helper::request(
            &socket,
            &AdminRequest {
                operation_id: intent.operation_id.clone(),
                step: AdminStep::ProbeRun,
            },
        );
        self.fault(Fault::AfterProductHelperReply)?;
        let finished = system_now().filter(|t| t.get() >= now.get()).unwrap_or(now);
        let outcome = match &reply {
            Ok(admin_helper::Reply::Done(Some(payload))) => admin_helper::decode_probe(payload),
            _ => None,
        };
        match (reply, outcome) {
            // Refused before the helper created anything: a known failure.
            (Ok(admin_helper::Reply::Refused(error)), _) => {
                let receipt = serde_json::json!({
                    "receipt_schema": "rustiron-restore-probe/2",
                    "probe_account": intent.probe_account,
                    "refused": error.code(),
                    "note": "the admin helper refused before creating anything; no check is claimed",
                    "cleanup": {"status": "complete", "leftover_resources": 0, "removal_failures": 0, "unverified": []},
                });
                self.journal.finish_probe(
                    &intent.operation_id,
                    ProbeState::Failed,
                    &receipt.to_string(),
                    finished,
                )?;
                Err(error)
            }
            // D-031 (W373): the helper ran the probe and its cleanup; record
            // the outcome and receipt it reported.
            (_, Some((receipt, state))) => Ok(Admitted::New(self.journal.finish_probe(
                &intent.operation_id,
                state,
                &receipt.to_string(),
                finished,
            )?)),
            // An unreadable or lost reply is unknown: the probe stays
            // `running` for the admin cleanup, which never claims a pass.
            (Ok(admin_helper::Reply::Done(_)) | Err(_), None) => {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "scope": "product_restore_probe",
                        "operation_id": intent.operation_id.as_str(),
                        "outcome": "uncertain_cleanup_required",
                    })
                );
                Err(ExecutorError::Unavailable)
            }
        }
    }

    /// W319: durable admission of a product v2 capture, then the helper's
    /// bound repository check. A restore probe plan is refused here.
    pub fn product_backup_capture(
        &mut self,
        request: &AdmissionRequest<'_>,
    ) -> Result<Admitted<Capture>, ExecutorError> {
        let plan = ProductBackupPlan::decode(request.plan)?;
        let ProductBackupTarget::BackupCapture { recipe_id } = plan.target() else {
            return Err(ExecutorError::InvalidRequest);
        };
        let method = match recipe_id {
            CaptureRecipe::SiteFilesDbV1 => CaptureMethod::SiteFilesDbV1,
            CaptureRecipe::SiteFilesDbFrozenV1 => CaptureMethod::SiteFilesDbFrozenV1,
        };
        let authenticated = self.authenticate_product_backup(
            request.peer_uid,
            &plan,
            request.grant,
            request.signature,
            request.now,
        )?;
        let grant = &authenticated.grant;
        let intent = CaptureIntent {
            operation_id: request.operation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            grant_id: grant.grant_id().clone(),
            nonce: grant.nonce().clone(),
            plan_digest: plan.digest(),
            grant_digest: grant_digest(grant.as_bytes()),
            host_id: authenticated.host_id.clone(),
            host_epoch: authenticated.host_epoch.clone(),
            site_id: plan.site_id().clone(),
            expires_at: grant.expires_at(),
        };
        // Step 2: an authenticated exact replay gets stored status, even if
        // the destination changed since; anything else under this id is a
        // replay refusal.
        if let Some(existing) = self.journal.capture_status(&intent.operation_id)? {
            return if existing.intent == intent {
                Ok(Admitted::Existing(existing))
            } else {
                Err(ExecutorError::ReplayDenied)
            };
        }
        let destination =
            self.check_product_destination(&plan, authenticated.destination.as_ref())?;
        let now = request.now.ok_or(ExecutorError::TimeDenied)?;
        self.admit_and_run_product_capture(
            &intent,
            signed_inputs(request)?,
            method,
            destination,
            now,
        )
    }

    /// Steps 4 and 5 of a product capture, shared with the standing capture
    /// (D-035): the site preconditions, the durable intent with the matched
    /// digest and retention, then the admin helper's capture and its
    /// recorded outcome.
    pub(super) fn admit_and_run_product_capture(
        &mut self,
        intent: &CaptureIntent,
        staged: super::StagedAdmission,
        method: CaptureMethod,
        destination: &ProductBackupPolicy,
        now: Timestamp,
    ) -> Result<Admitted<Capture>, ExecutorError> {
        let digest = destination.digest();
        let retention = destination
            .resolve_site(&intent.site_id)
            .map(|site| u32::from(site.retention_days()))
            .ok_or(ExecutorError::PreconditionChanged)?;
        let socket = self.product_site_ready(&intent.site_id)?;
        let staged = super::StagedAdmission {
            operation_id: intent.operation_id.clone(),
            signed: staged.signed,
        };
        let Admitted::New(_) = self.admit(staged, |journal| {
            journal.record_capture(intent, now, method, Some(retention), &digest)
        })?
        else {
            let existing = self
                .journal
                .capture_status(&intent.operation_id)?
                .ok_or(ExecutorError::Unavailable)?;
            return Ok(Admitted::Existing(existing));
        };
        self.fault(Fault::AfterProductAdmission)?;
        let reply = admin_helper::request(
            &socket,
            &AdminRequest {
                operation_id: intent.operation_id.clone(),
                step: AdminStep::CaptureRun,
            },
        );
        self.fault(Fault::AfterProductHelperReply)?;
        let finished = system_now().filter(|t| t.get() >= now.get()).unwrap_or(now);
        let root = crate::provision::SiteLayout::derive(&intent.site_id)
            .root
            .to_string_lossy()
            .into_owned();
        let is_app = self
            .journal
            .app_facts_by_site(&intent.site_id)
            .ok()
            .flatten()
            .is_some();
        let outcome = match reply {
            // Refused before any snapshot effect (the bind or the closed
            // write gate): a known failure.
            Ok(admin_helper::Reply::Refused(error)) => {
                crate::capture::CaptureOutcome::NotStarted(error)
            }
            // W356/W603: the helper's capture outcome. Anything unreadable is
            // uncertain; a relayed manifest is checked again for the site kind.
            Ok(admin_helper::Reply::Done(Some(payload))) => admin_helper::decode_capture_for_kind(
                &payload,
                &root,
                method == CaptureMethod::SiteFilesDbFrozenV1,
                is_app,
            ),
            // A lost or empty reply is unknown: the capture stays `running`
            // for operator recovery rather than becoming success or failure.
            Ok(admin_helper::Reply::Done(None)) | Err(_) => {
                crate::capture::CaptureOutcome::Uncertain {
                    error: ExecutorError::Unavailable,
                    snapshot: None,
                }
            }
        };
        self.record_capture_outcome(
            &intent.operation_id,
            outcome,
            finished,
            "product_backup_capture",
        )
    }
}
