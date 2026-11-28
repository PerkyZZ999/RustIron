//! Durable admission, the single fixture effect and observer reconciliation.

use std::collections::HashSet;

use rustiron_contracts::{Id, Timestamp};
use rustiron_journal::{
    Admitted, Capture, CaptureIntent, CaptureMethod, CaptureState, FixtureJournal, JournalError,
    Operation, Probe, ProbeIntent, ProbeState, Provision, ProvisionState, ProvisionStep,
    RecordedState, SignedAdmission,
};

use crate::{
    AdmissionRequest, ExecutorError, TrustAnchor,
    admin_helper::{self, AdminRequest, AdminStep},
    capture, check_live, files, mark, ols, page_cache, policy, provision,
    registry::{self, SwitchOutcome},
    restore, verified_capture, verified_eject, verified_intent, verified_ols, verified_probe,
    verified_site,
};
use rustiron_contracts::approval::{CaptureRecipe, Sha256Digest, SiteRecipe};
use rustiron_journal::Intent;
use sha2::{Digest, Sha256};

mod clone_scrub;
mod credential_rotate;
mod dns_change;
mod dns_import;
mod product_backup;
mod readopt;
pub(crate) mod repository_preflight;
mod site_clone;
mod site_delete;
mod site_quota;
mod site_restore;
mod site_retire;
mod site_update;
mod standing_capture;

pub use readopt::ReadoptObservation;

const WORDPRESS_713_FILE: &str = "wordpress-7.1.3.tar.gz";
const WORDPRESS_713_MARKER: &str = "$wp_version = '7.1.3';";
/// Upstream per-file MD5 list for WordPress 7.1.3 en_US
/// (api.wordpress.org core/checksums), pinned here; cross-checked against the
/// pinned tarball: 3782 files, all equal (W029).
const WORDPRESS_713_CHECKSUMS_FILE: &str = "wordpress-7.1.3.md5.json";
const WORDPRESS_713_CHECKSUMS_SHA256: &str =
    "78ff5ec132f655e0ed8411984d985bd3bd58271f782745d20200e28a8e571671";

/// W633 (M-25): verified signed inputs paired with the requested operation ID
/// so D-098 blast-radius replay checks bind exact operation identity (preventing
/// standing-capture runs sharing plan/grant bytes from bypassing budgets).
pub(crate) struct StagedAdmission {
    pub(crate) operation_id: Id,
    pub(crate) signed: SignedAdmission,
}

/// W396 (D-045): the canonical plan and grant of a request whose signature
/// was verified, with the issuer and signer-policy epoch from the signed
/// grant (the binding checks made them equal to the enrolled values). The
/// journal refuses bytes that do not hash to the intent digests.
pub(crate) fn signed_inputs(
    request: &AdmissionRequest<'_>,
) -> Result<StagedAdmission, ExecutorError> {
    let plan = rustiron_contracts::CanonicalObject::decode(request.plan)
        .map_err(|_| ExecutorError::InvalidRequest)?;
    let grant = rustiron_contracts::CanonicalObject::decode(request.grant)
        .map_err(|_| ExecutorError::InvalidRequest)?;
    let fields: serde_json::Value =
        serde_json::from_slice(grant.as_bytes()).map_err(|_| ExecutorError::InvalidRequest)?;
    let member = |name: &str| {
        fields[name]
            .as_str()
            .and_then(|value| Id::try_from(value.to_owned()).ok())
            .ok_or(ExecutorError::InvalidRequest)
    };
    Ok(StagedAdmission {
        operation_id: request.operation_id.clone(),
        signed: SignedAdmission {
            issuer: member("issuer")?,
            signer_policy_epoch: member("signer_policy_epoch")?,
            plan: plan.as_bytes().to_vec(),
            grant: grant.as_bytes().to_vec(),
        },
    })
}

/// Journal name of a site recipe, recorded in the Recipe step's resource.
/// What a provision's Recipe step does: a site recipe, or (W446, D-053) the
/// import steps with the import's signed facts.
#[derive(Clone, Copy)]
pub(crate) enum StepRecipe<'a> {
    Site(SiteRecipe),
    Import(&'a rustiron_journal::ImportFacts),
    /// W499 (D-078): the clone steps with the clone's signed source facts.
    Clone(&'a rustiron_journal::CloneFacts),
    /// W572 (D-095): a proxy site: the identity file only, no PHP or database.
    Proxy,
    /// W598 (D-099) & W658 (D-102): a modern app site (Node.js, Bun, or Static SPA)
    /// with optional v2 full-stack/DB specification.
    App(
        &'a rustiron_journal::AppFacts,
        Option<&'a rustiron_journal::AppFullstackSpec>,
    ),
}

/// W499 (D-078): the Recipe step's recorded name of a staging clone.
pub(crate) const CLONE_RECIPE: &str = "site_clone_v1";

/// The Recipe step's recorded name of an import.
pub(crate) const IMPORT_RECIPE: &str = "import_v1";
/// D-074: the Recipe step's recorded name of a static import.
pub(crate) const IMPORT_STATIC_RECIPE: &str = "import_static_v1";

impl StepRecipe<'_> {
    fn name(self) -> &'static str {
        match self {
            Self::Site(recipe) => recipe_name(recipe),
            Self::Import(facts) if facts.is_static() => IMPORT_STATIC_RECIPE,
            Self::Import(_) => IMPORT_RECIPE,
            Self::Clone(_) => CLONE_RECIPE,
            Self::Proxy => crate::proxy_site::PROXY_RECIPE,
            Self::App(_, _) => crate::app_site::APP_RECIPE,
        }
    }

    /// The site recipe the shared steps take; an import's shared steps
    /// (every step but Recipe and Verify) do not read it.
    fn site(self) -> SiteRecipe {
        match self {
            Self::Site(recipe) => recipe,
            Self::Import(_) | Self::Clone(_) | Self::Proxy | Self::App(_, _) => {
                SiteRecipe::Wordpress713InstallV1
            }
        }
    }
}

pub(crate) fn recipe_name(recipe: SiteRecipe) -> &'static str {
    match recipe {
        SiteRecipe::Wordpress713V1 => "wordpress713_v1",
        SiteRecipe::Wordpress713InstallV1 => "wordpress713_install_v1",
    }
}

/// Inverse of [`recipe_name`]; anything else is not a recorded recipe.
pub(crate) fn recipe_from_name(name: &str) -> Option<SiteRecipe> {
    [
        SiteRecipe::Wordpress713V1,
        SiteRecipe::Wordpress713InstallV1,
    ]
    .into_iter()
    .find(|recipe| recipe_name(*recipe) == name)
}

/// Everything one provision step needs, derived from the journal and the
/// trusted policy; nothing comes from a helper request.
pub(crate) struct SiteStep<'a> {
    pub layout: &'a provision::SiteLayout,
    pub allocated: u32,
    pub recipe: SiteRecipe,
    pub hostname: &'a rustiron_contracts::approval::Hostname,
    pub wordpress: &'a Sha256Digest,
    pub recipes_dir: &'a std::path::Path,
    /// W335: the quota journaled in the Directories step's intent.
    pub quota: crate::quota::QuotaPlan,
    /// W335: the uid journaled by the Account step, if it was recorded.
    pub site_uid: Option<u32>,
}

/// The uid the provision's Account step journaled (`uid=<n>`), if any.
pub(crate) fn journaled_uid(provision: &Provision) -> Option<u32> {
    let first = provision.steps.first()?;
    if first.step != ProvisionStep::Account {
        return None;
    }
    match provision::recorded_numbers(std::slice::from_ref(&first.resource), "uid=")[..] {
        [uid] => Some(uid),
        _ => None,
    }
}

/// Runs the effect of one provision step, in this process or the helper.
/// The database password lives only in `password`, from Database to
/// Credentials; if it is lost in between, Credentials fails closed.
pub(crate) fn run_site_step(
    step: ProvisionStep,
    site: &SiteStep<'_>,
    password: &mut Option<String>,
) -> Result<(), ExecutorError> {
    let layout = site.layout;
    match step {
        ProvisionStep::Account => provision::create_account(layout, site.allocated).map(drop),
        // W335: the quota is set and read back before any site directory
        // exists, so a quota failure leaves no tree behind.
        ProvisionStep::Directories => crate::quota::apply(
            &mut crate::quota::SystemQuota,
            site.quota,
            &layout.account,
            site.site_uid,
        )
        .and_then(|_| provision::create_directories(layout))
        .map(drop),
        ProvisionStep::Labels => provision::apply_labels(layout, site.allocated).map(drop),
        ProvisionStep::Database => {
            provision::create_database(layout).map(|(_, secret)| *password = Some(secret))
        }
        ProvisionStep::Credentials => match password.take() {
            Some(secret) => provision::write_credentials(layout, &secret).map(drop),
            None => Err(ExecutorError::StepFailed),
        },
        ProvisionStep::Recipe => provision::unpack_recipe(
            layout,
            site.recipes_dir,
            WORDPRESS_713_FILE,
            site.wordpress,
            WORDPRESS_713_MARKER,
        )
        .and_then(|_| provision::write_wp_config(layout))
        .and_then(|_| provision::write_site_marker(layout))
        .and_then(|_| crate::certificate::prepare_webroot(&layout.account))
        .and_then(|_| match site.recipe {
            SiteRecipe::Wordpress713V1 => Ok(()),
            SiteRecipe::Wordpress713InstallV1 => {
                provision::install_wordpress(layout, site.hostname).map(drop)
            }
        }),
        ProvisionStep::PhpUnits => provision::install_php_units(layout).map(drop),
        ProvisionStep::Verify => Sha256Digest::try_from(WORDPRESS_713_CHECKSUMS_SHA256.to_owned())
            .map_err(|_| ExecutorError::Unavailable)
            .and_then(|pinned| {
                provision::read_pinned(site.recipes_dir, WORDPRESS_713_CHECKSUMS_FILE, &pinned)
            })
            .and_then(|checksums| {
                let installed = site.recipe == SiteRecipe::Wordpress713InstallV1;
                provision::verify_site(layout, &checksums, installed)
            })
            .map(drop),
    }
}

/// The executor's sole journal writer, opened only as the anchor's owner.
///
/// `submit` returning `Admitted::New` means the nonce is consumed and the
/// intent is durable. It is still not proof that any effect happened, and
/// `Existing` is status only, never permission to repeat an effect.
pub struct Executor {
    anchor: TrustAnchor,
    journal: FixtureJournal,
    /// Host and epoch the journal was opened for; the admission mark binds them.
    identity: (Id, Id),
    /// Intents newly recorded by this instance; only these may be executed,
    /// once. A restarted executor never infers that an effect did not happen.
    admitted: HashSet<String>,
    #[cfg(feature = "fault-injection")]
    fault: Option<Fault>,
    /// Test-only: what the next re-adoption observation returns.
    #[cfg(feature = "fault-injection")]
    readopt_observation: Option<ReadoptObservation>,
}

/// Crash points for tests; compiled in only with the `fault-injection` feature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    /// After the durable attempt mark, before any registry write.
    AfterAttemptMark,
    /// After the switch, before the outcome is observed and recorded.
    AfterSwitch,
    /// After the durable compensation mark, before its switch.
    AfterCompensationMark,
    /// After the compensation switch, before the outcome is recorded.
    AfterCompensationSwitch,
    /// After a provision step is journaled as intent, before its effect.
    AfterProvisionStepBegin,
    /// After a product capture or probe intent and its admission mark are
    /// durable, before the admin helper request.
    AfterProductAdmission,
    /// After the admin helper replies for a product capture or probe, before
    /// the outcome is recorded.
    AfterProductHelperReply,
    /// W372: after a re-adoption is recorded `verifying`, before the
    /// read-only observation.
    AfterReadoptIntent,
    /// W377: after a re-adoption's observation and decision, before the
    /// transaction that records `adopted` or `refused`.
    AfterReadoptObservation,
    /// W380: after an OLS activation's intent and admission mark are
    /// durable, before the preflight and the staged generation.
    AfterOlsIntent,
    /// W384: inside the staging of an OLS activation, after the temporary
    /// folder is written and read back, before its rename to the target id
    /// (so before the effect mark).
    DuringOlsStaging,
    /// W380: after an OLS activation's durable effect mark, before the
    /// switch of `current`.
    AfterOlsEffectMark,
    /// W380: after the switch, the config test and the reload (or the
    /// bootstrap start), before the verification and its record.
    AfterOlsServing,
    /// W380: after an unverified activation's durable compensation mark,
    /// before the restore inside the activation.
    AfterOlsRestoreMark,
}

impl Executor {
    /// Explicitly creates an empty journal for the enrolled host/epoch.
    /// Refuses any existing artifact; never repairs or recreates history.
    ///
    /// A fresh journal is refused while the admission mark records history
    /// for this same host and epoch: that would forget consumed grants, so an
    /// epoch rotation must come first (review F-01).
    pub fn initialize(anchor: TrustAnchor) -> Result<Self, ExecutorError> {
        let (host_id, host_epoch) = prepare(&anchor)?;
        if mark::read(&anchor)?.is_some_and(|seen| {
            seen.host == host_id.as_str() && seen.epoch == host_epoch.as_str() && seen.count > 0
        }) {
            return Err(ExecutorError::JournalRollback);
        }
        let journal = FixtureJournal::initialize_as_process_owner(
            &anchor.journal_dir,
            host_id.clone(),
            host_epoch.clone(),
        )
        .map_err(|error| match error {
            JournalError::Conflict => ExecutorError::StateExists,
            other => other.into(),
        })?;
        mark::write(&anchor, &host_id, &host_epoch, 0)?;
        Ok(Self {
            anchor,
            journal,
            identity: (host_id, host_epoch),
            admitted: HashSet::new(),
            #[cfg(feature = "fault-injection")]
            fault: None,
            #[cfg(feature = "fault-injection")]
            readopt_observation: None,
        })
    }

    /// Admin, service stopped: one-way in-place migration of a supported
    /// journal bound to the enrolled host and epoch.
    pub fn migrate(anchor: TrustAnchor) -> Result<(), ExecutorError> {
        let (host_id, host_epoch) = prepare(&anchor)?;
        FixtureJournal::migrate_as_process_owner(&anchor.journal_dir, host_id, host_epoch)
            .map(drop)
            .map_err(|error| match error {
                JournalError::Conflict => ExecutorError::IdentityMismatch,
                other => other.into(),
            })
    }

    /// Read-only snapshot for display, safe while the service runs: no writer
    /// lease, a read-only journal connection, and only non-secret policy facts.
    /// It reports what the executor recorded, not a fresh host observation.
    pub fn observe(anchor: &TrustAnchor) -> Result<serde_json::Value, ExecutorError> {
        let loaded = load_state_policy(anchor)?;
        let signer = crate::signer::facts(&loaded.allowed_signers, &loaded.revocations);
        let policy = &loaded.policy;
        let seen = FixtureJournal::observe_as_process_owner(
            &anchor.journal_dir,
            &policy.host_id,
            &policy.host_epoch,
        )
        .map_err(|error| match error {
            JournalError::Conflict => ExecutorError::IdentityMismatch,
            other => other.into(),
        })?;
        let mut observation =
            observation_json(policy, &seen, crate::packages::query().as_deref(), signer);
        let verifier_matches = crate::signature::check_verifier(&loaded).is_ok();
        if let Some(backup) = loaded.product_backup {
            observation["host"]["product_backup_enrollment"] = serde_json::json!({
                "destination_id": backup.destination_id(),
                "destination_policy_digest": backup.digest(),
            });
        }
        // W464 (D-060): each served certificate and its finding; the key is
        // absent on a host without one, so earlier observations are unchanged.
        if !seen.certificates.is_empty() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs());
            observation["certificates"] = serde_json::Value::Array(
                seen.certificates
                    .iter()
                    .map(|served| {
                        serde_json::json!({
                            "site_id": served.site_id,
                            "hostname": served.hostname,
                            "certificate_sha256": served.certificate_sha256,
                            "not_after": served.not_after,
                            "finding": certificate_finding(served, now),
                            // W473-F1: `finding` names the most urgent fact;
                            // a failed renewal stays visible beside it.
                            "last_renewal_failed": served.last_renewal_failed,
                            // D-064: who renews it.
                            "renewed_by": if served.ejected { "operator" } else { "rustiron" },
                        })
                    })
                    .collect(),
            );
        }
        // W483-F1 (P06): whether the installed signature verifier still has
        // the enrolled digest. An openssh update replaces it, and then every
        // signed request is refused until the digest is measured again.
        observation["host"]["signature_verifier"] = serde_json::json!({
            "matches_enrollment": verifier_matches,
        });
        // W392: the public receipt key, for the operator's off-host record.
        observation["host"]["receipt_key"] = crate::receipt_key::facts(
            &anchor.policy_dir.join(crate::receipt_key::KEY_DIR),
            anchor.owner_uid,
        );
        // W594 (P23, D-098): durable consumed and remaining authority budget.
        let window_seconds = policy
            .blast_radius
            .as_ref()
            .map_or(3600_i64, |limits| limits.window_seconds as i64);
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs() as i64);
        let anchor_time = seen.last_time.max(now_unix);
        let window_start = anchor_time.saturating_sub(window_seconds);
        let usage = FixtureJournal::observe_authority_usage_as_process_owner(
            &anchor.journal_dir,
            &policy.host_id,
            &policy.host_epoch,
            window_start,
        )
        .map_err(|error| match error {
            JournalError::Conflict => ExecutorError::IdentityMismatch,
            other => other.into(),
        })?;
        let budget = rustiron_contracts::approval::AuthorityBudgetReport::build(
            policy.blast_radius.clone(),
            usage,
        );
        observation["authority_budget"] =
            serde_json::to_value(&budget).map_err(|_| ExecutorError::Unavailable)?;
        Ok(observation)
    }

    /// Opens only valid existing state bound to the enrolled host/epoch and
    /// not behind its admission mark; a journal ahead of the mark (a crash
    /// between the journal commit and the mark update) moves the mark up.
    pub fn open(anchor: TrustAnchor) -> Result<Self, ExecutorError> {
        let mut executor = Self::open_unfenced(anchor)?;
        executor.fence()?;
        Ok(executor)
    }

    fn open_unfenced(anchor: TrustAnchor) -> Result<Self, ExecutorError> {
        let (host_id, host_epoch) = prepare(&anchor)?;
        let journal = FixtureJournal::open_as_process_owner(
            &anchor.journal_dir,
            host_id.clone(),
            host_epoch.clone(),
        )
        .map_err(|error| match error {
            JournalError::Conflict => ExecutorError::IdentityMismatch,
            other => other.into(),
        })?;
        Ok(Self {
            anchor,
            journal,
            identity: (host_id, host_epoch),
            admitted: HashSet::new(),
            #[cfg(feature = "fault-injection")]
            fault: None,
            #[cfg(feature = "fault-injection")]
            readopt_observation: None,
        })
    }

    /// Admin, service stopped: writes the admission mark for a journal that
    /// has none for its host and epoch (first deployment of the mark, or a
    /// crash right after an initialize). Refused while a mark for this host
    /// and epoch exists. The operator asserts the journal is current; root
    /// on the host can always make that claim (see W048 limits).
    pub fn seal_admission_mark(anchor: TrustAnchor) -> Result<u64, ExecutorError> {
        let executor = Self::open_unfenced(anchor)?;
        let (host, epoch) = &executor.identity;
        if mark::read(&executor.anchor)?
            .is_some_and(|seen| seen.host == host.as_str() && seen.epoch == epoch.as_str())
        {
            return Err(ExecutorError::StateExists);
        }
        let count = executor.journal.admission_count()?;
        mark::write(&executor.anchor, host, epoch, count)?;
        Ok(count)
    }

    /// W381 (D-032): the OLS boot guard, before `lshttpd`, the admin helper
    /// and the executor start. It holds the journal writer lease for the
    /// whole run, so it refuses to act while an executor runs. It checks the
    /// journal against the admission mark but never moves the mark, and it
    /// records nothing in the journal. See [`ols::boot_guard`].
    pub fn ols_boot_guard(anchor: TrustAnchor) -> ols::boot_guard::GuardReport {
        use ols::boot_guard::{self, JournalFinding};
        let executor = Self::open_unfenced(anchor);
        let journal = match &executor {
            Err(error) => JournalFinding::Unknown(error.code()),
            Ok(executor) => executor.boot_guard_finding(),
        };
        // The link is read for the report in every case; only a pending
        // activation can lead to a change.
        let include = ols::open_include();
        let report = boot_guard::run(journal, include, |include, predecessor| {
            ols::generation_digest(include, &predecessor.0).as_ref() == Ok(&predecessor.1)
        });
        drop(executor);
        report
    }

    /// W381: the journal finding of the boot guard; any error is unknown.
    fn boot_guard_finding(&self) -> ols::boot_guard::JournalFinding {
        use ols::boot_guard::JournalFinding;
        let (host, epoch) = &self.identity;
        match pending_boot_activation(&self.anchor, host, epoch, &self.journal) {
            Ok(Some(activation)) => JournalFinding::Pending(activation),
            Ok(None) => JournalFinding::Settled,
            Err(error) => JournalFinding::Unknown(error.code()),
        }
    }

    /// Refuses unless the journal is at or ahead of the admission mark, and
    /// moves the mark up to the journal. Returns the journal's count.
    fn fence(&mut self) -> Result<u64, ExecutorError> {
        let (host, epoch) = &self.identity;
        let seen = mark::read(&self.anchor)?;
        let count = self.journal.admission_count()?;
        mark::check(seen.as_ref(), host, epoch, count)?;
        if seen.is_some_and(|seen| count > seen.count) {
            mark::write(&self.anchor, host, epoch, count)?;
        }
        Ok(count)
    }

    /// One journal admission inside the fence: refused if the journal is
    /// behind the mark; after the journal commit the mark is fsynced to the
    /// new count. A crash in between leaves the journal ahead, which `open`
    /// accepts. If the mark cannot be written the error is returned and the
    /// committed intent is left for status and reconcile, never executed by
    /// this call's caller.
    ///
    /// W396 (D-045): `signed` holds the verified canonical plan and grant.
    /// The record call stores them with a new intent, in its transaction.
    fn admit<T>(
        &mut self,
        staged: StagedAdmission,
        record: impl FnOnce(&mut FixtureJournal) -> Result<T, JournalError>,
    ) -> Result<T, ExecutorError> {
        let before = self.fence()?;
        self.enforce_blast_radius(&staged)?;
        self.journal.stage_signed(staged.signed);
        let result = record(&mut self.journal);
        self.journal.clear_signed();
        let result = result?;
        let after = self.journal.admission_count()?;
        if after > before {
            let (host, epoch) = &self.identity;
            mark::write(&self.anchor, host, epoch, after)?;
        }
        Ok(result)
    }

    /// W700 (W689 candidate 3): the shared opening of a signed verb, in one
    /// fixed order: the enrolled identity, the request time, then the replay
    /// rule. An operation the journal already holds (`stored`) skips the
    /// fresh checks and goes to the recording transaction, which returns it
    /// only for an exact replay and refuses any other request. A new
    /// operation must pass `fresh` before [`Self::admit`] records it.
    fn admit_signed<Row>(
        &mut self,
        request: &AdmissionRequest<'_>,
        (host_id, host_epoch): (&Id, &Id),
        stored: impl FnOnce(&FixtureJournal) -> Result<bool, JournalError>,
        fresh: impl FnOnce(&Self, Timestamp) -> Result<(), ExecutorError>,
        record: impl FnOnce(&mut FixtureJournal, Timestamp) -> Result<Admitted<Row>, JournalError>,
    ) -> Result<Admitted<Row>, ExecutorError> {
        self.check_identity(host_id, host_epoch)?;
        let now = request.now.ok_or(ExecutorError::TimeDenied)?;
        if !stored(&self.journal)? {
            fresh(self, now)?;
        }
        self.admit(signed_inputs(request)?, |journal| record(journal, now))
    }

    /// W594 (P23, D-098) & W633 (M-25): enforces enrolled `blast_radius` limits
    /// durably against the SQLite journal before any new intent is committed.
    /// Only exact replays matching the recorded `operation_id`, plan digest, and
    /// grant digest bypass budget deduction, so later standing-capture runs with
    /// distinct derived operation IDs are counted against enrolled budgets.
    fn enforce_blast_radius(&self, staged: &StagedAdmission) -> Result<(), ExecutorError> {
        let loaded = load_state_policy(&self.anchor)?;
        let Some(limits) = &loaded.policy.blast_radius else {
            return Ok(());
        };
        let signed = &staged.signed;
        let plan_sha = rustiron_contracts::approval::Sha256Digest::from_bytes(
            sha2::Sha256::digest(&signed.plan).into(),
        );
        let grant_sha = rustiron_contracts::approval::Sha256Digest::from_bytes(
            sha2::Sha256::digest(&signed.grant).into(),
        );
        if self.journal.has_signed_admission_for_operation(
            staged.operation_id.as_str(),
            plan_sha.as_str(),
            grant_sha.as_str(),
        )? {
            return Ok(());
        }
        let envelope = rustiron_contracts::approval::envelope_for_plan(&signed.plan)
            .ok_or(ExecutorError::InvalidRequest)?;
        let last_time = self.journal.last_time()?;
        let valid_from = rustiron_contracts::approval::plan_window_bounds(&signed.plan)
            .map_or(0_i64, |(from, _)| from as i64);
        let anchor_time = last_time.max(valid_from);
        let window_start = anchor_time.saturating_sub(limits.window_seconds as i64);
        let usage = self.journal.authority_usage(window_start)?;
        rustiron_contracts::approval::check_envelope_budget(limits, &envelope, &usage)
            .map_err(|_| ExecutorError::PreconditionChanged)?;
        Ok(())
    }

    /// Runs every [`admit`](crate::admit) check and then records intent in one transaction,
    /// consuming the grant, nonce, operation and retry key. An exact verified
    /// repeat returns stored status before the live check, since a completed
    /// effect has moved the predecessor. Policy is re-read on every call.
    pub fn submit(
        &mut self,
        request: &AdmissionRequest<'_>,
    ) -> Result<Admitted<Operation>, ExecutorError> {
        let intent = verified_intent(&self.anchor, request)?;
        self.check_identity(&intent.host_id, &intent.host_epoch)?;
        if let Some(existing) = self.journal.existing(&intent)? {
            return Ok(Admitted::Existing(existing));
        }
        check_live(&self.anchor, &intent)?;
        let now = request.now.ok_or(ExecutorError::TimeDenied)?;
        let result = self.admit(signed_inputs(request)?, |journal| {
            journal.record_intent(&intent, now)
        })?;
        if let Admitted::New(operation) = &result {
            self.admitted
                .insert(operation.intent.operation_id.as_str().to_owned());
        }
        Ok(result)
    }

    /// Performs the bound generation switch for an intent this instance just
    /// recorded, then records what the executor itself observes. Every path
    /// after admission ends in a recorded observation; an `Err` describes why
    /// the effect was not completed and the stored state tells what is known.
    pub fn execute(
        &mut self,
        operation_id: &Id,
        now: Option<Timestamp>,
    ) -> Result<Operation, ExecutorError> {
        if !self.admitted.remove(operation_id.as_str()) {
            return Err(ExecutorError::NotAdmitted);
        }
        let operation = self
            .journal
            .status(operation_id)?
            .filter(|operation| operation.state == RecordedState::Intent)
            .ok_or(ExecutorError::NotAdmitted)?;
        let intent = &operation.intent;
        if now.is_none_or(|now| now.get() >= intent.expires_at.get()) {
            self.observe_and_record(operation_id, &intent.resource_id)?;
            return Err(ExecutorError::TimeDenied);
        }
        let owner = self.anchor.owner_uid;
        let registry_dir = match files::open_trusted_directory(&self.anchor.registry_dir, owner) {
            Ok(directory) => directory,
            Err(error) => {
                self.record(operation_id, None)?;
                return Err(error);
            }
        };
        let live = registry::observe(&registry_dir, &intent.resource_id, owner);
        if !live.as_ref().is_ok_and(|live| {
            live.generation == intent.predecessor_generation
                && live.digest == intent.predecessor_digest
        }) {
            self.record(operation_id, live.ok())?;
            return Err(ExecutorError::PreconditionChanged);
        }
        self.journal.mark_effect_attempted(operation_id)?;
        self.fault(Fault::AfterAttemptMark)?;
        let outcome = registry::switch(
            &registry_dir,
            &intent.resource_id,
            &intent.target_generation,
            &intent.target_digest,
            owner,
        );
        self.fault(Fault::AfterSwitch)?;
        let observed = registry::observe(&registry_dir, &intent.resource_id, owner).ok();
        let recorded = self.record(operation_id, observed)?;
        match outcome {
            SwitchOutcome::NotAttempted(error) => Err(error),
            SwitchOutcome::Attempted(_) => Ok(recorded),
        }
    }

    /// The single signed compensation: restore the recorded predecessor for an
    /// attempted effect that ended in `needs_attention`, before the grant's
    /// compensation deadline. The attempt is recorded before the switch, so it
    /// can never run twice, including across restarts.
    pub fn compensate(
        &mut self,
        operation_id: &Id,
        now: Option<Timestamp>,
    ) -> Result<Operation, ExecutorError> {
        let now = now.ok_or(ExecutorError::TimeDenied)?;
        self.ols_restore_refusal(operation_id)?;
        let operation = self
            .journal
            .begin_compensation(operation_id, now)
            .map_err(|error| match error {
                JournalError::Conflict => ExecutorError::CompensationDenied,
                other => other.into(),
            })?;
        let intent = &operation.intent;
        self.fault(Fault::AfterCompensationMark)?;
        if intent.resource_id == ols_resource()? {
            let intent = intent.clone();
            return self.compensate_ols(operation_id, &intent);
        }
        let owner = self.anchor.owner_uid;
        let registry_dir = match files::open_trusted_directory(&self.anchor.registry_dir, owner) {
            Ok(directory) => directory,
            Err(error) => {
                self.record(operation_id, None)?;
                return Err(error);
            }
        };
        let outcome = registry::switch(
            &registry_dir,
            &intent.resource_id,
            &intent.predecessor_generation,
            &intent.predecessor_digest,
            owner,
        );
        self.fault(Fault::AfterCompensationSwitch)?;
        let observed = registry::observe(&registry_dir, &intent.resource_id, owner).ok();
        let recorded = self.record(operation_id, observed)?;
        match outcome {
            SwitchOutcome::NotAttempted(error) => Err(error),
            SwitchOutcome::Attempted(_) => Ok(recorded),
        }
    }

    /// Test-only crash simulation: stop at `fault` without recording anything.
    #[cfg(feature = "fault-injection")]
    pub fn inject_fault(&mut self, fault: Fault) {
        self.fault = Some(fault);
    }

    #[cfg(feature = "fault-injection")]
    fn fault(&mut self, point: Fault) -> Result<(), ExecutorError> {
        if self.fault == Some(point) {
            self.fault = None;
            return Err(ExecutorError::Unavailable);
        }
        Ok(())
    }

    #[cfg(not(feature = "fault-injection"))]
    #[inline(always)]
    fn fault(&mut self, _: Fault) -> Result<(), ExecutorError> {
        Ok(())
    }

    /// Records the executor's own current observation for an unresolved
    /// operation, e.g. after a restart. Never performs or repeats an effect.
    pub fn reconcile(&mut self, operation_id: &Id) -> Result<Operation, ExecutorError> {
        let operation = self
            .journal
            .status(operation_id)?
            .ok_or(ExecutorError::NotAdmitted)?;
        if !operation.state.is_unresolved() {
            return Ok(operation);
        }
        if operation.intent.resource_id == ols_resource()? {
            return self.reconcile_ols(operation_id, &operation.intent, operation.effect_attempted);
        }
        self.observe_and_record(operation_id, &operation.intent.resource_id)
    }

    /// OLS recovery observation. A symlink is not effective state, so the
    /// predecessor is recorded only after a bounded recycle (reload) and
    /// identity probes for adopted sites and every registered provision; an
    /// interrupted activation found on its target is never claimed verified
    /// by observation (it stays `needs_attention` for the single signed restore).
    ///
    /// W384: without the effect mark, the activation never switched
    /// `current` and never asked for a reload; it only staged under new
    /// names. The admin helper allows no serving step in that state (only
    /// the preflight), so `reconcile` asks for none and records the live
    /// predecessor that the history before the operation explains.
    fn reconcile_ols(
        &mut self,
        operation_id: &Id,
        intent: &Intent,
        effect_attempted: bool,
    ) -> Result<Operation, ExecutorError> {
        if ols::is_bootstrap_predecessor(&intent.predecessor_generation, &intent.predecessor_digest)
        {
            return self.reconcile_bootstrap(operation_id);
        }
        let policy = self.ols_policy()?;
        let include = ols::open_include()?;
        let predecessor = (
            intent.predecessor_generation.clone(),
            intent.predecessor_digest.clone(),
        );
        let observed = match ols::observe(&include) {
            Ok(live) if live == predecessor => {
                // W362: reload only over a `current` that the history before
                // this operation explains; a refusal records nothing.
                let established = self.established_before(operation_id)?;
                if let Some(checks) = ols::generation_refusal(&live, established.as_ref()) {
                    eprintln!(
                        "{{\"scope\":\"ols_reconcile\",\"content_addressed\":{},\"explained\":\"{:?}\"}}",
                        checks.0, checks.1
                    );
                    return Err(ExecutorError::Drift);
                }
                if !effect_attempted {
                    return Ok(self.journal.record_observation(
                        operation_id,
                        Some(&live.0),
                        Some(&live.1),
                    )?);
                }
                let socket = self.anchor.admin_socket.clone();
                if let Some(path) = socket.as_deref() {
                    // W222: a missing helper is a visible error, not "nothing ran".
                    admin_helper::reach(
                        path,
                        admin_helper::REACH_ATTEMPTS,
                        admin_helper::REACH_PAUSE,
                    )?;
                }
                let ask = |step| AdminRequest {
                    operation_id: operation_id.clone(),
                    step,
                };
                let stepped =
                    admin_helper::route(socket.as_deref(), &ask(AdminStep::OlsReload), || {
                        provision::run("/usr/bin/systemctl", &["reload", "lshttpd.service"])
                    })
                    .and_then(|()| self.restore_ejected_php(operation_id, socket.as_deref()))
                    .and_then(|()| {
                        admin_helper::route(socket.as_deref(), &ask(AdminStep::OlsVerify), || {
                            self.probe_registered(&policy)
                        })
                    });
                reconcile_step(stepped)?
                    .then(|| self.observe_restored_ols(&include, intent).ok())
                    .flatten()
            }
            _ => None,
        };
        let (generation, digest) = match &observed {
            Some((id, digest)) => (Some(id), Some(digest)),
            None => (None, None),
        };
        Ok(self
            .journal
            .record_observation(operation_id, generation, digest)?)
    }

    /// W382 (D-033): the reconcile of an interrupted bootstrap activation.
    /// Its predecessor is "no generation": no `current`, OLS stopped, and
    /// both ports closed. Through the admin helper, the read-only
    /// `ols_bootstrap_confirm` step decides those facts from the journal and
    /// the live host; in this process (D-016 lab mode) the executor reads
    /// them itself. Only a confirmation records the bootstrap predecessor:
    /// the journal then records `untouched`, or `failed_compensated` after
    /// the restore mark. Anything else records no observation
    /// (`needs_attention`), and a binding refusal is an error that records
    /// nothing. Nothing is started, stopped, or removed.
    fn reconcile_bootstrap(&mut self, operation_id: &Id) -> Result<Operation, ExecutorError> {
        let confirmed = match self.anchor.admin_socket.clone() {
            Some(path) => {
                // W222: a missing helper is a visible error, not "nothing ran".
                admin_helper::reach(
                    &path,
                    admin_helper::REACH_ATTEMPTS,
                    admin_helper::REACH_PAUSE,
                )?;
                let request = AdminRequest {
                    operation_id: operation_id.clone(),
                    step: AdminStep::OlsBootstrapConfirm,
                };
                reconcile_step(admin_helper::route(Some(&path), &request, || {
                    Err(ExecutorError::Unavailable)
                }))?
            }
            None => {
                let policy = self.ols_policy()?;
                let include = ols::open_include()?;
                let facts = self.bootstrap_facts(&policy, &include, Some(operation_id))?;
                if !facts.predecessor_confirmed() {
                    eprintln!("{{\"scope\":\"ols_bootstrap_reconcile\",\"facts\":\"{facts:?}\"}}");
                }
                facts.predecessor_confirmed()
            }
        };
        let observed = confirmed.then(ols::bootstrap_generation);
        Ok(self.journal.record_observation(
            operation_id,
            observed.as_ref().map(|(id, _)| id),
            observed.as_ref().map(|(_, digest)| digest),
        )?)
    }

    /// W362: refuses the OLS restore of a predecessor that the history before
    /// `operation_id` does not explain, before the compensation mark, so a
    /// refusal records nothing and spends no compensation. Other resources
    /// and operations that the journal would not let compensate pass to the
    /// journal's own refusal.
    fn ols_restore_refusal(&self, operation_id: &Id) -> Result<(), ExecutorError> {
        let Some(operation) = self.journal.status(operation_id)? else {
            return Ok(());
        };
        let intent = &operation.intent;
        let compensable = operation.state == RecordedState::NeedsAttention
            && operation.effect_attempted
            && !operation.compensation_attempted;
        if intent.resource_id != ols_resource()? || !compensable {
            return Ok(());
        }
        let predecessor = (
            intent.predecessor_generation.clone(),
            intent.predecessor_digest.clone(),
        );
        let established = self.established_before(operation_id)?;
        match ols::restore_refusal(&predecessor, established.as_ref()) {
            None => Ok(()),
            Some(checks) => {
                eprintln!(
                    "{{\"scope\":\"ols_compensate\",\"content_addressed\":{},\"explained\":\"{:?}\"}}",
                    checks.0, checks.1
                );
                Err(ExecutorError::Drift)
            }
        }
    }

    /// The single signed OLS restore: switch back only to a predecessor whose
    /// stored bytes still match its recorded digest, reload, probe, record.
    fn compensate_ols(
        &mut self,
        operation_id: &Id,
        intent: &Intent,
    ) -> Result<Operation, ExecutorError> {
        if ols::is_bootstrap_predecessor(&intent.predecessor_generation, &intent.predecessor_digest)
        {
            // W355: the bootstrap restore: stop OLS, remove `current`.
            let restored = self.ols_policy().and_then(|policy| {
                let include = ols::open_include()?;
                self.restore_bootstrap(operation_id, &policy, &include)
                    .ok_or(ExecutorError::StepFailed)
            });
            let observed = restored.as_ref().ok();
            let recorded = self.journal.record_observation(
                operation_id,
                observed.map(|(id, _)| id),
                observed.map(|(_, digest)| digest),
            )?;
            return restored.map(|_| recorded);
        }
        let restored = self.ols_policy().and_then(|policy| {
            let include = ols::open_include()?;
            if ols::generation_digest(&include, &intent.predecessor_generation)?
                != intent.predecessor_digest
            {
                return Err(ExecutorError::Drift);
            }
            ols::switch(&include, &intent.predecessor_generation)?;
            let socket = self.anchor.admin_socket.clone();
            let ask = |step| AdminRequest {
                operation_id: operation_id.clone(),
                step,
            };
            admin_helper::route(socket.as_deref(), &ask(AdminStep::OlsReload), || {
                provision::run("/usr/bin/systemctl", &["reload", "lshttpd.service"])
            })?;
            self.restore_ejected_php(operation_id, socket.as_deref())?;
            admin_helper::route(socket.as_deref(), &ask(AdminStep::OlsVerify), || {
                self.probe_registered(&policy)
            })?;
            // W370: the restore of a page-cache change also deactivates the
            // plugin as the site and empties the site's storage, so an
            // interrupted plugin step never leaves the plugin active.
            if let Some(site) = self.page_cache_change_site(operation_id)? {
                admin_helper::route(socket.as_deref(), &ask(AdminStep::PageCacheRemove), || {
                    let hostname = self
                        .journal
                        .provision_for_site(&site)?
                        .ok_or(ExecutorError::Unavailable)?
                        .intent
                        .hostname;
                    page_cache::remove(
                        &provision::SiteLayout::derive(&site),
                        &policy.address,
                        &hostname,
                    )
                    .map(drop)
                })?;
            }
            self.observe_restored_ols(&include, intent)
        });
        let observed = restored.as_ref().ok();
        let recorded = self.journal.record_observation(
            operation_id,
            observed.map(|(id, _)| id),
            observed.map(|(_, digest)| digest),
        )?;
        restored.map(|_| recorded)
    }

    /// W387 (D-037): for an ejection, on its restored predecessor, enable
    /// and start the site's Rustiron PHP socket and sandbox timer again,
    /// which its stop step may have disabled. Nothing for an activation.
    fn restore_ejected_php(
        &self,
        operation_id: &Id,
        socket: Option<&std::path::Path>,
    ) -> Result<(), ExecutorError> {
        let Some(site) = self.journal.ejection_site(operation_id)? else {
            return Ok(());
        };
        let account = provision::SiteLayout::derive(&site).account;
        let request = AdminRequest {
            operation_id: operation_id.clone(),
            step: AdminStep::EjectPhpRestore,
        };
        admin_helper::route(socket, &request, || {
            crate::ejection::restore_site_php(&account)
        })
    }

    /// Accepts recovery only on the exact predecessor. For eject, the
    /// managed vhost must be present before the standalone copy can move.
    fn observe_restored_ols(
        &self,
        include: &std::os::fd::OwnedFd,
        intent: &Intent,
    ) -> Result<(Id, Sha256Digest), ExecutorError> {
        let live = ols::observe(include)?;
        if live.0 != intent.predecessor_generation || live.1 != intent.predecessor_digest {
            return Err(ExecutorError::Drift);
        }
        if let Some(site) = self.journal.ejection_site(&intent.operation_id)? {
            let account = site.account_name();
            if !ols::managed_accounts(include, &live.0)?.contains(&account) {
                return Err(ExecutorError::Drift);
            }
            ols::archive_ejected(&account, &intent.operation_id, &intent.grant_digest)?;
        }
        Ok(live)
    }

    /// W370: the site of the page-cache opt-in or opt-out that an
    /// operation records, if any.
    fn page_cache_change_site(
        &self,
        operation_id: &Id,
    ) -> Result<Option<rustiron_contracts::approval::SiteId>, ExecutorError> {
        Ok(match self.journal.page_cache_site(operation_id)? {
            Some(site) => Some(site),
            None => self.journal.page_cache_opt_out_site(operation_id)?,
        })
    }

    /// W355: the bootstrap facts in this process (D-016 lab mode). The
    /// history is the journal's before `operation`, or before any new one.
    fn bootstrap_facts(
        &self,
        policy: &crate::policy::OlsPolicy,
        include: &std::os::fd::OwnedFd,
        operation: Option<&Id>,
    ) -> Result<ols::BootstrapFacts, ExecutorError> {
        let history = self.ols_history(operation)?;
        let adopted: Vec<&str> = policy.adopted.iter().map(|s| s.name.as_str()).collect();
        ols::BootstrapFacts::observe(
            history,
            include,
            &policy.parent_sha256,
            &policy.ports()?,
            &adopted,
        )
    }

    /// W355: the bootstrap compensation. Stops OLS (through the helper when
    /// enrolled) and waits for the stopped state, then removes `current`.
    /// Returns the bootstrap generation to record only when all of that
    /// holds; otherwise prints the facts and returns `None`, so the
    /// operation stays `needs_attention`.
    fn restore_bootstrap(
        &self,
        operation: &Id,
        policy: &crate::policy::OlsPolicy,
        include: &std::os::fd::OwnedFd,
    ) -> Option<(Id, Sha256Digest)> {
        let request = AdminRequest {
            operation_id: operation.clone(),
            step: AdminStep::OlsStop,
        };
        let stopped = admin_helper::route(self.anchor.admin_socket.as_deref(), &request, || {
            ols::stop_and_wait(&policy.ports()?)
        })
        .and_then(|()| ols::clear_current(include));
        let current = ols::observe_current(include);
        let restored = ols::bootstrap_restored(&stopped, &current);
        if restored.is_none() {
            eprintln!(
                "{{\"scope\":\"ols_bootstrap_compensation\",\"stop_and_clear\":\"{stopped:?}\",\"current\":\"{current:?}\"}}"
            );
        }
        restored
    }

    fn ols_policy(&self) -> Result<crate::policy::OlsPolicy, ExecutorError> {
        let owner = self.anchor.owner_uid;
        let loaded = crate::policy::load(
            &crate::files::open_trusted_directory(&self.anchor.policy_dir, owner)?,
            owner,
        )?;
        loaded.policy.ols.ok_or(ExecutorError::Unavailable)
    }

    fn observe_and_record(
        &mut self,
        operation_id: &Id,
        resource: &Id,
    ) -> Result<Operation, ExecutorError> {
        let owner = self.anchor.owner_uid;
        let observed = files::open_trusted_directory(&self.anchor.registry_dir, owner)
            .and_then(|directory| registry::observe(&directory, resource, owner))
            .ok();
        self.record(operation_id, observed)
    }

    fn record(
        &mut self,
        operation_id: &Id,
        observed: Option<registry::LiveObservation>,
    ) -> Result<Operation, ExecutorError> {
        let (generation, digest) = match &observed {
            Some(live) => (Some(&live.generation), Some(&live.digest)),
            None => (None, None),
        };
        Ok(self
            .journal
            .record_observation(operation_id, generation, digest)?)
    }

    /// Admits one signed `site_provision` and runs its steps in journal order.
    /// Each step's intent is durable before its effect; any failure leaves the
    /// created resources and quarantines the provision. An exact verified
    /// repeat returns stored status and runs nothing.
    pub fn provision(
        &mut self,
        request: &AdmissionRequest<'_>,
    ) -> Result<Admitted<Provision>, ExecutorError> {
        let crate::VerifiedSite {
            intent,
            enrolled,
            recipe,
            quota_limits,
        } = verified_site(&self.anchor, request)?;
        self.check_identity(&intent.host_id, &intent.host_epoch)?;
        let now = request.now.ok_or(ExecutorError::TimeDenied)?;
        // W372: an exact repeat answers from the journal, before the live
        // collision check (a succeeded provision's account exists).
        if let Some(existing) = self.journal.provision_status(&intent.operation_id)? {
            // W446: an import with the same intent is not this provision.
            let import = self.journal.import_status(&intent.operation_id)?;
            let proxy = self.journal.proxy_facts(&intent.operation_id)?;
            return if existing.intent == intent && import.is_none() && proxy.is_none() {
                Ok(Admitted::Existing(existing))
            } else {
                Err(ExecutorError::ReplayDenied)
            };
        }
        // W372 (W369 finding): an existing account, group or site root is a
        // collision before intent, so it records nothing and the site ID
        // stays free for a re-adoption.
        self.provision_collision(&provision::SiteLayout::derive(&intent.site_id))?;
        let operation = match self.admit(signed_inputs(request)?, |journal| {
            journal.record_provision(&intent, now)
        })? {
            Admitted::Existing(existing) => return Ok(Admitted::Existing(existing)),
            Admitted::New(created) => created.intent.operation_id,
        };
        let quota = crate::quota::QuotaIntent::select(quota_limits, enrolled.quota);
        self.run_provision_steps(
            &operation,
            &intent,
            &enrolled,
            quota,
            StepRecipe::Site(recipe),
        )
    }

    /// W446 (D-053): admits one signed `site_import` and runs the provision
    /// steps with the import steps inside the Recipe step, in journal order.
    /// Before intent the intake archive is checked, so a wrong archive
    /// creates nothing. An exact verified repeat returns stored status.
    pub fn import(
        &mut self,
        request: &AdmissionRequest<'_>,
    ) -> Result<Admitted<Provision>, ExecutorError> {
        let crate::VerifiedImport {
            intent,
            enrolled,
            quota_limits,
            archive_sha256,
            manifest_sha256,
            file_entries,
            file_bytes,
            dump_bytes,
            target_php,
            source_hostname,
            alias_hostname,
        } = crate::verified_import(&self.anchor, request)?;
        self.check_identity(&intent.host_id, &intent.host_epoch)?;
        let now = request.now.ok_or(ExecutorError::TimeDenied)?;
        let facts = rustiron_journal::ImportFacts {
            archive_sha256,
            manifest_sha256,
            file_entries,
            file_bytes,
            dump_bytes,
            target_php,
            source_hostname,
            alias_hostname,
        };
        if let Some(existing) = self.journal.provision_status(&intent.operation_id)? {
            let recorded = self.journal.import_status(&intent.operation_id)?;
            return if existing.intent == intent
                && recorded.is_some_and(|import| import.facts == facts)
            {
                Ok(Admitted::Existing(existing))
            } else {
                Err(ExecutorError::ReplayDenied)
            };
        }
        self.provision_collision(&provision::SiteLayout::derive(&intent.site_id))?;
        crate::import::intake(
            std::path::Path::new(crate::layout::MIGRATION_INTAKE_DIR),
            self.anchor.owner_uid,
            &intent.site_id,
            &facts.archive_sha256,
            crate::import::MAX_ARCHIVE_BYTES,
        )?;
        let operation = match self.admit(signed_inputs(request)?, |journal| {
            journal.record_import(&intent, &facts, now)
        })? {
            Admitted::Existing(existing) => return Ok(Admitted::Existing(existing)),
            Admitted::New(created) => created.intent.operation_id,
        };
        let quota = crate::quota::QuotaIntent::select(Some(quota_limits), enrolled.quota);
        self.run_provision_steps(
            &operation,
            &intent,
            &enrolled,
            quota,
            StepRecipe::Import(&facts),
        )
    }

    /// W572 (D-095): admits one signed `proxy_site_provision` and runs the
    /// provision steps of a proxy site, in journal order. The routes are
    /// journaled with the reservation; nothing contacts a port behind the
    /// site. An exact verified repeat returns stored status.
    pub fn provision_proxy(
        &mut self,
        request: &AdmissionRequest<'_>,
    ) -> Result<Admitted<Provision>, ExecutorError> {
        let crate::VerifiedProxy {
            intent,
            enrolled,
            facts,
        } = crate::verified_proxy(&self.anchor, request)?;
        self.check_identity(&intent.host_id, &intent.host_epoch)?;
        let now = request.now.ok_or(ExecutorError::TimeDenied)?;
        if let Some(existing) = self.journal.provision_status(&intent.operation_id)? {
            let recorded = self.journal.proxy_facts(&intent.operation_id)?;
            return if existing.intent == intent && recorded.as_ref() == Some(&facts) {
                Ok(Admitted::Existing(existing))
            } else {
                Err(ExecutorError::ReplayDenied)
            };
        }
        self.provision_collision(&provision::SiteLayout::derive(&intent.site_id))?;
        let operation = match self.admit(signed_inputs(request)?, |journal| {
            journal.record_proxy_provision(&intent, &facts, now)
        })? {
            Admitted::Existing(existing) => return Ok(Admitted::Existing(existing)),
            Admitted::New(created) => created.intent.operation_id,
        };
        // The plan signs no quota: the enrolled policy limits apply.
        let quota = crate::quota::QuotaIntent::select(None, enrolled.quota);
        self.run_provision_steps(&operation, &intent, &enrolled, quota, StepRecipe::Proxy)
    }

    /// W598 (D-099) & W659 (D-102): admits one signed `app_provision` (v1 or v2
    /// full-stack/Caddy/PostgreSQL 18) and runs its confined provision steps in
    /// journal order.
    pub fn provision_app(
        &mut self,
        request: &AdmissionRequest<'_>,
    ) -> Result<Admitted<Provision>, ExecutorError> {
        let crate::VerifiedAppProvision {
            intent,
            enrolled,
            facts,
            fullstack,
        } = crate::verified_app_provision(&self.anchor, request)?;
        self.check_identity(&intent.host_id, &intent.host_epoch)?;
        let now = request.now.ok_or(ExecutorError::TimeDenied)?;
        if let Some(existing) = self.journal.provision_status(&intent.operation_id)? {
            let recorded = self.journal.app_facts(&intent.operation_id)?;
            let recorded_spec = self.journal.app_fullstack_spec(&intent.operation_id)?;
            return if existing.intent == intent
                && recorded.as_ref() == Some(&facts)
                && recorded_spec == fullstack
            {
                Ok(Admitted::Existing(existing))
            } else {
                Err(ExecutorError::ReplayDenied)
            };
        }
        self.provision_collision(&provision::SiteLayout::derive(&intent.site_id))?;
        let block_hard_kib = facts.quota_mib.saturating_mul(1024);
        let requested_quota = match enrolled.quota {
            Some(cap) => {
                if block_hard_kib > cap.block_hard_kib {
                    return Err(ExecutorError::BindingDenied);
                }
                Some(crate::quota::QuotaLimits {
                    block_hard_kib,
                    inode_hard: cap.inode_hard,
                })
            }
            None => None,
        };
        let operation = match self.admit(signed_inputs(request)?, |journal| match &fullstack {
            Some(spec) => journal.record_fullstack_app_provision(&intent, &facts, spec, now),
            None => journal.record_app_provision(&intent, &facts, now),
        })? {
            Admitted::Existing(existing) => return Ok(Admitted::Existing(existing)),
            Admitted::New(created) => created.intent.operation_id,
        };
        let quota = crate::quota::QuotaIntent::select(requested_quota, enrolled.quota);
        self.run_provision_steps(
            &operation,
            &intent,
            &enrolled,
            quota,
            StepRecipe::App(&facts, fullstack.as_ref()),
        )
    }

    /// W598 (D-099) & W659 (D-102): admits one signed `app_deploy` release
    /// bundle and runs `Unpack` -> optional `Migrate` -> `Activate` -> `Health`
    /// -> optional blue/green Caddy cutover, automatically running `Rollback`
    /// on any failure.
    pub fn deploy_app(
        &mut self,
        request: &AdmissionRequest<'_>,
    ) -> Result<Admitted<rustiron_journal::AppRelease>, ExecutorError> {
        let crate::VerifiedAppDeploy {
            intent,
            blue_green_cutover,
        } = crate::verified_app_deploy(&self.anchor, request)?;
        self.check_identity(&intent.host_id, &intent.host_epoch)?;
        let now = request.now.ok_or(ExecutorError::TimeDenied)?;
        // Pre-intent checks: site must exist as an app, runtime must match, and
        // blue/green cutover requires a blue/green-provisioned app.
        if self.journal.app_release(&intent.operation_id)?.is_none() {
            let Some(facts) = self.journal.app_facts_by_site(&intent.site_id)? else {
                return Err(ExecutorError::PreconditionChanged);
            };
            if facts.runtime != intent.runtime {
                return Err(ExecutorError::BindingDenied);
            }
            let spec = self.journal.app_fullstack_spec_by_site(&intent.site_id)?;
            if blue_green_cutover && !spec.as_ref().is_some_and(|s| s.blue_green) {
                return Err(ExecutorError::BindingDenied);
            }
        }
        let previous = self
            .journal
            .latest_app_release(&intent.site_id)?
            .map(|r| r.release_id);
        let release = match self.admit(signed_inputs(request)?, |journal| {
            journal.record_app_release(&intent, now)
        })? {
            rustiron_journal::Admitted::Existing(existing) => {
                return Ok(rustiron_journal::Admitted::Existing(existing));
            }
            rustiron_journal::Admitted::New(created) => created,
        };
        let facts = self
            .journal
            .app_facts_by_site(&intent.site_id)?
            .ok_or(ExecutorError::PreconditionChanged)?;
        let spec = self.journal.app_fullstack_spec_by_site(&intent.site_id)?;
        let effective_bg = blue_green_cutover && spec.as_ref().is_some_and(|s| s.blue_green);
        let layout = provision::SiteLayout::derive(&intent.site_id);
        let mut steps = vec![rustiron_journal::AppReleaseStep::Unpack];
        if release.migration_entrypoint.is_some() {
            steps.push(rustiron_journal::AppReleaseStep::Migrate);
        }
        steps.push(rustiron_journal::AppReleaseStep::Activate);
        steps.push(rustiron_journal::AppReleaseStep::Health);
        let mut failed_error = None;
        for step in steps {
            self.journal
                .begin_app_release_step(&intent.operation_id, step)?;
            let outcome = admin_helper::route(
                self.anchor.admin_socket.as_deref(),
                &AdminRequest {
                    operation_id: intent.operation_id.clone(),
                    step: AdminStep::AppDeployStep,
                },
                || {
                    crate::app_site::run_deploy_step(
                        step,
                        &layout,
                        &facts,
                        spec.as_ref(),
                        &release,
                        previous.as_deref(),
                        effective_bg,
                    )
                },
            );
            self.journal
                .finish_app_release_step(&intent.operation_id, step, outcome.is_ok())?;
            if let Err(err) = outcome {
                failed_error = Some(err);
                break;
            }
        }
        // W659 (D-102): post-health zero-downtime blue/green slot flip and/or
        // Caddy generation activation. Any failure reverts the slot in journal
        // and runs `Rollback` before settling.
        if failed_error.is_none()
            && let Some(ref s) = spec
            && (effective_bg || s.ingress == rustiron_contracts::approval::IngressEngine::Caddy)
        {
            let prov_op = self
                .journal
                .provision_for_site(&intent.site_id)?
                .map(|p| p.intent.operation_id)
                .ok_or(ExecutorError::PreconditionChanged)?;
            let old_slot = s.active_slot;
            if effective_bg {
                self.journal
                    .set_app_active_slot(&prov_op, old_slot.opposite())?;
            }
            let cutover_res: Result<(), ExecutorError> = (|| {
                if s.ingress == rustiron_contracts::approval::IngressEngine::Caddy {
                    let owner = self.anchor.owner_uid;
                    let loaded = policy::load(
                        &files::open_trusted_directory(&self.anchor.policy_dir, owner)?,
                        owner,
                    )?;
                    let caddy_policy = loaded
                        .policy
                        .caddy
                        .as_ref()
                        .ok_or(ExecutorError::Unavailable)?;
                    let render_cfg = crate::caddy::render_config_from_policy(caddy_policy)?;
                    let payload = if let Some(socket) = self.anchor.admin_socket.as_deref() {
                        match admin_helper::request(
                            socket,
                            &AdminRequest {
                                operation_id: intent.operation_id.clone(),
                                step: AdminStep::AppCaddyActivate,
                            },
                        )? {
                            admin_helper::Reply::Done(Some(text)) => text,
                            admin_helper::Reply::Done(None) => {
                                return Err(ExecutorError::Unavailable);
                            }
                            admin_helper::Reply::Refused(err) => return Err(err),
                        }
                    } else {
                        let records = FixtureJournal::records_as_process_owner(
                            &self.anchor.journal_dir,
                            &intent.host_id,
                            &intent.host_epoch,
                            &intent.operation_id,
                            Some(&crate::ols::bootstrap_generation()),
                        )?;
                        let sites = crate::caddy::sites_from_records(caddy_policy, &records)?;
                        let generation = crate::caddy::render(&render_cfg, &sites)?;
                        let (gen_id, gen_digest, _) = crate::caddy::activate_live(
                            &generation,
                            &intent.operation_id,
                            &caddy_policy.binary_sha256,
                            &|| Ok(()),
                        )?;
                        if effective_bg {
                            crate::app_site::finish_blue_green_cutover(
                                &layout,
                                &facts,
                                s,
                                &release.release_id,
                                old_slot,
                            )?;
                        }
                        format!(
                            "{} {} {}",
                            gen_id.as_str(),
                            gen_digest.as_str(),
                            sites.len()
                        )
                    };
                    let parts: Vec<&str> = payload.split_whitespace().collect();
                    if parts.len() != 3 {
                        return Err(ExecutorError::Unavailable);
                    }
                    let gen_id = Id::try_from(parts[0].to_owned())
                        .map_err(|_| ExecutorError::Unavailable)?;
                    let config_sha256 = Sha256Digest::try_from(parts[1].to_owned())
                        .map_err(|_| ExecutorError::Unavailable)?;
                    let site_count: u64 =
                        parts[2].parse().map_err(|_| ExecutorError::Unavailable)?;
                    self.journal.record_active_caddy_generation(
                        &rustiron_journal::CaddyGeneration {
                            generation_id: gen_id,
                            operation_id: intent.operation_id.clone(),
                            ingress_mode: render_cfg.mode,
                            config_sha256,
                            site_count,
                            created_at: now,
                            state: rustiron_journal::CaddyGenerationState::Active,
                        },
                    )?;
                } else if effective_bg {
                    crate::app_site::finish_blue_green_cutover(
                        &layout,
                        &facts,
                        s,
                        &release.release_id,
                        old_slot,
                    )?;
                }
                Ok(())
            })();
            if let Err(err) = cutover_res {
                if effective_bg {
                    // W674: an unrecorded slot revert leaves the release open.
                    self.journal.set_app_active_slot(&prov_op, old_slot)?;
                }
                failed_error = Some(err);
            }
        }
        if let Some(err) = failed_error {
            self.journal.begin_app_release_step(
                &intent.operation_id,
                rustiron_journal::AppReleaseStep::Rollback,
            )?;
            let rb = admin_helper::route(
                self.anchor.admin_socket.as_deref(),
                &AdminRequest {
                    operation_id: intent.operation_id.clone(),
                    step: AdminStep::AppDeployStep,
                },
                || {
                    crate::app_site::run_deploy_step(
                        rustiron_journal::AppReleaseStep::Rollback,
                        &layout,
                        &facts,
                        spec.as_ref(),
                        &release,
                        previous.as_deref(),
                        effective_bg,
                    )
                },
            );
            self.journal.finish_app_release_step(
                &intent.operation_id,
                rustiron_journal::AppReleaseStep::Rollback,
                rb.is_ok(),
            )?;
            // W674: when Caddy could not be restored, the units are back but
            // ingress is unknown; the release stays open for reconciliation.
            if rb.is_ok() && err != ExecutorError::RollbackFailed {
                let settled = self.journal.finish_app_release(
                    &intent.operation_id,
                    rustiron_journal::AppReleaseState::RolledBack,
                )?;
                return Ok(rustiron_journal::Admitted::New(settled));
            }
            return Err(err);
        }
        let settled = self.journal.finish_app_release(
            &intent.operation_id,
            rustiron_journal::AppReleaseState::Done,
        )?;
        Ok(rustiron_journal::Admitted::New(settled))
    }

    /// W598 (D-099) & W659 (D-102): admits one signed `app_lifecycle`
    /// (`start`/`stop`/`restart`) and applies it through the admin helper.
    pub fn app_lifecycle(
        &mut self,
        request: &AdmissionRequest<'_>,
    ) -> Result<Admitted<rustiron_journal::AppLifecycle>, ExecutorError> {
        let intent = crate::verified_app_lifecycle(&self.anchor, request)?;
        self.check_identity(&intent.host_id, &intent.host_epoch)?;
        let now = request.now.ok_or(ExecutorError::TimeDenied)?;
        if self.journal.app_lifecycle(&intent.operation_id)?.is_none()
            && self
                .journal
                .app_fullstack_spec_by_site(&intent.site_id)?
                .is_some_and(|s| s.topology == rustiron_contracts::approval::AppTopology::StaticSpa)
        {
            return Err(ExecutorError::BindingDenied);
        }
        let lifecycle = match self.admit(signed_inputs(request)?, |journal| {
            journal.record_app_lifecycle(&intent, now)
        })? {
            rustiron_journal::Admitted::Existing(existing) => {
                return Ok(rustiron_journal::Admitted::Existing(existing));
            }
            rustiron_journal::Admitted::New(created) => created,
        };
        let facts = self
            .journal
            .app_facts_by_site(&intent.site_id)?
            .ok_or(ExecutorError::PreconditionChanged)?;
        let spec = self.journal.app_fullstack_spec_by_site(&intent.site_id)?;
        let layout = provision::SiteLayout::derive(&intent.site_id);
        let outcome = admin_helper::route(
            self.anchor.admin_socket.as_deref(),
            &AdminRequest {
                operation_id: intent.operation_id.clone(),
                step: AdminStep::AppLifecycle,
            },
            || {
                crate::app_site::run_lifecycle_for(
                    &layout.account,
                    facts.worker_entrypoint.is_some(),
                    spec.as_ref(),
                    lifecycle.action,
                )
            },
        );
        let settled = self
            .journal
            .finish_app_lifecycle(&intent.operation_id, outcome.is_ok())?;
        outcome?;
        Ok(rustiron_journal::Admitted::New(settled))
    }

    /// Stored `app_deploy` release status, if recorded.
    pub fn app_release_status(
        &self,
        operation_id: &Id,
    ) -> Result<Option<rustiron_journal::AppRelease>, ExecutorError> {
        Ok(self.journal.app_release(operation_id)?)
    }

    /// Stored `app_lifecycle` status, if recorded.
    pub fn app_lifecycle_status(
        &self,
        operation_id: &Id,
    ) -> Result<Option<rustiron_journal::AppLifecycle>, ExecutorError> {
        Ok(self.journal.app_lifecycle(operation_id)?)
    }

    /// The provision steps of a newly admitted provision or import.
    fn run_provision_steps(
        &mut self,
        operation: &Id,
        intent: &rustiron_journal::ProvisionIntent,
        enrolled: &policy::ProvisioningPolicy,
        quota: crate::quota::QuotaIntent,
        recipe: StepRecipe<'_>,
    ) -> Result<Admitted<Provision>, ExecutorError> {
        let operation = operation.clone();
        let layout = provision::SiteLayout::derive(&intent.site_id);
        let ranges = provision::Ranges {
            uid: (enrolled.uid_min, enrolled.uid_max),
            category: (enrolled.category_min, enrolled.category_max),
        };
        let mut password = None;
        // W335/W341: the signed v2 limits or, for a v1 plan, the enrolled
        // policy limits; journaled with their source in the Directories intent.
        for step in ProvisionStep::ALL {
            // Allocations are chosen and journaled before the effect and
            // excluded from every later provision, even after a removal.
            // W372: also every adopted site's allocation and the highest
            // signed allocation floor, which only move the next value up.
            let retired = |key| -> Result<Vec<u32>, ExecutorError> {
                let mut numbers =
                    provision::recorded_numbers(&self.journal.recorded_resources(step)?, key);
                let (uids, categories) = self.journal.adopted_allocations()?;
                let floor = self.journal.allocation_floor()?;
                if key == "uid=" {
                    numbers.extend(uids);
                    numbers.extend(floor.map(|(uid, _)| uid));
                } else {
                    numbers.extend(categories);
                    numbers.extend(floor.map(|(_, category)| category));
                }
                Ok(numbers)
            };
            let plain = format!("{step:?} {}", layout.account);
            let allocation = match step {
                ProvisionStep::Account => retired("uid=")
                    .and_then(|ids| provision::choose_uid(ranges, &ids))
                    .map(|uid| (format!("{plain} uid={uid}"), uid)),
                ProvisionStep::Labels => retired("level=s0:c")
                    .and_then(|ids| provision::choose_category(ranges, &ids))
                    .map(|category| (format!("{plain} level=s0:c{category}"), category)),
                ProvisionStep::Directories => Ok((format!("{plain} {}", quota.resource()), 0)),
                ProvisionStep::Recipe => Ok((format!("{plain} recipe={}", recipe.name()), 0)),
                // W572: a proxy site journals these steps without an effect.
                _ if matches!(recipe, StepRecipe::Proxy) && crate::proxy_site::skips(step) => {
                    Ok((format!("{plain} not used (proxy site)"), 0))
                }
                // W598 (D-099) & W658 (D-102 C2): an app site skips PHP units
                // always, and skips DB/Credentials only for none/sqlite.
                _ if matches!(recipe, StepRecipe::App(_, _)) && {
                    let db = match recipe {
                        StepRecipe::App(_, spec) => spec
                            .map_or(rustiron_contracts::approval::AppDatabase::Sqlite, |s| {
                                s.database
                            }),
                        _ => rustiron_contracts::approval::AppDatabase::Sqlite,
                    };
                    crate::app_site::skips(step, db)
                } =>
                {
                    Ok((format!("{plain} not used (app site)"), 0))
                }
                _ => Ok((plain.clone(), 0)),
            };
            let (planned, allocated) = match allocation {
                Ok(chosen) => chosen,
                Err(error) => {
                    // Nothing was attempted; record the step failed so the
                    // provision is quarantined, never left running.
                    self.journal.begin_step(&operation, step, &plain)?;
                    self.journal.finish_step(&operation, step, false)?;
                    return Err(error);
                }
            };
            let recorded = self.journal.begin_step(&operation, step, &planned)?;
            self.fault(Fault::AfterProvisionStepBegin)?;
            // W572 (D-095): a proxy site's own steps. The skipped steps
            // change nothing; Recipe and Verify run in the helper.
            if matches!(recipe, StepRecipe::Proxy) {
                if crate::proxy_site::skips(step) {
                    self.journal.finish_step(&operation, step, true)?;
                    continue;
                }
                if matches!(step, ProvisionStep::Recipe | ProvisionStep::Verify) {
                    let outcome = admin_helper::route(
                        self.anchor.admin_socket.as_deref(),
                        &AdminRequest {
                            operation_id: operation.clone(),
                            step: AdminStep::ProvisionStep,
                        },
                        || crate::proxy_site::run_step(step, &layout),
                    );
                    self.journal
                        .finish_step(&operation, step, outcome.is_ok())?;
                    outcome?;
                    continue;
                }
            }
            if let StepRecipe::App(facts, spec) = recipe {
                let app_db = spec.map_or(rustiron_contracts::approval::AppDatabase::Sqlite, |s| {
                    s.database
                });
                if crate::app_site::skips(step, app_db) {
                    self.journal.finish_step(&operation, step, true)?;
                    continue;
                }
                if matches!(
                    step,
                    ProvisionStep::Database
                        | ProvisionStep::Credentials
                        | ProvisionStep::Recipe
                        | ProvisionStep::Verify
                ) {
                    let outcome = admin_helper::route(
                        self.anchor.admin_socket.as_deref(),
                        &AdminRequest {
                            operation_id: operation.clone(),
                            step: AdminStep::ProvisionStep,
                        },
                        || match step {
                            ProvisionStep::Database => {
                                crate::app_site::run_database_step(&layout, app_db)
                                    .map(|secret| password = Some(secret))
                            }
                            ProvisionStep::Credentials => match password.take() {
                                Some(secret) => {
                                    crate::app_site::run_credentials_step(&layout, app_db, &secret)
                                }
                                None => Err(ExecutorError::StepFailed),
                            },
                            _ => crate::app_site::run_provision_step(step, &layout, facts, spec),
                        },
                    );
                    self.journal
                        .finish_step(&operation, step, outcome.is_ok())?;
                    outcome?;
                    continue;
                }
            }
            if let StepRecipe::Clone(facts) = recipe {
                if step == ProvisionStep::Recipe {
                    self.run_clone_steps(&operation, intent, &layout, facts)?;
                    self.journal.finish_step(&operation, step, true)?;
                    continue;
                }
                if step == ProvisionStep::Verify {
                    // W499: a clone is verified as a WordPress import is.
                    let outcome = admin_helper::route(
                        self.anchor.admin_socket.as_deref(),
                        &AdminRequest {
                            operation_id: operation.clone(),
                            step: AdminStep::ProvisionStep,
                        },
                        || crate::import::verify_import(&layout, &intent.hostname, false),
                    );
                    self.journal
                        .finish_step(&operation, step, outcome.is_ok())?;
                    outcome?;
                    continue;
                }
            }
            if let StepRecipe::Import(facts) = recipe {
                if step == ProvisionStep::Recipe {
                    self.run_import_steps(&operation, intent, &layout, facts)?;
                    self.journal.finish_step(&operation, step, true)?;
                    continue;
                }
                if step == ProvisionStep::Verify {
                    // W451: the import's own Verify, routed like every step.
                    let outcome = admin_helper::route(
                        self.anchor.admin_socket.as_deref(),
                        &AdminRequest {
                            operation_id: operation.clone(),
                            step: AdminStep::ProvisionStep,
                        },
                        || {
                            crate::import::verify_import(
                                &layout,
                                &intent.hostname,
                                facts.is_static(),
                            )
                        },
                    );
                    self.journal
                        .finish_step(&operation, step, outcome.is_ok())?;
                    outcome?;
                    continue;
                }
            }
            let site = SiteStep {
                layout: &layout,
                allocated,
                recipe: recipe.site(),
                hostname: &intent.hostname,
                wordpress: &enrolled.wordpress_713_sha256,
                recipes_dir: &self.anchor.recipes_dir,
                quota: quota.plan,
                site_uid: journaled_uid(&recorded),
            };
            let outcome = admin_helper::route(
                self.anchor.admin_socket.as_deref(),
                &AdminRequest {
                    operation_id: operation.clone(),
                    step: AdminStep::ProvisionStep,
                },
                || run_site_step(step, &site, &mut password),
            );
            let recorded = self
                .journal
                .finish_step(&operation, step, outcome.is_ok())?;
            if let Err(error) = outcome {
                debug_assert_eq!(recorded.state, ProvisionState::Quarantined);
                return Err(error);
            }
        }
        self.journal
            .provision_status(&operation)?
            .map(Admitted::New)
            .ok_or(ExecutorError::Unavailable)
    }

    /// The import steps inside an import's open Recipe step. Each intent is
    /// durable before its effect; a failure quarantines the provision.
    fn run_import_steps(
        &mut self,
        operation: &Id,
        intent: &rustiron_journal::ProvisionIntent,
        layout: &provision::SiteLayout,
        facts: &rustiron_journal::ImportFacts,
    ) -> Result<(), ExecutorError> {
        let owner = self.anchor.owner_uid;
        for step in rustiron_journal::ImportStep::ALL {
            self.journal.begin_import_step(operation, step)?;
            let context = crate::import::ImportStepContext {
                layout,
                site_id: &intent.site_id,
                hostname: &intent.hostname,
                facts,
                owner,
            };
            let outcome = admin_helper::route(
                self.anchor.admin_socket.as_deref(),
                &AdminRequest {
                    operation_id: operation.clone(),
                    step: AdminStep::ProvisionStep,
                },
                || crate::import::run_import_step(step, &context),
            );
            self.journal
                .finish_import_step(operation, step, outcome.is_ok())?;
            if let Err(error) = outcome {
                // W457 (D-057 option B): the failed import is quarantined;
                // remove its leftover secrets under its own authority. The
                // step's error is returned whatever the scrub's outcome.
                self.failed_step_scrub(operation)?;
                return Err(error);
            }
        }
        Ok(())
    }

    /// W499 (D-078): the clone steps inside a clone's open Recipe step. Each
    /// intent is durable before its effect; a failure quarantines the
    /// provision and leaves the target unserved.
    fn run_clone_steps(
        &mut self,
        operation: &Id,
        intent: &rustiron_journal::ProvisionIntent,
        layout: &provision::SiteLayout,
        facts: &rustiron_journal::CloneFacts,
    ) -> Result<(), ExecutorError> {
        for step in rustiron_journal::CloneStep::ALL {
            self.journal.begin_clone_step(operation, step)?;
            let context = crate::staging_clone::CloneStepContext {
                anchor: &self.anchor,
                layout,
                hostname: &intent.hostname,
                facts,
            };
            let outcome = admin_helper::route(
                self.anchor.admin_socket.as_deref(),
                &AdminRequest {
                    operation_id: operation.clone(),
                    step: AdminStep::ProvisionStep,
                },
                || crate::staging_clone::run_clone_step(step, &context),
            );
            self.journal
                .finish_clone_step(operation, step, outcome.is_ok())?;
            if let Err(error) = outcome {
                // W501: the failed clone is quarantined; remove the source's
                // data it fetched under its own authority. The step's error
                // is returned whatever the scrub's outcome.
                self.failed_clone_scrub(operation)?;
                return Err(error);
            }
        }
        Ok(())
    }

    /// W501 (D-078): the scrub after a failed clone step, as the target.
    fn failed_clone_scrub(&mut self, operation: &Id) -> Result<(), ExecutorError> {
        self.journal.begin_clone_scrub(operation)?;
        let outcome = admin_helper::route(
            self.anchor.admin_socket.as_deref(),
            &AdminRequest {
                operation_id: operation.clone(),
                step: AdminStep::CloneScrub,
            },
            || {
                let provision = self
                    .journal
                    .provision_status(operation)?
                    .ok_or(ExecutorError::Unavailable)?;
                crate::staging_clone::scrub_site(&provision::SiteLayout::derive(
                    &provision.intent.site_id,
                ))
            },
        );
        self.journal
            .finish_clone_scrub(operation, outcome.is_ok())?;
        Ok(())
    }

    /// W459 (D-057): admits one signed `import_scrub` of an ended import and
    /// runs it: the helper removes `tmp/import` and the archive copy as the
    /// site, then the executor removes the intake archive. The scrub is
    /// `done` only when both succeed; any failure records it `failed`. An
    /// exact repeat returns the stored scrub and runs nothing.
    pub fn scrub(
        &mut self,
        request: &AdmissionRequest<'_>,
    ) -> Result<Admitted<rustiron_journal::ImportScrub>, ExecutorError> {
        let intent = crate::verified_scrub(&self.anchor, request)?;
        self.check_identity(&intent.host_id, &intent.host_epoch)?;
        let now = request.now.ok_or(ExecutorError::TimeDenied)?;
        let scrub = match self.admit(signed_inputs(request)?, |journal| {
            journal.record_scrub(&intent, now)
        })? {
            rustiron_journal::Admitted::Existing(existing) => {
                return Ok(rustiron_journal::Admitted::Existing(existing));
            }
            rustiron_journal::Admitted::New(scrub) => scrub,
        };
        let site = admin_helper::route(
            self.anchor.admin_socket.as_deref(),
            &AdminRequest {
                operation_id: intent.import_operation_id.clone(),
                step: AdminStep::ImportScrub,
            },
            || crate::import::scrub_site(&provision::SiteLayout::derive(&intent.site_id)),
        );
        let outcome = site.and_then(|()| {
            crate::import::remove_intake(
                std::path::Path::new(crate::layout::MIGRATION_INTAKE_DIR),
                self.anchor.owner_uid,
                &intent.site_id,
                &intent.archive_sha256,
            )
        });
        let import = self
            .journal
            .finish_import_scrub(&scrub.operation_id, outcome.is_ok())?;
        outcome?;
        import
            .scrubs
            .into_iter()
            .find(|row| row.operation_id == scrub.operation_id)
            .map(rustiron_journal::Admitted::New)
            .ok_or(ExecutorError::Unavailable)
    }

    /// W462 (D-059): admits one signed `certificate_issue` and asks the
    /// admin helper to run it. A readable result is recorded: `installed`
    /// with the chain's SHA-256 and expiry, or `failed`. A lost or
    /// unreadable reply leaves the row `intent`, an unknown outcome that
    /// blocks other admissions until `fail-certificate` settles it. An exact
    /// repeat returns the stored row and runs nothing.
    pub fn certificate(
        &mut self,
        request: &AdmissionRequest<'_>,
    ) -> Result<Admitted<rustiron_journal::Certificate>, ExecutorError> {
        let intent = crate::verified_certificate(&self.anchor, request)?;
        self.check_identity(&intent.host_id, &intent.host_epoch)?;
        let now = request.now.ok_or(ExecutorError::TimeDenied)?;
        // W480 (W479-F2): a site that cannot take this certificate is a
        // precondition, not a replay. An exact repeat still answers from
        // the journal, which repeats every check in its transaction.
        if self
            .journal
            .certificate_status(&intent.operation_id)?
            .is_none()
        {
            let provision = self.journal.provision_for_site(&intent.site_id)?;
            certificate_precondition(provision.as_ref(), &self.journal.ejected_sites()?, &intent)?;
            if let Some(alias) = &intent.alias_hostname {
                let provision = provision.ok_or(ExecutorError::PreconditionChanged)?;
                if self
                    .journal
                    .import_alias(&provision.intent.operation_id)?
                    .as_ref()
                    != Some(alias)
                {
                    return Err(ExecutorError::PreconditionChanged);
                }
                let generation = crate::certificate::require_pair_mapping(
                    &provision::SiteLayout::derive(&intent.site_id).account,
                    &intent.hostname,
                    alias,
                    false,
                )?;
                if Some(generation) != self.ols_established()? {
                    return Err(ExecutorError::Drift);
                }
            }
        }
        let row = match self.admit(signed_inputs(request)?, |journal| {
            journal.record_certificate(&intent, now)
        })? {
            rustiron_journal::Admitted::Existing(existing) => {
                return Ok(rustiron_journal::Admitted::Existing(existing));
            }
            rustiron_journal::Admitted::New(row) => row,
        };
        let socket = self
            .anchor
            .admin_socket
            .clone()
            .ok_or(ExecutorError::Unavailable)?;
        let reply = admin_helper::request(
            &socket,
            &AdminRequest {
                operation_id: row.intent.operation_id.clone(),
                step: AdminStep::CertificateIssue,
            },
        )?;
        let installed = match reply {
            admin_helper::Reply::Done(Some(payload)) => {
                Some(parse_installed(&payload).ok_or(ExecutorError::Unavailable)?)
            }
            admin_helper::Reply::Done(None) => return Err(ExecutorError::Unavailable),
            admin_helper::Reply::Refused(ExecutorError::Drift)
                if row.intent.alias_hostname.is_some() =>
            {
                return Err(ExecutorError::Drift);
            }
            // W674: the previous certificate could not be restored, so
            // `failed` ("nothing new is served") would be unproven; the row
            // stays `intent` for reconciliation.
            admin_helper::Reply::Refused(ExecutorError::RollbackFailed) => {
                return Err(ExecutorError::RollbackFailed);
            }
            admin_helper::Reply::Refused(error) => {
                self.journal
                    .finish_certificate(&row.intent.operation_id, None)?;
                return Err(error);
            }
        };
        let finished = self.journal.finish_certificate(
            &row.intent.operation_id,
            installed.as_ref().map(|(sha, not_after)| (sha, *not_after)),
        )?;
        Ok(rustiron_journal::Admitted::New(finished))
    }

    /// W464 (D-060): renews every due site under its issuance's standing
    /// grant, one at a time. Each renewal's intent is journaled before the
    /// helper runs it; a readable outcome is recorded, and a lost reply
    /// leaves it `intent` and stops this round. Returns how many renewals
    /// were installed.
    pub fn renew_due(&mut self) -> Result<usize, ExecutorError> {
        let Some(socket) = self.anchor.admin_socket.clone() else {
            return Ok(0);
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| Timestamp::try_from(elapsed.as_secs()).ok())
            .ok_or(ExecutorError::TimeDenied)?;
        let mut installed = 0;
        for target in self.journal.due_renewals(now)? {
            if let Some(alias) = &target.alias_hostname {
                if !load_state_policy(&self.anchor)?
                    .policy
                    .alias_certificate_enabled()
                {
                    continue;
                }
                match crate::certificate::require_pair_mapping(
                    &provision::SiteLayout::derive(&target.site_id).account,
                    &target.hostname,
                    alias,
                    true,
                ) {
                    Ok(generation) if Some(generation.clone()) == self.ols_established()? => {}
                    Ok(_) => return Err(ExecutorError::Drift),
                    Err(ExecutorError::PreconditionChanged) => continue,
                    Err(error) => return Err(error),
                }
            }
            let renewal_id = Id::try_from(format!("rn_{}", crate::ols::stage::random_hex()?))
                .map_err(|_| ExecutorError::Unavailable)?;
            let renewal = self.journal.begin_renewal(&target, &renewal_id, now)?;
            let reply = admin_helper::request(
                &socket,
                &AdminRequest {
                    operation_id: renewal.renewal_id.clone(),
                    step: AdminStep::CertificateRenew,
                },
            )?;
            let outcome = match reply {
                admin_helper::Reply::Done(Some(payload)) => {
                    Some(parse_installed(&payload).ok_or(ExecutorError::Unavailable)?)
                }
                admin_helper::Reply::Done(None) => return Err(ExecutorError::Unavailable),
                admin_helper::Reply::Refused(ExecutorError::Drift)
                    if target.alias_hostname.is_some() =>
                {
                    return Err(ExecutorError::Drift);
                }
                admin_helper::Reply::Refused(_) => None,
            };
            self.journal.finish_renewal(
                &renewal.renewal_id,
                outcome.as_ref().map(|(sha, not_after)| (sha, *not_after)),
            )?;
            eprintln!(
                "{}",
                serde_json::json!({
                    "scope": "certificate_renew",
                    "site": target.site_id.as_str(),
                    "renewal": renewal.renewal_id.as_str(),
                    "state": if outcome.is_some() { "installed" } else { "failed" },
                })
            );
            installed += usize::from(outcome.is_some());
        }
        Ok(installed)
    }

    /// W464: the stored renewal, for status.
    pub fn renewal_status(
        &self,
        renewal_id: &Id,
    ) -> Result<Option<rustiron_journal::Renewal>, ExecutorError> {
        Ok(self.journal.renewal_status(renewal_id)?)
    }

    /// W462: the stored issuance, for status and replies.
    pub fn certificate_status(
        &self,
        operation_id: &Id,
    ) -> Result<Option<rustiron_journal::Certificate>, ExecutorError> {
        Ok(self.journal.certificate_status(operation_id)?)
    }

    /// W462: the operator's settlement of an issuance left `intent` by a
    /// lost reply, after checking the host. It records `failed`; nothing is
    /// served from it, and a new issuance installs a fresh chain.
    pub fn fail_certificate(
        &mut self,
        operation_id: &Id,
    ) -> Result<rustiron_journal::Certificate, ExecutorError> {
        Ok(self.journal.finish_certificate(operation_id, None)?)
    }

    /// W459: the stored signed scrub, for status and replies.
    pub fn scrub_status(
        &self,
        operation_id: &Id,
    ) -> Result<Option<rustiron_journal::ImportScrub>, ExecutorError> {
        Ok(self
            .journal
            .signed_scrub_status(operation_id)?
            .map(|(scrub, _)| scrub))
    }

    /// W457: the automatic scrub of a failed import, intent first. A failed
    /// scrub stays recorded as failed; a signed `import_scrub` removes the
    /// leftovers later.
    fn failed_step_scrub(&mut self, operation: &Id) -> Result<(), ExecutorError> {
        self.journal.begin_failed_step_scrub(operation)?;
        let outcome = admin_helper::route(
            self.anchor.admin_socket.as_deref(),
            &AdminRequest {
                operation_id: operation.clone(),
                step: AdminStep::ImportScrub,
            },
            || {
                let provision = self
                    .journal
                    .provision_status(operation)?
                    .ok_or(ExecutorError::Unavailable)?;
                crate::import::scrub_site(&provision::SiteLayout::derive(&provision.intent.site_id))
            },
        );
        self.journal
            .finish_import_scrub(operation, outcome.is_ok())?;
        Ok(())
    }

    /// Signed lab OLS `config_activate`: render the listener generation for
    /// the enrolled adopted sites, the named succeeded provisions and every
    /// ejected site, record intent, switch, test, reload and require every
    /// site's identity probe.
    pub fn activate_ols(
        &mut self,
        request: &AdmissionRequest<'_>,
    ) -> Result<Admitted<Operation>, ExecutorError> {
        let (plan, grant, enrolled) = verified_ols(&self.anchor, request)?;
        self.check_enrolled_identity(&enrolled)?;
        let digests = (plan.digest(), grant_digest(grant.as_bytes()));
        if let Some(existing) = self.replay_status(request, &digests)? {
            return Ok(Admitted::Existing(existing));
        }
        let ejected = self.journal.ejected_sites()?;
        if plan.site_ids().iter().any(|site| ejected.contains(site)) {
            return Err(ExecutorError::PreconditionChanged);
        }
        let mut sites = self.served(plan.site_ids(), false)?;
        sites.extend(self.served(&ejected, true)?);
        let (expected, expected_digest) = plan.expected();
        // W368: a v2 plan opts one served site in to the page cache. The
        // site must already be served by the predecessor generation (so a
        // bootstrap never opts in) and must not be opted in. W370: a v3 plan
        // opts one opted-in site out; a site that the lab policy lists for
        // storage cannot opt out. A later v2 plan re-enables the site.
        // W395: the opt-out names the recipe of the site's opt-in.
        let page_cache = match (plan.page_cache(), plan.page_cache_opt_out()) {
            (Some(opt_in), None) => Some(PageCacheChange::OptIn(
                opt_in.site_id().clone(),
                opt_in.recipe(),
            )),
            (None, Some(opt_out)) => Some(PageCacheChange::OptOut(
                opt_out.site_id().clone(),
                opt_out.recipe(),
            )),
            _ => None,
        };
        if let Some(change) = &page_cache {
            let site = change.site();
            self.refuse_proxy_site(site)?;
            let account = provision::SiteLayout::derive(site).account;
            let served = ols::open_include()
                .and_then(|include| ols::managed_accounts(&include, expected))?;
            let opted_in = self.journal.page_cache_sites()?.contains(site);
            let listed = enrolled
                .ols
                .as_ref()
                .is_some_and(|ols| ols.lscache.contains(site));
            let admitted = match change {
                PageCacheChange::OptIn(..) => !opted_in,
                PageCacheChange::OptOut(_, recipe) => {
                    opted_in
                        && !listed
                        && self.journal.page_cache_site_recipe(site)?
                            == Some(page_cache::recipe_name(*recipe))
                }
            };
            if !served.contains(&account) || !admitted {
                return Err(ExecutorError::PreconditionChanged);
            }
        }
        let base = IntentBase {
            grant_id: grant.grant_id().clone(),
            nonce: grant.nonce().clone(),
            digests,
            predecessor: (expected.clone(), expected_digest.clone()),
            expires_at: grant.expires_at(),
            compensation_valid_until: grant.compensation_valid_until(),
        };
        self.apply_generation(
            request,
            &enrolled,
            base,
            sites,
            Change::Activate(page_cache.as_ref()),
        )
    }

    /// Signed `site_eject`: render a standalone vhost outside the include
    /// and serve it through the new generation. On success the journal
    /// records the site as ejected, and activations can no longer name it.
    pub fn eject_site(
        &mut self,
        request: &AdmissionRequest<'_>,
    ) -> Result<Admitted<Operation>, ExecutorError> {
        let (plan, grant, enrolled) = verified_eject(&self.anchor, request)?;
        self.check_enrolled_identity(&enrolled)?;
        let digests = (plan.digest(), grant_digest(grant.as_bytes()));
        if let Some(existing) = self.replay_status(request, &digests)? {
            return Ok(Admitted::Existing(existing));
        }
        let site = plan.site_id().clone();
        let mut ejected = self.journal.ejected_sites()?;
        let (expected, expected_digest) = plan.expected();
        let include = ols::open_include()?;
        let account = provision::SiteLayout::derive(&site).account;
        let provision = self
            .journal
            .provision_for_site(&site)?
            .filter(|provision| provision.state.is_owned())
            .ok_or(ExecutorError::PreconditionChanged)?;
        self.refuse_proxy_site(&site)?;
        let reserved = self.journal.import_alias(&provision.intent.operation_id)?;
        let static_hostname = match (plan.names(), plan.static_hostname(), reserved.as_ref()) {
            // W511-F2 (P08): a static import has a standalone vhost only as
            // the certified alias pair (D-077) or the signed single-name
            // static handover (D-097). Its schema 1 eject would run the
            // WordPress check after the switch and fail, so it is refused
            // before intent.
            (None, None, None)
                if self
                    .journal
                    .import_status(&provision.intent.operation_id)?
                    .is_some_and(|import| import.facts.is_static()) =>
            {
                return Err(ExecutorError::PreconditionChanged);
            }
            (None, None, None) => None,
            (Some((primary, alias)), None, Some(reserved))
                if primary == &provision.intent.hostname && alias == reserved =>
            {
                if !enrolled.alias_certificate_enabled() || self.anchor.admin_socket.is_none() {
                    return Err(ExecutorError::Unavailable);
                }
                if self.journal.installed_certificate_alias(&site)?.as_ref() != Some(alias)
                    || ejected.contains(&site)
                {
                    return Err(ExecutorError::PreconditionChanged);
                }
                for secure in [false, true] {
                    let (id, digest) =
                        crate::certificate::require_pair_mapping(&account, primary, alias, secure)?;
                    if &id != expected || &digest != expected_digest {
                        return Err(ExecutorError::PreconditionChanged);
                    }
                }
                None
            }
            (None, Some(hostname), None) if hostname == &provision.intent.hostname => {
                if provision.state != rustiron_journal::ProvisionState::Succeeded
                    || !self
                        .journal
                        .import_status(&provision.intent.operation_id)?
                        .is_some_and(|import| {
                            import.facts.is_static()
                                && import.facts.source_hostname.is_none()
                                && import.facts.alias_hostname.is_none()
                                && import.is_complete()
                        })
                    || self.journal.installed_certificate_alias(&site)?.is_some()
                    || ejected.contains(&site)
                {
                    return Err(ExecutorError::PreconditionChanged);
                }
                let has_tls = self.journal.installed_certificate(&site)?.is_some();
                if !enrolled.static_eject_enabled(has_tls) || self.anchor.admin_socket.is_none() {
                    return Err(ExecutorError::Unavailable);
                }
                if enrolled.ols.as_ref().is_some_and(|ols| {
                    ols.adopted
                        .iter()
                        .any(|adopted| &adopted.hostname == hostname)
                }) {
                    return Err(ExecutorError::PreconditionChanged);
                }
                let (id, digest) =
                    crate::certificate::require_single_static_mapping(&account, hostname, has_tls)?;
                if &id != expected || &digest != expected_digest {
                    return Err(ExecutorError::PreconditionChanged);
                }
                Some(hostname)
            }
            _ => return Err(ExecutorError::PreconditionChanged),
        };
        let managed: Vec<rustiron_contracts::approval::SiteId> =
            ols::managed_accounts(&include, expected)?
                .iter()
                .filter_map(|name| name.strip_prefix("rs_"))
                .filter_map(|id| rustiron_contracts::approval::SiteId::try_from(id.to_owned()).ok())
                .collect();
        if ejected.contains(&site) || !managed.contains(&site) {
            return Err(ExecutorError::PreconditionChanged);
        }
        if ols::has_eject_marker(&account)? {
            return Err(ExecutorError::Collision);
        }
        let remaining: Vec<_> = managed.into_iter().filter(|other| other != &site).collect();
        ejected.push(site.clone());
        let mut sites = self.served(&remaining, false)?;
        sites.extend(self.served(&ejected, true)?);
        if static_hostname.is_some()
            && let Some(target) = sites.iter_mut().find(|served| served.account == account)
        {
            target.static_ejected = true;
        }
        let base = IntentBase {
            grant_id: grant.grant_id().clone(),
            nonce: grant.nonce().clone(),
            digests,
            predecessor: (expected.clone(), expected_digest.clone()),
            expires_at: grant.expires_at(),
            compensation_valid_until: grant.compensation_valid_until(),
        };
        self.apply_generation(
            request,
            &enrolled,
            base,
            sites,
            Change::Eject {
                site: &site,
                account: &account,
                static_hostname,
            },
        )
    }

    /// Signed lab `backup_capture`: durable intent, then the contained
    /// per-site dump, snapshot (tagged with the operation) and repository
    /// check, then the recorded outcome. Ejected sites are no longer managed
    /// and are refused. Nothing on the site or in the store is deleted.
    pub fn backup_capture(
        &mut self,
        request: &AdmissionRequest<'_>,
    ) -> Result<Admitted<Capture>, ExecutorError> {
        let (plan, grant, enrolled) = verified_capture(&self.anchor, request)?;
        self.check_enrolled_identity(&enrolled)?;
        let backup = enrolled.backup.clone().ok_or(ExecutorError::Unavailable)?;
        let site = plan.site_id().clone();
        let intent = CaptureIntent {
            operation_id: request.operation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            grant_id: grant.grant_id().clone(),
            nonce: grant.nonce().clone(),
            plan_digest: plan.digest(),
            grant_digest: grant_digest(grant.as_bytes()),
            host_id: enrolled.host_id.clone(),
            host_epoch: enrolled.host_epoch,
            site_id: site.clone(),
            expires_at: grant.expires_at(),
        };
        let now = request.now.ok_or(ExecutorError::TimeDenied)?;
        if self.journal.ejected_sites()?.contains(&site) {
            if let Some(existing) = self.journal.capture_status(&intent.operation_id)?
                && existing.intent == intent
            {
                return Ok(Admitted::Existing(existing));
            }
            return Err(ExecutorError::PreconditionChanged);
        }
        let layout = provision::SiteLayout::derive(&site);
        if self.journal.capture_status(&intent.operation_id)?.is_none() {
            // Like a restore probe: only a site this journal provisioned
            // successfully is captured (W187), whatever credentials exist.
            self.journal
                .provision_for_site(&site)?
                .filter(|provision| provision.state.is_owned())
                .ok_or(ExecutorError::PreconditionChanged)?;
            self.refuse_proxy_site(&site)?;
            if !capture::credentials_enrolled(&layout) {
                return Err(ExecutorError::Unavailable);
            }
        }
        let method = match plan.target().1 {
            CaptureRecipe::SiteFilesDbV1 => CaptureMethod::SiteFilesDbV1,
            CaptureRecipe::SiteFilesDbFrozenV1 => CaptureMethod::SiteFilesDbFrozenV1,
        };
        let backup_digest = backup.digest()?;
        let Admitted::New(_) = self.admit(signed_inputs(request)?, |journal| {
            journal.record_capture(&intent, now, method, backup.retention_days, &backup_digest)
        })?
        else {
            let existing = self
                .journal
                .capture_status(&intent.operation_id)?
                .ok_or(ExecutorError::Unavailable)?;
            return Ok(Admitted::Existing(existing));
        };
        let is_app = self
            .journal
            .app_facts_by_site(&site)
            .ok()
            .flatten()
            .is_some();
        let outcome = match self.anchor.admin_socket.as_deref() {
            // A lost or unreadable reply is uncertain: the helper may have
            // written a snapshot, so the capture stays `running`.
            Some(socket) => match admin_helper::request(
                socket,
                &AdminRequest {
                    operation_id: intent.operation_id.clone(),
                    step: AdminStep::CaptureRun,
                },
            ) {
                Ok(admin_helper::Reply::Done(Some(payload))) => {
                    admin_helper::decode_capture_for_kind(
                        &payload,
                        &layout.root.to_string_lossy(),
                        method == CaptureMethod::SiteFilesDbFrozenV1,
                        is_app,
                    )
                }
                Ok(admin_helper::Reply::Done(None)) => capture::CaptureOutcome::Uncertain {
                    error: ExecutorError::Unavailable,
                    snapshot: None,
                },
                // Refused before anything ran: a known failure.
                Ok(admin_helper::Reply::Refused(error)) => {
                    capture::CaptureOutcome::NotStarted(error)
                }
                Err(error) => capture::CaptureOutcome::Uncertain {
                    error,
                    snapshot: None,
                },
            },
            None => {
                let destination = capture::Destination {
                    repository_base: &backup.repository_base,
                    store_address: &backup.store_address.to_string(),
                };
                capture::capture_site(
                    &layout,
                    &destination,
                    intent.operation_id.as_str(),
                    method == CaptureMethod::SiteFilesDbFrozenV1,
                )
            }
        };
        let finished = system_now().unwrap_or(now);
        let finished = if finished.get() >= now.get() {
            finished
        } else {
            now
        };
        self.record_capture_outcome(&intent.operation_id, outcome, finished, "backup_capture")
    }

    /// Journals a capture outcome (lab W033/W203, product W356): succeeded
    /// with the snapshot, its counts, label and stored manifest; failed when
    /// nothing was started; otherwise left `running` for recovery.
    pub(crate) fn record_capture_outcome(
        &mut self,
        operation_id: &Id,
        outcome: capture::CaptureOutcome,
        finished: rustiron_contracts::Timestamp,
        scope: &str,
    ) -> Result<Admitted<Capture>, ExecutorError> {
        match outcome {
            capture::CaptureOutcome::Succeeded(snapshot) => {
                // W203: the file is stored before the row; any failure only
                // leaves the manifest unrecorded.
                let directory = self.anchor.journal_dir.with_file_name("manifests");
                let manifest = snapshot.manifest.as_ref().and_then(|built| {
                    match crate::manifest::store(&directory, self.anchor.owner_uid, built) {
                        Ok(()) => Some(crate::manifest::record(built)),
                        Err(error) => {
                            eprintln!(
                                "{}",
                                serde_json::json!({"scope": scope,
                                    "operation_id": operation_id.as_str(),
                                    "outcome": "manifest_not_recorded",
                                    "error": error.code()})
                            );
                            None
                        }
                    }
                });
                Ok(Admitted::New(self.journal.finish_capture_succeeded(
                    operation_id,
                    finished,
                    rustiron_journal::CaptureSuccess {
                        snapshot_id: &snapshot.id,
                        extent: snapshot.extent(),
                        manifest: manifest.as_ref(),
                        consistency: Some(&snapshot.consistency),
                        retention: snapshot.retention.as_ref(),
                    },
                )?))
            }
            // W391 (v18): the failure keeps its stable refusal code.
            capture::CaptureOutcome::NotStarted(error) => {
                self.journal
                    .refuse_capture(operation_id, finished, error.code())?;
                Err(error)
            }
            // A snapshot may exist: never record failed. The capture stays
            // `running` (reply `intent` with the error) and blocks new
            // captures until `capture-reconcile` finds it by its tag.
            capture::CaptureOutcome::Uncertain { error, snapshot } => {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "scope": scope,
                        "operation_id": operation_id.as_str(),
                        "outcome": "uncertain_reconcile_required",
                        "error": error.code(),
                        "snapshot_seen": snapshot,
                    })
                );
                Err(error)
            }
        }
    }

    /// Admin recovery for a capture left `running` by a crash or an
    /// uncertain outcome: look up the snapshot tagged with its operation id.
    /// An empty lookup records failure once the site's units are idle.
    /// The lab can recover one verified snapshot. The product path leaves
    /// tagged snapshots unresolved until it has evidence of a complete write.
    pub fn reconcile_capture(&mut self, operation_id: &Id) -> Result<Capture, ExecutorError> {
        let existing = self
            .journal
            .capture_status(operation_id)?
            .ok_or(ExecutorError::NotAdmitted)?;
        if existing.state != CaptureState::Running {
            return Ok(existing);
        }
        if cfg!(rustiron_profile = "product") {
            return self
                .reconcile_product_capture(existing, crate::product_capture::Recovery::Reconcile);
        }
        let backup = crate::policy::load_bound_backup(
            &self.anchor,
            &existing.intent.host_id,
            &existing.intent.host_epoch,
            existing.backup_policy_digest.as_ref(),
        )?;
        let destination = capture::Destination {
            repository_base: &backup.repository_base,
            store_address: &backup.store_address.to_string(),
        };
        let layout = provision::SiteLayout::derive(&existing.intent.site_id);
        let found = capture::find_snapshot(&layout, &destination, operation_id.as_str())?;
        let now = system_now().ok_or(ExecutorError::TimeDenied)?;
        Ok(self.journal.reconcile_finish_capture(
            operation_id,
            found.as_deref(),
            if now.get() >= existing.started_at.get() {
                now
            } else {
                existing.started_at
            },
        )?)
    }

    /// W366 admin settlement of a product capture left `running` whose
    /// tagged snapshot cannot be claimed (a lost helper reply, a partial
    /// write, or a check that failed after the write). It runs the same
    /// fresh checks as [`Self::reconcile_capture`]: the bound projection,
    /// idle site units, the store namespace and credentials, the enrolled
    /// repository ID, and exactly one snapshot with the operation tag. Then
    /// it records `failed` and keeps that snapshot only as unclaimed
    /// evidence. No tag records plain `failed`; any failed check records
    /// nothing. It never records `succeeded`. A capture that is not
    /// `running` returns its stored status unchanged, with no store use.
    /// Lab builds refuse it: their reconcile already records a found tag.
    pub fn settle_capture_unclaimed(
        &mut self,
        operation_id: &Id,
    ) -> Result<Capture, ExecutorError> {
        if !cfg!(rustiron_profile = "product") {
            return Err(ExecutorError::InvalidRequest);
        }
        let existing = self
            .journal
            .capture_status(operation_id)?
            .ok_or(ExecutorError::NotAdmitted)?;
        if existing.state != CaptureState::Running {
            return Ok(existing);
        }
        self.reconcile_product_capture(existing, crate::product_capture::Recovery::SettleUnclaimed)
    }

    /// Signed lab `restore_probe`: the throwaway probe account is chosen and
    /// journaled with the intent before any sandbox resource exists; then
    /// the contained restore, application check and cleanup run, and the
    /// seven-field receipt is recorded. The source site is never written.
    pub fn restore_probe(
        &mut self,
        request: &AdmissionRequest<'_>,
    ) -> Result<Admitted<Probe>, ExecutorError> {
        let (plan, grant, enrolled) = verified_probe(&self.anchor, request)?;
        self.check_enrolled_identity(&enrolled)?;
        let backup = enrolled.backup.clone().ok_or(ExecutorError::Unavailable)?;
        let site = plan.site_id().clone();
        let now = request.now.ok_or(ExecutorError::TimeDenied)?;
        let digests = (plan.digest(), grant_digest(grant.as_bytes()));
        if let Some(existing) = self.journal.probe_status(&request.operation_id)? {
            return if existing.intent.idempotency_key == request.idempotency_key
                && existing.intent.plan_digest == digests.0
                && existing.intent.grant_digest == digests.1
            {
                Ok(Admitted::Existing(existing))
            } else {
                Err(ExecutorError::ReplayDenied)
            };
        }
        let provision = self
            .journal
            .provision_for_site(&site)?
            .filter(|provision| provision.state.is_owned())
            .ok_or(ExecutorError::PreconditionChanged)?;
        let layout = provision::SiteLayout::derive(&site);
        if self.journal.ejected_sites()?.contains(&site) {
            return Err(ExecutorError::PreconditionChanged);
        }
        self.refuse_proxy_site(&site)?;
        if !restore::fetch_enrolled(&layout.account) {
            return Err(ExecutorError::Unavailable);
        }
        let mut random = [0_u8; 3];
        rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty())
            .map_err(|_| ExecutorError::Unavailable)?;
        let probe_account: String = random.iter().fold("rp_".to_owned(), |mut name, byte| {
            name.push_str(&format!("{byte:02x}"));
            name
        });
        let intent = ProbeIntent {
            operation_id: request.operation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            grant_id: grant.grant_id().clone(),
            nonce: grant.nonce().clone(),
            plan_digest: digests.0,
            grant_digest: digests.1,
            host_id: enrolled.host_id.clone(),
            host_epoch: enrolled.host_epoch,
            site_id: site,
            snapshot_id: plan.snapshot_id().clone(),
            probe_account,
            expires_at: grant.expires_at(),
        };
        let backup_digest = backup.digest()?;
        let Admitted::New(_) = self.admit(signed_inputs(request)?, |journal| {
            journal.record_probe(&intent, now, &backup_digest)
        })?
        else {
            return Err(ExecutorError::ReplayDenied);
        };
        let repository = format!("{}/{}", backup.repository_base, layout.account);
        let store = backup.store_address.to_string();
        let target = restore::ProbeTarget {
            account: &layout.account,
            hostname: provision.intent.hostname.as_str(),
            snapshot: intent.snapshot_id.as_str(),
            probe: &intent.probe_account,
        };
        let lab = restore::LabStore {
            repository: &repository,
            store_address: &store,
        };
        let (receipt, state) = match self.anchor.admin_socket.as_deref() {
            // An unknown outcome leaves the probe `running` for the admin
            // cleanup (`cleanup_probe`); it is never recorded as failed.
            Some(socket) => admin_helper::probe_outcome(
                admin_helper::request(
                    socket,
                    &AdminRequest {
                        operation_id: intent.operation_id.clone(),
                        step: AdminStep::ProbeRun,
                    },
                )?,
                &intent.probe_account,
            )?,
            None => restore::run_probe(&target, &lab, now.get()),
        };
        let finished = system_now().filter(|t| t.get() >= now.get()).unwrap_or(now);
        Ok(Admitted::New(self.journal.finish_probe(
            &intent.operation_id,
            state,
            &receipt.to_string(),
            finished,
        )?))
    }

    /// Admin cleanup for a probe left `running` (crash) or
    /// `cleanup_incomplete`: remove exactly its journaled sandbox resources;
    /// with nothing left it is recorded `failed` (it never claims a pass).
    pub fn cleanup_probe(&mut self, operation_id: &Id) -> Result<Probe, ExecutorError> {
        let existing = self
            .journal
            .probe_status(operation_id)?
            .ok_or(ExecutorError::NotAdmitted)?;
        if !matches!(
            existing.state,
            ProbeState::Running | ProbeState::CleanupIncomplete
        ) {
            return Ok(existing);
        }
        let layout = provision::SiteLayout::derive(&existing.intent.site_id);
        let target = restore::ProbeTarget {
            account: &layout.account,
            hostname: "",
            snapshot: existing.intent.snapshot_id.as_str(),
            probe: &existing.intent.probe_account,
        };
        let cleanup = restore::cleanup(&target);
        let now = system_now().ok_or(ExecutorError::TimeDenied)?;
        let now = if now.get() >= existing.started_at.get() {
            now
        } else {
            existing.started_at
        };
        finish_probe_cleanup(&mut self.journal, &existing, &cleanup, now)
    }

    /// Recorded probe status only.
    pub fn probe_status(&self, operation_id: &Id) -> Result<Option<Probe>, ExecutorError> {
        Ok(self.journal.probe_status(operation_id)?)
    }

    /// Recorded capture status only.
    pub fn capture_status(&self, operation_id: &Id) -> Result<Option<Capture>, ExecutorError> {
        Ok(self.journal.capture_status(operation_id)?)
    }

    /// An exact repeat (same operation, retry key and signed digests) is
    /// answered from the journal before anything live is computed, because
    /// the live generation may have moved on since it succeeded.
    fn replay_status(
        &self,
        request: &AdmissionRequest<'_>,
        (plan_digest, grant_digest): &(Sha256Digest, Sha256Digest),
    ) -> Result<Option<Operation>, ExecutorError> {
        match self.journal.status(&request.operation_id)? {
            Some(existing)
                if existing.intent.idempotency_key == request.idempotency_key
                    && &existing.intent.plan_digest == plan_digest
                    && &existing.intent.grant_digest == grant_digest =>
            {
                Ok(Some(existing))
            }
            Some(_) => Err(ExecutorError::ReplayDenied),
            None => Ok(None),
        }
    }

    /// W574 (D-095): a proxy site has no PHP, database, or WordPress, so
    /// the verbs that need them (capture, restore probe, update, eject,
    /// page cache) refuse it before intent.
    pub(crate) fn refuse_proxy_site(
        &self,
        site: &rustiron_contracts::approval::SiteId,
    ) -> Result<(), ExecutorError> {
        match self.journal.provision_for_site(site)? {
            Some(provision)
                if self
                    .journal
                    .proxy_facts(&provision.intent.operation_id)?
                    .is_some()
                    && self
                        .journal
                        .app_facts(&provision.intent.operation_id)?
                        .is_none() =>
            {
                Err(ExecutorError::PreconditionChanged)
            }
            _ => Ok(()),
        }
    }

    /// Served-site entries for owned provisions (succeeded, or adopted by a
    /// re-adoption, W372), from the journal only.
    fn served(
        &self,
        site_ids: &[rustiron_contracts::approval::SiteId],
        ejected: bool,
    ) -> Result<Vec<ols::ServedSite>, ExecutorError> {
        let static_ejected = if ejected {
            self.journal.static_ejected_sites()?
        } else {
            Vec::new()
        };
        site_ids
            .iter()
            .map(|site| {
                let provision = self
                    .journal
                    .provision_for_site(site)?
                    .filter(|provision| provision.state.is_owned())
                    .ok_or(ExecutorError::PreconditionChanged)?;
                // W462: the site's latest installed certificate. D-064
                // (W471-F1): an ejected site keeps it, so its standalone vhost
                // and the TLS listener keep serving HTTPS.
                let tls = self
                    .journal
                    .installed_certificate(site)?
                    .map(|(sha, _)| sha);
                let alias_hostname = self.journal.import_alias(&provision.intent.operation_id)?;
                let tls_alias = self.journal.installed_certificate_alias(site)?;
                if tls_alias.is_some() && tls_alias != alias_hostname {
                    return Err(ExecutorError::PreconditionChanged);
                }
                // W574 (D-095): a proxy site's journaled routes.
                let proxy = self.journal.proxy_facts(&provision.intent.operation_id)?;
                Ok(ols::ServedSite {
                    account: provision::SiteLayout::derive(site).account,
                    alias_hostname,
                    hostname: provision.intent.hostname,
                    ejected,
                    static_ejected: ejected && static_ejected.contains(site),
                    lscache: false,
                    tls,
                    tls_alias,
                    acme: false,
                    proxy,
                })
            })
            .collect()
    }

    /// The shared activation path: render (sites in account order), bind the
    /// intent to the plan's expected predecessor, re-observe live state and
    /// drift, record intent (an ejection also binds its site), write an
    /// ejected copy, stage, switch, test, reload, probe every site, and on
    /// any unverified outcome run the single signed restore.
    fn apply_generation(
        &mut self,
        request: &AdmissionRequest<'_>,
        enrolled: &crate::policy::Policy,
        base: IntentBase,
        mut sites: Vec<ols::ServedSite>,
        change: Change<'_>,
    ) -> Result<Admitted<Operation>, ExecutorError> {
        let ols_policy = enrolled.ols.clone().ok_or(ExecutorError::Unavailable)?;
        for site in &sites {
            if site.tls_alias.is_some() && !enrolled.alias_certificate_enabled() {
                return Err(ExecutorError::Unavailable);
            }
            if let Some(alias) = &site.alias_hostname {
                if !ols_policy.http_is_loopback()
                    || !enrolled
                        .migration
                        .as_ref()
                        .is_some_and(|migration| migration.static_alias_http)
                {
                    return Err(ExecutorError::Unavailable);
                }
                if ols_policy
                    .adopted
                    .iter()
                    .any(|adopted| &adopted.hostname == alias || adopted.hostname == site.hostname)
                {
                    return Err(ExecutorError::PreconditionChanged);
                }
            }
        }
        let (eject, page_cache) = match change {
            Change::Activate(page_cache) => (None, page_cache),
            Change::Eject {
                site,
                account,
                static_hostname,
            } => (Some((site, account, static_hostname)), None),
        };
        sites.sort_by(|a, b| a.account.cmp(&b.account));
        // W368: cache storage for the policy list (lab), every opted-in
        // site, and this plan's opt-in site. W370: never for this plan's
        // opt-out site; every other vhost renders the cache module off.
        let mut cache_sites = ols_policy.lscache.clone();
        cache_sites.extend(self.journal.page_cache_sites()?);
        match page_cache {
            Some(PageCacheChange::OptIn(site, _)) => cache_sites.push(site.clone()),
            Some(PageCacheChange::OptOut(site, _)) => cache_sites.retain(|other| other != site),
            None => {}
        }
        let cached: Vec<String> = cache_sites
            .iter()
            .map(|site| provision::SiteLayout::derive(site).account)
            .collect();
        for site in &mut sites {
            site.lscache = cached.contains(&site.account);
            // W461 (D-059): until slice 3 journals issuance, an existing
            // webroot decides whether the vhost serves the challenge.
            site.acme = !site.ejected && ols::acme_webroot_present(&site.account);
        }
        let include = ols::open_include()?;
        let (current, current_digest) = base.predecessor.clone();
        let generation = ols::render_with_tls(
            &ols_policy.listener,
            &ols_policy.address,
            ols_policy.tls_address.as_deref(),
            &ols_policy.adopted,
            &sites,
        );
        let target_digest = ols::digest(&generation);
        let target = ols::generation_id(&target_digest);
        if target == current {
            return Err(ExecutorError::GenerationCurrent);
        }
        let intent = Intent {
            operation_id: request.operation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            grant_id: base.grant_id,
            nonce: base.nonce,
            plan_digest: base.digests.0,
            grant_digest: base.digests.1,
            host_id: enrolled.host_id.clone(),
            host_epoch: enrolled.host_epoch.clone(),
            resource_id: ols_resource()?,
            predecessor_generation: current.clone(),
            predecessor_digest: current_digest.clone(),
            target_generation: target.clone(),
            target_digest: target_digest.clone(),
            expires_at: base.expires_at,
            compensation_valid_until: base.compensation_valid_until,
        };
        if let Some(existing) = self.journal.existing(&intent)? {
            return Ok(Admitted::Existing(existing));
        }
        // W355: no `current` is the bootstrap state only for a plan that
        // names the bootstrap predecessor; it then starts instead of reloads.
        let live = ols::observe_current(&include)?;
        let mode = ols::activation_mode(live.as_ref(), &(current.clone(), current_digest.clone()))?;
        let socket = self.anchor.admin_socket.clone();
        // In-process (D-016 lab mode) drift is refused before any journal
        // row. Through the helper (W200) the request needs a journaled
        // operation, so the intent is recorded first and a drifted
        // activation ends `untouched`, an audit record with no effect.
        // W359: the generation checks, which need no helper, refuse before
        // intent in both modes, so a refusal records nothing. W360: they
        // judge the `current` that `activation_mode` matched to the plan
        // predecessor (one read), so the predecessor the intent records is
        // the one checked; a second read could see another generation.
        let predecessor = (current.clone(), current_digest);
        if socket.is_some() && mode == ols::ActivationMode::Running {
            let established = self.ols_established()?;
            if let Some(checks) = ols::generation_refusal(&predecessor, established.as_ref()) {
                eprintln!(
                    "{{\"scope\":\"ols_activate\",\"before_intent\":true,\"content_addressed\":{},\"explained\":\"{:?}\"}}",
                    checks.0, checks.1
                );
                return Err(ExecutorError::Drift);
            }
        }
        // W360: through the helper, a bootstrap whose history does not leave
        // the host at its start is refused before intent too; the helper
        // still decides every bootstrap fact after intent. An unresolved
        // operation is left to the admission, which refuses it as busy.
        if socket.is_some() && mode == ols::ActivationMode::Bootstrap {
            let history = self.ols_history(None)?;
            if history != rustiron_journal::ResourceHistory::Unresolved
                && !ols::bootstrap_history_admits(&history)
            {
                let established = match &history {
                    rustiron_journal::ResourceHistory::Established(id, _) => id.as_str(),
                    _ => "",
                };
                eprintln!(
                    "{{\"scope\":\"ols_bootstrap\",\"before_intent\":true,\"established\":\"{established}\"}}"
                );
                return Err(ExecutorError::Drift);
            }
        }
        if socket.is_none() {
            match mode {
                ols::ActivationMode::Running => {
                    let drift = self.ols_drift(&ols_policy, &predecessor)?;
                    if !drift.clean() {
                        eprintln!("{{\"scope\":\"ols_activate\",\"drift\":\"{drift:?}\"}}");
                        return Err(ExecutorError::Drift);
                    }
                    if !page_cache_ols_ok(eject.is_some(), &sites, drift.page_cache_ols_tested) {
                        return Err(ExecutorError::Drift);
                    }
                }
                ols::ActivationMode::Bootstrap => {
                    let facts = self.bootstrap_facts(&ols_policy, &include, None)?;
                    if !facts.hold(ols::BootstrapStage::BeforeSwitch) {
                        eprintln!("{{\"scope\":\"ols_bootstrap\",\"facts\":\"{facts:?}\"}}");
                        return Err(ExecutorError::Drift);
                    }
                }
            }
        }
        let now = request.now.ok_or(ExecutorError::TimeDenied)?;
        let operation = intent.operation_id.clone();
        let recorded = self.admit(signed_inputs(request)?, |journal| {
            match (eject, page_cache) {
                (Some((site, _, Some(hostname))), _) => {
                    journal.record_static_ejection_intent(&intent, site, hostname, now)
                }
                (Some((site, _, None)), _) => journal.record_ejection_intent(&intent, site, now),
                (None, Some(PageCacheChange::OptIn(site, recipe))) => journal
                    .record_page_cache_intent(&intent, site, page_cache::recipe_name(*recipe), now),
                (None, Some(PageCacheChange::OptOut(site, recipe))) => journal
                    .record_page_cache_opt_out_intent(
                        &intent,
                        site,
                        page_cache::recipe_name(*recipe),
                        now,
                    ),
                (None, None) => journal.record_intent(&intent, now),
            }
        })?;
        let Admitted::New(_) = recorded else {
            return Err(ExecutorError::ReplayDenied);
        };
        self.fault(Fault::AfterOlsIntent)?;
        let ask = |step| AdminRequest {
            operation_id: operation.clone(),
            step,
        };
        if let Some(socket) = socket.as_deref() {
            let clean = match mode {
                ols::ActivationMode::Running => {
                    // W357: the intent is already recorded, so the latest
                    // operation is this one; compare with the generation the
                    // journal established before it, as the in-process check
                    // does before intent. W359: generation drift is refused
                    // before intent, so this is a recheck for a change since.
                    // W360: a refusal records the plan predecessor, which
                    // the check before intent found established; an
                    // `untouched` operation establishes nothing of its own.
                    let established = self.established_before(&operation)?;
                    let live = ols::observe(&include)?;
                    let generation = ols::current_checks(Some(&live), established.as_ref());
                    let drift = ols::preflight_report(
                        admin_helper::request(socket, &ask(AdminStep::OlsPreflight)),
                        generation,
                    );
                    if !drift.is_some_and(|drift| drift.clean()) {
                        eprintln!("{{\"scope\":\"ols_activate\",\"drift\":\"{drift:?}\"}}");
                    }
                    let page_cache = page_cache_ols_ok(
                        eject.is_some(),
                        &sites,
                        drift.is_some_and(|drift| drift.page_cache_ols_tested),
                    );
                    drift.is_some_and(|drift| drift.clean()) && page_cache
                }
                // The helper decides the bootstrap facts itself from the
                // journaled predecessor; only a bare `ok` passes.
                ols::ActivationMode::Bootstrap => matches!(
                    admin_helper::request(socket, &ask(AdminStep::OlsPreflight)),
                    Ok(admin_helper::Reply::Done(None))
                ),
            };
            if !clean {
                self.journal.record_observation(
                    &operation,
                    Some(&current),
                    Some(&intent.predecessor_digest),
                )?;
                return Err(ExecutorError::Drift);
            }
        }
        // W384: the target is written in a temporary sibling folder and gets
        // its id only when complete and read back. A folder under the id is
        // reused only when identical; one with other files is moved aside,
        // never trusted and never deleted.
        let staged = ols::prepare(&include, &target, &generation, &operation);
        let staged = match staged {
            Ok(staging) => {
                self.fault(Fault::DuringOlsStaging)?;
                ols::publish(&include, &target, staging)
            }
            Err(error) => Err(error),
        };
        stage_line(&include, &operation, &target, staged.as_ref());
        if let Err(error) = staged {
            self.journal.record_observation(
                &operation,
                Some(&current),
                Some(&intent.predecessor_digest),
            )?;
            return Err(error);
        }
        self.journal.mark_effect_attempted(&operation)?;
        self.fault(Fault::AfterOlsEffectMark)?;
        let socket = socket.as_deref();
        let standalone = match eject {
            Some((_, account, static_hostname)) => sites
                .iter()
                .find(|site| site.account == account)
                .ok_or(ExecutorError::Unavailable)
                .and_then(|site| {
                    let vhost = if site.alias_hostname.is_some() {
                        ols::ejected_static_vhost(account, site.hostname.as_str())
                    } else if let Some(hostname) = static_hostname {
                        if hostname != &site.hostname {
                            return Err(ExecutorError::PreconditionChanged);
                        }
                        ols::ejected_single_static_vhost(
                            account,
                            hostname.as_str(),
                            site.tls.is_some(),
                        )
                    } else {
                        ols::ejected_vhost(
                            account,
                            site.hostname.as_str(),
                            site.lscache,
                            site.tls.is_some(),
                        )
                    };
                    ols::write_ejected(account, vhost.as_bytes(), &operation, &intent.grant_digest)
                }),
            None => Ok(()),
        };
        let served = standalone
            .and_then(|()| ols::switch(&include, &target))
            .and_then(|()| {
                admin_helper::route(socket, &ask(AdminStep::OlsConfigTest), || {
                    crate::ols::config_test()
                })
            })
            .and_then(|()| {
                admin_helper::route(socket, &ask(mode.serving_step()), || {
                    if mode == ols::ActivationMode::Bootstrap {
                        let facts =
                            self.bootstrap_facts(&ols_policy, &include, Some(&operation))?;
                        let target = (target.clone(), target_digest.clone());
                        if !facts.hold(ols::BootstrapStage::Start(&target)) {
                            return Err(ExecutorError::Drift);
                        }
                    }
                    provision::run(
                        "/usr/bin/systemctl",
                        &[mode.systemctl_verb(), ols::OLS_UNIT],
                    )
                })
            });
        if served.is_ok() {
            self.fault(Fault::AfterOlsServing)?;
        }
        let activated = served
            .and_then(|()| match eject {
                // W387 (D-037): OLS now starts the site's PHP itself. Stop
                // and disable the site's Rustiron PHP units, and require a
                // PHP answer without them, before the verification.
                Some((site, account, static_hostname)) => {
                    admin_helper::route(socket, &ask(AdminStep::EjectPhpStop), || {
                        let probe = if static_hostname.is_some() {
                            let tls = sites
                                .iter()
                                .find(|served| served.account == account)
                                .is_some_and(|served| served.tls.is_some());
                            crate::ejection::EjectProbe::StaticSingle { tls }
                        } else {
                            crate::ejection::EjectProbe::WordPress
                        };
                        crate::ejection::stop_site_php(
                            account,
                            &ols_policy.address,
                            ols_policy.tls_address.as_deref(),
                            served_hostname(&sites, site)?,
                            probe,
                        )
                    })
                }
                None => Ok(()),
            })
            .and_then(|()| {
                admin_helper::route(socket, &ask(AdminStep::OlsVerify), || {
                    probe_with_retry(&ols_policy, &sites)
                        .and_then(|()| parent_unchanged(&ols_policy))
                        .and_then(|()| match mode {
                            ols::ActivationMode::Running => Ok(()),
                            ols::ActivationMode::Bootstrap => {
                                admin_helper::server_checks(&ols_policy)?
                                    .webadmin_closed
                                    .then_some(())
                                    .ok_or(ExecutorError::Drift)
                            }
                        })
                })
            })
            .and_then(|()| match page_cache {
                // W368: the site now has its own cache storage and every
                // site answered; install the plugin as the site. A failure
                // here takes the same single signed restore as a failed probe.
                Some(PageCacheChange::OptIn(site, recipe)) => {
                    admin_helper::route(socket, &ask(AdminStep::PageCacheInstall), || {
                        page_cache::install(
                            &provision::SiteLayout::derive(site),
                            &self.anchor.recipes_dir,
                            &ols_policy.address,
                            served_hostname(&sites, site)?,
                            *recipe,
                        )
                        .map(drop)
                    })
                }
                // W370: the site's vhost now has the cache module off and
                // every site answered; deactivate the plugin as the site and
                // empty the site's storage.
                Some(PageCacheChange::OptOut(site, _)) => {
                    admin_helper::route(socket, &ask(AdminStep::PageCacheRemove), || {
                        page_cache::remove(
                            &provision::SiteLayout::derive(site),
                            &ols_policy.address,
                            served_hostname(&sites, site)?,
                        )
                        .map(drop)
                    })
                }
                None => Ok(()),
            });
        let observed = ols::observe(&include).ok();
        if activated.is_ok() && observed.as_ref() == Some(&(target, target_digest)) {
            let (id, digest) = observed.unwrap_or_else(|| unreachable!());
            return Ok(Admitted::New(self.journal.record_observation(
                &operation,
                Some(&id),
                Some(&digest),
            )?));
        }
        // Not verified: block, then the single signed restore of the previous generation.
        self.journal.record_observation(&operation, None, None)?;
        if mode == ols::ActivationMode::Bootstrap {
            // W355: back to "no generation": stop OLS, remove `current`.
            let marked = self.journal.begin_compensation(&operation, now);
            if marked.is_ok() {
                self.fault(Fault::AfterOlsRestoreMark)?;
            }
            let restored = marked
                .map_err(ExecutorError::from)
                .map(|_| self.restore_bootstrap(&operation, &ols_policy, &include));
            let (id, digest) = match restored {
                Ok(Some((id, digest))) => (Some(id), Some(digest)),
                _ => (None, None),
            };
            self.journal
                .record_observation(&operation, id.as_ref(), digest.as_ref())?;
            return Err(activated.err().unwrap_or(ExecutorError::StepFailed));
        }
        let marked = self.journal.begin_compensation(&operation, now);
        if marked.is_ok() {
            self.fault(Fault::AfterOlsRestoreMark)?;
        }
        let restored = marked
            .map_err(ExecutorError::from)
            .and_then(|_| ols::switch(&include, &current))
            .and_then(|()| {
                admin_helper::route(socket, &ask(AdminStep::OlsReload), || {
                    provision::run("/usr/bin/systemctl", &["reload", "lshttpd.service"])
                })
            })
            .and_then(|()| self.restore_ejected_php(&operation, socket))
            .and_then(|()| {
                admin_helper::route(socket, &ask(AdminStep::OlsVerify), || {
                    self.probe_registered(&ols_policy)
                })
            })
            .and_then(|()| match page_cache {
                // W370: after the restore, a page-cache change never leaves
                // the plugin active or entries in the site's storage. A
                // failed removal leaves the operation unverified.
                Some(change) => {
                    admin_helper::route(socket, &ask(AdminStep::PageCacheRemove), || {
                        page_cache::remove(
                            &provision::SiteLayout::derive(change.site()),
                            &ols_policy.address,
                            served_hostname(&sites, change.site())?,
                        )
                        .map(drop)
                    })
                }
                None => Ok(()),
            })
            .and_then(|()| self.observe_restored_ols(&include, &intent));
        let (id, digest) = restored
            .as_ref()
            .map_or((None, None), |(id, digest)| (Some(id), Some(digest)));
        self.journal.record_observation(&operation, id, digest)?;
        Err(activated.err().unwrap_or(ExecutorError::StepFailed))
    }

    /// Read-only lab OLS observation for review: `current`, its digest and
    /// every drift check, against the journal and enrolled policy.
    /// W355: with no `current`, the live generation reported is the
    /// bootstrap one and `current` is `None`.
    pub fn ols_status(&self) -> Result<OlsStatus, ExecutorError> {
        let policy = self.ols_policy()?;
        let include = ols::open_include()?;
        let current = ols::observe_current(&include)?;
        let live = current.clone().unwrap_or_else(ols::bootstrap_generation);
        // W362: judged on `current` as observed; in the product profile an
        // empty history establishes the bootstrap generation.
        let established = self.ols_established()?;
        let generation = ols::current_checks(current.as_ref(), established.as_ref());
        let Some(socket) = self.anchor.admin_socket.as_deref() else {
            let adopted: Vec<&str> = policy.adopted.iter().map(|s| s.name.as_str()).collect();
            let report = ols::observe_drift(
                generation,
                &policy.parent_sha256,
                policy.webadmin_port,
                &adopted,
            );
            return Ok((current, live, report));
        };
        // W202: the server checks need the helper's reads under confinement.
        let checks = admin_helper::ols_status(socket)?;
        Ok((current, live, checks.report(generation)))
    }

    /// W357: the OLS generation the journal established before
    /// `operation`; `None` when nothing was established or an earlier
    /// operation is unresolved. W362: see [`ols::established_generation`]
    /// for an empty history.
    fn established_before(
        &self,
        operation: &Id,
    ) -> Result<Option<(Id, Sha256Digest)>, ExecutorError> {
        Ok(ols::established_generation(
            self.ols_history(Some(operation))?,
        ))
    }

    /// W360: the OLS history before `operation` (or before a new one), with
    /// the bootstrap generation as the baseline: only a verified activation
    /// establishes a generation; a failed bootstrap re-establishes the start.
    ///
    /// W372: after a generation adoption, the adopted generation is the
    /// baseline instead of the bootstrap one, and an empty history
    /// establishes it ([`ols::with_adoption`]).
    fn ols_history(
        &self,
        operation: Option<&Id>,
    ) -> Result<rustiron_journal::ResourceHistory, ExecutorError> {
        journal_ols_history(&self.journal, &ols_resource()?, operation)
    }

    /// W372: what established the OLS generation the checks compare with:
    /// `operation` (a verified activation), `adoption` (the generation
    /// form of `site_readopt`), `bootstrap` (the product rule for an empty
    /// history), `none` (lab, empty history) or `unresolved`.
    pub fn ols_established_by(&self) -> Result<&'static str, ExecutorError> {
        let own = self
            .journal
            .resource_history(&ols_resource()?, None, None)?;
        Ok(match own {
            rustiron_journal::ResourceHistory::Established(..) => "operation",
            rustiron_journal::ResourceHistory::Unresolved => "unresolved",
            rustiron_journal::ResourceHistory::Empty => {
                if self.journal.ols_adoption()?.is_some() {
                    "adoption"
                } else if cfg!(rustiron_profile = "product") {
                    "bootstrap"
                } else {
                    "none"
                }
            }
        })
    }

    /// W360: the OLS generation the journal established, under the rule of
    /// [`Self::ols_history`]. W362: see [`ols::established_generation`] for
    /// an empty history.
    fn ols_established(&self) -> Result<Option<(Id, Sha256Digest)>, ExecutorError> {
        Ok(ols::established_generation(self.ols_history(None)?))
    }

    /// The in-process drift report for `live`, the `current` the caller
    /// already matched to the plan predecessor.
    fn ols_drift(
        &self,
        ols_policy: &crate::policy::OlsPolicy,
        live: &(Id, Sha256Digest),
    ) -> Result<ols::DriftReport, ExecutorError> {
        let established = self.ols_established()?;
        let adopted: Vec<&str> = ols_policy
            .adopted
            .iter()
            .map(|site| site.name.as_str())
            .collect();
        Ok(ols::observe_drift(
            ols::current_checks(Some(live), established.as_ref()),
            &ols_policy.parent_sha256,
            ols_policy.webadmin_port,
            &adopted,
        ))
    }

    /// Read-only export of one provisioned site's ownership: the journal
    /// record, live account/label/database/unit facts and whether the active
    /// OLS generation serves it (with the vhost file's digest). Secrets are
    /// never read; nothing is changed.
    pub fn export_site(
        &self,
        site: &rustiron_contracts::approval::SiteId,
    ) -> Result<serde_json::Value, ExecutorError> {
        let provision = self
            .journal
            .provision_for_site(site)?
            .ok_or(ExecutorError::NotAdmitted)?;
        let layout = provision::SiteLayout::derive(site);
        let state = match provision.state {
            ProvisionState::Running => "running",
            ProvisionState::Succeeded => "succeeded",
            ProvisionState::Quarantined => "quarantined",
            ProvisionState::Adopted => "adopted",
            ProvisionState::Deleted => "deleted",
        };
        // W372: an adopted site names its re-adoption, the previous epoch
        // and the SHA-256 of the recorded facts.
        let readoption = match provision.state {
            ProvisionState::Adopted => self
                .journal
                .readoption_status(&provision.intent.operation_id)?
                .map(|row| {
                    serde_json::json!({
                        "operation_id": row.intent.operation_id.as_str(),
                        "previous_epoch": row.intent.previous_epoch.as_str(),
                        "evidence_sha256": row.intent.evidence_sha256.as_str(),
                        "facts_sha256": row.facts.as_deref().map(|facts| {
                            grant_digest(facts.as_bytes()).as_str().to_owned()
                        }),
                    })
                }),
            _ => None,
        };
        let provenance = match provision.state {
            ProvisionState::Adopted => "explicitly_adopted",
            _ => "created",
        };
        let adoption = self.journal.site_adoption(&provision.intent.operation_id)?;
        let uid = adoption
            .as_ref()
            .map(|adopted| adopted.uid)
            .or_else(|| journaled_uid(&provision));
        let quota_facts = match (self.journal.latest_quota_limits(site)?, adoption, uid) {
            // W534 (D-088): a signed quota change replaces the earlier
            // limits.
            (Some((block_hard_kib, inode_hard)), _, Some(uid)) => crate::quota::changed_facts(
                &mut crate::quota::SystemQuota,
                uid,
                crate::quota::QuotaLimits {
                    block_hard_kib,
                    inode_hard,
                },
            ),
            (_, Some(adopted), _) => crate::quota::adopted_facts(
                &mut crate::quota::SystemQuota,
                adopted.uid,
                crate::quota::QuotaLimits {
                    block_hard_kib: adopted.quota_kib,
                    inode_hard: adopted.quota_inodes,
                },
            ),
            _ => crate::quota::facts(&mut crate::quota::SystemQuota, &provision),
        };
        let ejected = self.journal.ejected_sites()?.contains(site);
        let ols = ols::open_include()
            .and_then(|include| {
                Ok((
                    ols::observe(&include)?,
                    if ejected {
                        ols::ejected_digest(&layout.account)
                    } else {
                        ols::vhost_digest(&include, &layout.account)?
                    },
                ))
            })
            .ok();
        Ok(serde_json::json!({
            "schema_version": 1,
            "kind": "rustiron_lab_site_export",
            "site_id": site.as_str(),
            "hostname": provision.intent.hostname.as_str(),
            "provenance": provenance,
            "readoption": readoption,
            "provision": {
                "operation_id": provision.intent.operation_id.as_str(),
                "state": state,
                "plan_digest": provision.intent.plan_digest.as_str(),
                "host_epoch": provision.intent.host_epoch.as_str(),
            },
            "ownership": provision::ownership_facts(&layout),
            "quota": quota_facts,
            "ols": ols.map(|((generation, digest), vhost)| serde_json::json!({
                "current_generation": generation.as_str(),
                "current_digest": digest.as_str(),
                "ejected": ejected,
                "vhost_file": if ejected {
                    format!("{}/{}/vhost.conf", ols::EJECTED_DIR, layout.account)
                } else {
                    format!("{}/generations/{}/{}.vhost", ols::INCLUDE_DIR, generation.as_str(), layout.account)
                },
                "vhost_sha256": vhost.as_ref().map(|d| d.as_str().to_owned()),
                "served": vhost.is_some(),
            })),
            "limitations": [
                "lab export with synthetic keys; an ejected site's vhost entry is still rendered by Rustiron's listener include until uninstall",
                "secrets are reported as present/absent only and must be recovered from the host",
                "adopted-site and parent OLS configuration are not included",
            ],
        }))
    }

    /// The provision recorded for a site id, if any; status only.
    pub fn provision_for_site(
        &self,
        site: &rustiron_contracts::approval::SiteId,
    ) -> Result<Option<Provision>, ExecutorError> {
        Ok(self.journal.provision_for_site(site)?)
    }

    /// W335 admin retire step (service stopped, after the account is
    /// removed): clear the quota the provision journaled for its uid. The
    /// uid and the limits come only from this site's journal record.
    pub fn retire_site_quota(
        &self,
        site: &rustiron_contracts::approval::SiteId,
    ) -> Result<serde_json::Value, ExecutorError> {
        let provision = self
            .journal
            .provision_for_site(site)?
            .ok_or(ExecutorError::NotAdmitted)?;
        // W372: an adopted site's uid is its adoption record.
        if let Some(adopted) = self.journal.site_adoption(&provision.intent.operation_id)? {
            return crate::quota::retire_adopted(&mut crate::quota::SystemQuota, site, adopted.uid);
        }
        crate::quota::retire(&mut crate::quota::SystemQuota, &provision)
    }

    /// Recorded provision status only.
    pub fn provision_status(&self, operation_id: &Id) -> Result<Option<Provision>, ExecutorError> {
        Ok(self.journal.provision_status(operation_id)?)
    }

    /// Quarantines a provision left running by a crash; infers no step outcome.
    pub fn quarantine_provision(&mut self, operation_id: &Id) -> Result<Provision, ExecutorError> {
        Ok(self.journal.quarantine_provision(operation_id)?)
    }

    /// D-103 (W778): the owned sites for `site_records`, as (site ID,
    /// hostname, adopted). One row more than the limit lets the caller refuse
    /// an oversized answer instead of cutting it short.
    pub fn owned_sites(&self) -> Result<Vec<(String, String, bool)>, ExecutorError> {
        self.journal
            .owned_sites(rustiron_contracts::MAX_INVENTORY_SITES + 1)
            .map_err(Into::into)
    }

    /// D-104 (W779): the closed host summary from the read-only observation.
    pub fn host_summary(&self) -> Result<rustiron_contracts::summary::HostSummary, ExecutorError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        crate::host_summary::project(&Self::observe(&self.anchor)?, now)
    }

    /// Self-attested receipt for a finished probe or capture, signed by the
    /// host receipt key when one is installed (W392). None when the id is absent.
    pub fn evidence(&self, operation_id: &Id) -> Result<Option<serde_json::Value>, ExecutorError> {
        let document = if let Some(probe) = self.probe_status(operation_id)? {
            let receipt = probe
                .receipt
                .as_deref()
                .and_then(|text| serde_json::from_str(text).ok())
                .ok_or(ExecutorError::NotAdmitted)?;
            crate::receipt::recovery_receipt(&probe, receipt)?
        } else if let Some(capture) = self.capture_status(operation_id)? {
            crate::receipt::capture_receipt(&capture)?
        } else {
            return Ok(None);
        };
        crate::receipt_key::sign(&self.anchor, document).map(Some)
    }

    /// Recorded status only; creates no history and grants nothing.
    pub fn status(&self, operation_id: &Id) -> Result<Option<Operation>, ExecutorError> {
        Ok(self.journal.status(operation_id)?)
    }

    /// W377: the enrolled host and epoch that a request was verified against
    /// must be the ones this journal was opened for. A policy re-enrolled
    /// while the executor keeps an older journal open is refused before
    /// intent as a journal identity mismatch, as the product backup verbs
    /// do, and never reaches the journal's replay refusal. W380: every
    /// signed verb runs this check right after its verification.
    pub(crate) fn check_enrolled_identity(
        &self,
        enrolled: &policy::Policy,
    ) -> Result<(), ExecutorError> {
        self.check_identity(&enrolled.host_id, &enrolled.host_epoch)
    }

    /// [`Self::check_enrolled_identity`] for a verified intent that carries
    /// the enrolled host and epoch (the fixture verb and `site_provision`).
    fn check_identity(&self, host_id: &Id, host_epoch: &Id) -> Result<(), ExecutorError> {
        if host_id != &self.identity.0 || host_epoch != &self.identity.1 {
            return Err(ExecutorError::IdentityMismatch);
        }
        Ok(())
    }

    /// Rechecks current enrollment and the rollback fence before a status read.
    pub(crate) fn authorize_status_peer(&self, peer_uid: u32) -> Result<(), ExecutorError> {
        let directory =
            files::open_trusted_directory(&self.anchor.policy_dir, self.anchor.owner_uid)?;
        let policy = policy::load(&directory, self.anchor.owner_uid)?.policy;
        if policy.requester_uid != peer_uid {
            return Err(ExecutorError::PeerDenied);
        }
        if (policy.host_id, policy.host_epoch) != self.identity {
            return Err(ExecutorError::IdentityMismatch);
        }
        let seen = mark::read(&self.anchor)?;
        mark::check(
            seen.as_ref(),
            &self.identity.0,
            &self.identity.1,
            self.journal.admission_count()?,
        )
    }
}

/// The process must actually be the anchor owner (root in the lab), with no
/// setuid mixture, and the journal directory must have trusted ancestry.
pub(crate) fn prepare(anchor: &TrustAnchor) -> Result<(Id, Id), ExecutorError> {
    let loaded = load_state_policy(anchor)?;
    Ok((loaded.policy.host_id, loaded.policy.host_epoch))
}

/// Checks the rollback fence and reads the pending OLS action while the
/// caller holds the journal lease.
pub(crate) fn pending_boot_activation(
    anchor: &TrustAnchor,
    host: &Id,
    epoch: &Id,
    journal: &FixtureJournal,
) -> Result<Option<ols::boot_guard::PendingActivation>, ExecutorError> {
    let mark = mark::read(anchor)?;
    mark::check(mark.as_ref(), host, epoch, journal.admission_count()?)?;
    let resource = ols_resource()?;
    let Some(operation) = journal.unresolved_operation(&resource)? else {
        return Ok(None);
    };
    let history = journal_ols_history(journal, &resource, Some(&operation.intent.operation_id))?;
    Ok(Some(ols::boot_guard::pending_activation(
        &operation, history,
    )))
}

fn journal_ols_history(
    journal: &FixtureJournal,
    resource: &Id,
    operation: Option<&Id>,
) -> Result<rustiron_journal::ResourceHistory, ExecutorError> {
    let adoption = journal.ols_adoption()?;
    let baseline = adoption.clone().unwrap_or_else(ols::bootstrap_generation);
    let history = journal.resource_history(resource, operation, Some(&baseline))?;
    Ok(ols::with_adoption(history, adoption))
}

fn load_state_policy(anchor: &TrustAnchor) -> Result<policy::LoadedPolicy, ExecutorError> {
    let (uid, euid) = (rustix::process::getuid(), rustix::process::geteuid());
    if uid != euid || euid.as_raw() != anchor.owner_uid {
        return Err(ExecutorError::AccessDenied);
    }
    files::open_trusted_directory(&anchor.journal_dir, anchor.owner_uid)?;
    let policy_dir = files::open_trusted_directory(&anchor.policy_dir, anchor.owner_uid)?;
    policy::load(&policy_dir, anchor.owner_uid)
}

/// Succeeded provisions split into still-managed and ejected sites.
///
/// Last-known-good restore probes both. Adopted sites are probed separately.
pub(crate) fn split_registered<'a>(
    succeeded: &'a [rustiron_contracts::approval::SiteId],
    ejected: &'a [rustiron_contracts::approval::SiteId],
) -> (
    Vec<&'a rustiron_contracts::approval::SiteId>,
    Vec<&'a rustiron_contracts::approval::SiteId>,
) {
    let active = succeeded
        .iter()
        .filter(|site| !ejected.contains(site))
        .collect();
    let ejected = ejected
        .iter()
        .filter(|site| succeeded.contains(site))
        .collect();
    (active, ejected)
}

impl Executor {
    fn registered_sites(&self) -> Result<Vec<ols::ServedSite>, ExecutorError> {
        let ejected = self.journal.ejected_sites()?;
        let succeeded = self.journal.succeeded_sites()?;
        let (active, ejected) = split_registered(&succeeded, &ejected);
        let active: Vec<_> = active.into_iter().cloned().collect();
        let ejected: Vec<_> = ejected.into_iter().cloned().collect();
        let mut sites = self.served(&active, false)?;
        sites.extend(self.served(&ejected, true)?);
        Ok(sites)
    }

    /// W519-F1 (D-085): probes the registered sites that the live
    /// generation names, and every ejected site, as the admin helper's
    /// verification does. A site that a signed activation took offline is
    /// not probed.
    fn probe_registered(&self, policy: &crate::policy::OlsPolicy) -> Result<(), ExecutorError> {
        let include = ols::open_include()?;
        let (live, _) = ols::observe(&include)?;
        let named = ols::managed_accounts(&include, &live)?;
        let sites = generation_sites(self.registered_sites()?, &named);
        probe_with_retry(policy, &sites)
    }
}

/// W519-F1: the registered sites that a generation naming `named`
/// accounts serves, plus every ejected site.
fn generation_sites(registered: Vec<ols::ServedSite>, named: &[String]) -> Vec<ols::ServedSite> {
    registered
        .into_iter()
        .filter(|site| site.ejected || named.contains(&site.account))
        .collect()
}

/// OLS graceful reload takes a moment; probe for up to about 10 seconds.
pub(crate) fn probe_with_retry(
    policy: &crate::policy::OlsPolicy,
    sites: &[ols::ServedSite],
) -> Result<(), ExecutorError> {
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if ols::probe_all(
            &policy.address,
            policy.tls_address.as_deref(),
            &policy.adopted,
            sites,
        )
        .is_ok()
        {
            return Ok(());
        }
    }
    // W511 (P08): name the sites that did not answer with their identity,
    // so the operator need not repeat the activation to find them.
    let failed: Vec<&str> = sites
        .iter()
        .filter(|site| {
            ols::probe_all(
                &policy.address,
                policy.tls_address.as_deref(),
                &[],
                std::slice::from_ref(*site),
            )
            .is_err()
        })
        .map(|site| site.account.as_str())
        .collect();
    eprintln!(
        "{}",
        serde_json::json!({"scope": "ols_verify_probe", "unanswered_sites": failed})
    );
    Err(ExecutorError::ProbeFailed)
}

/// `ols-status`: `current` (`None` when absent), the generation that stands
/// for it (the bootstrap one when absent), and the drift checks.
/// W427 (D-052): an activation that serves a site with the cache-on recipe
/// needs a tested OLS version, because the post-password bypass depends on
/// it (W426-F1). An eject is the recovery path and is never held back.
fn page_cache_ols_ok(eject: bool, sites: &[ols::ServedSite], tested: bool) -> bool {
    let needed = !eject && sites.iter().any(|site| site.lscache);
    if needed && !tested {
        eprintln!("{{\"scope\":\"ols_activate\",\"page_cache_ols_tested\":false}}");
    }
    !needed || tested
}

#[cfg(test)]
mod page_cache_ols_tests {
    use super::page_cache_ols_ok;
    use crate::ols::ServedSite;

    fn site(account: &str, lscache: bool) -> ServedSite {
        ServedSite {
            account: account.to_owned(),
            alias_hostname: None,
            hostname: rustiron_contracts::approval::Hostname::try_from(format!(
                "{}.example.test",
                account.trim_start_matches("rs_")
            ))
            .unwrap(),
            ejected: false,
            static_ejected: false,
            lscache,
            tls_alias: None,
            tls: None,
            acme: false,
            proxy: None,
        }
    }

    #[test]
    fn a_cached_site_needs_a_tested_ols_except_for_an_eject() {
        let cached = [site("rs_a", true), site("rs_b", false)];
        let plain = [site("rs_a", false), site("rs_b", false)];
        assert!(!page_cache_ols_ok(false, &cached, false));
        assert!(page_cache_ols_ok(false, &cached, true));
        assert!(page_cache_ols_ok(false, &plain, false));
        assert!(page_cache_ols_ok(true, &cached, false));
    }
}

pub type OlsStatus = (
    Option<(Id, Sha256Digest)>,
    (Id, Sha256Digest),
    ols::DriftReport,
);

/// What one generation change does besides rendering (W368): an activation,
/// optionally with one page-cache change, or an ejection.
enum Change<'a> {
    Activate(Option<&'a PageCacheChange>),
    Eject {
        site: &'a rustiron_contracts::approval::SiteId,
        account: &'a str,
        static_hostname: Option<&'a rustiron_contracts::approval::Hostname>,
    },
}

/// One site's page-cache change in an activation: the opt-in (W368) or the
/// opt-out (W370), with its approved recipe (W395).
enum PageCacheChange {
    OptIn(
        rustiron_contracts::approval::SiteId,
        rustiron_contracts::approval::PageCacheRecipe,
    ),
    OptOut(
        rustiron_contracts::approval::SiteId,
        rustiron_contracts::approval::PageCacheRecipe,
    ),
}

impl PageCacheChange {
    fn site(&self) -> &rustiron_contracts::approval::SiteId {
        match self {
            Self::OptIn(site, _) | Self::OptOut(site, _) => site,
        }
    }
}

/// The hostname of a served site of the generation being applied.
fn served_hostname<'a>(
    sites: &'a [ols::ServedSite],
    site: &rustiron_contracts::approval::SiteId,
) -> Result<&'a rustiron_contracts::approval::Hostname, ExecutorError> {
    let account = provision::SiteLayout::derive(site).account;
    sites
        .iter()
        .find(|served| served.account == account)
        .map(|served| &served.hostname)
        .ok_or(ExecutorError::Unavailable)
}

/// W384: one JSON line (executor log) per staging: what happened to the
/// folder under the target id, the quarantine name it now has, and the
/// staging leftovers that `generations` holds. Names only, no paths.
fn stage_line(
    include: &std::os::fd::OwnedFd,
    operation: &Id,
    target: &Id,
    staged: Result<&ols::Staged, &ExecutorError>,
) {
    let (outcome, quarantined) = match staged {
        Ok(ols::Staged::Reused) => ("reused", None),
        Ok(ols::Staged::Written) => ("written", None),
        Ok(ols::Staged::Quarantined(name)) => ("quarantined", Some(name.as_str())),
        Err(error) => (error.code(), None),
    };
    let leftovers = ols::leftovers(include).ok();
    eprintln!(
        "{}",
        serde_json::json!({
            "scope": "ols_stage",
            "operation_id": operation.as_str(),
            "target": target.as_str(),
            "staged": outcome,
            "quarantined": quarantined,
            "leftovers": leftovers,
        })
    );
}

/// Signed fields an OLS intent carries besides the rendered target.
struct IntentBase {
    grant_id: Id,
    nonce: Id,
    /// Plan digest and complete canonical grant digest.
    digests: (Sha256Digest, Sha256Digest),
    predecessor: (Id, Sha256Digest),
    expires_at: Timestamp,
    compensation_valid_until: Timestamp,
}

pub(super) fn system_now() -> Option<Timestamp> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Timestamp::try_from(seconds).ok()
}

pub(super) fn grant_digest(grant: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(grant).into())
}

pub(crate) fn ols_resource() -> Result<Id, ExecutorError> {
    Id::try_from("ols_lab_listener".to_owned()).map_err(|_| ExecutorError::Unavailable)
}

/// After the reload: the parent OLS read must still be the reviewed one.
pub(crate) fn parent_unchanged(ols_policy: &crate::policy::OlsPolicy) -> Result<(), ExecutorError> {
    if ols::parent_reviewed(&ols_policy.parent_sha256)
        && ols::webadmin_closed(ols_policy.webadmin_port)
    {
        Ok(())
    } else {
        Err(ExecutorError::Drift)
    }
}

/// A snapshot revert of the whole guest rolls the journal and the admission
/// mark back together. That pair is not detected. Rotate the host epoch
/// after any such revert. Grant windows stay at most 3600 seconds.
pub const WHOLE_VM_REVERT_LIMIT: &str = "a whole-VM revert that rolls the journal and the admission mark back together is not detected; rotate the host epoch after any such revert; grant windows stay at most 3600 seconds";

/// Capture evidence for display. A running row, or a success without a
/// lowercase 64-hex snapshot id, has no fields. Digests stay out.
fn capture_observation_fields(capture: &rustiron_journal::ObservedCapture) -> serde_json::Value {
    let Some(observed_at) = capture.finished_at else {
        return serde_json::Value::Null;
    };
    if capture.state == "running" {
        return serde_json::Value::Null;
    }
    let succeeded = capture.state == "succeeded"
        && capture.snapshot_id.as_deref().is_some_and(|id| {
            id.len() == 64
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        });
    if capture.state == "succeeded" && !succeeded {
        return serde_json::Value::Null;
    }
    let mut fields =
        crate::receipt::capture_fields(succeeded, capture.method.is_some(), observed_at);
    // W379: the same label and unclaimed-snapshot wording as the receipt.
    if let Some(label) = crate::observed::capture_consistency(capture)["label"].as_str()
        && let Some(scope) = fields["application_consistency_assessed"]["scope"].as_str()
    {
        fields["application_consistency_assessed"]["scope"] =
            format!("{scope}; database marker label: {label}").into();
    }
    if !crate::observed::unclaimed_snapshot(capture).is_null() {
        crate::receipt::mark_unclaimed_artifacts(&mut fields);
    }
    fields
}

/// Display JSON. Nonces, idempotency keys, grant ids and digests stay out:
/// a viewer needs outcomes, not replay material.
fn provision_step_name(position: i64) -> Option<&'static str> {
    match position {
        0 => Some("account"),
        1 => Some("directories"),
        2 => Some("labels"),
        3 => Some("database"),
        4 => Some("credentials"),
        5 => Some("recipe"),
        6 => Some("phpunits"),
        7 => Some("verify"),
        _ => None,
    }
}

fn observation_json(
    policy: &policy::Policy,
    seen: &rustiron_journal::Observation,
    packages: Option<&[crate::packages::Pin]>,
    signer: serde_json::Value,
) -> serde_json::Value {
    use serde_json::json;
    let fields = |receipt: &Option<String>| {
        receipt
            .as_deref()
            .and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok())
            .map_or(serde_json::Value::Null, |value| value["fields"].clone())
    };
    json!({
        "schema": "rustiron-lab-observation/1",
        "limits": [WHOLE_VM_REVERT_LIMIT],
        "host": {
            "host_id": policy.host_id.as_str(),
            "host_epoch": policy.host_epoch.as_str(),
            "issuer": policy.issuer.as_str(),
            "signer_policy_epoch": policy.signer_policy_epoch.as_str(),
            "ols_listener": policy.ols.as_ref().map(|ols| ols.address.clone()),
            "migration_php_versions": policy.migration.as_ref().map(|migration| {
                migration
                    .php_versions
                    .iter()
                    .map(rustiron_contracts::migration::PhpVersion::as_str)
                    .collect::<Vec<_>>()
            }),
            "adopted_sites": policy.ols.as_ref().map(|ols| ols.adopted.iter().map(|site| json!({
                "name": site.name, "hostname": site.hostname,
            })).collect::<Vec<_>>()),
            "backup_destination": policy.backup.as_ref().map(|backup| backup.destination_id.clone()),
            "backup_retention_days": policy.backup.as_ref().and_then(|backup| backup.retention_days),
            // Absent (null) when the rpm query failed: the console shows it as missing.
            "packages": crate::packages::to_json(packages),
            // W364: `not_observed` in the product build, which runs no rpm query.
            "package_source": crate::packages::SOURCE,
            // W233: non-secret signer facts; null when the allowlist shape is unexpected.
            "signer": signer,
        },
        "journal_last_time": seen.last_time,
        "sites": seen.provisions.iter().map(|p| json!({
            "site_id": p.site_id, "hostname": p.hostname, "operation_id": p.operation_id,
            "state": p.state, "steps_done": p.steps_done, "steps_recorded": p.steps_recorded,
            "failed_step": p.failed_step.and_then(provision_step_name),
            "ejected": seen.operations.iter().any(|o| o.ejected_site.as_deref() == Some(p.site_id.as_str())
                && o.state == "succeeded"),
            // W379: journal facts only; live quota usage stays in `export SITE`.
            "page_cache": crate::observed::page_cache_state(p),
            "quota": crate::observed::recorded_quota(p),
            // W575 (D-095): a proxy site's loopback ports; empty otherwise.
            "proxy_ports": p.proxy_ports,
            // W591 (P01): an active D-075 static alias hostname, when present.
            "alias_hostname": p.alias_hostname,
            // W598 (D-099): P27 modern app runtime and newest done release, when present.
            "app_runtime": p.app_runtime,
            "app_active_release": p.app_active_release,
        })).collect::<Vec<_>>(),
        "operations": seen.operations.iter().map(|o| {
            let (kind, site) = crate::observed::operation_kind(o);
            json!({
                "operation_id": o.operation_id, "kind": kind,
                "resource_id": o.resource_id, "site_id": site,
                "target_generation": o.target_generation, "state": o.state,
                "effect_attempted": o.effect_attempted, "expires_at": o.expires_at,
            })
        }).collect::<Vec<_>>(),
        "captures": seen.captures.iter().map(|c| json!({
            "operation_id": c.operation_id, "site_id": c.site_id, "state": c.state,
            "snapshot_id": c.snapshot_id, "started_at": c.started_at, "finished_at": c.finished_at,
            "capture_method": c.method,
            "retention_days": c.retention_days,
            "snapshot_files": c.files,
            "snapshot_bytes": c.bytes,
            "manifest": c.manifest_sha256.as_ref().map(|sha| json!({
                "sha256": sha, "entries": c.manifest_entries,
                "regular_bytes": c.manifest_regular_bytes, "truncated": c.manifest_truncated,
            })),
            "fields": capture_observation_fields(c),
            // W379: the receipt's label and the W366 unclaimed snapshot.
            "consistency": crate::observed::capture_consistency(c),
            "unclaimed_snapshot_id": crate::observed::unclaimed_snapshot(c),
            // W391 (v18): the evidence summary and a refused capture's code.
            "retention": crate::retention_evidence::observed_retention(c),
            "refusal": crate::retention_evidence::observed_refusal(c),
        })).collect::<Vec<_>>(),
        "probes": seen.probes.iter().map(|p| json!({
            "operation_id": p.operation_id, "site_id": p.site_id, "snapshot_id": p.snapshot_id,
            "state": p.state, "started_at": p.started_at, "finished_at": p.finished_at,
            "fields": fields(&p.receipt),
            "refusal": crate::observed::probe_refusal(p.receipt.as_deref()),
        })).collect::<Vec<_>>(),
        // W372: re-adoptions beside provisions.
        "readoptions": seen.readoptions.iter().map(|r| json!({
            "operation_id": r.operation_id, "form": r.form, "site_id": r.site_id,
            "state": r.state, "previous_epoch": r.previous_epoch,
            "evidence_sha256": r.evidence_sha256, "refusal": r.refusal, "rule": r.rule,
        })).collect::<Vec<_>>(),
        // W396 (D-045): each admission's recorded digests and signed bytes.
        "admissions": crate::observed::admissions(&seen.admissions),
        "signed_objects": crate::observed::signed_objects(&seen.admissions),
    })
}

/// Persist observed cleanup only; no host effects. Incomplete retries keep the block.
pub(crate) fn finish_probe_cleanup(
    journal: &mut FixtureJournal,
    existing: &Probe,
    cleanup: &restore::CleanupReport,
    now: Timestamp,
) -> Result<Probe, ExecutorError> {
    let state = cleanup.probe_state(false);
    if existing.state == ProbeState::CleanupIncomplete && state == ProbeState::CleanupIncomplete {
        return Ok(existing.clone());
    }
    // D-031 (W373): a product build records the product receipt schema.
    let schema = if cfg!(rustiron_profile = "product") {
        "rustiron-restore-probe/2"
    } else {
        "rustiron-lab-restore-probe/1"
    };
    let receipt = serde_json::json!({
        "receipt_schema": schema,
        "probe_account": existing.intent.probe_account,
        "admin_cleanup": true,
        "cleanup": cleanup.receipt(),
        "note": "probe interrupted or left resources; no check is claimed",
    });
    Ok(journal.finish_probe(
        &existing.intent.operation_id,
        state,
        &receipt.to_string(),
        now,
    )?)
}

/// W220: a reconcile step the helper refused (wrong peer, binding or
/// run-once) is surfaced as an error, not recorded as an unknown outcome;
/// any other failure is an observation failure (`Ok(false)`).
fn reconcile_step(result: Result<(), ExecutorError>) -> Result<bool, ExecutorError> {
    match result {
        Ok(()) => Ok(true),
        Err(
            refused @ (ExecutorError::PeerDenied
            | ExecutorError::BindingDenied
            | ExecutorError::ReplayDenied
            | ExecutorError::HelperUnreachable),
        ) => Err(refused),
        Err(_) => Ok(false),
    }
}

/// W480 (W479-F2): a certificate needs a served site of exactly the signed
/// hostname: a succeeded or adopted provision that is not ejected.
fn certificate_precondition(
    provision: Option<&rustiron_journal::Provision>,
    ejected: &[rustiron_contracts::approval::SiteId],
    intent: &rustiron_journal::CertificateIntent,
) -> Result<(), ExecutorError> {
    let served = provision.is_some_and(|provision| {
        provision.intent.hostname == intent.hostname
            && matches!(
                provision.state,
                rustiron_journal::ProvisionState::Succeeded
                    | rustiron_journal::ProvisionState::Adopted
            )
    });
    if served && !ejected.contains(&intent.site_id) {
        Ok(())
    } else {
        Err(ExecutorError::PreconditionChanged)
    }
}

#[cfg(test)]
mod certificate_precondition_tests {
    use super::{ExecutorError, certificate_precondition};
    use rustiron_contracts::approval::{Hostname, Sha256Digest, SiteId};
    use rustiron_contracts::{Id, Timestamp};
    use rustiron_journal::{CertificateIntent, Provision, ProvisionIntent, ProvisionState};

    fn id(text: &str) -> Id {
        Id::try_from(text.to_owned()).unwrap()
    }

    fn host(text: &str) -> Hostname {
        Hostname::try_from(text.to_owned()).unwrap()
    }

    fn site() -> SiteId {
        SiteId::try_from("acamt".to_owned()).unwrap()
    }

    fn provision(hostname: &str, state: ProvisionState) -> Provision {
        Provision {
            intent: ProvisionIntent {
                operation_id: id("op_imp"),
                idempotency_key: id("idem_imp"),
                grant_id: id("grant_imp"),
                nonce: id("nonce_imp"),
                plan_digest: Sha256Digest::try_from("a".repeat(64)).unwrap(),
                grant_digest: Sha256Digest::try_from("b".repeat(64)).unwrap(),
                host_id: id("host"),
                host_epoch: id("epoch"),
                site_id: site(),
                hostname: host(hostname),
                expires_at: Timestamp::try_from(10_000).unwrap(),
            },
            state,
            steps: Vec::new(),
        }
    }

    fn intent(hostname: &str) -> CertificateIntent {
        CertificateIntent {
            operation_id: id("op_cert"),
            idempotency_key: id("idem_cert"),
            grant_id: id("grant_cert"),
            nonce: id("nonce_cert"),
            plan_digest: Sha256Digest::try_from("c".repeat(64)).unwrap(),
            grant_digest: Sha256Digest::try_from("d".repeat(64)).unwrap(),
            host_id: id("host"),
            host_epoch: id("epoch"),
            site_id: site(),
            hostname: host(hostname),
            alias_hostname: None,
            expires_at: Timestamp::try_from(10_000).unwrap(),
            renew_until: None,
        }
    }

    /// W479-F2: each reason a site cannot take the certificate is
    /// `PRECONDITION_CHANGED`, never a replay.
    #[test]
    fn only_a_served_site_of_the_signed_hostname_takes_a_certificate() {
        let name = "testwp.example.test";
        let ok = |p: Option<&Provision>, ejected: &[SiteId], h: &str| {
            certificate_precondition(p, ejected, &intent(h))
        };
        for state in [ProvisionState::Succeeded, ProvisionState::Adopted] {
            assert_eq!(ok(Some(&provision(name, state)), &[], name), Ok(()));
        }
        let refused = Err(ExecutorError::PreconditionChanged);
        let served = provision(name, ProvisionState::Succeeded);
        assert_eq!(
            ok(Some(&served), &[], "acamt.example.test"),
            refused,
            "other hostname"
        );
        assert_eq!(ok(None, &[], name), refused, "no site");
        assert_eq!(ok(Some(&served), &[site()], name), refused, "ejected");
        for state in [ProvisionState::Running, ProvisionState::Quarantined] {
            assert_eq!(ok(Some(&provision(name, state)), &[], name), refused);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_helper_refusal_fails_the_reconcile_visibly() {
        use super::reconcile_step;
        use crate::ExecutorError as E;
        for refused in [E::PeerDenied, E::BindingDenied, E::ReplayDenied] {
            assert_eq!(reconcile_step(Err(refused)), Err(refused));
        }
        assert_eq!(reconcile_step(Err(E::StepFailed)), Ok(false));
        assert_eq!(reconcile_step(Err(E::Unavailable)), Ok(false));
        assert_eq!(reconcile_step(Ok(())), Ok(true));
    }

    use super::split_registered;
    use rustiron_contracts::approval::SiteId;

    fn site(name: &str) -> SiteId {
        SiteId::try_from(name.to_owned()).unwrap()
    }

    fn observed_capture(
        state: &str,
        snapshot: Option<&str>,
        finished: bool,
        method: bool,
    ) -> rustiron_journal::ObservedCapture {
        rustiron_journal::ObservedCapture {
            operation_id: "op_cap".to_owned(),
            site_id: "blog13".to_owned(),
            state: state.to_owned(),
            snapshot_id: snapshot.map(str::to_owned),
            started_at: 1,
            finished_at: finished.then_some(2),
            method: method.then(|| "site_files_db_v1".to_owned()),
            retention_days: None,
            files: None,
            bytes: None,
            manifest_sha256: None,
            manifest_entries: None,
            manifest_regular_bytes: None,
            manifest_truncated: None,
            consistency: None,
            unclaimed_snapshot_id: None,
            retention: None,
            refusal: None,
        }
    }

    /// W379: as its receipt states it, a settled capture with an unclaimed
    /// snapshot reads artifacts `unknown`, never `pass`; the matched label
    /// is named in the consistency scope of a succeeded capture.
    #[test]
    fn capture_observation_fields_match_the_receipt_for_labels_and_unclaimed_snapshots() {
        let snapshot = "ab".repeat(32);
        let mut settled = observed_capture("failed", None, true, true);
        settled.unclaimed_snapshot_id = Some(snapshot.clone());
        let fields = super::capture_observation_fields(&settled);
        assert_eq!(fields["artifacts_complete"]["status"], "unknown");
        assert!(
            fields["artifacts_complete"]["scope"]
                .as_str()
                .unwrap()
                .contains("outcome was uncertain")
        );
        assert_eq!(fields["repository_integrity_checked"]["status"], "not_run");
        let mut matched = observed_capture("succeeded", Some(&snapshot), true, true);
        matched.consistency = Some(("matched".to_owned(), None));
        let fields = super::capture_observation_fields(&matched);
        assert!(
            fields["application_consistency_assessed"]["scope"]
                .as_str()
                .unwrap()
                .ends_with("database marker label: matched")
        );
        let unlabelled = super::capture_observation_fields(&observed_capture(
            "succeeded",
            Some(&snapshot),
            true,
            true,
        ));
        assert!(
            unlabelled["application_consistency_assessed"]["scope"]
                .as_str()
                .unwrap()
                .ends_with("database marker label: unmatched")
        );
    }

    #[test]
    fn capture_observation_fields_follow_the_receipt_and_omit_an_unfinished_row() {
        let snapshot = "ab".repeat(32);
        let fields = super::capture_observation_fields(&observed_capture(
            "succeeded",
            Some(&snapshot),
            true,
            true,
        ));
        assert_eq!(fields["repository_integrity_checked"]["status"], "pass");
        assert_eq!(fields["repository_integrity_checked"]["observed_at"], 2);
        assert!(
            fields["repository_integrity_checked"]["evidence_refs"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(fields["artifacts_complete"]["status"], "unknown");
        assert_eq!(fields["independent_copy_confirmed"]["status"], "unknown");
        assert_eq!(fields["decryption_tested"]["status"], "not_run");
        assert!(
            fields["application_consistency_assessed"]["scope"]
                .as_str()
                .unwrap()
                .contains("no shared freeze point")
        );
        assert!(fields.get("grant_id").is_none());
        assert!(
            super::capture_observation_fields(&observed_capture("running", None, false, true))
                .is_null()
        );
        let uppercase = "AB".repeat(32);
        assert!(
            super::capture_observation_fields(&observed_capture(
                "succeeded",
                Some(&uppercase),
                true,
                true
            ))
            .is_null()
        );
        let failed =
            super::capture_observation_fields(&observed_capture("failed", None, true, true));
        assert_eq!(failed["repository_integrity_checked"]["status"], "not_run");
        let legacy = super::capture_observation_fields(&observed_capture(
            "succeeded",
            Some(&snapshot),
            true,
            false,
        ));
        assert!(
            legacy["application_consistency_assessed"]["scope"]
                .as_str()
                .unwrap()
                .contains("not recorded")
        );
    }

    #[test]
    fn a_failed_step_position_names_the_fixed_step() {
        assert_eq!(super::provision_step_name(0), Some("account"));
        assert_eq!(super::provision_step_name(5), Some("recipe"));
        assert_eq!(super::provision_step_name(7), Some("verify"));
        assert_eq!(super::provision_step_name(8), None);
    }

    #[test]
    fn observation_states_the_whole_vm_revert_limit() {
        assert!(super::WHOLE_VM_REVERT_LIMIT.contains("admission mark"));
        assert!(super::WHOLE_VM_REVERT_LIMIT.contains("host epoch"));
        assert!(super::WHOLE_VM_REVERT_LIMIT.contains("3600"));
    }

    #[test]
    fn last_known_good_probes_managed_and_ejected_sites() {
        let succeeded = vec![site("blog5"), site("blog9"), site("blog10")];
        let ejected = vec![site("blog9")];
        let (active, ejected) = split_registered(&succeeded, &ejected);
        assert_eq!(
            active.iter().map(|site| site.as_str()).collect::<Vec<_>>(),
            ["blog5", "blog10"]
        );
        assert_eq!(
            ejected.iter().map(|site| site.as_str()).collect::<Vec<_>>(),
            ["blog9"]
        );
    }
}

/// W462: the helper's `<sha256> <not_after>` certificate reply.
fn parse_installed(payload: &str) -> Option<(Sha256Digest, Timestamp)> {
    let (sha, not_after) = payload.split_once(' ')?;
    Some((
        Sha256Digest::try_from(sha.to_owned()).ok()?,
        Timestamp::try_from(not_after.parse::<u64>().ok()?).ok()?,
    ))
}

/// W464 (D-060): fewer than this many seconds before expiry is a finding.
const EXPIRY_WARNING_SECONDS: u64 = 14 * 24 * 3600;

/// W464: `expired`, `expires_soon` (under 14 days), `renewal_failed`, or
/// `null` for a healthy served certificate. An unknown clock (0) reports
/// nothing rather than a false finding.
fn certificate_finding(
    served: &rustiron_journal::ObservedCertificate,
    now: u64,
) -> serde_json::Value {
    if now == 0 {
        return serde_json::Value::Null;
    }
    if served.not_after <= now {
        serde_json::json!("expired")
    } else if served.not_after - now < EXPIRY_WARNING_SECONDS {
        serde_json::json!("expires_soon")
    } else if served.last_renewal_failed {
        serde_json::json!("renewal_failed")
    } else {
        serde_json::Value::Null
    }
}

#[cfg(test)]
mod certificate_finding_tests {
    use super::certificate_finding;

    fn served(not_after: u64, failed: bool) -> rustiron_journal::ObservedCertificate {
        rustiron_journal::ObservedCertificate {
            site_id: "blog1".to_owned(),
            hostname: "blog1.example.test".to_owned(),
            certificate_sha256: "a".repeat(64),
            not_after,
            last_renewal_failed: failed,
            ejected: false,
        }
    }

    #[test]
    fn a_restore_probes_only_the_sites_its_generation_names() {
        // W519-F1: an offline site is not probed; an ejected one always is.
        let site = |account: &str, ejected: bool| crate::ols::ServedSite {
            account: account.to_owned(),
            hostname: format!("{}.example.test", &account[3..])
                .try_into()
                .unwrap(),
            alias_hostname: None,
            ejected,
            static_ejected: false,
            lscache: false,
            tls: None,
            tls_alias: None,
            acme: false,
            proxy: None,
        };
        let registered = vec![
            site("rs_blog1", false),
            site("rs_blog2", false),
            site("rs_gone", true),
        ];
        let probed: Vec<_> = crate::durable::generation_sites(registered, &["rs_blog1".to_owned()])
            .into_iter()
            .map(|site| site.account)
            .collect();
        assert_eq!(probed, ["rs_blog1", "rs_gone"]);
    }

    #[test]
    fn expiry_and_failed_renewal_are_findings() {
        let day = 24 * 3600;
        let now = 1_000 * day;
        assert_eq!(certificate_finding(&served(now, false), now), "expired");
        assert_eq!(
            certificate_finding(&served(now + 13 * day, false), now),
            "expires_soon"
        );
        assert_eq!(
            certificate_finding(&served(now + 60 * day, true), now),
            "renewal_failed"
        );
        assert!(certificate_finding(&served(now + 60 * day, false), now).is_null());
        assert!(
            certificate_finding(&served(1, false), 0).is_null(),
            "unknown clock"
        );
    }
}
