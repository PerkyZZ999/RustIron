//! Lab-only root fixture executor. Paths and owner are compiled constants.
//!
//! `rustiron-s02-executor initialize` creates an empty journal once;
//! `migrate` upgrades a valid v3 journal to v4 in place (service stopped);
//! `rustiron-s02-executor serve` binds a fresh socket and serves sequentially.
//! Admin recovery, with the service stopped (the journal writer lock refuses a
//! second process): `status OP`, `reconcile OP` (observe and record only) and
//! `compensate OP` (the single signed restore; `compensate OP --admin-helper`
//! runs its OLS steps through the helper, W370), `provision SITE` (the
//! recorded provision and the resource each step reported, for review) and
//! `quarantine-provision OP` (stop a provision a crash left running; no step
//! outcome is inferred and nothing is undone, W173),
//! `retire-quota SITE` (W335: after the site account is removed, clear the
//! quota its provision journaled for its uid, and read the result back),
//! `quota-readiness` (W335 enrollment check: the sites filesystem has user
//! quota on and enforced; read-only, prints a refusal code otherwise),
//! `ols-status` (the live OLS generation and every drift check, read-only)
//! `export SITE` (one site's ownership manifest, read-only, no secrets),
//! `update-status OP` and `update-reconcile OP --admin-helper` (W518,
//! D-084: an open update's rollback runs again through the admin helper),
//! `update-inventory SITE --admin-helper` (W530, D-087: a site's installed
//! core, plugins, and themes, read only through the admin helper),
//! `quota-status OP` and `quota-reconcile OP --admin-helper` (W535, D-088:
//! an open quota change's limits are set again through the admin helper),
//! `restore-status OP` and `restore-reconcile OP signed|safety
//! --admin-helper` (W543, D-089: an open restore's next attempt restores the
//! signed capture again or the safety capture through the admin helper),
//! `dns-import-status OP` and `dns-import-reconcile OP --admin-helper` (W563,
//! D-091: an open zone import's step runs again through the admin helper),
//! `dns-change-status OP` and `dns-change-reconcile OP --admin-helper` (W565,
//! D-091: an open record change is applied again or settled),
//! `delete-status OP` and `delete-reconcile OP --admin-helper` (W522,
//! D-085: an open deletion's removal runs again through the admin helper),
//! `capture-status OP` and `capture-reconcile OP` (a capture left running:
//! find its tagged snapshot and record the outcome; the product build
//! records only an empty result), `capture-reconcile OP --settle-unclaimed`
//! (W366, product build: the same fresh checks, then a capture with one
//! tagged snapshot is recorded `failed` and the snapshot kept unclaimed;
//! never `succeeded`), `probe-status OP` and
//! `probe-cleanup OP` (remove an interrupted probe's journaled sandbox), and
//! `receipt-export OP` (a portable, self-attested RecoveryReceipt v1 for a
//! finished restore probe, or derived from a finished capture row).
//! `observe` alone runs beside the serving executor: a read-only, non-secret
//! JSON snapshot of the journal and policy for the console.
//! `readopt-status OP` prints a re-adoption (W372): form, state, facts,
//! refusal, previous epoch and evidence digest; `reconcile OP` of a
//! `verifying` re-adoption repeats its read-only observation.
//! `ols-boot-guard` (W381, D-032; the boot unit runs it before `lshttpd`,
//! the admin helper and the executor) points `current` back at the
//! journaled predecessor of an OLS activation whose effect mark is recorded
//! and not settled, or removes it for a bootstrap activation. It records
//! nothing in the journal and never moves the admission mark.
//! `seal-admission-mark` (service stopped) writes the admission high-water
//! mark for a journal that has none for its host/epoch; every open and
//! admission refuses a journal behind that mark (`JOURNAL_ROLLBACK`).
#![warn(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "W672: production code returns errors; tests may unwrap (clippy.toml)"
)]

use std::{path::PathBuf, process::ExitCode};

use std::time::{SystemTime, UNIX_EPOCH};

use rustiron_contracts::{Id, Timestamp, approval::SiteId};
use rustiron_executor::{
    Executor, ExecutorError, TrustAnchor, receipt::capture_receipt, receipt::recovery_receipt,
    serve,
};
use rustiron_journal::{
    Capture, CaptureState, Operation, ProbeState, Provision, ProvisionState, ReadoptState,
    Readoption, RecordedState,
};

const SOCKET: &str = rustiron_executor::layout::EXECUTOR_SOCKET;

fn anchor() -> TrustAnchor {
    TrustAnchor::host()
}

fn run() -> Result<(), ExecutorError> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["initialize"] => Executor::initialize(anchor()).map(drop),
        ["migrate"] => Executor::migrate(anchor()),
        ["seal-admission-mark"] => {
            let count = Executor::seal_admission_mark(anchor())?;
            println!("{}", serde_json::json!({ "admission_mark": count }));
            Ok(())
        }
        ["serve"] => {
            let mut executor = Executor::open(anchor())?;
            let listener = serve::bind(std::path::Path::new(SOCKET), 0)?;
            serve::serve(&mut executor, &listener)
        }
        ["serve", "--admin-helper"] => {
            let mut lab = anchor();
            lab.admin_socket = Some(PathBuf::from(rustiron_executor::admin_helper::LAB_SOCKET));
            let mut executor = Executor::open(lab)?;
            let listener = serve::bind(std::path::Path::new(SOCKET), 0)?;
            serve::serve(&mut executor, &listener)
        }
        ["reconcile", operation, "--admin-helper"] => {
            // Lab (W200): the OLS reload and probes go through the helper,
            // which accepts only a peer in the executor domain.
            let operation =
                Id::try_from(operation.to_owned()).map_err(|_| ExecutorError::InvalidRequest)?;
            let mut lab = anchor();
            lab.admin_socket = Some(PathBuf::from(rustiron_executor::admin_helper::LAB_SOCKET));
            let mut executor = Executor::open(lab)?;
            if executor.readoption_status(&operation)?.is_some() {
                println!(
                    "{}",
                    readopt_report(&executor.reconcile_readoption(&operation)?)
                );
                return Ok(());
            }
            print_operation(&executor.reconcile(&operation)?);
            Ok(())
        }
        ["readopt-status", operation] => {
            let operation =
                Id::try_from(operation.to_owned()).map_err(|_| ExecutorError::InvalidRequest)?;
            let row = Executor::open(anchor())?
                .readoption_status(&operation)?
                .ok_or(ExecutorError::NotAdmitted)?;
            println!("{}", readopt_report(&row));
            Ok(())
        }
        ["compensate", operation, "--admin-helper"] => {
            // W370: the single signed restore of an OLS operation through the
            // helper (reload, probes, and the page-cache removal of a
            // page-cache change); the executor domain runs none of them.
            let operation =
                Id::try_from(operation.to_owned()).map_err(|_| ExecutorError::InvalidRequest)?;
            let mut lab = anchor();
            lab.admin_socket = Some(PathBuf::from(rustiron_executor::admin_helper::LAB_SOCKET));
            print_operation(&Executor::open(lab)?.compensate(&operation, now())?);
            Ok(())
        }
        [command @ ("status" | "reconcile" | "compensate"), operation] => {
            let operation =
                Id::try_from(operation.to_owned()).map_err(|_| ExecutorError::InvalidRequest)?;
            let mut executor = Executor::open(anchor())?;
            if command == "reconcile" && executor.readoption_status(&operation)?.is_some() {
                println!(
                    "{}",
                    readopt_report(&executor.reconcile_readoption(&operation)?)
                );
                return Ok(());
            }
            let result = match command {
                "status" => executor
                    .status(&operation)?
                    .ok_or(ExecutorError::NotAdmitted)?,
                "reconcile" => executor.reconcile(&operation)?,
                _ => executor.compensate(&operation, now())?,
            };
            print_operation(&result);
            Ok(())
        }
        ["observe"] => {
            println!("{}", Executor::observe(&anchor())?);
            Ok(())
        }
        ["ols-boot-guard"] => {
            // W381 (D-032): one JSON line; a failed change exits 2.
            let report = Executor::ols_boot_guard(anchor());
            println!("{}", report.json());
            if report.failed() {
                return Err(ExecutorError::StepFailed);
            }
            Ok(())
        }
        ["ols-status", ref flags @ ..] if flags.is_empty() || flags == ["--admin-helper"] => {
            let mut lab = anchor();
            if !flags.is_empty() {
                // W202: the helper accepts only a peer in the executor domain.
                lab.admin_socket = Some(PathBuf::from(rustiron_executor::admin_helper::LAB_SOCKET));
            }
            let executor = Executor::open(lab)?;
            let (current, (id, digest), drift) = executor.ols_status()?;
            let established_by = executor.ols_established_by()?;
            // W355: with no `current` the generation shown is the bootstrap
            // predecessor a first config_activate plan must name.
            println!(
                "{}",
                serde_json::json!({
                    "current": current.as_ref().map(|(id, _)| id.as_str()),
                    "generation": id.as_str(),
                    "digest": digest.as_str(),
                    "content_addressed": drift.content_addressed,
                    "explained_by_journal": drift.explained,
                    "parent_reviewed": drift.parent_reviewed,
                    "webadmin_closed": drift.webadmin_closed,
                    "adopted_vhosts_pinned": drift.adopted_vhosts_pinned,
                    "page_cache_ols_tested": drift.page_cache_ols_tested,
                    "established_by": established_by,
                    "clean": drift.clean(),
                })
            );
            Ok(())
        }
        [
            command @ ("capture-status" | "capture-reconcile"),
            operation,
            ref flags @ ..,
        ] if flags.is_empty()
            || (command == "capture-reconcile" && flags == ["--settle-unclaimed"]) =>
        {
            let operation =
                Id::try_from(operation.to_owned()).map_err(|_| ExecutorError::InvalidRequest)?;
            let mut executor = Executor::open(anchor())?;
            let capture = if command == "capture-status" {
                executor
                    .capture_status(&operation)?
                    .ok_or(ExecutorError::NotAdmitted)?
            } else if flags.is_empty() {
                executor.reconcile_capture(&operation)?
            } else {
                // W366: settle a tagged snapshot as unclaimed; never success.
                executor.settle_capture_unclaimed(&operation)?
            };
            println!("{}", capture_report(&capture));
            Ok(())
        }
        // W518-F2 (D-084): an update's status, or the operator's reconcile of
        // an open update through the admin helper (executor service stopped).
        ["update-status", operation] => {
            let operation =
                Id::try_from(operation.to_owned()).map_err(|_| ExecutorError::InvalidRequest)?;
            let update = Executor::open(anchor())?
                .update_status(&operation)?
                .ok_or(ExecutorError::NotAdmitted)?;
            println!("{}", update_report(&update));
            Ok(())
        }
        ["update-reconcile", operation, "--admin-helper"] => {
            let operation =
                Id::try_from(operation.to_owned()).map_err(|_| ExecutorError::InvalidRequest)?;
            let mut lab = anchor();
            lab.admin_socket = Some(PathBuf::from(rustiron_executor::admin_helper::LAB_SOCKET));
            println!(
                "{}",
                update_report(&Executor::open(lab)?.reconcile_update(&operation)?)
            );
            Ok(())
        }
        // W530 (D-087): a site's installed versions, read only, through the
        // admin helper (executor service stopped).
        ["update-inventory", site, "--admin-helper"] => {
            let site = rustiron_contracts::approval::SiteId::try_from((*site).to_owned())
                .map_err(|_| ExecutorError::InvalidRequest)?;
            let mut lab = anchor();
            lab.admin_socket = Some(PathBuf::from(rustiron_executor::admin_helper::LAB_SOCKET));
            println!("{}", Executor::open(lab)?.update_inventory(&site)?);
            Ok(())
        }
        // W543 (D-089): a restore's status, or the operator's reconcile of
        // an open restore through the admin helper (executor service
        // stopped): the next attempt restores the signed capture again or
        // the safety capture.
        ["restore-status", operation] => {
            let operation =
                Id::try_from(operation.to_owned()).map_err(|_| ExecutorError::InvalidRequest)?;
            let restore = Executor::open(anchor())?
                .site_restore_status(&operation)?
                .ok_or(ExecutorError::NotAdmitted)?;
            println!("{}", restore_report(&restore));
            Ok(())
        }
        ["restore-reconcile", operation, from, "--admin-helper"] => {
            let operation =
                Id::try_from(operation.to_owned()).map_err(|_| ExecutorError::InvalidRequest)?;
            let from = match from {
                "signed" => rustiron_journal::RestoreFrom::Signed,
                "safety" => rustiron_journal::RestoreFrom::Safety,
                _ => return Err(ExecutorError::InvalidRequest),
            };
            let mut lab = anchor();
            lab.admin_socket = Some(PathBuf::from(rustiron_executor::admin_helper::LAB_SOCKET));
            let mut executor = Executor::open(lab)?;
            let outcome = executor.reconcile_restore(&operation, from);
            // The stored restore is printed after a failed step too.
            if let Some(restore) = executor.site_restore_status(&operation)? {
                println!("{}", restore_report(&restore));
            }
            outcome.map(drop)
        }
        // W563 (D-091): a zone import's status, or the operator's reconcile
        // of an import left open through the admin helper (executor service
        // stopped). The helper refuses before any effect when the zone is
        // already on the server, so a reconcile then records `failed`.
        ["dns-import-status", operation] => {
            let operation =
                Id::try_from(operation.to_owned()).map_err(|_| ExecutorError::InvalidRequest)?;
            let import = Executor::open(anchor())?
                .dns_import_status(&operation)?
                .ok_or(ExecutorError::NotAdmitted)?;
            println!("{}", dns_import_report(&import));
            Ok(())
        }
        ["dns-import-reconcile", operation, "--admin-helper"] => {
            let operation =
                Id::try_from(operation.to_owned()).map_err(|_| ExecutorError::InvalidRequest)?;
            let mut lab = anchor();
            lab.admin_socket = Some(PathBuf::from(rustiron_executor::admin_helper::LAB_SOCKET));
            let mut executor = Executor::open(lab)?;
            let outcome = executor.reconcile_dns_import(&operation);
            if let Some(import) = executor.dns_import_status(&operation)? {
                println!("{}", dns_import_report(&import));
            }
            outcome.map(drop)
        }
        // W565 (D-091): a record change's status, or the operator's
        // reconcile of a change left open through the admin helper (executor
        // service stopped): it settles `done` only when every set already is
        // the intended one or the change applies again over the sets read
        // before intent.
        ["dns-change-status", operation] => {
            let operation =
                Id::try_from(operation.to_owned()).map_err(|_| ExecutorError::InvalidRequest)?;
            let change = Executor::open(anchor())?
                .dns_change_status(&operation)?
                .ok_or(ExecutorError::NotAdmitted)?;
            println!("{}", dns_change_report(&change));
            Ok(())
        }
        ["dns-change-reconcile", operation, "--admin-helper"] => {
            let operation =
                Id::try_from(operation.to_owned()).map_err(|_| ExecutorError::InvalidRequest)?;
            let mut lab = anchor();
            lab.admin_socket = Some(PathBuf::from(rustiron_executor::admin_helper::LAB_SOCKET));
            let mut executor = Executor::open(lab)?;
            let outcome = executor.reconcile_dns_change(&operation);
            if let Some(change) = executor.dns_change_status(&operation)? {
                println!("{}", dns_change_report(&change));
            }
            outcome.map(drop)
        }
        // W535 (D-088): a quota change's status, or the operator's reconcile
        // of an open change through the admin helper (executor service
        // stopped).
        ["quota-status", operation] => {
            let operation =
                Id::try_from(operation.to_owned()).map_err(|_| ExecutorError::InvalidRequest)?;
            let change = Executor::open(anchor())?
                .quota_change_status(&operation)?
                .ok_or(ExecutorError::NotAdmitted)?;
            println!("{}", quota_change_report(&change));
            Ok(())
        }
        ["quota-reconcile", operation, "--admin-helper"] => {
            let operation =
                Id::try_from(operation.to_owned()).map_err(|_| ExecutorError::InvalidRequest)?;
            let mut lab = anchor();
            lab.admin_socket = Some(PathBuf::from(rustiron_executor::admin_helper::LAB_SOCKET));
            println!(
                "{}",
                quota_change_report(&Executor::open(lab)?.reconcile_quota_change(&operation)?)
            );
            Ok(())
        }
        // W609 (D-100): a credential rotation's status, or the operator's
        // reconcile of an unresolved (`intent` / `needs_attention`) rotation
        // through the admin helper (executor service stopped).
        ["credential-rotate-status", operation] => {
            let operation =
                Id::try_from(operation.to_owned()).map_err(|_| ExecutorError::InvalidRequest)?;
            let row = Executor::open(anchor())?
                .credential_rotation_status(&operation)?
                .ok_or(ExecutorError::NotAdmitted)?;
            println!("{}", credential_rotate_report(&row));
            Ok(())
        }
        [
            "credential-rotate-reconcile",
            operation,
            outcome,
            "--admin-helper",
        ] => {
            let operation =
                Id::try_from(operation.to_owned()).map_err(|_| ExecutorError::InvalidRequest)?;
            let outcome = match outcome {
                "done" => rustiron_journal::CredentialRotateState::Done,
                "failed_compensated" => rustiron_journal::CredentialRotateState::FailedCompensated,
                "failed" => rustiron_journal::CredentialRotateState::Failed,
                _ => return Err(ExecutorError::InvalidRequest),
            };
            let mut lab = anchor();
            lab.admin_socket = Some(PathBuf::from(rustiron_executor::admin_helper::LAB_SOCKET));
            println!(
                "{}",
                credential_rotate_report(
                    &Executor::open(lab)?.reconcile_credential_rotation(&operation, outcome)?
                )
            );
            Ok(())
        }
        // W522 (D-085): a deletion's status, or the operator's reconcile of
        // an open deletion through the admin helper (executor service
        // stopped).
        ["delete-status", operation] => {
            let operation =
                Id::try_from(operation.to_owned()).map_err(|_| ExecutorError::InvalidRequest)?;
            let deletion = Executor::open(anchor())?
                .deletion_status(&operation)?
                .ok_or(ExecutorError::NotAdmitted)?;
            println!("{}", deletion_report(&deletion));
            Ok(())
        }
        ["delete-reconcile", operation, "--admin-helper"] => {
            let operation =
                Id::try_from(operation.to_owned()).map_err(|_| ExecutorError::InvalidRequest)?;
            let mut lab = anchor();
            lab.admin_socket = Some(PathBuf::from(rustiron_executor::admin_helper::LAB_SOCKET));
            println!(
                "{}",
                deletion_report(&Executor::open(lab)?.reconcile_deletion(&operation)?)
            );
            Ok(())
        }
        [command @ ("probe-status" | "probe-cleanup"), operation] => {
            let operation =
                Id::try_from(operation.to_owned()).map_err(|_| ExecutorError::InvalidRequest)?;
            let mut executor = Executor::open(anchor())?;
            let probe = if command == "probe-status" {
                executor
                    .probe_status(&operation)?
                    .ok_or(ExecutorError::NotAdmitted)?
            } else {
                executor.cleanup_probe(&operation)?
            };
            let state = match probe.state {
                ProbeState::Running => "running",
                ProbeState::Passed => "passed",
                ProbeState::Failed => "failed",
                ProbeState::CleanupIncomplete => "cleanup_incomplete",
            };
            let receipt: serde_json::Value = probe
                .receipt
                .as_deref()
                .and_then(|text| serde_json::from_str(text).ok())
                .unwrap_or(serde_json::Value::Null);
            println!(
                "{}",
                serde_json::json!({
                    "operation_id": probe.intent.operation_id.as_str(),
                    "site_id": probe.intent.site_id.as_str(),
                    "probe_account": probe.intent.probe_account,
                    "state": state,
                    "receipt": receipt,
                })
            );
            Ok(())
        }
        ["receipt-export", operation] => {
            let operation =
                Id::try_from(operation.to_owned()).map_err(|_| ExecutorError::InvalidRequest)?;
            let executor = Executor::open(anchor())?;
            if let Some(probe) = executor.probe_status(&operation)? {
                let receipt: serde_json::Value = probe
                    .receipt
                    .as_deref()
                    .and_then(|text| serde_json::from_str(text).ok())
                    .ok_or(ExecutorError::NotAdmitted)?;
                let document = recovery_receipt(&probe, receipt)?;
                println!(
                    "{}",
                    rustiron_executor::receipt_key::sign(&anchor(), document)?
                );
                return Ok(());
            }
            let capture = executor
                .capture_status(&operation)?
                .ok_or(ExecutorError::NotAdmitted)?;
            let document = capture_receipt(&capture)?;
            println!(
                "{}",
                rustiron_executor::receipt_key::sign(&anchor(), document)?
            );
            Ok(())
        }
        ["export", site] => {
            let site =
                SiteId::try_from(site.to_owned()).map_err(|_| ExecutorError::InvalidRequest)?;
            println!("{}", Executor::open(anchor())?.export_site(&site)?);
            Ok(())
        }
        ["provision", site] => {
            let site =
                SiteId::try_from(site.to_owned()).map_err(|_| ExecutorError::InvalidRequest)?;
            let provision = Executor::open(anchor())?
                .provision_for_site(&site)?
                .ok_or(ExecutorError::NotAdmitted)?;
            println!("{}", provision_report(&provision));
            Ok(())
        }
        ["retire-quota", site] => {
            let site =
                SiteId::try_from(site.to_owned()).map_err(|_| ExecutorError::InvalidRequest)?;
            println!("{}", Executor::open(anchor())?.retire_site_quota(&site)?);
            Ok(())
        }
        // W550 (D-091): the `pdns.conf` that the enrolled `dns` section
        // renders, for review. Read only.
        ["dns-config"] => {
            print!("{}", rustiron_executor::dns_config(&anchor())?);
            Ok(())
        }
        ["quota-readiness"] => {
            let (report, ready) = rustiron_executor::quota::host_readiness();
            println!("{report}");
            if ready {
                Ok(())
            } else {
                Err(ExecutorError::QuotaUnavailable)
            }
        }
        // W462: settle an issuance left `intent` by a lost helper reply.
        ["fail-certificate", operation] => {
            let operation =
                Id::try_from(operation.to_owned()).map_err(|_| ExecutorError::InvalidRequest)?;
            let row = Executor::open(anchor())?.fail_certificate(&operation)?;
            println!(
                "{}",
                serde_json::json!({ "operation_id": row.intent.operation_id.as_str(), "state": "failed" })
            );
            Ok(())
        }
        ["quarantine-provision", operation] => {
            let operation =
                Id::try_from(operation.to_owned()).map_err(|_| ExecutorError::InvalidRequest)?;
            let provision = Executor::open(anchor())?.quarantine_provision(&operation)?;
            println!("{}", provision_report(&provision));
            Ok(())
        }
        _ => Err(ExecutorError::InvalidRequest),
    }
}

/// W518: one JSON line for `update-status` and `update-reconcile`.
fn update_report(update: &rustiron_journal::SiteUpdate) -> String {
    let step_state = |state: rustiron_journal::StepState| match state {
        rustiron_journal::StepState::Intent => "intent",
        rustiron_journal::StepState::Done => "done",
        rustiron_journal::StepState::Failed => "failed",
    };
    serde_json::json!({
        "operation_id": update.operation_id.as_str(),
        "site_id": update.site_id.as_str(),
        "state": match update.state {
            rustiron_journal::UpdateState::Intent => "intent",
            rustiron_journal::UpdateState::Done => "done",
            rustiron_journal::UpdateState::RolledBack => "rolled_back",
        },
        "steps": update.steps.iter().map(|record| serde_json::json!({
            "step": format!("{:?}", record.step).to_lowercase(),
            "state": step_state(record.state),
        })).collect::<Vec<_>>(),
        "rollback": update.rollback.map(step_state),
    })
    .to_string()
}

/// W543: one JSON line for `restore-status` and `restore-reconcile`.
fn restore_report(restore: &rustiron_journal::SiteRestore) -> String {
    let state = |state| match state {
        rustiron_journal::StepState::Intent => "intent",
        rustiron_journal::StepState::Done => "done",
        rustiron_journal::StepState::Failed => "failed",
    };
    serde_json::json!({
        "operation_id": restore.operation_id.as_str(),
        "site_id": restore.site_id.as_str(),
        "scope": restore.scope.as_str(),
        "capture_operation_id": restore.capture_operation_id.as_str(),
        "safety_capture_operation_id": restore.safety_capture_operation_id.as_str(),
        "attempts": restore.attempts.iter().map(|attempt| serde_json::json!({
            "from": attempt.from.as_str(),
            "state": state(attempt.state),
            "steps": attempt.steps.iter().map(|record| format!(
                "{}:{}", record.step.as_str(), state(record.state)
            )).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "state": match restore.state {
            rustiron_journal::RestoreState::Intent => "intent",
            rustiron_journal::RestoreState::Done => "done",
            rustiron_journal::RestoreState::Reverted => "reverted",
        },
    })
    .to_string()
}

/// W535: one JSON line for `quota-status` and `quota-reconcile`.
/// W563: one JSON line for `dns-import-status` and `dns-import-reconcile`.
fn dns_import_report(import: &rustiron_journal::DnsImport) -> String {
    serde_json::json!({
        "operation_id": import.operation_id.as_str(),
        "zone": import.zone.as_str(),
        "zone_sha256": import.zone_sha256.as_str(),
        "record_sets": import.record_sets,
        "state": match import.state {
            rustiron_journal::StepState::Intent => "intent",
            rustiron_journal::StepState::Done => "done",
            rustiron_journal::StepState::Failed => "failed",
        },
    })
    .to_string()
}

/// W565: one JSON line for `dns-change-status` and `dns-change-reconcile`.
fn dns_change_report(change: &rustiron_journal::DnsChange) -> String {
    let state = |state| match state {
        rustiron_journal::StepState::Intent => "intent",
        rustiron_journal::StepState::Done => "done",
        rustiron_journal::StepState::Failed => "failed",
    };
    serde_json::json!({
        "operation_id": change.operation_id.as_str(),
        "zone": change.zone.as_str(),
        "state": state(change.state),
        "sets": change.sets.iter().map(|set| serde_json::json!({
            "owner": set.owner,
            "type": set.kind.as_str(),
            "before": set.before,
            "after": set.after,
        })).collect::<Vec<_>>(),
    })
    .to_string()
}

fn quota_change_report(change: &rustiron_journal::QuotaChange) -> String {
    serde_json::json!({
        "operation_id": change.operation_id.as_str(),
        "site_id": change.site_id.as_str(),
        "block_hard_kib": change.block_hard_kib,
        "inode_hard": change.inode_hard,
        "state": match change.state {
            rustiron_journal::StepState::Intent => "intent",
            rustiron_journal::StepState::Done => "done",
            rustiron_journal::StepState::Failed => "failed",
        },
    })
    .to_string()
}

/// W609: one JSON line for `credential-rotate-status` and `credential-rotate-reconcile`.
fn credential_rotate_report(row: &rustiron_journal::CredentialRotation) -> String {
    serde_json::json!({
        "operation_id": row.operation_id.as_str(),
        "site_id": row.site_id.as_str(),
        "hostname": row.hostname.as_str(),
        "target": row.target.as_str(),
        "state": row.state.as_str(),
    })
    .to_string()
}

/// W522: one JSON line for `delete-status` and `delete-reconcile`.
fn deletion_report(deletion: &rustiron_journal::Deletion) -> String {
    serde_json::json!({
        "operation_id": deletion.operation_id.as_str(),
        "site_id": deletion.site_id.as_str(),
        "provision_operation_id": deletion.provision_operation_id.as_str(),
        "capture_operation_id": deletion.capture_operation_id.as_ref().map(rustiron_contracts::Id::as_str),
        "state": match deletion.state {
            rustiron_journal::StepState::Intent => "intent",
            rustiron_journal::StepState::Done => "done",
            rustiron_journal::StepState::Failed => "failed",
        },
    })
    .to_string()
}

/// One JSON line for `capture-status` and `capture-reconcile`.
fn capture_report(capture: &Capture) -> serde_json::Value {
    let state = match capture.state {
        CaptureState::Running => "running",
        CaptureState::Succeeded => "succeeded",
        CaptureState::Failed => "failed",
    };
    serde_json::json!({
        "operation_id": capture.intent.operation_id.as_str(),
        "site_id": capture.intent.site_id.as_str(),
        "state": state,
        "snapshot_id": capture.snapshot_id,
        "unclaimed_snapshot_id": capture.unclaimed_snapshot_id,
        "capture_method": capture.method.map(rustiron_journal::CaptureMethod::as_str),
        "retention_days": capture.retention_days,
        "started_at": capture.started_at.get(),
        "finished_at": capture.finished_at.map(rustiron_contracts::Timestamp::get),
        "manifest": capture.manifest.as_ref().map(|m| serde_json::json!({
            "sha256": m.sha256, "entries": m.entries,
            "regular_bytes": m.regular_bytes, "truncated": m.truncated})),
        "destination": "local-PC lab destination (not independent off-host)",
    })
}

/// One JSON line; resources are bounded executor-written descriptions.
fn provision_report(provision: &Provision) -> serde_json::Value {
    let state = match provision.state {
        ProvisionState::Running => "running",
        ProvisionState::Succeeded => "succeeded",
        ProvisionState::Quarantined => "quarantined",
        ProvisionState::Adopted => "adopted",
        ProvisionState::Deleted => "deleted",
    };
    let steps: Vec<_> = provision
        .steps
        .iter()
        .map(|step| {
            serde_json::json!({
                "step": format!("{:?}", step.step).to_lowercase(),
                "state": format!("{:?}", step.state).to_lowercase(),
                "resource": step.resource,
            })
        })
        .collect();
    serde_json::json!({
        "operation_id": provision.intent.operation_id.as_str(),
        "site_id": provision.intent.site_id.as_str(),
        "state": state,
        "steps": steps,
    })
}

/// One JSON line for `readopt-status` and the reconcile of a re-adoption.
fn readopt_report(row: &Readoption) -> serde_json::Value {
    let state = match row.state {
        ReadoptState::Verifying => "verifying",
        ReadoptState::Adopted => "adopted",
        ReadoptState::Refused => "refused",
    };
    let facts: serde_json::Value = row
        .facts
        .as_deref()
        .and_then(|text| serde_json::from_str(text).ok())
        .unwrap_or(serde_json::Value::Null);
    serde_json::json!({
        "operation_id": row.intent.operation_id.as_str(),
        "form": row.intent.form.as_str(),
        "site_id": row.intent.site.as_ref().map(|(site, _)| site.as_str()),
        "hostname": row.intent.site.as_ref().map(|(_, hostname)| hostname.as_str()),
        "state": state,
        "facts": facts,
        "refusal": row.refusal.as_ref().map(|(code, rule)| serde_json::json!({"code": code, "rule": rule})),
        "previous_epoch": row.intent.previous_epoch.as_str(),
        "evidence_sha256": row.intent.evidence_sha256.as_str(),
        "plan_sha256": row.intent.plan_digest.as_str(),
    })
}

fn now() -> Option<Timestamp> {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    Timestamp::try_from(seconds).ok()
}

fn print_operation(operation: &Operation) {
    let state = match operation.state {
        RecordedState::Intent => "intent",
        RecordedState::Succeeded => "succeeded",
        RecordedState::Untouched => "untouched",
        RecordedState::NeedsAttention => "needs_attention",
        RecordedState::Compensating => "compensating",
        RecordedState::FailedCompensated => "failed_compensated",
    };
    println!(
        "{{\"operation_id\":\"{}\",\"state\":\"{}\",\"effect_attempted\":{},\"compensation_attempted\":{}}}",
        operation.intent.operation_id.as_str(),
        state,
        operation.effect_attempted,
        operation.compensation_attempted
    );
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "{{\"scope\":\"s02_lab_executor\",\"error\":\"{}\"}}",
                error.code()
            );
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use rustiron_contracts::{
        Id, Timestamp,
        approval::{Sha256Digest, SiteId},
    };
    use rustiron_journal::{Capture, CaptureIntent, CaptureState};

    use super::{ExecutorError, capture_receipt};

    fn capture(state: CaptureState, snapshot: Option<&str>, finished: bool) -> Capture {
        let id = |text: &str| Id::try_from(text.to_owned()).unwrap();
        let digest = |byte: u8| Sha256Digest::try_from(format!("{byte:02x}").repeat(32)).unwrap();
        let time = |seconds: u64| Timestamp::try_from(seconds).unwrap();
        Capture {
            backup_policy_digest: None,
            intent: CaptureIntent {
                operation_id: id("cap_w050"),
                idempotency_key: id("cap_key_w050"),
                grant_id: id("cap_grant_w050"),
                nonce: id("cap_nonce_w050"),
                plan_digest: digest(0xab),
                grant_digest: digest(0xcd),
                host_id: id("host_fixture"),
                host_epoch: id("epoch_fixture"),
                site_id: SiteId::try_from("blog13".to_owned()).unwrap(),
                expires_at: time(2_000),
            },
            started_at: time(1_000),
            state,
            snapshot_id: snapshot.map(str::to_owned),
            finished_at: finished.then(|| time(1_300)),
            method: Some(rustiron_journal::CaptureMethod::SiteFilesDbV1),
            retention_days: Some(30),
            files: None,
            bytes: None,
            manifest: None,
            consistency: None,
            unclaimed_snapshot_id: None,
            retention_evidence: None,
            refusal: None,
        }
    }

    fn status(document: &serde_json::Value, field: &str) -> String {
        document["body"]["fields"][field]["status"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn checker(document: &serde_json::Value) -> std::process::Output {
        // W289: one file per call. Tests in this binary build identical
        // receipts concurrently; a shared name let one test remove the file
        // another was checking (1 of 40 runs failed).
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let call = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rustiron-receipt-{}-{call}.json",
            std::process::id()
        ));
        std::fs::File::create_new(&path)
            .and_then(|mut file| {
                std::io::Write::write_all(&mut file, document.to_string().as_bytes())
            })
            .unwrap();
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let output = std::process::Command::new("python3")
            .arg(root.join("scripts/check_receipt.py"))
            .arg(&path)
            .output()
            .expect("python3");
        std::fs::remove_file(path).ok();
        output
    }

    #[test]
    fn capture_receipts_and_site_ownership_facts_carry_no_secret_shape() {
        use rustiron_executor::redaction::secret_shapes;
        let snapshot = "ab".repeat(32);
        for (state, snapshot, finished) in [
            (CaptureState::Succeeded, Some(snapshot.as_str()), true),
            (CaptureState::Failed, None, true),
        ] {
            let text = capture_receipt(&capture(state, snapshot, finished))
                .unwrap()
                .to_string();
            assert!(
                secret_shapes(&text).is_empty(),
                "{:?}",
                secret_shapes(&text)
            );
        }
        let site = SiteId::try_from("blog13".to_owned()).unwrap();
        let layout = rustiron_executor::provision::SiteLayout::derive(&site);
        let facts = rustiron_executor::provision::ownership_facts(&layout).to_string();
        assert!(secret_shapes(&facts).is_empty(), "{facts}");
        // The check is live: a generated-secret-shaped value in a receipt field is caught.
        let mut planted = capture_receipt(&capture(CaptureState::Failed, None, true)).unwrap();
        planted["body"]["note"] = "0123456789abcdef".repeat(3).into();
        assert_eq!(
            secret_shapes(&planted.to_string()),
            ["generated_secret_hex48"]
        );
    }

    /// W391 (v18): a succeeded capture with stored evidence exports each
    /// object version, and a refused capture exports its code; both pass
    /// `check_receipt.py`, and a tampered version ID does not.
    #[test]
    fn stored_retention_evidence_and_a_refusal_code_export_checker_clean_receipts() {
        let snapshot = "ab".repeat(32);
        let mut succeeded = capture(CaptureState::Succeeded, Some(&snapshot), true);
        succeeded.retention_evidence = Some(rustiron_journal::RetentionEvidence {
            before_days: 30,
            after_days: 30,
            objects: vec![rustiron_journal::ObjectRetention {
                kind: rustiron_journal::RetainedObjectKind::Snapshot,
                object_id: snapshot,
                version_id: "76b01aea-db7c-4b38-b41d-3c031085d108".to_owned(),
                retain_until: 1_000 + 30 * 86_400,
            }],
        });
        let document = capture_receipt(&succeeded).unwrap();
        let retention = &document["body"]["retention"];
        assert_eq!(retention["status"], "recorded");
        assert_eq!(
            retention["objects"][0]["version_id"],
            "76b01aea-db7c-4b38-b41d-3c031085d108"
        );
        assert_eq!(document["body"].get("refusal"), None);
        let output = checker(&document);
        assert!(output.status.success(), "{output:?}");
        let mut tampered = document.clone();
        tampered["body"]["retention"]["objects"][0]["version_id"] = "null".into();
        assert!(!checker(&tampered).status.success());

        let mut refused = capture(CaptureState::Failed, None, true);
        refused.refusal = Some("RETENTION_LOCK_UNVERIFIED".to_owned());
        let document = capture_receipt(&refused).unwrap();
        assert_eq!(document["body"]["refusal"], "RETENTION_LOCK_UNVERIFIED");
        assert_eq!(document["body"]["retention"]["status"], "not_recorded");
        let output = checker(&document);
        assert!(output.status.success(), "{output:?}");
        // A row without v18 records carries no refusal key at all.
        let old = capture_receipt(&capture(CaptureState::Failed, None, true)).unwrap();
        assert_eq!(old["body"].get("refusal"), None);
    }

    #[test]
    fn a_succeeded_capture_exports_a_checker_clean_receipt_without_claiming_independence() {
        let snapshot = "ab".repeat(32);
        let document =
            capture_receipt(&capture(CaptureState::Succeeded, Some(&snapshot), true)).unwrap();
        assert_eq!(status(&document, "repository_integrity_checked"), "pass");
        assert_eq!(
            document["body"]["fields"]["repository_integrity_checked"]["observed_at"],
            1_300
        );
        assert!(
            document["body"]["fields"]["repository_integrity_checked"]["evidence_refs"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(status(&document, "artifacts_complete"), "unknown");
        assert_eq!(status(&document, "decryption_tested"), "not_run");
        assert_eq!(status(&document, "independent_copy_confirmed"), "unknown");
        assert_eq!(
            status(&document, "application_consistency_assessed"),
            "unknown"
        );
        assert_eq!(document["body"]["capture_method"], "site_files_db_v1");
        assert!(
            document["body"]["fields"]["application_consistency_assessed"]["scope"]
                .as_str()
                .unwrap()
                .contains("no shared freeze point")
        );
        assert_eq!(document["body"]["operation"]["verb"], "backup_capture");
        assert!(
            document["body"]["limitations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item.as_str().unwrap().contains("retention days"))
        );
        // W216: the measured order is stated, with the operator remedy.
        assert!(
            document["body"]["limitations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| {
                    let item = item.as_str().unwrap();
                    item.contains("database is dumped before the files are read")
                        && item.contains("without their database rows")
                        && item.contains("quiesce")
                })
        );
        assert_eq!(document["body"]["recorded_window_s"], 300);
        let output = checker(&document);
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let tampered = {
            let mut copy = document;
            copy["body"]["fields"]["independent_copy_confirmed"]["status"] = "pass".into();
            copy
        };
        let rejected = checker(&tampered);
        assert!(!rejected.status.success());
        assert!(String::from_utf8_lossy(&rejected.stdout).contains("body_sha256 does not match"));
    }

    #[test]
    fn each_capture_receipt_states_matched_or_unmatched_with_the_reason() {
        use rustiron_journal::{CaptureConsistency as C, UnmatchedReason as R};
        for (label, expected) in [
            (Some(C::Matched), ("matched", None)),
            (
                Some(C::Unmatched(R::DatabaseChanged)),
                ("unmatched", Some("database_changed")),
            ),
            (
                Some(C::Unmatched(R::MarkerUnavailable)),
                ("unmatched", Some("marker_unavailable")),
            ),
            // Recorded before v11, or without the check (D-021 default).
            (None, ("unmatched", Some("not_checked"))),
        ] {
            let mut row = capture(CaptureState::Succeeded, Some(&"ab".repeat(32)), true);
            row.consistency = label;
            let document = capture_receipt(&row).unwrap();
            let body = &document["body"]["consistency"];
            assert_eq!(body["label"], expected.0, "{label:?}");
            assert_eq!(body["reason"].as_str(), expected.1, "{label:?}");
            assert!(body["scope"].as_str().unwrap().contains("marker"));
            let scope = document["body"]["fields"]["application_consistency_assessed"]["scope"]
                .as_str()
                .unwrap();
            assert!(scope.contains(expected.0), "{scope}");
            // Not an aggregate verdict: the field status stays unknown.
            assert_eq!(
                status(&document, "application_consistency_assessed"),
                "unknown"
            );
            let output = checker(&document);
            assert!(
                output.status.success(),
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        // A failed capture claims nothing.
        let failed = capture_receipt(&capture(CaptureState::Failed, None, true)).unwrap();
        assert!(failed["body"]["consistency"].is_null());
    }

    #[test]
    fn legacy_capture_receipt_does_not_infer_a_method() {
        let mut legacy = capture(CaptureState::Succeeded, Some(&"ab".repeat(32)), true);
        legacy.method = None;
        let document = capture_receipt(&legacy).unwrap();
        assert!(document["body"]["capture_method"].is_null());
        assert_eq!(
            status(&document, "application_consistency_assessed"),
            "unknown"
        );
        assert!(
            document["body"]["fields"]["application_consistency_assessed"]["scope"]
                .as_str()
                .unwrap()
                .contains("not recorded")
        );
        assert!(checker(&document).status.success());
    }

    /// W374: the W371 product probe refusal exported `fields` and
    /// `limitations` as null, and the offline checker refused it. Each
    /// stored receipt of a probe that ran no check now exports a receipt
    /// the checker accepts, with no pass.
    #[test]
    fn a_probe_without_check_results_exports_a_checker_clean_receipt() {
        use rustiron_contracts::approval::SnapshotId;
        use rustiron_journal::{Probe, ProbeIntent, ProbeState};
        let id = |text: &str| Id::try_from(text.to_owned()).unwrap();
        let digest = |byte: u8| Sha256Digest::try_from(format!("{byte:02x}").repeat(32)).unwrap();
        let probe = |state| Probe {
            backup_policy_digest: Some(digest(0xee)),
            intent: ProbeIntent {
                operation_id: id("op_w374_probe"),
                idempotency_key: id("key_w374_probe"),
                grant_id: id("grant_w374_probe"),
                nonce: id("nonce_w374_probe"),
                plan_digest: digest(0xab),
                grant_digest: digest(0xcd),
                host_id: id("host_fixture"),
                host_epoch: id("epoch_fixture"),
                site_id: SiteId::try_from("w371a".to_owned()).unwrap(),
                snapshot_id: SnapshotId::try_from("54".repeat(32)).unwrap(),
                probe_account: "rp_a0e1b9".to_owned(),
                expires_at: Timestamp::try_from(2_000).unwrap(),
            },
            started_at: Timestamp::try_from(1_000).unwrap(),
            state,
            receipt: None,
            finished_at: Some(Timestamp::try_from(1_000).unwrap()),
        };
        // The stored receipt of op_w371_probe_1 (S10-W371/21-after-probe.log).
        let product = r#"{"cleanup":{"leftover_resources":0,"removal_failures":0,"status":"complete","unverified":[]},"note":"the admin helper refused before creating anything; no check is claimed","probe_account":"rp_a0e1b9","receipt_schema":"rustiron-restore-probe/2","refused":"NOT_ADMITTED_FOR_EFFECT"}"#;
        let lab = r#"{"receipt_schema":"rustiron-lab-restore-probe/1","probe_account":"rp_a0e1b9","refused":"PEER_DENIED","note":"the admin helper refused before creating anything; no check is claimed","cleanup":{"status":"complete","leftover_resources":0,"removal_failures":0,"unverified":[]}}"#;
        let cleanup = r#"{"receipt_schema":"rustiron-lab-restore-probe/1","probe_account":"rp_a0e1b9","admin_cleanup":true,"cleanup":{"leftover_resources":null,"status":"unknown","unverified":["passwd"],"removal_failures":0},"note":"probe interrupted or left resources; no check is claimed"}"#;
        for (stored, state, expected) in [
            (product, ProbeState::Failed, "not_run"),
            (lab, ProbeState::Failed, "not_run"),
            (cleanup, ProbeState::CleanupIncomplete, "unknown"),
            (cleanup, ProbeState::Failed, "unknown"),
        ] {
            let document =
                super::recovery_receipt(&probe(state), serde_json::from_str(stored).unwrap())
                    .unwrap();
            for field in [
                "artifacts_complete",
                "repository_integrity_checked",
                "decryption_tested",
                "application_consistency_assessed",
                "restored_in_isolation",
                "health_checks_passed",
                "independent_copy_confirmed",
            ] {
                assert_eq!(status(&document, field), expected, "{field} {stored}");
            }
            assert!(!limitations(&document).is_empty());
            let output = checker(&document);
            assert!(
                output.status.success(),
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn a_failed_or_unfinished_capture_does_not_claim_a_checked_snapshot() {
        let failed = capture_receipt(&capture(CaptureState::Failed, None, true)).unwrap();
        assert_eq!(status(&failed, "repository_integrity_checked"), "not_run");
        assert!(failed["body"]["snapshot_id"].is_null());
        assert!(checker(&failed).status.success());
        assert_eq!(
            capture_receipt(&capture(CaptureState::Running, None, false)).unwrap_err(),
            ExecutorError::NotAdmitted
        );
        assert_eq!(
            capture_receipt(&capture(CaptureState::Succeeded, None, true)).unwrap_err(),
            ExecutorError::Unavailable
        );
    }

    /// W366: a settled capture states its unclaimed snapshot and claims no
    /// complete, checked or retained capture. The offline checker accepts
    /// it and refuses an unclaimed snapshot beside a success claim.
    #[test]
    fn a_settled_capture_receipt_keeps_the_snapshot_unclaimed() {
        let snapshot = "a5".repeat(32);
        let mut row = capture(CaptureState::Failed, None, true);
        row.unclaimed_snapshot_id = Some(snapshot.clone());
        let document = capture_receipt(&row).unwrap();
        let body = &document["body"];
        assert_eq!(body["operation"]["state"], "failed");
        assert!(body["snapshot_id"].is_null());
        assert_eq!(body["unclaimed_snapshot"]["snapshot_id"], snapshot.as_str());
        assert_eq!(body["unclaimed_snapshot"]["claimed"], false);
        assert!(body["consistency"].is_null());
        assert!(body["manifest"].is_null());
        assert_eq!(status(&document, "artifacts_complete"), "unknown");
        assert_eq!(status(&document, "repository_integrity_checked"), "not_run");
        assert_eq!(status(&document, "restored_in_isolation"), "not_run");
        assert!(
            limitations(&document)
                .iter()
                .any(|line| line.contains("unclaimed") && line.contains("not a backup of record"))
        );
        assert!(checker(&document).status.success());
        // A plain failed receipt names no unclaimed snapshot.
        let plain = capture_receipt(&capture(CaptureState::Failed, None, true)).unwrap();
        assert!(plain["body"].get("unclaimed_snapshot").is_none());
        // An unclaimed snapshot beside a success claim is refused offline.
        let mut forged = document.clone();
        forged["body"]["operation"]["state"] = "succeeded".into();
        forged["body"]["snapshot_id"] = snapshot.into();
        let canonical = serde_json::to_vec(&forged["body"]).unwrap();
        forged["body_sha256"] = sha256_hex(&canonical).into();
        let output = checker(&forged);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("unclaimed_snapshot"));
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::Digest;
        sha2::Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn limitations(document: &serde_json::Value) -> Vec<String> {
        document["body"]["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|line| line.as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn a_succeeded_capture_receipt_carries_its_manifest_and_no_independent_copy() {
        // W356: snapshot ID, label, enrolled retention days and manifest.
        let snapshot = "ab".repeat(32);
        let mut row = capture(CaptureState::Succeeded, Some(&snapshot), true);
        row.files = Some(3);
        row.bytes = Some(9);
        row.consistency = Some(rustiron_journal::CaptureConsistency::Matched);
        row.manifest = Some(rustiron_journal::CaptureManifest {
            sha256: "cd".repeat(32),
            entries: 4,
            regular_bytes: 9,
            truncated: false,
        });
        let document = capture_receipt(&row).unwrap();
        let body = &document["body"];
        assert_eq!(body["snapshot_id"], snapshot.as_str());
        assert_eq!(body["consistency"]["label"], "matched");
        assert_eq!(
            body["manifest"],
            serde_json::json!({"sha256": "cd".repeat(32), "entries": 4, "regular_bytes": 9, "truncated": false})
        );
        assert_eq!(body["retention"]["days"], 30);
        assert_eq!(body["retention"]["status"], "not_recorded");
        assert!(
            !limitations(&document)
                .iter()
                .any(|line| line.contains("operator recovery"))
        );
        assert!(checker(&document).status.success());

        // Recovery records no counts and no manifest, and says so.
        let recovered = capture(CaptureState::Succeeded, Some(&snapshot), true);
        let document = capture_receipt(&recovered).unwrap();
        assert_eq!(document["body"]["manifest"]["recorded"], false);
        assert_eq!(document["body"]["retention"]["status"], "not_recorded");
        assert!(
            limitations(&document)
                .iter()
                .any(|line| line.contains("operator recovery"))
        );
        assert!(checker(&document).status.success());

        // No capture receipt claims an independent copy (D-026).
        for row in [row, recovered, capture(CaptureState::Failed, None, true)] {
            let document = capture_receipt(&row).unwrap();
            assert_ne!(status(&document, "independent_copy_confirmed"), "pass");
            assert!(!document.to_string().contains("\"independent_copy\":true"));
        }
        let failed = capture_receipt(&capture(CaptureState::Failed, None, true)).unwrap();
        assert!(failed["body"]["manifest"].is_null());
    }
}
