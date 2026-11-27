//! Wire contract for the proposed one-shot administration helper (W171).
//!
//! The steady executor asks the helper for one fixed step of one journaled
//! operation. The request carries only the operation id and the step name.
//! The helper rereads the durable intent and derives every path, account,
//! context and unit from it; nothing else crosses this boundary.
//! [`authorize`] decides, [`handle`] serves one connection, and [`request`]
//! is the executor's client. Every provision step is routed as
//! `provision_step` (W173); a whole capture as `capture_run` and a whole
//! restore probe, with its cleanup, as `probe_run` (W174). Capture and probe
//! replies carry the bounded result the executor journals.

use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    time::Duration,
};

use rustiron_contracts::Id;
use rustiron_journal::{
    Capture, CaptureState, FixtureJournal, Operation, OperationRecords, Probe, ProbeState,
    Provision, ProvisionState, ProvisionStep, ReadoptState, Readoption, RecordedState, StepState,
};

use crate::{ExecutorError, TrustAnchor, durable, provision, provision::SiteLayout, restore};

/// Lab helper socket, bound by `rustiron-admin-helper`.
pub const LAB_SOCKET: &str = crate::layout::ADMIN_SOCKET;
const TIMEOUT: Duration = Duration::from_secs(120);

mod boot_restore;
mod wire;

pub use boot_restore::{BootRestoreOutcome, boot_restore_ejected_php};
pub use wire::{
    AdminRequest, AdminStep, MAX_ADMIN_REPLY_BYTES, MAX_ADMIN_REQUEST_BYTES, OLS_STATUS_REQUEST,
    ReplyLine, decode_reply, decode_site_root, is_ols_status, site_root_request,
};

fn installed_chain<'a>(
    records: &'a OperationRecords,
    site: &rustiron_contracts::approval::SiteId,
) -> Option<&'a rustiron_contracts::approval::Sha256Digest> {
    records
        .certificates
        .iter()
        .find_map(|(candidate, digest)| (site == candidate).then_some(digest))
}

fn verify_alias_tls(
    policy: &crate::policy::OlsPolicy,
    include: &std::os::fd::OwnedFd,
    generation: &Id,
    sites: &[crate::ols::ServedSite],
    pairs: &[(
        rustiron_contracts::approval::SiteId,
        rustiron_contracts::approval::Hostname,
        rustiron_contracts::approval::Sha256Digest,
    )],
    restoring: bool,
    ejecting: Option<&rustiron_contracts::approval::SiteId>,
) -> Result<(), ExecutorError> {
    if pairs.is_empty() {
        return Ok(());
    }
    let config = crate::ols::stored_generation(include, generation)?;
    for (site, alias, sha) in pairs {
        let account = SiteLayout::derive(site).account;
        let Some(served) = sites.iter().find(|served| served.account == account) else {
            continue;
        };
        if served.alias_hostname.as_ref() != Some(alias) {
            return Err(ExecutorError::PreconditionChanged);
        }
        if !crate::ols::maps_alias_pair(&config, &account, &served.hostname, alias, true) {
            // A first TLS activation may restore the verified HTTP-only generation.
            if restoring && !served.ejected && ejecting != Some(site) {
                continue;
            }
            return Err(ExecutorError::PreconditionChanged);
        }
        let listener = policy
            .tls_address
            .as_deref()
            .ok_or(ExecutorError::Unavailable)?;
        crate::certificate::verify_pair_leaf(listener, &account, &served.hostname, alias, sha)?;
    }
    Ok(())
}

/// D-097: validates the journaled single-name static ejection's binding
/// against the live predecessor generation and any installed single-name
/// leaf before the switch. Refusal leaves the operation `untouched`.
fn preflight_static_ejection(
    policy: &crate::policy::OlsPolicy,
    intent: &rustiron_journal::Intent,
    records: &OperationRecords,
) -> Result<(), ExecutorError> {
    let Some(hostname) = records.static_ejection.as_ref() else {
        return Ok(());
    };
    let site = records
        .ejection
        .as_ref()
        .ok_or(ExecutorError::BindingDenied)?;
    let provision = records
        .served
        .iter()
        .find(|provision| &provision.intent.site_id == site)
        .ok_or(ExecutorError::BindingDenied)?;
    if &provision.intent.hostname != hostname
        || records.served_aliases.contains_key(site.as_str())
        || records.served_proxies.contains_key(site.as_str())
        || records
            .certificate_pairs
            .iter()
            .any(|(candidate, _, _)| candidate == site)
    {
        return Err(ExecutorError::BindingDenied);
    }
    let account = SiteLayout::derive(site).account;
    let installed = installed_chain(records, site);
    let include = crate::ols::open_include()?;
    let (live, digest) = crate::ols::observe(&include)?;
    if live != intent.predecessor_generation || digest != intent.predecessor_digest {
        return Err(ExecutorError::PreconditionChanged);
    }
    let config = crate::ols::stored_generation(&include, &live)?;
    if !crate::ols::single_static_maps_ok(&config, &account, hostname, installed.is_some())
        || !crate::ols::single_static_vhost_ok(&config, &account, installed.is_some(), false)
    {
        return Err(ExecutorError::PreconditionChanged);
    }
    if let Some(sha) = installed {
        let listener = policy
            .tls_address
            .as_deref()
            .ok_or(ExecutorError::Unavailable)?;
        crate::certificate::verify_single_leaf(listener, &account, hostname, sha)?;
    } else if !matches!(
        std::fs::symlink_metadata(crate::ols::tls_live(&account)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    ) {
        return Err(ExecutorError::Drift);
    }
    Ok(())
}

/// D-097: verifies the single-name static ejection's target generation (or
/// restored managed predecessor during compensation/reconcile), its exact
/// listener maps, standalone vhost bytes, and any installed single-name leaf.
fn verify_static_ejection(
    policy: &crate::policy::OlsPolicy,
    include: &std::os::fd::OwnedFd,
    generation: &Id,
    records: &OperationRecords,
    restoring: bool,
) -> Result<(), ExecutorError> {
    let Some(hostname) = records.static_ejection.as_ref() else {
        return Ok(());
    };
    let site = records
        .ejection
        .as_ref()
        .ok_or(ExecutorError::BindingDenied)?;
    let provision = records
        .served
        .iter()
        .find(|provision| &provision.intent.site_id == site)
        .ok_or(ExecutorError::BindingDenied)?;
    if &provision.intent.hostname != hostname
        || records.served_aliases.contains_key(site.as_str())
        || records.served_proxies.contains_key(site.as_str())
        || records
            .certificate_pairs
            .iter()
            .any(|(candidate, _, _)| candidate == site)
    {
        return Err(ExecutorError::BindingDenied);
    }
    let account = SiteLayout::derive(site).account;
    let installed = installed_chain(records, site);
    let config = crate::ols::stored_generation(include, generation)?;
    if !crate::ols::single_static_maps_ok(&config, &account, hostname, installed.is_some())
        || !crate::ols::single_static_vhost_ok(&config, &account, installed.is_some(), !restoring)
    {
        return Err(ExecutorError::PreconditionChanged);
    }
    if !restoring {
        let expected_vhost = crate::ols::ejected_single_static_vhost(
            &account,
            hostname.as_str(),
            installed.is_some(),
        );
        let expected_digest = rustiron_contracts::approval::Sha256Digest::from_bytes(
            <sha2::Sha256 as sha2::Digest>::digest(expected_vhost.as_bytes()).into(),
        );
        if crate::ols::ejected_digest(&account).as_ref() != Some(&expected_digest) {
            return Err(ExecutorError::Drift);
        }
    }
    if let Some(sha) = installed {
        let listener = policy
            .tls_address
            .as_deref()
            .ok_or(ExecutorError::Unavailable)?;
        crate::certificate::verify_single_leaf(listener, &account, hostname, sha)?;
        crate::ols::probe_identity_tls(listener, &account, hostname)?;
    } else {
        if !matches!(
            std::fs::symlink_metadata(crate::ols::tls_live(&account)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        ) {
            return Err(ExecutorError::Drift);
        }
        crate::ols::probe_identity(&policy.address, &account, hostname)?;
    }
    Ok(())
}

/// The catalogue verbs whose steps the helper runs, as recorded in the
/// journal intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verb {
    /// `site_provision`.
    SiteProvision,
    /// `config_activate`.
    ConfigActivate,
    /// `backup_capture`.
    BackupCapture,
    /// `restore_probe`.
    RestoreProbe,
    /// `site_eject`.
    SiteEject,
    /// `site_readopt` (W372): only the read-only observation.
    SiteReadopt,
    /// `certificate_issue` (W462): only its one issuance step.
    CertificateIssue,
    /// `site_update` (W516): its open step or its open rollback.
    SiteUpdate,
    /// `site_restore` (W543): the open step of its open attempt.
    SiteRestore,
    /// `dns_zone_import` (W563): its one import step; once done, the read
    /// of the zone it owns (W565).
    DnsZoneImport,
    /// `dns_change` (W565): its one change step.
    DnsChange,
    /// `app_deploy` (W598, D-099): its open release step.
    AppDeploy,
    /// `app_lifecycle` (W598, D-099): its one unit action.
    AppLifecycle,
    /// `site_credential_rotate` (W609, D-100): MariaDB password rotation & verify.
    SiteCredentialRotate,
}

/// Whether an operation of `verb` may ever request `step`: one step per
/// provision, probe and capture; activation and eject only the OLS
/// observation, test, reload and verify steps (W200), and the bootstrap
/// start and stop (W355).
pub fn step_allowed(verb: Verb, step: AdminStep) -> bool {
    use AdminStep as S;
    match verb {
        // W457 (D-057): an import provision's scrub runs under it.
        // W501 (D-078): a clone provision's scrub runs under it.
        Verb::SiteProvision => {
            matches!(
                step,
                S::ProvisionStep
                    | S::ImportScrub
                    | S::CloneScrub
                    | S::SiteRetire
                    | S::SiteDelete
                    | S::UpdateInventory
                    | S::SiteQuotaSet
            )
        }
        Verb::RestoreProbe => step == S::ProbeRun,
        Verb::BackupCapture => step == S::CaptureRun,
        Verb::SiteReadopt => step == S::ReadoptObserve,
        // W464: an issuance's own step, or a renewal under its grant; the
        // record decides which (`Record::Certificate` or `Record::Renewal`).
        Verb::CertificateIssue => matches!(step, S::CertificateIssue | S::CertificateRenew),
        Verb::SiteUpdate => matches!(step, S::UpdateStep | S::UpdateRollback),
        Verb::SiteRestore => step == S::RestoreStep,
        Verb::DnsZoneImport => matches!(step, S::DnsImport | S::DnsZoneRead),
        Verb::DnsChange => step == S::DnsChange,
        Verb::AppDeploy => matches!(step, S::AppDeployStep | S::AppCaddyActivate),
        Verb::AppLifecycle => step == S::AppLifecycle,
        Verb::SiteCredentialRotate => {
            matches!(step, S::SiteCredentialRotate | S::SiteCredentialVerify)
        }
        Verb::ConfigActivate => ols_step(step),
        // W387 (D-037): only an ejection stops or restores its site's PHP.
        Verb::SiteEject => ols_step(step) || matches!(step, S::EjectPhpStop | S::EjectPhpRestore),
    }
}

/// The steps that every OLS operation, activation or ejection, may ask for.
fn ols_step(step: AdminStep) -> bool {
    use AdminStep as S;
    matches!(
        step,
        S::OlsPreflight
            | S::OlsConfigTest
            | S::OlsReload
            | S::OlsVerify
            | S::OlsStart
            | S::OlsStop
            | S::PageCacheInstall
            | S::PageCacheRemove
            | S::OlsBootstrapConfirm
    )
}

impl AdminRequest {
    /// [`AdminRequest::decode`], with anything else an `InvalidRequest`.
    pub fn parse(bytes: &[u8]) -> Result<Self, ExecutorError> {
        Self::decode(bytes).ok_or(ExecutorError::InvalidRequest)
    }
}

/// How often and how far apart [`reach`] looks for the helper socket: up
/// to 10 s for a helper that is starting or restarting.
pub const REACH_ATTEMPTS: u32 = 50;
/// See [`REACH_ATTEMPTS`].
pub const REACH_PAUSE: Duration = Duration::from_millis(200);

/// Asks the helper for the read-only server checks (W202). W361: the helper
/// unit is `Type=simple`, so a status run right after `systemctl start`
/// waits for the socket first.
pub fn ols_status(socket: &Path) -> Result<crate::ols::ServerChecks, ExecutorError> {
    reach(socket, REACH_ATTEMPTS, REACH_PAUSE)?;
    let wait = TIMEOUT;
    let mut stream = UnixStream::connect(socket).map_err(|_| ExecutorError::Unavailable)?;
    stream
        .set_read_timeout(Some(wait))
        .and_then(|()| stream.set_write_timeout(Some(wait)))
        .and_then(|()| stream.write_all(OLS_STATUS_REQUEST))
        .and_then(|()| stream.shutdown(std::net::Shutdown::Write))
        .map_err(|_| ExecutorError::Unavailable)?;
    let mut reply = String::new();
    std::io::Read::take(&mut stream, 1024)
        .read_to_string(&mut reply)
        .map_err(|_| ExecutorError::Unavailable)?;
    match parse_reply(&reply)? {
        Reply::Done(Some(payload)) => {
            crate::ols::ServerChecks::decode(&payload).ok_or(ExecutorError::Unavailable)
        }
        Reply::Done(None) => Err(ExecutorError::Unavailable),
        Reply::Refused(error) => Err(error),
    }
}

/// W372: asks the helper whether the derived site root exists, before a
/// provision's intent. Only `ok absent` is absent; anything else counts as
/// present, and an unreachable helper is an error.
pub fn site_root_present(
    socket: &Path,
    site: &rustiron_contracts::approval::SiteId,
) -> Result<bool, ExecutorError> {
    reach(socket, REACH_ATTEMPTS, REACH_PAUSE)?;
    let mut stream = UnixStream::connect(socket).map_err(|_| ExecutorError::HelperUnreachable)?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(TIMEOUT)))
        .and_then(|()| stream.write_all(&site_root_request(site)))
        .and_then(|()| stream.shutdown(std::net::Shutdown::Write))
        .map_err(|_| ExecutorError::Unavailable)?;
    let mut reply = String::new();
    std::io::Read::take(&mut stream, 1024)
        .read_to_string(&mut reply)
        .map_err(|_| ExecutorError::Unavailable)?;
    match parse_reply(&reply)? {
        Reply::Done(Some(payload)) => Ok(payload != "absent"),
        Reply::Done(None) => Ok(true),
        Reply::Refused(error) => Err(error),
    }
}

/// The journal record a request names, as the helper reread it.
#[derive(Clone, Copy, Debug)]
pub enum Record<'a> {
    /// A site provision.
    Provision(&'a Provision),
    /// A restore probe.
    Probe(&'a Probe),
    /// A backup capture.
    Capture(&'a Capture),
    /// An OLS activation (W200).
    Ols(&'a Operation),
    /// An OLS operation that ejects the site, from its ejection row (W387).
    Ejection(&'a Operation, &'a rustiron_contracts::approval::SiteId),
    /// A re-adoption (W372).
    Readoption(&'a Readoption),
    /// A certificate issuance (W462).
    Certificate(&'a rustiron_journal::Certificate),
    /// A certificate renewal under its issuance's grant (W464).
    Renewal(&'a rustiron_journal::Renewal),
    /// A WordPress update (W516, D-084).
    Update(&'a rustiron_journal::SiteUpdate),
    /// A restore of a live site (W543, D-089).
    Restore(&'a rustiron_journal::SiteRestore),
    /// A zone import (W563, D-091).
    DnsImport(&'a rustiron_journal::DnsImport),
    /// A record change with its checked signed plan bytes (W565, D-091).
    DnsChange(&'a rustiron_journal::DnsChange, &'a [u8]),
    /// A modern app release deployment (W598, D-099).
    AppRelease(&'a rustiron_journal::AppRelease),
    /// A modern app lifecycle action (W598, D-099).
    AppLifecycle(&'a rustiron_journal::AppLifecycle),
    /// A per-site credential rotation (W609, D-100).
    CredentialRotation(&'a rustiron_journal::CredentialRotation),
}

/// One authorized step with every target derived from the journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminAction {
    /// The step to run.
    pub step: AdminStep,
    /// Site or probe account the step acts on.
    pub account: String,
    /// Owned root the step acts on.
    pub root: PathBuf,
}

/// Decides one request from the peer and the reread journal record.
///
/// The peer must be the enrolled executor UID. The record must belong to the
/// request, its verb must allow the step, and the step must match the
/// journal's current unfinished work:
/// - provision: only `provision_step`, while the last step is `Intent`;
/// - probe: only `probe_run` while `Running`;
/// - capture: only `capture_run` while `Running`.
///
/// Probe and capture keep no per-step rows; the helper also refuses a second
/// run of one operation for its own lifetime (see [`Helper`]).
pub fn authorize(
    peer_uid: u32,
    executor_uid: u32,
    request: &AdminRequest,
    record: Record<'_>,
) -> Result<AdminAction, ExecutorError> {
    if peer_uid != executor_uid {
        return Err(ExecutorError::PeerDenied);
    }
    let denied = ExecutorError::BindingDenied;
    let step = request.step;
    let (operation_id, verb, current, account, root) = match record {
        Record::Provision(provision) => {
            let layout = SiteLayout::derive(&provision.intent.site_id);
            // W457: a scrub runs only on an ended provision; the open scrub
            // itself is checked against the import when it runs (W459).
            let current = if step == AdminStep::SiteRetire {
                provision.state == ProvisionState::Quarantined
            } else if step == AdminStep::SiteDelete {
                // W522 (D-085): the journal marked the site deleted.
                provision.state == ProvisionState::Deleted
            } else if matches!(step, AdminStep::UpdateInventory | AdminStep::SiteQuotaSet) {
                // W530 (D-087): any site the journal owns; read only.
                // W535 (D-088): its open quota change is checked when the
                // step runs.
                provision.state.is_owned()
            } else if matches!(step, AdminStep::ImportScrub | AdminStep::CloneScrub) {
                matches!(
                    provision.state,
                    ProvisionState::Quarantined | ProvisionState::Succeeded
                )
            } else {
                provision.state == ProvisionState::Running
                    && provision
                        .steps
                        .last()
                        .is_some_and(|last| last.state == StepState::Intent)
            };
            (
                &provision.intent.operation_id,
                Verb::SiteProvision,
                current,
                layout.account,
                layout.root,
            )
        }
        Record::Probe(probe) => {
            let account = probe.intent.probe_account.clone();
            let current = probe.state == ProbeState::Running;
            let root = Path::new(restore::BASE).join(&account);
            (
                &probe.intent.operation_id,
                Verb::RestoreProbe,
                current,
                account,
                root,
            )
        }
        Record::Capture(capture) => {
            let layout = SiteLayout::derive(&capture.intent.site_id);
            let current = capture.state == CaptureState::Running;
            (
                &capture.intent.operation_id,
                Verb::BackupCapture,
                current,
                layout.account,
                layout.root,
            )
        }
        Record::Ols(operation) => (
            &operation.intent.operation_id,
            Verb::ConfigActivate,
            ols_step_current(operation, step),
            operation.intent.resource_id.as_str().to_owned(),
            PathBuf::from(crate::ols::INCLUDE_DIR),
        ),
        Record::Ejection(operation, _) => (
            &operation.intent.operation_id,
            Verb::SiteEject,
            ols_step_current(operation, step),
            operation.intent.resource_id.as_str().to_owned(),
            PathBuf::from(crate::ols::INCLUDE_DIR),
        ),
        // W372: only while the re-adoption is `verifying`; a settled one
        // is never observed again.
        Record::Readoption(row) => {
            let current = row.state == ReadoptState::Verifying;
            let (account, root) = match &row.intent.site {
                Some((site, _)) => {
                    let layout = SiteLayout::derive(site);
                    (layout.account, layout.root)
                }
                None => (
                    "ols_lab_listener".to_owned(),
                    PathBuf::from(crate::ols::INCLUDE_DIR),
                ),
            };
            (
                &row.intent.operation_id,
                Verb::SiteReadopt,
                current,
                account,
                root,
            )
        }
        // W464: only while the renewal is open.
        Record::Renewal(row) => {
            let layout = SiteLayout::derive(&row.target.site_id);
            (
                &row.renewal_id,
                Verb::CertificateIssue,
                row.state == rustiron_journal::CertificateState::Intent,
                layout.account,
                layout.root,
            )
        }
        // W516: the step only while the journal's last step is open and no
        // rollback began; the rollback only while it is open.
        Record::Update(row) => {
            let layout = SiteLayout::derive(&row.site_id);
            let open = row.state == rustiron_journal::UpdateState::Intent;
            let current = match step {
                AdminStep::UpdateStep => {
                    open && row.rollback.is_none()
                        && row
                            .steps
                            .last()
                            .is_some_and(|last| last.state == StepState::Intent)
                }
                AdminStep::UpdateRollback => open && row.rollback == Some(StepState::Intent),
                _ => false,
            };
            (
                &row.operation_id,
                Verb::SiteUpdate,
                current,
                layout.account,
                layout.root,
            )
        }
        // W543: only the open step of the restore's open attempt.
        Record::Restore(row) => {
            let layout = SiteLayout::derive(&row.site_id);
            let current = row.state == rustiron_journal::RestoreState::Intent
                && row.current().is_some_and(|attempt| {
                    attempt.state == StepState::Intent
                        && attempt
                            .steps
                            .last()
                            .is_some_and(|last| last.state == StepState::Intent)
                });
            (
                &row.operation_id,
                Verb::SiteRestore,
                current,
                layout.account,
                layout.root,
            )
        }
        // W563: only while the import is open. It acts on PowerDNS's own
        // database as the `pdns` user, never on a site.
        // W565: the read of the zone only once the import is done.
        Record::DnsImport(row) => (
            &row.operation_id,
            Verb::DnsZoneImport,
            match step {
                AdminStep::DnsZoneRead => row.state == StepState::Done,
                _ => row.state == StepState::Intent,
            },
            crate::dns::PDNS_USER.to_owned(),
            PathBuf::from(crate::dns::PDNS_STATE_DIR),
        ),
        // W565: only while the change is open.
        Record::DnsChange(row, _) => (
            &row.operation_id,
            Verb::DnsChange,
            row.state == StepState::Intent,
            crate::dns::PDNS_USER.to_owned(),
            PathBuf::from(crate::dns::PDNS_STATE_DIR),
        ),
        // W598 (D-099) & W659 (D-102): `AppDeployStep` while its last step is
        // open; `AppCaddyActivate` while the release is open and `Health` is done.
        Record::AppRelease(row) => {
            let layout = SiteLayout::derive(&row.site_id);
            let current = match step {
                AdminStep::AppDeployStep => {
                    row.state == rustiron_journal::AppReleaseState::Intent
                        && row
                            .steps
                            .last()
                            .is_some_and(|last| last.state == StepState::Intent)
                }
                AdminStep::AppCaddyActivate => {
                    row.state == rustiron_journal::AppReleaseState::Intent
                        && row.steps.iter().any(|s| {
                            s.step == rustiron_journal::AppReleaseStep::Health
                                && s.state == StepState::Done
                        })
                }
                _ => false,
            };
            (
                &row.operation_id,
                Verb::AppDeploy,
                current,
                layout.account,
                layout.root,
            )
        }
        // W598 (D-099): only while the lifecycle operation is open.
        Record::AppLifecycle(row) => {
            let layout = SiteLayout::derive(&row.site_id);
            (
                &row.operation_id,
                Verb::AppLifecycle,
                row.state == StepState::Intent,
                layout.account,
                layout.root,
            )
        }
        // W609 (D-100): rotation runs only in `intent`; read-only verify runs
        // while `intent` or `needs_attention` (for operator reconciliation).
        Record::CredentialRotation(row) => {
            let layout = SiteLayout::derive(&row.site_id);
            let current = match step {
                AdminStep::SiteCredentialRotate => {
                    row.state == rustiron_journal::CredentialRotateState::Intent
                }
                AdminStep::SiteCredentialVerify => row.state.is_open(),
                _ => false,
            };
            (
                &row.operation_id,
                Verb::SiteCredentialRotate,
                current,
                layout.account,
                layout.root,
            )
        }
        // W462: only while the issuance is open.
        Record::Certificate(row) => {
            let layout = SiteLayout::derive(&row.intent.site_id);
            (
                &row.intent.operation_id,
                Verb::CertificateIssue,
                row.state == rustiron_journal::CertificateState::Intent,
                layout.account,
                layout.root,
            )
        }
    };
    if operation_id != &request.operation_id || !step_allowed(verb, step) || !current {
        return Err(denied);
    }
    Ok(AdminAction {
        step,
        account,
        root,
    })
}

/// Whether the journal state of an OLS operation is the one `step` belongs
/// to: the preflight only before the effect mark; the config test only
/// after it; reload and verify after it, during the one compensation, or for
/// the reconcile of an attempted operation left `needs_attention` (both then
/// only on the predecessor, checked when the step runs).
///
/// W355: an operation whose journaled predecessor is the bootstrap
/// generation never reloads. It may start after the effect mark, verify only
/// its target, and stop only during its one compensation. No other
/// operation may start or stop. The bootstrap facts are checked when the
/// step runs.
///
/// W382 (D-033): only a bootstrap operation may ask for the read-only
/// bootstrap confirmation, and only while it is unresolved (`intent`,
/// `needs_attention` or `compensating`), for `reconcile`.
pub fn ols_step_current(operation: &Operation, step: AdminStep) -> bool {
    let attempted = operation.state == RecordedState::Intent && operation.effect_attempted;
    let reconcile = operation.state == RecordedState::NeedsAttention && operation.effect_attempted;
    let compensating = operation.state == RecordedState::Compensating;
    let bootstrap = crate::ols::is_bootstrap_predecessor(
        &operation.intent.predecessor_generation,
        &operation.intent.predecessor_digest,
    );
    match step {
        AdminStep::OlsPreflight => {
            operation.state == RecordedState::Intent && !operation.effect_attempted
        }
        AdminStep::OlsConfigTest => attempted,
        AdminStep::OlsReload => !bootstrap && (attempted || reconcile || compensating),
        AdminStep::OlsVerify if bootstrap => attempted,
        AdminStep::OlsVerify => attempted || reconcile || compensating,
        AdminStep::OlsStart => bootstrap && attempted,
        AdminStep::OlsStop => bootstrap && compensating,
        AdminStep::OlsBootstrapConfirm => bootstrap && operation.state.is_unresolved(),
        // W368: only while the activation itself runs, never in a reconcile
        // or compensation, and never for a bootstrap. The journaled opt-in
        // is required when the step runs.
        AdminStep::PageCacheInstall => !bootstrap && attempted,
        // W370: after the verified target of an opt-out, or after the one
        // compensating restore of any page-cache change; never in a
        // reconcile and never for a bootstrap. The journaled change is
        // required when the step runs.
        AdminStep::PageCacheRemove => !bootstrap && (attempted || compensating),
        // W387 (D-037): the stop only while the ejection runs after its
        // effect mark; the restore in the states of the predecessor reload
        // (the reconcile of an attempted ejection, its one compensation).
        // The step itself requires the target or the predecessor live.
        AdminStep::EjectPhpStop => !bootstrap && attempted,
        AdminStep::EjectPhpRestore => !bootstrap && (attempted || reconcile || compensating),
        _ => false,
    }
}

/// Picks the single record an operation id names; none or several is refused.
pub fn single_record(records: &OperationRecords) -> Result<Record<'_>, ExecutorError> {
    // W372: an adopted site's provision row shares its re-adoption's id.
    let adopted = records.provision.as_ref().is_some_and(|provision| {
        provision.state == ProvisionState::Adopted
            && records
                .readoption
                .as_ref()
                .is_some_and(|row| row.intent.operation_id == provision.intent.operation_id)
    });
    let provision = records.provision.as_ref().filter(|_| !adopted);
    if let Some(rotation) = &records.credential_rotation {
        return match (
            provision,
            &records.probe,
            &records.capture,
            &records.operation,
            &records.readoption,
            &records.certificate,
            &records.renewal,
            &records.site_update,
            &records.site_restore,
            &records.dns_import,
            &records.dns_change,
            &records.app_release,
            &records.app_lifecycle,
        ) {
            (None, None, None, None, None, None, None, None, None, None, None, None, None) => {
                Ok(Record::CredentialRotation(rotation))
            }
            _ => Err(ExecutorError::BindingDenied),
        };
    }
    if let Some(release) = &records.app_release {
        return match (
            provision,
            &records.probe,
            &records.capture,
            &records.operation,
            &records.readoption,
            &records.certificate,
            &records.renewal,
            &records.site_update,
            &records.site_restore,
            &records.dns_import,
            &records.dns_change,
            &records.app_lifecycle,
        ) {
            (None, None, None, None, None, None, None, None, None, None, None, None) => {
                Ok(Record::AppRelease(release))
            }
            _ => Err(ExecutorError::BindingDenied),
        };
    }
    if let Some(lifecycle) = &records.app_lifecycle {
        return match (
            provision,
            &records.probe,
            &records.capture,
            &records.operation,
            &records.readoption,
            &records.certificate,
            &records.renewal,
            &records.site_update,
            &records.site_restore,
            &records.dns_import,
            &records.dns_change,
        ) {
            (None, None, None, None, None, None, None, None, None, None, None) => {
                Ok(Record::AppLifecycle(lifecycle))
            }
            _ => Err(ExecutorError::BindingDenied),
        };
    }
    if let Some(change) = &records.dns_change {
        // W565: a change's operation names no other record, and its plan
        // bytes must be stored.
        let plan = records
            .dns_change_plan
            .as_deref()
            .ok_or(ExecutorError::BindingDenied)?;
        return match (
            provision,
            &records.probe,
            &records.capture,
            &records.operation,
            &records.readoption,
            &records.certificate,
            &records.renewal,
            &records.site_update,
            &records.site_restore,
            &records.dns_import,
        ) {
            (None, None, None, None, None, None, None, None, None, None) => {
                Ok(Record::DnsChange(change, plan))
            }
            _ => Err(ExecutorError::BindingDenied),
        };
    }
    if let Some(import) = &records.dns_import {
        // W563: a zone import's operation names no other record.
        return match (
            provision,
            &records.probe,
            &records.capture,
            &records.operation,
            &records.readoption,
            &records.certificate,
            &records.renewal,
            &records.site_update,
            &records.site_restore,
        ) {
            (None, None, None, None, None, None, None, None, None) => Ok(Record::DnsImport(import)),
            _ => Err(ExecutorError::BindingDenied),
        };
    }
    if let Some(restore) = &records.site_restore {
        // W543: a restore's operation names no other record.
        return match (
            provision,
            &records.probe,
            &records.capture,
            &records.operation,
            &records.readoption,
            &records.certificate,
            &records.renewal,
            &records.site_update,
        ) {
            (None, None, None, None, None, None, None, None) => Ok(Record::Restore(restore)),
            _ => Err(ExecutorError::BindingDenied),
        };
    }
    if let Some(update) = &records.site_update {
        // W516: an update's operation names no other record.
        return match (
            provision,
            &records.probe,
            &records.capture,
            &records.operation,
            &records.readoption,
            &records.certificate,
            &records.renewal,
        ) {
            (None, None, None, None, None, None, None) => Ok(Record::Update(update)),
            _ => Err(ExecutorError::BindingDenied),
        };
    }
    if let Some(renewal) = &records.renewal {
        // W464: a renewal id names no other record.
        return match (
            provision,
            &records.probe,
            &records.capture,
            &records.operation,
            &records.readoption,
            &records.certificate,
        ) {
            (None, None, None, None, None, None) => Ok(Record::Renewal(renewal)),
            _ => Err(ExecutorError::BindingDenied),
        };
    }
    if let Some(certificate) = &records.certificate {
        // W462: a certificate id names no other record.
        return match (
            provision,
            &records.probe,
            &records.capture,
            &records.operation,
            &records.readoption,
        ) {
            (None, None, None, None, None) => Ok(Record::Certificate(certificate)),
            _ => Err(ExecutorError::BindingDenied),
        };
    }
    if records.static_ejection.is_some()
        && (records.operation.is_none() || records.ejection.is_none())
    {
        return Err(ExecutorError::BindingDenied);
    }
    match (
        provision,
        &records.probe,
        &records.capture,
        &records.operation,
        &records.readoption,
    ) {
        (Some(provision), None, None, None, None) => Ok(Record::Provision(provision)),
        (None, Some(probe), None, None, None) => Ok(Record::Probe(probe)),
        (None, None, Some(capture), None, None) => Ok(Record::Capture(capture)),
        (None, None, None, Some(operation), None) => Ok(match &records.ejection {
            Some(site) => Record::Ejection(operation, site),
            None => Record::Ols(operation),
        }),
        (None, None, None, None, Some(row)) => Ok(Record::Readoption(row)),
        _ => Err(ExecutorError::BindingDenied),
    }
}

/// The allocation the executor journaled before the effect, from the current
/// step's resource text (`uid=` or `level=s0:c`).
fn planned(record: Record<'_>, key: &str) -> Result<u32, ExecutorError> {
    let Record::Provision(provision) = record else {
        return Err(ExecutorError::BindingDenied);
    };
    let resource = provision.steps.last().map(|last| last.resource.clone());
    match provision::recorded_numbers(&resource.into_iter().collect::<Vec<_>>(), key)[..] {
        [number] => Ok(number),
        _ => Err(ExecutorError::BindingDenied),
    }
}

/// W335/W341: the quota for the current provision step. The Directories
/// step uses the plan journaled in its intent. Policy limits must equal the
/// policy enrolled now; signed plan limits must be at most its cap. A
/// missing, malformed or no longer permitted plan is refused. Other steps
/// never touch the quota.
pub(crate) fn journaled_quota(
    last: &rustiron_journal::StepRecord,
    enrolled: Option<crate::quota::QuotaLimits>,
) -> Result<crate::quota::QuotaPlan, ExecutorError> {
    use crate::quota::{QuotaPlan, RecordedQuota};
    if last.step != ProvisionStep::Directories {
        return Ok(QuotaPlan::NotEnforced);
    }
    match RecordedQuota::parse(&last.resource) {
        RecordedQuota::Plan(intent) if intent.permitted_by(enrolled) => Ok(intent.plan),
        _ => Err(ExecutorError::BindingDenied),
    }
}

/// SELinux type of a context string `user:role:type:level`.
pub fn context_type(context: &str) -> Option<&str> {
    let mut fields = context.trim_end_matches(['\0', '\n']).split(':');
    match (fields.next(), fields.next(), fields.next()) {
        (Some(_), Some(_), Some(kind)) if !kind.is_empty() => Some(kind),
        _ => None,
    }
}

/// SELinux type of a live process, read from `/proc/<pid>/attr/current`.
/// Unreadable or malformed is `None`, which every check treats as refusal.
pub fn process_type(pid: &str) -> Option<String> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/attr/current")).ok()?;
    context_type(&text).map(str::to_owned)
}

/// Lab confined domains: the helper refuses to serve outside its own, and
/// serves only peers in the executor's.
pub const LAB_HELPER_TYPE: &str = "rustiron_admin_t";
/// Peer domain the confined lab helper requires.
pub const LAB_EXECUTOR_TYPE: &str = "rustiron_executor_t";

/// How long the executor waits for a whole capture or probe.
const RUN_TIMEOUT: Duration = Duration::from_secs(45 * 60);

/// One helper process: the anchor, the peer domain it requires (`None`
/// only for unconfined tests), the database password carried from the
/// Database step to the Credentials step of the same operation, and the
/// captures and probes it already ran (never run twice by this process).
pub struct Helper {
    anchor: TrustAnchor,
    peer_type: Option<String>,
    password: Option<(Id, String)>,
    ran: Vec<Id>,
    ols_ran: Vec<(Id, AdminStep, RecordedState)>,
    started: u64,
}

impl Helper {
    /// A helper for `anchor` that requires peers of `peer_type`.
    pub fn new(anchor: TrustAnchor, peer_type: Option<String>) -> Self {
        Self {
            anchor,
            peer_type,
            password: None,
            ran: Vec::new(),
            ols_ran: Vec::new(),
            started: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(u64::MAX, |elapsed| elapsed.as_secs()),
        }
    }

    /// Serves one connection on the calling thread: kernel peer (UID, then
    /// SELinux type), one bounded request, journal reread, decision, effect,
    /// one reply line (`ok`, `ok <json>` or the stable error code).
    pub fn handle(&mut self, mut stream: UnixStream) {
        let bytes = read_request(&mut stream);
        self.answer(stream, bytes);
    }

    /// Decides and replies for a request already read from `stream`.
    fn answer(&mut self, mut stream: UnixStream, bytes: Result<Vec<u8>, ExecutorError>) {
        let outcome = self.serve(&stream, bytes);
        let reply = match &outcome {
            Ok(payload) => ReplyLine::Done(payload.as_deref()),
            Err(error) => ReplyLine::Code(error.code()),
        }
        .encode();
        // A peer that stops reading cannot hold the helper (W186).
        let _ = stream.set_write_timeout(Some(REPLY_TIMEOUT));
        let _ = stream.write_all(reply.as_bytes());
    }

    fn serve(
        &mut self,
        stream: &UnixStream,
        bytes: Result<Vec<u8>, ExecutorError>,
    ) -> Result<Option<String>, ExecutorError> {
        let anchor = &self.anchor;
        let peer = rustix::net::sockopt::socket_peercred(stream)
            .map_err(|_| ExecutorError::PeerDenied)?
            .uid
            .as_raw();
        let bytes = bytes?;
        // Refused before parsing or any journal read; the bounded read lets
        // the refusal arrive instead of a connection reset.
        if peer != anchor.owner_uid {
            return Err(ExecutorError::PeerDenied);
        }
        if let Some(required) = &self.peer_type {
            // D-020 (W331): the label the kernel captured at connect time,
            // not the pid's current label, so pid reuse cannot satisfy it.
            let label = crate::peer_label::peer_label(stream);
            if label.as_deref().and_then(context_type) != Some(required.as_str()) {
                return Err(ExecutorError::PeerDenied);
            }
        }
        if is_ols_status(&bytes) {
            // Read-only: no journal, no step, no run-once entry.
            let policy = self.enrolled_ols()?;
            return server_checks(&policy).map(|checks| Some(checks.encode()));
        }
        if let Some(site) = decode_site_root(&bytes) {
            // W372, read-only: the path comes from the site ID grammar.
            let present = crate::readopt::site_root_present(&SiteLayout::derive(&site));
            return Ok(Some(if present { "present" } else { "absent" }.to_owned()));
        }
        let request = AdminRequest::parse(&bytes)?;
        // W508: a refusal before the step names its stage in the journal
        // (step name and error code only, no request content).
        let refused = |stage: &str, error: ExecutorError| {
            eprintln!(
                "{}",
                serde_json::json!({
                    "scope": "admin_helper_refusal",
                    "step": request.step.name(),
                    "stage": stage,
                    "error": error.code(),
                })
            );
            error
        };
        let (host, epoch) = durable::prepare(anchor).map_err(|e| refused("policy", e))?;
        let records = FixtureJournal::records_as_process_owner(
            &anchor.journal_dir,
            &host,
            &epoch,
            &request.operation_id,
            // W360: the bootstrap generation is the OLS baseline.
            Some(&crate::ols::bootstrap_generation()),
        )
        .map_err(|e| refused("journal", e.into()))?;
        let record = single_record(&records).map_err(|e| refused("record", e))?;
        let action = authorize(peer, anchor.owner_uid, &request, record)
            .map_err(|e| refused("authorize", e))?;
        match (action.step, record) {
            (AdminStep::ProvisionStep, Record::Provision(provision)) => self
                .provision_step(
                    &action,
                    provision,
                    records.import.as_ref(),
                    records.site_clone.as_ref(),
                    records.app.as_ref(),
                    records.app_fullstack.as_ref(),
                    records.proxy.is_some(),
                )
                .map(|()| None),
            (AdminStep::AppDeployStep, Record::AppRelease(release)) => {
                let facts = records.app.as_ref().ok_or(ExecutorError::BindingDenied)?;
                let open = release
                    .steps
                    .last()
                    .filter(|s| s.state == StepState::Intent)
                    .ok_or(ExecutorError::BindingDenied)?;
                let layout = SiteLayout {
                    account: action.account.clone(),
                    root: action.root.clone(),
                };
                let blue_green_cutover =
                    records.app_fullstack.as_ref().is_some_and(|s| s.blue_green);
                crate::app_site::run_deploy_step(
                    open.step,
                    &layout,
                    facts,
                    records.app_fullstack.as_ref(),
                    release,
                    records.app_previous_release_id.as_deref(),
                    blue_green_cutover,
                )
                .map(|()| None)
            }
            (AdminStep::AppCaddyActivate, Record::AppRelease(release)) => {
                let facts = records.app.as_ref().ok_or(ExecutorError::BindingDenied)?;
                let spec = records
                    .app_fullstack
                    .as_ref()
                    .ok_or(ExecutorError::BindingDenied)?;
                if spec.ingress != rustiron_contracts::approval::IngressEngine::Caddy {
                    return Err(ExecutorError::BindingDenied);
                }
                let caddy_policy = self.enrolled_caddy()?;
                let render_cfg = crate::caddy::render_config_from_policy(&caddy_policy)?;
                let sites = crate::caddy::sites_from_records(&caddy_policy, &records)?;
                let generation = crate::caddy::render(&render_cfg, &sites)?;
                let (gen_id, gen_digest, _) = crate::caddy::activate_live(
                    &generation,
                    &release.operation_id,
                    &caddy_policy.binary_sha256,
                    &|| Ok(()),
                )?;
                if spec.blue_green {
                    let layout = SiteLayout {
                        account: action.account.clone(),
                        root: action.root.clone(),
                    };
                    // `active_slot` was already flipped to the new slot in the journal;
                    // drain the opposite (old) slot now that Caddy serves the new slot.
                    let drained_slot = spec.active_slot.opposite();
                    crate::app_site::finish_blue_green_cutover(
                        &layout,
                        facts,
                        spec,
                        &release.release_id,
                        drained_slot,
                    )?;
                }
                Ok(Some(format!(
                    "{} {} {}",
                    gen_id.as_str(),
                    gen_digest.as_str(),
                    sites.len()
                )))
            }
            (AdminStep::AppLifecycle, Record::AppLifecycle(lifecycle)) => {
                let facts = records.app.as_ref().ok_or(ExecutorError::BindingDenied)?;
                crate::app_site::run_lifecycle_for(
                    &action.account,
                    facts.worker_entrypoint.is_some(),
                    records.app_fullstack.as_ref(),
                    lifecycle.action,
                )
                .map(|()| None)
            }
            (
                AdminStep::SiteCredentialRotate | AdminStep::SiteCredentialVerify,
                Record::CredentialRotation(rotation),
            ) => {
                let served = records
                    .served
                    .iter()
                    .find(|p| p.intent.site_id == rotation.site_id)
                    .ok_or(ExecutorError::BindingDenied)?;
                if served.intent.hostname != rotation.hostname
                    || records.ejected.contains(&rotation.site_id)
                {
                    return Err(ExecutorError::BindingDenied);
                }
                let layout = SiteLayout {
                    account: action.account.clone(),
                    root: action.root.clone(),
                };
                use rustiron_contracts::approval::{AppDatabase, CredentialTarget};
                match rotation.target {
                    CredentialTarget::MariadbUserPassword => {
                        let policy = self.enrolled_ols()?;
                        if action.step == AdminStep::SiteCredentialVerify {
                            crate::credential_rotate::verify_live_credentials(
                                &layout,
                                &rotation.hostname,
                                &policy.address,
                                policy.tls_address.as_deref(),
                            )
                            .map(|()| None)
                        } else {
                            crate::credential_rotate::rotate_mariadb_password(
                                &layout,
                                &rotation.hostname,
                                &rotation.operation_id,
                                &policy.address,
                                policy.tls_address.as_deref(),
                            )
                            .map(|outcome| Some(outcome.as_str().to_owned()))
                        }
                    }
                    CredentialTarget::AppMariadbPassword => {
                        let facts = records.app.as_ref().ok_or(ExecutorError::BindingDenied)?;
                        let spec = records
                            .app_fullstack
                            .as_ref()
                            .ok_or(ExecutorError::BindingDenied)?;
                        if spec.database != AppDatabase::Mariadb {
                            return Err(ExecutorError::BindingDenied);
                        }
                        if action.step == AdminStep::SiteCredentialVerify {
                            crate::credential_rotate::verify_live_app_credentials(
                                &layout,
                                facts,
                                rotation.target,
                                &rotation.operation_id,
                            )
                            .map(|()| None)
                        } else {
                            crate::credential_rotate::rotate_app_mariadb_password(
                                &layout,
                                facts,
                                &rotation.operation_id,
                            )
                            .map(|outcome| Some(outcome.as_str().to_owned()))
                        }
                    }
                    CredentialTarget::AppPostgresql18Password => {
                        let facts = records.app.as_ref().ok_or(ExecutorError::BindingDenied)?;
                        let spec = records
                            .app_fullstack
                            .as_ref()
                            .ok_or(ExecutorError::BindingDenied)?;
                        if spec.database != AppDatabase::Postgresql18 {
                            return Err(ExecutorError::BindingDenied);
                        }
                        if action.step == AdminStep::SiteCredentialVerify {
                            crate::credential_rotate::verify_live_app_credentials(
                                &layout,
                                facts,
                                rotation.target,
                                &rotation.operation_id,
                            )
                            .map(|()| None)
                        } else {
                            crate::credential_rotate::rotate_app_postgres_password(
                                &layout,
                                facts,
                                &rotation.operation_id,
                            )
                            .map(|outcome| Some(outcome.as_str().to_owned()))
                        }
                    }
                }
            }
            (AdminStep::CertificateIssue, Record::Certificate(row)) => self
                .certificate_run(
                    &action,
                    &row.intent.operation_id,
                    &row.intent.hostname,
                    row.intent.alias_hostname.as_ref(),
                    installed_chain(&records, &row.intent.site_id),
                )
                .map(Some),
            (AdminStep::CertificateRenew, Record::Renewal(row)) => self
                .certificate_run(
                    &action,
                    &row.renewal_id,
                    &row.target.hostname,
                    row.target.alias_hostname.as_ref(),
                    installed_chain(&records, &row.target.site_id),
                )
                .map(Some),
            (AdminStep::ImportScrub, Record::Provision(provision)) => {
                import_scrub(&action, provision, records.import.as_ref()).map(|()| None)
            }
            (AdminStep::SiteRetire, Record::Provision(provision)) => {
                // W508 (D-080): only for the journal's open retirement.
                if records
                    .retirement
                    .as_ref()
                    .is_none_or(|retirement| retirement.state != StepState::Intent)
                {
                    return Err(ExecutorError::BindingDenied);
                }
                crate::site_retire::remove(provision).map(|()| None)
            }
            (AdminStep::SiteQuotaSet, Record::Provision(provision)) => {
                // W535 (D-088): only the journal's open change of this site,
                // with its signed limits.
                let change = records
                    .quota_change
                    .as_ref()
                    .filter(|change| {
                        change.state == StepState::Intent
                            && change.site_id == provision.intent.site_id
                    })
                    .ok_or(ExecutorError::BindingDenied)?;
                crate::quota::change(
                    &mut crate::quota::SystemQuota,
                    &SiteLayout::derive(&provision.intent.site_id).account,
                    crate::quota::QuotaLimits {
                        block_hard_kib: change.block_hard_kib,
                        inode_hard: change.inode_hard,
                    },
                )
                .map(|_| None)
            }
            (AdminStep::UpdateInventory, Record::Provision(provision)) => {
                // W530 (D-087): read only, as the site; the report is the
                // reply.
                crate::site_update::inventory(&SiteLayout::derive(&provision.intent.site_id))
                    .map(|report| Some(report.to_string()))
            }
            (AdminStep::SiteDelete, Record::Provision(provision)) => {
                // W522 (D-085) & W658 (D-102 C2): only for the journal's open deletion.
                if records
                    .deletion
                    .as_ref()
                    .is_none_or(|deletion| deletion.state != StepState::Intent)
                {
                    return Err(ExecutorError::BindingDenied);
                }
                let app_db = records.app_fullstack.as_ref().map(|s| s.database);
                crate::site_delete::remove_with_app_db(provision, app_db).map(|()| None)
            }
            (AdminStep::UpdateStep | AdminStep::UpdateRollback, Record::Update(update)) => {
                // W516 (D-084): every value from the journal and the policy.
                let policy = self.enrolled_ols()?;
                let hostname = &records
                    .served
                    .iter()
                    .find(|provision| provision.intent.site_id == update.site_id)
                    .ok_or(ExecutorError::BindingDenied)?
                    .intent
                    .hostname;
                // W517: the capture's record, for the rollback's restore.
                let capture_records = FixtureJournal::records_as_process_owner(
                    &anchor.journal_dir,
                    &host,
                    &epoch,
                    &update.capture_operation_id,
                    None,
                )?;
                let context = crate::site_update::UpdateContext {
                    update,
                    hostname,
                    address: &policy.address,
                    tls_address: policy.tls_address.as_deref(),
                    intake_dir: std::path::Path::new(crate::layout::UPDATE_INTAKE_DIR),
                    owner: anchor.owner_uid,
                    anchor,
                    capture: capture_records.capture.as_ref(),
                };
                let outcome = if action.step == AdminStep::UpdateRollback {
                    crate::site_update::rollback(&context)
                } else {
                    let step = update
                        .steps
                        .last()
                        .ok_or(ExecutorError::BindingDenied)?
                        .step;
                    crate::site_update::run_step(&context, step)
                };
                // W518: an update step's failure names its step and code.
                if let Err(error) = &outcome {
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "scope": "admin_helper_step",
                            "step": action.step.name(),
                            "update_step": update.steps.last().map(|last| format!("{:?}", last.step)),
                            "error": error.code(),
                        })
                    );
                }
                outcome.map(|()| None)
            }
            (AdminStep::RestoreStep, Record::Restore(restore)) => {
                // W543 (D-089): every value from the journal and the policy.
                let policy = self.enrolled_ols()?;
                let hostname = &records
                    .served
                    .iter()
                    .find(|provision| provision.intent.site_id == restore.site_id)
                    .ok_or(ExecutorError::BindingDenied)?
                    .intent
                    .hostname;
                let attempt = restore.current().ok_or(ExecutorError::BindingDenied)?;
                let step = attempt
                    .steps
                    .last()
                    .ok_or(ExecutorError::BindingDenied)?
                    .step;
                let capture_records = FixtureJournal::records_as_process_owner(
                    &anchor.journal_dir,
                    &host,
                    &epoch,
                    restore.capture_of(attempt.from),
                    None,
                )?;
                let capture = capture_records
                    .capture
                    .as_ref()
                    .ok_or(ExecutorError::BindingDenied)?;
                let context = crate::site_restore::RestoreContext {
                    restore,
                    capture,
                    hostname,
                    address: &policy.address,
                    tls_address: policy.tls_address.as_deref(),
                    anchor,
                    app: records.app.as_ref(),
                    app_database: records.app_fullstack.as_ref().map(|s| s.database),
                };
                let outcome = crate::site_restore::run_step(&context, step);
                if let Err(error) = &outcome {
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "scope": "admin_helper_step",
                            "step": action.step.name(),
                            "restore_step": step.as_str(),
                            "error": error.code(),
                        })
                    );
                }
                outcome.map(|()| None)
            }
            (AdminStep::DnsImport, Record::DnsImport(import)) => {
                // W563 (D-091): every value from the journal, the intake
                // file, and the enrolled `dns` section.
                let dns = self.enrolled_dns()?;
                let outcome = crate::dns_import::run(
                    &mut crate::dns_import::SystemPdns,
                    import,
                    &dns,
                    std::path::Path::new(crate::layout::DNS_INTAKE_DIR),
                    anchor.owner_uid,
                );
                if let Err(error) = &outcome {
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "scope": "admin_helper_step",
                            "step": action.step.name(),
                            "error": error.code(),
                        })
                    );
                }
                outcome.map(|()| None)
            }
            (AdminStep::DnsZoneRead, Record::DnsImport(import)) => {
                // W565: read only; the zone the done import owns. W566-F1:
                // a reply payload is one line, so the listing goes as one
                // JSON string.
                crate::dns_change::read_zone(&mut crate::dns_import::SystemPdns, &import.zone)
                    .and_then(|bytes| {
                        String::from_utf8(bytes).map_err(|_| ExecutorError::StepFailed)
                    })
                    .and_then(|text| {
                        serde_json::to_string(&text).map_err(|_| ExecutorError::StepFailed)
                    })
                    .map(Some)
            }
            (AdminStep::DnsChange, Record::DnsChange(change, plan)) => {
                // W565 (D-091): the signed plan stored at admission and the
                // sets the executor read before intent.
                let plan = rustiron_contracts::approval::DnsChangePlan::decode(plan)
                    .map_err(|_| ExecutorError::BindingDenied)?;
                let outcome =
                    crate::dns_change::run(&mut crate::dns_import::SystemPdns, change, &plan);
                if let Err(error) = &outcome {
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "scope": "admin_helper_step",
                            "step": action.step.name(),
                            "error": error.code(),
                        })
                    );
                }
                outcome.map(|()| None)
            }
            (AdminStep::CloneScrub, Record::Provision(provision)) => {
                clone_scrub(&action, provision, records.site_clone.as_ref()).map(|()| None)
            }
            (AdminStep::CaptureRun, Record::Capture(capture)) => {
                self.once(&capture.intent.operation_id, capture.started_at.get())?;
                self.capture_run(
                    &action,
                    capture,
                    records.app.as_ref(),
                    records.app_fullstack.as_ref().map(|s| s.database),
                )
                .map(Some)
            }
            (AdminStep::ProbeRun, Record::Probe(probe)) => {
                let source = records
                    .probe_source
                    .as_ref()
                    .filter(|source| source.state.is_owned())
                    .ok_or(ExecutorError::BindingDenied)?;
                self.once(&probe.intent.operation_id, probe.started_at.get())?;
                self.probe_run(probe, source).map(Some)
            }
            (step, Record::Ols(operation) | Record::Ejection(operation, _)) => {
                self.ols_once(operation, step)?;
                self.ols_step(step, operation, &records)
            }
            (AdminStep::ReadoptObserve, Record::Readoption(row)) => {
                self.readopt_observe(row, &records).map(Some)
            }
            _ => Err(ExecutorError::BindingDenied),
        }
    }

    /// W372: the read-only facts of a `verifying` re-adoption, as root.
    /// The site, or the listed sites and their hostnames, come from the
    /// journaled plan (whose digest the journal checked) and the journal's
    /// owned provisions; nothing comes from the request.
    fn readopt_observe(
        &self,
        row: &Readoption,
        records: &OperationRecords,
    ) -> Result<String, ExecutorError> {
        let plan = rustiron_contracts::approval::ReadoptPlan::decode(row.intent.plan.as_bytes())
            .map_err(|_| ExecutorError::BindingDenied)?;
        if plan.digest() != row.intent.plan_digest {
            return Err(ExecutorError::BindingDenied);
        }
        if let Some((site, _, _)) = plan.site() {
            return Ok(crate::readopt::observe_host_site(&SiteLayout::derive(site)).encode());
        }
        let (_, _, listed) = plan.generation().ok_or(ExecutorError::BindingDenied)?;
        let policy = self.enrolled_ols()?;
        let sites = listed
            .iter()
            .map(|site| {
                let provision = records
                    .served
                    .iter()
                    .find(|provision| &provision.intent.site_id == site)
                    .ok_or(ExecutorError::BindingDenied)?;
                Ok(crate::ols::ServedSite {
                    account: SiteLayout::derive(site).account,
                    hostname: provision.intent.hostname.clone(),
                    alias_hostname: records.served_aliases.get(site.as_str()).cloned(),
                    ejected: false,
                    static_ejected: false,
                    lscache: false,
                    tls_alias: None,
                    tls: None,
                    acme: false,
                    proxy: records.served_proxies.get(site.as_str()).cloned(),
                })
            })
            .collect::<Result<Vec<_>, ExecutorError>>()?;
        crate::readopt::observe_host_generation(&policy, &sites).map(|facts| facts.encode())
    }

    /// An OLS step runs at most once per operation and journal state in this
    /// process (W200): the activation's reload and verify, and then those of
    /// its one compensation. The `operations` table keeps no start time, so
    /// unlike [`Self::once`] a restarted helper relies on the journal state
    /// alone; every OLS step is an observation, a test or the fixed reload.
    ///
    /// W382 (D-033): the bootstrap confirmation changes nothing, so it keeps
    /// no run-once entry, like `ols_status`.
    fn ols_once(&mut self, operation: &Operation, step: AdminStep) -> Result<(), ExecutorError> {
        if step == AdminStep::OlsBootstrapConfirm {
            return Ok(());
        }
        let key = (operation.intent.operation_id.clone(), step, operation.state);
        if self.ols_ran.contains(&key) {
            return Err(ExecutorError::ReplayDenied);
        }
        self.ols_ran.push(key);
        Ok(())
    }

    /// W462 (D-059), W464 (D-060): the open issuance or renewal, once per
    /// helper process. Every value comes from the journal row and the
    /// enrolled policy. The reply is the installed chain's SHA-256 and its
    /// expiry in Unix seconds.
    fn certificate_run(
        &mut self,
        action: &AdminAction,
        operation: &Id,
        hostname: &rustiron_contracts::approval::Hostname,
        alias: Option<&rustiron_contracts::approval::Hostname>,
        previous_chain: Option<&rustiron_contracts::approval::Sha256Digest>,
    ) -> Result<String, ExecutorError> {
        if self.ran.contains(operation) {
            return Err(ExecutorError::ReplayDenied);
        }
        self.ran.push(operation.clone());
        let owner = self.anchor.owner_uid;
        let loaded = crate::policy::load(
            &crate::files::open_trusted_directory(&self.anchor.policy_dir, owner)?,
            owner,
        )?;
        let mut served_pair = None;
        if let Some(alias) = alias {
            if !loaded.policy.alias_certificate_enabled() {
                return Err(ExecutorError::Unavailable);
            }
            let ols = loaded
                .policy
                .ols
                .as_ref()
                .ok_or(ExecutorError::Unavailable)?;
            durable::parent_unchanged(ols)?;
            crate::certificate::require_pair_mapping(&action.account, hostname, alias, false)?;
            let active = crate::certificate::pair_serves_tls(&action.account, hostname, alias)?;
            if let Some(sha) = previous_chain {
                crate::certificate::check_live(&action.account, sha)?;
                if active {
                    served_pair = Some(sha);
                }
            }
            if active && served_pair.is_none()
                || action.step == AdminStep::CertificateRenew && !active
            {
                return Err(ExecutorError::PreconditionChanged);
            }
        }
        let (Some(ols), Some(acme)) = (loaded.policy.ols, loaded.policy.acme) else {
            return Err(ExecutorError::Unavailable);
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| rustiron_contracts::Timestamp::try_from(elapsed.as_secs()).ok())
            .ok_or(ExecutorError::TimeDenied)?;
        let tls_address = ols.tls_address.clone().ok_or(ExecutorError::Unavailable)?;
        let (sha, not_after) = crate::certificate::issue(&crate::certificate::Issue {
            account: &action.account,
            hostname,
            alias,
            served_pair,
            listener: &ols.address,
            tls_listener: &tls_address,
            directory: &acme.directory,
            ca_bundle: acme.ca_bundle.as_deref(),
            now,
        })?;
        Ok(format!("{} {}", sha.as_str(), not_after.get()))
    }

    fn enrolled_dns(&self) -> Result<crate::dns::DnsPolicy, ExecutorError> {
        let owner = self.anchor.owner_uid;
        let loaded = crate::policy::load(
            &crate::files::open_trusted_directory(&self.anchor.policy_dir, owner)?,
            owner,
        )?;
        loaded.policy.dns.ok_or(ExecutorError::Unavailable)
    }

    fn enrolled_ols(&self) -> Result<crate::policy::OlsPolicy, ExecutorError> {
        let owner = self.anchor.owner_uid;
        let loaded = crate::policy::load(
            &crate::files::open_trusted_directory(&self.anchor.policy_dir, owner)?,
            owner,
        )?;
        loaded.policy.ols.ok_or(ExecutorError::Unavailable)
    }

    fn enrolled_caddy(&self) -> Result<crate::policy::CaddyPolicy, ExecutorError> {
        let owner = self.anchor.owner_uid;
        let loaded = crate::policy::load(
            &crate::files::open_trusted_directory(&self.anchor.policy_dir, owner)?,
            owner,
        )?;
        loaded.policy.caddy.ok_or(ExecutorError::Unavailable)
    }

    /// Runs one OLS step; every value comes from the enrolled policy and the
    /// journal, never from the request.
    fn ols_step(
        &self,
        step: AdminStep,
        operation: &Operation,
        records: &OperationRecords,
    ) -> Result<Option<String>, ExecutorError> {
        let policy = self.enrolled_ols()?;
        let intent = &operation.intent;
        if crate::ols::is_bootstrap_predecessor(
            &intent.predecessor_generation,
            &intent.predecessor_digest,
        ) {
            return bootstrap_step(step, operation, records, &policy);
        }
        match step {
            AdminStep::OlsPreflight => {
                // D-060: each served site's live link names its latest
                // installed chain, or the generation would serve another.
                let served: Vec<_> = records
                    .served
                    .iter()
                    .map(|provision| &provision.intent.site_id)
                    .collect();
                for (site, sha) in &records.certificates {
                    if served.contains(&site) && !records.ejected.contains(site) {
                        crate::certificate::check_live(&SiteLayout::derive(site).account, sha)?;
                    }
                }
                preflight_static_ejection(&policy, intent, records)?;
                server_checks(&policy).map(|c| Some(c.encode()))
            }
            AdminStep::OlsConfigTest => crate::ols::config_test().map(|()| None),
            AdminStep::OlsReload => {
                if operation.state == RecordedState::NeedsAttention {
                    let intent = &operation.intent;
                    let live = crate::ols::observe(&crate::ols::open_include()?)?;
                    if live
                        != (
                            intent.predecessor_generation.clone(),
                            intent.predecessor_digest.clone(),
                        )
                    {
                        return Err(ExecutorError::PreconditionChanged);
                    }
                }
                provision::run("/usr/bin/systemctl", &["reload", "lshttpd.service"]).map(|()| None)
            }
            AdminStep::OlsVerify => {
                let intent = &operation.intent;
                let expected = if matches!(
                    operation.state,
                    RecordedState::Compensating | RecordedState::NeedsAttention
                ) {
                    (&intent.predecessor_generation, &intent.predecessor_digest)
                } else {
                    (&intent.target_generation, &intent.target_digest)
                };
                let include = crate::ols::open_include()?;
                let (live, digest) = crate::ols::observe(&include)?;
                if (&live, &digest) != expected {
                    return Err(ExecutorError::PreconditionChanged);
                }
                let managed = crate::ols::managed_accounts(&include, &live)?;
                let provisions: Vec<_> = records
                    .served
                    .iter()
                    .map(|p| {
                        let site = &p.intent.site_id;
                        (
                            site.clone(),
                            p.intent.hostname.clone(),
                            records.served_aliases.get(site.as_str()).cloned(),
                        )
                    })
                    .collect();
                let sites = crate::ols::served_from(&managed, &provisions, &records.ejected)?;
                durable::probe_with_retry(&policy, &sites)?;
                let restoring = matches!(
                    operation.state,
                    RecordedState::Compensating | RecordedState::NeedsAttention
                );
                verify_alias_tls(
                    &policy,
                    &include,
                    &live,
                    &sites,
                    &records.certificate_pairs,
                    restoring,
                    records.ejection.as_ref(),
                )?;
                verify_static_ejection(&policy, &include, &live, records, restoring)?;
                durable::parent_unchanged(&policy)?;
                Ok(None)
            }
            AdminStep::PageCacheInstall => {
                // W368: the journaled opt-in site, served by the target
                // generation the activation just verified. W395: with the
                // journaled recipe of that opt-in.
                let site = records
                    .page_cache
                    .as_ref()
                    .ok_or(ExecutorError::BindingDenied)?;
                let recipe = records
                    .page_cache_recipe
                    .and_then(crate::page_cache::recipe_from_name)
                    .ok_or(ExecutorError::BindingDenied)?;
                let include = crate::ols::open_include()?;
                let live = crate::ols::observe(&include)?;
                if live
                    != (
                        intent.target_generation.clone(),
                        intent.target_digest.clone(),
                    )
                {
                    return Err(ExecutorError::PreconditionChanged);
                }
                let layout = SiteLayout::derive(site);
                if !crate::ols::managed_accounts(&include, &live.0)?.contains(&layout.account) {
                    return Err(ExecutorError::BindingDenied);
                }
                let hostname = &records
                    .served
                    .iter()
                    .find(|provision| &provision.intent.site_id == site)
                    .ok_or(ExecutorError::BindingDenied)?
                    .intent
                    .hostname;
                crate::page_cache::install(
                    &layout,
                    &self.anchor.recipes_dir,
                    &policy.address,
                    hostname,
                    recipe,
                )
                .map(|_| None)
            }
            AdminStep::PageCacheRemove => {
                // W370: during the activation, only the journaled opt-out on
                // its verified target; during the one compensation, the
                // site of either change on the restored predecessor.
                let (site, expected) = if operation.state == RecordedState::Compensating {
                    (
                        records
                            .page_cache
                            .as_ref()
                            .or(records.page_cache_opt_out.as_ref()),
                        (
                            intent.predecessor_generation.clone(),
                            intent.predecessor_digest.clone(),
                        ),
                    )
                } else {
                    (
                        records.page_cache_opt_out.as_ref(),
                        (
                            intent.target_generation.clone(),
                            intent.target_digest.clone(),
                        ),
                    )
                };
                let site = site.ok_or(ExecutorError::BindingDenied)?;
                let include = crate::ols::open_include()?;
                let live = crate::ols::observe(&include)?;
                if live != expected {
                    return Err(ExecutorError::PreconditionChanged);
                }
                let layout = SiteLayout::derive(site);
                if !crate::ols::managed_accounts(&include, &live.0)?.contains(&layout.account) {
                    return Err(ExecutorError::BindingDenied);
                }
                let hostname = &records
                    .served
                    .iter()
                    .find(|provision| &provision.intent.site_id == site)
                    .ok_or(ExecutorError::BindingDenied)?
                    .intent
                    .hostname;
                crate::page_cache::remove(&layout, &policy.address, hostname).map(|_| None)
            }
            AdminStep::EjectPhpStop | AdminStep::EjectPhpRestore => {
                // W387 (D-037): the journaled ejection's own site. The stop
                // runs on the verified switch to the target, whose include
                // no longer holds the site's managed vhost; the restore on
                // the predecessor, which holds it again.
                let site = records
                    .ejection
                    .as_ref()
                    .ok_or(ExecutorError::BindingDenied)?;
                let stop = step == AdminStep::EjectPhpStop;
                let expected = if stop {
                    (
                        intent.target_generation.clone(),
                        intent.target_digest.clone(),
                    )
                } else {
                    (
                        intent.predecessor_generation.clone(),
                        intent.predecessor_digest.clone(),
                    )
                };
                let include = crate::ols::open_include()?;
                let live = crate::ols::observe(&include)?;
                if live != expected {
                    return Err(ExecutorError::PreconditionChanged);
                }
                let layout = SiteLayout::derive(site);
                let managed =
                    crate::ols::managed_accounts(&include, &live.0)?.contains(&layout.account);
                if managed == stop {
                    return Err(ExecutorError::BindingDenied);
                }
                if !stop {
                    return crate::ejection::restore_site_php(&layout.account).map(|()| None);
                }
                let hostname = &records
                    .served
                    .iter()
                    .find(|provision| &provision.intent.site_id == site)
                    .ok_or(ExecutorError::BindingDenied)?
                    .intent
                    .hostname;
                let alias = records.served_aliases.get(site.as_str());
                let probe = match (&records.static_ejection, alias) {
                    (Some(recorded), None) if recorded == hostname => {
                        crate::ejection::EjectProbe::StaticSingle {
                            tls: installed_chain(records, site).is_some(),
                        }
                    }
                    (Some(_), _) => return Err(ExecutorError::BindingDenied),
                    (None, Some(alias)) => crate::ejection::EjectProbe::StaticAlias(alias),
                    (None, None) => crate::ejection::EjectProbe::WordPress,
                };
                crate::ejection::stop_site_php(
                    &layout.account,
                    &policy.address,
                    policy.tls_address.as_deref(),
                    hostname,
                    probe,
                )
                .map(|()| None)
            }
            _ => Err(ExecutorError::BindingDenied),
        }
    }

    /// A capture or probe runs at most once: never twice in this process,
    /// and never one journaled before this process started (in the same
    /// second included), so a restart cannot lose the guard (W177). The
    /// executor sends a request right after journaling it; an older
    /// `running` operation goes to operator recovery instead. An unreadable
    /// clock sets the start to the maximum, refusing everything.
    fn once(&mut self, operation: &Id, journaled_at: u64) -> Result<(), ExecutorError> {
        if journaled_at <= self.started || self.ran.contains(operation) {
            return Err(ExecutorError::ReplayDenied);
        }
        self.ran.push(operation.clone());
        Ok(())
    }

    fn capture_run(
        &self,
        action: &AdminAction,
        capture: &Capture,
        app: Option<&rustiron_journal::AppFacts>,
        app_database: Option<rustiron_contracts::approval::AppDatabase>,
    ) -> Result<String, ExecutorError> {
        if cfg!(rustiron_profile = "product") {
            return self.product_capture_run(capture, app, app_database);
        }
        let backup = crate::policy::load_bound_backup(
            &self.anchor,
            &capture.intent.host_id,
            &capture.intent.host_epoch,
            capture.backup_policy_digest.as_ref(),
        )?;
        let layout = SiteLayout {
            account: action.account.clone(),
            root: action.root.clone(),
        };
        let store = backup.store_address.to_string();
        let destination = crate::capture::Destination {
            repository_base: &backup.repository_base,
            store_address: &store,
        };
        let outcome = crate::capture::capture_site(
            &layout,
            &destination,
            capture.intent.operation_id.as_str(),
            capture.method == Some(rustiron_journal::CaptureMethod::SiteFilesDbFrozenV1),
        );
        Ok(encode_capture(&outcome))
    }

    /// W319/W356: a product capture re-binds the journaled projection digest
    /// (design step 1). With the write gate closed (lab builds; D-029 opens
    /// it in product builds) it then refuses with `NOT_ADMITTED_FOR_EFFECT`,
    /// before any store check, secret, network, dump or restic. With the
    /// gate open it runs steps 2 to 10 and replies
    /// with the capture outcome; from the start of the snapshot worker that
    /// reply is never a refusal, so the executor keeps the capture `running`
    /// unless the write was verified.
    fn product_capture_run(
        &self,
        capture: &Capture,
        app: Option<&rustiron_journal::AppFacts>,
        app_database: Option<rustiron_contracts::approval::AppDatabase>,
    ) -> Result<String, ExecutorError> {
        let destination = crate::policy::load_bound_product_backup(
            &self.anchor,
            &capture.intent.host_id,
            &capture.intent.host_epoch,
            capture.backup_policy_digest.as_ref(),
        )?;
        // `authorize` derived the action's account and root from this same
        // site ID; the effects derive them again from it.
        product_capture_effects_for_app_db(
            &self.anchor,
            &destination,
            &capture.intent.site_id,
            &capture.intent.operation_id,
            capture.method == Some(rustiron_journal::CaptureMethod::SiteFilesDbFrozenV1),
            app,
            app_database,
        )
    }

    /// W320, D-031 (W373): a product restore probe re-binds the journaled
    /// projection digest and verifies the site's repository identity with
    /// the fetch credential. Either failure is a refusal before any sandbox
    /// exists. Then the lab probe phases run with the product store half:
    /// the size check and the fetch through the store worker in the store
    /// namespace, as the probe account at the probe level. The reply is the
    /// probe outcome with its receipt, cleanup included.
    fn product_probe_run(
        &self,
        probe: &Probe,
        source: &Provision,
    ) -> Result<String, ExecutorError> {
        let destination = crate::policy::load_bound_product_backup(
            &self.anchor,
            &probe.intent.host_id,
            &probe.intent.host_epoch,
            probe.backup_policy_digest.as_ref(),
        )?;
        let layout = SiteLayout::derive(&probe.intent.site_id);
        let level = crate::capture::site_level(&layout)?;
        crate::store_network::check_repository(
            &self.anchor,
            &destination,
            &probe.intent.site_id,
            &level,
        )?;
        let store = restore::ProductStore {
            anchor: &self.anchor,
            policy: &destination,
            site: &probe.intent.site_id,
            site_level: &level,
        };
        let target = restore::ProbeTarget {
            account: &layout.account,
            hostname: source.intent.hostname.as_str(),
            snapshot: probe.intent.snapshot_id.as_str(),
            probe: &probe.intent.probe_account,
        };
        let (receipt, state) = restore::run_probe_with(&target, &store, probe.started_at.get());
        Ok(encode_probe(&receipt, state))
    }

    fn probe_run(&self, probe: &Probe, source: &Provision) -> Result<String, ExecutorError> {
        if cfg!(rustiron_profile = "product") {
            return self.product_probe_run(probe, source);
        }
        let backup = crate::policy::load_bound_backup(
            &self.anchor,
            &probe.intent.host_id,
            &probe.intent.host_epoch,
            probe.backup_policy_digest.as_ref(),
        )?;
        let layout = SiteLayout::derive(&probe.intent.site_id);
        let repository = format!("{}/{}", backup.repository_base, layout.account);
        let store = backup.store_address.to_string();
        let target = restore::ProbeTarget {
            account: &layout.account,
            hostname: source.intent.hostname.as_str(),
            snapshot: probe.intent.snapshot_id.as_str(),
            probe: &probe.intent.probe_account,
        };
        let lab = restore::LabStore {
            repository: &repository,
            store_address: &store,
        };
        let (receipt, state) = restore::run_probe(&target, &lab, probe.started_at.get());
        Ok(encode_probe(&receipt, state))
    }

    /// Runs the provision step the journal records as current.
    #[allow(clippy::too_many_arguments)]
    fn provision_step(
        &mut self,
        action: &AdminAction,
        provision: &Provision,
        import: Option<&rustiron_journal::Import>,
        site_clone: Option<&rustiron_journal::SiteClone>,
        app: Option<&rustiron_journal::AppFacts>,
        app_fullstack: Option<&rustiron_journal::AppFullstackSpec>,
        proxy: bool,
    ) -> Result<(), ExecutorError> {
        let last = provision.steps.last().ok_or(ExecutorError::BindingDenied)?;
        let layout = SiteLayout {
            account: action.account.clone(),
            root: action.root.clone(),
        };
        // W598 (D-099) & W658 (D-102 C2): a modern app site, known from its journaled app row.
        if let Some(facts) = app {
            let app_db = app_fullstack
                .map(|s| s.database)
                .unwrap_or(rustiron_contracts::approval::AppDatabase::Sqlite);
            let operation = &provision.intent.operation_id;
            return match last.step {
                step if crate::app_site::skips(step, app_db) => Err(ExecutorError::BindingDenied),
                ProvisionStep::Database => {
                    let secret = crate::app_site::run_database_step(&layout, app_db)?;
                    self.password = Some((operation.clone(), secret));
                    Ok(())
                }
                ProvisionStep::Credentials => {
                    let secret = match self.password.take() {
                        Some((id, secret)) if &id == operation => secret,
                        _ => return Err(ExecutorError::StepFailed),
                    };
                    crate::app_site::run_credentials_step(&layout, app_db, &secret)
                }
                ProvisionStep::Recipe | ProvisionStep::Verify => {
                    crate::app_site::run_provision_step(last.step, &layout, facts, app_fullstack)
                }
                _ => self.shared_provision_step(provision, last, &layout),
            };
        }
        // W572 (D-095): a proxy site, known from its journaled routes. Its
        // Recipe and Verify are its own; the executor journals the skipped
        // steps without asking the helper, so a request for one is refused.
        if proxy {
            return match last.step {
                ProvisionStep::Recipe | ProvisionStep::Verify => {
                    crate::proxy_site::run_step(last.step, &layout)
                }
                step if crate::proxy_site::skips(step) => Err(ExecutorError::BindingDenied),
                _ => self.shared_provision_step(provision, last, &layout),
            };
        }
        // W499 (D-078): a clone's open Recipe step runs its open clone step,
        // read from the journal; its Verify is the import Verify.
        if let Some(clone) = site_clone {
            return match last.step {
                ProvisionStep::Recipe => {
                    let open = clone
                        .steps
                        .last()
                        .filter(|record| record.state == StepState::Intent)
                        .ok_or(ExecutorError::BindingDenied)?;
                    crate::staging_clone::run_clone_step(
                        open.step,
                        &crate::staging_clone::CloneStepContext {
                            anchor: &self.anchor,
                            layout: &layout,
                            hostname: &provision.intent.hostname,
                            facts: &clone.facts,
                        },
                    )
                }
                ProvisionStep::Verify => {
                    crate::import::verify_import(&layout, &provision.intent.hostname, false)
                }
                _ => self.shared_provision_step(provision, last, &layout),
            };
        }
        // W446 (D-053): an import's open Recipe step runs its open import
        // step, read from the journal; W451: its Verify runs the import Verify.
        if let Some(import) = import {
            return match last.step {
                ProvisionStep::Recipe => {
                    let open = import
                        .steps
                        .last()
                        .filter(|record| record.state == StepState::Intent)
                        .ok_or(ExecutorError::BindingDenied)?;
                    crate::import::run_import_step(
                        open.step,
                        &crate::import::ImportStepContext {
                            layout: &layout,
                            site_id: &provision.intent.site_id,
                            hostname: &provision.intent.hostname,
                            facts: &import.facts,
                            owner: self.anchor.owner_uid,
                        },
                    )
                }
                // W451: the import's own Verify.
                ProvisionStep::Verify => crate::import::verify_import(
                    &layout,
                    &provision.intent.hostname,
                    import.facts.is_static(),
                ),
                _ => self.shared_provision_step(provision, last, &layout),
            };
        }
        self.shared_provision_step(provision, last, &layout)
    }

    /// A provision step that a site provision and an import share.
    fn shared_provision_step(
        &mut self,
        provision: &Provision,
        last: &rustiron_journal::StepRecord,
        layout: &SiteLayout,
    ) -> Result<(), ExecutorError> {
        let record = Record::Provision(provision);
        let allocated = match last.step {
            ProvisionStep::Account => planned(record, "uid=")?,
            ProvisionStep::Labels => planned(record, "level=s0:c")?,
            _ => 0,
        };
        let recipe = step_recipe(provision, last.step)?;
        let owner = self.anchor.owner_uid;
        let loaded = crate::policy::load(
            &crate::files::open_trusted_directory(&self.anchor.policy_dir, owner)?,
            owner,
        )?;
        let provisioning = loaded
            .policy
            .provisioning
            .ok_or(ExecutorError::Unavailable)?;
        let quota = journaled_quota(last, provisioning.quota)?;
        let operation = &provision.intent.operation_id;
        let mut password = match self.password.take() {
            Some((id, secret)) if &id == operation => Some(secret),
            _ => None,
        };
        let outcome = durable::run_site_step(
            last.step,
            &durable::SiteStep {
                layout,
                allocated,
                recipe,
                hostname: &provision.intent.hostname,
                wordpress: &provisioning.wordpress_713_sha256,
                recipes_dir: &self.anchor.recipes_dir,
                quota,
                site_uid: durable::journaled_uid(provision),
            },
            &mut password,
        );
        self.password = password.map(|secret| (operation.clone(), secret));
        outcome
    }
}

/// The recipe that a provision step runs with: the one that the journal's
/// Recipe step record names. The Recipe and Verify steps read it, so both
/// refuse a provision without that record (W399: the Verify step had read
/// its own record, which names no recipe). Earlier steps do not read it.
pub(crate) fn step_recipe(
    provision: &Provision,
    step: ProvisionStep,
) -> Result<rustiron_contracts::approval::SiteRecipe, ExecutorError> {
    let recorded = provision
        .steps
        .iter()
        .find(|record| record.step == ProvisionStep::Recipe)
        .and_then(|record| record.resource.rsplit_once(" recipe="))
        .and_then(|(_, name)| durable::recipe_from_name(name));
    match (step, recorded) {
        (_, Some(recipe)) => Ok(recipe),
        (ProvisionStep::Recipe | ProvisionStep::Verify, None) => Err(ExecutorError::BindingDenied),
        (_, None) => Ok(rustiron_contracts::approval::SiteRecipe::Wordpress713V1),
    }
}

/// W356: the product write gate as the helper applies it, right after the
/// bind. A closed gate is `NOT_ADMITTED_FOR_EFFECT`: the executor records
/// the capture `failed` with no snapshot.
pub(crate) fn gate(writes_enabled: bool) -> Result<(), ExecutorError> {
    if writes_enabled {
        Ok(())
    } else {
        Err(ExecutorError::NotAdmitted)
    }
}

/// W356: what the helper runs for a product capture after the bind: the
/// write gate, then design steps 2 to 10 for `site` against the bound
/// projection `policy`. `Err` is a refusal before anything started (the
/// closed gate). `Ok` is the capture outcome line that the executor
/// journals; it is uncertain for every failure from the snapshot worker's
/// start on. Public so the root lab test drives the same code without a
/// journal; it never chooses a path, tag or argument.
pub fn product_capture_effects(
    anchor: &TrustAnchor,
    policy: &rustiron_contracts::approval::ProductBackupPolicy,
    site: &rustiron_contracts::approval::SiteId,
    operation: &Id,
    frozen: bool,
) -> Result<String, ExecutorError> {
    product_capture_effects_for(anchor, policy, site, operation, frozen, None)
}

/// W601 (D-096/P30): as [`product_capture_effects`] with optional app metadata.
pub fn product_capture_effects_for(
    anchor: &TrustAnchor,
    policy: &rustiron_contracts::approval::ProductBackupPolicy,
    site: &rustiron_contracts::approval::SiteId,
    operation: &Id,
    frozen: bool,
    app: Option<&rustiron_journal::AppFacts>,
) -> Result<String, ExecutorError> {
    product_capture_effects_for_app_db(anchor, policy, site, operation, frozen, app, None)
}

/// W658 (D-102 C2): as [`product_capture_effects_for`] with explicit modern app
/// database engine selection (`none`/`sqlite`/`mariadb`/`postgresql_18`).
#[allow(clippy::too_many_arguments)]
pub fn product_capture_effects_for_app_db(
    anchor: &TrustAnchor,
    policy: &rustiron_contracts::approval::ProductBackupPolicy,
    site: &rustiron_contracts::approval::SiteId,
    operation: &Id,
    frozen: bool,
    app: Option<&rustiron_journal::AppFacts>,
    app_database: Option<rustiron_contracts::approval::AppDatabase>,
) -> Result<String, ExecutorError> {
    gate(crate::write_gate::PRODUCT_WRITES_ENABLED)?;
    let layout = SiteLayout::derive(site);
    let outcome = crate::product_capture::capture_site_for_app_db(
        anchor,
        policy,
        site,
        &layout,
        operation,
        frozen,
        app,
        app_database,
    );
    Ok(encode_capture(&outcome))
}

/// Capture outcome as one JSON line.
/// A manifest that would push the reply past [`MAX_ADMIN_REPLY_BYTES`] is
/// dropped: the capture is still reported, only unrecorded (W203).
pub fn encode_capture(outcome: &crate::capture::CaptureOutcome) -> String {
    use crate::capture::CaptureOutcome as O;
    match outcome {
        O::Succeeded(snapshot) => {
            let mut base = serde_json::json!({"outcome": "succeeded",
                "id": snapshot.id, "files": snapshot.files, "bytes": snapshot.bytes,
                "consistency": {"label": snapshot.consistency.label(),
                    "reason": snapshot.consistency.reason()}});
            // W391: at most 1024 object lines; it always fits the reply.
            if let Some(evidence) = &snapshot.retention {
                base["retention"] = crate::retention_evidence::to_relay(evidence);
            }
            let with = snapshot.manifest.as_ref().and_then(|built| {
                let text = std::str::from_utf8(&built.bytes).ok()?;
                let mut value = base.clone();
                value["manifest"] = serde_json::json!({"sha256": built.sha256,
                    "truncated": built.truncated, "text": text});
                let line = value.to_string();
                (line.len() + 4 <= MAX_ADMIN_REPLY_BYTES).then_some(line)
            });
            return with.unwrap_or_else(|| base.to_string());
        }
        O::NotStarted(error) => {
            serde_json::json!({"outcome": "not_started", "error": error.code()})
        }
        O::Uncertain { error, snapshot } => serde_json::json!({"outcome": "uncertain",
            "error": error.code(), "snapshot": snapshot}),
    }
    .to_string()
}

/// Reads a capture reply. Anything unrecognised is uncertain: the helper may
/// have written a snapshot, so it is never read as a known failure.
/// A relayed manifest is re-verified against `root`; a bad one is dropped
/// without changing the outcome.
pub fn decode_capture(payload: &str, root: &str) -> crate::capture::CaptureOutcome {
    decode_capture_for(payload, root, false)
}

/// As [`decode_capture`] for a capture of the frozen recipe (W258) or not: a
/// frozen capture's missing or unknown label reads as `freeze_not_held`,
/// and only a frozen capture may carry that reason.
pub fn decode_capture_for(
    payload: &str,
    root: &str,
    frozen: bool,
) -> crate::capture::CaptureOutcome {
    decode_capture_for_kind(payload, root, frozen, false)
}

/// W601 (D-096/P30): as [`decode_capture_for`] accepting `data/` + SQLite
/// bundle manifests when `is_app` is `true`.
pub fn decode_capture_for_kind(
    payload: &str,
    root: &str,
    frozen: bool,
    is_app: bool,
) -> crate::capture::CaptureOutcome {
    use crate::capture::{CaptureOutcome as O, CapturedSnapshot};
    let uncertain = O::Uncertain {
        error: ExecutorError::Unavailable,
        snapshot: None,
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(payload) else {
        return uncertain;
    };
    let error = value["error"]
        .as_str()
        .and_then(ExecutorError::from_code)
        .unwrap_or(ExecutorError::Unavailable);
    let id = |field: &serde_json::Value| {
        field
            .as_str()
            .filter(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
            .map(str::to_owned)
    };
    match value["outcome"].as_str() {
        Some("succeeded") => match id(&value["id"]) {
            Some(id) => O::Succeeded(CapturedSnapshot {
                retention: crate::retention_evidence::from_relay(&value["retention"], &id),
                id,
                files: value["files"].as_u64(),
                bytes: value["bytes"].as_u64(),
                manifest: relayed(&value["manifest"], root, is_app),
                consistency: relayed_consistency(&value["consistency"], frozen),
            }),
            None => uncertain,
        },
        Some("not_started") => O::NotStarted(error),
        Some("uncertain") => O::Uncertain {
            error,
            snapshot: id(&value["snapshot"]),
        },
        _ => uncertain,
    }
}

/// W252: a relayed label; anything missing or unknown is never `matched`.
fn relayed_consistency(
    value: &serde_json::Value,
    frozen: bool,
) -> rustiron_journal::CaptureConsistency {
    use rustiron_journal::{CaptureConsistency as C, UnmatchedReason as R};
    let unknown = if frozen {
        R::FreezeNotHeld
    } else {
        R::MarkerUnavailable
    };
    match (value["label"].as_str(), &value["reason"]) {
        (Some("matched"), serde_json::Value::Null) if value.get("reason").is_some() => C::Matched,
        (Some("unmatched"), reason) if reason == "database_changed" => {
            C::Unmatched(R::DatabaseChanged)
        }
        (Some("unmatched"), reason) if reason == "marker_unavailable" => {
            C::Unmatched(R::MarkerUnavailable)
        }
        _ => C::Unmatched(unknown),
    }
}

fn relayed(value: &serde_json::Value, root: &str, is_app: bool) -> Option<crate::manifest::Built> {
    let (subdir, dump) = if is_app {
        ("data", crate::app_site::app_bundle_path(root))
    } else {
        ("html", crate::capture::dump_path(root))
    };
    crate::manifest::from_relay_for(
        value["text"].as_str()?.as_bytes().to_vec(),
        value["sha256"].as_str()?,
        value["truncated"].as_bool()?,
        root,
        subdir,
        &dump,
    )
}

fn probe_state_name(state: ProbeState) -> &'static str {
    match state {
        ProbeState::Running => "running",
        ProbeState::Passed => "passed",
        ProbeState::Failed => "failed",
        ProbeState::CleanupIncomplete => "cleanup_incomplete",
    }
}

/// Probe receipt and outcome as one JSON line.
pub fn encode_probe(receipt: &serde_json::Value, state: ProbeState) -> String {
    serde_json::json!({"state": probe_state_name(state), "receipt": receipt}).to_string()
}

/// Reads a probe reply; `None` when the outcome is unknown (the probe then
/// stays `running` for the admin cleanup). `running` is never a final state.
pub fn decode_probe(payload: &str) -> Option<(serde_json::Value, ProbeState)> {
    let mut value = serde_json::from_str::<serde_json::Value>(payload).ok()?;
    let state = [
        ProbeState::Passed,
        ProbeState::Failed,
        ProbeState::CleanupIncomplete,
    ]
    .into_iter()
    .find(|state| value["state"].as_str() == Some(probe_state_name(*state)))?;
    let receipt = value.get_mut("receipt")?.take();
    receipt.is_object().then_some((receipt, state))
}

/// The probe result the executor journals for a helper reply. A refusal
/// came before the helper created anything, so the probe is `failed` with
/// nothing to clean (W175: it used to stay `running` and block new probes).
/// An unreadable payload is an unknown outcome: the probe stays `running`
/// for `probe-cleanup`.
pub fn probe_outcome(
    reply: Reply,
    probe_account: &str,
) -> Result<(serde_json::Value, ProbeState), ExecutorError> {
    match reply {
        Reply::Done(payload) => payload
            .as_deref()
            .and_then(decode_probe)
            .ok_or(ExecutorError::Unavailable),
        Reply::Refused(error) => Ok((
            serde_json::json!({
                "receipt_schema": "rustiron-lab-restore-probe/1",
                "probe_account": probe_account,
                "refused": error.code(),
                "note": "the admin helper refused before creating anything; no check is claimed",
                "cleanup": {"status": "complete", "leftover_resources": 0, "removal_failures": 0, "unverified": []},
            }),
            ProbeState::Failed,
        )),
    }
}

/// Connections whose request line is still being read, at most (W186).
/// Well under the unit's `TasksMax`, which the steps' own processes share.
pub const MAX_PENDING_READS: usize = 8;
/// Whole-request read deadline: the executor writes its line at once.
pub const READ_DEADLINE: Duration = Duration::from_secs(5);
/// How long a reply write may block on a peer that does not read.
const REPLY_TIMEOUT: Duration = Duration::from_secs(5);

/// Reads one request line (bounded) within [`READ_DEADLINE`] in total, so a
/// slow writer cannot extend it byte by byte.
fn read_request(stream: &mut UnixStream) -> Result<Vec<u8>, ExecutorError> {
    let deadline = std::time::Instant::now() + READ_DEADLINE;
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; MAX_ADMIN_REQUEST_BYTES + 1];
    loop {
        let left = deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or(ExecutorError::InvalidRequest)?;
        stream
            .set_read_timeout(Some(left))
            .map_err(|_| ExecutorError::Unavailable)?;
        let room = MAX_ADMIN_REQUEST_BYTES + 1 - bytes.len();
        match stream.read(&mut chunk[..room]) {
            Ok(0) => return Ok(bytes),
            Ok(read) => {
                bytes.extend_from_slice(&chunk[..read]);
                if bytes.len() > MAX_ADMIN_REQUEST_BYTES {
                    return Ok(bytes);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(ExecutorError::InvalidRequest),
        }
    }
}

/// Serves `listener` forever: request lines are read on up to `max_reads`
/// threads at once (over that, a connection is refused with
/// `EXECUTOR_DEPENDENCY_UNAVAILABLE` at once), and every decision and effect
/// runs in order on the one thread that owns `helper`. Peer, authorization
/// and journal rules are those of [`Helper::handle`].
pub fn serve_helper(
    helper: &mut Helper,
    listener: &std::os::unix::net::UnixListener,
    max_reads: usize,
) -> Result<(), ExecutorError> {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };
    let reading = Arc::new(AtomicUsize::new(0));
    let (queue, requests) =
        mpsc::sync_channel::<(UnixStream, Result<Vec<u8>, ExecutorError>)>(max_reads.max(1));
    std::thread::scope(|scope| {
        scope.spawn(move || {
            for (stream, bytes) in requests {
                helper.answer(stream, bytes);
            }
        });
        let result = loop {
            let mut stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(_) => break Err(ExecutorError::Unavailable),
            };
            let taken = reading
                .fetch_add(1, Ordering::AcqRel)
                .checked_add(1)
                .is_some_and(|now| now <= max_reads);
            if !taken {
                reading.fetch_sub(1, Ordering::AcqRel);
            }
            if !taken {
                let _ = stream.set_write_timeout(Some(Duration::from_millis(100)));
                let _ = stream.write_all(b"EXECUTOR_DEPENDENCY_UNAVAILABLE\n");
                continue;
            }
            let (slot, queue) = (Arc::clone(&reading), queue.clone());
            let spawned = std::thread::Builder::new().spawn(move || {
                let bytes = read_request(&mut stream);
                slot.fetch_sub(1, Ordering::AcqRel);
                let _ = queue.send((stream, bytes));
            });
            if spawned.is_err() {
                reading.fetch_sub(1, Ordering::AcqRel);
            }
        };
        drop(queue);
        result
    })
}

/// Serves one connection with an unconfined helper (no peer domain check).
pub fn handle(anchor: &TrustAnchor, stream: UnixStream) {
    Helper::new(anchor.clone(), None).handle(stream);
}

/// Routes one provision step: through the helper when a socket is enrolled,
/// otherwise in this process (the recorded D-016 lab mode).
pub fn route(
    socket: Option<&Path>,
    admin: &AdminRequest,
    direct: impl FnOnce() -> Result<(), ExecutorError>,
) -> Result<(), ExecutorError> {
    match socket {
        Some(socket) => match request(socket, admin)? {
            Reply::Done(None) => Ok(()),
            Reply::Done(Some(_)) => Err(ExecutorError::StepFailed),
            Reply::Refused(error) => Err(error),
        },
        None => direct(),
    }
}

/// W222: waits for the helper socket to exist (a restarting helper removes
/// and recreates it), checking up to `attempts` times `pause` apart, without
/// connecting. Absent throughout is `HelperUnreachable`.
pub fn reach(socket: &Path, attempts: u32, pause: Duration) -> Result<(), ExecutorError> {
    use std::os::unix::fs::FileTypeExt;
    for attempt in 0..attempts {
        if std::fs::symlink_metadata(socket).is_ok_and(|meta| meta.file_type().is_socket()) {
            return Ok(());
        }
        if attempt == 0 {
            eprintln!(
                "admin helper socket {} absent; waiting for a restarting helper",
                socket.display()
            );
        }
        if attempt + 1 < attempts {
            std::thread::sleep(pause);
        }
    }
    eprintln!(
        "admin helper unreachable at {}: it is stopped or did not come back; nothing was sent",
        socket.display()
    );
    Err(ExecutorError::HelperUnreachable)
}

/// A helper reply the executor could read.
#[derive(Debug, Eq, PartialEq)]
pub enum Reply {
    /// The step ran; its payload, if any.
    Done(Option<String>),
    /// The helper answered with a known error code. For a capture or probe
    /// this is a refusal before anything ran (the run's own failures come
    /// back as a payload).
    Refused(ExecutorError),
}

/// Executor client: sends one request and reads one reply. `Err` means the
/// reply was lost or unreadable: the step's outcome is unknown.
pub fn request(socket: &Path, request: &AdminRequest) -> Result<Reply, ExecutorError> {
    let unavailable = |_| ExecutorError::Unavailable;
    // No connection means nothing was sent, so nothing ran: a refusal, not
    // an unknown outcome (W175: a helper that was down left captures
    // uncertain and blocking).
    let Ok(mut stream) = UnixStream::connect(socket) else {
        return Ok(Reply::Refused(ExecutorError::HelperUnreachable));
    };
    let wait = match request.step {
        AdminStep::CaptureRun
        | AdminStep::ProbeRun
        | AdminStep::CertificateIssue
        | AdminStep::CertificateRenew
        | AdminStep::SiteCredentialRotate => RUN_TIMEOUT,
        _ => TIMEOUT,
    };
    stream.set_read_timeout(Some(wait)).map_err(unavailable)?;
    stream.write_all(&request.encode()).map_err(unavailable)?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(unavailable)?;
    let mut reply = String::new();
    stream
        .take(MAX_ADMIN_REPLY_BYTES as u64 + 1)
        .read_to_string(&mut reply)
        .map_err(unavailable)?;
    parse_reply(&reply)
}

/// `ok\n` is success, `ok <payload>\n` success with a payload, a known
/// error code a refusal; anything else is an unknown outcome (`Err`).
pub fn parse_reply(reply: &str) -> Result<Reply, ExecutorError> {
    match decode_reply(reply).ok_or(ExecutorError::Unavailable)? {
        ReplyLine::Done(payload) => Ok(Reply::Done(payload.map(str::to_owned))),
        ReplyLine::Code(code) => ExecutorError::from_code(code)
            .map(Reply::Refused)
            .ok_or(ExecutorError::Unavailable),
    }
}

#[cfg(test)]
#[path = "admin_helper_tests.rs"]
mod tests;

/// W355: one OLS step of a bootstrap activation. The helper re-derives the
/// bootstrap facts from the journal history it reread, the include
/// directory and the live host at the moment of the request; the
/// executor's choice of mode is never trusted.
/// - preflight: the facts before the switch (no `current`), or `DRIFT`;
/// - config test: as for any activation;
/// - start: the facts with `current` exactly the journaled target, then
///   `systemctl start`; otherwise `DRIFT` and nothing runs;
/// - verify: the target's sites answer, the parent is unchanged, WebAdmin
///   is closed and the listener listens;
/// - stop (compensation only): `current` is absent or the target, then
///   `systemctl stop` and a bounded wait for the stopped state;
/// - confirm (W382, D-033; any unresolved state): the facts of the
///   bootstrap predecessor ([`crate::ols::BootstrapFacts::predecessor_confirmed`]),
///   or `DRIFT` with the facts in the system journal. It reads only.
fn bootstrap_step(
    step: AdminStep,
    operation: &Operation,
    records: &OperationRecords,
    policy: &crate::policy::OlsPolicy,
) -> Result<Option<String>, ExecutorError> {
    let intent = &operation.intent;
    let ports = policy.ports()?;
    let target = (
        intent.target_generation.clone(),
        intent.target_digest.clone(),
    );
    let facts = || -> Result<crate::ols::BootstrapFacts, ExecutorError> {
        // W372: an adoption establishes its generation over an empty history.
        let history = crate::ols::with_adoption(
            records
                .ols_history
                .clone()
                .ok_or(ExecutorError::BindingDenied)?,
            records.ols_adoption.clone(),
        );
        let adopted: Vec<&str> = policy.adopted.iter().map(|s| s.name.as_str()).collect();
        crate::ols::BootstrapFacts::observe(
            history,
            &crate::ols::open_include()?,
            &policy.parent_sha256,
            &ports,
            &adopted,
        )
    };
    let refuse = |facts: &crate::ols::BootstrapFacts| {
        eprintln!(
            "{{\"scope\":\"ols_bootstrap\",\"step\":\"{}\",\"facts\":\"{facts:?}\"}}",
            step.name()
        );
        Err(ExecutorError::Drift)
    };
    match step {
        AdminStep::OlsPreflight => {
            let facts = facts()?;
            if !facts.hold(crate::ols::BootstrapStage::BeforeSwitch) {
                return refuse(&facts);
            }
            Ok(None)
        }
        AdminStep::OlsConfigTest => crate::ols::config_test().map(|()| None),
        AdminStep::OlsStart => {
            let facts = facts()?;
            if !facts.hold(crate::ols::BootstrapStage::Start(&target)) {
                return refuse(&facts);
            }
            provision::run("/usr/bin/systemctl", &["start", crate::ols::OLS_UNIT]).map(|()| None)
        }
        AdminStep::OlsVerify => {
            let include = crate::ols::open_include()?;
            if crate::ols::observe(&include)? != target {
                return Err(ExecutorError::PreconditionChanged);
            }
            let managed = crate::ols::managed_accounts(&include, &target.0)?;
            let provisions: Vec<_> = records
                .served
                .iter()
                .map(|p| {
                    let site = &p.intent.site_id;
                    (
                        site.clone(),
                        p.intent.hostname.clone(),
                        records.served_aliases.get(site.as_str()).cloned(),
                    )
                })
                .collect();
            let sites = crate::ols::served_from(&managed, &provisions, &records.ejected)?;
            durable::probe_with_retry(policy, &sites)?;
            verify_alias_tls(
                policy,
                &include,
                &target.0,
                &sites,
                &records.certificate_pairs,
                false,
                None,
            )?;
            durable::parent_unchanged(policy)?;
            if !server_checks(policy)?.webadmin_closed {
                return Err(ExecutorError::Drift);
            }
            Ok(None)
        }
        AdminStep::OlsStop => {
            match crate::ols::observe_current(&crate::ols::open_include()?)? {
                None => {}
                Some(live) if live == target => {}
                Some(_) => return Err(ExecutorError::Drift),
            }
            crate::ols::stop_and_wait(&ports).map(|()| None)
        }
        AdminStep::OlsBootstrapConfirm => {
            let facts = facts()?;
            if !facts.predecessor_confirmed() {
                return refuse(&facts);
            }
            Ok(None)
        }
        _ => Err(ExecutorError::BindingDenied),
    }
}

/// The helper-side drift checks from the enrolled OLS policy.
pub(crate) fn server_checks(
    policy: &crate::policy::OlsPolicy,
) -> Result<crate::ols::ServerChecks, ExecutorError> {
    let adopted: Vec<&str> = policy.adopted.iter().map(|s| s.name.as_str()).collect();
    let listener = policy
        .address
        .parse::<std::net::SocketAddr>()
        .map_err(|_| ExecutorError::Unavailable)?
        .port();
    Ok(crate::ols::ServerChecks::observe(
        &policy.parent_sha256,
        (policy.webadmin_port, listener),
        &adopted,
    ))
}

/// W457 (D-057): the open scrub of an ended import, read from the journal.
/// The request names the import's operation; the journal allows at most one
/// open scrub for it. W459: a signed scrub also runs on a succeeded import.
/// The paths come from the journaled site.
/// W501 (D-078): the open scrub of a clone quarantined by a failed clone
/// step, read from the journal.
fn clone_scrub(
    action: &AdminAction,
    provision: &Provision,
    site_clone: Option<&rustiron_journal::SiteClone>,
) -> Result<(), ExecutorError> {
    // W501: after a failed clone step; W538 (D-078 signed clone scrub): or
    // under an open signed scrub, also when an interruption left the last
    // clone step at `intent`.
    let open = site_clone.is_some_and(|clone| {
        clone.scrub == Some(StepState::Intent)
            && (clone.steps.last().map(|record| record.state) == Some(StepState::Failed)
                || clone.signed_scrub == Some(StepState::Intent))
    }) && provision.state == ProvisionState::Quarantined;
    if !open {
        return Err(ExecutorError::BindingDenied);
    }
    crate::staging_clone::scrub_site(&SiteLayout {
        account: action.account.clone(),
        root: action.root.clone(),
    })
}

fn import_scrub(
    action: &AdminAction,
    provision: &Provision,
    import: Option<&rustiron_journal::Import>,
) -> Result<(), ExecutorError> {
    let open = import
        .and_then(|import| {
            import
                .scrubs
                .iter()
                .find(|scrub| scrub.state == StepState::Intent)
        })
        .filter(|scrub| match scrub.origin {
            rustiron_journal::ScrubOrigin::FailedStep => {
                scrub.operation_id == provision.intent.operation_id
                    && provision.state == ProvisionState::Quarantined
            }
            rustiron_journal::ScrubOrigin::Signed => matches!(
                provision.state,
                ProvisionState::Quarantined | ProvisionState::Succeeded
            ),
        });
    if open.is_none() {
        return Err(ExecutorError::BindingDenied);
    }
    crate::import::scrub_site(&SiteLayout {
        account: action.account.clone(),
        root: action.root.clone(),
    })
}
