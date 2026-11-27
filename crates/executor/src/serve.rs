//! Unix-socket front end: frames are read concurrently (bounded in total and
//! per peer UID, W184), then processed one at a time by the single thread
//! that owns the executor, so the journal keeps exactly one writer.
//!
//! The requester is the kernel-reported peer UID; the executor's policy decides
//! whether that UID is enrolled. Socket permissions only limit who can connect.

use std::{
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::Path,
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use rustiron_contracts::{
    ErrorCode, Id, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, Timestamp,
    approval::{
        PlanKind, PreparedPlan, ProductBackupPlan, ProductBackupTarget, StandingCapturePlan,
    },
    execution::{
        OutcomeState, StatusQuery, SubmissionReply, decode_evidence_query, decode_status_query,
        decode_submission, status_query_request_id,
    },
    local::{self, DEADLINE},
};
use rustiron_journal::{
    Admitted, AppLifecycle, AppRelease, AppReleaseState, Capture, CaptureState, Certificate,
    CertificateState, CloneScrubGrant, CredentialRotateState, CredentialRotation, Deletion,
    DnsChange, DnsImport, ImportScrub, Operation, Probe, ProbeState, Provision, ProvisionState,
    QuotaChange, ReadoptState, Readoption, RecordedState, Renewal, RestoreState, Retirement,
    SiteRestore, SiteUpdate, StepState, UpdateState,
};

use crate::{AdmissionRequest, Executor, ExecutorError, files};

/// Binds a fresh socket in a trusted directory; never removes an existing entry.
/// The socket is mode 0660 with the process's group, so only members of the
/// service's requester group can connect (connection is not authority: the
/// enrolled peer UID check in [`handle`] still decides).
pub fn bind(path: &Path, owner: u32) -> Result<UnixListener, ExecutorError> {
    let parent = path.parent().ok_or(ExecutorError::AccessDenied)?;
    files::open_traversable_directory(parent, owner)?;
    let listener = UnixListener::bind(path).map_err(|_| ExecutorError::Unavailable)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
        .map_err(|_| ExecutorError::Unavailable)?;
    Ok(listener)
}

/// Bounds on connections whose request frame is still being read.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Connections being read at once, across all peers.
    pub total: usize,
    /// Connections being read at once from one peer UID.
    pub per_peer: usize,
}

/// Default limits: an idle peer can hold at most `per_peer` read slots for
/// one deadline each; other peers and the processor are never blocked.
pub const LIMITS: Limits = Limits {
    total: 32,
    per_peer: 4,
};

/// How long a refusal or reply written from the accept loop may take.
const REFUSAL_DEADLINE: Duration = Duration::from_millis(100);

#[derive(Default)]
struct Slots {
    total: usize,
    per_peer: std::collections::HashMap<u32, usize>,
}

impl Slots {
    fn take(&mut self, limits: Limits, uid: u32) -> bool {
        let peer = self.per_peer.entry(uid).or_insert(0);
        if self.total >= limits.total || *peer >= limits.per_peer {
            return false;
        }
        *peer += 1;
        self.total += 1;
        true
    }

    fn release(&mut self, uid: u32) {
        if let Some(peer) = self.per_peer.get_mut(&uid) {
            *peer -= 1;
            if *peer == 0 {
                self.per_peer.remove(&uid);
            }
        }
        self.total -= 1;
    }
}

struct Pending {
    stream: UnixStream,
    uid: u32,
    frame: Result<Vec<u8>, ErrorCode>,
}

/// W464: how often the executor looks for due certificate renewals.
const RENEW_TICK: std::time::Duration = std::time::Duration::from_secs(600);

/// Serves connections with [`LIMITS`].
pub fn serve(executor: &mut Executor, listener: &UnixListener) -> Result<(), ExecutorError> {
    serve_with(executor, listener, LIMITS)
}

/// Accepts connections and reads each frame on its own thread under the
/// limits; a connection over a limit is refused with `UNAVAILABLE` at once.
/// Complete frames are processed in arrival order by one thread holding the
/// only `&mut Executor`, so admission and the journal are unchanged.
pub fn serve_with(
    executor: &mut Executor,
    listener: &UnixListener,
    limits: Limits,
) -> Result<(), ExecutorError> {
    let slots = Arc::new(Mutex::new(Slots::default()));
    let (queue, frames) = mpsc::sync_channel::<Pending>(limits.total.max(1));
    std::thread::scope(|scope| {
        scope.spawn(move || {
            // W464 (D-060): between requests, the one thread holding the
            // executor renews due certificates, first a minute after start
            // and then every RENEW_TICK.
            let mut next_renewal = Instant::now() + std::time::Duration::from_secs(60);
            loop {
                match frames.recv_timeout(std::time::Duration::from_secs(60)) {
                    Ok(pending) => {
                        let bytes = reply_bytes(executor, pending.uid, pending.frame);
                        let mut stream = pending.stream;
                        std::thread::spawn(move || {
                            send(&mut stream, bytes, Instant::now() + DEADLINE)
                        });
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
                if Instant::now() >= next_renewal {
                    if let Err(error) = executor.renew_due() {
                        eprintln!(
                            "{}",
                            serde_json::json!({"scope": "certificate_renew", "error": error.code()})
                        );
                    }
                    next_renewal = Instant::now() + RENEW_TICK;
                }
            }
        });
        let result = loop {
            let Ok((stream, _)) = listener.accept() else {
                break Err(ExecutorError::Unavailable);
            };
            dispatch(stream, limits, &slots, &queue);
        };
        drop(queue);
        result
    })
}

fn dispatch(
    mut stream: UnixStream,
    limits: Limits,
    slots: &Arc<Mutex<Slots>>,
    queue: &mpsc::SyncSender<Pending>,
) {
    let Ok(peer) = rustix::net::sockopt::socket_peercred(&stream) else {
        refuse(&mut stream, ExecutorError::PeerDenied);
        return;
    };
    let uid = peer.uid.as_raw();
    let taken = slots.lock().is_ok_and(|mut slots| slots.take(limits, uid));
    if !taken {
        refuse(&mut stream, ExecutorError::Unavailable);
        return;
    }
    let slots = Arc::clone(slots);
    let queue = queue.clone();
    std::thread::spawn(move || {
        let frame = local::read_frame(
            &mut stream,
            MAX_REQUEST_BYTES,
            ErrorCode::RequestTooLarge,
            Instant::now() + DEADLINE,
        );
        if let Ok(mut slots) = slots.lock() {
            slots.release(uid);
        }
        let _ = queue.send(Pending { stream, uid, frame });
    });
}

fn refuse(stream: &mut UnixStream, error: ExecutorError) {
    if let Ok(bytes) = serde_json::to_vec(&error_reply(None, error)) {
        send(stream, Some(bytes), Instant::now() + REFUSAL_DEADLINE);
    }
    // Discard what the client already sent, without waiting, so closing does
    // not reset the connection before the refusal is read. A client that
    // writes later may see a reset instead, which is still a refusal.
    if stream.set_nonblocking(true).is_ok() {
        let mut sink = [0_u8; 8192];
        let mut left = MAX_REQUEST_BYTES + 4;
        while left > 0 {
            match std::io::Read::read(stream, &mut sink) {
                Ok(0) | Err(_) => break,
                Ok(read) => left = left.saturating_sub(read),
            }
        }
    }
}

fn send(stream: &mut UnixStream, bytes: Option<Vec<u8>>, deadline: Instant) -> bool {
    bytes.is_some_and(|bytes| {
        local::write_frame(
            stream,
            &bytes,
            MAX_RESPONSE_BYTES,
            ErrorCode::ResponseTooLarge,
            deadline,
        )
        .is_ok()
    })
}

/// Handles one framed submission on the calling thread; false means no
/// complete reply was delivered.
pub fn handle(executor: &mut Executor, mut stream: UnixStream) -> bool {
    let deadline = Instant::now() + DEADLINE;
    let bytes = match rustix::net::sockopt::socket_peercred(&stream) {
        Ok(peer) => {
            let frame = local::read_frame(
                &mut stream,
                MAX_REQUEST_BYTES,
                ErrorCode::RequestTooLarge,
                deadline,
            );
            reply_bytes(executor, peer.uid.as_raw(), frame)
        }
        Err(_) => serde_json::to_vec(&error_reply(None, ExecutorError::PeerDenied)).ok(),
    };
    // The request had its own deadline; the reply gets a fresh one, since a
    // provision runs for many seconds between reading and replying.
    send(&mut stream, bytes, Instant::now() + DEADLINE)
}

/// The reply for one read frame (or its read error), from the processor.
fn reply_bytes(
    executor: &mut Executor,
    peer_uid: u32,
    frame: Result<Vec<u8>, ErrorCode>,
) -> Option<Vec<u8>> {
    match frame {
        Ok(frame) => match decode_status_query(&frame) {
            Ok(query) => serde_json::to_vec(&status_query(executor, peer_uid, query)),
            Err(error) => match status_query_request_id(&frame) {
                Ok(request_id) => serde_json::to_vec(&serde_json::json!({
                    "schema_version": 1, "request_id": request_id, "status": "error",
                    "data": null, "error": error.api_error(),
                })),
                Err(_) => match decode_evidence_query(&frame) {
                    Ok(query) => serde_json::to_vec(&evidence_query(executor, peer_uid, query)),
                    Err(_) => serde_json::to_vec(&process(executor, &frame, peer_uid)),
                },
            },
        },
        Err(_) => serde_json::to_vec(&error_reply(None, ExecutorError::InvalidRequest)),
    }
    .ok()
}

fn process(executor: &mut Executor, frame: &[u8], peer_uid: u32) -> SubmissionReply {
    let Ok(submission) = decode_submission(frame) else {
        return error_reply(None, ExecutorError::InvalidRequest);
    };
    let operation_id = submission.operation_id.clone();
    // W686: one admission request; each plan kind below decides which verb receives it.
    let request = AdmissionRequest {
        peer_uid,
        plan: submission.plan,
        grant: submission.grant,
        signature: submission.signature.as_bytes(),
        operation_id: submission.operation_id,
        idempotency_key: submission.idempotency_key,
        now: system_time(),
    };
    match route(submission.plan) {
        Route::SiteClone => {
            // W499 (D-078): the clone needs the product store; a lab build
            // stops every clone before intent.
            if !cfg!(rustiron_profile = "product") {
                let error = executor
                    .preflight_site_clone(&request)
                    .err()
                    .unwrap_or(ExecutorError::NotAdmitted);
                return error_reply(Some(operation_id), error);
            }
            admission_reply(
                executor.site_clone(&request),
                executor,
                peer_uid,
                &operation_id,
            )
        }
        Route::StandingCapture => admission_reply(
            executor.product_standing_capture(&request),
            executor,
            peer_uid,
            &operation_id,
        ),
        Route::ProductCapture => admission_reply(
            executor.product_backup_capture(&request),
            executor,
            peer_uid,
            &operation_id,
        ),
        Route::ProductProbe => admission_reply(
            executor.product_restore_probe(&request),
            executor,
            peer_uid,
            &operation_id,
        ),
        Route::Probe => admission_reply(
            executor.restore_probe(&request),
            executor,
            peer_uid,
            &operation_id,
        ),
        Route::Capture => admission_reply(
            executor.backup_capture(&request),
            executor,
            peer_uid,
            &operation_id,
        ),
        Route::Readopt => admission_reply(
            executor.readopt(&request),
            executor,
            peer_uid,
            &operation_id,
        ),
        Route::Eject => admission_reply(
            executor.eject_site(&request),
            executor,
            peer_uid,
            &operation_id,
        ),
        Route::Ols => admission_reply(
            executor.activate_ols(&request),
            executor,
            peer_uid,
            &operation_id,
        ),
        Route::Certificate => admission_reply(
            executor.certificate(&request),
            executor,
            peer_uid,
            &operation_id,
        ),
        Route::SiteUpdate => admission_reply(
            executor.update_site(&request),
            executor,
            peer_uid,
            &operation_id,
        ),
        Route::Retire => admission_reply(
            executor.retire_site(&request),
            executor,
            peer_uid,
            &operation_id,
        ),
        Route::Quota => admission_reply(
            executor.change_quota(&request),
            executor,
            peer_uid,
            &operation_id,
        ),
        Route::CredentialRotate => admission_reply(
            executor.rotate_site_credentials(&request),
            executor,
            peer_uid,
            &operation_id,
        ),
        Route::Restore => admission_reply(
            executor.restore_site(&request),
            executor,
            peer_uid,
            &operation_id,
        ),
        Route::DnsChange => admission_reply(
            executor.change_dns(&request),
            executor,
            peer_uid,
            &operation_id,
        ),
        Route::DnsImport => admission_reply(
            executor.import_dns_zone(&request),
            executor,
            peer_uid,
            &operation_id,
        ),
        Route::CloneScrub => admission_reply(
            executor.scrub_clone(&request),
            executor,
            peer_uid,
            &operation_id,
        ),
        Route::Delete => admission_reply(
            executor.delete_site(&request),
            executor,
            peer_uid,
            &operation_id,
        ),
        Route::Scrub => {
            admission_reply(executor.scrub(&request), executor, peer_uid, &operation_id)
        }
        Route::Proxy => admission_reply(
            executor.provision_proxy(&request),
            executor,
            peer_uid,
            &operation_id,
        ),
        Route::AppProvision => admission_reply(
            executor.provision_app(&request),
            executor,
            peer_uid,
            &operation_id,
        ),
        Route::AppDeploy => admission_reply(
            executor.deploy_app(&request),
            executor,
            peer_uid,
            &operation_id,
        ),
        Route::AppLifecycle => admission_reply(
            executor.app_lifecycle(&request),
            executor,
            peer_uid,
            &operation_id,
        ),
        Route::Import => {
            admission_reply(executor.import(&request), executor, peer_uid, &operation_id)
        }
        Route::Provision => admission_reply(
            executor.provision(&request),
            executor,
            peer_uid,
            &operation_id,
        ),
        Route::Generic => generic_submit(executor, &request, peer_uid, operation_id),
    }
}

/// W688: the verb a submitted plan goes to, decided once from its validated
/// kind. The match is exhaustive, so a new plan kind cannot be left unrouted;
/// a plan no closed kind accepts takes the generic (fixture) path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Route {
    /// W499 (D-078): a staging clone; a lab build stops it before intent.
    SiteClone,
    /// D-035 (W386): one run of a standing capture grant (product only).
    StandingCapture,
    /// W319: a product capture, admitted durably (product only).
    ProductCapture,
    /// W320: a product restore probe, admitted durably (product only).
    ProductProbe,
    /// A lab restore probe.
    Probe,
    /// A lab backup capture.
    Capture,
    /// W372: re-adoption records only.
    Readopt,
    /// A signed site ejection.
    Eject,
    /// A signed OLS configuration activation.
    Ols,
    /// W462 (D-059): a signed certificate issuance.
    Certificate,
    /// W515 (D-084): a signed WordPress plugin and theme update.
    SiteUpdate,
    /// W508 (D-080): a signed retirement of a quarantined site.
    Retire,
    /// W535 (D-088): a signed change of a site's quota.
    Quota,
    /// W609 (D-100): a signed per-site MariaDB credential rotation.
    CredentialRotate,
    /// W543 (D-089): a signed restore of a live site from its own capture.
    Restore,
    /// W565 (D-091): a signed change of an owned zone's record sets.
    DnsChange,
    /// W563 (D-091): a signed import of one DNS zone.
    DnsImport,
    /// W538 (D-078): a signed scrub of a quarantined clone.
    CloneScrub,
    /// W522 (D-085): a signed deletion of a live site that is offline.
    Delete,
    /// W459 (D-057): a signed scrub of an ended import's leftovers.
    Scrub,
    /// W572 (D-095): the provision steps of a proxy site.
    Proxy,
    /// W598 (D-099): P27 app provision.
    AppProvision,
    /// W598 (D-099): P27 app release deploy.
    AppDeploy,
    /// W598 (D-099): P27 app start, stop, or restart.
    AppLifecycle,
    /// W446 (D-053): the provision steps with a site import.
    Import,
    /// A WordPress site provision.
    Provision,
    /// No closed kind: the generic (fixture) path.
    Generic,
}

fn route(plan: &[u8]) -> Route {
    let Ok(prepared) = PreparedPlan::decode(plan) else {
        return Route::Generic;
    };
    match prepared.kind() {
        PlanKind::SiteClone => Route::SiteClone,
        PlanKind::BackupCapture | PlanKind::RestoreProbe => backup_route(plan),
        PlanKind::SiteReadopt => Route::Readopt,
        PlanKind::SiteEject => Route::Eject,
        PlanKind::ConfigActivate => Route::Ols,
        PlanKind::CertificateIssue => Route::Certificate,
        PlanKind::SiteUpdate => Route::SiteUpdate,
        PlanKind::SiteRetire => Route::Retire,
        PlanKind::SiteQuota => Route::Quota,
        PlanKind::SiteCredentialRotate => Route::CredentialRotate,
        PlanKind::SiteRestore => Route::Restore,
        PlanKind::DnsChange => Route::DnsChange,
        PlanKind::DnsZoneImport => Route::DnsImport,
        PlanKind::CloneScrub => Route::CloneScrub,
        PlanKind::SiteDelete => Route::Delete,
        PlanKind::ImportScrub => Route::Scrub,
        PlanKind::ProxySiteProvision => Route::Proxy,
        PlanKind::AppProvision => Route::AppProvision,
        PlanKind::AppDeploy => Route::AppDeploy,
        PlanKind::AppLifecycle => Route::AppLifecycle,
        PlanKind::SiteImport => Route::Import,
        PlanKind::SiteProvision => Route::Provision,
    }
}

/// Capture and probe kinds split by schema version between four forms; the
/// standing and product forms are admitted only by a product build.
fn backup_route(plan: &[u8]) -> Route {
    if cfg!(rustiron_profile = "product") {
        if StandingCapturePlan::decode(plan).is_ok() {
            return Route::StandingCapture;
        }
        if let Ok(plan) = ProductBackupPlan::decode(plan) {
            return match plan.target() {
                ProductBackupTarget::BackupCapture { .. } => Route::ProductCapture,
                ProductBackupTarget::RestoreProbe { .. } => Route::ProductProbe,
            };
        }
    }
    if rustiron_contracts::approval::ProbePlan::decode(plan).is_ok() {
        return Route::Probe;
    }
    if rustiron_contracts::approval::CapturePlan::decode(plan).is_ok() {
        return Route::Capture;
    }
    Route::Generic
}

/// A plan no closed kind accepts: the journal's generic submit, then execute.
fn generic_submit(
    executor: &mut Executor,
    request: &AdmissionRequest<'_>,
    peer_uid: u32,
    operation_id: Id,
) -> SubmissionReply {
    match executor.submit(request) {
        Ok(Admitted::Existing(operation)) => row_reply(&operation, true, None),
        Ok(Admitted::New(_)) => match executor.execute(&operation_id, system_time()) {
            Ok(operation) => row_reply(&operation, false, None),
            Err(error) => match stored_for_peer::<Operation>(executor, peer_uid, &operation_id) {
                Some(operation) => row_reply(&operation, false, Some(error)),
                None => error_reply(Some(operation_id), error),
            },
        },
        Err(error) => error_reply(Some(operation_id), error),
    }
}

/// W686: the reply every admitted verb shares. A refusal after intent replies with the
/// stored row and its code; with no stored row visible to this peer it is a plain error.
fn admission_reply<Row: ReplyRow>(
    result: Result<Admitted<Row>, ExecutorError>,
    executor: &Executor,
    peer_uid: u32,
    operation_id: &Id,
) -> SubmissionReply {
    match result {
        Ok(admitted) => {
            let (row, existing) = admitted.into_row();
            row_reply(&row, existing, None)
        }
        Err(error) => match stored_for_peer::<Row>(executor, peer_uid, operation_id) {
            Some(row) => row_reply(&row, false, Some(error)),
            None => error_reply(Some(operation_id.clone()), error),
        },
    }
}

/// W329/W332: stored status for a refused submission of any verb, only for
/// a peer a status query would answer. A refusal to any other peer carries
/// no state, even when it names an existing operation.
fn stored_for_peer<Row: ReplyRow>(
    executor: &Executor,
    peer_uid: u32,
    operation_id: &Id,
) -> Option<Row> {
    executor
        .authorize_status_peer(peer_uid)
        .and_then(|()| Row::stored(executor, operation_id))
        .ok()
        .flatten()
}

fn evidence_query(
    executor: &Executor,
    peer_uid: u32,
    query: rustiron_contracts::execution::EvidenceQuery,
) -> serde_json::Value {
    let result = (|| {
        executor
            .authorize_status_peer(peer_uid)
            .map_err(|error| match error {
                ExecutorError::PeerDenied => ErrorCode::UnauthorizedPeer,
                _ => ErrorCode::DependencyUnavailable,
            })?;
        match executor.evidence(&query.operation_id) {
            Ok(Some(receipt)) => Ok(receipt),
            Ok(None) => Err(ErrorCode::NotFound),
            Err(ExecutorError::NotAdmitted) => Err(ErrorCode::NotFound),
            Err(_) => Err(ErrorCode::DependencyUnavailable),
        }
    })();
    match result {
        Ok(receipt) => serde_json::json!({
            "schema_version": 1, "request_id": query.request_id, "status": "ok",
            "data": {"kind": "evidence_export", "value": {"operation_id": query.operation_id, "receipt": receipt}},
            "error": null,
        }),
        Err(error) => serde_json::json!({
            "schema_version": 1, "request_id": query.request_id, "status": "error",
            "data": null, "error": rustiron_contracts::ApiError::new(error),
        }),
    }
}

fn status_query(executor: &Executor, peer_uid: u32, query: StatusQuery) -> serde_json::Value {
    let result = (|| {
        executor
            .authorize_status_peer(peer_uid)
            .map_err(|error| match error {
                ExecutorError::PeerDenied => ErrorCode::UnauthorizedPeer,
                _ => ErrorCode::DependencyUnavailable,
            })?;
        let id = &query.operation_id;
        // The provision must stay second: a re-adopted site's provision row
        // shares the id of its re-adoption, which answers for both (W372).
        // W462-F2, W508, W515, W544-F1, W563, W565, W609, W646: every signed
        // row answers status, so a long effect is never reported as unknown.
        let candidates = [
            stored_outcome::<Operation>(executor, id),
            stored_outcome::<Provision>(executor, id),
            stored_outcome::<Capture>(executor, id),
            stored_outcome::<Probe>(executor, id),
            stored_outcome::<Readoption>(executor, id),
            stored_outcome::<ImportScrub>(executor, id),
            stored_outcome::<Certificate>(executor, id),
            stored_outcome::<SiteUpdate>(executor, id),
            stored_outcome::<Retirement>(executor, id),
            stored_outcome::<Deletion>(executor, id),
            stored_outcome::<QuotaChange>(executor, id),
            stored_outcome::<CloneScrubGrant>(executor, id),
            stored_outcome::<SiteRestore>(executor, id),
            stored_outcome::<DnsImport>(executor, id),
            stored_outcome::<DnsChange>(executor, id),
            stored_outcome::<CredentialRotation>(executor, id),
            stored_outcome::<AppRelease>(executor, id),
            stored_outcome::<AppLifecycle>(executor, id),
            stored_outcome::<Renewal>(executor, id),
        ];
        let readopted = matches!(executor.readoption_status(id), Ok(Some(_)));
        let mut found = None;
        for (index, candidate) in candidates.into_iter().enumerate() {
            if readopted && index == 1 {
                continue;
            }
            if let Some(state) = candidate.map_err(|_| ErrorCode::DependencyUnavailable)?
                && found.replace(state).is_some()
            {
                return Err(ErrorCode::DependencyUnavailable);
            }
        }
        found.ok_or(ErrorCode::NotFound)
    })();
    match result {
        Ok(state) => serde_json::json!({
            "schema_version": 1, "request_id": query.request_id, "status": "ok",
            "data": {"kind": "operation_status", "value": {"operation_id": query.operation_id, "state": state}}, "error": null,
        }),
        Err(error) => {
            let error = if error == ErrorCode::NotFound {
                serde_json::json!({"code": "NOT_FOUND", "message": "Operation not found in the journal.", "retryable": false, "operation_id": null, "details": []})
            } else {
                serde_json::json!(rustiron_contracts::ApiError::new(error))
            };
            serde_json::json!({
                "schema_version": 1, "request_id": query.request_id, "status": "error",
                "data": null, "error": error,
            })
        }
    }
}

/// Current system time; its trustworthiness is a lab assumption, not proven.
fn system_time() -> Option<Timestamp> {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    Timestamp::try_from(seconds).ok()
}

/// W709 (pass 33, fix 2): what a submission reply and a status query need
/// from a stored row: its operation, its state on the wire, and how to find
/// it again. Each journal row type maps its own states here, once.
trait ReplyRow: Sized {
    fn operation_id(&self) -> &Id;
    fn outcome(&self) -> OutcomeState;
    /// Only a failed capture names a snapshot it could not claim.
    fn unclaimed_snapshot_id(&self) -> Option<String> {
        None
    }
    /// The stored row for `operation`, read through the executor.
    fn stored(executor: &Executor, operation: &Id) -> Result<Option<Self>, ExecutorError>;
}

/// The reply for one stored row.
fn row_reply<Row: ReplyRow>(
    row: &Row,
    replay: bool,
    error: Option<ExecutorError>,
) -> SubmissionReply {
    SubmissionReply {
        schema_version: 1,
        operation_id: Some(row.operation_id().clone()),
        state: Some(row.outcome()),
        replay,
        error: error.map(|error| error.code().to_owned()),
        unclaimed_snapshot_id: row.unclaimed_snapshot_id(),
    }
}

/// The wire state of the stored row for `operation`, if it is this kind.
fn stored_outcome<Row: ReplyRow>(
    executor: &Executor,
    operation: &Id,
) -> Result<Option<OutcomeState>, ExecutorError> {
    Ok(Row::stored(executor, operation)?.map(|row| row.outcome()))
}

/// W522: the state of an operation recorded as one step: a retirement
/// (D-080), a deletion (D-085), and the other one-step verbs.
fn step_outcome(state: StepState) -> OutcomeState {
    match state {
        StepState::Intent => OutcomeState::Intent,
        StepState::Done => OutcomeState::Succeeded,
        StepState::Failed => OutcomeState::Failed,
    }
}

impl ReplyRow for Operation {
    fn operation_id(&self) -> &Id {
        &self.intent.operation_id
    }
    fn outcome(&self) -> OutcomeState {
        match self.state {
            RecordedState::Intent => OutcomeState::Intent,
            RecordedState::Succeeded => OutcomeState::Succeeded,
            RecordedState::Untouched => OutcomeState::Untouched,
            RecordedState::NeedsAttention => OutcomeState::NeedsAttention,
            RecordedState::Compensating => OutcomeState::Compensating,
            RecordedState::FailedCompensated => OutcomeState::FailedCompensated,
        }
    }
    fn stored(executor: &Executor, operation: &Id) -> Result<Option<Self>, ExecutorError> {
        executor.status(operation)
    }
}

/// Probes reuse the reply states: passed is succeeded; a failed probe left
/// nothing behind (untouched); leftover sandbox resources need attention.
impl ReplyRow for Probe {
    fn operation_id(&self) -> &Id {
        &self.intent.operation_id
    }
    fn outcome(&self) -> OutcomeState {
        match self.state {
            ProbeState::Running => OutcomeState::Intent,
            ProbeState::Passed => OutcomeState::Succeeded,
            ProbeState::Failed => OutcomeState::Untouched,
            ProbeState::CleanupIncomplete => OutcomeState::NeedsAttention,
        }
    }
    fn stored(executor: &Executor, operation: &Id) -> Result<Option<Self>, ExecutorError> {
        executor.probe_status(operation)
    }
}

/// A capture replies its recorded state. A failure at or after the snapshot
/// step stays running and reads as intent until `capture-reconcile`
/// resolves it by the operation tag. W381 (D-032): a recorded failure is
/// `failed`, never `untouched`. Recovery records `failed` after a write that
/// left store objects (W321, W376 cut 3), and the W366 settlement records it
/// with an unclaimed snapshot, which the reply then names.
impl ReplyRow for Capture {
    fn operation_id(&self) -> &Id {
        &self.intent.operation_id
    }
    fn outcome(&self) -> OutcomeState {
        match self.state {
            CaptureState::Running => OutcomeState::Intent,
            CaptureState::Succeeded => OutcomeState::Succeeded,
            CaptureState::Failed => OutcomeState::Failed,
        }
    }
    fn unclaimed_snapshot_id(&self) -> Option<String> {
        self.unclaimed_snapshot_id
            .clone()
            .filter(|_| self.state == CaptureState::Failed)
    }
    fn stored(executor: &Executor, operation: &Id) -> Result<Option<Self>, ExecutorError> {
        executor.capture_status(operation)
    }
}

/// W372: re-adoptions reuse the reply states: `verifying` is intent (not
/// settled), `adopted` succeeded, and `refused` untouched (nothing but the
/// row was recorded and nothing on the host changed).
impl ReplyRow for Readoption {
    fn operation_id(&self) -> &Id {
        &self.intent.operation_id
    }
    fn outcome(&self) -> OutcomeState {
        match self.state {
            ReadoptState::Verifying => OutcomeState::Intent,
            ReadoptState::Adopted => OutcomeState::Succeeded,
            ReadoptState::Refused => OutcomeState::Untouched,
        }
    }
    fn stored(executor: &Executor, operation: &Id) -> Result<Option<Self>, ExecutorError> {
        executor.readoption_status(operation)
    }
}

/// W462: an issuance is `intent` until observed, then `succeeded` when its
/// chain is installed, or `failed`.
fn certificate_outcome(state: CertificateState) -> OutcomeState {
    match state {
        CertificateState::Intent => OutcomeState::Intent,
        CertificateState::Installed => OutcomeState::Succeeded,
        CertificateState::Failed => OutcomeState::Failed,
    }
}

impl ReplyRow for Certificate {
    fn operation_id(&self) -> &Id {
        &self.intent.operation_id
    }
    fn outcome(&self) -> OutcomeState {
        certificate_outcome(self.state)
    }
    fn stored(executor: &Executor, operation: &Id) -> Result<Option<Self>, ExecutorError> {
        executor.certificate_status(operation)
    }
}

/// A renewal answers status under its renewal id, with the issuance states.
impl ReplyRow for Renewal {
    fn operation_id(&self) -> &Id {
        &self.renewal_id
    }
    fn outcome(&self) -> OutcomeState {
        certificate_outcome(self.state)
    }
    fn stored(executor: &Executor, operation: &Id) -> Result<Option<Self>, ExecutorError> {
        executor.renewal_status(operation)
    }
}

/// W515: an update's state: open, done, or rolled back to its predecessor.
impl ReplyRow for SiteUpdate {
    fn operation_id(&self) -> &Id {
        &self.operation_id
    }
    fn outcome(&self) -> OutcomeState {
        match self.state {
            UpdateState::Intent => OutcomeState::Intent,
            UpdateState::Done => OutcomeState::Succeeded,
            UpdateState::RolledBack => OutcomeState::FailedCompensated,
        }
    }
    fn stored(executor: &Executor, operation: &Id) -> Result<Option<Self>, ExecutorError> {
        executor.update_status(operation)
    }
}

/// W598 (D-099): an `app_deploy` release's state: open, done, or rolled back.
impl ReplyRow for AppRelease {
    fn operation_id(&self) -> &Id {
        &self.operation_id
    }
    fn outcome(&self) -> OutcomeState {
        match self.state {
            AppReleaseState::Intent => OutcomeState::Intent,
            AppReleaseState::Done => OutcomeState::Succeeded,
            AppReleaseState::RolledBack => OutcomeState::FailedCompensated,
        }
    }
    fn stored(executor: &Executor, operation: &Id) -> Result<Option<Self>, ExecutorError> {
        executor.app_release_status(operation)
    }
}

/// W543: an open restore is `intent`, also after a failed step (the reply
/// then carries the step's error); a reverted one is `failed_compensated`.
impl ReplyRow for SiteRestore {
    fn operation_id(&self) -> &Id {
        &self.operation_id
    }
    fn outcome(&self) -> OutcomeState {
        match self.state {
            RestoreState::Intent => OutcomeState::Intent,
            RestoreState::Done => OutcomeState::Succeeded,
            RestoreState::Reverted => OutcomeState::FailedCompensated,
        }
    }
    fn stored(executor: &Executor, operation: &Id) -> Result<Option<Self>, ExecutorError> {
        executor.site_restore_status(operation)
    }
}

impl ReplyRow for CredentialRotation {
    fn operation_id(&self) -> &Id {
        &self.operation_id
    }
    fn outcome(&self) -> OutcomeState {
        match self.state {
            CredentialRotateState::Intent => OutcomeState::Intent,
            CredentialRotateState::Done => OutcomeState::Succeeded,
            CredentialRotateState::FailedCompensated => OutcomeState::FailedCompensated,
            CredentialRotateState::NeedsAttention => OutcomeState::NeedsAttention,
            CredentialRotateState::Failed => OutcomeState::Failed,
        }
    }
    fn stored(executor: &Executor, operation: &Id) -> Result<Option<Self>, ExecutorError> {
        executor.credential_rotation_status(operation)
    }
}

/// A quarantined provision is a known stop with resources kept. It is not
/// the uncertain `needs_attention` state used after an OLS activation fault.
impl ReplyRow for Provision {
    fn operation_id(&self) -> &Id {
        &self.intent.operation_id
    }
    fn outcome(&self) -> OutcomeState {
        match self.state {
            ProvisionState::Running => OutcomeState::Intent,
            ProvisionState::Succeeded => OutcomeState::Succeeded,
            ProvisionState::Quarantined => OutcomeState::Quarantined,
            ProvisionState::Adopted => OutcomeState::Succeeded,
            // D-085: the provision itself succeeded; a later deletion
            // has its own operation and status.
            ProvisionState::Deleted => OutcomeState::Succeeded,
        }
    }
    fn stored(executor: &Executor, operation: &Id) -> Result<Option<Self>, ExecutorError> {
        executor.provision_status(operation)
    }
}

/// The one-step rows: each replies [`step_outcome`] of its state.
macro_rules! step_rows {
    ($($row:ty => $status:ident),+ $(,)?) => {$(
        impl ReplyRow for $row {
            fn operation_id(&self) -> &Id {
                &self.operation_id
            }
            fn outcome(&self) -> OutcomeState {
                step_outcome(self.state)
            }
            fn stored(executor: &Executor, operation: &Id) -> Result<Option<Self>, ExecutorError> {
                executor.$status(operation)
            }
        }
    )+};
}

step_rows! {
    Retirement => retirement_status,
    Deletion => deletion_status,
    QuotaChange => quota_change_status,
    CloneScrubGrant => clone_scrub_status,
    DnsImport => dns_import_status,
    DnsChange => dns_change_status,
    AppLifecycle => app_lifecycle_status,
    ImportScrub => scrub_status,
}

pub(crate) fn error_reply(operation_id: Option<Id>, error: ExecutorError) -> SubmissionReply {
    SubmissionReply {
        schema_version: 1,
        operation_id,
        state: None,
        replay: false,
        error: Some(error.code().to_owned()),
        unclaimed_snapshot_id: None,
    }
}

#[cfg(test)]
mod tests {
    use rustiron_contracts::{
        Id, Timestamp,
        approval::{Hostname, Sha256Digest, SiteId},
        execution::OutcomeState,
    };
    use rustiron_journal::{
        Capture, CaptureIntent, CaptureState, Provision, ProvisionIntent, ProvisionState,
    };

    use super::row_reply;
    use crate::ExecutorError;

    /// W544-F1: a restore's reply and status: open (also after a failed
    /// step, with its error) is `intent`, done is `succeeded`, and reverted
    /// to the safety capture is `failed_compensated`.
    #[test]
    fn a_restore_replies_with_its_recorded_outcome() {
        use rustiron_journal::{RestoreState, SiteRestore};
        let id = |text: &str| Id::try_from(text.to_owned()).unwrap();
        let mut row = SiteRestore {
            operation_id: id("op_r"),
            site_id: SiteId::try_from("blog1".to_owned()).unwrap(),
            scope: rustiron_contracts::approval::RestoreScope::Database,
            capture_operation_id: id("cap_old"),
            snapshot_id: rustiron_contracts::approval::SnapshotId::try_from("b".repeat(64))
                .unwrap(),
            manifest_sha256: Sha256Digest::try_from("1".repeat(64)).unwrap(),
            safety_capture_operation_id: id("cap_safe"),
            attempts: Vec::new(),
            state: RestoreState::Intent,
        };
        let failed = row_reply(&row, false, Some(ExecutorError::StepFailed));
        assert_eq!(failed.state, Some(OutcomeState::Intent));
        assert_eq!(
            failed.error.as_deref(),
            Some(ExecutorError::StepFailed.code())
        );
        row.state = RestoreState::Done;
        assert_eq!(
            row_reply(&row, true, None).state,
            Some(OutcomeState::Succeeded)
        );
        row.state = RestoreState::Reverted;
        assert_eq!(
            row_reply(&row, false, None).state,
            Some(OutcomeState::FailedCompensated)
        );
    }

    fn capture(state: CaptureState) -> Capture {
        let id = |text: &str| Id::try_from(text.to_owned()).unwrap();
        let digest = |c: char| Sha256Digest::try_from(c.to_string().repeat(64)).unwrap();
        let time = |t: u64| Timestamp::try_from(t).unwrap();
        Capture {
            backup_policy_digest: None,
            intent: CaptureIntent {
                operation_id: id("cap_1"),
                idempotency_key: id("cap_key_1"),
                grant_id: id("cap_grant_1"),
                nonce: id("cap_nonce_1"),
                plan_digest: digest('a'),
                grant_digest: digest('b'),
                host_id: id("host_fixture"),
                host_epoch: id("epoch_fixture"),
                site_id: SiteId::try_from("blog9".to_owned()).unwrap(),
                expires_at: time(2000),
            },
            started_at: time(1000),
            state,
            snapshot_id: None,
            finished_at: None,
            method: Some(rustiron_journal::CaptureMethod::SiteFilesDbV1),
            retention_days: None,
            files: None,
            bytes: None,
            manifest: None,
            consistency: None,
            unclaimed_snapshot_id: None,
            retention_evidence: None,
            refusal: None,
        }
    }

    #[test]
    fn an_uncertain_capture_left_running_replies_intent_with_its_error() {
        let reply = row_reply(
            &capture(CaptureState::Running),
            false,
            Some(ExecutorError::StepFailed),
        );
        assert_eq!(reply.state, Some(OutcomeState::Intent));
        assert_eq!(
            reply.error.as_deref(),
            Some(ExecutorError::StepFailed.code())
        );
    }

    /// W381 (D-032): a failed capture replies its recorded state, `failed`,
    /// never `untouched`: W321 recovery records `failed` after a write that
    /// left store objects (W376 cut 3), and the W366 settlement records it
    /// with an unclaimed snapshot in the store.
    #[test]
    fn a_recorded_failure_replies_failed_and_never_untouched() {
        let failed = row_reply(
            &capture(CaptureState::Failed),
            false,
            Some(ExecutorError::StepFailed),
        );
        assert_eq!(failed.state, Some(OutcomeState::Failed));
        assert_eq!(failed.unclaimed_snapshot_id, None);
        assert_eq!(failed.exit_code(), 5);
        let snapshot = "c".repeat(64);
        let settled = row_reply(
            &Capture {
                unclaimed_snapshot_id: Some(snapshot.clone()),
                ..capture(CaptureState::Failed)
            },
            true,
            None,
        );
        assert_eq!(settled.state, Some(OutcomeState::Failed));
        assert_eq!(settled.unclaimed_snapshot_id, Some(snapshot));
        assert_eq!(
            serde_json::to_value(&settled).unwrap()["unclaimed_snapshot_id"],
            "c".repeat(64)
        );
        let done = row_reply(&capture(CaptureState::Succeeded), true, None);
        assert_eq!(done.state, Some(OutcomeState::Succeeded));
        assert_eq!(done.unclaimed_snapshot_id, None);
        let running = row_reply(&capture(CaptureState::Running), false, None);
        assert_eq!(running.state, Some(OutcomeState::Intent));
        assert!(
            serde_json::to_value(&running)
                .unwrap()
                .get("unclaimed_snapshot_id")
                .is_none()
        );
    }

    #[test]
    fn a_quarantined_provision_is_not_an_uncertain_activation() {
        let id = |text: &str| Id::try_from(text.to_owned()).unwrap();
        let digest = |c: char| Sha256Digest::try_from(c.to_string().repeat(64)).unwrap();
        let time = |t: u64| Timestamp::try_from(t).unwrap();
        let provision = Provision {
            intent: ProvisionIntent {
                operation_id: id("prov_1"),
                idempotency_key: id("prov_key_1"),
                grant_id: id("prov_grant_1"),
                nonce: id("prov_nonce_1"),
                plan_digest: digest('c'),
                grant_digest: digest('d'),
                host_id: id("host_fixture"),
                host_epoch: id("epoch_fixture"),
                site_id: SiteId::try_from("blog9".to_owned()).unwrap(),
                hostname: Hostname::try_from("blog9.example.test".to_owned()).unwrap(),
                expires_at: time(2000),
            },
            state: ProvisionState::Quarantined,
            steps: Vec::new(),
        };
        let reply = row_reply(&provision, false, Some(ExecutorError::StepFailed));
        assert_eq!(reply.state, Some(OutcomeState::Quarantined));
        assert_ne!(reply.state, Some(OutcomeState::NeedsAttention));
        assert_eq!(
            serde_json::to_value(&reply).unwrap()["state"],
            "quarantined"
        );
    }

    #[test]
    fn app_release_reply_maps_intent_done_and_rolled_back() {
        let id = |text: &str| Id::try_from(text.to_owned()).unwrap();
        let digest = |c: char| Sha256Digest::try_from(c.to_string().repeat(64)).unwrap();
        let mut row = rustiron_journal::AppRelease {
            operation_id: id("op_w646_app"),
            site_id: SiteId::try_from("emdash1".to_owned()).unwrap(),
            release_id: "rel-1".to_owned(),
            runtime: rustiron_contracts::approval::AppRuntime::Node22V1,
            artifact_sha256: digest('c'),
            manifest_sha256: digest('d'),
            file_count: 10,
            total_bytes: 1024,
            migration_entrypoint: None,
            capture_operation_id: None,
            health_path: "/health".to_owned(),
            steps: Vec::new(),
            state: rustiron_journal::AppReleaseState::Intent,
        };
        assert_eq!(
            row_reply(&row, false, None).state,
            Some(OutcomeState::Intent)
        );
        row.state = rustiron_journal::AppReleaseState::Done;
        assert_eq!(
            row_reply(&row, false, None).state,
            Some(OutcomeState::Succeeded)
        );
        row.state = rustiron_journal::AppReleaseState::RolledBack;
        assert_eq!(
            row_reply(&row, false, None).state,
            Some(OutcomeState::FailedCompensated)
        );
    }
}

#[cfg(test)]
mod route_tests {
    use super::{Route, route};
    use rustiron_contracts::approval::{
        AppDeployPlan, AppLifecyclePlan, AppProvisionPlan, CapturePlan, CertificatePlan,
        CloneScrubPlan, CredentialRotatePlan, DeletePlan, DnsChangePlan, DnsImportPlan, EjectPlan,
        ImportPlan, OlsPlan, ProbePlan, ProductBackupPlan, ProductBackupTarget, ProxyPlan,
        QuotaPlan, ReadoptPlan, RestorePlan, RetirePlan, ScrubPlan, SiteClonePlan, SitePlan,
        SiteUpdatePlan, StandingCapturePlan,
    };
    use std::path::{Path, PathBuf};

    /// One decoder of the old chain and the route it chose.
    type Accepts = (fn(&[u8]) -> bool, Route);

    /// The W686 trial-decode order, kept as the characterization oracle.
    fn trial_route(plan: &[u8]) -> Route {
        let product = cfg!(rustiron_profile = "product");
        if SiteClonePlan::decode(plan).is_ok() {
            return Route::SiteClone;
        }
        if product && StandingCapturePlan::decode(plan).is_ok() {
            return Route::StandingCapture;
        }
        if product && let Ok(plan) = ProductBackupPlan::decode(plan) {
            return match plan.target() {
                ProductBackupTarget::BackupCapture { .. } => Route::ProductCapture,
                ProductBackupTarget::RestoreProbe { .. } => Route::ProductProbe,
            };
        }
        let checks: [Accepts; 22] = [
            (|p| ProbePlan::decode(p).is_ok(), Route::Probe),
            (|p| CapturePlan::decode(p).is_ok(), Route::Capture),
            (|p| ReadoptPlan::decode(p).is_ok(), Route::Readopt),
            (|p| EjectPlan::decode(p).is_ok(), Route::Eject),
            (|p| OlsPlan::decode(p).is_ok(), Route::Ols),
            (|p| CertificatePlan::decode(p).is_ok(), Route::Certificate),
            (|p| SiteUpdatePlan::decode(p).is_ok(), Route::SiteUpdate),
            (|p| RetirePlan::decode(p).is_ok(), Route::Retire),
            (|p| QuotaPlan::decode(p).is_ok(), Route::Quota),
            (
                |p| CredentialRotatePlan::decode(p).is_ok(),
                Route::CredentialRotate,
            ),
            (|p| RestorePlan::decode(p).is_ok(), Route::Restore),
            (|p| DnsChangePlan::decode(p).is_ok(), Route::DnsChange),
            (|p| DnsImportPlan::decode(p).is_ok(), Route::DnsImport),
            (|p| CloneScrubPlan::decode(p).is_ok(), Route::CloneScrub),
            (|p| DeletePlan::decode(p).is_ok(), Route::Delete),
            (|p| ScrubPlan::decode(p).is_ok(), Route::Scrub),
            (|p| ProxyPlan::decode(p).is_ok(), Route::Proxy),
            (|p| AppProvisionPlan::decode(p).is_ok(), Route::AppProvision),
            (|p| AppDeployPlan::decode(p).is_ok(), Route::AppDeploy),
            (|p| AppLifecyclePlan::decode(p).is_ok(), Route::AppLifecycle),
            (|p| ImportPlan::decode(p).is_ok(), Route::Import),
            (|p| SitePlan::decode(p).is_ok(), Route::Provision),
        ];
        checks
            .iter()
            .find(|(accepts, _)| accepts(plan))
            .map_or(Route::Generic, |&(_, route)| route)
    }

    fn json_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                json_files(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "json") {
                out.push(path);
            }
        }
    }

    /// W688: routing by the validated kind sends every recorded plan where the
    /// old trial chain did.
    #[test]
    fn kind_routing_matches_the_trial_chain_for_every_fixture_plan() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut files = Vec::new();
        for dir in ["docs/validation", "crates", "fuzz"] {
            json_files(&root.join(dir), &mut files);
        }
        let mut routed = 0;
        for file in &files {
            let bytes = std::fs::read(file).unwrap();
            let expected = trial_route(&bytes);
            assert_eq!(route(&bytes), expected, "{}", file.display());
            if expected != Route::Generic {
                routed += 1;
            }
        }
        assert!(routed >= 18, "only {routed} fixture plans were routed");
    }
}
