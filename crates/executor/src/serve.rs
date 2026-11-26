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
    approval::{ProductBackupPlan, ProductBackupTarget, StandingCapturePlan},
    execution::{
        OutcomeState, StatusQuery, SubmissionReply, decode_evidence_query, decode_status_query,
        decode_submission, status_query_request_id,
    },
    local::{self, DEADLINE},
};
use rustiron_journal::{
    Capture, CaptureResult, CaptureState, Operation, Probe, ProbeResult, ProbeState, Provision,
    ProvisionResult, ProvisionState, ReadoptResult, ReadoptState, Readoption, RecordResult,
    RecordedState,
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
            let stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(_) => break Err(ExecutorError::Unavailable),
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
    let taken = slots
        .lock()
        .map(|mut slots| slots.take(limits, uid))
        .unwrap_or(false);
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
    if rustiron_contracts::approval::SiteClonePlan::decode(submission.plan).is_ok() {
        let request = AdmissionRequest {
            peer_uid,
            plan: submission.plan,
            grant: submission.grant,
            signature: submission.signature.as_bytes(),
            operation_id: submission.operation_id,
            idempotency_key: submission.idempotency_key,
            now: system_time(),
        };
        // W499 (D-078): the clone needs the product store; a lab build
        // stops every clone before intent.
        if !cfg!(rustiron_profile = "product") {
            let error = executor
                .preflight_site_clone(&request)
                .err()
                .unwrap_or(ExecutorError::NotAdmitted);
            return error_reply(Some(operation_id), error);
        }
        return match executor.site_clone(&request) {
            Ok(ProvisionResult::New(provision)) => provision_reply(&provision, false, None),
            Ok(ProvisionResult::Existing(provision)) => provision_reply(&provision, true, None),
            Err(error) => match stored_for_peer(executor, peer_uid, |executor| {
                executor.provision_status(&operation_id)
            }) {
                Some(provision) => provision_reply(&provision, false, Some(error)),
                None => error_reply(Some(operation_id), error),
            },
        };
    }
    // D-035 (W386): one run of a standing capture grant (product only).
    if cfg!(rustiron_profile = "product") && StandingCapturePlan::decode(submission.plan).is_ok() {
        let request = AdmissionRequest {
            peer_uid,
            plan: submission.plan,
            grant: submission.grant,
            signature: submission.signature.as_bytes(),
            operation_id: submission.operation_id,
            idempotency_key: submission.idempotency_key,
            now: system_time(),
        };
        return match executor.product_standing_capture(&request) {
            Ok(CaptureResult::New(capture)) => capture_reply(&capture, false, None),
            Ok(CaptureResult::Existing(capture)) => capture_reply(&capture, true, None),
            Err(error) => match stored_for_peer(executor, peer_uid, |executor| {
                executor.capture_status(&operation_id)
            }) {
                Some(capture) => capture_reply(&capture, false, Some(error)),
                None => error_reply(Some(operation_id), error),
            },
        };
    }
    if cfg!(rustiron_profile = "product")
        && let Ok(plan) = ProductBackupPlan::decode(submission.plan)
    {
        // W319/W320: product captures and restore probes are admitted
        // durably; their effects are not enabled.
        let request = AdmissionRequest {
            peer_uid,
            plan: submission.plan,
            grant: submission.grant,
            signature: submission.signature.as_bytes(),
            operation_id: submission.operation_id,
            idempotency_key: submission.idempotency_key,
            now: system_time(),
        };
        return match plan.target() {
            ProductBackupTarget::BackupCapture { .. } => {
                match executor.product_backup_capture(&request) {
                    Ok(CaptureResult::New(capture)) => capture_reply(&capture, false, None),
                    Ok(CaptureResult::Existing(capture)) => capture_reply(&capture, true, None),
                    Err(error) => match stored_for_peer(executor, peer_uid, |executor| {
                        executor.capture_status(&operation_id)
                    }) {
                        Some(capture) => capture_reply(&capture, false, Some(error)),
                        None => error_reply(Some(operation_id), error),
                    },
                }
            }
            ProductBackupTarget::RestoreProbe { .. } => {
                match executor.product_restore_probe(&request) {
                    Ok(ProbeResult::New(probe)) => probe_reply(&probe, false, None),
                    Ok(ProbeResult::Existing(probe)) => probe_reply(&probe, true, None),
                    Err(error) => match stored_for_peer(executor, peer_uid, |executor| {
                        executor.probe_status(&operation_id)
                    }) {
                        Some(probe) => probe_reply(&probe, false, Some(error)),
                        None => error_reply(Some(operation_id), error),
                    },
                }
            }
        };
    }
    if rustiron_contracts::approval::ProbePlan::decode(submission.plan).is_ok() {
        let request = AdmissionRequest {
            peer_uid,
            plan: submission.plan,
            grant: submission.grant,
            signature: submission.signature.as_bytes(),
            operation_id: submission.operation_id,
            idempotency_key: submission.idempotency_key,
            now: system_time(),
        };
        return match executor.restore_probe(&request) {
            Ok(ProbeResult::New(probe)) => probe_reply(&probe, false, None),
            Ok(ProbeResult::Existing(probe)) => probe_reply(&probe, true, None),
            Err(error) => match stored_for_peer(executor, peer_uid, |executor| {
                executor.probe_status(&operation_id)
            }) {
                Some(probe) => probe_reply(&probe, false, Some(error)),
                None => error_reply(Some(operation_id), error),
            },
        };
    }
    if rustiron_contracts::approval::CapturePlan::decode(submission.plan).is_ok() {
        let request = AdmissionRequest {
            peer_uid,
            plan: submission.plan,
            grant: submission.grant,
            signature: submission.signature.as_bytes(),
            operation_id: submission.operation_id,
            idempotency_key: submission.idempotency_key,
            now: system_time(),
        };
        return match executor.backup_capture(&request) {
            Ok(CaptureResult::New(capture)) => capture_reply(&capture, false, None),
            Ok(CaptureResult::Existing(capture)) => capture_reply(&capture, true, None),
            Err(error) => match stored_for_peer(executor, peer_uid, |executor| {
                executor.capture_status(&operation_id)
            }) {
                Some(capture) => capture_reply(&capture, false, Some(error)),
                None => error_reply(Some(operation_id), error),
            },
        };
    }
    if rustiron_contracts::approval::ReadoptPlan::decode(submission.plan).is_ok() {
        // W372: re-adoption records only; a refusal after intent replies
        // with the stored row and its code.
        let request = AdmissionRequest {
            peer_uid,
            plan: submission.plan,
            grant: submission.grant,
            signature: submission.signature.as_bytes(),
            operation_id: submission.operation_id,
            idempotency_key: submission.idempotency_key,
            now: system_time(),
        };
        return match executor.readopt(&request) {
            Ok(ReadoptResult::New(row)) => readopt_reply(&row, false, None),
            Ok(ReadoptResult::Existing(row)) => readopt_reply(&row, true, None),
            Err(error) => match stored_for_peer(executor, peer_uid, |executor| {
                executor.readoption_status(&operation_id)
            }) {
                Some(row) => readopt_reply(&row, false, Some(error)),
                None => error_reply(Some(operation_id), error),
            },
        };
    }
    if rustiron_contracts::approval::EjectPlan::decode(submission.plan).is_ok() {
        let request = AdmissionRequest {
            peer_uid,
            plan: submission.plan,
            grant: submission.grant,
            signature: submission.signature.as_bytes(),
            operation_id: submission.operation_id,
            idempotency_key: submission.idempotency_key,
            now: system_time(),
        };
        return match executor.eject_site(&request) {
            Ok(RecordResult::New(operation)) => reply(&operation, false, None),
            Ok(RecordResult::Existing(operation)) => reply(&operation, true, None),
            Err(error) => match stored_for_peer(executor, peer_uid, |executor| {
                executor.status(&operation_id)
            }) {
                Some(operation) => reply(&operation, false, Some(error)),
                None => error_reply(Some(operation_id), error),
            },
        };
    }
    if rustiron_contracts::approval::OlsPlan::decode(submission.plan).is_ok() {
        let request = AdmissionRequest {
            peer_uid,
            plan: submission.plan,
            grant: submission.grant,
            signature: submission.signature.as_bytes(),
            operation_id: submission.operation_id,
            idempotency_key: submission.idempotency_key,
            now: system_time(),
        };
        return match executor.activate_ols(&request) {
            Ok(RecordResult::New(operation)) => reply(&operation, false, None),
            Ok(RecordResult::Existing(operation)) => reply(&operation, true, None),
            Err(error) => match stored_for_peer(executor, peer_uid, |executor| {
                executor.status(&operation_id)
            }) {
                Some(operation) => reply(&operation, false, Some(error)),
                None => error_reply(Some(operation_id), error),
            },
        };
    }
    // W462 (D-059): a signed certificate issuance.
    if rustiron_contracts::approval::CertificatePlan::decode(submission.plan).is_ok() {
        let request = AdmissionRequest {
            peer_uid,
            plan: submission.plan,
            grant: submission.grant,
            signature: submission.signature.as_bytes(),
            operation_id: submission.operation_id,
            idempotency_key: submission.idempotency_key,
            now: system_time(),
        };
        return match executor.certificate(&request) {
            Ok(rustiron_journal::CertificateResult::New(row)) => {
                certificate_reply(&row, false, None)
            }
            Ok(rustiron_journal::CertificateResult::Existing(row)) => {
                certificate_reply(&row, true, None)
            }
            Err(error) => match stored_for_peer(executor, peer_uid, |executor| {
                executor.certificate_status(&operation_id)
            }) {
                Some(row) => certificate_reply(&row, false, Some(error)),
                None => error_reply(Some(operation_id), error),
            },
        };
    }
    // W515 (D-084): a signed WordPress plugin and theme update.
    if rustiron_contracts::approval::SiteUpdatePlan::decode(submission.plan).is_ok() {
        let request = AdmissionRequest {
            peer_uid,
            plan: submission.plan,
            grant: submission.grant,
            signature: submission.signature.as_bytes(),
            operation_id: submission.operation_id,
            idempotency_key: submission.idempotency_key,
            now: system_time(),
        };
        return match executor.update_site(&request) {
            Ok(rustiron_journal::UpdateResult::New(row)) => update_reply(&row, false, None),
            Ok(rustiron_journal::UpdateResult::Existing(row)) => update_reply(&row, true, None),
            Err(error) => match stored_for_peer(executor, peer_uid, |executor| {
                executor.update_status(&operation_id)
            }) {
                Some(row) => update_reply(&row, false, Some(error)),
                None => error_reply(Some(operation_id), error),
            },
        };
    }
    // W508 (D-080): a signed retirement of a quarantined site.
    if rustiron_contracts::approval::RetirePlan::decode(submission.plan).is_ok() {
        let request = AdmissionRequest {
            peer_uid,
            plan: submission.plan,
            grant: submission.grant,
            signature: submission.signature.as_bytes(),
            operation_id: submission.operation_id,
            idempotency_key: submission.idempotency_key,
            now: system_time(),
        };
        return match executor.retire_site(&request) {
            Ok(rustiron_journal::RetireResult::New(row)) => retire_reply(&row, false, None),
            Ok(rustiron_journal::RetireResult::Existing(row)) => retire_reply(&row, true, None),
            Err(error) => match stored_for_peer(executor, peer_uid, |executor| {
                executor.retirement_status(&operation_id)
            }) {
                Some(row) => retire_reply(&row, false, Some(error)),
                None => error_reply(Some(operation_id), error),
            },
        };
    }
    // W535 (D-088): a signed change of a site's quota.
    if rustiron_contracts::approval::QuotaPlan::decode(submission.plan).is_ok() {
        let request = AdmissionRequest {
            peer_uid,
            plan: submission.plan,
            grant: submission.grant,
            signature: submission.signature.as_bytes(),
            operation_id: submission.operation_id,
            idempotency_key: submission.idempotency_key,
            now: system_time(),
        };
        return match executor.change_quota(&request) {
            Ok(rustiron_journal::QuotaChangeResult::New(row)) => {
                step_reply(&row.operation_id, row.state, false, None)
            }
            Ok(rustiron_journal::QuotaChangeResult::Existing(row)) => {
                step_reply(&row.operation_id, row.state, true, None)
            }
            Err(error) => match stored_for_peer(executor, peer_uid, |executor| {
                executor.quota_change_status(&operation_id)
            }) {
                Some(row) => step_reply(&row.operation_id, row.state, false, Some(error)),
                None => error_reply(Some(operation_id), error),
            },
        };
    }
    // W609 (D-100): a signed per-site MariaDB credential rotation.
    if rustiron_contracts::approval::CredentialRotatePlan::decode(submission.plan).is_ok() {
        let request = AdmissionRequest {
            peer_uid,
            plan: submission.plan,
            grant: submission.grant,
            signature: submission.signature.as_bytes(),
            operation_id: submission.operation_id,
            idempotency_key: submission.idempotency_key,
            now: system_time(),
        };
        return match executor.rotate_site_credentials(&request) {
            Ok(rustiron_journal::CredentialRotateResult::New(row)) => {
                credential_rotate_reply(&row, false, None)
            }
            Ok(rustiron_journal::CredentialRotateResult::Existing(row)) => {
                credential_rotate_reply(&row, true, None)
            }
            Err(error) => match stored_for_peer(executor, peer_uid, |executor| {
                executor.credential_rotation_status(&operation_id)
            }) {
                Some(row) => credential_rotate_reply(&row, false, Some(error)),
                None => error_reply(Some(operation_id), error),
            },
        };
    }
    // W543 (D-089): a signed restore of a live site from its own capture.
    if rustiron_contracts::approval::RestorePlan::decode(submission.plan).is_ok() {
        let request = AdmissionRequest {
            peer_uid,
            plan: submission.plan,
            grant: submission.grant,
            signature: submission.signature.as_bytes(),
            operation_id: submission.operation_id,
            idempotency_key: submission.idempotency_key,
            now: system_time(),
        };
        return match executor.restore_site(&request) {
            Ok(rustiron_journal::RestoreResult::New(row)) => restore_reply(&row, false, None),
            Ok(rustiron_journal::RestoreResult::Existing(row)) => restore_reply(&row, true, None),
            Err(error) => match stored_for_peer(executor, peer_uid, |executor| {
                executor.site_restore_status(&operation_id)
            }) {
                Some(row) => restore_reply(&row, false, Some(error)),
                None => error_reply(Some(operation_id), error),
            },
        };
    }
    // W565 (D-091): a signed change of an owned zone's record sets.
    if rustiron_contracts::approval::DnsChangePlan::decode(submission.plan).is_ok() {
        let request = AdmissionRequest {
            peer_uid,
            plan: submission.plan,
            grant: submission.grant,
            signature: submission.signature.as_bytes(),
            operation_id: submission.operation_id,
            idempotency_key: submission.idempotency_key,
            now: system_time(),
        };
        return match executor.change_dns(&request) {
            Ok(rustiron_journal::DnsChangeResult::New(row)) => {
                step_reply(&row.operation_id, row.state, false, None)
            }
            Ok(rustiron_journal::DnsChangeResult::Existing(row)) => {
                step_reply(&row.operation_id, row.state, true, None)
            }
            Err(error) => match stored_for_peer(executor, peer_uid, |executor| {
                executor.dns_change_status(&operation_id)
            }) {
                Some(row) => step_reply(&row.operation_id, row.state, false, Some(error)),
                None => error_reply(Some(operation_id), error),
            },
        };
    }
    // W563 (D-091): a signed import of one DNS zone.
    if rustiron_contracts::approval::DnsImportPlan::decode(submission.plan).is_ok() {
        let request = AdmissionRequest {
            peer_uid,
            plan: submission.plan,
            grant: submission.grant,
            signature: submission.signature.as_bytes(),
            operation_id: submission.operation_id,
            idempotency_key: submission.idempotency_key,
            now: system_time(),
        };
        return match executor.import_dns_zone(&request) {
            Ok(rustiron_journal::DnsImportResult::New(row)) => {
                step_reply(&row.operation_id, row.state, false, None)
            }
            Ok(rustiron_journal::DnsImportResult::Existing(row)) => {
                step_reply(&row.operation_id, row.state, true, None)
            }
            Err(error) => match stored_for_peer(executor, peer_uid, |executor| {
                executor.dns_import_status(&operation_id)
            }) {
                Some(row) => step_reply(&row.operation_id, row.state, false, Some(error)),
                None => error_reply(Some(operation_id), error),
            },
        };
    }
    // W538 (D-078): a signed scrub of a quarantined clone.
    if rustiron_contracts::approval::CloneScrubPlan::decode(submission.plan).is_ok() {
        let request = AdmissionRequest {
            peer_uid,
            plan: submission.plan,
            grant: submission.grant,
            signature: submission.signature.as_bytes(),
            operation_id: submission.operation_id,
            idempotency_key: submission.idempotency_key,
            now: system_time(),
        };
        return match executor.scrub_clone(&request) {
            Ok(rustiron_journal::CloneScrubResult::New(row)) => {
                step_reply(&row.operation_id, row.state, false, None)
            }
            Ok(rustiron_journal::CloneScrubResult::Existing(row)) => {
                step_reply(&row.operation_id, row.state, true, None)
            }
            Err(error) => match stored_for_peer(executor, peer_uid, |executor| {
                executor.clone_scrub_status(&operation_id)
            }) {
                Some(row) => step_reply(&row.operation_id, row.state, false, Some(error)),
                None => error_reply(Some(operation_id), error),
            },
        };
    }
    // W522 (D-085): a signed deletion of a live site that is offline.
    if rustiron_contracts::approval::DeletePlan::decode(submission.plan).is_ok() {
        let request = AdmissionRequest {
            peer_uid,
            plan: submission.plan,
            grant: submission.grant,
            signature: submission.signature.as_bytes(),
            operation_id: submission.operation_id,
            idempotency_key: submission.idempotency_key,
            now: system_time(),
        };
        return match executor.delete_site(&request) {
            Ok(rustiron_journal::DeleteResult::New(row)) => {
                step_reply(&row.operation_id, row.state, false, None)
            }
            Ok(rustiron_journal::DeleteResult::Existing(row)) => {
                step_reply(&row.operation_id, row.state, true, None)
            }
            Err(error) => match stored_for_peer(executor, peer_uid, |executor| {
                executor.deletion_status(&operation_id)
            }) {
                Some(row) => step_reply(&row.operation_id, row.state, false, Some(error)),
                None => error_reply(Some(operation_id), error),
            },
        };
    }
    // W459 (D-057): a signed scrub of an ended import's leftovers.
    if rustiron_contracts::approval::ScrubPlan::decode(submission.plan).is_ok() {
        let request = AdmissionRequest {
            peer_uid,
            plan: submission.plan,
            grant: submission.grant,
            signature: submission.signature.as_bytes(),
            operation_id: submission.operation_id,
            idempotency_key: submission.idempotency_key,
            now: system_time(),
        };
        return match executor.scrub(&request) {
            Ok(rustiron_journal::ScrubResult::New(scrub)) => scrub_reply(&scrub, false, None),
            Ok(rustiron_journal::ScrubResult::Existing(scrub)) => scrub_reply(&scrub, true, None),
            Err(error) => match stored_for_peer(executor, peer_uid, |executor| {
                executor.scrub_status(&operation_id)
            }) {
                Some(scrub) => scrub_reply(&scrub, false, Some(error)),
                None => error_reply(Some(operation_id), error),
            },
        };
    }
    // W572 (D-095): a proxy site runs the provision steps of a proxy site.
    if rustiron_contracts::approval::ProxyPlan::decode(submission.plan).is_ok() {
        let request = AdmissionRequest {
            peer_uid,
            plan: submission.plan,
            grant: submission.grant,
            signature: submission.signature.as_bytes(),
            operation_id: submission.operation_id,
            idempotency_key: submission.idempotency_key,
            now: system_time(),
        };
        return match executor.provision_proxy(&request) {
            Ok(ProvisionResult::New(provision)) => provision_reply(&provision, false, None),
            Ok(ProvisionResult::Existing(provision)) => provision_reply(&provision, true, None),
            Err(error) => match stored_for_peer(executor, peer_uid, |executor| {
                executor.provision_status(&operation_id)
            }) {
                Some(provision) => provision_reply(&provision, false, Some(error)),
                None => error_reply(Some(operation_id), error),
            },
        };
    }
    // W598 (D-099): P27 modern app hosting (`app_provision`, `app_deploy`, `app_lifecycle`).
    if rustiron_contracts::approval::AppProvisionPlan::decode(submission.plan).is_ok() {
        let request = AdmissionRequest {
            peer_uid,
            plan: submission.plan,
            grant: submission.grant,
            signature: submission.signature.as_bytes(),
            operation_id: submission.operation_id,
            idempotency_key: submission.idempotency_key,
            now: system_time(),
        };
        return match executor.provision_app(&request) {
            Ok(ProvisionResult::New(provision)) => provision_reply(&provision, false, None),
            Ok(ProvisionResult::Existing(provision)) => provision_reply(&provision, true, None),
            Err(error) => match stored_for_peer(executor, peer_uid, |executor| {
                executor.provision_status(&operation_id)
            }) {
                Some(provision) => provision_reply(&provision, false, Some(error)),
                None => error_reply(Some(operation_id), error),
            },
        };
    }
    if rustiron_contracts::approval::AppDeployPlan::decode(submission.plan).is_ok() {
        let request = AdmissionRequest {
            peer_uid,
            plan: submission.plan,
            grant: submission.grant,
            signature: submission.signature.as_bytes(),
            operation_id: submission.operation_id,
            idempotency_key: submission.idempotency_key,
            now: system_time(),
        };
        return match executor.deploy_app(&request) {
            Ok(rustiron_journal::AppReleaseResult::New(row)) => {
                app_release_reply(&row, false, None)
            }
            Ok(rustiron_journal::AppReleaseResult::Existing(row)) => {
                app_release_reply(&row, true, None)
            }
            Err(error) => match stored_for_peer(executor, peer_uid, |executor| {
                executor.app_release_status(&operation_id)
            }) {
                Some(row) => app_release_reply(&row, false, Some(error)),
                None => error_reply(Some(operation_id), error),
            },
        };
    }
    if rustiron_contracts::approval::AppLifecyclePlan::decode(submission.plan).is_ok() {
        let request = AdmissionRequest {
            peer_uid,
            plan: submission.plan,
            grant: submission.grant,
            signature: submission.signature.as_bytes(),
            operation_id: submission.operation_id,
            idempotency_key: submission.idempotency_key,
            now: system_time(),
        };
        return match executor.app_lifecycle(&request) {
            Ok(rustiron_journal::AppLifecycleResult::New(row)) => {
                step_reply(&row.operation_id, row.state, false, None)
            }
            Ok(rustiron_journal::AppLifecycleResult::Existing(row)) => {
                step_reply(&row.operation_id, row.state, true, None)
            }
            Err(error) => match stored_for_peer(executor, peer_uid, |executor| {
                executor.app_lifecycle_status(&operation_id)
            }) {
                Some(row) => step_reply(&row.operation_id, row.state, false, Some(error)),
                None => error_reply(Some(operation_id), error),
            },
        };
    }
    // W446 (D-053): a site import runs the provision steps with its import.
    if rustiron_contracts::approval::ImportPlan::decode(submission.plan).is_ok() {
        let request = AdmissionRequest {
            peer_uid,
            plan: submission.plan,
            grant: submission.grant,
            signature: submission.signature.as_bytes(),
            operation_id: submission.operation_id,
            idempotency_key: submission.idempotency_key,
            now: system_time(),
        };
        return match executor.import(&request) {
            Ok(ProvisionResult::New(provision)) => provision_reply(&provision, false, None),
            Ok(ProvisionResult::Existing(provision)) => provision_reply(&provision, true, None),
            Err(error) => match stored_for_peer(executor, peer_uid, |executor| {
                executor.provision_status(&operation_id)
            }) {
                Some(provision) => provision_reply(&provision, false, Some(error)),
                None => error_reply(Some(operation_id), error),
            },
        };
    }
    if rustiron_contracts::approval::SitePlan::decode(submission.plan).is_ok() {
        let request = AdmissionRequest {
            peer_uid,
            plan: submission.plan,
            grant: submission.grant,
            signature: submission.signature.as_bytes(),
            operation_id: submission.operation_id,
            idempotency_key: submission.idempotency_key,
            now: system_time(),
        };
        return match executor.provision(&request) {
            Ok(ProvisionResult::New(provision)) => provision_reply(&provision, false, None),
            Ok(ProvisionResult::Existing(provision)) => provision_reply(&provision, true, None),
            Err(error) => match stored_for_peer(executor, peer_uid, |executor| {
                executor.provision_status(&operation_id)
            }) {
                Some(provision) => provision_reply(&provision, false, Some(error)),
                None => error_reply(Some(operation_id), error),
            },
        };
    }
    let request = AdmissionRequest {
        peer_uid,
        plan: submission.plan,
        grant: submission.grant,
        signature: submission.signature.as_bytes(),
        operation_id: submission.operation_id,
        idempotency_key: submission.idempotency_key,
        now: system_time(),
    };
    match executor.submit(&request) {
        Ok(RecordResult::Existing(operation)) => reply(&operation, true, None),
        Ok(RecordResult::New(_)) => match executor.execute(&operation_id, system_time()) {
            Ok(operation) => reply(&operation, false, None),
            Err(error) => match stored_for_peer(executor, peer_uid, |executor| {
                executor.status(&operation_id)
            }) {
                Some(operation) => reply(&operation, false, Some(error)),
                None => error_reply(Some(operation_id), error),
            },
        },
        Err(error) => error_reply(Some(operation_id), error),
    }
}

/// W329/W332: stored status for a refused submission of any verb, only for
/// a peer a status query would answer. A refusal to any other peer carries
/// no state, even when it names an existing operation.
fn stored_for_peer<T>(
    executor: &Executor,
    peer_uid: u32,
    status: impl FnOnce(&Executor) -> Result<Option<T>, ExecutorError>,
) -> Option<T> {
    executor
        .authorize_status_peer(peer_uid)
        .and_then(|()| status(executor))
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
        let candidates = [
            executor
                .status(id)
                .map(|v| v.map(|op| reply(&op, false, None))),
            executor
                .provision_status(id)
                .map(|v| v.map(|op| provision_reply(&op, false, None))),
            executor
                .capture_status(id)
                .map(|v| v.map(|op| capture_reply(&op, false, None))),
            executor
                .probe_status(id)
                .map(|v| v.map(|op| probe_reply(&op, false, None))),
            // W372: an adopted site's provision row shares the id of its
            // re-adoption; the re-adoption answers for both.
            executor
                .readoption_status(id)
                .map(|v| v.map(|row| readopt_reply(&row, false, None))),
            // W462-F2: signed scrubs and certificates answer status too, so
            // a long issuance is not reported as unknown.
            executor
                .scrub_status(id)
                .map(|v| v.map(|row| scrub_reply(&row, false, None))),
            executor
                .certificate_status(id)
                .map(|v| v.map(|row| certificate_reply(&row, false, None))),
            // W515: a signed update answers status too.
            executor
                .update_status(id)
                .map(|v| v.map(|row| update_reply(&row, false, None))),
            // W508: a signed retirement answers status too.
            executor
                .retirement_status(id)
                .map(|v| v.map(|row| retire_reply(&row, false, None))),
            // W544-F1: a signed deletion, quota change, clone scrub, and
            // restore answer status too, so a restore longer than the reply
            // deadline is not reported as unknown.
            executor
                .deletion_status(id)
                .map(|v| v.map(|row| step_reply(&row.operation_id, row.state, false, None))),
            executor
                .quota_change_status(id)
                .map(|v| v.map(|row| step_reply(&row.operation_id, row.state, false, None))),
            executor
                .clone_scrub_status(id)
                .map(|v| v.map(|row| step_reply(&row.operation_id, row.state, false, None))),
            executor
                .site_restore_status(id)
                .map(|v| v.map(|row| restore_reply(&row, false, None))),
            // W563: a signed zone import answers status too.
            executor
                .dns_import_status(id)
                .map(|v| v.map(|row| step_reply(&row.operation_id, row.state, false, None))),
            // W565: a signed record change answers status too.
            executor
                .dns_change_status(id)
                .map(|v| v.map(|row| step_reply(&row.operation_id, row.state, false, None))),
            // W609: a signed credential rotation answers status too.
            executor
                .credential_rotation_status(id)
                .map(|v| v.map(|row| credential_rotate_reply(&row, false, None))),
            // W646: signed P27/P30 app deploys and lifecycles answer status too,
            // so a large release unpack exceeding the initial reply deadline is
            // reconciled cleanly instead of returning NOT_FOUND / outcome_unknown.
            executor
                .app_release_status(id)
                .map(|v| v.map(|row| app_release_reply(&row, false, None))),
            executor
                .app_lifecycle_status(id)
                .map(|v| v.map(|row| step_reply(&row.operation_id, row.state, false, None))),
            executor.renewal_status(id).map(|v| {
                v.map(|row| SubmissionReply {
                    schema_version: 1,
                    operation_id: Some(row.renewal_id.clone()),
                    state: Some(match row.state {
                        rustiron_journal::CertificateState::Intent => OutcomeState::Intent,
                        rustiron_journal::CertificateState::Installed => OutcomeState::Succeeded,
                        rustiron_journal::CertificateState::Failed => OutcomeState::Failed,
                    }),
                    replay: false,
                    error: None,
                    unclaimed_snapshot_id: None,
                })
            }),
        ];
        let readopted = matches!(executor.readoption_status(id), Ok(Some(_)));
        let mut found = None;
        for (index, candidate) in candidates.into_iter().enumerate() {
            if readopted && index == 1 {
                continue;
            }
            if let Some(reply) = candidate.map_err(|_| ErrorCode::DependencyUnavailable)? {
                let state = reply.state.ok_or(ErrorCode::DependencyUnavailable)?;
                if found.replace(state).is_some() {
                    return Err(ErrorCode::DependencyUnavailable);
                }
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

fn reply(operation: &Operation, replay: bool, error: Option<ExecutorError>) -> SubmissionReply {
    SubmissionReply {
        schema_version: 1,
        operation_id: Some(operation.intent.operation_id.clone()),
        state: Some(match operation.state {
            RecordedState::Intent => OutcomeState::Intent,
            RecordedState::Succeeded => OutcomeState::Succeeded,
            RecordedState::Untouched => OutcomeState::Untouched,
            RecordedState::NeedsAttention => OutcomeState::NeedsAttention,
            RecordedState::Compensating => OutcomeState::Compensating,
            RecordedState::FailedCompensated => OutcomeState::FailedCompensated,
        }),
        replay,
        error: error.map(|error| error.code().to_owned()),
        unclaimed_snapshot_id: None,
    }
}

/// Probes reuse the reply states: passed is succeeded; a failed probe left
/// nothing behind (untouched); leftover sandbox resources need attention.
fn probe_reply(probe: &Probe, replay: bool, error: Option<ExecutorError>) -> SubmissionReply {
    SubmissionReply {
        schema_version: 1,
        operation_id: Some(probe.intent.operation_id.clone()),
        state: Some(match probe.state {
            ProbeState::Running => OutcomeState::Intent,
            ProbeState::Passed => OutcomeState::Succeeded,
            ProbeState::Failed => OutcomeState::Untouched,
            ProbeState::CleanupIncomplete => OutcomeState::NeedsAttention,
        }),
        replay,
        error: error.map(|error| error.code().to_owned()),
        unclaimed_snapshot_id: None,
    }
}

/// A capture replies its recorded state. A failure at or after the snapshot
/// step stays running and reads as intent until `capture-reconcile`
/// resolves it by the operation tag. W381 (D-032): a recorded failure is
/// `failed`, never `untouched`. Recovery records `failed` after a write that
/// left store objects (W321, W376 cut 3), and the W366 settlement records it
/// with an unclaimed snapshot, which the reply then names.
fn capture_reply(capture: &Capture, replay: bool, error: Option<ExecutorError>) -> SubmissionReply {
    let failed = capture.state == CaptureState::Failed;
    SubmissionReply {
        schema_version: 1,
        operation_id: Some(capture.intent.operation_id.clone()),
        state: Some(match capture.state {
            CaptureState::Running => OutcomeState::Intent,
            CaptureState::Succeeded => OutcomeState::Succeeded,
            CaptureState::Failed => OutcomeState::Failed,
        }),
        replay,
        error: error.map(|error| error.code().to_owned()),
        unclaimed_snapshot_id: capture.unclaimed_snapshot_id.clone().filter(|_| failed),
    }
}

/// W372: re-adoptions reuse the reply states: `verifying` is intent (not
/// settled), `adopted` succeeded, and `refused` untouched (nothing but the
/// row was recorded and nothing on the host changed).
fn readopt_reply(row: &Readoption, replay: bool, error: Option<ExecutorError>) -> SubmissionReply {
    SubmissionReply {
        schema_version: 1,
        operation_id: Some(row.intent.operation_id.clone()),
        state: Some(match row.state {
            ReadoptState::Verifying => OutcomeState::Intent,
            ReadoptState::Adopted => OutcomeState::Succeeded,
            ReadoptState::Refused => OutcomeState::Untouched,
        }),
        replay,
        error: error.map(|error| error.code().to_owned()),
        unclaimed_snapshot_id: None,
    }
}

/// W462: an issuance is `intent` until observed, then `succeeded` when its
/// chain is installed, or `failed`.
fn certificate_reply(
    row: &rustiron_journal::Certificate,
    replay: bool,
    error: Option<ExecutorError>,
) -> SubmissionReply {
    SubmissionReply {
        schema_version: 1,
        operation_id: Some(row.intent.operation_id.clone()),
        state: Some(match row.state {
            rustiron_journal::CertificateState::Intent => OutcomeState::Intent,
            rustiron_journal::CertificateState::Installed => OutcomeState::Succeeded,
            rustiron_journal::CertificateState::Failed => OutcomeState::Failed,
        }),
        replay,
        error: error.map(|error| error.code().to_owned()),
        unclaimed_snapshot_id: None,
    }
}

/// W459: a scrub is `intent` until observed, then `succeeded` or `failed`.
/// W515: an update's state: open, done, or rolled back to its predecessor.
fn update_reply(
    row: &rustiron_journal::SiteUpdate,
    replay: bool,
    error: Option<ExecutorError>,
) -> SubmissionReply {
    SubmissionReply {
        schema_version: 1,
        operation_id: Some(row.operation_id.clone()),
        state: Some(match row.state {
            rustiron_journal::UpdateState::Intent => OutcomeState::Intent,
            rustiron_journal::UpdateState::Done => OutcomeState::Succeeded,
            rustiron_journal::UpdateState::RolledBack => OutcomeState::FailedCompensated,
        }),
        replay,
        error: error.map(|error| error.code().to_owned()),
        unclaimed_snapshot_id: None,
    }
}

/// W598 (D-099): an `app_deploy` release's state: open, done, or rolled back.
fn app_release_reply(
    row: &rustiron_journal::AppRelease,
    replay: bool,
    error: Option<ExecutorError>,
) -> SubmissionReply {
    SubmissionReply {
        schema_version: 1,
        operation_id: Some(row.operation_id.clone()),
        state: Some(match row.state {
            rustiron_journal::AppReleaseState::Intent => OutcomeState::Intent,
            rustiron_journal::AppReleaseState::Done => OutcomeState::Succeeded,
            rustiron_journal::AppReleaseState::RolledBack => OutcomeState::FailedCompensated,
        }),
        replay,
        error: error.map(|error| error.code().to_owned()),
        unclaimed_snapshot_id: None,
    }
}

/// W543: an open restore is `intent`, also after a failed step (the reply
/// then carries the step's error); a reverted one is `failed_compensated`.
fn restore_reply(
    row: &rustiron_journal::SiteRestore,
    replay: bool,
    error: Option<ExecutorError>,
) -> SubmissionReply {
    SubmissionReply {
        schema_version: 1,
        operation_id: Some(row.operation_id.clone()),
        state: Some(match row.state {
            rustiron_journal::RestoreState::Intent => OutcomeState::Intent,
            rustiron_journal::RestoreState::Done => OutcomeState::Succeeded,
            rustiron_journal::RestoreState::Reverted => OutcomeState::FailedCompensated,
        }),
        replay,
        error: error.map(|error| error.code().to_owned()),
        unclaimed_snapshot_id: None,
    }
}

fn retire_reply(
    row: &rustiron_journal::Retirement,
    replay: bool,
    error: Option<ExecutorError>,
) -> SubmissionReply {
    step_reply(&row.operation_id, row.state, replay, error)
}

/// W522: the reply for an operation recorded as one step: a retirement
/// (D-080) or a deletion (D-085).
fn step_reply(
    operation_id: &rustiron_contracts::Id,
    state: rustiron_journal::StepState,
    replay: bool,
    error: Option<ExecutorError>,
) -> SubmissionReply {
    SubmissionReply {
        schema_version: 1,
        operation_id: Some(operation_id.clone()),
        state: Some(match state {
            rustiron_journal::StepState::Intent => OutcomeState::Intent,
            rustiron_journal::StepState::Done => OutcomeState::Succeeded,
            rustiron_journal::StepState::Failed => OutcomeState::Failed,
        }),
        replay,
        error: error.map(|error| error.code().to_owned()),
        unclaimed_snapshot_id: None,
    }
}

fn credential_rotate_reply(
    row: &rustiron_journal::CredentialRotation,
    replay: bool,
    error: Option<ExecutorError>,
) -> SubmissionReply {
    SubmissionReply {
        schema_version: 1,
        operation_id: Some(row.operation_id.clone()),
        state: Some(match row.state {
            rustiron_journal::CredentialRotateState::Intent => OutcomeState::Intent,
            rustiron_journal::CredentialRotateState::Done => OutcomeState::Succeeded,
            rustiron_journal::CredentialRotateState::FailedCompensated => {
                OutcomeState::FailedCompensated
            }
            rustiron_journal::CredentialRotateState::NeedsAttention => OutcomeState::NeedsAttention,
            rustiron_journal::CredentialRotateState::Failed => OutcomeState::Failed,
        }),
        replay,
        error: error.map(|error| error.code().to_owned()),
        unclaimed_snapshot_id: None,
    }
}

fn scrub_reply(
    scrub: &rustiron_journal::ImportScrub,
    replay: bool,
    error: Option<ExecutorError>,
) -> SubmissionReply {
    SubmissionReply {
        schema_version: 1,
        operation_id: Some(scrub.operation_id.clone()),
        state: Some(match scrub.state {
            rustiron_journal::StepState::Intent => OutcomeState::Intent,
            rustiron_journal::StepState::Done => OutcomeState::Succeeded,
            rustiron_journal::StepState::Failed => OutcomeState::Failed,
        }),
        replay,
        error: error.map(|error| error.code().to_owned()),
        unclaimed_snapshot_id: None,
    }
}

/// A quarantined provision is a known stop with resources kept. It is not
/// the uncertain `needs_attention` state used after an OLS activation fault.
fn provision_reply(
    provision: &Provision,
    replay: bool,
    error: Option<ExecutorError>,
) -> SubmissionReply {
    SubmissionReply {
        schema_version: 1,
        operation_id: Some(provision.intent.operation_id.clone()),
        state: Some(match provision.state {
            ProvisionState::Running => OutcomeState::Intent,
            ProvisionState::Succeeded => OutcomeState::Succeeded,
            ProvisionState::Quarantined => OutcomeState::Quarantined,
            ProvisionState::Adopted => OutcomeState::Succeeded,
            // D-085: the provision itself succeeded; a later deletion
            // has its own operation and status.
            ProvisionState::Deleted => OutcomeState::Succeeded,
        }),
        replay,
        error: error.map(|error| error.code().to_owned()),
        unclaimed_snapshot_id: None,
    }
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

    use super::{capture_reply, provision_reply, restore_reply};
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
        let failed = restore_reply(&row, false, Some(ExecutorError::StepFailed));
        assert_eq!(failed.state, Some(OutcomeState::Intent));
        assert_eq!(
            failed.error.as_deref(),
            Some(ExecutorError::StepFailed.code())
        );
        row.state = RestoreState::Done;
        assert_eq!(
            restore_reply(&row, true, None).state,
            Some(OutcomeState::Succeeded)
        );
        row.state = RestoreState::Reverted;
        assert_eq!(
            restore_reply(&row, false, None).state,
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
        let reply = capture_reply(
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
        let failed = capture_reply(
            &capture(CaptureState::Failed),
            false,
            Some(ExecutorError::StepFailed),
        );
        assert_eq!(failed.state, Some(OutcomeState::Failed));
        assert_eq!(failed.unclaimed_snapshot_id, None);
        assert_eq!(failed.exit_code(), 5);
        let snapshot = "c".repeat(64);
        let settled = capture_reply(
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
        let done = capture_reply(&capture(CaptureState::Succeeded), true, None);
        assert_eq!(done.state, Some(OutcomeState::Succeeded));
        assert_eq!(done.unclaimed_snapshot_id, None);
        let running = capture_reply(&capture(CaptureState::Running), false, None);
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
        let reply = provision_reply(&provision, false, Some(ExecutorError::StepFailed));
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
            super::app_release_reply(&row, false, None).state,
            Some(OutcomeState::Intent)
        );
        row.state = rustiron_journal::AppReleaseState::Done;
        assert_eq!(
            super::app_release_reply(&row, false, None).state,
            Some(OutcomeState::Succeeded)
        );
        row.state = rustiron_journal::AppReleaseState::RolledBack;
        assert_eq!(
            super::app_release_reply(&row, false, None).state,
            Some(OutcomeState::FailedCompensated)
        );
    }
}
