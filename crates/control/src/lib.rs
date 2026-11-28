//! Unprivileged local-development coordinator; inventory observations grant no authority.
#![warn(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "W672: production code returns errors; tests may unwrap (clippy.toml)"
)]

use rustiron_contracts::{
    apply::{
        ApplyOutcome, ApplyRequest, ApplyResponse, NotSentReason, decode_apply_request,
        encode_apply_response,
    },
    local::{self, DEADLINE, MAX_CONNECTIONS},
    *,
};
use std::{
    fs,
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

pub mod executor_transport;
mod journal_sites;
mod observe;
pub mod submission_worker;

/// Binds only a fresh pathname in a private directory; never removes an existing entry.
pub fn bind(path: &Path) -> Result<UnixListener, ErrorCode> {
    let uid = local::operator_uid()?;
    local::check_parent(path, uid)?;
    let listener = UnixListener::bind(path).map_err(local::io_code)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(local::io_code)?;
    Ok(listener)
}

/// Coordinator owns at most one serialized, process-locked inventory connection.
pub struct Coordinator {
    inventory: Option<Mutex<rustiron_core::InventoryStore>>,
    executor: Option<executor_transport::ExecutorTransport>,
    submissions: Option<submission_worker::SubmissionWorker>,
}

impl Coordinator {
    /// Creates a doctor-only or inventory-enabled local coordinator.
    pub fn new(inventory: Option<rustiron_core::InventoryStore>) -> Self {
        Self {
            inventory: inventory.map(Mutex::new),
            executor: None,
            submissions: None,
        }
    }

    /// Enables executor queries using a coordinator-owned endpoint configuration.
    pub fn with_executor(mut self, executor: executor_transport::ExecutorTransport) -> Self {
        self.submissions = Some(submission_worker::SubmissionWorker::new(executor.clone()));
        self.executor = Some(executor);
        self
    }

    /// Serves authenticated requests with bounded workers; caller owns socket lifecycle.
    pub fn serve(self, listener: UnixListener) -> Result<(), ErrorCode> {
        local::operator_uid()?;
        let coordinator = Arc::new(self);
        let active = Arc::new(AtomicUsize::new(0));
        loop {
            let (stream, _) = listener.accept().map_err(local::io_code)?;
            if active
                .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                    (n < MAX_CONNECTIONS).then_some(n + 1)
                })
                .is_err()
            {
                drop(stream);
                continue;
            }
            let permit = Permit(Arc::clone(&active));
            let coordinator = Arc::clone(&coordinator);
            thread::Builder::new()
                .name("rustiron-client".into())
                .spawn(move || {
                    let _permit = permit;
                    coordinator.handle(stream)
                })
                .map_err(|_| ErrorCode::DependencyUnavailable)?;
        }
    }

    /// Handles one authenticated frame; false means no complete response was delivered.
    pub fn handle(&self, mut stream: UnixStream) -> bool {
        let deadline = Instant::now() + DEADLINE;
        let response = process_request(
            &mut stream,
            deadline,
            self.inventory.as_ref(),
            self.executor.as_ref(),
            self.submissions.as_ref(),
        );
        let bytes = match response {
            OperatorResponse::Read(response) => encode_response(&response),
            OperatorResponse::Apply(response) => encode_apply_response(&response),
        };
        let Ok(bytes) = bytes else {
            return false;
        };
        local::write_frame(
            &mut stream,
            &bytes,
            MAX_RESPONSE_BYTES,
            ErrorCode::ResponseTooLarge,
            deadline,
        )
        .is_ok()
    }
}

/// Serves the original doctor-only development mode, without a state directory.
pub fn serve(listener: UnixListener) -> Result<(), ErrorCode> {
    Coordinator::new(None).serve(listener)
}

struct Permit(Arc<AtomicUsize>);
impl Drop for Permit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Handles one connection with the same-UID development policy before parsing data.
///
/// This policy is not the future separately enrolled service/operator policy.
/// Returns false when no complete response could be delivered. A disconnected
/// or timed-out read client has no admitted operation to recover or retry.
pub fn handle_connection(stream: UnixStream) -> bool {
    Coordinator::new(None).handle(stream)
}

fn process_request(
    stream: &mut UnixStream,
    deadline: Instant,
    inventory: Option<&Mutex<rustiron_core::InventoryStore>>,
    executor: Option<&executor_transport::ExecutorTransport>,
    submissions: Option<&submission_worker::SubmissionWorker>,
) -> OperatorResponse {
    let outcome = (|| {
        let uid = local::operator_uid()?;
        local::require_peer(stream, uid)?;
        let bytes = local::read_frame(
            stream,
            MAX_REQUEST_BYTES,
            ErrorCode::RequestTooLarge,
            deadline,
        )?;
        Ok::<_, ErrorCode>(bytes)
    })();
    let bytes = match outcome {
        Ok(bytes) => bytes,
        Err(code) => {
            return OperatorResponse::Read(Response {
                request_id: None,
                result: Err(ApiError::new(code)),
            });
        }
    };
    let is_apply = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|value| {
            value
                .get("method")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .is_some_and(|method| method == "plan_apply");
    if is_apply {
        return match decode_apply_request(&bytes) {
            Ok(request) => OperatorResponse::Apply(apply(request, submissions, deadline)),
            Err(error) => OperatorResponse::Read(Response {
                request_id: None,
                result: Err(error.api_error()),
            }),
        };
    }
    match decode_request(&bytes) {
        Ok(request) => OperatorResponse::Read(Response {
            request_id: Some(request.request_id.clone()),
            result: match request.command {
                ReadCommand::Doctor => Ok(ReadData::Doctor(observe::doctor())),
                ReadCommand::OperationStatus { operation_id } => executor
                    .ok_or_else(|| ApiError::new(ErrorCode::DependencyUnavailable))
                    .and_then(|executor| {
                        executor
                            .status_until(
                                &rustiron_contracts::execution::StatusQuery {
                                    request_id: request.request_id,
                                    operation_id,
                                },
                                deadline,
                            )
                            .map_err(ApiError::new)
                    })
                    .and_then(|response| response.result.map(ReadData::OperationStatus)),
                ReadCommand::EvidenceExport { operation_id } => executor
                    .ok_or_else(|| ApiError::new(ErrorCode::DependencyUnavailable))
                    .and_then(|executor| {
                        executor
                            .evidence_until(
                                &rustiron_contracts::execution::EvidenceQuery {
                                    request_id: request.request_id,
                                    operation_id,
                                },
                                deadline,
                            )
                            .map_err(ApiError::new)
                    })
                    .and_then(|result| result.map(ReadData::EvidenceExport)),
                ReadCommand::HostSummary => executor
                    .ok_or_else(|| ApiError::new(ErrorCode::DependencyUnavailable))
                    .and_then(|executor| {
                        executor
                            .host_summary_until(
                                &rustiron_contracts::summary::HostSummaryQuery {
                                    request_id: request.request_id,
                                },
                                deadline,
                            )
                            .map_err(ApiError::new)
                    })
                    .and_then(|result| result.map(ReadData::HostSummary)),
                // D-103 (W778): with no operator report, the executor journal answers.
                command => match has_report(inventory) {
                    Ok(true) => read_inventory(inventory, command).map_err(ApiError::new),
                    Ok(false) => {
                        journal_sites::read(executor, request.request_id, command, deadline)
                    }
                    Err(code) => Err(ApiError::new(code)),
                },
            },
        }),
        Err(error) => OperatorResponse::Read(Response {
            request_id: None,
            result: Err(error.api_error()),
        }),
    }
}

enum OperatorResponse {
    Read(Response),
    Apply(ApplyResponse),
}

fn apply(
    request: ApplyRequest,
    worker: Option<&submission_worker::SubmissionWorker>,
    deadline: Instant,
) -> ApplyResponse {
    use executor_transport::SubmitFailure;
    use submission_worker::StartFailure;

    let outcome = match worker {
        None => ApplyOutcome::NotSent {
            reason: NotSentReason::Unavailable,
        },
        Some(worker) => match worker.start(
            &request.operation_id,
            &request.idempotency_key,
            &request.plan,
            &request.grant,
            &request.signature,
        ) {
            Err(StartFailure::Busy) => ApplyOutcome::NotSent {
                reason: NotSentReason::Busy,
            },
            Err(StartFailure::InvalidInput | StartFailure::Unavailable) => ApplyOutcome::NotSent {
                reason: NotSentReason::Unavailable,
            },
            Ok(ticket) => {
                // Reserve a small amount of the handler budget for framing the reply.
                let wait = deadline
                    .saturating_duration_since(Instant::now())
                    .saturating_sub(Duration::from_millis(200));
                match ticket.wait_timeout(wait) {
                    Ok(Ok(reply)) => ApplyOutcome::ExecutorReply { reply },
                    Ok(Err(SubmitFailure::InvalidInput | SubmitFailure::NotSent)) => {
                        ApplyOutcome::NotSent {
                            reason: NotSentReason::Unavailable,
                        }
                    }
                    Ok(Err(SubmitFailure::OutcomeUnknown)) | Err(_) => ApplyOutcome::OutcomeUnknown,
                }
            }
        },
    };
    ApplyResponse {
        request_id: request.request_id,
        operation_id: request.operation_id,
        outcome,
    }
}

/// Whether the inventory holds an operator report; a missing store has none.
fn has_report(inventory: Option<&Mutex<rustiron_core::InventoryStore>>) -> Result<bool, ErrorCode> {
    let Some(mutex) = inventory else {
        return Ok(false);
    };
    let mut store = mutex
        .try_lock()
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    store.has_report()
}

fn read_inventory(
    inventory: Option<&Mutex<rustiron_core::InventoryStore>>,
    command: ReadCommand,
) -> Result<ReadData, ErrorCode> {
    let mutex = inventory.ok_or(ErrorCode::DependencyUnavailable)?;
    // Do not queue unbounded waits behind database work or a poisoned coordinator.
    let mut store = mutex
        .try_lock()
        .map_err(|_| ErrorCode::DependencyUnavailable)?;
    match command {
        ReadCommand::SiteList { cursor, limit } => {
            store.list(cursor.as_ref(), limit).map(ReadData::SiteList)
        }
        ReadCommand::SiteInspect { site_id } => store.inspect(&site_id).map(ReadData::SiteInspect),
        ReadCommand::Doctor
        | ReadCommand::OperationStatus { .. }
        | ReadCommand::EvidenceExport { .. }
        | ReadCommand::HostSummary => Err(ErrorCode::InvalidRequest),
    }
}
