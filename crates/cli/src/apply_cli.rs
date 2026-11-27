//! Local file-based submission; never signs or passes file paths to the executor.

use rustiron_contracts::{
    ErrorCode, Id, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, ReadCommand, ReadData, Request, Response,
    apply::{
        ApplyOutcome, ApplyRequest, ApplyResponse, NotSentReason, decode_apply_response,
        encode_apply_request, encode_apply_response,
    },
    execution::{MAX_SIGNATURE_TEXT, OutcomeState, SubmissionReply},
    local::{self, DEADLINE},
};
use std::{
    io::Write,
    path::Path,
    process::ExitCode,
    time::{Duration, Instant},
};

use crate::{Output, emit, failure, file_input};

/// W251: default bound on waiting for a recorded state after the reply deadline.
pub(crate) const DEFAULT_WAIT_SECONDS: u64 = 300;
/// Upper bound accepted for `--wait-seconds`.
pub(crate) const MAX_WAIT_SECONDS: u64 = 3600;
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// The identity of one apply attempt and how long to wait for its state.
pub(crate) struct Attempt {
    pub(crate) operation_id: Id,
    pub(crate) idempotency_key: Id,
    pub(crate) wait: Duration,
}

pub(crate) fn run(
    socket: &Path,
    output: Output,
    plan: &Path,
    grant: &Path,
    signature: &Path,
    attempt: Attempt,
) -> ExitCode {
    let loaded = (|| {
        let plan = file_input::read(plan, MAX_REQUEST_BYTES)?;
        let grant = file_input::read(grant, MAX_REQUEST_BYTES)?;
        let signature = String::from_utf8(file_input::read(signature, MAX_SIGNATURE_TEXT)?)
            .map_err(|_| ErrorCode::InvalidRequest)?;
        Ok::<_, ErrorCode>((plan, grant, signature))
    })();
    let (plan, grant, signature) = match loaded {
        Ok(loaded) => loaded,
        Err(code) => return emit(&failure(code), output),
    };
    run_bytes(socket, output, plan, grant, signature, attempt)
}

pub(crate) fn run_bytes(
    socket: &Path,
    output: Output,
    plan: Vec<u8>,
    grant: Vec<u8>,
    signature: String,
    attempt: Attempt,
) -> ExitCode {
    let Attempt {
        operation_id,
        idempotency_key,
        wait,
    } = attempt;
    let request = Ok::<_, ErrorCode>(ApplyRequest {
        request_id: crate::cli_request_id(""),
        operation_id,
        idempotency_key,
        plan: plan.trim_ascii().to_vec(),
        grant: grant.trim_ascii().to_vec(),
        signature,
    });
    let request = match request {
        Ok(request) => request,
        Err(code) => return emit(&failure(code), output),
    };
    let bytes = match encode_apply_request(&request) {
        Ok(bytes) => bytes,
        Err(error) => return emit(&failure(error.api_error().code()), output),
    };
    let (response, coordinator) = exchange(socket, &request, &bytes);
    if matches!(response.outcome, ApplyOutcome::OutcomeUnknown)
        && !wait.is_zero()
        && let Some(state) = wait_for_state(socket, &request.operation_id, wait)
    {
        return emit_waited(&response, state, output);
    }
    emit_apply(&response, coordinator, output)
}

/// D-035 (W386): one scheduled submission, without printing. Returns the
/// coordinator's apply response as JSON (with the state recorded after the
/// wait, when the reply deadline passed) and the exit class `apply-file`
/// would give it.
pub(crate) fn submit_quiet(
    socket: &Path,
    plan: &[u8],
    grant: &[u8],
    signature: &str,
    attempt: Attempt,
) -> (serde_json::Value, u8) {
    let request = ApplyRequest {
        request_id: crate::cli_request_id(""),
        operation_id: attempt.operation_id,
        idempotency_key: attempt.idempotency_key,
        plan: plan.trim_ascii().to_vec(),
        grant: grant.trim_ascii().to_vec(),
        signature: signature.to_owned(),
    };
    let Ok(bytes) = encode_apply_request(&request) else {
        return (serde_json::json!({"outcome": "invalid_request"}), 2);
    };
    let (response, _) = exchange(socket, &request, &bytes);
    let mut wire = encode_apply_response(&response)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .unwrap_or(serde_json::Value::Null);
    if matches!(response.outcome, ApplyOutcome::OutcomeUnknown)
        && !attempt.wait.is_zero()
        && let Some(state) = wait_for_state(socket, &request.operation_id, attempt.wait)
    {
        wire["data"]["value"]["outcome"] = serde_json::json!({
            "kind": "recorded_after_wait",
            "state": state,
        });
        return (wire, waited_exit(&response, state));
    }
    let code = outcome_exit(&response.outcome);
    (wire, code)
}

/// The exit class of one apply outcome (SPEC exit table).
fn outcome_exit(outcome: &ApplyOutcome) -> u8 {
    match outcome {
        ApplyOutcome::NotSent {
            reason: NotSentReason::Unauthorized,
        } => 3,
        ApplyOutcome::NotSent {
            reason: NotSentReason::InvalidConfiguration,
        } => 2,
        ApplyOutcome::NotSent { .. } | ApplyOutcome::OutcomeUnknown => 7,
        ApplyOutcome::ExecutorReply { reply } => reply.exit_code(),
    }
}

/// The exit class of a state read after the reply deadline.
fn waited_exit(response: &ApplyResponse, state: OutcomeState) -> u8 {
    SubmissionReply {
        schema_version: 1,
        operation_id: Some(response.operation_id.clone()),
        state: Some(state),
        replay: false,
        error: None,
        unclaimed_snapshot_id: None,
    }
    .exit_code()
}

/// Polls the coordinator's status read until the operation has a recorded
/// state other than `intent`, or `wait` passes. Read errors (busy, unknown
/// operation, a restarting coordinator) are not final: a missing status is
/// not proof of anything, so the answer then stays unknown.
fn wait_for_state(socket: &Path, operation_id: &Id, wait: Duration) -> Option<OutcomeState> {
    let deadline = Instant::now() + wait;
    for attempt in 0u64.. {
        let request = Request {
            request_id: crate::cli_request_id(&format!("-s{attempt}")),
            command: ReadCommand::OperationStatus {
                operation_id: operation_id.clone(),
            },
        };
        if let Ok(Response {
            result: Ok(ReadData::OperationStatus(status)),
            ..
        }) = crate::exchange(socket, &request)
            && status.operation_id == *operation_id
            && status.state != OutcomeState::Intent
        {
            return Some(status.state);
        }
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        std::thread::sleep(POLL_INTERVAL.min(deadline - now));
    }
    None
}

/// Reports a state read after the reply deadline. It is the executor's
/// recorded state, not an executor reply: `replay` is not known.
fn emit_waited(response: &ApplyResponse, state: OutcomeState, output: Output) -> ExitCode {
    let code = waited_exit(response, state);
    let bytes = match output {
        Output::Json => encode_apply_response(response).ok().and_then(|bytes| {
            let mut wire: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
            wire["data"]["value"]["outcome"] = serde_json::json!({
                "kind": "recorded_after_wait",
                "state": state,
            });
            let mut bytes = serde_json::to_vec(&wire).ok()?;
            bytes.push(b'\n');
            Some(bytes)
        }),
        Output::Human => Some(
            format!(
                "Operation {}: the reply deadline passed; recorded state {state:?} after waiting.\n",
                response.operation_id.as_str()
            )
            .into_bytes(),
        ),
    };
    match bytes {
        Some(bytes) if std::io::stdout().lock().write_all(&bytes).is_ok() => ExitCode::from(code),
        _ => ExitCode::from(7),
    }
}

/// Whether the CLI reached the coordinator socket. It only selects the
/// operator diagnostic; the wire outcome and exit code do not depend on it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Coordinator {
    /// The socket accepted the connection, or the attempt stopped before it.
    NotMissing,
    /// No socket or no listener: for example, a coordinator stopped by its
    /// start limit, which removes its runtime directory (W364, W365).
    Unreachable,
}

fn exchange(socket: &Path, request: &ApplyRequest, bytes: &[u8]) -> (ApplyResponse, Coordinator) {
    let response = |outcome| ApplyResponse {
        request_id: request.request_id.clone(),
        operation_id: request.operation_id.clone(),
        outcome,
    };
    let deadline = Instant::now() + DEADLINE;
    let uid = match local::operator_uid() {
        Ok(uid) => uid,
        Err(code) => {
            let outcome = ApplyOutcome::NotSent {
                reason: not_sent_reason(code),
            };
            return (response(outcome), Coordinator::NotMissing);
        }
    };
    let mut stream = match local::connect(socket, uid, deadline) {
        Ok(stream) => stream,
        Err(code) => {
            let reason = not_sent_reason(code);
            let coordinator = if reason == NotSentReason::Unavailable {
                Coordinator::Unreachable
            } else {
                Coordinator::NotMissing
            };
            return (response(ApplyOutcome::NotSent { reason }), coordinator);
        }
    };
    (
        exchange_frames(&mut stream, request, bytes, deadline),
        Coordinator::NotMissing,
    )
}

fn exchange_frames(
    stream: &mut std::os::unix::net::UnixStream,
    request: &ApplyRequest,
    bytes: &[u8],
    deadline: Instant,
) -> ApplyResponse {
    let response = |outcome| ApplyResponse {
        request_id: request.request_id.clone(),
        operation_id: request.operation_id.clone(),
        outcome,
    };
    if local::write_frame(
        stream,
        bytes,
        MAX_REQUEST_BYTES,
        ErrorCode::RequestTooLarge,
        deadline,
    )
    .is_err()
    {
        return response(ApplyOutcome::OutcomeUnknown);
    }
    let Ok(reply) = local::read_frame(
        stream,
        MAX_RESPONSE_BYTES,
        ErrorCode::ResponseTooLarge,
        deadline,
    ) else {
        return response(ApplyOutcome::OutcomeUnknown);
    };
    decode_apply_response(&reply, &request.request_id, &request.operation_id)
        .unwrap_or_else(|_| response(ApplyOutcome::OutcomeUnknown))
}

fn not_sent_reason(code: ErrorCode) -> NotSentReason {
    match code {
        ErrorCode::UnauthorizedPeer => NotSentReason::Unauthorized,
        ErrorCode::InvalidRequest => NotSentReason::InvalidConfiguration,
        _ => NotSentReason::Unavailable,
    }
}

/// Bounded stderr diagnostic (SPEC: diagnostics go to stderr) for an attempt
/// that never reached the coordinator socket. It names no path or peer data.
const COORDINATOR_UNREACHABLE: &str = "rustiron: the coordinator socket could not be reached; \
    this attempt was not sent. Check the coordinator service, then send the same operation ID \
    and idempotency key again.\n";

fn emit_apply(response: &ApplyResponse, coordinator: Coordinator, output: Output) -> ExitCode {
    let unreachable = coordinator == Coordinator::Unreachable
        && matches!(response.outcome, ApplyOutcome::NotSent { .. });
    if unreachable {
        // A failed stderr write changes nothing: stdout and the exit code
        // still carry the `not_sent` outcome.
        let _ = std::io::stderr()
            .lock()
            .write_all(COORDINATOR_UNREACHABLE.as_bytes());
    }
    let code = outcome_exit(&response.outcome);
    let bytes = match output {
        Output::Json => encode_apply_response(response).map(|mut bytes| { bytes.push(b'\n'); bytes }),
        Output::Human => Ok(match &response.outcome {
            ApplyOutcome::NotSent { .. } if unreachable => format!("Operation {}: this attempt was not sent (the coordinator socket could not be reached); earlier attempts may still be in flight.\n", response.operation_id.as_str()),
            ApplyOutcome::NotSent { reason } => format!("Operation {}: this attempt was not sent ({reason:?}); earlier attempts may still be in flight.\n", response.operation_id.as_str()),
            ApplyOutcome::OutcomeUnknown => format!("Operation {}: outcome unknown. Reconcile before retrying; a missing status alone is not proof of safety.\n", response.operation_id.as_str()),
            ApplyOutcome::ExecutorReply { reply } => format!("Operation {}: recorded state {:?}, replay {}, error {:?}.\n", response.operation_id.as_str(), reply.state, reply.replay, reply.error),
        }.into_bytes()),
    };
    match bytes {
        Ok(bytes) if std::io::stdout().lock().write_all(&bytes).is_ok() => ExitCode::from(code),
        _ => ExitCode::from(7),
    }
}
