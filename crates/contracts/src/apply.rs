//! Closed operator submission messages. These messages grant no authority.

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::{
    Id, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, ProtocolError,
    codec::validate_json,
    execution::{MAX_SIGNATURE_TEXT, SubmissionReply, decode_submission_reply, encode_submission},
};

/// One bounded signed submission. Plan and grant bytes are forwarded unchanged.
pub struct ApplyRequest {
    /// Operator request correlation ID.
    pub request_id: Id,
    /// Intended executor operation ID.
    pub operation_id: Id,
    /// Executor idempotency key.
    pub idempotency_key: Id,
    /// Already prepared plan object, not an authority assertion.
    pub plan: Vec<u8>,
    /// Already signed grant object.
    pub grant: Vec<u8>,
    /// Detached signature text.
    pub signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRequest<'a> {
    schema_version: u16,
    request_id: Id,
    method: ApplyMethod,
    #[serde(borrow, deserialize_with = "crate::codec::object")]
    params: Params<'a>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ApplyMethod {
    PlanApply,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Params<'a> {
    operation_id: Id,
    idempotency_key: Id,
    #[serde(borrow)]
    plan: &'a RawValue,
    #[serde(borrow)]
    grant: &'a RawValue,
    signature: String,
}

#[derive(Serialize)]
struct OutgoingRequest<'a> {
    schema_version: u16,
    request_id: &'a Id,
    method: &'static str,
    params: OutgoingParams<'a>,
}

#[derive(Serialize)]
struct OutgoingParams<'a> {
    operation_id: &'a Id,
    idempotency_key: &'a Id,
    plan: &'a RawValue,
    grant: &'a RawValue,
    signature: &'a str,
}

/// Decode a closed request, rejecting duplicate members and non-object signed data.
pub fn decode_apply_request(bytes: &[u8]) -> Result<ApplyRequest, ProtocolError> {
    validate_json(bytes, MAX_REQUEST_BYTES, ProtocolError::RequestTooLarge)?;
    let wire: WireRequest<'_> =
        serde_json::from_slice(bytes).map_err(|_| ProtocolError::InvalidMessage)?;
    if wire.schema_version != 1 {
        return Err(ProtocolError::UnsupportedVersion);
    }
    match wire.method {
        ApplyMethod::PlanApply => {}
    }
    if !wire.params.plan.get().starts_with('{') || !wire.params.grant.get().starts_with('{') {
        return Err(ProtocolError::InvalidMessage);
    }
    let params = wire.params;
    encode_submission(
        &params.operation_id,
        &params.idempotency_key,
        params.plan.get().as_bytes(),
        params.grant.get().as_bytes(),
        &params.signature,
    )?;
    Ok(ApplyRequest {
        request_id: wire.request_id,
        operation_id: params.operation_id,
        idempotency_key: params.idempotency_key,
        plan: params.plan.get().as_bytes().to_vec(),
        grant: params.grant.get().as_bytes().to_vec(),
        signature: params.signature,
    })
}

/// Encode a request, preserving the raw signed objects inside the envelope.
pub fn encode_apply_request(request: &ApplyRequest) -> Result<Vec<u8>, ProtocolError> {
    if request.plan.trim_ascii() != request.plan || request.grant.trim_ascii() != request.grant {
        return Err(ProtocolError::InvalidMessage);
    }
    if request
        .plan
        .len()
        .saturating_add(request.grant.len())
        .saturating_add(request.signature.len())
        > MAX_REQUEST_BYTES
    {
        return Err(ProtocolError::RequestTooLarge);
    }
    if request.signature.len() > MAX_SIGNATURE_TEXT {
        return Err(ProtocolError::InvalidMessage);
    }
    let raw = |bytes: &[u8]| -> Result<Box<RawValue>, ProtocolError> {
        let text = std::str::from_utf8(bytes).map_err(|_| ProtocolError::InvalidMessage)?;
        RawValue::from_string(text.to_owned()).map_err(|_| ProtocolError::InvalidMessage)
    };
    let plan = raw(&request.plan)?;
    let grant = raw(&request.grant)?;
    let bytes = serde_json::to_vec(&OutgoingRequest {
        schema_version: 1,
        request_id: &request.request_id,
        method: "plan_apply",
        params: OutgoingParams {
            operation_id: &request.operation_id,
            idempotency_key: &request.idempotency_key,
            plan: &plan,
            grant: &grant,
            signature: &request.signature,
        },
    })
    .map_err(|_| ProtocolError::InvalidMessage)?;
    decode_apply_request(&bytes)?;
    Ok(bytes)
}

/// Why a submission was known not to have been sent.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotSentReason {
    /// The single local worker was already active.
    Busy,
    /// The worker or its connection was unavailable before sending.
    Unavailable,
    /// The local requester or coordinator peer was not authorized.
    Unauthorized,
    /// Local socket configuration was invalid before sending.
    InvalidConfiguration,
}

/// A coordinator observation, never an inference from a missing journal row.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApplyOutcome {
    /// This attempt was not sent; an earlier attempt may still be in flight.
    NotSent {
        /// The reason the submission was not sent.
        reason: NotSentReason,
    },
    /// Sending may have begun; neither admission nor outcome is known.
    OutcomeUnknown,
    /// The executor returned a validated, correlated reply.
    ExecutorReply {
        /// The correlated executor reply.
        reply: SubmissionReply,
    },
}

/// An apply response associated with both the request and operation.
#[derive(Debug, Eq, PartialEq)]
pub struct ApplyResponse {
    /// Operator request ID.
    pub request_id: Id,
    /// Requested operation ID.
    pub operation_id: Id,
    /// Transport or executor result.
    pub outcome: ApplyOutcome,
}

/// Encode a correlated response without asserting admission for unknown work.
pub fn encode_apply_response(response: &ApplyResponse) -> Result<Vec<u8>, ProtocolError> {
    let bytes = serde_json::to_vec(&serde_json::json!({"schema_version": 1,
        "request_id": response.request_id, "status": "ok", "data": {"kind": "plan_apply",
        "value": {"operation_id": response.operation_id, "outcome": response.outcome}}, "error": null
    })).map_err(|_| ProtocolError::InvalidMessage)?;
    decode_apply_response(&bytes, &response.request_id, &response.operation_id)?;
    Ok(bytes)
}

/// Decode and correlate the response, including any executor-reported operation.
pub fn decode_apply_response(
    bytes: &[u8],
    request_id: &Id,
    operation_id: &Id,
) -> Result<ApplyResponse, ProtocolError> {
    validate_json(bytes, MAX_RESPONSE_BYTES, ProtocolError::ResponseTooLarge)?;
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| ProtocolError::InvalidMessage)?;
    let object = value.as_object().ok_or(ProtocolError::InvalidMessage)?;
    if object
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        != Some(1)
    {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let actual_request: Id = serde_json::from_value(
        object
            .get("request_id")
            .cloned()
            .ok_or(ProtocolError::InvalidMessage)?,
    )
    .map_err(|_| ProtocolError::InvalidMessage)?;
    if &actual_request != request_id
        || object.get("status").and_then(serde_json::Value::as_str) != Some("ok")
        || object.get("error") != Some(&serde_json::Value::Null)
    {
        return Err(ProtocolError::InvalidMessage);
    }
    let data = object
        .get("data")
        .and_then(serde_json::Value::as_object)
        .ok_or(ProtocolError::InvalidMessage)?;
    if data.get("kind").and_then(serde_json::Value::as_str) != Some("plan_apply") {
        return Err(ProtocolError::InvalidMessage);
    }
    let value = data
        .get("value")
        .and_then(serde_json::Value::as_object)
        .ok_or(ProtocolError::InvalidMessage)?;
    let actual_operation: Id = serde_json::from_value(
        value
            .get("operation_id")
            .cloned()
            .ok_or(ProtocolError::InvalidMessage)?,
    )
    .map_err(|_| ProtocolError::InvalidMessage)?;
    if &actual_operation != operation_id {
        return Err(ProtocolError::InvalidMessage);
    }
    let outcome_value = value
        .get("outcome")
        .filter(|outcome| outcome.is_object())
        .ok_or(ProtocolError::InvalidMessage)?;
    let outcome_object = outcome_value
        .as_object()
        .ok_or(ProtocolError::InvalidMessage)?;
    let outcome: ApplyOutcome =
        serde_json::from_value(outcome_value.clone()).map_err(|_| ProtocolError::InvalidMessage)?;
    match &outcome {
        ApplyOutcome::NotSent { .. } if outcome_object.contains_key("reply") => {
            return Err(ProtocolError::InvalidMessage);
        }
        ApplyOutcome::OutcomeUnknown
            if outcome_object.contains_key("reply") || outcome_object.contains_key("reason") =>
        {
            return Err(ProtocolError::InvalidMessage);
        }
        ApplyOutcome::ExecutorReply { .. } if outcome_object.contains_key("reason") => {
            return Err(ProtocolError::InvalidMessage);
        }
        _ => {}
    }
    if let ApplyOutcome::ExecutorReply { .. } = &outcome {
        let reply = outcome_value
            .get("reply")
            .filter(|reply| reply.is_object())
            .ok_or(ProtocolError::InvalidMessage)?;
        let bytes = serde_json::to_vec(reply).map_err(|_| ProtocolError::InvalidMessage)?;
        decode_submission_reply(&bytes, operation_id)?;
    }
    Ok(ApplyResponse {
        request_id: actual_request,
        operation_id: actual_operation,
        outcome,
    })
}
