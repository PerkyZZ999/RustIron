//! Executor submission wire format (schema v1) for the isolated lab fixture.
//!
//! A decoded submission is untrusted input. Peer identity comes from kernel
//! socket credentials, never from these bytes; plan/grant bytes are validated
//! by [`crate::approval`] and the executor, not here.

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::{
    ApiError, Id, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, ProtocolError, codec::validate_json,
};

/// Maximum armored SSHSIG text accepted in one submission.
pub const MAX_SIGNATURE_TEXT: usize = 16 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum StatusMethod {
    OperationStatus,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StatusParams {
    operation_id: Id,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireStatusQuery {
    schema_version: u16,
    request_id: Id,
    method: StatusMethod,
    #[serde(deserialize_with = "crate::codec::object")]
    params: StatusParams,
}

#[derive(Deserialize)]
struct StatusQueryHeader {
    request_id: Id,
    method: StatusMethod,
}

/// A bounded status query; the executor independently authorizes the peer.
#[derive(Debug, Eq, PartialEq)]
pub struct StatusQuery {
    /// Correlation identifier for this query.
    pub request_id: Id,
    /// Identifier of the recorded operation to inspect.
    pub operation_id: Id,
}

/// Decodes a closed, duplicate-free executor status query.
pub fn decode_status_query(bytes: &[u8]) -> Result<StatusQuery, ProtocolError> {
    validate_json(bytes, MAX_REQUEST_BYTES, ProtocolError::RequestTooLarge)?;
    let query: WireStatusQuery =
        serde_json::from_slice(bytes).map_err(|_| ProtocolError::InvalidMessage)?;
    if query.schema_version != 1 {
        return Err(ProtocolError::UnsupportedVersion);
    }
    Ok(StatusQuery {
        request_id: query.request_id,
        operation_id: query.params.operation_id,
    })
}

/// Identifies a status query for a correlated parse error after duplicate checks.
pub fn status_query_request_id(bytes: &[u8]) -> Result<Id, ProtocolError> {
    validate_json(bytes, MAX_REQUEST_BYTES, ProtocolError::RequestTooLarge)?;
    let header: StatusQueryHeader =
        serde_json::from_slice(bytes).map_err(|_| ProtocolError::InvalidMessage)?;
    match header.method {
        StatusMethod::OperationStatus => Ok(header.request_id),
    }
}

/// Encodes one executor status query with validated identifiers.
pub fn encode_status_query(query: &StatusQuery) -> Result<Vec<u8>, ProtocolError> {
    let wire = WireStatusQuery {
        schema_version: 1,
        request_id: query.request_id.clone(),
        method: StatusMethod::OperationStatus,
        params: StatusParams {
            operation_id: query.operation_id.clone(),
        },
    };
    let bytes = serde_json::to_vec(&wire).map_err(|_| ProtocolError::InvalidMessage)?;
    decode_status_query(&bytes)?;
    Ok(bytes)
}

/// Recorded operation state returned by an authorized status query.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StatusValue {
    /// The queried operation identity.
    pub operation_id: Id,
    /// Its stored state, not a fresh observation of the host.
    pub state: OutcomeState,
}

#[derive(Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
enum StatusData {
    OperationStatus(#[serde(deserialize_with = "crate::codec::object")] StatusValue),
}

/// A correlated status response, containing state or a fixed public error.
#[derive(Debug)]
pub struct StatusResponse {
    /// Query correlation identifier.
    pub request_id: Id,
    /// Recorded state or an error; neither authorizes an effect.
    pub result: Result<StatusValue, ApiError>,
}

/// Decodes and correlates a bounded status response to its query and operation.
pub fn decode_status_response(
    bytes: &[u8],
    query: &StatusQuery,
) -> Result<StatusResponse, ProtocolError> {
    validate_json(bytes, MAX_RESPONSE_BYTES, ProtocolError::ResponseTooLarge)?;
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| ProtocolError::InvalidMessage)?;
    let object = value.as_object().ok_or(ProtocolError::InvalidMessage)?;
    for field in ["schema_version", "request_id", "status", "data", "error"] {
        if !object.contains_key(field) {
            return Err(ProtocolError::InvalidMessage);
        }
    }
    let version = object["schema_version"]
        .as_u64()
        .and_then(|version| u16::try_from(version).ok())
        .ok_or(ProtocolError::InvalidMessage)?;
    if version != 1 {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let request_id: Id = serde_json::from_value(object["request_id"].clone())
        .map_err(|_| ProtocolError::InvalidMessage)?;
    if request_id != query.request_id {
        return Err(ProtocolError::InvalidMessage);
    }
    let result = match object["status"].as_str() {
        Some("ok") if object["error"].is_null() => {
            let StatusData::OperationStatus(data) = serde_json::from_value(object["data"].clone())
                .map_err(|_| ProtocolError::InvalidMessage)?;
            if data.operation_id != query.operation_id {
                return Err(ProtocolError::InvalidMessage);
            }
            Ok(data)
        }
        Some("error") if object["data"].is_null() => {
            let error_object = object["error"]
                .as_object()
                .ok_or(ProtocolError::InvalidMessage)?;
            if ["code", "message", "retryable", "operation_id", "details"]
                .iter()
                .any(|field| !error_object.contains_key(*field))
            {
                return Err(ProtocolError::InvalidMessage);
            }
            let error: ApiError = serde_json::from_value(object["error"].clone())
                .map_err(|_| ProtocolError::InvalidMessage)?;
            if !error.is_bounded_read_error() {
                return Err(ProtocolError::InvalidMessage);
            }
            Err(error)
        }
        _ => return Err(ProtocolError::InvalidMessage),
    };
    Ok(StatusResponse { request_id, result })
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum EvidenceMethod {
    EvidenceExport,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceParams {
    operation_id: Id,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireEvidenceQuery {
    schema_version: u16,
    request_id: Id,
    method: EvidenceMethod,
    #[serde(deserialize_with = "crate::codec::object")]
    params: EvidenceParams,
}

/// A read-only request for one self-attested receipt.
#[derive(Debug, Eq, PartialEq)]
pub struct EvidenceQuery {
    /// Correlation identifier for this query.
    pub request_id: Id,
    /// Recorded operation whose receipt is requested.
    pub operation_id: Id,
}

/// The sealed receipt document. It is not an independent attestation.
///
/// W392 (D-040 item 6): the executor states whether the host receipt key
/// signed the canonical body. A signature is checked for shape only here;
/// `scripts/check_receipt.py` verifies it offline with the public key the
/// operator recorded. A receipt from an older executor states neither.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "WireEvidenceReceipt")]
pub struct EvidenceReceipt {
    /// Receipt body.
    pub body: serde_json::Value,
    /// SHA-256 of the canonical body.
    pub body_sha256: String,
    /// [`RECEIPT_ATTESTATION_SIGNED`] or [`RECEIPT_ATTESTATION_UNSIGNED`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
    /// The host receipt key signature, present only on a signed receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<ReceiptSignature>,
}

/// SSHSIG namespace of a receipt signature; it separates receipt signatures
/// from plan signatures (`rustiron-plan-v1`).
pub const RECEIPT_SIGNATURE_NAMESPACE: &str = "rustiron-receipt-v1";
/// The label of a receipt that the host receipt key signed.
pub const RECEIPT_ATTESTATION_SIGNED: &str = "self-attested, signed";
/// The label of a receipt from a host without a receipt key.
pub const RECEIPT_ATTESTATION_UNSIGNED: &str = "self-attested, unsigned";
/// Maximum armored receipt signature text. An Ed25519 SSHSIG is about 300 bytes.
pub const MAX_RECEIPT_SIGNATURE_TEXT: usize = 4096;
const ARMOR_BEGIN: &str = "-----BEGIN SSH SIGNATURE-----\n";
const ARMOR_END: &str = "-----END SSH SIGNATURE-----\n";

/// An SSHSIG over the canonical receipt body by the host receipt key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptSignature {
    /// Always `sshsig`.
    pub format: String,
    /// Always [`RECEIPT_SIGNATURE_NAMESPACE`].
    pub namespace: String,
    /// OpenSSH `SHA256:` fingerprint of the signing key.
    pub key_fingerprint: String,
    /// The armored signature that `ssh-keygen -Y sign` wrote.
    pub armored: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEvidenceReceipt {
    body: serde_json::Value,
    body_sha256: String,
    #[serde(default)]
    attestation: Option<String>,
    #[serde(default)]
    signature: Option<ReceiptSignature>,
}

impl TryFrom<WireEvidenceReceipt> for EvidenceReceipt {
    type Error = &'static str;

    fn try_from(wire: WireEvidenceReceipt) -> Result<Self, Self::Error> {
        match (wire.attestation.as_deref(), &wire.signature) {
            (None, None) | (Some(RECEIPT_ATTESTATION_UNSIGNED), None) => {}
            (Some(RECEIPT_ATTESTATION_SIGNED), Some(signature)) if signature.is_valid_shape() => {}
            _ => return Err("receipt attestation and signature disagree"),
        }
        Ok(Self {
            body: wire.body,
            body_sha256: wire.body_sha256,
            attestation: wire.attestation,
            signature: wire.signature,
        })
    }
}

impl ReceiptSignature {
    /// Fixed format and namespace, an OpenSSH SHA-256 fingerprint, and one
    /// bounded armored block.
    fn is_valid_shape(&self) -> bool {
        let fingerprint = self.key_fingerprint.strip_prefix("SHA256:");
        let armored = &self.armored;
        self.format == "sshsig"
            && self.namespace == RECEIPT_SIGNATURE_NAMESPACE
            && fingerprint.is_some_and(|text| {
                text.len() == 43
                    && text
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
            })
            && armored.len() <= MAX_RECEIPT_SIGNATURE_TEXT
            && armored
                .strip_prefix(ARMOR_BEGIN)
                .and_then(|rest| rest.strip_suffix(ARMOR_END))
                .is_some_and(|inner| {
                    !inner.is_empty()
                        && inner.bytes().all(|b| {
                            b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'\n')
                        })
                })
    }
}

/// Recorded receipt for one operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceValue {
    /// The queried operation.
    pub operation_id: Id,
    /// Self-attested receipt.
    #[serde(deserialize_with = "crate::codec::object")]
    pub receipt: EvidenceReceipt,
}

/// Decodes a closed evidence query.
pub fn decode_evidence_query(bytes: &[u8]) -> Result<EvidenceQuery, ProtocolError> {
    validate_json(bytes, MAX_REQUEST_BYTES, ProtocolError::RequestTooLarge)?;
    let query: WireEvidenceQuery =
        serde_json::from_slice(bytes).map_err(|_| ProtocolError::InvalidMessage)?;
    if query.schema_version != 1 {
        return Err(ProtocolError::UnsupportedVersion);
    }
    Ok(EvidenceQuery {
        request_id: query.request_id,
        operation_id: query.params.operation_id,
    })
}

/// Encodes one evidence query.
pub fn encode_evidence_query(query: &EvidenceQuery) -> Result<Vec<u8>, ProtocolError> {
    let wire = WireEvidenceQuery {
        schema_version: 1,
        request_id: query.request_id.clone(),
        method: EvidenceMethod::EvidenceExport,
        params: EvidenceParams {
            operation_id: query.operation_id.clone(),
        },
    };
    let bytes = serde_json::to_vec(&wire).map_err(|_| ProtocolError::InvalidMessage)?;
    decode_evidence_query(&bytes)?;
    Ok(bytes)
}

/// Decodes a correlated evidence response.
pub fn decode_evidence_response(
    bytes: &[u8],
    query: &EvidenceQuery,
) -> Result<Result<EvidenceValue, ApiError>, ProtocolError> {
    validate_json(bytes, MAX_RESPONSE_BYTES, ProtocolError::ResponseTooLarge)?;
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| ProtocolError::InvalidMessage)?;
    let object = value.as_object().ok_or(ProtocolError::InvalidMessage)?;
    for field in ["schema_version", "request_id", "status", "data", "error"] {
        if !object.contains_key(field) {
            return Err(ProtocolError::InvalidMessage);
        }
    }
    let version = object["schema_version"]
        .as_u64()
        .and_then(|version| u16::try_from(version).ok())
        .ok_or(ProtocolError::InvalidMessage)?;
    if version != 1 {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let request_id: Id = serde_json::from_value(object["request_id"].clone())
        .map_err(|_| ProtocolError::InvalidMessage)?;
    if request_id != query.request_id {
        return Err(ProtocolError::InvalidMessage);
    }
    match object["status"].as_str() {
        Some("ok") if object["error"].is_null() => {
            let data = object["data"]
                .as_object()
                .ok_or(ProtocolError::InvalidMessage)?;
            if data.get("kind").and_then(|kind| kind.as_str()) != Some("evidence_export") {
                return Err(ProtocolError::InvalidMessage);
            }
            let parsed: EvidenceValue = serde_json::from_value(
                data.get("value")
                    .cloned()
                    .ok_or(ProtocolError::InvalidMessage)?,
            )
            .map_err(|_| ProtocolError::InvalidMessage)?;
            if parsed.operation_id != query.operation_id {
                return Err(ProtocolError::InvalidMessage);
            }
            let digest = parsed.receipt.body_sha256.as_bytes();
            if digest.len() != 64
                || !digest
                    .iter()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err(ProtocolError::InvalidMessage);
            }
            if !parsed.receipt.body.is_object() {
                return Err(ProtocolError::InvalidMessage);
            }
            Ok(Ok(parsed))
        }
        Some("error") if object["data"].is_null() => {
            let error_object = object["error"]
                .as_object()
                .ok_or(ProtocolError::InvalidMessage)?;
            if ["code", "message", "retryable", "operation_id", "details"]
                .iter()
                .any(|field| !error_object.contains_key(*field))
            {
                return Err(ProtocolError::InvalidMessage);
            }
            let error: ApiError = serde_json::from_value(object["error"].clone())
                .map_err(|_| ProtocolError::InvalidMessage)?;
            if !error.is_bounded_read_error() {
                return Err(ProtocolError::InvalidMessage);
            }
            Ok(Err(error))
        }
        _ => Err(ProtocolError::InvalidMessage),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSubmission<'a> {
    schema_version: u16,
    operation_id: Id,
    idempotency_key: Id,
    #[serde(borrow)]
    plan: &'a RawValue,
    #[serde(borrow)]
    grant: &'a RawValue,
    signature: String,
}

#[derive(Serialize)]
struct OutgoingSubmission<'a> {
    schema_version: u16,
    operation_id: &'a Id,
    idempotency_key: &'a Id,
    plan: &'a RawValue,
    grant: &'a RawValue,
    signature: &'a str,
}

/// One fixture submission, borrowing the exact submitted plan/grant bytes.
pub struct Submission<'a> {
    /// Requested operation identity.
    pub operation_id: Id,
    /// Requested retry key.
    pub idempotency_key: Id,
    /// Exact plan object bytes as sent.
    pub plan: &'a [u8],
    /// Exact grant object bytes as sent.
    pub grant: &'a [u8],
    /// Armored detached SSHSIG text.
    pub signature: String,
}

/// Decodes a bounded, closed, duplicate-free submission envelope.
pub fn decode_submission(bytes: &[u8]) -> Result<Submission<'_>, ProtocolError> {
    validate_json(bytes, MAX_REQUEST_BYTES, ProtocolError::RequestTooLarge)?;
    let wire: WireSubmission<'_> =
        serde_json::from_slice(bytes).map_err(|_| ProtocolError::InvalidMessage)?;
    if wire.schema_version != 1 {
        return Err(ProtocolError::UnsupportedVersion);
    }
    if wire.signature.len() > MAX_SIGNATURE_TEXT || !wire.signature.is_ascii() {
        return Err(ProtocolError::InvalidMessage);
    }
    if !wire.plan.get().starts_with('{') || !wire.grant.get().starts_with('{') {
        return Err(ProtocolError::InvalidMessage);
    }
    Ok(Submission {
        operation_id: wire.operation_id,
        idempotency_key: wire.idempotency_key,
        plan: wire.plan.get().as_bytes(),
        grant: wire.grant.get().as_bytes(),
        signature: wire.signature,
    })
}

/// Encodes a submission; plan/grant must already be JSON objects.
pub fn encode_submission(
    operation_id: &Id,
    idempotency_key: &Id,
    plan: &[u8],
    grant: &[u8],
    signature: &str,
) -> Result<Vec<u8>, ProtocolError> {
    if plan.trim_ascii() != plan || grant.trim_ascii() != grant {
        return Err(ProtocolError::InvalidMessage);
    }
    if plan
        .len()
        .saturating_add(grant.len())
        .saturating_add(signature.len())
        > MAX_REQUEST_BYTES
    {
        return Err(ProtocolError::RequestTooLarge);
    }
    let raw = |bytes: &[u8]| -> Result<Box<RawValue>, ProtocolError> {
        let text = std::str::from_utf8(bytes).map_err(|_| ProtocolError::InvalidMessage)?;
        RawValue::from_string(text.to_owned()).map_err(|_| ProtocolError::InvalidMessage)
    };
    let raw_plan = raw(plan)?;
    let raw_grant = raw(grant)?;
    let bytes = serde_json::to_vec(&OutgoingSubmission {
        schema_version: 1,
        operation_id,
        idempotency_key,
        plan: &raw_plan,
        grant: &raw_grant,
        signature,
    })
    .map_err(|_| ProtocolError::InvalidMessage)?;
    decode_submission(&bytes)?;
    Ok(bytes)
}

/// Final recorded state reported to the requester.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeState {
    /// Intent recorded; effect status unknown until reconciled.
    Intent,
    /// Executor observed the complete target.
    Succeeded,
    /// Executor observed the complete predecessor.
    Untouched,
    /// Reality not established; resource blocked.
    NeedsAttention,
    /// A provision stopped with its created resources kept. The outcome is
    /// known. This is not an uncertain OLS activation.
    Quarantined,
    /// The single compensation attempt is recorded; outcome not yet observed.
    Compensating,
    /// Compensation restored the predecessor; the step itself failed.
    FailedCompensated,
    /// W381 (D-032): the operation stopped and recorded a failure. No claim
    /// that the predecessor is complete: a failed capture can leave store
    /// objects, and a settled one keeps an unclaimed snapshot (W366).
    Failed,
}

/// Executor reply: either a recorded outcome or a stable error code.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmissionReply {
    /// Always 1.
    pub schema_version: u16,
    /// Operation the reply concerns, when the envelope was decodable.
    pub operation_id: Option<Id>,
    /// Recorded state, when the journal holds this operation.
    pub state: Option<OutcomeState>,
    /// True when an exact earlier submission was found (status only).
    pub replay: bool,
    /// Stable machine code for a refusal or incomplete effect.
    pub error: Option<String>,
    /// W381 (D-032): with `failed` only, the tagged snapshot that the W366
    /// settlement kept as unclaimed evidence (64 lowercase hex). Additive:
    /// absent when there is none. It claims no restore or retention.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unclaimed_snapshot_id: Option<String>,
}

impl SubmissionReply {
    /// CLI exit status for the executor's recorded or refused outcome.
    pub fn exit_code(&self) -> u8 {
        match (self.state, &self.error) {
            (Some(OutcomeState::Succeeded), None) => 0,
            // W360: an OLS activation refused after intent by its drift or
            // precondition recheck, with no effect attempted: the refusal
            // exit, as before intent. Other untouched outcomes stay 5.
            // W381 (D-032): `failed` replaced `untouched` for a failed
            // capture and keeps its exit classes.
            (Some(OutcomeState::Untouched | OutcomeState::Failed), Some(error))
                if matches!(error.as_str(), "OLS_DRIFT" | "PRECONDITION_CHANGED") =>
            {
                4
            }
            (
                Some(
                    OutcomeState::Untouched
                    | OutcomeState::Failed
                    | OutcomeState::FailedCompensated
                    | OutcomeState::Quarantined,
                ),
                _,
            )
            | (Some(OutcomeState::Succeeded), Some(_)) => 5,
            (Some(_), _) => 6,
            (None, error) => match error.as_deref() {
                Some("INVALID_REQUEST") => 2,
                Some(
                    "EXECUTOR_ACCESS_DENIED"
                    | "PEER_DENIED"
                    | "FIXTURE_BINDING_DENIED"
                    | "GRANT_TIME_DENIED"
                    | "INVALID_SIGNATURE"
                    | "REPLAY_DENIED"
                    | "STANDING_WINDOW_CLOSED"
                    | "STANDING_RUN_MISMATCH",
                ) => 3,
                Some(error) if is_conflict(error) => 4,
                _ => 7,
            },
        }
    }
}

/// Precondition, ownership, drift or idempotency conflicts (SPEC exit 4).
fn is_conflict(error: &str) -> bool {
    matches!(
        error,
        "PRECONDITION_CHANGED"
            | "UNRESOLVED_OPERATION"
            | "JOURNAL_STATE_EXISTS"
            | "NOT_ADMITTED_FOR_EFFECT"
            | "COMPENSATION_DENIED"
            | "PROVISION_COLLISION"
            | "OLS_DRIFT"
            | "OLS_GENERATION_CURRENT"
    )
}

/// Decodes and correlates a bounded executor reply to the requested operation.
/// A malformed or missing reply never establishes the effect's outcome.
pub fn decode_submission_reply(
    bytes: &[u8],
    expected_operation: &Id,
) -> Result<SubmissionReply, ProtocolError> {
    validate_json(bytes, MAX_RESPONSE_BYTES, ProtocolError::ResponseTooLarge)?;
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| ProtocolError::InvalidMessage)?;
    let object = value.as_object().ok_or(ProtocolError::InvalidMessage)?;
    if ["schema_version", "operation_id", "state", "replay", "error"]
        .iter()
        .any(|field| !object.contains_key(*field))
    {
        return Err(ProtocolError::InvalidMessage);
    }
    let reply: SubmissionReply =
        serde_json::from_value(value).map_err(|_| ProtocolError::InvalidMessage)?;
    if reply.schema_version != 1 {
        return Err(ProtocolError::UnsupportedVersion);
    }
    if reply
        .operation_id
        .as_ref()
        .is_some_and(|id| id != expected_operation)
        || (reply.state.is_some() && reply.operation_id.is_none())
        || (reply.state.is_none() && (reply.error.is_none() || reply.replay))
        || reply.error.as_ref().is_some_and(|error| {
            error.is_empty()
                || error.len() > 64
                || !error
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        })
        || reply
            .unclaimed_snapshot_id
            .as_ref()
            .is_some_and(|snapshot| {
                reply.state != Some(OutcomeState::Failed)
                    || snapshot.len() != 64
                    || !snapshot
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
    {
        return Err(ProtocolError::InvalidMessage);
    }
    Ok(reply)
}
