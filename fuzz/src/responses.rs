//! Response oracles with fixed external correlation facts and interface-specific extensions.

use rustiron_contracts::apply::{ApplyOutcome, decode_apply_response, encode_apply_response};
use rustiron_contracts::execution::{
    EvidenceQuery, StatusQuery, SubmissionReply, decode_evidence_response, decode_status_response,
    decode_submission_reply,
};
use rustiron_contracts::{
    Id, MAX_RESPONSE_BYTES, ProtocolError, ReadData, Response, decode_response, encode_response,
};
use serde_json::{Value, json};

fn id(value: &str) -> Id {
    Id::try_from(value.to_owned()).unwrap()
}

fn bounded_decode<T>(input: &[u8], result: Result<T, ProtocolError>) -> Option<T> {
    if input.len() > MAX_RESPONSE_BYTES {
        assert_eq!(result.err(), Some(ProtocolError::ResponseTooLarge));
        None
    } else {
        result.ok()
    }
}

fn encoded_read(response: &Response) -> Option<Vec<u8>> {
    match encode_response(response) {
        Ok(bytes) => Some(bytes),
        Err(error) => {
            // Normalizing arbitrary receipt numbers can expand a valid input.
            assert_eq!(error, ProtocolError::ResponseTooLarge);
            None
        }
    }
}

fn required(value: &Value, fields: &[&str]) {
    let object = value.as_object().expect("response record must be named");
    assert!(
        fields.iter().all(|field| object.contains_key(*field)),
        "required response field missing"
    );
}

// Compare known output fields where the input supplies them; defaults and ignored
// additive fields need not appear identically in the wire reconstruction.
fn preserved_known_values(input: &Value, output: &Value) {
    match (input, output) {
        (Value::Object(input), Value::Object(output)) => {
            for (key, value) in output {
                if let Some(original) = input.get(key) {
                    preserved_known_values(original, value);
                }
            }
        }
        (Value::Array(input), Value::Array(output)) => {
            assert_eq!(input.len(), output.len());
            for (a, b) in input.iter().zip(output) {
                preserved_known_values(a, b);
            }
        }
        _ => assert_eq!(input, output, "known response value changed"),
    }
}

fn refused(value: &Value, accepts: &impl Fn(&[u8]) -> bool, reason: &str) {
    let bytes = serde_json::to_vec(value).unwrap();
    if bytes.len() <= MAX_RESPONSE_BYTES {
        assert!(!accepts(&bytes), "{reason}");
    }
}

fn common_controls(input: &[u8], value: &Value, accepts: impl Fn(&[u8]) -> bool) {
    let mut changed = value.clone();
    changed["schema_version"] = json!(2);
    refused(&changed, &accepts, "unsupported response version accepted");
    for field in ["schema_version", "request_id", "status", "data", "error"] {
        let mut changed = value.clone();
        changed.as_object_mut().unwrap().remove(field);
        refused(
            &changed,
            &accepts,
            "missing response envelope field accepted",
        );
    }
    for prefix in [
        br#"{"schema_version":1,"#.as_slice(),
        br#"{"schema_vers\u0069on":1,"#,
    ] {
        let mut duplicate = prefix.to_vec();
        duplicate.extend_from_slice(&input.trim_ascii_start()[1..]);
        if duplicate.len() <= MAX_RESPONSE_BYTES {
            assert!(!accepts(&duplicate), "duplicate response field accepted");
        }
    }
}

fn envelope(value: &Value, success: bool) {
    required(
        value,
        &["schema_version", "request_id", "status", "data", "error"],
    );
    assert_eq!(value["schema_version"], json!(1));
    if success {
        assert_eq!(value["status"], json!("ok"));
        assert!(value["data"].is_object() && value["error"].is_null());
        required(&value["data"], &["kind", "value"]);
    } else {
        assert_eq!(value["status"], json!("error"));
        assert!(value["data"].is_null());
        required(
            &value["error"],
            &["code", "message", "retryable", "operation_id", "details"],
        );
        assert!(value["error"]["operation_id"].is_null());
        assert!(value["error"]["details"].as_array().unwrap().len() <= 8);
    }
}

fn reply_relations(value: &Value, reply: &SubmissionReply) {
    required(
        value,
        &["schema_version", "operation_id", "state", "replay", "error"],
    );
    preserved_known_values(value, &serde_json::to_value(reply).unwrap());
    assert_eq!(reply.schema_version, 1);
    assert!(
        reply
            .operation_id
            .as_ref()
            .is_none_or(|id| id.as_str() == "operation_1"),
        "unrelated reply operation accepted"
    );
    assert!(
        reply.state.is_none() || reply.operation_id.is_some(),
        "unidentified recorded reply accepted"
    );
    assert!(
        reply.state.is_some() || (reply.error.is_some() && !reply.replay),
        "empty/replayed refusal accepted"
    );
    if let Some(error) = &reply.error {
        assert!(!error.is_empty() && error.len() <= 64);
        assert!(
            error
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        );
    }
    let exit = match (value["state"].as_str(), value["error"].as_str()) {
        (Some("succeeded"), None) => 0,
        (Some("untouched" | "failed_compensated" | "quarantined" | "succeeded"), _) => 5,
        (Some("intent" | "needs_attention" | "compensating"), _) => 6,
        (None, Some("INVALID_REQUEST")) => 2,
        (
            None,
            Some(
                "EXECUTOR_ACCESS_DENIED"
                | "PEER_DENIED"
                | "FIXTURE_BINDING_DENIED"
                | "GRANT_TIME_DENIED"
                | "INVALID_SIGNATURE"
                | "REPLAY_DENIED"
                | "STANDING_WINDOW_CLOSED"
                | "STANDING_RUN_MISMATCH",
            ),
        ) => 3,
        (
            None,
            Some(
                "PRECONDITION_CHANGED"
                | "UNRESOLVED_OPERATION"
                | "JOURNAL_STATE_EXISTS"
                | "NOT_ADMITTED_FOR_EFFECT"
                | "COMPENSATION_DENIED"
                | "PROVISION_COLLISION"
                | "OLS_DRIFT"
                | "OLS_GENERATION_CURRENT",
            ),
        ) => 4,
        (None, Some(_)) => 7,
        _ => panic!("invalid reply state accepted"),
    };
    assert_eq!(reply.exit_code(), exit, "reply exit code misstates outcome");
}

/// Fixed expected operation; the input cannot choose its correlation context.
pub fn submission_reply(input: &[u8]) -> bool {
    let Some(reply) = bounded_decode(input, decode_submission_reply(input, &id("operation_1")))
    else {
        return false;
    };
    let value: Value = serde_json::from_slice(input).unwrap();
    reply_relations(&value, &reply);
    assert_eq!(
        decode_submission_reply(&serde_json::to_vec(&reply).unwrap(), &id("operation_1")).unwrap(),
        reply
    );
    for field in ["schema_version", "operation_id", "state", "replay", "error"] {
        let mut changed = value.clone();
        changed.as_object_mut().unwrap().remove(field);
        refused(
            &changed,
            &|b| decode_submission_reply(b, &id("operation_1")).is_ok(),
            "missing executor reply field accepted",
        );
    }
    let mut changed = value.clone();
    changed["operation_id"] = json!("other_operation");
    refused(
        &changed,
        &|b| decode_submission_reply(b, &id("operation_1")).is_ok(),
        "changed reply operation accepted",
    );
    changed = value.clone();
    changed["future"] = json!(true);
    let bytes = serde_json::to_vec(&changed).unwrap();
    if bytes.len() <= MAX_RESPONSE_BYTES {
        assert_eq!(
            decode_submission_reply(&bytes, &id("operation_1"))
                .expect("additive executor reply extension refused"),
            reply
        );
    }
    changed = value;
    changed["state"] = Value::Null;
    changed["error"] = Value::Null;
    refused(
        &changed,
        &|b| decode_submission_reply(b, &id("operation_1")).is_ok(),
        "empty executor reply accepted",
    );
    true
}

/// Fixed request and operation facts, with additive outer/outcome compatibility.
pub fn apply_response(input: &[u8]) -> bool {
    let Some(response) = bounded_decode(
        input,
        decode_apply_response(input, &id("request_1"), &id("operation_1")),
    ) else {
        return false;
    };
    let value: Value = serde_json::from_slice(input).unwrap();
    envelope(&value, true);
    assert_eq!(value["request_id"], json!("request_1"));
    assert_eq!(
        value["data"]["kind"],
        json!("plan_apply"),
        "wrong apply data kind accepted"
    );
    assert_eq!(value["data"]["value"]["operation_id"], json!("operation_1"));
    assert_eq!(
        response.request_id.as_str(),
        "request_1",
        "unrelated apply request accepted"
    );
    assert_eq!(
        response.operation_id.as_str(),
        "operation_1",
        "unrelated apply operation accepted"
    );
    let outcome = &value["data"]["value"]["outcome"];
    match &response.outcome {
        ApplyOutcome::NotSent { .. } => assert!(
            outcome.get("reply").is_none(),
            "not-sent reply ambiguity accepted"
        ),
        ApplyOutcome::OutcomeUnknown => assert!(
            outcome.get("reply").is_none() && outcome.get("reason").is_none(),
            "unknown outcome ambiguity accepted"
        ),
        ApplyOutcome::ExecutorReply { reply } => {
            assert!(outcome.get("reason").is_none());
            reply_relations(&outcome["reply"], reply);
        }
    }
    preserved_known_values(outcome, &serde_json::to_value(&response.outcome).unwrap());
    assert_eq!(
        decode_apply_response(
            &encode_apply_response(&response).unwrap(),
            &id("request_1"),
            &id("operation_1")
        )
        .unwrap(),
        response
    );
    assert!(
        decode_apply_response(input, &id("other_request"), &id("operation_1")).is_err(),
        "changed apply correlation accepted"
    );
    assert!(
        decode_apply_response(input, &id("request_1"), &id("other_operation")).is_err(),
        "changed apply operation context accepted"
    );
    let mut extended = value.clone();
    extended["future"] = json!(true);
    extended["data"]["value"]["outcome"]["future"] = json!(true);
    if matches!(response.outcome, ApplyOutcome::ExecutorReply { .. }) {
        extended["data"]["value"]["outcome"]["reply"]["future"] = json!(true);
    }
    let bytes = serde_json::to_vec(&extended).unwrap();
    if bytes.len() <= MAX_RESPONSE_BYTES {
        assert_eq!(
            decode_apply_response(&bytes, &id("request_1"), &id("operation_1")).unwrap(),
            response
        );
    }
    let mut ambiguous = value.clone();
    let field = if matches!(response.outcome, ApplyOutcome::ExecutorReply { .. }) {
        "reason"
    } else {
        "reply"
    };
    ambiguous["data"]["value"]["outcome"][field] = Value::Null;
    refused(
        &ambiguous,
        &|b| decode_apply_response(b, &id("request_1"), &id("operation_1")).is_ok(),
        "ambiguous apply outcome accepted",
    );
    common_controls(input, &value, |b| {
        decode_apply_response(b, &id("request_1"), &id("operation_1")).is_ok()
    });
    true
}

/// Generic read parsing preserves data but delegates correlation to its caller.
pub fn read_response(input: &[u8]) -> bool {
    let Some(response) = bounded_decode(input, decode_response(input)) else {
        return false;
    };
    let value: Value = serde_json::from_slice(input).unwrap();
    envelope(&value, response.result.is_ok());
    assert_eq!(
        value["request_id"],
        serde_json::to_value(&response.request_id).unwrap()
    );
    if let Some(encoded) = encoded_read(&response) {
        let output: Value = serde_json::from_slice(&encoded).unwrap();
        preserved_known_values(&value, &output);
        assert_eq!(decode_response(&encoded).unwrap(), response);
    }
    let mut extended = value.clone();
    extended["future"] = json!({"ignored":true});
    let bytes = serde_json::to_vec(&extended).unwrap();
    if bytes.len() <= MAX_RESPONSE_BYTES {
        assert_eq!(decode_response(&bytes).unwrap(), response);
    }
    let mut invalid = value.clone();
    if response.result.is_ok() {
        invalid["error"] = json!({});
    } else {
        invalid["data"] = json!({});
    }
    refused(
        &invalid,
        &|b| decode_response(b).is_ok(),
        "contradictory read slots accepted",
    );
    if response.result.is_err() {
        invalid = value.clone();
        invalid["error"]
            .as_object_mut()
            .unwrap()
            .remove("operation_id");
        refused(
            &invalid,
            &|b| decode_response(b).is_ok(),
            "missing read-error operation_id accepted",
        );
        invalid = value.clone();
        invalid["error"]["operation_id"] = json!("operation_1");
        refused(
            &invalid,
            &|b| decode_response(b).is_ok(),
            "read error asserted operation authority",
        );
    }
    if let Ok(ReadData::SiteList(page)) = &response.result {
        assert!(page.items.len() <= 100);
        required(&value["data"]["value"], &["items", "next_cursor"]);
        let mut missing = value.clone();
        missing["data"]["value"]
            .as_object_mut()
            .unwrap()
            .remove("next_cursor");
        refused(
            &missing,
            &|b| decode_response(b).is_ok(),
            "missing page cursor accepted",
        );
    }
    common_controls(input, &value, |b| decode_response(b).is_ok());
    true
}

/// Independently fixed status query, including distinct bounded refusals.
pub fn status_response(input: &[u8]) -> bool {
    let query = StatusQuery {
        request_id: id("query_1"),
        operation_id: id("operation_1"),
    };
    let Some(response) = bounded_decode(input, decode_status_response(input, &query)) else {
        return false;
    };
    let value: Value = serde_json::from_slice(input).unwrap();
    envelope(&value, response.result.is_ok());
    assert_eq!(
        response.request_id, query.request_id,
        "unrelated status request accepted"
    );
    if let Ok(data) = &response.result {
        assert_eq!(
            data.operation_id, query.operation_id,
            "unrelated status operation accepted"
        );
    }
    let projected = Response {
        request_id: Some(query.request_id.clone()),
        result: response.result.clone().map(ReadData::OperationStatus),
    };
    if let Some(encoded) = encoded_read(&projected) {
        preserved_known_values(&value, &serde_json::from_slice(&encoded).unwrap());
        assert_eq!(
            decode_status_response(&encoded, &query).unwrap().result,
            response.result
        );
    }
    let mut extended = value.clone();
    extended["future"] = json!(true);
    let bytes = serde_json::to_vec(&extended).unwrap();
    if bytes.len() <= MAX_RESPONSE_BYTES {
        assert_eq!(
            decode_status_response(&bytes, &query).unwrap().result,
            response.result
        );
    }
    let other = StatusQuery {
        request_id: id("other_request"),
        operation_id: query.operation_id.clone(),
    };
    assert!(
        decode_status_response(input, &other).is_err(),
        "changed status correlation accepted"
    );
    if response.result.is_ok() {
        let other = StatusQuery {
            request_id: query.request_id.clone(),
            operation_id: id("other_operation"),
        };
        assert!(
            decode_status_response(input, &other).is_err(),
            "changed status operation context accepted"
        );
    }
    common_controls(input, &value, |b| decode_status_response(b, &query).is_ok());
    true
}

/// W392: an accepted receipt states its attestation consistently with the
/// signature, checked against the raw members; a signature never survives
/// without the signed label, and an unsigned label never carries one.
fn receipt_signature_shape(raw: &Value, receipt: &rustiron_contracts::execution::EvidenceReceipt) {
    use rustiron_contracts::execution::{
        RECEIPT_ATTESTATION_SIGNED, RECEIPT_ATTESTATION_UNSIGNED, RECEIPT_SIGNATURE_NAMESPACE,
    };
    let label = raw.get("attestation").and_then(Value::as_str);
    assert_eq!(receipt.attestation.as_deref(), label, "attestation changed");
    match &receipt.signature {
        Some(signature) => {
            assert_eq!(
                label,
                Some(RECEIPT_ATTESTATION_SIGNED),
                "signature without the signed label"
            );
            assert_eq!(signature.format, "sshsig");
            assert_eq!(
                signature.namespace, RECEIPT_SIGNATURE_NAMESPACE,
                "other namespace accepted"
            );
            assert_eq!(raw["signature"]["armored"], json!(signature.armored));
            assert!(
                signature.armored.len() <= 4096,
                "oversized signature accepted"
            );
            assert!(
                signature
                    .armored
                    .starts_with("-----BEGIN SSH SIGNATURE-----\n")
            );
            assert!(signature.armored.ends_with("-----END SSH SIGNATURE-----\n"));
            assert!(signature.key_fingerprint.starts_with("SHA256:"));
            assert_eq!(signature.key_fingerprint.len(), 50);
        }
        None => assert!(
            label.is_none() || label == Some(RECEIPT_ATTESTATION_UNSIGNED),
            "signed label without a signature accepted"
        ),
    }
}

/// Correlated self-attested receipt shape, without authenticating its body hash.
pub fn evidence_response(input: &[u8]) -> bool {
    let query = EvidenceQuery {
        request_id: id("query_1"),
        operation_id: id("operation_1"),
    };
    let Some(result) = bounded_decode(input, decode_evidence_response(input, &query)) else {
        return false;
    };
    let value: Value = serde_json::from_slice(input).unwrap();
    envelope(&value, result.is_ok());
    assert_eq!(
        value["request_id"],
        json!("query_1"),
        "unrelated evidence request accepted"
    );
    if let Ok(data) = &result {
        assert_eq!(
            data.operation_id, query.operation_id,
            "unrelated evidence operation accepted"
        );
        assert!(data.receipt.body.is_object());
        let digest = data.receipt.body_sha256.as_bytes();
        assert!(
            digest.len() == 64
                && digest
                    .iter()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)),
            "invalid receipt digest shape accepted"
        );
        receipt_signature_shape(&value["data"]["value"]["receipt"], &data.receipt);
    }
    let projected = Response {
        request_id: Some(query.request_id.clone()),
        result: result.clone().map(ReadData::EvidenceExport),
    };
    if let Some(encoded) = encoded_read(&projected) {
        preserved_known_values(&value, &serde_json::from_slice(&encoded).unwrap());
        assert_eq!(decode_evidence_response(&encoded, &query).unwrap(), result);
    }
    let mut extended = value.clone();
    extended["future"] = json!(true);
    let bytes = serde_json::to_vec(&extended).unwrap();
    if bytes.len() <= MAX_RESPONSE_BYTES {
        assert_eq!(decode_evidence_response(&bytes, &query).unwrap(), result);
    }
    let other = EvidenceQuery {
        request_id: id("other_request"),
        operation_id: query.operation_id.clone(),
    };
    assert!(
        decode_evidence_response(input, &other).is_err(),
        "changed evidence correlation accepted"
    );
    if result.is_ok() {
        let other = EvidenceQuery {
            request_id: query.request_id.clone(),
            operation_id: id("other_operation"),
        };
        assert!(
            decode_evidence_response(input, &other).is_err(),
            "changed evidence operation context accepted"
        );
        for digest in ["a".repeat(63), "A".repeat(64)] {
            let mut invalid = value.clone();
            invalid["data"]["value"]["receipt"]["body_sha256"] = json!(digest);
            refused(
                &invalid,
                &|b| decode_evidence_response(b, &query).is_ok(),
                "invalid receipt digest text accepted",
            );
        }
        // W392: a signed receipt without its signature, or with another
        // namespace, is refused.
        let receipt = &value["data"]["value"]["receipt"];
        if receipt.get("signature").is_some() {
            let mut stripped = value.clone();
            stripped["data"]["value"]["receipt"]
                .as_object_mut()
                .unwrap()
                .remove("signature");
            refused(
                &stripped,
                &|b| decode_evidence_response(b, &query).is_ok(),
                "signed label without a signature accepted",
            );
            let mut other = value.clone();
            other["data"]["value"]["receipt"]["signature"]["namespace"] = json!("rustiron-plan-v1");
            refused(
                &other,
                &|b| decode_evidence_response(b, &query).is_ok(),
                "plan namespace accepted for a receipt",
            );
        }
    }
    common_controls(input, &value, |b| {
        decode_evidence_response(b, &query).is_ok()
    });
    true
}
