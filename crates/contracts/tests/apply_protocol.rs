//! Closed operator submission contract; no executor authority is granted here.

use rustiron_contracts::{
    Id, MAX_REQUEST_BYTES, ProtocolError,
    apply::{
        ApplyOutcome, ApplyRequest, ApplyResponse, NotSentReason, decode_apply_request,
        decode_apply_response, encode_apply_request, encode_apply_response,
    },
    execution::{OutcomeState, SubmissionReply},
};

fn id(text: &str) -> Id {
    Id::try_from(text.to_owned()).unwrap()
}

fn request() -> ApplyRequest {
    ApplyRequest {
        request_id: id("request_1"),
        operation_id: id("operation_1"),
        idempotency_key: id("retry_1"),
        plan: br#"{"nested": {"x":1}}"#.to_vec(),
        grant: br#"{"issuer":"fixture"}"#.to_vec(),
        signature: "synthetic_signature".into(),
    }
}

#[test]
fn request_roundtrip_preserves_the_signed_objects_and_signature() {
    let input = request();
    let decoded = decode_apply_request(&encode_apply_request(&input).unwrap()).unwrap();
    assert_eq!(decoded.request_id, input.request_id);
    assert_eq!(decoded.operation_id, input.operation_id);
    assert_eq!(decoded.idempotency_key, input.idempotency_key);
    assert_eq!(decoded.plan, input.plan);
    assert_eq!(decoded.grant, input.grant);
    assert_eq!(decoded.signature, input.signature);
}

#[test]
fn executor_submission_preserves_object_bytes() {
    let input = request();
    let executor_frame = rustiron_contracts::execution::encode_submission(
        &input.operation_id,
        &input.idempotency_key,
        &input.plan,
        &input.grant,
        &input.signature,
    )
    .unwrap();
    let forwarded = rustiron_contracts::execution::decode_submission(&executor_frame).unwrap();
    assert_eq!(forwarded.plan, input.plan);
    assert_eq!(forwarded.grant, input.grant);
    assert_eq!(
        rustiron_contracts::execution::encode_submission(
            &input.operation_id,
            &input.idempotency_key,
            b"[]",
            b"{}",
            &input.signature
        )
        .err(),
        Some(ProtocolError::InvalidMessage)
    );
    assert_eq!(
        rustiron_contracts::execution::encode_submission(
            &input.operation_id,
            &input.idempotency_key,
            b" {}",
            b"{}",
            &input.signature
        )
        .err(),
        Some(ProtocolError::InvalidMessage)
    );
}

#[test]
fn request_refuses_unknown_fields_duplicates_wrong_shapes_and_oversize() {
    for bytes in [
        br#"{"schema_version":1,"request_id":"r","method":"plan_apply","params":{"operation_id":"o","idempotency_key":"k","plan":{},"grant":{},"signature":"s","path":"/etc"}}"#.as_slice(),
        br#"{"schema_version":1,"request_id":"r","method":"plan_apply","params":{"operation_id":"o","idempotency_key":"k","plan":{"a":1,"a":2},"grant":{},"signature":"s"}}"#.as_slice(),
        br#"{"schema_version":1,"request_id":"r","method":"plan_apply","params":{"operation_id":"o","idempotency_key":"k","plan":[],"grant":{},"signature":"s"}}"#.as_slice(),
        br#"{"schema_version":1,"request_id":"r","method":"plan_apply","params":["o","k",{}, {}, "s"]}"#.as_slice(),
    ] {
        assert_eq!(decode_apply_request(bytes).err(), Some(ProtocolError::InvalidMessage));
    }
    assert_eq!(
        decode_apply_request(&vec![b' '; MAX_REQUEST_BYTES + 1]).err(),
        Some(ProtocolError::RequestTooLarge)
    );
}

#[test]
fn outcomes_are_correlated_and_do_not_invent_admission() {
    let request = request();
    for outcome in [
        ApplyOutcome::NotSent {
            reason: NotSentReason::Busy,
        },
        ApplyOutcome::OutcomeUnknown,
        ApplyOutcome::ExecutorReply {
            reply: SubmissionReply {
                schema_version: 1,
                operation_id: Some(id("operation_1")),
                state: Some(OutcomeState::Intent),
                replay: false,
                error: None,
                unclaimed_snapshot_id: None,
            },
        },
    ] {
        let response = ApplyResponse {
            request_id: request.request_id.clone(),
            operation_id: request.operation_id.clone(),
            outcome,
        };
        let bytes = encode_apply_response(&response).unwrap();
        assert_eq!(
            decode_apply_response(&bytes, &request.request_id, &request.operation_id).unwrap(),
            response
        );
        assert_eq!(
            decode_apply_response(&bytes, &id("other_request"), &request.operation_id).unwrap_err(),
            ProtocolError::InvalidMessage
        );
        assert_eq!(
            decode_apply_response(&bytes, &request.request_id, &id("other_operation")).unwrap_err(),
            ProtocolError::InvalidMessage
        );
    }
}

#[test]
fn executor_reply_for_another_operation_is_not_accepted() {
    let response = ApplyResponse {
        request_id: id("request_1"),
        operation_id: id("operation_1"),
        outcome: ApplyOutcome::ExecutorReply {
            reply: SubmissionReply {
                schema_version: 1,
                operation_id: Some(id("other")),
                state: Some(OutcomeState::Succeeded),
                replay: false,
                error: None,
                unclaimed_snapshot_id: None,
            },
        },
    };
    assert_eq!(
        encode_apply_response(&response).unwrap_err(),
        ProtocolError::InvalidMessage
    );
}

#[test]
fn response_rejects_ambiguous_or_positional_outcomes() {
    for bytes in [
        br#"{"schema_version":1,"request_id":"request_1","status":"ok","data":{"kind":"plan_apply","value":{"operation_id":"operation_1","outcome":["outcome_unknown"]}},"error":null}"#.as_slice(),
        br#"{"schema_version":1,"request_id":"request_1","status":"ok","data":{"kind":"plan_apply","value":{"operation_id":"operation_1","outcome":{"kind":"outcome_unknown","reply":{"state":"succeeded"}}}},"error":null}"#.as_slice(),
        br#"{"schema_version":1,"request_id":"request_1","status":"ok","data":{"kind":"plan_apply","value":{"operation_id":"operation_1","outcome":{"kind":"outcome_unknown","kind":"not_sent","reason":"busy"}}},"error":null}"#.as_slice(),
        br#"{"schema_version":1,"request_id":"request_1","status":"ok","data":{"kind":"plan_apply","value":{"operation_id":"operation_1","outcome":{"kind":"outcome_unknown"}}},"error":{}}"#.as_slice(),
    ] {
        assert_eq!(decode_apply_response(bytes, &id("request_1"), &id("operation_1")).unwrap_err(), ProtocolError::InvalidMessage);
    }
}

#[test]
fn additive_response_fields_do_not_change_the_outcome() {
    let bytes = br#"{"schema_version":1,"request_id":"request_1","status":"ok","future":true,"data":{"kind":"plan_apply","value":{"operation_id":"operation_1","outcome":{"kind":"outcome_unknown","future":"ignored"}}},"error":null}"#;
    assert_eq!(
        decode_apply_response(bytes, &id("request_1"), &id("operation_1"))
            .unwrap()
            .outcome,
        ApplyOutcome::OutcomeUnknown
    );
}

#[test]
fn additive_nested_executor_reply_fields_preserve_the_apply_outcome() {
    let bytes = br#"{"schema_version":1,"request_id":"request_1","status":"ok","data":{"kind":"plan_apply","value":{"operation_id":"operation_1","outcome":{"kind":"executor_reply","reply":{"schema_version":1,"operation_id":"operation_1","state":"intent","replay":false,"error":null,"future":true}}}},"error":null}"#;
    let response = decode_apply_response(bytes, &id("request_1"), &id("operation_1")).unwrap();
    assert!(matches!(
        response.outcome,
        ApplyOutcome::ExecutorReply {
            reply: SubmissionReply {
                state: Some(OutcomeState::Intent),
                ..
            }
        }
    ));
}
