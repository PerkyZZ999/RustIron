//! Executor replies must be bounded and correlated to the requested operation.
use rustiron_contracts::{
    Id, MAX_RESPONSE_BYTES, ProtocolError, execution::decode_submission_reply,
};

fn id() -> Id {
    Id::try_from("op_1".to_owned()).unwrap()
}

#[test]
fn additive_reply_fields_preserve_the_recorded_outcome() {
    let bytes = br#"{"schema_version":1,"operation_id":"op_1","state":"intent","replay":false,"error":null,"future":{"ignored":true}}"#;
    let reply = decode_submission_reply(bytes, &id()).unwrap();
    assert_eq!(
        reply.state,
        Some(rustiron_contracts::execution::OutcomeState::Intent)
    );
    assert_eq!(reply.exit_code(), 6);
}

#[test]
fn accepts_a_recorded_matching_outcome_and_a_redacted_refusal() {
    let success = br#"{"schema_version":1,"operation_id":"op_1","state":"succeeded","replay":false,"error":null}"#;
    assert!(decode_submission_reply(success, &id()).is_ok());
    let refusal = br#"{"schema_version":1,"operation_id":null,"state":null,"replay":false,"error":"INVALID_REQUEST"}"#;
    assert!(decode_submission_reply(refusal, &id()).is_ok());
}

#[test]
fn refuses_an_unrelated_or_unidentified_recorded_outcome() {
    let wrong = br#"{"schema_version":1,"operation_id":"op_other","state":"succeeded","replay":false,"error":null}"#;
    let missing = br#"{"schema_version":1,"operation_id":null,"state":"succeeded","replay":false,"error":null}"#;
    assert_eq!(
        decode_submission_reply(wrong, &id()).unwrap_err(),
        ProtocolError::InvalidMessage
    );
    assert_eq!(
        decode_submission_reply(missing, &id()).unwrap_err(),
        ProtocolError::InvalidMessage
    );
}

#[test]
fn rejects_invalid_or_ambiguous_reply_envelopes() {
    let duplicate = br#"{"schema_version":1,"operation_id":"op_1","state":"succeeded","state":"intent","replay":false,"error":null}"#;
    let missing =
        br#"{"schema_version":1,"operation_id":"op_1","state":"succeeded","replay":false}"#;
    let no_outcome =
        br#"{"schema_version":1,"operation_id":"op_1","state":null,"replay":false,"error":null}"#;
    let replay_refusal = br#"{"schema_version":1,"operation_id":"op_1","state":null,"replay":true,"error":"INVALID_REQUEST"}"#;
    assert_eq!(
        decode_submission_reply(duplicate, &id()).unwrap_err(),
        ProtocolError::InvalidMessage
    );
    assert_eq!(
        decode_submission_reply(missing, &id()).unwrap_err(),
        ProtocolError::InvalidMessage
    );
    assert_eq!(
        decode_submission_reply(no_outcome, &id()).unwrap_err(),
        ProtocolError::InvalidMessage
    );
    assert_eq!(
        decode_submission_reply(replay_refusal, &id()).unwrap_err(),
        ProtocolError::InvalidMessage
    );
}

#[test]
fn rejects_unknown_version_and_unsafe_error_text() {
    let version = br#"{"schema_version":2,"operation_id":"op_1","state":"succeeded","replay":false,"error":null}"#;
    let error = br#"{"schema_version":1,"operation_id":"op_1","state":null,"replay":false,"error":"unsafe\ntext"}"#;
    assert_eq!(
        decode_submission_reply(version, &id()).unwrap_err(),
        ProtocolError::UnsupportedVersion
    );
    assert_eq!(
        decode_submission_reply(error, &id()).unwrap_err(),
        ProtocolError::InvalidMessage
    );
}

#[test]
fn rejects_oversized_reply_before_decoding() {
    assert_eq!(
        decode_submission_reply(&vec![b' '; MAX_RESPONSE_BYTES + 1], &id()).unwrap_err(),
        ProtocolError::ResponseTooLarge
    );
}

#[test]
fn recorded_states_have_truthful_exit_codes() {
    for (state, expected) in [
        ("succeeded", 0),
        ("untouched", 5),
        ("quarantined", 5),
        ("failed_compensated", 5),
        ("intent", 6),
        ("needs_attention", 6),
        ("compensating", 6),
    ] {
        let bytes = format!(
            r#"{{"schema_version":1,"operation_id":"op_1","state":"{state}","replay":false,"error":null}}"#
        );
        assert_eq!(
            decode_submission_reply(bytes.as_bytes(), &id())
                .unwrap()
                .exit_code(),
            expected
        );
    }
    for (error, expected) in [
        ("INVALID_REQUEST", 2),
        ("INVALID_SIGNATURE", 3),
        ("REPLAY_DENIED", 3),
        // W386 (D-035): standing capture refusals before intent.
        ("STANDING_WINDOW_CLOSED", 3),
        ("STANDING_RUN_MISMATCH", 3),
        ("PRECONDITION_CHANGED", 4),
        ("OLS_DRIFT", 4),
        ("OLS_GENERATION_CURRENT", 4),
        ("EXECUTOR_DEPENDENCY_UNAVAILABLE", 7),
        ("REGISTRY_UNAVAILABLE", 7),
        ("JOURNAL_ROLLBACK", 7),
        ("NEW_UNKNOWN_CODE", 7),
    ] {
        let bytes = format!(
            r#"{{"schema_version":1,"operation_id":null,"state":null,"replay":false,"error":"{error}"}}"#
        );
        assert_eq!(
            decode_submission_reply(bytes.as_bytes(), &id())
                .unwrap()
                .exit_code(),
            expected
        );
    }
    // W360: an operation that ended `untouched` because its drift or
    // precondition recheck refused it after intent is a refusal, as before
    // intent (W359 recorded exit 5 for `op_w359d1`). Any other untouched
    // outcome, and every effect that was attempted, stays a known failure.
    for (state, error, expected) in [
        ("untouched", "OLS_DRIFT", 4),
        ("untouched", "PRECONDITION_CHANGED", 4),
        ("untouched", "NOT_ADMITTED_FOR_EFFECT", 5),
        ("untouched", "PROVISION_STEP_FAILED", 5),
        ("untouched", "NEW_UNKNOWN_CODE", 5),
        ("failed_compensated", "OLS_DRIFT", 5),
        ("quarantined", "PRECONDITION_CHANGED", 5),
        ("needs_attention", "OLS_DRIFT", 6),
    ] {
        let bytes = format!(
            r#"{{"schema_version":1,"operation_id":"op_1","state":"{state}","replay":false,"error":"{error}"}}"#
        );
        assert_eq!(
            decode_submission_reply(bytes.as_bytes(), &id())
                .unwrap()
                .exit_code(),
            expected,
            "{state} {error}"
        );
    }
    let failed = br#"{"schema_version":1,"operation_id":"op_1","state":"succeeded","replay":false,"error":"VERIFICATION_FAILED"}"#;
    assert_eq!(
        decode_submission_reply(failed, &id()).unwrap().exit_code(),
        5
    );
}

/// W381 (D-032): a failed capture replies `failed`, not `untouched`. The
/// exit classes stay those of `untouched`: 5, or 4 for a recheck refusal
/// after intent. A settled capture carries its unclaimed snapshot ID.
#[test]
fn a_failed_capture_replies_failed_with_the_untouched_exit_classes() {
    for (error, expected) in [
        ("null", 5),
        ("\"PROVISION_STEP_FAILED\"", 5),
        ("\"NOT_ADMITTED_FOR_EFFECT\"", 5),
        ("\"PRECONDITION_CHANGED\"", 4),
        ("\"OLS_DRIFT\"", 4),
    ] {
        let bytes = format!(
            r#"{{"schema_version":1,"operation_id":"op_1","state":"failed","replay":false,"error":{error}}}"#
        );
        let reply = decode_submission_reply(bytes.as_bytes(), &id()).unwrap();
        assert_eq!(
            reply.state,
            Some(rustiron_contracts::execution::OutcomeState::Failed)
        );
        assert_eq!(reply.unclaimed_snapshot_id, None);
        assert_eq!(reply.exit_code(), expected, "{error}");
    }
    let snapshot = "ab".repeat(32);
    let settled = format!(
        r#"{{"schema_version":1,"operation_id":"op_1","state":"failed","replay":true,"error":null,"unclaimed_snapshot_id":"{snapshot}"}}"#
    );
    let reply = decode_submission_reply(settled.as_bytes(), &id()).unwrap();
    assert_eq!(
        reply.unclaimed_snapshot_id.as_deref(),
        Some(snapshot.as_str())
    );
    assert_eq!(reply.exit_code(), 5);
    // The field is additive: a reply without it never shows `null`.
    let plain = decode_submission_reply(
        br#"{"schema_version":1,"operation_id":"op_1","state":"failed","replay":false,"error":null}"#,
        &id(),
    )
    .unwrap();
    let encoded = serde_json::to_value(plain).unwrap();
    assert!(encoded.get("unclaimed_snapshot_id").is_none());
}

/// W381: an unclaimed snapshot ID belongs only to a `failed` reply and is
/// exactly 64 lowercase hex characters.
#[test]
fn an_unclaimed_snapshot_beside_another_state_or_malformed_is_refused() {
    let snapshot = "ab".repeat(32);
    for (state, value) in [
        ("succeeded", snapshot.clone()),
        ("untouched", snapshot.clone()),
        ("intent", snapshot.clone()),
        ("failed", "AB".repeat(32)),
        ("failed", "ab".repeat(31)),
        ("failed", format!("{}\n", "ab".repeat(32))),
    ] {
        let bytes = format!(
            r#"{{"schema_version":1,"operation_id":"op_1","state":"{state}","replay":false,"error":null,"unclaimed_snapshot_id":{}}}"#,
            serde_json::to_string(&value).unwrap()
        );
        assert_eq!(
            decode_submission_reply(bytes.as_bytes(), &id()).unwrap_err(),
            ProtocolError::InvalidMessage,
            "{state} {value:?}"
        );
    }
}
