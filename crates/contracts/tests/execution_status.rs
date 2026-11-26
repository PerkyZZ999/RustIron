//! Executor status queries are closed and responses must correlate.
use rustiron_contracts::{
    ErrorCode, Id, ProtocolError,
    execution::{
        EvidenceQuery, OutcomeState, StatusQuery, decode_evidence_query, decode_evidence_response,
        decode_status_query, decode_status_response, encode_evidence_query, encode_status_query,
    },
};

fn id(text: &str) -> Id {
    Id::try_from(text.to_owned()).unwrap()
}

fn query() -> StatusQuery {
    StatusQuery {
        request_id: id("query_1"),
        operation_id: id("operation_1"),
    }
}

#[test]
fn request_round_trips_and_rejects_ambiguous_input() {
    assert_eq!(
        decode_status_query(&encode_status_query(&query()).unwrap()).unwrap(),
        query()
    );
    let duplicate = br#"{"schema_version":1,"request_id":"q","method":"operation_status","params":{"operation_id":"one","operation_id":"two"}}"#;
    let extra = br#"{"schema_version":1,"request_id":"q","method":"operation_status","params":{"operation_id":"one","path":"/tmp"}}"#;
    assert_eq!(
        decode_status_query(duplicate).unwrap_err(),
        ProtocolError::InvalidMessage
    );
    assert_eq!(
        decode_status_query(extra).unwrap_err(),
        ProtocolError::InvalidMessage
    );
}

#[test]
fn response_correlates_request_and_operation() {
    let bytes = br#"{"schema_version":1,"request_id":"query_1","status":"ok","data":{"kind":"operation_status","value":{"operation_id":"operation_1","state":"intent"}},"error":null}"#;
    let response = decode_status_response(bytes, &query()).unwrap();
    assert_eq!(response.result.unwrap().state, OutcomeState::Intent);
    let wrong = br#"{"schema_version":1,"request_id":"query_1","status":"ok","data":{"kind":"operation_status","value":{"operation_id":"other","state":"succeeded"}},"error":null}"#;
    assert_eq!(
        decode_status_response(wrong, &query()).unwrap_err(),
        ProtocolError::InvalidMessage
    );
    let wrong_request = br#"{"schema_version":1,"request_id":"other","status":"ok","data":{"kind":"operation_status","value":{"operation_id":"operation_1","state":"intent"}},"error":null}"#;
    assert_eq!(
        decode_status_response(wrong_request, &query()).unwrap_err(),
        ProtocolError::InvalidMessage
    );
}

#[test]
fn refusal_is_distinct_from_a_recorded_outcome() {
    let bytes = br#"{"schema_version":1,"request_id":"query_1","status":"error","data":null,"error":{"code":"NOT_FOUND","message":"Not found","retryable":false,"operation_id":null,"details":[]}}"#;
    assert_eq!(
        decode_status_response(bytes, &query())
            .unwrap()
            .result
            .unwrap_err()
            .code(),
        ErrorCode::NotFound
    );
    let bad =
        br#"{"schema_version":1,"request_id":"query_1","status":"ok","data":null,"error":null}"#;
    assert_eq!(
        decode_status_response(bad, &query()).unwrap_err(),
        ProtocolError::InvalidMessage
    );
}

#[test]
fn response_refuses_duplicate_fields_and_unbounded_error_claims() {
    let duplicate = br#"{"schema_version":1,"request_id":"query_1","status":"ok","data":{"kind":"operation_status","value":{"operation_id":"operation_1","state":"intent","state":"succeeded"}},"error":null}"#;
    let admitted_error = br#"{"schema_version":1,"request_id":"query_1","status":"error","data":null,"error":{"code":"NOT_FOUND","message":"Not found","retryable":false,"operation_id":"operation_1","details":[]}}"#;
    assert_eq!(
        decode_status_response(duplicate, &query()).unwrap_err(),
        ProtocolError::InvalidMessage
    );
    assert_eq!(
        decode_status_response(admitted_error, &query()).unwrap_err(),
        ProtocolError::InvalidMessage
    );
}

#[test]
fn status_response_rejects_positional_value() {
    let bytes = br#"{"schema_version":1,"request_id":"query_1","status":"ok","data":{"kind":"operation_status","value":["operation_1","succeeded"]},"error":null}"#;
    assert_eq!(
        decode_status_response(bytes, &query()).unwrap_err(),
        ProtocolError::InvalidMessage
    );
}

#[test]
fn status_request_rejects_positional_params() {
    let bytes = br#"{"schema_version":1,"request_id":"query_1","method":"operation_status","params":["operation_1"]}"#;
    assert_eq!(
        decode_status_query(bytes).unwrap_err(),
        ProtocolError::InvalidMessage
    );
}

#[test]
fn response_accepts_additive_fields_without_changing_known_state() {
    let bytes = br#"{"schema_version":1,"request_id":"query_1","status":"ok","future":true,"data":{"kind":"operation_status","value":{"operation_id":"operation_1","state":"intent","extra":"ignored"}},"error":null}"#;
    let response = decode_status_response(bytes, &query()).unwrap();
    assert_eq!(response.result.unwrap().state, OutcomeState::Intent);
}

fn evidence() -> EvidenceQuery {
    EvidenceQuery {
        request_id: id("query_1"),
        operation_id: id("operation_1"),
    }
}

#[test]
fn evidence_query_round_trips_and_correlates_the_receipt() {
    assert_eq!(
        decode_evidence_query(&encode_evidence_query(&evidence()).unwrap()).unwrap(),
        evidence()
    );
    let digest = "ab".repeat(32);
    let bytes = format!(
        r#"{{"schema_version":1,"request_id":"query_1","status":"ok","data":{{"kind":"evidence_export","value":{{"operation_id":"operation_1","receipt":{{"body":{{"receipt_schema":"rustiron-recovery-receipt/1"}},"body_sha256":"{digest}"}}}}}},"error":null}}"#
    );
    let parsed = decode_evidence_response(bytes.as_bytes(), &evidence())
        .unwrap()
        .unwrap();
    assert_eq!(parsed.operation_id, evidence().operation_id);
    assert_eq!(parsed.receipt.body_sha256, digest);
    let wrong = bytes.replace("operation_1", "other");
    assert_eq!(
        decode_evidence_response(wrong.as_bytes(), &evidence()).unwrap_err(),
        ProtocolError::InvalidMessage
    );
    let short = bytes.replace(&digest, "abcd");
    assert_eq!(
        decode_evidence_response(short.as_bytes(), &evidence()).unwrap_err(),
        ProtocolError::InvalidMessage
    );
}

/// W392 (D-040 item 6): a receipt states whether the host receipt key
/// signed it. The shape is checked here; the signature is verified offline.
#[test]
fn evidence_receipt_states_its_signature_consistently() {
    use rustiron_contracts::execution::{
        EvidenceReceipt, RECEIPT_ATTESTATION_SIGNED, RECEIPT_ATTESTATION_UNSIGNED,
        RECEIPT_SIGNATURE_NAMESPACE,
    };
    assert_eq!(RECEIPT_SIGNATURE_NAMESPACE, "rustiron-receipt-v1");
    assert_eq!(RECEIPT_ATTESTATION_SIGNED, "self-attested, signed");
    assert_eq!(RECEIPT_ATTESTATION_UNSIGNED, "self-attested, unsigned");
    let digest = "ab".repeat(32);
    let armored = "-----BEGIN SSH SIGNATURE-----\nU1NIU0lH\n-----END SSH SIGNATURE-----\n";
    let fingerprint = "SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8";
    let signature = serde_json::json!({
        "format": "sshsig",
        "namespace": "rustiron-receipt-v1",
        "key_fingerprint": fingerprint,
        "armored": armored,
    });
    let receipt = |extra: serde_json::Value| {
        let mut value = serde_json::json!({
            "body": {"receipt_schema": "rustiron-recovery-receipt/1"},
            "body_sha256": digest,
        });
        for (key, member) in extra.as_object().unwrap() {
            value[key] = member.clone();
        }
        value
    };
    let response = |receipt: &serde_json::Value| {
        serde_json::json!({
            "schema_version": 1, "request_id": "query_1", "status": "ok",
            "data": {"kind": "evidence_export", "value": {"operation_id": "operation_1", "receipt": receipt}},
            "error": null,
        })
        .to_string()
    };
    // An old executor states nothing; the others state their label.
    for good in [
        receipt(serde_json::json!({})),
        receipt(serde_json::json!({"attestation": "self-attested, unsigned"})),
        receipt(
            serde_json::json!({"attestation": "self-attested, signed", "signature": signature}),
        ),
    ] {
        let parsed: EvidenceReceipt = serde_json::from_value(good.clone()).unwrap();
        assert_eq!(serde_json::to_value(&parsed).unwrap(), good);
        let decoded = decode_evidence_response(response(&good).as_bytes(), &evidence())
            .unwrap()
            .unwrap();
        assert_eq!(decoded.receipt, parsed);
    }
    let changed = |key: &str, value: serde_json::Value| {
        let mut changed = signature.clone();
        changed[key] = value;
        changed
    };
    let long = format!(
        "-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----\n",
        "A".repeat(5000)
    );
    let signed = |signature: serde_json::Value| {
        receipt(serde_json::json!({"attestation": "self-attested, signed", "signature": signature}))
    };
    for bad in [
        receipt(serde_json::json!({"attestation": "self-attested, signed"})),
        receipt(
            serde_json::json!({"attestation": "self-attested, unsigned", "signature": signature}),
        ),
        receipt(serde_json::json!({"signature": signature})),
        receipt(serde_json::json!({"attestation": "signed"})),
        signed(changed("namespace", "rustiron-plan-v1".into())),
        signed(changed("format", "x509".into())),
        signed(changed("key_fingerprint", "MD5:00".into())),
        signed(changed("armored", "U1NIU0lH".into())),
        signed(changed("armored", long.into())),
        signed(changed(
            "key_path",
            "/etc/rustiron/receipt-key/ed25519".into(),
        )),
    ] {
        assert!(
            serde_json::from_value::<EvidenceReceipt>(bad.clone()).is_err(),
            "{bad}"
        );
        assert_eq!(
            decode_evidence_response(response(&bad).as_bytes(), &evidence()).unwrap_err(),
            ProtocolError::InvalidMessage,
            "{bad}"
        );
    }
}
