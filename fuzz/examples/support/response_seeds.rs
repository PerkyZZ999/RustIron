//! Positive/refusal response paths with fixed external correlation identities.

use rustiron_contracts::{MAX_JSON_DEPTH, MAX_RESPONSE_BYTES};
use serde_json::{Value, json};

const TARGETS: [&str; 5] = [
    "submission_reply",
    "apply_response",
    "read_response",
    "status_response",
    "evidence_response",
];
const STATES: [&str; 7] = [
    "intent",
    "succeeded",
    "untouched",
    "needs_attention",
    "quarantined",
    "compensating",
    "failed_compensated",
];

pub(super) fn input_limits() -> Value {
    TARGETS
        .into_iter()
        .map(|target| (target.to_owned(), json!(MAX_RESPONSE_BYTES + 1)))
        .collect()
}

fn reply(state: Value, error: Value) -> Value {
    json!({"schema_version":1,"operation_id":"operation_1","state":state,"replay":false,"error":error})
}

fn envelope(request: &str, kind: &str, data: Value) -> Value {
    json!({"schema_version":1,"request_id":request,"status":"ok","data":{"kind":kind,"value":data},"error":null})
}

fn refusal() -> Value {
    json!({"schema_version":1,"request_id":"query_1","status":"error","data":null,"error":{"code":"NOT_FOUND","message":"Not found","retryable":false,"operation_id":null,"details":[]}})
}

fn emit(
    seed: &mut impl FnMut(&str, &str, &[u8], bool),
    target: &str,
    name: &str,
    value: &Value,
    accepted: bool,
) {
    seed(target, name, &serde_json::to_vec(value).unwrap(), accepted);
}

pub(super) fn generate(seed: &mut impl FnMut(&str, &str, &[u8], bool)) {
    for state in STATES {
        let value = reply(json!(state), Value::Null);
        emit(seed, "submission_reply", state, &value, true);
        let mut replay = value.clone();
        replay["replay"] = json!(true);
        emit(
            seed,
            "submission_reply",
            &format!("{state}-replay"),
            &replay,
            true,
        );
        let value = envelope(
            "request_1",
            "plan_apply",
            json!({"operation_id":"operation_1","outcome":{"kind":"executor_reply","reply":value}}),
        );
        emit(seed, "apply_response", state, &value, true);
        let status = envelope(
            "query_1",
            "operation_status",
            json!({"operation_id":"operation_1","state":state}),
        );
        emit(seed, "status_response", state, &status, true);
        emit(seed, "read_response", state, &status, true);
    }
    for error in [
        "INVALID_REQUEST",
        "INVALID_SIGNATURE",
        "PRECONDITION_CHANGED",
        "REGISTRY_UNAVAILABLE",
        "NEW_UNKNOWN_CODE",
    ] {
        let mut value = reply(Value::Null, json!(error));
        value["operation_id"] = Value::Null;
        emit(seed, "submission_reply", error, &value, true);
    }
    for error in [json!("UNVERIFIED"), json!("X".repeat(64))] {
        emit(
            seed,
            "submission_reply",
            &format!("state-error-{}", error.as_str().unwrap().len()),
            &reply(json!("succeeded"), error),
            true,
        );
    }
    for reason in [
        "busy",
        "unavailable",
        "unauthorized",
        "invalid_configuration",
    ] {
        emit(
            seed,
            "apply_response",
            reason,
            &envelope(
                "request_1",
                "plan_apply",
                json!({"operation_id":"operation_1","outcome":{"kind":"not_sent","reason":reason}}),
            ),
            true,
        );
    }
    let mut extended_reply = reply(json!("intent"), Value::Null);
    extended_reply["future"] = json!(true);
    emit(
        seed,
        "apply_response",
        "nested-reply-extension",
        &envelope(
            "request_1",
            "plan_apply",
            json!({"operation_id":"operation_1","outcome":{"kind":"executor_reply","reply":extended_reply}}),
        ),
        true,
    );
    let apply = envelope(
        "request_1",
        "plan_apply",
        json!({"operation_id":"operation_1","outcome":{"kind":"outcome_unknown"}}),
    );
    emit(seed, "apply_response", "outcome-unknown", &apply, true);
    let evidence = envelope(
        "query_1",
        "evidence_export",
        json!({"operation_id":"operation_1","receipt":{"body":{"self_attested":true},"body_sha256":"a".repeat(64)}}),
    );
    emit(seed, "evidence_response", "receipt-shape", &evidence, true);
    emit(seed, "read_response", "receipt-shape", &evidence, true);
    // W392: signed and unsigned receipt labels; the signature text is test text.
    let signature = json!({
        "format": "sshsig",
        "namespace": "rustiron-receipt-v1",
        "key_fingerprint": "SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8",
        "armored": "-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAQ==\n-----END SSH SIGNATURE-----\n",
    });
    for (name, receipt, accepted) in [
        (
            "receipt-signed",
            json!({"attestation":"self-attested, signed","signature":signature}),
            true,
        ),
        (
            "receipt-unsigned",
            json!({"attestation":"self-attested, unsigned"}),
            true,
        ),
        (
            "receipt-signed-without-signature",
            json!({"attestation":"self-attested, signed"}),
            false,
        ),
        (
            "receipt-unsigned-with-signature",
            json!({"attestation":"self-attested, unsigned","signature":signature}),
            false,
        ),
    ] {
        let mut receipt = receipt;
        receipt["body"] = json!({"self_attested":true});
        receipt["body_sha256"] = json!("a".repeat(64));
        let response = envelope(
            "query_1",
            "evidence_export",
            json!({"operation_id":"operation_1","receipt":receipt}),
        );
        emit(seed, "evidence_response", name, &response, accepted);
    }
    let page = envelope(
        "query_1",
        "site_list",
        json!({"items":[],"next_cursor":null}),
    );
    emit(seed, "read_response", "empty-page", &page, true);
    let row = json!({"site_id":"site_1","name":"Fixture","ownership":"observed_only"});
    emit(
        seed,
        "read_response",
        "site-inspect",
        &envelope(
            "query_1",
            "site_inspect",
            json!({"site":row,"configuration_generation":{"state":"unknown","reason":"not_checked"}}),
        ),
        true,
    );

    let page = envelope(
        "query_1",
        "site_list",
        json!({"items":vec![row.clone();100],"next_cursor":null}),
    );
    emit(seed, "read_response", "max-page", &page, true);
    let mut changed = page.clone();
    changed["data"]["value"]["items"] = json!(vec![row; 101]);
    emit(seed, "read_response", "over-page", &changed, false);
    changed = page.clone();
    changed["data"]["value"]
        .as_object_mut()
        .unwrap()
        .remove("next_cursor");
    emit(seed, "read_response", "missing-cursor", &changed, false);
    let denied = refusal();
    for target in ["read_response", "status_response", "evidence_response"] {
        emit(seed, target, "refusal", &denied, true);
        let mut changed = denied.clone();
        changed["error"]["details"] = json!(vec!["detail"; 8]);
        emit(seed, target, "max-error-details", &changed, true);
        changed["error"]["details"] = json!(vec!["detail"; 9]);
        emit(seed, target, "over-error-details", &changed, false);
        changed = denied.clone();
        changed["error"]
            .as_object_mut()
            .unwrap()
            .remove("operation_id");
        emit(seed, target, "missing-error-operation", &changed, false);
        changed = denied.clone();
        changed["error"]["operation_id"] = json!("operation_1");
        emit(seed, target, "error-operation-authority", &changed, false);
    }
    for (target, base) in [
        ("submission_reply", reply(json!("intent"), Value::Null)),
        ("apply_response", apply),
        (
            "read_response",
            envelope(
                "query_1",
                "operation_status",
                json!({"operation_id":"operation_1","state":"intent"}),
            ),
        ),
        (
            "status_response",
            envelope(
                "query_1",
                "operation_status",
                json!({"operation_id":"operation_1","state":"intent"}),
            ),
        ),
        ("evidence_response", evidence),
    ] {
        let mut changed = base.clone();
        changed["future"] = json!(true);
        emit(seed, target, "outer-extension", &changed, true);
        changed = base.clone();
        changed["schema_version"] = json!(2);
        emit(seed, target, "unsupported-version", &changed, false);
        for field in if target == "submission_reply" {
            &["schema_version", "operation_id", "state", "replay", "error"][..]
        } else {
            &["schema_version", "request_id", "status", "data", "error"][..]
        } {
            changed = base.clone();
            changed.as_object_mut().unwrap().remove(*field);
            emit(seed, target, &format!("missing-{field}"), &changed, false);
        }
        if target == "submission_reply" {
            for (name, error) in [
                ("empty-code", "".to_owned()),
                ("lowercase-code", "unsafe".to_owned()),
                ("over-code", "X".repeat(65)),
            ] {
                changed = base.clone();
                changed["error"] = json!(error);
                emit(seed, target, name, &changed, false);
            }
            changed = base.clone();
            changed["operation_id"] = Value::Null;
            emit(seed, target, "unidentified-state", &changed, false);
            changed = reply(Value::Null, Value::Null);
            emit(seed, target, "empty-result", &changed, false);
            changed = reply(Value::Null, json!("INVALID_REQUEST"));
            changed["replay"] = json!(true);
            emit(seed, target, "replayed-refusal", &changed, false);
            changed = base.clone();
            changed["operation_id"] = json!("other_operation");
            emit(seed, target, "other-operation", &changed, false);
        } else {
            changed = base.clone();
            changed["error"] = json!({});
            emit(seed, target, "contradictory-slots", &changed, false);
            changed = base.clone();
            changed["data"]["kind"] = json!("unknown_kind");
            emit(seed, target, "unknown-kind", &changed, false);
            if target != "read_response" {
                changed = base.clone();
                changed["request_id"] = json!("other_request");
                emit(seed, target, "other-request", &changed, false);
                changed = base.clone();
                changed["data"]["value"]["operation_id"] = json!("other_operation");
                emit(seed, target, "other-operation", &changed, false);
            }
            if target == "apply_response" {
                changed = base.clone();
                changed["data"]["value"]["outcome"]["reply"] = Value::Null;
                emit(seed, target, "ambiguous-outcome", &changed, false);
            }
            if target == "evidence_response" {
                changed = base.clone();
                changed["data"]["value"]["receipt"]["body_sha256"] = json!("A".repeat(64));
                emit(seed, target, "upper-digest", &changed, false);
                changed = base.clone();
                changed["data"]["value"]["receipt"]["body"] = json!([]);
                emit(seed, target, "array-receipt", &changed, false);
            }
        }
        let bytes = serde_json::to_vec(&base).unwrap();
        let mut duplicate = br#"{"schema_vers\u0069on":1,"#.to_vec();
        duplicate.extend_from_slice(&bytes[1..]);
        seed(target, "escaped-duplicate", &duplicate, false);
        let mut exact = bytes.clone();
        exact.resize(MAX_RESPONSE_BYTES, b' ');
        seed(target, "exact-size", &exact, true);
        exact.push(b' ');
        seed(target, "over-size", &exact, false);
        if target != "submission_reply" {
            for (name, arrays, accepted) in [
                ("exact-depth", MAX_JSON_DEPTH - 1, true),
                ("over-depth", MAX_JSON_DEPTH, false),
            ] {
                let depth = format!(
                    r#"{{"future":{}0{},{}"#,
                    "[".repeat(arrays),
                    "]".repeat(arrays),
                    std::str::from_utf8(&bytes[1..]).unwrap()
                );
                seed(target, name, depth.as_bytes(), accepted);
            }
        }
    }
    // A valid lexical number spelling can grow when Value is re-encoded.
    let numbers = "1e3,".repeat((MAX_RESPONSE_BYTES - 1024) / 4);
    let expanded = format!(
        r#"{{"schema_version":1,"request_id":"query_1","status":"ok","data":{{"kind":"evidence_export","value":{{"operation_id":"operation_1","receipt":{{"body":{{"numbers":[{numbers}0]}},"body_sha256":"{}"}}}}}},"error":null}}"#,
        "a".repeat(64)
    );
    for target in ["read_response", "evidence_response"] {
        seed(target, "encoding-expansion", expanded.as_bytes(), true);
    }
    for target in TARGETS {
        for (name, bytes) in [
            ("empty", b"".as_slice()),
            ("root-array", b"[]"),
            ("invalid-utf8", b"{\"x\":\"\xff\"}"),
            ("lone-surrogate", br#"{"x":"\ud800"}"#),
        ] {
            seed(target, name, bytes, false);
        }
    }
    seed(
        "read_response",
        "doctor-golden",
        include_bytes!("../../../crates/contracts/tests/fixtures/doctor-response.json"),
        true,
    );
    seed(
        "read_response",
        "error-golden",
        include_bytes!("../../../crates/contracts/tests/fixtures/error-response.json"),
        true,
    );
}
