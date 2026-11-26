//! Raw signed-object transport oracles. Decoding grants no authority.

use std::collections::BTreeMap;

use rustiron_contracts::apply::{decode_apply_request, encode_apply_request};
use rustiron_contracts::execution::{
    MAX_SIGNATURE_TEXT, Submission, decode_submission, encode_submission,
};
use rustiron_contracts::{Id, MAX_REQUEST_BYTES, ProtocolError};
use serde_json::{Value, json, value::RawValue};

type RawMap = BTreeMap<String, Box<RawValue>>;

fn raw_map(bytes: &[u8]) -> RawMap {
    serde_json::from_slice(bytes).expect("accepted envelope must be a JSON object")
}

fn keys(value: &Value, expected: &[&str]) {
    let object = value.as_object().unwrap();
    assert_eq!(object.len(), expected.len(), "closed wire fields changed");
    assert!(expected.iter().all(|key| object.contains_key(*key)));
}

fn signed_fields(
    raw: &RawMap,
    operation: &Id,
    retry: &Id,
    plan: &[u8],
    grant: &[u8],
    signature: &str,
) {
    let value: Value = serde_json::from_str(&serde_json::to_string(raw).unwrap()).unwrap();
    assert_eq!(value["operation_id"].as_str(), Some(operation.as_str()));
    assert_eq!(value["idempotency_key"].as_str(), Some(retry.as_str()));
    assert_eq!(value["signature"].as_str(), Some(signature));
    assert!(signature.is_ascii() && signature.len() <= MAX_SIGNATURE_TEXT);
    assert_eq!(
        plan,
        raw["plan"].get().as_bytes(),
        "wire plan bytes changed"
    );
    assert_eq!(
        grant,
        raw["grant"].get().as_bytes(),
        "wire grant bytes changed"
    );
    assert!(plan.starts_with(b"{") && grant.starts_with(b"{"));
}

fn same_submission(first: &Submission<'_>, second: &Submission<'_>) {
    assert_eq!(first.operation_id, second.operation_id);
    assert_eq!(first.idempotency_key, second.idempotency_key);
    assert_eq!(first.plan, second.plan, "roundtrip changed raw plan bytes");
    assert_eq!(
        first.grant, second.grant,
        "roundtrip changed raw grant bytes"
    );
    assert_eq!(first.signature, second.signature);
}

fn refused_if_bounded(bytes: &[u8], accepts: &impl Fn(&[u8]) -> bool, reason: &str) {
    if bytes.len() <= MAX_REQUEST_BYTES {
        assert!(!accepts(bytes), "{reason}");
    }
}

fn nested_duplicate(input: &[u8], apply: bool, field: &str) -> Vec<u8> {
    let mut outer = raw_map(input);
    let mut fields = if apply {
        raw_map(outer["params"].get().as_bytes())
    } else {
        raw_map(input)
    };
    let original = fields[field].get();
    let inner = &original[1..original.len() - 1];
    let remainder = if inner.trim().is_empty() {
        String::new()
    } else {
        format!(",{inner}")
    };
    let duplicate = format!(r#"{{"fuzz_dup":0,"fuzz_d\u0075p":1{remainder}}}"#);
    fields.insert(field.to_owned(), RawValue::from_string(duplicate).unwrap());
    if apply {
        outer.insert(
            "params".to_owned(),
            RawValue::from_string(serde_json::to_string(&fields).unwrap()).unwrap(),
        );
        serde_json::to_vec(&outer).unwrap()
    } else {
        serde_json::to_vec(&fields).unwrap()
    }
}

fn envelope_controls(input: &[u8], apply: bool, accepts: impl Fn(&[u8]) -> bool) {
    let value: Value = serde_json::from_slice(input).unwrap();
    for (field, replacement, reason) in [
        (
            "schema_version",
            json!(2),
            "unsupported wire version accepted",
        ),
        ("fuzz_unknown", json!(true), "unknown wire member accepted"),
    ] {
        let mut changed = value.clone();
        changed[field] = replacement;
        refused_if_bounded(&serde_json::to_vec(&changed).unwrap(), &accepts, reason);
    }
    // Preserve nested raw bytes while inserting duplicate top-level names.
    for prefix in [
        br#"{"schema_version":1,"#.as_slice(),
        br#"{"sch\u0065ma_version":1,"#,
    ] {
        let mut duplicate = prefix.to_vec();
        duplicate.extend_from_slice(&input.trim_ascii_start()[1..]);
        refused_if_bounded(&duplicate, &accepts, "duplicate wire member accepted");
    }
    for field in ["plan", "grant"] {
        refused_if_bounded(
            &nested_duplicate(input, apply, field),
            &accepts,
            "nested duplicate wire member accepted",
        );
    }
    for (field, replacement, reason) in [
        ("plan", json!([]), "non-object wire plan accepted"),
        ("grant", Value::Null, "non-object wire grant accepted"),
        ("signature", json!("é"), "non-ASCII wire signature accepted"),
        (
            "signature",
            json!("x".repeat(MAX_SIGNATURE_TEXT + 1)),
            "oversized wire signature accepted",
        ),
    ] {
        let mut changed = value.clone();
        let fields = if apply {
            &mut changed["params"]
        } else {
            &mut changed
        };
        fields[field] = replacement;
        refused_if_bounded(&serde_json::to_vec(&changed).unwrap(), &accepts, reason);
    }
    if apply {
        let mut changed = value;
        changed["params"]["fuzz_unknown"] = json!(true);
        refused_if_bounded(
            &serde_json::to_vec(&changed).unwrap(),
            &accepts,
            "unknown apply parameter accepted",
        );
    }
}

/// Exercise the raw executor envelope, without interpreting or verifying a grant.
pub fn submission(input: &[u8]) -> bool {
    let decoded = decode_submission(input);
    if input.len() > MAX_REQUEST_BYTES {
        assert_eq!(decoded.err(), Some(ProtocolError::RequestTooLarge));
        return false;
    }
    let Ok(first) = decoded else {
        return false;
    };
    let raw = raw_map(input);
    let value: Value = serde_json::from_slice(input).unwrap();
    keys(
        &value,
        &[
            "schema_version",
            "operation_id",
            "idempotency_key",
            "plan",
            "grant",
            "signature",
        ],
    );
    assert_eq!(value["schema_version"], json!(1));
    signed_fields(
        &raw,
        &first.operation_id,
        &first.idempotency_key,
        first.plan,
        first.grant,
        &first.signature,
    );
    let encoded = encode_submission(
        &first.operation_id,
        &first.idempotency_key,
        first.plan,
        first.grant,
        &first.signature,
    )
    .unwrap();
    same_submission(&first, &decode_submission(&encoded).unwrap());
    envelope_controls(input, false, |bytes| decode_submission(bytes).is_ok());
    for (plan, grant) in [(b" {}".as_slice(), first.grant), (first.plan, b"{} ")] {
        assert_eq!(
            encode_submission(
                &first.operation_id,
                &first.idempotency_key,
                plan,
                grant,
                &first.signature
            )
            .err(),
            Some(ProtocolError::InvalidMessage),
            "encoder accepted signed-object outer whitespace"
        );
    }
    true
}

/// Exercise the operator envelope and the pure forwarding encoder/decoder chain.
pub fn apply_request(input: &[u8]) -> bool {
    let decoded = decode_apply_request(input);
    if input.len() > MAX_REQUEST_BYTES {
        assert_eq!(decoded.err(), Some(ProtocolError::RequestTooLarge));
        return false;
    }
    let Ok(first) = decoded else {
        return false;
    };
    let outer = raw_map(input);
    let raw = raw_map(outer["params"].get().as_bytes());
    let value: Value = serde_json::from_slice(input).unwrap();
    keys(
        &value,
        &["schema_version", "request_id", "method", "params"],
    );
    keys(
        &value["params"],
        &[
            "operation_id",
            "idempotency_key",
            "plan",
            "grant",
            "signature",
        ],
    );
    assert_eq!(value["schema_version"], json!(1));
    assert_eq!(value["method"], json!("plan_apply"));
    assert_eq!(
        value["request_id"].as_str(),
        Some(first.request_id.as_str())
    );
    signed_fields(
        &raw,
        &first.operation_id,
        &first.idempotency_key,
        &first.plan,
        &first.grant,
        &first.signature,
    );
    let encoded = encode_apply_request(&first).unwrap();
    let second = decode_apply_request(&encoded).unwrap();
    assert_eq!(second.request_id, first.request_id);
    assert_eq!(second.operation_id, first.operation_id);
    assert_eq!(second.idempotency_key, first.idempotency_key);
    assert_eq!(
        second.plan, first.plan,
        "apply roundtrip changed raw plan bytes"
    );
    assert_eq!(
        second.grant, first.grant,
        "apply roundtrip changed raw grant bytes"
    );
    assert_eq!(second.signature, first.signature);
    let forwarded = encode_submission(
        &first.operation_id,
        &first.idempotency_key,
        &first.plan,
        &first.grant,
        &first.signature,
    )
    .unwrap();
    let submission = decode_submission(&forwarded).unwrap();
    signed_fields(
        &raw,
        &submission.operation_id,
        &submission.idempotency_key,
        submission.plan,
        submission.grant,
        &submission.signature,
    );
    envelope_controls(input, true, |bytes| decode_apply_request(bytes).is_ok());
    true
}
