//! Canonical byte and digest boundary regressions, without authority or effects.

use rustiron_contracts::{CanonicalObject, MAX_JSON_DEPTH, MAX_REQUEST_BYTES, ProtocolError};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    name: String,
    input: String,
    canonical: String,
    plan_digest: String,
}

fn vector(name: &str) -> Vector {
    serde_json::from_str::<Vec<Vector>>(include_str!("fixtures/canonical-vectors.json"))
        .unwrap()
        .into_iter()
        .find(|vector| vector.name == name)
        .unwrap()
}

fn assert_vector(name: &str) {
    let expected = vector(name);
    let actual = CanonicalObject::decode(expected.input.as_bytes()).unwrap();
    assert_eq!(actual.as_bytes(), expected.canonical.as_bytes());
    let digest = actual.plan_domain_digest();
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(hex, expected.plan_digest);
    assert_eq!(CanonicalObject::decode(actual.as_bytes()).unwrap(), actual);
}

#[test]
fn rfc_property_order_uses_utf16_including_non_bmp_keys() {
    assert_vector("rfc8785_property_order");
}

#[test]
fn escaping_and_literal_types_preserve_values() {
    assert_vector("escaping_and_literal_types");
}

#[test]
fn nested_unsigned_limits_are_exact_and_arrays_keep_order() {
    assert_vector("nested_unsigned_limits");
}

#[test]
fn unicode_is_not_normalized() {
    assert_vector("unicode_not_normalized");
}

#[test]
fn empty_object_is_canonical_but_does_not_imply_a_plan_schema() {
    assert_vector("empty_object");
}

#[test]
fn whitespace_and_key_order_do_not_change_the_digest() {
    let first = CanonicalObject::decode(br#"{ "b":2,"a":1 }"#).unwrap();
    let second = CanonicalObject::decode(br#"{"a":1,"b":2}"#).unwrap();
    assert_eq!(first.plan_domain_digest(), second.plan_domain_digest());
}

#[test]
fn semantic_changes_cannot_share_a_fixture_digest() {
    let first = CanonicalObject::decode(br#"{"site":"one","steps":[1,2]}"#).unwrap();
    let other_site = CanonicalObject::decode(br#"{"site":"two","steps":[1,2]}"#).unwrap();
    let other_order = CanonicalObject::decode(br#"{"site":"one","steps":[2,1]}"#).unwrap();
    assert_ne!(first.plan_domain_digest(), other_site.plan_domain_digest());
    assert_ne!(first.plan_domain_digest(), other_order.plan_domain_digest());
}

fn invalid(input: &[u8]) {
    let error = CanonicalObject::decode(input).unwrap_err();
    assert_eq!(error, ProtocolError::InvalidMessage);
    assert!(!error.to_string().contains("INPUT_CANARY"));
}

#[test]
fn decoded_alias_keys_are_duplicates() {
    invalid(br#"{"INPUT_CANARY":1,"\u0049NPUT_CANARY":2}"#);
}

#[test]
fn nested_array_objects_cannot_hide_duplicates() {
    invalid(br#"{"x":[{"a":1,"a":2}]}"#);
}

#[test]
fn out_of_range_integer_is_not_rounded_to_an_approved_value() {
    invalid(br#"{"n":9007199254740992}"#);
}

#[test]
fn enormous_integer_is_rejected_before_float_conversion() {
    invalid(br#"{"n":1844674407370955161600000}"#);
}

#[test]
fn negative_integer_is_not_a_budget() {
    invalid(br#"{"n":-1}"#);
}

#[test]
fn negative_zero_is_not_normalized_into_authority() {
    invalid(br#"{"n":-0}"#);
}

#[test]
fn fraction_token_is_rejected_even_if_its_value_is_integral() {
    invalid(br#"{"n":1.0}"#);
}

#[test]
fn exponent_token_is_rejected_even_if_its_value_is_integral() {
    invalid(br#"{"n":1e0}"#);
}

#[test]
fn non_object_root_is_rejected() {
    invalid(br#"[{}]"#);
}

#[test]
fn trailing_input_is_rejected() {
    invalid(br#"{} {"INPUT_CANARY":1}"#);
}

#[test]
fn invalid_utf8_is_rejected_without_echo() {
    invalid(b"{\"INPUT_CANARY\":\"\xff\"}");
}

#[test]
fn lone_surrogate_is_rejected() {
    invalid(br#"{"INPUT_CANARY":"\ud800"}"#);
}

#[test]
fn exact_byte_limit_is_accepted_and_one_more_is_refused() {
    let input = format!(r#"{{"v":"{}"}}"#, "x".repeat(MAX_REQUEST_BYTES - 8));
    assert_eq!(input.len(), MAX_REQUEST_BYTES);
    assert!(CanonicalObject::decode(input.as_bytes()).is_ok());
    let too_large = format!("{input} ");
    assert_eq!(
        CanonicalObject::decode(too_large.as_bytes()),
        Err(ProtocolError::RequestTooLarge)
    );
}

#[test]
fn exact_depth_limit_is_accepted_and_one_more_is_refused() {
    let accepted = format!(
        r#"{{"v":{}0{}}}"#,
        "[".repeat(MAX_JSON_DEPTH - 1),
        "]".repeat(MAX_JSON_DEPTH - 1)
    );
    assert!(CanonicalObject::decode(accepted.as_bytes()).is_ok());
    let too_deep = format!(
        r#"{{"v":{}0{}}}"#,
        "[".repeat(MAX_JSON_DEPTH),
        "]".repeat(MAX_JSON_DEPTH)
    );
    invalid(too_deep.as_bytes());
}
