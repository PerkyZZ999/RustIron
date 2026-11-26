//! The executor's readers of the admin helper's capture and probe reply
//! payloads (B12, W324). They are the real executor functions, linked from
//! the `rustiron-executor` library; no copy is fuzzed.

use rustiron_executor::ExecutorError;
use rustiron_executor::admin_helper::{
    decode_capture_for, decode_probe, encode_capture, encode_probe,
};
use rustiron_journal::ProbeState;
use serde_json::Value;

/// The largest payload the campaigns feed. The 8 MiB reply ceiling is
/// enforced before these decoders run and is unit-tested in the executor.
pub const ADMIN_PAYLOAD_MAX_INPUT: usize = 64 * 1024;

/// The site root a relayed manifest is re-verified against.
pub const RELAY_ROOT: &str = "/srv/sites/rs_blog";

fn snapshot_id(field: &Value) -> Option<&str> {
    field
        .as_str()
        .filter(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn error_code(input: &Value) -> &'static str {
    input["error"]
        .as_str()
        .and_then(ExecutorError::from_code)
        .unwrap_or(ExecutorError::Unavailable)
        .code()
}

/// Whether a parsed reply names an outcome the decoder must honor.
fn recognized(input: &Value) -> bool {
    match input["outcome"].as_str() {
        Some("succeeded") => snapshot_id(&input["id"]).is_some(),
        Some("not_started" | "uncertain") => true,
        _ => false,
    }
}

fn without_manifest(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.remove("manifest");
    }
    value
}

fn check_consistency(decoded: &Value, input: &Value, frozen: bool) {
    let label = decoded["consistency"]["label"].as_str();
    let reason = &decoded["consistency"]["reason"];
    let claimed = &input["consistency"];
    match label {
        Some("matched") => {
            assert_eq!(claimed["label"].as_str(), Some("matched"));
            assert_eq!(
                claimed.get("reason"),
                Some(&Value::Null),
                "matched without a null reason"
            );
            assert!(reason.is_null());
        }
        Some("unmatched") => match reason.as_str() {
            Some("database_changed") => {
                assert_eq!(claimed["label"].as_str(), Some("unmatched"));
                assert_eq!(claimed["reason"].as_str(), Some("database_changed"));
            }
            Some("marker_unavailable") => assert!(
                !frozen || claimed["reason"].as_str() == Some("marker_unavailable"),
                "a frozen capture's lost label read as marker_unavailable"
            ),
            Some("freeze_not_held") => assert!(frozen, "freeze_not_held on an unfrozen capture"),
            other => panic!("unknown unmatched reason {other:?}"),
        },
        other => panic!("unknown consistency label {other:?}"),
    }
}

fn check_capture(text: &str, input: Option<&Value>, frozen: bool) -> bool {
    let outcome = decode_capture_for(text, RELAY_ROOT, frozen);
    let line = encode_capture(&outcome);
    let decoded: Value = serde_json::from_str(&line).expect("the encoder writes JSON");
    assert_eq!(
        decode_capture_for(&line, RELAY_ROOT, frozen),
        outcome,
        "a decoded capture does not survive its own encoding"
    );
    let fallback = decode_capture_for("", RELAY_ROOT, frozen);
    let Some(input) = input.filter(|input| recognized(input)) else {
        assert_eq!(outcome, fallback, "an unreadable reply was not uncertain");
        return false;
    };
    assert_eq!(decoded["outcome"], input["outcome"], "the outcome changed");
    match decoded["outcome"].as_str() {
        Some("succeeded") => {
            let id = snapshot_id(&decoded["id"]).expect("a success without a 64-hex id");
            assert_eq!(Some(id), input["id"].as_str());
            for count in ["files", "bytes"] {
                assert_eq!(decoded[count].as_u64(), input[count].as_u64(), "{count}");
            }
            check_consistency(&decoded, input, frozen);
            if let Some(manifest) = decoded.get("manifest") {
                for field in ["sha256", "text", "truncated"] {
                    assert_eq!(
                        manifest[field], input["manifest"][field],
                        "manifest {field}"
                    );
                }
            }
            // A relayed manifest, good or bad, never changes the outcome.
            let bare = without_manifest(input.clone()).to_string();
            let bare_line = encode_capture(&decode_capture_for(&bare, RELAY_ROOT, frozen));
            let bare_decoded: Value = serde_json::from_str(&bare_line).unwrap();
            assert_eq!(
                bare_decoded,
                without_manifest(decoded),
                "the manifest changed the outcome"
            );
        }
        Some("not_started") => assert_eq!(decoded["error"].as_str(), Some(error_code(input))),
        Some("uncertain") => {
            assert_eq!(decoded["error"].as_str(), Some(error_code(input)));
            assert_eq!(
                decoded["snapshot"].as_str(),
                snapshot_id(&input["snapshot"])
            );
        }
        other => panic!("unknown capture outcome {other:?}"),
    }
    // The decoder reads only the parsed value, not its spelling.
    assert_eq!(
        decode_capture_for(&input.to_string(), RELAY_ROOT, frozen),
        outcome,
        "a respelled reply decoded differently"
    );
    true
}

/// Capture reply decoding, for both a plain and a frozen capture: no panic;
/// an unreadable or unknown reply is the uncertain fallback; a decoded
/// success carries the input's 64-hex id and counts; a missing or unknown
/// consistency label is never `matched`, and `freeze_not_held` comes only
/// for a frozen capture; a kept manifest is the input's and never changes the
/// outcome; a decoded outcome survives its own encoding. Non-UTF-8 is
/// refused before decoding, as the client's string read is.
pub fn admin_capture_payload(input: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(input) else {
        return false;
    };
    let parsed = serde_json::from_str::<Value>(text).ok();
    let read = check_capture(text, parsed.as_ref(), false);
    check_capture(text, parsed.as_ref(), true);
    read
}

fn state_name(state: ProbeState) -> &'static str {
    match state {
        ProbeState::Passed => "passed",
        ProbeState::Failed => "failed",
        ProbeState::CleanupIncomplete => "cleanup_incomplete",
        ProbeState::Running => panic!("a probe reply decoded as running"),
    }
}

fn has_float(value: &Value) -> bool {
    match value {
        Value::Number(number) => number.is_f64(),
        Value::Array(items) => items.iter().any(has_float),
        Value::Object(members) => members.values().any(has_float),
        _ => false,
    }
}

/// Probe reply decoding: no panic; a decoded state is one of the three final
/// closed states and names the input's state; the receipt is the input's
/// object; anything else is unknown (`None`). A decoded reply re-encodes to
/// the same state, and `running` never decodes. Non-UTF-8 is refused before
/// decoding, as the client's string read is.
pub fn admin_probe_payload(input: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(input) else {
        return false;
    };
    let parsed = serde_json::from_str::<Value>(text).ok();
    let Some((receipt, state)) = decode_probe(text) else {
        let known = parsed.as_ref().is_some_and(|value| {
            matches!(
                value["state"].as_str(),
                Some("passed" | "failed" | "cleanup_incomplete")
            ) && value["receipt"].is_object()
        });
        assert!(!known, "a final state with an object receipt was refused");
        return false;
    };
    let value = parsed.expect("a decoded probe reply is JSON");
    assert_eq!(value["state"].as_str(), Some(state_name(state)));
    assert!(receipt.is_object(), "the receipt is not an object");
    assert_eq!(value.get("receipt"), Some(&receipt), "the receipt changed");
    let (again, again_state) =
        decode_probe(&encode_probe(&receipt, state)).expect("an encoded probe decodes");
    assert_eq!(again_state, state);
    // Best-effort float parsing may move a receipt float by one unit in the
    // last place; such receipts are compared by state only.
    if !has_float(&receipt) {
        assert_eq!(again, receipt, "the receipt does not survive its encoding");
    }
    assert_eq!(
        decode_probe(&encode_probe(&receipt, ProbeState::Running)),
        None,
        "running decoded as a final state"
    );
    true
}
