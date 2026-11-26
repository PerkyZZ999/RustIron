//! Admin-helper capture and probe payload seeds (W324). Each accepted seed is
//! the executor encoder's own output, plus each refusal class.

use rustiron_executor::ExecutorError;
use rustiron_executor::admin_helper::{decode_capture_for, encode_capture, encode_probe};
use rustiron_fuzz::{ADMIN_PAYLOAD_MAX_INPUT, RELAY_ROOT};
use rustiron_journal::ProbeState;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The encoder's output for the outcome the executor reads from `reply`.
fn encoded(reply: &Value, frozen: bool) -> String {
    encode_capture(&decode_capture_for(&reply.to_string(), RELAY_ROOT, frozen))
}

/// A canonical one-entry manifest for `path`, with its digest.
fn manifest(path: &str) -> Value {
    let text = format!(
        "{{\"path\":\"{path}\",\"kind\":\"file\",\"size\":1,\"sha256\":\"{}\",\"mode\":420}}\n",
        hex(&Sha256::digest(b"x"))
    );
    json!({"sha256": hex(&Sha256::digest(text.as_bytes())), "truncated": false, "text": text})
}

/// Pads a JSON object with an ignored member to exactly `size` bytes.
fn padded(mut value: Value, size: usize) -> Vec<u8> {
    value["padding"] = json!("");
    let filler = size - value.to_string().len();
    value["padding"] = json!("p".repeat(filler));
    let bytes = value.to_string().into_bytes();
    assert_eq!(bytes.len(), size);
    bytes
}

fn too_deep() -> String {
    format!("{{\"outcome\":{}0{}}}", "[".repeat(200), "]".repeat(200))
}

pub(super) fn generate(seed: &mut impl FnMut(&str, &str, &[u8], bool)) {
    capture(seed);
    probe(seed);
}

fn capture(seed: &mut impl FnMut(&str, &str, &[u8], bool)) {
    let id = "ab".repeat(32);
    let matched = json!({"label": "matched", "reason": null});
    let succeeded = json!({"outcome": "succeeded", "id": id, "files": 3, "bytes": 1024,
        "consistency": matched});
    let with_manifest = |manifest: Value| {
        let mut reply = succeeded.clone();
        reply["manifest"] = manifest;
        reply
    };
    let mut tampered = manifest("srv/sites/rs_blog/html/index.php");
    tampered["sha256"] = json!("0".repeat(64));
    let empty_text = "";
    let empty_manifest = json!({"sha256": hex(&Sha256::digest(empty_text.as_bytes())),
        "truncated": true, "text": empty_text});
    let unmatched = |reason: &str| {
        let mut reply = succeeded.clone();
        reply["consistency"] = json!({"label": "unmatched", "reason": reason});
        reply
    };
    let kept = encoded(
        &with_manifest(manifest("srv/sites/rs_blog/html/index.php")),
        false,
    );
    assert!(
        kept.contains("\"manifest\""),
        "the manifest seed must keep its manifest"
    );
    let mut accepted = vec![
        ("succeeded", encoded(&succeeded, false)),
        ("succeeded-frozen", encoded(&succeeded, true)),
        (
            "succeeded-no-counts",
            encoded(&json!({"outcome": "succeeded", "id": id}), false),
        ),
        (
            "database-changed",
            encoded(&unmatched("database_changed"), false),
        ),
        (
            "marker-unavailable",
            encoded(&unmatched("marker_unavailable"), false),
        ),
        (
            "freeze-not-held",
            encoded(&unmatched("freeze_not_held"), true),
        ),
        ("manifest", kept),
        (
            "empty-manifest",
            encoded(&with_manifest(empty_manifest), false),
        ),
        (
            "foreign-manifest",
            with_manifest(manifest("srv/sites/rs_other/html/index.php")).to_string(),
        ),
        ("tampered-manifest", with_manifest(tampered).to_string()),
        (
            "uppercase-id",
            encoded(
                &json!({"outcome": "succeeded", "id": "AB".repeat(32)}),
                false,
            ),
        ),
        ("unknown-label", unmatched("freeze_missed").to_string()),
        ("matched-reason", {
            let mut reply = succeeded.clone();
            reply["consistency"] = json!({"label": "matched", "reason": "x"});
            reply.to_string()
        }),
        (
            "duplicate-outcome",
            format!("{{\"outcome\":\"failed\",\"outcome\":\"succeeded\",\"id\":\"{id}\"}}"),
        ),
        (
            "uncertain-snapshot",
            encoded(
                &json!({"outcome": "uncertain", "error": ExecutorError::StepFailed.code(),
                    "snapshot": id}),
                false,
            ),
        ),
        (
            "uncertain",
            encoded(&json!({"outcome": "uncertain"}), false),
        ),
        (
            "uncertain-short-snapshot",
            json!({"outcome": "uncertain", "snapshot": "ab"}).to_string(),
        ),
        (
            "not-started-unknown-error",
            json!({"outcome": "not_started", "error": "NOPE"}).to_string(),
        ),
        (
            "not-started-wrong-type",
            json!({"outcome": "not_started", "error": 7}).to_string(),
        ),
        ("counts-wrong-type", {
            let mut reply = succeeded.clone();
            reply["files"] = json!("3");
            reply["bytes"] = json!(-1);
            reply.to_string()
        }),
    ];
    for error in [
        ExecutorError::Unavailable,
        ExecutorError::StepFailed,
        ExecutorError::Busy,
    ] {
        accepted.push((
            error.code(),
            encoded(
                &json!({"outcome": "not_started", "error": error.code()}),
                false,
            ),
        ));
    }
    for (name, bytes) in accepted {
        seed("admin_capture_payload", name, bytes.as_bytes(), true);
    }
    seed(
        "admin_capture_payload",
        "largest",
        &padded(succeeded.clone(), ADMIN_PAYLOAD_MAX_INPUT),
        true,
    );

    let line = encoded(&succeeded, false);
    for (name, bytes) in [
        ("empty", Vec::new()),
        ("not-json", b"nope".to_vec()),
        ("truncated", line.as_bytes()[..line.len() / 2].to_vec()),
        ("array", b"[]".to_vec()),
        ("null", b"null".to_vec()),
        ("no-outcome", b"{}".to_vec()),
        ("failed", br#"{"outcome":"failed"}"#.to_vec()),
        ("outcome-number", br#"{"outcome":1}"#.to_vec()),
        (
            "outcome-case",
            line.replace("\"succeeded\"", "\"Succeeded\"").into_bytes(),
        ),
        (
            "short-id",
            br#"{"outcome":"succeeded","id":"short"}"#.to_vec(),
        ),
        ("long-id", line.replace(&id, &format!("{id}a")).into_bytes()),
        (
            "non-hex-id",
            line.replace(&id, &"g".repeat(64)).into_bytes(),
        ),
        ("id-number", br#"{"outcome":"succeeded","id":7}"#.to_vec()),
        ("too-deep", too_deep().into_bytes()),
        ("lone-surrogate", br#"{"outcome":"\ud800"}"#.to_vec()),
        ("invalid-utf8", b"{\"outcome\":\"succeeded\xff\"}".to_vec()),
    ] {
        seed("admin_capture_payload", name, &bytes, false);
    }
    seed(
        "admin_capture_payload",
        "largest-unknown",
        &padded(json!({"outcome": "failed"}), ADMIN_PAYLOAD_MAX_INPUT),
        false,
    );
}

fn probe(seed: &mut impl FnMut(&str, &str, &[u8], bool)) {
    let receipt = json!({
        "receipt_schema": "rustiron-lab-restore-probe/1",
        "probe_account": "rs_probe_w324",
        "checks": {"database": "passed", "files": "passed"},
        "cleanup": {"status": "complete", "leftover_resources": 0, "removal_failures": 0,
            "unverified": []},
    });
    let refused = json!({
        "receipt_schema": "rustiron-lab-restore-probe/1",
        "probe_account": "rs_probe_w324",
        "refused": ExecutorError::HelperUnreachable.code(),
        "cleanup": {"status": "complete", "leftover_resources": 0, "removal_failures": 0,
            "unverified": []},
    });
    for (name, receipt, state) in [
        ("passed", &receipt, ProbeState::Passed),
        ("failed", &receipt, ProbeState::Failed),
        (
            "cleanup-incomplete",
            &receipt,
            ProbeState::CleanupIncomplete,
        ),
        ("refused-receipt", &refused, ProbeState::Failed),
        ("empty-receipt", &json!({}), ProbeState::Passed),
        (
            "float-receipt",
            &json!({"ratio": 0.1, "large": 1.7976931348623157e308}),
            ProbeState::Failed,
        ),
    ] {
        seed(
            "admin_probe_payload",
            name,
            encode_probe(receipt, state).as_bytes(),
            true,
        );
    }
    let mut extra: Value =
        serde_json::from_str(&encode_probe(&receipt, ProbeState::Passed)).unwrap();
    extra["unknown_member"] = json!(true);
    seed(
        "admin_probe_payload",
        "extra-member",
        extra.to_string().as_bytes(),
        true,
    );
    seed(
        "admin_probe_payload",
        "largest",
        &padded(extra, ADMIN_PAYLOAD_MAX_INPUT),
        true,
    );

    let line = encode_probe(&receipt, ProbeState::Passed);
    for (name, bytes) in [
        (
            "running",
            encode_probe(&receipt, ProbeState::Running).into_bytes(),
        ),
        ("empty", Vec::new()),
        ("not-json", b"nope".to_vec()),
        ("truncated", line.as_bytes()[..line.len() / 2].to_vec()),
        ("array", b"[]".to_vec()),
        ("no-state", br#"{"receipt":{}}"#.to_vec()),
        (
            "unknown-state",
            br#"{"state":"skipped","receipt":{}}"#.to_vec(),
        ),
        ("state-case", br#"{"state":"Passed","receipt":{}}"#.to_vec()),
        ("state-number", br#"{"state":1,"receipt":{}}"#.to_vec()),
        ("no-receipt", br#"{"state":"passed"}"#.to_vec()),
        (
            "receipt-number",
            br#"{"state":"passed","receipt":1}"#.to_vec(),
        ),
        (
            "receipt-array",
            br#"{"state":"failed","receipt":[]}"#.to_vec(),
        ),
        (
            "receipt-null",
            br#"{"state":"failed","receipt":null}"#.to_vec(),
        ),
        (
            "too-deep",
            format!(
                "{{\"state\":\"passed\",\"receipt\":{{\"a\":{}0{}}}}}",
                "[".repeat(200),
                "]".repeat(200)
            )
            .into_bytes(),
        ),
        (
            "invalid-utf8",
            b"{\"state\":\"passed\",\"receipt\":{\"a\":\"\xff\"}}".to_vec(),
        ),
    ] {
        seed("admin_probe_payload", name, &bytes, false);
    }
}
