//! Deterministic raw envelopes; construction deliberately preserves lexical bytes.

use rustiron_contracts::{MAX_JSON_DEPTH, MAX_REQUEST_BYTES, execution::MAX_SIGNATURE_TEXT};

fn envelope(apply: bool, plan: &str, grant: &str, signature: &str) -> Vec<u8> {
    let signature = serde_json::to_string(signature).unwrap();
    let fields = format!(
        r#""operation_id":"operation_1","idempotency_key":"retry_1","plan":{plan},"grant":{grant},"signature":{signature}"#
    );
    if apply {
        format!(r#"{{"schema_version":1,"request_id":"request_1","method":"plan_apply","params":{{{fields}}}}}"#).into_bytes()
    } else {
        format!(r#"{{"schema_version":1,{fields}}}"#).into_bytes()
    }
}

pub(super) fn generate(seed: &mut impl FnMut(&str, &str, &[u8], bool)) {
    for (target, apply) in [("submission", false), ("apply_request", true)] {
        for (name, plan, grant) in super::FIXTURES {
            let plan = std::str::from_utf8(plan).unwrap().trim();
            let grant = std::str::from_utf8(grant).unwrap().trim();
            seed(
                target,
                name,
                &envelope(apply, plan, grant, "synthetic_signature"),
                true,
            );
        }
        for (name, plan, grant) in [
            ("empty-objects", "{}", "{}"),
            (
                "raw-spellings",
                r#"{ "z":1e0, "a":"\u0061", "nested":[{"num":-0,"float":1.50}] }"#,
                r#"{"\u0069ssuer" : "fixture", "list" : [3,2,1]}"#,
            ),
            (
                "unicode-order",
                r#"{"\ud83d\ude00":"é","z":0,"a":null}"#,
                r#"{ "\u20ac":"€" }"#,
            ),
        ] {
            seed(target, name, &envelope(apply, plan, grant, ""), true);
        }
        let base = envelope(
            apply,
            r#"{"x": 1}"#,
            r#"{"g": true}"#,
            "synthetic_signature",
        );
        seed(
            target,
            "signature-limit",
            &envelope(apply, "{}", "{}", &"s".repeat(MAX_SIGNATURE_TEXT)),
            true,
        );
        seed(
            target,
            "signature-over-limit",
            &envelope(apply, "{}", "{}", &"s".repeat(MAX_SIGNATURE_TEXT + 1)),
            false,
        );
        seed(
            target,
            "signature-non-ascii",
            &envelope(apply, "{}", "{}", "é"),
            false,
        );
        seed(
            target,
            "signature-escaped-ascii",
            &envelope(apply, "{}", "{}", "\n\0\t\u{7f}\\\""),
            true,
        );
        let mut spaced = b" \n".to_vec();
        spaced.extend_from_slice(&base);
        spaced.extend_from_slice(b"\t ");
        seed(target, "outer-whitespace", &spaced, true);
        let empty = envelope(apply, r#"{"pad":""}"#, "{}", "s");
        let padding = "x".repeat(MAX_REQUEST_BYTES - empty.len());
        let exact = envelope(apply, &format!(r#"{{"pad":"{padding}"}}"#), "{}", "s");
        assert_eq!(exact.len(), MAX_REQUEST_BYTES);
        seed(target, "exact-size", &exact, true);
        let mut over = exact;
        over.push(b' ');
        seed(target, "over-size", &over, false);
        let arrays = MAX_JSON_DEPTH - if apply { 3 } else { 2 };
        for (name, count, accepted) in [
            ("exact-depth", arrays, true),
            ("over-depth", arrays + 1, false),
        ] {
            let plan = format!(
                r#"{{"nested":{}0{}}}"#,
                "[".repeat(count),
                "]".repeat(count)
            );
            seed(target, name, &envelope(apply, &plan, "{}", "s"), accepted);
        }
        for (name, plan, grant) in [
            ("plan-array", "[]", "{}"),
            ("grant-null", "{}", "null"),
            ("nested-duplicate", r#"{"a":[{"dup":1,"dup":2}]}"#, "{}"),
            ("escaped-duplicate", r#"{"dup":1,"du\u0070":2}"#, "{}"),
            ("lone-surrogate", r#"{"x":"\ud800"}"#, "{}"),
        ] {
            seed(target, name, &envelope(apply, plan, grant, "s"), false);
        }
        for (name, prefix) in [
            ("duplicate-envelope", br#"{"schema_version":1,"#.as_slice()),
            (
                "duplicate-escaped-envelope",
                br#"{"sch\u0065ma_version":1,"#,
            ),
            ("unknown-envelope", br#"{"future":true,"#),
        ] {
            let mut bytes = prefix.to_vec();
            bytes.extend_from_slice(&base[1..]);
            seed(target, name, &bytes, false);
        }
        let text = std::str::from_utf8(&base).unwrap();
        for (name, old, new) in [
            (
                "unsupported-version",
                "\"schema_version\":1",
                "\"schema_version\":2",
            ),
            ("invalid-operation-id", "operation_1", "../outside"),
            ("missing-grant", "\"grant\":", "\"not_grant\":"),
        ] {
            seed(target, name, text.replace(old, new).as_bytes(), false);
        }
        let mut trailing = base.clone();
        trailing.extend_from_slice(b"{}");
        seed(target, "trailing-object", &trailing, false);
        if apply {
            for (name, old, new) in [
                (
                    "unknown-parameter",
                    "\"params\":{",
                    "\"params\":{\"future\":true,",
                ),
                (
                    "duplicate-parameter",
                    "\"params\":{",
                    "\"params\":{\"signature\":\"s\",",
                ),
                ("wrong-method", "plan_apply", "doctor"),
            ] {
                seed(target, name, text.replace(old, new).as_bytes(), false);
            }
            let mut positional: serde_json::Value = serde_json::from_slice(&base).unwrap();
            positional["params"] = serde_json::json!([positional["params"]]);
            seed(
                target,
                "positional-params",
                &serde_json::to_vec(&positional).unwrap(),
                false,
            );
        }
        for (name, bytes) in [
            ("empty", b"".as_slice()),
            ("array-root", b"[]"),
            ("invalid-utf8", b"{\"x\":\"\xff\"}"),
        ] {
            seed(target, name, bytes, false);
        }
    }
}
