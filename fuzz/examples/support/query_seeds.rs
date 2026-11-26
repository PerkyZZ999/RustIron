//! Closed query fixtures and explicit partial-header witnesses.

use rustiron_contracts::{MAX_JSON_DEPTH, MAX_REQUEST_BYTES, execution::status_query_request_id};
use serde_json::{Value, json};

fn request(method: &str, params: Value) -> Value {
    json!({"schema_version":1,"request_id":"query_1","method":method,"params":params})
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

pub(super) fn generate(seed: &mut impl FnMut(&str, &str, &[u8], bool)) -> Value {
    for (name, bytes) in [
        (
            "doctor-golden",
            include_bytes!("../../../crates/contracts/tests/fixtures/doctor-request.json")
                .as_slice(),
        ),
        (
            "list-golden",
            include_bytes!("../../../crates/contracts/tests/fixtures/list-request.json"),
        ),
        (
            "inspect-golden",
            include_bytes!("../../../crates/contracts/tests/fixtures/inspect-request.json"),
        ),
    ] {
        seed("read_request", name, bytes, true);
    }
    for (name, params) in [
        ("cursor-omitted", json!({"limit":1})),
        ("cursor-null", json!({"limit":100,"cursor":null})),
        ("cursor-token", json!({"limit":20,"cursor":"cursor_1"})),
        ("cursor-max", json!({"limit":20,"cursor":"x".repeat(64)})),
    ] {
        emit(
            seed,
            "read_request",
            name,
            &request("site_list", params),
            true,
        );
    }
    for (name, params) in [
        ("limit-zero", json!({"limit":0})),
        ("limit-over", json!({"limit":101})),
        ("limit-fraction", json!({"limit":1.0})),
        ("limit-negative", json!({"limit":-1})),
        ("limit-string", json!({"limit":"20"})),
        ("missing-limit", json!({})),
        ("cursor-empty", json!({"limit":20,"cursor":""})),
        ("cursor-path", json!({"limit":20,"cursor":"../path"})),
        ("cursor-over", json!({"limit":20,"cursor":"x".repeat(65)})),
    ] {
        emit(
            seed,
            "read_request",
            name,
            &request("site_list", params),
            false,
        );
    }
    for (name, params, accepted) in [
        ("site-id-max", json!({"site_id":"x".repeat(64)}), true),
        ("site-id-over", json!({"site_id":"x".repeat(65)}), false),
    ] {
        emit(
            seed,
            "read_request",
            name,
            &request("site_inspect", params),
            accepted,
        );
    }
    for (target, method) in [
        ("status_query", "operation_status"),
        ("evidence_query", "evidence_export"),
    ] {
        let base = request(method, json!({"operation_id":"operation_1"}));
        emit(seed, target, "valid", &base, true);
        emit(seed, "read_request", method, &base, true);
        let mut extended = base.clone();
        extended["params"]["operation_id"] = json!("x".repeat(64));
        emit(seed, target, "operation-max", &extended, true);
        extended["params"]["operation_id"] = json!("x".repeat(65));
        emit(seed, target, "operation-over", &extended, false);
        let mut positional = base.clone();
        positional["params"] = json!(["operation_1"]);
        emit(seed, target, "positional-params", &positional, false);
        let mut wrong = base.clone();
        wrong["method"] = json!(if method == "operation_status" {
            "evidence_export"
        } else {
            "operation_status"
        });
        emit(seed, target, "other-query-method", &wrong, false);
    }
    for (target, base) in [
        ("read_request", request("doctor", json!({}))),
        (
            "status_query",
            request("operation_status", json!({"operation_id":"operation_1"})),
        ),
        (
            "evidence_query",
            request("evidence_export", json!({"operation_id":"operation_1"})),
        ),
    ] {
        for (field, replacement, name) in [
            ("schema_version", json!(2), "unsupported-version"),
            ("request_id", json!("x".repeat(64)), "id-max"),
            ("request_id", json!("x".repeat(65)), "id-over"),
            ("request_id", json!(""), "id-empty"),
            ("request_id", json!("../path"), "id-path"),
            ("method", json!("unknown_method"), "unknown-method"),
            ("params", json!([]), "array-params"),
            ("params", Value::Null, "null-params"),
            ("future", json!(true), "unknown-envelope"),
        ] {
            let mut changed = base.clone();
            changed[field] = replacement;
            emit(seed, target, name, &changed, name == "id-max");
        }
        for field in ["schema_version", "request_id", "method", "params"] {
            let mut changed = base.clone();
            changed.as_object_mut().unwrap().remove(field);
            emit(seed, target, &format!("missing-{field}"), &changed, false);
        }
        let mut changed = base.clone();
        changed["params"]["future"] = json!(true);
        emit(seed, target, "unknown-parameter", &changed, false);
        let bytes = serde_json::to_vec(&base).unwrap();
        let mut duplicate = br#"{"req\u0075est_id":"duplicate","#.to_vec();
        duplicate.extend_from_slice(&bytes[1..]);
        seed(target, "escaped-duplicate", &duplicate, false);
        let mut exact = bytes.clone();
        exact.resize(MAX_REQUEST_BYTES, b' ');
        seed(target, "exact-size", &exact, true);
        exact.push(b' ');
        seed(target, "over-size", &exact, false);
        let mut trailing = bytes;
        trailing.extend_from_slice(b"{}");
        seed(target, "trailing-json", &trailing, false);
        for (name, bytes) in [
            ("empty", b"".as_slice()),
            ("array-root", b"[]"),
            ("invalid-utf8", b"{\"x\":\"\xff\"}"),
            ("lone-surrogate", br#"{"x":"\ud800"}"#),
        ] {
            seed(target, name, bytes, false);
        }
    }
    let mut witnesses = Vec::new();
    for (name,bytes,expected) in [
        ("header-only", br#"{"request_id":"header_1","method":"operation_status","params":[]}"#.to_vec(), true),
        ("header-version-two", br#"{"schema_version":2,"request_id":"header_1","method":"operation_status","params":{"operation_id":"operation_1"}}"#.to_vec(), true),
        ("header-duplicate-nested", br#"{"request_id":"header_1","method":"operation_status","params":{"a":0,"\u0061":1}}"#.to_vec(), false),
        ("header-exact-depth", depth(MAX_JSON_DEPTH-1), true),
        ("header-over-depth", depth(MAX_JSON_DEPTH), false),
    ] {
        let result = status_query_request_id(&bytes);assert_eq!(result.is_ok(),expected,"header witness {name}");
        if let Ok(id) = result {assert_eq!(id.as_str(),"header_1");}
        seed("status_query",name,&bytes,false);
        witnesses.push(json!({"name":name,"header_accepted":expected,"full_query_accepted":false}));
    }
    json!(witnesses)
}

fn depth(arrays: usize) -> Vec<u8> {
    format!(
        r#"{{"request_id":"header_1","method":"operation_status","params":{}0{}}}"#,
        "[".repeat(arrays),
        "]".repeat(arrays)
    )
    .into_bytes()
}
