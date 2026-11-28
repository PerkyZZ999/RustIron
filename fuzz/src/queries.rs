//! Closed read/query codecs and a deliberately partial correlation header.

use rustiron_contracts::execution::{
    decode_evidence_query, decode_status_query, encode_evidence_query, encode_status_query,
    status_query_request_id,
};
use rustiron_contracts::{
    Id, MAX_JSON_DEPTH, MAX_REQUEST_BYTES, ProtocolError, ReadCommand, decode_request,
    encode_request,
};
use serde_json::{Value, json};

const MAX_ID_BYTES: usize = 64;

fn id_matches(value: &Value, id: &Id) {
    assert_eq!(value.as_str(), Some(id.as_str()), "query identity changed");
    assert!(!id.as_str().is_empty() && id.as_str().len() <= MAX_ID_BYTES);
    assert!(
        id.as_str()
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    );
}

fn fields(value: &Value, expected: &[&str]) {
    let object = value.as_object().expect("query record must be named");
    assert_eq!(object.len(), expected.len(), "closed query fields expanded");
    assert!(expected.iter().all(|key| object.contains_key(*key)));
}

fn refuse(value: &Value, accepts: &impl Fn(&[u8]) -> bool, reason: &str) {
    let bytes = serde_json::to_vec(value).unwrap();
    if bytes.len() <= MAX_REQUEST_BYTES {
        assert!(!accepts(&bytes), "{reason}");
    }
}

fn controls(input: &[u8], value: &Value, accepts: impl Fn(&[u8]) -> bool) {
    for (field, replacement, reason) in [
        (
            "schema_version",
            json!(2),
            "unsupported query version accepted",
        ),
        (
            "fuzz_unknown",
            json!(true),
            "unknown query envelope field accepted",
        ),
        ("params", json!([]), "positional query parameters accepted"),
        (
            "request_id",
            json!("x".repeat(MAX_ID_BYTES + 1)),
            "overlong query identity accepted",
        ),
    ] {
        let mut changed = value.clone();
        changed[field] = replacement;
        refuse(&changed, &accepts, reason);
    }
    for field in ["schema_version", "request_id", "method", "params"] {
        let mut changed = value.clone();
        changed.as_object_mut().unwrap().remove(field);
        refuse(
            &changed,
            &accepts,
            "missing required query envelope field accepted",
        );
    }
    let mut changed = value.clone();
    changed["params"]["fuzz_unknown"] = json!(true);
    refuse(&changed, &accepts, "unknown query parameter accepted");
    let mut positional = value.clone();
    positional["params"] = Value::Array(
        value["params"]
            .as_object()
            .unwrap()
            .values()
            .cloned()
            .collect(),
    );
    refuse(&positional, &accepts, "positional query record accepted");
    let mut duplicate = br#"{"req\u0075est_id":"duplicate","#.to_vec();
    duplicate.extend_from_slice(&input.trim_ascii_start()[1..]);
    if duplicate.len() <= MAX_REQUEST_BYTES {
        assert!(!accepts(&duplicate), "duplicate query envelope accepted");
    }
}

fn shape(value: &Value, request_id: &Id) {
    fields(value, &["schema_version", "request_id", "method", "params"]);
    assert_eq!(value["schema_version"], json!(1));
    id_matches(&value["request_id"], request_id);
}

fn header_properties(input: &[u8]) {
    let decoded = status_query_request_id(input);
    if input.len() > MAX_REQUEST_BYTES {
        assert_eq!(decoded.err(), Some(ProtocolError::RequestTooLarge));
        return;
    }
    let Ok(id) = decoded else {
        return;
    };
    let value: Value = serde_json::from_slice(input).unwrap();
    assert_eq!(value["method"], json!("operation_status"));
    id_matches(&value["request_id"], &id);
    let encoded_id = serde_json::to_string(id.as_str()).unwrap();
    // No version and invalid full-query params: correlation remains useful.
    let partial =
        format!(r#"{{"request_id":{encoded_id},"method":"operation_status","params":[]}}"#);
    assert_eq!(
        status_query_request_id(partial.as_bytes()).unwrap(),
        id,
        "partial status header rejected"
    );
    assert!(
        decode_status_query(partial.as_bytes()).is_err(),
        "partial header became a full query"
    );
    for (arrays, accepted) in [(MAX_JSON_DEPTH - 1, true), (MAX_JSON_DEPTH, false)] {
        let nested = format!(
            r#"{{"request_id":{encoded_id},"method":"operation_status","params":{}0{}}}"#,
            "[".repeat(arrays),
            "]".repeat(arrays)
        );
        assert_eq!(
            status_query_request_id(nested.as_bytes()).is_ok(),
            accepted,
            "status header depth bound changed"
        );
    }
    let duplicate = format!(
        r#"{{"request_id":{encoded_id},"method":"operation_status","params":{{"dup":0,"du\u0070":1}}}}"#
    );
    assert!(
        status_query_request_id(duplicate.as_bytes()).is_err(),
        "duplicate status header member accepted"
    );
}

/// All six read methods, including intentional omitted/null cursor equivalence.
pub fn read_request(input: &[u8]) -> bool {
    let decoded = decode_request(input);
    if input.len() > MAX_REQUEST_BYTES {
        assert_eq!(decoded.err(), Some(ProtocolError::RequestTooLarge));
        return false;
    }
    let Ok(request) = decoded else {
        return false;
    };
    let value: Value = serde_json::from_slice(input).unwrap();
    shape(&value, &request.request_id);
    let params = &value["params"];
    let method = match &request.command {
        ReadCommand::Doctor => {
            fields(params, &[]);
            "doctor"
        }
        ReadCommand::SiteList { cursor, limit } => {
            assert!(params.is_object());
            assert_eq!(
                params.as_object().unwrap().len(),
                if params.get("cursor").is_some() { 2 } else { 1 }
            );
            assert_eq!(params["limit"].as_u64(), Some(u64::from(limit.get())));
            assert!(
                (1..=100).contains(&limit.get()),
                "query page limit expanded"
            );
            match cursor {
                Some(cursor) => id_matches(&params["cursor"], cursor),
                None => assert!(params.get("cursor").is_none_or(Value::is_null)),
            }
            for cursor in [None, Some(Value::Null)] {
                let mut changed = value.clone();
                changed["params"].as_object_mut().unwrap().remove("cursor");
                if let Some(cursor) = cursor {
                    changed["params"]["cursor"] = cursor;
                }
                let decoded = decode_request(&serde_json::to_vec(&changed).unwrap())
                    .expect("omitted/null query cursor refused");
                assert_eq!(
                    decoded.command,
                    ReadCommand::SiteList {
                        cursor: None,
                        limit: *limit
                    }
                );
            }
            let mut changed = value.clone();
            changed["params"]["limit"] = json!(101);
            refuse(
                &changed,
                &|b| decode_request(b).is_ok(),
                "query page expansion accepted",
            );
            "site_list"
        }
        ReadCommand::SiteInspect { site_id } => {
            fields(params, &["site_id"]);
            id_matches(&params["site_id"], site_id);
            "site_inspect"
        }
        ReadCommand::OperationStatus { operation_id } => {
            fields(params, &["operation_id"]);
            id_matches(&params["operation_id"], operation_id);
            let query = decode_status_query(input).expect("read/status query disagreement");
            assert_eq!(query.request_id, request.request_id);
            assert_eq!(&query.operation_id, operation_id);
            "operation_status"
        }
        ReadCommand::EvidenceExport { operation_id } => {
            fields(params, &["operation_id"]);
            id_matches(&params["operation_id"], operation_id);
            let query = decode_evidence_query(input).expect("read/evidence query disagreement");
            assert_eq!(query.request_id, request.request_id);
            assert_eq!(&query.operation_id, operation_id);
            "evidence_export"
        }
        // D-104 (W779): the read request and the executor query share one shape.
        ReadCommand::HostSummary => {
            fields(params, &[]);
            let query = rustiron_contracts::summary::decode_host_summary_query(input)
                .expect("read/host summary query disagreement");
            assert_eq!(query.request_id, request.request_id);
            "host_summary"
        }
    };
    assert_eq!(
        value["method"].as_str(),
        Some(method),
        "query method changed"
    );
    assert_eq!(
        decode_request(&encode_request(&request).unwrap()).unwrap(),
        request
    );
    controls(input, &value, |bytes| decode_request(bytes).is_ok());
    true
}

/// Full executor status query plus separately checked partial header extraction.
pub fn status_query(input: &[u8]) -> bool {
    header_properties(input);
    let decoded = decode_status_query(input);
    if input.len() > MAX_REQUEST_BYTES {
        assert_eq!(decoded.err(), Some(ProtocolError::RequestTooLarge));
        return false;
    }
    let Ok(query) = decoded else {
        return false;
    };
    let value: Value = serde_json::from_slice(input).unwrap();
    shape(&value, &query.request_id);
    fields(&value["params"], &["operation_id"]);
    assert_eq!(value["method"], json!("operation_status"));
    id_matches(&value["params"]["operation_id"], &query.operation_id);
    assert_eq!(
        decode_status_query(&encode_status_query(&query).unwrap()).unwrap(),
        query
    );
    assert_eq!(status_query_request_id(input).unwrap(), query.request_id);
    let read = decode_request(input).expect("status/read query disagreement");
    assert_eq!(read.request_id, query.request_id);
    assert_eq!(
        read.command,
        ReadCommand::OperationStatus {
            operation_id: query.operation_id
        }
    );
    controls(input, &value, |bytes| decode_status_query(bytes).is_ok());
    true
}

/// Closed evidence query, with no receipt generation or executor effects.
pub fn evidence_query(input: &[u8]) -> bool {
    let decoded = decode_evidence_query(input);
    if input.len() > MAX_REQUEST_BYTES {
        assert_eq!(decoded.err(), Some(ProtocolError::RequestTooLarge));
        return false;
    }
    let Ok(query) = decoded else {
        return false;
    };
    let value: Value = serde_json::from_slice(input).unwrap();
    shape(&value, &query.request_id);
    fields(&value["params"], &["operation_id"]);
    assert_eq!(value["method"], json!("evidence_export"));
    id_matches(&value["params"]["operation_id"], &query.operation_id);
    assert_eq!(
        decode_evidence_query(&encode_evidence_query(&query).unwrap()).unwrap(),
        query
    );
    let read = decode_request(input).expect("evidence/read query disagreement");
    assert_eq!(read.request_id, query.request_id);
    assert_eq!(
        read.command,
        ReadCommand::EvidenceExport {
            operation_id: query.operation_id
        }
    );
    controls(input, &value, |bytes| decode_evidence_query(bytes).is_ok());
    true
}
