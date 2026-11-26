//! Read-side public contract and adversarial JSON regressions, not socket/host proof.

use rustiron_contracts::*;

const DOCTOR: &str = include_str!("fixtures/doctor-request.json");
const DOCTOR_RESPONSE: &str = include_str!("fixtures/doctor-response.json");

#[test]
fn operation_status_contract_is_closed_and_requires_named_results() {
    let request = br#"{"schema_version":1,"request_id":"r-1","method":"operation_status","params":{"operation_id":"op-1"}}"#;
    assert_eq!(
        encode_request(&decode_request(request).unwrap()).unwrap(),
        request
    );
    for invalid in [
        br#"{"schema_version":1,"request_id":"r-1","method":"operation_status","params":{"operation_id":"op-1","path":"/tmp"}}"#.as_slice(),
        br#"{"schema_version":1,"request_id":"r-1","method":"operation_status","params":["op-1"]}"#.as_slice(),
    ] {
        assert!(decode_request(invalid).is_err());
    }
    let response = br#"{"schema_version":1,"request_id":"r-1","status":"ok","data":{"kind":"operation_status","value":{"operation_id":"op-1","state":"intent"}},"error":null}"#;
    let parsed = decode_response(response).unwrap();
    assert_eq!(encode_response(&parsed).unwrap(), response);
    let array = br#"{"schema_version":1,"request_id":"r-1","status":"ok","data":{"kind":"operation_status","value":["op-1","intent"]},"error":null}"#;
    assert!(decode_response(array).is_err());
}

#[test]
fn all_read_requests_round_trip_against_goldens() {
    for fixture in [
        DOCTOR,
        include_str!("fixtures/list-request.json"),
        include_str!("fixtures/inspect-request.json"),
    ] {
        let request = decode_request(fixture.as_bytes()).expect("golden request is valid");
        assert_eq!(
            encode_request(&request).unwrap(),
            fixture.trim_end().as_bytes()
        );
    }
}

#[test]
fn success_and_error_responses_round_trip_against_goldens() {
    for fixture in [
        DOCTOR_RESPONSE,
        include_str!("fixtures/error-response.json"),
    ] {
        let response = decode_response(fixture.as_bytes()).unwrap();
        assert_eq!(
            encode_response(&response).unwrap(),
            fixture.trim_end().as_bytes()
        );
    }
}

#[test]
fn human_doctor_golden_preserves_evidence_states() {
    let response = decode_response(DOCTOR_RESPONSE.as_bytes()).unwrap();
    assert_eq!(
        render_human(&response).unwrap(),
        include_str!("fixtures/doctor-response.txt")
    );
}

#[test]
fn older_doctor_responses_leave_new_acceptance_fields_unknown() {
    let mut wire: serde_json::Value = serde_json::from_str(DOCTOR_RESPONSE).unwrap();
    let report = wire["data"]["value"].as_object_mut().unwrap();
    report.remove("hosting_profile");
    report.remove("site_confinement");
    let response = decode_response(&serde_json::to_vec(&wire).unwrap()).unwrap();
    let Ok(ReadData::Doctor(report)) = response.result else {
        panic!("expected doctor");
    };
    assert_eq!(
        report.hosting_profile,
        Observation::Unknown {
            reason: UnknownReason::NotChecked
        }
    );
    assert_eq!(
        report.site_confinement,
        Observation::Unknown {
            reason: UnknownReason::NotChecked
        }
    );
}

#[test]
fn rejects_unknown_request_members_and_methods() {
    for input in [
        DOCTOR.replace("\"params\":{}", "\"params\":{},\"root\":true"),
        DOCTOR.replace("\"params\":{}", "\"params\":{\"root\":true}"),
        DOCTOR.replace("doctor", "plan_apply"),
        DOCTOR.replace("doctor", "run_shell"),
        include_str!("fixtures/list-request.json")
            .replace("\"limit\":20", "\"limit\":20,\"path\":\"/etc\""),
    ] {
        assert!(
            decode_request(input.as_bytes()).is_err(),
            "unexpected acceptance: {input}"
        );
    }
}

#[test]
fn requires_object_envelopes_and_parameter_objects() {
    assert!(decode_request(br#"[1,"r-1","doctor",{}]"#).is_err());
    for params in ["[]", "null", "true", "1", "\"text\""] {
        let input = DOCTOR.replace("\"params\":{}", &format!("\"params\":{params}"));
        assert!(decode_request(input.as_bytes()).is_err());
    }
}

#[test]
fn rejects_duplicates_in_envelopes_params_and_decoded_key_aliases() {
    for input in [
        DOCTOR.replace(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
        ),
        DOCTOR.replace(
            "\"method\":\"doctor\"",
            r#""method":"doctor","\u006dethod":"doctor""#,
        ),
        include_str!("fixtures/list-request.json")
            .replace("\"limit\":20", "\"limit\":20,\"limit\":20"),
    ] {
        assert_eq!(
            decode_request(input.as_bytes()),
            Err(ProtocolError::InvalidMessage)
        );
    }
}

#[test]
fn validates_version_without_float_coercion_or_fallback() {
    assert_eq!(
        decode_request(
            DOCTOR
                .replace("\"schema_version\":1", "\"schema_version\":2")
                .as_bytes()
        ),
        Err(ProtocolError::UnsupportedVersion)
    );
    for version in ["-1", "1.0", "1e0", "65536", "\"1\"", "null"] {
        assert!(
            decode_request(
                DOCTOR
                    .replace(
                        "\"schema_version\":1",
                        &format!("\"schema_version\":{version}")
                    )
                    .as_bytes()
            )
            .is_err()
        );
    }
}

#[test]
fn enforces_byte_limits_before_json_parsing() {
    let mut exact = DOCTOR.trim_end().as_bytes().to_vec();
    exact.resize(MAX_REQUEST_BYTES, b' ');
    assert!(decode_request(&exact).is_ok());
    exact.push(b' ');
    assert_eq!(decode_request(&exact), Err(ProtocolError::RequestTooLarge));
    assert_eq!(
        decode_response(&vec![b' '; MAX_RESPONSE_BYTES + 1]),
        Err(ProtocolError::ResponseTooLarge)
    );
}

#[test]
fn rejects_excessive_nesting_and_allows_bounded_response_extensions() {
    let shallow = DOCTOR_RESPONSE
        .trim_end()
        .strip_suffix('}')
        .unwrap()
        .to_owned()
        + ",\"extension\":{\"items\":[1,true,null,\"x\"]}}";
    assert!(decode_response(shallow.as_bytes()).is_ok());
    let at_limit = format!(
        "{},\"extension\":{}0{}}}",
        DOCTOR_RESPONSE.trim_end().strip_suffix('}').unwrap(),
        "[".repeat(MAX_JSON_DEPTH - 1),
        "]".repeat(MAX_JSON_DEPTH - 1)
    );
    assert!(decode_response(at_limit.as_bytes()).is_ok());
    let deep = format!(
        "{},\"extension\":{}0{}}}",
        DOCTOR_RESPONSE.trim_end().strip_suffix('}').unwrap(),
        "[".repeat(MAX_JSON_DEPTH),
        "]".repeat(MAX_JSON_DEPTH)
    );
    assert!(decode_response(deep.as_bytes()).is_err());
    let duplicate = shallow.replace("\"items\":[1,true,null,\"x\"]", "\"items\":1,\"items\":2");
    assert!(decode_response(duplicate.as_bytes()).is_err());
}

#[test]
fn rejects_trailing_data_truncation_empty_and_invalid_utf8() {
    for input in [
        b"".as_slice(),
        b"{}",
        b"null",
        b"\xff",
        &DOCTOR.as_bytes()[..DOCTOR.len() - 3],
    ] {
        assert!(decode_request(input).is_err());
    }
    assert!(decode_request(format!("{DOCTOR}{{}}").as_bytes()).is_err());
}

#[test]
fn validates_opaque_identifiers_limits_and_exact_timestamps() {
    for id in ["", "..", "site/a", "site a", "é", "a\u{001b}"] {
        assert!(Id::try_from(id.to_owned()).is_err());
    }
    assert!(Id::try_from("x".repeat(64)).is_ok());
    assert!(Id::try_from("x".repeat(65)).is_err());
    assert!(PageLimit::try_from(1).is_ok());
    assert!(PageLimit::try_from(100).is_ok());
    for limit in [0, 101, u16::MAX] {
        assert!(PageLimit::try_from(limit).is_err());
    }
    assert!(Timestamp::try_from((1_u64 << 53) - 1).is_ok());
    assert!(Timestamp::try_from(1_u64 << 53).is_err());
    assert!(Text::try_from("é".repeat(256)).is_ok());
    assert!(Text::try_from("é".repeat(257)).is_err());
}

#[test]
fn wire_values_cannot_bypass_validated_primitive_bounds() {
    let list = include_str!("fixtures/list-request.json");
    for limit in ["0", "101", "1.0", "-1", "\"20\""] {
        assert!(
            decode_request(
                list.replace("\"limit\":20", &format!("\"limit\":{limit}"))
                    .as_bytes()
            )
            .is_err()
        );
    }
    let mut response: serde_json::Value = serde_json::from_str(DOCTOR_RESPONSE).unwrap();
    response["data"]["value"]["os_name"]["observed_at"] = serde_json::json!(1_u64 << 53);
    assert!(decode_response(&serde_json::to_vec(&response).unwrap()).is_err());
    response["data"]["value"]["os_name"]["observed_at"] = serde_json::json!(1);
    response["data"]["value"]["os_name"]["value"] = serde_json::json!("x".repeat(513));
    assert!(decode_response(&serde_json::to_vec(&response).unwrap()).is_err());
}

#[test]
fn read_error_requires_explicit_null_operation_id() {
    let bytes = br#"{"schema_version":1,"request_id":null,"status":"error","data":null,"error":{"code":"INVALID_REQUEST","message":"Invalid request","retryable":false,"details":[]}}"#;
    assert_eq!(decode_response(bytes), Err(ProtocolError::InvalidMessage));
}

#[test]
fn read_errors_reject_unbounded_details_and_operation_authority() {
    let fixture = include_str!("fixtures/error-response.json");
    let mut response: serde_json::Value = serde_json::from_str(fixture).unwrap();
    response["error"]["details"] = serde_json::json!(vec!["bounded"; 8]);
    assert!(decode_response(&serde_json::to_vec(&response).unwrap()).is_ok());
    response["error"]["details"] = serde_json::json!(vec!["bounded"; 9]);
    assert!(decode_response(&serde_json::to_vec(&response).unwrap()).is_err());
    response["error"]["details"] = serde_json::json!([]);
    response["error"]["operation_id"] = serde_json::json!("op-1");
    assert!(decode_response(&serde_json::to_vec(&response).unwrap()).is_err());
}

#[test]
fn rejects_response_status_slot_mismatches_and_missing_correlation() {
    for response in [
        DOCTOR_RESPONSE.replace("\"status\":\"ok\"", "\"status\":\"error\""),
        DOCTOR_RESPONSE.replace("\"request_id\":\"r-1\"", "\"request_id\":null"),
        DOCTOR_RESPONSE.replace("\"error\":null", "\"error\":{}"),
        DOCTOR_RESPONSE.replace(",\"error\":null", ""),
        DOCTOR_RESPONSE.replace("\"error\":null", "\"error\":null,\"error\":null"),
    ] {
        assert!(decode_response(response.as_bytes()).is_err());
    }
}

#[test]
fn does_not_accept_positional_arrays_for_named_response_records() {
    let mut response: serde_json::Value = serde_json::from_str(DOCTOR_RESPONSE).unwrap();
    let report = response["data"]["value"].take();
    response["data"]["value"] = serde_json::json!([
        report["os_name"],
        report["os_version"],
        report["kernel_release"],
        report["architecture"]
    ]);
    assert!(decode_response(&serde_json::to_vec(&response).unwrap()).is_err());
    let page = br#"{"schema_version":1,"request_id":"r-1","status":"ok","data":{"kind":"site_list","value":{"items":[["s-1","Name","unknown"]],"next_cursor":null}},"error":null}"#;
    assert!(decode_response(page).is_err());
}

#[test]
fn preserves_page_end_empty_inventory_and_unknown_ownership() {
    let response = Response {
        request_id: Some(Id::try_from("r-1".to_owned()).unwrap()),
        result: Ok(ReadData::SiteList(SitePage {
            items: Vec::new(),
            next_cursor: None,
        })),
    };
    assert_eq!(
        decode_response(&encode_response(&response).unwrap()).unwrap(),
        response
    );
    assert_eq!(
        render_human(&response).unwrap(),
        "Sites: 0 record(s)\nEnd of list\n"
    );
    let site = SiteSummary {
        site_id: Id::try_from("s-1".to_owned()).unwrap(),
        name: Text::try_from("Example".to_owned()).unwrap(),
        ownership: Ownership::Unknown,
        inventory: None,
    };
    let too_many = Response {
        result: Ok(ReadData::SiteList(SitePage {
            items: vec![site; 101],
            next_cursor: None,
        })),
        ..response
    };
    assert_eq!(
        encode_response(&too_many),
        Err(ProtocolError::InvalidMessage)
    );
    assert_eq!(render_human(&too_many), Err(ProtocolError::InvalidMessage));
    let mut wire = serde_json::json!({
        "schema_version": 1, "request_id": "r-1", "status": "ok", "error": null,
        "data": {"kind": "site_list", "value": {"items": [], "next_cursor": null}}
    });
    let mut missing_cursor = wire.clone();
    missing_cursor["data"]["value"]
        .as_object_mut()
        .unwrap()
        .remove("next_cursor");
    assert!(decode_response(&serde_json::to_vec(&missing_cursor).unwrap()).is_err());
    if let Ok(ReadData::SiteList(page)) = too_many.result {
        wire["data"]["value"]["items"] = serde_json::to_value(page.items).unwrap();
    }
    assert!(decode_response(&serde_json::to_vec(&wire).unwrap()).is_err());
}

#[test]
fn escapes_terminal_control_and_bidi_data_without_corrupting_unicode() {
    let escaped = escape_human("Équipe\u{001b}[31m\n\r\t\u{202e}fake");
    assert!(escaped.starts_with("Équipe"));
    assert!(!escaped.chars().any(char::is_control));
    assert!(!escaped.contains('\u{202e}'));
    assert!(escaped.contains("\\n"));
    let mut wire: serde_json::Value = serde_json::from_str(DOCTOR_RESPONSE).unwrap();
    wire["data"]["value"]["os_name"]["value"] =
        serde_json::json!("Équipe\u{001b}[31m\n\u{202e}fake");
    let response = decode_response(&serde_json::to_vec(&wire).unwrap()).unwrap();
    let human = render_human(&response).unwrap();
    assert!(human.contains(&escape_human("Équipe\u{001b}[31m\n\u{202e}fake")));
    assert!(!human.contains('\u{001b}'));
    assert!(!human.contains('\u{202e}'));
}

/// W420 (T13): a receipt carries restored-site text, such as the probe's page
/// title. The human evidence output escapes bidirectional formatting and the
/// controls that JSON keeps raw (DEL and C1), so restored text cannot reorder
/// or restyle the operator's terminal line.
#[test]
fn human_evidence_export_escapes_restored_text() {
    let hostile = "W420 \u{202e}deliaf\u{2066} title\u{009b}31m\u{007f}";
    let wire = serde_json::json!({
        "schema_version": 1, "request_id": "query_1", "status": "ok",
        "data": {"kind": "evidence_export", "value": {"operation_id": "operation_1", "receipt": {
            "body": {"receipt_schema": "rustiron-recovery-receipt/1",
                     "fields": {"health_checks_passed": {"observed": {"home_title": hostile}}}},
            "body_sha256": "ab".repeat(32),
        }}},
        "error": null,
    });
    let response = decode_response(&serde_json::to_vec(&wire).unwrap()).unwrap();
    let human = render_human(&response).unwrap();
    for raw in ['\u{202e}', '\u{2066}', '\u{009b}', '\u{007f}'] {
        assert!(!human.contains(raw), "raw {raw:?} reached the human output");
    }
    assert!(human.contains("W420 \\u{202e}deliaf\\u{2066} title"));
    assert!(human.contains("Self-attested receipt. Not independent proof."));
}

#[test]
fn parser_errors_do_not_reflect_canary_input_into_diagnostics() {
    let canary = "CANARY_NOT_A_SECRET_abcdef";
    let input = DOCTOR.replace(
        "\"params\":{}",
        &format!("\"params\":{{\"{canary}\":\"{canary}\"}}"),
    );
    let failure = decode_request(input.as_bytes()).unwrap_err();
    let response = Response {
        request_id: None,
        result: Err(failure.api_error()),
    };
    let json = String::from_utf8(encode_response(&response).unwrap()).unwrap();
    assert!(!json.contains(canary));
    assert!(!render_human(&response).unwrap().contains(canary));
    assert!(!failure.to_string().contains(canary));
}

#[test]
fn error_codes_have_stable_exit_classes() {
    for code in [
        ErrorCode::InvalidRequest,
        ErrorCode::UnsupportedVersion,
        ErrorCode::RequestTooLarge,
        ErrorCode::ResponseTooLarge,
    ] {
        assert_eq!(code.exit_code(), 2);
    }
    assert_eq!(ErrorCode::UnauthorizedPeer.exit_code(), 3);
    assert_eq!(ErrorCode::NotFound.exit_code(), 4);
    assert_eq!(ErrorCode::CursorExpired.exit_code(), 4);
    assert_eq!(ErrorCode::DependencyUnavailable.exit_code(), 7);
}
