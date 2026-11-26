//! Closed observation-file and rendered-provenance contracts.
use rustiron_contracts::*;

const REPORT:&[u8]=br#"{"schema_version":1,"report":{"reported_at":42,"source":"operator_report"},"complete":true,"sites":[{"site_id":"a","name":"Reported site","configuration_generation":null}]}"#;

#[test]
fn observation_file_round_trips_without_ownership_or_host_paths() {
    let snapshot = decode_inventory_snapshot(REPORT).unwrap();
    assert_eq!(encode_inventory_snapshot(&snapshot).unwrap(), REPORT);
    assert_eq!(snapshot.report.source, InventorySource::OperatorReport);
}

#[test]
fn observation_file_cannot_assert_created_ownership() {
    let input = String::from_utf8(REPORT.to_vec()).unwrap().replace(
        "\"name\":\"Reported site\"",
        "\"name\":\"Reported site\",\"ownership\":\"created\"",
    );
    assert_eq!(
        decode_inventory_snapshot(input.as_bytes()),
        Err(ProtocolError::InvalidMessage)
    );
}

#[test]
fn observation_file_rejects_duplicate_members_before_typed_decoding() {
    let input = String::from_utf8(REPORT.to_vec())
        .unwrap()
        .replace("\"complete\":true", "\"complete\":true,\"complete\":true");
    assert_eq!(
        decode_inventory_snapshot(input.as_bytes()),
        Err(ProtocolError::InvalidMessage)
    );
}

#[test]
fn human_site_text_identifies_reported_provenance_and_escapes_name() {
    let snapshot = decode_inventory_snapshot(REPORT).unwrap();
    let response = Response {
        request_id: Some(Id::try_from("r-1".to_owned()).unwrap()),
        result: Ok(ReadData::SiteList(SitePage {
            items: vec![SiteSummary {
                site_id: Id::try_from("a".to_owned()).unwrap(),
                name: Text::try_from("Name\u{001b}[31m".to_owned()).unwrap(),
                ownership: Ownership::ObservedOnly,
                inventory: Some(snapshot.report),
            }],
            next_cursor: None,
        })),
    };
    let text = render_human(&response).unwrap();
    assert!(text.contains("operator_report; unix_seconds=42"));
    assert!(!text.contains('\u{001b}'));
}

#[test]
fn response_provenance_cannot_use_positional_arrays() {
    let input=br#"{"schema_version":1,"request_id":"r-1","status":"ok","data":{"kind":"site_list","value":{"items":[{"site_id":"a","name":"A","ownership":"observed_only","inventory":[42,"operator_report"]}],"next_cursor":null}},"error":null}"#;
    assert_eq!(decode_response(input), Err(ProtocolError::InvalidMessage));
}

#[test]
fn observation_envelope_requires_named_object_fields() {
    let input = br#"[1,{"reported_at":42,"source":"operator_report"},true,[]]"#;
    assert_eq!(
        decode_inventory_snapshot(input),
        Err(ProtocolError::InvalidMessage)
    );
}

#[test]
fn observation_input_size_is_checked_before_parsing() {
    assert_eq!(
        decode_inventory_snapshot(&vec![b' '; MAX_RESPONSE_BYTES + 1]),
        Err(ProtocolError::RequestTooLarge)
    );
}

#[test]
fn response_provenance_tolerates_additive_fields() {
    let input=br#"{"schema_version":1,"request_id":"r-1","status":"ok","data":{"kind":"site_list","value":{"items":[{"site_id":"a","name":"A","ownership":"observed_only","inventory":{"reported_at":42,"source":"operator_report","collector":"future"}}],"next_cursor":null}},"error":null}"#;
    let response = decode_response(input).unwrap();
    let Ok(ReadData::SiteList(page)) = response.result else {
        panic!("expected page")
    };
    assert_eq!(
        page.items[0].inventory.as_ref().unwrap().reported_at.get(),
        42
    );
}

#[test]
fn observation_import_provenance_remains_closed() {
    let input = String::from_utf8(REPORT.to_vec()).unwrap().replace(
        "\"source\":\"operator_report\"",
        "\"source\":\"operator_report\",\"collector\":\"future\"",
    );
    assert_eq!(
        decode_inventory_snapshot(input.as_bytes()),
        Err(ProtocolError::InvalidMessage)
    );
}
