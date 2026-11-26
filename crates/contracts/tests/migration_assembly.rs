//! P01 slice 2a: the inventory is built from a worker report and an operator declaration.

use rustiron_contracts::migration::{
    ExportObservation, ExportReason, ExportStatus, Field, MigrationRequest, Refusal, TargetProfile,
    TargetState, assemble_inventory, decode_export_observation, decode_operator_declaration,
    plan_migration, render_dry_run,
};
use serde_json::{Value, json};

const DIGEST: &str = "4b3e1d0c9a8f7e6d5c4b3a291807f6e5d4c3b2a1908f7e6d5c4b3a2918070605";

fn observation() -> Value {
    json!({
        "schema_version": 1,
        "status": "complete",
        "reason": null,
        "hostname": "blog.example.test",
        "aliases": [],
        "child_domains": 0,
        "files": {"entries": 10, "bytes": 1000, "manifest_sha256": DIGEST, "unsafe_entries": 0},
        "uploads": {"files": 2, "bytes": 100},
        "databases": [{"bytes": 500, "charset": "utf8mb4", "collation": "utf8mb4_unicode_ci"}],
        "php_version": "8.2",
        "site_url": "https://blog.example.test",
        "home_url": "https://blog.example.test",
        "tls": "none",
        "credentials": {"database_users": 1, "panel_users": 1, "api_tokens": 0},
        "dns_records": 4,
        "mail_accounts": 0
    })
}

fn declaration() -> Value {
    json!({
        "schema_version": 1,
        "source_profile": {"os": "AlmaLinux 9.6", "panel": "CyberPanel 2.4", "web_server": "OpenLiteSpeed 1.8"},
        "hostname": "blog.example.test",
        "php_extensions": ["mysqli"],
        "cron_entries": 0,
        "dns": {"authority": "registrar DNS", "addresses": ["192.0.2.10"]},
        "mail": {"mx": 0, "spf": false, "dkim": false, "dmarc": false, "outbound": "none"},
        "api_consumers": 0
    })
}

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn plan(observation: &Value, declaration: &Value) -> Result<String, Vec<Refusal>> {
    let observation = decode_export_observation(&bytes(observation)).unwrap();
    let declaration = decode_operator_declaration(&bytes(declaration)).unwrap();
    let inventory = assemble_inventory(&observation, &declaration).unwrap();
    let request: MigrationRequest =
        serde_json::from_value(json!({"site_id": "blog", "target_php": "8.2"})).unwrap();
    let profile: TargetProfile =
        serde_json::from_value(json!({"php_versions": ["8.2"], "php_extensions": ["mysqli"]}))
            .unwrap();
    let state: TargetState = serde_json::from_value(
        json!({"site_ids": [], "hostnames": [], "accounts": [], "databases": []}),
    )
    .unwrap();
    plan_migration(&inventory, &request, &profile, &state).map(|plan| render_dry_run(&plan))
}

#[test]
fn a_complete_report_and_declaration_plan_a_move() {
    let text = plan(&observation(), &declaration()).unwrap();
    assert!(text.contains("TLS: none on the source."), "{text}");
}

#[test]
fn each_source_holds_only_its_own_fields() {
    let mut value = observation();
    value["php_extensions"] = json!(["mysqli"]);
    assert!(decode_export_observation(&bytes(&value)).is_err());
    let mut value = observation();
    value["source_profile"] = json!(null);
    assert!(decode_export_observation(&bytes(&value)).is_err());

    let mut value = declaration();
    value["files"] = observation()["files"].clone();
    assert!(decode_operator_declaration(&bytes(&value)).is_err());
    let mut value = declaration();
    value["php_version"] = json!("8.2");
    assert!(decode_operator_declaration(&bytes(&value)).is_err());
}

#[test]
fn a_missing_member_refuses_and_null_means_unknown() {
    let mut value = observation();
    value.as_object_mut().unwrap().remove("hostname");
    assert!(decode_export_observation(&bytes(&value)).is_err());
    let mut value = declaration();
    value.as_object_mut().unwrap().remove("cron_entries");
    assert!(decode_operator_declaration(&bytes(&value)).is_err());

    let mut value = observation();
    value["hostname"] = json!(null);
    let mut declared = declaration();
    declared["cron_entries"] = json!(null);
    let found = plan(&value, &declared).unwrap_err();
    assert!(
        found.contains(&Refusal::Unknown(Field::Hostname)),
        "{found:?}"
    );
    assert!(
        found.contains(&Refusal::Unknown(Field::CronEntries)),
        "{found:?}"
    );
}

#[test]
fn a_stopped_report_observes_nothing() {
    let stopped = ExportObservation::stopped(ExportStatus::Limit, ExportReason::Entries);
    let value = serde_json::to_value(&stopped).unwrap();
    let found = plan(&value, &declaration()).unwrap_err();
    for field in [
        Field::Hostname,
        Field::Files,
        Field::Databases,
        Field::MailAccounts,
    ] {
        assert!(
            found.contains(&Refusal::Unknown(field)),
            "{field:?}: {found:?}"
        );
    }

    let mut value = serde_json::to_value(&stopped).unwrap();
    value["dns_records"] = json!(4);
    assert!(
        decode_export_observation(&bytes(&value)).is_err(),
        "a stopped report with a value"
    );

    let mut value = serde_json::to_value(&stopped).unwrap();
    value["status"] = json!("error");
    assert!(
        decode_export_observation(&bytes(&value)).is_err(),
        "a limit reason on an error"
    );

    let mut value = serde_json::to_value(&stopped).unwrap();
    value["reason"] = json!(null);
    assert!(
        decode_export_observation(&bytes(&value)).is_err(),
        "a stop without a reason"
    );

    let mut value = observation();
    value["reason"] = json!("io");
    assert!(
        decode_export_observation(&bytes(&value)).is_err(),
        "a complete report with a reason"
    );
}

#[test]
fn assembly_keeps_the_inventory_bounds() {
    let mut value = observation();
    value["aliases"] = json!(vec!["a.example.test"; 65]);
    let observation = decode_export_observation(&bytes(&value)).unwrap();
    let declaration = decode_operator_declaration(&bytes(&declaration())).unwrap();
    assert!(assemble_inventory(&observation, &declaration).is_err());
}

#[test]
fn a_tree_report_is_closed_and_consistent() {
    use rustiron_contracts::migration::decode_tree_report;
    let files = observation()["files"].clone();
    let good = json!({"schema_version": 1, "status": "complete", "reason": null, "files": files});
    assert!(decode_tree_report(&bytes(&good)).is_ok());
    for bad in [
        json!({"schema_version": 1, "status": "complete", "reason": "io", "files": files}),
        json!({"schema_version": 1, "status": "complete", "reason": null, "files": null}),
        json!({"schema_version": 1, "status": "error", "reason": "io", "files": files}),
        json!({"schema_version": 1, "status": "error", "reason": "time", "files": null}),
        json!({"schema_version": 1, "status": "limit", "reason": "io", "files": null}),
        json!({"schema_version": 1, "status": "complete", "reason": null, "files": files, "hostname": null}),
        json!({"schema_version": 1, "status": "complete", "files": files}),
    ] {
        assert!(decode_tree_report(&bytes(&bad)).is_err(), "{bad}");
    }
    let stopped =
        json!({"schema_version": 1, "status": "limit", "reason": "entries", "files": null});
    assert!(decode_tree_report(&bytes(&stopped)).is_ok());
}
