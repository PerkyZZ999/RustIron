use super::super::inventory_report::{Reason, Status};
use super::*;
fn complete() -> serde_json::Value {
    serde_json::json!({"schema_version":3,"status":"complete","reason":null,"files":2,"dump":true,"entries":3,"max_depth":1,"world_writable":1,"extra_paths":0})
}
fn parsed(value: serde_json::Value) -> Result<Report, ExecutorError> {
    decode(&serde_json::to_vec(&value).unwrap())
}
#[test]
fn complete_report_is_accepted() {
    assert_eq!(parsed(complete()).unwrap().files, Some(2));
}
#[test]
fn limit_report_carries_no_file_claim() {
    let r=parsed(serde_json::json!({"schema_version":3,"status":"limit","reason":"entries","files":null,"dump":null,"entries":100000,"max_depth":64,"world_writable":null,"extra_paths":null})).unwrap();
    assert_eq!(r.status, Status::Limit);
    assert_eq!(r.files, None);
}
#[test]
fn error_report_carries_no_file_claim() {
    let r=parsed(serde_json::json!({"schema_version":3,"status":"error","reason":"io","files":null,"dump":null,"entries":1,"max_depth":0,"world_writable":null,"extra_paths":null})).unwrap();
    assert_eq!(r.status, Status::Error);
}
macro_rules! refused {
    ($test:ident,$key:literal,$value:expr) => {
        #[test]
        fn $test() {
            let mut v = complete();
            v[$key] = $value;
            assert_eq!(parsed(v), Err(ExecutorError::InvalidRequest));
        }
    };
}
refused!(unknown_version, "schema_version", serde_json::json!(4));
refused!(
    version_2_without_extra_paths,
    "schema_version",
    serde_json::json!(2)
);
refused!(
    more_extra_paths_than_entries,
    "extra_paths",
    serde_json::json!(2)
);
refused!(
    old_version_without_world_writable,
    "schema_version",
    serde_json::json!(1)
);
refused!(
    more_world_writable_than_files,
    "world_writable",
    serde_json::json!(3)
);
refused!(
    complete_with_unknown_world_writable,
    "world_writable",
    serde_json::Value::Null
);
refused!(unknown_field, "extra", serde_json::json!(true));
refused!(unknown_status, "status", serde_json::json!("healthy"));
refused!(over_entry_bound, "entries", serde_json::json!(100001));
refused!(over_depth_bound, "max_depth", serde_json::json!(65));
refused!(more_files_than_entries, "files", serde_json::json!(4));
refused!(
    complete_with_unknown_files,
    "files",
    serde_json::Value::Null
);
refused!(complete_with_unknown_dump, "dump", serde_json::Value::Null);
refused!(
    complete_with_error_reason,
    "reason",
    serde_json::json!("io")
);
refused!(partial_count_on_limit, "status", serde_json::json!("limit"));
macro_rules! required {
    ($test:ident,$field:literal) => {
        #[test]
        fn $test() {
            let mut v = complete();
            v.as_object_mut().unwrap().remove($field);
            assert_eq!(parsed(v), Err(ExecutorError::InvalidRequest));
        }
    };
}
required!(reason_must_be_explicit, "reason");
required!(files_must_be_explicit, "files");
required!(dump_must_be_explicit, "dump");
required!(world_writable_must_be_explicit, "world_writable");
required!(extra_paths_must_be_explicit, "extra_paths");
#[test]
fn privileged_error_is_accepted_and_claims_nothing() {
    let r=parsed(serde_json::json!({"schema_version":3,"status":"error","reason":"privileged","files":null,"dump":null,"entries":1,"max_depth":0,"world_writable":null,"extra_paths":null})).unwrap();
    assert_eq!(r.reason, Some(Reason::Privileged));
    assert_eq!(
        parsed(
            serde_json::json!({"schema_version":3,"status":"error","reason":"privileged","files":null,"dump":null,"entries":1,"max_depth":0,"world_writable":0,"extra_paths":null})
        ),
        Err(ExecutorError::InvalidRequest)
    );
}
#[test]
fn duplicate_member_is_refused() {
    assert_eq!(decode(br#"{"schema_version":3,"schema_version":3,"status":"complete","reason":null,"files":0,"dump":false,"entries":0,"max_depth":0,"world_writable":0,"extra_paths":0}"#),Err(ExecutorError::InvalidRequest));
}
#[test]
fn oversized_report_is_refused() {
    let mut bytes = serde_json::to_vec(&complete()).unwrap();
    bytes.resize(4097, b' ');
    assert_eq!(decode(&bytes), Err(ExecutorError::InvalidRequest));
}
#[test]
fn truncated_report_is_refused() {
    assert_eq!(decode(b"{"), Err(ExecutorError::InvalidRequest));
}
#[test]
fn unavailable_inventory_cannot_pass_artifact_gate() {
    let checks = super::super::Checks {
        fetch: true,
        ..Default::default()
    };
    assert!(!checks.artifacts_complete());
    assert_eq!(checks.artifacts_status(), "unknown");
}
#[test]
fn limit_inventory_cannot_pass_artifact_gate() {
    let mut r = parsed(complete()).unwrap();
    r.status = Status::Limit;
    r.reason = Some(Reason::Depth);
    r.files = None;
    r.dump = None;
    let checks = super::super::Checks {
        fetch: true,
        inventory: Some(r),
        ..Default::default()
    };
    assert!(!checks.artifacts_complete());
    assert_eq!(checks.artifacts_status(), "unknown");
}
#[test]
fn complete_inventory_can_pass_artifact_gate() {
    let checks = super::super::Checks {
        fetch: true,
        inventory: Some(parsed(complete()).unwrap()),
        ..Default::default()
    };
    assert!(checks.artifacts_complete());
    assert_eq!(checks.artifacts_status(), "pass");
}
#[test]
fn empty_inventory_is_known_incomplete() {
    let mut v = complete();
    v["files"] = serde_json::json!(0);
    v["world_writable"] = serde_json::json!(0);
    let checks = super::super::Checks {
        fetch: true,
        inventory: Some(parsed(v).unwrap()),
        ..Default::default()
    };
    assert!(!checks.artifacts_complete());
    assert_eq!(checks.artifacts_status(), "fail");
}
#[test]
fn inventory_launch_has_no_network_or_fetch_credentials() {
    let target = ProbeTarget {
        account: "rs_blog13",
        hostname: "blog13.example.test",
        snapshot: "",
        probe: "rp_abcdef",
    };
    let p = properties("/run/rustiron-admin/fixture.inventory.json");
    let args = super::super::unit_arguments(
        &target,
        "fixture-unit",
        &p,
        &[
            &format!("{BIN}/restore-inventory"),
            &super::super::restore_root(&target),
            &super::super::site_below_restore(&target),
        ],
    );
    let end = args.iter().position(|s| s == "--").unwrap();
    let properties: Vec<_> = args[..end]
        .windows(2)
        .filter_map(|p| (p[0] == "--property").then_some(p[1].as_str()))
        .collect();
    assert!(properties.contains(&"User=rp_abcdef"));
    assert!(properties.contains(&"Group=rp_abcdef"));
    assert!(properties.contains(&"NoNewPrivileges=yes"));
    assert!(properties.contains(&"CapabilityBoundingSet="));
    assert!(properties.contains(&"PrivateNetwork=yes"));
    assert!(properties.contains(&"IPAddressDeny=any"));
    assert!(properties.contains(&"MemoryMax=512M"));
    assert!(properties.contains(&"RuntimeMaxSec=100"));
    assert!(properties.contains(&"SELinuxContext=system_u:system_r:rustiron_capture_t:s0:c950"));
    assert!(
        !properties
            .iter()
            .any(|p| p.starts_with("LoadCredential=") || p.starts_with("IPAddressAllow="))
    );
    assert!(
        properties.contains(
            &format!(
                "InaccessiblePaths=-{} -/run/credentials",
                crate::layout::JOB_CREDENTIALS_DIR
            )
            .as_str()
        )
    );
    assert_eq!(
        &args[end + 1..],
        [
            format!("{BIN}/restore-inventory"),
            "/srv/restore-probes/rp_abcdef/tmp/restore".to_owned(),
            "srv/sites/rs_blog13".to_owned()
        ]
    );
}
fn assess_with(report: Option<Report>, integrity: bool) -> (bool, bool) {
    use std::cell::Cell;
    let imported = Cell::new(false);
    let health = Cell::new(false);
    let mut checks = super::super::Checks {
        fetch: true,
        integrity,
        inventory: report,
        ..Default::default()
    };
    checks.assess(
        || {
            imported.set(true);
            (true, None)
        },
        || {
            health.set(true);
            Some(serde_json::json!({}))
        },
    );
    (imported.get(), health.get())
}
#[test]
fn unavailable_inventory_prevents_import_and_health() {
    assert_eq!(assess_with(None, true), (false, false));
}
#[test]
fn limit_inventory_prevents_import_and_health() {
    let r=parsed(serde_json::json!({"schema_version":3,"status":"limit","reason":"depth","files":null,"dump":null,"entries":1,"max_depth":1,"world_writable":null,"extra_paths":null})).unwrap();
    assert_eq!(assess_with(Some(r), true), (false, false));
}
#[test]
fn failed_integrity_prevents_import_and_health() {
    assert_eq!(
        assess_with(Some(parsed(complete()).unwrap()), false),
        (false, false)
    );
}
#[test]
fn complete_inventory_allows_import_then_health() {
    assert_eq!(
        assess_with(Some(parsed(complete()).unwrap()), true),
        (true, true)
    );
}
/// W378 (W328 c4b): version 3 states the entries outside the captured site
/// paths; version 2 cannot say whether a snapshot held foreign paths.
fn complete_v3(extra: u64) -> serde_json::Value {
    serde_json::json!({"schema_version":3,"status":"complete","reason":null,"files":2,"dump":true,"entries":3 + extra,"max_depth":1,"world_writable":0,"extra_paths":extra})
}
#[test]
fn a_version_3_report_states_extra_snapshot_paths() {
    let r = serde_json::to_value(parsed(complete_v3(2)).unwrap()).unwrap();
    assert_eq!(r["extra_paths"], 2);
    assert_eq!(r["entries"], 5);
    let r = serde_json::to_value(parsed(complete_v3(0)).unwrap()).unwrap();
    assert_eq!(r["extra_paths"], 0);
}
#[test]
fn a_report_that_cannot_state_extra_paths_is_refused() {
    // Version 2 has no member for them.
    assert_eq!(
        parsed(
            serde_json::json!({"schema_version":2,"status":"complete","reason":null,"files":2,"dump":true,"entries":3,"max_depth":1,"world_writable":1})
        ),
        Err(ExecutorError::InvalidRequest)
    );
    let mut v = complete_v3(1);
    v.as_object_mut().unwrap().remove("extra_paths");
    assert_eq!(parsed(v), Err(ExecutorError::InvalidRequest));
    let mut v = complete_v3(1);
    v["extra_paths"] = serde_json::Value::Null;
    assert_eq!(parsed(v), Err(ExecutorError::InvalidRequest));
    // Html files and extra paths are both entries.
    let mut v = complete_v3(2);
    v["entries"] = serde_json::json!(3);
    assert_eq!(parsed(v), Err(ExecutorError::InvalidRequest));
    // Only a complete report claims a count.
    let error = serde_json::json!({"schema_version":3,"status":"error","reason":"io","files":null,"dump":null,"entries":1,"max_depth":0,"world_writable":null,"extra_paths":0});
    assert_eq!(parsed(error), Err(ExecutorError::InvalidRequest));
}
#[test]
fn exact_report_bound_is_accepted() {
    let mut bytes = serde_json::to_vec(&complete()).unwrap();
    bytes.resize(4096, b' ');
    assert!(decode(&bytes).is_ok());
}

#[test]
fn probe_units_are_killed_before_the_helper_deadline() {
    // W208: as capture in W207, a unit that holds SIGTERM must not outlive
    // the helper's command deadline, so the stop after the ceiling is bounded.
    let target = ProbeTarget {
        account: "rs_blog13",
        hostname: "blog13.example.test",
        snapshot: "",
        probe: "rp_abcdef",
    };
    let args = super::super::unit_arguments(&target, "fixture-unit", &[], &["/bin/true"]);
    let value = |key: &str| -> u64 {
        args.iter()
            .find_map(|a| a.strip_prefix(key))
            .unwrap()
            .parse()
            .unwrap()
    };
    let run = value("RuntimeMaxSec=");
    let stop = value("TimeoutStopSec=");
    assert!(run + stop + 10 <= crate::provision::COMMAND_TIMEOUT.as_secs());
}
