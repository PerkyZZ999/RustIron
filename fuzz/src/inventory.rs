//! The restore inventory report decoder, included from the executor by path so
//! the fuzz graph gains serde only, not the executor's system dependencies.

#[path = "../../crates/executor/src/restore/inventory_report.rs"]
mod report;

use report::{MAX_DEPTH, MAX_ENTRIES, MAX_REPORT_BYTES, Status, decode};
use serde_json::Value;

const MEMBERS: [&str; 9] = [
    "schema_version",
    "status",
    "reason",
    "files",
    "dump",
    "entries",
    "max_depth",
    "world_writable",
    "extra_paths",
];

/// The largest input the campaign feeds: one byte over the report ceiling.
pub const INVENTORY_MAX_INPUT: usize = MAX_REPORT_BYTES + 1;

fn refused(value: &Value) -> bool {
    let bytes = serde_json::to_vec(value).expect("re-encode");
    bytes.len() <= MAX_REPORT_BYTES && decode(&bytes).is_none()
}

/// Check the closed report shape: ceiling, exact members, version, bounds,
/// status-specific claims and stable re-encoding, plus changes that must fail.
pub fn inventory_report(input: &[u8]) -> bool {
    let decoded = decode(input);
    if input.len() > MAX_REPORT_BYTES {
        assert!(decoded.is_none(), "oversized report accepted");
        return false;
    }
    let Some(report) = decoded else {
        return false;
    };
    let value: Value = serde_json::from_slice(input).expect("accepted report must be JSON");
    let object = value
        .as_object()
        .expect("accepted report must be an object");
    assert_eq!(object.len(), MEMBERS.len(), "member set is not closed");
    assert!(MEMBERS.iter().all(|name| object.contains_key(*name)));
    assert_eq!(report.schema_version, 3);
    assert!(report.entries <= MAX_ENTRIES && report.max_depth <= MAX_DEPTH);
    assert_eq!(value["entries"].as_u64(), Some(report.entries));
    let complete = report.status == Status::Complete;
    assert_eq!(
        complete,
        report.files.is_some(),
        "only complete claims files"
    );
    assert_eq!(
        complete,
        report.dump.is_some(),
        "only complete claims a dump"
    );
    assert_eq!(
        complete,
        report.reason.is_none(),
        "only complete has no reason"
    );
    assert_eq!(
        complete,
        report.world_writable.is_some(),
        "only complete counts world-writable files"
    );
    assert_eq!(
        complete,
        report.extra_paths.is_some(),
        "only complete counts extra snapshot paths"
    );
    if let Some(files) = report.files {
        assert!(files <= report.entries, "more files than entries");
        assert!(
            report
                .extra_paths
                .is_some_and(|extra| files + extra <= report.entries),
            "files and extra paths above entries"
        );
        assert!(
            report.world_writable.is_some_and(|w| w <= files),
            "more world-writable than files"
        );
    }
    let encoded = serde_json::to_vec(&report).expect("encode");
    assert_eq!(
        decode(&encoded),
        Some(report.clone()),
        "re-encoding changed it"
    );

    // Known-invalid changes.
    for version in [1, 2, 4] {
        let mut changed = value.clone();
        changed["schema_version"] = version.into();
        assert!(refused(&changed), "another schema version accepted");
    }
    let mut changed = value.clone();
    changed["unexpected"] = true.into();
    assert!(refused(&changed), "unknown member accepted");
    let mut changed = value.clone();
    changed["entries"] = (MAX_ENTRIES + 1).into();
    assert!(refused(&changed), "entry ceiling not enforced");
    let mut changed = value.clone();
    changed["max_depth"] = (MAX_DEPTH + 1).into();
    assert!(refused(&changed), "depth ceiling not enforced");
    let mut changed = value.clone();
    changed.as_object_mut().unwrap().remove("reason");
    assert!(refused(&changed), "missing member accepted");
    let mut changed = value;
    if complete {
        changed["files"] = (report.entries + 1).into();
        assert!(refused(&changed), "files above entries accepted");
        changed["files"] = report.files.unwrap().into();
        changed["world_writable"] = (report.files.unwrap() + 1).into();
        assert!(refused(&changed), "world-writable above files accepted");
        changed["world_writable"] = 0.into();
        changed["extra_paths"] = (report.entries + 1).into();
        assert!(refused(&changed), "extra paths above entries accepted");
        changed["extra_paths"] = 0.into();
        changed["files"] = 0.into();
        changed["reason"] = "io".into();
        assert!(refused(&changed), "complete report with a reason accepted");
    } else {
        changed["extra_paths"] = 0.into();
        assert!(refused(&changed), "non-complete report counted extra paths");
        changed["extra_paths"] = Value::Null;
        changed["files"] = 0.into();
        assert!(refused(&changed), "non-complete report claimed files");
    }
    true
}
