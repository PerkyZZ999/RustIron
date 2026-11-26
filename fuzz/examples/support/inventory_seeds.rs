//! Restore inventory report seeds: every accepted status/reason and each refusal class.

use serde_json::{Value, json};

fn report(
    status: &str,
    reason: Value,
    files: Value,
    dump: Value,
    entries: u64,
    depth: u32,
) -> Value {
    let counted = if status == "complete" {
        json!(0)
    } else {
        Value::Null
    };
    json!({"schema_version":3,"status":status,"reason":reason,"files":files,"dump":dump,
           "entries":entries,"max_depth":depth,"world_writable":counted,"extra_paths":counted})
}

pub(super) fn generate(seed: &mut impl FnMut(&str, &str, &[u8], bool)) {
    let mut add = |name: &str, value: &Value, accepted: bool| {
        seed(
            "inventory_report",
            name,
            &serde_json::to_vec(value).unwrap(),
            accepted,
        );
    };
    let complete = report("complete", Value::Null, json!(2), json!(true), 3, 1);
    add("complete", &complete, true);
    add(
        "complete-empty",
        &report("complete", Value::Null, json!(0), json!(false), 0, 0),
        true,
    );
    add(
        "complete-ceilings",
        &report(
            "complete",
            Value::Null,
            json!(100_000),
            json!(true),
            100_000,
            64,
        ),
        true,
    );
    for reason in ["io", "unsupported", "changed", "identity", "privileged"] {
        add(
            &format!("error-{reason}"),
            &report("error", json!(reason), Value::Null, Value::Null, 1, 0),
            true,
        );
    }
    for reason in ["entries", "depth", "time"] {
        add(
            &format!("limit-{reason}"),
            &report(
                "limit",
                json!(reason),
                Value::Null,
                Value::Null,
                100_000,
                64,
            ),
            true,
        );
    }
    let changes: [(&str, &str, Value); 18] = [
        ("schema-1", "schema_version", json!(1)),
        ("schema-2", "schema_version", json!(2)),
        ("schema-4", "schema_version", json!(4)),
        ("extra-paths-over-entries", "extra_paths", json!(2)),
        ("extra-paths-missing-claim", "extra_paths", Value::Null),
        ("world-writable-over-files", "world_writable", json!(3)),
        (
            "world-writable-missing-claim",
            "world_writable",
            Value::Null,
        ),
        ("status-unknown", "status", json!("partial")),
        ("complete-with-reason", "reason", json!("io")),
        ("files-over-entries", "files", json!(4)),
        ("files-missing-claim", "files", Value::Null),
        ("dump-missing-claim", "dump", Value::Null),
        ("entries-over-ceiling", "entries", json!(100_001)),
        ("depth-over-ceiling", "max_depth", json!(65)),
        ("negative-entries", "entries", json!(-1)),
        ("files-as-text", "files", json!("2")),
        ("unknown-member", "extra", json!(true)),
        ("reason-unknown", "reason", json!("other")),
    ];
    for (name, key, value) in changes {
        let mut changed = complete.clone();
        changed[key] = value;
        add(name, &changed, false);
    }
    add(
        "error-with-files",
        &report("error", json!("io"), json!(0), Value::Null, 1, 0),
        false,
    );
    let mut counted = report("error", json!("privileged"), Value::Null, Value::Null, 1, 0);
    counted["world_writable"] = json!(0);
    add("error-with-world-writable", &counted, false);
    let mut ww = complete.clone();
    ww["world_writable"] = json!(2);
    add("complete-world-writable", &ww, true);
    // W378: a snapshot with entries outside the site's html and dump paths.
    let mut extra = complete.clone();
    extra["entries"] = json!(4);
    extra["extra_paths"] = json!(2);
    add("complete-extra-paths", &extra, true);
    let mut extra_error = report("error", json!("io"), Value::Null, Value::Null, 1, 0);
    extra_error["extra_paths"] = json!(0);
    add("error-with-extra-paths", &extra_error, false);
    add(
        "limit-with-io",
        &report("limit", json!("io"), Value::Null, Value::Null, 1, 0),
        false,
    );
    add(
        "error-with-limit-reason",
        &report("error", json!("time"), Value::Null, Value::Null, 1, 0),
        false,
    );
    let mut missing = complete.clone();
    missing.as_object_mut().unwrap().remove("reason");
    add("missing-member", &missing, false);
    seed("inventory_report", "not-an-object", b"[1]", false);
    seed("inventory_report", "duplicate-member",
         br#"{"schema_version":3,"schema_version":3,"status":"complete","reason":null,"files":2,"dump":true,"entries":3,"max_depth":1,"world_writable":0,"extra_paths":0}"#, false);
    seed(
        "inventory_report",
        "truncated",
        br#"{"schema_version":3,"status":"comp"#,
        false,
    );
    // Valid JSON one byte over the ceiling (padding) is refused by size.
    let bytes = serde_json::to_vec(&complete).unwrap();
    let mut padded = vec![b' '; rustiron_fuzz::INVENTORY_MAX_INPUT - bytes.len()];
    padded.extend_from_slice(&bytes);
    seed("inventory_report", "oversized", &padded, false);
    // Exactly at the ceiling is decoded.
    let mut at_ceiling = vec![b' '; rustiron_fuzz::INVENTORY_MAX_INPUT - 1 - bytes.len()];
    at_ceiling.extend_from_slice(&bytes);
    seed("inventory_report", "at-ceiling", &at_ceiling, true);
}
