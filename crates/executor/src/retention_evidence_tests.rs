use rustiron_journal::{ObjectRetention, RetainedObjectKind, RetentionEvidence};

use super::*;

const SNAPSHOT: &str = "a50c8b74e3c0f1d2a50c8b74e3c0f1d2a50c8b74e3c0f1d2a50c8b74e3c0f1d2";

fn postcheck() -> String {
    format!(
        "bucket Enabled COMPLIANCE 30\nobject snapshot {SNAPSHOT} 76b01aea-db7c-4b38-b41d-3c031085d108 COMPLIANCE 1797183776\nobject pack {} v2 COMPLIANCE 1797183777\n",
        "9f".repeat(32)
    )
}

#[test]
fn the_precheck_reading_is_one_bucket_line() {
    let reading = parse_lock(b"bucket Enabled COMPLIANCE 30\n", false).unwrap();
    assert_eq!(reading.days, 30);
    assert!(reading.objects.is_empty());
    for bad in [
        &b""[..],
        b"bucket Enabled COMPLIANCE 30",
        b"bucket Suspended COMPLIANCE 30\n",
        b"bucket Enabled GOVERNANCE 30\n",
        b"bucket Enabled COMPLIANCE 030\n",
        b"bucket Enabled COMPLIANCE 0\n",
        b"bucket Enabled COMPLIANCE 36501\n",
        b"bucket Enabled COMPLIANCE 30\nbucket Enabled COMPLIANCE 30\n",
    ] {
        assert!(
            parse_lock(bad, false).is_none(),
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
    // A precheck reading carries no object; a postcheck reading needs one.
    assert!(parse_lock(postcheck().as_bytes(), false).is_none());
    assert!(parse_lock(b"bucket Enabled COMPLIANCE 30\n", true).is_none());
}

#[test]
fn the_postcheck_reading_lists_each_object_version() {
    let reading = parse_lock(postcheck().as_bytes(), true).unwrap();
    assert_eq!(reading.days, 30);
    assert_eq!(
        reading.objects,
        [
            ObjectRetention {
                kind: RetainedObjectKind::Snapshot,
                object_id: SNAPSHOT.to_owned(),
                version_id: "76b01aea-db7c-4b38-b41d-3c031085d108".to_owned(),
                retain_until: 1_797_183_776,
            },
            ObjectRetention {
                kind: RetainedObjectKind::Pack,
                object_id: "9f".repeat(32),
                version_id: "v2".to_owned(),
                retain_until: 1_797_183_777,
            },
        ]
    );
    for (from, to) in [
        ("object pack", "object config"),
        ("v2 COMPLIANCE", "null COMPLIANCE"),
        ("v2 COMPLIANCE", "v+2 COMPLIANCE"),
        ("v2 COMPLIANCE", "v2 GOVERNANCE"),
        ("1797183777", "-1"),
        ("1797183777", "01797183777"),
        (&"9f".repeat(32), &"9F".repeat(32)),
    ] {
        let bad = postcheck().replace(from, to);
        assert!(parse_lock(bad.as_bytes(), true).is_none(), "{bad}");
    }
    let mut many = String::from("bucket Enabled COMPLIANCE 30\n");
    for n in 0..1025 {
        many.push_str(&format!("object pack {n:064x} v1 COMPLIANCE 1\n"));
    }
    assert!(parse_lock(many.as_bytes(), true).is_none());
}

#[test]
fn evidence_needs_the_written_snapshot_once() {
    let before = parse_lock(b"bucket Enabled COMPLIANCE 31\n", false).unwrap();
    let after = parse_lock(postcheck().as_bytes(), true).unwrap();
    let evidence = evidence(&before, &after, SNAPSHOT).unwrap();
    assert_eq!(
        (
            evidence.before_days,
            evidence.after_days,
            evidence.objects.len()
        ),
        (31, 30, 2)
    );
    assert!(super::evidence(&before, &after, &"b".repeat(64)).is_none());
    let twice = parse_lock(
        format!(
            "{}object snapshot {SNAPSHOT} v3 COMPLIANCE 1797183778\n",
            postcheck()
        )
        .as_bytes(),
        true,
    )
    .unwrap();
    assert!(super::evidence(&before, &twice, SNAPSHOT).is_none());
}

#[test]
fn the_relayed_evidence_round_trips_and_refuses_changes() {
    let before = parse_lock(b"bucket Enabled COMPLIANCE 30\n", false).unwrap();
    let after = parse_lock(postcheck().as_bytes(), true).unwrap();
    let evidence = evidence(&before, &after, SNAPSHOT).unwrap();
    let relayed = to_relay(&evidence);
    assert_eq!(from_relay(&relayed, SNAPSHOT), Some(evidence));
    assert_eq!(from_relay(&relayed, &"b".repeat(64)), None);
    let mut bad = relayed.clone();
    bad["objects"][1]["version_id"] = "null".into();
    assert_eq!(from_relay(&bad, SNAPSHOT), None);
    let mut bad = relayed;
    bad["before_days"] = 0.into();
    assert_eq!(from_relay(&bad, SNAPSHOT), None);
    assert_eq!(from_relay(&serde_json::Value::Null, SNAPSHOT), None);
}

fn sample() -> RetentionEvidence {
    let before = parse_lock(b"bucket Enabled COMPLIANCE 30\n", false).unwrap();
    let after = parse_lock(postcheck().as_bytes(), true).unwrap();
    evidence(&before, &after, SNAPSHOT).unwrap()
}

/// The receipt states each object version as read and the checks that
/// passed; a row without evidence keeps the W371 `not_recorded` bytes.
#[test]
fn the_receipt_retention_block_states_recorded_or_not_recorded() {
    let mut limitations = Vec::new();
    let recorded = receipt_retention(Some(30), Some(&sample()), &mut limitations);
    assert_eq!(recorded["status"], "recorded");
    assert_eq!(recorded["days"], 30);
    assert_eq!(recorded["checks"]["before"]["result"], "passed");
    assert_eq!(recorded["checks"]["after"]["default_mode"], "COMPLIANCE");
    assert_eq!(recorded["checks"]["after"]["versioning"], "Enabled");
    assert_eq!(recorded["objects"][0]["kind"], "snapshot");
    assert_eq!(
        recorded["objects"][0]["version_id"],
        "76b01aea-db7c-4b38-b41d-3c031085d108"
    );
    assert_eq!(recorded["objects"][1]["mode"], "COMPLIANCE");
    assert_eq!(recorded["objects"][1]["retain_until"], 1_797_183_777);
    assert!(recorded["scope"].as_str().unwrap().contains("postcheck"));
    assert!(
        limitations
            .iter()
            .any(|line| line.contains("reused from earlier captures"))
    );
    let mut old = Vec::new();
    assert_eq!(
        receipt_retention(Some(30), None, &mut old),
        serde_json::json!({"days": 30, "status": "not_recorded"})
    );
    assert_eq!(
        old,
        [
            "retention days 30 were copied from the enrolled policy; the journal does not record per-object retention evidence"
        ]
    );
    let mut none = Vec::new();
    assert_eq!(
        receipt_retention(None, None, &mut none),
        serde_json::Value::Null
    );
    assert_eq!(none, ["retention days were not stored on this capture row"]);
}
