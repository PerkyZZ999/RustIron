//! W391 (B09, D-041): per-version retention evidence. The `lock` worker
//! prints closed lines for what it read: the bucket default at the lock
//! precheck and postcheck, and at the postcheck each object version that
//! the capture wrote. The admin helper relays the parsed evidence, the
//! executor stores it with the success (journal v18), and the receipt and
//! the observation state it. A capture without evidence keeps the W371
//! `not_recorded` receipt bytes.

use rustiron_journal::{
    MAX_LOCK_DAYS, MAX_RETAINED_OBJECTS, ObjectRetention, ObservedCapture, RETENTION_MODE,
    RetainedObjectKind, RetentionEvidence, version_id_ok,
};
use serde_json::{Value, json};

/// Largest `lock` worker output the runner reads: the bucket line and
/// 1024 object lines of at most 232 bytes each.
pub(crate) const MAX_LOCK_OUTPUT_BYTES: usize = 256 * 1024;

/// Sorted new index IDs reported by the write worker for one backup.
/// The one argument stays below Linux's per-argument size limit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WrittenIndexes(String);

impl WrittenIndexes {
    /// Bound of the comma-separated worker argument.
    pub const MAX_BYTES: usize = (MAX_RETAINED_OBJECTS - 1) * 65 - 1;

    /// Reads a closed list of full, unique IDs, or `-` for no new indexes.
    pub fn parse(word: &str) -> Option<Self> {
        if word != "-" {
            if word.len() > Self::MAX_BYTES {
                return None;
            }
            let mut previous = "";
            for id in word.split(',') {
                if !lower_hex64(id) || id <= previous {
                    return None;
                }
                previous = id;
            }
        }
        Some(Self(word.to_owned()))
    }

    /// Canonical worker argument.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// IDs only, in key order.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.0.split(',').filter(|id| *id != "-")
    }

    /// Checks that the readback covers every reported index.
    pub(crate) fn matches(&self, reading: &LockReading) -> bool {
        let has_pack = reading
            .objects
            .iter()
            .any(|object| object.kind == RetainedObjectKind::Pack);
        (has_pack == (self.0 != "-"))
            && self.ids().eq(reading.objects.iter().filter_map(|object| {
                (object.kind == RetainedObjectKind::Index).then_some(object.object_id.as_str())
            }))
    }
}

/// What one `lock` worker run read back.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockReading {
    /// The bucket's default COMPLIANCE days.
    pub days: u32,
    /// With an operation, each object version the worker read back.
    pub objects: Vec<ObjectRetention>,
}

/// A canonical non-negative decimal.
fn decimal(word: &str) -> Option<i64> {
    ((word == "0" || !word.starts_with('0')) && word.bytes().all(|b| b.is_ascii_digit()))
        .then(|| word.parse().ok())
        .flatten()
}

fn lower_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The worker's whole output: one `bucket Enabled COMPLIANCE DAYS` line,
/// then, only when `with_objects`, 1 to 1024 lines of
/// `object KIND ID VERSION COMPLIANCE UNTIL`. Anything else is `None`.
pub(crate) fn parse_lock(bytes: &[u8], with_objects: bool) -> Option<LockReading> {
    if bytes.len() > MAX_LOCK_OUTPUT_BYTES {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?.strip_suffix('\n')?;
    let mut lines = text.split('\n');
    let days = match lines.next()?.split(' ').collect::<Vec<_>>().as_slice() {
        ["bucket", "Enabled", "COMPLIANCE", days] => u32::try_from(decimal(days)?).ok()?,
        _ => return None,
    };
    if !(1..=MAX_LOCK_DAYS).contains(&days) {
        return None;
    }
    let objects = lines
        .map(
            |line| match line.split(' ').collect::<Vec<_>>().as_slice() {
                ["object", kind, id, version, mode, until]
                    if *mode == RETENTION_MODE && lower_hex64(id) && version_id_ok(version) =>
                {
                    Some(ObjectRetention {
                        kind: RetainedObjectKind::from_name(kind)?,
                        object_id: (*id).to_owned(),
                        version_id: (*version).to_owned(),
                        retain_until: decimal(until)?,
                    })
                }
                _ => None,
            },
        )
        .collect::<Option<Vec<_>>>()?;
    let count_ok = if with_objects {
        (1..=MAX_RETAINED_OBJECTS).contains(&objects.len())
    } else {
        objects.is_empty()
    };
    count_ok.then_some(LockReading { days, objects })
}

/// The evidence of one capture from its precheck and postcheck readings.
/// `None` unless exactly one snapshot object names `snapshot`.
pub(crate) fn evidence(
    before: &LockReading,
    after: &LockReading,
    snapshot: &str,
) -> Option<RetentionEvidence> {
    let evidence = RetentionEvidence {
        before_days: before.days,
        after_days: after.days,
        objects: after.objects.clone(),
    };
    evidence.valid_for(snapshot).then_some(evidence)
}

fn object_json(object: &ObjectRetention) -> Value {
    json!({
        "kind": object.kind.as_str(),
        "object_id": object.object_id,
        "version_id": object.version_id,
        "mode": RETENTION_MODE,
        "retain_until": object.retain_until,
    })
}

/// The evidence as the admin helper relays it to the executor.
pub(crate) fn to_relay(evidence: &RetentionEvidence) -> Value {
    json!({
        "before_days": evidence.before_days,
        "after_days": evidence.after_days,
        "objects": evidence.objects.iter().map(object_json).collect::<Vec<_>>(),
    })
}

/// Relayed evidence, checked again; anything malformed is `None`, which
/// leaves the evidence unrecorded without changing the outcome.
pub(crate) fn from_relay(value: &Value, snapshot: &str) -> Option<RetentionEvidence> {
    let day = |field: &Value| u32::try_from(field.as_u64()?).ok();
    let objects = value["objects"]
        .as_array()?
        .iter()
        .map(|object| {
            (object["mode"] == RETENTION_MODE).then_some(())?;
            Some(ObjectRetention {
                kind: RetainedObjectKind::from_name(object["kind"].as_str()?)?,
                object_id: object["object_id"].as_str()?.to_owned(),
                version_id: object["version_id"].as_str()?.to_owned(),
                retain_until: object["retain_until"].as_i64()?,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    let evidence = RetentionEvidence {
        before_days: day(&value["before_days"])?,
        after_days: day(&value["after_days"])?,
        objects,
    };
    evidence.valid_for(snapshot).then_some(evidence)
}

fn check_json(days: u32) -> Value {
    json!({
        "result": "passed",
        "versioning": "Enabled",
        "default_mode": RETENTION_MODE,
        "default_days": days,
    })
}

/// The receipt's `retention` value. Without evidence it is the W371 shape,
/// byte for byte, with the same limitation lines.
pub(crate) fn receipt_retention(
    days: Option<u32>,
    evidence: Option<&RetentionEvidence>,
    limitations: &mut Vec<String>,
) -> Value {
    match (days, evidence) {
        (_, Some(evidence)) => {
            limitations.push("retention evidence states what the lock reader read at this capture's postcheck; a later change at the store is not observed, and packs reused from earlier captures keep only the retention their own capture checked".to_owned());
            json!({
                "days": days,
                "status": "recorded",
                "checks": {
                    "before": check_json(evidence.before_days),
                    "after": check_json(evidence.after_days),
                },
                "objects": evidence.objects.iter().map(object_json).collect::<Vec<_>>(),
                "scope": "the lock precheck and postcheck read the bucket's versioning and default COMPLIANCE retention; at the postcheck a HEAD read named each written object's version, and the version-pinned GetObjectRetention returned COMPLIANCE with the same retain-until time, covering the enrolled days from the snapshot start",
            })
        }
        (Some(days), None) => {
            limitations.push(format!(
                "retention days {days} were copied from the enrolled policy; the journal does not record per-object retention evidence"
            ));
            json!({"days": days, "status": "not_recorded"})
        }
        (None, None) => {
            limitations.push("retention days were not stored on this capture row".to_owned());
            Value::Null
        }
    }
}

/// The observation's summary of a capture's evidence; `null` without it.
pub(crate) fn observed_retention(capture: &ObservedCapture) -> Value {
    match &capture.retention {
        Some(r) if capture.state == "succeeded" => json!({
            "status": "recorded",
            "before_days": r.before_days,
            "after_days": r.after_days,
            "objects": r.objects,
            "earliest_retain_until": r.earliest_retain_until,
            "latest_retain_until": r.latest_retain_until,
        }),
        _ => Value::Null,
    }
}

/// The observation's refusal code of a failed capture; `null` otherwise.
pub(crate) fn observed_refusal(capture: &ObservedCapture) -> Value {
    match capture.refusal.as_deref() {
        Some(code) if capture.state == "failed" && rustiron_journal::refusal_code_ok(code) => {
            Value::from(code)
        }
        _ => Value::Null,
    }
}

#[cfg(test)]
#[path = "retention_evidence_tests.rs"]
mod tests;
