//! Self-attested recovery receipts. A receipt is not independent proof.

use rustiron_journal::{Capture, CaptureState, Probe, ProbeState};
use sha2::{Digest, Sha256};

use crate::ExecutorError;

/// Portable RecoveryReceipt v1 for a finished restore probe.
pub fn recovery_receipt(
    probe: &Probe,
    receipt: serde_json::Value,
) -> Result<serde_json::Value, ExecutorError> {
    let state = match probe.state {
        ProbeState::Running => "running",
        ProbeState::Passed => "passed",
        ProbeState::Failed => "failed",
        ProbeState::CleanupIncomplete => "cleanup_incomplete",
    };
    let missing = MissingResult::of(&receipt);
    let (fields, filled) = completed_fields(
        receipt["fields"].clone(),
        probe.finished_at.map(unix_seconds).transpose()?,
        &missing,
    );
    let limitations = probe_limitations(&receipt["limitations"], &filled, &missing);
    seal_receipt(serde_json::json!({
        "receipt_schema": "rustiron-recovery-receipt/1",
        "host_id": probe.intent.host_id.as_str(),
        "host_epoch": probe.intent.host_epoch.as_str(),
        "site_id": probe.intent.site_id.as_str(),
        "operation": {
            "verb": "restore_probe",
            "operation_id": probe.intent.operation_id.as_str(),
            "grant_id": probe.intent.grant_id.as_str(),
            "plan_digest": probe.intent.plan_digest.as_str(),
            "grant_digest": probe.intent.grant_digest.as_str(),
            "started_at": probe.started_at.get(),
            "finished_at": probe.finished_at.map(rustiron_contracts::Timestamp::get),
            "state": state,
        },
        "snapshot_id": probe.intent.snapshot_id.as_str(),
        "fields": fields,
        "durations_ms": receipt["durations_ms"].clone(),
        "cleanup": receipt["cleanup"].clone(),
        "inventory": receipt["inventory"].clone(),
        "limitations": limitations,
        "attester": receipt_attester(),
    }))
}

/// RecoveryReceipt v1 derived from a finished capture row.
pub fn capture_receipt(capture: &Capture) -> Result<serde_json::Value, ExecutorError> {
    let Some(observed_at) = capture.finished_at.map(unix_seconds).transpose()? else {
        return Err(ExecutorError::NotAdmitted);
    };
    if capture.state == CaptureState::Running {
        return Err(ExecutorError::NotAdmitted);
    }
    let succeeded = capture.state == CaptureState::Succeeded;
    if succeeded
        && !capture.snapshot_id.as_deref().is_some_and(|id| {
            id.len() == 64
                && id
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
    {
        return Err(ExecutorError::Unavailable);
    }
    // W252 (D-021 option E): the marker label, stated, never an aggregate.
    let consistency = succeeded.then(|| {
        let (label, reason) = capture.consistency.as_ref().map_or(
            ("unmatched", Some("not_checked")),
            |c| (c.label(), c.reason()),
        );
        serde_json::json!({
            "label": label,
            "reason": reason,
            "scope": "matched means the per-table database checksum marker read before the dump equals the one read after the snapshot check; it does not prove an application freeze, and a change that is reverted inside the window is not seen",
        })
    });
    let mut fields = capture_fields(succeeded, capture.method.is_some(), observed_at);
    if let Some(body) = &consistency
        && let Some(scope) = fields["application_consistency_assessed"]["scope"].as_str()
    {
        let label = body["label"].as_str().unwrap_or("unmatched");
        fields["application_consistency_assessed"]["scope"] =
            format!("{scope}; database marker label: {label}").into();
    }
    let window_s = capture
        .finished_at
        .map(|done| done.get().saturating_sub(capture.started_at.get()));
    // W203/W356: the stored manifest record, when the capture kept one.
    let manifest = succeeded.then(|| match &capture.manifest {
        Some(m) => serde_json::json!({
            "sha256": m.sha256,
            "entries": m.entries,
            "regular_bytes": m.regular_bytes,
            "truncated": m.truncated,
        }),
        None => serde_json::json!({
            "recorded": false,
            "reason": "no manifest was recorded for this capture (recovery records none; a refused or oversized listing is dropped)",
        }),
    });
    let mut limitations = vec![
        "derived at export from the capture journal row; not a stored restore-probe receipt".to_owned(),
        "decryption, isolated restore, and application health were not run".to_owned(),
        "file and database atomicity is not claimed".to_owned(),
        "the database is dumped before the files are read, so file writes made after the dump can be in the snapshot without their database rows (W216: about 0.5 s and 7 writes on a lab site); quiesce site writes when a matched pair is needed".to_owned(),
        "a missing destination attestation is not an independent copy".to_owned(),
    ];
    // W391: the stored per-version evidence (v18), or the W371 shape for a
    // row without it. A product build can also read lab rows.
    let retention = crate::retention_evidence::receipt_retention(
        capture.retention_days,
        capture.retention_evidence.as_ref(),
        &mut limitations,
    );
    if cfg!(rustiron_profile = "product") {
        limitations.push("the enrolled store is not shown to be off-site or independent of this host (D-026); this receipt never claims an independent copy".to_owned());
    }
    if succeeded && (capture.files.is_none() || capture.bytes.is_none()) {
        limitations.push("no file or byte count is recorded: operator recovery recorded this capture, or it predates counts; whether restic read every source file is not known".to_owned());
    }
    // W366: a settled capture names its tagged snapshot as unclaimed
    // evidence only; nothing about that snapshot is claimed.
    let unclaimed = capture
        .unclaimed_snapshot_id
        .as_deref()
        .filter(|_| capture.state == CaptureState::Failed)
        .map(|id| {
            mark_unclaimed_artifacts(&mut fields);
            limitations.push("an operator settled this capture after an uncertain outcome; its tagged snapshot is unclaimed and is not a backup of record".to_owned());
            serde_json::json!({
                "snapshot_id": id,
                "claimed": false,
                "scope": "the one snapshot that carried this operation's tag when the operator settled the capture; kept as evidence only. Its completeness, restic check, per-object retention and manifest are not recorded",
            })
        });
    let mut body = serde_json::json!({
        "receipt_schema": "rustiron-recovery-receipt/1",
        "host_id": capture.intent.host_id.as_str(),
        "host_epoch": capture.intent.host_epoch.as_str(),
        "site_id": capture.intent.site_id.as_str(),
        "operation": {
            "verb": "backup_capture",
            "operation_id": capture.intent.operation_id.as_str(),
            "grant_id": capture.intent.grant_id.as_str(),
            "plan_digest": capture.intent.plan_digest.as_str(),
            "grant_digest": capture.intent.grant_digest.as_str(),
            "started_at": capture.started_at.get(),
            "finished_at": capture.finished_at.map(rustiron_contracts::Timestamp::get),
            "state": if succeeded { "succeeded" } else { "failed" },
        },
        "snapshot_id": capture.snapshot_id,
        "capture_method": capture.method.map(rustiron_journal::CaptureMethod::as_str),
        "retention_days": capture.retention_days,
        "retention": retention,
        "recorded_window_s": window_s,
        "consistency": consistency,
        "manifest": manifest,
        "fields": fields,
        "cleanup": {"scope": "capture does not create a restore sandbox"},
        "limitations": limitations,
        "attester": receipt_attester(),
    });
    if let Some(unclaimed) = unclaimed {
        body["unclaimed_snapshot"] = unclaimed;
    }
    // W391 (v18): a refused capture names its stored code.
    if let Some(code) = capture.refusal.as_deref().filter(|_| !succeeded) {
        body["refusal"] = code.into();
    }
    seal_receipt(body)
}

const NO_EVIDENCE_OBJECT: &str = "no separate evidence object is stored for this field";

/// W366: on a settled capture, a tagged snapshot exists, so artifacts are
/// `unknown` rather than `not_run`. Shared with the observation (W379).
pub(crate) fn mark_unclaimed_artifacts(fields: &mut serde_json::Value) {
    fields["artifacts_complete"]["status"] = "unknown".into();
    fields["artifacts_complete"]["scope"] = "a snapshot carries this operation's tag, but the capture outcome was uncertain; whether it holds every source file is not known".into();
}

fn unix_seconds(time: rustiron_contracts::Timestamp) -> Result<i64, ExecutorError> {
    i64::try_from(time.get()).map_err(|_| ExecutorError::Unavailable)
}

/// Seven capture evidence fields. No digests, grant ids, or snapshot id.
/// `observed_at` is the journal finish time. `evidence_refs` stays empty
/// because this row does not name a separate evidence object.
pub(crate) fn capture_fields(
    succeeded: bool,
    method_known: bool,
    observed_at: i64,
) -> serde_json::Value {
    let field = |status: &str, scope: &str| {
        serde_json::json!({
            "status": status,
            "scope": scope,
            "observed_at": observed_at,
            "evidence_refs": [],
            "limitations": [NO_EVIDENCE_OBJECT],
        })
    };
    serde_json::json!({
        "artifacts_complete": field(
            if succeeded { "unknown" } else { "not_run" },
            if succeeded {
                "snapshot id recorded; the capture row does not count files or the database dump"
            } else {
                "no checked snapshot was recorded"
            },
        ),
        "repository_integrity_checked": field(
            if succeeded { "pass" } else { "not_run" },
            if succeeded {
                "succeeded is recorded only after restic check passes"
            } else {
                "restic check was not recorded as passed"
            },
        ),
        "decryption_tested": field("not_run", "capture does not decrypt the snapshot"),
        "application_consistency_assessed": field(
            if succeeded { "unknown" } else { "not_run" },
            if method_known {
                "admitted recipe uses a single-transaction dump followed by files; there is no shared freeze point or application read-back"
            } else {
                "the capture method is not recorded on this row; application consistency was not assessed"
            },
        ),
        "restored_in_isolation": field("not_run", "a capture is not a restore"),
        "health_checks_passed": field("not_run", "application health is a restore probe, not a capture"),
        "independent_copy_confirmed": field(
            "unknown",
            "the capture row does not store a destination; independence is unproven",
        ),
    })
}

/// The seven SPEC evidence fields of a RecoveryReceipt v1.
const SPEC_FIELDS: [&str; 7] = [
    "artifacts_complete",
    "repository_integrity_checked",
    "decryption_tested",
    "application_consistency_assessed",
    "restored_in_isolation",
    "health_checks_passed",
    "independent_copy_confirmed",
];

/// W374: why a stored probe receipt has no check result. A refused probe
/// stopped before any check, so its checks did not run. A probe that the
/// admin cleanup closed may have started a check, so its result is unknown.
enum MissingResult {
    Refused(String),
    AdminCleanup,
    NotRecorded,
}

impl MissingResult {
    fn of(receipt: &serde_json::Value) -> Self {
        let code = receipt["refused"].as_str().filter(|code| {
            !code.is_empty()
                && code
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte == b'_')
        });
        match code {
            Some(code) => Self::Refused(code.to_owned()),
            None if receipt["admin_cleanup"] == true => Self::AdminCleanup,
            None => Self::NotRecorded,
        }
    }

    fn status(&self) -> &'static str {
        match self {
            Self::Refused(_) => "not_run",
            Self::AdminCleanup | Self::NotRecorded => "unknown",
        }
    }

    fn scope(&self) -> String {
        match self {
            Self::Refused(code) => format!(
                "not attempted: the probe was refused with {code} before any sandbox or snapshot restore"
            ),
            Self::AdminCleanup => "no result recorded: the admin cleanup closed an interrupted probe; a check may have started, and none is claimed".to_owned(),
            Self::NotRecorded => "no result recorded: the stored probe receipt does not name this field; none is claimed".to_owned(),
        }
    }

    fn limitations(&self) -> Vec<String> {
        let reason = match self {
            Self::Refused(code) => format!(
                "the probe was refused with {code} before any sandbox; snapshot restore and decryption, restic check, isolated restore, database import, and application health were not attempted; a repository identity check can have run before the refusal"
            ),
            Self::AdminCleanup => "the admin cleanup closed an interrupted probe; no check result was recorded, so none is claimed".to_owned(),
            Self::NotRecorded => "the stored probe receipt records no check result; none is claimed".to_owned(),
        };
        vec![
            "derived at export from the probe journal row; the stored probe receipt states no limitations".to_owned(),
            reason,
            "no field claims a result that the stored probe receipt did not record".to_owned(),
        ]
    }
}

/// The stored limitations when they are a non-empty list of non-empty
/// strings, else the limitations of the missing result. When the stored
/// receipt named only some SPEC fields, the added ones are named.
fn probe_limitations(
    stored: &serde_json::Value,
    filled: &[&str],
    missing: &MissingResult,
) -> serde_json::Value {
    let mut limitations = non_empty_strings(stored).unwrap_or_else(|| missing.limitations());
    if !filled.is_empty() && filled.len() < SPEC_FIELDS.len() {
        limitations.push(format!(
            "the stored probe receipt did not name {}; the export states {} for each",
            filled.join(", "),
            missing.status()
        ));
    }
    serde_json::json!(limitations)
}

fn non_empty_strings(value: &serde_json::Value) -> Option<Vec<String>> {
    let rows = value.as_array().filter(|rows| !rows.is_empty())?;
    rows.iter()
        .map(|row| {
            row.as_str()
                .filter(|text| !text.is_empty())
                .map(str::to_owned)
        })
        .collect()
}

/// Fill SPEC keys the stored probe receipt does not have. Status and scope
/// stay as recorded. An existing time or ref list is kept. W374: a SPEC
/// field that the stored receipt does not name is added with the status of
/// the missing result. The names of the added fields are returned.
fn completed_fields(
    fields: serde_json::Value,
    observed_at: Option<i64>,
    missing: &MissingResult,
) -> (serde_json::Value, Vec<&'static str>) {
    let mut map = match fields {
        serde_json::Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    let mut filled = Vec::new();
    for name in SPEC_FIELDS {
        if !map.contains_key(name) {
            map.insert(
                name.to_owned(),
                serde_json::json!({"status": missing.status(), "scope": missing.scope()}),
            );
            filled.push(name);
        }
    }
    for value in map.values_mut() {
        let Some(entry) = value.as_object_mut() else {
            continue;
        };
        if !entry.contains_key("observed_at")
            && let Some(seconds) = observed_at
        {
            entry.insert("observed_at".to_owned(), serde_json::json!(seconds));
        }
        if !entry.contains_key("evidence_refs") {
            entry.insert("evidence_refs".to_owned(), serde_json::json!([]));
        }
        if entry
            .get("limitations")
            .and_then(non_empty_strings)
            .is_none()
        {
            entry.insert(
                "limitations".to_owned(),
                serde_json::json!([NO_EVIDENCE_OBJECT]),
            );
        }
    }
    (serde_json::Value::Object(map), filled)
}

fn receipt_attester() -> serde_json::Value {
    serde_json::json!({
        "kind": "local_executor_self_attested",
        "note": "root-written local record; not immutable proof and not independent evidence",
    })
}

fn seal_receipt(body: serde_json::Value) -> Result<serde_json::Value, ExecutorError> {
    let text = body.to_string();
    let canonical = rustiron_contracts::CanonicalObject::decode(text.as_bytes())
        .map_err(|_| ExecutorError::Unavailable)?;
    let digest = Sha256::digest(canonical.as_bytes());
    Ok(serde_json::json!({
        "body": body,
        "body_sha256": digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
    }))
}

#[cfg(test)]
mod tests {
    use rustiron_contracts::{
        Id, Timestamp,
        approval::{Sha256Digest, SiteId, SnapshotId},
    };
    use rustiron_journal::{Probe, ProbeIntent, ProbeState};

    use super::recovery_receipt;

    fn identity(text: &str) -> Id {
        Id::try_from(text.to_owned()).unwrap()
    }

    #[test]
    fn a_probe_export_keeps_recorded_status_and_fills_missing_spec_keys() {
        let digest = |byte: u8| Sha256Digest::try_from(format!("{byte:02x}").repeat(32)).unwrap();
        let probe = Probe {
            backup_policy_digest: None,
            intent: ProbeIntent {
                operation_id: identity("op_probe"),
                idempotency_key: identity("probe_key"),
                grant_id: identity("probe_grant"),
                nonce: identity("probe_nonce"),
                plan_digest: digest(1),
                grant_digest: digest(2),
                host_id: identity("host_fixture"),
                host_epoch: identity("epoch_fixture"),
                site_id: SiteId::try_from("blog13".to_owned()).unwrap(),
                snapshot_id: SnapshotId::try_from("ab".repeat(32)).unwrap(),
                probe_account: "rp_abcdef".to_owned(),
                expires_at: Timestamp::try_from(2_000).unwrap(),
            },
            started_at: Timestamp::try_from(1_000).unwrap(),
            state: ProbeState::Passed,
            receipt: None,
            finished_at: Some(Timestamp::try_from(1_300).unwrap()),
        };
        let inventory = serde_json::json!({"schema_version":2,"status":"complete","reason":null,"files":2,"dump":true,"entries":2,"max_depth":0,"world_writable":0});
        let stored = serde_json::json!({
            "inventory": inventory,
            "fields": {
                "artifacts_complete": {
                    "status": "pass",
                    "scope": "files",
                    "observed_at": 50,
                    "evidence_refs": ["journal:op_probe"],
                },
                "independent_copy_confirmed": {"status": "fail", "scope": "local"},
            }
        });
        let document = recovery_receipt(&probe, stored).unwrap();
        let kept = &document["body"]["fields"]["artifacts_complete"];
        assert_eq!(kept["status"], "pass");
        assert_eq!(kept["scope"], "files");
        assert_eq!(kept["observed_at"], 50);
        assert_eq!(kept["evidence_refs"][0], "journal:op_probe");
        let filled = &document["body"]["fields"]["independent_copy_confirmed"];
        assert_eq!(filled["status"], "fail");
        assert_eq!(filled["observed_at"], 1_300);
        assert!(filled["evidence_refs"].as_array().unwrap().is_empty());
        assert_eq!(
            filled["limitations"][0],
            "no separate evidence object is stored for this field"
        );
        assert!(document["body"].get("grant_id").is_none());
        assert_eq!(document["body"]["inventory"], inventory);
        // W374: the five fields the stored receipt did not name are stated
        // as unknown, and the export names them.
        let added = &document["body"]["fields"]["decryption_tested"];
        assert_eq!(added["status"], "unknown");
        assert!(
            added["scope"]
                .as_str()
                .unwrap()
                .contains("no result recorded")
        );
        let last = limitations(&document).pop().unwrap();
        assert!(
            last.contains("did not name repository_integrity_checked, decryption_tested"),
            "{last}"
        );
    }

    fn probe(state: ProbeState) -> Probe {
        let digest = |byte: u8| Sha256Digest::try_from(format!("{byte:02x}").repeat(32)).unwrap();
        Probe {
            backup_policy_digest: None,
            intent: ProbeIntent {
                operation_id: identity("op_probe"),
                idempotency_key: identity("probe_key"),
                grant_id: identity("probe_grant"),
                nonce: identity("probe_nonce"),
                plan_digest: digest(1),
                grant_digest: digest(2),
                host_id: identity("host_fixture"),
                host_epoch: identity("epoch_fixture"),
                site_id: SiteId::try_from("blog13".to_owned()).unwrap(),
                snapshot_id: SnapshotId::try_from("ab".repeat(32)).unwrap(),
                probe_account: "rp_abcdef".to_owned(),
                expires_at: Timestamp::try_from(2_000).unwrap(),
            },
            started_at: Timestamp::try_from(1_000).unwrap(),
            state,
            receipt: None,
            finished_at: Some(Timestamp::try_from(1_000).unwrap()),
        }
    }

    fn limitations(document: &serde_json::Value) -> Vec<String> {
        document["body"]["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row.as_str().unwrap().to_owned())
            .collect()
    }

    fn statuses(document: &serde_json::Value) -> Vec<(String, String)> {
        super::SPEC_FIELDS
            .iter()
            .map(|name| {
                let field = &document["body"]["fields"][*name];
                (
                    field["status"].as_str().unwrap().to_owned(),
                    field["scope"].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    }

    /// W374: the stored receipt of a refused probe (product W320 shape)
    /// has no fields or limitations. The export states each field as
    /// not_run with the refusal and says what was not attempted.
    #[test]
    fn a_refused_probe_export_states_every_field_not_run() {
        let stored = serde_json::json!({
            "receipt_schema": "rustiron-restore-probe/2",
            "probe_account": "rp_abcdef",
            "refused": "NOT_ADMITTED_FOR_EFFECT",
            "note": "the admin helper refused before creating anything; no check is claimed",
            "cleanup": {"status": "complete", "leftover_resources": 0, "removal_failures": 0, "unverified": []},
        });
        let document = recovery_receipt(&probe(ProbeState::Failed), stored.clone()).unwrap();
        let body = &document["body"];
        assert_eq!(body["operation"]["state"], "failed");
        assert_eq!(body["cleanup"], stored["cleanup"]);
        for (status, scope) in statuses(&document) {
            assert_eq!(status, "not_run");
            assert!(
                scope.contains("refused with NOT_ADMITTED_FOR_EFFECT"),
                "{scope}"
            );
        }
        let field = &body["fields"]["independent_copy_confirmed"];
        assert_eq!(field["observed_at"], 1_000);
        assert!(field["evidence_refs"].as_array().unwrap().is_empty());
        let rows = limitations(&document);
        assert_eq!(rows.len(), 3);
        assert!(rows[1].contains("NOT_ADMITTED_FOR_EFFECT"));
        assert!(rows[1].contains("were not attempted"));
        // The lab refusal shape (W175) is exported the same way.
        let mut lab = stored;
        lab["receipt_schema"] = "rustiron-lab-restore-probe/1".into();
        let exported = recovery_receipt(&probe(ProbeState::Failed), lab).unwrap();
        assert_eq!(exported["body"]["fields"], body["fields"]);
    }

    /// W374: a probe closed by the admin cleanup may have started a check,
    /// so its fields are unknown, never not_run or pass.
    #[test]
    fn an_admin_cleanup_probe_export_states_every_field_unknown() {
        let stored = serde_json::json!({
            "receipt_schema": "rustiron-lab-restore-probe/1",
            "probe_account": "rp_abcdef",
            "admin_cleanup": true,
            "cleanup": {"status": "complete", "leftover_resources": 0, "removal_failures": 0, "unverified": []},
            "note": "probe interrupted or left resources; no check is claimed",
        });
        for state in [ProbeState::Failed, ProbeState::CleanupIncomplete] {
            let document = recovery_receipt(&probe(state), stored.clone()).unwrap();
            for (status, scope) in statuses(&document) {
                assert_eq!(status, "unknown");
                assert!(scope.contains("admin cleanup"), "{scope}");
            }
            assert!(limitations(&document)[1].contains("no check result was recorded"));
        }
    }

    /// A refusal code that is not an error code is not copied into text.
    #[test]
    fn an_unexpected_refusal_value_is_not_quoted() {
        let stored = serde_json::json!({"refused": "x; pass"});
        let document = recovery_receipt(&probe(ProbeState::Failed), stored).unwrap();
        assert!(!document.to_string().contains("x; pass"));
        for (status, _) in statuses(&document) {
            assert_eq!(status, "unknown");
        }
    }

    /// A complete stored receipt is exported unchanged in its fields and
    /// limitations.
    #[test]
    fn a_complete_probe_receipt_keeps_its_fields_and_limitations() {
        let fields: serde_json::Map<String, serde_json::Value> = super::SPEC_FIELDS
            .iter()
            .map(|name| {
                (
                    (*name).to_owned(),
                    serde_json::json!({"status": "fail", "scope": "lab"}),
                )
            })
            .collect();
        let stored = serde_json::json!({
            "fields": fields,
            "limitations": ["lab only, synthetic keys"],
        });
        let document = recovery_receipt(&probe(ProbeState::Failed), stored).unwrap();
        assert_eq!(limitations(&document), ["lab only, synthetic keys"]);
        for (status, scope) in statuses(&document) {
            assert_eq!((status.as_str(), scope.as_str()), ("fail", "lab"));
        }
    }
}
