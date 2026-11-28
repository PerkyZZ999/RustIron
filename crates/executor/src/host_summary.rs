//! D-104 (W779): the closed host summary, projected from the read-only
//! observation. A field the projection does not name never leaves here.

use std::collections::BTreeMap;

use rustiron_contracts::{
    Id, Text, Timestamp,
    summary::{CertificateState, HostSummary, RecordedRun, SiteBackups, SiteState},
};
use serde_json::Value;

use crate::ExecutorError;

fn id(value: &Value) -> Result<Id, ExecutorError> {
    value
        .as_str()
        .and_then(|text| Id::try_from(text.to_owned()).ok())
        .ok_or(ExecutorError::Unavailable)
}

fn optional_id(value: &Value) -> Result<Option<Id>, ExecutorError> {
    if value.is_null() {
        Ok(None)
    } else {
        id(value).map(Some)
    }
}

fn text(value: &Value) -> Result<Text, ExecutorError> {
    value
        .as_str()
        .and_then(|text| Text::try_from(text.to_owned()).ok())
        .ok_or(ExecutorError::Unavailable)
}

fn time(value: &Value) -> Result<Timestamp, ExecutorError> {
    value
        .as_u64()
        .and_then(|seconds| Timestamp::try_from(seconds).ok())
        .ok_or(ExecutorError::Unavailable)
}

fn rows(value: &Value) -> &[Value] {
    value.as_array().map_or(&[], Vec::as_slice)
}

/// The newest run per site, by start time, from `captures` or `probes`.
fn newest(observation: &Value, key: &str) -> Result<BTreeMap<String, RecordedRun>, ExecutorError> {
    let mut newest: BTreeMap<String, RecordedRun> = BTreeMap::new();
    for row in rows(&observation[key]) {
        // A product (host) capture names no site; it is not a site backup.
        let Some(site) = row["site_id"].as_str() else {
            continue;
        };
        let run = RecordedRun {
            operation_id: id(&row["operation_id"])?,
            state: id(&row["state"])?,
            started_at: time(&row["started_at"])?,
            finished_at: if row["finished_at"].is_null() {
                None
            } else {
                Some(time(&row["finished_at"])?)
            },
        };
        let replace = newest
            .get(site)
            .is_none_or(|current| current.started_at.get() <= run.started_at.get());
        if replace {
            newest.insert(site.to_owned(), run);
        }
    }
    Ok(newest)
}

/// Projects an observation document; `now` is the summary's `observed_at`.
pub(crate) fn project(observation: &Value, now: u64) -> Result<HostSummary, ExecutorError> {
    let host = &observation["host"];
    let sites = rows(&observation["sites"])
        .iter()
        .map(|site| {
            Ok(SiteState {
                site_id: id(&site["site_id"])?,
                hostname: text(&site["hostname"])?,
                state: id(&site["state"])?,
                failed_step: optional_id(&site["failed_step"])?,
                ejected: site["ejected"].as_bool().unwrap_or(false),
            })
        })
        .collect::<Result<Vec<_>, ExecutorError>>()?;
    let certificates = rows(&observation["certificates"])
        .iter()
        .map(|served| {
            Ok(CertificateState {
                site_id: id(&served["site_id"])?,
                hostname: text(&served["hostname"])?,
                not_after: time(&served["not_after"])?,
                finding: optional_id(&served["finding"])?,
                last_renewal_failed: served["last_renewal_failed"].as_bool().unwrap_or(false),
                renewed_by: id(&served["renewed_by"])?,
            })
        })
        .collect::<Result<Vec<_>, ExecutorError>>()?;
    let mut captures = newest(observation, "captures")?;
    let mut probes = newest(observation, "probes")?;
    let names: std::collections::BTreeSet<String> =
        captures.keys().chain(probes.keys()).cloned().collect();
    let backups = names
        .into_iter()
        .map(|site| {
            Ok(SiteBackups {
                site_id: Id::try_from(site.clone()).map_err(|_| ExecutorError::Unavailable)?,
                capture: captures.remove(&site),
                probe: probes.remove(&site),
            })
        })
        .collect::<Result<Vec<_>, ExecutorError>>()?;
    let summary = HostSummary {
        observed_at: Timestamp::try_from(now).map_err(|_| ExecutorError::Unavailable)?,
        journal_last_time: Timestamp::try_from(
            u64::try_from(observation["journal_last_time"].as_i64().unwrap_or(0)).unwrap_or(0),
        )
        .map_err(|_| ExecutorError::Unavailable)?,
        signature_verifier_matches: host["signature_verifier"]["matches_enrollment"]
            .as_bool()
            .unwrap_or(false),
        backup_destination_enrolled: !host["backup_destination"].is_null(),
        backup_retention_days: host["backup_retention_days"]
            .as_u64()
            .and_then(|days| u32::try_from(days).ok()),
        sites,
        certificates,
        backups,
    };
    summary.validate().map_err(|_| ExecutorError::Unavailable)?;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::project;
    use serde_json::json;

    fn observation() -> serde_json::Value {
        json!({
            "journal_last_time": 900,
            "host": {
                "backup_destination": "store1", "backup_retention_days": 30,
                "signature_verifier": {"matches_enrollment": true},
                "signer": {"fingerprint": "SHA256:x"}, "receipt_key": {"present": true},
            },
            "sites": [
                {"site_id": "blog1", "hostname": "blog1.example.test", "state": "succeeded",
                 "failed_step": null, "ejected": false, "operation_id": "op_p1", "quota": {"kib": 5}},
                {"site_id": "blog2", "hostname": "blog2.example.test", "state": "quarantined",
                 "failed_step": "database", "ejected": false},
            ],
            "certificates": [
                {"site_id": "blog1", "hostname": "blog1.example.test", "not_after": 2000,
                 "certificate_sha256": "ab", "finding": "expires_soon",
                 "last_renewal_failed": false, "renewed_by": "rustiron"},
            ],
            "captures": [
                {"operation_id": "cap_old", "site_id": "blog1", "state": "succeeded",
                 "started_at": 100, "finished_at": 110, "snapshot_id": "s1"},
                {"operation_id": "cap_new", "site_id": "blog1", "state": "succeeded",
                 "started_at": 200, "finished_at": 210, "snapshot_id": "s2"},
                {"operation_id": "cap_host", "site_id": null, "state": "succeeded",
                 "started_at": 300, "finished_at": 310},
            ],
            "probes": [
                {"operation_id": "probe_1", "site_id": "blog2", "state": "failed",
                 "started_at": 150, "finished_at": null},
            ],
            "admissions": [{"plan": "secret plan bytes"}],
            "signed_objects": [{"grant": "secret grant bytes"}],
        })
    }

    #[test]
    fn the_summary_keeps_only_named_fields_and_the_newest_run_per_site() {
        let summary = project(&observation(), 1000).unwrap();
        assert_eq!(summary.sites.len(), 2);
        assert_eq!(
            summary.sites[1].failed_step.as_ref().unwrap().as_str(),
            "database"
        );
        assert_eq!(
            summary.certificates[0].finding.as_ref().unwrap().as_str(),
            "expires_soon"
        );
        assert_eq!(summary.backups.len(), 2);
        let blog1 = &summary.backups[0];
        assert_eq!(
            blog1.capture.as_ref().unwrap().operation_id.as_str(),
            "cap_new"
        );
        assert!(blog1.probe.is_none());
        assert!(
            summary.backups[1]
                .probe
                .as_ref()
                .unwrap()
                .finished_at
                .is_none()
        );
        assert!(summary.backup_destination_enrolled);
        let text = serde_json::to_string(&summary).unwrap();
        for leaked in [
            "secret",
            "snapshot_id",
            "quota",
            "certificate_sha256",
            "signer",
            "cap_host",
        ] {
            assert!(!text.contains(leaked), "{leaked} leaked");
        }
    }

    #[test]
    fn a_malformed_row_refuses_the_whole_summary() {
        let mut bad = observation();
        bad["sites"][0]["site_id"] = json!("../etc");
        assert!(project(&bad, 1000).is_err());
        let mut empty = observation();
        empty["sites"] = json!(null);
        empty["certificates"] = json!(null);
        assert!(project(&empty, 1000).unwrap().sites.is_empty());
    }
}
