//! Closed metadata report shared by the unprivileged worker, its caller and
//! the fuzz workspace (which includes this file by path; serde only).
use serde::{Deserialize, Serialize};

pub(crate) const MAX_ENTRIES: u64 = 100_000;
pub(crate) const MAX_DEPTH: u32 = 64;
pub(crate) const MAX_REPORT_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Status {
    Complete,
    Error,
    Limit,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Reason {
    Io,
    Unsupported,
    Changed,
    Identity,
    Entries,
    Depth,
    Time,
    /// W222: a setuid or setgid regular file (refused, never imported).
    Privileged,
    /// W232: a restored directory writable by others (refused).
    WorldWritableDirectory,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Report {
    pub(crate) schema_version: u8,
    pub(crate) status: Status,
    #[serde(deserialize_with = "nullable")]
    pub(crate) reason: Option<Reason>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) files: Option<u64>,
    #[serde(deserialize_with = "nullable")]
    pub(crate) dump: Option<bool>,
    pub(crate) entries: u64,
    pub(crate) max_depth: u32,
    /// W222: regular files writable by others; counted, not refused
    /// (`complete` only).
    #[serde(deserialize_with = "nullable")]
    pub(crate) world_writable: Option<u64>,
    /// W378 (version 3): entries outside the captured site paths (`html/`
    /// and the dump), counted by name where they first leave those paths and
    /// never descended; included in `entries` (`complete` only).
    #[serde(deserialize_with = "nullable")]
    pub(crate) extra_paths: Option<u64>,
}

fn nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::deserialize(d)
}

/// The caller's closed decoder: bounded bytes, known members only, version 3
/// (version 2 added `world_writable`, version 3 `extra_paths`), bounded
/// counts, and a status-specific shape (only `complete` claims files).
pub(crate) fn decode(bytes: &[u8]) -> Option<Report> {
    if bytes.len() > MAX_REPORT_BYTES {
        return None;
    }
    let report: Report = serde_json::from_slice(bytes).ok()?;
    let shape = match report.status {
        Status::Complete => {
            report.reason.is_none()
                && report.dump.is_some()
                && report.files.is_some_and(|files| {
                    report
                        .extra_paths
                        .and_then(|extra| extra.checked_add(files))
                        .is_some_and(|counted| counted <= report.entries)
                        && report.world_writable.is_some_and(|w| w <= files)
                })
        }
        Status::Error => {
            matches!(
                report.reason,
                Some(
                    Reason::Io
                        | Reason::Unsupported
                        | Reason::Changed
                        | Reason::Identity
                        | Reason::Privileged
                        | Reason::WorldWritableDirectory
                )
            ) && report.files.is_none()
                && report.dump.is_none()
                && report.world_writable.is_none()
                && report.extra_paths.is_none()
        }
        Status::Limit => {
            matches!(
                report.reason,
                Some(Reason::Entries | Reason::Depth | Reason::Time)
            ) && report.files.is_none()
                && report.dump.is_none()
                && report.world_writable.is_none()
                && report.extra_paths.is_none()
        }
    };
    (report.schema_version == 3
        && report.entries <= MAX_ENTRIES
        && report.max_depth <= MAX_DEPTH
        && shape)
        .then_some(report)
}
