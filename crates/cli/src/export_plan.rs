//! D-089 (W545): the offline export plan of one capture's database dump.
//!
//! The operator runs it on the PC with two files: the site repository's
//! `restic snapshots --json` listing, read with the site's read-only fetch
//! key, and an executor observation, which carries the journal-recorded
//! captures. It names one capture operation. It contacts nothing and
//! changes nothing. It prints the capture's snapshot, the dump's fixed path
//! in that snapshot, and the `restic` arguments that write the dump to
//! standard output.
//!
//! The capture must be a succeeded capture of the site in the observation,
//! and its snapshot must be in the listing with the site's dump path. A
//! snapshot that is only in the listing is not a recorded capture and is
//! never planned. Otherwise the command names the refusal and exits 3.

use std::{
    io::{self, Write},
    path::Path,
    process::ExitCode,
};

use rustiron_contracts::{ErrorCode, Id, approval::SiteId};
use serde::Deserialize;

use crate::{Output, emit, failure, file_input};

/// Largest accepted listing or observation.
const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Deserialize)]
pub(crate) struct Snapshot {
    pub(crate) id: String,
    pub(crate) paths: Vec<String>,
}

#[derive(Deserialize)]
struct Observation {
    captures: Vec<Capture>,
}

#[derive(Deserialize)]
pub(crate) struct Capture {
    pub(crate) operation_id: String,
    pub(crate) site_id: String,
    pub(crate) state: String,
    pub(crate) snapshot_id: Option<String>,
    pub(crate) finished_at: Option<i64>,
}

/// Why no export is planned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Refusal {
    /// No succeeded capture of the site has this operation.
    NotRecorded,
    /// The listing does not show the capture's snapshot.
    NotListed,
    /// The listed snapshot does not hold the site's dump path.
    NoDump,
}

impl Refusal {
    fn code(self) -> &'static str {
        match self {
            Self::NotRecorded => "capture_not_recorded",
            Self::NotListed => "snapshot_not_listed",
            Self::NoDump => "dump_not_in_snapshot",
        }
    }
}

/// The planned export: the snapshot, the journal's finish time, and the path.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Export {
    pub(crate) snapshot: String,
    pub(crate) finished_at: i64,
    pub(crate) path: String,
}

/// The dump's fixed path in every capture of the site (W203).
pub(crate) fn dump_path(site: &SiteId) -> String {
    format!(
        "/srv/sites/{}/tmp/rustiron-capture.sql",
        site.account_name()
    )
}

fn full_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The export of `operation`, or why there is none.
pub(crate) fn plan(
    listing: &[Snapshot],
    captures: &[Capture],
    site: &SiteId,
    operation: &Id,
) -> Result<Export, Refusal> {
    let mut recorded = captures.iter().filter(|capture| {
        capture.operation_id == operation.as_str()
            && capture.site_id == site.as_str()
            && capture.state == "succeeded"
    });
    let (Some(capture), None) = (recorded.next(), recorded.next()) else {
        return Err(Refusal::NotRecorded);
    };
    let (Some(snapshot), Some(finished_at)) = (&capture.snapshot_id, capture.finished_at) else {
        return Err(Refusal::NotRecorded);
    };
    if !full_id(snapshot) {
        return Err(Refusal::NotRecorded);
    }
    let path = dump_path(site);
    let listed = listing
        .iter()
        .find(|entry| entry.id == *snapshot)
        .ok_or(Refusal::NotListed)?;
    if !listed.paths.contains(&path) {
        return Err(Refusal::NoDump);
    }
    Ok(Export {
        snapshot: snapshot.clone(),
        finished_at,
        path,
    })
}

fn read_inputs(
    snapshots: &Path,
    observation: &Path,
) -> Result<(Vec<Snapshot>, Vec<Capture>), ErrorCode> {
    let listing: Vec<Snapshot> =
        serde_json::from_slice(&file_input::read(snapshots, MAX_INPUT_BYTES)?)
            .map_err(|_| ErrorCode::InvalidRequest)?;
    if listing.iter().any(|entry| !full_id(&entry.id)) {
        return Err(ErrorCode::InvalidRequest);
    }
    let observed: Observation =
        serde_json::from_slice(&file_input::read(observation, MAX_INPUT_BYTES)?)
            .map_err(|_| ErrorCode::InvalidRequest)?;
    Ok((listing, observed.captures))
}

pub(crate) fn run(
    snapshots: &Path,
    observation: &Path,
    site: &str,
    capture: &str,
    output: Output,
) -> ExitCode {
    let (Ok(site), Ok(operation)) = (
        SiteId::try_from(site.to_owned()),
        Id::try_from(capture.to_owned()),
    ) else {
        return emit(&failure(ErrorCode::InvalidRequest), output);
    };
    let (listing, captures) = match read_inputs(snapshots, observation) {
        Ok(inputs) => inputs,
        Err(error) => return emit(&failure(error), output),
    };
    let result = plan(&listing, &captures, &site, &operation);
    let mut stdout = io::stdout().lock();
    let written = match (&result, output) {
        (Ok(export), Output::Json) => writeln!(
            stdout,
            "{}",
            serde_json::json!({
                "site_id": site.as_str(),
                "capture_operation_id": operation.as_str(),
                "snapshot_id": export.snapshot,
                "finished_at": export.finished_at,
                "dump_path": export.path,
                "restic_args": ["dump", "--no-lock", export.snapshot, export.path],
            })
        ),
        (Ok(export), Output::Human) => write!(
            stdout,
            "site {} capture {}\nsnapshot {}\nfinished_at {}\nrun: restic dump --no-lock {} {}\n",
            site.as_str(),
            operation.as_str(),
            export.snapshot,
            export.finished_at,
            export.snapshot,
            export.path
        ),
        (Err(refusal), Output::Json) => writeln!(
            stdout,
            "{}",
            serde_json::json!({
                "site_id": site.as_str(),
                "capture_operation_id": operation.as_str(),
                "refusal": refusal.code(),
            })
        ),
        (Err(refusal), Output::Human) => write!(
            stdout,
            "site {} capture {}\nREFUSED {}\n",
            site.as_str(),
            operation.as_str(),
            refusal.code()
        ),
    };
    match (written, result.is_ok()) {
        (Err(_), _) => ExitCode::from(7),
        (Ok(()), true) => ExitCode::SUCCESS,
        (Ok(()), false) => ExitCode::from(3),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site() -> SiteId {
        SiteId::try_from("blog1".to_owned()).unwrap()
    }
    fn op(text: &str) -> Id {
        Id::try_from(text.to_owned()).unwrap()
    }
    fn id(c: char) -> String {
        c.to_string().repeat(64)
    }
    fn capture(operation: &str, site: &str, state: &str, snapshot: Option<String>) -> Capture {
        Capture {
            operation_id: operation.to_owned(),
            site_id: site.to_owned(),
            state: state.to_owned(),
            snapshot_id: snapshot,
            finished_at: Some(1000),
        }
    }
    fn listed(snapshot: String, with_dump: bool) -> Snapshot {
        let mut paths = vec!["/srv/sites/rs_blog1/html".to_owned()];
        if with_dump {
            paths.push("/srv/sites/rs_blog1/tmp/rustiron-capture.sql".to_owned());
        }
        Snapshot {
            id: snapshot,
            paths,
        }
    }

    #[test]
    fn the_dump_path_comes_from_the_site_id_only() {
        assert_eq!(
            dump_path(&site()),
            "/srv/sites/rs_blog1/tmp/rustiron-capture.sql"
        );
    }

    #[test]
    fn only_a_listed_recorded_capture_of_the_site_with_its_dump_is_planned() {
        let captures = [
            capture("cap_a", "blog1", "succeeded", Some(id('a'))),
            capture("cap_f", "blog1", "failed", None),
            capture("cap_o", "blog2", "succeeded", Some(id('o'))),
            capture("cap_n", "blog1", "succeeded", Some(id('9'))),
            capture("cap_d", "blog1", "succeeded", Some(id('d'))),
        ];
        let listing = [
            listed(id('a'), true),
            listed(id('o'), true),
            listed(id('d'), false),
            // Only in the listing: never planned.
            listed(id('u'), true),
        ];
        assert_eq!(
            plan(&listing, &captures, &site(), &op("cap_a")),
            Ok(Export {
                snapshot: id('a'),
                finished_at: 1000,
                path: "/srv/sites/rs_blog1/tmp/rustiron-capture.sql".to_owned(),
            })
        );
        for (operation, refusal) in [
            ("cap_f", Refusal::NotRecorded),
            ("cap_o", Refusal::NotRecorded),
            ("cap_missing", Refusal::NotRecorded),
            ("cap_n", Refusal::NotListed),
            ("cap_d", Refusal::NoDump),
        ] {
            assert_eq!(
                plan(&listing, &captures, &site(), &op(operation)),
                Err(refusal),
                "{operation}"
            );
        }
        // A short snapshot ID or two rows with one operation are refused.
        let short = [capture(
            "cap_s",
            "blog1",
            "succeeded",
            Some("abc".to_owned()),
        )];
        assert_eq!(
            plan(&listing, &short, &site(), &op("cap_s")),
            Err(Refusal::NotRecorded)
        );
        let twice = [
            capture("cap_a", "blog1", "succeeded", Some(id('a'))),
            capture("cap_a", "blog1", "succeeded", Some(id('a'))),
        ];
        assert_eq!(
            plan(&listing, &twice, &site(), &op("cap_a")),
            Err(Refusal::NotRecorded)
        );
    }
}
