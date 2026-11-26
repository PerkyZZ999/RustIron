//! D-079 (W503): the offline retention plan of one site's repository.
//!
//! The retention authority runs it on the operator PC with two files: the
//! repository's `restic snapshots --json` listing, read with that authority's
//! own key, and an executor observation, which carries the journal-recorded
//! captures. It contacts nothing and changes nothing. It prints which
//! snapshots the authority may forget.
//!
//! The rule never counts snapshots, so a flood of new snapshots cannot push
//! out a recorded capture:
//! - the newest recorded capture is always kept, so a long outage never
//!   leaves the site without a good snapshot;
//! - each recorded capture that finished within the window is kept, by the
//!   journal's time, not the snapshot's self-reported time;
//! - an unrecorded snapshot within the window is kept (it costs only space);
//! - everything else may be forgotten.
//!
//! A recorded capture that the listing does not show was hidden or removed.
//! It is reported, and the command exits 3.

use std::{
    collections::BTreeSet,
    io::{self, Write},
    path::Path,
    process::ExitCode,
};

use rustiron_contracts::{ErrorCode, approval::SiteId};
use serde::Deserialize;

use crate::{Output, emit, failure, file_input};

/// Largest accepted listing or observation.
const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;
/// The D-010 retention floor and the projection's ceiling.
pub(crate) const MIN_KEEP_DAYS: u32 = 30;
pub(crate) const MAX_KEEP_DAYS: u32 = 3650;
const DAY: i64 = 86_400;

#[derive(Deserialize)]
struct Snapshot {
    id: String,
    time: String,
}

#[derive(Deserialize)]
struct Observation {
    captures: Vec<Capture>,
}

#[derive(Deserialize)]
struct Capture {
    site_id: String,
    state: String,
    snapshot_id: Option<String>,
    finished_at: Option<i64>,
}

/// One recorded capture: its snapshot and the journal's finish time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Recorded {
    pub(crate) snapshot: String,
    pub(crate) finished_at: i64,
}

/// One listed snapshot and its self-reported time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Listed {
    pub(crate) id: String,
    pub(crate) time: i64,
}

/// What the authority may do with each snapshot.
#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct Plan {
    pub(crate) keep_recorded: Vec<String>,
    pub(crate) keep_unrecorded: Vec<String>,
    pub(crate) forget: Vec<String>,
    pub(crate) missing_recorded: Vec<String>,
}

fn full_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Days from 1970-01-01 to a proleptic Gregorian date (Howard Hinnant).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Seconds since the epoch of an RFC 3339 time as restic prints it:
/// `YYYY-MM-DDTHH:MM:SS[.fraction](Z|±HH:MM)`. Anything else is `None`.
pub(crate) fn parse_time(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    let number = |range: std::ops::Range<usize>| -> Option<i64> {
        let part = text.get(range)?;
        part.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| part.parse().ok())?
    };
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let mut rest = &text[19..];
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        rest = &fraction[digits..];
    }
    let offset = match rest {
        "Z" => 0,
        _ => {
            let sign = match rest.as_bytes().first() {
                Some(b'+') => 1,
                Some(b'-') => -1,
                _ => return None,
            };
            let zone = &rest[1..];
            if zone.len() != 5 || zone.as_bytes()[2] != b':' {
                return None;
            }
            let (hours, minutes): (i64, i64) = (zone[..2].parse().ok()?, zone[3..].parse().ok()?);
            if hours > 23
                || minutes > 59
                || !zone[..2]
                    .bytes()
                    .chain(zone[3..].bytes())
                    .all(|b| b.is_ascii_digit())
            {
                return None;
            }
            sign * (hours * 3600 + minutes * 60)
        }
    };
    Some(days_from_civil(year, month, day) * DAY + hour * 3600 + minute * 60 + second - offset)
}

/// The D-079 rule. `now` and every time are seconds since the epoch.
pub(crate) fn plan(listed: &[Listed], recorded: &[Recorded], now: i64, keep_days: u32) -> Plan {
    let window_start = now - i64::from(keep_days) * DAY;
    let newest = recorded
        .iter()
        .max_by_key(|capture| capture.finished_at)
        .map(|capture| capture.snapshot.as_str());
    let kept_recorded: BTreeSet<&str> = recorded
        .iter()
        .filter(|capture| {
            Some(capture.snapshot.as_str()) == newest || capture.finished_at >= window_start
        })
        .map(|capture| capture.snapshot.as_str())
        .collect();
    let all_recorded: BTreeSet<&str> = recorded.iter().map(|c| c.snapshot.as_str()).collect();
    let listed_ids: BTreeSet<&str> = listed.iter().map(|s| s.id.as_str()).collect();
    let mut result = Plan::default();
    for snapshot in listed {
        let id = snapshot.id.as_str();
        if kept_recorded.contains(id) {
            result.keep_recorded.push(id.to_owned());
        } else if !all_recorded.contains(id) && snapshot.time >= window_start {
            result.keep_unrecorded.push(id.to_owned());
        } else {
            result.forget.push(id.to_owned());
        }
    }
    result.missing_recorded = all_recorded
        .iter()
        .filter(|id| !listed_ids.contains(**id))
        .map(|id| (*id).to_owned())
        .collect();
    for list in [
        &mut result.keep_recorded,
        &mut result.keep_unrecorded,
        &mut result.forget,
    ] {
        list.sort();
        list.dedup();
    }
    result
}

fn read_inputs(
    snapshots: &Path,
    observation: &Path,
    site: &SiteId,
) -> Result<(Vec<Listed>, Vec<Recorded>), ErrorCode> {
    let listing: Vec<Snapshot> =
        serde_json::from_slice(&file_input::read(snapshots, MAX_INPUT_BYTES)?)
            .map_err(|_| ErrorCode::InvalidRequest)?;
    let observed: Observation =
        serde_json::from_slice(&file_input::read(observation, MAX_INPUT_BYTES)?)
            .map_err(|_| ErrorCode::InvalidRequest)?;
    let listed = listing
        .into_iter()
        .map(|snapshot| {
            let time = parse_time(&snapshot.time).ok_or(ErrorCode::InvalidRequest)?;
            full_id(&snapshot.id)
                .then_some(Listed {
                    id: snapshot.id,
                    time,
                })
                .ok_or(ErrorCode::InvalidRequest)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut recorded = Vec::new();
    for capture in observed.captures {
        if capture.site_id != site.as_str() || capture.state != "succeeded" {
            continue;
        }
        match (capture.snapshot_id, capture.finished_at) {
            (Some(snapshot), Some(finished_at)) if full_id(&snapshot) => {
                recorded.push(Recorded {
                    snapshot,
                    finished_at,
                });
            }
            _ => return Err(ErrorCode::InvalidRequest),
        }
    }
    Ok((listed, recorded))
}

pub(crate) fn run(
    snapshots: &Path,
    observation: &Path,
    site: &str,
    keep_days: u32,
    now: Option<i64>,
    output: Output,
) -> ExitCode {
    let Ok(site) = SiteId::try_from(site.to_owned()) else {
        return emit(&failure(ErrorCode::InvalidRequest), output);
    };
    let now = match now {
        Some(now) => now,
        None => match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(elapsed) => i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX),
            Err(_) => return emit(&failure(ErrorCode::InvalidRequest), output),
        },
    };
    let (listed, recorded) = match read_inputs(snapshots, observation, &site) {
        Ok(inputs) => inputs,
        Err(error) => return emit(&failure(error), output),
    };
    let result = plan(&listed, &recorded, now, keep_days);
    let mut stdout = io::stdout().lock();
    let written = match output {
        Output::Json => writeln!(
            stdout,
            "{}",
            serde_json::json!({
                "site_id": site.as_str(),
                "now": now,
                "keep_within_days": keep_days,
                "keep_recorded": result.keep_recorded,
                "keep_unrecorded": result.keep_unrecorded,
                "forget": result.forget,
                "missing_recorded": result.missing_recorded,
            })
        ),
        Output::Human => {
            let mut text = format!("site {} keep within {keep_days} days\n", site.as_str());
            for (label, ids) in [
                ("keep recorded", &result.keep_recorded),
                ("keep unrecorded", &result.keep_unrecorded),
                ("forget", &result.forget),
                ("MISSING recorded", &result.missing_recorded),
            ] {
                for id in ids {
                    text.push_str(&format!("{label} {id}\n"));
                }
            }
            write!(stdout, "{text}")
        }
    };
    match (written, result.missing_recorded.is_empty()) {
        (Err(_), _) => ExitCode::from(7),
        (Ok(()), true) => ExitCode::SUCCESS,
        (Ok(()), false) => ExitCode::from(3),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn id(c: char) -> String {
        c.to_string().repeat(64)
    }

    #[test]
    fn restic_times_parse_with_any_offset_and_fraction() {
        assert_eq!(parse_time("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_time("2026-11-20T01:53:00.123456789Z"),
            parse_time("2026-11-19T20:53:00-05:00")
        );
        assert_eq!(parse_time("2000-03-01T00:00:00+00:00"), Some(951_868_800));
        for bad in [
            "",
            "2026-11-20 01:53:00Z",
            "2026-13-01T00:00:00Z",
            "2026-11-20T01:53:00",
            "2026-11-20T01:53:00.Z",
            "2026-11-20T01:53:00+5:00",
            "2026-11-20T01:53:00+05:0x",
        ] {
            assert_eq!(parse_time(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_snapshot_flood_cannot_push_out_a_recorded_capture() {
        let recorded = vec![
            Recorded {
                snapshot: id('a'),
                finished_at: NOW - 60 * DAY,
            },
            Recorded {
                snapshot: id('b'),
                finished_at: NOW - 40 * DAY,
            },
            Recorded {
                snapshot: id('c'),
                finished_at: NOW - DAY,
            },
        ];
        let mut listed: Vec<Listed> = recorded
            .iter()
            .map(|r| Listed {
                id: r.snapshot.clone(),
                time: r.finished_at,
            })
            .collect();
        // Attacker snapshots: many new ones, one backdated, one future-dated.
        for (n, time) in [(1, NOW), (2, NOW - 10), (3, NOW - 90 * DAY), (4, NOW + DAY)] {
            listed.push(Listed {
                id: format!("{n}").repeat(64),
                time,
            });
        }
        let result = plan(&listed, &recorded, NOW, 30);
        assert_eq!(result.keep_recorded, [id('c')]);
        assert_eq!(result.forget, [id('3'), id('a'), id('b')]);
        assert_eq!(result.keep_unrecorded, [id('1'), id('2'), id('4')]);
        assert!(result.missing_recorded.is_empty());
    }

    #[test]
    fn the_newest_recorded_capture_survives_a_long_outage() {
        let recorded = vec![
            Recorded {
                snapshot: id('a'),
                finished_at: NOW - 100 * DAY,
            },
            Recorded {
                snapshot: id('b'),
                finished_at: NOW - 90 * DAY,
            },
        ];
        let listed = vec![
            Listed {
                id: id('a'),
                time: NOW - 100 * DAY,
            },
            Listed {
                id: id('b'),
                // The snapshot's own time is ignored for a recorded capture.
                time: NOW - 900 * DAY,
            },
        ];
        let result = plan(&listed, &recorded, NOW, 30);
        assert_eq!(result.keep_recorded, [id('b')]);
        assert_eq!(result.forget, [id('a')]);
    }

    #[test]
    fn a_hidden_recorded_capture_is_reported() {
        let recorded = vec![Recorded {
            snapshot: id('a'),
            finished_at: NOW - DAY,
        }];
        let result = plan(&[], &recorded, NOW, 30);
        assert_eq!(result.missing_recorded, [id('a')]);
        assert!(result.forget.is_empty());
    }
}
