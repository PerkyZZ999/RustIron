//! D-035 (W386): the standing capture schedule on the requester side.
//!
//! `schedule runs` lists the windows and the run identities of a standing
//! grant offline. `schedule run` submits the open window's run of each named
//! site through the coordinator, then reports the status. `schedule status`
//! reads every window's run state and the newest snapshot of each site, and
//! alerts on a missed or failed newest window, an exceeded RPO target or a
//! used-up grant. None of these commands grants or widens authority: the
//! executor derives the run and checks the window with its own clock.

use std::{
    io::{self, Write},
    path::Path,
    process::ExitCode,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rustiron_contracts::{
    ErrorCode, Id, MAX_REQUEST_BYTES, ReadCommand, ReadData, Request, Response,
    approval::{StandingCaptureGrant, StandingCapturePlan, WindowPosition},
    escape_human,
    execution::{MAX_SIGNATURE_TEXT, OutcomeState},
};
use serde_json::{Value, json};

use crate::{Output, apply_cli, emit, failure, file_input};

/// Exit status when the report alerts (a verified failure class, SPEC 5).
const ALERT_EXIT: u8 = 5;
/// Exit status when no window is open (an authorization refusal, SPEC 3).
const NO_WINDOW_EXIT: u8 = 3;

/// The signed files of one standing grant, decoded and checked together.
struct Standing {
    plan_bytes: Vec<u8>,
    grant_bytes: Vec<u8>,
    signature: String,
    plan: StandingCapturePlan,
    grant: StandingCaptureGrant,
}

impl Standing {
    /// Reads `plan.json`, `grant.json` and `grant.json.sig` from `dir`.
    /// The grant must bind this plan, its sites and its schedule; this
    /// checks no signature or host fact.
    fn load(dir: &Path) -> Result<Self, ErrorCode> {
        let plan_bytes = file_input::read(&dir.join("plan.json"), MAX_REQUEST_BYTES)?;
        let grant_bytes = file_input::read(&dir.join("grant.json"), MAX_REQUEST_BYTES)?;
        let signature = String::from_utf8(file_input::read(
            &dir.join("grant.json.sig"),
            MAX_SIGNATURE_TEXT,
        )?)
        .map_err(|_| ErrorCode::InvalidRequest)?;
        let plan = StandingCapturePlan::decode(plan_bytes.trim_ascii())
            .map_err(|_| ErrorCode::InvalidRequest)?;
        let grant = StandingCaptureGrant::decode(grant_bytes.trim_ascii())
            .map_err(|_| ErrorCode::InvalidRequest)?;
        if grant.plan_digest() != &plan.digest()
            || grant.schedule() != plan.schedule()
            || grant.site_ids() != plan.site_ids()
        {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(Self {
            plan_bytes,
            grant_bytes,
            signature,
            plan,
            grant,
        })
    }

    fn header(&self, scope: &str, now: u64) -> Value {
        let schedule = self.grant.schedule();
        json!({
            "scope": scope,
            "authority": "none",
            "checked_at": now,
            "plan_digest": self.plan.digest(),
            "grant_sha256": self.grant.sha256(),
            "site_ids": self.grant.site_ids().iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            "schedule": {
                "first_window_start": schedule.first_window_start,
                "period_seconds": schedule.period_seconds,
                "window_seconds": schedule.window_seconds,
                "max_runs": schedule.max_runs,
            },
            "expires_at": self.grant.expires_at().get(),
        })
    }
}

fn now() -> Result<u64, ErrorCode> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| ErrorCode::DependencyUnavailable)
}

fn write(value: &Value, output: Output, status: u8) -> ExitCode {
    let text = match output {
        Output::Json => serde_json::to_string(value).map(|text| text + "\n"),
        Output::Human => serde_json::to_string_pretty(value).map(|pretty| {
            pretty
                .lines()
                .map(|line| escape_human(line) + "\n")
                .collect()
        }),
    };
    match text {
        Ok(text) if io::stdout().lock().write_all(text.as_bytes()).is_ok() => {
            ExitCode::from(status)
        }
        _ => ExitCode::from(7),
    }
}

/// `schedule runs`: every window and its run identities, offline.
pub(crate) fn runs(dir: &Path, output: Output) -> ExitCode {
    let (standing, now) = match Standing::load(dir).and_then(|s| Ok((s, now()?))) {
        Ok(loaded) => loaded,
        Err(code) => return emit(&failure(code), output),
    };
    let schedule = standing.grant.schedule();
    let windows = (0..schedule.max_runs)
        .filter_map(|window| {
            let (opens, closes) = schedule.window(window)?;
            let runs = standing
                .grant
                .site_ids()
                .iter()
                .filter_map(|site| {
                    let run = standing.grant.run(site, window)?;
                    Some(json!({
                        "site_id": site.as_str(),
                        "operation_id": run.operation_id,
                        "idempotency_key": run.idempotency_key,
                    }))
                })
                .collect::<Vec<_>>();
            Some(json!({"window": window, "opens_at": opens, "closes_at": closes, "runs": runs}))
        })
        .collect::<Vec<_>>();
    let mut report = standing.header("standing_runs", now);
    report["windows"] = json!(windows);
    write(&report, output, 0)
}

/// One coordinator read; `Err` carries the public error code.
fn read(socket: &Path, command: ReadCommand) -> Result<ReadData, ErrorCode> {
    let request = Request {
        request_id: Id::try_from(format!("cli-{}", std::process::id()))
            .expect("PID IDs are bounded ASCII"),
        command,
    };
    match crate::exchange(socket, &request)? {
        Response {
            result: Ok(data), ..
        } => Ok(data),
        Response {
            result: Err(error), ..
        } => Err(error.code()),
    }
}

fn state_name(state: OutcomeState) -> String {
    serde_json::to_value(state)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

/// The newest succeeded run of one site and its receipt facts.
fn newest_snapshot(socket: &Path, operation_id: &Id, window: u64) -> Value {
    let receipt = match read(
        socket,
        ReadCommand::EvidenceExport {
            operation_id: operation_id.clone(),
        },
    ) {
        Ok(ReadData::EvidenceExport(evidence)) => evidence.receipt.body,
        _ => Value::Null,
    };
    json!({
        "operation_id": operation_id,
        "window": window,
        "snapshot_id": receipt["snapshot_id"],
        "started_at": receipt["operation"]["started_at"],
        "finished_at": receipt["operation"]["finished_at"],
    })
}

/// `schedule status` report and whether it alerts.
fn report(socket: &Path, standing: &Standing, now: u64, rpo_target: u64) -> (Value, bool) {
    let grant = &standing.grant;
    let schedule = grant.schedule();
    let closed = schedule.closed_windows(now);
    let (mut windows, mut missed, mut failed, mut unknown) = (vec![], vec![], vec![], vec![]);
    let mut newest: Vec<Option<(u64, Id)>> = vec![None; grant.site_ids().len()];
    for window in 0..schedule.max_runs {
        let Some((opens, closes)) = schedule.window(window) else {
            break;
        };
        let phase = if now < opens {
            "pending"
        } else if now < closes {
            "open"
        } else {
            "closed"
        };
        let mut runs = vec![];
        for (index, site) in grant.site_ids().iter().enumerate() {
            let Some(run) = grant.run(site, window) else {
                continue;
            };
            let state = if phase == "pending" {
                "pending".to_owned()
            } else {
                match read(
                    socket,
                    ReadCommand::OperationStatus {
                        operation_id: run.operation_id.clone(),
                    },
                ) {
                    Ok(ReadData::OperationStatus(status)) => state_name(status.state),
                    Err(ErrorCode::NotFound) if phase == "closed" => "missed".to_owned(),
                    Err(ErrorCode::NotFound) => "not_started".to_owned(),
                    _ => "unknown".to_owned(),
                }
            };
            let entry = json!({"window": window, "site_id": site.as_str()});
            match state.as_str() {
                "missed" => missed.push(entry),
                "failed" | "untouched" | "failed_compensated" | "quarantined" => failed.push(entry),
                "unknown" => unknown.push(entry),
                "succeeded" => newest[index] = Some((window, run.operation_id.clone())),
                _ => {}
            }
            runs.push(json!({
                "site_id": site.as_str(),
                "operation_id": run.operation_id,
                "state": state,
            }));
        }
        windows.push(json!({
            "window": window, "opens_at": opens, "closes_at": closes, "phase": phase, "runs": runs,
        }));
    }
    let mut alerts = vec![];
    let newest_closed = closed.checked_sub(1);
    let in_newest = |list: &[Value]| {
        newest_closed.is_some_and(|w| list.iter().any(|entry| entry["window"] == w))
    };
    if in_newest(&missed) {
        alerts.push("newest_closed_window_missed");
    }
    if in_newest(&failed) {
        alerts.push("newest_closed_window_failed");
    }
    if !unknown.is_empty() {
        alerts.push("status_unknown");
    }
    let sites = grant
        .site_ids()
        .iter()
        .zip(&newest)
        .map(|(site, newest)| {
            let snapshot = newest
                .as_ref()
                .map(|(window, operation)| newest_snapshot(socket, operation, *window));
            let age = snapshot
                .as_ref()
                .and_then(|s| s["started_at"].as_u64())
                .map(|started| now.saturating_sub(started));
            let met = age.is_some_and(|age| age <= rpo_target);
            if !met {
                alerts.push("rpo_exceeded");
            }
            json!({
                "site_id": site.as_str(),
                "newest_snapshot": snapshot,
                "snapshot_age_seconds": age,
                "rpo_met": met,
            })
        })
        .collect::<Vec<_>>();
    let remaining = schedule.max_runs - closed;
    if remaining == 0 {
        alerts.push("grant_exhausted");
    }
    alerts.dedup();
    let alert = !alerts.is_empty();
    let mut value = standing.header("standing_status", now);
    for (key, item) in [
        ("rpo_target_seconds", json!(rpo_target)),
        ("closed_windows", json!(closed)),
        ("remaining_windows", json!(remaining)),
        ("missed", json!(missed)),
        ("failed", json!(failed)),
        ("sites", json!(sites)),
        ("alerts", json!(alerts)),
        ("windows", json!(windows)),
    ] {
        value[key] = item;
    }
    (value, alert)
}

/// `schedule status`: every window, missed runs and the snapshot age.
pub(crate) fn status(socket: &Path, dir: &Path, output: Output, rpo_target: u64) -> ExitCode {
    let (standing, now) = match Standing::load(dir).and_then(|s| Ok((s, now()?))) {
        Ok(loaded) => loaded,
        Err(code) => return emit(&failure(code), output),
    };
    let (value, alert) = report(socket, &standing, now, rpo_target);
    write(&value, output, if alert { ALERT_EXIT } else { 0 })
}

/// `schedule run`: the open window's run of each named site, then the
/// status. Outside every window it submits nothing.
pub(crate) fn run(
    socket: &Path,
    dir: &Path,
    output: Output,
    wait: Duration,
    rpo_target: u64,
) -> ExitCode {
    let (standing, started) = match Standing::load(dir).and_then(|s| Ok((s, now()?))) {
        Ok(loaded) => loaded,
        Err(code) => return emit(&failure(code), output),
    };
    let schedule = standing.grant.schedule();
    let mut value = standing.header("standing_run", started);
    let mut exit = 0;
    match schedule.position(started) {
        WindowPosition::Open {
            index,
            opens_at,
            closes_at,
        } => {
            let mut submissions = vec![];
            for site in standing.grant.site_ids() {
                let Some(run) = standing.grant.run(site, index) else {
                    continue;
                };
                let (response, code) = apply_cli::submit_quiet(
                    socket,
                    &standing.plan_bytes,
                    &standing.grant_bytes,
                    &standing.signature,
                    apply_cli::Attempt {
                        operation_id: run.operation_id.clone(),
                        idempotency_key: run.idempotency_key,
                        wait,
                    },
                );
                if exit == 0 {
                    exit = code;
                }
                submissions.push(json!({
                    "site_id": site.as_str(),
                    "operation_id": run.operation_id,
                    "exit": code,
                    "response": response,
                }));
            }
            value["window"] =
                json!({"window": index, "opens_at": opens_at, "closes_at": closes_at});
            value["submissions"] = json!(submissions);
        }
        WindowPosition::Closed { next } => {
            value["window"] = Value::Null;
            value["next_window_opens_at"] = json!(
                next.and_then(|window| schedule.window(window))
                    .map(|(opens, _)| opens)
            );
            value["submissions"] = json!([]);
            exit = NO_WINDOW_EXIT;
        }
    }
    let finished = now().unwrap_or(started).max(started);
    let (status, alert) = report(socket, &standing, finished, rpo_target);
    value["status"] = status;
    if exit == 0 && alert {
        exit = ALERT_EXIT;
    }
    write(&value, output, exit)
}
