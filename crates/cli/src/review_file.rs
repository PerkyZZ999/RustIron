//! Offline review of the complete semantic plan, without granting authority.

use crate::{Output, emit, failure, file_input};
use rustiron_contracts::{
    ErrorCode, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
    approval::{PreparedPlan, StandingCapturePlan},
    escape_human,
};
use std::{
    io::{self, Write},
    path::Path,
    process::ExitCode,
};

pub(crate) fn run(path: &Path, output: Output) -> ExitCode {
    let bytes = match file_input::read(path, MAX_REQUEST_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => return emit(&failure(error), output),
    };
    write_rendered(&bytes, output, "plan_review")
}

pub(crate) fn write_rendered(bytes: &[u8], output: Output, scope: &str) -> ExitCode {
    let bytes = match render(bytes, output, scope) {
        Ok(bytes) => bytes,
        Err(error) => return emit(&failure(error), output),
    };
    if io::stdout().lock().write_all(&bytes).is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(7)
    }
}

fn render(bytes: &[u8], output: Output, scope: &str) -> Result<Vec<u8>, ErrorCode> {
    let prepared = PreparedPlan::decode(bytes).map_err(|_| ErrorCode::InvalidRequest)?;
    let verb = prepared.kind().as_str();
    let digest = prepared.digest().as_str().to_owned();
    let plan: serde_json::Value =
        serde_json::from_slice(prepared.as_bytes()).map_err(|_| ErrorCode::InvalidRequest)?;
    // D-035 (W386): a standing capture plan also lists every signed window,
    // so the reviewer sees each second a capture may start.
    let windows = StandingCapturePlan::decode(prepared.as_bytes())
        .ok()
        .map(|standing| {
            let schedule = standing.schedule();
            (0..schedule.max_runs)
                .filter_map(|window| {
                    let (opens, closes) = schedule.window(window)?;
                    Some(serde_json::json!({"window": window, "opens_at": opens, "closes_at": closes}))
                })
                .collect::<Vec<_>>()
        });
    let mut result = BoundedOutput::default();
    match output {
        Output::Json => {
            let mut report = serde_json::json!({"scope":scope, "verb":verb, "plan_digest":digest, "authority":"none", "plan":plan});
            if let Some(windows) = &windows {
                report["standing_windows"] = serde_json::json!(windows);
            }
            serde_json::to_writer(&mut result, &report).map_err(|_| ErrorCode::ResponseTooLarge)?;
            writeln!(result).map_err(|_| ErrorCode::ResponseTooLarge)?;
        }
        Output::Human => {
            writeln!(result, "verb: {verb}\nplan digest: {digest}\nauthority: none (not signature verification or approval)\ncomplete plan:").map_err(|_| ErrorCode::ResponseTooLarge)?;
            let mut pretty = BoundedOutput::default();
            serde_json::to_writer_pretty(&mut pretty, &plan)
                .map_err(|_| ErrorCode::ResponseTooLarge)?;
            let text = std::str::from_utf8(&pretty.0).map_err(|_| ErrorCode::InvalidRequest)?;
            for line in text.lines() {
                writeln!(result, "{}", escape_human(line))
                    .map_err(|_| ErrorCode::ResponseTooLarge)?;
            }
            if let Some(windows) = &windows {
                writeln!(
                    result,
                    "standing capture windows (Unix seconds, opens inclusive, closes exclusive):"
                )
                .map_err(|_| ErrorCode::ResponseTooLarge)?;
                for window in windows {
                    writeln!(
                        result,
                        "  window {}: {} to {}",
                        window["window"], window["opens_at"], window["closes_at"]
                    )
                    .map_err(|_| ErrorCode::ResponseTooLarge)?;
                }
            }
        }
    }
    Ok(result.0)
}

#[derive(Default)]
struct BoundedOutput(Vec<u8>);
impl Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.0.len().saturating_add(bytes.len()) > MAX_RESPONSE_BYTES {
            return Err(io::Error::other("review exceeds output limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
