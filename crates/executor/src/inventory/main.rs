//! Fixed metadata worker. Run only as an unprivileged restore identity.
use std::{io::Write, path::Path, process::ExitCode};
#[path = "../restore/inventory_report.rs"]
#[expect(
    dead_code,
    reason = "the worker writes reports; only callers decode them"
)]
mod report;
mod worker;

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().collect();
    // W378: the restore target, then the site path below it.
    if args.len() != 3 {
        eprintln!("{{\"error\":\"INVENTORY_ARGUMENTS\"}}");
        return ExitCode::from(2);
    }
    let report = worker::inventory(
        Path::new(&args[1]),
        Path::new(&args[2]),
        worker::Limits::default(),
    );
    let Ok(mut bytes) = serde_json::to_vec(&report) else {
        return ExitCode::from(2);
    };
    if bytes.len() >= report::MAX_REPORT_BYTES {
        return ExitCode::from(2);
    }
    bytes.push(b'\n');
    if std::io::stdout().lock().write_all(&bytes).is_err() {
        return ExitCode::from(2);
    }
    if report.reason == Some(report::Reason::Identity) {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}
