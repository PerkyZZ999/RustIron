//! Disposable same-user test harness; never a root executor or admission service.
use rustiron_journal::{FixtureJournal, JournalError};
use std::{
    io::{Read, Write},
    path::PathBuf,
    process::ExitCode,
};
#[path = "../tests/support/mod.rs"]
mod support;
use support::*;
fn run() -> Result<(), JournalError> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 {
        return Err(JournalError::Conflict);
    }
    let directory = PathBuf::from(&args[0]);
    let action = args[1].to_str().ok_or(JournalError::Conflict)?;
    if action == "init" {
        FixtureJournal::initialize(&directory, id("host_fixture"), id("epoch_fixture"))?;
        return Ok(());
    }
    let mut journal = FixtureJournal::open(&directory, id("host_fixture"), id("epoch_fixture"))?;
    match action {
        "crash" => {
            journal.record_intent(&intent(1), time(1000))?;
            std::process::exit(77);
        }
        "hold" => {
            println!("ready");
            std::io::stdout()
                .flush()
                .map_err(|_| JournalError::Unavailable)?;
            let mut byte = [0];
            std::io::stdin()
                .read(&mut byte)
                .map_err(|_| JournalError::Unavailable)?;
        }
        "inspect" => {
            let settings = journal.settings()?;
            println!(
                "{} {} {} {}",
                settings.journal_mode,
                settings.synchronous,
                settings.foreign_keys,
                settings.trusted_schema
            );
            println!(
                "{:?}",
                journal.status(&id("operation_1"))?.map(|op| op.state)
            );
        }
        "new" => {
            println!("{:?}", journal.record_intent(&intent(2), time(1001))?);
        }
        "unknown" => {
            println!(
                "{:?}",
                journal
                    .record_observation(&id("operation_1"), None, None)?
                    .state
            );
        }
        "complete" => {
            let first = intent(1);
            println!(
                "{:?}",
                journal
                    .record_observation(
                        &first.operation_id,
                        Some(&first.target_generation),
                        Some(&first.target_digest)
                    )?
                    .state
            );
        }
        _ => return Err(JournalError::Conflict),
    }
    Ok(())
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            println!("{error}");
            ExitCode::from(2)
        }
    }
}
