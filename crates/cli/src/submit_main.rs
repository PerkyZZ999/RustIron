//! Unprivileged requester client for the S02 lab fixture executor.
//!
//! Sends one signed submission and prints the executor's reply. It holds no
//! signing key and grants nothing; the executor decides from its own policy.
#![warn(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "W672: production code returns errors; tests may unwrap (clippy.toml)"
)]

use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
    process::ExitCode,
    time::Instant,
};

use clap::Parser;

const REPLY_WAIT: std::time::Duration = std::time::Duration::from_secs(600);
use rustiron_contracts::{
    ErrorCode, Id, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
    execution::{MAX_SIGNATURE_TEXT, SubmissionReply, decode_submission_reply, encode_submission},
    local::{self, DEADLINE},
};

#[derive(Parser)]
#[command(
    name = "rustiron-submit",
    about = "Submit one signed lab fixture plan to the executor socket"
)]
struct Args {
    #[arg(long, default_value = "/run/rustiron-s02-lab/executor.sock")]
    socket: PathBuf,
    /// Expected executor UID, checked from kernel peer credentials.
    #[arg(long, default_value_t = 0)]
    executor_uid: u32,
    #[arg(long)]
    plan: PathBuf,
    #[arg(long)]
    grant: PathBuf,
    #[arg(long)]
    signature: PathBuf,
    #[arg(long)]
    operation_id: String,
    #[arg(long)]
    idempotency_key: String,
}

fn read(path: &PathBuf, limit: usize) -> Result<Vec<u8>, u8> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| 2u8)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| 2u8)?;
    if bytes.len() > limit {
        return Err(2);
    }
    Ok(bytes)
}

fn run(args: Args) -> Result<SubmissionReply, u8> {
    let id = |value: String| Id::try_from(value).map_err(|_| 2u8);
    let plan = read(&args.plan, MAX_REQUEST_BYTES)?;
    let grant = read(&args.grant, MAX_REQUEST_BYTES)?;
    let signature =
        String::from_utf8(read(&args.signature, MAX_SIGNATURE_TEXT)?).map_err(|_| 2u8)?;
    let trim = |bytes: &[u8]| bytes.trim_ascii().to_vec();
    let operation_id = id(args.operation_id)?;
    let frame = encode_submission(
        &operation_id,
        &id(args.idempotency_key)?,
        &trim(&plan),
        &trim(&grant),
        &signature,
    )
    .map_err(|_| 2u8)?;
    let deadline = Instant::now() + DEADLINE;
    let mut stream = UnixStream::connect(&args.socket).map_err(|_| 7u8)?;
    local::require_peer(&stream, args.executor_uid).map_err(|_| 7u8)?;
    local::write_frame(
        &mut stream,
        &frame,
        MAX_REQUEST_BYTES,
        ErrorCode::RequestTooLarge,
        deadline,
    )
    .map_err(|_| 7u8)?;
    // A site provision runs every step before replying; wait for it, bounded.
    let reply = local::read_frame(
        &mut stream,
        MAX_RESPONSE_BYTES,
        ErrorCode::ResponseTooLarge,
        Instant::now() + REPLY_WAIT,
    )
    .map_err(|_| 7u8)?;
    decode_submission_reply(&reply, &operation_id).map_err(|_| 7u8)
}

fn main() -> ExitCode {
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
            return if error.print().is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(7)
            };
        }
        Err(_) => return ExitCode::from(2),
    };
    match run(args) {
        Ok(reply) => {
            let code = reply.exit_code();
            let Ok(mut text) = serde_json::to_vec(&reply) else {
                return ExitCode::from(7);
            };
            text.push(b'\n');
            if std::io::stdout().lock().write_all(&text).is_err() {
                return ExitCode::from(7);
            }
            ExitCode::from(code)
        }
        Err(code) => ExitCode::from(code),
    }
}
