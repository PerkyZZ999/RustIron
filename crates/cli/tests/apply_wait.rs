//! B05 (W251): after an unknown apply outcome the CLI waits, bounded, for the
//! operation's recorded state through the coordinator's status read.

use rustiron_contracts::{
    ErrorCode, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, ReadCommand, ReadData, Response,
    apply::decode_apply_request,
    decode_request, encode_response,
    execution::{OutcomeState, StatusValue},
    local,
};
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    os::unix::net::UnixStream,
    path::PathBuf,
    process::{Command, Output},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct Fixture {
    directory: PathBuf,
    socket: PathBuf,
}
/// W720: a folder-name part that no other test in this process uses. The
/// clock alone can repeat across parallel tests.
fn unique_suffix() -> String {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_nanos());
    let next = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{nanos}-{next}")
}

impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "ri-cli-wait-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        fs::write(directory.join("plan.json"), b"{\"p\":1}").unwrap();
        fs::write(directory.join("grant.json"), b"{\"g\":1}").unwrap();
        fs::write(directory.join("signature"), b"synthetic_signature").unwrap();
        let socket = directory.join("control.sock");
        Self { directory, socket }
    }
    fn run(&self, wait: Option<&str>, output: &str) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rustiron"));
        command
            .arg("--socket")
            .arg(&self.socket)
            .args(["plan", "apply-file", "--plan-file"])
            .arg(self.directory.join("plan.json"))
            .arg("--grant-file")
            .arg(self.directory.join("grant.json"))
            .arg("--signature-file")
            .arg(self.directory.join("signature"))
            .args([
                "--operation-id",
                "operation_1",
                "--idempotency-key",
                "retry_1",
                "--output",
                output,
            ]);
        if let Some(wait) = wait {
            command.args(["--wait-seconds", wait]);
        }
        command.output().unwrap()
    }
    /// Serves connections in order: the first is the apply (reply dropped,
    /// so the outcome is unknown); each later one answers a status read with
    /// the next state (`None` = unknown operation error). Returns the number
    /// of status reads served once the client stops connecting.
    fn server(&self, states: Vec<Option<OutcomeState>>) -> thread::JoinHandle<usize> {
        let listener = rustiron_control::bind(&self.socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        thread::spawn(move || {
            let mut served = 0;
            let mut idle = Instant::now();
            let mut first = true;
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        idle = Instant::now();
                        stream.set_nonblocking(false).unwrap();
                        if first {
                            first = false;
                            apply_without_reply(stream);
                        } else {
                            let state = states
                                .get(served)
                                .copied()
                                .unwrap_or(Some(OutcomeState::Intent));
                            status(stream, state);
                            served += 1;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if idle.elapsed() > Duration::from_secs(8) {
                            return served;
                        }
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => panic!("accept failed: {e}"),
                }
            }
        })
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn read(stream: &mut UnixStream) -> Vec<u8> {
    local::read_frame(
        stream,
        MAX_REQUEST_BYTES,
        ErrorCode::RequestTooLarge,
        Instant::now() + local::DEADLINE,
    )
    .unwrap()
}

fn apply_without_reply(mut stream: UnixStream) {
    decode_apply_request(&read(&mut stream)).unwrap();
}

fn status(mut stream: UnixStream, state: Option<OutcomeState>) {
    let request = decode_request(&read(&mut stream)).unwrap();
    let ReadCommand::OperationStatus { operation_id } = request.command else {
        panic!("expected a status read");
    };
    assert_eq!(operation_id.as_str(), "operation_1");
    let result = match state {
        Some(state) => Ok(ReadData::OperationStatus(StatusValue {
            operation_id,
            state,
        })),
        None => Err(rustiron_contracts::ApiError::new(ErrorCode::InvalidRequest)),
    };
    let response = Response {
        request_id: Some(request.request_id),
        result,
    };
    local::write_frame(
        &mut stream,
        &encode_response(&response).unwrap(),
        MAX_RESPONSE_BYTES,
        ErrorCode::ResponseTooLarge,
        Instant::now() + local::DEADLINE,
    )
    .unwrap();
}

fn outcome(output: &Output) -> serde_json::Value {
    let wire: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(wire["data"]["value"]["operation_id"], "operation_1");
    wire["data"]["value"]["outcome"].clone()
}

#[test]
fn an_unknown_outcome_waits_for_the_recorded_state() {
    let fixture = Fixture::new();
    let server = fixture.server(vec![
        None,
        Some(OutcomeState::Intent),
        Some(OutcomeState::Succeeded),
    ]);
    let output = fixture.run(Some("20"), "json");
    let outcome = outcome(&output);
    assert_eq!(outcome["kind"], "recorded_after_wait", "{outcome}");
    assert_eq!(outcome["state"], "succeeded");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        server.join().unwrap(),
        3,
        "stops polling once a final state is read"
    );
}

#[test]
fn a_final_failure_after_waiting_keeps_its_exit_code() {
    let fixture = Fixture::new();
    let server = fixture.server(vec![Some(OutcomeState::NeedsAttention)]);
    let output = fixture.run(Some("20"), "json");
    assert_eq!(outcome(&output)["state"], "needs_attention");
    assert_eq!(output.status.code(), Some(6));
    assert_eq!(server.join().unwrap(), 1);
}

#[test]
fn the_wait_is_bounded_and_then_stays_unknown() {
    let fixture = Fixture::new();
    let server = fixture.server(vec![]);
    let started = Instant::now();
    let output = fixture.run(Some("2"), "json");
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(outcome(&output)["kind"], "outcome_unknown");
    assert_eq!(output.status.code(), Some(7));
    assert!(server.join().unwrap() >= 1);
}

#[test]
fn zero_wait_keeps_the_old_unknown_reply_without_status_reads() {
    let fixture = Fixture::new();
    let server = fixture.server(vec![Some(OutcomeState::Succeeded)]);
    let output = fixture.run(Some("0"), "json");
    assert_eq!(outcome(&output)["kind"], "outcome_unknown");
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(server.join().unwrap(), 0);
}

#[test]
fn human_output_names_the_state_read_after_waiting() {
    let fixture = Fixture::new();
    let server = fixture.server(vec![Some(OutcomeState::Succeeded)]);
    let output = fixture.run(Some("20"), "human");
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("recorded state Succeeded"), "{text}");
    assert!(text.contains("after waiting"), "{text}");
    assert_eq!(output.status.code(), Some(0));
    server.join().unwrap();
}
