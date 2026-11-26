//! File-based apply uses the real CLI and synthetic same-user socket peers.

use rustiron_contracts::{
    ErrorCode, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
    apply::{ApplyOutcome, ApplyResponse, decode_apply_request, encode_apply_response},
    execution::{OutcomeState, SubmissionReply},
    local,
};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
    process::{Command, Output},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct Fixture {
    directory: PathBuf,
    socket: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "ri-cli-apply-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        fs::write(directory.join("plan.json"), b"{\"p\": {\"n\":1}}\n").unwrap();
        fs::write(directory.join("grant.json"), b"{\"g\": true}\n").unwrap();
        fs::write(directory.join("signature"), b"synthetic_signature").unwrap();
        let socket = directory.join("control.sock");
        Self { directory, socket }
    }
    fn run(&self) -> Output {
        self.run_as("json")
    }
    fn run_as(&self, output: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_rustiron"))
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
                // W251: these cases test the single exchange; waiting is in apply_wait.rs.
                "--wait-seconds",
                "0",
            ])
            .output()
            .unwrap()
    }
    fn server(
        &self,
        handler: impl FnOnce(std::os::unix::net::UnixStream) + Send + 'static,
    ) -> thread::JoinHandle<()> {
        let listener = rustiron_control::bind(&self.socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        thread::spawn(move || {
            let deadline = Instant::now() + local::DEADLINE;
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        handler(stream);
                        break;
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
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
        fs::remove_dir_all(&self.directory).unwrap();
    }
}

fn outcome(output: &Output) -> serde_json::Value {
    let wire: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(wire["data"]["value"]["operation_id"], "operation_1");
    wire["data"]["value"]["outcome"].clone()
}

#[test]
fn signed_files_reach_the_coordinator_and_a_success_is_reported() {
    let fixture = Fixture::new();
    let server = fixture.server(|mut stream| {
        let bytes = local::read_frame(
            &mut stream,
            MAX_REQUEST_BYTES,
            ErrorCode::RequestTooLarge,
            Instant::now() + local::DEADLINE,
        )
        .unwrap();
        let request = decode_apply_request(&bytes).unwrap();
        assert_eq!(request.plan, br#"{"p": {"n":1}}"#);
        assert_eq!(request.grant, br#"{"g": true}"#);
        assert_eq!(request.signature, "synthetic_signature");
        let response = ApplyResponse {
            request_id: request.request_id,
            operation_id: request.operation_id.clone(),
            outcome: ApplyOutcome::ExecutorReply {
                reply: SubmissionReply {
                    schema_version: 1,
                    operation_id: Some(request.operation_id),
                    state: Some(OutcomeState::Succeeded),
                    replay: false,
                    error: None,
                    unclaimed_snapshot_id: None,
                },
            },
        };
        local::write_frame(
            &mut stream,
            &encode_apply_response(&response).unwrap(),
            MAX_RESPONSE_BYTES,
            ErrorCode::ResponseTooLarge,
            Instant::now() + local::DEADLINE,
        )
        .unwrap();
    });
    let output = fixture.run();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(outcome(&output)["kind"], "executor_reply");
    server.join().unwrap();
}

#[test]
fn a_lost_reply_is_unknown_and_keeps_the_operation_id() {
    let fixture = Fixture::new();
    let server = fixture.server(|mut stream| {
        let bytes = local::read_frame(
            &mut stream,
            MAX_REQUEST_BYTES,
            ErrorCode::RequestTooLarge,
            Instant::now() + local::DEADLINE,
        )
        .unwrap();
        decode_apply_request(&bytes).unwrap();
    });
    let output = fixture.run();
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(outcome(&output)["kind"], "outcome_unknown");
    server.join().unwrap();
}

#[test]
fn a_missing_coordinator_is_not_sent() {
    let fixture = Fixture::new();
    let output = fixture.run();
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(outcome(&output)["kind"], "not_sent");
}

/// W365: a coordinator stopped by its start limit removes its runtime
/// directory. The JSON stays the `not_sent` outcome with exit 7, and stderr
/// names the coordinator socket, so the operator knows which service to check.
#[test]
fn a_missing_coordinator_socket_is_named_on_stderr() {
    let fixture = Fixture::new();
    let output = fixture.run();
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(outcome(&output)["reason"], "unavailable");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        stderr,
        "rustiron: the coordinator socket could not be reached; this attempt was not sent. \
         Check the coordinator service, then send the same operation ID and idempotency key again.\n"
    );
}

/// W365: the human answer names the coordinator socket too.
#[test]
fn a_missing_coordinator_socket_is_named_in_human_output() {
    let fixture = Fixture::new();
    let output = fixture.run_as("human");
    assert_eq!(output.status.code(), Some(7));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        stdout,
        "Operation operation_1: this attempt was not sent (the coordinator socket could not be reached); \
         earlier attempts may still be in flight.\n"
    );
}

#[test]
fn coordinator_without_executor_confirms_the_attempt_was_not_sent() {
    let fixture = Fixture::new();
    let server = fixture.server(|stream| {
        assert!(rustiron_control::handle_connection(stream));
    });
    let output = fixture.run();
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(outcome(&output)["kind"], "not_sent");
    assert_eq!(outcome(&output)["reason"], "unavailable");
    // The coordinator answered: no claim that its socket was missing.
    assert!(output.stderr.is_empty());
    server.join().unwrap();
}

#[test]
fn untrusted_socket_directory_is_not_sent_and_returns_denial() {
    let fixture = Fixture::new();
    let _listener = rustiron_control::bind(&fixture.socket).unwrap();
    fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o755)).unwrap();
    let output = fixture.run();
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(outcome(&output)["kind"], "not_sent");
    assert_eq!(outcome(&output)["reason"], "unauthorized");
    fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn a_reply_for_another_operation_is_unknown() {
    let fixture = Fixture::new();
    let server = fixture.server(|mut stream| {
        let bytes = local::read_frame(&mut stream, MAX_REQUEST_BYTES, ErrorCode::RequestTooLarge, Instant::now() + local::DEADLINE).unwrap();
        let request = decode_apply_request(&bytes).unwrap();
        let bytes = serde_json::to_vec(&serde_json::json!({"schema_version":1,"request_id":request.request_id,"status":"ok","data":{"kind":"plan_apply","value":{"operation_id":"other_operation","outcome":{"kind":"executor_reply","reply":{"schema_version":1,"operation_id":"other_operation","state":"succeeded","replay":false,"error":null}}}},"error":null})).unwrap();
        local::write_frame(&mut stream, &bytes, MAX_RESPONSE_BYTES, ErrorCode::ResponseTooLarge, Instant::now() + local::DEADLINE).unwrap();
    });
    let output = fixture.run();
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(outcome(&output)["kind"], "outcome_unknown");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("synthetic_signature"));
    server.join().unwrap();
}

#[test]
fn an_executor_intent_is_not_reported_as_success() {
    let fixture = Fixture::new();
    let server = fixture.server(|mut stream| {
        let bytes = local::read_frame(
            &mut stream,
            MAX_REQUEST_BYTES,
            ErrorCode::RequestTooLarge,
            Instant::now() + local::DEADLINE,
        )
        .unwrap();
        let request = decode_apply_request(&bytes).unwrap();
        let response = ApplyResponse {
            request_id: request.request_id,
            operation_id: request.operation_id.clone(),
            outcome: ApplyOutcome::ExecutorReply {
                reply: SubmissionReply {
                    schema_version: 1,
                    operation_id: Some(request.operation_id),
                    state: Some(OutcomeState::Intent),
                    replay: false,
                    error: None,
                    unclaimed_snapshot_id: None,
                },
            },
        };
        local::write_frame(
            &mut stream,
            &encode_apply_response(&response).unwrap(),
            MAX_RESPONSE_BYTES,
            ErrorCode::ResponseTooLarge,
            Instant::now() + local::DEADLINE,
        )
        .unwrap();
    });
    let output = fixture.run();
    assert_eq!(output.status.code(), Some(6));
    assert_eq!(outcome(&output)["reply"]["state"], "intent");
    server.join().unwrap();
}

#[test]
fn symlinked_input_is_refused_without_echoing_a_path() {
    let fixture = Fixture::new();
    fs::remove_file(fixture.directory.join("signature")).unwrap();
    std::os::unix::fs::symlink(
        fixture.directory.join("grant.json"),
        fixture.directory.join("signature"),
    )
    .unwrap();
    let output = fixture.run();
    assert_eq!(output.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(fixture.directory.to_str().unwrap()));
}
