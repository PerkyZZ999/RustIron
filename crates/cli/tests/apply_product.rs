//! W326 (B05): the operator CLI submits signed product v2 capture and probe
//! plans through a same-user coordinator socket and reports the recorded
//! outcome. The coordinator here is synthetic; the coordinator-to-executor
//! hop is tested in `rustiron-control` against a fake executor socket.

use rustiron_contracts::{
    ErrorCode, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, ReadCommand, ReadData, Response,
    apply::{ApplyOutcome, ApplyResponse, decode_apply_request, encode_apply_response},
    approval::{ProductBackupPlan, ProductBackupTarget},
    decode_request, encode_response,
    execution::{OutcomeState, StatusValue, SubmissionReply},
    local,
};
use serde_json::Value;
use std::{
    fs,
    os::unix::{fs::DirBuilderExt, net::UnixStream},
    path::PathBuf,
    process::{Command, Output},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const VECTORS: &str = include_str!("../../contracts/tests/fixtures/product-backup-vectors.json");
/// The recorded W319/W320 lab outcome for an admitted product operation.
const REFUSED: &str = "NOT_ADMITTED_FOR_EFFECT";

fn vector(name: &str) -> Value {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    vectors
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["name"] == name)
        .unwrap()
        .clone()
}

fn text<'a>(vector: &'a Value, field: &str) -> &'a str {
    vector[field].as_str().unwrap()
}

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
    fn new(vector: &Value) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "ri-cli-product-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        fs::write(directory.join("plan.json"), text(vector, "plan_input")).unwrap();
        fs::write(directory.join("grant.json"), text(vector, "grant_input")).unwrap();
        fs::write(directory.join("signature"), b"synthetic_signature").unwrap();
        let socket = directory.join("control.sock");
        Self { directory, socket }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.join(name)
    }

    fn rustiron(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rustiron"));
        command.arg("--socket").arg(&self.socket);
        command
    }

    fn identity(command: &mut Command) -> &mut Command {
        command.args([
            "--operation-id",
            "operation_1",
            "--idempotency-key",
            "retry_1",
            "--output",
            "json",
        ])
    }

    /// Imports the plan, then submits the stored plan with the v2 grant.
    fn apply_stored(&self, plan_id: &str) -> Output {
        let store = self.path("plans");
        fs::DirBuilder::new().mode(0o700).create(&store).unwrap();
        let imported = self
            .rustiron()
            .args(["plan", "import-file", "--plan-dir"])
            .arg(&store)
            .arg(self.path("plan.json"))
            .args(["--output", "json"])
            .output()
            .unwrap();
        assert!(
            imported.status.success(),
            "{}",
            String::from_utf8_lossy(&imported.stdout)
        );
        let mut command = self.rustiron();
        command
            .args(["plan", "apply", "--plan-dir"])
            .arg(&store)
            .arg(plan_id)
            .arg("--grant-file")
            .arg(self.path("grant.json"))
            .arg("--signature-file")
            .arg(self.path("signature"));
        Self::identity(&mut command).output().unwrap()
    }

    fn apply_file(&self, wait_seconds: &str) -> Output {
        let mut command = self.rustiron();
        command
            .args(["plan", "apply-file", "--plan-file"])
            .arg(self.path("plan.json"))
            .arg("--grant-file")
            .arg(self.path("grant.json"))
            .arg("--signature-file")
            .arg(self.path("signature"))
            .args(["--wait-seconds", wait_seconds]);
        Self::identity(&mut command).output().unwrap()
    }

    /// Serves the apply and then one status read per entry of `states`.
    /// The stored path sends `plan_canonical`; a plan file is sent as read.
    /// `reply` = `None` drops the apply reply, so the outcome is unknown.
    fn coordinator(
        &self,
        vector: &Value,
        plan_field: &str,
        reply: Option<SubmissionReply>,
        states: Vec<OutcomeState>,
    ) -> thread::JoinHandle<usize> {
        let plan = text(vector, plan_field).trim().as_bytes().to_vec();
        let grant = text(vector, "grant_input").trim().as_bytes().to_vec();
        let capture = vector["name"] == "capture";
        let listener = rustiron_control::bind(&self.socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        thread::spawn(move || {
            let mut reply = Some(reply);
            let mut served = 0;
            let mut idle = Instant::now();
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        idle = Instant::now();
                        stream.set_nonblocking(false).unwrap();
                        if let Some(reply) = reply.take() {
                            apply(stream, &plan, &grant, capture, reply);
                            if states.is_empty() {
                                return served;
                            }
                        } else {
                            status(stream, states[served.min(states.len() - 1)]);
                            served += 1;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if idle.elapsed() > Duration::from_secs(8) {
                            return served;
                        }
                        thread::sleep(Duration::from_millis(5));
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

fn write(stream: &mut UnixStream, bytes: &[u8]) {
    local::write_frame(
        stream,
        bytes,
        MAX_RESPONSE_BYTES,
        ErrorCode::ResponseTooLarge,
        Instant::now() + local::DEADLINE,
    )
    .unwrap();
}

/// Checks the exact signed v2 bytes and answers with `reply`, if any.
fn apply(
    mut stream: UnixStream,
    plan: &[u8],
    grant: &[u8],
    capture: bool,
    reply: Option<SubmissionReply>,
) {
    let request = decode_apply_request(&read(&mut stream)).unwrap();
    assert_eq!(request.plan, plan, "the v2 plan bytes");
    assert_eq!(request.grant, grant, "the grant bytes as signed");
    assert_eq!(request.signature, "synthetic_signature");
    let decoded = ProductBackupPlan::decode(&request.plan).unwrap();
    assert_eq!(
        matches!(decoded.target(), ProductBackupTarget::BackupCapture { .. }),
        capture
    );
    let Some(reply) = reply else {
        return;
    };
    let response = ApplyResponse {
        request_id: request.request_id,
        operation_id: request.operation_id,
        outcome: ApplyOutcome::ExecutorReply { reply },
    };
    write(&mut stream, &encode_apply_response(&response).unwrap());
}

fn status(mut stream: UnixStream, state: OutcomeState) {
    let request = decode_request(&read(&mut stream)).unwrap();
    let ReadCommand::OperationStatus { operation_id } = request.command else {
        panic!("expected a status read");
    };
    assert_eq!(operation_id.as_str(), "operation_1");
    let response = Response {
        request_id: Some(request.request_id),
        result: Ok(ReadData::OperationStatus(StatusValue {
            operation_id,
            state,
        })),
    };
    write(&mut stream, &encode_response(&response).unwrap());
}

fn recorded(state: OutcomeState, error: Option<&str>) -> SubmissionReply {
    SubmissionReply {
        schema_version: 1,
        operation_id: Some("operation_1".to_owned().try_into().unwrap()),
        state: Some(state),
        replay: false,
        error: error.map(str::to_owned),
        unclaimed_snapshot_id: None,
    }
}

fn outcome(output: &Output) -> Value {
    let wire: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&output.stdout)));
    assert_eq!(wire["data"]["value"]["operation_id"], "operation_1");
    wire["data"]["value"]["outcome"].clone()
}

#[test]
fn a_stored_product_plan_is_submitted_and_its_recorded_reply_is_reported() {
    for (name, plan_id) in [
        ("capture", "plan_product_capture"),
        ("probe", "plan_product_probe"),
    ] {
        let vector = vector(name);
        let fixture = Fixture::new(&vector);
        let server = fixture.coordinator(
            &vector,
            "plan_canonical",
            Some(recorded(OutcomeState::Untouched, Some(REFUSED))),
            vec![],
        );
        let output = fixture.apply_stored(plan_id);
        let outcome = outcome(&output);
        assert_eq!(outcome["kind"], "executor_reply", "{name}: {outcome}");
        assert_eq!(outcome["reply"]["state"], "untouched", "{name}");
        assert_eq!(outcome["reply"]["error"], REFUSED, "{name}");
        assert_eq!(output.status.code(), Some(5), "{name}: known, not success");
        assert_eq!(server.join().unwrap(), 0, "{name}: no status read needed");
    }
}

#[test]
fn a_product_capture_left_running_is_read_back_after_the_deadline() {
    let vector = vector("capture");
    let fixture = Fixture::new(&vector);
    let server = fixture.coordinator(
        &vector,
        "plan_input",
        None,
        vec![OutcomeState::Intent, OutcomeState::Untouched],
    );
    let output = fixture.apply_file("20");
    let outcome = outcome(&output);
    assert_eq!(outcome["kind"], "recorded_after_wait", "{outcome}");
    assert_eq!(outcome["state"], "untouched");
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(server.join().unwrap(), 2, "polls past the running capture");
}

/// W381 (D-032): a failed capture replies `failed`, with the unclaimed
/// snapshot of a W366 settlement when there is one, and exits 5 as
/// `untouched` did. A recheck refusal after intent still exits 4.
#[test]
fn a_failed_capture_reply_reports_failed_and_keeps_the_exit_class() {
    let snapshot = "d".repeat(64);
    for (error, unclaimed, expected) in [
        (None, Some(snapshot), 5),
        (Some("PROVISION_STEP_FAILED"), None, 5),
        (Some("PRECONDITION_CHANGED"), None, 4),
    ] {
        let vector = vector("capture");
        let fixture = Fixture::new(&vector);
        let mut reply = recorded(OutcomeState::Failed, error);
        reply.unclaimed_snapshot_id = unclaimed.clone();
        let server = fixture.coordinator(&vector, "plan_canonical", Some(reply), vec![]);
        let output = fixture.apply_stored("plan_product_capture");
        let outcome = outcome(&output);
        assert_eq!(outcome["kind"], "executor_reply", "{outcome}");
        assert_eq!(outcome["reply"]["state"], "failed");
        match &unclaimed {
            Some(snapshot) => assert_eq!(outcome["reply"]["unclaimed_snapshot_id"], *snapshot),
            None => assert!(outcome["reply"].get("unclaimed_snapshot_id").is_none()),
        }
        assert_eq!(output.status.code(), Some(expected), "{error:?}");
        assert_eq!(server.join().unwrap(), 0);
    }
    // The state read after the reply deadline.
    let vector = vector("capture");
    let fixture = Fixture::new(&vector);
    let server = fixture.coordinator(
        &vector,
        "plan_input",
        None,
        vec![OutcomeState::Intent, OutcomeState::Failed],
    );
    let output = fixture.apply_file("20");
    let outcome = outcome(&output);
    assert_eq!(outcome["kind"], "recorded_after_wait", "{outcome}");
    assert_eq!(outcome["state"], "failed");
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(server.join().unwrap(), 2);
}
