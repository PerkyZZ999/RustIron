//! W386 (D-035): standing capture plan creation and review, the offline run
//! list, and `schedule run` / `schedule status` against a synthetic
//! coordinator. The CLI grants nothing; the executor checks are tested in
//! the executor's product-profile suite.

use rustiron_contracts::{
    ApiError, ErrorCode, Id, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, ReadCommand, ReadData,
    Response,
    apply::{ApplyOutcome, ApplyResponse, decode_apply_request, encode_apply_response},
    approval::{SiteId, StandingCaptureGrant, StandingCapturePlan},
    decode_request, encode_response,
    execution::{EvidenceReceipt, EvidenceValue, OutcomeState, StatusValue, SubmissionReply},
    local,
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs,
    os::unix::{fs::DirBuilderExt, net::UnixStream},
    path::PathBuf,
    process::{Command, Output},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const VECTORS: &str = include_str!("../../contracts/tests/fixtures/standing-capture-vectors.json");

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

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

struct Fixture {
    directory: PathBuf,
    socket: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "ri-cli-standing-{}-{}",
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
        let socket = directory.join("control.sock");
        Self { directory, socket }
    }

    /// Writes the plan, the grant and a placeholder signature.
    fn write(&self, plan: &[u8], grant: &[u8]) {
        fs::write(self.directory.join("plan.json"), plan).unwrap();
        fs::write(self.directory.join("grant.json"), grant).unwrap();
        fs::write(
            self.directory.join("grant.json.sig"),
            b"synthetic_signature",
        )
        .unwrap();
    }

    fn rustiron(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_rustiron"))
            .arg("--socket")
            .arg(&self.socket)
            .args(args)
            .arg("--dir")
            .arg(&self.directory)
            .args(["--output", "json"])
            .output()
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

/// The compressed vector with window 0 opening `offset` seconds ago.
fn rebased(offset: u64) -> (Vec<u8>, Vec<u8>, u64) {
    let v = vector("compressed");
    let mut plan: Value = serde_json::from_str(v["plan_canonical"].as_str().unwrap()).unwrap();
    let mut grant: Value = serde_json::from_str(v["grant_canonical"].as_str().unwrap()).unwrap();
    let start = now() - offset;
    for record in [&mut plan, &mut grant] {
        record["valid_from"] = json!(start);
        record["first_window_start"] = json!(start);
        record["expires_at"] = json!(start + 3_600);
    }
    let plan = serde_json::to_vec(&plan).unwrap();
    grant["plan_digest"] = json!(StandingCapturePlan::decode(&plan).unwrap().digest());
    (plan, serde_json::to_vec(&grant).unwrap(), start)
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

/// A synthetic coordinator: records each apply as `succeeded`, answers
/// status reads from `recorded` (others `NOT_FOUND`), and exports a
/// receipt that started at `started[op]`.
#[derive(Default)]
struct Journal {
    recorded: HashMap<String, OutcomeState>,
    started: HashMap<String, u64>,
    applied: Vec<String>,
}

fn coordinator(
    socket: &std::path::Path,
    journal: Arc<Mutex<Journal>>,
    plan: Vec<u8>,
) -> thread::JoinHandle<()> {
    let listener = rustiron_control::bind(socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        let mut idle = Instant::now();
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    idle = Instant::now();
                    stream.set_nonblocking(false).unwrap();
                    let frame = read(&mut stream);
                    let mut journal = journal.lock().unwrap();
                    if let Ok(request) = decode_apply_request(&frame) {
                        assert_eq!(request.plan, plan, "the standing plan bytes");
                        let operation = request.operation_id.as_str().to_owned();
                        journal.applied.push(operation.clone());
                        journal
                            .recorded
                            .insert(operation.clone(), OutcomeState::Succeeded);
                        journal.started.insert(operation, now());
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
                        write(&mut stream, &encode_apply_response(&response).unwrap());
                        continue;
                    }
                    let request = decode_request(&frame).unwrap();
                    let result = match request.command {
                        ReadCommand::OperationStatus { operation_id } => {
                            match journal.recorded.get(operation_id.as_str()) {
                                Some(state) => Ok(ReadData::OperationStatus(StatusValue {
                                    operation_id,
                                    state: *state,
                                })),
                                None => Err(ApiError::new(ErrorCode::NotFound)),
                            }
                        }
                        ReadCommand::EvidenceExport { operation_id } => {
                            let started = journal.started[operation_id.as_str()];
                            Ok(ReadData::EvidenceExport(EvidenceValue {
                                operation_id,
                                receipt: EvidenceReceipt {
                                    body: json!({
                                        "snapshot_id": "ab".repeat(32),
                                        "operation": {"started_at": started, "finished_at": started + 30},
                                    }),
                                    body_sha256: "0".repeat(64),
                                    attestation: None,
                                    signature: None,
                                },
                            }))
                        }
                        other => panic!("unexpected read {other:?}"),
                    };
                    let response = Response {
                        request_id: Some(request.request_id),
                        result,
                    };
                    write(&mut stream, &encode_response(&response).unwrap());
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if idle.elapsed() > Duration::from_secs(3) {
                        return;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("accept failed: {e}"),
            }
        }
    })
}

fn run_id(grant: &[u8], window: u64) -> String {
    StandingCaptureGrant::decode(grant)
        .unwrap()
        .run(&SiteId::try_from("blog9".to_owned()).unwrap(), window)
        .unwrap()
        .operation_id
        .as_str()
        .to_owned()
}

#[test]
fn plan_creation_matches_the_vector_and_refuses_out_of_bounds_schedules() {
    let v = vector("daily");
    let plan: Value = serde_json::from_str(v["plan_canonical"].as_str().unwrap()).unwrap();
    let field = |name: &str| plan[name].to_string().trim_matches('"').to_owned();
    let args = |max_runs: &str| {
        let mut args = vec![
            "plan".to_owned(),
            "create".to_owned(),
            "product-standing-capture".to_owned(),
        ];
        for name in [
            "plan_id",
            "host_id",
            "host_epoch",
            "profile_digest",
            "requester",
            "destination_id",
            "destination_policy_digest",
            "recipe_id",
            "first_window_start",
            "period_seconds",
            "window_seconds",
            "valid_from",
            "expires_at",
        ] {
            args.push(format!("--{}", name.replace('_', "-")));
            args.push(field(name));
        }
        // Unsorted on the command line; the plan lists them sorted.
        for site in ["blog9", "blog13"] {
            args.extend(["--site-id".to_owned(), site.to_owned()]);
        }
        args.extend([
            "--max-runs".to_owned(),
            max_runs.to_owned(),
            "--limitation".to_owned(),
            "synthetic standing capture vector".to_owned(),
        ]);
        args
    };
    let created = Command::new(env!("CARGO_BIN_EXE_rustiron"))
        .args(args("35"))
        .output()
        .unwrap();
    assert!(created.status.success(), "{created:?}");
    assert_eq!(
        created.stdout,
        v["plan_canonical"].as_str().unwrap().as_bytes()
    );
    let refused = Command::new(env!("CARGO_BIN_EXE_rustiron"))
        .args(args("36"))
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(2));
    assert!(StandingCapturePlan::decode(&refused.stdout).is_err());
}

#[test]
fn review_lists_every_signed_window() {
    let fixture = Fixture::new();
    let v = vector("daily");
    fixture.write(
        v["plan_canonical"].as_str().unwrap().as_bytes(),
        v["grant_canonical"].as_str().unwrap().as_bytes(),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_rustiron"))
        .args(["--output", "json", "plan", "review-file"])
        .arg(fixture.directory.join("plan.json"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let review: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(review["verb"], "backup_capture");
    assert_eq!(review["plan_digest"], v["plan_digest"]);
    let windows = review["standing_windows"].as_array().unwrap();
    assert_eq!(windows.len(), 35);
    assert_eq!(windows[0]["opens_at"], 1_799_996_100);
    assert_eq!(
        windows[34]["closes_at"],
        1_799_996_100 + 34 * 86_400 + 7_200
    );
}

#[test]
fn the_offline_run_list_matches_the_vector_identities() {
    let fixture = Fixture::new();
    let v = vector("daily");
    fixture.write(
        v["plan_input"].as_str().unwrap().as_bytes(),
        v["grant_input"].as_str().unwrap().as_bytes(),
    );
    let output = fixture.rustiron(&["schedule", "runs"]);
    assert!(output.status.success(), "{output:?}");
    let listed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(listed["authority"], "none");
    assert_eq!(listed["grant_sha256"], v["grant_sha256"]);
    assert_eq!(listed["windows"].as_array().unwrap().len(), 35);
    for expected in v["runs"].as_array().unwrap() {
        let window = &listed["windows"][expected["window"].as_u64().unwrap() as usize];
        let run = window["runs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|run| run["site_id"] == expected["site_id"])
            .unwrap();
        assert_eq!(run["operation_id"], expected["operation_id"]);
        assert_eq!(run["idempotency_key"], expected["idempotency_key"]);
    }
    // A grant for another plan is refused before anything is listed.
    let other = vector("compressed");
    fixture.write(
        v["plan_input"].as_str().unwrap().as_bytes(),
        other["grant_input"].as_str().unwrap().as_bytes(),
    );
    let refused = fixture.rustiron(&["schedule", "runs"]);
    assert_eq!(refused.status.code(), Some(2));
}

#[test]
fn a_run_submits_the_open_window_and_reports_a_missed_window() {
    let fixture = Fixture::new();
    // Window 3 opened 10 s ago; windows 0 to 2 are closed.
    let (plan, grant, start) = rebased(3 * 300 + 10);
    fixture.write(&plan, &grant);
    let journal = Arc::new(Mutex::new(Journal::default()));
    {
        let mut journal = journal.lock().unwrap();
        journal
            .recorded
            .insert(run_id(&grant, 0), OutcomeState::Succeeded);
        journal.started.insert(run_id(&grant, 0), start + 5);
        journal
            .recorded
            .insert(run_id(&grant, 1), OutcomeState::Failed);
    }
    let server = coordinator(&fixture.socket, Arc::clone(&journal), plan.clone());
    let output = fixture.rustiron(&["schedule", "run", "--rpo-target-seconds", "600"]);
    server.join().unwrap();
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    // Window 2 has no run: the newest closed window is missed.
    assert_eq!(output.status.code(), Some(5), "{report}");
    assert_eq!(journal.lock().unwrap().applied, vec![run_id(&grant, 3)]);
    assert_eq!(report["window"]["window"], 3);
    assert_eq!(report["submissions"][0]["exit"], 0);
    let status = &report["status"];
    let states: Vec<&str> = status["windows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["runs"][0]["state"].as_str().unwrap())
        .collect();
    assert_eq!(
        states,
        [
            "succeeded",
            "failed",
            "missed",
            "succeeded",
            "pending",
            "pending"
        ]
    );
    assert_eq!(status["missed"], json!([{"window": 2, "site_id": "blog9"}]));
    assert_eq!(status["failed"], json!([{"window": 1, "site_id": "blog9"}]));
    assert_eq!(status["alerts"], json!(["newest_closed_window_missed"]));
    assert_eq!(status["remaining_windows"], 3);
    let site = &status["sites"][0];
    assert_eq!(site["newest_snapshot"]["window"], 3);
    assert_eq!(site["newest_snapshot"]["operation_id"], run_id(&grant, 3));
    assert!(site["snapshot_age_seconds"].as_u64().unwrap() <= 5);
    assert_eq!(site["rpo_met"], true);
}

#[test]
fn status_alone_alerts_on_rpo_and_run_outside_a_window_submits_nothing() {
    let fixture = Fixture::new();
    // Window 1 closed 30 s ago; window 2 opens in 150 s.
    let (plan, grant, start) = rebased(300 + 150);
    fixture.write(&plan, &grant);
    let journal = Arc::new(Mutex::new(Journal::default()));
    {
        let mut journal = journal.lock().unwrap();
        for window in [0, 1] {
            journal
                .recorded
                .insert(run_id(&grant, window), OutcomeState::Succeeded);
        }
        journal.started.insert(run_id(&grant, 1), start + 301);
    }
    let server = coordinator(&fixture.socket, Arc::clone(&journal), plan.clone());
    let output = fixture.rustiron(&["schedule", "run", "--rpo-target-seconds", "100"]);
    server.join().unwrap();
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(3), "{report}");
    assert!(journal.lock().unwrap().applied.is_empty());
    assert_eq!(report["window"], Value::Null);
    assert_eq!(report["next_window_opens_at"], start + 600);
    assert_eq!(report["status"]["alerts"], json!(["rpo_exceeded"]));
    assert_eq!(report["status"]["sites"][0]["rpo_met"], false);

    fs::remove_file(&fixture.socket).unwrap();
    let server = coordinator(&fixture.socket, Arc::clone(&journal), plan);
    let status = fixture.rustiron(&["schedule", "status", "--rpo-target-seconds", "600"]);
    server.join().unwrap();
    let report: Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status.status.code(), Some(0), "{report}");
    assert_eq!(report["alerts"], json!([]));
    assert_eq!(report["closed_windows"], 2);
    let _ = Id::try_from(
        report["sites"][0]["newest_snapshot"]["operation_id"]
            .as_str()
            .unwrap()
            .to_owned(),
    )
    .unwrap();
}
