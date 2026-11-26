//! Real CLI subprocesses and production connection handler on a private Linux socket.

use rustiron_contracts::{local, *};
use std::{
    fs,
    io::{Read, Write},
    net::Shutdown,
    os::unix::{
        fs::{DirBuilderExt, PermissionsExt},
        net::UnixStream,
    },
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
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("ri-{}-{suffix}", std::process::id()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let socket = directory.join("control.sock");
        Self { directory, socket }
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_rustiron"))
            .arg("--socket")
            .arg(&self.socket)
            .args(args)
            .output()
            .unwrap()
    }
    fn once(&self, handler: impl FnOnce(UnixStream) + Send + 'static) -> thread::JoinHandle<()> {
        let listener = rustiron_control::bind(&self.socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        thread::spawn(move || {
            let deadline = Instant::now() + local::DEADLINE;
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        handler(stream);
                        return;
                    }
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => panic!("test accept failed: {error}"),
                }
            }
        })
    }
    fn real(&self) -> thread::JoinHandle<()> {
        self.once(|stream| {
            assert!(rustiron_control::handle_connection(stream));
        })
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).unwrap();
    }
}

fn response(output: &Output) -> Response {
    decode_response(&output.stdout).unwrap()
}
fn take_request(stream: &mut UnixStream) -> Request {
    let bytes = local::read_frame(
        stream,
        MAX_REQUEST_BYTES,
        ErrorCode::RequestTooLarge,
        Instant::now() + local::DEADLINE,
    )
    .unwrap();
    decode_request(&bytes).unwrap()
}

#[test]
fn doctor_subprocess_has_json_and_human_observations_without_profile_claims() {
    for mode in ["json", "human"] {
        let fixture = Fixture::new();
        let server = fixture.real();
        let output = fixture.run(&["doctor", "--output", mode]);
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        if mode == "json" {
            let result = response(&output);
            let Ok(ReadData::Doctor(report)) = result.result else {
                panic!("expected doctor");
            };
            assert!(matches!(
                report.kernel_release,
                Observation::Observed { .. }
            ));
            assert_eq!(
                report.hosting_profile,
                Observation::Unknown {
                    reason: UnknownReason::NotChecked
                }
            );
            assert_eq!(
                report.site_confinement,
                Observation::Unknown {
                    reason: UnknownReason::NotChecked
                }
            );
        } else {
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(text.contains("Hosting profile: unknown (NotChecked)"));
            assert!(text.contains("Site confinement: unknown (NotChecked)"));
        }
        server.join().unwrap();
    }
}

#[test]
fn inventory_is_unavailable_instead_of_fabricated_empty() {
    for args in [
        &["site", "list", "--limit", "20", "--output", "json"][..],
        &["site", "inspect", "site-a", "--output", "json"][..],
    ] {
        let fixture = Fixture::new();
        let server = fixture.real();
        let output = fixture.run(args);
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(
            response(&output).result.unwrap_err().code(),
            ErrorCode::DependencyUnavailable
        );
        server.join().unwrap();
    }
}

#[test]
fn operation_status_is_unavailable_without_an_executor() {
    let fixture = Fixture::new();
    let server = fixture.real();
    let output = fixture.run(&["operation", "status", "op-1", "--output", "json"]);
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(
        response(&output).result.unwrap_err().code(),
        ErrorCode::DependencyUnavailable
    );
    server.join().unwrap();
}

#[test]
fn operation_status_cli_checks_the_operation_and_renders_the_recorded_state() {
    for matching in [true, false] {
        let fixture = Fixture::new();
        let server = fixture.once(move |mut stream| {
            let request = take_request(&mut stream);
            assert_eq!(
                request.command,
                ReadCommand::OperationStatus {
                    operation_id: Id::try_from("op-1".to_owned()).unwrap()
                }
            );
            let response = Response {
                request_id: Some(request.request_id),
                result: Ok(ReadData::OperationStatus(
                    rustiron_contracts::execution::StatusValue {
                        operation_id: Id::try_from(
                            if matching { "op-1" } else { "other" }.to_owned(),
                        )
                        .unwrap(),
                        state: rustiron_contracts::execution::OutcomeState::Intent,
                    },
                )),
            };
            local::write_frame(
                &mut stream,
                &encode_response(&response).unwrap(),
                MAX_RESPONSE_BYTES,
                ErrorCode::ResponseTooLarge,
                Instant::now() + local::DEADLINE,
            )
            .unwrap();
        });
        let output = fixture.run(&["operation", "status", "op-1", "--output", "human"]);
        if matching {
            assert!(output.status.success());
            assert!(
                String::from_utf8(output.stdout)
                    .unwrap()
                    .contains("Recorded state: Intent")
            );
        } else {
            assert_eq!(output.status.code(), Some(2));
        }
        server.join().unwrap();
    }
}

#[test]
fn evidence_export_is_unavailable_without_an_executor() {
    let fixture = Fixture::new();
    let server = fixture.real();
    let output = fixture.run(&["evidence", "export", "op-1", "--output", "json"]);
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(
        response(&output).result.unwrap_err().code(),
        ErrorCode::DependencyUnavailable
    );
    server.join().unwrap();
}

#[test]
fn evidence_export_cli_checks_the_operation_and_labels_the_receipt() {
    for matching in [true, false] {
        let fixture = Fixture::new();
        let server = fixture.once(move |mut stream| {
            let request = take_request(&mut stream);
            assert_eq!(
                request.command,
                ReadCommand::EvidenceExport {
                    operation_id: Id::try_from("op-1".to_owned()).unwrap()
                }
            );
            let response = Response {
                request_id: Some(request.request_id),
                result: Ok(ReadData::EvidenceExport(
                    rustiron_contracts::execution::EvidenceValue {
                        operation_id: Id::try_from(
                            if matching { "op-1" } else { "other" }.to_owned(),
                        )
                        .unwrap(),
                        receipt: rustiron_contracts::execution::EvidenceReceipt {
                            body: serde_json::json!({"receipt_schema": "rustiron-recovery-receipt/1"}),
                            body_sha256: "ab".repeat(32),
                            attestation: None,
                            signature: None,
                        },
                    },
                )),
            };
            local::write_frame(
                &mut stream,
                &encode_response(&response).unwrap(),
                MAX_RESPONSE_BYTES,
                ErrorCode::ResponseTooLarge,
                Instant::now() + local::DEADLINE,
            )
            .unwrap();
        });
        let output = fixture.run(&["evidence", "export", "op-1", "--output", "human"]);
        if matching {
            assert!(output.status.success());
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(text.contains("Self-attested receipt. Not independent proof."));
            assert!(text.contains("Signature: none (self-attested, unsigned)."));
        } else {
            assert_eq!(output.status.code(), Some(2));
        }
        server.join().unwrap();
    }
}

#[test]
fn absence_and_unsafe_socket_paths_have_fixed_public_errors() {
    let fixture = Fixture::new();
    let output = fixture.run(&["doctor", "--output", "json"]);
    assert_eq!(output.status.code(), Some(7));
    let listener = rustiron_control::bind(&fixture.socket).unwrap();
    assert!(rustiron_control::bind(&fixture.socket).is_err());
    assert!(fixture.socket.exists());
    fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o755)).unwrap();
    let output = fixture.run(&["doctor", "--output", "json"]);
    assert_eq!(output.status.code(), Some(3));
    fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o700)).unwrap();
    drop(listener);
    fs::remove_file(&fixture.socket).unwrap();
    std::os::unix::fs::symlink("missing", &fixture.socket).unwrap();
    let output = fixture.run(&["doctor", "--output", "json"]);
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn cli_usage_errors_do_not_echo_canary_values() {
    let fixture = Fixture::new();
    let canary = "CANARY_NOT_A_SECRET_cli_input";
    for args in [
        vec!["doctor", "--output", "json", "--unknown", canary],
        vec![
            "site", "inspect", canary, "--output", "json", "--limit", "0",
        ],
        vec!["site", "list", "--limit", "101", "--output", "json"],
    ] {
        let output = fixture.run(&args);
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(
            response(&output).result.unwrap_err().code(),
            ErrorCode::InvalidRequest
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains(canary));
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn cli_rejects_wrong_response_id_kind_and_oversized_prefix() {
    for case in [0, 1, 2] {
        let fixture = Fixture::new();
        let server = fixture.once(move |mut stream| {
            let request = take_request(&mut stream);
            if case == 2 {
                stream
                    .write_all(&((MAX_RESPONSE_BYTES + 1) as u32).to_be_bytes())
                    .unwrap();
                stream.shutdown(Shutdown::Write).unwrap();
                return;
            }
            let result = Response {
                request_id: Some(if case == 0 {
                    Id::try_from("wrong-id".to_owned()).unwrap()
                } else {
                    request.request_id
                }),
                result: if case == 0 {
                    Err(ApiError::new(ErrorCode::NotFound))
                } else {
                    Ok(ReadData::SiteList(SitePage {
                        items: vec![],
                        next_cursor: None,
                    }))
                },
            };
            local::write_frame(
                &mut stream,
                &encode_response(&result).unwrap(),
                MAX_RESPONSE_BYTES,
                ErrorCode::ResponseTooLarge,
                Instant::now() + local::DEADLINE,
            )
            .unwrap();
        });
        let output = fixture.run(&["doctor", "--output", "json"]);
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(
            response(&output).result.unwrap_err().code(),
            if case == 2 {
                ErrorCode::ResponseTooLarge
            } else {
                ErrorCode::InvalidRequest
            }
        );
        server.join().unwrap();
    }
}

#[test]
fn real_cli_deadline_bounds_an_unresponsive_coordinator() {
    let fixture = Fixture::new();
    let server = fixture.once(|mut stream| {
        take_request(&mut stream);
        thread::sleep(local::DEADLINE + Duration::from_millis(150));
    });
    let start = Instant::now();
    let output = fixture.run(&["doctor", "--output", "json"]);
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(
        response(&output).result.unwrap_err().code(),
        ErrorCode::DependencyUnavailable
    );
    assert!(start.elapsed() < local::DEADLINE + Duration::from_secs(2));
    server.join().unwrap();
}

#[test]
fn malformed_client_data_gets_safe_server_errors() {
    let fixture = Fixture::new();
    let server = fixture.real();
    let mut stream = UnixStream::connect(&fixture.socket).unwrap();
    let input = br#"{"schema_version":1,"request_id":"r-1","method":"doctor","params":{"CANARY_NOT_A_SECRET":"value"}}"#;
    local::write_frame(
        &mut stream,
        input,
        MAX_REQUEST_BYTES,
        ErrorCode::RequestTooLarge,
        Instant::now() + local::DEADLINE,
    )
    .unwrap();
    let bytes = local::read_frame(
        &mut stream,
        MAX_RESPONSE_BYTES,
        ErrorCode::ResponseTooLarge,
        Instant::now() + local::DEADLINE,
    )
    .unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("CANARY_NOT_A_SECRET"));
    assert_eq!(
        decode_response(&bytes).unwrap().result.unwrap_err().code(),
        ErrorCode::InvalidRequest
    );
    server.join().unwrap();
}

#[test]
fn real_cli_inspects_persisted_report_without_claiming_adoption() {
    let fixture = Fixture::new();
    let mut store = rustiron_core::InventoryStore::initialize(&fixture.directory).unwrap();
    let report = InventoryProvenance {
        reported_at: Timestamp::try_from(42).unwrap(),
        source: InventorySource::OperatorReport,
    };
    store
        .replace(&InventorySnapshot {
            schema_version: SchemaVersion::V1,
            report: report.clone(),
            complete: true,
            sites: vec![ReportedSite {
                site_id: Id::try_from("site-a".to_owned()).unwrap(),
                name: Text::try_from("Reported A".to_owned()).unwrap(),
                configuration_generation: None,
            }],
        })
        .unwrap();
    let coordinator = rustiron_control::Coordinator::new(Some(store));
    let server = fixture.once(move |stream| {
        assert!(coordinator.handle(stream));
    });
    let output = fixture.run(&["site", "inspect", "site-a", "--output", "json"]);
    assert_eq!(output.status.code(), Some(0));
    let Ok(ReadData::SiteInspect(site)) = response(&output).result else {
        panic!("expected persisted site")
    };
    assert_eq!(site.site.ownership, Ownership::ObservedOnly);
    assert_eq!(site.site.inventory, Some(report));
    assert_eq!(
        site.configuration_generation,
        Observation::Unknown {
            reason: UnknownReason::NotChecked
        }
    );
    server.join().unwrap();
}

#[test]
fn a_stalled_peer_does_not_block_the_next_read() {
    let fixture = Fixture::new();
    let listener = rustiron_control::bind(&fixture.socket).unwrap();
    thread::spawn(move || {
        let _ = rustiron_control::Coordinator::new(None).serve(listener);
    });
    let _stalled = UnixStream::connect(&fixture.socket).unwrap();
    let start = Instant::now();
    let output = fixture.run(&["doctor", "--output", "json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn the_ninth_connection_is_dropped_while_eight_are_held() {
    let fixture = Fixture::new();
    let listener = rustiron_control::bind(&fixture.socket).unwrap();
    thread::spawn(move || {
        let _ = rustiron_control::Coordinator::new(None).serve(listener);
    });
    let mut held = Vec::new();
    for _ in 0..local::MAX_CONNECTIONS {
        held.push(UnixStream::connect(&fixture.socket).unwrap());
    }
    thread::sleep(Duration::from_millis(50));
    let start = Instant::now();
    let refused = fixture.run(&["doctor", "--output", "json"]);
    assert_eq!(refused.status.code(), Some(7));
    assert_eq!(
        response(&refused).result.unwrap_err().code(),
        ErrorCode::DependencyUnavailable
    );
    assert!(start.elapsed() < Duration::from_secs(2));
    drop(held);
    thread::sleep(Duration::from_millis(100));
    let output = fixture.run(&["doctor", "--output", "json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn a_slow_byte_does_not_extend_the_read_deadline() {
    let fixture = Fixture::new();
    let listener = rustiron_control::bind(&fixture.socket).unwrap();
    thread::spawn(move || {
        let _ = rustiron_control::Coordinator::new(None).serve(listener);
    });
    let mut stream = UnixStream::connect(&fixture.socket).unwrap();
    stream.write_all(&[0]).unwrap();
    stream
        .set_read_timeout(Some(local::DEADLINE + Duration::from_secs(3)))
        .unwrap();
    let start = Instant::now();
    let mut buffer = [0_u8; 64];
    let _ = stream.read(&mut buffer);
    let elapsed = start.elapsed();
    assert!(
        elapsed < local::DEADLINE + Duration::from_secs(2),
        "slow byte extended the wait to {elapsed:?}"
    );
    assert!(
        elapsed > Duration::from_secs(3),
        "failed before the deadline"
    );
}
