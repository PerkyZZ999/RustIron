//! The lab submit client does not report an unrelated operation as successful.
use std::{
    fs,
    os::unix::{fs::DirBuilderExt, net::UnixListener},
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
    thread,
    time::Instant,
};

use rustiron_contracts::{ErrorCode, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, local};

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn submit_with_reply(reply: &'static [u8]) -> Output {
    let directory = std::env::temp_dir().join(format!(
        "ri-submit-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let socket = directory.join("executor.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        local::read_frame(
            &mut stream,
            MAX_REQUEST_BYTES,
            ErrorCode::RequestTooLarge,
            Instant::now() + local::DEADLINE,
        )
        .unwrap();
        local::write_frame(
            &mut stream,
            reply,
            MAX_RESPONSE_BYTES,
            ErrorCode::ResponseTooLarge,
            Instant::now() + local::DEADLINE,
        )
        .unwrap();
    });
    let plan = directory.join("plan.json");
    let grant = directory.join("grant.json");
    let signature = directory.join("signature");
    fs::write(&plan, b"{}").unwrap();
    fs::write(&grant, b"{}").unwrap();
    fs::write(&signature, b"fixture").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_rustiron-submit"))
        .arg("--socket")
        .arg(socket)
        .arg("--executor-uid")
        .arg(rustix::process::getuid().as_raw().to_string())
        .arg("--plan")
        .arg(plan)
        .arg("--grant")
        .arg(grant)
        .arg("--signature")
        .arg(signature)
        .args(["--operation-id", "op_1", "--idempotency-key", "retry_1"])
        .output()
        .unwrap();
    server.join().unwrap();
    fs::remove_dir_all(directory).unwrap();
    output
}

#[test]
fn unrelated_success_is_transport_failure_not_success() {
    let output = submit_with_reply(br#"{"schema_version":1,"operation_id":"op_other","state":"succeeded","replay":false,"error":null}"#);
    assert_eq!(output.status.code(), Some(7));
    assert!(output.stdout.is_empty());
}

#[test]
fn matching_success_is_reported() {
    let output = submit_with_reply(br#"{"schema_version":1,"operation_id":"op_1","state":"succeeded","replay":false,"error":null}"#);
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains("op_1"));
}
