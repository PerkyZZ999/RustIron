//! W363 (B09): product capture write faults on the lab, through the
//! executor, the real admin helper and a fixture journal.
//!
//! The root lab tests here need a product-profile build (D-029 retired the
//! lab write-proof flag that W363 and W366 used), the store namespace and
//! relay, and the HTTPS lab store (docs/validation/S10-W363). They are
//! ignored by default.

use std::{
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    process::Command,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use rustiron_contracts::execution::OutcomeState;
use rustiron_executor::{Executor, ExecutorError, admin_helper, receipt};
use rustiron_journal::CaptureState;

use super::{
    admission::{id, provision},
    write::{env, lab_capture, lab_write_fixture},
};

const ACCOUNT: &str = "rs_w344a";
const SYSTEMCTL: &str = "/usr/bin/systemctl";

/// The UTC time of day, `HH:MM:SS.mmm`, to line up with a store trace.
fn utc() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let seconds = now.as_secs() % 86_400;
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60,
        now.subsec_millis()
    )
}

/// The first active unit that matches `pattern` within `limit`.
fn wait_for_unit(pattern: &str, limit: Duration) -> Option<String> {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        let listed = Command::new(SYSTEMCTL)
            .args(["list-units", "--plain", "--no-legend", "--", pattern])
            .output()
            .ok()?;
        if let Some(unit) = String::from_utf8_lossy(&listed.stdout)
            .split_whitespace()
            .next()
        {
            return Some(unit.to_owned());
        }
        thread::sleep(Duration::from_millis(10));
    }
    None
}

fn write_unit_pattern() -> String {
    format!("rustiron-store-write-{ACCOUNT}-*")
}

/// Bytes that the peer acknowledged on the established connections to
/// `port` inside the store namespace (`ss` `bytes_acked`).
fn store_bytes_acked(port: &str) -> u64 {
    let filter = format!("dport = :{port}");
    let listed = Command::new("/usr/sbin/ip")
        .args(["netns", "exec", "rustiron-store", "/usr/sbin/ss", "-Htni"])
        .args(["state", "established", &filter])
        .output();
    let Ok(listed) = listed else { return 0 };
    String::from_utf8_lossy(&listed.stdout)
        .split_whitespace()
        .filter_map(|word| word.strip_prefix("bytes_acked:"))
        .filter_map(|count| count.parse::<u64>().ok())
        .sum()
}

/// Stops the relay listener, and with it the relay, once the snapshot
/// write unit has sent `after` bytes toward the store. Returns the unit
/// and the bytes seen at the stop.
fn stop_relay_during_write(port: &str, after: u64) -> Option<(String, u64)> {
    let unit = wait_for_unit(&write_unit_pattern(), Duration::from_secs(120))?;
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        let sent = store_bytes_acked(port);
        if sent >= after {
            let stopped = Command::new(SYSTEMCTL)
                .args(["stop", &format!("rustiron-store-relay@{port}.socket")])
                .status()
                .ok()?;
            println!(
                "w363_event utc={} relay_stopped={stopped} bytes_acked={sent}",
                utc()
            );
            return stopped.success().then_some((unit, sent));
        }
        thread::sleep(Duration::from_millis(20));
    }
    None
}

/// Forwards one executor request to the real helper and returns the
/// helper's reply line. With `drop_during_write`, the executor's
/// connection closes as soon as the snapshot write unit runs (design step
/// 6). The executor then loses the reply while the helper finishes.
fn helper_proxy(
    front: UnixListener,
    helper: PathBuf,
    drop_during_write: bool,
) -> thread::JoinHandle<String> {
    thread::spawn(move || {
        let (mut executor_side, _) = front.accept().unwrap();
        let mut request = Vec::new();
        executor_side.read_to_end(&mut request).unwrap();
        let mut helper_side = UnixStream::connect(&helper).unwrap();
        helper_side.write_all(&request).unwrap();
        helper_side.shutdown(std::net::Shutdown::Write).unwrap();
        if drop_during_write {
            let unit = wait_for_unit(&write_unit_pattern(), Duration::from_secs(120));
            drop(executor_side);
            println!("w363_event utc={} reply_dropped_during={unit:?}", utc());
            let mut reply = String::new();
            helper_side.read_to_string(&mut reply).unwrap();
            return reply;
        }
        let mut reply = String::new();
        helper_side.read_to_string(&mut reply).unwrap();
        executor_side.write_all(reply.as_bytes()).unwrap();
        reply
    })
}

/// The helper's reply line without the manifest text.
fn reply_summary(reply: &str) -> String {
    let Some(payload) = reply.trim_end().strip_prefix("ok ") else {
        return format!("{:?}", reply.trim_end());
    };
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(payload) else {
        return "unreadable".to_owned();
    };
    if let Some(manifest) = value.get_mut("manifest").and_then(|m| m.as_object_mut()) {
        let lines = manifest
            .remove("text")
            .and_then(|text| text.as_str().map(|t| t.lines().count()));
        manifest.insert("lines".to_owned(), serde_json::json!(lines));
    }
    value.to_string()
}

/// W363 root lab test: one product capture of site `w344a` through the
/// executor, the real admin helper and a product-profile build, on a
/// fixture journal under /run (never the live one), then recovery. Run
/// through docs/validation/S10-W363/probe_faults.sh. `W363_CASE`:
/// - `full`: the capture succeeds and is journaled with its snapshot.
/// - `drift`: the operator PC changes the bucket default retention after
///   the lock precheck. The capture stays `running`. Recovery finds the
///   tagged snapshot and keeps it `running`.
/// - `lost_reply`: the executor's helper connection closes during the
///   snapshot write. The capture stays `running`, and recovery keeps it so.
/// - `relay_stop`: the relay stops during the snapshot write. The capture
///   stays `running`. Recovery runs after the relay starts again, finds no
///   tagged snapshot, and settles it `failed`.
#[test]
#[ignore = "root lab test: run through docs/validation/S10-W363/probe_faults.sh"]
fn product_capture_faults_as_root() {
    let case = env("W363_CASE");
    let (mut fixture, destination) = lab_write_fixture();
    let helper_socket = fixture.anchor.journal_dir.with_file_name("helper.sock");
    let helper_listener = UnixListener::bind(&helper_socket).unwrap();
    let front = fixture.anchor.journal_dir.with_file_name("front.sock");
    let front_listener = UnixListener::bind(&front).unwrap();
    fixture.anchor.admin_socket = Some(front);
    provision(&fixture.anchor, "w344a");
    let mut helper = admin_helper::Helper::new(fixture.anchor.clone(), None);
    thread::spawn(move || {
        let _ = admin_helper::serve_helper(&mut helper, &helper_listener, 4);
    });
    // The helper refuses work journaled in or before its start second (W177).
    thread::sleep(Duration::from_millis(1100));
    let mut executor = Executor::open(fixture.anchor.clone()).unwrap();
    let proxy = helper_proxy(front_listener, helper_socket, case == "lost_reply");
    let port = env("W363_RELAY_PORT");
    let after = env("W363_STOP_AFTER_BYTES").parse::<u64>().unwrap();
    let stopper = (case == "relay_stop").then(|| {
        let port = port.clone();
        thread::spawn(move || stop_relay_during_write(&port, after))
    });

    let name = env("W356_OPERATION");
    let operation = id(&name);
    println!(
        "w363_event utc={} submit case={case} operation={name}",
        utc()
    );
    let reply = lab_capture(&fixture, &destination, &name).submit(
        &mut executor,
        &operation,
        &id(&format!("key_{name}")),
    );
    println!(
        "w363_event utc={} reply state={:?} error={:?}",
        utc(),
        reply.state,
        reply.error
    );
    let helper_reply = proxy.join().unwrap();
    println!("w363_helper_reply={}", reply_summary(&helper_reply));
    if let Some(stopper) = stopper {
        let stopped = stopper.join().unwrap();
        let started = Command::new(SYSTEMCTL)
            .args(["start", &format!("rustiron-store-relay@{port}.socket")])
            .status()
            .unwrap();
        println!(
            "w363_event utc={} relay_started={started} stopped_during={stopped:?}",
            utc()
        );
        assert!(stopped.is_some() && started.success());
    }
    let recorded = executor.capture_status(&operation).unwrap().unwrap();
    println!(
        "w363_journal state={:?} snapshot={:?} files={:?} bytes={:?} consistency={:?}",
        recorded.state, recorded.snapshot_id, recorded.files, recorded.bytes, recorded.consistency
    );
    if case == "full" {
        assert_eq!(reply.state, Some(OutcomeState::Succeeded), "{reply:?}");
        assert_eq!(recorded.state, CaptureState::Succeeded);
        assert!(recorded.snapshot_id.is_some());
        return;
    }
    assert_eq!(reply.state, Some(OutcomeState::Intent), "{reply:?}");
    assert_eq!(recorded.state, CaptureState::Running);
    assert_eq!(recorded.snapshot_id, None);
    assert_eq!(
        receipt::capture_receipt(&recorded).unwrap_err(),
        ExecutorError::NotAdmitted,
    );
    let expected_error = match case.as_str() {
        "drift" => Some(ExecutorError::RetentionUnverified.code()),
        "lost_reply" => Some(ExecutorError::Unavailable.code()),
        "relay_stop" => {
            assert!(helper_reply.contains("\"snapshot\":null"), "{helper_reply}");
            reply.error.as_deref()
        }
        other => panic!("unknown case {other}"),
    };
    assert_eq!(reply.error.as_deref(), expected_error);

    let recovered = executor.reconcile_capture(&operation);
    let settled = executor.capture_status(&operation).unwrap().unwrap();
    println!(
        "w363_recovery result={:?} state={:?} snapshot={:?}",
        recovered.as_ref().map(|c| c.state),
        settled.state,
        settled.snapshot_id
    );
    if case == "relay_stop" {
        assert_eq!(recovered.unwrap().state, CaptureState::Failed);
        assert_eq!(settled.state, CaptureState::Failed);
    } else {
        assert_eq!(recovered.unwrap_err(), ExecutorError::PreconditionChanged);
        assert_eq!(settled.state, CaptureState::Running);
    }
    assert_eq!(settled.snapshot_id, None);
}

/// The snapshot ID that the helper reply names: `id` on a success, or
/// `snapshot` on an uncertain outcome.
fn replied_snapshot(reply: &str) -> Option<String> {
    let payload = reply.trim_end().strip_prefix("ok ")?;
    let value: serde_json::Value = serde_json::from_str(payload).ok()?;
    value["id"]
        .as_str()
        .or_else(|| value["snapshot"].as_str())
        .map(str::to_owned)
}

/// Starts a real admin helper on a new socket pair and returns the
/// executor's front socket and the proxy that forwards one request.
fn helper_behind_proxy(
    fixture: &super::BackupFixture,
    label: &str,
    drop_during_write: bool,
) -> (PathBuf, thread::JoinHandle<String>) {
    let directory = &fixture.anchor.journal_dir;
    let helper_socket = directory.with_file_name(format!("helper-{label}.sock"));
    let helper_listener = UnixListener::bind(&helper_socket).unwrap();
    let front = directory.with_file_name(format!("front-{label}.sock"));
    let front_listener = UnixListener::bind(&front).unwrap();
    let mut helper = admin_helper::Helper::new(fixture.anchor.clone(), None);
    thread::spawn(move || {
        let _ = admin_helper::serve_helper(&mut helper, &helper_listener, 4);
    });
    // The helper refuses work journaled in or before its start second (W177).
    thread::sleep(Duration::from_millis(1100));
    let proxy = helper_proxy(front_listener, helper_socket, drop_during_write);
    (front, proxy)
}

/// W366 root lab test: operator settlement of a capture that recovery
/// leaves `running`, then a new capture of the same site. The fixture is
/// the W363 one: the executor, the real admin helper and a fixture journal
/// under /run. Run through the docs/validation/S10-W366 lab steps with a
/// product-profile build. `W366_CASE`:
/// - `lost_reply`: the executor's helper connection closes during the
///   snapshot write, and the helper finishes a complete write.
/// - `partial`: a site file that the site account cannot read makes restic
///   exit 3 with a tagged partial snapshot. `W366_UNREADABLE` names the
///   file; the lab script creates it with mode 0 before the run.
///
/// In both cases plain recovery keeps the capture `running`. The settlement
/// records `failed`, keeps the tagged snapshot unclaimed, and writes the
/// receipt to `W366_RECEIPT`. A replay changes nothing. A new capture of
/// the site is then admitted and succeeds.
#[test]
#[ignore = "root lab test: run through the docs/validation/S10-W366 lab steps"]
fn product_capture_settlement_as_root() {
    let case = env("W366_CASE");
    let (mut fixture, destination) = lab_write_fixture();
    provision(&fixture.anchor, "w344a");
    let (front, proxy) = helper_behind_proxy(&fixture, "first", case == "lost_reply");
    fixture.anchor.admin_socket = Some(front);
    let mut executor = Executor::open(fixture.anchor.clone()).unwrap();
    if case == "partial" {
        let metadata = std::fs::metadata(env("W366_UNREADABLE")).unwrap();
        let mode = std::os::unix::fs::PermissionsExt::mode(&metadata.permissions());
        assert_eq!(mode & 0o777, 0);
    }

    let name = env("W356_OPERATION");
    let operation = id(&name);
    println!(
        "w366_event utc={} submit case={case} operation={name}",
        utc()
    );
    let reply = lab_capture(&fixture, &destination, &name).submit(
        &mut executor,
        &operation,
        &id(&format!("key_{name}")),
    );
    println!(
        "w366_event utc={} reply state={:?} error={:?}",
        utc(),
        reply.state,
        reply.error
    );
    // The proxy returns only after the helper's whole sequence ended.
    let helper_reply = proxy.join().unwrap();
    println!("w366_helper_reply={}", reply_summary(&helper_reply));
    let snapshot = replied_snapshot(&helper_reply).expect("the helper named a snapshot");
    match case.as_str() {
        "lost_reply" => assert!(helper_reply.contains("\"outcome\":\"succeeded\"")),
        "partial" => assert!(helper_reply.contains("\"outcome\":\"uncertain\"")),
        other => panic!("unknown case {other}"),
    }
    assert_eq!(reply.state, Some(OutcomeState::Intent), "{reply:?}");
    assert_eq!(
        executor.capture_status(&operation).unwrap().unwrap().state,
        CaptureState::Running
    );

    // Plain recovery: the tag alone is not proof of a complete write.
    assert_eq!(
        executor.reconcile_capture(&operation).unwrap_err(),
        ExecutorError::PreconditionChanged
    );
    // Settlement: `failed`, the snapshot unclaimed, never `succeeded`.
    let settled = executor.settle_capture_unclaimed(&operation).unwrap();
    println!(
        "w366_settled utc={} state={:?} snapshot={:?} unclaimed={:?} finished_at={:?}",
        utc(),
        settled.state,
        settled.snapshot_id,
        settled.unclaimed_snapshot_id,
        settled.finished_at.map(|t| t.get())
    );
    assert_eq!(settled.state, CaptureState::Failed);
    assert_eq!(settled.snapshot_id, None);
    assert_eq!(
        settled.unclaimed_snapshot_id.as_deref(),
        Some(snapshot.as_str())
    );
    let exported = receipt::capture_receipt(&settled).unwrap();
    assert_eq!(exported["body"]["operation"]["state"], "failed");
    assert_eq!(exported["body"]["unclaimed_snapshot"]["claimed"], false);
    std::fs::write(env("W366_RECEIPT"), exported.to_string()).unwrap();
    // A replay returns the stored status; nothing changes.
    assert_eq!(
        executor.settle_capture_unclaimed(&operation).unwrap(),
        settled
    );
    assert_eq!(executor.reconcile_capture(&operation).unwrap(), settled);

    // The site is free: a new capture is admitted and succeeds.
    if case == "partial" {
        std::fs::remove_file(env("W366_UNREADABLE")).unwrap();
    }
    drop(executor);
    let (front, proxy) = helper_behind_proxy(&fixture, "next", false);
    fixture.anchor.admin_socket = Some(front);
    let mut executor = Executor::open(fixture.anchor.clone()).unwrap();
    let next = format!("{name}_next");
    let reply = lab_capture(&fixture, &destination, &next).submit(
        &mut executor,
        &id(&next),
        &id(&format!("key_{next}")),
    );
    println!(
        "w366_next utc={} reply state={:?} error={:?} helper={}",
        utc(),
        reply.state,
        reply.error,
        reply_summary(&proxy.join().unwrap())
    );
    assert_eq!(reply.state, Some(OutcomeState::Succeeded), "{reply:?}");
    let recorded = executor.capture_status(&id(&next)).unwrap().unwrap();
    assert_eq!(recorded.state, CaptureState::Succeeded);
    assert_ne!(recorded.snapshot_id.as_deref(), Some(snapshot.as_str()));
}
