//! Real Linux socket framing and credential tests; no privileged identities.

use rustiron_contracts::{ErrorCode, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, local};
use std::{
    io::Write,
    net::Shutdown,
    os::unix::net::UnixStream,
    thread,
    time::{Duration, Instant},
};

#[test]
fn requires_exact_kernel_peer_uid() {
    let (first, second) = UnixStream::pair().unwrap();
    let uid = local::operator_uid().unwrap();
    assert!(local::require_peer(&first, uid).is_ok());
    assert_eq!(
        local::require_peer(&second, u32::MAX),
        Err(ErrorCode::UnauthorizedPeer)
    );
}

#[test]
fn round_trip_requires_one_complete_frame_and_eof() {
    let (mut sender, mut receiver) = UnixStream::pair().unwrap();
    let deadline = Instant::now() + local::DEADLINE;
    local::write_frame(
        &mut sender,
        b"{}",
        MAX_REQUEST_BYTES,
        ErrorCode::RequestTooLarge,
        deadline,
    )
    .unwrap();
    assert_eq!(
        local::read_frame(
            &mut receiver,
            MAX_REQUEST_BYTES,
            ErrorCode::RequestTooLarge,
            deadline
        )
        .unwrap(),
        b"{}"
    );
}

#[test]
fn rejects_truncated_empty_oversized_and_trailing_frames() {
    for (bytes, error) in [
        (vec![], ErrorCode::InvalidRequest),
        (vec![0, 0], ErrorCode::InvalidRequest),
        (vec![0, 0, 0, 0], ErrorCode::InvalidRequest),
        (vec![0, 0, 0, 2, b'{'], ErrorCode::InvalidRequest),
        (vec![0, 0, 0, 2, b'{', b'}', 0], ErrorCode::InvalidRequest),
        (
            ((MAX_REQUEST_BYTES + 1) as u32).to_be_bytes().to_vec(),
            ErrorCode::RequestTooLarge,
        ),
    ] {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        sender.write_all(&bytes).unwrap();
        sender.shutdown(Shutdown::Write).unwrap();
        assert_eq!(
            local::read_frame(
                &mut receiver,
                MAX_REQUEST_BYTES,
                ErrorCode::RequestTooLarge,
                Instant::now() + local::DEADLINE
            ),
            Err(error)
        );
    }
}

#[test]
fn trickled_bytes_cannot_reset_the_absolute_deadline() {
    let (mut sender, mut receiver) = UnixStream::pair().unwrap();
    let writer = thread::spawn(move || {
        let bytes = [0, 0, 0, 5, b'a', b'b', b'c', b'd', b'e'];
        for byte in bytes {
            if sender.write_all(&[byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(40));
        }
    });
    let start = Instant::now();
    assert_eq!(
        local::read_frame(
            &mut receiver,
            MAX_REQUEST_BYTES,
            ErrorCode::RequestTooLarge,
            start + Duration::from_millis(100)
        ),
        Err(ErrorCode::DependencyUnavailable)
    );
    assert!(start.elapsed() < Duration::from_secs(1));
    drop(receiver);
    writer.join().unwrap();
}

#[test]
fn withheld_eof_and_blocked_output_have_deadlines() {
    let (mut sender, mut receiver) = UnixStream::pair().unwrap();
    sender.write_all(&[0, 0, 0, 2, b'{', b'}']).unwrap();
    assert_eq!(
        local::read_frame(
            &mut receiver,
            10,
            ErrorCode::RequestTooLarge,
            Instant::now() + Duration::from_millis(70)
        ),
        Err(ErrorCode::DependencyUnavailable)
    );
    let (mut sender, _receiver) = UnixStream::pair().unwrap();
    assert_eq!(
        local::write_frame(
            &mut sender,
            &vec![b'x'; MAX_RESPONSE_BYTES],
            MAX_RESPONSE_BYTES,
            ErrorCode::ResponseTooLarge,
            Instant::now() + Duration::from_millis(70)
        ),
        Err(ErrorCode::DependencyUnavailable)
    );
}
