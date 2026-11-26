//! Linux-only framing and peer-credential primitives for the local development IPC.
//!
//! Callers choose their trusted expected UID; these helpers grant no executor authority.

use crate::ErrorCode;
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    net::{self, AddressFamily, SocketAddrUnix, SocketFlags, SocketType},
    process::{geteuid, getuid},
};
use std::{
    fs,
    io::{self, Read, Write},
    net::Shutdown,
    os::unix::{
        fs::{FileTypeExt, MetadataExt},
        net::UnixStream,
    },
    path::Path,
    time::{Duration, Instant},
};

/// Complete local transaction deadline, not a timeout reset by each byte.
pub const DEADLINE: Duration = Duration::from_secs(5);
/// Maximum active coordinator handlers; excess accepted connections are closed.
pub const MAX_CONNECTIONS: usize = 8;

/// Requires an ordinary non-root development identity, without setuid execution.
pub fn operator_uid() -> Result<u32, ErrorCode> {
    let uid = geteuid();
    if uid.is_root() || uid != getuid() {
        return Err(ErrorCode::UnauthorizedPeer);
    }
    Ok(uid.as_raw())
}

/// Checks the kernel's connected peer UID against caller-owned policy.
pub fn require_peer(stream: &UnixStream, expected_uid: u32) -> Result<(), ErrorCode> {
    let peer = net::sockopt::socket_peercred(stream).map_err(|_| ErrorCode::UnauthorizedPeer)?;
    if peer.uid.as_raw() != expected_uid {
        return Err(ErrorCode::UnauthorizedPeer);
    }
    Ok(())
}

/// Requires an absolute socket path in an existing canonical, owner-only directory.
pub fn check_parent(path: &Path, uid: u32) -> Result<(), ErrorCode> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(ErrorCode::InvalidRequest);
    }
    let parent = path.parent().ok_or(ErrorCode::InvalidRequest)?;
    let metadata = fs::symlink_metadata(parent).map_err(io_code)?;
    if !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.mode() & 0o7777 != 0o700
        || fs::canonicalize(parent).map_err(io_code)? != parent
    {
        return Err(ErrorCode::UnauthorizedPeer);
    }
    Ok(())
}

/// Connects without an unbounded backlog wait and verifies pathname and kernel peer.
pub fn connect(path: &Path, uid: u32, deadline: Instant) -> Result<UnixStream, ErrorCode> {
    check_parent(path, uid)?;
    let metadata = fs::symlink_metadata(path).map_err(io_code)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != uid
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(ErrorCode::UnauthorizedPeer);
    }
    connect_peer(path, uid, deadline)
}

/// Connects with a deadline and verifies kernel peer credentials.
///
/// This does not validate pathname ownership or ancestry. Callers must do so
/// according to their own trust policy before invoking it.
pub fn connect_peer(path: &Path, uid: u32, deadline: Instant) -> Result<UnixStream, ErrorCode> {
    let fd = net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| ErrorCode::DependencyUnavailable)?;
    let address = SocketAddrUnix::new(path).map_err(|_| ErrorCode::InvalidRequest)?;
    match net::connect(&fd, &address) {
        Ok(()) => {}
        Err(rustix::io::Errno::INPROGRESS) => {
            loop {
                let remaining = remaining(deadline)?;
                let timeout =
                    Timespec::try_from(remaining).map_err(|_| ErrorCode::DependencyUnavailable)?;
                let mut fds = [PollFd::new(&fd, PollFlags::OUT)];
                match poll(&mut fds, Some(&timeout)) {
                    Ok(0) => return Err(ErrorCode::DependencyUnavailable),
                    Ok(_) => break,
                    Err(rustix::io::Errno::INTR) => continue,
                    Err(_) => return Err(ErrorCode::DependencyUnavailable),
                }
            }
            net::sockopt::socket_error(&fd)
                .map_err(|_| ErrorCode::DependencyUnavailable)?
                .map_err(|_| ErrorCode::DependencyUnavailable)?;
        }
        Err(error) => return Err(io_code(error.into())),
    }
    let stream = UnixStream::from(fd);
    stream.set_nonblocking(false).map_err(io_code)?;
    require_peer(&stream, uid)?;
    Ok(stream)
}

/// Reads one length-prefixed payload followed by EOF, within an absolute deadline.
///
/// EOF is required: senders half-close their write direction after the frame.
/// The length is checked before allocating, and trailing frames are rejected.
pub fn read_frame(
    stream: &mut UnixStream,
    limit: usize,
    too_large: ErrorCode,
    deadline: Instant,
) -> Result<Vec<u8>, ErrorCode> {
    let mut prefix = [0; 4];
    read_exact(stream, &mut prefix, deadline)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > limit {
        return Err(too_large);
    }
    if length == 0 {
        return Err(ErrorCode::InvalidRequest);
    }
    let mut payload = vec![0; length];
    read_exact(stream, &mut payload, deadline)?;
    let mut extra = [0];
    if read_some(stream, &mut extra, deadline)? != 0 {
        return Err(ErrorCode::InvalidRequest);
    }
    Ok(payload)
}

/// Writes exactly one bounded frame and half-closes the write direction.
pub fn write_frame(
    stream: &mut UnixStream,
    payload: &[u8],
    limit: usize,
    too_large: ErrorCode,
    deadline: Instant,
) -> Result<(), ErrorCode> {
    if payload.len() > limit {
        return Err(too_large);
    }
    let length = u32::try_from(payload.len()).map_err(|_| too_large)?;
    write_all(stream, &length.to_be_bytes(), deadline)?;
    write_all(stream, payload, deadline)?;
    stream.shutdown(Shutdown::Write).map_err(io_code)
}

fn remaining(deadline: Instant) -> Result<Duration, ErrorCode> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(ErrorCode::DependencyUnavailable)
}

fn read_some(
    stream: &mut UnixStream,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<usize, ErrorCode> {
    loop {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(io_code)?;
        match stream.read(buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => {
                remaining(deadline)?;
                return result.map_err(io_code);
            }
        }
    }
}

fn read_exact(
    stream: &mut UnixStream,
    mut buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), ErrorCode> {
    while !buffer.is_empty() {
        let count = read_some(stream, buffer, deadline)?;
        if count == 0 {
            return Err(ErrorCode::InvalidRequest);
        }
        buffer = &mut buffer[count..];
    }
    Ok(())
}

fn write_all(
    stream: &mut UnixStream,
    mut buffer: &[u8],
    deadline: Instant,
) -> Result<(), ErrorCode> {
    while !buffer.is_empty() {
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(io_code)?;
        match stream.write(buffer) {
            Ok(0) => return Err(ErrorCode::DependencyUnavailable),
            Ok(count) => {
                remaining(deadline)?;
                buffer = &buffer[count..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(io_code(error)),
        }
    }
    Ok(())
}

/// Converts OS failures to fixed public categories, without exposing raw paths/context.
pub fn io_code(error: io::Error) -> ErrorCode {
    if error.kind() == io::ErrorKind::PermissionDenied {
        ErrorCode::UnauthorizedPeer
    } else {
        ErrorCode::DependencyUnavailable
    }
}
