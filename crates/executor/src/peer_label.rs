//! D-020 (W331): the peer's SELinux label as the kernel captured it when the
//! peer connected (`SO_PEERSEC`). Unlike `/proc/<pid>/attr/current`, the
//! label is bound to the connection, so a reused pid cannot satisfy it.
//!
//! This module is the workspace's single recorded exception to the
//! `unsafe_code` lint (D-020 option 1). `tests/unsafe_scope.rs` fails when
//! `unsafe` appears in any other source file.
#![allow(unsafe_code)]

use std::os::{fd::AsRawFd, unix::net::UnixStream};

/// Longest label accepted. SELinux contexts are far shorter; a longer one
/// is refused rather than truncated.
const MAX_LABEL: usize = 256;

/// The connected peer's security context, for example
/// `system_u:system_r:rustiron_executor_t:s0`. `None` when the kernel has no
/// label for the socket (no LSM, `ENOPROTOOPT`), the label does not fit, or
/// it is not UTF-8. Every caller treats `None` as a refusal.
pub fn peer_label(stream: &UnixStream) -> Option<String> {
    let mut buffer = [0_u8; MAX_LABEL];
    let mut length = libc::socklen_t::try_from(MAX_LABEL).ok()?;
    // SAFETY: `stream` keeps its descriptor open for the whole call. The
    // pointer and `length` describe `buffer`, which is writable for
    // `MAX_LABEL` bytes; the kernel writes at most `length` bytes and stores
    // the label length in `length`. No other memory is read or written.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERSEC,
            buffer.as_mut_ptr().cast(),
            &raw mut length,
        )
    };
    if result != 0 {
        return None;
    }
    let length = usize::try_from(length).ok().filter(|n| *n <= MAX_LABEL)?;
    label_text(&buffer[..length])
}

/// The label bytes the kernel returned, without one trailing NUL.
fn label_text(bytes: &[u8]) -> Option<String> {
    let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    if bytes.is_empty() || bytes.contains(&0) {
        return None;
    }
    String::from_utf8(bytes.to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_bytes_are_one_non_empty_utf8_string() {
        assert_eq!(
            label_text(b"system_u:system_r:rustiron_executor_t:s0\0").as_deref(),
            Some("system_u:system_r:rustiron_executor_t:s0")
        );
        assert_eq!(
            label_text(b"unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023").as_deref(),
            Some("unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023")
        );
        for bad in [&b""[..], b"\0", b"a\0b\0", b"\xff\xfe\0"] {
            assert_eq!(label_text(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_socket_pair_has_a_label_or_none_never_garbage() {
        // Without an LSM the kernel answers ENOPROTOOPT (None); with SELinux
        // the pair carries this process's context. Both are acceptable here;
        // the lab run proves the confined case (W331 evidence).
        let (first, _second) = UnixStream::pair().unwrap();
        if let Some(label) = peer_label(&first) {
            assert!(label.split(':').count() >= 4, "{label}");
        }
    }
}
