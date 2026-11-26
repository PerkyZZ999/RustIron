//! The executor/admin-helper line wire (W272), included from the executor by
//! path so the fuzz graph gains only `rustiron-contracts` (for `Id`).

#[path = "../../crates/executor/src/admin_helper/wire.rs"]
mod wire;

use wire::{
    AdminRequest, AdminStep, MAX_ADMIN_REPLY_BYTES, MAX_ADMIN_REQUEST_BYTES, ReplyLine,
    decode_reply, decode_site_root, is_ols_status, site_root_request,
};

/// The largest request input the campaign feeds: one byte over the ceiling.
pub const ADMIN_REQUEST_MAX_INPUT: usize = MAX_ADMIN_REQUEST_BYTES + 1;

/// The largest reply input the campaign feeds. The 8 MiB reply ceiling itself
/// is unit-tested in the executor; the campaign explores line structure.
pub const ADMIN_REPLY_MAX_INPUT: usize = 64 * 1024;

/// Helper-side request decoding: size ceiling, exactly one canonical
/// encoding per request, the read-only status line is never a step, and
/// changed framing, version or field count is refused.
pub fn admin_request(input: &[u8]) -> bool {
    let decoded = AdminRequest::decode(input);
    assert!(
        !(is_ols_status(input) && decoded.is_some()),
        "the status request decoded as a step"
    );
    // W372: the site-root line is exact, never a step and never the status line.
    if let Some(site) = decode_site_root(input) {
        assert!(decoded.is_none(), "the site-root request decoded as a step");
        assert!(!is_ols_status(input));
        assert_eq!(
            site_root_request(&site),
            input,
            "accepted a non-canonical site-root line"
        );
        return false;
    }
    if input.len() > MAX_ADMIN_REQUEST_BYTES {
        assert!(decoded.is_none(), "oversized request accepted");
        return false;
    }
    let Some(request) = decoded else {
        return false;
    };
    assert_eq!(request.encode(), input, "accepted a non-canonical request");
    let line = &input[..input.len() - 1];
    for changed in [
        line.to_vec(),
        [line, b" \n"].concat(),
        [line, b"\r\n"].concat(),
        [b" ", input].concat(),
        [b"v2", &input[2..]].concat(),
        [input, input].concat(),
    ] {
        assert_eq!(AdminRequest::decode(&changed), None, "{changed:?}");
    }
    for step in AdminStep::ALL {
        let other = AdminRequest {
            operation_id: request.operation_id.clone(),
            step,
        };
        let bytes = other.encode();
        assert!(bytes.len() <= MAX_ADMIN_REQUEST_BYTES);
        assert_eq!(AdminRequest::decode(&bytes), Some(other));
    }
    true
}

/// Executor-side reply splitting: a decoded reply re-encodes to the exact
/// input, success and code lines never overlap, and no line carries a second
/// line. Non-UTF-8 is refused before splitting, as the client's string read is.
pub fn admin_reply(input: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(input) else {
        return false;
    };
    let Some(line) = decode_reply(text) else {
        let body = text.strip_suffix('\n');
        assert!(
            text.len() > MAX_ADMIN_REPLY_BYTES || body.is_none_or(|body| body.contains('\n')),
            "a single bounded line was refused"
        );
        return false;
    };
    assert_eq!(line.encode(), text, "reply decoding is not exact");
    match line {
        ReplyLine::Done(None) => assert_eq!(text, "ok\n"),
        ReplyLine::Done(Some(payload)) => assert!(!payload.contains('\n')),
        ReplyLine::Code(code) => {
            assert!(
                code != "ok" && !code.starts_with("ok "),
                "success read as a code"
            );
            assert!(!code.contains('\n'));
        }
    }
    true
}
