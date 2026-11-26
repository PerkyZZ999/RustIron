//! Admin-helper wire seeds: every step and reply shape, and each refusal class.

pub(super) fn generate(seed: &mut impl FnMut(&str, &str, &[u8], bool)) {
    let steps = [
        "provision_step",
        "capture_run",
        "probe_run",
        "ols_preflight",
        "ols_config_test",
        "ols_reload",
        "ols_verify",
    ];
    for step in steps {
        seed(
            "admin_request",
            step,
            format!("v1 op_w272 {step}\n").as_bytes(),
            true,
        );
    }
    let longest_id = "a".repeat(64);
    seed(
        "admin_request",
        "longest-id",
        format!("v1 {longest_id} ols_config_test\n").as_bytes(),
        true,
    );
    // One byte over the 128-byte ceiling, the campaign's input cap.
    let mut oversized = b"v1 op_w272 capture_run".to_vec();
    oversized.resize(128, b' ');
    oversized.push(b'\n');
    for (name, bytes) in [
        ("ols-status", b"v1 ols_status\n".to_vec()),
        ("site-root", b"v1 site_root blog1\n".to_vec()),
        ("no-newline", b"v1 op_w272 capture_run".to_vec()),
        ("crlf", b"v1 op_w272 capture_run\r\n".to_vec()),
        ("extra-field", b"v1 op_w272 capture_run x\n".to_vec()),
        ("double-space", b"v1  op_w272 capture_run\n".to_vec()),
        ("wrong-version", b"v2 op_w272 capture_run\n".to_vec()),
        ("unknown-step", b"v1 op_w272 run_anything\n".to_vec()),
        ("bad-id", b"v1 op/w272 capture_run\n".to_vec()),
        (
            "id-too-long",
            format!("v1 {longest_id}a capture_run\n").into_bytes(),
        ),
        ("invalid-utf8", b"v1 op_\xff capture_run\n".to_vec()),
        ("oversized", oversized),
    ] {
        seed("admin_request", name, &bytes, false);
    }

    for (name, bytes) in [
        ("ok", "ok\n"),
        ("ok-empty-payload", "ok \n"),
        ("ok-payload", "ok {\"a\":1}\n"),
        ("known-code", "REPLAY_DENIED\n"),
        ("unknown-code", "WHATEVER\n"),
        ("okay-is-a-code", "okay\n"),
    ] {
        seed("admin_reply", name, bytes.as_bytes(), true);
    }
    for (name, bytes) in [
        ("empty", b"".as_slice()),
        ("no-newline", b"ok"),
        ("two-lines", b"ok\nok\n"),
        ("payload-newline", b"ok a\nREPLAY_DENIED\n"),
        ("invalid-utf8", b"ok \xff\n"),
    ] {
        seed("admin_reply", name, bytes, false);
    }
}
