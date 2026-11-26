//! The capture-manifest tar reader, worker walk and canonical builder,
//! included from the executor by path so the fuzz graph gains serde and sha2
//! only, not the executor's system dependencies.

#[path = "../../crates/executor/src/manifest/format.rs"]
#[expect(dead_code, reason = "the fuzz oracle uses only the parsing subset")]
mod format;
#[path = "../../crates/executor/src/manifest/tar.rs"]
mod tar;
#[path = "../../crates/executor/src/manifest/worker.rs"]
#[expect(
    dead_code,
    reason = "the restic argv is not part of the parser surface"
)]
mod worker;

/// The largest archive input the campaign feeds.
pub const MANIFEST_MAX_INPUT: usize = 64 * 1024;

/// Walk arbitrary archive bytes under small bounds; whatever the walk writes
/// must stay under its stream bound, and a stream that builds must verify to
/// the same digest and counts, be sorted, and rebuild byte-identically. The
/// same input read as worker output must never panic either. A walk that
/// repeats a path must not build.
pub fn capture_manifest(input: &[u8]) -> bool {
    let _ = format::build(input);
    let _ = format::verify(input);
    let limits = worker::Limits {
        entries: 64,
        path_bytes: format::MAX_PATH_BYTES,
        regular_bytes: 1 << 20,
        stream_bytes: 32 * 1024,
    };
    let mut out = Vec::new();
    let walked = worker::walk(input, &mut out, limits);
    assert!(
        out.len() <= limits.stream_bytes,
        "walk exceeded its stream bound"
    );
    let Ok(end) = walked else {
        return false;
    };
    // The worker binary appends the end line, inside the reserved room.
    out.extend_from_slice(format::end_line(end).as_bytes());
    out.push(b'\n');
    assert!(out.len() <= format::MAX_STREAM_BYTES);
    // The streaming walk does not remember paths (200 000 paths of 1 KiB
    // would not fit its memory); the root-side builder refuses a repeated
    // path instead, and the capture is then recorded without a manifest.
    let Some(built) = format::build(&out) else {
        assert!(
            repeats_a_path(&out),
            "a finished walk without repeats must build"
        );
        return false;
    };
    assert_eq!(
        format::verify(&built.bytes),
        Some((built.entries, built.regular_bytes))
    );
    let mut tampered = built.bytes.clone();
    if let Some(first) = tampered.first_mut() {
        *first ^= 0x01;
        assert_ne!(format::digest_hex(&tampered), built.sha256);
    }
    true
}

fn repeats_a_path(stream: &[u8]) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    stream
        .split(|&b| b == b'\n')
        .filter_map(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
        .filter_map(|value| value["path"].as_str().map(str::to_owned))
        .any(|path| !seen.insert(path))
}
