//! W203 manifest worker, format and store, on synthetic tar streams.
use super::{
    format::{self, Kind},
    tar::{Archive, Error},
    worker::{self, Limits},
};

const ROOT: &str = "/srv/sites/rs_blog9";
const DUMP: &str = "/srv/sites/rs_blog9/tmp/rustiron-capture.sql";

/// One ustar header block (with checksum) for `name`.
fn header(name: &[u8], flag: u8, size: u64, mode: u32) -> Vec<u8> {
    let mut block = vec![0_u8; 512];
    block[..name.len().min(100)].copy_from_slice(&name[..name.len().min(100)]);
    block[100..108].copy_from_slice(format!("{mode:07o}\0").as_bytes());
    block[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    block[156] = flag;
    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");
    block[148..156].copy_from_slice(b"        ");
    let sum: u32 = block.iter().map(|&b| u32::from(b)).sum();
    block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    block
}

fn pad(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    out.resize(data.len().div_ceil(512) * 512, 0);
    out
}

fn member(name: &[u8], flag: u8, content: &[u8], mode: u32) -> Vec<u8> {
    let mut out = header(name, flag, content.len() as u64, mode);
    out.extend(pad(content));
    out
}

fn pax_path(path: &[u8]) -> Vec<u8> {
    let mut record = b" path=".to_vec();
    record.extend_from_slice(path);
    record.push(b'\n');
    let mut length = record.len();
    while format!("{length}").len() + record.len() != length {
        length = format!("{length}").len() + record.len();
    }
    let mut data = format!("{length}").into_bytes();
    data.extend(record);
    member(b"PaxHeaders/x", b'x', &data, 0o644)
}

fn archive(members: &[Vec<u8>]) -> Vec<u8> {
    let mut out: Vec<u8> = members.concat();
    out.extend([0_u8; 1024]);
    out
}

fn site(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut members = vec![
        member(b"/", b'5', b"", 0o755),
        member(b"/srv", b'5', b"", 0o755),
        member(b"/srv/sites", b'5', b"", 0o755),
        member(b"/srv/sites/rs_blog9", b'5', b"", 0o750),
        member(b"/srv/sites/rs_blog9/html", b'5', b"", 0o750),
    ];
    for (name, content) in files {
        members.push(member(
            format!("/srv/sites/rs_blog9/html/{name}").as_bytes(),
            b'0',
            content,
            0o640,
        ));
    }
    archive(&members)
}

fn run(stream: &[u8], limits: Limits) -> Vec<u8> {
    let mut out = Vec::new();
    let end = worker::walk(stream, &mut out, limits).unwrap();
    out.extend(format::end_line(end).as_bytes());
    out.push(b'\n');
    out
}

fn manifest(stream: &[u8]) -> Option<format::Built> {
    super::from_worker(&run(stream, Limits::default()), ROOT, DUMP)
}

#[test]
fn restic_runs_one_fixed_read_only_dump_of_the_snapshot() {
    let id = "a".repeat(64);
    assert_eq!(
        worker::restic_arguments(&id).unwrap(),
        [
            "dump",
            "--no-lock",
            "--no-cache",
            "--archive",
            "tar",
            id.as_str(),
            "/"
        ]
    );
    for bad in [
        "A".repeat(64),
        "a".repeat(63),
        format!("{}/", "a".repeat(63)),
        "--repo=x".to_owned(),
    ] {
        assert!(worker::restic_arguments(&bad).is_none());
    }
}

#[test]
fn the_canonical_manifest_is_sorted_escaped_and_hashes_content() {
    let built = manifest(&site(&[("b.php", b"<?php b"), ("a.php", b"<?php a")])).unwrap();
    let text = String::from_utf8(built.bytes.clone()).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 6);
    assert_eq!(
        lines[0],
        r#"{"path":"srv","kind":"dir","size":0,"sha256":null,"mode":493}"#
    );
    assert!(lines[4].starts_with(
        r#"{"path":"srv/sites/rs_blog9/html/a.php","kind":"file","size":7,"sha256":""#
    ));
    assert!(lines[4].contains(&format::digest_hex(b"<?php a")));
    assert_eq!(built.entries, 6);
    assert_eq!(built.regular_bytes, 14);
    assert!(!built.truncated);
    assert_eq!(built.sha256, format::digest_hex(&built.bytes));
    assert!(text.ends_with('\n'));
}

#[test]
fn the_same_tree_in_any_order_has_the_same_digest_and_one_byte_changes_it() {
    let one = manifest(&site(&[("a.php", b"x"), ("b.php", b"y")])).unwrap();
    let two = manifest(&site(&[("b.php", b"y"), ("a.php", b"x")])).unwrap();
    assert_eq!(one, two);
    let changed = manifest(&site(&[("a.php", b"x"), ("b.php", b"z")])).unwrap();
    assert_ne!(one.sha256, changed.sha256);
    let renamed = manifest(&site(&[("a.php", b"x"), ("c.php", b"y")])).unwrap();
    assert_ne!(one.sha256, renamed.sha256);
}

#[test]
fn non_utf8_control_and_hex_prefixed_paths_get_one_hex_spelling() {
    assert_eq!(format::encode_path(b"plain/a b.php"), "plain/a b.php");
    assert_eq!(
        format::encode_path(b"a\xffb"),
        "hex:61ffb6".replace("b6", "62")
    );
    assert_eq!(format::encode_path(b"a\nb"), "hex:610a62");
    assert_eq!(format::encode_path(b"hex:41"), "hex:6865783a3431");
    for raw in [
        &b"a\xffb"[..],
        b"a\nb",
        b"hex:41",
        "\u{e9}t\u{e9}".as_bytes(),
    ] {
        assert_eq!(format::decode_path(&format::encode_path(raw)).unwrap(), raw);
    }
    // Alternate spellings of the same raw path are refused.
    assert!(format::decode_path("hex:61").is_none());
    assert!(format::decode_path("hex:6A").is_none());
    let built = manifest(&site(&[("caf\u{e9}\u{301}.php", b"x")])).unwrap();
    assert!(
        String::from_utf8(built.bytes)
            .unwrap()
            .contains("caf\u{e9}\u{301}.php")
    );
    let raw = archive(&[member(
        b"/srv/sites/rs_blog9/html/\xff.php",
        b'0',
        b"x",
        0o644,
    )]);
    let text = String::from_utf8(manifest(&raw).unwrap().bytes).unwrap();
    assert!(text.contains(&format!("\"path\":\"hex:{}", "7372762f")));
}

#[test]
fn pax_and_gnu_long_names_are_read() {
    let long = format!("/srv/sites/rs_blog9/html/{}.php", "d".repeat(150));
    let mut gnu = member(
        b"././@LongLink",
        b'L',
        format!("{long}\0").as_bytes(),
        0o644,
    );
    gnu.extend(member(b"truncated-name", b'0', b"g", 0o644));
    let mut pax = pax_path(format!("{long}x").as_bytes());
    pax.extend(member(b"short", b'0', b"p", 0o644));
    let built = manifest(&archive(&[gnu, pax])).unwrap();
    let text = String::from_utf8(built.bytes).unwrap();
    assert!(text.contains(&format!("\"path\":\"{}\"", &long[1..])));
    assert!(text.contains(&format!("\"path\":\"{}x\"", &long[1..])));
    assert_eq!(built.entries, 2);
}

#[test]
fn malformed_archives_are_errors_not_short_lists() {
    let mut bad_sum = site(&[("a.php", b"x")]);
    bad_sum[600] ^= 1;
    let mut short = site(&[("a.php", b"x")]);
    short.truncate(512 * 6 + 100);
    let mut out = Vec::new();
    assert_eq!(
        worker::walk(&bad_sum[..], &mut out, Limits::default()).err(),
        Some(Error::Malformed)
    );
    assert_eq!(
        worker::walk(&short[..], &mut out, Limits::default()).err(),
        Some(Error::Io)
    );
    let unknown = archive(&[member(b"x", b'Z', b"", 0o644)]);
    assert_eq!(
        worker::walk(&unknown[..], &mut out, Limits::default()).err(),
        Some(Error::Malformed)
    );
    let mut archive_reader = Archive::new(&unknown[..]);
    assert!(archive_reader.next().is_err());
}

#[test]
fn each_bound_truncates_and_is_recorded() {
    let stream = site(&[("a.php", b"xx"), ("b.php", b"yy"), ("c.php", b"zz")]);
    let limits = Limits::default();
    let cases = [
        Limits {
            entries: 6,
            ..limits
        },
        Limits {
            regular_bytes: 3,
            ..limits
        },
        Limits {
            stream_bytes: 900,
            ..limits
        },
    ];
    for bounded in cases {
        let built = super::from_worker(&run(&stream, bounded), ROOT, DUMP).unwrap();
        assert!(built.truncated, "{bounded:?}");
        assert!(built.entries < 7, "{bounded:?}");
    }
    let long = format!("/srv/sites/rs_blog9/html/{}", "p".repeat(1100));
    let mut gnu = member(b"././@LongLink", b'L', long.as_bytes(), 0o644);
    gnu.extend(member(b"n", b'0', b"x", 0o644));
    let built = manifest(&archive(&[gnu])).unwrap();
    assert!(built.truncated);
    assert_eq!(built.entries, 0);
    let full = manifest(&stream).unwrap();
    assert!(!full.truncated);
    assert_eq!(full.entries, 7);
}

#[test]
fn malformed_or_oversized_worker_output_builds_nothing() {
    let good = run(&site(&[("a.php", b"x")]), Limits::default());
    assert!(super::from_worker(&good, ROOT, DUMP).is_some());
    let text = String::from_utf8(good.clone()).unwrap();
    let no_end: String = text
        .lines()
        .filter(|l| !l.starts_with("{\"end\""))
        .map(|l| format!("{l}\n"))
        .collect();
    let miscounted = text.replace("\"entries\":5", "\"entries\":4");
    let respelled = text.replacen("\"size\":0", "\"size\": 0", 1);
    let extra_member = text.replacen("\"mode\":493}", "\"mode\":493,\"x\":1}", 1);
    let duplicated = {
        let first = text.lines().next().unwrap();
        text.replacen("\"entries\":5", "\"entries\":6", 1).replacen(
            first,
            &format!("{first}\n{first}"),
            1,
        )
    };
    for bad in [
        no_end,
        miscounted,
        respelled,
        extra_member,
        duplicated,
        text.trim_end().to_owned(),
    ] {
        assert!(
            super::from_worker(bad.as_bytes(), ROOT, DUMP).is_none(),
            "{bad}"
        );
    }
    let mut huge = vec![b' '; format::MAX_STREAM_BYTES + 8192];
    huge.extend(&good);
    assert!(super::from_worker(&huge, ROOT, DUMP).is_none());
}

#[test]
fn a_secret_shaped_path_drops_the_manifest() {
    for name in [
        "password=hunter.php",
        "x-----BEGIN.php",
        &format!("{}.php", "a".repeat(48)),
    ] {
        assert!(manifest(&site(&[(name, b"x")])).is_none(), "{name}");
    }
}

#[test]
fn paths_outside_the_snapshot_sources_drop_the_manifest() {
    for path in [
        "/etc/rustiron-s07-lab/sites/rs_blog9/repo.password",
        "/srv/sites/rs_other/html/index.php",
        "/srv/sites/rs_blog9/private/db.cnf",
        "/srv/sites/rs_blog9/htmlx/a.php",
    ] {
        let stream = archive(&[member(path.as_bytes(), b'0', b"x", 0o600)]);
        assert!(manifest(&stream).is_none(), "{path}");
    }
    let dump = archive(&[member(DUMP.as_bytes(), b'0', b"-- sql", 0o600)]);
    assert_eq!(manifest(&dump).unwrap().entries, 1);
}

#[test]
fn a_relayed_manifest_is_rechecked_against_its_digest() {
    let built = manifest(&site(&[("a.php", b"x")])).unwrap();
    let again = super::from_relay(built.bytes.clone(), &built.sha256, false, ROOT, DUMP).unwrap();
    assert_eq!(again, built);
    assert!(super::from_relay(built.bytes.clone(), &"0".repeat(64), false, ROOT, DUMP).is_none());
    let mut reordered: Vec<&str> = std::str::from_utf8(&built.bytes).unwrap().lines().collect();
    reordered.reverse();
    let bytes = format!("{}\n", reordered.join("\n")).into_bytes();
    let sha = format::digest_hex(&bytes);
    assert!(super::from_relay(bytes, &sha, false, ROOT, DUMP).is_none());
}

/// W288: in a setgid directory whose group is not the process group, the
/// stored file carries the directory's group. Uses a supplementary group of
/// the test user; with none there is nothing to distinguish, and it says so.
#[test]
fn the_store_takes_the_group_of_a_setgid_directory() {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let own = rustix::process::getegid();
    let Some(other) = rustix::process::getgroups()
        .unwrap()
        .into_iter()
        .find(|group| *group != own)
    else {
        eprintln!("skipped: the test user has no supplementary group");
        return;
    };
    let directory = std::env::temp_dir().join(format!("ri-manifests-g-{}", std::process::id()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    rustix::fs::chown(&directory, None, Some(other)).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o2700)).unwrap();
    let owner = rustix::process::getuid().as_raw();
    let built = manifest(&site(&[("a.php", b"x")])).unwrap();
    super::store(&directory, owner, &built).unwrap();
    let stored = std::fs::metadata(directory.join(format!("{}.jsonl", built.sha256))).unwrap();
    assert_eq!(stored.gid(), other.as_raw());
    assert_eq!(stored.mode() & 0o777, 0o600);
    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn the_store_writes_one_private_file_named_by_its_digest() {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let directory = std::env::temp_dir().join(format!("ri-manifests-{}", std::process::id()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let owner = rustix::process::getuid().as_raw();
    let built = manifest(&site(&[("a.php", b"x")])).unwrap();
    super::store(&directory, owner, &built).unwrap();
    super::store(&directory, owner, &built).unwrap();
    let path = directory.join(format!("{}.jsonl", built.sha256));
    assert_eq!(std::fs::read(&path).unwrap(), built.bytes);
    assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
    let mut other = built.clone();
    other.bytes.push(b'\n');
    assert_eq!(
        super::store(&directory, owner, &other).err(),
        Some(crate::ExecutorError::StepFailed)
    );
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
    std::fs::remove_dir_all(&directory).unwrap();
    assert!(super::store(&directory, owner, &built).is_err());
}

#[test]
fn kinds_other_than_files_carry_no_size_or_digest() {
    let stream = archive(&[
        member(b"/srv/sites/rs_blog9/html", b'5', b"", 0o750),
        member(b"/srv/sites/rs_blog9/html/l", b'2', b"", 0o777),
        member(b"/srv/sites/rs_blog9/html/f", b'6', b"", 0o644),
    ]);
    let text = String::from_utf8(manifest(&stream).unwrap().bytes).unwrap();
    assert!(text.contains("\"kind\":\"symlink\",\"size\":0,\"sha256\":null"));
    assert!(text.contains("\"kind\":\"other\""));
    assert!(!format::valid(&format::Entry {
        path: "a".into(),
        kind: Kind::Dir,
        size: 1,
        sha256: None,
        mode: 0,
    }));
}

#[test]
fn a_repeated_path_in_the_archive_drops_the_manifest() {
    // Found by the W203 fuzz campaign: the streaming walk lists both members
    // (it keeps no path set); the root-side builder must refuse the list.
    let twice = member(b"srv/sites/rs_blog9/html/a", b'0', b"x", 0o644);
    assert_eq!(manifest(&archive(&[twice.clone(), twice])), None);
}

#[test]
fn the_stored_file_takes_the_directory_group_not_the_process_group() {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let egid = rustix::process::getegid().as_raw();
    let Some(group) = rustix::process::getgroups()
        .unwrap()
        .into_iter()
        .map(rustix::process::Gid::as_raw)
        .find(|gid| *gid != egid)
    else {
        eprintln!("skipped: no supplementary group to tell the groups apart");
        return;
    };
    let directory = std::env::temp_dir().join(format!("ri-manifests-group-{}", std::process::id()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    std::os::unix::fs::chown(&directory, None, Some(group)).unwrap();
    let owner = rustix::process::getuid().as_raw();
    let built = manifest(&site(&[("a.php", b"x")])).unwrap();
    let stored = super::store(&directory, owner, &built);
    let path = directory.join(format!("{}.jsonl", built.sha256));
    let gid = std::fs::metadata(&path).map(|m| m.gid());
    std::fs::remove_dir_all(&directory).unwrap();
    stored.unwrap();
    assert_eq!(gid.unwrap(), group);
}
