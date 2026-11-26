//! Capture-manifest seeds: small valid archives and each malformed class.

fn header(name: &str, kind: u8, size: usize, mode: u32) -> Vec<u8> {
    let mut block = vec![0u8; 512];
    block[..name.len()].copy_from_slice(name.as_bytes());
    let octal = |block: &mut [u8], at: usize, width: usize, value: u64| {
        let text = format!("{value:0w$o}\0", w = width - 1);
        block[at..at + width].copy_from_slice(text.as_bytes());
    };
    octal(&mut block, 100, 8, u64::from(mode));
    octal(&mut block, 108, 8, 0);
    octal(&mut block, 116, 8, 0);
    octal(&mut block, 124, 12, size as u64);
    octal(&mut block, 136, 12, 0);
    block[156] = kind;
    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");
    block[148..156].copy_from_slice(b"        ");
    let sum: u32 = block.iter().map(|&b| u32::from(b)).sum();
    block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    block
}

fn member(name: &str, kind: u8, data: &[u8], mode: u32) -> Vec<u8> {
    let mut out = header(name, kind, data.len(), mode);
    out.extend_from_slice(data);
    out.resize(out.len().div_ceil(512) * 512, 0);
    out
}

fn archive(members: &[Vec<u8>]) -> Vec<u8> {
    let mut out = members.concat();
    out.extend_from_slice(&[0u8; 1024]);
    out
}

pub(super) fn generate(seed: &mut impl FnMut(&str, &str, &[u8], bool)) {
    let mut add = |name: &str, bytes: &[u8], accepted: bool| {
        seed("capture_manifest", name, bytes, accepted);
    };
    let site = archive(&[
        member("srv/", b'5', b"", 0o755),
        member("srv/sites/", b'5', b"", 0o755),
        member("srv/sites/blog/html/index.php", b'0', b"<?php\n", 0o644),
        member("srv/sites/blog/html/link", b'2', b"", 0o777),
    ]);
    add("site-tree", &site, true);
    add("empty-archive", &archive(&[]), true);
    let mut long = member(
        "././@LongLink",
        b'L',
        format!("srv/{}", "a".repeat(200)).as_bytes(),
        0o644,
    );
    long.extend(member("short", b'0', b"x", 0o644));
    add("gnu-long-name", &archive(&[long]), true);
    let many: Vec<Vec<u8>> = (0..70)
        .map(|i| member(&format!("srv/f{i:03}"), b'0', b"", 0o644))
        .collect();
    add("entry-bound", &archive(&many), true);
    let twice = member("srv/same", b'0', b"x", 0o644);
    add("repeated-path", &archive(&[twice.clone(), twice]), false);
    add("not-a-tar", b"not a tar archive", false);
    let mut bad_sum = site.clone();
    bad_sum[148] = b'7';
    add("bad-checksum", &bad_sum, false);
    add("cut-content", &site[..512 * 3 + 3], false);
}
