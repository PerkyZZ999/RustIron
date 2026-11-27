//! D-020 (W331): `unsafe` appears only in the one recorded exception,
//! `crates/executor/src/peer_label.rs`. The workspace lint is `deny`, so an
//! `allow(unsafe_code)` anywhere else would otherwise pass review unnoticed.
use std::{fs, path::Path};

const EXCEPTION: &str = "crates/executor/src/peer_label.rs";

fn rust_files(directory: &Path, found: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            rust_files(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
}

/// The keyword, split so this file does not match its own scan.
const KEYWORD: &str = concat!("un", "safe");

/// Code forms of the keyword and the lint exception. W672: the lint name
/// alone, so `allow`/`expect` with a `reason`, or split over lines, still match.
fn patterns() -> [String; 5] {
    [
        format!("{KEYWORD} {{"),
        format!("{KEYWORD} fn"),
        format!("{KEYWORD} impl"),
        format!("{KEYWORD} extern"),
        format!("{KEYWORD}_code"),
    ]
}

/// Non-comment lines that use the keyword as Rust code.
fn unsafe_lines(text: &str) -> Vec<String> {
    let patterns = patterns();
    text.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("//"))
        .filter(|line| {
            patterns
                .iter()
                .any(|pattern| line.contains(pattern.as_str()))
        })
        .map(str::to_owned)
        .collect()
}

#[test]
fn unsafe_is_confined_to_the_peer_label_module() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    for directory in ["crates", "fuzz/src", "fuzz/fuzz_targets", "fuzz/examples"] {
        rust_files(&root.join(directory), &mut files);
    }
    assert!(files.len() > 50, "the scan found too few files");
    let mut seen_exception = false;
    for file in files {
        let relative = file
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let lines = unsafe_lines(&fs::read_to_string(&file).unwrap());
        if relative == EXCEPTION {
            seen_exception = !lines.is_empty();
            continue;
        }
        assert!(lines.is_empty(), "{relative} uses unsafe: {lines:?}");
    }
    assert!(seen_exception, "the recorded exception moved or vanished");
}

#[test]
fn the_scan_sees_a_planted_block_and_skips_comments() {
    assert_eq!(
        unsafe_lines(&format!("let x = {KEYWORD} {{ f() }};")).len(),
        1
    );
    assert_eq!(unsafe_lines(&format!("#![allow({KEYWORD}_code)]")).len(), 1);
    assert_eq!(
        unsafe_lines(&format!("#![expect({KEYWORD}_code, reason = \"x\")]")).len(),
        1
    );
    assert_eq!(unsafe_lines(&format!("    {KEYWORD}_code,")).len(), 1);
    assert!(unsafe_lines(&format!("// {KEYWORD} {{ not code }}")).is_empty());
}
