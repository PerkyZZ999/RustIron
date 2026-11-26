//! Closed capture-manifest line format (W203), shared by the in-job worker,
//! the root-side builder and the fuzz workspace (included by path; serde and
//! sha2 only). Each entry line is one JSON object with members in a fixed
//! order; the worker ends a complete or bounded stream with one `end` line.
//! The canonical manifest is the entry lines sorted by path bytes, each
//! followed by `\n`; its SHA-256 is the recorded digest.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Most entries listed; one more marks the list truncated.
pub(crate) const MAX_ENTRIES: u64 = 200_000;
/// Longest raw path (bytes); a longer one stops the listing as truncated.
pub(crate) const MAX_PATH_BYTES: usize = 1024;
/// Regular bytes hashed at most: the W180 restore-size ceiling (2 GiB).
pub(crate) const MAX_REGULAR_BYTES: u64 = 2 << 30;
/// Worker output budget. The unit stdout read is capped at 4 MiB; the
/// worker stops (truncated) before this so its `end` line always fits.
pub(crate) const MAX_STREAM_BYTES: usize = 3 * 1024 * 1024 + 512 * 1024;
/// Largest canonical manifest accepted anywhere (entries only).
pub(crate) const MAX_MANIFEST_BYTES: usize = MAX_STREAM_BYTES;

/// Entry kind as listed by the archive.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Kind {
    /// Regular file; content hashed.
    File,
    /// Directory.
    Dir,
    /// Symbolic link; target not followed or hashed.
    Symlink,
    /// Anything else (device, fifo, hard link record); content not hashed.
    Other,
}

/// One listed archive entry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Entry {
    /// Escaped path (see `encode_path`).
    pub(crate) path: String,
    /// Kind.
    pub(crate) kind: Kind,
    /// Content size; 0 unless a regular file.
    pub(crate) size: u64,
    /// SHA-256 of the content (64 lowercase hex) for a regular file only.
    #[serde(deserialize_with = "nullable")]
    pub(crate) sha256: Option<String>,
    /// Permission bits (at most 0o7777).
    pub(crate) mode: u32,
}

/// Closing summary the worker writes last.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct End {
    /// Entry lines written.
    pub(crate) entries: u64,
    /// Sum of listed regular file sizes.
    pub(crate) regular_bytes: u64,
    /// A bound stopped the listing.
    pub(crate) truncated: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EndLine {
    pub(crate) end: End,
}

fn nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::deserialize(d)
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn is_lower_hex(text: &str) -> bool {
    text.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// SHA-256 as 64 lowercase hex.
pub(crate) fn digest_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    lower_hex(&digest)
}

/// A path as listed: UTF-8 text as is, unless it is not UTF-8, contains a
/// control character, or already starts with `hex:`; those become `hex:`
/// and the lowercase hex of the raw bytes. One spelling per raw path.
pub(crate) fn encode_path(raw: &[u8]) -> String {
    match std::str::from_utf8(raw) {
        Ok(text) if !text.starts_with("hex:") && !text.chars().any(char::is_control) => {
            text.to_owned()
        }
        _ => format!("hex:{}", lower_hex(raw)),
    }
}

/// The raw bytes of an encoded path, when it is the one spelling.
pub(crate) fn decode_path(path: &str) -> Option<Vec<u8>> {
    let raw = match path.strip_prefix("hex:") {
        Some(hex) => {
            if hex.len() % 2 != 0 || !is_lower_hex(hex) {
                return None;
            }
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
                .collect::<Option<Vec<u8>>>()?
        }
        None => path.as_bytes().to_vec(),
    };
    (!raw.is_empty() && raw.len() <= MAX_PATH_BYTES && encode_path(&raw) == path).then_some(raw)
}

/// Whether an entry is in its one valid shape.
pub(crate) fn valid(entry: &Entry) -> bool {
    decode_path(&entry.path).is_some()
        && entry.mode <= 0o7777
        && match entry.kind {
            Kind::File => entry
                .sha256
                .as_deref()
                .is_some_and(|d| d.len() == 64 && is_lower_hex(d)),
            _ => entry.size == 0 && entry.sha256.is_none(),
        }
}

/// The one line spelling of an entry (no trailing newline).
pub(crate) fn line(entry: &Entry) -> String {
    serde_json::to_string(entry).unwrap_or_default()
}

/// The one line spelling of the closing summary.
pub(crate) fn end_line(end: End) -> String {
    serde_json::to_string(&EndLine { end }).unwrap_or_default()
}

/// A canonical manifest with its digest and counts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Built {
    /// SHA-256 of `bytes`.
    pub(crate) sha256: String,
    /// Entries listed.
    pub(crate) entries: u64,
    /// Sum of regular file sizes.
    pub(crate) regular_bytes: u64,
    /// The worker stopped at a bound.
    pub(crate) truncated: bool,
    /// Canonical bytes.
    pub(crate) bytes: Vec<u8>,
}

fn parse_entry(text: &str) -> Option<Entry> {
    let entry: Entry = serde_json::from_str(text).ok()?;
    (valid(&entry) && line(&entry) == text).then_some(entry)
}

/// Builds the canonical manifest from worker output. Refuses anything not in
/// the closed shape: a missing or non-final `end` line, counts that differ,
/// a bound exceeded, duplicate paths, or alternate spellings.
pub(crate) fn build(stream: &[u8]) -> Option<Built> {
    if stream.len() > MAX_STREAM_BYTES + 4096 {
        return None;
    }
    let text = std::str::from_utf8(stream).ok()?;
    let body = text.strip_suffix('\n')?;
    let (entries_text, end_text) = match body.rsplit_once('\n') {
        Some((entries, end)) => (Some(entries), end),
        None => (None, body),
    };
    let end: EndLine = serde_json::from_str(end_text).ok()?;
    if end_line(end.end) != end_text {
        return None;
    }
    let mut entries = Vec::new();
    for item in entries_text.into_iter().flat_map(|t| t.split('\n')) {
        entries.push(parse_entry(item)?);
    }
    finish(entries, end.end)
}

fn finish(mut entries: Vec<Entry>, end: End) -> Option<Built> {
    let count = u64::try_from(entries.len()).ok()?;
    if count != end.entries || count > MAX_ENTRIES {
        return None;
    }
    let mut regular: u64 = 0;
    for entry in &entries {
        if entry.kind == Kind::File {
            regular = regular.checked_add(entry.size)?;
        }
    }
    if regular != end.regular_bytes || regular > MAX_REGULAR_BYTES {
        return None;
    }
    let mut keyed: Vec<(Vec<u8>, Entry)> = entries
        .drain(..)
        .map(|e| decode_path(&e.path).map(|raw| (raw, e)))
        .collect::<Option<_>>()?;
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    if keyed.windows(2).any(|w| w[0].0 == w[1].0) {
        return None;
    }
    let mut bytes = Vec::new();
    for (_, entry) in &keyed {
        bytes.extend_from_slice(line(entry).as_bytes());
        bytes.push(b'\n');
    }
    if bytes.len() > MAX_MANIFEST_BYTES {
        return None;
    }
    Some(Built {
        sha256: digest_hex(&bytes),
        entries: count,
        regular_bytes: regular,
        truncated: end.truncated,
        bytes,
    })
}

/// Re-checks canonical manifest bytes received from elsewhere: every line in
/// its one spelling, strictly sorted, within bounds. Returns entries and
/// regular bytes.
pub(crate) fn verify(bytes: &[u8]) -> Option<(u64, u64)> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return None;
    }
    if bytes.is_empty() {
        return Some((0, 0));
    }
    let text = std::str::from_utf8(bytes).ok()?.strip_suffix('\n')?;
    let mut previous: Option<Vec<u8>> = None;
    let (mut count, mut regular) = (0_u64, 0_u64);
    for item in text.split('\n') {
        let entry = parse_entry(item)?;
        let raw = decode_path(&entry.path)?;
        if previous.as_ref().is_some_and(|p| p >= &raw) {
            return None;
        }
        previous = Some(raw);
        count += 1;
        if entry.kind == Kind::File {
            regular = regular.checked_add(entry.size)?;
        }
    }
    (count <= MAX_ENTRIES && regular <= MAX_REGULAR_BYTES).then_some((count, regular))
}
