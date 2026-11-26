//! Bounded scan of a `mysqldump` file: size, the first table's default
//! character set and collation, and the WordPress site and home URLs.
use rustiron_contracts::{
    Text,
    migration::{DumpSummary, ExportReason},
};
use rustix::{fd::OwnedFd, io::Errno};

use crate::walk::Clock;

/// The header part that must hold the first `CREATE TABLE`.
const HEADER_BYTES: usize = 64 * 1024;
const MAX_URL_BYTES: usize = 2048;
const SITE_URL: &[u8] = b"'siteurl','";
const HOME_URL: &[u8] = b"'home','";

/// One option value seen in the dump: unseen, one value, or more than one.
#[derive(Debug, Default, PartialEq)]
pub(crate) enum Seen {
    #[default]
    None,
    One(Vec<u8>),
    Ambiguous,
}

impl Seen {
    fn add(&mut self, value: Option<&[u8]>) {
        *self = match (std::mem::take(self), value) {
            (Self::Ambiguous, _) | (_, None) => Self::Ambiguous,
            (Self::None, Some(value)) => Self::One(value.to_vec()),
            (Self::One(seen), Some(value)) if seen == value => Self::One(seen),
            (Self::One(_), Some(_)) => Self::Ambiguous,
        };
    }

    /// The value, when exactly one was seen and it is plain text.
    pub(crate) fn text(&self) -> Option<Text> {
        match self {
            Self::One(value) => std::str::from_utf8(value)
                .ok()
                .and_then(|value| Text::try_from(value.to_owned()).ok()),
            _ => None,
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct Dump {
    pub(crate) summary: Option<DumpSummary>,
    pub(crate) site_url: Seen,
    pub(crate) home_url: Seen,
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// The `[a-z0-9_]` word after `key` in the first `CREATE TABLE` statement.
fn table_option(header: &[u8], key: &[u8]) -> Option<Text> {
    let table = find(header, b"CREATE TABLE")?;
    let end = table + find(&header[table..], b";")?;
    let statement = &header[table..end];
    let start = find(statement, key)? + key.len();
    let word: Vec<u8> = statement[start..]
        .iter()
        .copied()
        .take_while(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
        .take(64)
        .collect();
    let word = String::from_utf8(word)
        .ok()
        .filter(|word| !word.is_empty())?;
    Text::try_from(word).ok()
}

/// The quoted value at the start of `value`. A value with an escape, longer
/// than the bound, or cut off at the end of the dump counts as unreadable.
fn value_at(value: &[u8]) -> Option<&[u8]> {
    let end = value
        .iter()
        .take(MAX_URL_BYTES + 1)
        .position(|byte| *byte == b'\'' || *byte == b'\\')?;
    (value[end] == b'\'').then_some(&value[..end])
}

/// Scans the whole dump in chunks. A marker is read only once the bytes after
/// it can hold a whole value, so a marker across a chunk edge is not missed.
pub(crate) fn scan(fd: &OwnedFd, clock: &Clock<'_>) -> Result<Dump, ExportReason> {
    let overlap = SITE_URL.len().max(HOME_URL.len()) + MAX_URL_BYTES + 1;
    let mut dump = Dump::default();
    let mut header = Vec::with_capacity(HEADER_BYTES);
    let mut pending: Vec<u8> = Vec::new();
    let mut buffer = vec![0; 256 * 1024];
    let mut bytes: u64 = 0;
    loop {
        clock.check()?;
        let read = match rustix::io::read(fd, &mut buffer) {
            Ok(read) => read,
            Err(Errno::INTR) => continue,
            Err(_) => return Err(ExportReason::Io),
        };
        let done = read == 0;
        bytes += u64::try_from(read).map_err(|_| ExportReason::Io)?;
        if header.len() < HEADER_BYTES {
            let take = read.min(HEADER_BYTES - header.len());
            header.extend_from_slice(&buffer[..take]);
        }
        pending.extend_from_slice(&buffer[..read]);
        let limit = if done {
            pending.len()
        } else {
            pending.len().saturating_sub(overlap)
        };
        for (marker, seen) in [
            (SITE_URL, &mut dump.site_url),
            (HOME_URL, &mut dump.home_url),
        ] {
            let mut from = 0;
            while let Some(at) = find(&pending[from..], marker) {
                let start = from + at;
                if start >= limit {
                    break;
                }
                seen.add(value_at(&pending[start + marker.len()..]));
                from = start + 1;
            }
        }
        pending.drain(..limit);
        if done {
            break;
        }
    }
    dump.summary = match (
        table_option(&header, b"DEFAULT CHARSET="),
        table_option(&header, b"COLLATE="),
    ) {
        (Some(charset), Some(collation)) => Some(DumpSummary {
            bytes,
            charset,
            collation,
        }),
        _ => None,
    };
    Ok(dump)
}
