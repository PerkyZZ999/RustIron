//! Bounded streaming reader for the tar archive `restic dump` writes (ustar
//! with PAX and GNU long-name records). It reads headers and hands content to
//! a sink; it never writes files, follows links or interprets content. Shared
//! with the fuzz workspace by path (no dependencies).
use std::io::Read;

use super::format::{Kind, MAX_PATH_BYTES};

const BLOCK: usize = 512;
/// Largest PAX or GNU long-name record read into memory.
pub(crate) const MAX_META_BYTES: u64 = 64 * 1024;

/// Why the archive could not be read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    /// The stream ended early or a read failed.
    Io,
    /// A header or record is not in a supported shape.
    Malformed,
}

/// One archive member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Header {
    /// Raw path bytes as archived (normalised: no leading `/` or `./`, no
    /// trailing `/`). Never empty.
    pub(crate) path: Vec<u8>,
    /// Member kind.
    pub(crate) kind: Kind,
    /// Content bytes that follow the header (0 for non-files).
    pub(crate) size: u64,
    /// Permission bits.
    pub(crate) mode: u32,
}

/// Streaming archive reader.
pub(crate) struct Archive<R> {
    inner: R,
    pending: Option<u64>,
}

fn field(block: &[u8]) -> &[u8] {
    let end = block.iter().position(|&b| b == 0).unwrap_or(block.len());
    &block[..end]
}

fn number(block: &[u8]) -> Option<u64> {
    if block.first().is_some_and(|b| b & 0x80 != 0) {
        // GNU base-256: only positive values that fit.
        if block[0] != 0x80 {
            return None;
        }
        let mut value: u64 = 0;
        for &b in &block[1..] {
            value = value.checked_mul(256)?.checked_add(u64::from(b))?;
        }
        return Some(value);
    }
    let text = field(block);
    let trimmed: Vec<u8> = text
        .iter()
        .copied()
        .skip_while(|b| *b == b' ')
        .take_while(|b| *b != b' ')
        .collect();
    if trimmed.is_empty() {
        return Some(0);
    }
    let mut value: u64 = 0;
    for b in trimmed {
        if !(b'0'..=b'7').contains(&b) {
            return None;
        }
        value = value.checked_mul(8)?.checked_add(u64::from(b - b'0'))?;
    }
    Some(value)
}

fn checksum_ok(block: &[u8; BLOCK]) -> bool {
    let Some(stored) = number(&block[148..156]) else {
        return false;
    };
    let sum: u64 = block
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            if (148..156).contains(&i) {
                32
            } else {
                u64::from(b)
            }
        })
        .sum();
    sum == stored
}

fn normalise(raw: &[u8]) -> Vec<u8> {
    let mut path = raw;
    loop {
        if let Some(rest) = path.strip_prefix(b"./") {
            path = rest;
        } else if let Some(rest) = path.strip_prefix(b"/") {
            path = rest;
        } else {
            break;
        }
    }
    while let Some(rest) = path.strip_suffix(b"/") {
        path = rest;
    }
    path.to_vec()
}

fn pax_records(data: &[u8]) -> Result<(Option<Vec<u8>>, Option<u64>), Error> {
    let (mut path, mut size) = (None, None);
    let mut rest = data;
    while !rest.is_empty() {
        let space = rest
            .iter()
            .position(|&b| b == b' ')
            .ok_or(Error::Malformed)?;
        let length: usize = std::str::from_utf8(&rest[..space])
            .ok()
            .and_then(|t| t.parse().ok())
            .ok_or(Error::Malformed)?;
        if length <= space + 1 || length > rest.len() || rest[length - 1] != b'\n' {
            return Err(Error::Malformed);
        }
        let record = &rest[space + 1..length - 1];
        let equals = record
            .iter()
            .position(|&b| b == b'=')
            .ok_or(Error::Malformed)?;
        let (key, value) = (&record[..equals], &record[equals + 1..]);
        match key {
            b"path" => path = Some(value.to_vec()),
            b"size" => {
                size = Some(
                    std::str::from_utf8(value)
                        .ok()
                        .and_then(|t| t.parse().ok())
                        .ok_or(Error::Malformed)?,
                );
            }
            _ => {}
        }
        rest = &rest[length..];
    }
    Ok((path, size))
}

impl<R: Read> Archive<R> {
    /// A reader over `inner`.
    pub(crate) fn new(inner: R) -> Self {
        Self {
            inner,
            pending: None,
        }
    }

    fn block(&mut self) -> Result<[u8; BLOCK], Error> {
        let mut block = [0_u8; BLOCK];
        self.inner.read_exact(&mut block).map_err(|_| Error::Io)?;
        Ok(block)
    }

    fn padding(size: u64) -> u64 {
        (BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64
    }

    fn discard(&mut self, mut count: u64) -> Result<(), Error> {
        let mut buffer = [0_u8; 8192];
        while count > 0 {
            let take = usize::try_from(count.min(buffer.len() as u64)).unwrap_or(buffer.len());
            self.inner
                .read_exact(&mut buffer[..take])
                .map_err(|_| Error::Io)?;
            count -= take as u64;
        }
        Ok(())
    }

    fn meta(&mut self, size: u64) -> Result<Vec<u8>, Error> {
        if size > MAX_META_BYTES {
            return Err(Error::Malformed);
        }
        let mut data = vec![0_u8; usize::try_from(size).map_err(|_| Error::Malformed)?];
        self.inner.read_exact(&mut data).map_err(|_| Error::Io)?;
        self.discard(Self::padding(size))?;
        Ok(data)
    }

    /// The next member, or `None` at the end-of-archive block. The previous
    /// member's content must have been consumed with `content`.
    pub(crate) fn next(&mut self) -> Result<Option<Header>, Error> {
        if self.pending.is_some() {
            return Err(Error::Malformed);
        }
        let (mut long_path, mut pax_path, mut pax_size) = (None, None, None);
        loop {
            let block = self.block()?;
            if block.iter().all(|&b| b == 0) {
                return if long_path.is_none() && pax_path.is_none() && pax_size.is_none() {
                    Ok(None)
                } else {
                    Err(Error::Malformed)
                };
            }
            if !checksum_ok(&block) {
                return Err(Error::Malformed);
            }
            let size = number(&block[124..136]).ok_or(Error::Malformed)?;
            let flag = block[156];
            match flag {
                b'x' => {
                    let (path, size) = pax_records(&self.meta(size)?)?;
                    pax_path = path.or(pax_path);
                    pax_size = size.or(pax_size);
                    continue;
                }
                b'g' => {
                    self.meta(size)?;
                    continue;
                }
                b'L' => {
                    let mut name = self.meta(size)?;
                    while name.last() == Some(&0) {
                        name.pop();
                    }
                    long_path = Some(name);
                    continue;
                }
                b'K' => {
                    self.meta(size)?;
                    continue;
                }
                _ => {}
            }
            let kind = match flag {
                b'0' | 0 | b'7' => Kind::File,
                b'5' => Kind::Dir,
                b'2' => Kind::Symlink,
                b'1' | b'3' | b'4' | b'6' => Kind::Other,
                _ => return Err(Error::Malformed),
            };
            let raw = match (pax_path, long_path) {
                (Some(path), _) | (None, Some(path)) => path,
                (None, None) => {
                    let name = field(&block[..100]);
                    if &block[257..263] == b"ustar\0" && block[345] != 0 {
                        let mut joined = field(&block[345..500]).to_vec();
                        joined.push(b'/');
                        joined.extend_from_slice(name);
                        joined
                    } else {
                        name.to_vec()
                    }
                }
            };
            let size = pax_size.unwrap_or(size);
            let mode = u32::try_from(number(&block[100..108]).ok_or(Error::Malformed)? & 0o7777)
                .map_err(|_| Error::Malformed)?;
            let path = normalise(&raw);
            if path.len() > MAX_PATH_BYTES * 4 {
                return Err(Error::Malformed);
            }
            self.pending = Some(size);
            return Ok(Some(Header {
                path,
                kind,
                size,
                mode,
            }));
        }
    }

    /// Consumes the current member's content, passing it to `sink` in order.
    pub(crate) fn content(&mut self, mut sink: impl FnMut(&[u8])) -> Result<(), Error> {
        let size = self.pending.take().ok_or(Error::Malformed)?;
        let mut left = size;
        let mut buffer = vec![0_u8; 64 * 1024];
        while left > 0 {
            let take = usize::try_from(left.min(buffer.len() as u64)).unwrap_or(buffer.len());
            self.inner
                .read_exact(&mut buffer[..take])
                .map_err(|_| Error::Io)?;
            sink(&buffer[..take]);
            left -= take as u64;
        }
        self.discard(Self::padding(size))
    }
}
