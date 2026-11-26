//! Reads the subject, issuer, and expiry of the exported leaf certificate.
//!
//! Only `<domain>.cert.pem`, or the first certificate of
//! `<domain>.fullchain.pem`, is opened. The private key file is never opened.
//! The DER reader checks every length against its enclosing element and reads
//! only the fields it reports; it verifies no signature and trusts no chain.
use rustiron_contracts::{
    Text, Timestamp,
    approval::Hostname,
    migration::{ExportReason, TlsObservation, TlsSummary},
};
use rustix::fs::{self, AtFlags};
use rustix::{fd::OwnedFd, io::Errno};

const MAX_PEM_BYTES: usize = 64 * 1024;
const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
const END: &[u8] = b"-----END CERTIFICATE-----";
const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
const ORGANIZATION: &[u8] = &[0x55, 0x04, 0x0a];

/// The certificate the export holds; `None` when it cannot be read.
pub(crate) fn observe(
    root: &OwnedFd,
    hostname: &Hostname,
) -> Result<Option<TlsObservation>, ExportReason> {
    let name = |part: &str| format!("{}.{part}", hostname.as_str());
    let present = |file: &str| match fs::statat(root, file, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(Errno::NOENT) => Ok(false),
        Err(_) => Err(ExportReason::Io),
    };
    let leaf = name("cert.pem");
    let chain = name("fullchain.pem");
    let file = if present(&leaf)? {
        leaf
    } else if present(&chain)? {
        chain
    } else if present(&name("privkey.pem"))? {
        // A key without a certificate: the certificate is unknown.
        return Ok(None);
    } else {
        return Ok(Some(TlsObservation::None));
    };
    let pem = match crate::read_small(root, &file, MAX_PEM_BYTES) {
        Ok(pem) => pem,
        Err(ExportReason::Metadata) => return Ok(None),
        Err(other) => return Err(other),
    };
    Ok(first_certificate(&pem)
        .and_then(|der| summary(&der))
        .map(TlsObservation::Certificate))
}

fn first_certificate(pem: &[u8]) -> Option<Vec<u8>> {
    let start = find(pem, BEGIN)? + BEGIN.len();
    let end = start + find(&pem[start..], END)?;
    base64(&pem[start..end])
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Standard base64 with padding; ASCII whitespace is skipped.
fn base64(text: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut buffer = 0u32;
    let mut bits = 0;
    let mut padding = 0;
    for &byte in text {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                padding += 1;
                continue;
            }
            byte if byte.is_ascii_whitespace() => continue,
            _ => return None,
        };
        if padding > 0 {
            return None;
        }
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).ok()?);
        }
    }
    (padding <= 2).then_some(out)
}

/// One DER element: its tag and its content.
fn element(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 2 || rest.len() < count {
            return None;
        }
        let length = rest[..count]
            .iter()
            .fold(0usize, |acc, byte| (acc << 8) | usize::from(*byte));
        (length, &rest[count..])
    };
    (rest.len() >= length).then(|| (tag, &rest[..length], &rest[length..]))
}

fn expect(input: &[u8], wanted: u8) -> Option<(&[u8], &[u8])> {
    let (tag, content, rest) = element(input)?;
    (tag == wanted).then_some((content, rest))
}

const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;

fn summary(der: &[u8]) -> Option<TlsSummary> {
    let (certificate, _) = expect(der, SEQUENCE)?;
    let (tbs, _) = expect(certificate, SEQUENCE)?;
    let mut rest = tbs;
    // [0] EXPLICIT version, when present.
    if rest.first() == Some(&0xa0) {
        rest = element(rest)?.2;
    }
    let (_serial, rest) = expect(rest, 0x02)?;
    let (_algorithm, rest) = expect(rest, SEQUENCE)?;
    let (issuer, rest) = expect(rest, SEQUENCE)?;
    let (validity, rest) = expect(rest, SEQUENCE)?;
    let (subject, _) = expect(rest, SEQUENCE)?;
    let (_, _, after) = element(validity)?;
    let (tag, not_after, _) = element(after)?;
    Some(TlsSummary {
        subject: attribute(subject, COMMON_NAME)?,
        issuer: attribute(issuer, COMMON_NAME).or_else(|| attribute(issuer, ORGANIZATION))?,
        not_after: time(tag, not_after)?,
    })
}

/// The first value of the attribute `oid` in a Name, as text.
fn attribute(mut name: &[u8], oid: &[u8]) -> Option<Text> {
    while !name.is_empty() {
        let (set, rest) = expect(name, SET)?;
        name = rest;
        let mut entries = set;
        while !entries.is_empty() {
            let (entry, more) = expect(entries, SEQUENCE)?;
            entries = more;
            let (found, value) = expect(entry, 0x06)?;
            if found == oid {
                let (tag, text, _) = element(value)?;
                // UTF8String, PrintableString, or IA5String only.
                if !matches!(tag, 0x0c | 0x13 | 0x16) {
                    return None;
                }
                let text = std::str::from_utf8(text).ok()?;
                return Text::try_from(text.to_owned()).ok();
            }
        }
    }
    None
}

/// UTCTime `YYMMDDHHMMSSZ` (years 1950 to 2049) or GeneralizedTime
/// `YYYYMMDDHHMMSSZ`, as seconds since the epoch.
fn time(tag: u8, text: &[u8]) -> Option<Timestamp> {
    let digits = |part: &[u8]| -> Option<i64> {
        part.iter().try_fold(0i64, |acc, byte| {
            byte.is_ascii_digit()
                .then(|| acc * 10 + i64::from(byte - b'0'))
        })
    };
    let (year, rest) = match (tag, text.len()) {
        (0x17, 13) => {
            let short = digits(&text[..2])?;
            (
                if short < 50 {
                    2000 + short
                } else {
                    1900 + short
                },
                &text[2..],
            )
        }
        (0x18, 15) => (digits(&text[..4])?, &text[4..]),
        _ => return None,
    };
    if rest.last() != Some(&b'Z') {
        return None;
    }
    let field = |at: usize| digits(&rest[at..at + 2]);
    let (month, day, hour, minute, second) =
        (field(0)?, field(2)?, field(4)?, field(6)?, field(8)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
        || year < 1970
    {
        return None;
    }
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;
    Timestamp::try_from(u64::try_from(seconds).ok()?).ok()
}

/// Days since 1970-01-01 in the proleptic Gregorian calendar (Hinnant).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted = (month + 9) % 12;
    let day_of_year = (153 * shifted + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(tag: u8, text: &str) -> Option<u64> {
        time(tag, text.as_bytes()).map(Timestamp::get)
    }

    #[test]
    fn certificate_times_follow_the_der_rules() {
        assert_eq!(at(0x17, "700101000000Z"), Some(0));
        assert_eq!(
            at(0x17, "490101000000Z"),
            Some(2_493_072_000),
            "UTCTime 49 is 2049"
        );
        assert_eq!(
            at(0x17, "500101000000Z"),
            None,
            "UTCTime 50 is 1950, before the epoch"
        );
        assert_eq!(
            at(0x18, "20240229235959Z"),
            Some(1_709_251_199),
            "a leap day"
        );
        for (tag, text) in [
            (0x17, "271301000000Z"),
            (0x17, "270132000000Z"),
            (0x17, "270101240000Z"),
            (0x17, "2701010000000"),
            (0x17, "20270101000000Z"),
            (0x18, "270101000000Z"),
            (0x18, "2027010100000+Z"),
            (0x02, "270101000000Z"),
        ] {
            assert_eq!(at(tag, text), None, "{text}");
        }
    }

    #[test]
    fn der_lengths_never_pass_their_element() {
        assert_eq!(element(&[0x30, 0x05, 1, 2]), None);
        assert_eq!(element(&[0x30, 0x82, 0xff]), None);
        assert_eq!(
            element(&[0x30, 0x83, 0, 0, 1, 0]),
            None,
            "lengths over two bytes"
        );
        assert_eq!(element(&[0x30, 0x80]), None, "indefinite length");
        assert_eq!(
            element(&[0x30, 0x02, 1, 2, 9]),
            Some((0x30, &[1u8, 2][..], &[9u8][..]))
        );
        assert_eq!(summary(&[0x30, 0x03, 0x30, 0x01, 0x00]), None);
    }
}
