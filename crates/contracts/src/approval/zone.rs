//! D-091 (W551): the canonical zone file of a `dns_zone_import` and its
//! record sets ([DNS design](../../../docs/technical/DNS.md)).
//!
//! A canonical zone file holds one record per line, in this form:
//!
//! ```text
//! <owner.> <ttl> IN <TYPE> <rdata>
//! ```
//!
//! The lines are sorted bytewise and unique, so the file has one digest.
//! Names are absolute and lowercase. The types are the closed set of
//! D-091. The SOA and the NS set are at the apex only. A CNAME stands
//! alone at its owner. Every record of a set has the set's TTL. Parsing
//! grants nothing; the executor still checks the zone against the host.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{ApprovalError, Sha256Digest};

/// The largest canonical zone file.
pub const MAX_ZONE_BYTES: usize = 1024 * 1024;
/// The most lines in a canonical zone file.
pub const MAX_ZONE_LINES: usize = 20_000;
/// The longest line, without its newline.
pub const MAX_ZONE_LINE_BYTES: usize = 4096;
/// The TTL bounds of every record, in seconds.
pub const MIN_TTL: u32 = 60;
/// The TTL bounds of every record, in seconds.
pub const MAX_TTL: u32 = 604_800;

/// Why a zone file is refused; the line number is 1-based.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZoneError {
    /// The file is larger than the bound, not UTF-8, or does not end in a
    /// newline.
    Shape,
    /// This line does not follow the grammar.
    Line(usize),
    /// This line does not sort after the one before it, or repeats it.
    Order(usize),
    /// The SOA or the apex NS set is missing, repeated, or misplaced, or a
    /// CNAME shares its owner, or a set mixes TTLs.
    Structure,
}

/// A DNS zone name: lowercase labels of letters, digits, and inner
/// hyphens, at least two labels, without the final dot.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
#[serde(try_from = "String")]
pub struct ZoneName(String);

impl ZoneName {
    /// The validated name, without the final dot.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The absolute apex name, with the final dot.
    pub fn apex(&self) -> String {
        format!("{}.", self.0)
    }
}

impl TryFrom<String> for ZoneName {
    type Error = ApprovalError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let labels: Vec<_> = value.split('.').collect();
        let host_label = |label: &str| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        };
        if value.len() > 253 || labels.len() < 2 || !labels.iter().all(|l| host_label(l)) {
            return Err(ApprovalError::InvalidMessage);
        }
        Ok(Self(value))
    }
}

/// The record types a zone may hold (D-091).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
pub enum RecordType {
    /// Start of authority; the apex only.
    #[serde(rename = "SOA")]
    Soa,
    /// Name servers; the apex only.
    #[serde(rename = "NS")]
    Ns,
    /// IPv4 address.
    A,
    /// IPv6 address.
    #[serde(rename = "AAAA")]
    Aaaa,
    /// Alias; alone at its owner.
    #[serde(rename = "CNAME")]
    Cname,
    /// Mail exchanger.
    #[serde(rename = "MX")]
    Mx,
    /// Text.
    #[serde(rename = "TXT")]
    Txt,
    /// Service location.
    #[serde(rename = "SRV")]
    Srv,
    /// Certification authority authorization.
    #[serde(rename = "CAA")]
    Caa,
}

impl RecordType {
    /// The type's mnemonic.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Soa => "SOA",
            Self::Ns => "NS",
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Cname => "CNAME",
            Self::Mx => "MX",
            Self::Txt => "TXT",
            Self::Srv => "SRV",
            Self::Caa => "CAA",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        [
            Self::Soa,
            Self::Ns,
            Self::A,
            Self::Aaaa,
            Self::Cname,
            Self::Mx,
            Self::Txt,
            Self::Srv,
            Self::Caa,
        ]
        .into_iter()
        .find(|kind| kind.as_str() == name)
    }

    /// Whether a `dns_change` may name this type (no SOA or NS edit).
    pub fn changeable(self) -> bool {
        !matches!(self, Self::Soa | Self::Ns)
    }
}

/// One record set: every record of one owner and type, in canonical order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordSet {
    /// The absolute owner name.
    pub owner: String,
    /// The type.
    pub kind: RecordType,
    /// The set's TTL.
    pub ttl: u32,
    /// The canonical rdata of each record, sorted.
    pub records: Vec<String>,
}

impl RecordSet {
    /// The set's canonical lines, each ending in a newline.
    pub fn canonical(&self) -> String {
        self.records
            .iter()
            .map(|rdata| {
                format!(
                    "{} {} IN {} {rdata}\n",
                    self.owner,
                    self.ttl,
                    self.kind.as_str()
                )
            })
            .collect()
    }

    /// The SHA-256 of [`Self::canonical`], which a `dns_change` names as
    /// the set it expects.
    pub fn digest(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(Sha256::digest(self.canonical().as_bytes()).into())
    }

    /// Whether the set is a mail record set: MX, the apex TXT (SPF), a
    /// `_domainkey` name, or `_dmarc`.
    pub fn is_mail(&self, zone: &ZoneName) -> bool {
        self.kind == RecordType::Mx
            || (self.kind == RecordType::Txt && self.owner == zone.apex())
            || self.owner.contains("._domainkey.")
            || self.owner.starts_with("_dmarc.")
    }
}

/// A parsed canonical zone file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedZone {
    /// The zone.
    pub zone: ZoneName,
    /// The SHA-256 of the file's bytes.
    pub sha256: Sha256Digest,
    /// Its record sets, ordered by owner and type.
    pub record_sets: Vec<RecordSet>,
}

/// A DNS name label: letters, digits, `-`, and `_`, 1 to 63 bytes, without
/// a leading or trailing hyphen.
fn label(text: &str) -> bool {
    (1..=63).contains(&text.len())
        && !text.starts_with('-')
        && !text.ends_with('-')
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// An absolute lowercase name: labels and the final dot.
fn absolute(name: &str) -> bool {
    name.len() <= 254
        && name
            .strip_suffix('.')
            .is_some_and(|body| !body.is_empty() && body.split('.').all(label))
}

/// An owner name inside the zone; a `*` is allowed as the whole leftmost
/// label only.
pub(super) fn owner_in(owner: &str, zone: &ZoneName) -> bool {
    let apex = zone.apex();
    if owner == apex {
        return true;
    }
    let Some(prefix) = owner
        .strip_suffix(&apex)
        .and_then(|prefix| prefix.strip_suffix('.'))
    else {
        return false;
    };
    let mut labels = prefix.split('.');
    owner.len() <= 254
        && labels
            .next()
            .is_some_and(|first| first == "*" || label(first))
        && labels.all(label)
}

fn number<T: std::str::FromStr + ToString>(text: &str) -> Option<T> {
    let value = text.parse::<T>().ok()?;
    (value.to_string() == text).then_some(value)
}

/// One quoted TXT or CAA string of printable ASCII, with `\"` and `\\` as
/// the only escapes, at most 255 bytes inside the quotes. Returns the rest.
fn quoted(text: &str) -> Option<&str> {
    let body = text.strip_prefix('"')?;
    let bytes = body.as_bytes();
    let mut index = 0;
    let mut length = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                return (length <= 255).then_some(&body[index + 1..]);
            }
            b'\\' => {
                if !matches!(bytes.get(index + 1), Some(b'"' | b'\\')) {
                    return None;
                }
                index += 2;
            }
            0x20..=0x7e => index += 1,
            _ => return None,
        }
        length += 1;
    }
    None
}

/// The rdata grammar of each type, already in canonical form.
pub(super) fn rdata_ok(kind: RecordType, rdata: &str) -> bool {
    let fields: Vec<&str> = rdata.split(' ').collect();
    match kind {
        RecordType::A => rdata
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|address| address.to_string() == rdata),
        RecordType::Aaaa => rdata
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|address| address.to_string() == rdata),
        RecordType::Cname | RecordType::Ns => absolute(rdata),
        RecordType::Mx => {
            fields.len() == 2 && number::<u16>(fields[0]).is_some() && absolute(fields[1])
        }
        RecordType::Srv => {
            fields.len() == 4
                && fields[..3]
                    .iter()
                    .all(|field| number::<u16>(field).is_some())
                && absolute(fields[3])
        }
        RecordType::Soa => {
            fields.len() == 7
                && absolute(fields[0])
                && absolute(fields[1])
                && fields[2..]
                    .iter()
                    .all(|field| number::<u32>(field).is_some())
        }
        RecordType::Caa => {
            fields.len() >= 3
                && number::<u8>(fields[0]).is_some()
                && matches!(fields[1], "issue" | "issuewild" | "iodef")
                && {
                    let value = rdata.splitn(3, ' ').nth(2).unwrap_or_default();
                    quoted(value).is_some_and(str::is_empty)
                }
        }
        RecordType::Txt => {
            let mut rest = rdata;
            if rest.len() > 4096 {
                return false;
            }
            loop {
                match quoted(rest) {
                    Some("") => return true,
                    Some(after) => match after.strip_prefix(' ') {
                        Some(next) => rest = next,
                        None => return false,
                    },
                    None => return false,
                }
            }
        }
    }
}

/// Parses one canonical line into owner, TTL, type, and rdata.
fn line<'a>(text: &'a str, zone: &ZoneName) -> Option<(&'a str, u32, RecordType, &'a str)> {
    if text.len() > MAX_ZONE_LINE_BYTES {
        return None;
    }
    let mut parts = text.splitn(5, ' ');
    let owner = parts.next()?;
    let ttl = number::<u32>(parts.next()?)?;
    if parts.next()? != "IN" {
        return None;
    }
    let kind = RecordType::from_name(parts.next()?)?;
    let rdata = parts.next()?;
    let apex = owner == zone.apex();
    let placed = match kind {
        RecordType::Soa | RecordType::Ns => apex,
        RecordType::Cname => !apex,
        _ => true,
    };
    ((MIN_TTL..=MAX_TTL).contains(&ttl) && owner_in(owner, zone) && placed && rdata_ok(kind, rdata))
        .then_some((owner, ttl, kind, rdata))
}

/// Parses and checks a canonical zone file of `zone`.
pub fn parse_zone(zone: &ZoneName, bytes: &[u8]) -> Result<ParsedZone, ZoneError> {
    if bytes.len() > MAX_ZONE_BYTES || !bytes.ends_with(b"\n") {
        return Err(ZoneError::Shape);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ZoneError::Shape)?;
    let lines: Vec<&str> = text[..text.len() - 1].split('\n').collect();
    if lines.len() > MAX_ZONE_LINES {
        return Err(ZoneError::Shape);
    }
    let mut sets: BTreeMap<(String, RecordType), RecordSet> = BTreeMap::new();
    for (index, raw) in lines.iter().enumerate() {
        let (owner, ttl, kind, rdata) = line(raw, zone).ok_or(ZoneError::Line(index + 1))?;
        if index > 0 && lines[index - 1] >= *raw {
            return Err(ZoneError::Order(index + 1));
        }
        let set = sets
            .entry((owner.to_owned(), kind))
            .or_insert_with(|| RecordSet {
                owner: owner.to_owned(),
                kind,
                ttl,
                records: Vec::new(),
            });
        if set.ttl != ttl {
            return Err(ZoneError::Structure);
        }
        set.records.push(rdata.to_owned());
    }
    let apex = zone.apex();
    let count = |kind| {
        sets.get(&(apex.clone(), kind))
            .map_or(0, |set: &RecordSet| set.records.len())
    };
    let cname_alone = sets
        .values()
        .filter(|set| set.kind == RecordType::Cname)
        .all(|cname| {
            cname.records.len() == 1
                && sets
                    .keys()
                    .filter(|(owner, _)| *owner == cname.owner)
                    .count()
                    == 1
        });
    if count(RecordType::Soa) != 1 || count(RecordType::Ns) == 0 || !cname_alone {
        return Err(ZoneError::Structure);
    }
    Ok(ParsedZone {
        zone: zone.clone(),
        sha256: Sha256Digest::from_bytes(Sha256::digest(bytes).into()),
        record_sets: sets.into_values().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone() -> ZoneName {
        ZoneName::try_from("example.test".to_owned()).unwrap()
    }

    /// A small zone with every type, mail records, and a wildcard, sorted.
    pub(crate) const ZONE: &str = "\
*.example.test. 3600 IN A 203.0.113.20
_dmarc.example.test. 3600 IN TXT \"v=DMARC1; p=none\"
_sip._tcp.example.test. 3600 IN SRV 10 5 5060 sip.example.test.
example.test. 3600 IN A 203.0.113.10
example.test. 3600 IN AAAA 2001:db8::10
example.test. 3600 IN CAA 0 issue \"letsencrypt.org\"
example.test. 3600 IN MX 10 mail.example.test.
example.test. 3600 IN MX 20 backup-mx.example.net.
example.test. 3600 IN NS ns1.example.test.
example.test. 3600 IN NS ns2.example.test.
example.test. 3600 IN SOA ns1.example.test. hostmaster.example.test. 2026112101 10800 3600 604800 3600
example.test. 3600 IN TXT \"v=spf1 mx ~all\"
selector1._domainkey.example.test. 3600 IN CNAME selector1-example-test._domainkey.example.onmicrosoft.com.
www.example.test. 300 IN CNAME example.test.
";

    #[test]
    fn a_canonical_zone_parses_into_ordered_record_sets() {
        let parsed = parse_zone(&zone(), ZONE.as_bytes()).unwrap();
        assert_eq!(parsed.record_sets.len(), 12);
        let mx = parsed
            .record_sets
            .iter()
            .find(|set| set.kind == RecordType::Mx)
            .unwrap();
        assert_eq!(
            mx.records,
            ["10 mail.example.test.", "20 backup-mx.example.net."]
        );
        assert_eq!(
            mx.canonical(),
            "example.test. 3600 IN MX 10 mail.example.test.\nexample.test. 3600 IN MX 20 backup-mx.example.net.\n"
        );
        let mail: Vec<_> = parsed
            .record_sets
            .iter()
            .filter(|set| set.is_mail(&zone()))
            .map(|set| (set.owner.as_str(), set.kind))
            .collect();
        assert_eq!(
            mail,
            [
                ("_dmarc.example.test.", RecordType::Txt),
                ("example.test.", RecordType::Mx),
                ("example.test.", RecordType::Txt),
                ("selector1._domainkey.example.test.", RecordType::Cname),
            ]
        );
        assert_eq!(
            parsed.sha256,
            Sha256Digest::from_bytes(Sha256::digest(ZONE.as_bytes()).into())
        );
        assert!(!RecordType::Soa.changeable() && !RecordType::Ns.changeable());
        assert!(RecordType::Txt.changeable());
    }

    fn with_line(index: usize, replacement: &str) -> String {
        let mut lines: Vec<&str> = ZONE.lines().collect();
        lines[index] = replacement;
        let mut text = lines.join("\n");
        text.push('\n');
        text
    }

    #[test]
    fn each_line_rule_is_refused_with_its_line() {
        // Line 4 (index 3) is `example.test. 3600 IN A 203.0.113.10`.
        for bad in [
            "example.test. 3600 IN A 203.0.113.010",
            "example.test. 3600 IN A 999.0.113.10",
            "example.test. 3600 in A 203.0.113.10",
            "example.test. 3600 IN PTR host.example.test.",
            "example.test. 30 IN A 203.0.113.10",
            "example.test. 0600 IN A 203.0.113.10",
            "example.test 3600 IN A 203.0.113.10",
            "Example.test. 3600 IN A 203.0.113.10",
            "example.test.  3600 IN A 203.0.113.10",
        ] {
            assert_eq!(
                parse_zone(&zone(), with_line(3, bad).as_bytes()),
                Err(ZoneError::Line(4)),
                "{bad}"
            );
        }
        // Outside the zone, sorted into the same place.
        let outside = "example.test.evil. 3600 IN A 203.0.113.10";
        assert_eq!(
            parse_zone(&zone(), with_line(3, outside).as_bytes()),
            Err(ZoneError::Line(4))
        );
    }

    #[test]
    fn rdata_grammars_are_closed() {
        let ok = [
            (RecordType::Txt, "\"a\\\"b\" \"c\\\\d\""),
            (
                RecordType::Caa,
                "128 iodef \"mailto:security@example.test\"",
            ),
            (RecordType::Srv, "0 0 443 target.example.net."),
            (RecordType::Aaaa, "2001:db8::1"),
        ];
        for (kind, rdata) in ok {
            assert!(rdata_ok(kind, rdata), "{rdata}");
        }
        let refused = [
            (RecordType::Txt, "unquoted"),
            (RecordType::Txt, "\"a\"\"b\""),
            (RecordType::Txt, "\"tab\there\""),
            (RecordType::Txt, "\"\\x41\""),
            (RecordType::Txt, "\"open"),
            (RecordType::Caa, "0 tbs \"x\""),
            (RecordType::Caa, "256 issue \"x\""),
            (RecordType::Mx, "10 mail.example.test"),
            (RecordType::Mx, "70000 mail.example.test."),
            (RecordType::Srv, "0 0 443 target"),
            (RecordType::Aaaa, "2001:DB8::1"),
            (RecordType::Aaaa, "2001:0db8::1"),
            (RecordType::Cname, "a..b."),
            (
                RecordType::Soa,
                "ns1.example.test. hostmaster.example.test. 1 2 3 4",
            ),
        ];
        for (kind, rdata) in refused {
            assert!(!rdata_ok(kind, rdata), "{rdata}");
        }
        assert!(!rdata_ok(
            RecordType::Txt,
            &format!("\"{}\"", "a".repeat(256))
        ));
        assert!(rdata_ok(
            RecordType::Txt,
            &format!("\"{}\"", "a".repeat(255))
        ));
    }

    #[test]
    fn order_structure_and_shape_are_checked() {
        let lines: Vec<&str> = ZONE.lines().collect();
        let mut swapped = lines.clone();
        swapped.swap(3, 4);
        let text = swapped.join("\n") + "\n";
        assert_eq!(
            parse_zone(&zone(), text.as_bytes()),
            Err(ZoneError::Order(5))
        );
        let mut repeated = lines.clone();
        repeated.insert(4, lines[3]);
        let text = repeated.join("\n") + "\n";
        assert_eq!(
            parse_zone(&zone(), text.as_bytes()),
            Err(ZoneError::Order(5))
        );
        // A second TTL in the MX set, no SOA, and a CNAME beside an A, each
        // with its lines in canonical order.
        let sorted = |text: String| {
            let mut lines: Vec<&str> = text.lines().collect();
            lines.sort_unstable();
            lines.join("\n") + "\n"
        };
        for text in [
            with_line(7, "example.test. 300 IN MX 20 backup-mx.example.net."),
            ZONE.replace(
                "example.test. 3600 IN SOA ns1.example.test. hostmaster.example.test. 2026112101 10800 3600 604800 3600\n",
                "",
            ),
            ZONE.replace(
                "www.example.test. 300 IN CNAME example.test.\n",
                "www.example.test. 300 IN A 203.0.113.30\nwww.example.test. 300 IN CNAME example.test.\n",
            ),
        ] {
            assert_eq!(
                parse_zone(&zone(), sorted(text).as_bytes()),
                Err(ZoneError::Structure)
            );
        }
        // An NS below the apex is refused on its line.
        assert_eq!(
            parse_zone(
                &zone(),
                ZONE.replace(
                    "www.example.test. 300 IN CNAME example.test.\n",
                    "www.example.test. 300 IN NS ns3.example.net.\n"
                )
                .as_bytes()
            ),
            Err(ZoneError::Line(14))
        );
        assert_eq!(
            parse_zone(&zone(), ZONE.trim_end().as_bytes()),
            Err(ZoneError::Shape)
        );
        assert_eq!(parse_zone(&zone(), &[0xff, b'\n']), Err(ZoneError::Shape));
        assert_eq!(
            parse_zone(&zone(), &vec![b'a'; MAX_ZONE_BYTES + 1]),
            Err(ZoneError::Shape)
        );
    }

    #[test]
    fn zone_names_are_lowercase_with_two_labels() {
        for good in ["example.test", "xn--bcher-kva.example", "a-b.c"] {
            assert!(ZoneName::try_from(good.to_owned()).is_ok(), "{good}");
        }
        for bad in [
            "test",
            "Example.test",
            "example.test.",
            "-a.test",
            "a_b.test",
            "",
        ] {
            assert!(ZoneName::try_from(bad.to_owned()).is_err(), "{bad}");
        }
    }
}
