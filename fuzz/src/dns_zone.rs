//! Canonical DNS zone parser oracle (D-091, W638 / M-06).

use std::collections::BTreeMap;

use rustiron_contracts::approval::{
    MAX_TTL, MAX_ZONE_BYTES, MIN_TTL, RecordType, ZoneError, ZoneName, parse_zone,
};
use sha2::{Digest, Sha256};

/// Campaign input cap: one byte past `MAX_ZONE_BYTES` so oversized zones are tested.
pub const DNS_ZONE_MAX_INPUT: usize = MAX_ZONE_BYTES + 1;

/// Verify bounds, canonical stability, SOA/NS apex rules, CNAME exclusivity, and digest framing.
pub fn dns_zone(input: &[u8]) -> bool {
    let zone = ZoneName::try_from("example.test".to_owned()).unwrap();
    let parsed = parse_zone(&zone, input);
    if input.len() > MAX_ZONE_BYTES {
        assert_eq!(parsed, Err(ZoneError::Shape));
        return false;
    }
    let Ok(parsed) = parsed else {
        return false;
    };
    assert_eq!(parsed.zone, zone);
    let expected_hex: String = Sha256::digest(input)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(parsed.sha256.as_str(), expected_hex);

    let apex = zone.apex();
    let suffix = format!(".{apex}");
    let mut soa_count = 0usize;
    let mut apex_ns_count = 0usize;
    let mut kinds_by_owner: BTreeMap<&str, Vec<RecordType>> = BTreeMap::new();
    let mut reassembled_lines: Vec<String> = Vec::new();

    for set in &parsed.record_sets {
        assert!(!set.records.is_empty(), "empty record set accepted");
        assert!(
            (MIN_TTL..=MAX_TTL).contains(&set.ttl),
            "TTL out of bounds accepted"
        );
        assert!(
            set.owner == apex || set.owner.ends_with(&suffix),
            "out-of-zone owner accepted"
        );
        if set.kind == RecordType::Soa {
            assert_eq!(set.owner, apex, "non-apex SOA accepted");
            assert_eq!(set.records.len(), 1, "multiple SOA records accepted");
            soa_count += 1;
        }
        if set.kind == RecordType::Ns {
            assert_eq!(set.owner, apex, "non-apex NS accepted");
            apex_ns_count += set.records.len();
        }
        kinds_by_owner
            .entry(set.owner.as_str())
            .or_default()
            .push(set.kind);
        for line in set.canonical().lines() {
            reassembled_lines.push(line.to_owned());
        }
    }
    assert_eq!(soa_count, 1, "missing SOA");
    assert!(apex_ns_count >= 1, "missing apex NS");
    for kinds in kinds_by_owner.values() {
        if kinds.contains(&RecordType::Cname) {
            assert_eq!(kinds.len(), 1, "CNAME coexists with another record set");
        }
    }

    reassembled_lines.sort();
    let mut canonical = reassembled_lines.join("\n");
    canonical.push('\n');
    assert_eq!(
        canonical.as_bytes(),
        input,
        "accepted zone was not canonical"
    );
    assert_eq!(
        parse_zone(&zone, canonical.as_bytes()),
        Ok(parsed),
        "re-parsing canonical zone changed result"
    );

    // Stripping the trailing newline or duplicating the first line must fail.
    assert_eq!(
        parse_zone(&zone, &input[..input.len() - 1]),
        Err(ZoneError::Shape)
    );
    let first_line = reassembled_lines[0].as_str();
    let duplicated = format!("{first_line}\n{canonical}");
    assert!(
        parse_zone(&zone, duplicated.as_bytes()).is_err(),
        "duplicate zone line accepted"
    );
    true
}
