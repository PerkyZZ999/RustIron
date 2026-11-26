//! W342: the product `lock` action's S3 response reader and `curl` builders
//! (W334), included from the executor by path. `s3.rs` reads
//! `super::lock::MIN_DAYS`, so `lock.rs` comes in beside it. Both files need
//! only `serde`, `serde_json` and `sha2`, so the fuzz graph gains no package.
//!
//! `Element` keeps its fields private: the oracles compare whole elements
//! with the derived `PartialEq` and check the decisions, not the tree.

#[path = "../../crates/executor/src/manifest/lock.rs"]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "s3.rs reads only the retention floor")
)]
mod lock;
#[path = "../../crates/executor/src/manifest/s3.rs"]
#[expect(
    dead_code,
    reason = "the worker's request constants and restic JSON readers are not under test here"
)]
mod s3;

use std::net::{Ipv4Addr, SocketAddrV4};

use s3::{Bucket, Element, LIST_MAX_KEYS, MAX_CURL_OUTPUT, Page};

/// The largest response body the four response campaigns feed. It holds a
/// full 1,000-key listing page and the 16,384-element ceiling.
pub const S3_RESPONSE_MAX_INPUT: usize = 256 * 1024;
/// The batch campaign feeds one count byte and up to one byte over the
/// `curl` stdout ceiling.
pub const S3_BATCH_MAX_INPUT: usize = 1 + MAX_CURL_OUTPUT + 1;
/// The builder campaign feeds a handful of fields; a URL is at most 1,024
/// bytes, so 8 KiB holds an over-long URL beside the other fields.
pub const S3_CURL_MAX_INPUT: usize = 8 * 1024;
/// The longest RFC 3339 time the reader accepts is 35 bytes.
pub const S3_TIMESTAMP_MAX_INPUT: usize = 64;

/// The fixed enrolment facts of the listing campaign.
pub const LIST_BUCKET: &str = "rustiron-lab";
/// The listed prefix: the site repository's `index/` directory.
pub const LIST_PREFIX: &str = "sites/rs_blog/index/";
/// The `start-after` key the listing campaign also tries.
pub fn list_after() -> String {
    format!("{LIST_PREFIX}{}", "8".repeat(64))
}

/// The S3 namespace the root may carry.
pub const NAMESPACE: &str = "http://s3.amazonaws.com/doc/2006-03-01/";
/// The XML declaration AWS and MinIO write before each body.
pub const DECLARATION: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
/// The `curl --write-out` marker after an HTTP 200 body.
pub const MARKER: &str = "\n200\n";

/// The reader's documented ceilings (s3.rs `MAX_DEPTH`, `MAX_ELEMENTS`):
/// the root is at depth 0, so seven levels; 16,384 elements a document.
const LEVELS: usize = 7;
const ELEMENTS: usize = 16 * 1024;
/// RFC 3339 times with an offset of up to 23:59 around years 1970 to 9999.
const FIRST_SECOND: i64 = -(23 * 3600 + 59 * 60);
const LAST_LOCAL_SECOND: i64 = 253_402_300_799;
const LAST_SECOND: i64 = LAST_LOCAL_SECOND + 23 * 3600 + 59 * 60;
const DAY: i64 = 86_400;
/// The SigV4 clock bound the retention decision allows.
const SKEW: i64 = 15 * 60;
/// The lab retention floor (D-010).
const FLOOR_DAYS: u64 = 30;

fn one(body: &[u8]) -> Option<Element> {
    let documents = s3::batch(&[body, MARKER.as_bytes()].concat(), 1)?;
    <[Element; 1]>::try_from(documents).ok().map(|[root]| root)
}

/// Reader properties shared by the four response targets. The body is read
/// as `curl` prints it, followed by the HTTP 200 marker. Returns the root.
fn read(body: &[u8]) -> Option<Element> {
    let root = one(body);
    if !body.starts_with(b"<?xml ") {
        assert_eq!(
            one(&[DECLARATION.as_bytes(), body].concat()),
            root,
            "a declaration changed the reading"
        );
    }
    assert_eq!(
        one(&[body, b" \t\r\n"].concat()),
        root,
        "white space before the marker changed the reading"
    );
    let root = root?;
    let marked = [body, MARKER.as_bytes()].concat();
    let twice = s3::batch(&[marked.as_slice(), &marked].concat(), 2)
        .expect("the same document twice in one batch must read");
    assert!(twice.iter().all(|element| *element == root));
    assert!(s3::batch(&marked, 0).is_none() && s3::batch(&marked, 2).is_none());
    assert!(s3::batch(&[body, b"\n403\n"].concat(), 1).is_none());
    assert!(
        s3::batch(body, 1).is_none(),
        "a body without its marker read"
    );
    raw_contract(
        std::str::from_utf8(body).expect("an accepted body is UTF-8"),
        1,
    );
    Some(root)
}

/// What accepted text of `documents` documents can hold, measured on the
/// raw text.
fn raw_contract(text: &str, documents: usize) {
    assert!(text.len() <= MAX_CURL_OUTPUT);
    assert!(!text.contains("<!"), "a comment, CDATA or DTD was read");
    assert!(
        !text
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r')),
        "a control character was read"
    );
    for (at, _) in text.match_indices('&') {
        let rest = &text[at..];
        assert!(
            [
                "&amp;", "&lt;", "&gt;", "&quot;", "&apos;", "&#34;", "&#39;"
            ]
            .iter()
            .any(|reference| rest.starts_with(reference)),
            "an unknown reference was read: {:?}",
            &rest[..rest.len().min(12)]
        );
    }
    // '>' never occurs in text, so "/>" only ends an empty-element tag.
    let bytes = text.as_bytes();
    let (mut depth, mut deepest, mut elements) = (0_usize, 0, 0);
    for (at, byte) in bytes.iter().enumerate() {
        match (byte, bytes.get(at + 1)) {
            (b'<', Some(b'/')) => depth -= 1,
            (b'<', Some(next)) if next.is_ascii_alphabetic() => {
                depth += 1;
                elements += 1;
                deepest = deepest.max(depth);
            }
            (b'/', Some(b'>')) => depth -= 1,
            _ => {}
        }
    }
    assert_eq!(depth, 0);
    assert!(deepest <= LEVELS, "{deepest} levels were read");
    assert!(
        elements <= ELEMENTS * documents.max(1),
        "{elements} elements were read"
    );
}

/// No body passes two response shapes.
fn passes_one_shape_at_most(root: &Element) {
    let after = list_after();
    let passed = [
        s3::versioning_enabled(root),
        s3::default_retention_days(root).is_some(),
        s3::compliance_until(root).is_some(),
        s3::list_page(root, LIST_BUCKET, LIST_PREFIX, None).is_some()
            || s3::list_page(root, LIST_BUCKET, LIST_PREFIX, Some(&after)).is_some(),
    ];
    assert!(
        passed.iter().filter(|pass| **pass).count() <= 1,
        "a body passed two shapes: {passed:?}"
    );
}

fn canonical(body: &str) -> Element {
    one(body.as_bytes()).expect("a canonical body must read")
}

fn versioning_body(status: &str) -> String {
    format!(
        "{DECLARATION}<VersioningConfiguration xmlns=\"{NAMESPACE}\"><Status>{status}</Status></VersioningConfiguration>"
    )
}

fn lock_body(period: &str) -> String {
    format!(
        "{DECLARATION}<ObjectLockConfiguration xmlns=\"{NAMESPACE}\"><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode>{period}</DefaultRetention></Rule></ObjectLockConfiguration>"
    )
}

fn retention_body(until: &str) -> String {
    format!(
        "{DECLARATION}<Retention xmlns=\"{NAMESPACE}\"><Mode>COMPLIANCE</Mode><RetainUntilDate>{until}</RetainUntilDate></Retention>"
    )
}

/// `GetBucketVersioning`: a pass is exactly what the bucket check needs from
/// the versioning half, and the canonical shapes pass and fail as stated.
pub fn s3_versioning(input: &[u8]) -> bool {
    let Some(root) = read(input) else {
        return false;
    };
    passes_one_shape_at_most(&root);
    let enabled = s3::versioning_enabled(&root);
    let lock = canonical(&lock_body("<Days>30</Days>"));
    assert_eq!(s3::bucket_passes(&root, &lock, 30), enabled);
    assert!(s3::versioning_enabled(&canonical(&versioning_body(
        "Enabled"
    ))));
    assert!(!s3::versioning_enabled(&canonical(&versioning_body(
        "Suspended"
    ))));
    enabled
}

/// `GetObjectLockConfiguration`: the days are in range, the value survives
/// the canonical `Days` or `Years` shape, and the bucket check passes
/// exactly at the enrolled days and never under the floor.
pub fn s3_object_lock(input: &[u8]) -> bool {
    let Some(root) = read(input) else {
        return false;
    };
    passes_one_shape_at_most(&root);
    let versioning = canonical(&versioning_body("Enabled"));
    let Some(days) = s3::default_retention_days(&root) else {
        assert!(!s3::bucket_passes(&versioning, &root, 1));
        return false;
    };
    assert!((1..=999_999 * 365).contains(&days), "{days} days");
    let mut shapes = 0;
    if days <= 999_999 {
        let body = lock_body(&format!("<Days>{days}</Days>"));
        assert_eq!(s3::default_retention_days(&canonical(&body)), Some(days));
        shapes += 1;
    }
    if days % 365 == 0 {
        let body = lock_body(&format!("<Years>{}</Years>", days / 365));
        assert_eq!(s3::default_retention_days(&canonical(&body)), Some(days));
        shapes += 1;
    }
    assert!(shapes > 0, "{days} days has no canonical shape");
    let enrolled = u16::try_from(days).unwrap_or(u16::MAX);
    for enrolled in [
        1,
        29,
        30,
        31,
        enrolled,
        enrolled.saturating_add(1),
        u16::MAX,
    ] {
        let expected = days >= u64::from(enrolled) && days >= FLOOR_DAYS;
        assert_eq!(
            s3::bucket_passes(&versioning, &root, enrolled),
            expected,
            "{days} days, {enrolled} enrolled"
        );
    }
    true
}

/// `GetObjectRetention`: the time is in range, survives the canonical
/// shape, and covers the enrolled days exactly at the stated boundary.
pub fn s3_retention(input: &[u8]) -> bool {
    let Some(root) = read(input) else {
        return false;
    };
    passes_one_shape_at_most(&root);
    let Some(until) = s3::compliance_until(&root) else {
        return false;
    };
    assert!((FIRST_SECOND..=LAST_SECOND).contains(&until), "{until}");
    if let Some(text) = format_time(until) {
        let again = s3::compliance_until(&canonical(&retention_body(&text)));
        assert_eq!(again, Some(until), "{text}");
    }
    for enrolled in [1, 30, 365, u16::MAX] {
        let started = until - i64::from(enrolled) * DAY + SKEW;
        assert!(s3::retention_covers(until, started, enrolled));
        assert!(!s3::retention_covers(until, started + 1, enrolled));
    }
    true
}

/// `ListObjectsV2` against the fixed enrolment, from the start and after a
/// fixed key: every accepted key is the prefix plus a full ID, in strictly
/// rising order after `start-after`; the page is bounded; a truncated page
/// makes progress; the page survives its canonical shape; another bucket or
/// prefix refuses; and the written-object keys build valid retention URLs.
pub fn s3_list(input: &[u8]) -> bool {
    let Some(root) = read(input) else {
        return false;
    };
    passes_one_shape_at_most(&root);
    let after = list_after();
    let mut accepted = false;
    for start in [None, Some(after.as_str())] {
        let Some(page) = s3::list_page(&root, LIST_BUCKET, LIST_PREFIX, start) else {
            continue;
        };
        accepted = true;
        check_page(&page, start);
        assert!(s3::list_page(&root, "rustiron-other", LIST_PREFIX, start).is_none());
        assert!(s3::list_page(&root, LIST_BUCKET, "sites/rs_other/index/", start).is_none());
        if page
            .entries
            .iter()
            .all(|(_, modified)| format_time(*modified).is_some())
        {
            let body = listing_body(&page, start);
            let again = s3::list_page(&canonical(&body), LIST_BUCKET, LIST_PREFIX, start);
            assert_eq!(again.as_ref(), Some(&page), "{body}");
        }
        written_keys(&page);
    }
    accepted
}

fn check_page(page: &Page, start: Option<&str>) {
    assert!(page.entries.len() <= LIST_MAX_KEYS);
    assert!(!page.truncated || !page.entries.is_empty());
    let mut last = start.map(str::to_owned);
    for (id, modified) in &page.entries {
        assert!(s3::full_id(id), "{id}");
        assert!((FIRST_SECOND..=LAST_SECOND).contains(modified));
        let key = format!("{LIST_PREFIX}{id}");
        assert!(last.as_ref().is_none_or(|last| key > *last), "{key}");
        last = Some(key);
    }
}

/// The canonical page as AWS writes it.
fn listing_body(page: &Page, start: Option<&str>) -> String {
    let after = start
        .map(|key| format!("<StartAfter>{key}</StartAfter>"))
        .unwrap_or_default();
    let contents: String = page
        .entries
        .iter()
        .map(|(id, modified)| {
            format!(
                "<Contents><Key>{LIST_PREFIX}{id}</Key><LastModified>{}</LastModified><ETag>&quot;0&quot;</ETag><Size>1</Size><StorageClass>STANDARD</StorageClass></Contents>",
                format_time(*modified).unwrap_or_default()
            )
        })
        .collect();
    format!(
        "{DECLARATION}<ListBucketResult xmlns=\"{NAMESPACE}\"><Name>{LIST_BUCKET}</Name><Prefix>{LIST_PREFIX}</Prefix>{after}<KeyCount>{}</KeyCount><MaxKeys>{LIST_MAX_KEYS}</MaxKeys><IsTruncated>{}</IsTruncated>{contents}</ListBucketResult>",
        page.entries.len(),
        page.truncated
    )
}

/// The listed IDs as the capture's new indexes: each key is one fixed
/// object, and each retention URL passes the config check with one query.
fn written_keys(page: &Page) {
    use std::collections::BTreeSet;
    let before: BTreeSet<_> = page
        .entries
        .iter()
        .step_by(2)
        .map(|(id, _)| id.clone())
        .collect();
    let after: BTreeSet<_> = page.entries.iter().map(|(id, _)| id.clone()).collect();
    let wrote_packs = after.len() > before.len();
    let indexes = s3::written_index_ids(&before, &after, wrote_packs).unwrap();
    let expected: Vec<_> = page
        .entries
        .iter()
        .skip(1)
        .step_by(2)
        .map(|(id, _)| id.clone())
        .collect();
    assert_eq!(indexes, expected);
    let snapshot = "d".repeat(64);
    let packs = BTreeSet::new();
    let Some(objects) = s3::written_objects("sites/rs_blog", &snapshot, &indexes, &packs) else {
        panic!("at most 1,000 indexes always fit the object ceiling");
    };
    assert_eq!(objects.len(), 1 + indexes.len());
    let bucket = Bucket {
        endpoint: SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 23), 443),
        name: LIST_BUCKET,
    };
    // W391: the version-pinned retention read of each written object.
    let urls: Vec<String> = objects
        .iter()
        .map(|object| bucket.retention_version(&object.key, "v1"))
        .collect();
    for url in &urls {
        assert_eq!(url.matches('?').count(), 1, "{url}");
        assert!(url.ends_with("?retention&versionId=v1"));
    }
    assert!(s3::curl_config("SYNTHETIC_W342", "synthetic", &urls).is_some());
}

/// `curl` batch stdout: the first byte picks a count of 0 to 3 documents.
/// An accepted batch has exactly that many documents, each followed by the
/// HTTP 200 marker; no other count reads the same bytes; the stdout ceiling
/// holds; and the batch twice over reads twice the documents.
pub fn s3_batch(input: &[u8]) -> bool {
    let Some((first, output)) = input.split_first() else {
        return false;
    };
    let count = usize::from(first % 4);
    let documents = s3::batch(output, count);
    if output.len() > MAX_CURL_OUTPUT {
        assert!(documents.is_none(), "oversized output read");
        return false;
    }
    let Some(documents) = documents else {
        return false;
    };
    assert_eq!(documents.len(), count);
    assert_eq!(count == 0, output.is_empty());
    assert!(s3::batch(output, count + 1).is_none());
    if count > 0 {
        assert!(s3::batch(output, count - 1).is_none());
        assert!(output.ends_with(b"200\n"));
        let doubled = s3::batch(&[output, output].concat(), count * 2);
        if output.len() * 2 <= MAX_CURL_OUTPUT {
            let doubled = doubled.expect("a batch twice over must read");
            assert!(doubled[..count] == documents[..] && doubled[count..] == documents[..]);
        } else {
            assert!(doubled.is_none());
        }
    }
    raw_contract(
        std::str::from_utf8(output).expect("accepted output is UTF-8"),
        count,
    );
    for root in &documents {
        let after = list_after();
        let _ = s3::versioning_enabled(root);
        let _ = s3::default_retention_days(root);
        let _ = s3::compliance_until(root);
        let _ = s3::list_page(root, LIST_BUCKET, LIST_PREFIX, Some(&after));
    }
    true
}

/// RFC 3339 times: the reader agrees with an independent reference, an
/// accepted time is in range and the canonical spellings read the same.
pub fn s3_timestamp(input: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(input) else {
        return false;
    };
    let parsed = s3::timestamp(text);
    assert_eq!(parsed, reference_time(text), "{text:?}");
    let Some(seconds) = parsed else {
        return false;
    };
    assert!((20..=35).contains(&text.len()));
    assert!((FIRST_SECOND..=LAST_SECOND).contains(&seconds));
    if let Some(canonical) = format_time(seconds) {
        assert_eq!(s3::timestamp(&canonical), Some(seconds), "{canonical}");
        let millis = canonical.replace('Z', ".000Z");
        assert_eq!(s3::timestamp(&millis), Some(seconds), "{millis}");
        let offset = canonical.replace('Z', "+00:00");
        assert_eq!(s3::timestamp(&offset), Some(seconds), "{offset}");
    }
    true
}

fn leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn month_lengths(year: i64) -> [i64; 12] {
    let february = if leap(year) { 29 } else { 28 };
    [31, february, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
}

/// An independent RFC 3339 reader: `YYYY-MM-DDTHH:MM:SS`, an optional
/// fraction of 1 to 9 digits, then `Z` or `+HH:MM`/`-HH:MM`.
fn reference_time(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    let field = |start: usize, width: usize| -> Option<i64> {
        let digits = bytes.get(start..start + width)?;
        digits.iter().all(u8::is_ascii_digit).then(|| {
            digits
                .iter()
                .fold(0, |value, digit| value * 10 + i64::from(digit - b'0'))
        })
    };
    let separators = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')];
    if separators
        .iter()
        .any(|(at, byte)| bytes.get(*at) != Some(byte))
    {
        return None;
    }
    let (year, month, day) = (field(0, 4)?, field(5, 2)?, field(8, 2)?);
    let (hour, minute, second) = (field(11, 2)?, field(14, 2)?, field(17, 2)?);
    let mut at = 19;
    if bytes.get(at) == Some(&b'.') {
        let digits = bytes[at + 1..]
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        if !(1..=9).contains(&digits) {
            return None;
        }
        at += 1 + digits;
    }
    let offset = match &bytes[at..] {
        b"Z" => 0,
        [sign @ (b'+' | b'-'), _, _, b':', _, _] => {
            let (hours, minutes) = (field(at + 1, 2)?, field(at + 4, 2)?);
            if hours > 23 || minutes > 59 {
                return None;
            }
            let value = hours * 3600 + minutes * 60;
            if *sign == b'+' { value } else { -value }
        }
        _ => return None,
    };
    if !(1970..=9999).contains(&year) || !(1..=12).contains(&month) {
        return None;
    }
    let lengths = month_lengths(year);
    let month_index = usize::try_from(month - 1).ok()?;
    if day < 1 || day > lengths[month_index] || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let leaps_before = |year: i64| (year - 1) / 4 - (year - 1) / 100 + (year - 1) / 400;
    let days = 365 * (year - 1970) + leaps_before(year) - leaps_before(1970)
        + lengths[..month_index].iter().sum::<i64>()
        + day
        - 1;
    Some(days * DAY + hour * 3600 + minute * 60 + second - offset)
}

/// The canonical `Z` spelling of `seconds`, for times in years 1970 to 9999.
pub fn format_time(seconds: i64) -> Option<String> {
    if !(0..=LAST_LOCAL_SECOND).contains(&seconds) {
        return None;
    }
    let (mut days, rest) = (seconds / DAY, seconds % DAY);
    let mut year = 1970;
    while days >= if leap(year) { 366 } else { 365 } {
        days -= if leap(year) { 366 } else { 365 };
        year += 1;
    }
    let mut month = 0;
    for length in month_lengths(year) {
        if days < length {
            break;
        }
        days -= length;
        month += 1;
    }
    Some(format!(
        "{year:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        month + 1,
        days + 1,
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    ))
}

/// The builder campaign's fields, split at each 0xFF byte (never UTF-8):
/// access key, secret, region, bucket name, object key, listed prefix,
/// `start-after` (absent when the field is missing), port, then extra URLs.
struct Fields {
    access: String,
    secret: String,
    region: String,
    bucket: String,
    key: String,
    prefix: String,
    after: Option<String>,
    port: u16,
    urls: Vec<String>,
}

impl Fields {
    fn split(input: &[u8]) -> Self {
        let mut parts = input
            .split(|byte| *byte == 0xff)
            .map(|part| String::from_utf8_lossy(part).into_owned());
        let mut next = || parts.next().unwrap_or_default();
        let (access, secret, region) = (next(), next(), next());
        let (bucket, key, prefix) = (next(), next(), next());
        let mut rest: Vec<String> = parts.collect();
        let after = (!rest.is_empty()).then(|| rest.remove(0));
        let port = if rest.is_empty() {
            443
        } else {
            rest.remove(0).parse().unwrap_or(443)
        };
        Self {
            access,
            secret,
            region,
            bucket,
            key,
            prefix,
            after,
            port,
            urls: rest,
        }
    }
}

/// The stated key allowlist: S3 access keys and secrets are base64-like.
fn key_ok(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_+-/=".contains(&byte))
}

/// The stated URL allowlist: HTTPS, at most 1,024 bytes, URL characters.
fn url_ok(url: &str) -> bool {
    url.starts_with("https://")
        && url.len() <= 1024
        && url
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~:/?&=%".contains(&byte))
}

/// Bytes that could leave a quoted `curl` config value or start another.
fn unsafe_byte(byte: u8) -> bool {
    !byte.is_ascii_graphic() || matches!(byte, b'"' | b'\\' | b'\'' | b'#' | b' ')
}

/// A lowercase label as the destination contract enrols a bucket or region.
fn label(value: &str, shortest: usize) -> bool {
    (shortest..=63).contains(&value.len())
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn percent_decode(encoded: &str) -> Option<Vec<u8>> {
    let bytes = encoded.as_bytes();
    let mut decoded = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let byte = bytes[at];
        if byte == b'%' {
            let pair = bytes.get(at + 1..at + 3)?;
            if !pair
                .iter()
                .all(|digit| digit.is_ascii_digit() || (b'A'..=b'F').contains(digit))
            {
                return None;
            }
            decoded.push(u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?);
            at += 3;
        } else if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            decoded.push(byte);
            at += 1;
        } else {
            return None;
        }
    }
    Some(decoded)
}

/// The `curl` argv, config and URL builders. A key, secret, region or URL
/// outside its allowlist never reaches the config or argv; an accepted
/// config holds no byte that could leave its quotes and reads back to the
/// exact inputs; the URLs keep the endpoint, bucket and query fixed and the
/// listing query decodes back to the prefix and `start-after`.
pub fn s3_curl(input: &[u8]) -> bool {
    let fields = Fields::split(input);
    let arguments = check_arguments(&fields.region);
    let bucket = Bucket {
        endpoint: SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 23), fields.port),
        name: &fields.bucket,
    };
    let base = if fields.port == 443 {
        format!("https://198.51.100.23/{}", fields.bucket)
    } else {
        format!("https://198.51.100.23:{}/{}", fields.port, fields.bucket)
    };
    let versioning = bucket.versioning();
    let object_lock = bucket.object_lock();
    let retention = bucket.retention_version(&fields.key, "v1");
    let list = bucket.list(&fields.prefix, fields.after.as_deref());
    assert_eq!(versioning, format!("{base}?versioning"));
    assert_eq!(object_lock, format!("{base}?object-lock"));
    assert_eq!(
        retention,
        format!("{base}/{}?retention&versionId=v1", fields.key)
    );
    check_list_url(&list, &base, &fields);
    if label(&fields.bucket, 3) {
        for url in [&versioning, &object_lock] {
            assert!(url_ok(url), "{url}");
        }
        assert_eq!(url_ok(&list), list.len() <= 1024, "{list}");
        let fixed = |text: &str| {
            text.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_/".contains(&byte)
            })
        };
        if fixed(&fields.key) && retention.len() <= 1024 {
            assert!(url_ok(&retention));
            assert_eq!(retention.matches('?').count(), 1);
        }
    }
    let mut urls = vec![versioning, object_lock, retention, list];
    urls.extend(fields.urls.iter().cloned());
    for url in &urls {
        check_config(&fields.access, &fields.secret, std::slice::from_ref(url));
    }
    let config = check_config(&fields.access, &fields.secret, &urls);
    assert!(check_config(&fields.access, &fields.secret, &[]).is_none());
    arguments.is_some() && config.is_some()
}

fn check_arguments(region: &str) -> Option<Vec<String>> {
    let (config, ca) = ("/proc/self/fd/7", "/proc/self/fd/5");
    let arguments = s3::curl_arguments(config, ca, region);
    assert_eq!(arguments.is_some(), label_or_dash(region), "{region:?}");
    let arguments = arguments?;
    assert_eq!(arguments.len(), 25);
    assert_eq!(arguments[..3], ["-q", "-K", config]);
    assert_eq!(arguments[3..5], ["--cacert", ca]);
    assert_eq!(arguments[5], "--aws-sigv4");
    assert_eq!(arguments[6], format!("aws:amz:{region}:s3"));
    for pair in [
        ["--proto", "=https"],
        ["--max-redirs", "0"],
        ["--noproxy", "*"],
        ["--max-filesize", "1048576"],
    ] {
        assert!(
            arguments.windows(2).any(|window| window == pair),
            "{pair:?}"
        );
    }
    for flag in ["--tlsv1.2", "--globoff", "--fail", "--silent"] {
        assert!(arguments.iter().any(|argument| argument == flag), "{flag}");
    }
    for (at, argument) in arguments.iter().enumerate() {
        assert!(!argument.bytes().any(|byte| byte.is_ascii_control()));
        assert!(!argument.starts_with("http"), "a URL in argv");
        let config_flag = matches!(argument.as_str(), "-K" | "--config");
        assert!(!config_flag || at == 1, "a second config");
        assert!(!matches!(
            argument.as_str(),
            "-u" | "--user" | "-H" | "--header" | "-o" | "--output" | "-d" | "--data"
        ));
    }
    Some(arguments)
}

/// The region allowlist: 1 to 63 lowercase letters, digits or dashes.
fn label_or_dash(region: &str) -> bool {
    (1..=63).contains(&region.len())
        && region
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn check_list_url(list: &str, base: &str, fields: &Fields) {
    let query = list
        .strip_prefix(&format!(
            "{base}?list-type=2&max-keys={LIST_MAX_KEYS}&prefix="
        ))
        .expect("the listing query is fixed");
    let (prefix, after) = match query.split_once("&start-after=") {
        Some((prefix, after)) => (prefix, Some(after)),
        None => (query, None),
    };
    assert_eq!(
        percent_decode(prefix),
        Some(fields.prefix.clone().into_bytes())
    );
    assert_eq!(
        after.map(percent_decode),
        fields
            .after
            .as_ref()
            .map(|after| Some(after.clone().into_bytes()))
    );
}

fn check_config(access: &str, secret: &str, urls: &[String]) -> Option<String> {
    let config = s3::curl_config(access, secret, urls);
    let expected =
        key_ok(access) && key_ok(secret) && !urls.is_empty() && urls.iter().all(|url| url_ok(url));
    assert_eq!(config.is_some(), expected, "{access:?} {secret:?} {urls:?}");
    let config = config?;
    let lines: Vec<&str> = config.lines().collect();
    assert_eq!(lines.len(), 1 + urls.len());
    assert!(config.ends_with('\n') && !config.contains('\r'));
    let quoted = |line: &str, name: &str| -> String {
        let value = line
            .strip_prefix(&format!("{name} = \""))
            .and_then(|rest| rest.strip_suffix('"'))
            .unwrap_or_else(|| panic!("an unquoted line: {line:?}"));
        assert!(
            !value.bytes().any(unsafe_byte),
            "a byte that could leave its quotes: {value:?}"
        );
        value.to_owned()
    };
    let user = quoted(lines[0], "user");
    assert_eq!(user.split_once(':'), Some((access, secret)));
    for (line, url) in lines[1..].iter().zip(urls) {
        assert_eq!(&quoted(line, "url"), url);
    }
    Some(config)
}
