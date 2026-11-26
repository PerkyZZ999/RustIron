//! W334: the fixed S3 reads of the product `lock` action (D-025 items 1 and
//! 2). Pure parts only: the `curl` argument and config builders, a strict
//! bounded XML reader for the four S3 response shapes the action reads, and
//! the retention decisions. The worker in `repository.rs` runs the requests.
//!
//! Every response shape is closed. An unknown element, an attribute other
//! than the S3 namespace on the root, mixed content, a comment, a CDATA
//! section, a DTD, an unknown entity, a numeric character reference other
//! than the `&#34;` and `&#39;` that MinIO writes, or input over a bound
//! refuses.

use std::collections::BTreeSet;

use serde::Deserialize;

/// The OS `curl` (AlmaLinux 10 ships 8.12.1). A system tool, so it stays
/// beside the code that uses it ([layout](../layout.rs)).
pub(crate) const CURL: &str = "/usr/bin/curl";
/// The S3 protocol's XML namespace. The root may carry it or nothing.
const NAMESPACE: &str = "http://s3.amazonaws.com/doc/2006-03-01/";
/// SigV4 refuses a request whose time is more than 15 minutes from the
/// store's clock, so every accepted request bounds the clock difference.
pub(crate) const SKEW_SECS: i64 = 15 * 60;
/// Keys per listing page. The response must echo it.
pub(crate) const LIST_MAX_KEYS: usize = 1000;
/// Listing pages of the repository's `index/` directory. A repository with
/// more index files than this refuses (fail closed).
pub(crate) const MAX_LIST_PAGES: usize = 16;
/// Objects one per-object check reads. More refuses (fail closed).
pub(crate) const MAX_OBJECTS: usize = 1024;
/// Retention requests in one `curl` run.
pub(crate) const BATCH: usize = 128;
/// Bound of one `curl` run's stdout.
pub(crate) const MAX_CURL_OUTPUT: usize = 1024 * 1024;
const MAX_DEPTH: usize = 6;
const MAX_ELEMENTS: usize = 16 * 1024;
const DAY_SECS: i64 = 86_400;
/// Per-transfer marker that `curl --write-out` prints after each body.
const WRITE_OUT: &str = "\\n%{response_code}\\n";
/// W391: the one line `curl --write-out` prints per HEAD transfer.
const HEAD_WRITE_OUT: &str = "%{response_code} %header{x-amz-version-id} %header{x-amz-object-lock-mode} %header{x-amz-object-lock-retain-until-date}\\n";

/// The fixed `curl` argv for one batch. `config` and `ca` are paths to
/// sealed snapshots. The argv carries no secret: the credentials and the
/// URLs are in the config file, which `-q -K` reads (`-q` first, so no
/// `.curlrc` is read).
pub(crate) fn curl_arguments(config: &str, ca: &str, region: &str) -> Option<Vec<String>> {
    arguments(config, ca, region, false)
}

/// W391: the fixed `curl` argv for one HEAD batch. As [`curl_arguments`],
/// with `--head` and one write-out line per transfer: the status, the
/// version ID, the object-lock mode and the retain-until time. The config
/// sends each transfer's headers to `/dev/null` ([`curl_head_config`]).
pub(crate) fn curl_head_arguments(config: &str, ca: &str, region: &str) -> Option<Vec<String>> {
    arguments(config, ca, region, true)
}

fn arguments(config: &str, ca: &str, region: &str, head: bool) -> Option<Vec<String>> {
    if !region_ok(region) {
        return None;
    }
    let fixed = ["-q", "-K", config, "--cacert", ca, "--aws-sigv4"];
    let mut args: Vec<String> = fixed.iter().map(|value| (*value).to_owned()).collect();
    args.push(format!("aws:amz:{region}:s3"));
    args.extend(
        [
            "--proto",
            "=https",
            "--max-redirs",
            "0",
            "--tlsv1.2",
            "--noproxy",
            "*",
            "--globoff",
            "--fail",
            "--silent",
            "--connect-timeout",
            "5",
            "--max-time",
            "15",
            "--write-out",
            if head { HEAD_WRITE_OUT } else { WRITE_OUT },
        ]
        .map(str::to_owned),
    );
    if head {
        // W403 F1: curl compares `--max-filesize` with the Content-Length of
        // a HEAD answer, which is the object size, and exits 63 for a pack
        // over the limit. A HEAD answer has no body, so the limit is dropped.
        args.push("--head".to_owned());
    } else {
        args.extend(["--max-filesize", "1048576"].map(str::to_owned));
    }
    Some(args)
}

/// The sealed config file text: the static key pair, then one `url` line
/// per request. Refuses a value that could escape its quoted string.
pub(crate) fn curl_config(access: &str, secret: &str, urls: &[String]) -> Option<String> {
    config(access, secret, urls, false)
}

/// W391: as [`curl_config`], with each `url` line followed by an `output`
/// line that sends that transfer's headers to `/dev/null`, so stdout holds
/// only the write-out lines.
pub(crate) fn curl_head_config(access: &str, secret: &str, urls: &[String]) -> Option<String> {
    config(access, secret, urls, true)
}

fn config(access: &str, secret: &str, urls: &[String], head: bool) -> Option<String> {
    let key = |value: &str| {
        !value.is_empty()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_+-/=".contains(&byte))
    };
    if !key(access) || !key(secret) || urls.is_empty() || !urls.iter().all(|url| url_ok(url)) {
        return None;
    }
    let mut text = format!("user = \"{access}:{secret}\"\n");
    for url in urls {
        text.push_str(&format!("url = \"{url}\"\n"));
        if head {
            text.push_str("output = \"/dev/null\"\n");
        }
    }
    Some(text)
}

fn region_ok(region: &str) -> bool {
    (1..=63).contains(&region.len())
        && region
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn url_ok(url: &str) -> bool {
    url.starts_with("https://")
        && url.len() <= 1024
        && url
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~:/?&=%".contains(&byte))
}

/// Path-style request URLs for the enrolled bucket. The endpoint is the
/// enrolled IPv4 address and port; the port is left out when it is 443.
pub(crate) struct Bucket<'a> {
    pub(crate) endpoint: std::net::SocketAddrV4,
    pub(crate) name: &'a str,
}

impl Bucket<'_> {
    fn base(&self) -> String {
        if self.endpoint.port() == 443 {
            format!("https://{}/{}", self.endpoint.ip(), self.name)
        } else {
            format!("https://{}/{}", self.endpoint, self.name)
        }
    }

    /// `GetBucketVersioning`.
    pub(crate) fn versioning(&self) -> String {
        format!("{}?versioning", self.base())
    }

    /// `GetObjectLockConfiguration`.
    pub(crate) fn object_lock(&self) -> String {
        format!("{}?object-lock", self.base())
    }

    /// W391: `GetObjectRetention` of one version of one key. The version ID
    /// passed [`version_ok`], so it needs no encoding.
    pub(crate) fn retention_version(&self, key: &str, version: &str) -> String {
        format!("{}/{key}?retention&versionId={version}", self.base())
    }

    /// W391: `HeadObject` of one key (fixed characters only).
    pub(crate) fn object(&self, key: &str) -> String {
        format!("{}/{key}", self.base())
    }

    /// One `ListObjectsV2` page of `prefix`, after `start_after`.
    pub(crate) fn list(&self, prefix: &str, start_after: Option<&str>) -> String {
        let mut url = format!(
            "{}?list-type=2&max-keys={LIST_MAX_KEYS}&prefix={}",
            self.base(),
            encode(prefix)
        );
        if let Some(key) = start_after {
            url.push_str(&format!("&start-after={}", encode(key)));
        }
        url
    }
}

/// Percent-encodes everything outside the RFC 3986 unreserved set, as the
/// SigV4 canonical query needs.
fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

/// One parsed XML element: either text or child elements, never both.
#[derive(Debug, PartialEq)]
pub(crate) struct Element {
    name: String,
    text: String,
    children: Vec<Element>,
}

struct Reader<'a> {
    input: &'a str,
    at: usize,
    elements: usize,
}

impl<'a> Reader<'a> {
    fn rest(&self) -> &'a str {
        &self.input[self.at..]
    }

    fn eat(&mut self, token: &str) -> bool {
        let found = self.rest().starts_with(token);
        if found {
            self.at += token.len();
        }
        found
    }

    fn space(&mut self) {
        let skipped = self.rest().len()
            - self
                .rest()
                .trim_start_matches([' ', '\t', '\r', '\n'])
                .len();
        self.at += skipped;
    }

    fn name(&mut self) -> Option<&'a str> {
        let rest = self.rest();
        let length = rest
            .bytes()
            .position(|byte| !byte.is_ascii_alphanumeric())
            .unwrap_or(rest.len());
        let name = &rest[..length];
        (!name.is_empty() && name.as_bytes()[0].is_ascii_alphabetic() && length <= 64).then(|| {
            self.at += length;
            name
        })
    }

    /// The optional `<?xml ...?>` declaration.
    fn declaration(&mut self) -> Option<()> {
        if !self.eat("<?xml ") {
            return Some(());
        }
        let end = self.rest().find("?>")?;
        let body = &self.rest()[..end];
        if end > 64
            || !body
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b" =\"'.-_".contains(&byte))
        {
            return None;
        }
        self.at += end + 2;
        Some(())
    }

    fn element(&mut self, depth: usize) -> Option<Element> {
        self.elements += 1;
        if depth > MAX_DEPTH || self.elements > MAX_ELEMENTS || !self.eat("<") {
            return None;
        }
        let name = self.name()?.to_owned();
        let mut namespace = false;
        loop {
            self.space();
            if self.eat("/>") {
                return Some(Element {
                    name,
                    text: String::new(),
                    children: Vec::new(),
                });
            }
            if self.eat(">") {
                break;
            }
            // Only the S3 namespace, only on the root, only once.
            if depth != 0 || namespace || !self.eat("xmlns=\"") {
                return None;
            }
            let end = self.rest().find('"')?;
            if &self.rest()[..end] != NAMESPACE {
                return None;
            }
            self.at += end + 1;
            namespace = true;
        }
        let mut text = String::new();
        let mut children = Vec::new();
        loop {
            if self.eat("</") {
                if self.name()? != name {
                    return None;
                }
                self.space();
                if !self.eat(">") {
                    return None;
                }
                break;
            }
            if self.rest().starts_with("<!") || self.rest().starts_with("<?") {
                return None;
            }
            if self.rest().starts_with('<') {
                children.push(self.element(depth + 1)?);
                continue;
            }
            let end = self.rest().find('<')?;
            text.push_str(&unescape(&self.rest()[..end])?);
            self.at += end;
        }
        if !children.is_empty() {
            if !text.trim_matches([' ', '\t', '\r', '\n']).is_empty() {
                return None;
            }
            text.clear();
        }
        Some(Element {
            name,
            text,
            children,
        })
    }
}

fn unescape(raw: &str) -> Option<String> {
    let mut text = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(index) = rest.find(['&', '>']) {
        if rest.as_bytes()[index] == b'>' {
            return None;
        }
        text.push_str(&rest[..index]);
        rest = &rest[index..];
        let end = rest.find(';')?;
        text.push(match &rest[..=end] {
            "&amp;" => '&',
            "&lt;" => '<',
            "&gt;" => '>',
            "&quot;" => '"',
            "&apos;" => '\'',
            // W342: Go's `encoding/xml` (MinIO) writes `"` and `'` so.
            "&#34;" => '"',
            "&#39;" => '\'',
            _ => return None,
        });
        rest = &rest[end + 1..];
    }
    text.push_str(rest);
    text.chars()
        .all(|c| !c.is_control() || matches!(c, '\t' | '\n' | '\r'))
        .then_some(text)
}

/// Reads one document from the front of `input`. Returns the root element
/// and the bytes it used, so a batch can read the next one.
fn document(input: &str) -> Option<(Element, usize)> {
    let mut reader = Reader {
        input,
        at: 0,
        elements: 0,
    };
    reader.declaration()?;
    reader.space();
    let root = reader.element(0)?;
    Some((root, reader.at))
}

/// One complete document and nothing after it but white space.
#[cfg(test)]
fn parse(input: &[u8]) -> Option<Element> {
    let input = std::str::from_utf8(input).ok()?;
    let (root, used) = document(input)?;
    input[used..]
        .trim_matches([' ', '\t', '\r', '\n'])
        .is_empty()
        .then_some(root)
}

/// Splits one `curl` batch stdout into `count` documents. Each body must be
/// followed by the `--write-out` marker with HTTP status 200.
pub(crate) fn batch(output: &[u8], count: usize) -> Option<Vec<Element>> {
    if output.len() > MAX_CURL_OUTPUT {
        return None;
    }
    let mut rest = std::str::from_utf8(output).ok()?;
    let mut documents = Vec::with_capacity(count);
    for _ in 0..count {
        let (root, used) = document(rest)?;
        rest = rest[used..].trim_start_matches([' ', '\t', '\r', '\n']);
        rest = rest.strip_prefix("200\n")?;
        documents.push(root);
    }
    rest.is_empty().then_some(documents)
}

impl Element {
    fn leaf(&self) -> Option<&str> {
        self.children.is_empty().then_some(self.text.as_str())
    }

    /// The children named in `names`, each at most once, in `names` order.
    /// Any other child refuses.
    fn fields<const N: usize>(&self, names: [&str; N]) -> Option<[Option<&Element>; N]> {
        let mut found = [None; N];
        for child in &self.children {
            let index = names.iter().position(|name| *name == child.name)?;
            if found[index].replace(child).is_some() {
                return None;
            }
        }
        Some(found)
    }
}

/// `GetBucketVersioning`: true only for `Status` `Enabled`. MinIO's
/// excluded-prefix extensions are unknown elements and refuse.
pub(crate) fn versioning_enabled(root: &Element) -> bool {
    (|| {
        if root.name != "VersioningConfiguration" {
            return None;
        }
        let [status, mfa] = root.fields(["Status", "MfaDelete"])?;
        if let Some(mfa) = mfa
            && !matches!(mfa.leaf()?, "Enabled" | "Disabled")
        {
            return None;
        }
        (status?.leaf()? == "Enabled").then_some(())
    })()
    .is_some()
}

fn count(text: &str) -> Option<u64> {
    (!text.is_empty() && text.len() <= 6 && text.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| text.parse().ok())
        .flatten()
        .filter(|value| *value > 0)
}

/// `GetObjectLockConfiguration`: the default COMPLIANCE retention in days
/// (`Years` count as 365 days each), or `None` for anything else.
pub(crate) fn default_retention_days(root: &Element) -> Option<u64> {
    if root.name != "ObjectLockConfiguration" {
        return None;
    }
    let [enabled, rule] = root.fields(["ObjectLockEnabled", "Rule"])?;
    if enabled?.leaf()? != "Enabled" {
        return None;
    }
    let [retention] = rule?.fields(["DefaultRetention"])?;
    let [mode, days, years] = retention?.fields(["Mode", "Days", "Years"])?;
    if mode?.leaf()? != "COMPLIANCE" {
        return None;
    }
    match (days, years) {
        (Some(days), None) => count(days.leaf()?),
        (None, Some(years)) => count(years.leaf()?)?.checked_mul(365),
        _ => None,
    }
}

/// `GetObjectRetention`: the COMPLIANCE retain-until time in Unix seconds.
pub(crate) fn compliance_until(root: &Element) -> Option<i64> {
    if root.name != "Retention" {
        return None;
    }
    let [mode, until] = root.fields(["Mode", "RetainUntilDate"])?;
    if mode?.leaf()? != "COMPLIANCE" {
        return None;
    }
    timestamp(until?.leaf()?)
}

/// One `ListObjectsV2` page: index file IDs with their modification times.
#[derive(Debug, PartialEq)]
pub(crate) struct Page {
    pub(crate) entries: Vec<(String, i64)>,
    pub(crate) truncated: bool,
}

/// Elements of one `Contents` entry that the check ignores.
const IGNORED_CONTENT: [&str; 6] = [
    "ETag",
    "Size",
    "StorageClass",
    "Owner",
    "ChecksumAlgorithm",
    "ChecksumType",
];

/// A listing page of `prefix` in `bucket`, requested after `start_after`.
/// Every key must be `prefix` plus a full lowercase ID, in strictly rising
/// order after `start_after`. A truncated page must make progress.
pub(crate) fn list_page(
    root: &Element,
    bucket: &str,
    prefix: &str,
    start_after: Option<&str>,
) -> Option<Page> {
    if root.name != "ListBucketResult" {
        return None;
    }
    let mut singles: [Option<&str>; 6] = [None; 6];
    let names = [
        "Name",
        "Prefix",
        "KeyCount",
        "MaxKeys",
        "IsTruncated",
        "StartAfter",
    ];
    let mut entries = Vec::new();
    let mut last = start_after.map(str::to_owned);
    for child in &root.children {
        if child.name == "Contents" {
            let (key, modified) = content(child)?;
            let id = key.strip_prefix(prefix).filter(|id| full_id(id))?;
            if last.as_deref().is_some_and(|last| key.as_str() <= last) {
                return None;
            }
            entries.push((id.to_owned(), modified));
            last = Some(key);
            continue;
        }
        // `NextContinuationToken` is ignored: paging uses `start-after`.
        if child.name == "NextContinuationToken" {
            child.leaf()?;
            continue;
        }
        let index = names.iter().position(|name| *name == child.name)?;
        if singles[index].replace(child.leaf()?).is_some() {
            return None;
        }
    }
    let [name, listed, key_count, max_keys, truncated, after] = singles;
    let truncated = match truncated? {
        "true" => true,
        "false" => false,
        _ => return None,
    };
    let sent = start_after.unwrap_or("");
    if name? != bucket
        || listed? != prefix
        || max_keys? != LIST_MAX_KEYS.to_string()
        || key_count? != entries.len().to_string()
        || entries.len() > LIST_MAX_KEYS
        || after.is_some_and(|after| after != sent)
        || (truncated && entries.is_empty())
    {
        return None;
    }
    Some(Page { entries, truncated })
}

fn content(entry: &Element) -> Option<(String, i64)> {
    let (mut key, mut modified) = (None, None);
    for child in &entry.children {
        match child.name.as_str() {
            "Key" if key.is_none() => key = Some(child.leaf()?.to_owned()),
            "LastModified" if modified.is_none() => modified = Some(timestamp(child.leaf()?)?),
            name if IGNORED_CONTENT.contains(&name) => {}
            _ => return None,
        }
    }
    Some((key?, modified?))
}

/// A full restic ID: 64 lowercase hexadecimal characters.
pub(crate) fn full_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Unix seconds of an RFC 3339 time with `Z` or a numeric offset and an
/// optional fraction of up to nine digits (dropped). Years 1970 to 9999.
pub(crate) fn timestamp(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if !text.is_ascii()
        || bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
    {
        return None;
    }
    if bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    let number = |range| number_in(text, range);
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    let mut rest = &text[19..];
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits = fraction
            .bytes()
            .position(|byte| !byte.is_ascii_digit())
            .unwrap_or(fraction.len());
        if !(1..=9).contains(&digits) {
            return None;
        }
        rest = &fraction[digits..];
    }
    let offset = match rest {
        "Z" => 0,
        _ if rest.len() == 6 && rest.as_bytes()[3] == b':' => {
            let sign = match rest.as_bytes()[0] {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let (hours, minutes) = (number_in(rest, 1..3)?, number_in(rest, 4..6)?);
            if hours > 23 || minutes > 59 {
                return None;
            }
            sign * (hours * 3600 + minutes * 60)
        }
        _ => return None,
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day < 1
        || day > month_days[usize::try_from(month - 1).ok()?]
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    // Days from civil (Howard Hinnant).
    let shifted = if month <= 2 { year - 1 } else { year };
    let era = shifted.div_euclid(400);
    let year_of_era = shifted - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Some(days * DAY_SECS + hour * 3600 + minute * 60 + second - offset)
}

fn number_in(text: &str, range: std::ops::Range<usize>) -> Option<i64> {
    let part = text.get(range)?;
    part.bytes()
        .all(|byte| byte.is_ascii_digit())
        .then(|| part.parse().ok())
        .flatten()
}

/// The bucket default passes: versioning enabled and a default COMPLIANCE
/// retention of at least `enrolled` days (and never under the lab floor).
pub(crate) fn bucket_passes(versioning: &Element, lock: &Element, enrolled: u16) -> bool {
    versioning_enabled(versioning)
        && default_retention_days(lock)
            .is_some_and(|days| days >= u64::from(enrolled) && days >= super::lock::MIN_DAYS)
}

/// The one snapshot `restic snapshots --json --tag` listed: its full ID and
/// its start, the earlier of `time` and `summary.backup_start` (restic
/// v0.19.1 `data.Snapshot`). Both must be present. Anything other than
/// exactly one snapshot refuses.
pub(crate) fn tagged_snapshot(listing: &[u8]) -> Option<(String, i64)> {
    let items: Vec<serde_json::Value> = serde_json::from_slice(listing).ok()?;
    let [item] = items.as_slice() else {
        return None;
    };
    let id = item.get("id")?.as_str()?;
    let time = timestamp(item.get("time")?.as_str()?)?;
    let start = timestamp(item.get("summary")?.get("backup_start")?.as_str()?)?;
    full_id(id).then(|| (id.to_owned(), time.min(start)))
}

/// New index keys in two complete listings around one backup. A removal
/// contradicts the append-only capture profile. New packs must have an
/// index, and the object budget must leave room for the snapshot.
pub(crate) fn written_index_ids(
    before: &BTreeSet<String>,
    after: &BTreeSet<String>,
    wrote_packs: bool,
) -> Option<Vec<String>> {
    if !before.is_subset(after) {
        return None;
    }
    let count = after.len() - before.len();
    if wrote_packs != (count > 0) || count >= MAX_OBJECTS {
        return None;
    }
    Some(after.difference(before).cloned().collect())
}

/// The decrypted JSON of one restic index file (`restic cat index`).
/// Restic v0.19.1 `jsonIndex` writes only `packs`; older repositories may
/// still hold `supersedes`, which the check ignores.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexFile {
    #[serde(default)]
    #[serde(rename = "supersedes")]
    _supersedes: Option<Vec<String>>,
    packs: Vec<IndexPack>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexPack {
    id: String,
    #[serde(rename = "blobs")]
    _blobs: Vec<serde::de::IgnoredAny>,
}

/// Adds the pack IDs of one index file to `packs`. Refuses a malformed
/// file or a pack ID that is not a full ID.
pub(crate) fn index_packs(json: &[u8], packs: &mut BTreeSet<String>) -> Option<()> {
    let index: IndexFile = serde_json::from_slice(json).ok()?;
    for pack in index.packs {
        if !full_id(&pack.id) {
            return None;
        }
        packs.insert(pack.id);
    }
    Some(())
}

/// One object a capture wrote (W391): its kind word, restic ID and key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WrittenObject {
    /// `snapshot`, `index` or `pack`.
    pub(crate) kind: &'static str,
    /// The restic object ID (64 lowercase hex).
    pub(crate) id: String,
    /// The object's key in the bucket.
    pub(crate) key: String,
}

/// The objects a capture wrote: its snapshot file, the new index files, and
/// the packs those index files list. `None` above [`MAX_OBJECTS`].
pub(crate) fn written_objects(
    prefix: &str,
    snapshot: &str,
    indexes: &[String],
    packs: &BTreeSet<String>,
) -> Option<Vec<WrittenObject>> {
    let object = |kind, id: &str, key| WrittenObject {
        kind,
        id: id.to_owned(),
        key,
    };
    let mut objects = vec![object(
        "snapshot",
        snapshot,
        format!("{prefix}/snapshots/{snapshot}"),
    )];
    objects.extend(
        indexes
            .iter()
            .map(|id| object("index", id, format!("{prefix}/index/{id}"))),
    );
    objects.extend(
        packs
            .iter()
            .map(|id| object("pack", id, format!("{prefix}/data/{}/{id}", &id[..2]))),
    );
    (objects.len() <= MAX_OBJECTS).then_some(objects)
}

/// W391: a store version ID the reader accepts: 1 to 128 of `A-Z`, `a-z`,
/// `0-9`, `.`, `_` and `-`, never `null` (an object written while
/// versioning was off).
pub(crate) fn version_ok(version: &str) -> bool {
    (1..=128).contains(&version.len())
        && version != "null"
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

/// W391: what one HEAD read returned for the current version of a key.
#[derive(Debug, PartialEq)]
pub(crate) struct HeadRead {
    /// The version ID.
    pub(crate) version: String,
    /// The COMPLIANCE retain-until time, Unix seconds.
    pub(crate) until: i64,
}

/// W391: the write-out lines of one HEAD batch, one per URL in order. Each
/// must be HTTP 200 with a version ID, COMPLIANCE and an RFC 3339 time.
pub(crate) fn head_batch(output: &[u8], count: usize) -> Option<Vec<HeadRead>> {
    if output.len() > MAX_CURL_OUTPUT {
        return None;
    }
    let text = std::str::from_utf8(output).ok()?.strip_suffix('\n')?;
    let reads = text
        .split('\n')
        .map(
            |line| match line.split(' ').collect::<Vec<_>>().as_slice() {
                ["200", version, "COMPLIANCE", until] if version_ok(version) => Some(HeadRead {
                    version: (*version).to_owned(),
                    until: timestamp(until)?,
                }),
                _ => None,
            },
        )
        .collect::<Option<Vec<_>>>()?;
    (reads.len() == count).then_some(reads)
}

/// W391: the `lock` worker's bucket line: the default the check passed.
pub(crate) fn bucket_line(days: u64) -> String {
    format!("bucket Enabled COMPLIANCE {days}\n")
}

/// W391: the `lock` worker's line for one object version it read back.
pub(crate) fn object_line(kind: &str, id: &str, version: &str, until: i64) -> String {
    format!("object {kind} {id} {version} COMPLIANCE {until}\n")
}

/// An object's retain-until time covers the enrolled retention from the
/// snapshot start, less the clock bound.
pub(crate) fn retention_covers(until: i64, started: i64, enrolled: u16) -> bool {
    until >= started + i64::from(enrolled) * DAY_SECS - SKEW_SECS
}

#[cfg(test)]
mod tests {
    use super::*;

    const NS: &str = r#" xmlns="http://s3.amazonaws.com/doc/2006-03-01/""#;
    const DECL: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";

    fn doc(body: &str) -> Element {
        parse(body.as_bytes()).unwrap_or_else(|| panic!("{body}"))
    }

    fn versioning(status: &str) -> String {
        format!(
            "{DECL}<VersioningConfiguration{NS}><Status>{status}</Status></VersioningConfiguration>"
        )
    }

    fn lock(mode: &str, period: &str) -> String {
        format!(
            "{DECL}<ObjectLockConfiguration{NS}><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>{mode}</Mode>{period}</DefaultRetention></Rule></ObjectLockConfiguration>"
        )
    }

    #[test]
    fn the_argv_carries_no_secret_and_reads_the_config_first() {
        let args = curl_arguments("/proc/self/fd/7", "/proc/self/fd/5", "lab-east-2").unwrap();
        assert_eq!(&args[..3], ["-q", "-K", "/proc/self/fd/7"]);
        for pair in [
            ["--cacert", "/proc/self/fd/5"],
            ["--aws-sigv4", "aws:amz:lab-east-2:s3"],
            ["--proto", "=https"],
            ["--max-redirs", "0"],
            ["--max-time", "15"],
        ] {
            assert!(args.windows(2).any(|w| w == pair), "{pair:?}");
        }
        let config = curl_config(
            "SYNTHETIC_W334",
            "synthetic+secret/=",
            &["https://198.51.100.23/b?versioning".to_owned()],
        )
        .unwrap();
        assert_eq!(
            config,
            "user = \"SYNTHETIC_W334:synthetic+secret/=\"\nurl = \"https://198.51.100.23/b?versioning\"\n"
        );
        for arg in &args {
            assert!(!arg.contains("SYNTHETIC_W334") && !arg.contains("synthetic+secret"));
            assert!(!arg.starts_with("http"), "no URL in argv: {arg}");
        }
        assert!(
            !args
                .iter()
                .any(|arg| arg == "-u" || arg == "--user" || arg == "-H")
        );
        for region in ["", "US-EAST-1", "a b", "x\"y", "r:1"] {
            assert_eq!(curl_arguments("c", "a", region), None, "{region}");
        }
    }

    #[test]
    fn the_config_refuses_values_that_escape_quoting() {
        let url = ["https://198.51.100.23/b?versioning".to_owned()];
        assert_eq!(curl_config("A\"", "S", &url), None);
        assert_eq!(curl_config("A", "S\\", &url), None);
        assert_eq!(curl_config("A", "S\nurl = x", &url), None);
        assert_eq!(curl_config("A:B", "S", &url), None);
        assert_eq!(curl_config("", "S", &url), None);
        assert_eq!(curl_config("A", "S", &[]), None);
        for bad in [
            "http://198.51.100.23/b",
            "https://198.51.100.23/b\"",
            "https://198.51.100.23/b c",
            "https://198.51.100.23/b\n",
            "file:///etc/passwd",
        ] {
            assert_eq!(curl_config("A", "S", &[bad.to_owned()]), None, "{bad}");
        }
    }

    #[test]
    fn urls_are_path_style_on_the_enrolled_endpoint() {
        let bucket = Bucket {
            endpoint: "198.51.100.23:443".parse().unwrap(),
            name: "rustiron-store",
        };
        assert_eq!(
            bucket.versioning(),
            "https://198.51.100.23/rustiron-store?versioning"
        );
        assert_eq!(
            bucket.object_lock(),
            "https://198.51.100.23/rustiron-store?object-lock"
        );
        assert_eq!(
            bucket.object("sites/rs_a/snapshots/ab"),
            "https://198.51.100.23/rustiron-store/sites/rs_a/snapshots/ab"
        );
        assert_eq!(
            bucket.list("sites/rs_a/index/", Some("sites/rs_a/index/00")),
            "https://198.51.100.23/rustiron-store?list-type=2&max-keys=1000&prefix=sites%2Frs_a%2Findex%2F&start-after=sites%2Frs_a%2Findex%2F00"
        );
        let other = Bucket {
            endpoint: "198.51.100.23:8443".parse().unwrap(),
            name: "b",
        };
        assert_eq!(
            other.versioning(),
            "https://198.51.100.23:8443/b?versioning"
        );
        assert!(url_ok(&bucket.list("sites/rs_a/index/", None)));
    }

    #[test]
    fn versioning_passes_only_enabled() {
        assert!(versioning_enabled(&doc(&versioning("Enabled"))));
        assert!(versioning_enabled(&doc(
            "<VersioningConfiguration><Status>Enabled</Status><MfaDelete>Disabled</MfaDelete></VersioningConfiguration>"
        )));
        assert!(!versioning_enabled(&doc(&versioning("Suspended"))));
        assert!(!versioning_enabled(&doc(&versioning(" Enabled"))));
        assert!(!versioning_enabled(&doc(&format!(
            "<VersioningConfiguration{NS}/>"
        ))));
        assert!(!versioning_enabled(&doc(&format!(
            "<VersioningConfiguration{NS}><Status>Enabled</Status><ExcludeFolders>true</ExcludeFolders></VersioningConfiguration>"
        ))));
        assert!(!versioning_enabled(&doc(&format!(
            "<VersioningConfiguration{NS}><Status>Enabled</Status><Status>Enabled</Status></VersioningConfiguration>"
        ))));
        assert!(!versioning_enabled(&doc(
            "<Error><Code>AccessDenied</Code></Error>"
        )));
    }

    #[test]
    fn only_a_long_enough_compliance_default_passes() {
        let ok = lock("COMPLIANCE", "<Days>30</Days>");
        assert_eq!(default_retention_days(&doc(&ok)), Some(30));
        assert_eq!(
            default_retention_days(&doc(&lock("COMPLIANCE", "<Years>1</Years>"))),
            Some(365)
        );
        for bad in [
            lock("GOVERNANCE", "<Days>30</Days>"),
            lock("COMPLIANCE", "<Days>30</Days><Years>1</Years>"),
            lock("COMPLIANCE", ""),
            lock("COMPLIANCE", "<Days>0</Days>"),
            lock("COMPLIANCE", "<Days>-3</Days>"),
            lock("COMPLIANCE", "<Days>1234567</Days>"),
            lock("COMPLIANCE", "<Days>30</Days><Extra/>"),
            ok.replace("<ObjectLockEnabled>Enabled", "<ObjectLockEnabled>Disabled"),
            // W226: root cleared the default rule.
            format!(
                "<ObjectLockConfiguration{NS}><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>"
            ),
        ] {
            assert_eq!(default_retention_days(&doc(&bad)), None, "{bad}");
        }
        let versioned = doc(&versioning("Enabled"));
        assert!(bucket_passes(&versioned, &doc(&ok), 30));
        assert!(
            !bucket_passes(&versioned, &doc(&ok), 31),
            "short of the enrolled retention"
        );
        assert!(bucket_passes(
            &versioned,
            &doc(&lock("COMPLIANCE", "<Days>90</Days>")),
            31
        ));
        assert!(
            !bucket_passes(&versioned, &doc(&lock("COMPLIANCE", "<Days>29</Days>")), 1),
            "never under the floor"
        );
        assert!(!bucket_passes(
            &doc(&versioning("Suspended")),
            &doc(&ok),
            30
        ));
    }

    #[test]
    fn the_reader_refuses_unknown_and_garbled_shapes() {
        for bad in [
            "",
            "<",
            "Enabled",
            "<A>",
            "<A></B>",
            "<A>x</A><A>y</A>",
            "<A>x<B>y</B></A>",
            "<A><!-- c --></A>",
            "<A><![CDATA[x]]></A>",
            "<!DOCTYPE A [<!ENTITY e \"x\">]><A>&e;</A>",
            "<A>&e;</A>",
            "<A>&#65;</A>",
            "<A>a > b</A>",
            "<A b=\"c\"/>",
            "<A xmlns=\"urn:other\"/>",
            "<A><B xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/></A>",
            "<A>\u{1}</A>",
            "\u{feff}<A/>",
            "<?xml version=\"1.0\"?><?pi x?><A/>",
        ] {
            assert_eq!(parse(bad.as_bytes()), None, "{bad:?}");
        }
        assert_eq!(parse(b"<A>\xff</A>"), None);
        let deep = "<A>".repeat(MAX_DEPTH + 2) + &"</A>".repeat(MAX_DEPTH + 2);
        assert_eq!(parse(deep.as_bytes()), None);
        let wide = format!("<A>{}</A>", "<B/>".repeat(MAX_ELEMENTS));
        assert_eq!(parse(wide.as_bytes()), None);
        assert_eq!(doc("<A>a &amp; b</A>").text, "a & b");
        assert_eq!(doc("<A>\n <B/>\n</A >").children.len(), 1);
    }

    /// W342: Go's `encoding/xml`, which MinIO uses for its responses,
    /// writes `"` and `'` in text as `&#34;` and `&#39;`. Every MinIO
    /// listing entry has a quoted `ETag`, so a reader that refuses these two
    /// references refuses every non-empty MinIO listing page.
    #[test]
    fn the_reader_reads_the_two_go_quote_references() {
        assert_eq!(doc("<A>&#34;x&#39;</A>").text, "\"x'");
        for bad in [
            "<A>&#65;</A>",
            "<A>&#x22;</A>",
            "<A>&#034;</A>",
            "<A>&#34</A>",
            "<A>&#9;</A>",
        ] {
            assert_eq!(parse(bad.as_bytes()), None, "{bad:?}");
        }
        let prefix = "sites/rs_a/index/";
        let key = format!("{prefix}{}", "a".repeat(64));
        let minio =
            listing(&[(&key, "2026-11-12T15:00:00.000Z")], false, None).replace("&quot;", "&#34;");
        assert!(minio.contains("<ETag>&#34;x&#34;</ETag>"));
        assert!(list_page(&doc(&minio), "b", prefix, None).is_some());
    }

    /// W345: a `ListObjectsV2` page byte for byte as the W344 MinIO lab
    /// store returned it to the lock worker's request.
    #[test]
    fn a_captured_minio_listing_page_parses() {
        let body = concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
            "<Name>rustiron-lab-tls</Name><Prefix>sites/rs_w344a/index/</Prefix>",
            "<KeyCount>1</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>",
            "<Contents><Key>sites/rs_w344a/index/",
            "24e83336839225431db3958a81cac9468a0da28d4869a5fa2bcbde8d07a22cf4</Key>",
            "<LastModified>2026-11-12T19:47:47.407Z</LastModified>",
            "<ETag>&#34;4721e08151531c55a5ef8da5376d748e&#34;</ETag><Size>507</Size>",
            "<StorageClass>STANDARD</StorageClass></Contents></ListBucketResult>",
        );
        let page = list_page(
            &doc(body),
            "rustiron-lab-tls",
            "sites/rs_w344a/index/",
            None,
        )
        .unwrap();
        assert_eq!(
            page.entries,
            [(
                "24e83336839225431db3958a81cac9468a0da28d4869a5fa2bcbde8d07a22cf4".to_owned(),
                1_794_512_867
            )]
        );
        assert!(!page.truncated);
    }

    #[test]
    fn a_batch_needs_every_document_and_a_200_marker_each() {
        let one = versioning("Enabled");
        let two = lock("COMPLIANCE", "<Days>30</Days>");
        let output = format!("{one}\n200\n{two}\n200\n");
        let documents = batch(output.as_bytes(), 2).unwrap();
        assert!(versioning_enabled(&documents[0]));
        assert_eq!(default_retention_days(&documents[1]), Some(30));
        for bad in [
            format!("{one}\n200\n"),
            format!("{one}\n200\n{two}\n403\n"),
            format!("{one}\n200\n\n403\n"),
            format!("{one}\n200\n{two}\n200\nextra"),
            format!("{one}200\n{two}\n200\n{two}\n200\n"),
            format!("{one}\n301\n{two}\n200\n"),
        ] {
            assert_eq!(batch(bad.as_bytes(), 2), None, "{bad:?}");
        }
        let oversized = vec![b' '; MAX_CURL_OUTPUT + 1];
        assert_eq!(batch(&oversized, 0), None);
    }

    #[test]
    fn timestamps_follow_rfc_3339() {
        assert_eq!(timestamp("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(timestamp("2026-11-12T15:00:00.000Z"), Some(1_794_495_600));
        assert_eq!(
            timestamp("2026-11-12T10:00:00.123456789-05:00"),
            Some(1_794_495_600)
        );
        assert_eq!(timestamp("2024-02-29T00:00:00+00:00"), Some(1_709_164_800));
        for bad in [
            "2026-11-12 15:00:00Z",
            "2026-11-12T15:00:00",
            "2026-13-12T15:00:00Z",
            "2026-02-29T15:00:00Z",
            "2026-11-12T24:00:00Z",
            "2026-11-12T15:00:00.Z",
            "2026-11-12T15:00:00.1234567890Z",
            "2026-11-12T15:00:00+0500",
            "1969-12-31T23:59:59Z",
            "+026-11-12T15:00:00Z",
            "2026-11-12T15:00:00Zjunk",
        ] {
            assert_eq!(timestamp(bad), None, "{bad}");
        }
    }

    #[test]
    fn retention_must_be_compliance_and_cover_the_enrolled_days() {
        let started = timestamp("2026-11-12T15:00:00Z").unwrap();
        let retention = |mode: &str, until: &str| {
            doc(&format!(
                "<Retention{NS}><Mode>{mode}</Mode><RetainUntilDate>{until}</RetainUntilDate></Retention>"
            ))
        };
        let until = compliance_until(&retention("COMPLIANCE", "2026-12-12T15:01:00.000Z")).unwrap();
        assert!(retention_covers(until, started, 30));
        assert!(!retention_covers(until, started, 31));
        // Within the SigV4 clock bound.
        let early = compliance_until(&retention("COMPLIANCE", "2026-12-12T14:46:00Z")).unwrap();
        assert!(retention_covers(early, started, 30));
        let short = compliance_until(&retention("COMPLIANCE", "2026-12-12T14:44:59Z")).unwrap();
        assert!(!retention_covers(short, started, 30));
        assert_eq!(
            compliance_until(&retention("GOVERNANCE", "2027-12-12T00:00:00Z")),
            None
        );
        assert_eq!(compliance_until(&retention("COMPLIANCE", "never")), None);
        assert_eq!(
            compliance_until(&doc(&format!(
                "<Retention{NS}><Mode>COMPLIANCE</Mode></Retention>"
            ))),
            None,
            "missing date"
        );
        assert_eq!(
            compliance_until(&doc(&format!(
                "<Retention{NS}><RetainUntilDate>2027-01-01T00:00:00Z</RetainUntilDate></Retention>"
            ))),
            None,
            "missing mode"
        );
        assert_eq!(
            compliance_until(&doc(
                "<Error><Code>NoSuchObjectLockConfiguration</Code></Error>"
            )),
            None
        );
    }

    fn listing(entries: &[(&str, &str)], truncated: bool, after: Option<&str>) -> String {
        let contents: String = entries
            .iter()
            .map(|(key, modified)| {
                format!(
                    "<Contents><Key>{key}</Key><LastModified>{modified}</LastModified><ETag>&quot;x&quot;</ETag><Size>10</Size><Owner><ID>o</ID><DisplayName>o</DisplayName></Owner><StorageClass>STANDARD</StorageClass></Contents>"
                )
            })
            .collect();
        let after = after
            .map(|a| format!("<StartAfter>{a}</StartAfter>"))
            .unwrap_or_default();
        format!(
            "{DECL}<ListBucketResult{NS}><Name>b</Name><Prefix>sites/rs_a/index/</Prefix>{after}<KeyCount>{}</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>{truncated}</IsTruncated>{contents}</ListBucketResult>",
            entries.len()
        )
    }

    #[test]
    fn listing_pages_hold_only_index_ids_in_order() {
        let prefix = "sites/rs_a/index/";
        let a = format!("{prefix}{}", "a".repeat(64));
        let b = format!("{prefix}{}", "b".repeat(64));
        let page = list_page(
            &doc(&listing(
                &[(&a, "2026-11-12T15:00:00Z"), (&b, "2026-11-12T16:00:00.5Z")],
                false,
                None,
            )),
            "b",
            prefix,
            None,
        )
        .unwrap();
        assert_eq!(
            page,
            Page {
                entries: vec![
                    ("a".repeat(64), 1_794_495_600),
                    ("b".repeat(64), 1_794_499_200)
                ],
                truncated: false
            }
        );
        let next = list_page(
            &doc(&listing(&[(&b, "2026-11-12T16:00:00Z")], true, Some(&a))),
            "b",
            prefix,
            Some(&a),
        );
        assert!(next.is_some_and(|page| page.truncated));
        let other = format!("sites/rs_b/index/{}", "c".repeat(64));
        let short = format!("{prefix}{}", "c".repeat(63));
        for (body, after) in [
            (
                listing(
                    &[(&b, "2026-11-12T15:00:00Z"), (&a, "2026-11-12T15:00:00Z")],
                    false,
                    None,
                ),
                None,
            ),
            (
                listing(&[(&a, "2026-11-12T15:00:00Z")], false, None),
                Some(a.as_str()),
            ),
            (
                listing(&[(&other, "2026-11-12T15:00:00Z")], false, None),
                None,
            ),
            (
                listing(&[(&short, "2026-11-12T15:00:00Z")], false, None),
                None,
            ),
            (listing(&[(&a, "yesterday")], false, None), None),
            (listing(&[], true, None), None),
            (
                listing(&[(&a, "2026-11-12T15:00:00Z")], false, None)
                    .replace("<KeyCount>1", "<KeyCount>2"),
                None,
            ),
            (
                listing(&[], false, None).replace("<Name>b", "<Name>c"),
                None,
            ),
            (
                listing(&[], false, None).replace("<MaxKeys>1000", "<MaxKeys>5"),
                None,
            ),
            (
                listing(&[], false, None).replace(
                    "</ListBucketResult>",
                    "<CommonPrefixes><Prefix>p</Prefix></CommonPrefixes></ListBucketResult>",
                ),
                None,
            ),
            (
                listing(&[(&a, "2026-11-12T15:00:00Z")], false, None)
                    .replace("<Size>", "<UserMetadata/><Size>"),
                None,
            ),
            (
                listing(&[], false, None).replace("<IsTruncated>false", "<IsTruncated>no"),
                None,
            ),
        ] {
            assert_eq!(list_page(&doc(&body), "b", prefix, after), None, "{body}");
        }
    }

    #[test]
    fn a_recent_index_already_present_before_capture_is_not_a_write() {
        let old = "1".repeat(64);
        let new = "2".repeat(64);
        let before = BTreeSet::from([old.clone()]);
        let after = BTreeSet::from([old, new.clone()]);
        assert_eq!(written_index_ids(&before, &after, true), Some(vec![new]));
        assert_eq!(written_index_ids(&before, &before, false), Some(vec![]));
        assert_eq!(written_index_ids(&before, &before, true), None);
        assert_eq!(written_index_ids(&before, &after, false), None);
        assert_eq!(written_index_ids(&after, &before, true), None);
    }

    #[test]
    fn the_capture_wrote_its_snapshot_new_indexes_and_their_packs() {
        let snapshot = "d".repeat(64);
        let listing = format!(
            r#"[{{"id":"{snapshot}","short_id":"dddddddd","time":"2026-11-12T10:00:00.5-05:00","tree":"{0}","paths":["/srv"],"tags":["rustiron-op-op_a"],"summary":{{"backup_start":"2026-11-12T15:00:01Z","backup_end":"2026-11-12T15:01:00Z"}}}}]"#,
            "e".repeat(64)
        );
        let (id, started) = tagged_snapshot(listing.as_bytes()).unwrap();
        assert_eq!((id.as_str(), started), (snapshot.as_str(), 1_794_495_600));
        let earlier = listing.replace("15:00:01Z", "14:59:00Z");
        assert_eq!(
            tagged_snapshot(earlier.as_bytes()).map(|(_, start)| start),
            Some(1_794_495_540),
            "the earlier of time and backup_start"
        );
        assert_eq!(tagged_snapshot(b"[]"), None);
        assert_eq!(
            tagged_snapshot(format!("[{0},{0}]", &listing[1..listing.len() - 1]).as_bytes()),
            None
        );
        for bad in [
            listing.replace("\"time\"", "\"when\""),
            listing.replace("\"backup_start\"", "\"start\""),
            listing.replace("\"summary\"", "\"other\""),
            listing.replace(&snapshot, &"D".repeat(64)),
        ] {
            assert_eq!(tagged_snapshot(bad.as_bytes()), None, "{bad}");
        }

        let before = BTreeSet::from(["1".repeat(64)]);
        let after = BTreeSet::from(["1".repeat(64), "2".repeat(64), "3".repeat(64)]);
        let indexes = written_index_ids(&before, &after, true).unwrap();
        assert_eq!(indexes, ["2".repeat(64), "3".repeat(64)]);

        let mut packs = BTreeSet::new();
        let index = format!(
            r#"{{"supersedes":null,"packs":[{{"id":"{0}","blobs":[{{"id":"{1}","type":"data","offset":0,"length":10,"uncompressed_length":20}}]}},{{"id":"{2}","blobs":[]}}]}}"#,
            "a".repeat(64),
            "f".repeat(64),
            "b".repeat(64)
        );
        assert!(index_packs(index.as_bytes(), &mut packs).is_some());
        assert!(
            index_packs(
                format!(r#"{{"packs":[{{"id":"{}","blobs":[]}}]}}"#, "a".repeat(64)).as_bytes(),
                &mut packs
            )
            .is_some()
        );
        assert_eq!(packs.len(), 2, "a pack listed twice is read once");
        for bad in [
            r#"{"packs":[{"id":"short","blobs":[]}]}"#.to_owned(),
            r#"{"packs":[{"id":"x"}]}"#.to_owned(),
            r#"{"packs":[],"extra":1}"#.to_owned(),
            r#"[]"#.to_owned(),
        ] {
            assert_eq!(
                index_packs(bad.as_bytes(), &mut BTreeSet::new()),
                None,
                "{bad}"
            );
        }

        let objects = written_objects("sites/rs_a", &snapshot, &indexes, &packs).unwrap();
        let kinds: Vec<&str> = objects.iter().map(|object| object.kind).collect();
        assert_eq!(kinds, ["snapshot", "index", "index", "pack", "pack"]);
        assert_eq!(objects[3].id, "a".repeat(64));
        let keys: Vec<String> = objects.into_iter().map(|object| object.key).collect();
        assert_eq!(
            keys,
            [
                format!("sites/rs_a/snapshots/{snapshot}"),
                format!("sites/rs_a/index/{}", "2".repeat(64)),
                format!("sites/rs_a/index/{}", "3".repeat(64)),
                format!("sites/rs_a/data/aa/{}", "a".repeat(64)),
                format!("sites/rs_a/data/bb/{}", "b".repeat(64)),
            ]
        );
        let many: BTreeSet<String> = (0..MAX_OBJECTS).map(|n| format!("{n:064x}")).collect();
        assert_eq!(written_objects("sites/rs_a", &snapshot, &[], &many), None);
    }

    /// W391: the HEAD batch writes no body to stdout. Each transfer's output
    /// goes to `/dev/null`, and one write-out line carries the status and
    /// the three headers.
    #[test]
    fn the_head_batch_reads_three_headers_and_keeps_secrets_out_of_argv() {
        let args = curl_head_arguments("/proc/self/fd/7", "/proc/self/fd/5", "lab-east-2").unwrap();
        assert_eq!(&args[..3], ["-q", "-K", "/proc/self/fd/7"]);
        assert!(args.iter().any(|arg| arg == "--head"));
        assert!(args.windows(2).any(|w| w
            == [
                "--write-out",
                "%{response_code} %header{x-amz-version-id} %header{x-amz-object-lock-mode} %header{x-amz-object-lock-retain-until-date}\\n"
            ]));
        assert!(args.windows(2).any(|w| w == ["--proto", "=https"]));
        let urls = [
            "https://198.51.100.23/b/sites/rs_a/snapshots/ab".to_owned(),
            "https://198.51.100.23/b/sites/rs_a/index/cd".to_owned(),
        ];
        assert_eq!(
            curl_head_config("SYNTHETIC_W391", "synthetic+secret/=", &urls).unwrap(),
            "user = \"SYNTHETIC_W391:synthetic+secret/=\"\nurl = \"https://198.51.100.23/b/sites/rs_a/snapshots/ab\"\noutput = \"/dev/null\"\nurl = \"https://198.51.100.23/b/sites/rs_a/index/cd\"\noutput = \"/dev/null\"\n"
        );
        for arg in &args {
            assert!(!arg.contains("SYNTHETIC_W391") && !arg.starts_with("http"));
        }
        assert_eq!(curl_head_config("A\"", "S", &urls), None);
        assert_eq!(curl_head_config("A", "S", &[]), None);
        assert_eq!(curl_head_arguments("c", "a", "A B"), None);
    }

    /// W403 F1: curl checks `--max-filesize` against the Content-Length of a
    /// HEAD answer and exits 63 for an object over the limit, so a capture
    /// with a 16 MiB restic pack could never pass the lock read-back. The
    /// HEAD batch reads no body; only the GET batch keeps the size limit.
    #[test]
    fn the_head_batch_has_no_body_size_limit_and_the_get_batch_keeps_it() {
        let head = curl_head_arguments("/proc/self/fd/7", "/proc/self/fd/5", "us-east-1").unwrap();
        assert!(!head.iter().any(|arg| arg == "--max-filesize"));
        let get = curl_arguments("/proc/self/fd/7", "/proc/self/fd/5", "us-east-1").unwrap();
        assert!(get.windows(2).any(|w| w == ["--max-filesize", "1048576"]));
    }

    /// W391: one complete line per object, in order, each HTTP 200 with a
    /// version ID, COMPLIANCE and an RFC 3339 retain-until time.
    #[test]
    fn head_reads_need_one_complete_line_per_object() {
        let good = b"200 76b01aea-db7c-4b38-b41d-3c031085d108 COMPLIANCE 2026-12-13T17:42:56.054Z\n200 v2 COMPLIANCE 2026-12-13T17:42:57Z\n";
        let reads = head_batch(good, 2).unwrap();
        assert_eq!(reads[0].version, "76b01aea-db7c-4b38-b41d-3c031085d108");
        assert_eq!(reads[0].until, 1_797_183_776);
        assert_eq!(reads[1].version, "v2");
        assert_eq!(head_batch(good, 1), None, "count must match");
        assert_eq!(head_batch(good, 3), None, "count must match");
        for bad in [
            &b"404   \n"[..],
            b"200  COMPLIANCE 2026-12-13T17:42:56Z\n",
            b"200 null COMPLIANCE 2026-12-13T17:42:56Z\n",
            b"200 v1 GOVERNANCE 2026-12-13T17:42:56Z\n",
            b"200 v1 COMPLIANCE never\n",
            b"200 v1 COMPLIANCE 2026-12-13T17:42:56Z",
            b"200 v1 COMPLIANCE 2026-12-13T17:42:56Z extra\n",
            b"200 v+1 COMPLIANCE 2026-12-13T17:42:56Z\n",
            b"200  v1 COMPLIANCE 2026-12-13T17:42:56Z\n",
        ] {
            assert_eq!(head_batch(bad, 1), None, "{}", String::from_utf8_lossy(bad));
        }
        assert!(version_ok(&"v".repeat(128)));
        assert!(!version_ok(&"v".repeat(129)));
        assert!(!version_ok(""));
    }

    #[test]
    fn the_pinned_retention_url_names_the_version() {
        let bucket = Bucket {
            endpoint: "198.51.100.23:9443".parse().unwrap(),
            name: "b",
        };
        let url = bucket.retention_version(
            "sites/rs_a/snapshots/ab",
            "76b01aea-db7c-4b38-b41d-3c031085d108",
        );
        assert_eq!(
            url,
            "https://198.51.100.23:9443/b/sites/rs_a/snapshots/ab?retention&versionId=76b01aea-db7c-4b38-b41d-3c031085d108"
        );
        assert!(url_ok(&url));
    }

    /// W391: the closed lines the `lock` worker prints for the runner.
    #[test]
    fn lock_lines_are_closed() {
        assert_eq!(bucket_line(30), "bucket Enabled COMPLIANCE 30\n");
        assert_eq!(
            object_line("pack", &"a".repeat(64), "v2", 1_797_183_776),
            format!("object pack {} v2 COMPLIANCE 1797183776\n", "a".repeat(64))
        );
    }
}
