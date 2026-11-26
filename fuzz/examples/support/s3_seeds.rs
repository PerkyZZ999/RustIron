//! S3 response, `curl` batch, builder and time seeds (W342). The response
//! bodies follow the shapes AWS and MinIO document and write; they were
//! written for this corpus, not copied from another test corpus.

use rustiron_fuzz::{
    DECLARATION as DECL, LIST_BUCKET, LIST_PREFIX, MARKER, NAMESPACE, S3_RESPONSE_MAX_INPUT,
    list_after,
};

fn root(name: &str, body: &str) -> String {
    format!("{DECL}<{name} xmlns=\"{NAMESPACE}\">{body}</{name}>")
}

fn versioning(body: &str) -> String {
    root("VersioningConfiguration", body)
}

fn lock(rule: &str) -> String {
    root(
        "ObjectLockConfiguration",
        &format!("<ObjectLockEnabled>Enabled</ObjectLockEnabled>{rule}"),
    )
}

fn compliance(period: &str) -> String {
    lock(&format!(
        "<Rule><DefaultRetention><Mode>COMPLIANCE</Mode>{period}</DefaultRetention></Rule>"
    ))
}

fn retention(mode: &str, until: &str) -> String {
    root(
        "Retention",
        &format!("<Mode>{mode}</Mode><RetainUntilDate>{until}</RetainUntilDate>"),
    )
}

/// An AWS error document, as S3 returns it with a non-200 status.
fn error(code: &str) -> String {
    format!(
        "{DECL}<Error><Code>{code}</Code><Message>synthetic</Message><BucketName>{LIST_BUCKET}</BucketName><RequestId>0000000000000000</RequestId><HostId>synthetic</HostId></Error>"
    )
}

fn id(n: usize) -> String {
    format!("{n:064x}")
}

/// One AWS-style `Contents` entry.
fn aws_entry(id: &str, modified: &str) -> String {
    format!(
        "<Contents><Key>{LIST_PREFIX}{id}</Key><LastModified>{modified}</LastModified><ETag>&quot;0f343b0931126a20f133d67c2b018a3b&quot;</ETag><ChecksumAlgorithm>CRC64NVME</ChecksumAlgorithm><ChecksumType>FULL_OBJECT</ChecksumType><Size>1048</Size><StorageClass>STANDARD</StorageClass></Contents>"
    )
}

/// One MinIO-style entry: Go's `encoding/xml` writes the quoted `ETag` as
/// `&#34;`, and MinIO adds its `Owner`.
fn minio_entry(id: &str, modified: &str) -> String {
    format!(
        "<Contents><Key>{LIST_PREFIX}{id}</Key><LastModified>{modified}</LastModified><ETag>&#34;0f343b0931126a20f133d67c2b018a3b&#34;</ETag><Size>1048</Size><Owner><ID>02d6176db174dc93cb1b899f7c6078f08654445fe8cf1b6ce98d8855f66bdbf4</ID><DisplayName>minio</DisplayName></Owner><StorageClass>STANDARD</StorageClass></Contents>"
    )
}

fn compact_entry(id: &str) -> String {
    format!(
        "<Contents><Key>{LIST_PREFIX}{id}</Key><LastModified>2026-11-12T15:00:00Z</LastModified></Contents>"
    )
}

/// A listing page with `count` entries in `contents`.
fn page(count: usize, truncated: bool, after: Option<&str>, contents: &str) -> String {
    let after = after
        .map(|key| format!("<StartAfter>{key}</StartAfter>"))
        .unwrap_or_default();
    root(
        "ListBucketResult",
        &format!(
            "<Name>{LIST_BUCKET}</Name><Prefix>{LIST_PREFIX}</Prefix>{after}<KeyCount>{count}</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>{truncated}</IsTruncated>{contents}"
        ),
    )
}

pub(super) fn generate(seed: &mut impl FnMut(&str, &str, &[u8], bool)) {
    reader(seed);
    versioning_seeds(seed);
    lock_seeds(seed);
    retention_seeds(seed);
    list_seeds(seed);
    batch_seeds(seed);
    curl_seeds(seed);
    timestamp_seeds(seed);
}

/// Refusals of the shared reader, fed to each response target.
fn reader(seed: &mut impl FnMut(&str, &str, &[u8], bool)) {
    let enabled = versioning("<Status>Enabled</Status>");
    let deep = format!("{}{}", "<A>".repeat(8), "</A>".repeat(8));
    let wide = format!("<A>{}</A>", "<B/>".repeat(16 * 1024));
    let cases: [(&str, Vec<u8>); 22] = [
        ("empty", Vec::new()),
        ("text", b"Enabled".to_vec()),
        (
            "truncated",
            enabled.as_bytes()[..enabled.len() - 3].to_vec(),
        ),
        ("unclosed", b"<A>".to_vec()),
        ("mismatched", b"<A></B>".to_vec()),
        ("two-roots", b"<A>x</A><A>y</A>".to_vec()),
        ("mixed", b"<A>x<B>y</B></A>".to_vec()),
        ("comment", b"<A><!-- c --></A>".to_vec()),
        ("cdata", b"<A><![CDATA[x]]></A>".to_vec()),
        (
            "dtd",
            b"<!DOCTYPE A [<!ENTITY e \"x\">]><A>&e;</A>".to_vec(),
        ),
        ("unknown-entity", b"<A>&e;</A>".to_vec()),
        ("decimal-reference", b"<A>&#65;</A>".to_vec()),
        ("hex-reference", b"<A>&#x22;</A>".to_vec()),
        ("raw-gt", b"<A>a > b</A>".to_vec()),
        ("attribute", b"<A b=\"c\"/>".to_vec()),
        ("other-namespace", b"<A xmlns=\"urn:other\"/>".to_vec()),
        (
            "nested-namespace",
            format!("<A><B xmlns=\"{NAMESPACE}\"/></A>").into_bytes(),
        ),
        ("control", b"<A>\x01</A>".to_vec()),
        ("bom", "\u{feff}<A/>".as_bytes().to_vec()),
        (
            "processing-instruction",
            b"<?xml version=\"1.0\"?><?pi x?><A/>".to_vec(),
        ),
        ("deep", deep.into_bytes()),
        ("wide", wide.into_bytes()),
    ];
    for target in ["s3_versioning", "s3_object_lock", "s3_retention", "s3_list"] {
        for (name, bytes) in &cases {
            seed(target, name, bytes, false);
        }
        seed(target, "invalid-utf8", b"<A>\xff</A>", false);
    }
}

fn versioning_seeds(seed: &mut impl FnMut(&str, &str, &[u8], bool)) {
    let target = "s3_versioning";
    let enabled = versioning("<Status>Enabled</Status>");
    let pretty = format!(
        "{DECL}<VersioningConfiguration xmlns=\"{NAMESPACE}\">\n  <Status>Enabled</Status>\n</VersioningConfiguration>\n"
    );
    let mut exact = enabled.clone().into_bytes();
    exact.resize(S3_RESPONSE_MAX_INPUT, b' ');
    for (name, body) in [
        ("aws-enabled", enabled.clone().into_bytes()),
        (
            "aws-mfa-disabled",
            versioning("<Status>Enabled</Status><MfaDelete>Disabled</MfaDelete>").into_bytes(),
        ),
        ("pretty", pretty.into_bytes()),
        (
            "no-declaration",
            enabled.trim_start_matches(DECL).as_bytes().to_vec(),
        ),
        (
            "no-namespace",
            b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>".to_vec(),
        ),
        ("exact-cap", exact),
    ] {
        seed(target, name, &body, true);
    }
    for (name, body) in [
        ("suspended", versioning("<Status>Suspended</Status>")),
        (
            "never-enabled",
            format!("{DECL}<VersioningConfiguration xmlns=\"{NAMESPACE}\"/>"),
        ),
        (
            "minio-excluded-prefixes",
            versioning(
                "<Status>Enabled</Status><ExcludedPrefixes><Prefix>tmp/</Prefix></ExcludedPrefixes>",
            ),
        ),
        (
            "minio-exclude-folders",
            versioning("<Status>Enabled</Status><ExcludeFolders>true</ExcludeFolders>"),
        ),
        (
            "repeated-status",
            versioning("<Status>Enabled</Status><Status>Enabled</Status>"),
        ),
        ("padded-status", versioning("<Status> Enabled</Status>")),
        (
            "unknown-mfa",
            versioning("<Status>Enabled</Status><MfaDelete>Maybe</MfaDelete>"),
        ),
        ("access-denied", error("AccessDenied")),
        ("lock-body", compliance("<Days>30</Days>")),
    ] {
        seed(target, name, body.as_bytes(), false);
    }
    let mut over = enabled.into_bytes();
    over.resize(S3_RESPONSE_MAX_INPUT - 1, b' ');
    over.push(b'x');
    seed(target, "exact-cap-trailing-text", &over, false);
}

fn lock_seeds(seed: &mut impl FnMut(&str, &str, &[u8], bool)) {
    let target = "s3_object_lock";
    let pretty = format!(
        "{DECL}<ObjectLockConfiguration xmlns=\"{NAMESPACE}\">\n  <ObjectLockEnabled>Enabled</ObjectLockEnabled>\n  <Rule>\n    <DefaultRetention>\n      <Mode>COMPLIANCE</Mode>\n      <Days>30</Days>\n    </DefaultRetention>\n  </Rule>\n</ObjectLockConfiguration>\n"
    );
    for (name, body) in [
        ("aws-30-days", compliance("<Days>30</Days>")),
        ("pretty", pretty),
        ("ten-years-of-days", compliance("<Days>3650</Days>")),
        ("one-year", compliance("<Years>1</Years>")),
        ("largest-days", compliance("<Days>999999</Days>")),
        ("largest-years", compliance("<Years>999999</Years>")),
        ("under-floor", compliance("<Days>29</Days>")),
    ] {
        seed(target, name, body.as_bytes(), true);
    }
    let disabled = compliance("<Days>30</Days>")
        .replace("<ObjectLockEnabled>Enabled", "<ObjectLockEnabled>Disabled");
    for (name, body) in [
        (
            "governance",
            lock(
                "<Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>30</Days></DefaultRetention></Rule>",
            ),
        ),
        (
            "days-and-years",
            compliance("<Days>30</Days><Years>1</Years>"),
        ),
        ("no-period", compliance("")),
        ("zero-days", compliance("<Days>0</Days>")),
        ("negative-days", compliance("<Days>-3</Days>")),
        ("seven-digit-days", compliance("<Days>1234567</Days>")),
        ("extra-element", compliance("<Days>30</Days><Extra/>")),
        ("disabled", disabled),
        ("no-rule", lock("")),
        (
            "padded-mode",
            compliance("<Days>30</Days>").replace("<Mode>COMPLIANCE", "<Mode>COMPLIANCE "),
        ),
        ("not-found", error("ObjectLockConfigurationNotFoundError")),
        ("versioning-body", versioning("<Status>Enabled</Status>")),
    ] {
        seed(target, name, body.as_bytes(), false);
    }
}

fn retention_seeds(seed: &mut impl FnMut(&str, &str, &[u8], bool)) {
    let target = "s3_retention";
    for (name, until) in [
        ("aws-millis", "2026-12-12T15:01:00.000Z"),
        ("minio-seconds", "2026-12-12T15:01:00Z"),
        ("nanoseconds", "2026-12-12T15:01:00.123456789Z"),
        ("negative-offset", "2026-12-12T10:01:00-05:00"),
        ("epoch", "1970-01-01T00:00:00Z"),
        ("last-second", "9999-12-31T23:59:59Z"),
        ("before-epoch-by-offset", "1970-01-01T00:00:00+23:59"),
        ("after-9999-by-offset", "9999-12-31T23:59:59-23:59"),
    ] {
        seed(
            target,
            name,
            retention("COMPLIANCE", until).as_bytes(),
            true,
        );
    }
    for (name, body) in [
        (
            "governance",
            retention("GOVERNANCE", "2027-12-12T00:00:00Z"),
        ),
        ("never", retention("COMPLIANCE", "never")),
        (
            "leap-second",
            retention("COMPLIANCE", "2026-12-31T23:59:60Z"),
        ),
        (
            "not-a-leap-day",
            retention("COMPLIANCE", "2026-02-29T00:00:00Z"),
        ),
        (
            "lowercase-t",
            retention("COMPLIANCE", "2026-12-12t15:01:00Z"),
        ),
        ("missing-date", root("Retention", "<Mode>COMPLIANCE</Mode>")),
        (
            "missing-mode",
            root(
                "Retention",
                "<RetainUntilDate>2027-01-01T00:00:00Z</RetainUntilDate>",
            ),
        ),
        ("no-configuration", error("NoSuchObjectLockConfiguration")),
        ("lock-body", compliance("<Days>30</Days>")),
    ] {
        seed(target, name, body.as_bytes(), false);
    }
}

fn list_seeds(seed: &mut impl FnMut(&str, &str, &[u8], bool)) {
    let target = "s3_list";
    let after = list_after();
    let aws = format!(
        "{}{}",
        aws_entry(&id(1), "2026-11-12T15:00:00.000Z"),
        aws_entry(&id(2), "2026-11-12T16:00:00.000Z")
    );
    let minio = minio_entry(&"a".repeat(64), "2026-11-12T15:00:00.000Z");
    let full: String = (0..1000).map(|n| compact_entry(&id(n))).collect();
    let over: String = (0..1001).map(|n| compact_entry(&id(n))).collect();
    let owner = |children: usize, nested: &str| {
        format!(
            "<Contents><Key>{LIST_PREFIX}{}</Key><LastModified>2026-11-12T15:00:00Z</LastModified><Owner>{}{nested}</Owner></Contents>",
            id(1),
            "<a/>".repeat(children)
        )
    };
    let after_entries = format!(
        "{}{}",
        aws_entry(&"9".repeat(64), "2026-11-12T15:00:00Z"),
        aws_entry(&"a".repeat(64), "2026-11-12T15:00:00Z")
    );
    for (name, body) in [
        ("aws-two", page(2, false, None, &aws)),
        ("minio-one", page(1, false, None, &minio)),
        ("empty", page(0, false, None, "")),
        (
            "truncated-with-token",
            page(2, true, None, &aws).replace(
                "</ListBucketResult>",
                "<NextContinuationToken>1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM=</NextContinuationToken></ListBucketResult>",
            ),
        ),
        ("after-key", page(2, false, Some(&after), &after_entries)),
        ("full-page", page(1000, true, None, &full)),
        // Ten elements around the Owner; its 16,374 children reach 16,384.
        ("element-ceiling", page(1, false, None, &owner(16_374, ""))),
        (
            "depth-ceiling",
            page(1, false, None, &owner(0, "<b><c><d><e/></d></c></b>")),
        ),
    ] {
        seed(target, name, body.as_bytes(), true);
    }
    let other_site = format!(
        "<Contents><Key>sites/rs_other/index/{}</Key><LastModified>2026-11-12T15:00:00Z</LastModified></Contents>",
        id(1)
    );
    let one = compact_entry(&id(1));
    for (name, body) in [
        (
            "unordered",
            page(2, false, None, &format!("{}{}", compact_entry(&id(2)), one)),
        ),
        ("repeated-key", page(2, false, None, &format!("{one}{one}"))),
        ("not-after-start", page(1, false, Some(&after), &one)),
        ("other-site", page(1, false, None, &other_site)),
        (
            "short-id",
            page(1, false, None, &compact_entry(&"c".repeat(63))),
        ),
        (
            "uppercase-id",
            page(1, false, None, &compact_entry(&"C".repeat(64))),
        ),
        (
            "bad-time",
            page(
                1,
                false,
                None,
                &one.replace("2026-11-12T15:00:00Z", "yesterday"),
            ),
        ),
        ("truncated-empty", page(0, true, None, "")),
        ("wrong-count", page(2, false, None, &one)),
        (
            "other-bucket",
            page(0, false, None, "")
                .replace(&format!("<Name>{LIST_BUCKET}<"), "<Name>rustiron-other<"),
        ),
        (
            "other-max-keys",
            page(0, false, None, "").replace("<MaxKeys>1000", "<MaxKeys>5"),
        ),
        (
            "common-prefixes",
            page(0, false, None, "").replace(
                "</ListBucketResult>",
                "<CommonPrefixes><Prefix>p</Prefix></CommonPrefixes></ListBucketResult>",
            ),
        ),
        (
            "delimiter",
            page(0, false, None, "").replace(
                "</ListBucketResult>",
                "<Delimiter>/</Delimiter></ListBucketResult>",
            ),
        ),
        (
            "user-metadata",
            page(
                1,
                false,
                None,
                &one.replace("<LastModified>", "<UserMetadata/><LastModified>"),
            ),
        ),
        (
            "bad-truncated",
            page(0, false, None, "").replace("<IsTruncated>false", "<IsTruncated>no"),
        ),
        (
            "repeated-name",
            page(0, false, None, "").replace(
                "</ListBucketResult>",
                &format!("<Name>{LIST_BUCKET}</Name></ListBucketResult>"),
            ),
        ),
        ("over-full-page", page(1001, true, None, &over)),
        (
            "over-element-ceiling",
            page(1, false, None, &owner(16_375, "")),
        ),
        (
            "over-depth-ceiling",
            page(
                1,
                false,
                None,
                &owner(0, "<b><c><d><e><f/></e></d></c></b>"),
            ),
        ),
        ("no-such-bucket", error("NoSuchBucket")),
    ] {
        seed(target, name, body.as_bytes(), false);
    }
}

fn batch_seeds(seed: &mut impl FnMut(&str, &str, &[u8], bool)) {
    let target = "s3_batch";
    let versioning = versioning("<Status>Enabled</Status>");
    let lock = compliance("<Days>30</Days>");
    let retention = retention("COMPLIANCE", "2026-12-12T15:01:00.000Z");
    let batch = |count: u8, bodies: &[&str], marker: &str| {
        let mut bytes = vec![count];
        for body in bodies {
            bytes.extend_from_slice(body.as_bytes());
            bytes.extend_from_slice(marker.as_bytes());
        }
        bytes
    };
    // One document, white space, then the marker: exactly the 1 MiB ceiling.
    let ceiling = 1024 * 1024;
    let mut exact = vec![1];
    exact.extend_from_slice(versioning.as_bytes());
    exact.resize(1 + ceiling - 4, b' ');
    exact.extend_from_slice(b"200\n");
    let mut over = vec![1];
    over.extend_from_slice(versioning.as_bytes());
    over.resize(1 + ceiling + 1 - 4, b' ');
    over.extend_from_slice(b"200\n");
    for (name, bytes) in [
        ("one", batch(1, &[&versioning], MARKER)),
        ("lock-pair", batch(2, &[&versioning, &lock], MARKER)),
        (
            "retention-three",
            batch(3, &[retention.as_str(); 3], MARKER),
        ),
        ("none", vec![0]),
        ("exact-ceiling", exact),
        // curl always prints a newline first; the reader also takes none.
        ("glued-marker", batch(1, &[&versioning], "200\n")),
    ] {
        seed(target, name, &bytes, true);
    }
    for (name, bytes) in [
        ("empty", Vec::new()),
        ("forbidden", batch(1, &[&versioning], "\n403\n")),
        ("redirect", batch(2, &[&versioning, &lock], "\n301\n")),
        ("no-marker", batch(1, &[&versioning], "")),
        ("short", batch(3, &[&versioning, &lock], MARKER)),
        ("long", batch(1, &[&versioning, &lock], MARKER)),
        ("none-with-output", batch(4, &[&versioning], MARKER)),
        (
            "trailing-text",
            [batch(1, &[&versioning], MARKER), b"extra".to_vec()].concat(),
        ),
        ("over-ceiling", over),
    ] {
        seed(target, name, &bytes, false);
    }
}

/// The builder fields, separated by 0xFF bytes (never UTF-8).
fn fields(parts: &[&str]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (at, part) in parts.iter().enumerate() {
        if at > 0 {
            bytes.push(0xff);
        }
        bytes.extend_from_slice(part.as_bytes());
    }
    bytes
}

fn curl_seeds(seed: &mut impl FnMut(&str, &str, &[u8], bool)) {
    let target = "s3_curl";
    let snapshot = format!("sites/rs_blog/snapshots/{}", "d".repeat(64));
    let after = list_after();
    let (access, secret) = ("SYNTHETIC_W342", "synthetic+secret/=");
    let lab = [
        access,
        secret,
        "lab-east-2",
        LIST_BUCKET,
        snapshot.as_str(),
        LIST_PREFIX,
        after.as_str(),
        "443",
    ];
    let with = |at: usize, value: &str| {
        let mut parts = lab.to_vec();
        parts[at] = value;
        fields(&parts)
    };
    let longest = format!("https://198.51.100.23/{}", "a".repeat(1024 - 22));
    let too_long = format!("{longest}a");
    let minio = fields(&[
        access,
        secret,
        "us-east-1",
        "backups",
        "sites/rs_blog/config",
        "sites/rs_blog/index/",
    ]);
    for (name, bytes) in [
        ("lab", fields(&lab)),
        ("minio-no-after", minio),
        ("port-9000", with(7, "9000")),
        ("encoded-prefix", with(5, "a b/\"\n&=?é")),
        (
            "extra-url",
            fields(&[&lab[..], &["https://198.51.100.23/b?versioning"]].concat()),
        ),
        (
            "longest-url",
            fields(&[&lab[..], &[longest.as_str()]].concat()),
        ),
    ] {
        seed(target, name, &bytes, true);
    }
    for (name, bytes) in [
        ("access-quote", with(0, "A\"")),
        ("access-backslash", with(0, "A\\")),
        ("access-newline", with(0, "A\nurl = x")),
        ("access-colon", with(0, "A:B")),
        ("access-space", with(0, "A B")),
        ("access-empty", with(0, "")),
        ("secret-quote", with(1, "S\"")),
        ("secret-backslash", with(1, "S\\")),
        (
            "secret-newline",
            with(1, "S\nurl = \"https://203.0.113.9/\""),
        ),
        ("region-uppercase", with(2, "US-EAST-1")),
        ("region-space", with(2, "a b")),
        ("region-quote", with(2, "x\"y")),
        ("region-colon", with(2, "r:1")),
        ("region-empty", with(2, "")),
        ("region-64", with(2, &"r".repeat(64))),
        ("bucket-quote", with(3, "b\"")),
        ("bucket-space", with(3, "b c")),
        ("key-newline", with(4, "k\nurl = x")),
        ("key-backslash", with(4, "k\\")),
        (
            "extra-http",
            fields(&[&lab[..], &["http://198.51.100.23/b"]].concat()),
        ),
        (
            "extra-file",
            fields(&[&lab[..], &["file:///etc/passwd"]].concat()),
        ),
        (
            "extra-quote",
            fields(&[&lab[..], &["https://198.51.100.23/b\""]].concat()),
        ),
        (
            "extra-newline",
            fields(&[&lab[..], &["https://198.51.100.23/b\n"]].concat()),
        ),
        (
            "extra-unicode",
            fields(&[&lab[..], &["https://198.51.100.23/é"]].concat()),
        ),
        (
            "extra-too-long",
            fields(&[&lab[..], &[too_long.as_str()]].concat()),
        ),
        ("empty", Vec::new()),
    ] {
        seed(target, name, &bytes, false);
    }
}

fn timestamp_seeds(seed: &mut impl FnMut(&str, &str, &[u8], bool)) {
    let target = "s3_timestamp";
    for (name, text) in [
        ("epoch", "1970-01-01T00:00:00Z"),
        ("millis", "2026-11-12T15:00:00.000Z"),
        ("nanoseconds-offset", "2026-11-12T10:00:00.123456789-05:00"),
        ("leap-day", "2024-02-29T00:00:00+00:00"),
        ("leap-century", "2000-02-29T12:00:00Z"),
        ("last-second", "9999-12-31T23:59:59Z"),
        ("longest", "9999-12-31T23:59:59.999999999+23:59"),
        ("before-epoch-by-offset", "1970-01-01T00:00:00+23:59"),
        ("after-9999-by-offset", "9999-12-31T23:59:59-23:59"),
    ] {
        seed(target, name, text.as_bytes(), true);
    }
    for (name, text) in [
        ("space", "2026-11-12 15:00:00Z"),
        ("no-zone", "2026-11-12T15:00:00"),
        ("month-13", "2026-13-12T15:00:00Z"),
        ("not-a-leap-day", "2026-02-29T15:00:00Z"),
        ("not-a-leap-century", "2100-02-29T00:00:00Z"),
        ("hour-24", "2026-11-12T24:00:00Z"),
        ("leap-second", "2026-12-31T23:59:60Z"),
        ("empty-fraction", "2026-11-12T15:00:00.Z"),
        ("ten-digit-fraction", "2026-11-12T15:00:00.1234567890Z"),
        ("compact-offset", "2026-11-12T15:00:00+0500"),
        ("offset-24", "2026-11-12T15:00:00+24:00"),
        ("before-1970", "1969-12-31T23:59:59Z"),
        ("signed-year", "+026-11-12T15:00:00Z"),
        ("trailing", "2026-11-12T15:00:00Zjunk"),
        ("lowercase-z", "2026-11-12T15:00:00z"),
        ("unicode-digit", "２026-11-12T15:00:00Z"),
        ("empty", ""),
    ] {
        seed(target, name, text.as_bytes(), false);
    }
    seed(target, "invalid-utf8", b"2026-11-12T15:00:00\xffZ", false);
}
