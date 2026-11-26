//! W228: the capture's retention-lock check. The worker (`capture-manifest
//! lock`) asks the store for the bucket's default object-lock configuration
//! with the site's own capture identity (`s3:GetBucketObjectLockConfiguration`
//! is in the per-site policy; no root key). The runner accepts only the one
//! closed pass line, so a capture fails closed when the default is not
//! COMPLIANCE for at least `MIN_DAYS`.
//!
//! Per-version retention dates are NOT checked: reading them needs
//! `s3:GetObjectRetention`, which the per-site policy does not grant.
use sha2::{Digest, Sha256};

/// The shortest default retention a capture accepts (D-010: 30 days).
pub(crate) const MIN_DAYS: u64 = 30;
const REGION: &str = "us-east-1";

fn plain(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_:".contains(&b))
}

/// Store endpoint (`host:port`) and bucket from `s3:http://host:port/bucket/...`.
pub(crate) fn endpoint(repository: &str) -> Option<(String, String)> {
    let rest = repository.strip_prefix("s3:http://")?;
    let (host, path) = rest.split_once('/')?;
    let bucket = path.split('/').next()?;
    (plain(host) && plain(bucket) && host.contains(':'))
        .then(|| (host.to_owned(), bucket.to_owned()))
}

/// Access key and secret from an AWS shared-credentials file's `[default]`.
pub(crate) fn credentials(text: &str) -> Option<(String, String)> {
    let (mut section, mut access, mut secret) = (false, None, None);
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            section = line == "[default]";
        } else if section && let Some((name, value)) = line.split_once('=') {
            let value = value.trim().to_owned();
            match name.trim() {
                "aws_access_key_id" => access = Some(value),
                "aws_secret_access_key" => secret = Some(value),
                _ => {}
            }
        }
    }
    Some((
        access.filter(|a| !a.is_empty())?,
        secret.filter(|s| !s.is_empty())?,
    ))
}

fn element<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    if xml.matches(&open).count() != 1 {
        return None;
    }
    let start = xml.find(&open)? + open.len();
    let end = start + xml[start..].find(&close)?;
    Some(&xml[start..end])
}

/// Days of the default COMPLIANCE retention in an `ObjectLockConfiguration`
/// body, or `None` for anything else (disabled, GOVERNANCE, absent rule,
/// years, malformed).
pub(crate) fn compliance_days(xml: &str) -> Option<u64> {
    let config = element(xml, "ObjectLockConfiguration")?;
    if element(config, "ObjectLockEnabled")? != "Enabled" {
        return None;
    }
    let retention = element(element(config, "Rule")?, "DefaultRetention")?;
    if element(retention, "Mode")? != "COMPLIANCE" || retention.contains("<Years>") {
        return None;
    }
    let days = element(retention, "Days")?;
    if !days.bytes().all(|b| b.is_ascii_digit()) || days.len() > 6 {
        return None;
    }
    days.parse().ok()
}

/// The single line the worker prints on a pass.
pub(crate) fn pass_line(days: u64) -> String {
    format!("{{\"lock\":\"COMPLIANCE\",\"days\":{days}}}")
}

/// Runner side: whether the worker's whole output is a pass line.
pub(crate) fn verified(output: &str) -> bool {
    let Some(line) = output.strip_suffix('\n') else {
        return false;
    };
    if line.contains('\n') {
        return false;
    }
    let Some(days) = line
        .strip_prefix("{\"lock\":\"COMPLIANCE\",\"days\":")
        .and_then(|rest| rest.strip_suffix('}'))
    else {
        return false;
    };
    days.len() <= 6
        && days.bytes().all(|b| b.is_ascii_digit())
        && days.parse::<u64>().is_ok_and(|days| days >= MIN_DAYS)
}

/// HMAC-SHA256.
pub(crate) fn hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0_u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let pad = |byte: u8| block.map(|b| b ^ byte);
    let inner = Sha256::new()
        .chain_update(pad(0x36))
        .chain_update(message)
        .finalize();
    Sha256::new()
        .chain_update(pad(0x5c))
        .chain_update(inner)
        .finalize()
        .into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hex SHA-256 of the empty body.
pub(crate) fn empty_hash() -> String {
    hex(&Sha256::digest(b""))
}

/// SigV4 `Authorization` header value for a GET of `path?{query}=` with an
/// empty body, at `amz_date` (`YYYYMMDDTHHMMSSZ`).
pub(crate) fn authorization(
    access: &str,
    secret: &str,
    host: &str,
    path: &str,
    query: &str,
    amz_date: &str,
) -> String {
    let date = &amz_date[..8.min(amz_date.len())];
    let body = empty_hash();
    let canonical = format!(
        "GET\n{path}\n{query}=\nhost:{host}\nx-amz-content-sha256:{body}\nx-amz-date:{amz_date}\n\nhost;x-amz-content-sha256;x-amz-date\n{body}"
    );
    let scope = format!("{date}/{REGION}/s3/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex(&Sha256::digest(canonical.as_bytes()))
    );
    let mut key = hmac(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    for part in [REGION, "s3", "aws4_request"] {
        key = hmac(&key, part.as_bytes());
    }
    format!(
        "AWS4-HMAC-SHA256 Credential={access}/{scope},SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature={}",
        hex(&hmac(&key, to_sign.as_bytes()))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_is_http_host_and_bucket_only() {
        assert_eq!(
            endpoint("s3:http://192.168.122.1:9000/rustiron-lab-backups/sites/rs_blog13"),
            Some((
                "192.168.122.1:9000".to_owned(),
                "rustiron-lab-backups".to_owned()
            ))
        );
        for bad in [
            "s3:https://h:9000/b/sites/x",
            "s3:http://h:9000/",
            "s3:http://h:9000",
            "local:/srv/x",
            "s3:http://h:9000/b c/x",
            "s3:http://h\r\n:9000/b/x",
        ] {
            assert_eq!(endpoint(bad), None, "{bad}");
        }
    }

    #[test]
    fn credentials_come_from_the_default_profile() {
        let text = "[other]\naws_access_key_id = NO\naws_secret_access_key = NO\n[default]\naws_access_key_id = AK\naws_secret_access_key=SK\n";
        assert_eq!(credentials(text), Some(("AK".to_owned(), "SK".to_owned())));
        assert_eq!(credentials("[default]\naws_access_key_id = AK\n"), None);
        assert_eq!(credentials(""), None);
    }

    #[test]
    fn only_compliance_with_days_passes() {
        let ok = "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>30</Days></DefaultRetention></Rule></ObjectLockConfiguration>";
        assert_eq!(compliance_days(ok), Some(30));
        assert_eq!(
            compliance_days(&ok.replace("COMPLIANCE", "GOVERNANCE")),
            None
        );
        assert_eq!(
            compliance_days(&ok.replace("Enabled</", "Disabled</")),
            None
        );
        assert_eq!(
            compliance_days(
                "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>"
            ),
            None,
            "W226: root cleared the default rule"
        );
        assert_eq!(
            compliance_days(&ok.replace("<Days>30</Days>", "<Years>1</Years>")),
            None
        );
        assert_eq!(compliance_days(&ok.replace("30", "x")), None);
        assert_eq!(
            compliance_days("<Error><Code>AccessDenied</Code></Error>"),
            None
        );
        assert_eq!(
            compliance_days(&format!("{ok}{ok}")),
            None,
            "one configuration only"
        );
    }

    #[test]
    fn the_runner_accepts_only_a_pass_line_at_the_minimum() {
        assert!(verified(&format!("{}\n", pass_line(30))));
        assert!(verified(&format!("{}\n", pass_line(365))));
        assert!(!verified(&format!("{}\n", pass_line(29))));
        assert!(!verified(""));
        assert!(!verified("{\"lock\":\"GOVERNANCE\",\"days\":30}\n"));
        assert!(!verified(&format!("{0}\n{0}\n", pass_line(30))));
        assert!(!verified(&format!("{}\nextra\n", pass_line(30))));
        assert!(!verified("{\"lock\":\"COMPLIANCE\",\"days\":30,\"x\":1}\n"));
    }

    #[test]
    fn hmac_matches_rfc4231_case_2() {
        let mac = hmac(b"Jefe", b"what do ya want for nothing?");
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn signature_matches_the_aws_get_bucket_lifecycle_example() {
        // AWS SigV4 S3 documentation example "GET Bucket Lifecycle".
        let header = authorization(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "examplebucket.s3.amazonaws.com",
            "/",
            "lifecycle",
            "20130524T000000Z",
        );
        assert_eq!(
            header,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"
        );
    }
}
