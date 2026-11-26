//! Offline HTTPS S3 destination validation against the independent W307
//! vector (port 443) and the independent W352 vector (enrolled port 9443).

use rustiron_contracts::approval::{
    ApprovalError, MAX_PRODUCT_BACKUP_POLICY_BYTES, ProductBackupPolicy, SiteId,
};
use serde_json::{Value, json};

const PROJECTION: &str = include_str!("../../../docs/validation/S10-W307/projection.json");
const DIGEST: &str = include_str!("../../../docs/validation/S10-W307/projection-digest.txt");
const PORT_PROJECTION: &str =
    include_str!("../../../docs/validation/S10-W352/projection-port.json");
const PORT_DIGEST: &str =
    include_str!("../../../docs/validation/S10-W352/projection-port-digest.txt");

fn projection() -> Value {
    serde_json::from_str(PROJECTION).unwrap()
}

fn changed(pointer: &str, value: Value) -> String {
    let mut projection = projection();
    *projection.pointer_mut(pointer).unwrap() = value;
    projection.to_string()
}

/// The W307 projection with another port and its egress profile.
fn with_port(port: Value, profile: &str) -> String {
    let mut projection = projection();
    projection["transport"]["port"] = port;
    projection["transport"]["egress_profile"] = json!(profile);
    projection.to_string()
}

#[test]
fn an_enrolled_non_443_port_matches_the_independent_vector() {
    let policy = ProductBackupPolicy::decode(PORT_PROJECTION.as_bytes()).unwrap();
    assert_eq!(policy.destination_id().as_str(), "offsite_port_fixture");
    assert_eq!(policy.digest().as_str(), PORT_DIGEST.trim_end());
    let site = SiteId::try_from("blog9".to_owned()).unwrap();
    let resolved = policy.resolve_site(&site).unwrap();
    assert_eq!(resolved.endpoint().to_string(), "198.51.100.23:9443");
    assert_eq!(
        resolved.repository_url(),
        "s3:https://198.51.100.23:9443/rustiron-proof/sites/rs_blog9"
    );
}

#[test]
fn the_port_is_bounded_and_names_its_egress_profile() {
    for port in [1, 80, 444, 8443, 9443, 65535] {
        let policy =
            ProductBackupPolicy::decode(with_port(json!(port), "ipv4_tcp_port_v1").as_bytes())
                .unwrap();
        let site = SiteId::try_from("blog13".to_owned()).unwrap();
        assert_eq!(
            policy.resolve_site(&site).unwrap().endpoint().port(),
            port,
            "{port}"
        );
        assert_ne!(policy.digest().as_str(), DIGEST.trim_end(), "{port}");
        // A non-443 port never carries the 443 profile.
        assert_invalid(&with_port(json!(port), "ipv4_tcp_443_v1"), "443 profile");
    }
    // Port 443 has exactly one spelling, so one effect has one digest.
    assert_invalid(
        &with_port(json!(443), "ipv4_tcp_port_v1"),
        "443 port profile",
    );
    for port in [
        json!(0),
        json!(65536),
        json!(-1),
        json!(443.0),
        json!("443"),
        json!(null),
        json!(1e3),
    ] {
        assert_invalid(
            &with_port(port.clone(), "ipv4_tcp_port_v1"),
            &port.to_string(),
        );
    }
    let leading_zero = PORT_PROJECTION.replace("\"port\": 9443,", "\"port\": 09443,");
    assert_ne!(leading_zero, PORT_PROJECTION);
    assert!(ProductBackupPolicy::decode(leading_zero.as_bytes()).is_err());
}

#[test]
fn destination_digest_matches_the_independent_vector() {
    let original = ProductBackupPolicy::decode(PROJECTION.as_bytes()).unwrap();
    let compact = ProductBackupPolicy::decode(projection().to_string().as_bytes()).unwrap();
    assert_eq!(original.destination_id().as_str(), "offsite_fixture");
    assert_eq!(original.as_bytes(), compact.as_bytes());
    assert_eq!(original.digest().as_str(), DIGEST.trim_end());
}

#[test]
fn resolves_both_repository_and_credential_rows_by_enrolled_site() {
    let policy = ProductBackupPolicy::decode(PROJECTION.as_bytes()).unwrap();
    for (site_id, repo_id, capture_auth, fetch_auth) in
        [("blog13", "b", "d", "f"), ("blog9", "c", "e", "0")]
    {
        let site = SiteId::try_from(site_id.to_owned()).unwrap();
        let resolved = policy.resolve_site(&site).unwrap();
        assert_eq!(resolved.repository_id().as_str(), repo_id.repeat(64));
        assert_eq!(policy.repository_id(&site), Some(resolved.repository_id()));
        assert_eq!(
            resolved.repository_url(),
            format!("s3:https://198.51.100.23:443/rustiron-proof/sites/rs_{site_id}")
        );
        assert_eq!(resolved.endpoint().to_string(), "198.51.100.23:443");
        assert_eq!(resolved.region(), "fixture-1");
        assert_eq!(resolved.ca_sha256().as_str(), "a".repeat(64));
        assert_eq!(resolved.retention_days(), 30);
        let account = std::path::PathBuf::from(format!("rs_{site_id}"));
        assert_eq!(resolved.password_path(), account.join("repo.password"));
        for (credential, phase, leaf, authorization) in [
            (
                resolved.capture_credential(),
                "capture",
                "aws",
                capture_auth,
            ),
            (
                resolved.fetch_credential(),
                "fetch",
                "fetch-aws",
                fetch_auth,
            ),
        ] {
            assert_eq!(
                credential.relative_path(),
                account.join(leaf),
                "{site_id} {phase}"
            );
            assert_eq!(credential.profile_id().as_str(), format!("fixture_{phase}"));
            assert_eq!(
                credential.principal_id().as_str(),
                format!("{phase}_{site_id}")
            );
            assert_eq!(
                credential.authorization_sha256().as_str(),
                authorization.repeat(64)
            );
        }
    }
    let unenrolled = SiteId::try_from("other1".to_owned()).unwrap();
    assert!(policy.resolve_site(&unenrolled).is_none());
}

#[test]
fn destination_digest_binds_every_variable_enrollment_field() {
    for (field, replacement) in [
        ("/destination_id", json!("other_destination")),
        ("/retention_days", json!(3650)),
        ("/transport/store_id", json!("other_store")),
        ("/transport/endpoint_ipv4", json!("10.1.2.255")),
        ("/transport/region", json!("fixture-2")),
        ("/transport/bucket", json!("other-bucket")),
        ("/transport/ca_sha256", json!("1".repeat(64))),
        (
            "/transport/repositories/0/repository_id",
            json!("1".repeat(64)),
        ),
        (
            "/capture_credential_profile/profile_id",
            json!("other_capture"),
        ),
        ("/fetch_credential_profile/profile_id", json!("other_fetch")),
        (
            "/capture_credential_profile/principals/0/principal_id",
            json!("other_writer"),
        ),
        (
            "/fetch_credential_profile/principals/0/principal_id",
            json!("other_reader"),
        ),
        (
            "/capture_credential_profile/principals/0/authorization_sha256",
            json!("1".repeat(64)),
        ),
        (
            "/fetch_credential_profile/principals/0/authorization_sha256",
            json!("1".repeat(64)),
        ),
    ] {
        let policy = ProductBackupPolicy::decode(changed(field, replacement).as_bytes()).unwrap();
        assert_ne!(policy.digest().as_str(), DIGEST.trim_end(), "{field}");
    }
    let mut renamed_site = projection();
    for entry in [
        "/transport/repositories/0/site_id",
        "/capture_credential_profile/principals/0/site_id",
        "/fetch_credential_profile/principals/0/site_id",
    ] {
        *renamed_site.pointer_mut(entry).unwrap() = json!("blog14");
    }
    let policy = ProductBackupPolicy::decode(renamed_site.to_string().as_bytes()).unwrap();
    assert_ne!(policy.digest().as_str(), DIGEST.trim_end(), "site mapping");
}

#[test]
fn destination_rejects_open_shape_and_invalid_effect_parameters() {
    assert_eq!(
        ProductBackupPolicy::decode(changed("/schema_version", json!(1)).as_bytes()).unwrap_err(),
        ApprovalError::UnsupportedVersion
    );
    assert_eq!(
        ProductBackupPolicy::decode(&vec![b' '; MAX_PRODUCT_BACKUP_POLICY_BYTES + 1]).unwrap_err(),
        ApprovalError::RequestTooLarge
    );
    for (field, replacement) in [
        ("/destination_id", json!("lab_pc_store")),
        ("/transport_id", json!("s3_other_v1")),
        ("/transport/port", json!(8443)),
        ("/transport/port", json!(0)),
        ("/transport/egress_profile", json!("ipv4_tcp_port_v1")),
        ("/transport/bucket", json!("bad/bucket")),
        ("/transport/bucket", json!("ab")),
        ("/transport/region", json!("")),
        ("/transport/region", json!("fixture-")),
        ("/transport/region", json!("x".repeat(64))),
        ("/transport/repository_root", json!("other")),
        ("/transport/egress_profile", json!("any")),
        ("/transport/retention_mode", json!("governance")),
        ("/transport/ca_sha256", json!("A".repeat(64))),
        ("/retention_days", json!(29)),
        ("/retention_days", json!(3651)),
        ("/capture_credential_profile/scope", json!("site_fetch_v1")),
        ("/fetch_credential_profile/credential_slot", json!("aws")),
    ] {
        assert_invalid(&changed(field, replacement), field);
    }
    for address in [
        "0.0.0.0",
        "0.1.2.3",
        "127.1.2.3",
        "169.254.1.1",
        "224.0.0.1",
        "240.1.2.3",
        "255.255.255.255",
        "::ffff:192.0.2.8",
        "198.051.100.23",
        "198.51.100.23:443",
        "store.example",
    ] {
        assert_invalid(
            &changed("/transport/endpoint_ipv4", json!(address)),
            address,
        );
    }
    for object in [
        "",
        "/transport",
        "/transport/repositories/0",
        "/capture_credential_profile",
        "/fetch_credential_profile/principals/0",
    ] {
        let mut extra = projection();
        extra.pointer_mut(object).unwrap()["extra"] = json!("value");
        assert_invalid(&extra.to_string(), object);
    }
    let missing = PROJECTION.replace("\"port\": 443,", "");
    assert_invalid(&missing, "missing port");
    let duplicate = PROJECTION.replace("\"port\": 443,", "\"port\": 443, \"port\": 443,");
    assert_invalid(&duplicate, "duplicate port");
}

#[test]
fn destination_rejects_unordered_or_ambiguous_site_and_principal_mappings() {
    let original = projection();
    for (field, replacement) in [
        ("/transport/repositories", json!([])),
        ("/transport/repositories/1/site_id", json!("blog13")),
        (
            "/transport/repositories/1/repository_id",
            original["transport"]["repositories"][0]["repository_id"].clone(),
        ),
        ("/transport/repositories/1/site_id", json!("blog0")),
        ("/fetch_credential_profile/principals", json!([])),
        (
            "/fetch_credential_profile/principals/0/site_id",
            json!("blog9"),
        ),
        (
            "/capture_credential_profile/principals/1/principal_id",
            json!("capture_blog13"),
        ),
        (
            "/fetch_credential_profile/principals/0/principal_id",
            json!("capture_blog13"),
        ),
    ] {
        assert_invalid(&changed(field, replacement), field);
    }
    // Reordering all three arrays together still violates canonical site order.
    let mut reversed = projection();
    for array in [
        "/transport/repositories",
        "/capture_credential_profile/principals",
        "/fetch_credential_profile/principals",
    ] {
        reversed
            .pointer_mut(array)
            .unwrap()
            .as_array_mut()
            .unwrap()
            .reverse();
    }
    assert_invalid(&reversed.to_string(), "reversed site order");
}

fn assert_invalid(input: &str, case: &str) {
    assert_eq!(
        ProductBackupPolicy::decode(input.as_bytes()).err(),
        Some(ApprovalError::InvalidMessage),
        "{case}"
    );
}
