//! Public protocol-version compatibility regression cases.

use rustiron_contracts::SchemaVersion;

#[test]
fn accepts_the_documented_wire_version() {
    let version = SchemaVersion::try_from(1).expect("schema v1 is supported");
    assert_eq!(version, SchemaVersion::V1);
    assert_eq!(version.get(), 1);
}

#[test]
fn rejects_unknown_versions_without_falling_back() {
    for value in [0, 2, u16::MAX] {
        let error = SchemaVersion::try_from(value).expect_err("unknown version must fail");
        assert_eq!(error.received(), value);
    }
}

#[test]
fn explains_the_supported_version() {
    let error = SchemaVersion::try_from(2).expect_err("schema v2 is unsupported");
    assert_eq!(
        error.to_string(),
        "unsupported schema version 2; expected 1"
    );
}
