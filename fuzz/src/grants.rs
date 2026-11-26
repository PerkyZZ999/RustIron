//! Closed grant decoder oracles across all 23 catalogue verbs, without signatures or replay authority.

use rustiron_contracts::approval::{
    AppDeployGrant, AppLifecycleGrant, AppProvisionGrant, ApprovalError, CaptureGrant,
    CertificateGrant, CloneScrubGrant, CredentialRotateGrant, DeleteGrant, DnsChangeGrant,
    DnsImportGrant, EjectGrant, ImportGrant, OlsGrant, ProbeGrant, ProxyGrant, QuotaGrant,
    ReadoptGrant, RestoreGrant, RetireGrant, ScrubGrant, SiteCloneGrant, SiteGrant,
    SiteUpdateGrant,
};
use rustiron_contracts::{CanonicalObject, MAX_REQUEST_BYTES};
use serde_json::{Value, json};

const MAX_GRANT_WINDOW_SECONDS: u64 = 3600;

/// Exercise every catalogue grant decoder, with exact canonical/identity checks.
pub fn grant(input: &[u8]) -> bool {
    let mut accepted = 0;
    macro_rules! check {
        ($grant:ty, $verb:literal) => {
            match <$grant>::decode(input) {
                Ok(grant) => {
                    accepted += 1;
                    let value: Value = serde_json::from_slice(input).unwrap();
                    assert_eq!(value["verbs"], json!([$verb]));
                    assert_eq!(value["max_operations"], json!(1));
                    assert_ne!(value["issuer"], value["requester"]);
                    let start = value["valid_from"].as_u64().unwrap();
                    let end = value["expires_at"].as_u64().unwrap();
                    assert!(
                        start < end && end - start <= MAX_GRANT_WINDOW_SECONDS,
                        "grant time window expanded"
                    );
                    assert_eq!(value["grant_id"].as_str(), Some(grant.grant_id().as_str()));
                    assert_eq!(value["nonce"].as_str(), Some(grant.nonce().as_str()));
                    assert_eq!(end, grant.expires_at().get());
                    assert_eq!(
                        grant.as_bytes(),
                        CanonicalObject::decode(input).unwrap().as_bytes()
                    );
                    let again = <$grant>::decode(grant.as_bytes()).unwrap();
                    assert_eq!(again.as_bytes(), grant.as_bytes());
                    assert_eq!(again.grant_id(), grant.grant_id());
                    assert_eq!(again.nonce(), grant.nonce());
                    assert_eq!(again.expires_at(), grant.expires_at());
                    for (field, replacement, reason) in [
                        (
                            "fuzz_unsupported_member",
                            json!(true),
                            "unknown grant member accepted",
                        ),
                        (
                            "max_operations",
                            json!(2),
                            "grant operation expansion accepted",
                        ),
                        (
                            "issuer",
                            value["requester"].clone(),
                            "self-issued grant accepted",
                        ),
                    ] {
                        let mut changed = value.clone();
                        changed[field] = replacement;
                        let bytes = serde_json::to_vec(&changed).unwrap();
                        assert!(<$grant>::decode(&bytes).is_err(), "{reason}");
                    }
                }
                Err(error) if input.len() > MAX_REQUEST_BYTES => {
                    assert_eq!(error, ApprovalError::RequestTooLarge);
                }
                Err(_) => {}
            }
        };
    }
    check!(SiteGrant, "site_provision");
    check!(OlsGrant, "config_activate");
    check!(EjectGrant, "site_eject");
    check!(CaptureGrant, "backup_capture");
    check!(ProbeGrant, "restore_probe");
    check!(ReadoptGrant, "site_readopt");
    check!(ImportGrant, "site_import");
    check!(ScrubGrant, "import_scrub");
    check!(CertificateGrant, "certificate_issue");
    check!(SiteCloneGrant, "site_clone");
    check!(RetireGrant, "site_retire");
    check!(SiteUpdateGrant, "site_update");
    check!(DeleteGrant, "site_delete");
    check!(QuotaGrant, "site_quota");
    check!(CloneScrubGrant, "clone_scrub");
    check!(RestoreGrant, "site_restore");
    check!(DnsImportGrant, "dns_zone_import");
    check!(DnsChangeGrant, "dns_change");
    check!(ProxyGrant, "proxy_site_provision");
    check!(AppProvisionGrant, "app_provision");
    check!(AppDeployGrant, "app_deploy");
    check!(AppLifecycleGrant, "app_lifecycle");
    check!(CredentialRotateGrant, "site_credential_rotate");
    assert!(accepted <= 1, "cross-kind grant accepted");
    accepted == 1
}
