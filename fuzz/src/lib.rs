//! Pure parser oracles shared by the fuzz targets and deterministic seed smoke.

use rustiron_contracts::approval::{
    AppDeployPlan, AppLifecyclePlan, AppProvisionPlan, ApprovalError, CapturePlan, CertificatePlan,
    CloneScrubPlan, CredentialRotatePlan, DeletePlan, DnsChangePlan, DnsImportPlan, EjectPlan,
    ImportPlan, MAX_STANDING_RUNS, MAX_STANDING_SITES, OlsPlan, PlanKind, PreparedPlan, ProbePlan,
    ProductBackupPlan, ProxyPlan, QuotaPlan, ReadoptForm, ReadoptPlan, RestorePlan, RetirePlan,
    ScrubPlan, SiteClonePlan, SitePlan, SiteQuotaLimits, SiteUpdatePlan, StandingCapturePlan,
    envelope_for_plan,
};
use rustiron_contracts::{CanonicalObject, MAX_REQUEST_BYTES, ProtocolError};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn domain_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"rustiron/plan/v1\0");
    hash.update(bytes);
    hash.finalize().into()
}

/// One closed plan decoder and the plan kinds it stands for.
type ClosedDecoder = (fn(&[u8]) -> bool, &'static [PlanKind]);

/// W690: the plan kinds each closed decoder that accepts `input` stands for.
fn accepting_kinds(input: &[u8]) -> Vec<&'static [PlanKind]> {
    use PlanKind as K;
    let decoders: [ClosedDecoder; 25] = [
        (|b| SitePlan::decode(b).is_ok(), &[K::SiteProvision]),
        (|b| OlsPlan::decode(b).is_ok(), &[K::ConfigActivate]),
        (|b| EjectPlan::decode(b).is_ok(), &[K::SiteEject]),
        (|b| CapturePlan::decode(b).is_ok(), &[K::BackupCapture]),
        (|b| ProbePlan::decode(b).is_ok(), &[K::RestoreProbe]),
        (|b| ReadoptPlan::decode(b).is_ok(), &[K::SiteReadopt]),
        (|b| ImportPlan::decode(b).is_ok(), &[K::SiteImport]),
        (|b| ScrubPlan::decode(b).is_ok(), &[K::ImportScrub]),
        (
            |b| CertificatePlan::decode(b).is_ok(),
            &[K::CertificateIssue],
        ),
        (
            |b| ProductBackupPlan::decode(b).is_ok(),
            &[K::BackupCapture, K::RestoreProbe],
        ),
        (
            |b| StandingCapturePlan::decode(b).is_ok(),
            &[K::BackupCapture],
        ),
        (|b| SiteClonePlan::decode(b).is_ok(), &[K::SiteClone]),
        (|b| RetirePlan::decode(b).is_ok(), &[K::SiteRetire]),
        (|b| SiteUpdatePlan::decode(b).is_ok(), &[K::SiteUpdate]),
        (|b| DeletePlan::decode(b).is_ok(), &[K::SiteDelete]),
        (|b| QuotaPlan::decode(b).is_ok(), &[K::SiteQuota]),
        (|b| CloneScrubPlan::decode(b).is_ok(), &[K::CloneScrub]),
        (|b| RestorePlan::decode(b).is_ok(), &[K::SiteRestore]),
        (|b| DnsImportPlan::decode(b).is_ok(), &[K::DnsZoneImport]),
        (|b| DnsChangePlan::decode(b).is_ok(), &[K::DnsChange]),
        (|b| ProxyPlan::decode(b).is_ok(), &[K::ProxySiteProvision]),
        (|b| AppProvisionPlan::decode(b).is_ok(), &[K::AppProvision]),
        (|b| AppDeployPlan::decode(b).is_ok(), &[K::AppDeploy]),
        (|b| AppLifecyclePlan::decode(b).is_ok(), &[K::AppLifecycle]),
        (
            |b| CredentialRotatePlan::decode(b).is_ok(),
            &[K::SiteCredentialRotate],
        ),
    ];
    decoders
        .iter()
        .filter(|(accepts, _)| accepts(input))
        .map(|&(_, kinds)| kinds)
        .collect()
}

/// Check bounded shape, value preservation, canonical stability and digest framing.
/// Returns whether the input was accepted, so seed smoke can prove positive paths.
pub fn canonical_object(input: &[u8]) -> bool {
    let decoded = CanonicalObject::decode(input);
    if input.len() > MAX_REQUEST_BYTES {
        assert_eq!(decoded, Err(ProtocolError::RequestTooLarge));
        return false;
    }
    let Ok(object) = decoded else {
        return false;
    };
    let original: Value = serde_json::from_slice(input).expect("accepted object must be JSON");
    assert!(original.is_object());
    let canonical: Value = serde_json::from_slice(object.as_bytes()).expect("canonical JSON");
    assert_eq!(canonical, original, "canonicalization lost semantic values");
    assert_eq!(CanonicalObject::decode(object.as_bytes()).unwrap(), object);
    assert_eq!(
        object.plan_domain_digest(),
        domain_digest(object.as_bytes())
    );
    assert!(object.as_bytes().len() <= MAX_REQUEST_BYTES);

    // Metamorphic duplicate names must fail, including a decoded Unicode alias.
    let duplicate = format!(
        r#"{{"value":{},"dup":0,"du\u0070":1}}"#,
        std::str::from_utf8(object.as_bytes()).unwrap()
    );
    assert!(
        CanonicalObject::decode(duplicate.as_bytes()).is_err(),
        "decoded duplicate key accepted"
    );
    true
}

/// Check exact typed dispatch, identity, canonical bytes and non-authorizing digest.
/// Accepted plans are also changed in ways with known valid/invalid outcomes.
pub fn prepared_plan(input: &[u8]) -> bool {
    let decoded = PreparedPlan::decode(input);
    // W690: the executor routes a submission by this kind (W688), so every
    // closed decoder must agree with it: at most one accepts any input, and
    // whatever one accepts, `PreparedPlan` accepts with that decoder's kind.
    let accepting = accepting_kinds(input);
    assert!(accepting.len() <= 1, "decoders overlap: {accepting:?}");
    if let Some(kinds) = accepting.first() {
        let kind = decoded
            .as_ref()
            .expect("a closed decoder accepted it")
            .kind();
        assert!(kinds.contains(&kind), "{kind:?} not in {kinds:?}");
    }
    if input.len() > MAX_REQUEST_BYTES {
        assert_eq!(decoded.err(), Some(ApprovalError::RequestTooLarge));
        return false;
    }
    let Ok(plan) = decoded else {
        return false;
    };
    let mut value: Value = serde_json::from_slice(input).expect("accepted plan must be JSON");
    assert_eq!(Some(plan.id().as_str()), value["plan_id"].as_str());
    assert_eq!(Some(plan.kind().as_str()), value["verb"].as_str());
    let expected = match (value["verb"].as_str(), value["schema_version"].as_u64()) {
        (Some("site_provision"), Some(1 | 2)) => {
            let site = SitePlan::decode(input).unwrap();
            // W341: only v2 carries signed limits, always inside the bounds.
            let limits = site.quota_limits();
            assert_eq!(limits.is_some(), site.schema_version() == 2);
            assert_eq!(value.get("quota_limits").is_some(), limits.is_some());
            if let Some(limits) = limits {
                assert_eq!(
                    SiteQuotaLimits::new(limits.block_hard_kib(), limits.inode_hard()),
                    Ok(limits)
                );
                assert_eq!(value["expected_effects"]["sets_quota"], true);
            }
            site.digest()
        }
        (Some("config_activate"), Some(1..=3)) => {
            let ols = OlsPlan::decode(input).unwrap();
            // W368: only v2 carries the page-cache opt-in, always for a served site.
            let opt_in = ols.page_cache();
            assert_eq!(opt_in.is_some(), ols.schema_version() == 2);
            assert_eq!(value.get("page_cache").is_some(), opt_in.is_some());
            if let Some(opt_in) = opt_in {
                assert!(ols.site_ids().contains(opt_in.site_id()));
            }
            // W370: only v3 carries the opt-out, always for a served site.
            let opt_out = ols.page_cache_opt_out();
            assert_eq!(opt_out.is_some(), ols.schema_version() == 3);
            assert_eq!(value.get("page_cache_opt_out").is_some(), opt_out.is_some());
            if let Some(opt_out) = opt_out {
                assert!(ols.site_ids().contains(opt_out.site_id()));
            }
            ols.digest()
        }
        (Some("site_eject"), Some(1..=3)) => EjectPlan::decode(input).unwrap().digest(),
        (Some("site_readopt"), Some(1)) => {
            // W372: one closed form; every effect but the record is false,
            // and the previous epoch is never the plan's own.
            let readopt = ReadoptPlan::decode(input).unwrap();
            assert_ne!(value["previous_epoch"], value["host_epoch"]);
            for effect in [
                "creates_account",
                "creates_database",
                "traffic_activation",
                "network_access",
                "sets_quota",
            ] {
                assert_eq!(value["expected_effects"][effect], false, "{effect}");
            }
            match readopt.form() {
                ReadoptForm::Site => {
                    assert!(readopt.site().is_some() && readopt.generation().is_none());
                    assert_eq!(value["expected_effects"]["records_ownership"], true);
                }
                ReadoptForm::Generation => {
                    let (_, _, sites) = readopt.generation().unwrap();
                    assert!(readopt.site().is_none());
                    assert!(
                        sites
                            .windows(2)
                            .all(|pair| pair[0].as_str() < pair[1].as_str())
                    );
                    assert_eq!(value["expected_effects"]["records_generation"], true);
                }
            }
            readopt.digest()
        }
        (Some("site_import"), Some(1..=3)) => ImportPlan::decode(input).unwrap().digest(),
        (Some("import_scrub"), Some(1)) => ScrubPlan::decode(input).unwrap().digest(),
        (Some("certificate_issue"), Some(1..=3)) => {
            CertificatePlan::decode(input).unwrap().digest()
        }
        (Some("backup_capture"), Some(1)) => CapturePlan::decode(input).unwrap().digest(),
        (Some("restore_probe"), Some(1)) => ProbePlan::decode(input).unwrap().digest(),
        (Some("backup_capture" | "restore_probe"), Some(2)) => {
            ProductBackupPlan::decode(input).unwrap().digest()
        }
        (Some("backup_capture"), Some(3)) => {
            // W386 (D-035): sorted named sites and a bounded window series
            // that fits inside the signed validity.
            let standing = StandingCapturePlan::decode(input).unwrap();
            let sites = standing.site_ids();
            assert!((1..=MAX_STANDING_SITES).contains(&sites.len()));
            assert!(
                sites
                    .windows(2)
                    .all(|pair| pair[0].as_str() < pair[1].as_str())
            );
            let schedule = standing.schedule();
            assert!((1..=MAX_STANDING_RUNS).contains(&schedule.max_runs));
            assert!(schedule.window_seconds <= schedule.period_seconds / 2);
            let (_, last_end) = schedule.window(schedule.max_runs - 1).unwrap();
            assert!(last_end <= value["expires_at"].as_u64().unwrap());
            assert!(schedule.first_window_start >= value["valid_from"].as_u64().unwrap());
            assert!(schedule.window(schedule.max_runs).is_none());
            standing.digest()
        }
        (Some("site_clone"), Some(1)) => SiteClonePlan::decode(input).unwrap().digest(),
        (Some("site_retire"), Some(1)) => RetirePlan::decode(input).unwrap().digest(),
        (Some("site_update"), Some(1)) => SiteUpdatePlan::decode(input).unwrap().digest(),
        (Some("site_delete"), Some(1 | 2)) => DeletePlan::decode(input).unwrap().digest(),
        (Some("site_quota"), Some(1)) => QuotaPlan::decode(input).unwrap().digest(),
        (Some("clone_scrub"), Some(1)) => CloneScrubPlan::decode(input).unwrap().digest(),
        (Some("site_restore"), Some(1)) => RestorePlan::decode(input).unwrap().digest(),
        (Some("dns_zone_import"), Some(1)) => DnsImportPlan::decode(input).unwrap().digest(),
        (Some("dns_change"), Some(1)) => DnsChangePlan::decode(input).unwrap().digest(),
        (Some("proxy_site_provision"), Some(1)) => ProxyPlan::decode(input).unwrap().digest(),
        (Some("app_provision"), Some(1 | 2)) => AppProvisionPlan::decode(input).unwrap().digest(),
        (Some("app_deploy"), Some(1 | 2)) => AppDeployPlan::decode(input).unwrap().digest(),
        (Some("app_lifecycle"), Some(1)) => AppLifecyclePlan::decode(input).unwrap().digest(),
        (Some("site_credential_rotate"), Some(1 | 2)) => {
            CredentialRotatePlan::decode(input).unwrap().digest()
        }
        _ => panic!("unsupported plan verb or version accepted"),
    };
    assert_eq!(plan.digest(), expected);
    if let Some(env) = envelope_for_plan(plan.as_bytes()) {
        assert_eq!(env.verb, plan.kind().as_str());
        assert_eq!(envelope_for_plan(plan.as_bytes()), Some(env));
    }
    let object = CanonicalObject::decode(input).unwrap();
    assert_eq!(plan.as_bytes(), object.as_bytes());
    let expected_hex: String = domain_digest(plan.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(plan.digest().as_str(), expected_hex);
    let roundtrip = PreparedPlan::decode(plan.as_bytes()).unwrap();
    assert_eq!(roundtrip.as_bytes(), plan.as_bytes());
    assert_eq!(roundtrip.id(), plan.id());
    assert_eq!(roundtrip.kind(), plan.kind());
    assert_eq!(roundtrip.digest(), plan.digest());

    value["fuzz_unsupported_member"] = true.into();
    assert!(
        PreparedPlan::decode(&serde_json::to_vec(&value).unwrap()).is_err(),
        "unknown plan member accepted"
    );
    value
        .as_object_mut()
        .unwrap()
        .remove("fuzz_unsupported_member");
    let new_id = if plan.id().as_str() == "fuzz_changed_plan_a" {
        "fuzz_changed_plan_b"
    } else {
        "fuzz_changed_plan_a"
    };
    value["plan_id"] = new_id.into();
    let changed_bytes = serde_json::to_vec(&value).unwrap();
    let changed_result = PreparedPlan::decode(&changed_bytes);
    if changed_bytes.len() > MAX_REQUEST_BYTES {
        assert_eq!(changed_result.err(), Some(ApprovalError::RequestTooLarge));
        return true;
    }
    let changed = changed_result.expect("changing only an intrinsic plan id must remain valid");
    assert_eq!(changed.id().as_str(), new_id);
    assert_eq!(changed.kind(), plan.kind());
    assert_ne!(changed.digest(), plan.digest());
    true
}

mod bindings;
mod grants;
pub use bindings::plan_grant_binding;
pub use grants::grant;

mod wire;
pub use wire::{apply_request, submission};

mod responses;
pub use responses::{
    apply_response, evidence_response, read_response, status_response, submission_reply,
};

mod queries;
pub use queries::{evidence_query, read_request, status_query};

mod inventory;
pub use inventory::{INVENTORY_MAX_INPUT, inventory_report};

mod manifest;
pub use manifest::{MANIFEST_MAX_INPUT, capture_manifest};

mod admin;
pub use admin::{ADMIN_REPLY_MAX_INPUT, ADMIN_REQUEST_MAX_INPUT, admin_reply, admin_request};

mod admin_payload;
pub use admin_payload::{
    ADMIN_PAYLOAD_MAX_INPUT, RELAY_ROOT, admin_capture_payload, admin_probe_payload,
};

mod s3_store;
pub use s3_store::{
    DECLARATION, LIST_BUCKET, LIST_PREFIX, MARKER, NAMESPACE, S3_BATCH_MAX_INPUT,
    S3_CURL_MAX_INPUT, S3_RESPONSE_MAX_INPUT, S3_TIMESTAMP_MAX_INPUT, format_time, list_after,
    s3_batch, s3_curl, s3_list, s3_object_lock, s3_retention, s3_timestamp, s3_versioning,
};

mod dns_zone;
pub use dns_zone::{DNS_ZONE_MAX_INPUT, dns_zone};
