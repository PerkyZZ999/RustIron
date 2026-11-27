//! W515 (D-084): a signed `site_update` is checked against real SQLite
//! fixture records up to the host checks, and nothing is recorded.

use rustiron_contracts::approval::SiteUpdatePlan;
use rustiron_journal::{CaptureConsistency, CaptureManifest};

use super::*;

fn time(seconds: u64) -> Timestamp {
    Timestamp::try_from(seconds).unwrap()
}

fn identifier(value: &str) -> rustiron_contracts::Id {
    value.to_owned().try_into().unwrap()
}

/// A served `blog9` with one succeeded capture `op_capture1` at 1100.
fn seed(fixture: &BackupFixture) {
    drop(Executor::initialize(fixture.anchor.clone()).unwrap());
    let mut journal = FixtureJournal::open_as_process_owner(
        &fixture.anchor.journal_dir,
        identifier("host_lab"),
        identifier("epoch_1"),
    )
    .unwrap();
    let provision = ProvisionIntent {
        operation_id: identifier("op_update_site"),
        idempotency_key: identifier("key_update_site"),
        grant_id: identifier("grant_update_site"),
        nonce: identifier("nonce_update_site"),
        plan_digest: Sha256Digest::from_bytes([1; 32]),
        grant_digest: Sha256Digest::from_bytes([2; 32]),
        host_id: identifier("host_lab"),
        host_epoch: identifier("epoch_1"),
        site_id: "blog9".to_owned().try_into().unwrap(),
        hostname: "blog9.example.test".to_owned().try_into().unwrap(),
        expires_at: time(1400),
    };
    journal.record_provision(&provision, time(1000)).unwrap();
    for step in ProvisionStep::ALL {
        journal
            .begin_step(&provision.operation_id, step, "synthetic")
            .unwrap();
        journal
            .finish_step(&provision.operation_id, step, true)
            .unwrap();
    }
    let capture = CaptureIntent {
        operation_id: identifier("op_capture1"),
        idempotency_key: identifier("key_update_capture"),
        grant_id: identifier("grant_update_capture"),
        nonce: identifier("nonce_update_capture"),
        plan_digest: Sha256Digest::from_bytes([3; 32]),
        grant_digest: Sha256Digest::from_bytes([4; 32]),
        host_id: provision.host_id,
        host_epoch: provision.host_epoch,
        site_id: provision.site_id,
        expires_at: time(1400),
    };
    journal
        .record_capture(
            &capture,
            time(1050),
            CaptureMethod::SiteFilesDbV1,
            Some(30),
            &Sha256Digest::from_bytes([5; 32]),
        )
        .unwrap();
    journal
        .finish_capture_labelled(
            &capture.operation_id,
            Some(&"b".repeat(64)),
            time(1100),
            None,
            Some(&CaptureManifest {
                sha256: "c".repeat(64),
                entries: 2,
                regular_bytes: 16,
                truncated: false,
            }),
            Some(&CaptureConsistency::Matched),
        )
        .unwrap();
}

#[test]
fn a_signed_update_is_checked_against_the_journal_and_records_nothing() {
    let fixture = BackupFixture::new();
    seed(&fixture);
    let mut executor = Executor::open(fixture.anchor.clone()).unwrap();
    let before = fixture.replay_state();
    let plan: Value = serde_json::from_slice(include_bytes!(
        "../../../contracts/tests/fixtures/update-plan.json"
    ))
    .unwrap();
    let request = |plan: &Value, site: &str, operation: &str| {
        let bytes = plan.to_string();
        let parsed = SiteUpdatePlan::decode(bytes.as_bytes()).unwrap();
        let mut grant: Value = serde_json::from_slice(include_bytes!(
            "../../../contracts/tests/fixtures/update-grant.json"
        ))
        .unwrap();
        grant["site_ids"] = json!([site]);
        grant["plan_digest"] = json!(parsed.digest());
        let grant = grant.to_string();
        let signature = fixture.sign(grant.as_bytes());
        (bytes, grant, signature, operation.to_owned())
    };
    let mut exact = plan;
    exact["site_id"] = json!("blog9");
    exact["capture_operation_id"] = json!("op_capture1");
    let mut other_capture = exact.clone();
    other_capture["capture_operation_id"] = json!("op_capture2");
    let mut unserved = exact.clone();
    unserved["site_id"] = json!("blog8");
    // W527 (D-086): a core update passes the same journal checks as any
    // update and stops at the host's OLS include too.
    let mut core = exact.clone();
    core["components"] = json!([{"kind": "core", "slug": "wordpress", "from_version": "7.0.9", "to_version": "7.1.5"}]);
    for (plan, site, expected) in [
        // Every journal check passes; the next check opens the host's OLS
        // include, which this test host does not hold as a trusted folder.
        (&exact, "blog9", ExecutorError::AccessDenied),
        (&other_capture, "blog9", ExecutorError::PreconditionChanged),
        (&unserved, "blog8", ExecutorError::PreconditionChanged),
        (&core, "blog9", ExecutorError::AccessDenied),
    ] {
        let (bytes, grant, signature, operation) = request(plan, site, "op_site_update");
        let admission = AdmissionRequest {
            peer_uid: 4242,
            plan: bytes.as_bytes(),
            grant: grant.as_bytes(),
            signature: &signature,
            operation_id: identifier(&operation),
            idempotency_key: identifier("key_site_update"),
            now: Some(time(1200)),
        };
        assert_eq!(
            executor.update_site(&admission).err(),
            Some(expected),
            "{site} {}",
            plan["capture_operation_id"]
        );
    }
    // A grant signed by another key is refused before any check.
    let (bytes, grant, _, _) = request(&exact, "blog9", "op_site_update");
    let other_key = fixture.root.join("other-key");
    new_key(&other_key);
    let other = sign(
        &other_key,
        &fixture.root.join("other-message"),
        CanonicalObject::decode(grant.as_bytes())
            .unwrap()
            .as_bytes(),
        "rustiron-plan-v1",
    );
    let admission = AdmissionRequest {
        peer_uid: 4242,
        plan: bytes.as_bytes(),
        grant: grant.as_bytes(),
        signature: &other,
        operation_id: identifier("op_site_update"),
        idempotency_key: identifier("key_site_update"),
        now: Some(time(1200)),
    };
    assert!(executor.update_site(&admission).is_err());
    assert_eq!(fixture.replay_state(), before);
}

/// W700: a stored update answers only an exact replay. A different signed
/// update that names the same operation is refused (`REPLAY_DENIED`); before,
/// it got the stored row as if it were a replay.
#[test]
fn a_different_update_naming_a_stored_operation_is_refused() {
    use rustiron_contracts::{
        CanonicalObject,
        approval::{ComponentSlug, ComponentVersion, UpdateComponent, UpdateKind},
    };
    use rustiron_journal::{SignedAdmission, UpdateIntent};
    use sha2::{Digest, Sha256};
    const PLAN: &str = r#"{"plan_id":"plan_stored","schema_version":1,"site_id":"blog9"}"#;
    const GRANT: &str = r#"{"grant_id":"grant_stored","issuer":"lab_agent","nonce":"nonce_stored","signer_policy_epoch":"policy_3"}"#;
    let fixture = BackupFixture::new();
    seed(&fixture);
    let mut journal = FixtureJournal::open_as_process_owner(
        &fixture.anchor.journal_dir,
        identifier("host_lab"),
        identifier("epoch_1"),
    )
    .unwrap();
    journal.stage_signed(SignedAdmission {
        plan: PLAN.as_bytes().to_vec(),
        grant: GRANT.as_bytes().to_vec(),
        issuer: identifier("lab_agent"),
        signer_policy_epoch: identifier("policy_3"),
    });
    let stored = UpdateIntent {
        operation_id: identifier("op_site_update"),
        idempotency_key: identifier("key_stored_update"),
        grant_id: identifier("grant_stored"),
        nonce: identifier("nonce_stored"),
        plan_digest: Sha256Digest::from_bytes(
            CanonicalObject::decode(PLAN.as_bytes())
                .unwrap()
                .plan_domain_digest(),
        ),
        grant_digest: Sha256Digest::from_bytes(Sha256::digest(GRANT.as_bytes()).into()),
        host_id: identifier("host_lab"),
        host_epoch: identifier("epoch_1"),
        site_id: "blog9".to_owned().try_into().unwrap(),
        capture_operation_id: identifier("op_capture1"),
        recipe_digest: Sha256Digest::from_bytes([9; 32]),
        components: vec![UpdateComponent {
            kind: UpdateKind::Plugin,
            slug: ComponentSlug::try_from("hello-dolly".to_owned()).unwrap(),
            from_version: ComponentVersion::try_from("1.7.1".to_owned()).unwrap(),
            to_version: ComponentVersion::try_from("1.7.2".to_owned()).unwrap(),
        }],
        expires_at: time(1400),
    };
    journal.record_update(&stored, time(1150)).unwrap();
    drop(journal);

    let mut executor = Executor::open(fixture.anchor.clone()).unwrap();
    let mut plan: Value = serde_json::from_slice(include_bytes!(
        "../../../contracts/tests/fixtures/update-plan.json"
    ))
    .unwrap();
    plan["site_id"] = json!("blog9");
    plan["capture_operation_id"] = json!("op_capture1");
    let bytes = plan.to_string();
    let parsed = SiteUpdatePlan::decode(bytes.as_bytes()).unwrap();
    let mut grant: Value = serde_json::from_slice(include_bytes!(
        "../../../contracts/tests/fixtures/update-grant.json"
    ))
    .unwrap();
    grant["site_ids"] = json!(["blog9"]);
    grant["plan_digest"] = json!(parsed.digest());
    let grant = grant.to_string();
    let signature = fixture.sign(grant.as_bytes());
    let admission = AdmissionRequest {
        peer_uid: 4242,
        plan: bytes.as_bytes(),
        grant: grant.as_bytes(),
        signature: &signature,
        operation_id: identifier("op_site_update"),
        idempotency_key: identifier("key_site_update"),
        now: Some(time(1200)),
    };
    assert_eq!(
        executor.update_site(&admission).err(),
        Some(ExecutorError::ReplayDenied)
    );
}
