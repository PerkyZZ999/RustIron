//! W522 (D-085): a signed `site_delete` is checked against real SQLite
//! fixture records up to the host checks, and nothing is recorded.

use rustiron_contracts::approval::DeletePlan;
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
        operation_id: identifier("op_delete_site"),
        idempotency_key: identifier("key_delete_site"),
        grant_id: identifier("grant_delete_site"),
        nonce: identifier("nonce_delete_site"),
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
        idempotency_key: identifier("key_delete_capture"),
        grant_id: identifier("grant_delete_capture"),
        nonce: identifier("nonce_delete_capture"),
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
fn a_signed_deletion_is_checked_against_the_journal_and_records_nothing() {
    let fixture = BackupFixture::new();
    seed(&fixture);
    let mut executor = Executor::open(fixture.anchor.clone()).unwrap();
    let before = fixture.replay_state();
    let plan: Value = serde_json::from_slice(include_bytes!(
        "../../../contracts/tests/fixtures/delete-plan.json"
    ))
    .unwrap();
    let request = |plan: &Value, site: &str| {
        let bytes = plan.to_string();
        let parsed = DeletePlan::decode(bytes.as_bytes()).unwrap();
        let mut grant: Value = serde_json::from_slice(include_bytes!(
            "../../../contracts/tests/fixtures/delete-grant.json"
        ))
        .unwrap();
        grant["site_ids"] = json!([site]);
        grant["plan_digest"] = json!(parsed.digest());
        let grant = grant.to_string();
        let signature = fixture.sign(grant.as_bytes());
        (bytes, grant, signature)
    };
    let mut exact = plan;
    exact["site_id"] = json!("blog9");
    exact["hostname"] = json!("blog9.example.test");
    exact["capture_operation_id"] = json!("op_capture1");
    let mut other_hostname = exact.clone();
    other_hostname["hostname"] = json!("blog8.example.test");
    let mut unknown = exact.clone();
    unknown["site_id"] = json!("blog8");
    unknown["hostname"] = json!("blog8.example.test");
    for (plan, site, expected) in [
        // Every journal check before intent passes; the next check opens
        // the host's OLS include, which this test host does not hold as a
        // trusted folder.
        (&exact, "blog9", ExecutorError::AccessDenied),
        (&other_hostname, "blog9", ExecutorError::PreconditionChanged),
        (&unknown, "blog8", ExecutorError::PreconditionChanged),
    ] {
        let (bytes, grant, signature) = request(plan, site);
        let admission = AdmissionRequest {
            peer_uid: 4242,
            plan: bytes.as_bytes(),
            grant: grant.as_bytes(),
            signature: &signature,
            operation_id: identifier("op_site_delete"),
            idempotency_key: identifier("key_site_delete"),
            now: Some(time(1200)),
        };
        assert_eq!(
            executor.delete_site(&admission).err(),
            Some(expected),
            "{site} {}",
            plan["hostname"]
        );
    }
    // A grant signed by another key is refused before any check.
    let (bytes, grant, _) = request(&exact, "blog9");
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
        operation_id: identifier("op_site_delete"),
        idempotency_key: identifier("key_site_delete"),
        now: Some(time(1200)),
    };
    assert!(executor.delete_site(&admission).is_err());
    assert_eq!(fixture.replay_state(), before);
}
