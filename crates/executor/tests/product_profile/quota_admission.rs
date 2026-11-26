//! W535 (D-088): a signed `site_quota` change is checked against real
//! SQLite fixture records and the enrolled policy before its intent, and
//! nothing is recorded.

use rustiron_contracts::approval::QuotaPlan;
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
        operation_id: identifier("op_quota_site"),
        idempotency_key: identifier("key_quota_site"),
        grant_id: identifier("grant_quota_site"),
        nonce: identifier("nonce_quota_site"),
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
        idempotency_key: identifier("key_quota_capture"),
        grant_id: identifier("grant_quota_capture"),
        nonce: identifier("nonce_quota_capture"),
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
fn a_signed_quota_change_is_checked_before_intent_and_records_nothing() {
    let fixture = BackupFixture::new();
    seed(&fixture);
    let mut executor = Executor::open(fixture.anchor.clone()).unwrap();
    let before = fixture.replay_state();
    let plan: Value = serde_json::from_slice(include_bytes!(
        "../../../contracts/tests/fixtures/quota-plan.json"
    ))
    .unwrap();
    let request = |plan: &Value, site: &str| {
        let bytes = plan.to_string();
        let parsed = QuotaPlan::decode(bytes.as_bytes()).unwrap();
        let mut grant: Value = serde_json::from_slice(include_bytes!(
            "../../../contracts/tests/fixtures/quota-grant.json"
        ))
        .unwrap();
        grant["site_ids"] = json!([site]);
        grant["plan_digest"] = json!(parsed.digest());
        let grant = grant.to_string();
        let signature = fixture.sign(grant.as_bytes());
        (bytes, grant, signature)
    };
    let mut exact = plan.clone();
    exact["site_id"] = json!("blog9");
    let mut unknown = exact.clone();
    unknown["site_id"] = json!("blog8");
    let mut above_cap = exact.clone();
    above_cap["quota_limits"] =
        json!({"block_hard_kib": 16_u64 * 1024 * 1024 * 1024, "inode_hard": 100_000_000});
    for (plan, site, expected) in [
        (&exact, "blog9", ExecutorError::Unavailable),
        (&unknown, "blog8", ExecutorError::PreconditionChanged),
        (&above_cap, "blog9", ExecutorError::PreconditionChanged),
    ] {
        let (bytes, grant, signature) = request(plan, site);
        let admission = AdmissionRequest {
            peer_uid: 4242,
            plan: bytes.as_bytes(),
            grant: grant.as_bytes(),
            signature: &signature,
            operation_id: identifier("op_site_quota"),
            idempotency_key: identifier("key_site_quota"),
            now: Some(time(1200)),
        };
        assert_eq!(
            executor.change_quota(&admission).err(),
            Some(expected),
            "{site} {}",
            plan["quota_limits"]
        );
    }
    assert_eq!(fixture.replay_state(), before);
}
