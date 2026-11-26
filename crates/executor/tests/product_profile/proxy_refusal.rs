//! W574 (D-095): a proxy site has no WordPress, so the update inventory
//! refuses it before it asks the admin helper. W576: only a proxy site is
//! deleted without a capture. Against real SQLite fixture records; nothing
//! is recorded.

use rustiron_contracts::approval::{DeletePlan, ProxyRoute};
use rustiron_journal::ProxyFacts;

use super::*;

fn time(seconds: u64) -> Timestamp {
    Timestamp::try_from(seconds).unwrap()
}

fn identifier(value: &str) -> rustiron_contracts::Id {
    value.to_owned().try_into().unwrap()
}

fn intent(site: &str, number: u8) -> ProvisionIntent {
    ProvisionIntent {
        operation_id: identifier(&format!("op_{site}")),
        idempotency_key: identifier(&format!("key_{site}")),
        grant_id: identifier(&format!("grant_{site}")),
        nonce: identifier(&format!("nonce_{site}")),
        plan_digest: Sha256Digest::from_bytes([number; 32]),
        grant_digest: Sha256Digest::from_bytes([number + 1; 32]),
        host_id: identifier("host_lab"),
        host_epoch: identifier("epoch_1"),
        site_id: site.to_owned().try_into().unwrap(),
        hostname: format!("{site}.example.test").try_into().unwrap(),
        expires_at: time(1400),
    }
}

/// A served WordPress site `blog9` and a served proxy site `ytproxy`.
fn seed(fixture: &BackupFixture) {
    drop(Executor::initialize(fixture.anchor.clone()).unwrap());
    let mut journal = FixtureJournal::open_as_process_owner(
        &fixture.anchor.journal_dir,
        identifier("host_lab"),
        identifier("epoch_1"),
    )
    .unwrap();
    let blog = intent("blog9", 1);
    journal.record_provision(&blog, time(1000)).unwrap();
    let proxy = intent("ytproxy", 3);
    for (site, proxied) in [(&blog, false), (&proxy, true)] {
        if proxied {
            let facts = ProxyFacts {
                routes: vec![ProxyRoute {
                    prefix: "/".to_owned(),
                    port: 3100,
                }],
                websockets: Vec::new(),
            };
            journal
                .record_proxy_provision(site, &facts, time(1001))
                .unwrap();
        }
        for step in ProvisionStep::ALL {
            journal
                .begin_step(&site.operation_id, step, "synthetic")
                .unwrap();
            journal.finish_step(&site.operation_id, step, true).unwrap();
        }
    }
}

#[test]
fn the_update_inventory_refuses_a_proxy_site() {
    let fixture = BackupFixture::new();
    seed(&fixture);
    let executor = Executor::open(fixture.anchor.clone()).unwrap();
    let before = fixture.replay_state();
    // A WordPress site passes the journal checks and stops at the missing
    // admin helper; the proxy site stops before it.
    assert_eq!(
        executor
            .update_inventory(&"blog9".to_owned().try_into().unwrap())
            .err(),
        Some(ExecutorError::Unavailable)
    );
    assert_eq!(
        executor
            .update_inventory(&"ytproxy".to_owned().try_into().unwrap())
            .err(),
        Some(ExecutorError::PreconditionChanged)
    );
    assert_eq!(fixture.replay_state(), before);
}

/// W576 (D-095): a schema 2 deletion (no capture) passes the journal checks
/// for the proxy site and stops at the host's OLS include; for a WordPress
/// site it is refused, and a proxy site cannot name a capture.
#[test]
fn only_a_proxy_site_is_deleted_without_a_capture() {
    let fixture = BackupFixture::new();
    seed(&fixture);
    let mut executor = Executor::open(fixture.anchor.clone()).unwrap();
    let before = fixture.replay_state();
    let plan: Value = serde_json::from_slice(include_bytes!(
        "../../../contracts/tests/fixtures/delete-plan.json"
    ))
    .unwrap();
    let plan_for = |site: &str, capture: Option<&str>| {
        let mut plan = plan.clone();
        plan["site_id"] = json!(site);
        plan["hostname"] = json!(format!("{site}.example.test"));
        match capture {
            Some(capture) => plan["capture_operation_id"] = json!(capture),
            None => {
                plan["schema_version"] = json!(2);
                plan.as_object_mut().unwrap().remove("capture_operation_id");
            }
        }
        plan
    };
    for (site, capture, expected) in [
        // Every journal check before intent passes; the next check opens
        // the host's OLS include, which this test host does not hold.
        ("ytproxy", None, ExecutorError::AccessDenied),
        ("blog9", None, ExecutorError::PreconditionChanged),
        (
            "ytproxy",
            Some("op_capture1"),
            ExecutorError::PreconditionChanged,
        ),
    ] {
        let bytes = plan_for(site, capture).to_string();
        let parsed = DeletePlan::decode(bytes.as_bytes()).unwrap();
        let mut grant: Value = serde_json::from_slice(include_bytes!(
            "../../../contracts/tests/fixtures/delete-grant.json"
        ))
        .unwrap();
        grant["site_ids"] = json!([site]);
        grant["plan_digest"] = json!(parsed.digest());
        let grant = grant.to_string();
        let signature = fixture.sign(grant.as_bytes());
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
            "{site} {capture:?}"
        );
    }
    assert_eq!(fixture.replay_state(), before);
}
