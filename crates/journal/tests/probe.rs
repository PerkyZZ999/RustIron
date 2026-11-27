//! Restore probe journal behavior on real SQLite; no host effects.
use rustiron_contracts::approval::{Hostname, SiteId, SnapshotId};
use rustiron_journal::{
    Admitted, FixtureJournal, JournalError, ProbeIntent, ProbeState, ProvisionIntent, ProvisionStep,
};
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
mod support;
use support::*;

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct State(PathBuf);
impl State {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ri-probe-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn init(&self) -> FixtureJournal {
        FixtureJournal::initialize(&self.0, id("host_fixture"), id("epoch_fixture")).unwrap()
    }
    fn open(&self) -> Result<FixtureJournal, JournalError> {
        FixtureJournal::open(&self.0, id("host_fixture"), id("epoch_fixture"))
    }
    fn sql(&self, sql: &str) {
        rusqlite::Connection::open(self.0.join("fixture-journal.sqlite"))
            .unwrap()
            .execute_batch(sql)
            .unwrap();
    }
}
impl Drop for State {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn provisioned(ledger: &mut FixtureJournal, site: &str) {
    let intent = ProvisionIntent {
        operation_id: id(&format!("prov_{site}")),
        idempotency_key: id(&format!("prov_key_{site}")),
        grant_id: id(&format!("prov_grant_{site}")),
        nonce: id(&format!("prov_nonce_{site}")),
        plan_digest: digest('a'),
        grant_digest: digest('b'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: SiteId::try_from(site.to_owned()).unwrap(),
        hostname: Hostname::try_from(format!("{site}.example.test")).unwrap(),
        expires_at: time(10000),
    };
    ledger.record_provision(&intent, time(900)).unwrap();
    for step in ProvisionStep::ALL {
        ledger.begin_step(&intent.operation_id, step, "r").unwrap();
        ledger
            .finish_step(&intent.operation_id, step, true)
            .unwrap();
    }
}

fn probe(n: u32, site: &str, account: &str) -> ProbeIntent {
    ProbeIntent {
        operation_id: id(&format!("probe_{n}")),
        idempotency_key: id(&format!("probe_key_{n}")),
        grant_id: id(&format!("probe_grant_{n}")),
        nonce: id(&format!("probe_nonce_{n}")),
        plan_digest: digest('c'),
        grant_digest: digest('d'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: SiteId::try_from(site.to_owned()).unwrap(),
        snapshot_id: SnapshotId::try_from("a".repeat(64)).unwrap(),
        probe_account: account.to_owned(),
        expires_at: time(10000),
    }
}

#[test]
fn a_probe_records_its_account_before_effects_and_blocks_until_cleaned() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog13");
    assert_eq!(
        ledger
            .record_probe(&probe(1, "blog13", "rp_xyz"), time(1000), &digest('e'))
            .err(),
        Some(JournalError::Conflict),
        "malformed probe account"
    );
    let first = probe(1, "blog13", "rp_00aa11");
    assert!(matches!(
        ledger
            .record_probe(&first, time(1000), &digest('e'))
            .unwrap(),
        Admitted::New(_)
    ));
    assert!(matches!(
        ledger
            .record_probe(&first, time(1000), &digest('e'))
            .unwrap(),
        Admitted::Existing(_)
    ));
    drop(ledger);
    let mut ledger = state.open().unwrap();
    let stored = ledger.probe_status(&first.operation_id).unwrap().unwrap();
    assert_eq!(stored.state, ProbeState::Running);
    assert_eq!(stored.backup_policy_digest, Some(digest('e')));
    assert_eq!(stored.intent.probe_account, "rp_00aa11");
    assert_eq!(
        ledger
            .record_probe(&probe(2, "blog13", "rp_00aa12"), time(1001), &digest('e'))
            .err(),
        Some(JournalError::Busy)
    );
    ledger
        .finish_probe(
            &first.operation_id,
            ProbeState::CleanupIncomplete,
            "{}",
            time(1002),
        )
        .unwrap();
    assert_eq!(
        ledger
            .record_probe(&probe(2, "blog13", "rp_00aa12"), time(1003), &digest('e'))
            .err(),
        Some(JournalError::Busy),
        "leftover resources block new probes"
    );
    assert_eq!(
        ledger
            .finish_probe(&first.operation_id, ProbeState::Passed, "{}", time(1004))
            .err(),
        Some(JournalError::Conflict),
        "only admin cleanup may close it, as failed"
    );
    ledger
        .finish_probe(
            &first.operation_id,
            ProbeState::Failed,
            "{\"cleanup\":0}",
            time(1004),
        )
        .unwrap();
    assert!(matches!(
        ledger
            .record_probe(&probe(2, "blog13", "rp_00aa12"), time(1005), &digest('e'))
            .unwrap(),
        Admitted::New(_)
    ));
    assert_eq!(
        ledger
            .record_probe(&probe(3, "blog13", "rp_00aa12"), time(1006), &digest('e'))
            .err(),
        Some(JournalError::Conflict),
        "probe accounts are never reused"
    );
}

#[test]
fn a_finished_probe_without_a_receipt_is_refused_on_open() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog13");
    let first = probe(1, "blog13", "rp_00aa11");
    ledger
        .record_probe(&first, time(1000), &digest('e'))
        .unwrap();
    ledger
        .finish_probe(&first.operation_id, ProbeState::Passed, "{}", time(1001))
        .unwrap();
    drop(ledger);
    state.sql("UPDATE restore_probes SET receipt=NULL;");
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
}

#[test]
fn a_fixture_nonce_cannot_start_a_probe() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog13");
    let fixture = intent(7);
    ledger.record_intent(&fixture, time(1000)).unwrap();
    let mut reused = probe(1, "blog13", "rp_00aa11");
    reused.nonce = fixture.nonce.clone();
    assert_eq!(
        ledger.record_probe(&reused, time(1001), &digest('e')).err(),
        Some(JournalError::Conflict)
    );
}
