//! W462 (journal v23, D-059): one signed certificate issuance per managed
//! site at a time. Real SQLite; no host effects.
use rustiron_contracts::approval::{Hostname, SiteId};
use rustiron_journal::{
    Admitted, CertificateIntent, CertificateState, FixtureJournal, JournalError, ProvisionIntent,
    ProvisionStep,
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
            "ri-cert-{}-{}",
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
    fn migrate(&self) -> Result<FixtureJournal, JournalError> {
        FixtureJournal::migrate(&self.0, id("host_fixture"), id("epoch_fixture"))
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

fn site(n: u32) -> ProvisionIntent {
    ProvisionIntent {
        operation_id: id(&format!("site_op_{n}")),
        idempotency_key: id(&format!("site_key_{n}")),
        grant_id: id(&format!("site_grant_{n}")),
        nonce: id(&format!("site_nonce_{n}")),
        plan_digest: digest('a'),
        grant_digest: digest('b'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: SiteId::try_from(format!("blog{n}")).unwrap(),
        hostname: Hostname::try_from(format!("blog{n}.example.test")).unwrap(),
        expires_at: time(10000),
    }
}

/// A provision whose steps all succeeded.
fn served(ledger: &mut FixtureJournal, intent: &ProvisionIntent, at: u64) {
    ledger.record_provision(intent, time(at)).unwrap();
    for step in ProvisionStep::ALL {
        ledger
            .begin_step(&intent.operation_id, step, "resource")
            .unwrap();
        ledger
            .finish_step(&intent.operation_id, step, true)
            .unwrap();
    }
}

fn certificate(site: &ProvisionIntent, n: u32) -> CertificateIntent {
    CertificateIntent {
        operation_id: id(&format!("cert_op_{n}")),
        idempotency_key: id(&format!("cert_key_{n}")),
        grant_id: id(&format!("cert_grant_{n}")),
        nonce: id(&format!("cert_nonce_{n}")),
        plan_digest: digest('c'),
        grant_digest: digest('d'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: site.site_id.clone(),
        hostname: site.hostname.clone(),
        alias_hostname: None,
        expires_at: time(10000),
        renew_until: None,
    }
}

#[test]
fn an_issuance_is_admitted_once_installed_and_served_from_the_journal() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    served(&mut ledger, &one, 1000);
    let before = ledger.admission_count().unwrap();
    let first = certificate(&one, 1);
    assert!(matches!(
        ledger.record_certificate(&first, time(1100)).unwrap(),
        Admitted::New(row) if row.state == CertificateState::Intent
    ));
    assert_eq!(ledger.admission_count().unwrap(), before + 1);
    assert!(matches!(
        ledger.record_certificate(&first, time(1101)).unwrap(),
        Admitted::Existing(_)
    ));
    let mut other = first.clone();
    other.plan_digest = digest('9');
    assert_eq!(
        ledger.record_certificate(&other, time(1102)).err(),
        Some(JournalError::Conflict)
    );
    assert_eq!(
        ledger
            .record_certificate(&certificate(&one, 2), time(1103))
            .err(),
        Some(JournalError::Busy),
        "an open issuance blocks another"
    );
    assert_eq!(ledger.installed_certificate(&one.site_id).unwrap(), None);
    let row = ledger
        .finish_certificate(&first.operation_id, Some((&digest('e'), time(9000))))
        .unwrap();
    assert_eq!(row.state, CertificateState::Installed);
    assert_eq!(
        ledger.installed_certificate(&one.site_id).unwrap(),
        Some((digest('e'), time(9000)))
    );
    assert_eq!(
        ledger.finish_certificate(&first.operation_id, None).err(),
        Some(JournalError::Conflict),
        "a settled issuance is not finished again"
    );
    // A later failed issuance keeps the installed certificate served.
    let second = certificate(&one, 3);
    ledger.record_certificate(&second, time(1104)).unwrap();
    ledger
        .finish_certificate(&second.operation_id, None)
        .unwrap();
    assert_eq!(
        ledger.installed_certificate(&one.site_id).unwrap(),
        Some((digest('e'), time(9000)))
    );
    drop(ledger);
    let ledger = state.open().unwrap();
    assert_eq!(
        ledger
            .certificate_status(&second.operation_id)
            .unwrap()
            .unwrap()
            .state,
        CertificateState::Failed
    );
}

#[test]
fn an_issuance_needs_an_owned_site_with_its_hostname() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    assert_eq!(
        ledger
            .record_certificate(&certificate(&one, 1), time(1000))
            .err(),
        Some(JournalError::Conflict),
        "no such site"
    );
    ledger.record_provision(&one, time(1001)).unwrap();
    assert_eq!(
        ledger
            .record_certificate(&certificate(&one, 2), time(1002))
            .err(),
        Some(JournalError::Busy),
        "a running provision"
    );
    ledger.quarantine_provision(&one.operation_id).unwrap();
    assert_eq!(
        ledger
            .record_certificate(&certificate(&one, 3), time(1003))
            .err(),
        Some(JournalError::Conflict),
        "a quarantined site"
    );
    let two = site(2);
    served(&mut ledger, &two, 1003);
    let mut wrong = certificate(&two, 4);
    wrong.hostname = Hostname::try_from("other.example.test".to_owned()).unwrap();
    assert_eq!(
        ledger.record_certificate(&wrong, time(1004)).err(),
        Some(JournalError::Conflict)
    );
    let mut reused = certificate(&two, 5);
    reused.nonce = two.nonce.clone();
    assert_eq!(
        ledger.record_certificate(&reused, time(1005)).err(),
        Some(JournalError::Conflict),
        "the provision's nonce"
    );
    let mut late = certificate(&two, 6);
    late.expires_at = time(1006);
    assert_eq!(
        ledger.record_certificate(&late, time(1006)).err(),
        Some(JournalError::Expired)
    );
}

#[test]
fn a_v22_journal_migrates_to_v23() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    served(&mut ledger, &one, 1000);
    drop(ledger);
    state.sql(&legacy_import_schema(22));
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let mut ledger = state.migrate().unwrap();
    assert!(matches!(
        ledger
            .record_certificate(&certificate(&one, 1), time(1100))
            .unwrap(),
        Admitted::New(_)
    ));
    drop(ledger);
    assert!(state.open().is_ok());
}

/// W464 (D-060): an issuance with a renewal window, installed, expiring at
/// `not_after`.
fn granted(
    ledger: &mut FixtureJournal,
    site: &ProvisionIntent,
    n: u32,
    at: u64,
    renew_until: u64,
    not_after: u64,
) -> CertificateIntent {
    let mut intent = certificate(site, n);
    intent.renew_until = Some(time(renew_until));
    ledger.record_certificate(&intent, time(at)).unwrap();
    ledger
        .finish_certificate(&intent.operation_id, Some((&digest('e'), time(not_after))))
        .unwrap();
    intent
}

const DAY: u64 = 24 * 3600;

#[test]
fn a_renewal_is_due_inside_its_window_and_then_serves_the_new_chain() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    served(&mut ledger, &one, 1000);
    let issued = granted(
        &mut ledger,
        &one,
        1,
        1100,
        1100 + 300 * DAY,
        1100 + 90 * DAY,
    );
    // Not yet within 30 days of expiry.
    assert!(
        ledger
            .due_renewals(time(1100 + 59 * DAY))
            .unwrap()
            .is_empty()
    );
    let at = 1100 + 61 * DAY;
    let due = ledger.due_renewals(time(at)).unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].operation_id, issued.operation_id);
    let before = ledger.admission_count().unwrap();
    let renewal = ledger
        .begin_renewal(&due[0], &id("rn_1"), time(at))
        .unwrap();
    assert_eq!(renewal.state, CertificateState::Intent);
    assert_eq!(
        ledger.admission_count().unwrap(),
        before,
        "not an admission"
    );
    let mut blocked = certificate(&one, 2);
    blocked.expires_at = time(at + DAY);
    assert_eq!(
        ledger.record_certificate(&blocked, time(at + 1)).err(),
        Some(JournalError::Busy),
        "an open renewal blocks admissions"
    );
    ledger
        .finish_renewal(&id("rn_1"), Some((&digest('f'), time(at + 90 * DAY))))
        .unwrap();
    assert_eq!(
        ledger.installed_certificate(&one.site_id).unwrap(),
        Some((digest('f'), time(at + 90 * DAY))),
        "the renewal is served"
    );
    assert!(
        ledger.due_renewals(time(at + 1)).unwrap().is_empty(),
        "not due now"
    );
}

#[test]
fn a_failed_renewal_backs_off_and_a_closed_window_renews_nothing() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    served(&mut ledger, &one, 1000);
    granted(&mut ledger, &one, 1, 1100, 1100 + 70 * DAY, 1100 + 90 * DAY);
    let at = 1100 + 61 * DAY;
    let due = ledger.due_renewals(time(at)).unwrap();
    ledger
        .begin_renewal(&due[0], &id("rn_1"), time(at))
        .unwrap();
    ledger.finish_renewal(&id("rn_1"), None).unwrap();
    assert_eq!(
        ledger.installed_certificate(&one.site_id).unwrap(),
        Some((digest('e'), time(1100 + 90 * DAY))),
        "the failed renewal keeps the served chain"
    );
    assert!(
        ledger.due_renewals(time(at + 3600)).unwrap().is_empty(),
        "backed off"
    );
    assert_eq!(ledger.due_renewals(time(at + 7 * 3600)).unwrap().len(), 1);
    assert!(
        ledger
            .due_renewals(time(1100 + 71 * DAY))
            .unwrap()
            .is_empty(),
        "after renew_until"
    );
    assert_eq!(
        ledger
            .begin_renewal(&due[0], &id("rn_2"), time(1100 + 71 * DAY))
            .err(),
        Some(JournalError::Conflict),
        "not due"
    );
    assert_eq!(
        ledger.finish_renewal(&id("rn_1"), None).err(),
        Some(JournalError::Conflict),
        "settled"
    );
}

#[test]
fn an_issuance_without_a_window_is_never_renewed() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    served(&mut ledger, &one, 1000);
    let first = certificate(&one, 1);
    ledger.record_certificate(&first, time(1100)).unwrap();
    ledger
        .finish_certificate(&first.operation_id, Some((&digest('e'), time(1200))))
        .unwrap();
    assert!(ledger.due_renewals(time(1150)).unwrap().is_empty());
}

#[test]
fn a_v23_journal_migrates_to_v24() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    served(&mut ledger, &one, 1000);
    drop(ledger);
    state.sql(&legacy_import_schema(23));
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let mut ledger = state.migrate().unwrap();
    granted(&mut ledger, &one, 1, 1100, 1100 + DAY, 1100 + 2 * DAY);
    drop(ledger);
    assert!(state.open().is_ok());
}

/// W469 (P08): an ejected site is not renewed and gets no new issuance; D-064:
/// its certificate is still observed, marked ejected.
#[test]
fn an_ejected_site_is_not_renewed_or_issued() {
    let state = State::new();
    let mut ledger = state.init();
    let one = site(1);
    served(&mut ledger, &one, 1000);
    granted(
        &mut ledger,
        &one,
        1,
        1100,
        1100 + 300 * DAY,
        1100 + 90 * DAY,
    );
    let at = 1100 + 61 * DAY;
    assert_eq!(ledger.due_renewals(time(at)).unwrap().len(), 1);
    let seen = || {
        FixtureJournal::observe(&state.0, &id("host_fixture"), &id("epoch_fixture"))
            .unwrap()
            .certificates
            .iter()
            .map(|served| served.ejected)
            .collect::<Vec<_>>()
    };
    assert_eq!(seen(), [false]);
    let mut eject = intent(9);
    eject.resource_id = id("ols_lab_listener");
    eject.expires_at = time(at + DAY);
    eject.compensation_valid_until = time(at + 2 * DAY);
    ledger
        .record_ejection_intent(&eject, &one.site_id, time(at))
        .unwrap();
    ledger
        .record_observation(
            &eject.operation_id,
            Some(&eject.target_generation),
            Some(&eject.target_digest),
        )
        .unwrap();
    assert_eq!(
        ledger.ejected_sites().unwrap(),
        std::slice::from_ref(&one.site_id)
    );
    assert!(ledger.due_renewals(time(at)).unwrap().is_empty());
    assert_eq!(seen(), [true], "still served, no longer renewed (D-064)");
    let mut again = certificate(&one, 2);
    again.expires_at = time(at + DAY);
    assert_eq!(
        ledger.record_certificate(&again, time(at + 1)).err(),
        Some(JournalError::Conflict)
    );
}
