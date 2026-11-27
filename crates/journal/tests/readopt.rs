//! W372 (journal v16, D-030): re-adoption records. A re-adoption is
//! admitted `verifying` like any other intent, and only the executor's
//! verified outcome turns it into `adopted` (with a provision row in state
//! `adopted`, or the one generation adoption) or `refused`. Real SQLite; no
//! host effects.
use rustiron_contracts::{
    Id,
    approval::{Hostname, ReadoptForm, ReadoptPlan, SiteId},
};
use rustiron_journal::{
    Admitted, FixtureJournal, JournalError, ProvisionIntent, ProvisionState, ProvisionStep,
    ReadoptOutcome, ReadoptState, Readoption, ReadoptionIntent, SiteAdoption,
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
            "ri-readopt-{}-{}",
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
    fn query(&self, sql: &str) -> i64 {
        rusqlite::Connection::open(self.0.join("fixture-journal.sqlite"))
            .unwrap()
            .query_row(sql, [], |row| row.get(0))
            .unwrap()
    }
}
impl Drop for State {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn site(name: &str) -> SiteId {
    SiteId::try_from(name.to_owned()).unwrap()
}

fn host(name: &str) -> Hostname {
    Hostname::try_from(format!("{name}.example.test")).unwrap()
}

const HEAD: &str = r#""schema_version":1,"plan_id":"plan_readopt","host_id":"host_fixture","host_epoch":"epoch_fixture","profile_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","requester":"agent_1","verb":"site_readopt","previous_epoch":"epoch_old","risk_class":"lab_only","valid_from":1000,"expires_at":2000,"limitations":[]"#;
const EFFECTS: &str = r#""creates_account":false,"creates_database":false,"traffic_activation":false,"network_access":false,"sets_quota":false"#;

/// A canonical site-form plan for `name` bound to the fixture journal.
fn site_plan(name: &str) -> ReadoptPlan {
    let plan = format!(
        r#"{{{HEAD},"form":"site","site_id":"{name}","hostname":"{name}.example.test","quota_limits":{{"block_hard_kib":262144,"inode_hard":20000}},"evidence_sha256":"{c}","observations":[{{"state":"present_unowned","site_id":"{name}","hostname":"{name}.example.test","observed_at":990,"source":"reported_registry"}}],"expected_effects":{{{EFFECTS},"records_ownership":true}}}}"#,
        c = "c".repeat(64)
    );
    ReadoptPlan::decode(plan.as_bytes()).unwrap()
}

fn generation_plan(sites: &[&str]) -> ReadoptPlan {
    let list = sites
        .iter()
        .map(|site| format!("\"{site}\""))
        .collect::<Vec<_>>()
        .join(",");
    let plan = format!(
        r#"{{{HEAD},"form":"generation","target":"ols_lab_listener","expected_generation":"rbc7e46957fb865b0","expected_digest":"{b}","site_ids":[{list}],"evidence_sha256":"{d}","observations":[{{"state":"observed","generation":"rbc7e46957fb865b0","content_digest":"{b}","observed_at":990,"source":"reported_registry"}}],"expected_effects":{{{EFFECTS},"records_generation":true}}}}"#,
        b = "b".repeat(64),
        d = "d".repeat(64)
    );
    ReadoptPlan::decode(plan.as_bytes()).unwrap()
}

fn readoption(n: u32, plan: &ReadoptPlan) -> ReadoptionIntent {
    ReadoptionIntent {
        operation_id: id(&format!("readopt_{n}")),
        idempotency_key: id(&format!("readopt_key_{n}")),
        grant_id: id(&format!("readopt_grant_{n}")),
        nonce: id(&format!("readopt_nonce_{n}")),
        plan_digest: plan.digest(),
        grant_digest: digest('b'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        form: plan.form(),
        site: plan
            .site()
            .map(|(site, hostname, _)| (site.clone(), hostname.clone())),
        previous_epoch: plan.previous_epoch().clone(),
        evidence_sha256: plan.evidence_sha256().clone(),
        expires_at: time(10000),
        plan: String::from_utf8(plan.as_bytes().to_vec()).unwrap(),
    }
}

fn record(ledger: &mut FixtureJournal, intent: &ReadoptionIntent, at: u64) -> Admitted<Readoption> {
    ledger.record_readoption(intent, time(at)).unwrap()
}

fn adopted_site(uid: u32, category: u32) -> SiteAdoption {
    SiteAdoption {
        uid,
        category,
        quota_kib: 262_144,
        quota_inodes: 20_000,
    }
}

fn provisioned(ledger: &mut FixtureJournal, name: &str) -> Id {
    let intent = ProvisionIntent {
        operation_id: id(&format!("prov_{name}")),
        idempotency_key: id(&format!("prov_key_{name}")),
        grant_id: id(&format!("prov_grant_{name}")),
        nonce: id(&format!("prov_nonce_{name}")),
        plan_digest: digest('a'),
        grant_digest: digest('b'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: site(name),
        hostname: host(name),
        expires_at: time(10000),
    };
    ledger.record_provision(&intent, time(900)).unwrap();
    for step in ProvisionStep::ALL {
        let resource = match step {
            ProvisionStep::Account => "Account rs_x uid=3005".to_owned(),
            ProvisionStep::Labels => "Labels rs_x level=s0:c205".to_owned(),
            _ => "r".to_owned(),
        };
        ledger
            .begin_step(&intent.operation_id, step, &resource)
            .unwrap();
        ledger
            .finish_step(&intent.operation_id, step, true)
            .unwrap();
    }
    intent.operation_id
}

#[test]
fn a_fresh_journal_is_v20_and_provisions_admit_the_adopted_state() {
    let state = State::new();
    drop(state.init());
    assert_eq!(state.query("PRAGMA user_version"), 45);
    for table in [
        "readoptions",
        "provision_adoptions",
        "ols_adoptions",
        "allocation_floors",
    ] {
        assert_eq!(
            state.query(&format!(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='{table}'"
            )),
            1,
            "{table}"
        );
    }
    assert_eq!(
        state.query(
            "SELECT instr(sql, '''adopted''') > 0 FROM sqlite_master WHERE name='provisions'"
        ),
        1
    );
}

#[test]
fn a_v16_journal_migrates_and_keeps_every_row_and_the_admission_count() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog1");
    let activation = {
        let mut activation = intent(1);
        activation.resource_id = id("ols_lab_listener");
        activation
    };
    ledger.record_intent(&activation, time(1000)).unwrap();
    let count = ledger.admission_count().unwrap();
    drop(ledger);
    let before = (
        state.query("SELECT count(*) FROM provisions"),
        state.query("SELECT count(*) FROM provision_steps"),
        state.query("SELECT count(*) FROM operations"),
    );
    state.sql(TO_V16);
    assert_eq!(state.query("PRAGMA user_version"), 16);
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
    let mut migrated =
        FixtureJournal::migrate(&state.0, id("host_fixture"), id("epoch_fixture")).unwrap();
    assert_eq!(migrated.admission_count().unwrap(), count);
    assert!(matches!(
        migrated.record_intent(&activation, time(1001)).unwrap(),
        Admitted::Existing(_)
    ));
    let provision = migrated
        .provision_for_site(&site("blog1"))
        .unwrap()
        .unwrap();
    assert_eq!(provision.state, ProvisionState::Succeeded);
    assert_eq!(provision.steps.len(), ProvisionStep::ALL.len());
    drop(migrated);
    assert_eq!(state.query("PRAGMA user_version"), 45);
    assert_eq!(
        (
            state.query("SELECT count(*) FROM provisions"),
            state.query("SELECT count(*) FROM provision_steps"),
            state.query("SELECT count(*) FROM operations"),
        ),
        before
    );
    assert_eq!(
        state.query("SELECT count(*) FROM pragma_foreign_key_check"),
        0
    );
    // The migrated schema is exactly the fresh one, so it opens again.
    let reopened = state.open().unwrap();
    assert_eq!(reopened.admission_count().unwrap(), count);
}

#[test]
fn a_migrated_journal_has_the_fresh_schema_text() {
    let fresh = State::new();
    drop(fresh.init());
    let migrated = State::new();
    drop(migrated.init());
    migrated.sql(TO_V16);
    drop(FixtureJournal::migrate(&migrated.0, id("host_fixture"), id("epoch_fixture")).unwrap());
    let schema = |state: &State| -> Vec<(String, String)> {
        let c = rusqlite::Connection::open(state.0.join("fixture-journal.sqlite")).unwrap();
        let mut query = c
            .prepare("SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name")
            .unwrap();
        query
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert_eq!(schema(&fresh), schema(&migrated));
}

#[test]
fn a_site_readoption_is_verifying_then_adopted_with_an_adopted_provision() {
    let state = State::new();
    let mut ledger = state.init();
    let plan = site_plan("blog1");
    let intent = readoption(1, &plan);
    let Admitted::New(new) = record(&mut ledger, &intent, 1000) else {
        panic!("first record must be new");
    };
    assert_eq!(new.state, ReadoptState::Verifying);
    assert_eq!(new.intent.form, ReadoptForm::Site);
    assert_eq!(ledger.admission_count().unwrap(), 1);
    // An exact repeat is status only.
    assert!(matches!(
        record(&mut ledger, &intent, 1001),
        Admitted::Existing(existing) if existing.state == ReadoptState::Verifying
    ));
    // Verifying holds the site free and records no provision.
    assert_eq!(ledger.provision_for_site(&site("blog1")).unwrap(), None);
    let done = ledger
        .finish_readoption(
            &intent.operation_id,
            ReadoptOutcome::Adopted {
                facts: r#"{"uid":3001}"#,
                site: Some(adopted_site(3001, 201)),
                generation: None,
                floor: Some((3002, 202)),
            },
        )
        .unwrap();
    assert_eq!(done.state, ReadoptState::Adopted);
    assert_eq!(done.facts.as_deref(), Some(r#"{"uid":3001}"#));
    let provision = ledger.provision_for_site(&site("blog1")).unwrap().unwrap();
    assert_eq!(provision.state, ProvisionState::Adopted);
    assert!(provision.steps.is_empty());
    assert_eq!(provision.intent.operation_id, intent.operation_id);
    assert_eq!(provision.intent.hostname, host("blog1"));
    assert_eq!(
        ledger.site_adoption(&intent.operation_id).unwrap(),
        Some(adopted_site(3001, 201))
    );
    assert_eq!(ledger.succeeded_sites().unwrap(), vec![site("blog1")]);
    assert_eq!(
        ledger.adopted_allocations().unwrap(),
        (vec![3001], vec![201])
    );
    assert_eq!(ledger.allocation_floor().unwrap(), Some((3002, 202)));
    // The adopted provision row is not a second admission.
    assert_eq!(ledger.admission_count().unwrap(), 1);
    assert!(
        ledger
            .finish_readoption(
                &intent.operation_id,
                ReadoptOutcome::Refused {
                    facts: "{}",
                    code: "READOPT_MISMATCH",
                    rule: "account",
                },
            )
            .is_err()
    );
    drop(ledger);
    let ledger = state.open().unwrap();
    assert_eq!(
        ledger
            .readoption_status(&intent.operation_id)
            .unwrap()
            .unwrap()
            .state,
        ReadoptState::Adopted
    );
}

#[test]
fn a_refused_readoption_keeps_only_its_row_and_the_site_stays_free() {
    let state = State::new();
    let mut ledger = state.init();
    let first = readoption(1, &site_plan("blog1"));
    record(&mut ledger, &first, 1000);
    let refused = ledger
        .finish_readoption(
            &first.operation_id,
            ReadoptOutcome::Refused {
                facts: r#"{"database":"foreign_grant"}"#,
                code: "READOPT_MISMATCH",
                rule: "database",
            },
        )
        .unwrap();
    assert_eq!(refused.state, ReadoptState::Refused);
    assert_eq!(
        refused.refusal,
        Some(("READOPT_MISMATCH".to_owned(), "database".to_owned()))
    );
    assert_eq!(ledger.provision_for_site(&site("blog1")).unwrap(), None);
    assert_eq!(ledger.allocation_floor().unwrap(), None);
    // A corrected plan, with a new grant, may re-adopt the same site.
    let second = readoption(2, &site_plan("blog1"));
    assert!(matches!(
        record(&mut ledger, &second, 1010),
        Admitted::New(_)
    ));
    assert_eq!(ledger.admission_count().unwrap(), 2);
}

#[test]
fn a_verifying_readoption_blocks_every_other_admission() {
    let state = State::new();
    let mut ledger = state.init();
    let pending = readoption(1, &site_plan("blog1"));
    record(&mut ledger, &pending, 1000);
    assert_eq!(
        ledger.record_intent(&intent(1), time(1001)).err(),
        Some(JournalError::Busy)
    );
    let provision = ProvisionIntent {
        operation_id: id("prov_other"),
        idempotency_key: id("prov_key_other"),
        grant_id: id("prov_grant_other"),
        nonce: id("prov_nonce_other"),
        plan_digest: digest('a'),
        grant_digest: digest('b'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        site_id: site("other"),
        hostname: host("other"),
        expires_at: time(10000),
    };
    assert_eq!(
        ledger.record_provision(&provision, time(1001)).err(),
        Some(JournalError::Busy)
    );
    let second = readoption(2, &site_plan("blog2"));
    assert_eq!(
        ledger.record_readoption(&second, time(1001)).err(),
        Some(JournalError::Busy)
    );
}

#[test]
fn an_unresolved_operation_or_running_provision_blocks_a_readoption() {
    let state = State::new();
    let mut ledger = state.init();
    ledger.record_intent(&intent(1), time(1000)).unwrap();
    assert_eq!(
        ledger
            .record_readoption(&readoption(1, &site_plan("blog1")), time(1001))
            .err(),
        Some(JournalError::Busy)
    );
}

#[test]
fn a_provisioned_site_or_hostname_cannot_be_readopted() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog1");
    assert_eq!(
        ledger
            .record_readoption(&readoption(1, &site_plan("blog1")), time(1000))
            .err(),
        Some(JournalError::Consumed)
    );
}

#[test]
fn replayed_grants_nonces_and_operations_are_conflicts() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog9");
    let mut reused = readoption(1, &site_plan("blog1"));
    reused.nonce = id("prov_nonce_blog9");
    assert_eq!(
        ledger.record_readoption(&reused, time(1000)).err(),
        Some(JournalError::Conflict)
    );
    let first = readoption(1, &site_plan("blog1"));
    record(&mut ledger, &first, 1000);
    let mut same_key = readoption(2, &site_plan("blog1"));
    same_key.idempotency_key = first.idempotency_key.clone();
    assert_eq!(
        ledger.record_readoption(&same_key, time(1001)).err(),
        Some(JournalError::Conflict)
    );
    // A plan that does not hash to the recorded digest is refused.
    let mut forged = readoption(3, &site_plan("blog3"));
    forged.plan_digest = digest('f');
    ledger
        .finish_readoption(
            &first.operation_id,
            ReadoptOutcome::Refused {
                facts: "{}",
                code: "READOPT_MISMATCH",
                rule: "account",
            },
        )
        .unwrap();
    assert_eq!(
        ledger.record_readoption(&forged, time(1002)).err(),
        Some(JournalError::Conflict)
    );
}

#[test]
fn one_generation_adoption_per_journal() {
    let state = State::new();
    let mut ledger = state.init();
    let plan = generation_plan(&["blog1"]);
    let first = readoption(1, &plan);
    record(&mut ledger, &first, 1000);
    assert_eq!(ledger.ols_adoption().unwrap(), None);
    let (generation, digest, _) = plan.generation().unwrap();
    ledger
        .finish_readoption(
            &first.operation_id,
            ReadoptOutcome::Adopted {
                facts: "{}",
                site: None,
                generation: Some((generation.clone(), digest.clone())),
                floor: None,
            },
        )
        .unwrap();
    assert_eq!(
        ledger.ols_adoption().unwrap(),
        Some((generation.clone(), digest.clone()))
    );
    let second = readoption(2, &generation_plan(&["blog1"]));
    assert_eq!(
        ledger.record_readoption(&second, time(1010)).err(),
        Some(JournalError::Consumed)
    );
}

#[test]
fn an_outcome_must_match_its_form() {
    let state = State::new();
    let mut ledger = state.init();
    let site_form = readoption(1, &site_plan("blog1"));
    record(&mut ledger, &site_form, 1000);
    assert_eq!(
        ledger
            .finish_readoption(
                &site_form.operation_id,
                ReadoptOutcome::Adopted {
                    facts: "{}",
                    site: None,
                    generation: Some((id("r0123456789abcdef"), digest('e'))),
                    floor: None,
                },
            )
            .err(),
        Some(JournalError::Conflict)
    );
    let too_long = "x".repeat(4097);
    assert_eq!(
        ledger
            .finish_readoption(
                &site_form.operation_id,
                ReadoptOutcome::Refused {
                    facts: &too_long,
                    code: "READOPT_MISMATCH",
                    rule: "account",
                },
            )
            .err(),
        Some(JournalError::Conflict)
    );
    assert_eq!(
        ledger
            .readoption_status(&site_form.operation_id)
            .unwrap()
            .unwrap()
            .state,
        ReadoptState::Verifying
    );
}

#[test]
fn a_planted_adopted_provision_without_its_readoption_is_refused_on_open() {
    let state = State::new();
    drop(state.init());
    state.sql(
        "INSERT INTO provisions VALUES('op_x','key_x','grant_x','nonce_x','aa','bb','host_fixture','epoch_fixture','blog1','blog1.example.test',10000,'adopted')",
    );
    assert_eq!(state.open().err(), Some(JournalError::Unavailable));
}

#[test]
fn ejections_and_page_cache_accept_an_adopted_site() {
    let state = State::new();
    let mut ledger = state.init();
    let intent = readoption(1, &site_plan("blog1"));
    record(&mut ledger, &intent, 1000);
    ledger
        .finish_readoption(
            &intent.operation_id,
            ReadoptOutcome::Adopted {
                facts: "{}",
                site: Some(adopted_site(3001, 201)),
                generation: None,
                floor: None,
            },
        )
        .unwrap();
    let mut activation = rustiron_journal::Intent {
        resource_id: id("ols_lab_listener"),
        ..support::intent(5)
    };
    activation.expires_at = time(20000);
    activation.compensation_valid_until = time(20300);
    assert!(matches!(
        ledger
            .record_page_cache_intent(
                &activation,
                &site("blog1"),
                "litespeed_cache_793_v1",
                time(1100)
            )
            .unwrap(),
        Admitted::New(_)
    ));
    drop(ledger);
    assert!(state.open().is_ok());
}

/// W379: the read-only observation gives a provisioned site its journaled
/// Directories resource and an adopted site the quota its re-adoption verified.
#[test]
fn the_observation_carries_the_recorded_quota_of_provisioned_and_adopted_sites() {
    let state = State::new();
    let mut ledger = state.init();
    provisioned(&mut ledger, "blog2");
    let plan = site_plan("blog1");
    let intent = readoption(1, &plan);
    record(&mut ledger, &intent, 1000);
    ledger
        .finish_readoption(
            &intent.operation_id,
            ReadoptOutcome::Adopted {
                facts: r#"{"uid":3001}"#,
                site: Some(adopted_site(3001, 201)),
                generation: None,
                floor: Some((3002, 202)),
            },
        )
        .unwrap();
    drop(ledger);
    let seen =
        FixtureJournal::observe(&state.0, &id("host_fixture"), &id("epoch_fixture")).unwrap();
    let provisioned = &seen.provisions[0];
    assert_eq!(provisioned.site_id, "blog2");
    assert_eq!(provisioned.directories_resource.as_deref(), Some("r"));
    assert_eq!(provisioned.adopted_quota, None);
    let adopted = &seen.provisions[1];
    assert_eq!(adopted.site_id, "blog1");
    assert_eq!(adopted.state, "adopted");
    assert_eq!(adopted.directories_resource, None);
    assert_eq!(adopted.adopted_quota, Some((262_144, 20_000)));
}
