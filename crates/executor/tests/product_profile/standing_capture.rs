//! W386 (D-035): admission of standing captures (plan and grant schema 3)
//! against a stub helper. The executor derives each run identity from the
//! signed grant and checks the window with its own clock.

use std::{
    sync::atomic::Ordering,
    time::{SystemTime, UNIX_EPOCH},
};

use rustiron_contracts::{
    Id,
    approval::{SiteId, StandingCaptureGrant, StandingRun},
    execution::OutcomeState,
};
use rustiron_executor::{Executor, ExecutorError};
use rustiron_journal::CaptureState;
use serde_json::{Value, json};

use super::{
    BackupFixture,
    admission::{id, provision, provision_in, stub_helper_for},
    verification::{SignedBackup, enroll},
};

const VECTORS: &str =
    include_str!("../../../contracts/tests/fixtures/standing-capture-vectors.json");

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The compressed vector (period 300 s, window 120 s, 6 windows, `blog9`)
/// with window 0 opening `offset` seconds before now.
pub(super) fn standing(offset: u64, sites: &[&str]) -> (Value, Value) {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    let vector = vectors
        .into_iter()
        .find(|v| v["name"] == "compressed")
        .unwrap();
    let mut plan: Value = serde_json::from_str(vector["plan_canonical"].as_str().unwrap()).unwrap();
    let mut grant: Value =
        serde_json::from_str(vector["grant_canonical"].as_str().unwrap()).unwrap();
    let start = now() - offset;
    for record in [&mut plan, &mut grant] {
        record["valid_from"] = json!(start);
        record["first_window_start"] = json!(start);
        record["expires_at"] = json!(start + 3_600);
        record["site_ids"] = json!(sites);
    }
    plan["destination_policy_digest"] = json!(super::PROJECTION_DIGEST.trim_end());
    (plan, grant)
}

pub(super) fn run(signed: &SignedBackup, site: &str, window: u64) -> StandingRun {
    StandingCaptureGrant::decode(&signed.grant)
        .unwrap()
        .run(&SiteId::try_from(site.to_owned()).unwrap(), window)
        .unwrap()
}

/// Sends a run and expects a refusal before intent with no state change.
fn refused(
    fixture: &BackupFixture,
    executor: &mut Executor,
    signed: &SignedBackup,
    operation: &Id,
    key: &Id,
    error: ExecutorError,
) {
    let before = fixture.replay_state();
    let reply = signed.submit(executor, operation, key);
    assert_eq!(reply.error.as_deref(), Some(error.code()), "{operation:?}");
    assert_eq!(reply.state, None);
    assert!(!reply.replay);
    assert!(executor.capture_status(operation).unwrap().is_none());
    assert_eq!(fixture.replay_state(), before);
}

#[test]
fn a_standing_run_is_admitted_once_in_its_window_and_replays_status_only() {
    let mut fixture = BackupFixture::new();
    enroll(&fixture);
    let calls = stub_helper_for(
        &mut fixture.anchor,
        "capture_run",
        "NOT_ADMITTED_FOR_EFFECT\n",
    );
    provision(&fixture.anchor, "blog9");
    let mut executor = Executor::open(fixture.anchor.clone()).unwrap();
    let (plan, grant) = standing(30, &["blog9"]);
    let signed = SignedBackup::new(&fixture, &plan, grant);
    let first = run(&signed, "blog9", 0);
    let (_, mark_before) = fixture.replay_state();

    let reply = signed.submit(&mut executor, &first.operation_id, &first.idempotency_key);
    assert_eq!(reply.state, Some(OutcomeState::Failed));
    assert_eq!(reply.error.as_deref(), Some("NOT_ADMITTED_FOR_EFFECT"));
    assert!(!reply.replay);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_ne!(fixture.replay_state().1, mark_before);
    let recorded = executor
        .capture_status(&first.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(recorded.state, CaptureState::Failed);
    assert_eq!(recorded.intent.idempotency_key, first.idempotency_key);
    assert_eq!(recorded.intent.grant_id, first.grant_id);
    assert_eq!(recorded.intent.nonce, first.nonce);
    let grant = StandingCaptureGrant::decode(&signed.grant).unwrap();
    assert_eq!(recorded.intent.grant_digest, grant.sha256());
    assert_eq!(recorded.retention_days, Some(30));
    // W396 (D-045): the run keeps the exact standing plan and grant bytes.
    let observation = Executor::observe(&fixture.anchor).unwrap();
    let admission = observation["admissions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["operation_id"] == first.operation_id.as_str())
        .unwrap();
    assert_eq!(admission["kind"], "capture");
    assert_eq!(admission["grant_digest"], grant.sha256().as_str());
    let stored = |part: &str| {
        let sha = admission["signed"][part]["sha256"].as_str().unwrap();
        observation["signed_objects"][sha]
            .as_str()
            .unwrap()
            .as_bytes()
            .to_vec()
    };
    assert_eq!(stored("grant"), grant.as_bytes());
    let canonical_plan =
        rustiron_contracts::CanonicalObject::decode(&serde_json::to_vec(&plan).unwrap()).unwrap();
    assert_eq!(stored("plan"), canonical_plan.as_bytes());
    assert_eq!(admission["signed"]["verification"], "sshsig_verified");
    // The intent expires when window 0 closes.
    assert_eq!(
        recorded.intent.expires_at.get(),
        plan["first_window_start"].as_u64().unwrap() + 120
    );

    // The same run again: stored status, no second helper run.
    let replay = signed.submit(&mut executor, &first.operation_id, &first.idempotency_key);
    assert!(replay.replay);
    assert_eq!(replay.state, Some(OutcomeState::Failed));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // Another identity in the same window is not a run of this grant.
    refused(
        &fixture,
        &mut executor,
        &signed,
        &id("op_w386_again"),
        &id("key_w386_again"),
        ExecutorError::RunMismatch,
    );
    // The right operation ID with another idempotency key: refused; the
    // reply carries the stored status of that operation (W329).
    let other = run(&signed, "blog9", 1);
    let before = fixture.replay_state();
    let reply = signed.submit(&mut executor, &first.operation_id, &other.idempotency_key);
    assert_eq!(
        reply.error.as_deref(),
        Some(ExecutorError::RunMismatch.code())
    );
    assert_eq!(reply.state, Some(OutcomeState::Failed));
    assert!(!reply.replay);
    assert_eq!(fixture.replay_state(), before);
    // The next window's run is refused while window 0 is open.
    refused(
        &fixture,
        &mut executor,
        &signed,
        &other.operation_id,
        &other.idempotency_key,
        ExecutorError::WindowClosed,
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn a_run_outside_its_window_is_refused_before_intent() {
    let mut fixture = BackupFixture::new();
    enroll(&fixture);
    let calls = stub_helper_for(
        &mut fixture.anchor,
        "capture_run",
        "NOT_ADMITTED_FOR_EFFECT\n",
    );
    provision(&fixture.anchor, "blog9");
    let mut executor = Executor::open(fixture.anchor.clone()).unwrap();
    // Window 0 closed 80 s ago; window 1 opens in 100 s.
    let (plan, grant) = standing(200, &["blog9"]);
    let signed = SignedBackup::new(&fixture, &plan, grant);
    for window in [0, 1, 5] {
        let run = run(&signed, "blog9", window);
        refused(
            &fixture,
            &mut executor,
            &signed,
            &run.operation_id,
            &run.idempotency_key,
            ExecutorError::WindowClosed,
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn a_later_window_is_admitted_and_a_missed_window_stays_closed() {
    let mut fixture = BackupFixture::new();
    enroll(&fixture);
    let calls = stub_helper_for(
        &mut fixture.anchor,
        "capture_run",
        "NOT_ADMITTED_FOR_EFFECT\n",
    );
    provision(&fixture.anchor, "blog9");
    let mut executor = Executor::open(fixture.anchor.clone()).unwrap();
    // Window 3 opened 10 s ago.
    let (plan, grant) = standing(3 * 300 + 10, &["blog9"]);
    let signed = SignedBackup::new(&fixture, &plan, grant);
    let missed = run(&signed, "blog9", 2);
    refused(
        &fixture,
        &mut executor,
        &signed,
        &missed.operation_id,
        &missed.idempotency_key,
        ExecutorError::WindowClosed,
    );
    let third = run(&signed, "blog9", 3);
    let reply = signed.submit(&mut executor, &third.operation_id, &third.idempotency_key);
    assert_eq!(reply.state, Some(OutcomeState::Failed));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn each_named_site_gets_its_own_run_and_an_unnamed_site_none() {
    let mut fixture = BackupFixture::new();
    enroll(&fixture);
    let calls = stub_helper_for(
        &mut fixture.anchor,
        "capture_run",
        "NOT_ADMITTED_FOR_EFFECT\n",
    );
    provision(&fixture.anchor, "blog13");
    provision_in(&fixture.anchor, "blog9");
    let mut executor = Executor::open(fixture.anchor.clone()).unwrap();
    let (plan, grant) = standing(30, &["blog13", "blog9"]);
    let signed = SignedBackup::new(&fixture, &plan, grant);
    for site in ["blog13", "blog9"] {
        let run = run(&signed, site, 0);
        let reply = signed.submit(&mut executor, &run.operation_id, &run.idempotency_key);
        assert_eq!(reply.state, Some(OutcomeState::Failed), "{site}");
        let recorded = executor.capture_status(&run.operation_id).unwrap().unwrap();
        assert_eq!(recorded.intent.site_id.as_str(), site);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    // A run derived for a site the grant does not name.
    let foreign = rustiron_contracts::approval::standing_run(
        &StandingCaptureGrant::decode(&signed.grant)
            .unwrap()
            .sha256(),
        &SiteId::try_from("blog7".to_owned()).unwrap(),
        0,
    );
    refused(
        &fixture,
        &mut executor,
        &signed,
        &foreign.operation_id,
        &foreign.idempotency_key,
        ExecutorError::RunMismatch,
    );
}

#[test]
fn a_changed_destination_or_an_unprovisioned_site_refuses_before_intent() {
    let mut fixture = BackupFixture::new();
    let policy = enroll(&fixture);
    let calls = stub_helper_for(
        &mut fixture.anchor,
        "capture_run",
        "NOT_ADMITTED_FOR_EFFECT\n",
    );
    provision(&fixture.anchor, "blog9");
    let mut executor = Executor::open(fixture.anchor.clone()).unwrap();

    // The site named by the grant has no provision.
    let (plan, grant) = standing(30, &["blog13"]);
    let signed = SignedBackup::new(&fixture, &plan, grant);
    let unprovisioned = run(&signed, "blog13", 0);
    refused(
        &fixture,
        &mut executor,
        &signed,
        &unprovisioned.operation_id,
        &unprovisioned.idempotency_key,
        ExecutorError::PreconditionChanged,
    );

    // A signed digest that is not the enrolled one.
    let (mut plan, grant) = standing(30, &["blog9"]);
    plan["destination_policy_digest"] = json!("b".repeat(64));
    let signed = SignedBackup::new(&fixture, &plan, grant);
    let changed = run(&signed, "blog9", 0);
    refused(
        &fixture,
        &mut executor,
        &signed,
        &changed.operation_id,
        &changed.idempotency_key,
        ExecutorError::PreconditionChanged,
    );

    // Another destination ID than the enrollment.
    let (mut plan, mut grant) = standing(30, &["blog9"]);
    plan["destination_id"] = json!("other_store");
    grant["destinations"] = json!(["other_store"]);
    let signed = SignedBackup::new(&fixture, &plan, grant);
    let other = run(&signed, "blog9", 0);
    refused(
        &fixture,
        &mut executor,
        &signed,
        &other.operation_id,
        &other.idempotency_key,
        ExecutorError::PreconditionChanged,
    );

    // A plan changed after signing: the grant's plan digest no longer binds.
    let (plan, grant) = standing(30, &["blog9"]);
    let mut signed = SignedBackup::new(&fixture, &plan, grant);
    let mut tampered: Value = serde_json::from_slice(&signed.plan).unwrap();
    tampered["recipe_id"] = json!("site_files_db_frozen_v1");
    signed.plan = serde_json::to_vec(&tampered).unwrap();
    let bound = run(&signed, "blog9", 0);
    refused(
        &fixture,
        &mut executor,
        &signed,
        &bound.operation_id,
        &bound.idempotency_key,
        ExecutorError::BindingDenied,
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    drop(policy);
}
