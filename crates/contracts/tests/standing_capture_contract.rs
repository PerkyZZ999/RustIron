//! W386 (D-035): standing capture plan and grant schema 3, the window
//! series and the derived run identities. No signer, executor or host
//! effect is involved.

use rustiron_contracts::{
    Id, Timestamp,
    approval::{
        ApprovalError, PlanKind, PreparedPlan, Sha256Digest, SiteId, StandingCaptureBindingContext,
        StandingCaptureGrant, StandingCapturePlan, WindowPosition, check_standing_capture_binding,
        standing_run,
    },
};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
struct Run {
    site_id: String,
    window: u64,
    operation_id: String,
    idempotency_key: String,
    grant_id: String,
    nonce: String,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    plan_input: String,
    plan_canonical: String,
    plan_digest: String,
    grant_input: String,
    grant_canonical: String,
    grant_sha256: String,
    runs: Vec<Run>,
}

fn vectors() -> Vec<Vector> {
    serde_json::from_str(include_str!("fixtures/standing-capture-vectors.json")).unwrap()
}

fn vector(name: &str) -> Vector {
    vectors().into_iter().find(|v| v.name == name).unwrap()
}

fn id(text: &str) -> Id {
    Id::try_from(text.to_owned()).unwrap()
}

fn site(text: &str) -> SiteId {
    SiteId::try_from(text.to_owned()).unwrap()
}

fn check(
    plan: &StandingCapturePlan,
    grant: &StandingCaptureGrant,
    now: Option<u64>,
) -> Result<(), ApprovalError> {
    check_standing_capture_binding(
        plan,
        grant,
        &StandingCaptureBindingContext {
            host_id: &id("host_lab"),
            host_epoch: &id("epoch_1"),
            profile_digest: &Sha256Digest::try_from("a".repeat(64)).unwrap(),
            requester: &id("agent_1"),
            issuer: &id("operator_1"),
            signer_policy_epoch: &id("policy_1"),
            now: now.map(|t| Timestamp::try_from(t).unwrap()),
        },
    )
}

fn values(name: &str) -> (Value, Value) {
    let v = vector(name);
    (
        serde_json::from_str(&v.plan_canonical).unwrap(),
        serde_json::from_str(&v.grant_canonical).unwrap(),
    )
}

/// Encodes a changed plan and a grant bound to its new digest.
fn pair(plan: &Value, grant: &Value) -> (Vec<u8>, Vec<u8>) {
    let plan_bytes = serde_json::to_vec(plan).unwrap();
    let mut grant = grant.clone();
    if let Ok(decoded) = StandingCapturePlan::decode(&plan_bytes) {
        grant["plan_digest"] = json!(decoded.digest());
    }
    (plan_bytes, serde_json::to_vec(&grant).unwrap())
}

#[test]
fn the_vectors_match_the_independent_bytes_digests_and_runs() {
    for v in vectors() {
        let plan = StandingCapturePlan::decode(v.plan_input.as_bytes()).unwrap();
        assert_eq!(plan.as_bytes(), v.plan_canonical.as_bytes(), "{}", v.name);
        assert_eq!(plan.digest().as_str(), v.plan_digest, "{}", v.name);
        let prepared = PreparedPlan::decode(v.plan_input.as_bytes()).unwrap();
        assert_eq!(prepared.kind(), PlanKind::BackupCapture);
        assert_eq!(prepared.digest(), plan.digest());
        let grant = StandingCaptureGrant::decode(v.grant_input.as_bytes()).unwrap();
        assert_eq!(grant.as_bytes(), v.grant_canonical.as_bytes(), "{}", v.name);
        assert_eq!(grant.sha256().as_str(), v.grant_sha256, "{}", v.name);
        assert!(!v.runs.is_empty());
        for expected in &v.runs {
            let run = grant
                .run(&site(&expected.site_id), expected.window)
                .unwrap();
            assert_eq!(run.window, expected.window);
            assert_eq!(run.operation_id.as_str(), expected.operation_id);
            assert_eq!(run.idempotency_key.as_str(), expected.idempotency_key);
            assert_eq!(run.grant_id.as_str(), expected.grant_id);
            assert_eq!(run.nonce.as_str(), expected.nonce);
            assert_eq!(
                run,
                standing_run(&grant.sha256(), &site(&expected.site_id), expected.window)
            );
            let (found_site, found) = grant.find_run(&run.operation_id).unwrap();
            assert_eq!((found_site, found), (site(&expected.site_id), run));
        }
    }
}

#[test]
fn a_matching_pair_binds_inside_its_validity_only() {
    let v = vector("daily");
    let plan = StandingCapturePlan::decode(v.plan_canonical.as_bytes()).unwrap();
    let grant = StandingCaptureGrant::decode(v.grant_canonical.as_bytes()).unwrap();
    let schedule = plan.schedule();
    assert_eq!(schedule, grant.schedule());
    let start = schedule.first_window_start;
    assert_eq!(check(&plan, &grant, Some(start)), Ok(()));
    assert_eq!(
        check(&plan, &grant, Some(start - 1)),
        Err(ApprovalError::OutsideValidity)
    );
    assert_eq!(
        check(&plan, &grant, Some(grant.expires_at().get())),
        Err(ApprovalError::OutsideValidity)
    );
    assert_eq!(
        check(&plan, &grant, None),
        Err(ApprovalError::ClockUncertain)
    );
}

#[test]
fn every_bound_field_must_match_between_plan_and_grant() {
    let (plan, grant) = values("daily");
    let start = plan["first_window_start"].as_u64().unwrap();
    let cases: [(&str, Value); 9] = [
        ("site_ids", json!(["blog9"])),
        ("destinations", json!(["other_store"])),
        ("first_window_start", json!(start + 60)),
        ("period_seconds", json!(43_200)),
        ("window_seconds", json!(3_600)),
        ("max_runs", json!(34)),
        ("plan_id", json!("plan_other")),
        ("host_epoch", json!("epoch_2")),
        ("issuer", json!("operator_2")),
    ];
    for (field, value) in cases {
        let mut changed = grant.clone();
        changed[field] = value;
        let decoded_plan =
            StandingCapturePlan::decode(&serde_json::to_vec(&plan).unwrap()).unwrap();
        let decoded = StandingCaptureGrant::decode(&serde_json::to_vec(&changed).unwrap()).unwrap();
        assert_eq!(
            check(&decoded_plan, &decoded, Some(start)),
            Err(ApprovalError::BindingMismatch),
            "{field}"
        );
    }
    // A different plan under the same grant fails on the digest.
    let mut other = plan.clone();
    other["recipe_id"] = json!("site_files_db_frozen_v1");
    let decoded_plan = StandingCapturePlan::decode(&serde_json::to_vec(&other).unwrap()).unwrap();
    let decoded = StandingCaptureGrant::decode(&serde_json::to_vec(&grant).unwrap()).unwrap();
    assert_eq!(
        check(&decoded_plan, &decoded, Some(start)),
        Err(ApprovalError::BindingMismatch)
    );
    // A grant longer than its plan.
    let (mut plan2, mut grant2) = (plan.clone(), grant.clone());
    plan2["expires_at"] = json!(plan["expires_at"].as_u64().unwrap() - 1);
    grant2["expires_at"] = grant["expires_at"].clone();
    let (plan_bytes, grant_bytes) = pair(&plan2, &grant2);
    assert_eq!(
        check(
            &StandingCapturePlan::decode(&plan_bytes).unwrap(),
            &StandingCaptureGrant::decode(&grant_bytes).unwrap(),
            Some(start)
        ),
        Err(ApprovalError::BindingMismatch)
    );
}

#[test]
fn the_schedule_bounds_refuse_both_records() {
    let (plan, grant) = values("compressed");
    let start = plan["first_window_start"].as_u64().unwrap();
    let valid_from = plan["valid_from"].as_u64().unwrap();
    let cases: Vec<Vec<(&str, Value)>> = vec![
        vec![("period_seconds", json!(299))],
        vec![("period_seconds", json!(86_401))],
        vec![("window_seconds", json!(59))],
        vec![("window_seconds", json!(151))],
        vec![
            ("period_seconds", json!(86_400)),
            ("window_seconds", json!(14_401)),
            ("max_runs", json!(1)),
        ],
        vec![("max_runs", json!(0))],
        vec![("max_runs", json!(36))],
        vec![("first_window_start", json!(valid_from - 1))],
        // The last window would close after expiry.
        vec![
            ("max_runs", json!(12)),
            ("first_window_start", json!(start + 200)),
        ],
        vec![("expires_at", json!(valid_from + 35 * 86_400 + 1))],
        vec![("expires_at", json!(valid_from))],
        vec![("site_ids", json!([]))],
        vec![("site_ids", json!(["blog9", "blog13"]))],
        vec![("site_ids", json!(["blog9", "blog9"]))],
        vec![(
            "site_ids",
            json!((0..17).map(|n| format!("site{n:02}")).collect::<Vec<_>>()),
        )],
    ];
    for changes in cases {
        let mut p = plan.clone();
        let mut g = grant.clone();
        for (field, value) in &changes {
            p[*field] = value.clone();
            g[*field] = value.clone();
        }
        assert_eq!(
            StandingCapturePlan::decode(&serde_json::to_vec(&p).unwrap()).unwrap_err(),
            ApprovalError::InvalidPlan,
            "{changes:?}"
        );
        assert_eq!(
            StandingCaptureGrant::decode(&serde_json::to_vec(&g).unwrap()).unwrap_err(),
            ApprovalError::InvalidGrant,
            "{changes:?}"
        );
    }
    // The largest accepted values: 35 daily windows of 4 h over 35 days.
    let mut p = plan;
    p["period_seconds"] = json!(86_400);
    p["window_seconds"] = json!(14_400);
    p["max_runs"] = json!(35);
    p["expires_at"] = json!(valid_from + 35 * 86_400);
    p["site_ids"] = json!((0..16).map(|n| format!("site{n:02}")).collect::<Vec<_>>());
    StandingCapturePlan::decode(&serde_json::to_vec(&p).unwrap()).unwrap();
}

#[test]
fn other_shapes_and_scopes_are_refused() {
    let (plan, grant) = values("compressed");
    let refused_plan = |p: Value| StandingCapturePlan::decode(&serde_json::to_vec(&p).unwrap());
    let refused_grant = |g: Value| StandingCaptureGrant::decode(&serde_json::to_vec(&g).unwrap());
    let mut p = plan.clone();
    p["destination_id"] = json!("lab_pc_store");
    assert_eq!(refused_plan(p).unwrap_err(), ApprovalError::InvalidPlan);
    let mut p = plan.clone();
    p["verb"] = json!("restore_probe");
    assert_eq!(refused_plan(p).unwrap_err(), ApprovalError::InvalidMessage);
    let mut p = plan.clone();
    p["extra"] = json!(1);
    assert_eq!(refused_plan(p).unwrap_err(), ApprovalError::InvalidMessage);
    let mut p = plan.clone();
    p["schema_version"] = json!(2);
    assert_eq!(
        refused_plan(p).unwrap_err(),
        ApprovalError::UnsupportedVersion
    );
    let mut p = plan;
    p["limitations"] = json!(vec!["x"; 9]);
    assert_eq!(refused_plan(p).unwrap_err(), ApprovalError::InvalidPlan);

    let mut g = grant.clone();
    g["issuer"] = json!("agent_1");
    assert_eq!(refused_grant(g).unwrap_err(), ApprovalError::InvalidGrant);
    let mut g = grant.clone();
    g["verbs"] = json!(["backup_capture", "backup_capture"]);
    assert_eq!(refused_grant(g).unwrap_err(), ApprovalError::InvalidGrant);
    let mut g = grant.clone();
    g["verbs"] = json!(["restore_probe"]);
    assert_eq!(refused_grant(g).unwrap_err(), ApprovalError::InvalidMessage);
    let mut g = grant.clone();
    g["destinations"] = json!(["offsite_fixture", "other_store"]);
    assert_eq!(refused_grant(g).unwrap_err(), ApprovalError::InvalidGrant);
    let mut g = grant.clone();
    g["destinations"] = json!(["lab_pc_store"]);
    assert_eq!(refused_grant(g).unwrap_err(), ApprovalError::InvalidGrant);
    let mut g = grant.clone();
    g["max_operations"] = json!(1);
    assert_eq!(refused_grant(g).unwrap_err(), ApprovalError::InvalidMessage);
    let mut g = grant;
    g["schema_version"] = json!(2);
    assert_eq!(
        refused_grant(g).unwrap_err(),
        ApprovalError::UnsupportedVersion
    );

    // A schema 2 capture plan is not a standing plan, and the reverse.
    let v2: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/product-backup-vectors.json")).unwrap();
    let v2_plan = v2
        .iter()
        .find(|v| v["name"] == "capture")
        .map(|v| v["plan_input"].as_str().unwrap().to_owned())
        .unwrap();
    assert!(StandingCapturePlan::decode(v2_plan.as_bytes()).is_err());
    assert!(
        rustiron_contracts::approval::ProductBackupPlan::decode(
            vector("compressed").plan_canonical.as_bytes()
        )
        .is_err()
    );
}

#[test]
fn windows_open_at_their_start_and_close_before_their_end() {
    let v = vector("compressed");
    let plan = StandingCapturePlan::decode(v.plan_canonical.as_bytes()).unwrap();
    let s = plan.schedule();
    let start = s.first_window_start;
    assert_eq!(s.window(0), Some((start, start + 120)));
    assert_eq!(s.window(5), Some((start + 1500, start + 1620)));
    assert_eq!(s.window(6), None);
    assert_eq!(
        s.position(start - 1),
        WindowPosition::Closed { next: Some(0) }
    );
    assert_eq!(
        s.position(start),
        WindowPosition::Open {
            index: 0,
            opens_at: start,
            closes_at: start + 120
        }
    );
    assert_eq!(
        s.position(start + 119),
        WindowPosition::Open {
            index: 0,
            opens_at: start,
            closes_at: start + 120
        }
    );
    assert_eq!(
        s.position(start + 120),
        WindowPosition::Closed { next: Some(1) }
    );
    assert_eq!(
        s.position(start + 300),
        WindowPosition::Open {
            index: 1,
            opens_at: start + 300,
            closes_at: start + 420
        }
    );
    assert_eq!(
        s.position(start + 1620),
        WindowPosition::Closed { next: None }
    );
    assert_eq!(
        s.position(start + 100_000),
        WindowPosition::Closed { next: None }
    );
    assert_eq!(s.closed_windows(start), 0);
    assert_eq!(s.closed_windows(start + 120), 1);
    assert_eq!(s.closed_windows(start + 419), 1);
    assert_eq!(s.closed_windows(start + 100_000), 6);
}

#[test]
fn runs_belong_to_one_grant_site_and_window() {
    let v = vector("daily");
    let grant = StandingCaptureGrant::decode(v.grant_canonical.as_bytes()).unwrap();
    assert!(grant.run(&site("blog7"), 0).is_none());
    assert!(grant.run(&site("blog9"), 35).is_none());
    let a = grant.run(&site("blog9"), 0).unwrap();
    let b = grant.run(&site("blog9"), 1).unwrap();
    let c = grant.run(&site("blog13"), 0).unwrap();
    assert_ne!(a.operation_id, b.operation_id);
    assert_ne!(a.operation_id, c.operation_id);
    assert!(
        grant
            .find_run(&id("sc_00000000000000000000000000000000"))
            .is_none()
    );
    // A different grant (here the other vector) derives other identities.
    let other =
        StandingCaptureGrant::decode(vector("compressed").grant_canonical.as_bytes()).unwrap();
    assert_ne!(
        other.run(&site("blog9"), 0).unwrap().operation_id,
        a.operation_id
    );
    assert!(other.find_run(&a.operation_id).is_none());
}
