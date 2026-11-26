//! Semantic pair oracles with independently fixed synthetic context facts.

use rustiron_contracts::approval::{
    ApprovalError, CaptureBindingContext, CaptureGrant, CapturePlan, EjectBindingContext,
    EjectGrant, EjectPlan, OlsBindingContext, OlsGrant, OlsPlan, ProbeBindingContext, ProbeGrant,
    ProbePlan, ProductBackupBindingContext, ProductBackupGrant, ProductBackupPlan,
    ReadoptBindingContext, ReadoptGrant, ReadoptPlan, Sha256Digest, SiteBindingContext, SiteGrant,
    SitePlan, SiteQuotaLimits, StandingCaptureBindingContext, StandingCaptureGrant,
    StandingCapturePlan, WindowPosition, check_capture_binding, check_eject_binding,
    check_ols_binding, check_probe_binding, check_product_backup_binding, check_readopt_binding,
    check_site_binding, check_standing_capture_binding, standing_run,
};
use rustiron_contracts::{CanonicalObject, Id, MAX_REQUEST_BYTES, Timestamp};
use serde_json::{Value, json};

#[derive(Clone)]
struct Facts {
    host: Id,
    epoch: Id,
    profile: Sha256Digest,
    requester: Id,
    issuer: Id,
    signer_epoch: Id,
    recipe: Sha256Digest,
    quota_cap: Option<SiteQuotaLimits>,
}

impl Facts {
    fn fixture() -> Self {
        Self {
            host: id("host_lab"),
            epoch: id("epoch_1"),
            profile: Sha256Digest::try_from("a".repeat(64)).unwrap(),
            requester: id("agent_1"),
            issuer: id("operator_1"),
            signer_epoch: id("policy_1"),
            recipe: Sha256Digest::try_from("d".repeat(64)).unwrap(),
            quota_cap: Some(SiteQuotaLimits::new(5_242_880, 500_000).unwrap()),
        }
    }
}

/// W341: a v2 site plan binds only with an enrolled cap at least its signed
/// limits; a v1 plan binds the same with or without any cap.
fn site_quota_properties(
    plan: &SitePlan,
    grant: &SiteGrant,
    now: Option<Timestamp>,
    check: impl Fn(&SiteGrant, &Facts, Option<Timestamp>) -> Result<(), ApprovalError>,
) {
    let facts = Facts::fixture();
    if check(grant, &facts, now).is_err() {
        return;
    }
    let with_cap = |cap: Option<SiteQuotaLimits>| {
        let mut changed = facts.clone();
        changed.quota_cap = cap;
        check(grant, &changed, now)
    };
    let smallest = SiteQuotaLimits::new(
        SiteQuotaLimits::MIN_BLOCK_HARD_KIB,
        SiteQuotaLimits::MIN_INODE_HARD,
    )
    .unwrap();
    match plan.quota_limits() {
        None => {
            assert_eq!(plan.schema_version(), 1);
            assert_eq!(with_cap(None), Ok(()), "v1 needed an enrolled quota");
            assert_eq!(with_cap(Some(smallest)), Ok(()), "v1 compared a cap");
        }
        Some(limits) => {
            assert_eq!(plan.schema_version(), 2);
            assert!(
                limits.within(&facts.quota_cap.unwrap()),
                "limits above the cap bound"
            );
            assert_eq!(with_cap(Some(limits)), Ok(()), "an equal cap refused");
            assert_eq!(
                with_cap(None),
                Err(ApprovalError::BindingMismatch),
                "v2 bound without an enrolled quota"
            );
            for lower in [
                limits
                    .block_hard_kib()
                    .checked_sub(1)
                    .and_then(|kib| SiteQuotaLimits::new(kib, limits.inode_hard()).ok()),
                limits
                    .inode_hard()
                    .checked_sub(1)
                    .and_then(|inodes| SiteQuotaLimits::new(limits.block_hard_kib(), inodes).ok()),
            ]
            .into_iter()
            .flatten()
            {
                assert_eq!(
                    with_cap(Some(lower)),
                    Err(ApprovalError::BindingMismatch),
                    "a cap below the signed limits accepted"
                );
            }
        }
    }
}

fn id(value: &str) -> Id {
    Id::try_from(value.to_owned()).unwrap()
}

fn altered(value: &Value, field: &str, first: Value, second: Value) -> Value {
    let mut changed = value.clone();
    changed[field] = if value[field] == first { second } else { first };
    changed
}

#[derive(Clone, Copy, Debug)]
enum ContextFault {
    Host,
    Epoch,
    Profile,
    Requester,
    Issuer,
    SignerEpoch,
}

fn successful_tuple_relations(plan: &Value, grant: &Value) {
    for field in [
        "plan_id",
        "host_id",
        "host_epoch",
        "profile_digest",
        "requester",
        "risk_class",
    ] {
        assert_eq!(grant[field], plan[field], "bound field {field} differs");
    }
    let canonical = CanonicalObject::decode(&serde_json::to_vec(plan).unwrap()).unwrap();
    let digest = Sha256Digest::from_bytes(crate::domain_digest(canonical.as_bytes()));
    assert_eq!(
        grant["plan_digest"].as_str(),
        Some(digest.as_str()),
        "bound plan digest differs"
    );
    assert!(
        grant["valid_from"].as_u64().unwrap() >= plan["valid_from"].as_u64().unwrap()
            && grant["expires_at"].as_u64().unwrap() <= plan["expires_at"].as_u64().unwrap(),
        "grant window exceeds plan"
    );
    let sites = plan
        .get("site_ids")
        .cloned()
        .unwrap_or_else(|| json!([plan["site_id"]]));
    assert_eq!(grant["site_ids"], sites, "site scope differs");
    if let Some(compensation) = plan.get("compensation") {
        assert_eq!(
            &grant["compensation"], compensation,
            "compensation scope differs"
        );
    }
    if let Some(destination) = plan.get("destination_id") {
        assert_eq!(
            grant["destinations"],
            json!([destination]),
            "destination scope differs"
        );
    }
    if let Some(snapshot) = plan.get("snapshot_id") {
        assert_eq!(
            grant["snapshot_ids"],
            json!([snapshot]),
            "snapshot scope differs"
        );
    }
}

fn binding_properties<G>(
    grant: &G,
    value: &Value,
    plan_value: &Value,
    now: Option<Timestamp>,
    decode: fn(&[u8]) -> Result<G, ApprovalError>,
    check: impl Fn(&G, &Facts, Option<Timestamp>) -> Result<(), ApprovalError>,
) -> bool {
    let facts = Facts::fixture();
    let start = Timestamp::try_from(value["valid_from"].as_u64().unwrap()).unwrap();
    let end = Timestamp::try_from(value["expires_at"].as_u64().unwrap()).unwrap();
    let actual = check(grant, &facts, now);
    if check(grant, &facts, Some(start)).is_err() {
        assert!(actual.is_err(), "time change rescued a mismatched binding");
        return false;
    }
    successful_tuple_relations(plan_value, value);
    let expected = match now {
        None => Err(ApprovalError::ClockUncertain),
        Some(time) if time.get() < start.get() || time.get() >= end.get() => {
            Err(ApprovalError::OutsideValidity)
        }
        Some(_) => Ok(()),
    };
    assert_eq!(actual, expected, "binding clock interval differs");
    assert_eq!(
        check(grant, &facts, None),
        Err(ApprovalError::ClockUncertain)
    );
    assert_eq!(
        check(grant, &facts, Some(end)),
        Err(ApprovalError::OutsideValidity),
        "expiry boundary accepted"
    );
    if let Some(before) = start.get().checked_sub(1) {
        assert_eq!(
            check(grant, &facts, Some(Timestamp::try_from(before).unwrap())),
            Err(ApprovalError::OutsideValidity)
        );
    }
    for fault in [
        ContextFault::Host,
        ContextFault::Epoch,
        ContextFault::Profile,
        ContextFault::Requester,
        ContextFault::Issuer,
        ContextFault::SignerEpoch,
    ] {
        let mut changed = facts.clone();
        match fault {
            ContextFault::Host => changed.host = id("other_host"),
            ContextFault::Epoch => changed.epoch = id("other_epoch"),
            ContextFault::Profile => {
                changed.profile = Sha256Digest::try_from("b".repeat(64)).unwrap()
            }
            ContextFault::Requester => changed.requester = id("other_requester"),
            ContextFault::Issuer => changed.issuer = id("other_issuer"),
            ContextFault::SignerEpoch => changed.signer_epoch = id("other_policy"),
        }
        assert_eq!(
            check(grant, &changed, Some(start)),
            Err(ApprovalError::BindingMismatch),
            "changed context {fault:?} accepted"
        );
    }
    for (field, first, second) in [
        ("plan_digest", json!("0".repeat(64)), json!("1".repeat(64))),
        ("plan_id", json!("other_plan_a"), json!("other_plan_b")),
        ("site_ids", json!(["fuzzsite"]), json!(["fuzzother"])),
    ] {
        let bytes = serde_json::to_vec(&altered(value, field, first, second)).unwrap();
        if bytes.len() <= MAX_REQUEST_BYTES {
            let changed = decode(&bytes).expect("scope mutation must remain intrinsically valid");
            assert_eq!(
                check(&changed, &facts, Some(start)),
                Err(ApprovalError::BindingMismatch),
                "changed grant {field} accepted"
            );
        }
    }
    let bytes = serde_json::to_vec(&altered(
        value,
        "nonce",
        json!("other_nonce_a"),
        json!("other_nonce_b"),
    ))
    .unwrap();
    if bytes.len() <= MAX_REQUEST_BYTES {
        let changed = decode(&bytes).unwrap();
        assert_eq!(
            check(&changed, &facts, Some(start)),
            Ok(()),
            "pure binding unexpectedly consumed a nonce"
        );
    }
    actual.is_ok()
}

/// W386 (D-035): every derived run belongs to one site and window of the
/// grant, the windows open and close at their signed seconds, and a run
/// past the last window does not exist.
fn standing_run_properties(grant: &StandingCaptureGrant) {
    let schedule = grant.schedule();
    let digest = grant.sha256();
    for site in grant.site_ids() {
        assert!(
            grant.run(site, schedule.max_runs).is_none(),
            "run past the last window"
        );
        for window in [0, schedule.max_runs - 1] {
            let run = grant.run(site, window).unwrap();
            assert_eq!(run, standing_run(&digest, site, window));
            assert!(run.operation_id.as_str().starts_with("sc_"));
            assert_eq!(&run.operation_id.as_str()[3..], &run.grant_id.as_str()[3..]);
            assert_eq!(&run.idempotency_key.as_str()[3..], &run.nonce.as_str()[3..]);
            let (found_site, found) = grant.find_run(&run.operation_id).unwrap();
            assert_eq!((&found_site, found.window), (site, window));
            let (opens, closes) = schedule.window(window).unwrap();
            assert_eq!(closes - opens, schedule.window_seconds);
            for (time, open) in [(opens, true), (closes - 1, true), (closes, false)] {
                let position = schedule.position(time);
                assert_eq!(
                    matches!(position, WindowPosition::Open { index, .. } if index == window),
                    open,
                    "window boundary differs"
                );
            }
        }
    }
}

/// W372: a `site_readopt` pair. A site form binds only under an enrolled
/// cap at least its signed limits and never without one; the generation
/// form ignores the cap.
fn readopt_pair(
    plan_bytes: &[u8],
    grant_bytes: &[u8],
    grant_value: &Value,
    plan_value: &Value,
    now: Option<Timestamp>,
) -> bool {
    let (Ok(plan), Ok(grant)) = (
        ReadoptPlan::decode(plan_bytes),
        ReadoptGrant::decode(grant_bytes),
    ) else {
        return false;
    };
    let check = |grant: &ReadoptGrant, facts: &Facts, now| {
        check_readopt_binding(
            &plan,
            grant,
            &ReadoptBindingContext {
                host_id: &facts.host,
                host_epoch: &facts.epoch,
                profile_digest: &facts.profile,
                requester: &facts.requester,
                issuer: &facts.issuer,
                signer_policy_epoch: &facts.signer_epoch,
                quota_cap: facts.quota_cap,
                now,
            },
        )
    };
    let facts = Facts::fixture();
    if check(&grant, &facts, now).is_ok() {
        let mut uncapped = facts.clone();
        uncapped.quota_cap = None;
        let expected = if plan.site().is_some() {
            Err(ApprovalError::BindingMismatch)
        } else {
            Ok(())
        };
        assert_eq!(
            check(&grant, &uncapped, now),
            expected,
            "quota cap rule differs"
        );
        if let Some((_, _, limits)) = plan.site() {
            assert!(
                limits.within(&facts.quota_cap.unwrap()),
                "limits above the cap bound"
            );
        }
    }
    binding_properties(
        &grant,
        grant_value,
        plan_value,
        now,
        ReadoptGrant::decode,
        check,
    )
}

/// Fuzz bounded semantic plan/grant pairs and synthetic asserted time.
/// Context facts stay independent of input; this is not a signed-wire format.
pub fn plan_grant_binding(input: &[u8]) -> bool {
    if CanonicalObject::decode(input).is_err() {
        return false;
    }
    let wrapper: Value = serde_json::from_slice(input).unwrap();
    let (Some(plan_value), Some(grant_value)) = (wrapper.get("plan"), wrapper.get("grant")) else {
        return false;
    };
    let now = match wrapper.get("now") {
        None | Some(Value::Null) => None,
        Some(value) => {
            let Some(value) = value.as_u64() else {
                return false;
            };
            let Ok(time) = Timestamp::try_from(value) else {
                return false;
            };
            Some(time)
        }
    };
    let plan_bytes = serde_json::to_vec(plan_value).unwrap();
    let grant_bytes = serde_json::to_vec(grant_value).unwrap();
    macro_rules! pair {
        ($plan:ty, $grant:ty, $context:ident, $check:ident $(, $recipe:ident)? $(; $quota:ident)?) => {{
            let (Ok(plan), Ok(grant)) = (<$plan>::decode(&plan_bytes), <$grant>::decode(&grant_bytes)) else { return false; };
            let check = |grant: &$grant, facts: &Facts, now| $check(&plan, grant, &$context {
                host_id: &facts.host, host_epoch: &facts.epoch, profile_digest: &facts.profile,
                requester: &facts.requester, issuer: &facts.issuer, signer_policy_epoch: &facts.signer_epoch,
                now, $($recipe: &facts.recipe,)? $($quota: facts.quota_cap,)?
            });
            $(let _ = stringify!($quota); site_quota_properties(&plan, &grant, now, &check);)?
            $(let mut different = Facts::fixture();
              different.recipe = Sha256Digest::try_from("e".repeat(64)).unwrap();
              if check(&grant, &Facts::fixture(), now).is_ok() {
                  assert_eq!(check(&grant, &different, now), Err(ApprovalError::BindingMismatch), concat!("changed recipe context ", stringify!($recipe), " accepted"));
              })?
            binding_properties(&grant, grant_value, plan_value, now, <$grant>::decode, check)
        }};
    }
    if plan_value["schema_version"] == 3 && plan_value["verb"] == "backup_capture" {
        if let Ok(grant) = StandingCaptureGrant::decode(&grant_bytes) {
            standing_run_properties(&grant);
        }
        return pair!(
            StandingCapturePlan,
            StandingCaptureGrant,
            StandingCaptureBindingContext,
            check_standing_capture_binding
        );
    }
    if plan_value["schema_version"] == 2
        && plan_value["verb"] != "site_provision"
        && plan_value["verb"] != "config_activate"
    {
        return pair!(
            ProductBackupPlan,
            ProductBackupGrant,
            ProductBackupBindingContext,
            check_product_backup_binding
        );
    }
    match plan_value["verb"].as_str() {
        Some("site_provision") => pair!(
            SitePlan,
            SiteGrant,
            SiteBindingContext,
            check_site_binding,
            wordpress_713_digest;
            quota_cap
        ),
        Some("config_activate") => pair!(OlsPlan, OlsGrant, OlsBindingContext, check_ols_binding),
        Some("site_eject") => pair!(
            EjectPlan,
            EjectGrant,
            EjectBindingContext,
            check_eject_binding
        ),
        Some("backup_capture") => pair!(
            CapturePlan,
            CaptureGrant,
            CaptureBindingContext,
            check_capture_binding
        ),
        Some("restore_probe") => pair!(
            ProbePlan,
            ProbeGrant,
            ProbeBindingContext,
            check_probe_binding
        ),
        Some("site_readopt") => {
            readopt_pair(&plan_bytes, &grant_bytes, grant_value, plan_value, now)
        }
        _ => false,
    }
}
