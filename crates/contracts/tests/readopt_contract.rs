//! W372 (D-030): public `site_readopt` plan/grant checks for both forms.
//! No signer, executor or host effect is involved.

use rustiron_contracts::{
    Id, Timestamp,
    approval::{
        ApprovalError, PlanKind, PreparedPlan, ReadoptBindingContext, ReadoptForm, ReadoptGrant,
        ReadoptPlan, Sha256Digest, SiteQuotaLimits, check_readopt_binding,
    },
};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
struct Vector {
    name: String,
    plan_input: String,
    plan_canonical: String,
    plan_digest: String,
    grant_input: String,
    grant_canonical: String,
}

fn vectors() -> Vec<Vector> {
    serde_json::from_str(include_str!("fixtures/readopt-plan-vectors.json")).unwrap()
}

fn vector(name: &str) -> Vector {
    vectors().into_iter().find(|v| v.name == name).unwrap()
}

fn id(text: &str) -> Id {
    Id::try_from(text.to_owned()).unwrap()
}

fn cap() -> SiteQuotaLimits {
    SiteQuotaLimits::new(5_242_880, 500_000).unwrap()
}

fn check(
    plan: &ReadoptPlan,
    grant: &ReadoptGrant,
    quota_cap: Option<SiteQuotaLimits>,
    now: Option<u64>,
) -> Result<(), ApprovalError> {
    check_readopt_binding(
        plan,
        grant,
        &ReadoptBindingContext {
            host_id: &id("host_lab"),
            host_epoch: &id("epoch_2"),
            profile_digest: &Sha256Digest::try_from("a".repeat(64)).unwrap(),
            requester: &id("agent_1"),
            issuer: &id("operator_1"),
            signer_policy_epoch: &id("policy_1"),
            quota_cap,
            now: now.map(|t| Timestamp::try_from(t).unwrap()),
        },
    )
}

fn edited(input: &str, edit: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut value: Value = serde_json::from_str(input).unwrap();
    edit(&mut value);
    serde_json::to_vec(&value).unwrap()
}

fn plan_edit(name: &str, edit: impl FnOnce(&mut Value)) -> Result<ReadoptPlan, ApprovalError> {
    ReadoptPlan::decode(&edited(&vector(name).plan_input, edit))
}

/// A grant for `plan`, edited, re-bound to the plan digest.
fn grant_for(name: &str, plan: &ReadoptPlan, edit: impl FnOnce(&mut Value)) -> ReadoptGrant {
    ReadoptGrant::decode(&edited(&vector(name).grant_input, |grant| {
        grant["plan_digest"] = json!(plan.digest().as_str());
        edit(grant);
    }))
    .unwrap()
}

#[test]
fn vectors_match_independent_bytes_digest_and_bind() {
    let all = vectors();
    assert_eq!(
        all.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(),
        ["site", "generation"]
    );
    for v in &all {
        let plan = ReadoptPlan::decode(v.plan_input.as_bytes()).unwrap();
        assert_eq!(plan.as_bytes(), v.plan_canonical.as_bytes(), "{}", v.name);
        assert_eq!(plan.digest().as_str(), v.plan_digest, "{}", v.name);
        let grant = ReadoptGrant::decode(v.grant_input.as_bytes()).unwrap();
        assert_eq!(grant.as_bytes(), v.grant_canonical.as_bytes(), "{}", v.name);
        assert_eq!(check(&plan, &grant, Some(cap()), Some(1500)), Ok(()));
        let prepared = PreparedPlan::decode(v.plan_input.as_bytes()).unwrap();
        assert_eq!(prepared.kind(), PlanKind::SiteReadopt);
        assert_eq!(prepared.kind().as_str(), "site_readopt");
        assert_eq!(prepared.digest(), plan.digest());
    }
}

#[test]
fn the_site_form_exposes_only_site_fields() {
    let plan = ReadoptPlan::decode(vector("site").plan_input.as_bytes()).unwrap();
    assert_eq!(plan.form(), ReadoptForm::Site);
    let (site, hostname, limits) = plan.site().unwrap();
    assert_eq!(site.as_str(), "blog1");
    assert_eq!(hostname.as_str(), "blog1.example.test");
    assert_eq!(
        (limits.block_hard_kib(), limits.inode_hard()),
        (262_144, 20_000)
    );
    assert!(plan.generation().is_none());
    assert_eq!(plan.previous_epoch().as_str(), "epoch_1");
    let floor = plan.allocation_floor().unwrap();
    assert_eq!((floor.uid(), floor.category()), (3002, 202));
}

#[test]
fn the_generation_form_exposes_only_generation_fields() {
    let plan = ReadoptPlan::decode(vector("generation").plan_input.as_bytes()).unwrap();
    assert_eq!(plan.form(), ReadoptForm::Generation);
    let (generation, digest, sites) = plan.generation().unwrap();
    assert_eq!(generation.as_str(), "rbc7e46957fb865b0");
    assert_eq!(digest.as_str(), "b".repeat(64));
    assert_eq!(
        sites.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        ["blog1", "blog2"]
    );
    assert!(plan.site().is_none());
    assert!(plan.allocation_floor().is_none());
}

#[test]
fn unknown_null_and_missing_members_are_refused() {
    for name in ["site", "generation"] {
        assert_eq!(
            plan_edit(name, |p| p["extra"] = json!(1)).err(),
            Some(ApprovalError::InvalidMessage)
        );
        for member in ["previous_epoch", "evidence_sha256", "form", "observations"] {
            assert_eq!(
                plan_edit(name, |p| {
                    p.as_object_mut().unwrap().remove(member);
                })
                .err(),
                Some(ApprovalError::InvalidMessage),
                "{name} without {member}"
            );
        }
        assert!(plan_edit(name, |p| p["allocation_floor"] = Value::Null).is_err());
        assert_eq!(
            plan_edit(name, |p| p["schema_version"] = json!(2)).err(),
            Some(ApprovalError::UnsupportedVersion)
        );
    }
    assert!(plan_edit("site", |p| p["quota_limits"] = Value::Null).is_err());
    assert!(plan_edit("generation", |p| p["site_ids"] = Value::Null).is_err());
}

#[test]
fn a_mixed_or_incomplete_form_is_refused() {
    let invalid = Some(ApprovalError::InvalidPlan);
    // Site form with a generation member, and the reverse.
    assert_eq!(
        plan_edit("site", |p| p["expected_generation"] = json!("g1")).err(),
        invalid
    );
    assert_eq!(
        plan_edit("site", |p| p["site_ids"] = json!(["blog1"])).err(),
        invalid
    );
    assert_eq!(
        plan_edit("site", |p| p["target"] = json!("ols_lab_listener")).err(),
        invalid
    );
    assert_eq!(
        plan_edit("generation", |p| p["site_id"] = json!("blog1")).err(),
        invalid
    );
    assert_eq!(
        plan_edit("generation", |p| p["quota_limits"] =
            json!({"block_hard_kib": 262144, "inode_hard": 20000}))
        .err(),
        invalid
    );
    // A form whose own members are missing.
    for member in ["site_id", "hostname", "quota_limits"] {
        assert!(
            plan_edit("site", |p| {
                p.as_object_mut().unwrap().remove(member);
            })
            .is_err(),
            "site without {member}"
        );
    }
    for member in [
        "target",
        "expected_generation",
        "expected_digest",
        "site_ids",
    ] {
        assert!(
            plan_edit("generation", |p| {
                p.as_object_mut().unwrap().remove(member);
            })
            .is_err(),
            "generation without {member}"
        );
    }
    // The other form's observation or effects.
    assert_eq!(
        plan_edit("site", |p| p["form"] = json!("generation")).err(),
        invalid
    );
    assert_eq!(
        plan_edit("generation", |p| p["form"] = json!("site")).err(),
        invalid
    );
    assert_eq!(
        plan_edit("site", |p| {
            p["expected_effects"]["records_generation"] = json!(true);
        })
        .err(),
        invalid
    );
    assert_eq!(
        plan_edit("generation", |p| {
            p["expected_effects"]["records_ownership"] = json!(true);
        })
        .err(),
        invalid
    );
}

#[test]
fn every_effect_is_fixed_and_the_epochs_differ() {
    let invalid = Some(ApprovalError::InvalidPlan);
    for name in ["site", "generation"] {
        for effect in [
            "creates_account",
            "creates_database",
            "traffic_activation",
            "network_access",
            "sets_quota",
        ] {
            assert_eq!(
                plan_edit(name, |p| p["expected_effects"][effect] = json!(true)).err(),
                invalid,
                "{name} {effect}"
            );
        }
        assert_eq!(
            plan_edit(name, |p| p["previous_epoch"] = json!("epoch_2")).err(),
            invalid,
            "{name}: the previous epoch is the plan's own"
        );
        assert_eq!(
            plan_edit(name, |p| p["observations"][0]["observed_at"] = json!(600)).err(),
            invalid,
            "{name}: a stale observation"
        );
        assert_eq!(
            plan_edit(name, |p| {
                let observation = p["observations"][0].clone();
                p["observations"] = json!([observation.clone(), observation]);
            })
            .err(),
            invalid
        );
    }
    assert_eq!(
        plan_edit("site", |p| p["expected_effects"]["records_ownership"] =
            json!(false))
        .err(),
        invalid
    );
    assert_eq!(
        plan_edit("generation", |p| {
            p["expected_effects"]["records_generation"] = json!(false);
        })
        .err(),
        invalid
    );
}

#[test]
fn observations_must_name_the_planned_resource() {
    let invalid = Some(ApprovalError::InvalidPlan);
    assert_eq!(
        plan_edit("site", |p| p["observations"][0]["site_id"] = json!("blog2")).err(),
        invalid
    );
    assert_eq!(
        plan_edit("site", |p| {
            p["observations"][0]["hostname"] = json!("other.example.test");
        })
        .err(),
        invalid
    );
    assert_eq!(
        plan_edit("generation", |p| {
            p["observations"][0]["generation"] = json!("r0000000000000000");
        })
        .err(),
        invalid
    );
    assert_eq!(
        plan_edit("generation", |p| {
            p["observations"][0]["content_digest"] = json!("e".repeat(64));
        })
        .err(),
        invalid
    );
}

#[test]
fn generation_site_lists_are_sorted_unique_and_bounded() {
    let invalid = Some(ApprovalError::InvalidPlan);
    assert_eq!(
        plan_edit("generation", |p| p["site_ids"] = json!(["blog2", "blog1"])).err(),
        invalid
    );
    assert_eq!(
        plan_edit("generation", |p| p["site_ids"] = json!(["blog1", "blog1"])).err(),
        invalid
    );
    assert_eq!(
        plan_edit("generation", |p| p["site_ids"] = json!([])).err(),
        invalid
    );
    let sites = |n: usize| -> Value { (0..n).map(|i| json!(format!("site{i:03}"))).collect() };
    assert!(plan_edit("generation", |p| p["site_ids"] = sites(32)).is_ok());
    assert_eq!(
        plan_edit("generation", |p| p["site_ids"] = sites(33)).err(),
        invalid
    );
}

#[test]
fn allocation_floors_are_bounded() {
    let invalid = Some(ApprovalError::InvalidPlan);
    assert_eq!(
        plan_edit("site", |p| p["allocation_floor"]["category"] = json!(1024)).err(),
        invalid
    );
    assert_eq!(
        plan_edit("site", |p| p["allocation_floor"]["uid"] = json!(0)).err(),
        invalid
    );
    assert!(
        plan_edit("site", |p| p["allocation_floor"]["uid"] =
            json!(4_294_967_296_u64))
        .is_err()
    );
    assert!(plan_edit("site", |p| p["allocation_floor"]["extra"] = json!(1)).is_err());
    assert!(
        plan_edit("site", |p| {
            p.as_object_mut().unwrap().remove("allocation_floor");
        })
        .is_ok()
    );
    assert!(
        plan_edit("generation", |p| p["allocation_floor"] =
            json!({"uid": 3001, "category": 201}))
        .is_ok()
    );
}

#[test]
fn the_grant_is_closed() {
    let invalid = |name: &str, edit: fn(&mut Value)| {
        ReadoptGrant::decode(&edited(&vector(name).grant_input, edit)).err()
    };
    for name in ["site", "generation"] {
        assert_eq!(
            invalid(name, |g| g["verbs"] =
                json!(["site_readopt", "site_readopt"])),
            Some(ApprovalError::InvalidGrant)
        );
        assert!(invalid(name, |g| g["verbs"] = json!(["site_provision"])).is_some());
        assert_eq!(
            invalid(name, |g| g["max_operations"] = json!(2)),
            Some(ApprovalError::InvalidGrant)
        );
        assert_eq!(
            invalid(name, |g| g["issuer"] = json!("agent_1")),
            Some(ApprovalError::InvalidGrant)
        );
        assert_eq!(
            invalid(name, |g| g["site_ids"] = json!([])),
            Some(ApprovalError::InvalidGrant)
        );
        assert_eq!(
            invalid(name, |g| g["compensation"] = json!({})),
            Some(ApprovalError::InvalidMessage)
        );
        assert_eq!(
            invalid(name, |g| g["schema_version"] = json!(2)),
            Some(ApprovalError::UnsupportedVersion)
        );
    }
    assert_eq!(
        invalid("generation", |g| g["targets"] =
            json!(["ols_lab_listener", "ols_lab_listener"])),
        Some(ApprovalError::InvalidGrant)
    );
    assert!(invalid("generation", |g| g["targets"] = Value::Null).is_some());
}

#[test]
fn every_bound_field_and_the_scope_matter() {
    for name in ["site", "generation"] {
        let plan = ReadoptPlan::decode(vector(name).plan_input.as_bytes()).unwrap();
        let ok = grant_for(name, &plan, |_| {});
        assert_eq!(check(&plan, &ok, Some(cap()), Some(1500)), Ok(()));
        let mismatch = Err(ApprovalError::BindingMismatch);
        for (field, value) in [
            ("plan_id", json!("plan_other")),
            ("host_id", json!("host_other")),
            ("host_epoch", json!("epoch_1")),
            ("profile_digest", json!("f".repeat(64))),
            ("requester", json!("agent_2")),
            ("issuer", json!("operator_2")),
            ("signer_policy_epoch", json!("policy_2")),
            ("site_ids", json!(["blog9"])),
            ("valid_from", json!(900)),
            ("expires_at", json!(2100)),
        ] {
            let grant = grant_for(name, &plan, |g| g[field] = value);
            assert_eq!(
                check(&plan, &grant, Some(cap()), Some(1500)),
                mismatch,
                "{name} {field}"
            );
        }
        let other_digest = grant_for(name, &plan, |g| g["plan_digest"] = json!("f".repeat(64)));
        assert_eq!(
            check(&plan, &other_digest, Some(cap()), Some(1500)),
            mismatch
        );
        assert_eq!(
            check(&plan, &ok, Some(cap()), None),
            Err(ApprovalError::ClockUncertain)
        );
        assert_eq!(
            check(&plan, &ok, Some(cap()), Some(1900)),
            Err(ApprovalError::OutsideValidity)
        );
        assert_eq!(
            check(&plan, &ok, Some(cap()), Some(1099)),
            Err(ApprovalError::OutsideValidity)
        );
    }
    // The OLS resource belongs to the generation form only.
    let site = ReadoptPlan::decode(vector("site").plan_input.as_bytes()).unwrap();
    let with_target = grant_for("site", &site, |g| {
        g["targets"] = json!(["ols_lab_listener"])
    });
    assert_eq!(
        check(&site, &with_target, Some(cap()), Some(1500)),
        Err(ApprovalError::BindingMismatch)
    );
    let generation = ReadoptPlan::decode(vector("generation").plan_input.as_bytes()).unwrap();
    let without_target = grant_for("generation", &generation, |g| {
        g.as_object_mut().unwrap().remove("targets");
    });
    assert_eq!(
        check(&generation, &without_target, Some(cap()), Some(1500)),
        Err(ApprovalError::BindingMismatch)
    );
    let one_site = grant_for("generation", &generation, |g| {
        g["site_ids"] = json!(["blog1"])
    });
    assert_eq!(
        check(&generation, &one_site, Some(cap()), Some(1500)),
        Err(ApprovalError::BindingMismatch)
    );
}

#[test]
fn site_limits_bind_only_within_the_enrolled_quota() {
    let plan = ReadoptPlan::decode(vector("site").plan_input.as_bytes()).unwrap();
    let grant = grant_for("site", &plan, |_| {});
    let exact = SiteQuotaLimits::new(262_144, 20_000).unwrap();
    assert_eq!(check(&plan, &grant, Some(exact), Some(1500)), Ok(()));
    for lower in [
        SiteQuotaLimits::new(262_143, 20_000).unwrap(),
        SiteQuotaLimits::new(262_144, 19_999).unwrap(),
    ] {
        assert_eq!(
            check(&plan, &grant, Some(lower), Some(1500)),
            Err(ApprovalError::BindingMismatch)
        );
    }
    assert_eq!(
        check(&plan, &grant, None, Some(1500)),
        Err(ApprovalError::BindingMismatch),
        "a site form needs an enrolled quota"
    );
    let generation = ReadoptPlan::decode(vector("generation").plan_input.as_bytes()).unwrap();
    let grant = grant_for("generation", &generation, |_| {});
    assert_eq!(check(&generation, &grant, None, Some(1500)), Ok(()));
}
