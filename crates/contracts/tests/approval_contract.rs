//! Public fixture plan/grant checks; no signer, executor or host effects.

use rustiron_contracts::{
    Id, Timestamp,
    approval::{
        ApprovalError, FixtureBindingContext, FixtureGrant, FixturePlan, Sha256Digest,
        check_fixture_binding,
    },
};
use serde_json::{Value, json};

const PLAN: &[u8] = include_bytes!("fixtures/fixture-plan.json");
const GRANT: &[u8] = include_bytes!("fixtures/fixture-grant.json");

#[test]
fn complete_fixture_records_retain_canonical_original_bytes() {
    let plan = FixturePlan::decode(PLAN).unwrap();
    let grant = FixtureGrant::decode(GRANT).unwrap();
    assert_eq!(
        FixturePlan::decode(plan.as_bytes()).unwrap().digest(),
        plan.digest()
    );
    assert_eq!(
        FixtureGrant::decode(grant.as_bytes()).unwrap().as_bytes(),
        grant.as_bytes()
    );
}

fn plan_value() -> Value {
    serde_json::from_slice(PLAN).unwrap()
}
fn grant_value() -> Value {
    serde_json::from_slice(GRANT).unwrap()
}
fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn changed_plan(pointer: &str, value: Value) -> Result<FixturePlan, ApprovalError> {
    let mut record = plan_value();
    *record.pointer_mut(pointer).unwrap() = value;
    FixturePlan::decode(&bytes(&record))
}

fn changed_grant(pointer: &str, value: Value) -> Result<FixtureGrant, ApprovalError> {
    let mut record = grant_value();
    *record.pointer_mut(pointer).unwrap() = value;
    FixtureGrant::decode(&bytes(&record))
}

fn check(plan: &FixturePlan, grant: &FixtureGrant, now: Option<u64>) -> Result<(), ApprovalError> {
    let host = Id::try_from("host_lab".to_owned()).unwrap();
    let epoch = Id::try_from("epoch_1".to_owned()).unwrap();
    let profile = Sha256Digest::try_from("a".repeat(64)).unwrap();
    let requester = Id::try_from("agent_1".to_owned()).unwrap();
    let issuer = Id::try_from("operator_1".to_owned()).unwrap();
    let policy = Id::try_from("policy_1".to_owned()).unwrap();
    check_fixture_binding(
        plan,
        grant,
        &FixtureBindingContext {
            host_id: &host,
            host_epoch: &epoch,
            profile_digest: &profile,
            requester: &requester,
            issuer: &issuer,
            signer_policy_epoch: &policy,
            now: now.map(|value| Timestamp::try_from(value).unwrap()),
        },
    )
}

#[test]
fn matching_fixture_bindings_pass_without_claiming_signature_or_replay_proof() {
    assert_eq!(
        check(
            &FixturePlan::decode(PLAN).unwrap(),
            &FixtureGrant::decode(GRANT).unwrap(),
            Some(1200)
        ),
        Ok(())
    );
}

macro_rules! missing_plan_fields {
    ($($test:ident: $field:literal),* $(,)?) => { $(
        #[test] fn $test() {
            let mut value = plan_value();
            value.as_object_mut().unwrap().remove($field);
            assert_eq!(FixturePlan::decode(&bytes(&value)).unwrap_err(), ApprovalError::InvalidMessage);
        }
    )* };
}

missing_plan_fields! {
    missing_plan_version: "schema_version", missing_plan_id: "plan_id",
    missing_plan_host: "host_id", missing_plan_epoch: "host_epoch",
    missing_plan_profile: "profile_digest", missing_plan_requester: "requester",
    missing_plan_resources: "resource_ids", missing_plan_observations: "observations",
    missing_plan_steps: "steps", missing_plan_artifacts: "artifact_digests",
    missing_plan_generator: "generator_version", missing_plan_effects: "expected_effects",
    missing_plan_dependencies: "dependencies", missing_plan_external: "external_effects",
    missing_plan_radius: "blast_radius", missing_plan_risk: "risk_class",
    missing_plan_reversibility: "reversibility", missing_plan_downtime: "downtime_estimate",
    missing_plan_data_loss: "data_loss_exposure", missing_plan_budgets: "budgets",
    missing_plan_start: "valid_from", missing_plan_expiry: "expires_at",
    missing_plan_compensation: "compensation", missing_plan_limits: "limitations",
}

macro_rules! rejected_plan_changes {
    ($($test:ident: $pointer:literal => $value:expr, $error:ident);* $(;)?) => { $(
        #[test] fn $test() {
            assert_eq!(changed_plan($pointer, $value).unwrap_err(), ApprovalError::$error);
        }
    )* };
}

rejected_plan_changes! {
    newer_plan_version: "/schema_version" => json!(2), UnsupportedVersion;
    numeric_version_alias: "/schema_version" => json!(1.0), InvalidMessage;
    empty_resources: "/resource_ids" => json!([]), InvalidPlan;
    duplicate_resources: "/resource_ids" => json!(["fixture_1","fixture_1"]), InvalidPlan;
    wildcard_resource: "/resource_ids" => json!(["*"]), InvalidMessage;
    unknown_required_precondition: "/observations/0" => json!({"state":"unknown","resource_id":"fixture_1","reason":"not_checked"}), UnknownPrecondition;
    incomplete_required_precondition: "/observations/0/complete" => json!(false), UnknownPrecondition;
    missing_observation: "/observations" => json!([]), InvalidPlan;
    future_observation: "/observations/0/observed_at" => json!(1001), InvalidPlan;
    stale_observation: "/observations/0/observed_at" => json!(699), InvalidPlan;
    other_observed_generation: "/observations/0/generation" => json!("other"), InvalidPlan;
    other_observed_resource: "/observations/0/resource_id" => json!("other"), InvalidPlan;
    no_steps: "/steps" => json!([]), InvalidPlan;
    arbitrary_verb: "/steps/0/verb" => json!("run_shell"), InvalidMessage;
    arbitrary_recipe: "/steps/0/effect" => json!("caller_recipe"), InvalidMessage;
    wrong_recipe_role: "/steps/0/effect" => json!("fixture_restore_v1"), InvalidPlan;
    other_step_resource: "/steps/0/resource_id" => json!("other"), InvalidPlan;
    unchanged_generation: "/steps/0/target_generation" => json!("gen_old"), InvalidPlan;
    missing_artifact: "/artifact_digests" => json!([]), InvalidPlan;
    artifact_reference_mismatch: "/artifact_digests/0/artifact_id" => json!("other"), InvalidPlan;
    uppercase_digest: "/artifact_digests/0/digest" => json!("A".repeat(64)), InvalidMessage;
    short_digest: "/profile_digest" => json!("abc"), InvalidMessage;
    bad_generator: "/generator_version" => json!("fixture_generator_v2"), InvalidMessage;
    unbound_dependency: "/dependencies" => json!(["other"]), InvalidPlan;
    external_effect: "/external_effects" => json!(["network_access"]), InvalidPlan;
    hidden_network_effect: "/expected_effects/network_access" => json!(true), InvalidPlan;
    hidden_recycle: "/expected_effects/global_recycles" => json!(1), InvalidPlan;
    suppressed_effect: "/expected_effects/generation_switches" => json!(0), InvalidPlan;
    missing_probe_scope: "/expected_effects/probe_resources" => json!([]), InvalidPlan;
    other_blast_radius: "/blast_radius/resource_ids" => json!(["other"]), InvalidPlan;
    real_host_blast_radius: "/blast_radius/all_hosted_sites" => json!(true), InvalidPlan;
    non_lab_risk: "/risk_class" => json!("production"), InvalidMessage;
    arbitrary_reversibility: "/reversibility" => json!("fully_reversible"), InvalidMessage;
    implicit_zero_estimate: "/downtime_estimate" => json!(0), InvalidMessage;
    estimate_without_basis: "/data_loss_exposure" => json!({"state":"estimated","value":0,"basis":""}), InvalidPlan;
    empty_time_window: "/expires_at" => json!(1000), InvalidPlan;
    too_long_window: "/expires_at" => json!(4601), InvalidPlan;
    float_budget: "/budgets/runtime_seconds" => json!(1.5), InvalidMessage;
    zero_runtime: "/budgets/runtime_seconds" => json!(0), InvalidPlan;
    excessive_runtime: "/budgets/runtime_seconds" => json!(301), InvalidPlan;
    cpu_exceeds_runtime: "/budgets/cpu_seconds" => json!(61), InvalidPlan;
    zero_memory: "/budgets/memory_bytes" => json!(0), InvalidPlan;
    excessive_pids: "/budgets/pids" => json!(33), InvalidPlan;
    excessive_output: "/budgets/output_bytes" => json!(1048577), InvalidPlan;
    excessive_temp: "/budgets/temporary_bytes" => json!(16777217), InvalidPlan;
    unbounded_recycle_budget: "/budgets/global_recycles" => json!(1), InvalidPlan;
    wrong_compensation_generation: "/compensation/generation" => json!("other"), InvalidPlan;
    arbitrary_compensation: "/compensation/recipe" => json!("fixture_activate_v1"), InvalidPlan;
    multiple_compensations: "/compensation/max_attempts" => json!(2), InvalidPlan;
    compensation_before_expiry: "/compensation/valid_until" => json!(1999), InvalidPlan;
    excessive_recovery_window: "/compensation/valid_until" => json!(2301), InvalidPlan;
    positional_settings: "/steps/0/settings" => json!(["beta"]), InvalidMessage;
    positional_artifact: "/artifact_digests/0" => json!(["artifact_beta","c".repeat(64)]), InvalidMessage;
    positional_budgets: "/budgets" => json!([1,0,1,60,30,67108864,4,4096,4096]), InvalidMessage;
    unknown_settings_field: "/steps/0/settings" => json!({"variant":"beta","command":"INPUT_CANARY"}), InvalidMessage;
    unknown_estimate_field: "/downtime_estimate" => json!({"state":"unknown","reason":"not_checked","value":0}), InvalidMessage;
}

macro_rules! bound_changes {
    ($($test:ident: $pointer:literal => $value:expr);* $(;)?) => { $(
        #[test] fn $test() {
            let original = FixturePlan::decode(PLAN).unwrap();
            let changed = changed_plan($pointer, $value).unwrap();
            assert_ne!(changed.digest(), original.digest());
            assert_eq!(check(&changed, &FixtureGrant::decode(GRANT).unwrap(), Some(1200)), Err(ApprovalError::BindingMismatch));
        }
    )* };
}

bound_changes! {
    plan_id_is_hashed: "/plan_id" => json!("other_plan");
    host_is_hashed: "/host_id" => json!("other_host");
    epoch_is_hashed: "/host_epoch" => json!("other_epoch");
    profile_is_hashed: "/profile_digest" => json!("d".repeat(64));
    requester_is_hashed: "/requester" => json!("other_requester");
    observation_digest_is_hashed: "/observations/0/content_digest" => json!("d".repeat(64));
    observation_time_is_hashed: "/observations/0/observed_at" => json!(989);
    step_id_is_hashed: "/steps/0/step_id" => json!("other_step");
    semantic_settings_are_hashed: "/steps/0/settings/variant" => json!("alpha");
    target_generation_is_hashed: "/steps/0/target_generation" => json!("other_generation");
    artifact_content_is_hashed: "/artifact_digests/0/digest" => json!("d".repeat(64));
    diagnostic_unknown_reason_is_hashed: "/downtime_estimate/reason" => json!("unavailable");
    diagnostic_estimate_is_hashed: "/data_loss_exposure/value" => json!(1);
    budget_is_hashed: "/budgets/runtime_seconds" => json!(61);
    validity_is_hashed: "/valid_from" => json!(1001);
    limitations_are_hashed: "/limitations/0" => json!("Different review limitation.");
}

macro_rules! grant_mismatches {
    ($($test:ident: $pointer:literal => $value:expr);* $(;)?) => { $(
        #[test] fn $test() {
            let grant = changed_grant($pointer, $value).unwrap();
            assert_eq!(check(&FixturePlan::decode(PLAN).unwrap(), &grant, Some(1200)), Err(ApprovalError::BindingMismatch));
        }
    )* };
}

grant_mismatches! {
    wrong_grant_digest: "/plan_digest" => json!("d".repeat(64));
    wrong_grant_plan: "/plan_id" => json!("other");
    wrong_grant_host: "/host_id" => json!("other");
    wrong_grant_epoch: "/host_epoch" => json!("other");
    wrong_grant_profile: "/profile_digest" => json!("d".repeat(64));
    wrong_grant_requester: "/requester" => json!("other");
    wrong_grant_issuer: "/issuer" => json!("other");
    wrong_grant_policy_epoch: "/signer_policy_epoch" => json!("other");
    wrong_grant_resource: "/resource_ids" => json!(["other"]);
    expanded_grant_start: "/valid_from" => json!(999);
    expanded_grant_expiry: "/expires_at" => json!(2001);
    expanded_runtime: "/budgets/runtime_seconds" => json!(61);
    underfunded_runtime: "/budgets/runtime_seconds" => json!(59);
    wrong_recovery_generation: "/compensation/generation" => json!("other");
}

#[test]
fn grant_cannot_approve_its_requester() {
    assert_eq!(
        changed_grant("/issuer", json!("agent_1")).unwrap_err(),
        ApprovalError::InvalidGrant
    );
}

#[test]
fn grant_cannot_authorize_multiple_operations() {
    assert_eq!(
        changed_grant("/max_operations", json!(2)).unwrap_err(),
        ApprovalError::InvalidGrant
    );
}

#[test]
fn grant_cannot_add_another_verb() {
    assert_eq!(
        changed_grant("/verbs", json!(["config_activate", "site_eject"])).unwrap_err(),
        ApprovalError::InvalidMessage
    );
}

#[test]
fn repeated_verb_is_not_additional_authority() {
    assert_eq!(
        changed_grant("/verbs", json!(["config_activate", "config_activate"])).unwrap_err(),
        ApprovalError::InvalidGrant
    );
}

#[test]
fn unknown_time_denies_consideration() {
    assert_eq!(
        check(
            &FixturePlan::decode(PLAN).unwrap(),
            &FixtureGrant::decode(GRANT).unwrap(),
            None
        ),
        Err(ApprovalError::ClockUncertain)
    );
}

#[test]
fn time_before_start_denies_consideration() {
    assert_eq!(
        check(
            &FixturePlan::decode(PLAN).unwrap(),
            &FixtureGrant::decode(GRANT).unwrap(),
            Some(1099)
        ),
        Err(ApprovalError::OutsideValidity)
    );
}

#[test]
fn exact_start_is_valid() {
    assert_eq!(
        check(
            &FixturePlan::decode(PLAN).unwrap(),
            &FixtureGrant::decode(GRANT).unwrap(),
            Some(1100)
        ),
        Ok(())
    );
}

#[test]
fn exact_expiry_denies_new_work_even_with_recovery_time_remaining() {
    assert_eq!(
        check(
            &FixturePlan::decode(PLAN).unwrap(),
            &FixtureGrant::decode(GRANT).unwrap(),
            Some(1900)
        ),
        Err(ApprovalError::OutsideValidity)
    );
}

#[test]
fn changed_matching_host_claims_do_not_override_independent_policy() {
    let plan = changed_plan("/host_id", json!("other")).unwrap();
    let mut grant = grant_value();
    grant["host_id"] = json!("other");
    grant["plan_digest"] = json!(plan.digest().as_str());
    assert_eq!(
        check(
            &plan,
            &FixtureGrant::decode(&bytes(&grant)).unwrap(),
            Some(1200)
        ),
        Err(ApprovalError::BindingMismatch)
    );
}

#[test]
fn malformed_input_is_not_echoed_in_contract_errors() {
    let error = FixturePlan::decode(br#"{"INPUT_CANARY":"secret"}"#).unwrap_err();
    assert_eq!(error, ApprovalError::InvalidMessage);
    assert!(!error.to_string().contains("INPUT_CANARY"));
    assert!(!error.to_string().contains("secret"));
}

#[test]
fn decoded_duplicate_keys_are_rejected_before_typed_buffering() {
    let source = std::str::from_utf8(PLAN).unwrap().replacen(
        "\"schema_version\": 1",
        "\"schema_version\": 1,\"\\u0073chema_version\": 1",
        1,
    );
    assert_eq!(
        FixturePlan::decode(source.as_bytes()).unwrap_err(),
        ApprovalError::InvalidMessage
    );
}

macro_rules! missing_grant_fields {
    ($($test:ident: $field:literal),* $(,)?) => { $(
        #[test] fn $test() {
            let mut value = grant_value();
            value.as_object_mut().unwrap().remove($field);
            assert_eq!(FixtureGrant::decode(&bytes(&value)).unwrap_err(), ApprovalError::InvalidMessage);
        }
    )* };
}

missing_grant_fields! {
    missing_grant_version: "schema_version", missing_grant_id: "grant_id",
    missing_grant_nonce: "nonce", missing_grant_plan: "plan_id",
    missing_grant_digest: "plan_digest", missing_grant_host: "host_id",
    missing_grant_epoch: "host_epoch", missing_grant_profile: "profile_digest",
    missing_grant_issuer: "issuer", missing_grant_requester: "requester",
    missing_grant_policy: "signer_policy_epoch", missing_grant_resources: "resource_ids",
    missing_grant_verbs: "verbs", missing_grant_risk: "risk_class",
    missing_grant_start: "valid_from", missing_grant_expiry: "expires_at",
    missing_grant_budgets: "budgets", missing_grant_compensation: "compensation",
    missing_grant_operation_bound: "max_operations",
}

macro_rules! closed_plan_records {
    ($($test:ident: $pointer:literal),* $(,)?) => { $(
        #[test] fn $test() {
            let mut value = plan_value();
            value.pointer_mut($pointer).unwrap().as_object_mut().unwrap().insert("INPUT_CANARY".into(), json!("secret"));
            assert_eq!(FixturePlan::decode(&bytes(&value)).unwrap_err(), ApprovalError::InvalidMessage);
        }
    )* };
}

closed_plan_records! {
    plan_has_no_extension_bag: "", observation_has_no_extension_bag: "/observations/0",
    step_has_no_extension_bag: "/steps/0", artifact_has_no_extension_bag: "/artifact_digests/0",
    settings_have_no_extension_bag: "/steps/0/settings", effects_have_no_extension_bag: "/expected_effects",
    blast_radius_has_no_extension_bag: "/blast_radius", budgets_have_no_extension_bag: "/budgets",
    compensation_has_no_extension_bag: "/compensation", estimates_have_no_extension_bag: "/data_loss_exposure",
}

#[test]
fn grant_has_no_policy_extension_bag() {
    let mut value = grant_value();
    value["enroll_signer"] = json!("INPUT_CANARY");
    assert_eq!(
        FixtureGrant::decode(&bytes(&value)).unwrap_err(),
        ApprovalError::InvalidMessage
    );
}

#[test]
fn signature_transport_is_not_stripped_out_of_semantic_plan() {
    let mut value = plan_value();
    value["signature"] = json!("INPUT_CANARY");
    assert_eq!(
        FixturePlan::decode(&bytes(&value)).unwrap_err(),
        ApprovalError::InvalidMessage
    );
}

#[test]
fn recovery_window_cannot_expand_even_when_normal_window_is_unchanged() {
    let plan = changed_plan("/compensation/valid_until", json!(2050)).unwrap();
    let mut grant = grant_value();
    grant["plan_digest"] = json!(plan.digest().as_str());
    assert_eq!(
        check(
            &plan,
            &FixtureGrant::decode(&bytes(&grant)).unwrap(),
            Some(1200)
        ),
        Err(ApprovalError::BindingMismatch)
    );
}

macro_rules! independent_policy_facts {
    ($($test:ident: $pointer:literal => $value:expr);* $(;)?) => { $(
        #[test] fn $test() {
            let plan = changed_plan($pointer, $value).unwrap();
            let mut grant = grant_value();
            *grant.pointer_mut($pointer).unwrap() = $value;
            grant["plan_digest"] = json!(plan.digest().as_str());
            assert_eq!(check(&plan, &FixtureGrant::decode(&bytes(&grant)).unwrap(), Some(1200)), Err(ApprovalError::BindingMismatch));
        }
    )* };
}

independent_policy_facts! {
    consistent_claimed_epoch_cannot_override_policy: "/host_epoch" => json!("other");
    consistent_claimed_profile_cannot_override_policy: "/profile_digest" => json!("d".repeat(64));
    consistent_claimed_requester_cannot_override_policy: "/requester" => json!("other");
}

#[test]
fn nonce_and_grant_id_remain_in_the_exact_signature_payload() {
    let grant = FixtureGrant::decode(GRANT).unwrap();
    assert_ne!(
        grant.as_bytes(),
        changed_grant("/nonce", json!("another_nonce"))
            .unwrap()
            .as_bytes()
    );
    assert_ne!(
        grant.as_bytes(),
        changed_grant("/grant_id", json!("another_grant"))
            .unwrap()
            .as_bytes()
    );
}

#[test]
fn key_reordering_and_whitespace_preserve_full_fixture_binding() {
    let reparsed = FixturePlan::decode(&bytes(&plan_value())).unwrap();
    assert_eq!(
        check(&reparsed, &FixtureGrant::decode(GRANT).unwrap(), Some(1200)),
        Ok(())
    );
}

#[test]
fn two_activations_are_not_hidden_inside_one_fixture_step_budget() {
    let mut value = plan_value();
    let second = value["steps"][0].clone();
    value["steps"].as_array_mut().unwrap().push(second);
    assert_eq!(
        FixturePlan::decode(&bytes(&value)).unwrap_err(),
        ApprovalError::InvalidPlan
    );
}

#[test]
fn record_byte_limit_applies_before_closed_schema_parsing() {
    let bytes = vec![b' '; rustiron_contracts::MAX_REQUEST_BYTES + 1];
    assert_eq!(
        FixturePlan::decode(&bytes).unwrap_err(),
        ApprovalError::RequestTooLarge
    );
    assert_eq!(
        FixtureGrant::decode(&bytes).unwrap_err(),
        ApprovalError::RequestTooLarge
    );
}

#[test]
fn exponent_alias_does_not_become_an_integer_budget() {
    let source = std::str::from_utf8(PLAN)
        .unwrap()
        .replace("\"runtime_seconds\": 60", "\"runtime_seconds\": 6e1");
    assert_eq!(
        FixturePlan::decode(source.as_bytes()).unwrap_err(),
        ApprovalError::InvalidMessage
    );
}
