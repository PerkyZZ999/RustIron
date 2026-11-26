//! W341 (D-028 item 3): the product profile takes per-site quota limits only
//! from a signed site plan v2. A v1 plan, whose limits would come from policy,
//! is refused before intent. W399 (D-047): it also admits only the install
//! recipe, so no product site is left at the WordPress installer.

use rustiron_contracts::Timestamp;
use rustiron_executor::{AdmissionRequest, Executor, ExecutorError, Fault};
use rustiron_journal::{ProvisionState, ProvisionStep};
use serde_json::Value;

use super::BackupFixture;

const V1_PLAN: &[u8] = include_bytes!("../../../contracts/tests/fixtures/site-plan.json");
const V1_GRANT: &[u8] = include_bytes!("../../../contracts/tests/fixtures/site-grant.json");
const V2_VECTORS: &str =
    include_str!("../../../contracts/tests/fixtures/site-plan-v2-vectors.json");

fn request<'a>(plan: &'a [u8], grant: &'a [u8], signature: &'a [u8]) -> AdmissionRequest<'a> {
    AdmissionRequest {
        peer_uid: 4242,
        plan,
        grant,
        signature,
        operation_id: "op_product_site".to_owned().try_into().unwrap(),
        idempotency_key: "key_product_site".to_owned().try_into().unwrap(),
        now: Some(Timestamp::try_from(1200).unwrap()),
    }
}

#[test]
fn product_site_provision_requires_signed_v2_limits() {
    let fixture = BackupFixture::new();
    let mut executor = Executor::initialize(fixture.anchor.clone()).unwrap();
    let before = fixture.replay_state();
    let v1_signature = fixture.sign(V1_GRANT);
    let v1 = request(V1_PLAN, V1_GRANT, &v1_signature);
    assert_eq!(
        executor.provision(&v1).err(),
        Some(ExecutorError::BindingDenied),
        "a v1 plan takes its limits from policy"
    );
    assert_eq!(executor.provision_status(&v1.operation_id).unwrap(), None);
    assert_eq!(fixture.replay_state(), before);

    // W399: vector 1 names the install recipe; vector 0 the unpack-only one.
    let vectors: Value = serde_json::from_str(V2_VECTORS).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(vectors[1]["plan_input"].as_str().unwrap()).unwrap()["recipe_id"],
        "wordpress713_install_v1"
    );
    let plan = vectors[1]["plan_input"].as_str().unwrap().as_bytes();
    let grant = vectors[1]["grant_input"].as_str().unwrap().as_bytes();
    let signature = fixture.sign(grant);
    executor.inject_fault(Fault::AfterProvisionStepBegin);
    assert_eq!(
        executor.provision(&request(plan, grant, &signature)).err(),
        Some(ExecutorError::Unavailable),
        "the v2 plan is admitted; the fault stops after the first intent"
    );
    let running = executor
        .provision_status(&v1.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(running.state, ProvisionState::Running);
    assert_eq!(running.steps[0].step, ProvisionStep::Account);
}

/// W399 (D-047): a signed v2 plan with the unpack-only recipe would leave the
/// site at the WordPress installer, where the first visitor sets the admin
/// login. The product profile refuses it before intent and records nothing.
#[test]
fn product_site_provision_refuses_the_unpack_only_recipe() {
    let fixture = BackupFixture::new();
    let mut executor = Executor::initialize(fixture.anchor.clone()).unwrap();
    let before = fixture.replay_state();
    let vectors: Value = serde_json::from_str(V2_VECTORS).unwrap();
    let input = vectors[0]["plan_input"].as_str().unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(input).unwrap()["recipe_id"],
        "wordpress713_v1"
    );
    let grant = vectors[0]["grant_input"].as_str().unwrap().as_bytes();
    let signature = fixture.sign(grant);
    let unpack_only = request(input.as_bytes(), grant, &signature);
    assert_eq!(
        executor.provision(&unpack_only).err(),
        Some(ExecutorError::BindingDenied)
    );
    assert_eq!(
        executor
            .provision_status(&unpack_only.operation_id)
            .unwrap(),
        None
    );
    assert_eq!(fixture.replay_state(), before);
}
