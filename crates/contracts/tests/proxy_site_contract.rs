//! CP08 `proxy_site_provision` plan/grant checks (W571); no signer, executor or host effects.

use rustiron_contracts::{
    Id, Timestamp,
    approval::{
        ApprovalError, PlanKind, PreparedPlan, ProxyBindingContext, ProxyGrant, ProxyPlan,
        Sha256Digest, check_proxy_binding, routable_port, valid_prefix,
    },
};
use serde_json::{Value, json};

const PLAN: &[u8] = include_bytes!("fixtures/proxy-site-plan.json");
const GRANT: &[u8] = include_bytes!("fixtures/proxy-site-grant.json");
/// Computed independently with Python's json/hashlib when the fixture was made.
const PLAN_DIGEST: &str = "4cfba528410ceb7335442c622ce436e43fdc8ccdf5093afb7e1e064ecb9a6b34";

fn edited(bytes: &[u8], pointer: &str, new: Option<Value>) -> Vec<u8> {
    let mut record: Value = serde_json::from_slice(bytes).unwrap();
    match new {
        Some(new) => match record.pointer_mut(pointer) {
            Some(slot) => *slot = new,
            None => {
                record
                    .as_object_mut()
                    .unwrap()
                    .insert(pointer.trim_start_matches('/').to_owned(), new);
            }
        },
        None => {
            let (parent, member) = pointer.rsplit_once('/').unwrap();
            let object = if parent.is_empty() {
                &mut record
            } else {
                record.pointer_mut(parent).unwrap()
            };
            object.as_object_mut().unwrap().remove(member);
        }
    }
    serde_json::to_vec(&record).unwrap()
}

fn id(text: &str) -> Id {
    Id::try_from(text.to_owned()).unwrap()
}

fn check(plan: &ProxyPlan, grant: &ProxyGrant, now: Option<u64>) -> Result<(), ApprovalError> {
    check_proxy_binding(
        plan,
        grant,
        &ProxyBindingContext {
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

#[test]
fn fixture_decodes_with_independently_computed_digest_and_binds() {
    let plan = ProxyPlan::decode(PLAN).unwrap();
    let grant = ProxyGrant::decode(GRANT).unwrap();
    assert_eq!(plan.digest().as_str(), PLAN_DIGEST);
    assert_eq!(plan.site_id().as_str(), "ytproxy");
    assert_eq!(plan.hostname().as_str(), "yt.example.test");
    assert_eq!(
        plan.routes()
            .iter()
            .map(|route| (route.prefix.as_str(), route.port))
            .collect::<Vec<_>>(),
        [("/", 3100), ("/api/", 3101), ("/downloads/", 3101)]
    );
    assert_eq!(plan.websockets()[0].prefix, "/ws/");
    assert_eq!(plan.ports(), [3100, 3101]);
    assert_eq!(grant.grant_id().as_str(), "grant_proxy_site");
    assert_eq!(check(&plan, &grant, Some(1500)), Ok(()));
    let prepared = PreparedPlan::decode(PLAN).unwrap();
    assert_eq!(prepared.kind(), PlanKind::ProxySiteProvision);
    assert_eq!(prepared.kind().as_str(), "proxy_site_provision");
    assert_eq!(prepared.digest().as_str(), PLAN_DIGEST);
}

#[test]
fn prefixes_and_ports_follow_the_grammar() {
    for good in ["/", "/api/", "/downloads/", "/a/b-c/d_e/", "/v1.2/"] {
        assert!(valid_prefix(good), "{good}");
    }
    for bad in [
        "", "api/", "/api", "//", "/API/", "/a//b/", "/./", "/../", "/a b/", "/a?b/", "/%2e/",
    ] {
        assert!(!valid_prefix(bad), "{bad}");
    }
    assert!(!valid_prefix(&format!("/{}/", "a".repeat(127))));
    for port in [1024, 3000, 3552, 43187, 65535] {
        assert!(routable_port(port), "{port}");
    }
    for port in [0, 22, 80, 443, 1023, 3306] {
        assert!(!routable_port(port), "{port}");
    }
}

#[test]
fn plan_semantics_are_closed() {
    for (pointer, new) in [
        ("/schema_version", Some(json!(2))),
        ("/verb", Some(json!("site_provision"))),
        ("/site_id", Some(json!("Yt"))),
        ("/hostname", Some(json!("yt.example.test."))),
        ("/routes", Some(json!([]))),
        ("/routes", Some(json!([{"prefix": "/api/", "port": 3101}]))),
        (
            "/routes",
            Some(json!([{"prefix": "/", "port": 3100}, {"prefix": "/", "port": 3101}])),
        ),
        ("/routes/0/port", Some(json!(80))),
        ("/routes/0/port", Some(json!(3306))),
        ("/routes/0/port", Some(json!(70000))),
        ("/routes/1/prefix", Some(json!("/api"))),
        ("/routes/1/prefix", Some(json!("/../"))),
        ("/routes/0/address", Some(json!("10.0.0.5"))),
        ("/routes/0/host", Some(json!("other.test"))),
        (
            "/routes",
            Some(json!(
                (0..9)
                    .map(|n| json!({"prefix": format!("/p{n}/"), "port": 3000}))
                    .chain([json!({"prefix": "/", "port": 3000})])
                    .collect::<Vec<_>>()
            )),
        ),
        ("/websockets", None),
        ("/websockets/0/port", Some(json!(1023))),
        ("/websockets/0/prefix", Some(json!("ws"))),
        (
            "/websockets",
            Some(json!([{"prefix": "/ws/", "port": 3100}, {"prefix": "/ws/", "port": 3101}])),
        ),
        ("/expected_effects/starts_services", Some(json!(true))),
        ("/expected_effects/backs_up_services", Some(json!(true))),
        ("/expected_effects/traffic_activation", Some(json!(true))),
        ("/expected_effects/forwards_to_loopback", Some(json!(false))),
        ("/expected_effects/extra", Some(json!(true))),
        ("/expires_at", Some(json!(1000))),
        ("/limitations", Some(json!(vec!["x"; 9]))),
        ("/upstream", Some(json!("http://10.0.0.5:3000"))),
    ] {
        assert!(
            ProxyPlan::decode(&edited(PLAN, pointer, new.clone())).is_err(),
            "{pointer} {new:?}"
        );
    }
    // No WebSocket path is allowed.
    assert!(ProxyPlan::decode(&edited(PLAN, "/websockets", Some(json!([])))).is_ok());
}

#[test]
fn grant_semantics_are_closed() {
    for (pointer, new) in [
        ("/schema_version", Some(json!(2))),
        ("/verbs", Some(json!(["site_provision"]))),
        (
            "/verbs",
            Some(json!(["proxy_site_provision", "proxy_site_provision"])),
        ),
        ("/site_ids", Some(json!(["ytproxy", "other1"]))),
        ("/site_ids", Some(json!([]))),
        ("/max_operations", Some(json!(2))),
        ("/issuer", Some(json!("agent_1"))),
        ("/expires_at", Some(json!(1100))),
        ("/extra", Some(json!(1))),
    ] {
        assert!(
            ProxyGrant::decode(&edited(GRANT, pointer, new.clone())).is_err(),
            "{pointer} {new:?}"
        );
    }
}

#[test]
fn binding_and_time_are_checked() {
    let plan = ProxyPlan::decode(PLAN).unwrap();
    for (pointer, new) in [
        ("/plan_digest", json!("c".repeat(64))),
        ("/plan_id", json!("plan_other")),
        ("/host_id", json!("host_other")),
        ("/host_epoch", json!("epoch_2")),
        ("/requester", json!("agent_2")),
        ("/issuer", json!("operator_2")),
        ("/signer_policy_epoch", json!("policy_2")),
        ("/site_ids", json!(["other1"])),
        ("/risk_class", json!("production_candidate")),
        ("/valid_from", json!(900)),
        ("/expires_at", json!(2100)),
    ] {
        let grant = ProxyGrant::decode(&edited(GRANT, pointer, Some(new.clone())));
        if let Ok(grant) = grant {
            assert_eq!(
                check(&plan, &grant, Some(1500)),
                Err(ApprovalError::BindingMismatch),
                "{pointer} {new}"
            );
        }
    }
    let grant = ProxyGrant::decode(GRANT).unwrap();
    assert_eq!(
        check(&plan, &grant, None),
        Err(ApprovalError::ClockUncertain)
    );
    for now in [1099, 1900] {
        assert_eq!(
            check(&plan, &grant, Some(now)),
            Err(ApprovalError::OutsideValidity),
            "{now}"
        );
    }
}
