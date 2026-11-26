//! Create fresh bounded corpora, proving each seed's expected oracle path first.

use rustiron_contracts::{MAX_JSON_DEPTH, MAX_REQUEST_BYTES};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{env, fs, path::Path};

#[path = "support/admin_payload_seeds.rs"]
mod admin_payload_seeds;
#[path = "support/admin_seeds.rs"]
mod admin_seeds;
#[path = "support/inventory_seeds.rs"]
mod inventory_seeds;
#[path = "support/manifest_seeds.rs"]
mod manifest_seeds;
#[path = "support/query_seeds.rs"]
mod query_seeds;
#[path = "support/response_seeds.rs"]
mod response_seeds;
#[path = "support/s3_seeds.rs"]
mod s3_seeds;
#[path = "support/v1_plan_seeds.rs"]
mod v1_plan_seeds;
#[path = "support/wire_seeds.rs"]
mod wire_seeds;

const FIXTURES: [(&str, &[u8], &[u8]); 5] = [
    (
        "site",
        include_bytes!("../../crates/contracts/tests/fixtures/site-plan.json"),
        include_bytes!("../../crates/contracts/tests/fixtures/site-grant.json"),
    ),
    (
        "ols",
        include_bytes!("../../crates/contracts/tests/fixtures/ols-plan.json"),
        include_bytes!("../../crates/contracts/tests/fixtures/ols-grant.json"),
    ),
    (
        "eject",
        include_bytes!("../../crates/contracts/tests/fixtures/eject-plan.json"),
        include_bytes!("../../crates/contracts/tests/fixtures/eject-grant.json"),
    ),
    (
        "capture",
        include_bytes!("../../crates/contracts/tests/fixtures/capture-plan.json"),
        include_bytes!("../../crates/contracts/tests/fixtures/capture-grant.json"),
    ),
    (
        "probe",
        include_bytes!("../../crates/contracts/tests/fixtures/probe-plan.json"),
        include_bytes!("../../crates/contracts/tests/fixtures/probe-grant.json"),
    ),
];

fn main() {
    let destination = env::args_os().nth(1).expect("fresh corpus directory");
    let destination = Path::new(&destination);
    fs::create_dir(destination).expect("corpus destination must not exist");
    let mut records = Vec::new();
    let mut seed = |target: &str, name: &str, bytes: &[u8], accepted: bool| {
        let actual = match target {
            "canonical_object" => rustiron_fuzz::canonical_object(bytes),
            "prepared_plan" => rustiron_fuzz::prepared_plan(bytes),
            "grant" => rustiron_fuzz::grant(bytes),
            "submission" => rustiron_fuzz::submission(bytes),
            "apply_request" => rustiron_fuzz::apply_request(bytes),
            "submission_reply" => rustiron_fuzz::submission_reply(bytes),
            "apply_response" => rustiron_fuzz::apply_response(bytes),
            "read_response" => rustiron_fuzz::read_response(bytes),
            "status_response" => rustiron_fuzz::status_response(bytes),
            "evidence_response" => rustiron_fuzz::evidence_response(bytes),
            "read_request" => rustiron_fuzz::read_request(bytes),
            "status_query" => rustiron_fuzz::status_query(bytes),
            "evidence_query" => rustiron_fuzz::evidence_query(bytes),
            "plan_grant_binding" => rustiron_fuzz::plan_grant_binding(bytes),
            "inventory_report" => rustiron_fuzz::inventory_report(bytes),
            "capture_manifest" => rustiron_fuzz::capture_manifest(bytes),
            "admin_request" => rustiron_fuzz::admin_request(bytes),
            "admin_reply" => rustiron_fuzz::admin_reply(bytes),
            "admin_capture_payload" => rustiron_fuzz::admin_capture_payload(bytes),
            "admin_probe_payload" => rustiron_fuzz::admin_probe_payload(bytes),
            "s3_versioning" => rustiron_fuzz::s3_versioning(bytes),
            "s3_object_lock" => rustiron_fuzz::s3_object_lock(bytes),
            "s3_retention" => rustiron_fuzz::s3_retention(bytes),
            "s3_list" => rustiron_fuzz::s3_list(bytes),
            "s3_batch" => rustiron_fuzz::s3_batch(bytes),
            "s3_curl" => rustiron_fuzz::s3_curl(bytes),
            "s3_timestamp" => rustiron_fuzz::s3_timestamp(bytes),
            "dns_zone" => rustiron_fuzz::dns_zone(bytes),
            _ => unreachable!(),
        };
        assert_eq!(
            actual, accepted,
            "seed {target}/{name} did not take its expected path"
        );
        fs::create_dir_all(destination.join(target)).unwrap();
        fs::write(destination.join(target).join(name), bytes).unwrap();
        records.push(
            json!({"target":target,"name":name,"accepted":actual,"bytes":bytes.len(),
                           "sha256":Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect::<String>()}),
        );
    };
    let vectors: Value = serde_json::from_str(include_str!(
        "../../crates/contracts/tests/fixtures/canonical-vectors.json"
    ))
    .unwrap();
    for vector in vectors.as_array().unwrap() {
        seed(
            "canonical_object",
            vector["name"].as_str().unwrap(),
            vector["input"].as_str().unwrap().as_bytes(),
            true,
        );
    }
    for (name, bytes, _) in FIXTURES {
        seed("canonical_object", name, bytes, true);
        seed("prepared_plan", name, bytes, true);
        let mut extra: Value = serde_json::from_slice(bytes).unwrap();
        extra["unexpected"] = true.into();
        seed(
            "prepared_plan",
            &format!("{name}-unknown-member"),
            &serde_json::to_vec(&extra).unwrap(),
            false,
        );
    }
    for (name, bytes) in [
        ("empty", b"".as_slice()),
        ("invalid-utf8", b"\xff"),
        ("duplicate-alias", br#"{"dup":0,"du\u0070":1}"#),
        ("fraction", br#"{"n":1.0}"#),
        ("exponent", br#"{"n":1e0}"#),
        ("negative-zero", br#"{"n":-0}"#),
        ("trailing", b"{} {}"),
        ("non-object", b"[{}]"),
        ("surrogate", br#"{"x":"\ud800"}"#),
    ] {
        seed("canonical_object", name, bytes, false);
        seed("prepared_plan", name, bytes, false);
    }
    let exact = format!(r#"{{"v":"{}"}}"#, "x".repeat(MAX_REQUEST_BYTES - 8));
    seed("canonical_object", "exact-size", exact.as_bytes(), true);
    let oversized = format!("{exact} ");
    seed("canonical_object", "oversized", oversized.as_bytes(), false);
    seed("prepared_plan", "oversized", oversized.as_bytes(), false);
    let exact_depth = format!(
        r#"{{"v":{}0{}}}"#,
        "[".repeat(MAX_JSON_DEPTH - 1),
        "]".repeat(MAX_JSON_DEPTH - 1)
    );
    seed(
        "canonical_object",
        "exact-depth",
        exact_depth.as_bytes(),
        true,
    );
    let too_deep = format!(
        r#"{{"v":{}0{}}}"#,
        "[".repeat(MAX_JSON_DEPTH),
        "]".repeat(MAX_JSON_DEPTH)
    );
    seed("canonical_object", "too-deep", too_deep.as_bytes(), false);
    seed(
        "prepared_plan",
        "fixture-switch",
        include_bytes!("../../crates/contracts/tests/fixtures/fixture-plan.json"),
        false,
    );
    seed(
        "prepared_plan",
        "grant",
        include_bytes!("../../crates/contracts/tests/fixtures/site-grant.json"),
        false,
    );
    let mut forbidden: Value = serde_json::from_slice(include_bytes!(
        "../../crates/contracts/tests/fixtures/site-plan.json"
    ))
    .unwrap();
    forbidden["expected_effects"]["traffic_activation"] = true.into();
    seed(
        "prepared_plan",
        "forbidden-effect",
        &serde_json::to_vec(&forbidden).unwrap(),
        false,
    );
    grant_seeds(&mut seed);
    wire_seeds::generate(&mut seed);
    response_seeds::generate(&mut seed);
    let header_checks = query_seeds::generate(&mut seed);
    inventory_seeds::generate(&mut seed);
    manifest_seeds::generate(&mut seed);
    admin_seeds::generate(&mut seed);
    admin_payload_seeds::generate(&mut seed);
    s3_seeds::generate(&mut seed);
    v1_plan_seeds::generate(&mut seed);
    let mut limits = response_seeds::input_limits();
    limits["inventory_report"] = rustiron_fuzz::INVENTORY_MAX_INPUT.into();
    limits["capture_manifest"] = rustiron_fuzz::MANIFEST_MAX_INPUT.into();
    limits["admin_request"] = rustiron_fuzz::ADMIN_REQUEST_MAX_INPUT.into();
    limits["admin_reply"] = rustiron_fuzz::ADMIN_REPLY_MAX_INPUT.into();
    limits["admin_capture_payload"] = rustiron_fuzz::ADMIN_PAYLOAD_MAX_INPUT.into();
    limits["admin_probe_payload"] = rustiron_fuzz::ADMIN_PAYLOAD_MAX_INPUT.into();
    for target in ["s3_versioning", "s3_object_lock", "s3_retention", "s3_list"] {
        limits[target] = rustiron_fuzz::S3_RESPONSE_MAX_INPUT.into();
    }
    limits["s3_batch"] = rustiron_fuzz::S3_BATCH_MAX_INPUT.into();
    limits["s3_curl"] = rustiron_fuzz::S3_CURL_MAX_INPUT.into();
    limits["s3_timestamp"] = rustiron_fuzz::S3_TIMESTAMP_MAX_INPUT.into();
    limits["dns_zone"] = rustiron_fuzz::DNS_ZONE_MAX_INPUT.into();
    let metadata = json!({"max_input_bytes":MAX_REQUEST_BYTES + 1,"seeds":records,"target_max_input_bytes":limits,"status_header_checks":header_checks});
    fs::write(
        destination.join("seeds.json"),
        serde_json::to_vec_pretty(&metadata).unwrap(),
    )
    .unwrap();
    println!("{}", serde_json::to_string(&metadata).unwrap());
}

fn grant_seeds(seed: &mut impl FnMut(&str, &str, &[u8], bool)) {
    for (index, (name, plan, grant)) in FIXTURES.iter().enumerate() {
        seed("grant", name, grant, true);
        let plan: Value = serde_json::from_slice(plan).unwrap();
        let grant: Value = serde_json::from_slice(grant).unwrap();
        let start = grant["valid_from"].as_u64().unwrap();
        let end = grant["expires_at"].as_u64().unwrap();
        for (suffix, now, accepted) in [
            ("valid", json!(1200), true),
            ("start", json!(start), true),
            ("before", json!(start - 1), false),
            ("expiry", json!(end), false),
            ("unknown-clock", Value::Null, false),
        ] {
            seed(
                "plan_grant_binding",
                &format!("{name}-{suffix}"),
                &serde_json::to_vec(&json!({"plan":plan,"grant":grant,"now":now})).unwrap(),
                accepted,
            );
        }
        for (field, value) in [
            ("max_operations", json!(2)),
            ("issuer", grant["requester"].clone()),
            ("unknown_member", json!(true)),
            ("verbs", json!(["unknown_verb"])),
        ] {
            let mut changed = grant.clone();
            changed[field] = value;
            seed(
                "grant",
                &format!("{name}-{field}"),
                &serde_json::to_vec(&changed).unwrap(),
                false,
            );
        }
        let mut changed = grant.clone();
        changed["plan_digest"] = json!("0".repeat(64));
        seed(
            "grant",
            &format!("{name}-unbound-digest"),
            &serde_json::to_vec(&changed).unwrap(),
            true,
        );
        seed(
            "plan_grant_binding",
            &format!("{name}-unbound-digest"),
            &serde_json::to_vec(&json!({"plan":plan,"grant":changed,"now":1200})).unwrap(),
            false,
        );
        for (field, time) in [
            ("valid_from", plan["valid_from"].as_u64().unwrap() - 1),
            ("expires_at", plan["expires_at"].as_u64().unwrap() + 1),
        ] {
            let mut changed = grant.clone();
            changed[field] = json!(time);
            seed(
                "grant",
                &format!("{name}-outside-plan-{field}"),
                &serde_json::to_vec(&changed).unwrap(),
                true,
            );
            seed(
                "plan_grant_binding",
                &format!("{name}-outside-plan-{field}"),
                &serde_json::to_vec(&json!({"plan":plan,"grant":changed,"now":1200})).unwrap(),
                false,
            );
        }
        if grant.get("snapshot_ids").is_some() {
            let mut changed = grant.clone();
            changed["snapshot_ids"] = json!(["f".repeat(64)]);
            seed(
                "grant",
                &format!("{name}-other-snapshot"),
                &serde_json::to_vec(&changed).unwrap(),
                true,
            );
            seed(
                "plan_grant_binding",
                &format!("{name}-other-snapshot"),
                &serde_json::to_vec(&json!({"plan":plan,"grant":changed,"now":1200})).unwrap(),
                false,
            );
        }
        if let Some(compensation) = grant.get("compensation") {
            let mut changed = grant.clone();
            let until = compensation["valid_until"].as_u64().unwrap();
            let end = grant["expires_at"].as_u64().unwrap();
            changed["compensation"]["valid_until"] =
                json!(if until > end { until - 1 } else { until + 1 });
            seed(
                "grant",
                &format!("{name}-other-compensation"),
                &serde_json::to_vec(&changed).unwrap(),
                true,
            );
            seed(
                "plan_grant_binding",
                &format!("{name}-other-compensation"),
                &serde_json::to_vec(&json!({"plan":plan,"grant":changed,"now":1200})).unwrap(),
                false,
            );
        }
        let other: Value =
            serde_json::from_slice(FIXTURES[(index + 1) % FIXTURES.len()].2).unwrap();
        seed(
            "plan_grant_binding",
            &format!("{name}-cross-kind"),
            &serde_json::to_vec(&json!({"plan":plan,"grant":other,"now":1200})).unwrap(),
            false,
        );
        let mut foreign_plan = plan.clone();
        foreign_plan["host_id"] = json!("other_host");
        let prepared = rustiron_contracts::approval::PreparedPlan::decode(
            &serde_json::to_vec(&foreign_plan).unwrap(),
        )
        .unwrap();
        let mut foreign_grant = grant.clone();
        foreign_grant["host_id"] = json!("other_host");
        foreign_grant["plan_digest"] = json!(prepared.digest().as_str());
        seed(
            "grant",
            &format!("{name}-foreign-host"),
            &serde_json::to_vec(&foreign_grant).unwrap(),
            true,
        );
        seed(
            "plan_grant_binding",
            &format!("{name}-foreign-host"),
            &serde_json::to_vec(&json!({"plan":foreign_plan,"grant":foreign_grant,"now":1200}))
                .unwrap(),
            false,
        );
    }
    product_backup_seeds(seed);
    site_v2_seeds(seed);
    readopt_seeds(seed);
    standing_seeds(seed);
    for (name, bytes) in [
        ("empty", b"".as_slice()),
        ("non-object", b"[]"),
        ("invalid-utf8", b"{\"x\":\"\xff\"}"),
        ("duplicate-alias", br#"{"dup":0,"du\u0070":1}"#),
        ("fraction", br#"{"n":1.0}"#),
    ] {
        seed("grant", name, bytes, false);
        seed("plan_grant_binding", name, bytes, false);
    }
    let oversized = format!(r#"{{"v":"{}"}} "#, "x".repeat(MAX_REQUEST_BYTES - 8));
    seed("grant", "oversized", oversized.as_bytes(), false);
    seed(
        "plan_grant_binding",
        "oversized",
        oversized.as_bytes(),
        false,
    );
    seed(
        "grant",
        "fixture-switch",
        include_bytes!("../../crates/contracts/tests/fixtures/fixture-grant.json"),
        false,
    );
}

/// W386 (D-035): both standing capture vectors, at their first window and
/// with a grant that names one window more than its plan.
fn standing_seeds(seed: &mut impl FnMut(&str, &str, &[u8], bool)) {
    let vectors: Vec<Value> = serde_json::from_str(include_str!(
        "../../crates/contracts/tests/fixtures/standing-capture-vectors.json"
    ))
    .unwrap();
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        let input = vector["plan_input"].as_str().unwrap().as_bytes();
        seed("prepared_plan", &format!("standing-{name}"), input, true);
        let plan: Value = serde_json::from_slice(input).unwrap();
        let grant: Value = serde_json::from_str(vector["grant_input"].as_str().unwrap()).unwrap();
        let now = plan["first_window_start"].clone();
        let bytes = serde_json::to_vec(&json!({"plan":plan,"grant":grant,"now":now})).unwrap();
        seed(
            "plan_grant_binding",
            &format!("standing-{name}"),
            &bytes,
            true,
        );
        let mut wider = grant.clone();
        wider["max_runs"] = json!(plan["max_runs"].as_u64().unwrap() - 1);
        let bytes = serde_json::to_vec(&json!({"plan":plan,"grant":wider,"now":now})).unwrap();
        seed(
            "plan_grant_binding",
            &format!("standing-{name}-other-schedule"),
            &bytes,
            false,
        );
    }
}

/// W372: both `site_readopt` forms, rebound to the fixed fuzz epoch, a
/// mixed form and a site form above the enrolled cap.
fn readopt_seeds(seed: &mut impl FnMut(&str, &str, &[u8], bool)) {
    let vectors: Vec<Value> = serde_json::from_str(include_str!(
        "../../crates/contracts/tests/fixtures/readopt-plan-vectors.json"
    ))
    .unwrap();
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        let input = vector["plan_input"].as_str().unwrap().as_bytes();
        seed("prepared_plan", &format!("readopt-{name}"), input, true);
        seed(
            "grant",
            &format!("readopt-{name}"),
            vector["grant_input"].as_str().unwrap().as_bytes(),
            true,
        );
        let mut plan: Value = serde_json::from_slice(input).unwrap();
        plan["host_epoch"] = json!("epoch_1");
        plan["previous_epoch"] = json!("epoch_0");
        let digest = |plan: &Value| {
            rustiron_contracts::approval::ReadoptPlan::decode(&serde_json::to_vec(plan).unwrap())
                .unwrap()
                .digest()
        };
        let mut grant: Value =
            serde_json::from_str(vector["grant_input"].as_str().unwrap()).unwrap();
        grant["host_epoch"] = json!("epoch_1");
        grant["plan_digest"] = json!(digest(&plan).as_str());
        let bytes = serde_json::to_vec(&json!({"plan":plan,"grant":grant,"now":1200})).unwrap();
        seed(
            "plan_grant_binding",
            &format!("readopt-{name}"),
            &bytes,
            true,
        );
        let mut mixed = plan.clone();
        if name == "site" {
            mixed["expected_generation"] = json!("g1");
        } else {
            mixed["site_id"] = json!("blog1");
        }
        seed(
            "prepared_plan",
            &format!("readopt-{name}-mixed"),
            &serde_json::to_vec(&mixed).unwrap(),
            false,
        );
        if name == "site" {
            let mut above = plan.clone();
            above["quota_limits"]["block_hard_kib"] = json!(5_242_881);
            let mut above_grant = grant.clone();
            above_grant["plan_digest"] = json!(digest(&above).as_str());
            let bytes =
                serde_json::to_vec(&json!({"plan":above,"grant":above_grant,"now":1200})).unwrap();
            seed(
                "plan_grant_binding",
                "readopt-site-above-cap",
                &bytes,
                false,
            );
        }
    }
}

/// W341: site plan v2 vectors, their closed shape and the enrolled cap.
fn site_v2_seeds(seed: &mut impl FnMut(&str, &str, &[u8], bool)) {
    let vectors: Vec<Value> = serde_json::from_str(include_str!(
        "../../crates/contracts/tests/fixtures/site-plan-v2-vectors.json"
    ))
    .unwrap();
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        let plan: Value = serde_json::from_str(vector["plan_input"].as_str().unwrap()).unwrap();
        let grant: Value = serde_json::from_str(vector["grant_input"].as_str().unwrap()).unwrap();
        seed(
            "canonical_object",
            &format!("site-v2-{name}"),
            vector["plan_input"].as_str().unwrap().as_bytes(),
            true,
        );
        seed(
            "prepared_plan",
            &format!("site-v2-{name}"),
            vector["plan_input"].as_str().unwrap().as_bytes(),
            true,
        );
        let mut without_limits = plan.clone();
        without_limits
            .as_object_mut()
            .unwrap()
            .remove("quota_limits");
        let mut v1_with_limits = plan.clone();
        v1_with_limits["schema_version"] = json!(1);
        let mut below_bounds = plan.clone();
        below_bounds["quota_limits"]["block_hard_kib"] = json!(65_535);
        for (case, bytes) in [
            ("without-limits", &without_limits),
            ("v1-with-limits", &v1_with_limits),
            ("below-bounds", &below_bounds),
        ] {
            seed(
                "prepared_plan",
                &format!("site-v2-{name}-{case}"),
                &serde_json::to_vec(bytes).unwrap(),
                false,
            );
        }
        // The fixed fuzz cap is the D-028 default; one KiB more never binds.
        let mut above_cap = plan.clone();
        above_cap["quota_limits"]["block_hard_kib"] = json!(5_242_881);
        let above_digest = rustiron_contracts::approval::SitePlan::decode(
            &serde_json::to_vec(&above_cap).unwrap(),
        )
        .unwrap()
        .digest();
        let mut above_grant = grant.clone();
        above_grant["plan_digest"] = json!(above_digest.as_str());
        for (case, plan, grant, accepted) in [
            ("valid", &plan, &grant, true),
            ("above-cap", &above_cap, &above_grant, false),
            ("limits-changed", &above_cap, &grant, false),
        ] {
            let bytes = serde_json::to_vec(&json!({"plan":plan,"grant":grant,"now":1200})).unwrap();
            seed(
                "plan_grant_binding",
                &format!("site-v2-{name}-{case}"),
                &bytes,
                accepted,
            );
        }
    }
}

fn product_backup_seeds(seed: &mut impl FnMut(&str, &str, &[u8], bool)) {
    let vectors: Vec<Value> = serde_json::from_str(include_str!(
        "../../crates/contracts/tests/fixtures/product-backup-vectors.json"
    ))
    .unwrap();
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        let plan: Value = serde_json::from_str(vector["plan_input"].as_str().unwrap()).unwrap();
        let grant: Value = serde_json::from_str(vector["grant_input"].as_str().unwrap()).unwrap();
        seed(
            "prepared_plan",
            &format!("product-{name}"),
            vector["plan_input"].as_str().unwrap().as_bytes(),
            true,
        );
        let mut wrong_version = plan.clone();
        wrong_version["schema_version"] = json!(1);
        seed(
            "prepared_plan",
            &format!("product-{name}-wrong-version"),
            &serde_json::to_vec(&wrong_version).unwrap(),
            false,
        );
        let mut changed_policy = plan.clone();
        changed_policy["destination_policy_digest"] = json!("c".repeat(64));
        let mut wrong_destination = grant.clone();
        wrong_destination["destinations"] = json!(["another_destination"]);
        for (case, plan, grant, accepted) in [
            ("valid", &plan, &grant, true),
            ("policy-drift", &changed_policy, &grant, false),
            ("destination-mismatch", &plan, &wrong_destination, false),
        ] {
            let bytes = serde_json::to_vec(&json!({"plan":plan,"grant":grant,"now":1200})).unwrap();
            seed(
                "plan_grant_binding",
                &format!("product-{name}-{case}"),
                &bytes,
                accepted,
            );
        }
    }
}
