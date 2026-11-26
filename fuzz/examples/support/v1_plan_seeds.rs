//! W638 (M-06): Seed corpora for all newer v1.0 plan verbs, grants, and canonical DNS zones.

use rustiron_contracts::approval::{MAX_ZONE_BYTES, PreparedPlan};
use serde_json::{Value, json};

const NEWER_FIXTURES: [(&str, &[u8], &[u8]); 13] = [
    (
        "import",
        include_bytes!("../../../crates/contracts/tests/fixtures/import-plan.json"),
        include_bytes!("../../../crates/contracts/tests/fixtures/import-grant.json"),
    ),
    (
        "scrub",
        include_bytes!("../../../crates/contracts/tests/fixtures/scrub-plan.json"),
        include_bytes!("../../../crates/contracts/tests/fixtures/scrub-grant.json"),
    ),
    (
        "certificate",
        include_bytes!("../../../crates/contracts/tests/fixtures/certificate-plan.json"),
        include_bytes!("../../../crates/contracts/tests/fixtures/certificate-grant.json"),
    ),
    (
        "site-clone",
        include_bytes!("../../../crates/contracts/tests/fixtures/site-clone-plan.json"),
        include_bytes!("../../../crates/contracts/tests/fixtures/site-clone-grant.json"),
    ),
    (
        "clone-scrub",
        include_bytes!("../../../crates/contracts/tests/fixtures/clone-scrub-plan.json"),
        include_bytes!("../../../crates/contracts/tests/fixtures/clone-scrub-grant.json"),
    ),
    (
        "retire",
        include_bytes!("../../../crates/contracts/tests/fixtures/retire-plan.json"),
        include_bytes!("../../../crates/contracts/tests/fixtures/retire-grant.json"),
    ),
    (
        "update",
        include_bytes!("../../../crates/contracts/tests/fixtures/update-plan.json"),
        include_bytes!("../../../crates/contracts/tests/fixtures/update-grant.json"),
    ),
    (
        "delete",
        include_bytes!("../../../crates/contracts/tests/fixtures/delete-plan.json"),
        include_bytes!("../../../crates/contracts/tests/fixtures/delete-grant.json"),
    ),
    (
        "quota",
        include_bytes!("../../../crates/contracts/tests/fixtures/quota-plan.json"),
        include_bytes!("../../../crates/contracts/tests/fixtures/quota-grant.json"),
    ),
    (
        "restore",
        include_bytes!("../../../crates/contracts/tests/fixtures/restore-plan.json"),
        include_bytes!("../../../crates/contracts/tests/fixtures/restore-grant.json"),
    ),
    (
        "dns-import",
        include_bytes!("../../../crates/contracts/tests/fixtures/dns-import-plan.json"),
        include_bytes!("../../../crates/contracts/tests/fixtures/dns-import-grant.json"),
    ),
    (
        "dns-change",
        include_bytes!("../../../crates/contracts/tests/fixtures/dns-change-plan.json"),
        include_bytes!("../../../crates/contracts/tests/fixtures/dns-change-grant.json"),
    ),
    (
        "proxy-site",
        include_bytes!("../../../crates/contracts/tests/fixtures/proxy-site-plan.json"),
        include_bytes!("../../../crates/contracts/tests/fixtures/proxy-site-grant.json"),
    ),
];

const EXTRA_PLAN_FIXTURES: [(&str, &[u8]); 4] = [
    (
        "eject-v3",
        include_bytes!("../../../crates/contracts/tests/fixtures/eject-plan-v3.json"),
    ),
    (
        "import-alias",
        include_bytes!("../../../crates/contracts/tests/fixtures/import-plan-alias.json"),
    ),
    (
        "import-rename",
        include_bytes!("../../../crates/contracts/tests/fixtures/import-plan-rename.json"),
    ),
    (
        "certificate-alias",
        include_bytes!("../../../crates/contracts/tests/fixtures/certificate-plan-alias.json"),
    ),
];

fn sha(ch: char) -> String {
    std::iter::repeat_n(ch, 64).collect()
}

fn app_and_credential_plans() -> [(&'static str, Value, &'static str); 4] {
    [
        (
            "app-provision",
            json!({
                "schema_version": 1,
                "plan_id": "plan_app_prov_fuzz",
                "host_id": "host_lab",
                "host_epoch": "epoch_1",
                "profile_digest": sha('a'),
                "requester": "agent_1",
                "verb": "app_provision",
                "site_id": "emdash1",
                "hostname": "emdash.example.test",
                "runtime": "node_22_v1",
                "port": 43187,
                "routes": [{"prefix": "/", "port": 43187}],
                "websockets": [{"prefix": "/_emdash/api/content/", "port": 43187}],
                "entrypoint": "dist/server/entry.mjs",
                "worker_entrypoint": "dist/worker.mjs",
                "health_path": "/health",
                "env_keys": ["EMDASH_ENCRYPTION_KEY", "EMDASH_SITE_URL"],
                "memory_max_mib": 512,
                "tasks_max": 64,
                "quota_mib": 2048,
                "expected_effects": {
                    "creates_account": true,
                    "forwards_to_loopback": true,
                    "installs_app_unit": true,
                    "traffic_activation": false,
                    "runs_package_scripts": false
                },
                "risk_class": "lab_only",
                "valid_from": 1000,
                "expires_at": 2000,
                "limitations": ["fuzz seed"]
            }),
            "app_provision",
        ),
        (
            "app-deploy",
            json!({
                "schema_version": 1,
                "plan_id": "plan_app_dep_fuzz",
                "host_id": "host_lab",
                "host_epoch": "epoch_1",
                "profile_digest": sha('a'),
                "requester": "agent_1",
                "verb": "app_deploy",
                "site_id": "emdash1",
                "release_id": "rel-2026.11.24-01",
                "runtime": "node_22_v1",
                "artifact_sha256": sha('b'),
                "manifest_sha256": sha('c'),
                "file_count": 120,
                "total_bytes": 1_048_576,
                "migration_entrypoint": "scripts/migrate.mjs",
                "capture_operation_id": "op_cap_1",
                "health_path": "/health",
                "expected_effects": {
                    "unpacks_as_site": true,
                    "switches_release": true,
                    "restarts_app_unit": true,
                    "rolls_back_on_failed_health": true,
                    "runs_package_scripts": false,
                    "traffic_activation": false
                },
                "risk_class": "lab_only",
                "valid_from": 1000,
                "expires_at": 2000,
                "limitations": ["fuzz seed"]
            }),
            "app_deploy",
        ),
        (
            "app-lifecycle",
            json!({
                "schema_version": 1,
                "plan_id": "plan_app_life_fuzz",
                "host_id": "host_lab",
                "host_epoch": "epoch_1",
                "profile_digest": sha('a'),
                "requester": "agent_1",
                "verb": "app_lifecycle",
                "site_id": "emdash1",
                "action": "restart",
                "expected_effects": {
                    "changes_app_unit_state": true,
                    "reloads_ols": false,
                    "changes_files": false
                },
                "risk_class": "lab_only",
                "valid_from": 1000,
                "expires_at": 2000,
                "limitations": ["fuzz seed"]
            }),
            "app_lifecycle",
        ),
        (
            "credential-rotate",
            json!({
                "schema_version": 1,
                "plan_id": "plan_cred_rot_fuzz",
                "host_id": "host_lab",
                "host_epoch": "epoch_1",
                "profile_digest": sha('a'),
                "requester": "agent_1",
                "verb": "site_credential_rotate",
                "site_id": "blog1",
                "hostname": "blog1.example.test",
                "target": "mariadb_user_password",
                "expected_effects": {
                    "rotates_db_password": true,
                    "updates_db_cnf": true,
                    "restarts_site_php": true,
                    "traffic_activation": false,
                    "network_access": false,
                    "secret_in_plan": false
                },
                "risk_class": "lab_only",
                "valid_from": 1000,
                "expires_at": 2000,
                "limitations": ["fuzz seed"]
            }),
            "site_credential_rotate",
        ),
    ]
}

pub fn generate(seed: &mut impl FnMut(&str, &str, &[u8], bool)) {
    for (name, plan, grant) in NEWER_FIXTURES {
        seed("prepared_plan", name, plan, true);
        seed("grant", name, grant, true);
        let mut extra: Value = serde_json::from_slice(plan).unwrap();
        extra["unexpected"] = true.into();
        seed(
            "prepared_plan",
            &format!("{name}-unknown-member"),
            &serde_json::to_vec(&extra).unwrap(),
            false,
        );
    }
    for (name, plan) in EXTRA_PLAN_FIXTURES {
        seed("prepared_plan", name, plan, true);
    }
    for (name, plan_value, verb) in app_and_credential_plans() {
        let plan_bytes = serde_json::to_vec(&plan_value).unwrap();
        seed("prepared_plan", name, &plan_bytes, true);
        let prepared = PreparedPlan::decode(&plan_bytes).unwrap();
        let grant_value = json!({
            "schema_version": 1,
            "grant_id": format!("grant_{verb}_fuzz"),
            "nonce": format!("nonce_{verb}_fuzz"),
            "plan_id": plan_value["plan_id"],
            "plan_digest": prepared.digest().as_str(),
            "host_id": "host_lab",
            "host_epoch": "epoch_1",
            "profile_digest": sha('a'),
            "issuer": "operator_1",
            "requester": "agent_1",
            "signer_policy_epoch": "policy_1",
            "site_ids": [plan_value["site_id"]],
            "verbs": [verb],
            "risk_class": "lab_only",
            "valid_from": 1100,
            "expires_at": 1900,
            "max_operations": 1
        });
        seed(
            "grant",
            name,
            &serde_json::to_vec(&grant_value).unwrap(),
            true,
        );
        let mut bad_plan = plan_value.clone();
        bad_plan["unexpected"] = true.into();
        seed(
            "prepared_plan",
            &format!("{name}-unknown-member"),
            &serde_json::to_vec(&bad_plan).unwrap(),
            false,
        );
    }

    // D-091 canonical DNS zone seeds.
    let valid_zone = concat!(
        "example.test. 300 IN A 203.0.113.10\n",
        "example.test. 300 IN MX 10 mail.example.test.\n",
        "example.test. 300 IN NS ns1.example.test.\n",
        "example.test. 300 IN NS ns2.example.test.\n",
        "example.test. 300 IN SOA ns1.example.test. hostmaster.example.test. 2026112401 3600 900 1209600 300\n",
        "example.test. 300 IN TXT \"v=spf1 -all\"\n",
        "www.example.test. 300 IN CNAME example.test.\n",
    );
    seed("dns_zone", "valid", valid_zone.as_bytes(), true);
    seed("dns_zone", "empty", b"", false);
    seed("dns_zone", "invalid-utf8", b"\xff\n", false);
    seed(
        "dns_zone",
        "missing-newline",
        valid_zone.trim_end_matches('\n').as_bytes(),
        false,
    );
    seed(
        "dns_zone",
        "unsorted",
        concat!(
            "www.example.test. 300 IN CNAME example.test.\n",
            "example.test. 300 IN NS ns1.example.test.\n",
            "example.test. 300 IN SOA ns1.example.test. hostmaster.example.test. 2026112401 3600 900 1209600 300\n",
        )
        .as_bytes(),
        false,
    );
    seed(
        "dns_zone",
        "cname-collision",
        concat!(
            "example.test. 300 IN NS ns1.example.test.\n",
            "example.test. 300 IN SOA ns1.example.test. hostmaster.example.test. 2026112401 3600 900 1209600 300\n",
            "www.example.test. 300 IN A 203.0.113.10\n",
            "www.example.test. 300 IN CNAME example.test.\n",
        )
        .as_bytes(),
        false,
    );
    seed(
        "dns_zone",
        "missing-soa",
        b"example.test. 300 IN NS ns1.example.test.\n",
        false,
    );
    let oversized = vec![b'a'; MAX_ZONE_BYTES + 1];
    seed("dns_zone", "oversized", &oversized, false);
}
