//! W620 (P19 Slice 1): Tiered opt-in MCP write-capability security & forwarding tests.

use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

const NOW: u64 = 1_795_500_300;
const SIG: &str = "-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAQ==\n-----END SSH SIGNATURE-----";

struct Fixture {
    dir: PathBuf,
    socket: PathBuf,
}

/// W720: a folder-name part that no other test in this process uses. The
/// clock alone can repeat across parallel tests.
fn unique_suffix() -> String {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_nanos());
    let next = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{nanos}-{next}")
}

impl Fixture {
    fn new() -> Self {
        let suffix = unique_suffix();
        let dir = PathBuf::from("/tmp").join(format!("ri-p19-{}-{suffix}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let socket = dir.join("control.sock");
        Self { dir, socket }
    }

    fn run_mcp(&self, extra_args: &[&str], lines: &[String]) -> Vec<Value> {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rustiron-mcp"));
        cmd.args(extra_args);
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        {
            let mut stdin = child.stdin.take().unwrap();
            for line in lines {
                stdin.write_all(line.as_bytes()).unwrap();
                stdin.write_all(b"\n").unwrap();
            }
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "rustiron-mcp exited {:?}, stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .collect()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn rotate_plan_json() -> String {
    serde_json::to_string(&json!({
        "schema_version": 1,
        "plan_id": "plan_p19_1",
        "host_id": "rustiron_w447_schedule",
        "host_epoch": "epoch_w447_1",
        "profile_digest": "1a547a0b9c893a63fd11135e0c92846e400fb9bdd9e7558c6fada6eeeb5db4ab",
        "requester": "rustiron_coordinator",
        "verb": "site_credential_rotate",
        "site_id": "cp02",
        "hostname": "cp02.example.test",
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
        "valid_from": 1_795_500_000,
        "expires_at": 1_795_500_900,
        "limitations": ["nonproduction test"]
    }))
    .unwrap()
}

/// W693: a closed `site_credential_rotate` grant for `rotate_plan_json`, so the
/// MCP gate's strict contract decoder accepts it; `extra` adds members to test refusal.
fn grant_json(plan_digest: &str, issuer: &str, expires_at: u64, blanket: bool) -> String {
    let mut g = json!({
        "schema_version": 1,
        "grant_id": "grant_p19_1",
        "nonce": "nonce_p19_1",
        "plan_id": "plan_p19_1",
        "plan_digest": plan_digest,
        "host_id": "rustiron_w447_schedule",
        "host_epoch": "epoch_w447_1",
        "profile_digest": "1a547a0b9c893a63fd11135e0c92846e400fb9bdd9e7558c6fada6eeeb5db4ab",
        "issuer": issuer,
        "requester": "rustiron_coordinator",
        "signer_policy_epoch": "policy_3",
        "site_ids": ["cp02"],
        "verbs": ["site_credential_rotate"],
        "risk_class": "lab_only",
        "valid_from": 1_795_500_000,
        "expires_at": expires_at,
        "max_operations": 1
    });
    if blanket {
        g["blanket"] = json!(true);
    }
    serde_json::to_string(&g).unwrap()
}

fn call_apply(id: u64, tier: &str, plan_json: &str, grant_json: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "rustiron_plan_apply_approved",
            "arguments": {
                "operation_id": format!("op_p19_{id}"),
                "idempotency_key": format!("idem_p19_{id}"),
                "target_tier": tier,
                "plan_json": plan_json,
                "grant_json": grant_json,
                "signature": SIG
            }
        }
    })
    .to_string()
}

fn inspect_plan_digest(fixture: &Fixture, plan_json: &str) -> String {
    let replies = fixture.run_mcp(
        &[],
        &[json!({
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": { "name": "rustiron_plan_inspect", "arguments": { "plan_json": plan_json } }
        })
        .to_string()],
    );
    replies[0]["result"]["structuredContent"]["result"]["plan_digest"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn destructive_tier_cli_and_default_readonly_are_refused() {
    let out = Command::new(env!("CARGO_BIN_EXE_rustiron-mcp"))
        .args(["--write-tier", "destructive", "--agent-id", "agent_a"])
        .output()
        .unwrap();
    assert!(!out.status.success());

    // Default read-only refuses rustiron_plan_apply_approved
    let fixture = Fixture::new();
    let plan = rotate_plan_json();
    let digest = inspect_plan_digest(&fixture, &plan);
    let grant = grant_json(&digest, "charles", NOW + 600, false);
    let replies = fixture.run_mcp(&[], &[call_apply(1, "nonproduction", &plan, &grant)]);
    assert_eq!(replies[0]["error"]["message"], "UNKNOWN_OR_DISALLOWED_TOOL");
}

#[test]
fn enforces_tiers_no_self_approval_no_blanket_no_budget_expansion_expiry_and_live_forward() {
    let fixture = Fixture::new();
    let listener = rustiron_control::bind(&fixture.socket).unwrap();
    let coordinator = rustiron_control::Coordinator::new(None);
    thread::spawn(move || {
        let _ = coordinator.serve(listener);
    });

    let plan = rotate_plan_json();
    let digest = inspect_plan_digest(&fixture, &plan);

    let valid_grant = grant_json(&digest, "charles", NOW + 600, false);
    let self_grant = grant_json(&digest, "agent_ci", NOW + 600, false);
    let blanket_grant = grant_json(&digest, "charles", NOW + 600, true);
    let expired_grant = grant_json(&digest, "charles", NOW - 10, false);
    let wrong_digest_grant = grant_json("00".repeat(32).as_str(), "charles", NOW + 600, false);

    let now_str = NOW.to_string();
    let replies = fixture.run_mcp(
        &[
            "--socket",
            fixture.socket.to_str().unwrap(),
            "--write-tier",
            "nonproduction",
            "--agent-id",
            "agent_ci",
            "--max-changes",
            "4",
            "--now",
            &now_str,
        ],
        &[
            // 1. tools/list has 8 tools including opt-in write tool
            json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}).to_string(),
            // 2. Production tier escalation denied on nonproduction server
            call_apply(2, "production", &plan, &valid_grant),
            // 3. Destructive tier denied
            call_apply(3, "destructive", &plan, &valid_grant),
            // 4. Self-approval refused (issuer == agent_ci)
            call_apply(4, "nonproduction", &plan, &self_grant),
            // 5. Blanket token refused
            call_apply(5, "nonproduction", &plan, &blanket_grant),
            // 6. Expired grant refused
            call_apply(6, "nonproduction", &plan, &expired_grant),
            // 7. Digest mismatch refused
            call_apply(7, "nonproduction", &plan, &wrong_digest_grant),
            // 8. Valid nonproduction call forwards byte-exact to live coordinator -> truthful not_sent (unavailable)
            call_apply(8, "nonproduction", &plan, &valid_grant),
            // 10. W693 (R13): a grant for another verb is refused
            call_apply(
                10,
                "nonproduction",
                &plan,
                &valid_grant.replace("site_credential_rotate", "site_quota"),
            ),
            // 9. W633 (R13): duplicate-key non-canonical grant JSON refused locally before coordinator
            call_apply(
                9,
                "nonproduction",
                &plan,
                &format!(
                    r#"{{"plan_digest":"{digest}","plan_digest":"{digest}","issuer":"operator_1","valid_from":1795000000,"expires_at":1795001800}}"#
                ),
            ),
        ],
    );

    assert_eq!(replies[0]["result"]["tools"].as_array().unwrap().len(), 14);
    assert_eq!(
        replies[1]["result"]["structuredContent"]["result"]["error"]["code"],
        "TIER_ESCALATION_DENIED"
    );
    assert_eq!(
        replies[2]["result"]["structuredContent"]["result"]["error"]["code"],
        "DESTRUCTIVE_TIER_REFUSED"
    );
    assert_eq!(
        replies[3]["result"]["structuredContent"]["result"]["error"]["code"],
        "SELF_APPROVAL_REFUSED"
    );
    // W693: a blanket member is not part of any closed grant, so the strict
    // decoder refuses it before the policy checks.
    assert_eq!(
        replies[4]["result"]["structuredContent"]["result"]["error"]["code"],
        "INVALID_GRANT"
    );
    assert_eq!(
        replies[5]["result"]["structuredContent"]["result"]["error"]["code"],
        "GRANT_EXPIRED_OR_INVALID_WINDOW"
    );
    assert_eq!(
        replies[6]["result"]["structuredContent"]["result"]["error"]["code"],
        "DIGEST_MISMATCH"
    );

    // Live coordinator returned truthful ApplyOutcome::NotSent { reason: Unavailable } (no executor attached)
    let fwd = &replies[7]["result"]["structuredContent"];
    assert_eq!(fwd["authority"], "externally_signed_grant_only");
    assert_eq!(fwd["self_approval_allowed"], false);
    assert_eq!(fwd["budget_expansion_allowed"], false);
    assert_eq!(fwd["destructive_allowed"], false);
    assert_eq!(fwd["result"]["verb"], "site_credential_rotate");
    assert_eq!(fwd["result"]["outcome"]["kind"], "not_sent");
    assert_eq!(replies[7]["result"]["isError"], true);
    for reply in &replies[8..10] {
        assert_eq!(
            reply["result"]["structuredContent"]["result"]["error"]["code"],
            "INVALID_GRANT"
        );
    }

    // 9. Budget expansion check: max-changes=0 refuses the 1-change plan before coordinator
    let budget_replies = fixture.run_mcp(
        &[
            "--socket",
            fixture.socket.to_str().unwrap(),
            "--write-tier",
            "nonproduction",
            "--agent-id",
            "agent_ci",
            "--max-changes",
            "0",
            "--now",
            &now_str,
        ],
        &[call_apply(9, "nonproduction", &plan, &valid_grant)],
    );
    assert_eq!(
        budget_replies[0]["result"]["structuredContent"]["result"]["error"]["code"],
        "BUDGET_EXPANSION_REFUSED"
    );
}
