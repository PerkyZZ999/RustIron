//! W619 (P18 Slice 1): Scoped remote automation gateway forced-command
//! verifier and capability evaluator. Enforces closed SSH_ORIGINAL_COMMAND
//! parsing, zero interactive shell / generic sudo / signing-agent forwarding,
//! identity separation, host/epoch/environment binding, short-lived TTL,
//! revocation, replay denial, scope-escalation denial, operation-ID
//! reconciliation, and strict refusal to mint approvals or bypass local
//! executor policy.

use rustiron_contracts::escape_human;
use serde_json::{Value, json};
use std::collections::BTreeSet;

/// Output schema for `rustiron-control --verify-gateway-request`.
pub(crate) const SCHEMA: &str = "rustiron-gateway-decision/1";
/// Expected input schema for a gateway evaluation request.
pub(crate) const INPUT_SCHEMA: &str = "rustiron-gateway-request/1";

/// Short-lived capability maximum lifetime (1 hour).
const MAX_CAPABILITY_TTL_SECS: u64 = 3600;
const MAX_COMMAND_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RiskTier {
    Read = 0,
    Nonproduction = 1,
    Production = 2,
}

impl RiskTier {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "read" => Some(Self::Read),
            "nonproduction" => Some(Self::Nonproduction),
            "production" => Some(Self::Production),
            _ => None,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Nonproduction => "nonproduction",
            Self::Production => "production",
        }
    }
}

struct ParsedCommand {
    verb: &'static str,
    site_id: Option<String>,
    operation_id: Option<String>,
    is_write: bool,
    is_reconcile: bool,
}

/// Pure deterministic evaluation of one remote automation gateway request.
pub(crate) fn evaluate(req: &Value, now: u64) -> Value {
    if req["schema"].as_str() != Some(INPUT_SCHEMA) {
        return deny(
            now,
            None,
            None,
            None,
            "INVALID_SCHEMA",
            "Request schema must be rustiron-gateway-request/1.",
        );
    }

    // 1. Session hardening: no signing-agent forwarding, no PTY, pinned host key, SSH restrict.
    let session = &req["session"];
    if session["ssh_auth_sock_present"].as_bool() == Some(true) {
        return deny(
            now,
            None,
            None,
            None,
            "AGENT_FORWARDING_DENIED",
            "Signing-agent forwarding (SSH_AUTH_SOCK) is strictly forbidden on the automation gateway.",
        );
    }
    if session["pty_allocated"].as_bool() == Some(true) {
        return deny(
            now,
            None,
            None,
            None,
            "INTERACTIVE_PTY_DENIED",
            "Interactive PTY allocation is forbidden; forced-command sessions must set no-pty.",
        );
    }
    if session["authorized_key_restrict"].as_bool() != Some(true) {
        return deny(
            now,
            None,
            None,
            None,
            "MISSING_SSH_RESTRICT",
            "Authorized key entry must enforce SSH `restrict` option.",
        );
    }
    if session["host_key_pinned"].as_bool() != Some(true) {
        return deny(
            now,
            None,
            None,
            None,
            "UNPINNED_HOST_KEY",
            "Remote client must verify a pinned host key.",
        );
    }

    // 2. Parse SSH_ORIGINAL_COMMAND strictly against the closed allowlist.
    let raw_cmd = session["ssh_original_command"].as_str().unwrap_or("");
    let parsed = match parse_forced_command(raw_cmd) {
        Ok(cmd) => cmd,
        Err((code, msg)) => return deny(now, None, None, None, code, msg),
    };

    // 3. Validate gateway context and short-lived capability token.
    let gw = &req["gateway"];
    let cap = &req["capability"];

    let agent_id = cap["agent_id"].as_str().unwrap_or("");
    let cap_id = cap["capability_id"].as_str().unwrap_or("");
    let operator_id = gw["human_operator_id"].as_str().unwrap_or("");
    let gw_host = gw["host_id"].as_str().unwrap_or("");
    let gw_epoch = gw["host_epoch"].as_str().unwrap_or("");
    let gw_env = gw["environment"].as_str().unwrap_or("");

    if !valid_token(agent_id) || !valid_token(cap_id) {
        return deny(
            now,
            Some(&parsed),
            None,
            None,
            "INVALID_CAPABILITY_IDENTITY",
            "Capability requires valid non-empty agent_id and capability_id.",
        );
    }
    if !operator_id.is_empty() && agent_id == operator_id {
        return deny(
            now,
            Some(&parsed),
            Some(agent_id),
            Some(cap_id),
            "IDENTITY_SEPARATION_VIOLATED",
            "Named agent identity must be strictly separate from the human operator identity.",
        );
    }

    // Revocation checks
    let revoked_caps = string_set(gw["revoked_capabilities"].as_array());
    let revoked_agents = string_set(gw["revoked_agents"].as_array());
    if revoked_caps.contains(cap_id) || revoked_agents.contains(agent_id) {
        return deny(
            now,
            Some(&parsed),
            Some(agent_id),
            Some(cap_id),
            "CAPABILITY_REVOKED",
            "Capability or agent identity has been revoked.",
        );
    }

    // Host, epoch, and environment binding
    if gw_host.is_empty()
        || cap["host_id"].as_str() != Some(gw_host)
        || gw_epoch.is_empty()
        || cap["host_epoch"].as_str() != Some(gw_epoch)
    {
        return deny(
            now,
            Some(&parsed),
            Some(agent_id),
            Some(cap_id),
            "HOST_OR_EPOCH_MISMATCH",
            "Capability host_id and host_epoch must match this host's active enrollment.",
        );
    }
    if gw_env.is_empty() || cap["environment"].as_str() != Some(gw_env) {
        return deny(
            now,
            Some(&parsed),
            Some(agent_id),
            Some(cap_id),
            "ENVIRONMENT_MISMATCH",
            "Capability environment does not match this host environment.",
        );
    }

    // Short-lived expiry window
    let (Some(issued_at), Some(expires_at)) =
        (cap["issued_at"].as_u64(), cap["expires_at"].as_u64())
    else {
        return deny(
            now,
            Some(&parsed),
            Some(agent_id),
            Some(cap_id),
            "INVALID_EXPIRY",
            "Capability must declare numeric issued_at and expires_at.",
        );
    };
    if expires_at <= issued_at || expires_at - issued_at > MAX_CAPABILITY_TTL_SECS {
        return deny(
            now,
            Some(&parsed),
            Some(agent_id),
            Some(cap_id),
            "TTL_EXCEEDS_SHORT_LIVED_CAP",
            "Capability TTL must be positive and at most 3600 seconds.",
        );
    }
    if now < issued_at || now > expires_at {
        return deny(
            now,
            Some(&parsed),
            Some(agent_id),
            Some(cap_id),
            "CAPABILITY_EXPIRED",
            "Capability is outside its valid time window.",
        );
    }

    // Replay check (read-only operation-status reconciliation is explicitly idempotent)
    let nonce = req["request_nonce"].as_str().unwrap_or("");
    if !valid_token(nonce) {
        return deny(
            now,
            Some(&parsed),
            Some(agent_id),
            Some(cap_id),
            "MISSING_NONCE",
            "Every gateway invocation must supply a valid request_nonce.",
        );
    }
    let seen_nonces = string_set(gw["seen_nonces"].as_array());
    if seen_nonces.contains(nonce) && !parsed.is_reconcile {
        return deny(
            now,
            Some(&parsed),
            Some(agent_id),
            Some(cap_id),
            "REPLAY_DENIED",
            "Request nonce was already consumed; reconnect using operation-status <operation_id> instead of replaying.",
        );
    }

    // Verb scope check
    let allowed_verbs = string_set(cap["allowed_verbs"].as_array());
    if !allowed_verbs.contains(parsed.verb) {
        return deny(
            now,
            Some(&parsed),
            Some(agent_id),
            Some(cap_id),
            "VERB_ESCALATION_DENIED",
            "Requested verb is outside capability allowed_verbs.",
        );
    }

    // Site scope check
    if let Some(ref site_id) = parsed.site_id {
        let allowed_sites = string_set(cap["allowed_sites"].as_array());
        if !allowed_sites.contains(site_id.as_str()) {
            return deny(
                now,
                Some(&parsed),
                Some(agent_id),
                Some(cap_id),
                "SITE_ESCALATION_DENIED",
                "Requested site_id is outside capability allowed_sites.",
            );
        }
    }

    // Risk tier check
    let required_risk = if !parsed.is_write {
        RiskTier::Read
    } else if gw_env == "production" {
        RiskTier::Production
    } else {
        RiskTier::Nonproduction
    };
    let Some(cap_risk) = cap["max_risk_tier"].as_str().and_then(RiskTier::parse) else {
        return deny(
            now,
            Some(&parsed),
            Some(agent_id),
            Some(cap_id),
            "RISK_ESCALATION_DENIED",
            "Capability max_risk_tier is missing or disallowed (destructive tier forbidden).",
        );
    };
    if cap_risk < required_risk {
        return deny(
            now,
            Some(&parsed),
            Some(agent_id),
            Some(cap_id),
            "RISK_ESCALATION_DENIED",
            "Requested operation risk tier exceeds capability max_risk_tier.",
        );
    }

    // Separate approval custody check for plan-apply: capability NEVER mints approvals.
    if parsed.is_write {
        let grant_present = req["external_grant"]["present"].as_bool() == Some(true);
        let grant_signer = req["external_grant"]["signer_id"].as_str().unwrap_or("");
        if !grant_present || grant_signer.is_empty() || grant_signer == agent_id {
            return deny(
                now,
                Some(&parsed),
                Some(agent_id),
                Some(cap_id),
                "CAPABILITY_CANNOT_MINT_APPROVAL",
                "Remote gateway capability cannot mint approval or self-sign; a separate externally signed executor grant is mandatory.",
            );
        }
    }

    json!({
        "schema": SCHEMA,
        "evaluated_at": now,
        "allowed": true,
        "denial_code": null,
        "reason": "Forced command and short-lived capability verified; dispatch to unprivileged local coordinator.",
        "verb": parsed.verb,
        "site_id": parsed.site_id.as_deref().map(escape_human),
        "operation_id": parsed.operation_id.as_deref().map(escape_human),
        "agent_id": escape_human(agent_id),
        "capability_id": escape_human(cap_id),
        "required_risk_tier": required_risk.as_str(),
        "reconcile_by_operation_id": parsed.operation_id.as_deref().map(escape_human),
        "dispatch_target": "local_unprivileged_coordinator",
        "invariants": {
            "interactive_shell_allowed": false,
            "generic_sudo_allowed": false,
            "agent_forwarding_allowed": false,
            "can_mint_approval": false,
            "can_bypass_executor_policy": false,
        },
    })
}

fn deny(
    now: u64,
    parsed: Option<&ParsedCommand>,
    agent_id: Option<&str>,
    cap_id: Option<&str>,
    code: &'static str,
    reason: &'static str,
) -> Value {
    json!({
        "schema": SCHEMA,
        "evaluated_at": now,
        "allowed": false,
        "denial_code": code,
        "reason": reason,
        "verb": parsed.map(|p| p.verb),
        "site_id": parsed.and_then(|p| p.site_id.as_deref()).map(escape_human),
        "operation_id": parsed.and_then(|p| p.operation_id.as_deref()).map(escape_human),
        "agent_id": agent_id.map(escape_human),
        "capability_id": cap_id.map(escape_human),
        "dispatch_target": null,
        "invariants": {
            "interactive_shell_allowed": false,
            "generic_sudo_allowed": false,
            "agent_forwarding_allowed": false,
            "can_mint_approval": false,
            "can_bypass_executor_policy": false,
        },
    })
}

fn parse_forced_command(raw: &str) -> Result<ParsedCommand, (&'static str, &'static str)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err((
            "INTERACTIVE_SHELL_DENIED",
            "Empty SSH_ORIGINAL_COMMAND (interactive shell attempt) is forbidden.",
        ));
    }
    if trimmed.len() > MAX_COMMAND_BYTES {
        return Err((
            "COMMAND_TOO_LONG",
            "Forced command exceeds maximum allowed byte length.",
        ));
    }
    if trimmed.bytes().any(|b| {
        matches!(
            b,
            b';' | b'&'
                | b'|'
                | b'$'
                | b'`'
                | b'<'
                | b'>'
                | b'\\'
                | b'\''
                | b'"'
                | b'\n'
                | b'\r'
                | b'\0'
        )
    }) {
        return Err((
            "SHELL_INJECTION_DENIED",
            "Shell metacharacters are forbidden in SSH_ORIGINAL_COMMAND.",
        ));
    }

    let tokens: Vec<&str> = trimmed.split_ascii_whitespace().collect();
    match tokens.as_slice() {
        ["sudo", ..] => Err((
            "GENERIC_SUDO_DENIED",
            "Generic sudo invocation is forbidden on the remote automation gateway.",
        )),
        ["sh" | "bash" | "zsh" | "/bin/sh" | "/bin/bash", ..] => Err((
            "INTERACTIVE_SHELL_DENIED",
            "Direct shell invocation is forbidden on the remote automation gateway.",
        )),
        ["doctor"] => Ok(ParsedCommand {
            verb: "doctor",
            site_id: None,
            operation_id: None,
            is_write: false,
            is_reconcile: false,
        }),
        ["site-list"] => Ok(ParsedCommand {
            verb: "site-list",
            site_id: None,
            operation_id: None,
            is_write: false,
            is_reconcile: false,
        }),
        ["site-inspect", site_id] if valid_token(site_id) => Ok(ParsedCommand {
            verb: "site-inspect",
            site_id: Some((*site_id).to_owned()),
            operation_id: None,
            is_write: false,
            is_reconcile: false,
        }),
        ["operation-status", op_id] if valid_token(op_id) => Ok(ParsedCommand {
            verb: "operation-status",
            site_id: None,
            operation_id: Some((*op_id).to_owned()),
            is_write: false,
            is_reconcile: true,
        }),
        ["evidence-export", op_id] if valid_token(op_id) => Ok(ParsedCommand {
            verb: "evidence-export",
            site_id: None,
            operation_id: Some((*op_id).to_owned()),
            is_write: false,
            is_reconcile: true,
        }),
        ["plan-apply", site_id, op_id] if valid_token(site_id) && valid_token(op_id) => {
            Ok(ParsedCommand {
                verb: "plan-apply",
                site_id: Some((*site_id).to_owned()),
                operation_id: Some((*op_id).to_owned()),
                is_write: true,
                is_reconcile: false,
            })
        }
        _ => Err((
            "UNKNOWN_COMMAND",
            "SSH_ORIGINAL_COMMAND does not match any closed gateway verb.",
        )),
    }
}

fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 64
        && !token.contains("..")
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn string_set(arr: Option<&Vec<Value>>) -> BTreeSet<&str> {
    arr.map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// Concise human-readable operator summary for a gateway verification decision.
pub(crate) fn human(report: &Value) -> String {
    let allowed = report["allowed"].as_bool().unwrap_or(false);
    let verb = report["verb"].as_str().unwrap_or("none");
    let code = report["denial_code"].as_str().unwrap_or("OK");
    let reason = report["reason"].as_str().unwrap_or("");
    format!(
        "Rustiron remote gateway: allowed={allowed} code={code} verb={verb} can_mint_approval=false can_bypass_executor_policy=false\n  reason: {reason}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_795_800_000;

    fn base_req(cmd: &str) -> Value {
        json!({
            "schema": INPUT_SCHEMA,
            "request_nonce": "nonce_001",
            "session": {
                "ssh_original_command": cmd,
                "ssh_auth_sock_present": false,
                "pty_allocated": false,
                "authorized_key_restrict": true,
                "host_key_pinned": true
            },
            "gateway": {
                "host_id": "host-alpha",
                "host_epoch": "policy_3",
                "environment": "staging",
                "human_operator_id": "charles",
                "revoked_capabilities": ["cap_revoked"],
                "revoked_agents": ["agent_revoked"],
                "seen_nonces": ["nonce_used"]
            },
            "capability": {
                "capability_id": "cap_001",
                "agent_id": "agent_ci_staging",
                "host_id": "host-alpha",
                "host_epoch": "policy_3",
                "environment": "staging",
                "allowed_verbs": ["doctor", "site-inspect", "operation-status", "plan-apply"],
                "allowed_sites": ["cp02"],
                "max_risk_tier": "nonproduction",
                "issued_at": NOW - 60,
                "expires_at": NOW + 600
            },
            "external_grant": {
                "present": true,
                "signer_id": "charles"
            }
        })
    }

    #[test]
    fn allows_valid_scoped_read_and_externally_signed_apply() {
        let read_rep = evaluate(&base_req("site-inspect cp02"), NOW);
        assert_eq!(read_rep["allowed"], true);
        assert_eq!(read_rep["verb"], "site-inspect");
        assert_eq!(read_rep["invariants"]["can_mint_approval"], false);

        let apply_rep = evaluate(&base_req("plan-apply cp02 op_77"), NOW);
        assert_eq!(apply_rep["allowed"], true);
        assert_eq!(apply_rep["reconcile_by_operation_id"], "op_77");
        assert_eq!(apply_rep["invariants"]["can_bypass_executor_policy"], false);
    }

    #[test]
    fn denies_shell_sudo_agent_forwarding_and_injection() {
        assert_eq!(
            evaluate(&base_req(""), NOW)["denial_code"],
            "INTERACTIVE_SHELL_DENIED"
        );
        assert_eq!(
            evaluate(&base_req("sudo ls"), NOW)["denial_code"],
            "GENERIC_SUDO_DENIED"
        );
        assert_eq!(
            evaluate(&base_req("doctor; id"), NOW)["denial_code"],
            "SHELL_INJECTION_DENIED"
        );

        let mut fwd = base_req("doctor");
        fwd["session"]["ssh_auth_sock_present"] = json!(true);
        assert_eq!(
            evaluate(&fwd, NOW)["denial_code"],
            "AGENT_FORWARDING_DENIED"
        );
    }

    #[test]
    fn denies_revocation_expiry_replay_identity_and_scope_escalation() {
        let mut revoked = base_req("doctor");
        revoked["capability"]["capability_id"] = json!("cap_revoked");
        assert_eq!(evaluate(&revoked, NOW)["denial_code"], "CAPABILITY_REVOKED");

        let mut expired = base_req("doctor");
        expired["capability"]["expires_at"] = json!(NOW - 1);
        assert_eq!(evaluate(&expired, NOW)["denial_code"], "CAPABILITY_EXPIRED");

        let mut replay = base_req("plan-apply cp02 op_77");
        replay["request_nonce"] = json!("nonce_used");
        assert_eq!(evaluate(&replay, NOW)["denial_code"], "REPLAY_DENIED");

        // Disconnected call reconciliation by operation-status remains allowed!
        let mut reconcile = base_req("operation-status op_77");
        reconcile["request_nonce"] = json!("nonce_used");
        assert_eq!(evaluate(&reconcile, NOW)["allowed"], true);

        let mut same_id = base_req("doctor");
        same_id["capability"]["agent_id"] = json!("charles");
        assert_eq!(
            evaluate(&same_id, NOW)["denial_code"],
            "IDENTITY_SEPARATION_VIOLATED"
        );

        let wrong_site = base_req("site-inspect other_site");
        assert_eq!(
            evaluate(&wrong_site, NOW)["denial_code"],
            "SITE_ESCALATION_DENIED"
        );

        let mut self_sign = base_req("plan-apply cp02 op_77");
        self_sign["external_grant"]["signer_id"] = json!("agent_ci_staging");
        assert_eq!(
            evaluate(&self_sign, NOW)["denial_code"],
            "CAPABILITY_CANNOT_MINT_APPROVAL"
        );
    }
}
