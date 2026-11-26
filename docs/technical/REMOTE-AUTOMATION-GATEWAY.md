# Scoped remote automation gateway (P18 Slice 1)

**Status:** Slice 1 contract and forced-command verifier lab verified ([W619](../validation/S10-W619/README.md)); live SSH daemon deployment and independent authentication/host-key review remain explicit checkpoints before production remote access.
**Scope:** Strictly deterministic forced-command & short-lived capability verifier in `rustiron-control --verify-gateway-request`.

## Purpose

Remote automation MUST NOT reuse interactive operator SSH sessions, generic `sudo`, or forwarded SSH signing agents.
Under P18, a named non-human agent connects over SSH with `restrict,no-pty,no-agent-forwarding,no-port-forwarding,no-X11-forwarding,command=...`.
The unprivileged forced-command dispatcher enforces short-lived verb, site, environment, time, and risk capabilities before forwarding to the coordinator.

## Command interface

```sh
rustiron-control --verify-gateway-request <gateway-request.json> [--now <unix_seconds>] [--human]
```

Reads `<gateway-request.json>` (`rustiron-gateway-request/1`) with `O_NONBLOCK | O_NOFOLLOW` and bounded size, mutates nothing, and emits a `rustiron-gateway-decision/1` report.

## Non-negotiable security invariants

Every response explicitly asserts:

- `interactive_shell_allowed: false` (empty `SSH_ORIGINAL_COMMAND`, shell binaries, and PTYs are denied);
- `generic_sudo_allowed: false` (`sudo ...` is denied);
- `agent_forwarding_allowed: false` (`SSH_AUTH_SOCK` presence is denied);
- `can_mint_approval: false` (capabilities NEVER mint approvals; `plan-apply` requires a separate externally signed grant whose `signer_id != agent_id`);
- `can_bypass_executor_policy: false` (valid calls dispatch only to `local_unprivileged_coordinator`, and the privileged executor still independently verifies every signed grant, precondition, replay mark, and D-098 budget).

## Closed command allowlist and enforcement

Only six closed commands are parsed (zero shell metacharacters, zero path traversal):

- `doctor` (`read`)
- `site-list` (`read`)
- `site-inspect <site_id>` (`read`, checked against `allowed_sites`)
- `operation-status <operation_id>` (`read`, idempotent reconciliation for disconnected calls)
- `evidence-export <operation_id>` (`read`, idempotent reconciliation)
- `plan-apply <site_id> <operation_id>` (`nonproduction` or `production`, requires separate external grant)

Enforced denials:

- `AGENT_FORWARDING_DENIED`, `INTERACTIVE_PTY_DENIED`, `MISSING_SSH_RESTRICT`, `UNPINNED_HOST_KEY`
- `INTERACTIVE_SHELL_DENIED`, `GENERIC_SUDO_DENIED`, `SHELL_INJECTION_DENIED`, `UNKNOWN_COMMAND`
- `IDENTITY_SEPARATION_VIOLATED` (`agent_id == human_operator_id`)
- `CAPABILITY_REVOKED`, `HOST_OR_EPOCH_MISMATCH`, `ENVIRONMENT_MISMATCH`
- `TTL_EXCEEDS_SHORT_LIVED_CAP` (`> 3600 s`), `CAPABILITY_EXPIRED`
- `REPLAY_DENIED` (for non-reconcile calls reusing a `request_nonce`)
- `VERB_ESCALATION_DENIED`, `SITE_ESCALATION_DENIED`, `RISK_ESCALATION_DENIED` (destructive tier is refused)
- `CAPABILITY_CANNOT_MINT_APPROVAL`
