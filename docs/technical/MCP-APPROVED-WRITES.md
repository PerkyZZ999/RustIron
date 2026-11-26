# Individually approved MCP write capabilities (P19 Slice 1)

**Status:** Slice 1 opt-in write gate & local coordinator forwarding lab verified ([W620](../validation/S10-W620/README.md)); live automation-risk policy review remains an explicit owner checkpoint before production write enablement.
**Scope:** Opt-in `--write-tier nonproduction|production --agent-id <ID>` mode on `rustiron-mcp` (preserving P17/D-101 strictly read-only defaults).

## Purpose

When explicitly opted in for an authorized agent, `rustiron-mcp` exposes one closed write tool (`rustiron_plan_apply_approved`).
It submits an externally signed plan and grant pair through the coordinator `plan_apply` contract (`crates/contracts/src/apply.rs`).

Without `--write-tier`, `rustiron-mcp` exposes ONLY the 7 strictly read-only P17 tools and refuses `rustiron_plan_apply_approved`.

## Separate risk tiers and hard stops

1. **Read (`--write-tier read`, default)**: zero mutating tools advertised or accepted.
2. **Nonproduction (`--write-tier nonproduction`)**: accepts only `target_tier: "nonproduction"` calls; refuses `production` (`TIER_ESCALATION_DENIED`).
3. **Production (`--write-tier production`)**: accepts `nonproduction` and `production` calls, capping production grant TTL at `3600 s`.
4. **Destructive (always refused)**: `--write-tier destructive` is rejected at CLI startup, `target_tier: "destructive"` is rejected, and destructive verbs (`site_delete`, `site_retire`, `clone_scrub`, `site_eject`) return `DESTRUCTIVE_TIER_REFUSED`.

## Enforced P19 invariants

- **No self-approval (`SELF_APPROVAL_REFUSED`)**: `grant.issuer` (or `signer_id`) must be non-empty and strictly different from `--agent-id`.
- **No blanket production tokens (`NO_BLANKET_TOKEN` / `DIGEST_MISMATCH`)**: refuses wildcard or blanket grants and requires exact `grant.plan_digest == canonical_plan_digest`.
- **No budget expansion (`BUDGET_EXPANSION_REFUSED`)**: verifies `envelope_for_plan(plan_json)` against configured `--max-changes`, `--max-ols-reloads`, and `max_operations <= 1`.
- **Prompt-injection resistance**: strict `deny_unknown_fields`, closed canonical plan decoder, no arbitrary tools, no shell execution, and `untrusted_data: true` response framing.
- **Truthful retry and expiry outcomes**: Checks grant time bounds before forwarding and returns the coordinator `ApplyOutcome` (`executor_reply`, `not_sent`, or `outcome_unknown`). Unknown or unsent attempts never become success.
