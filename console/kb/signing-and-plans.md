---
title: "Approve changes with signed plans"
description: "The four steps behind every change: create a plan, review it, sign it on your own computer, and apply it."
category: "getting-started"
order: 3
readMinutes: 4
runbooks: ["Runbook 05","Runbook 34"]
keywords: ["plan","grant","sign","ssh-keygen","sshsign","canonical","apply","blast radius","workflow"]
consoleLinks: [{"to":"/plans/new","label":"New plan wizard"},{"to":"/operations","label":"Operations"}]
---

## The 4-step signed-change lifecycle {#four-step-flow}

Every Console wizard generates exact CLI commands for you. Rather than executing privileged mutations directly from the browser, RustIron separates drafting from cryptographic approval.

- Step 1 — Create: build a deterministic canonical plan.json and matching grant.json bound to one operation ID, host ID, host epoch, and short expiry window.
- Step 2 — Inspect: review the human-readable blast-radius summary (affected sites, global OLS reload impact, authority budget) before signing.
- Step 3 — Sign offline: sign grant.json with your operator SSH key in the dedicated rustiron-plan-v1 namespace.
- Step 4 — Apply & verify: submit plan.json, grant.json, and grant.json.sig to the coordinator and inspect the recorded operation outcome.

```sh title="Inspect, sign offline, and apply a prepared plan directory" where="Workstation (operator)"
rustiron plan review-file ./plan-dir/plan.json
ssh-keygen -Y sign -f ~/.ssh/rustiron-operator -n rustiron-plan-v1 ./plan-dir/grant.json
rustiron plan apply --plan ./plan-dir/plan.json --grant ./plan-dir/grant.json --sig ./plan-dir/grant.json.sig
```

## Replay protection & expiry {#replay-protection}

Each grant carries a unique operation_id, host_epoch, signer policy epoch, and strict not_before / expires_at timestamps. Once admitted by the executor, the same grant cannot be replayed on another host or after an epoch rotation.
