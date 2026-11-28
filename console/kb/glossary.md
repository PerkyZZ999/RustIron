---
title: "Glossary"
description: "The terms used across RustIron's docs and Console."
---

- **Plan**: Immutable canonical JSON list of intended host effects. Reviewing a plan is not approving it.
- **Approval / Grant**: Short-lived SSHSIG-signed scope binding one exact plan SHA-256 digest to one host and epoch.
- **Coordinator**: Unprivileged local daemon (rustiron-coordinator) that validates read requests and forwards signed plans.
- **Executor**: Privileged service (rustiron-executor) that independently verifies peer identity, signature, replay, and preconditions before running fixed scoped operations.
- **Operation**: Durable execution record of one approved plan in the executor journal, identified by an operation ID.
- **Needs attention**: An interrupted or ambiguous operation outcome. Never treated as succeeded or safe to blindly retry.
- **Quarantined site**: A site whose provisioning or recovery stopped midway; stays isolated until explicitly reconciled or retired.
- **Eject**: Stop RustIron management for a site while keeping its files, database, OLS vhost, and TLS certificates serving.
- **SELinux MCS**: Multi-Category Security labels (s0:c\<N\>) confining each PHP pool and app unit so compromised sites cannot read peers.
- **Snapshot**: Encrypted restic backup artifact in the backup store. Proven recoverable only after restore-probe verification.
- **Unclaimed snapshot**: Backup data uploaded during a failed or interrupted capture; kept visible for retention reconciliation, never counted as a backup of record.
- **Drift**: Observed difference between host state and managed configuration. RustIron explains drift instead of silently resetting it.
- **Root-only / Not checked**: A check requiring root privileges (such as sshd -T or firewall-cmd) that the unprivileged observer refuses to guess.
- **Blast-radius envelope**: Pre-signing summary showing affected sites, global OpenLiteSpeed reload impact, and durable authority budget.
