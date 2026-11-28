---
title: "Troubleshooting"
description: "Fix operations that need attention, recover after a crash or power loss, and uninstall."
category: "updates-releases"
order: 26
readMinutes: 5
runbooks: ["Runbook 07","Runbook 11","Runbook 12","Runbook 17"]
keywords: ["troubleshoot","troubleshooting","crash","power loss","needs attention","quarantined","drift","break-glass","uninstall","reconcile"]
consoleLinks: [{"to":"/operations","label":"Operations"},{"to":"/host/diagnoses","label":"Host diagnoses"},{"to":"/states","label":"Shared states"}]
---

## Handling Needs attention & quarantined states {#needs-attention}

When a power cut, reload timeout, or interrupted step prevents RustIron from proving an operation's exact outcome, it stops further conflicting writes and flags the operation as Needs attention (or marks a partially provisioned site as Quarantined).

- Never blindly re-submit a failing or uncertain operation; open Operations -\> \[Operation ID\] first to inspect every recorded step.
- After verifying live service state on the host, run the explicit reconciliation or retirement procedure for that verb (Runbook 11).

## Emergency manual edits & drift explanation {#drift-and-breakglass}

If you ever have to edit a host configuration file manually during an incident (break-glass), RustIron detects the drift and refuses to overwrite your edit silently (auto_reset: false). Use --explain-drift to classify each difference and choose whether to adopt, restore, ignore, or eject.

```sh title="Explain observed host drift without modifying anything" where="Server (unprivileged)"
rustiron-control --explain-drift /path/to/observation.json --human
```

## Cleanly uninstalling RustIron while keeping sites alive {#clean-uninstall}

packaging/uninstall-product.py removes RustIron control-plane services, binaries, and SELinux policy modules while keeping all hosted site files, MariaDB databases, and a root-only archive intact.

```sh title="Preview a safe product uninstall" where="Server (root)"
sudo python3 packaging/uninstall-product.py --dry-run
```
