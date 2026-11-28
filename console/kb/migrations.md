---
title: "Move sites to RustIron"
description: "Import WordPress sites from CyberPanel, or move WordPress content to EmDash."
category: "recovery-migration"
order: 22
readMinutes: 5
runbooks: ["Runbook 33","Runbook 37"]
keywords: ["migrate","migration","cyberpanel","import","wxr","emdash","cutover","declaration","scrub"]
consoleLinks: [{"to":"/migration","label":"Migration"},{"to":"/apps","label":"Apps"}]
---

## Import a WordPress site from CyberPanel {#cyberpanel-import}

CyberPanel migrations never modify your source VPS, DNS, or email. Export the site offline, inventory it against live target host observations, sign an OperatorDeclaration (SSHSIG), and inspect every dry-run refusal (such as extra databases or missing PHP extensions) before importing.

:::note[Post-import cleanup (import_scrub)]
After verifying HTTP parity on the target server, run import_scrub to remove staged archives and leftover source credentials cleanly.
:::

```sh title="Generate a CyberPanel migration dry-run & import plan" where="Workstation (operator)"
rustiron-plan migrate \
  --inventory ./source-inventory.json \
  --target-observation ./target-observation.json \
  --declaration ./declaration.json \
  --declaration-sig ./declaration.json.sig
```

## Migrate WordPress content to EmDash CMS {#wp-to-emdash}

Use packaging/wordpress-to-emdash.py to convert a WordPress WXR XML export and captured uploads into an EmDash 1.6.0 migration plan with SHA-256 media verification, 301 permalink redirect maps, and strict draft isolation (unpublished drafts stay 404 publicly).

```sh title="Plan an offline WordPress -> EmDash WXR migration" where="Workstation (operator)"
python3 packaging/wordpress-to-emdash.py plan \
  --wxr ./wordpress-export.xml \
  --uploads ./wp-content/uploads \
  --out ./emdash-migration-plan
```
