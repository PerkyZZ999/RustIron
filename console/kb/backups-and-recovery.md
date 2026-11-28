---
title: "Backups & restores"
description: "Take encrypted backups, schedule them, read their results, and restore a site."
category: "recovery-migration"
order: 21
readMinutes: 5
runbooks: ["Runbook 01","Runbook 10","Runbook 13","Runbook 22","Runbook 26"]
keywords: ["backup","restore","restic","snapshot","retention","compliance","object lock","probe","recovery","schedule"]
consoleLinks: [{"to":"/recovery","label":"Backups"},{"to":"/recovery/schedules","label":"Scheduled capture"},{"to":"/recovery/store","label":"Backup store"}]
---

## Why RustIron backups survive a compromised host {#immutable-backups}

Backup captures use restic client-side encryption to an S3-compatible store (such as RustFS) with Object Lock COMPLIANCE retention. Crucially, the source host holds append-only credentials and cannot delete, forget, or shorten retention on existing snapshots.

```sh title="Create a one-off backup capture plan" where="Workstation (operator)"
rustiron plan create product-backup-capture --site-id wpblog --out-dir ./plans/wpblog-cap
```

```sh title="Create a daily standing capture grant (D-035, <= 35 days)" where="Workstation (operator)"
rustiron plan create product-standing-capture \
  --site-id wpblog \
  --period-seconds 86400 \
  --window-seconds 3600 \
  --max-runs 30 \
  --out-dir ./plans/wpblog-sched
```

## Reading the 7-field Recovery Evidence strip {#seven-evidence-fields}

A snapshot file alone does not prove recoverability. RustIron tracks seven independent verification fields for every site — shown on Websites and Backups:

- 1. Artifacts present — encrypted files and database dump recorded in the store.
- 2. Integrity verified — SHA-256 and restic repository checksums match.
- 3. Decryption tested — repository key decrypted the capture cleanly.
- 4. App consistency — database marker matched the captured site state.
- 5. Isolated restore — contained restore probe unpacked cleanly without touching the live site.
- 6. Health checks — restored workload answered HTTP/database verification probes.
- 7. Independent copy — retention lock / off-host copy confirmed.

```sh title="Run a non-destructive contained restore probe" where="Workstation (operator)"
rustiron plan create product-restore-probe --site-id wpblog --out-dir ./plans/wpblog-probe
```
