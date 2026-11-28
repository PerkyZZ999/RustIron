---
title: "Backups in the Console"
description: "See how ready each site is to be restored, plan backups, and check your backup storage."
category: "console"
order: 8
readMinutes: 4
runbooks: ["Runbook 10","Runbook 13","Runbook 22"]
keywords: ["backup","recovery","restore","snapshot","schedule","evidence","receipt","store","probe"]
consoleLinks: [{"to":"/recovery","label":"Backups"},{"to":"/recovery/schedules","label":"Scheduled capture"},{"to":"/recovery/store","label":"Backup store"}]
---

## Backups {#recovery}

The Backups page shows, site by site, weakest first, how sure you can be that a backup will restore. RustIron does not count a backup as recoverable until a restore has been tested.

For each site it checks seven things:

- every expected file and database part exists;
- a repository check covered the backup;
- the backup was decrypted with a recovered key;
- the timing between files and database was checked;
- it was restored into a fresh, isolated sandbox;
- the restored site answered test requests;
- a separate copy exists in another place.

## Take a backup or test a restore {#actions}

The Backup & restore panel on the Backups page prepares a backup of a site, or a restore test (a recovery probe) in an isolated sandbox. A restore test never touches the live site. Choose the site, and the panel gives you the commands to create and sign the plan.

To do the same for several sites, tick them in the list and choose Back up now or Test a restore: you get one plan command per site.

Click a backup (a snapshot) to see its parts and its checks. Click a restore test result (a receipt) to see how the restore went and the safe next step.

## Schedules {#schedules}

Scheduled capture lists the backups that run on their own and lets you prepare a new schedule. Each schedule has a fixed time window and stores its backups encrypted, away from the server.

## Backup store {#store}

Backup store shows where your backups go: the S3-compatible storage, its retention lock, and how much space the backups use. The storage keys stay on the server and never appear in the Console.
