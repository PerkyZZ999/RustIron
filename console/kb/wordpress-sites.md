---
title: "WordPress sites"
description: "Create, tune, update, and remove isolated WordPress sites."
category: "hosting"
order: 14
readMinutes: 5
runbooks: ["Runbook 15","Runbook 24","Runbook 25","Runbook 34"]
keywords: ["wordpress","site","provision","lsphp","php","lscache","page cache","quota","eject","delete","clone"]
consoleLinks: [{"to":"/sites","label":"Sites"},{"to":"/sites/new","label":"Add website wizard"}]
---

## Provision a new WordPress website {#provision-wp}

Use the Add Website wizard (/sites/new) or run rustiron plan create site-provision to generate a signed provisioning plan. RustIron creates a dedicated system user, unique SELinux MCS context, isolated LSPHP 8.4 pool, per-site MariaDB database and credentials, OpenLiteSpeed vhost, and XFS disk quota.

```sh title="Generate a WordPress site-provision plan" where="Workstation (operator)"
rustiron plan create site-provision \
  --site-id wpblog \
  --hostname blog.example.com \
  --out-dir ./plans/wpblog
```

## PHP workers, LiteSpeed Page Cache & WordPress updates {#tuning-updates}

Per-site maintenance controls live under Sites -\> \[Site\] -\> Maintenance. Config changes (PHP worker limits, LiteSpeed Page Cache opt-in/out) run through config-activate; WordPress core, plugin, and theme updates run unprivileged as the site account and roll back cleanly if post-update health probes fail.

```sh title="Tune PHP workers and activate configuration" where="Workstation (operator)"
rustiron plan create config-activate \
  --site-id wpblog \
  --php-max-children 6 \
  --out-dir ./plans/wpblog-cfg
```

## Eject vs. Delete a site {#eject-vs-delete}

RustIron separates handing a site back to manual administration (eject) from removing it permanently (delete).

- Eject (site-eject): stops RustIron management while preserving the website files, MariaDB database, standalone OLS vhost, and TLS certificates intact.
- Delete: requires a fresh (\< 24 h) verified backup capture before removing the live site root, PHP pool, and database.

```sh title="Prepare a non-destructive site-eject plan" where="Workstation (operator)"
rustiron plan create site-eject --site-id wpblog --out-dir ./plans/wpblog-eject
```
