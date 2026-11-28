---
title: "PostgreSQL"
description: "Add PostgreSQL next to MariaDB and give each app its own database user."
category: "hosting"
order: 18
readMinutes: 5
runbooks: ["Runbook 27","Runbook 32","Runbook 35"]
keywords: ["postgresql","postgres","pg18","18.7","scram-sha-256","database_url","pg_dump","pg_restore","pgdg","mariadb","sqlite","rotate"]
consoleLinks: [{"to":"/databases","label":"Databases"},{"to":"/sites/new","label":"Deploy app with DB"},{"to":"/host/updates","label":"Stack versions"}]
---

## Choose the right database engine per app {#selectable-db}

When provisioning a modern app, select one of four closed database modes: none (stateless), sqlite (local WAL file in site data/), mariadb (isolated 127.0.0.1:3306 account), or postgresql_18 (PostgreSQL 18.7+ on 127.0.0.1:5432 with SCRAM-SHA-256).

- Opt-in SELinux database confinement: stateless and SQLite apps remain in rustiron_app_t with zero TCP connect permissions. Apps choosing MariaDB run in rustiron_app_mariadb_t (loopback 3306 only); apps choosing PostgreSQL 18 run in rustiron_app_pg_t (loopback 5432 only).
- PostgreSQL 18 is pinned via AlmaLinux 10 PGDG EL-10 repositories with SHA-256 key verification, listen_addresses = '127.0.0.1', and strict scram-sha-256 pg_hba.conf rules.

```sh title="Enable hardened PostgreSQL 18.7 during host setup" where="Server (root)"
sudo python3 packaging/rustiron-install-wizard.py --enable-postgres --dry-run
```

## Zero-exposure DATABASE_URL provisioning & password rotation {#database-url-rotation}

RustIron creates one isolated role (rs\_\<site_id\>) and database (rs\_\<site_id\>\_app) per app, generates a high-entropy password locally inside the executor, and writes DATABASE_URL atomically into /srv/sites/\<site_id\>/private/app.env (mode 0400). Passwords never enter plans, logs, or the browser.

```sh title="Rotate an app's PostgreSQL 18 password and update DATABASE_URL" where="Workstation (operator)"
rustiron plan create site-credential-rotate \
  --plan-id <plan_id> --host-id <host_id> --host-epoch <epoch> \
  --profile-digest <sha256> --requester <requester> \
  --site-id saasapp --hostname app.example.com \
  --target app_postgresql_18_password \
  --valid-from <unix> --expires-at <unix> > ./plan.json
```

## Pre-migration snapshots & encrypted restic backups {#pg-backups-migrations}

Before running any schema migration during app-deploy, RustIron captures a consistent custom-format pg_dump (-Fc) into a root-only 0700 staging directory and automatically runs pg_restore --clean if the migration or post-deploy health check fails. Backup captures include the PostgreSQL 18 dump inside the encrypted restic snapshot alongside site files.

:::note[Never expose port 5432 externally]
Host Diagnoses and the Firewall Rule Builder continuously guard TCP port 5432 so PostgreSQL 18 stays loopback-only (127.0.0.1).
:::
