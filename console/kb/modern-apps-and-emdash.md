---
title: "Node.js, Bun & EmDash apps"
description: "Run Node.js and Bun apps and EmDash CMS sites, each in its own confined service."
category: "hosting"
order: 15
readMinutes: 5
runbooks: ["Runbook 30","Runbook 32","Runbook 33"]
keywords: ["emdash","cms","node","nodejs","bun","app","deploy","rollback","websocket","sqlite","fts5","proxy"]
consoleLinks: [{"to":"/apps","label":"Apps"},{"to":"/sites/new","label":"Deploy app wizard"}]
---

## 1. Provision an isolated app runtime {#provision-app}

Every modern app runs under its own systemd service (rustiron-app@rs\_\<site_id\>.service) confined by rustiron_app_t:s0:c\<N\> and IPAddressDeny=any + IPAddressAllow=localhost. OpenLiteSpeed proxies public HTTPS traffic (and optional WebSocket paths) to the app's private 127.0.0.1 port.

```sh title="Provision an EmDash CMS / Node.js 22 app" where="Workstation (operator)"
rustiron plan create app-provision \
  --site-id emdash1 \
  --hostname cms.example.com \
  --runtime node_22_v1 \
  --port 3210 \
  --out-dir ./plans/emdash1-prov
```

```sh title="Provision a Bun 1.4 API app" where="Workstation (operator)"
rustiron plan create app-provision \
  --site-id bunapi \
  --hostname api.example.com \
  --runtime bun_1_v1 \
  --port 3102 \
  --out-dir ./plans/bunapi-prov
```

## 2. Deploy immutable releases with automatic rollback {#deploy-and-rollback}

App builds run off-host so no compiler or npm install ever runs privileged on the server. Package your built artifact into a verified tarball (or use packaging/emdash-recipe.py for EmDash 1.6.0), then deploy with app-deploy.

- Before running any schema migration, RustIron snapshots the EmDash SQLite database into a root-only 0700 directory.
- If the migration exits non-zero or the loopback /health probe fails, RustIron automatically restores the previous release symlink and pre-migration SQLite snapshot.
- Secret values live in root-prepared 0400 files on the host — only declared key names ever appear in plans or the Console.

```sh title="Deploy a new app release bundle" where="Workstation (operator)"
rustiron plan create app-deploy \
  --site-id emdash1 \
  --release-id emdash-1.6.1-r1 \
  --bundle-path /srv/staging/emdash-1.6.1-r1.tar.gz \
  --out-dir ./plans/emdash1-deploy
```
