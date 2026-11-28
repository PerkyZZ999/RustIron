---
title: "Full-stack apps with Caddy"
description: "Host apps with a separate front end and back end behind a confined Caddy server."
category: "hosting"
order: 16
readMinutes: 6
runbooks: ["Runbook 32","Runbook 34"]
keywords: ["caddy","fullstack","full-stack","spa","vite","react","elysia","hono","nextjs","astro","tanstack","blue-green","http3","sse","websocket","rustiron-app-pack"]
consoleLinks: [{"to":"/sites/new","label":"Deploy full-stack app wizard"},{"to":"/apps","label":"Apps"},{"to":"/host/logs","label":"Caddy logs"}]
---

## Four supported full-stack topologies {#four-topologies}

RustIron v0.1.1 supports four closed modern-app topologies behind confined Caddy 2.10+ (HTTP/2, HTTP/3 QUIC on 443/udp, Brotli/Zstd compression, WebSockets, and unbuffered SSE) without ever reloading OpenLiteSpeed or interrupting WordPress traffic.

- static_spa — Static SPA assets (Vite/React/Vue/Svelte) served directly by Caddy with SPA index.html fallback and zero background daemon.
- backend_api — Single Bun 1.4 or Node.js 22 backend or full-stack SSR app (Next.js Standalone, Astro SSR, Elysia/Hono API) on a loopback port.
- fullstack_split — Static SPA front-end served directly by Caddy alongside a confined Bun/Node API backend on /api/ (with optional prefix stripping and WebSocket/SSE routes).
- fullstack_dual_ssr — Dedicated SSR frontend service (rustiron-app-web@) plus a separate API backend service (rustiron-app@), each with optional blue/green standby slots.

## Dual-Mode Caddy Ingress & Shared TLS Custody {#dual-mode-and-tls}

On single-IP servers running both WordPress and modern apps, enable caddy_edge_over_ols in the installation wizard. Caddy binds :80/:443 (TCP + 443/udp), serves modern apps directly, and transparently bridges WordPress/PHP domains to OpenLiteSpeed on 127.0.0.1:8080 with authentic X-Forwarded-\* headers — preserving .htaccess, LSPHP 8.4, and LiteSpeed Cache.

- Single TLS custody (Decision B1): Caddy keeps its admin API on a 0700 Unix socket (never TCP :2019) and runs with auto_https disable_certs, reading certificates read-only from /etc/rustiron-tls/\<account\>/live/ managed by rustiron-acme.
- Confined SELinux domain (rustiron_caddy_t): Caddy cannot bind outbound HTTP/HTTPS, cannot write certificates, and runs with ProtectSystem=strict and CapabilityBoundingSet=CAP_NET_BIND_SERVICE.

```sh title="Enable Dual-Mode Caddy Edge-over-OLS with HTTP/3" where="Server (root)"
sudo python3 packaging/rustiron-install-wizard.py --ingress-mode caddy_edge_over_ols --dry-run
```

## Off-host packaging & zero-downtime blue/green deploys {#pack-and-blue-green}

Never run npm install or bundlers as root on the server. Build locally or in CI, pack a deterministic tarball with packaging/rustiron-app-pack.py (which refuses symlinks, .env secrets, and missing entrypoints), upload it, and sign an app-deploy plan.

When blue/green is enabled, RustIron unpacks the new release, starts the standby slot (Slot B or A), probes its loopback health endpoint, reloads Caddy atomically onto the healthy standby port, and drains the old slot — rolling back automatically if health checks fail.

```sh title="List built-in presets and pack a Vite + Elysia full-stack bundle off-host" where="Workstation (operator)"
python3 packaging/rustiron-app-pack.py presets
python3 packaging/rustiron-app-pack.py pack \
  --preset vite-elysia \
  --frontend-dist ./frontend/dist \
  --backend-dist ./backend/dist \
  --out ./release-out \
  --site-id saasapp \
  --release-id rel-20261126-01 \
  --database postgresql_18 \
  --blue-green-cutover
```
