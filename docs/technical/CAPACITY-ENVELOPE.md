# Measured Support and Capacity Envelope

Updated: 2026-11-24 (America/Toronto).
Roadmap item: [P12](../planning/ROADMAP.md#p12--publish-a-measured-support-and-capacity-envelope).
Evidence: [W607](../validation/S10-W607/README.md) (5-trial preregistered lab campaign), [W424](../validation/S10-W424/README.md) (B13 7.91M-request cached/uncached/private operation-overhead trial), and [G0](../feasibility/g0/G0_OPUS_SYSTEMS_REPORT.md) (historical baseline).

This document replaces assumptions with measured latency, error, CPU, PSS, disk I/O, PHP, SQLite, and MariaDB data.
All measurements ran under SELinux **Enforcing** with per-site confinement active.

## 1. Supported stack versions

Authoritative machine-readable pins live in [`crates/control/support-matrix.json`](../../crates/control/support-matrix.json) and [Support matrix](SUPPORT-MATRIX.md) (D-063). v1.0 supports AlmaLinux 10 x86_64 only ([D-058](../decisions/D-058-v1-scope.md)).

| Component | Package / Profile | Supported Series | Measured Lab Version (W607) | End of Life |
| --- | --- | --- | --- | --- |
| OS | AlmaLinux 10 x86_64 | 10.x (min 10.2) | 10.3 (`6.12.0-264.16.1.el10_3`) | 2035-05-31 |
| Web server | `openlitespeed` | 1.9 (min 1.9.4) | `1.9.4-3.el10` | Rolling 1.9 |
| PHP runtime | `lsphp84` (per-site pool) | 8.4 (min 8.4.27) | `8.4.27-1.el10` | 2028-12-31 |
| Database | `mariadb-server` (loopback) | 10.11 LTS (min 10.11.18) | `10.11.18-1.el10_2.alma.2` | 2028-02-16 |
| Authoritative DNS | `pdns` (`when_installed`, D-092) | 5.1 (min 5.1.5) | `5.1.5` (W560–W566) | 2028-01-01 |
| Node.js apps & EmDash | `nodejs` (`node_22_v1`, D-099/D-096) | 22 LTS (min 22.23.4) | `22.23.4-1.el10_2` | 2027-04-30 |
| Bun apps | `bun_1_v1` (D-099) | 1.4.x | `1.4.2` (W599) | Upstream |

## 2. Measured cost of isolation and control plane

Measured on disposable AlmaLinux 10.3 KVM guest `w607-p12` (4 vCPU, 4,655 MiB usable RAM, SELinux **Enforcing**, 11 sites registered and served simultaneously; [W607](../validation/S10-W607/README.md)):

| Component | Idle Procs | Idle PSS | Peak Active PSS (Load/Soak) | 180 s Soak PSS Drift | Notes |
| --- | ---: | ---: | ---: | ---: | --- |
| Rustiron control plane (`executor`, `coordinator`, `admin-helper`) | 3 | **20.5 MiB** | **21.0 MiB** | **+0.0 MiB** | `observe` p50 46.3 ms / max 97.2 ms under 74% CPU soak |
| OpenLiteSpeed (`litespeed`) | 6 | **12.6 MiB** | **13.7 MiB** | **+0.0 MiB** | Shared ingress across all 11 HTTP/HTTPS/proxy sites |
| MariaDB (`mariadbd`) | 1 | **144.0 MiB** | **152.2 MiB** | **-0.0 MiB** | 170,247 queries during 180 s soak, 0 errors |
| Per-site LSPHP 8.4 pools (active sites) | 5–7 | **149.0 MiB** | **221.7 MiB** | **-75.6 MiB** | ~30–45 MiB PSS per active PHP site; heavy Elementor adds ~35 MiB |
| EmDash 1.6.0 CMS (`node_22_v1`, SQLite FTS5) | 1 | **52.6 MiB** | **73.0 MiB** | **-0.1 MiB** | `MemoryMax=512M`, `TasksMax=128`, restart-to-ready **208.4 ms** |

**Baseline host footprint (OS, services, 11 served sites, 1 EmDash app):** Idle RAM use is ~970 MiB (~3,680 MiB `MemAvailable` of 4,655 MiB).
Over 1.07 million measured HTTP requests produced **0 new SELinux AVCs**.

## 3. Measured workload envelope (W607 + W424)

### Cold-start latency (after service restart, W607 Trial 2)

| Workload | Restart-to-Ready | Cold Request | Warm p50 (5 req) |
| --- | ---: | ---: | ---: |
| WordPress native (`cp02.example.test`, `rs_cp02` restarted) | immediate socket | **286.9 ms** | **30.5–35.3 ms** |
| Static site (`cptstatic.example.test`, `enableScript 0`) | — | **0.43 ms** | **0.20 ms** |
| EmDash 1.6.0 SSR (`emdashp12.example.test`, unit restarted) | **208.4 ms** | **1.61 ms** | **0.68 ms** |
| EmDash 1.6.0 SQLite FTS5 (`/_emdash/api/content/`) | **208.4 ms** | **1.23 ms** | **0.48 ms** |

### Traffic-class load matrix (20 s windows, c=1 and c=8, W607 Trial 3)

| Traffic Class | Concurrency | Requests | Errors | Throughput (req/s) | p50 (ms) | p95 (ms) | p99 (ms) | Guest CPU | MariaDB Queries |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| WordPress home (`cp02`, `ls_enabled=0`, 1 PHP worker) | c=1 / c=8 | 645 / 669 | 0 / 0 | 31.7 / 32.8 | 30.7 / 210.2 | 33.3 / 485.9 | 38.5 / 513.0 | 29% / 32% | 19,997 / 20,741 |
| WordPress uncached (`?p12_nocache=`, 1 PHP worker) | c=1 / c=8 | 629 / 675 | 0 / 0 | 30.9 / 33.1 | 31.1 / 207.3 | 36.9 / 497.5 | 43.7 / 585.5 | 33% / 29% | 19,505 / 20,927 |
| WordPress logged-in (`Cookie: wordpress_logged_in_*`) | c=1 / c=8 | 633 / 667 | 0 / 0 | 31.1 / 32.7 | 31.0 / 208.4 | 36.8 / 492.8 | 44.1 / 581.3 | 32% / 36% | 19,625 / 20,695 |
| WordPress private (`/wp-login.php`) | c=1 / c=8 | 2,126 / 2,257 | 0 / 0 | 104.4 / 111.1 | 9.3 / 83.4 | 10.3 / 133.4 | 11.9 / 182.7 | 26% / 37% | 29,766 / 31,600 |
| Heavy WordPress + Elementor Pro HTTPS (`acamt`, uncached, ~180 queries/req) | c=1 / c=8 | 80 / 89 | 0 / 0 | 3.9 / 4.2 | 247.2 / 1,642.8 | 276.7 / 3,692.9 | 282.5 / 4,301.4 | 33% / 27% | 14,425 / 16,047 |
| Static site (`cptstatic`, `enableScript 0`) | c=1 / c=8 | 103,471 / 113,375 | 0 / 0 | 5,033 / 5,453 | 0.2 / 1.3 | 0.2 / 2.5 | 0.3 / 3.2 | 37% / 57% | 2 / 2 |
| EmDash 1.6.0 SSR (`emdashp12`, OLS proxy -> Node 22 + SQLite) | c=1 / c=8 | 61,110 / 94,120 | 0 / 0 | 3,002 / 4,590 | 0.3 / 1.6 | 0.4 / 2.8 | 0.5 / 3.7 | 38% / 74% | 2 / 2 |
| EmDash 1.6.0 FTS5 (`/_emdash/api/content/?q=emdash`) | c=1 / c=8 | 55,568 / 99,348 | 0 / 0 | 2,724 / 4,731 | 0.3 / 1.5 | 0.5 / 2.6 | 0.7 / 3.2 | 44% / 70% | 2 / 2 |

- **LSCache-enabled WordPress baseline (W424, B13):** With D-044 cache-on enabled, 3,956,627 `cached` and 3,905,672 `private_anon` requests completed with **0 errors**. Cached hit share reached **1.00** with **2.1 ms** p95. During active capture, cached p95 rose to **2.3 ms** (`private` p99 ratio up to 1.26).
- **Historical G0 baseline preserved:** P12 does **not** erase G0's recorded **34 uncached timeouts** under unconstrained concurrency. Heavy Elementor (`3.9–4.2 req/s`, p99 `4.30 s` at `c=8`, `maxConns=1`) shows why uncached pages queue unless D-044 LSCache serves public traffic.

### Failure isolation and PHP worker saturation (W607 Trial 5)

- **Backend outage isolation:** Stopping `rustiron-app@rs_emdashp12.service` returned **380/380 `503`** for EmDash. WordPress (`cp02`) served **380/380 `200`** (p50 31.6 ms) and static (`cptstatic`) served **380/380 `200`** (p50 0.32 ms). Restarting restored `/health` to `200`.
- **PHP worker saturation (`c=16`, `maxConns=1`):** Uncached WordPress queued to **503/503 `200`** (32.5 rps, p50 **484.6 ms**, p99 **1,087.1 ms**, 0 errors). Static stayed at **150/150 `200`** (p50 0.43 ms) and EmDash stayed at **148/148 `200`** (p50 1.08 ms).

## 4. Resource floors, limits, and support tiers

These planning tiers leave >=35% memory headroom for OS page cache, MariaDB buffer pool growth, dnf updates, and backup capture workers (`rustiron_capture_t`). **Sampled PSS is a floor, not a density promise.**

| Support Tier | Minimum VPS Profile | Recommended Workload Ceiling | Per-Site Defaults | Required Operational Guardrails |
| --- | --- | --- | --- | --- |
| **Tier 1 — Entry Personal Host** | 2 vCPU, 4 GiB RAM, 40 GiB NVMe/SSD + 2 GiB swap | Up to 4 low-traffic WordPress sites (with LSCache on) **or** 2 WordPress + 2 Node.js/Bun/EmDash apps + static sites | PHP `maxConns=1`, `memory_limit=256M`; App `MemoryMax=256–512M`, `TasksMax=64–128`; XFS quota `>= 512 MiB` (core updates need ~2x release headroom) | Enable D-044 LSCache on public WordPress sites; run captures sequentially via D-035 standing grants |
| **Tier 2 — Standard Single-Host Panel (v1.0 target)** | 4 vCPU, 8 GiB RAM, 80 GiB NVMe/SSD + 4 GiB swap | Up to 10 mixed sites (e.g., 5–6 WordPress with LSCache, 2–3 EmDash/Node/Bun apps, static/proxy sites) + PowerDNS 5.1 | Same per-site confinement; keep heavy Elementor/WooCommerce sites cached and isolated | Monitor P04 diagnoses & P05 Uptime Kuma heartbeats; verify disk & inode headroom before `site_update` |
| **Tier 3 — Heavy / Uncached Dynamic** | 4–8 vCPU, 16 GiB RAM, 160+ GiB NVMe | High-traffic logged-in WordPress or multiple concurrent Node.js/Bun workers | Requires explicit per-site quota/limit tuning (never disable SELinux or per-site UIDs) | Measure on target hardware during P11 pilot before expanding site count |

## 5. Explicit non-claims and limits

1. **Single-host lab KVM profile:** W607 ran on a local 4-vCPU KVM guest backed by NVMe with loopback load generation. Public VPS network jitter, noisy neighbours, and slower block storage will increase tail latency and disk I/O wait. Independent VPS validation supplements this envelope during the P11 pilot.
2. **Confinement is never traded for throughput:** Every number above was measured with SELinux Enforcing, per-site UIDs, `rustiron_php_t`, `rustiron-app@.service` cgroup limits, and `PrivateNetwork=yes` unpack/migration isolation intact.
3. **No density promise from idle RAM:** Heavy plugins (Elementor Pro at ~180 queries/req and 247 ms) saturate CPU and PHP workers before RAM runs out.
4. **Control-plane `diagnose` deviation in W607 Trial 4:** See [W607](../validation/S10-W607/README.md#deviations) for the exact harness path deviation recorded transparently.
