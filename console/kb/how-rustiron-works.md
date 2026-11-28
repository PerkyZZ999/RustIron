---
title: "How RustIron works"
description: "How RustIron makes changes safely, why your sites keep running without it, and how each site is isolated."
category: "getting-started"
order: 1
readMinutes: 4
runbooks: ["Runbook 03","Runbook 05","Runbook 34"]
keywords: ["architecture","coordinator","executor","selinux","mcs","sshsign","custody","security","webadmin"]
consoleLinks: [{"to":"/","label":"Host overview"},{"to":"/host/services","label":"Services"},{"to":"/operations","label":"Operations"}]
---

## The strict management path {#management-path}

RustIron is a hosting control plane built around mature Linux infrastructure — OpenLiteSpeed (OLS), LSPHP, MariaDB, systemd, firewalld, PowerDNS, restic, and enforcing SELinux on AlmaLinux 10.

Every privileged change flows through one narrow chain: CLI -\> unprivileged coordinator -\> independently validating executor -\> fixed scoped operations. The executor never accepts raw shell commands, arbitrary SQL, or arbitrary config text.

- Website traffic bypasses RustIron completely: visitors connect straight to OpenLiteSpeed, PHP pools, or loopback apps. Even if the Console or coordinator is stopped, hosted sites keep serving.
- OpenLiteSpeed WebAdmin (:7080) remains permanently disabled under the managed profile so there is no second privileged admin plane.
- The Console Admin Panel runs strictly unprivileged, defaults to read-only observation, and never holds SSHSIG production signing keys.

## Per-site isolation (Unix UID + SELinux MCS + systemd) {#isolation-layers}

Each WordPress website and modern app gets its own dedicated non-root Linux account (rs\_\<site_id\>), its own XFS project disk/inode quota, and a unique SELinux Multi-Category Security (MCS) category.

- WordPress PHP pools run in rustiron_php_t:s0:c\<N\> with isolated sockets and no cross-site filesystem access.
- Node.js 22, Bun 1.4, and EmDash CMS apps run in rustiron_app_t:s0:c\<N\> with ProtectSystem=strict, NoNewPrivileges=yes, and IPAddressDeny=any (allowing only loopback 127.0.0.1/::1 behind OpenLiteSpeed).
- MariaDB binds strictly to the local Unix socket with per-site accounts; port 3306 is never exposed externally.

## Separate signing custody & durable journals {#separate-custody}

Plans are deterministic JSON documents signed offline on your workstation with OpenSSH SSHSIG (namespace rustiron-plan-v1). Before executing anything, the executor checks peer identity, exact signed SHA-256 digest, grant expiry, host/epoch binding, replay admission mark, and live preconditions.

:::note[Unknown outcomes are never silently retried]
If an operation is interrupted mid-flight, the executor records the exact step state in its durable journal and marks the operation as Needs attention until reconciled explicitly.
:::
