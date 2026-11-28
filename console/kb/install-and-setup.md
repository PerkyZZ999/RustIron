---
title: "Install RustIron"
description: "Set up RustIron on a fresh AlmaLinux 10 server and create your first Console admin."
category: "getting-started"
order: 2
readMinutes: 5
runbooks: ["Runbook 05","Runbook 09","Runbook 38"]
keywords: ["install","wizard","almalinux","enroll","setup","token","admin","bootstrap","first-run"]
consoleLinks: [{"to":"/users","label":"Users & access"},{"to":"/host/diagnoses","label":"Host diagnoses"}]
---

## 1. Run the AlmaLinux 10 installation wizard {#install-wizard}

On a fresh AlmaLinux 10 x86_64 server with Enforcing SELinux, run the guided installation wizard. It checks OS/SELinux prerequisites, verifies or installs the stack (OpenLiteSpeed, LSPHP 8.4, MariaDB, firewalld, Certbot), deploys binaries and SELinux policies, enrolls your operator signing key, hardens SSH, applies the rustiron firewalld zone, and configures the Console service.

```sh title="Interactive installation wizard (recommended)" where="Server (root)"
sudo python3 packaging/rustiron-install-wizard.py
```

```sh title="Dry-run plan without modifying the server" where="Server (root)"
sudo python3 packaging/rustiron-install-wizard.py --dry-run
```

```sh title="Non-interactive install with explicit operator key & Console domain" where="Server (root)"
sudo python3 packaging/rustiron-install-wizard.py --non-interactive \
  --host-id prod-01 \
  --signer-id operator \
  --signer-pubkey /path/to/operator.pub \
  --console-domain console.example.com \
  --apply
```

## 2. Create your Console Admin account {#first-admin}

When RUSTIRON_CONSOLE_AUTH_REQUIRED=1 and RUSTIRON_CONSOLE_SETUP_TOKEN are set in /etc/rustiron-console/env, the Console stays completely locked behind a standalone setup gate until the first Admin account is created. Public self-registration is permanently disabled (403).

:::caution[Keep signing keys on your workstation]
Your Better Auth Console account controls access to the web UI. Production infrastructure changes still require offline SSHSIG signatures from your operator key.
:::

```sh title="Inspect the one-time setup token on the server (never share publicly)" where="Server (root)"
sudo grep '^RUSTIRON_CONSOLE_SETUP_TOKEN=' /etc/rustiron-console/env
```

## 3. Verify enrollment and host health {#verify-health}

After installation completes, confirm the executor, coordinator, SELinux confinement, and firewall zone are healthy.

```sh title="Run read-only diagnosis and firewall zone check" where="Server (root)"
sudo python3 packaging/firewall-zone.py --check
sudo systemctl is-active rustiron-executor rustiron-coordinator rustiron-console
```
