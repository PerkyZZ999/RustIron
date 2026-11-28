---
title: "Health checks & SELinux"
description: "What each check on Host diagnoses means, and how to read the server logs."
category: "security-ops"
order: 23
readMinutes: 4
runbooks: ["Runbook 04","Runbook 23","Runbook 28"]
keywords: ["diagnoses","diagnosis","unknown","selinux","ssh","firewalld","logs","alerts","uptime kuma","unprivileged"]
consoleLinks: [{"to":"/host/diagnoses","label":"Host diagnoses"},{"to":"/host/logs","label":"Server logs"},{"to":"/host/alerts","label":"Alerts"}]
---

## Why SSH and firewalld show as root-only checks {#why-root-only}

By security design, rustiron-control refuses to run as root (uid 0) and the Console never widens its privileges. On AlmaLinux 10, unprivileged users can verify that sshd.service and firewalld.service are active via systemd, but cannot inspect root-only sshd -T effective directives or firewall-cmd D-Bus zone rules.

Rather than guessing or faking a green badge, RustIron reports those two policy checks honestly as root-only until verified from an SSH root shell.

```sh title="Verify SSH policy and rustiron firewalld zone directly on the server" where="Server (root)"
sudo sshd -T | grep -Ei '^(passwordauthentication|kbdinteractiveauthentication|permitrootlogin)'
sudo python3 packaging/firewall-zone.py --check
```

## SELinux confinement, server logs & alert check-ins {#selinux-and-logs}

Server Logs (/host/logs) exposes bounded, secret-redacted journalctl output for a closed allowlist of services (executor, control, OLS, MariaDB, PowerDNS, Postfix, Dovecot). Alerts (/host/alerts) pairs with rustiron-alert-checkin.timer to push redacted dead-man heartbeats to Uptime Kuma.

```sh title="Run CLI host diagnosis and print the redacted alert check-in line" where="Server (unprivileged)"
rustiron-control --diagnose --alert-line
```
