---
title: "Firewall & scheduled jobs"
description: "Keep the firewall closed, manage cron and backup timers, and limit background traffic."
category: "security-ops"
order: 24
readMinutes: 4
runbooks: ["Runbook 13","Runbook 28"]
keywords: ["firewall","firewalld","ports","cron","timer","wp-cron","traffic","budget","3306","7080","4319"]
consoleLinks: [{"to":"/host/firewall","label":"Firewall"},{"to":"/host/cron","label":"Cron jobs"},{"to":"/host/metrics","label":"Host metrics"}]
---

## The rustiron firewalld zone {#firewall-zone}

packaging/firewall-zone.py creates and verifies a dedicated rustiron zone that opens only public web ports (80/tcp, 443/tcp, 443/udp for HTTP/3) and your active SSH port — keeping MariaDB (3306), OpenLiteSpeed WebAdmin (7080), the Console loopback listener (4319), and internal app ports closed to the internet.

```sh title="Check or apply the rustiron firewalld zone safely (verifies sshd first)" where="Server (root)"
sudo python3 packaging/firewall-zone.py --check
sudo python3 packaging/firewall-zone.py --apply
```

## Managed systemd timers & traffic-budget deferral {#cron-and-budget}

RustIron ships packaged systemd timers for site WP-Cron (rustiron-site-cron.timer), standing backup captures (rustiron-scheduled-capture.timer), and Uptime Kuma heartbeats (rustiron-alert-checkin.timer). Under bursty traffic, the traffic-budget evaluator defers non-urgent background work while enforcing strict RPO deadlines.

```sh title="Evaluate current traffic-budget decision for a background job" where="Server (unprivileged)"
rustiron-control --background-budget /path/to/observation.json --job backup_capture --human
```
