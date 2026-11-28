---
title: "Domains, HTTPS & DNS"
description: "Get free HTTPS certificates, manage DNS zones, and put the Console on your own domain."
category: "domains-mail"
order: 19
readMinutes: 5
runbooks: ["Runbook 21","Runbook 29","Runbook 38"]
keywords: ["domain","ssl","tls","https","acme","letsencrypt","certbot","dns","powerdns","zone","mx","spf","dmarc"]
consoleLinks: [{"to":"/domains","label":"Domains"},{"to":"/domains/new","label":"Add domain wizard"}]
---

## HTTPS certificates & automatic renewal {#ssl-certificates}

RustIron issues single-hostname ECDSA P-256 certificates using confined HTTP-01 challenges under the rustiron-acme account. Private keys never leave the host, and certbot-renew.timer renews certificates inside the 30-day window before triggering a graceful OLS reload.

- Make sure DNS A/AAAA records point to your server's public IP and TCP ports 80 & 443 are open in the rustiron firewalld zone.
- Verify the active ACME directory (Let's Encrypt production vs. staging) with packaging/enrollment-policy.py.

```sh title="Check enrolled ACME configuration on the server" where="Server (root)"
sudo python3 packaging/enrollment-policy.py acme --show
sudo systemctl status certbot-renew.timer
```

## Authoritative PowerDNS 5.1 zones & safe DNS record edits {#powerdns-zones}

Use Add Domain (/domains/new) to generate a canonical sorted .zone file and dns-zone-import command, and use Domains -\> \[Hostname\] -\> DNS records to stage A, AAAA, CNAME, MX, TXT, CAA, SRV, and NS updates with automatic mail-record protection.

```sh title="Import a canonical DNS zone or apply compare-and-set record edits" where="Workstation (operator)"
rustiron plan create dns-zone-import --zone example.com --zone-file ./example.com.zone --out-dir ./plans/zone-import
rustiron plan create dns-change --zone example.com --operations ./dns-ops.json --out-dir ./plans/dns-edit
```

## Hosting the Console on a custom HTTPS domain {#console-https-origin}

By default the Console listens on 127.0.0.1:4319 only. To serve it behind OpenLiteSpeed at a custom subdomain such as console.example.com, set RUSTIRON_CONSOLE_ORIGIN=https://console.example.com and RUSTIRON_CONSOLE_AUTH_REQUIRED=1 in /etc/rustiron-console/env and provision a loopback proxy site with HTTPS.
