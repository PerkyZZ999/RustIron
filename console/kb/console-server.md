---
title: "Server pages"
description: "Watch your server's health, services, firewall, scheduled jobs, logs, alerts, and updates."
category: "console"
order: 9
readMinutes: 4
runbooks: ["Runbook 23","Runbook 28"]
keywords: ["overview","metrics","services","firewall","cron","logs","diagnoses","alerts","updates","health","csv"]
consoleLinks: [{"to":"/","label":"Host overview"},{"to":"/host/diagnoses","label":"Diagnoses"},{"to":"/host/logs","label":"Logs"}]
---

## Overview {#overview}

The Overview page is the first page you see. It shows CPU, memory, disk, and uptime, quick actions, a resource history chart, your sites and services, recent changes, recovery status, and any open findings. Anything that needs your attention is at the top.

## Metrics and services {#metrics}

Metrics shows the CPU, memory, and disk history of the server. Pick a time range, open the sample table for exact values, and use Export CSV to download the samples.

Services lists the server software that RustIron manages and whether each one is running. Restarting a service or changing its settings is a plan, like any other change.

## Firewall and scheduled jobs {#firewall}

Firewall shows the ports that are open to the internet. Database and admin ports stay closed. The rule builder prepares a firewall change and gives you its commands.

Cron jobs lists the server's timers and each website's scheduled jobs, such as WordPress cron. Heavy jobs wait when the server is busy, but backups still run before their deadline.

## Logs {#logs}

Logs shows the recent log lines of one service at a time. Choose the service and how many lines to show, filter by severity, turn on auto-refresh, or download the lines as a file. Passwords, keys, tokens, and cookies are removed before you see them.

## Diagnoses and alerts {#diagnoses}

Diagnoses runs health checks on security, services, certificates, storage, and backups, and lists open findings with what to do about them. A few checks, such as SSH and the firewall, need root access, so the Console shows them as "Not checked" and explains how to run them on the server.

Alerts shows the server's heartbeat to your monitoring service. If the server stops checking in, your monitoring service alerts you.

## Updates {#updates}

Updates lists the versions of the server software, how long each is supported, and security notices. Updates themselves run from the server's command line, with automatic rollback. "Update RustIron" explains how.
