---
title: "Console tour"
description: "Open the Console in your browser, sign in, and find your way around its pages."
category: "console"
order: 4
readMinutes: 4
runbooks: ["Runbook 38"]
keywords: ["console","web","ui","browser","sign in","login","tunnel","navigation","search","theme","tour"]
consoleLinks: [{"to":"/","label":"Host overview"},{"to":"/settings","label":"Settings"}]
---

## Open the Console {#open}

The Console is RustIron's web interface. It runs on your server and listens only on the server itself, at port 4319. It is never open to the internet on its own.

To use it from your computer, open an SSH tunnel to the server and browse to http://127.0.0.1:4319/. You can also put it behind your own HTTPS domain; Runbook 38 shows how.

:::caution[Keep port 4319 private]
Never open port 4319 to the internet. Use the SSH tunnel, a private network, or the HTTPS setup in Runbook 38.
:::

```sh title="Open an SSH tunnel to the Console" where="Workstation (operator)"
ssh -N -L 4319:127.0.0.1:4319 operator@your-vps.example.com
```

## Sign in {#sign-in}

The first time, the Console asks for the setup token from the server and lets you create the first Admin account. After that, everyone signs in with an email and a password.

Admin accounts also need a second factor: a 6-digit code from an authenticator app. The Console asks you to set it up after your first sign-in. See "Users, roles & sign-in" for the details.

## Find your way around {#layout}

The menu on the left groups the pages by what they are about:

- Overview: the health of the whole server on one page.
- Hosting: Sites, Apps, Databases, and Migration.
- Domains & mail: Domains and Email.
- Safety: Recovery (backups) and Operations (the history of changes).
- Host: Metrics, Services, Firewall, Cron jobs, Logs, Diagnoses, Alerts, and Updates.
- At the bottom: Users, Settings, and Docs & KB.

## The top bar {#top-bar}

The bar at the top has a search box (press Ctrl K to open it from anywhere), a light and dark theme switch, a button to refresh the data, notifications for anything that needs attention, and the name of the server with the time of its last reading.

## Read-only until you choose otherwise {#read-only}

By default the Console only shows information. It never changes your server by itself, and it never holds the keys that approve changes.

When you want to change something, the Console helps you prepare the change and gives you the commands to sign it on your own computer. "Make changes from the Console" explains this step by step.

:::note[What the data means]
The Console shows what it last read from the server. If it cannot read the server, a page says "Unavailable" and tells you what to check. It never fills the gap with sample data.
:::
