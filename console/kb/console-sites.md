---
title: "Websites & apps in the Console"
description: "Add a website or app, look after it, and check its databases from the Console."
category: "console"
order: 6
readMinutes: 4
runbooks: ["Runbook 15","Runbook 32"]
keywords: ["sites","apps","website","wordpress","emdash","node","bun","proxy","databases","migration","add website"]
consoleLinks: [{"to":"/sites","label":"Websites"},{"to":"/apps","label":"Apps"},{"to":"/databases","label":"Databases"}]
---

## Add a website {#add}

Open Websites and choose Add website. Fill in the name and the address of the site. The summary on the right shows what will be created, and the commands panel gives you the commands to create and sign the plan; "Make changes from the Console" explains the next steps.

First, pick what you want to host:

- WordPress: its own PHP pool, a MariaDB database, and LiteSpeed Cache.
- EmDash CMS: a Node.js CMS with a built-in SQLite database.
- Modern full-stack app: a front end and a Bun or Node.js back end behind Caddy, with the database you choose.
- Reverse proxy: HTTPS in front of an app that already runs on the server, WebSockets included.

## Look after a site {#site}

Click a website in the list to open it, or Inspect to see its details beside the list. A website's pages are:

- Overview: whether it answers on the web, how ready its backups are, its runtime and account, its resource use, and its recent changes.
- Configuration: the settings RustIron manages for the site, their history, and any difference RustIron found on the server (drift).
- Maintenance: database password changes, scheduled WordPress jobs, and approved maintenance tasks.
- Operations: every change made to this site.
- Backups: the site's backups and restore tests.

## Back up several websites at once {#bulk}

On Websites, tick the websites you want, or Choose all, and pick Back up now or Test a restore. The Console shows one plan command per website. Run them on your computer, review and sign each plan, and submit it on the Plans page. Nothing changes until you do, and websites are never removed in bulk.

## Apps {#apps}

The Apps page lists your Node.js, Bun, and EmDash apps, whether each is running, and its current release. Choose Inspect to see an app's runtime, its service, its memory and task limits, the names of its secrets (never their values), and its backups. To restart several apps, tick them and choose Restart: you get one signed plan per app, as for websites.

A new release of an app is a plan too: modern app deploy, in New plan.

## Databases {#databases}

The Databases page lists each site's databases: MariaDB, PostgreSQL, or SQLite. Every database has its own user and is reachable only from the server itself. To change a database password, use the site's Maintenance page or credential rotation in New plan.

## Move sites {#migration}

The Migration page imports websites from CyberPanel and moves WordPress content to EmDash CMS. Your old server, DNS, and email stay as they are until you approve the switch. "Move sites to RustIron" has the full steps.
