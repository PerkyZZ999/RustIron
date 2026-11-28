---
title: "Domains & email in the Console"
description: "Add a domain, edit its DNS records, get HTTPS, and manage mailboxes from the Console."
category: "console"
order: 7
readMinutes: 4
runbooks: ["Runbook 30","Runbook 36"]
keywords: ["domains","dns","records","ssl","https","certificate","email","mailbox","alias","forwarder","mx","spf","dkim","dmarc"]
consoleLinks: [{"to":"/domains","label":"Domains"},{"to":"/mail","label":"Email"}]
---

## Domains {#domains}

The Domains page lists the domains on your server, their HTTPS certificates, and their DNS zones. Click a domain to see its certificate, the result of the last HTTPS check, and its DNS zone.

To add one, choose Add domain. You can create a DNS zone with starter records, or ask for an HTTPS certificate for a domain your server already hosts. The form gives you the commands to create and sign the change.

## DNS records {#dns}

Open a domain's DNS page to see its records. In the record editor you add, change, or remove records. Your edits are collected as staged changes, so you can check them together before you copy the commands that apply them.

The DNS page also lists every recorded DNS change, so you can see what changed and when.

## HTTPS certificates {#https}

Certificates come from Let's Encrypt and renew on their own. The Issue or renew SSL panel gives you the command to get a certificate now, for example right after you point a new domain at the server.

## Email {#email}

The Email page manages mailboxes and forwarders (aliases) in the Console's own list. That list is prepared in the Console first and then applied to the mail server, so a new mailbox is "pending host sync" until it is applied. Export downloads the list as a file for the mail server.

The page also shows the DNS records that mail needs (MX, SPF, DKIM, and DMARC) and how each website sends its email through RustIron's relay.

:::note[Changes are off by default]
Creating or changing mailboxes in the Console needs the Operator or Admin role, and the server owner must turn it on. Until then, the page is read-only.
:::
