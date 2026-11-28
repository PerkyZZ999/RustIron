---
title: "Email"
description: "Send site email through RustIron's relay, manage mailboxes, and check your mail DNS records."
category: "domains-mail"
order: 20
readMinutes: 4
runbooks: ["Runbook 36","Runbook 38"]
keywords: ["email","mail","postfix","dovecot","relay","smtp","mailbox","alias","spf","dkim","dmarc"]
consoleLinks: [{"to":"/mail","label":"Email"},{"to":"/domains","label":"Domains & DNS"}]
---

## Per-site outbound mail relay (D-071) {#outbound-relay}

PHP pools run without arbitrary outbound network access or shell execution, preventing compromised plugins from turning your server into a spam botnet. Instead, transactional mail routes through a confined per-site Postfix Unix socket and authenticated upstream smarthost.

```sh title="Check per-site mail relay policy and confinement on the server" where="Server (root)"
sudo python3 packaging/mail-relay.py --check
```

## Optional Console mailbox & alias catalog {#mailbox-catalog}

By default under D-090 read-only mode, mailbox writes in the Console return 405 MAIL_WRITES_DISABLED. When explicitly enabled with RUSTIRON_CONSOLE_MAIL_WRITES=1, Admin/Operator accounts can maintain a local Argon2id-hashed Postfix/Dovecot mailbox & alias catalog and export virtual maps via /api/mail/export for host synchronization.

:::note[Mail DNS stays protected]
Site changes never silently alter MX, SPF, DKIM, or DMARC records. Any change to mail-sensitive records triggers an explicit warning in the DNS editor.
:::
