---
title: "Users, roles & sign-in"
description: "Add Console users, choose what each one can do, and keep Admin accounts safe with a second factor."
category: "console"
order: 10
readMinutes: 4
runbooks: ["Runbook 38"]
keywords: ["users","roles","admin","operator","viewer","account","password","second factor","2fa","totp","recovery codes","settings"]
consoleLinks: [{"to":"/users","label":"Users & access"},{"to":"/settings","label":"Settings"}]
---

## Roles {#roles}

Every Console account has one of three roles. A role never signs plans: only a plan signed on your own computer can change the server.

- Viewer: can see everything (dashboards, sites, metrics, logs) but change nothing.
- Operator: can also prepare changes and submit signed plans.
- Admin: can also add, change, and remove Console accounts.

## Add and manage users {#users}

Admins open Users & access and use Add Console user: a name, an email, a first password of at least 10 characters, and a role. The list below shows every account. Change a role from its menu, or delete an account; the Console asks you to confirm first.

The Console keeps at least one Admin: you cannot demote or delete the last one, and you cannot delete your own account. A role change or a deletion signs that account out at once.

## Second factor for Admins {#second-factor}

Every Admin signs in with a password and a 6-digit code from an authenticator app. The first time, the Console asks for your password again, shows a QR code to scan (or a key to type), and turns the factor on after one correct code.

It then shows ten recovery codes, once. Save them somewhere outside the server. Each one signs you in once if you lose your phone; after that, set up the app again.

:::caution[If you lose both]
If an Admin loses the app and every recovery code, the factor can only be reset from a shell on the server, as shown below. Runbook 38 explains the steps.
:::

```sh title="Reset a lost second factor" where="Server (root)"
sudo -u rustiron-coordinator env RUSTIRON_CONSOLE_AUTH_DB=/var/lib/rustiron-console/auth.sqlite \
  /usr/local/bin/bun run --cwd /opt/rustiron/console reset-second-factor owner@example.com
```

## Settings {#settings}

Settings holds your own Console preferences, such as the theme and the default chart range; they are stored in your browser. It also shows, read-only, the server's profile and the keys that are allowed to approve changes. Server security settings are never changed from here.
