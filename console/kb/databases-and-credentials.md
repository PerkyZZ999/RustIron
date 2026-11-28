---
title: "Databases & passwords"
description: "Manage each site's database, change its password, and export it."
category: "hosting"
order: 17
readMinutes: 4
runbooks: ["Runbook 27","Runbook 35"]
keywords: ["database","mariadb","mysql","sqlite","password","rotate","credentials","export","dump","sql"]
consoleLinks: [{"to":"/databases","label":"Databases"},{"to":"/recovery","label":"Backups"}]
---

## How per-site database isolation works {#db-isolation}

MariaDB is bound strictly to localhost via zz-rustiron-loopback.cnf (zero external TCP listeners on port 3306). Each WordPress site gets its own database (rs\_\<site_id\>\_wp) and least-privilege user with credentials stored in a 0400 db.cnf file readable only by that site's PHP user. EmDash CMS apps use local WAL-mode SQLite databases with native FTS5 inside their confined data/ directory.

## Rotate a MariaDB password with zero secret exposure {#password-rotation}

site-credential-rotate generates a new high-entropy password locally inside the executor, updates MariaDB, atomically swaps the site's db.cnf, and restarts the site's PHP pool — so the password never touches plans, logs, shell history, or the browser.

```sh title="Create a signed database password rotation plan" where="Workstation (operator)"
rustiron plan create site-credential-rotate \
  --site-id wpblog \
  --hostname blog.example.com \
  --out-dir ./plans/wpblog-rotate
```

## Export a clean SQL dump safely offline {#offline-sql-export}

Rather than exposing phpMyAdmin on the public internet, extract consistent SQL dumps directly from any verified restic backup snapshot on your operator workstation.

```sh title="Dump a site's SQL database from an encrypted restic snapshot" where="Workstation (operator)"
restic -r <repo> dump <snapshot_id> /db.sql.zst | zstd -d > ./wpblog-dump.sql
```
