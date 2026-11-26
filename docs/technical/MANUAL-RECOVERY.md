# Manual site recovery without Rustiron (lab), 2026-10-26

Updated: 2026-11-12, America/Toronto (W354).

This guide restores one WordPress site from its encrypted backup onto a clean AlmaLinux 10 host using only standard packages.
The guide does not need Rustiron, the original host or its journal.
Step 6 copies two files from the Rustiron repository to the clean host: `lab/s08/recover_unpriv.sh` and `lab/s08/health.php`.

[D-026](../decisions/D-026-defer-offsite-and-escrow.md) defers recovery from the USB escrow stick or the off-site copy until after v1.0.
Independent-copy recovery remains **NOT_RUN**.
D-018 permits an agent runner without implementation context; another human guide follower is optional.
Use the [autonomy policy](../AUTONOMY.md) for current participation requirements.

## Evidence for this guide

| Task | Scope |
| --- | --- |
| [W036](../validation/S09-W036/README.md) | An earlier version of steps 3–13, a database import, and a health check as root in an AlmaLinux 10.2 container |
| [W218](../validation/S10-W218/README.md) | The unprivileged check of steps 16–19 on blog13 data; W218 did not repeat the fetch steps |
| [W325](../validation/S10-W325/README.md) | Steps 2–8 of the previous text (now steps 9–19) with synthetic data and stand-in images; findings F01–F28 |
| [W327](../validation/S10-W327/README.md) | The changes for the findings that D-026 does not defer, and the check script exit status |
| [W337](../validation/S10-W337/README.md) | Steps 1–29 in order on a clean AlmaLinux 10.2 host in Enforcing mode, with a blog13 snapshot from the lab store. Step 28 used a test-only web server |
| [W350](../validation/S10-W350/README.md) | A timed run of steps 1–30 on a clean AlmaLinux 10.2 host in Enforcing mode, with the same snapshot and a test-only web server; guide problems G1–G7 |
| [W353](../validation/S10-W353/README.md) | The changes for G1–G7 |
| [W354](../validation/S10-W354/README.md) | A timed run of steps 1–30 of the W353 text on a clean AlmaLinux 10.2 host in Enforcing mode, with a non-root `<login>`, the `America/Toronto` time zone, the same snapshot, and the test-only verification server |

W337 and W350 ran the text before the W353 changes. W354 ran the W353 text.
The test-only verification server is the W350 configuration, not a production recipe.

## What you need (key recovery)

The PC holds these, never the site host's only copy:

| Item | Lab location on the operator PC |
| --- | --- |
| Store address and bucket | `http://192.168.122.1:9000`, bucket `rustiron-lab-backups` |
| Read-only fetch key for the site | `~/.config/rustiron-lab/sites/<account>/fetch-aws` |
| Repository password (decryption key) | `~/.config/rustiron-lab/sites/<account>/repo.password` |
| Site account, for example `rs_blog13` | The `site_provision` plan of the site, or the `export SITE` output of the executor |
| Site hostname, for example `blog13.example.test` | The `site_provision` plan of the site; the capture receipt does not hold it |
| Capture receipt (optional) | The JSON reply that `rustiron-submit` printed for the capture, or `receipt-export OP` output, saved off the site host |
| Rustiron repository checkout (`<repo>`) | Any copy of the repository; step 6 copies two files from it |
| SSH access to the clean host as `<login>` | The key that the clean host accepts for `<login>`. See [Before you start](#before-you-start) |

The read-only fetch key can list and read only the site's prefix in the store ([site-fetch-policy.json.in](../../lab/s07/site-fetch-policy.json.in)).
The key cannot write, lock, or delete.
Without the repository password, nobody can decrypt the backup.
Keep a second copy of these offline.

A capture receipt holds the snapshot ID in `snapshot_id`.
The `consistency.label` field is `matched` or `unmatched`, and `consistency.reason` explains an `unmatched` label.
Only `matched` means that the files and the database agree ([08](../operator/08-CAPTURE-FREEZE-LIMITS.md)).
The executor journal on the site host holds the receipts.
After host loss, you have only the receipts that you saved elsewhere.

## Safety scope

Restored PHP and SQL are untrusted.
Steps 18–19 run restored code only through [lab/s08/recover_unpriv.sh](../../lab/s08/recover_unpriv.sh).
The script refuses to run unless it has a non-root user, no effective capabilities, `NoNewPrivs`, and no network interface except `lo`.
Do not run restored code from a root shell.
The fixed product restore runner has its own identity and containment contract.

## Before you start

- Run every step on the clean host as root, in one shell (`sudo -i`). Later steps use shell variables from earlier steps.
- Steps 6 and 7 also run commands on the operator PC. They copy files to the clean host with `scp`, as the account `<login>`.
- Use `root` as `<login>` if the clean host accepts an SSH key for root. A host from the lab kickstart [cleanhost-ks.cfg.in](../../lab/s09/cleanhost-ks.cfg.in) has only `root`, with the lab key. Otherwise, use an administrator account that can run `sudo -i`.
- `scp` puts the files in the home folder of `<login>`. Step 2 sets `L` to that folder.
- The clean host needs network access in steps 3–13. The [test-only verification server](#test-only-verification-server) also needs it for `dnf install`. Steps 3 and 5 reach the AlmaLinux and EPEL mirrors and the container registry.
- The lab store listens on `192.168.122.1`, the libvirt network of the operator PC. Put the clean host on that network.
- If a step fails or its outcome is unknown, stop and use the failure table. Do not continue to the next step.

## Steps on the clean host

### Prepare the host

1. Record the start time:

   ```sh
   date -u +%Y-%m-%dT%H:%M:%SZ | tee /root/recovery-start.txt
   ```

   The command prints one UTC time. Copy it into the recovery record.
2. Set the site variables and the home folder of `<login>`. Replace `A` and `H` with the site's account and hostname:

   ```sh
   A=rs_blog13; H=blog13.example.test; L=/root
   ```

   `echo "$A $H $L"` prints the account, the hostname, and the folder.
   `L=/root` applies when `<login>` is `root`. For another account, set `L=/home/<login>`.
   W350 used `root` and `/root`. W354 used the account `opadmin` and `L=/home/opadmin`.
3. Install the host tools:

   ```sh
   dnf install -y epel-release
   dnf install -y restic podman mariadb-server
   ```

   `restic version` prints `restic 0.18.0` or later. Step 13 needs `restore --exclude-xattr`, and restic 0.18.0 is the first release with that option.
   W036 and W337 used restic 0.19.1 from EPEL, and W325 used restic 0.18.1. W337 used podman 5.8.2 from AppStream.
4. Write the tools image definition:

   ```sh
   install -d -m 0700 /root/recovery-tools
   printf 'FROM docker.io/library/almalinux:10\nRUN dnf install -y mariadb-server php-cli php-mysqlnd && dnf clean all\n' \
     > /root/recovery-tools/Containerfile
   ```

   `cat /root/recovery-tools/Containerfile` prints the `FROM` line and the `RUN` line.
   W218 built the same packages on `almalinux:10`. W036 recorded PHP 8.3.36 on AlmaLinux 10.2.
5. Build the tools image while the host has network access:

   ```sh
   podman build -t recovery-tools /root/recovery-tools
   ```

   `podman image exists recovery-tools && echo ready` prints `ready`.
6. Copy the two check files to the clean host and compare their SHA-256 values.
   On the operator PC, in the repository checkout, print the values and copy the files. Replace `<repo>`, `<login>`, and `<clean-host>`:

   ```sh
   cd <repo>
   sha256sum lab/s08/recover_unpriv.sh lab/s08/health.php
   scp lab/s08/recover_unpriv.sh lab/s08/health.php <login>@<clean-host>:
   ```

   `sha256sum` prints one value per file. `echo $?` after `scp` prints `0`.
   On the clean host, install the files next to the image definition, remove the copies, and print the values:

   ```sh
   install -m 0555 "$L/recover_unpriv.sh" /root/recovery-tools/recover_unpriv.sh
   install -m 0444 "$L/health.php" /root/recovery-tools/health.php
   rm -f "$L/recover_unpriv.sh" "$L/health.php"
   sha256sum /root/recovery-tools/recover_unpriv.sh /root/recovery-tools/health.php
   ```

   The two values on the clean host are the same as the two values on the operator PC. If a value is different, stop and copy the files again.
   `ls -l /root/recovery-tools/recover_unpriv.sh` shows `-r-xr-xr-x`.
   W350 used `scp` and a SHA-256 comparison on both sides, with `root` as `<login>`.
   W354 ran these commands with a non-root `<login>`, and the values were the same.

### Fetch the backup

7. On the operator PC, copy the two key files to the clean host. Replace `<account>`, `<login>`, and `<clean-host>`:

   ```sh
   scp ~/.config/rustiron-lab/sites/<account>/fetch-aws \
     ~/.config/rustiron-lab/sites/<account>/repo.password <login>@<clean-host>:
   ```

   `echo $?` prints `0`. In a terminal, scp also prints one line per file with `100%`.
8. On the clean host, move the key files from the home folder of `<login>` into a root-only folder:

   ```sh
   install -d -m 0700 /root/recovery-keys
   install -m 0400 -o root -g root "$L/fetch-aws" "$L/repo.password" /root/recovery-keys/
   rm -f "$L/fetch-aws" "$L/repo.password"
   ```

   `ls -l /root/recovery-keys` shows two files with mode `-r--------` and owner `root`.
9. Point restic at the site repository:

   ```sh
   export AWS_SHARED_CREDENTIALS_FILE=/root/recovery-keys/fetch-aws
   export RESTIC_PASSWORD_FILE=/root/recovery-keys/repo.password
   export RESTIC_REPOSITORY="s3:http://192.168.122.1:9000/rustiron-lab-backups/sites/$A"
   ```

   `echo "$RESTIC_REPOSITORY"` prints one `s3:http://` prefix, then the store address, the bucket, and `sites/` with the account.
   Do not paste the table's `http://` address after `s3:http://`.
10. Check the repository structure:

    ```sh
    restic check --no-lock
    ```

    restic prints `no errors were found` and exits 0.
    The read-only key cannot create a lock, so every restic command needs `--no-lock`.
11. List the snapshots:

    ```sh
    restic snapshots --no-lock
    ```

    restic prints a table with at least one snapshot of the two paths `/srv/sites/<account>/html` and `/srv/sites/<account>/tmp/rustiron-capture.sql`.
    The table puts the second path of a snapshot on its own line. The table shows times in the local time zone of the clean host.
    Step 12 reads the same list as JSON.
12. List the product capture snapshots of the site with their UTC times:

    ```sh
    restic snapshots --no-lock --json | python3 -c '
    import datetime, json, re, sys
    a = sys.argv[1]
    want = {"/srv/sites/" + a + "/html", "/srv/sites/" + a + "/tmp/rustiron-capture.sql"}
    rows = []
    for s in json.load(sys.stdin):
        tags = s.get("tags") or []
        if set(s.get("paths") or []) == want and any(t.startswith("rustiron-op-") for t in tags):
            t = datetime.datetime.fromisoformat(re.sub(r"\.[0-9]+", "", s["time"]).replace("Z", "+00:00"))
            rows.append((t.astimezone(datetime.timezone.utc), s["short_id"], ",".join(tags)))
    for t, i, g in sorted(rows):
        print(i, t.strftime("%Y-%m-%dT%H:%M:%SZ"), g)
    ' "$A"
    ```

    The command prints one line per product capture snapshot, oldest first: the short ID, the time in UTC, and the tags.
    A product capture snapshot has a tag that starts with `rustiron-op-`, and holds the two paths from step 11 and no other path.
    The command reads only the JSON fields `short_id`, `time`, `tags`, and `paths`. After step 3, the host has `python3`: step 3 installs `python3-policycoreutils` as a dependency (W350).

    If the command prints nothing, the repository has no product capture of this site. Check `$A`. Do not select a test snapshot.
    In W354, the step 11 table had 97 snapshots. The filter printed the same 79 snapshots as the table rows with a `rustiron-op-` tag and the two paths.

    Select the snapshot and set its ID:

    ```sh
    SNAP=<snapshot-id>
    ```

    Use these rules, in this order:
    1. The newest saved capture receipt with `consistency.label` `matched`.
    2. If no saved receipt has `matched`, the newest saved capture receipt.
    3. If you saved no receipt, the last line of the filter output: the newest product capture snapshot. Record the consistency label as unknown, and treat the snapshot as `unmatched`.

    The first 8 characters of a receipt `snapshot_id` are the short ID in the filter output.
    Do not select a snapshot only because it is the newest. The repository can hold snapshots from tests and other tools. The lab repository holds hostile test snapshots, for example with the tags `w328-hostile` and `w180-bomb-b3`.

    Show the selected snapshot with UTC times:

    ```sh
    TZ=UTC restic snapshots --no-lock "$SNAP"
    ```

    restic prints exactly that snapshot. Its time is the same as the UTC time in the filter output.
    Copy the ID and the UTC time into the recovery record as `snapshot_id` and `snapshot_time_utc`.
    Do not copy a time from a restic table without `TZ=UTC`.
    Do not copy the time from the step 13 restore line. That line uses the time zone of the source host.
    Do not use `latest`: the record must name the restored snapshot.

    In W354, the clean host used `America/Toronto`. The step 11 table showed `14:58:01`, and this command showed `19:58:01` and `Timestamps shown in UTC`.
13. Restore the snapshot:

    ```sh
    restic restore --no-lock --exclude-xattr security.selinux --target /recovery "$SNAP"
    ```

    restic prints `Summary: Restored` and exits 0.
    The source host's SELinux labels do not apply on a new host, and restoring them fails without privileges.
    The site is under `/recovery/srv/sites/$A/html`, and the database dump is at `/recovery/srv/sites/$A/tmp/rustiron-capture.sql`.
14. Copy an untouched serving copy before any restored code runs:

    ```sh
    install -d -m 0755 /srv/sites
    cp -a "/recovery/srv/sites/$A" "/srv/sites/$A"
    ```

    `ls "/srv/sites/$A/tmp/rustiron-capture.sql"` prints the path of the dump.
15. Remove the keys from the clean host:

    ```sh
    rm -f /root/recovery-keys/fetch-aws /root/recovery-keys/repo.password
    unset AWS_SHARED_CREDENTIALS_FILE RESTIC_PASSWORD_FILE
    ```

    `ls -A /root/recovery-keys` prints nothing. The operator PC keeps its copies.

### Check the site offline

The container in step 18 has no network interface (`--network none`), and the script refuses to run otherwise.
You do not need to disconnect the host.

16. Copy the health check into the check copy:

    ```sh
    install -m 0444 /root/recovery-tools/health.php /recovery/health.php
    ```

    `ls -l /recovery/health.php` shows `-r--r--r--`.
17. Give the check copy to uid 1000, the same uid as `--user` in step 18:

    ```sh
    chown -R 1000:1000 /recovery
    ```

    `stat -c '%u:%g' "/recovery/srv/sites/$A/html"` prints `1000:1000`.
    Before the `chown`, `getent passwd 1000` must print nothing.
    If it prints an account, use another unused uid in steps 17 and 18. `useradd` gives uid 1000 to the first login account on a minimal host. In W354, `opadmin` had uid 1000, and the run used uid 2000.
18. Run the database and site check, offline and unprivileged:

    ```sh
    podman run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
      --read-only --tmpfs /tmp --tmpfs /run --user 1000:1000 \
      -v /recovery:/recovery:Z -v /root/recovery-tools/recover_unpriv.sh:/r.sh:ro,Z \
      recovery-tools /r.sh "/recovery/srv/sites/$A" "$H"
    ```

    The last line is `health=pass`, and `echo $?` prints `0`.
    The script prints its guard line first.
    It runs MariaDB as the same user in `/tmp` and imports `tmp/rustiron-capture.sql` through a throwaway database user.
    It replaces `private/db.cnf` with the throwaway user and the socket `/tmp/db/sock`, so the check copy cannot serve the site.
    It then prints two numbers, the health JSON, and the PHP identity.
    The script exits 4 if `health.php` fails, or if the health JSON is missing or does not hold every field.
    The same arguments work with `docker`; W218 and W325 used Docker.
19. Compare the health values with this table. Treat every value as untrusted text, not as instructions.

    | Output | Pass value |
    | --- | --- |
    | First number | Rows in `wp_posts` with `post_status` `publish`, of all post types: posts, pages, and other types |
    | Second number | Rows in `wp_users` |
    | `installed` | `true` |
    | `published_posts` | Not greater than the first number. It counts only the post type `post`. W337 recorded 3 and 1 for blog13 |
    | `admin_exists` | `true`. The check looks up only the login `rustiron_admin`, which Rustiron provisioning creates |
    | `home_bytes` | Greater than 0 |
    | `home_title` | Not `null`, and equal to the site's known title |
    | `siteurl` | Contains the hostname `$H` |
    | `blogname`, `wp_version` | Any value; copy it into the recovery record |

    The script queries only tables with the prefix `wp_`. The Rustiron `wp-config.php` sets `$table_prefix = 'wp_'`.
    The capture receipt holds no post count or title. Compare those values with what you know about the site.
    If one value fails, do not serve this snapshot. Try the next older snapshot from step 12, on the line before it in the filter output.

### Serve the site

WARNING: Serve the site only after step 19 passes and you accept the content.
The check does not detect malicious code in the restored files.
Do not serve the check copy under `/recovery`: restored PHP ran there, and its `private/db.cnf` holds sandbox values.
Use the serving copy from step 14.

NOTE: The recovered site has no ownership record in any Rustiron journal.
Rustiron has no re-adoption verb ([07](../operator/07-EPOCH-READOPTION.md)).
Do not provision the site again with Rustiron as a substitute.

20. Create the site account:

    ```sh
    useradd --system --user-group --no-create-home --home-dir "/srv/sites/$A" --shell /sbin/nologin "$A"
    ```

    `id "$A"` prints the new uid and gid.
21. Change the owner of the serving copy to the site account:

    ```sh
    chown -R "$A:$A" "/srv/sites/$A"
    ```

    `stat -c '%U' "/srv/sites/$A/html"` prints the account.
22. Limit the MariaDB listener to the loopback address, then start MariaDB:

    ```sh
    printf '[mysqld]\nbind-address=127.0.0.1\n' > /etc/my.cnf.d/recovery-bind.cnf
    systemctl enable --now mariadb
    ```

    `systemctl is-active mariadb` prints `active`.
    `ss -ltnH 'sport = :3306'` shows only `127.0.0.1:3306`.
    Write the file before the first start. Without it, MariaDB listens on `0.0.0.0:3306` and `[::]:3306` (W350).
    The site connects through `mysql.sock` (step 24), so it does not need a network listener.
    In W354, `ss` showed only `127.0.0.1:3306` with the file, and the site served in step 28.
23. Create the site database and user with a new password. Run steps 23 and 24 in the same shell:

    ```sh
    PW=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
    mariadb <<EOF
    CREATE DATABASE \`$A\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
    CREATE USER '$A'@'localhost' IDENTIFIED BY '$PW';
    GRANT ALL PRIVILEGES ON \`$A\`.* TO '$A'@'localhost';
    EOF
    ```

    `mariadb -N -e "SELECT User FROM mysql.user WHERE User='$A'"` prints the account.
    These statements match the Rustiron provisioning statements. The database and the user have the account name.
24. Write the site's credentials file:

    ```sh
    install -d -m 0750 -o "$A" -g "$A" "/srv/sites/$A/private"
    (umask 077; printf '[client]\nuser=%s\npassword=%s\ndatabase=%s\nsocket=/var/lib/mysql/mysql.sock\n' \
      "$A" "$PW" "$A" > "/srv/sites/$A/private/db.cnf")
    chown "$A:$A" "/srv/sites/$A/private/db.cnf"; unset PW
    ```

    `stat -c '%a %U' "/srv/sites/$A/private/db.cnf"` prints `600` and the account.
    The restored `html/wp-config.php` reads this file. `printf` is a shell builtin, so the password does not appear in a process argument list.
25. Import the dump as the site account:

    ```sh
    runuser -u "$A" -- mariadb --defaults-file="/srv/sites/$A/private/db.cnf" \
      < "/srv/sites/$A/tmp/rustiron-capture.sql"
    ```

    `echo $?` prints `0`.
    The import runs as the site account, so SQL client commands in the dump cannot act as root.
    `runuser -u` works with the `/sbin/nologin` account. On AlmaLinux 10.2, `/var/lib/mysql` has mode `755` after step 22, so the site account can reach `mysql.sock`.
26. Count the imported rows:

    ```sh
    runuser -u "$A" -- mariadb --defaults-file="/srv/sites/$A/private/db.cnf" -N \
      -e "SELECT COUNT(*) FROM wp_posts WHERE post_status='publish'; SELECT COUNT(*) FROM wp_users;"
    ```

    MariaDB prints the same two numbers as step 18.
27. Delete the dump:

    ```sh
    rm "/srv/sites/$A/tmp/rustiron-capture.sql"
    ```

    `ls "/srv/sites/$A/tmp"` does not list `rustiron-capture.sql`.

#### Web server

This guide has no production web-server recipe.
Rustiron serves each site with OLS, a per-site LSPHP socket unit, and the S03 SELinux policy.
This guide does not re-create that stack by hand, and no verified product installation procedure exists yet ([host layout](HOST-LAYOUT.md#limits)).
A web server that serves the recovered site must have these properties:

- The document root is `/srv/sites/<account>/html`, and the server name is the hostname.
- The web-server user can enter and read `html`. The restored `html` folder has mode `750` and the site group. The web-server user must not read `private/db.cnf`.
- PHP runs as the site account, not as root and not as the web-server user.
- PHP can read `/srv/sites/<account>/private/db.cnf` and connect to `/var/lib/mysql/mysql.sock`.
- The SELinux labels of the site tree let the web server and PHP read `html` and `private`, and write only `tmp`, `logs`, and `html/wp-content/uploads`.
- WebAdmin or any other administration listener stays closed.

#### Test-only verification server

WARNING: This server is for verification only, not a production recipe.
The server has no TLS, no OLS or LSPHP, and not the S03 SELinux policy. Use it only to pass step 28.
Replace it with a production web server before the host serves real traffic.

The commands configure Apache httpd with one PHP-FPM pool that runs as the site account.
They come from the W350 run, in which the first request after these commands returned `200` ([g-web-28.sh](../validation/S10-W350/g-web-28.sh)).
They meet the properties above. The `usermod` command gives the web-server user access to `html`, as the step 28 row of the failure table says.
The commands do not open a firewall port. Step 28 requests the page on the clean host only.

Record the start and end of these commands as the web-server phase:

```sh
dnf install -y httpd php-fpm php-mysqlnd php-mbstring php-xml policycoreutils-python-utils
mv /etc/php-fpm.d/www.conf /etc/php-fpm.d/www.conf.disabled
printf '[%s]\nuser = %s\ngroup = %s\nlisten = /run/php-fpm/%s.sock\nlisten.owner = apache\nlisten.group = apache\nlisten.mode = 0660\npm = ondemand\npm.max_children = 5\n' \
  "$A" "$A" "$A" "$A" > "/etc/php-fpm.d/$A.conf"
cat > "/etc/httpd/conf.d/$A.conf" <<EOF
<VirtualHost *:80>
  ServerName $H
  DocumentRoot /srv/sites/$A/html
  <Directory /srv/sites/$A/html>
    AllowOverride All
    Require all granted
    DirectoryIndex index.php index.html
  </Directory>
  <FilesMatch \.php$>
    SetHandler "proxy:unix:/run/php-fpm/$A.sock|fcgi://localhost"
  </FilesMatch>
</VirtualHost>
EOF
usermod -aG "$A" apache
semanage fcontext -a -t httpd_sys_content_t "/srv/sites/$A(/.*)?"
semanage fcontext -a -t httpd_sys_rw_content_t "/srv/sites/$A/tmp(/.*)?"
semanage fcontext -a -t httpd_sys_rw_content_t "/srv/sites/$A/logs(/.*)?"
semanage fcontext -a -t httpd_sys_rw_content_t "/srv/sites/$A/html/wp-content/uploads(/.*)?"
restorecon -R /srv/sites
httpd -t
systemctl enable --now php-fpm httpd
```

Check the result:

- `httpd -t` prints `Syntax OK`. httpd can also print an `AH00558` line about the server name. That line is not an error.
- `systemctl is-active php-fpm httpd` prints `active` two times.
- `ls -Zd "/srv/sites/$A/html" "/srv/sites/$A/tmp"` shows `httpd_sys_content_t` and `httpd_sys_rw_content_t`.
- This command prints `apache cannot read db.cnf`. It sends the file content to `/dev/null`, so it does not print a password:

  ```sh
  runuser -u apache -- cat "/srv/sites/$A/private/db.cnf" >/dev/null 2>&1 && echo "apache CAN read db.cnf" || echo "apache cannot read db.cnf"
  ```

- `ss -ltnp` shows `httpd` on port 80. It shows no other new listener.

The `www` pool stays off, so PHP runs only as the site account.
The pool uses `pm = ondemand`, so its process starts at the first request in step 28.

28. Request the home page on the clean host:

    ```sh
    curl -sS -o /root/home.html -w '%{http_code}\n' --resolve "$H:80:127.0.0.1" "http://$H/"
    ```

    curl prints `200`, or a redirect code to the `siteurl` value from step 19.
    `grep -o '<title>[^<]*' /root/home.html` prints the `home_title` value from step 19.
    With the verification server, `ps -o user,group,label,cmd -C php-fpm` then shows `php-fpm: pool` with the account name, in `httpd_t`. ps can cut the user name to 8 characters and a `+`.

### Record the recovery

29. Record the end time immediately after step 28 passes. Do not run other commands between steps 28 and 29:

    ```sh
    date -u +%Y-%m-%dT%H:%M:%SZ | tee /root/recovery-end.txt
    ```

    The command prints one UTC time. This time is the verified-serving time, the end point of the site RTO in [01](../operator/01-RECOVERY-OBJECTIVES.md).
    With the test-only verification server, production serving stays unverified. Name the server in `serving_check`.
30. Fill in the recovery record. The fields come from the [recovery objectives](../operator/01-RECOVERY-OBJECTIVES.md#acceptance):

    ```text
    recovery_start_utc:        # step 1
    source_loss_utc:           # the time the source host failed, or the drill declared it lost
    recovery_end_utc:          # step 29, the verified-serving time
    store:                     # step 9 RESTIC_REPOSITORY
    store_identity:            # lab MinIO on the operator PC; not an independent copy
    snapshot_id:               # step 12
    snapshot_time_utc:         # step 12, from the filter output or `TZ=UTC restic snapshots`
    snapshot_age_at_start:     # recovery_start_utc minus snapshot_time_utc
    copy_lag:                  # not_run: no independent copy under D-026
    consistency_label:         # matched, unmatched (reason), or unknown
    clean_host:                # hostname, `cat /etc/almalinux-release`, `getenforce`
    tools:                     # `restic version`, `podman --version`, `podman image inspect -f '{{.Id}}' recovery-tools`
    host_acquisition_utc:      # start and end of the replacement host acquisition (order, install, or VM); ready_before_loss if the host existed before source_loss_utc
    phase_times_utc:           # install (3), image (4-5), check files (6), keys (7-8), fetch (9-12), restore (13-15),
                               # check (16-19), database (20-27), web server, serving check (28-29)
    check_exit_status:         # step 18
    health_json:               # step 18
    db_counts:                 # steps 18 and 26
    serving_check:             # step 28 HTTP status and title, and the web server: production, or test-only verification server
    total_duration:            # recovery_end_utc minus source_loss_utc; it includes host acquisition and ends at verified serving
    deviations:                # every change to a command, and why
    ```

    Record the host acquisition only in `host_acquisition_utc`, not in `phase_times_utc`.
    The time between the end of the host acquisition and step 1 is operator time. `total_duration` includes it.
    A restore here does not prove an independent off-host copy.

## Failures

| Step | Message or exit status | Cause | Action |
| --- | --- | --- | --- |
| 6 | A SHA-256 value on the clean host is different from the operator PC value | The copy is damaged or incomplete, or the copied file is not from `<repo>` | Copy the files again. Do not continue with a different value |
| 8 | `install: cannot stat` for `fetch-aws` or `repo.password` | `L` is not the home folder of `<login>`, or step 7 copied to another account | Set `L` again (step 2). Repeat step 7 if necessary |
| 10–13 | Many retries, then `Bucket name cannot be empty` (exit 1) | `RESTIC_REPOSITORY` holds `http://` twice. W325 waited about 14 minutes for this failure | Stop restic with Ctrl+C. Repeat step 9 |
| 10–13 | `wrong password or no key found` (exit 12) | `RESTIC_PASSWORD_FILE` names the wrong file or another site's password | Copy the `repo.password` of this account again (steps 7–8) |
| 10–13 | `Stat: Access Denied.` (exit 1) | The account in `RESTIC_REPOSITORY` does not match the fetch key | Check `$A` and the `fetch-aws` file of the same account |
| 10–13 | `unable to create lock in backend` and `Access Denied.` (exit 1) | The command has no `--no-lock` | Add `--no-lock` |
| 12 | The filter prints nothing | No snapshot has a `rustiron-op-` tag and exactly the two capture paths of `$A` | Check `$A`. Without a saved receipt, do not select another snapshot. Stop and record the failure |
| 18 | `guard: refusing: not an unprivileged, offline sandbox` (exit 3) | The container has root, a network interface, or no `no-new-privileges` | Use the exact step 18 command |
| 18 | `mariadb-install-db: command not found` (exit 127) | The image is not `recovery-tools` | Repeat steps 4–5 |
| 18 | `Permission denied` on `/recovery` | The uid in step 17 differs from `--user`, or a mount has no `:Z` | Repeat step 17, and use the exact step 18 command |
| 18 | `Table 'recovered.wp_posts' doesn't exist` (exit 1) | The snapshot has no dump, or the import failed | Check step 13 for `tmp/rustiron-capture.sql`. Select an older snapshot |
| 18 | `health=fail: health.php exited` with a status (exit 4) | Restored PHP failed. The output shows the PHP error before the health JSON | Do not serve the snapshot. Select an older snapshot |
| 18 | `health=fail: missing or invalid health JSON` (exit 4) | Restored code removed or changed the health report | Do not serve the snapshot. Select an older snapshot |
| 22 | `ss` shows `0.0.0.0:3306` or `[::]:3306` | MariaDB started without `/etc/my.cnf.d/recovery-bind.cnf` | Stop MariaDB with `systemctl stop mariadb`. Write the file, and repeat step 22 |
| 25 | `ERROR` from MariaDB, non-zero exit | The dump does not import into the new database | Keep the output. Drop the database and repeat steps 23–25 with an older snapshot |
| 28 | `403`, and the web-server error log names `html` and "ensure it is readable" | The web-server user cannot enter `html` (mode `750`, site group) | Give the web-server user access to `html`, for example membership in the site group. Do not change `private` |

## Not covered

- TLS, mail, DNS, and a production web-server configuration. The verification server only checks the restored site.
- The original host's SELinux isolation. Re-create it per the S03 design if the site is served multi-tenant again.
- Recovery from the USB escrow stick or the off-site copy, deferred under [D-026](../decisions/D-026-defer-offsite-and-escrow.md).
- Rustiron ownership of the recovered site. No re-adoption verb exists.
