# OLS package upgrade

Updated: 2026-11-13, America/Toronto.
This procedure upgrades, downgrades, or reinstalls the `openlitespeed` package on an enrolled product host.
It also restores the Rustiron parent configuration after a change.
[W389](../validation/S10-W389/README.md) is the lab evidence. [D-038](../decisions/D-038-ols-parent-start-condition.md) is the start condition.

Run each command as root in the root shell of the host.

## What the package does

- The package marks `/usr/local/lsws/conf/httpd_config.conf` as `%config(noreplace)`. When the package parent changes, `rpm` writes `httpd_config.conf.rpmnew` and keeps the Rustiron parent.
- The immutable flag on the parent refuses each write, owner change, and rename. The package scriptlet ignores the refused `chown`.
- The package writes `/usr/lib/systemd/system/lshttpd.service` and the alias `lsws.service` again. The package does not change the Rustiron drop-ins in `/etc/systemd/system/lshttpd.service.d/`.
- After each change, the package restarts `lshttpd` (`systemctl restart lsws`). The sites do not answer for less than 1 s. In W389, each outage was 0.16 to 0.57 s.
- The package does not change `/etc/rustiron-ols`. The last-known-good generation stays `current`.

## Before the change

1. Make sure that no OLS operation is unresolved. Use `rustiron-executor status OP` for the last activation. Do not change the package while an activation runs.
2. Record the facts:

   ```sh
   rpm -q openlitespeed
   lsattr /usr/local/lsws/conf/httpd_config.conf
   sha256sum /usr/local/lsws/conf/httpd_config.conf /usr/share/rustiron/ols/httpd_config.conf
   readlink /etc/rustiron-ols/current
   systemctl show -p DropInPaths -p KillMode -p ActiveState lshttpd.service
   ```

   The flag list shows `i`. Both digests are the same, and they are the `ols.parent_sha256` value of the enrollment.
3. Check the OLS state. `ols-status` needs the journal writer lock, so stop the coordinator and the executor for it:

   ```sh
   systemctl stop rustiron-coordinator.service rustiron-executor.service
   systemd-run --wait --pipe --quiet /usr/libexec/rustiron/rustiron-executor ols-status --admin-helper
   systemctl start rustiron-executor.service rustiron-coordinator.service
   ```

   The result shows `"clean":true` and `"parent_reviewed":true`.
4. If a site has the cache-on recipe ([turn the page cache on](15-PAGE-CACHE-ON.md)), the target version must be a tested one: `1.9.4` ([D-052](../decisions/D-052-page-cache-ols-versions.md)). `cat /usr/local/lsws/VERSION` shows the installed version. On another version, unlocked visitors of a password-protected post get the cached public page ([W426](../validation/S10-W426/README.md)). Opt each such site out first, or do not make the change.

## Change the package

1. Run the change, for example `dnf upgrade openlitespeed`. To install a given build, name it: `dnf downgrade openlitespeed-1.9.4-1.el10`.
2. A line `warning: /usr/local/lsws/conf/httpd_config.conf created as /usr/local/lsws/conf/httpd_config.conf.rpmnew` is expected when the package parent changed.
   Do not copy the `.rpmnew` file over the parent. Rustiron does not read it. A new Rustiron parent comes only from a new Rustiron build.
3. Do not remove the immutable flag, and do not run `lswsctrl` directly.

## After the change

1. Do the checks of [Before the change](#before-the-change) again. The digests, the flag, `current`, and the drop-ins are the same as before. `lshttpd` is `active`, and `KillMode` is `mixed`.
2. Make sure that ports 7080 and 8088 do not listen: `ss -ltn | grep -E ':(7080|8088) '` prints nothing.
3. Request each site through the listener. Each site answers as before.
   With a cache-on site, `ols-status` shows `"page_cache_ols_tested":true`. With `false`, Rustiron refuses each activation that serves a cache-on site; an eject and an opt-out still run.
4. Read the denials since the change: `ausearch --input-logs -m AVC,USER_AVC,SELINUX_ERR -ts recent`.

## Restore a changed parent

The parent changes only when a root user removes the immutable flag.
These facts show a changed parent:

- `ols-status` shows `"parent_reviewed":false`.
- An activation ends `untouched` with the error `OLS_DRIFT` (exit 4). It changes nothing, and nothing needs settlement. Send the activation again with a new operation ID after the restore.
- After a restart, `lshttpd` is `inactive`, and the unit journal shows `Skipped due to 'exec-condition'` (D-038).

Do these steps:

1. Write the shipped parent next to the parent, then rename it over the parent:

   ```sh
   P=/usr/local/lsws/conf/httpd_config.conf
   chattr -i $P
   install -o root -g root -m 0644 /usr/share/rustiron/ols/httpd_config.conf $P.rustiron-new
   mv -f $P.rustiron-new $P
   restorecon -v $P
   chattr +i $P
   ```

2. Check the result. The owner is `root:root`, the mode is 0644, the label type is `usr_t`, and the flag list shows `i`. The digest is the `ols.parent_sha256` value of the enrollment.

   ```sh
   stat -c '%U:%G %a %h' $P; ls -Z $P; lsattr $P; sha256sum $P
   ```

3. Restart OLS: `systemctl restart lshttpd.service`. Then do the checks of [After the change](#after-the-change).
4. If the enrollment digest is not the digest of `/usr/share/rustiron/ols/httpd_config.conf`, stop. The installed build is not the enrolled one. Do not start OLS.

## Limits

- The start condition compares bytes only. The executor review also checks the owner, the mode, the link count, and the flag.
- A reload does not run the start condition. Do not reload OLS while the parent differs.
- W389 tested `openlitespeed` 1.9.2-3, 1.9.3-1, and 1.9.4-3 from the LiteSpeed repositories for EL10. Another build can have other scriptlets. Read `rpm -q --scripts openlitespeed` of a new build first.
