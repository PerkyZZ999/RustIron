# Break-glass: an emergency manual change

Updated: 2026-11-17, America/Toronto.
This procedure makes an emergency change on an enrolled product host by hand, when Rustiron cannot make it or must not run. It also returns the host to Rustiron management afterward.
[W472](../validation/S10-W472/README.md) is the lab rehearsal. Roadmap [P08](../planning/ROADMAP.md#p08--rehearse-operator-break-glass-eject-and-full-removal).

Run each command as root in the root shell of the host.

## What Rustiron does with a manual change

- Rustiron never resets a manual change. No timer, renewal, job, or boot step rewrites a managed file to undo it.
- Rustiron reports the change. For an OLS file, `ols-status` shows `"clean":false` and `"explained_by_journal":false`.
- Rustiron refuses the next signed OLS change while the drift stays. The refusal records nothing and changes nothing (exit 4, for example `PRECONDITION_CHANGED` or `OLS_DRIFT`).
- A change to the OLS parent is different. The boot guard does not start `lshttpd` with a changed parent (D-038). Do not edit the parent: use [restore a changed parent](14-OLS-UPGRADE.md#restore-a-changed-parent).

## Make the change

1. Stop the Rustiron management units. Websites keep serving.

   ```sh
   systemctl stop rustiron-site-cron.timer rustiron-coordinator.service rustiron-executor.service rustiron-admin-helper.service
   ```

   When the [alert check-in](23-ALERT-CHECKIN.md) is on, it reports the stopped units, and Kuma mails a `down` alert. Pause the monitor in Kuma first if you do not want that mail.

2. Keep a copy of each file before you change it, for example:

   ```sh
   G=$(readlink /etc/rustiron-ols/current)
   cp -a /etc/rustiron-ols/$G/rs_SITE.vhost /root/rs_SITE.vhost.before
   ```

3. Make the change. Then apply it with `systemctl restart lshttpd`. Do not run `lswsctrl`, and do not remove the immutable flag of the parent.
4. Check the sites: `curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: HOSTNAME' http://LISTENER/`.
5. Start the management units again, so that the observations and the backups continue. Start `rustiron-site-cron.timer` only when it was enabled before:

   ```sh
   systemctl start rustiron-admin-helper.service rustiron-executor.service rustiron-coordinator.service
   ```

## Check what Rustiron sees

`ols-status` needs the journal writer lock, so stop the coordinator and the executor for it:

```sh
systemctl stop rustiron-coordinator.service rustiron-executor.service
systemd-run --wait --pipe --quiet /usr/libexec/rustiron/rustiron-executor ols-status --admin-helper
systemctl start rustiron-executor.service rustiron-coordinator.service
```

While the change stays, the output shows `"clean":false`. Signed OLS changes are refused.

## Return to management

Choose one of these:

- **Undo the change.** When the emergency is over, put back each kept copy, run `restorecon -v` on the file, and run `systemctl restart lshttpd`. `ols-status` then shows `"clean":true` and `"explained_by_journal":true`. Signed OLS changes run again.
- **Keep the change outside Rustiron.** Eject the site ([D-037](../decisions/D-037-independent-eject.md)) after you undo the change. Then make the change in its standalone vhost. Rustiron no longer manages an ejected site.

Rustiron has no verb that accepts an unreviewed managed file as its own. A change that must stay under management needs a reviewed Rustiron change.
