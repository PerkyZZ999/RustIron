# WordPress plugin and theme update

This procedure updates plugins and themes ([D-084](../decisions/D-084-wordpress-update.md)) or WordPress core ([D-086](../decisions/D-086-wordpress-core-update.md)) of one managed WordPress site through a signed `site_update`. WordPress cannot update itself: its code is read-only to its PHP, and its PHP has no network. [W518](../validation/S10-W518/README.md) rehearsed it on a lab host.

## Before you start

- The site is served and not ejected, and the product store is enrolled for it ([page 10](10-PRODUCT-STORE-ENROLLMENT.md)).
- The host has the root-only folder `/var/lib/rustiron/update-intake` (mode 0700). A fresh installation makes it. On a host updated from an earlier build, make it once: `install -d -o root -g root -m 0700 /var/lib/rustiron/update-intake`.
- Each component to update is installed at the version you name as its from-version.

## Find and prepare updates

Rustiron runs no update on its own ([D-087](../decisions/D-087-prepared-wordpress-updates.md)): each update is signed. These two steps find what is pending and prepare it.

1. On the host, read the site's installed versions. Nothing is changed or recorded. Keep the admin helper running. Write the report through `cat`: SELinux refuses PID 1 a file in root's home that `--pipe` would hand it directly:

   ```sh
   systemctl stop rustiron-coordinator.service rustiron-executor.service
   systemd-run --wait --pipe --quiet /usr/libexec/rustiron/rustiron-executor update-inventory SITE_ID --admin-helper | cat > inventory.json
   systemctl start rustiron-executor.service rustiron-coordinator.service
   ```

2. On the operator PC, compare it with WordPress.org. Each line names a component with `state` `update` (and its `to` version), `current`, or `unknown` (WordPress.org does not serve it, for example a premium plugin). A newer core branch is shown as `newer_branch` and is never prepared: a branch change is your decision.

   ```sh
   python3 -I packaging/wordpress-update-watch.py inventory.json
   ```

3. To prepare them, add `--fetch OUTDIR`. The tool downloads each newer release with its checksums and writes `OUTDIR/core` and `OUTDIR/extensions`, each with `recipe.tar`, `recipe_digest`, and `components.txt` (the plan's components in order). Continue with [Run the update](#run-the-update) for each folder.

## Prepare the recipe (operator PC)

1. Download each release archive from `downloads.wordpress.org`, for example `https://downloads.wordpress.org/plugin/akismet.5.7.2.zip` or `https://downloads.wordpress.org/theme/twentytwentyfour.1.6.zip`. For a plugin, also download its checksum list, `https://downloads.wordpress.org/plugin-checksums/akismet/5.7.2.json`.
2. Build the recipe. The tool needs no network and refuses anything it cannot check:

   ```sh
   python3 -I packaging/wordpress-update-recipe.py OUTDIR \
       --plugin akismet 5.7.2 akismet.5.7.2.zip akismet.5.7.2.json \
       --theme twentytwentyfour 1.6 twentytwentyfour.1.6.zip
   ```

   It prints `recipe_digest`, then the manifest. Plugins come first, then themes, each in the order you gave. The plan must name the components in that order.

3. For WordPress core, download `https://wordpress.org/wordpress-<version>.zip`, its SHA-1 `https://wordpress.org/wordpress-<version>.zip.sha1`, and its checksum list `https://api.wordpress.org/core/checksums/1.0/?version=<version>&locale=en_US`. A core update names core only:

   ```sh
   python3 -I packaging/wordpress-update-recipe.py OUTDIR \
       --core 7.1.4 wordpress-7.1.4.zip wordpress-7.1.4.zip.sha1 core-7.1.4.json
   ```

   The plan's component is `core` `wordpress` with the installed version as from-version. The site's `wp-content` is not touched; update the bundled themes and plugins as themes and plugins.

## Run the update

The update copies the recipe into the site's `tmp` and unpacks the new code beside the old, so the site's quota needs room for both: about twice the release. A core release is about 95 MB. When the room is short, the Unpack step fails before it writes anything, and the helper logs `quota_headroom` with the need and the room.

To give a site more room, sign a `site_quota` change ([D-088](../decisions/D-088-site-quota-change.md)) with its new hard block limit in KiB and inode limit. Both must be at most the enrolled cap and above the site's current use, which `repquota -u /srv/sites` shows. `rustiron-plan inspect` shows both limits. The result is `succeeded` with the limits set and read back, or `failed` with the quota unchanged and the reason in `journalctl -u rustiron-admin-helper` (`site_quota`). `quota-status OPERATION` prints a change; an open one is set again with `quota-reconcile OPERATION --admin-helper`, with the coordinator and executor stopped as for an open update.


1. Take a signed `backup_capture` of the site. The update must name it, and it must be the site's newest succeeded capture from the last hour.
2. Copy `OUTDIR/recipe.tar` to the host as root, without any group or other access: `/var/lib/rustiron/update-intake/<site_id>/recipe.tar` (folder 0700, file 0600).
3. Sign and submit the `site_update` plan. `rustiron-plan inspect` shows each component with both versions. Read them before signing.
4. Read the result:

| State | Meaning |
| --- | --- |
| `succeeded` | Every component is at its new version, and the site answered its marker, login, and home page. The old folders are removed. For core, WordPress's database upgrade has run, and visitors saw its maintenance page during the swap |
| `failed_compensated` | A step failed. The old code is back, and, if any folder had been swapped, the database came back from the capture. Writes since the capture are lost. Read `journalctl -u rustiron-admin-helper` for the `admin_helper_step` and `site_update` lines |
| `intent` | The update is open: a rollback could not be verified. The site takes no other update until it is settled |

## Settle an open update

Stop the coordinator and the executor; keep the admin helper running. Then run the rollback again:

```sh
systemctl stop rustiron-coordinator.service rustiron-executor.service
systemd-run --wait --pipe --quiet /usr/libexec/rustiron/rustiron-executor update-reconcile OPERATION --admin-helper
systemctl start rustiron-executor.service rustiron-coordinator.service
```

It records an open step as failed and runs the rollback again: the code, and the database when the Swap step had begun. The output is the update's record. `rolled_back` is settled. If it stays `intent`, read the helper lines, correct the cause (for example the store), and run it again. `update-status OPERATION` prints the record without changing it, also with the executor stopped.

## Limits

- A component's files may use letters, digits, and `. _ - @ , + ~`. A release with other characters in a file name, such as a space, is refused.
- A table that new code created and the capture lacks stays after a rollback.
- A root file that an old core release had and the new one lacks stays in the site root.
