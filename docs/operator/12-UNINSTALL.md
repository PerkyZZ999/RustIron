# Uninstall the product

This page tells the operator how to remove a Rustiron product installation from an AlmaLinux 10 host.
The tool is [packaging/uninstall-product.py](../../packaging/uninstall-product.py). It removes only what [packaging/install-product.py](../../packaging/install-product.py) installed.
[W385](../validation/S10-W385/README.md) records the rehearsal on a product host.
[W387](../validation/S10-W387/README.md) records a full uninstallation that keeps an ejected site serving ([D-037](../decisions/D-037-independent-eject.md)).

## What the uninstaller reads

The installer writes `/var/lib/rustiron/install-record.json` before the first payload file.
The record names each installed file with its SHA-256 and mode, and each folder that the installer made.
It also names the state folders, the policy modules, and the identities.
The record also holds the bytes digest, owner, mode, and SELinux type of the package OLS parent.

The uninstaller acts only on the paths, units, modules, and identities of the record and of the product layout.
It refuses before the first change when one of these facts is true:

- A recorded file has other bytes, another owner, another mode, or more than one link.
- An installed folder holds an entry that the installation did not make.
- A unit folder holds a `rustiron-*` path of an unknown kind. The known kinds are the recorded units, the site PHP drop-ins and enable links, and the enrollment drop-in of the admin helper.
- A local SELinux label names a Rustiron type that the uninstaller does not know.
- The journal holds an unresolved operation.
- The Rustiron include serves a site that stops serving with the parent choice, and the operator did not acknowledge it.

The command prints every refusal reason with `REFUSED` and exits with status 1.
On a host without the record, `install-product.py` did not install the product. The uninstaller refuses that host.

## Choose the OLS parent

The command has no default for the OLS parent. Choose one of the two values.

| `--ols-parent` | OLS parent after the run | Sites | Use it when |
| --- | --- | --- | --- |
| `keep` | The Rustiron parent stays, without the immutable flag | Each site that the Rustiron include serves keeps serving | The sites must stay online, and no Rustiron management must stay |
| `package` | Without ejected sites: the package parent comes back with its bytes, owner, mode, and SELinux type, and `lshttpd.service` stays stopped. With ejected sites: the standalone parent, and `lshttpd.service` runs | Only the ejected sites are served | No Rustiron file, unit, module, or account must stay |

### Ejected sites

`site_eject` makes a site independent of Rustiron ([D-037](../decisions/D-037-independent-eject.md)).
The ejected site uses its standalone vhost in `/etc/rustiron-ejected/<account>/vhost.conf`. OLS starts PHP for a WordPress site as the site account. A standalone static vhost has scripting disabled. The site's Rustiron PHP units are stopped and disabled.

WARNING: An ejected site has no Rustiron isolation. Its PHP runs in the OLS domain `unconfined_service_t`, with no per-site SELinux category, no PHP unit sandbox, no network refusal, and no cgroup limit. Only the site account and the OLS rlimits separate it. See [Isolation after eject](../decisions/D-037-independent-eject.md#isolation-after-eject).

An ejected site needs no acknowledgement flag with `keep` or with `package`.
A site that an eject before W387 made still uses the Rustiron PHP unit. With `package`, that site needs `--unserve-sites`, and the uninstaller prints the reason.

### What keeps serving with `keep`

With `keep`, the Rustiron include serves each site. A site that is not ejected still needs the Rustiron site PHP units.
`keep` leaves these items in place:

| Item | Path or name |
| --- | --- |
| OLS parent | `/usr/local/lsws/conf/httpd_config.conf`, the shipped bytes |
| Listener and virtual hosts | `/etc/rustiron-ols/current` and its generations |
| Vhost files of ejected sites | `/etc/rustiron-ejected/<account>/vhost.conf` |
| Installed certificate chains | `/etc/rustiron-tls` (the include's TLS listener names them; nothing renews them after the run) |
| Site PHP unit templates | `rustiron-site-php@.service`, `rustiron-site-php@.socket`, `rustiron-site-sandbox-check@.service`, `rustiron-site-sandbox-check@.timer` in `/etc/systemd/system` |
| Site PHP drop-ins and enable links | `rustiron-site-php@<account>.service.d`, the enabled socket and timer of each site |
| Sandbox check | `/usr/libexec/rustiron/check-site-sandbox` |
| Policy modules | `rustiron_php`, `rustiron_admin`, `rustiron_executor`, and the port label `rustiron_ols_port_t` of the listener |
| Package parent copy | `/var/lib/rustiron/ols-package/httpd_config.conf` and a reduced install record |

The `rustiron_php` module needs a type of `rustiron_admin`. The modules `rustiron_admin` and `rustiron_executor` need types of each other. Thus the three modules stay together.
The reduced record names only these items. A later run with `--ols-parent package` removes them.

`keep` removes both `lshttpd.service` drop-ins. The package unit then has `KillMode=none`.
After `systemctl stop lshttpd.service`, the old OLS processes can serve for a short time. In W385, the listener closed about 2 s after the stop.

### What comes back with `package`

Without ejected sites, the package parent comes back.
The package parent of openlitespeed 1.9.4 opens WebAdmin on port 7080 and the Example listener on port 8088.
The uninstaller leaves `lshttpd.service` stopped. The package keeps the unit enabled, so OLS starts with the package parent at the next boot.

NOTE: `openlitespeed -t` gives exit status 1 for the package parent. The output has 2 `WARN` lines for the Example virtual host. OLS starts with that parent (W385). The uninstaller prints the status and continues.

### The standalone parent with `package`

When the include serves ejected sites, the uninstaller does these steps instead of the package parent restore:

1. It copies each standalone vhost to `/usr/local/lsws/conf/vhosts/<account>/vhconf.conf`, with the owner and mode of the package parent, and resets the SELinux labels.
2. It writes the standalone parent to `/usr/local/lsws/conf/httpd_config.conf`, with the owner, mode, and SELinux type of the package parent and no immutable flag.
   The standalone parent has the server settings of the Rustiron parent without its comments and include line. WebAdmin stays disabled.
   The standalone parent has one `virtualHost` for each ejected site and the listener of the include, with the same name and address.
3. After the removal, it starts `lshttpd.service`. It checks each ejected site's identity marker and requires the PHP login page for WordPress. For a site with a certificate, the HTTP listener may redirect the marker to the same name over HTTPS. The HTTPS listener must then answer with the marker and the login page, pinned to the handed-over leaf ([W511](../validation/S10-W511/README.md)).

#### Ejected sites with a certificate

An ejected site keeps HTTPS with its installed chain ([D-064](../decisions/D-064-eject-certificate.md)). With `package`, the uninstaller hands the chain over:

1. It copies `/etc/rustiron-tls/<account>/live/fullchain.pem` and `key.pem` into `/usr/local/lsws/conf/vhosts/<account>/`. The key is root-only (mode 0600).
2. The copied `vhconf.conf` names those copies in its `vhssl` block.
3. The standalone parent gets the TLS listener of the include, with the same name and address, and maps each such site. Its default certificate is the first site's copy.
4. `/etc/rustiron-tls` and `/var/lib/rustiron-acme` (the certbot account) move into the archive. `certbot-renew.timer` is unmasked. It returns to the package state: the package preset enables it, and it starts at the next boot. It renews only lineages in `/etc/letsencrypt`, which Rustiron never writes (W471).

The uninstaller refuses when such a site's `live` link or files are missing.
After the run, renew the certificate yourself before it expires, for example with certbot and a deploy hook that copies the new files and reloads OLS.

The [D-077 disposable lab scope](../decisions/D-077-alias-certificate-scope.md#independent-eject-on-the-disposable-lab) also covers a certified static primary and alias. Both names stay on their original loopback listeners. The uninstaller checks the installed chain digest, then probes both HTTP names and both HTTPS names with the copied leaf pinned. The standalone static vhost has scripting disabled.

For the [D-097 single-name lab form](../decisions/D-097-eject-static-single-name.md), package removal requires one HTTP map for the hostname in the standalone vhost. When the vhost has TLS, it also requires the same HTTPS map and verifies the installed chain and served leaf. Fixture verification is complete. The signed executor path and disposable guest rehearsal remain open. [W588 evidence](../validation/S10-W588/README.md)

The dry run prints the standalone parent and each copy with its SHA-256. Read them before `--apply`.
After the run, the operator owns the standalone parent and the vhost files. The package parent is in the archive, as `var/lib/rustiron/ols-package/httpd_config.conf`.
The listener stops for the time of the run. In W387, the stop to the first answer took less than one minute.

## Evidence and the archive

By default, the uninstaller moves the evidence into a new folder `/var/lib/rustiron-archive/uninstall-<UTC time>`. The folder and `/var/lib/rustiron-archive` have mode 0700 and belong to root.
The uninstaller deletes no evidence. It deletes two credentials before the move: the receipt private key ([D-042](../decisions/D-042-host-receipt-key.md)) and the alert push link ([D-083](../decisions/D-083-alert-delivery.md)).

| Evidence | `keep` | `package` |
| --- | --- | --- |
| `/etc/rustiron` (policy, signer list, revocations, job credentials) | Archived | Archived |
| Receipt private key `/etc/rustiron/receipt-key/ed25519` | Deleted before the archive move | Deleted before the archive move |
| Receipt public key `/etc/rustiron/receipt-key/ed25519.pub` | Archived | Archived |
| Alert push link `/etc/rustiron/alert-push.url` ([alert check-in](23-ALERT-CHECKIN.md)) | Deleted before the archive move | Deleted before the archive move |
| Journal, admission mark, recipes, capture manifests, scratch | Archived | Archived |
| Install record | Copied to the archive; the reduced record stays | Archived |
| Package parent copy | Stays | Archived after the restore, or after the standalone parent write |
| `/var/lib/rustiron-coordinator` | Archived | Archived |
| `/etc/systemd/system/rustiron-admin-helper.service.d` | Archived | Archived |
| `/etc/rustiron-ols`, `/etc/rustiron-ejected`, site PHP drop-ins | Stay | Archived |
| `/etc/rustiron-tls` (installed chains and keys) | Stays | Archived, after the hand-over copies |
| `/var/lib/rustiron-acme` (certbot account and lineages) | Archived | Archived |
| Local SELinux port and file context labels | Saved as `selinux-local-ports.txt` and `selinux-local-fcontexts.txt` | Saved |
| System journal `/var/log/journal` ([D-072](../decisions/D-072-persistent-journal.md)) | Stays; the journald drop-in is removed, so journald returns to `Storage=auto`, which keeps using the folder while it exists | Stays, as with `keep` |

The archive keeps the original paths below its folder, for example `etc/rustiron/policy.json`.
After the move, the uninstaller relabels the archive (`var_lib_t`) and writes 2 files:

- `MANIFEST`: one `sha256sum` line for each archived file.
- `METADATA`: the kind, owner, group, and mode of each archived entry.

To verify an archive, run:

```sh
cd /var/lib/rustiron-archive/uninstall-<UTC time> && sha256sum -c --quiet MANIFEST
```

The command prints nothing and exits with status 0 when every file matches.

WARNING: `--destroy-evidence` deletes the evidence instead. Without the job credentials, no one can open the backup repositories of the sites. Without the journal, no later re-adoption can prove ownership. The flag never changes site data.

NOTE: After the uninstallation, no one can sign a receipt for this installation. Check its receipts with the archived public key or with your off-host record of it: `python3 scripts/check_receipt.py RECEIPT.json --public-key ed25519.pub` ([W392](../validation/S10-W392/README.md)). A new installation makes a new key. Keep each public key with its installation dates.

NOTE: The archive keeps the numeric owner of the coordinator files. A later installation can give the same number to the new coordinator account. `METADATA` keeps the owner of the archive time.

## What the uninstaller never changes

- The site folders in `/srv/sites`, their files, quotas, and SELinux file context rules.
- The site accounts `rs_<site>` and their groups.
- The site databases and database users, and `mariadb.service`. It removes Rustiron's `/etc/my.cnf.d/zz-rustiron-loopback.cnf` with the payload; MariaDB keeps listening on loopback until its next restart, then returns to the distribution's default ([W569](../validation/S10-W569/README.md)).
- A non-empty `/srv/restore-probes`.
- The `/srv/sites` mount point that existed before the installation.

## Before you start

1. Settle each unresolved operation with the [after power loss](11-AFTER-POWER-LOSS.md) page. The uninstaller refuses an unresolved operation.
2. Eject each site that must keep serving without Rustiron. Use the `site_eject` verb with a signed request. Or, with `keep`, plan to pass `--leave-managed-sites`.
3. Get the source tree of the installed build. Run the uninstaller from that tree, as root.
4. If the `rustiron` firewall zone is the default, put `public` back with `python3 packaging/firewall-zone.py --restore --apply` ([page 28](28-FIREWALL-ZONE.md)). The uninstaller does not change the firewall.

## Uninstall

1. Print the plan:

   ```sh
   python3 packaging/uninstall-product.py --ols-parent keep
   ```

   The command changes nothing. The first line is `DRY RUN`. Each line after it names one fact or one action.
2. Read each line. `SERVES` names a site that keeps serving. `STANDALONE` names an ejected site that the standalone parent serves. `UNSERVED` names a site that stops serving. `TENANT` names a site folder that stays. `KEEP` names an item of the serving set. `ABSENT` names a recorded file that is missing. `STOP and DISABLE` names the units that stop: the management timers (scheduled capture, WordPress jobs, alert check-in) before the services, so no enabled timer outlives its service ([W511](../validation/S10-W511/README.md)).
3. If the plan has `REFUSED` lines, correct each cause, then do step 1 again.
4. Apply the plan:

   ```sh
   python3 packaging/uninstall-product.py --ols-parent keep --apply
   ```

   The command prints each action before it runs it. The last line is `PASS management removed; the serving set stays`.
5. Request a page of each site through its listener. For example, `curl -H 'Host: <host name>' http://127.0.0.1:<port>/`. Each site answers as before.
6. Verify the archive with `sha256sum -c` (see [Evidence and the archive](#evidence-and-the-archive)).

For `--ols-parent package`, add `--unserve-sites` when the include still serves a site that is not ejected.
Without ejected sites, the last line is `PASS uninstalled; lshttpd.service stays stopped with the package parent`.
With ejected sites, the last line is `PASS uninstalled; lshttpd.service serves <accounts> with the standalone parent`.

## Flags

| Flag | Effect |
| --- | --- |
| `--ols-parent keep` or `--ols-parent package` | Required. See [Choose the OLS parent](#choose-the-ols-parent) |
| `--leave-managed-sites` | With `keep`: accept that sites that are not ejected stay served by the Rustiron-rendered include |
| `--unserve-sites` | With `package`: accept that the sites of the Rustiron include that are not ejected stop serving |
| `--accept-unresolved` | Archive the journal with its unresolved operations. The operations stay unresolved in the archive |
| `--destroy-evidence` | Delete the evidence instead of the archive move |
| `--apply` | Act. Without it, the command prints the plan only |

## After a failed run

The uninstaller stops at the first failed action. It rolls nothing back. The lines before `FAILED` name the actions that ran.

- Correct the cause, then run the same command again. The next run reports files that are gone as `ABSENT`.
- If the package parent or the standalone parent is in place already, the next run reports `RESTORED` and resets its SELinux label.
- A standalone vhost copy of a failed run is accepted when it has the same bytes. Another folder with the account name in `/usr/local/lsws/conf/vhosts` is refused.
- The failed run can leave an archive folder without `MANIFEST`. Keep that folder. The next run makes a new folder.

## Install again on the same host

The installer accepts `/srv/sites` only as an empty mount point (W361). After an uninstallation, the old site folders are still there.

1. Move the old site file system away from `/srv/sites`, or keep it unmounted on its disk.
2. Mount a new empty XFS file system with `usrquota` at `/srv/sites` ([sites file system](09-PRODUCT-ENROLLMENT.md#sites-file-system)).
3. Install with `install-product.py` as before.
4. Enroll the host with a new host epoch ([product enrollment](09-PRODUCT-ENROLLMENT.md)).
5. Provision sites with new site IDs, because the old site accounts, databases, and file context rules hold the old IDs.

The new installation does not adopt the old sites. The archived journal stays in its archive.

NOTE: A new installation replaces the standalone parent with the Rustiron parent, and the ejected sites stop serving. `site_readopt` cannot take an ejected site back ([D-037](../decisions/D-037-independent-eject.md#reversibility)).

## Limits

- An ejected site keeps its site account, its local file context rules, and the files `rustiron-site.txt` and `private/rustiron-admin.txt` in its own folder. These items are site data.
- The kept include and the archive keep the numeric group of the deleted `rustiron-requesters` group. The files have no group write permission.
- The uninstaller does not stop or remove a store network namespace that is still present in `/run/netns`. A reboot removes it.
- `rustiron-ols-boot-guard.service` refuses a manual stop. After the removal, systemd lists it as `not-found` until the next boot.
