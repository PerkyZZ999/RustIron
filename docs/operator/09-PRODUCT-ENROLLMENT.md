# Product host enrollment

This procedure takes a product host from "installed" to "enrolled".
After installation, the executor refuses every command with `EXECUTOR_NOT_ENROLLED` ([W347](../validation/S10-W347/README.md)).
After enrollment, the executor and the coordinator start in their domains, and the read-only checks work.
[W358](../validation/S10-W358/README.md) records the first run on a clean AlmaLinux 10.2 host.
[W361](../validation/S10-W361/README.md) records a second run with only the committed code.
In that run, the sites file system was mounted before the installation.

## Scope and authority

The procedure enrolls one host with schema 1 of `policy.json`: the host identity, one signer, provisioning with a quota, and the OLS listener.
The procedure does not enroll a backup destination. The product backup pin (schema 2) has its own [binding contract](../technical/PRODUCT-BACKUP-BINDING.md).
To enroll a product backup destination after this procedure, use [product store enrollment](10-PRODUCT-STORE-ENROLLMENT.md).

The signer is a trust decision:

- In the lab, the agent signer is `lab_agent` with signer-policy epoch `policy_3` (D-011). Its private key stays on the operator PC in `~/.config/rustiron-lab/agent-signing`.
- On a production host, the issuer is the operator's human key ([key custody](03-KEY-CUSTODY.md), [operator key](05-OPERATOR-KEY.md)). The choice of that key, its public half, and the first production signature are a human checkpoint. An agent prepares the files. An agent does not enroll a production signer.

Copy only the public half of a signer key to the host. These items never go to the host, a log, or the evidence:

- a private key;
- a passphrase;
- a store credential.

## Roles

| Role | Does |
| --- | --- |
| Operator (root on the host) | Measures the host facts, chooses the identity values, reviews each file, installs the files, and starts the services |
| `packaging/enrollment-policy.py` | Writes `policy.json` and `allowed_signers` from explicit arguments. Checks each value against the executor rules. Writes a new file with mode 0600 and prints its SHA-256. It invents no value and reads no private key |
| `rustiron-executor initialize` | Creates the journal and writes the admission mark with count 0 |
| `rustiron-control --init-state` | Creates the coordinator store |
| Signer (PC) | Signs each grant. The host never sees the private key |

## Preconditions

1. The product installation finished with `PASS installed` ([packaging README](../../packaging/README.md#host-installation)).
   Keep the installer output. It holds the `ols.parent_sha256=` line.
   It also holds the `receipt_key.public=` and `receipt_key.fingerprint=` lines. See [Receipt key](#receipt-key).
   The installer stops `lshttpd`, so the unit shows `failed` until the first activation. The OLS main process exits 255 after its graceful stop ([D-022](../decisions/D-022-ols-stop-exit-255.md), [W364](../validation/S10-W364/README.md)).
2. SELinux is `Enforcing`.
3. The sites file system holds `/srv/sites` with user quota on. Mount it before the installation. See [Sites file system](#sites-file-system).
4. `/etc/rustiron` holds no `policy.json`. The executor answers `EXECUTOR_NOT_ENROLLED`.
5. These packages are installed: `quota` (`setquota`, `repquota`, `quotaon`), `lsphp84-mysqlnd`, `lsphp84-process`, and the WordPress extensions of [D-054](../decisions/D-054-site-php-extensions.md): `lsphp84-xml`, `lsphp84-gd`, `lsphp84-opcache`, `lsphp84-sodium`, and `lsphp84-bcmath`.
   The provisioning check script calls `mysqli` and `posix_getpwuid`. Preflight refuses a host without these packages.
6. The package `lsphp` has the type `rustiron_php_exec_t` (`ls -Z /usr/local/lsws/lsphp84/bin/lsphp`). The installer relabels it. After an installation with an older installer, run `restorecon -v /usr/local/lsws/lsphp84/bin/lsphp`.

## Optional: mbstring and intl

The base profile has no `mbstring` and no `intl`. Some WordPress plugins need them. Add them only to a host whose sites need them ([D-055](../decisions/D-055-remi-php-libraries.md)). Their libraries come from Remi's repository, pinned to two packages.

Run these commands as root from the source tree of the installed build:

```sh
cd /etc/pki/rpm-gpg
for year in 2024 2025 2026; do curl -fsS -o RPM-GPG-KEY-remi$year https://rpms.remirepo.net/RPM-GPG-KEY-remi$year; done
sha256sum -c ~/src/packaging/repos/remi-keys.sha256
install -o root -g root -m 0644 ~/src/packaging/repos/rustiron-remi-php-libs.repo /etc/yum.repos.d/
restorecon /etc/yum.repos.d/rustiron-remi-php-libs.repo
dnf install lsphp84-mbstring lsphp84-intl
```

- The key check must print `OK` for each file. Otherwise, stop and remove the files.
- `dnf` must show only `oniguruma5php` and `libicu78` from `rustiron-remi-php-libs`, and the key fingerprint `CF1D F005 7CE8 5DFF 5B2F 2A37 C2FD 3B2C 2A09 48E4` for them.
- Afterwards, `dnf repoquery --installed --qf '%{from_repo} %{name}' | grep rustiron-remi` lists those two packages only.

## Receipt key

The installer makes the host receipt key in `/etc/rustiron/receipt-key` ([D-042](../decisions/D-042-host-receipt-key.md), [W392](../validation/S10-W392/README.md)).
The executor signs each exported receipt with it. A signed receipt is still self-attested: root on the host can sign anything with that key.

| Path | Owner and mode | SELinux type |
| --- | --- | --- |
| `/etc/rustiron/receipt-key` | `root:root` 0700 | `rustiron_receipt_key_t` |
| `ed25519` (private key) | `root:root` 0400 | `rustiron_receipt_key_t` |
| `ed25519.pub` (public key) | `root:root` 0444 | `rustiron_receipt_key_t` |

1. Copy the `receipt_key.public=` line from the installer output to a record off the host. Write the value after `=` as one line in a file, for example `HOST-receipt.pub`.
2. Check that the `receipt_key.fingerprint=` line equals the output of `ssh-keygen -l -E sha256 -f HOST-receipt.pub` on the machine that keeps the record.
3. Keep the record with the host ID and the installation date. A reinstallation makes a new key. An epoch rotation or a re-adoption keeps the key.

Do not copy, print, or move the private key. The key file never leaves the host. The uninstaller deletes it ([uninstall](12-UNINSTALL.md#evidence-and-the-archive)).

To check a receipt off the host, run `python3 scripts/check_receipt.py RECEIPT.json --public-key HOST-receipt.pub`.
The command requires a signature and passes only when the key in the record signed the receipt body.

## Sites file system

Mount a dedicated file system at `/srv/sites` before the installation.
Preflight and the installer accept an existing `/srv/sites` only if all of these are true ([W361](../validation/S10-W361/README.md)):

- The path is the root of one mounted file system. No other mount is on it or below it, and it is not a bind mount.
- The path is a directory, `root:root`, mode 0755, and empty.
- Its SELinux type is `var_t` (the base policy type before the installation) or `httpd_sys_content_t`.

They refuse any other existing `/srv/sites`. Do these steps before the installation:

1. Format the device. For XFS, `mkfs.xfs -L rs-sites DEVICE`. The XFS label has at most 12 characters.
2. Add one line to `/etc/fstab`: `LABEL=rs-sites /srv/sites xfs defaults,usrquota 0 0`.
3. Run `install -d -m 0755 /srv/sites`, `systemctl daemon-reload`, and `mount /srv/sites`.
4. Set the shape: `chown root:root /srv/sites`, `chmod 0755 /srv/sites`, `restorecon -v /srv/sites`. The expected type is `var_t`.
5. Install the product. The installer keeps the mount point (`KEPT empty mount point /srv/sites`) and relabels it to `httpd_sys_content_t`.
6. Run `/usr/libexec/rustiron/rustiron-executor quota-readiness` as root in the login shell, after the installation.
   Do not run it through `systemd-run`. The executor domain has no quota authority, so it always answers `quota_state_unknown` there.
   The expected output has `"user_quota":"enforced"` and the exit status is 0. A refusal prints a `refusal` code ([W335](../validation/S10-W335/README.md)).

A new ext4 file system holds `lost+found`, so preflight refuses it as not empty.
For ext4, mount the file system after the installation, then set the shape as in step 4. The expected type is then `httpd_sys_content_t`.

## Values to measure and choose

Measure each fact on the host. Do not copy a value from another host.

| Policy field | Value | How to get it |
| --- | --- | --- |
| `host_id` | Operator choice: 1–64 of `A-Z a-z 0-9 _ -` | Unique for each host |
| `host_epoch` | Operator choice, same grammar | A new epoch needs a new journal ([epoch re-adoption](07-EPOCH-READOPTION.md)) |
| `profile_digest` | 64 lowercase hex digits | The SHA-256 of the reviewed host profile file. W358 used the job tool profile that the installation used |
| `requester` | The coordinator's identity in plans, for example `rustiron_coordinator` | Must differ from `issuer` |
| `requester_uid` | `id -u rustiron-coordinator` | The installer creates the account. The kernel peer UID must equal this value |
| `issuer` | The signer name in `allowed_signers` | `lab_agent` in the lab. The human key name in production |
| `signer_policy_epoch` | The signer epoch | `policy_3` in the lab |
| `verifier_sha256` | `sha256sum /usr/bin/ssh-keygen` | Measure again after an `openssh` update, or signature checks refuse. The diagnosis check `verifier` fails then; [measure the verifier again](#measure-the-verifier-again) |
| `provisioning.wordpress_713_sha256` | `d2a09acb6a15e3b9c471d72557753c266d6f41a79ed19bfe04cbfe49e283b2a5` | The reviewed recipe pin (W016c) |
| `provisioning.uid_min`, `uid_max` | Inside 2000–59999, ordered | Free UIDs for site accounts |
| `provisioning.category_min`, `category_max` | Inside 1–1023, ordered | Free SELinux categories |
| `provisioning.quota` | `block_hard_kib` 65536–17179869184, `inode_hard` 1000–100000000 | D-028 default: 5242880 KiB and 500000 inodes. The product profile refuses provisioning without a quota |
| `ols.listener` | Letter, then up to 31 letters, digits, or `_` | The listener name in the rendered generation |
| `ols.address` | `IP:PORT` | The address that the listener binds |
| `ols.parent_sha256` | The `ols.parent_sha256=` line of the installer output | Compare it with `sha256sum /usr/local/lsws/conf/httpd_config.conf` |
| `ols.webadmin_port` | `7080` for the OLS package | Must not listen. Must differ from the listener port |

The tool writes `adopted` and `lscache` as empty lists. A fresh product host adopts no site.

A product site plan names the recipe `wordpress713_install_v1` with the `provisioning.wordpress_713_sha256` digest.
The executor refuses `wordpress713_v1` before intent (`FIXTURE_BINDING_DENIED`), because that recipe leaves the site at the WordPress installer ([D-047](../decisions/D-047-provisioned-site-install.md)).
The provision installs WordPress as the site account. The administrator login and its generated password are only in `/srv/sites/rs_SITE/private/rustiron-admin.txt` (mode 0600, `root:root`). Read the file as root on the host, and do not copy it into tickets or logs.

## Procedure

Run each step as root on the host unless the step names the PC.

1. **Recipe store.** Fetch the two pinned recipe files into a private folder, check them, and install them:

   ```sh
   curl -fsS -o wordpress-7.1.3.tar.gz https://wordpress.org/wordpress-7.1.3.tar.gz
   curl -fsS -o wordpress-7.1.3.md5.json 'https://api.wordpress.org/core/checksums/1.0/?version=7.1.3&locale=en_US'
   echo "d2a09acb6a15e3b9c471d72557753c266d6f41a79ed19bfe04cbfe49e283b2a5  wordpress-7.1.3.tar.gz" | sha256sum -c -
   echo "78ff5ec132f655e0ed8411984d985bd3bd58271f782745d20200e28a8e571671  wordpress-7.1.3.md5.json" | sha256sum -c -
   install -o root -g root -m 0644 wordpress-7.1.3.tar.gz wordpress-7.1.3.md5.json /var/lib/rustiron/recipes/
   restorecon -R /var/lib/rustiron/recipes
   ```

   Stop if a digest does not match. The executor compiles in the checksum-list digest and refuses any other list.
   For the page-cache opt-in ([W368](../validation/S10-W368/README.md)), also prepare the LiteSpeed Cache recipe. Fetch the two files into a new private folder, then run the tool from the source tree of the installed build:

   ```sh
   curl -fsS -o litespeed-cache.7.9.3.zip https://downloads.wordpress.org/plugin/litespeed-cache.7.9.3.zip
   curl -fsS -o litespeed-cache.7.9.3.checksums.json https://downloads.wordpress.org/plugin-checksums/litespeed-cache/7.9.3.json
   install -d -m 0700 OUT
   python3 -I packaging/page-cache-recipe.py litespeed-cache.7.9.3.zip litespeed-cache.7.9.3.checksums.json OUT
   install -o root -g root -m 0644 OUT/litespeed-cache-7.9.3.tar OUT/litespeed-cache-7.9.3.checksums.json /var/lib/rustiron/recipes/
   restorecon -R /var/lib/rustiron/recipes
   ```

   The tool checks both pins and prints `0db968c7e9ae8a17023f2db3fef1134ba006e1e3f104c3fe715b7f46534e20a9` for the archive. Stop if it prints `REFUSED`.
2. **Signer public key.** On the PC, copy only the public key file (for example `operator_synthetic.pub` in the lab) to the host.
3. **Policy file.** From the source tree of the installed build, write the policy into a private folder:

   ```sh
   python3 packaging/enrollment-policy.py policy --out DIR/policy.json \
       --host-id HOST --host-epoch EPOCH --profile-digest HEX \
       --requester rustiron_coordinator --requester-uid "$(id -u rustiron-coordinator)" \
       --issuer ISSUER --signer-policy-epoch SIGNER_EPOCH \
       --verifier-sha256 "$(sha256sum /usr/bin/ssh-keygen | cut -d' ' -f1)" \
       --wordpress-sha256 HEX --uid-range 3001-3099 --category-range 201-299 \
       --quota-block-hard-kib KIB --quota-inode-hard N \
       --ols-listener NAME --ols-address IP:PORT --ols-parent-sha256 HEX --ols-webadmin-port 7080
   ```

   Read the file. The file is one line of canonical JSON with no final new line.
4. **Signer list.** Write `allowed_signers` from the public key, and an empty revocation list:

   ```sh
   python3 packaging/enrollment-policy.py allowed-signers --out DIR/allowed_signers \
       --issuer ISSUER --public-key KEY.pub
   : >DIR/revocations
   ```

   The file holds one line: the issuer, `namespaces="rustiron-plan-v1"`, `ssh-ed25519`, and the key. The tool removes the key comment.
5. **Install the trust files.** `/etc/rustiron` exists from the installation (`root:root`, mode 0700, `rustiron_executor_conf_t`).

   ```sh
   for f in policy.json allowed_signers revocations; do
       install -o root -g root -m 0600 DIR/$f /etc/rustiron/$f
   done
   restorecon -R /etc/rustiron
   ```

   Each file must be a regular file with one link, `root:root`, mode 0600. The executor refuses any other shape with `EXECUTOR_ACCESS_DENIED`.
6. **Database server.** Run `systemctl enable --now mariadb.service`. Site provisioning uses the local socket `/var/lib/mysql/mysql.sock`.
7. **Listener port label and helper address.** Run `semanage port -a -t rustiron_ols_port_t -p tcp PORT` with the listener port. If the base policy already labels that port, use `-m` in place of `-a`.
   The admin helper connects to the listener during the activation check. Its unit has `IPAddressDeny=any`, so allow only the listener address in a drop-in:

   ```sh
   install -d -m 0755 /etc/systemd/system/rustiron-admin-helper.service.d
   printf '[Service]\nIPAddressAllow=IP/32\n' >/etc/systemd/system/rustiron-admin-helper.service.d/50-ols-listener.conf
   chmod 0644 /etc/systemd/system/rustiron-admin-helper.service.d/50-ols-listener.conf
   restorecon -R /etc/systemd/system/rustiron-admin-helper.service.d
   systemctl daemon-reload
   ```

8. **Journal and admission mark.** With the executor service stopped, run `/usr/libexec/rustiron/rustiron-executor initialize`, then `restorecon -R /var/lib/rustiron`.
   The command refuses a folder that already holds a journal. Do not delete a journal to repeat this step.
9. **Coordinator store.**

   ```sh
   install -d -o rustiron-coordinator -g rustiron-coordinator -m 0700 /var/lib/rustiron-coordinator
   runuser -u rustiron-coordinator -- /usr/libexec/rustiron/rustiron-control \
       --state-dir /var/lib/rustiron-coordinator --init-state
   restorecon -R /var/lib/rustiron-coordinator
   ```

10. **OLS state.** Start the admin helper (`systemctl start rustiron-admin-helper.service`). Then, with the executor service still stopped, run:

    ```sh
    systemd-run --wait --pipe --quiet /usr/libexec/rustiron/rustiron-executor ols-status --admin-helper
    ```

    A fresh host prints `"current":null`, `"generation":"re3b0c44298fc1c14"`, and `"parent_reviewed":true` ([W355](../validation/S10-W355/README.md)).
    Before the first activation, `webadmin_closed` and `clean` are false. The check also requires the enrolled listener to listen, and no listener exists yet.
    Use `--admin-helper`. Without it, the command reads the server root and `/proc/net` in the executor domain, which has no access to them.
    The command waits up to 10 s for the helper socket, because `systemctl start` returns before the helper binds it ([W361](../validation/S10-W361/README.md)).
11. **Services.** Run `systemctl enable --now rustiron-admin-helper.service rustiron-executor.service rustiron-coordinator.service`.
    The units are `Type=simple`, so `systemctl` returns before each socket exists.
    Do the checks below only after `/run/rustiron/executor.sock` and `/run/rustiron-coordinator/control.sock` exist (`test -S PATH`).

## Checks that prove enrollment

| Check | Expected result |
| --- | --- |
| `systemctl is-active` for the three units | `active` for each |
| `/proc/<pid>/attr/current` of each process | `rustiron_admin_t`, `rustiron_executor_t`, `rustiron_coordinator_t` |
| `systemd-run --wait --pipe --quiet /usr/libexec/rustiron/rustiron-executor observe` | Exit 0 and one JSON object with the enrolled host and epoch. It runs beside the serving executor. `packages` is null and `package_source` is `not_observed`: the product executor does not run `rpm` ([W364](../validation/S10-W364/README.md)). `host.receipt_key.state` is `present`, and its `public_key` and `fingerprint` equal your off-host record |
| `rustiron-executor quota-readiness` in the root shell | Exit 0, `"user_quota":"enforced"` |
| `ols-status` in step 10 | `parent_reviewed` true, `current` null, `generation` `re3b0c44298fc1c14` |
| `runuser -u rustiron-coordinator -- rustiron --output json --socket /run/rustiron-coordinator/control.sock doctor` | The coordinator answers |
| `ausearch --input-logs -m AVC,USER_AVC,SELINUX_ERR -ts boot` | No `rustiron` denial |

## Next steps

- The first site uses a signed site plan of schema 2 with quota limits at most the enrolled quota ([W341](../validation/S10-W341/README.md)).
- The first `config_activate` names the empty generation `re3b0c44298fc1c14` with digest `e3b0c442…b855`. It starts `lshttpd` ([W355](../validation/S10-W355/README.md)).
- Submit plans through the coordinator as the `rustiron-coordinator` account. The executor refuses every other peer UID.
- To back up a site, enroll the product store with [product store enrollment](10-PRODUCT-STORE-ENROLLMENT.md).
- After the first activation, `ols-status --admin-helper` with the executor stopped prints `clean` true. Only the enrolled listener listens, and ports 7080 and 8088 are closed.
- `export SITE` reports the quota of a site. Run it in the root shell with the executor stopped. In the executor domain it cannot read the quota or the unit states.

## Failure and recovery

| Answer | Meaning | Action |
| --- | --- | --- |
| `EXECUTOR_NOT_ENROLLED` | No `policy.json` | Do steps 3–5 |
| `EXECUTOR_ACCESS_DENIED` | A trust file or folder has a wrong owner, mode, link count, or link | Fix the shape. Do not relax the mode |
| `EXECUTOR_DEPENDENCY_UNAVAILABLE` | A policy value fails a rule, the signer list is malformed, or the verifier digest differs | Write the file again with the tool. Measure the verifier again |
| `JOURNAL_STATE_EXISTS` from `initialize` | A journal exists and the policy names a new epoch | Keep it. A new epoch needs the epoch procedure |
| `JOURNAL_ROLLBACK` from `initialize` | The epoch is unchanged and the admission mark records admitted work ([W369](../validation/S10-W369/README.md)) | Keep the journal and the mark. Use the epoch procedure |
| `JOURNAL_ROLLBACK` | The journal is behind the admission mark | Treat it as a restored journal. Rotate the epoch |
| `not_sent`, exit 7, and `the coordinator socket could not be reached` on stderr | The coordinator does not run. After more than 5 starts in 60 s, systemd refuses new starts (`Result=start-limit-hit`) | Run `systemctl reset-failed rustiron-coordinator.service`, then start it. Send the plan again with the same operation ID and idempotency key |

## Measure the verifier again

An `openssh` update replaces `/usr/bin/ssh-keygen`, the program that checks every signature. The executor then refuses every signed request with `EXECUTOR_DEPENDENCY_UNAVAILABLE`, and the diagnosis check `verifier` fails ([W483](../validation/S10-W483/README.md)). Serving does not change. As root, from the source tree of the installed build:

```sh
rpm -V openssh-clients        # no output: the installed files match the signed package
install -d -m 0700 /root/verifier-update
python3 packaging/enrollment-policy.py verifier --policy /etc/rustiron/policy.json \
    --out /root/verifier-update/policy.json
install -o root -g root -m 0600 /root/verifier-update/policy.json /etc/rustiron/policy.json
restorecon -R /etc/rustiron
```

The tool prints the old and the new digest and changes nothing else in the policy. If `rpm -V` prints a line for `/usr/bin/ssh-keygen`, stop: the program does not match its package.

Do not edit a trust file in place on a running host.
Stop the executor, and install the new file with the same shape. Then start the executor again.
