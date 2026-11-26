# Rustiron product staging

Use an unprivileged build user on AlmaLinux 10 x86_64.
Provide the pinned Rust toolchain, cached Cargo dependencies, SQLite build inputs, and the SELinux policy development tools.
From the source root, run:

```sh
python3 scripts/prepare_sqlite.py --fetch
sh packaging/stage-product.sh EXISTING_OUTPUT_PARENT
```

The command prints the path of a new private staging root.
The root contains the product management binaries, two Rust job workers, systemd units, sysusers configuration, and SELinux policy packages.
The site PHP units use the shared sandbox checker and the installed LSPHP executable.
`SHA256SUMS` records their bytes for subsequent integrity checks.

Use the staging root to validate file paths and package contents. Keep it private.

The staging build sets only `--cfg rustiron_profile="product"`. That profile opens the capture write gate ([D-029](../docs/decisions/D-029-product-write-gate.md)).
A product host with an enrolled backup destination writes capture snapshots to that store ([W371](../docs/validation/S10-W371/README.md)).

## Store namespace and relay

The staging root includes `rustiron-store-netns.service`, the `rustiron-store-relay@.socket` and `rustiron-store-relay@.service` templates, the fixed `store-netns` setup program, and the `rustiron_store_relay` policy package.
They read the enrolled endpoint from `/etc/rustiron/store-network.env`. The file contains exactly two lines, in this order:

```text
RUSTIRON_STORE_ENDPOINT=<IPv4>
RUSTIRON_STORE_PORT=<port>
```

The port is the enrolled projection port, 443 by default. The setup program refuses a value that is not canonical or not on one line.
The namespace keeps loopback only. The relay forwards store connections to that one address and port without IP forwarding or firewall changes.

Enable the namespace service and the relay socket instance for the enrolled port only after store enrollment, for example `rustiron-store-relay@443.socket`.
For a port other than 443, first label it with `semanage port -a -t rustiron_store_port_t -p tcp PORT`. If the base policy already gives that single port its own entry, use `-m` in place of `-a`.
The label applies to the port on the whole host. Choose a port that no other local service uses.

The executor refuses store jobs unless the file, the namespace filter, and the one listener match the enrolled projection.
[W317](../docs/validation/S10-W317/README.md) records the boot and refusal proofs. [W352](../docs/validation/S10-W352/README.md) records the enrolled-port proof.
[W371](../docs/validation/S10-W371/README.md) records a product capture through these units on a fresh product host.

## Host job tools

Stage the vendor executables on the host with the installed RPMs.
Use the reviewed pin file and an existing private output parent.

```sh
python3 packaging/stage-job-tools.py PROFILE EXISTING_OUTPUT_PARENT
```

The command checks package identity, RPM file digests, and the bytes it copies.
It prints a separate host job root for the installer.
Keep that root on the same host and keep the Rustiron artifact bundle separate.

The [lab pin file](profiles/alma10-lab-job-tools.toml) records the AlmaLinux 10.2 tuple installed on the lab VM.
The [EPEL el10_3 pin file](profiles/alma10-epel-el10_3-job-tools.toml) records the tuple that a new host installs today. EPEL replaced the restic build in November 2026 ([W339](../docs/validation/S10-W339/README.md), W349).
Production package provenance, host enrollment, and service activation remain open.

## Installer preflight

Run the read-only check as root on the intended AlmaLinux 10 host.
Use both private staging roots and the same reviewed host job profile.

```sh
python3 packaging/install-preflight.py MANAGEMENT_ROOT HOST_JOB_ROOT JOB_PROFILE
```

The check verifies the exact payload inventory and file modes.
It checks the pinned host executables again and reports existing Rustiron paths, units, identities, and policy modules.
Exit 0 means the checked prerequisites passed. Exit 1 identifies a refusal. Exit 2 identifies a usage error.
Host enrollment, artifact authenticity, and runtime acceptance require separate checks.

## Offline installation root

Use the staged inputs to assemble a disposable filesystem root for verification.
Run as root with an existing root-owned mode-0700 output parent and trusted ancestry.

```sh
python3 packaging/assemble-install-root.py MANAGEMENT_ROOT HOST_JOB_ROOT JOB_PROFILE OUTPUT_PARENT
```

The command prints a new root with the fixed payloads and empty state directories.
The root keeps the journal and admission mark separate and sets the manifest directory to mode 2700.
Systemd creates runtime directories and coordinator state during later service setup.
Keep the offline root private and verify it before use.

## Host installation

Run the installer as root on the fresh host with the assembled root and the same inputs.

```sh
python3 packaging/install-product.py INSTALL_ROOT MANAGEMENT_ROOT HOST_JOB_ROOT JOB_PROFILE \
  --release-signers /etc/rustiron/release-allowed-signers --release-signer-id RELEASE_SIGNER_ID
```

The installer verifies `MANAGEMENT_ROOT/SHA256SUMS.sig` against `--release-signers` in the `rustiron-release-v1` OpenSSH SSHSIG namespace before reading or writing any host file (disposable lab overlays without a release signature must pass `--allow-unsigned-lab` explicitly).

The command accepts only the exact assembled inventory, bytes, modes, and ownership.
The installer repeats the preflight host and conflict checks and refuses before the first write.
It copies the payload and state directories without replacing a path and creates the coordinator identity.
Then it loads the policy packages, relabels the installed paths, and reloads systemd.
The installer does not enable or start a unit, enroll the host, or roll back a failure after the first write.
[W339](../docs/validation/S10-W339/README.md) records the first clean-host installation.

The installer also relabels the package `lsphp`, which the `rustiron_php` module labels as the site PHP entry point ([W358](../docs/validation/S10-W358/README.md)).
Preflight requires `lsphp84-mysqlnd`, `lsphp84-process`, and `quota` with the server packages. Since [D-054](../docs/decisions/D-054-site-php-extensions.md) it also requires the WordPress extensions `lsphp84-xml`, `lsphp84-gd`, `lsphp84-opcache`, `lsphp84-sodium`, and `lsphp84-bcmath`. `mbstring` and `intl` are optional: [`repos/`](repos/) holds the pinned source of their libraries ([D-055](../docs/decisions/D-055-remi-php-libraries.md)).
Preflight and the installer accept an existing `/srv/sites` only as an empty mount root, `root:root`, mode 0755, with the type `var_t` or `httpd_sys_content_t`.
The installer keeps that mount point and relabels it. Any other existing `/srv/sites` refuses ([W361](../docs/validation/S10-W361/README.md)).

## Product update

`packaging/update-product.py` updates the payload of an enrolled host from a new assembled root and rolls one update back ([D-049](../docs/decisions/D-049-product-update.md)).
It refuses a changed payload file set, mode, or shipped parent template, drift from the install record, and an active capture or probe unit.
It stops only the management units, keeps a copy of each changed file below `/var/lib/rustiron/updates`, and renames each new file into place.
The [product update page](../docs/operator/16-PRODUCT-UPDATE.md) gives the procedure. [W409](../docs/validation/S10-W409/README.md) is the rehearsal.

## Scheduled capture units

The staging root carries [rustiron-scheduled-capture.service](systemd/rustiron-scheduled-capture.service), its daily timer, [rustiron-scheduled-capture-check.service](systemd/rustiron-scheduled-capture-check.service), and its hourly timer ([D-035](../docs/decisions/D-035-scheduled-capture.md)).
Both services run `rustiron schedule` as `rustiron-coordinator` through the coordinator socket. They read the signed files in `/var/lib/rustiron-coordinator/standing/current`.
The installer does not enable the timers. The [scheduled capture page](../docs/operator/13-SCHEDULED-CAPTURE.md) gives the operator steps.
`RUSTIRON_RPO_TARGET_SECONDS` in each service sets the RPO target of the report (86400 by default).

## OLS unit drop-in

The package `lshttpd.service` has `KillMode=none`, so OLS workers stay alive after a stop ([W245](../docs/validation/S10-W245/README.md), [W361](../docs/validation/S10-W361/README.md)).
The staging root carries [systemd/lshttpd.service.d/50-rustiron-killmode.conf](systemd/lshttpd.service.d/50-rustiron-killmode.conf), which sets `KillMode=mixed`.
After a stop, systemd sends SIGKILL to each process left in the unit.

The staging root also carries [systemd/lshttpd.service.d/51-rustiron-boot-guard.conf](systemd/lshttpd.service.d/51-rustiron-boot-guard.conf) and [rustiron-ols-boot-guard.service](systemd/rustiron-ols-boot-guard.service) ([D-032](../docs/decisions/D-032-power-cut-serving-and-reply-states.md)).

The staging root also carries [journald/50-rustiron-persistent.conf](journald/50-rustiron-persistent.conf), a persistent system journal ([D-072](../docs/decisions/D-072-persistent-journal.md)).
The drop-in makes `lshttpd` want the boot guard and start after it.
At boot, the guard puts `current` back on the journaled predecessor of an OLS activation that a power cut left unverified. For a bootstrap activation, it removes `current`.
The guard unit then runs a fixed one-shot admin helper command.
After an interrupted eject, the helper starts the restored site's PHP socket and timer for this boot.
The guard records nothing in the journal. The [after power loss page](../docs/operator/11-AFTER-POWER-LOSS.md) gives the recovery.

The drop-in also has `ConditionPathIsSymbolicLink=/etc/rustiron-ols/current` ([D-033](../docs/decisions/D-033-bootstrap-crash-settlement.md)). With no `current`, systemd skips the start, and `lshttpd` stays `inactive` with no restart loop. The condition reads only the link, because SELinux refuses `init_t` a read of the link ([W382](../docs/validation/S10-W382/README.md)).

The drop-in also has `ExecCondition=/usr/bin/cmp -s` of the shipped parent template and the live parent ([D-038](../docs/decisions/D-038-ols-parent-start-condition.md)). OLS starts only when the two files are byte-identical. Otherwise systemd skips the start, and `lshttpd` stays `inactive` with no listener.

The OLS package restarts `lshttpd` on each upgrade, downgrade, and reinstall. Without the condition, a restart with another parent served that parent, with WebAdmin open ([W389](../docs/validation/S10-W389/README.md)).
A reload does not run the condition. The [OLS upgrade page](../docs/operator/14-OLS-UPGRADE.md) gives the procedure.

Preflight and the installer refuse an OLS unit that is not the package fragment, that has a drop-in, or that needs a reload.
After `daemon-reload`, the installer requires the package fragment, only the two Rustiron drop-ins, and `KillMode=mixed`, and then stops OLS.
A stopped unit shows `failed`, because the OLS main process exits 255 after its graceful stop ([D-022](../docs/decisions/D-022-ols-stop-exit-255.md)).
The first activation and its compensation require `KillMode=mixed` ([W364](../docs/validation/S10-W364/README.md)).

## Host uninstallation

The installer writes `/var/lib/rustiron/install-record.json` before the first payload file ([W385](../docs/validation/S10-W385/README.md)).
The record names each installed file with its SHA-256 and mode, and the folders that the installer made.
It also names the policy modules, the identities, and the facts of the package OLS parent.
Run the uninstaller as root from the source tree of the installed build:

```sh
python3 packaging/uninstall-product.py --ols-parent keep|package [--apply]
```

Without `--apply`, the command prints each planned action and changes nothing.
It removes only what the record names. It refuses a recorded file with other bytes, owner, or mode.
It moves the evidence to a root-only archive with a `MANIFEST`.
The evidence is the policy, the signer files, the journal, the admission mark, the coordinator store, and the credentials.
Only `--destroy-evidence` deletes the evidence. The command never changes site files, site accounts, or site databases.
`keep` leaves the Rustiron parent and the serving set, so the served sites keep serving. `package` restores the package parent and leaves OLS stopped.
With sites that `site_eject` made standalone, `package` writes a standalone parent instead, copies each standalone vhost into `/usr/local/lsws/conf/vhosts`, and starts OLS ([D-037](../docs/decisions/D-037-independent-eject.md), [W387](../docs/validation/S10-W387/README.md)).
The [uninstall page](../docs/operator/12-UNINSTALL.md) gives the procedure.

## Host enrollment

After the installation, enroll the host with the [product enrollment procedure](../docs/operator/09-PRODUCT-ENROLLMENT.md).
`enrollment-policy.py` writes `policy.json` and `allowed_signers` from explicit operator values:

```sh
python3 packaging/enrollment-policy.py policy --out FILE --host-id ID ...
python3 packaging/enrollment-policy.py allowed-signers --out FILE --issuer ID --public-key KEY.pub
```

The tool checks each value against the executor rules and writes a new file with mode 0600. It reads no private key.
Without a backup pin, the policy is schema 1.
With `--product-backup-destination-id` and `--product-backup-digest`, the tool writes schema 2 with the `product_backup` pin ([W374](../docs/validation/S10-W374/README.md)).
The [product store enrollment](../docs/operator/10-PRODUCT-STORE-ENROLLMENT.md) gives the procedure.
With `--dns-listen`, `--dns-name-servers`, `--dns-hostmaster`, `--dns-secondaries`, `--dns-tsig-key`, and `--dns-soa`, the tool writes the `dns` section of [D-091](../docs/decisions/D-091-cp05-v1-scope.md) ([W550](../docs/validation/S10-W550/README.md)). `rustiron-executor dns-config` prints the `pdns.conf` that the enrolled section renders, for review; nothing installs or starts PowerDNS yet.
The `dns` command sets only that section in a copy of an installed policy. [`repos/`](repos/) holds the pinned PowerDNS 5.1 source of [D-092](../docs/decisions/D-092-powerdns-source.md): the repository file limited to `pdns`, `pdns-backend-sqlite`, and `pdns-tools`, and the key's SHA-256 ([W560](../docs/validation/S10-W560/README.md)).
`packaging/dns-zone-sets.py` prints a zone's record sets with the digests a signed `dns_change` expects, or the canonical zone text, from `pdnsutil zone list` output; it changes nothing ([run DNS](../docs/operator/29-DNS.md)).
With `--firewall-ssh-port` (and `--firewall-dhcpv6-client`), the tool writes the `firewall` section of [D-095](../docs/decisions/D-095-cp08-v1-scope.md); the `firewall` command sets only that section in a copy of an installed policy ([W559](../docs/validation/S10-W559/README.md)).
With `--acme-directory` (and optional `--acme-ca-bundle` under `/var/lib/rustiron-acme/`), the tool writes the `acme` section of [D-059](../docs/decisions/D-059-tls-certificates.md); the `acme` command sets only that section in a copy of an installed policy ([W646](../docs/validation/S10-W646/README.md)).

## Installation wizard

`packaging/rustiron-install-wizard.py` provides an interactive (`--interactive`) and auditable non-interactive (`--plan` default, `--json`, `--apply`) AlmaLinux 10 x86_64 onboarding wizard ([W646](../docs/validation/S10-W646/README.md)):

```sh
python3 packaging/rustiron-install-wizard.py --interactive
python3 packaging/rustiron-install-wizard.py --host-id HOST_ID --public-ipv4 IP --issuer SIGNER_ID --json
```

Without `--apply`, the wizard inspects host prerequisites read-only and prints a validated blueprint covering OS packages, key-only SSH hardening (`01-rustiron-ssh.conf`), SELinux Enforcing (`/.autorelabel` reboot gate), dedicated XFS `usrquota` `/srv/sites` setup, signed release installation (`rustiron-release-v1`), `enrollment-policy.py` (including ACME, TLS, firewall, and blast-radius limits), `rustiron-admin-helper` and `rustiron-site-cron` listener IP drop-ins, `firewall-zone.py`, and optional D-090 loopback Console setup (`NODE_ENV=production`, `RUSTIRON_CONSOLE_AUTH_REQUIRED=1`, out-of-band setup token).
It never creates or reads private signing keys on the host. This wizard is experimental pre-release tooling; no supported public release exists yet.

## Unified release updater

`packaging/rustiron-updater.py` wraps `stage-job-tools.py`, `assemble-install-root.py`, `update-product.py` (D-049/D-062/D-063/H-09), optional atomic Console Admin Panel swaps, and signed `releases.json` channel checks in one command (`status`, `check`, `verify`, `plan`, `apply`, `rollback`, [W647](../docs/validation/S10-W647/README.md)).
Release bundles and channel indexes are packed and signed off-host with `scripts/release/bundle_release.py` in the dedicated `rustiron-release-v1` OpenSSH SSHSIG namespace ([product update runbook](../docs/operator/16-PRODUCT-UPDATE.md#unified-release-bundles-and-one-command-updater-w647)).

## Host firewall zone

`packaging/firewall-zone.py` renders the `rustiron` firewalld zone from the `firewall` section and makes it the default zone ([firewall design](../docs/technical/FIREWALL.md)).
Without `--apply` it prints the zone and the plan. It refuses before any change unless `sshd` listens on the enrolled port and the default zone is `public` or `rustiron`.
After the change it checks the interfaces and the exact allowed set, and sets `public` back as the default when a step or check fails. `--restore --apply` sets `public` back and removes the zone file. `--check` reports drift from the enrolled zone and changes nothing ([W568](../docs/validation/S10-W568/README.md)).

The payload's `/etc/my.cnf.d/zz-rustiron-loopback.cnf` keeps MariaDB on loopback; the installer and the updater restart MariaDB with it and refuse any other TCP listener on 3306 ([W569](../docs/validation/S10-W569/README.md)).
The [firewall zone page](../docs/operator/28-FIREWALL-ZONE.md) gives the procedure.

## Receipt key

After the policy modules load, the installer makes the host receipt key with `ssh-keygen -t ed25519` in `/etc/rustiron/receipt-key` ([D-042](../docs/decisions/D-042-host-receipt-key.md)).
The private key is `root:root` 0400, the public key 0444, and both have the type `rustiron_receipt_key_t`.
The installer refuses an existing key, checks the labels, and prints `receipt_key.public=` and `receipt_key.fingerprint=` for the operator's off-host record ([enrollment](../docs/operator/09-PRODUCT-ENROLLMENT.md#receipt-key)).
The uninstaller deletes the private key and archives the public key.

## OLS parent configuration

The staging root carries the reviewed OLS parent, [ols/httpd_config.conf](ols/httpd_config.conf), at `/usr/share/rustiron/ols/httpd_config.conf`.
The parent closes WebAdmin, sets the D-028 server limits, registers the cache module with storage off, and holds exactly one Rustiron include.
It also sets the [D-039](../docs/decisions/D-039-tls-defaults-in-the-parent.md) TLS defaults: TLS 1.2 suites with ECDHE and an AEAD cipher only, and no HTTP/3 (`quicEnable 0`).
Its `CGIRLimit` block lets the OLS suEXEC daemon start the PHP of an ejected site, never as an account or group under 1000 ([D-037](../docs/decisions/D-037-independent-eject.md)).
It defines no listener, virtual host, or PHP application. The Rustiron include renders them.

Preflight and the installer refuse a missing, linked, or immutable parent, and a parent that already holds the Rustiron include.
After the payload, the installer does these steps:

1. It keeps the package parent as `/var/lib/rustiron/ols-package/httpd_config.conf`, mode 0400, in a root-only directory.
2. It replaces the parent with the shipped bytes, `root:root` mode 0644, and relabels it (`usr_t`).
3. It sets the immutable flag, checks the bytes and metadata again, and runs the OLS configuration test.
4. It stops `lshttpd` and checks that ports 7080 and 8088 do not listen. OLS 1.9.4 does not run without a listener, so OLS stays stopped until the first Rustiron generation. At each boot before that generation, systemd skips the start of `lshttpd` (D-033).
   The first `config_activate` is a bootstrap activation. It starts `lshttpd` instead of reloading it ([W355](../docs/validation/S10-W355/README.md)).
5. It prints `ols.parent_sha256=<digest>` for the enrollment policy.

The `rust-tc quick` suite checks that the shipped parent passes the executor review for its own digest.
[W348](../docs/validation/S10-W348/README.md) records the clean-host proof.
