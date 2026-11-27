# Product update

Updated: 2026-11-15, America/Toronto.
This procedure updates the Rustiron payload of an enrolled product host to a new build, and rolls one update back.
[D-049](../decisions/D-049-product-update.md) is the decision. [W409](../validation/S10-W409/README.md) is the lab rehearsal.

Run each command as root in the root shell of the host.
The update keeps the journal, the admission mark, the enrollment, the receipt key, and the sites.
Websites keep serving. Management requests fail while the executor is stopped.

## What the command refuses

- A file mode that differs from `/var/lib/rustiron/install-record.json`.
- A change of the shipped OLS parent template.
- An installed payload file that is not exactly what the install record states.
- A file the release adds whose destination already exists, or whose folder does not exist.
- A release that removes a shipped SELinux module.
- An active capture, probe, or scheduled capture unit.
- An installed OS, OLS, PHP, or MariaDB version outside the new build's [support matrix](../technical/SUPPORT-MATRIX.md) (D-063).

A refused update changes nothing. A changed parent needs its own reviewed procedure.

## Added and removed files

Under [D-062](../decisions/D-062-update-payload-set.md), a release may add and remove payload files. The plan prints `ADD` and `REMOVE` lines next to `CHANGE`. A removed file's copy is kept in the update folder, and a rollback restores it and removes the added files.

An added file may need a new folder inside `/usr/share/rustiron` or `/usr/libexec/rustiron`. The update creates that folder (root, `0755`). A rollback removes it again when it is empty ([W734](../validation/S10-W734/README.md)). The update also creates any install-time state folder that an older host lacks, for example `/etc/rustiron-caddy` for the executor unit. The install record lists it as a state folder, and a rollback removes it when it is empty ([W735](../validation/S10-W735/README.md)). When the sysusers file changes, the update creates its identities. New units are not enabled; enable them as their own page says.

## Before the update

1. Build the new source with the same toolchain steps as the installed build, as the build account. Stage the product and the job tools into a new output folder.
2. Assemble the update root with the new tree's own `packaging/assemble-install-root.py` into a new root-only folder.
3. Record the state:

   ```sh
   cat /var/lib/rustiron/admission/admission-mark
   sha256sum /var/lib/rustiron/install-record.json
   systemctl is-active rustiron-admin-helper rustiron-executor rustiron-coordinator lshttpd
   ```

4. An operation that the journal shows as `running` stays in the journal. Settle it after the update with the new build ([after power loss](11-AFTER-POWER-LOSS.md#recovery-commands)).

## Update

From the new source tree, with the new root, the new management and host job folders, the job tools profile, and the trusted `rustiron-release-v1` allowed-signers file:

```sh
python3 packaging/update-product.py ROOT MANAGEMENT JOBS PROFILE \
  --release-signers /etc/rustiron/release-allowed-signers --release-signer-id RELEASE_SIGNER_ID
python3 packaging/update-product.py ROOT MANAGEMENT JOBS PROFILE \
  --release-signers /etc/rustiron/release-allowed-signers --release-signer-id RELEASE_SIGNER_ID --apply
```

The command refuses unsigned staging roots by default (`H-09`). Disposable lab rehearsals without a release signature must pass `--allow-unsigned-lab` explicitly.

The first command prints each `CHANGE` and the units it would stop, and changes nothing.
The second prints `UPDATE FOLDER`, each `REPLACED` file, each `ACTIVE` unit, and `PASS update applied`.
Keep the printed update folder name.

## Check

```sh
cat /var/lib/rustiron/admission/admission-mark
systemd-run --wait --pipe --quiet /usr/libexec/rustiron/rustiron-executor observe
```

The admission mark is unchanged. `observe` reads the same host, epoch, sites, and operations.

## Journal schema change

The updater does not change the journal ([D-049](../decisions/D-049-product-update.md)). A build that raises the journal schema needs its own migration step after the update.

- Builds from [W442](../validation/S10-W442/README.md) on use journal v21, from [W457](../validation/S10-W457/README.md) v22, from [W462](../validation/S10-W462/README.md) v23, from [W464](../validation/S10-W464/README.md) v24, from [W479](../validation/S10-W479/README.md) v25, from [W489](../validation/S10-W489/README.md) v26, from [W491](../validation/S10-W491/README.md) v27, from [W494](../validation/S10-W494/README.md) v28, from [W498](../validation/S10-W498/README.md) v29, from [W501](../validation/S10-W501/README.md) v30, from [W508](../validation/S10-W508/README.md) v31, and from [W514](../validation/S10-W514/README.md) v32. The frozen M1 candidate uses v20.
- Until the migration, the new executor refuses the older journal and exits, so `observe` fails.
- After the migration, an older executor refuses the new journal, so a rollback to an older build no longer works.

W457 rehearsed the migration from v21 to v22 on a lab product host. After the update:

1. Run `systemctl is-active rustiron-executor`. An updater from [W458](../validation/S10-W458/README.md) on fails the update when a unit stops within 3 s of its start; an older one could pass before the executor exited (W457-F1). Check again a few seconds after the update.
2. Stop the services: `systemctl stop rustiron-coordinator rustiron-executor rustiron-admin-helper`.
3. Keep a copy of `/var/lib/rustiron/executor/fixture-journal.sqlite` in a root-only folder.
4. Run `/usr/libexec/rustiron/rustiron-executor migrate`. It exits 0 on success.
5. Run `restorecon -R /var/lib/rustiron`.
6. Start the services: `systemctl start rustiron-admin-helper rustiron-executor rustiron-coordinator`.
7. A few seconds later, check that all three are active, and that the admission mark count did not change.

The migration from v20 is not rehearsed on a product host.

## Roll back

```sh
python3 packaging/update-product.py --rollback /var/lib/rustiron/updates/STAMP
python3 packaging/update-product.py --rollback /var/lib/rustiron/updates/STAMP --apply
```

The rollback refuses when an installed file or the install record changed after that update.
The update folder stays as evidence. The [uninstaller](12-UNINSTALL.md) archives it with the other state.

## Unified release bundles and one-command updater (W647)

Maintainers can package a staged management root (`packaging/stage-product.sh`), optional Console Admin Panel source archive (`console/`), optional CycloneDX SBOM, and `release.json` into a single reproducible, off-host signed tarball and channel index (`releases.json`) using `scripts/release/bundle_release.py`:

```sh
python3 scripts/release/bundle_release.py pack --version X.Y.Z --git-commit COMMIT \
  --management-root MANAGEMENT_ROOT --console-dir console --out-dir dist-release
python3 scripts/release/bundle_release.py sign dist-release/rustiron-X.Y.Z-almalinux10-x86_64.tar.gz --key OFFHOST_RELEASE_KEY
python3 scripts/release/bundle_release.py index --index dist-release/releases.json \
  --bundle dist-release/rustiron-X.Y.Z-almalinux10-x86_64.tar.gz \
  --bundle-url https://releases.example.invalid/rustiron-X.Y.Z-almalinux10-x86_64.tar.gz
python3 scripts/release/bundle_release.py sign dist-release/releases.json --key OFFHOST_RELEASE_KEY
```

Operators on an enrolled AlmaLinux 10 host can then inspect status, check a signed channel index, verify a bundle offline, dry-run, apply, or roll back both the Rust control plane and the Console Admin Panel in one command via `packaging/rustiron-updater.py`:

```sh
python3 packaging/rustiron-updater.py status
python3 packaging/rustiron-updater.py check --manifest-url https://releases.example.invalid/releases.json \
  --release-signers /etc/rustiron/release-allowed-signers --release-signer-id RELEASE_SIGNER_ID
python3 packaging/rustiron-updater.py plan --bundle rustiron-X.Y.Z-almalinux10-x86_64.tar.gz \
  --release-signers /etc/rustiron/release-allowed-signers --release-signer-id RELEASE_SIGNER_ID
python3 packaging/rustiron-updater.py apply --bundle rustiron-X.Y.Z-almalinux10-x86_64.tar.gz \
  --release-signers /etc/rustiron/release-allowed-signers --release-signer-id RELEASE_SIGNER_ID
python3 packaging/rustiron-updater.py rollback --update-dir /var/lib/rustiron/updates/STAMP --apply
```

The updater verifies both the outer bundle signature and the inner `management/SHA256SUMS.sig` in `rustiron-release-v1`, delegates core payload replacement to `packaging/update-product.py`, preserves `/etc/rustiron-console/env` and SQLite databases during Console swaps, captures `console.before.tar.gz` for rollback, refuses downgrades unless `--allow-downgrade` is passed, and requires explicit `--migrate-journal` when a release raises the journal schema version. No supported public release server exists yet.

## After a failure

A `FAILED incomplete` line names the update folder. The folder holds a copy of each changed file and the old record.
The units that the command stopped stay stopped. Compare the installed files with `update.json` in that folder before you start a unit.
