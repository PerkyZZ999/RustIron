# After power loss

This page tells the operator of a product host what to do after a power loss, a hard reset, or a kernel crash.
It covers each verb that can be interrupted, the command that settles it, and where to run that command.
[W376](../validation/S10-W376/README.md) cut the power of a product host during six durable effects. [W381](../validation/S10-W381/README.md) proves the OLS boot guard of [D-032](../decisions/D-032-power-cut-serving-and-reply-states.md).
[W382](../validation/S10-W382/README.md) proves the bootstrap settlement of [D-033](../decisions/D-033-bootstrap-crash-settlement.md).
[W384](../validation/S10-W384/README.md) proves that a cut during the staging of a generation does not block the next activation.

The examples use `E=/usr/libexec/rustiron/rustiron-executor`. Replace `<operation>` with the operation ID.

## What starts at boot

| Unit | Starts because | What it does at boot |
| --- | --- | --- |
| `rustiron-ols-boot-guard.service` | `lshttpd.service` wants it (drop-in `51-rustiron-boot-guard.conf`) | Runs once, before OLS, the admin helper, and the executor. See [Boot guard](#boot-guard) |
| `lshttpd.service` | The OpenLiteSpeed package enables it | Serves the generation that `/etc/rustiron-ols/current` names. With no `current`, systemd skips the start (D-033), and the unit stays `inactive` with no restart loop |
| `rustiron-coordinator.service` | Enrollment enables it | Wants the executor |
| `rustiron-executor.service` | The coordinator wants it | Requires the admin helper. Opens the journal, rolls back a hot SQLite journal, and moves the admission mark up when the journal is one admission ahead |
| `rustiron-admin-helper.service` | The executor requires it | Waits for executor requests |
| `mariadb.service`, site PHP sockets | Enrollment and provisioning enable them | Serve the sites |

The services start with no operator. An interrupted operation stays in the journal as it was. No service settles it, and no service claims an outcome for it.

## Boot guard

A power cut can come after an OLS activation switched `current` and before the executor verified the new generation.
The boot guard then changes `current` before OLS starts:

| Interrupted activation | `current` at boot | Guard effect | Result |
| --- | --- | --- | --- |
| Running host (`current` existed before) | The target | Points `current` back at the journaled predecessor | OLS serves the predecessor |
| First activation (bootstrap) | The target | Removes `current` | OLS stays down |
| Any | The predecessor, or absent for a bootstrap | None | As before the activation |

In every other case, the guard changes nothing. The guard records nothing in the journal. The operation stays unresolved until you settle it.

After an interrupted `site_eject`, the admin helper checks the restored generation before OLS starts.
It starts the affected managed site's PHP socket and sandbox timer for this boot.
Use the recovery commands below to enable the units and settle the operation.

To read what the guard did at this boot:

```sh
journalctl -b -u rustiron-ols-boot-guard.service -o cat
```

The guard line has `decision` (`restore_predecessor`, `remove_current`, or `keep`), `reason` for `keep`, the `operation_id`, and `current_before` and `current_after`.
`journal_written` is always `false`.
The second line has scope `ols_boot_php_restore`.
The result `ready` means systemd reports the site socket and timer active.
If the helper reports `failed`, use the error code and the recovery commands below.

NOTE: On a host with a volatile system journal, the line is lost at the next boot. The journal row and `current` stay.

## What blocks new work

An interrupted operation blocks new work of its kind. A new request gets `UNRESOLVED_OPERATION` with no state, and the executor records nothing for it.
A `verifying` re-adoption blocks every admission.
The block ends when the recovery command records a final state.

To list the operations that are not settled, run this read-only command. The command is safe while the executor runs:

```sh
systemd-run --wait --pipe --quiet $E observe
```

Look for these states: `intent`, `needs_attention`, or `compensating` (in `operations`), `running` (in `sites`, `captures`, and `probes`), `cleanup_incomplete`, and `verifying`.

## Recovery commands

The recovery commands need the journal writer lock. Stop the executor and the coordinator first.
"Executor domain" means `systemd-run --wait --pipe --quiet $E ...`. The admin helper accepts only a peer in the executor domain.
"Root shell" means `$E ...` from a root login shell.

| Verb | Interrupted state | Admin helper | Command and place | Final state |
| --- | --- | --- | --- | --- |
| `config_activate`, `site_eject` | `intent`, `needs_attention`, or `compensating` | Running | Executor domain: `reconcile <operation> --admin-helper`, then `compensate <operation> --admin-helper` if the state is `needs_attention`. For a bootstrap activation, see [Settle a bootstrap activation](#settle-a-bootstrap-activation) | `untouched` or `failed_compensated` |
| `site_provision` | `running` | Stopped | Root shell: `quarantine-provision <operation>` | `quarantined`. The created resources stay |
| `backup_capture` | `running` | Stopped | Root shell: `capture-reconcile <operation>`. If the row stays `running` with a tagged snapshot: `capture-reconcile <operation> --settle-unclaimed` | `failed`, with an unclaimed snapshot after the settlement |
| `restore_probe` | `running` or `cleanup_incomplete` | Stopped | Root shell: `probe-cleanup <operation>` | `failed` with `leftover_resources` 0 |
| `site_readopt` | `verifying` | Running | Executor domain: `reconcile <operation> --admin-helper` | `adopted` or `refused` |

CAUTION: Run `capture-reconcile` from the root shell only. In the executor domain, SELinux refuses its unit listing, and the command fails with `PROVISION_STEP_FAILED` ([W376](../validation/S10-W376/README.md#avc-denials)).

The `compensate` command needs the signed compensation deadline of the grant. After that deadline, the executor refuses `compensate`. OLS then serves the predecessor, and the row stays `needs_attention`.

## Settle an OLS activation

1. Read the guard line: `journalctl -b -u rustiron-ols-boot-guard.service -o cat`.
2. Stop the services: `systemctl stop rustiron-coordinator.service rustiron-executor.service`.
3. Start the admin helper if it is not active: `systemctl start rustiron-admin-helper.service`.
4. Read the row: `systemd-run --wait --pipe --quiet $E status <operation>`.
5. Observe and record: `systemd-run --wait --pipe --quiet $E reconcile <operation> --admin-helper`.
6. If the state is `needs_attention`, restore: `systemd-run --wait --pipe --quiet $E compensate <operation> --admin-helper`.
7. Check the result: `systemd-run --wait --pipe --quiet $E status <operation>`. Expect `failed_compensated` or `untouched`.
8. Check OLS: `systemd-run --wait --pipe --quiet $E ols-status --admin-helper`. Expect `explained_by_journal` `true`.
9. Start the services: `systemctl start rustiron-executor.service rustiron-coordinator.service`.
10. Send a new signed request for the change, with a new operation ID.

For a bootstrap activation, read [Settle a bootstrap activation](#settle-a-bootstrap-activation) first.

## Settle a bootstrap activation

A bootstrap activation is the first `config_activate` on a host with no `current` ([W355](../validation/S10-W355/README.md)).
Its predecessor is the empty generation: no `current`, OLS stopped, and no listener. The status command shows it as `predecessor` `re3b0c44298fc1c14`.

`reconcile` asks the admin helper to confirm that state. It changes nothing. The admin helper confirms only when all of these facts hold:

- No `/etc/rustiron-ols/current` exists.
- `lshttpd.service` is `inactive` or `failed`.
- Neither the enrolled listener port nor the WebAdmin port listens.
- The parent is the reviewed one.

| Host at `reconcile` | Result |
| --- | --- |
| The facts hold, no restore mark (`compensation_attempted` `false`) | `untouched` |
| The facts hold, restore mark (`compensation_attempted` `true`) | `failed_compensated` |
| `current` names the target, or OLS runs | `needs_attention`. The admin helper log has one `ols_bootstrap` line with the facts |

After a power cut, the boot guard removed the unverified target before OLS started. Then `reconcile` records `untouched`, and you do not need `compensate`.

If `reconcile` records `needs_attention`:

1. If `compensation_attempted` is `false`, run `compensate <operation> --admin-helper` in the executor domain. It stops OLS, removes `current`, and records `failed_compensated`.
2. If `compensate` is refused (`COMPENSATION_DENIED`), the restore was spent or its deadline passed. Keep the executor and the coordinator stopped, and do these steps:
   1. Stop OLS: `systemctl stop lshttpd.service`.
   2. Remove the unverified target with the boot guard command: `systemd-run --wait --pipe --quiet $E ols-boot-guard`. Expect `"decision":"remove_current"`.
   3. Run `reconcile <operation> --admin-helper` again. Expect `failed_compensated` or `untouched`.

CAUTION: Do not remove `current` by hand. The guard command removes it only when the journal names it as the unverified target of the unsettled activation.

You do not need to stop `lshttpd` before a bootstrap activation after a reboot. With no `current`, systemd does not start it.

## Staging leftovers

A cut during the staging of an OLS activation leaves the row at `intent` with no effect mark. Settle it as in [Settle an OLS activation](#settle-an-ols-activation). `reconcile` records `untouched`.

With no effect mark, `reconcile` asks the admin helper for no step. It reads `current` and records `untouched` when `current` is the journaled predecessor. Before W384, `reconcile` asked for a reload, the admin helper refused it with `FIXTURE_BINDING_DENIED`, and the row stayed `intent`.

The cut can also leave folders under `/etc/rustiron-ols/generations`. The executor never reads them, and it never deletes them:

| Folder name | Cause | Effect on the next activation |
| --- | --- | --- |
| `<generation>.staging-<16 hex>` | A cut before the staged files were complete | None. The next activation stages the generation in a new temporary folder |
| `<generation>.quarantine-<operation>` | The folder of the target held other files, for example after a cut during the staging of a build before W384. The activation `<operation>` moved it aside | None. The activation staged the generation again |

To read what each staging did, run this command:

```sh
journalctl -u rustiron-executor.service -o cat | grep '"scope":"ols_stage"'
```

The JSON line has `operation_id`, `target`, `staged` (`written`, `reused`, `quarantined`, or an error code), `quarantined`, and `leftovers` (the folder names of the table).

You can keep the folders. To remove one, examine it first, and then remove only that folder:

```sh
ls -laZ /etc/rustiron-ols/generations/<folder>
rm -r /etc/rustiron-ols/generations/<folder>
```

CAUTION: Remove only a folder whose name has `.staging-` or `.quarantine-`. Do not remove a folder whose name is a generation ID. `current` or the journal can name it.

An activation can fail with `PROVISION_COLLISION`, with `"staged":"PROVISION_COLLISION"` in its `ols_stage` line. Then the entry under the target ID is not a folder that the executor can move aside. Examples are a link, a file, a folder with another owner, or a folder that holds a link. The operation records `untouched`.

Examine the entry. Move it out of `generations` only after you know what made it. Then send a new signed request.

## Settle other verbs

1. Stop the services: `systemctl stop rustiron-coordinator.service rustiron-executor.service rustiron-admin-helper.service`.
2. Read the row: `capture-status`, `probe-status`, or `provision <site>` in the executor domain.
3. Run the command of the verb from the [Recovery commands](#recovery-commands) table.
4. Run the command again. Expect the same final state.
5. Start the services: `systemctl start rustiron-admin-helper.service rustiron-executor.service rustiron-coordinator.service`.

For a `site_readopt`, keep the admin helper running and use `reconcile <operation> --admin-helper` in the executor domain.

## Verify the host

1. Check the units: `systemctl is-active rustiron-admin-helper.service rustiron-executor.service rustiron-coordinator.service lshttpd.service`.
2. Check the coordinator: `runuser -u rustiron-coordinator -- /usr/bin/rustiron --output json --socket /run/rustiron-coordinator/control.sock doctor`.
3. List the rows again with `observe`. Expect no row in the states of [What blocks new work](#what-blocks-new-work).
4. Request each site through the enrolled listener, for example `curl -H 'Host: <hostname>' http://127.0.0.1:8090/`.
5. Read the denials: `ausearch --input-logs -m AVC,USER_AVC,SELINUX_ERR -ts boot`.

## Limits

- The guard trusts a root-owned journal that passes the identity and admission mark checks, as the executor does.
- After a cut of a page-cache opt-in, the plugin can stay active until `compensate` removes it. The predecessor vhost has the cache module off.
- `systemctl start lshttpd.service` with no `current` starts nothing and returns success. Check the unit with `systemctl show -p ConditionResult lshttpd.service`.
- If `lshttpd` is disabled, the guard does not run at boot. A later start of `lshttpd` runs the guard, but the executor then holds the journal lease, and the guard changes nothing.
- A staging writes, syncs, and reads back each file before the rename. This check does not prove the bytes on the drive after a later loss of a volatile drive cache.
- The lab cuts do not model the loss of a volatile drive cache.
