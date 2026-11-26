# Staging clone

This page describes how a signed `site_clone` creates a new staging site from one completed native capture, under [D-078](../decisions/D-078-managed-wordpress-clone.md). The scope is the disposable synthetic lab that the owner approved. A clone grants no serving, promotion, or change to the source site.

## Admission

The executor verifies the enrolled peer, the closed schema 1 plan and grant, the signature, the host and epoch, and the validity window ([W497](../validation/S10-W497/README.md)). It needs the provisioning enrollment, a loopback OLS profile, and the enrolled product destination with the signed projection digest and the source's repository pin.

The source must be a succeeded native WordPress provision under the signed hostname with no ejection. The capture must be that site's succeeded capture of the signed snapshot. It also needs an untruncated manifest with the signed digest, the `matched` consistency label, and the signed destination projection. A target with a journal claim, an enrolled adopted hostname, or an existing account, group, or site root is refused before intent.

A product build then records the clone ([W499](../validation/S10-W499/README.md), lab verified in [W500](../validation/S10-W500/README.md)). Journal v29 reserves the target site ID and hostname and rechecks the source in one transaction ([W498](../validation/S10-W498/README.md)). A lab build stops every clone at `NOT_ADMITTED_FOR_EFFECT` before intent, because the fetch needs the product store.

The plan signs no quota. The enrolled policy limits apply.

## Steps

The provision steps create the target's own account, level, quota, database, and credentials. The Recipe step holds the five clone steps, each with a durable intent before its effect. The admin helper runs each step from the journal. A failed step quarantines the provision and leaves the target unserved.

| Step | Mechanism | Check by root |
| --- | --- | --- |
| Fetch | The product store worker runs `clone-restore-size` and then `clone-restore`. It runs as the target account at the target's level in `rustiron_capture_t`, in the store namespace, with the source site's fetch key pair. The one writable path is the target's own `tmp`, and restic creates `tmp/clone` | The projection digest and the repository pin are bound again. The size and file count are within the restore probe ceilings. `tmp/clone` is a directory of the target |
| Observe | The `clone-tree` worker action lists the fetched tree in the capture manifest line format. It runs as the target in the capture domain with no network or credentials, and root receives only its stdout | Root rebuilds the canonical manifest with the capture builder. The manifest passes the capture's source and secret-shape checks, is untruncated, and has the signed digest |
| Files | An unpack job copies the fetched `html` into the target's empty `html` without following links. Then it removes the fetched `html` | The `--tree` reports of both trees are equal with no unsafe entries. Every entry is the target's and has the target's content label |
| Database | Unpack jobs move the fetched dump to `tmp/import`. The capture worker's `site-import` action imports it as the target's database user under the D-034 size watch | The dump is a single-link regular file of the target |
| Config | Root checks the restored `wp-config.php`. It replaces that file and the identity marker with new target files and prepares the ACME webroot. The bounded D-070 rewrite changes the source hostname to the target hostname in the target's database. An unpack job removes `tmp/clone` and `tmp/import` | The restored file must equal the native template with eight salts of the fixed shape. Other layouts are refused. The labels hold after the rewrite, and the leftovers are gone |

The Verify step is the import Verify. The serving units survive a boot. The site PHP reports the target's account, its own database login and tables, a site URL at the target hostname, read-only code, and no readable other site.

## Limits

- Serving needs a separate signed OLS activation. The clone grant cannot change the source, its route, DNS, or exposure.
- The Files step holds two copies of `html` in the target's quota until it removes the fetched copy.
- A failed clone keeps its names. After a failed clone step, the executor scrubs it: an unpack job removes `tmp/clone` and `tmp/import`, and root removes `html/wp-config.php` by descriptor ([W501](../validation/S10-W501/README.md)). Journal v30 records the scrub, and the helper runs it only as the open `clone_scrub` of that quarantined clone. An interrupted clone that an operator quarantined keeps its fetched tree until a signed scrub exists.
- The source keeps serving. Writes made on the source after the capture are not in the clone.
