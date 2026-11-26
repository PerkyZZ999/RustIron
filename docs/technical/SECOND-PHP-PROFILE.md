# Deliberate second PHP profile contract (P20 Slice 1)

**Status:** Slice 1 isolation, EOL matrix, and switch/rollback verifier are lab verified ([W621](../validation/S10-W621/README.md)).
Live RPM installation and mixed-version VM proof follow post-v1.0 owner package approval.
**Scope:** Closed two-profile allowlist and per-site isolation verifier in `rustiron-control --verify-php-profile`.

## Purpose

Under [D-081](../decisions/D-081-cp02-v1-scope.md), v1.0 ships with one tested PHP profile (`lsphp84`). Supporting a second PHP profile after v1.0 MUST remain deliberate and bounded:

- **No "all PHP versions" matrix (`all_php_versions_supported: false`)**.
- **No shared isolation shortcuts (`shared_isolation_shortcuts_allowed: false`)**.

## Supported profile matrix & memory cost

| Profile ID | PHP Series | Package | Binary | Upstream EOL | Incremental idle host cost |
| --- | --- | --- | --- | --- | --- |
| `php84_wp_v1` | 8.4 | `lsphp84` | `/usr/local/lsws/lsphp84/bin/lsphp` | `2028-12-31` | Baseline (`0 MiB` incremental) |
| `php85_wp_v1` | 8.5 | `lsphp85` | `/usr/local/lsws/lsphp85/bin/lsphp` | `2029-12-31` | `~38 MiB` idle pool + package disk footprint |

Any other profile identifier (`php74`, `php81`, `*`, etc.) is refused with `UNSUPPORTED_PHP_PROFILE`.

## Per-site isolation boundaries

Every site on either profile MUST keep strictly isolated:

1. Unique non-root Unix UID/GID (`rs_<site_id>`).
2. Unique SELinux MCS category pair under `rustiron_php_t` (D-019 egress denial and D-046 exec denial preserved on both profiles).
3. Unique private Unix socket under `/run/rustiron-site-php/<profile>_rs_<site_id>.sock`.
4. Unique private temporary/session directory and per-profile OPcache directory (zero cross-site or cross-version OPcache/tmp sharing).
5. Explicit systemd cgroup limits (`MemoryMax`, `CPUQuota`, `TasksMax`).

## Mixed-version switch & rollback preconditions

Switching a site from `php84_wp_v1` to `php85_wp_v1` (or rolling back) requires:

- A succeeded P03 backup capture within the last `24 h`;
- Verified PHP extension compatibility for the site's WordPress plugins/themes;
- A recorded rollback/forward-repair profile (`previous_profile` within the supported allowlist) so a failed post-switch loopback health probe restores the prior generation cleanly.

## Command interface

```sh
rustiron-control --verify-php-profile <php-profile-plan.json> [--now <unix_seconds>] [--human]
```
