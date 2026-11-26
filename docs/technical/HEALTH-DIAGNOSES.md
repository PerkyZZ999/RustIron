# P04 host and site diagnoses

2026-11-17. Roadmap [P04](../planning/ROADMAP.md#p04--make-routine-hostsite-health-actionable).
Read-only. Diagnoses never repair, never change a host setting, and never open a port.

## Command

`rustiron-control --host-status --diagnose [--human]` diagnoses the host status. With `--merge-observation FILE` instead of `--host-status`, it also diagnoses the executor's journal observation (sites, captures, certificates). It runs as the unprivileged operator account; it needs no `sudo`.

With an observation, the merge asks the enrolled listener for at most 32 sites' identity files and PHP health. Served sites come first, then the others; a `deleted` site is never asked ([W578](../validation/S10-W578/README.md)). Proxy sites' ports are read from the kernel's listener tables, for at most 32 proxy sites.

The JSON output (`rustiron-diagnosis/1`) has a `summary` (the worst state: `fail`, then `unknown`, then `warn`, else `ok`) and one finding per check. `--human` prints one line for each finding that is not `ok`, then the counts and "Nothing was changed." `--alert-line` prints the Uptime Kuma push query of the [alert check-in](../operator/23-ALERT-CHECKIN.md) ([D-083](../decisions/D-083-alert-delivery.md)).

Each finding names:

- `check` and `state`: `ok`, `warn`, `fail`, or `unknown`. A fact that could not be read is `unknown`, with an action, never a silent pass.
- `owner`: `rustiron` for what Rustiron manages (its units, sites' backups, certificates), `host` for what it only observes (clock, SSH, firewalld, SELinux, storage, the stack's services).
- `subject`: an identifier or a number from the observation, escaped for the terminal.
- `reason` and `action`: fixed text. No file content, path from a request, or secret is printed.

## Checks

| Check | Fail | Warn | Unknown |
| --- | --- | --- | --- |
| Clock | Not synchronized | Synchronized but more than 1 s off | `timedatectl` unreadable |
| SELinux | Permissive | — | Mode unreadable |
| SSH | — | Passwords accepted; root login with a password | `sshd -T` unreadable |
| firewalld | Not running | — | State unreadable |
| Storage (`/`, space and inodes) | Under 10% free | Under 20% free | `statvfs` failed |
| Pressure | — | Memory under 10% available; five-minute load over twice the CPU count | Memory unreadable |
| Services | A failed unit, or a unit that serving or management needs is not active | Another listed unit is not active | Unit state or failed list unreadable |
| Log rotation | — | No run in two days | Last run unreadable |
| Database | MariaDB does not answer its socket | — | Not asked |
| MariaDB network ([W569](../validation/S10-W569/README.md)) | A TCP listener on 3306 beyond loopback | — | — (an older observation adds no finding) |
| Backup (each served site but a proxy site; W465, [W600](../validation/S10-W600/README.md)) | A restore probe left `cleanup_incomplete` | No succeeded capture, newest succeeded capture older than 26 h (D-010 RPO 24 h), newest succeeded capture's recorded COMPLIANCE retention lock shorter than enrolled days or expired, newest succeeded capture consistency `unmatched` (D-021), or newest restore probe `failed` | No journal observation given, or policy `retention_days` present without per-object lock evidence |
| Capture (W505, [W600](../validation/S10-W600/README.md)) | A capture is still `running` more than 15 minutes after its start ([W504](../validation/S10-W504/README.md)), or the newest capture attempt for a served site failed with a recorded backup/retention refusal code | The newest capture attempt for a served site settled `failed` with an unclaimed snapshot or failed after the last succeeded capture | — |
| Certificate (each served site) | Expired | Under 14 days left, or the last renewal failed. An ejected site's certificate has owner `host` (D-064). A failed renewal is named even when the expiry warning applies (W473) | Expiry unreadable |
| PHP (each managed site but a proxy site, W487) | The site's own PHP does not answer `/rustiron-php-health.php` with the site account ([D-073](../decisions/D-073-php-health-probe.md)) | — | The vhost has no health context (404, or a redirect from the site's own rules): rendered before D-073, or not served; the next activation adds it |
| Proxy (each port of a served proxy site, [W575](../validation/S10-W575/README.md)) | — | Nothing listens on the port at `127.0.0.1` (the service behind it is stopped; OLS answers 503), or the service also listens beyond loopback (a Docker-published port bypasses firewalld) | The kernel's listener tables were unreadable |
| App (each served P27 Node.js or Bun app, [W598](../validation/S10-W598/README.md), [W599](../validation/S10-W599/README.md)) | App systemd unit `failed` | Deployed app unit not `active` (OLS answers 503), or restart counter > 0 | Unit state unreadable |
| Packages (W485) | A package other than a kernel or a GPG key is installed twice: an interrupted dnf transaction ([W484](../validation/S10-W484/README.md)). The action is the forward repair | — | `rpm -qa` unreadable |
| Signature verifier (W483) | The installed `/usr/bin/ssh-keygen` differs from the enrolled digest: every signed request is refused | — | The executor observation has no verifier fact (an observation before W483 adds no finding) |
| Support (OS, OLS, PHP, MariaDB) | Outside the supported series, older than the reviewed minimum, or past the series' end of life ([support matrix](SUPPORT-MATRIX.md)) | Under 180 days to the end of life; the matrix is past its review date | Version unreadable, or no PHP build in the supported series |

A listed unit that is not loaded on this host (for example the lab executor on a product host) is skipped. A site's PHP pool is socket-activated: an idle pool's service is `inactive`, which is `ok`; only `failed` is a finding.

As an unprivileged account, the command cannot read `sshd -T` or ask firewalld, so those two checks report `unknown` with the operator command to run. That is the intended result: Rustiron does not widen its access to read them. Drift from the Rustiron firewall zone is checked as root with `packaging/firewall-zone.py --check` ([page 28](../operator/28-FIREWALL-ZONE.md), [W568](../validation/S10-W568/README.md)).
