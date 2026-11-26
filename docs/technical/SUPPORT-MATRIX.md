# Support matrix

2026-11-17. Decision [D-063](../decisions/D-063-support-matrix.md). Roadmap [P06](../planning/ROADMAP.md#p06--rehearse-stack-and-product-upgrades-safely).
The machine-readable copy is [`crates/control/support-matrix.json`](../../crates/control/support-matrix.json). This page explains it; the file is the source.

## Supported versions

Reviewed 2026-11-17. Next review by 2027-03-17 (120 days).

| Component | Package | Series | Minimum patch | End of life | Lab evidence |
| --- | --- | --- | --- | --- | --- |
| AlmaLinux | — | 10 | 10.2 | 2035-05-31 (security support) | AlmaLinux 10.2 on the lab hosts |
| OpenLiteSpeed | `openlitespeed` | 1.9 | 1.9.4 | None published; checked at each review | [W389](../validation/S10-W389/README.md) package change, [W426](../validation/S10-W426/README.md) cache |
| PHP | `lsphp84` | 8.4 | 8.4.27 | 2028-12-31 (upstream security support) | Every WordPress lab site |
| MariaDB | `mariadb-server` | 10.11 | 10.11.18 | 2028-02-16 (upstream LTS; the earlier date counts) | Every product lab host |
| PowerDNS Authoritative | `pdns` | 5.1 | 5.1.5 | 2028-01-01 (upstream gives about January 2028; the start of the month counts) | [W560](../validation/S10-W560/README.md) |

PowerDNS is marked `when_installed` ([W562](../validation/S10-W562/README.md)): the installer, the updater, and the diagnosis check it only where the `pdns` package is installed, which a host with the `dns` section of [D-091](../decisions/D-091-cp05-v1-scope.md) has. It comes from the pinned source of [D-092](../decisions/D-092-powerdns-source.md).

certbot comes from EPEL ([D-059](../decisions/D-059-certificates.md)). It is not in the matrix: Rustiron runs it only through its fixed issuance step, and its version does not change a host's served files.

## Rules

- **Patches.** A version in the series at or above the minimum is supported. Updates inside a series come from dnf; Rustiron does not hold them back.
- **Too old.** Below the minimum, a security update is missing. The installer and updater refuse the host. The diagnosis fails with "Apply the pending security updates with dnf."
- **Another series.** Unsupported until a new decision, a lab rehearsal, and a new matrix. Do not downgrade a database in place to return to the series.
- **End of life.** The diagnosis warns 180 days before; at the date, it fails and the installer and updater refuse.
- **Review.** The installer, updater, and diagnosis use the review date in the matrix. After 120 days, the diagnosis warns and the installer and updater refuse. Update to a Rustiron build with a reviewed matrix.

## Where it is checked

| Step | Check | Effect |
| --- | --- | --- |
| Install | `install-preflight.py` reads `rpm -q --qf '%{VERSION}'` for each package and the os-release `VERSION_ID` | Refused before any change |
| Product update | `update-product.py` checks the same with the new build's matrix | Refused before any change |
| Diagnosis | `rustiron-control --host-status --diagnose` compares the observed versions with the built-in matrix (check `support`) | Read-only finding ([diagnoses](HEALTH-DIAGNOSES.md)) |

## Stack update procedures

Each procedure runs on an enrolled product host as root. Capture each site first when the step can change data ([scheduled capture](../operator/13-SCHEDULED-CAPTURE.md)).

| Component | Procedure | Recovery when it fails |
| --- | --- | --- |
| AlmaLinux minor or patch | `dnf upgrade`, reboot, then the diagnosis and [after power loss](../operator/11-AFTER-POWER-LOSS.md) checks. When `openssh` changed, the check `verifier` fails until you [measure the verifier again](../operator/09-PRODUCT-ENROLLMENT.md#measure-the-verifier-again) (W483) | Boot the previous kernel. Packages are repaired forward, not downgraded |
| OpenLiteSpeed | [OLS package upgrade](../operator/14-OLS-UPGRADE.md) | The same page restores a changed parent; the last-known-good generation is kept |
| PHP (`lsphp84*`) | `dnf upgrade 'lsphp84*'`, then `systemctl restart 'rustiron-site-php@*.service'` and request a PHP page of each site (the identity file `/rustiron-site.txt` does not use PHP) | Forward repair. After an interrupted transaction (the diagnosis check `packages` fails): `dnf remove --duplicates`, `dnf distro-sync 'lsphp84*'`, `dnf reinstall 'lsphp84*'`, `rpm -V` the packages, then restart the site PHP services ([W484](../validation/S10-W484/README.md)). Site files are not changed by a PHP patch |
| MariaDB | Capture each site, `dnf upgrade mariadb-server`, `systemctl restart mariadb`, then `mariadb-upgrade` only when the package says so; then diagnose | Restore the captures ([D-010](../decisions/DECISIONS.md)); never `dnf downgrade mariadb-server` |
| Rustiron | [Product update](../operator/16-PRODUCT-UPDATE.md) | The same page's rollback |

A failed mid-update Rustiron update is covered by its rollback ([W409](../validation/S10-W409/README.md), [W467](../validation/S10-W467/README.md)). [W483](../validation/S10-W483/README.md) rehearsed the AlmaLinux row with a real version change, 10.2 to 10.3, on a lab product host. The PHP and MariaDB rows have not been rehearsed with a real version change: no newer package was available to the lab.
