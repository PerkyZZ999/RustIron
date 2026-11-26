# Executor host layout

Updated: 2026-11-12.
This contract lists every Rustiron-owned host location that the executor binaries compile in.
The source of the values is [`crates/executor/src/layout.rs`](../../crates/executor/src/layout.rs).
[W284](../validation/S10-W284/README.md) records the change and its checks.

The module holds two profiles: `lab` and `product`.
The default build compiles the lab profile.
A build with `--cfg rustiron_profile="product"` compiles the product profile ([W287](../validation/S10-W287/README.md)).
`rust-tc quick` builds and tests both.

The [product executor unit](../../packaging/systemd/rustiron-executor.service) starts the [admin helper unit](../../packaging/systemd/rustiron-admin-helper.service) and uses the helper for privileged steps.
[W290](../validation/S10-W290/README.md) records offline verification of these units with the coordinator.
The Cargo executor binary still builds as `rustiron-s02-executor`. The product unit expects the product-profile build at `/usr/libexec/rustiron/rustiron-executor`.
The helper unit denies IP traffic by default. A product host profile must allow only its enrolled OLS listener address for HTTP verification.
The [product staging command](../../packaging/README.md) assembles the management units and compiled policy on AlmaLinux 10.
It places the site PHP and sandbox check units under `/etc/systemd/system`, where provisioning reads the PHP templates.
The product PHP service uses a private network namespace and permits Unix sockets for LSAPI and MariaDB.
[W294](../validation/S10-W294/README.md) records checks on the staged units and sandbox checker.

## Rule

`layout.rs` is the only executor source file that names absolute Rustiron-owned host paths.
The executor, the administration helper, and the capture-manifest worker read their paths from that file.
The test `crates/executor/tests/host_layout.rs` fails when another production source line names an owned location.

No value comes from a request.
A listed path is not trusted because it is listed.
Each use keeps its ownership, ancestry, and link checks.

Locations that other software owns stay beside the code that uses them.
Examples are the OLS server root, the MariaDB socket, the LSPHP binary, and system tools.
Those locations are host-profile facts.

## Locations

| Constant | Lab value | Purpose | Product value |
| --- | --- | --- | --- |
| `POLICY_DIR` | `/etc/rustiron-s02-lab` | Root policy, signer allowlist, revocations | `/etc/rustiron` |
| `FIXTURE_REGISTRY_DIR` | `/var/lib/rustiron-s02-lab/fixture` | Lab fixture registry | None; the product build refuses the fixture verb |
| `SCRATCH_DIR` | `/var/lib/rustiron-s02-lab/scratch` | Private verifier inputs | `/var/lib/rustiron/scratch` |
| `JOURNAL_DIR` | `/var/lib/rustiron-s02-lab/executor` | Executor journal | `/var/lib/rustiron/executor` |
| `MARK_DIR` | `/var/lib/rustiron-s02-lab/admission` | Admission high-water mark | `/var/lib/rustiron/admission` |
| `RECIPES_DIR` | `/var/lib/rustiron-s04-lab/recipes` | Pinned provisioning recipes | `/var/lib/rustiron/recipes` |
| `EXECUTOR_SOCKET` | `/run/rustiron-s02-lab/executor.sock` | Submission socket | `/run/rustiron/executor.sock` |
| `ADMIN_RUNTIME_DIR` | `/run/rustiron-admin` | Helper runtime directory and job output | `/run/rustiron-admin` |
| `ADMIN_SOCKET` | `/run/rustiron-admin/helper.sock` | Helper socket | Same |
| `JOB_CREDENTIALS_DIR` | `/etc/rustiron-s07-lab/sites` | Per-site repository identities and passwords | `/etc/rustiron/credentials/sites` |
| `JOB_BIN_DIR` | `/usr/local/libexec/rustiron-s07-lab` | Capture and probe job programs | `/usr/libexec/rustiron/jobs` |
| `JOB_RESTIC` | `/usr/local/libexec/rustiron-s07-lab/restic` | restic copy for the manifest worker | Inside the job program directory |
| `JOB_MIGRATION_INVENTORY` | `/usr/local/libexec/rustiron-s07-lab/migration-inventory` | Export inventory worker for site imports (W446, D-053) | `/usr/libexec/rustiron/jobs/migration-inventory` |
| `MIGRATION_INTAKE_DIR` | `/var/lib/rustiron-s02-lab/migration-intake` | Root-only intake of site import archives (W446, D-053) | `/var/lib/rustiron/migration-intake` |
| `APP_INTAKE_DIR` | `/var/lib/rustiron-s02-lab/app-intake` | Root-only intake of prepared P27 app release bundles (W598, D-099) | `/var/lib/rustiron/app-intake` |
| `SITES_ROOT` | `/srv/sites` | Parent of each site | `/srv/sites` (kept) |
| `RESTORE_PROBES_ROOT` | `/srv/restore-probes` | Parent of each probe sandbox | `/srv/restore-probes` (kept) |
| `OLS_INCLUDE_DIR` | `/etc/rustiron-ols` | Owned OLS generations and `current` | `/etc/rustiron-ols` |
| `OLS_INCLUDE_LINE` | `include /etc/rustiron-ols/current/*.conf` | The line the reviewed parent holds | Follows `OLS_INCLUDE_DIR` |
| `OLS_EJECTED_DIR` | `/etc/rustiron-ejected` | Vhost files of ejected sites | `/etc/rustiron-ejected` |
| `SITE_PHP_UNIT_PREFIX` | `/etc/systemd/system/rustiron-site-php@` | Prefix of the pool template and site drop-ins | Same |
| `SITE_PHP_UNIT` | `/etc/systemd/system/rustiron-site-php@.service` | Pool unit template | Same |
| `SITE_APP_UNIT_PREFIX` | `/etc/systemd/system/rustiron-app@` | Prefix of the per-site modern app template and drop-ins (W598, D-099) | Same |
| `SITE_APP_WORKER_UNIT_PREFIX` | `/etc/systemd/system/rustiron-app-worker@` | Prefix of the per-site companion worker template and drop-ins (W598, D-099) | Same |
| `SITE_APP_UNIT` | `/etc/systemd/system/rustiron-app@.service` | Modern app unit template (W598, D-099) | Same |
| `SITE_APP_WORKER_UNIT` | `/etc/systemd/system/rustiron-app-worker@.service` | Companion worker unit template (W598, D-099) | Same |
| `SITE_SOCKETS_DIR` | `/run/rustiron-sites` | Per-site PHP pool sockets | Same |
| `STORE_NETNS` | `/run/netns/rustiron-store` | Endpoint-only network namespace for store jobs; the executor verifies it (W315) | Same |

[D-024](../decisions/D-024-product-host-layout.md) records the product column and its reasons.
[`policy/selinux/rustiron_executor.fc`](../../policy/selinux/rustiron_executor.fc) and the [product coordinator unit](../../packaging/systemd/rustiron-coordinator.service) already use the `/etc/rustiron`, `/var/lib/rustiron`, `/run/rustiron`, and `/usr/libexec/rustiron` roots.
The [product enrollment contract](PRODUCT-BACKUP-BINDING.md#product-executor-enrollment) defines the fixed `backup-destination.json` leaf under the product policy directory.

## Product job labels

Build the product capture module with the [product file contexts](../../packaging/selinux/rustiron_capture.fc) and the existing [capture type enforcement](../../lab/s07/selinux/rustiron_capture.te).
The file contexts assign the capture entry type to six named regular files.
The [host job staging command](../../packaging/README.md#host-job-tools) checks the three external programs against the selected RPM profile.
It prepares a separate host-local root with the verified files under `/usr/libexec/rustiron/jobs`.

The [product credential module](../../packaging/selinux/rustiron_job_credential.te) assigns a dedicated type under `/etc/rustiron/credentials/sites`.
The executor can traverse the directories and read file metadata for enrollment checks.
PID 1 can read the credential files for `LoadCredential=`.
The job reads the per-unit credential copy.
[W291](../validation/S10-W291/README.md) records the linked policy and label checks.

## Copies outside the module

Some files cannot import the module.
The test compares each copy with the module.

| Copy | Location it repeats |
| --- | --- |
| `provision_assets/install.php`, `provision_assets/verify.php` | `SITES_ROOT` |
| `crates/cli/src/submit_main.rs` default socket | `EXECUTOR_SOCKET` |
| `crates/control/src/host.rs` generation map | `OLS_INCLUDE_DIR` |
| `crates/cli/src/uninstall.rs` moved roots | `POLICY_DIR`, the state root, the recipes root, `OLS_INCLUDE_DIR` |
| `lab/s02/rustiron-s02-lab-executor.service` | Runtime directory of `EXECUTOR_SOCKET`; state root |
| `lab/s10/rustiron-s10-lab-admin-helper.service` | `ADMIN_RUNTIME_DIR` |
| `packaging/systemd/rustiron-executor.service` | Product runtime directory, state root, and OLS trees |
| `packaging/systemd/rustiron-ols-boot-guard.service` | Product state root and `OLS_INCLUDE_DIR` (D-032) |
| `packaging/systemd/rustiron-admin-helper.service` | Product `ADMIN_RUNTIME_DIR` |
| `lab/s03/rustiron-site-php@.socket` | `SITE_SOCKETS_DIR` |
| `lab/s07/selinux/rustiron_capture.fc` | `JOB_BIN_DIR`, `JOB_RESTIC` |
| `packaging/selinux/rustiron_capture.fc` | Product `JOB_BIN_DIR`, `JOB_RESTIC` |
| `packaging/selinux/rustiron_job_credential.fc` | Product `JOB_CREDENTIALS_DIR` |
| `policy/selinux/rustiron_admin.fc` | `ADMIN_RUNTIME_DIR`, `RESTORE_PROBES_ROOT` |
| `policy/selinux/rustiron_executor.fc` | `OLS_INCLUDE_DIR`, `OLS_EJECTED_DIR` |

The test does not cover these copies:

- Lab shell and Python harnesses under `lab/`.
- Lab local file contexts in `lab/s10/c07_fcontext.txt`.
- The control crate's lab executor unit name.
- The site PHP unit template body in `lab/s03/`.

A product profile must change or replace each of them.

## Limits

The product profile selects the compiled locations.
With no fixture registry, the product build refuses the fixture verb with `INVALID_REQUEST` before it reads any state.
The fixture code is still linked into that build.

The product build refuses lab v1 capture and restore probe admission with `INVALID_REQUEST`.
The helper and capture reconciliation also refuse to load the lab backup policy for repository use.
Historical status stays readable. See the [W303 verification](../validation/S10-W303/README.md).

Lab deployment uses the lab profile and paths.
The [installer preflight](../../packaging/README.md#installer-preflight) checks staged inputs, base prerequisites, and conflicts with an existing installation.
The [offline assembler](../../packaging/README.md#offline-installation-root) copies fixed payloads and creates empty, root-owned state directories.
The product admin module labels the `/srv/sites` directory as `httpd_sys_content_t:s0`.
Provisioning sets each child site's category through its existing per-site rules.
[W298](../validation/S10-W298/README.md) records the exact product mapping and linked policy checks.
Product installation still needs signer policy and a verified install procedure.
Product confinement and operation tests remain open on a clean AlmaLinux host.
