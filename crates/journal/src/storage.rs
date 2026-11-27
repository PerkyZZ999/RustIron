use crate::{Intent, JournalError, Operation, RecordedState};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Row, params};
use rustiron_contracts::{Id, Timestamp, approval::Sha256Digest, local};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::Duration,
};

pub(crate) const MAX_OPERATIONS: i64 = 1000;
const MAX_DATABASE_BYTES: u64 = 16 * 1024 * 1024;
const DATABASE: &str = "fixture-journal.sqlite";
const APPLICATION_ID: i64 = 0x52494a52;
/// v2 adds the effect-attempt mark and one bounded compensation attempt;
/// v3 adds multi-step site provisions; v4 adds site ejections (an OLS
/// operation that hands one provisioned site's vhost over); v5 adds backup
/// captures; v6 adds restore probes; v7 adds admitted capture methods;
/// v8 adds the retention count copied onto a new capture;
/// v9 adds the restic summary file count and byte count for a succeeded capture;
/// v10 adds the capture artifact manifest digest and counts;
/// v11 adds the D-021 capture consistency label (W252);
/// v12 adds the D-021 option A freeze record (W257);
/// v13 binds capture and probe records to the enrolled backup policy (W300);
/// v14 keeps the tagged snapshot of an operator-settled `failed` capture as
/// unclaimed evidence (W366);
/// v15 binds a `config_activate` v2 operation to its page-cache opt-in site
/// (W368);
/// v16 binds a `config_activate` v3 operation to its page-cache opt-out site
/// (W370);
/// v17 adds re-adoption (W372, D-030): the `readoptions` record, the
/// `adopted` provision state (a rebuild of `provisions`, because SQLite
/// cannot change a `CHECK`), the adopted site's allocations, the one
/// generation adoption and the signed allocation floors;
/// v18 adds the capture refusal code and the per-version retention evidence
/// that the product lock reader read back (W391, D-041);
/// v19 adds the recipe of a page-cache change that does not use the W368
/// recipe (W395, D-044: the cache-on recipe);
/// v20 adds the exact canonical plan and grant bytes of each admission, with
/// the verified signer facts (W396, D-045);
/// v21 adds site imports (W442, D-053): the signed dry-run facts of an
/// import provision and its import steps;
/// v22 adds import scrubs (D-057): the removal of an ended import's
/// leftover secrets, after a failed import step or by a signed scrub;
/// v23 adds site certificates (W462, D-059);
/// v24 adds their standing renewal grants and renewals (W464, D-060);
/// v25 adds the source hostname of an import that serves the site under
/// another hostname (D-070);
/// v26 lets an import have no database dump (D-074: a static site), a
/// rebuild of `imports`, because SQLite cannot change a `CHECK`;
/// v27 records one static import alias and its reservation (D-075).
/// v28 records the second exact DNS name in a signed certificate intent (D-077);
/// v29 adds staging clones (W498, D-078): the signed source facts of a clone
/// provision and its clone steps;
/// v30 records the scrub after a failed clone step (W501, D-078);
/// v31 records the signed retirement of a quarantined site (W508, D-080);
/// v32 records signed plugin and theme updates (W514, D-084);
/// v33 records the signed deletion of a live site and its provision state
/// `deleted` (W521, D-085), a rebuild of `provisions`;
/// v34 admits the update component kind `core` (W526, D-086), a rebuild of
/// `update_components`;
/// v35 records signed changes of a site's quota (W534, D-088);
/// v36 records signed scrubs of a quarantined clone (W538, D-078);
/// v37 records signed restores of a live site (W542, D-089);
/// v38 records signed DNS zone imports (W552, D-091);
/// v39 records signed DNS record changes (W554, D-091);
/// v40 records the routes of proxy site provisions (W572, D-095);
/// v41 admits a deletion without a capture, for a proxy site (W576,
/// D-095), a rebuild of `deletions`;
/// v42 records the hostname of a single-name static ejection (W587, D-097);
/// v43 records P27 modern app provisions, releases, steps, and lifecycles (W597, D-099);
/// v44 records P13 signed site credential rotations (W608, D-100);
/// v45 records D-102 full-stack app topologies, Caddy generations, and app DB targets (W656).
const SCHEMA_VERSION: i64 = 45;
/// The first version whose `apps`/`app_releases`/`credential_rotations` admit
/// `static_v1` and app DB rotation targets and append `app_fullstack_specs` / `caddy_generations`.
const FULLSTACK_APPS_VERSION: i64 = 45;
/// The first version that has `apps` and `app_releases` (D-099).
const APPS_VERSION: i64 = 43;
/// The first version that has `credential_rotations` (D-100).
const CREDENTIAL_ROTATE_VERSION: i64 = 44;
/// `apps` as versions 43 and 44 created it; validated before migration.
const LEGACY_APPS: &str = "CREATE TABLE apps (operation_id TEXT PRIMARY KEY REFERENCES provisions(operation_id), runtime TEXT NOT NULL CHECK(runtime IN ('node_22_v1','bun_1_v1')), port INTEGER NOT NULL CHECK(port BETWEEN 1024 AND 65535 AND port<>3306), entrypoint TEXT NOT NULL CHECK(length(entrypoint) BETWEEN 1 AND 128), worker_entrypoint TEXT CHECK(worker_entrypoint IS NULL OR length(worker_entrypoint) BETWEEN 1 AND 128), health_path TEXT NOT NULL CHECK(length(health_path) BETWEEN 1 AND 128 AND health_path GLOB '/*'), env_keys TEXT NOT NULL CHECK(length(env_keys)<=4200 AND env_keys NOT GLOB '*[^A-Z0-9_,]*'), memory_max_mib INTEGER NOT NULL CHECK(memory_max_mib BETWEEN 64 AND 8192), tasks_max INTEGER NOT NULL CHECK(tasks_max BETWEEN 16 AND 1024), quota_mib INTEGER NOT NULL CHECK(quota_mib BETWEEN 128 AND 65536)) STRICT";
/// `app_releases` as versions 43 and 44 created it; validated before migration.
const LEGACY_APP_RELEASES: &str = "CREATE TABLE app_releases (operation_id TEXT PRIMARY KEY, site_id TEXT NOT NULL REFERENCES provisions(site_id), release_id TEXT NOT NULL CHECK(length(release_id) BETWEEN 1 AND 64), runtime TEXT NOT NULL CHECK(runtime IN ('node_22_v1','bun_1_v1')), artifact_sha256 TEXT NOT NULL CHECK(length(artifact_sha256)=64 AND artifact_sha256 NOT GLOB '*[^0-9a-f]*'), manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256)=64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'), file_count INTEGER NOT NULL CHECK(file_count BETWEEN 1 AND 50000), total_bytes INTEGER NOT NULL CHECK(total_bytes BETWEEN 1 AND 536870912), migration_entrypoint TEXT CHECK(migration_entrypoint IS NULL OR length(migration_entrypoint) BETWEEN 1 AND 128), capture_operation_id TEXT REFERENCES captures(operation_id), health_path TEXT NOT NULL CHECK(length(health_path) BETWEEN 1 AND 128 AND health_path GLOB '/*'), idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL CHECK(length(plan_digest)=64 AND plan_digest NOT GLOB '*[^0-9a-f]*'), grant_digest TEXT NOT NULL CHECK(length(grant_digest)=64 AND grant_digest NOT GLOB '*[^0-9a-f]*'), expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('intent','done','rolled_back')), UNIQUE(site_id, release_id)) STRICT";
/// `credential_rotations` as version 44 created it; validated before migration.
const LEGACY_CREDENTIAL_ROTATIONS: &str = "CREATE TABLE credential_rotations (operation_id TEXT PRIMARY KEY, site_id TEXT NOT NULL REFERENCES provisions(site_id), hostname TEXT NOT NULL CHECK(length(hostname) BETWEEN 1 AND 253 AND hostname NOT GLOB '*[^a-z0-9.-]*'), target TEXT NOT NULL CHECK(target='mariadb_user_password'), idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL CHECK(length(plan_digest)=64 AND plan_digest NOT GLOB '*[^0-9a-f]*'), grant_digest TEXT NOT NULL CHECK(length(grant_digest)=64 AND grant_digest NOT GLOB '*[^0-9a-f]*'), expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('intent','done','failed_compensated','needs_attention','failed'))) STRICT";
/// The first version whose `deletions` admits no capture (W576).
const NULLABLE_DELETE_CAPTURE_VERSION: i64 = 41;
/// `deletions` as versions 33 to 40 created it; validated before migration.
const LEGACY_DELETIONS: &str = "CREATE TABLE deletions (operation_id TEXT PRIMARY KEY, provision_operation_id TEXT NOT NULL REFERENCES provisions(operation_id), capture_operation_id TEXT NOT NULL REFERENCES captures(operation_id), idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL CHECK(length(plan_digest)=64 AND plan_digest NOT GLOB '*[^0-9a-f]*'), grant_digest TEXT NOT NULL CHECK(length(grant_digest)=64 AND grant_digest NOT GLOB '*[^0-9a-f]*'), expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('intent','done','failed'))) STRICT";
/// The first version whose `provisions` table admits the `adopted` state.
const ADOPTED_STATE_VERSION: i64 = 17;
/// The first version whose `provisions` table admits the `deleted` state (D-085).
const DELETED_STATE_VERSION: i64 = 33;
/// The first version that has `update_components` (D-084).
const UPDATES_VERSION: i64 = 32;
/// The first version whose `update_components` admits the kind `core` (D-086).
const CORE_UPDATE_VERSION: i64 = 34;
/// `update_components` as versions 32 and 33 created it; validated before
/// migration.
const LEGACY_UPDATE_COMPONENTS: &str = "CREATE TABLE update_components (operation_id TEXT NOT NULL REFERENCES updates(operation_id), position INTEGER NOT NULL CHECK(position BETWEEN 0 AND 7), kind TEXT NOT NULL CHECK(kind IN ('plugin','theme')), slug TEXT NOT NULL CHECK(length(slug) BETWEEN 1 AND 64 AND slug NOT GLOB '*[^a-z0-9_-]*' AND slug NOT GLOB '[-_]*'), from_version TEXT NOT NULL CHECK(length(from_version) BETWEEN 1 AND 32 AND from_version NOT GLOB '*[^0-9A-Za-z.-]*' AND from_version GLOB '[0-9]*'), to_version TEXT NOT NULL CHECK(length(to_version) BETWEEN 1 AND 32 AND to_version NOT GLOB '*[^0-9A-Za-z.-]*' AND to_version GLOB '[0-9]*' AND to_version<>from_version), PRIMARY KEY(operation_id, position), UNIQUE(operation_id, kind, slug)) STRICT";
/// `provisions` as versions 17 to 32 created it; validated before migration.
const ADOPTED_PROVISIONS: &str = "CREATE TABLE provisions (operation_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL, grant_digest TEXT NOT NULL, host_id TEXT NOT NULL, host_epoch TEXT NOT NULL, site_id TEXT NOT NULL UNIQUE, hostname TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('running','succeeded','quarantined','adopted'))) STRICT";
/// `provisions` as versions 3 to 16 created it; validated before migration.
const LEGACY_PROVISIONS: &str = "CREATE TABLE provisions (operation_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL, grant_digest TEXT NOT NULL, host_id TEXT NOT NULL, host_epoch TEXT NOT NULL, site_id TEXT NOT NULL UNIQUE, hostname TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('running','succeeded','quarantined'))) STRICT";
/// The first version that has `imports` (D-053).
const IMPORTS_VERSION: i64 = 21;
/// The first version whose `imports` table admits a dump size of 0 (D-074).
const STATIC_IMPORT_VERSION: i64 = 26;
/// `imports` as versions 21 to 25 created it; validated before migration.
const LEGACY_IMPORTS: &str = "CREATE TABLE imports (operation_id TEXT PRIMARY KEY REFERENCES provisions(operation_id), archive_sha256 TEXT NOT NULL CHECK(length(archive_sha256)=64 AND archive_sha256 NOT GLOB '*[^0-9a-f]*'), manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256)=64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'), file_entries INTEGER NOT NULL CHECK(file_entries BETWEEN 1 AND 200000), file_bytes INTEGER NOT NULL CHECK(file_bytes>=0), dump_bytes INTEGER NOT NULL CHECK(dump_bytes BETWEEN 1 AND 2147483648), target_php TEXT NOT NULL CHECK(length(target_php) BETWEEN 3 AND 4 AND target_php GLOB '[5-9].[0-9]*' AND substr(target_php,3) NOT GLOB '*[^0-9]*')) STRICT";
/// Supported in-place migration sources and how many `SCHEMA` entries each
/// has; later entries are only ever appended.
const MIGRATION_SOURCES: [(i64, usize); 42] = [
    (3, 6),
    (4, 7),
    (5, 9),
    (6, 11),
    (7, 12),
    (8, 13),
    (9, 14),
    (10, 15),
    (11, 16),
    (12, 17),
    (13, 19),
    (14, 20),
    (15, 21),
    (16, 22),
    (17, 28),
    (18, 31),
    (19, 32),
    (20, 34),
    (21, 36),
    (22, 38),
    (23, 40),
    (24, 43),
    (25, 44),
    (26, 44),
    (27, 46),
    (28, 47),
    (29, 49),
    (30, 50),
    (31, 52),
    (32, 57),
    (33, 59),
    (34, 59),
    (35, 61),
    (36, 63),
    (37, 68),
    (38, 70),
    (39, 73),
    (40, 74),
    (41, 74),
    (42, 75),
    (43, 81),
    (44, 83),
];
const SCHEMA: [(&str, &str); 86] = [
    (
        "metadata",
        "CREATE TABLE metadata (singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL CHECK(version=1), host_id TEXT NOT NULL, host_epoch TEXT NOT NULL, last_time INTEGER NOT NULL CHECK(last_time>=0)) STRICT",
    ),
    (
        "operations",
        "CREATE TABLE operations (operation_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL, grant_digest TEXT NOT NULL, host_id TEXT NOT NULL, host_epoch TEXT NOT NULL, resource_id TEXT NOT NULL, predecessor_generation TEXT NOT NULL, predecessor_digest TEXT NOT NULL, target_generation TEXT NOT NULL, target_digest TEXT NOT NULL, expires_at INTEGER NOT NULL CHECK(expires_at>=0), compensation_valid_until INTEGER NOT NULL CHECK(compensation_valid_until>=expires_at), state TEXT NOT NULL CHECK(state IN ('intent','succeeded','untouched','needs_attention','compensating','failed_compensated')), effect_attempted INTEGER NOT NULL CHECK(effect_attempted IN (0,1)), compensation_attempts INTEGER NOT NULL CHECK(compensation_attempts IN (0,1))) STRICT",
    ),
    (
        "one_unresolved",
        "CREATE UNIQUE INDEX one_unresolved ON operations((1)) WHERE state IN ('intent','needs_attention','compensating')",
    ),
    (
        "provisions",
        "CREATE TABLE provisions (operation_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL, grant_digest TEXT NOT NULL, host_id TEXT NOT NULL, host_epoch TEXT NOT NULL, site_id TEXT NOT NULL UNIQUE, hostname TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('running','succeeded','quarantined','adopted','deleted'))) STRICT",
    ),
    (
        "provision_steps",
        "CREATE TABLE provision_steps (operation_id TEXT NOT NULL REFERENCES provisions(operation_id), position INTEGER NOT NULL CHECK(position BETWEEN 0 AND 7), state TEXT NOT NULL CHECK(state IN ('intent','done','failed')), resource TEXT NOT NULL CHECK(length(resource) BETWEEN 1 AND 256), PRIMARY KEY(operation_id, position)) STRICT",
    ),
    (
        "one_running_provision",
        "CREATE UNIQUE INDEX one_running_provision ON provisions((1)) WHERE state='running'",
    ),
    (
        "ejections",
        "CREATE TABLE ejections (operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id), site_id TEXT NOT NULL REFERENCES provisions(site_id)) STRICT",
    ),
    (
        "captures",
        "CREATE TABLE captures (operation_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL, grant_digest TEXT NOT NULL, host_id TEXT NOT NULL, host_epoch TEXT NOT NULL, site_id TEXT NOT NULL REFERENCES provisions(site_id), expires_at INTEGER NOT NULL CHECK(expires_at>=0), started_at INTEGER NOT NULL CHECK(started_at>=0), state TEXT NOT NULL CHECK(state IN ('running','succeeded','failed')), snapshot_id TEXT CHECK(snapshot_id IS NULL OR length(snapshot_id)=64), finished_at INTEGER CHECK(finished_at IS NULL OR finished_at>=started_at)) STRICT",
    ),
    (
        "one_running_capture",
        "CREATE UNIQUE INDEX one_running_capture ON captures((1)) WHERE state='running'",
    ),
    (
        "restore_probes",
        "CREATE TABLE restore_probes (operation_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL, grant_digest TEXT NOT NULL, host_id TEXT NOT NULL, host_epoch TEXT NOT NULL, site_id TEXT NOT NULL REFERENCES provisions(site_id), snapshot_id TEXT NOT NULL CHECK(length(snapshot_id)=64), probe_account TEXT NOT NULL UNIQUE CHECK(length(probe_account)=9), expires_at INTEGER NOT NULL CHECK(expires_at>=0), started_at INTEGER NOT NULL CHECK(started_at>=0), state TEXT NOT NULL CHECK(state IN ('running','passed','failed','cleanup_incomplete')), receipt TEXT CHECK(receipt IS NULL OR length(receipt)<=16384), finished_at INTEGER CHECK(finished_at IS NULL OR finished_at>=started_at)) STRICT",
    ),
    (
        "one_running_probe",
        "CREATE UNIQUE INDEX one_running_probe ON restore_probes((1)) WHERE state='running'",
    ),
    (
        "capture_methods",
        "CREATE TABLE capture_methods (operation_id TEXT PRIMARY KEY REFERENCES captures(operation_id), method TEXT NOT NULL CHECK(method='site_files_db_v1')) STRICT",
    ),
    (
        "capture_retention",
        "CREATE TABLE capture_retention (operation_id TEXT PRIMARY KEY REFERENCES captures(operation_id), retention_days INTEGER NOT NULL CHECK(retention_days BETWEEN 1 AND 3650)) STRICT",
    ),
    (
        "capture_extent",
        "CREATE TABLE capture_extent (operation_id TEXT PRIMARY KEY REFERENCES captures(operation_id), files INTEGER NOT NULL CHECK(files>=0), bytes INTEGER NOT NULL CHECK(bytes>=0)) STRICT",
    ),
    (
        "capture_manifest",
        "CREATE TABLE capture_manifest (operation_id TEXT PRIMARY KEY REFERENCES captures(operation_id), manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256)=64), entries INTEGER NOT NULL CHECK(entries BETWEEN 0 AND 200000), regular_bytes INTEGER NOT NULL CHECK(regular_bytes>=0), truncated INTEGER NOT NULL CHECK(truncated IN (0,1))) STRICT",
    ),
    (
        "capture_consistency",
        "CREATE TABLE capture_consistency (operation_id TEXT PRIMARY KEY REFERENCES captures(operation_id), label TEXT NOT NULL CHECK(label IN ('matched','unmatched')), reason TEXT CHECK((label='matched' AND reason IS NULL) OR (label='unmatched' AND reason IS NOT NULL AND reason IN ('database_changed','marker_unavailable')))) STRICT",
    ),
    (
        "capture_freeze",
        "CREATE TABLE capture_freeze (operation_id TEXT PRIMARY KEY REFERENCES captures(operation_id), held INTEGER CHECK(held IS NULL OR held IN (0,1))) STRICT",
    ),
    (
        "capture_backup_policy",
        "CREATE TABLE capture_backup_policy (operation_id TEXT PRIMARY KEY REFERENCES captures(operation_id), digest TEXT NOT NULL CHECK(length(digest)=64 AND digest NOT GLOB '*[^0-9a-f]*')) STRICT",
    ),
    (
        "probe_backup_policy",
        "CREATE TABLE probe_backup_policy (operation_id TEXT PRIMARY KEY REFERENCES restore_probes(operation_id), digest TEXT NOT NULL CHECK(length(digest)=64 AND digest NOT GLOB '*[^0-9a-f]*')) STRICT",
    ),
    (
        "capture_unclaimed",
        "CREATE TABLE capture_unclaimed (operation_id TEXT PRIMARY KEY REFERENCES captures(operation_id), snapshot_id TEXT NOT NULL CHECK(length(snapshot_id)=64 AND snapshot_id NOT GLOB '*[^0-9a-f]*')) STRICT",
    ),
    (
        "page_cache_optins",
        "CREATE TABLE page_cache_optins (operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id), site_id TEXT NOT NULL REFERENCES provisions(site_id), recipe TEXT NOT NULL CHECK(recipe='litespeed_cache_793_v1')) STRICT",
    ),
    (
        "page_cache_optouts",
        "CREATE TABLE page_cache_optouts (operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id), site_id TEXT NOT NULL REFERENCES provisions(site_id), recipe TEXT NOT NULL CHECK(recipe='litespeed_cache_793_v1')) STRICT",
    ),
    (
        "readoptions",
        "CREATE TABLE readoptions (operation_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL CHECK(length(plan_digest)=64), grant_digest TEXT NOT NULL CHECK(length(grant_digest)=64), host_id TEXT NOT NULL, host_epoch TEXT NOT NULL, form TEXT NOT NULL CHECK(form IN ('site','generation')), site_id TEXT, hostname TEXT, previous_epoch TEXT NOT NULL, evidence_sha256 TEXT NOT NULL CHECK(length(evidence_sha256)=64), expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('verifying','adopted','refused')), facts TEXT CHECK(facts IS NULL OR length(facts) BETWEEN 2 AND 4096), refusal TEXT CHECK(refusal IS NULL OR refusal IN ('READOPT_MISMATCH','OLS_DRIFT')), rule TEXT CHECK(rule IS NULL OR (length(rule) BETWEEN 1 AND 64 AND rule NOT GLOB '*[^a-z_]*')), plan TEXT NOT NULL CHECK(length(plan) BETWEEN 2 AND 65536), CHECK((form='site')=(site_id IS NOT NULL AND hostname IS NOT NULL) AND (form='generation')=(site_id IS NULL AND hostname IS NULL)), CHECK((state='verifying' AND facts IS NULL AND refusal IS NULL AND rule IS NULL) OR (state='adopted' AND facts IS NOT NULL AND refusal IS NULL AND rule IS NULL) OR (state='refused' AND facts IS NOT NULL AND refusal IS NOT NULL AND rule IS NOT NULL))) STRICT",
    ),
    (
        "one_verifying_readoption",
        "CREATE UNIQUE INDEX one_verifying_readoption ON readoptions((1)) WHERE state='verifying'",
    ),
    (
        "provision_adoptions",
        "CREATE TABLE provision_adoptions (operation_id TEXT PRIMARY KEY REFERENCES provisions(operation_id), uid INTEGER NOT NULL CHECK(uid BETWEEN 1 AND 4294967294), category INTEGER NOT NULL CHECK(category BETWEEN 0 AND 1023), quota_kib INTEGER NOT NULL CHECK(quota_kib>0), quota_inodes INTEGER NOT NULL CHECK(quota_inodes>0)) STRICT",
    ),
    (
        "ols_adoptions",
        "CREATE TABLE ols_adoptions (operation_id TEXT PRIMARY KEY REFERENCES readoptions(operation_id), generation TEXT NOT NULL CHECK(length(generation) BETWEEN 1 AND 64), digest TEXT NOT NULL CHECK(length(digest)=64 AND digest NOT GLOB '*[^0-9a-f]*')) STRICT",
    ),
    (
        "one_ols_adoption",
        "CREATE UNIQUE INDEX one_ols_adoption ON ols_adoptions((1))",
    ),
    (
        "allocation_floors",
        "CREATE TABLE allocation_floors (operation_id TEXT PRIMARY KEY REFERENCES readoptions(operation_id), uid INTEGER NOT NULL CHECK(uid BETWEEN 1 AND 4294967294), category INTEGER NOT NULL CHECK(category BETWEEN 0 AND 1023)) STRICT",
    ),
    (
        "capture_refusals",
        "CREATE TABLE capture_refusals (operation_id TEXT PRIMARY KEY REFERENCES captures(operation_id), code TEXT NOT NULL CHECK(length(code) BETWEEN 1 AND 64 AND code NOT GLOB '*[^A-Z0-9_]*')) STRICT",
    ),
    (
        "capture_lock_checks",
        "CREATE TABLE capture_lock_checks (operation_id TEXT PRIMARY KEY REFERENCES captures(operation_id), before_mode TEXT NOT NULL CHECK(before_mode='COMPLIANCE'), before_days INTEGER NOT NULL CHECK(before_days BETWEEN 1 AND 36500), after_mode TEXT NOT NULL CHECK(after_mode='COMPLIANCE'), after_days INTEGER NOT NULL CHECK(after_days BETWEEN 1 AND 36500), objects INTEGER NOT NULL CHECK(objects BETWEEN 1 AND 1024)) STRICT",
    ),
    (
        "capture_object_retention",
        "CREATE TABLE capture_object_retention (operation_id TEXT NOT NULL REFERENCES capture_lock_checks(operation_id), position INTEGER NOT NULL CHECK(position BETWEEN 0 AND 1023), kind TEXT NOT NULL CHECK(kind IN ('snapshot','index','pack')), object_id TEXT NOT NULL CHECK(length(object_id)=64 AND object_id NOT GLOB '*[^0-9a-f]*'), version_id TEXT NOT NULL CHECK(length(version_id) BETWEEN 1 AND 128 AND version_id NOT GLOB '*[^A-Za-z0-9._-]*' AND version_id<>'null'), mode TEXT NOT NULL CHECK(mode='COMPLIANCE'), retain_until INTEGER NOT NULL CHECK(retain_until>=0), PRIMARY KEY(operation_id, position)) STRICT, WITHOUT ROWID",
    ),
    (
        "page_cache_recipes",
        "CREATE TABLE page_cache_recipes (operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id), recipe TEXT NOT NULL CHECK(recipe='litespeed_cache_793_cache_on_v1')) STRICT",
    ),
    (
        "signed_objects",
        "CREATE TABLE signed_objects (sha256 TEXT PRIMARY KEY CHECK(length(sha256)=64 AND sha256 NOT GLOB '*[^0-9a-f]*'), canonical TEXT NOT NULL CHECK(length(CAST(canonical AS BLOB)) BETWEEN 2 AND 8192)) STRICT, WITHOUT ROWID",
    ),
    (
        "admission_signatures",
        "CREATE TABLE admission_signatures (operation_id TEXT PRIMARY KEY, plan_sha256 TEXT NOT NULL CHECK(length(plan_sha256)=64 AND plan_sha256 NOT GLOB '*[^0-9a-f]*'), plan_bytes INTEGER NOT NULL CHECK(plan_bytes BETWEEN 2 AND 262144), grant_sha256 TEXT NOT NULL CHECK(length(grant_sha256)=64 AND grant_sha256 NOT GLOB '*[^0-9a-f]*'), grant_bytes INTEGER NOT NULL CHECK(grant_bytes BETWEEN 2 AND 262144), issuer TEXT NOT NULL CHECK(length(issuer) BETWEEN 1 AND 64), signer_policy_epoch TEXT NOT NULL CHECK(length(signer_policy_epoch) BETWEEN 1 AND 64), verification TEXT NOT NULL CHECK(verification='sshsig_verified')) STRICT",
    ),
    (
        "imports",
        "CREATE TABLE imports (operation_id TEXT PRIMARY KEY REFERENCES provisions(operation_id), archive_sha256 TEXT NOT NULL CHECK(length(archive_sha256)=64 AND archive_sha256 NOT GLOB '*[^0-9a-f]*'), manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256)=64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'), file_entries INTEGER NOT NULL CHECK(file_entries BETWEEN 1 AND 200000), file_bytes INTEGER NOT NULL CHECK(file_bytes>=0), dump_bytes INTEGER NOT NULL CHECK(dump_bytes BETWEEN 0 AND 2147483648), target_php TEXT NOT NULL CHECK(length(target_php) BETWEEN 3 AND 4 AND target_php GLOB '[5-9].[0-9]*' AND substr(target_php,3) NOT GLOB '*[^0-9]*')) STRICT",
    ),
    (
        "import_steps",
        "CREATE TABLE import_steps (operation_id TEXT NOT NULL REFERENCES imports(operation_id), position INTEGER NOT NULL CHECK(position BETWEEN 0 AND 5), state TEXT NOT NULL CHECK(state IN ('intent','done','failed')), PRIMARY KEY(operation_id, position)) STRICT",
    ),
    (
        "import_scrubs",
        "CREATE TABLE import_scrubs (operation_id TEXT PRIMARY KEY, import_operation_id TEXT NOT NULL REFERENCES imports(operation_id), origin TEXT NOT NULL CHECK(origin IN ('failed_step','signed')), idempotency_key TEXT UNIQUE, grant_id TEXT UNIQUE, nonce TEXT UNIQUE, plan_digest TEXT CHECK(plan_digest IS NULL OR (length(plan_digest)=64 AND plan_digest NOT GLOB '*[^0-9a-f]*')), grant_digest TEXT CHECK(grant_digest IS NULL OR (length(grant_digest)=64 AND grant_digest NOT GLOB '*[^0-9a-f]*')), expires_at INTEGER CHECK(expires_at IS NULL OR expires_at>=0), state TEXT NOT NULL CHECK(state IN ('intent','done','failed')), CHECK((origin='failed_step' AND operation_id=import_operation_id AND idempotency_key IS NULL AND grant_id IS NULL AND nonce IS NULL AND plan_digest IS NULL AND grant_digest IS NULL AND expires_at IS NULL) OR (origin='signed' AND operation_id<>import_operation_id AND idempotency_key IS NOT NULL AND grant_id IS NOT NULL AND nonce IS NOT NULL AND plan_digest IS NOT NULL AND grant_digest IS NOT NULL AND expires_at IS NOT NULL))) STRICT",
    ),
    (
        "one_open_scrub",
        "CREATE UNIQUE INDEX one_open_scrub ON import_scrubs(import_operation_id) WHERE state='intent'",
    ),
    (
        "certificates",
        "CREATE TABLE certificates (operation_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL CHECK(length(plan_digest)=64 AND plan_digest NOT GLOB '*[^0-9a-f]*'), grant_digest TEXT NOT NULL CHECK(length(grant_digest)=64 AND grant_digest NOT GLOB '*[^0-9a-f]*'), site_id TEXT NOT NULL REFERENCES provisions(site_id), hostname TEXT NOT NULL, expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('intent','installed','failed')), certificate_sha256 TEXT CHECK(certificate_sha256 IS NULL OR (length(certificate_sha256)=64 AND certificate_sha256 NOT GLOB '*[^0-9a-f]*')), not_after INTEGER CHECK(not_after IS NULL OR not_after>=0), CHECK((state='installed') = (certificate_sha256 IS NOT NULL AND not_after IS NOT NULL))) STRICT",
    ),
    (
        "one_open_certificate",
        "CREATE UNIQUE INDEX one_open_certificate ON certificates((1)) WHERE state='intent'",
    ),
    (
        "certificate_grants",
        "CREATE TABLE certificate_grants (operation_id TEXT PRIMARY KEY REFERENCES certificates(operation_id), renew_until INTEGER NOT NULL CHECK(renew_until>=0)) STRICT",
    ),
    (
        "certificate_renewals",
        "CREATE TABLE certificate_renewals (renewal_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL REFERENCES certificates(operation_id), started_at INTEGER NOT NULL CHECK(started_at>=0), state TEXT NOT NULL CHECK(state IN ('intent','installed','failed')), certificate_sha256 TEXT CHECK(certificate_sha256 IS NULL OR (length(certificate_sha256)=64 AND certificate_sha256 NOT GLOB '*[^0-9a-f]*')), not_after INTEGER CHECK(not_after IS NULL OR not_after>=0), CHECK((state='installed') = (certificate_sha256 IS NOT NULL AND not_after IS NOT NULL))) STRICT",
    ),
    (
        "one_open_renewal",
        "CREATE UNIQUE INDEX one_open_renewal ON certificate_renewals((1)) WHERE state='intent'",
    ),
    (
        "import_sources",
        "CREATE TABLE import_sources (operation_id TEXT PRIMARY KEY REFERENCES imports(operation_id), source_hostname TEXT NOT NULL CHECK(length(source_hostname) BETWEEN 1 AND 253 AND source_hostname NOT GLOB '*[^a-z0-9.-]*')) STRICT",
    ),
    (
        "import_aliases",
        "CREATE TABLE import_aliases (operation_id TEXT PRIMARY KEY REFERENCES imports(operation_id), hostname TEXT NOT NULL CHECK(length(hostname) BETWEEN 1 AND 253 AND hostname NOT GLOB '*[^a-z0-9.-]*'), released INTEGER NOT NULL CHECK(released IN (0,1))) STRICT",
    ),
    (
        "active_import_alias",
        "CREATE UNIQUE INDEX active_import_alias ON import_aliases(hostname) WHERE released=0",
    ),
    (
        "certificate_aliases",
        "CREATE TABLE certificate_aliases (operation_id TEXT PRIMARY KEY REFERENCES certificates(operation_id), hostname TEXT NOT NULL CHECK(length(hostname) BETWEEN 1 AND 253 AND hostname NOT GLOB '*[^a-z0-9.-]*')) STRICT",
    ),
    (
        "clones",
        "CREATE TABLE clones (operation_id TEXT PRIMARY KEY REFERENCES provisions(operation_id), source_site_id TEXT NOT NULL REFERENCES provisions(site_id), source_hostname TEXT NOT NULL CHECK(length(source_hostname) BETWEEN 1 AND 253 AND source_hostname NOT GLOB '*[^a-z0-9.-]*'), capture_operation_id TEXT NOT NULL REFERENCES captures(operation_id), snapshot_id TEXT NOT NULL CHECK(length(snapshot_id)=64 AND snapshot_id NOT GLOB '*[^0-9a-f]*'), manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256)=64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'), destination_policy_digest TEXT NOT NULL CHECK(length(destination_policy_digest)=64 AND destination_policy_digest NOT GLOB '*[^0-9a-f]*'), repository_id TEXT NOT NULL CHECK(length(repository_id)=64 AND repository_id NOT GLOB '*[^0-9a-f]*')) STRICT",
    ),
    (
        "clone_steps",
        "CREATE TABLE clone_steps (operation_id TEXT NOT NULL REFERENCES clones(operation_id), position INTEGER NOT NULL CHECK(position BETWEEN 0 AND 4), state TEXT NOT NULL CHECK(state IN ('intent','done','failed')), PRIMARY KEY(operation_id, position)) STRICT",
    ),
    (
        "clone_scrubs",
        "CREATE TABLE clone_scrubs (operation_id TEXT PRIMARY KEY REFERENCES clones(operation_id), state TEXT NOT NULL CHECK(state IN ('intent','done','failed'))) STRICT",
    ),
    (
        "retirements",
        "CREATE TABLE retirements (operation_id TEXT PRIMARY KEY, provision_operation_id TEXT NOT NULL REFERENCES provisions(operation_id), idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL CHECK(length(plan_digest)=64 AND plan_digest NOT GLOB '*[^0-9a-f]*'), grant_digest TEXT NOT NULL CHECK(length(grant_digest)=64 AND grant_digest NOT GLOB '*[^0-9a-f]*'), expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('intent','done','failed'))) STRICT",
    ),
    (
        "one_retirement",
        "CREATE UNIQUE INDEX one_retirement ON retirements(provision_operation_id) WHERE state<>'failed'",
    ),
    (
        "updates",
        "CREATE TABLE updates (operation_id TEXT PRIMARY KEY, site_id TEXT NOT NULL REFERENCES provisions(site_id), capture_operation_id TEXT NOT NULL REFERENCES captures(operation_id), recipe_digest TEXT NOT NULL CHECK(length(recipe_digest)=64 AND recipe_digest NOT GLOB '*[^0-9a-f]*'), idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL CHECK(length(plan_digest)=64 AND plan_digest NOT GLOB '*[^0-9a-f]*'), grant_digest TEXT NOT NULL CHECK(length(grant_digest)=64 AND grant_digest NOT GLOB '*[^0-9a-f]*'), expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('intent','done','rolled_back'))) STRICT",
    ),
    (
        "one_open_update",
        "CREATE UNIQUE INDEX one_open_update ON updates(site_id) WHERE state='intent'",
    ),
    (
        "update_components",
        "CREATE TABLE update_components (operation_id TEXT NOT NULL REFERENCES updates(operation_id), position INTEGER NOT NULL CHECK(position BETWEEN 0 AND 7), kind TEXT NOT NULL CHECK(kind IN ('plugin','theme','core')), slug TEXT NOT NULL CHECK(length(slug) BETWEEN 1 AND 64 AND slug NOT GLOB '*[^a-z0-9_-]*' AND slug NOT GLOB '[-_]*'), from_version TEXT NOT NULL CHECK(length(from_version) BETWEEN 1 AND 32 AND from_version NOT GLOB '*[^0-9A-Za-z.-]*' AND from_version GLOB '[0-9]*'), to_version TEXT NOT NULL CHECK(length(to_version) BETWEEN 1 AND 32 AND to_version NOT GLOB '*[^0-9A-Za-z.-]*' AND to_version GLOB '[0-9]*' AND to_version<>from_version), PRIMARY KEY(operation_id, position), UNIQUE(operation_id, kind, slug)) STRICT",
    ),
    (
        "update_steps",
        "CREATE TABLE update_steps (operation_id TEXT NOT NULL REFERENCES updates(operation_id), position INTEGER NOT NULL CHECK(position BETWEEN 0 AND 3), state TEXT NOT NULL CHECK(state IN ('intent','done','failed')), PRIMARY KEY(operation_id, position)) STRICT",
    ),
    (
        "update_rollbacks",
        "CREATE TABLE update_rollbacks (operation_id TEXT PRIMARY KEY REFERENCES updates(operation_id), state TEXT NOT NULL CHECK(state IN ('intent','done','failed'))) STRICT",
    ),
    (
        "deletions",
        "CREATE TABLE deletions (operation_id TEXT PRIMARY KEY, provision_operation_id TEXT NOT NULL REFERENCES provisions(operation_id), capture_operation_id TEXT REFERENCES captures(operation_id), idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL CHECK(length(plan_digest)=64 AND plan_digest NOT GLOB '*[^0-9a-f]*'), grant_digest TEXT NOT NULL CHECK(length(grant_digest)=64 AND grant_digest NOT GLOB '*[^0-9a-f]*'), expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('intent','done','failed'))) STRICT",
    ),
    (
        "one_deletion",
        "CREATE UNIQUE INDEX one_deletion ON deletions(provision_operation_id) WHERE state<>'failed'",
    ),
    (
        "quota_changes",
        "CREATE TABLE quota_changes (operation_id TEXT PRIMARY KEY, site_id TEXT NOT NULL REFERENCES provisions(site_id), idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL CHECK(length(plan_digest)=64 AND plan_digest NOT GLOB '*[^0-9a-f]*'), grant_digest TEXT NOT NULL CHECK(length(grant_digest)=64 AND grant_digest NOT GLOB '*[^0-9a-f]*'), block_hard_kib INTEGER NOT NULL CHECK(block_hard_kib BETWEEN 65536 AND 17179869184), inode_hard INTEGER NOT NULL CHECK(inode_hard BETWEEN 1000 AND 100000000), expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('intent','done','failed'))) STRICT",
    ),
    (
        "one_open_quota_change",
        "CREATE UNIQUE INDEX one_open_quota_change ON quota_changes(site_id) WHERE state='intent'",
    ),
    (
        "clone_scrub_grants",
        "CREATE TABLE clone_scrub_grants (operation_id TEXT PRIMARY KEY, clone_operation_id TEXT NOT NULL REFERENCES clones(operation_id), idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL CHECK(length(plan_digest)=64 AND plan_digest NOT GLOB '*[^0-9a-f]*'), grant_digest TEXT NOT NULL CHECK(length(grant_digest)=64 AND grant_digest NOT GLOB '*[^0-9a-f]*'), expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('intent','done','failed'))) STRICT",
    ),
    (
        "one_open_clone_scrub_grant",
        "CREATE UNIQUE INDEX one_open_clone_scrub_grant ON clone_scrub_grants(clone_operation_id) WHERE state='intent'",
    ),
    (
        "site_restores",
        "CREATE TABLE site_restores (operation_id TEXT PRIMARY KEY, site_id TEXT NOT NULL REFERENCES provisions(site_id), scope TEXT NOT NULL CHECK(scope IN ('database','files_and_database')), capture_operation_id TEXT NOT NULL REFERENCES captures(operation_id), snapshot_id TEXT NOT NULL CHECK(length(snapshot_id)=64 AND snapshot_id NOT GLOB '*[^0-9a-f]*'), manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256)=64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'), safety_capture_operation_id TEXT NOT NULL REFERENCES captures(operation_id) CHECK(safety_capture_operation_id<>capture_operation_id), idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL CHECK(length(plan_digest)=64 AND plan_digest NOT GLOB '*[^0-9a-f]*'), grant_digest TEXT NOT NULL CHECK(length(grant_digest)=64 AND grant_digest NOT GLOB '*[^0-9a-f]*'), expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('intent','done','reverted'))) STRICT",
    ),
    (
        "one_open_restore",
        "CREATE UNIQUE INDEX one_open_restore ON site_restores(site_id) WHERE state='intent'",
    ),
    (
        "restore_attempts",
        "CREATE TABLE restore_attempts (operation_id TEXT NOT NULL REFERENCES site_restores(operation_id), attempt INTEGER NOT NULL CHECK(attempt BETWEEN 0 AND 7), source TEXT NOT NULL CHECK(source IN ('signed','safety')), state TEXT NOT NULL CHECK(state IN ('intent','done','failed')), PRIMARY KEY(operation_id, attempt)) STRICT",
    ),
    (
        "one_open_restore_attempt",
        "CREATE UNIQUE INDEX one_open_restore_attempt ON restore_attempts(operation_id) WHERE state='intent'",
    ),
    (
        "restore_steps",
        "CREATE TABLE restore_steps (operation_id TEXT NOT NULL, attempt INTEGER NOT NULL, position INTEGER NOT NULL CHECK(position BETWEEN 0 AND 5), step TEXT NOT NULL CHECK(step IN ('maintenance','fetch','database','files','reopen','health')), state TEXT NOT NULL CHECK(state IN ('intent','done','failed')), PRIMARY KEY(operation_id, attempt, position), FOREIGN KEY(operation_id, attempt) REFERENCES restore_attempts(operation_id, attempt)) STRICT",
    ),
    (
        "dns_imports",
        "CREATE TABLE dns_imports (operation_id TEXT PRIMARY KEY, zone TEXT NOT NULL CHECK(length(zone) BETWEEN 3 AND 253 AND zone NOT GLOB '*[^a-z0-9.-]*' AND zone GLOB '*.*'), zone_sha256 TEXT NOT NULL CHECK(length(zone_sha256)=64 AND zone_sha256 NOT GLOB '*[^0-9a-f]*'), record_sets INTEGER NOT NULL CHECK(record_sets BETWEEN 1 AND 20000), idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL CHECK(length(plan_digest)=64 AND plan_digest NOT GLOB '*[^0-9a-f]*'), grant_digest TEXT NOT NULL CHECK(length(grant_digest)=64 AND grant_digest NOT GLOB '*[^0-9a-f]*'), expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('intent','done','failed'))) STRICT",
    ),
    (
        "one_live_dns_import",
        "CREATE UNIQUE INDEX one_live_dns_import ON dns_imports(zone) WHERE state<>'failed'",
    ),
    (
        "dns_changes",
        "CREATE TABLE dns_changes (operation_id TEXT PRIMARY KEY, zone TEXT NOT NULL CHECK(length(zone) BETWEEN 3 AND 253 AND zone NOT GLOB '*[^a-z0-9.-]*' AND zone GLOB '*.*'), idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL CHECK(length(plan_digest)=64 AND plan_digest NOT GLOB '*[^0-9a-f]*'), grant_digest TEXT NOT NULL CHECK(length(grant_digest)=64 AND grant_digest NOT GLOB '*[^0-9a-f]*'), expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('intent','done','failed'))) STRICT",
    ),
    (
        "one_open_dns_change",
        "CREATE UNIQUE INDEX one_open_dns_change ON dns_changes(zone) WHERE state='intent'",
    ),
    (
        "dns_change_sets",
        "CREATE TABLE dns_change_sets (operation_id TEXT NOT NULL REFERENCES dns_changes(operation_id), position INTEGER NOT NULL CHECK(position BETWEEN 0 AND 15), owner TEXT NOT NULL CHECK(length(owner) BETWEEN 2 AND 254 AND owner GLOB '*.'), type TEXT NOT NULL CHECK(type IN ('A','AAAA','CNAME','MX','TXT','SRV','CAA')), expected TEXT NOT NULL CHECK(expected='absent' OR (length(expected)=64 AND expected NOT GLOB '*[^0-9a-f]*')), before TEXT CHECK(before IS NULL OR length(before) BETWEEN 1 AND 262144), after TEXT CHECK(after IS NULL OR length(after) BETWEEN 1 AND 262144), PRIMARY KEY(operation_id, position), UNIQUE(operation_id, owner, type)) STRICT",
    ),
    (
        "proxy_routes",
        "CREATE TABLE proxy_routes (operation_id TEXT NOT NULL REFERENCES provisions(operation_id), kind TEXT NOT NULL CHECK(kind IN ('route','websocket')), position INTEGER NOT NULL CHECK(position BETWEEN 0 AND 7), prefix TEXT NOT NULL CHECK(length(prefix) BETWEEN 1 AND 128 AND prefix GLOB '/*' AND prefix GLOB '*/' AND prefix NOT GLOB '*[^a-z0-9/._-]*' AND prefix NOT GLOB '*//*'), port INTEGER NOT NULL CHECK(port BETWEEN 1024 AND 65535 AND port<>3306), PRIMARY KEY(operation_id, kind, position), UNIQUE(operation_id, kind, prefix)) STRICT",
    ),
    (
        "static_ejections",
        "CREATE TABLE static_ejections (operation_id TEXT PRIMARY KEY REFERENCES ejections(operation_id), hostname TEXT NOT NULL CHECK(length(hostname) BETWEEN 1 AND 253 AND hostname NOT GLOB '*[^a-z0-9.-]*')) STRICT",
    ),
    (
        "apps",
        "CREATE TABLE apps (operation_id TEXT PRIMARY KEY REFERENCES provisions(operation_id), runtime TEXT NOT NULL CHECK(runtime IN ('node_22_v1','bun_1_v1','static_v1')), port INTEGER NOT NULL CHECK(port=0 OR (port BETWEEN 1024 AND 65535 AND port<>3306)), entrypoint TEXT NOT NULL CHECK(length(entrypoint) BETWEEN 0 AND 128), worker_entrypoint TEXT CHECK(worker_entrypoint IS NULL OR length(worker_entrypoint) BETWEEN 1 AND 128), health_path TEXT NOT NULL CHECK(length(health_path) BETWEEN 1 AND 128 AND health_path GLOB '/*'), env_keys TEXT NOT NULL CHECK(length(env_keys)<=4200 AND env_keys NOT GLOB '*[^A-Z0-9_,]*'), memory_max_mib INTEGER NOT NULL CHECK(memory_max_mib BETWEEN 64 AND 8192), tasks_max INTEGER NOT NULL CHECK(tasks_max BETWEEN 16 AND 1024), quota_mib INTEGER NOT NULL CHECK(quota_mib BETWEEN 128 AND 65536)) STRICT",
    ),
    (
        "app_releases",
        "CREATE TABLE app_releases (operation_id TEXT PRIMARY KEY, site_id TEXT NOT NULL REFERENCES provisions(site_id), release_id TEXT NOT NULL CHECK(length(release_id) BETWEEN 1 AND 64), runtime TEXT NOT NULL CHECK(runtime IN ('node_22_v1','bun_1_v1','static_v1')), artifact_sha256 TEXT NOT NULL CHECK(length(artifact_sha256)=64 AND artifact_sha256 NOT GLOB '*[^0-9a-f]*'), manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256)=64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'), file_count INTEGER NOT NULL CHECK(file_count BETWEEN 1 AND 50000), total_bytes INTEGER NOT NULL CHECK(total_bytes BETWEEN 1 AND 536870912), migration_entrypoint TEXT CHECK(migration_entrypoint IS NULL OR length(migration_entrypoint) BETWEEN 1 AND 128), capture_operation_id TEXT REFERENCES captures(operation_id), health_path TEXT NOT NULL CHECK(length(health_path) BETWEEN 1 AND 128 AND health_path GLOB '/*'), idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL CHECK(length(plan_digest)=64 AND plan_digest NOT GLOB '*[^0-9a-f]*'), grant_digest TEXT NOT NULL CHECK(length(grant_digest)=64 AND grant_digest NOT GLOB '*[^0-9a-f]*'), expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('intent','done','rolled_back')), UNIQUE(site_id, release_id)) STRICT",
    ),
    (
        "one_open_app_release",
        "CREATE UNIQUE INDEX one_open_app_release ON app_releases(site_id) WHERE state='intent'",
    ),
    (
        "app_release_steps",
        "CREATE TABLE app_release_steps (operation_id TEXT NOT NULL REFERENCES app_releases(operation_id), position INTEGER NOT NULL CHECK(position BETWEEN 0 AND 4), state TEXT NOT NULL CHECK(state IN ('intent','done','failed')), PRIMARY KEY(operation_id, position)) STRICT",
    ),
    (
        "app_lifecycles",
        "CREATE TABLE app_lifecycles (operation_id TEXT PRIMARY KEY, site_id TEXT NOT NULL REFERENCES provisions(site_id), action TEXT NOT NULL CHECK(action IN ('start','stop','restart')), idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL CHECK(length(plan_digest)=64 AND plan_digest NOT GLOB '*[^0-9a-f]*'), grant_digest TEXT NOT NULL CHECK(length(grant_digest)=64 AND grant_digest NOT GLOB '*[^0-9a-f]*'), expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('intent','done','failed'))) STRICT",
    ),
    (
        "one_open_app_lifecycle",
        "CREATE UNIQUE INDEX one_open_app_lifecycle ON app_lifecycles(site_id) WHERE state='intent'",
    ),
    (
        "credential_rotations",
        "CREATE TABLE credential_rotations (operation_id TEXT PRIMARY KEY, site_id TEXT NOT NULL REFERENCES provisions(site_id), hostname TEXT NOT NULL CHECK(length(hostname) BETWEEN 1 AND 253 AND hostname NOT GLOB '*[^a-z0-9.-]*'), target TEXT NOT NULL CHECK(target IN ('mariadb_user_password','app_mariadb_password','app_postgresql_18_password')), idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL CHECK(length(plan_digest)=64 AND plan_digest NOT GLOB '*[^0-9a-f]*'), grant_digest TEXT NOT NULL CHECK(length(grant_digest)=64 AND grant_digest NOT GLOB '*[^0-9a-f]*'), expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('intent','done','failed_compensated','needs_attention','failed'))) STRICT",
    ),
    (
        "one_open_credential_rotation",
        "CREATE UNIQUE INDEX one_open_credential_rotation ON credential_rotations(site_id) WHERE state IN ('intent','needs_attention')",
    ),
    (
        "app_fullstack_specs",
        "CREATE TABLE app_fullstack_specs (operation_id TEXT PRIMARY KEY REFERENCES apps(operation_id), ingress TEXT NOT NULL CHECK(ingress IN ('ols','caddy')), topology TEXT NOT NULL CHECK(topology IN ('static_spa','backend_api','fullstack_split','fullstack_dual_ssr')), database_engine TEXT NOT NULL CHECK(database_engine IN ('none','sqlite','mariadb','postgresql_18')), blue_green INTEGER NOT NULL CHECK(blue_green IN (0,1)), active_slot TEXT NOT NULL CHECK(active_slot IN ('a','b')), standby_port INTEGER CHECK(standby_port IS NULL OR (standby_port BETWEEN 1024 AND 65535 AND standby_port NOT IN (2019,3306,5432))), spa_fallback INTEGER NOT NULL CHECK(spa_fallback IN (0,1)), frontend_dir TEXT CHECK(frontend_dir IS NULL OR length(frontend_dir) BETWEEN 1 AND 128), frontend_runtime TEXT CHECK(frontend_runtime IS NULL OR frontend_runtime IN ('node_22_v1','bun_1_v1')), frontend_entrypoint TEXT CHECK(frontend_entrypoint IS NULL OR length(frontend_entrypoint) BETWEEN 1 AND 128), frontend_port INTEGER CHECK(frontend_port IS NULL OR (frontend_port BETWEEN 1024 AND 65535 AND frontend_port NOT IN (2019,3306,5432))), frontend_standby_port INTEGER CHECK(frontend_standby_port IS NULL OR (frontend_standby_port BETWEEN 1024 AND 65535 AND frontend_standby_port NOT IN (2019,3306,5432))), sse_prefixes TEXT NOT NULL CHECK(length(sse_prefixes)<=1100), strip_api_prefixes TEXT NOT NULL CHECK(length(strip_api_prefixes)<=1100)) STRICT",
    ),
    (
        "caddy_generations",
        "CREATE TABLE caddy_generations (generation_id TEXT PRIMARY KEY CHECK(length(generation_id) BETWEEN 1 AND 64), operation_id TEXT NOT NULL CHECK(length(operation_id) BETWEEN 1 AND 64), ingress_mode TEXT NOT NULL CHECK(ingress_mode IN ('caddy_only','caddy_multi_ip','caddy_edge_over_ols')), config_sha256 TEXT NOT NULL CHECK(length(config_sha256)=64 AND config_sha256 NOT GLOB '*[^0-9a-f]*'), site_count INTEGER NOT NULL CHECK(site_count>=0), created_at INTEGER NOT NULL CHECK(created_at>=0), state TEXT NOT NULL CHECK(state IN ('staged','active','rolled_back'))) STRICT",
    ),
    (
        "one_active_caddy_generation",
        "CREATE UNIQUE INDEX one_active_caddy_generation ON caddy_generations((1)) WHERE state='active'",
    ),
];

/// The schema a journal of `version` has, from its first `count` entries:
/// before v17 `provisions` has the legacy state check.
fn schema_at(version: i64, count: usize) -> Vec<(&'static str, &'static str)> {
    SCHEMA[..count]
        .iter()
        .map(|&(name, sql)| {
            if version < ADOPTED_STATE_VERSION && name == "provisions" {
                (name, LEGACY_PROVISIONS)
            } else if version < DELETED_STATE_VERSION && name == "provisions" {
                (name, ADOPTED_PROVISIONS)
            } else if version < STATIC_IMPORT_VERSION && name == "imports" {
                (name, LEGACY_IMPORTS)
            } else if version < CORE_UPDATE_VERSION && name == "update_components" {
                (name, LEGACY_UPDATE_COMPONENTS)
            } else if version < NULLABLE_DELETE_CAPTURE_VERSION && name == "deletions" {
                (name, LEGACY_DELETIONS)
            } else if version < FULLSTACK_APPS_VERSION && name == "apps" {
                (name, LEGACY_APPS)
            } else if version < FULLSTACK_APPS_VERSION && name == "app_releases" {
                (name, LEGACY_APP_RELEASES)
            } else if version < FULLSTACK_APPS_VERSION && name == "credential_rotations" {
                (name, LEGACY_CREDENTIAL_ROTATIONS)
            } else {
                (name, sql)
            }
        })
        .collect()
}

fn schema_sql(name: &str) -> Result<&'static str, JournalError> {
    SCHEMA
        .iter()
        .find(|(entry, _)| *entry == name)
        .map(|(_, sql)| *sql)
        .ok_or(JournalError::Unavailable)
}

/// D-074: rebuilds `imports` with the v26 dump check inside the migration
/// transaction, as [`rebuild_provisions`] does: foreign keys are off, every
/// row is copied back unchanged, and the foreign-key check must find nothing.
fn rebuild_imports(transaction: &rusqlite::Transaction<'_>) -> Result<(), JournalError> {
    transaction
        .execute_batch(&format!(
            "CREATE TEMP TABLE imports_old AS SELECT * FROM imports; DROP TABLE imports; {}; \
             INSERT INTO imports SELECT * FROM temp.imports_old; DROP TABLE temp.imports_old;",
            schema_sql("imports")?
        ))
        .map_err(unavailable)?;
    let mut check = transaction
        .prepare("PRAGMA foreign_key_check")
        .map_err(unavailable)?;
    if check.exists([]).map_err(unavailable)? {
        return Err(JournalError::Unavailable);
    }
    Ok(())
}

/// D-086: rebuilds `update_components` with the v34 kind check, as
/// [`rebuild_provisions`] does: foreign keys are off, every row is copied
/// back unchanged, and the foreign-key check must find nothing.
/// W576 (D-095): rebuilds `deletions` with the v41 nullable capture, as
/// [`rebuild_update_components`] does: every row is copied back unchanged
/// and the foreign-key check must then find nothing.
fn rebuild_deletions(transaction: &rusqlite::Transaction<'_>) -> Result<(), JournalError> {
    transaction
        .execute_batch(&format!(
            "CREATE TEMP TABLE deletions_old AS SELECT * FROM deletions; DROP TABLE deletions; {}; \
             INSERT INTO deletions SELECT * FROM temp.deletions_old; DROP TABLE temp.deletions_old; {};",
            schema_sql("deletions")?,
            schema_sql("one_deletion")?
        ))
        .map_err(unavailable)?;
    let mut check = transaction
        .prepare("PRAGMA foreign_key_check")
        .map_err(unavailable)?;
    if check.exists([]).map_err(unavailable)? {
        return Err(JournalError::Unavailable);
    }
    Ok(())
}

fn rebuild_update_components(transaction: &rusqlite::Transaction<'_>) -> Result<(), JournalError> {
    transaction
        .execute_batch(&format!(
            "CREATE TEMP TABLE update_components_old AS SELECT * FROM update_components; DROP TABLE update_components; {}; \
             INSERT INTO update_components SELECT * FROM temp.update_components_old; DROP TABLE temp.update_components_old;",
            schema_sql("update_components")?
        ))
        .map_err(unavailable)?;
    let mut check = transaction
        .prepare("PRAGMA foreign_key_check")
        .map_err(unavailable)?;
    if check.exists([]).map_err(unavailable)? {
        return Err(JournalError::Unavailable);
    }
    Ok(())
}

/// W372: rebuilds `provisions` with the v17 state check inside the
/// migration transaction. Foreign keys are off on this connection, so the
/// drop does not cascade; every row is copied back unchanged and the
/// foreign-key check must then find nothing.
fn rebuild_apps_v45(transaction: &rusqlite::Transaction<'_>) -> Result<(), JournalError> {
    transaction
        .execute_batch(&format!(
            "CREATE TEMP TABLE apps_old AS SELECT * FROM apps; DROP TABLE apps; {}; \
             INSERT INTO apps SELECT * FROM temp.apps_old; DROP TABLE temp.apps_old; \
             CREATE TEMP TABLE app_releases_old AS SELECT * FROM app_releases; DROP TABLE app_releases; {}; \
             INSERT INTO app_releases SELECT * FROM temp.app_releases_old; DROP TABLE temp.app_releases_old; {};",
            schema_sql("apps")?,
            schema_sql("app_releases")?,
            schema_sql("one_open_app_release")?
        ))
        .map_err(unavailable)?;
    let mut check = transaction
        .prepare("PRAGMA foreign_key_check")
        .map_err(unavailable)?;
    if check.exists([]).map_err(unavailable)? {
        return Err(JournalError::Unavailable);
    }
    Ok(())
}

fn rebuild_credential_rotations_v45(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<(), JournalError> {
    transaction
        .execute_batch(&format!(
            "CREATE TEMP TABLE cred_old AS SELECT * FROM credential_rotations; DROP TABLE credential_rotations; {}; \
             INSERT INTO credential_rotations SELECT * FROM temp.cred_old; DROP TABLE temp.cred_old; {};",
            schema_sql("credential_rotations")?,
            schema_sql("one_open_credential_rotation")?
        ))
        .map_err(unavailable)?;
    let mut check = transaction
        .prepare("PRAGMA foreign_key_check")
        .map_err(unavailable)?;
    if check.exists([]).map_err(unavailable)? {
        return Err(JournalError::Unavailable);
    }
    Ok(())
}

fn rebuild_provisions(transaction: &rusqlite::Transaction<'_>) -> Result<(), JournalError> {
    transaction
        .execute_batch(&format!(
            "CREATE TEMP TABLE provisions_old AS SELECT * FROM provisions; DROP TABLE provisions; {}; \
             INSERT INTO provisions SELECT * FROM temp.provisions_old; DROP TABLE temp.provisions_old; {};",
            schema_sql("provisions")?,
            schema_sql("one_running_provision")?
        ))
        .map_err(unavailable)?;
    let mut check = transaction
        .prepare("PRAGMA foreign_key_check")
        .map_err(unavailable)?;
    if check.exists([]).map_err(unavailable)? {
        return Err(JournalError::Unavailable);
    }
    Ok(())
}

pub(crate) fn unavailable<T>(_: T) -> JournalError {
    JournalError::Unavailable
}

fn native() -> Result<(), JournalError> {
    let c = Connection::open_in_memory().map_err(unavailable)?;
    let source: String = c
        .query_row("SELECT sqlite_source_id()", [], |r| r.get(0))
        .map_err(unavailable)?;
    if rusqlite::version() != "3.54.1"
        || source
            != "2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76"
    {
        return Err(JournalError::Unavailable);
    }
    Ok(())
}

fn check_parent(directory: &Path, uid: u32) -> Result<(), JournalError> {
    native()?;
    local::check_parent(&directory.join(DATABASE), uid).map_err(|_| JournalError::AccessDenied)
}

fn check_file(path: &Path, uid: u32) -> Result<(), JournalError> {
    let metadata = fs::symlink_metadata(path).map_err(unavailable)?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(JournalError::AccessDenied);
    }
    if metadata.len() > MAX_DATABASE_BYTES {
        return Err(JournalError::Unavailable);
    }
    Ok(())
}

fn lease(directory: &Path, create: bool, uid: u32) -> Result<File, JournalError> {
    let path = directory.join("writer.lock");
    if !create {
        check_file(&path, uid)?;
    }
    let file = OpenOptions::new()
        .read(true)
        // The descriptor only holds the flock after creation.
        .write(create)
        .create_new(create)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&path)
        .map_err(|_| JournalError::AccessDenied)?;
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| JournalError::AccessDenied)?;
    Ok(file)
}

pub(crate) fn initialize_files(directory: &Path, uid: u32) -> Result<File, JournalError> {
    check_parent(directory, uid)?;
    if fs::read_dir(directory)
        .map_err(unavailable)?
        .next()
        .is_some()
    {
        return Err(JournalError::Conflict);
    }
    let lease = lease(directory, true, uid)?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join(DATABASE))
        .map_err(unavailable)?;
    Ok(lease)
}

pub(crate) fn open_files(directory: &Path, uid: u32) -> Result<File, JournalError> {
    check_parent(directory, uid)?;
    check_file(&directory.join(DATABASE), uid)?;
    for name in [
        "fixture-journal.sqlite-journal",
        "fixture-journal.sqlite-wal",
        "fixture-journal.sqlite-shm",
    ] {
        match fs::symlink_metadata(directory.join(name)) {
            Ok(_) => check_file(&directory.join(name), uid)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(unavailable(error)),
        }
    }
    lease(directory, false, uid)
}

/// Read-only open for display: the same ownership, schema and integrity checks
/// as the writer, but no lease and a query-only connection.
pub(crate) fn open_read_only(
    directory: &Path,
    uid: u32,
    host: &Id,
    epoch: &Id,
) -> Result<Connection, JournalError> {
    check_parent(directory, uid)?;
    check_file(&directory.join(DATABASE), uid)?;
    let c =
        Connection::open_with_flags(directory.join(DATABASE), flags(true)).map_err(unavailable)?;
    c.busy_timeout(Duration::from_millis(250))
        .map_err(unavailable)?;
    c.pragma_update(None, "query_only", "ON")
        .map_err(unavailable)?;
    c.pragma_update(None, "trusted_schema", "OFF")
        .map_err(unavailable)?;
    validate(&c, host, epoch)?;
    Ok(c)
}

fn flags(read_only: bool) -> OpenFlags {
    (if read_only {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    } else {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    }) | OpenFlags::SQLITE_OPEN_NOFOLLOW
}

fn configure(c: &Connection) -> Result<(), JournalError> {
    c.busy_timeout(Duration::from_millis(250))
        .map_err(unavailable)?;
    for (name, value) in [
        ("journal_mode", "DELETE"),
        ("synchronous", "EXTRA"),
        ("foreign_keys", "ON"),
        ("trusted_schema", "OFF"),
        ("page_size", "4096"),
        ("max_page_count", "4096"),
    ] {
        c.pragma_update(None, name, value).map_err(unavailable)?;
    }
    let mode: String = c
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(unavailable)?;
    let read = |name| {
        c.pragma_query_value::<i64, _>(None, name, |row| row.get(0))
            .map_err(unavailable)
    };
    if mode != "delete"
        || read("synchronous")? != 3
        || read("foreign_keys")? != 1
        || read("trusted_schema")? != 0
        || read("page_size")? != 4096
        || read("max_page_count")? > 4096
    {
        return Err(JournalError::Unavailable);
    }
    Ok(())
}

pub(crate) fn initialize(
    directory: &Path,
    host: &Id,
    epoch: &Id,
) -> Result<Connection, JournalError> {
    let mut c =
        Connection::open_with_flags(directory.join(DATABASE), flags(false)).map_err(unavailable)?;
    configure(&c)?;
    let transaction = c.transaction().map_err(unavailable)?;
    for (_, sql) in SCHEMA {
        transaction.execute_batch(sql).map_err(unavailable)?;
    }
    transaction
        .execute(
            "INSERT INTO metadata VALUES(1,1,?1,?2,0)",
            params![host.as_str(), epoch.as_str()],
        )
        .map_err(unavailable)?;
    transaction
        .pragma_update(None, "application_id", APPLICATION_ID)
        .map_err(unavailable)?;
    transaction
        .pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(unavailable)?;
    transaction.commit().map_err(unavailable)?;
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(unavailable)?;
    Ok(c)
}

pub(crate) fn open(directory: &Path, host: &Id, epoch: &Id) -> Result<Connection, JournalError> {
    let path = directory.join(DATABASE);
    // A hot rollback journal (writer killed mid-transaction, W214) can only
    // be rolled back by a read-write connection; `open_files` already held
    // it to the database's owner/mode/link checks. SQLite rolls it back on
    // the first read below, before validation and before any write of ours.
    if !directory.join(format!("{DATABASE}-journal")).exists() {
        let probe = Connection::open_with_flags(&path, flags(true)).map_err(unavailable)?;
        validate(&probe, host, epoch)?;
        drop(probe);
    }
    let c = Connection::open_with_flags(path, flags(false)).map_err(unavailable)?;
    validate(&c, host, epoch)?;
    configure(&c)?;
    Ok(c)
}

/// One-way in-place migration from a supported older schema. The source shape
/// and identity are checked first; appended tables and the version change are
/// validated inside the transaction before commit. A refused result does not
/// commit the migration.
pub(crate) fn migrate(directory: &Path, host: &Id, epoch: &Id) -> Result<Connection, JournalError> {
    let path = directory.join(DATABASE);
    let mut c = Connection::open_with_flags(&path, flags(false)).map_err(unavailable)?;
    let version: i64 = c
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(unavailable)?;
    let (_, existing) = MIGRATION_SOURCES
        .iter()
        .copied()
        .find(|(source, _)| *source == version)
        .ok_or(JournalError::Unavailable)?;
    validate_version(&c, host, epoch, version, &schema_at(version, existing))?;
    configure(&c)?;
    // D-085: every earlier journal gets the v33 provision state check.
    let rebuild = version < DELETED_STATE_VERSION;
    // D-074: a journal that has `imports` gets its v26 dump check.
    let rebuild_import_table = (IMPORTS_VERSION..STATIC_IMPORT_VERSION).contains(&version);
    // D-086: a journal that has `update_components` gets its v34 kind check.
    let rebuild_components = (UPDATES_VERSION..CORE_UPDATE_VERSION).contains(&version);
    // W576: a journal that has `deletions` gets its v41 nullable capture.
    let rebuild_deletion_table =
        (DELETED_STATE_VERSION..NULLABLE_DELETE_CAPTURE_VERSION).contains(&version);
    // W656 (D-102): v43/v44 journals rebuild apps/app_releases (and v44 rebuilds credential_rotations).
    let rebuild_apps_tables = (APPS_VERSION..FULLSTACK_APPS_VERSION).contains(&version);
    let rebuild_cred_table = (CREDENTIAL_ROTATE_VERSION..FULLSTACK_APPS_VERSION).contains(&version);
    let rebuilds = rebuild
        || rebuild_import_table
        || rebuild_components
        || rebuild_deletion_table
        || rebuild_apps_tables
        || rebuild_cred_table;
    if rebuilds {
        // A table rebuild needs foreign keys off; SQLite ignores this
        // pragma inside a transaction, so it is set before.
        c.pragma_update(None, "foreign_keys", "OFF")
            .map_err(unavailable)?;
    }
    let transaction = c.transaction().map_err(unavailable)?;
    for (_, sql) in &SCHEMA[existing..] {
        transaction.execute_batch(sql).map_err(unavailable)?;
    }
    if rebuild {
        rebuild_provisions(&transaction)?;
    }
    if rebuild_import_table {
        rebuild_imports(&transaction)?;
    }
    if rebuild_components {
        rebuild_update_components(&transaction)?;
    }
    if rebuild_deletion_table {
        rebuild_deletions(&transaction)?;
    }
    if rebuild_apps_tables {
        rebuild_apps_v45(&transaction)?;
    }
    if rebuild_cred_table {
        rebuild_credential_rotations_v45(&transaction)?;
    }
    transaction
        .pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(unavailable)?;
    #[cfg(test)]
    migration_test_checkpoint("before_commit");
    validate(&transaction, host, epoch)?;
    transaction.commit().map_err(unavailable)?;
    #[cfg(test)]
    migration_test_checkpoint("after_commit");
    if rebuilds {
        configure(&c)?;
    }
    Ok(c)
}

#[cfg(test)]
fn migration_test_checkpoint(phase: &str) {
    if std::env::var("RUSTIRON_TEST_MIGRATION_CHECKPOINT").as_deref() == Ok(phase) {
        let marker = std::env::var_os("RUSTIRON_TEST_MIGRATION_MARKER").expect("marker path");
        fs::write(marker, phase).expect("write migration checkpoint");
        loop {
            std::thread::park();
        }
    }
}

fn validate(c: &Connection, host: &Id, epoch: &Id) -> Result<(), JournalError> {
    validate_version(c, host, epoch, SCHEMA_VERSION, &SCHEMA)?;
    crate::import::validate_aliases(c)?;
    crate::site_clone::validate(c)?;
    crate::retire::validate(c)?;
    crate::site_update::validate(c)?;
    crate::delete::validate(c)?;
    crate::quota_change::validate(c)?;
    crate::site_restore::validate(c)?;
    crate::dns::validate(c)?;
    crate::proxy::validate(c)?;
    crate::app::validate(c)?;
    crate::credential_rotate::validate(c)?;
    crate::readopt::validate(c, host, epoch)?;
    crate::provision::validate_ejections(c)?;
    crate::provision::validate_page_cache(c)?;
    crate::capture::validate(c, host, epoch)?;
    crate::probe::validate(c, host, epoch)?;
    crate::signed::validate(c)
}

fn validate_version(
    c: &Connection,
    host: &Id,
    epoch: &Id,
    version: i64,
    schema: &[(&str, &str)],
) -> Result<(), JournalError> {
    let get = |name| {
        c.pragma_query_value::<i64, _>(None, name, |row| row.get(0))
            .map_err(unavailable)
    };
    if get("application_id")? != APPLICATION_ID || get("user_version")? != version {
        return Err(JournalError::Unavailable);
    }
    let count: i64 = c
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )
        .map_err(unavailable)?;
    if count != schema.len() as i64 {
        return Err(JournalError::Unavailable);
    }
    for (name, sql) in schema {
        let actual: String = c
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name=?1",
                [name],
                |row| row.get(0),
            )
            .map_err(unavailable)?;
        if actual != *sql {
            return Err(JournalError::Unavailable);
        }
    }
    let check: String = c
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(unavailable)?;
    if check != "ok" {
        return Err(JournalError::Unavailable);
    }
    let (actual_host, actual_epoch, last_time, version): (String, String, i64, i64) = c
        .query_row(
            "SELECT host_id,host_epoch,last_time,version FROM metadata WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(unavailable)?;
    if actual_host != host.as_str() || actual_epoch != epoch.as_str() {
        return Err(JournalError::Conflict);
    }
    if version != 1
        || u64::try_from(last_time)
            .ok()
            .and_then(|time| Timestamp::try_from(time).ok())
            .is_none()
    {
        return Err(JournalError::Unavailable);
    }
    let mut query = c
        .prepare("SELECT * FROM operations LIMIT ?1")
        .map_err(unavailable)?;
    let rows = query
        .query_map([MAX_OPERATIONS + 1], decode)
        .map_err(unavailable)?;
    let mut count = 0;
    let mut unresolved = 0;
    for row in rows {
        let row = row.map_err(unavailable)?;
        count += 1;
        if row.intent.host_id != *host
            || row.intent.host_epoch != *epoch
            || row.intent.predecessor_generation == row.intent.target_generation
            || (row.compensation_attempted && !row.effect_attempted)
            || (matches!(
                row.state,
                RecordedState::Compensating | RecordedState::FailedCompensated
            ) && !row.compensation_attempted)
        {
            return Err(JournalError::Unavailable);
        }
        if row.state.is_unresolved() {
            unresolved += 1;
        }
    }
    if count > MAX_OPERATIONS || unresolved > 1 {
        return Err(JournalError::Unavailable);
    }
    crate::provision::validate(c, host, epoch)
}

pub(crate) fn state_text(state: RecordedState) -> &'static str {
    match state {
        RecordedState::Intent => "intent",
        RecordedState::Succeeded => "succeeded",
        RecordedState::Untouched => "untouched",
        RecordedState::NeedsAttention => "needs_attention",
        RecordedState::Compensating => "compensating",
        RecordedState::FailedCompensated => "failed_compensated",
    }
}

fn decode(row: &Row<'_>) -> rusqlite::Result<Operation> {
    let id = |i| Id::try_from(row.get::<_, String>(i)?).map_err(|_| rusqlite::Error::InvalidQuery);
    let digest = |i| {
        Sha256Digest::try_from(row.get::<_, String>(i)?).map_err(|_| rusqlite::Error::InvalidQuery)
    };
    let time = |i| {
        u64::try_from(row.get::<_, i64>(i)?)
            .ok()
            .and_then(|time| Timestamp::try_from(time).ok())
            .ok_or(rusqlite::Error::InvalidQuery)
    };
    let flag = |i| match row.get::<_, i64>(i)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(rusqlite::Error::InvalidQuery),
    };
    let state = match row.get::<_, String>(15)?.as_str() {
        "intent" => RecordedState::Intent,
        "succeeded" => RecordedState::Succeeded,
        "untouched" => RecordedState::Untouched,
        "needs_attention" => RecordedState::NeedsAttention,
        "compensating" => RecordedState::Compensating,
        "failed_compensated" => RecordedState::FailedCompensated,
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    Ok(Operation {
        intent: Intent {
            operation_id: id(0)?,
            idempotency_key: id(1)?,
            grant_id: id(2)?,
            nonce: id(3)?,
            plan_digest: digest(4)?,
            grant_digest: digest(5)?,
            host_id: id(6)?,
            host_epoch: id(7)?,
            resource_id: id(8)?,
            predecessor_generation: id(9)?,
            predecessor_digest: digest(10)?,
            target_generation: id(11)?,
            target_digest: digest(12)?,
            expires_at: time(13)?,
            compensation_valid_until: time(14)?,
        },
        state,
        effect_attempted: flag(16)?,
        compensation_attempted: flag(17)?,
    })
}

pub(crate) fn by_key(c: &Connection, id: &Id) -> Result<Option<Operation>, JournalError> {
    c.query_row(
        "SELECT * FROM operations WHERE idempotency_key=?1",
        [id.as_str()],
        decode,
    )
    .optional()
    .map_err(unavailable)
}
pub(crate) fn by_operation(c: &Connection, id: &Id) -> Result<Option<Operation>, JournalError> {
    c.query_row(
        "SELECT * FROM operations WHERE operation_id=?1",
        [id.as_str()],
        decode,
    )
    .optional()
    .map_err(unavailable)
}

pub(crate) fn insert(c: &Connection, i: &Intent) -> Result<(), JournalError> {
    c.execute(
        "INSERT INTO operations VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,'intent',0,0)",
        params![
            i.operation_id.as_str(),
            i.idempotency_key.as_str(),
            i.grant_id.as_str(),
            i.nonce.as_str(),
            i.plan_digest.as_str(),
            i.grant_digest.as_str(),
            i.host_id.as_str(),
            i.host_epoch.as_str(),
            i.resource_id.as_str(),
            i.predecessor_generation.as_str(),
            i.predecessor_digest.as_str(),
            i.target_generation.as_str(),
            i.target_digest.as_str(),
            i.expires_at.get() as i64,
            i.compensation_valid_until.get() as i64
        ],
    )
    .map_err(unavailable)?;
    Ok(())
}

/// Whether the operation, grant or nonce is already bound to any record.
pub(crate) fn consumed(c: &Connection, i: &Intent) -> Result<bool, JournalError> {
    consumed_ids(c, &i.operation_id, &i.grant_id, &i.nonce)
}

/// Whether an operation id, grant or nonce is bound to any fixture,
/// provision, capture, restore probe, re-adoption or import scrub.
pub(crate) fn consumed_ids(
    c: &Connection,
    operation: &Id,
    grant: &Id,
    nonce: &Id,
) -> Result<bool, JournalError> {
    c.query_row(
        "SELECT EXISTS(SELECT 1 FROM operations WHERE operation_id=?1 OR grant_id=?2 OR nonce=?3) OR EXISTS(SELECT 1 FROM provisions WHERE operation_id=?1 OR grant_id=?2 OR nonce=?3) OR EXISTS(SELECT 1 FROM captures WHERE operation_id=?1 OR grant_id=?2 OR nonce=?3) OR EXISTS(SELECT 1 FROM restore_probes WHERE operation_id=?1 OR grant_id=?2 OR nonce=?3) OR EXISTS(SELECT 1 FROM readoptions WHERE operation_id=?1 OR grant_id=?2 OR nonce=?3) OR EXISTS(SELECT 1 FROM import_scrubs WHERE operation_id=?1 OR grant_id=?2 OR nonce=?3) OR EXISTS(SELECT 1 FROM certificates WHERE operation_id=?1 OR grant_id=?2 OR nonce=?3) OR EXISTS(SELECT 1 FROM retirements WHERE operation_id=?1 OR grant_id=?2 OR nonce=?3) OR EXISTS(SELECT 1 FROM updates WHERE operation_id=?1 OR grant_id=?2 OR nonce=?3) OR EXISTS(SELECT 1 FROM deletions WHERE operation_id=?1 OR grant_id=?2 OR nonce=?3) OR EXISTS(SELECT 1 FROM quota_changes WHERE operation_id=?1 OR grant_id=?2 OR nonce=?3) OR EXISTS(SELECT 1 FROM clone_scrub_grants WHERE operation_id=?1 OR grant_id=?2 OR nonce=?3) OR EXISTS(SELECT 1 FROM site_restores WHERE operation_id=?1 OR grant_id=?2 OR nonce=?3) OR EXISTS(SELECT 1 FROM dns_imports WHERE operation_id=?1 OR grant_id=?2 OR nonce=?3) OR EXISTS(SELECT 1 FROM dns_changes WHERE operation_id=?1 OR grant_id=?2 OR nonce=?3) OR EXISTS(SELECT 1 FROM app_releases WHERE operation_id=?1 OR grant_id=?2 OR nonce=?3) OR EXISTS(SELECT 1 FROM app_lifecycles WHERE operation_id=?1 OR grant_id=?2 OR nonce=?3) OR EXISTS(SELECT 1 FROM credential_rotations WHERE operation_id=?1 OR grant_id=?2 OR nonce=?3) OR EXISTS(SELECT 1 FROM certificate_renewals WHERE renewal_id=?1)",
        params![operation.as_str(), grant.as_str(), nonce.as_str()],
        |row| row.get(0),
    )
    .map_err(unavailable)
}

/// W372: a re-adoption still `verifying` blocks every other admission until
/// it is settled by its outcome or by `reconcile`.
pub(crate) fn readoption_verifying(c: &Connection) -> Result<bool, JournalError> {
    c.query_row(
        "SELECT EXISTS(SELECT 1 FROM readoptions WHERE state='verifying')",
        [],
        |row| row.get(0),
    )
    .map_err(unavailable)
}

/// Refuses reliable time earlier than the last accepted admission.
pub(crate) fn check_clock(c: &Connection, now: Timestamp) -> Result<(), JournalError> {
    let last: i64 = c
        .query_row(
            "SELECT last_time FROM metadata WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(unavailable)?;
    if (now.get() as i64) < last {
        return Err(JournalError::ClockRollback);
    }
    Ok(())
}

/// Records the latest accepted admission time.
pub(crate) fn set_clock(c: &Connection, now: Timestamp) -> Result<(), JournalError> {
    c.execute(
        "UPDATE metadata SET last_time=?1 WHERE singleton=1",
        [now.get() as i64],
    )
    .map_err(unavailable)?;
    Ok(())
}

#[cfg(test)]
mod migration_crash_tests {
    use std::{
        os::unix::{fs::DirBuilderExt, process::ExitStatusExt},
        path::Path,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };

    use rustiron_contracts::{Id, Timestamp, approval::Sha256Digest};

    use crate::{FixtureJournal, Intent, RecordResult, RecordedState};

    /// The v24 to v16 steps of the downgrades below: the import (v21) and
    /// later tables and the re-adoption tables dropped and `provisions` rebuilt with the v16 state check.
    fn to_v16() -> String {
        format!(
            "PRAGMA foreign_keys=OFF; DROP TABLE caddy_generations; DROP TABLE app_fullstack_specs; DROP TABLE credential_rotations; DROP TABLE app_lifecycles; DROP TABLE app_release_steps; DROP TABLE app_releases; DROP TABLE apps; DROP TABLE static_ejections; DROP TABLE proxy_routes; DROP TABLE dns_change_sets; DROP TABLE dns_changes; DROP TABLE dns_imports; DROP TABLE restore_steps; DROP TABLE restore_attempts; DROP TABLE site_restores; DROP TABLE clone_scrub_grants; DROP TABLE quota_changes; DROP TABLE deletions; DROP TABLE update_rollbacks; DROP TABLE update_steps; DROP TABLE update_components; DROP TABLE updates; DROP TABLE retirements; DROP TABLE clone_scrubs; DROP TABLE clone_steps; DROP TABLE clones; DROP TABLE certificate_aliases; DROP TABLE import_aliases; DROP TABLE import_sources; DROP TABLE certificate_renewals; DROP TABLE certificate_grants; DROP TABLE certificates; DROP TABLE import_scrubs; DROP TABLE import_steps; DROP TABLE imports; DROP TABLE admission_signatures; DROP TABLE signed_objects; DROP TABLE page_cache_recipes; DROP TABLE capture_object_retention; DROP TABLE capture_lock_checks; DROP TABLE capture_refusals; DROP TABLE allocation_floors; DROP TABLE ols_adoptions; DROP TABLE provision_adoptions; DROP TABLE readoptions; \
             CREATE TEMP TABLE p AS SELECT * FROM provisions; DROP TABLE provisions; {}; INSERT INTO provisions SELECT * FROM temp.p; DROP TABLE temp.p; {};",
            super::LEGACY_PROVISIONS,
            super::schema_sql("one_running_provision").unwrap()
        )
    }

    fn id(value: &str) -> Id {
        Id::try_from(value.to_owned()).unwrap()
    }

    fn intent() -> Intent {
        let digest =
            |character: char| Sha256Digest::try_from(character.to_string().repeat(64)).unwrap();
        Intent {
            operation_id: id("operation_1"),
            idempotency_key: id("retry_1"),
            grant_id: id("grant_1"),
            nonce: id("nonce_1"),
            plan_digest: digest('a'),
            grant_digest: digest('b'),
            host_id: id("host_fixture"),
            host_epoch: id("epoch_fixture"),
            resource_id: id("resource_fixture"),
            predecessor_generation: id("old_generation"),
            predecessor_digest: digest('c'),
            target_generation: id("new_generation"),
            target_digest: digest('d'),
            expires_at: Timestamp::try_from(10000).unwrap(),
            compensation_valid_until: Timestamp::try_from(10300).unwrap(),
        }
    }

    fn migrate(directory: &Path) -> Result<FixtureJournal, crate::JournalError> {
        FixtureJournal::migrate(directory, id("host_fixture"), id("epoch_fixture"))
    }

    #[test]
    fn killed_migration_preserves_admission_before_and_after_commit() {
        if let Some(directory) = std::env::var_os("RUSTIRON_TEST_MIGRATION_DIRECTORY") {
            let _result = migrate(Path::new(&directory));
            panic!("child did not reach its checkpoint");
        }

        for phase in ["before_commit", "after_commit"] {
            let directory = std::env::temp_dir()
                .join(format!("rustiron-migration-{}-{phase}", std::process::id()));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .unwrap();
            let mut journal =
                FixtureJournal::initialize(&directory, id("host_fixture"), id("epoch_fixture"))
                    .unwrap();
            let admitted = intent();
            journal
                .record_intent(&admitted, Timestamp::try_from(1000).unwrap())
                .unwrap();
            drop(journal);
            let connection =
                rusqlite::Connection::open(directory.join("fixture-journal.sqlite")).unwrap();
            connection
                .execute_batch(&format!("{} DROP TABLE page_cache_optouts; DROP TABLE page_cache_optins; DROP TABLE capture_unclaimed; DROP TABLE capture_backup_policy; DROP TABLE probe_backup_policy; DROP TABLE capture_freeze; DROP TABLE capture_consistency; DROP TABLE capture_manifest; DROP TABLE capture_extent; DROP TABLE capture_retention; DROP TABLE capture_methods; PRAGMA user_version=6;", to_v16()))
                .unwrap();
            drop(connection);

            let marker = directory.join("migration-checkpoint");
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "storage::migration_crash_tests::killed_migration_preserves_admission_before_and_after_commit"])
                .env("RUSTIRON_TEST_MIGRATION_DIRECTORY", &directory)
                .env("RUSTIRON_TEST_MIGRATION_CHECKPOINT", phase)
                .env("RUSTIRON_TEST_MIGRATION_MARKER", &marker)
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn().unwrap();
            let deadline = Instant::now() + Duration::from_secs(15);
            while !marker.exists()
                && Instant::now() < deadline
                && child.try_wait().unwrap().is_none()
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            let reached = marker.exists();
            if child.try_wait().unwrap().is_none() {
                child.kill().unwrap();
            }
            let status = child.wait().unwrap();
            assert!(reached, "child missed {phase} checkpoint: {status}");
            assert_eq!(status.signal(), Some(9), "child was not killed at {phase}");

            let mut reopened = if phase == "before_commit" {
                assert!(
                    FixtureJournal::open(&directory, id("host_fixture"), id("epoch_fixture"))
                        .is_err()
                );
                migrate(&directory).unwrap()
            } else {
                FixtureJournal::open(&directory, id("host_fixture"), id("epoch_fixture")).unwrap()
            };
            let RecordResult::Existing(existing) = reopened
                .record_intent(&admitted, Timestamp::try_from(1001).unwrap())
                .unwrap()
            else {
                panic!("admitted operation became new after {phase}");
            };
            assert_eq!(existing.state, RecordedState::Intent);
            assert_eq!(reopened.admission_count().unwrap(), 1);
            drop(reopened);
            std::fs::remove_dir_all(directory).unwrap();
        }
    }

    /// W214 (B10): a writer killed mid-transaction leaves a hot rollback
    /// journal; the next writer open must let SQLite roll it back (the
    /// sidecar passes the same owner/mode/link checks) and then validate,
    /// instead of refusing the journal until manual repair.
    #[test]
    fn a_hot_rollback_journal_from_a_killed_writer_is_rolled_back_on_open() {
        if let Some(directory) = std::env::var_os("RUSTIRON_TEST_HOT_DIRECTORY") {
            let directory = Path::new(&directory);
            let c = rusqlite::Connection::open(directory.join("fixture-journal.sqlite")).unwrap();
            c.execute_batch(
                "PRAGMA journal_mode=DELETE; PRAGMA cache_size=1; BEGIN IMMEDIATE; \
                 CREATE TABLE junk(b BLOB); INSERT INTO junk VALUES(zeroblob(300000)); \
                 UPDATE metadata SET host_id='hostile';",
            )
            .unwrap();
            std::fs::write(directory.join("hot-marker"), b"").unwrap();
            loop {
                std::thread::park();
            }
        }
        let directory =
            std::env::temp_dir().join(format!("rustiron-hot-journal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let mut journal =
            FixtureJournal::initialize(&directory, id("host_fixture"), id("epoch_fixture"))
                .unwrap();
        let admitted = intent();
        journal
            .record_intent(&admitted, Timestamp::try_from(1000).unwrap())
            .unwrap();
        drop(journal);
        let marker = directory.join("hot-marker");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "storage::migration_crash_tests::a_hot_rollback_journal_from_a_killed_writer_is_rolled_back_on_open"])
            .env("RUSTIRON_TEST_HOT_DIRECTORY", &directory)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        while !marker.exists() && Instant::now() < deadline && child.try_wait().unwrap().is_none() {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(marker.exists(), "child never held the transaction");
        child.kill().unwrap();
        assert_eq!(child.wait().unwrap().signal(), Some(9));
        std::fs::remove_file(&marker).unwrap();
        assert!(
            directory.join("fixture-journal.sqlite-journal").exists(),
            "no hot journal"
        );
        let mut reopened =
            FixtureJournal::open(&directory, id("host_fixture"), id("epoch_fixture"))
                .expect("hot journal must be rolled back, not refused");
        assert!(!directory.join("fixture-journal.sqlite-journal").exists());
        let RecordResult::Existing(existing) = reopened
            .record_intent(&admitted, Timestamp::try_from(1001).unwrap())
            .unwrap()
        else {
            panic!("admitted operation became new after the cut");
        };
        assert_eq!(existing.state, RecordedState::Intent);
        assert_eq!(reopened.admission_count().unwrap(), 1);
        drop(reopened);
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn write_v6(directory: &Path) {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(directory)
            .unwrap();
        let mut journal =
            FixtureJournal::initialize(directory, id("host_fixture"), id("epoch_fixture")).unwrap();
        journal
            .record_intent(&intent(), Timestamp::try_from(1000).unwrap())
            .unwrap();
        drop(journal);
        let connection =
            rusqlite::Connection::open(directory.join("fixture-journal.sqlite")).unwrap();
        connection
            .execute_batch(
                &format!("{} DROP TABLE page_cache_optouts; DROP TABLE page_cache_optins; DROP TABLE capture_unclaimed; DROP TABLE capture_backup_policy; DROP TABLE probe_backup_policy; DROP TABLE capture_freeze; DROP TABLE capture_consistency; DROP TABLE capture_manifest; DROP TABLE capture_extent; DROP TABLE capture_retention; DROP TABLE capture_methods; PRAGMA user_version=6;", to_v16()),
            )
            .unwrap();
    }

    /// A normal run migrates the disposable v6 journal and keeps the admitted
    /// operation. `RUSTIRON_V6_DIRECTORY` only writes that v6 journal and
    /// returns, so a later injected write failure can use the same bytes.
    #[test]
    fn a_v6_journal_migrates_without_losing_the_admitted_operation() {
        if let Some(path) = std::env::var_os("RUSTIRON_V6_DIRECTORY") {
            write_v6(Path::new(&path));
            return;
        }
        let directory =
            std::env::temp_dir().join(format!("rustiron-v6-migrate-{}", std::process::id()));
        write_v6(&directory);
        let mut journal = migrate(&directory).unwrap();
        let RecordResult::Existing(existing) = journal
            .record_intent(&intent(), Timestamp::try_from(1001).unwrap())
            .unwrap()
        else {
            panic!("admitted operation was not kept");
        };
        assert_eq!(existing.state, RecordedState::Intent);
        assert_eq!(journal.admission_count().unwrap(), 1);
        drop(journal);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
