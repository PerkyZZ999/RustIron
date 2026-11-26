use rustiron_contracts::{Id, Timestamp, approval::Sha256Digest};
use rustiron_journal::Intent;
pub fn id(value: &str) -> Id {
    Id::try_from(value.to_owned()).unwrap()
}
pub fn time(value: u64) -> Timestamp {
    Timestamp::try_from(value).unwrap()
}
pub fn digest(character: char) -> Sha256Digest {
    Sha256Digest::try_from(character.to_string().repeat(64)).unwrap()
}
pub fn intent(number: u32) -> Intent {
    Intent {
        operation_id: id(&format!("operation_{number}")),
        idempotency_key: id(&format!("retry_{number}")),
        grant_id: id(&format!("grant_{number}")),
        nonce: id(&format!("nonce_{number}")),
        plan_digest: digest('a'),
        grant_digest: digest('b'),
        host_id: id("host_fixture"),
        host_epoch: id("epoch_fixture"),
        resource_id: id("resource_fixture"),
        predecessor_generation: id("old_generation"),
        predecessor_digest: digest('c'),
        target_generation: id("new_generation"),
        target_digest: digest('d'),
        expires_at: time(10000),
        compensation_valid_until: time(10300),
    }
}

/// Rebuilds the import table with the original v21 dump-size constraint.
#[allow(dead_code)]
const REBUILD_LEGACY_IMPORTS: &str = "PRAGMA foreign_keys=OFF; DROP TABLE credential_rotations; DROP TABLE app_lifecycles; DROP TABLE app_release_steps; DROP TABLE app_releases; DROP TABLE apps; DROP TABLE static_ejections; DROP TABLE proxy_routes; DROP TABLE dns_change_sets; DROP TABLE dns_changes; DROP TABLE dns_imports; DROP TABLE restore_steps; DROP TABLE restore_attempts; DROP TABLE site_restores; DROP TABLE clone_scrub_grants; DROP TABLE quota_changes; DROP TABLE deletions; CREATE TEMP TABLE p32 AS SELECT * FROM provisions; DROP TABLE provisions; CREATE TABLE provisions (operation_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL, grant_digest TEXT NOT NULL, host_id TEXT NOT NULL, host_epoch TEXT NOT NULL, site_id TEXT NOT NULL UNIQUE, hostname TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('running','succeeded','quarantined','adopted'))) STRICT; INSERT INTO provisions SELECT * FROM temp.p32; DROP TABLE temp.p32; CREATE UNIQUE INDEX one_running_provision ON provisions((1)) WHERE state='running'; DROP TABLE update_rollbacks; DROP TABLE update_steps; DROP TABLE update_components; DROP INDEX one_open_update; DROP TABLE updates; DROP INDEX one_retirement; DROP TABLE retirements; DROP TABLE clone_scrubs; DROP TABLE clone_steps; DROP TABLE clones; DROP TABLE certificate_aliases; DROP TABLE import_aliases; PRAGMA foreign_keys=OFF; CREATE TEMP TABLE imports_new AS SELECT * FROM imports; DROP TABLE imports; CREATE TABLE imports (operation_id TEXT PRIMARY KEY REFERENCES provisions(operation_id), archive_sha256 TEXT NOT NULL CHECK(length(archive_sha256)=64 AND archive_sha256 NOT GLOB '*[^0-9a-f]*'), manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256)=64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'), file_entries INTEGER NOT NULL CHECK(file_entries BETWEEN 1 AND 200000), file_bytes INTEGER NOT NULL CHECK(file_bytes>=0), dump_bytes INTEGER NOT NULL CHECK(dump_bytes BETWEEN 1 AND 2147483648), target_php TEXT NOT NULL CHECK(length(target_php) BETWEEN 3 AND 4 AND target_php GLOB '[5-9].[0-9]*' AND substr(target_php,3) NOT GLOB '*[^0-9]*')) STRICT; INSERT INTO imports SELECT * FROM temp.imports_new; DROP TABLE temp.imports_new; ";

/// SQL to downgrade a fresh journal to a historical import schema.
#[allow(dead_code)]
pub fn legacy_import_schema(version: u8) -> String {
    let drop_tables = match version {
        21 => {
            "DROP TABLE import_sources; DROP TABLE certificate_renewals; DROP TABLE certificate_grants; DROP TABLE certificates; DROP TABLE import_scrubs;"
        }
        22 => {
            "DROP TABLE import_sources; DROP TABLE certificate_renewals; DROP TABLE certificate_grants; DROP TABLE certificates;"
        }
        23 => {
            "DROP TABLE import_sources; DROP TABLE certificate_renewals; DROP TABLE certificate_grants;"
        }
        24 => "DROP TABLE import_sources;",
        25 => "",
        _ => panic!("unsupported import schema version {version}"),
    };
    format!("{REBUILD_LEGACY_IMPORTS} {drop_tables} PRAGMA user_version={version};")
}

/// W442: turns a fresh journal into the v20 shape: the import tables (and
/// the v22 scrubs) dropped.
#[allow(dead_code)]
pub const TO_V20: &str = "PRAGMA foreign_keys=OFF; DROP TABLE credential_rotations; DROP TABLE app_lifecycles; DROP TABLE app_release_steps; DROP TABLE app_releases; DROP TABLE apps; DROP TABLE static_ejections; DROP TABLE proxy_routes; DROP TABLE dns_change_sets; DROP TABLE dns_changes; DROP TABLE dns_imports; DROP TABLE restore_steps; DROP TABLE restore_attempts; DROP TABLE site_restores; DROP TABLE clone_scrub_grants; DROP TABLE quota_changes; DROP TABLE deletions; CREATE TEMP TABLE p32 AS SELECT * FROM provisions; DROP TABLE provisions; CREATE TABLE provisions (operation_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL, grant_digest TEXT NOT NULL, host_id TEXT NOT NULL, host_epoch TEXT NOT NULL, site_id TEXT NOT NULL UNIQUE, hostname TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('running','succeeded','quarantined','adopted'))) STRICT; INSERT INTO provisions SELECT * FROM temp.p32; DROP TABLE temp.p32; CREATE UNIQUE INDEX one_running_provision ON provisions((1)) WHERE state='running'; DROP TABLE update_rollbacks; DROP TABLE update_steps; DROP TABLE update_components; DROP INDEX one_open_update; DROP TABLE updates; DROP INDEX one_retirement; DROP TABLE retirements; DROP TABLE clone_scrubs; DROP TABLE clone_steps; DROP TABLE clones; DROP TABLE certificate_aliases; DROP TABLE import_aliases; DROP TABLE import_sources; DROP TABLE certificate_renewals; DROP TABLE certificate_grants; DROP TABLE certificates; DROP TABLE import_scrubs; DROP TABLE import_steps; DROP TABLE imports; \
PRAGMA user_version=20;";

/// W396: turns a fresh v20 journal into the v19 shape: the signed admission
/// tables dropped.
#[allow(dead_code)]
pub const TO_V19: &str = "PRAGMA foreign_keys=OFF; DROP TABLE credential_rotations; DROP TABLE app_lifecycles; DROP TABLE app_release_steps; DROP TABLE app_releases; DROP TABLE apps; DROP TABLE static_ejections; DROP TABLE proxy_routes; DROP TABLE dns_change_sets; DROP TABLE dns_changes; DROP TABLE dns_imports; DROP TABLE restore_steps; DROP TABLE restore_attempts; DROP TABLE site_restores; DROP TABLE clone_scrub_grants; DROP TABLE quota_changes; DROP TABLE deletions; CREATE TEMP TABLE p32 AS SELECT * FROM provisions; DROP TABLE provisions; CREATE TABLE provisions (operation_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL, grant_digest TEXT NOT NULL, host_id TEXT NOT NULL, host_epoch TEXT NOT NULL, site_id TEXT NOT NULL UNIQUE, hostname TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('running','succeeded','quarantined','adopted'))) STRICT; INSERT INTO provisions SELECT * FROM temp.p32; DROP TABLE temp.p32; CREATE UNIQUE INDEX one_running_provision ON provisions((1)) WHERE state='running'; DROP TABLE update_rollbacks; DROP TABLE update_steps; DROP TABLE update_components; DROP INDEX one_open_update; DROP TABLE updates; DROP INDEX one_retirement; DROP TABLE retirements; DROP TABLE clone_scrubs; DROP TABLE clone_steps; DROP TABLE clones; DROP TABLE certificate_aliases; DROP TABLE import_aliases; DROP TABLE import_sources; DROP TABLE certificate_renewals; DROP TABLE certificate_grants; DROP TABLE certificates; DROP TABLE import_scrubs; DROP TABLE import_steps; DROP TABLE imports; DROP TABLE admission_signatures; DROP TABLE signed_objects; \
PRAGMA user_version=19;";

/// W395: turns a fresh journal into the v18 shape: the v20 tables (as
/// [`TO_V19`]) and the page-cache recipe table dropped.
#[allow(dead_code)]
pub const TO_V18: &str = "PRAGMA foreign_keys=OFF; DROP TABLE credential_rotations; DROP TABLE app_lifecycles; DROP TABLE app_release_steps; DROP TABLE app_releases; DROP TABLE apps; DROP TABLE static_ejections; DROP TABLE proxy_routes; DROP TABLE dns_change_sets; DROP TABLE dns_changes; DROP TABLE dns_imports; DROP TABLE restore_steps; DROP TABLE restore_attempts; DROP TABLE site_restores; DROP TABLE clone_scrub_grants; DROP TABLE quota_changes; DROP TABLE deletions; CREATE TEMP TABLE p32 AS SELECT * FROM provisions; DROP TABLE provisions; CREATE TABLE provisions (operation_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL, grant_digest TEXT NOT NULL, host_id TEXT NOT NULL, host_epoch TEXT NOT NULL, site_id TEXT NOT NULL UNIQUE, hostname TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('running','succeeded','quarantined','adopted'))) STRICT; INSERT INTO provisions SELECT * FROM temp.p32; DROP TABLE temp.p32; CREATE UNIQUE INDEX one_running_provision ON provisions((1)) WHERE state='running'; DROP TABLE update_rollbacks; DROP TABLE update_steps; DROP TABLE update_components; DROP INDEX one_open_update; DROP TABLE updates; DROP INDEX one_retirement; DROP TABLE retirements; DROP TABLE clone_scrubs; DROP TABLE clone_steps; DROP TABLE clones; DROP TABLE certificate_aliases; DROP TABLE import_aliases; DROP TABLE import_sources; PRAGMA foreign_keys=OFF; \
DROP TABLE certificate_renewals; DROP TABLE certificate_grants; DROP TABLE certificates; DROP TABLE import_scrubs; DROP TABLE import_steps; DROP TABLE imports; DROP TABLE admission_signatures; DROP TABLE signed_objects; \
DROP TABLE page_cache_recipes; PRAGMA user_version=18;";

/// W391: turns a fresh journal into the v17 shape: the v19 and v20 tables (as
/// [`TO_V18`]), the retention evidence and capture refusal tables dropped.
#[allow(dead_code)]
pub const TO_V17: &str = "PRAGMA foreign_keys=OFF; DROP TABLE credential_rotations; DROP TABLE app_lifecycles; DROP TABLE app_release_steps; DROP TABLE app_releases; DROP TABLE apps; DROP TABLE static_ejections; DROP TABLE proxy_routes; DROP TABLE dns_change_sets; DROP TABLE dns_changes; DROP TABLE dns_imports; DROP TABLE restore_steps; DROP TABLE restore_attempts; DROP TABLE site_restores; DROP TABLE clone_scrub_grants; DROP TABLE quota_changes; DROP TABLE deletions; CREATE TEMP TABLE p32 AS SELECT * FROM provisions; DROP TABLE provisions; CREATE TABLE provisions (operation_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL, grant_digest TEXT NOT NULL, host_id TEXT NOT NULL, host_epoch TEXT NOT NULL, site_id TEXT NOT NULL UNIQUE, hostname TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('running','succeeded','quarantined','adopted'))) STRICT; INSERT INTO provisions SELECT * FROM temp.p32; DROP TABLE temp.p32; CREATE UNIQUE INDEX one_running_provision ON provisions((1)) WHERE state='running'; DROP TABLE update_rollbacks; DROP TABLE update_steps; DROP TABLE update_components; DROP INDEX one_open_update; DROP TABLE updates; DROP INDEX one_retirement; DROP TABLE retirements; DROP TABLE clone_scrubs; DROP TABLE clone_steps; DROP TABLE clones; DROP TABLE certificate_aliases; DROP TABLE import_aliases; DROP TABLE import_sources; PRAGMA foreign_keys=OFF; \
DROP TABLE certificate_renewals; DROP TABLE certificate_grants; DROP TABLE certificates; DROP TABLE import_scrubs; DROP TABLE import_steps; DROP TABLE imports; DROP TABLE admission_signatures; DROP TABLE signed_objects; DROP TABLE page_cache_recipes; \
DROP TABLE capture_object_retention; DROP TABLE capture_lock_checks; DROP TABLE capture_refusals; \
PRAGMA user_version=17;";

/// W372: turns a fresh journal into the v16 shape: the v18 to v20 tables (as
/// [`TO_V17`]) and the re-adoption tables dropped, and `provisions` rebuilt
/// with the v16 state check. Other tests then drop further tables to reach
/// older versions.
#[allow(dead_code)]
pub const TO_V16: &str = "PRAGMA foreign_keys=OFF; DROP TABLE credential_rotations; DROP TABLE app_lifecycles; DROP TABLE app_release_steps; DROP TABLE app_releases; DROP TABLE apps; DROP TABLE static_ejections; DROP TABLE proxy_routes; DROP TABLE dns_change_sets; DROP TABLE dns_changes; DROP TABLE dns_imports; DROP TABLE restore_steps; DROP TABLE restore_attempts; DROP TABLE site_restores; DROP TABLE clone_scrub_grants; DROP TABLE quota_changes; DROP TABLE deletions; CREATE TEMP TABLE p32 AS SELECT * FROM provisions; DROP TABLE provisions; CREATE TABLE provisions (operation_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL, grant_digest TEXT NOT NULL, host_id TEXT NOT NULL, host_epoch TEXT NOT NULL, site_id TEXT NOT NULL UNIQUE, hostname TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('running','succeeded','quarantined','adopted'))) STRICT; INSERT INTO provisions SELECT * FROM temp.p32; DROP TABLE temp.p32; CREATE UNIQUE INDEX one_running_provision ON provisions((1)) WHERE state='running'; DROP TABLE update_rollbacks; DROP TABLE update_steps; DROP TABLE update_components; DROP INDEX one_open_update; DROP TABLE updates; DROP INDEX one_retirement; DROP TABLE retirements; DROP TABLE clone_scrubs; DROP TABLE clone_steps; DROP TABLE clones; DROP TABLE certificate_aliases; DROP TABLE import_aliases; DROP TABLE import_sources; PRAGMA foreign_keys=OFF; \
DROP TABLE certificate_renewals; DROP TABLE certificate_grants; DROP TABLE certificates; DROP TABLE import_scrubs; DROP TABLE import_steps; DROP TABLE imports; DROP TABLE admission_signatures; DROP TABLE signed_objects; DROP TABLE page_cache_recipes; \
DROP TABLE capture_object_retention; DROP TABLE capture_lock_checks; DROP TABLE capture_refusals; \
DROP TABLE allocation_floors; DROP TABLE ols_adoptions; DROP TABLE provision_adoptions; DROP TABLE readoptions; \
CREATE TEMP TABLE provisions_v17 AS SELECT * FROM provisions; DROP TABLE provisions; \
CREATE TABLE provisions (operation_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL, grant_digest TEXT NOT NULL, host_id TEXT NOT NULL, host_epoch TEXT NOT NULL, site_id TEXT NOT NULL UNIQUE, hostname TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('running','succeeded','quarantined'))) STRICT; \
INSERT INTO provisions SELECT * FROM temp.provisions_v17; DROP TABLE temp.provisions_v17; \
CREATE UNIQUE INDEX one_running_provision ON provisions((1)) WHERE state='running'; \
PRAGMA user_version=16;";

/// W396: the exact v20 tables.
#[allow(dead_code)]
pub const DDL_V20: [(&str, &str); 2] = [
    (
        "signed_objects",
        "CREATE TABLE signed_objects (sha256 TEXT PRIMARY KEY CHECK(length(sha256)=64 AND sha256 NOT GLOB '*[^0-9a-f]*'), canonical TEXT NOT NULL CHECK(length(CAST(canonical AS BLOB)) BETWEEN 2 AND 8192)) STRICT, WITHOUT ROWID",
    ),
    (
        "admission_signatures",
        "CREATE TABLE admission_signatures (operation_id TEXT PRIMARY KEY, plan_sha256 TEXT NOT NULL CHECK(length(plan_sha256)=64 AND plan_sha256 NOT GLOB '*[^0-9a-f]*'), plan_bytes INTEGER NOT NULL CHECK(plan_bytes BETWEEN 2 AND 262144), grant_sha256 TEXT NOT NULL CHECK(length(grant_sha256)=64 AND grant_sha256 NOT GLOB '*[^0-9a-f]*'), grant_bytes INTEGER NOT NULL CHECK(grant_bytes BETWEEN 2 AND 262144), issuer TEXT NOT NULL CHECK(length(issuer) BETWEEN 1 AND 64), signer_policy_epoch TEXT NOT NULL CHECK(length(signer_policy_epoch) BETWEEN 1 AND 64), verification TEXT NOT NULL CHECK(verification='sshsig_verified')) STRICT",
    ),
];

/// W576: turns the v41 `deletions` (nullable capture) back into the v33 to
/// v40 table, rows kept, for a downgrade to one of those versions.
#[allow(dead_code)]
pub const TO_V40_DELETIONS: &str = "CREATE TEMP TABLE d40 AS SELECT * FROM deletions; DROP TABLE deletions; CREATE TABLE deletions (operation_id TEXT PRIMARY KEY, provision_operation_id TEXT NOT NULL REFERENCES provisions(operation_id), capture_operation_id TEXT NOT NULL REFERENCES captures(operation_id), idempotency_key TEXT NOT NULL UNIQUE, grant_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL CHECK(length(plan_digest)=64 AND plan_digest NOT GLOB '*[^0-9a-f]*'), grant_digest TEXT NOT NULL CHECK(length(grant_digest)=64 AND grant_digest NOT GLOB '*[^0-9a-f]*'), expires_at INTEGER NOT NULL CHECK(expires_at>=0), state TEXT NOT NULL CHECK(state IN ('intent','done','failed'))) STRICT; INSERT INTO deletions SELECT * FROM temp.d40; DROP TABLE temp.d40; CREATE UNIQUE INDEX one_deletion ON deletions(provision_operation_id) WHERE state<>'failed';";
