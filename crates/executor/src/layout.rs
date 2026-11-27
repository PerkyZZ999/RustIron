//! Every Rustiron-owned host location compiled into the executor binaries.
//!
//! Two profiles are written here and one is compiled in. The default is the
//! lab. A build with `--cfg rustiron_profile="product"` takes the product
//! values of D-024 instead. The executor, the administration helper and the
//! capture-manifest worker take their own paths from the selected profile
//! and nowhere else (`tests/host_layout.rs` enforces that). Locations owned
//! by other software (the OLS server root, MariaDB, system tools) are
//! host-profile facts and stay beside the code that uses them.
//!
//! No value here comes from a request. A path is still not trusted because
//! it is listed: every use keeps its own ownership, ancestry and link checks.

#[cfg(not(rustiron_profile = "product"))]
pub use lab::*;
#[cfg(rustiron_profile = "product")]
pub use product::*;

/// The database dump a capture writes into `<site root>/tmp` and snapshots
/// (W033). A file name, not a location: both profiles use it under the
/// site's own tmp directory, and the product worker derives the full path
/// from [`SITES_ROOT`] and the site ID (W356).
pub const CAPTURE_DUMP_FILE: &str = "rustiron-capture.sql";

/// Plain file name of an app site's consistent SQLite online-backup tar bundle
/// inside `<site>/tmp` (W601, D-096/P30).
pub const APP_SQLITE_BUNDLE_FILE: &str = "rustiron-app-sqlite.tar";

/// Plain file name of a PostgreSQL 18 app site's custom-format `pg_dump` file
/// inside `<site>/tmp` (W658, D-102 Decision C2).
pub const APP_PG_DUMP_FILE: &str = "rustiron-app-postgres.dump";

/// Plain file name of a MariaDB app site's consistent SQL dump file inside
/// `<site>/tmp` (W658, D-102 Decision C2).
pub const APP_MARIADB_DUMP_FILE: &str = "rustiron-app-mariadb.sql";

/// The writable directory of one probe sandbox,
/// `<RESTORE_PROBES_ROOT>/<probe>/tmp`, for a journaled probe account
/// (`rp_` and six lowercase hex digits). Any other name is `None`. The
/// executor and the product store worker both derive the restore target
/// from it (D-031, W373).
pub fn probe_tmp(probe: &str) -> Option<String> {
    let hex = probe.strip_prefix("rp_")?;
    (hex.len() == 6
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    .then(|| format!("{RESTORE_PROBES_ROOT}/{probe}/tmp"))
}

/// The restore target inside [`probe_tmp`]. Restic creates it.
pub const PROBE_RESTORE_DIR: &str = "restore";

/// D-078 (W499): the writable directory of a clone's fetch, the target
/// site's own `<SITES_ROOT>/<account>/tmp`, for a site account (`rs_` and a
/// valid site ID). Any other name is `None`. The executor and the product
/// store worker both derive the clone's restore target from it.
pub fn clone_tmp(account: &str) -> Option<String> {
    let site = account.strip_prefix("rs_")?;
    rustiron_contracts::approval::SiteId::try_from(site.to_owned())
        .ok()
        .filter(|id| id.account_name() == account)
        .map(|_| format!("{SITES_ROOT}/{account}/tmp"))
}

/// The clone's restore target inside [`clone_tmp`]. Restic creates it.
pub const CLONE_RESTORE_DIR: &str = "clone";

/// The lab profile: the `almalinux10` fixture host. The default.
pub mod lab {
    /// Root-admin policy directory (`policy.json`, `allowed_signers`, `revocations`).
    pub const POLICY_DIR: &str = "/etc/rustiron-s02-lab";
    /// Lab fixture registry root. The fixture switch is a lab-only path.
    pub const FIXTURE_REGISTRY_DIR: Option<&str> = Some("/var/lib/rustiron-s02-lab/fixture");
    /// Private scratch directory for verifier inputs.
    pub const SCRATCH_DIR: &str = "/var/lib/rustiron-s02-lab/scratch";
    /// Owner-only directory holding the executor journal.
    pub const JOURNAL_DIR: &str = "/var/lib/rustiron-s02-lab/executor";
    /// Owner-only directory holding the admission high-water mark, outside
    /// [`JOURNAL_DIR`] so restoring the journal directory leaves it behind.
    pub const MARK_DIR: &str = "/var/lib/rustiron-s02-lab/admission";
    /// Root-owned store of pinned provisioning recipes.
    pub const RECIPES_DIR: &str = "/var/lib/rustiron-s04-lab/recipes";

    /// The executor's submission socket.
    pub const EXECUTOR_SOCKET: &str = "/run/rustiron-s02-lab/executor.sock";
    /// The administration helper's runtime directory. PID 1 also writes each
    /// capture and probe unit's stdout here for the helper to read (W174).
    pub const ADMIN_RUNTIME_DIR: &str = "/run/rustiron-admin";
    /// The administration helper's socket, inside [`ADMIN_RUNTIME_DIR`].
    pub const ADMIN_SOCKET: &str = "/run/rustiron-admin/helper.sock";

    /// Root-only per-site upload/read identities and repository passwords.
    pub const JOB_CREDENTIALS_DIR: &str = "/etc/rustiron-s07-lab/sites";
    /// Capture and probe job programs: byte-identical copies of the RPM
    /// binaries and the fixed workers, labelled as the job domains' entries.
    pub const JOB_BIN_DIR: &str = "/usr/local/libexec/rustiron-s07-lab";
    /// The restic copy inside [`JOB_BIN_DIR`], named in full for the
    /// capture-manifest worker, which builds no paths.
    pub const JOB_RESTIC: &str = "/usr/local/libexec/rustiron-s07-lab/restic";
    /// W446 (D-053): the export inventory worker inside [`JOB_BIN_DIR`].
    pub const JOB_MIGRATION_INVENTORY: &str =
        "/usr/local/libexec/rustiron-s07-lab/migration-inventory";
    /// W446 (D-053): root-only intake of site import archives,
    /// `<MIGRATION_INTAKE_DIR>/<site_id>/export.tar.gz`.
    pub const MIGRATION_INTAKE_DIR: &str = "/var/lib/rustiron-s02-lab/migration-intake";
    /// W515 (D-084): root-only intake of WordPress update recipes,
    /// `<UPDATE_INTAKE_DIR>/<site_id>/recipe.tar`.
    pub const UPDATE_INTAKE_DIR: &str = "/var/lib/rustiron-s02-lab/update-intake";
    /// W563 (D-091): root-only intake of canonical zone files,
    /// `<DNS_INTAKE_DIR>/<zone>/zone.txt`.
    pub const DNS_INTAKE_DIR: &str = "/var/lib/rustiron-s02-lab/dns-intake";
    /// W598 (D-099): root-only intake of prepared app release bundles,
    /// `<APP_INTAKE_DIR>/<site_id>/<release_id>/bundle.tar.gz` and `manifest.sha256`.
    pub const APP_INTAKE_DIR: &str = "/var/lib/rustiron-s02-lab/app-intake";

    /// Parent of every provisioned site: `<SITES_ROOT>/<account>`.
    pub const SITES_ROOT: &str = "/srv/sites";
    /// Parent of every restore-probe sandbox: `<RESTORE_PROBES_ROOT>/<probe>`.
    pub const RESTORE_PROBES_ROOT: &str = "/srv/restore-probes";

    /// The Rustiron-owned OLS include directory (generations and `current`).
    pub const OLS_INCLUDE_DIR: &str = "/etc/rustiron-ols";
    /// W657 (D-102): the Rustiron-owned Caddy configuration directory (generations and `current`).
    pub const CADDY_CONFIG_DIR: &str = "/etc/rustiron-caddy";
    /// W662-F4: Caddy admin API socket in its unit's `0700` `RuntimeDirectory=`.
    pub const CADDY_ADMIN_SOCKET: &str = "/run/rustiron-caddy/admin.sock";
    /// The one line the reviewed OLS parent must hold to load [`OLS_INCLUDE_DIR`].
    pub const OLS_INCLUDE_LINE: &str = "include /etc/rustiron-ols/current/*.conf";
    /// Where ejected sites' vhost files live, outside [`OLS_INCLUDE_DIR`].
    pub const OLS_EJECTED_DIR: &str = "/etc/rustiron-ejected";
    /// D-059: installed certificates, `<account>/<certificate sha256>/`,
    /// outside [`OLS_INCLUDE_DIR`] so that generations never hold a key.
    pub const OLS_TLS_DIR: &str = "/etc/rustiron-tls";
    /// D-059: the state folder of the `rustiron-acme` certbot account.
    pub const ACME_STATE_DIR: &str = "/var/lib/rustiron-acme";
    /// Prefix of the per-site PHP pool unit template and of each site's
    /// `<prefix><account>.service.d` drop-in directory.
    pub const SITE_PHP_UNIT_PREFIX: &str = "/etc/systemd/system/rustiron-site-php@";
    /// The per-site PHP pool unit template.
    pub const SITE_PHP_UNIT: &str = "/etc/systemd/system/rustiron-site-php@.service";
    /// W598 (D-099): prefix of the per-site modern app unit template and drop-ins.
    pub const SITE_APP_UNIT_PREFIX: &str = "/etc/systemd/system/rustiron-app@";
    /// W659 (D-102): prefix of the blue/green standby slot B backend unit template.
    pub const SITE_APP_B_UNIT_PREFIX: &str = "/etc/systemd/system/rustiron-app-b@";
    /// W659 (D-102): prefix of the dual-SSR frontend unit template and drop-ins.
    pub const SITE_APP_WEB_UNIT_PREFIX: &str = "/etc/systemd/system/rustiron-app-web@";
    /// W659 (D-102): prefix of the blue/green standby slot B dual-SSR frontend unit template.
    pub const SITE_APP_WEB_B_UNIT_PREFIX: &str = "/etc/systemd/system/rustiron-app-web-b@";
    /// W598 (D-099): prefix of the per-site companion worker unit template and drop-ins.
    pub const SITE_APP_WORKER_UNIT_PREFIX: &str = "/etc/systemd/system/rustiron-app-worker@";
    /// W598 (D-099): per-site modern app unit template.
    pub const SITE_APP_UNIT: &str = "/etc/systemd/system/rustiron-app@.service";
    /// W659 (D-102): blue/green standby slot B backend unit template.
    pub const SITE_APP_B_UNIT: &str = "/etc/systemd/system/rustiron-app-b@.service";
    /// W659 (D-102): dual-SSR frontend unit template.
    pub const SITE_APP_WEB_UNIT: &str = "/etc/systemd/system/rustiron-app-web@.service";
    /// W659 (D-102): blue/green standby slot B dual-SSR frontend unit template.
    pub const SITE_APP_WEB_B_UNIT: &str = "/etc/systemd/system/rustiron-app-web-b@.service";
    /// W598 (D-099): per-site companion worker unit template.
    pub const SITE_APP_WORKER_UNIT: &str = "/etc/systemd/system/rustiron-app-worker@.service";
    /// Directory of the per-site PHP pool sockets: `<dir>/<account>.sock`.
    pub const SITE_SOCKETS_DIR: &str = "/run/rustiron-sites";
    /// Handle of the endpoint-only network namespace for store jobs (W315).
    /// A root-owned host setup creates it; the executor only verifies it.
    pub const STORE_NETNS: &str = "/run/netns/rustiron-store";

    /// Every path of this profile, for checks that must cover all of them.
    pub const ALL: &[&str] = &[
        POLICY_DIR,
        SCRATCH_DIR,
        JOURNAL_DIR,
        MARK_DIR,
        RECIPES_DIR,
        EXECUTOR_SOCKET,
        ADMIN_RUNTIME_DIR,
        ADMIN_SOCKET,
        JOB_CREDENTIALS_DIR,
        JOB_BIN_DIR,
        JOB_RESTIC,
        JOB_MIGRATION_INVENTORY,
        MIGRATION_INTAKE_DIR,
        UPDATE_INTAKE_DIR,
        DNS_INTAKE_DIR,
        APP_INTAKE_DIR,
        SITES_ROOT,
        RESTORE_PROBES_ROOT,
        OLS_INCLUDE_DIR,
        CADDY_CONFIG_DIR,
        CADDY_ADMIN_SOCKET,
        OLS_EJECTED_DIR,
        OLS_TLS_DIR,
        ACME_STATE_DIR,
        SITE_PHP_UNIT_PREFIX,
        SITE_PHP_UNIT,
        SITE_APP_UNIT_PREFIX,
        SITE_APP_B_UNIT_PREFIX,
        SITE_APP_WEB_UNIT_PREFIX,
        SITE_APP_WEB_B_UNIT_PREFIX,
        SITE_APP_WORKER_UNIT_PREFIX,
        SITE_APP_UNIT,
        SITE_APP_B_UNIT,
        SITE_APP_WEB_UNIT,
        SITE_APP_WEB_B_UNIT,
        SITE_APP_WORKER_UNIT,
        SITE_SOCKETS_DIR,
        STORE_NETNS,
    ];
}

/// The product profile ([D-024](../../../docs/decisions/D-024-product-host-layout.md)).
/// The product systemd units use these paths. Product installation is pending.
pub mod product {
    /// Root-admin policy directory (`policy.json`, `allowed_signers`, `revocations`).
    pub const POLICY_DIR: &str = "/etc/rustiron";
    /// None: the lab fixture switch does not exist in the product profile.
    pub const FIXTURE_REGISTRY_DIR: Option<&str> = None;
    /// Private scratch directory for verifier inputs.
    pub const SCRATCH_DIR: &str = "/var/lib/rustiron/scratch";
    /// Owner-only directory holding the executor journal.
    pub const JOURNAL_DIR: &str = "/var/lib/rustiron/executor";
    /// Owner-only directory holding the admission high-water mark, outside
    /// [`JOURNAL_DIR`] so restoring the journal directory leaves it behind.
    pub const MARK_DIR: &str = "/var/lib/rustiron/admission";
    /// Root-owned store of pinned provisioning recipes.
    pub const RECIPES_DIR: &str = "/var/lib/rustiron/recipes";

    /// The executor's submission socket.
    pub const EXECUTOR_SOCKET: &str = "/run/rustiron/executor.sock";
    /// The administration helper's runtime directory. PID 1 also writes each
    /// capture and probe unit's stdout here for the helper to read (W174).
    pub const ADMIN_RUNTIME_DIR: &str = "/run/rustiron-admin";
    /// The administration helper's socket, inside [`ADMIN_RUNTIME_DIR`].
    pub const ADMIN_SOCKET: &str = "/run/rustiron-admin/helper.sock";

    /// Root-only per-site upload/read identities and repository passwords.
    pub const JOB_CREDENTIALS_DIR: &str = "/etc/rustiron/credentials/sites";
    /// Capture and probe job programs: byte-identical copies of the RPM
    /// binaries and the fixed workers, labelled as the job domains' entries.
    pub const JOB_BIN_DIR: &str = "/usr/libexec/rustiron/jobs";
    /// The restic copy inside [`JOB_BIN_DIR`], named in full for the
    /// capture-manifest worker, which builds no paths.
    pub const JOB_RESTIC: &str = "/usr/libexec/rustiron/jobs/restic";
    /// W446 (D-053): the export inventory worker inside [`JOB_BIN_DIR`].
    pub const JOB_MIGRATION_INVENTORY: &str = "/usr/libexec/rustiron/jobs/migration-inventory";
    /// W446 (D-053): root-only intake of site import archives,
    /// `<MIGRATION_INTAKE_DIR>/<site_id>/export.tar.gz`.
    pub const MIGRATION_INTAKE_DIR: &str = "/var/lib/rustiron/migration-intake";
    /// W515 (D-084): root-only intake of WordPress update recipes,
    /// `<UPDATE_INTAKE_DIR>/<site_id>/recipe.tar`.
    pub const UPDATE_INTAKE_DIR: &str = "/var/lib/rustiron/update-intake";
    /// W563 (D-091): root-only intake of canonical zone files,
    /// `<DNS_INTAKE_DIR>/<zone>/zone.txt`.
    pub const DNS_INTAKE_DIR: &str = "/var/lib/rustiron/dns-intake";
    /// W598 (D-099): root-only intake of prepared app release bundles,
    /// `<APP_INTAKE_DIR>/<site_id>/<release_id>/bundle.tar.gz` and `manifest.sha256`.
    pub const APP_INTAKE_DIR: &str = "/var/lib/rustiron/app-intake";

    /// Parent of every provisioned site: `<SITES_ROOT>/<account>`.
    pub const SITES_ROOT: &str = "/srv/sites";
    /// Parent of every restore-probe sandbox: `<RESTORE_PROBES_ROOT>/<probe>`.
    pub const RESTORE_PROBES_ROOT: &str = "/srv/restore-probes";

    /// The Rustiron-owned OLS include directory (generations and `current`).
    pub const OLS_INCLUDE_DIR: &str = "/etc/rustiron-ols";
    /// W657 (D-102): the Rustiron-owned Caddy configuration directory (generations and `current`).
    pub const CADDY_CONFIG_DIR: &str = "/etc/rustiron-caddy";
    /// W662-F4: Caddy admin API socket in its unit's `0700` `RuntimeDirectory=`.
    pub const CADDY_ADMIN_SOCKET: &str = "/run/rustiron-caddy/admin.sock";
    /// The one line the reviewed OLS parent must hold to load [`OLS_INCLUDE_DIR`].
    pub const OLS_INCLUDE_LINE: &str = "include /etc/rustiron-ols/current/*.conf";
    /// Where ejected sites' vhost files live, outside [`OLS_INCLUDE_DIR`].
    pub const OLS_EJECTED_DIR: &str = "/etc/rustiron-ejected";
    /// D-059: installed certificates, `<account>/<certificate sha256>/`,
    /// outside [`OLS_INCLUDE_DIR`] so that generations never hold a key.
    pub const OLS_TLS_DIR: &str = "/etc/rustiron-tls";
    /// D-059: the state folder of the `rustiron-acme` certbot account.
    pub const ACME_STATE_DIR: &str = "/var/lib/rustiron-acme";
    /// Prefix of the per-site PHP pool unit template and of each site's
    /// `<prefix><account>.service.d` drop-in directory.
    pub const SITE_PHP_UNIT_PREFIX: &str = "/etc/systemd/system/rustiron-site-php@";
    /// The per-site PHP pool unit template.
    pub const SITE_PHP_UNIT: &str = "/etc/systemd/system/rustiron-site-php@.service";
    /// W598 (D-099): prefix of the per-site modern app unit template and drop-ins.
    pub const SITE_APP_UNIT_PREFIX: &str = "/etc/systemd/system/rustiron-app@";
    /// W659 (D-102): prefix of the blue/green standby slot B backend unit template.
    pub const SITE_APP_B_UNIT_PREFIX: &str = "/etc/systemd/system/rustiron-app-b@";
    /// W659 (D-102): prefix of the dual-SSR frontend unit template and drop-ins.
    pub const SITE_APP_WEB_UNIT_PREFIX: &str = "/etc/systemd/system/rustiron-app-web@";
    /// W659 (D-102): prefix of the blue/green standby slot B dual-SSR frontend unit template.
    pub const SITE_APP_WEB_B_UNIT_PREFIX: &str = "/etc/systemd/system/rustiron-app-web-b@";
    /// W598 (D-099): prefix of the per-site companion worker unit template and drop-ins.
    pub const SITE_APP_WORKER_UNIT_PREFIX: &str = "/etc/systemd/system/rustiron-app-worker@";
    /// W598 (D-099): per-site modern app unit template.
    pub const SITE_APP_UNIT: &str = "/etc/systemd/system/rustiron-app@.service";
    /// W659 (D-102): blue/green standby slot B backend unit template.
    pub const SITE_APP_B_UNIT: &str = "/etc/systemd/system/rustiron-app-b@.service";
    /// W659 (D-102): dual-SSR frontend unit template.
    pub const SITE_APP_WEB_UNIT: &str = "/etc/systemd/system/rustiron-app-web@.service";
    /// W659 (D-102): blue/green standby slot B dual-SSR frontend unit template.
    pub const SITE_APP_WEB_B_UNIT: &str = "/etc/systemd/system/rustiron-app-web-b@.service";
    /// W598 (D-099): per-site companion worker unit template.
    pub const SITE_APP_WORKER_UNIT: &str = "/etc/systemd/system/rustiron-app-worker@.service";
    /// Directory of the per-site PHP pool sockets: `<dir>/<account>.sock`.
    pub const SITE_SOCKETS_DIR: &str = "/run/rustiron-sites";
    /// Handle of the endpoint-only network namespace for store jobs (W315).
    /// A root-owned host setup creates it; the executor only verifies it.
    pub const STORE_NETNS: &str = "/run/netns/rustiron-store";

    /// Every path of this profile, for checks that must cover all of them.
    pub const ALL: &[&str] = &[
        POLICY_DIR,
        SCRATCH_DIR,
        JOURNAL_DIR,
        MARK_DIR,
        RECIPES_DIR,
        EXECUTOR_SOCKET,
        ADMIN_RUNTIME_DIR,
        ADMIN_SOCKET,
        JOB_CREDENTIALS_DIR,
        JOB_BIN_DIR,
        JOB_RESTIC,
        JOB_MIGRATION_INVENTORY,
        MIGRATION_INTAKE_DIR,
        UPDATE_INTAKE_DIR,
        DNS_INTAKE_DIR,
        APP_INTAKE_DIR,
        SITES_ROOT,
        RESTORE_PROBES_ROOT,
        OLS_INCLUDE_DIR,
        CADDY_CONFIG_DIR,
        CADDY_ADMIN_SOCKET,
        OLS_EJECTED_DIR,
        OLS_TLS_DIR,
        ACME_STATE_DIR,
        SITE_PHP_UNIT_PREFIX,
        SITE_PHP_UNIT,
        SITE_APP_UNIT_PREFIX,
        SITE_APP_B_UNIT_PREFIX,
        SITE_APP_WEB_UNIT_PREFIX,
        SITE_APP_WEB_B_UNIT_PREFIX,
        SITE_APP_WORKER_UNIT_PREFIX,
        SITE_APP_UNIT,
        SITE_APP_B_UNIT,
        SITE_APP_WEB_UNIT,
        SITE_APP_WEB_B_UNIT,
        SITE_APP_WORKER_UNIT,
        SITE_SOCKETS_DIR,
        STORE_NETNS,
    ];
}

#[cfg(test)]
mod tests {
    use super::{lab, product};

    struct Profile {
        all: &'static [&'static str],
        fixture: Option<&'static str>,
        include_line: &'static str,
    }

    const PROFILES: [Profile; 2] = [
        Profile {
            all: lab::ALL,
            fixture: lab::FIXTURE_REGISTRY_DIR,
            include_line: lab::OLS_INCLUDE_LINE,
        },
        Profile {
            all: product::ALL,
            fixture: product::FIXTURE_REGISTRY_DIR,
            include_line: product::OLS_INCLUDE_LINE,
        },
    ];

    fn normal(path: &str) -> bool {
        path.starts_with('/')
            && path.split('/').skip(1).all(|part| {
                !part.is_empty()
                    && part != "."
                    && part != ".."
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b))
            })
    }

    #[test]
    fn only_a_journaled_probe_account_names_a_sandbox() {
        assert_eq!(
            super::probe_tmp("rp_0a9fbc").as_deref(),
            Some("/srv/restore-probes/rp_0a9fbc/tmp")
        );
        for name in [
            "",
            "rp_",
            "rp_0a9fb",
            "rp_0a9fbc0",
            "rp_0A9FBC",
            "rp_0a9fbg",
            "rs_0a9fbc",
            "rp_../..",
            "rp_0a9f/c",
            "rp_0a9fbc\n",
            " rp_0a9fbc",
        ] {
            assert_eq!(super::probe_tmp(name), None, "{name:?}");
        }
        assert!(!super::PROBE_RESTORE_DIR.contains('/'));
    }

    #[test]
    fn only_a_site_account_names_a_clone_fetch_directory() {
        assert_eq!(
            super::clone_tmp("rs_stage9").as_deref(),
            Some(format!("{}/rs_stage9/tmp", super::SITES_ROOT).as_str())
        );
        for name in [
            "",
            "rs_",
            "stage9",
            "rp_0a9fbc",
            "rs_../x",
            "rs_stage9/tmp",
            "rs_Stage9",
            "rs_stage9\n",
            " rs_stage9",
        ] {
            assert_eq!(super::clone_tmp(name), None, "{name:?}");
        }
        assert!(!super::CLONE_RESTORE_DIR.contains('/'));
        assert_ne!(super::CLONE_RESTORE_DIR, super::PROBE_RESTORE_DIR);
    }

    #[test]
    fn the_capture_dump_is_one_plain_file_name() {
        let names = [
            super::CAPTURE_DUMP_FILE,
            super::APP_SQLITE_BUNDLE_FILE,
            super::APP_PG_DUMP_FILE,
            super::APP_MARIADB_DUMP_FILE,
        ];
        for (i, name) in names.iter().enumerate() {
            assert!(!name.is_empty() && !name.contains('/') && !name.starts_with('.'));
            assert!(
                !names[..i].contains(name),
                "duplicate dump file name: {name}"
            );
        }
    }

    #[test]
    fn every_location_is_a_distinct_normal_absolute_path() {
        for profile in &PROFILES {
            assert_eq!(profile.all.len(), 38);
            for (index, path) in profile.all.iter().chain(&profile.fixture).enumerate() {
                assert!(normal(path), "{path}");
                assert!(
                    !profile.all[..index.min(profile.all.len())].contains(path),
                    "{path} listed twice"
                );
            }
        }
    }

    /// W446: the export worker is a file of the job program folder.
    #[test]
    fn the_migration_worker_is_inside_the_job_folder() {
        for (bin, worker) in [
            (lab::JOB_BIN_DIR, lab::JOB_MIGRATION_INVENTORY),
            (product::JOB_BIN_DIR, product::JOB_MIGRATION_INVENTORY),
        ] {
            assert_eq!(worker, format!("{bin}/migration-inventory"));
        }
    }

    #[test]
    fn derived_locations_stay_inside_their_parents() {
        for (admin, socket, bin, restic, include, line, prefix, unit) in [
            (
                lab::ADMIN_RUNTIME_DIR,
                lab::ADMIN_SOCKET,
                lab::JOB_BIN_DIR,
                lab::JOB_RESTIC,
                lab::OLS_INCLUDE_DIR,
                lab::OLS_INCLUDE_LINE,
                lab::SITE_PHP_UNIT_PREFIX,
                lab::SITE_PHP_UNIT,
            ),
            (
                product::ADMIN_RUNTIME_DIR,
                product::ADMIN_SOCKET,
                product::JOB_BIN_DIR,
                product::JOB_RESTIC,
                product::OLS_INCLUDE_DIR,
                product::OLS_INCLUDE_LINE,
                product::SITE_PHP_UNIT_PREFIX,
                product::SITE_PHP_UNIT,
            ),
        ] {
            assert_eq!(socket, format!("{admin}/helper.sock"));
            assert_eq!(restic, format!("{bin}/restic"));
            assert_eq!(line, format!("include {include}/current/*.conf"));
            assert_eq!(unit, format!("{prefix}.service"));
        }
        assert!(
            PROFILES
                .iter()
                .all(|p| p.include_line.starts_with("include /"))
        );
    }

    #[test]
    fn replay_state_and_its_mark_do_not_share_a_directory() {
        for (journal, mark, include, ejected, sites, probes) in [
            (
                lab::JOURNAL_DIR,
                lab::MARK_DIR,
                lab::OLS_INCLUDE_DIR,
                lab::OLS_EJECTED_DIR,
                lab::SITES_ROOT,
                lab::RESTORE_PROBES_ROOT,
            ),
            (
                product::JOURNAL_DIR,
                product::MARK_DIR,
                product::OLS_INCLUDE_DIR,
                product::OLS_EJECTED_DIR,
                product::SITES_ROOT,
                product::RESTORE_PROBES_ROOT,
            ),
        ] {
            // Restoring the journal directory must not carry the mark with it.
            assert!(!mark.starts_with(journal) && !journal.starts_with(mark));
            // Ejected configuration survives removal of the Rustiron include.
            assert!(!ejected.starts_with(include));
            // A probe sandbox is never inside the served sites.
            assert!(!probes.starts_with(sites));
        }
    }

    #[test]
    fn the_product_profile_names_no_lab_location_and_has_no_fixture() {
        assert_eq!(product::FIXTURE_REGISTRY_DIR, None);
        assert!(lab::FIXTURE_REGISTRY_DIR.is_some());
        for path in product::ALL {
            assert!(
                !path.contains("lab") && !path.contains("/usr/local/"),
                "{path}"
            );
        }
        // D-024 keeps these where every snapshot and proof already has them.
        assert_eq!(product::SITES_ROOT, lab::SITES_ROOT);
        assert_eq!(product::RESTORE_PROBES_ROOT, lab::RESTORE_PROBES_ROOT);
        assert_eq!(product::OLS_INCLUDE_DIR, lab::OLS_INCLUDE_DIR);
        assert_eq!(product::CADDY_CONFIG_DIR, lab::CADDY_CONFIG_DIR);
        assert_eq!(product::OLS_EJECTED_DIR, lab::OLS_EJECTED_DIR);
    }
}
