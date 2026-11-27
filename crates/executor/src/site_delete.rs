//! D-085 (W522): the removal of a deleted live site, run by the admin helper
//! for the journal's open deletion.
//!
//! The provision succeeded, so every step made its resource. The removal
//! runs fixed commands with every name derived from the journaled site ID
//! and hostname: the PHP units and drop-in, the database and user, the file
//! contexts, the site root, the TLS folder, the certbot lineage, the update
//! intake, the account and group, and the quota. A part that is already
//! gone is not an error, so the removal can run again. The site's store
//! credentials and backups stay (D-085 "What stays").
//!
//! W523-F1: the helper only reads certbot's state (D-059), so certbot itself
//! deletes the lineage, as `rustiron-acme` in a confined transient unit with
//! no network, like an issuance. W523-F2: the helper only reads the
//! executor's state, so the executor removes the site's update intake
//! ([`remove_update_intake`]) after the helper's removal.

use rustiron_contracts::approval::AppDatabase;
use rustiron_journal::{Provision, ProvisionState};

use crate::{ExecutorError, provision};

/// The `live` folder of the site's certbot lineage (its certificate name is
/// its hostname); present only when the site was issued a certificate.
fn lineage_live(hostname: &str) -> String {
    format!("{}/config/live/{hostname}", crate::layout::ACME_STATE_DIR)
}

/// W523-F1: `certbot delete` of the site's lineage, as `rustiron-acme` in a
/// confined transient unit with no network; certbot removes `live`,
/// `archive`, and the renewal file itself.
fn certbot_delete(hostname: &str) -> (&'static str, Vec<String>) {
    let state = crate::layout::ACME_STATE_DIR;
    let mut args: Vec<String> = [
        "--wait",
        "--quiet",
        "--collect",
        "--property=User=rustiron-acme",
        "--property=Group=rustiron-acme",
        "--property=NoNewPrivileges=yes",
        "--property=ProtectSystem=strict",
        "--property=ProtectHome=yes",
        "--property=PrivateTmp=yes",
        "--property=PrivateDevices=yes",
        "--property=CapabilityBoundingSet=",
        "--property=RestrictAddressFamilies=AF_UNIX",
        "--property=IPAddressDeny=any",
        "--property=RuntimeMaxSec=120",
        "--property=StandardOutput=null",
    ]
    .map(String::from)
    .to_vec();
    args.push(format!("--property=ReadWritePaths={state}"));
    args.extend(["--", "/usr/bin/certbot", "delete", "--non-interactive"].map(String::from));
    for (flag, value) in [
        ("--config-dir", format!("{state}/config")),
        ("--work-dir", format!("{state}/work")),
        ("--logs-dir", format!("{state}/logs")),
        ("--cert-name", hostname.to_owned()),
    ] {
        args.push(flag.to_owned());
        args.push(value);
    }
    ("/usr/bin/systemd-run", args)
}

fn rm(path: String) -> (&'static str, Vec<String>) {
    (
        "/usr/bin/rm",
        vec![
            "-rf".to_owned(),
            "--one-file-system".to_owned(),
            "--".to_owned(),
            path,
        ],
    )
}

/// The fixed commands that remove a deleted site, in order; `certbot
/// delete` only when the site has a lineage. Nothing for a provision that
/// is not `deleted`.
pub(crate) fn removal_commands(
    provision: &Provision,
    lineage: bool,
) -> Vec<(&'static str, Vec<String>)> {
    if provision.state != ProvisionState::Deleted {
        return Vec::new();
    }
    let site = &provision.intent.site_id;
    let layout = provision::SiteLayout::derive(site);
    let account = layout.account.clone();
    let root = layout.root.to_string_lossy().into_owned();
    let mut commands = vec![
        (
            "/usr/bin/systemctl",
            vec![
                "disable".to_owned(),
                "--now".to_owned(),
                "--".to_owned(),
                format!("rustiron-site-sandbox-check@{account}.timer"),
                format!("rustiron-site-php@{account}.socket"),
                format!("rustiron-site-php@{account}.service"),
                format!("rustiron-app@{account}.service"),
                format!("rustiron-app-b@{account}.service"),
                format!("rustiron-app-web@{account}.service"),
                format!("rustiron-app-web-b@{account}.service"),
                format!("rustiron-app-worker@{account}.service"),
            ],
        ),
        rm(format!(
            "{}{account}.service.d",
            crate::layout::SITE_PHP_UNIT_PREFIX
        )),
        rm(format!(
            "{}{account}.service.d",
            crate::layout::SITE_APP_UNIT_PREFIX
        )),
        rm(format!(
            "{}{account}.service.d",
            crate::layout::SITE_APP_B_UNIT_PREFIX
        )),
        rm(format!(
            "{}{account}.service.d",
            crate::layout::SITE_APP_WEB_UNIT_PREFIX
        )),
        rm(format!(
            "{}{account}.service.d",
            crate::layout::SITE_APP_WEB_B_UNIT_PREFIX
        )),
        rm(format!(
            "{}{account}.service.d",
            crate::layout::SITE_APP_WORKER_UNIT_PREFIX
        )),
        ("/usr/bin/systemctl", vec!["daemon-reload".to_owned()]),
    ];
    let mut patterns = vec![format!("{root}/(tmp|logs)(/.*)?"), format!("{root}(/.*)?")];
    if provision.steps.iter().any(|step| {
        step.step == rustiron_journal::ProvisionStep::Recipe
            && step.resource.contains(crate::app_site::APP_RECIPE)
    }) {
        patterns.insert(0, format!("{root}/data(/.*)?"));
    }
    for pattern in patterns {
        commands.push((
            "/usr/sbin/semanage",
            vec![
                "fcontext".to_owned(),
                "--delete".to_owned(),
                "--".to_owned(),
                pattern,
            ],
        ));
    }
    commands.push(rm(root));
    commands.push(rm(format!("{}/{account}", crate::layout::OLS_TLS_DIR)));
    if lineage {
        commands.push(certbot_delete(provision.intent.hostname.as_str()));
    }
    commands.push(("/usr/sbin/userdel", vec!["--".to_owned(), account]));
    commands
}

/// W523-F2: the executor removes the site's update intake under `base`
/// without following a link; an absent intake is not an error.
pub(crate) fn remove_update_intake(
    base: &std::path::Path,
    site: &rustiron_contracts::approval::SiteId,
) -> Result<(), ExecutorError> {
    let intake = base.join(site.as_str());
    match std::fs::symlink_metadata(&intake) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(ExecutorError::StepFailed),
        Ok(meta) if meta.is_dir() => {
            std::fs::remove_dir_all(&intake).map_err(|_| ExecutorError::StepFailed)
        }
        Ok(_) => std::fs::remove_file(&intake).map_err(|_| ExecutorError::StepFailed),
    }
}

/// The SQL that removes the site database and user.
fn database_sql(provision: &Provision) -> String {
    let account = provision::SiteLayout::derive(&provision.intent.site_id).account;
    format!("DROP DATABASE IF EXISTS `{account}`; DROP USER IF EXISTS '{account}'@'localhost';\n")
}

/// Runs the removal and logs the phase that failed, with no command text.
pub(crate) fn remove(provision: &Provision) -> Result<(), ExecutorError> {
    remove_with_app_db(provision, None)
}

/// W658 (D-102 C2): runs site removal including PostgreSQL 18 role/database
/// cleanup when the site was provisioned with `AppDatabase::Postgresql18`.
pub(crate) fn remove_with_app_db(
    provision: &Provision,
    app_db: Option<AppDatabase>,
) -> Result<(), ExecutorError> {
    let account = provision::SiteLayout::derive(&provision.intent.site_id).account;
    remove_phases(provision, app_db).map_err(|(phase, error)| {
        eprintln!(
            "{}",
            serde_json::json!({
                "scope": "site_delete",
                "account": account,
                "phase": phase,
                "error": error.code(),
            })
        );
        error
    })
}

/// A missing unit, context, path, or group is not an error; the account,
/// the root, and the TLS folder must be gone at the end.
fn remove_phases(
    provision: &Provision,
    app_db: Option<AppDatabase>,
) -> Result<(), (&'static str, ExecutorError)> {
    if provision.state != ProvisionState::Deleted {
        return Err(("state", ExecutorError::BindingDenied));
    }
    let layout = provision::SiteLayout::derive(&provision.intent.site_id);
    let account = layout.account.clone();
    let passwd = provision::read_etc("passwd").map_err(|e| ("passwd", e))?;
    let present = provision::account_uid(&passwd, &account).is_some();
    provision::mariadb_admin(&database_sql(provision)).map_err(|e| ("database", e))?;
    if app_db == Some(AppDatabase::Postgresql18) {
        crate::postgres::drop_database_and_role(&account).map_err(|e| ("postgres", e))?;
    }
    let live = lineage_live(provision.intent.hostname.as_str());
    let lineage = std::fs::symlink_metadata(&live).is_ok();
    for (program, args) in &removal_commands(provision, lineage) {
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        let result = provision::run(program, &borrowed);
        // An absent unit or context, or an account already gone, is no error.
        let tolerated = matches!(*program, "/usr/bin/systemctl" | "/usr/sbin/semanage")
            || (*program == "/usr/sbin/userdel" && !present);
        if let Err(error) = result
            && !tolerated
        {
            return Err((program_phase(program), error));
        }
    }
    let group = provision::read_etc("group").map_err(|e| ("group", e))?;
    if group
        .lines()
        .any(|line| line.split(':').next() == Some(account.as_str()))
    {
        provision::run("/usr/sbin/groupdel", &["--", &account]).map_err(|e| ("groupdel", e))?;
    }
    crate::quota::retire(&mut crate::quota::SystemQuota, provision).map_err(|e| ("quota", e))?;
    let passwd = provision::read_etc("passwd").map_err(|e| ("passwd", e))?;
    let tls = std::path::Path::new(crate::layout::OLS_TLS_DIR).join(&account);
    if provision::account_uid(&passwd, &account).is_some()
        || std::fs::symlink_metadata(&layout.root).is_ok()
        || std::fs::symlink_metadata(&tls).is_ok()
        || std::fs::symlink_metadata(&live).is_ok()
    {
        return Err(("check", ExecutorError::StepFailed));
    }
    Ok(())
}

fn program_phase(program: &str) -> &'static str {
    match program {
        "/usr/bin/rm" => "remove",
        "/usr/sbin/userdel" => "userdel",
        "/usr/sbin/semanage" => "contexts",
        "/usr/bin/systemd-run" => "certbot",
        _ => "units",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustiron_journal::{ProvisionIntent, ProvisionStep, StepRecord, StepState};

    fn provision(state: ProvisionState) -> Provision {
        let id = |text: &str| rustiron_contracts::Id::try_from(text.to_owned()).unwrap();
        let digest = rustiron_contracts::approval::Sha256Digest::from_bytes([1; 32]);
        Provision {
            intent: ProvisionIntent {
                operation_id: id("op"),
                idempotency_key: id("key"),
                grant_id: id("grant"),
                nonce: id("nonce"),
                plan_digest: digest.clone(),
                grant_digest: digest,
                host_id: id("host"),
                host_epoch: id("epoch"),
                site_id: "blog1".to_owned().try_into().unwrap(),
                hostname: "blog1.example.test".to_owned().try_into().unwrap(),
                expires_at: rustiron_contracts::Timestamp::try_from(10).unwrap(),
            },
            state,
            steps: ProvisionStep::ALL
                .iter()
                .map(|step| StepRecord {
                    step: *step,
                    state: StepState::Done,
                    resource: "r".to_owned(),
                })
                .collect(),
        }
    }

    fn programs(provision: &Provision) -> Vec<String> {
        removal_commands(provision, true)
            .into_iter()
            .map(|(program, args)| format!("{program} {}", args.join(" ")))
            .collect()
    }

    #[test]
    fn a_deleted_site_loses_everything_it_owns_on_the_host_but_its_store_credentials() {
        let root = format!("{}/rs_blog1", crate::layout::SITES_ROOT);
        let acme = crate::layout::ACME_STATE_DIR;
        let listed = programs(&provision(ProvisionState::Deleted));
        let rm = |path: &str| format!("/usr/bin/rm -rf --one-file-system -- {path}");
        for expected in [
            "/usr/bin/systemctl disable --now -- rustiron-site-sandbox-check@rs_blog1.timer rustiron-site-php@rs_blog1.socket rustiron-site-php@rs_blog1.service rustiron-app@rs_blog1.service rustiron-app-b@rs_blog1.service rustiron-app-web@rs_blog1.service rustiron-app-web-b@rs_blog1.service rustiron-app-worker@rs_blog1.service".to_owned(),
            rm(&format!("{}rs_blog1.service.d", crate::layout::SITE_PHP_UNIT_PREFIX)),
            rm(&format!("{}rs_blog1.service.d", crate::layout::SITE_APP_UNIT_PREFIX)),
            rm(&format!("{}rs_blog1.service.d", crate::layout::SITE_APP_B_UNIT_PREFIX)),
            rm(&format!("{}rs_blog1.service.d", crate::layout::SITE_APP_WEB_UNIT_PREFIX)),
            rm(&format!("{}rs_blog1.service.d", crate::layout::SITE_APP_WEB_B_UNIT_PREFIX)),
            rm(&format!("{}rs_blog1.service.d", crate::layout::SITE_APP_WORKER_UNIT_PREFIX)),
            format!("/usr/sbin/semanage fcontext --delete -- {root}(/.*)?"),
            rm(&root),
            rm(&format!("{}/rs_blog1", crate::layout::OLS_TLS_DIR)),
            "/usr/sbin/userdel -- rs_blog1".to_owned(),
        ] {
            assert!(listed.contains(&expected), "{expected}");
        }
        assert_eq!(listed.last().unwrap(), "/usr/sbin/userdel -- rs_blog1");
        // W523-F1: certbot deletes its own lineage, confined, with no
        // network; the helper never writes certbot's state.
        let certbot = listed
            .iter()
            .find(|line| line.starts_with("/usr/bin/systemd-run "))
            .unwrap();
        for part in [
            "--property=User=rustiron-acme",
            "--property=IPAddressDeny=any",
            &format!("--property=ReadWritePaths={acme}"),
            "-- /usr/bin/certbot delete --non-interactive",
            &format!("--config-dir {acme}/config"),
            "--cert-name blog1.example.test",
        ] {
            assert!(certbot.contains(part), "{part}");
        }
        assert!(
            !listed
                .iter()
                .any(|line| line.contains(&format!("rm -rf --one-file-system -- {acme}")))
        );
        // W523-F2: the helper never writes the executor's update intake.
        assert!(
            !listed
                .iter()
                .any(|line| line.contains(crate::layout::UPDATE_INTAKE_DIR))
        );
        // Without a lineage there is nothing for certbot to delete.
        assert!(
            !removal_commands(&provision(ProvisionState::Deleted), false)
                .iter()
                .any(|(program, _)| *program == "/usr/bin/systemd-run")
        );
        // The store credentials stay, so the backups stay readable.
        assert!(
            !listed
                .iter()
                .any(|line| line.contains(crate::layout::JOB_CREDENTIALS_DIR))
        );
        assert!(
            database_sql(&provision(ProvisionState::Deleted))
                .contains("DROP DATABASE IF EXISTS `rs_blog1`")
        );
    }

    #[test]
    fn the_executor_removes_the_update_intake_without_following_a_link() {
        let base = std::env::temp_dir().join(format!("ri-intake-{}", std::process::id()));
        let site: rustiron_contracts::approval::SiteId = "blog1".to_owned().try_into().unwrap();
        let outside = base.join("outside");
        std::fs::create_dir_all(base.join("blog1")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(base.join("blog1/recipe.tar"), b"r").unwrap();
        std::fs::write(outside.join("keep"), b"k").unwrap();
        remove_update_intake(&base, &site).unwrap();
        assert!(!base.join("blog1").exists());
        // Absent is not an error; a link is removed, not followed.
        remove_update_intake(&base, &site).unwrap();
        std::os::unix::fs::symlink(&outside, base.join("blog1")).unwrap();
        remove_update_intake(&base, &site).unwrap();
        assert!(outside.join("keep").exists());
        assert!(std::fs::symlink_metadata(base.join("blog1")).is_err());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn only_a_deleted_provision_is_removed() {
        for state in [
            ProvisionState::Succeeded,
            ProvisionState::Adopted,
            ProvisionState::Quarantined,
            ProvisionState::Running,
        ] {
            assert!(programs(&provision(state)).is_empty(), "{state:?}");
            assert_eq!(
                remove(&provision(state)),
                Err(ExecutorError::BindingDenied),
                "{state:?}"
            );
        }
    }
}
