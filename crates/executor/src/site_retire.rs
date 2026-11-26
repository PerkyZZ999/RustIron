//! D-080 (W508): the removal of a quarantined site, run by the admin helper
//! for the journal's open retirement.
//!
//! It undoes only the provision steps that the journal records as `done` or
//! `intent` (an effect may have happened), in reverse order, with fixed
//! commands. Every name is derived from the journaled site ID. A `failed`
//! Account step means the name collided and the account is not ours:
//! nothing is removed. The steps follow the W018 lab script.

use rustiron_journal::{Provision, ProvisionState, ProvisionStep, StepState};

use crate::{ExecutorError, provision};

/// Whether the journal records the step's effect as possible.
fn made(provision: &Provision, step: ProvisionStep) -> bool {
    provision.steps.iter().any(|record| {
        record.step == step && matches!(record.state, StepState::Done | StepState::Intent)
    })
}

/// The fixed commands that undo `provision`'s recorded steps, in order.
pub(crate) fn removal_commands(provision: &Provision) -> Vec<(&'static str, Vec<String>)> {
    let layout = provision::SiteLayout::derive(&provision.intent.site_id);
    let account = layout.account.clone();
    let root = layout.root.to_string_lossy().into_owned();
    let mut commands = Vec::new();
    if provision.state != ProvisionState::Quarantined || !made(provision, ProvisionStep::Account) {
        return commands;
    }
    if made(provision, ProvisionStep::PhpUnits) {
        commands.push((
            "/usr/bin/systemctl",
            vec![
                "disable".to_owned(),
                "--now".to_owned(),
                "--".to_owned(),
                format!("rustiron-site-sandbox-check@{account}.timer"),
                format!("rustiron-site-php@{account}.socket"),
                format!("rustiron-site-php@{account}.service"),
            ],
        ));
        commands.push((
            "/usr/bin/rm",
            vec![
                "-rf".to_owned(),
                "--one-file-system".to_owned(),
                "--".to_owned(),
                format!("{}{account}.service.d", crate::layout::SITE_PHP_UNIT_PREFIX),
            ],
        ));
        commands.push(("/usr/bin/systemctl", vec!["daemon-reload".to_owned()]));
    }
    if made(provision, ProvisionStep::Labels) {
        let mut patterns = vec![format!("{root}/(tmp|logs)(/.*)?"), format!("{root}(/.*)?")];
        if provision.steps.iter().any(|step| {
            step.step == ProvisionStep::Recipe
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
    }
    if made(provision, ProvisionStep::Directories) {
        commands.push((
            "/usr/bin/rm",
            vec![
                "-rf".to_owned(),
                "--one-file-system".to_owned(),
                "--".to_owned(),
                root,
            ],
        ));
    }
    commands.push(("/usr/sbin/userdel", vec!["--".to_owned(), account.clone()]));
    commands
}

/// The SQL that removes the site database and user, when the Database step
/// is recorded.
fn database_sql(provision: &Provision) -> Option<String> {
    let account = provision::SiteLayout::derive(&provision.intent.site_id).account;
    made(provision, ProvisionStep::Database).then(|| {
        format!(
            "DROP DATABASE IF EXISTS `{account}`; DROP USER IF EXISTS '{account}'@'localhost';\n"
        )
    })
}

/// Runs the removal and logs the phase that failed, with no command text.
pub(crate) fn remove(provision: &Provision) -> Result<(), ExecutorError> {
    let account = provision::SiteLayout::derive(&provision.intent.site_id).account;
    remove_phases(provision).map_err(|(phase, error)| {
        eprintln!(
            "{}",
            serde_json::json!({
                "scope": "site_retire",
                "account": account,
                "phase": phase,
                "error": error.code(),
            })
        );
        error
    })
}

/// Runs the removal of a quarantined provision. A missing unit, context, or
/// group is not an error; the account and root must be gone at the end.
fn remove_phases(provision: &Provision) -> Result<(), (&'static str, ExecutorError)> {
    if provision.state != ProvisionState::Quarantined {
        return Err(("state", ExecutorError::BindingDenied));
    }
    if !made(provision, ProvisionStep::Account) {
        return Ok(());
    }
    let layout = provision::SiteLayout::derive(&provision.intent.site_id);
    let account = layout.account.clone();
    let passwd = provision::read_etc("passwd").map_err(|e| ("passwd", e))?;
    let present = provision::account_uid(&passwd, &account).is_some();
    let commands = removal_commands(provision);
    if let Some(sql) = database_sql(provision) {
        provision::mariadb_admin(&sql).map_err(|e| ("database", e))?;
    }
    for (program, args) in &commands {
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
    if provision::account_uid(&passwd, &account).is_some()
        || std::fs::symlink_metadata(&layout.root).is_ok()
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
        _ => "units",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustiron_journal::{ProvisionIntent, StepRecord};

    fn provision(steps: &[(ProvisionStep, StepState)], state: ProvisionState) -> Provision {
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
            steps: steps
                .iter()
                .map(|(step, state)| StepRecord {
                    step: *step,
                    state: *state,
                    resource: "r".to_owned(),
                })
                .collect(),
        }
    }

    fn programs(provision: &Provision) -> Vec<String> {
        removal_commands(provision)
            .into_iter()
            .map(|(program, args)| format!("{program} {}", args.join(" ")))
            .collect()
    }

    #[test]
    fn only_recorded_steps_of_a_quarantined_provision_are_undone() {
        use ProvisionStep as S;
        use StepState::{Done, Failed, Intent};
        let root = format!("{}/rs_blog1", crate::layout::SITES_ROOT);
        // Account done, Directories open: the root and the account go; no
        // units, contexts or database.
        let early = provision(
            &[(S::Account, Done), (S::Directories, Intent)],
            ProvisionState::Quarantined,
        );
        assert_eq!(
            programs(&early),
            [
                format!("/usr/bin/rm -rf --one-file-system -- {root}"),
                "/usr/sbin/userdel -- rs_blog1".to_owned(),
            ]
        );
        assert_eq!(database_sql(&early), None);
        let full = provision(
            &[
                (S::Account, Done),
                (S::Directories, Done),
                (S::Labels, Done),
                (S::Database, Done),
                (S::Credentials, Done),
                (S::Recipe, Done),
                (S::PhpUnits, Failed),
            ],
            ProvisionState::Quarantined,
        );
        let listed = programs(&full);
        assert!(
            !listed
                .iter()
                .any(|line| line.contains("rustiron-site-php@"))
        );
        assert!(
            listed.iter().any(
                |line| line == &format!("/usr/sbin/semanage fcontext --delete -- {root}(/.*)?")
            )
        );
        assert!(
            database_sql(&full)
                .unwrap()
                .contains("DROP DATABASE IF EXISTS `rs_blog1`")
        );
        // A collided Account step, or a provision that is not quarantined,
        // removes nothing.
        for refused in [
            provision(&[(S::Account, Failed)], ProvisionState::Quarantined),
            provision(&[(S::Account, Done)], ProvisionState::Succeeded),
        ] {
            assert!(programs(&refused).is_empty());
        }
        assert_eq!(
            remove(&provision(&[(S::Account, Done)], ProvisionState::Succeeded)),
            Err(ExecutorError::BindingDenied)
        );
    }
}
