//! W212b: the PHP-capacity check made by the helper's `ols_preflight` from
//! real files, and the executor's fail-closed reading of the helper reply.
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use rustiron_executor::ExecutorError;
use rustiron_executor::admin_helper::Reply;
use rustiron_executor::ols::{
    ServerChecks, php_capacity_at, php_unit_overridden_in, preflight_report,
};

const UNIT4: &str =
    "[Service]\nUser=%i\nEnvironment=PHP_LSAPI_CHILDREN=4 PHP_LSAPI_MAX_REQUESTS=500\n";
const SITE_LEVEL: &str = "[Service]\nEnvironment=RUSTIRON_SITE_LEVEL=s0:c13\n";

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("w212b-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn tree(name: &str, parent: &str, unit: &str, dropin: Option<&str>) -> PathBuf {
    let dir = scratch(name);
    std::fs::write(dir.join("httpd_config.conf"), parent).unwrap();
    std::fs::write(dir.join("rustiron-site-php@.service"), unit).unwrap();
    if let Some(text) = dropin {
        let d = dir.join("rustiron-site-php@rs_blog13.service.d");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("50-selinux.conf"), text).unwrap();
    }
    dir
}

fn capacity(dir: &Path, cpus: u32) -> bool {
    php_capacity_at(
        &dir.join("httpd_config.conf"),
        &dir.join("rustiron-site-php@.service"),
        &[dir],
        Some(cpus),
    )
}

#[test]
fn the_provision_site_level_dropin_is_not_a_capacity_override() {
    let dir = tree("level", "serverName x\n", UNIT4, Some(SITE_LEVEL));
    assert!(!php_unit_overridden_in(&[&dir]));
    assert!(
        capacity(&dir, 4),
        "4 workers, 4 children, site-level drop-in"
    );
}

#[test]
fn fewer_workers_than_ols_processes_is_refused() {
    let dir = tree("starved", "httpdWorkers 6\n", UNIT4, None);
    assert!(!capacity(&dir, 4));
    let dir = tree("cpus", "serverName x\n", UNIT4, None);
    assert!(!capacity(&dir, 8), "8 CPUs → 8 OLS processes > 4 children");
    assert!(capacity(&dir, 4));
}

#[test]
fn hostile_dropins_missing_or_unreadable_files_are_refused() {
    for text in [
        "[Service]\nEnvironment=PHP_LSAPI_CHILDREN=1\n",
        "[Service]\nEnvironmentFile=/tmp/x\n",
        "[Service]\nExecStart=\nExecStart=/bin/lsphp\n",
        "[Service]\nUnsetEnvironment=PHP_LSAPI_CHILDREN\n",
    ] {
        let dir = tree("hostile", "serverName x\n", UNIT4, Some(text));
        assert!(!capacity(&dir, 4), "accepted {text:?}");
    }
    let dir = tree("nounit", "serverName x\n", UNIT4, None);
    std::fs::remove_file(dir.join("rustiron-site-php@.service")).unwrap();
    assert!(!capacity(&dir, 4));
    let dir = tree("noparent", "serverName x\n", UNIT4, None);
    std::fs::remove_file(dir.join("httpd_config.conf")).unwrap();
    assert!(!capacity(&dir, 4));
    let dir = tree("locked", "serverName x\n", UNIT4, Some(SITE_LEVEL));
    let d = dir.join("rustiron-site-php@rs_blog13.service.d");
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o000)).unwrap();
    let unreadable = std::fs::read_dir(&d).is_err();
    let result = capacity(&dir, 4);
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
    if unreadable {
        assert!(!result, "an unreadable drop-in dir must fail closed");
    }
}

fn checks(php_capacity: bool) -> ServerChecks {
    ServerChecks {
        parent_reviewed: true,
        webadmin_closed: true,
        adopted_vhosts_pinned: true,
        php_capacity,
        page_cache_ols_tested: true,
    }
}

#[test]
fn executor_refuses_a_missing_refused_or_forged_helper_result() {
    let generation = (true, Some(true));
    let clean = |reply| preflight_report(reply, generation).is_some_and(|r| r.clean());
    assert!(clean(Ok(Reply::Done(Some(checks(true).encode())))));
    assert!(
        !clean(Ok(Reply::Done(Some(checks(false).encode())))),
        "false capacity"
    );
    assert!(!clean(Ok(Reply::Done(None))), "no payload");
    assert!(!clean(Err(ExecutorError::Unavailable)), "no helper");
    assert!(
        !clean(Ok(Reply::Refused(ExecutorError::BindingDenied))),
        "refused"
    );
    for forged in [
        r#"{"parent_reviewed":true,"webadmin_closed":true,"adopted_vhosts_pinned":true}"#,
        r#"{"parent_reviewed":true,"webadmin_closed":true,"adopted_vhosts_pinned":true,"php_capacity":"yes"}"#,
        r#"{"parent_reviewed":true,"webadmin_closed":true,"adopted_vhosts_pinned":true,"php_capacity":true,"php_capacity_override":true}"#,
        "true",
        "",
    ] {
        assert!(
            !clean(Ok(Reply::Done(Some(forged.to_owned())))),
            "accepted {forged}"
        );
    }
    assert!(
        !preflight_report(
            Ok(Reply::Done(Some(checks(true).encode()))),
            (false, Some(true))
        )
        .is_some_and(|r| r.clean()),
        "generation checks still apply"
    );
}
