//! W572 (D-095): the provision steps of a proxy site.
//!
//! A proxy site is a provision: Account, Directories and Labels are the
//! shared steps. Database, Credentials and PhpUnits have no effect and are
//! journaled done as not used. Its Recipe step writes only the identity
//! file and prepares the ACME webroot; its Verify step checks that file.
//! Nothing here reads or contacts a port behind the site: the routes are
//! the OLS render's (`docs/technical/PROXY-SITE.md`).

use std::io::Read;

use rustiron_journal::ProvisionStep;
use rustix::fs::{Mode, OFlags};

use crate::{
    ExecutorError, files,
    provision::{self, SiteLayout},
};

/// The Recipe step's recorded name of a proxy site.
pub(crate) const PROXY_RECIPE: &str = "proxy_v1";

/// The identity file, the only file a proxy site's `html` holds.
const IDENTITY: &str = "rustiron-site.txt";

/// The SELinux type of every site file.
const CONTENT_TYPE: &str = "system_u:object_r:httpd_sys_content_t:";

/// Whether a proxy site journals `step` done without an effect.
pub(crate) fn skips(step: ProvisionStep) -> bool {
    matches!(
        step,
        ProvisionStep::Database | ProvisionStep::Credentials | ProvisionStep::PhpUnits
    )
}

/// The Recipe or Verify step of a proxy site; any other step is not its own.
pub(crate) fn run_step(step: ProvisionStep, layout: &SiteLayout) -> Result<(), ExecutorError> {
    match step {
        ProvisionStep::Recipe => provision::write_site_marker(layout)
            .and_then(|_| crate::certificate::prepare_webroot(&layout.account)),
        ProvisionStep::Verify => verify(layout).map(drop),
        _ => Err(ExecutorError::BindingDenied),
    }
}

/// Whether no route names a port that the host serves or reserves: the
/// enrolled OLS listener, TLS listener and WebAdmin ports, and the enrolled
/// SSH port.
pub(crate) fn ports_free(reserved: &[u16], ports: &[u16]) -> bool {
    ports.iter().all(|port| !reserved.contains(port))
}

/// Whether the identity file names exactly `account`.
pub(crate) fn identity_matches(text: &[u8], account: &str) -> bool {
    text == format!("{account}\n").as_bytes()
}

/// Whether `html` holds only the identity file.
pub(crate) fn only_identity(names: &[String]) -> bool {
    names == [IDENTITY]
}

/// Whether the identity file has the site's own level, as the site root.
pub(crate) fn same_level(root: &str, marker: &str) -> bool {
    root.trim()
        .strip_prefix(CONTENT_TYPE)
        .is_some_and(|level| level.starts_with("s0:c") && marker.trim() == root.trim())
}

/// Verify: OLS starts at boot, `html` holds only the identity file, which
/// names the account, is the site's own, and has the site's level.
fn verify(layout: &SiteLayout) -> Result<String, ExecutorError> {
    let failed = |_| ExecutorError::StepFailed;
    let state = provision::output(
        "/usr/bin/systemctl",
        &["is-enabled", "--", "lshttpd.service"],
    )?;
    if state.trim() != "enabled" {
        return Err(ExecutorError::StepFailed);
    }
    let passwd = provision::read_etc("passwd")?;
    let uid = provision::account_uid(&passwd, &layout.account).ok_or(ExecutorError::StepFailed)?;
    let html = layout.root.join("html");
    let directory = files::open_traversable_directory(&html, uid)?;
    let mut names = Vec::new();
    for entry in std::fs::read_dir(&html).map_err(|_| ExecutorError::StepFailed)? {
        let entry = entry.map_err(|_| ExecutorError::StepFailed)?;
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    if !only_identity(&names) {
        return Err(ExecutorError::StepFailed);
    }
    let fd = rustix::fs::openat(
        &directory,
        IDENTITY,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(failed)?;
    let stat = rustix::fs::fstat(&fd).map_err(failed)?;
    let mut text = Vec::new();
    std::fs::File::from(fd)
        .take(256)
        .read_to_end(&mut text)
        .map_err(|_| ExecutorError::StepFailed)?;
    if stat.st_uid != uid || !identity_matches(&text, &layout.account) {
        return Err(ExecutorError::StepFailed);
    }
    let root = provision::path_str(&layout.root)?;
    let marker = html.join(IDENTITY);
    let context = |path: &str| provision::output("/usr/bin/stat", &["-c", "%C", "--", path]);
    if !same_level(&context(root)?, &context(provision::path_str(&marker)?)?) {
        return Err(ExecutorError::StepFailed);
    }
    Ok(format!("verified proxy site {}", layout.account))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_three_unused_steps_are_skipped() {
        let skipped: Vec<_> = ProvisionStep::ALL
            .into_iter()
            .filter(|step| skips(*step))
            .collect();
        assert_eq!(
            skipped,
            [
                ProvisionStep::Database,
                ProvisionStep::Credentials,
                ProvisionStep::PhpUnits
            ]
        );
        let layout = SiteLayout::derive(&"ytproxy".to_owned().try_into().unwrap());
        for step in [
            ProvisionStep::Account,
            ProvisionStep::Directories,
            ProvisionStep::Labels,
            ProvisionStep::Database,
            ProvisionStep::Credentials,
            ProvisionStep::PhpUnits,
        ] {
            assert_eq!(
                run_step(step, &layout),
                Err(ExecutorError::BindingDenied),
                "{step:?}"
            );
        }
    }

    #[test]
    fn enrolled_ports_are_refused() {
        let reserved = [8088, 7080, 8443, 2222];
        assert!(ports_free(&reserved, &[3000, 3100, 43187]));
        for port in reserved {
            assert!(!ports_free(&reserved, &[3100, port]), "{port}");
        }
    }

    #[test]
    fn the_identity_checks_are_exact() {
        assert!(identity_matches(b"rs_ytproxy\n", "rs_ytproxy"));
        for text in [&b"rs_ytproxy"[..], b"rs_other\n", b"rs_ytproxy\n\n", b""] {
            assert!(!identity_matches(text, "rs_ytproxy"));
        }
        assert!(only_identity(&["rustiron-site.txt".to_owned()]));
        assert!(!only_identity(&[]));
        assert!(!only_identity(&[
            "rustiron-site.txt".to_owned(),
            "index.php".to_owned()
        ]));
        let level = "system_u:object_r:httpd_sys_content_t:s0:c201\n";
        assert!(same_level(level, level));
        assert!(!same_level(
            level,
            "system_u:object_r:httpd_sys_content_t:s0:c202"
        ));
        assert!(!same_level(
            "system_u:object_r:httpd_sys_content_t:s0",
            "system_u:object_r:httpd_sys_content_t:s0"
        ));
        assert!(!same_level(
            "system_u:object_r:user_home_t:s0:c201",
            "system_u:object_r:user_home_t:s0:c201"
        ));
    }
}
