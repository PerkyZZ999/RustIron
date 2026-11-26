//! W387 (D-037): the unit steps of `site_eject`.
//!
//! After the switch to the generation that serves the site from its
//! standalone vhost ([`crate::ols::ejected_vhost`]), OpenLiteSpeed starts
//! the site's PHP itself. The ejected site then needs no Rustiron unit:
//! [`stop_site_php`] stops and disables the site's PHP socket, service, and
//! sandbox timer, and proves that PHP still answers through the listener.
//! The one compensation and the reconcile of an attempted ejection run
//! [`restore_site_php`] on the restored predecessor.
//!
//! Every unit name comes from the account, which comes from the journaled
//! site ID. Nothing comes from a request.

use std::time::Duration;

use rustiron_contracts::approval::Hostname;

use crate::{ExecutorError, provision};

const SYSTEMCTL: &str = "/usr/bin/systemctl";
/// How often and how far apart the PHP answer is tried after the stop.
const PHP_ATTEMPTS: u32 = 20;
const PHP_PAUSE: Duration = Duration::from_millis(500);
/// The page every provisioned WordPress site serves through its PHP.
pub const PHP_PROBE_PATH: &str = "/wp-login.php";

/// The Rustiron PHP units of one site: the socket, the service, and the
/// sandbox timer of the provision's PhpUnits step.
pub fn php_units(account: &str) -> [String; 3] {
    [
        format!("rustiron-site-php@{account}.socket"),
        format!("rustiron-site-php@{account}.service"),
        format!("rustiron-site-sandbox-check@{account}.timer"),
    ]
}

/// The `systemctl` argument lists of [`stop_site_php`], in order: disable
/// and stop the socket and the timer, then stop the service that the socket
/// may have started.
pub fn stop_commands(account: &str) -> Vec<Vec<String>> {
    let [socket, service, timer] = php_units(account);
    vec![
        vec![
            "disable".to_owned(),
            "--now".to_owned(),
            "--".to_owned(),
            socket,
            timer,
        ],
        vec!["stop".to_owned(), "--".to_owned(), service],
    ]
}

/// The `systemctl` argument list of [`restore_site_php`]: the provision's
/// own enable and start of the socket and the timer.
pub fn restore_command(account: &str) -> Vec<String> {
    let [socket, _, timer] = php_units(account);
    vec![
        "enable".to_owned(),
        "--now".to_owned(),
        "--".to_owned(),
        socket,
        timer,
    ]
}

/// Whether a GET of [`PHP_PROBE_PATH`] shows a working PHP: the WordPress
/// login form (status 200), or the WordPress redirect of a site that is not
/// installed yet (status 302 with `X-Redirect-By: WordPress`). Both need the
/// site's PHP and its database connection. The PHP source is never one.
pub fn php_answered(status: u16, headers: &str, body: &str) -> bool {
    let wordpress_redirect = headers
        .lines()
        .any(|line| line.trim().eq_ignore_ascii_case("x-redirect-by: WordPress"));
    !body.contains("<?php")
        && match status {
            200 => body.contains("loginform"),
            302 => wordpress_redirect,
            _ => false,
        }
}

/// Whether `systemctl is-active` and `is-enabled` outputs show a unit that
/// neither runs nor starts at boot.
pub fn unit_released(active: &str, enabled: &str) -> bool {
    !matches!(active.trim(), "active" | "activating" | "reloading")
        && !matches!(enabled.trim(), "enabled" | "enabled-runtime" | "static")
}

fn systemctl(arguments: &[String]) -> Result<(), ExecutorError> {
    let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
    provision::run(SYSTEMCTL, &arguments)
}

/// `systemctl is-active` and `is-enabled` of one unit; both exit non-zero
/// for a unit that is not active or not enabled.
fn unit_state(unit: &str) -> Result<(String, String), ExecutorError> {
    let active = provision::output_allowing(SYSTEMCTL, &["is-active", "--", unit], &[0, 3, 4])?;
    let enabled = provision::output_allowing(SYSTEMCTL, &["is-enabled", "--", unit], &[0, 1, 4])?;
    Ok((active, enabled))
}

/// One probe answer for the log: the status code and whether it showed
/// PHP, or the error code. Never the body.
fn answer_note(answer: &Result<(u16, String, String), ExecutorError>) -> String {
    match answer {
        Ok((status, headers, body)) => {
            format!("{status} php={}", php_answered(*status, headers, body))
        }
        Err(error) => error.code().to_owned(),
    }
}

/// W511-F1 (P08): the WordPress login answers through the HTTP listener,
/// or, for a site that sends HTTP to HTTPS, through the TLS listener. Only
/// the site's own vhost is mapped for its name on either listener. Returns
/// the result and a note of the answers for the failure log.
pub(crate) fn wordpress_answers(
    address: &str,
    tls_address: Option<&str>,
    hostname: &Hostname,
) -> (bool, String) {
    let answered = |answer: &Result<(u16, String, String), ExecutorError>| {
        answer
            .as_ref()
            .is_ok_and(|(status, headers, body)| php_answered(*status, headers, body))
    };
    let http = crate::ols::get_response(address, hostname.as_str(), PHP_PROBE_PATH);
    if answered(&http) {
        return (true, String::new());
    }
    let mut note = format!("http {}", answer_note(&http));
    if let Some(tls) = tls_address {
        let https = crate::ols::get_response_tls(tls, hostname.as_str(), PHP_PROBE_PATH);
        if answered(&https) {
            return (true, String::new());
        }
        note.push_str(&format!(", https {}", answer_note(&https)));
    }
    (false, note)
}

/// What [`stop_site_php`] probes after stopping and disabling the managed PHP
/// units for an ejected site.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EjectProbe<'a> {
    /// D-037: standalone OLS-started PHP answers `/wp-login.php`.
    WordPress,
    /// D-077: standalone static alias pair answers `/rustiron-site.txt` on HTTP
    /// for both names.
    StaticAlias(&'a Hostname),
    /// D-097: standalone single-name static site answers `/rustiron-site.txt`
    /// on HTTP (or via exact HTTPS redirect when `tls` is true) and, when
    /// `tls` is true, on HTTPS directly.
    StaticSingle {
        /// Whether the site is served over HTTPS as well as HTTP.
        tls: bool,
    },
}

/// Stops and disables the site's Rustiron PHP units, then requires that
/// each one neither runs nor starts at boot. Check the WordPress login or,
/// for a static handover, the site's identity marker on its served listeners.
pub fn stop_site_php(
    account: &str,
    address: &str,
    tls_address: Option<&str>,
    hostname: &Hostname,
    probe: EjectProbe<'_>,
) -> Result<(), ExecutorError> {
    for command in stop_commands(account) {
        systemctl(&command)?;
    }
    let [socket, service, timer] = php_units(account);
    for unit in [socket, timer] {
        let (active, enabled) = unit_state(&unit)?;
        if !unit_released(&active, &enabled) {
            return Err(ExecutorError::StepFailed);
        }
    }
    // The service has no install section: the socket starts it, so it is
    // only required to have stopped.
    let (active, _) = unit_state(&service)?;
    if !unit_released(&active, "") {
        return Err(ExecutorError::StepFailed);
    }
    let mut note = String::new();
    for _ in 0..PHP_ATTEMPTS {
        let serving = match probe {
            EjectProbe::StaticAlias(alias) => [hostname, alias]
                .into_iter()
                .all(|name| crate::ols::probe_identity(address, account, name).is_ok()),
            EjectProbe::StaticSingle { tls: false } => {
                let http = crate::ols::probe_identity(address, account, hostname);
                if http.is_ok() {
                    true
                } else {
                    note = format!(
                        "static-http {}",
                        http.err().map_or("ok", ExecutorError::code)
                    );
                    false
                }
            }
            EjectProbe::StaticSingle { tls: true } => {
                let http =
                    crate::ols::probe_identity_or_https(address, tls_address, account, hostname);
                let https = tls_address
                    .ok_or(ExecutorError::Unavailable)
                    .and_then(|tls| crate::ols::probe_identity_tls(tls, account, hostname));
                if http.is_ok() && https.is_ok() {
                    true
                } else {
                    note = format!(
                        "static-tls http={} https={}",
                        http.err().map_or("ok", ExecutorError::code),
                        https.err().map_or("ok", ExecutorError::code)
                    );
                    false
                }
            }
            EjectProbe::WordPress => {
                let (serving, last) = wordpress_answers(address, tls_address, hostname);
                note = last;
                serving
            }
        };
        if serving {
            return Ok(());
        }
        std::thread::sleep(PHP_PAUSE);
    }
    // W511: the last answers, without a body, for the operator.
    eprintln!(
        "{}",
        serde_json::json!({"scope": "eject_php_probe", "account": account, "last": note})
    );
    Err(ExecutorError::ProbeFailed)
}

/// Enables and starts the site's Rustiron PHP socket and sandbox timer
/// again and requires the socket active. Safe to repeat.
pub fn restore_site_php(account: &str) -> Result<(), ExecutorError> {
    systemctl(&restore_command(account))?;
    let [socket, _, _] = php_units(account);
    let (active, _) = unit_state(&socket)?;
    if active.trim() == "active" {
        Ok(())
    } else {
        Err(ExecutorError::StepFailed)
    }
}

/// Starts the managed PHP socket and timer for this boot. Journal recovery
/// can enable them persistently once OLS can verify the restored site.
pub(crate) fn start_recovery_php(account: &str) -> Result<(), ExecutorError> {
    let [socket, _, timer] = php_units(account);
    provision::run(SYSTEMCTL, &["start", "--", &socket, &timer])?;
    provision::run(SYSTEMCTL, &["is-active", "--", &socket])?;
    provision::run(SYSTEMCTL, &["is-active", "--", &timer])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_units_and_commands_derive_from_the_account_only() {
        assert_eq!(
            php_units("rs_blog9"),
            [
                "rustiron-site-php@rs_blog9.socket",
                "rustiron-site-php@rs_blog9.service",
                "rustiron-site-sandbox-check@rs_blog9.timer",
            ]
        );
        assert_eq!(
            stop_commands("rs_blog9"),
            [
                vec![
                    "disable",
                    "--now",
                    "--",
                    "rustiron-site-php@rs_blog9.socket",
                    "rustiron-site-sandbox-check@rs_blog9.timer",
                ],
                vec!["stop", "--", "rustiron-site-php@rs_blog9.service"],
            ]
        );
        assert_eq!(
            restore_command("rs_blog9"),
            [
                "enable",
                "--now",
                "--",
                "rustiron-site-php@rs_blog9.socket",
                "rustiron-site-sandbox-check@rs_blog9.timer",
            ]
        );
    }

    /// W387 run 2: a provisioned site that is not installed yet answers
    /// the login page with the WordPress redirect to its installer. That
    /// answer also needs the PHP and the database connection.
    #[test]
    fn only_wordpress_php_output_is_a_php_answer() {
        let form = "<form name=\"loginform\" id=\"loginform\" action=\"/wp-login.php\">";
        let plain = "HTTP/1.1 200 OK\r\nserver: LiteSpeed";
        let redirect = "HTTP/1.1 302 Found\r\nx-powered-by: PHP/8.4.27\r\nx-redirect-by: WordPress\r\nlocation: http://blog9.example.test/wp-admin/install.php";
        assert!(php_answered(200, plain, form));
        assert!(php_answered(302, redirect, ""));
        assert!(
            !php_answered(503, plain, form),
            "OLS could not start the PHP"
        );
        assert!(
            !php_answered(302, plain, ""),
            "a redirect that no WordPress code made"
        );
        assert!(!php_answered(301, redirect, ""));
        assert!(!php_answered(
            200,
            plain,
            "<html>Service Unavailable</html>"
        ));
        assert!(
            !php_answered(200, plain, "<?php\n// loginform"),
            "the source text, not a PHP answer"
        );
    }

    #[test]
    fn a_released_unit_neither_runs_nor_starts_at_boot() {
        assert!(unit_released("inactive\n", "disabled\n"));
        assert!(unit_released("failed\n", "disabled\n"));
        assert!(unit_released("inactive\n", "indirect\n"));
        assert!(!unit_released("active\n", "disabled\n"));
        assert!(!unit_released("activating\n", "disabled\n"));
        assert!(!unit_released("inactive\n", "enabled\n"));
        assert!(!unit_released("inactive\n", "static\n"));
    }
}
