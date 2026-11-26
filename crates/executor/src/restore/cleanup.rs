//! Fixed sandbox cleanup and conservative observations; no caller-selected commands.

use super::{BASE, ProbeTarget};
use crate::{ExecutorError, provision};

/// A null count means the remaining resources could not all be observed.
pub(crate) struct CleanupReport {
    leftover_resources: Option<u64>,
    unverified: Vec<&'static str>,
    removal_failures: u32,
}

impl CleanupReport {
    pub(crate) fn is_clean(&self) -> bool {
        self.leftover_resources == Some(0) && self.unverified.is_empty()
    }

    pub(crate) fn probe_state(&self, passed: bool) -> rustiron_journal::ProbeState {
        match (passed, self.is_clean()) {
            (_, false) => rustiron_journal::ProbeState::CleanupIncomplete,
            (true, true) => rustiron_journal::ProbeState::Passed,
            (false, true) => rustiron_journal::ProbeState::Failed,
        }
    }

    pub(crate) fn receipt(&self) -> serde_json::Value {
        serde_json::json!({
            "leftover_resources": self.leftover_resources,
            "status": if self.is_clean() { "complete" } else if self.unverified.is_empty() { "incomplete" } else { "unknown" },
            "unverified": self.unverified,
            "removal_failures": self.removal_failures,
        })
    }
}

trait CleanupHost {
    fn stop(&mut self) -> Result<(), ExecutorError>;
    /// Waits briefly before the unit list is read again.
    fn settle(&mut self);
    fn units_absent(&mut self) -> Result<bool, ExecutorError>;
    fn remove(&mut self) -> u32;
    fn passwd(&mut self) -> Result<String, ExecutorError>;
    fn rules(&mut self) -> Result<String, ExecutorError>;
    fn exists(&mut self, path: &str) -> std::io::Result<bool>;
    fn databases(&mut self) -> Result<String, ExecutorError>;
}

pub(crate) fn cleanup(target: &ProbeTarget<'_>) -> CleanupReport {
    cleanup_with(
        &mut SystemCleanup {
            probe: target.probe,
        },
        target.probe,
    )
}

/// Unit-list re-reads after a failed stop (200 ms apart, 2 s in all).
const STOP_POLLS: u32 = 10;

fn cleanup_with(host: &mut impl CleanupHost, probe: &str) -> CleanupReport {
    // A failed unit that `--collect` has not yet unloaded can still match
    // the stop pattern, and stopping it is refused (W179: the confined helper
    // lacks `init_t:system stop`). Nothing runs once no matching unit is
    // loaded, so a failed stop is accepted only when the units are gone.
    if host.stop().is_err()
        && !(0..STOP_POLLS).any(|_| {
            host.settle();
            host.units_absent() == Ok(true)
        })
    {
        return unknown("stop");
    }
    if host.units_absent() != Ok(true) {
        return unknown("units");
    }
    // Deletion may be idempotent (already absent). Retain tool failures, but
    // decide completion from independent postconditions, never exit codes alone.
    let removal_failures = host.remove();
    let root = format!("{BASE}/{probe}");
    let checks = [
        (
            "units",
            host.units_absent().and_then(|absent| {
                if absent {
                    Ok(0)
                } else {
                    Err(ExecutorError::Unavailable)
                }
            }),
        ),
        (
            "account",
            host.passwd().and_then(|text| account_count(&text, probe)),
        ),
        (
            "policy",
            host.rules().and_then(|text| {
                if text.len() >= 1 << 20 {
                    return Err(ExecutorError::Unavailable);
                }
                Ok(u64::from(text.contains(&root)))
            }),
        ),
        ("root", path_count(host.exists(&root))),
        (
            "spool",
            path_count(host.exists(&format!("/var/spool/mail/{probe}"))),
        ),
        (
            "database",
            host.databases().and_then(|text| database_count(&text)),
        ),
    ];
    let mut count = 0_u64;
    let mut unverified = Vec::new();
    for (name, observed) in checks {
        match observed {
            Ok(value) => match count.checked_add(value) {
                Some(total) => count = total,
                None => unverified.push("resource_count"),
            },
            Err(_) => unverified.push(name),
        }
    }
    CleanupReport {
        leftover_resources: unverified.is_empty().then_some(count),
        unverified,
        removal_failures,
    }
}

fn unknown(check: &'static str) -> CleanupReport {
    CleanupReport {
        leftover_resources: None,
        unverified: vec![check],
        removal_failures: 0,
    }
}

fn path_count(observed: std::io::Result<bool>) -> Result<u64, ExecutorError> {
    match observed {
        Ok(present) => Ok(u64::from(present)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(_) => Err(ExecutorError::Unavailable),
    }
}

fn database_count(text: &str) -> Result<u64, ExecutorError> {
    let words: Vec<_> = text.split_whitespace().collect();
    if words.len() != 2
        || words
            .iter()
            .any(|word| !word.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(ExecutorError::Unavailable);
    }
    let user = words[0]
        .parse::<u64>()
        .map_err(|_| ExecutorError::Unavailable)?;
    let database = words[1]
        .parse::<u64>()
        .map_err(|_| ExecutorError::Unavailable)?;
    user.checked_add(database).ok_or(ExecutorError::Unavailable)
}

fn account_count(text: &str, probe: &str) -> Result<u64, ExecutorError> {
    let mut root = false;
    let mut found = 0;
    for line in text.lines() {
        let fields: Vec<_> = line.split(':').collect();
        if fields.len() != 7
            || fields[0].is_empty()
            || fields[2].parse::<u32>().is_err()
            || fields[3].parse::<u32>().is_err()
        {
            return Err(ExecutorError::Unavailable);
        }
        root |= fields[0] == "root" && fields[2] == "0";
        if fields[0] == probe {
            found += 1;
        }
    }
    if !root || found > 1 {
        return Err(ExecutorError::Unavailable);
    }
    Ok(found)
}

fn path_exists(path: &str) -> std::io::Result<bool> {
    std::fs::symlink_metadata(path).map(|_| true)
}

struct SystemCleanup<'a> {
    probe: &'a str,
}

impl CleanupHost for SystemCleanup<'_> {
    fn stop(&mut self) -> Result<(), ExecutorError> {
        provision::run(
            "/usr/bin/systemctl",
            &["stop", "--", &format!("rustiron-probe-{}-*", self.probe)],
        )
    }

    fn settle(&mut self) {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    fn units_absent(&mut self) -> Result<bool, ExecutorError> {
        // Any retained matching unit blocks deletion, even if reported inactive.
        provision::output(
            "/usr/bin/systemctl",
            &[
                "list-units",
                "--all",
                "--no-legend",
                "--plain",
                "--no-pager",
                "--full",
                "--",
                &format!("rustiron-probe-{}-*", self.probe),
            ],
        )
        .map(|text| text.trim().is_empty())
    }

    fn remove(&mut self) -> u32 {
        let probe = self.probe;
        let root = format!("{BASE}/{probe}");
        let results = [
            provision::mariadb_admin(&format!(
                "DROP DATABASE IF EXISTS `{probe}`; DROP USER IF EXISTS '{probe}'@'localhost';\n"
            )),
            provision::run(
                "/usr/sbin/semanage",
                &["fcontext", "-d", "--", &format!("{root}/tmp(/.*)?")],
            ),
            provision::run(
                "/usr/sbin/semanage",
                &["fcontext", "-d", "--", &format!("{root}(/.*)?")],
            ),
            provision::run("/usr/bin/rm", &["-rf", "--", &root]),
            provision::run("/usr/sbin/userdel", &["--", probe]),
            provision::run(
                "/usr/bin/rm",
                &["-f", "--", &format!("/var/spool/mail/{probe}")],
            ),
        ];
        results.iter().filter(|result| result.is_err()).count() as u32
    }

    fn passwd(&mut self) -> Result<String, ExecutorError> {
        provision::read_etc("passwd")
    }

    fn rules(&mut self) -> Result<String, ExecutorError> {
        provision::output("/usr/sbin/semanage", &["fcontext", "--list", "-C"])
    }

    fn exists(&mut self, path: &str) -> std::io::Result<bool> {
        path_exists(path)
    }

    fn databases(&mut self) -> Result<String, ExecutorError> {
        provision::output(
            "/usr/bin/mariadb",
            &[
                "--batch",
                "--skip-column-names",
                "--socket",
                "/var/lib/mysql/mysql.sock",
                "--execute",
                &format!(
                    "SELECT COUNT(*) FROM mysql.user WHERE User='{}'; SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='{}';",
                    self.probe, self.probe
                ),
            ],
        )
    }
}

#[cfg(test)]
mod tests;
