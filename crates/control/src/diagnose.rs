//! W465 (P04): read-only diagnoses over the merged host status and the
//! executor's journal observation. A pure function of that document and the
//! time: it runs nothing and changes nothing. Every check ends `ok`, `warn`,
//! `fail`, or `unknown`; an unreadable fact is `unknown` with an action, never
//! a silent pass. Texts are fixed; only identifiers and numbers from the
//! observation appear, so the output stays redacted.

use serde_json::{Value, json};

/// The output schema.
pub(crate) const SCHEMA: &str = "rustiron-diagnosis/1";

/// D-010: a site's newest succeeded capture may be this old (RPO 24 h plus
/// two hours for the schedule).
const BACKUP_AGE_SECONDS: i64 = 26 * 3600;
/// D-060: fewer than this many seconds before expiry is a finding.
const CERTIFICATE_WARNING_SECONDS: u64 = 14 * 24 * 3600;
/// Log rotation runs daily; two days without a run is a finding.
const LOGROTATE_SECONDS: u64 = 2 * 24 * 3600;

/// D-063 (P06): the reviewed support matrix, shared with the installer
/// preflight.
const SUPPORT_MATRIX: &str = include_str!("../support-matrix.json");

/// Units whose failure stops Rustiron's management or a site's serving.
const CRITICAL_UNITS: [&str; 7] = [
    "lshttpd.service",
    "mariadb.service",
    "rustiron-executor.service",
    "rustiron-admin-helper.service",
    "rustiron-coordinator.service",
    "rustiron-s02-lab-executor.service",
    "chronyd.service",
];

struct Finding {
    check: &'static str,
    state: &'static str,
    owner: &'static str,
    subject: String,
    reason: &'static str,
    action: &'static str,
}

impl Finding {
    fn json(&self) -> Value {
        json!({
            "check": self.check, "state": self.state, "owner": self.owner,
            "subject": self.subject, "reason": self.reason, "action": self.action,
        })
    }
}

fn finding(
    check: &'static str,
    state: &'static str,
    owner: &'static str,
    subject: impl Into<String>,
    reason: &'static str,
    action: &'static str,
) -> Finding {
    Finding {
        check,
        state,
        owner,
        subject: subject.into(),
        reason,
        action,
    }
}

/// Every finding for `merged` (a journal observation whose `machine` is the
/// host status) at Unix time `now`.
pub(crate) fn diagnose(merged: &Value, now: u64) -> Value {
    let matrix = serde_json::from_str(SUPPORT_MATRIX).unwrap_or(Value::Null);
    diagnose_with(merged, now, &matrix)
}

fn diagnose_with(merged: &Value, now: u64, matrix: &Value) -> Value {
    let machine = &merged["machine"];
    let mut out = Vec::new();
    clock(machine, &mut out);
    selinux(machine, &mut out);
    ssh(machine, &mut out);
    firewall(machine, &mut out);
    storage(machine, &mut out);
    pressure(machine, &mut out);
    services(machine, now, &mut out);
    database(machine, &mut out);
    packages(machine, &mut out);
    backups(merged, now, &mut out);
    unsettled_captures(merged, now, &mut out);
    p03_backup_observations(merged, now, &mut out);
    certificates(merged, now, &mut out);
    php(merged, &mut out);
    proxy(merged, &mut out);
    app_units(merged, &mut out);
    stack(machine, now, matrix, &mut out);
    verifier(merged, &mut out);
    let worst = ["fail", "unknown", "warn"]
        .into_iter()
        .find(|state| out.iter().any(|finding| finding.state == *state))
        .unwrap_or("ok");
    json!({
        "schema": SCHEMA,
        "observed_at": machine["observed_at"],
        "summary": worst,
        "repairs": "none: diagnoses change nothing",
        "findings": out.iter().map(Finding::json).collect::<Vec<_>>(),
    })
}

fn clock(machine: &Value, out: &mut Vec<Finding>) {
    let clock = &machine["clock"];
    out.push(match clock["synchronized"].as_bool() {
        Some(true) => match clock["offset_us"].as_i64() {
            Some(offset) if offset.unsigned_abs() > 1_000_000 => finding(
                "clock",
                "warn",
                "host",
                "system clock",
                "The clock is synchronized but more than one second off.",
                "Check `chronyc tracking` and the NTP sources.",
            ),
            _ => finding(
                "clock",
                "ok",
                "host",
                "system clock",
                "The clock is synchronized.",
                "None.",
            ),
        },
        Some(false) => finding(
            "clock",
            "fail",
            "host",
            "system clock",
            "The clock is not synchronized. Grant times, renewals, and backups depend on it.",
            "Start chronyd and check `chronyc sources`.",
        ),
        None => finding(
            "clock",
            "unknown",
            "host",
            "system clock",
            "The synchronization state could not be read.",
            "Run `timedatectl show -p NTPSynchronized` as an operator.",
        ),
    });
}

fn selinux(machine: &Value, out: &mut Vec<Finding>) {
    out.push(match machine["selinux"].as_str() {
        Some("enforcing") => finding(
            "selinux",
            "ok",
            "host",
            "SELinux",
            "SELinux is enforcing.",
            "None.",
        ),
        Some("permissive") => finding(
            "selinux",
            "fail",
            "host",
            "SELinux",
            "SELinux is permissive: site and executor confinement is not enforced.",
            "Find why it was changed, then run `setenforce 1` and set SELINUX=enforcing.",
        ),
        _ => finding(
            "selinux",
            "unknown",
            "host",
            "SELinux",
            "The SELinux mode could not be read.",
            "Run `getenforce` as an operator.",
        ),
    });
}

fn ssh(machine: &Value, out: &mut Vec<Finding>) {
    let ssh = &machine["ssh"];
    if ssh["readable"] != true {
        out.push(finding(
            "ssh",
            "unknown",
            "host",
            "OpenSSH policy",
            "The effective sshd policy could not be read.",
            "Run `sshd -T` as an operator.",
        ));
        return;
    }
    let mut weak = false;
    if ssh["password_authentication"] == "yes" || ssh["kbd_interactive_authentication"] == "yes" {
        weak = true;
        out.push(finding(
            "ssh",
            "warn",
            "host",
            "OpenSSH policy",
            "sshd accepts passwords.",
            "Use keys and set PasswordAuthentication no.",
        ));
    }
    if ssh["permit_root_login"] == "yes" {
        weak = true;
        out.push(finding(
            "ssh",
            "warn",
            "host",
            "OpenSSH policy",
            "sshd permits root login with a password.",
            "Set PermitRootLogin prohibit-password or no.",
        ));
    }
    if !weak {
        out.push(finding(
            "ssh",
            "ok",
            "host",
            "OpenSSH policy",
            "sshd accepts keys only.",
            "None.",
        ));
    }
}

fn firewall(machine: &Value, out: &mut Vec<Finding>) {
    let firewall = &machine["firewall"];
    out.push(if firewall["readable"] != true {
        finding(
            "firewall",
            "unknown",
            "host",
            "firewalld",
            "The firewall state could not be read.",
            "As root, run `firewall-cmd --state`, and `packaging/firewall-zone.py --check` for drift from the Rustiron zone (page 28).",
        )
    } else if firewall["state"] == "running" {
        finding(
            "firewall",
            "ok",
            "host",
            "firewalld",
            "firewalld is running.",
            "None.",
        )
    } else {
        finding(
            "firewall",
            "fail",
            "host",
            "firewalld",
            "firewalld is not running.",
            "Start firewalld; Rustiron never opens ports itself.",
        )
    });
}

fn storage(machine: &Value, out: &mut Vec<Finding>) {
    let disk = &machine["disk"];
    let path = disk["path"].as_str().unwrap_or("/").to_owned();
    for (total, available, what) in [
        ("total_bytes", "available_bytes", "space"),
        ("inode_total", "inode_available", "inodes"),
    ] {
        let (Some(total), Some(available)) = (disk[total].as_u64(), disk[available].as_u64())
        else {
            out.push(finding(
                "storage",
                "unknown",
                "host",
                format!("{path} {what}"),
                "The file system could not be read.",
                "Run `df -h` and `df -i` as an operator.",
            ));
            continue;
        };
        let percent = available
            .saturating_mul(100)
            .checked_div(total)
            .unwrap_or(0);
        out.push(if percent < 10 {
            finding(
                "storage",
                "fail",
                "host",
                format!("{path} {what} {percent}% free"),
                "Less than 10% is free. Captures, imports, and the journal can fail.",
                "Free space or grow the file system; Rustiron deletes nothing.",
            )
        } else if percent < 20 {
            finding(
                "storage",
                "warn",
                "host",
                format!("{path} {what} {percent}% free"),
                "Less than 20% is free.",
                "Plan to free space or grow the file system.",
            )
        } else {
            finding(
                "storage",
                "ok",
                "host",
                format!("{path} {what} {percent}% free"),
                "Enough is free.",
                "None.",
            )
        });
    }
}

fn pressure(machine: &Value, out: &mut Vec<Finding>) {
    let memory = &machine["memory"];
    if let (Some(total), Some(available)) = (
        memory["total_bytes"].as_u64(),
        memory["available_bytes"].as_u64(),
    ) {
        let percent = available
            .saturating_mul(100)
            .checked_div(total)
            .unwrap_or(0);
        out.push(if percent < 10 {
            finding(
                "pressure",
                "warn",
                "host",
                format!("memory {percent}% available"),
                "Less than 10% of memory is available.",
                "Find the largest processes; site limits bound each PHP pool.",
            )
        } else {
            finding(
                "pressure",
                "ok",
                "host",
                format!("memory {percent}% available"),
                "Memory is available.",
                "None.",
            )
        });
    } else {
        out.push(finding(
            "pressure",
            "unknown",
            "host",
            "memory",
            "Memory could not be read.",
            "Read /proc/meminfo as an operator.",
        ));
    }
    let cpus = machine["cpu"]["count"]
        .as_f64()
        .filter(|count| *count > 0.0);
    let load = machine["cpu"]["load"][1].as_f64();
    if let (Some(cpus), Some(load)) = (cpus, load)
        && load / cpus > 2.0
    {
        out.push(finding(
            "pressure",
            "warn",
            "host",
            format!("load {load:.2} on {cpus} CPUs"),
            "The five-minute load is more than twice the CPU count.",
            "Find what is busy; per-site CPU limits bound each PHP pool.",
        ));
    }
}

fn services(machine: &Value, now: u64, out: &mut Vec<Finding>) {
    let empty = Vec::new();
    for service in machine["services"].as_array().unwrap_or(&empty) {
        let Some(unit) = service["unit"].as_str() else {
            continue;
        };
        if service["load"]
            .as_str()
            .is_some_and(|load| load != "loaded")
        {
            continue;
        }
        let owner = if unit.starts_with("rustiron") {
            "rustiron"
        } else {
            "host"
        };
        if unit == "logrotate.timer" {
            out.push(match service["last_trigger"].as_u64() {
                Some(last) if now.saturating_sub(last) <= LOGROTATE_SECONDS => finding(
                    "logrotate",
                    "ok",
                    "host",
                    unit,
                    "Logs were rotated in the last two days.",
                    "None.",
                ),
                Some(_) => finding(
                    "logrotate",
                    "warn",
                    "host",
                    unit,
                    "Logs were not rotated in the last two days.",
                    "Check `systemctl status logrotate.service`.",
                ),
                None => finding(
                    "logrotate",
                    "unknown",
                    "host",
                    unit,
                    "The last rotation time could not be read.",
                    "Check `systemctl list-timers logrotate.timer`.",
                ),
            });
            continue;
        }
        let active = service["active"].as_str();
        // W465-F1: a site's PHP pool is socket-activated, so its service is
        // `inactive` while idle; only `failed` is a finding.
        let site_pool = unit.starts_with("rustiron-site-php@");
        if site_pool && active == Some("inactive") {
            out.push(finding(
                "service",
                "ok",
                owner,
                unit,
                "The socket-activated pool is idle.",
                "None.",
            ));
            continue;
        }
        let critical = CRITICAL_UNITS.contains(&unit) || site_pool;
        out.push(match active {
            Some("active") => finding("service", "ok", owner, unit, "The unit is active.", "None."),
            Some("failed") => finding(
                "service",
                "fail",
                owner,
                unit,
                "The unit failed.",
                "Read `journalctl -u` for the unit; Rustiron does not restart it.",
            ),
            Some(_) if critical => finding(
                "service",
                "fail",
                owner,
                unit,
                "A unit that serving or management needs is not active.",
                "Read `systemctl status` for the unit and start it if that is intended.",
            ),
            Some(_) => finding(
                "service",
                "warn",
                owner,
                unit,
                "The unit is not active.",
                "Check whether it should run.",
            ),
            None => finding(
                "service",
                "unknown",
                owner,
                unit,
                "The unit state could not be read.",
                "Run `systemctl status` for the unit as an operator.",
            ),
        });
    }
    let failed = &machine["failed_units"];
    if failed["readable"] == true {
        for unit in failed["units"].as_array().unwrap_or(&empty) {
            if let Some(unit) = unit.as_str() {
                out.push(finding(
                    "service",
                    "fail",
                    if unit.starts_with("rustiron") {
                        "rustiron"
                    } else {
                        "host"
                    },
                    unit,
                    "systemd lists the unit as failed.",
                    "Read `journalctl -u` for the unit; Rustiron does not reset it.",
                ));
            }
        }
    } else {
        out.push(finding(
            "service",
            "unknown",
            "host",
            "failed units",
            "The list of failed units could not be read.",
            "Run `systemctl --failed` as an operator.",
        ));
    }
}

fn database(machine: &Value, out: &mut Vec<Finding>) {
    // W465-F2: the host status reports `responding`, `not_responding`, or
    // `unknown`.
    out.push(match machine["database"]["ping"].as_str() {
        Some("responding") => finding(
            "database",
            "ok",
            "host",
            "MariaDB",
            "MariaDB answers on its socket.",
            "None.",
        ),
        Some("not_responding") => finding(
            "database",
            "fail",
            "host",
            "MariaDB",
            "MariaDB does not answer on its socket. Sites and captures need it.",
            "Read `journalctl -u mariadb` and check its disk space.",
        ),
        _ => finding(
            "database",
            "unknown",
            "host",
            "MariaDB",
            "The database could not be asked.",
            "Run `mariadb-admin ping` as an operator.",
        ),
    });
    // W569 (W558-F1): an older observation has no listener count.
    match machine["database"]["listeners_beyond_loopback"].as_u64() {
        Some(0) => out.push(finding(
            "database",
            "ok",
            "host",
            "MariaDB network",
            "MariaDB listens on loopback only.",
            "None.",
        )),
        Some(_) => out.push(finding(
            "database",
            "fail",
            "host",
            "MariaDB network",
            "MariaDB listens on an address beyond loopback. Rustiron and its sites use the socket only.",
            "Check that /etc/my.cnf.d/zz-rustiron-loopback.cnf is installed and nothing later sets bind-address, then restart mariadb.",
        )),
        None => {}
    }
}

fn backups(merged: &Value, now: u64, out: &mut Vec<Finding>) {
    let Some(sites) = merged["sites"].as_array() else {
        out.push(finding(
            "backup",
            "unknown",
            "rustiron",
            "sites",
            "The journal observation is missing.",
            "Run the executor observation and diagnose again with --merge-observation.",
        ));
        return;
    };
    let empty = Vec::new();
    let captures = merged["captures"].as_array().unwrap_or(&empty);
    for site in sites {
        let (Some(id), Some("succeeded")) = (site["site_id"].as_str(), site["state"].as_str())
        else {
            continue;
        };
        if site["ejected"] == true {
            continue;
        }
        // W575 (D-095): Rustiron backs up nothing behind a proxy site.
        if is_proxy(site) {
            continue;
        }
        let newest = captures
            .iter()
            .filter(|capture| capture["site_id"] == id && capture["state"] == "succeeded")
            .filter_map(|capture| capture["finished_at"].as_i64())
            .max();
        let now = i64::try_from(now).unwrap_or(i64::MAX);
        out.push(match newest {
            Some(finished) if now - finished <= BACKUP_AGE_SECONDS => finding(
                "backup",
                "ok",
                "rustiron",
                id,
                "A capture succeeded within the recovery point objective.",
                "None.",
            ),
            Some(_) => finding(
                "backup",
                "warn",
                "rustiron",
                id,
                "The newest succeeded capture is older than 26 hours (D-010 RPO 24 h).",
                "Check the capture schedule and the newest capture's outcome.",
            ),
            None => finding(
                "backup",
                "warn",
                "rustiron",
                id,
                "No capture of this site has succeeded.",
                "Run or schedule a backup_capture for the site.",
            ),
        });
    }
}

/// W505 (W504 observation): a capture still `running` this long after its
/// start is not in progress: its unit has ended (the write unit's runtime is
/// at most 100 s), and the executor waits for a settlement.
const UNSETTLED_CAPTURE_SECONDS: i64 = 15 * 60;

/// A capture left `running` (an uncertain outcome) blocks every new capture
/// of the host until an operator settles it, so the RPO is missed.
fn unsettled_captures(merged: &Value, now: u64, out: &mut Vec<Finding>) {
    let Some(captures) = merged["captures"].as_array() else {
        return;
    };
    let now = i64::try_from(now).unwrap_or(i64::MAX);
    for capture in captures {
        let (Some("running"), Some(started), Some(operation)) = (
            capture["state"].as_str(),
            capture["started_at"].as_i64(),
            capture["operation_id"].as_str(),
        ) else {
            continue;
        };
        if now - started > UNSETTLED_CAPTURE_SECONDS {
            out.push(finding(
                "capture",
                "fail",
                "rustiron",
                operation,
                "A capture has an uncertain outcome and is not settled. Every new capture is refused until it is.",
                "Stop the admin helper and the executor, then run capture-reconcile for this operation with --settle-unclaimed (capture recovery).",
            ));
        }
    }
}

/// W600 (P04 / P03): read-only backup observations for each served, non-ejected,
/// non-proxy site: newest failed/refused/unclaimed capture attempts, recorded
/// COMPLIANCE object retention lock status (W391/D-079), D-021 consistency
/// labels, and restore-probe failures or incomplete sandbox cleanup.
fn p03_backup_observations(merged: &Value, now: u64, out: &mut Vec<Finding>) {
    let Some(sites) = merged["sites"].as_array() else {
        return;
    };
    let empty = Vec::new();
    let captures = merged["captures"].as_array().unwrap_or(&empty);
    let now_i64 = i64::try_from(now).unwrap_or(i64::MAX);

    for site in sites {
        let (Some(id), Some("succeeded")) = (site["site_id"].as_str(), site["state"].as_str())
        else {
            continue;
        };
        if site["ejected"] == true || is_proxy(site) {
            continue;
        }
        // Newest capture attempt for this site (by started_at, breaking ties by order).
        let newest_attempt = captures
            .iter()
            .enumerate()
            .filter(|(_, c)| c["site_id"] == id)
            .max_by_key(|(idx, c)| (c["started_at"].as_i64().unwrap_or(i64::MIN), *idx))
            .map(|(_, c)| c);
        if let Some(latest) = newest_attempt
            && latest["state"] == "failed"
        {
            let op = latest["operation_id"].as_str().unwrap_or("unknown");
            let subject = format!("{id} {op}");
            if latest["refusal"].as_str().is_some_and(|s| !s.is_empty()) {
                out.push(finding(
                    "capture",
                    "fail",
                    "rustiron",
                    subject,
                    "The newest capture was refused by backup or retention policy checks.",
                    "Read the refusal code in the executor observation, verify bucket Object Lock and credentials (page 22), then run a fresh backup_capture.",
                ));
            } else if latest["unclaimed_snapshot_id"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
            {
                out.push(finding(
                    "capture",
                    "warn",
                    "rustiron",
                    subject,
                    "The newest capture settled failed with an unclaimed snapshot (not a backup of record).",
                    "Check store reachability and site quota, review unclaimed snapshots with the retention principal (page 22), then run a fresh backup_capture.",
                ));
            } else {
                out.push(finding(
                    "capture",
                    "warn",
                    "rustiron",
                    subject,
                    "The newest capture attempt failed.",
                    "Inspect the capture unit journal, store reachability, and site quota, then run a fresh backup_capture.",
                ));
            }
        }

        // Newest succeeded capture: retention lock evidence and D-021 consistency.
        let newest_ok = captures
            .iter()
            .enumerate()
            .filter(|(_, c)| c["site_id"] == id && c["state"] == "succeeded")
            .max_by_key(|(idx, c)| (c["finished_at"].as_i64().unwrap_or(i64::MIN), *idx))
            .map(|(_, c)| c);
        if let Some(ok_cap) = newest_ok {
            let retention = &ok_cap["retention"];
            let policy_days = ok_cap["retention_days"].as_u64();
            if retention["status"] == "recorded" {
                let before_days = retention["before_days"].as_u64();
                let after_days = retention["after_days"].as_u64();
                let earliest = retention["earliest_retain_until"].as_i64();
                let degraded = match (before_days, after_days, earliest) {
                    (Some(b), Some(a), Some(until)) => {
                        a < b || policy_days.is_some_and(|d| a < d) || until <= now_i64
                    }
                    _ => true,
                };
                if degraded {
                    out.push(finding(
                        "backup",
                        "warn",
                        "rustiron",
                        format!("{id} retention"),
                        "The newest succeeded capture's recorded COMPLIANCE retention lock is shorter than enrolled days or has expired.",
                        "Verify bucket Object Lock default retention with the retention principal and run `rustiron backup retention-plan` (page 22).",
                    ));
                } else {
                    out.push(finding(
                        "backup",
                        "ok",
                        "rustiron",
                        format!("{id} retention"),
                        "The newest succeeded capture recorded COMPLIANCE object retention covering the enrolled window.",
                        "None.",
                    ));
                }
            } else if policy_days.is_some() {
                out.push(finding(
                    "backup",
                    "unknown",
                    "rustiron",
                    format!("{id} retention"),
                    "Retention days were copied from policy without per-object lock evidence.",
                    "Verify bucket Object Lock configuration and run a product capture with lock checks (page 22).",
                ));
            }

            if ok_cap["consistency"]["label"] == "unmatched" {
                out.push(finding(
                    "backup",
                    "warn",
                    "rustiron",
                    format!("{id} consistency"),
                    "The newest succeeded capture's database dump and file walk were not proven to match (D-021).",
                    "Check site write activity or freeze lock and run backup_capture during a quiet window.",
                ));
            }
        }
    }

    // Restore probe failures and incomplete sandbox cleanup.
    let probes = merged["probes"].as_array().unwrap_or(&empty);
    for probe in probes {
        if probe["state"] == "cleanup_incomplete" {
            let site = probe["site_id"].as_str().unwrap_or("unknown");
            let op = probe["operation_id"].as_str().unwrap_or("unknown");
            out.push(finding(
                "backup",
                "fail",
                "rustiron",
                format!("{site} probe {op}"),
                "A restore probe left sandbox cleanup incomplete.",
                "Finish restore-probe cleanup as root before starting another restore probe.",
            ));
        }
    }
    let mut latest_probe_by_site: std::collections::BTreeMap<&str, (i64, usize, &Value)> =
        std::collections::BTreeMap::new();
    for (idx, probe) in probes.iter().enumerate() {
        let Some(site) = probe["site_id"].as_str() else {
            continue;
        };
        let started = probe["started_at"].as_i64().unwrap_or(i64::MIN);
        let replace = latest_probe_by_site
            .get(site)
            .is_none_or(|(s, i, _)| (started, idx) > (*s, *i));
        if replace {
            latest_probe_by_site.insert(site, (started, idx, probe));
        }
    }
    for (site, (_, _, probe)) in latest_probe_by_site {
        if probe["state"] == "failed" {
            let op = probe["operation_id"].as_str().unwrap_or("unknown");
            out.push(finding(
                "backup",
                "warn",
                "rustiron",
                format!("{site} probe {op}"),
                "The newest restore probe for this site failed.",
                "Inspect the restore probe receipt and verify the snapshot before relying on it for recovery.",
            ));
        }
    }
}

fn certificates(merged: &Value, now: u64, out: &mut Vec<Finding>) {
    let empty = Vec::new();
    for served in merged["certificates"].as_array().unwrap_or(&empty) {
        let site = served["site_id"]
            .as_str()
            .unwrap_or("unknown site")
            .to_owned();
        let Some(not_after) = served["not_after"].as_u64() else {
            out.push(finding(
                "certificate",
                "unknown",
                "rustiron",
                site,
                "The certificate's expiry could not be read.",
                "Run the executor observation as an operator.",
            ));
            continue;
        };
        // D-064: an ejected site's certificate is still served, but the
        // operator renews it.
        if served["renewed_by"] == "operator" {
            out.push(if not_after <= now {
                finding(
                    "certificate",
                    "fail",
                    "host",
                    site,
                    "The ejected site's certificate has expired; Rustiron no longer renews it.",
                    "Renew it outside Rustiron, or uninstall Rustiron to hand the files over (D-064).",
                )
            } else if not_after - now < CERTIFICATE_WARNING_SECONDS {
                finding(
                    "certificate",
                    "warn",
                    "host",
                    site,
                    "The ejected site's certificate expires in less than 14 days; Rustiron no longer renews it.",
                    "Renew it outside Rustiron, or uninstall Rustiron to hand the files over (D-064).",
                )
            } else {
                finding(
                    "certificate",
                    "ok",
                    "host",
                    site,
                    "The ejected site's certificate is valid; the operator renews it.",
                    "None.",
                )
            });
            continue;
        }
        out.push(if not_after <= now {
            finding(
                "certificate",
                "fail",
                "rustiron",
                site,
                "The served certificate has expired.",
                "Check the last renewal and sign a new certificate_issue if needed.",
            )
        } else if not_after - now < CERTIFICATE_WARNING_SECONDS
            && served["last_renewal_failed"] == true
        {
            // W473-F1: both facts; the failure says what to read.
            finding(
                "certificate",
                "warn",
                "rustiron",
                site,
                "The served certificate expires in less than 14 days, and the last renewal failed.",
                "Read the admin helper journal for certificate_issue failures; the next attempt waits six hours.",
            )
        } else if not_after - now < CERTIFICATE_WARNING_SECONDS {
            finding(
                "certificate",
                "warn",
                "rustiron",
                site,
                "The served certificate expires in less than 14 days.",
                "Check that renewal runs (executor journal: certificate_renew).",
            )
        } else if served["finding"] == "renewal_failed" || served["last_renewal_failed"] == true {
            finding(
                "certificate",
                "warn",
                "rustiron",
                site,
                "The last renewal failed; the served certificate is unchanged.",
                "Read the admin helper journal for certificate_issue failures.",
            )
        } else {
            finding(
                "certificate",
                "ok",
                "rustiron",
                site,
                "The served certificate is valid.",
                "None.",
            )
        });
    }
}

/// Dotted decimal parts, or `None` for anything else.
fn version_parts(text: &str) -> Option<Vec<u64>> {
    text.split('.').map(|part| part.parse().ok()).collect()
}

/// The observed version of one matrix component.
fn observed_version<'a>(machine: &'a Value, name: &str, series: &str) -> Option<&'a str> {
    match name {
        "os" => machine["os"]["version"].as_str(),
        // Several PHP builds may be installed; the managed one is the series.
        "php" => machine["stack"]["php"]
            .as_array()?
            .iter()
            .find_map(|version| {
                version
                    .as_str()
                    .filter(|text| *text == series || text.starts_with(&format!("{series}.")))
            }),
        _ => machine["stack"][name].as_str(),
    }
}

/// D-063: each stack component against the reviewed matrix.
fn stack(machine: &Value, now: u64, matrix: &Value, out: &mut Vec<Finding>) {
    let (Some(components), Some(reviewed), Some(review_days), Some(warn_days)) = (
        matrix["components"].as_array(),
        matrix["reviewed_unix"].as_u64(),
        matrix["review_days"].as_u64(),
        matrix["warn_before_end_days"].as_u64(),
    ) else {
        out.push(finding(
            "support",
            "unknown",
            "rustiron",
            "support matrix",
            "The built-in support matrix could not be read.",
            "Reinstall the reviewed rustiron-control build.",
        ));
        return;
    };
    if now.saturating_sub(reviewed) > review_days * 86_400 {
        out.push(finding(
            "support",
            "warn",
            "rustiron",
            "support matrix",
            "The support matrix is past its review date.",
            "Review end-of-life dates and minimum versions (D-063) and update Rustiron.",
        ));
    }
    for component in components {
        let (Some(name), Some(series), Some(minimum)) = (
            component["name"].as_str(),
            component["series"].as_str(),
            component["minimum"].as_str().and_then(version_parts),
        ) else {
            continue;
        };
        let label = component["label"].as_str().unwrap_or(name).to_owned();
        // W562: a component marked `when_installed` (PowerDNS) is checked
        // only where the host reports it.
        if component["when_installed"].as_bool() == Some(true) && machine["stack"][name].is_null() {
            continue;
        }
        let Some(version) = observed_version(machine, name, series) else {
            out.push(finding(
                "support",
                "unknown",
                "host",
                label,
                "The installed version could not be read or is not in the supported series.",
                "Run `rustiron-control --host-status` as an operator and compare D-063.",
            ));
            continue;
        };
        let in_series = version == series || version.starts_with(&format!("{series}."));
        let end = component["end_of_life_unix"].as_u64();
        out.push(match version_parts(version) {
            _ if !in_series => finding(
                "support",
                "fail",
                "host",
                label,
                "The installed series is not in the support matrix.",
                "Return to the supported series (D-063); do not downgrade a database in place.",
            ),
            Some(parts) if parts < minimum => finding(
                "support",
                "fail",
                "host",
                label,
                "The installed version is older than the reviewed minimum.",
                "Apply the pending security updates with dnf.",
            ),
            None => finding(
                "support",
                "unknown",
                "host",
                label,
                "The installed version could not be parsed.",
                "Compare the installed version with D-063 by hand.",
            ),
            _ if end.is_some_and(|end| now >= end) => finding(
                "support",
                "fail",
                "host",
                label,
                "The supported series has reached its end of life.",
                "Plan the move to a newer supported series before more updates.",
            ),
            _ if end.is_some_and(|end| end - now < warn_days * 86_400) => finding(
                "support",
                "warn",
                "host",
                label,
                "The supported series reaches its end of life within 180 days.",
                "Plan the move to a newer supported series.",
            ),
            _ => finding(
                "support",
                "ok",
                "host",
                label,
                "The installed version is supported.",
                "None.",
            ),
        });
    }
}

/// W575: a site with journaled proxy ports.
fn is_proxy(site: &Value) -> bool {
    site["proxy_ports"]
        .as_array()
        .is_some_and(|ports| !ports.is_empty())
}

/// W598 (D-099): read-only systemd unit health for enrolled P27 app sites.
fn app_units(merged: &Value, out: &mut Vec<Finding>) {
    let empty = Vec::new();
    for site in merged["sites"].as_array().unwrap_or(&empty) {
        if site["app_runtime"].as_str().is_none()
            || !matches!(site["state"].as_str(), Some("succeeded" | "adopted"))
            || site["ejected"] == true
        {
            continue;
        }
        let name = site["site_id"].as_str().unwrap_or("unknown site");
        let deployed = site["app_active_release"].as_str().is_some();
        let unit = &site["app_unit"];
        let active = unit["active_state"].as_str();
        out.push(match (deployed, active) {
            (false, _) => finding(
                "app",
                "ok",
                "host",
                name,
                "App site is provisioned with no deployed release yet.",
                "Deploy a signed release bundle with app_deploy.",
            ),
            (true, Some("active")) => app_unit_confinement_finding(name, unit),
            (true, Some(_)) => finding(
                "app",
                "warn",
                "host",
                name,
                "The deployed app systemd unit is not active; OLS answers 503 for its routes.",
                "Inspect journalctl -u rustiron-app@rs_<site> and run a signed app_lifecycle restart.",
            ),
            (true, None) => finding(
                "app",
                "unknown",
                "host",
                name,
                "The app unit status was not observed.",
                "Run the diagnosis on the host with --merge-observation.",
            ),
        });
    }
}

/// W633 (V-03): never claim confinement solely from `ActiveState=active`.
/// Inspect observed systemd hardening and SELinux context fields truthfully.
fn app_unit_confinement_finding(name: &str, unit: &Value) -> Finding {
    let no_new_privs = unit["no_new_privileges"].as_str();
    let protect_sys = unit["protect_system"].as_str();
    let ip_deny = unit["ip_address_deny"].as_str();
    let priv_net = unit["private_network"].as_str();
    let selinux = unit["selinux_context"].as_str();
    let hardening_observed = no_new_privs.is_some()
        || protect_sys.is_some()
        || ip_deny.is_some()
        || priv_net.is_some()
        || selinux.is_some();
    if !hardening_observed {
        return finding(
            "app",
            "ok",
            "host",
            name,
            "The app systemd unit is active (confinement properties were not present in this observation).",
            "Re-run --merge-observation with current rustiron-control to inspect unit hardening.",
        );
    }
    let fs_ok = no_new_privs == Some("yes") && protect_sys == Some("strict");
    // W640-F1: systemd expands IPAddressDeny=any to "0.0.0.0/0 ::/0" in `systemctl show`.
    let net_ok = priv_net == Some("yes")
        || ip_deny
            .is_some_and(|v| v.contains("any") || (v.contains("0.0.0.0/0") && v.contains("::/0")));
    let mac_ok = selinux.is_some_and(|ctx| ctx.contains(":rustiron_app_t:s0:c"));
    if !fs_ok || !net_ok {
        return finding(
            "app",
            "warn",
            "host",
            name,
            "The app systemd unit is active, but expected filesystem or network confinement properties are missing.",
            "Verify rustiron-app@.service has NoNewPrivileges=yes, ProtectSystem=strict, and IPAddressDeny=any.",
        );
    }
    if !mac_ok {
        return finding(
            "app",
            "ok",
            "host",
            name,
            "The app systemd unit is active with systemd filesystem and loopback network hardening; no dedicated SELinux MCS app domain is observed.",
            "Track dedicated SELinux MCS app domain rollout before claiming MAC cross-app isolation.",
        );
    }
    finding(
        "app",
        "ok",
        "host",
        name,
        "The app systemd unit is active with verified systemd filesystem, network, and SELinux MCS confinement.",
        "None.",
    )
}

/// W575 (D-095): each served proxy site's ports, from the kernel's listener
/// tables only. A port where nothing listens is a stopped service: OLS
/// answers 503 for its routes. A service that also listens beyond loopback
/// can be reached without the proxy site; a Docker-published port bypasses
/// firewalld. Rustiron starts, changes, and backs up nothing behind the port.
fn proxy(merged: &Value, out: &mut Vec<Finding>) {
    let empty = Vec::new();
    for site in merged["sites"].as_array().unwrap_or(&empty) {
        if !is_proxy(site) || !matches!(site["state"].as_str(), Some("succeeded" | "adopted")) {
            continue;
        }
        let name = site["site_id"].as_str().unwrap_or("unknown site");
        let Some(ports) = site["proxy"].as_array() else {
            out.push(finding(
                "proxy",
                "unknown",
                "host",
                name,
                "The kernel's listener tables were not readable, so the ports behind the proxy site were not checked.",
                "Run the diagnosis on the host with --merge-observation.",
            ));
            continue;
        };
        for port in ports {
            let subject = format!("{name} port {}", port["port"]);
            out.push(
                match (port["listening"].as_u64(), port["beyond_loopback"].as_u64()) {
                    (Some(0), _) => finding(
                        "proxy",
                        "warn",
                        "host",
                        subject,
                        "Nothing listens on this port at 127.0.0.1: the service behind the proxy site is stopped, and OLS answers 503 for its routes.",
                        "Start the service behind the port. Rustiron does not manage it.",
                    ),
                    (Some(_), Some(0)) => finding(
                        "proxy",
                        "ok",
                        "host",
                        subject,
                        "A service listens on this port on loopback only.",
                        "None.",
                    ),
                    (Some(_), Some(_)) => finding(
                        "proxy",
                        "warn",
                        "host",
                        subject,
                        "The service on this port also listens beyond loopback, so it can be reached without the proxy site. A Docker-published port bypasses firewalld.",
                        "Publish the port on 127.0.0.1 only (for Docker, 127.0.0.1:PORT:PORT).",
                    ),
                    _ => finding(
                        "proxy",
                        "unknown",
                        "host",
                        subject,
                        "The listener facts for this port are malformed.",
                        "Run the diagnosis again.",
                    ),
                },
            );
        }
    }
}

/// D-073 (W487, W484-F1): each managed site's own PHP must answer its health
/// request with its account. The identity file is static, so a broken PHP
/// build shows only here. A 404 or a redirect is a vhost without the health
/// context (rendered before W487, or a site that no generation serves): the
/// context has rewriting off, so it never redirects.
fn php(merged: &Value, out: &mut Vec<Finding>) {
    let empty = Vec::new();
    for site in merged["sites"].as_array().unwrap_or(&empty) {
        let health = &site["php_health"];
        if health.is_null() {
            continue;
        }
        let name = site["site_id"]
            .as_str()
            .unwrap_or("unknown site")
            .to_owned();
        out.push(match (health["status"].as_u64(), health["account_matches"].as_bool()) {
            (Some(200), Some(true)) => finding(
                "php",
                "ok",
                "rustiron",
                name,
                "The site's own PHP answers as the site account.",
                "None.",
            ),
            (Some(404 | 300..=399), _) => finding(
                "php",
                "unknown",
                "rustiron",
                name,
                "The site's vhost has no PHP health context: it was rendered before D-073, or no generation serves the site.",
                "If the site is served, run a config_activate; the new generation adds the context (D-073).",
            ),
            _ => finding(
                "php",
                "fail",
                "rustiron",
                name,
                "The site's PHP does not answer as the site account: PHP pages fail even when the identity file answers.",
                "Check `systemctl status rustiron-site-php@<account>` and `rpm -V lsphp84`; after an interrupted update, repair forward (support matrix).",
            ),
        });
    }
}

/// W485 (W484-F2): a package installed twice is what an interrupted dnf
/// transaction leaves; the files of either version may be broken.
fn packages(machine: &Value, out: &mut Vec<Finding>) {
    let facts = &machine["packages"];
    if facts.is_null() {
        return;
    }
    let names: Option<Vec<&str>> = facts["duplicates"]
        .as_array()
        .map(|list| list.iter().filter_map(Value::as_str).collect());
    out.push(match (facts["readable"].as_bool(), names) {
        (Some(true), Some(names)) if names.is_empty() => finding(
            "packages",
            "ok",
            "host",
            "packages",
            "No package is installed twice.",
            "None.",
        ),
        (Some(true), Some(names)) => finding(
            "packages",
            "fail",
            "host",
            format!(
                "{}{}",
                names.join(", "),
                if facts["truncated"] == true { " and more" } else { "" }
            ),
            "An interrupted package update left two versions of these packages. Their files may be broken: a site can answer 500 while its identity file answers 200.",
            "As root, repair forward: `dnf remove --duplicates`, `dnf distro-sync`, then `rpm -V` the named packages and restart the services that use them (support matrix).",
        ),
        _ => finding(
            "packages",
            "unknown",
            "host",
            "packages",
            "The installed packages could not be listed.",
            "Run `rpm -qa` as an operator.",
        ),
    });
}

/// W483-F1 (P06): the executor checks that the installed `ssh-keygen` still
/// has the enrolled digest. An observation before W483 has no such fact.
fn verifier(merged: &Value, out: &mut Vec<Finding>) {
    let fact = &merged["host"]["signature_verifier"]["matches_enrollment"];
    if fact.is_null() {
        return;
    }
    out.push(match fact.as_bool() {
        Some(true) => finding(
            "verifier",
            "ok",
            "rustiron",
            "signature verifier",
            "The installed ssh-keygen has the enrolled digest.",
            "None.",
        ),
        Some(false) => finding(
            "verifier",
            "fail",
            "rustiron",
            "signature verifier",
            "The installed ssh-keygen differs from the enrolled digest, so every signed request is refused (an openssh update replaces it).",
            "Check the package with `rpm -V openssh-clients`, then measure the verifier again and write the policy with the enrollment tool (operator page 09).",
        ),
        None => finding(
            "verifier",
            "unknown",
            "rustiron",
            "signature verifier",
            "The verifier fact could not be read.",
            "Run the executor observation as an operator.",
        ),
    });
}

/// One line per finding that is not `ok`, then the summary.
/// D-083: the checks whose `warn` also alerts: what Rustiron owns for the
/// owner's sites (backup age, certificates, unsettled captures) and space.
const ALERT_WARN_CHECKS: [&str; 5] = ["backup", "certificate", "capture", "storage", "support"];
/// Longest alert message, so Kuma's mail stays short.
const MAX_ALERT_MESSAGE: usize = 300;

/// D-083 (P05): the Uptime Kuma push query for `diagnosis`. `down` when a
/// finding fails, or warns in one of [`ALERT_WARN_CHECKS`]; the message
/// names those findings (`state check subject`), most severe first, and is
/// percent-encoded. `unknown` findings (facts the unprivileged diagnosis
/// cannot read) do not alert.
pub(crate) fn alert_query(diagnosis: &Value) -> String {
    let empty = Vec::new();
    let findings = diagnosis["findings"].as_array().unwrap_or(&empty);
    let mut alerts: Vec<String> = Vec::new();
    for wanted in ["fail", "warn"] {
        for finding in findings {
            let check = finding["check"].as_str().unwrap_or("unknown");
            let state = finding["state"].as_str().unwrap_or("");
            if state == wanted && (wanted == "fail" || ALERT_WARN_CHECKS.contains(&check)) {
                let subject = finding["subject"].as_str().unwrap_or("");
                alerts.push(format!("{state} {check} {subject}"));
            }
        }
    }
    let (status, message) = if alerts.is_empty() {
        ("up", "ok".to_owned())
    } else {
        let mut message = alerts.join("; ");
        if message.len() > MAX_ALERT_MESSAGE {
            let cut = (0..=MAX_ALERT_MESSAGE)
                .rev()
                .find(|index| message.is_char_boundary(*index))
                .unwrap_or(0);
            message.truncate(cut);
            message.push_str(" ...");
        }
        ("down", message)
    };
    format!("status={status}&msg={}&ping=", percent_encode(&message))
}

/// RFC 3986 unreserved characters stay; every other byte is `%XX`.
fn percent_encode(text: &str) -> String {
    text.bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

pub(crate) fn human(diagnosis: &Value) -> String {
    let mut text = String::new();
    let empty = Vec::new();
    for finding in diagnosis["findings"].as_array().unwrap_or(&empty) {
        if finding["state"] == "ok" {
            continue;
        }
        text.push_str(&format!(
            "{:<7} {:<11} {:<8} {}: {} Action: {}\n",
            finding["state"].as_str().unwrap_or("?").to_uppercase(),
            finding["check"].as_str().unwrap_or("?"),
            finding["owner"].as_str().unwrap_or("?"),
            rustiron_contracts::escape_human(finding["subject"].as_str().unwrap_or("?")),
            finding["reason"].as_str().unwrap_or(""),
            finding["action"].as_str().unwrap_or(""),
        ));
    }
    let count = |state: &str| {
        diagnosis["findings"]
            .as_array()
            .map_or(0, |all| all.iter().filter(|f| f["state"] == state).count())
    };
    text.push_str(&format!(
        "summary: {} ({} ok, {} warn, {} fail, {} unknown). Nothing was changed.\n",
        diagnosis["summary"].as_str().unwrap_or("?"),
        count("ok"),
        count("warn"),
        count("fail"),
        count("unknown")
    ));
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 2_000_000_000;
    const DAY: u64 = 86_400;

    fn matrix() -> Value {
        json!({
            "reviewed_unix": NOW - DAY, "review_days": 120, "warn_before_end_days": 180,
            "components": [
                {"name": "os", "label": "AlmaLinux", "series": "10", "minimum": "10.2",
                 "end_of_life_unix": NOW + 3000 * DAY},
                {"name": "openlitespeed", "label": "OpenLiteSpeed", "series": "1.9",
                 "minimum": "1.9.4", "end_of_life_unix": null},
                {"name": "php", "label": "PHP (lsphp84)", "series": "8.4", "minimum": "8.4.27",
                 "end_of_life_unix": NOW + 700 * DAY},
                {"name": "mariadb", "label": "MariaDB", "series": "10.11", "minimum": "10.11.18",
                 "end_of_life_unix": NOW + 400 * DAY},
            ],
        })
    }

    /// The fixed test matrix keeps these tests independent of real dates.
    fn diagnose(merged: &Value, now: u64) -> Value {
        diagnose_with(merged, now, &matrix())
    }

    fn healthy() -> Value {
        json!({
            "sites": [{"site_id": "blog1", "state": "succeeded", "ejected": false}],
            "captures": [{"site_id": "blog1", "state": "succeeded", "finished_at": NOW - 3600}],
            "certificates": [{"site_id": "blog1", "not_after": NOW + 60 * 86400, "finding": null}],
            "machine": {
                "observed_at": NOW,
                "clock": {"synchronized": true, "offset_us": 120},
                "selinux": "enforcing",
                "ssh": {"readable": true, "permit_root_login": "prohibit-password",
                        "password_authentication": "no", "kbd_interactive_authentication": "no"},
                "firewall": {"readable": true, "state": "running"},
                "disk": {"path": "/", "total_bytes": 100, "available_bytes": 60,
                         "inode_total": 100, "inode_available": 90},
                "memory": {"total_bytes": 100, "available_bytes": 50},
                "cpu": {"count": 4, "load": [0.5, 0.5, 0.5]},
                "services": [
                    {"unit": "lshttpd.service", "load": "loaded", "active": "active"},
                    {"unit": "mariadb.service", "load": "loaded", "active": "active"},
                    {"unit": "rustiron-executor.service", "load": "loaded", "active": "active"},
                    {"unit": "rustiron-s02-lab-executor.service", "load": "not-found", "active": "inactive"},
                    {"unit": "rustiron-site-php@rs_blog1.service", "load": "loaded", "active": "inactive"},
                    {"unit": "logrotate.timer", "load": "loaded", "active": "active", "last_trigger": NOW - 3600},
                ],
                "failed_units": {"readable": true, "units": []},
                "database": {"ping": "responding"},
                "os": {"version": "10.2"},
                "stack": {"openlitespeed": "1.9.4", "mariadb": "10.11.18",
                          "php": ["8.3.9", "8.4.27"]},
            },
        })
    }

    fn states(diagnosis: &Value, check: &str) -> Vec<String> {
        diagnosis["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|finding| finding["check"] == check)
            .map(|finding| finding["state"].as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn a_healthy_host_is_ok_and_absent_units_are_skipped() {
        let diagnosis = diagnose(&healthy(), NOW);
        assert_eq!(diagnosis["summary"], "ok", "{diagnosis:#}");
        assert_eq!(diagnosis["schema"], SCHEMA);
        assert!(
            !diagnosis.to_string().contains("rustiron-s02-lab-executor"),
            "a unit absent on this host is not a finding"
        );
    }

    /// W575 (D-095): one finding per proxy port; a stopped service or one
    /// beyond loopback warns, unreadable tables are unknown, and a proxy
    /// site has no backup finding.
    #[test]
    fn proxy_ports_warn_when_stopped_or_beyond_loopback() {
        let mut host = healthy();
        host["sites"].as_array_mut().unwrap().push(
            json!({"site_id": "ytproxy", "state": "succeeded", "ejected": false,
                         "proxy_ports": [3100, 3101, 3102]}),
        );
        let diagnosis = diagnose(&host, NOW);
        assert_eq!(states(&diagnosis, "proxy"), ["unknown"]);
        assert_eq!(states(&diagnosis, "backup"), ["ok"], "blog1 only");
        host["sites"][1]["proxy"] = json!([
            {"port": 3100, "listening": 1, "beyond_loopback": 0},
            {"port": 3101, "listening": 0, "beyond_loopback": 0},
            {"port": 3102, "listening": 1, "beyond_loopback": 1},
        ]);
        let diagnosis = diagnose(&host, NOW);
        assert_eq!(states(&diagnosis, "proxy"), ["ok", "warn", "warn"]);
        assert_eq!(diagnosis["summary"], "warn");
        let subjects: Vec<_> = diagnosis["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|finding| finding["check"] == "proxy")
            .map(|finding| finding["subject"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            subjects,
            [
                "ytproxy port 3100",
                "ytproxy port 3101",
                "ytproxy port 3102"
            ]
        );
        // A quarantined proxy site is not served, so it is not checked.
        host["sites"][1]["state"] = json!("quarantined");
        assert!(states(&diagnose(&host, NOW), "proxy").is_empty());
    }

    /// D-073 (W487): the PHP health of each managed site.
    #[test]
    fn a_site_whose_php_does_not_answer_as_its_account_fails() {
        assert_eq!(
            states(&diagnose(&healthy(), NOW), "php"),
            Vec::<String>::new()
        );
        let mut host = healthy();
        let with = |host: &mut Value, health: Value| host["sites"][0]["php_health"] = health;
        with(&mut host, json!({"status": 200, "account_matches": true}));
        assert_eq!(states(&diagnose(&host, NOW), "php"), ["ok"]);
        for broken in [
            json!({"status": 500, "account_matches": false}),
            json!({"status": 200, "account_matches": false}),
            json!({"status": 503}),
            // W487-F1: a hung pool gives no answer at all.
            json!({"status": null, "account_matches": false}),
        ] {
            with(&mut host, broken.clone());
            let diagnosis = diagnose(&host, NOW);
            assert_eq!(states(&diagnosis, "php"), ["fail"], "{broken}");
            assert_eq!(diagnosis["summary"], "fail");
        }
        // W487: without the context, a site's own forced-HTTPS rule answers.
        for missing in [404, 301, 302] {
            with(
                &mut host,
                json!({"status": missing, "account_matches": false}),
            );
            assert_eq!(
                states(&diagnose(&host, NOW), "php"),
                ["unknown"],
                "{missing}"
            );
        }
    }

    /// D-083 (P05): pressure and unknown facts do not alert; failures and
    /// the listed warnings do, failures first, cut and percent-encoded.
    #[test]
    fn the_alert_query_is_up_only_without_an_alerting_finding() {
        let up = json!({"findings": [
            {"check": "ssh", "state": "unknown", "subject": "sshd"},
            {"check": "pressure", "state": "warn", "subject": "load"},
            {"check": "clock", "state": "ok", "subject": "x"},
        ]});
        assert_eq!(alert_query(&up), "status=up&msg=ok&ping=");
        let down = json!({"findings": [
            {"check": "backup", "state": "warn", "subject": "blog1"},
            {"check": "capture", "state": "fail", "subject": "op_x"},
        ]});
        assert_eq!(
            alert_query(&down),
            "status=down&msg=fail%20capture%20op_x%3B%20warn%20backup%20blog1&ping="
        );
        let many = json!({"findings": (0..60)
            .map(|n| json!({"check": "php", "state": "fail", "subject": format!("site{n}")}))
            .collect::<Vec<_>>()});
        let query = alert_query(&many);
        assert!(query.starts_with("status=down&msg=") && query.contains("%20...&ping="));
        assert!(query.len() < 3 * 310 + 40);
        assert!(!alert_query(&json!({})).contains("down"));
    }

    #[test]
    fn an_unsettled_capture_fails_and_a_running_one_does_not() {
        let mut host = healthy();
        host["captures"] = json!([
            {"site_id": "blog1", "state": "succeeded", "finished_at": NOW - 3600, "operation_id": "op_ok", "started_at": NOW - 3700},
            {"site_id": "blog1", "state": "running", "started_at": NOW - 60, "operation_id": "op_now"},
        ]);
        assert!(states(&diagnose(&host, NOW), "capture").is_empty());
        host["captures"][1]["started_at"] = json!(NOW - 16 * 60);
        let diagnosis = diagnose(&host, NOW);
        assert_eq!(states(&diagnosis, "capture"), ["fail"]);
        assert_eq!(diagnosis["summary"], "fail");
        let finding = diagnosis["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["check"] == "capture")
            .unwrap();
        assert_eq!(finding["subject"], "op_now");
        assert!(
            finding["action"]
                .as_str()
                .unwrap()
                .contains("--settle-unclaimed")
        );
    }

    /// W600 (P04 / P03): refused, failed, and unclaimed capture attempts,
    /// COMPLIANCE retention evidence, D-021 unmatched consistency, and restore
    /// probe failures/incomplete cleanup produce actionable findings.
    #[test]
    fn p03_backup_observations_diagnose_refusals_retention_consistency_and_probes() {
        let mut host = healthy();
        let ok_cap = json!({
            "operation_id": "op_ok",
            "site_id": "blog1",
            "state": "succeeded",
            "started_at": NOW - 7200,
            "finished_at": NOW - 7000,
            "retention_days": 30,
            "retention": {
                "status": "recorded",
                "before_days": 30,
                "after_days": 30,
                "objects": 4,
                "earliest_retain_until": NOW + 29 * DAY,
                "latest_retain_until": NOW + 30 * DAY,
            },
            "consistency": {"label": "matched", "reason": null},
            "unclaimed_snapshot_id": null,
            "refusal": null,
        });
        host["captures"] = json!([ok_cap]);
        let clean = diagnose(&host, NOW);
        assert_eq!(clean["summary"], "ok", "{clean:#}");
        assert_eq!(states(&clean, "backup"), ["ok", "ok"]);

        // Newer failed capture with refusal code fails and alerts even while RPO is fresh.
        host["captures"].as_array_mut().unwrap().push(json!({
            "operation_id": "op_refused",
            "site_id": "blog1",
            "state": "failed",
            "started_at": NOW - 300,
            "finished_at": NOW - 290,
            "refusal": "LOCK_RETENTION_TOO_SHORT",
            "unclaimed_snapshot_id": null,
        }));
        let refused = diagnose(&host, NOW);
        assert_eq!(states(&refused, "capture"), ["fail"]);
        assert!(alert_query(&refused).contains("fail%20capture%20blog1%20op_refused"));

        // Settled failed capture with unclaimed snapshot warns and alerts.
        host["captures"][1] = json!({
            "operation_id": "op_unclaimed",
            "site_id": "blog1",
            "state": "failed",
            "started_at": NOW - 200,
            "finished_at": NOW - 190,
            "refusal": null,
            "unclaimed_snapshot_id": "ab".repeat(32),
        });
        let unclaimed = diagnose(&host, NOW);
        assert_eq!(states(&unclaimed, "capture"), ["warn"]);
        assert!(alert_query(&unclaimed).contains("warn%20capture%20blog1%20op_unclaimed"));

        // Degraded retention + unmatched consistency + probe failures.
        host["captures"] = json!([{
            "operation_id": "op_ok2",
            "site_id": "blog1",
            "state": "succeeded",
            "started_at": NOW - 3600,
            "finished_at": NOW - 3500,
            "retention_days": 30,
            "retention": {
                "status": "recorded",
                "before_days": 30,
                "after_days": 7,
                "objects": 4,
                "earliest_retain_until": NOW + 6 * DAY,
                "latest_retain_until": NOW + 7 * DAY,
            },
            "consistency": {"label": "unmatched", "reason": "freeze_not_held"},
            "unclaimed_snapshot_id": null,
            "refusal": null,
        }]);
        host["probes"] = json!([
            {"operation_id": "op_probe_dirty", "site_id": "blog1", "state": "cleanup_incomplete", "started_at": NOW - 500},
            {"operation_id": "op_probe_fail", "site_id": "blog1", "state": "failed", "started_at": NOW - 100},
        ]);
        let bad = diagnose(&host, NOW);
        // backup findings: age ok, retention warn, consistency warn, cleanup_incomplete fail, newest probe failed warn.
        assert_eq!(
            states(&bad, "backup"),
            ["ok", "warn", "warn", "fail", "warn"]
        );
        assert_eq!(bad["summary"], "fail");

        // Policy retention_days without lock evidence reports unknown (not silent pass).
        host["captures"] = json!([{
            "operation_id": "op_nolock",
            "site_id": "blog1",
            "state": "succeeded",
            "started_at": NOW - 3600,
            "finished_at": NOW - 3500,
            "retention_days": 30,
            "retention": null,
            "consistency": {"label": "matched", "reason": null},
        }]);
        host["probes"] = json!([]);
        let nolock = diagnose(&host, NOW);
        assert_eq!(states(&nolock, "backup"), ["ok", "unknown"]);
    }

    /// W510: the packaged check-in runs this binary's alert line and pushes
    /// only a query it produced; its unit runs only with the push link.
    #[test]
    fn the_packaged_check_in_pushes_the_alert_line() {
        let script = include_str!("../../../packaging/alert/rustiron-alert-checkin");
        let unit = include_str!("../../../packaging/systemd/rustiron-alert-checkin.service");
        let stage = include_str!("../../../packaging/stage-product.sh");
        assert!(script.contains("/usr/libexec/rustiron/rustiron-control --merge-observation"));
        assert!(script.contains("--diagnose --alert-line"));
        // W510-F1: a system service cannot use `systemd-run --pipe`.
        assert!(!script.contains("systemd-run --wait"));
        assert!(script.contains(
            "\nif /usr/libexec/rustiron/rustiron-executor observe > \"$observation\"; then\n"
        ));
        assert!(script.contains("link_file=/etc/rustiron/alert-push.url"));
        assert!(script.contains("| curl -fsS -m 20 --retry 2 --retry-delay 5 -o /dev/null -K -"));
        assert!(unit.contains("\nExecStart=/usr/libexec/rustiron/alert-checkin\n"));
        assert!(unit.contains("\nConditionPathExists=/etc/rustiron/alert-push.url\n"));
        assert!(
            stage.contains("packaging/alert/rustiron-alert-checkin \"$libexec/alert-checkin\"")
        );
        for query in [
            alert_query(&json!({})),
            alert_query(
                &json!({"findings": [{"check": "capture", "state": "fail", "subject": "a\"b c"}]}),
            ),
        ] {
            assert!(query.starts_with("status=up&msg=") || query.starts_with("status=down&msg="));
            assert!(
                query
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-._~%&=".contains(&byte))
            );
        }
    }

    /// W485 (W484-F2): duplicate packages fail with the forward repair;
    /// a host status without the fact adds no finding.
    #[test]
    fn duplicate_packages_fail_with_the_forward_repair() {
        assert_eq!(
            states(&diagnose(&healthy(), NOW), "packages"),
            Vec::<String>::new()
        );
        let mut host = healthy();
        host["machine"]["packages"] =
            json!({"readable": true, "duplicates": [], "truncated": false});
        assert_eq!(states(&diagnose(&host, NOW), "packages"), ["ok"]);
        host["machine"]["packages"]["duplicates"] = json!(["lsphp84.x86_64", "lsphp84-pdo.x86_64"]);
        let diagnosis = diagnose(&host, NOW);
        assert_eq!(states(&diagnosis, "packages"), ["fail"]);
        assert_eq!(diagnosis["summary"], "fail");
        let text = diagnosis.to_string();
        assert!(
            text.contains("lsphp84.x86_64, lsphp84-pdo.x86_64"),
            "{text}"
        );
        assert!(text.contains("dnf remove --duplicates"), "{text}");
        host["machine"]["packages"] =
            json!({"readable": false, "duplicates": null, "truncated": false});
        assert_eq!(states(&diagnose(&host, NOW), "packages"), ["unknown"]);
    }

    /// W483-F1: a replaced ssh-keygen fails the host with the enrollment
    /// action; an observation without the fact adds no finding.
    #[test]
    fn a_changed_signature_verifier_fails_with_its_action() {
        assert_eq!(
            states(&diagnose(&healthy(), NOW), "verifier"),
            Vec::<String>::new()
        );
        let mut host = healthy();
        host["host"]["signature_verifier"] = json!({"matches_enrollment": true});
        assert_eq!(states(&diagnose(&host, NOW), "verifier"), ["ok"]);
        host["host"]["signature_verifier"]["matches_enrollment"] = json!(false);
        let diagnosis = diagnose(&host, NOW);
        assert_eq!(diagnosis["summary"], "fail");
        assert_eq!(states(&diagnosis, "verifier"), ["fail"]);
        assert!(diagnosis.to_string().contains("rpm -V openssh-clients"));
        host["host"]["signature_verifier"]["matches_enrollment"] = json!("yes");
        assert_eq!(states(&diagnose(&host, NOW), "verifier"), ["unknown"]);
    }

    /// The P04 fault cases: disk pressure, clock, failed service and
    /// database, missing backup, and certificate failure.
    #[test]
    fn injected_faults_become_findings_with_actions() {
        let mut host = healthy();
        host["machine"]["clock"]["synchronized"] = json!(false);
        host["machine"]["disk"]["available_bytes"] = json!(5);
        host["machine"]["services"][1]["active"] = json!("failed");
        host["machine"]["services"][4]["active"] = json!("failed");
        host["machine"]["database"]["ping"] = json!("not_responding");
        host["captures"] = json!([]);
        host["certificates"][0]["not_after"] = json!(NOW - 1);
        let diagnosis = diagnose(&host, NOW);
        assert_eq!(diagnosis["summary"], "fail");
        assert_eq!(states(&diagnosis, "clock"), ["fail"]);
        assert_eq!(states(&diagnosis, "storage"), ["fail", "ok"]);
        assert!(states(&diagnosis, "service").contains(&"fail".to_owned()));
        assert_eq!(states(&diagnosis, "database"), ["fail"]);
        assert_eq!(states(&diagnosis, "backup"), ["warn"]);
        // W569 (W558-F1): MariaDB beyond loopback fails; loopback only is ok.
        let mut exposed = healthy();
        exposed["machine"]["database"]["listeners_beyond_loopback"] = json!(2);
        assert_eq!(states(&diagnose(&exposed, NOW), "database"), ["ok", "fail"]);
        exposed["machine"]["database"]["listeners_beyond_loopback"] = json!(0);
        assert_eq!(states(&diagnose(&exposed, NOW), "database"), ["ok", "ok"]);
        assert_eq!(states(&diagnosis, "certificate"), ["fail"]);
        for finding in diagnosis["findings"].as_array().unwrap() {
            if finding["state"] != "ok" {
                assert_ne!(finding["action"], "None.", "{finding}");
            }
        }
        let mut renewal = healthy();
        renewal["certificates"][0]["finding"] = json!("renewal_failed");
        assert_eq!(states(&diagnose(&renewal, NOW), "certificate"), ["warn"]);
        let mut ejected = healthy();
        ejected["certificates"][0]["renewed_by"] = json!("operator");
        ejected["certificates"][0]["not_after"] = json!(NOW + 86400);
        let found = diagnose(&ejected, NOW);
        assert_eq!(states(&found, "certificate"), ["warn"]);
        assert!(found.to_string().contains("no longer renews it"));
        let mut soon = healthy();
        soon["certificates"][0]["not_after"] = json!(NOW + 86400);
        assert_eq!(states(&diagnose(&soon, NOW), "certificate"), ["warn"]);
        assert!(
            !diagnose(&soon, NOW)
                .to_string()
                .contains("last renewal failed")
        );
        soon["certificates"][0]["last_renewal_failed"] = json!(true);
        assert!(
            diagnose(&soon, NOW)
                .to_string()
                .contains("and the last renewal failed"),
            "W473-F1: a failed renewal is not hidden by the expiry warning"
        );
        let mut old = healthy();
        old["captures"][0]["finished_at"] = json!(NOW - 27 * 3600);
        assert_eq!(states(&diagnose(&old, NOW), "backup"), ["warn"]);
    }

    /// Unreadable facts are unknown, never a silent pass.
    #[test]
    fn unknowns_are_reported_not_passed() {
        let mut host = healthy();
        host["machine"]["clock"]["synchronized"] = Value::Null;
        host["machine"]["selinux"] = Value::Null;
        host["machine"]["ssh"]["readable"] = json!(false);
        host["machine"]["firewall"]["readable"] = json!(false);
        host["machine"]["disk"]["total_bytes"] = Value::Null;
        host["machine"]["failed_units"]["readable"] = json!(false);
        host["machine"]["database"]["ping"] = json!("unknown");
        let diagnosis = diagnose(&host, NOW);
        assert_eq!(diagnosis["summary"], "unknown");
        for check in ["clock", "selinux", "ssh", "firewall", "database"] {
            assert_eq!(states(&diagnosis, check), ["unknown"], "{check}");
        }
        assert_eq!(
            states(
                &diagnose(&json!({"machine": healthy()["machine"]}), NOW),
                "backup"
            ),
            ["unknown"]
        );
    }

    #[test]
    fn the_human_text_is_redacted_and_says_nothing_changed() {
        let mut host = healthy();
        host["sites"][0]["site_id"] = json!("blog1\u{1b}[31m");
        host["captures"] = json!([]);
        let text = human(&diagnose(&host, NOW));
        assert!(!text.contains('\u{1b}'), "{text}");
        assert!(text.starts_with("WARN    backup      rustiron "), "{text}");
        assert!(text.ends_with("Nothing was changed.\n"), "{text}");
    }

    #[test]
    fn the_built_in_matrix_reads_and_passes_the_reviewed_stack() {
        let built_in: Value = serde_json::from_str(SUPPORT_MATRIX).unwrap();
        let now = built_in["reviewed_unix"].as_u64().unwrap() + DAY;
        let mut host = healthy();
        host["machine"]["stack"]["php"] = json!(["8.4.27"]);
        let diagnosis = diagnose_with(&host, now, &built_in);
        assert_eq!(states(&diagnosis, "support"), ["ok"; 4], "{diagnosis:#}");
        assert_eq!(built_in["schema"], "rustiron-support-matrix/1");
    }

    #[test]
    fn unsupported_old_or_ending_versions_are_findings() {
        let mut host = healthy();
        host["machine"]["os"]["version"] = json!("9.6");
        host["machine"]["stack"]["openlitespeed"] = json!("1.9.3");
        host["machine"]["stack"]["php"] = json!(["8.3.9"]);
        host["machine"]["stack"]["mariadb"] = json!("11.4.2");
        let diagnosis = diagnose(&host, NOW);
        assert_eq!(
            states(&diagnosis, "support"),
            ["fail", "fail", "unknown", "fail"]
        );
        // A newer patch in the series is supported.
        let mut newer = healthy();
        newer["machine"]["stack"]["openlitespeed"] = json!("1.9.10");
        assert_eq!(states(&diagnose(&newer, NOW), "support"), ["ok"; 4]);
        // Near and past the end of life; an overdue review.
        assert_eq!(
            states(&diagnose(&healthy(), NOW + 300 * DAY), "support"),
            ["warn", "ok", "ok", "ok", "warn"]
        );
        assert_eq!(
            states(&diagnose(&healthy(), NOW + 550 * DAY), "support"),
            ["warn", "ok", "ok", "warn", "fail"]
        );
        // W562: PowerDNS only where it is installed.
        let mut with_dns = matrix();
        with_dns["components"].as_array_mut().unwrap().push(json!({
            "name": "powerdns", "label": "PowerDNS Authoritative", "series": "5.1",
            "minimum": "5.1.5", "end_of_life_unix": NOW + 500 * DAY, "when_installed": true}));
        assert_eq!(
            states(&diagnose_with(&healthy(), NOW, &with_dns), "support"),
            ["ok"; 4]
        );
        let mut dns_host = healthy();
        dns_host["machine"]["stack"]["powerdns"] = json!("5.1.5");
        assert_eq!(
            states(&diagnose_with(&dns_host, NOW, &with_dns), "support"),
            ["ok"; 5]
        );
        dns_host["machine"]["stack"]["powerdns"] = json!("5.0.7");
        assert_eq!(
            states(&diagnose_with(&dns_host, NOW, &with_dns), "support"),
            ["ok", "ok", "ok", "ok", "fail"]
        );
        // W651: Node.js and Bun optional runtimes are checked when installed.
        let mut with_runtimes = with_dns.clone();
        with_runtimes["components"]
            .as_array_mut()
            .unwrap()
            .push(json!({
            "name": "nodejs", "label": "Node.js", "series": "22",
            "minimum": "22.23.4", "end_of_life_unix": NOW + 500 * DAY, "when_installed": true}));
        with_runtimes["components"]
            .as_array_mut()
            .unwrap()
            .push(json!({
            "name": "bun", "label": "Bun", "series": "1",
            "minimum": "1.4.2", "end_of_life_unix": null, "when_installed": true}));
        let mut app_host = healthy();
        app_host["machine"]["stack"]["nodejs"] = json!("22.23.4");
        app_host["machine"]["stack"]["bun"] = json!("1.4.5");
        assert_eq!(
            states(&diagnose_with(&app_host, NOW, &with_runtimes), "support"),
            ["ok"; 6]
        );
        app_host["machine"]["stack"]["nodejs"] = json!("22.10.0");
        assert_eq!(
            states(&diagnose_with(&app_host, NOW, &with_runtimes), "support"),
            ["ok", "ok", "ok", "ok", "fail", "ok"]
        );
        let broken = diagnose_with(&healthy(), NOW, &Value::Null);
        assert_eq!(states(&broken, "support"), ["unknown"]);
    }

    #[test]
    fn w633_app_unit_confinement_diagnosis_checks_effective_hardening() {
        let mut host = healthy();
        // Weakened hardening (no network restriction) -> warn
        host["sites"] = json!([{
            "site_id": "app_weak",
            "hostname": "weak.example.test",
            "state": "succeeded",
            "app_runtime": "node_22_v1",
            "app_active_release": "rel_1",
            "app_unit": {
                "unit": "rustiron-app@rs_app_weak.service",
                "active_state": "active",
                "no_new_privileges": "yes",
                "protect_system": "strict",
                "ip_address_deny": null,
                "private_network": "no",
                "selinux_context": null
            }
        }]);
        assert_eq!(states(&diagnose(&host, NOW), "app"), ["warn"]);

        // Systemd fs + network hardening present without dedicated SELinux MCS -> ok with truthful wording
        host["sites"][0]["app_unit"]["ip_address_deny"] = json!("any");
        let d_no_mac = diagnose(&host, NOW);
        assert_eq!(states(&d_no_mac, "app"), ["ok"]);
        let reason_no_mac = d_no_mac["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["check"] == "app")
            .unwrap()["reason"]
            .as_str()
            .unwrap();
        assert!(reason_no_mac.contains("no dedicated SELinux MCS app domain"));

        // Full systemd (including real systemd CIDR expansion of IPAddressDeny=any)
        // + dedicated SELinux MCS context -> verified (W640-F1)
        host["sites"][0]["app_unit"]["ip_address_deny"] = json!("0.0.0.0/0 ::/0");
        host["sites"][0]["app_unit"]["selinux_context"] =
            json!("system_u:system_r:rustiron_app_t:s0:c205");
        let d_full = diagnose(&host, NOW);
        assert_eq!(states(&d_full, "app"), ["ok"]);
        let reason_full = d_full["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["check"] == "app")
            .unwrap()["reason"]
            .as_str()
            .unwrap();
        assert!(reason_full.contains("SELinux MCS confinement"));

        // Unconfined SELinux context must not claim SELinux MCS confinement
        host["sites"][0]["app_unit"]["selinux_context"] =
            json!("system_u:system_r:unconfined_service_t:s0");
        let d_unconfined = diagnose(&host, NOW);
        let reason_unconfined = d_unconfined["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["check"] == "app")
            .unwrap()["reason"]
            .as_str()
            .unwrap();
        assert!(reason_unconfined.contains("no dedicated SELinux MCS app domain"));
    }
}
