//! W615 (P24): Ownership-aware deep drift explanation over a merged host
//! observation. Strictly read-only: never resets, edits, or guesses ownership.
//! Distinguishes package updates, manual emergency edits, unknown/foreign
//! resources, and unreadable unprivileged checks, and maps each delta to
//! explicit operator choices (`adopt`, `restore_owned`, `ignore`, `eject`).

use rustiron_contracts::escape_human;
use serde_json::{Value, json};
use std::collections::BTreeSet;

/// Output schema for `rustiron-control --explain-drift`.
pub(crate) const SCHEMA: &str = "rustiron-drift-explanation/1";

struct Resolution {
    choice: &'static str,
    summary: &'static str,
    command_hint: &'static str,
    runbook: &'static str,
}

impl Resolution {
    fn json(&self) -> Value {
        json!({
            "choice": self.choice,
            "summary": self.summary,
            "command_hint": self.command_hint,
            "runbook": self.runbook,
            "preserves_foreign_state": true,
        })
    }
}

struct DriftDelta {
    resource_id: String,
    resource_kind: &'static str,
    ownership: &'static str,
    cause: &'static str,
    severity: &'static str,
    affected_resources: Vec<String>,
    consequences: &'static str,
    allowed_resolutions: Vec<Resolution>,
}

impl DriftDelta {
    fn json(&self) -> Value {
        json!({
            "resource_id": escape_human(&self.resource_id),
            "resource_kind": self.resource_kind,
            "ownership": self.ownership,
            "cause": self.cause,
            "severity": self.severity,
            "affected_resources": self.affected_resources.iter().map(|s| escape_human(s)).collect::<Vec<_>>(),
            "consequences": self.consequences,
            "allowed_resolutions": self.allowed_resolutions.iter().map(Resolution::json).collect::<Vec<_>>(),
        })
    }
}

/// Pure read-only drift explanation over a merged executor + host observation.
pub(crate) fn explain(merged: &Value) -> Value {
    let machine = &merged["machine"];
    let mut deltas = Vec::new();
    let served_sites = collect_managed_sites(merged);

    check_signature_verifier(merged, &mut deltas);
    check_ols_drift(merged, machine, &served_sites, &mut deltas);
    check_site_drift(merged, &mut deltas);
    check_firewall_drift(machine, &mut deltas);
    check_package_drift(machine, &mut deltas);
    check_unit_drift(machine, &mut deltas);

    let ejected_count = merged["sites"].as_array().map_or(0, |sites| {
        sites
            .iter()
            .filter(|s| s["ejected"].as_bool() == Some(true))
            .count()
    });

    let summary = if deltas.iter().any(|d| d.severity == "high") {
        "drift_blocks_mutations"
    } else if !deltas.is_empty() {
        "drift_observed"
    } else {
        "clean"
    };

    json!({
        "schema": SCHEMA,
        "observed_at": machine["observed_at"],
        "summary": summary,
        "auto_reset": false,
        "preserves_foreign_state": true,
        "ejected_sites_preserved": ejected_count,
        "delta_count": deltas.len(),
        "deltas": deltas.iter().map(DriftDelta::json).collect::<Vec<_>>(),
    })
}

fn collect_managed_sites(merged: &Value) -> Vec<String> {
    merged["sites"]
        .as_array()
        .map(|sites| {
            sites
                .iter()
                .filter(|s| s["ejected"].as_bool() != Some(true))
                .filter_map(|s| s["site_id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn known_hostnames(merged: &Value) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    if let Some(sites) = merged["sites"].as_array() {
        for site in sites {
            if let Some(host) = site["hostname"].as_str() {
                set.insert(host.to_ascii_lowercase());
            }
            if let Some(alias) = site["alias_hostname"].as_str() {
                set.insert(alias.to_ascii_lowercase());
            }
        }
    }
    set
}

fn check_signature_verifier(merged: &Value, out: &mut Vec<DriftDelta>) {
    let sv = &merged["host"]["signature_verifier"];
    if sv["matches"].as_bool() == Some(false) {
        let rpm_updated = merged["machine"]["packages"]["duplicate_count"].as_u64() == Some(0)
            || sv["package_verified"].as_bool() == Some(true);
        let cause = if rpm_updated {
            "package_update"
        } else {
            "manual_emergency_edit"
        };
        out.push(DriftDelta {
            resource_id: "ssh-keygen".to_owned(),
            resource_kind: "signature_verifier",
            ownership: "host_shared",
            cause,
            severity: "high",
            affected_resources: vec!["all_signed_admissions".to_owned()],
            consequences: "Executor refuses every new signed grant until the installed verifier digest is deliberately re-measured or restored.",
            allowed_resolutions: vec![
                Resolution {
                    choice: "adopt",
                    summary: "Verify the upgraded openssh-clients RPM and re-measure the verifier digest in host policy.",
                    command_hint: "sudo python3 packaging/enrollment-policy.py verifier",
                    runbook: "docs/operator/16-PRODUCT-UPDATE.md",
                },
                Resolution {
                    choice: "restore_owned",
                    summary: "Reinstall the expected openssh-clients package if the binary change was unintended.",
                    command_hint: "sudo dnf reinstall openssh-clients",
                    runbook: "docs/operator/16-PRODUCT-UPDATE.md",
                },
            ],
        });
    }
}

fn check_ols_drift(
    merged: &Value,
    machine: &Value,
    served_sites: &[String],
    out: &mut Vec<DriftDelta>,
) {
    let ols = &merged["ols"];
    let affected = if served_sites.is_empty() {
        vec!["ols_listener".to_owned()]
    } else {
        served_sites.to_vec()
    };

    if ols["parent_reviewed"].as_bool() == Some(false) {
        let pkg_changed =
            merged["host"]["packages"]["openlitespeed_changed"].as_bool() == Some(true);
        let cause = if pkg_changed {
            "package_update"
        } else {
            "manual_emergency_edit"
        };
        out.push(DriftDelta {
            resource_id: "httpd_config.conf".to_owned(),
            resource_kind: "ols_parent",
            ownership: "rustiron_owned",
            cause,
            severity: "high",
            affected_resources: affected.clone(),
            consequences: "Signed OLS activations refuse until the immutable parent configuration matches the reviewed digest.",
            allowed_resolutions: vec![
                Resolution {
                    choice: "restore_owned",
                    summary: "Restore the pinned Rustiron OLS parent configuration explicitly.",
                    command_hint: "See Runbook 14 (OLS parent restore)",
                    runbook: "docs/operator/14-OLS-UPGRADE.md",
                },
                Resolution {
                    choice: "adopt",
                    summary: "Review the diff and explicitly update the enrolled parent SHA-256.",
                    command_hint: "See Runbook 14 (OLS package upgrade)",
                    runbook: "docs/operator/14-OLS-UPGRADE.md",
                },
            ],
        });
    }

    if ols["explained_by_journal"].as_bool() == Some(false) || ols["clean"].as_bool() == Some(false)
    {
        out.push(DriftDelta {
            resource_id: ols["current"]
                .as_str()
                .unwrap_or("ols_current_generation")
                .to_owned(),
            resource_kind: "ols_generation",
            ownership: "rustiron_owned",
            cause: "manual_emergency_edit",
            severity: "high",
            affected_resources: affected,
            consequences: "Live OLS include differs from the last journaled generation; signed config_activate refuses without resetting the manual edit.",
            allowed_resolutions: vec![
                Resolution {
                    choice: "adopt",
                    summary: "Explicitly re-adopt the verified live OLS generation via signed site_readopt_generation.",
                    command_hint: "rustiron plan create site-readopt-generation ...",
                    runbook: "docs/operator/17-BREAK-GLASS.md",
                },
                Resolution {
                    choice: "restore_owned",
                    summary: "Apply a new signed config_activate plan to replace the emergency edit intentionally.",
                    command_hint: "rustiron plan create config-activate ...",
                    runbook: "docs/operator/17-BREAK-GLASS.md",
                },
                Resolution {
                    choice: "eject",
                    summary: "Eject an affected site if it will be managed manually outside Rustiron.",
                    command_hint: "rustiron plan create site-eject ...",
                    runbook: "docs/operator/12-UNINSTALL.md",
                },
            ],
        });
    }

    // Foreign / unknown vhosts present in live OLS map but absent from managed journal sites.
    if let Some(hosts) = machine["ols_map"]["hosts"].as_array() {
        let known = known_hostnames(merged);
        for host_val in hosts {
            let Some(host) = host_val.as_str() else {
                continue;
            };
            if !known.contains(&host.to_ascii_lowercase()) {
                out.push(DriftDelta {
                    resource_id: host.to_owned(),
                    resource_kind: "ols_vhost",
                    ownership: "foreign_unknown",
                    cause: "unknown_foreign_resource",
                    severity: "medium",
                    affected_resources: vec![host.to_owned()],
                    consequences: "Served by OpenLiteSpeed outside the Rustiron journal. Rustiron never guesses ownership or overwrites foreign vhosts.",
                    allowed_resolutions: vec![
                        Resolution {
                            choice: "ignore",
                            summary: "Leave this foreign vhost untouched; Rustiron preserves foreign state.",
                            command_hint: "No command required.",
                            runbook: "docs/operator/17-BREAK-GLASS.md",
                        },
                        Resolution {
                            choice: "adopt",
                            summary: "Import or explicitly re-adopt only if you intentionally transfer this site to Rustiron.",
                            command_hint: "rustiron plan create site-readopt ...",
                            runbook: "docs/operator/07-EPOCH-READOPTION.md",
                        },
                    ],
                });
            }
        }
    }
}

fn check_site_drift(merged: &Value, out: &mut Vec<DriftDelta>) {
    let Some(sites) = merged["sites"].as_array() else {
        return;
    };
    for site in sites {
        if site["ejected"].as_bool() == Some(true) {
            // Ejected sites belong to the operator; never flag as unexpected drift.
            continue;
        }
        let site_id = site["site_id"]
            .as_str()
            .unwrap_or("unknown_site")
            .to_owned();
        let state = site["state"].as_str().unwrap_or("unknown");
        if state == "quarantined" {
            out.push(DriftDelta {
                resource_id: site_id.clone(),
                resource_kind: "site_runtime",
                ownership: "rustiron_owned",
                cause: "manual_emergency_edit",
                severity: "high",
                affected_resources: vec![site_id],
                consequences: "Site is quarantined in the journal and excluded from live serving until scrubbed or retired.",
                allowed_resolutions: vec![Resolution {
                    choice: "restore_owned",
                    summary: "Inspect the failed operation and run the matching signed scrub or retire workflow.",
                    command_hint: "rustiron operation status <operation_id>",
                    runbook: "docs/operator/11-AFTER-POWER-LOSS.md",
                }],
            });
            continue;
        }
        let account_missing = site["host_account"].as_str() == Some("absent");
        let dir_missing = site["host_directory"].as_str() == Some("absent");
        if account_missing || dir_missing {
            out.push(DriftDelta {
                resource_id: site_id.clone(),
                resource_kind: "site_runtime",
                ownership: "rustiron_owned",
                cause: "manual_emergency_edit",
                severity: "high",
                affected_resources: vec![site_id],
                consequences: "Managed site account or site root is missing on disk; serving and backups cannot succeed.",
                allowed_resolutions: vec![
                    Resolution {
                        choice: "restore_owned",
                        summary: "Restore the site from a verified backup capture.",
                        command_hint: "See Runbook 26 (site restore)",
                        runbook: "docs/operator/26-SITE-RESTORE.md",
                    },
                    Resolution {
                        choice: "eject",
                        summary: "Explicitly eject or delete the site record if removal was intentional.",
                        command_hint: "See Runbook 25 (delete live site)",
                        runbook: "docs/operator/25-DELETE-LIVE-SITE.md",
                    },
                ],
            });
        }
    }
}

fn check_firewall_drift(machine: &Value, out: &mut Vec<DriftDelta>) {
    let fw = &machine["firewall"];
    if fw.is_null() {
        return;
    }
    if fw["readable"].as_bool() == Some(false) {
        out.push(DriftDelta {
            resource_id: "firewalld".to_owned(),
            resource_kind: "firewalld",
            ownership: "host_shared",
            cause: "unreadable_unprivileged",
            severity: "low",
            affected_resources: vec!["host_ingress".to_owned()],
            consequences: "Unprivileged observer cannot read firewalld zones; drift is unknown, never assumed clean.",
            allowed_resolutions: vec![
                Resolution {
                    choice: "restore_owned",
                    summary: "Verify the enrolled firewalld zone as root.",
                    command_hint: "sudo python3 packaging/firewall-zone.py --check",
                    runbook: "docs/operator/28-FIREWALL-ZONE.md",
                },
                Resolution {
                    choice: "ignore",
                    summary: "Keep unprivileged observation read-only without widening permissions.",
                    command_hint: "No command required.",
                    runbook: "docs/operator/28-FIREWALL-ZONE.md",
                },
            ],
        });
        return;
    }
    if let Some(zone) = fw["default_zone"].as_str()
        && zone != "rustiron"
    {
        out.push(DriftDelta {
            resource_id: format!("firewalld:{zone}"),
            resource_kind: "firewalld",
            ownership: "foreign_unknown",
            cause: "manual_emergency_edit",
            severity: "medium",
            affected_resources: vec!["host_ingress".to_owned()],
            consequences: "Active default firewalld zone is not the enrolled `rustiron` zone; exposed ports may diverge from policy.",
            allowed_resolutions: vec![
                Resolution {
                    choice: "restore_owned",
                    summary: "Check diff and apply the enrolled `rustiron` zone explicitly without dropping SSH.",
                    command_hint: "sudo python3 packaging/firewall-zone.py --apply",
                    runbook: "docs/operator/28-FIREWALL-ZONE.md",
                },
                Resolution {
                    choice: "ignore",
                    summary: "Retain the operator-managed firewall zone explicitly.",
                    command_hint: "No command required.",
                    runbook: "docs/operator/28-FIREWALL-ZONE.md",
                },
            ],
        });
    }
}

fn check_package_drift(machine: &Value, out: &mut Vec<DriftDelta>) {
    let dups = machine["packages"]["duplicate_count"].as_u64().unwrap_or(0);
    if dups > 0 {
        out.push(DriftDelta {
            resource_id: "rpm_database".to_owned(),
            resource_kind: "package_pin",
            ownership: "host_shared",
            cause: "package_update",
            severity: "high",
            affected_resources: vec!["os_packages".to_owned()],
            consequences: "Duplicate RPM packages indicate an interrupted package update (W484); PHP or OLS binaries may mismatch.",
            allowed_resolutions: vec![Resolution {
                choice: "restore_owned",
                summary: "Run forward repair via dnf to remove duplicate packages and synchronize versions.",
                command_hint: "sudo dnf remove --duplicates && sudo dnf distro-sync",
                runbook: "docs/operator/16-PRODUCT-UPDATE.md",
            }],
        });
    }
}

fn check_unit_drift(machine: &Value, out: &mut Vec<DriftDelta>) {
    let Some(units) = machine["failed_units"]["units"].as_array() else {
        return;
    };
    for unit_val in units {
        let Some(unit) = unit_val.as_str() else {
            continue;
        };
        let is_rustiron = unit.starts_with("rustiron-") || unit == "lshttpd.service";
        if is_rustiron {
            out.push(DriftDelta {
                resource_id: unit.to_owned(),
                resource_kind: "systemd_unit",
                ownership: "rustiron_owned",
                cause: "manual_emergency_edit",
                severity: "high",
                affected_resources: vec![unit.to_owned()],
                consequences: "Managed unit is in failed state; affected site or control-plane capability is degraded.",
                allowed_resolutions: vec![Resolution {
                    choice: "restore_owned",
                    summary: "Inspect journald logs and restart the managed unit explicitly.",
                    command_hint: "sudo journalctl -u <unit> -n 50 && sudo systemctl restart <unit>",
                    runbook: "docs/operator/11-AFTER-POWER-LOSS.md",
                }],
            });
        } else {
            out.push(DriftDelta {
                resource_id: unit.to_owned(),
                resource_kind: "systemd_unit",
                ownership: "foreign_unknown",
                cause: "unknown_foreign_resource",
                severity: "low",
                affected_resources: vec![unit.to_owned()],
                consequences: "Foreign host systemd unit failed; Rustiron never restarts or modifies unmanaged host services.",
                allowed_resolutions: vec![Resolution {
                    choice: "ignore",
                    summary: "Handle this unmanaged host service outside Rustiron; foreign state is preserved.",
                    command_hint: "sudo systemctl status <unit>",
                    runbook: "docs/operator/17-BREAK-GLASS.md",
                }],
            });
        }
    }
}

/// Renders one concise redacted block per drift delta for terminal review.
pub(crate) fn human(report: &Value) -> String {
    let summary = report["summary"].as_str().unwrap_or("unknown");
    let count = report["delta_count"].as_u64().unwrap_or(0);
    let ejected = report["ejected_sites_preserved"].as_u64().unwrap_or(0);
    let mut out = format!(
        "drift summary: {summary} ({count} delta(s); auto_reset=false; ejected_preserved={ejected})\n"
    );
    if let Some(deltas) = report["deltas"].as_array() {
        for delta in deltas {
            let rid = delta["resource_id"].as_str().unwrap_or("?");
            let kind = delta["resource_kind"].as_str().unwrap_or("?");
            let own = delta["ownership"].as_str().unwrap_or("?");
            let cause = delta["cause"].as_str().unwrap_or("?");
            let cons = delta["consequences"].as_str().unwrap_or("");
            let choices: Vec<&str> = delta["allowed_resolutions"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|r| r["choice"].as_str())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            out.push_str(&format!(
                "- [{kind}] {rid} (owner={own}, cause={cause}) choices=[{}] — {cons}\n",
                choices.join(",")
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_observation_reports_zero_deltas_and_preserves_ejected_sites() {
        let merged = json!({
            "host": { "signature_verifier": { "matches": true } },
            "ols": { "parent_reviewed": true, "explained_by_journal": true, "clean": true, "current": "gen_1" },
            "sites": [
                { "site_id": "cp02", "hostname": "cp02.example.test", "state": "succeeded", "ejected": false, "host_account": "present", "host_directory": "present" },
                { "site_id": "ej01", "hostname": "ej01.example.test", "state": "succeeded", "ejected": true, "host_account": "absent", "host_directory": "absent" }
            ],
            "machine": {
                "observed_at": 1_795_500_000,
                "firewall": { "readable": true, "default_zone": "rustiron" },
                "ols_map": { "readable": true, "hosts": ["cp02.example.test", "ej01.example.test"] },
                "packages": { "duplicate_count": 0 },
                "failed_units": { "readable": true, "units": [] }
            }
        });
        let report = explain(&merged);
        assert_eq!(report["summary"], "clean");
        assert_eq!(report["auto_reset"], false);
        assert_eq!(report["preserves_foreign_state"], true);
        assert_eq!(report["ejected_sites_preserved"], 1);
        assert_eq!(report["delta_count"], 0);
    }

    #[test]
    fn distinguishes_package_update_manual_edit_and_foreign_resources() {
        let merged = json!({
            "host": {
                "signature_verifier": { "matches": false, "package_verified": true },
                "packages": { "openlitespeed_changed": false }
            },
            "ols": { "parent_reviewed": false, "explained_by_journal": false, "clean": false, "current": "gen_breakglass" },
            "sites": [
                { "site_id": "cp02", "hostname": "cp02.example.test", "state": "succeeded", "ejected": false }
            ],
            "machine": {
                "observed_at": 1_795_500_000,
                "firewall": { "readable": true, "default_zone": "public" },
                "ols_map": { "readable": true, "hosts": ["cp02.example.test", "foreign-blog.example.test"] },
                "packages": { "duplicate_count": 2 },
                "failed_units": { "readable": true, "units": ["custom-backup.service", "rustiron-site-cron.service"] }
            }
        });
        let report = explain(&merged);
        assert_eq!(report["summary"], "drift_blocks_mutations");
        assert_eq!(report["auto_reset"], false);
        let deltas = report["deltas"].as_array().unwrap();

        // 1. Verifier change classified as package_update
        let sv = deltas
            .iter()
            .find(|d| d["resource_kind"] == "signature_verifier")
            .unwrap();
        assert_eq!(sv["cause"], "package_update");

        // 2. Break-glass OLS edit classified as manual_emergency_edit affecting cp02
        let ols_gen = deltas
            .iter()
            .find(|d| d["resource_kind"] == "ols_generation")
            .unwrap();
        assert_eq!(ols_gen["cause"], "manual_emergency_edit");
        assert_eq!(ols_gen["affected_resources"], json!(["cp02"]));

        // 3. Foreign vhost classified as foreign_unknown / unknown_foreign_resource; NEVER offers restore_owned
        let foreign = deltas
            .iter()
            .find(|d| d["resource_id"] == "foreign-blog.example.test")
            .unwrap();
        assert_eq!(foreign["ownership"], "foreign_unknown");
        assert_eq!(foreign["cause"], "unknown_foreign_resource");
        let foreign_choices: Vec<&str> = foreign["allowed_resolutions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|r| r["choice"].as_str())
            .collect();
        assert!(foreign_choices.contains(&"ignore"));
        assert!(!foreign_choices.contains(&"restore_owned"));

        // 4. Foreign failed unit never offers restore_owned
        let foreign_unit = deltas
            .iter()
            .find(|d| d["resource_id"] == "custom-backup.service")
            .unwrap();
        assert_eq!(foreign_unit["ownership"], "foreign_unknown");
        assert_eq!(foreign_unit["allowed_resolutions"][0]["choice"], "ignore");

        // 5. Duplicate RPMs classified as package_update
        let pkg = deltas
            .iter()
            .find(|d| d["resource_kind"] == "package_pin")
            .unwrap();
        assert_eq!(pkg["cause"], "package_update");

        let rendered = human(&report);
        assert!(rendered.contains("auto_reset=false"));
        assert!(rendered.contains("foreign-blog.example.test"));
    }
}
