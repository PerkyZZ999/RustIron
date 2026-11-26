//! W623 (CP07 Slice 1): Post-v1.0 multi-tenant delegation ACL, quota,
//! ownership-transfer, and cross-account isolation verifier. Strictly
//! read-only: enforces separate tenancy boundaries and refuses cross-tenant
//! escalation, quota over-allocation, arbitrary service control, and built-in
//! billing-engine creep.

use rustiron_contracts::escape_human;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// Output schema for `rustiron-control --verify-delegation`.
pub(crate) const SCHEMA: &str = "rustiron-delegation-check/1";
/// Expected input schema.
pub(crate) const INPUT_SCHEMA: &str = "rustiron-delegation-policy/1";

const ALLOWED_ROLES: [&str; 3] = ["admin", "reseller", "tenant_user"];
const ALLOWED_TENANT_SERVICES: [&str; 3] = ["site_php_restart", "app_restart", "site_cron_trigger"];

/// Verifies a CP07 delegation & tenancy policy document.
pub(crate) fn verify(doc: &Value) -> Value {
    if doc["schema"].as_str() != Some(INPUT_SCHEMA) {
        return refused(
            "INVALID_SCHEMA",
            "Input schema must be rustiron-delegation-policy/1.",
        );
    }

    if doc["built_in_billing_engine"].as_bool() == Some(true) {
        return refused(
            "BILLING_ENGINE_FORBIDDEN",
            "CP07 inventories external billing integrations only; built-in billing engines are out of scope.",
        );
    }

    let host_disk_budget_mib = doc["host_disk_budget_mib"].as_u64().unwrap_or(0);
    if host_disk_budget_mib == 0 {
        return refused(
            "MISSING_HOST_BUDGET",
            "Explicit host_disk_budget_mib > 0 is required.",
        );
    }

    let Some(accounts) = doc["accounts"].as_array() else {
        return refused("INVALID_ACCOUNTS", "accounts array is required.");
    };
    let Some(sites) = doc["sites"].as_array() else {
        return refused("INVALID_SITES", "sites array is required.");
    };

    let mut failures = Vec::new();
    let mut role_by_account: BTreeMap<String, String> = BTreeMap::new();
    let mut quota_by_account: BTreeMap<String, u64> = BTreeMap::new();
    let mut parent_by_account: BTreeMap<String, Option<String>> = BTreeMap::new();

    for acc in accounts {
        let id = acc["account_id"].as_str().unwrap_or("");
        let role = acc["role"].as_str().unwrap_or("");
        let quota = acc["disk_quota_mib"].as_u64().unwrap_or(0);
        let parent = acc["parent_reseller_id"].as_str().map(str::to_owned);

        if id.is_empty() || role_by_account.contains_key(id) {
            failures.push(format!(
                "INVALID_ACCOUNT_ID: account_id `{}` missing or duplicated.",
                escape_human(id)
            ));
            continue;
        }
        if !ALLOWED_ROLES.contains(&role) {
            failures.push(format!(
                "UNKNOWN_ROLE: account `{}` has unsupported role `{}`.",
                escape_human(id),
                escape_human(role)
            ));
            continue;
        }
        if acc["root_shell_allowed"].as_bool() == Some(true)
            || acc["arbitrary_systemd_control"].as_bool() == Some(true)
        {
            failures.push(format!(
                "PRIVILEGE_ESCALATION_REFUSED: account `{}` cannot hold root shell or arbitrary systemd control.",
                escape_human(id)
            ));
        }
        if role != "admin"
            && let Some(controls) = acc["allowed_service_controls"].as_array()
        {
            for ctrl in controls {
                let c = ctrl.as_str().unwrap_or("");
                if !ALLOWED_TENANT_SERVICES.contains(&c) {
                    failures.push(format!(
                        "UNBOUNDED_SERVICE_CONTROL: account `{}` requested disallowed service control `{}`.",
                        escape_human(id),
                        escape_human(c)
                    ));
                }
            }
        }
        role_by_account.insert(id.to_owned(), role.to_owned());
        quota_by_account.insert(id.to_owned(), quota);
        parent_by_account.insert(id.to_owned(), parent);
    }

    // Check reseller sub-account quota totals do not exceed reseller package quota.
    let mut reseller_allocated: BTreeMap<String, u64> = BTreeMap::new();
    for (acc_id, parent) in &parent_by_account {
        if let Some(parent_id) = parent {
            if role_by_account.get(parent_id).map(String::as_str) != Some("reseller") {
                failures.push(format!(
                    "INVALID_RESELLER_PARENT: account `{}` references non-reseller parent `{}`.",
                    escape_human(acc_id),
                    escape_human(parent_id)
                ));
            } else {
                let q = quota_by_account.get(acc_id).copied().unwrap_or(0);
                *reseller_allocated.entry(parent_id.clone()).or_default() += q;
            }
        }
    }
    for (reseller_id, used) in &reseller_allocated {
        let cap = quota_by_account.get(reseller_id).copied().unwrap_or(0);
        if *used > cap {
            failures.push(format!(
                "QUOTA_OVERALLOCATION: reseller `{}` sub-accounts allocate {used} MiB exceeding package quota {cap} MiB.",
                escape_human(reseller_id)
            ));
        }
    }

    // Check sites: unique site ownership, unique Unix UID, site quota within owner quota, and total within host budget.
    let mut seen_sites = BTreeSet::new();
    let mut seen_uids = BTreeSet::new();
    let mut owner_site_quota: BTreeMap<String, u64> = BTreeMap::new();
    let mut total_site_disk_mib = 0_u64;

    for site in sites {
        let site_id = site["site_id"].as_str().unwrap_or("");
        let owner = site["owner_account_id"].as_str().unwrap_or("");
        let uid = site["unix_uid"].as_u64();
        let disk = site["disk_quota_mib"].as_u64().unwrap_or(0);

        if site_id.is_empty() || !seen_sites.insert(site_id.to_owned()) {
            failures.push(format!(
                "INVALID_SITE_ID: site_id `{}` missing or duplicated.",
                escape_human(site_id)
            ));
            continue;
        }
        if !role_by_account.contains_key(owner) {
            failures.push(format!(
                "UNKNOWN_SITE_OWNER: site `{}` references unknown owner `{}`.",
                escape_human(site_id),
                escape_human(owner)
            ));
            continue;
        }
        if uid.is_none_or(|u| u < 1000 || !seen_uids.insert(u)) {
            failures.push(format!(
                "TENANCY_ISOLATION_VIOLATION: site `{}` lacks a unique non-root unix_uid.",
                escape_human(site_id)
            ));
        }
        *owner_site_quota.entry(owner.to_owned()).or_default() += disk;
        total_site_disk_mib = total_site_disk_mib.saturating_add(disk);
    }

    for (owner, used) in &owner_site_quota {
        let cap = quota_by_account.get(owner).copied().unwrap_or(0);
        if cap > 0 && *used > cap {
            failures.push(format!(
                "QUOTA_OVERALLOCATION: account `{}` sites sum to {used} MiB exceeding account quota {cap} MiB.",
                escape_human(owner)
            ));
        }
    }
    if total_site_disk_mib > host_disk_budget_mib {
        failures.push(format!(
            "QUOTA_OVERALLOCATION: total site disk quotas ({total_site_disk_mib} MiB) exceed host_disk_budget_mib ({host_disk_budget_mib} MiB)."
        ));
    }

    // Check cross-account access probes (adversarial denial checks)
    let mut access_results = Vec::new();
    if let Some(checks) = doc["access_checks"].as_array() {
        for chk in checks {
            let actor = chk["actor_account_id"].as_str().unwrap_or("");
            let target_site = chk["target_site_id"].as_str().unwrap_or("");
            let action = chk["action"].as_str().unwrap_or("");
            let allowed = check_access(
                actor,
                target_site,
                action,
                &role_by_account,
                &parent_by_account,
                sites,
            );
            let expect_deny = chk["expect_denied"].as_bool() == Some(true);
            if expect_deny && allowed {
                failures.push(format!(
                    "CROSS_TENANT_ACCESS_LEAK: actor `{}` was unexpectedly permitted `{}` on `{}`.",
                    escape_human(actor),
                    escape_human(action),
                    escape_human(target_site)
                ));
            }
            access_results.push(json!({
                "actor_account_id": escape_human(actor),
                "target_site_id": escape_human(target_site),
                "action": escape_human(action),
                "allowed": allowed,
            }));
        }
    }

    // Check ownership transfers require explicit dual approval (current owner + admin/target)
    if let Some(transfers) = doc["ownership_transfers"].as_array() {
        for tr in transfers {
            let site_id = tr["site_id"].as_str().unwrap_or("");
            let from_ok = tr["current_owner_approved"].as_bool() == Some(true);
            let admin_ok = tr["admin_signed_grant_present"].as_bool() == Some(true);
            if !from_ok || !admin_ok {
                failures.push(format!(
                    "UNAPPROVED_OWNERSHIP_TRANSFER: transfer for site `{}` requires both current_owner_approved and admin_signed_grant_present.",
                    escape_human(site_id)
                ));
            }
        }
    }

    let passed = failures.is_empty();
    json!({
        "schema": SCHEMA,
        "passed": passed,
        "separate_tenancy_enforced": true,
        "built_in_billing_engine": false,
        "root_shell_delegation_allowed": false,
        "host_disk_budget_mib": host_disk_budget_mib,
        "total_site_disk_mib": total_site_disk_mib,
        "account_count": role_by_account.len(),
        "site_count": seen_sites.len(),
        "access_results": access_results,
        "failure_count": failures.len(),
        "failures": failures,
    })
}

fn check_access(
    actor: &str,
    target_site: &str,
    action: &str,
    roles: &BTreeMap<String, String>,
    parents: &BTreeMap<String, Option<String>>,
    sites: &[Value],
) -> bool {
    let Some(actor_role) = roles.get(actor).map(String::as_str) else {
        return false;
    };
    let Some(site) = sites
        .iter()
        .find(|s| s["site_id"].as_str() == Some(target_site))
    else {
        return false;
    };
    let owner = site["owner_account_id"].as_str().unwrap_or("");
    if actor_role == "admin" {
        return true;
    }
    if actor == owner {
        return matches!(
            action,
            "inspect" | "site_php_restart" | "app_restart" | "site_cron_trigger"
        );
    }
    if actor_role == "reseller" {
        return parents
            .get(owner)
            .and_then(|p| p.as_deref())
            .is_some_and(|parent| parent == actor)
            && matches!(action, "inspect" | "site_php_restart" | "app_restart");
    }
    false
}

fn refused(code: &'static str, reason: &'static str) -> Value {
    json!({
        "schema": SCHEMA,
        "passed": false,
        "separate_tenancy_enforced": true,
        "built_in_billing_engine": false,
        "root_shell_delegation_allowed": false,
        "failure_count": 1,
        "failures": [format!("{code}: {reason}")],
    })
}

/// Concise human-readable operator summary for CP07 delegation verification.
pub(crate) fn human(report: &Value) -> String {
    let passed = report["passed"].as_bool().unwrap_or(false);
    let fails = report["failure_count"].as_u64().unwrap_or(0);
    let accounts = report["account_count"].as_u64().unwrap_or(0);
    let sites = report["site_count"].as_u64().unwrap_or(0);
    let mut out = format!(
        "Rustiron delegation check (CP07): passed={passed} failures={fails} accounts={accounts} sites={sites} billing_engine=false\n"
    );
    if let Some(items) = report["failures"].as_array() {
        for f in items {
            if let Some(s) = f.as_str() {
                out.push_str(&format!("  [FAIL] {s}\n"));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_policy() -> Value {
        json!({
            "schema": INPUT_SCHEMA,
            "built_in_billing_engine": false,
            "host_disk_budget_mib": 20_000,
            "accounts": [
                { "account_id": "owner_admin", "role": "admin", "disk_quota_mib": 20_000 },
                { "account_id": "res_a", "role": "reseller", "disk_quota_mib": 8_000, "allowed_service_controls": ["site_php_restart"] },
                { "account_id": "tenant_1", "role": "tenant_user", "parent_reseller_id": "res_a", "disk_quota_mib": 4_000, "allowed_service_controls": ["site_php_restart", "site_cron_trigger"] },
                { "account_id": "tenant_2", "role": "tenant_user", "parent_reseller_id": "res_a", "disk_quota_mib": 4_000, "allowed_service_controls": ["site_php_restart"] }
            ],
            "sites": [
                { "site_id": "s1", "owner_account_id": "tenant_1", "unix_uid": 3001, "disk_quota_mib": 2_000 },
                { "site_id": "s2", "owner_account_id": "tenant_2", "unix_uid": 3002, "disk_quota_mib": 2_000 }
            ],
            "access_checks": [
                { "actor_account_id": "tenant_1", "target_site_id": "s1", "action": "site_php_restart", "expect_denied": false },
                { "actor_account_id": "tenant_1", "target_site_id": "s2", "action": "inspect", "expect_denied": true },
                { "actor_account_id": "res_a", "target_site_id": "s1", "action": "inspect", "expect_denied": false }
            ],
            "ownership_transfers": [
                { "site_id": "s1", "current_owner_approved": true, "admin_signed_grant_present": true }
            ]
        })
    }

    #[test]
    fn enforces_tenancy_quotas_and_cross_account_denials() {
        let rep = verify(&valid_policy());
        assert_eq!(rep["passed"], true);
        assert_eq!(rep["built_in_billing_engine"], false);
        assert_eq!(rep["access_results"][0]["allowed"], true);
        assert_eq!(rep["access_results"][1]["allowed"], false);
        assert_eq!(rep["access_results"][2]["allowed"], true);
    }

    #[test]
    fn refuses_billing_engine_overallocation_and_unbounded_service_control() {
        let mut p = valid_policy();
        p["accounts"][2]["disk_quota_mib"] = json!(6_000); // 6000 + 4000 > reseller 8000
        p["accounts"][2]["allowed_service_controls"] = json!(["systemctl_restart_mariadb"]);
        p["ownership_transfers"][0]["admin_signed_grant_present"] = json!(false);
        let rep = verify(&p);
        assert_eq!(rep["passed"], false);
        let text = rep["failures"].to_string();
        assert!(text.contains("QUOTA_OVERALLOCATION"));
        assert!(text.contains("UNBOUNDED_SERVICE_CONTROL"));
        assert!(text.contains("UNAPPROVED_OWNERSHIP_TRANSFER"));

        let mut bill = valid_policy();
        bill["built_in_billing_engine"] = json!(true);
        assert_eq!(verify(&bill)["passed"], false);
    }
}
