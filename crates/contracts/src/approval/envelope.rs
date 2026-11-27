//! P23 (D-098): operator-visible blast-radius envelopes and durable authority
//! budget checks.
//!
//! Every closed operation plan maps deterministically to a [`BlastRadiusEnvelope`]
//! describing its site, change, reload, time, resource, and privilege budgets,
//! including an explicit explanation whenever an operation triggers a global
//! OpenLiteSpeed reload affecting all served sites.
//!
//! Enrolled [`BlastRadiusLimits`] are enforced durably by the executor against
//! the SQLite journal before any new intent is committed (never dashboard-only,
//! never replacing exact per-operation human approval).

use serde::{Deserialize, Serialize};

use super::{
    AppDeployPlan, AppLifecyclePlan, AppProvisionPlan, CapturePlan, CertificatePlan,
    CloneScrubPlan, CredentialRotatePlan, DeletePlan, DnsChangePlan, DnsImportPlan, EjectPlan,
    FixturePlan, ImportPlan, OlsPlan, PlanKind, ProbePlan, ProductBackupPlan, ProductBackupTarget,
    ProxyPlan, QuotaPlan, ReadoptPlan, RestorePlan, RestoreScope, RetirePlan, ScrubPlan,
    SiteClonePlan, SitePlan, SiteUpdatePlan, StandingCapturePlan,
};

/// Human- and agent-visible policy explanation of OpenLiteSpeed reload scope.
pub const ALL_SITE_OLS_IMPACT_EXPLANATION: &str = "Global OLS reload: affects every served site on the enrolled listener(s), not only the changed site; failure restores the predecessor generation with at most 1 bounded compensation reload.";

/// Blast-radius scope category of a closed operation plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpactScope {
    /// Changes only one named site (account, files, database, certificate, or quota).
    SingleSite,
    /// Renders and reloads the shared OLS listener generation, affecting every served site.
    AllServedSitesOlsReload,
    /// Imports or modifies record sets inside one owned PowerDNS zone.
    SingleZoneDns,
    /// Verifies and records ownership of existing host state without mutating traffic.
    HostReadopt,
    /// Mutates one synthetic fixture registry resource (lab only).
    FixtureResource,
}

/// Complete operator-visible blast-radius envelope of one closed plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlastRadiusEnvelope {
    /// Operation verb (`config_activate`, `site_provision`, etc.).
    pub verb: String,
    /// Scope category.
    pub scope: ImpactScope,
    /// Exact count of sites explicitly named by the plan.
    pub sites_named: u64,
    /// True when the operation reloads OLS across all served sites.
    pub all_served_sites: bool,
    /// Maximum normal OLS reloads authorized by this plan (0 or 1).
    pub ols_reloads: u64,
    /// Maximum bounded compensation reloads on failure (0 or 1).
    pub compensation_reloads: u64,
    /// Maximum distinct resource/component/record changes in this plan.
    pub max_changes: u64,
    /// Maximum operations authorized by a matching grant.
    pub max_operations: u64,
    /// Signed validity window (`expires_at - valid_from`) in seconds, when present.
    pub time_window_seconds: Option<u64>,
    /// Bounded resource limits (signed quota, file/dump caps, or worker bounds).
    pub resource_budget: String,
    /// Privilege boundary exercised by the executor and its helpers.
    pub privilege_boundary: String,
    /// Explicit all-site OLS impact warning when `all_served_sites` is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub all_site_ols_impact: Option<String>,
}

impl BlastRadiusEnvelope {
    /// Compact single-line summary for `rustiron-plan inspect`.
    pub fn summary_line(&self) -> String {
        let sites = if self.all_served_sites {
            format!("all served sites ({} named)", self.sites_named)
        } else {
            format!("{} site(s)", self.sites_named)
        };
        let time = self
            .time_window_seconds
            .map_or_else(|| "bounded".to_owned(), |s| format!("{s}s window"));
        format!(
            "scope {:?}; {sites}; changes {}; OLS reloads {} (+{} comp); {time}; resources: {}; privilege: {}",
            self.scope,
            self.max_changes,
            self.ols_reloads,
            self.compensation_reloads,
            self.resource_budget,
            self.privilege_boundary
        )
    }
}

/// Enrolled host blast-radius policy limits (`policy.json` `blast_radius` section).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlastRadiusLimits {
    /// Rolling enforcement window in seconds (60..=86400).
    pub window_seconds: u64,
    /// Maximum new admissions in the rolling window (1..=1000).
    pub max_admissions_per_window: u64,
    /// Maximum all-site OLS reloads (`config_activate` + `site_eject`) in the window (1..=64).
    pub max_ols_reloads_per_window: u64,
    /// Maximum served sites in one `config_activate` plan (1..=32).
    pub max_served_sites_per_activation: u64,
    /// Optional hard epoch ceiling on total admissions (1..=10000).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_admissions: Option<u64>,
    /// Optional hard epoch ceiling on total all-site OLS reloads (1..=1000).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_ols_reloads: Option<u64>,
}

impl BlastRadiusLimits {
    /// Validates every bound strictly.
    pub fn valid(&self) -> bool {
        (60..=86_400).contains(&self.window_seconds)
            && (1..=1000).contains(&self.max_admissions_per_window)
            && (1..=64).contains(&self.max_ols_reloads_per_window)
            && (1..=32).contains(&self.max_served_sites_per_activation)
            && self
                .max_total_admissions
                .is_none_or(|max| (1..=10_000).contains(&max))
            && self
                .max_total_ols_reloads
                .is_none_or(|max| (1..=1000).contains(&max))
    }
}

/// Durable authority consumption read from the SQLite journal.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityUsage {
    /// Total admitted operations recorded in this host epoch.
    pub total_admissions: u64,
    /// Total all-site OLS reload operations (`config_activate` + `site_eject`) in this epoch.
    pub total_ols_reloads: u64,
    /// Admitted operations active within the configured rolling window.
    pub recent_admissions: u64,
    /// All-site OLS reload operations active within the configured rolling window.
    pub recent_ols_reloads: u64,
    /// Owned, non-ejected sites currently tracked in the journal.
    pub served_sites: u64,
}

/// Remaining authority derived from enrolled [`BlastRadiusLimits`] and durable [`AuthorityUsage`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRemaining {
    /// Remaining admissions in the current rolling window.
    pub recent_admissions: u64,
    /// Remaining all-site OLS reloads in the current rolling window.
    pub recent_ols_reloads: u64,
    /// Remaining total admissions in this epoch, when a hard total cap is enrolled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_admissions: Option<u64>,
    /// Remaining total OLS reloads in this epoch, when a hard total cap is enrolled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_ols_reloads: Option<u64>,
}

/// Durable authority-budget report exposed in `Executor::observe`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityBudgetReport {
    /// True when `blast_radius` limits are enrolled in `policy.json`.
    pub enrolled: bool,
    /// Explicit explanation of global OLS reload impact.
    pub all_site_ols_impact: String,
    /// Enrolled limits, or `null` when no blast-radius envelope policy is enrolled.
    pub limits: Option<BlastRadiusLimits>,
    /// Durable consumption read from SQLite.
    pub consumed: AuthorityUsage,
    /// Exact remaining authority, or `null` when no limits are enrolled.
    pub remaining: Option<AuthorityRemaining>,
}

impl AuthorityBudgetReport {
    /// Builds a truthful report from optional policy limits and durable journal counts.
    pub fn build(limits: Option<BlastRadiusLimits>, consumed: AuthorityUsage) -> Self {
        let remaining = limits.as_ref().map(|cap| AuthorityRemaining {
            recent_admissions: cap
                .max_admissions_per_window
                .saturating_sub(consumed.recent_admissions),
            recent_ols_reloads: cap
                .max_ols_reloads_per_window
                .saturating_sub(consumed.recent_ols_reloads),
            total_admissions: cap
                .max_total_admissions
                .map(|max| max.saturating_sub(consumed.total_admissions)),
            total_ols_reloads: cap
                .max_total_ols_reloads
                .map(|max| max.saturating_sub(consumed.total_ols_reloads)),
        });
        Self {
            enrolled: limits.is_some(),
            all_site_ols_impact: ALL_SITE_OLS_IMPACT_EXPLANATION.to_owned(),
            limits,
            consumed,
            remaining,
        }
    }
}

/// Reason a plan violates the enrolled [`BlastRadiusLimits`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeRefusal {
    /// `config_activate` names more sites than `max_served_sites_per_activation`.
    TooManyServedSites,
    /// Rolling-window admission budget is exhausted.
    AdmissionWindowExhausted,
    /// Rolling-window all-site OLS reload budget is exhausted.
    OlsReloadWindowExhausted,
    /// Hard epoch total admission ceiling is exhausted.
    AdmissionTotalExhausted,
    /// Hard epoch total OLS reload ceiling is exhausted.
    OlsReloadTotalExhausted,
}

/// Pure durable budget check run by the executor before recording any new intent.
pub fn check_envelope_budget(
    limits: &BlastRadiusLimits,
    envelope: &BlastRadiusEnvelope,
    usage: &AuthorityUsage,
) -> Result<(), EnvelopeRefusal> {
    if envelope.verb == "config_activate"
        && envelope.sites_named > limits.max_served_sites_per_activation
    {
        return Err(EnvelopeRefusal::TooManyServedSites);
    }
    if usage.recent_admissions >= limits.max_admissions_per_window {
        return Err(EnvelopeRefusal::AdmissionWindowExhausted);
    }
    if let Some(max_total) = limits.max_total_admissions
        && usage.total_admissions >= max_total
    {
        return Err(EnvelopeRefusal::AdmissionTotalExhausted);
    }
    if envelope.ols_reloads > 0 {
        if usage.recent_ols_reloads >= limits.max_ols_reloads_per_window {
            return Err(EnvelopeRefusal::OlsReloadWindowExhausted);
        }
        if let Some(max_reloads) = limits.max_total_ols_reloads
            && usage.total_ols_reloads >= max_reloads
        {
            return Err(EnvelopeRefusal::OlsReloadTotalExhausted);
        }
    }
    Ok(())
}

/// Extracts `valid_from` and `expires_at` from an already-validated closed plan JSON.
pub fn plan_window_bounds(bytes: &[u8]) -> Option<(u64, u64)> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let valid_from = value.get("valid_from")?.as_u64()?;
    let expires_at = value.get("expires_at")?.as_u64()?;
    (expires_at >= valid_from).then_some((valid_from, expires_at))
}

/// Decodes any closed Rustiron operation plan and returns its deterministic
/// [`BlastRadiusEnvelope`], or `None` if `bytes` is not a valid closed plan.
pub fn envelope_for_plan(bytes: &[u8]) -> Option<BlastRadiusEnvelope> {
    let time_window_seconds = plan_window_bounds(bytes).map(|(from, until)| until - from);

    if let Ok(plan) = OlsPlan::decode(bytes) {
        let sites_named = plan.site_ids().len() as u64;
        return Some(BlastRadiusEnvelope {
            verb: "config_activate".to_owned(),
            scope: ImpactScope::AllServedSitesOlsReload,
            sites_named,
            all_served_sites: true,
            ols_reloads: 1,
            compensation_reloads: 1,
            max_changes: 1,
            max_operations: 1,
            time_window_seconds,
            resource_budget: format!(
                "1 listener generation covering {sites_named} named managed site(s) plus adopted/ejected sites"
            ),
            privilege_boundary:
                "executor + admin_helper (root OLS config generation, reload, and all-site probes)"
                    .to_owned(),
            all_site_ols_impact: Some(ALL_SITE_OLS_IMPACT_EXPLANATION.to_owned()),
        });
    }
    if let Ok(plan) = EjectPlan::decode(bytes) {
        let kind = if plan.static_hostname().is_some() {
            "standalone single-name static vhost (script disabled)"
        } else if plan.names().is_some() {
            "standalone certified static alias vhost (script disabled)"
        } else {
            "standalone unmanaged WordPress vhost"
        };
        return Some(BlastRadiusEnvelope {
            verb: PlanKind::SiteEject.as_str().to_owned(),
            scope: ImpactScope::AllServedSitesOlsReload,
            sites_named: 1,
            all_served_sites: true,
            ols_reloads: 1,
            compensation_reloads: 1,
            max_changes: 1,
            max_operations: 1,
            time_window_seconds,
            resource_budget: format!("1 site handover ({kind}); preserves all site data"),
            privilege_boundary:
                "executor + admin_helper (root OLS standalone handover, reload, and PHP unit stop)"
                    .to_owned(),
            all_site_ols_impact: Some(ALL_SITE_OLS_IMPACT_EXPLANATION.to_owned()),
        });
    }
    if let Ok(plan) = SitePlan::decode(bytes) {
        let quota = plan.quota_limits().map_or_else(
            || "enrolled policy quota".to_owned(),
            |q| format!("{} KiB / {} inodes", q.block_hard_kib(), q.inode_hard()),
        );
        return Some(BlastRadiusEnvelope {
            verb: PlanKind::SiteProvision.as_str().to_owned(),
            scope: ImpactScope::SingleSite,
            sites_named: 1,
            all_served_sites: false,
            ols_reloads: 0,
            compensation_reloads: 0,
            max_changes: 1,
            max_operations: 1,
            time_window_seconds,
            resource_budget: format!("1 site account/DB/pool; quota {quota}"),
            privilege_boundary:
                "executor + admin_helper (account/DB/unit) + confined site unpack job".to_owned(),
            all_site_ols_impact: None,
        });
    }
    if let Ok(plan) = ImportPlan::decode(bytes) {
        let q = plan.quota_limits();
        return Some(BlastRadiusEnvelope {
            verb: PlanKind::SiteImport.as_str().to_owned(),
            scope: ImpactScope::SingleSite,
            sites_named: 1,
            all_served_sites: false,
            ols_reloads: 0,
            compensation_reloads: 0,
            max_changes: 1,
            max_operations: 1,
            time_window_seconds,
            resource_budget: format!(
                "{} files ({} bytes), {} dump bytes; quota {} KiB / {} inodes",
                plan.file_entries(),
                plan.file_bytes(),
                plan.dump_bytes(),
                q.block_hard_kib(),
                q.inode_hard()
            ),
            privilege_boundary: "executor + admin_helper + confined site unpack/inventory/DB jobs"
                .to_owned(),
            all_site_ols_impact: None,
        });
    }
    if let Ok(_plan) = SiteClonePlan::decode(bytes) {
        return Some(BlastRadiusEnvelope {
            verb: PlanKind::SiteClone.as_str().to_owned(),
            scope: ImpactScope::SingleSite,
            sites_named: 1,
            all_served_sites: false,
            ols_reloads: 0,
            compensation_reloads: 0,
            max_changes: 1,
            max_operations: 1,
            time_window_seconds,
            resource_budget: "1 new staging site within enrolled quota cap".to_owned(),
            privilege_boundary: "executor + admin_helper + confined clone fetch/unpack/DB jobs"
                .to_owned(),
            all_site_ols_impact: None,
        });
    }
    if let Ok(plan) = ProxyPlan::decode(bytes) {
        return Some(BlastRadiusEnvelope {
            verb: PlanKind::ProxySiteProvision.as_str().to_owned(),
            scope: ImpactScope::SingleSite,
            sites_named: 1,
            all_served_sites: false,
            ols_reloads: 0,
            compensation_reloads: 0,
            max_changes: (plan.routes().len() + plan.websockets().len()) as u64,
            max_operations: 1,
            time_window_seconds,
            resource_budget: format!(
                "{} HTTP route(s), {} WebSocket route(s); loopback only; no PHP or DB",
                plan.routes().len(),
                plan.websockets().len()
            ),
            privilege_boundary: "executor + admin_helper (account/skeleton/ACME webroot only)"
                .to_owned(),
            all_site_ols_impact: None,
        });
    }
    if let Ok(plan) = CertificatePlan::decode(bytes) {
        let names = if plan.alias_hostname().is_some() {
            2
        } else {
            1
        };
        return Some(BlastRadiusEnvelope {
            verb: PlanKind::CertificateIssue.as_str().to_owned(),
            scope: ImpactScope::SingleSite,
            sites_named: 1,
            all_served_sites: false,
            ols_reloads: 0,
            compensation_reloads: 0,
            max_changes: names,
            max_operations: 1,
            time_window_seconds,
            resource_budget: format!("{names} DNS name(s) via HTTP-01; enrolled CA only"),
            privilege_boundary: "executor + confined rustiron-acme HTTP-01 job".to_owned(),
            all_site_ols_impact: None,
        });
    }
    if let Ok(plan) = SiteUpdatePlan::decode(bytes) {
        let count = plan.components().len() as u64;
        return Some(BlastRadiusEnvelope {
            verb: PlanKind::SiteUpdate.as_str().to_owned(),
            scope: ImpactScope::SingleSite,
            sites_named: 1,
            all_served_sites: false,
            ols_reloads: 0,
            compensation_reloads: 0,
            max_changes: count,
            max_operations: 1,
            time_window_seconds,
            resource_budget: format!("{count} pinned component(s) within site quota"),
            privilege_boundary: "executor + admin_helper + confined site swap/health/rollback jobs"
                .to_owned(),
            all_site_ols_impact: None,
        });
    }
    if let Ok(plan) = QuotaPlan::decode(bytes) {
        let q = plan.quota_limits();
        return Some(BlastRadiusEnvelope {
            verb: PlanKind::SiteQuota.as_str().to_owned(),
            scope: ImpactScope::SingleSite,
            sites_named: 1,
            all_served_sites: false,
            ols_reloads: 0,
            compensation_reloads: 0,
            max_changes: 1,
            max_operations: 1,
            time_window_seconds,
            resource_budget: format!(
                "hard {} KiB / {} inodes (capped by enrolled policy)",
                q.block_hard_kib(),
                q.inode_hard()
            ),
            privilege_boundary: "executor + admin_helper (filesystem quota set/readback)"
                .to_owned(),
            all_site_ols_impact: None,
        });
    }
    if let Ok(plan) = RestorePlan::decode(bytes) {
        let scope_label = match plan.scope() {
            RestoreScope::Database => "database only",
            RestoreScope::FilesAndDatabase => "files and database",
        };
        return Some(BlastRadiusEnvelope {
            verb: PlanKind::SiteRestore.as_str().to_owned(),
            scope: ImpactScope::SingleSite,
            sites_named: 1,
            all_served_sites: false,
            ols_reloads: 0,
            compensation_reloads: 0,
            max_changes: 1,
            max_operations: 1,
            time_window_seconds,
            resource_budget: format!("restore {scope_label} behind a fresh safety capture"),
            privilege_boundary: "executor + admin_helper + confined site fetch/DB/exchange jobs"
                .to_owned(),
            all_site_ols_impact: None,
        });
    }
    if let Ok(_plan) = DeletePlan::decode(bytes) {
        return Some(BlastRadiusEnvelope {
            verb: PlanKind::SiteDelete.as_str().to_owned(),
            scope: ImpactScope::SingleSite,
            sites_named: 1,
            all_served_sites: false,
            ols_reloads: 0,
            compensation_reloads: 0,
            max_changes: 1,
            max_operations: 1,
            time_window_seconds,
            resource_budget: "removes 1 offline site; retains backups and store credentials"
                .to_owned(),
            privilege_boundary: "executor + admin_helper (root site resource removal)".to_owned(),
            all_site_ols_impact: None,
        });
    }
    if let Ok(_plan) = RetirePlan::decode(bytes) {
        return Some(BlastRadiusEnvelope {
            verb: PlanKind::SiteRetire.as_str().to_owned(),
            scope: ImpactScope::SingleSite,
            sites_named: 1,
            all_served_sites: false,
            ols_reloads: 0,
            compensation_reloads: 0,
            max_changes: 1,
            max_operations: 1,
            time_window_seconds,
            resource_budget: "removes 1 quarantined unserved site".to_owned(),
            privilege_boundary: "executor + admin_helper (root quarantined-site cleanup)"
                .to_owned(),
            all_site_ols_impact: None,
        });
    }
    if let Ok(_plan) = ScrubPlan::decode(bytes) {
        return Some(BlastRadiusEnvelope {
            verb: PlanKind::ImportScrub.as_str().to_owned(),
            scope: ImpactScope::SingleSite,
            sites_named: 1,
            all_served_sites: false,
            ols_reloads: 0,
            compensation_reloads: 0,
            max_changes: 1,
            max_operations: 1,
            time_window_seconds,
            resource_budget: "removes 1 import's intake archive and tmp/import staging".to_owned(),
            privilege_boundary: "executor + confined site unpack cleanup".to_owned(),
            all_site_ols_impact: None,
        });
    }
    if let Ok(_plan) = CloneScrubPlan::decode(bytes) {
        return Some(BlastRadiusEnvelope {
            verb: PlanKind::CloneScrub.as_str().to_owned(),
            scope: ImpactScope::SingleSite,
            sites_named: 1,
            all_served_sites: false,
            ols_reloads: 0,
            compensation_reloads: 0,
            max_changes: 1,
            max_operations: 1,
            time_window_seconds,
            resource_budget: "removes 1 quarantined clone's staged artifacts".to_owned(),
            privilege_boundary: "executor + confined site unpack cleanup".to_owned(),
            all_site_ols_impact: None,
        });
    }
    if let Ok(plan) = DnsImportPlan::decode(bytes) {
        return Some(BlastRadiusEnvelope {
            verb: PlanKind::DnsZoneImport.as_str().to_owned(),
            scope: ImpactScope::SingleZoneDns,
            sites_named: 0,
            all_served_sites: false,
            ols_reloads: 0,
            compensation_reloads: 0,
            max_changes: u64::from(plan.record_sets()),
            max_operations: 1,
            time_window_seconds,
            resource_budget: format!(
                "1 new authoritative zone ({} record sets)",
                plan.record_sets()
            ),
            privilege_boundary: "executor + admin_helper (PowerDNS SQLite zone import)".to_owned(),
            all_site_ols_impact: None,
        });
    }
    if let Ok(plan) = DnsChangePlan::decode(bytes) {
        let ops = plan.operations().len() as u64;
        return Some(BlastRadiusEnvelope {
            verb: PlanKind::DnsChange.as_str().to_owned(),
            scope: ImpactScope::SingleZoneDns,
            sites_named: 0,
            all_served_sites: false,
            ols_reloads: 0,
            compensation_reloads: 0,
            max_changes: ops,
            max_operations: 1,
            time_window_seconds,
            resource_budget: format!("compare-and-set on {ops} record set(s) in 1 owned zone"),
            privilege_boundary: "executor + admin_helper (PowerDNS SQLite CAS + cache purge)"
                .to_owned(),
            all_site_ols_impact: None,
        });
    }
    if let Ok(plan) = ReadoptPlan::decode(bytes) {
        let sites_named = if plan.site().is_some() {
            1
        } else {
            plan.generation()
                .map_or(0, |(_, _, sites)| sites.len() as u64)
        };
        return Some(BlastRadiusEnvelope {
            verb: PlanKind::SiteReadopt.as_str().to_owned(),
            scope: ImpactScope::HostReadopt,
            sites_named,
            all_served_sites: false,
            ols_reloads: 0,
            compensation_reloads: 0,
            max_changes: 0,
            max_operations: 1,
            time_window_seconds,
            resource_budget: "read-only host verification; zero host mutations".to_owned(),
            privilege_boundary: "executor + admin_helper (read-only ownership verification)"
                .to_owned(),
            all_site_ols_impact: None,
        });
    }
    if let Ok(_plan) = CapturePlan::decode(bytes) {
        return Some(BlastRadiusEnvelope {
            verb: PlanKind::BackupCapture.as_str().to_owned(),
            scope: ImpactScope::SingleSite,
            sites_named: 1,
            all_served_sites: false,
            ols_reloads: 0,
            compensation_reloads: 0,
            max_changes: 1,
            max_operations: 1,
            time_window_seconds,
            resource_budget: "1 append-only encrypted snapshot; no delete or prune".to_owned(),
            privilege_boundary: "executor + confined per-site capture worker (append-only key)"
                .to_owned(),
            all_site_ols_impact: None,
        });
    }
    if let Ok(_plan) = ProbePlan::decode(bytes) {
        return Some(BlastRadiusEnvelope {
            verb: PlanKind::RestoreProbe.as_str().to_owned(),
            scope: ImpactScope::SingleSite,
            sites_named: 1,
            all_served_sites: false,
            ols_reloads: 0,
            compensation_reloads: 0,
            max_changes: 0,
            max_operations: 1,
            time_window_seconds,
            resource_budget: "throwaway sandbox restore; source site untouched".to_owned(),
            privilege_boundary: "executor + confined ephemeral probe account (read-only store key)"
                .to_owned(),
            all_site_ols_impact: None,
        });
    }
    if let Ok(plan) = ProductBackupPlan::decode(bytes) {
        let (verb, changes, resources, privs) = match plan.target() {
            ProductBackupTarget::BackupCapture { .. } => (
                PlanKind::BackupCapture.as_str(),
                1,
                "1 append-only encrypted product snapshot; no delete or prune",
                "executor + confined per-site capture worker (append-only HTTPS store key)",
            ),
            ProductBackupTarget::RestoreProbe { .. } => (
                PlanKind::RestoreProbe.as_str(),
                0,
                "throwaway sandbox restore; source site untouched",
                "executor + confined ephemeral probe account (read-only store key)",
            ),
        };
        return Some(BlastRadiusEnvelope {
            verb: verb.to_owned(),
            scope: ImpactScope::SingleSite,
            sites_named: 1,
            all_served_sites: false,
            ols_reloads: 0,
            compensation_reloads: 0,
            max_changes: changes,
            max_operations: 1,
            time_window_seconds,
            resource_budget: resources.to_owned(),
            privilege_boundary: privs.to_owned(),
            all_site_ols_impact: None,
        });
    }
    if let Ok(plan) = StandingCapturePlan::decode(bytes) {
        let sites = plan.site_ids().len() as u64;
        let max_runs = plan.schedule().max_runs;
        let total = sites.saturating_mul(max_runs);
        return Some(BlastRadiusEnvelope {
            verb: PlanKind::BackupCapture.as_str().to_owned(),
            scope: ImpactScope::SingleSite,
            sites_named: sites,
            all_served_sites: false,
            ols_reloads: 0,
            compensation_reloads: 0,
            max_changes: total,
            max_operations: total,
            time_window_seconds,
            resource_budget: format!(
                "up to {total} append-only snapshots ({sites} site(s) x {max_runs} window(s)); no delete or prune"
            ),
            privilege_boundary:
                "executor + confined per-site capture worker (standing append-only schedule)"
                    .to_owned(),
            all_site_ols_impact: None,
        });
    }
    if let Ok(plan) = AppProvisionPlan::decode(bytes) {
        let worker = if plan.worker_entrypoint().is_some() {
            " + companion worker"
        } else {
            ""
        };
        let extra_v2 = if plan.schema_version() == 2 {
            let bg = if plan.blue_green() {
                ", blue/green"
            } else {
                ""
            };
            format!(
                ", ingress {}, topology {}, db {}{bg}",
                plan.ingress().as_str(),
                plan.topology().as_str(),
                plan.database().as_str(),
            )
        } else {
            String::new()
        };
        let port_text = if plan.port() == 0 {
            "static (no loopback port)".to_owned()
        } else if let Some(fp) = plan.frontend_port() {
            format!(
                "loopback 127.0.0.1:{} + frontend 127.0.0.1:{fp}",
                plan.port()
            )
        } else {
            format!("loopback 127.0.0.1:{}", plan.port())
        };
        return Some(BlastRadiusEnvelope {
            verb: PlanKind::AppProvision.as_str().to_owned(),
            scope: ImpactScope::SingleSite,
            sites_named: 1,
            all_served_sites: false,
            ols_reloads: 0,
            compensation_reloads: 0,
            max_changes: 1,
            max_operations: 1,
            time_window_seconds,
            resource_budget: format!(
                "{}, {port_text}, {} MiB RAM, {} tasks, {} MiB quota, {} route(s), {} websocket(s){worker}{extra_v2}",
                plan.runtime().as_str(),
                plan.memory_max_mib(),
                plan.tasks_max(),
                plan.quota_mib(),
                plan.routes().len(),
                plan.websockets().len(),
            ),
            privilege_boundary: if plan.database().provisions_server_db() {
                format!(
                    "executor + admin_helper (site account, SELinux MCS, confined systemd unit, per-site {} database; no ingress reload, no root package scripts)",
                    plan.database().as_str()
                )
            } else {
                "executor + admin_helper (site account, SELinux MCS, confined systemd unit; no OLS reload, no root package scripts)"
                    .to_owned()
            },
            all_site_ols_impact: None,
        });
    }
    if let Ok(plan) = AppDeployPlan::decode(bytes) {
        let migration = if plan.migration_entrypoint().is_some() {
            ", bounded unprivileged migration with capture rollback"
        } else {
            ""
        };
        let bg = if plan.blue_green_cutover() {
            ", blue/green Caddy cutover"
        } else {
            ""
        };
        return Some(BlastRadiusEnvelope {
            verb: PlanKind::AppDeploy.as_str().to_owned(),
            scope: ImpactScope::SingleSite,
            sites_named: 1,
            all_served_sites: false,
            ols_reloads: 0,
            compensation_reloads: 0,
            max_changes: 1,
            max_operations: 1,
            time_window_seconds,
            resource_budget: format!(
                "{} release {}: {} file(s), {} bytes{migration}{bg}, bounded health probe + auto-rollback",
                plan.runtime().as_str(),
                plan.release_id(),
                plan.file_count(),
                plan.total_bytes(),
            ),
            privilege_boundary: if plan.blue_green_cutover() {
                "executor + unprivileged site unpack/migration + blue/green standby start + atomic Caddy reload (no OLS reload, no root package scripts)"
                    .to_owned()
            } else {
                "executor + unprivileged site unpack/migration + systemd unit restart (no OLS reload, no root package scripts)"
                    .to_owned()
            },
            all_site_ols_impact: None,
        });
    }
    if let Ok(plan) = AppLifecyclePlan::decode(bytes) {
        return Some(BlastRadiusEnvelope {
            verb: PlanKind::AppLifecycle.as_str().to_owned(),
            scope: ImpactScope::SingleSite,
            sites_named: 1,
            all_served_sites: false,
            ols_reloads: 0,
            compensation_reloads: 0,
            max_changes: 1,
            max_operations: 1,
            time_window_seconds,
            resource_budget: format!(
                "systemd unit {} for site {}",
                plan.action().as_str(),
                plan.site_id().as_str()
            ),
            privilege_boundary:
                "executor + admin_helper (systemd unit state change only; no file or OLS change)"
                    .to_owned(),
            all_site_ols_impact: None,
        });
    }
    if let Ok(plan) = CredentialRotatePlan::decode(bytes) {
        return Some(BlastRadiusEnvelope {
            verb: PlanKind::SiteCredentialRotate.as_str().to_owned(),
            scope: ImpactScope::SingleSite,
            sites_named: 1,
            all_served_sites: false,
            ols_reloads: 0,
            compensation_reloads: 0,
            max_changes: 1,
            max_operations: 1,
            time_window_seconds,
            resource_budget: format!(
                "rotates {} for site {} ({}); zero secrets in plan; bounded 1-attempt compensation",
                plan.target().as_str(),
                plan.site_id().as_str(),
                plan.hostname().as_str(),
            ),
            privilege_boundary:
                "executor + admin_helper (MariaDB ALTER USER + atomic 0600 private/db.cnf + site PHP pool restart; no OLS reload, no arbitrary SQL)"
                    .to_owned(),
            all_site_ols_impact: None,
        });
    }
    if let Ok(_plan) = FixturePlan::decode(bytes) {
        return Some(BlastRadiusEnvelope {
            verb: "config_activate".to_owned(),
            scope: ImpactScope::FixtureResource,
            sites_named: 0,
            all_served_sites: false,
            ols_reloads: 0,
            compensation_reloads: 0,
            max_changes: 1,
            max_operations: 1,
            time_window_seconds,
            resource_budget: "1 fixture resource generation (lab only)".to_owned(),
            privilege_boundary: "executor fixture registry only".to_owned(),
            all_site_ols_impact: None,
        });
    }
    None
}
