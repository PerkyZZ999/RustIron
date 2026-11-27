//! Build one closed plan from operator fields.
//!
//! The result is canonical bytes for review and signing elsewhere. These
//! commands do not observe the host, sign, or submit.

use rustiron_contracts::{
    ErrorCode, MAX_REQUEST_BYTES,
    approval::{MAX_ZONE_BYTES, PreparedPlan, SetOperation, ZoneName, parse_zone},
};
use std::{
    io::{self, Write},
    path::Path,
    process::ExitCode,
};

use crate::file_input;

const ASSERTED_ABSENCE: &str = "operator-asserted absence; Rustiron did not observe the host";
const ASSERTED_GENERATION: &str = "operator-supplied generation; Rustiron did not observe the host";
const ASSERTED_CAPTURE: &str =
    "operator-named site; Rustiron did not observe the host or capture it";
const ASSERTED_PROBE: &str =
    "operator-named snapshot; Rustiron did not restore it or touch the source site";

pub(crate) struct SiteProvision {
    pub plan_id: String,
    pub host_id: String,
    pub host_epoch: String,
    pub profile_digest: String,
    pub requester: String,
    pub site_id: String,
    pub hostname: String,
    pub recipe: String,
    pub recipe_digest: String,
    pub observed_at: u64,
    pub valid_from: u64,
    pub expires_at: u64,
    pub limitations: Vec<String>,
    /// W341: signed hard limits (KiB, inodes). Present: plan schema v2.
    /// Absent: schema v1, whose limits are the executor's enrolled policy.
    pub quota: Option<(u64, u64)>,
}

pub(crate) fn site_provision(request: SiteProvision) -> ExitCode {
    let limitations = if request.limitations.is_empty() {
        vec![ASSERTED_ABSENCE.to_owned()]
    } else {
        request.limitations
    };
    let mut draft = serde_json::json!({
        "schema_version": 1,
        "plan_id": request.plan_id,
        "host_id": request.host_id,
        "host_epoch": request.host_epoch,
        "profile_digest": request.profile_digest,
        "requester": request.requester,
        "verb": "site_provision",
        "site_id": request.site_id,
        "hostname": request.hostname,
        "recipe_id": request.recipe,
        "recipe_digest": request.recipe_digest,
        "observations": [{
            "state": "absent",
            "site_id": request.site_id,
            "hostname": request.hostname,
            "observed_at": request.observed_at,
            "source": "reported_registry",
        }],
        "expected_effects": {
            "creates_account": true,
            "creates_database": true,
            "traffic_activation": false,
            "network_access": false,
        },
        "risk_class": "lab_only",
        "valid_from": request.valid_from,
        "expires_at": request.expires_at,
        "limitations": limitations,
    });
    if let Some((block_hard_kib, inode_hard)) = request.quota {
        draft["schema_version"] = 2.into();
        draft["expected_effects"]["sets_quota"] = true.into();
        draft["quota_limits"] = serde_json::json!({
            "block_hard_kib": block_hard_kib,
            "inode_hard": inode_hard,
        });
    }
    emit_canonical(&draft)
}

pub(crate) struct SiteEject {
    pub plan_id: String,
    pub host_id: String,
    pub host_epoch: String,
    pub profile_digest: String,
    pub requester: String,
    pub site_id: String,
    pub hostname: Option<String>,
    pub alias_hostname: Option<String>,
    pub expected_generation: String,
    pub expected_digest: String,
    pub observed_at: u64,
    pub valid_from: u64,
    pub expires_at: u64,
    pub compensation_until: u64,
    pub limitations: Vec<String>,
}

pub(crate) fn site_eject(request: SiteEject) -> ExitCode {
    let limitations = if request.limitations.is_empty() {
        vec![ASSERTED_GENERATION.to_owned()]
    } else {
        request.limitations
    };
    let generation = request.expected_generation;
    let digest = request.expected_digest;
    let mut draft = serde_json::json!({
        "schema_version": 1,
        "plan_id": request.plan_id,
        "host_id": request.host_id,
        "host_epoch": request.host_epoch,
        "profile_digest": request.profile_digest,
        "requester": request.requester,
        "verb": "site_eject",
        "target": "ols_lab_listener",
        "site_id": request.site_id,
        "expected_generation": generation,
        "expected_digest": digest,
        "observations": [{
            "state": "observed",
            "generation": generation.clone(),
            "content_digest": digest.clone(),
            "observed_at": request.observed_at,
            "source": "reported_registry",
        }],
        "risk_class": "lab_only",
        "valid_from": request.valid_from,
        "expires_at": request.expires_at,
        "compensation": {
            "recipe": "ols_restore_lkg_v1",
            "max_attempts": 1,
            "valid_until": request.compensation_until,
        },
        "limitations": limitations,
    });
    match (request.hostname, request.alias_hostname) {
        (Some(hostname), Some(alias)) => {
            draft["schema_version"] = 2.into();
            draft["hostname"] = hostname.into();
            draft["alias_hostname"] = alias.into();
        }
        (Some(hostname), None) => {
            draft["schema_version"] = 3.into();
            draft["hostname"] = hostname.into();
        }
        (None, None) => {}
        (None, Some(_)) => unreachable!("clap requires --hostname with --alias-hostname"),
    }
    emit_canonical(&draft)
}

pub(crate) struct ConfigActivate {
    pub plan_id: String,
    pub host_id: String,
    pub host_epoch: String,
    pub profile_digest: String,
    pub requester: String,
    pub site_ids: Vec<String>,
    pub expected_generation: String,
    pub expected_digest: String,
    pub observed_at: u64,
    pub valid_from: u64,
    pub expires_at: u64,
    pub compensation_until: u64,
    pub limitations: Vec<String>,
}

pub(crate) fn config_activate(request: ConfigActivate) -> ExitCode {
    let limitations = if request.limitations.is_empty() {
        vec![ASSERTED_GENERATION.to_owned()]
    } else {
        request.limitations
    };
    let generation = request.expected_generation;
    let digest = request.expected_digest;
    let draft = serde_json::json!({
        "schema_version": 1,
        "plan_id": request.plan_id,
        "host_id": request.host_id,
        "host_epoch": request.host_epoch,
        "profile_digest": request.profile_digest,
        "requester": request.requester,
        "verb": "config_activate",
        "target": "ols_lab_listener",
        "site_ids": request.site_ids,
        "expected_generation": generation,
        "expected_digest": digest,
        "observations": [{
            "state": "observed",
            "generation": generation.clone(),
            "content_digest": digest.clone(),
            "observed_at": request.observed_at,
            "source": "reported_registry",
        }],
        "risk_class": "lab_only",
        "valid_from": request.valid_from,
        "expires_at": request.expires_at,
        "compensation": {
            "recipe": "ols_restore_lkg_v1",
            "max_attempts": 1,
            "valid_until": request.compensation_until,
        },
        "limitations": limitations,
    });
    emit_canonical(&draft)
}

pub(crate) struct BackupCapture {
    pub plan_id: String,
    pub host_id: String,
    pub host_epoch: String,
    pub profile_digest: String,
    pub requester: String,
    pub site_id: String,
    pub valid_from: u64,
    pub expires_at: u64,
    pub limitations: Vec<String>,
}

pub(crate) fn backup_capture(request: BackupCapture) -> ExitCode {
    let limitations = if request.limitations.is_empty() {
        vec![ASSERTED_CAPTURE.to_owned()]
    } else {
        request.limitations
    };
    let draft = serde_json::json!({
        "schema_version": 1,
        "plan_id": request.plan_id,
        "host_id": request.host_id,
        "host_epoch": request.host_epoch,
        "profile_digest": request.profile_digest,
        "requester": request.requester,
        "verb": "backup_capture",
        "site_id": request.site_id,
        "destination_id": "lab_pc_store",
        "recipe_id": "site_files_db_v1",
        "risk_class": "lab_only",
        "valid_from": request.valid_from,
        "expires_at": request.expires_at,
        "limitations": limitations,
    });
    emit_canonical(&draft)
}

pub(crate) struct RestoreProbe {
    pub plan_id: String,
    pub host_id: String,
    pub host_epoch: String,
    pub profile_digest: String,
    pub requester: String,
    pub site_id: String,
    pub snapshot_id: String,
    pub valid_from: u64,
    pub expires_at: u64,
    pub limitations: Vec<String>,
}

pub(crate) fn restore_probe(request: RestoreProbe) -> ExitCode {
    let limitations = if request.limitations.is_empty() {
        vec![ASSERTED_PROBE.to_owned()]
    } else {
        request.limitations
    };
    let draft = serde_json::json!({
        "schema_version": 1,
        "plan_id": request.plan_id,
        "host_id": request.host_id,
        "host_epoch": request.host_epoch,
        "profile_digest": request.profile_digest,
        "requester": request.requester,
        "verb": "restore_probe",
        "site_id": request.site_id,
        "snapshot_id": request.snapshot_id,
        "profile_id": "local_no_egress_v1",
        "risk_class": "lab_only",
        "valid_from": request.valid_from,
        "expires_at": request.expires_at,
        "limitations": limitations,
    });
    emit_canonical(&draft)
}

#[derive(clap::Args)]
pub(crate) struct ProductBackup {
    #[arg(long)]
    plan_id: String,
    #[arg(long)]
    host_id: String,
    #[arg(long)]
    host_epoch: String,
    #[arg(long)]
    profile_digest: String,
    #[arg(long)]
    requester: String,
    #[arg(long)]
    site_id: String,
    /// Destination ID from the operator-reviewed enrollment.
    #[arg(long)]
    destination_id: String,
    /// Destination policy SHA-256 from the operator-reviewed enrollment.
    #[arg(long)]
    destination_policy_digest: String,
    #[arg(long)]
    valid_from: u64,
    #[arg(long)]
    expires_at: u64,
    #[arg(long)]
    limitation: Vec<String>,
}

pub(crate) enum ProductTarget {
    Capture {
        recipe_id: String,
    },
    Probe {
        snapshot_id: String,
        profile_id: String,
    },
}

pub(crate) fn product_backup(request: ProductBackup, target: ProductTarget) -> ExitCode {
    let use_default_limitation = request.limitation.is_empty();
    let mut draft = serde_json::json!({
        "schema_version": 2,
        "plan_id": request.plan_id,
        "host_id": request.host_id,
        "host_epoch": request.host_epoch,
        "profile_digest": request.profile_digest,
        "requester": request.requester,
        "site_id": request.site_id,
        "destination_id": request.destination_id,
        "destination_policy_digest": request.destination_policy_digest,
        "risk_class": "production",
        "valid_from": request.valid_from,
        "expires_at": request.expires_at,
        "limitations": request.limitation,
    });
    let default_limitation = match target {
        ProductTarget::Capture { recipe_id } => {
            draft["verb"] = serde_json::json!("backup_capture");
            draft["recipe_id"] = serde_json::json!(recipe_id);
            ASSERTED_CAPTURE
        }
        ProductTarget::Probe {
            snapshot_id,
            profile_id,
        } => {
            draft["verb"] = serde_json::json!("restore_probe");
            draft["snapshot_id"] = serde_json::json!(snapshot_id);
            draft["profile_id"] = serde_json::json!(profile_id);
            ASSERTED_PROBE
        }
    };
    if use_default_limitation {
        draft["limitations"] = serde_json::json!([default_limitation]);
    }
    emit_canonical(&draft)
}

const ASSERTED_STANDING: &str =
    "operator-named sites and schedule; Rustiron did not observe the host or capture it";

/// D-035 (W386): the fields of a standing capture plan.
#[derive(clap::Args)]
pub(crate) struct StandingCapture {
    #[arg(long)]
    plan_id: String,
    #[arg(long)]
    host_id: String,
    #[arg(long)]
    host_epoch: String,
    #[arg(long)]
    profile_digest: String,
    #[arg(long)]
    requester: String,
    /// A named site; repeat for 1 to 16 sites. The plan lists them sorted.
    #[arg(long, required = true)]
    site_id: Vec<String>,
    /// Destination ID from the operator-reviewed enrollment.
    #[arg(long)]
    destination_id: String,
    /// Destination policy SHA-256 from the operator-reviewed enrollment.
    #[arg(long)]
    destination_policy_digest: String,
    /// Fixed capture recipe ID.
    #[arg(long)]
    recipe_id: String,
    /// Opening second (Unix) of window 0.
    #[arg(long)]
    first_window_start: u64,
    /// Seconds between two window openings (300 to 86400).
    #[arg(long)]
    period_seconds: u64,
    /// Seconds each window stays open (60 to 14400, at most half the period).
    #[arg(long)]
    window_seconds: u64,
    /// Number of windows (1 to 35).
    #[arg(long)]
    max_runs: u64,
    #[arg(long)]
    valid_from: u64,
    #[arg(long)]
    expires_at: u64,
    #[arg(long)]
    limitation: Vec<String>,
}

/// D-035 (W386): a standing capture plan (schema 3) for offline review.
pub(crate) fn standing_capture(request: StandingCapture) -> ExitCode {
    let mut sites = request.site_id;
    sites.sort();
    let limitations = if request.limitation.is_empty() {
        vec![ASSERTED_STANDING.to_owned()]
    } else {
        request.limitation
    };
    let draft = serde_json::json!({
        "schema_version": 3,
        "plan_id": request.plan_id,
        "host_id": request.host_id,
        "host_epoch": request.host_epoch,
        "profile_digest": request.profile_digest,
        "requester": request.requester,
        "verb": "backup_capture",
        "site_ids": sites,
        "destination_id": request.destination_id,
        "destination_policy_digest": request.destination_policy_digest,
        "recipe_id": request.recipe_id,
        "first_window_start": request.first_window_start,
        "period_seconds": request.period_seconds,
        "window_seconds": request.window_seconds,
        "max_runs": request.max_runs,
        "risk_class": "production",
        "valid_from": request.valid_from,
        "expires_at": request.expires_at,
        "limitations": limitations,
    });
    emit_canonical(&draft)
}

const ASSERTED_READOPT: &str =
    "operator-supplied facts from the pre-rotation export; the executor verifies the host";

/// W372: the fields both `site_readopt` forms share.
#[derive(clap::Args)]
pub(crate) struct Readopt {
    #[arg(long)]
    plan_id: String,
    #[arg(long)]
    host_id: String,
    /// The current (new) epoch.
    #[arg(long)]
    host_epoch: String,
    #[arg(long)]
    profile_digest: String,
    #[arg(long)]
    requester: String,
    /// The archived journal's epoch (evidence for the review only).
    #[arg(long)]
    previous_epoch: String,
    /// SHA-256 of the pre-rotation `export` (site form) or `ols-status`
    /// (generation form) output.
    #[arg(long)]
    evidence_sha256: String,
    /// Optional signed allocation floor: the highest UID the previous epoch
    /// recorded; requires `--floor-category`.
    #[arg(long, requires = "floor_category")]
    floor_uid: Option<u32>,
    /// The highest category the previous epoch recorded.
    #[arg(long, requires = "floor_uid")]
    floor_category: Option<u32>,
    #[arg(long)]
    observed_at: u64,
    #[arg(long)]
    valid_from: u64,
    #[arg(long)]
    expires_at: u64,
    #[arg(long)]
    limitation: Vec<String>,
}

/// W372: which form, with its own fields.
pub(crate) enum ReadoptTarget {
    Site {
        site_id: String,
        hostname: String,
        quota: (u64, u64),
    },
    Generation {
        site_ids: Vec<String>,
        expected_generation: String,
        expected_digest: String,
    },
}

/// W372: one `site_readopt` plan. Every effect is fixed `false`; the
/// executor records ownership only after it verifies the host.
pub(crate) fn site_readopt(request: Readopt, target: ReadoptTarget) -> ExitCode {
    let limitations = if request.limitation.is_empty() {
        vec![ASSERTED_READOPT.to_owned()]
    } else {
        request.limitation
    };
    let effects = |record: &str| {
        let mut effects = serde_json::json!({
            "creates_account": false,
            "creates_database": false,
            "traffic_activation": false,
            "network_access": false,
            "sets_quota": false,
        });
        effects[record] = true.into();
        effects
    };
    let mut draft = serde_json::json!({
        "schema_version": 1,
        "plan_id": request.plan_id,
        "host_id": request.host_id,
        "host_epoch": request.host_epoch,
        "profile_digest": request.profile_digest,
        "requester": request.requester,
        "verb": "site_readopt",
        "previous_epoch": request.previous_epoch,
        "evidence_sha256": request.evidence_sha256,
        "risk_class": "lab_only",
        "valid_from": request.valid_from,
        "expires_at": request.expires_at,
        "limitations": limitations,
    });
    if let Some((uid, category)) = request.floor_uid.zip(request.floor_category) {
        draft["allocation_floor"] = serde_json::json!({"uid": uid, "category": category});
    }
    match target {
        ReadoptTarget::Site {
            site_id,
            hostname,
            quota: (block_hard_kib, inode_hard),
        } => {
            draft["form"] = "site".into();
            draft["observations"] = serde_json::json!([{
                "state": "present_unowned",
                "site_id": site_id,
                "hostname": hostname,
                "observed_at": request.observed_at,
                "source": "reported_registry",
            }]);
            draft["site_id"] = site_id.into();
            draft["hostname"] = hostname.into();
            draft["quota_limits"] = serde_json::json!({
                "block_hard_kib": block_hard_kib,
                "inode_hard": inode_hard,
            });
            draft["expected_effects"] = effects("records_ownership");
        }
        ReadoptTarget::Generation {
            mut site_ids,
            expected_generation,
            expected_digest,
        } => {
            site_ids.sort();
            draft["form"] = "generation".into();
            draft["target"] = "ols_lab_listener".into();
            draft["observations"] = serde_json::json!([{
                "state": "observed",
                "generation": expected_generation,
                "content_digest": expected_digest,
                "observed_at": request.observed_at,
                "source": "reported_registry",
            }]);
            draft["site_ids"] = site_ids.into();
            draft["expected_generation"] = expected_generation.into();
            draft["expected_digest"] = expected_digest.into();
            draft["expected_effects"] = effects("records_generation");
        }
    }
    emit_canonical(&draft)
}

/// Fields shared by the two schema 1 DNS plans.
#[derive(clap::Args)]
pub(crate) struct DnsPlan {
    #[arg(long)]
    plan_id: String,
    #[arg(long)]
    host_id: String,
    #[arg(long)]
    host_epoch: String,
    #[arg(long)]
    profile_digest: String,
    #[arg(long)]
    requester: String,
    /// Lowercase zone name without a final dot.
    #[arg(long)]
    zone: String,
    #[arg(long)]
    valid_from: u64,
    #[arg(long)]
    expires_at: u64,
    #[arg(long)]
    limitation: Vec<String>,
}

impl DnsPlan {
    fn draft(self, verb: &str) -> serde_json::Value {
        let limitations = if self.limitation.is_empty() {
            vec!["operator-supplied DNS inputs; Rustiron did not observe the host".to_owned()]
        } else {
            self.limitation
        };
        serde_json::json!({
            "schema_version": 1,
            "plan_id": self.plan_id,
            "host_id": self.host_id,
            "host_epoch": self.host_epoch,
            "profile_digest": self.profile_digest,
            "requester": self.requester,
            "verb": verb,
            "zone": self.zone,
            "risk_class": "lab_only",
            "valid_from": self.valid_from,
            "expires_at": self.expires_at,
            "limitations": limitations,
        })
    }
}

fn read_dns_input(path: &Path, limit: usize) -> Result<Vec<u8>, ExitCode> {
    file_input::read(path, limit).map_err(|error| {
        let name = match error {
            ErrorCode::RequestTooLarge => "DNS_INPUT_TOO_LARGE",
            _ => "INVALID_DNS_INPUT",
        };
        fail(error.exit_code(), name)
    })
}

pub(crate) fn dns_zone_import(request: DnsPlan, zone_file: &Path) -> ExitCode {
    let Ok(zone) = ZoneName::try_from(request.zone.clone()) else {
        return fail(ErrorCode::InvalidRequest.exit_code(), "INVALID_PLAN");
    };
    let bytes = match read_dns_input(zone_file, MAX_ZONE_BYTES) {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    let Ok(parsed) = parse_zone(&zone, &bytes) else {
        return fail(ErrorCode::InvalidRequest.exit_code(), "INVALID_ZONE_FILE");
    };
    let mut draft = request.draft("dns_zone_import");
    draft["zone_sha256"] = parsed.sha256.as_str().into();
    draft["record_sets"] = parsed.record_sets.len().into();
    draft["expected_effects"] = serde_json::json!({
        "creates_zone": true,
        "answers_queries": true,
        "changes_other_zones": false,
        "changes_delegation": false,
    });
    emit_canonical(&draft)
}

pub(crate) fn dns_change(request: DnsPlan, operations_file: &Path) -> ExitCode {
    let bytes = match read_dns_input(operations_file, MAX_REQUEST_BYTES) {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    let Ok(operations) = serde_json::from_slice::<Vec<SetOperation>>(&bytes) else {
        return fail(
            ErrorCode::InvalidRequest.exit_code(),
            "INVALID_DNS_OPERATIONS",
        );
    };
    let mut draft = request.draft("dns_change");
    draft["operations"] = serde_json::json!(operations);
    draft["expected_effects"] = serde_json::json!({
        "changes_records": true,
        "changes_soa_or_ns": false,
        "changes_other_zones": false,
        "changes_delegation": false,
    });
    emit_canonical(&draft)
}

/// Shared envelope fields for P27 modern app hosting plans (D-099).
#[derive(clap::Args)]
pub(crate) struct AppCommon {
    #[arg(long)]
    plan_id: String,
    #[arg(long)]
    host_id: String,
    #[arg(long)]
    host_epoch: String,
    #[arg(long)]
    profile_digest: String,
    #[arg(long)]
    requester: String,
    #[arg(long)]
    site_id: String,
    #[arg(long)]
    valid_from: u64,
    #[arg(long)]
    expires_at: u64,
    #[arg(long)]
    limitation: Vec<String>,
}

/// Build an offline `app_provision` plan (D-099 schema v1 or D-102 schema v2).
#[derive(clap::Args)]
pub(crate) struct AppProvisionArgs {
    #[command(flatten)]
    common: AppCommon,
    #[arg(long)]
    hostname: String,
    /// Closed runtime profile (`node_22_v1`, `bun_1_v1`, or `static_v1` in schema v2).
    #[arg(long)]
    runtime: String,
    /// Loopback port on `127.0.0.1` (`0` for `static_spa`, else 1024..=65535 excluding 2019/3306/5432).
    #[arg(long, default_value_t = 0)]
    port: u16,
    /// Route prefix forwarded to `127.0.0.1:<port>` (repeat as needed; defaults to `/` for `backend_api`, `/api/` for split/dual).
    #[arg(long)]
    route_prefix: Vec<String>,
    /// Optional WebSocket prefix forwarded to `127.0.0.1:<port>` (repeat as needed).
    #[arg(long)]
    websocket_prefix: Vec<String>,
    /// Relative release entrypoint for the HTTP app service (empty for `static_spa`).
    #[arg(long, default_value = "")]
    entrypoint: String,
    /// Optional relative release entrypoint for a companion background worker.
    #[arg(long)]
    worker_entrypoint: Option<String>,
    /// Loopback HTTP health check path (e.g. `/health` or `/`).
    #[arg(long, default_value = "/")]
    health_path: String,
    /// Allowed environment variable key name (names only, never values; sorted automatically).
    #[arg(long)]
    env_key: Vec<String>,
    #[arg(long, default_value_t = 512)]
    memory_max_mib: u64,
    #[arg(long, default_value_t = 64)]
    tasks_max: u64,
    #[arg(long, default_value_t = 1024)]
    quota_mib: u64,
    /// Schema v2 edge ingress engine (`ols` or `caddy`).
    #[arg(long)]
    ingress: Option<String>,
    /// Schema v2 topology (`static_spa`, `backend_api`, `fullstack_split`, `fullstack_dual_ssr`).
    #[arg(long)]
    topology: Option<String>,
    /// Schema v2 database engine (`none`, `sqlite`, `mariadb`, `postgresql_18`).
    #[arg(long)]
    database: Option<String>,
    /// Schema v2 zero-downtime blue/green slot cutover.
    #[arg(long, default_value_t = false)]
    blue_green: bool,
    /// Schema v2 standby loopback port for blue/green cutover.
    #[arg(long)]
    standby_port: Option<u16>,
    /// Schema v2 Caddy SPA `try_files /index.html` fallback.
    #[arg(long, default_value_t = false)]
    spa_fallback: bool,
    /// Schema v2 relative static frontend directory inside release (`static_spa` / `fullstack_split`).
    #[arg(long)]
    frontend_dir: Option<String>,
    /// Schema v2 SSR frontend runtime (`fullstack_dual_ssr`).
    #[arg(long)]
    frontend_runtime: Option<String>,
    /// Schema v2 SSR frontend entrypoint (`fullstack_dual_ssr`).
    #[arg(long)]
    frontend_entrypoint: Option<String>,
    /// Schema v2 SSR frontend loopback port (`fullstack_dual_ssr`).
    #[arg(long)]
    frontend_port: Option<u16>,
    /// Schema v2 SSR frontend standby loopback port for blue/green `fullstack_dual_ssr`.
    #[arg(long)]
    frontend_standby_port: Option<u16>,
    /// Schema v2 unbuffered SSE path prefixes (Caddy only; sorted automatically).
    #[arg(long)]
    sse_prefix: Vec<String>,
    /// Schema v2 API prefixes stripped before forwarding upstream (Caddy only; sorted automatically).
    #[arg(long)]
    strip_api_prefix: Vec<String>,
}

pub(crate) fn app_provision(request: AppProvisionArgs) -> ExitCode {
    // W664 (W662-F5): the app domain binds only unreserved_port_t ports.
    let ports = [
        Some(request.port),
        request.standby_port,
        request.frontend_port,
        request.frontend_standby_port,
    ];
    for port in ports.into_iter().flatten().filter(|port| *port != 0) {
        if let Some(kind) = rustiron_contracts::approval::app_port_selinux_conflict(port) {
            let _ = writeln!(
                io::stderr(),
                "{{\"scope\":\"plan_create\",\"error\":\"APP_PORT_NOT_UNRESERVED\",\"port\":{port},\"selinux_type\":\"{kind}\",\"authority\":\"none\"}}"
            );
            return ExitCode::from(ErrorCode::InvalidRequest.exit_code());
        }
    }
    let limitations = if request.common.limitation.is_empty() {
        vec!["operator-supplied app provision inputs; Rustiron did not observe the host".to_owned()]
    } else {
        request.common.limitation
    };
    let is_v2 = request.ingress.is_some()
        || request.topology.is_some()
        || request.database.is_some()
        || request.blue_green
        || request.standby_port.is_some()
        || request.spa_fallback
        || request.frontend_dir.is_some()
        || request.frontend_runtime.is_some()
        || request.frontend_entrypoint.is_some()
        || request.frontend_port.is_some()
        || request.frontend_standby_port.is_some()
        || !request.sse_prefix.is_empty()
        || !request.strip_api_prefix.is_empty()
        || request.runtime == "static_v1";

    let mut env_keys = request.env_key;
    env_keys.sort();

    if !is_v2 {
        let prefixes = if request.route_prefix.is_empty() {
            vec!["/".to_owned()]
        } else {
            request.route_prefix
        };
        let routes: Vec<serde_json::Value> = prefixes
            .into_iter()
            .map(|prefix| serde_json::json!({ "prefix": prefix, "port": request.port }))
            .collect();
        let websockets: Vec<serde_json::Value> = request
            .websocket_prefix
            .into_iter()
            .map(|prefix| serde_json::json!({ "prefix": prefix, "port": request.port }))
            .collect();
        let mut draft = serde_json::json!({
            "schema_version": 1,
            "plan_id": request.common.plan_id,
            "host_id": request.common.host_id,
            "host_epoch": request.common.host_epoch,
            "profile_digest": request.common.profile_digest,
            "requester": request.common.requester,
            "verb": "app_provision",
            "site_id": request.common.site_id,
            "hostname": request.hostname,
            "runtime": request.runtime,
            "port": request.port,
            "routes": routes,
            "websockets": websockets,
            "entrypoint": request.entrypoint,
            "health_path": request.health_path,
            "env_keys": env_keys,
            "memory_max_mib": request.memory_max_mib,
            "tasks_max": request.tasks_max,
            "quota_mib": request.quota_mib,
            "expected_effects": {
                "creates_account": true,
                "forwards_to_loopback": true,
                "installs_app_unit": true,
                "traffic_activation": false,
                "runs_package_scripts": false,
            },
            "risk_class": "lab_only",
            "valid_from": request.common.valid_from,
            "expires_at": request.common.expires_at,
            "limitations": limitations,
        });
        if let Some(worker) = request.worker_entrypoint {
            draft["worker_entrypoint"] = worker.into();
        }
        return emit_canonical(&draft);
    }

    let topology = request.topology.unwrap_or_else(|| {
        if request.runtime == "static_v1" {
            "static_spa".to_owned()
        } else {
            "backend_api".to_owned()
        }
    });
    let ingress = request.ingress.unwrap_or_else(|| "caddy".to_owned());
    let database = request.database.unwrap_or_else(|| {
        if topology == "static_spa" {
            "none".to_owned()
        } else {
            "sqlite".to_owned()
        }
    });
    let routes: Vec<serde_json::Value> = match topology.as_str() {
        "static_spa" => Vec::new(),
        "fullstack_split" => {
            let prefixes = if request.route_prefix.is_empty() {
                vec!["/api/".to_owned()]
            } else {
                request.route_prefix
            };
            prefixes
                .into_iter()
                .map(|prefix| serde_json::json!({ "prefix": prefix, "port": request.port }))
                .collect()
        }
        "fullstack_dual_ssr" => {
            let fp = request.frontend_port.unwrap_or(0);
            let mut list = vec![serde_json::json!({ "prefix": "/", "port": fp })];
            let api_prefixes = if request.route_prefix.is_empty() {
                vec!["/api/".to_owned()]
            } else {
                request.route_prefix
            };
            for prefix in api_prefixes {
                if prefix != "/" {
                    list.push(serde_json::json!({ "prefix": prefix, "port": request.port }));
                }
            }
            list
        }
        _ => {
            let prefixes = if request.route_prefix.is_empty() {
                vec!["/".to_owned()]
            } else {
                request.route_prefix
            };
            prefixes
                .into_iter()
                .map(|prefix| serde_json::json!({ "prefix": prefix, "port": request.port }))
                .collect()
        }
    };
    let websockets: Vec<serde_json::Value> = request
        .websocket_prefix
        .into_iter()
        .map(|prefix| serde_json::json!({ "prefix": prefix, "port": request.port }))
        .collect();
    let has_runtime = topology != "static_spa";
    let creates_database = matches!(database.as_str(), "mariadb" | "postgresql_18");
    let mut draft = serde_json::json!({
        "schema_version": 2,
        "plan_id": request.common.plan_id,
        "host_id": request.common.host_id,
        "host_epoch": request.common.host_epoch,
        "profile_digest": request.common.profile_digest,
        "requester": request.common.requester,
        "verb": "app_provision",
        "site_id": request.common.site_id,
        "hostname": request.hostname,
        "runtime": request.runtime,
        "port": request.port,
        "routes": routes,
        "websockets": websockets,
        "entrypoint": request.entrypoint,
        "health_path": request.health_path,
        "env_keys": env_keys,
        "memory_max_mib": request.memory_max_mib,
        "tasks_max": request.tasks_max,
        "quota_mib": request.quota_mib,
        "ingress": ingress,
        "topology": topology,
        "database": database,
        "blue_green": request.blue_green,
        "spa_fallback": request.spa_fallback,
        "expected_effects": {
            "creates_account": true,
            "forwards_to_loopback": has_runtime,
            "installs_app_unit": has_runtime,
            "creates_database": creates_database,
            "traffic_activation": false,
            "runs_package_scripts": false,
        },
        "risk_class": "lab_only",
        "valid_from": request.common.valid_from,
        "expires_at": request.common.expires_at,
        "limitations": limitations,
    });
    if let Some(worker) = request.worker_entrypoint {
        draft["worker_entrypoint"] = worker.into();
    }
    if let Some(sp) = request.standby_port {
        draft["standby_port"] = sp.into();
    }
    if let Some(dir) = request.frontend_dir {
        draft["frontend_dir"] = dir.into();
    }
    if let Some(fr) = request.frontend_runtime {
        draft["frontend_runtime"] = fr.into();
    }
    if let Some(fe) = request.frontend_entrypoint {
        draft["frontend_entrypoint"] = fe.into();
    }
    if let Some(fp) = request.frontend_port {
        draft["frontend_port"] = fp.into();
    }
    if let Some(fsp) = request.frontend_standby_port {
        draft["frontend_standby_port"] = fsp.into();
    }
    if !request.sse_prefix.is_empty() {
        let mut sse = request.sse_prefix;
        sse.sort();
        draft["sse_prefixes"] = sse.into();
    }
    if !request.strip_api_prefix.is_empty() {
        let mut strip = request.strip_api_prefix;
        strip.sort();
        draft["strip_api_prefixes"] = strip.into();
    }
    emit_canonical(&draft)
}

/// Build an offline `app_deploy` plan (D-099 schema v1 or D-102 schema v2).
#[derive(clap::Args)]
pub(crate) struct AppDeployArgs {
    #[command(flatten)]
    common: AppCommon,
    #[arg(long)]
    release_id: String,
    #[arg(long)]
    runtime: String,
    #[arg(long)]
    artifact_sha256: String,
    #[arg(long)]
    manifest_sha256: String,
    #[arg(long)]
    file_count: u64,
    #[arg(long)]
    total_bytes: u64,
    #[arg(long)]
    migration_entrypoint: Option<String>,
    #[arg(long)]
    capture_operation_id: Option<String>,
    #[arg(long, default_value = "/")]
    health_path: String,
    /// Schema v2 zero-downtime blue/green slot cutover via Caddy reload.
    #[arg(long, default_value_t = false)]
    blue_green_cutover: bool,
}

pub(crate) fn app_deploy(request: AppDeployArgs) -> ExitCode {
    let limitations = if request.common.limitation.is_empty() {
        vec![
            "operator-supplied release bundle digests; Rustiron did not inspect the host"
                .to_owned(),
        ]
    } else {
        request.common.limitation
    };
    let is_v2 = request.blue_green_cutover || request.runtime == "static_v1";
    let has_runtime = request.runtime != "static_v1";
    let mut draft = if is_v2 {
        serde_json::json!({
            "schema_version": 2,
            "plan_id": request.common.plan_id,
            "host_id": request.common.host_id,
            "host_epoch": request.common.host_epoch,
            "profile_digest": request.common.profile_digest,
            "requester": request.common.requester,
            "verb": "app_deploy",
            "site_id": request.common.site_id,
            "release_id": request.release_id,
            "runtime": request.runtime,
            "artifact_sha256": request.artifact_sha256,
            "manifest_sha256": request.manifest_sha256,
            "file_count": request.file_count,
            "total_bytes": request.total_bytes,
            "health_path": request.health_path,
            "blue_green_cutover": request.blue_green_cutover,
            "expected_effects": {
                "unpacks_as_site": true,
                "switches_release": true,
                "restarts_app_unit": has_runtime,
                "rolls_back_on_failed_health": true,
                "runs_package_scripts": false,
                "traffic_activation": false,
                "reloads_caddy": has_runtime && request.blue_green_cutover,
            },
            "risk_class": "lab_only",
            "valid_from": request.common.valid_from,
            "expires_at": request.common.expires_at,
            "limitations": limitations,
        })
    } else {
        serde_json::json!({
            "schema_version": 1,
            "plan_id": request.common.plan_id,
            "host_id": request.common.host_id,
            "host_epoch": request.common.host_epoch,
            "profile_digest": request.common.profile_digest,
            "requester": request.common.requester,
            "verb": "app_deploy",
            "site_id": request.common.site_id,
            "release_id": request.release_id,
            "runtime": request.runtime,
            "artifact_sha256": request.artifact_sha256,
            "manifest_sha256": request.manifest_sha256,
            "file_count": request.file_count,
            "total_bytes": request.total_bytes,
            "health_path": request.health_path,
            "expected_effects": {
                "unpacks_as_site": true,
                "switches_release": true,
                "restarts_app_unit": true,
                "rolls_back_on_failed_health": true,
                "runs_package_scripts": false,
                "traffic_activation": false,
            },
            "risk_class": "lab_only",
            "valid_from": request.common.valid_from,
            "expires_at": request.common.expires_at,
            "limitations": limitations,
        })
    };
    if let Some(migration) = request.migration_entrypoint {
        draft["migration_entrypoint"] = migration.into();
    }
    if let Some(capture) = request.capture_operation_id {
        draft["capture_operation_id"] = capture.into();
    }
    emit_canonical(&draft)
}

/// Build an offline `app_lifecycle` plan (D-099).
#[derive(clap::Args)]
pub(crate) struct AppLifecycleArgs {
    #[command(flatten)]
    common: AppCommon,
    /// Closed action (`start`, `stop`, or `restart`).
    #[arg(long)]
    action: String,
}

pub(crate) fn app_lifecycle(request: AppLifecycleArgs) -> ExitCode {
    let limitations = if request.common.limitation.is_empty() {
        vec!["operator-requested unit action; Rustiron did not observe the host".to_owned()]
    } else {
        request.common.limitation
    };
    let draft = serde_json::json!({
        "schema_version": 1,
        "plan_id": request.common.plan_id,
        "host_id": request.common.host_id,
        "host_epoch": request.common.host_epoch,
        "profile_digest": request.common.profile_digest,
        "requester": request.common.requester,
        "verb": "app_lifecycle",
        "site_id": request.common.site_id,
        "action": request.action,
        "expected_effects": {
            "changes_app_unit_state": true,
            "reloads_ols": false,
            "changes_files": false,
        },
        "risk_class": "lab_only",
        "valid_from": request.common.valid_from,
        "expires_at": request.common.expires_at,
        "limitations": limitations,
    });
    emit_canonical(&draft)
}

/// Build an offline `site_credential_rotate` plan (D-100, P13).
#[derive(clap::Args)]
pub(crate) struct SiteCredentialRotateArgs {
    #[command(flatten)]
    common: AppCommon,
    #[arg(long)]
    hostname: String,
    #[arg(long, default_value = "mariadb_user_password")]
    target: String,
}

pub(crate) fn site_credential_rotate(request: SiteCredentialRotateArgs) -> ExitCode {
    let is_app_target = matches!(
        request.target.as_str(),
        "app_mariadb_password" | "app_postgresql_18_password"
    );
    let limitations = if request.common.limitation.is_empty() {
        vec![if is_app_target {
            "host generates fresh random app DB password locally; no secret enters the plan"
                .to_owned()
        } else {
            "host generates fresh 32-byte random MariaDB password locally; no secret enters the plan"
                .to_owned()
        }]
    } else {
        request.common.limitation
    };
    let draft = if is_app_target {
        serde_json::json!({
            "schema_version": 2,
            "plan_id": request.common.plan_id,
            "host_id": request.common.host_id,
            "host_epoch": request.common.host_epoch,
            "profile_digest": request.common.profile_digest,
            "requester": request.common.requester,
            "verb": "site_credential_rotate",
            "site_id": request.common.site_id,
            "hostname": request.hostname,
            "target": request.target,
            "expected_effects": {
                "rotates_db_password": true,
                "updates_db_cnf": false,
                "restarts_site_php": false,
                "updates_app_env": true,
                "restarts_app_unit": true,
                "traffic_activation": false,
                "network_access": false,
                "secret_in_plan": false,
            },
            "risk_class": "lab_only",
            "valid_from": request.common.valid_from,
            "expires_at": request.common.expires_at,
            "limitations": limitations,
        })
    } else {
        serde_json::json!({
            "schema_version": 1,
            "plan_id": request.common.plan_id,
            "host_id": request.common.host_id,
            "host_epoch": request.common.host_epoch,
            "profile_digest": request.common.profile_digest,
            "requester": request.common.requester,
            "verb": "site_credential_rotate",
            "site_id": request.common.site_id,
            "hostname": request.hostname,
            "target": request.target,
            "expected_effects": {
                "rotates_db_password": true,
                "updates_db_cnf": true,
                "restarts_site_php": true,
                "traffic_activation": false,
                "network_access": false,
                "secret_in_plan": false,
            },
            "risk_class": "lab_only",
            "valid_from": request.common.valid_from,
            "expires_at": request.common.expires_at,
            "limitations": limitations,
        })
    };
    emit_canonical(&draft)
}

fn emit_canonical(draft: &serde_json::Value) -> ExitCode {
    let prepared = match PreparedPlan::decode(draft.to_string().as_bytes()) {
        Ok(prepared) => prepared,
        Err(_) => return fail(ErrorCode::InvalidRequest.exit_code(), "INVALID_PLAN"),
    };
    if io::stdout().lock().write_all(prepared.as_bytes()).is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(7)
    }
}

fn fail(status: u8, name: &str) -> ExitCode {
    let _ = writeln!(
        io::stderr(),
        "{{\"scope\":\"plan_create\",\"error\":\"{name}\",\"authority\":\"none\"}}"
    );
    ExitCode::from(status)
}
