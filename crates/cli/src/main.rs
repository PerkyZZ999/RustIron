//! Local human/JSON CLI; no privileged operations or private signing material.
#![warn(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "W672: production code returns errors; tests may unwrap (clippy.toml)"
)]

mod apply_cli;
mod destination_digest;
mod export_plan;
mod file_input;
mod plan_create;
mod plan_store;
mod retention_plan;
mod review_file;
mod schedule;
mod state;
mod uninstall;

use clap::{Parser, Subcommand, ValueEnum};
use rustiron_contracts::{
    local::{self, DEADLINE},
    *,
};
use std::{
    ffi::OsString,
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
    time::Instant,
};

#[derive(Clone, Copy, ValueEnum)]
enum Output {
    Human,
    Json,
}

#[derive(Parser)]
#[command(
    name = "rustiron",
    about = "Inspect Rustiron through the local development coordinator"
)]
struct Args {
    /// Socket pathname in the current user's private mode-0700 directory.
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Output representation; errors also use this format.
    #[arg(long, value_enum, default_value = "human", global = true)]
    output: Output,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Inspect accessible OS metadata; hosting acceptance remains unknown.
    Doctor,
    /// Query coordinator inventory (unavailable until W004).
    Site {
        #[command(subcommand)]
        command: SiteCommand,
    },
    /// Export one self-attested recovery receipt.
    Evidence {
        #[command(subcommand)]
        command: EvidenceCommand,
    },
    /// Inspect an operation's recorded executor state.
    Operation {
        #[command(subcommand)]
        command: OperationCommand,
    },
    /// Plan a management-only uninstall. Site data stays.
    Uninstall {
        #[command(subcommand)]
        command: UninstallCommand,
    },
    /// Export coordinator metadata or compare it with an executor observation.
    State {
        #[command(subcommand)]
        command: StateCommand,
    },
    /// Work with prepared plans.
    Plan {
        #[command(subcommand)]
        command: Box<PlanCommand>,
    },
    /// D-035: runs of a standing capture grant. Grants nothing.
    Schedule {
        #[command(subcommand)]
        command: ScheduleCommand,
    },
    /// D-079: offline backup retention work for the retention authority.
    Backup {
        #[command(subcommand)]
        command: BackupCommand,
    },
}

#[derive(Subcommand)]
enum BackupCommand {
    /// D-089: the `restic dump` of one recorded capture's database dump,
    /// from a `restic snapshots --json` listing read with the site's fetch
    /// key and an executor observation. Offline; changes nothing. Exits 3
    /// when the capture is not a listed, recorded capture of the site with
    /// its dump.
    ExportPlan {
        /// `restic snapshots --json` of the site's repository.
        #[arg(long)]
        snapshots: PathBuf,
        /// Executor `observe` JSON with the recorded captures.
        #[arg(long)]
        observation: PathBuf,
        /// The site ID.
        #[arg(long)]
        site: String,
        /// The capture's operation ID.
        #[arg(long)]
        capture: String,
    },
    /// Which snapshots of one site's repository the retention authority may
    /// forget, from a `restic snapshots --json` listing and an executor
    /// observation. Offline; changes nothing. Exits 3 when a recorded
    /// capture is missing from the listing.
    RetentionPlan {
        /// `restic snapshots --json` of the site's repository.
        #[arg(long)]
        snapshots: PathBuf,
        /// Executor `observe` JSON with the recorded captures.
        #[arg(long)]
        observation: PathBuf,
        /// The site ID.
        #[arg(long)]
        site: String,
        /// Keep every recorded capture finished within this many days.
        #[arg(long, default_value_t = retention_plan::MIN_KEEP_DAYS,
              value_parser = clap::value_parser!(u32).range(i64::from(retention_plan::MIN_KEEP_DAYS)..=i64::from(retention_plan::MAX_KEEP_DAYS)))]
        keep_within_days: u32,
        /// Evaluation time in seconds since the epoch (default: now).
        #[arg(long)]
        now: Option<i64>,
    },
}

#[derive(Subcommand)]
enum ScheduleCommand {
    /// List every window and its run identities, offline.
    Runs {
        /// Folder with `plan.json`, `grant.json` and `grant.json.sig`.
        #[arg(long)]
        dir: PathBuf,
    },
    /// Submit the open window's run of each named site, then report the status.
    Run {
        /// Folder with `plan.json`, `grant.json` and `grant.json.sig`.
        #[arg(long)]
        dir: PathBuf,
        /// After the reply deadline, wait up to this many seconds for each
        /// run's recorded state.
        #[arg(long, default_value_t = apply_cli::DEFAULT_WAIT_SECONDS,
              value_parser = clap::value_parser!(u64).range(0..=apply_cli::MAX_WAIT_SECONDS))]
        wait_seconds: u64,
        /// Alert when a site's newest snapshot is older than this (D-010: 24 h).
        #[arg(long, default_value_t = 86_400)]
        rpo_target_seconds: u64,
    },
    /// Report every window, missed runs, and the snapshot age of each site.
    Status {
        /// Folder with `plan.json`, `grant.json` and `grant.json.sig`.
        #[arg(long)]
        dir: PathBuf,
        /// Alert when a site's newest snapshot is older than this (D-010: 24 h).
        #[arg(long, default_value_t = 86_400)]
        rpo_target_seconds: u64,
    },
}

#[derive(Subcommand)]
enum UninstallCommand {
    /// Show the move set. Refuses while any recorded site is still managed.
    Plan {
        /// `rustiron-lab-observation/1` JSON.
        #[arg(long)]
        observation: PathBuf,
    },
    /// Move the closed management set under a prefix. Does not delete site data.
    Apply {
        /// Root of the tree to edit. Tests use a temporary directory.
        #[arg(long)]
        prefix: PathBuf,
        /// `rustiron-lab-observation/1` JSON.
        #[arg(long)]
        observation: PathBuf,
    },
}

#[derive(Subcommand)]
enum StateCommand {
    /// Write the coordinator inventory snapshot. This is not the executor journal.
    Export {
        /// Private mode-0700 directory for the coordinator store.
        #[arg(long)]
        state_dir: PathBuf,
    },
    /// Compare inventory site identities with an executor observation file.
    Compare {
        /// Private mode-0700 directory for the coordinator store.
        #[arg(long)]
        state_dir: PathBuf,
        /// `rustiron-lab-observation/1` JSON. Extra fields are ignored.
        #[arg(long)]
        observation: PathBuf,
    },
}

#[derive(Subcommand)]
enum PlanCommand {
    /// Build a closed plan for offline review. Stdout is the canonical plan.
    Create {
        #[command(subcommand)]
        command: CreateCommand,
    },
    /// Review all fields of a closed plan file offline.
    ReviewFile { path: PathBuf },
    /// Validate an HTTPS S3 destination projection and compute its offline digest.
    DestinationDigest { path: PathBuf },
    /// Store the canonical bytes of one validated plan. This does not sign or submit it.
    ImportFile {
        /// Private mode-0700 directory for the plan store.
        #[arg(long)]
        plan_dir: PathBuf,
        path: PathBuf,
    },
    /// Submit a stored plan with a separate grant and signature. The coordinator does not sign.
    Apply {
        /// Private mode-0700 directory for the plan store.
        #[arg(long)]
        plan_dir: PathBuf,
        #[arg(value_parser = parse_id)]
        plan_id: Id,
        #[arg(long)]
        grant_file: PathBuf,
        #[arg(long)]
        signature_file: PathBuf,
        #[arg(long, value_parser = parse_id)]
        operation_id: Id,
        #[arg(long, value_parser = parse_id)]
        idempotency_key: Id,
    },
    /// Show one stored plan in full. This does not sign, approve, or submit it.
    Inspect {
        /// Private mode-0700 directory for the plan store.
        #[arg(long)]
        plan_dir: PathBuf,
        #[arg(value_parser = parse_id)]
        plan_id: Id,
    },
    /// Write one stored plan's canonical bytes to stdout.
    Export {
        /// Private mode-0700 directory for the plan store.
        #[arg(long)]
        plan_dir: PathBuf,
        #[arg(value_parser = parse_id)]
        plan_id: Id,
    },
    /// Submit separately prepared signed files through the coordinator.
    ApplyFile {
        #[arg(long)]
        plan_file: PathBuf,
        #[arg(long)]
        grant_file: PathBuf,
        #[arg(long)]
        signature_file: PathBuf,
        #[arg(long, value_parser = parse_id)]
        operation_id: Id,
        #[arg(long, value_parser = parse_id)]
        idempotency_key: Id,
        /// If the coordinator's reply deadline passes, wait up to this many
        /// seconds for the operation's recorded state (0 = do not wait).
        #[arg(long, default_value_t = apply_cli::DEFAULT_WAIT_SECONDS,
              value_parser = clap::value_parser!(u64).range(0..=apply_cli::MAX_WAIT_SECONDS))]
        wait_seconds: u64,
    },
}

#[derive(Subcommand)]
enum CreateCommand {
    /// A site provision that creates an account and database and does not activate traffic.
    SiteProvision {
        #[command(flatten)]
        header: plan_create::PlanHeader,
        #[arg(long)]
        site_id: String,
        #[arg(long)]
        hostname: String,
        #[arg(long)]
        recipe: String,
        #[arg(long)]
        recipe_digest: String,
        #[arg(long)]
        observed_at: u64,
        #[arg(long)]
        valid_from: u64,
        #[arg(long)]
        expires_at: u64,
        #[arg(long)]
        limitation: Vec<String>,
        /// Signed hard block limit in KiB; with `--quota-inode-hard`, makes a
        /// schema v2 plan. Without both, the executor applies its enrolled policy.
        #[arg(long, requires = "quota_inode_hard")]
        quota_block_hard_kib: Option<u64>,
        /// Signed hard inode limit; requires `--quota-block-hard-kib`.
        #[arg(long, requires = "quota_block_hard_kib")]
        quota_inode_hard: Option<u64>,
    },
    /// Hand one site's vhost outside Rustiron. Nothing is deleted.
    SiteEject {
        #[command(flatten)]
        header: plan_create::PlanHeader,
        #[arg(long)]
        site_id: String,
        #[arg(long)]
        hostname: Option<String>,
        #[arg(long, requires = "hostname")]
        alias_hostname: Option<String>,
        #[arg(long)]
        expected_generation: String,
        #[arg(long)]
        expected_digest: String,
        #[arg(long)]
        observed_at: u64,
        #[arg(long)]
        valid_from: u64,
        #[arg(long)]
        expires_at: u64,
        #[arg(long)]
        compensation_until: u64,
        #[arg(long)]
        limitation: Vec<String>,
    },
    /// Name the sites an OLS generation should serve. This does not reload the server.
    ConfigActivate {
        #[command(flatten)]
        header: plan_create::PlanHeader,
        #[arg(long)]
        site_id: Vec<String>,
        #[arg(long)]
        expected_generation: String,
        #[arg(long)]
        expected_digest: String,
        #[arg(long)]
        observed_at: u64,
        #[arg(long)]
        valid_from: u64,
        #[arg(long)]
        expires_at: u64,
        #[arg(long)]
        compensation_until: u64,
        #[arg(long)]
        limitation: Vec<String>,
    },
    /// Name one site for a lab capture. This does not read or copy the site.
    BackupCapture {
        #[command(flatten)]
        header: plan_create::PlanHeader,
        #[arg(long)]
        site_id: String,
        #[arg(long)]
        valid_from: u64,
        #[arg(long)]
        expires_at: u64,
        #[arg(long)]
        limitation: Vec<String>,
    },
    /// Name one snapshot for a throwaway probe. This does not restore the source site.
    RestoreProbe {
        #[command(flatten)]
        header: plan_create::PlanHeader,
        #[arg(long)]
        site_id: String,
        #[arg(long)]
        snapshot_id: String,
        #[arg(long)]
        valid_from: u64,
        #[arg(long)]
        expires_at: u64,
        #[arg(long)]
        limitation: Vec<String>,
    },
    /// W372: re-adopt one existing site after an epoch rotation. Records
    /// ownership only after the executor verifies the host; changes nothing.
    SiteReadopt {
        #[command(flatten)]
        readopt: plan_create::Readopt,
        #[arg(long)]
        site_id: String,
        #[arg(long)]
        hostname: String,
        /// The site's live hard block limit in KiB (from the export).
        #[arg(long)]
        quota_block_hard_kib: u64,
        /// The site's live hard inode limit (from the export).
        #[arg(long)]
        quota_inode_hard: u64,
    },
    /// W372: adopt the live OLS generation after an epoch rotation. Records
    /// it only when the executor renders the same bytes; changes nothing.
    SiteReadoptGeneration {
        #[command(flatten)]
        readopt: plan_create::Readopt,
        /// Every site the live generation serves.
        #[arg(long)]
        site_id: Vec<String>,
        #[arg(long)]
        expected_generation: String,
        #[arg(long)]
        expected_digest: String,
    },
    /// Prepare a product capture plan for offline review.
    ProductBackupCapture {
        #[command(flatten)]
        backup: plan_create::ProductBackup,
        /// Fixed capture recipe ID.
        #[arg(long)]
        recipe_id: String,
    },
    /// D-035: prepare a standing capture plan (schema 3) for offline review.
    ProductStandingCapture {
        #[command(flatten)]
        standing: plan_create::StandingCapture,
    },
    /// Prepare a product restore probe plan for offline review.
    ProductRestoreProbe {
        #[command(flatten)]
        backup: plan_create::ProductBackup,
        /// Full snapshot ID in the destination repository.
        #[arg(long)]
        snapshot_id: String,
        /// Fixed restore sandbox profile ID.
        #[arg(long)]
        profile_id: String,
    },
    /// Prepare a zone import from a canonical zone file.
    DnsZoneImport {
        #[command(flatten)]
        dns: plan_create::DnsPlan,
        /// Canonical zone text whose exact bytes the plan names.
        #[arg(long)]
        zone_file: PathBuf,
    },
    /// Prepare a record change from reviewed operations and expected set digests.
    DnsChange {
        #[command(flatten)]
        dns: plan_create::DnsPlan,
        /// A JSON array of DNS operations in the order to apply them.
        #[arg(long)]
        operations_file: PathBuf,
    },
    /// D-099: prepare a Node.js or Bun app provision plan for offline review.
    AppProvision {
        #[command(flatten)]
        app: Box<plan_create::AppProvisionArgs>,
    },
    /// D-099: prepare a signed prebuilt app release deployment plan.
    AppDeploy {
        #[command(flatten)]
        app: Box<plan_create::AppDeployArgs>,
    },
    /// D-099: prepare a signed start, stop, or restart plan for an app unit.
    AppLifecycle {
        #[command(flatten)]
        app: plan_create::AppLifecycleArgs,
    },
    /// D-100: prepare a signed per-site MariaDB credential rotation plan (zero secrets in plan).
    SiteCredentialRotate {
        #[command(flatten)]
        rotate: plan_create::SiteCredentialRotateArgs,
    },
}

#[derive(Subcommand)]
enum EvidenceCommand {
    /// Read the receipt recorded for one operation.
    Export {
        #[arg(value_parser = parse_id)]
        receipt_id: Id,
    },
}

#[derive(Subcommand)]
enum OperationCommand {
    Status {
        #[arg(value_parser = parse_id)]
        operation_id: Id,
    },
}

#[derive(Subcommand)]
enum SiteCommand {
    List {
        #[arg(long, default_value = "20", value_parser = parse_limit)]
        limit: PageLimit,
        #[arg(long, value_parser = parse_id)]
        cursor: Option<Id>,
    },
    Inspect {
        #[arg(value_parser = parse_id)]
        site_id: Id,
    },
}

fn parse_id(value: &str) -> Result<Id, &'static str> {
    Id::try_from(value.to_owned()).map_err(|_| "invalid ID")
}
fn parse_limit(value: &str) -> Result<PageLimit, &'static str> {
    value
        .parse::<u16>()
        .ok()
        .and_then(|value| PageLimit::try_from(value).ok())
        .ok_or("invalid limit")
}

fn main() -> ExitCode {
    let raw: Vec<OsString> = std::env::args_os().collect();
    let args = match Args::try_parse_from(&raw) {
        Ok(args) => args,
        Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
            return if error.print().is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(7)
            };
        }
        Err(_) => {
            let json = raw.iter().any(|arg| arg == "--output=json")
                || raw
                    .windows(2)
                    .any(|args| args[0] == "--output" && args[1] == "json");
            return emit(
                &failure(ErrorCode::InvalidRequest),
                if json { Output::Json } else { Output::Human },
            );
        }
    };
    let command = match args.command {
        Command::Doctor => ReadCommand::Doctor,
        Command::Site {
            command: SiteCommand::List { cursor, limit },
        } => ReadCommand::SiteList { cursor, limit },
        Command::Site {
            command: SiteCommand::Inspect { site_id },
        } => ReadCommand::SiteInspect { site_id },
        Command::Operation {
            command: OperationCommand::Status { operation_id },
        } => ReadCommand::OperationStatus { operation_id },
        Command::Evidence {
            command: EvidenceCommand::Export { receipt_id },
        } => ReadCommand::EvidenceExport {
            operation_id: receipt_id,
        },
        Command::Uninstall { command } => {
            return match command {
                UninstallCommand::Plan { observation } => {
                    uninstall::plan(&observation, args.output)
                }
                UninstallCommand::Apply {
                    prefix,
                    observation,
                } => uninstall::apply(&prefix, &observation, args.output),
            };
        }
        Command::State { command } => {
            return match command {
                StateCommand::Export { state_dir } => state::export(&state_dir, args.output),
                StateCommand::Compare {
                    state_dir,
                    observation,
                } => state::compare(&state_dir, &observation, args.output),
            };
        }
        Command::Backup {
            command:
                BackupCommand::ExportPlan {
                    snapshots,
                    observation,
                    site,
                    capture,
                },
        } => {
            return export_plan::run(&snapshots, &observation, &site, &capture, args.output);
        }
        Command::Backup {
            command:
                BackupCommand::RetentionPlan {
                    snapshots,
                    observation,
                    site,
                    keep_within_days,
                    now,
                },
        } => {
            return retention_plan::run(
                &snapshots,
                &observation,
                &site,
                keep_within_days,
                now,
                args.output,
            );
        }
        Command::Schedule { command } => {
            return match command {
                ScheduleCommand::Runs { dir } => schedule::runs(&dir, args.output),
                ScheduleCommand::Run {
                    dir,
                    wait_seconds,
                    rpo_target_seconds,
                } => match args.socket.as_deref() {
                    Some(socket) => schedule::run(
                        socket,
                        &dir,
                        args.output,
                        std::time::Duration::from_secs(wait_seconds),
                        rpo_target_seconds,
                    ),
                    None => emit(&failure(ErrorCode::InvalidRequest), args.output),
                },
                ScheduleCommand::Status {
                    dir,
                    rpo_target_seconds,
                } => match args.socket.as_deref() {
                    Some(socket) => schedule::status(socket, &dir, args.output, rpo_target_seconds),
                    None => emit(&failure(ErrorCode::InvalidRequest), args.output),
                },
            };
        }
        Command::Plan { command } => {
            return match *command {
                PlanCommand::Create { command } => match command {
                    CreateCommand::SiteProvision {
                        header,
                        site_id,
                        hostname,
                        recipe,
                        recipe_digest,
                        observed_at,
                        valid_from,
                        expires_at,
                        limitation,
                        quota_block_hard_kib,
                        quota_inode_hard,
                    } => plan_create::site_provision(plan_create::SiteProvision {
                        header,
                        site_id,
                        hostname,
                        recipe,
                        recipe_digest,
                        observed_at,
                        valid_from,
                        expires_at,
                        limitations: limitation,
                        quota: quota_block_hard_kib.zip(quota_inode_hard),
                    }),
                    CreateCommand::SiteEject {
                        header,
                        site_id,
                        hostname,
                        alias_hostname,
                        expected_generation,
                        expected_digest,
                        observed_at,
                        valid_from,
                        expires_at,
                        compensation_until,
                        limitation,
                    } => plan_create::site_eject(plan_create::SiteEject {
                        header,
                        site_id,
                        hostname,
                        alias_hostname,
                        expected_generation,
                        expected_digest,
                        observed_at,
                        valid_from,
                        expires_at,
                        compensation_until,
                        limitations: limitation,
                    }),
                    CreateCommand::ConfigActivate {
                        header,
                        site_id,
                        expected_generation,
                        expected_digest,
                        observed_at,
                        valid_from,
                        expires_at,
                        compensation_until,
                        limitation,
                    } => plan_create::config_activate(plan_create::ConfigActivate {
                        header,
                        site_ids: site_id,
                        expected_generation,
                        expected_digest,
                        observed_at,
                        valid_from,
                        expires_at,
                        compensation_until,
                        limitations: limitation,
                    }),
                    CreateCommand::BackupCapture {
                        header,
                        site_id,
                        valid_from,
                        expires_at,
                        limitation,
                    } => plan_create::backup_capture(plan_create::BackupCapture {
                        header,
                        site_id,
                        valid_from,
                        expires_at,
                        limitations: limitation,
                    }),
                    CreateCommand::RestoreProbe {
                        header,
                        site_id,
                        snapshot_id,
                        valid_from,
                        expires_at,
                        limitation,
                    } => plan_create::restore_probe(plan_create::RestoreProbe {
                        header,
                        site_id,
                        snapshot_id,
                        valid_from,
                        expires_at,
                        limitations: limitation,
                    }),
                    CreateCommand::SiteReadopt {
                        readopt,
                        site_id,
                        hostname,
                        quota_block_hard_kib,
                        quota_inode_hard,
                    } => plan_create::site_readopt(
                        readopt,
                        plan_create::ReadoptTarget::Site {
                            site_id,
                            hostname,
                            quota: (quota_block_hard_kib, quota_inode_hard),
                        },
                    ),
                    CreateCommand::SiteReadoptGeneration {
                        readopt,
                        site_id,
                        expected_generation,
                        expected_digest,
                    } => plan_create::site_readopt(
                        readopt,
                        plan_create::ReadoptTarget::Generation {
                            site_ids: site_id,
                            expected_generation,
                            expected_digest,
                        },
                    ),
                    CreateCommand::ProductBackupCapture { backup, recipe_id } => {
                        plan_create::product_backup(
                            backup,
                            plan_create::ProductTarget::Capture { recipe_id },
                        )
                    }
                    CreateCommand::ProductStandingCapture { standing } => {
                        plan_create::standing_capture(standing)
                    }
                    CreateCommand::ProductRestoreProbe {
                        backup,
                        snapshot_id,
                        profile_id,
                    } => plan_create::product_backup(
                        backup,
                        plan_create::ProductTarget::Probe {
                            snapshot_id,
                            profile_id,
                        },
                    ),
                    CreateCommand::DnsZoneImport { dns, zone_file } => {
                        plan_create::dns_zone_import(dns, &zone_file)
                    }
                    CreateCommand::DnsChange {
                        dns,
                        operations_file,
                    } => plan_create::dns_change(dns, &operations_file),
                    CreateCommand::AppProvision { app } => plan_create::app_provision(*app),
                    CreateCommand::AppDeploy { app } => plan_create::app_deploy(*app),
                    CreateCommand::AppLifecycle { app } => plan_create::app_lifecycle(app),
                    CreateCommand::SiteCredentialRotate { rotate } => {
                        plan_create::site_credential_rotate(rotate)
                    }
                },
                PlanCommand::ReviewFile { path } => review_file::run(&path, args.output),
                PlanCommand::DestinationDigest { path } => {
                    destination_digest::run(&path, args.output)
                }
                PlanCommand::ImportFile { plan_dir, path } => {
                    plan_store::import(&plan_dir, &path, args.output)
                }
                PlanCommand::Inspect { plan_dir, plan_id } => {
                    plan_store::inspect(&plan_dir, &plan_id, args.output)
                }
                PlanCommand::Export { plan_dir, plan_id } => {
                    plan_store::export(&plan_dir, &plan_id)
                }
                PlanCommand::Apply {
                    plan_dir,
                    plan_id,
                    grant_file,
                    signature_file,
                    operation_id,
                    idempotency_key,
                } => {
                    let Some(socket) = args.socket.as_deref() else {
                        return emit(&failure(ErrorCode::InvalidRequest), args.output);
                    };
                    plan_store::apply_stored(plan_store::StoredApply {
                        directory: &plan_dir,
                        id: &plan_id,
                        socket,
                        grant_file: &grant_file,
                        signature_file: &signature_file,
                        operation_id,
                        idempotency_key,
                        output: args.output,
                    })
                }
                PlanCommand::ApplyFile {
                    plan_file,
                    grant_file,
                    signature_file,
                    operation_id,
                    idempotency_key,
                    wait_seconds,
                } => {
                    let Some(socket) = args.socket.as_deref() else {
                        return emit(&failure(ErrorCode::InvalidRequest), args.output);
                    };
                    apply_cli::run(
                        socket,
                        args.output,
                        &plan_file,
                        &grant_file,
                        &signature_file,
                        apply_cli::Attempt {
                            operation_id,
                            idempotency_key,
                            wait: std::time::Duration::from_secs(wait_seconds),
                        },
                    )
                }
            };
        }
    };
    let Some(socket) = args.socket.as_deref() else {
        return emit(&failure(ErrorCode::InvalidRequest), args.output);
    };
    let request = Request {
        request_id: crate::cli_request_id(""),
        command,
    };
    let response = exchange(socket, &request).unwrap_or_else(failure);
    emit(&response, args.output)
}

fn failure(code: ErrorCode) -> Response {
    Response {
        request_id: None,
        result: Err(ApiError::new(code)),
    }
}

fn exchange(path: &std::path::Path, request: &Request) -> Result<Response, ErrorCode> {
    let deadline = Instant::now() + DEADLINE;
    let uid = local::operator_uid()?;
    let mut stream = local::connect(path, uid, deadline)?;
    let bytes = encode_request(request).map_err(|error| error.api_error().code())?;
    local::write_frame(
        &mut stream,
        &bytes,
        MAX_REQUEST_BYTES,
        ErrorCode::RequestTooLarge,
        deadline,
    )?;
    let bytes = local::read_frame(
        &mut stream,
        MAX_RESPONSE_BYTES,
        ErrorCode::ResponseTooLarge,
        deadline,
    )?;
    let response = decode_response(&bytes).map_err(|error| error.api_error().code())?;
    if response
        .request_id
        .as_ref()
        .is_some_and(|id| id != &request.request_id)
    {
        return Err(ErrorCode::InvalidRequest);
    }
    let kind_matches = matches!(
        (&request.command, &response.result),
        (ReadCommand::Doctor, Ok(ReadData::Doctor(_)))
            | (ReadCommand::SiteList { .. }, Ok(ReadData::SiteList(_)))
            | (
                ReadCommand::SiteInspect { .. },
                Ok(ReadData::SiteInspect(_))
            )
            | (_, Err(_))
    ) || matches!((&request.command, &response.result),
        (ReadCommand::OperationStatus { operation_id }, Ok(ReadData::OperationStatus(status)))
            if *operation_id == status.operation_id)
        || matches!((&request.command, &response.result),
            (ReadCommand::EvidenceExport { operation_id }, Ok(ReadData::EvidenceExport(evidence)))
                if *operation_id == evidence.operation_id);
    if !kind_matches {
        return Err(ErrorCode::InvalidRequest);
    }
    Ok(response)
}

fn emit(response: &Response, output: Output) -> ExitCode {
    let status = response
        .result
        .as_ref()
        .err()
        .map_or(0, |error| error.code().exit_code());
    let bytes = match output {
        Output::Json => encode_response(response).map(|mut bytes| {
            bytes.push(b'\n');
            bytes
        }),
        Output::Human => render_human(response).map(String::into_bytes),
    };
    match bytes {
        Ok(bytes) if io::stdout().lock().write_all(&bytes).is_ok() => ExitCode::from(status),
        _ => ExitCode::from(7),
    }
}

/// The coordinator request ID for this CLI process: `cli-<pid><suffix>`.
#[expect(
    clippy::expect_used,
    reason = "a decimal PID with a fixed ASCII prefix and suffix is always a valid Id"
)]
pub(crate) fn cli_request_id(suffix: &str) -> Id {
    Id::try_from(format!("cli-{}{suffix}", std::process::id())).expect("PID IDs are bounded ASCII")
}
