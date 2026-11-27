//! Local unprivileged coordinator and offline inventory metadata maintenance.
#![warn(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "W672: production code returns errors; tests may unwrap (clippy.toml)"
)]

mod delegation;
mod diagnose;
mod drift;
mod experiment_card;
mod fleet;
mod host;
mod php_profiles;
mod remote_gateway;
mod site_cron;
mod traffic_budget;
mod valkey_policy;

use clap::{ArgGroup, Parser};
use rustiron_contracts::{
    ErrorCode, MAX_RESPONSE_BYTES, decode_inventory_snapshot, encode_inventory_snapshot, local,
};
use rustiron_core::InventoryStore;
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::ExitCode,
};

#[derive(Parser)]
#[command(
    name = "rustiron-control",
    about = "Unprivileged local Rustiron coordinator"
)]
#[command(group(ArgGroup::new("mode").args(["socket","init_state","import_observations","export_observations","host_status","merge_observation","explain_drift","background_budget","evaluate_experiment","aggregate_hosts","verify_gateway_request","verify_php_profile","verify_valkey_plan","verify_delegation","site_cron"]).required(true)))]
struct Args {
    /// Fresh socket pathname in an existing private directory owned by this user.
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Root-owned executor socket, configured at startup for status queries.
    #[arg(long, requires = "socket")]
    executor_socket: Option<PathBuf>,
    /// Existing canonical mode-0700 coordinator state directory.
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Explicitly initialize a new database; does not declare an empty host report.
    #[arg(long, requires = "state_dir")]
    init_state: bool,
    /// Offline bounded metadata replacement; no adoption or host changes.
    #[arg(long, requires = "state_dir")]
    import_observations: Option<PathBuf>,
    /// Offline consistent metadata export as one JSON object.
    #[arg(long, requires = "state_dir")]
    export_observations: bool,
    /// Read-only host status (counters, disk, fixed service states) as one JSON object.
    #[arg(long)]
    host_status: bool,
    /// Merge unprivileged host status into a journal observation and print it.
    #[arg(long)]
    merge_observation: Option<PathBuf>,
    /// Replace this regular file with the current host status (0600, no follow).
    #[arg(long)]
    write_status: Option<PathBuf>,
    /// Append one compact sample to this regular file, capped at 2880 rows.
    #[arg(long)]
    record_samples: Option<PathBuf>,
    /// W465 (P04): print read-only diagnoses of the host status (and of the
    /// merged observation, when given) instead of the status. Repairs nothing.
    #[arg(long)]
    diagnose: bool,
    /// W615 (P24): explain ownership-aware drift (package updates, manual edits,
    /// unknown/foreign resources) and explicit resolution choices for a merged
    /// observation JSON file. Strictly read-only; never resets or edits state.
    #[arg(long)]
    explain_drift: Option<PathBuf>,
    /// W616 (P25): evaluate traffic-aware background work budget for a merged
    /// observation JSON file. Strictly read-only; never hides missed jobs or
    /// tunes databases.
    #[arg(long)]
    background_budget: Option<PathBuf>,
    /// With --background-budget: job class (`site_cron`, `backup_capture`, `maintenance`).
    #[arg(long, requires = "background_budget", default_value = "site_cron")]
    job: String,
    /// With --background-budget: optional single site identifier filter.
    #[arg(long, requires = "background_budget")]
    site: Option<String>,
    /// With --background-budget: operator override (`auto`, `force_run`, `disable`).
    #[arg(long, requires = "background_budget", default_value = "auto")]
    budget_override: String,
    /// With --background-budget: seconds elapsed past the job's scheduled start.
    #[arg(long, requires = "background_budget", default_value_t = 0)]
    backlog_secs: u64,
    /// With --background-budget: consecutive traffic deferrals recorded so far.
    #[arg(long, requires = "background_budget", default_value_t = 0)]
    deferrals: u32,
    /// Optional Unix timestamp override for deterministic checks (`--background-budget`, `--aggregate-hosts`).
    #[arg(long)]
    now: Option<u64>,
    /// W617 (P22): evaluate a preregistered Experiment Card JSON file and emit
    /// retain/revert evidence. Strictly read-only; refuses automatic DB changes
    /// and unsafe private caching.
    #[arg(long)]
    evaluate_experiment: Option<PathBuf>,
    /// W618 (P28 Slice 1): aggregate independent per-host observations into a
    /// strictly read-only multi-host inventory without distributed implicit
    /// authority.
    #[arg(long)]
    aggregate_hosts: Option<PathBuf>,
    /// W619 (P18 Slice 1): verify an SSH forced-command remote automation
    /// gateway request and short-lived capability token. Strictly read-only.
    #[arg(long)]
    verify_gateway_request: Option<PathBuf>,
    /// W621 (P20 Slice 1): verify a deliberate second PHP profile placement or
    /// version-switch plan against EOL, isolation, and rollback preconditions.
    #[arg(long)]
    verify_php_profile: Option<PathBuf>,
    /// W622 (P21 Slice 1): verify an optional per-site Valkey plan against
    /// workload benefit, Unix-socket/UID/MCS/namespace isolation, memory/eviction,
    /// and private/auth/cart/checkout safety rules.
    #[arg(long)]
    verify_valkey_plan: Option<PathBuf>,
    /// W623 (CP07 Slice 1): verify a post-v1.0 multi-tenant delegation ACL,
    /// quota, ownership-transfer, and cross-account isolation policy.
    #[arg(long)]
    verify_delegation: Option<PathBuf>,
    /// Concise human output (`--diagnose`, `--explain-drift`, `--background-budget`, `--evaluate-experiment`, `--aggregate-hosts`, `--verify-gateway-request`, `--verify-php-profile`, `--verify-valkey-plan`, `--verify-delegation`).
    #[arg(long)]
    human: bool,
    /// D-083 (P05): with --diagnose, print the Uptime Kuma push query
    /// (`status=up|down&msg=...&ping=`) for the alert check-in.
    #[arg(long, requires = "diagnose", conflicts_with = "human")]
    alert_line: bool,
    /// W466 (D-061): ask each managed site's PHP to run its due WordPress
    /// jobs through the local OLS listener, once.
    #[arg(long)]
    site_cron: bool,
}

fn main() -> ExitCode {
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
            return if error.print().is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(7)
            };
        }
        Err(_) => {
            eprintln!("Invalid coordinator arguments; use --help.");
            return ExitCode::from(2);
        }
    };
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => {
            eprintln!("{}", code.message());
            ExitCode::from(code.exit_code())
        }
    }
}

fn run(args: Args) -> Result<(), ErrorCode> {
    local::operator_uid()?;
    if args.site_cron {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ErrorCode::DependencyUnavailable)?
            .as_secs();
        let _lock = match site_cron::hold_lock(std::path::Path::new(site_cron::LOCK), now) {
            Ok(lock) => lock,
            Err(site_cron::LockError::Busy) => {
                // Another run is asking the sites now, or one started less
                // than a minute ago; this one asks nothing.
                writeln!(
                    std::io::stdout(),
                    "{}",
                    serde_json::json!({"scope": "site_cron", "busy": true})
                )
                .map_err(local::io_code)?;
                return Ok(());
            }
            Err(site_cron::LockError::Unavailable) => return Err(ErrorCode::DependencyUnavailable),
        };
        let text = host::read_small(host::OLS_MAP).ok_or(ErrorCode::DependencyUnavailable)?;
        let lines = site_cron::run(&text).map_err(|()| ErrorCode::DependencyUnavailable)?;
        let mut out = std::io::stdout().lock();
        for line in lines {
            writeln!(out, "{line}").map_err(local::io_code)?;
        }
        return Ok(());
    }
    if let Some(path) = &args.explain_drift {
        let merged = host::read_observation(path)?;
        let report = drift::explain(&merged);
        let text = if args.human {
            drift::human(&report)
        } else {
            format!("{report}\n")
        };
        return std::io::stdout()
            .lock()
            .write_all(text.as_bytes())
            .map_err(local::io_code);
    }
    if let Some(path) = &args.background_budget {
        let job = traffic_budget::JobKind::parse(&args.job).ok_or(ErrorCode::InvalidRequest)?;
        let override_mode = traffic_budget::OverrideMode::parse(&args.budget_override)
            .ok_or(ErrorCode::InvalidRequest)?;
        let now = match args.now {
            Some(ts) => ts,
            None => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| ErrorCode::DependencyUnavailable)?
                .as_secs(),
        };
        let merged = host::read_observation(path)?;
        let report = traffic_budget::evaluate(
            &merged,
            &traffic_budget::BudgetInput {
                job,
                site: args.site.as_deref(),
                override_mode,
                backlog_seconds: args.backlog_secs,
                consecutive_deferrals: args.deferrals,
                now,
            },
        );
        let text = if args.human {
            traffic_budget::human(&report)
        } else {
            format!("{report}\n")
        };
        return std::io::stdout()
            .lock()
            .write_all(text.as_bytes())
            .map_err(local::io_code);
    }
    if let Some(path) = &args.evaluate_experiment {
        let card = host::read_observation(path)?;
        let report = experiment_card::evaluate(&card);
        let text = if args.human {
            experiment_card::human(&report)
        } else {
            format!("{report}\n")
        };
        return std::io::stdout()
            .lock()
            .write_all(text.as_bytes())
            .map_err(local::io_code);
    }
    if let Some(path) = &args.aggregate_hosts {
        let now = match args.now {
            Some(ts) => ts,
            None => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| ErrorCode::DependencyUnavailable)?
                .as_secs(),
        };
        let manifest = host::read_observation(path)?;
        let report = fleet::aggregate(&manifest, now);
        let text = if args.human {
            fleet::human(&report)
        } else {
            format!("{report}\n")
        };
        return std::io::stdout()
            .lock()
            .write_all(text.as_bytes())
            .map_err(local::io_code);
    }
    if let Some(path) = &args.verify_gateway_request {
        let now = match args.now {
            Some(ts) => ts,
            None => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| ErrorCode::DependencyUnavailable)?
                .as_secs(),
        };
        let req = host::read_observation(path)?;
        let report = remote_gateway::evaluate(&req, now);
        let text = if args.human {
            remote_gateway::human(&report)
        } else {
            format!("{report}\n")
        };
        return std::io::stdout()
            .lock()
            .write_all(text.as_bytes())
            .map_err(local::io_code);
    }
    if let Some(path) = &args.verify_php_profile {
        let now = match args.now {
            Some(ts) => ts,
            None => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| ErrorCode::DependencyUnavailable)?
                .as_secs(),
        };
        let plan = host::read_observation(path)?;
        let report = php_profiles::verify(&plan, now);
        let text = if args.human {
            php_profiles::human(&report)
        } else {
            format!("{report}\n")
        };
        return std::io::stdout()
            .lock()
            .write_all(text.as_bytes())
            .map_err(local::io_code);
    }
    if let Some(path) = &args.verify_valkey_plan {
        let plan = host::read_observation(path)?;
        let report = valkey_policy::verify(&plan);
        let text = if args.human {
            valkey_policy::human(&report)
        } else {
            format!("{report}\n")
        };
        return std::io::stdout()
            .lock()
            .write_all(text.as_bytes())
            .map_err(local::io_code);
    }
    if let Some(path) = &args.verify_delegation {
        let policy = host::read_observation(path)?;
        let report = delegation::verify(&policy);
        let text = if args.human {
            delegation::human(&report)
        } else {
            format!("{report}\n")
        };
        return std::io::stdout()
            .lock()
            .write_all(text.as_bytes())
            .map_err(local::io_code);
    }
    if args.host_status
        || args.merge_observation.is_some()
        || args.write_status.is_some()
        || args.record_samples.is_some()
        || args.diagnose
    {
        return host_command(&args);
    }
    if args.init_state {
        InventoryStore::initialize(args.state_dir.as_deref().ok_or(ErrorCode::InvalidRequest)?)?;
        return Ok(());
    }
    if let Some(path) = args.import_observations {
        let snapshot = read_report(&path)?;
        return InventoryStore::open(args.state_dir.as_deref().ok_or(ErrorCode::InvalidRequest)?)?
            .replace(&snapshot);
    }
    if args.export_observations {
        let snapshot =
            InventoryStore::open(args.state_dir.as_deref().ok_or(ErrorCode::InvalidRequest)?)?
                .export()?;
        let mut bytes =
            encode_inventory_snapshot(&snapshot).map_err(|error| error.api_error().code())?;
        bytes.push(b'\n');
        return std::io::stdout()
            .lock()
            .write_all(&bytes)
            .map_err(local::io_code);
    }
    let store = args
        .state_dir
        .as_deref()
        .map(InventoryStore::open)
        .transpose()?;
    let mut coordinator = rustiron_control::Coordinator::new(store);
    if let Some(path) = args.executor_socket {
        coordinator = coordinator
            .with_executor(rustiron_control::executor_transport::ExecutorTransport::new(path)?);
    }
    let listener =
        rustiron_control::bind(args.socket.as_deref().ok_or(ErrorCode::InvalidRequest)?)?;
    coordinator.serve(listener)
}

fn host_command(args: &Args) -> Result<(), ErrorCode> {
    let status = host::status();
    if let Some(path) = &args.write_status {
        host::write_json(path, &status)?;
    }
    let samples = args
        .record_samples
        .as_deref()
        .map(|path| host::record_samples(path, &status))
        .transpose()?;
    let output = if let Some(path) = &args.merge_observation {
        host::merge_observation(host::read_observation(path)?, status, samples.as_ref())?
    } else if args.diagnose {
        serde_json::json!({ "machine": status })
    } else {
        status
    };
    if args.diagnose {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .map_err(|_| ErrorCode::DependencyUnavailable)?;
        let diagnosis = diagnose::diagnose(&output, now);
        let text = if args.alert_line {
            format!("{}\n", diagnose::alert_query(&diagnosis))
        } else if args.human {
            diagnose::human(&diagnosis)
        } else {
            format!("{diagnosis}\n")
        };
        return std::io::stdout()
            .lock()
            .write_all(text.as_bytes())
            .map_err(local::io_code);
    }
    writeln!(std::io::stdout().lock(), "{output}").map_err(local::io_code)
}

fn read_report(path: &Path) -> Result<rustiron_contracts::InventorySnapshot, ErrorCode> {
    let flags = (rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOFOLLOW)
        .bits()
        .try_into()
        .map_err(|_| ErrorCode::InvalidRequest)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .map_err(local::io_code)?;
    if !file.metadata().map_err(local::io_code)?.is_file() {
        return Err(ErrorCode::InvalidRequest);
    }
    let mut bytes = Vec::new();
    file.take((MAX_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(local::io_code)?;
    decode_inventory_snapshot(&bytes).map_err(|error| error.api_error().code())
}
