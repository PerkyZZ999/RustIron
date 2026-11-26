//! `rustiron-mcp`: Workstation-local stdio MCP server for Rustiron.
//!
//! Default mode is strictly read-only (P17/D-101): zero mutating tools, zero
//! network listeners, zero signing keys.
//!
//! Opt-in P19 Slice 1 (`--write-tier nonproduction|production --agent-id <ID>`)
//! exposes one closed tool (`rustiron_plan_apply_approved`) that requires an
//! externally signed, non-blanket, unexpired, single-operation executor grant
//! within configured D-098 budgets and never allows self-approval or
//! destructive verbs.

mod mcp;
mod plan_summary;

use clap::Parser;
use std::{
    io::{self, BufReader},
    path::PathBuf,
    process::ExitCode,
};

#[derive(Parser)]
#[command(
    name = "rustiron-mcp",
    about = "Workstation-local stdio MCP server for Rustiron (P17 read-only default; opt-in P19 approved writes)"
)]
struct Args {
    /// Local coordinator Unix socket pathname in an owner-only mode-0700 directory.
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Maximum risk tier exposed by this MCP instance: `read` (default, P17),
    /// `nonproduction`, or `production` (P19). `destructive` is always refused.
    #[arg(long, default_value = "read")]
    write_tier: String,
    /// Separate non-human agent identifier required when `--write-tier` != `read`
    /// to enforce zero self-approval (`grant.issuer != agent_id`).
    #[arg(long)]
    agent_id: Option<String>,
    /// Maximum D-098 `envelope.max_changes` permitted for MCP-submitted plans.
    #[arg(long, default_value_t = 4)]
    max_changes: u64,
    /// Maximum D-098 `envelope.ols_reloads` permitted for MCP-submitted plans.
    #[arg(long, default_value_t = 1)]
    max_ols_reloads: u64,
    /// Optional Unix timestamp override for deterministic grant expiry checks.
    #[arg(long)]
    now: Option<u64>,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let Some(tier) = mcp::WriteTier::parse(&args.write_tier) else {
        eprintln!(
            "Invalid --write-tier (allowed: read, nonproduction, production; destructive is forbidden)."
        );
        return ExitCode::from(2);
    };
    if tier != mcp::WriteTier::Read {
        let valid_agent = args.agent_id.as_deref().is_some_and(|id| {
            !id.is_empty()
                && id.len() <= 64
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        });
        if !valid_agent {
            eprintln!("--agent-id (alphanumeric/_/-) is required when --write-tier != read.");
            return ExitCode::from(2);
        }
    }
    let policy = mcp::WritePolicy {
        tier,
        agent_id: args.agent_id,
        max_changes: args.max_changes,
        max_ols_reloads: args.max_ols_reloads,
        now_override: args.now,
    };
    let stdin = io::stdin();
    let stdout = io::stdout();
    match mcp::serve(
        BufReader::new(stdin.lock()),
        stdout.lock(),
        args.socket.as_deref(),
        &policy,
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(7),
    }
}
