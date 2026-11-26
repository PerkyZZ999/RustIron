//! W456 + W591: `rustiron-plan migrate OBSERVATION DECLARATION TARGET [OPTIONS]`,
//! the offline P01 dry run. It merges the export worker's report with the
//! operator's declaration and runs the planner against either a hand-stated
//! target (W456) or a target profile and state derived directly from the
//! target's own merged observation (`--target-observation`, W591).
//!
//! When `--declaration-sig`, `--allowed-signers`, and `--principal` are given,
//! the declaration must be exact canonical JSON and pass offline SSHSIG
//! verification in namespace `rustiron-migration-declaration-v1` (distinct from
//! `rustiron-plan-v1`). The command holds no execution authority: applying the
//! steps still needs a signed `site_import` plan (D-053).

use crate::file_input;
use rustiron_contracts::{
    CanonicalObject, Id, MAX_REQUEST_BYTES,
    migration::{
        DECLARATION_NAMESPACE, MAX_MIGRATION_INVENTORY_BYTES, MAX_TARGET_OBSERVATION_BYTES,
        MigrationRequest, Refusal, TargetProfile, TargetState, assemble_inventory,
        decode_export_observation, decode_operator_declaration, derive_target_from_observation,
        plan_migration, render_dry_run,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const VERIFIER: &str = "/usr/bin/ssh-keygen";
const MAX_SIGNATURE_BYTES: usize = 16 * 1024;
const MAX_KEY_POLICY_BYTES: usize = 64 * 1024;
const VERIFY_TIMEOUT: Duration = Duration::from_secs(5);

/// The hand-written target side of the W456 dry run.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    request: MigrationRequest,
    profile: TargetProfile,
    state: TargetState,
}

/// Optional offline SSHSIG verification inputs for a signed operator declaration.
pub(crate) struct DeclarationSignature<'a> {
    pub signature: &'a Path,
    pub allowed_signers: &'a Path,
    pub principal: &'a str,
    pub revocations: Option<&'a Path>,
}

/// Options for `rustiron-plan migrate`.
pub(crate) struct Options<'a> {
    pub target_observation: Option<&'a Path>,
    pub signature: Option<DeclarationSignature<'a>>,
}

/// The planner's result.
pub(crate) enum Outcome {
    /// The rendered dry run (exit 0).
    Plan(String),
    /// Every planner refusal, as fixed JSON (exit 3).
    Refused(String),
    /// Malformed or unreadable input (exit 2).
    InvalidInput,
    /// Declaration signature verification failed or key was revoked (exit 4).
    SignatureDenied,
    /// Verifier binary or scratch environment unavailable (exit 7).
    DependencyUnavailable,
}

#[derive(Serialize)]
struct Refused<'a> {
    scope: &'static str,
    refusals: &'a [Refusal],
}

/// Runs the offline P01 dry run.
pub(crate) fn run(
    observation: &Path,
    declaration: &Path,
    target: &Path,
    options: &Options<'_>,
) -> Outcome {
    let Ok(observation_bytes) = file_input::read(observation, MAX_MIGRATION_INVENTORY_BYTES) else {
        return Outcome::InvalidInput;
    };
    let Ok(observation) = decode_export_observation(&observation_bytes) else {
        return Outcome::InvalidInput;
    };
    let Ok(declaration_bytes) = file_input::read(declaration, MAX_MIGRATION_INVENTORY_BYTES) else {
        return Outcome::InvalidInput;
    };

    let verified_principal = if let Some(sig) = &options.signature {
        match verify_declaration(&declaration_bytes, sig) {
            Ok(principal) => Some(principal),
            Err(outcome) => return outcome,
        }
    } else {
        None
    };

    let Ok(declaration) = decode_operator_declaration(&declaration_bytes) else {
        return Outcome::InvalidInput;
    };

    let (request, profile, state, observed_host) =
        if let Some(obs_path) = options.target_observation {
            let Ok(obs_bytes) = file_input::read(obs_path, MAX_TARGET_OBSERVATION_BYTES) else {
                return Outcome::InvalidInput;
            };
            let Ok(observed) = derive_target_from_observation(&obs_bytes) else {
                return Outcome::InvalidInput;
            };
            let Ok(request_bytes) = file_input::read(target, MAX_REQUEST_BYTES) else {
                return Outcome::InvalidInput;
            };
            let Ok(request) = serde_json::from_slice::<MigrationRequest>(&request_bytes) else {
                return Outcome::InvalidInput;
            };
            (
                request,
                observed.profile,
                observed.state,
                Some((observed.host_id, observed.host_epoch)),
            )
        } else {
            let Ok(target_bytes) = file_input::read(target, MAX_REQUEST_BYTES) else {
                return Outcome::InvalidInput;
            };
            let Ok(target) = serde_json::from_slice::<Target>(&target_bytes) else {
                return Outcome::InvalidInput;
            };
            (target.request, target.profile, target.state, None)
        };

    let Ok(inventory) = assemble_inventory(&observation, &declaration) else {
        return Outcome::InvalidInput;
    };
    match plan_migration(&inventory, &request, &profile, &state) {
        Ok(plan) => {
            let mut text = render_dry_run(&plan);
            if let Some(principal) = verified_principal {
                text.push_str(&format!(
                    "Declaration signature: verified ({}, namespace {DECLARATION_NAMESPACE}).\n",
                    principal.as_str()
                ));
            }
            if let Some((host_id, host_epoch)) = observed_host {
                text.push_str(&format!(
                    "Target profile and state: derived from target observation ({}, {}).\n",
                    host_id.as_str(),
                    host_epoch.as_str()
                ));
            }
            Outcome::Plan(text)
        }
        Err(refusals) => match serde_json::to_string(&Refused {
            scope: "migration_plan",
            refusals: &refusals,
        }) {
            Ok(json) => Outcome::Refused(json),
            Err(_) => Outcome::InvalidInput,
        },
    }
}

/// Verifies that `declaration_bytes` is exact RFC 8785 canonical JSON and has
/// a valid SSHSIG signature for `sig.principal` in [`DECLARATION_NAMESPACE`].
fn verify_declaration(
    declaration_bytes: &[u8],
    sig: &DeclarationSignature<'_>,
) -> Result<Id, Outcome> {
    let principal = Id::try_from(sig.principal.to_owned()).map_err(|_| Outcome::InvalidInput)?;
    // Require exact canonical bytes so the signed file cannot differ in key
    // order or whitespace from what the operator reviewed.
    let canonical =
        CanonicalObject::decode(declaration_bytes).map_err(|_| Outcome::InvalidInput)?;
    if canonical.as_bytes() != declaration_bytes {
        return Err(Outcome::InvalidInput);
    }

    let signature =
        file_input::read(sig.signature, MAX_SIGNATURE_BYTES).map_err(|_| Outcome::InvalidInput)?;
    let allowed = file_input::read(sig.allowed_signers, MAX_KEY_POLICY_BYTES)
        .map_err(|_| Outcome::InvalidInput)?;
    check_allowed_signers(&allowed, principal.as_str())?;
    let revocations = match sig.revocations {
        Some(path) => {
            Some(file_input::read(path, MAX_KEY_POLICY_BYTES).map_err(|_| Outcome::InvalidInput)?)
        }
        None => None,
    };

    check_verifier_binary()?;

    let mut scratch = Scratch::new()?;
    let result = (|| {
        let input = scratch.write("declaration", declaration_bytes)?;
        let sig_path = scratch.write("signature", &signature)?;
        let allowed_path = scratch.write("allowed", &allowed)?;
        let revoked_path = match &revocations {
            Some(bytes) => Some(scratch.write("revoked", bytes)?),
            None => None,
        };
        let stdin_file = File::open(&input).map_err(|_| Outcome::DependencyUnavailable)?;
        let mut command = Command::new(VERIFIER);
        command
            .args([
                "-Y",
                "verify",
                "-q",
                "-I",
                principal.as_str(),
                "-n",
                DECLARATION_NAMESPACE,
                "-f",
            ])
            .arg(&allowed_path)
            .arg("-s")
            .arg(&sig_path);
        if let Some(revoked) = &revoked_path {
            command.arg("-r").arg(revoked);
        }
        let mut child = command
            .env_clear()
            .stdin(stdin_file)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| Outcome::DependencyUnavailable)?;
        wait_verifier(&mut child, Instant::now() + VERIFY_TIMEOUT)
    })();
    let cleanup = scratch.close();
    cleanup?;
    result?;
    Ok(principal)
}

fn check_verifier_binary() -> Result<(), Outcome> {
    let metadata = fs::symlink_metadata(VERIFIER).map_err(|_| Outcome::DependencyUnavailable)?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(Outcome::DependencyUnavailable);
    }
    Ok(())
}

/// Every non-empty line in `allowed_signers` must pin an explicit principal
/// (never `*`), the exact declaration namespace, and an `ssh-ed25519` public
/// key. At least one entry must match `principal`.
fn check_allowed_signers(bytes: &[u8], principal: &str) -> Result<(), Outcome> {
    let text = std::str::from_utf8(bytes).map_err(|_| Outcome::InvalidInput)?;
    let expected_ns = format!(r#"namespaces="{DECLARATION_NAMESPACE}""#);
    let mut matched_principal = false;
    let mut count = 0usize;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        count += 1;
        if count > 32 {
            return Err(Outcome::InvalidInput);
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 4
            || Id::try_from(parts[0].to_owned()).is_err()
            || parts[1] != expected_ns
            || parts[2] != "ssh-ed25519"
            || parts[3].is_empty()
            || parts[3].len() > 128
            || !parts[3]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"+/=".contains(&byte))
        {
            return Err(Outcome::InvalidInput);
        }
        if parts[0] == principal {
            matched_principal = true;
        }
    }
    if count == 0 || !matched_principal {
        return Err(Outcome::InvalidInput);
    }
    Ok(())
}

fn wait_verifier(child: &mut Child, deadline: Instant) -> Result<(), Outcome> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() {
                    Ok(())
                } else {
                    Err(Outcome::SignatureDenied)
                };
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            _ => {
                let killed = child.kill();
                let reaped = child.wait();
                killed.map_err(|_| Outcome::DependencyUnavailable)?;
                reaped.map_err(|_| Outcome::DependencyUnavailable)?;
                return Err(Outcome::DependencyUnavailable);
            }
        }
    }
}

struct Scratch {
    path: PathBuf,
    names: Vec<&'static str>,
}

impl Scratch {
    fn new() -> Result<Self, Outcome> {
        let mut random = [0; 16];
        rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty())
            .map_err(|_| Outcome::DependencyUnavailable)?;
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = PathBuf::from(format!("/tmp/rustiron-migrate-{suffix}"));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|_| Outcome::DependencyUnavailable)?;
        Ok(Self {
            path,
            names: Vec::new(),
        })
    }

    fn write(&mut self, name: &'static str, bytes: &[u8]) -> Result<PathBuf, Outcome> {
        let path = self.path.join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|_| Outcome::DependencyUnavailable)?;
        self.names.push(name);
        file.write_all(bytes)
            .map_err(|_| Outcome::DependencyUnavailable)?;
        Ok(path)
    }

    fn close(self) -> Result<(), Outcome> {
        for name in &self.names {
            fs::remove_file(self.path.join(name)).map_err(|_| Outcome::DependencyUnavailable)?;
        }
        fs::remove_dir(&self.path).map_err(|_| Outcome::DependencyUnavailable)
    }
}
