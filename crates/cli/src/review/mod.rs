use std::{
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

use clap::{Parser, ValueEnum};
use rustiron_contracts::{
    CanonicalObject, Id, MAX_REQUEST_BYTES, Timestamp,
    approval::{
        ApprovalError, FixtureBindingContext, FixtureGrant, FixturePlan,
        MAX_PRODUCT_BACKUP_POLICY_BYTES, ProductBackupBindingContext, ProductBackupCredential,
        ProductBackupGrant, ProductBackupPlan, ProductBackupPolicy, ProductBackupSite,
        Sha256Digest, StandingCaptureBindingContext, StandingCaptureGrant, StandingCapturePlan,
        check_fixture_binding, check_product_backup_binding, check_standing_capture_binding,
    },
    escape_human, local,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

mod files;
mod verify;

#[derive(Clone, Copy, ValueEnum)]
enum Output {
    Human,
    Json,
    GrantBytes,
}

#[derive(Parser)]
#[command(
    name = "rustiron-review",
    about = "Review a fixture or product backup grant offline; no execution authority"
)]
struct Args {
    #[arg(long)]
    plan: PathBuf,
    #[arg(long)]
    grant: PathBuf,
    /// Independent offline policy, including the reviewed ssh-keygen binary hash.
    #[arg(long)]
    policy: PathBuf,
    /// Independent HTTPS S3 projection. Required for product backup v2 review.
    #[arg(long)]
    destination_policy: Option<PathBuf>,
    #[arg(long, requires_all=["allowed_signers", "revocations"])]
    signature: Option<PathBuf>,
    #[arg(long, requires = "signature")]
    allowed_signers: Option<PathBuf>,
    #[arg(long, requires = "signature")]
    revocations: Option<PathBuf>,
    /// Synthetic fixture testing only; always labeled in the review receipt.
    #[arg(long)]
    synthetic_time: Option<u64>,
    #[arg(long, value_enum, default_value = "human")]
    output: Output,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    schema_version: u16,
    host_id: Id,
    host_epoch: Id,
    profile_digest: Sha256Digest,
    requester: Id,
    issuer: Id,
    signer_policy_epoch: Id,
    verifier_sha256: Sha256Digest,
    #[serde(skip_serializing_if = "Option::is_none")]
    backup_destination: Option<BackupDestination>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BackupDestination {
    destination_id: Id,
    destination_policy_digest: Sha256Digest,
}

#[derive(Clone, Copy)]
enum ReviewScope {
    Fixture,
    ProductBackup,
}

impl ReviewScope {
    fn name(self) -> &'static str {
        match self {
            Self::Fixture => "offline_fixture_review",
            Self::ProductBackup => "offline_product_backup_review",
        }
    }

    fn binding_code(self) -> &'static str {
        match self {
            Self::Fixture => "FIXTURE_BINDING_DENIED",
            Self::ProductBackup => "PRODUCT_BACKUP_BINDING_DENIED",
        }
    }

    fn heading(self) -> &'static str {
        match self {
            Self::Fixture => "Offline fixture review; no execution authority\n",
            Self::ProductBackup => "Offline product backup review (no execution authority)\n",
        }
    }
}

struct Failure {
    exit: u8,
    code: &'static str,
    scope: ReviewScope,
}
impl Failure {
    fn new(exit: u8, code: &'static str) -> Self {
        Self {
            exit,
            code,
            scope: ReviewScope::Fixture,
        }
    }

    fn for_scope(mut self, scope: ReviewScope) -> Self {
        self.scope = scope;
        self
    }

    fn input() -> Self {
        Self::new(2, "INVALID_REVIEW_INPUT")
    }
    fn dependency() -> Self {
        Self::new(7, "REVIEW_DEPENDENCY_UNAVAILABLE")
    }
    fn signature() -> Self {
        Self::new(3, "INVALID_SIGNATURE")
    }
    fn approval(error: ApprovalError, scope: ReviewScope) -> Self {
        match error {
            ApprovalError::OutsideValidity | ApprovalError::ClockUncertain => {
                Self::new(3, "GRANT_TIME_DENIED")
            }
            ApprovalError::BindingMismatch | ApprovalError::UnknownPrecondition => {
                Self::new(4, scope.binding_code())
            }
            _ => Self::input(),
        }
    }
}

fn hash(bytes: &[u8]) -> String {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
        .as_str()
        .to_owned()
}

pub(super) fn main() -> ExitCode {
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
            return if error.print().is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(7)
            };
        }
        Err(_) => return fail(Failure::input()),
    };
    match run(args) {
        Ok(bytes) if io::stdout().lock().write_all(&bytes).is_ok() => ExitCode::SUCCESS,
        Ok(_) => fail(Failure::dependency()),
        Err(error) => fail(error),
    }
}

fn fail(error: Failure) -> ExitCode {
    let output = format!(
        "{{\"scope\":\"{}\",\"error\":\"{}\"}}\n",
        error.scope.name(),
        error.code
    );
    match io::stdout().lock().write_all(output.as_bytes()) {
        Ok(()) => ExitCode::from(error.exit),
        Err(_) => ExitCode::from(7),
    }
}

fn run(args: Args) -> Result<Vec<u8>, Failure> {
    local::operator_uid().map_err(|_| Failure::new(3, "ORDINARY_USER_REQUIRED"))?;
    let policy_bytes = files::read(&args.policy, 16 * 1024)?;
    let policy_bytes = CanonicalObject::decode(&policy_bytes).map_err(|_| Failure::input())?;
    let policy: Policy =
        serde_json::from_slice(policy_bytes.as_bytes()).map_err(|_| Failure::input())?;
    let original: serde_json::Value =
        serde_json::from_slice(policy_bytes.as_bytes()).map_err(|_| Failure::input())?;
    // Preserve the v1 field set, including refusal of an explicit null
    // destination that the optional field would otherwise omit.
    if serde_json::to_value(&policy).map_err(|_| Failure::input())? != original {
        return Err(Failure::input());
    }
    let scope = match (policy.schema_version, &policy.backup_destination) {
        (1, None) if args.destination_policy.is_none() => ReviewScope::Fixture,
        (2, Some(_)) => ReviewScope::ProductBackup,
        _ => return Err(Failure::input()),
    };
    review(args, &policy, &policy_bytes, scope).map_err(|failure| failure.for_scope(scope))
}

struct BoundInputs {
    plan: Vec<u8>,
    grant: Vec<u8>,
    plan_digest: Sha256Digest,
    repository: Option<ReviewedRepository>,
    /// D-035 (W386): each named site's repository and every signed window.
    standing: Option<serde_json::Value>,
}

struct ReviewedRepository {
    id: Sha256Digest,
    settings: serde_json::Value,
}

impl ReviewedRepository {
    fn from_site(site: ProductBackupSite<'_>) -> Self {
        let credential = |value: ProductBackupCredential<'_>| {
            serde_json::json!({
                "relative_path": value.relative_path(),
                "profile_id": value.profile_id(),
                "principal_id": value.principal_id(),
                "authorization_sha256": value.authorization_sha256(),
            })
        };
        Self {
            id: site.repository_id().clone(),
            settings: serde_json::json!({
                "url": site.repository_url(),
                "endpoint": site.endpoint().to_string(),
                "region": site.region(),
                "ca_sha256": site.ca_sha256(),
                "retention_days": site.retention_days(),
                "password_relative_path": site.password_path(),
                "capture_credential": credential(site.capture_credential()),
                "fetch_credential": credential(site.fetch_credential()),
            }),
        }
    }
}

fn bind_inputs(
    args: &Args,
    policy: &Policy,
    scope: ReviewScope,
    now: Timestamp,
) -> Result<BoundInputs, Failure> {
    let plan = files::read(&args.plan, MAX_REQUEST_BYTES)?;
    let grant = files::read(&args.grant, MAX_REQUEST_BYTES)?;
    let failure = |error| Failure::approval(error, scope);
    if let Some(destination) = &policy.backup_destination {
        let projection_path = args
            .destination_policy
            .as_ref()
            .ok_or_else(Failure::input)?;
        if let Ok(standing) = StandingCapturePlan::decode(&plan) {
            return bind_standing(
                &standing,
                &grant,
                policy,
                destination,
                projection_path,
                now,
                failure,
            );
        }
        let plan = ProductBackupPlan::decode(&plan).map_err(failure)?;
        let grant = ProductBackupGrant::decode(&grant).map_err(failure)?;
        check_product_backup_binding(
            &plan,
            &grant,
            &ProductBackupBindingContext {
                host_id: &policy.host_id,
                host_epoch: &policy.host_epoch,
                profile_digest: &policy.profile_digest,
                requester: &policy.requester,
                issuer: &policy.issuer,
                signer_policy_epoch: &policy.signer_policy_epoch,
                now: Some(now),
            },
        )
        .map_err(failure)?;
        let projection_bytes = files::read(projection_path, MAX_PRODUCT_BACKUP_POLICY_BYTES)?;
        let projection = ProductBackupPolicy::decode(&projection_bytes).map_err(failure)?;
        if plan.destination_id() != &destination.destination_id
            || plan.destination_policy_digest() != &destination.destination_policy_digest
            || projection.destination_id() != &destination.destination_id
            || projection.digest() != destination.destination_policy_digest
        {
            return Err(Failure::new(4, "DESTINATION_POLICY_MISMATCH"));
        }
        let site = projection
            .resolve_site(plan.site_id())
            .ok_or_else(|| Failure::new(4, "DESTINATION_SITE_NOT_ENROLLED"))?;
        return Ok(BoundInputs {
            plan: plan.as_bytes().to_vec(),
            grant: grant.as_bytes().to_vec(),
            plan_digest: plan.digest(),
            repository: Some(ReviewedRepository::from_site(site)),
            standing: None,
        });
    }
    let plan = FixturePlan::decode(&plan).map_err(failure)?;
    let grant = FixtureGrant::decode(&grant).map_err(failure)?;
    check_fixture_binding(
        &plan,
        &grant,
        &FixtureBindingContext {
            host_id: &policy.host_id,
            host_epoch: &policy.host_epoch,
            profile_digest: &policy.profile_digest,
            requester: &policy.requester,
            issuer: &policy.issuer,
            signer_policy_epoch: &policy.signer_policy_epoch,
            now: Some(now),
        },
    )
    .map_err(failure)?;
    Ok(BoundInputs {
        plan: plan.as_bytes().to_vec(),
        grant: grant.as_bytes().to_vec(),
        plan_digest: plan.digest(),
        repository: None,
        standing: None,
    })
}

/// D-035 (W386): a standing capture grant under the same review policy and
/// projection. Every named site must resolve to an enrolled repository.
fn bind_standing(
    plan: &StandingCapturePlan,
    grant: &[u8],
    policy: &Policy,
    destination: &BackupDestination,
    projection_path: &std::path::Path,
    now: Timestamp,
    failure: impl Fn(ApprovalError) -> Failure,
) -> Result<BoundInputs, Failure> {
    let grant = StandingCaptureGrant::decode(grant).map_err(&failure)?;
    check_standing_capture_binding(
        plan,
        &grant,
        &StandingCaptureBindingContext {
            host_id: &policy.host_id,
            host_epoch: &policy.host_epoch,
            profile_digest: &policy.profile_digest,
            requester: &policy.requester,
            issuer: &policy.issuer,
            signer_policy_epoch: &policy.signer_policy_epoch,
            now: Some(now),
        },
    )
    .map_err(&failure)?;
    let projection_bytes = files::read(projection_path, MAX_PRODUCT_BACKUP_POLICY_BYTES)?;
    let projection = ProductBackupPolicy::decode(&projection_bytes).map_err(&failure)?;
    if plan.destination_id() != &destination.destination_id
        || plan.destination_policy_digest() != &destination.destination_policy_digest
        || projection.destination_id() != &destination.destination_id
        || projection.digest() != destination.destination_policy_digest
    {
        return Err(Failure::new(4, "DESTINATION_POLICY_MISMATCH"));
    }
    let mut repositories = serde_json::Map::new();
    for site in plan.site_ids() {
        let resolved = projection
            .resolve_site(site)
            .ok_or_else(|| Failure::new(4, "DESTINATION_SITE_NOT_ENROLLED"))?;
        let reviewed = ReviewedRepository::from_site(resolved);
        repositories.insert(
            site.as_str().to_owned(),
            serde_json::json!({"repository_id": reviewed.id, "repository": reviewed.settings}),
        );
    }
    let schedule = plan.schedule();
    let windows = (0..schedule.max_runs)
        .filter_map(|window| {
            let (opens, closes) = schedule.window(window)?;
            Some(serde_json::json!({"window": window, "opens_at": opens, "closes_at": closes}))
        })
        .collect::<Vec<_>>();
    Ok(BoundInputs {
        plan: plan.as_bytes().to_vec(),
        grant: grant.as_bytes().to_vec(),
        plan_digest: plan.digest(),
        repository: None,
        standing: Some(serde_json::json!({
            "repositories": repositories,
            "windows": windows,
            "max_captures": schedule.max_runs * plan.site_ids().len() as u64,
        })),
    })
}

fn review(
    args: Args,
    policy: &Policy,
    policy_bytes: &CanonicalObject,
    scope: ReviewScope,
) -> Result<Vec<u8>, Failure> {
    let now = args.synthetic_time.map_or_else(
        || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|time| time.as_secs())
                .map_err(|_| Failure::dependency())
        },
        Ok,
    )?;
    let now = Timestamp::try_from(now).map_err(|_| Failure::input())?;
    let inputs = bind_inputs(&args, policy, scope, now)?;
    let signature_evidence = match (args.signature, args.allowed_signers, args.revocations) {
        (Some(signature), Some(allowed_signers), Some(revocations)) => {
            let evidence = verify::verify(
                &inputs.grant,
                policy,
                &verify::SignatureFiles {
                    signature,
                    allowed_signers,
                    revocations,
                },
            )?;
            Some(serde_json::json!({"namespace":verify::NAMESPACE,
                "allowed_signers_sha256":evidence.allowed_sha256,
                "revocations_sha256":evidence.revocations_sha256,
                "verifier_sha256":policy.verifier_sha256.as_str()}))
        }
        (None, None, None) => None,
        _ => return Err(Failure::input()),
    };
    let signature_status = if signature_evidence.is_some() {
        "verified"
    } else {
        "not_checked"
    };
    if matches!(args.output, Output::GrantBytes) {
        return Ok(inputs.grant);
    }
    let mut review = serde_json::json!({
        "scope":scope.name(), "execution_authority":false, "signature_status":signature_status,
        "synthetic_time":args.synthetic_time.is_some(), "checked_at":now.get(),
        "plan_digest":inputs.plan_digest.as_str(), "canonical_grant_sha256":hash(&inputs.grant),
        "policy_sha256":hash(policy_bytes.as_bytes()),
        "signature_evidence":signature_evidence,
        "plan":serde_json::from_slice::<serde_json::Value>(&inputs.plan).map_err(|_| Failure::input())?,
        "grant":serde_json::from_slice::<serde_json::Value>(&inputs.grant).map_err(|_| Failure::input())?,
    });
    if let Some(repository) = inputs.repository {
        review["destination_policy_binding"] = serde_json::json!("matched");
        review["repository_id"] = serde_json::json!(repository.id);
        review["repository"] = repository.settings;
    }
    if let Some(standing) = inputs.standing {
        review["destination_policy_binding"] = serde_json::json!("matched");
        review["standing_capture"] = standing;
    }
    if matches!(args.output, Output::Json) {
        let mut bytes = serde_json::to_vec(&review).map_err(|_| Failure::dependency())?;
        bytes.push(b'\n');
        return Ok(bytes);
    }
    let pretty = serde_json::to_string_pretty(&review).map_err(|_| Failure::dependency())?;
    let mut human = String::from(scope.heading());
    for line in pretty.lines() {
        human.push_str(&escape_human(line));
        human.push('\n');
    }
    Ok(human.into_bytes())
}
