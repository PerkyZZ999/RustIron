//! D-035 (W386): the standing product capture plan and grant (schema 3).
//!
//! One signed grant authorizes `backup_capture` only, for 1 to 16 named
//! sites and one enrolled destination, in a fixed series of windows. The
//! executor derives one run identity for each site and window from the
//! SHA-256 of the canonical grant, so the existing replay ledger consumes
//! each run once. Decoding and binding confer no authority.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{CanonicalObject, Id, Text, Timestamp};

use super::{ApprovalError, CaptureRecipe, Sha256Digest, SiteId, product_backup::LAB_DESTINATION};

const VERSION: u16 = 3;
/// Shortest signed period between window openings (lab proofs).
pub const MIN_STANDING_PERIOD_SECONDS: u64 = 300;
/// Longest signed period between window openings (one day).
pub const MAX_STANDING_PERIOD_SECONDS: u64 = 86_400;
/// Shortest signed window.
pub const MIN_STANDING_WINDOW_SECONDS: u64 = 60;
/// Longest signed window; a window is also at most half of the period.
pub const MAX_STANDING_WINDOW_SECONDS: u64 = 14_400;
/// Most windows one grant can name.
pub const MAX_STANDING_RUNS: u64 = 35;
/// Most sites one grant can name.
pub const MAX_STANDING_SITES: usize = 16;
/// Longest signed validity of a standing grant (35 days).
pub const MAX_STANDING_SPAN_SECONDS: u64 = 35 * 86_400;
/// Hash domain of the derived run identities.
pub const STANDING_RUN_DOMAIN: &str = "rustiron/standing-capture-run/v1";

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Risk {
    Production,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Verb {
    BackupCapture,
}

/// The signed window series shared by the plan and the grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StandingSchedule {
    /// Opening second of window 0.
    pub first_window_start: u64,
    /// Seconds between two window openings.
    pub period_seconds: u64,
    /// Seconds each window stays open.
    pub window_seconds: u64,
    /// Number of windows.
    pub max_runs: u64,
}

/// Where a time falls in the signed window series.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowPosition {
    /// Window `index` is open: `opens_at <= now < closes_at`.
    Open {
        /// Zero-based window number.
        index: u64,
        /// First second of the window.
        opens_at: u64,
        /// First second after the window.
        closes_at: u64,
    },
    /// No window is open; `next` is the next window, if one is left.
    Closed {
        /// The next window number, or none after the last window.
        next: Option<u64>,
    },
}

impl StandingSchedule {
    /// Opening and closing second of window `index`, if the schedule has it.
    pub fn window(&self, index: u64) -> Option<(u64, u64)> {
        if index >= self.max_runs {
            return None;
        }
        let opens = index
            .checked_mul(self.period_seconds)?
            .checked_add(self.first_window_start)?;
        Some((opens, opens.checked_add(self.window_seconds)?))
    }

    /// The window that is open at `now`, or the next one.
    pub fn position(&self, now: u64) -> WindowPosition {
        if now < self.first_window_start {
            return WindowPosition::Closed { next: Some(0) };
        }
        let index = (now - self.first_window_start) / self.period_seconds;
        match self.window(index) {
            Some((opens_at, closes_at)) if now < closes_at => WindowPosition::Open {
                index,
                opens_at,
                closes_at,
            },
            _ => WindowPosition::Closed {
                next: (index + 1 < self.max_runs).then_some(index + 1),
            },
        }
    }

    /// Number of windows that closed at or before `now`.
    pub fn closed_windows(&self, now: u64) -> u64 {
        (0..self.max_runs)
            .take_while(|index| self.window(*index).is_some_and(|(_, closes)| closes <= now))
            .count() as u64
    }

    fn valid(&self, valid_from: Timestamp, expires_at: Timestamp) -> bool {
        let last_end = self
            .max_runs
            .checked_sub(1)
            .and_then(|last| self.window(last))
            .map(|(_, closes)| closes);
        (MIN_STANDING_PERIOD_SECONDS..=MAX_STANDING_PERIOD_SECONDS).contains(&self.period_seconds)
            && (MIN_STANDING_WINDOW_SECONDS..=MAX_STANDING_WINDOW_SECONDS)
                .contains(&self.window_seconds)
            && self.window_seconds <= self.period_seconds / 2
            && (1..=MAX_STANDING_RUNS).contains(&self.max_runs)
            && self.first_window_start >= valid_from.get()
            && last_end.is_some_and(|end| end <= expires_at.get())
            && expires_at.get() > valid_from.get()
            && expires_at.get() - valid_from.get() <= MAX_STANDING_SPAN_SECONDS
    }
}

/// One derived run of a standing grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StandingRun {
    /// Zero-based window number.
    pub window: u64,
    /// Operation ID (`sc_` and 32 hex digits).
    pub operation_id: Id,
    /// Idempotency key (`sk_` and 32 hex digits).
    pub idempotency_key: Id,
    /// Single-use run grant ID recorded in the journal (`sg_`).
    pub grant_id: Id,
    /// Single-use run nonce recorded in the journal (`sn_`).
    pub nonce: Id,
}

/// Derives the run identity of `site` in `window` for the grant whose
/// canonical bytes have SHA-256 `grant_sha256`.
pub fn standing_run(grant_sha256: &Sha256Digest, site: &SiteId, window: u64) -> StandingRun {
    let mut hasher = Sha256::new();
    for part in [
        STANDING_RUN_DOMAIN.as_bytes(),
        grant_sha256.as_str().as_bytes(),
        site.as_str().as_bytes(),
    ] {
        hasher.update(part);
        hasher.update([0]);
    }
    hasher.update(window.to_string().as_bytes());
    let hex = Sha256Digest::from_bytes(hasher.finalize().into());
    let (first, second) = hex.as_str().split_at(32);
    let id = |prefix: &str, half: &str| {
        Id::try_from(format!("{prefix}{half}")).expect("prefixed hex is a valid ID")
    };
    StandingRun {
        window,
        operation_id: id("sc_", first),
        idempotency_key: id("sk_", second),
        grant_id: id("sg_", first),
        nonce: id("sn_", second),
    }
}

fn sorted_sites(sites: &[SiteId]) -> bool {
    (1..=MAX_STANDING_SITES).contains(&sites.len())
        && sites
            .windows(2)
            .all(|pair| pair[0].as_str() < pair[1].as_str())
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PlanRecord {
    schema_version: u16,
    plan_id: Id,
    host_id: Id,
    host_epoch: Id,
    profile_digest: Sha256Digest,
    requester: Id,
    verb: Verb,
    site_ids: Vec<SiteId>,
    destination_id: Id,
    destination_policy_digest: Sha256Digest,
    recipe_id: CaptureRecipe,
    first_window_start: u64,
    period_seconds: u64,
    window_seconds: u64,
    max_runs: u64,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
    limitations: Vec<Text>,
}

impl PlanRecord {
    fn schedule(&self) -> StandingSchedule {
        StandingSchedule {
            first_window_start: self.first_window_start,
            period_seconds: self.period_seconds,
            window_seconds: self.window_seconds,
            max_runs: self.max_runs,
        }
    }

    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != VERSION {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.destination_id.as_str() == LAB_DESTINATION
            || self.limitations.len() > 8
            || !sorted_sites(&self.site_ids)
            || !self.schedule().valid(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidPlan);
        }
        Ok(())
    }
}

/// A validated standing capture plan with its original canonical bytes.
#[derive(Debug)]
pub struct StandingCapturePlan {
    record: PlanRecord,
    canonical: CanonicalObject,
}

impl StandingCapturePlan {
    /// Decodes the exact schema 3 plan and its intrinsic constraints.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, PlanRecord::validate)?;
        Ok(Self { record, canonical })
    }

    /// Complete canonical plan bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.canonical.as_bytes()
    }

    /// Domain-separated digest of the complete canonical plan.
    pub fn digest(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(self.canonical.plan_domain_digest())
    }

    /// The named sites, strictly ascending.
    pub fn site_ids(&self) -> &[SiteId] {
        &self.record.site_ids
    }

    /// The one destination named by this plan.
    pub fn destination_id(&self) -> &Id {
        &self.record.destination_id
    }

    /// The expected digest of the destination's enrolled policy.
    pub fn destination_policy_digest(&self) -> &Sha256Digest {
        &self.record.destination_policy_digest
    }

    /// The fixed capture recipe.
    pub fn recipe_id(&self) -> CaptureRecipe {
        self.record.recipe_id
    }

    /// The signed window series.
    pub fn schedule(&self) -> StandingSchedule {
        self.record.schedule()
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GrantRecord {
    schema_version: u16,
    grant_id: Id,
    nonce: Id,
    plan_id: Id,
    plan_digest: Sha256Digest,
    host_id: Id,
    host_epoch: Id,
    profile_digest: Sha256Digest,
    issuer: Id,
    requester: Id,
    signer_policy_epoch: Id,
    verbs: Vec<Verb>,
    site_ids: Vec<SiteId>,
    destinations: Vec<Id>,
    first_window_start: u64,
    period_seconds: u64,
    window_seconds: u64,
    max_runs: u64,
    risk_class: Risk,
    valid_from: Timestamp,
    expires_at: Timestamp,
}

impl GrantRecord {
    fn schedule(&self) -> StandingSchedule {
        StandingSchedule {
            first_window_start: self.first_window_start,
            period_seconds: self.period_seconds,
            window_seconds: self.window_seconds,
            max_runs: self.max_runs,
        }
    }

    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != VERSION {
            return Err(ApprovalError::UnsupportedVersion);
        }
        let one_product_destination = matches!(
            self.destinations.as_slice(),
            [destination] if destination.as_str() != LAB_DESTINATION
        );
        if self.issuer == self.requester
            || self.verbs != [Verb::BackupCapture]
            || !sorted_sites(&self.site_ids)
            || !one_product_destination
            || !self.schedule().valid(self.valid_from, self.expires_at)
        {
            return Err(ApprovalError::InvalidGrant);
        }
        Ok(())
    }
}

/// A validated standing capture grant before signature or authority checks.
#[derive(Debug)]
pub struct StandingCaptureGrant {
    record: GrantRecord,
    canonical: CanonicalObject,
}

impl StandingCaptureGrant {
    /// Decodes the exact schema 3 grant and its intrinsic constraints.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, GrantRecord::validate)?;
        Ok(Self { record, canonical })
    }

    /// Canonical bytes covered by the detached signature.
    pub fn as_bytes(&self) -> &[u8] {
        self.canonical.as_bytes()
    }

    /// SHA-256 of the canonical grant bytes; the journal `grant_digest`
    /// and the input of every derived run identity.
    pub fn sha256(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(Sha256::digest(self.as_bytes()).into())
    }

    /// Digest of the plan this grant binds.
    pub fn plan_digest(&self) -> &Sha256Digest {
        &self.record.plan_digest
    }

    /// Signed standing grant identity.
    pub fn grant_id(&self) -> &Id {
        &self.record.grant_id
    }

    /// Signed exclusive execution deadline.
    pub fn expires_at(&self) -> Timestamp {
        self.record.expires_at
    }

    /// The signed window series.
    pub fn schedule(&self) -> StandingSchedule {
        self.record.schedule()
    }

    /// The named sites, strictly ascending.
    pub fn site_ids(&self) -> &[SiteId] {
        &self.record.site_ids
    }

    /// The run of `site` in `window`, if the grant names both.
    pub fn run(&self, site: &SiteId, window: u64) -> Option<StandingRun> {
        (self.record.site_ids.contains(site) && window < self.record.max_runs)
            .then(|| standing_run(&self.sha256(), site, window))
    }

    /// The named site and run whose operation ID is `operation_id`.
    pub fn find_run(&self, operation_id: &Id) -> Option<(SiteId, StandingRun)> {
        let digest = self.sha256();
        self.record.site_ids.iter().find_map(|site| {
            (0..self.record.max_runs)
                .map(|window| standing_run(&digest, site, window))
                .find(|run| &run.operation_id == operation_id)
                .map(|run| (site.clone(), run))
        })
    }
}

/// Independent host and signer facts for standing capture binding.
pub struct StandingCaptureBindingContext<'a> {
    /// Enrolled host identity.
    pub host_id: &'a Id,
    /// Enrolled host epoch.
    pub host_epoch: &'a Id,
    /// Enrolled host profile digest.
    pub profile_digest: &'a Sha256Digest,
    /// Requester resolved from the kernel peer.
    pub requester: &'a Id,
    /// Enrolled signer principal.
    pub issuer: &'a Id,
    /// Current signer and revocation policy epoch.
    pub signer_policy_epoch: &'a Id,
    /// Reliable Unix seconds, if available.
    pub now: Option<Timestamp>,
}

/// Checks pure binding and grant validity. The window, signature, replay
/// and destination checks belong to the caller.
pub fn check_standing_capture_binding(
    plan: &StandingCapturePlan,
    grant: &StandingCaptureGrant,
    context: &StandingCaptureBindingContext<'_>,
) -> Result<(), ApprovalError> {
    let p = &plan.record;
    let g = &grant.record;
    if g.plan_digest != plan.digest()
        || g.plan_id != p.plan_id
        || g.host_id != p.host_id
        || g.host_epoch != p.host_epoch
        || g.profile_digest != p.profile_digest
        || g.requester != p.requester
        || g.site_ids != p.site_ids
        || g.destinations != std::slice::from_ref(&p.destination_id)
        || g.schedule() != p.schedule()
        || &p.host_id != context.host_id
        || &p.host_epoch != context.host_epoch
        || &p.profile_digest != context.profile_digest
        || &p.requester != context.requester
        || &g.issuer != context.issuer
        || &g.signer_policy_epoch != context.signer_policy_epoch
        || g.valid_from.get() < p.valid_from.get()
        || g.expires_at.get() > p.expires_at.get()
    {
        return Err(ApprovalError::BindingMismatch);
    }
    let now = context.now.ok_or(ApprovalError::ClockUncertain)?;
    if now.get() < g.valid_from.get() || now.get() >= g.expires_at.get() {
        return Err(ApprovalError::OutsideValidity);
    }
    Ok(())
}
