use serde::{Deserialize, Serialize};

use crate::{CanonicalObject, Id, Text, Timestamp, UnknownReason};

use super::{ApprovalError, Sha256Digest, types::*};

/// A closed fixture plan retaining the canonical original semantic object.
///
/// Observations are caller reports requiring independent executor re-observation.
/// Successful decoding does not prove ownership, signatures or execution safety.
#[derive(Debug)]
pub struct FixturePlan {
    pub(super) record: PlanRecord,
    canonical: CanonicalObject,
}

impl FixturePlan {
    /// Decodes schema v1 and verifies the single fixed lab-fixture semantics.
    pub fn decode(input: &[u8]) -> Result<Self, ApprovalError> {
        let (record, canonical) = super::decode(input, PlanRecord::validate)?;
        Ok(Self { record, canonical })
    }

    /// Complete immutable semantic bytes, including all diagnostics/limitations.
    pub fn as_bytes(&self) -> &[u8] {
        self.canonical.as_bytes()
    }

    /// Domain-separated SHA-256 of the complete validated semantic object.
    pub fn digest(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(self.canonical.plan_domain_digest())
    }

    /// The single bound activation; its predecessor is still a caller report.
    pub fn activation(&self) -> FixtureActivation<'_> {
        let step = &self.record.steps[0];
        let Observation::Observed { content_digest, .. } = &self.record.observations[0] else {
            unreachable!("decode refuses unknown fixture observations")
        };
        FixtureActivation {
            resource_id: &step.resource_id,
            expected_generation: &step.expected_generation,
            expected_digest: content_digest,
            target_generation: &step.target_generation,
            target_digest: &self.record.artifact_digests[0].digest,
        }
    }
}

/// Bound fixture activation fields. Expected values must be re-observed live.
#[derive(Clone, Copy, Debug)]
pub struct FixtureActivation<'a> {
    /// Sole affected registry resource identifier.
    pub resource_id: &'a Id,
    /// Reported predecessor generation.
    pub expected_generation: &'a Id,
    /// Reported predecessor content digest.
    pub expected_digest: &'a Sha256Digest,
    /// Bound candidate generation.
    pub target_generation: &'a Id,
    /// Bound candidate artifact digest.
    pub target_digest: &'a Sha256Digest,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PlanRecord {
    pub schema_version: u16,
    pub plan_id: Id,
    pub host_id: Id,
    pub host_epoch: Id,
    pub profile_digest: Sha256Digest,
    pub requester: Id,
    pub resource_ids: Vec<Id>,
    #[serde(deserialize_with = "crate::codec::object_list")]
    pub observations: Vec<Observation>,
    #[serde(deserialize_with = "crate::codec::object_list")]
    pub steps: Vec<Step>,
    #[serde(deserialize_with = "crate::codec::object_list")]
    pub artifact_digests: Vec<Artifact>,
    pub generator_version: Generator,
    #[serde(deserialize_with = "crate::codec::object")]
    pub expected_effects: Effects,
    pub dependencies: Vec<Id>,
    pub external_effects: Vec<Id>,
    #[serde(deserialize_with = "crate::codec::object")]
    pub blast_radius: BlastRadius,
    pub risk_class: Risk,
    pub reversibility: Reversibility,
    #[serde(deserialize_with = "crate::codec::object")]
    pub downtime_estimate: Estimate,
    #[serde(deserialize_with = "crate::codec::object")]
    pub data_loss_exposure: Estimate,
    #[serde(deserialize_with = "crate::codec::object")]
    pub budgets: Budgets,
    pub valid_from: Timestamp,
    pub expires_at: Timestamp,
    #[serde(deserialize_with = "crate::codec::object")]
    pub compensation: Compensation,
    pub limitations: Vec<Text>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Observation {
    Observed {
        resource_id: Id,
        generation: Id,
        content_digest: Sha256Digest,
        observed_at: Timestamp,
        source: ReportSource,
        complete: bool,
    },
    Unknown {
        resource_id: Id,
        reason: UnknownReason,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReportSource {
    ReportedRegistry,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Step {
    pub step_id: Id,
    pub resource_id: Id,
    pub verb: Verb,
    pub precheck: Recipe,
    pub effect: Recipe,
    pub observer: Recipe,
    pub verification: Recipe,
    pub compensation: Recipe,
    #[serde(deserialize_with = "crate::codec::object")]
    pub settings: Settings,
    pub expected_generation: Id,
    pub target_generation: Id,
    pub artifact_id: Id,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Artifact {
    pub artifact_id: Id,
    pub digest: Sha256Digest,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Effects {
    pub generation_switches: u64,
    pub global_recycles: u64,
    pub probe_resources: Vec<Id>,
    pub network_access: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BlastRadius {
    pub resource_ids: Vec<Id>,
    pub all_hosted_sites: bool,
}

impl PlanRecord {
    fn validate(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1 {
            return Err(ApprovalError::UnsupportedVersion);
        }
        if self.resource_ids.len() != 1
            || self.steps.len() != 1
            || self.observations.len() != 1
            || self.artifact_digests.len() != 1
            || !self.dependencies.is_empty()
            || !self.external_effects.is_empty()
            || self.limitations.len() > 8
            || !valid_window(self.valid_from, self.expires_at)
            || !self.budgets.valid()
            || !self.compensation.valid(self.expires_at)
            || !self.downtime_estimate.valid()
            || !self.data_loss_exposure.valid()
        {
            return Err(ApprovalError::InvalidPlan);
        }
        self.validate_step()?;
        self.validate_observation()
    }

    fn validate_step(&self) -> Result<(), ApprovalError> {
        let step = &self.steps[0];
        let effects = &self.expected_effects;
        if step.resource_id != self.resource_ids[0]
            || step.expected_generation == step.target_generation
            || step.precheck != Recipe::FixturePrecheckV1
            || step.effect != Recipe::FixtureActivateV1
            || step.observer != Recipe::FixtureObserveV1
            || step.verification != Recipe::FixtureVerifyV1
            || step.compensation != Recipe::FixtureRestoreV1
            || self.artifact_digests[0].artifact_id != step.artifact_id
            || self.compensation.generation != step.expected_generation
            || effects.generation_switches != 1
            || effects.global_recycles != 0
            || effects.network_access
            || effects.probe_resources != self.resource_ids
            || self.blast_radius.resource_ids != self.resource_ids
            || self.blast_radius.all_hosted_sites
        {
            return Err(ApprovalError::InvalidPlan);
        }
        Ok(())
    }

    fn validate_observation(&self) -> Result<(), ApprovalError> {
        match &self.observations[0] {
            Observation::Unknown { .. } => Err(ApprovalError::UnknownPrecondition),
            Observation::Observed {
                complete: false, ..
            } => Err(ApprovalError::UnknownPrecondition),
            Observation::Observed {
                resource_id,
                generation,
                observed_at,
                ..
            } => {
                if resource_id != &self.resource_ids[0]
                    || generation != &self.steps[0].expected_generation
                    || observed_at.get() > self.valid_from.get()
                    || self.valid_from.get() - observed_at.get() > MAX_OBSERVATION_AGE_SECONDS
                {
                    return Err(ApprovalError::InvalidPlan);
                }
                Ok(())
            }
        }
    }
}
