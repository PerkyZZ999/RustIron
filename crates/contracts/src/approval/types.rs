use serde::{Deserialize, Serialize};

use crate::{Id, Text, Timestamp, UnknownReason};

use super::ApprovalError;

const MAX_WINDOW_SECONDS: u64 = 3600;
const MAX_COMPENSATION_SECONDS: u64 = 300;
const MAX_RUNTIME_SECONDS: u64 = 300;
const MAX_MEMORY_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PIDS: u64 = 32;
const MAX_OUTPUT_BYTES: u64 = 1024 * 1024;
const MAX_TEMPORARY_BYTES: u64 = 16 * 1024 * 1024;
/// How long a recorded observation stays current for plan admission and inventory labels.
pub const MAX_OBSERVATION_AGE_SECONDS: u64 = 300;

/// A canonical lowercase SHA-256 reference; this alone verifies no artifact.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(try_from = "String")]
pub struct Sha256Digest(String);

impl Sha256Digest {
    /// Returns its exact 64-character lowercase hex representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Renders a computed digest; does not load or trust any external artifact.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
    }
}

impl TryFrom<String> for Sha256Digest {
    type Error = ApprovalError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ApprovalError::InvalidMessage);
        }
        Ok(Self(value))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Verb {
    ConfigActivate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Recipe {
    FixturePrecheckV1,
    FixtureActivateV1,
    FixtureObserveV1,
    FixtureVerifyV1,
    FixtureRestoreV1,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Generator {
    FixtureGeneratorV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Risk {
    LabOnly,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Reversibility {
    BoundedLastKnownGood,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Variant {
    Alpha,
    Beta,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Settings {
    pub variant: Variant,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Estimate {
    Unknown { reason: UnknownReason },
    Estimated { value: u64, basis: Text },
}

impl Estimate {
    pub fn valid(&self) -> bool {
        match self {
            Self::Unknown { .. } => true,
            Self::Estimated { value, basis } => {
                *value < (1_u64 << 53) && !basis.as_str().is_empty()
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Budgets {
    pub steps: u64,
    pub global_recycles: u64,
    pub affected_resources: u64,
    pub runtime_seconds: u64,
    pub cpu_seconds: u64,
    pub memory_bytes: u64,
    pub pids: u64,
    pub output_bytes: u64,
    pub temporary_bytes: u64,
}

impl Budgets {
    pub fn valid(&self) -> bool {
        self.steps == 1
            && self.global_recycles == 0
            && self.affected_resources == 1
            && (1..=MAX_RUNTIME_SECONDS).contains(&self.runtime_seconds)
            && (1..=self.runtime_seconds).contains(&self.cpu_seconds)
            && (1..=MAX_MEMORY_BYTES).contains(&self.memory_bytes)
            && (1..=MAX_PIDS).contains(&self.pids)
            && (1..=MAX_OUTPUT_BYTES).contains(&self.output_bytes)
            && self.temporary_bytes <= MAX_TEMPORARY_BYTES
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Compensation {
    pub recipe: Recipe,
    pub generation: Id,
    pub max_attempts: u64,
    pub valid_until: Timestamp,
}

impl Compensation {
    pub fn valid(&self, expires_at: Timestamp) -> bool {
        self.recipe == Recipe::FixtureRestoreV1
            && self.max_attempts == 1
            && self.valid_until.get() >= expires_at.get()
            && self.valid_until.get() - expires_at.get() <= MAX_COMPENSATION_SECONDS
    }
}

pub(super) fn valid_window(start: Timestamp, end: Timestamp) -> bool {
    end.get() > start.get() && end.get() - start.get() <= MAX_WINDOW_SECONDS
}
