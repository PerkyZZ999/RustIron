use serde::{Deserialize, Serialize};

use crate::ProtocolError;

/// Maximum complete request JSON payload, excluding the future framing prefix.
pub const MAX_REQUEST_BYTES: usize = 256 * 1024;
/// Maximum complete response JSON payload.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
/// Maximum nesting depth, counting the outer object or array.
pub const MAX_JSON_DEPTH: usize = 32;
/// Maximum records in one page.
pub const MAX_PAGE_SIZE: u16 = 100;

/// Bounded ASCII transport ID, not a path, permission or trusted resource record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Id(String);

impl Id {
    /// Returns the validated opaque identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Id {
    type Error = ProtocolError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err(ProtocolError::InvalidIdentifier);
        }
        Ok(Self(value))
    }
}

/// Bounded UTF-8 display data, never an instruction or an automatic redaction guarantee.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Text(String);

impl Text {
    /// Returns the display data; escape it for its output context.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Text {
    type Error = ProtocolError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() > 512 {
            return Err(ProtocolError::InvalidText);
        }
        Ok(Self(value))
    }
}

/// Validated page-size bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct PageLimit(u16);

impl PageLimit {
    /// Returns the page size.
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for PageLimit {
    type Error = ProtocolError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        if !(1..=MAX_PAGE_SIZE).contains(&value) {
            return Err(ProtocolError::InvalidLimit);
        }
        Ok(Self(value))
    }
}

impl From<PageLimit> for u16 {
    fn from(value: PageLimit) -> Self {
        value.get()
    }
}

/// UTC Unix seconds represented exactly by JSON's common numeric consumers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "u64", into = "u64")]
pub struct Timestamp(u64);

impl Timestamp {
    /// Returns UTC Unix seconds.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl TryFrom<u64> for Timestamp {
    type Error = ProtocolError;
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value > (1_u64 << 53) - 1 {
            return Err(ProtocolError::InvalidTimestamp);
        }
        Ok(Self(value))
    }
}

impl From<Timestamp> for u64 {
    fn from(value: Timestamp) -> Self {
        value.get()
    }
}

/// Source of a bounded read-side observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationSource {
    /// Operating-system release metadata.
    OsRelease,
    /// Kernel/platform metadata.
    Kernel,
    /// Coordinator inventory, which grants no executor authority.
    Inventory,
    /// A profile hypothesis rather than an observed live property.
    Profile,
}

/// Why an observation is unknown rather than a fabricated value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownReason {
    /// The check has not run.
    NotChecked,
    /// Required access was unavailable.
    PermissionDenied,
    /// The data source could not be read.
    Unavailable,
    /// This profile does not support the check.
    Unsupported,
}

/// Observed, inferred, unknown and stale values remain structurally distinct.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Observation<T> {
    /// Direct observation at a known time and source.
    Observed {
        /// Observed data.
        value: T,
        /// Observation time, not fetch time.
        observed_at: Timestamp,
        /// Provenance.
        source: ObservationSource,
    },
    /// A labeled inference, not accepted hosting evidence.
    Inferred {
        /// Proposed data.
        value: T,
        /// Inference time.
        observed_at: Timestamp,
        /// Provenance.
        source: ObservationSource,
    },
    /// No usable value is asserted.
    Unknown {
        /// Cause of the missing observation.
        reason: UnknownReason,
    },
    /// Last-known data retained with its original time.
    Stale {
        /// Last-known data.
        value: T,
        /// Original observation time.
        observed_at: Timestamp,
        /// Original provenance.
        source: ObservationSource,
    },
}

/// Minimal read-side host inspection; no privileged host-profile acceptance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DoctorReport {
    /// OS name metadata.
    pub os_name: Observation<Text>,
    /// OS version metadata.
    pub os_version: Observation<Text>,
    /// Kernel release metadata.
    pub kernel_release: Observation<Text>,
    /// Architecture metadata.
    pub architecture: Observation<Text>,
    /// Candidate hosting-profile acceptance is not inferred from OS metadata.
    #[serde(default = "not_checked")]
    pub hosting_profile: Observation<Text>,
    /// Effective site confinement needs the later adversarial host proof.
    #[serde(default = "not_checked")]
    pub site_confinement: Observation<Text>,
}

fn not_checked<T>() -> Observation<T> {
    Observation::Unknown {
        reason: UnknownReason::NotChecked,
    }
}

/// Inventory provenance, not permission to mutate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ownership {
    /// Created by a recorded Rustiron workflow.
    Created,
    /// Adopted explicitly by an operator.
    ExplicitlyAdopted,
    /// Observed with no mutation authority.
    ObservedOnly,
    /// Provenance is not established.
    Unknown,
}

/// A bounded site row from coordinator inventory.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SiteSummary {
    /// Opaque resource ID, never a path.
    pub site_id: Id,
    /// Untrusted display data.
    pub name: Text,
    /// Inventory provenance.
    pub ownership: Ownership,
    /// Original reporting provenance; absent in older v1 responses.
    #[serde(default, deserialize_with = "crate::codec::optional_object")]
    pub inventory: Option<crate::InventoryProvenance>,
}

/// A bounded page with an opaque continuation token.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SitePage {
    /// At most MAX_PAGE_SIZE records; codecs enforce the count.
    #[serde(deserialize_with = "crate::codec::object_list")]
    pub items: Vec<SiteSummary>,
    /// None means the end of the current traversal.
    #[serde(deserialize_with = "Option::deserialize")]
    pub next_cursor: Option<Id>,
}

/// Site inspection without raw configuration or credentials.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SiteDetail {
    /// Inventory identity and provenance.
    #[serde(deserialize_with = "crate::codec::object")]
    pub site: SiteSummary,
    /// Known generation reference, not configuration contents.
    pub configuration_generation: Observation<Id>,
}

/// The initially enabled methods have no host mutation effects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadCommand {
    /// Inspect accessible host metadata.
    Doctor,
    /// Read a bounded inventory page.
    SiteList {
        /// Opaque continuation token.
        cursor: Option<Id>,
        /// Validated requested size.
        limit: PageLimit,
    },
    /// Inspect a site present in permitted inventory.
    SiteInspect {
        /// Opaque ID, not a caller-authored path.
        site_id: Id,
    },
    /// Read an executor's recorded state, without inferring current host state.
    OperationStatus {
        /// The operation to inspect.
        operation_id: Id,
    },
    /// Read one self-attested recovery receipt.
    EvidenceExport {
        /// The operation whose receipt is requested.
        operation_id: Id,
    },
}

/// A validated read-only request; byte entrypoints enforce transport bounds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    /// Correlates the response without exposing a secret.
    pub request_id: Id,
    /// Fixed semantic request.
    pub command: ReadCommand,
}

/// Successful read data, tagged independently from operation states.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ReadData {
    /// Host metadata.
    Doctor(#[serde(deserialize_with = "crate::codec::object")] DoctorReport),
    /// Inventory page.
    SiteList(#[serde(deserialize_with = "crate::codec::object")] SitePage),
    /// A single inventory record.
    SiteInspect(#[serde(deserialize_with = "crate::codec::object")] SiteDetail),
    /// Recorded executor state for one operation.
    OperationStatus(
        #[serde(deserialize_with = "crate::codec::object")] crate::execution::StatusValue,
    ),
    /// Self-attested receipt for one operation.
    EvidenceExport(
        #[serde(deserialize_with = "crate::codec::object")] crate::execution::EvidenceValue,
    ),
}

/// Exactly one success payload or error; wire codecs emit the required null slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Response {
    /// None when a malformed request could not supply a trustworthy correlation ID.
    pub request_id: Option<Id>,
    /// Read success or bounded error, never both.
    pub result: Result<ReadData, crate::ApiError>,
}
