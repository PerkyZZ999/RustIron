//! Shared wire contracts for Rustiron's local, versioned interfaces.
//!
//! This crate defines data contracts, not authorization or privileged effects.
#![warn(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "W672: production code returns errors; tests may unwrap (clippy.toml)"
)]

use std::error::Error;
use std::fmt;

pub mod apply;
pub mod approval;
mod canonical;
mod codec;
mod error;
pub mod execution;
mod inventory;
pub mod local;
pub mod migration;
mod model;
mod render;
pub mod summary;

pub use canonical::CanonicalObject;
pub use codec::{decode_request, decode_response, encode_request, encode_response};
pub use error::{ApiError, ErrorCode, ProtocolError};
pub use inventory::{
    InventoryProvenance, InventorySnapshot, InventorySource, MAX_INVENTORY_SITES, ReportedSite,
    decode_inventory_snapshot, encode_inventory_snapshot,
};
pub use model::{
    DoctorReport, Id, MAX_JSON_DEPTH, MAX_PAGE_SIZE, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
    Observation, ObservationSource, Ownership, PageLimit, ReadCommand, ReadData, Request, Response,
    SiteDetail, SitePage, SiteSummary, Text, Timestamp, UnknownReason,
};
pub use render::{escape_human, render_human};

/// A protocol schema version supported by this build.
///
/// Unknown versions must be rejected rather than interpreted as the current one.
///
/// ```
/// use rustiron_contracts::SchemaVersion;
///
/// let version = SchemaVersion::try_from(1)?;
/// assert_eq!(version, SchemaVersion::V1);
/// assert_eq!(version.get(), 1);
/// # Ok::<(), rustiron_contracts::UnsupportedVersion>(())
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct SchemaVersion(u16);

impl SchemaVersion {
    /// The initial local protocol schema.
    pub const V1: Self = Self(1);

    /// Returns the numeric value used in wire envelopes.
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for SchemaVersion {
    type Error = UnsupportedVersion;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::V1),
            other => Err(UnsupportedVersion(other)),
        }
    }
}

impl From<SchemaVersion> for u16 {
    fn from(version: SchemaVersion) -> Self {
        version.get()
    }
}

/// A wire schema version this build cannot interpret.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsupportedVersion(u16);

impl UnsupportedVersion {
    /// Returns the rejected numeric version.
    pub const fn received(self) -> u16 {
        self.0
    }
}

impl fmt::Display for UnsupportedVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "unsupported schema version {}; expected 1",
            self.0
        )
    }
}

impl Error for UnsupportedVersion {}
