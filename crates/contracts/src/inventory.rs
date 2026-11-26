use crate::{Id, MAX_RESPONSE_BYTES, ProtocolError, SchemaVersion, Text, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Maximum records in an explicit observation snapshot; not a hosting-density claim.
pub const MAX_INVENTORY_SITES: usize = 1000;

/// Origin of inventory metadata, never an execution authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InventorySource {
    /// Metadata explicitly reported by the operator, not a live verified host probe.
    OperatorReport,
}

/// Provenance retained on imported observations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InventoryProvenance {
    /// Reported observation time, not an acceptance or import timestamp.
    pub reported_at: Timestamp,
    /// Unprivileged metadata source.
    pub source: InventorySource,
}

/// Closed import record: it cannot assert adoption or contain privileged paths.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportedSite {
    /// Opaque site reference.
    pub site_id: Id,
    /// Untrusted display text; producers must exclude credentials.
    pub name: Text,
    /// Reported generation reference, not configuration contents.
    pub configuration_generation: Option<Id>,
}

/// Explicit complete report for the coordinator, not an authoritative host manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventorySnapshot {
    /// Supported import schema.
    pub schema_version: SchemaVersion,
    /// Reporting source and original time.
    #[serde(deserialize_with = "closed_provenance")]
    pub report: InventoryProvenance,
    /// Caller declares a complete report scope; partial replacement is refused.
    pub complete: bool,
    /// Bounded unique records.
    #[serde(deserialize_with = "crate::codec::object_list")]
    pub sites: Vec<ReportedSite>,
}

fn closed_provenance<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<InventoryProvenance, D::Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Report {
        reported_at: Timestamp,
        source: InventorySource,
    }
    let report = crate::codec::object::<D, Report>(decoder)?;
    Ok(InventoryProvenance {
        reported_at: report.reported_at,
        source: report.source,
    })
}

impl InventorySnapshot {
    /// Validates full-replacement semantics, limits and duplicate identifiers.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if !self.complete || self.sites.len() > MAX_INVENTORY_SITES {
            return Err(ProtocolError::InvalidMessage);
        }
        let mut identifiers = BTreeSet::new();
        for site in &self.sites {
            if !identifiers.insert(site.site_id.as_str()) {
                return Err(ProtocolError::InvalidMessage);
            }
        }
        Ok(())
    }
}

/// Decodes a bounded closed observation import, rejecting duplicates before buffering.
pub fn decode_inventory_snapshot(bytes: &[u8]) -> Result<InventorySnapshot, ProtocolError> {
    crate::codec::validate_json(bytes, MAX_RESPONSE_BYTES, ProtocolError::RequestTooLarge)?;
    let snapshot: InventorySnapshot =
        serde_json::from_slice(bytes).map_err(|_| ProtocolError::InvalidMessage)?;
    snapshot.validate()?;
    Ok(snapshot)
}

/// Emits a bounded metadata export, preserving reporting provenance.
pub fn encode_inventory_snapshot(snapshot: &InventorySnapshot) -> Result<Vec<u8>, ProtocolError> {
    snapshot.validate()?;
    let bytes = serde_json::to_vec(snapshot).map_err(|_| ProtocolError::InvalidMessage)?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(ProtocolError::ResponseTooLarge);
    }
    Ok(bytes)
}
