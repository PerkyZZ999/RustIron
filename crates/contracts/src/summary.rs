//! D-104 (W779): a bounded, closed host summary projected from the executor
//! observation. Recorded journal facts only; no paths, keys, plans, or receipts.

use serde::{Deserialize, Serialize};

use crate::{ApiError, Id, MAX_INVENTORY_SITES, ProtocolError, Text, Timestamp};

/// One provision as the journal records it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiteState {
    /// Opaque site ID.
    pub site_id: Id,
    /// The hostname it serves; untrusted display data.
    pub hostname: Text,
    /// Recorded provision state, for example `succeeded` or `quarantined`.
    pub state: Id,
    /// The failed provisioning step, when one is recorded.
    pub failed_step: Option<Id>,
    /// Whether a succeeded ejection hands the site to the operator.
    pub ejected: bool,
}

/// One served certificate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateState {
    /// Opaque site ID.
    pub site_id: Id,
    /// The certificate's hostname; untrusted display data.
    pub hostname: Text,
    /// Expiry, UTC Unix seconds.
    pub not_after: Timestamp,
    /// `expired`, `expires_soon`, or `renewal_failed`; none when it is fine.
    pub finding: Option<Id>,
    /// Whether the newest renewal failed.
    pub last_renewal_failed: bool,
    /// `rustiron` or `operator`.
    pub renewed_by: Id,
}

/// One recorded capture or restore probe.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedRun {
    /// Its operation ID, for `operation_status` and `evidence_export`.
    pub operation_id: Id,
    /// Recorded state, for example `succeeded`.
    pub state: Id,
    /// Start, UTC Unix seconds.
    pub started_at: Timestamp,
    /// Finish, when it finished.
    pub finished_at: Option<Timestamp>,
}

/// The newest capture and restore probe of one site.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiteBackups {
    /// Opaque site ID.
    pub site_id: Id,
    /// The newest capture, by start time.
    pub capture: Option<RecordedRun>,
    /// The newest restore probe, by start time.
    pub probe: Option<RecordedRun>,
}

/// The host summary: recorded facts, not a live probe of any site.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostSummary {
    /// When the executor built this summary.
    pub observed_at: Timestamp,
    /// The journal's last admission time.
    pub journal_last_time: Timestamp,
    /// Whether the installed signature verifier still has the enrolled digest.
    pub signature_verifier_matches: bool,
    /// Whether a product backup destination is enrolled.
    pub backup_destination_enrolled: bool,
    /// The enrolled retention, in days.
    pub backup_retention_days: Option<u32>,
    /// Every recorded provision, at most [`MAX_INVENTORY_SITES`].
    pub sites: Vec<SiteState>,
    /// Every served certificate, at most [`MAX_INVENTORY_SITES`].
    pub certificates: Vec<CertificateState>,
    /// Sites with a capture or probe, at most [`MAX_INVENTORY_SITES`].
    pub backups: Vec<SiteBackups>,
}

impl HostSummary {
    /// Refuses lists over the bound or repeated site IDs.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        fn unique<'a>(ids: impl Iterator<Item = &'a Id>) -> bool {
            let mut seen = std::collections::BTreeSet::new();
            ids.into_iter().all(|id| seen.insert(id.as_str()))
        }
        if self.sites.len() > MAX_INVENTORY_SITES
            || self.certificates.len() > MAX_INVENTORY_SITES
            || self.backups.len() > MAX_INVENTORY_SITES
            || !unique(self.sites.iter().map(|site| &site.site_id))
            || !unique(self.backups.iter().map(|site| &site.site_id))
        {
            return Err(ProtocolError::InvalidMessage);
        }
        Ok(())
    }
}

/// A read-only request for the host summary.
#[derive(Debug, Eq, PartialEq)]
pub struct HostSummaryQuery {
    /// Correlation identifier for this query.
    pub request_id: Id,
}

/// Decodes a closed `host_summary` executor query.
pub fn decode_host_summary_query(bytes: &[u8]) -> Result<HostSummaryQuery, ProtocolError> {
    crate::execution::decode_bare_query(bytes, "host_summary")
        .map(|request_id| HostSummaryQuery { request_id })
}

/// Encodes one `host_summary` executor query.
pub fn encode_host_summary_query(query: &HostSummaryQuery) -> Result<Vec<u8>, ProtocolError> {
    crate::execution::encode_bare_query(&query.request_id, "host_summary")
}

/// Decodes a correlated, validated `host_summary` executor response.
pub fn decode_host_summary_response(
    bytes: &[u8],
    query: &HostSummaryQuery,
) -> Result<Result<HostSummary, ApiError>, ProtocolError> {
    let value = match crate::execution::decode_bare_reply(bytes, &query.request_id, "host_summary")?
    {
        Ok(value) => value,
        Err(error) => return Ok(Err(error)),
    };
    let summary: HostSummary =
        serde_json::from_value(value).map_err(|_| ProtocolError::InvalidMessage)?;
    summary.validate()?;
    Ok(Ok(summary))
}
