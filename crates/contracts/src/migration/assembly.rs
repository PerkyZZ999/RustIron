//! Builds a [`MigrationInventory`] from its two sources.
//!
//! The export worker writes an [`ExportObservation`] and the operator writes an
//! [`OperatorDeclaration`]. Each type holds only the fields of its own source,
//! so a worker cannot declare a fact and an operator cannot claim to have
//! observed one. A `null` member means that source does not know the fact.

use serde::{Deserialize, Deserializer, Serialize};

use super::{
    CredentialCounts, DnsFacts, DumpSummary, Fact, FileSummary, MAX_MIGRATION_INVENTORY_BYTES,
    MailRecords, MigrationInventory, PhpExtension, PhpVersion, SourceProfile, TlsSummary,
    UploadSummary,
};
use crate::approval::Hostname;
use crate::{ProtocolError, SchemaVersion, Text};

/// A present member whose value may be `null`; a missing member is refused.
fn known<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    decoder: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(decoder)
}

/// The worker's outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportStatus {
    /// Every observation in the report was made.
    Complete,
    /// The worker stopped on an error; it observed nothing.
    Error,
    /// The worker reached a fixed limit; it observed nothing.
    Limit,
}

/// Why the worker stopped. No path, name, or content enters a reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportReason {
    /// Reading failed.
    Io,
    /// The export layout is not the supported one.
    Unsupported,
    /// An entry changed during the walk.
    Changed,
    /// The worker ran as root or with mismatched identities.
    Identity,
    /// `meta.xml` is malformed or outside the closed field set.
    Metadata,
    /// Entry limit.
    Entries,
    /// Depth limit.
    Depth,
    /// Time limit.
    Time,
}

/// The source certificate as the worker saw it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsObservation {
    /// The export holds no certificate.
    None,
    /// The export holds this certificate.
    Certificate(TlsSummary),
}

/// What the unprivileged export worker observed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportObservation {
    /// Supported schema.
    pub schema_version: SchemaVersion,
    /// Outcome.
    pub status: ExportStatus,
    /// Present exactly when the status is not complete.
    #[serde(deserialize_with = "known")]
    pub reason: Option<ExportReason>,
    /// Primary hostname.
    #[serde(deserialize_with = "known")]
    pub hostname: Option<Hostname>,
    /// Alias hostnames.
    #[serde(deserialize_with = "known")]
    pub aliases: Option<Vec<Hostname>>,
    /// Child domains.
    #[serde(deserialize_with = "known")]
    pub child_domains: Option<u32>,
    /// File tree summary.
    #[serde(deserialize_with = "known")]
    pub files: Option<FileSummary>,
    /// Uploads tree summary.
    #[serde(deserialize_with = "known")]
    pub uploads: Option<UploadSummary>,
    /// Database dumps.
    #[serde(deserialize_with = "known")]
    pub databases: Option<Vec<DumpSummary>>,
    /// Source PHP version.
    #[serde(deserialize_with = "known")]
    pub php_version: Option<PhpVersion>,
    /// WordPress site URL.
    #[serde(deserialize_with = "known")]
    pub site_url: Option<Text>,
    /// WordPress home URL.
    #[serde(deserialize_with = "known")]
    pub home_url: Option<Text>,
    /// Source certificate.
    #[serde(deserialize_with = "known")]
    pub tls: Option<TlsObservation>,
    /// Credential counts.
    #[serde(deserialize_with = "known")]
    pub credentials: Option<CredentialCounts>,
    /// DNS records in the export.
    #[serde(deserialize_with = "known")]
    pub dns_records: Option<u32>,
    /// Mail accounts in the export.
    #[serde(deserialize_with = "known")]
    pub mail_accounts: Option<u32>,
    /// D-066: entries the import leaves on the source; absent when none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left_on_source: Option<Vec<super::LeftOnSource>>,
}

impl ExportObservation {
    /// A report of a stopped worker: every observation is unknown.
    pub fn stopped(status: ExportStatus, reason: ExportReason) -> Self {
        Self {
            schema_version: SchemaVersion::V1,
            status,
            reason: Some(reason),
            hostname: None,
            aliases: None,
            child_domains: None,
            files: None,
            uploads: None,
            databases: None,
            php_version: None,
            site_url: None,
            home_url: None,
            tls: None,
            credentials: None,
            dns_records: None,
            mail_accounts: None,
            left_on_source: None,
        }
    }

    fn consistent(&self) -> bool {
        match self.status {
            ExportStatus::Complete => self.reason.is_none(),
            ExportStatus::Error | ExportStatus::Limit => {
                let limit = matches!(
                    self.reason,
                    Some(ExportReason::Entries | ExportReason::Depth | ExportReason::Time)
                );
                self.reason.is_some()
                    && (self.status == ExportStatus::Limit) == limit
                    && *self == Self::stopped(self.status, self.reason.unwrap_or(ExportReason::Io))
            }
        }
    }
}

/// What the operator declares in the signed questionnaire.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorDeclaration {
    /// Supported schema.
    pub schema_version: SchemaVersion,
    /// Source host profile.
    #[serde(deserialize_with = "known")]
    pub source_profile: Option<SourceProfile>,
    /// Primary hostname, restated.
    #[serde(deserialize_with = "known")]
    pub hostname: Option<Hostname>,
    /// PHP extensions the site uses.
    #[serde(deserialize_with = "known")]
    pub php_extensions: Option<Vec<PhpExtension>>,
    /// System cron entries for the site user.
    #[serde(deserialize_with = "known")]
    pub cron_entries: Option<u32>,
    /// DNS authority and answers.
    #[serde(deserialize_with = "known")]
    pub dns: Option<DnsFacts>,
    /// Mail records and path.
    #[serde(deserialize_with = "known")]
    pub mail: Option<MailRecords>,
    /// Consumers of the incumbent panel API.
    #[serde(deserialize_with = "known")]
    pub api_consumers: Option<u32>,
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, ProtocolError> {
    crate::codec::validate_json(
        bytes,
        MAX_MIGRATION_INVENTORY_BYTES,
        ProtocolError::RequestTooLarge,
    )?;
    serde_json::from_slice(bytes).map_err(|_| ProtocolError::InvalidMessage)
}

/// Decodes a bounded worker report and checks its status and reason.
pub fn decode_export_observation(bytes: &[u8]) -> Result<ExportObservation, ProtocolError> {
    let observation: ExportObservation = decode(bytes)?;
    if !observation.consistent() {
        return Err(ProtocolError::InvalidMessage);
    }
    Ok(observation)
}

/// Decodes a bounded operator declaration.
pub fn decode_operator_declaration(bytes: &[u8]) -> Result<OperatorDeclaration, ProtocolError> {
    decode(bytes)
}

fn observed<T: Clone>(value: &Option<T>) -> Fact<T> {
    value.clone().map_or(Fact::Unknown, Fact::Observed)
}

fn declared<T: Clone>(value: &Option<T>) -> Fact<T> {
    value.clone().map_or(Fact::Unknown, Fact::Declared)
}

/// Builds the inventory. Unknown facts stay unknown, so the planner refuses them.
/// The result goes through the same bounds as a decoded inventory.
pub fn assemble_inventory(
    observation: &ExportObservation,
    declaration: &OperatorDeclaration,
) -> Result<MigrationInventory, ProtocolError> {
    let o = observation;
    let d = declaration;
    let inventory = MigrationInventory {
        schema_version: SchemaVersion::V1,
        source_profile: declared(&d.source_profile),
        hostname: observed(&o.hostname),
        declared_hostname: declared(&d.hostname),
        aliases: observed(&o.aliases),
        child_domains: observed(&o.child_domains),
        files: observed(&o.files),
        uploads: observed(&o.uploads),
        databases: observed(&o.databases),
        php_version: observed(&o.php_version),
        php_extensions: declared(&d.php_extensions),
        site_url: observed(&o.site_url),
        home_url: observed(&o.home_url),
        cron_entries: declared(&d.cron_entries),
        tls: match &o.tls {
            None => Fact::Unknown,
            Some(TlsObservation::None) => Fact::Observed(None),
            Some(TlsObservation::Certificate(tls)) => Fact::Observed(Some(tls.clone())),
        },
        credentials: observed(&o.credentials),
        dns: declared(&d.dns),
        dns_records: observed(&o.dns_records),
        mail: declared(&d.mail),
        mail_accounts: observed(&o.mail_accounts),
        api_consumers: declared(&d.api_consumers),
        left_on_source: o.left_on_source.clone().unwrap_or_default(),
    };
    if !inventory.within_bounds() {
        return Err(ProtocolError::InvalidMessage);
    }
    Ok(inventory)
}

/// W448: the export worker's `--tree` report: the manifest of one folder
/// only. The Files step compares the imported `html` with the extracted
/// document root through it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeReport {
    /// Supported schema.
    pub schema_version: SchemaVersion,
    /// Outcome.
    pub status: ExportStatus,
    /// Present exactly when the status is not complete.
    #[serde(deserialize_with = "known")]
    pub reason: Option<ExportReason>,
    /// The folder's summary; present exactly when the status is complete.
    #[serde(deserialize_with = "known")]
    pub files: Option<FileSummary>,
}

impl TreeReport {
    fn consistent(&self) -> bool {
        let limit = matches!(
            self.reason,
            Some(ExportReason::Entries | ExportReason::Depth | ExportReason::Time)
        );
        match self.status {
            ExportStatus::Complete => self.reason.is_none() && self.files.is_some(),
            ExportStatus::Error => self.reason.is_some() && !limit && self.files.is_none(),
            ExportStatus::Limit => limit && self.files.is_none(),
        }
    }
}

/// Decodes a bounded tree report and checks its status and reason.
pub fn decode_tree_report(bytes: &[u8]) -> Result<TreeReport, ProtocolError> {
    let report: TreeReport = decode(bytes)?;
    if !report.consistent() {
        return Err(ProtocolError::InvalidMessage);
    }
    Ok(report)
}
