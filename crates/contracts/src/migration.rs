//! P01 migration inventory and dry-run planner (no effects).
//!
//! The inventory describes a source site from an export that the operator made
//! with the incumbent's own tool. Each fact is observed (read from the export by
//! an unprivileged worker), declared (by the operator), or unknown. The planner
//! is a pure function: it either returns the ordered target steps or every
//! refusal it finds. It never authorizes an effect: under D-053 one signed
//! `site_import` plan covers the steps, and serving the site needs a separate
//! signed `config_activate`. See `docs/technical/MIGRATION-INVENTORY.md`.

mod assembly;
mod target;

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::approval::{Hostname, Sha256Digest, SiteId};
use crate::{ProtocolError, SchemaVersion, Text, Timestamp, escape_human};

pub use assembly::{
    ExportObservation, ExportReason, ExportStatus, OperatorDeclaration, TlsObservation, TreeReport,
    assemble_inventory, decode_export_observation, decode_operator_declaration, decode_tree_report,
};
pub use target::{
    DECLARATION_NAMESPACE, MAX_TARGET_OBSERVATION_BYTES, ObservedTarget,
    derive_target_from_observation,
};

/// Maximum encoded inventory size.
pub const MAX_MIGRATION_INVENTORY_BYTES: usize = 64 * 1024;
const MAX_ALIASES: usize = 64;
const MAX_DATABASES: usize = 16;
const MAX_EXTENSIONS: usize = 128;
const MAX_ADDRESSES: usize = 16;

/// Where one inventory fact comes from.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fact<T> {
    /// Read from the export by the unprivileged inventory worker.
    Observed(T),
    /// Stated by the operator in the signed questionnaire.
    Declared(T),
    /// Neither observed nor declared.
    Unknown,
}

/// `<major>.<minor>`, for example `8.2`.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct PhpVersion(String);

impl PhpVersion {
    /// The validated version text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PhpVersion {
    type Error = ProtocolError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let valid = match value.split_once('.') {
            Some((major, minor)) => {
                major.len() == 1
                    && matches!(major.as_bytes()[0], b'5'..=b'9')
                    && (1..=2).contains(&minor.len())
                    && minor.bytes().all(|byte| byte.is_ascii_digit())
            }
            None => false,
        };
        if !valid {
            return Err(ProtocolError::InvalidMessage);
        }
        Ok(Self(value))
    }
}

/// `[a-z][a-z0-9_]{0,31}`: a PHP extension name.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct PhpExtension(String);

impl PhpExtension {
    /// The validated extension name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PhpExtension {
    type Error = ProtocolError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let bytes = value.as_bytes();
        if !(1..=32).contains(&bytes.len())
            || !bytes[0].is_ascii_lowercase()
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
        {
            return Err(ProtocolError::InvalidMessage);
        }
        Ok(Self(value))
    }
}

/// The declared source host profile; a comparison reference only.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceProfile {
    /// Operating system and version.
    pub os: Text,
    /// Hosting panel and version.
    pub panel: Text,
    /// Web server and version.
    pub web_server: Text,
}

/// The worker's summary of the exported file tree.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileSummary {
    /// Files and directories in the tree.
    pub entries: u64,
    /// Total regular-file bytes.
    pub bytes: u64,
    /// Digest of the worker's sorted per-file manifest.
    pub manifest_sha256: Sha256Digest,
    /// Links, special files, setuid or setgid files, and paths that leave the root.
    pub unsafe_entries: u64,
}

/// The uploads part of the file tree.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadSummary {
    /// Regular files under the uploads tree.
    pub files: u64,
    /// Their total bytes.
    pub bytes: u64,
}

/// One database dump, from its header.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DumpSummary {
    /// Dump size in bytes.
    pub bytes: u64,
    /// Default character set.
    pub charset: Text,
    /// Default collation.
    pub collation: Text,
}

/// D-066: what an export holds but the import leaves on the source.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeftKind {
    /// A database that the live `wp-config.php` does not name.
    Database,
    /// CyberPanel's `mail.<hostname>` child domain with only its placeholder.
    ChildDomain,
}

/// D-066: one export entry the import leaves on the source.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeftOnSource {
    /// What it is.
    pub kind: LeftKind,
    /// Its database or domain name, from the export.
    pub name: Text,
    /// Dump size in bytes, for a database.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
}

/// D-066: at most this many entries are left on the source.
pub const MAX_LEFT_ON_SOURCE: usize = 16;

/// The source certificate; reported only, its private key is never read.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSummary {
    /// Certificate subject.
    pub subject: Text,
    /// Certificate issuer.
    pub issuer: Text,
    /// Expiry time.
    pub not_after: Timestamp,
}

/// Credential counts; values and hashes never enter the inventory.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialCounts {
    /// Database users with grants on the site's databases.
    pub database_users: u32,
    /// Panel users for the site.
    pub panel_users: u32,
    /// Panel API tokens.
    pub api_tokens: u32,
}

/// The declared DNS situation; Rustiron changes none of it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsFacts {
    /// Who serves the zone.
    pub authority: Text,
    /// Current A and AAAA answers for the hostname.
    pub addresses: Vec<Text>,
}

/// The declared mail records and path; Rustiron changes none of it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailRecords {
    /// MX records.
    pub mx: u32,
    /// An SPF record exists.
    pub spf: bool,
    /// A DKIM record exists.
    pub dkim: bool,
    /// A DMARC record exists.
    pub dmarc: bool,
    /// How the site sends mail.
    pub outbound: Text,
}

/// A closed source-site inventory. Unknown members are refused, so credentials
/// cannot ride along in extra fields.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationInventory {
    /// Supported inventory schema.
    pub schema_version: SchemaVersion,
    /// Declared source host profile.
    pub source_profile: Fact<SourceProfile>,
    /// Primary hostname, observed.
    pub hostname: Fact<Hostname>,
    /// Primary hostname, restated by the operator.
    pub declared_hostname: Fact<Hostname>,
    /// Alias hostnames, observed.
    pub aliases: Fact<Vec<Hostname>>,
    /// Child domains, observed.
    pub child_domains: Fact<u32>,
    /// The file tree, observed.
    pub files: Fact<FileSummary>,
    /// The uploads tree, observed.
    pub uploads: Fact<UploadSummary>,
    /// Database dumps, observed.
    pub databases: Fact<Vec<DumpSummary>>,
    /// Source PHP version, observed.
    pub php_version: Fact<PhpVersion>,
    /// PHP extensions the site uses, declared.
    pub php_extensions: Fact<Vec<PhpExtension>>,
    /// WordPress site URL from the dump, observed.
    pub site_url: Fact<Text>,
    /// WordPress home URL from the dump, observed.
    pub home_url: Fact<Text>,
    /// System cron entries for the site user, declared.
    pub cron_entries: Fact<u32>,
    /// Source certificate, observed; `null` when the site has none.
    pub tls: Fact<Option<TlsSummary>>,
    /// Credential counts, observed.
    pub credentials: Fact<CredentialCounts>,
    /// DNS authority and answers, declared.
    pub dns: Fact<DnsFacts>,
    /// DNS records in the export, observed.
    pub dns_records: Fact<u32>,
    /// Mail records and path, declared.
    pub mail: Fact<MailRecords>,
    /// Mail accounts in the export, observed.
    pub mail_accounts: Fact<u32>,
    /// Consumers of the incumbent panel API, declared.
    pub api_consumers: Fact<u32>,
    /// D-066: export entries the import leaves on the source, observed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub left_on_source: Vec<LeftOnSource>,
}

impl MigrationInventory {
    fn within_bounds(&self) -> bool {
        let list = |fact_len: Option<usize>, max: usize| fact_len.is_none_or(|len| len <= max);
        list(value(&self.aliases).map(Vec::len), MAX_ALIASES)
            && list(value(&self.databases).map(Vec::len), MAX_DATABASES)
            && list(value(&self.php_extensions).map(Vec::len), MAX_EXTENSIONS)
            && list(
                value(&self.dns).map(|dns| dns.addresses.len()),
                MAX_ADDRESSES,
            )
            && self.left_on_source.len() <= MAX_LEFT_ON_SOURCE
    }
}

fn value<T>(fact: &Fact<T>) -> Option<&T> {
    match fact {
        Fact::Observed(value) | Fact::Declared(value) => Some(value),
        Fact::Unknown => None,
    }
}

/// Decodes a bounded closed inventory.
pub fn decode_migration_inventory(bytes: &[u8]) -> Result<MigrationInventory, ProtocolError> {
    crate::codec::validate_json(
        bytes,
        MAX_MIGRATION_INVENTORY_BYTES,
        ProtocolError::RequestTooLarge,
    )?;
    let inventory: MigrationInventory =
        serde_json::from_slice(bytes).map_err(|_| ProtocolError::InvalidMessage)?;
    if !inventory.within_bounds() {
        return Err(ProtocolError::InvalidMessage);
    }
    Ok(inventory)
}

/// What the operator asks for.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationRequest {
    /// The new target site.
    pub site_id: SiteId,
    /// The target LSPHP version, stated explicitly even when unchanged.
    pub target_php: PhpVersion,
    /// D-070: the hostname the target serves the site under, when it is not
    /// the source's. Absent or equal to the source's means no change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<Hostname>,
    /// D-075: explicit request for the one observed static alias.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias_hostname: Option<Hostname>,
}

/// The enrolled target profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetProfile {
    /// Installed LSPHP versions.
    pub php_versions: Vec<PhpVersion>,
    /// Extensions available in every installed version.
    pub php_extensions: Vec<PhpExtension>,
}

/// What already exists on the target, from its current observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetState {
    /// Known site IDs.
    pub site_ids: Vec<SiteId>,
    /// Served or recorded hostnames.
    pub hostnames: Vec<Hostname>,
    /// Unix accounts.
    pub accounts: Vec<Text>,
    /// Database names.
    pub databases: Vec<Text>,
}

/// An inventory field, for refusal reasons.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    /// `source_profile`
    SourceProfile,
    /// `hostname`
    Hostname,
    /// `declared_hostname`
    DeclaredHostname,
    /// `aliases`
    Aliases,
    /// `child_domains`
    ChildDomains,
    /// `files`
    Files,
    /// `uploads`
    Uploads,
    /// `databases`
    Databases,
    /// `php_version`
    PhpVersion,
    /// `php_extensions`
    PhpExtensions,
    /// `site_url`
    SiteUrl,
    /// `home_url`
    HomeUrl,
    /// `cron_entries`
    CronEntries,
    /// `tls`
    Tls,
    /// `credentials`
    Credentials,
    /// `dns`
    Dns,
    /// `dns_records`
    DnsRecords,
    /// `mail`
    Mail,
    /// `mail_accounts`
    MailAccounts,
    /// `api_consumers`
    ApiConsumers,
}

/// Why the planner refuses. The planner reports every reason it finds.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    /// A required field is unknown, so the inventory is incomplete.
    Unknown(Field),
    /// A field came from the wrong source (observed versus declared).
    WrongSource(Field),
    /// The declared hostname differs from the observed one.
    HostnameContradiction,
    /// The uploads tree is larger than the whole file tree.
    UploadsExceedFiles,
    /// The target site ID exists.
    SiteExists,
    /// The hostname exists on the target.
    HostnameExists,
    /// The site account exists on the target.
    AccountExists,
    /// The site database exists on the target.
    DatabaseExists,
    /// The export holds links, special or setuid files, or escaping paths.
    UnsafeEntries,
    /// The alias request and observed export do not fit the D-075 scope.
    AliasesUnsupported,
    /// Child domains are not supported in the first slice.
    ChildDomainsUnsupported,
    /// The first slice needs exactly one database; D-074 also accepts none.
    DatabaseCount,
    /// D-074: a static site (no database) under another hostname.
    StaticHostnameChange,
    /// A URL is not the primary hostname at the root.
    UrlChange(Field),
    /// The target profile lacks an extension the site uses.
    MissingExtension(PhpExtension),
    /// The requested target PHP version is not installed.
    PhpVersionUnavailable,
}

/// One target step. One signed `site_import` plan covers them all (D-053).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    /// Create the site identity, directories, database, and PHP unit with no application.
    Provision {
        /// The provisioning recipe.
        recipe: ImportRecipe,
    },
    /// Import the file tree as the site user.
    ImportFiles {
        /// Entries to import.
        entries: u64,
        /// Bytes to import.
        bytes: u64,
        /// The manifest the imported tree must match.
        manifest_sha256: Sha256Digest,
    },
    /// Import the dump as the site's database user.
    ImportDatabase {
        /// Dump bytes.
        bytes: u64,
        /// Dump character set.
        charset: Text,
        /// Dump collation.
        collation: Text,
    },
    /// Write the new database credentials into the site's configuration as the site user.
    RotateDatabaseCredentials,
    /// D-070: serve the site under another hostname: replace its links in
    /// the site's database. The D-069 path move uses the source hostname.
    ChangeHostname {
        /// The source site's hostname.
        from: Hostname,
        /// The hostname the target serves.
        to: Hostname,
    },
    /// Run the site sandbox check and probe the site on a test hostname.
    SandboxCheckAndProbe,
}

/// Provisioning recipes for a migrated site.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportRecipe {
    /// Site identity without an application, for an import.
    ImportV1,
    /// D-074: the same, for a static site with no database content.
    ImportStaticV1,
}

/// What the plan reports and leaves alone.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Reported {
    source_profile: SourceProfile,
    uploads: UploadSummary,
    cron_entries: u32,
    tls: Option<TlsSummary>,
    credentials: CredentialCounts,
    dns: DnsFacts,
    dns_records: u32,
    mail: MailRecords,
    mail_accounts: u32,
    api_consumers: u32,
    left_on_source: Vec<LeftOnSource>,
}

/// A dry-run migration plan. It changes nothing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DryRunPlan {
    site_id: SiteId,
    /// The hostname the target serves.
    hostname: Hostname,
    /// D-070: the source hostname, when it differs from `hostname`.
    source_hostname: Option<Hostname>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    alias_hostname: Option<Hostname>,
    php: (PhpVersion, PhpVersion),
    steps: Vec<Step>,
    reported: Reported,
}

impl DryRunPlan {
    /// The ordered target steps.
    pub fn steps(&self) -> &[Step] {
        &self.steps
    }

    /// The served hostname.
    pub fn hostname(&self) -> &Hostname {
        &self.hostname
    }

    /// D-070: the source hostname, when the target serves another one.
    pub fn source_hostname(&self) -> Option<&Hostname> {
        self.source_hostname.as_ref()
    }

    /// The source and target PHP versions, when they differ.
    pub fn php_change(&self) -> Option<(&PhpVersion, &PhpVersion)> {
        (self.php.0 != self.php.1).then_some((&self.php.0, &self.php.1))
    }
}

#[derive(Clone, Copy)]
enum Source {
    Observed,
    Declared,
}

struct Check<'a> {
    refusals: &'a mut Vec<Refusal>,
}

impl Check<'_> {
    fn take<'f, T>(&mut self, fact: &'f Fact<T>, field: Field, wanted: Source) -> Option<&'f T> {
        match (fact, wanted) {
            (Fact::Observed(value), Source::Observed)
            | (Fact::Declared(value), Source::Declared) => Some(value),
            (Fact::Unknown, _) => {
                self.refusals.push(Refusal::Unknown(field));
                None
            }
            _ => {
                self.refusals.push(Refusal::WrongSource(field));
                None
            }
        }
    }
}

fn url_is_root_of(url: &str, hostname: &Hostname) -> bool {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"));
    rest.is_some_and(|rest| {
        rest == hostname.as_str() || rest.strip_suffix('/') == Some(hostname.as_str())
    })
}

/// Plans a migration, or returns every refusal found. No effect happens here.
pub fn plan_migration(
    inventory: &MigrationInventory,
    request: &MigrationRequest,
    profile: &TargetProfile,
    state: &TargetState,
) -> Result<DryRunPlan, Vec<Refusal>> {
    use Source::{Declared, Observed};
    let mut refusals = Vec::new();
    let mut check = Check {
        refusals: &mut refusals,
    };
    let i = inventory;
    let source_profile = check.take(&i.source_profile, Field::SourceProfile, Declared);
    let hostname = check.take(&i.hostname, Field::Hostname, Observed);
    let declared_hostname = check.take(&i.declared_hostname, Field::DeclaredHostname, Declared);
    let aliases = check.take(&i.aliases, Field::Aliases, Observed);
    let child_domains = check.take(&i.child_domains, Field::ChildDomains, Observed);
    let files = check.take(&i.files, Field::Files, Observed);
    let uploads = check.take(&i.uploads, Field::Uploads, Observed);
    let databases = check.take(&i.databases, Field::Databases, Observed);
    let php_version = check.take(&i.php_version, Field::PhpVersion, Observed);
    let php_extensions = check.take(&i.php_extensions, Field::PhpExtensions, Declared);
    // D-074: a static site has no dump, so no WordPress URLs to observe.
    let is_static = matches!(&i.databases, Fact::Observed(dumps) if dumps.is_empty());
    let (site_url, home_url) = if is_static {
        (None, None)
    } else {
        (
            check.take(&i.site_url, Field::SiteUrl, Observed),
            check.take(&i.home_url, Field::HomeUrl, Observed),
        )
    };
    let cron_entries = check.take(&i.cron_entries, Field::CronEntries, Declared);
    let tls = check.take(&i.tls, Field::Tls, Observed);
    let credentials = check.take(&i.credentials, Field::Credentials, Observed);
    let dns = check.take(&i.dns, Field::Dns, Declared);
    let dns_records = check.take(&i.dns_records, Field::DnsRecords, Observed);
    let mail = check.take(&i.mail, Field::Mail, Declared);
    let mail_accounts = check.take(&i.mail_accounts, Field::MailAccounts, Observed);
    let api_consumers = check.take(&i.api_consumers, Field::ApiConsumers, Declared);

    if let (Some(observed), Some(declared)) = (hostname, declared_hostname)
        && observed != declared
    {
        refusals.push(Refusal::HostnameContradiction);
    }
    if let (Some(files), Some(uploads)) = (files, uploads)
        && (uploads.files > files.entries || uploads.bytes > files.bytes)
    {
        refusals.push(Refusal::UploadsExceedFiles);
    }
    if files.is_some_and(|files| files.unsafe_entries > 0) {
        refusals.push(Refusal::UnsafeEntries);
    }
    let alias = request.alias_hostname.as_ref();
    let alias_ok = match (aliases.map(Vec::as_slice), alias) {
        (Some([]) | None, None) => true,
        (Some([observed]), Some(alias)) => {
            is_static && observed == alias && hostname.is_some_and(|primary| primary != alias)
        }
        _ => false,
    };
    if !alias_ok {
        refusals.push(Refusal::AliasesUnsupported);
    }
    if child_domains.is_some_and(|count| *count > 0) {
        refusals.push(Refusal::ChildDomainsUnsupported);
    }
    if databases.is_some_and(|dumps| dumps.len() > 1) {
        refusals.push(Refusal::DatabaseCount);
    }
    if is_static
        && let (Some(served), Some(observed)) = (request.hostname.as_ref(), hostname)
        && served != observed
    {
        refusals.push(Refusal::StaticHostnameChange);
    }
    if let Some(hostname) = hostname {
        for (field, url) in [(Field::SiteUrl, site_url), (Field::HomeUrl, home_url)] {
            if url.is_some_and(|url| !url_is_root_of(url.as_str(), hostname)) {
                refusals.push(Refusal::UrlChange(field));
            }
        }
        // D-070: the hostname that must be free is the one the target serves.
        let served = request.hostname.as_ref().unwrap_or(hostname);
        if state.hostnames.contains(served)
            || alias.is_some_and(|name| state.hostnames.contains(name))
        {
            refusals.push(Refusal::HostnameExists);
        }
    }
    let account = request.site_id.account_name();
    if state.site_ids.contains(&request.site_id) {
        refusals.push(Refusal::SiteExists);
    }
    if state.accounts.iter().any(|name| name.as_str() == account) {
        refusals.push(Refusal::AccountExists);
    }
    if state.databases.iter().any(|name| name.as_str() == account) {
        refusals.push(Refusal::DatabaseExists);
    }
    if !profile.php_versions.contains(&request.target_php) {
        refusals.push(Refusal::PhpVersionUnavailable);
    }
    let available: BTreeSet<&PhpExtension> = profile.php_extensions.iter().collect();
    for extension in php_extensions.into_iter().flatten() {
        if !available.contains(extension) {
            refusals.push(Refusal::MissingExtension(extension.clone()));
        }
    }

    let complete = (
        source_profile,
        hostname,
        files,
        uploads,
        // D-074: `Some(None)` is a static site; `None` an unknown database.
        databases.map(|dumps| dumps.first()),
        php_version,
        cron_entries,
        tls,
        credentials,
        dns,
        dns_records,
        mail,
        mail_accounts,
        api_consumers,
    );
    let (
        Some(source_profile),
        Some(hostname),
        Some(files),
        Some(uploads),
        Some(dump),
        Some(php_version),
        Some(cron_entries),
        Some(tls),
        Some(credentials),
        Some(dns),
        Some(dns_records),
        Some(mail),
        Some(mail_accounts),
        Some(api_consumers),
    ) = complete
    else {
        return Err(refusals);
    };
    if !refusals.is_empty() {
        return Err(refusals);
    }
    let served = request.hostname.as_ref().unwrap_or(hostname);
    let source_hostname = (served != hostname).then(|| hostname.clone());
    let recipe = if dump.is_some() {
        ImportRecipe::ImportV1
    } else {
        ImportRecipe::ImportStaticV1
    };
    let mut steps = vec![
        Step::Provision { recipe },
        Step::ImportFiles {
            entries: files.entries,
            bytes: files.bytes,
            manifest_sha256: files.manifest_sha256.clone(),
        },
    ];
    if let Some(dump) = dump {
        steps.push(Step::ImportDatabase {
            bytes: dump.bytes,
            charset: dump.charset.clone(),
            collation: dump.collation.clone(),
        });
        steps.push(Step::RotateDatabaseCredentials);
    }
    if let Some(from) = &source_hostname {
        steps.push(Step::ChangeHostname {
            from: from.clone(),
            to: served.clone(),
        });
    }
    steps.push(Step::SandboxCheckAndProbe);
    Ok(DryRunPlan {
        site_id: request.site_id.clone(),
        hostname: served.clone(),
        source_hostname,
        alias_hostname: alias.cloned(),
        php: (php_version.clone(), request.target_php.clone()),
        steps,
        reported: Reported {
            source_profile: source_profile.clone(),
            uploads: uploads.clone(),
            cron_entries: *cron_entries,
            tls: tls.clone(),
            credentials: credentials.clone(),
            dns: dns.clone(),
            dns_records: *dns_records,
            mail: mail.clone(),
            mail_accounts: *mail_accounts,
            api_consumers: *api_consumers,
            left_on_source: inventory.left_on_source.clone(),
        },
    })
}

fn present(flag: bool) -> &'static str {
    if flag { "present" } else { "absent" }
}

/// Renders the dry run for a terminal; every operator or export text is escaped.
pub fn render_dry_run(plan: &DryRunPlan) -> String {
    let e = |text: &Text| escape_human(text.as_str());
    let r = &plan.reported;
    let mut out = format!(
        "Dry run: nothing changes on any host.\nSite {} for {}.\nSource: {}, {}, {}.\n",
        plan.site_id.as_str(),
        plan.hostname.as_str(),
        e(&r.source_profile.os),
        e(&r.source_profile.panel),
        e(&r.source_profile.web_server),
    );
    if let Some(source) = &plan.source_hostname {
        out.push_str(&format!(
            "Hostname changes from {} to {}: sign a site_import plan of schema 2 with source_hostname {}.\n",
            source.as_str(),
            plan.hostname.as_str(),
            source.as_str()
        ));
    }
    if let Some(alias) = &plan.alias_hostname {
        out.push_str(&format!(
            "HTTP alias on the enrolled loopback listener: {}. Sign a site_import plan of schema 3.\n",
            alias.as_str()
        ));
    }
    match plan.php_change() {
        Some((from, to)) => out.push_str(&format!(
            "PHP changes from {} to {}.\n",
            from.as_str(),
            to.as_str()
        )),
        None => out.push_str(&format!("PHP stays {}.\n", plan.php.1.as_str())),
    }
    out.push_str("Steps, all in one signed site_import plan:\n");
    for (number, step) in plan.steps.iter().enumerate() {
        let line = match step {
            Step::Provision { recipe } => format!(
                "provision the site identity, database, and PHP unit with recipe {}",
                match recipe {
                    ImportRecipe::ImportV1 => "import_v1",
                    ImportRecipe::ImportStaticV1 =>
                        "import_static_v1 (a static site: the database stays empty)",
                }
            ),
            Step::ImportFiles {
                entries,
                bytes,
                manifest_sha256,
            } => format!(
                "import {entries} entries ({bytes} bytes) as the site user; manifest {}",
                manifest_sha256.as_str()
            ),
            Step::ImportDatabase {
                bytes,
                charset,
                collation,
            } => format!(
                "import the {bytes}-byte dump ({}, {}) as the site's database user",
                e(charset),
                e(collation)
            ),
            Step::RotateDatabaseCredentials => {
                "write new database credentials into the site configuration as the site user"
                    .to_owned()
            }
            Step::ChangeHostname { from, to } => format!(
                "replace //{} with //{} in the site's database, as the site; mail addresses and post GUIDs stay",
                from.as_str(),
                to.as_str()
            ),
            Step::SandboxCheckAndProbe => {
                "check the site sandbox and probe the site on a test hostname".to_owned()
            }
        };
        out.push_str(&format!("  {}. {line}\n", number + 1));
    }
    out.push_str("Serving the site needs a separate signed config_activate plan.\n");
    out.push_str(&format!(
        "Uploads: {} files, {} bytes.\n",
        r.uploads.files, r.uploads.bytes
    ));
    match &r.tls {
        Some(tls) => out.push_str(&format!(
            "TLS: {} from {}, expires at {}; the key is not imported.\n",
            e(&tls.subject),
            e(&tls.issuer),
            tls.not_after.get()
        )),
        None => out.push_str("TLS: none on the source.\n"),
    }
    let addresses: Vec<String> = r.dns.addresses.iter().map(e).collect();
    out.push_str(&format!(
        "No DNS record changes. Authority: {}; answers: {}; {} records in the export.\n",
        e(&r.dns.authority),
        addresses.join(", "),
        r.dns_records
    ));
    out.push_str(&format!(
        "No mail setting changes. MX {}, SPF {}, DKIM {}, DMARC {}, outbound: {}. {} mail accounts stay on the incumbent.\n",
        r.mail.mx,
        present(r.mail.spf),
        present(r.mail.dkim),
        present(r.mail.dmarc),
        e(&r.mail.outbound),
        r.mail_accounts
    ));
    out.push_str(&format!(
        "Not imported: {} database users, {} panel users, {} API tokens. {} cron entries and {} API consumers are reported only.\n",
        r.credentials.database_users,
        r.credentials.panel_users,
        r.credentials.api_tokens,
        r.cron_entries,
        r.api_consumers
    ));
    // D-066: what the export holds but the import leaves on the source.
    for left in &r.left_on_source {
        out.push_str(&match (left.kind, left.bytes) {
            (LeftKind::Database, Some(bytes)) => format!(
                "Left on the source: database {} ({bytes} bytes), which the live wp-config.php does not name.\n",
                e(&left.name)
            ),
            (LeftKind::Database, None) => format!(
                "Left on the source: database {}, which the live wp-config.php does not name.\n",
                e(&left.name)
            ),
            (LeftKind::ChildDomain, _) => format!(
                "Left on the source: child domain {}, which holds only the panel's placeholder page.\n",
                e(&left.name)
            ),
        });
    }
    out
}
