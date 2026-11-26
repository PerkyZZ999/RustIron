//! W591 (P01): derive [`TargetProfile`] and [`TargetState`] directly from a
//! target host's merged read-only observation (`rustiron-lab-observation/1`
//! with `machine` of `rustiron-host-status/1`).
//!
//! Pure and fail-closed: an observation without enrolled migration PHP versions
//! or without observed PHP modules for every enrolled version is refused, so
//! the planner never guesses target capabilities or existing claims.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::{PhpExtension, PhpVersion, TargetProfile, TargetState};
use crate::approval::{Hostname, SiteId};
use crate::{Id, ProtocolError, Text};

/// Maximum merged target observation size accepted offline (4 MiB).
pub const MAX_TARGET_OBSERVATION_BYTES: usize = 4 * 1024 * 1024;

/// Dedicated SSHSIG namespace for signed P01 operator migration declarations.
/// Distinct from `rustiron-plan-v1`, `rustiron-receipt-v1`, and `rustiron-release-v1`.
pub const DECLARATION_NAMESPACE: &str = "rustiron-migration-declaration-v1";

const OBSERVATION_SCHEMA: &str = "rustiron-lab-observation/1";
const HOST_STATUS_SCHEMA: &str = "rustiron-host-status/1";
const MAX_ENROLLED_PHP_VERSIONS: usize = 8;
const MAX_OBSERVED_PHP_EXTENSIONS: usize = 256;

/// Target capabilities, existing claims, and host identity derived from a
/// target host's merged observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedTarget {
    /// Enrolled host identifier from `host.host_id`.
    pub host_id: Id,
    /// Enrolled host epoch from `host.host_epoch`.
    pub host_epoch: Id,
    /// Enrolled LSPHP versions and extensions available in every enrolled version.
    pub profile: TargetProfile,
    /// Existing site IDs, hostnames (including active aliases and adopted sites),
    /// Unix site accounts, and database names observed on the target.
    pub state: TargetState,
}

/// Derives a closed [`ObservedTarget`] from a merged target observation JSON.
///
/// Refuses observations that:
/// - exceed [`MAX_TARGET_OBSERVATION_BYTES`] or are not valid JSON objects,
/// - do not carry `schema == "rustiron-lab-observation/1"` and
///   `machine.schema == "rustiron-host-status/1"`,
/// - lack `host.migration_php_versions` (1..=8 distinct valid PHP versions),
/// - lack `machine.stack.php_extensions` for any enrolled PHP version, or
/// - contain malformed site IDs, hostnames, states, or account names.
pub fn derive_target_from_observation(bytes: &[u8]) -> Result<ObservedTarget, ProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_TARGET_OBSERVATION_BYTES {
        return Err(if bytes.len() > MAX_TARGET_OBSERVATION_BYTES {
            ProtocolError::RequestTooLarge
        } else {
            ProtocolError::InvalidMessage
        });
    }
    let root: Value = serde_json::from_slice(bytes).map_err(|_| ProtocolError::InvalidMessage)?;
    let root_obj = root.as_object().ok_or(ProtocolError::InvalidMessage)?;
    if root_obj.get("schema").and_then(Value::as_str) != Some(OBSERVATION_SCHEMA) {
        return Err(ProtocolError::InvalidMessage);
    }
    let host = root_obj
        .get("host")
        .and_then(Value::as_object)
        .ok_or(ProtocolError::InvalidMessage)?;
    let host_id = parse_id(host.get("host_id"))?;
    let host_epoch = parse_id(host.get("host_epoch"))?;

    let machine = root_obj
        .get("machine")
        .and_then(Value::as_object)
        .ok_or(ProtocolError::InvalidMessage)?;
    if machine.get("schema").and_then(Value::as_str) != Some(HOST_STATUS_SCHEMA) {
        return Err(ProtocolError::InvalidMessage);
    }

    let profile = derive_profile(host, machine)?;
    let state = derive_state(root_obj, host, machine)?;
    Ok(ObservedTarget {
        host_id,
        host_epoch,
        profile,
        state,
    })
}

fn parse_id(value: Option<&Value>) -> Result<Id, ProtocolError> {
    let text = value
        .and_then(Value::as_str)
        .ok_or(ProtocolError::InvalidMessage)?;
    Id::try_from(text.to_owned())
}

fn derive_profile(
    host: &serde_json::Map<String, Value>,
    machine: &serde_json::Map<String, Value>,
) -> Result<TargetProfile, ProtocolError> {
    let raw_versions = host
        .get("migration_php_versions")
        .and_then(Value::as_array)
        .ok_or(ProtocolError::InvalidMessage)?;
    if raw_versions.is_empty() || raw_versions.len() > MAX_ENROLLED_PHP_VERSIONS {
        return Err(ProtocolError::InvalidMessage);
    }
    let mut php_versions = Vec::with_capacity(raw_versions.len());
    let mut seen_versions = BTreeSet::new();
    for entry in raw_versions {
        let text = entry.as_str().ok_or(ProtocolError::InvalidMessage)?;
        let version = PhpVersion::try_from(text.to_owned())?;
        if !seen_versions.insert(version.clone()) {
            return Err(ProtocolError::InvalidMessage);
        }
        php_versions.push(version);
    }

    let ext_map = machine
        .get("stack")
        .and_then(Value::as_object)
        .and_then(|stack| stack.get("php_extensions"))
        .and_then(Value::as_object)
        .ok_or(ProtocolError::InvalidMessage)?;

    // Intersection across every enrolled PHP version (TargetProfile contract).
    let mut common: Option<BTreeSet<PhpExtension>> = None;
    for version in &php_versions {
        let raw_exts = ext_map
            .get(version.as_str())
            .and_then(Value::as_array)
            .ok_or(ProtocolError::InvalidMessage)?;
        if raw_exts.is_empty() || raw_exts.len() > MAX_OBSERVED_PHP_EXTENSIONS {
            return Err(ProtocolError::InvalidMessage);
        }
        let mut set = BTreeSet::new();
        for ext in raw_exts {
            let text = ext.as_str().ok_or(ProtocolError::InvalidMessage)?;
            set.insert(PhpExtension::try_from(text.to_owned())?);
        }
        common = Some(match common {
            None => set,
            Some(existing) => existing.intersection(&set).cloned().collect(),
        });
    }
    let php_extensions: Vec<PhpExtension> = common.unwrap_or_default().into_iter().collect();
    if php_extensions.is_empty() {
        return Err(ProtocolError::InvalidMessage);
    }
    Ok(TargetProfile {
        php_versions,
        php_extensions,
    })
}

fn derive_state(
    root: &serde_json::Map<String, Value>,
    host: &serde_json::Map<String, Value>,
    machine: &serde_json::Map<String, Value>,
) -> Result<TargetState, ProtocolError> {
    let sites = root
        .get("sites")
        .and_then(Value::as_array)
        .ok_or(ProtocolError::InvalidMessage)?;

    let mut site_ids: BTreeMap<String, SiteId> = BTreeMap::new();
    let mut hostnames: BTreeMap<String, Hostname> = BTreeMap::new();
    let mut accounts: BTreeMap<String, Text> = BTreeMap::new();
    let mut databases: BTreeMap<String, Text> = BTreeMap::new();

    for entry in sites {
        let site = entry.as_object().ok_or(ProtocolError::InvalidMessage)?;
        let site_id_str = site
            .get("site_id")
            .and_then(Value::as_str)
            .ok_or(ProtocolError::InvalidMessage)?;
        let site_id =
            SiteId::try_from(site_id_str.to_owned()).map_err(|_| ProtocolError::InvalidMessage)?;
        let hostname_str = site
            .get("hostname")
            .and_then(Value::as_str)
            .ok_or(ProtocolError::InvalidMessage)?;
        let hostname = Hostname::try_from(hostname_str.to_owned())
            .map_err(|_| ProtocolError::InvalidMessage)?;
        let state = site
            .get("state")
            .and_then(Value::as_str)
            .ok_or(ProtocolError::InvalidMessage)?;
        if !matches!(
            state,
            "running" | "succeeded" | "quarantined" | "adopted" | "deleted"
        ) {
            return Err(ProtocolError::InvalidMessage);
        }

        // Every provision row reserves its site_id and hostname for the journal's
        // lifetime (including quarantined and deleted sites under D-085).
        site_ids.insert(site_id.as_str().to_owned(), site_id.clone());
        hostnames.insert(hostname.as_str().to_owned(), hostname);

        if let Some(alias_val) = site.get("alias_hostname")
            && !alias_val.is_null()
        {
            let alias_str = alias_val.as_str().ok_or(ProtocolError::InvalidMessage)?;
            let alias = Hostname::try_from(alias_str.to_owned())
                .map_err(|_| ProtocolError::InvalidMessage)?;
            hostnames.insert(alias.as_str().to_owned(), alias);
        }

        if state != "deleted" {
            let account = Text::try_from(site_id.account_name())?;
            accounts.insert(account.as_str().to_owned(), account.clone());
            databases.insert(account.as_str().to_owned(), account);
        }
    }

    if let Some(adopted_val) = host.get("adopted_sites")
        && !adopted_val.is_null()
    {
        let adopted = adopted_val
            .as_array()
            .ok_or(ProtocolError::InvalidMessage)?;
        for entry in adopted {
            let host_str = entry
                .as_object()
                .and_then(|obj| obj.get("hostname"))
                .and_then(Value::as_str)
                .ok_or(ProtocolError::InvalidMessage)?;
            let host_name = Hostname::try_from(host_str.to_owned())
                .map_err(|_| ProtocolError::InvalidMessage)?;
            hostnames.insert(host_name.as_str().to_owned(), host_name);
        }
    }

    if let Some(site_accounts_val) = machine.get("site_accounts")
        && !site_accounts_val.is_null()
    {
        let site_accounts = site_accounts_val
            .as_array()
            .ok_or(ProtocolError::InvalidMessage)?;
        for entry in site_accounts {
            let acct_str = entry.as_str().ok_or(ProtocolError::InvalidMessage)?;
            let account = Text::try_from(acct_str.to_owned())?;
            accounts.insert(account.as_str().to_owned(), account);
        }
    }

    if let Some(services_val) = machine.get("services")
        && !services_val.is_null()
    {
        let services = services_val
            .as_array()
            .ok_or(ProtocolError::InvalidMessage)?;
        for entry in services {
            if let Some(unit) = entry
                .as_object()
                .and_then(|obj| obj.get("unit"))
                .and_then(Value::as_str)
                && let Some(account) = unit
                    .strip_prefix("rustiron-site-php@")
                    .and_then(|rest| rest.strip_suffix(".service"))
                && !account.is_empty()
            {
                let account_text = Text::try_from(account.to_owned())?;
                accounts.insert(account_text.as_str().to_owned(), account_text);
            }
        }
    }

    Ok(TargetState {
        site_ids: site_ids.into_values().collect(),
        hostnames: hostnames.into_values().collect(),
        accounts: accounts.into_values().collect(),
        databases: databases.into_values().collect(),
    })
}
