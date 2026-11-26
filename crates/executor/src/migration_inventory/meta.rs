//! Reads the closed field set of a CyberPanel `meta.xml`.
//!
//! Elements that carry secrets (`userPassword`, `token`, `password`) are
//! never copied: only the presence of a token is counted.
use quick_xml::{Reader, events::Event};
use rustiron_contracts::{
    approval::Hostname,
    migration::{CredentialCounts, ExportReason, PhpVersion},
};

pub(crate) const MAX_META_BYTES: usize = 1024 * 1024;
const MAX_DEPTH: usize = 8;

/// What `meta.xml` states.
#[derive(Debug, Default)]
pub(crate) struct Meta {
    pub(crate) hostname: Option<Hostname>,
    /// `None` when the stated version is not `PHP <major>.<minor>`.
    pub(crate) php_version: Option<PhpVersion>,
    pub(crate) aliases: Vec<Hostname>,
    pub(crate) child_domains: u32,
    /// D-066: the child domains' names, in `meta.xml` order.
    pub(crate) child_domain_names: Vec<String>,
    pub(crate) databases: Vec<String>,
    pub(crate) database_users: u32,
    pub(crate) panel_users: u32,
    pub(crate) api_tokens: u32,
    pub(crate) dns_records: u32,
    pub(crate) mail_accounts: u32,
    php_seen: bool,
}

impl Meta {
    pub(crate) fn credentials(&self) -> CredentialCounts {
        CredentialCounts {
            database_users: self.database_users,
            panel_users: self.panel_users,
            api_tokens: self.api_tokens,
        }
    }
}

/// A database name that is safe as a dump file stem.
fn database_name(value: &str) -> Option<String> {
    ((1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'))
    .then(|| value.to_owned())
}

fn hostname(value: &str) -> Result<Hostname, ExportReason> {
    Hostname::try_from(value.to_owned()).map_err(|_| ExportReason::Metadata)
}

fn php(value: &str) -> Option<PhpVersion> {
    let version = value.strip_prefix("PHP ").unwrap_or(value);
    PhpVersion::try_from(version.to_owned()).ok()
}

fn bump(count: &mut u32) -> Result<(), ExportReason> {
    *count = count.checked_add(1).ok_or(ExportReason::Metadata)?;
    Ok(())
}

/// Parses `meta.xml`. Any structure outside the expected document is an error.
pub(crate) fn parse(bytes: &[u8]) -> Result<Meta, ExportReason> {
    if bytes.len() > MAX_META_BYTES {
        return Err(ExportReason::Metadata);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ExportReason::Metadata)?;
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(true);
    let mut meta = Meta::default();
    let mut stack: Vec<String> = Vec::new();
    let mut root_seen = false;
    loop {
        match reader.read_event().map_err(|_| ExportReason::Metadata)? {
            Event::Start(start) => {
                let qname = start.name();
                let name: &str = qname.as_ref();
                let name = name.to_owned();
                if stack.is_empty() {
                    if root_seen || name != "metaFile" {
                        return Err(ExportReason::Metadata);
                    }
                    root_seen = true;
                }
                stack.push(name);
                if stack.len() > MAX_DEPTH {
                    return Err(ExportReason::Metadata);
                }
                match path(&stack).as_slice() {
                    ["metaFile", "ChildDomains", "domain"] => bump(&mut meta.child_domains)?,
                    ["metaFile", "Databases", "database", "databaseUsers"] => {
                        bump(&mut meta.database_users)?;
                    }
                    ["metaFile", "dnsrecords", "dnsrecord"] => bump(&mut meta.dns_records)?,
                    ["metaFile", "emails", "emailAccount"] => bump(&mut meta.mail_accounts)?,
                    _ => {}
                }
            }
            Event::Empty(_) if stack.is_empty() => return Err(ExportReason::Metadata),
            Event::Empty(_) | Event::Comment(_) | Event::Decl(_) => {}
            Event::End(_) => {
                stack.pop();
            }
            Event::Text(text) => {
                let value = text.xml10_content();
                record(&mut meta, &path(&stack), &value)?;
            }
            // An entity or character reference inside a read value could hide
            // its real text; outside the read values it is skipped.
            Event::GeneralRef(_) => {
                if reads_value(&path(&stack)) {
                    return Err(ExportReason::Metadata);
                }
            }
            Event::Eof => break,
            Event::DocType(_) | Event::PI(_) | Event::CData(_) => {
                return Err(ExportReason::Metadata);
            }
        }
    }
    if !root_seen || !stack.is_empty() || !meta.php_seen {
        return Err(ExportReason::Metadata);
    }
    Ok(meta)
}

fn path(stack: &[String]) -> Vec<&str> {
    stack.iter().map(String::as_str).collect()
}

fn reads_value(path: &[&str]) -> bool {
    matches!(
        path,
        [
            "metaFile",
            "masterDomain" | "phpSelection" | "userName" | "token"
        ] | ["metaFile", "Aliases", "alias"]
            | ["metaFile", "ChildDomains", "domain", "domain"]
            | ["metaFile", "Databases", "database", "dbName"]
    )
}

fn record(meta: &mut Meta, path: &[&str], value: &str) -> Result<(), ExportReason> {
    match path {
        ["metaFile", "masterDomain"] => {
            if meta.hostname.is_some() {
                return Err(ExportReason::Metadata);
            }
            meta.hostname = Some(hostname(value)?);
        }
        ["metaFile", "phpSelection"] => {
            if meta.php_seen {
                return Err(ExportReason::Metadata);
            }
            meta.php_seen = true;
            meta.php_version = php(value);
        }
        ["metaFile", "userName"] if !value.is_empty() => bump(&mut meta.panel_users)?,
        // Only the presence of a token is counted; its text is dropped here.
        ["metaFile", "token"] if !value.is_empty() => bump(&mut meta.api_tokens)?,
        ["metaFile", "Aliases", "alias"] => meta.aliases.push(hostname(value)?),
        ["metaFile", "ChildDomains", "domain", "domain"] => {
            meta.child_domain_names
                .push(hostname(value)?.as_str().to_owned());
        }
        ["metaFile", "Databases", "database", "dbName"] => {
            let name = database_name(value).ok_or(ExportReason::Metadata)?;
            if meta.databases.contains(&name) {
                return Err(ExportReason::Metadata);
            }
            meta.databases.push(name);
        }
        _ => {}
    }
    Ok(())
}
