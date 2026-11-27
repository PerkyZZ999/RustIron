//! Coordinator inventory export and a metadata comparison with an executor
//! observation. A match is not adoption and not journal authority.

use crate::{Output, file_input};
use rustiron_contracts::{
    ErrorCode, Id, MAX_RESPONSE_BYTES, Text, encode_inventory_snapshot, escape_human,
};
use rustiron_core::InventoryStore;
use std::{
    collections::BTreeMap,
    io::{self, Write},
    path::Path,
    process::ExitCode,
};

pub(crate) fn export(directory: &Path, output: Output) -> ExitCode {
    let mut store = match InventoryStore::open(directory) {
        Ok(store) => store,
        Err(error) => return fail(error),
    };
    let snapshot = match store.export() {
        Ok(snapshot) => snapshot,
        Err(error) => return fail(error),
    };
    let Ok(bytes) = encode_inventory_snapshot(&snapshot) else {
        return fail(ErrorCode::DependencyUnavailable);
    };
    let rendered = match output {
        Output::Json => {
            let mut bytes = bytes;
            bytes.push(b'\n');
            bytes
        }
        Output::Human => human_export(&snapshot),
    };
    write_out(&rendered)
}

pub(crate) fn compare(directory: &Path, observation: &Path, output: Output) -> ExitCode {
    let observed = match file_input::read(observation, MAX_RESPONSE_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => return fail(error),
    };
    let journal = match journal_sites(&observed) {
        Ok(sites) => sites,
        Err(error) => return fail(error),
    };
    let mut store = match InventoryStore::open(directory) {
        Ok(store) => store,
        Err(error) => return fail(error),
    };
    let snapshot = match store.export() {
        Ok(snapshot) => snapshot,
        Err(error) => return fail(error),
    };
    let mut coordinator = BTreeMap::new();
    for site in snapshot.sites {
        coordinator.insert(
            site.site_id.as_str().to_owned(),
            site.name.as_str().to_owned(),
        );
    }
    let report = difference(&coordinator, &journal);
    let status = if report.consistent { 0 } else { 4 };
    let bytes = match output {
        Output::Json => serde_json::to_vec(&report).unwrap_or_else(|_| {
            br#"{"scope":"state_compare","error":"UNAVAILABLE","authority":"none"}"#.to_vec()
        }),
        Output::Human => human_compare(&report),
    };
    let mut bytes = bytes;
    bytes.push(b'\n');
    if write_out(&bytes) == ExitCode::SUCCESS {
        ExitCode::from(status)
    } else {
        ExitCode::from(7)
    }
}

#[derive(serde::Serialize)]
struct CompareReport {
    scope: &'static str,
    authority: &'static str,
    consistent: bool,
    matched: usize,
    only_coordinator: Vec<String>,
    only_journal: Vec<String>,
    name_mismatch: Vec<NameMismatch>,
}

#[derive(serde::Serialize)]
struct NameMismatch {
    site_id: String,
    coordinator: String,
    journal: String,
}

fn difference(
    coordinator: &BTreeMap<String, String>,
    journal: &BTreeMap<String, String>,
) -> CompareReport {
    let mut only_coordinator = Vec::new();
    let mut only_journal = Vec::new();
    let mut name_mismatch = Vec::new();
    let mut matched = 0;
    for (id, name) in coordinator {
        match journal.get(id) {
            None => only_coordinator.push(id.clone()),
            Some(hostname) if hostname == name => matched += 1,
            Some(hostname) => name_mismatch.push(NameMismatch {
                site_id: id.clone(),
                coordinator: name.clone(),
                journal: hostname.clone(),
            }),
        }
    }
    for id in journal.keys() {
        if !coordinator.contains_key(id) {
            only_journal.push(id.clone());
        }
    }
    let consistent =
        only_coordinator.is_empty() && only_journal.is_empty() && name_mismatch.is_empty();
    CompareReport {
        scope: "state_compare",
        authority: "none",
        consistent,
        matched,
        only_coordinator,
        only_journal,
        name_mismatch,
    }
}

fn journal_sites(bytes: &[u8]) -> Result<BTreeMap<String, String>, ErrorCode> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| ErrorCode::InvalidRequest)?;
    let object = value.as_object().ok_or(ErrorCode::InvalidRequest)?;
    if object.get("schema").and_then(|item| item.as_str()) != Some("rustiron-lab-observation/1") {
        return Err(ErrorCode::InvalidRequest);
    }
    let sites = object
        .get("sites")
        .and_then(|item| item.as_array())
        .ok_or(ErrorCode::InvalidRequest)?;
    if sites.len() > 1000 {
        return Err(ErrorCode::InvalidRequest);
    }
    let mut found = BTreeMap::new();
    for site in sites {
        let site = site.as_object().ok_or(ErrorCode::InvalidRequest)?;
        let id = site
            .get("site_id")
            .and_then(|item| item.as_str())
            .ok_or(ErrorCode::InvalidRequest)?;
        let hostname = site
            .get("hostname")
            .and_then(|item| item.as_str())
            .ok_or(ErrorCode::InvalidRequest)?;
        Id::try_from(id.to_owned()).map_err(|_| ErrorCode::InvalidRequest)?;
        Text::try_from(hostname.to_owned()).map_err(|_| ErrorCode::InvalidRequest)?;
        if found.insert(id.to_owned(), hostname.to_owned()).is_some() {
            return Err(ErrorCode::InvalidRequest);
        }
    }
    Ok(found)
}

fn human_export(snapshot: &rustiron_contracts::InventorySnapshot) -> Vec<u8> {
    let mut text = format!(
        "authority: none (coordinator metadata; not the executor journal)\nsites: {}\n",
        snapshot.sites.len()
    );
    for site in &snapshot.sites {
        text.push_str(&format!(
            "{} {}\n",
            escape_human(site.site_id.as_str()),
            escape_human(site.name.as_str())
        ));
    }
    text.into_bytes()
}

fn human_compare(report: &CompareReport) -> Vec<u8> {
    let mut text = format!(
        "authority: none (metadata comparison; not adoption)\nconsistent: {}\nmatched: {}\n",
        report.consistent, report.matched
    );
    for id in &report.only_coordinator {
        text.push_str(&format!("only coordinator: {id}\n"));
    }
    for id in &report.only_journal {
        text.push_str(&format!("only journal: {id}\n"));
    }
    for mismatch in &report.name_mismatch {
        text.push_str(&format!(
            "name mismatch: {} coordinator={} journal={}\n",
            escape_human(&mismatch.site_id),
            escape_human(&mismatch.coordinator),
            escape_human(&mismatch.journal)
        ));
    }
    text.into_bytes()
}

fn fail(error: ErrorCode) -> ExitCode {
    let name = match error {
        ErrorCode::InvalidRequest => "INVALID_REQUEST",
        ErrorCode::RequestTooLarge => "REQUEST_TOO_LARGE",
        ErrorCode::UnauthorizedPeer => "UNAUTHORIZED",
        ErrorCode::DependencyUnavailable => "UNAVAILABLE",
        _ => "UNAVAILABLE",
    };
    let mut bytes = serde_json::to_vec(&serde_json::json!({
        "scope": "state",
        "error": name,
        "authority": "none",
    }))
    .unwrap_or_else(|_| br#"{"scope":"state","error":"UNAVAILABLE","authority":"none"}"#.to_vec());
    bytes.push(b'\n');
    if write_out(&bytes) == ExitCode::SUCCESS {
        ExitCode::from(error.exit_code())
    } else {
        ExitCode::from(7)
    }
}

fn write_out(bytes: &[u8]) -> ExitCode {
    if io::stdout().lock().write_all(bytes).is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(7)
    }
}
