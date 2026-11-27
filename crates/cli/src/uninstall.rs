//! Plan a management-only uninstall. Site data, ejected vhosts, and serving
//! prerequisites are never in the move set. Nothing is deleted.

use crate::{Output, file_input};
use rustiron_contracts::{ErrorCode, Id, MAX_RESPONSE_BYTES};
use std::{
    fs,
    io::{self, Write},
    path::{Component, Path, PathBuf},
    process::ExitCode,
};

const MOVE: &[&str] = &[
    "etc/rustiron-ols",
    "etc/rustiron-s02-lab",
    "var/lib/rustiron-s02-lab",
    "var/lib/rustiron-s04-lab",
    "usr/local/libexec/rustiron-s02-lab",
    "usr/local/libexec/rustiron-s02-lab-test",
    "etc/systemd/system/rustiron-s02-lab-executor.service",
    "etc/systemd/system/rustiron-s02-lab-executor.service.d",
];

const PROTECTED: &[&str] = &[
    "srv/sites",
    "var/lib/mysql",
    "etc/rustiron-ejected",
    "etc/ols-sites",
];

const STASH: &str = "root/rustiron-uninstalled";

pub(crate) fn plan(observation: &Path, output: Output) -> ExitCode {
    match load(observation) {
        Ok(plan) => emit(&plan, output, if plan.actionable { 0 } else { 4 }),
        Err(error) => fail(error),
    }
}

pub(crate) fn apply(prefix: &Path, observation: &Path, output: Output) -> ExitCode {
    let plan = match load(observation) {
        Ok(plan) => plan,
        Err(error) => return fail(error),
    };
    if !plan.actionable {
        return emit(&plan, output, 4);
    }
    if let Err(error) = move_management(prefix) {
        return fail(error);
    }
    emit(&plan, output, 0)
}

#[derive(serde::Serialize)]
struct UninstallPlan {
    scope: &'static str,
    authority: &'static str,
    deletes_site_data: bool,
    actionable: bool,
    still_managed: Vec<String>,
    move_paths: Vec<&'static str>,
    protected: Vec<&'static str>,
}

fn load(observation: &Path) -> Result<UninstallPlan, ErrorCode> {
    let bytes = file_input::read(observation, MAX_RESPONSE_BYTES)?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| ErrorCode::InvalidRequest)?;
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
    let mut still_managed = Vec::new();
    for site in sites {
        let site = site.as_object().ok_or(ErrorCode::InvalidRequest)?;
        let id = site
            .get("site_id")
            .and_then(|item| item.as_str())
            .ok_or(ErrorCode::InvalidRequest)?;
        Id::try_from(id.to_owned()).map_err(|_| ErrorCode::InvalidRequest)?;
        let ejected = site.get("ejected").and_then(serde_json::Value::as_bool) == Some(true);
        if !ejected {
            still_managed.push(id.to_owned());
        }
    }
    still_managed.sort();
    Ok(UninstallPlan {
        scope: "uninstall",
        authority: "none",
        deletes_site_data: false,
        actionable: still_managed.is_empty(),
        still_managed,
        move_paths: MOVE.to_vec(),
        protected: PROTECTED.to_vec(),
    })
}

fn move_management(prefix: &Path) -> Result<(), ErrorCode> {
    let prefix = fs::canonicalize(prefix).map_err(|_| ErrorCode::InvalidRequest)?;
    if !prefix.is_dir() {
        return Err(ErrorCode::InvalidRequest);
    }
    let stash = prefix.join(STASH);
    if stash.symlink_metadata().is_ok() {
        return Err(ErrorCode::InvalidRequest);
    }
    let mut present = Vec::new();
    for relative in MOVE {
        let path = prefixed(&prefix, relative)?;
        match path.symlink_metadata() {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(ErrorCode::DependencyUnavailable),
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(ErrorCode::InvalidRequest);
            }
            Ok(_) => {
                let parent = path.parent().ok_or(ErrorCode::InvalidRequest)?;
                let canonical = fs::canonicalize(parent).map_err(|_| ErrorCode::InvalidRequest)?;
                if !canonical.starts_with(&prefix) {
                    return Err(ErrorCode::InvalidRequest);
                }
                present.push(path);
            }
        }
    }
    if !present.is_empty() {
        fs::create_dir_all(&stash).map_err(|_| ErrorCode::DependencyUnavailable)?;
    }
    for path in present {
        let name = path
            .strip_prefix(&prefix)
            .map_err(|_| ErrorCode::InvalidRequest)?
            .to_string_lossy()
            .replace('/', "_");
        fs::rename(&path, stash.join(name)).map_err(|_| ErrorCode::DependencyUnavailable)?;
    }
    Ok(())
}

fn prefixed(prefix: &Path, relative: &str) -> Result<PathBuf, ErrorCode> {
    let relative = Path::new(relative);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ErrorCode::InvalidRequest);
    }
    Ok(prefix.join(relative))
}

fn emit(plan: &UninstallPlan, output: Output, status: u8) -> ExitCode {
    let bytes = match output {
        Output::Json => serde_json::to_vec(plan).unwrap_or_else(|_| {
            br#"{"scope":"uninstall","error":"UNAVAILABLE","authority":"none"}"#.to_vec()
        }),
        Output::Human => human(plan),
    };
    finish(bytes, status)
}

fn human(plan: &UninstallPlan) -> Vec<u8> {
    let mut text = format!(
        "authority: none\ndeletes site data: no\nactionable: {}\n",
        plan.actionable
    );
    for id in &plan.still_managed {
        text.push_str(&format!("still managed: {id}\n"));
    }
    for path in &plan.move_paths {
        text.push_str(&format!("move: {path}\n"));
    }
    for path in &plan.protected {
        text.push_str(&format!("protected: {path}\n"));
    }
    text.into_bytes()
}

fn fail(error: ErrorCode) -> ExitCode {
    let name = match error {
        ErrorCode::InvalidRequest => "INVALID_REQUEST",
        ErrorCode::RequestTooLarge => "REQUEST_TOO_LARGE",
        _ => "UNAVAILABLE",
    };
    let bytes = serde_json::to_vec(&serde_json::json!({
        "scope": "uninstall",
        "error": name,
        "authority": "none",
        "deletes_site_data": false,
    }))
    .unwrap_or_else(|_| {
        br#"{"scope":"uninstall","error":"UNAVAILABLE","authority":"none","deletes_site_data":false}"#.to_vec()
    });
    finish(bytes, error.exit_code())
}

fn finish(mut bytes: Vec<u8>, status: u8) -> ExitCode {
    bytes.push(b'\n');
    if io::stdout().lock().write_all(&bytes).is_ok() {
        ExitCode::from(status)
    } else {
        ExitCode::from(7)
    }
}
