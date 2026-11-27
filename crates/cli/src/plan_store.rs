//! Store and read canonical plan bytes. This does not sign or submit them.

use crate::{Output, apply_cli, file_input};
use rustiron_contracts::{ErrorCode, Id, MAX_REQUEST_BYTES};
use rustiron_core::{PlanStore, PlanStoreError, StoredPlan};
use std::{
    io::{self, Write},
    path::Path,
    process::ExitCode,
};

pub(crate) fn import(directory: &Path, path: &Path, output: Output) -> ExitCode {
    let bytes = match file_input::read(path, MAX_REQUEST_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => return fail(error.exit_code(), "INVALID_REQUEST"),
    };
    let mut store = match PlanStore::open(directory).or_else(|_| PlanStore::initialize(directory)) {
        Ok(store) => store,
        Err(error) => return fail(code(error), label(error)),
    };
    match store.put(&bytes) {
        Ok(stored) => emit(&stored, output),
        Err(error) => fail(code(error), label(error)),
    }
}

pub(crate) struct StoredApply<'a> {
    pub directory: &'a Path,
    pub id: &'a Id,
    pub socket: &'a Path,
    pub grant_file: &'a Path,
    pub signature_file: &'a Path,
    pub operation_id: Id,
    pub idempotency_key: Id,
    pub output: Output,
}

pub(crate) fn apply_stored(request: StoredApply<'_>) -> ExitCode {
    let StoredApply {
        directory,
        id,
        socket,
        grant_file,
        signature_file,
        operation_id,
        idempotency_key,
        output,
    } = request;
    let mut store = match PlanStore::open(directory) {
        Ok(store) => store,
        Err(error) => return refuse(code(error), label(error)),
    };
    let plan = match store.get(id) {
        Ok(plan) => plan,
        Err(error) => return refuse(code(error), label(error)),
    };
    let Ok(prepared) = rustiron_contracts::approval::PreparedPlan::decode(&plan) else {
        return refuse(7, "UNAVAILABLE");
    };
    let Ok(grant) = file_input::read(grant_file, rustiron_contracts::MAX_REQUEST_BYTES) else {
        return refuse(2, "INVALID_GRANT");
    };
    let Ok(signature) = file_input::read(
        signature_file,
        rustiron_contracts::execution::MAX_SIGNATURE_TEXT,
    ) else {
        return refuse(2, "INVALID_GRANT");
    };
    let Ok(signature) = String::from_utf8(signature) else {
        return refuse(2, "INVALID_GRANT");
    };
    let Ok(claim) = serde_json::from_slice::<serde_json::Value>(&grant) else {
        return refuse(2, "INVALID_GRANT");
    };
    let claimed_id = claim.get("plan_id").and_then(|value| value.as_str());
    let claimed_digest = claim.get("plan_digest").and_then(|value| value.as_str());
    if claimed_id != Some(prepared.id().as_str()) {
        return refuse(4, "PLAN_ID_MISMATCH");
    }
    if claimed_digest != Some(prepared.digest().as_str()) {
        return refuse(4, "PLAN_DIGEST_MISMATCH");
    }
    apply_cli::run_bytes(
        socket,
        output,
        plan,
        grant,
        signature,
        apply_cli::Attempt {
            operation_id,
            idempotency_key,
            wait: std::time::Duration::from_secs(apply_cli::DEFAULT_WAIT_SECONDS),
        },
    )
}

pub(crate) fn inspect(directory: &Path, id: &Id, output: Output) -> ExitCode {
    let mut store = match PlanStore::open(directory) {
        Ok(store) => store,
        Err(error) => return fail(code(error), label(error)),
    };
    match store.get(id) {
        Ok(bytes) => crate::review_file::write_rendered(&bytes, output, "plan_inspect"),
        Err(error) => fail(code(error), label(error)),
    }
}

pub(crate) fn export(directory: &Path, id: &Id) -> ExitCode {
    let mut store = match PlanStore::open(directory) {
        Ok(store) => store,
        Err(error) => return fail(code(error), label(error)),
    };
    match store.get(id) {
        Ok(bytes) if io::stdout().lock().write_all(&bytes).is_ok() => ExitCode::SUCCESS,
        Ok(_) => ExitCode::from(7),
        Err(error) => fail(code(error), label(error)),
    }
}

fn emit(stored: &StoredPlan, output: Output) -> ExitCode {
    let stored_label = if stored.inserted { "new" } else { "existing" };
    let bytes = match output {
        Output::Json => serde_json::to_vec(&serde_json::json!({
            "scope": "plan_store",
            "plan_id": stored.id.as_str(),
            "verb": stored.kind.as_str(),
            "plan_digest": stored.digest.as_str(),
            "stored": stored_label,
            "authority": "none",
        })),
        Output::Human => Ok(format!(
            "plan_id: {}\nverb: {}\nplan digest: {}\nstored: {stored_label}\nauthority: none (stored bytes only; not signed or admitted)\n",
            stored.id.as_str(),
            stored.kind.as_str(),
            stored.digest.as_str()
        )
        .into_bytes()),
    };
    match bytes {
        Ok(mut bytes) => {
            if matches!(output, Output::Json) {
                bytes.push(b'\n');
            }
            if io::stdout().lock().write_all(&bytes).is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(7)
            }
        }
        Err(_) => ExitCode::from(7),
    }
}

fn fail(status: u8, name: &str) -> ExitCode {
    report(status, name, false)
}

fn refuse(status: u8, name: &str) -> ExitCode {
    report(status, name, true)
}

fn report(status: u8, name: &str, not_sent: bool) -> ExitCode {
    let mut body = serde_json::json!({
        "scope": "plan_store",
        "error": name,
        "authority": "none",
    });
    if not_sent {
        body["attempt"] = "not_sent".into();
    }
    let mut bytes = serde_json::to_vec(&body).unwrap_or_else(|_| {
        br#"{"scope":"plan_store","error":"UNAVAILABLE","authority":"none"}"#.to_vec()
    });
    bytes.push(b'\n');
    if io::stdout().lock().write_all(&bytes).is_ok() {
        ExitCode::from(status)
    } else {
        ExitCode::from(7)
    }
}

fn code(error: PlanStoreError) -> u8 {
    match error {
        PlanStoreError::InvalidPlan => ErrorCode::InvalidRequest.exit_code(),
        PlanStoreError::Conflict | PlanStoreError::NotFound => 4,
        PlanStoreError::Unauthorized => ErrorCode::UnauthorizedPeer.exit_code(),
        PlanStoreError::Unavailable => ErrorCode::DependencyUnavailable.exit_code(),
    }
}

fn label(error: PlanStoreError) -> &'static str {
    match error {
        PlanStoreError::InvalidPlan => "INVALID_PLAN",
        PlanStoreError::Conflict => "PLAN_ID_CONFLICT",
        PlanStoreError::NotFound => "PLAN_NOT_FOUND",
        PlanStoreError::Unauthorized => "UNAUTHORIZED",
        PlanStoreError::Unavailable => "UNAVAILABLE",
    }
}
