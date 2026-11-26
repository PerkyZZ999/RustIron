use std::{
    io::{self, Write},
    path::Path,
    process::ExitCode,
};

use rustiron_contracts::{
    ErrorCode,
    approval::{ApprovalError, MAX_PRODUCT_BACKUP_POLICY_BYTES, ProductBackupPolicy},
};

use crate::{Output, emit, failure, file_input};

pub(crate) fn run(path: &Path, output: Output) -> ExitCode {
    let policy = file_input::read(path, MAX_PRODUCT_BACKUP_POLICY_BYTES).and_then(|bytes| {
        ProductBackupPolicy::decode(&bytes).map_err(|error| match error {
            ApprovalError::RequestTooLarge => ErrorCode::RequestTooLarge,
            _ => ErrorCode::InvalidRequest,
        })
    });
    let policy = match policy {
        Ok(policy) => policy,
        Err(error) => return emit(&failure(error), output),
    };

    let id = policy.destination_id().as_str();
    let digest = policy.digest();
    let digest = digest.as_str();
    let mut stdout = io::stdout().lock();
    let result = match output {
        Output::Human => writeln!(
            stdout,
            "destination ID {id}\ndestination policy digest {digest}"
        ),
        Output::Json => writeln!(
            stdout,
            "{}",
            serde_json::json!({
                "destination_id": id,
                "destination_policy_digest": digest,
            })
        ),
    };
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(7)
    }
}
