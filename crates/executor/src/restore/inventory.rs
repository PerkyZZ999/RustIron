//! Root-side launch and closed report validation; never walks restored content.
use super::{
    BIN, CREDENTIALS_DIR, LEVEL, ProbeTarget,
    inventory_report::{self, MAX_REPORT_BYTES, Report},
    restore_root, run_unit, site_below_restore, unit_name,
};
use crate::{ExecutorError, files};
use rustix::fs::{self, AtFlags};
use std::path::Path;

/// Unit stdout lands in the runner's (the admin helper's) runtime directory.
const OUTPUT: &str = crate::capture::OUTPUT_DIR;

pub(super) fn decode(bytes: &[u8]) -> Result<Report, ExecutorError> {
    inventory_report::decode(bytes).ok_or(ExecutorError::InvalidRequest)
}

pub(super) fn properties(output: &str) -> Vec<String> {
    vec![
        format!("SELinuxContext=system_u:system_r:rustiron_capture_t:{LEVEL}"),
        "PrivateNetwork=yes".to_owned(), "IPAddressDeny=any".to_owned(),
        format!("InaccessiblePaths=-{CREDENTIALS_DIR} -/run/credentials"),
        "UnsetEnvironment=AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE AWS_SHARED_CREDENTIALS_FILE AWS_CONFIG_FILE RESTIC_PASSWORD RESTIC_PASSWORD_FILE RESTIC_PASSWORD_COMMAND RESTIC_REPOSITORY RESTIC_REPOSITORY_FILE CREDENTIALS_DIRECTORY".to_owned(),
        format!("StandardOutput=truncate:{output}"),
    ]
}

pub(super) fn collect(target: &ProbeTarget<'_>) -> Result<Report, ExecutorError> {
    let unit = unit_name(target, "inventory")?;
    let name = format!("{unit}.inventory.json");
    let directory = files::open_traversable_directory(Path::new(OUTPUT), 0)?;
    let output = format!("{OUTPUT}/{name}");
    let ran = run_unit(
        target,
        &unit,
        &properties(&output),
        &[
            &format!("{BIN}/restore-inventory"),
            &restore_root(target),
            &site_below_restore(target),
        ],
    );
    let bytes = files::read_child(
        &directory,
        &name,
        0,
        files::Exposure::Readable,
        MAX_REPORT_BYTES,
    );
    let removed = fs::unlinkat(&directory, &name, AtFlags::empty());
    ran?;
    removed.map_err(|_| ExecutorError::Unavailable)?;
    decode(&bytes?)
}

#[cfg(test)]
#[path = "inventory_tests.rs"]
mod tests;
