//! The OLS adapter of [`crate::generation`]: OLS generations are read back
//! without the copies OLS writes itself ([`read_generation`]). The staging
//! rules (W384, W394) are documented in [`crate::generation`].

use std::os::fd::OwnedFd;

use rustiron_contracts::Id;

use super::{Generation, read_generation};
use crate::{ExecutorError, generation};

#[cfg(test)]
pub(crate) use crate::generation::leftovers_in;
pub use crate::generation::{QUARANTINE_MARK, STAGING_MARK, Staged, Staging};
pub(crate) use crate::generation::{random_hex, rename_verified};

/// Checks the folder under the id, moves a differing one aside, and writes
/// and verifies a temporary folder. Nothing gets the id here.
pub fn prepare(
    include: &OwnedFd,
    id: &Id,
    generation: &Generation,
    operation: &Id,
) -> Result<Staging, ExecutorError> {
    prepare_owned(include, id, generation, operation, 0)
}

/// Renames the temporary folder of [`prepare`] to the id, never over an
/// existing entry, and syncs `generations`.
pub fn publish(include: &OwnedFd, id: &Id, staging: Staging) -> Result<Staged, ExecutorError> {
    publish_owned(include, id, staging, 0)
}

/// [`prepare`] then [`publish`], with the required owner of `generations`
/// and its folders (the test user in unit tests).
#[cfg(test)]
pub(crate) fn stage_owned(
    include: &OwnedFd,
    id: &Id,
    generation: &Generation,
    operation: &Id,
    owner: u32,
) -> Result<Staged, ExecutorError> {
    let staging = prepare_owned(include, id, generation, operation, owner)?;
    publish_owned(include, id, staging, owner)
}

/// Names under `generations` that a staging left: temporary folders and
/// quarantined folders, in name order. Read-only.
pub fn leftovers(include: &OwnedFd) -> Result<Vec<String>, ExecutorError> {
    generation::leftovers(include, 0)
}

pub(crate) fn prepare_owned(
    include: &OwnedFd,
    id: &Id,
    generation: &Generation,
    operation: &Id,
    owner: u32,
) -> Result<Staging, ExecutorError> {
    generation::prepare(include, id, generation, operation, owner, read_generation)
}

pub(crate) fn publish_owned(
    include: &OwnedFd,
    id: &Id,
    staging: Staging,
    owner: u32,
) -> Result<Staged, ExecutorError> {
    generation::publish(include, id, staging, owner)
}

/// Writes and verifies a temporary folder, read back as OLS reads it.
pub(super) fn write_temporary(
    generations: &OwnedFd,
    temporary: &str,
    generation: &Generation,
    owner: u32,
) -> Result<(u64, u64), ExecutorError> {
    generation::write_temporary(generations, temporary, generation, owner, read_generation)
}
