//! Live fixture registry observation from fixed, root-derived locations.
//!
//! Layout below the trusted registry directory, never caller-selected:
//! `<resource_id>/current` is a symlink whose exact text is
//! `generations/<generation_id>`, and that generation holds one `content` file.
//! Generations are root-enrolled in advance; [`switch`] only repoints `current`.

use std::os::fd::OwnedFd;

use rustiron_contracts::{Id, approval::Sha256Digest};
use rustix::fs;
use sha2::{Digest, Sha256};

use crate::{
    ExecutorError,
    files::{Exposure, open_child_directory, read_child},
};

const MAX_CONTENT_BYTES: usize = 1024 * 1024;
const MAX_LINK_BYTES: usize = 128;

/// One complete current observation made by the executor itself.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct LiveObservation {
    pub generation: Id,
    pub digest: Sha256Digest,
}

pub(crate) fn observe(
    registry: &OwnedFd,
    resource: &Id,
    owner: u32,
) -> Result<LiveObservation, ExecutorError> {
    let unavailable = ExecutorError::RegistryUnavailable;
    let resource_dir = open_child_directory(registry, resource.as_str(), owner)?;
    let target = fs::readlinkat(&resource_dir, "current", Vec::with_capacity(MAX_LINK_BYTES))
        .map_err(|_| unavailable)?;
    let target = target.to_str().map_err(|_| unavailable)?;
    let generation = target
        .strip_prefix("generations/")
        .filter(|_| target.len() <= MAX_LINK_BYTES)
        .ok_or(unavailable)?;
    // Id validation refuses `/`, `.` and empty names, so this is one component.
    let generation = Id::try_from(generation.to_owned()).map_err(|_| unavailable)?;
    let digest = generation_digest(&resource_dir, &generation, owner)?;
    Ok(LiveObservation { generation, digest })
}

/// Digest of one enrolled generation's content, read descriptor-relative.
fn generation_digest(
    resource_dir: &OwnedFd,
    generation: &Id,
    owner: u32,
) -> Result<Sha256Digest, ExecutorError> {
    let generations = open_child_directory(resource_dir, "generations", owner)?;
    let directory = open_child_directory(&generations, generation.as_str(), owner)?;
    let content = read_child(
        &directory,
        "content",
        owner,
        Exposure::Readable,
        MAX_CONTENT_BYTES,
    )?;
    Ok(Sha256Digest::from_bytes(Sha256::digest(&content).into()))
}

/// Whether [`switch`] reached the atomic rename; after `Attempted` reality is
/// unknown until observed.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum SwitchOutcome {
    /// Refused before any registry write: target missing or digest mismatch.
    NotAttempted(ExecutorError),
    /// A temporary link was created and the rename was issued; may have failed.
    Attempted(Result<(), ExecutorError>),
}

/// Atomically repoints `current` at an enrolled target whose content matches
/// `target_digest`: a fresh temporary symlink, `renameat` over `current`, then
/// a directory fsync. No path comes from the request.
pub(crate) fn switch(
    registry: &OwnedFd,
    resource: &Id,
    target: &Id,
    target_digest: &Sha256Digest,
    owner: u32,
) -> SwitchOutcome {
    let resource_dir = match open_child_directory(registry, resource.as_str(), owner) {
        Ok(directory) => directory,
        Err(error) => return SwitchOutcome::NotAttempted(error),
    };
    match generation_digest(&resource_dir, target, owner) {
        Ok(digest) if &digest == target_digest => {}
        Ok(_) => return SwitchOutcome::NotAttempted(ExecutorError::PreconditionChanged),
        Err(error) => return SwitchOutcome::NotAttempted(error),
    }
    let mut random = [0; 8];
    if rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty()).is_err() {
        return SwitchOutcome::NotAttempted(ExecutorError::Unavailable);
    }
    let temporary: String = random
        .iter()
        .fold(String::from("current.next-"), |mut name, byte| {
            name.push_str(&format!("{byte:02x}"));
            name
        });
    let link = format!("generations/{}", target.as_str());
    if fs::symlinkat(link.as_str(), &resource_dir, temporary.as_str()).is_err() {
        return SwitchOutcome::NotAttempted(ExecutorError::Unavailable);
    }
    let renamed = fs::renameat(&resource_dir, temporary.as_str(), &resource_dir, "current");
    if renamed.is_err() {
        let _ = fs::unlinkat(&resource_dir, temporary.as_str(), fs::AtFlags::empty());
        return SwitchOutcome::Attempted(Err(ExecutorError::Unavailable));
    }
    SwitchOutcome::Attempted(fs::fsync(&resource_dir).map_err(|_| ExecutorError::Unavailable))
}
