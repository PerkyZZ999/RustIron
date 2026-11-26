//! Bounded reads of local regular files, without following the final symlink.

use rustiron_contracts::ErrorCode;
use std::{fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt, path::Path};

pub(crate) fn read(path: &Path, limit: usize) -> Result<Vec<u8>, ErrorCode> {
    let flags = (rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOFOLLOW)
        .bits()
        .try_into()
        .map_err(|_| ErrorCode::InvalidRequest)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .map_err(|_| ErrorCode::InvalidRequest)?;
    if !file
        .metadata()
        .map_err(|_| ErrorCode::InvalidRequest)?
        .is_file()
    {
        return Err(ErrorCode::InvalidRequest);
    }
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ErrorCode::InvalidRequest)?;
    if bytes.len() > limit {
        return Err(ErrorCode::RequestTooLarge);
    }
    Ok(bytes)
}
