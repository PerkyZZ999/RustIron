//! SSHSIG verification of exact canonical grant bytes against enrolled policy.
//!
//! The executor verifies independently of the offline reviewer; a review
//! receipt is never accepted as evidence that a signature was checked.

use std::{
    fs::File,
    io::Write,
    os::fd::OwnedFd,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use rustix::fs::{self, AtFlags, Mode, OFlags};
use sha2::{Digest, Sha256};

use crate::{ExecutorError, policy::LoadedPolicy};

const VERIFIER: &str = "/usr/bin/ssh-keygen";
const NAMESPACE: &str = "rustiron-plan-v1";
const MAX_VERIFIER_BYTES: usize = 16 * 1024 * 1024;
const VERIFY_TIMEOUT: Duration = Duration::from_secs(5);
const NAMES: [&str; 4] = ["grant", "signature", "allowed", "revoked"];

pub(crate) fn verify(
    grant: &[u8],
    signature: &[u8],
    loaded: &LoadedPolicy,
    scratch_path: &Path,
    scratch: &OwnedFd,
) -> Result<(), ExecutorError> {
    check_verifier(loaded)?;
    let mut random = [0; 16];
    rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty())
        .map_err(|_| ExecutorError::Unavailable)?;
    let name: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    fs::mkdirat(scratch, name.as_str(), Mode::RWXU).map_err(|_| ExecutorError::Unavailable)?;
    let result = (|| {
        let directory = fs::openat(
            scratch,
            name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ExecutorError::Unavailable)?;
        let contents = [
            grant,
            signature,
            &loaded.allowed_signers,
            &loaded.revocations,
        ];
        for (file, bytes) in NAMES.iter().zip(contents) {
            write_new(&directory, file, bytes)?;
        }
        let base = scratch_path.join(&name);
        let input = File::open(base.join("grant")).map_err(|_| ExecutorError::Unavailable)?;
        let mut child = Command::new(VERIFIER)
            .args(["-Y", "verify", "-q", "-I"])
            .arg(loaded.policy.issuer.as_str())
            .args(["-n", NAMESPACE, "-f"])
            .arg(base.join("allowed"))
            .arg("-s")
            .arg(base.join("signature"))
            .arg("-r")
            .arg(base.join("revoked"))
            .env_clear()
            .stdin(input)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ExecutorError::Unavailable)?;
        wait(&mut child, Instant::now() + VERIFY_TIMEOUT)
    })();
    let cleanup = remove(scratch, &name);
    result.and(cleanup)
}

pub(crate) fn check_verifier(loaded: &LoadedPolicy) -> Result<(), ExecutorError> {
    let unavailable = ExecutorError::Unavailable;
    let fd = fs::open(
        VERIFIER,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| unavailable)?;
    let stat = fs::fstat(&fd).map_err(|_| unavailable)?;
    if fs::FileType::from_raw_mode(stat.st_mode) != fs::FileType::RegularFile
        || stat.st_uid != 0
        || stat.st_mode & 0o022 != 0
    {
        return Err(unavailable);
    }
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(
        &mut std::io::Read::take(File::from(fd), MAX_VERIFIER_BYTES as u64 + 1),
        &mut bytes,
    )
    .map_err(|_| unavailable)?;
    let digest =
        rustiron_contracts::approval::Sha256Digest::from_bytes(Sha256::digest(&bytes).into());
    if bytes.len() > MAX_VERIFIER_BYTES || digest != loaded.policy.verifier_sha256 {
        return Err(unavailable);
    }
    Ok(())
}

fn write_new(directory: &OwnedFd, name: &str, bytes: &[u8]) -> Result<(), ExecutorError> {
    let fd = fs::openat(
        directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| ExecutorError::Unavailable)?;
    File::from(fd)
        .write_all(bytes)
        .map_err(|_| ExecutorError::Unavailable)
}

fn remove(scratch: &OwnedFd, name: &str) -> Result<(), ExecutorError> {
    let base = PathBuf::from(name);
    for file in NAMES {
        match fs::unlinkat(scratch, base.join(file), AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => {}
            Err(_) => return Err(ExecutorError::Unavailable),
        }
    }
    fs::unlinkat(scratch, name, AtFlags::REMOVEDIR).map_err(|_| ExecutorError::Unavailable)
}

fn wait(child: &mut Child, deadline: Instant) -> Result<(), ExecutorError> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(_)) => return Err(ExecutorError::SignatureDenied),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            _ => {
                let killed = child.kill();
                let reaped = child.wait();
                killed.map_err(|_| ExecutorError::Unavailable)?;
                reaped.map_err(|_| ExecutorError::Unavailable)?;
                return Err(ExecutorError::Unavailable);
            }
        }
    }
}
