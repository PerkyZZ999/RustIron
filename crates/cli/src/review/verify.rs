use std::{
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use super::{Failure, Policy, files, hash};

pub(super) const VERIFIER: &str = "/usr/bin/ssh-keygen";
pub(super) const NAMESPACE: &str = "rustiron-plan-v1";
const MAX_VERIFIER_BYTES: usize = 16 * 1024 * 1024;
const MAX_SIGNATURE_BYTES: usize = 16 * 1024;
const MAX_KEY_POLICY_BYTES: usize = 64 * 1024;
const VERIFY_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) struct SignatureFiles {
    pub signature: PathBuf,
    pub allowed_signers: PathBuf,
    pub revocations: PathBuf,
}

pub(super) struct SignatureEvidence {
    pub allowed_sha256: String,
    pub revocations_sha256: String,
}

pub(super) fn verify(
    grant: &[u8],
    policy: &Policy,
    paths: &SignatureFiles,
) -> Result<SignatureEvidence, Failure> {
    let binary = Path::new(VERIFIER);
    let metadata = std::fs::symlink_metadata(binary).map_err(|_| Failure::dependency())?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || hash(&files::read(binary, MAX_VERIFIER_BYTES)?) != policy.verifier_sha256.as_str()
    {
        return Err(Failure::dependency());
    }
    let signature = files::read(&paths.signature, MAX_SIGNATURE_BYTES)?;
    let allowed = files::read(&paths.allowed_signers, MAX_KEY_POLICY_BYTES)?;
    let revoked = files::read(&paths.revocations, MAX_KEY_POLICY_BYTES)?;
    check_allowed(&allowed, policy)?;
    let mut scratch = files::Scratch::new()?;
    let result = (|| {
        let input = scratch.write("grant", grant)?;
        let sig = scratch.write("signature", &signature)?;
        let keys = scratch.write("allowed", &allowed)?;
        let revocations = scratch.write("revoked", &revoked)?;
        let mut child = Command::new(VERIFIER)
            .args([
                "-Y",
                "verify",
                "-q",
                "-I",
                policy.issuer.as_str(),
                "-n",
                NAMESPACE,
                "-f",
            ])
            .arg(keys)
            .arg("-s")
            .arg(sig)
            .arg("-r")
            .arg(revocations)
            .env_clear()
            .stdin(files::input_file(&input)?)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| Failure::dependency())?;
        wait(&mut child, Instant::now() + VERIFY_TIMEOUT)
    })();
    let cleanup = scratch.close();
    cleanup?;
    result?;
    Ok(SignatureEvidence {
        allowed_sha256: hash(&allowed),
        revocations_sha256: hash(&revoked),
    })
}

fn wait(child: &mut std::process::Child, deadline: Instant) -> Result<(), Failure> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() {
                    Ok(())
                } else {
                    Err(Failure::signature())
                };
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            _ => {
                let killed = child.kill();
                let reaped = child.wait();
                killed.map_err(|_| Failure::dependency())?;
                reaped.map_err(|_| Failure::dependency())?;
                return Err(Failure::dependency());
            }
        }
    }
}

fn check_allowed(bytes: &[u8], policy: &Policy) -> Result<(), Failure> {
    let text = std::str::from_utf8(bytes).map_err(|_| Failure::input())?;
    let parts: Vec<_> = text.split_whitespace().collect();
    if parts.len() != 4
        || parts[0] != policy.issuer.as_str()
        || parts[1] != r#"namespaces="rustiron-plan-v1""#
        || parts[2] != "ssh-ed25519"
        || parts[3].len() > 128
        || !parts[3]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+/=".contains(&byte))
    {
        return Err(Failure::input());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadline_failure_kills_and_reaps_our_child() {
        let mut child = Command::new("/usr/bin/sleep").arg("30").spawn().unwrap();
        let error = wait(&mut child, Instant::now()).err().unwrap();
        assert_eq!(error.exit, 7);
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(child.try_wait().unwrap().unwrap().signal(), Some(9));
    }
}
