//! Synthetic test-driver utilities; not part of an executor runtime API.

use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

use sha2::{Digest, Sha256};

pub(crate) const KEYGEN: &str = "/usr/bin/ssh-keygen";

pub(crate) fn hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn run(command: &mut Command) {
    let output = command.env_clear().output().unwrap();
    assert!(output.status.success(), "{output:?}");
}

pub(crate) fn private_dir(path: &Path) {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

pub(crate) fn private_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

pub(crate) fn new_key(path: &Path) {
    run(Command::new(KEYGEN)
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "SYNTHETIC_ONLY",
            "-f",
        ])
        .arg(path));
}

pub(crate) fn sign(key: &Path, message: &Path, bytes: &[u8], namespace: &str) -> Vec<u8> {
    private_file(message, bytes);
    let mut name = message.as_os_str().to_owned();
    name.push(".sig");
    let signature = PathBuf::from(name);
    match fs::remove_file(&signature) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("cannot remove previous synthetic signature: {error}"),
    }
    run(Command::new(KEYGEN)
        .args(["-q", "-Y", "sign", "-n", namespace, "-f"])
        .arg(key)
        .arg(message));
    fs::read(signature).unwrap()
}
