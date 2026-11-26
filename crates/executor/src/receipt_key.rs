//! W392 (D-040 item 6, D-042): the host receipt key signs each exported
//! receipt. A signed receipt is still self-attested: root on the host can
//! sign anything with this key.
//!
//! The installer makes an Ed25519 key with `ssh-keygen` in
//! `<policy dir>/receipt-key` (product: `/etc/rustiron/receipt-key`). The
//! executor never reads the private key. It checks the shape of the file and
//! lets the pinned `ssh-keygen -Y sign` read it, as plan signatures are
//! checked with the pinned `ssh-keygen -Y verify` (`signature.rs`).
//!
//! The signed bytes are the canonical receipt body, the same bytes that
//! `body_sha256` covers. Every body member is signed, so a new receipt field
//! needs no change here. The SSHSIG namespace `rustiron-receipt-v1` separates
//! the domain from plan signatures (`rustiron-plan-v1`).

use std::{
    io::{Read, Write},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use rustiron_contracts::execution::{
    EvidenceReceipt, RECEIPT_ATTESTATION_SIGNED, RECEIPT_ATTESTATION_UNSIGNED,
    RECEIPT_SIGNATURE_NAMESPACE,
};
use rustix::fs::{self, AtFlags, FileType};
use sha2::{Digest, Sha256};

use crate::{
    ExecutorError, TrustAnchor,
    files::{self, Exposure},
    policy, signature, signer,
};

/// The key folder below the policy folder.
pub const KEY_DIR: &str = "receipt-key";
/// The private key. Only `ssh-keygen` opens it.
pub const PRIVATE_KEY: &str = "ed25519";
/// The public key, for `observe` and the fingerprint.
pub const PUBLIC_KEY: &str = "ed25519.pub";
/// The SSHSIG namespace of a receipt signature.
pub const NAMESPACE: &str = RECEIPT_SIGNATURE_NAMESPACE;

const SIGNER: &str = "/usr/bin/ssh-keygen";
const SIGN_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PUBLIC_KEY_BYTES: usize = 1024;
const MAX_SIGNATURE_BYTES: u64 = 4096;

/// The installed public key: `ssh-ed25519 BASE64` and its OpenSSH fingerprint.
struct PublicKey {
    line: String,
    fingerprint: String,
}

/// Signs a sealed receipt with the host receipt key in the enrolled policy
/// folder. Without a key, the receipt states that it is unsigned. Before
/// signing, the enrolled `ssh-keygen` digest is checked, as for plan
/// signatures.
pub fn sign(
    anchor: &TrustAnchor,
    document: serde_json::Value,
) -> Result<serde_json::Value, ExecutorError> {
    let folder = anchor.policy_dir.join(KEY_DIR);
    let Some(key) = open_key(&folder, anchor.owner_uid)? else {
        return Ok(unsigned(document));
    };
    let policy_dir = files::open_trusted_directory(&anchor.policy_dir, anchor.owner_uid)?;
    signature::check_verifier(&policy::load(&policy_dir, anchor.owner_uid)?)?;
    sign_with(&folder, &key, document)
}

/// Signs with the key in `folder`, owned by `owner`, without the verifier
/// digest check. Tests use it with a key in a private folder.
pub fn sign_in(
    folder: &Path,
    owner: u32,
    document: serde_json::Value,
) -> Result<serde_json::Value, ExecutorError> {
    match open_key(folder, owner)? {
        Some(key) => sign_with(folder, &key, document),
        None => Ok(unsigned(document)),
    }
}

/// Public facts of the key for `observe`. Never the private key.
pub fn facts(folder: &Path, owner: u32) -> serde_json::Value {
    match open_key(folder, owner) {
        Ok(Some(key)) => serde_json::json!({
            "state": "present",
            "algorithm": "ssh-ed25519",
            "public_key": key.line,
            "fingerprint": key.fingerprint,
            "namespace": NAMESPACE,
        }),
        Ok(None) => serde_json::json!({"state": "absent"}),
        Err(_) => serde_json::json!({"state": "refused"}),
    }
}

fn unsigned(mut document: serde_json::Value) -> serde_json::Value {
    document["attestation"] = RECEIPT_ATTESTATION_UNSIGNED.into();
    document
}

/// None when the folder or the private key is absent. Any other shape is
/// refused: the folder owner-only, the private key a regular file with one
/// link and no group or other access, the public key not writable by others.
fn open_key(folder: &Path, owner: u32) -> Result<Option<PublicKey>, ExecutorError> {
    let deny = ExecutorError::AccessDenied;
    match std::fs::symlink_metadata(folder) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(deny),
        Ok(_) => {}
    }
    let directory = files::open_trusted_directory(folder, owner)?;
    let private = match fs::statat(&directory, PRIVATE_KEY, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(deny),
        Ok(stat) => stat,
    };
    if FileType::from_raw_mode(private.st_mode) != FileType::RegularFile
        || private.st_uid != owner
        || private.st_nlink != 1
        || private.st_mode & 0o077 != 0
    {
        return Err(deny);
    }
    let bytes = files::read_child(
        &directory,
        PUBLIC_KEY,
        owner,
        Exposure::Readable,
        MAX_PUBLIC_KEY_BYTES,
    )?;
    public_key(&bytes).map(Some).ok_or(deny)
}

/// `ssh-ed25519 BASE64 [comment]` with an Ed25519 key blob.
fn public_key(bytes: &[u8]) -> Option<PublicKey> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut words = text.split_whitespace();
    let (algorithm, key) = (words.next()?, words.next()?);
    let blob = signer::ed25519_blob(key).filter(|_| algorithm == "ssh-ed25519")?;
    Some(PublicKey {
        line: format!("{algorithm} {key}"),
        fingerprint: signer::fingerprint(&blob),
    })
}

fn sign_with(
    folder: &Path,
    key: &PublicKey,
    mut document: serde_json::Value,
) -> Result<serde_json::Value, ExecutorError> {
    let unavailable = ExecutorError::Unavailable;
    let text = document.get("body").ok_or(unavailable)?.to_string();
    let canonical =
        rustiron_contracts::CanonicalObject::decode(text.as_bytes()).map_err(|_| unavailable)?;
    let digest: String = Sha256::digest(canonical.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if document["body_sha256"] != digest.as_str() {
        return Err(unavailable);
    }
    let armored = run_signer(&folder.join(PRIVATE_KEY), canonical.as_bytes())?;
    document["attestation"] = RECEIPT_ATTESTATION_SIGNED.into();
    document["signature"] = serde_json::json!({
        "format": "sshsig",
        "namespace": NAMESPACE,
        "key_fingerprint": key.fingerprint,
        "armored": armored,
    });
    // The signed document must be a valid evidence receipt.
    serde_json::from_value::<EvidenceReceipt>(document.clone()).map_err(|_| unavailable)?;
    Ok(document)
}

/// `ssh-keygen -Y sign -f KEY -n rustiron-receipt-v1` with the bytes on
/// stdin and the armored signature on stdout. The key path is not secret;
/// the key itself is never in argv, a log, or this process.
fn run_signer(private: &Path, bytes: &[u8]) -> Result<String, ExecutorError> {
    let unavailable = ExecutorError::Unavailable;
    let mut child = Command::new(SIGNER)
        .args(["-Y", "sign", "-f"])
        .arg(private)
        .args(["-n", NAMESPACE])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| unavailable)?;
    let written = child
        .stdin
        .take()
        .ok_or(unavailable)
        .and_then(|mut stdin| stdin.write_all(bytes).map_err(|_| unavailable));
    let finished = wait(&mut child, Instant::now() + SIGN_TIMEOUT);
    written.and(finished)?;
    let mut armored = String::new();
    child
        .stdout
        .take()
        .ok_or(unavailable)?
        .take(MAX_SIGNATURE_BYTES + 1)
        .read_to_string(&mut armored)
        .map_err(|_| unavailable)?;
    if armored.len() as u64 > MAX_SIGNATURE_BYTES {
        return Err(unavailable);
    }
    Ok(armored)
}

fn wait(child: &mut Child, deadline: Instant) -> Result<(), ExecutorError> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(_)) => return Err(ExecutorError::Unavailable),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ExecutorError::Unavailable);
            }
        }
    }
}
