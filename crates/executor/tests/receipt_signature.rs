//! W392 (D-040 item 6): the host receipt key signs the canonical receipt
//! body. The vectors were written by a Python script that runs neither this
//! code nor OpenSSH (`docs/validation/S10-W392/make_receipt_vectors.py`).
//! Ed25519 is deterministic, so the signature that the executor gets from
//! `ssh-keygen -Y sign` must equal the vector byte for byte.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use rustiron_executor::{ExecutorError, receipt_key};

const VECTORS: &str = include_str!("../../contracts/tests/fixtures/receipt-signature-vectors.json");

fn vectors() -> serde_json::Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn owner() -> u32 {
    rustix::process::geteuid().as_raw()
}

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scratch(name: &str) -> Scratch {
    let root = std::env::temp_dir().join(format!("ri-w392-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    Scratch(root)
}

/// A key folder in the installed shape: folder 0700, private key 0400,
/// public key 0444, all owned by the test user.
fn key_folder(root: &Path) -> PathBuf {
    let set = vectors();
    let key = &set["test_key"];
    let folder = root.join(receipt_key::KEY_DIR);
    fs::create_dir(&folder).unwrap();
    fs::set_permissions(&folder, fs::Permissions::from_mode(0o700)).unwrap();
    let body = key["openssh_private_body_b64"].as_str().unwrap();
    let mut pem = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for line in body.as_bytes().chunks(70) {
        pem.push_str(std::str::from_utf8(line).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    let private = folder.join(receipt_key::PRIVATE_KEY);
    fs::write(&private, pem).unwrap();
    fs::set_permissions(&private, fs::Permissions::from_mode(0o400)).unwrap();
    let public = folder.join(receipt_key::PUBLIC_KEY);
    let line = format!(
        "{} rustiron-receipt-test\n",
        key["public_key"].as_str().unwrap()
    );
    fs::write(&public, line).unwrap();
    fs::set_permissions(&public, fs::Permissions::from_mode(0o444)).unwrap();
    folder
}

fn document(vector: &serde_json::Value) -> serde_json::Value {
    let body: serde_json::Value =
        serde_json::from_str(vector["body_input"].as_str().unwrap()).unwrap();
    serde_json::json!({"body": body, "body_sha256": vector["body_sha256"]})
}

#[test]
fn the_receipt_key_signs_the_canonical_body_like_the_independent_vectors() {
    let root = scratch("vectors");
    let folder = key_folder(&root.0);
    let set = vectors();
    assert_eq!(set["namespace"], receipt_key::NAMESPACE);
    for vector in set["vectors"].as_array().unwrap() {
        let unsigned = document(vector);
        let signed = receipt_key::sign_in(&folder, owner(), unsigned.clone()).unwrap();
        assert_eq!(signed["body"], unsigned["body"], "{}", vector["name"]);
        assert_eq!(signed["body_sha256"], unsigned["body_sha256"]);
        assert_eq!(signed["attestation"], "self-attested, signed");
        let signature = &signed["signature"];
        assert_eq!(signature["format"], "sshsig");
        assert_eq!(signature["namespace"], "rustiron-receipt-v1");
        assert_eq!(signature["key_fingerprint"], set["test_key"]["fingerprint"]);
        assert_eq!(
            signature["armored"], vector["armored"],
            "{}",
            vector["name"]
        );
        // The signed document is a valid evidence receipt.
        serde_json::from_value::<rustiron_contracts::execution::EvidenceReceipt>(signed.clone())
            .unwrap();
        assert!(!signed.to_string().contains("PRIVATE KEY"));
    }
}

#[test]
fn a_host_without_a_receipt_key_states_an_unsigned_receipt() {
    let root = scratch("absent");
    let vector = &vectors()["vectors"][0];
    let unsigned = document(vector);
    let missing = root.0.join(receipt_key::KEY_DIR);
    let result = receipt_key::sign_in(&missing, owner(), unsigned.clone()).unwrap();
    assert_eq!(result["attestation"], "self-attested, unsigned");
    assert!(result.get("signature").is_none());
    assert_eq!(result["body"], unsigned["body"]);
    assert_eq!(
        receipt_key::facts(&missing, owner()),
        serde_json::json!({"state": "absent"})
    );
    // A folder without the private key is the same absent state.
    fs::create_dir(&missing).unwrap();
    fs::set_permissions(&missing, fs::Permissions::from_mode(0o700)).unwrap();
    let result = receipt_key::sign_in(&missing, owner(), unsigned).unwrap();
    assert_eq!(result["attestation"], "self-attested, unsigned");
}

/// A change to the installed key folder.
type Change = fn(&Path);

#[test]
fn a_receipt_key_in_another_shape_is_refused_and_never_signs() {
    let vector = &vectors()["vectors"][0];
    let cases: [(&str, Change); 4] = [
        ("group-readable", |folder| {
            let key = folder.join(receipt_key::PRIVATE_KEY);
            fs::set_permissions(key, fs::Permissions::from_mode(0o440)).unwrap();
        }),
        ("open-folder", |folder| {
            fs::set_permissions(folder, fs::Permissions::from_mode(0o755)).unwrap();
        }),
        ("linked", |folder| {
            let key = folder.join(receipt_key::PRIVATE_KEY);
            fs::rename(&key, folder.join("elsewhere")).unwrap();
            std::os::unix::fs::symlink("elsewhere", key).unwrap();
        }),
        ("writable-public", |folder| {
            let key = folder.join(receipt_key::PUBLIC_KEY);
            fs::set_permissions(key, fs::Permissions::from_mode(0o666)).unwrap();
        }),
    ];
    for (name, change) in cases {
        let root = scratch(name);
        let folder = key_folder(&root.0);
        change(&folder);
        assert_eq!(
            receipt_key::sign_in(&folder, owner(), document(vector)).unwrap_err(),
            ExecutorError::AccessDenied,
            "{name}"
        );
    }
}

#[test]
fn a_body_that_does_not_match_its_digest_is_not_signed() {
    let root = scratch("digest");
    let folder = key_folder(&root.0);
    let mut changed = document(&vectors()["vectors"][0]);
    changed["body"]["site_id"] = "other".into();
    assert_eq!(
        receipt_key::sign_in(&folder, owner(), changed).unwrap_err(),
        ExecutorError::Unavailable
    );
}

#[test]
fn observe_facts_carry_the_public_key_and_fingerprint_only() {
    let root = scratch("facts");
    let folder = key_folder(&root.0);
    let set = vectors();
    let facts = receipt_key::facts(&folder, owner());
    assert_eq!(
        facts,
        serde_json::json!({
            "state": "present",
            "algorithm": "ssh-ed25519",
            "public_key": set["test_key"]["public_key"],
            "fingerprint": set["test_key"]["fingerprint"],
            "namespace": "rustiron-receipt-v1",
        })
    );
    assert!(!facts.to_string().contains("PRIVATE"));
}
