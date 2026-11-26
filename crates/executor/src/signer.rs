//! W233 (B14): non-secret signer facts for `executor observe`: the enrolled
//! principal, namespace, key type and OpenSSH SHA256 fingerprint, plus a
//! digest of the revocation list. Never the key material itself.
use sha2::{Digest, Sha256};

/// Facts from an `allowed_signers` line already accepted by `policy::load`,
/// or null when the bytes do not have that exact shape.
pub(crate) fn facts(allowed: &[u8], revocations: &[u8]) -> serde_json::Value {
    let parsed = (|| {
        let text = std::str::from_utf8(allowed).ok()?;
        let parts: Vec<_> = text.split_whitespace().collect();
        let [principal, namespace, algorithm, key] = parts[..] else {
            return None;
        };
        let namespace = namespace.strip_prefix("namespaces=\"")?.strip_suffix('"')?;
        let blob = ed25519_blob(key).filter(|_| algorithm == "ssh-ed25519")?;
        Some((principal, namespace, algorithm, fingerprint(&blob)))
    })();
    let Some((principal, namespace, algorithm, fingerprint)) = parsed else {
        return serde_json::Value::Null;
    };
    let revoked: String = Sha256::digest(revocations)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    serde_json::json!({
        "principal": principal,
        "namespace": namespace,
        "algorithm": algorithm,
        "fingerprint": fingerprint,
        "revocations_bytes": revocations.len(),
        "revocations_sha256": revoked,
    })
}

/// The OpenSSH Ed25519 key blob of a base64 key: string "ssh-ed25519",
/// string of 32 bytes. W392 also reads the receipt public key with it.
pub(crate) fn ed25519_blob(key: &str) -> Option<Vec<u8>> {
    let blob = base64(key)?;
    let mut expected = Vec::with_capacity(51);
    expected.extend_from_slice(&11u32.to_be_bytes());
    expected.extend_from_slice(b"ssh-ed25519");
    expected.extend_from_slice(&32u32.to_be_bytes());
    (blob.len() == 51 && blob[..19] == expected[..]).then_some(blob)
}

/// The OpenSSH `SHA256:` fingerprint of a key blob.
pub(crate) fn fingerprint(blob: &[u8]) -> String {
    format!("SHA256:{}", base64_encode_unpadded(&Sha256::digest(blob)))
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Strict padded standard base64 (length a multiple of 4).
fn base64(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) || bytes.len() > 128 {
        return None;
    }
    let pad = bytes.iter().rev().take_while(|&&b| b == b'=').count();
    if pad > 2 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for &b in chunk {
            let v = if b == b'=' {
                0
            } else {
                ALPHABET.iter().position(|&a| a == b)? as u32
            };
            n = n << 6 | v;
        }
        out.extend_from_slice(&n.to_be_bytes()[1..]);
    }
    if bytes[..bytes.len() - pad].contains(&b'=') {
        return None;
    }
    out.truncate(out.len() - pad);
    Some(out)
}

fn base64_encode_unpadded(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut n = 0u32;
        for (i, &b) in chunk.iter().enumerate() {
            n |= u32::from(b) << (16 - 8 * i);
        }
        for i in 0..=chunk.len() {
            out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::facts;

    // Throwaway public key generated for this test (private half discarded);
    // `ssh-keygen -lf` gave SHA256:1qxNSGzuxAUJztinl6g7k5tlkJccQie3h6fdhLFn05U.
    const KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIIozfpYUrZ5sVRFNdsx/DeTBXUkPGulbQimYiehslcAJ";

    fn line(key: &str) -> Vec<u8> {
        format!("lab_agent namespaces=\"rustiron-plan-v1\" ssh-ed25519 {key}\n").into_bytes()
    }

    #[test]
    fn facts_match_openssh_and_never_carry_the_key() {
        let f = facts(&line(KEY), b"");
        assert_eq!(f["principal"], "lab_agent");
        assert_eq!(f["namespace"], "rustiron-plan-v1");
        assert_eq!(f["algorithm"], "ssh-ed25519");
        assert_eq!(
            f["fingerprint"],
            "SHA256:1qxNSGzuxAUJztinl6g7k5tlkJccQie3h6fdhLFn05U"
        );
        assert_eq!(f["revocations_bytes"], 0);
        assert_eq!(
            f["revocations_sha256"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(!f.to_string().contains(KEY));
    }

    #[test]
    fn malformed_or_mismatched_keys_give_null() {
        for bad in [
            line("AAAA!!!!"),
            line("AAAAB3NzaC1yc2EAAAADAQABAAAAgQ"), // valid base64, not an ed25519 blob
            line(&KEY[..KEY.len() - 4]),
            b"lab_agent ssh-ed25519\n".to_vec(),
            b"\xff".to_vec(),
        ] {
            assert!(facts(&bad, b"").is_null(), "{bad:?}");
        }
    }
}
