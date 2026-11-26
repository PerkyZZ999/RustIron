use sha2::{Digest, Sha256};

use crate::{MAX_REQUEST_BYTES, ProtocolError, codec::validate_canonical_json};

// Fixed ASCII domain followed by one NUL, then the complete canonical object.
const PLAN_DIGEST_DOMAIN: &[u8] = b"rustiron/plan/v1\0";

/// Bounded RFC 8785 object bytes with an unsigned exact-integer input profile.
///
/// This validates JSON shape, not a plan schema or authorization. Callers must
/// independently validate all typed plan/grant semantics before using a digest
/// for signing or admission. No field is removed or defaulted by this helper.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalObject {
    bytes: Vec<u8>,
}

impl CanonicalObject {
    /// Rejects ambiguous/unbounded JSON before applying RFC 8785 serialization.
    ///
    /// Numeric tokens must be integers in 0..=2^53-1, without negative signs,
    /// fraction or exponent notation. Arbitrary RFC 8785 numbers are not accepted.
    pub fn decode(input: &[u8]) -> Result<Self, ProtocolError> {
        validate_canonical_json(input)?;
        let value: serde_json::Value =
            serde_json::from_slice(input).map_err(|_| ProtocolError::InvalidMessage)?;
        let bytes =
            serde_json_canonicalizer::to_vec(&value).map_err(|_| ProtocolError::InvalidMessage)?;
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(ProtocolError::RequestTooLarge);
        }
        Ok(Self { bytes })
    }

    /// Returns immutable canonical UTF-8 bytes, with no trailing newline.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// SHA-256 of `rustiron/plan/v1`, one zero byte, then the canonical object.
    ///
    /// This is byte plumbing only. The object may have arbitrary keys and is not
    /// established as a valid plan, a grant, human approval or authority to act.
    pub fn plan_domain_digest(&self) -> [u8; 32] {
        self.domain_digest(PLAN_DIGEST_DOMAIN)
    }

    pub(crate) fn domain_digest(&self, domain: &[u8]) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(domain);
        hash.update(&self.bytes);
        hash.finalize().into()
    }
}
