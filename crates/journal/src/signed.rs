//! W396 (journal v20, D-045): the exact canonical plan and grant bytes of
//! each admission, with the signer facts the executor verified.
//!
//! The executor stages one [`SignedAdmission`] before it records an intent.
//! The record call writes it in the same transaction as the new intent, and
//! only when the intent is new. The journal checks that the plan bytes hash
//! to the intent's plan digest (with the `rustiron/plan/v1` framing) and that
//! the grant bytes hash to its grant digest; otherwise the record is refused.
//!
//! Objects are stored once by SHA-256, so the runs of one standing capture
//! grant share their plan and grant. An object over [`MAX_OBJECT_BYTES`] is
//! not kept; its link row still names its digest and length. The detached
//! signature, keys and secrets are never stored here.

use rusqlite::{Transaction, params};
use rustiron_contracts::{CanonicalObject, Id, approval::Sha256Digest};
use sha2::{Digest, Sha256};

use crate::{FixtureJournal, JournalError, storage};

/// The largest canonical object the journal keeps, in bytes.
pub const MAX_OBJECT_BYTES: usize = 8192;
/// The only verification result a row can state: the executor records a
/// row only after `ssh-keygen -Y verify` accepted the grant signature.
pub const VERIFICATION: &str = "sshsig_verified";
/// The SSHSIG namespace of plan and grant signatures.
pub const NAMESPACE: &str = "rustiron-plan-v1";

/// The verified signed inputs of one admission, built by the executor after
/// the signature check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedAdmission {
    /// The complete canonical plan bytes.
    pub plan: Vec<u8>,
    /// The complete canonical grant bytes that the signature covers.
    pub grant: Vec<u8>,
    /// The enrolled issuer principal the signature verified against.
    pub issuer: Id,
    /// The enrolled signer-policy epoch the grant is bound to.
    pub signer_policy_epoch: Id,
}

/// The digests a staged admission must match: the intent's plan and grant
/// digests.
pub(crate) struct Expected<'a> {
    pub plan_digest: &'a Sha256Digest,
    pub grant_digest: &'a Sha256Digest,
}

/// A staged admission that passed its digest checks.
pub(crate) struct Checked {
    signed: SignedAdmission,
    plan_sha256: String,
    grant_sha256: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// SHA-256 of `bytes`, lowercase hex.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// The bytes are one canonical object, unchanged by canonicalization.
fn canonical(bytes: &[u8]) -> Option<CanonicalObject> {
    CanonicalObject::decode(bytes)
        .ok()
        .filter(|object| object.as_bytes() == bytes)
}

/// Whether `plan` hashes to `digest` with the plan domain framing.
pub(crate) fn plan_matches(plan: &[u8], digest: &str) -> bool {
    canonical(plan).is_some_and(|object| hex(&object.plan_domain_digest()) == digest)
}

impl SignedAdmission {
    fn check(self, expected: &Expected<'_>) -> Result<Checked, JournalError> {
        let grant_sha256 = sha256_hex(&self.grant);
        if !plan_matches(&self.plan, expected.plan_digest.as_str())
            || canonical(&self.grant).is_none()
            || grant_sha256 != expected.grant_digest.as_str()
        {
            return Err(JournalError::Conflict);
        }
        Ok(Checked {
            plan_sha256: sha256_hex(&self.plan),
            grant_sha256,
            signed: self,
        })
    }
}

impl FixtureJournal {
    /// Stages the signed inputs of the next admission. The next record call
    /// takes them, whatever its result; a call that records a new intent
    /// stores them in the same transaction.
    pub fn stage_signed(&mut self, signed: SignedAdmission) {
        self.staged = Some(signed);
    }

    /// Drops a staged admission that no record call took.
    pub fn clear_signed(&mut self) {
        self.staged = None;
    }

    /// Takes the staged admission and checks it against the intent digests
    /// before the record transaction begins.
    pub(crate) fn take_signed(
        &mut self,
        expected: &Expected<'_>,
    ) -> Result<Option<Checked>, JournalError> {
        self.staged
            .take()
            .map(|signed| signed.check(expected))
            .transpose()
    }
}

/// Inserts the link row and each object within the bound that is not
/// already stored. Called only for a new intent.
pub(crate) fn insert(
    transaction: &Transaction<'_>,
    operation_id: &Id,
    checked: Option<&Checked>,
) -> Result<(), JournalError> {
    let Some(checked) = checked else {
        return Ok(());
    };
    let signed = &checked.signed;
    for (sha256, bytes) in [
        (&checked.plan_sha256, &signed.plan),
        (&checked.grant_sha256, &signed.grant),
    ] {
        if bytes.len() > MAX_OBJECT_BYTES {
            continue;
        }
        let text = std::str::from_utf8(bytes).map_err(storage::unavailable)?;
        transaction
            .execute(
                "INSERT OR IGNORE INTO signed_objects(sha256,canonical) VALUES(?1,?2)",
                params![sha256, text],
            )
            .map_err(storage::unavailable)?;
    }
    transaction
        .execute(
            "INSERT INTO admission_signatures VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                operation_id.as_str(),
                checked.plan_sha256,
                signed.plan.len() as i64,
                checked.grant_sha256,
                signed.grant.len() as i64,
                signed.issuer.as_str(),
                signed.signer_policy_epoch.as_str(),
                VERIFICATION,
            ],
        )
        .map_err(storage::unavailable)?;
    Ok(())
}

/// Every admission with its recorded digests, as one row source.
pub(crate) const INTENTS: &str = "SELECT operation_id, plan_digest, grant_digest, 'operation' AS source FROM operations \
     UNION ALL SELECT operation_id, plan_digest, grant_digest, 'provision' FROM provisions WHERE state<>'adopted' \
     UNION ALL SELECT operation_id, plan_digest, grant_digest, 'capture' FROM captures \
     UNION ALL SELECT operation_id, plan_digest, grant_digest, 'probe' FROM restore_probes \
     UNION ALL SELECT operation_id, plan_digest, grant_digest, 'readoption' FROM readoptions \
     UNION ALL SELECT operation_id, plan_digest, grant_digest, 'scrub' FROM import_scrubs WHERE origin='signed' \
     UNION ALL SELECT operation_id, plan_digest, grant_digest, 'certificate' FROM certificates \
     UNION ALL SELECT operation_id, plan_digest, grant_digest, 'retirement' FROM retirements \
     UNION ALL SELECT operation_id, plan_digest, grant_digest, 'update' FROM updates \
     UNION ALL SELECT operation_id, plan_digest, grant_digest, 'deletion' FROM deletions \
     UNION ALL SELECT operation_id, plan_digest, grant_digest, 'quota_change' FROM quota_changes \
     UNION ALL SELECT operation_id, plan_digest, grant_digest, 'clone_scrub' FROM clone_scrub_grants \
     UNION ALL SELECT operation_id, plan_digest, grant_digest, 'site_restore' FROM site_restores \
     UNION ALL SELECT operation_id, plan_digest, grant_digest, 'dns_import' FROM dns_imports \
     UNION ALL SELECT operation_id, plan_digest, grant_digest, 'dns_change' FROM dns_changes \
     UNION ALL SELECT operation_id, plan_digest, grant_digest, 'app_release' FROM app_releases \
     UNION ALL SELECT operation_id, plan_digest, grant_digest, 'app_lifecycle' FROM app_lifecycles \
     UNION ALL SELECT operation_id, plan_digest, grant_digest, 'credential_rotation' FROM credential_rotations";

/// On open: each link row names one recorded intent with the same grant
/// digest; each object hashes to its key, is a canonical object and is
/// named by a link row; each kept plan hashes to its intent's plan digest.
pub(crate) fn validate(c: &rusqlite::Connection) -> Result<(), JournalError> {
    let u = storage::unavailable;
    let broken: bool = c
        .query_row(
            &format!(
                "SELECT EXISTS(SELECT 1 FROM admission_signatures a WHERE (SELECT count(*) FROM ({INTENTS}) i \
                 WHERE i.operation_id=a.operation_id AND i.grant_digest=a.grant_sha256)<>1) \
                 OR EXISTS(SELECT 1 FROM signed_objects o WHERE NOT EXISTS(SELECT 1 FROM admission_signatures a \
                 WHERE a.plan_sha256=o.sha256 OR a.grant_sha256=o.sha256)) \
                 OR EXISTS(SELECT 1 FROM admission_signatures a JOIN signed_objects o ON o.sha256=a.plan_sha256 \
                 WHERE length(CAST(o.canonical AS BLOB))<>a.plan_bytes) \
                 OR EXISTS(SELECT 1 FROM admission_signatures a JOIN signed_objects o ON o.sha256=a.grant_sha256 \
                 WHERE length(CAST(o.canonical AS BLOB))<>a.grant_bytes)"
            ),
            [],
            |row| row.get(0),
        )
        .map_err(u)?;
    if broken {
        return Err(JournalError::Unavailable);
    }
    let mut objects = c
        .prepare("SELECT sha256, canonical FROM signed_objects")
        .map_err(u)?;
    let rows = objects
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(u)?;
    for row in rows {
        let (sha256, text) = row.map_err(u)?;
        if sha256_hex(text.as_bytes()) != sha256 || canonical(text.as_bytes()).is_none() {
            return Err(JournalError::Unavailable);
        }
    }
    let mut plans = c
        .prepare(&format!(
            "SELECT o.canonical, i.plan_digest FROM admission_signatures a \
             JOIN ({INTENTS}) i ON i.operation_id=a.operation_id \
             JOIN signed_objects o ON o.sha256=a.plan_sha256"
        ))
        .map_err(u)?;
    let rows = plans
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(u)?;
    for row in rows {
        let (plan, digest) = row.map_err(u)?;
        if !plan_matches(plan.as_bytes(), &digest) {
            return Err(JournalError::Unavailable);
        }
    }
    Ok(())
}
