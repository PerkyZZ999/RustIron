//! Re-adoption records (schema v16, W372, D-030).
//!
//! A re-adoption is admitted like any intent: one transaction consumes the
//! grant, nonce, operation and retry key and records the row `verifying`.
//! The executor then observes the host (read-only) and records the outcome:
//! `adopted`, with an `adopted` provision row for the site form or the one
//! generation adoption for the generation form, or `refused`. A `verifying`
//! row blocks every other admission. This library verifies none of the
//! facts it stores; the executor decides them.

use rusqlite::{Connection, OptionalExtension, Row, params};
use rustiron_contracts::{
    Id, Timestamp,
    approval::{Hostname, ReadoptForm, ReadoptPlan, Sha256Digest, SiteId},
};

use crate::{FixtureJournal, JournalError, storage};

const MAX_READOPTIONS: i64 = 100;
const MAX_FACTS: usize = 4096;
const MAX_PLAN: usize = 65536;

/// Recorded re-adoption state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadoptState {
    /// Admitted; the read-only observation has not been recorded yet.
    Verifying,
    /// Every verified fact matched; ownership is recorded.
    Adopted,
    /// A verified fact did not match; nothing was recorded but this row.
    Refused,
}

impl ReadoptState {
    fn text(self) -> &'static str {
        match self {
            Self::Verifying => "verifying",
            Self::Adopted => "adopted",
            Self::Refused => "refused",
        }
    }
}

/// Immutable admitted re-adoption, built by the executor from verified inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadoptionIntent {
    /// Operation identity.
    pub operation_id: Id,
    /// Retry key bound to every field.
    pub idempotency_key: Id,
    /// Signed grant identity.
    pub grant_id: Id,
    /// Single-use signed nonce.
    pub nonce: Id,
    /// Complete plan digest; `plan` must hash to it.
    pub plan_digest: Sha256Digest,
    /// Complete canonical grant digest.
    pub grant_digest: Sha256Digest,
    /// Enrolled host identity.
    pub host_id: Id,
    /// Enrolled host epoch.
    pub host_epoch: Id,
    /// The plan's form.
    pub form: ReadoptForm,
    /// Site form: the site and its hostname; `None` for the generation form.
    pub site: Option<(SiteId, Hostname)>,
    /// The archived journal's epoch; evidence only.
    pub previous_epoch: Id,
    /// SHA-256 of the pre-rotation output; evidence only.
    pub evidence_sha256: Sha256Digest,
    /// Normal grant deadline for the admission.
    pub expires_at: Timestamp,
    /// The complete canonical plan, kept so a reconcile compares a new
    /// observation with exactly the signed plan.
    pub plan: String,
}

/// A stored re-adoption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Readoption {
    /// Immutable admitted data.
    pub intent: ReadoptionIntent,
    /// Current state.
    pub state: ReadoptState,
    /// Canonical JSON of the observed facts, once recorded (no secret).
    pub facts: Option<String>,
    /// For `refused`: the stable code and the first failed rule.
    pub refusal: Option<(String, String)>,
}

/// New durable re-adoption, or status of an exact earlier one.
#[derive(Debug, Eq, PartialEq)]
pub enum ReadoptResult {
    /// Intent committed; nonce consumed.
    New(Readoption),
    /// Status only; never permission to observe or record again.
    Existing(Readoption),
}

/// The allocations an adopted site holds, as the executor observed them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SiteAdoption {
    /// Site UID (equal to its GID).
    pub uid: u32,
    /// SELinux category of the site level.
    pub category: u32,
    /// Hard block limit in KiB.
    pub quota_kib: u64,
    /// Hard inode limit.
    pub quota_inodes: u64,
}

/// The executor's verified outcome for a `verifying` re-adoption.
#[derive(Clone, Debug)]
pub enum ReadoptOutcome<'a> {
    /// Every rule held.
    Adopted {
        /// Canonical JSON of the facts, at most 4096 bytes.
        facts: &'a str,
        /// Site form: the allocations the site holds.
        site: Option<SiteAdoption>,
        /// Generation form: the live generation and its digest.
        generation: Option<(Id, Sha256Digest)>,
        /// The plan's allocation floor (UID, category), if any.
        floor: Option<(u32, u32)>,
    },
    /// A rule failed.
    Refused {
        /// Canonical JSON of the facts, at most 4096 bytes.
        facts: &'a str,
        /// `READOPT_MISMATCH` or `OLS_DRIFT`.
        code: &'a str,
        /// The first failed rule, `[a-z_]{1,64}`.
        rule: &'a str,
    },
}

fn bad() -> rusqlite::Error {
    rusqlite::Error::InvalidQuery
}

fn decode_row(row: &Row<'_>) -> rusqlite::Result<Readoption> {
    let id = |i| Id::try_from(row.get::<_, String>(i)?).map_err(|_| bad());
    let digest = |i| Sha256Digest::try_from(row.get::<_, String>(i)?).map_err(|_| bad());
    let form = match row.get::<_, String>(8)?.as_str() {
        "site" => ReadoptForm::Site,
        "generation" => ReadoptForm::Generation,
        _ => return Err(bad()),
    };
    let site = match (
        row.get::<_, Option<String>>(9)?,
        row.get::<_, Option<String>>(10)?,
    ) {
        (Some(site), Some(hostname)) => Some((
            SiteId::try_from(site).map_err(|_| bad())?,
            Hostname::try_from(hostname).map_err(|_| bad())?,
        )),
        (None, None) => None,
        _ => return Err(bad()),
    };
    let state = match row.get::<_, String>(14)?.as_str() {
        "verifying" => ReadoptState::Verifying,
        "adopted" => ReadoptState::Adopted,
        "refused" => ReadoptState::Refused,
        _ => return Err(bad()),
    };
    let refusal = match (
        row.get::<_, Option<String>>(16)?,
        row.get::<_, Option<String>>(17)?,
    ) {
        (Some(code), Some(rule)) => Some((code, rule)),
        (None, None) => None,
        _ => return Err(bad()),
    };
    Ok(Readoption {
        intent: ReadoptionIntent {
            operation_id: id(0)?,
            idempotency_key: id(1)?,
            grant_id: id(2)?,
            nonce: id(3)?,
            plan_digest: digest(4)?,
            grant_digest: digest(5)?,
            host_id: id(6)?,
            host_epoch: id(7)?,
            form,
            site,
            previous_epoch: id(11)?,
            evidence_sha256: digest(12)?,
            expires_at: u64::try_from(row.get::<_, i64>(13)?)
                .ok()
                .and_then(|time| Timestamp::try_from(time).ok())
                .ok_or_else(bad)?,
            plan: row.get(18)?,
        },
        state,
        facts: row.get(15)?,
        refusal,
    })
}

const COLUMNS: &str = "operation_id,idempotency_key,grant_id,nonce,plan_digest,grant_digest,host_id,host_epoch,form,site_id,hostname,previous_epoch,evidence_sha256,expires_at,state,facts,refusal,rule,plan";

fn find(c: &Connection, column: &str, value: &str) -> Result<Option<Readoption>, JournalError> {
    c.query_row(
        &format!("SELECT {COLUMNS} FROM readoptions WHERE {column}=?1"),
        [value],
        decode_row,
    )
    .optional()
    .map_err(storage::unavailable)
}

/// Whether the stored plan is a re-adoption plan that hashes to the
/// recorded digest and names the recorded form, site and epochs.
fn plan_matches(intent: &ReadoptionIntent) -> bool {
    if intent.plan.len() > MAX_PLAN {
        return false;
    }
    let Ok(plan) = ReadoptPlan::decode(intent.plan.as_bytes()) else {
        return false;
    };
    plan.digest() == intent.plan_digest
        && plan.form() == intent.form
        && plan.previous_epoch() == &intent.previous_epoch
        && plan.evidence_sha256() == &intent.evidence_sha256
        && plan
            .site()
            .map(|(site, hostname, _)| (site.clone(), hostname.clone()))
            == intent.site
}

/// Whether any admitted work is unsettled: an unresolved operation, a
/// running provision or capture, a running or uncleaned probe, or a
/// verifying re-adoption.
pub(crate) fn any_unresolved(c: &Connection) -> Result<bool, JournalError> {
    c.query_row(
        "SELECT EXISTS(SELECT 1 FROM operations WHERE state IN ('intent','needs_attention','compensating')) \
         OR EXISTS(SELECT 1 FROM provisions WHERE state='running') \
         OR EXISTS(SELECT 1 FROM captures WHERE state='running') \
         OR EXISTS(SELECT 1 FROM restore_probes WHERE state IN ('running','cleanup_incomplete')) \
         OR EXISTS(SELECT 1 FROM readoptions WHERE state='verifying') \
         OR EXISTS(SELECT 1 FROM import_scrubs WHERE state='intent') \
         OR EXISTS(SELECT 1 FROM certificates WHERE state='intent') \
         OR EXISTS(SELECT 1 FROM certificate_renewals WHERE state='intent')",
        [],
        |row| row.get(0),
    )
    .map_err(storage::unavailable)
}

impl FixtureJournal {
    /// Reads whether an ID or hostname is reserved by a provision or static alias.
    /// Does not reserve either value.
    pub fn site_identity_is_reserved(
        &self,
        site: &SiteId,
        hostname: &Hostname,
    ) -> Result<bool, JournalError> {
        site_taken(&self.connection, site, hostname)
    }
}

fn site_taken(c: &Connection, site: &SiteId, hostname: &Hostname) -> Result<bool, JournalError> {
    if crate::import::alias_taken(c, hostname)? {
        return Ok(true);
    }
    c.query_row(
        "SELECT EXISTS(SELECT 1 FROM provisions WHERE site_id=?1 OR hostname=?2)",
        params![site.as_str(), hostname.as_str()],
        |row| row.get(0),
    )
    .map_err(storage::unavailable)
}

fn generation_adopted(c: &Connection) -> Result<bool, JournalError> {
    c.query_row("SELECT EXISTS(SELECT 1 FROM ols_adoptions)", [], |row| {
        row.get(0)
    })
    .map_err(storage::unavailable)
}

fn bounded_facts(facts: &str) -> bool {
    (2..=MAX_FACTS).contains(&facts.len()) && facts.bytes().all(|b| (0x20..0x7f).contains(&b))
}

impl FixtureJournal {
    /// Records a new re-adoption `verifying` in one transaction, or returns
    /// exact status. Refuses a replayed identity (`Conflict`), unsettled
    /// work (`Busy`), a site or hostname any provision holds or a second
    /// generation adoption (`Consumed`), and a full history (`Capacity`).
    pub fn record_readoption(
        &mut self,
        intent: &ReadoptionIntent,
        now: Timestamp,
    ) -> Result<ReadoptResult, JournalError> {
        let signed = self.take_signed(&crate::signed::Expected {
            plan_digest: &intent.plan_digest,
            grant_digest: &intent.grant_digest,
        })?;
        if intent.host_id != self.host_id
            || intent.host_epoch != self.host_epoch
            || intent.previous_epoch == self.host_epoch
            || !plan_matches(intent)
        {
            return Err(JournalError::Conflict);
        }
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        if let Some(existing) = find(
            &transaction,
            "idempotency_key",
            intent.idempotency_key.as_str(),
        )? {
            return if existing.intent == *intent {
                Ok(ReadoptResult::Existing(existing))
            } else {
                Err(JournalError::Conflict)
            };
        }
        if storage::consumed_ids(
            &transaction,
            &intent.operation_id,
            &intent.grant_id,
            &intent.nonce,
        )? {
            return Err(JournalError::Conflict);
        }
        storage::check_clock(&transaction, now)?;
        if now.get() >= intent.expires_at.get() {
            return Err(JournalError::Expired);
        }
        if any_unresolved(&transaction)? {
            return Err(JournalError::Busy);
        }
        let taken = match &intent.site {
            Some((site, hostname)) => site_taken(&transaction, site, hostname)?,
            None => generation_adopted(&transaction)?,
        };
        if taken {
            return Err(JournalError::Consumed);
        }
        let count: i64 = transaction
            .query_row("SELECT count(*) FROM readoptions", [], |row| row.get(0))
            .map_err(storage::unavailable)?;
        if count >= MAX_READOPTIONS {
            return Err(JournalError::Capacity);
        }
        let (site, hostname) = match &intent.site {
            Some((site, hostname)) => (Some(site.as_str()), Some(hostname.as_str())),
            None => (None, None),
        };
        transaction
            .execute(
                &format!("INSERT INTO readoptions({COLUMNS}) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,'verifying',NULL,NULL,NULL,?15)"),
                params![
                    intent.operation_id.as_str(),
                    intent.idempotency_key.as_str(),
                    intent.grant_id.as_str(),
                    intent.nonce.as_str(),
                    intent.plan_digest.as_str(),
                    intent.grant_digest.as_str(),
                    intent.host_id.as_str(),
                    intent.host_epoch.as_str(),
                    intent.form.as_str(),
                    site,
                    hostname,
                    intent.previous_epoch.as_str(),
                    intent.evidence_sha256.as_str(),
                    intent.expires_at.get() as i64,
                    intent.plan,
                ],
            )
            .map_err(storage::unavailable)?;
        crate::signed::insert(&transaction, &intent.operation_id, signed.as_ref())?;
        storage::set_clock(&transaction, now)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(ReadoptResult::New(Readoption {
            intent: intent.clone(),
            state: ReadoptState::Verifying,
            facts: None,
            refusal: None,
        }))
    }

    /// Records the verified outcome of a `verifying` re-adoption in one
    /// transaction. `Adopted` must carry exactly what its form records.
    /// Anything else, or a row that is no longer `verifying`, is a conflict
    /// and changes nothing.
    pub fn finish_readoption(
        &mut self,
        operation_id: &Id,
        outcome: ReadoptOutcome<'_>,
    ) -> Result<Readoption, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let stored = find(&transaction, "operation_id", operation_id.as_str())?
            .ok_or(JournalError::Conflict)?;
        if stored.state != ReadoptState::Verifying {
            return Err(JournalError::Conflict);
        }
        let intent = &stored.intent;
        match outcome {
            ReadoptOutcome::Adopted {
                facts,
                site,
                generation,
                floor,
            } => {
                if !bounded_facts(facts) {
                    return Err(JournalError::Conflict);
                }
                match (&intent.site, site, generation) {
                    (Some((site_id, hostname)), Some(adoption), None) => {
                        if site_taken(&transaction, site_id, hostname)? {
                            return Err(JournalError::Conflict);
                        }
                        transaction
                            .execute(
                                "INSERT INTO provisions VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,'adopted')",
                                params![
                                    intent.operation_id.as_str(),
                                    intent.idempotency_key.as_str(),
                                    intent.grant_id.as_str(),
                                    intent.nonce.as_str(),
                                    intent.plan_digest.as_str(),
                                    intent.grant_digest.as_str(),
                                    intent.host_id.as_str(),
                                    intent.host_epoch.as_str(),
                                    site_id.as_str(),
                                    hostname.as_str(),
                                    intent.expires_at.get() as i64,
                                ],
                            )
                            .map_err(storage::unavailable)?;
                        transaction
                            .execute(
                                "INSERT INTO provision_adoptions VALUES(?1,?2,?3,?4,?5)",
                                params![
                                    intent.operation_id.as_str(),
                                    i64::from(adoption.uid),
                                    i64::from(adoption.category),
                                    i64::try_from(adoption.quota_kib)
                                        .map_err(storage::unavailable)?,
                                    i64::try_from(adoption.quota_inodes)
                                        .map_err(storage::unavailable)?,
                                ],
                            )
                            .map_err(storage::unavailable)?;
                    }
                    (None, None, Some((generation, digest))) => {
                        if generation_adopted(&transaction)? {
                            return Err(JournalError::Conflict);
                        }
                        transaction
                            .execute(
                                "INSERT INTO ols_adoptions VALUES(?1,?2,?3)",
                                params![
                                    intent.operation_id.as_str(),
                                    generation.as_str(),
                                    digest.as_str()
                                ],
                            )
                            .map_err(storage::unavailable)?;
                    }
                    _ => return Err(JournalError::Conflict),
                }
                if let Some((uid, category)) = floor {
                    transaction
                        .execute(
                            "INSERT INTO allocation_floors VALUES(?1,?2,?3)",
                            params![
                                intent.operation_id.as_str(),
                                i64::from(uid),
                                i64::from(category)
                            ],
                        )
                        .map_err(storage::unavailable)?;
                }
                transaction
                    .execute(
                        "UPDATE readoptions SET state=?1, facts=?2 WHERE operation_id=?3",
                        params![ReadoptState::Adopted.text(), facts, operation_id.as_str()],
                    )
                    .map_err(storage::unavailable)?;
            }
            ReadoptOutcome::Refused { facts, code, rule } => {
                if !bounded_facts(facts) {
                    return Err(JournalError::Conflict);
                }
                transaction
                    .execute(
                        "UPDATE readoptions SET state=?1, facts=?2, refusal=?3, rule=?4 WHERE operation_id=?5",
                        params![
                            ReadoptState::Refused.text(),
                            facts,
                            code,
                            rule,
                            operation_id.as_str()
                        ],
                    )
                    .map_err(|_| JournalError::Conflict)?;
            }
        }
        transaction.commit().map_err(storage::unavailable)?;
        self.readoption_status(operation_id)?
            .ok_or(JournalError::Unavailable)
    }

    /// Recorded re-adoption status only.
    pub fn readoption_status(&self, operation_id: &Id) -> Result<Option<Readoption>, JournalError> {
        find(&self.connection, "operation_id", operation_id.as_str())
    }

    /// The allocations an adopted provision holds, if `operation_id` is one.
    pub fn site_adoption(&self, operation_id: &Id) -> Result<Option<SiteAdoption>, JournalError> {
        site_adoption(&self.connection, operation_id)
    }

    /// The adopted generation and its digest, if the journal holds one.
    pub fn ols_adoption(&self) -> Result<Option<(Id, Sha256Digest)>, JournalError> {
        ols_adoption(&self.connection)
    }

    /// UIDs and categories of every adopted site, so no later allocation
    /// reuses them.
    pub fn adopted_allocations(&self) -> Result<(Vec<u32>, Vec<u32>), JournalError> {
        let mut query = self
            .connection
            .prepare("SELECT uid, category FROM provision_adoptions ORDER BY rowid")
            .map_err(storage::unavailable)?;
        let rows = query
            .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))
            .map_err(storage::unavailable)?;
        let mut uids = Vec::new();
        let mut categories = Vec::new();
        for row in rows {
            let (uid, category) = row.map_err(storage::unavailable)?;
            uids.push(u32::try_from(uid).map_err(storage::unavailable)?);
            categories.push(u32::try_from(category).map_err(storage::unavailable)?);
        }
        Ok((uids, categories))
    }

    /// The highest signed allocation floor of every adopted re-adoption.
    pub fn allocation_floor(&self) -> Result<Option<(u32, u32)>, JournalError> {
        let (uid, category): (Option<i64>, Option<i64>) = self
            .connection
            .query_row(
                "SELECT max(uid), max(category) FROM allocation_floors",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(storage::unavailable)?;
        match (uid, category) {
            (Some(uid), Some(category)) => Ok(Some((
                u32::try_from(uid).map_err(storage::unavailable)?,
                u32::try_from(category).map_err(storage::unavailable)?,
            ))),
            _ => Ok(None),
        }
    }

    /// Every re-adoption, in recorded order.
    pub fn readoptions(&self) -> Result<Vec<Readoption>, JournalError> {
        all(&self.connection)
    }
}

pub(crate) fn all(c: &Connection) -> Result<Vec<Readoption>, JournalError> {
    let mut query = c
        .prepare(&format!(
            "SELECT {COLUMNS} FROM readoptions ORDER BY rowid LIMIT {}",
            MAX_READOPTIONS + 1
        ))
        .map_err(storage::unavailable)?;
    let rows = query
        .query_map([], decode_row)
        .map_err(storage::unavailable)?;
    rows.collect::<Result<_, _>>().map_err(storage::unavailable)
}

pub(crate) fn by_operation(c: &Connection, id: &Id) -> Result<Option<Readoption>, JournalError> {
    find(c, "operation_id", id.as_str())
}

pub(crate) fn site_adoption(
    c: &Connection,
    operation_id: &Id,
) -> Result<Option<SiteAdoption>, JournalError> {
    let row: Option<(i64, i64, i64, i64)> = c
        .query_row(
            "SELECT uid, category, quota_kib, quota_inodes FROM provision_adoptions WHERE operation_id=?1",
            [operation_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(storage::unavailable)?;
    row.map(|(uid, category, kib, inodes)| {
        Ok(SiteAdoption {
            uid: u32::try_from(uid).map_err(storage::unavailable)?,
            category: u32::try_from(category).map_err(storage::unavailable)?,
            quota_kib: u64::try_from(kib).map_err(storage::unavailable)?,
            quota_inodes: u64::try_from(inodes).map_err(storage::unavailable)?,
        })
    })
    .transpose()
}

pub(crate) fn ols_adoption(c: &Connection) -> Result<Option<(Id, Sha256Digest)>, JournalError> {
    let row: Option<(String, String)> = c
        .query_row(
            "SELECT a.generation, a.digest FROM ols_adoptions a JOIN readoptions r USING(operation_id) WHERE r.state='adopted'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(storage::unavailable)?;
    row.map(|(generation, digest)| {
        Ok((
            Id::try_from(generation).map_err(storage::unavailable)?,
            Sha256Digest::try_from(digest).map_err(storage::unavailable)?,
        ))
    })
    .transpose()
}

/// Opening refuses re-adoption rows that contradict each other or the
/// provisions they produced: every row is this journal's, its stored plan
/// hashes to its digest, an `adopted` provision exists exactly for an
/// adopted site form (with no steps and its allocations), and the
/// generation adoption and allocation floors belong to adopted rows of the
/// right form.
pub(crate) fn validate(c: &Connection, host: &Id, epoch: &Id) -> Result<(), JournalError> {
    let rows = all(c)?;
    if rows.len() as i64 > MAX_READOPTIONS
        || rows
            .iter()
            .filter(|row| row.state == ReadoptState::Verifying)
            .count()
            > 1
    {
        return Err(JournalError::Unavailable);
    }
    for row in &rows {
        if &row.intent.host_id != host
            || &row.intent.host_epoch != epoch
            || !plan_matches(&row.intent)
        {
            return Err(JournalError::Unavailable);
        }
    }
    let broken: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM provisions p WHERE p.state='adopted' AND NOT EXISTS(SELECT 1 FROM readoptions r WHERE r.operation_id=p.operation_id AND r.form='site' AND r.state='adopted' AND r.site_id=p.site_id AND r.hostname=p.hostname)) \
             OR EXISTS(SELECT 1 FROM readoptions r WHERE r.form='site' AND r.state='adopted' AND NOT EXISTS(SELECT 1 FROM provisions p WHERE p.operation_id=r.operation_id AND p.state='adopted')) \
             OR EXISTS(SELECT 1 FROM provisions p WHERE p.state='adopted' AND (EXISTS(SELECT 1 FROM provision_steps s WHERE s.operation_id=p.operation_id) OR NOT EXISTS(SELECT 1 FROM provision_adoptions a WHERE a.operation_id=p.operation_id))) \
             OR EXISTS(SELECT 1 FROM provision_adoptions a LEFT JOIN provisions p USING(operation_id) WHERE p.state IS NULL OR p.state<>'adopted') \
             OR EXISTS(SELECT 1 FROM ols_adoptions a LEFT JOIN readoptions r USING(operation_id) WHERE r.state IS NULL OR r.state<>'adopted' OR r.form<>'generation') \
             OR EXISTS(SELECT 1 FROM readoptions r WHERE r.form='generation' AND r.state='adopted' AND NOT EXISTS(SELECT 1 FROM ols_adoptions a WHERE a.operation_id=r.operation_id)) \
             OR EXISTS(SELECT 1 FROM allocation_floors f LEFT JOIN readoptions r USING(operation_id) WHERE r.state IS NULL OR r.state<>'adopted')",
            [],
            |row| row.get(0),
        )
        .map_err(storage::unavailable)?;
    if broken {
        return Err(JournalError::Unavailable);
    }
    Ok(())
}
