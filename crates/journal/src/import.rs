//! Site imports (schema v21, W442, D-053) and their scrubs (v22, D-057).
//! v25 (D-070) keeps the source hostname of an import that serves the site
//! under another hostname.
//!
//! An import is a provision: it reserves its site and hostname in
//! `provisions` and runs the provision steps. Its Recipe step holds the
//! import steps, in a fixed order, each with a durable intent before its
//! effect. The signed dry-run facts are kept with the provision so that each
//! step can be checked against them. Nothing here reads the intake or a host.

use rusqlite::{OptionalExtension, params};
use rustiron_contracts::{
    Id, Timestamp,
    approval::{Hostname, Sha256Digest, SiteId},
    migration::PhpVersion,
};

use crate::{
    Admitted, FixtureJournal, JournalError, Provision, ProvisionIntent, ProvisionState,
    ProvisionStep, StepState, provision, storage,
};

/// The signed dry-run facts of one import.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportFacts {
    /// SHA-256 of the intake archive.
    pub archive_sha256: Sha256Digest,
    /// Manifest digest the extracted tree must match.
    pub manifest_sha256: Sha256Digest,
    /// Entries of the extracted home tree.
    pub file_entries: u64,
    /// Regular-file bytes of the extracted home tree.
    pub file_bytes: u64,
    /// Size of the database dump; 0 for a static site (D-074).
    pub dump_bytes: u64,
    /// LSPHP version for the site.
    pub target_php: PhpVersion,
    /// D-070: the source site's hostname when the import serves the site
    /// under another one; `None` when they are the same.
    pub source_hostname: Option<Hostname>,
    /// D-075: the exact alias signed by a schema 3 static import.
    pub alias_hostname: Option<Hostname>,
}

impl ImportFacts {
    /// D-074: a static site, imported with no database content.
    pub fn is_static(&self) -> bool {
        self.dump_bytes == 0
    }

    /// D-070: the hostname of the source site: the signed source hostname,
    /// else the provision's own `hostname`.
    pub fn source_or<'a>(&'a self, hostname: &'a Hostname) -> &'a Hostname {
        self.source_hostname.as_ref().unwrap_or(hostname)
    }
}

/// The fixed import steps, in the only order they may run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportStep {
    /// Open the intake archive and check its digest.
    Intake,
    /// Extract it as the site account.
    Extract,
    /// Observe the extracted tree and compare it with the facts.
    Observe,
    /// Move the document root into place.
    Files,
    /// Import the dump as the site's database user.
    Database,
    /// Rewrite the site's database credentials.
    Config,
}

impl ImportStep {
    /// Every step in order.
    pub const ALL: [Self; 6] = [
        Self::Intake,
        Self::Extract,
        Self::Observe,
        Self::Files,
        Self::Database,
        Self::Config,
    ];

    fn position(self) -> i64 {
        Self::ALL.iter().position(|step| *step == self).unwrap_or(0) as i64
    }
}

/// One recorded import step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportStepRecord {
    /// Which step.
    pub step: ImportStep,
    /// Its state.
    pub state: StepState,
}

/// Why an import scrub runs (D-057).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScrubOrigin {
    /// An import step failed; the executor removes the import's leftovers
    /// under the import's own signed authority.
    FailedStep,
    /// A signed `import_scrub` of an ended import.
    Signed,
}

/// One recorded scrub of an import's leftover secrets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportScrub {
    /// The scrub's operation; the import's own for [`ScrubOrigin::FailedStep`].
    pub operation_id: Id,
    /// Why it runs.
    pub origin: ScrubOrigin,
    /// `intent` until its outcome is observed.
    pub state: StepState,
}

/// A stored import: its facts and the steps recorded so far.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Import {
    /// Signed dry-run facts.
    pub facts: ImportFacts,
    /// Steps recorded so far, in order.
    pub steps: Vec<ImportStepRecord>,
    /// Scrubs recorded so far, in order (D-057).
    pub scrubs: Vec<ImportScrub>,
}

impl Import {
    /// Whether every import step completed (`done`).
    pub fn is_complete(&self) -> bool {
        self.steps.len() == ImportStep::ALL.len()
            && self
                .steps
                .iter()
                .all(|record| record.state == StepState::Done)
    }
}

/// W459 (D-057): an admitted signed scrub; built by the executor from
/// verified inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScrubIntent {
    /// The scrub's operation.
    pub operation_id: Id,
    /// Retry key bound to every field.
    pub idempotency_key: Id,
    /// Signed grant identity.
    pub grant_id: Id,
    /// Single-use signed nonce.
    pub nonce: Id,
    /// Complete plan digest.
    pub plan_digest: Sha256Digest,
    /// Complete canonical grant digest.
    pub grant_digest: Sha256Digest,
    /// Enrolled host identity.
    pub host_id: Id,
    /// Enrolled host epoch.
    pub host_epoch: Id,
    /// The scrubbed import's operation.
    pub import_operation_id: Id,
    /// The import's site, as signed.
    pub site_id: SiteId,
    /// The import's archive digest, as signed.
    pub archive_sha256: Sha256Digest,
    /// Normal grant deadline.
    pub expires_at: Timestamp,
}

const SCRUB_COLUMNS: &str = "operation_id, import_operation_id, idempotency_key, grant_id, nonce, plan_digest, grant_digest, expires_at, state";

fn count(value: u64) -> Result<i64, JournalError> {
    i64::try_from(value).map_err(|_| JournalError::Conflict)
}

pub(crate) fn insert(
    c: &rusqlite::Connection,
    operation_id: &Id,
    facts: &ImportFacts,
) -> Result<(), JournalError> {
    // D-074: a static import (no dump) keeps its source hostname.
    if facts.dump_bytes == 0 && facts.source_hostname.is_some() {
        return Err(JournalError::Conflict);
    }
    c.execute(
        "INSERT INTO imports VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            operation_id.as_str(),
            facts.archive_sha256.as_str(),
            facts.manifest_sha256.as_str(),
            count(facts.file_entries)?,
            count(facts.file_bytes)?,
            count(facts.dump_bytes)?,
            facts.target_php.as_str(),
        ],
    )
    .map_err(storage::unavailable)?;
    if let Some(source) = &facts.source_hostname {
        c.execute(
            "INSERT INTO import_sources VALUES(?1,?2)",
            params![operation_id.as_str(), source.as_str()],
        )
        .map_err(storage::unavailable)?;
    }
    if let Some(alias) = &facts.alias_hostname {
        c.execute(
            "INSERT INTO import_aliases VALUES(?1,?2,0)",
            params![operation_id.as_str(), alias.as_str()],
        )
        .map_err(storage::unavailable)?;
    }
    Ok(())
}

/// Whether an import holds this name as an active alias.
pub(crate) fn alias_taken(
    c: &rusqlite::Connection,
    hostname: &Hostname,
) -> Result<bool, JournalError> {
    c.query_row(
        "SELECT EXISTS(SELECT 1 FROM import_aliases WHERE hostname=?1 AND released=0)",
        [hostname.as_str()],
        |row| row.get(0),
    )
    .map_err(storage::unavailable)
}

pub(crate) fn validate_aliases(c: &rusqlite::Connection) -> Result<(), JournalError> {
    let mut query = c.prepare(
        "SELECT a.hostname, i.dump_bytes=0 AND s.operation_id IS NULL AND p.operation_id IS NOT NULL \
         AND a.released=(p.state='quarantined' AND EXISTS(SELECT 1 FROM import_scrubs sc \
             WHERE sc.import_operation_id=a.operation_id AND sc.state='done')) \
         AND (a.released=1 OR NOT EXISTS(SELECT 1 FROM provisions h WHERE h.hostname=a.hostname)) \
         FROM import_aliases a LEFT JOIN imports i USING(operation_id) \
         LEFT JOIN provisions p USING(operation_id) LEFT JOIN import_sources s USING(operation_id)",
    ).map_err(storage::unavailable)?;
    let mut rows = query.query([]).map_err(storage::unavailable)?;
    while let Some(row) = rows.next().map_err(storage::unavailable)? {
        let hostname = row.get::<_, String>(0).map_err(storage::unavailable)?;
        if row
            .get::<_, Option<bool>>(1)
            .map_err(storage::unavailable)?
            != Some(true)
            || Hostname::try_from(hostname).is_err()
        {
            return Err(JournalError::Unavailable);
        }
    }
    Ok(())
}

pub(crate) fn facts(
    c: &rusqlite::Connection,
    operation_id: &Id,
) -> Result<Option<ImportFacts>, JournalError> {
    let row = c
        .query_row(
            "SELECT archive_sha256, manifest_sha256, file_entries, file_bytes, dump_bytes, target_php FROM imports WHERE operation_id=?1",
            [operation_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()
        .map_err(storage::unavailable)?;
    let Some((archive, manifest, entries, bytes, dump, php)) = row else {
        return Ok(None);
    };
    let source: Option<String> = c
        .query_row(
            "SELECT source_hostname FROM import_sources WHERE operation_id=?1",
            [operation_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage::unavailable)?;
    let source_hostname = source
        .map(|text| Hostname::try_from(text).map_err(|_| JournalError::Unavailable))
        .transpose()?;
    let digest = |text: String| Sha256Digest::try_from(text).map_err(|_| JournalError::Unavailable);
    let number = |value: i64| u64::try_from(value).map_err(|_| JournalError::Unavailable);
    Ok(Some(ImportFacts {
        archive_sha256: digest(archive)?,
        manifest_sha256: digest(manifest)?,
        file_entries: number(entries)?,
        file_bytes: number(bytes)?,
        dump_bytes: number(dump)?,
        target_php: PhpVersion::try_from(php).map_err(|_| JournalError::Unavailable)?,
        source_hostname,
        alias_hostname: alias_of(c, operation_id)?,
    }))
}

pub(crate) fn alias_of(
    c: &rusqlite::Connection,
    operation_id: &Id,
) -> Result<Option<Hostname>, JournalError> {
    c.query_row(
        "SELECT hostname FROM import_aliases WHERE operation_id=?1",
        [operation_id.as_str()],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(storage::unavailable)?
    .map(|text| Hostname::try_from(text).map_err(|_| JournalError::Unavailable))
    .transpose()
}

fn steps(
    c: &rusqlite::Connection,
    operation_id: &Id,
) -> Result<Vec<ImportStepRecord>, JournalError> {
    let mut query = c
        .prepare("SELECT position, state FROM import_steps WHERE operation_id=?1 ORDER BY position")
        .map_err(storage::unavailable)?;
    let rows = query
        .query_map([operation_id.as_str()], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(storage::unavailable)?;
    let mut records = Vec::new();
    for (index, row) in rows.enumerate() {
        let (position, state) = row.map_err(storage::unavailable)?;
        let step = usize::try_from(position)
            .ok()
            .and_then(|position| ImportStep::ALL.get(position).copied())
            .filter(|_| position == index as i64)
            .ok_or(JournalError::Unavailable)?;
        let state = state_of(&state)?;
        records.push(ImportStepRecord { step, state });
    }
    Ok(records)
}

fn state_of(text: &str) -> Result<StepState, JournalError> {
    match text {
        "intent" => Ok(StepState::Intent),
        "done" => Ok(StepState::Done),
        "failed" => Ok(StepState::Failed),
        _ => Err(JournalError::Unavailable),
    }
}

fn scrubs(c: &rusqlite::Connection, operation_id: &Id) -> Result<Vec<ImportScrub>, JournalError> {
    let mut query = c
        .prepare("SELECT operation_id, origin, state FROM import_scrubs WHERE import_operation_id=?1 ORDER BY rowid")
        .map_err(storage::unavailable)?;
    let rows = query
        .query_map([operation_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(storage::unavailable)?;
    let mut records = Vec::new();
    for row in rows {
        let (id, origin, state) = row.map_err(storage::unavailable)?;
        records.push(ImportScrub {
            operation_id: Id::try_from(id).map_err(|_| JournalError::Unavailable)?,
            origin: match origin.as_str() {
                "failed_step" => ScrubOrigin::FailedStep,
                "signed" => ScrubOrigin::Signed,
                _ => return Err(JournalError::Unavailable),
            },
            state: state_of(&state)?,
        });
    }
    Ok(records)
}

pub(crate) fn load(
    c: &rusqlite::Connection,
    operation_id: &Id,
) -> Result<Option<Import>, JournalError> {
    match facts(c, operation_id)? {
        Some(facts) => Ok(Some(Import {
            facts,
            steps: steps(c, operation_id)?,
            scrubs: scrubs(c, operation_id)?,
        })),
        None => Ok(None),
    }
}

/// True for a provision without import facts, or an import whose six steps
/// are all done.
pub(crate) fn complete_or_absent(
    c: &rusqlite::Connection,
    operation_id: &Id,
) -> Result<bool, JournalError> {
    Ok(load(c, operation_id)?.is_none_or(|import| import.is_complete()))
}

/// D-067: the hostname a scrubbed, quarantined import holds instead of its
/// own. `.invalid` never resolves (RFC 6761), and the prefix is unique per
/// operation.
pub(crate) fn released_hostname(operation: &Id) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(operation.as_str().as_bytes());
    let hex: String = digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("released-{hex}.invalid")
}

/// D-067: gives a quarantined import whose scrub is done its released
/// hostname when it still holds `hostname`. Runs inside the caller's
/// transaction, so a refused admission rolls it back.
pub(crate) fn release_scrubbed_hostname(
    c: &rusqlite::Connection,
    hostname: &rustiron_contracts::approval::Hostname,
) -> Result<(), JournalError> {
    let holder: Option<String> = c
        .query_row(
            "SELECT p.operation_id FROM provisions p WHERE p.hostname=?1 AND p.state='quarantined' \
             AND EXISTS(SELECT 1 FROM import_scrubs s WHERE s.import_operation_id=p.operation_id AND s.state='done')",
            [hostname.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage::unavailable)?;
    if let Some(holder) = holder {
        let holder = Id::try_from(holder).map_err(|_| JournalError::Unavailable)?;
        c.execute(
            "UPDATE provisions SET hostname=?1 WHERE operation_id=?2",
            params![released_hostname(&holder), holder.as_str()],
        )
        .map_err(storage::unavailable)?;
    }
    Ok(())
}

/// The provision is running with its Recipe step open (intent recorded).
fn in_recipe(c: &rusqlite::Connection, operation_id: &Id) -> Result<bool, JournalError> {
    let provision = provision::by_operation(c, operation_id)?.ok_or(JournalError::Conflict)?;
    let last = provision.steps.last();
    Ok(provision.state == ProvisionState::Running
        && last.is_some_and(|record| {
            record.step == ProvisionStep::Recipe && record.state == StepState::Intent
        }))
}

/// A signed scrub stored under the intent's operation or retry key: whether
/// it is exactly this intent, and its record.
fn signed_scrub(
    c: &rusqlite::Connection,
    intent: &ScrubIntent,
) -> Result<Option<(bool, ImportScrub)>, JournalError> {
    let row = c
        .query_row(
            &format!("SELECT {SCRUB_COLUMNS} FROM import_scrubs WHERE origin='signed' AND (operation_id=?1 OR idempotency_key=?2)"),
            params![intent.operation_id.as_str(), intent.idempotency_key.as_str()],
            |row| {
                Ok([0, 1, 2, 3, 4, 5, 6]
                    .map(|index| row.get::<_, String>(index))
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()
                    .map(|texts| (texts, row.get::<_, i64>(7), row.get::<_, String>(8))))
            },
        )
        .optional()
        .map_err(storage::unavailable)?;
    let Some(Ok((texts, Ok(expires_at), Ok(state)))) = row else {
        return match row {
            None => Ok(None),
            Some(_) => Err(JournalError::Unavailable),
        };
    };
    let exact = texts
        == [
            intent.operation_id.as_str(),
            intent.import_operation_id.as_str(),
            intent.idempotency_key.as_str(),
            intent.grant_id.as_str(),
            intent.nonce.as_str(),
            intent.plan_digest.as_str(),
            intent.grant_digest.as_str(),
        ]
        && expires_at == intent.expires_at.get() as i64;
    let operation_id = Id::try_from(texts[0].clone()).map_err(|_| JournalError::Unavailable)?;
    Ok(Some((
        exact,
        ImportScrub {
            operation_id,
            origin: ScrubOrigin::Signed,
            state: state_of(&state)?,
        },
    )))
}

impl FixtureJournal {
    /// The recorded alias of an import. Callers must verify site ownership
    /// before deriving a serving configuration from it.
    pub fn import_alias(&self, operation_id: &Id) -> Result<Option<Hostname>, JournalError> {
        alias_of(&self.connection, operation_id)
    }

    /// Records a new import provision with its facts, or the exact earlier status.
    pub fn record_import(
        &mut self,
        intent: &ProvisionIntent,
        facts: &ImportFacts,
        now: Timestamp,
    ) -> Result<Admitted<Provision>, JournalError> {
        self.admit_provision(intent, provision::Origin::Import(facts), now)
    }

    /// Commits an import step's intent before its effect. The provision's
    /// Recipe step must be open, the earlier import steps done, and this
    /// step not recorded before.
    pub fn begin_import_step(
        &mut self,
        operation_id: &Id,
        step: ImportStep,
    ) -> Result<Import, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let import = load(&transaction, operation_id)?.ok_or(JournalError::Conflict)?;
        if !in_recipe(&transaction, operation_id)?
            || import.steps.len() as i64 != step.position()
            || import
                .steps
                .iter()
                .any(|record| record.state != StepState::Done)
        {
            return Err(JournalError::Conflict);
        }
        transaction
            .execute(
                "INSERT INTO import_steps VALUES(?1,?2,'intent')",
                params![operation_id.as_str(), step.position()],
            )
            .map_err(storage::unavailable)?;
        transaction.commit().map_err(storage::unavailable)?;
        self.import_status(operation_id)?
            .ok_or(JournalError::Unavailable)
    }

    /// Records an import step's observed outcome. A failure marks the
    /// Recipe step failed and quarantines the provision.
    pub fn finish_import_step(
        &mut self,
        operation_id: &Id,
        step: ImportStep,
        done: bool,
    ) -> Result<Import, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let import = load(&transaction, operation_id)?.ok_or(JournalError::Conflict)?;
        let last = import.steps.last().ok_or(JournalError::Conflict)?;
        if !in_recipe(&transaction, operation_id)?
            || last.step != step
            || last.state != StepState::Intent
        {
            return Err(JournalError::Conflict);
        }
        transaction
            .execute(
                "UPDATE import_steps SET state=?1 WHERE operation_id=?2 AND position=?3",
                params![
                    if done { "done" } else { "failed" },
                    operation_id.as_str(),
                    step.position()
                ],
            )
            .map_err(storage::unavailable)?;
        // A failure fails the open Recipe step and quarantines the provision
        // in the same transaction.
        if !done {
            transaction
                .execute(
                    "UPDATE provision_steps SET state='failed' WHERE operation_id=?1 AND position=?2",
                    params![operation_id.as_str(), ProvisionStep::Recipe.position()],
                )
                .map_err(storage::unavailable)?;
            provision::set_state(&transaction, operation_id, ProvisionState::Quarantined)?;
        }
        transaction.commit().map_err(storage::unavailable)?;
        self.import_status(operation_id)?
            .ok_or(JournalError::Unavailable)
    }

    /// D-057 option B: commits the intent of the automatic scrub after a
    /// failed import step, before its effect. The import must be
    /// quarantined by that failure (its last import step failed) and have
    /// no scrub yet. The scrub runs under the import's own operation.
    pub fn begin_failed_step_scrub(&mut self, operation_id: &Id) -> Result<Import, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let import = load(&transaction, operation_id)?.ok_or(JournalError::Conflict)?;
        let provision =
            provision::by_operation(&transaction, operation_id)?.ok_or(JournalError::Conflict)?;
        if provision.state != ProvisionState::Quarantined
            || import.steps.last().map(|record| record.state) != Some(StepState::Failed)
            || !import.scrubs.is_empty()
        {
            return Err(JournalError::Conflict);
        }
        transaction
            .execute(
                "INSERT INTO import_scrubs(operation_id, import_operation_id, origin, state) VALUES(?1,?1,'failed_step','intent')",
                [operation_id.as_str()],
            )
            .map_err(storage::unavailable)?;
        transaction.commit().map_err(storage::unavailable)?;
        self.import_status(operation_id)?
            .ok_or(JournalError::Unavailable)
    }

    /// Records the observed outcome of an open scrub. Returns the import.
    ///
    /// D-067 (W478): a scrub that succeeds on a quarantined import releases
    /// the import's hostname in the same transaction, so the same site can be
    /// imported again under a new site ID. The provision keeps its site ID
    /// (its account and folder stay) and gets the hostname
    /// `released-<16 hex>.invalid`, derived from its operation. The signed
    /// plan of the import still names the original hostname.
    pub fn finish_import_scrub(
        &mut self,
        scrub_operation_id: &Id,
        done: bool,
    ) -> Result<Import, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let import_operation: Option<String> = transaction
            .query_row(
                "SELECT import_operation_id FROM import_scrubs WHERE operation_id=?1 AND state='intent'",
                [scrub_operation_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage::unavailable)?;
        let import_operation = Id::try_from(import_operation.ok_or(JournalError::Conflict)?)
            .map_err(|_| JournalError::Unavailable)?;
        transaction
            .execute(
                "UPDATE import_scrubs SET state=?1 WHERE operation_id=?2",
                params![
                    if done { "done" } else { "failed" },
                    scrub_operation_id.as_str()
                ],
            )
            .map_err(storage::unavailable)?;
        if done {
            transaction
                .execute(
                    "UPDATE provisions SET hostname=?1 WHERE operation_id=?2 AND state='quarantined'",
                    params![released_hostname(&import_operation), import_operation.as_str()],
                )
                .map_err(storage::unavailable)?;
            transaction
                .execute(
                    "UPDATE import_aliases SET released=1 WHERE operation_id=?1 AND EXISTS(\
                     SELECT 1 FROM provisions WHERE operation_id=?1 AND state='quarantined')",
                    [import_operation.as_str()],
                )
                .map_err(storage::unavailable)?;
        }
        transaction.commit().map_err(storage::unavailable)?;
        self.import_status(&import_operation)?
            .ok_or(JournalError::Unavailable)
    }

    /// W459 (D-057): admits one signed scrub of an ended import, or answers
    /// an exact repeat. The import must be this journal's, of the signed
    /// site and archive, `quarantined` or `succeeded`, with no import step
    /// in `intent` and no open scrub; nothing else may be unresolved.
    pub fn record_scrub(
        &mut self,
        intent: &ScrubIntent,
        now: Timestamp,
    ) -> Result<Admitted<ImportScrub>, JournalError> {
        let signed = self.take_signed(&crate::signed::Expected {
            plan_digest: &intent.plan_digest,
            grant_digest: &intent.grant_digest,
        })?;
        if intent.host_id != self.host_id || intent.host_epoch != self.host_epoch {
            return Err(JournalError::Conflict);
        }
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        if let Some((stored, scrub)) = signed_scrub(&transaction, intent)? {
            return if stored {
                Ok(Admitted::Existing(scrub))
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
        if crate::readopt::any_unresolved(&transaction)? {
            return Err(JournalError::Busy);
        }
        let import =
            load(&transaction, &intent.import_operation_id)?.ok_or(JournalError::Conflict)?;
        let provision = provision::by_operation(&transaction, &intent.import_operation_id)?
            .ok_or(JournalError::Conflict)?;
        if provision.intent.site_id != intent.site_id
            || import.facts.archive_sha256 != intent.archive_sha256
            || !matches!(
                provision.state,
                ProvisionState::Quarantined | ProvisionState::Succeeded
            )
            || import
                .steps
                .iter()
                .any(|record| record.state == StepState::Intent)
        {
            return Err(JournalError::Conflict);
        }
        transaction
            .execute(
                &format!("INSERT INTO import_scrubs({SCRUB_COLUMNS}, origin) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'intent','signed')"),
                params![
                    intent.operation_id.as_str(),
                    intent.import_operation_id.as_str(),
                    intent.idempotency_key.as_str(),
                    intent.grant_id.as_str(),
                    intent.nonce.as_str(),
                    intent.plan_digest.as_str(),
                    intent.grant_digest.as_str(),
                    intent.expires_at.get() as i64,
                ],
            )
            .map_err(storage::unavailable)?;
        crate::signed::insert(&transaction, &intent.operation_id, signed.as_ref())?;
        storage::set_clock(&transaction, now)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(Admitted::New(ImportScrub {
            operation_id: intent.operation_id.clone(),
            origin: ScrubOrigin::Signed,
            state: StepState::Intent,
        }))
    }

    /// W459: the stored signed scrub with this operation, and its import's
    /// operation; `None` for an unknown or automatic one.
    pub fn signed_scrub_status(
        &self,
        operation_id: &Id,
    ) -> Result<Option<(ImportScrub, Id)>, JournalError> {
        let row = self
            .connection
            .query_row(
                "SELECT import_operation_id, state FROM import_scrubs WHERE operation_id=?1 AND origin='signed'",
                [operation_id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(storage::unavailable)?;
        let Some((import, state)) = row else {
            return Ok(None);
        };
        Ok(Some((
            ImportScrub {
                operation_id: operation_id.clone(),
                origin: ScrubOrigin::Signed,
                state: state_of(&state)?,
            },
            Id::try_from(import).map_err(|_| JournalError::Unavailable)?,
        )))
    }

    /// Recorded import status; `None` for a plain provision or an unknown ID.
    pub fn import_status(&self, operation_id: &Id) -> Result<Option<Import>, JournalError> {
        load(&self.connection, operation_id)
    }
}
