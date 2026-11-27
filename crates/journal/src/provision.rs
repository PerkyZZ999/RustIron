//! Multi-step site provisions (schema v3): one durable intent per step before
//! its effect, an outcome after it, and quarantine instead of retries.

use rusqlite::{Connection, OptionalExtension, Row, params};
use rustiron_contracts::{
    Id, Timestamp,
    approval::{Hostname, Sha256Digest, SiteId},
};

use crate::{Admitted, FixtureJournal, JournalError, storage};

const MAX_PROVISIONS: i64 = 100;
const MAX_RESOURCE: usize = 256;

/// The fixed provisioning steps, in the only order they may run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvisionStep {
    /// Allocate the site account and group.
    Account,
    /// Create the site directory tree.
    Directories,
    /// Apply the site's SELinux level.
    Labels,
    /// Create the scoped database and its user.
    Database,
    /// Write the site's database credentials.
    Credentials,
    /// Unpack the pinned recipe as the site account.
    Recipe,
    /// Install the site's PHP units.
    PhpUnits,
    /// Verify identity, checksums, database login and served probe.
    Verify,
}

impl ProvisionStep {
    /// Every step in order.
    pub const ALL: [Self; 8] = [
        Self::Account,
        Self::Directories,
        Self::Labels,
        Self::Database,
        Self::Credentials,
        Self::Recipe,
        Self::PhpUnits,
        Self::Verify,
    ];

    pub(crate) fn position(self) -> i64 {
        Self::ALL.iter().position(|step| *step == self).unwrap_or(0) as i64
    }
}

/// Recorded step state; `Intent` means the effect may have happened.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StepState {
    /// Durable intent recorded; outcome unknown.
    Intent,
    /// Effect observed complete.
    Done,
    /// Effect failed or could not be verified; provision is quarantined.
    Failed,
}

/// Recorded provision state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvisionState {
    /// Steps in progress; blocks other provisions.
    Running,
    /// Every step done.
    Succeeded,
    /// Stopped with created resources kept for review; never retried automatically.
    Quarantined,
    /// W372: an existing site that a verified re-adoption recorded. It has
    /// no steps; it is owned like a succeeded provision.
    Adopted,
    /// W521 (D-085): a succeeded site whose signed deletion was admitted.
    /// It is never served again; its site ID and hostname stay consumed.
    Deleted,
}

impl ProvisionState {
    /// Whether the journal owns the site: provisioned here (`created`) or
    /// re-adopted (`explicitly_adopted`).
    pub fn is_owned(self) -> bool {
        matches!(self, Self::Succeeded | Self::Adopted)
    }
}

/// Immutable admitted provision; built by the executor from verified inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvisionIntent {
    /// Operation identity.
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
    /// Site being created; unique for the journal's lifetime.
    pub site_id: SiteId,
    /// Hostname being reserved; unique for the journal's lifetime.
    pub hostname: Hostname,
    /// Normal grant deadline for starting the provision.
    pub expires_at: Timestamp,
}

/// One recorded step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StepRecord {
    /// Which step.
    pub step: ProvisionStep,
    /// Its state.
    pub state: StepState,
    /// Bounded description of the resource the step creates (for review).
    pub resource: String,
}

/// Stored provision with its steps.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Provision {
    /// Immutable admitted data.
    pub intent: ProvisionIntent,
    /// Current state.
    pub state: ProvisionState,
    /// Steps recorded so far, in order.
    pub steps: Vec<StepRecord>,
}

/// What a new provision's Recipe step holds.
#[derive(Clone, Copy)]
pub(crate) enum Origin<'a> {
    /// A recipe install.
    Recipe,
    /// An import with its signed dry-run facts (W442).
    Import(&'a crate::import::ImportFacts),
    /// A clone with its signed source facts (W498, D-078).
    Clone(&'a crate::site_clone::CloneFacts),
    /// A proxy site with its signed routes (W572, D-095).
    Proxy(&'a crate::proxy::ProxyFacts),
    /// A modern app site with its signed runtime facts, routes, and optional D-102 full-stack spec.
    App(
        &'a crate::app::AppFacts,
        Option<&'a crate::app::AppFullstackSpec>,
    ),
}

impl<'a> Origin<'a> {
    fn import(self) -> Option<&'a crate::import::ImportFacts> {
        match self {
            Self::Import(facts) => Some(facts),
            _ => None,
        }
    }

    fn clone_facts(self) -> Option<&'a crate::site_clone::CloneFacts> {
        match self {
            Self::Clone(facts) => Some(facts),
            _ => None,
        }
    }

    fn proxy(self) -> Option<&'a crate::proxy::ProxyFacts> {
        match self {
            Self::Proxy(facts) => Some(facts),
            Self::App(facts, _)
                if !facts.routes.routes.is_empty() || !facts.routes.websockets.is_empty() =>
            {
                Some(&facts.routes)
            }
            _ => None,
        }
    }

    fn app(
        self,
    ) -> Option<(
        &'a crate::app::AppFacts,
        Option<&'a crate::app::AppFullstackSpec>,
    )> {
        match self {
            Self::App(facts, spec) => Some((facts, spec)),
            _ => None,
        }
    }
}

impl FixtureJournal {
    /// Records a new provision in one transaction, or returns exact status.
    pub fn record_provision(
        &mut self,
        intent: &ProvisionIntent,
        now: Timestamp,
    ) -> Result<Admitted<Provision>, JournalError> {
        self.admit_provision(intent, Origin::Recipe, now)
    }

    /// Records a new provision, with the import facts of an import (W442),
    /// in one transaction, or returns the exact earlier status. A retry must
    /// match the intent and the import facts, or their absence.
    pub(crate) fn admit_provision(
        &mut self,
        intent: &ProvisionIntent,
        origin: Origin<'_>,
        now: Timestamp,
    ) -> Result<Admitted<Provision>, JournalError> {
        let import = origin.import();
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
        if let Some(existing) = by_key(&transaction, &intent.idempotency_key)? {
            let recorded = crate::import::facts(&transaction, &existing.intent.operation_id)?;
            let cloned = crate::site_clone::facts(&transaction, &existing.intent.operation_id)?;
            let routes = crate::proxy::facts(&transaction, &existing.intent.operation_id)?;
            let app = crate::app::facts(&transaction, &existing.intent.operation_id)?;
            let fullstack =
                crate::app::fullstack_spec(&transaction, &existing.intent.operation_id)?;
            let expected_app = origin.app().map(|(f, _)| f);
            let expected_fullstack = origin.app().and_then(|(_, s)| s);
            return if existing.intent == *intent
                && recorded.as_ref() == import
                && cloned.as_ref() == origin.clone_facts()
                && routes.as_ref() == origin.proxy()
                && app.as_ref() == expected_app
                && fullstack.as_ref() == expected_fullstack
            {
                Ok(Admitted::Existing(existing))
            } else {
                Err(JournalError::Conflict)
            };
        }
        if import.is_some() {
            // D-067: a scrubbed, quarantined import (even one scrubbed before
            // D-067) does not hold the hostname of a new import.
            crate::import::release_scrubbed_hostname(&transaction, &intent.hostname)?;
        }
        let taken: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM provisions WHERE site_id=?1 OR hostname=?2)",
                params![intent.site_id.as_str(), intent.hostname.as_str()],
                |row| row.get(0),
            )
            .map_err(storage::unavailable)?;
        if storage::consumed_ids(
            &transaction,
            &intent.operation_id,
            &intent.grant_id,
            &intent.nonce,
        )? {
            return Err(JournalError::Conflict);
        }
        if taken || crate::import::alias_taken(&transaction, &intent.hostname)? {
            return Err(JournalError::Consumed);
        }
        if let Some((facts, spec)) = origin.app() {
            let ports = match spec {
                Some(fs) => fs.all_ports(facts),
                None if facts.port > 0 => vec![facts.port],
                None => Vec::new(),
            };
            if crate::app::ports_taken(&transaction, &ports)? {
                return Err(JournalError::Consumed);
            }
        }
        // D-078: the reservation and the source recheck commit together.
        if let Some(facts) = origin.clone_facts()
            && !crate::site_clone::source_holds(&transaction, facts)?
        {
            return Err(JournalError::SourceChanged);
        }
        if let Some((facts, alias)) =
            import.and_then(|facts| facts.alias_hostname.as_ref().map(|alias| (facts, alias)))
        {
            if !facts.is_static() || facts.source_hostname.is_some() || alias == &intent.hostname {
                return Err(JournalError::Conflict);
            }
            let primary_taken: bool = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM provisions WHERE hostname=?1)",
                    [alias.as_str()],
                    |row| row.get(0),
                )
                .map_err(storage::unavailable)?;
            if primary_taken || crate::import::alias_taken(&transaction, alias)? {
                return Err(JournalError::Consumed);
            }
        }
        storage::check_clock(&transaction, now)?;
        if now.get() >= intent.expires_at.get() {
            return Err(JournalError::Expired);
        }
        let (running, count): (bool, i64) = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM provisions WHERE state='running'), count(*) FROM provisions",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(storage::unavailable)?;
        if running || storage::readoption_verifying(&transaction)? {
            return Err(JournalError::Busy);
        }
        if count >= MAX_PROVISIONS {
            return Err(JournalError::Capacity);
        }
        transaction
            .execute(
                "INSERT INTO provisions VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,'running')",
                params![
                    intent.operation_id.as_str(),
                    intent.idempotency_key.as_str(),
                    intent.grant_id.as_str(),
                    intent.nonce.as_str(),
                    intent.plan_digest.as_str(),
                    intent.grant_digest.as_str(),
                    intent.host_id.as_str(),
                    intent.host_epoch.as_str(),
                    intent.site_id.as_str(),
                    intent.hostname.as_str(),
                    intent.expires_at.get() as i64
                ],
            )
            .map_err(storage::unavailable)?;
        if let Some(facts) = import {
            crate::import::insert(&transaction, &intent.operation_id, facts)?;
        }
        if let Some(facts) = origin.clone_facts() {
            crate::site_clone::insert(&transaction, &intent.operation_id, facts)?;
        }
        if let Some((facts, spec)) = origin.app() {
            crate::app::insert(&transaction, &intent.operation_id, facts, spec)?;
        } else if let Some(facts) = origin.proxy() {
            crate::proxy::insert(&transaction, &intent.operation_id, facts)?;
        }
        crate::signed::insert(&transaction, &intent.operation_id, signed.as_ref())?;
        storage::set_clock(&transaction, now)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(Admitted::New(Provision {
            intent: intent.clone(),
            state: ProvisionState::Running,
            steps: Vec::new(),
        }))
    }

    /// Commits a step's intent before its effect. The previous steps must all
    /// be done and this step must not have been recorded before.
    pub fn begin_step(
        &mut self,
        operation_id: &Id,
        step: ProvisionStep,
        resource: &str,
    ) -> Result<Provision, JournalError> {
        if resource.is_empty()
            || resource.len() > MAX_RESOURCE
            || !resource.bytes().all(|byte| (0x20..0x7f).contains(&byte))
        {
            return Err(JournalError::Conflict);
        }
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let provision = by_operation(&transaction, operation_id)?.ok_or(JournalError::Conflict)?;
        if provision.state != ProvisionState::Running
            || provision.steps.len() as i64 != step.position()
            || provision
                .steps
                .iter()
                .any(|record| record.state != StepState::Done)
        {
            return Err(JournalError::Conflict);
        }
        transaction
            .execute(
                "INSERT INTO provision_steps VALUES(?1,?2,'intent',?3)",
                params![operation_id.as_str(), step.position(), resource],
            )
            .map_err(storage::unavailable)?;
        transaction.commit().map_err(storage::unavailable)?;
        self.provision_status(operation_id)?
            .ok_or(JournalError::Unavailable)
    }

    /// Records a step's observed outcome. A failure quarantines the provision.
    pub fn finish_step(
        &mut self,
        operation_id: &Id,
        step: ProvisionStep,
        done: bool,
    ) -> Result<Provision, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let provision = by_operation(&transaction, operation_id)?.ok_or(JournalError::Conflict)?;
        let last = provision.steps.last().ok_or(JournalError::Conflict)?;
        if provision.state != ProvisionState::Running
            || last.step != step
            || last.state != StepState::Intent
        {
            return Err(JournalError::Conflict);
        }
        // W442: an import's Recipe step is done only with every import step
        // done; W498: a clone's, with every clone step done.
        if done
            && step == ProvisionStep::Recipe
            && !(crate::import::complete_or_absent(&transaction, operation_id)?
                && crate::site_clone::complete_or_absent(&transaction, operation_id)?)
        {
            return Err(JournalError::Conflict);
        }
        transaction
            .execute(
                "UPDATE provision_steps SET state=?1 WHERE operation_id=?2 AND position=?3",
                params![
                    if done { "done" } else { "failed" },
                    operation_id.as_str(),
                    step.position()
                ],
            )
            .map_err(storage::unavailable)?;
        if !done {
            set_state(&transaction, operation_id, ProvisionState::Quarantined)?;
        } else if step == ProvisionStep::Verify {
            set_state(&transaction, operation_id, ProvisionState::Succeeded)?;
        }
        transaction.commit().map_err(storage::unavailable)?;
        self.provision_status(operation_id)?
            .ok_or(JournalError::Unavailable)
    }

    /// Stops a running provision without inferring any step's outcome (for
    /// example after a restart with a step still in `Intent`).
    pub fn quarantine_provision(&mut self, operation_id: &Id) -> Result<Provision, JournalError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        let provision = by_operation(&transaction, operation_id)?.ok_or(JournalError::Conflict)?;
        if provision.state == ProvisionState::Running {
            set_state(&transaction, operation_id, ProvisionState::Quarantined)?;
        }
        transaction.commit().map_err(storage::unavailable)?;
        self.provision_status(operation_id)?
            .ok_or(JournalError::Unavailable)
    }

    /// The provision recorded for a site id, if any.
    pub fn provision_for_site(&self, site: &SiteId) -> Result<Option<Provision>, JournalError> {
        by_site(&self.connection, site)
    }

    /// Recorded status only.
    pub fn provision_status(&self, operation_id: &Id) -> Result<Option<Provision>, JournalError> {
        by_operation(&self.connection, operation_id)
    }

    /// Every resource ever recorded for `step`, in any provision state, so an
    /// allocation is never reused for the journal's lifetime.
    pub fn recorded_resources(&self, step: ProvisionStep) -> Result<Vec<String>, JournalError> {
        let mut query = self
            .connection
            .prepare("SELECT resource FROM provision_steps WHERE position=?1")
            .map_err(storage::unavailable)?;
        let rows = query
            .query_map([step.position()], |row| row.get::<_, String>(0))
            .map_err(storage::unavailable)?;
        rows.collect::<Result<_, _>>().map_err(storage::unavailable)
    }
}

pub(crate) fn set_state(
    c: &rusqlite::Connection,
    operation_id: &Id,
    state: ProvisionState,
) -> Result<(), JournalError> {
    let text = match state {
        ProvisionState::Running => "running",
        ProvisionState::Succeeded => "succeeded",
        ProvisionState::Quarantined => "quarantined",
        ProvisionState::Adopted => "adopted",
        ProvisionState::Deleted => "deleted",
    };
    c.execute(
        "UPDATE provisions SET state=?1 WHERE operation_id=?2",
        params![text, operation_id.as_str()],
    )
    .map_err(storage::unavailable)?;
    Ok(())
}

fn decode_row(row: &Row<'_>) -> rusqlite::Result<(ProvisionIntent, ProvisionState)> {
    let bad = || rusqlite::Error::InvalidQuery;
    let id = |i| Id::try_from(row.get::<_, String>(i)?).map_err(|_| bad());
    let digest = |i| Sha256Digest::try_from(row.get::<_, String>(i)?).map_err(|_| bad());
    let state = match row.get::<_, String>(11)?.as_str() {
        "running" => ProvisionState::Running,
        "succeeded" => ProvisionState::Succeeded,
        "quarantined" => ProvisionState::Quarantined,
        "adopted" => ProvisionState::Adopted,
        "deleted" => ProvisionState::Deleted,
        _ => return Err(bad()),
    };
    Ok((
        ProvisionIntent {
            operation_id: id(0)?,
            idempotency_key: id(1)?,
            grant_id: id(2)?,
            nonce: id(3)?,
            plan_digest: digest(4)?,
            grant_digest: digest(5)?,
            host_id: id(6)?,
            host_epoch: id(7)?,
            site_id: SiteId::try_from(row.get::<_, String>(8)?).map_err(|_| bad())?,
            hostname: Hostname::try_from(row.get::<_, String>(9)?).map_err(|_| bad())?,
            expires_at: u64::try_from(row.get::<_, i64>(10)?)
                .ok()
                .and_then(|time| Timestamp::try_from(time).ok())
                .ok_or_else(bad)?,
        },
        state,
    ))
}

fn steps(c: &rusqlite::Connection, operation_id: &Id) -> Result<Vec<StepRecord>, JournalError> {
    let mut query = c
        .prepare("SELECT position, state, resource FROM provision_steps WHERE operation_id=?1 ORDER BY position")
        .map_err(storage::unavailable)?;
    let rows = query
        .query_map([operation_id.as_str()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(storage::unavailable)?;
    let mut records = Vec::new();
    for (expected, row) in rows.enumerate() {
        let (position, state, resource) = row.map_err(storage::unavailable)?;
        let step = *ProvisionStep::ALL
            .get(expected)
            .filter(|_| position == expected as i64)
            .ok_or(JournalError::Unavailable)?;
        let state = match state.as_str() {
            "intent" => StepState::Intent,
            "done" => StepState::Done,
            "failed" => StepState::Failed,
            _ => return Err(JournalError::Unavailable),
        };
        records.push(StepRecord {
            step,
            state,
            resource,
        });
    }
    Ok(records)
}

fn load(
    c: &rusqlite::Connection,
    found: Option<(ProvisionIntent, ProvisionState)>,
) -> Result<Option<Provision>, JournalError> {
    let Some((intent, state)) = found else {
        return Ok(None);
    };
    let steps = steps(c, &intent.operation_id)?;
    Ok(Some(Provision {
        intent,
        state,
        steps,
    }))
}

fn by_key(c: &rusqlite::Connection, key: &Id) -> Result<Option<Provision>, JournalError> {
    let found = c
        .query_row(
            "SELECT * FROM provisions WHERE idempotency_key=?1",
            [key.as_str()],
            decode_row,
        )
        .optional()
        .map_err(storage::unavailable)?;
    load(c, found)
}

fn site_ids(c: &rusqlite::Connection, sql: &str) -> Result<Vec<SiteId>, JournalError> {
    let mut query = c.prepare(sql).map_err(storage::unavailable)?;
    let rows = query
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(storage::unavailable)?;
    rows.map(|row| {
        SiteId::try_from(row.map_err(storage::unavailable)?).map_err(storage::unavailable)
    })
    .collect()
}

/// Sites whose ejection succeeded, sorted by site id.
pub(crate) fn ejected(c: &rusqlite::Connection) -> Result<Vec<SiteId>, JournalError> {
    site_ids(
        c,
        "SELECT e.site_id FROM ejections e JOIN operations o ON o.operation_id=e.operation_id WHERE o.state='succeeded' ORDER BY e.site_id",
    )
}

/// Sites whose single-name static ejection succeeded (D-097), sorted by site id.
pub(crate) fn static_ejected(c: &rusqlite::Connection) -> Result<Vec<SiteId>, JournalError> {
    site_ids(
        c,
        "SELECT e.site_id FROM static_ejections s JOIN ejections e ON e.operation_id=s.operation_id JOIN operations o ON o.operation_id=e.operation_id WHERE o.state='succeeded' ORDER BY e.site_id",
    )
}

/// The recorded single-name static hostname for `operation_id`, if any (D-097).
pub(crate) fn static_ejection_of(
    c: &rusqlite::Connection,
    operation_id: &Id,
) -> Result<Option<Hostname>, JournalError> {
    c.query_row(
        "SELECT hostname FROM static_ejections WHERE operation_id=?1",
        [operation_id.as_str()],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(storage::unavailable)?
    .map(|text| Hostname::try_from(text).map_err(storage::unavailable))
    .transpose()
}

/// Every owned provision (succeeded or adopted, W372), sorted by site id.
pub(crate) fn succeeded(c: &rusqlite::Connection) -> Result<Vec<Provision>, JournalError> {
    site_ids(
        c,
        "SELECT site_id FROM provisions WHERE state IN ('succeeded','adopted') ORDER BY site_id",
    )?
    .iter()
    .filter_map(|site| by_site(c, site).transpose())
    .collect()
}

pub(crate) fn by_site(
    c: &rusqlite::Connection,
    site: &SiteId,
) -> Result<Option<Provision>, JournalError> {
    let found = c
        .query_row(
            "SELECT * FROM provisions WHERE site_id=?1",
            [site.as_str()],
            decode_row,
        )
        .optional()
        .map_err(storage::unavailable)?;
    load(c, found)
}

pub(crate) fn by_operation(
    c: &rusqlite::Connection,
    id: &Id,
) -> Result<Option<Provision>, JournalError> {
    let found = c
        .query_row(
            "SELECT * FROM provisions WHERE operation_id=?1",
            [id.as_str()],
            decode_row,
        )
        .optional()
        .map_err(storage::unavailable)?;
    load(c, found)
}

impl FixtureJournal {
    /// Records an ejection's OLS intent and binds it to `site` in one
    /// transaction. The site needs an owned provision and no ejection that
    /// succeeded or is unresolved. An exact repeat returns status only.
    pub fn record_ejection_intent(
        &mut self,
        intent: &crate::Intent,
        site: &SiteId,
        now: Timestamp,
    ) -> Result<crate::Admitted<crate::Operation>, JournalError> {
        self.record_ejection(intent, site, None, now)
    }

    /// Records a single-name static ejection and its exact hostname in the
    /// intent transaction. Only completed static imports without an alias
    /// are eligible. An exact repeat returns status only.
    pub fn record_static_ejection_intent(
        &mut self,
        intent: &crate::Intent,
        site: &SiteId,
        hostname: &Hostname,
        now: Timestamp,
    ) -> Result<crate::Admitted<crate::Operation>, JournalError> {
        self.record_ejection(intent, site, Some(hostname), now)
    }

    fn record_ejection(
        &mut self,
        intent: &crate::Intent,
        site: &SiteId,
        static_hostname: Option<&Hostname>,
        now: Timestamp,
    ) -> Result<crate::Admitted<crate::Operation>, JournalError> {
        if let Some(existing) = self.existing(intent)? {
            if self.ejection_site(&intent.operation_id)?.as_ref() != Some(site)
                || self
                    .static_ejection_hostname(&intent.operation_id)?
                    .as_ref()
                    != static_hostname
            {
                return Err(JournalError::Conflict);
            }
            return Ok(crate::Admitted::Existing(existing));
        }
        if !self
            .provision_for_site(site)?
            .is_some_and(|p| p.state.is_owned())
            || self.ejection_blocks(site)?
        {
            return Err(JournalError::Conflict);
        }
        self.record_intent_with(intent, now, |transaction| {
            let operation = intent.operation_id.as_str();
            transaction
                .execute(
                    "INSERT INTO ejections VALUES(?1,?2)",
                    params![operation, site.as_str()],
                )
                .map_err(storage::unavailable)?;
            if let Some(hostname) = static_hostname {
                let provision = by_site(transaction, site)?.ok_or(JournalError::Conflict)?;
                if provision.state != ProvisionState::Succeeded
                    || !static_ejection_matches(transaction, &provision, hostname)?
                {
                    return Err(JournalError::Conflict);
                }
                transaction
                    .execute(
                        "INSERT INTO static_ejections VALUES(?1,?2)",
                        params![operation, hostname.as_str()],
                    )
                    .map_err(storage::unavailable)?;
            }
            Ok(())
        })
    }

    /// Owned provisions (succeeded or adopted, W372), sorted by site id. A
    /// running or quarantined row is omitted.
    pub fn succeeded_sites(&self) -> Result<Vec<SiteId>, JournalError> {
        site_ids(
            &self.connection,
            "SELECT site_id FROM provisions WHERE state IN ('succeeded','adopted') ORDER BY site_id",
        )
    }

    /// Sites whose ejection succeeded, sorted by site id.
    pub fn ejected_sites(&self) -> Result<Vec<SiteId>, JournalError> {
        ejected(&self.connection)
    }

    /// Sites whose single-name static ejection succeeded (D-097), sorted by site id.
    pub fn static_ejected_sites(&self) -> Result<Vec<SiteId>, JournalError> {
        static_ejected(&self.connection)
    }

    /// The site an operation ejects, if it is an ejection.
    pub fn ejection_site(&self, operation_id: &Id) -> Result<Option<SiteId>, JournalError> {
        self.connection
            .query_row(
                "SELECT site_id FROM ejections WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(storage::unavailable)?
            .map(|text| SiteId::try_from(text).map_err(storage::unavailable))
            .transpose()
    }

    /// The exact hostname recorded for a single-name static ejection.
    pub fn static_ejection_hostname(
        &self,
        operation_id: &Id,
    ) -> Result<Option<Hostname>, JournalError> {
        static_ejection_of(&self.connection, operation_id)
    }

    fn ejection_blocks(&self, site: &SiteId) -> Result<bool, JournalError> {
        self.connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM ejections e JOIN operations o ON o.operation_id=e.operation_id WHERE e.site_id=?1 AND o.state IN ('succeeded','intent','needs_attention','compensating'))",
                [site.as_str()],
                |row| row.get(0),
            )
            .map_err(storage::unavailable)
    }
}

/// The page-cache recipe the v15 and v16 tables admit (W368). Every
/// opt-in and opt-out row names it.
const PAGE_CACHE_RECIPE: &str = "litespeed_cache_793_v1";
/// W395 (v19, D-044): the cache-on recipe. It uses the same pinned plugin,
/// so its opt-in or opt-out row names [`PAGE_CACHE_RECIPE`]; one
/// `page_cache_recipes` row in the same transaction names this recipe.
const CACHE_ON_RECIPE: &str = "litespeed_cache_793_cache_on_v1";

/// The journal name of a recorded recipe column (`None`: the W368 recipe).
fn recipe_name(side: Option<String>) -> Result<&'static str, JournalError> {
    match side.as_deref() {
        None => Ok(PAGE_CACHE_RECIPE),
        Some(CACHE_ON_RECIPE) => Ok(CACHE_ON_RECIPE),
        Some(_) => Err(JournalError::Unavailable),
    }
}

/// Every page-cache change (opt-in and opt-out) with its recipe row, if any.
const CHANGES_WITH_RECIPE: &str = "SELECT x.operation_id, x.site_id, x.opt_in, r.recipe FROM (SELECT operation_id, site_id, 1 AS opt_in FROM page_cache_optins UNION ALL SELECT operation_id, site_id, 0 FROM page_cache_optouts) x \
     LEFT JOIN page_cache_recipes r ON r.operation_id=x.operation_id";

/// Every succeeded page-cache change in journal order (W370): the site,
/// whether it opted in (`true`) or out, and its recipe (W395).
fn page_cache_history(
    c: &rusqlite::Connection,
) -> Result<Vec<(SiteId, bool, &'static str)>, JournalError> {
    let mut query = c
        .prepare(&format!(
            "SELECT y.site_id, y.opt_in, y.recipe FROM ({CHANGES_WITH_RECIPE}) y \
             JOIN operations o ON o.operation_id=y.operation_id WHERE o.state='succeeded' ORDER BY o.rowid"
        ))
        .map_err(storage::unavailable)?;
    let rows = query
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, bool>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })
        .map_err(storage::unavailable)?;
    rows.map(|row| {
        let (site, opt_in, recipe) = row.map_err(storage::unavailable)?;
        Ok((
            SiteId::try_from(site).map_err(storage::unavailable)?,
            opt_in,
            recipe_name(recipe)?,
        ))
    })
    .collect()
}

/// W395: the recipe of `site`'s opt-in while the site is opted in.
pub(crate) fn page_cache_site_recipe(
    c: &rusqlite::Connection,
    site: &SiteId,
) -> Result<Option<&'static str>, JournalError> {
    Ok(page_cache_history(c)?
        .into_iter()
        .rfind(|(changed, _, _)| changed == site)
        .and_then(|(_, opt_in, recipe)| opt_in.then_some(recipe)))
}

/// W395: the recipe of a page-cache operation, if it is one.
pub(crate) fn page_cache_recipe(
    c: &rusqlite::Connection,
    operation_id: &Id,
) -> Result<Option<&'static str>, JournalError> {
    c.query_row(
        &format!("SELECT y.recipe FROM ({CHANGES_WITH_RECIPE}) y WHERE y.operation_id=?1"),
        [operation_id.as_str()],
        |row| row.get::<_, Option<String>>(0),
    )
    .optional()
    .map_err(storage::unavailable)?
    .map(recipe_name)
    .transpose()
}

/// W395: adds the recipe row of a change that does not use the W368 recipe.
fn record_recipe(
    transaction: &rusqlite::Transaction<'_>,
    operation: &Id,
    recipe: &str,
) -> Result<(), JournalError> {
    if recipe == PAGE_CACHE_RECIPE {
        return Ok(());
    }
    transaction
        .execute(
            "INSERT INTO page_cache_recipes VALUES(?1,?2)",
            params![operation.as_str(), recipe],
        )
        .map(drop)
        .map_err(storage::unavailable)
}

/// Sites whose latest succeeded page-cache change is an opt-in, sorted by
/// site id (W368; W370 adds the opt-out and the re-enable).
pub(crate) fn page_cache(c: &rusqlite::Connection) -> Result<Vec<SiteId>, JournalError> {
    let mut latest = std::collections::BTreeMap::new();
    for (site, opt_in, _) in page_cache_history(c)? {
        latest.insert(site.as_str().to_owned(), (site, opt_in));
    }
    Ok(latest
        .into_values()
        .filter_map(|(site, opt_in)| opt_in.then_some(site))
        .collect())
}

/// The site a page-cache opt-out operation names, if it is one (W370).
pub(crate) fn page_cache_opt_out_site(
    c: &rusqlite::Connection,
    operation_id: &Id,
) -> Result<Option<SiteId>, JournalError> {
    c.query_row(
        "SELECT site_id FROM page_cache_optouts WHERE operation_id=?1",
        [operation_id.as_str()],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(storage::unavailable)?
    .map(|text| SiteId::try_from(text).map_err(storage::unavailable))
    .transpose()
}

/// The site a page-cache opt-in operation names, if it is one.
pub(crate) fn page_cache_site(
    c: &rusqlite::Connection,
    operation_id: &Id,
) -> Result<Option<SiteId>, JournalError> {
    c.query_row(
        "SELECT site_id FROM page_cache_optins WHERE operation_id=?1",
        [operation_id.as_str()],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(storage::unavailable)?
    .map(|text| SiteId::try_from(text).map_err(storage::unavailable))
    .transpose()
}

impl FixtureJournal {
    /// W368: records a `config_activate` v2 intent and binds it to its
    /// page-cache opt-in `site` and `recipe` in one transaction. The site
    /// needs a succeeded provision, must not be opted in, and must have no
    /// unresolved page-cache change. W370: a site whose opt-out succeeded
    /// may opt in again. W395: `recipe` is the W368 recipe or the cache-on
    /// recipe; the cache-on recipe adds its recipe row in the same
    /// transaction. An exact repeat returns status only.
    pub fn record_page_cache_intent(
        &mut self,
        intent: &crate::Intent,
        site: &SiteId,
        recipe: &str,
        now: Timestamp,
    ) -> Result<crate::Admitted<crate::Operation>, JournalError> {
        if let Some(existing) = self.existing(intent)? {
            return Ok(crate::Admitted::Existing(existing));
        }
        if ![PAGE_CACHE_RECIPE, CACHE_ON_RECIPE].contains(&recipe)
            || !self
                .provision_for_site(site)?
                .is_some_and(|p| p.state.is_owned())
            || self.page_cache_unresolved(site)?
            || self.page_cache_sites()?.contains(site)
        {
            return Err(JournalError::Conflict);
        }
        let operation = intent.operation_id.clone();
        self.record_intent_with(intent, now, |transaction| {
            transaction
                .execute(
                    "INSERT INTO page_cache_optins VALUES(?1,?2,?3)",
                    params![operation.as_str(), site.as_str(), PAGE_CACHE_RECIPE],
                )
                .map_err(storage::unavailable)?;
            record_recipe(transaction, &operation, recipe)
        })
    }

    /// W370: records a `config_activate` v3 intent and binds it to its
    /// page-cache opt-out `site` and `recipe` in one transaction. The site
    /// must be opted in with `recipe` (W395: the recipe of its opt-in) and
    /// have no unresolved page-cache change. An exact repeat returns status
    /// only.
    pub fn record_page_cache_opt_out_intent(
        &mut self,
        intent: &crate::Intent,
        site: &SiteId,
        recipe: &str,
        now: Timestamp,
    ) -> Result<crate::Admitted<crate::Operation>, JournalError> {
        if let Some(existing) = self.existing(intent)? {
            return Ok(crate::Admitted::Existing(existing));
        }
        if !self
            .provision_for_site(site)?
            .is_some_and(|p| p.state.is_owned())
            || self.page_cache_unresolved(site)?
            || self.page_cache_site_recipe(site)? != Some(recipe)
        {
            return Err(JournalError::Conflict);
        }
        let operation = intent.operation_id.clone();
        self.record_intent_with(intent, now, |transaction| {
            transaction
                .execute(
                    "INSERT INTO page_cache_optouts VALUES(?1,?2,?3)",
                    params![operation.as_str(), site.as_str(), PAGE_CACHE_RECIPE],
                )
                .map_err(storage::unavailable)?;
            record_recipe(transaction, &operation, recipe)
        })
    }

    /// Sites that are opted in to the page cache: their latest succeeded
    /// page-cache change is an opt-in. Sorted by site id.
    pub fn page_cache_sites(&self) -> Result<Vec<SiteId>, JournalError> {
        page_cache(&self.connection)
    }

    /// W395: the recipe of `site`'s opt-in while the site is opted in.
    pub fn page_cache_site_recipe(
        &self,
        site: &SiteId,
    ) -> Result<Option<&'static str>, JournalError> {
        page_cache_site_recipe(&self.connection, site)
    }

    /// The site an operation opts in to the page cache, if it is an opt-in.
    pub fn page_cache_site(&self, operation_id: &Id) -> Result<Option<SiteId>, JournalError> {
        page_cache_site(&self.connection, operation_id)
    }

    /// The site an operation opts out of the page cache, if it is an
    /// opt-out (W370).
    pub fn page_cache_opt_out_site(
        &self,
        operation_id: &Id,
    ) -> Result<Option<SiteId>, JournalError> {
        page_cache_opt_out_site(&self.connection, operation_id)
    }

    /// Whether `site` has a page-cache opt-in or opt-out that is not yet
    /// resolved.
    fn page_cache_unresolved(&self, site: &SiteId) -> Result<bool, JournalError> {
        self.connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM (SELECT operation_id, site_id FROM page_cache_optins UNION ALL SELECT operation_id, site_id FROM page_cache_optouts) p JOIN operations o ON o.operation_id=p.operation_id WHERE p.site_id=?1 AND o.state IN ('intent','needs_attention','compensating'))",
                [site.as_str()],
                |row| row.get(0),
            )
            .map_err(storage::unavailable)
    }
}

/// Every opt-in and opt-out names an existing operation and an owned
/// provision (W372: succeeded or adopted), no operation is both, and each site's succeeded changes
/// alternate, starting with an opt-in (W368, W370). W395: every recipe row
/// belongs to an opt-in or an opt-out, and an opt-out has the recipe of the
/// opt-in before it.
pub(crate) fn validate_page_cache(c: &rusqlite::Connection) -> Result<(), JournalError> {
    let broken: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM (SELECT operation_id, site_id FROM page_cache_optins UNION ALL SELECT operation_id, site_id FROM page_cache_optouts) x LEFT JOIN operations o ON o.operation_id=x.operation_id LEFT JOIN provisions p ON p.site_id=x.site_id WHERE o.operation_id IS NULL OR p.state IS NULL OR p.state NOT IN ('succeeded','adopted','deleted')) \
             OR EXISTS(SELECT 1 FROM page_cache_optins i JOIN page_cache_optouts u ON u.operation_id=i.operation_id) \
             OR EXISTS(SELECT 1 FROM page_cache_recipes r WHERE r.operation_id NOT IN (SELECT operation_id FROM page_cache_optins UNION ALL SELECT operation_id FROM page_cache_optouts))",
            [],
            |row| row.get(0),
        )
        .map_err(storage::unavailable)?;
    let mut opted_in = std::collections::BTreeMap::new();
    for (site, opt_in, recipe) in page_cache_history(c)? {
        let before = opted_in.insert(site.as_str().to_owned(), (opt_in, recipe));
        let (was_in, was_recipe) = before.unwrap_or((false, recipe));
        // W395: an opt-out names the recipe of the opt-in before it.
        if was_in == opt_in || (!opt_in && was_recipe != recipe) {
            return Err(JournalError::Unavailable);
        }
    }
    if broken {
        return Err(JournalError::Unavailable);
    }
    Ok(())
}

fn static_ejection_matches(
    c: &Connection,
    provision: &Provision,
    hostname: &Hostname,
) -> Result<bool, JournalError> {
    let operation = &provision.intent.operation_id;
    Ok(&provision.intent.hostname == hostname
        && crate::import::load(c, operation)?.is_some_and(|import| {
            import.facts.is_static()
                && import.facts.source_hostname.is_none()
                && import.facts.alias_hostname.is_none()
                && import.is_complete()
        })
        && crate::proxy::facts(c, operation)?.is_none())
}

/// Every ejection names an existing operation and provision, and no site
/// has more than one succeeded ejection. Static records also bind the exact
/// name and import provenance.
pub(crate) fn validate_ejections(c: &Connection) -> Result<(), JournalError> {
    let broken: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM ejections e LEFT JOIN operations o ON o.operation_id=e.operation_id LEFT JOIN provisions p ON p.site_id=e.site_id WHERE o.operation_id IS NULL OR p.state IS NULL OR p.state NOT IN ('succeeded','adopted','deleted')) \
             OR EXISTS(SELECT 1 FROM ejections e JOIN operations o ON o.operation_id=e.operation_id WHERE o.state='succeeded' GROUP BY e.site_id HAVING count(*)>1)",
            [],
            |row| row.get(0),
        )
        .map_err(storage::unavailable)?;
    if broken {
        return Err(JournalError::Unavailable);
    }
    let mut query = c
        .prepare("SELECT e.site_id, s.hostname FROM static_ejections s LEFT JOIN ejections e USING(operation_id)")
        .map_err(storage::unavailable)?;
    let mut rows = query.query([]).map_err(storage::unavailable)?;
    while let Some(row) = rows.next().map_err(storage::unavailable)? {
        let site = SiteId::try_from(row.get::<_, String>(0).map_err(storage::unavailable)?)
            .map_err(storage::unavailable)?;
        let hostname = Hostname::try_from(row.get::<_, String>(1).map_err(storage::unavailable)?)
            .map_err(storage::unavailable)?;
        let provision = by_site(c, &site)?.ok_or(JournalError::Unavailable)?;
        if !matches!(
            provision.state,
            ProvisionState::Succeeded | ProvisionState::Deleted
        ) || !static_ejection_matches(c, &provision, &hostname)?
        {
            return Err(JournalError::Unavailable);
        }
    }
    Ok(())
}

/// Opening refuses provisions whose rows contradict the step rules.
pub(crate) fn validate(
    c: &rusqlite::Connection,
    host: &Id,
    epoch: &Id,
) -> Result<(), JournalError> {
    let mut query = c
        .prepare("SELECT * FROM provisions LIMIT ?1")
        .map_err(storage::unavailable)?;
    let rows: Vec<_> = query
        .query_map([MAX_PROVISIONS + 1], decode_row)
        .map_err(storage::unavailable)?
        .collect::<Result<_, _>>()
        .map_err(storage::unavailable)?;
    if rows.len() as i64 > MAX_PROVISIONS
        || rows
            .iter()
            .filter(|(_, state)| *state == ProvisionState::Running)
            .count()
            > 1
    {
        return Err(JournalError::Unavailable);
    }
    for (intent, state) in rows {
        if &intent.host_id != host || &intent.host_epoch != epoch {
            return Err(JournalError::Unavailable);
        }
        let steps = steps(c, &intent.operation_id)?;
        let done = steps.iter().filter(|s| s.state == StepState::Done).count();
        let consistent = match state {
            // D-085: only a succeeded provision is deleted.
            ProvisionState::Succeeded | ProvisionState::Deleted => done == ProvisionStep::ALL.len(),
            ProvisionState::Running => {
                steps.iter().all(|s| s.state != StepState::Failed)
                    && done + 1 >= steps.len()
                    && steps[..done].iter().all(|s| s.state == StepState::Done)
            }
            ProvisionState::Quarantined => steps[..done].iter().all(|s| s.state == StepState::Done),
            // W372: recorded by a re-adoption, never by steps.
            ProvisionState::Adopted => steps.is_empty(),
        };
        if !consistent {
            return Err(JournalError::Unavailable);
        }
    }
    let orphans: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM provision_steps WHERE operation_id NOT IN (SELECT operation_id FROM provisions))",
            [],
            |row| row.get(0),
        )
        .map_err(storage::unavailable)?;
    if orphans {
        return Err(JournalError::Unavailable);
    }
    Ok(())
}
