//! Site certificates (schema v23, W462, D-059) and their renewals (v24,
//! W464, D-060). D-077 (v28) records the exact second name, when signed.
//!
//! A signed `certificate_issue` is one admission for one managed site. Its
//! row is `intent` until the admin helper's issuance is observed, then
//! `installed` with the SHA-256 of the installed chain and its expiry, or
//! `failed`. Nothing here reads the host or the CA.

use rusqlite::{OptionalExtension, params};
use rustiron_contracts::{
    Id, Timestamp,
    approval::{Hostname, Sha256Digest, SiteId},
};

use crate::{Admitted, FixtureJournal, JournalError, ProvisionState, provision, storage};

/// An admitted certificate issuance; built by the executor from verified
/// inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateIntent {
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
    /// The managed site.
    pub site_id: SiteId,
    /// Its recorded primary hostname.
    pub hostname: Hostname,
    /// D-077: the second exact DNS name, if included in the signed scope.
    pub alias_hostname: Option<Hostname>,
    /// Normal grant deadline.
    pub expires_at: Timestamp,
    /// D-060: the signed end of standing renewal; `None` grants none.
    pub renew_until: Option<Timestamp>,
}

/// Where an issuance stands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateState {
    /// Admitted; the outcome is not observed yet.
    Intent,
    /// Issued, checked, and installed.
    Installed,
    /// Stopped; nothing new is served.
    Failed,
}

/// One recorded issuance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Certificate {
    /// The admitted intent.
    pub intent: CertificateIntent,
    /// Its state.
    pub state: CertificateState,
    /// For `installed`: the installed chain's SHA-256 and its expiry.
    pub installed: Option<(Sha256Digest, Timestamp)>,
}

const COLUMNS: &str = "operation_id, idempotency_key, grant_id, nonce, plan_digest, grant_digest, site_id, hostname, expires_at, state, certificate_sha256, not_after";

fn read(
    c: &rusqlite::Connection,
    host: (&Id, &Id),
    filter: &str,
    value: &str,
) -> Result<Option<Certificate>, JournalError> {
    let row = c
        .query_row(
            &format!(
                "SELECT {COLUMNS} FROM certificates WHERE {filter}=?1 ORDER BY rowid DESC LIMIT 1"
            ),
            [value],
            |row| {
                Ok((
                    [0, 1, 2, 3, 4, 5, 6, 7].map(|index| row.get::<_, String>(index)),
                    row.get::<_, i64>(8),
                    row.get::<_, String>(9),
                    row.get::<_, Option<String>>(10),
                    row.get::<_, Option<i64>>(11),
                ))
            },
        )
        .optional()
        .map_err(storage::unavailable)?;
    let Some((texts, expires_at, state, sha, not_after)) = row else {
        return Ok(None);
    };
    let u = |_| JournalError::Unavailable;
    let texts: Vec<String> = texts.into_iter().collect::<Result<_, _>>().map_err(u)?;
    let id = |text: &String| Id::try_from(text.clone()).map_err(|_| JournalError::Unavailable);
    let digest =
        |text: &String| Sha256Digest::try_from(text.clone()).map_err(|_| JournalError::Unavailable);
    let time = |value: i64| {
        u64::try_from(value)
            .ok()
            .and_then(|value| Timestamp::try_from(value).ok())
            .ok_or(JournalError::Unavailable)
    };
    let state = match state.map_err(u)?.as_str() {
        "intent" => CertificateState::Intent,
        "installed" => CertificateState::Installed,
        "failed" => CertificateState::Failed,
        _ => return Err(JournalError::Unavailable),
    };
    let installed = match (sha.map_err(u)?, not_after.map_err(u)?) {
        (Some(sha), Some(not_after)) => Some((digest(&sha)?, time(not_after)?)),
        (None, None) => None,
        _ => return Err(JournalError::Unavailable),
    };
    let renew_until: Option<i64> = c
        .query_row(
            "SELECT renew_until FROM certificate_grants WHERE operation_id=?1",
            [texts[0].as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage::unavailable)?;
    Ok(Some(Certificate {
        intent: CertificateIntent {
            operation_id: id(&texts[0])?,
            idempotency_key: id(&texts[1])?,
            grant_id: id(&texts[2])?,
            nonce: id(&texts[3])?,
            plan_digest: digest(&texts[4])?,
            grant_digest: digest(&texts[5])?,
            host_id: host.0.clone(),
            host_epoch: host.1.clone(),
            site_id: SiteId::try_from(texts[6].clone()).map_err(|_| JournalError::Unavailable)?,
            hostname: Hostname::try_from(texts[7].clone())
                .map_err(|_| JournalError::Unavailable)?,
            alias_hostname: alias(c, &texts[0])?,
            expires_at: time(expires_at.map_err(u)?)?,
            renew_until: renew_until.map(time).transpose()?,
        },
        state,
        installed,
    }))
}

fn alias(c: &rusqlite::Connection, operation: &str) -> Result<Option<Hostname>, JournalError> {
    c.query_row(
        "SELECT hostname FROM certificate_aliases WHERE operation_id=?1",
        [operation],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(storage::unavailable)?
    .map(|name| Hostname::try_from(name).map_err(storage::unavailable))
    .transpose()
}

/// The exact alias and digest of each site's latest installed pair.
pub(crate) fn installed_pairs(
    c: &rusqlite::Connection,
) -> Result<Vec<(SiteId, Hostname, Sha256Digest)>, JournalError> {
    let mut pairs = Vec::new();
    for (site, _) in installed_by_site(c)? {
        if let Some((sha, _, id)) = served_chain(c, site.as_str())?
            && let Some(alias) = alias(c, id.as_str())?
        {
            pairs.push((site, alias, sha));
        }
    }
    Ok(pairs)
}

/// D-060: the chain a site serves: its latest installed issuance, or that
/// issuance's latest installed renewal. Returns the digest, the expiry, and
/// the issuance's operation.
fn served_chain(
    c: &rusqlite::Connection,
    site: &str,
) -> Result<Option<(Sha256Digest, Timestamp, Id)>, JournalError> {
    let issuance: Option<(String, String, i64)> = c
        .query_row(
            "SELECT operation_id, certificate_sha256, not_after FROM certificates WHERE site_id=?1 AND state='installed' ORDER BY rowid DESC LIMIT 1",
            [site],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(storage::unavailable)?;
    let Some((operation, mut sha, mut not_after)) = issuance else {
        return Ok(None);
    };
    if let Some((renewed, until)) = c
        .query_row(
            "SELECT certificate_sha256, not_after FROM certificate_renewals WHERE operation_id=?1 AND state='installed' ORDER BY rowid DESC LIMIT 1",
            [operation.as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(storage::unavailable)?
    {
        sha = renewed;
        not_after = until;
    }
    Ok(Some((
        Sha256Digest::try_from(sha).map_err(|_| JournalError::Unavailable)?,
        u64::try_from(not_after)
            .ok()
            .and_then(|value| Timestamp::try_from(value).ok())
            .ok_or(JournalError::Unavailable)?,
        Id::try_from(operation).map_err(|_| JournalError::Unavailable)?,
    )))
}

/// W464: every site's served chain for the observation. D-085: a deleted
/// site's chain is gone with it and is never observed or renewed.
pub(crate) fn observed(
    c: &rusqlite::Connection,
) -> Result<Vec<crate::observe::ObservedCertificate>, JournalError> {
    let mut query = c
        .prepare("SELECT DISTINCT c.site_id, c.hostname FROM certificates c JOIN provisions p ON p.site_id=c.site_id \
             WHERE c.state='installed' AND p.state<>'deleted' ORDER BY c.site_id")
        .map_err(storage::unavailable)?;
    let sites: Vec<(String, String)> = query
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(storage::unavailable)?
        .collect::<Result<_, _>>()
        .map_err(storage::unavailable)?;
    // D-064: an ejected site still serves its certificate, but Rustiron no
    // longer renews it; the observation says so.
    let ejected = provision::ejected(c)?;
    let mut observed = Vec::new();
    for (site, hostname) in sites {
        let is_ejected = ejected.iter().any(|own| own.as_str() == site);
        let Some((sha, not_after, operation)) = served_chain(c, &site)? else {
            continue;
        };
        let last: Option<String> = c
            .query_row(
                "SELECT state FROM certificate_renewals WHERE operation_id=?1 ORDER BY rowid DESC LIMIT 1",
                [operation.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage::unavailable)?;
        observed.push(crate::observe::ObservedCertificate {
            site_id: site,
            hostname,
            certificate_sha256: sha.as_str().to_owned(),
            not_after: not_after.get(),
            last_renewal_failed: last.as_deref() == Some("failed"),
            ejected: is_ejected,
        });
    }
    Ok(observed)
}

/// D-060: every site's served chain digest, by site id.
pub(crate) fn installed_by_site(
    c: &rusqlite::Connection,
) -> Result<Vec<(SiteId, Sha256Digest)>, JournalError> {
    let mut query = c
        .prepare(
            "SELECT DISTINCT c.site_id FROM certificates c JOIN provisions p ON p.site_id=c.site_id \
             WHERE c.state='installed' AND p.state<>'deleted' ORDER BY c.site_id",
        )
        .map_err(storage::unavailable)?;
    let sites: Vec<String> = query
        .query_map([], |row| row.get(0))
        .map_err(storage::unavailable)?
        .collect::<Result<_, _>>()
        .map_err(storage::unavailable)?;
    let mut served = Vec::new();
    for site in sites {
        if let Some((sha, _, _)) = served_chain(c, &site)? {
            served.push((
                SiteId::try_from(site).map_err(|_| JournalError::Unavailable)?,
                sha,
            ));
        }
    }
    Ok(served)
}

/// The recorded issuance with this operation, for the admin helper.
pub(crate) fn by_operation(
    c: &rusqlite::Connection,
    host: (&Id, &Id),
    operation_id: &Id,
) -> Result<Option<Certificate>, JournalError> {
    read(c, host, "operation_id", operation_id.as_str())
}

impl FixtureJournal {
    /// W462 (D-059): admits one signed issuance for a managed site, or
    /// answers an exact repeat. The site must be owned (`succeeded` or
    /// `adopted`) with this hostname, and nothing else may be unresolved.
    pub fn record_certificate(
        &mut self,
        intent: &CertificateIntent,
        now: Timestamp,
    ) -> Result<Admitted<Certificate>, JournalError> {
        let signed = self.take_signed(&crate::signed::Expected {
            plan_digest: &intent.plan_digest,
            grant_digest: &intent.grant_digest,
        })?;
        if intent.host_id != self.host_id || intent.host_epoch != self.host_epoch {
            return Err(JournalError::Conflict);
        }
        let host = (self.host_id.clone(), self.host_epoch.clone());
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        for (filter, value) in [
            ("operation_id", intent.operation_id.as_str()),
            ("idempotency_key", intent.idempotency_key.as_str()),
        ] {
            if let Some(existing) = read(&transaction, (&host.0, &host.1), filter, value)? {
                return if existing.intent == *intent {
                    Ok(Admitted::Existing(existing))
                } else {
                    Err(JournalError::Conflict)
                };
            }
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
        let provision =
            provision::by_site(&transaction, &intent.site_id)?.ok_or(JournalError::Conflict)?;
        // W469 (P08): an ejected site is no longer Rustiron's to serve.
        if provision.intent.hostname != intent.hostname
            || !matches!(
                provision.state,
                ProvisionState::Succeeded | ProvisionState::Adopted
            )
            || provision::ejected(&transaction)?.contains(&intent.site_id)
        {
            return Err(JournalError::Conflict);
        }
        if let Some(name) = &intent.alias_hostname
            && (name == &intent.hostname
                || crate::import::alias_of(&transaction, &provision.intent.operation_id)?.as_ref()
                    != Some(name))
        {
            return Err(JournalError::Consumed);
        }
        if let Some((_, _, previous)) = served_chain(&transaction, intent.site_id.as_str())?
            && alias(&transaction, previous.as_str())? != intent.alias_hostname
        {
            return Err(JournalError::Consumed);
        }
        transaction
            .execute(
                &format!("INSERT INTO certificates({COLUMNS}) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,'intent',NULL,NULL)"),
                params![
                    intent.operation_id.as_str(),
                    intent.idempotency_key.as_str(),
                    intent.grant_id.as_str(),
                    intent.nonce.as_str(),
                    intent.plan_digest.as_str(),
                    intent.grant_digest.as_str(),
                    intent.site_id.as_str(),
                    intent.hostname.as_str(),
                    intent.expires_at.get() as i64,
                ],
            )
            .map_err(storage::unavailable)?;
        if let Some(until) = intent.renew_until {
            transaction
                .execute(
                    "INSERT INTO certificate_grants VALUES(?1,?2)",
                    params![intent.operation_id.as_str(), until.get() as i64],
                )
                .map_err(storage::unavailable)?;
        }
        if let Some(name) = &intent.alias_hostname {
            transaction
                .execute(
                    "INSERT INTO certificate_aliases VALUES(?1,?2)",
                    params![intent.operation_id.as_str(), name.as_str()],
                )
                .map_err(storage::unavailable)?;
        }
        crate::signed::insert(&transaction, &intent.operation_id, signed.as_ref())?;
        storage::set_clock(&transaction, now)?;
        transaction.commit().map_err(storage::unavailable)?;
        Ok(Admitted::New(Certificate {
            intent: intent.clone(),
            state: CertificateState::Intent,
            installed: None,
        }))
    }

    /// Records the observed outcome of an open issuance: the installed
    /// chain's SHA-256 and expiry, or `None` for a failure.
    pub fn finish_certificate(
        &mut self,
        operation_id: &Id,
        installed: Option<(&Sha256Digest, Timestamp)>,
    ) -> Result<Certificate, JournalError> {
        let changed = match installed {
            Some((sha, not_after)) => self.connection.execute(
                "UPDATE certificates SET state='installed', certificate_sha256=?1, not_after=?2 WHERE operation_id=?3 AND state='intent'",
                params![sha.as_str(), not_after.get() as i64, operation_id.as_str()],
            ),
            None => self.connection.execute(
                "UPDATE certificates SET state='failed' WHERE operation_id=?1 AND state='intent'",
                [operation_id.as_str()],
            ),
        }
        .map_err(storage::unavailable)?;
        if changed != 1 {
            return Err(JournalError::Conflict);
        }
        self.certificate_status(operation_id)?
            .ok_or(JournalError::Unavailable)
    }

    /// The recorded issuance with this operation.
    pub fn certificate_status(
        &self,
        operation_id: &Id,
    ) -> Result<Option<Certificate>, JournalError> {
        by_operation(
            &self.connection,
            (&self.host_id, &self.host_epoch),
            operation_id,
        )
    }

    /// The site's served chain (D-060): its digest and expiry.
    pub fn installed_certificate(
        &self,
        site: &SiteId,
    ) -> Result<Option<(Sha256Digest, Timestamp)>, JournalError> {
        Ok(served_chain(&self.connection, site.as_str())?.map(|(sha, until, _)| (sha, until)))
    }

    /// Alias covered by the latest installed issuance, if any.
    pub fn installed_certificate_alias(
        &self,
        site: &SiteId,
    ) -> Result<Option<Hostname>, JournalError> {
        match served_chain(&self.connection, site.as_str())? {
            Some((_, _, id)) => alias(&self.connection, id.as_str()),
            None => Ok(None),
        }
    }

    /// D-060: the sites whose served chain is due for renewal at `now`: the
    /// issuance's signed window is open, the site is still owned under the
    /// same hostname, the chain expires within [`RENEW_BEFORE_SECONDS`], and
    /// no renewal of the issuance started within [`RENEW_RETRY_SECONDS`].
    pub fn due_renewals(&self, now: Timestamp) -> Result<Vec<RenewalTarget>, JournalError> {
        let mut query = self
            .connection
            .prepare("SELECT DISTINCT c.site_id FROM certificates c JOIN provisions p ON p.site_id=c.site_id \
             WHERE c.state='installed' AND p.state<>'deleted' ORDER BY c.site_id")
            .map_err(storage::unavailable)?;
        let sites: Vec<String> = query
            .query_map([], |row| row.get(0))
            .map_err(storage::unavailable)?
            .collect::<Result<_, _>>()
            .map_err(storage::unavailable)?;
        // W469 (P08): an ejected site's certificate is the operator's; the
        // standing renewal stops with the ejection.
        let ejected = provision::ejected(&self.connection)?;
        let mut due = Vec::new();
        for site in sites {
            if ejected.iter().any(|own| own.as_str() == site) {
                continue;
            }
            let Some((_, not_after, operation)) = served_chain(&self.connection, &site)? else {
                continue;
            };
            let Some(row) = self.certificate_status(&operation)? else {
                continue;
            };
            let window_open = row
                .intent
                .renew_until
                .is_some_and(|until| now.get() < until.get());
            let expiring = not_after.get() <= now.get().saturating_add(RENEW_BEFORE_SECONDS);
            let recent: bool = self
                .connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM certificate_renewals WHERE operation_id=?1 AND started_at>?2)",
                    params![
                        operation.as_str(),
                        now.get().saturating_sub(RENEW_RETRY_SECONDS) as i64,
                    ],
                    |row| row.get(0),
                )
                .map_err(storage::unavailable)?;
            let Some(owned) =
                provision::by_site(&self.connection, &row.intent.site_id)?.filter(|site| {
                    site.intent.hostname == row.intent.hostname && site.state.is_owned()
                })
            else {
                continue;
            };
            if let Some(name) = &row.intent.alias_hostname
                && crate::import::alias_of(&self.connection, &owned.intent.operation_id)?.as_ref()
                    != Some(name)
            {
                continue;
            }
            if window_open && expiring && !recent {
                due.push(RenewalTarget {
                    operation_id: operation,
                    site_id: row.intent.site_id,
                    hostname: row.intent.hostname,
                    alias_hostname: row.intent.alias_hostname,
                });
            }
        }
        Ok(due)
    }

    /// D-060: commits a renewal's intent before its effect. The target must
    /// still be due, and nothing else may be unresolved.
    pub fn begin_renewal(
        &mut self,
        target: &RenewalTarget,
        renewal_id: &Id,
        now: Timestamp,
    ) -> Result<Renewal, JournalError> {
        if !self.due_renewals(now)?.contains(target) {
            return Err(JournalError::Conflict);
        }
        let transaction = self
            .connection
            .transaction()
            .map_err(storage::unavailable)?;
        if crate::readopt::any_unresolved(&transaction)? {
            return Err(JournalError::Busy);
        }
        if storage::consumed_ids(&transaction, renewal_id, renewal_id, renewal_id)? {
            return Err(JournalError::Conflict);
        }
        storage::check_clock(&transaction, now)?;
        transaction
            .execute(
                "INSERT INTO certificate_renewals VALUES(?1,?2,?3,'intent',NULL,NULL)",
                params![
                    renewal_id.as_str(),
                    target.operation_id.as_str(),
                    now.get() as i64
                ],
            )
            .map_err(storage::unavailable)?;
        storage::set_clock(&transaction, now)?;
        transaction.commit().map_err(storage::unavailable)?;
        self.renewal_status(renewal_id)?
            .ok_or(JournalError::Unavailable)
    }

    /// D-060: records an open renewal's observed outcome.
    pub fn finish_renewal(
        &mut self,
        renewal_id: &Id,
        installed: Option<(&Sha256Digest, Timestamp)>,
    ) -> Result<Renewal, JournalError> {
        let changed = match installed {
            Some((sha, not_after)) => self.connection.execute(
                "UPDATE certificate_renewals SET state='installed', certificate_sha256=?1, not_after=?2 WHERE renewal_id=?3 AND state='intent'",
                params![sha.as_str(), not_after.get() as i64, renewal_id.as_str()],
            ),
            None => self.connection.execute(
                "UPDATE certificate_renewals SET state='failed' WHERE renewal_id=?1 AND state='intent'",
                [renewal_id.as_str()],
            ),
        }
        .map_err(storage::unavailable)?;
        if changed != 1 {
            return Err(JournalError::Conflict);
        }
        self.renewal_status(renewal_id)?
            .ok_or(JournalError::Unavailable)
    }

    /// D-060: one recorded renewal.
    pub fn renewal_status(&self, renewal_id: &Id) -> Result<Option<Renewal>, JournalError> {
        renewal(
            &self.connection,
            (&self.host_id, &self.host_epoch),
            renewal_id,
        )
    }
}

/// D-060: renew when the served chain expires within 30 days.
pub const RENEW_BEFORE_SECONDS: u64 = 30 * 24 * 3600;
/// D-060: at most one renewal attempt per issuance in six hours.
pub const RENEW_RETRY_SECONDS: u64 = 6 * 3600;

/// D-060: one site due for renewal under its issuance's standing grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenewalTarget {
    /// The issuance whose grant authorizes the renewal.
    pub operation_id: Id,
    /// Its site.
    pub site_id: SiteId,
    /// Its hostname.
    pub hostname: Hostname,
    /// The second DNS name from the signed issuance.
    pub alias_hostname: Option<Hostname>,
}

/// D-060: one recorded renewal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Renewal {
    /// The renewal's own id.
    pub renewal_id: Id,
    /// The issuance it renews.
    pub target: RenewalTarget,
    /// Its state.
    pub state: CertificateState,
    /// For `installed`: the new chain's digest and expiry.
    pub installed: Option<(Sha256Digest, Timestamp)>,
}

/// The recorded renewal with this id, for status and the admin helper.
pub(crate) fn renewal(
    c: &rusqlite::Connection,
    host: (&Id, &Id),
    renewal_id: &Id,
) -> Result<Option<Renewal>, JournalError> {
    let row: Option<(String, String, Option<String>, Option<i64>)> = c
        .query_row(
            "SELECT operation_id, state, certificate_sha256, not_after FROM certificate_renewals WHERE renewal_id=?1",
            [renewal_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(storage::unavailable)?;
    let Some((operation, state, sha, not_after)) = row else {
        return Ok(None);
    };
    let issuance = read(c, host, "operation_id", &operation)?.ok_or(JournalError::Unavailable)?;
    let state = match state.as_str() {
        "intent" => CertificateState::Intent,
        "installed" => CertificateState::Installed,
        "failed" => CertificateState::Failed,
        _ => return Err(JournalError::Unavailable),
    };
    let installed = match (sha, not_after) {
        (Some(sha), Some(not_after)) => Some((
            Sha256Digest::try_from(sha).map_err(|_| JournalError::Unavailable)?,
            u64::try_from(not_after)
                .ok()
                .and_then(|value| Timestamp::try_from(value).ok())
                .ok_or(JournalError::Unavailable)?,
        )),
        (None, None) => None,
        _ => return Err(JournalError::Unavailable),
    };
    Ok(Some(Renewal {
        renewal_id: renewal_id.clone(),
        target: RenewalTarget {
            operation_id: issuance.intent.operation_id,
            site_id: issuance.intent.site_id,
            hostname: issuance.intent.hostname,
            alias_hostname: issuance.intent.alias_hostname,
        },
        state,
        installed,
    }))
}
