//! Proxy site provisions (schema v40, W572, D-095).
//!
//! A proxy site is a provision: it reserves its site ID and hostname in
//! `provisions` and runs the provision steps. Its signed routes are stored
//! in `proxy_routes`, in the transaction that reserves the site, and never
//! change. A provision with route rows is a proxy site. Nothing here reads
//! a host or a port.

use std::collections::BTreeSet;

use rusqlite::params;
use rustiron_contracts::{
    Id, Timestamp,
    approval::{MAX_PROXY_ROUTES, ProxyRoute, routable_port, valid_prefix},
};

use crate::{
    Admitted, FixtureJournal, JournalError, Provision, ProvisionIntent, provision::Origin, storage,
};

/// The signed routes of one proxy site.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyFacts {
    /// The path routes, in signed order, `/` among them.
    pub routes: Vec<ProxyRoute>,
    /// The WebSocket paths, in signed order.
    pub websockets: Vec<ProxyRoute>,
}

impl ProxyFacts {
    /// Whether the routes follow the contract: 1 to 8 routes with `/`, 0 to
    /// 8 WebSocket paths, unique prefixes of the grammar, routable ports.
    pub fn is_valid(&self) -> bool {
        valid_list(&self.routes, 1)
            && self.routes.iter().any(|route| route.prefix == "/")
            && valid_list(&self.websockets, 0)
    }

    /// Whether the routes follow D-102 `fullstack_split`: 1 to 8 non-root API
    /// routes (Caddy serves static `/`), 0 to 8 WebSocket paths, unique prefixes.
    pub fn is_valid_app_split(&self) -> bool {
        valid_list(&self.routes, 1)
            && !self.routes.iter().any(|route| route.prefix == "/")
            && valid_list(&self.websockets, 0)
    }

    /// Every distinct port, in order.
    pub fn ports(&self) -> Vec<u16> {
        self.routes
            .iter()
            .chain(&self.websockets)
            .map(|route| route.port)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

fn valid_list(routes: &[ProxyRoute], low: usize) -> bool {
    let prefixes: BTreeSet<&str> = routes.iter().map(|route| route.prefix.as_str()).collect();
    (low..=MAX_PROXY_ROUTES).contains(&routes.len())
        && prefixes.len() == routes.len()
        && routes
            .iter()
            .all(|route| valid_prefix(&route.prefix) && routable_port(route.port))
}

const KINDS: [&str; 2] = ["route", "websocket"];

impl FixtureJournal {
    /// Records a new proxy site provision with its routes in one
    /// transaction, or returns the exact earlier status. A retry must match
    /// the intent and the routes.
    pub fn record_proxy_provision(
        &mut self,
        intent: &ProvisionIntent,
        facts: &ProxyFacts,
        now: Timestamp,
    ) -> Result<Admitted<Provision>, JournalError> {
        if !facts.is_valid() {
            return Err(JournalError::Conflict);
        }
        self.admit_provision(intent, Origin::Proxy(facts), now)
    }

    /// The routes of a proxy site provision; `None` for another provision.
    pub fn proxy_facts(&self, operation_id: &Id) -> Result<Option<ProxyFacts>, JournalError> {
        facts(&self.connection, operation_id)
    }
}

pub(crate) fn insert(
    c: &rusqlite::Connection,
    operation_id: &Id,
    facts: &ProxyFacts,
) -> Result<(), JournalError> {
    for (kind, routes) in KINDS.into_iter().zip([&facts.routes, &facts.websockets]) {
        for (position, route) in routes.iter().enumerate() {
            c.execute(
                "INSERT INTO proxy_routes VALUES(?1,?2,?3,?4,?5)",
                params![
                    operation_id.as_str(),
                    kind,
                    position as i64,
                    route.prefix,
                    i64::from(route.port)
                ],
            )
            .map_err(storage::unavailable)?;
        }
    }
    Ok(())
}

pub(crate) fn facts(
    c: &rusqlite::Connection,
    operation_id: &Id,
) -> Result<Option<ProxyFacts>, JournalError> {
    let mut statement = c
        .prepare(
            "SELECT kind, prefix, port FROM proxy_routes WHERE operation_id=?1 \
             ORDER BY kind, position",
        )
        .map_err(storage::unavailable)?;
    let rows = statement
        .query_map([operation_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .map_err(storage::unavailable)?;
    let mut facts = ProxyFacts {
        routes: Vec::new(),
        websockets: Vec::new(),
    };
    for row in rows {
        let (kind, prefix, port) = row.map_err(storage::unavailable)?;
        let port = u16::try_from(port).map_err(|_| JournalError::Unavailable)?;
        let list = match kind.as_str() {
            "route" => &mut facts.routes,
            "websocket" => &mut facts.websockets,
            _ => return Err(JournalError::Unavailable),
        };
        list.push(ProxyRoute { prefix, port });
    }
    if facts.routes.is_empty() && facts.websockets.is_empty() {
        return Ok(None);
    }
    let is_split_app: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM app_fullstack_specs WHERE operation_id=?1 AND topology='fullstack_split')",
            [operation_id.as_str()],
            |row| row.get(0),
        )
        .unwrap_or(false);
    let ok = if is_split_app {
        facts.is_valid_app_split()
    } else {
        facts.is_valid()
    };
    if !ok {
        return Err(JournalError::Unavailable);
    }
    Ok(Some(facts))
}

/// Every route belongs to a provision that is neither an import nor a
/// clone, positions have no gaps, and each proxy site's routes follow the
/// contract.
pub(crate) fn validate(c: &rusqlite::Connection) -> Result<(), JournalError> {
    let invalid: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM proxy_routes r LEFT JOIN provisions p USING(operation_id) \
             WHERE p.operation_id IS NULL \
             OR EXISTS(SELECT 1 FROM imports i WHERE i.operation_id=r.operation_id) \
             OR EXISTS(SELECT 1 FROM clones l WHERE l.operation_id=r.operation_id)) \
             OR EXISTS(SELECT 1 FROM proxy_routes GROUP BY operation_id, kind \
             HAVING count(*)<>max(position)+1)",
            [],
            |row| row.get(0),
        )
        .map_err(storage::unavailable)?;
    if invalid {
        return Err(JournalError::Unavailable);
    }
    let mut statement = c
        .prepare("SELECT DISTINCT operation_id FROM proxy_routes")
        .map_err(storage::unavailable)?;
    let operations = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(storage::unavailable)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage::unavailable)?;
    for operation in operations {
        let operation = Id::try_from(operation).map_err(|_| JournalError::Unavailable)?;
        if facts(c, &operation)?.is_none() {
            return Err(JournalError::Unavailable);
        }
    }
    Ok(())
}
