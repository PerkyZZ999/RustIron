//! D-103 (W778): site list and inspect from the executor journal, for a host
//! with no operator inventory report. Grants no authority; reads only.

use rustiron_contracts::{
    ApiError, ErrorCode, Id, InventoryProvenance, InventorySource, Observation, Ownership,
    PageLimit, ReadCommand, ReadData, SiteDetail, SitePage, SiteSummary, Timestamp, UnknownReason,
    execution::{SiteRecord, SiteRecordsQuery},
};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::executor_transport::ExecutorTransport;

/// Answers `site_list` or `site_inspect` from the executor's owned sites.
pub(crate) fn read(
    executor: Option<&ExecutorTransport>,
    request_id: Id,
    command: ReadCommand,
    deadline: Instant,
) -> Result<ReadData, ApiError> {
    let executor = executor.ok_or_else(|| ApiError::new(ErrorCode::DependencyUnavailable))?;
    let sites = executor
        .site_records_until(&SiteRecordsQuery { request_id }, deadline)
        .map_err(ApiError::new)??;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| Timestamp::try_from(elapsed.as_secs()).ok())
        .ok_or_else(|| ApiError::new(ErrorCode::DependencyUnavailable))?;
    match command {
        ReadCommand::SiteList { cursor, limit } => {
            page(&sites, cursor.as_ref(), limit, now).map(ReadData::SiteList)
        }
        ReadCommand::SiteInspect { site_id } => sites
            .iter()
            .find(|site| site.site_id == site_id)
            .map(|site| {
                ReadData::SiteInspect(SiteDetail {
                    site: summary(site, now),
                    // The journal row is not a live configuration probe.
                    configuration_generation: Observation::Unknown {
                        reason: UnknownReason::NotChecked,
                    },
                })
            })
            .ok_or(ErrorCode::NotFound),
        _ => Err(ErrorCode::InvalidRequest),
    }
    .map_err(ApiError::new)
}

fn summary(site: &SiteRecord, now: Timestamp) -> SiteSummary {
    SiteSummary {
        site_id: site.site_id.clone(),
        name: site.hostname.clone(),
        ownership: if site.adopted {
            Ownership::ExplicitlyAdopted
        } else {
            Ownership::Created
        },
        inventory: Some(InventoryProvenance {
            reported_at: now,
            source: InventorySource::ExecutorJournal,
        }),
    }
}

/// Cursor `journal-COUNT-OFFSET-LIMIT` (hex); the inventory store's cursors
/// are 56 hex digits, so neither source accepts the other's.
/// shortcut: a changed site count expires the cursor, but a same-count change
/// does not; bind it to a journal revision if agents page through many sites.
fn cursor(count: usize, offset: usize, limit: PageLimit) -> Result<Id, ErrorCode> {
    Id::try_from(format!(
        "journal-{count:04x}-{offset:04x}-{:04x}",
        limit.get()
    ))
    .map_err(|_| ErrorCode::DependencyUnavailable)
}

fn offset(token: Option<&Id>, count: usize, limit: PageLimit) -> Result<usize, ErrorCode> {
    let Some(token) = token else { return Ok(0) };
    let parts: Vec<&str> = token.as_str().split('-').collect();
    let number = |text: &str| {
        (text.len() == 4)
            .then(|| usize::from_str_radix(text, 16).ok())
            .flatten()
            .ok_or(ErrorCode::CursorExpired)
    };
    let [prefix, seen, at, size] = parts[..] else {
        return Err(ErrorCode::CursorExpired);
    };
    let at = number(at)?;
    if prefix != "journal"
        || number(seen)? != count
        || number(size)? != usize::from(limit.get())
        || at == 0
        || at >= count
        || at % usize::from(limit.get()) != 0
    {
        return Err(ErrorCode::CursorExpired);
    }
    Ok(at)
}

fn page(
    sites: &[SiteRecord],
    token: Option<&Id>,
    limit: PageLimit,
    now: Timestamp,
) -> Result<SitePage, ErrorCode> {
    let start = offset(token, sites.len(), limit)?;
    let end = sites.len().min(start + usize::from(limit.get()));
    let next_cursor = if end < sites.len() {
        Some(cursor(sites.len(), end, limit)?)
    } else {
        None
    };
    Ok(SitePage {
        items: sites[start..end]
            .iter()
            .map(|site| summary(site, now))
            .collect(),
        next_cursor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustiron_contracts::Text;

    fn site(id: &str, adopted: bool) -> SiteRecord {
        SiteRecord {
            site_id: Id::try_from(id.to_owned()).unwrap(),
            hostname: Text::try_from(format!("{id}.example.test")).unwrap(),
            adopted,
        }
    }

    fn limit(size: u16) -> PageLimit {
        PageLimit::try_from(size).unwrap()
    }

    #[test]
    fn pages_follow_the_journal_order_and_carry_journal_provenance() {
        let sites: Vec<_> = ["a", "b", "c"]
            .iter()
            .map(|id| site(id, *id == "b"))
            .collect();
        let now = Timestamp::try_from(42).unwrap();
        let first = page(&sites, None, limit(2), now).unwrap();
        assert_eq!(first.items.len(), 2);
        assert_eq!(first.items[1].ownership, Ownership::ExplicitlyAdopted);
        assert_eq!(first.items[0].ownership, Ownership::Created);
        assert_eq!(
            first.items[0].inventory.as_ref().unwrap().source,
            InventorySource::ExecutorJournal
        );
        let next = first.next_cursor.unwrap();
        let second = page(&sites, Some(&next), limit(2), now).unwrap();
        assert_eq!(second.items[0].site_id.as_str(), "c");
        assert!(second.next_cursor.is_none());
    }

    #[test]
    fn a_cursor_from_another_count_size_or_source_expires() {
        let sites: Vec<_> = ["a", "b", "c"].iter().map(|id| site(id, false)).collect();
        let now = Timestamp::try_from(42).unwrap();
        let next = page(&sites, None, limit(2), now)
            .unwrap()
            .next_cursor
            .unwrap();
        assert_eq!(
            page(&sites[..2], Some(&next), limit(2), now).unwrap_err(),
            ErrorCode::CursorExpired
        );
        assert_eq!(
            page(&sites, Some(&next), limit(1), now).unwrap_err(),
            ErrorCode::CursorExpired
        );
        let store = Id::try_from("0".repeat(56)).unwrap();
        assert_eq!(
            page(&sites, Some(&store), limit(2), now).unwrap_err(),
            ErrorCode::CursorExpired
        );
        let forged = Id::try_from("journal-0003-0001-0002".to_owned()).unwrap();
        assert_eq!(
            page(&sites, Some(&forged), limit(2), now).unwrap_err(),
            ErrorCode::CursorExpired
        );
    }
}
