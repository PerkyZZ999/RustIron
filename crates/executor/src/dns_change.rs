//! D-091 (W565): the admin helper's steps of a signed `dns_change`: the
//! read of an owned zone, and the compare-and-set change of its record sets.
//!
//! Every value comes from the journal: the change's sets and what the
//! executor read before intent, and the signed plan bytes stored at
//! admission, checked against the recorded plan digest. The helper applies
//! the operations only while every named set is still what was read before
//! intent; when every set already is the intended one (an interrupted
//! change being settled), it changes nothing.

use rustiron_contracts::approval::{
    ChangeAction, DnsChangePlan, ParsedZone, SetOperation, ZoneName, parse_zone,
};
use rustiron_journal::DnsChange;

use crate::ExecutorError;
use crate::dns_import::{Pdns, canonical_listing};

/// The zone as PowerDNS serves it, in the canonical grammar.
pub(crate) fn read_zone(pdns: &mut impl Pdns, zone: &ZoneName) -> Result<Vec<u8>, ExecutorError> {
    let listing = canonical_listing(&pdns.util(&["zone", "list", zone.as_str()], None)?);
    parse_zone(zone, &listing).map_err(|_| ExecutorError::StepFailed)?;
    Ok(listing)
}

/// Each operation's set in `zone` as canonical lines, or `None` when the
/// zone has no set of that owner and type.
pub(crate) fn sets_in(zone: &ParsedZone, operations: &[SetOperation]) -> Vec<Option<String>> {
    operations
        .iter()
        .map(|operation| {
            zone.record_sets
                .iter()
                .find(|set| set.owner == operation.owner && set.kind == operation.kind)
                .map(|set| set.canonical())
        })
        .collect()
}

/// The sets the operations leave: the replacement's canonical lines, or
/// `None` for a removal.
pub(crate) fn intended(operations: &[SetOperation]) -> Vec<Option<String>> {
    operations
        .iter()
        .map(|operation| operation.new_set().map(|set| set.canonical()))
        .collect()
}

/// The signed plan is the journal's change: same zone, and the same owners,
/// types, and expectations in the same order.
pub(crate) fn plan_is_change(plan: &DnsChangePlan, change: &DnsChange) -> bool {
    plan.zone() == &change.zone
        && plan.operations().len() == change.sets.len()
        && plan
            .operations()
            .iter()
            .zip(&change.sets)
            .all(|(operation, set)| {
                operation.owner == set.owner
                    && operation.kind == set.kind
                    && operation.expected == set.expected
            })
}

/// The helper's change step.
pub(crate) fn run(
    pdns: &mut impl Pdns,
    change: &DnsChange,
    plan: &DnsChangePlan,
) -> Result<(), ExecutorError> {
    if !plan_is_change(plan, change) {
        return Err(ExecutorError::BindingDenied);
    }
    let zone = &change.zone;
    let operations = plan.operations();
    let wanted = intended(operations);
    let read = |pdns: &mut _| -> Result<Vec<Option<String>>, ExecutorError> {
        let listing = read_zone(pdns, zone)?;
        let parsed = parse_zone(zone, &listing).map_err(|_| ExecutorError::StepFailed)?;
        Ok(sets_in(&parsed, operations))
    };
    let now = read(pdns)?;
    if now == wanted {
        return Ok(());
    }
    let before: Vec<Option<String>> = change.sets.iter().map(|set| set.before.clone()).collect();
    if now != before {
        return Err(ExecutorError::PreconditionChanged);
    }
    let name = zone.as_str();
    for operation in operations {
        let kind = operation.kind.as_str();
        match (operation.action, operation.new_set()) {
            (ChangeAction::Replace, Some(set)) => {
                let ttl = set.ttl.to_string();
                let mut args = vec!["rrset", "replace", name, &operation.owner, kind, &ttl];
                args.extend(set.records.iter().map(String::as_str));
                pdns.util(&args, None)?;
            }
            (ChangeAction::Remove, None) => {
                pdns.util(&["rrset", "delete", name, &operation.owner, kind], None)?;
            }
            _ => return Err(ExecutorError::BindingDenied),
        }
    }
    pdns.util(&["zone", "increase-serial", name], None)?;
    // `pdns_control purge NAME$` names the owner without its final dot
    // (W560).
    let mut owners: Vec<&str> = operations
        .iter()
        .map(|op| op.owner.trim_end_matches('.'))
        .collect();
    owners.sort_unstable();
    owners.dedup();
    for owner in owners {
        pdns.control(&["purge", &format!("{owner}$")])?;
    }
    if read(pdns)? == wanted {
        Ok(())
    } else {
        Err(ExecutorError::StepFailed)
    }
}

#[cfg(test)]
#[path = "dns_change_tests.rs"]
mod tests;
