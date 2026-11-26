//! D-091 (W565): admission of a signed `dns_change` and its one step.

use rustiron_contracts::Id;
use rustiron_contracts::approval::{SetOperation, ZoneName, parse_zone};
use rustiron_journal::{DnsChange, DnsChangeResult, DnsChangeSet, StepState};

use super::{Executor, signed_inputs};
use crate::{
    AdmissionRequest, ExecutorError,
    admin_helper::{self, AdminRequest, AdminStep, Reply},
};

impl Executor {
    /// Admits one signed change of an owned zone's record sets. Before
    /// intent, the executor reads each named set through the admin helper
    /// (under the zone's done import); the journal records the change only
    /// when every set agrees with what the plan expects. The helper then
    /// applies the change while every set is still what was read. After any
    /// outcome the sets are read again and recorded; the change is `done`
    /// only when the helper succeeded. An exact repeat returns the stored
    /// change and runs nothing.
    pub fn change_dns(
        &mut self,
        request: &AdmissionRequest<'_>,
    ) -> Result<DnsChangeResult, ExecutorError> {
        let (plan, mut intent) = crate::verified_dns_change(&self.anchor, request)?;
        self.check_identity(&intent.host_id, &intent.host_epoch)?;
        let now = request.now.ok_or(ExecutorError::TimeDenied)?;
        if let Some(existing) = self.journal.dns_change_status(&intent.operation_id)? {
            return Ok(DnsChangeResult::Existing(existing));
        }
        if self.anchor.admin_socket.is_none() {
            return Err(ExecutorError::Unavailable);
        }
        let before = self.read_sets(&intent.zone, plan.operations())?;
        intent.sets = plan
            .operations()
            .iter()
            .zip(before)
            .map(|(operation, before)| DnsChangeSet {
                owner: operation.owner.clone(),
                kind: operation.kind,
                expected: operation.expected.clone(),
                before,
                after: None,
            })
            .collect();
        let change = match self.admit(signed_inputs(request)?, |journal| {
            journal.record_dns_change(&intent, now)
        })? {
            DnsChangeResult::Existing(existing) => return Ok(DnsChangeResult::Existing(existing)),
            DnsChangeResult::New(change) => change,
        };
        Ok(DnsChangeResult::New(
            self.run_dns_change(&change, plan.operations())?,
        ))
    }

    /// The named sets of an owned zone as PowerDNS serves them, read by the
    /// admin helper under the zone's done import.
    fn read_sets(
        &mut self,
        zone: &ZoneName,
        operations: &[SetOperation],
    ) -> Result<Vec<Option<String>>, ExecutorError> {
        let import = self
            .journal
            .owning_dns_import(zone)?
            .ok_or(ExecutorError::PreconditionChanged)?;
        let socket = self
            .anchor
            .admin_socket
            .as_deref()
            .ok_or(ExecutorError::Unavailable)?;
        let request = AdminRequest {
            operation_id: import,
            step: AdminStep::DnsZoneRead,
        };
        // W566-F1: the listing comes as one JSON string on the reply line.
        let listing: String = match admin_helper::request(socket, &request)? {
            Reply::Done(Some(text)) => {
                serde_json::from_str(&text).map_err(|_| ExecutorError::StepFailed)?
            }
            Reply::Done(None) => return Err(ExecutorError::StepFailed),
            Reply::Refused(error) => return Err(error),
        };
        let parsed = parse_zone(zone, listing.as_bytes()).map_err(|_| ExecutorError::StepFailed)?;
        Ok(crate::dns_change::sets_in(&parsed, operations))
    }

    /// Asks the admin helper to apply the open change, reads the sets back,
    /// and records the outcome with them. An unreadable read-back records
    /// the change `failed` without the sets.
    fn run_dns_change(
        &mut self,
        change: &DnsChange,
        operations: &[SetOperation],
    ) -> Result<DnsChange, ExecutorError> {
        let outcome = admin_helper::route(
            self.anchor.admin_socket.as_deref(),
            &AdminRequest {
                operation_id: change.operation_id.clone(),
                step: AdminStep::DnsChange,
            },
            || Err(ExecutorError::Unavailable),
        );
        let after = self.read_sets(&change.zone, operations);
        let recorded = match &after {
            Ok(after) => self.journal.finish_dns_change(
                &change.operation_id,
                outcome.is_ok() && *after == crate::dns_change::intended(operations),
                after,
            )?,
            Err(_) => self
                .journal
                .finish_dns_change(&change.operation_id, false, &[])?,
        };
        outcome?;
        after?;
        Ok(recorded)
    }

    /// W565: settles a change left `intent` by a stopped executor: the
    /// helper runs the step again, which changes nothing when every set
    /// already is the intended one and refuses when a set is neither that
    /// nor what was read before intent. A settled change is returned as it
    /// is.
    pub fn reconcile_dns_change(&mut self, operation_id: &Id) -> Result<DnsChange, ExecutorError> {
        let change = self
            .journal
            .dns_change_status(operation_id)?
            .ok_or(ExecutorError::NotAdmitted)?;
        if change.state != StepState::Intent {
            return Ok(change);
        }
        let plan = rustiron_contracts::approval::DnsChangePlan::decode(
            &self
                .journal
                .dns_change_plan(operation_id)?
                .ok_or(ExecutorError::Unavailable)?,
        )
        .map_err(|_| ExecutorError::Unavailable)?;
        self.run_dns_change(&change, plan.operations())
    }

    /// W565: a stored record change, for status.
    pub fn dns_change_status(&self, operation_id: &Id) -> Result<Option<DnsChange>, ExecutorError> {
        Ok(self.journal.dns_change_status(operation_id)?)
    }
}
