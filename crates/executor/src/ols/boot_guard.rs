//! W381 (D-032): the boot guard of an interrupted OLS activation.
//!
//! A power cut between the switch and the verification leaves `current` on
//! the unverified target, and OLS serves it at boot (W376 cut 2). The guard
//! runs once per boot, before `lshttpd`, the admin helper and the executor.
//! It changes `current` only when the journal holds an OLS operation with
//! its effect mark recorded and not settled, and `current` is exactly that
//! operation's target. It then points `current` back at the journaled
//! predecessor, or removes `current` for a bootstrap activation, so OLS
//! serves the predecessor or stays down.
//!
//! The guard never records anything in the journal and never claims an
//! outcome. The operation stays unresolved for `reconcile` and the single
//! signed `compensate`. The restore of the predecessor passes the same W362
//! generation checks as `compensate`, and the stored predecessor must still
//! hash to its journaled digest. Every other finding changes nothing.

use std::os::fd::OwnedFd;

use rustiron_contracts::{Id, approval::Sha256Digest};
use rustiron_journal::{Operation, RecordedState, ResourceHistory};

use super::{
    clear_current, established_generation, is_bootstrap_predecessor, observe_current,
    restore_refusal, switch,
};
use crate::ExecutorError;

/// An unresolved OLS operation, as the journal records it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingActivation {
    /// The operation.
    pub operation_id: Id,
    /// Its recorded state: `intent`, `needs_attention` or `compensating`.
    pub state: RecordedState,
    /// Whether the durable effect mark is recorded (the switch may have run).
    pub effect_attempted: bool,
    /// The journaled predecessor generation and digest.
    pub predecessor: (Id, Sha256Digest),
    /// The journaled target generation and digest.
    pub target: (Id, Sha256Digest),
    /// The generation the history before the operation established (see
    /// [`established_generation`]).
    pub established_before: Option<(Id, Sha256Digest)>,
}

/// The pending activation of `operation`, with `history` the journal history
/// before it.
pub fn pending_activation(operation: &Operation, history: ResourceHistory) -> PendingActivation {
    let intent = &operation.intent;
    PendingActivation {
        operation_id: intent.operation_id.clone(),
        state: operation.state,
        effect_attempted: operation.effect_attempted,
        predecessor: (
            intent.predecessor_generation.clone(),
            intent.predecessor_digest.clone(),
        ),
        target: (
            intent.target_generation.clone(),
            intent.target_digest.clone(),
        ),
        established_before: established_generation(history),
    }
}

/// What the guard read from the journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JournalFinding {
    /// The journal did not open, is not bound to the enrolled host and
    /// epoch, is behind its admission mark, is held by a running executor,
    /// or holds more than one unresolved OLS row. The code names the error.
    Unknown(&'static str),
    /// No OLS operation is unresolved.
    Settled,
    /// One OLS operation is unresolved.
    Pending(PendingActivation),
}

/// `current` as the guard observed it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinkFinding {
    /// No entry named `current`.
    Absent,
    /// `current` names this stored generation, with the digest of its bytes.
    Names((Id, Sha256Digest)),
    /// `current` exists but is not a readable stored generation.
    Unreadable,
}

impl LinkFinding {
    /// Reads `current` in `include`.
    pub fn observe(include: &OwnedFd) -> Self {
        match observe_current(include) {
            Ok(None) => Self::Absent,
            Ok(Some(live)) => Self::Names(live),
            Err(_) => Self::Unreadable,
        }
    }

    fn text(&self) -> String {
        match self {
            Self::Absent => "absent".to_owned(),
            Self::Names((id, _)) => id.as_str().to_owned(),
            Self::Unreadable => "unreadable".to_owned(),
        }
    }
}

/// Why the guard changes nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeepReason {
    /// See [`JournalFinding::Unknown`].
    JournalUnknown,
    /// No OLS operation is unresolved.
    Settled,
    /// The operation has no effect mark, so its switch never ran.
    EffectNotAttempted,
    /// `current` is already the predecessor (absent for a bootstrap).
    OnPredecessor,
    /// `current` is neither the journaled target nor the predecessor, or
    /// it is unreadable.
    LinkUnexplained,
    /// The history before the operation does not explain the predecessor
    /// (W362), or the stored predecessor bytes no longer hash to its digest.
    PredecessorRefused,
}

impl KeepReason {
    fn code(self) -> &'static str {
        match self {
            Self::JournalUnknown => "journal_unknown",
            Self::Settled => "no_unsettled_activation",
            Self::EffectNotAttempted => "effect_not_attempted",
            Self::OnPredecessor => "on_predecessor",
            Self::LinkUnexplained => "link_unexplained",
            Self::PredecessorRefused => "predecessor_refused",
        }
    }
}

/// What the guard does.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuardDecision {
    /// Change nothing.
    Keep(KeepReason),
    /// Point `current` at the journaled predecessor.
    RestorePredecessor,
    /// Remove `current` (the predecessor is the bootstrap generation).
    RemoveCurrent,
}

impl GuardDecision {
    fn code(self) -> &'static str {
        match self {
            Self::Keep(_) => "keep",
            Self::RestorePredecessor => "restore_predecessor",
            Self::RemoveCurrent => "remove_current",
        }
    }
}

/// The decision table. `predecessor_stored` is whether the stored
/// predecessor directory hashes to the journaled digest; a bootstrap
/// predecessor has no directory and ignores it.
pub fn decide(
    journal: &JournalFinding,
    link: &LinkFinding,
    predecessor_stored: bool,
) -> GuardDecision {
    let activation = match journal {
        JournalFinding::Unknown(_) => return GuardDecision::Keep(KeepReason::JournalUnknown),
        JournalFinding::Settled => return GuardDecision::Keep(KeepReason::Settled),
        JournalFinding::Pending(activation) => activation,
    };
    if !activation.effect_attempted {
        return GuardDecision::Keep(KeepReason::EffectNotAttempted);
    }
    let (predecessor, digest) = &activation.predecessor;
    let bootstrap = is_bootstrap_predecessor(predecessor, digest);
    match link {
        LinkFinding::Absent if bootstrap => GuardDecision::Keep(KeepReason::OnPredecessor),
        LinkFinding::Names(live) if !bootstrap && live == &activation.predecessor => {
            GuardDecision::Keep(KeepReason::OnPredecessor)
        }
        LinkFinding::Names(live) if live == &activation.target => {
            let explained = restore_refusal(
                &activation.predecessor,
                activation.established_before.as_ref(),
            )
            .is_none();
            match (bootstrap, explained, predecessor_stored) {
                (_, false, _) | (false, true, false) => {
                    GuardDecision::Keep(KeepReason::PredecessorRefused)
                }
                (true, true, _) => GuardDecision::RemoveCurrent,
                (false, true, true) => GuardDecision::RestorePredecessor,
            }
        }
        _ => GuardDecision::Keep(KeepReason::LinkUnexplained),
    }
}

/// Whether `after`, read again after the change, is the intended result.
/// `None` for a decision that changes nothing.
pub fn restored(
    decision: &GuardDecision,
    activation: &PendingActivation,
    after: &LinkFinding,
) -> Option<bool> {
    match decision {
        GuardDecision::Keep(_) => None,
        GuardDecision::RestorePredecessor => {
            Some(after == &LinkFinding::Names(activation.predecessor.clone()))
        }
        GuardDecision::RemoveCurrent => Some(after == &LinkFinding::Absent),
    }
}

/// Makes the change of `decision` in `include`. Changes nothing for
/// [`GuardDecision::Keep`].
pub fn apply(
    include: &OwnedFd,
    decision: &GuardDecision,
    activation: &PendingActivation,
) -> Result<(), ExecutorError> {
    match decision {
        GuardDecision::Keep(_) => Ok(()),
        GuardDecision::RestorePredecessor => switch(include, &activation.predecessor.0),
        GuardDecision::RemoveCurrent => clear_current(include),
    }
}

/// What one guard run found and did, for the system journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuardReport {
    /// The journal finding.
    pub journal: JournalFinding,
    /// `current` before any change.
    pub before: LinkFinding,
    /// The decision.
    pub decision: GuardDecision,
    /// The error of the change, if it failed.
    pub error: Option<&'static str>,
    /// `current` read again after a change.
    pub after: Option<LinkFinding>,
    /// See [`restored`].
    pub restored: Option<bool>,
}

impl GuardReport {
    /// A change was made and its result is not the intended one.
    pub fn failed(&self) -> bool {
        self.restored == Some(false)
    }

    /// One JSON line. It names generations and the operation, never paths
    /// from the request, and claims no operation outcome.
    pub fn json(&self) -> serde_json::Value {
        let (operation, state, effect_attempted, predecessor, target) = match &self.journal {
            JournalFinding::Pending(activation) => (
                Some(activation.operation_id.as_str()),
                Some(state_text(activation.state)),
                Some(activation.effect_attempted),
                Some(activation.predecessor.0.as_str()),
                Some(activation.target.0.as_str()),
            ),
            _ => (None, None, None, None, None),
        };
        serde_json::json!({
            "scope": "ols_boot_guard",
            "decision": self.decision.code(),
            "reason": match self.decision {
                GuardDecision::Keep(reason) => Some(reason.code()),
                _ => None,
            },
            "journal_error": match self.journal {
                JournalFinding::Unknown(code) => Some(code),
                _ => None,
            },
            "operation_id": operation,
            "recorded_state": state,
            "effect_attempted": effect_attempted,
            "predecessor": predecessor,
            "target": target,
            "current_before": self.before.text(),
            "current_after": self.after.as_ref().map(LinkFinding::text),
            "change_error": self.error,
            "restored": self.restored,
            "journal_written": false,
        })
    }
}

fn state_text(state: RecordedState) -> &'static str {
    match state {
        RecordedState::Intent => "intent",
        RecordedState::Succeeded => "succeeded",
        RecordedState::Untouched => "untouched",
        RecordedState::NeedsAttention => "needs_attention",
        RecordedState::Compensating => "compensating",
        RecordedState::FailedCompensated => "failed_compensated",
    }
}

/// The whole guard run on `include` for `journal`: observe, decide, change,
/// read again. `predecessor_stored` reads the stored predecessor digest.
pub fn run(
    journal: JournalFinding,
    include: Result<OwnedFd, ExecutorError>,
    predecessor_stored: impl FnOnce(&OwnedFd, &(Id, Sha256Digest)) -> bool,
) -> GuardReport {
    let include = match include {
        Ok(include) => include,
        Err(_) => {
            return GuardReport {
                decision: decide(&journal, &LinkFinding::Unreadable, false),
                journal,
                before: LinkFinding::Unreadable,
                error: None,
                after: None,
                restored: None,
            };
        }
    };
    let before = LinkFinding::observe(&include);
    let stored = match &journal {
        JournalFinding::Pending(activation) => {
            predecessor_stored(&include, &activation.predecessor)
        }
        _ => false,
    };
    let decision = decide(&journal, &before, stored);
    let JournalFinding::Pending(activation) = &journal else {
        return GuardReport {
            journal,
            before,
            decision,
            error: None,
            after: None,
            restored: None,
        };
    };
    if matches!(decision, GuardDecision::Keep(_)) {
        return GuardReport {
            journal,
            before,
            decision,
            error: None,
            after: None,
            restored: None,
        };
    }
    let error = apply(&include, &decision, activation)
        .err()
        .map(|e| e.code());
    let after = LinkFinding::observe(&include);
    let restored = restored(&decision, activation, &after);
    GuardReport {
        journal,
        before,
        decision,
        error,
        after: Some(after),
        restored,
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use rustix::fs::{self, Mode, OFlags};

    use super::*;
    use crate::ols::{Generation, digest, generation_id, stage_owned};

    struct Include {
        path: std::path::PathBuf,
        fd: OwnedFd,
    }

    impl Drop for Include {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn include(tag: &str) -> Include {
        let path = std::env::temp_dir().join(format!("w381-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(path.join("generations")).unwrap();
        for dir in [path.clone(), path.join("generations")] {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let fd = fs::open(&path, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).unwrap();
        Include { path, fd }
    }

    fn me() -> u32 {
        rustix::process::getuid().as_raw()
    }

    /// Stages one generation and returns its id and digest.
    fn staged(include: &Include, body: &str) -> (Id, Sha256Digest) {
        let generation = Generation::from([("site.conf".to_owned(), body.as_bytes().to_vec())]);
        let digest = digest(&generation);
        let id = generation_id(&digest);
        stage_owned(&include.fd, &id, &generation, &id, me()).unwrap();
        (id, digest)
    }

    fn link(include: &Include) -> Option<String> {
        std::fs::read_link(include.path.join("current"))
            .ok()
            .map(|target| target.to_string_lossy().into_owned())
    }

    fn activation(
        predecessor: (Id, Sha256Digest),
        target: (Id, Sha256Digest),
    ) -> PendingActivation {
        PendingActivation {
            operation_id: Id::try_from("op_w381_unit".to_owned()).unwrap(),
            state: RecordedState::Intent,
            effect_attempted: true,
            established_before: Some(predecessor.clone()),
            predecessor,
            target,
        }
    }

    #[test]
    fn the_restore_points_current_back_at_the_predecessor_and_writes_nothing_else() {
        let inc = include("restore");
        let old = staged(&inc, "old");
        let new = staged(&inc, "new");
        crate::ols::switch(&inc.fd, &new.0).unwrap();
        let pending = activation(old.clone(), new.clone());
        apply(&inc.fd, &GuardDecision::RestorePredecessor, &pending).unwrap();
        assert_eq!(link(&inc), Some(format!("generations/{}", old.0.as_str())));
        // Both generations stay; no temporary link is left.
        let mut names: Vec<String> = std::fs::read_dir(&inc.path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["current", "generations"]);
        assert!(inc.path.join("generations").join(new.0.as_str()).is_dir());
    }

    #[test]
    fn the_bootstrap_removal_leaves_no_current_and_keeps_the_target_directory() {
        let inc = include("remove");
        let first = staged(&inc, "first");
        crate::ols::switch(&inc.fd, &first.0).unwrap();
        let pending = activation(crate::ols::bootstrap_generation(), first.clone());
        apply(&inc.fd, &GuardDecision::RemoveCurrent, &pending).unwrap();
        assert_eq!(link(&inc), None);
        assert!(inc.path.join("generations").join(first.0.as_str()).is_dir());
        // Absent is already removed.
        apply(&inc.fd, &GuardDecision::RemoveCurrent, &pending).unwrap();
    }

    #[test]
    fn a_keep_decision_never_touches_the_include() {
        let inc = include("keep");
        let old = staged(&inc, "old");
        let new = staged(&inc, "new");
        crate::ols::switch(&inc.fd, &new.0).unwrap();
        let pending = activation(old, new.clone());
        apply(
            &inc.fd,
            &GuardDecision::Keep(KeepReason::JournalUnknown),
            &pending,
        )
        .unwrap();
        assert_eq!(link(&inc), Some(format!("generations/{}", new.0.as_str())));
    }

    #[test]
    fn the_report_never_claims_a_journal_write_or_an_outcome() {
        let pending = activation(
            (
                Id::try_from("rold".to_owned()).unwrap(),
                digest(&Generation::new()),
            ),
            (
                Id::try_from("rnew".to_owned()).unwrap(),
                digest(&Generation::new()),
            ),
        );
        let report = GuardReport {
            journal: JournalFinding::Pending(pending.clone()),
            before: LinkFinding::Names(pending.target.clone()),
            decision: GuardDecision::RestorePredecessor,
            error: None,
            after: Some(LinkFinding::Names(pending.predecessor.clone())),
            restored: Some(true),
        };
        let json = report.json();
        assert_eq!(json["journal_written"], false);
        assert_eq!(json["recorded_state"], "intent");
        assert_eq!(json["decision"], "restore_predecessor");
        assert_eq!(json["current_before"], "rnew");
        assert_eq!(json["current_after"], "rold");
        assert!(!report.failed());
        let failed = GuardReport {
            restored: Some(false),
            ..report
        };
        assert!(failed.failed());
    }

    /// The link observation needs root-owned folders, so the lab run on a
    /// product host proves the other paths of [`run`]. An include folder
    /// that does not open is reported and changes nothing.
    #[test]
    fn a_run_without_the_include_folder_changes_nothing() {
        let first = crate::ols::bootstrap_generation();
        let target = (
            Id::try_from("rnew".to_owned()).unwrap(),
            digest(&Generation::new()),
        );
        let report = run(
            JournalFinding::Pending(activation(first, target)),
            Err(ExecutorError::RegistryUnavailable),
            |_, _| panic!("no include"),
        );
        assert_eq!(
            report.decision,
            GuardDecision::Keep(KeepReason::LinkUnexplained)
        );
        assert_eq!(report.before, LinkFinding::Unreadable);
        assert_eq!((report.after, report.restored), (None, None));
    }
}
