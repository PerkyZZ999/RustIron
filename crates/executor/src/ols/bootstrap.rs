//! W355: the first activation on a fresh product host.
//!
//! The installer pins a parent with no listener (W348), so OLS 1.9.4 refuses
//! to run and the installer leaves `lshttpd` stopped. Such a host has no
//! `current`, and systemd refuses to reload an inactive unit. A host is in
//! the bootstrap state only when every fact in [`BootstrapFacts`] holds;
//! then, and only then, the first activation starts OLS instead of
//! reloading it, and its compensation stops OLS and removes `current` again.
//! Every other host keeps the running-host drift checks.

use std::{os::fd::OwnedFd, time::Duration};

use rustiron_contracts::{Id, approval::Sha256Digest};
use rustiron_journal::ResourceHistory;
use rustix::fs::{self, AtFlags};

use super::{Generation, digest, generation_id, listening, observe};
use crate::ExecutorError;

/// The package unit the activation starts, reloads and stops.
pub const OLS_UNIT: &str = "lshttpd.service";
/// How long the bootstrap compensation waits for a stopped server and closed
/// ports after `systemctl stop` returns.
const STOP_WAIT: Duration = Duration::from_secs(60);
/// W364: the `KillMode` of [`OLS_UNIT`] with the shipped drop-in
/// (`50-rustiron-killmode.conf`, W245). The package unit has `KillMode=none`:
/// its workers outlived a stop (W243, W361). With `mixed`, systemd sends
/// SIGKILL to every process left in the unit after the main process exits.
pub const SHIPPED_KILL_MODE: &str = "mixed";

/// The predecessor a bootstrap activation names: the empty generation,
/// content-addressed like any other (`r` + 16 hex of its digest). No stored
/// directory holds it; it stands for "no `current`".
pub fn bootstrap_generation() -> (Id, Sha256Digest) {
    let digest = digest(&Generation::new());
    (generation_id(&digest), digest)
}

/// Whether an intent's predecessor is the bootstrap one.
pub fn is_bootstrap_predecessor(generation: &Id, digest: &Sha256Digest) -> bool {
    let (id, empty) = bootstrap_generation();
    generation == &id && digest == &empty
}

/// How an activation brings the server onto its target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationMode {
    /// `current` exists and is the plan's predecessor: running-host drift
    /// checks, then reload.
    Running,
    /// No `current` and the plan names the bootstrap predecessor: the
    /// bootstrap facts, then start.
    Bootstrap,
}

impl ActivationMode {
    /// The step that makes the server load the target: reload a running
    /// server, start a stopped bootstrap one.
    pub fn serving_step(self) -> crate::admin_helper::AdminStep {
        match self {
            Self::Running => crate::admin_helper::AdminStep::OlsReload,
            Self::Bootstrap => crate::admin_helper::AdminStep::OlsStart,
        }
    }

    /// The fixed `systemctl` verb of [`Self::serving_step`].
    pub fn systemctl_verb(self) -> &'static str {
        match self {
            Self::Running => "reload",
            Self::Bootstrap => "start",
        }
    }
}

/// Decides the mode from the live `current` and the plan's predecessor. A
/// missing `current` is bootstrap only for the bootstrap predecessor;
/// otherwise it stays the `REGISTRY_UNAVAILABLE` refusal it was before W355.
/// A present `current` must equal the predecessor, so a plan naming the
/// bootstrap predecessor on a host that has a `current` is refused.
pub fn activation_mode(
    live: Option<&(Id, Sha256Digest)>,
    predecessor: &(Id, Sha256Digest),
) -> Result<ActivationMode, ExecutorError> {
    match live {
        None if is_bootstrap_predecessor(&predecessor.0, &predecessor.1) => {
            Ok(ActivationMode::Bootstrap)
        }
        None => Err(ExecutorError::RegistryUnavailable),
        Some(live) if live == predecessor => Ok(ActivationMode::Running),
        Some(_) => Err(ExecutorError::PreconditionChanged),
    }
}

/// What the bootstrap compensation may record: the bootstrap generation
/// (then `failed_compensated`) only when OLS was stopped with its ports
/// closed and `current` is gone again. Anything else records no
/// observation, so the operation stays `needs_attention` with the facts.
pub fn bootstrap_restored(
    stopped: &Result<(), ExecutorError>,
    current_after: &Result<Option<(Id, Sha256Digest)>, ExecutorError>,
) -> Option<(Id, Sha256Digest)> {
    match (stopped, current_after) {
        (Ok(()), Ok(None)) => Some(bootstrap_generation()),
        _ => None,
    }
}

/// `current` as observed. `Ok(None)` only when no entry named `current`
/// exists; any other unreadable state stays an error, as in [`observe`].
pub fn observe_current(include: &OwnedFd) -> Result<Option<(Id, Sha256Digest)>, ExecutorError> {
    match fs::statat(include, "current", AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(None),
        _ => observe(include).map(Some),
    }
}

/// The bootstrap compensation's restore: removes `current` when it is a
/// symlink. Absent is already restored; any other file type is drift.
pub use crate::generation::clear_current;

/// `ActiveState` values of a server that is not running: never started or
/// stopped (`inactive`), or `failed`: a failed start (the package unit after
/// a boot with no generation), or a stop under the shipped `KillMode`
/// (the OLS main process exits 255, D-022). `activating` (an automatic restart pending)
/// and every other value are not stopped.
pub fn unit_stopped(state: Option<&str>) -> bool {
    matches!(state, Some("inactive" | "failed"))
}

/// Whether `KillMode` is the shipped one, so a stop ends every OLS process.
/// Any other or unknown value is not.
pub fn kill_mode_shipped(mode: Option<&str>) -> bool {
    mode == Some(SHIPPED_KILL_MODE)
}

/// `KillMode` of [`OLS_UNIT`], or `None` when systemd did not answer.
pub fn kill_mode() -> Option<String> {
    crate::provision::output(
        "/usr/bin/systemctl",
        &["show", "--property=KillMode", "--value", OLS_UNIT],
    )
    .ok()
    .map(|text| text.trim().to_owned())
}

/// Both listener tables were read and no port in `ports` listens in either.
/// An unreadable table is never closed.
pub fn ports_closed(tables: &[Option<String>; 2], ports: &[u16]) -> bool {
    tables.iter().all(|table| {
        table
            .as_deref()
            .is_some_and(|text| ports.iter().all(|&port| !listening(text, port)))
    })
}

/// The live `/proc/net/tcp` and `/proc/net/tcp6` tables.
pub fn listener_tables() -> [Option<String>; 2] {
    [
        std::fs::read_to_string("/proc/net/tcp").ok(),
        std::fs::read_to_string("/proc/net/tcp6").ok(),
    ]
}

/// `ActiveState` of [`OLS_UNIT`], or `None` when systemd did not answer.
pub fn unit_state() -> Option<String> {
    crate::provision::output(
        "/usr/bin/systemctl",
        &["show", "--property=ActiveState", "--value", OLS_UNIT],
    )
    .ok()
    .map(|text| text.trim().to_owned())
}

/// Whether the journal history before an operation leaves the host at its
/// start: nothing established, or the bootstrap generation re-established
/// by a failed and compensated (or refused) bootstrap. W360: the journal
/// re-establishes the bootstrap generation only from an empty history, so
/// a refused bootstrap after a real generation does not qualify. The
/// executor checks this before intent; the admin helper checks it again.
pub fn bootstrap_history_admits(history: &ResourceHistory) -> bool {
    let (empty, empty_digest) = bootstrap_generation();
    match history {
        ResourceHistory::Empty => true,
        ResourceHistory::Established(id, digest) => id == &empty && digest == &empty_digest,
        ResourceHistory::Unresolved => false,
    }
}

/// W362: the generation that `history` establishes for the generation
/// checks; `None` when it establishes none.
///
/// A product host starts with no `current` (W348, W355), so in the product
/// profile an empty history establishes the bootstrap generation: a
/// `current` found while the history is empty is unexplained drift, and
/// only a bootstrap activation passes. The lab profile keeps the W021
/// rule: an empty history establishes nothing, so any content-addressed
/// `current` passes (the lab VM has adopted and historical generations).
/// An unresolved operation establishes nothing in both profiles.
pub fn established_generation(history: ResourceHistory) -> Option<(Id, Sha256Digest)> {
    match history {
        ResourceHistory::Established(id, digest) => Some((id, digest)),
        ResourceHistory::Empty if cfg!(rustiron_profile = "product") => {
            Some(bootstrap_generation())
        }
        ResourceHistory::Empty | ResourceHistory::Unresolved => None,
    }
}

/// Where in the bootstrap activation the facts are checked.
#[derive(Clone, Copy, Debug)]
pub enum BootstrapStage<'a> {
    /// Before any effect: `current` must not exist.
    BeforeSwitch,
    /// At the start step: `current` must be exactly the journaled target.
    Start(&'a (Id, Sha256Digest)),
}

/// Everything the bootstrap decision reads. Installed and enrolled are the
/// preconditions of observing at all: a trusted include directory and an
/// enrolled OLS policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapFacts {
    /// What the journal established for the OLS resource before this
    /// operation. Only [`ResourceHistory::Empty`] or the bootstrap
    /// generation (a failed and compensated bootstrap) qualify.
    pub history: ResourceHistory,
    /// `current` (`None`: absent).
    pub current: Option<(Id, Sha256Digest)>,
    /// `ActiveState` of [`OLS_UNIT`].
    pub unit_state: Option<String>,
    /// W364: `KillMode` of [`OLS_UNIT`]. The first start needs the shipped
    /// value, so that its compensation can stop every OLS process.
    pub kill_mode: Option<String>,
    /// The parent is the enrolled reviewed one: digest, the D-028 limits,
    /// root-owned, one link and immutable.
    pub parent_reviewed: bool,
    /// Nothing listens on the enrolled listener or WebAdmin port.
    pub ports_closed: bool,
    /// Adopted vhosts are pinned, as on a running host.
    pub adopted_vhosts_pinned: bool,
    /// PHP children cover every OLS worker (W212), as on a running host.
    pub php_capacity: bool,
}

impl BootstrapFacts {
    /// Whether the host is in the bootstrap state at `stage`. Each fact is
    /// required; any one missing keeps the running-host behaviour.
    pub fn hold(&self, stage: BootstrapStage<'_>) -> bool {
        let history = bootstrap_history_admits(&self.history);
        let include = match stage {
            BootstrapStage::BeforeSwitch => self.current.is_none(),
            BootstrapStage::Start(target) => self.current.as_ref() == Some(target),
        };
        history
            && include
            && unit_stopped(self.unit_state.as_deref())
            && kill_mode_shipped(self.kill_mode.as_deref())
            && self.parent_reviewed
            && self.ports_closed
            && self.adopted_vhosts_pinned
            && self.php_capacity
    }

    /// W382 (D-033): whether the host is the bootstrap predecessor of an
    /// interrupted bootstrap activation, so that `reconcile` may record it:
    /// the history before the operation admits a bootstrap, no `current`
    /// exists, OLS is stopped, nothing listens on the enrolled listener or
    /// WebAdmin port, and the parent is the reviewed one. The facts that
    /// only a start needs (`KillMode`, adopted vhosts, PHP capacity) do not
    /// decide whether OLS serves anything, so they do not count. A `current`
    /// that names the journaled target is refused: the boot guard, or the
    /// signed restore, removes it first.
    pub fn predecessor_confirmed(&self) -> bool {
        bootstrap_history_admits(&self.history)
            && self.current.is_none()
            && unit_stopped(self.unit_state.as_deref())
            && self.ports_closed
            && self.parent_reviewed
    }

    /// Reads the live facts. `ports` are the enrolled listener and WebAdmin
    /// ports; `adopted` the enrolled adopted vhost names.
    pub fn observe(
        history: ResourceHistory,
        include: &OwnedFd,
        parent_sha256: &Sha256Digest,
        ports: &[u16],
        adopted: &[&str],
    ) -> Result<Self, ExecutorError> {
        Ok(Self {
            history,
            current: observe_current(include)?,
            unit_state: unit_state(),
            kill_mode: kill_mode(),
            parent_reviewed: super::parent_reviewed(parent_sha256),
            ports_closed: ports_closed(&listener_tables(), ports),
            adopted_vhosts_pinned: super::adopted_vhosts_pinned(adopted),
            php_capacity: super::php_capacity_live(),
        })
    }
}

/// The bootstrap compensation's stop: `systemctl stop`, then a bounded wait
/// until the unit is stopped and nothing listens on `ports`. Not reaching
/// that state is a failure, so the operation stays `needs_attention`.
///
/// W364: the stop always runs, but it restores the host only with the
/// shipped `KillMode`, read before the stop. Under any other value systemd
/// does not end the processes left in the unit, so the stop is a failure.
/// The unit then ends `failed`, because the OLS main process exits 255
/// after its graceful stop (D-022); [`unit_stopped`] accepts that state.
pub fn stop_and_wait(ports: &[u16]) -> Result<(), ExecutorError> {
    let shipped = kill_mode_shipped(kill_mode().as_deref());
    crate::provision::run("/usr/bin/systemctl", &["stop", OLS_UNIT])?;
    if !shipped {
        return Err(ExecutorError::StepFailed);
    }
    let deadline = std::time::Instant::now() + STOP_WAIT;
    loop {
        if unit_stopped(unit_state().as_deref()) && ports_closed(&listener_tables(), ports) {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(ExecutorError::StepFailed);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}
