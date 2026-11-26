//! D-031 (W373): the product store half of a restore probe.
//!
//! The size check and the fetch run the product store worker in the store
//! namespace, as the probe account at the probe level, with the fetch key
//! pair and the bound projection. Their units take the probe unit name, so
//! cleanup stops and lists them like every other probe unit. The repository
//! check is the capture's own `check` action (site account, site level,
//! fetch key). Nothing here takes a path, argument or command from a
//! request: the helper derives every input from the journal and the bound
//! projection.

use rustiron_contracts::approval::{ProductBackupPolicy, SiteId};

use super::{ProbeStore, ProbeTarget, Profile, unit_name, within_ceilings};
use crate::{ExecutorError, TrustAnchor, store_network};

/// The bound product destination of one probe.
pub(crate) struct ProductStore<'a> {
    /// The helper's trust anchor (policy directory and owner).
    pub anchor: &'a TrustAnchor,
    /// The projection whose digest the helper re-bound for this probe.
    pub policy: &'a ProductBackupPolicy,
    /// The probed site (the repository to read).
    pub site: &'a SiteId,
    /// The site's MCS level, for the `check` action only.
    pub site_level: &'a str,
}

impl ProbeStore for ProductStore<'_> {
    fn within_size(&self, target: &ProbeTarget<'_>) -> Result<(), ExecutorError> {
        let (size, files) = store_network::probe_restore_size(
            self.anchor,
            self.policy,
            self.site,
            target.probe,
            target.snapshot,
            unit_name(target, "size")?,
        )?;
        if within_ceilings(size, files) {
            Ok(())
        } else {
            Err(ExecutorError::StepFailed)
        }
    }

    fn fetch(&self, target: &ProbeTarget<'_>) -> Result<(), ExecutorError> {
        store_network::probe_restore(
            self.anchor,
            self.policy,
            self.site,
            target.probe,
            target.snapshot,
            unit_name(target, "fetch")?,
        )
    }

    fn check(&self, _target: &ProbeTarget<'_>) -> Result<(), ExecutorError> {
        store_network::check_structure(self.anchor, self.policy, self.site, self.site_level)
    }

    fn profile(&self) -> Profile {
        Profile::Product
    }
}
