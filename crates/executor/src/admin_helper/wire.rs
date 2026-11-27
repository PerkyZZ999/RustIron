//! Exact line encoding of the executor/admin-helper wire (W171, W202).
//!
//! Shared by the helper, its executor client and the fuzz workspace, which
//! includes this file by path (W272; `rustiron-contracts` only). Decoding
//! grants no authority: the helper still checks the kernel peer, rereads the
//! journal and authorizes; the executor still interprets the reply code.

use rustiron_contracts::{Id, approval::SiteId};

/// Longest accepted request line, including the trailing newline.
pub const MAX_ADMIN_REQUEST_BYTES: usize = 128;
/// Longest accepted reply line (a probe receipt is the largest payload).
pub const MAX_ADMIN_REPLY_BYTES: usize = 8 * 1024 * 1024;
const VERSION: &str = "v1";

/// The closed set of administrative steps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminStep {
    /// Run the provision step the journal records as current (W173). Which
    /// effect runs is read from the journal, never from the request.
    ProvisionStep,
    /// Run the journaled capture: dump, snapshot, check, dump removal (W174).
    CaptureRun,
    /// Run the journaled restore probe and its cleanup (W174).
    ProbeRun,
    /// Before an OLS activation's effect: the server-root and listener-table
    /// drift checks (W200).
    OlsPreflight,
    /// After the switch: `openlitespeed -t` (W200).
    OlsConfigTest,
    /// After the switch or the compensating switch back: the fixed
    /// `lshttpd` reload (W200).
    OlsReload,
    /// After a reload: every site of the generation the journal names must
    /// answer with its identity, and the parent must still be reviewed (W200).
    OlsVerify,
    /// W355: after the switch of a bootstrap activation, the fixed `lshttpd`
    /// start, only while the helper finds the bootstrap facts.
    OlsStart,
    /// W355: during the compensation of a bootstrap activation, the fixed
    /// `lshttpd` stop and a bounded wait for the stopped state.
    OlsStop,
    /// W368: after a verified activation that opts a site in to the page
    /// cache, the fixed plugin install as that site. The site comes from the
    /// journaled opt-in, never from the request.
    PageCacheInstall,
    /// W370: the fixed page-cache removal for one site: deactivate the
    /// plugin as the site and empty the site's own cache storage. After the
    /// verified activation of an opt-out, or after the one compensating
    /// restore of any page-cache change. The site comes from the journal.
    PageCacheRemove,
    /// W372: the read-only facts of a `verifying` re-adoption. The site, or
    /// the generation's sites, come from the journaled plan, never from the
    /// request. Nothing is changed.
    ReadoptObserve,
    /// W382 (D-033): the read-only bootstrap facts of an unresolved
    /// bootstrap activation, for `reconcile`. The helper confirms the
    /// bootstrap predecessor (OLS stopped, both ports closed, no `current`,
    /// the parent reviewed, the history before the operation) and changes
    /// nothing.
    OlsBootstrapConfirm,
    /// W387 (D-037): after the switch and reload of a `site_eject`, the
    /// fixed stop and disable of the ejected site's Rustiron PHP socket,
    /// service, and sandbox timer, then a PHP answer through the listener,
    /// which OLS now starts itself. The site comes from the journaled
    /// ejection, never from the request.
    EjectPhpStop,
    /// W387 (D-037): during the one compensation of a `site_eject`, or the
    /// reconcile of an attempted one, on the restored predecessor: the fixed
    /// enable and start of the site's Rustiron PHP socket and sandbox timer.
    EjectPhpRestore,
    /// W457 (D-057): remove an ended import's leftover secrets in the site's
    /// `tmp`: the extracted export and the archive copy, by an unpack job as
    /// the site. Only for the open scrub that the journal records.
    ImportScrub,
    /// W462 (D-059): the journal's open `certificate_issue`: create the
    /// site's HTTP-01 webroot, check that it is served, run certbot as
    /// `rustiron-acme`, check the chain, and install it. The reply carries
    /// the installed chain's SHA-256 and its expiry.
    CertificateIssue,
    /// W464 (D-060): the journal's open renewal of an issuance, under its
    /// standing grant: the same steps as [`Self::CertificateIssue`] for the
    /// issuance's site and hostname.
    CertificateRenew,
    /// W501 (D-078): remove a failed clone's fetched tree, its moved dump,
    /// and the restored `wp-config.php`, by an unpack job as the target.
    /// Only for the open scrub that the journal records.
    CloneScrub,
    /// W508 (D-080): remove what a quarantined provision's recorded steps
    /// made, for the open retirement that the journal records.
    SiteRetire,
    /// W516 (D-084): the open step of the journal's update: unpack, swap,
    /// script, or health.
    UpdateStep,
    /// W516 (D-084): the open rollback of the journal's update.
    UpdateRollback,
    /// W522 (D-085): remove a deleted site from the host, for the open
    /// deletion that the journal records.
    SiteDelete,
    /// W530 (D-087): report a served site's installed core, plugins, and
    /// themes, read only, as the site.
    UpdateInventory,
    /// W535 (D-088): set the hard limits of the site's open signed quota
    /// change and read them back.
    SiteQuotaSet,
    /// W543 (D-089): the open step of the journal's open restore attempt:
    /// maintenance, fetch, database, files, reopen, or health.
    RestoreStep,
    /// W563 (D-091): load the open zone import's intake file into
    /// PowerDNS, set its authority from the policy, publish it, and read it
    /// back.
    DnsImport,
    /// W565 (D-091): list an owned zone, read only, under its done import.
    DnsZoneRead,
    /// W565 (D-091): apply the open signed record change while every named
    /// set is still what was read before intent, and read it back.
    DnsChange,
    /// W598 (D-099): run the open step of the journal's `app_deploy`
    /// (`unpack`, `migrate`, `activate`, `health`, or `rollback`).
    AppDeployStep,
    /// W659 (D-102): render, validate, and atomically activate the Caddy
    /// generation after a healthy Caddy app deploy (and drain the previous
    /// blue/green slot when applicable).
    AppCaddyActivate,
    /// W598 (D-099): apply the open signed `app_lifecycle` unit state change.
    AppLifecycle,
    /// W609 (D-100): rotate a live WordPress site's MariaDB password and
    /// `private/db.cnf`, restart site PHP, verify new login & old rejection,
    /// and compensate once on failure.
    SiteCredentialRotate,
    /// W609 (D-100): read-only verification of `private/db.cnf` login and live
    /// WordPress health before operator reconciliation settles a rotation.
    SiteCredentialVerify,
}

impl AdminStep {
    /// Every step, in wire order.
    pub const ALL: [Self; 34] = [
        Self::ProvisionStep,
        Self::CaptureRun,
        Self::ProbeRun,
        Self::OlsPreflight,
        Self::OlsConfigTest,
        Self::OlsReload,
        Self::OlsVerify,
        Self::OlsStart,
        Self::OlsStop,
        Self::PageCacheInstall,
        Self::PageCacheRemove,
        Self::ReadoptObserve,
        Self::OlsBootstrapConfirm,
        Self::EjectPhpStop,
        Self::EjectPhpRestore,
        Self::ImportScrub,
        Self::CertificateIssue,
        Self::CertificateRenew,
        Self::CloneScrub,
        Self::SiteRetire,
        Self::UpdateStep,
        Self::UpdateRollback,
        Self::SiteDelete,
        Self::UpdateInventory,
        Self::SiteQuotaSet,
        Self::RestoreStep,
        Self::DnsImport,
        Self::DnsZoneRead,
        Self::DnsChange,
        Self::AppDeployStep,
        Self::AppCaddyActivate,
        Self::AppLifecycle,
        Self::SiteCredentialRotate,
        Self::SiteCredentialVerify,
    ];

    /// Exact wire name.
    pub fn name(self) -> &'static str {
        match self {
            Self::ProvisionStep => "provision_step",
            Self::CaptureRun => "capture_run",
            Self::ProbeRun => "probe_run",
            Self::OlsPreflight => "ols_preflight",
            Self::OlsConfigTest => "ols_config_test",
            Self::OlsReload => "ols_reload",
            Self::OlsVerify => "ols_verify",
            Self::OlsStart => "ols_start",
            Self::OlsStop => "ols_stop",
            Self::PageCacheInstall => "page_cache_install",
            Self::PageCacheRemove => "page_cache_remove",
            Self::ReadoptObserve => "readopt_observe",
            Self::OlsBootstrapConfirm => "ols_bootstrap_confirm",
            Self::EjectPhpStop => "eject_php_stop",
            Self::EjectPhpRestore => "eject_php_restore",
            Self::ImportScrub => "import_scrub",
            Self::CertificateIssue => "certificate_issue",
            Self::CertificateRenew => "certificate_renew",
            Self::CloneScrub => "clone_scrub",
            Self::SiteRetire => "site_retire",
            Self::UpdateStep => "update_step",
            Self::UpdateRollback => "update_rollback",
            Self::SiteDelete => "site_delete",
            Self::UpdateInventory => "update_inventory",
            Self::SiteQuotaSet => "site_quota_set",
            Self::RestoreStep => "restore_step",
            Self::DnsImport => "dns_import",
            Self::DnsZoneRead => "dns_zone_read",
            Self::DnsChange => "dns_change",
            Self::AppDeployStep => "app_deploy_step",
            Self::AppCaddyActivate => "app_caddy_activate",
            Self::AppLifecycle => "app_lifecycle",
            Self::SiteCredentialRotate => "site_credential_rotate",
            Self::SiteCredentialVerify => "site_credential_verify",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|step| step.name() == name)
    }
}

/// One syntactically valid helper request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminRequest {
    /// Journaled operation the step belongs to.
    pub operation_id: Id,
    /// Requested fixed step.
    pub step: AdminStep,
}

impl AdminRequest {
    /// Exact wire bytes: `v1 <operation_id> <step>\n`.
    pub fn encode(&self) -> Vec<u8> {
        format!(
            "{VERSION} {} {}\n",
            self.operation_id.as_str(),
            self.step.name()
        )
        .into_bytes()
    }

    /// Accepts only the exact encoding of some request; anything else,
    /// including the bounded-size violation, is `None`.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_ADMIN_REQUEST_BYTES {
            return None;
        }
        let line = std::str::from_utf8(bytes).ok()?.strip_suffix('\n')?;
        let mut fields = line.split(' ');
        let (Some(VERSION), Some(id), Some(step), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return None;
        };
        let operation_id = Id::try_from(id.to_owned()).ok()?;
        let step = AdminStep::from_name(step)?;
        Some(Self { operation_id, step })
    }
}

/// The one request without an operation (W202): read-only server checks for
/// `ols-status`. Exact bytes only; it never reads the journal or runs a step.
pub const OLS_STATUS_REQUEST: &[u8] = b"v1 ols_status\n";

/// Whether `bytes` is exactly [`OLS_STATUS_REQUEST`].
pub fn is_ols_status(bytes: &[u8]) -> bool {
    bytes == OLS_STATUS_REQUEST
}

/// W372: the second request without an operation, for the collision check
/// of `site_provision` before intent: `v1 site_root <site_id>\n`. The helper
/// derives the path from the site ID grammar and answers `ok present` or
/// `ok absent`; it never reads the journal or runs a step. A site ID has no
/// `_`, and every step name has one, so this line never decodes as a step.
pub fn site_root_request(site: &SiteId) -> Vec<u8> {
    format!("{VERSION} site_root {}\n", site.as_str()).into_bytes()
}

/// The site of an exact [`site_root_request`] line, or `None`.
pub fn decode_site_root(bytes: &[u8]) -> Option<SiteId> {
    if bytes.len() > MAX_ADMIN_REQUEST_BYTES {
        return None;
    }
    let line = std::str::from_utf8(bytes).ok()?.strip_suffix('\n')?;
    let site = line.strip_prefix("v1 site_root ")?;
    let site = SiteId::try_from(site.to_owned()).ok()?;
    (site_root_request(&site) == bytes).then_some(site)
}

/// One reply line before its code is interpreted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplyLine<'a> {
    /// `ok\n`, or `ok <payload>\n`.
    Done(Option<&'a str>),
    /// Any other single line: a stable error code if the reader knows it,
    /// otherwise an unknown outcome.
    Code(&'a str),
}

impl ReplyLine<'_> {
    /// Exact reply text, newline included. The helper never sends a payload
    /// or code containing a newline; such a line would decode as unreadable.
    pub fn encode(self) -> String {
        match self {
            Self::Done(None) => "ok\n".to_owned(),
            Self::Done(Some(payload)) => format!("ok {payload}\n"),
            Self::Code(code) => format!("{code}\n"),
        }
    }
}

/// Splits one reply. `None` means unreadable: oversized, not exactly one
/// newline-terminated line. The caller treats that as an unknown outcome.
pub fn decode_reply(reply: &str) -> Option<ReplyLine<'_>> {
    if reply.len() > MAX_ADMIN_REPLY_BYTES {
        return None;
    }
    let line = reply
        .strip_suffix('\n')
        .filter(|line| !line.contains('\n'))?;
    if line == "ok" {
        return Some(ReplyLine::Done(None));
    }
    if let Some(payload) = line.strip_prefix("ok ") {
        return Some(ReplyLine::Done(Some(payload)));
    }
    Some(ReplyLine::Code(line))
}
