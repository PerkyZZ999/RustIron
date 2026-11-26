//! Offline descriptions of closed operation plans.

use rustiron_contracts::approval::{
    AppDeployPlan, AppLifecyclePlan, AppProvisionPlan, CapturePlan, CertificatePlan, ChangeAction,
    CloneScrubPlan, CredentialRotatePlan, DeletePlan, DnsChangePlan, DnsImportPlan, EjectPlan,
    Expected, ImportPlan, OlsPlan, PageCacheRecipe, PlanKind, ProbePlan, ProductBackupPlan,
    ProductBackupTarget, ProxyPlan, QuotaPlan, ReadoptPlan, RestorePlan, RestoreScope, RetirePlan,
    ScrubPlan, SiteClonePlan, SitePlan, SiteUpdatePlan, envelope_for_plan,
};

/// A decoded plan: verb, digest and what it asks for as label/value lines.
pub(crate) type Description = (&'static str, String, Vec<(&'static str, String)>);

/// What a decoded plan asks for, including its P23 blast-radius envelope.
pub(crate) fn describe(bytes: &[u8]) -> Option<Description> {
    let (verb, digest, mut lines) = describe_body(bytes)?;
    if let Some(envelope) = envelope_for_plan(bytes) {
        lines.push(("blast radius", envelope.summary_line()));
        if let Some(impact) = envelope.all_site_ols_impact {
            lines.push(("all-site OLS impact", impact));
        }
    }
    Some((verb, digest, lines))
}

fn describe_body(bytes: &[u8]) -> Option<Description> {
    if let Ok(plan) = SiteClonePlan::decode(bytes) {
        let source = plan.source();
        let target = plan.target();
        return Some((
            PlanKind::SiteClone.as_str(),
            plan.digest().as_str().to_owned(),
            vec![
                ("source site", source.site_id.as_str().to_owned()),
                ("source hostname", source.hostname.as_str().to_owned()),
                ("capture operation", source.capture_operation_id.as_str().to_owned()),
                ("snapshot", source.snapshot_id.as_str().to_owned()),
                ("manifest digest", source.manifest_sha256.as_str().to_owned()),
                ("destination", source.destination_id.as_str().to_owned()),
                ("destination policy digest", source.destination_policy_digest.as_str().to_owned()),
                ("repository", source.repository_id.as_str().to_owned()),
                ("target site", target.site_id.as_str().to_owned()),
                ("target hostname", target.hostname.as_str().to_owned()),
                ("effects", "Fetches the recorded snapshot and creates a new staging site. Serving requires a separate signed activation.".to_owned()),
            ],
        ));
    }
    if let Ok(plan) = SitePlan::decode(bytes) {
        let (recipe, digest) = plan.recipe();
        // W341: v2 signs the limits; v1 leaves them to the enrolled policy.
        let quota = match plan.quota_limits() {
            Some(limits) => format!(
                "hard {} KiB, {} inodes (signed; at most the enrolled quota)",
                limits.block_hard_kib(),
                limits.inode_hard()
            ),
            None => "enrolled policy limits (plan schema 1)".to_owned(),
        };
        return Some((
            "site_provision",
            plan.digest().as_str().to_owned(),
            vec![
                ("site", plan.site_id().as_str().to_owned()),
                ("hostname", plan.hostname().as_str().to_owned()),
                ("recipe", format!("{recipe:?}")),
                ("recipe sha256", digest.as_str().to_owned()),
                ("quota", quota),
                (
                    "effects",
                    "creates an account, database and site; no traffic activation".to_owned(),
                ),
            ],
        ));
    }
    // W440 (D-053): what the signer accepts for a site import.
    if let Ok(plan) = ImportPlan::decode(bytes) {
        let limits = plan.quota_limits();
        // D-070: a renamed import says what it rewrites in the site.
        let source = match plan.source_hostname() {
            Some(source) => format!(
                "{}; the import rewrites //{} to //{} in the site's database",
                source.as_str(),
                source.as_str(),
                plan.hostname().as_str()
            ),
            None => "the same hostname".to_owned(),
        };
        let (dump, effect) = if plan.is_static() {
            (
                "none".to_owned(),
                "creates an account, empty database and site, and imports foreign files as the site",
            )
        } else {
            (
                format!("{} bytes", plan.dump_bytes()),
                "creates an account, database and site, and imports foreign code and database as the site",
            )
        };
        let mut fields = vec![
            ("site", plan.site_id().as_str().to_owned()),
            ("hostname", plan.hostname().as_str().to_owned()),
            ("source hostname", source),
        ];
        if let Some(alias) = plan.alias_hostname() {
            fields.push(("alias hostname", alias.as_str().to_owned()));
            fields.push((
                "alias serving",
                "HTTP on the enrolled loopback listener after separate activation".to_owned(),
            ));
        }
        fields.extend([
            ("archive sha256", plan.archive_sha256().as_str().to_owned()),
            (
                "manifest sha256",
                plan.manifest_sha256().as_str().to_owned(),
            ),
            (
                "files",
                format!(
                    "{} entries, {} bytes",
                    plan.file_entries(),
                    plan.file_bytes()
                ),
            ),
            ("database dump", dump),
            ("php", plan.target_php().as_str().to_owned()),
            (
                "quota",
                format!(
                    "hard {} KiB, {} inodes (signed; at most the enrolled quota)",
                    limits.block_hard_kib(),
                    limits.inode_hard()
                ),
            ),
            (
                "effects",
                format!("{effect}; no traffic activation, no DNS or mail change"),
            ),
        ]);
        return Some((
            PlanKind::SiteImport.as_str(),
            plan.digest().as_str().to_owned(),
            fields,
        ));
    }
    // W462 (D-059): what the signer accepts for a certificate.
    if let Ok(plan) = CertificatePlan::decode(bytes) {
        let mut fields = vec![
            ("site", plan.site_id().as_str().to_owned()),
            ("hostname", plan.hostname().as_str().to_owned()),
        ];
        if let Some(alias) = plan.alias_hostname() {
            fields.push(("alias hostname", alias.as_str().to_owned()));
            fields.push((
                "alias certificate support",
                "private CA and loopback listeners".to_owned(),
            ));
            fields.push((
                "standing renewal",
                plan.renew_until().map_or_else(
                    || "none".to_owned(),
                    |until| format!("through Unix timestamp {} for both hostnames", until.get()),
                ),
            ));
        }
        fields.extend([
            ("ca", "the CA directory of the enrolled policy".to_owned()),
            (
                "effects",
                "creates the site's HTTP-01 webroot, contacts the enrolled CA, and installs the certificate under /etc/rustiron-tls; serving it needs a separate config_activate; no DNS change".to_owned(),
            ),
        ]);
        return Some((
            PlanKind::CertificateIssue.as_str(),
            plan.digest().as_str().to_owned(),
            fields,
        ));
    }
    // W537 (D-078): what the signer accepts for a signed clone scrub.
    if let Ok(plan) = CloneScrubPlan::decode(bytes) {
        return Some((
            PlanKind::CloneScrub.as_str(),
            plan.digest().as_str().to_owned(),
            vec![
                ("site", plan.site_id().as_str().to_owned()),
                ("clone operation", plan.clone_operation_id().as_str().to_owned()),
                (
                    "effects",
                    "removes the quarantined clone's fetched tree, moved dump, and restored wp-config.php as the target; refused unless the clone is quarantined with no open or done scrub; deletes no site; the target's copied files and database stay".to_owned(),
                ),
            ],
        ));
    }
    // W541 (D-089): what the signer accepts for a restore of a served site.
    if let Ok(plan) = RestorePlan::decode(bytes) {
        let source = plan.source();
        let replaces = match plan.scope() {
            RestoreScope::Database => "replaces the site's whole database",
            RestoreScope::FilesAndDatabase => {
                "replaces the site's document root (its own wp-config.php stays) and its whole database"
            }
        };
        return Some((
            PlanKind::SiteRestore.as_str(),
            plan.digest().as_str().to_owned(),
            vec![
                ("site", plan.site_id().as_str().to_owned()),
                ("hostname", plan.hostname().as_str().to_owned()),
                ("scope", plan.scope().as_str().to_owned()),
                (
                    "capture operation",
                    source.capture_operation_id.as_str().to_owned(),
                ),
                ("snapshot", source.snapshot_id.as_str().to_owned()),
                (
                    "manifest sha256",
                    source.manifest_sha256.as_str().to_owned(),
                ),
                ("destination", source.destination_id.as_str().to_owned()),
                (
                    "destination policy digest",
                    source.destination_policy_digest.as_str().to_owned(),
                ),
                ("repository", source.repository_id.as_str().to_owned()),
                (
                    "safety capture operation",
                    plan.safety_capture_operation_id().as_str().to_owned(),
                ),
                (
                    "effects",
                    format!(
                        "{replaces} with the capture's, as the site, under WordPress maintenance mode; refused unless the safety capture is the site's newest succeeded one from the last 24 hours and the restored capture is older; changes made after the restored capture are lost from the site; deletes no backup and activates no traffic"
                    ),
                ),
            ],
        ));
    }
    // W553 (D-091): what the signer accepts for a change of record sets.
    if let Ok(plan) = DnsChangePlan::decode(bytes) {
        let zone = plan.zone();
        let mut lines = vec![("zone", zone.as_str().to_owned())];
        for operation in plan.operations() {
            let expected = match &operation.expected {
                Expected::Absent => "absent".to_owned(),
                Expected::Digest(digest) => digest.as_str().to_owned(),
            };
            let change = match (operation.action, operation.ttl, &operation.records) {
                (ChangeAction::Replace, Some(ttl), Some(records)) => {
                    format!("replace ttl {ttl}: {}", records.join(" | "))
                }
                _ => "remove".to_owned(),
            };
            let mail = if operation.is_mail(zone) {
                " [MAIL]"
            } else {
                ""
            };
            lines.push((
                "operation",
                format!(
                    "{} {}{mail}; expects {expected}; {change}",
                    operation.owner,
                    operation.kind.as_str()
                ),
            ));
        }
        lines.push((
            "effects",
            "replaces or removes each named record set of this owned zone, raises its SOA serial, and purges the changed names from PowerDNS's cache; refused before intent unless every set is as expected; changes no SOA or NS set, no other zone, and no registrar delegation; a set marked [MAIL] carries mail routing or sender checks".to_owned(),
        ));
        return Some((
            PlanKind::DnsChange.as_str(),
            plan.digest().as_str().to_owned(),
            lines,
        ));
    }
    // W571 (D-095): what the signer accepts for a proxy site.
    if let Ok(plan) = ProxyPlan::decode(bytes) {
        let mut lines = vec![
            ("site", plan.site_id().as_str().to_owned()),
            ("hostname", plan.hostname().as_str().to_owned()),
        ];
        for route in plan.routes() {
            lines.push((
                "route",
                format!("{} -> 127.0.0.1:{}", route.prefix, route.port),
            ));
        }
        for websocket in plan.websockets() {
            lines.push((
                "websocket",
                format!("{} -> 127.0.0.1:{}", websocket.prefix, websocket.port),
            ));
        }
        lines.push((
            "effects",
            "creates the site account and its folders (identity file, ACME webroot, maintenance page) with no PHP and no database; a separate config_activate serves the host name through OLS and forwards each route, longest prefix first, to its loopback port with the original Host; WebSockets pass only on the named paths; refused at an enrolled OLS port; starts, changes, and backs up no service behind the ports, and adds no X-Forwarded-For".to_owned(),
        ));
        return Some((
            PlanKind::ProxySiteProvision.as_str(),
            plan.digest().as_str().to_owned(),
            lines,
        ));
    }
    // W596 (D-099): P27 modern app hosting plans.
    if let Ok(plan) = AppProvisionPlan::decode(bytes) {
        let mut lines = vec![
            ("site", plan.site_id().as_str().to_owned()),
            ("hostname", plan.hostname().as_str().to_owned()),
            ("runtime", plan.runtime().as_str().to_owned()),
            ("loopback port", format!("127.0.0.1:{}", plan.port())),
            ("entrypoint", plan.entrypoint().to_owned()),
        ];
        if let Some(worker) = plan.worker_entrypoint() {
            lines.push(("worker entrypoint", worker.to_owned()));
        }
        lines.push(("health path", plan.health_path().to_owned()));
        lines.push((
            "env keys",
            if plan.env_keys().is_empty() {
                "none (names only; no secret values in plan)".to_owned()
            } else {
                format!(
                    "{} (names only; secret values live in 0400 private/app.env)",
                    plan.env_keys().join(", ")
                )
            },
        ));
        lines.push((
            "limits",
            format!(
                "{} MiB RAM, {} tasks, {} MiB quota",
                plan.memory_max_mib(),
                plan.tasks_max(),
                plan.quota_mib()
            ),
        ));
        for route in plan.routes() {
            lines.push((
                "route",
                format!("{} -> 127.0.0.1:{}", route.prefix, route.port),
            ));
        }
        for websocket in plan.websockets() {
            lines.push((
                "websocket",
                format!("{} -> 127.0.0.1:{}", websocket.prefix, websocket.port),
            ));
        }
        lines.push((
            "effects",
            "creates the site account, confined directories, SELinux MCS label, and rustiron-app@.service drop-in (plus worker unit if declared) with no PHP, no database, and no root package scripts; a separate config_activate serves the host name through OLS and a separate app_deploy activates a signed release bundle".to_owned(),
        ));
        return Some((
            PlanKind::AppProvision.as_str(),
            plan.digest().as_str().to_owned(),
            lines,
        ));
    }
    if let Ok(plan) = AppDeployPlan::decode(bytes) {
        let mut lines = vec![
            ("site", plan.site_id().as_str().to_owned()),
            ("release", plan.release_id().to_owned()),
            ("runtime", plan.runtime().as_str().to_owned()),
            (
                "artifact sha256",
                plan.artifact_sha256().as_str().to_owned(),
            ),
            (
                "manifest sha256",
                plan.manifest_sha256().as_str().to_owned(),
            ),
            (
                "bundle",
                format!(
                    "{} file(s), {} bytes",
                    plan.file_count(),
                    plan.total_bytes()
                ),
            ),
            ("health path", plan.health_path().to_owned()),
        ];
        if let Some(migration) = plan.migration_entrypoint() {
            lines.push(("migration entrypoint", migration.to_owned()));
        }
        if let Some(capture) = plan.capture_operation_id() {
            lines.push(("capture operation", capture.as_str().to_owned()));
        }
        lines.push((
            "effects",
            "verifies the signed prebuilt bundle and manifest, unpacks read-only as the site account, runs any declared bounded migration as the site, switches current atomically, restarts the app unit(s), probes loopback health, and rolls back automatically on health failure; runs no root package scripts and reloads no OLS listener".to_owned(),
        ));
        return Some((
            PlanKind::AppDeploy.as_str(),
            plan.digest().as_str().to_owned(),
            lines,
        ));
    }
    if let Ok(plan) = AppLifecyclePlan::decode(bytes) {
        return Some((
            PlanKind::AppLifecycle.as_str(),
            plan.digest().as_str().to_owned(),
            vec![
                ("site", plan.site_id().as_str().to_owned()),
                ("action", plan.action().as_str().to_owned()),
                (
                    "effects",
                    "changes only the enrolled app's systemd unit state (and companion worker if configured); changes no files, secrets, or OLS listener generation".to_owned(),
                ),
            ],
        ));
    }
    // W608 (D-100): P13 signed per-site MariaDB credential rotation.
    if let Ok(plan) = CredentialRotatePlan::decode(bytes) {
        return Some((
            PlanKind::SiteCredentialRotate.as_str(),
            plan.digest().as_str().to_owned(),
            vec![
                ("site", plan.site_id().as_str().to_owned()),
                ("hostname", plan.hostname().as_str().to_owned()),
                ("target", plan.target().as_str().to_owned()),
                (
                    "effects",
                    "generates a fresh 24-byte (48-hex-digit) random MariaDB password on the host (zero secrets in plan/grant/logs), alters only this site's MariaDB user, atomically updates 0600 private/db.cnf, restarts the site's PHP pool, and verifies DB login, old-password rejection, and HTTP health with 1 bounded compensation rollback on failure; reloads no OLS listener and accepts no arbitrary SQL".to_owned(),
                ),
            ],
        ));
    }
    // W551 (D-091): what the signer accepts for a zone import.
    if let Ok(plan) = DnsImportPlan::decode(bytes) {
        return Some((
            PlanKind::DnsZoneImport.as_str(),
            plan.digest().as_str().to_owned(),
            vec![
                ("zone", plan.zone().as_str().to_owned()),
                ("zone file sha256", plan.zone_sha256().as_str().to_owned()),
                ("record sets", plan.record_sets().to_string()),
                (
                    "effects",
                    "creates the zone on this host's PowerDNS from the canonical zone file in the intake folder, with the enrolled SOA and name servers, and keeps every mail record; the zone answers queries here at once; refused unless the zone is new to the host and the file has this digest and count; changes no other zone and no registrar delegation".to_owned(),
                ),
            ],
        ));
    }
    // W533 (D-088): what the signer accepts for a change of a site's quota.
    if let Ok(plan) = QuotaPlan::decode(bytes) {
        let limits = plan.quota_limits();
        return Some((
            PlanKind::SiteQuota.as_str(),
            plan.digest().as_str().to_owned(),
            vec![
                ("site", plan.site_id().as_str().to_owned()),
                ("hard block limit", format!("{} KiB", limits.block_hard_kib())),
                ("hard inode limit", limits.inode_hard().to_string()),
                (
                    "effects",
                    "sets the site's hard quota limits and reads them back; refused above the enrolled cap or below the site's current use; changes no file, account, database, or traffic".to_owned(),
                ),
            ],
        ));
    }
    // W520 (D-085): what the signer accepts for the deletion of a live site.
    if let Ok(plan) = DeletePlan::decode(bytes) {
        return Some((
            PlanKind::SiteDelete.as_str(),
            plan.digest().as_str().to_owned(),
            vec![
                ("site", plan.site_id().as_str().to_owned()),
                ("hostname", plan.hostname().as_str().to_owned()),
                match plan.capture_operation_id() {
                    Some(capture) => ("capture operation", capture.as_str().to_owned()),
                    // W576 (D-095): schema 2 deletes a proxy site.
                    None => (
                        "capture operation",
                        "none: refused unless the site is a proxy site (no files but its identity file; nothing behind its ports is touched)".to_owned(),
                    ),
                },
                (
                    "effects",
                    "deletes the site's account, files, database, PHP units, file contexts, quota, update intake, TLS folder and certificate keys; refused unless the site is offline and the capture is its newest succeeded one from the last 24 hours (a proxy site: no capture); the site can never be served again; deletes no backup and no DNS record; the site ID and hostname stay consumed; cannot be undone on the host".to_owned(),
                ),
            ],
        ));
    }
    // W507 (D-080): what the signer accepts for a site retirement.
    if let Ok(plan) = RetirePlan::decode(bytes) {
        return Some((
            PlanKind::SiteRetire.as_str(),
            plan.digest().as_str().to_owned(),
            vec![
                ("site", plan.site_id().as_str().to_owned()),
                ("provision operation", plan.provision_operation_id().as_str().to_owned()),
                (
                    "effects",
                    "deletes the quarantined site's account, files, database, PHP units, file contexts and quota that its recorded steps made; refused for a site that any OLS generation serves; deletes no backup; the site ID and hostname stay consumed; cannot be undone".to_owned(),
                ),
            ],
        ));
    }
    // W513 (D-084): what the signer accepts for a plugin and theme update.
    if let Ok(plan) = SiteUpdatePlan::decode(bytes) {
        let mut fields = vec![
            ("site", plan.site_id().as_str().to_owned()),
            ("recipe", plan.recipe_digest().as_str().to_owned()),
            (
                "capture operation",
                plan.capture_operation_id().as_str().to_owned(),
            ),
        ];
        fields.extend(plan.components().iter().map(|component| {
            (
                "component",
                format!(
                    "{} {} {} -> {}",
                    component.kind.as_str(),
                    component.slug.as_str(),
                    component.from_version.as_str(),
                    component.to_version.as_str()
                ),
            )
        }));
        fields.push((
            "effects",
            "replaces each named plugin or theme folder with the recipe's release, as the site, after a check of every file; refused unless each is installed at its from-version and the capture is the site's newest, from the last hour; a failed step or health check puts the old folders back and restores the site database from the capture, losing writes made since the capture; deletes no backup; no traffic change or network".to_owned(),
        ));
        return Some((
            PlanKind::SiteUpdate.as_str(),
            plan.digest().as_str().to_owned(),
            fields,
        ));
    }
    // W459 (D-057): what the signer accepts for an import scrub.
    if let Ok(plan) = ScrubPlan::decode(bytes) {
        return Some((
            PlanKind::ImportScrub.as_str(),
            plan.digest().as_str().to_owned(),
            vec![
                ("site", plan.site_id().as_str().to_owned()),
                ("import operation", plan.import_operation_id().as_str().to_owned()),
                ("archive sha256", plan.archive_sha256().as_str().to_owned()),
                (
                    "effects",
                    "removes the import's extracted export and archive copy from the site's tmp, and the intake archive; deletes no site, account, database or document root; no traffic change".to_owned(),
                ),
            ],
        ));
    }
    if let Ok(plan) = OlsPlan::decode(bytes) {
        let (generation, digest) = plan.expected();
        let sites: Vec<_> = plan.site_ids().iter().map(|site| site.as_str()).collect();
        let mut lines = vec![
            ("serve sites", sites.join(", ")),
            ("replaces generation", generation.as_str().to_owned()),
            ("expected digest", digest.as_str().to_owned()),
            (
                "effects",
                "new OLS generation, reload, all-site probes, restore on failure".to_owned(),
            ),
        ];
        // W368: schema 2 adds one page-cache opt-in.
        if let Some(opt_in) = plan.page_cache() {
            lines.push(("page cache site", opt_in.site_id().as_str().to_owned()));
            lines.push((
                "page cache recipe",
                serde_json::to_value(opt_in.recipe())
                    .ok()?
                    .as_str()?
                    .to_owned(),
            ));
            lines.push((
                "page cache recipe sha256",
                opt_in.recipe_digest().as_str().to_owned(),
            ));
            // W395: the cache-on recipe turns the page cache on.
            let effects = match opt_in.recipe() {
                PageCacheRecipe::LitespeedCache793V1 => {
                    "per-site cache storage and post-password bypass; pinned plugin unpacked \
                     (or the same pinned tree reused) and activated as the site; fixed settings \
                     stored and locked with the page cache off; existing logins ended; no network"
                }
                PageCacheRecipe::LitespeedCache793CacheOnV1 => {
                    "per-site cache storage and post-password bypass; pinned plugin unpacked \
                     (or the same pinned tree reused) and activated as the site; fixed settings \
                     stored and locked with the page cache ON for anonymous visitors; existing \
                     logins ended; an anonymous GET / must be stored and then served from the \
                     cache; no network"
                }
            };
            lines.push(("page cache effects", effects.to_owned()));
        }
        // W370: schema 3 turns one opted-in site's page cache off.
        if let Some(opt_out) = plan.page_cache_opt_out() {
            lines.push((
                "page cache opt-out site",
                opt_out.site_id().as_str().to_owned(),
            ));
            lines.push((
                "page cache recipe",
                serde_json::to_value(opt_out.recipe())
                    .ok()?
                    .as_str()?
                    .to_owned(),
            ));
            lines.push((
                "page cache effects",
                "cache storage removed from the site's server settings; plugin deactivated \
                 as the site; the site's own cache storage emptied; no network"
                    .to_owned(),
            ));
        }
        return Some(("config_activate", plan.digest().as_str().to_owned(), lines));
    }
    if let Ok(plan) = EjectPlan::decode(bytes) {
        let (generation, digest) = plan.expected();
        let mut lines = vec![
            ("site", plan.site_id().as_str().to_owned()),
            ("replaces generation", generation.as_str().to_owned()),
            ("expected digest", digest.as_str().to_owned()),
        ];
        let effects = if let Some(hostname) = plan.static_hostname() {
            lines.push(("hostname", hostname.as_str().to_owned()));
            lines.push(("runtime", "NOT_ADMITTED_FOR_EFFECT".to_owned()));
            "Writes a standalone static vhost with scripting disabled. The handover keeps the \
             served HTTP and verified TLS bindings. The executor stops and disables managed PHP \
             units and preserves site data. \
             The operator owns backups and certificate renewal."
        } else if let Some((primary, alias)) = plan.names() {
            lines.push(("hostname", primary.as_str().to_owned()));
            lines.push(("alias hostname", alias.as_str().to_owned()));
            "Writes a standalone static vhost and keeps both private-CA HTTPS names. \
             Retires the site's Rustiron PHP units and standing renewal. Preserves site data."
        } else {
            "writes a standalone vhost outside Rustiron (D-037): OLS starts the site PHP \
             as the site account; stops and disables the site's Rustiron PHP units; the \
             site then has no SELinux category, PHP sandbox, network refusal, or cgroup \
             limit; nothing deleted"
        };
        lines.push(("effects", effects.to_owned()));
        return Some(("site_eject", plan.digest().as_str().to_owned(), lines));
    }
    if let Ok(plan) = ReadoptPlan::decode(bytes) {
        // W372: every field, the previous epoch and the evidence digest, so
        // the signer can compare them with the archived output.
        let mut lines = vec![("form", plan.form().as_str().to_owned())];
        if let Some((site, hostname, limits)) = plan.site() {
            lines.push(("site", site.as_str().to_owned()));
            lines.push(("hostname", hostname.as_str().to_owned()));
            lines.push((
                "quota",
                format!(
                    "hard {} KiB, {} inodes (must equal the live quota; at most the enrolled quota)",
                    limits.block_hard_kib(),
                    limits.inode_hard()
                ),
            ));
        }
        if let Some((generation, digest, sites)) = plan.generation() {
            let sites: Vec<_> = sites.iter().map(|site| site.as_str()).collect();
            lines.push(("live generation", generation.as_str().to_owned()));
            lines.push(("generation digest", digest.as_str().to_owned()));
            lines.push(("served sites", sites.join(", ")));
        }
        lines.push(("previous epoch", plan.previous_epoch().as_str().to_owned()));
        lines.push((
            "evidence sha256",
            plan.evidence_sha256().as_str().to_owned(),
        ));
        lines.push((
            "allocation floor",
            plan.allocation_floor().map_or_else(
                || "none".to_owned(),
                |floor| format!("uid {}, category {}", floor.uid(), floor.category()),
            ),
        ));
        lines.push((
            "effects",
            "records ownership after the executor verifies the host; creates, changes and deletes nothing; no compensation"
                .to_owned(),
        ));
        return Some(("site_readopt", plan.digest().as_str().to_owned(), lines));
    }
    if let Ok(plan) = CapturePlan::decode(bytes) {
        let (destination, recipe) = plan.target();
        return Some((
            "backup_capture",
            plan.digest().as_str().to_owned(),
            vec![
                ("site", plan.site_id().as_str().to_owned()),
                ("destination", format!("{destination:?}")),
                ("recipe", format!("{recipe:?}")),
                (
                    "effects",
                    "adds one encrypted snapshot; deletes nothing".to_owned(),
                ),
            ],
        ));
    }
    if let Ok(plan) = ProbePlan::decode(bytes) {
        return Some((
            "restore_probe",
            plan.digest().as_str().to_owned(),
            vec![
                ("site", plan.site_id().as_str().to_owned()),
                ("snapshot", plan.snapshot_id().as_str().to_owned()),
                ("profile", format!("{:?}", plan.profile())),
                (
                    "effects",
                    "throwaway sandbox restore and check; source untouched".to_owned(),
                ),
            ],
        ));
    }
    let plan = ProductBackupPlan::decode(bytes).ok()?;
    let mut lines = vec![
        ("site", plan.site_id().as_str().to_owned()),
        ("destination", plan.destination_id().as_str().to_owned()),
        (
            "destination policy sha256",
            plan.destination_policy_digest().as_str().to_owned(),
        ),
    ];
    let verb = match plan.target() {
        ProductBackupTarget::BackupCapture { recipe_id } => {
            lines.push((
                "recipe",
                serde_json::to_value(recipe_id).ok()?.as_str()?.to_owned(),
            ));
            PlanKind::BackupCapture
        }
        ProductBackupTarget::RestoreProbe {
            snapshot_id,
            profile_id,
        } => {
            lines.push(("snapshot", snapshot_id.as_str().to_owned()));
            lines.push((
                "profile",
                serde_json::to_value(profile_id).ok()?.as_str()?.to_owned(),
            ));
            PlanKind::RestoreProbe
        }
    };
    Some((verb.as_str(), plan.digest().as_str().to_owned(), lines))
}
