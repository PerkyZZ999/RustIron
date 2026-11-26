//! D-091 (W563): the intake check and the admin helper's step of a signed
//! `dns_zone_import`.
//!
//! The operator copies the canonical zone file to
//! `<DNS_INTAKE_DIR>/<zone>/zone.txt` (root-only). The executor checks its
//! digest and record-set count before intent; the helper reads it again by
//! descriptor and checks it again before any effect. The helper then runs
//! `pdnsutil` as the `pdns` user in a sandboxed transient unit (W561): every
//! argument is built here from the journal and the enrolled policy, and the
//! zone text goes on standard input, never as a path from a request.

use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::Path;

use rustiron_contracts::approval::{
    MAX_ZONE_BYTES, ParsedZone, RecordSet, RecordType, ZoneName, parse_zone,
};
use rustiron_journal::DnsImport;
use rustix::fs::{self, FileType, Mode, OFlags};
use rustix::io::Errno;

use crate::dns::DnsPolicy;
use crate::{ExecutorError, files};

/// The zone file's name in the zone's intake folder.
pub(crate) const ZONE_FILE: &str = "zone.txt";
const PDNSUTIL: &str = "/usr/bin/pdnsutil";
const PDNS_CONTROL: &str = "/usr/bin/pdns_control";
const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
const FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NOCTTY)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);

/// Opens `<intake_dir>/<zone>/zone.txt` with the update intake's rules: the
/// folders and the file belong to `owner`, nobody else may read them, and
/// the file is a single-link regular file of 1 byte to 1 MiB.
fn open_zone_file(
    intake_dir: &Path,
    owner: u32,
    zone: &ZoneName,
) -> Result<OwnedFd, ExecutorError> {
    let deny = ExecutorError::AccessDenied;
    let intake = files::open_trusted_directory(intake_dir, owner)?;
    let folder = files::open_child_directory(&intake, zone.as_str(), owner)?;
    if fs::fstat(&folder).map_err(|_| deny)?.st_mode & 0o077 != 0 {
        return Err(deny);
    }
    let file = match fs::openat(&folder, ZONE_FILE, FLAGS, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Err(ExecutorError::PreconditionChanged),
        Err(_) => return Err(deny),
    };
    let stat = fs::fstat(&file).map_err(|_| deny)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != owner
        || stat.st_nlink != 1
        || stat.st_mode & 0o077 != 0
    {
        return Err(deny);
    }
    let size = usize::try_from(stat.st_size).map_err(|_| deny)?;
    if size == 0 || size > MAX_ZONE_BYTES {
        return Err(ExecutorError::PreconditionChanged);
    }
    Ok(file)
}

/// Reads and parses the intake zone file, and requires the signed digest
/// and record-set count.
pub(crate) fn intake_zone(
    intake_dir: &Path,
    owner: u32,
    zone: &ZoneName,
    sha256: &rustiron_contracts::approval::Sha256Digest,
    record_sets: u32,
) -> Result<(Vec<u8>, ParsedZone), ExecutorError> {
    let mut bytes = Vec::new();
    std::fs::File::from(open_zone_file(intake_dir, owner, zone)?)
        .take(MAX_ZONE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ExecutorError::PreconditionChanged)?;
    let parsed = parse_zone(zone, &bytes).map_err(|_| ExecutorError::PreconditionChanged)?;
    if &parsed.sha256 != sha256 || parsed.record_sets.len() != record_sets as usize {
        return Err(ExecutorError::PreconditionChanged);
    }
    Ok((bytes, parsed))
}

/// The PowerDNS tools the step runs; a test replaces them.
pub(crate) trait Pdns {
    /// `pdnsutil` with fixed arguments and optional standard input; its
    /// standard output on success.
    fn util(&mut self, args: &[&str], input: Option<&[u8]>) -> Result<String, ExecutorError>;
    /// `pdns_control` with fixed arguments.
    fn control(&mut self, args: &[&str]) -> Result<(), ExecutorError>;
}

/// The host's `pdnsutil` and `pdns_control`, each as `pdns` in a sandboxed
/// transient unit.
pub(crate) struct SystemPdns;

/// The transient unit's arguments (W561): the `pdns` user, only the
/// PowerDNS state folder writable, no network, no capabilities. W564-F1:
/// no `--pipe`, which hands the helper's pipes to systemd over D-Bus;
/// standard output goes to `output` in the helper's runtime folder, and
/// standard input, when given, comes from `input` there.
pub(crate) fn unit_args(unit: &str, output: &str, input: Option<&str>) -> Vec<String> {
    let mut args: Vec<String> = ["--wait", "--quiet", "--collect"]
        .map(String::from)
        .to_vec();
    args.push(format!("--unit={unit}"));
    let mut properties = vec![
        format!("User={}", crate::dns::PDNS_USER),
        format!("Group={}", crate::dns::PDNS_USER),
        format!("ReadWritePaths={}", crate::dns::PDNS_STATE_DIR),
        "NoNewPrivileges=yes".to_owned(),
        "CapabilityBoundingSet=".to_owned(),
        "ProtectSystem=strict".to_owned(),
        "ProtectHome=yes".to_owned(),
        "PrivateTmp=yes".to_owned(),
        "PrivateDevices=yes".to_owned(),
        "PrivateNetwork=yes".to_owned(),
        "RestrictSUIDSGID=yes".to_owned(),
        "UMask=0027".to_owned(),
        "MemoryMax=256M".to_owned(),
        "RuntimeMaxSec=120".to_owned(),
        format!("StandardOutput=truncate:{output}"),
        "StandardError=null".to_owned(),
    ];
    if let Some(input) = input {
        properties.push(format!("StandardInput=file:{input}"));
    }
    for property in properties {
        args.push("--property".to_owned());
        args.push(property);
    }
    args
}

/// W564-F3: `pdns_control` runs in a transient unit as `pdns`, which owns
/// PowerDNS's control socket, so it enters `pdns_control_t` from the unit,
/// not from the helper's domain. `NoNewPrivileges` would block that
/// transition, so the unit has no capabilities and no set-ID instead. Its
/// output is not read (W564-F4: `pdns_control_t` may not write the helper's
/// runtime files).
pub(crate) fn control_args(unit: &str) -> Vec<String> {
    let mut args: Vec<String> = ["--wait", "--quiet", "--collect"]
        .map(String::from)
        .to_vec();
    args.push(format!("--unit={unit}"));
    for property in [
        format!("User={}", crate::dns::PDNS_USER),
        format!("Group={}", crate::dns::PDNS_USER),
        "CapabilityBoundingSet=".to_owned(),
        "ProtectSystem=strict".to_owned(),
        "ProtectHome=yes".to_owned(),
        "PrivateTmp=yes".to_owned(),
        "PrivateDevices=yes".to_owned(),
        "PrivateNetwork=yes".to_owned(),
        "RestrictSUIDSGID=yes".to_owned(),
        "RuntimeMaxSec=60".to_owned(),
        "StandardOutput=null".to_owned(),
        "StandardError=null".to_owned(),
    ] {
        args.push("--property".to_owned());
        args.push(property);
    }
    args
}

impl Pdns for SystemPdns {
    fn util(&mut self, args: &[&str], input: Option<&[u8]>) -> Result<String, ExecutorError> {
        use rustix::fs::{AtFlags, unlinkat};
        let mut random = [0_u8; 8];
        rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty())
            .map_err(|_| ExecutorError::Unavailable)?;
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let unit = format!("rustiron-pdns-{suffix}");
        let folder = crate::layout::ADMIN_RUNTIME_DIR;
        let output = format!("{folder}/{unit}.out");
        let input_path = format!("{folder}/{unit}.in");
        crate::capture::ensure_output_dir()?;
        let directory = files::open_traversable_directory(Path::new(folder), 0)?;
        let input_name = format!("{unit}.in");
        if let Some(bytes) = input {
            // The checked bytes themselves, never the intake path. W564-F2:
            // `pdnsutil` re-opens `/dev/stdin` as `pdns`, which checks the
            // file's own mode, so the file is 0644; only root can reach it
            // by path, inside the 0700 runtime folder.
            let fd = fs::openat(
                &directory,
                input_name.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|_| ExecutorError::StepFailed)?;
            fs::fchmod(&fd, Mode::from_raw_mode(0o644)).map_err(|_| ExecutorError::StepFailed)?;
            let mut file = std::fs::File::from(fd);
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|_| ExecutorError::StepFailed)?;
        }
        let mut argv = unit_args(&unit, &output, input.map(|_| input_path.as_str()));
        argv.push("--".to_owned());
        argv.push(PDNSUTIL.to_owned());
        argv.extend(args.iter().map(|arg| (*arg).to_owned()));
        let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
        let ran = crate::provision::run(SYSTEMD_RUN, &borrowed);
        let name = format!("{unit}.out");
        let bytes = files::read_child(&directory, &name, 0, files::Exposure::Readable, 4 << 20);
        let _ = unlinkat(&directory, name.as_str(), AtFlags::empty());
        if input.is_some() {
            let _ = unlinkat(&directory, input_name.as_str(), AtFlags::empty());
        }
        ran?;
        String::from_utf8(bytes?).map_err(|_| ExecutorError::StepFailed)
    }

    fn control(&mut self, args: &[&str]) -> Result<(), ExecutorError> {
        let mut random = [0_u8; 8];
        rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty())
            .map_err(|_| ExecutorError::Unavailable)?;
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let mut argv = control_args(&format!("rustiron-pdns-control-{suffix}"));
        argv.push("--".to_owned());
        argv.push(PDNS_CONTROL.to_owned());
        argv.extend(args.iter().map(|arg| (*arg).to_owned()));
        let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
        crate::provision::run(SYSTEMD_RUN, &borrowed)
    }
}

/// Whether `pdnsutil zone list-all` output names the zone.
fn listed(output: &str, zone: &ZoneName) -> bool {
    let apex = zone.apex();
    output
        .lines()
        .map(str::trim)
        .any(|line| line == zone.as_str() || line == apex)
}

/// `pdnsutil zone list` output as a canonical zone file: tabs become single
/// spaces, the `$ORIGIN` line goes, and lines are sorted and unique. Only
/// [`parse_zone`] decides whether the result is canonical.
pub(crate) fn canonical_listing(output: &str) -> Vec<u8> {
    let mut lines: Vec<String> = output
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('$'))
        .map(|line| line.split('\t').collect::<Vec<_>>().join(" "))
        .collect();
    lines.sort();
    lines.dedup();
    let mut text = lines.join("\n");
    text.push('\n');
    text.into_bytes()
}

fn dotted(name: &str) -> String {
    format!("{name}.")
}

/// The SOA rdata the policy sets, with `serial`.
fn soa_rdata(policy: &DnsPolicy, serial: &str) -> String {
    let soa = &policy.soa;
    format!(
        "{} {} {serial} {} {} {} {}",
        dotted(policy.name_servers[0].as_str()),
        dotted(policy.hostmaster.as_str()),
        soa.refresh,
        soa.retry,
        soa.expire,
        soa.negative_ttl
    )
}

fn apex_set(zone: &ParsedZone, kind: RecordType) -> Result<&RecordSet, ExecutorError> {
    let apex = zone.zone.apex();
    zone.record_sets
        .iter()
        .find(|set| set.owner == apex && set.kind == kind)
        .ok_or(ExecutorError::PreconditionChanged)
}

fn is_authority(set: &RecordSet, apex: &str) -> bool {
    set.owner == apex && matches!(set.kind, RecordType::Soa | RecordType::Ns)
}

/// Whether the read-back zone is the intake zone with the policy's
/// authority: every other set the same, and nothing more; the SOA's names
/// and timers and the apex NS set from the policy.
pub(crate) fn read_back_matches(
    intake: &ParsedZone,
    served: &ParsedZone,
    policy: &DnsPolicy,
) -> bool {
    let apex = intake.zone.apex();
    let others = |zone: &ParsedZone| -> Vec<RecordSet> {
        zone.record_sets
            .iter()
            .filter(|set| !is_authority(set, &apex))
            .cloned()
            .collect()
    };
    if others(intake) != others(served) {
        return false;
    }
    let (Ok(soa), Ok(ns)) = (
        apex_set(served, RecordType::Soa),
        apex_set(served, RecordType::Ns),
    ) else {
        return false;
    };
    let names: Vec<String> = {
        let mut names: Vec<String> = policy
            .name_servers
            .iter()
            .map(|name| dotted(name.as_str()))
            .collect();
        names.sort();
        names
    };
    let soa_fits = soa.records.len() == 1
        && soa.records[0]
            .split(' ')
            .nth(2)
            .is_some_and(|serial| soa.records[0] == soa_rdata(policy, serial));
    soa_fits && ns.records == names
}

/// The helper's import step: the intake file again, then the load, the
/// authority, the publication, and the read-back. Every effect is refused
/// before it starts when the zone is already on the server.
pub(crate) fn run(
    pdns: &mut impl Pdns,
    import: &DnsImport,
    policy: &DnsPolicy,
    intake_dir: &Path,
    owner: u32,
) -> Result<(), ExecutorError> {
    let zone = &import.zone;
    let (bytes, intake) = intake_zone(
        intake_dir,
        owner,
        zone,
        &import.zone_sha256,
        import.record_sets,
    )?;
    if listed(&pdns.util(&["zone", "list-all"], None)?, zone) {
        return Err(ExecutorError::PreconditionChanged);
    }
    let name = zone.as_str();
    let apex = zone.apex();
    pdns.util(&["zone", "load", name, "/dev/stdin"], Some(&bytes))?;
    pdns.util(&["zone", "set-kind", name, "primary"], None)?;
    let soa = apex_set(&intake, RecordType::Soa)?;
    let serial = soa.records[0]
        .split(' ')
        .nth(2)
        .ok_or(ExecutorError::PreconditionChanged)?;
    let soa_ttl = soa.ttl.to_string();
    let soa_content = soa_rdata(policy, serial);
    pdns.util(
        &[
            "rrset",
            "replace",
            name,
            &apex,
            "SOA",
            &soa_ttl,
            &soa_content,
        ],
        None,
    )?;
    let ns_ttl = apex_set(&intake, RecordType::Ns)?.ttl.to_string();
    let servers: Vec<String> = policy
        .name_servers
        .iter()
        .map(|server| dotted(server.as_str()))
        .collect();
    let mut ns: Vec<&str> = vec!["rrset", "replace", name, &apex, "NS", &ns_ttl];
    ns.extend(servers.iter().map(String::as_str));
    pdns.util(&ns, None)?;
    if !policy.secondaries.is_empty() {
        pdns.util(
            &["tsigkey", "activate", name, &policy.tsig_key, "primary"],
            None,
        )?;
    }
    pdns.util(&["zone", "check", name], None)?;
    pdns.util(&["zone", "increase-serial", name], None)?;
    pdns.control(&["rediscover"])?;
    let listing = canonical_listing(&pdns.util(&["zone", "list", name], None)?);
    let served = parse_zone(zone, &listing).map_err(|_| ExecutorError::StepFailed)?;
    if read_back_matches(&intake, &served, policy) {
        Ok(())
    } else {
        Err(ExecutorError::StepFailed)
    }
}

#[cfg(test)]
#[path = "dns_import_tests.rs"]
mod tests;
