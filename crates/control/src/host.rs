//! Read-only, unprivileged host status for the console: kernel counters,
//! root filesystem space and the state of a fixed set of systemd units. Every
//! path and argument is a compiled constant; no caller input reaches a file
//! name or a command line. Unreadable facts are reported as unknown (null).

use rustiron_contracts::{ErrorCode, MAX_RESPONSE_BYTES, local};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};

const SYSTEMCTL: &str = "/usr/bin/systemctl";
const TIMEDATECTL: &str = "/usr/bin/timedatectl";
const RPM: &str = "/usr/bin/rpm";
const MAX_PROC_BYTES: usize = 64 * 1024;
const MAX_UNITS: usize = 64;
const MAX_STATUS_BYTES: usize = 256 * 1024;
const MAX_SAMPLES: usize = 2880;
const SAMPLE_SCHEMA: &str = "rustiron-host-samples/1";
const OBSERVATION_SCHEMA: &str = "rustiron-lab-observation/1";
const STATUS_SCHEMA: &str = "rustiron-host-status/1";

/// Units the lab profile depends on, in display order.
const UNITS: [(&str, &str); 14] = [
    ("lshttpd.service", "OpenLiteSpeed web server"),
    ("rustiron-caddy.service", "Caddy edge ingress"),
    ("mariadb.service", "MariaDB database"),
    ("postgresql-18.service", "PostgreSQL 18 database"),
    (
        "rustiron-s02-lab-executor.service",
        "Rustiron executor (lab)",
    ),
    // W465 (P04): the product units; a unit absent on this host is skipped
    // by its load state.
    ("rustiron-executor.service", "Rustiron executor"),
    (
        "rustiron-admin-helper.service",
        "Rustiron administration helper",
    ),
    ("rustiron-coordinator.service", "Rustiron coordinator"),
    ("sshd.service", "OpenSSH server"),
    ("firewalld.service", "Firewall"),
    ("crond.service", "Scheduled jobs (cron)"),
    ("chronyd.service", "Time synchronisation"),
    ("auditd.service", "Security audit log"),
    ("logrotate.timer", "Log rotation"),
];
/// Per-site PHP pools, listed by pattern so new sites appear on their own.
const SITE_PHP: &str = "rustiron-site-php@*.service";
/// Lab executor unit. Its SELinux context is read from the process, not changed.
const EXECUTOR_UNIT: &str = "rustiron-s02-lab-executor.service";
/// Active generation map. The path is fixed. The file text is not returned.
pub(crate) const OLS_MAP: &str = "/etc/rustiron-ols/current/vhosts.conf";

pub(crate) fn read_small(path: &str) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    (text.len() <= MAX_PROC_BYTES).then_some(text)
}

fn meminfo_bytes(text: &str, key: &str) -> Option<u64> {
    let line = text.lines().find(|line| line.starts_with(key))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    kib.checked_mul(1024)
}

fn loadavg(text: &str) -> Option<[f64; 3]> {
    let mut parts = text.split_whitespace().map(|part| part.parse::<f64>().ok());
    Some([parts.next()??, parts.next()??, parts.next()??])
}

fn os_field(text: &str, key: &str) -> Option<String> {
    text.lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
        .map(|value| value.trim_matches('"').chars().take(128).collect())
}

fn inode_counts(total: u64, available: u64) -> (Option<u64>, Option<u64>) {
    if total == 0 || available > total {
        (None, None)
    } else {
        (Some(total), Some(available))
    }
}

fn disk(path: &str) -> Value {
    match rustix::fs::statvfs(path) {
        Ok(stat) => {
            let (inode_total, inode_available) = inode_counts(stat.f_files, stat.f_favail);
            json!({
                "path": path,
                "total_bytes": stat.f_blocks.saturating_mul(stat.f_frsize),
                "available_bytes": stat.f_bavail.saturating_mul(stat.f_frsize),
                "inode_total": inode_total,
                "inode_available": inode_available,
            })
        }
        Err(_) => json!({
            "path": path,
            "total_bytes": null,
            "available_bytes": null,
            "inode_total": null,
            "inode_available": null,
        }),
    }
}

/// `systemctl show` output for fixed units; one `key=value` block per unit.
fn show(units: &[&str]) -> Vec<Value> {
    if units.is_empty() {
        return Vec::new();
    }
    let output = Command::new(SYSTEMCTL)
        .args([
            "show",
            "--timestamp=unix",
            "-p",
            "Id,LoadState,ActiveState,SubState,ActiveEnterTimestamp,LastTriggerUSec,MainPID",
        ])
        .args(units)
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    let Ok(output) = output else {
        return units.iter().map(|unit| unknown_unit(unit)).collect();
    };
    let text = String::from_utf8_lossy(&output.stdout);
    text.split("\n\n")
        .filter(|block| !block.trim().is_empty())
        .take(MAX_UNITS)
        .map(|block| {
            let get = |key: &str| {
                block
                    .lines()
                    .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
                    .map(str::to_owned)
            };
            let since = get("ActiveEnterTimestamp")
                .as_deref()
                .and_then(systemd_unix);
            let last_trigger = get("LastTriggerUSec").as_deref().and_then(systemd_unix);
            json!({
                "unit": get("Id"),
                "load": get("LoadState"),
                "active": get("ActiveState"),
                "sub": get("SubState"),
                "since": since,
                "last_trigger": last_trigger,
                "selinux_context": context_for_main_pid(get("MainPID").as_deref()),
            })
        })
        .collect()
}

/// `timedatectl` prints `yes` or `no`. Anything else, including a missing
/// binary, stays unknown.
fn parse_ntp_synchronized(text: &str) -> Option<bool> {
    match text.trim() {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

fn ssh_token(value: &str) -> Option<String> {
    let token = value.split_whitespace().next()?;
    if token.is_empty()
        || token.len() > 64
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return None;
    }
    Some(token.to_owned())
}

/// Effective `sshd -T` lines. Only the four fixed keys are kept. A failed
/// command, including a config the process cannot read, is not a policy.
fn parse_sshd_effective(text: &str) -> Value {
    let mut permit_root_login = None;
    let mut password_authentication = None;
    let mut pubkey_authentication = None;
    let mut kbd_interactive_authentication = None;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else {
            continue;
        };
        let Some(value) = parts.next().and_then(ssh_token) else {
            continue;
        };
        match key {
            "permitrootlogin" => permit_root_login = Some(value),
            "passwordauthentication" => password_authentication = Some(value),
            "pubkeyauthentication" => pubkey_authentication = Some(value),
            "kbdinteractiveauthentication" => kbd_interactive_authentication = Some(value),
            _ => {}
        }
    }
    let readable = permit_root_login.is_some()
        || password_authentication.is_some()
        || pubkey_authentication.is_some()
        || kbd_interactive_authentication.is_some();
    json!({
        "readable": readable,
        "permit_root_login": permit_root_login,
        "password_authentication": password_authentication,
        "pubkey_authentication": pubkey_authentication,
        "kbd_interactive_authentication": kbd_interactive_authentication,
    })
}

/// Count TCP listeners on `port` in a `/proc/net/tcp` table. State `0A` is
/// listen. The address is not returned.
fn count_listeners(text: &str, port: u16) -> u64 {
    text.lines()
        .filter_map(|line| {
            let mut columns = line.split_whitespace();
            let _slot = columns.next()?;
            let local = columns.next()?;
            let _remote = columns.next()?;
            let state = columns.next()?;
            let port_hex = local.rsplit_once(':')?.1;
            let parsed_port = u16::from_str_radix(port_hex, 16).ok()?;
            let parsed_state = u8::from_str_radix(state, 16).ok()?;
            (parsed_port == port && parsed_state == 0x0A).then_some(1_u64)
        })
        .sum()
}

/// W569 (W558-F1): whether a `/proc/net/tcp{,6}` local address is loopback:
/// 127.0.0.0/8, `::1`, or `::ffff:127.0.0.0/104`. The kernel prints each
/// 32-bit word in host order (little-endian here), so 127.x.x.x ends in
/// `7F`.
fn loopback_hex(address: &str) -> bool {
    match address.len() {
        8 => address.ends_with("7F"),
        32 => {
            address == "00000000000000000000000001000000"
                || (address.starts_with("0000000000000000FFFF0000") && address.ends_with("7F"))
        }
        _ => false,
    }
}

/// W569: listening sockets on `port` whose address is not loopback.
fn count_exposed_listeners(text: &str, port: u16) -> u64 {
    text.lines()
        .filter_map(|line| {
            let mut columns = line.split_whitespace();
            let _slot = columns.next()?;
            let local = columns.next()?;
            let _remote = columns.next()?;
            let state = columns.next()?;
            let (address, port_hex) = local.rsplit_once(':')?;
            let parsed_port = u16::from_str_radix(port_hex, 16).ok()?;
            let parsed_state = u8::from_str_radix(state, 16).ok()?;
            (parsed_port == port && parsed_state == 0x0A && !loopback_hex(address)).then_some(1_u64)
        })
        .sum()
}

/// W569: MariaDB's TCP listeners beyond loopback, from `/proc/net/tcp` and
/// `/proc/net/tcp6`, which any account may read. `None` when unreadable.
fn exposed_listeners_on(port: u16) -> Option<u64> {
    let mut seen = false;
    let mut total = 0u64;
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(bytes) = fs::read(path) else {
            continue;
        };
        if bytes.len() > 1024 * 1024 {
            return None;
        }
        let Ok(text) = String::from_utf8(bytes) else {
            return None;
        };
        seen = true;
        total = total.saturating_add(count_exposed_listeners(&text, port));
    }
    seen.then_some(total)
}

fn listeners_on(port: u16) -> Option<u64> {
    let mut seen = false;
    let mut total = 0u64;
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(bytes) = fs::read(path) else {
            continue;
        };
        if bytes.len() > 1024 * 1024 {
            return None;
        }
        let Ok(text) = String::from_utf8(bytes) else {
            return None;
        };
        seen = true;
        total = total.saturating_add(count_listeners(&text, port));
    }
    seen.then_some(total)
}

fn firewall_token(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return None;
    }
    Some(value.to_owned())
}

fn parse_firewall(state: &str, zone: &str, services: &str) -> Value {
    let state = match state.trim() {
        "running" => "running",
        "not running" => "not running",
        _ => return unread_firewall(),
    };
    let Some(default_zone) = firewall_token(zone.trim()) else {
        return unread_firewall();
    };
    let mut names = Vec::new();
    for name in services.split_whitespace() {
        let Some(token) = firewall_token(name) else {
            return unread_firewall();
        };
        names.push(token);
        if names.len() == 32 {
            break;
        }
    }
    json!({
        "readable": true,
        "state": state,
        "default_zone": default_zone,
        "services": names,
    })
}

fn unread_firewall() -> Value {
    json!({
        "readable": false,
        "state": null,
        "default_zone": null,
        "services": null,
    })
}

fn firewall_output(args: &[&str]) -> Option<String> {
    let output = Command::new("/usr/bin/firewall-cmd")
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

const MARIADB_SOCKET: &str = "/var/lib/mysql/mysql.sock";

/// `mariadb-admin ping` exits 0 when the server answers, including an
/// authentication refusal. That is not a successful query.
fn database_ping(ran: bool, success: bool) -> Value {
    let ping = if !ran {
        "unknown"
    } else if success {
        "responding"
    } else {
        "not_responding"
    };
    json!({
        "socket": MARIADB_SOCKET,
        "ping": ping,
    })
}

fn version_after(text: &str, marker: &str) -> Option<String> {
    let rest = text.split_once(marker)?.1;
    let token: String = rest
        .chars()
        .take_while(|character| character.is_ascii_digit() || *character == '.')
        .collect();
    if token.is_empty()
        || token.len() > 32
        || token.starts_with('.')
        || token.ends_with('.')
        || token.contains("..")
    {
        return None;
    }
    Some(token)
}

fn command_version(program: &str, args: &[&str], marker: &str) -> Option<String> {
    let output = Command::new(program)
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    version_after(&String::from_utf8_lossy(&output.stdout), marker)
}

/// Parses `lsphp -m` output into sorted distinct lowercase PHP extension names.
/// Skips blank lines and `[PHP Modules]` / `[Zend Modules]` section headers;
/// refuses unexpected or malformed tokens so the host observation never guesses.
fn parse_php_modules(text: &str) -> Option<Vec<String>> {
    let mut modules = std::collections::BTreeSet::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || (line.starts_with('[') && line.ends_with(']')) {
            continue;
        }
        let normalized = line.to_ascii_lowercase().replace(' ', "_");
        let bytes = normalized.as_bytes();
        if !(1..=32).contains(&bytes.len())
            || !bytes[0].is_ascii_lowercase()
            || !bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
        {
            return None;
        }
        modules.insert(normalized);
        if modules.len() > 256 {
            return None;
        }
    }
    (!modules.is_empty()).then(|| modules.into_iter().collect())
}

fn php_modules(program: &str) -> Option<Vec<String>> {
    let output = Command::new(program)
        .arg("-m")
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() || output.stdout.len() > 64 * 1024 {
        return None;
    }
    let text = std::str::from_utf8(&output.stdout).ok()?;
    parse_php_modules(text)
}

/// Extracts sorted distinct `rs_*` site account names from `/etc/passwd`.
fn site_accounts_from_passwd(text: &str) -> Vec<String> {
    let mut accounts = std::collections::BTreeSet::new();
    for line in text.lines() {
        let Some(name) = line.split(':').next() else {
            continue;
        };
        if name.starts_with("rs_")
            && (4..=32).contains(&name.len())
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            accounts.insert(name.to_owned());
        }
    }
    accounts.into_iter().collect()
}

fn site_accounts() -> Option<Vec<String>> {
    let flags = (rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOFOLLOW)
        .bits()
        .try_into()
        .ok()?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open("/etc/passwd")
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut text = String::new();
    file.take(256 * 1024 + 1).read_to_string(&mut text).ok()?;
    if text.len() > 256 * 1024 {
        return None;
    }
    Some(site_accounts_from_passwd(&text))
}

fn stack_versions() -> Value {
    let mut php = Vec::new();
    let mut php_extensions = serde_json::Map::new();
    for (series, lsphp, cli) in [
        (
            "8.4",
            "/usr/local/lsws/lsphp84/bin/lsphp",
            "/usr/local/lsws/lsphp84/bin/php",
        ),
        (
            "8.3",
            "/usr/local/lsws/lsphp83/bin/lsphp",
            "/usr/local/lsws/lsphp83/bin/php",
        ),
    ] {
        if let Some(version) = command_version(lsphp, &["-v"], "PHP ") {
            php.push(version);
            if let Some(modules) = php_modules(cli) {
                php_extensions.insert(series.to_owned(), json!(modules));
            }
        }
    }
    json!({
        "openlitespeed": command_version("/usr/local/lsws/bin/lshttpd", &["-v"], "LiteSpeed/"),
        "mariadb": command_version("/usr/bin/mariadb", &["--version"], "Distrib "),
        "php": php,
        "php_extensions": php_extensions,
        // W562 / W651 / W656: Optional components (`when_installed: true` in support-matrix.json)
        // report their version only when installed; absent binaries/packages stay null.
        "powerdns": command_version(RPM, &["-q", "--qf", "%{VERSION}", "pdns"], ""),
        "nodejs": command_version("/usr/bin/node", &["--version"], "v")
            .or_else(|| command_version(RPM, &["-q", "--qf", "%{VERSION}", "nodejs"], "")),
        "bun": command_version("/usr/local/bin/bun", &["--version"], ""),
        "caddy": command_version("/usr/local/bin/caddy", &["version"], "v")
            .or_else(|| command_version("/usr/bin/caddy", &["version"], "v")),
        "postgresql": command_version("/usr/pgsql-18/bin/postgres", &["--version"], "postgres (PostgreSQL) ")
            .or_else(|| command_version(RPM, &["-q", "--qf", "%{VERSION}", "postgresql18-server"], "")),
    })
}

fn postgresql_status() -> Value {
    let pg_isready = Path::new("/usr/pgsql-18/bin/pg_isready");
    let installed = pg_isready.is_file() || Path::new("/usr/pgsql-18/bin/postgres").is_file();
    if !installed {
        return json!({
            "installed": false,
            "ping": "not_installed",
            "listeners_beyond_loopback": 0,
        });
    }
    let output = Command::new(pg_isready)
        .args(["-h", "127.0.0.1", "-p", "5432", "-q"])
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    let ping = match output {
        Ok(out) if out.status.success() => "responding",
        Ok(_) => "not_responding",
        Err(_) => "unknown",
    };
    json!({
        "installed": true,
        "ping": ping,
        "listeners_beyond_loopback": exposed_listeners_on(5432),
    })
}

fn caddy_status() -> Value {
    let installed =
        Path::new("/usr/local/bin/caddy").is_file() || Path::new("/usr/bin/caddy").is_file();
    if !installed {
        return json!({
            "installed": false,
            "admin_port_listeners": 0,
        });
    }
    json!({
        "installed": true,
        "admin_port_listeners": listeners_on(2019),
    })
}

fn database_status() -> Value {
    let output = Command::new("/usr/bin/mariadb-admin")
        .args(["--protocol=socket", "--socket", MARIADB_SOCKET, "ping"])
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    let mut status = match output {
        Ok(output) => database_ping(true, output.status.success()),
        Err(_) => database_ping(false, false),
    };
    // W569 (W558-F1): MariaDB serves only its socket and loopback.
    status["listeners_beyond_loopback"] = json!(exposed_listeners_on(3306));
    status
}

fn firewall_policy() -> Value {
    let Some(state) = firewall_output(&["--state"]) else {
        return unread_firewall();
    };
    let Some(zone) = firewall_output(&["--get-default-zone"]) else {
        return unread_firewall();
    };
    let Some(services) = firewall_output(&["--list-services"]) else {
        return unread_firewall();
    };
    parse_firewall(&state, &zone, &services)
}

fn unread_ssh() -> Value {
    json!({
        "readable": false,
        "permit_root_login": null,
        "password_authentication": null,
        "pubkey_authentication": null,
        "kbd_interactive_authentication": null,
    })
}

fn ssh_policy() -> Value {
    let output = Command::new("/usr/sbin/sshd")
        .args(["-T"])
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    let Ok(output) = output else {
        return unread_ssh();
    };
    if !output.status.success() {
        return unread_ssh();
    }
    parse_sshd_effective(&String::from_utf8_lossy(&output.stdout))
}

/// A kernel SELinux label is `user:role:type:level`. The trailing NUL is
/// stripped. Anything else is not a context.
fn parse_selinux_context(text: &str) -> Option<String> {
    let token = text.trim_matches(|character: char| character == '\0' || character.is_whitespace());
    if token.is_empty()
        || token.len() > 256
        || token.split(':').count() < 4
        || !token.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'-' | b'.' | b',')
        })
    {
        return None;
    }
    Some(token.to_owned())
}

fn unread_executor_selinux() -> Value {
    json!({
        "unit": EXECUTOR_UNIT,
        "readable": false,
        "context": null,
    })
}

/// `MainPID` of the lab executor, then `/proc/<pid>/attr/current`. A missing
/// unit or an unreadable label stays unread. This does not set a domain.
fn executor_selinux() -> Value {
    let output = Command::new(SYSTEMCTL)
        .args(["show", "-p", "MainPID", "--value", EXECUTOR_UNIT])
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    let Ok(output) = output else {
        return unread_executor_selinux();
    };
    if !output.status.success() {
        return unread_executor_selinux();
    }
    let pid: u32 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .unwrap_or(0);
    if pid == 0 {
        return unread_executor_selinux();
    }
    let Some(text) = read_small(&format!("/proc/{pid}/attr/current")) else {
        return unread_executor_selinux();
    };
    let Some(context) = parse_selinux_context(&text) else {
        return unread_executor_selinux();
    };
    json!({
        "unit": EXECUTOR_UNIT,
        "readable": true,
        "context": context,
    })
}

/// W239: chronyd's local command protocol (candm.h, version 6) `tracking`
/// request over UDP 127.0.0.1:323 — what unprivileged `chronyc tracking`
/// sends. No exec, so it works under NoNewPrivileges (running `chronyc`
/// there was denied: `nnp_transition` to `chronyc_t`). Read only.
const CHRONY_CMD: (std::net::Ipv4Addr, u16) = (std::net::Ipv4Addr::LOCALHOST, 323);
const REQ_TRACKING: u16 = 33;
const RPY_TRACKING: u16 = 5;
/// chronyd answers only requests at least as long as the reply.
const TRACKING_REQUEST_LEN: usize = 108;

fn tracking_request(sequence: u32) -> Vec<u8> {
    let mut request = vec![0u8; TRACKING_REQUEST_LEN];
    request[0] = 6; // protocol version
    request[1] = 1; // PKT_TYPE_CMD_REQUEST
    request[4..6].copy_from_slice(&REQ_TRACKING.to_be_bytes());
    request[8..12].copy_from_slice(&sequence.to_be_bytes());
    request
}

/// chronyd's network float: 7-bit signed exponent, 25-bit signed coefficient.
fn chrony_float(word: u32) -> f64 {
    let mut exponent = (word >> 25) as i32;
    if exponent >= 1 << 6 {
        exponent -= 1 << 7;
    }
    let mut coefficient = (word & ((1 << 25) - 1)) as i32;
    if coefficient >= 1 << 24 {
        coefficient -= 1 << 25;
    }
    f64::from(coefficient) * 2f64.powi(exponent - 25)
}

/// `current_correction` is what chronyc prints as "System time": positive
/// means the clock is slow (behind NTP, negative microseconds here).
fn parse_tracking_reply(reply: &[u8], sequence: u32) -> Option<i64> {
    let be16 = |at: usize| u16::from_be_bytes([reply[at], reply[at + 1]]);
    if reply.len() < 72
        || reply[0] != 6
        || reply[1] != 2
        || be16(4) != REQ_TRACKING
        || be16(6) != RPY_TRACKING
        || be16(8) != 0
        || reply[16..20] != sequence.to_be_bytes()
    {
        return None;
    }
    let correction = chrony_float(u32::from_be_bytes(reply[68..72].try_into().ok()?));
    let micros = (-correction * 1e6).round();
    (micros.is_finite() && micros.abs() < 1e15).then_some(micros as i64)
}

fn chrony_offset_us() -> Option<i64> {
    let mut seed = [0u8; 4];
    rustix::rand::getrandom(&mut seed, rustix::rand::GetRandomFlags::empty()).ok()?;
    let sequence = u32::from_be_bytes(seed);
    let socket = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).ok()?;
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(1)))
        .ok()?;
    socket.connect(CHRONY_CMD).ok()?;
    socket.send(&tracking_request(sequence)).ok()?;
    let mut reply = [0u8; 512];
    let length = socket.recv(&mut reply).ok()?;
    parse_tracking_reply(&reply[..length], sequence)
}

fn ntp_synchronized() -> Option<bool> {
    let output = Command::new(TIMEDATECTL)
        .args(["show", "-p", "NTPSynchronized", "--value"])
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_ntp_synchronized(&String::from_utf8_lossy(&output.stdout))
}

/// `--timestamp=unix` prints `@seconds`. Some `*USec` fields are raw
/// microseconds. `n/a` and zero mean the event has not happened.
fn systemd_unix(value: &str) -> Option<u64> {
    let text = value.trim();
    if text.is_empty() || text == "n/a" || text == "0" {
        return None;
    }
    let digits = text.strip_prefix('@').unwrap_or(text);
    let parsed: u64 = digits.parse().ok()?;
    if parsed == 0 {
        return None;
    }
    if parsed > 10_000_000_000 {
        Some(parsed / 1_000_000)
    } else {
        Some(parsed)
    }
}

/// `busctl` prints `t <microseconds>`. Zero means the timer has not fired.
fn parse_busctl_usec(text: &str) -> Option<u64> {
    let digits = text.trim().strip_prefix("t ")?.split_whitespace().next()?;
    let usec: u64 = digits.parse().ok()?;
    if usec == 0 {
        return None;
    }
    Some(usec / 1_000_000)
}

fn logrotate_last_trigger() -> Option<u64> {
    let output = Command::new("/usr/bin/busctl")
        .args([
            "get-property",
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1/unit/logrotate_2etimer",
            "org.freedesktop.systemd1.Timer",
            "LastTriggerUSec",
        ])
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_busctl_usec(&String::from_utf8_lossy(&output.stdout))
}

fn unknown_unit(unit: &str) -> Value {
    json!({
        "unit": unit,
        "active": null,
        "sub": null,
        "since": null,
        "last_trigger": null,
        "selinux_context": null,
    })
}

/// SELinux label of a unit `MainPID`. Zero, a bad pid, or an unreadable
/// label stays unknown. This does not change the domain.
fn context_for_main_pid(pid_text: Option<&str>) -> Option<String> {
    let pid: u32 = pid_text?.trim().parse().ok()?;
    if pid == 0 {
        return None;
    }
    parse_selinux_context(&read_small(&format!("/proc/{pid}/attr/current"))?)
}

/// Loaded instances of the per-site PHP pool template.
fn site_php_units() -> Vec<String> {
    let output = Command::new(SYSTEMCTL)
        .args(["list-units", "--all", "--plain", "--no-legend", SITE_PHP])
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|unit| {
            unit.starts_with("rustiron-site-php@")
                && unit.ends_with(".service")
                && unit
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"@-_.".contains(&b))
        })
        .take(MAX_UNITS)
        .map(str::to_owned)
        .collect()
}

fn failed_unit_name(token: &str) -> Option<String> {
    if token.is_empty() || token.len() > 128 {
        return None;
    }
    let (name, suffix) = token.rsplit_once('.')?;
    if !matches!(
        suffix,
        "service" | "timer" | "socket" | "mount" | "path" | "target" | "scope"
    ) || name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"@-_.".contains(&byte))
    {
        return None;
    }
    Some(token.to_owned())
}

/// First column of `systemctl --failed --plain --no-legend`. At most 32 names.
/// `truncated` is true when another valid name was present after that.
fn parse_failed_units(text: &str) -> (Vec<String>, bool) {
    let mut units = Vec::new();
    let mut truncated = false;
    for line in text.lines() {
        let Some(name) = line.split_whitespace().next().and_then(failed_unit_name) else {
            continue;
        };
        if units.len() == 32 {
            truncated = true;
            break;
        }
        units.push(name);
    }
    (units, truncated)
}

/// W485 (W484-F2): package names installed more than once, from
/// `rpm -qa --qf '%{NAME}.%{ARCH}\n'`. Kernels and GPG keys are installed in
/// several versions by design; any other repeat is what an interrupted
/// transaction leaves. At most 32 names, sorted.
fn parse_duplicate_packages(text: &str) -> (Vec<String>, bool) {
    let mut seen = std::collections::BTreeMap::<&str, usize>::new();
    for line in text.lines() {
        let name = line.trim();
        let package = name.rsplit_once('.').map_or(name, |(package, _)| package);
        if name.is_empty()
            || package.starts_with("kernel")
            || package == "gpg-pubkey"
            || name.len() > 256
            || !name.bytes().all(|byte| byte.is_ascii_graphic())
        {
            continue;
        }
        *seen.entry(name).or_default() += 1;
    }
    let repeated: Vec<String> = seen
        .into_iter()
        .filter(|(_, count)| *count > 1)
        .map(|(name, _)| name.to_owned())
        .collect();
    let truncated = repeated.len() > 32;
    (repeated.into_iter().take(32).collect(), truncated)
}

fn duplicate_packages() -> Value {
    let output = Command::new(RPM)
        .args(["-qa", "--qf", "%{NAME}.%{ARCH}\n"])
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    match output {
        Ok(output) if output.status.success() => {
            let (names, truncated) =
                parse_duplicate_packages(&String::from_utf8_lossy(&output.stdout));
            json!({"readable": true, "duplicates": names, "truncated": truncated})
        }
        _ => json!({"readable": false, "duplicates": null, "truncated": false}),
    }
}

/// W466: whether a map token is a plain hostname.
pub(crate) fn hostname_token(token: &str) -> bool {
    map_hostname(token).is_some()
}

fn map_hostname(token: &str) -> Option<String> {
    if token.is_empty()
        || token.len() > 253
        || token.starts_with(['.', '-'])
        || token.ends_with(['.', '-'])
        || token.contains("..")
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
    {
        return None;
    }
    Some(token.to_owned())
}

/// `map <vhost> <hostname>` lines only. Other lines are ignored.
fn parse_ols_hosts(text: &str) -> Vec<String> {
    let mut hosts = Vec::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() != Some("map") {
            continue;
        }
        let _vhost = parts.next();
        let Some(host) = parts.next().and_then(map_hostname) else {
            continue;
        };
        if parts.next().is_some() || hosts.len() == 64 {
            continue;
        }
        hosts.push(host);
    }
    hosts
}

fn ols_map() -> Value {
    match read_small(OLS_MAP) {
        Some(text) => json!({"readable": true, "hosts": parse_ols_hosts(&text)}),
        None => json!({"readable": false, "hosts": null}),
    }
}

fn failed_units() -> Value {
    let output = Command::new(SYSTEMCTL)
        .args(["--failed", "--plain", "--no-legend", "--no-pager"])
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    let Ok(output) = output else {
        return json!({"readable": false, "units": null, "truncated": false});
    };
    if !output.status.success() {
        return json!({"readable": false, "units": null, "truncated": false});
    }
    let (units, truncated) = parse_failed_units(&String::from_utf8_lossy(&output.stdout));
    json!({"readable": true, "units": units, "truncated": truncated})
}

pub(crate) fn status() -> Value {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .ok();
    let meminfo = read_small("/proc/meminfo").unwrap_or_default();
    let release = read_small("/etc/os-release").unwrap_or_default();
    let load = read_small("/proc/loadavg").and_then(|text| loadavg(&text));
    let uptime = read_small("/proc/uptime")
        .and_then(|text| text.split_whitespace().next()?.parse::<f64>().ok())
        .map(|seconds| seconds as u64);
    let selinux = read_small("/sys/fs/selinux/enforce").map(|text| match text.trim() {
        "1" => "enforcing",
        "0" => "permissive",
        _ => "unknown",
    });
    let names: Vec<&str> = UNITS.iter().map(|(unit, _)| *unit).collect();
    let mut services: Vec<Value> = show(&names)
        .into_iter()
        .map(|mut value| {
            let label = UNITS
                .iter()
                .find(|(unit, _)| value["unit"].as_str() == Some(*unit))
                .map(|(_, label)| *label);
            value["label"] = json!(label);
            if value["unit"] == "logrotate.timer" && value["last_trigger"].is_null() {
                value["last_trigger"] = json!(logrotate_last_trigger());
            }
            value
        })
        .collect();
    let sites = site_php_units();
    let site_refs: Vec<&str> = sites.iter().map(String::as_str).collect();
    services.extend(show(&site_refs).into_iter().map(|mut value| {
        value["label"] = json!("Site PHP pool");
        value
    }));
    let kernel = rustix::system::uname();
    json!({
        "schema": "rustiron-host-status/1",
        "observed_at": now,
        "os": {
            "name": os_field(&release, "NAME"),
            "version": os_field(&release, "VERSION_ID"),
            "kernel": kernel.release().to_str().ok(),
        },
        "uptime_seconds": uptime,
        "cpu": {
            "count": std::thread::available_parallelism().ok().map(usize::from),
            "load": load,
        },
        "memory": {
            "total_bytes": meminfo_bytes(&meminfo, "MemTotal:"),
            "available_bytes": meminfo_bytes(&meminfo, "MemAvailable:"),
        },
        "disk": disk("/"),
        "selinux": selinux,
        "executor_selinux": executor_selinux(),
        "clock": { "synchronized": ntp_synchronized(), "offset_us": chrony_offset_us() },
        "ssh": ssh_policy(),
        "firewall": firewall_policy(),
        "database": database_status(),
        "postgresql": postgresql_status(),
        "caddy": caddy_status(),
        "stack": stack_versions(),
        "tls": { "listeners_443": listeners_on(443) },
        "failed_units": failed_units(),
        "packages": duplicate_packages(),
        "ols_map": ols_map(),
        "site_accounts": site_accounts(),
        "services": services,
    })
}

pub(crate) fn read_json(path: &Path, limit: usize) -> Result<Value, ErrorCode> {
    let flags = (rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOFOLLOW)
        .bits()
        .try_into()
        .map_err(|_| ErrorCode::InvalidRequest)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .map_err(local::io_code)?;
    if !file.metadata().map_err(local::io_code)?.is_file() {
        return Err(ErrorCode::InvalidRequest);
    }
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(local::io_code)?;
    if bytes.len() > limit {
        return Err(ErrorCode::RequestTooLarge);
    }
    serde_json::from_slice(&bytes).map_err(|_| ErrorCode::InvalidRequest)
}

pub(crate) fn write_json(path: &Path, value: &Value) -> Result<(), ErrorCode> {
    let parent = path.parent().ok_or(ErrorCode::InvalidRequest)?;
    if !parent.metadata().map_err(local::io_code)?.is_dir() {
        return Err(ErrorCode::InvalidRequest);
    }
    if path
        .symlink_metadata()
        .is_ok_and(|meta| meta.file_type().is_symlink())
    {
        return Err(ErrorCode::InvalidRequest);
    }
    let name = path.file_name().ok_or(ErrorCode::InvalidRequest)?;
    let temporary = parent.join(format!("{}.tmp", name.to_string_lossy()));
    let _ = fs::remove_file(&temporary);
    {
        let flags = rustix::fs::OFlags::NOFOLLOW
            .bits()
            .try_into()
            .map_err(|_| ErrorCode::InvalidRequest)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(flags)
            .open(&temporary)
            .map_err(local::io_code)?;
        file.write_all(value.to_string().as_bytes())
            .map_err(local::io_code)?;
        file.write_all(b"\n").map_err(local::io_code)?;
    }
    fs::rename(&temporary, path).map_err(local::io_code)
}

fn used_percent(total: Option<u64>, available: Option<u64>) -> Option<u8> {
    let total = total?;
    let available = available?;
    if total == 0 {
        return None;
    }
    let ratio = (total.saturating_sub(available) as f64 / total as f64) * 100.0;
    Some(ratio.round().clamp(0.0, 100.0) as u8)
}

fn cpu_percent(status: &Value) -> Option<u8> {
    let count = status["cpu"]["count"].as_u64()?;
    let load = status["cpu"]["load"].as_array()?.get(1)?.as_f64()?;
    if count == 0 {
        return None;
    }
    Some(((load / count as f64) * 100.0).round().clamp(0.0, 100.0) as u8)
}

pub(crate) fn sample(status: &Value) -> Value {
    json!({
        "t": status["observed_at"],
        "cpu": cpu_percent(status),
        "mem": used_percent(
            status["memory"]["total_bytes"].as_u64(),
            status["memory"]["available_bytes"].as_u64(),
        ),
        "disk": used_percent(
            status["disk"]["total_bytes"].as_u64(),
            status["disk"]["available_bytes"].as_u64(),
        ),
    })
}

/// A missing file and a zero-length file both mean there is no sample history.
/// A symlink or a non-empty file with the wrong schema is still refused.
fn stored_samples(path: &Path) -> Result<Vec<Value>, ErrorCode> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(local::io_code(error)),
    };
    if !metadata.file_type().is_file() {
        return Err(ErrorCode::InvalidRequest);
    }
    if metadata.len() == 0 {
        return Ok(Vec::new());
    }
    let existing = read_json(path, MAX_STATUS_BYTES)?;
    if existing["schema"] != SAMPLE_SCHEMA {
        return Err(ErrorCode::UnsupportedVersion);
    }
    Ok(existing["samples"].as_array().cloned().unwrap_or_default())
}

pub(crate) fn record_samples(path: &Path, status: &Value) -> Result<Value, ErrorCode> {
    let next = sample(status);
    let mut samples = stored_samples(path)?;
    if samples
        .last()
        .is_some_and(|last| last["t"] == next["t"] && !next["t"].is_null())
    {
        samples.pop();
    }
    samples.push(next);
    if samples.len() > MAX_SAMPLES {
        samples.drain(0..samples.len() - MAX_SAMPLES);
    }
    let document = json!({ "schema": SAMPLE_SCHEMA, "samples": samples });
    write_json(path, &document)?;
    Ok(document)
}

pub(crate) fn merge_observation(
    observation: Value,
    mut status: Value,
    samples: Option<&Value>,
) -> Result<Value, ErrorCode> {
    if observation["schema"] != OBSERVATION_SCHEMA {
        return Err(ErrorCode::UnsupportedVersion);
    }
    if status["schema"] != STATUS_SCHEMA {
        return Err(ErrorCode::InvalidRequest);
    }
    if let Some(document) = samples {
        if document["schema"] != SAMPLE_SCHEMA {
            return Err(ErrorCode::UnsupportedVersion);
        }
        status["samples"] = document["samples"].clone();
    }
    let mut merged = observation;
    annotate_site_http(&mut merged);
    annotate_proxy_ports(&mut merged, proc_tcp_tables().as_deref());
    annotate_app_units(&mut merged);
    merged["machine"] = status;
    Ok(merged)
}

/// W599-F4: indices of active P27 app sites bounded by [`MAX_PROBED_SITES`]
/// after filtering (so non-app provisions never crowd out app sites).
fn app_unit_indices(sites: &[Value]) -> Vec<usize> {
    sites
        .iter()
        .enumerate()
        .filter(|(_, site)| {
            site["app_runtime"].as_str().is_some()
                && matches!(site["state"].as_str(), Some("succeeded" | "adopted"))
        })
        .take(MAX_PROBED_SITES)
        .map(|(idx, _)| idx)
        .collect()
}

/// W598 (D-099): read-only `systemctl show` for each enrolled P27 app site's
/// systemd unit (`rustiron-app@rs_<site_id>.service`). Never mutates state.
fn annotate_app_units(observation: &mut Value) {
    let Some(sites) = observation.get_mut("sites").and_then(Value::as_array_mut) else {
        return;
    };
    for idx in app_unit_indices(sites) {
        let site = &mut sites[idx];
        let Some(site_id) = site["site_id"].as_str() else {
            continue;
        };
        let unit = format!("rustiron-app@rs_{site_id}.service");
        let output = Command::new("/usr/bin/systemctl")
            .args([
                "show",
                "--no-pager",
                "--property=ActiveState,SubState,NRestarts,SELinuxContext,IPAddressDeny,IPAddressAllow,PrivateNetwork,NoNewPrivileges,ProtectSystem",
                "--",
                &unit,
            ])
            .output();
        let Ok(out) = output else {
            continue;
        };
        if !out.status.success() {
            continue;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let mut active_state = None;
        let mut sub_state = None;
        let mut restarts: Option<u64> = None;
        let mut selinux_context = None;
        let mut ip_address_deny = None;
        let mut ip_address_allow = None;
        let mut private_network = None;
        let mut no_new_privileges = None;
        let mut protect_system = None;
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("ActiveState=") {
                active_state = Some(v.to_owned());
            } else if let Some(v) = line.strip_prefix("SubState=") {
                sub_state = Some(v.to_owned());
            } else if let Some(v) = line.strip_prefix("NRestarts=") {
                restarts = v.parse::<u64>().ok();
            } else if let Some(v) = line.strip_prefix("SELinuxContext=") {
                selinux_context = (!v.is_empty()).then(|| v.to_owned());
            } else if let Some(v) = line.strip_prefix("IPAddressDeny=") {
                ip_address_deny = (!v.is_empty()).then(|| v.to_owned());
            } else if let Some(v) = line.strip_prefix("IPAddressAllow=") {
                ip_address_allow = (!v.is_empty()).then(|| v.to_owned());
            } else if let Some(v) = line.strip_prefix("PrivateNetwork=") {
                private_network = (!v.is_empty()).then(|| v.to_owned());
            } else if let Some(v) = line.strip_prefix("NoNewPrivileges=") {
                no_new_privileges = (!v.is_empty()).then(|| v.to_owned());
            } else if let Some(v) = line.strip_prefix("ProtectSystem=") {
                protect_system = (!v.is_empty()).then(|| v.to_owned());
            }
        }
        if let Some(active) = active_state {
            site["app_unit"] = json!({
                "unit": unit,
                "active_state": active,
                "sub_state": sub_state,
                "restarts": restarts,
                "selinux_context": selinux_context,
                "ip_address_deny": ip_address_deny,
                "ip_address_allow": ip_address_allow,
                "private_network": private_network,
                "no_new_privileges": no_new_privileges,
                "protect_system": protect_system,
            });
        }
    }
}

/// The most sites one merge asks the listener about.
const MAX_PROBED_SITES: usize = 32;

/// W578 (W577-F3): which sites the merge probes, in order: the served ones
/// (succeeded or adopted, not ejected) first, then the others, never a
/// `deleted` site, at most [`MAX_PROBED_SITES`]. The journal keeps every
/// provision, so taking the first 32 rows left later served sites unprobed
/// on a host with a long history.
fn probe_order(sites: &[Value]) -> Vec<usize> {
    let served = |site: &Value| {
        matches!(site["state"].as_str(), Some("succeeded" | "adopted")) && site["ejected"] != true
    };
    let (first, rest): (Vec<usize>, Vec<usize>) = (0..sites.len())
        .filter(|&index| sites[index]["state"] != "deleted")
        .partition(|&index| served(&sites[index]));
    first
        .into_iter()
        .chain(rest)
        .take(MAX_PROBED_SITES)
        .collect()
}

/// Ask the enrolled listener for each site's identity file. A missing or
/// unreadable answer leaves the site without `http_status`.
fn annotate_site_http(observation: &mut Value) {
    let Some(address) = observation["host"]["ols_listener"].as_str() else {
        return;
    };
    let Ok(address) = address.parse::<SocketAddr>() else {
        return;
    };
    let Some(sites) = observation.get_mut("sites").and_then(Value::as_array_mut) else {
        return;
    };
    for index in probe_order(sites) {
        let site = &mut sites[index];
        let Some(host) = site["hostname"].as_str().and_then(map_hostname) else {
            continue;
        };
        if let Some(code) = probe_http(address, &host) {
            site["http_status"] = json!(code);
        }
        // D-073 (W487): the site's own PHP answers with its account. An
        // ejected or unfinished site has no health context.
        // W575: a proxy site has no PHP.
        let managed = matches!(site["state"].as_str(), Some("succeeded" | "adopted"))
            && site["ejected"] != true
            && site["proxy_ports"]
                .as_array()
                .is_none_or(std::vec::Vec::is_empty);
        let Some(account) = site["site_id"].as_str().map(|id| format!("rs_{id}")) else {
            continue;
        };
        if managed && let Some(answer) = probe_php(address, &host) {
            site["php_health"] = match answer {
                Some((status, body)) => php_health(status, &body, &account),
                // W487-F1: connected, but no valid answer (a hung pool).
                None => json!({"status": null, "account_matches": false}),
            };
        }
    }
}

/// W575 (D-095): the kernel's TCP tables (`/proc/net/tcp` and `tcp6`),
/// which any account may read. `None` when neither is readable or one is
/// too large or not text.
fn proc_tcp_tables() -> Option<Vec<String>> {
    let mut tables = Vec::new();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(bytes) = fs::read(path) else {
            continue;
        };
        if bytes.len() > 1024 * 1024 {
            return None;
        }
        tables.push(String::from_utf8(bytes).ok()?);
    }
    (!tables.is_empty()).then_some(tables)
}

/// W575: whether a `/proc/net/tcp{,6}` local address is the wildcard.
fn wildcard_hex(address: &str) -> bool {
    !address.is_empty() && address.bytes().all(|byte| byte == b'0')
}

/// W575: listening sockets on `port` that a connection to `127.0.0.1`
/// reaches (loopback or wildcard), and those beyond loopback (wildcard or
/// another address).
fn proxy_listeners(tables: &[String], port: u16) -> (u64, u64) {
    let (mut reachable, mut exposed) = (0, 0);
    for line in tables.iter().flat_map(|text| text.lines()) {
        let mut columns = line.split_whitespace();
        let (Some(_), Some(local), Some(_), Some(state)) = (
            columns.next(),
            columns.next(),
            columns.next(),
            columns.next(),
        ) else {
            continue;
        };
        let Some((address, port_hex)) = local.rsplit_once(':') else {
            continue;
        };
        if u16::from_str_radix(port_hex, 16).ok() != Some(port) || state != "0A" {
            continue;
        }
        if loopback_hex(address) || wildcard_hex(address) {
            reachable += 1;
        }
        if !loopback_hex(address) {
            exposed += 1;
        }
    }
    (reachable, exposed)
}

/// W575 (D-095): for each proxy site, whether something listens on each of
/// its ports where OLS connects (`127.0.0.1`), and whether it also listens
/// beyond loopback. Only the kernel's tables are read: no connection is
/// made and no answer is read. Unreadable tables leave the facts absent.
/// W577-F2: the bound counts proxy sites only; a journal with more than 32
/// provisions of any kind left the later proxy sites unchecked.
fn annotate_proxy_ports(observation: &mut Value, tables: Option<&[String]>) {
    let Some(tables) = tables else {
        return;
    };
    let Some(sites) = observation.get_mut("sites").and_then(Value::as_array_mut) else {
        return;
    };
    let proxies = sites.iter_mut().filter(|site| {
        site["proxy_ports"]
            .as_array()
            .is_some_and(|ports| !ports.is_empty())
    });
    for site in proxies.take(32) {
        let ports: Vec<u16> = site["proxy_ports"]
            .as_array()
            .map(|ports| {
                ports
                    .iter()
                    .filter_map(Value::as_u64)
                    .filter_map(|port| u16::try_from(port).ok())
                    .take(16)
                    .collect()
            })
            .unwrap_or_default();
        if ports.is_empty() {
            continue;
        }
        site["proxy"] = ports
            .iter()
            .map(|port| {
                let (listening, exposed) = proxy_listeners(tables, *port);
                json!({"port": port, "listening": listening, "beyond_loopback": exposed})
            })
            .collect();
    }
}

/// D-073: a PHP health answer as a fact: the status, and whether the body
/// is exactly the site's account. The body itself is never copied.
fn php_health(status: u16, body: &str, account: &str) -> Value {
    json!({"status": status, "account_matches": status == 200 && body.trim_end() == account})
}

/// `None` when the listener cannot be reached (no fact, as for
/// `http_status`); `Some(None)` when it accepted the request but gave no
/// valid answer within the time.
fn probe_php(address: SocketAddr, host: &str) -> Option<Option<(u16, String)>> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(500)).ok()?;
    let answer = (|| {
        // A socket-activated pool may start cold.
        stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
        stream
            .set_write_timeout(Some(Duration::from_millis(500)))
            .ok()?;
        let request = format!(
            "GET /rustiron-php-health.php HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).ok()?;
        let mut response = Vec::new();
        (&mut stream).take(4096).read_to_end(&mut response).ok()?;
        let status = parse_http_status(&response)?;
        let text = String::from_utf8_lossy(&response);
        let body = text.split_once("\r\n\r\n").map_or("", |(_, body)| body);
        Some((status, body.to_owned()))
    })();
    Some(answer)
}

fn probe_http(address: SocketAddr, host: &str) -> Option<u16> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(500)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_millis(500)))
        .ok()?;
    let request =
        format!("GET /rustiron-site.txt HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).ok()?;
    let mut buffer = [0_u8; 64];
    let read = stream.read(&mut buffer).ok()?;
    parse_http_status(&buffer[..read])
}

fn parse_http_status(bytes: &[u8]) -> Option<u16> {
    let text = std::str::from_utf8(bytes).ok()?;
    let code = text.split_whitespace().nth(1)?;
    let code = code.parse().ok()?;
    (100..600).contains(&code).then_some(code)
}

pub(crate) fn read_observation(path: &Path) -> Result<Value, ErrorCode> {
    read_json(path, MAX_RESPONSE_BYTES)
}

#[cfg(test)]
mod tests {

    /// W239: a real chronyd 4.x `tracking` reply captured on the lab VM
    /// (seq 3150400132); `chronyc tracking` printed 0.000206884 s slow.
    const TRACKING: &str = "06020000002100050000000000000000bbc74a840000000000000000179f10c2179f10c20000000000000000000000000001000000030000000000006aeb4c2d3a98c6c6ead8ef36ed74de89f2a91eed0b59188ef71ca552fcf37912f8823bc4f280c08c1a810e5a";

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn chrony_tracking_reply_gives_the_chronyc_offset() {
        let reply = unhex(TRACKING);
        assert_eq!(parse_tracking_reply(&reply, 3_150_400_132), Some(-207));
        // Wrong sequence, failure status, wrong reply code, truncated: unknown.
        assert_eq!(parse_tracking_reply(&reply, 1), None);
        let mut bad = reply.clone();
        bad[9] = 1; // status (bytes 8..10)
        assert_eq!(parse_tracking_reply(&bad, 3_150_400_132), None);
        let mut bad = reply.clone();
        bad[7] = 4; // reply code (bytes 6..8)
        assert_eq!(parse_tracking_reply(&bad, 3_150_400_132), None);
        assert_eq!(parse_tracking_reply(&reply[..71], 3_150_400_132), None);
    }

    #[test]
    fn chrony_float_decodes_sign_and_exponent() {
        assert_eq!(chrony_float(0), 0.0);
        // coefficient 1, exponent 25 -> 1.0; coefficient -1 -> -1.0
        assert_eq!(chrony_float(25 << 25 | 1), 1.0);
        assert_eq!(chrony_float(25 << 25 | ((1 << 25) - 1)), -1.0);
        // exponent -1 (two's complement in 7 bits) -> 2^-26
        assert_eq!(chrony_float(0x7f << 25 | 1), 2f64.powi(-26));
    }

    #[test]
    fn tracking_request_is_padded_to_the_reply_length() {
        let request = tracking_request(7);
        assert_eq!(request.len(), 108);
        assert_eq!(&request[..6], &[6, 1, 0, 0, 0, 33]);
        assert_eq!(&request[8..12], &7u32.to_be_bytes());
        assert!(request[20..].iter().all(|b| *b == 0));
    }
    use super::*;

    #[test]
    fn counters_parse_and_bad_input_is_unknown() {
        let meminfo = "MemTotal:        3800000 kB\nMemAvailable:    1900000 kB\n";
        assert_eq!(meminfo_bytes(meminfo, "MemTotal:"), Some(3_891_200_000));
        assert_eq!(meminfo_bytes(meminfo, "SwapTotal:"), None);
        assert_eq!(meminfo_bytes("MemTotal: lots kB", "MemTotal:"), None);
        assert_eq!(
            loadavg("0.52 0.40 0.31 1/250 999"),
            Some([0.52, 0.40, 0.31])
        );
        assert_eq!(loadavg("0.52"), None);
        assert_eq!(
            os_field("NAME=\"AlmaLinux\"\nVERSION_ID=\"10.0\"\n", "VERSION_ID").as_deref(),
            Some("10.0")
        );
        assert_eq!(os_field("NAME_EXTRA=x\n", "NAME"), None);
        assert_eq!(used_percent(Some(8), Some(6)), Some(25));
        assert_eq!(used_percent(Some(8), Some(8)), Some(0));
        assert_eq!(used_percent(Some(0), Some(0)), None);
        assert_eq!(parse_ntp_synchronized("yes\n"), Some(true));
        assert_eq!(parse_ntp_synchronized("no"), Some(false));
        assert_eq!(parse_ntp_synchronized("YES"), None);
        assert_eq!(parse_ntp_synchronized(""), None);
        assert_eq!(parse_http_status(b"HTTP/1.0 200 OK\r\n"), Some(200));
        assert_eq!(parse_http_status(b"HTTP/1.1 404 Not Found"), Some(404));
        assert_eq!(parse_http_status(b"HTTP/1.0 99"), None);
        assert_eq!(parse_http_status(b"not http"), None);
        let (units, truncated) = parse_failed_units(
            "rustiron-observe-local.service loaded failed failed observation\nnot a unit\n",
        );
        assert_eq!(units, vec!["rustiron-observe-local.service".to_owned()]);
        assert!(!truncated);
        assert_eq!(parse_failed_units("").0, Vec::<String>::new());
        let many = (0..33)
            .map(|index| format!("unit-{index}.service loaded failed failed x\n"))
            .collect::<String>();
        let (capped, over) = parse_failed_units(&many);
        assert_eq!(capped.len(), 32);
        assert!(over);
        assert_eq!(
            parse_ols_hosts(
                "virtualHost site_a {\n}\nlistener G0 {\n map site_a site-a.example.test\n map rs_blog13 blog13.example.test extra\n map bad ..\n"
            ),
            vec!["site-a.example.test".to_owned()]
        );
        assert_eq!(systemd_unix("@1793228407"), Some(1_793_228_407));
        assert_eq!(systemd_unix("1793228407000000"), Some(1_793_228_407));
        assert_eq!(systemd_unix("n/a"), None);
        assert_eq!(systemd_unix("0"), None);
        assert_eq!(systemd_unix(""), None);
        assert_eq!(
            parse_busctl_usec("t 1793161503887071\n"),
            Some(1_793_161_503)
        );
        assert_eq!(parse_busctl_usec("t 0"), None);
        assert_eq!(parse_busctl_usec("s no"), None);
        let policy = parse_sshd_effective(
            "port 22\npermitrootlogin without-password\npasswordauthentication no\npubkeyauthentication yes\nkbdinteractiveauthentication no\n",
        );
        assert_eq!(policy["readable"], true);
        assert_eq!(policy["permit_root_login"], "without-password");
        assert_eq!(policy["password_authentication"], "no");
        assert_eq!(policy["pubkey_authentication"], "yes");
        assert_eq!(policy["kbd_interactive_authentication"], "no");
        assert_eq!(parse_sshd_effective("port 22\n")["readable"], false);
        assert!(
            parse_sshd_effective("passwordauthentication bad/value")["password_authentication"]
                .is_null()
        );
        let table = "sl local_address rem_address st\n  0: 0100007F:01BB 00000000:0000 0A 0\n  1: 0100007F:1F9A 00000000:0000 0A 0\n  2: 0100007F:01BB 00000000:0000 01 0\n";
        assert_eq!(count_listeners(table, 443), 1);
        assert_eq!(count_listeners(table, 8090), 1);
        assert_eq!(count_listeners(table, 80), 0);
        // W569 (W558-F1): the W558 MariaDB on 0.0.0.0 and [::] is exposed;
        // 127.0.0.1, ::1, and ::ffff:127.0.0.1 are loopback.
        let v4 = "sl local_address rem_address st\n  0: 00000000:0CEA 00000000:0000 0A 0\n  1: 0100007F:0CEA 00000000:0000 0A 0\n  2: 1600A8C0:0CEA 0100A8C0:D2F0 01 0\n";
        let v6 = "sl local_address rem_address st\n  0: 00000000000000000000000000000000:0CEA 00000000000000000000000000000000:0000 0A 0\n  1: 00000000000000000000000001000000:0CEA 00000000000000000000000000000000:0000 0A 0\n  2: 0000000000000000FFFF00000100007F:0CEA 00000000000000000000000000000000:0000 0A 0\n";
        assert_eq!(count_exposed_listeners(v4, 3306), 1);
        assert_eq!(count_exposed_listeners(v6, 3306), 1);
        assert_eq!(count_exposed_listeners(v4, 443), 0);
        assert!(loopback_hex("0100007F") && loopback_hex("0200007F"));
        assert!(!loopback_hex("00000000") && !loopback_hex("1600A8C0"));
        let firewall = parse_firewall("running\n", "public", "cockpit dhcpv6-client ssh");
        assert_eq!(firewall["readable"], true);
        assert_eq!(firewall["state"], "running");
        assert_eq!(firewall["default_zone"], "public");
        assert_eq!(
            firewall["services"],
            json!(["cockpit", "dhcpv6-client", "ssh"])
        );
        assert_eq!(parse_firewall("nope", "public", "ssh")["readable"], false);
        assert_eq!(
            parse_firewall("running", "bad/zone", "ssh")["readable"],
            false
        );
        assert_eq!(database_ping(true, true)["ping"], "responding");
        assert_eq!(database_ping(true, false)["ping"], "not_responding");
        assert_eq!(database_ping(false, false)["ping"], "unknown");
        assert_eq!(
            version_after("LiteSpeed/1.9.3 Open\n", "LiteSpeed/").as_deref(),
            Some("1.9.3")
        );
        assert_eq!(
            version_after(
                "mariadb  Ver 15.1 Distrib 10.11.18-MariaDB, for Linux\n",
                "Distrib "
            )
            .as_deref(),
            Some("10.11.18")
        );
        assert_eq!(
            version_after("PHP 8.4.27 (litespeed)\n", "PHP ").as_deref(),
            Some("8.4.27")
        );
        assert_eq!(
            version_after("v2.10.2 h1:abc123\n", "v").as_deref(),
            Some("2.10.2")
        );
        assert_eq!(
            version_after("postgres (PostgreSQL) 18.7\n", "postgres (PostgreSQL) ").as_deref(),
            Some("18.7")
        );
        assert_eq!(version_after("PHP ..1\n", "PHP "), None);
        assert_eq!(
            parse_selinux_context("system_u:system_r:unconfined_service_t:s0\0").as_deref(),
            Some("system_u:system_r:unconfined_service_t:s0")
        );
        assert_eq!(
            parse_selinux_context("system_u:system_r:rustiron_php_t:s0:c201").as_deref(),
            Some("system_u:system_r:rustiron_php_t:s0:c201")
        );
        assert_eq!(parse_selinux_context("not a context"), None);
        assert_eq!(parse_selinux_context("user:role:type"), None);
        assert_eq!(parse_selinux_context(""), None);
        assert_eq!(context_for_main_pid(None), None);
        assert_eq!(context_for_main_pid(Some("0")), None);
        assert_eq!(context_for_main_pid(Some("nope")), None);
        assert_eq!(context_for_main_pid(Some("4294967294")), None);
        assert_eq!(
            database_ping(true, true)["socket"],
            "/var/lib/mysql/mysql.sock"
        );
        assert_eq!(inode_counts(100, 40), (Some(100), Some(40)));
        assert_eq!(inode_counts(0, 0), (None, None));
        assert_eq!(inode_counts(10, 11), (None, None));
        let root = disk("/");
        assert!(root.get("inode_total").is_some());
        assert!(root.get("inode_available").is_some());
        if let (Some(total), Some(available)) = (
            root["inode_total"].as_u64(),
            root["inode_available"].as_u64(),
        ) {
            assert!(available <= total);
            assert!(total > 0);
        } else {
            assert!(root["inode_total"].is_null());
            assert!(root["inode_available"].is_null());
        }
        let missing = disk("/no/such/rustiron-disk");
        assert!(missing["inode_total"].is_null());
        assert!(missing["inode_available"].is_null());
        assert!(missing["total_bytes"].is_null());
        let status = json!({
            "schema": STATUS_SCHEMA,
            "observed_at": 100,
            "cpu": { "count": 4, "load": [0.2, 1.0, 0.5] },
            "memory": { "total_bytes": 8, "available_bytes": 6 },
            "disk": { "path": "/", "total_bytes": 40, "available_bytes": 30 },
        });
        assert_eq!(sample(&status)["cpu"], 25);
        assert_eq!(sample(&status)["mem"], 25);
        assert_eq!(sample(&status)["disk"], 25);
    }

    /// W487-F1: a listener that answers, one that accepts and hangs (a
    /// broken PHP pool), and no listener give three different facts.
    #[test]
    fn the_php_probe_tells_an_answer_a_hang_and_no_listener_apart() {
        use std::net::TcpListener;
        let answering = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = answering.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = answering.accept().unwrap();
            let mut request = [0_u8; 512];
            let _ = stream.read(&mut request);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nrs_blog1\n")
                .unwrap();
        });
        assert_eq!(
            probe_php(address, "blog1.example.test"),
            Some(Some((200, "rs_blog1\n".to_owned())))
        );
        server.join().unwrap();
        let hanging = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = hanging.local_addr().unwrap();
        let holder = std::thread::spawn(move || {
            let (stream, _) = hanging.accept().unwrap();
            std::thread::sleep(Duration::from_secs(4));
            drop(stream);
        });
        assert_eq!(probe_php(address, "blog1.example.test"), Some(None));
        holder.join().unwrap();
        let closed = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        assert_eq!(probe_php(closed, "blog1.example.test"), None);
    }

    /// W578 (W577-F3): served sites are probed first and deleted ones never,
    /// whatever their place in the journal; the bound stays 32.
    #[test]
    fn served_sites_are_probed_first_and_deleted_ones_never() {
        let mut sites: Vec<Value> = (0..30)
            .map(|n| json!({"site_id": format!("gone{n}"), "state": "deleted"}))
            .collect();
        sites.extend((0..10).map(|n| json!({"site_id": format!("q{n}"), "state": "quarantined"})));
        sites.push(json!({"site_id": "ejected1", "state": "succeeded", "ejected": true}));
        sites.push(json!({"site_id": "blog1", "state": "succeeded", "ejected": false}));
        sites.push(json!({"site_id": "adopted1", "state": "adopted"}));
        let order = probe_order(&sites);
        let names: Vec<&str> = order
            .iter()
            .map(|&index| sites[index]["site_id"].as_str().unwrap())
            .collect();
        assert_eq!(&names[..2], ["blog1", "adopted1"]);
        assert_eq!(names.len(), 13);
        assert!(names.iter().all(|name| !name.starts_with("gone")));
        assert!(names.contains(&"ejected1") && names.contains(&"q9"));
        let many: Vec<Value> = (0..40)
            .map(|n| json!({"site_id": format!("s{n}"), "state": "succeeded"}))
            .collect();
        assert_eq!(probe_order(&many), (0..32).collect::<Vec<_>>());
    }

    /// W575 (D-095): per proxy port, the listeners a connection to
    /// 127.0.0.1 reaches (loopback or wildcard) and those beyond loopback;
    /// other ports, non-listening sockets, and other sites are ignored.
    #[test]
    fn proxy_ports_are_read_from_the_listener_tables() {
        let tcp = "  sl  local_address rem_address   st\n\
   0: 0100007F:0C1C 00000000:0000 0A 0\n\
   1: 00000000:0C1D 00000000:0000 0A 0\n\
   2: 0100007F:0C1D 0100007F:9C40 01 0\n\
   3: 0A00020F:0C1E 00000000:0000 0A 0\n";
        let tcp6 = "  sl  local_address\n\
   0: 00000000000000000000000001000000:0C1C 00000000000000000000000000000000:0000 0A 0\n\
   1: 00000000000000000000000000000000:0C1D 00000000000000000000000000000000:0000 0A 0\n";
        let tables = [tcp.to_owned(), tcp6.to_owned()];
        // 3100 on 127.0.0.1 and ::1; 3101 on 0.0.0.0 and :: (an established
        // connection does not count); 3102 only on 10.0.2.15; 3103 nowhere.
        assert_eq!(proxy_listeners(&tables, 3100), (2, 0));
        assert_eq!(proxy_listeners(&tables, 3101), (2, 2));
        assert_eq!(proxy_listeners(&tables, 3102), (0, 1));
        assert_eq!(proxy_listeners(&tables, 3103), (0, 0));
        // W577-F2: 40 other provisions before the proxy site.
        let mut sites: Vec<Value> = (0..40)
            .map(|n| json!({"site_id": format!("old{n}"), "proxy_ports": []}))
            .collect();
        sites.push(json!({"site_id": "ytproxy", "proxy_ports": [3100, 3101, 3103]}));
        sites.push(json!({"site_id": "blog1", "proxy_ports": []}));
        let mut observation = json!({ "sites": sites });
        annotate_proxy_ports(&mut observation, Some(&tables));
        let observation = json!({"sites": [
            observation["sites"][40].clone(),
            observation["sites"][41].clone(),
        ]});
        assert_eq!(
            observation["sites"][0]["proxy"],
            json!([
                {"port": 3100, "listening": 2, "beyond_loopback": 0},
                {"port": 3101, "listening": 2, "beyond_loopback": 2},
                {"port": 3103, "listening": 0, "beyond_loopback": 0},
            ])
        );
        assert!(observation["sites"][1].get("proxy").is_none());
        let mut unread = json!({"sites": [{"site_id": "ytproxy", "proxy_ports": [3100]}]});
        annotate_proxy_ports(&mut unread, None);
        assert!(unread["sites"][0].get("proxy").is_none());
    }

    /// D-073 (W487): only an exact account body is a match; the body is
    /// never copied into the fact.
    #[test]
    fn php_health_matches_only_the_exact_account() {
        assert_eq!(
            php_health(200, "rs_blog1\n", "rs_blog1"),
            json!({"status": 200, "account_matches": true})
        );
        for (status, body) in [
            (200, "rs_blog2\n"),
            (200, "rs_blog1 extra"),
            (500, "rs_blog1\n"),
            (200, ""),
        ] {
            assert_eq!(
                php_health(status, body, "rs_blog1")["account_matches"],
                false,
                "{status} {body:?}"
            );
        }
        assert!(
            !php_health(200, "secret-looking body", "rs_blog1")
                .to_string()
                .contains("secret")
        );
    }

    /// W485 (W484-F2): the W484 state after the power cut; kernels and GPG
    /// keys are installed more than once by design.
    #[test]
    fn duplicate_packages_are_named_and_installonly_ones_skipped() {
        let w484 = "lsphp84.x86_64\nlsphp84.x86_64\nlsphp84-gd.x86_64\nlsphp84-pdo.x86_64\n\
                    lsphp84-pdo.x86_64\nkernel.x86_64\nkernel.x86_64\nkernel-core.x86_64\n\
                    kernel-core.x86_64\ngpg-pubkey.(none)\ngpg-pubkey.(none)\nglibc.x86_64\n\
                    glibc.i686\n";
        assert_eq!(
            parse_duplicate_packages(w484),
            (
                vec!["lsphp84-pdo.x86_64".to_owned(), "lsphp84.x86_64".to_owned()],
                false
            )
        );
        assert_eq!(parse_duplicate_packages(""), (Vec::new(), false));
        let many: String = (0..40)
            .map(|n| format!("p{n}.x86_64\np{n}.x86_64\n"))
            .collect();
        let (names, truncated) = parse_duplicate_packages(&many);
        assert_eq!((names.len(), truncated), (32, true));
        assert_eq!(
            parse_duplicate_packages("a b.x86_64\na b.x86_64\n"),
            (Vec::new(), false)
        );
    }

    /// W720: a folder-name part that no other test in this process uses. The
    /// clock alone can repeat across parallel tests.
    fn unique_suffix() -> String {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |time| time.as_nanos());
        let next = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("{nanos}-{next}")
    }

    #[test]
    fn samples_cap_and_merge_keep_the_observation_schema() {
        let root = std::env::temp_dir().join(format!(
            "rustiron-status-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        fs::create_dir_all(&root).expect("temp dir");
        let path = root.join("samples.json");
        let mut status = json!({
            "schema": STATUS_SCHEMA,
            "observed_at": 1,
            "cpu": { "count": 4, "load": [0.0, 0.4, 0.0] },
            "memory": { "total_bytes": 100, "available_bytes": 50 },
            "disk": { "path": "/", "total_bytes": 100, "available_bytes": 80 },
        });
        // Pre-seed MAX_SAMPLES - 2 entries once, then exercise real record_samples
        // fsyncs across the exact MAX_SAMPLES (2880) boundary and FIFO eviction.
        let seeded: Vec<Value> = (1..=MAX_SAMPLES - 2)
            .map(|tick| {
                status["observed_at"] = json!(tick);
                sample(&status)
            })
            .collect();
        write_json(
            &path,
            &json!({ "schema": SAMPLE_SCHEMA, "samples": seeded }),
        )
        .expect("seed");
        for tick in (MAX_SAMPLES - 1)..=MAX_SAMPLES + 3 {
            status["observed_at"] = json!(tick);
            record_samples(&path, &status).expect("record");
        }
        let stored = read_json(&path, MAX_STATUS_BYTES).expect("read");
        assert_eq!(
            stored["samples"].as_array().map(Vec::len),
            Some(MAX_SAMPLES)
        );
        assert_eq!(stored["samples"][0]["t"], 4);
        let observation = json!({
            "schema": OBSERVATION_SCHEMA,
            "host": { "host_id": "lab" },
            "sites": [],
        });
        let merged = merge_observation(observation, status, Some(&stored)).expect("merge");
        assert_eq!(merged["schema"], OBSERVATION_SCHEMA);
        assert_eq!(merged["machine"]["schema"], STATUS_SCHEMA);
        assert_eq!(
            merged["machine"]["samples"].as_array().map(Vec::len),
            Some(MAX_SAMPLES)
        );
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn an_empty_samples_file_starts_a_new_history() {
        let root = std::env::temp_dir().join(format!(
            "rustiron-empty-samples-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        fs::create_dir_all(&root).expect("temp dir");
        let path = root.join("samples.json");
        fs::write(&path, "").expect("empty file");
        let status = json!({
            "schema": STATUS_SCHEMA,
            "observed_at": 9,
            "cpu": { "count": 4, "load": [0.0, 0.4, 0.0] },
            "memory": { "total_bytes": 100, "available_bytes": 50 },
            "disk": { "path": "/", "total_bytes": 100, "available_bytes": 80 },
        });
        let stored = record_samples(&path, &status).expect("empty file is a new history");
        assert_eq!(stored["schema"], SAMPLE_SCHEMA);
        assert_eq!(stored["samples"].as_array().map(Vec::len), Some(1));
        assert_eq!(stored["samples"][0]["t"], 9);
        fs::write(&path, "{\"schema\":\"other\"}\n").expect("wrong schema");
        assert_eq!(
            record_samples(&path, &status).expect_err("wrong schema"),
            ErrorCode::UnsupportedVersion
        );
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn a_symlink_status_file_is_refused() {
        let root = std::env::temp_dir().join(format!(
            "rustiron-status-link-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        fs::create_dir_all(&root).expect("temp dir");
        let target = root.join("real.json");
        let link = root.join("status.json");
        fs::write(&target, "{}\n").expect("target");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let err = write_json(&link, &json!({"schema": STATUS_SCHEMA})).expect_err("symlink");
        assert_eq!(err, ErrorCode::InvalidRequest);
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn parses_lsphp_module_listing_and_refuses_bad_lines() {
        let sample = "\n[PHP Modules]\nCore\ncurl\nPDO\nSimpleXML\nZend OPcache\n\n[Zend Modules]\nZend OPcache\n";
        assert_eq!(
            parse_php_modules(sample),
            Some(vec![
                "core".to_owned(),
                "curl".to_owned(),
                "pdo".to_owned(),
                "simplexml".to_owned(),
                "zend_opcache".to_owned(),
            ])
        );
        assert_eq!(parse_php_modules(""), None);
        assert_eq!(parse_php_modules("[PHP Modules]\n"), None);
        assert_eq!(parse_php_modules("[PHP Modules]\ncurl\nbad;cmd\n"), None);
    }

    #[test]
    fn extracts_only_valid_rustiron_site_accounts_from_passwd() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\n\
                      rs_blog1:x:3001:3001::/srv/sites/rs_blog1:/sbin/nologin\n\
                      rs_cp02:x:3002:3002::/srv/sites/rs_cp02:/sbin/nologin\n\
                      rs_blog1:x:3001:3001::/srv/sites/rs_blog1:/sbin/nologin\n\
                      rs_BAD:x:3003:3003::/tmp:/sbin/nologin\n\
                      rs_:x:3004:3004::/tmp:/sbin/nologin\n";
        assert_eq!(
            site_accounts_from_passwd(passwd),
            vec!["rs_blog1".to_owned(), "rs_cp02".to_owned()]
        );
    }

    #[test]
    fn app_unit_indices_filter_before_capping_past_forty_non_app_sites() {
        let mut sites: Vec<Value> = (0..40)
            .map(|n| json!({"site_id": format!("wp{n}"), "state": "succeeded"}))
            .collect();
        sites
            .push(json!({"site_id": "nodeapp", "state": "succeeded", "app_runtime": "node_22_v1"}));
        sites.push(json!({"site_id": "delapp", "state": "deleted", "app_runtime": "bun_1_v1"}));
        sites.push(json!({"site_id": "bunapi", "state": "succeeded", "app_runtime": "bun_1_v1"}));
        assert_eq!(app_unit_indices(&sites), vec![40, 42]);
    }
}
