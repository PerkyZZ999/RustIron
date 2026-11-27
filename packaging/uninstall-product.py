#!/usr/bin/env python3
"""Remove the Rustiron product installation that install-product.py made (W385).

The command reads /var/lib/rustiron/install-record.json and acts only on
the paths, units, accounts, and policy modules that the record names. It
refuses a recorded file whose bytes, owner, or mode changed, and an entry
in an installed folder or a Rustiron unit path that the installation did
not make. It never changes site files, site databases, or site accounts.

By default it moves the evidence (the policy, the signer files, the
journal, the admission mark, the coordinator store, and the credentials)
to a new root-only folder below /var/lib/rustiron-archive. Only
--destroy-evidence deletes the evidence. W392: the receipt private key is
deleted before the archive move; the archive keeps the public key.

The operator chooses the OLS parent:

  --ols-parent keep     The Rustiron parent, its include, the ejected
                        configuration, and the site PHP units and modules
                        stay, so the served sites keep serving.
  --ols-parent package  The package parent comes back with its bytes,
                        owner, mode, and label. OLS stays stopped, and no
                        site that the Rustiron include served is served.
                        D-037 (W387): when the include serves sites that
                        site_eject made standalone, the command writes a
                        standalone parent instead, copies each standalone
                        vhost into the OLS configuration folder, starts
                        OLS, and checks that each of those sites answers.

The command prints each action and changes nothing without --apply.
"""

import argparse
import dataclasses
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import stat
import subprocess
import sys
import time


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load_script(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


installer = load_script("install_product", HERE / "install-product.py")
preflight = installer.preflight

RECORD = installer.INSTALL_RECORD
RECORD_LIMIT = 256 * 1024
ARCHIVE_ROOT = "var/lib/rustiron-archive"
UNIT_DIR = "etc/systemd/system"
INCLUDE = "etc/rustiron-ols"
CADDY_INCLUDE = "etc/rustiron-caddy"
EJECTED = "etc/rustiron-ejected"
# D-059: installed certificate chains, and the certbot account's state.
TLS = "etc/rustiron-tls"
ACME_STATE = "var/lib/rustiron-acme"
# D-083 (W510): the root-only push link of the alert check-in.
ALERT_PUSH_LINK = "etc/rustiron/alert-push.url"
# D-059: the installer masks the certbot package's own renewal timer.
CERTBOT_TIMER = "certbot-renew.timer"
TLS_LIMIT = 64 * 1024
STATE = "var/lib/rustiron"
COORDINATOR_STATE = "var/lib/rustiron-coordinator"
# The enrollment drop-in of docs/operator/09-PRODUCT-ENROLLMENT.md step 7.
HELPER_DROPIN = f"{UNIT_DIR}/rustiron-admin-helper.service.d"
SITE_SOCKETS = "run/rustiron-sites"
# The lock file of check-site-sandbox (W046).
SANDBOX_LOCK = "run/rustiron-check-site-sandbox.lock"
SITE_SOCKET = re.compile(r"rs_[a-z][a-z0-9_]{0,31}\.sock")
SITES = preflight.SITES_ROOT
PROBES = "srv/restore-probes"
# What a served site needs after the uninstallation with --ols-parent keep.
# The PHP template starts check-site-sandbox before each pool. The
# rustiron_php module needs a type of rustiron_admin (W383), and
# rustiron_admin and rustiron_executor need types of each other, so the
# three modules stay together.
SERVING_PAYLOAD = (
    f"{UNIT_DIR}/rustiron-site-php@.service",
    f"{UNIT_DIR}/rustiron-site-php@.socket",
    f"{UNIT_DIR}/rustiron-site-sandbox-check@.service",
    f"{UNIT_DIR}/rustiron-site-sandbox-check@.timer",
    "usr/libexec/rustiron/check-site-sandbox",
)
SERVING_MODULES = ("rustiron_admin", "rustiron_executor", "rustiron_php")
SERVING_STATE = (INCLUDE, f"{INCLUDE}/generations", EJECTED, SITES, STATE, f"{STATE}/ols-package")
KEPT_STATE_ENTRIES = ("ols-package", "install-record.json")
# Port types that a module defines. A local port label of a removed type
# blocks the module removal, so it goes first.
MODULE_PORT_TYPES = {
    "rustiron_admin": ("rustiron_ols_port_t",),
    "rustiron_store_relay": ("rustiron_store_port_t",),
}
# The OLS boot guard refuses a manual stop (RefuseManualStop=yes); it is a
# finished oneshot, and nothing starts it once its drop-in is gone.
BOOT_GUARD = "rustiron-ols-boot-guard.service"
# How long OLS may take to close its listeners after a stop. With the package
# KillMode=none, systemd reports the unit stopped while the graceful stop
# still runs; in W385 the old processes kept the listener for about 2 s.
LISTENER_CLOSE_SECONDS = 120
LISTEN_TABLES = ("/proc/net/tcp", "/proc/net/tcp6")
RELAY_INSTANCES = (
    "/usr/bin/systemctl", "list-units", "--all", "--plain", "--no-legend", "--full",
    "rustiron-store-relay@*", "rustiron-mail-relay@*",
)
OBSERVE = (
    "/usr/bin/systemd-run", "--wait", "--pipe", "--quiet",
    "/usr/libexec/rustiron/rustiron-executor", "observe",
)
EXECUTOR = "usr/libexec/rustiron/rustiron-executor"
JOURNAL = f"{STATE}/executor"
# The states that docs/operator/11-AFTER-POWER-LOSS.md lists as not settled.
UNRESOLVED = ("intent", "running", "verifying", "compensating", "needs_attention", "cleanup_incomplete")
SITE_DROPIN = re.compile(r"rustiron-site-php@(rs_[a-z][a-z0-9_]{0,31})\.service\.d")
SITE_LINK = re.compile(
    r"rustiron-(?:site-php@(rs_[a-z][a-z0-9_]{0,31})\.socket|"
    r"site-sandbox-check@(rs_[a-z][a-z0-9_]{0,31})\.timer)"
)
GENERATION = re.compile(r"generations/[A-Za-z0-9_-]{1,64}")
INCLUDE_LIMIT = 1024 * 1024
HEX64 = re.compile(r"[0-9a-f]{64}")
# D-037 (W387): the standalone configuration of ejected sites. Each vhost
# goes to the OLS package's own vhost folder; the parent names it there.
OLS_VHOSTS = "usr/local/lsws/conf/vhosts"
STANDALONE_FILE = "vhconf.conf"
VHOST_LIMIT = 256 * 1024
ACCOUNT = re.compile(r"rs_[a-z][a-z0-9_]{0,31}")
HOSTNAME = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")
LISTENER = re.compile(r"[A-Za-z0-9_]{1,64}")
ADDRESS = re.compile(r"(?:\*|[0-9.]{7,15}|\[[0-9a-f:]{2,39}\]):[0-9]{1,5}")
STANDALONE_HEADER = (
    "# Standalone OpenLiteSpeed server configuration for ejected sites (D-037).\n"
    "# The product uninstaller wrote this file. The operator owns it now.\n"
    "# It keeps the reviewed server settings, with WebAdmin disabled, and serves\n"
    "# each ejected site from conf/vhosts/<account>/vhconf.conf. Static sites\n"
    "# keep scripts disabled. The package parent is in the archive.\n\n"
)
# How long the started OLS has to answer for each standalone site.
PROBE_SECONDS = 60
STATIC_VHOST_NAMES = {
    b"# Standalone static vhost": 2,
    b"# Standalone single-name static vhost": 1,
}


class Refused(Exception):
    def __init__(self, reasons):
        super().__init__("; ".join(reasons))
        self.reasons = list(reasons)


@dataclasses.dataclass
class Options:
    ols_parent: str | None = None
    leave_managed_sites: bool = False
    unserve_sites: bool = False
    destroy_evidence: bool = False
    accept_unresolved: bool = False


@dataclasses.dataclass
class Site:
    account: str
    config: str
    ejected: bool
    hostname: str | None = None
    # D-037 (W387): ejected with the standalone vhost that site_eject renders.
    standalone: bool = False
    # D-064 (W471): its standalone vhost serves the installed chain.
    tls: bool = False
    tls_hostname: str | None = None
    static_names: int | None = None

    @property
    def static(self):
        return self.static_names is not None


@dataclasses.dataclass
class Plan:
    notes: list
    actions: list
    # D-037 (W387): the accounts that the standalone parent serves.
    standalone: list = dataclasses.field(default_factory=list)


# The install record


def check_record(record):
    """The record names only paths, modules, and identities of the product."""
    problems = []
    if not isinstance(record, dict) or record.get("schema") != installer.INSTALL_RECORD_SCHEMA:
        return ["unrecognized install record"]
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return ["install record has no payload"]
    for name, entry in payload.items():
        if installer.PAYLOAD_MODES.get(name) is None:
            problems.append(f"install record names /{name}, which is not a product file")
        elif (not isinstance(entry, dict) or entry.get("mode") != installer.PAYLOAD_MODES[name]
              or not HEX64.fullmatch(str(entry.get("sha256")))):
            problems.append(f"install record entry for /{name} is not valid")
    allowed = {
        "created_directories": installer.payload_directories(),
        "state_directories": set(installer.STATE_DIRS),
        "modules": set(preflight.MODULES),
        "users": set(installer.SYSUSERS_USERS),
        "groups": set(installer.SYSUSERS_GROUPS),
        "relabelled": {installer.LSPHP},
    }
    for key, names in allowed.items():
        value = record.get(key)
        if not isinstance(value, list) or not all(isinstance(name, str) for name in value):
            problems.append(f"install record has no list {key}")
            continue
        for name in value:
            if name not in names:
                problems.append(f"install record names {name} in {key}, which the product does not make")
    for key in ("sites_mount_kept", "serving_kept"):
        if not isinstance(record.get(key), bool):
            problems.append(f"install record has no {key}")
    if not HEX64.fullmatch(str(record.get("shipped_parent_sha256"))):
        problems.append("install record has no shipped parent digest")
    parent = record.get("package_parent")
    if parent is not None and not (
        isinstance(parent, dict) and HEX64.fullmatch(str(parent.get("sha256")))
        and all(isinstance(parent.get(key), int) for key in ("uid", "gid", "mode"))
        and 0 <= parent["mode"] <= 0o777
        and (parent.get("selinux_type") is None or isinstance(parent["selinux_type"], str))
    ):
        problems.append("install record has an invalid package parent entry")
    return problems


def load_record(target, owner=0):
    path = target / RECORD
    try:
        info = path.lstat()
        content = installer.read_regular(path, RECORD_LIMIT)
    except FileNotFoundError:
        raise Refused([f"no install record /{RECORD}: install-product.py did not install this host"]) from None
    except (OSError, ValueError) as error:
        raise Refused([f"unreadable install record /{RECORD}: {error}"]) from None
    if info.st_uid != owner or info.st_mode & 0o022:
        raise Refused([f"install record /{RECORD} is not owned by root or is writable by others"])
    try:
        record = json.loads(content)
    except ValueError:
        raise Refused([f"install record /{RECORD} is not JSON"]) from None
    problems = check_record(record)
    if problems:
        raise Refused(problems)
    return record


def file_digest(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def payload_present(target, name, entry, owner=0):
    """True for the installed file, False when absent; refuse anything else."""
    path = target / name
    info = preflight.metadata(path)
    if info is None:
        return False
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or (info.st_uid, info.st_gid) != (owner, owner)
            or stat.S_IMODE(info.st_mode) != entry["mode"]
            or file_digest(path) != entry["sha256"]):
        raise ValueError(f"/{name} differs from the installed file")
    return True


# Host facts


def served_sites(target):
    """The virtual hosts that the live Rustiron include serves, in file order."""
    return include_facts(target)[0]


def listener_ports(target):
    """The TCP ports of the listeners that the live Rustiron include defines."""
    return include_facts(target)[1]


def include_facts(target):
    """(sites, listener ports) of the live Rustiron include; both empty without `current`."""
    sites, ports, _listener, _tls = include_listener(target)
    return sites, ports


def include_listener(target):
    """(sites with hostnames, listener ports, plain listener, TLS listener) of the include.

    Each listener is (name, address) or None.
    """
    link = target / INCLUDE / "current"
    if not link.is_symlink():
        if preflight.metadata(link) is not None:
            raise Refused([f"/{INCLUDE}/current is not a link"])
        return [], [], None, None
    destination = os.readlink(link)
    if not GENERATION.fullmatch(destination):
        raise Refused([f"/{INCLUDE}/current names {destination!r}, not a generation"])
    vhosts = target / INCLUDE / destination / "vhosts.conf"
    try:
        text = installer.read_regular(vhosts, INCLUDE_LIMIT).decode("utf-8")
    except (OSError, ValueError, UnicodeDecodeError) as error:
        raise Refused([f"unreadable /{INCLUDE}/{destination}/vhosts.conf: {error}"]) from None
    sites, ports, account, listeners, maps, secure = [], [], None, [], [], []
    in_listener = False
    for line in text.splitlines():
        words = line.split()
        if len(words) == 2 and words[0] == "address" and words[1].rpartition(":")[2].isdecimal():
            ports.append(int(words[1].rpartition(":")[2]))
            if in_listener and listeners[-1][1] is None:
                listeners[-1] = (listeners[-1][0], words[1])
        if len(words) == 3 and words[0] == "listener" and words[2] == "{":
            listeners.append((words[1], None))
            secure.append(False)
            maps.append({})
            in_listener = True
        elif words == ["}"]:
            in_listener = False
        elif words == ["secure", "1"] and in_listener:
            secure[-1] = True
        elif len(words) == 3 and words[0] == "map" and in_listener:
            if words[1] in maps[-1]:
                raise Refused([f"duplicate listener map for {words[1]}"])
            maps[-1][words[1]] = words[2]
        elif len(words) == 3 and words[0] == "virtualHost" and words[2] == "{":
            account = words[1]
        elif account and len(words) == 2 and words[0] == "configFile":
            ejected = words[1] == f"/{EJECTED}/{account}/vhost.conf"
            sites.append(Site(account, words[1], ejected))
            account = None
    # D-059: the plain listener, and the one TLS listener when there is one.
    plain = [i for i, is_tls in enumerate(secure) if not is_tls]
    tls = [i for i, is_tls in enumerate(secure) if is_tls]
    listener = listeners[plain[0]] if len(plain) == 1 and len(tls) <= 1 else None
    for site in sites:
        if listener is not None:
            site.hostname = maps[plain[0]].get(site.account)
        if len(tls) == 1:
            site.tls_hostname = maps[tls[0]].get(site.account)
    return sites, sorted(set(ports)), listener, (listeners[tls[0]] if len(tls) == 1 else None)


def static_name_count(content):
    return STATIC_VHOST_NAMES.get(content.partition(b"\n")[0])


def standalone_vhost(target, account, owner=0):
    """(bytes, None) for a standalone vhost of an ejected site, else (None, the reason).

    A standalone site serves static files or starts PHP through OLS as its
    site account. A vhost copied by an earlier eject still uses managed PHP.
    """
    path = target / EJECTED / account / "vhost.conf"
    try:
        info = path.lstat()
        content = installer.read_regular(path, VHOST_LIMIT)
        text = content.decode("utf-8")
    except (OSError, ValueError, UnicodeDecodeError) as error:
        return None, f"unreadable /{EJECTED}/{account}/vhost.conf: {error}"
    if info.st_uid != owner or info.st_mode & 0o022 or info.st_nlink != 1:
        return None, f"/{EJECTED}/{account}/vhost.conf is not a root-owned file"
    # D-064 (W470): the one vhssl block that site_eject renders names the
    # installed chain; the hand-over points it at the copies.
    static = static_name_count(content) is not None
    installed = ssl_block(f"/{TLS}/{account}/live")
    tls_copy = ""
    if text.endswith(installed):
        text = text.removesuffix(installed)
        tls_copy = ssl_block(f"/{OLS_VHOSTS}/{account}")
    lines = {line.strip() for line in text.splitlines()}
    standalone = static or {f"extUser {account}", f"extGroup {account}"} <= lines
    config_lines = (line for line in lines if not (static and line.startswith("vhDomain ")))
    if not standalone or any("rustiron" in line.lower() for line in config_lines):
        return None, f"{account} was ejected before W387; its vhost uses the Rustiron PHP unit"
    if static and re.search(r"^\s*vhssl\b", text, re.MULTILINE | re.IGNORECASE):
        return None, f"{account} has an unexpected standalone TLS block"
    return (text + tls_copy).encode(), None


def ssl_block(folder):
    """The vhost SSL block of D-059 for the chain in `folder`."""
    return f"vhssl {{\n keyFile {folder}/key.pem\n certFile {folder}/fullchain.pem\n certChain 1\n}}\n"


def installed_chain(target, account, owner=0, *, verify_digest=False):
    """D-064: (fullchain bytes, key bytes) of the site's live chain, or raise ValueError."""
    folder = target / TLS / account / "live"
    if not folder.is_symlink() or not HEX64.fullmatch(os.readlink(folder)):
        raise ValueError(f"/{TLS}/{account}/live is not the link to an installed chain")
    files = []
    for name in ("fullchain.pem", "key.pem"):
        path = folder / name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_nlink != 1:
            raise ValueError(f"/{TLS}/{account}/live/{name} is not a root-owned file")
        files.append(installer.read_regular(path, TLS_LIMIT))
    if b"-----BEGIN CERTIFICATE-----" not in files[0] or b"PRIVATE KEY-----" not in files[1]:
        raise ValueError(f"/{TLS}/{account}/live does not hold a chain and a key")
    if verify_digest and hashlib.sha256(files[0]).hexdigest() != os.readlink(folder):
        raise ValueError(f"/{TLS}/{account}/live chain does not match its installed digest")
    return tuple(files)


def standalone_parent(shipped, sites, listener, tls_listener=None):
    """The standalone parent: the shipped server settings, a virtual host for each site, one listener.

    The comment lines and the include line of the shipped parent go. The
    virtual host lines are the ones that the executor renders for a site.
    """
    body, blank = [], True
    for line in shipped.decode("utf-8").splitlines():
        if line.lstrip().startswith("#") or line.startswith("include "):
            continue
        if not line.strip():
            if not blank:
                body.append("")
            blank = True
            continue
        body.append(line)
        blank = False
    text = STANDALONE_HEADER + "\n".join(body).rstrip("\n") + "\n\n"
    ordered = sorted(sites, key=lambda site: site.account)
    for site in ordered:
        scripts = int(not site.static)
        text += (f"virtualHost {site.account} {{\n vhRoot /{SITES}/{site.account}/\n"
                 f" configFile $SERVER_ROOT/conf/vhosts/{site.account}/{STANDALONE_FILE}\n"
                 f" allowSymbolLink 0\n enableScript {scripts}\n restrained 1\n setUIDMode 0\n}}\n")
    name, address = listener
    text += f"listener {name} {{\n address {address}\n secure 0\n"
    for site in ordered:
        text += f" map {site.account} {site.hostname}\n"
    text += "}\n"
    # D-064 (W471): the TLS listener of the sites whose chain was handed over.
    secure = [site for site in ordered if site.tls]
    if secure and tls_listener is not None:
        tls_name, tls_address = tls_listener
        folder = f"/{OLS_VHOSTS}/{secure[0].account}"
        text += (f"listener {tls_name} {{\n address {tls_address}\n secure 1\n"
                 f" keyFile {folder}/key.pem\n certFile {folder}/fullchain.pem\n certChain 1\n")
        for site in secure:
            text += f" map {site.account} {site.tls_hostname}\n"
        text += "}\n"
    return text.encode()


def probe_address(address):
    """The local address to probe a listener on: a wildcard host becomes 127.0.0.1."""
    host, _, port = address.rpartition(":")
    return f"127.0.0.1:{port}" if host in ("*", "0.0.0.0") else address


def php_answered(status, redirect_by, page):
    """The PHP login page shows a working PHP: the WordPress login form (200), or the
    WordPress redirect of a site that is not installed yet (302 with X-Redirect-By).
    Both need the site's PHP and its database connection. The PHP source is never one."""
    if "<?php" in page:
        return False
    return (status == 200 and "loginform" in page) or (status == 302 and redirect_by == "WordPress")


def site_response(address, hostname, path, leaf):
    host, _, port = probe_address(address).rpartition(":")
    connection = http.client.HTTPConnection(host.strip("[]"), int(port), timeout=10)
    try:
        if leaf is not None:
            # The lab does not install the private CA in the host trust store.
            # Pin the leaf from the trusted, copied chain and send the exact SNI.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            connection.connect()
            connection.sock = context.wrap_socket(connection.sock, server_hostname=hostname)
            if hashlib.sha256(connection.sock.getpeercert(binary_form=True)).digest() != leaf:
                raise OSError("TLS leaf differs from the handed-over certificate")
        connection.request("GET", path, headers={"Host": hostname})
        response = connection.getresponse()
        return (response.status, response.getheader("X-Redirect-By", ""),
                response.read(1024 * 1024).decode("utf-8", "replace"),
                response.getheader("Location", ""))
    finally:
        connection.close()


def probe_site(address, hostname, account, *, static=False, leaf=None, https_redirect=False):
    """A standalone site answers with its marker and, for WordPress, its login.
    With `https_redirect`, the exact redirect of the marker to the same name over
    HTTPS also answers (W511-F3): the site's own rules apply to its marker after the
    eject; the HTTPS probe with the pinned leaf checks the marker itself."""
    deadline = time.monotonic() + PROBE_SECONDS
    last = "no answer"
    while True:
        try:
            marker_status, _, marker, location = site_response(
                address, hostname, "/rustiron-site.txt", leaf)
            last = f"marker {marker_status}"
            accepted = marker_status == 200 and marker.strip() == account
            if not accepted and https_redirect and marker_status in (301, 302, 307, 308):
                accepted = location == f"https://{hostname}/rustiron-site.txt"
                static = True
            if accepted and not static:
                status, redirect_by, page, _ = site_response(address, hostname, "/wp-login.php", leaf)
                last += f", PHP login page {status}"
                accepted = php_answered(status, redirect_by, page)
            if accepted:
                listener = "HTTPS" if leaf is not None else "HTTP"
                print(f"PROBE {account} {hostname}: {listener} {last}", flush=True)
                return
        except (OSError, http.client.HTTPException) as error:
            last = str(error)
        if time.monotonic() > deadline:
            raise ValueError(f"{account} does not answer through {address}: {last}")
        time.sleep(1)


def unresolved_operations(observation):
    """Every `operation_id state` pair at any depth whose state is not settled."""
    found = []

    def walk(value):
        if isinstance(value, dict):
            if value.get("state") in UNRESOLVED and isinstance(value.get("operation_id"), str):
                found.append(f"{value['operation_id']} {value['state']}")
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(observation)
    return found


def management_units(record, present):
    """The installed management timers, then services, that are present, without
    templates and the guard. W511-F4 (P08): an enabled timer (the scheduled capture,
    the WordPress jobs, the alert check-in) is stopped and disabled first, so it
    neither starts a removed service nor leaves its enable link behind."""
    names = {".timer": [], ".service": []}
    for name in sorted(record["payload"]):
        unit = Path(name).name
        kind = Path(unit).suffix
        if (name.startswith("usr/lib/systemd/system/") and present.get(name)
                and kind in names and "@" not in unit and unit != BOOT_GUARD):
            names[kind].append(unit)
    return [*names[".timer"], *names[".service"]]


def management_unit_names(record):
    names = []
    for name in record["payload"]:
        if name.startswith("usr/lib/systemd/system/"):
            names.append(Path(name).name)
    return names


def is_management_unit(name, units):
    for unit in units:
        if name == unit:
            return True
        if "@." in unit:
            prefix, suffix = unit.split("@.", 1)
            if name.startswith(prefix + "@") and name.endswith("." + suffix):
                return True
    return False


def scan_units(target, record):
    """Classify each Rustiron path in the unit folders; refuse unknown ones.

    Returns (site accounts, site drop-in folders, enrollment folders).
    """
    units = management_unit_names(record)
    accounts, dropins, enrollment, problems = set(), [], [], []
    for root in preflight.UNIT_ROOTS:
        folder = target / root
        if not folder.is_dir() or folder.is_symlink():
            continue
        for entry in sorted(folder.iterdir()):
            relative = f"{root}/{entry.name}"
            if entry.name.startswith("rustiron-"):
                site = SITE_DROPIN.fullmatch(entry.name)
                if relative in record["payload"]:
                    continue
                if relative == HELPER_DROPIN:
                    enrollment.append(relative)
                elif root == UNIT_DIR and site:
                    accounts.add(site.group(1))
                    dropins.append(relative)
                else:
                    problems.append(f"/{relative} was not installed")
            elif entry.suffix in {".wants", ".requires", ".upholds"} and entry.is_dir():
                for link in sorted(entry.glob("rustiron-*")):
                    site = SITE_LINK.fullmatch(link.name)
                    if site:
                        accounts.add(site.group(1) or site.group(2))
                    elif not is_management_unit(link.name, units):
                        problems.append(f"/{root}/{entry.name}/{link.name} was not installed")
    if problems:
        raise Refused(problems)
    return sorted(accounts), dropins, enrollment


def unknown_entries(target, record, kept):
    """Entries of installed folders that neither the record nor a kept file names."""
    payload = set(record["payload"]) | set(kept)
    created = set(record["created_directories"])
    problems = []
    for directory in sorted(created):
        path = target / directory
        if not path.is_dir() or path.is_symlink():
            continue
        for entry in sorted(path.iterdir()):
            relative = f"{directory}/{entry.name}"
            if relative not in payload and relative not in created:
                problems.append(f"/{relative} was not installed")
    return problems


def local_ports(text):
    """(type, protocol, port) for each local port label line."""
    labels = []
    for line in text.splitlines():
        words = line.replace(",", " ").split()
        if len(words) >= 3 and words[1] in ("tcp", "udp", "sctp", "dccp") and words[0].endswith("_t"):
            labels.extend((words[0], words[1], port) for port in words[2:])
    return labels


def existing(query, database, name):
    try:
        return query("/usr/bin/getent", database, name).strip()
    except (OSError, subprocess.SubprocessError):
        return ""


# Actions


def create_private(path, owner=0):
    path.mkdir(mode=0o700)
    os.chown(path, owner, owner)
    path.chmod(0o700)


def private_folders(archive, relative, owner=0):
    """Create each missing folder of `relative` below the archive, mode 0700."""
    folder = archive
    for part in Path(relative).parts:
        folder = folder / part
        if preflight.metadata(folder) is None:
            create_private(folder, owner)
    return folder


def move_into(archive, target, relative, owner=0):
    private_folders(archive, Path(relative).parent, owner)
    os.rename(target / relative, archive / relative)


def delete(path):
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


def write_exclusive(path, content, uid, gid, mode):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as written:
        written.write(content)
        written.flush()
        os.fchown(written.fileno(), uid, gid)
        os.fchmod(written.fileno(), mode)
        os.fsync(written.fileno())


def replace_file(path, content, uid, gid, mode):
    staged = path.with_name(f"{path.name}.rustiron-uninstall")
    write_exclusive(staged, content, uid, gid, mode)
    try:
        os.rename(staged, path)
    except BaseException:
        staged.unlink(missing_ok=True)
        raise
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def write_manifest(archive, owner=0):
    """MANIFEST: sha256sum lines for each file. METADATA: kind, owner, mode of each entry."""
    sums, metadata = [], []
    for path in sorted(archive.rglob("*")):
        relative = str(path.relative_to(archive))
        info = path.lstat()
        kind = "dir" if stat.S_ISDIR(info.st_mode) else "link" if stat.S_ISLNK(info.st_mode) else "file"
        metadata.append(f"{kind} {info.st_uid}:{info.st_gid} {stat.S_IMODE(info.st_mode):04o} {relative}")
        if kind == "file":
            sums.append(f"{file_digest(path)}  {relative}")
    write_exclusive(archive / "MANIFEST", ("\n".join(sums) + "\n").encode(), owner, owner, 0o400)
    write_exclusive(archive / "METADATA", ("\n".join(metadata) + "\n").encode(), owner, owner, 0o400)


def clean_runtime(target):
    """Remove what the stopped site units leave in /run (W385).

    systemd keeps a socket file after the socket unit stops. Only sockets
    named after a site account and the sandbox check lock go; any other
    entry keeps the folder.
    """
    sockets = target / SITE_SOCKETS
    if sockets.is_dir() and not sockets.is_symlink():
        for entry in sockets.iterdir():
            if SITE_SOCKET.fullmatch(entry.name) and stat.S_ISSOCK(entry.lstat().st_mode):
                entry.unlink()
        if not any(sockets.iterdir()):
            sockets.rmdir()
    lock = target / SANDBOX_LOCK
    info = preflight.metadata(lock)
    if info is not None and stat.S_ISREG(info.st_mode):
        lock.unlink()


def stop_and_disable(runner, query, units):
    """Stop the loaded units, then disable each one that `systemctl is-enabled` reports enabled."""
    loaded = []
    for unit in units:
        try:
            if query("/usr/bin/systemctl", "show", "-p", "LoadState", "--value", unit).strip() == "loaded":
                loaded.append(unit)
        except (OSError, subprocess.SubprocessError):
            continue
    units = loaded
    if not units:
        return
    runner("/usr/bin/systemctl", "stop", *units)
    enabled = []
    for unit in units:
        try:
            if query("/usr/bin/systemctl", "is-enabled", unit).strip() == "enabled":
                enabled.append(unit)
        except (OSError, subprocess.SubprocessError):
            continue
    if enabled:
        runner("/usr/bin/systemctl", "disable", *enabled)


def remove_payload(target, name, entry, owner):
    if payload_present(target, name, entry, owner):
        (target / name).unlink()


def report_config_test(runner, which="the package parent"):
    """Run `openlitespeed -t` once and print its result; it is not a gate.

    W385: the package parent of openlitespeed 1.9.4 gives exit status 1 with
    only two WARN lines for the Example virtual host, and OLS starts with it.
    """
    try:
        runner("/usr/local/lsws/bin/openlitespeed", "-t")
        print(f"NOTE OLS configuration test of {which}: exit status 0", flush=True)
    except subprocess.CalledProcessError as error:
        print(f"NOTE OLS configuration test of {which}: exit status {error.returncode}", flush=True)


def check_parent_label(target, expected):
    path = target / installer.OLS_PARENT
    try:
        found = preflight.selinux_type(path)
    except OSError:
        return
    if expected and found != expected:
        raise ValueError(f"/{installer.OLS_PARENT} has SELinux type {found}, expected {expected}")


@dataclasses.dataclass
class Facts:
    """What the read-only checks found; the actions use it."""
    target: Path
    record: dict
    keep: bool
    archive: Path
    owner: int
    present: dict = dataclasses.field(default_factory=dict)
    kept_payload: list = dataclasses.field(default_factory=list)
    accounts: list = dataclasses.field(default_factory=list)
    site_dropins: list = dataclasses.field(default_factory=list)
    enrollment: list = dataclasses.field(default_factory=list)
    sites: list = dataclasses.field(default_factory=list)
    ports: list = dataclasses.field(default_factory=list)
    package_bytes: bytes | None = None
    restored: bool = False
    ports_text: str = ""
    fcontexts_text: str = ""
    loaded: set = dataclasses.field(default_factory=set)
    removed_modules: list = dataclasses.field(default_factory=list)
    port_labels: list = dataclasses.field(default_factory=list)
    evidence: list = dataclasses.field(default_factory=list)
    # D-037 (W387): with the package parent, the standalone sites, their
    # vhost bytes, the listener, and the standalone parent bytes.
    listener: tuple | None = None
    standalone: list = dataclasses.field(default_factory=list)
    vhosts: dict = dataclasses.field(default_factory=dict)
    standalone_bytes: bytes | None = None
    # D-064 (W471): the TLS listener, and each TLS standalone site's chain and key.
    tls_listener: tuple | None = None
    chains: dict = dataclasses.field(default_factory=dict)


def check_installation(facts, problems):
    """Recorded files, installed folders, and Rustiron unit paths."""
    target, record = facts.target, facts.record
    facts.kept_payload = [name for name in SERVING_PAYLOAD if facts.keep and name in record["payload"]]
    for name, entry in sorted(record["payload"].items()):
        try:
            facts.present[name] = payload_present(target, name, entry, facts.owner)
        except (OSError, ValueError) as error:
            problems.append(str(error))
    problems.extend(unknown_entries(target, record, facts.kept_payload))
    try:
        facts.accounts, facts.site_dropins, facts.enrollment = scan_units(target, record)
    except Refused as refused:
        problems.extend(refused.reasons)


def check_sites(facts, options, notes, problems):
    """The served sites against the parent choice and its acknowledgement.

    D-037 (W387): with the package parent, a site that site_eject made
    standalone keeps serving and needs no acknowledgement.
    """
    try:
        facts.sites, facts.ports, facts.listener, facts.tls_listener = include_listener(facts.target)
    except Refused as refused:
        problems.extend(refused.reasons)
    legacy = {}
    for site in facts.sites:
        if site.ejected:
            content, reason = standalone_vhost(facts.target, site.account, facts.owner)
            site.standalone = content is not None
            if content is not None:
                facts.vhosts[site.account] = content
                site.tls = content.endswith(ssl_block(f"/{OLS_VHOSTS}/{site.account}").encode())
                site.static_names = static_name_count(content)
            else:
                legacy[site.account] = reason
    for site in facts.sites:
        how = "ejected" if site.ejected else "not ejected"
        if site.static:
            action = "SERVES" if facts.keep else "STANDALONE"
            notes.append(f"{action} {site.account} keeps serving as a static vhost")
        elif facts.keep and site.standalone:
            notes.append(f"SERVES {site.account} (ejected) through /{INCLUDE}/current and {site.config}; "
                         f"OLS starts its PHP as {site.account}")
        elif facts.keep:
            notes.append(f"SERVES {site.account} ({how}) through /{INCLUDE}/current, {site.config}, "
                         f"rustiron-site-php@{site.account}.socket, and the rustiron_php module")
        elif site.standalone:
            notes.append(f"STANDALONE {site.account} keeps serving: OLS starts its PHP as {site.account} "
                         f"from /{OLS_VHOSTS}/{site.account}/{STANDALONE_FILE}")
        else:
            notes.append(f"UNSERVED {site.account} ({how}): the package parent does not load the "
                         "Rustiron include")
    managed = [site.account for site in facts.sites if not site.ejected]
    if facts.keep and managed and not options.leave_managed_sites:
        problems.append(f"sites served and not ejected: {', '.join(managed)}. Eject them, or pass "
                        "--leave-managed-sites to leave them served as-is by the Rustiron-rendered include")
    if facts.keep:
        return
    unserved = [site.account for site in facts.sites if not site.standalone]
    if unserved and not options.unserve_sites:
        problems.append(f"sites served by the Rustiron include: {', '.join(unserved)}. "
                        "The package parent stops serving them; pass --unserve-sites to accept that")
        problems.extend(legacy[account] for account in unserved if account in legacy)
    facts.standalone = [site for site in facts.sites if site.standalone]
    check_standalone(facts, problems)


def check_standalone(facts, problems):
    """The listener, the maps, and free OLS vhost folders for the standalone sites."""
    if not facts.standalone:
        return
    name, address = facts.listener or (None, None)
    if not LISTENER.fullmatch(name or "") or not ADDRESS.fullmatch(address or ""):
        problems.append(f"the include defines no single listener for the standalone sites: {facts.listener}")
        facts.listener = None
    vhosts = facts.target / OLS_VHOSTS
    if not vhosts.is_dir() or vhosts.is_symlink():
        problems.append(f"/{OLS_VHOSTS} is not the OLS package's vhost folder")
    if any(site.tls for site in facts.standalone):
        tls_name, tls_address = facts.tls_listener or (None, None)
        if not LISTENER.fullmatch(tls_name or "") or not ADDRESS.fullmatch(tls_address or ""):
            problems.append(f"the include defines no single TLS listener for the standalone sites: "
                            f"{facts.tls_listener}")
    for site in facts.standalone:
        http_names = (site.hostname or "").split(",")
        tls_names = (site.tls_hostname or "").split(",")
        if (not ACCOUNT.fullmatch(site.account)
                or len(http_names) != (site.static_names or 1)
                or len(set(http_names)) != len(http_names)
                or not all(HOSTNAME.fullmatch(name) for name in http_names)
                or (site.tls and tls_names != http_names)
                or (site.static and not static_listener_scope(facts, site, http_names[0]))):
            problems.append(f"{site.account} has no valid listener map in the include")
        if site.tls:
            try:
                facts.chains[site.account] = installed_chain(
                    facts.target, site.account, facts.owner, verify_digest=site.static)
                # W511: the leaf pins the HTTPS probe of every handed-over site.
                static_chain_leaf(facts.chains[site.account][0])
            except (OSError, ValueError) as error:
                problems.append(f"{site.account}: {error}")
        folder = facts.target / OLS_VHOSTS / site.account
        if preflight.metadata(folder) is None:
            continue
        expected = {STANDALONE_FILE: facts.vhosts[site.account]}
        if site.account in facts.chains:
            expected.update(zip(("fullchain.pem", "key.pem"), facts.chains[site.account]))
        try:
            same = (not folder.is_symlink()
                    and sorted(entry.name for entry in folder.iterdir()) == sorted(expected)
                    and all(installer.read_regular(folder / name, VHOST_LIMIT) == content
                            for name, content in expected.items()))
        except (OSError, ValueError):
            same = False
        if not same:
            problems.append(f"/{OLS_VHOSTS}/{site.account} exists and is not the standalone vhost of a "
                            "failed run; move it away first")


def static_listener_scope(facts, site, primary):
    """Bind the standalone vhost to its primary map and enrolled lab listener scope."""
    domains = [words[1:] for line in facts.vhosts[site.account].splitlines()
               if (words := line.split()) and words[0].lower() == b"vhdomain"]
    if domains != [[primary.encode()]] or not is_loopback(facts.listener):
        return False
    if site.tls:
        return is_loopback(facts.tls_listener)
    return site.static_names == 1 and site.tls_hostname is None


def is_loopback(listener):
    if listener is None:
        return False
    try:
        return ipaddress.ip_address(listener[1].rpartition(":")[0].strip("[]")).is_loopback
    except (ValueError, AttributeError):
        return False


def static_chain_leaf(chain):
    end = b"-----END CERTIFICATE-----"
    first, separator, _ = chain.partition(end)
    if not separator or not first.startswith(b"-----BEGIN CERTIFICATE-----"):
        raise ValueError("the standalone chain has no leaf certificate")
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert((first + end).decode("ascii"))).digest()


def shipped_bytes(facts):
    """The shipped parent text: the installed template, or the live parent while it is the shipped one."""
    shipped = facts.record["shipped_parent_sha256"]
    for name in (installer.PARENT_TEMPLATE, installer.OLS_PARENT):
        try:
            content = installer.read_regular(facts.target / name)
        except (OSError, ValueError):
            continue
        if hashlib.sha256(content).hexdigest() == shipped:
            return content
    return None


def check_parent(facts, problems):
    """For the package parent: the shipped parent now, and the kept package copy."""
    if facts.keep:
        return
    parent = facts.record.get("package_parent")
    try:
        found = file_digest(facts.target / installer.OLS_PARENT)
    except OSError as error:
        found = None
        problems.append(f"unreadable /{installer.OLS_PARENT}: {error.strerror}")
    if facts.standalone and facts.listener is not None:
        # D-037 (W387): the standalone parent replaces the package parent.
        shipped = shipped_bytes(facts)
        if shipped is None:
            problems.append("the shipped parent text is not available to render the standalone parent")
        else:
            facts.standalone_bytes = standalone_parent(shipped, facts.standalone, facts.listener,
                                                       facts.tls_listener)
    # A run that failed after the restore finds the package or standalone bytes already.
    wanted = (hashlib.sha256(facts.standalone_bytes).hexdigest() if facts.standalone_bytes
              else parent["sha256"] if parent is not None else None)
    facts.restored = wanted is not None and found == wanted
    if found is not None and found != facts.record["shipped_parent_sha256"] and not facts.restored:
        problems.append(f"/{installer.OLS_PARENT} is not the shipped parent; restore refused")
    if parent is None:
        problems.append("the install record has no package parent to restore")
        return
    try:
        facts.package_bytes = installer.read_regular(facts.target / installer.PACKAGE_PARENT_COPY)
    except (OSError, ValueError) as error:
        problems.append(f"unreadable /{installer.PACKAGE_PARENT_COPY}: {error}")
        return
    if hashlib.sha256(facts.package_bytes).hexdigest() != parent["sha256"]:
        problems.append(f"/{installer.PACKAGE_PARENT_COPY} differs from the recorded package parent")


def check_journal(target, options, query, notes, problems):
    """No unresolved operation, unless the operator accepts archiving it."""
    journal = target / JOURNAL
    if not ((target / EXECUTOR).is_file() and journal.is_dir() and any(journal.iterdir())):
        return
    try:
        unresolved = unresolved_operations(json.loads(query(*OBSERVE)))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        unresolved = [f"the journal observation failed ({error})"]
    if unresolved and not options.accept_unresolved:
        problems.append("unresolved operations: " + ", ".join(unresolved)
                        + ". Settle them first (docs/operator/11-AFTER-POWER-LOSS.md), or pass "
                        "--accept-unresolved to archive them unresolved")
    notes.extend(f"UNRESOLVED {line}" for line in unresolved)


def check_selinux(facts, query, problems):
    """The modules to remove and the local labels that name their types."""
    removed = set(facts.record["modules"]) - (set(SERVING_MODULES) if facts.keep else set())
    facts.removed_modules = sorted(removed)
    removed_ports = {kind for module in removed for kind in MODULE_PORT_TYPES.get(module, ())}
    known_ports = {kind for kinds in MODULE_PORT_TYPES.values() for kind in kinds}
    try:
        facts.ports_text = query("/usr/sbin/semanage", "port", "-l", "-C")
        facts.fcontexts_text = query("/usr/sbin/semanage", "fcontext", "-l", "-C")
        modules = query("/usr/sbin/semodule", "-l")
    except (OSError, subprocess.SubprocessError) as error:
        problems.append(f"SELinux query failed: {error}")
        return
    facts.loaded = {line.split()[0] for line in modules.splitlines() if line.split()}
    # W634 (H-11): refuse unknown loaded rustiron_* SELinux modules that are not
    # tracked in the install record so uninstall never leaves untracked policy loaded.
    recorded_modules = set(facts.record["modules"])
    unknown_modules = sorted(
        mod for mod in facts.loaded if mod.startswith("rustiron_") and mod not in recorded_modules
    )
    for mod in unknown_modules:
        problems.append(f"unknown loaded Rustiron SELinux module not in install record: {mod}")
    for kind, protocol, port in local_ports(facts.ports_text):
        if kind in removed_ports:
            facts.port_labels.append((kind, protocol, port))
        elif kind.startswith("rustiron_") and kind not in known_ports:
            problems.append(f"local port label {kind} {protocol} {port} names an unknown Rustiron type")
    for line in facts.fcontexts_text.splitlines():
        if "rustiron_" in line:
            problems.append(f"local file context rule names a Rustiron type: {line.strip()}")


def check_evidence(facts, options, problems):
    """The evidence paths, and an archive on the same file system."""
    target = facts.target
    evidence = []
    if facts.keep:
        evidence.extend(("etc/rustiron", CADDY_INCLUDE))
        if (target / STATE).is_dir():
            evidence.extend(f"{STATE}/{entry.name}" for entry in sorted((target / STATE).iterdir())
                            if entry.name not in KEPT_STATE_ENTRIES)
    else:
        evidence.extend(("etc/rustiron", STATE, INCLUDE, CADDY_INCLUDE, EJECTED, TLS, *facts.site_dropins))
    # D-059: the certbot account's state; with the kept parent, the include
    # still names the installed chains, so /etc/rustiron-tls stays.
    evidence.extend((ACME_STATE, COORDINATOR_STATE, *facts.enrollment))
    facts.evidence = [name for name in dict.fromkeys(evidence) if preflight.metadata(target / name) is not None]
    if options.destroy_evidence:
        return
    if preflight.metadata(facts.archive) is not None:
        problems.append(f"/{facts.archive.relative_to(target)} exists")
    info = preflight.metadata(target / ARCHIVE_ROOT)
    if info is not None and (not stat.S_ISDIR(info.st_mode) or info.st_uid != facts.owner
                             or stat.S_IMODE(info.st_mode) != 0o700):
        problems.append(f"/{ARCHIVE_ROOT} must be a root-owned folder with mode 0700")
    device = (target / "var/lib").stat().st_dev
    for name in facts.evidence:
        if (target / name).parent.stat().st_dev != device:
            problems.append(f"/{name} is on another file system than /{ARCHIVE_ROOT}")


def stay_notes(facts):
    """What stays on the host, and what the installation never made."""
    target, record = facts.target, facts.record
    notes = [f"ABSENT /{name}" for name, present in sorted(facts.present.items()) if not present]
    notes.extend(f"KEEP /{name} (serving)" for name in facts.kept_payload)
    notes.extend(f"KEEP module {module} (serving)"
                 for module in sorted(set(record["modules"]) - set(facts.removed_modules)))
    notes.extend(f"ABSENT module {module}" for module in facts.removed_modules if module not in facts.loaded)
    for root in (SITES, PROBES):
        if (target / root).is_dir():
            notes.extend(f"TENANT /{root}/{entry.name} stays in place"
                         for entry in sorted((target / root).iterdir()))
    if facts.keep:
        accounts = ", ".join(facts.accounts) or "no site"
        notes.append(f"KEEP /{installer.OLS_PARENT} (Rustiron parent), /{INCLUDE}, /{EJECTED}, /{TLS}, "
                     f"/{STATE}/ols-package, and the site PHP units of {accounts}")
        notes.append("NOTE lshttpd.service keeps running. Without the drop-ins it has the package "
                     "KillMode=none: a stop is graceful, and old OLS processes can serve for a short time")
    if facts.restored:
        which = "standalone" if facts.standalone_bytes else "package"
        notes.append(f"RESTORED /{installer.OLS_PARENT} holds the {which} parent already")
    if facts.standalone_bytes:
        notes.append(f"NOTE the standalone parent of /{installer.OLS_PARENT}, for review:")
        notes.extend(f"  | {line}" for line in facts.standalone_bytes.decode().splitlines())
        notes.append("NOTE the standalone sites lose the Rustiron isolation: OLS runs their PHP in "
                     "unconfined_service_t as the site account, with no per-site SELinux category, "
                     "PHP unit sandbox, network refusal, or cgroup limit (D-037)")
    return notes


def stop_actions(facts, query, act):
    """Stop OLS and the site units (package parent), then the management units."""
    if not facts.keep:
        ports = facts.ports

        def stop_ols(runner):
            runner("/usr/bin/systemctl", "stop", "lshttpd.service")
            installer.wait_closed(ports, LISTENER_CLOSE_SECONDS, LISTEN_TABLES)

        shown = ", ".join(map(str, ports)) or "none"
        act(f"STOP lshttpd.service, then wait until no listener uses port {shown}", stop_ols)
        for account in facts.accounts:
            units = (f"rustiron-site-php@{account}.socket", f"rustiron-site-sandbox-check@{account}.timer",
                     f"rustiron-site-php@{account}.service")
            act(f"STOP and DISABLE {' '.join(units)}",
                lambda runner, units=units: stop_and_disable(runner, query, units))
    try:
        relays = [line.split()[0] for line in query(*RELAY_INSTANCES).splitlines() if line.split()]
    except (OSError, subprocess.SubprocessError):
        relays = []
    management = [*management_units(facts.record, facts.present), *relays]
    if management:
        act(f"STOP and DISABLE {' '.join(management)}",
            lambda runner: stop_and_disable(runner, query, management))


def parent_actions(facts, act):
    """Lift the flag of the kept Rustiron parent, or restore the package parent."""
    name = installer.OLS_PARENT
    if facts.keep:
        act(f"UNPIN /{name} (Rustiron parent stays, immutable flag lifted)",
            lambda runner: runner("/usr/bin/chattr", "-i", f"/{name}"))
        return
    parent = facts.record["package_parent"]
    for site in facts.standalone:
        standalone_vhost_action(facts, site, parent, act)
    if facts.restored:
        act(f"RESTORECON -F /{name} (the label of a restore that a failed run left)",
            lambda runner: runner("/usr/sbin/restorecon", "-F", "-v", f"/{name}"))
        return
    if facts.standalone_bytes:
        standalone_parent_action(facts, parent, act)
        return
    path, content = facts.target / name, facts.package_bytes

    def restore(runner):
        runner("/usr/bin/chattr", "-i", f"/{name}")
        replace_file(path, content, parent["uid"], parent["gid"], parent["mode"])
        runner("/usr/sbin/restorecon", "-F", "-v", f"/{name}")
        check_parent_label(facts.target, parent["selinux_type"])
        if file_digest(path) != parent["sha256"]:
            raise ValueError(f"/{name} differs from the package parent after the restore")
        report_config_test(runner)

    act(f"RESTORE /{name} from /{installer.PACKAGE_PARENT_COPY} sha256={parent['sha256']} "
        f"owner {parent['uid']}:{parent['gid']} mode {parent['mode']:04o} type {parent['selinux_type']}, "
        "then report the OLS configuration test", restore)


def standalone_vhost_action(facts, site, parent, act):
    """D-037 (W387): copy one standalone vhost into the OLS vhost folder, with the package owner."""
    folder = facts.target / OLS_VHOSTS / site.account
    content = facts.vhosts[site.account]
    chain = facts.chains.get(site.account, ())

    def copy(runner):
        if preflight.metadata(folder) is None:
            folder.mkdir(mode=0o750)
        os.chown(folder, parent["uid"], parent["gid"])
        folder.chmod(0o750)
        target = folder / STANDALONE_FILE
        if preflight.metadata(target) is None:
            write_exclusive(target, content, parent["uid"], parent["gid"], parent["mode"])
        if installer.read_regular(target, VHOST_LIMIT) != content:
            raise ValueError(f"/{OLS_VHOSTS}/{site.account}/{STANDALONE_FILE} differs from the ejected vhost")
        # D-064 (W471): the chain and key; the key stays root-only.
        for name, data, mode in zip(("fullchain.pem", "key.pem"), chain, (0o644, 0o600)):
            path = folder / name
            if preflight.metadata(path) is None:
                write_exclusive(path, data, facts.owner, facts.owner, mode)
            if installer.read_regular(path, TLS_LIMIT) != data:
                raise ValueError(f"/{OLS_VHOSTS}/{site.account}/{name} differs from the installed chain")
        runner("/usr/sbin/restorecon", "-R", "-F", "-v", f"/{OLS_VHOSTS}/{site.account}")

    handed = (f", and /{TLS}/{site.account}/live/fullchain.pem and key.pem (mode 0600) beside it; "
              "the operator renews them from now on (D-064)") if chain else ""
    act(f"COPY /{EJECTED}/{site.account}/vhost.conf -> /{OLS_VHOSTS}/{site.account}/{STANDALONE_FILE} "
        f"sha256={hashlib.sha256(content).hexdigest()} owner {parent['uid']}:{parent['gid']} "
        f"mode {parent['mode']:04o}{handed}", copy)


def standalone_parent_action(facts, parent, act):
    """D-037 (W387): write the standalone parent with the owner, mode, and label of the package parent."""
    name, content = installer.OLS_PARENT, facts.standalone_bytes
    digest = hashlib.sha256(content).hexdigest()

    def write(runner):
        runner("/usr/bin/chattr", "-i", f"/{name}")
        replace_file(facts.target / name, content, parent["uid"], parent["gid"], parent["mode"])
        runner("/usr/sbin/restorecon", "-F", "-v", f"/{name}")
        check_parent_label(facts.target, parent["selinux_type"])
        if file_digest(facts.target / name) != digest:
            raise ValueError(f"/{name} differs from the standalone parent after the write")
        report_config_test(runner, "the standalone parent")

    act(f"WRITE /{name} (standalone parent sha256={digest}, owner {parent['uid']}:{parent['gid']} "
        f"mode {parent['mode']:04o} type {parent['selinux_type']}), then report the OLS configuration "
        "test", write)


def serve_actions(facts, act):
    """D-037 (W387): start OLS with the standalone parent and probe each standalone site."""
    if facts.keep or not facts.standalone:
        return
    name, address = facts.listener
    accounts = " ".join(site.account for site in facts.standalone)

    def serve(runner):
        runner("/usr/bin/systemctl", "start", "lshttpd.service")
        for site in facts.standalone:
            if site.static or site.tls:
                # Use the marker on HTTP before checking the same site and
                # handed-over leaf on HTTPS. An HTTP-only site needs its marker.
                for hostname in site.hostname.split(","):
                    probe_site(address, hostname, site.account, static=True, https_redirect=site.tls)
                if site.tls:
                    leaf = static_chain_leaf(facts.chains[site.account][0])
                    for hostname in site.tls_hostname.split(","):
                        probe_site(facts.tls_listener[1], hostname, site.account, static=site.static, leaf=leaf)
            else:
                probe_site(address, site.hostname, site.account)

    act(f"START lshttpd.service, then probe {accounts} through listener {name} on {address}", serve)


def evidence_actions(facts, options, act):
    """Move each evidence path to the archive, or delete it with --destroy-evidence."""
    target, archive, owner = facts.target, facts.archive, facts.owner
    shown = f"/{archive.relative_to(target)}"
    if facts.keep and not options.destroy_evidence:
        act(f"COPY /{RECORD} -> {shown}/{RECORD}",
            lambda runner: shutil.copy2(target / RECORD,
                                        private_folders(archive, STATE, owner) / Path(RECORD).name))
    # W392 (D-042): the receipt private key never moves into the archive, so
    # no one signs a receipt for this installation after it is removed. The
    # public key stays in the archive and in the operator's off-host record.
    receipt_key = f"{installer.RECEIPT_KEY_DIR}/ed25519"
    if (not options.destroy_evidence and "etc/rustiron" in facts.evidence
            and preflight.metadata(target / receipt_key) is not None):
        act(f"DELETE /{receipt_key} (the receipt private key; the archive keeps the public key)",
            lambda runner: (target / receipt_key).unlink())
    # W510 (D-083): the alert push link is a credential of the owner's Kuma
    # monitor, not evidence. It never moves into the archive.
    if (not options.destroy_evidence and "etc/rustiron" in facts.evidence
            and preflight.metadata(target / ALERT_PUSH_LINK) is not None):
        act(f"DELETE /{ALERT_PUSH_LINK} (the alert push link; a credential, not evidence)",
            lambda runner: (target / ALERT_PUSH_LINK).unlink())
    for name in facts.evidence:
        if options.destroy_evidence:
            act(f"DELETE /{name} (--destroy-evidence)", lambda runner, name=name: delete(target / name))
        else:
            act(f"ARCHIVE /{name} -> {shown}/{name}",
                lambda runner, name=name: move_into(archive, target, name, owner))


def removal_actions(facts, act):
    """Remove the recorded files and the folders that the installation made."""
    target, record, owner = facts.target, facts.record, facts.owner
    for name, entry in sorted(record["payload"].items()):
        if facts.present[name] and name not in facts.kept_payload:
            act(f"REMOVE /{name} sha256={entry['sha256']}",
                lambda runner, name=name, entry=entry: remove_payload(target, name, entry, owner))
    needed = {str(parent) for name in facts.kept_payload for parent in Path(name).parents}
    for directory in sorted(record["created_directories"], key=lambda name: (-name.count("/"), name)):
        if directory not in needed and (target / directory).is_dir():
            act(f"RMDIR /{directory}", lambda runner, directory=directory: (target / directory).rmdir())
    for root in [PROBES] + ([] if facts.keep else [SITES]):
        path = target / root
        if root in record["state_directories"] and path.is_dir() and not any(path.iterdir()):
            act(f"RMDIR /{root} (empty)", lambda runner, path=path: path.rmdir())
    if not facts.keep:
        act(f"CLEAN /{SITE_SOCKETS} (the sockets of the stopped site units) and /{SANDBOX_LOCK}",
            lambda runner: clean_runtime(target))


def selinux_actions(facts, options, act):
    """Port labels, then modules, then the labels that the modules gave."""
    for kind, protocol, port in facts.port_labels:
        act(f"SEMANAGE delete port {kind} {protocol} {port}",
            lambda runner, arguments=("-t", kind, "-p", protocol, port):
                runner("/usr/sbin/semanage", "port", "-d", *arguments))
    modules = [module for module in facts.removed_modules if module in facts.loaded]
    if modules:
        act(f"SEMODULE remove {' '.join(modules)}", lambda runner: runner("/usr/sbin/semodule", "-r", *modules))
    if not facts.keep:
        for name in facts.record["relabelled"]:
            act(f"RESTORECON /{name}", lambda runner, name=name: runner("/usr/sbin/restorecon", "-v", f"/{name}"))
        if facts.record["sites_mount_kept"]:
            act(f"RESTORECON /{SITES} (the folder only)",
                lambda runner: runner("/usr/sbin/restorecon", "-v", f"/{SITES}"))
    if not options.destroy_evidence:
        shown = f"/{facts.archive.relative_to(facts.target)}"
        act(f"RESTORECON -R {shown}", lambda runner: runner("/usr/sbin/restorecon", "-R", shown))


def account_actions(facts, query, act):
    """Remove the identities that the sysusers file made."""
    for user in facts.record["users"]:
        if existing(query, "passwd", user):
            act(f"USERDEL {user}", lambda runner, user=user: runner("/usr/sbin/userdel", user))
    for group in facts.record["groups"]:
        if existing(query, "group", group):
            # userdel can remove the user's own group first.
            act(f"GROUPDEL {group}",
                lambda runner, group=group: (runner("/usr/sbin/groupdel", group)
                                             if existing(query, "group", group) else None))


def build_plan(target, options, query, owner=0, stamp=None):
    """Check the host and list each action; change nothing. Refuse with every reason."""
    if options.ols_parent not in ("keep", "package"):
        raise Refused(["choose the OLS parent: --ols-parent keep or --ols-parent package"])
    record = load_record(target, owner)
    stamp = stamp or time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    facts = Facts(target, record, options.ols_parent == "keep",
                  target / ARCHIVE_ROOT / f"uninstall-{stamp}", owner)
    notes, problems = [], []
    check_installation(facts, problems)
    check_sites(facts, options, notes, problems)
    check_parent(facts, problems)
    check_journal(target, options, query, notes, problems)
    check_selinux(facts, query, problems)
    check_evidence(facts, options, problems)
    if problems:
        raise Refused(problems)
    notes.extend(stay_notes(facts))

    actions = []

    def act(text, function):
        actions.append((text, function))

    archive = facts.archive
    if not options.destroy_evidence:
        if preflight.metadata(target / ARCHIVE_ROOT) is None:
            act(f"MKDIR /{ARCHIVE_ROOT} mode 0700", lambda runner: create_private(target / ARCHIVE_ROOT, owner))
        act(f"MKDIR /{archive.relative_to(target)} mode 0700", lambda runner: create_private(archive, owner))
    stop_actions(facts, query, act)
    if not options.destroy_evidence:
        for name, text in (("selinux-local-ports.txt", facts.ports_text),
                           ("selinux-local-fcontexts.txt", facts.fcontexts_text)):
            act(f"SAVE {name} (local SELinux labels before the removal)",
                lambda runner, name=name, text=text:
                    write_exclusive(archive / name, text.encode(), owner, owner, 0o400))
    parent_actions(facts, act)
    evidence_actions(facts, options, act)
    removal_actions(facts, act)
    selinux_actions(facts, options, act)
    account_actions(facts, query, act)
    # D-059: the installer masked the certbot package's timer. W471-F2: the
    # unmask returns it to the package state (its preset enables it; it starts
    # at the next boot). It renews only lineages in /etc/letsencrypt, which
    # Rustiron never wrote.
    act(f"UNMASK {CERTBOT_TIMER} (back to the package state; not started now)",
        lambda runner: runner("/usr/bin/systemctl", "unmask", CERTBOT_TIMER))
    act("DAEMON-RELOAD", lambda runner: runner("/usr/bin/systemctl", "daemon-reload"))
    act("CHECK lshttpd.service is the package unit with no drop-in", lambda runner: check_unit(query))
    serve_actions(facts, act)
    if facts.keep:
        reduced = reduced_record(target, record, facts.kept_payload)
        act(f"RECORD /{RECORD} (what stays: {len(facts.kept_payload)} files, "
            f"modules {' '.join(SERVING_MODULES)})",
            lambda runner: replace_file(target / RECORD, reduced, owner, owner, 0o400))
    if not options.destroy_evidence:
        act(f"MANIFEST /{archive.relative_to(target)}/MANIFEST and METADATA",
            lambda runner: write_manifest(archive, owner))
    return Plan(notes, actions, [site.account for site in facts.standalone])


def reduced_record(target, record, kept_payload):
    """The record of the serving set that --ols-parent keep leaves."""
    needed = {str(parent) for name in kept_payload for parent in Path(name).parents}
    reduced = dict(record)
    reduced["payload"] = {name: record["payload"][name] for name in kept_payload}
    reduced["created_directories"] = sorted(name for name in record["created_directories"] if name in needed)
    reduced["state_directories"] = sorted(
        name for name in record["state_directories"]
        if name in SERVING_STATE or (name == PROBES and (target / PROBES).is_dir())
    )
    reduced["modules"] = sorted(SERVING_MODULES)
    reduced["users"] = []
    reduced["groups"] = []
    reduced["serving_kept"] = True
    return (json.dumps(reduced, indent=1, sort_keys=True) + "\n").encode()


def check_unit(query):
    mismatches = list(preflight.ols_unit_mismatches(
        preflight.OLS_UNIT_FRESH,
        lambda: query("/usr/bin/systemctl", "show", *(f"--property={name}" for name in preflight.OLS_UNIT_FRESH),
                      preflight.OLS_UNIT),
    ))
    if mismatches:
        raise ValueError("; ".join(mismatches))


def show(plan, report=print):
    for line in plan.notes:
        report(line)
    for text, _function in plan.actions:
        report(text)


def execute(plan, runner, report=print):
    """Run each action in order and stop at the first failure; nothing rolls back."""
    for line in plan.notes:
        report(line)
    for text, function in plan.actions:
        report(text)
        function(runner)


def query(*arguments):
    return subprocess.run(
        arguments, check=True, text=True, capture_output=True, timeout=120,
        stdin=subprocess.DEVNULL, env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"},
    ).stdout


def parse_arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ols-parent", choices=("keep", "package"), required=True,
                        help="keep the Rustiron parent and the serving set, or restore the package parent")
    parser.add_argument("--leave-managed-sites", action="store_true",
                        help="with keep: leave sites that are not ejected served by the Rustiron-rendered include")
    parser.add_argument("--unserve-sites", action="store_true",
                        help="with package: accept that no site of the Rustiron include is served")
    parser.add_argument("--destroy-evidence", action="store_true",
                        help="delete the evidence instead of moving it to the archive")
    parser.add_argument("--accept-unresolved", action="store_true",
                        help="archive the journal with unresolved operations")
    parser.add_argument("--apply", action="store_true", help="act; without it, print the plan only")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_arguments(argv)
    if (os.getuid(), os.geteuid(), os.getegid()) != (0, 0, 0):
        print("REFUSED root:root is required", file=sys.stderr)
        return 2
    os.umask(0o077)
    options = Options(args.ols_parent, args.leave_managed_sites, args.unserve_sites,
                      args.destroy_evidence, args.accept_unresolved)
    try:
        plan = build_plan(Path("/"), options, query)
    except Refused as refused:
        for reason in refused.reasons:
            print(f"REFUSED {reason}", file=sys.stderr)
        return 1
    if not args.apply:
        print("DRY RUN: each action below is planned; nothing changes", flush=True)
        show(plan, lambda line: print(line, flush=True))
        print("DRY RUN: no change. Repeat the command with --apply to act", flush=True)
        return 0
    try:
        execute(plan, installer.run, lambda line: print(line, flush=True))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        # The actions printed above ran. Nothing is rolled back.
        print(f"FAILED incomplete uninstallation: {error}", file=sys.stderr)
        return 1
    if options.ols_parent == "keep":
        print("PASS management removed; the serving set stays", flush=True)
    elif plan.standalone:
        print(f"PASS uninstalled; lshttpd.service serves {', '.join(plan.standalone)} with the "
              "standalone parent", flush=True)
    else:
        print("PASS uninstalled; lshttpd.service stays stopped with the package parent", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
