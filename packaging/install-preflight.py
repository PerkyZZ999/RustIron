#!/usr/bin/env python3
"""Check staged inputs and a fresh AlmaLinux host without installing."""

import argparse
import fcntl
import grp
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import platform
import pwd
import stat
import subprocess
import sys
import tempfile
import time


HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True


def load_script(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


manifest = load_script("release_manifest", HERE.parent / "scripts/release/release_manifest.py")
jobs = load_script("stage_job_tools", HERE / "stage-job-tools.py")

EXECUTABLES = (
    "usr/bin/rustiron",
    "usr/libexec/rustiron/rustiron-control",
    "usr/libexec/rustiron/rustiron-mcp",
    "usr/libexec/rustiron/rustiron-executor",
    "usr/libexec/rustiron/rustiron-admin-helper",
    "usr/libexec/rustiron/check-site-sandbox",
    "usr/libexec/rustiron/store-netns",
    "usr/libexec/rustiron/alert-checkin",
    "usr/libexec/rustiron/mail-relay",
    "usr/libexec/rustiron/jobs/restore-inventory",
    "usr/libexec/rustiron/jobs/capture-manifest",
    "usr/libexec/rustiron/jobs/migration-inventory",
)
MANAGEMENT_UNITS = (
    "rustiron-admin-helper.service", "rustiron-coordinator.service", "rustiron-executor.service",
    "rustiron-ols-boot-guard.service",
    # W657 (D-102): confined Caddy edge ingress daemon (enabled only when enrolled).
    "rustiron-caddy.service",
    "rustiron-store-netns.service", "rustiron-store-relay@.socket", "rustiron-store-relay@.service",
    # D-071 (P07, CP06): per-site outbound mail Unix-socket relay.
    "rustiron-mail-relay@.socket", "rustiron-mail-relay@.service",
    # W386 (D-035): the scheduled capture and its missed-run check.
    "rustiron-scheduled-capture.service", "rustiron-scheduled-capture.timer",
    "rustiron-scheduled-capture-check.service", "rustiron-scheduled-capture-check.timer",
    # W466 (D-061): WordPress jobs through each site's own PHP.
    "rustiron-site-cron.service", "rustiron-site-cron.timer",
    # D-083 (P05): the alert check-in to the owner's Uptime Kuma.
    "rustiron-alert-checkin.service", "rustiron-alert-checkin.timer",
)
SITE_UNITS = (
    "rustiron-site-php@.service", "rustiron-site-php@.socket",
    "rustiron-site-sandbox-check@.service", "rustiron-site-sandbox-check@.timer",
    "rustiron-app@.service", "rustiron-app-b@.service",
    "rustiron-app-web@.service", "rustiron-app-web-b@.service",
    "rustiron-app-worker@.service",
)
MODULES = (
    "rustiron_admin", "rustiron_app", "rustiron_caddy", "rustiron_capture", "rustiron_coordinator",
    "rustiron_executor", "rustiron_job_credential", "rustiron_mail_relay",
    "rustiron_php", "rustiron_store_relay",
)
# W364: the drop-in that gives the package lshttpd unit KillMode=mixed (W245,
# D-022). The package unit has KillMode=none, so its workers outlived a stop
# (W243, W361). Before installation the unit must be the vendor fragment with
# no drop-in, so no other drop-in can set KillMode after the Rustiron one.
OLS_UNIT = "lshttpd.service"
OLS_UNIT_DROPIN = "etc/systemd/system/lshttpd.service.d/50-rustiron-killmode.conf"
# W381 (D-032): the drop-in that makes lshttpd want the OLS boot guard and
# start after it, so OLS never serves an unverified generation at boot.
OLS_GUARD_DROPIN = "etc/systemd/system/lshttpd.service.d/51-rustiron-boot-guard.conf"
# W486 (W484-F3): the system journal persists across boots and power cuts.
JOURNALD_DROPIN = "etc/systemd/journald.conf.d/50-rustiron-persistent.conf"
# W569 (W558-F1): MariaDB answers on loopback only.
MARIADB_DROPIN = "etc/my.cnf.d/zz-rustiron-loopback.cnf"
# W777: lets members of rustiron-agents start rustiron-mcp, and nothing else.
SUDOERS_DROPIN = "etc/sudoers.d/rustiron-mcp"
# W658 (D-102 Decision C2): PostgreSQL 18 loopback and strict pg_hba templates.
POSTGRES_LOOPBACK_TEMPLATE = "usr/share/rustiron/postgres/zz-rustiron-loopback.conf"
POSTGRES_HBA_TEMPLATE = "usr/share/rustiron/postgres/pg_hba.conf"
# W487 (D-073): the PHP health file that every managed vhost serves.
PHP_HEALTH = "usr/share/rustiron/ols/php-health.php"
# W610 (D-071): the inspected WordPress must-use plugin for Unix-socket mail relay.
MAIL_MU_PLUGIN = "usr/share/rustiron/rustiron-mail-relay.php"
OLS_UNIT_DROPINS = (OLS_UNIT_DROPIN, OLS_GUARD_DROPIN)
OLS_UNIT_FRESH = {
    "FragmentPath": "/usr/lib/systemd/system/lshttpd.service",
    "DropInPaths": "",
    "NeedDaemonReload": "no",
}
MANAGEMENT_FILES = {
    **dict.fromkeys(EXECUTABLES, 0o755),
    **dict.fromkeys((f"usr/lib/systemd/system/{name}" for name in MANAGEMENT_UNITS), 0o644),
    **dict.fromkeys((f"etc/systemd/system/{name}" for name in SITE_UNITS), 0o644),
    **dict.fromkeys((f"usr/share/rustiron/selinux/{name}.pp" for name in MODULES), 0o644),
    "usr/lib/sysusers.d/rustiron-coordinator.conf": 0o644,
    "usr/share/doc/rustiron/README.md": 0o644,
    "usr/share/licenses/rustiron/LICENSE": 0o644,
    "usr/share/rustiron/ols/httpd_config.conf": 0o644,
    PHP_HEALTH: 0o644,
    MAIL_MU_PLUGIN: 0o644,
    **dict.fromkeys(OLS_UNIT_DROPINS, 0o644),
    JOURNALD_DROPIN: 0o644,
    MARIADB_DROPIN: 0o644,
    SUDOERS_DROPIN: 0o440,
    POSTGRES_LOOPBACK_TEMPLATE: 0o644,
    POSTGRES_HBA_TEMPLATE: 0o644,
}
JOB_FILES = {f"usr/libexec/rustiron/jobs/{name}": 0o755 for name in jobs.TOOLS}
OWNED_ROOTS = (
    "etc/rustiron", "etc/rustiron-ols", "etc/rustiron-caddy", "etc/rustiron-ejected", "var/lib/rustiron",
    "var/lib/rustiron-coordinator", "run/rustiron", "run/rustiron-admin",
    "run/rustiron-coordinator", "run/rustiron-sites", "srv/sites", "srv/restore-probes",
    "usr/libexec/rustiron", "usr/share/rustiron", "usr/share/doc/rustiron",
    "usr/share/licenses/rustiron",
)
LAB_ROOTS = (
    "etc/rustiron-s02-lab", "var/lib/rustiron-s02-lab", "var/lib/rustiron-s04-lab",
    "usr/local/libexec/rustiron-s02-lab",
)
UNIT_ROOTS = (
    "etc/systemd/system", "etc/systemd/system.control", "run/systemd/system",
    "run/systemd/system.control", "usr/local/lib/systemd/system", "usr/lib/systemd/system",
)
SYSUSERS_ROOTS = (
    "etc/sysusers.d", "run/sysusers.d", "usr/local/lib/sysusers.d", "usr/lib/sysusers.d",
)
# W361: the sites file system may be mounted before installation. An existing
# /srv/sites is accepted only as the root of one file system, root:root 0755,
# empty, with the base policy type of /srv or the type the product gives it.
SITES_ROOT = "srv/sites"
SITES_MOUNT_TYPES = ("var_t", "httpd_sys_content_t")
MOUNTINFO = "/proc/self/mountinfo"
# W348: the OLS parent that the installer replaces with the shipped template.
OLS_PARENT = "usr/local/lsws/conf/httpd_config.conf"
PARENT_TEMPLATE = "usr/share/rustiron/ols/httpd_config.conf"
OLS_ACCOUNT = "lsadm"
OLS_INCLUDE_LINE = "include /etc/rustiron-ols/current/*.conf"
PARENT_MAX_BYTES = 256 * 1024
FS_IOC_GETFLAGS = 0x80086601
FS_IMMUTABLE_FL = 0x10
# W358: site PHP needs posix (lsphp84-process) and mysqli (lsphp84-mysqlnd)
# for provisioning verify.php; the product quota step runs the quota tools.
# W453 (D-054): the WordPress extensions whose dependencies come from the
# AlmaLinux, EPEL, and LiteSpeed repositories already in the profile.
REQUIRED_PACKAGES = (
    "openlitespeed", "lsphp84", "lsphp84-mysqlnd", "lsphp84-process", "mariadb-server", "quota",
    "lsphp84-xml", "lsphp84-gd", "lsphp84-opcache", "lsphp84-sodium", "lsphp84-bcmath",
    # D-059 (W464): certbot from EPEL runs as rustiron-acme for issuance.
    "certbot",
)
COMMANDS = (
    "/usr/bin/systemctl", "/usr/bin/systemd-run", "/usr/bin/systemd-sysusers",
    "/usr/bin/seinfo", "/usr/bin/ssh-keygen", "/usr/sbin/semanage",
    "/usr/sbin/restorecon", "/usr/bin/chattr", "/usr/local/lsws/lsphp84/bin/lsphp",
    "/usr/local/lsws/bin/openlitespeed",
    # W389 (D-038): the lshttpd start condition compares the parent.
    "/usr/bin/cmp",
)
# D-063 (P06): the reviewed support matrix, shared with `rustiron-control`.
SUPPORT_MATRIX = HERE.parent / "crates/control/support-matrix.json"
STACK_PACKAGES = {"openlitespeed": "openlitespeed", "php": "lsphp84", "mariadb": "mariadb-server",
                  "powerdns": "pdns", "caddy": "caddy", "postgresql": "postgresql18-server"}


def load_matrix(path=SUPPORT_MATRIX):
    matrix = json.loads(path.read_text())
    if matrix.get("schema") != "rustiron-support-matrix/1":
        raise ValueError("unrecognized support matrix")
    return matrix


def version_parts(text):
    parts = text.split(".")
    if not all(part.isdecimal() and part.isascii() for part in parts):
        return None
    return [int(part) for part in parts]


def support_problems(matrix, versions, now):
    """D-063: each installed version outside the reviewed matrix, as text."""
    problems = []
    if now - matrix["reviewed_unix"] > matrix["review_days"] * 86400:
        problems.append(f"support matrix reviewed {matrix['reviewed']} is past its review date")
    for component in matrix["components"]:
        label, series = component["label"], component["series"]
        version = versions.get(component["name"])
        end = component["end_of_life_unix"]
        if version is None and component.get("when_installed"):
            continue  # W562: PowerDNS is checked only where it is installed.
        if version is None:
            problems.append(f"{label}: installed version unreadable")
        elif version != series and not version.startswith(series + "."):
            problems.append(f"{label} {version} is not in the supported series {series}")
        elif (version_parts(version) or [-1]) < version_parts(component["minimum"]):
            problems.append(f"{label} {version} is older than the reviewed minimum {component['minimum']}")
        elif end is not None and now >= end:
            problems.append(f"{label} {series} reached its end of life {component['end_of_life']}")
    return problems


def installed_versions(release=None, rpm=None):
    release = release or platform.freedesktop_os_release()
    versions = {"os": release.get("VERSION_ID")} if release.get("ID") == "almalinux" else {}
    for name, package in STACK_PACKAGES.items():
        try:
            versions[name] = (rpm or query)("/usr/bin/rpm", "-q", "--qf", "%{VERSION}", package)
        except subprocess.SubprocessError:
            pass
    return versions


def exposed_mariadb(ss_output):
    """W569: the local addresses of TCP listeners on 3306 that are not
    loopback, from `ss -Htln 'sport = :3306'`."""
    exposed = []
    for line in ss_output.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        address = fields[3].rsplit(":", 1)[0].strip("[]").split("%", 1)[0]
        try:
            loopback = ipaddress.ip_address(address).is_loopback or (
                address.startswith("::ffff:") and ipaddress.ip_address(address[7:]).is_loopback)
        except ValueError:
            loopback = False
        if not loopback:
            exposed.append(fields[3])
    return exposed


def check_mariadb_loopback(read=None):
    """W569 (W558-F1): after MariaDB restarts with the drop-in, it listens on
    loopback only."""
    output = (read or query)("/usr/sbin/ss", "-Htln", "sport = :3306")
    exposed = exposed_mariadb(output)
    if exposed:
        raise ValueError(f"MariaDB listens beyond loopback on {', '.join(exposed)}")


def check_postgres_loopback(read=None):
    """W658 (D-102 C2): when PostgreSQL 18 is installed and listening, it must
    bind loopback only (never 0.0.0.0:5432 or [::]:5432)."""
    output = (read or query)("/usr/sbin/ss", "-Htln", "sport = :5432")
    exposed = exposed_mariadb(output)
    if exposed:
        raise ValueError(f"PostgreSQL 18 listens beyond loopback on {', '.join(exposed)}")


def check_support(now=None):
    problems = support_problems(load_matrix(), installed_versions(), time.time() if now is None else now)
    if problems:
        raise ValueError("; ".join(problems))


RELEASE_SIG_NAMESPACE = "rustiron-release-v1"
RELEASE_SIG_MAX_BYTES = 16 * 1024
ALLOWED_SIGNERS_MAX_BYTES = 64 * 1024


def read_trusted_file(path, limit, owner=0, label="file"):
    """Read a single-link regular file owned by owner and not group/world-writable."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError(f"{label} must be a single-link regular file")
        if info.st_uid != owner or (info.st_mode & 0o022):
            raise ValueError(f"{label} must be owned by uid {owner} and not group/world-writable")
        content = source.read(limit + 1)
    if not content or len(content) > limit:
        raise ValueError(f"{label} is empty or exceeds {limit} bytes")
    return content


def verify_release_signature(root, allowed_signers, signer_id, *, owner=0, verifier=None):
    """Verify the OpenSSH SSHSIG signature of root/SHA256SUMS in rustiron-release-v1 (H-09).

    Reads SHA256SUMS, SHA256SUMS.sig, and allowed_signers once without following
    symlinks or hardlinks, checks SHA256SUMS against the canonical directory
    manifest, and verifies the exact bytes with ssh-keygen -Y verify.
    """
    if (
        not isinstance(signer_id, str)
        or not (1 <= len(signer_id) <= 128)
        or not signer_id.isascii()
        or any(ord(ch) <= 32 or ord(ch) == 127 for ch in signer_id)
    ):
        raise ValueError("invalid release signer identity")
    allowed_bytes = read_trusted_file(
        allowed_signers, ALLOWED_SIGNERS_MAX_BYTES, owner=owner, label="release allowed-signers",
    )
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if stat.S_IMODE(os.fstat(directory).st_mode) != 0o700:
            raise ValueError("staging root must have mode 0700")
        content = manifest.canonical_manifest(directory)
        with manifest.regular_file(directory, "SHA256SUMS") as source:
            if source.read(len(content) + 1) != content:
                raise ValueError("staged bytes differ from SHA256SUMS")
        try:
            with manifest.regular_file(directory, "SHA256SUMS.sig") as sig_source:
                sig_bytes = sig_source.read(RELEASE_SIG_MAX_BYTES + 1)
        except FileNotFoundError:
            raise ValueError("missing release signature SHA256SUMS.sig") from None
    finally:
        os.close(directory)
    if not sig_bytes or len(sig_bytes) > RELEASE_SIG_MAX_BYTES:
        raise ValueError("release signature SHA256SUMS.sig is empty or too large")
    try:
        sig_text = sig_bytes.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("release signature SHA256SUMS.sig is not ASCII armored") from None
    if not sig_text.lstrip().startswith("-----BEGIN SSH SIGNATURE-----"):
        raise ValueError("release signature SHA256SUMS.sig is not an SSHSIG block")

    with tempfile.TemporaryDirectory(prefix="rustiron-relsig-") as scratch:
        scratch_dir = Path(scratch)
        scratch_dir.chmod(0o700)
        allowed_tmp = scratch_dir / "allowed_signers"
        sig_tmp = scratch_dir / "SHA256SUMS.sig"
        allowed_tmp.write_bytes(allowed_bytes)
        allowed_tmp.chmod(0o400)
        sig_tmp.write_bytes(sig_bytes)
        sig_tmp.chmod(0o400)
        cmd = (
            "/usr/bin/ssh-keygen", "-Y", "verify",
            "-f", str(allowed_tmp),
            "-I", signer_id,
            "-n", RELEASE_SIG_NAMESPACE,
            "-s", str(sig_tmp),
        )
        if verifier is not None:
            ok = verifier(cmd, content)
        else:
            result = subprocess.run(
                cmd, input=content, capture_output=True, timeout=30, check=False,
                env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"},
            )
            ok = result.returncode == 0
    if not ok:
        raise ValueError(
            f"release signature verification failed (namespace={RELEASE_SIG_NAMESPACE}, signer={signer_id})"
        )
    return {
        "verified": True,
        "namespace": RELEASE_SIG_NAMESPACE,
        "signer_id": signer_id,
        "sha256sums_sha256": hashlib.sha256(content).hexdigest(),
    }


def check_release_trust(root, release_signers, release_signer_id, allow_unsigned_lab,
                        *, owner=0, verifier=None):
    """Enforce release SSHSIG verification by default; require explicit opt-in for unsigned lab roots."""
    if allow_unsigned_lab:
        if release_signers is not None or release_signer_id is not None:
            raise ValueError("--allow-unsigned-lab cannot be combined with --release-signers or --release-signer-id")
        return {"verified": False, "mode": "unsigned_lab"}
    if release_signers is None or not release_signer_id:
        raise ValueError(
            "release signature verification is required: pass --release-signers PATH and "
            "--release-signer-id ID (or --allow-unsigned-lab for lab-only unsigned staging)"
        )
    return verify_release_signature(
        root, release_signers, release_signer_id, owner=owner, verifier=verifier,
    )


def check_stage(root, expected):
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if stat.S_IMODE(os.fstat(directory).st_mode) != 0o700:
            raise ValueError("staging root must have mode 0700")
        content = manifest.canonical_manifest(directory)
        with manifest.regular_file(directory, "SHA256SUMS") as source:
            if source.read(len(content) + 1) != content:
                raise ValueError("staged bytes differ from the manifest")
        entries = {}
        for line in content.decode("utf-8").splitlines():
            digest, name = line.split("  ", 1)
            entries[name] = digest
        if entries.keys() != expected.keys():
            missing = sorted(expected.keys() - entries.keys())
            extra = sorted(entries.keys() - expected.keys())
            raise ValueError(f"unexpected payload inventory (missing={missing}, extra={extra})")
        for name, mode in expected.items():
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if stat.S_IMODE(info.st_mode) != mode:
                raise ValueError(f"unexpected mode for {name}")
        return entries
    finally:
        os.close(directory)


def check_jobs(root, profile_path):
    staged = check_stage(root, JOB_FILES)
    profile = jobs.load_profile(profile_path)
    for name, pin in profile.items():
        if staged[f"usr/libexec/rustiron/jobs/{name}"] != pin["sha256"]:
            raise ValueError(f"staged bytes differ from the approved pin for {name}")
        with jobs.open_installed_tool(name, pin) as source:
            if hashlib.file_digest(source, "sha256").hexdigest() != pin["sha256"]:
                raise ValueError(f"installed bytes differ from the approved pin for {name}")
    return staged


def metadata(path):
    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def trusted_directory(root, relative, owner=0):
    for directory in (*reversed(relative.parents), relative):
        info = metadata(root / directory)
        if info is None:
            return False
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
            raise ValueError(f"untrusted destination parent /{directory}")
    return True


def read_mountinfo():
    return Path(MOUNTINFO).read_text()


def selinux_type(path):
    label = os.getxattr(path, "security.selinux", follow_symlinks=False)
    fields = label.rstrip(b"\0").decode("ascii", "replace").split(":")
    return fields[2] if len(fields) >= 4 else "unparsed"


def check_empty_sites_mount(root, owner=0):
    """Accept an existing /srv/sites only as an empty, unshared mount root.

    The mount table must hold exactly one mount at the path and none below it.
    That mount shows the root of its file system, on the device of the path.
    Any other existing path is refused as before.
    """
    path = root / SITES_ROOT
    info = path.lstat()
    mount_point = str(path)
    entries = [line.split() for line in read_mountinfo().splitlines()]
    below = [fields for fields in entries
             if len(fields) > 4 and (fields[4] == mount_point or fields[4].startswith(mount_point + "/"))]
    if not stat.S_ISDIR(info.st_mode) or not below:
        raise ValueError(f"existing path /{SITES_ROOT}")
    device = f"{os.major(info.st_dev)}:{os.minor(info.st_dev)}"
    if len(below) != 1 or below[0][4] != mount_point or below[0][3] != "/" or below[0][2] != device:
        raise ValueError(f"existing mount /{SITES_ROOT} is not the root of one file system")
    if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (owner, owner, 0o755):
        raise ValueError(f"existing mount /{SITES_ROOT} must be a 0755 directory owned by root")
    with os.scandir(path) as listing:
        if next(listing, None) is not None:
            raise ValueError(f"existing mount /{SITES_ROOT} is not empty")
    found = selinux_type(path)
    if found not in SITES_MOUNT_TYPES:
        raise ValueError(f"existing mount /{SITES_ROOT} has SELinux type {found}")


def check_destination(root, relative, owner=0):
    path = Path(relative)
    if trusted_directory(root, path.parent, owner) and metadata(root / path) is not None:
        if relative == SITES_ROOT:
            check_empty_sites_mount(root, owner)
            return
        raise ValueError(f"existing path /{relative}")


def destination_conflicts(root, owner=0):
    paths = (
        *OWNED_ROOTS, *LAB_ROOTS, "usr/bin/rustiron", SUDOERS_DROPIN,
        *(f"{directory}/rustiron-coordinator.conf" for directory in SYSUSERS_ROOTS),
    )
    for name in paths:
        try:
            check_destination(root, name, owner)
        except ValueError as error:
            yield str(error)
    for name in UNIT_ROOTS:
        try:
            if not trusted_directory(root, Path(name), owner):
                continue
            for entry in sorted((root / name).iterdir()):
                if entry.name.startswith("rustiron-"):
                    yield f"existing unit path /{entry.relative_to(root)}"
                elif entry.suffix in {".wants", ".requires", ".upholds"}:
                    relative = entry.relative_to(root)
                    if trusted_directory(root, relative, owner):
                        for link in sorted(entry.glob("rustiron-*")):
                            yield f"existing unit path /{link.relative_to(root)}"
        except ValueError as error:
            yield str(error)


def immutable(descriptor):
    """Whether the file has the immutable flag; unsupported filesystems have none."""
    flags = bytearray(8)
    try:
        fcntl.ioctl(descriptor, FS_IOC_GETFLAGS, flags)
    except OSError:
        return False
    return bool(int.from_bytes(flags[:4], sys.byteorder) & FS_IMMUTABLE_FL)


def conf_directory_owners(owner):
    """The OLS package owns conf/ as lsadm (W348); root may own it too."""
    try:
        return {owner, pwd.getpwnam(OLS_ACCOUNT).pw_uid}
    except KeyError:
        return {owner}


def read_package_parent(root, owner=0):
    """Read the package's OLS parent; refuse a link, an odd file, or a managed parent.

    The server root and its ancestors must be root-owned. The conf directory
    may belong to lsadm, but no one else, and group and other cannot write it.
    """
    path = Path(OLS_PARENT)
    missing = ValueError(f"missing OLS parent /{OLS_PARENT}")
    if not trusted_directory(root, path.parent.parent, owner):
        raise missing
    conf = metadata(root / path.parent)
    if conf is None:
        raise missing
    if (
        not stat.S_ISDIR(conf.st_mode)
        or conf.st_uid not in conf_directory_owners(owner)
        or conf.st_mode & 0o022
    ):
        raise ValueError(f"untrusted destination parent /{path.parent}")
    try:
        descriptor = os.open(root / path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        raise ValueError(f"missing OLS parent /{OLS_PARENT}") from None
    except OSError as error:
        raise ValueError(f"unreadable OLS parent /{OLS_PARENT}: {error.strerror}") from None
    with os.fdopen(descriptor, "rb") as parent:
        info = os.fstat(parent.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError(f"OLS parent /{OLS_PARENT} is not a single-link regular file")
        if immutable(parent.fileno()):
            raise ValueError(f"existing Rustiron-managed OLS parent /{OLS_PARENT} (immutable)")
        content = parent.read(PARENT_MAX_BYTES + 1)
    if len(content) > PARENT_MAX_BYTES:
        raise ValueError(f"OLS parent /{OLS_PARENT} is too large")
    lines = (" ".join(line.split()) for line in content.decode("utf-8", "replace").splitlines())
    if OLS_INCLUDE_LINE in lines:
        raise ValueError(f"existing Rustiron-managed OLS parent /{OLS_PARENT} (Rustiron include)")
    return content


def ols_parent_conflicts(root, owner=0):
    try:
        read_package_parent(root, owner)
    except ValueError as error:
        yield str(error)


def unit_properties(text, names):
    """Parse `systemctl show` lines; exactly the named properties, each once."""
    found = {}
    for line in text.splitlines():
        name, separator, value = line.partition("=")
        if not separator or name in found:
            raise ValueError("unrecognized systemctl show output")
        found[name] = value
    if set(found) != set(names):
        raise ValueError("unrecognized systemctl show output")
    return found


def ols_unit_mismatches(expected, show=None):
    """Compare the effective lshttpd unit properties with `expected`."""
    names = tuple(expected)
    show = show or (lambda: query(
        "/usr/bin/systemctl", "show", *(f"--property={name}" for name in names), OLS_UNIT,
    ))
    try:
        found = unit_properties(show(), names)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        yield f"OLS unit {OLS_UNIT}: {error}"
        return
    for name, value in expected.items():
        if found[name] != value:
            yield f"OLS unit {OLS_UNIT} {name}={found[name]}, expected {value!r}"


def ols_unit_conflicts(show=None):
    """The package unit before installation: the vendor fragment and no drop-in."""
    yield from ols_unit_mismatches(OLS_UNIT_FRESH, show)


def query(*arguments):
    return subprocess.run(
        arguments, check=True, text=True, capture_output=True, timeout=10,
        stdin=subprocess.DEVNULL, env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"},
    ).stdout.strip()


def host_requirements():
    release = platform.freedesktop_os_release()
    if release.get("ID") != "almalinux" or release.get("VERSION_ID", "").split(".")[0] != "10":
        raise ValueError("requires AlmaLinux 10")
    if platform.machine() != "x86_64":
        raise ValueError("requires x86_64")
    if Path("/proc/1/comm").read_text().strip() != "systemd":
        raise ValueError("requires systemd as PID 1")
    if query("/usr/sbin/getenforce") != "Enforcing":
        raise ValueError("requires enforcing SELinux")
    for name in COMMANDS:
        if not Path(name).is_file() or not os.access(name, os.X_OK):
            raise ValueError(f"required executable unavailable: {name}")
    query("/usr/bin/rpm", "-q", *REQUIRED_PACKAGES)
    check_support()


def existing_authority():
    for kind, lookup, name in (
        ("user", pwd.getpwnam, "rustiron-coordinator"),
        ("group", grp.getgrnam, "rustiron-coordinator"),
        ("group", grp.getgrnam, "rustiron-requesters"),
        ("user", pwd.getpwnam, "rustiron-acme"),
        ("group", grp.getgrnam, "rustiron-acme"),
        ("user", pwd.getpwnam, "rustiron-caddy"),
        ("group", grp.getgrnam, "rustiron-caddy"),
    ):
        try:
            lookup(name)
        except KeyError:
            continue
        yield f"existing {kind} {name}"
    listing = query("/usr/sbin/semodule", "-lfull")
    if not listing:
        raise ValueError("empty SELinux module list")
    for line in listing.splitlines():
        priority, name, *_ = line.split()
        if not priority.isdecimal():
            raise ValueError("unrecognized SELinux module list")
        if name.startswith("rustiron_"):
            yield f"existing SELinux module {name}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("management_root", type=Path)
    parser.add_argument("host_job_root", type=Path)
    parser.add_argument("job_profile", type=Path)
    parser.add_argument("--release-signers", type=Path, default=None,
                        help="OpenSSH allowed-signers file for rustiron-release-v1 verification")
    parser.add_argument("--release-signer-id", default=None,
                        help="Expected signer identity in --release-signers")
    parser.add_argument("--allow-unsigned-lab", action="store_true",
                        help="Explicitly allow unsigned management staging on disposable lab hosts")
    args = parser.parse_args()
    if os.getuid() != 0 or os.geteuid() != 0:
        parser.error("root inspection is required for host accounts and SELinux policy")
    failures = []
    checks = (
        ("release signature", lambda: check_release_trust(
            args.management_root, args.release_signers, args.release_signer_id, args.allow_unsigned_lab)),
        ("management artifacts", lambda: check_stage(args.management_root, MANAGEMENT_FILES)),
        ("host job artifacts", lambda: check_jobs(args.host_job_root, args.job_profile)),
        ("host prerequisites", host_requirements),
    )
    for label, check in checks:
        try:
            check()
            print(f"PASS {label}", flush=True)
        except (OSError, ValueError, subprocess.SubprocessError, manifest.InvalidPackage) as error:
            failures.append(f"{label}: {error}")
    try:
        failures.extend(destination_conflicts(Path("/")))
        failures.extend(ols_parent_conflicts(Path("/")))
        failures.extend(ols_unit_conflicts())
        failures.extend(existing_authority())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        failures.append(f"host conflicts: {error}")
    for failure in failures:
        print(f"REFUSED {failure}", file=sys.stderr)
    if failures:
        return 1
    print("PASS fresh-host preflight")
    return 0


if __name__ == "__main__":
    sys.exit(main())
