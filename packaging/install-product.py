#!/usr/bin/env python3
"""Install a verified offline Rustiron root onto a fresh AlmaLinux host.

The command copies exactly the assembled payload and state directories,
creates the coordinator identity, loads the policy packages, and reloads
systemd. It keeps a root-only copy of the package's OLS parent, writes the
shipped parent once as root:root 0644 with the immutable flag, and prints its
SHA-256 for enrollment. The shipped parent defines no listener, and OLS 1.9.4
does not start without one (W348), so the command stops OLS until the first
Rustiron generation renders a listener. It does not enable or start a unit
and does not enroll the host. Before the first payload file, it writes
/var/lib/rustiron/install-record.json for packaging/uninstall-product.py.
W392: it makes the host receipt key in /etc/rustiron/receipt-key with
ssh-keygen and prints the public key and its fingerprint (receipt_key.*
lines) for the operator to record off the host.
"""

import argparse
import base64
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
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


assembler = load_script("assemble_install_root", HERE / "assemble-install-root.py")
preflight = assembler.preflight
manifest = preflight.manifest

PAYLOAD_MODES = {**preflight.MANAGEMENT_FILES, **preflight.JOB_FILES}
STATE_DIRS = assembler.STATE_DIRS
SYSUSERS = "usr/lib/sysusers.d/rustiron-coordinator.conf"
OLS_PARENT = preflight.OLS_PARENT
PARENT_TEMPLATE = preflight.PARENT_TEMPLATE
PACKAGE_PARENT_COPY = "var/lib/rustiron/ols-package/httpd_config.conf"
# The type restorecon gives the parent; the lab parent has the same type (W338).
PARENT_TYPE = "usr_t"
# The package's WebAdmin and sample listener ports (W339). Neither may listen after the stop.
PACKAGE_PORTS = (7080, 8088)
CONFIG_TEST_ATTEMPTS = 3
PORT_CLOSE_SECONDS = 60
MODULE_DIR = "usr/share/rustiron/selinux"
# W385: the record of this installation, for packaging/uninstall-product.py.
INSTALL_RECORD = "var/lib/rustiron/install-record.json"
INSTALL_RECORD_SCHEMA = "rustiron-install-record/1"
# The identities that the sysusers file creates.
SYSUSERS_USERS = ("rustiron-coordinator", "rustiron-acme")
SYSUSERS_GROUPS = ("rustiron-coordinator", "rustiron-requesters", "rustiron-acme")
# W646: certbot runs as rustiron-acme with ReadWritePaths=/var/lib/rustiron-acme.
ACME_STATE = "var/lib/rustiron-acme"
ACME_SUBDIRS = ("config", "work", "logs")
LSPHP = "usr/local/lsws/lsphp84/bin/lsphp"
# Paths whose labels the loaded modules define; restorecon reads them again.
RELABEL = (
    "etc/rustiron", "etc/rustiron-ols", "etc/rustiron-ejected", "var/lib/rustiron",
    ACME_STATE,
    "srv/sites", "srv/restore-probes", "usr/bin/rustiron", "usr/libexec/rustiron",
    "usr/share/rustiron", "usr/share/doc/rustiron", "usr/share/licenses/rustiron",
    SYSUSERS, *(name for name in PAYLOAD_MODES if "/systemd/system/" in name),
    # W569: the MariaDB drop-in keeps mysqld_etc_t.
    preflight.MARIADB_DROPIN,
    # W358: the package's lsphp, which rustiron_php labels as the site PHP
    # entry point (rustiron_php_exec_t); it keeps bin_t without a relabel.
    LSPHP,
)


def payload_directories():
    directories = set()
    for name in (*PAYLOAD_MODES, *STATE_DIRS):
        directories.update(str(parent) for parent in Path(name).parents if str(parent) != ".")
    return directories - STATE_DIRS.keys()


def verify_install_root(root, digests, owner=0):
    """Accept only the assembled inventory, modes, ownership, and bytes."""
    directory = os.open(root, assembler.DIRECTORY_FLAGS)
    try:
        info = os.fstat(directory)
        if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (owner, owner, 0o700):
            raise ValueError("install root must be owner-only with mode 0700")
        content = manifest.canonical_manifest(directory).decode("utf-8")
    finally:
        os.close(directory)
    found = {name: digest for digest, name in (line.split("  ", 1) for line in content.splitlines())}
    if found != digests:
        missing = sorted(digests.keys() - found.keys())
        extra = sorted(found.keys() - digests.keys())
        changed = sorted(name for name in found.keys() & digests.keys() if found[name] != digests[name])
        raise ValueError(f"install root differs (missing={missing}, extra={extra}, changed={changed})")
    allowed = {**STATE_DIRS, **dict.fromkeys(payload_directories(), 0o755)}
    for path in root.rglob("*"):
        relative = str(path.relative_to(root))
        info = path.lstat()
        if (info.st_uid, info.st_gid) != (owner, owner):
            raise ValueError(f"unexpected ownership for {relative}")
        if stat.S_ISDIR(info.st_mode):
            if stat.S_IMODE(info.st_mode) != allowed.get(relative):
                raise ValueError(f"unexpected directory {relative}")
        elif stat.S_IMODE(info.st_mode) != PAYLOAD_MODES[relative]:
            raise ValueError(f"unexpected mode for {relative}")


def package_parent_facts(target, owner=0):
    """Digest, owner, mode, and SELinux type of the package parent (W385).

    The uninstaller restores these values. The type is None when the file
    system has no SELinux label.
    """
    content = preflight.read_package_parent(target, owner)
    path = target / OLS_PARENT
    info = path.lstat()
    try:
        label = preflight.selinux_type(path)
    except OSError:
        label = None
    return {
        "sha256": hashlib.sha256(content).hexdigest(),
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
        "selinux_type": label,
    }


def install_record(target, digests, kept_sites_mount, package_parent, release_signature=None):
    """The record of what this installation creates (W385).

    The installer writes it before the first payload file, so the
    uninstaller also finds the paths of an incomplete installation.
    """
    created = sorted(name for name in payload_directories()
                     if preflight.metadata(target / name) is None)
    state = sorted(name for name in STATE_DIRS
                   if not (kept_sites_mount and name == preflight.SITES_ROOT))
    record = {
        "schema": INSTALL_RECORD_SCHEMA,
        "payload": {name: {"sha256": digests[name], "mode": PAYLOAD_MODES[name]}
                    for name in sorted(PAYLOAD_MODES)},
        "created_directories": created,
        "state_directories": state,
        "sites_mount_kept": kept_sites_mount,
        "package_parent": package_parent,
        "shipped_parent_sha256": digests[PARENT_TEMPLATE],
        "modules": sorted(preflight.MODULES),
        "users": list(SYSUSERS_USERS),
        "groups": list(SYSUSERS_GROUPS),
        "relabelled": [LSPHP],
        "serving_kept": False,
    }
    if release_signature is not None:
        record["release_signature"] = release_signature
    return (json.dumps(record, indent=1, sort_keys=True) + "\n").encode()


def install_payload(root, target, digests, report=print, owner=0, package_parent=None,
                    release_signature=None):
    """Create each state directory and payload file; refuse any existing path.

    The one exception is /srv/sites when it is an empty mount root with the
    preflight shape (W361): the installer keeps it and relabels it later.
    After the state directories, the installer writes the install record.
    """
    kept_sites_mount = preflight.metadata(target / preflight.SITES_ROOT) is not None
    record = install_record(target, digests, kept_sites_mount, package_parent,
                            release_signature=release_signature)
    for name, mode in sorted(STATE_DIRS.items()):
        destination = target / name
        if name == preflight.SITES_ROOT and kept_sites_mount:
            preflight.check_empty_sites_mount(target, owner)
            report(f"KEPT empty mount point /{name}")
            continue
        destination.mkdir(mode=0o700)
        destination.chmod(mode)
        report(f"INSTALLED /{name}")
    write_new(target / INSTALL_RECORD, record, 0o400, owner)
    report(f"INSTALLED /{INSTALL_RECORD}")
    root_fd = os.open(root, assembler.DIRECTORY_FLAGS)
    try:
        for name in sorted(PAYLOAD_MODES):
            relative = Path(name)
            for parent in reversed(relative.parents):
                if str(parent) != "." and not (target / parent).exists():
                    (target / parent).mkdir(mode=0o755)
                    report(f"INSTALLED /{parent}")
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
            descriptor = os.open(target / relative, flags, 0o600)
            with os.fdopen(descriptor, "wb+") as written:
                with assembler.open_payload(root_fd, relative) as original:
                    while chunk := original.read(1 << 20):
                        written.write(chunk)
                written.flush()
                written.seek(0)
                if hashlib.file_digest(written, "sha256").hexdigest() != digests[name]:
                    raise ValueError(f"installed bytes differ for {name}")
                os.fchmod(written.fileno(), PAYLOAD_MODES[name])
                os.fsync(written.fileno())
            report(f"INSTALLED /{name}")
    finally:
        os.close(root_fd)


def write_new(path, content, mode, owner=0):
    """Create path exclusively with content, owner, and mode, and flush it."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as written:
        written.write(content)
        written.flush()
        os.fchown(written.fileno(), owner, owner)
        os.fchmod(written.fileno(), mode)
        os.fsync(written.fileno())


def read_regular(path, limit=preflight.PARENT_MAX_BYTES):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError(f"not a regular file: {path}")
        content = source.read(limit + 1)
    if len(content) > limit:
        raise ValueError(f"file is too large: {path}")
    return content


def replace_parent(target, template_digest, owner=0, report=print):
    """Keep the package parent root-only, then put the shipped parent in its place.

    The copy and the staged parent are created exclusively. The package parent
    must not change between the copy and the rename. Returns the parent digest.
    """
    original = preflight.read_package_parent(target, owner)
    write_new(target / PACKAGE_PARENT_COPY, original, 0o400, owner)
    report(f"KEPT /{PACKAGE_PARENT_COPY} sha256={hashlib.sha256(original).hexdigest()}")
    template = read_regular(target / PARENT_TEMPLATE)
    if hashlib.sha256(template).hexdigest() != template_digest:
        raise ValueError(f"installed bytes differ for {PARENT_TEMPLATE}")
    parent = target / OLS_PARENT
    staged = parent.with_name(f"{parent.name}.rustiron-new")
    write_new(staged, template, 0o644, owner)
    try:
        if preflight.read_package_parent(target, owner) != original:
            raise ValueError(f"OLS parent /{OLS_PARENT} changed during installation")
        os.rename(staged, parent)
    except BaseException:
        staged.unlink(missing_ok=True)
        raise
    directory = os.open(parent.parent, assembler.DIRECTORY_FLAGS)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    report(f"INSTALLED /{OLS_PARENT}")
    return template_digest


def check_pinned_parent(path, digest, owner=0):
    """The parent holds the shipped bytes, root:root 0644, one link, immutable."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as parent:
        info = os.fstat(parent.fileno())
        shape = (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink)
        if not stat.S_ISREG(info.st_mode) or shape != (owner, owner, 0o644, 1):
            raise ValueError(f"unexpected owner, mode, or links for {path}")
        if not preflight.immutable(parent.fileno()):
            raise ValueError(f"{path} is not immutable")
        if hashlib.file_digest(parent, "sha256").hexdigest() != digest:
            raise ValueError(f"{path} differs from the shipped parent")


def listening(port, tables=("/proc/net/tcp", "/proc/net/tcp6")):
    """Whether a LISTEN socket uses port; an unreadable table counts as listening."""
    wanted = f"{port:04X}"
    for table in tables:
        try:
            lines = Path(table).read_text().splitlines()[1:]
        except OSError:
            return True
        for line in lines:
            fields = line.split()
            if fields[3] == "0A" and fields[1].rsplit(":", 1)[1] == wanted:
                return True
    return False


def config_test(attempts=CONFIG_TEST_ATTEMPTS, runner=None, pause=1.0):
    """Run the OLS configuration test until it passes once, printing each failure.

    W348: OLS 1.9.4 `openlitespeed -t` once failed with "Invalid User
    Name((null))" on a parent that passed before and after. An invalid parent
    fails every attempt.
    """
    runner = runner or run
    for attempt in range(1, attempts + 1):
        try:
            runner("/usr/local/lsws/bin/openlitespeed", "-t")
            return attempt
        except subprocess.CalledProcessError as error:
            print(f"WARN OLS configuration test attempt {attempt} failed: {error}", flush=True)
            if attempt == attempts:
                raise
            time.sleep(pause)
    raise ValueError("no OLS configuration test attempt")


def wait_closed(ports, timeout=PORT_CLOSE_SECONDS, tables=("/proc/net/tcp", "/proc/net/tcp6")):
    """Wait until no port listens; OLS stops its old processes gracefully."""
    deadline = time.monotonic() + timeout
    while any(listening(port, tables) for port in ports):
        if time.monotonic() > deadline:
            raise ValueError(f"a package listener port is still open: {ports}")
        time.sleep(0.5)


def seal_parent(digest):
    """Label, pin, and test the new parent, then stop the package server.

    The shipped parent has no listener. OLS 1.9.4 refuses to run without one
    ("No listener is available, stop server!"), so OLS stays stopped until
    the first Rustiron generation renders a listener.
    """
    path = f"/{OLS_PARENT}"
    run("/usr/sbin/restorecon", "-v", path)
    label = os.getxattr(path, "security.selinux", follow_symlinks=False)
    if label.rstrip(b"\0").decode().split(":")[2] != PARENT_TYPE:
        raise ValueError(f"unexpected SELinux label for {path}")
    run("/usr/bin/chattr", "+i", path)
    check_pinned_parent(path, digest)
    config_test()
    run("/usr/bin/systemctl", "stop", "lshttpd.service")
    wait_closed(PACKAGE_PORTS)
    print("PASS OLS parent pinned; lshttpd stopped until a Rustiron generation renders a listener",
          flush=True)
    print(f"ols.parent_sha256={digest}", flush=True)


def run(*arguments):
    print("RUN " + " ".join(arguments), flush=True)
    subprocess.run(
        arguments, check=True, stdin=subprocess.DEVNULL, timeout=600,
        env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"},
    )


# W364: the effective lshttpd unit after the drop-ins: the vendor fragment,
# only the Rustiron drop-ins, and KillMode=mixed (the C07 merged-unit check of
# W244 and W245, for the product). W381 (D-032): the second drop-in orders
# the OLS boot guard before lshttpd.
OLS_UNIT_INSTALLED = {
    **preflight.OLS_UNIT_FRESH,
    "DropInPaths": " ".join(f"/{name}" for name in preflight.OLS_UNIT_DROPINS),
    "KillMode": "mixed",
}


def check_ols_unit(show=None):
    mismatches = list(preflight.ols_unit_mismatches(OLS_UNIT_INSTALLED, show))
    if mismatches:
        raise ValueError("; ".join(mismatches))
    print(f"PASS OLS unit {preflight.OLS_UNIT} KillMode=mixed from /{preflight.OLS_UNIT_DROPIN}; "
          f"boot guard from /{preflight.OLS_GUARD_DROPIN}; no other drop-in", flush=True)


def prepare_acme_state(target=Path("/"), user="rustiron-acme", report=print, uid=None, gid=None):
    """Create /var/lib/rustiron-acme/{config,work,logs} owned by rustiron-acme 0700 (W646).

    Certbot runs confined as `rustiron-acme` with `ReadWritePaths=/var/lib/rustiron-acme`;
    without these directories created before `restorecon`, the first `certificate_issue`
    fails at systemd mount setup.
    """
    if uid is None:
        uid = pwd.getpwnam(user).pw_uid
    if gid is None:
        gid = grp.getgrnam(user).gr_gid
    base = target / ACME_STATE
    paths = [base, *(base / sub for sub in ACME_SUBDIRS)]
    for path in paths:
        if path.is_symlink():
            raise ValueError(f"refusing symlink at /{path.relative_to(target)}")
        path.mkdir(mode=0o700, exist_ok=True)
        fd = os.open(path, assembler.DIRECTORY_FLAGS)
        try:
            os.fchown(fd, uid, gid)
            os.fchmod(fd, 0o700)
        finally:
            os.close(fd)
        report(f"PREPARED /{path.relative_to(target)} mode=0700 owner={uid}:{gid}")


def reset_failed_optional(unit, runner=None):
    """Clear any residual failed state after masking an active timer (W646, systemd 257)."""
    if runner is not None:
        runner("/usr/bin/systemctl", "reset-failed", unit)
        return
    print(f"RUN /usr/bin/systemctl reset-failed {unit}", flush=True)
    subprocess.run(
        ("/usr/bin/systemctl", "reset-failed", unit),
        check=False,
        stdin=subprocess.DEVNULL,
        timeout=60,
        env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"},
    )


def configure_host():
    run("/usr/bin/systemd-sysusers", f"/{SYSUSERS}")
    prepare_acme_state()
    modules = sorted(f"/{MODULE_DIR}/{name}.pp" for name in preflight.MODULES)
    run("/usr/sbin/semodule", "-i", *modules)
    run("/usr/sbin/restorecon", "-R", "-v", *(f"/{name}" for name in RELABEL))
    # W464 (D-060): Rustiron's executor renews certificates under their
    # signed grants; the certbot package's own root timer must never run.
    run("/usr/bin/systemctl", "mask", "--now", "certbot-renew.timer")
    # W646: systemd 257 leaves a masked-while-active timer in `failed (resources)`
    # until explicitly reset.
    reset_failed_optional("certbot-renew.timer")
    run("/usr/bin/systemctl", "daemon-reload")
    # W486 (W484-F3): journald reads its new drop-in and keeps the journal
    # in /var/log/journal from now on.
    run("/usr/bin/systemctl", "restart", "systemd-journald.service")
    # W486-F1: a restart alone keeps the journal in /run; the flush creates
    # /var/log/journal and moves it there, as systemd-journal-flush does at boot.
    run("/usr/bin/journalctl", "--flush")
    # W569 (W558-F1): MariaDB reads its loopback drop-in; then it may listen
    # on loopback only.
    run("/usr/bin/systemctl", "restart", "mariadb.service")
    preflight.check_mariadb_loopback()
    check_ols_unit()


# W392 (D-040 item 6, D-042): the host receipt key. The executor's pinned
# ssh-keygen signs each exported receipt with it.
RECEIPT_KEY_DIR = "etc/rustiron/receipt-key"
RECEIPT_KEY_COMMENT = "rustiron-receipt"


def generate_receipt_key(target=Path("/"), runner=None, owner=0):
    """Make the host receipt key once, then print its public key and fingerprint.

    ssh-keygen writes the private key itself; it is never read, printed, or
    passed in argv here. The private key gets mode 0400 and the public key
    0444, both owned by root. The operator records the printed lines off the
    host. Returns the fingerprint.
    """
    folder = target / RECEIPT_KEY_DIR
    private, public = folder / "ed25519", folder / "ed25519.pub"
    for path in (private, public):
        if preflight.metadata(path) is not None:
            raise ValueError(f"receipt key /{path.relative_to(target)} exists")
    (runner or run)("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                    "-C", RECEIPT_KEY_COMMENT, "-f", str(private))
    for path, mode in ((private, 0o400), (public, 0o444)):
        os.chown(path, owner, owner, follow_symlinks=False)
        os.chmod(path, mode, follow_symlinks=False)
    words = read_regular(public, 1024).decode("ascii").split()
    if len(words) < 2 or words[0] != "ssh-ed25519":
        raise ValueError(f"unexpected receipt public key /{public.relative_to(target)}")
    digest = hashlib.sha256(base64.b64decode(words[1], validate=True)).digest()
    fingerprint = "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
    print(f"receipt_key.public={words[0]} {words[1]}", flush=True)
    print(f"receipt_key.fingerprint={fingerprint}", flush=True)
    return fingerprint


RECEIPT_KEY_TYPE = "rustiron_receipt_key_t"


def label_receipt_key(target=Path("/"), runner=None):
    """Give the key folder and both files the receipt key type, then check it."""
    folder = target / RECEIPT_KEY_DIR
    (runner or run)("/usr/sbin/restorecon", "-R", "-v", str(folder))
    for path in (folder, folder / "ed25519", folder / "ed25519.pub"):
        if preflight.selinux_type(path) != RECEIPT_KEY_TYPE:
            raise ValueError(f"unexpected SELinux label for /{path.relative_to(target)}")
    print(f"PASS receipt key /{RECEIPT_KEY_DIR}/ed25519 root:root 0400 {RECEIPT_KEY_TYPE}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("install_root", type=Path)
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
    if (os.getuid(), os.geteuid(), os.getegid()) != (0, 0, 0):
        parser.error("root:root is required to install")
    os.umask(0o022)
    try:
        release_signature = preflight.check_release_trust(
            args.management_root, args.release_signers, args.release_signer_id,
            args.allow_unsigned_lab,
        )
        digests = {
            **preflight.check_stage(args.management_root, preflight.MANAGEMENT_FILES),
            **preflight.check_jobs(args.host_job_root, args.job_profile),
        }
        verify_install_root(args.install_root, digests)
        preflight.host_requirements()
        conflicts = [
            *preflight.destination_conflicts(Path("/")),
            *preflight.ols_parent_conflicts(Path("/")),
            *preflight.ols_unit_conflicts(),
            *preflight.existing_authority(),
        ]
    except (OSError, ValueError, subprocess.SubprocessError, manifest.InvalidPackage) as error:
        print(f"REFUSED {error}", file=sys.stderr)
        return 1
    if conflicts:
        for conflict in conflicts:
            print(f"REFUSED {conflict}", file=sys.stderr)
        return 1
    if release_signature["verified"]:
        print(
            f"PASS release signature verified (namespace={release_signature['namespace']}, "
            f"signer={release_signature['signer_id']})",
            flush=True,
        )
    else:
        print("WARN unsigned lab install explicitly requested (--allow-unsigned-lab)", flush=True)
    print("PASS install root and fresh-host checks", flush=True)

    def report(line):
        print(line, flush=True)

    try:
        parent = package_parent_facts(Path("/"))
        install_payload(
            args.install_root, Path("/"), digests, report,
            package_parent=parent, release_signature=release_signature,
        )
        configure_host()
        generate_receipt_key()
        label_receipt_key()
        seal_parent(replace_parent(Path("/"), digests[PARENT_TEMPLATE], report=report))
    except (OSError, ValueError, subprocess.SubprocessError, manifest.InvalidPackage) as error:
        # Paths printed above remain. Nothing is rolled back or reported as installed.
        print(f"FAILED incomplete installation: {error}", file=sys.stderr)
        return 1
    print("PASS installed; no unit was enabled or started")
    return 0


if __name__ == "__main__":
    sys.exit(main())
