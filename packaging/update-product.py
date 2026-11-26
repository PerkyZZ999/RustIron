#!/usr/bin/env python3
"""Update the Rustiron payload of an enrolled host from a verified offline root (D-049).

  update-product.py INSTALL_ROOT MANAGEMENT_ROOT HOST_JOB_ROOT JOB_PROFILE [--apply]
  update-product.py --rollback UPDATE_DIR [--apply]

The command reads /var/lib/rustiron/install-record.json. It verifies the new
assembled root exactly as install-product.py does, and refuses when the
payload file set, a file mode, or the shipped OLS parent template differs from
the record, when an installed payload file drifted from the record, or while
a capture, probe, or scheduled capture unit is active. Without --apply it
prints the plan and changes nothing.

With --apply it stops only the active management units, copies each changed
file and the old record to a new root-only folder below
/var/lib/rustiron/updates, writes each new file beside its target, checks its
digest, renames it into place, reloads changed policy packages, relabels the
changed paths, reloads systemd, writes the new record, and starts the units it
stopped. OLS, site PHP, and the store units keep running. The journal and the
admission mark are not touched.

--rollback restores the files and the record that one update folder holds,
with the same checks. A failure after the first replacement prints the folder
and is not reported as success.
"""

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
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
UPDATES = "var/lib/rustiron/updates"
UPDATE_MANIFEST = "update.json"
UPDATE_SCHEMA = "rustiron-update/1"
OLD_RECORD = "install-record.before.json"
FILES = "files"
TEMP_SUFFIX = ".rustiron-update"
# The units that run Rustiron management code and hold no website traffic.
# Stopped (when active) for the swap and started again afterwards.
STOP_UNITS = (
    "rustiron-alert-checkin.timer",
    "rustiron-site-cron.timer",
    "rustiron-scheduled-capture.timer",
    "rustiron-scheduled-capture-check.timer",
    "rustiron-coordinator.service",
    "rustiron-executor.service",
    "rustiron-admin-helper.service",
)
# Units whose activity means an operation is running.
BUSY_PATTERNS = (
    "rustiron-capture-*", "rustiron-probe-*",
    "rustiron-scheduled-capture.service", "rustiron-scheduled-capture-check.service",
    "rustiron-alert-checkin.service",
)
MODULE_PREFIX = installer.MODULE_DIR + "/"


class Refused(Exception):
    def __init__(self, problems):
        super().__init__("; ".join(problems))
        self.problems = list(problems)


def run(*arguments):
    installer.run(*arguments)


def query(*arguments):
    """Run a read-only command and return its stdout (exit status ignored)."""
    result = subprocess.run(
        arguments, check=False, stdin=subprocess.DEVNULL, capture_output=True, text=True,
        timeout=120, env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"},
    )
    return result.stdout


def file_digest(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def load_record(target, owner=0):
    """The install record, checked as the uninstaller checks it."""
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
    if not isinstance(record, dict) or record.get("schema") != installer.INSTALL_RECORD_SCHEMA:
        raise Refused(["unrecognized install record schema"])
    payload = record.get("payload")
    if not isinstance(payload, dict) or not all(
        isinstance(entry, dict) and isinstance(entry.get("sha256"), str) and isinstance(entry.get("mode"), int)
        for entry in payload.values()
    ):
        raise Refused(["install record has no valid payload"])
    return record, content


# D-072 (W486): the one added file whose standard folder the updater may
# create. Every other added file needs its folder to exist (D-062).
CREATABLE_FOLDERS = {preflight.JOURNALD_DROPIN: "etc/systemd/journald.conf.d"}


def creatable_folder(target, name):
    folder = CREATABLE_FOLDERS.get(name)
    return (folder is not None and preflight.metadata(target / folder) is None
            and preflight.metadata((target / folder).parent) is not None)


def compatibility(record, digests, target=None):
    """Refusals for a change that this command does not perform.

    D-062 (W467): a release may add and remove payload files. An added file's
    destination must not exist (anything there is unexplained) and its folder
    must exist; a shipped SELinux module may not be removed.
    """
    problems = []
    recorded = record["payload"]
    for name in sorted(digests.keys() - recorded.keys()):
        if target is None:
            continue
        if preflight.metadata(target / name) is not None:
            problems.append(f"/{name} exists but is not in the install record")
        elif preflight.metadata((target / name).parent) is None and not creatable_folder(target, name):
            problems.append(f"the folder of added /{name} does not exist")
    for name in sorted(recorded.keys() - digests.keys()):
        if name.startswith(MODULE_PREFIX):
            problems.append(f"the release removes the SELinux module /{name}; that needs its own procedure")
    for name in sorted(recorded.keys() & digests.keys()):
        if recorded[name]["mode"] != installer.PAYLOAD_MODES.get(name):
            problems.append(f"mode of /{name} differs from the install record")
    template = installer.PARENT_TEMPLATE
    if record.get("shipped_parent_sha256") != digests.get(template):
        problems.append("the shipped OLS parent template changes; the parent needs its own procedure")
    return problems


def drift(target, record, owner=0):
    """Installed payload files that are not exactly what the record states."""
    problems = []
    for name, entry in sorted(record["payload"].items()):
        path = target / name
        info = preflight.metadata(path)
        if info is None:
            problems.append(f"/{name} is missing")
        elif not stat.S_ISREG(info.st_mode):
            problems.append(f"/{name} is not a regular file")
        elif (info.st_uid, info.st_gid) != (owner, owner) or stat.S_IMODE(info.st_mode) != entry["mode"]:
            problems.append(f"/{name} has another owner or mode than the install record")
        elif file_digest(path) != entry["sha256"]:
            problems.append(f"/{name} differs from the install record")
    return problems


def changed(record, digests):
    return sorted(name for name, entry in record["payload"].items()
                  if name in digests and digests[name] != entry["sha256"])


def added(record, digests):
    """D-062: payload files the release ships that the record does not hold."""
    return sorted(digests.keys() - record["payload"].keys())


def removed(record, digests):
    """D-062: recorded payload files the release no longer ships."""
    return sorted(record["payload"].keys() - digests.keys())


def busy_units(lister=None):
    text = (lister or query)("/usr/bin/systemctl", "list-units", "--state=active,activating,deactivating",
                             "--plain", "--no-legend", *BUSY_PATTERNS)
    return [line.split()[0] for line in text.splitlines() if line.split()]


def active_units(checker=None):
    active = []
    for unit in STOP_UNITS:
        state = (checker or query)("/usr/bin/systemctl", "is-active", unit).strip()
        if state in ("active", "activating", "reloading"):
            active.append(unit)
    return active


def new_record(record, digests, update_dir, dropped=()):
    """The record after an update: new digests, added files, dropped files."""
    updated = json.loads(json.dumps(record))
    for name, digest in digests.items():
        if name in updated["payload"]:
            updated["payload"][name]["sha256"] = digest
        else:
            updated["payload"][name] = {"sha256": digest, "mode": installer.PAYLOAD_MODES[name]}
    for name in dropped:
        updated["payload"].pop(name, None)
    # W471: identities a new sysusers file creates join the record, so the
    # uninstaller removes them; none is ever dropped here.
    for key, names in (("users", installer.SYSUSERS_USERS), ("groups", installer.SYSUSERS_GROUPS)):
        if key in updated:
            updated[key] = list(dict.fromkeys([*updated[key], *names]))
    history = updated.setdefault("updates", [])
    history.append(update_dir)
    return (json.dumps(updated, indent=1, sort_keys=True) + "\n").encode()


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def replace(path, read_chunks, digest, mode, owner=0):
    """Write a new file beside path, check its digest, and rename it into place."""
    temporary = path.with_name(path.name + TEMP_SUFFIX)
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb+") as written:
            for chunk in read_chunks():
                written.write(chunk)
            written.flush()
            written.seek(0)
            if hashlib.file_digest(written, "sha256").hexdigest() != digest:
                raise ValueError(f"written bytes differ for {path}")
            os.fchown(written.fileno(), owner, owner)
            os.fchmod(written.fileno(), mode)
            os.fsync(written.fileno())
        os.rename(temporary, path)
    except BaseException:
        if preflight.metadata(temporary) is not None:
            os.unlink(temporary)
        raise
    fsync_directory(path.parent)


def chunks_of(path):
    def read():
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(descriptor, "rb") as source:
            while chunk := source.read(1 << 20):
                yield chunk
    return read


def make_update_dir(target, stamp, owner=0):
    parent = target / UPDATES
    if preflight.metadata(parent) is None:
        parent.mkdir(mode=0o700)
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700:
        raise Refused([f"/{UPDATES} must be a root-owned folder with mode 0700"])
    folder = parent / stamp
    folder.mkdir(mode=0o700)
    (folder / FILES).mkdir(mode=0o700)
    return folder


def keep_copies(target, folder, names, record_content, owner=0):
    """Copy each changed installed file and the old record into the update folder."""
    for name in names:
        copy = folder / FILES / name
        copy.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        installer.write_new(copy, b"".join(chunks_of(target / name)()), 0o400, owner)
    installer.write_new(folder / OLD_RECORD, record_content, 0o400, owner)


def apply_files(target, names, source_chunks, digests, owner=0, report=print, label="REPLACED"):
    for name in names:
        replace(target / name, source_chunks(name), digests[name], installer.PAYLOAD_MODES[name], owner)
        report(f"{label} /{name} sha256={digests[name]}")


def unload_removed_modules(dropped, runner=None):
    """W634 (H-11): unload dropped SELinux policy modules before removing their
    .pp files so rolling back an update that added a module never leaves
    orphaned privileged policy loaded."""
    removed_modules = [
        Path(name).stem
        for name in dropped
        if name.startswith(MODULE_PREFIX) and name.endswith(".pp")
    ]
    if removed_modules:
        (runner or run)("/usr/sbin/semodule", "-r", *removed_modules)


def finish_host(target, names, runner=None, read=None):
    """Load changed policy packages, relabel changed paths, create changed
    sysusers identities (D-062), reload systemd."""
    runner = runner or run
    modules = [f"/{name}" for name in names if name.startswith(MODULE_PREFIX)]
    if modules:
        runner("/usr/sbin/semodule", "-i", *modules)
    if names:
        runner("/usr/sbin/restorecon", "-v", *(f"/{name}" for name in names))
    if installer.SYSUSERS in names:
        runner("/usr/bin/systemd-sysusers", f"/{installer.SYSUSERS}")
        if target == Path("/") and not (target / installer.ACME_STATE).exists():
            installer.prepare_acme_state(target)
            runner("/usr/sbin/restorecon", "-R", "-v", f"/{installer.ACME_STATE}")
    runner("/usr/bin/systemctl", "daemon-reload")
    # W486: a changed journald drop-in takes effect when journald restarts.
    if preflight.JOURNALD_DROPIN in names:
        runner("/usr/bin/systemctl", "restart", "systemd-journald.service")
        # W486-F1: the flush moves the running journal to /var/log/journal.
        runner("/usr/bin/journalctl", "--flush")
    # W569 (W558-F1): a new or changed MariaDB drop-in takes effect when
    # MariaDB restarts (sites pause for its restart); then it may listen on
    # loopback only.
    if preflight.MARIADB_DROPIN in names:
        runner("/usr/bin/systemctl", "restart", "mariadb.service")
        preflight.check_mariadb_loopback(read=read)


def remove_files(target, names, report=print):
    """D-062: unlink payload files the release no longer ships (their kept
    copies are already in the update folder)."""
    for name in names:
        (target / name).unlink()
        fsync_directory((target / name).parent)
        report(f"REMOVED /{name}")


def write_record(target, content, owner=0):
    replace(target / RECORD, lambda: iter((content,)), hashlib.sha256(content).hexdigest(), 0o400, owner)


# W457-F1: a Type=simple unit is `active` as soon as it is started, even when
# its process exits at once (an executor refusing an older journal). Each
# unit must stay active through every check of the settle window.
SETTLE_CHECKS = 6
SETTLE_INTERVAL = 0.5


def start_units(units, runner=None, checker=None, sleep=time.sleep):
    runner = runner or run
    checker = checker or query
    for unit in reversed(units):
        runner("/usr/bin/systemctl", "start", unit)
    for check in range(SETTLE_CHECKS):
        if check:
            sleep(SETTLE_INTERVAL)
        for unit in units:
            state = checker("/usr/bin/systemctl", "is-active", unit).strip()
            if state != "active":
                raise ValueError(f"{unit} is {state or 'unknown'} after the update")
    for unit in units:
        print(f"ACTIVE {unit}", flush=True)


def stop_units(units, runner=None):
    for unit in units:
        (runner or run)("/usr/bin/systemctl", "stop", unit)


def utc_stamp():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def plan_update(args, target=Path("/"), owner=0):
    release_signature = preflight.check_release_trust(
        args.management_root,
        getattr(args, "release_signers", None),
        getattr(args, "release_signer_id", None),
        getattr(args, "allow_unsigned_lab", False),
        owner=owner,
    )
    digests = {
        **preflight.check_stage(args.management_root, preflight.MANAGEMENT_FILES),
        **preflight.check_jobs(args.host_job_root, args.job_profile),
    }
    installer.verify_install_root(args.install_root, digests, owner=owner)
    record, content = load_record(target, owner=owner)
    problems = compatibility(record, digests, target) + drift(target, record, owner=owner)
    if target == Path("/"):
        # D-063: the new build's matrix must cover the installed stack.
        problems += preflight.support_problems(
            preflight.load_matrix(), preflight.installed_versions(), time.time())
    if problems:
        raise Refused(problems)
    return (
        record, content, digests, changed(record, digests), added(record, digests),
        removed(record, digests), release_signature,
    )


def plan_rollback(folder, target=Path("/"), owner=0):
    folder = folder.resolve()
    if folder.parent != (target / UPDATES).resolve():
        raise Refused([f"{folder} is not an update folder below /{UPDATES}"])
    manifest = json.loads(installer.read_regular(folder / UPDATE_MANIFEST, RECORD_LIMIT))
    if manifest.get("schema") != UPDATE_SCHEMA or manifest.get("state") != "complete":
        raise Refused([f"{folder} does not hold a complete update"])
    old_content = installer.read_regular(folder / OLD_RECORD, RECORD_LIMIT)
    old_record = json.loads(old_content)
    record, content = load_record(target, owner)
    if hashlib.sha256(content).hexdigest() != manifest["record_after_sha256"]:
        raise Refused(["the install record is not the one this update wrote"])
    problems = drift(target, record, owner)
    # D-062: a rollback restores the changed and the removed files from the
    # kept copies, and removes the files the update added.
    names = sorted(manifest["changed"])
    restored = sorted(manifest.get("removed", []))
    dropped = sorted(manifest.get("added", []))
    digests = {name: old_record["payload"][name]["sha256"] for name in [*names, *restored]}
    for name in [*names, *restored]:
        if file_digest(folder / FILES / name) != digests[name]:
            problems.append(f"kept copy of /{name} differs from the old record")
    for name in restored:
        if preflight.metadata(target / name) is not None:
            problems.append(f"/{name}, removed by the update, exists again")
    if problems:
        raise Refused(problems)
    return record, content, old_content, digests, names, restored, dropped, manifest.get("created_folders", [])


def manifest_bytes(manifest):
    return (json.dumps(manifest, indent=1, sort_keys=True) + "\n").encode()


def make_folders(target, created, owner=0, report=print):
    """D-072: create the missing standard folder of an added file, root 0755."""
    made = []
    for name in created:
        folder = CREATABLE_FOLDERS.get(name)
        if folder is not None and preflight.metadata(target / folder) is None:
            os.mkdir(target / folder, 0o755)
            os.chown(target / folder, owner, owner)
            os.chmod(target / folder, 0o755)
            fsync_directory((target / folder).parent)
            report(f"ADDED /{folder}/")
            made.append(folder)
    return made


def remove_folders(target, folders, report=print):
    """D-072: a rollback removes the folders its update created, when empty."""
    for folder in folders:
        try:
            os.rmdir(target / folder)
        except FileNotFoundError:
            continue
        except OSError:
            report(f"KEPT /{folder}/ (not empty)")
            continue
        fsync_directory((target / folder).parent)
        report(f"REMOVED /{folder}/")


def execute(target, names, record_content, final_record, source_chunks, digests, mode, owner=0,
            created=(), dropped=(), remove_empty=(), release_signature=None):
    """Stop, keep copies, replace, finish, record, start. Returns the update folder.

    D-062: `names` are replaced in place, `created` are new files, and
    `dropped` are removed after their copies are kept.
    """
    busy = busy_units()
    if busy:
        raise Refused([f"operation unit active: {unit}" for unit in busy])
    units = active_units()
    folder = make_update_dir(target, utc_stamp(), owner)
    manifest = {
        "schema": UPDATE_SCHEMA, "mode": mode, "changed": names, "stopped": units, "state": "started",
        "added": list(created), "removed": list(dropped),
        "record_before_sha256": hashlib.sha256(record_content).hexdigest(),
    }
    if release_signature is not None:
        manifest["release_signature"] = release_signature
    installer.write_new(folder / UPDATE_MANIFEST, manifest_bytes(manifest), 0o600, owner)
    print(f"UPDATE FOLDER {folder}", flush=True)
    keep_copies(target, folder, [*names, *dropped], record_content, owner)
    stop_units(units)
    busy = busy_units()
    if busy:
        start_units(units)
        raise Refused([f"operation unit active after the stop: {unit}" for unit in busy])
    try:
        apply_files(target, names, source_chunks, digests, owner)
        folders = make_folders(target, created, owner)
        manifest["created_folders"] = folders
        apply_files(target, created, source_chunks, digests, owner, label="ADDED")
        unload_removed_modules(dropped)
        remove_files(target, dropped)
        remove_folders(target, remove_empty)
        finish_host(target, [*folders, *names, *created])
        content = final_record(str(folder.relative_to(target)))
        if folders:
            # D-072: the uninstaller removes the folders this update created.
            updated = json.loads(content)
            updated["created_directories"] = sorted({*updated.get("created_directories", []), *folders})
            content = (json.dumps(updated, indent=1, sort_keys=True) + "\n").encode()
        write_record(target, content, owner)
        manifest.update(state="complete", record_after_sha256=hashlib.sha256(content).hexdigest())
        text = manifest_bytes(manifest)
        replace(folder / UPDATE_MANIFEST, lambda: iter((text,)), hashlib.sha256(text).hexdigest(), 0o400, owner)
        start_units(units)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"FAILED incomplete {mode}: {error}. The kept copies are in {folder}", file=sys.stderr)
        raise
    return folder


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("install_root", type=Path, nargs="?")
    parser.add_argument("management_root", type=Path, nargs="?")
    parser.add_argument("host_job_root", type=Path, nargs="?")
    parser.add_argument("job_profile", type=Path, nargs="?")
    parser.add_argument("--rollback", type=Path, metavar="UPDATE_DIR")
    parser.add_argument("--release-signers", type=Path, default=None,
                        help="OpenSSH allowed-signers file for rustiron-release-v1 verification")
    parser.add_argument("--release-signer-id", default=None,
                        help="Expected signer identity in --release-signers")
    parser.add_argument("--allow-unsigned-lab", action="store_true",
                        help="Explicitly allow unsigned management staging on disposable lab hosts")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    positional = (args.install_root, args.management_root, args.host_job_root, args.job_profile)
    if args.rollback is not None and (
        any(positional) or args.release_signers is not None
        or args.release_signer_id is not None or args.allow_unsigned_lab
    ):
        parser.error("--rollback takes no install root or release-signature options")
    if args.rollback is None and not all(positional):
        parser.error("the install root, management root, host job root, and job profile are required")
    if (os.getuid(), os.geteuid(), os.getegid()) != (0, 0, 0):
        parser.error("root:root is required to update")
    os.umask(0o077)
    target = Path("/")
    release_signature = None
    try:
        if args.rollback is None:
            record, content, digests, names, created, dropped, release_signature = plan_update(args)
            if release_signature["verified"]:
                print(
                    f"PASS release signature verified (namespace={release_signature['namespace']}, "
                    f"signer={release_signature['signer_id']})",
                    flush=True,
                )
            else:
                print("WARN unsigned lab update explicitly requested (--allow-unsigned-lab)", flush=True)
            root_fd = os.open(args.install_root, installer.assembler.DIRECTORY_FLAGS)

            def source_chunks(name):
                def read():
                    with installer.assembler.open_payload(root_fd, Path(name)) as source:
                        while chunk := source.read(1 << 20):
                            yield chunk
                return read

            def final_record(folder):
                return new_record(record, digests, folder, dropped)
            folders = []
            mode = "update"
        else:
            record, content, old_content, digests, names, created, dropped, folders = plan_rollback(args.rollback)
            kept = args.rollback.resolve() / FILES

            def source_chunks(name):
                return chunks_of(kept / name)

            def final_record(_folder):
                return old_content
            mode = "rollback"
        for name in names:
            before = record["payload"].get(name, {}).get("sha256", "absent")
            print(f"CHANGE /{name} {before} -> {digests[name]}", flush=True)
        for name in created:
            print(f"ADD /{name} {digests[name]}", flush=True)
        for name in dropped:
            print(f"REMOVE /{name}", flush=True)
        if not names and not created and not dropped:
            print("PASS nothing to change; the installed payload matches", flush=True)
            return 0
        busy = busy_units()
        if busy:
            raise Refused([f"operation unit active: {unit}" for unit in busy])
        count = len(names) + len(created) + len(dropped)
        print(f"PASS {mode} checks: {count} file(s); would stop {active_units() or 'no unit'}", flush=True)
        if not args.apply:
            print("PLAN ONLY: run again with --apply", flush=True)
            return 0
        folder = execute(target, names, content, final_record, source_chunks, digests, mode,
                         created=created, dropped=dropped, remove_empty=folders,
                         release_signature=release_signature)
    except Refused as refused:
        for problem in refused.problems:
            print(f"REFUSED {problem}", file=sys.stderr)
        return 1
    except (OSError, ValueError, subprocess.SubprocessError, installer.manifest.InvalidPackage) as error:
        print(f"FAILED {error}", file=sys.stderr)
        return 1
    print(f"PASS {mode} applied; kept copies in {folder}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
