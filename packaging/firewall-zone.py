#!/usr/bin/env python3
"""Apply or remove the Rustiron firewalld zone (W559, D-095).

The zone comes only from the `firewall` section of the enrolled policy
(/etc/rustiron/policy.json) and from whether its `dns` section is
enrolled. It allows the SSH port, HTTP, HTTPS, DNS when enrolled, and
DHCPv6 replies when enrolled; the firewalld default target rejects the
rest. No argument opens a port.

  firewall-zone.py [--policy FILE]             print the zone and the plan
  firewall-zone.py [--policy FILE] --apply     write, reload, set default, verify
  firewall-zone.py --restore [--apply]         set `public` back, remove the zone
  firewall-zone.py [--policy FILE] --check     report drift from the enrolled zone

Before any change the tool checks that firewalld runs, that the current
default zone is `public` or `rustiron`, that no permanent binding holds a
public interface in another zone, and that sshd listens on the enrolled
SSH port, so the operator keeps access. After the change it checks that
every interface with a default route is in the zone and that the zone
allows exactly the enrolled set. When a step or that check fails, it sets
`public` as the default zone again, removes the file, and refuses.

`--check` (W568) changes nothing. It compares the zone file with the policy's
render and the running firewalld with the enrolled set: the default zone,
the zone of each interface with a default route, and exactly the allowed
services and ports, with nothing else allowed. Each difference prints as a
`drift:` line and the exit is 1; a match prints `verified:` and exits 0.

Run it as root. Exit 0 is success or a printed plan; exit 1 is a refusal or
drift; exit 2 is a usage error.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ZONE = "rustiron"
FALLBACK = "public"
POLICY = Path("/etc/rustiron/policy.json")
ZONE_FILE = Path("/etc/firewalld/zones/rustiron.xml")
MAX_POLICY_BYTES = 16 * 1024
RESERVED_PORTS = (53, 80, 443)
ENV = {"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"}


class Refused(RuntimeError):
    pass


def run(argv: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, stdin=subprocess.DEVNULL,
                          env=ENV, check=False, timeout=60)


def load_policy(path: Path) -> dict:
    with path.open("rb") as handle:
        data = handle.read(MAX_POLICY_BYTES + 1)
    if len(data) > MAX_POLICY_BYTES:
        raise Refused(f"{path} is larger than 16 KiB")
    try:
        return json.loads(data)
    except ValueError as error:
        raise Refused(f"{path} is not JSON: {error}") from error


def enrolled(policy: dict) -> tuple[int, bool, bool]:
    """Return (ssh_port, dns, dhcpv6_client) with FirewallPolicy's rules."""
    section = policy.get("firewall")
    if not isinstance(section, dict):
        raise Refused("the policy has no firewall section; enroll one with --firewall-ssh-port")
    if set(section) != {"ssh_port", "dhcpv6_client"}:
        raise Refused("the firewall section must hold exactly ssh_port and dhcpv6_client")
    port, dhcpv6 = section["ssh_port"], section["dhcpv6_client"]
    if type(port) is not int or not 1 <= port <= 65535 or port in RESERVED_PORTS:
        raise Refused("firewall.ssh_port must be a port other than 53, 80 and 443")
    if type(dhcpv6) is not bool:
        raise Refused("firewall.dhcpv6_client must be true or false")
    return port, "dns" in policy, dhcpv6


def services(dns: bool, dhcpv6: bool) -> list[str]:
    return ["http", "https"] + (["dns"] if dns else []) + (["dhcpv6-client"] if dhcpv6 else [])


def render(port: int, dns: bool, dhcpv6: bool) -> str:
    lines = ['<?xml version="1.0" encoding="utf-8"?>', "<zone>", "  <short>Rustiron</short>",
             "  <description>Rendered by packaging/firewall-zone.py from /etc/rustiron/policy.json "
             "(D-095). Do not edit.</description>"]
    lines += [f'  <service name="{name}"/>' for name in services(dns, dhcpv6)]
    lines += [f'  <port protocol="tcp" port="{port}"/>', "</zone>", ""]
    return "\n".join(lines)


def query(runner, *arguments: str) -> str:
    result = runner(["firewall-cmd", *arguments])
    if result.returncode != 0:
        raise Refused(f"firewall-cmd {' '.join(arguments)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def public_interfaces(runner) -> list[str]:
    names = set()
    for family in ("-4", "-6"):
        result = runner(["ip", "-j", family, "route", "show", "default"])
        if result.returncode != 0:
            raise Refused(f"ip {family} route failed: {result.stderr.strip()}")
        names.update(route["dev"] for route in json.loads(result.stdout or "[]") if "dev" in route)
    if not names:
        raise Refused("no interface holds a default route")
    return sorted(names)


def sshd_listens(runner, port: int) -> bool:
    result = runner(["ss", "-Htlnp"])
    if result.returncode != 0:
        raise Refused(f"ss failed: {result.stderr.strip()}")
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 6 and fields[3].rsplit(":", 1)[-1] == str(port) \
                and '(("sshd",' in line:
            return True
    return False


def preflight(runner, port: int, interfaces: list[str]) -> str:
    if query(runner, "--state") != "running":
        raise Refused("firewalld is not running")
    default = query(runner, "--get-default-zone")
    if default not in (FALLBACK, ZONE):
        raise Refused(f"the default zone is {default!r}, not {FALLBACK!r} or {ZONE!r}; "
                      "the tool does not take over a zone it did not set")
    for name in interfaces:
        bound = runner(["firewall-cmd", "--permanent", f"--get-zone-of-interface={name}"])
        if bound.returncode == 0 and bound.stdout.strip() not in ("", ZONE):
            raise Refused(f"{name} is bound to zone {bound.stdout.strip()!r} permanently")
    if not sshd_listens(runner, port):
        raise Refused(f"sshd does not listen on TCP port {port}; refusing so access is kept")
    return default


def mismatches(runner, port: int, dns: bool, dhcpv6: bool, interfaces: list[str]) -> list[str]:
    problems = []
    if query(runner, "--get-default-zone") != ZONE:
        problems.append(f"the default zone is not {ZONE}")
    for name in interfaces:
        zone = runner(["firewall-cmd", f"--get-zone-of-interface={name}"]).stdout.strip()
        if zone != ZONE:
            problems.append(f"{name} is in zone {zone or 'none'}")
    expected = {
        "--list-services": " ".join(sorted(services(dns, dhcpv6))),
        "--list-ports": f"{port}/tcp",
        "--list-protocols": "", "--list-source-ports": "", "--list-forward-ports": "",
        "--list-rich-rules": "", "--list-sources": "", "--list-icmp-blocks": "",
    }
    for option, want in expected.items():
        have = " ".join(sorted(query(runner, f"--zone={ZONE}", option).split()))
        if have != want:
            problems.append(f"{option} is {have!r}, expected {want!r}")
    masquerade = runner(["firewall-cmd", f"--zone={ZONE}", "--query-masquerade"])
    if masquerade.stdout.strip() != "no":
        problems.append("masquerade is on")
    return problems


def write_zone(path: Path, text: str) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(descriptor, "w") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def step(runner, *argv: str) -> None:
    result = runner(list(argv))
    if result.returncode != 0:
        raise Refused(f"{' '.join(argv)} failed: {result.stderr.strip()}")
    print(f"ran: {' '.join(argv)}")


def ensure_fallback_ssh_port(runner, port: int | None) -> None:
    """W634 (H-12): before falling back to `public`, ensure a nonstandard SSH
    port is permanently permitted there so reload/restore cannot lock out SSH."""
    if port is None or port == 22:
        return
    token = f"{port}/tcp"
    existing = query(runner, "--permanent", f"--zone={FALLBACK}", "--list-ports").split()
    if token not in existing:
        step(runner, "firewall-cmd", "--permanent", f"--zone={FALLBACK}", f"--add-port={token}")


def remove(runner, path: Path, default: str, port: int | None = None) -> None:
    if default == FALLBACK:
        ensure_fallback_ssh_port(runner, port)
    step(runner, "firewall-cmd", f"--set-default-zone={default}")
    path.unlink(missing_ok=True)
    step(runner, "firewall-cmd", "--reload")


def restore_previous_zone(runner, path: Path, previous_text: str) -> None:
    """Restore an existing working `rustiron` zone file when an update fails."""
    write_zone(path, previous_text)
    step(runner, "restorecon", str(path))
    step(runner, "firewall-cmd", "--reload")
    step(runner, "firewall-cmd", f"--set-default-zone={ZONE}")


def apply(runner, path: Path, text: str, port: int, dns: bool, dhcpv6: bool) -> None:
    interfaces = public_interfaces(runner)
    previous = preflight(runner, port, interfaces)
    current = path.read_text() if path.exists() else None
    if current == text and previous == ZONE and not mismatches(runner, port, dns, dhcpv6,
                                                               interfaces):
        print("unchanged: the zone is applied and matches the policy")
        return
    write_zone(path, text)
    print(f"wrote: {path}")
    step(runner, "restorecon", str(path))
    try:
        step(runner, "firewall-cmd", "--check-config")
        step(runner, "firewall-cmd", "--reload")
        step(runner, "firewall-cmd", f"--set-default-zone={ZONE}")
        problems = mismatches(runner, port, dns, dhcpv6, interfaces)
    except Refused:
        if previous == ZONE and current is not None:
            restore_previous_zone(runner, path, current)
        else:
            remove(runner, path, FALLBACK, port=port)
        raise
    if problems:
        if previous == ZONE and current is not None:
            restore_previous_zone(runner, path, current)
            raise Refused(
                f"verification failed, restored previous {ZONE} zone: " + "; ".join(problems)
            )
        remove(runner, path, FALLBACK, port=port)
        raise Refused(f"verification failed, the default zone is {FALLBACK} again: " + "; ".join(problems))
    print(f"verified: {', '.join(interfaces)} in zone {ZONE}; allowed "
          f"{' '.join(services(dns, dhcpv6))} and {port}/tcp")


def drift(runner, path: Path, text: str, port: int, dns: bool, dhcpv6: bool) -> list[str]:
    """W568: every difference between the host and the enrolled zone."""
    if query(runner, "--state") != "running":
        return ["firewalld is not running"]
    problems = []
    if not path.exists():
        problems.append(f"{path} is missing")
    elif path.read_text() != text:
        problems.append(f"{path} differs from the zone the policy renders")
    # W568-F1: firewalld refuses every query of a zone it has not loaded.
    if ZONE not in query(runner, "--get-zones").split():
        default = query(runner, "--get-default-zone")
        return problems + [f"firewalld has no {ZONE} zone loaded", f"the default zone is {default}"]
    return problems + mismatches(runner, port, dns, dhcpv6, public_interfaces(runner))


def restore(runner, path: Path, apply_change: bool, port: int | None = None) -> None:
    if query(runner, "--state") != "running":
        raise Refused("firewalld is not running")
    default = query(runner, "--get-default-zone")
    if default != ZONE and not path.exists():
        print(f"unchanged: the default zone is {default} and no Rustiron zone file exists")
        return
    if default not in (ZONE, FALLBACK):
        raise Refused(f"the default zone is {default!r}; set it by hand before removing the file")
    if not apply_change:
        extra = f" (ensuring {port}/tcp in {FALLBACK})" if port and port != 22 else ""
        print(f"plan: set the default zone to {FALLBACK}{extra}, remove {path}, reload")
        return
    remove(runner, path, FALLBACK, port=port)
    if query(runner, "--get-default-zone") != FALLBACK:
        raise Refused(f"the default zone is not {FALLBACK} after the restore")
    print(f"restored: the default zone is {FALLBACK}")


def main(argv=None, runner=run, zone_file: Path = ZONE_FILE) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--policy", type=Path, default=POLICY)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--restore", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    if args.check and (args.apply or args.restore):
        parser.error("--check changes nothing; use it alone")
    try:
        if args.restore:
            restore_port = None
            if args.policy.exists():
                try:
                    restore_port, _, _ = enrolled(load_policy(args.policy))
                except (Refused, OSError, ValueError):
                    restore_port = None
            restore(runner, zone_file, args.apply, port=restore_port)
            return 0
        port, dns, dhcpv6 = enrolled(load_policy(args.policy))
        text = render(port, dns, dhcpv6)
        if args.check:
            problems = drift(runner, zone_file, text, port, dns, dhcpv6)
            for problem in problems:
                print(f"drift: {problem}")
            if problems:
                return 1
            print(f"verified: the {ZONE} zone matches the policy")
            return 0
        if not args.apply:
            print(text, end="")
            print(f"plan: write {zone_file}, check sshd on {port}/tcp, reload, "
                  f"set the default zone to {ZONE}, verify")
            return 0
        apply(runner, zone_file, text, port, dns, dhcpv6)
        return 0
    except (Refused, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
