#!/usr/bin/env python3
"""Write product enrollment files from explicit operator inputs (W358).

The tool invents no trust value. Every host, signer, digest, range, limit and
port comes from an argument that the operator measured or chose. The tool
checks each value against the executor's rules (crates/executor/src/policy.rs)
and writes one new file, mode 0600, that the operator reviews before
installing it into /etc/rustiron. It never reads a private key.

  enrollment-policy.py policy --out FILE --host-id ID --host-epoch ID \
      --profile-digest HEX --requester ID --requester-uid UID --issuer ID \
      --signer-policy-epoch ID --verifier-sha256 HEX \
      [--wordpress-sha256 HEX --uid-range MIN-MAX --category-range MIN-MAX \
       --quota-block-hard-kib KIB --quota-inode-hard N] \
      [--ols-listener NAME --ols-address IP:PORT --ols-parent-sha256 HEX \
       --ols-webadmin-port PORT [--ols-tls-address IP:PORT]] \
      [--product-backup-destination-id ID --product-backup-digest HEX] \
      [--migration-php-versions X.Y[,X.Y...]]
  enrollment-policy.py allowed-signers --out FILE --issuer ID --public-key FILE
  enrollment-policy.py verifier --policy FILE --out FILE [--verifier PATH]
  enrollment-policy.py firewall --policy FILE --out FILE --firewall-ssh-port PORT \
      [--firewall-dhcpv6-client]

  enrollment-policy.py dns --policy FILE --out FILE --dns-listen ... --dns-soa ...

`policy` also takes [--firewall-ssh-port PORT [--firewall-dhcpv6-client]]
for the `firewall` section (W559, D-095) that packaging/firewall-zone.py
applies. `firewall` and `dns` (W560) write the same canonical policy with
only that section set, for a host enrolled before it.

`verifier` (W483) is for an openssh update: it reads the installed policy,
measures the verifier (default /usr/bin/ssh-keygen), and writes the same
canonical policy with only `verifier_sha256` changed. Check the package with
`rpm -V openssh-clients` first: the tool trusts the file it measures.

Exit 0 writes the file and prints its SHA-256. Exit 1 is a refusal; exit 2 is
a usage error.

Without the product backup pin, the policy is schema 1. With both pin values,
the policy is schema 2 with a `product_backup` section (W374). The pin names
the reviewed projection `/etc/rustiron/backup-destination.json`: its
destination ID and the digest that `rustiron plan destination-digest` printed
for it. Only a product build loads a schema 2 policy, and the executor
refuses it unless the installed projection has the same ID and digest.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import stat
import sys

NAMESPACE = "rustiron-plan-v1"
ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
HEX = re.compile(r"[0-9a-f]{64}")
LISTENER = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,31}")
KEY = re.compile(r"[A-Za-z0-9+/=]{1,128}")
# SiteQuotaLimits bounds in crates/contracts/src/approval/site.rs.
BLOCK_KIB = (64 * 1024, 16 * 1024 * 1024 * 1024)
INODES = (1_000, 100_000_000)
MAX_POLICY_BYTES = 16 * 1024


class Refused(ValueError):
    pass


def canonical(value: dict) -> bytes:
    # ASCII keys and strings and unsigned integers only: RFC 8785 equals
    # sorted compact JSON (the lab request scripts use the same rule).
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def identifier(name: str, value: str) -> str:
    if not ID.fullmatch(value):
        raise Refused(f"{name} must be 1-64 ASCII letters, digits, '_' or '-'")
    return value


def digest(name: str, value: str) -> str:
    if not HEX.fullmatch(value):
        raise Refused(f"{name} must be 64 lowercase hex digits")
    return value


def number_range(name: str, text: str) -> tuple[int, int]:
    match = re.fullmatch(r"([0-9]{1,10})-([0-9]{1,10})", text)
    if not match:
        raise Refused(f"{name} must be MIN-MAX")
    return int(match.group(1)), int(match.group(2))


def provisioning(args) -> dict | None:
    fields = (args.wordpress_sha256, args.uid_range, args.category_range,
              args.quota_block_hard_kib, args.quota_inode_hard)
    if all(field is None for field in fields):
        return None
    if any(field is None for field in fields):
        # The product profile refuses provisioning without a quota (W335).
        raise Refused("provisioning needs the recipe digest, both ranges and both quota limits")
    uid_min, uid_max = number_range("--uid-range", args.uid_range)
    category_min, category_max = number_range("--category-range", args.category_range)
    if not (2000 <= uid_min <= uid_max < 60000):
        raise Refused("--uid-range must be ordered inside 2000-59999")
    if not (1 <= category_min <= category_max <= 1023):
        raise Refused("--category-range must be ordered inside 1-1023")
    if not BLOCK_KIB[0] <= args.quota_block_hard_kib <= BLOCK_KIB[1]:
        raise Refused(f"--quota-block-hard-kib must be {BLOCK_KIB[0]}-{BLOCK_KIB[1]}")
    if not INODES[0] <= args.quota_inode_hard <= INODES[1]:
        raise Refused(f"--quota-inode-hard must be {INODES[0]}-{INODES[1]}")
    return {
        "wordpress_713_sha256": digest("--wordpress-sha256", args.wordpress_sha256),
        "uid_min": uid_min, "uid_max": uid_max,
        "category_min": category_min, "category_max": category_max,
        "quota": {"block_hard_kib": args.quota_block_hard_kib,
                  "inode_hard": args.quota_inode_hard},
    }


def ols(args) -> dict | None:
    fields = (args.ols_listener, args.ols_address, args.ols_parent_sha256, args.ols_webadmin_port)
    if all(field is None for field in fields):
        return None
    if any(field is None for field in fields):
        raise Refused("the ols section needs the listener, address, parent digest and WebAdmin port")
    if not LISTENER.fullmatch(args.ols_listener):
        raise Refused("--ols-listener must start with a letter: 1-32 letters, digits or '_'")
    port = address_port("--ols-address", args.ols_address)
    if not 1 <= args.ols_webadmin_port <= 65535 or args.ols_webadmin_port == port:
        raise Refused("--ols-webadmin-port must be a port other than the listener port")
    # No adopted site and no lscache site on a fresh product host.
    section = {"listener": args.ols_listener, "address": args.ols_address, "adopted": [],
               "parent_sha256": digest("--ols-parent-sha256", args.ols_parent_sha256),
               "webadmin_port": args.ols_webadmin_port, "lscache": []}
    # D-059: the SNI listener for sites with a certificate, on its own port.
    if args.ols_tls_address is not None:
        tls_port = address_port("--ols-tls-address", args.ols_tls_address)
        if tls_port in (port, args.ols_webadmin_port):
            raise Refused("--ols-tls-address must use a port other than the listener and WebAdmin")
        if len(args.ols_listener) > 29:
            raise Refused("--ols-listener must be at most 29 characters with --ols-tls-address")
        section["tls_address"] = args.ols_tls_address
    return section


def address_port(flag: str, value: str) -> int:
    host, separator, port = value.rpartition(":")
    try:
        if not separator or not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        raise Refused(f"{flag} must be IP:PORT") from None
    return int(port)


PHP_VERSION = re.compile(r"[5-9]\.[0-9]{1,2}")


def migration(args, provisioning_section) -> dict | None:
    """W446 (D-053): the host's LSPHP versions for `site_import`."""
    if args.migration_php_versions is None:
        if args.migration_static_alias_http:
            raise Refused("static alias HTTP needs --migration-php-versions")
        return None
    if provisioning_section is None:
        raise Refused("the migration section needs the provisioning section")
    versions = args.migration_php_versions.split(",")
    if not 1 <= len(versions) <= 8 or len(set(versions)) != len(versions) \
            or not all(PHP_VERSION.fullmatch(version) for version in versions):
        raise Refused("--migration-php-versions must be 1 to 8 distinct X.Y versions (5.0 to 9.99)")
    section = {"php_versions": versions}
    if args.migration_static_alias_http:
        address = (args.ols_address or "").rpartition(":")[0].strip("[]")
        try:
            loopback = ipaddress.ip_address(address).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            raise Refused("static alias HTTP needs an OLS loopback listener")
        section["static_alias_http"] = True
    return section


HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
TSIG_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")


def host_name(flag: str, value: str) -> str:
    labels = value.split(".")
    if len(value) > 253 or len(labels) < 2 or not all(HOST_LABEL.fullmatch(label) for label in labels):
        raise Refused(f"{flag} must be a lowercase host name with at least two labels")
    return value


def addresses(flag: str, value: str, low: int, high: int) -> list[str]:
    items = [item for item in value.split(",") if item] if value else []
    try:
        parsed = [ipaddress.ip_address(item) for item in items]
    except ValueError:
        raise Refused(f"{flag} must list IP addresses") from None
    if not low <= len(parsed) <= high or len(set(parsed)) != len(parsed) \
            or any(item.is_unspecified or item.is_multicast for item in parsed):
        raise Refused(f"{flag} must list {low} to {high} distinct unicast addresses")
    return [str(item) for item in parsed]


def dns(args) -> dict | None:
    """W550 (D-091): the PowerDNS enrollment; DnsPolicy in crates/executor/src/dns.rs."""
    fields = (args.dns_listen, args.dns_name_servers, args.dns_hostmaster, args.dns_secondaries,
              args.dns_tsig_key, args.dns_soa)
    if all(field is None for field in fields):
        return None
    if any(field is None for field in fields):
        raise Refused("the dns section needs the listen addresses, name servers, hostmaster, "
                      "secondaries, TSIG key name and SOA timers")
    names = [host_name("--dns-name-servers", name) for name in args.dns_name_servers.split(",")]
    if not 2 <= len(names) <= 4 or len(set(names)) != len(names):
        raise Refused("--dns-name-servers must list 2 to 4 distinct host names")
    key = args.dns_tsig_key
    if not 1 <= len(key) <= 63 or not all(TSIG_LABEL.fullmatch(label) for label in key.split(".")):
        raise Refused("--dns-tsig-key must be lowercase labels of letters, digits and inner hyphens")
    try:
        refresh, retry, expire, negative = (int(part) for part in args.dns_soa.split(","))
    except ValueError:
        raise Refused("--dns-soa must be REFRESH,RETRY,EXPIRE,NEGATIVE_TTL") from None
    if not (1200 <= refresh <= 86400 and 300 <= retry < refresh
            and 604800 <= expire <= 2419200 and 60 <= negative <= 86400):
        raise Refused("--dns-soa is outside the RFC 1912 ranges")
    return {"listen": addresses("--dns-listen", args.dns_listen, 1, 4),
            "name_servers": names,
            "hostmaster": host_name("--dns-hostmaster", args.dns_hostmaster),
            "secondaries": addresses("--dns-secondaries", args.dns_secondaries, 0, 8),
            "tsig_key": key,
            "soa": {"refresh": refresh, "retry": retry, "expire": expire, "negative_ttl": negative}}


def acme(args) -> dict | None:
    """W646 (D-059): enrolled ACME CA; matches AcmePolicy::valid in crates/executor/src/policy.rs."""
    directory = getattr(args, "acme_directory", None)
    ca_bundle = getattr(args, "acme_ca_bundle", None)
    if directory is None and ca_bundle is None:
        return None
    if directory is None:
        raise Refused("--acme-ca-bundle needs --acme-directory")

    def plain(text: str, limit: int) -> bool:
        return 1 <= len(text) <= limit and all(
            33 <= ord(ch) <= 126 and ch not in {'"', "\\", "'", "`"} for ch in text
        )

    if not plain(directory, 256) or not directory.startswith("https://"):
        raise Refused("--acme-directory must be a plain ASCII https:// URL (<= 256 chars)")
    rest = directory.removeprefix("https://")
    if not rest or rest.startswith("/"):
        raise Refused("--acme-directory must name a host after https://")
    section: dict[str, str] = {"directory": directory}
    if ca_bundle is not None:
        prefix = "/var/lib/rustiron-acme/"
        if not plain(ca_bundle, 128) or not ca_bundle.startswith(prefix):
            raise Refused(
                f"--acme-ca-bundle must be a plain ASCII path under {prefix} (<= 128 chars)"
            )
        rel = ca_bundle.removeprefix(prefix)
        parts = rel.split("/")
        if not rel or any(not part or part in (".", "..") for part in parts):
            raise Refused("--acme-ca-bundle must be a normalized path under /var/lib/rustiron-acme/")
        section["ca_bundle"] = ca_bundle
    return section


def firewall(args) -> dict | None:
    """W559 (D-095): the Rustiron firewalld zone; FirewallPolicy in crates/executor/src/policy.rs."""
    if args.firewall_ssh_port is None:
        if args.firewall_dhcpv6_client:
            raise Refused("--firewall-dhcpv6-client needs --firewall-ssh-port")
        return None
    if not 1 <= args.firewall_ssh_port <= 65535 or args.firewall_ssh_port in (53, 80, 443):
        raise Refused("--firewall-ssh-port must be a port other than 53, 80 and 443")
    return {"ssh_port": args.firewall_ssh_port, "dhcpv6_client": args.firewall_dhcpv6_client}


def blast_radius(args) -> dict | None:
    """W594 (P23, D-098): durable blast-radius envelope limits."""
    required = (
        args.blast_radius_window_seconds,
        args.blast_radius_max_admissions,
        args.blast_radius_max_ols_reloads,
        args.blast_radius_max_served_sites,
    )
    optional = (
        args.blast_radius_max_total_admissions,
        args.blast_radius_max_total_ols_reloads,
    )
    if all(v is None for v in required + optional):
        return None
    if any(v is None for v in required):
        raise Refused(
            "blast-radius needs --blast-radius-window-seconds, --blast-radius-max-admissions, "
            "--blast-radius-max-ols-reloads, and --blast-radius-max-served-sites"
        )
    window, max_adm, max_ols, max_sites = required
    if not 60 <= window <= 86400:
        raise Refused("--blast-radius-window-seconds must be 60..86400")
    if not 1 <= max_adm <= 1000:
        raise Refused("--blast-radius-max-admissions must be 1..1000")
    if not 1 <= max_ols <= 64:
        raise Refused("--blast-radius-max-ols-reloads must be 1..64")
    if not 1 <= max_sites <= 32:
        raise Refused("--blast-radius-max-served-sites must be 1..32")
    section = {
        "window_seconds": window,
        "max_admissions_per_window": max_adm,
        "max_ols_reloads_per_window": max_ols,
        "max_served_sites_per_activation": max_sites,
    }
    if args.blast_radius_max_total_admissions is not None:
        if not 1 <= args.blast_radius_max_total_admissions <= 10000:
            raise Refused("--blast-radius-max-total-admissions must be 1..10000")
        section["max_total_admissions"] = args.blast_radius_max_total_admissions
    if args.blast_radius_max_total_ols_reloads is not None:
        if not 1 <= args.blast_radius_max_total_ols_reloads <= 1000:
            raise Refused("--blast-radius-max-total-ols-reloads must be 1..1000")
        section["max_total_ols_reloads"] = args.blast_radius_max_total_ols_reloads
    return section


CADDY_MODES = ("caddy_only", "caddy_multi_ip", "caddy_edge_over_ols")
CADDY_FORBIDDEN_PORTS = (2019, 3306, 5432)


def caddy(args, ols_section: dict | None = None) -> dict | None:
    """W657 (D-102, Decision A1): enrolled Caddy edge ingress section."""
    mode = getattr(args, "caddy_mode", None)
    http_addr = getattr(args, "caddy_http_address", None)
    https_addr = getattr(args, "caddy_https_address", None)
    ols_upstream = getattr(args, "caddy_ols_upstream", None)
    binary_sha256 = getattr(args, "caddy_binary_sha256", None)
    fields = (mode, http_addr, https_addr, binary_sha256)
    if all(field is None for field in (*fields, ols_upstream)):
        return None
    if any(field is None for field in fields):
        raise Refused(
            "the caddy section needs --caddy-mode, --caddy-http-address, "
            "--caddy-https-address, and --caddy-binary-sha256"
        )
    if mode not in CADDY_MODES:
        raise Refused(f"--caddy-mode must be one of {', '.join(CADDY_MODES)}")
    http_port = address_port("--caddy-http-address", http_addr)
    https_port = address_port("--caddy-https-address", https_addr)
    if http_port == https_port:
        raise Refused("--caddy-http-address and --caddy-https-address must use distinct ports")
    if http_port in CADDY_FORBIDDEN_PORTS or https_port in CADDY_FORBIDDEN_PORTS:
        raise Refused("Caddy listener ports must not be 2019, 3306, or 5432")
    section: dict[str, str] = {
        "mode": mode,
        "http_address": http_addr,
        "https_address": https_addr,
        "binary_sha256": digest("--caddy-binary-sha256", binary_sha256),
    }
    if mode == "caddy_edge_over_ols":
        if ols_upstream is None:
            raise Refused("--caddy-ols-upstream is required when --caddy-mode is caddy_edge_over_ols")
        up_port = address_port("--caddy-ols-upstream", ols_upstream)
        if up_port in CADDY_FORBIDDEN_PORTS:
            raise Refused("--caddy-ols-upstream must not use port 2019, 3306, or 5432")
        up_host = ols_upstream.rpartition(":")[0].strip("[]")
        if not ipaddress.ip_address(up_host).is_loopback:
            raise Refused("--caddy-ols-upstream must be a loopback IP:PORT (e.g. 127.0.0.1:8080)")
        if ols_section is not None and ols_section.get("address") != ols_upstream:
            raise Refused("--caddy-ols-upstream must match enrolled ols.address")
        section["ols_upstream"] = ols_upstream
    else:
        if ols_upstream is not None:
            raise Refused("--caddy-ols-upstream is only allowed with --caddy-mode caddy_edge_over_ols")
        if mode == "caddy_multi_ip" and ols_section is not None:
            ols_addrs = {ols_section.get("address"), ols_section.get("tls_address")}
            if http_addr in ols_addrs or https_addr in ols_addrs:
                raise Refused("caddy_multi_ip addresses must not collide with ols listener addresses")
    return section


def product_backup(args) -> dict | None:
    """W374: the schema 2 pin of the reviewed product backup projection."""
    fields = (args.product_backup_destination_id, args.product_backup_digest)
    if all(field is None for field in fields):
        return None
    if any(field is None for field in fields):
        raise Refused("the product backup pin needs the destination ID and its digest")
    # ProductBackupPin in crates/executor/src/policy.rs: an Id and a digest.
    return {"destination_id": identifier("--product-backup-destination-id",
                                         args.product_backup_destination_id),
            "destination_policy_digest": digest("--product-backup-digest",
                                                args.product_backup_digest)}


def policy(args) -> bytes:
    document = {
        "schema_version": 1,
        "host_id": identifier("--host-id", args.host_id),
        "host_epoch": identifier("--host-epoch", args.host_epoch),
        "profile_digest": digest("--profile-digest", args.profile_digest),
        "requester": identifier("--requester", args.requester),
        "requester_uid": args.requester_uid,
        "issuer": identifier("--issuer", args.issuer),
        "signer_policy_epoch": identifier("--signer-policy-epoch", args.signer_policy_epoch),
        "verifier_sha256": digest("--verifier-sha256", args.verifier_sha256),
    }
    if document["issuer"] == document["requester"]:
        raise Refused("the issuer and the requester must differ")
    if not 1 <= args.requester_uid < 2**32 - 1:
        raise Refused("--requester-uid must be a non-root UID")
    provisioning_section = provisioning(args)
    ols_section = ols(args)
    for name, section in (("provisioning", provisioning_section), ("ols", ols_section),
                          ("caddy", caddy(args, ols_section)),
                          ("acme", acme(args)),
                          ("migration", migration(args, provisioning_section)), ("dns", dns(args)),
                          ("firewall", firewall(args)), ("blast_radius", blast_radius(args))):
        if section is not None:
            document[name] = section
    # The executor loads schema 1 without the pin and schema 2 with it only.
    # The tool never writes the lab `backup` section, which schema 2 refuses.
    pin = product_backup(args)
    if pin is not None:
        document["schema_version"] = 2
        document["product_backup"] = pin
    content = canonical(document)
    if len(content) > MAX_POLICY_BYTES:
        raise Refused("policy is larger than 16 KiB")
    return content


MAX_VERIFIER_BYTES = 16 * 1024 * 1024


def installed_policy(path: str) -> dict:
    with open(path, "rb") as source:
        raw = source.read(MAX_POLICY_BYTES + 1)
    if len(raw) > MAX_POLICY_BYTES:
        raise Refused("policy is larger than 16 KiB")
    try:
        document = json.loads(raw)
    except ValueError:
        raise Refused("policy is not JSON") from None
    if not isinstance(document, dict) or canonical(document) != raw:
        raise Refused("policy is not one canonical JSON object")
    return document


def with_section(args, name: str, section: dict | None) -> bytes:
    """A copy of the installed policy with one optional section set (W559, W560)."""
    document = installed_policy(args.policy)
    if section is None:
        raise Refused(f"the {name} section needs its values")
    if document.get(name) == section:
        raise Refused(f"the policy already has this {name} section; nothing to write")
    print(f"{name} {json.dumps(document.get(name))} -> {json.dumps(section)}")
    document[name] = section
    content = canonical(document)
    if len(content) > MAX_POLICY_BYTES:
        raise Refused("policy is larger than 16 KiB")
    return content


def remeasured_verifier(args) -> bytes:
    document = installed_policy(args.policy)
    old = document.get("verifier_sha256")
    if not isinstance(old, str) or not HEX.fullmatch(old):
        raise Refused("policy has no verifier_sha256")
    descriptor = os.open(args.verifier, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as verifier:
        details = os.fstat(verifier.fileno())
        if not stat.S_ISREG(details.st_mode) or details.st_uid != 0 or details.st_mode & 0o022:
            raise Refused("the verifier must be a regular root-owned file that only root can write")
        content = verifier.read(MAX_VERIFIER_BYTES + 1)
    if len(content) > MAX_VERIFIER_BYTES:
        raise Refused("the verifier is larger than 16 MiB")
    new = hashlib.sha256(content).hexdigest()
    if new == old:
        raise Refused("the verifier already has the enrolled digest; nothing to write")
    document["verifier_sha256"] = new
    print(f"verifier_sha256 {old} -> {new}")
    return canonical(document)


def allowed_signers(args) -> bytes:
    issuer = identifier("--issuer", args.issuer)
    with open(args.public_key, "rb") as source:
        raw = source.read(4097)
    if len(raw) > 4096:
        raise Refused("public key file is larger than 4 KiB")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError:
        raise Refused("public key file is not ASCII") from None
    if len(lines) != 1:
        raise Refused("public key file must hold exactly one line")
    parts = lines[0].split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519" or not KEY.fullmatch(parts[1]):
        raise Refused("public key must be one plain ssh-ed25519 key")
    # The comment is dropped: the executor accepts exactly four fields.
    return f'{issuer} namespaces="{NAMESPACE}" ssh-ed25519 {parts[1]}\n'.encode()


def write_new(path: str, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "wb") as target:
        target.write(content)
        target.flush()
        os.fsync(target.fileno())


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = root.add_subparsers(dest="command", required=True)
    first = commands.add_parser("policy", help="write a canonical policy.json")
    first.add_argument("--out", required=True)
    for name in ("--host-id", "--host-epoch", "--profile-digest", "--requester", "--issuer",
                 "--signer-policy-epoch", "--verifier-sha256"):
        first.add_argument(name, required=True)
    first.add_argument("--requester-uid", type=int, required=True)
    for name in ("--wordpress-sha256", "--uid-range", "--category-range",
                 "--ols-listener", "--ols-address", "--ols-parent-sha256", "--ols-tls-address",
                 "--caddy-mode", "--caddy-http-address", "--caddy-https-address",
                 "--caddy-ols-upstream", "--caddy-binary-sha256",
                 "--acme-directory", "--acme-ca-bundle",
                 "--product-backup-destination-id", "--product-backup-digest",
                 "--migration-php-versions", "--dns-listen", "--dns-name-servers",
                 "--dns-hostmaster", "--dns-secondaries", "--dns-tsig-key", "--dns-soa"):
        first.add_argument(name)
    for name in ("--quota-block-hard-kib", "--quota-inode-hard", "--ols-webadmin-port",
                 "--firewall-ssh-port", "--blast-radius-window-seconds",
                 "--blast-radius-max-admissions", "--blast-radius-max-ols-reloads",
                 "--blast-radius-max-served-sites", "--blast-radius-max-total-admissions",
                 "--blast-radius-max-total-ols-reloads"):
        first.add_argument(name, type=int)
    first.add_argument("--migration-static-alias-http", action="store_true")
    first.add_argument("--firewall-dhcpv6-client", action="store_true")
    second = commands.add_parser("allowed-signers", help="write the one-line signer list")
    for name in ("--out", "--issuer", "--public-key"):
        second.add_argument(name, required=True)
    third = commands.add_parser("verifier", help="re-measure the verifier into a copy of the policy")
    for name in ("--policy", "--out"):
        third.add_argument(name, required=True)
    third.add_argument("--verifier", default="/usr/bin/ssh-keygen")
    fourth = commands.add_parser("firewall", help="set the firewall section in a copy of the policy")
    for name in ("--policy", "--out"):
        fourth.add_argument(name, required=True)
    fourth.add_argument("--firewall-ssh-port", type=int, required=True)
    fourth.add_argument("--firewall-dhcpv6-client", action="store_true")
    fifth = commands.add_parser("dns", help="set the dns section in a copy of the policy")
    for name in ("--policy", "--out", "--dns-listen", "--dns-name-servers", "--dns-hostmaster",
                 "--dns-secondaries", "--dns-tsig-key", "--dns-soa"):
        fifth.add_argument(name, required=True)
    sixth = commands.add_parser("blast-radius", help="set the blast_radius section in a copy of the policy")
    for name in ("--policy", "--out"):
        sixth.add_argument(name, required=True)
    for name in ("--blast-radius-window-seconds", "--blast-radius-max-admissions",
                 "--blast-radius-max-ols-reloads", "--blast-radius-max-served-sites"):
        sixth.add_argument(name, type=int, required=True)
    for name in ("--blast-radius-max-total-admissions", "--blast-radius-max-total-ols-reloads"):
        sixth.add_argument(name, type=int)
    seventh = commands.add_parser("acme", help="set the acme section in a copy of the policy")
    for name in ("--policy", "--out", "--acme-directory"):
        seventh.add_argument(name, required=True)
    seventh.add_argument("--acme-ca-bundle")
    eighth = commands.add_parser("caddy", help="set the caddy section in a copy of the policy")
    for name in ("--policy", "--out", "--caddy-mode", "--caddy-http-address",
                 "--caddy-https-address", "--caddy-binary-sha256"):
        eighth.add_argument(name, required=True)
    eighth.add_argument("--caddy-ols-upstream")
    return root


def with_caddy(args) -> bytes:
    document = installed_policy(args.policy)
    section = caddy(args, document.get("ols"))
    return with_section(args, "caddy", section)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        content = {"policy": policy, "allowed-signers": allowed_signers,
                   "verifier": remeasured_verifier,
                   "firewall": lambda args: with_section(args, "firewall", firewall(args)),
                   "dns": lambda args: with_section(args, "dns", dns(args)),
                   "blast-radius": lambda args: with_section(args, "blast_radius", blast_radius(args)),
                   "acme": lambda args: with_section(args, "acme", acme(args)),
                   "caddy": with_caddy}[args.command](args)
        write_new(args.out, content)
    except (Refused, OSError) as error:
        print(f"REFUSED {error}", file=sys.stderr)
        return 1
    print(f"WROTE {args.out} sha256={hashlib.sha256(content).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
