#!/usr/bin/env python3
"""Interactive and non-interactive AlmaLinux 10 x86_64 installation wizard (W646).

Guides an operator through preparing a fresh AlmaLinux 10 host and installing
Rustiron without inventing trust values, storing private signing keys on the
host, or weakening SELinux, firewalld, SSH, or D-090 loopback boundaries.

Modes:
  --plan (default): Validate inputs, inspect host prerequisites read-only,
      emit an auditable JSON and human installation blueprint plus exact
      commands, and change nothing on disk.
  --interactive: Walk through each setting on a TTY before running --plan
      (or --apply when explicitly requested).
  --apply: Execute bounded host-preparation steps (SSH key-only drop-in,
      SELinux Enforcing + /.autorelabel gate, optional XFS usrquota loopback
      /srv/sites volume, listener IP drop-ins for rustiron-admin-helper and
      rustiron-site-cron, and optional Console systemd unit & env skeleton),
      stopping cleanly if a one-time SELinux autorelabel reboot is required.

Signing keys MUST stay off-host; this wizard never creates or reads a private
plan or release signing key. Experimental pre-release tooling — no supported
public product release exists yet.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


enrollment = _load_module("enrollment_policy_wiz", HERE / "enrollment-policy.py")

DEFAULT_ACME_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
DEFAULT_JOB_PROFILE = "packaging/profiles/alma10-epel-el10_3-job-tools.toml"
DEFAULT_UID_RANGE = "3001-3099"
DEFAULT_CATEGORY_RANGE = "201-299"
DEFAULT_QUOTA_KIB = 5 * 1024 * 1024  # 5 GiB
DEFAULT_QUOTA_INODES = 500_000
DEFAULT_XFS_GIB = 40
DEFAULT_CONSOLE_PORT = 4319
HOSTNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")


class WizardError(ValueError):
    """Refusal raised before any host write when an input violates Rustiron policy."""


@dataclass(frozen=True)
class WizardConfig:
    host_id: str
    host_epoch: str
    public_ipv4: str
    ssh_port: int = 22
    dhcpv6_client: bool = True
    ols_listener: str = "RustironPublic"
    ols_http_port: int = 80
    ols_tls_port: int = 443
    ols_webadmin_port: int = 7080
    issuer: str = "operator_signer"
    signer_policy_epoch: str = "policy_1"
    acme_directory: str = DEFAULT_ACME_DIRECTORY
    uid_range: str = DEFAULT_UID_RANGE
    category_range: str = DEFAULT_CATEGORY_RANGE
    quota_block_hard_kib: int = DEFAULT_QUOTA_KIB
    quota_inode_hard: int = DEFAULT_QUOTA_INODES
    sites_xfs_loopback_gib: int = DEFAULT_XFS_GIB
    blast_window_seconds: int = 3600
    blast_max_admissions: int = 64
    blast_max_ols_reloads: int = 16
    blast_max_served_sites: int = 16
    enable_console: bool = True
    console_port: int = DEFAULT_CONSOLE_PORT
    console_domain: str | None = None
    job_profile: str = DEFAULT_JOB_PROFILE
    # W657 (D-102, Decision A1): dual-mode Caddy ingress enrollment.
    ingress_mode: str = "ols_only"
    caddy_ipv4: str | None = None
    ols_loopback_port: int = 8080
    # W658 (D-102, Decision C2): optional PostgreSQL 18.7 (PGDG EL-10) stack.
    enable_postgres: bool = False


VALID_INGRESS_MODES = ("ols_only", "caddy_only", "caddy_multi_ip", "caddy_edge_over_ols")


def validate_config(cfg: WizardConfig) -> None:
    """Validate every wizard field against enrollment-policy.py and D-095/D-098 rules."""
    try:
        enrollment.identifier("--host-id", cfg.host_id)
        enrollment.identifier("--host-epoch", cfg.host_epoch)
        enrollment.identifier("--issuer", cfg.issuer)
        enrollment.identifier("--signer-policy-epoch", cfg.signer_policy_epoch)
    except enrollment.Refused as error:
        raise WizardError(str(error)) from None

    if cfg.issuer == "rustiron_coordinator":
        raise WizardError("--issuer must differ from requester rustiron_coordinator")

    try:
        ip = ipaddress.ip_address(cfg.public_ipv4)
    except ValueError:
        raise WizardError("--public-ipv4 must be a valid IPv4 address") from None
    if ip.version != 4 or ip.is_unspecified or ip.is_multicast:
        raise WizardError("--public-ipv4 must be a unicast IPv4 address")

    if not 1 <= cfg.ssh_port <= 65535 or cfg.ssh_port in (53, 80, 443):
        raise WizardError("--ssh-port must be 1..65535 and not 53, 80, or 443")

    if not enrollment.LISTENER.fullmatch(cfg.ols_listener) or len(cfg.ols_listener) > 29:
        raise WizardError("--ols-listener must start with a letter and be 1..29 ASCII alphanumerics/_")

    ports = (cfg.ols_http_port, cfg.ols_tls_port, cfg.ols_webadmin_port)
    if any(not 1 <= p <= 65535 for p in ports) or len(set(ports)) != 3:
        raise WizardError("OLS HTTP, TLS, and WebAdmin ports must be distinct valid ports")

    try:
        uid_min, uid_max = enrollment.number_range("--uid-range", cfg.uid_range)
        cat_min, cat_max = enrollment.number_range("--category-range", cfg.category_range)
    except enrollment.Refused as error:
        raise WizardError(str(error)) from None
    if not (2000 <= uid_min <= uid_max < 60000):
        raise WizardError("--uid-range must be ordered inside 2000-59999")
    if not (1 <= cat_min <= cat_max <= 1023):
        raise WizardError("--category-range must be ordered inside 1-1023")
    if not enrollment.BLOCK_KIB[0] <= cfg.quota_block_hard_kib <= enrollment.BLOCK_KIB[1]:
        raise WizardError("--quota-block-hard-kib is outside allowed site quota bounds")
    if not enrollment.INODES[0] <= cfg.quota_inode_hard <= enrollment.INODES[1]:
        raise WizardError("--quota-inode-hard is outside allowed site inode bounds")

    if not 0 <= cfg.sites_xfs_loopback_gib <= 4096:
        raise WizardError("--sites-xfs-loopback-gib must be 0 (dedicated disk) or 1..4096 GiB")

    if not 60 <= cfg.blast_window_seconds <= 86400:
        raise WizardError("--blast-window-seconds must be 60..86400")
    if not 1 <= cfg.blast_max_admissions <= 1000:
        raise WizardError("--blast-max-admissions must be 1..1000")
    if not 1 <= cfg.blast_max_ols_reloads <= 64:
        raise WizardError("--blast-max-ols-reloads must be 1..64")
    if not 1 <= cfg.blast_max_served_sites <= 32:
        raise WizardError("--blast-max-served-sites must be 1..32")

    # Validate ACME directory via enrollment-policy's exact rules.
    ns = argparse.Namespace(acme_directory=cfg.acme_directory, acme_ca_bundle=None)
    try:
        enrollment.acme(ns)
    except enrollment.Refused as error:
        raise WizardError(str(error)) from None

    if cfg.enable_console:
        if not 1024 <= cfg.console_port <= 65535 or cfg.console_port == 3306:
            raise WizardError("--console-port must be 1024..65535 and never 3306")
        if cfg.console_domain is not None:
            dom = cfg.console_domain.strip().lower()
            if not HOSTNAME_RE.fullmatch(dom) or len(dom) > 253:
                raise WizardError("--console-domain must be a lowercase FQDN")

    if cfg.ingress_mode not in VALID_INGRESS_MODES:
        raise WizardError(f"--ingress-mode must be one of {', '.join(VALID_INGRESS_MODES)}")
    if cfg.ingress_mode == "caddy_multi_ip":
        if not cfg.caddy_ipv4:
            raise WizardError("--caddy-ipv4 is required when --ingress-mode is caddy_multi_ip")
        try:
            cip = ipaddress.ip_address(cfg.caddy_ipv4)
        except ValueError:
            raise WizardError("--caddy-ipv4 must be a valid IPv4 address") from None
        if cip.version != 4 or cip.is_unspecified or cip.is_multicast or str(cip) == cfg.public_ipv4:
            raise WizardError("--caddy-ipv4 must be a distinct unicast IPv4 address")
    elif cfg.caddy_ipv4 is not None:
        raise WizardError("--caddy-ipv4 is only valid with --ingress-mode caddy_multi_ip")
    if cfg.ingress_mode == "caddy_edge_over_ols":
        if not 1024 <= cfg.ols_loopback_port <= 65535 or cfg.ols_loopback_port in (2019, 3306, 5432, cfg.ols_webadmin_port):
            raise WizardError("--ols-loopback-port must be an unprivileged port other than 2019, 3306, 5432, or WebAdmin")


def inspect_host(root: Path = Path("/")) -> dict:
    """Read-only inspection of AlmaLinux 10 host prerequisites."""
    os_release = root / "etc/os-release"
    os_text = os_release.read_text(encoding="utf-8", errors="replace") if os_release.is_file() else ""
    os_id = ""
    version_id = ""
    for line in os_text.splitlines():
        if line.startswith("ID="):
            os_id = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("VERSION_ID="):
            version_id = line.split("=", 1)[1].strip().strip('"')

    selinux_cfg = root / "etc/selinux/config"
    selinux_configured = "unknown"
    if selinux_cfg.is_file():
        for line in selinux_cfg.read_text(encoding="utf-8", errors="replace").splitlines():
            stripped = line.strip()
            if stripped.startswith("SELINUX="):
                selinux_configured = stripped.split("=", 1)[1].strip()
                break

    enforce_file = root / "sys/fs/selinux/enforce"
    if enforce_file.is_file():
        val = enforce_file.read_text(encoding="utf-8", errors="replace").strip()
        selinux_runtime = "enforcing" if val == "1" else "permissive"
    else:
        selinux_runtime = "disabled"

    mountinfo_path = root / "proc/self/mountinfo"
    sites_usrquota = False
    if mountinfo_path.is_file():
        for line in mountinfo_path.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split()
            if len(parts) > 5 and parts[4] == "/srv/sites" and "usrquota" in line:
                sites_usrquota = True
                break

    ssh_hardening = (root / "etc/ssh/sshd_config.d/01-rustiron-ssh.conf").is_file()
    packages_present = {
        "openlitespeed": (root / "usr/local/lsws/bin/openlitespeed").is_file(),
        "lsphp84": (root / "usr/local/lsws/lsphp84/bin/lsphp").is_file(),
        "mariadb": (root / "usr/libexec/mariadbd").is_file() or (root / "usr/sbin/mariadbd").is_file(),
        "certbot": (root / "usr/bin/certbot").is_file(),
        "restic": (root / "usr/bin/restic").is_file(),
        "firewalld": (root / "usr/sbin/firewalld").is_file(),
        "bun": (root / "usr/local/bin/bun").is_file(),
        "caddy": (root / "usr/local/bin/caddy").is_file(),
        "postgresql18": (root / "usr/pgsql-18/bin/postgres").is_file(),
    }
    return {
        "os_id": os_id or "unknown",
        "version_id": version_id or "unknown",
        "is_almalinux_10": os_id == "almalinux" and version_id.startswith("10."),
        "selinux_configured": selinux_configured,
        "selinux_runtime": selinux_runtime,
        "selinux_reboot_needed": selinux_runtime != "enforcing",
        "sites_usrquota_mounted": sites_usrquota,
        "ssh_hardening_dropin_present": ssh_hardening,
        "packages": packages_present,
    }


def render_ssh_dropin(ssh_port: int) -> str:
    """Lexicographically first sshd drop-in (overrides 50-cloud-init.conf)."""
    lines = [
        "# Rustiron SSH hardening (overrides cloud-init 50-cloud-init.conf).",
        f"Port {ssh_port}",
        "PasswordAuthentication no",
        "KbdInteractiveAuthentication no",
        "PermitRootLogin prohibit-password",
    ]
    return "\n".join(lines) + "\n"


def render_ols_listener_dropin(public_ipv4: str) -> str:
    """Systemd drop-in allowing local OLS listener checks on the enrolled host IP."""
    return (
        "# Rustiron enrolled OLS listener IP allowlist (W646).\n"
        "[Service]\n"
        f"IPAddressAllow={public_ipv4}/32\n"
    )


def render_console_unit(working_dir: str = "/opt/rustiron/console") -> str:
    """Hardened systemd unit for the D-090 loopback Console Admin Panel."""
    return (
        "[Unit]\n"
        "Description=Rustiron Console Admin Panel (loopback only, D-090 hardened)\n"
        "After=network.target rustiron-coordinator.service\n\n"
        "[Service]\n"
        "Type=simple\n"
        "User=rustiron-build\n"
        "Group=rustiron-build\n"
        "SupplementaryGroups=systemd-journal\n"
        f"WorkingDirectory={working_dir}\n"
        "EnvironmentFile=/etc/rustiron-console/env\n"
        "ExecStart=/usr/local/bin/bun run src/server.ts\n"
        "Restart=on-failure\n"
        "RestartSec=3\n"
        "NoNewPrivileges=yes\n"
        "PrivateTmp=yes\n"
        "ProtectSystem=strict\n"
        "ProtectHome=read-only\n"
        "ProtectKernelTunables=yes\n"
        "ProtectKernelModules=yes\n"
        "ProtectControlGroups=yes\n"
        "LockPersonality=yes\n"
        "RestrictRealtime=yes\n"
        "RestrictSUIDSGID=yes\n"
        "ReadWritePaths=/var/lib/rustiron-console\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def render_console_env(cfg: WizardConfig, setup_token: str) -> str:
    """Root/console-readable 0600 environment file enforcing fail-closed auth setup."""
    lines = [
        "NODE_ENV=production",
        "RUSTIRON_CONSOLE_NO_FIXTURE=1",
        "RUSTIRON_CONSOLE_AUTH_REQUIRED=1",
        f"RUSTIRON_CONSOLE_PORT={cfg.console_port}",
        "RUSTIRON_COORDINATOR_SOCKET=/run/rustiron-coordinator/control.sock",
        "RUSTIRON_CONSOLE_AUTH_DB=/var/lib/rustiron-console/auth.sqlite",
        "RUSTIRON_CONSOLE_MAIL_DB=/var/lib/rustiron-console/mail.sqlite",
        f"RUSTIRON_CONSOLE_SETUP_TOKEN={setup_token}",
    ]
    if cfg.console_domain:
        lines.append(f"RUSTIRON_CONSOLE_ORIGIN=https://{cfg.console_domain.strip().lower()}")
    return "\n".join(lines) + "\n"


def build_enrollment_command(cfg: WizardConfig) -> list[str]:
    """Build exact packaging/enrollment-policy.py policy arguments."""
    cmd = [
        "python3",
        "packaging/enrollment-policy.py",
        "policy",
        "--out",
        "/etc/rustiron/policy.json",
        "--host-id",
        cfg.host_id,
        "--host-epoch",
        cfg.host_epoch,
        "--profile-digest",
        "<PROFILE_DIGEST_SHA256>",
        "--requester",
        "rustiron_coordinator",
        "--requester-uid",
        "$(id -u rustiron-coordinator)",
        "--issuer",
        cfg.issuer,
        "--signer-policy-epoch",
        cfg.signer_policy_epoch,
        "--verifier-sha256",
        "$(sha256sum /usr/bin/ssh-keygen | awk '{print $1}')",
        "--wordpress-sha256",
        "<WORDPRESS_713_SHA256>",
        "--uid-range",
        cfg.uid_range,
        "--category-range",
        cfg.category_range,
        "--quota-block-hard-kib",
        str(cfg.quota_block_hard_kib),
        "--quota-inode-hard",
        str(cfg.quota_inode_hard),
        "--ols-listener",
        cfg.ols_listener,
        "--ols-address",
        (
            f"127.0.0.1:{cfg.ols_loopback_port}"
            if cfg.ingress_mode == "caddy_edge_over_ols"
            else f"{cfg.public_ipv4}:{cfg.ols_http_port}"
        ),
        *(
            []
            if cfg.ingress_mode == "caddy_edge_over_ols"
            else ["--ols-tls-address", f"{cfg.public_ipv4}:{cfg.ols_tls_port}"]
        ),
        "--ols-parent-sha256",
        "<OLS_PARENT_SHA256_FROM_INSTALL>",
        "--ols-webadmin-port",
        str(cfg.ols_webadmin_port),
        *(
            [
                "--caddy-mode",
                cfg.ingress_mode,
                "--caddy-http-address",
                f"{cfg.caddy_ipv4 or cfg.public_ipv4}:80",
                "--caddy-https-address",
                f"{cfg.caddy_ipv4 or cfg.public_ipv4}:443",
                "--caddy-binary-sha256",
                "$(sha256sum /usr/local/bin/caddy | awk '{print $1}')",
                *(
                    ["--caddy-ols-upstream", f"127.0.0.1:{cfg.ols_loopback_port}"]
                    if cfg.ingress_mode == "caddy_edge_over_ols"
                    else []
                ),
            ]
            if cfg.ingress_mode != "ols_only"
            else []
        ),
        "--acme-directory",
        cfg.acme_directory,
        "--firewall-ssh-port",
        str(cfg.ssh_port),
        "--blast-radius-window-seconds",
        str(cfg.blast_window_seconds),
        "--blast-radius-max-admissions",
        str(cfg.blast_max_admissions),
        "--blast-radius-max-ols-reloads",
        str(cfg.blast_max_ols_reloads),
        "--blast-radius-max-served-sites",
        str(cfg.blast_max_served_sites),
    ]
    if cfg.dhcpv6_client:
        cmd.append("--firewall-dhcpv6-client")
    return cmd


def build_plan(cfg: WizardConfig, host_facts: dict) -> dict:
    """Build a complete, auditable installation blueprint without mutating the host."""
    validate_config(cfg)
    steps: list[dict] = []

    steps.append({
        "id": "os_update_and_packages",
        "title": "Update AlmaLinux 10 and install pinned hosting dependencies",
        "automated_in_apply": False,
        "commands": [
            "dnf -y upgrade",
            "dnf -y install epel-release policycoreutils-python-utils selinux-policy-devel "
            "firewalld audit mariadb-server certbot restic nodejs xfsprogs",
            "rpm -Uvh https://rpms.litespeedtech.com/centos/litespeed-repo-1.3-1.el10.noarch.rpm",
            "dnf -y install openlitespeed lsphp84 lsphp84-common lsphp84-mysqlnd lsphp84-gd "
            "lsphp84-intl lsphp84-mbstring lsphp84-opcache lsphp84-xml lsphp84-zip lsphp84-curl",
        ],
    })

    if cfg.enable_postgres:
        steps.append({
            "id": "postgresql_18_setup",
            "title": "Install and harden PostgreSQL 18 (18.7+ PGDG EL-10, loopback + SCRAM-SHA-256)",
            "automated_in_apply": False,
            "already_installed": bool(host_facts.get("packages", {}).get("postgresql18", False)),
            "commands": [
                "curl -fsSL https://download.postgresql.org/pub/repos/yum/keys/PGDG-RPM-GPG-KEY-RHEL -o /etc/pki/rpm-gpg/PGDG-RPM-GPG-KEY-RHEL",
                "(cd /etc/pki/rpm-gpg && sha256sum -c /opt/rustiron/packaging/repos/pgdg-keys.sha256)",
                "install -m 0644 packaging/repos/rustiron-pgdg-18.repo /etc/yum.repos.d/rustiron-pgdg-18.repo",
                "dnf -y install postgresql18-server postgresql18 postgresql18-libs",
                # W662-F2: label the PGDG server postgresql_exec_t (rustiron_app.fc) so it runs as postgresql_t.
                "restorecon -RF /usr/pgsql-18/bin",
                "/usr/pgsql-18/bin/postgresql-18-setup initdb",
                "install -d -m 0700 -o postgres -g postgres /var/lib/pgsql/18/data/conf.d",
                "install -m 0600 -o postgres -g postgres /usr/share/rustiron/postgres/zz-rustiron-loopback.conf /var/lib/pgsql/18/data/conf.d/zz-rustiron-loopback.conf",
                "install -m 0600 -o postgres -g postgres /usr/share/rustiron/postgres/pg_hba.conf /var/lib/pgsql/18/data/pg_hba.conf",
                "grep -qxF \"include_dir = 'conf.d'\" /var/lib/pgsql/18/data/postgresql.conf || echo \"include_dir = 'conf.d'\" >> /var/lib/pgsql/18/data/postgresql.conf",
                "systemctl enable --now postgresql-18.service",
            ],
        })

    steps.append({
        "id": "ssh_hardening",
        "title": "Enforce key-only SSH overriding cloud-init defaults",
        "automated_in_apply": True,
        "target_file": "/etc/ssh/sshd_config.d/01-rustiron-ssh.conf",
        "content_preview": render_ssh_dropin(cfg.ssh_port),
        "commands": ["sshd -t && systemctl reload sshd"],
    })

    steps.append({
        "id": "selinux_enforcing",
        "title": "Ensure SELinux Enforcing mode (reboot with /.autorelabel if disabled)",
        "automated_in_apply": True,
        "reboot_required": bool(host_facts.get("selinux_reboot_needed", True)),
        "commands": [
            "sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config",
            "touch /.autorelabel && systemctl reboot",
        ],
    })

    if cfg.sites_xfs_loopback_gib > 0:
        steps.append({
            "id": "sites_xfs_usrquota",
            "title": f"Provision dedicated {cfg.sites_xfs_loopback_gib} GiB XFS usrquota volume for /srv/sites",
            "automated_in_apply": True,
            "already_mounted": bool(host_facts.get("sites_usrquota_mounted", False)),
            "commands": [
                f"truncate -s {cfg.sites_xfs_loopback_gib}G /var/lib/rustiron-sites.img",
                "mkfs.xfs /var/lib/rustiron-sites.img",
                "mkdir -p /srv/sites && chmod 0755 /srv/sites",
                "echo '/var/lib/rustiron-sites.img /srv/sites xfs loop,usrquota 0 0' >> /etc/fstab",
                "mount -a && restorecon -v /srv/sites",
            ],
        })

    steps.append({
        "id": "stage_and_install_rustiron",
        "title": "Stage, verify off-host release signature (rustiron-release-v1), and install Rustiron",
        "automated_in_apply": False,
        "commands": [
            "python3 scripts/prepare_sqlite.py --fetch",
            "sh packaging/stage-product.sh /var/tmp/rustiron-stage",
            f"python3 packaging/stage-job-tools.py {shlex.quote(cfg.job_profile)} /var/tmp/rustiron-jobs",
            "# Off-host on operator workstation: sign MANAGEMENT_ROOT/SHA256SUMS in namespace rustiron-release-v1",
            f"python3 packaging/install-preflight.py <MANAGEMENT_ROOT> <HOST_JOB_ROOT> {shlex.quote(cfg.job_profile)} "
            "--release-signers /etc/rustiron/release-allowed-signers --release-signer-id <RELEASE_SIGNER_ID>",
            f"python3 packaging/assemble-install-root.py <MANAGEMENT_ROOT> <HOST_JOB_ROOT> {shlex.quote(cfg.job_profile)} /root/rustiron-root",
            f"python3 packaging/install-product.py <INSTALL_ROOT> <MANAGEMENT_ROOT> <HOST_JOB_ROOT> {shlex.quote(cfg.job_profile)} "
            "--release-signers /etc/rustiron/release-allowed-signers --release-signer-id <RELEASE_SIGNER_ID>",
        ],
    })

    steps.append({
        "id": "host_enrollment_and_dropins",
        "title": "Write enrolled policy.json, allowed_signers, and OLS listener drop-ins",
        "automated_in_apply": True,
        "dropin_files": [
            "/etc/systemd/system/rustiron-admin-helper.service.d/10-ols-listener.conf",
            "/etc/systemd/system/rustiron-site-cron.service.d/10-ols-listener.conf",
        ],
        "dropin_content": render_ols_listener_dropin(cfg.public_ipv4),
        "commands": [
            " ".join(build_enrollment_command(cfg)),
            f"python3 packaging/enrollment-policy.py allowed-signers --out /etc/rustiron/allowed_signers "
            f"--issuer {shlex.quote(cfg.issuer)} --public-key <OPERATOR_PLAN_SIGNER_PUB>",
            "chmod 0400 /etc/rustiron/policy.json /etc/rustiron/allowed_signers",
            "restorecon -R -v /etc/rustiron",
            "systemctl daemon-reload && systemctl enable --now rustiron-admin-helper rustiron-executor rustiron-coordinator rustiron-site-cron.timer",
        ],
    })

    steps.append({
        "id": "firewall_zone",
        "title": "Apply enrolled rustiron firewalld zone",
        "automated_in_apply": False,
        "commands": [
            "python3 packaging/firewall-zone.py --apply",
            "python3 packaging/firewall-zone.py --check",
        ],
    })

    if cfg.enable_console:
        console_step = {
            "id": "console_admin_panel",
            "title": "Install loopback D-090 Console Admin Panel with fail-closed Setup Token",
            "automated_in_apply": True,
            "target_unit": "/etc/systemd/system/rustiron-console.service",
            "target_env": "/etc/rustiron-console/env",
            "notes": [
                "Install Bun binary to /usr/local/bin/bun (0755 root:root, SELinux bin_t) so systemd init_t can exec it.",
                "RUSTIRON_CONSOLE_AUTH_REQUIRED=1 blocks /api/observation until initial Admin setup completes with RUSTIRON_CONSOLE_SETUP_TOKEN.",
            ],
            "commands": [
                "systemctl daemon-reload && systemctl enable --now rustiron-console.service",
            ],
        }
        if cfg.console_domain:
            console_step["notes"].append(
                f"Publish https://{cfg.console_domain.strip().lower()} via signed proxy_site_provision -> 127.0.0.1:{cfg.console_port}, "
                "config_activate, certificate_issue, and HTTPS config_activate."
            )
        steps.append(console_step)

    return {
        "schema": "rustiron-install-wizard-plan/1",
        "experimental": True,
        "private_keys_on_host": False,
        "config": asdict(cfg),
        "host_inspection": host_facts,
        "steps": steps,
    }


def write_restricted(path: Path, content: str, mode: int) -> None:
    """Atomically write a regular file refusing symlinks and setting exact mode."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink() or path.is_symlink():
        raise WizardError(f"refusing symlink at {path}")
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fchmod(handle.fileno(), mode)
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def apply_host_prep(
    cfg: WizardConfig,
    root: Path = Path("/"),
    runner=None,
    report=print,
) -> dict:
    """Apply bounded host preparation files safely; stops cleanly if SELinux reboot is needed."""
    validate_config(cfg)
    facts = inspect_host(root)
    written: list[str] = []

    ssh_dropin = root / "etc/ssh/sshd_config.d/01-rustiron-ssh.conf"
    write_restricted(ssh_dropin, render_ssh_dropin(cfg.ssh_port), 0o600)
    written.append(str(ssh_dropin))
    report(f"WROTE {ssh_dropin} (0600)")

    dropin_text = render_ols_listener_dropin(cfg.public_ipv4)
    for unit_dir in (
        "etc/systemd/system/rustiron-admin-helper.service.d/10-ols-listener.conf",
        "etc/systemd/system/rustiron-site-cron.service.d/10-ols-listener.conf",
    ):
        target = root / unit_dir
        write_restricted(target, dropin_text, 0o644)
        written.append(str(target))
        report(f"WROTE {target} (0644)")

    if cfg.enable_console:
        env_path = root / "etc/rustiron-console/env"
        if not env_path.exists():
            token = secrets.token_hex(24)
            write_restricted(env_path, render_console_env(cfg, token), 0o600)
            written.append(str(env_path))
            report(f"WROTE {env_path} (0600; setup token stored only on disk, never printed)")
        unit_path = root / "etc/systemd/system/rustiron-console.service"
        write_restricted(unit_path, render_console_unit(), 0o644)
        written.append(str(unit_path))
        report(f"WROTE {unit_path} (0644)")

    if facts["selinux_reboot_needed"]:
        selinux_cfg = root / "etc/selinux/config"
        if selinux_cfg.is_file():
            original = selinux_cfg.read_text(encoding="utf-8")
            updated = re.sub(r"^SELINUX=.*$", "SELINUX=enforcing", original, flags=re.M)
            if updated != original:
                write_restricted(selinux_cfg, updated, 0o644)
                written.append(str(selinux_cfg))
                report(f"UPDATED {selinux_cfg} -> SELINUX=enforcing")
        autorelabel = root / ".autorelabel"
        if not autorelabel.exists():
            write_restricted(autorelabel, "", 0o644)
            written.append(str(autorelabel))
        report("ACTION REQUIRED: Reboot the host now to finish SELinux Enforcing relabeling, then re-run the wizard.")
        return {"applied": True, "reboot_required": True, "written": written}

    if runner is not None:
        runner(["/usr/sbin/sshd", "-t"])
        runner(["/usr/bin/systemctl", "daemon-reload"])
    return {"applied": True, "reboot_required": False, "written": written}


def prompt_interactive(defaults: WizardConfig, input_fn=input, out=sys.stdout) -> WizardConfig:
    """Interactive TTY walkthrough collecting explicit operator choices."""
    def ask(label: str, default: str) -> str:
        raw = input_fn(f"{label} [{default}]: ").strip()
        return raw if raw else default

    print("\nRustIron Installation Wizard (AlmaLinux 10 x86_64 — Experimental Pre-Release)", file=out)
    print("Note: Private signing keys stay off-host; this wizard never reads or creates them.\n", file=out)

    host_id = ask("Host ID (e.g. prod_vps_1)", defaults.host_id)
    host_epoch = ask("Host epoch (e.g. epoch_1)", defaults.host_epoch)
    public_ipv4 = ask("Host public IPv4 address", defaults.public_ipv4)
    ssh_port = int(ask("SSH port (must not be 53/80/443)", str(defaults.ssh_port)))
    issuer = ask("Off-host plan signer issuer ID", defaults.issuer)
    signer_policy_epoch = ask("Signer policy epoch", defaults.signer_policy_epoch)
    acme_directory = ask("ACME directory URL", defaults.acme_directory)
    sites_xfs_gib = int(ask("Loopback XFS usrquota size for /srv/sites in GiB (0 = existing disk)", str(defaults.sites_xfs_loopback_gib)))
    enable_console = ask("Configure loopback Console Admin Panel? (yes/no)", "yes" if defaults.enable_console else "no").lower() in ("y", "yes")
    console_domain: str | None = defaults.console_domain
    if enable_console:
        dom = ask("Optional HTTPS hostname for Console (leave blank for SSH tunnel only)", defaults.console_domain or "")
        console_domain = dom or None

    cfg = WizardConfig(
        host_id=host_id,
        host_epoch=host_epoch,
        public_ipv4=public_ipv4,
        ssh_port=ssh_port,
        issuer=issuer,
        signer_policy_epoch=signer_policy_epoch,
        acme_directory=acme_directory,
        sites_xfs_loopback_gib=sites_xfs_gib,
        enable_console=enable_console,
        console_domain=console_domain,
    )
    validate_config(cfg)
    return cfg


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--interactive", action="store_true", help="Prompt interactively for host settings")
    parser.add_argument("--apply", action="store_true", help="Write host-prep drop-ins/config (default is read-only --plan)")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON plan")
    parser.add_argument("--root", type=Path, default=Path("/"), help="Filesystem root (default /; override for tests)")
    parser.add_argument("--host-id", default="rustiron_host_1")
    parser.add_argument("--host-epoch", default="epoch_1")
    parser.add_argument("--public-ipv4", default="203.0.113.10")
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument("--no-dhcpv6-client", action="store_true")
    parser.add_argument("--ols-listener", default="RustironPublic")
    parser.add_argument("--ols-http-port", type=int, default=80)
    parser.add_argument("--ols-tls-port", type=int, default=443)
    parser.add_argument("--ols-webadmin-port", type=int, default=7080)
    parser.add_argument("--issuer", default="operator_signer")
    parser.add_argument("--signer-policy-epoch", default="policy_1")
    parser.add_argument("--acme-directory", default=DEFAULT_ACME_DIRECTORY)
    parser.add_argument("--uid-range", default=DEFAULT_UID_RANGE)
    parser.add_argument("--category-range", default=DEFAULT_CATEGORY_RANGE)
    parser.add_argument("--quota-block-hard-kib", type=int, default=DEFAULT_QUOTA_KIB)
    parser.add_argument("--quota-inode-hard", type=int, default=DEFAULT_QUOTA_INODES)
    parser.add_argument("--sites-xfs-loopback-gib", type=int, default=DEFAULT_XFS_GIB)
    parser.add_argument("--no-console", action="store_true")
    parser.add_argument("--console-port", type=int, default=DEFAULT_CONSOLE_PORT)
    parser.add_argument("--console-domain", default=None)
    parser.add_argument("--job-profile", default=DEFAULT_JOB_PROFILE)
    parser.add_argument(
        "--ingress-mode",
        default="ols_only",
        choices=VALID_INGRESS_MODES,
        help="Host edge ingress mode (D-102 A1: ols_only, caddy_only, caddy_multi_ip, caddy_edge_over_ols)",
    )
    parser.add_argument("--caddy-ipv4", default=None, help="Dedicated IPv4 for Caddy when --ingress-mode=caddy_multi_ip")
    parser.add_argument("--ols-loopback-port", type=int, default=8080, help="Loopback OLS upstream port for caddy_edge_over_ols")
    parser.add_argument("--enable-postgres", action="store_true", help="Include PostgreSQL 18 (PGDG EL-10) installation & hardening steps (D-102 C2)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = WizardConfig(
        host_id=args.host_id,
        host_epoch=args.host_epoch,
        public_ipv4=args.public_ipv4,
        ssh_port=args.ssh_port,
        dhcpv6_client=not args.no_dhcpv6_client,
        ols_listener=args.ols_listener,
        ols_http_port=args.ols_http_port,
        ols_tls_port=args.ols_tls_port,
        ols_webadmin_port=args.ols_webadmin_port,
        issuer=args.issuer,
        signer_policy_epoch=args.signer_policy_epoch,
        acme_directory=args.acme_directory,
        uid_range=args.uid_range,
        category_range=args.category_range,
        quota_block_hard_kib=args.quota_block_hard_kib,
        quota_inode_hard=args.quota_inode_hard,
        sites_xfs_loopback_gib=args.sites_xfs_loopback_gib,
        enable_console=not args.no_console,
        console_port=args.console_port,
        console_domain=args.console_domain,
        job_profile=args.job_profile,
        ingress_mode=args.ingress_mode,
        caddy_ipv4=args.caddy_ipv4,
        ols_loopback_port=args.ols_loopback_port,
        enable_postgres=args.enable_postgres,
    )
    try:
        if args.interactive:
            cfg = prompt_interactive(cfg)
        facts = inspect_host(args.root)
        plan = build_plan(cfg, facts)
        if args.apply:
            if args.root == Path("/") and os.geteuid() != 0:
                raise WizardError("--apply on / requires root")
            result = apply_host_prep(
                cfg,
                root=args.root,
                runner=(
                    lambda cmd: subprocess.run(cmd, check=True, stdin=subprocess.DEVNULL, timeout=60)
                ) if args.root == Path("/") else None,
                report=(lambda _msg: None) if args.json else print,
            )
            if args.json:
                print(json.dumps({"plan": plan, "apply_result": result}, indent=2, sort_keys=True))
            return 0
    except (WizardError, OSError, subprocess.CalledProcessError) as error:
        print(f"REFUSED {error}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(plan, indent=2, sort_keys=True))
    else:
        print(f"RustIron Installation Blueprint — host={cfg.host_id} ({cfg.public_ipv4})")
        print(f"OS={facts['os_id']} {facts['version_id']} | SELinux={facts['selinux_runtime']} | /srv/sites usrquota={facts['sites_usrquota_mounted']}")
        print("Mode: dry-run plan (no changes written; pass --apply to write host-prep files)\n")
        for idx, step in enumerate(plan["steps"], start=1):
            print(f"{idx}. {step['title']} [{step['id']}]")
            for cmd in step.get("commands", []):
                print(f"   $ {cmd}")
            for note in step.get("notes", []):
                print(f"   ! {note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
