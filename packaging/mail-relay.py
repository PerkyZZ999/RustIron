#!/usr/bin/env python3
"""Configure and verify the Rustiron D-071 per-site outbound mail relay (W610).

Orchestrates AlmaLinux 10's stock Postfix and systemd-socket-proxyd so each
enabled WordPress site can send outbound mail strictly through its own Unix
socket (/run/rustiron-mail/<account>/smtp) without network egress (D-019),
shell exec (D-046), or relay credentials inside the site (D-071).

Commands (dry-run by default; pass --apply to write host state):
  mail-relay.py configure-host --lab-discard [--rate-limit N] [--apply]
  mail-relay.py configure-host --relay-host HOST [--relay-port 587] [--rate-limit N] [--apply]
  mail-relay.py enable-site --account rs_SITE --domain DOMAIN [--mcs-level s0:cN] [--rate-limit N] [--install-mu-plugin] [--apply]
  mail-relay.py disable-site --account rs_SITE [--remove-mu-plugin] [--apply]
  mail-relay.py check [--account rs_SITE ...]

Never prints SASL password contents. Run as root with --apply.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys

ENV = {"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"}
POSTFIX_DIR = Path("/etc/postfix")
RUSTIRON_POSTFIX_DIR = POSTFIX_DIR / "rustiron"
SASL_PASSWD = RUSTIRON_POSTFIX_DIR / "sasl_passwd"
SYSTEMD_ETC = Path("/etc/systemd/system")
TMPFILES_ETC = Path("/etc/tmpfiles.d")
SITES_ROOT = Path("/srv/sites")
MU_PLUGIN_SOURCE = Path("/usr/share/rustiron/rustiron-mail-relay.php")
RUN_MAIL_DIR = Path("/run/rustiron-mail")

ACCOUNT_RE = re.compile(r"^rs_[a-z][a-z0-9_]{0,31}$")
DOMAIN_RE = re.compile(
    r"^(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
MCS_RE = re.compile(r"^s0:c[0-9]{1,4}(?:,c[0-9]{1,4})?$")

MIN_RATE_LIMIT = 1
MAX_RATE_LIMIT = 600


class Refused(RuntimeError):
    pass


def validate_account(account: str) -> str:
    if not ACCOUNT_RE.match(account):
        raise Refused(f"invalid site account name: {account!r}")
    return account


def validate_domain(domain: str) -> str:
    lowered = domain.strip().lower()
    if not DOMAIN_RE.match(lowered):
        raise Refused(f"invalid sender domain: {domain!r}")
    return lowered


def validate_relay_host(host: str) -> str:
    lowered = host.strip().lower()
    if not HOST_RE.match(lowered):
        raise Refused(f"invalid relay host: {host!r}")
    return lowered


def validate_port(port: int) -> int:
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise Refused(f"invalid relay port: {port!r}")
    return port


def validate_rate_limit(limit: int) -> int:
    if (
        not isinstance(limit, int)
        or isinstance(limit, bool)
        or not MIN_RATE_LIMIT <= limit <= MAX_RATE_LIMIT
    ):
        raise Refused(f"rate limit must be between {MIN_RATE_LIMIT} and {MAX_RATE_LIMIT}")
    return limit


def validate_mcs_level(level: str | None) -> str | None:
    if level is None:
        return None
    if not MCS_RE.match(level):
        raise Refused(f"invalid SELinux MCS level: {level!r}")
    return level


def render_host_postconf(
    *,
    lab_discard: bool,
    relay_host: str | None = None,
    relay_port: int = 587,
    rate_limit: int = 30,
) -> dict[str, str]:
    """Return exact Postfix main.cf settings for D-071 loopback-only relay."""
    validate_rate_limit(rate_limit)
    if lab_discard and relay_host is not None:
        raise Refused("cannot combine --lab-discard with --relay-host")
    if not lab_discard and relay_host is None:
        raise Refused("must specify either --lab-discard or --relay-host")

    settings = {
        "inet_interfaces": "loopback-only",
        "inet_protocols": "ipv4",
        "mydestination": "",
        "local_transport": "error:local delivery disabled by Rustiron D-071",
        "mynetworks": "127.0.0.0/8",
        "smtpd_banner": "$myhostname ESMTP",
        "anvil_rate_time_unit": "60s",
        "smtpd_client_message_rate_limit": str(rate_limit),
        "message_size_limit": "10485760",
    }
    if lab_discard:
        settings.update(
            {
                "relayhost": "",
                "default_transport": "discard:rustiron-lab-discard",
                "smtp_sasl_auth_enable": "no",
                "smtp_sasl_password_maps": "",
                "smtp_tls_security_level": "may",
            }
        )
    else:
        host = validate_relay_host(relay_host or "")
        port = validate_port(relay_port)
        settings.update(
            {
                "relayhost": f"[{host}]:{port}",
                "default_transport": "smtp",
                "smtp_sasl_auth_enable": "yes",
                "smtp_sasl_password_maps": f"texthash:{SASL_PASSWD}",
                "smtp_sasl_security_options": "noanonymous",
                "smtp_tls_security_level": "encrypt",
                "smtp_tls_CAfile": "/etc/pki/tls/certs/ca-bundle.crt",
            }
        )
    return settings


def render_sender_pcre(domain: str) -> str:
    """Allow only envelope senders in the site's exact domain (case-insensitive)."""
    dom = validate_domain(domain)
    escaped = re.escape(dom)
    return (
        f"# Managed by Rustiron D-071 mail-relay.py for domain {dom}\n"
        f"/^[^@\\s]+@{escaped}$/i OK\n"
        f"/./ REJECT 554 5.7.1 Sender domain not permitted for this site\n"
    )


def sender_map_path(account: str) -> Path:
    validate_account(account)
    return RUSTIRON_POSTFIX_DIR / f"sender-{account}.pcre"


def render_master_service(account: str, rate_limit: int = 30) -> str:
    """Render one Postfix master.cf entry for postconf -M."""
    validate_account(account)
    validate_rate_limit(rate_limit)
    pcre = sender_map_path(account)
    return (
        f"rustiron-{account}/unix=rustiron-{account} unix n - n - 2 smtpd "
        f"-o syslog_name=postfix/rustiron-{account} "
        f"-o smtpd_sender_restrictions=check_sender_access,pcre:{pcre},reject "
        f"-o smtpd_relay_restrictions=check_sender_access,pcre:{pcre},reject "
        f"-o smtpd_recipient_restrictions=permit "
        f"-o smtpd_client_message_rate_limit={rate_limit}"
    )


def render_socket_dropin(account: str, mcs_level: str | None) -> str:
    validate_account(account)
    level = validate_mcs_level(mcs_level) or "s0"
    return (
        "# Managed by Rustiron D-071 mail-relay.py\n"
        "[Socket]\n"
        f"SELinuxContext=system_u:system_r:rustiron_mail_relay_t:{level}\n"
    )


def render_tmpfiles_entry(account: str) -> str:
    validate_account(account)
    return (
        "# Managed by Rustiron D-071 mail-relay.py\n"
        f"d /run/rustiron-mail 0755 root root -\n"
        f"d /run/rustiron-mail/{account} 0750 root {account} -\n"
    )


def render_service_dropin(account: str, mcs_level: str | None) -> str:
    validate_account(account)
    level = validate_mcs_level(mcs_level) or "s0"
    return (
        "# Managed by Rustiron D-071 mail-relay.py\n"
        "[Service]\n"
        f"SELinuxContext=system_u:system_r:rustiron_mail_relay_t:{level}\n"
    )


def detect_site_mcs_level(account: str, systemd_etc: Path = SYSTEMD_ETC) -> str | None:
    """Read the site's MCS category from its rustiron-site-php@ drop-in."""
    validate_account(account)
    dropin_dir = systemd_etc / f"rustiron-site-php@{account}.service.d"
    if not dropin_dir.is_dir():
        return None
    for conf in sorted(dropin_dir.glob("*.conf")):
        text = conf.read_text(encoding="utf-8", errors="replace")
        match = re.search(r"SELinuxContext=system_u:system_r:rustiron_php_t:(s0:c[0-9,c]+)", text)
        if match:
            return validate_mcs_level(match.group(1))
    return None


def run(argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    res = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        env=ENV,
        check=False,
        timeout=60,
    )
    if check and res.returncode != 0:
        raise Refused(
            f"command failed ({res.returncode}): {' '.join(argv)}: {res.stderr.strip()}"
        )
    return res


def configure_host(args: argparse.Namespace) -> int:
    settings = render_host_postconf(
        lab_discard=args.lab_discard,
        relay_host=args.relay_host,
        relay_port=args.relay_port,
        rate_limit=args.rate_limit,
    )
    if not args.apply:
        for key, value in settings.items():
            print(f"{key} = {value}")
        print("# Dry run only; pass --apply as root to configure Postfix.")
        return 0

    if os.geteuid() != 0:
        raise Refused("configure-host --apply requires root")
    RUSTIRON_POSTFIX_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chmod(RUSTIRON_POSTFIX_DIR, 0o755)
    # Start Postfix before postfix check so /var/lib/postfix keeps postfix_data_t (W482).
    run(["/usr/bin/systemctl", "enable", "--now", "postfix.service"])
    postconf_args = ["/usr/sbin/postconf", "-e"] + [f"{k}={v}" for k, v in settings.items()]
    run(postconf_args)
    run(["/usr/sbin/restorecon", "-R", "/var/lib/postfix", str(RUSTIRON_POSTFIX_DIR)])
    run(["/usr/sbin/postfix", "check"])
    run(["/usr/bin/systemctl", "restart", "postfix.service"])
    print("configured: postfix host relay")
    return 0


def enable_site(args: argparse.Namespace) -> int:
    account = validate_account(args.account)
    domain = validate_domain(args.domain)
    rate_limit = validate_rate_limit(args.rate_limit)
    mcs_level = validate_mcs_level(args.mcs_level) or detect_site_mcs_level(account)
    pcre_text = render_sender_pcre(domain)
    master_entry = render_master_service(account, rate_limit)
    sock_dropin = render_socket_dropin(account, mcs_level)
    svc_dropin = render_service_dropin(account, mcs_level)

    if not args.apply:
        print(f"# sender map: {sender_map_path(account)}")
        print(pcre_text, end="")
        print(f"# master.cf: postconf -M {master_entry}")
        print(f"# socket drop-in ({mcs_level or 's0'}):")
        print(sock_dropin, end="")
        print("# Dry run only; pass --apply as root to enable site mail relay.")
        return 0

    if os.geteuid() != 0:
        raise Refused("enable-site --apply requires root")
    try:
        pw = pwd.getpwnam(account)
    except KeyError as exc:
        raise Refused(f"site account does not exist: {account}") from exc

    RUSTIRON_POSTFIX_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
    map_path = sender_map_path(account)
    map_path.write_text(pcre_text, encoding="utf-8")
    os.chmod(map_path, 0o644)

    run(["/usr/sbin/postconf", "-M", master_entry])
    run(["/usr/sbin/postfix", "check"])
    run(["/usr/bin/systemctl", "reload-or-restart", "postfix.service"])

    sock_dir = SYSTEMD_ETC / f"rustiron-mail-relay@{account}.socket.d"
    svc_dir = SYSTEMD_ETC / f"rustiron-mail-relay@{account}.service.d"
    sock_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    svc_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    (sock_dir / "10-rustiron-site.conf").write_text(sock_dropin, encoding="utf-8")
    (svc_dir / "10-rustiron-site.conf").write_text(svc_dropin, encoding="utf-8")

    TMPFILES_ETC.mkdir(mode=0o755, parents=True, exist_ok=True)
    tmpfiles_conf = TMPFILES_ETC / f"rustiron-mail-{account}.conf"
    tmpfiles_conf.write_text(render_tmpfiles_entry(account), encoding="utf-8")
    os.chmod(tmpfiles_conf, 0o644)
    if mcs_level:
        pattern = f"/run/rustiron-mail/{account}(/.*)?"
        add_fc = run(
            ["/usr/sbin/semanage", "fcontext", "-a", "-t", "rustiron_mail_run_t", "-r", mcs_level, pattern],
            check=False,
        )
        if add_fc.returncode != 0:
            run(
                ["/usr/sbin/semanage", "fcontext", "-m", "-t", "rustiron_mail_run_t", "-r", mcs_level, pattern]
            )
    run(["/usr/bin/systemd-tmpfiles", "--create", str(tmpfiles_conf)])
    run(["/usr/sbin/restorecon", "-R", str(RUN_MAIL_DIR), str(RUSTIRON_POSTFIX_DIR)])
    run(["/usr/bin/systemctl", "daemon-reload"])
    run(["/usr/bin/systemctl", "enable", "--now", f"rustiron-mail-relay@{account}.socket"])
    run(["/usr/bin/systemctl", "restart", f"rustiron-mail-relay@{account}.socket"])

    # Ensure per-site runtime directory and socket carry exact 0750 root:<account> + MCS level.
    site_run_dir = RUN_MAIL_DIR / account
    if site_run_dir.is_dir():
        os.chown(site_run_dir, 0, pw.pw_gid)
        os.chmod(site_run_dir, 0o750)
        run(["/usr/sbin/restorecon", "-R", str(site_run_dir)])

    if args.install_mu_plugin:
        src = Path(args.mu_plugin_source)
        if not src.is_file():
            raise Refused(f"mu-plugin source not found: {src}")
        install_mu_plugin_safe(
            SITES_ROOT, account, src, pw.pw_uid, pw.pw_gid, mcs_level, run_fn=run
        )

    print(f"enabled: {account} -> domain={domain} mcs={mcs_level or 's0'} rate={rate_limit}/min")
    return 0


def install_mu_plugin_safe(
    sites_root: Path,
    account: str,
    src: Path,
    uid: int | None,
    gid: int | None,
    mcs_level: str,
    run_fn=run,
) -> Path:
    """W634 (V-01): traverse site-owned ancestry with O_DIRECTORY|O_NOFOLLOW,
    verify the source via O_NOFOLLOW, and install the mu-plugin atomically."""
    src_fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        src_stat = os.fstat(src_fd)
        if not stat.S_ISREG(src_stat.st_mode):
            raise Refused(f"mu-plugin source is not a regular file: {src}")
        with os.fdopen(src_fd, "rb") as handle:
            src_fd = -1
            payload = handle.read(262_144 + 1)
    finally:
        if src_fd >= 0:
            os.close(src_fd)
    if len(payload) > 262_144:
        raise Refused(f"mu-plugin source exceeds 256 KiB limit: {src}")

    dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    cur_fd = os.open(sites_root, dir_flags)
    try:
        for part in (account, "html", "wp-content"):
            try:
                next_fd = os.open(part, dir_flags, dir_fd=cur_fd)
            except OSError as exc:
                raise Refused(f"refused symlink or missing directory {part!r} under {sites_root}: {exc}") from exc
            os.close(cur_fd)
            cur_fd = next_fd
        try:
            os.mkdir("mu-plugins", 0o750, dir_fd=cur_fd)
        except FileExistsError:
            pass
        try:
            mu_fd = os.open("mu-plugins", dir_flags, dir_fd=cur_fd)
        except OSError as exc:
            raise Refused(f"refused non-directory or symlink mu-plugins: {exc}") from exc
        os.close(cur_fd)
        cur_fd = mu_fd
        if uid is not None and gid is not None:
            os.fchown(cur_fd, uid, gid)
            os.fchmod(cur_fd, 0o750)
        tmp_name = ".rustiron-mail-relay.php.tmp"
        dest_name = "rustiron-mail-relay.php"
        try:
            os.unlink(tmp_name, dir_fd=cur_fd)
        except FileNotFoundError:
            pass
        tmp_fd = os.open(
            tmp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o440,
            dir_fd=cur_fd,
        )
        try:
            with os.fdopen(tmp_fd, "wb") as out:
                tmp_fd = -1
                out.write(payload)
                out.flush()
                os.fsync(out.fileno())
                if uid is not None and gid is not None:
                    os.fchown(out.fileno(), uid, gid)
                os.fchmod(out.fileno(), 0o440)
            os.replace(tmp_name, dest_name, src_dir_fd=cur_fd, dst_dir_fd=cur_fd)
        except BaseException:
            if tmp_fd >= 0:
                os.close(tmp_fd)
            try:
                os.unlink(tmp_name, dir_fd=cur_fd)
            except FileNotFoundError:
                pass
            raise
    finally:
        if cur_fd >= 0:
            os.close(cur_fd)

    mu_dir = sites_root / account / "html" / "wp-content" / "mu-plugins"
    dest = mu_dir / "rustiron-mail-relay.php"
    if mcs_level:
        run_fn(
            [
                "/usr/bin/chcon",
                "-t",
                "httpd_sys_content_t",
                "-l",
                mcs_level,
                str(mu_dir),
                str(dest),
            ]
        )
    return dest


def disable_site(args: argparse.Namespace) -> int:
    account = validate_account(args.account)
    if not args.apply:
        print(f"# Dry run: would disable rustiron-mail-relay@{account}.socket and remove Postfix service rustiron-{account}")
        return 0
    if os.geteuid() != 0:
        raise Refused("disable-site --apply requires root")
    run(
        [
            "/usr/bin/systemctl",
            "disable",
            "--now",
            f"rustiron-mail-relay@{account}.socket",
            f"rustiron-mail-relay@{account}.service",
        ],
        check=False,
    )
    run(["/usr/sbin/postconf", "-MX", f"rustiron-{account}/unix"], check=False)
    sender_map_path(account).unlink(missing_ok=True)
    for kind in ("socket", "service"):
        d = SYSTEMD_ETC / f"rustiron-mail-relay@{account}.{kind}.d"
        if d.is_dir():
            shutil.rmtree(d)
    (TMPFILES_ETC / f"rustiron-mail-{account}.conf").unlink(missing_ok=True)
    run(
        ["/usr/sbin/semanage", "fcontext", "-d", f"/run/rustiron-mail/{account}(/.*)?"],
        check=False,
    )
    if args.remove_mu_plugin:
        (SITES_ROOT / account / "html" / "wp-content" / "mu-plugins" / "rustiron-mail-relay.php").unlink(
            missing_ok=True
        )
    run(["/usr/bin/systemctl", "daemon-reload"])
    run(["/usr/bin/systemctl", "reload-or-restart", "postfix.service"], check=False)
    print(f"disabled: {account}")
    return 0


def check_relay(args: argparse.Namespace) -> int:
    drift: list[str] = []
    iface = run(["/usr/sbin/postconf", "-h", "inet_interfaces"], check=False).stdout.strip()
    if iface != "loopback-only":
        drift.append(f"inet_interfaces={iface!r} (expected 'loopback-only')")
    mydest = run(["/usr/sbin/postconf", "-h", "mydestination"], check=False).stdout.strip()
    if mydest != "":
        drift.append(f"mydestination={mydest!r} (expected empty)")
    if SASL_PASSWD.exists():
        mode = SASL_PASSWD.stat().st_mode & 0o777
        if mode != 0o600 or SASL_PASSWD.stat().st_uid != 0:
            drift.append(f"{SASL_PASSWD} must be 0600 root:root (found {oct(mode)})")
    for raw in args.account or []:
        account = validate_account(raw)
        sock = RUN_MAIL_DIR / account / "smtp"
        if not sock.exists():
            drift.append(f"missing socket {sock}")
        if not sender_map_path(account).is_file():
            drift.append(f"missing sender map {sender_map_path(account)}")
    if drift:
        for item in drift:
            print(f"drift: {item}")
        return 1
    print("verified: postfix mail relay boundaries intact")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_host = sub.add_parser("configure-host")
    p_host.add_argument("--lab-discard", action="store_true")
    p_host.add_argument("--relay-host")
    p_host.add_argument("--relay-port", type=int, default=587)
    p_host.add_argument("--rate-limit", type=int, default=30)
    p_host.add_argument("--apply", action="store_true")

    p_en = sub.add_parser("enable-site")
    p_en.add_argument("--account", required=True)
    p_en.add_argument("--domain", required=True)
    p_en.add_argument("--mcs-level")
    p_en.add_argument("--rate-limit", type=int, default=30)
    p_en.add_argument("--install-mu-plugin", action="store_true")
    p_en.add_argument("--mu-plugin-source", default=str(MU_PLUGIN_SOURCE))
    p_en.add_argument("--apply", action="store_true")

    p_dis = sub.add_parser("disable-site")
    p_dis.add_argument("--account", required=True)
    p_dis.add_argument("--remove-mu-plugin", action="store_true")
    p_dis.add_argument("--apply", action="store_true")

    p_chk = sub.add_parser("check")
    p_chk.add_argument("--account", action="append")

    args = parser.parse_args(argv)
    try:
        if args.cmd == "configure-host":
            return configure_host(args)
        if args.cmd == "enable-site":
            return enable_site(args)
        if args.cmd == "disable-site":
            return disable_site(args)
        return check_relay(args)
    except Refused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
