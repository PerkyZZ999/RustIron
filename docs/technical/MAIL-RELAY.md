# Outbound Site Mail Relay Architecture (D-071, D-093)

Updated: 2026-11-24 (America/Toronto).
Roadmap items: [P07](../planning/ROADMAP.md#p07--schedule-wordpress-jobs-and-outbound-relay-mail-explicitly), [CP06](../planning/ROADMAP.md#cp06--mail-hosting).
Governing decisions: [D-071](../decisions/D-071-site-mail-relay.md), [D-093](../decisions/D-093-cp06-v1-scope.md), [D-019](../decisions/D-019-site-php-no-egress.md), [D-046](../decisions/D-046-php-exec-audit-scope.md).

## 1. Security boundaries preserved

Rustiron's lab-verified v1.0 host mail baseline runs no IMAP server, no host mailbox store, and no webmail on the host ([D-093](../decisions/D-093-cp06-v1-scope.md); the 2026-11-24 D-093 revision adds an opt-in Console-local Postfix/Dovecot mailbox catalog marked `pending_host_sync`, disabled by default, pending signed host sync). Outbound transactional mail from WordPress sites (password resets, form notifications, order receipts) follows one strict local-relay path that preserves every existing confinement guarantee:

1. **Zero network egress from site PHP ([D-019](../decisions/D-019-site-php-no-egress.md)):** `rustiron-site-php@<account>.service` keeps `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`, and `IPAddressDeny=any`. Site code cannot open TCP/UDP sockets or resolve DNS.
2. **Zero shell or binary exec from site PHP ([D-046](../decisions/D-046-php-exec-audit-scope.md)):** WordPress does not call PHP `mail()` or invoke `sendmail`/`msmtp`. Instead, the inspected read-only must-use plugin (`packaging/mail/rustiron-mail-relay.php`) subclasses WordPress's `PHPMailer` to keep native MIME assembly (`preSend()`) and transmit RFC 5321 SMTP directly over PHP's `stream_socket_client("unix:///run/rustiron-mail/<account>/smtp", ...)`. `rustiron_php_t` gains zero exec permissions.
3. **Per-site DAC and SELinux MCS socket isolation:** Each site runs `rustiron-mail-relay@<account>.socket` at `/run/rustiron-mail/<account>/smtp` (`0660 root:<account>` in `0750 root:<account>`). A drop-in sets `SELinuxContext=system_u:system_r:rustiron_mail_relay_t:s0:cN` so other sites face DAC and MCS denials.
4. **Confined socket proxy (`rustiron_mail_relay_t`):** `rustiron-mail-relay@<account>.service` runs `systemd-socket-proxyd` with `DynamicUser=yes`, `NoNewPrivileges=yes`, `RestrictAddressFamilies=AF_UNIX`, `ProtectSystem=strict`, `MemoryMax=32M`, and `TasksMax=16`. Dedicated policy `packaging/selinux/rustiron_mail_relay.te` permits forwarding only to `/var/spool/postfix/public/rustiron-<account>`.
5. **Per-site Postfix `smtpd` sender enforcement & rate limiting:** Stock AlmaLinux 10 Postfix listens strictly on `loopback-only` (`mydestination =`, local delivery disabled, zero public port 25). Each enabled site gets a dedicated Unix-socket `smtpd` service `rustiron-<account>` in `master.cf` with:
   - `smtpd_sender_restrictions = check_sender_access,pcre:/etc/postfix/rustiron/sender-<account>.pcre,reject` (accepting only `@<site-domain>`, rejecting spoofed sender domains with `554 5.7.1`),
   - `smtpd_client_message_rate_limit` enforced per site via Postfix `anvil`.
6. **Host-only smarthost credentials:** Authenticated submission to the external smarthost on port 587 (`smtp_tls_security_level = encrypt`, `smtp_sasl_auth_enable = yes`) reads `/etc/postfix/rustiron/sasl_passwd` (`0600 root:root`), invisible to every site and to `rustiron_mail_relay_t`. In disposable lab VMs, `--lab-discard` sets `default_transport = discard:rustiron-lab-discard` so zero lab mail leaves the VM.

## 2. Packaged components

- `packaging/selinux/rustiron_mail_relay.te` and `packaging/selinux/rustiron_mail_relay.fc`
- `packaging/systemd/rustiron-mail-relay@.socket` and `packaging/systemd/rustiron-mail-relay@.service`
- `packaging/mail/rustiron-mail-relay.php` (staged to `/usr/share/rustiron/rustiron-mail-relay.php`)
- `packaging/mail-relay.py` (staged to `/usr/libexec/rustiron/mail-relay`)
- Operator runbook: [`docs/operator/36-MAIL-RELAY-AND-CUTOVER.md`](../operator/36-MAIL-RELAY-AND-CUTOVER.md)
