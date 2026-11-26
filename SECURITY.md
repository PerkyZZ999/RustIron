# Security Policy

## Pre-release status

RustIron is experimental pre-release software and has not yet had a public production release.

## Security architecture

- **Separate signing custody:** Private plan (`rustiron-plan-v1`) and release (`rustiron-release-v1`) signing keys stay off-host; neither host services nor the Console Admin Panel hold signing keys.
- **Executor-enforced authority:** `rustiron-executor` independently verifies peer UID and SELinux context, pinned `/usr/bin/ssh-keygen` SHA-256, canonical plan/grant digests, blast-radius budgets, non-replay admission marks, and durable intent before mutating host state.
- **Tenant isolation:** Per-site Linux UIDs, XFS quotas, systemd sandboxing, and Enforcing SELinux MCS (`rustiron_php_t`, `rustiron_app_t`, `rustiron_mail_relay_t`) confine WordPress pools, Node.js/Bun/EmDash apps, and mail relays.
- **Hardened Console Admin Panel:** Loopback-only listener (`127.0.0.1:4319`), `Host` allowlist (`421`), zero CORS, full-screen Better Auth login lockdown (`HttpOnly; SameSite=Strict; Secure` on HTTPS, rate-limited setup and sign-in), strict CSP/HSTS/`X-Frame-Options: DENY`/`Permissions-Policy`/COOP/CORP headers on all HTML, static, and API routes, and read-only defaults (`405` on write/mail mutations unless explicitly enabled).

## Reporting a vulnerability

Do not disclose security vulnerabilities in public GitHub issues.
Use GitHub Private Vulnerability Reporting on this repository and include:

1. Affected commit or version
2. Impact and privilege boundary crossed
3. Minimal reproduction steps

## Verifying release artifacts

Release directories and unified release bundles carry OpenSSH SSHSIG signatures in the dedicated `rustiron-release-v1` namespace:

```sh
scripts/release/release_sig.sh verify RELEASE_DIR allowed_signers SIGNER_ID
python3 scripts/release/bundle_release.py verify BUNDLE.tar.gz --release-signers allowed_signers --release-signer-id SIGNER_ID
```

Verification refuses tampered bytes, extra or missing files, symlinks, hardlinks, path traversal, setuid bits, and signatures from untrusted keys or other namespaces.
