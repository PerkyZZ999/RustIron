# Remote console access evaluation & threat contract (P16 Slice 1)

**Status:** Slice 1 architecture and threat contract published ([W623](../validation/S10-W623/README.md)).
Remote exposure remains **disabled** by default under [D-090](../decisions/D-090-cp04-v1-scope.md).
Enabling it requires a separate release, security decision, and independent review.

## Evaluation of transport options

| Option | Exposure model | Recommendation |
| --- | --- | --- |
| **Option A — SSH local port-forward or private WireGuard/Tailscale overlay** | Zero public HTTP listener; console stays bound to `127.0.0.1` (`D-090`) and reuses SSH/VPN authentication + P15 separate-custody offline SSHSIG grants | **Recommended default** for single-operator and small-team remote access; local-first remains supported without expanding public attack surface. |
| **Option B — Dedicated TLS 1.3 + mutual TLS / WebAuthn management reverse proxy** | Explicit management-only hostname behind a reviewed proxy; short-lived bound sessions, hardware-backed MFA, strict Host/Origin/CSP/CSRF/rate-limit enforcement, and revocation list | **Optional post-v1.0 only** after separate exposure decision, P18 gateway alignment, and independent web/auth penetration review. |
| **Option C — Public password-only or convenience listener** | Internet-facing control panel without hardware MFA or separate custody | **Rejected (P16 Stop condition: never enable a public listener merely for convenience).** |

## Mandatory security & testing requirements before any live P16 enablement

1. **No alternate privileged path**: Remote sessions talk only to the unprivileged coordinator through `READ-PROTOCOL.md` and `plan_apply`. The browser and web server NEVER hold signing keys or mint approvals.
2. **Credential theft & revocation**: stolen session tokens or client certificates can be revoked immediately, terminating active sessions within seconds.
3. **Session expiry**: bounded idle and absolute session lifetimes enforced server-side.
4. **Origin, proxy, and TLS checks**: strict `Host`, `Origin`, `Sec-Fetch-Site`, `X-Forwarded-*` trust boundary (only from loopback proxy), TLS 1.3 minimum, and HSTS on management hostname.
5. **Brute-force & lockout recovery**: rate limiting with safe operator SSH/local break-glass recovery so lockout never traps the host.
6. **Local-first preserved**: `127.0.0.1` loopback operation remains fully functional with remote access turned off.
