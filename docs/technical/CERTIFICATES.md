# P02 certificates: issue, renew, and recover

2026-11-16. **Plan.** Roadmap [P02](../planning/ROADMAP.md#p02--issue-renew-and-recover-a-test-domain-certificate). Decisions [D-059](../decisions/D-059-certificates.md) and [D-060](../decisions/D-060-certificate-renewal.md) (renewal).
This page records the design. It authorizes no production effect.

[D-077](../decisions/D-077-alias-certificate-scope.md) adds the exact alias pair for the disposable private-CA lab. [W493](../validation/S10-W493/README.md) verifies offline review of the signed scope.

## Alias certificates in the lab

- `certificate_issue` schema 3 names the primary hostname and one distinct `alias_hostname`. The executor checks the alias reservation and the current HTTP generation before recording intent. Both listeners must be loopback, `migration.static_alias_http` must be enabled, and the enrolled ACME directory and trust bundle must be for the private lab CA.
- The administration helper checks the HTTP challenge for both names. It then runs certbot with loopback-only network access, the primary's lineage, and both domains. It requires exactly the two DNS SANs, a matching key, and current validity before installing the chain. Journal v28 records the second name in `certificate_aliases`.
- A separate signed activation adds both names to TLS. Verification checks both SNI fingerprints against the installed leaf. Standing renewal keeps the recorded pair and checks both SNI fingerprints after replacement. If the helper cannot verify restoration after a failure, the intent stays open for investigation.

## Boundary

- certbot runs as the unprivileged `rustiron-acme` account in a confined transient unit. It reads and writes only `/var/lib/rustiron-acme` and the site's challenge webroot. It reads no other part of a site tree.
- The ACME account key and the certificate keys stay in `/var/lib/rustiron-acme`, mode 0700. They never appear in a plan, a grant, a log, or evidence. Plans and receipts name a certificate by its SHA-256 and expiry.
- The executor derives every path from the site ID. It copies an issued certificate and key into the OLS generation only after checking them: one PEM chain whose leaf names exactly the signed hostname, a matching private key, and a validity window that covers now.
- OLS serves `/.well-known/acme-challenge/` for each vhost from `<site root>/acme/.well-known/acme-challenge/`, a folder that `rustiron-acme` owns and the site account cannot write. It is inside the site root because each vhost is `restrained` (W461).
- No DNS record and no mail setting changes.

## Flow

1. **Issue** (signed `certificate_issue`, slice 3): the plan names the site, its hostname, the CA directory URL from the enrolled policy, and the renewal window. The executor journals intent, runs certbot in the confined unit with the HTTP-01 webroot, checks the result, and records the certificate digest and expiry.
2. **Activate:** a generation that names the certificate in its vhost SSL block goes through the existing switch: preflight, `openlitespeed -t`, reload, and identity probes over TLS. A failure restores the predecessor.
3. **Renew** (slice 4): a timer runs `certbot renew` for hostnames whose standing grant is still valid. Each renewal is journaled. A renewed certificate is activated by the same switch. A failed renewal keeps the served certificate and raises an expiry warning in the health observation.
4. **Recover:** the predecessor generation still names the previous certificate files, so compensation restores them. An expired certificate with a failed renewal is a health finding, not a silent success.

## Lab CA

Caddy 2.10 from EPEL runs its `acme_server` on loopback on the lab host. Only the lab certbot trusts its root, through `REQUESTS_CA_BUNDLE`. Test hostnames resolve to loopback through `/etc/hosts` on the lab host. This is lab tooling, not product.

## Slices

1. The SNI listener and per-vhost SSL blocks in the rendered generation, with tests. No issuance.
2. The `rustiron-acme` account, its unit, the challenge context, and one lab issuance against the lab CA, run by hand under the lab rules.
3. The signed `certificate_issue` verb, its journal record, and activation.
4. Renewal, expiry warning, a failed challenge, and rollback.

## As implemented (W460)

[W460](../validation/S10-W460/README.md) adds slice 1, rendering only.

- `ols::render_with_tls` takes the enrolled TLS address. A managed site with a certificate gets `vhssl` with `keyFile` and `certFile` under `/etc/rustiron-tls/<account>/<certificate sha256>/`. One listener `<listener>TLS` (`secure 1`) maps exactly those sites. Its own key and certificate are the first such site's, for clients without SNI.
- Nothing sets `ciphers`, protocols, or `enableQuic`, so the [D-039](../decisions/D-039-tls-defaults-in-the-parent.md) parent defaults apply.
- The certificate folder is outside `/etc/rustiron-ols`, so a generation never holds a key, and the certificate digest is part of the generation's content address.
- The OLS policy gains an optional `tls_address` on its own port. Without it, or without a certificate, the render is byte-identical to the plain render, so enrolled hosts see no change.
- No site has a certificate yet: the journal record that sets one is slice 3.

## As implemented (W461)

[W461](../validation/S10-W461/README.md) runs slice 2 on a lab product host.

- With an enrolled TLS address, a vhost whose webroot exists serves only the challenge path from it, with rewrite off. OLS refuses a configuration whose context folder is missing (W461-F1), so a site without a webroot gets no context.
- certbot as `rustiron-acme`, in a sandboxed transient unit, got a certificate from Caddy's ACME server through the OLS listener.
- For slice 3: the install check reads the SAN (the subject can be empty), and the packaged `certbot-renew.timer` must be masked.

## As implemented (W462)

[W462](../validation/S10-W462/README.md) adds slice 3 and served a lab certificate over TLS.

- **Contract.** `certificate_issue` names a site and its hostname. Its fixed effects create the webroot, contact the enrolled CA, and install the certificate, with no traffic or DNS change. The CA directory and an optional lab bundle come from the policy's `acme` section; the executor also requires an enrolled OLS `tls_address`.
- **Journal v23.** `certificates` holds each issuance: `intent`, then `installed` with the chain's SHA-256 and expiry, or `failed`. One may be open at a time, and an open one blocks other admissions. Issuances count in the admission mark and the signed intents.
- **Helper step.** It creates the webroot, proves through the listener that a token is served for the hostname, runs certbot as `rustiron-acme` (sandboxed transient unit, `--force-renewal`, ECDSA key), reads the lineage only inside certbot's archive folder, and checks the staged chain with `openssl`: exactly one SAN, the hostname; the private key matches; valid now. It then renames the folder into `/etc/rustiron-tls/<account>/<sha256>/`.
- **Outcomes.** A readable result is recorded `installed` or `failed`. A lost reply leaves `intent`; `rustiron-executor fail-certificate <operation>` settles it after the operator checks the host.
- **Serving.** `config_activate` gives each managed site its latest installed chain, and the W460 render serves it on the SNI listener.
- **SELinux.** `rustiron_admin` 0.5.0 labels `/etc/rustiron-tls` `rustiron_tls_t` (helper-managed, created by file transition under `/etc`) and `/var/lib/rustiron-acme` `rustiron_acme_state_t` (helper read-only). The sysusers file adds `rustiron-acme`.

## As implemented (W463)

[W463](../validation/S10-W463/README.md) adds the first part of [D-060](../decisions/D-060-certificate-renewal.md).

- Generations name `/etc/rustiron-tls/<account>/live`, a link to the served chain folder. A new chain no longer changes the generation.
- Activation preflight refuses (`OLS_DRIFT`) when a served site's link does not name its latest installed digest.
- An issuance swaps the link. For a site served through the link, the helper runs `openlitespeed -t`, a graceful reload, and an `openssl s_client` probe that the listener serves the new leaf, and restores the previous link and reloads on any failure.
- `rustiron_admin` 0.5.2 manages links in `rustiron_tls_t` and may connect to the TLS listener's `http_port_t` port.

## As implemented (W464)

[W464](../validation/S10-W464/README.md) adds standing renewal under [D-060](../decisions/D-060-certificate-renewal.md).

- **Plan.** A schema 2 `certificate_issue` signs `renew_until`, later than `valid_from` and at most 366 days after it. Schema 1 grants no renewal.
- **Journal v24.** `certificate_grants` keeps each window, and `certificate_renewals` each renewal: `intent`, then `installed` with the new chain's digest and expiry, or `failed`. A site serves its latest installed issuance, or that issuance's latest installed renewal. An open renewal blocks admissions; renewals are not admissions and do not move the admission mark.
- **Due rule.** A renewal is due while the window is open, the site is still owned under the same hostname, the served chain expires within 30 days, and no renewal of the issuance started in the last six hours.
- **Driver.** Between requests, the executor's one request thread looks for due renewals a minute after start and then every 10 minutes. For each, it journals the intent and asks the helper's `certificate_renew` step, which runs the W462 issuance steps and the W463 checked switch. A readable outcome is recorded; a lost reply leaves the renewal `intent` and ends the round.
- **Finding.** The observation lists each served certificate with its digest and expiry and a finding: `expired`, `expires_soon` (under 14 days), `renewal_failed`, or none. A host without a certificate shows no `certificates` key.
- **Packaging.** The installer requires `certbot` and masks the package's `certbot-renew.timer`.

## Refusal before the journal (W480)

A `certificate_issue` for a site that cannot take it is refused with `PRECONDITION_CHANGED` before the journal, with nothing recorded and the nonce unused: no such site, a site that is not `succeeded` or `adopted`, an ejected site, or a hostname other than the site's. Before W480 the journal refused these cases with `REPLAY_DENIED` ([W479-F2](../validation/S10-W479/README.md#findings)). An exact repeat of an admitted issuance still answers from the journal.

## Ejected sites (W469, W470, D-064)

An ejected site ([D-037](../decisions/D-037-independent-eject.md)) is no longer Rustiron's to renew ([D-064](../decisions/D-064-eject-certificate.md)):

- The journal renews no certificate for it and refuses a new `certificate_issue` for it (`Conflict`). From W480, the executor refuses that issuance before the journal with `PRECONDITION_CHANGED`.
- Its standalone vhost keeps the `vhssl` block naming `/etc/rustiron-tls/<account>/live`, and the TLS listener keeps mapping it, so HTTPS continues (W470).
- The executor observation lists its certificate with `renewed_by: operator`. The diagnosis reports its expiry with owner `host` and the action to renew it outside Rustiron.

A site ejected before W470 has a standalone vhost without `vhssl`; its HTTPS stopped at the ejection.

At uninstall with `--ols-parent package` (W471), the chain and key of each such site are copied next to its standalone vhost, the standalone parent keeps the TLS listener, and Rustiron's certificate state moves into the archive ([uninstall](../operator/12-UNINSTALL.md#ejected-sites-with-a-certificate)).
