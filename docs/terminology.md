# Terminology

American English applies to this documentation suite.
Code identifiers retain their exact spelling.

## Canonical terms

| Canonical | Do not use | Definition |
| --- | --- | --- |
| Rustiron | | The open-source hosting panel and its control plane |
| Core | | The first WordPress operations and recovery milestone |
| coordinator | coordinator authority | The unprivileged process that forwards requests and records inventory |
| executor | generic root runner | The privileged process that independently validates fixed operations |
| console | | The React and TypeScript operator interface |
| plan | | Immutable bytes describing one bounded semantic change |
| grant | | Signed authorization bound to an exact plan and scope |
| operation | | One admitted execution with a stable identity and outcome |
| task | | One bounded development item identified by W plus a number |
| campaign | | One acceptance test family identified by T plus a number |
| gate | | An evidence checkpoint identified by G plus a number |
| slice | | A Core delivery outcome identified by S plus a number |
| card | | A retained feature contract identified by P plus a number |
| parity package | | A CyberPanel workflow group identified by CP plus a number |
| observation | | A dated report with source and completeness metadata |
| receipt | | An operation evidence report with scoped recovery fields |
| site | | An enrolled website with explicit resource ownership |
| app | | A managed Node.js or Bun application with a runtime profile and deployment lifecycle |
| EmDash CMS | | A pinned EmDash 1.6.0 Node.js Starter workload running under P27 and P30 (D-096) |
| proxy site | | An enrolled hostname whose OLS vhost forwards HTTP and WebSocket paths to a local loopback port (D-095) |
| blast-radius envelope | | A deterministic pre-signing summary of affected sites, global OLS reload impact, and durable authority budgets (D-098) |
| recovery probe | | A contained restore test; the API verb is `restore_probe` |
| standing grant | standing approval | A signed schema 3 grant that authorizes `backup_capture` runs in a fixed window series (D-035) |
| capture window | schedule slot | One signed interval of a standing grant, in which each named site gets one run |
| independent copy | | Recovery data outside the source's physical and administrative failure domains |
| mail relay | | Per-site Unix-socket outbound Postfix relay for transactional site mail (D-071; D-093 2026-11-24 revision also permits an opt-in Console-local mailbox catalog pending host sync) |
| Experiment Card | | A preregistered tuning hypothesis evaluated by statistical significance and safety budgets (P22) |
| support matrix | | The reviewed version pins, minimum patch levels, and EOL dates in `crates/control/support-matrix.json` (D-063) |
| agent | | An AI development or automation actor; not a system daemon |
| service | | An infrastructure process or systemd service |
| orchestration | | Bounded management of existing infrastructure programs |
| PowerDNS | | Authoritative DNS server (`pdns` 5.1) managed through signed `dns_zone_import` and `dns_change` operations (CP05, D-091/D-092) |
| firewalld | FirewallD | The host firewall service managing the enrolled `rustiron` zone; the executable uses `firewall-cmd` (CP08, D-095) |

## Identifiers and abbreviations

The closed privileged catalogue covers five Core verbs and eighteen v1.0 extension verbs:

- Core: `site_provision`, `config_activate`, `site_eject`, `backup_capture`, `restore_probe`.
- Lifecycle and maintenance: `site_readopt`, `site_import`, `import_scrub`, `certificate_issue`, `site_clone`, `clone_scrub`, `site_retire`, `site_update`, `site_delete`, `site_quota`, `site_restore`, `site_credential_rotate`.
- DNS, proxy, and modern apps: `dns_zone_import`, `dns_change`, `proxy_site_provision`, `app_provision`, `app_deploy`, `app_lifecycle`.

The fixture switch is a lab-only path outside the product catalogue.

OLS means OpenLiteSpeed.
LSPHP means the LiteSpeed PHP runtime.
RPO means recovery point objective.

RTO means recovery time objective.
MCP means Model Context Protocol.
An ADR is an architecture decision record.

`worktree` names a Git working tree.
A guest checkout names a source directory inside the lab VM.

## Status vocabulary

- **Planned** means required work without implementation acceptance.
- **Partial** means implementation or evidence exists. Exit conditions remain open.
- **Verified locally** means cited local checks passed.
- **Lab verified** means cited host checks passed for the stated lab scope.
- **Accepted** means the responsible authority accepted the stated scope.
- **Blocked** means a named dependency prevents the next action.
- `NOT_RUN` means the stated campaign has not run.

A passing test does not grant deployment authority.
An independent agent review does not mean independent human review.
