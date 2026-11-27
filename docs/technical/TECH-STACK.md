# Rustiron accepted technology stack

Updated: 2026-11-27.
Selected stack.
Distinguish implementation from acceptance.

The owner made these stack choices:

- accepted the Rust recommendations;
- selected Bun and the JS quality checks;
- specified conditional Elysia and Lucide/DevIcons;
- requested the local Rust-Toolchain gate;
- on 2026-11-26, moved the Console UI from Astryx to Tailwind CSS v4 + Coss UI (`@base-ui/react`) + `lucide-animated` + `evlog` (`W642`);
- on 2026-11-27, replaced `lucide-animated` with the static Lucide icon and a CSS spin (`W696`).

See [D-009 / ADR-007](../decisions/ADR-007-implementation-stack-and-quality-gates.md).
Six Cargo crates, the console workspace, and Rust/Bun quality gates exist.

Add only dependencies actually needed by each approved slice.

## Version policy

The owner requires the latest available versions that are mutually compatible.
Use current stable releases by default, verified from registries/official release sources at addition or update time.
Check Rust MSRV, peer/runtime requirements, licenses/advisories and the full project gates together.

Pin the tested project toolchains and commit Cargo/Bun lockfiles for reproducibility.
Do not float installations merely to appear current.
Recheck at subsequent dependency work.

An older version needs a recorded compatibility/security constraint and revisit condition.
This rule does not imply prereleases or major architecture changes.
Historical report versions describe their original environment, not a current dependency recommendation.

Do not rewrite preserved evidence.

## Stack and responsibility

| Layer | Selected direction | Boundary / status |
| --- | --- | --- |
| Host and website stack | AlmaLinux 10 x86_64, systemd, enforcing SELinux, OLS/LSPHP/LSCache, MariaDB | Existing accepted candidate; exact tuple and confinement proof remain gated |
| Core | Rust; modular coordinator and separate synchronous executor | Accepted; no TypeScript privileged executor |
| Contracts and CLI | Serde + serde_json, clap | Implemented strict contracts and canonicalization; full authority/host acceptance remains separate |
| Persistence | SQLite through rusqlite, explicit SQL migrations | Accepted; coordinator store and root registry/journal are separate authorities |
| Diagnostics / Linux | thiserror, tracing, narrow rustix features when needed | Accepted; redaction and descriptor/path invariants independently enforced |
| Rust quality gate | Rust-Toolchain through `rust-tc` | Integrated/proved in W001/W006; full doctor before each Rust task commit |
| Console | React + strict TypeScript | Selected; React/ReactDOM 19 with TanStack Router |
| JS/TS toolkit | Bun runtime, package manager, script runner, bundler and test runner wherever compatible | Default; `bun.lock`, frozen installs and pinned tools when configured |
| UI / styling | Tailwind CSS v4 (`bun-plugin-tailwind`, `tw-animate-css`) + Coss UI (`@base-ui/react`, CVA, copy-owned `console/src/components/ui/*`) + scoped `@layer components` CSS | Revised 2026-11-26 per owner direction (`W642`, replacing Astryx/StyleX); implements [DESIGN.md](../DESIGN.md) Matte Charcoal / Royal-Blue tokens |
| Icons & client telemetry | `lucide-react` (CSS motion for purposeful feedback only) + DevIcons for needed technology/brand marks; `evlog/client` structured console logging | No network log drain and no secret/signature logging |
| Console request validation | Zod v4, server-side only: one strict schema per JSON route and for coordinator replies | Accepted 2026-11-26 (`W681`); runs after the Host, Origin, CSRF, and size guards; plans and grants stay raw strings for the Rust decoder |
| Console sign-in | Better Auth with its two-factor plugin (TOTP and encrypted recovery codes); `uqr` draws the setup QR code in the browser | Accepted 2026-11-27 (`W727`, `W729`); Admin accounts need the second factor; `uqr` is MIT and has no dependencies |
| JS quality | Oxlint, Oxfmt, Fallow | Main lint/format/codebase gates; explicit TypeScript checking, tests and build still required |
| JS tests | `bun test`; React Testing Library with Happy DOM where appropriate | Replaces Vitest default; DOM emulator is not browser/layout proof |
| Browser acceptance | Playwright + accessibility checks and manual keyboard/screen-reader review | Separate browser automation; test its execution compatibility rather than assume Bun replaces it |
| Optional TS backend | Elysia on Bun, only when a TS HTTP/backend layer is needed | Unprivileged adapter to existing core; no alternate approval/executor authority |
| Routing / server state | TanStack Router installed; Query evaluated only for a concrete server-state need | TanStack Router is installed; evaluate additional server-state tooling only when needed |
| Charts | No chart library yet; choose one only for a concrete chart need | Data, semantics, and accessibility decide the choice |

Vite, Node/npm, Vitest, Biome, and Radix are not the default Rustiron Console toolchain.
A demonstrated compatibility gap can justify a narrow documented exception.
Do not silently reinstall superseded tooling or drop a required check.
Axum/Tokio is not required by the initial local core.
Conditional Elysia is the selected TS-backend direction, not a reason to create two gateways.

## Infrastructure and app hosting

D-018 requires orchestration of mature services.
PowerDNS is the authoritative DNS direction. firewalld is the host firewall direction.
These adapters are planned.

The lab does not establish production integration acceptance.
Node.js and Bun app hosting are required capabilities.
P26 chooses the direct or composed integration boundary.

P27 verifies both runtime profiles.
Use maintained mail, certificate, transfer, and optional app-platform components instead of replacement protocol implementations.
Pin versions after host/package compatibility and security checks.

This document installs no additional service.

## Rust implementation and local quality ownership

Keep the approved contracts/core/CLI/control/executor separation.
Start with standard Rust Unix I/O.
Serde does not by itself prove duplicate-key rejection, canonicalization or authorization. rusqlite uses explicit parameterized SQL, single-writer coordinator WAL/FULL and independent executor rollback-journal/EXTRA profiles, with effective settings and fault behavior verified. rustix wrappers still need ancestry/link/atomic-replacement/privilege tests.

Cryptographic library and exact SQLite linkage choices are reviewed in their relevant slices.

Follow [RUST-TOOLCHAIN-INTEGRATION](RUST-TOOLCHAIN-INTEGRATION.md) and the [owner's integration guide](/mnt/data-z/MyProjects/Rust-Toolchain/RUST-TOOLCHAIN.md).
`rust-tc quick` is day-to-day feedback; `rust-tc doctor` is the full local gate before each completed Rust task/commit.
The public interface is `rust-tc`, not `just` or the unrelated `rust-doctor` binary. cargo-deny owns advisories/licenses; do not add cargo-audit.

Nextest and separate doctests both remain required.
No Sonar integration is selected.
Miri, mutation and feature-powerset/fuzz runs are risk-triggered, not every-edit work.

Native security/recovery proof stays outside the generic quality gate. A green doctor run does not replace it.

## Tailwind and Coss UI with Bun

The Console moved from Astryx and StyleX to this stack in `W642` (owner, 2026-11-26).

- `bun-plugin-tailwind` compiles Tailwind CSS v4 in both the development server (`console/bunfig.toml`) and the production build (`console/scripts/build.ts`).
  The same CSS path must work in both modes.
- `console/src/styles.css` holds the [DESIGN.md](../DESIGN.md) tokens in `@theme inline`, the dark variant on `data-theme`, and the scoped `@layer` rules.
  Map new design roles there, and do not add unused font imports.
- The project owns its copy of the Coss UI components in `console/src/components/ui/`.
  They use Base UI (`@base-ui/react`) primitives and CVA variants.
  Change that copy. Do not add a second component library.
- Lucide (`lucide-react`) owns action and navigation icons.
  Use DevIcons only for real technologies and brands, respecting logo, contrast, and accessibility needs.
  Do not add a full icon catalogue or fetch CDN SVGs at runtime.
- Fallow must recognize the real app, build, and test entry points.
  Do not delete dynamically used components to get a clean report.

Package metadata does not prove the integration.
Browser, focus, and reflow checks in both themes do.

## Bun tests and JS quality gates

Bun owns package management, normal TS/JS execution, build scripts and unit/DOM runner wherever compatible.
[Bun's DOM documentation](https://bun.com/docs/test/dom) documents React Testing Library/Happy DOM integration.
Configure preload order, cleanup and missing browser APIs explicitly.
Keep Playwright real-browser journeys for CSS/layout, themes, glass compositing, keyboard and signed-operation flows.

[Oxlint](https://oxc.rs/docs/guide/usage/linter) owns linting.
Enable relevant React/hooks/accessibility rules instead of assuming defaults cover them.
[Oxfmt](https://oxc.rs/docs/guide/usage/formatter) owns formatting.

Exclude preserved historical reports/mockups and generated artifacts from formatter writes.
[Fallow](https://fallow.tools/llms.txt) owns codebase health, dead code, duplication and architecture checks under explicit severity/entrypoint policy.
Preserve exit codes and stderr.

Never turn `|| true` or an advisory-only review into a gate.
Use full-project checks as required, not only changed-file audit.
Current Fallow supports optional checker assistance, but is not a replacement for a TypeScript compiler or behavioral/security tests ([limitations](https://fallow.tools/docs/analysis/limitations.md)).

Future package scripts must expose one quality command covering format check, Oxlint, TypeScript checking, Fallow, Bun tests and production build.
Browser tests join the established suite when implemented.
Record exact commands after setup rather than pretending those scripts exist today.

Keep pinned/frozen dependencies, Bun's lifecycle-script trust explicit, and private/source-control material excluded.
Fallow auto-fixes require a preview and scope review.
Findings need investigation, not blanket ignores.

Choosing the local analyzer does not select cloud/beacon uploads or external service enrollment.

## Conditional Elysia boundary

A browser needs a bridge to the Unix-socket core.
If that bridge/backend is implemented in TypeScript, use [Elysia](https://elysiajs.com/llms.txt) on Bun, unprivileged and initially read-only.
Plain static UI hosting need not create a second application backend.
Choose the minimum adapter needed in P14/P15; do not implement both a Rust HTTP adapter and an Elysia backend by default.

Validate request/response schemas and core protocol compatibility.
Browser sessions, Elysia types/Eden clients or framework middleware cannot grant executor authority, access root journals or hold signing keys.
Bound local IPC, HTTP bodies/timeouts and outputs.

Address origin/CSRF/DNS-rebinding/session policy before even local exposure.
Remote/public management retains its separate gate.
Website serving remains OLS/PHP/MariaDB and independent of console availability.

## What is accepted versus still unverified

The owner selected the stack direction and gate ownership.
Do not ask again for unchanged selections.
`W642` integrated Bun, Tailwind, and the theme.
Runner/browser compatibility, Fallow graph coverage and TS adapter need/authentication await their slices.

W001/W006 established the Cargo workspace and Rust-Toolchain integration.
W002 adds the read contracts.
W003 adds clap 4.6.7, rustix 1.1.5 and the local coordinator/CLI.

W004 adds rusqlite 0.41.0 with bundled native bindings 0.39.0, coordinator metadata and pagination.
Verified gates cover 67 tests and one doctest, plus the real-binary smoke check and 24 detected deliberate isolated mutations.
W011 resolves the local bundle gap through the [verified private SQLite 3.54.1 build](NATIVE-SQLITE.md).

The published Rust packages remain unchanged.
No system library or registry source was changed.
Those early results did not establish a TS workspace or host acceptance.

The console now exists; State records its later evidence and remaining gates.
Current validation and remaining acceptance scope are recorded in VALIDATION.
