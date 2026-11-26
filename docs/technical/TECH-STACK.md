# Rustiron accepted technology stack

Updated: 2026-11-26.
Selected stack.
Distinguish implementation from acceptance.

The owner accepted the Rust recommendations, selected Bun and JS quality checks, specified conditional Elysia and Lucide/DevIcons, requested the local Rust-Toolchain gate, and on 2026-11-26 directed migrating the Console UI from Astryx to the refined Tailwind CSS v4 + Coss UI (`@base-ui/react`) + `lucide-animated` + `evlog` stack (`W642`).
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
Prereleases and major architecture changes are not implied by this rule.
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
| Icons & client telemetry | `lucide-react` + `lucide-animated` (purposeful feedback only) + DevIcons for needed technology/brand marks; `evlog/client` structured console logging | No network log drain and no secret/signature logging |
| JS quality | Oxlint, Oxfmt, Fallow | Main lint/format/codebase gates; explicit TypeScript checking, tests and build still required |
| JS tests | `bun test`; React Testing Library with Happy DOM where appropriate | Replaces Vitest default; DOM emulator is not browser/layout proof |
| Browser acceptance | Playwright + accessibility checks and manual keyboard/screen-reader review | Separate browser automation; test its execution compatibility rather than assume Bun replaces it |
| Optional TS backend | Elysia on Bun, only when a TS HTTP/backend layer is needed | Unprivileged adapter to existing core; no alternate approval/executor authority |
| Routing / server state | TanStack Router installed; Query evaluated only for a concrete server-state need | TanStack Router is installed; evaluate additional server-state tooling only when needed |
| Charts | Evaluate Astryx's chart facilities before adding a separate library | Recharts is no longer the default recommendation; data/semantics/accessibility remain decisive |

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

No additional service is installed by this document.

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

Native security/recovery proof remains outside the generic quality gate and cannot be replaced by a green doctor run.

## Astryx with Bun and the existing design

Read [Astryx's agent index](https://astryx.atmeta.com/llms.txt), then use the scoped CLI package (`@astryxdesign/cli`, not bare `astryx`).
Reviewed CLI/Core 0.7.4 documentation topics: `getting-started`, `styling-overview`, `use-a-theme` and `icons`.
Those were the original research versions.

The installed versions are pinned in the console package and lockfile.
The verified core package is `@astryxdesign/core`.
Do not invent a React package name.

Astryx's documented plain-CSS path loads its prebuilt reset/component CSS and an installed theme's production CSS.
Consumer components do not need recompiling.
Use this path with Bun initially, plus the required `@stylexjs/stylex` peer.

Custom application `stylex.create()` source or swizzled components require an additional compiler pipeline.
Bun compatibility for that pipeline is not proven.
Avoid introducing it merely for shell blur, layout or straightforward CSS.

Extend a neutral theme into Rustiron's royal-blue/light/dark theme, map the reviewed DESIGN.md roles, and compile custom theme output using Astryx's theme workflow.
Neutral's bundled typography is not permission to replace our system font candidate silently.
Explicitly map typography and avoid unused font imports.

Built theme CSS/module wiring must work identically in development and production.
Keep resets, cascade layers, theme and scoped application overrides deliberate.
No theme source ejection is selected.

Review generated agent files before merging any setup output so AGENTS.md and its CLAUDE.md import are preserved.

Astryx supports theme-scoped icon overrides: map semantic icons to Lucide so internal close/menu/status controls match our app's action family.
Use DevIcons only for actual technologies/brands, respecting logo/contrast/accessibility needs.
Do not add its full catalogue or fetch floating CDN SVGs into the console at runtime.

At P14, verify the Bun dev/production path imports all CSS, preserves theme mode, renders needed components and passes browser/focus/reflow checks in both mockup-derived themes.
Package metadata and successful CLI documentation queries are not that integration proof.
Fallow must recognize real app/build/theme/test entrypoints.
Do not suppress generated theme imports or delete dynamically used components merely to obtain a clean report.

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

Cloud/beacon uploads or external service enrollment are not selected by choosing the local analyzer.

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
Bun/Astryx/theme integration, runner/browser compatibility, Fallow graph coverage and TS adapter need/authentication await their slices.

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
