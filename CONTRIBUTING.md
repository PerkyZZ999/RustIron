# Contributing to RustIron

Thank you for your interest in RustIron.

## Scope and boundaries

RustIron is an open-source hosting control plane built with Rust and TypeScript (Apache-2.0).
It orchestrates mature AlmaLinux 10 infrastructure (OpenLiteSpeed, LSPHP, MariaDB, systemd, firewalld, PowerDNS, restic, and Enforcing SELinux) without reimplementing web servers, DNS servers, databases, or backup engines.

Keep these security invariants in every contribution:

- Never add arbitrary privileged command runners, shell interpolation (`shell=True` / `sh -c`), or unsanitized paths/SQL.
- Keep private signing keys outside host services, the Console backend, tests, logs, and commits.
- Treat coordinator requests, browser inputs, imported archives, and external feeds as untrusted until independently validated.
- Run tenant workloads (PHP, Node.js, Bun, EmDash, WP-CLI, archives) under scoped unprivileged identities with SELinux MCS confinement.

## Local development prerequisites

- Linux x86_64 with the Rust toolchain pinned in `rust-toolchain.toml`
- Bun 1.4+ for `console/`
- Python 3.11+ and OpenSSH (`ssh-keygen`) for packaging and release tests
- Chromium (`/usr/bin/chromium` or `RUSTIRON_CHROMIUM`) for Playwright + axe WCAG 2.2 AA Console checks

## Verification before submitting a pull request

Run from the repository root with `TMPDIR=/tmp`:

```sh
python3 scripts/prepare_sqlite.py --fetch
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
python3 -m unittest discover -s scripts/tests -v
bun run --cwd console verify
bun run --cwd console check:browser
git diff --check
```

## Security issues

Do not open public issues for security vulnerabilities. Follow [SECURITY.md](SECURITY.md).
