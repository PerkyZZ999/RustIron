---
title: "Update RustIron"
description: "Update a server in one command with automatic rollback, and see how releases are signed."
category: "updates-releases"
order: 25
readMinutes: 5
runbooks: ["Runbook 14","Runbook 16","Runbook 31"]
keywords: ["update","upgrade","rollback","release","bundle","updater","version","advisory","journal"]
consoleLinks: [{"to":"/host/updates","label":"Host updates"},{"to":"/host/services","label":"Services"}]
---

## Updating a host with rustiron-updater.py {#one-command-updater}

packaging/rustiron-updater.py updates both the Rust control plane (binaries, helper, coordinator, SELinux policies, systemd units via update-product.py) and the Console Admin Panel atomically — always preserving /etc/rustiron-console/env, Better Auth & Mail SQLite databases, and node_modules.

- Every update verifies two layers of rustiron-release-v1 OpenSSH signatures (both the outer bundle tarball and the inner SHA256SUMS manifest) before touching the host.
- Anti-downgrade protection refuses older versions by default; journal schema changes require explicit --migrate-journal.
- If anything fails or misbehaves, rollback restores both the previous control plane and previous Console directory cleanly.

```sh title="Check current version, preview update plan, apply, or roll back" where="Server (root)"
sudo python3 packaging/rustiron-updater.py status
sudo python3 packaging/rustiron-updater.py plan --bundle ./rustiron-0.2.0-almalinux10-x86_64.tar.gz --release-signers /etc/rustiron/release_signers --release-signer-id release
sudo python3 packaging/rustiron-updater.py apply --bundle ./rustiron-0.2.0-almalinux10-x86_64.tar.gz --release-signers /etc/rustiron/release_signers --release-signer-id release
sudo python3 packaging/rustiron-updater.py rollback --to <previous-version>
```

## Cutting & signing a release bundle (maintainers) {#release-bundler}

When you are ready to publish a new RustIron release, run scripts/release/bundle_release.py to pack a reproducible tarball, sign it offline with your release key in namespace rustiron-release-v1, verify it, and update your releases.json channel index.

```sh title="Pack, sign offline, verify, and index a release bundle" where="Build / maintainer"
python3 scripts/release/bundle_release.py pack --version 0.2.0 --staged-dir ./staged --include-console --out-dir ./releases
python3 scripts/release/bundle_release.py sign --bundle ./releases/rustiron-0.2.0-almalinux10-x86_64.tar.gz --key ~/.ssh/rustiron-release
python3 scripts/release/bundle_release.py verify --bundle ./releases/rustiron-0.2.0-almalinux10-x86_64.tar.gz --release-signers ./release_signers --release-signer-id release
python3 scripts/release/bundle_release.py index --dir ./releases --base-url https://releases.example.com/rustiron --out ./releases/releases.json
```
