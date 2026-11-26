# 31. Watch security advisories (P09)

Under [D-065](../decisions/D-065-v1-owner-choices.md) and [D-082](../decisions/D-082-release-ownership.md), an agent or operator checks pinned Rust, Bun/npm, AlmaLinux 10, and support-matrix versions against public security advisories on the operator PC. The watcher is read-only and never installs packages, modifies the repository, or authorizes a host change. The owner still reviews and signs every production update.

## Command

Run from the repository root:

```sh
python3 scripts/release/advisory_watch.py
```

To include a host's merged read-only observation (checking observed stack versions against `crates/control/support-matrix.json` and filtering AlmaLinux 10 errata against observed RPMs):

```sh
python3 scripts/release/advisory_watch.py --observation path/to/observation.json
```

To verify deterministically against a saved offline advisory bundle (no network access):

```sh
python3 scripts/release/advisory_watch.py --offline-bundle path/to/bundle.json
```

## Feeds and bounds

- **Rust crates (`Cargo.lock`):** queried against OSV (`https://api.osv.dev/v1/querybatch`, ecosystem `crates.io`).
- **Console packages (`console/bun.lock`):** queried against OSV (`https://api.osv.dev/v1/querybatch`, ecosystem `npm`).
- **AlmaLinux 10 host stack:** queried against `https://errata.almalinux.org/10/errata.json`, filtered to security errata (`type=security`) affecting the watched host RPM set (`almalinux-release`, `firewalld`, `glibc`, `kernel`, `mariadb`, `mariadb-server`, `openssh*`, `openssl*`, `restic`, `selinux-policy*`, `systemd`).
- **Support matrix (`crates/control/support-matrix.json`):** checks matrix review freshness, approaching/expired EOL dates, and (when `--observation` is given) observed host versions against series and minimums.
- Every input is read with `O_NOFOLLOW` and bounded size; only HTTPS feeds are accepted; untrusted advisory summaries are stripped of control characters.

## Exit codes and D-082 response targets

| Exit | Meaning | Next step |
| --- | --- | --- |
| `0` | All feeds and support-matrix checks succeeded with zero findings | Record the clean check |
| `1` | One or more advisories, EOL warnings, or support-matrix findings were reported | Triage per D-082: **48 hours** for `critical`/`high`, **7 days** for `moderate`/`low`. Prepare a tested patch on a branch, run all 27 gates (and a disposable VM rehearsal for host-stack updates), and present the diff and evidence for owner signing |
| `2` | Invalid input or unreachable/malformed feed (`feed_errors` non-empty) | Treat as incomplete (never as clean); inspect `feed_errors` and retry |
