# Ownership-aware drift explanation (P24)

Updated: 2026-11-24, America/Toronto.
Roadmap: [P24 — Explain ownership-aware drift in depth](../planning/ROADMAP.md#p24--explain-ownership-aware-drift-in-depth).
Evidence: [W615](../validation/S10-W615/README.md).

`rustiron-control --explain-drift <merged-observation.json> [--human]` provides deep, strictly read-only ownership-aware drift explanation (`schema: "rustiron-drift-explanation/1"`, `auto_reset: false`, `preserves_foreign_state: true`).

## 1. Drift classification model

Every observed delta explicitly names:

- **`ownership`:** `rustiron_owned`, `host_shared`, `ejected_operator_owned`, or `foreign_unknown` (never guessed!).
- **`cause`:** `package_update`, `manual_emergency_edit`, `unknown_foreign_resource`, or `unreadable_unprivileged`.
- **`affected_resources`:** Exact blast radius (e.g., OLS parent or generation drift lists all served managed sites; `ssh-keygen` verifier drift lists `all_signed_admissions`).
- **`consequences`:** Concrete operational impact (e.g., executor refuses signed activations without resetting manual break-glass edits).
- **`allowed_resolutions`:** Bounded explicit operator actions from `{adopt, restore_owned, ignore, eject}`, each carrying `preserves_foreign_state: true` and exact runbook references.

## 2. Hard safety invariants

1. **Zero silent background resets:** `--explain-drift` reads one bounded observation JSON file (`O_NOFOLLOW`, regular file) and writes only to `stdout`.
2. **Foreign state preserved:** Unknown OLS vhosts and unmanaged systemd units are classified `foreign_unknown` / `unknown_foreign_resource`. `restore_owned` is **never** offered for foreign resources.
3. **Ejected sites respected:** Sites with `ejected: true` are counted in `ejected_sites_preserved` and never flagged as unexpected drift or proposed for reset.
4. **Unreadable checks stay truthful:** Unprivileged checks that cannot inspect root-only state (e.g. `firewalld`) are labeled `unreadable_unprivileged`, never reported as clean.
