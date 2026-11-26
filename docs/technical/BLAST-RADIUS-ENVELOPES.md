# P23 blast-radius envelopes and durable authority budgets

2026-11-23. Decision [D-098](../decisions/D-098-blast-radius-envelopes.md). Roadmap [P23](../planning/ROADMAP.md#p23--extend-change-budgets-into-operator-visible-blast-radius-envelopes). Implementation [W594](../validation/S10-W594/README.md).

## Envelope dimensions

`rustiron_contracts::approval::envelope_for_plan` computes a closed `BlastRadiusEnvelope` from any valid closed plan:

| Dimension | Field(s) | Meaning |
| --- | --- | --- |
| Site | `scope`, `sites_named`, `all_served_sites` | Exact count of named sites and whether a global OLS reload impacts every served site |
| Change | `max_changes`, `max_operations` | Bounded resource/component/record-set changes authorized by the plan |
| Reload | `ols_reloads`, `compensation_reloads`, `all_site_ols_impact` | Global OLS reload budget (`1` normal + `1` bounded compensation restore for `config_activate` and `site_eject`; `0` for non-OLS verbs) |
| Time | `time_window_seconds` | Exact signed validity window (`expires_at - valid_from`) |
| Resource | `resource_budget` | Signed quota limits, file/dump ceilings, or bounded worker profile |
| Privilege | `privilege_boundary` | Exact executor/helper/confined-account boundary exercised |

Inspect offline before signing:

```sh
rustiron-plan inspect PLAN.json
rustiron-plan envelope PLAN.json
```

## Enrolled limits and durable enforcement

Enroll optional limits in `policy.json` using `packaging/enrollment-policy.py`:

```sh
python3 packaging/enrollment-policy.py blast-radius \
  --policy /etc/rustiron/policy.json \
  --out /tmp/policy-with-budget.json \
  --blast-radius-window-seconds 3600 \
  --blast-radius-max-admissions 20 \
  --blast-radius-max-ols-reloads 4 \
  --blast-radius-max-served-sites 16 \
  --blast-radius-max-total-admissions 500 \
  --blast-radius-max-total-ols-reloads 100
```

When `blast_radius` is enrolled:

1. `Executor::admit` checks durable SQLite journal counts (`FixtureJournal::authority_usage`) before committing any new intent.
2. Over-budget activations (`sites_named > max_served_sites_per_activation`), exhausted rolling-window ceilings, and exhausted hard epoch ceilings are rejected with `PRECONDITION_CHANGED` before intent or admission-mark advancement.
3. Exact idempotent replays already recorded in `admission_signatures` continue to return their stored status even when remaining authority is `0`.
4. Closing and reopening the executor preserves durable counts and continues rejecting resumed excess effects.
5. `Executor::observe` emits `authority_budget` containing `enrolled`, `all_site_ols_impact`, `limits`, `consumed`, and `remaining`.
