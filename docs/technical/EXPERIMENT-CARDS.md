# Experiment Cards and retain/revert evidence (P22)

**Status:** Lab verified ([W617](../validation/S10-W617/README.md)).
**Scope:** Strictly read-only statistical and safety evaluator in `rustiron-control --evaluate-experiment`.

## Purpose

Performance tuning must be evidence-backed, reversible, and safe. Under P22, every proposed tuning change is evaluated as a preregistered **Experiment Card** (`rustiron-experiment-card/1`) and exported as a deterministic **retain or revert evidence report** (`rustiron-experiment-result/1`).

## Command interface

```sh
rustiron-control --evaluate-experiment <experiment-card.json> [--human]
```

Reads `<experiment-card.json>` with `O_NONBLOCK | O_NOFOLLOW` and bounded size, mutates nothing, and outputs a JSON or `--human` verdict.

## Evidence-backed categories and hard stops

Allowed categories (`change.category`):

- `lscache_invalidation`
- `php_pool`
- `opcache`
- `app_workers`
- `uncached_path`

Hard stops enforced before statistical evaluation:

1. **No automatic database changes (`refused_automatic_db_change`)**: any card with `change.automatic_db_change == true` or a database/MariaDB/MySQL category is refused immediately (`automatic_db_changes_allowed: false`).
2. **No unsafe private caching (`refused_unsafe_private_caching`)**: any card declaring `caches_private_auth_or_cart == true`, `private_cache_leak_detected == true`, or any trial with `private_cache_safe == false` is refused for immediate revert (`unsafe_private_caching_allowed: false`).
3. **No invalid comparisons (`invalid_comparison`)**:
   - Baseline and candidate trials must share one identical `workload_digest`.
   - Each arm must have at least `preregistered_criteria.min_randomized_repeats` (`>= 3`) trials.
   - `preregistered_criteria.randomized_order` must be `true` AND trial arms must be interleaved (at least 2 arm transitions) to prevent time-drift confounding.

## Statistical & budget criteria

- **Correctness:** every candidate trial must report `correctness_passed: true` (`revert_correctness_failure` otherwise).
- **Error budget:** aggregate candidate HTTP error rate must stay `<= budget.max_error_rate` (`revert_error_budget_exceeded` otherwise).
- **Resource ceilings:** candidate peak RSS (`MiB`) and peak CPU (`%`) must stay within `budget.max_memory_rss_mib` and `budget.max_cpu_percent` (`revert_resource_budget_exceeded` otherwise).
- **Meaningful effect and confidence:** Computes Welch's two-sample `t`-statistic, Welch-Satterthwaite degrees of freedom, and two-sided critical `t` at `preregistered_criteria.confidence_level` (`[0.80, 0.99]`). Retention requires statistical significance and improvement `>= min_meaningful_effect_percent`.
- **Honest no-benefit reporting:** When a safe change fails to prove meaningful benefit, the verdict is `no_benefit_revert` (`recommendation: "revert"`, `benefit_proven: false`). Performance equivalence does not falsify proven recovery value.
