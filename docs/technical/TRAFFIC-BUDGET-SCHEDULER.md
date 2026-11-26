# Traffic-budgeted background work (P25)

**Status:** Lab verified ([W616](../validation/S10-W616/README.md)).
**Scope:** Strictly read-only, deterministic scheduling gate in `rustiron-control --background-budget`.

## Purpose

WordPress cron (`site_cron`), scheduled backup captures (`backup_capture`), and routine housekeeping (`maintenance`) compete for CPU, memory, and disk I/O with live visitor traffic. Under P25, background scheduling may defer non-urgent work during measured busy windows without:

- hiding missed jobs or RPO failures;
- starving background work indefinitely;
- silently skipping jobs when host telemetry is missing or stale;
- performing autonomous database tuning (`autonomous_db_tuning: false`).

## Command interface

```sh
rustiron-control --background-budget <merged-observation.json> \
  [--job site_cron|backup_capture|maintenance] \
  [--site <site_id>] \
  [--budget-override auto|force_run|disable] \
  [--backlog-secs <u64>] \
  [--deferrals <u32>] \
  [--now <unix_seconds>] \
  [--human]
```

The command reads `<merged-observation.json>` using `O_NONBLOCK | O_NOFOLLOW` with the coordinator response size cap, mutates nothing, and emits a `rustiron-background-budget/1` JSON report (or concise `--human` text).

## Decision hierarchy

Evaluated strictly in order:

1. **Operator override (`--budget-override disable` or `force_run`)**:
   - `disable` returns `run_operator_gate_disabled` (`allow_run: true`, `traffic_gating_active: false`).
   - `force_run` returns `run_operator_forced` (`allow_run: true`).
2. **Critical disk protection for `backup_capture`**:
   - If root filesystem available space is `< 10%`, returns `block_low_disk` (`allow_run: false`) and appends a `backup_blocked_low_disk` record to `missed_jobs` so the failure is never hidden.
3. **D-010 RPO deadline guard for `backup_capture`**:
   - For every active, non-ejected, non-proxy target site, inspects the newest `succeeded` capture.
   - If a site has no succeeded capture or its newest capture is `>= 22 h` old (`79 200 s`), return `run_rpo_override` (`allow_run: true`). This 2-hour margin protects the 24 h D-010 RPO objective regardless of busy traffic.
   - Any site past `24 h` (`86 400 s`) or without a capture is also recorded in `rpo.breached_sites` and `missed_jobs`.
4. **Starvation ceiling**:
   - `site_cron`: `backlog_seconds >= 1800` (30 min) or `consecutive_deferrals >= 6`.
   - `backup_capture`: `backlog_seconds >= 7200` (2 h) or `consecutive_deferrals >= 8`.
   - `maintenance`: `backlog_seconds >= 7200` (2 h) or `consecutive_deferrals >= 12`.
   - When reached, returns `run_starvation_override` (`allow_run: true`).
5. **Stale or missing telemetry fallback**:
   - If `machine.observed_at` is absent, older than `300 s`, or ahead of `--now` by more than `60 s`, returns `run_stale_metrics_fallback` (`allow_run: true`, `traffic_gating_active: false`) and adds `telemetry_stale_or_missing` to `missed_jobs`.
6. **Busy-window deferral (`defer`)**:
   - When telemetry is fresh and any busy threshold is exceeded:
     - `load1_per_cpu > 0.85` (1-minute burst) or `load5_per_cpu > 0.75` (5-minute sustained);
     - `memory_available_percent < 20%`;
     - `disk_available_percent < 15%`;
     - `machine.samples[]` CPU burst spike (`latest >= 70%` and `>= 25` percentage points above recent 15-minute median);
     - optional `machine.traffic.req_per_sec >= 50.0` or `active_connections >= 64`.
   - Returns `defer` (`allow_run: false`), exact `busy_reasons`, and bounded `retry_after_seconds` (`120 s` for `site_cron`, `300 s` for `backup_capture` / `maintenance`).
7. **Normal execution (`run`)**:
   - Observed metrics are fresh and within budget (`allow_run: true`).

## Visibility guarantees

- Every response includes `hides_missed_jobs: false`, `autonomous_db_tuning: false`, `missed_job_count`, and `missed_jobs[]`.
- Unsettled captures left `running` for more than `15 min` are surfaced in `rpo.unsettled_captures` and `missed_jobs[]` so operators never mistake a stuck capture for traffic deferral.
- All thresholds and ceilings are echoed under `policy` and `backlog`.
