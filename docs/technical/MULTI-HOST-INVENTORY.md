# Read-only multi-host inventory without distributed implicit authority (P28 Slice 1)

**Status:** Slice 1 lab verified ([W618](../validation/S10-W618/README.md)); P28 remains Partial until remote multi-host transport (P18) and separate multi-host write scope decisions are accepted.
**Scope:** Strictly read-only multi-host observation aggregator in `rustiron-control --aggregate-hosts`.

## Purpose

Multi-host operation must begin with read-only inventory aggregation and must never weaken single-host isolation or introduce implicit distributed authority. Every host remains an independent authority domain with its own:

- `host_id` and `host_epoch` (`signer_epoch`);
- local SQLite executor journal and exclusive admission locks (`per_host_lock_scope: "local_executor_journal_only"`);
- per-host signed approvals (a grant for host A can never authorize host B);
- independent backup and restore authority (`independent_restore_authority: true`).

Single-host Rustiron remains completely usable standalone (`single_host_standalone_preserved: true`).

## Command interface

```sh
rustiron-control --aggregate-hosts <fleet-observations.json> [--now <unix_seconds>] [--human]
```

Reads `<fleet-observations.json>` (`rustiron-fleet-observations/1`) using `O_NONBLOCK | O_NOFOLLOW` and bounded size, mutates nothing, and outputs a `rustiron-fleet-inventory/1` report.

## Enforced invariants

1. **No distributed implicit authority (`distributed_implicit_authority: false`)**:
   - Pending grants attached to a host entry are checked against that host's verified `host_id` and observed `host_epoch`. Any cross-host grant is marked `cross_host_approval_refused` (`eligible_for_host: false`), and any epoch mismatch is marked `epoch_mismatch_refused`.
2. **No false fleet-wide transaction (`fleet_wide_transaction: false`)**:
   - Partial failures, partitions, and credential revocations are reported per host without synthesizing an atomic multi-host commit.
3. **No blind replay across partitions (`blind_replay_on_partition: false`)**:
   - Partitioned or timed-out hosts report `outcome_certainty: "unknown_partitioned"` and `safe_to_blind_replay: false`, refusing pending grants until connectivity returns and operations reconcile by `operation_id`.
4. **Identity, staleness, revocation, and version skew visibility**:
   - Flags `host_identity_mismatch` when manifest `host_id` differs from the host's own observation `host.host_id`, and `duplicate_host_id_conflict` when a `host_id` appears twice.
   - Surfaces `revoked_credential` hosts separately from network partitions.
   - Flags observations older than `300 s` (or skewed `> 60 s`) as stale.
   - Reports `version_skew.detected: true` whenever reachable hosts run different executor journal versions.
