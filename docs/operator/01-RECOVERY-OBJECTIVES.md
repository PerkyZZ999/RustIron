# Recovery objectives

Accepted under D-010 on 2026-10-26, America/Toronto.
The targets are experimental measurement targets, not customer commitments.
Do not ask the owner to accept the same defaults again.

| Objective | Accepted target | Measurement |
| --- | --- | --- |
| RPO | 24 h | Age of the newest usable independent copy, including copy lag |
| Site RTO | 4 h | Host loss to verified serving, including keys, replacement host, restore, and checks |
| Host RTO | 8 h | The same outcome for every selected site |
| Locked retention | 30 days, compliance | Destination enforcement and deletion/retention-denial evidence |
| Capture schedule | 03:00 America/Toronto, daily | Capture plus independent-copy completion and missed-job detection |

## Scheduled capture

[D-035](../decisions/D-035-scheduled-capture.md) implements the capture schedule with a standing capture grant.
One signed grant authorizes `backup_capture` only, for named sites, in at most 35 fixed windows.
The timer `rustiron-scheduled-capture.timer` starts each run at 03:00 America/Toronto. The executor admits one run for each site in each window.
The check `rustiron-scheduled-capture-check.timer` reports missed windows and the snapshot age every hour.
[13-SCHEDULED-CAPTURE](13-SCHEDULED-CAPTURE.md) gives the operator steps.

[W386](../validation/S10-W386/README.md) measures the local RPO on a throwaway product host with a compressed schedule.
The local RPO is the age of the newest local snapshot at a simulated loss. The local RPO is not the independent-copy RPO of the table above.
On the November daylight saving change, one snapshot age is 25 h, because the window is fixed in UTC.

The custody procedure proposes a 6-month drill and a new drill after key changes.
That procedure needs actual execution evidence.

## Evidence limits

[W037](../validation/S09-W037/README.md) records 47 s for a local VM recovery.
[W036](../validation/S09-W036/README.md) records about 19 s in a container.
Those results exclude outage detection, physical key retrieval, replacement-host acquisition, and production routing.
Those results do not pass independent RPO/RTO acceptance.

## Acceptance

Measure from recovered custody and an independent copy.
Record source loss, snapshot age, copy lag, phases, host/storage identity, content/DB checks, and total duration.
Use the record template in step 30 of the [manual recovery guide](../technical/MANUAL-RECOVERY.md).
Step 1 of that guide records the start of the guide work.
Use a recovery runner without source-host or implementation context.

The manual recovery guide has no production web-server recipe.
Its test-only verification server lets a lab recovery pass step 28. Production serving stays unverified.
The site RTO ends at step 29, immediately after step 28 passes. The total runs from source loss to step 29.
Record the replacement-host acquisition and the web-server phase as separate times.

[D-026](../decisions/D-026-defer-offsite-and-escrow.md) defers independent-copy RPO and RTO measurement until after v1.0.

Another human guide follower is optional under D-018.
If measured recovery misses a target, record the failure and reopen D-010 with evidence.
The [roadmap](../planning/ROADMAP.md) owns the dependent task.
