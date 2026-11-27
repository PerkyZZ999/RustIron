# Executor admission candidate (W014a)

W014a–W057 mechanism history, with current scope noted for 2026-11-03.
`crates/executor` (`rustiron-executor`) composes the pre-journal checks the S02 fixture executor must make itself.
At W014a, the library had no binary, installation, effect, intent, or nonce consumption.

Later sections describe durable execution.
W168 records the deployed lab candidate.
This is not a supported product install.

Test signatures prove cryptographic behavior, not independent human approval ([S02 lab review](S02-LAB-REVIEW.md)).

## `admit(anchor, request)` order

1. Open the policy directory from `/` one component at a time with
   `O_NOFOLLOW`.
Ancestors must be root/owner-owned and not group/other-writable (sticky ancestors such as `/tmp` excepted).
The final directory is owner-only.
2. Read `policy.json` (canonical closed schema v1), `allowed_signers` (exactly
   one plain Ed25519 key for the enrolled issuer and namespace `rustiron-plan-v1`) and `revocations`.
Each is a single-link owner-only file.
3. Compare the kernel peer UID with the enrolled `requester_uid`. The request
   cannot name its own requester.
4. Decode the closed plan and grant and check their binding against enrolled
   host, epoch, profile, requester, issuer and signer-policy epoch, with reliable time inside the grant window.
5. Verify the SSHSIG over the exact canonical grant bytes with
   `/usr/bin/ssh-keygen`, whose root ownership and enrolled SHA-256 are checked first.
Inputs go to a fresh owner-only scratch directory that is removed.
6. Re-observe the registry: `<registry>/<resource_id>/current` must be a symlink
   whose text is exactly `generations/<Id>`.
That generation's `content` must be a single-link owner-owned file that only the owner can write.
Generation and content digest must both equal the plan's reported predecessor.
7. Return a journal `Intent` built from enrolled and observed values.

`TrustAnchor.owner_uid` exists so tests can run unprivileged.
The lab binary must fix it to 0 and compile its paths in.
Errors are the stable codes in `ExecutorError::code`, listed with their retry rule and operator action in [error codes](ERROR-CODES.md).
No rejected value is echoed.

## Durable admission (W014b)

`Executor::initialize` / `Executor::open` require real and effective UID to equal `owner_uid`.
The constructors reject setuid mixtures and check descriptor-safe journal ancestry.
They read enrolled host/epoch from policy and open the journal with `FixtureJournal::*_as_process_owner`.
The original `FixtureJournal::initialize`/`open` still refuse root.
Only these executor constructors accept it, and the owner is the actual process identity, never a caller-chosen UID.

`Executor::submit` runs `admit` and then `record_intent` in one SQLite transaction.
`New` means grant, nonce, operation and retry key are consumed and intent is durable.
It is still not evidence of any effect.

An exact repeat returns `Existing` (status only).
Additional codes: `REPLAY_DENIED`, `UNRESOLVED_OPERATION`, `CLOCK_ROLLBACK`, `JOURNAL_CAPACITY`, `JOURNAL_STATE_EXISTS`, `JOURNAL_IDENTITY_MISMATCH`, `JOURNAL_ROLLBACK`.
A denied admission records nothing.

Policy is re-read per submission.
A rotated epoch fails at the journal.
Every signed verb compares the enrolled host and epoch with the open journal right after its verification. The verbs are the fixture verb, `site_provision`, `config_activate`, `site_eject`, `site_readopt`, the lab `backup_capture` and `restore_probe`, and the two product backup verbs. A difference gives `JOURNAL_IDENTITY_MISMATCH` before intent and before the replay check. Thus a policy re-enrolled without an executor restart never gets `REPLAY_DENIED` ([W377](../validation/S10-W377/README.md), [W380](../validation/S10-W380/README.md)).

**Admission high-water mark (W048, review F-01).** After each committed admission, the executor fsyncs the journal's admission count to `admission-mark` in `mark_dir`.
The count includes all operation, provision, capture, and probe rows; those rows are never deleted.
`mark_dir` is root-only and outside the journal directory.
Open and every admission refuse `JOURNAL_ROLLBACK` in these cases:
- the journal is behind the mark for its host and epoch (an older copy was
  restored);
- the mark is missing;
- `initialize` is asked for a fresh journal in an epoch that already admitted
  work.

A journal ahead of the mark (a crash between the two writes) is accepted, and the mark catches up.
Recovery is an epoch rotation.
The admin command `seal-admission-mark` writes a first mark only where none exists for the host/epoch.
A whole-host revert rolls the mark back as well.
That case is not detected ([W048](../validation/S10-W048/README.md)).

**Decision: replay before the fence (W380, O1 of [W377](../validation/S10-W377/README.md#o1-replay-before-the-fence)).** Keep the current order.
Every verb answers an exact replay from the journal before the admission-mark check.
Only an admission checks the mark, and a status query checks it too.
The reasons are these:
- The executor fences the journal at `open`. While it runs, only the executor writes the journal and the mark. Thus a journal behind the mark at run time needs root to change the mark file while the executor runs. Root on the host is outside this boundary (W048).
- A replay answer creates no intent, consumes nothing, and starts no effect. A new admission after a replay still checks the fence and gets `JOURNAL_ROLLBACK`.
- A refusal reply never carries stored status from a journal behind the mark, because `stored_for_peer` checks the fence. The W377 product matrix shows `REPLAY_DENIED` with the stored status withheld.
- A fence check on each replay adds a mark read to the status path and changes no outcome that a non-root peer can cause.

The owner's standing instruction is to take the recommended option. This paragraph records that choice. A change needs a new task.

## Effect and observer (W014d)

`Executor::execute(operation_id, now)` runs only for an intent that this executor instance recorded as `New`, and only once.
After a restart it returns `NOT_ADMITTED_FOR_EFFECT` and never infers that an effect did not happen.
Under the journal writer lock it then:

1. records an observation and refuses with `GRANT_TIME_DENIED` if time is
   unknown or at/after grant expiry;
2. re-observes the registry and refuses with `PRECONDITION_CHANGED` unless
   generation and digest both still equal the recorded predecessor;
3. refuses before any write unless the enrolled target generation's content
   digest equals the bound artifact digest;
4. creates `current.next-<random>` with `symlinkat`, `renameat`s it over
   `current` and fsyncs the resource directory.
No path comes from the request;
5. observes again and records `succeeded`, `untouched` or `needs_attention`.

Every path after admission ends in a recorded observation.
`Executor::reconcile` records the executor's own observation for an unresolved operation (for example after a crash) and never performs or repeats an effect.
Observations record reality: if `current` already equals the target, the state is `succeeded` even when this call refused.

## Socket front end (W014e)

The lab-only binary `rustiron-s02-executor` has `initialize` and `serve` commands.
`initialize` creates the journal once.
`serve` binds a fresh socket. Since W184 it reads request frames concurrently: at most 32 connections at once and 4 for each peer UID. A connection over either limit gets `EXECUTOR_DEPENDENCY_UNAVAILABLE` at once. The single thread that owns the executor processes complete frames one at a time, in arrival order. Thus the executor stays the sole journal writer. The limits only bound availability: who may submit, signatures and journal rules are unchanged.

W168 records lab installation.
Its paths are compiled constants from the [W013 manifest](S02-LAB-REVIEW.md#reviewable-lab-scope-and-proposed-manifest): policy `/etc/rustiron-s02-lab`, registry, scratch and journal under `/var/lib/rustiron-s02-lab/`, socket `/run/rustiron-s02-lab/executor.sock`.
The owner is fixed to root.

The socket directory must be owner-owned and not group/other-writable.
The socket is mode 0660 with the service's group (`rustiron-s02-requesters` in the lab unit, directory 0750), and bind never removes an existing entry.
**Who may submit is decided only by the kernel peer UID** (`SO_PEERCRED`) matching the enrolled `requester_uid`.

Frames reuse the local length-prefix + EOF framing and the five-second deadline.
The request is the closed `contracts::execution` submission v1 (`schema_version`, `operation_id`, `idempotency_key`, `plan` and `grant` objects, armored `signature`), at most 256 KiB in total.
The reply is `SubmissionReply` (`operation_id`, `state`, `replay`, `error`).
[D-032](../decisions/D-032-power-cut-serving-and-reply-states.md) adds the state `failed` for a failed capture and the optional `unclaimed_snapshot_id`, which only a `failed` reply carries. A failed restore probe keeps `untouched`.

A new admission is executed immediately.
A verified exact repeat returns stored status (`replay: true`) before the live check, because a completed effect has moved the predecessor.
After expiry, a repeat gets `GRANT_TIME_DENIED`.

Executor time is the system clock, which is a lab assumption and not proven.

`rustiron-submit` is the unprivileged requester client.
The client checks the expected executor peer UID, default 0, then sends one submission.
Exit codes are:

| Exit | Meaning |
| --- | --- |
| 0 | `succeeded` |
| 5 | `untouched`, `failed`, or refused effect |
| 6 | `intent`/`needs_attention` |
| 2 | Malformed request |
| 3 | Authorization denial |
| 4 | Known precondition conflict, also an `untouched` or `failed` operation that `OLS_DRIFT` or `PRECONDITION_CHANGED` refused after intent (W360, D-032) |
| 7 | Dependency, unknown refusal, or transport failure |

W063 corrects the older all-refusals-as-3 mapping.
Since W055, it checks the bounded reply's version, fields, duplicate keys, error-code shape and operation identity before using the result.
[W160](../validation/S10-W160/README.md) restores additive executor reply compatibility, including nested apply replies.

Required fields and known outcome/correlation checks remain enforced.
An invalid reply returns 7: the admission outcome may be unknown, and the caller must query status before retrying.
This validation does not add a product coordinator or a requester-side status query.

W056 adds a separate `operation_status` query with a versioned request ID and an operation ID.
The enrolled socket peer, host/epoch and admission mark are rechecked before reading the journal.
It returns only recorded state or a fixed error, and does not execute or authorize work.

A missing row is not proof that a disconnected submission is safe to retry.
The shared decoder correlates both IDs.
See [W056](../validation/S10-W056/README.md).

W058/W062 later connect the coordinator and CLI to this endpoint.

[W057](../validation/S10-W057/README.md) adds a coordinator library transport for signed submissions and status.
The transport checks socket ownership, permissions, and root peer identity.
The transport bounds frames and waits.

A lost reply after sending yields an unknown outcome.
It does not sign, retry, or expose an operator method.
W092–W095 provide dated live transport evidence.

Complete product acceptance remains open.

## Compensation (W014f)

`execute` now commits `effect_attempted` before the switch.
`Executor::compensate (operation_id, now)` performs the single signed `fixture_restore_v1`: only for an attempted effect now in `needs_attention`, before the grant's `compensation.valid_until`, with known time and no clock rollback.
The attempt is committed before the restore switch, so it never runs twice, even across restarts.

The result is recorded from observation (`failed_compensated` when the complete predecessor is restored).
Refusal code: `COMPENSATION_DENIED`.
Drift without an attempted effect cannot be "compensated".

Compensation is a library/admin action and is not offered on the requester socket.
The lab binary exposes it as `rustiron-s02-executor compensate OP`, next to `status OP` and `reconcile OP`.
Run them with the unit stopped (the writer lock refuses a second process).

Crash points (`Fault::AfterAttemptMark`, `AfterSwitch`, `AfterCompensationMark`) exist only with the test-only `fault-injection` feature, enabled through the crate's own dev-dependency.
Normal builds of the lab binary do not include it (`cargo tree -e features,normal` shows no `fault-injection`).

The OLS activation has four crash points ([W380](../validation/S10-W380/README.md)): `AfterOlsIntent`, `AfterOlsEffectMark`, `AfterOlsServing`, and `AfterOlsRestoreMark`.
After a restart, `reconcile` records a running activation `untouched` only after a reload and a passing verification of the predecessor.
A target found as `current` stays `needs_attention` until the one signed restore.
A bootstrap activation that stops before its effect mark, or after its restore mark, stays `needs_attention` and blocks the OLS resource. W380 records this as an open issue.

## Not done here

W014 and W168 record lab installation and systemd restrictions.
Fault injection inside the rename, T04 races, and T05 power-loss acceptance remain open. fsync is issued but its durability is unproven without a power-loss test.
