# S02 fixture journal/admission design

2026-10-24.
W011 focused design.
Implementation and enforcing root integration remain pending.
Accepted D-004/D-005 require independent authority checks and one durable admission before effects.
This design does not change those locks.

W012 will first implement/test an **unprivileged fixture ledger library** with real SQLite and processes.
It is storage/consistency proof, not a root executor or authorization service.
Offline review receipts are untrusted input to the future root boundary.
They cannot bypass signature, custody, peer, policy, clock, ownership, resource or live-precondition checks.

| Concern | Fixture contract / required test |
| --- | --- |
| Explicit lifecycle | initialize only a new empty private directory; open requires an existing valid ledger; missing/corrupt/newer state never becomes empty history |
| Sole writer | Owner-only directory/files plus lifetime process flock; second process refuses; no waiting on transport while holding admission lock |
| Native tuple | Verified official SQLite 3.54.1/source ID, private static build, no system-library fallback acceptance |
| Durability | DELETE rollback journal, synchronous=EXTRA, foreign_keys=ON, trusted_schema=OFF; read back settings, bounded 250ms busy timeout |
| Schema | Dedicated application/user/schema IDs, exact reviewed DDL, STRICT tables and typed row checks; no automatic repair or migrations |
| Admission | One transaction binds immutable grant ID/nonce, idempotency key/digest, operation/resource/host epoch, expected and target generation/hash, and intent; commit error returns no new authority |
| Replay | Same key and identical immutable binding returns stored status; changed digest/binding conflicts; consumed nonce/grant cannot mint a second operation |
| Serialization | At most one unresolved intent or needs_attention operation; concurrent submissions cannot reserve two mutations |
| Time/epoch | Independent caller must verify trusted time and root epoch; fixture ledger persists last accepted time and rejects rollback; exact completed replay may retrieve status after expiry without repeating effects |
| Observations | Only complete matching target generation/hash may be recorded as succeeded; proven matching predecessor can be recorded untouched; other/unknown observations become needs_attention; only succeeded establishes a generation, and untouched or compensated keeps the earlier one (W360) |
| Restart | Persisted intent remains potentially effected and blocks new work; never convert it to untouched/success automatically; fixed future observers must reconcile reality |
| Failure | Failed commit/sync, read-only/corrupt DB, schema mismatch or ambiguous state denies admission; preserve existing records and blocks |

The future executor must independently validate all W009/W010 bindings and re-observe trusted registry/generations before constructing a journal admission.
A storage method accepting typed fixture data does not prove the caller did this.
A recorded observation is a caller report until integrated with a fixed enforcing observer.
Tests and documentation must retain this distinction.

The first fixture has one effect/step.
Actual host operations and additional steps still need durable per-step intents/budget consumption, external effects outside DB transactions, verification and terminal commit.
SQLite cannot make filesystem, OLS, database and external storage one atomic transaction.

W012 local process/transaction/crash tests may prove ledger persistence and refusal only.
They cannot prove power-loss/fsync behavior of the AlmaLinux disk, real root ancestry races, effective runner confinement, real signer separation or recovery from a rolled-back VM.
Those remain mandatory before S02/G1 and live promotion.
Restored authority history requires independently rotated host/ policy epochs.
A journal cannot detect its own coherent historical rollback.
