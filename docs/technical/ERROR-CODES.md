# Error codes

This page lists the stable error codes of the coordinator read protocol and the executor. For each code, it states what the code means, whether a requester can send the same request again, and what the operator does.

Tests keep this page complete. A test in `crates/contracts/src/error.rs` checks that every `ErrorCode` has a row. A test in `crates/executor/tests/error_codes.rs` checks that every code in `ExecutorError::ALL` has a row. Both tests also refuse a row for a code that does not exist.

Human messages are not a machine contract. Scripts must use the code.

## Retry rules

The "Same request again?" column uses these values:

- **Yes**: the request has no effect, so a retry is always safe.
- **After the fix**: the executor refused before it recorded an intent, so nothing was recorded or changed. After the cause is fixed, the same signed request can be sent again while its grant is valid.
- **Status first**: the code can follow a recorded intent or a lost reply. Query `operation_status` before any retry. A missing row is not proof that a retry is safe ([executor admission](EXECUTOR-ADMISSION.md)).
- **No**: the same request gets the same refusal. The action column gives the next step.

A lost or invalid reply is always **Status first**, whatever the code. The coordinator reports such a submission as `outcome_unknown` and never as a refusal.

## Read protocol (`ErrorCode`)

The coordinator returns these codes on the read protocol. The exit column is the CLI exit status. Reads change nothing, so a retry never causes an effect.

| Code | Exit | Meaning | Same request again? | Operator action |
| --- | --- | --- | --- | --- |
| `INVALID_REQUEST` | 2 | The schema or a parameter is not valid. | No | Correct the request against the [read protocol](READ-PROTOCOL.md). |
| `UNSUPPORTED_VERSION` | 2 | The peer uses a schema version that this build does not support. | No | Use schema version 1, or install matching versions of the CLI and the coordinator. |
| `REQUEST_TOO_LARGE` | 2 | The request is larger than the protocol limit. | No | Send a smaller request. |
| `RESPONSE_TOO_LARGE` | 2 | The response would be larger than the protocol limit. | No | Narrow the query, or use a smaller page limit. |
| `UNAUTHORIZED_PEER` | 3 | The local peer may not make this request. | No | Check the socket permissions and the user that runs the client. |
| `NOT_FOUND` | 4 | The resource is not in the permitted inventory. | Yes | Check the identifier. An inventory refresh can add the resource. |
| `CURSOR_EXPIRED` | 4 | The pagination cursor is no longer valid. | No | Start the list query again from the first page. |
| `DEPENDENCY_UNAVAILABLE` | 7 | A transport or a required service is not available. | Yes | Check the status of the coordinator and the executor, then try again. |

## Executor (`ExecutorError`)

The executor returns these codes in submission replies, receipts, and logs. The admin helper uses the same codes in its replies. A refusal never echoes the refused value.

| Code | Meaning | Same request again? | Operator action |
| --- | --- | --- | --- |
| `EXECUTOR_ACCESS_DENIED` | A trusted location has an unexpected owner, mode, link, or parent. | After the fix | As root, find the path that changed. Treat an unexplained change as possible tampering. Do not loosen a mode to make the check pass. |
| `EXECUTOR_DEPENDENCY_UNAVAILABLE` | The policy, the verifier, the scratch area, or another required part is missing or not usable. | Status first | Check the executor logs and the enrolled files, then query the operation status. |
| `PEER_DENIED` | The kernel peer is not the enrolled requester. | No | Only the enrolled requester user can submit. Check which service called the executor. |
| `INVALID_REQUEST` | The request is malformed, too large, or outside the closed schema. | No | Correct the requester. Do not edit the request by hand. |
| `FIXTURE_BINDING_DENIED` | The plan, the grant, and the enrolled policy do not agree. | No | Sign a new plan against the current enrolled host, epoch, and profile. |
| `GRANT_TIME_DENIED` | The executor has no reliable time, or the time is outside the grant window. An exact repeat after the grant expires also gets this code. | Status first | Check the clock synchronization. An expired grant needs a new signature. |
| `INVALID_SIGNATURE` | The signature, key, namespace, or revocation check failed. | No | Check the signer key and the revocation list, then sign again. |
| `REGISTRY_UNAVAILABLE` | The fixture executor cannot observe its registry completely. | After the fix | Restore the registry folder that the fixture policy names. |
| `PRECONDITION_CHANGED` | The live state is not the predecessor that the plan reported. | Status first | Observe the host again and sign a new plan from the fresh observation. |
| `REPLAY_DENIED` | The grant, nonce, operation, or retry key was already used with other bindings. The enrolled host or epoch can also differ from the open journal. | No | Sign a new plan with new identifiers. Never reuse an identifier for a different plan. |
| `UNRESOLVED_OPERATION` | An unresolved operation blocks new work. | After the fix | Query that operation and reconcile it first. |
| `CLOCK_ROLLBACK` | The reliable time moved backwards since the last recorded intent. | After the fix | Correct the time source. The executor admits nothing until its time passes the last intent. |
| `JOURNAL_CAPACITY` | The bounded replay history is full. The executor never prunes history silently. | No | Rotate the epoch ([manual recovery](MANUAL-RECOVERY.md)). |
| `JOURNAL_STATE_EXISTS` | Initialization found existing journal files and repaired nothing. | No | Inspect the existing journal. Do not delete it; it is the evidence. |
| `JOURNAL_IDENTITY_MISMATCH` | The host or epoch of the stored journal differs from the current enrollment. | After the fix | Restart the executor after a re-enrollment so that it opens the journal of the new epoch ([Runbook 07](../operator/07-EPOCH-READOPTION.md)). |
| `NOT_ADMITTED_FOR_EFFECT` | This executor instance did not record the intent, for example after a restart. | No | Use reconcile. Never assume that the effect did not happen. |
| `COMPENSATION_DENIED` | Compensation needs an attempted effect in `needs_attention` and no earlier compensation. | No | Read the operation status and follow its recorded state. |
| `PROVISION_COLLISION` | A resource that the provision would create already exists. Nothing was changed. | No | Find who owns the existing resource. Choose another name, or adopt the resource. |
| `PROVISION_STEP_FAILED` | A provisioning step or its verification failed. The executor kept the resources it made. | Status first | Read the failed step in the operation status, fix the cause, then reconcile. |
| `OLS_DRIFT` | The live OLS state differs from what the journal and the enrollment explain. Nothing was changed. | No | Explain the drift before any new plan ([drift explanation](DRIFT-EXPLANATION.md)). |
| `RECIPE_ARTIFACT_UNAVAILABLE` | A pinned recipe artifact is not in the trusted store. | After the fix | Put the pinned artifact in the trusted store, with its recorded digest. |
| `ACTIVATION_PROBE_FAILED` | After the switch and reload, a site identity or health probe failed. One restore of the previous generation follows. | Status first | Read the operation status, fix the site, then sign a new plan. |
| `JOURNAL_ROLLBACK` | The journal has fewer admissions than the external mark, or the mark is missing. | No | Rotate the epoch: archive, enroll again, and initialize ([manual recovery](MANUAL-RECOVERY.md)). |
| `ADMIN_HELPER_UNREACHABLE` | The admin helper socket was absent for the whole bounded wait. The executor sent nothing. | Status first | Start the admin helper service, then query the operation status. |
| `RETENTION_LOCK_UNVERIFIED` | The store retention lock was not verified as `COMPLIANCE` for at least 30 days, before or after a capture. | Status first | Set the retention lock on the store, then query the capture status. |
| `OLS_GENERATION_CURRENT` | The activation would render the generation that is already current. | No | No action. The host already has this configuration. |
| `SITE_QUOTA_UNAVAILABLE` | The sites filesystem cannot enforce the enrolled per-site user quota. Nothing was set. | After the fix | Mount the sites filesystem with enforced user quota (`usrquota`). |
| `EXECUTOR_NOT_ENROLLED` | The trusted policy folder has no `policy.json`. The host is installed but not enrolled. | After the fix | Enroll the host ([Runbook 09](../operator/09-PRODUCT-ENROLLMENT.md)). |
| `READOPT_MISMATCH` | A fact that the re-adoption verified does not agree with the signed plan or the enrolled policy. The re-adoption is recorded as refused. | No | Find which fact differs, then sign a new plan. |
| `STANDING_WINDOW_CLOSED` | No window of the standing grant is open, or the open window is not the window of the requested run. | No | The scheduler sends the next run in its own window. |
| `STANDING_RUN_MISMATCH` | The operation ID and the retry key are not a run that the standing grant derives. | No | Report a scheduler defect. Do not sign a replacement by hand. |
| `ACTIVATION_ROLLBACK_FAILED` | An activation failed, and the restore of the previous generation also failed. The live state is not known. | No | Follow [manual recovery](MANUAL-RECOVERY.md). The journal never records this operation as rolled back. |
