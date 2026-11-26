# Implemented read protocol v1

2026-10-24.
S01/W002 implements the unprivileged contract subset of [SPEC.md](SPEC.md), requirements R01/R02/R15.
The contracts crate parses and formats data.

W003 adds the [Linux local IPC helpers and coordinator/CLI](LOCAL-DEVELOPMENT.md), which inspect accessible OS metadata with a same-UID development policy.
Inventory persistence is now implemented by [W004](COORDINATOR-INVENTORY.md).
None of this grants mutation authority.

## Requests and limits

Use `rustiron_contracts::decode_request` / `encode_request` for wire bytes.
The envelope is a named JSON object with exactly `schema_version`, `request_id`, `method`, `params`.
Version is the integer `1`.

Unknown envelope/parameter members, methods and duplicate decoded JSON keys are rejected.
This includes escaped aliases such as `method` and `\u006dethod`.
Parameters must be objects.

| Method | Parameters | Successful data kind |
| --- | --- | --- |
| `doctor` | `{}` | `doctor` |
| `site_list` | `limit` integer 1–100; optional `cursor`, null or opaque ID | `site_list` |
| `site_inspect` | `site_id` opaque ID | `site_inspect` |
| `operation_status` | `operation_id` opaque ID | `operation_status` |

An ID is 1–64 ASCII bytes, letters/digits/underscore/hyphen only.
It is not a path, trusted resource record or permission.
A cursor is an opaque transport token.
W004 must bind and validate traversal state and report expired tokens.

| Bound | Value |
| --- | --- |
| Request JSON bytes, including whitespace | 262,144 |
| Response JSON bytes, including whitespace | 1,048,576 |
| Nested containers, including outer object | 32 |
| Display text per field | 512 UTF-8 bytes |
| Site records per page | 100 |
| Error detail strings | 8, each bounded as display text |
| UTC Unix timestamp seconds | Integer 0–9,007,199,254,740,991 |

The codec checks byte limits before parsing, scans decoded keys/depth without building a generic value tree, then decodes typed data.
Trailing input, malformed UTF-8 and positional arrays in place of named records are invalid.
Serialization is deterministic for these models, but is **not signed-plan canonicalization**.
Listener framing/connection limits must be enforced before buffering payloads; the W003 local IPC helpers implement that boundary separately from these codecs.

## Responses and observations

Use `decode_response` / `encode_response` for bounded wire envelopes.
Required members are `schema_version`, `request_id`, `status`, `data`, `error`.
Status is `ok` with non-null data and null error, or `error` with null data and non-null error.

Successful responses require an ID.
Errors may use null when request decoding could not establish one.
The client must correlate the ID and successful data kind to the outstanding method.

The codec alone cannot do that.

Successful `data` has `kind` and object `value`.
Response readers tolerate additive fields, but still reject duplicates, unknown enum variants, invalid known fields and bound violations.
They do not silently invent required fields.
A page requires `next_cursor`, explicitly null at end.
Omission is invalid.

Doctor reports `os_name`, `os_version`, `kernel_release`, and `architecture` observations.
W003 adds `hosting_profile` and `site_confinement`.
Those observations remain unknown until their acceptance checks exist.

New readers default those two to unknown/not_checked when older v1 responses omit them.
Site pages contain `items` of `site_id`, `name`, `ownership`.
Site inspection contains `site` and `configuration_generation`, an observation of a generation ID.

Ownership is `created`, `explicitly_adopted`, `observed_only` or `unknown` and never grants executor authority.
W004 report imports always produce observed_only.
Their additive `inventory` object contains `reported_at` and `source: operator_report`; older v1 rows may omit it, which means unknown provenance.

Named objects are required.
Known reported generations are inferred when the report time is within 300 seconds, and stale after that.
They are not host-verified values.

The original report time is kept.
Operation status reports an executor-recorded operation ID and state, not a fresh host observation.
A missing operation alone does not prove a retry safe.

Each observation has a `state`:

- `observed`, `inferred`, `stale`: bounded `value`, integer `observed_at`, `source`.
- `unknown`: `reason`. No usable value is asserted.

Sources: `os_release`, `kernel`, `inventory`, `profile`.
Unknown reasons: `not_checked`, `permission_denied`, `unavailable`, `unsupported`.
Stale values retain their original timestamp.
A profile inference is not live host evidence.

## Public errors and rendering

Errors contain `code`, bounded `message`, `retryable`, null `operation_id` and bounded `details`.
The `operation_id` member is required even when null; [W160](../validation/S10-W160/README.md) fixes generic decoding that previously defaulted an omitted member.
Read operations cannot claim an admitted mutation.

Generated errors default to `retryable: false`, no details and fixed actionable messages.
Human messages may evolve.
Codes and documented fields are the machine contract.

| Code | CLI exit class |
| --- | --- |
| `INVALID_REQUEST` | 2 |
| `UNSUPPORTED_VERSION` | 2 |
| `REQUEST_TOO_LARGE` | 2 |
| `RESPONSE_TOO_LARGE` | 2 |
| `UNAUTHORIZED_PEER` | 3 |
| `NOT_FOUND` | 4 |
| `CURSOR_EXPIRED` | 4 |
| `DEPENDENCY_UNAVAILABLE` | 7 |

The CLI applies these mappings.
W004 now returns NOT_FOUND and CURSOR_EXPIRED from its reported inventory.
Absent/unobserved stores return dependency-unavailable.

Success exits 0.
Malformed/duplicate/deep/schema-invalid messages map to `INVALID_REQUEST`; supported-range unknown integer versions map to `UNSUPPORTED_VERSION`.
Out-of-range or incorrectly typed version numbers are invalid schema input.

Size errors keep their distinct codes.
Raw parser errors/input are not reflected in public diagnostics.
Later signature/operation errors remain planned in SPEC.

`render_human` rechecks response invariants and escapes controls, newlines and bidirectional formatting in display text.
JSON output preserves text as JSON data.
Neither path is a generic credential detector: producers must select and redact approved metadata before constructing records.
Do not log raw requests, parser context, tenant files or tool stderr.
No transport/tool-output redaction claim follows from the parser-canary test.

## Checkpoint A example and evidence

The [doctor request](../../crates/contracts/tests/fixtures/doctor-request.json), [JSON result](../../crates/contracts/tests/fixtures/doctor-response.json) and [human result](../../crates/contracts/tests/fixtures/doctor-response.txt) are checked golden fixtures.
They are synthetic, including timestamps and OS values; they are not observations of the development host or VM.

```text
Host inspection (read-only)
OS name: AlmaLinux [observed; source=OsRelease; unix_seconds=1]
OS version: unknown (NotChecked)
Kernel: fixture-kernel [stale; source=Kernel; unix_seconds=1]
Architecture: x86_64 [inferred; source=Profile; unix_seconds=2]
Hosting profile: unknown (NotChecked)
Site confinement: unknown (NotChecked)
```

Run `rust-tc quick` or `rust-tc doctor` from the project root to reproduce the golden comparisons and adversarial contract corpus.
See [W002 gate receipt](../validation/S01-W002/rust-gates.json) and [campaign limits](../planning/VALIDATION.md).
This is partial T01/T02/T13 contract evidence.
Socket peers, deadlines, host effects and live canary credentials are not tested by these fixtures.
W003 supplies separate real local IPC evidence, with its distinct-UID and host-proof limitations recorded in the local development guide.
