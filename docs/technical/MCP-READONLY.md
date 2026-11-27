# Read-only workstation-local MCP adapter (P17 / D-101)

Updated: 2026-11-24, America/Toronto.
Decision: [D-101](../decisions/D-101-readonly-local-mcp.md).
Roadmap: [P17](../planning/ROADMAP.md#p17--expose-read-only-workstation-local-mcp).

`rustiron-mcp` exposes Rustiron's existing read-only coordinator queries and offline plan decoders over local `stdio` JSON-RPC 2.0 MCP.

## 1. Security boundary & threat model

| Threat | Defense enforced in `crates/cli/src/mcp.rs` |
| --- | --- |
| **Authority escalation / silent mutation** | Zero mutating tools compiled or registered; `plan_apply` is absent; unknown tool names fail with JSON-RPC `-32602 UNKNOWN_OR_DISALLOWED_TOOL`. |
| **Network exposure** | Strictly `stdin`/`stdout`; opens zero TCP/UDP/HTTP listeners. |
| **Prompt injection in site names, logs, or plan limitations** | Every tool output is wrapped in `{"authority":"none_read_only","untrusted_data":true,"result":...}`; human text fields pass `escape_human` to strip/escape ASCII control and terminal-escape sequences; MCP `instructions` explicitly warn clients to treat returned values as untrusted data. |
| **Unbounded memory / malformed JSON-RPC** | `read_bounded_line` caps every incoming line at `262,144` bytes (`-32600 REQUEST_TOO_LARGE`); malformed JSON returns `-32700`; wrong JSON-RPC version returns `-32600`; unknown methods return `-32601`; unknown tool fields rejected by `#[serde(deny_unknown_fields)]`. |
| **Stalled line** | A client may idle between requests. Once a line has begun, its newline must arrive within 30 seconds; otherwise the server answers `-32600 LINE_DEADLINE` and ends the session ([W692](../validation/S10-W692/README.md)). |
| **Path traversal & peer spoofing** | All IDs validated via `rustiron_contracts::Id` (`1..=64` ASCII `[A-Za-z0-9_-]`); coordinator socket checked via `local::connect` (absolute canonical path, `0700` dir, `0600` socket, `SO_PEERCRED` same non-root UID); errors return fixed `ErrorCode` names without echoing raw paths. |

## 2. Read-only tool catalogue

| Tool name | Backing contract | Arguments |
| --- | --- | --- |
| `rustiron_doctor` | `ReadCommand::Doctor` | `{}` |
| `rustiron_site_list` | `ReadCommand::SiteList` | `{ "limit"?: 1..=100, "cursor"?: string \| null }` |
| `rustiron_site_inspect` | `ReadCommand::SiteInspect` | `{ "site_id": Id }` |
| `rustiron_operation_status` | `ReadCommand::OperationStatus` | `{ "operation_id": Id }` |
| `rustiron_evidence_export` | `ReadCommand::EvidenceExport` | `{ "operation_id": Id }` |
| `rustiron_plan_inspect` | `plan_summary::describe` (offline) | `{ "plan_json": string }` |
| `rustiron_plan_envelope` | `approval::envelope_for_plan` (offline) | `{ "plan_json": string }` |

## 3. Usage

```sh
rustiron-mcp --socket /run/user/$(id -u)/rustiron/control.sock
```

Offline-only plan inspection and blast-radius envelope checks also work without `--socket`:

```sh
rustiron-mcp
```
