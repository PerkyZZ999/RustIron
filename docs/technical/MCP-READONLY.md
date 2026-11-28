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
| `rustiron_host_summary` | `ReadCommand::HostSummary` (D-104), host facts, site states, counts | `{}` |
| `rustiron_certificate_status` | `ReadCommand::HostSummary`, certificates only | `{}` |
| `rustiron_backup_status` | `ReadCommand::HostSummary`, newest capture and probe per site | `{ "site_id"?: Id }` |
| `rustiron_diagnoses` | the fixed `/usr/libexec/rustiron/rustiron-control --host-status --diagnose` (D-107: empty environment, 30 s, 1 MiB) | `{}` |
| `rustiron_plan_inspect` | `plan_summary::describe` (offline) | `{ "plan_json": string }` |
| `rustiron_plan_envelope` | `approval::envelope_for_plan` (offline) | `{ "plan_json": string }` |
| `rustiron_plan_draft` | `plan_create::run` through `plan_draft` (offline, D-105) | `{ "verb": string, "flags"?: object }` |
| `rustiron_plan_draft_help` | the `plan create` clap help (offline) | `{ "verb"?: string }` |

## 2a. Protocol, resources, and prompts (W784, D-106)

- `initialize` answers with the client's requested revision when it is `2025-06-18`, `2025-03-26`, or `2024-11-05`, and with `2025-06-18` otherwise. Capabilities: `tools`, `resources` (no subscribe, no list changes), and `prompts`.
- Every tool has a `title` and an `outputSchema` for the `structuredContent` frame (`authority`, `untrusted_data`, `result`).
- `resources/list` and `resources/read` serve the 26 Docs & KB guides and the glossary, compiled in from `console/kb/`, as `rustiron://guides/<slug>` (`text/markdown`). Only those exact URIs are read; anything else is `UNKNOWN_RESOURCE`. `resources/templates/list` is empty.
- `prompts/list` and `prompts/get`: `health_check`, `investigate_site`, `backup_readiness`, `prepare_change`, and `follow_change`. ID arguments are validated as IDs; free text is at most 2,000 bytes and escaped; unknown arguments are refused.

## 3. Usage

```sh
rustiron-mcp --socket /run/user/$(id -u)/rustiron/control.sock
```

Offline-only plan inspection and blast-radius envelope checks also work without `--socket`:

```sh
rustiron-mcp
```

## 4. On a host, over SSH (W776, W777)

The product installs the server as `/usr/libexec/rustiron/rustiron-mcp` (`bin_t`, not on `PATH`) and the rule `/etc/sudoers.d/rustiron-mcp` (`0440`):

```text
%rustiron-agents ALL=(rustiron-coordinator) NOPASSWD: /usr/libexec/rustiron/rustiron-mcp --socket /run/rustiron-coordinator/control.sock
```

- The `rustiron-agents` group comes from the product's sysusers file and has no members. The operator adds one SSH account with `usermod -aG rustiron-agents ACCOUNT`.
- Because sudoers matches the exact argument list, the account cannot add `--write-tier`, choose another socket, or run any other command as `rustiron-coordinator`.
- The workstation agent starts it with `ssh -T ACCOUNT@HOST sudo -n -u rustiron-coordinator /usr/libexec/rustiron/rustiron-mcp --socket /run/rustiron-coordinator/control.sock`.
- The update refuses to replace an existing `/etc/sudoers.d/rustiron-mcp` that the install record does not name; delete a hand-written copy first. The uninstaller removes the rule and the group.
