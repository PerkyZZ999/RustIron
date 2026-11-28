---
title: "Connect an AI agent"
description: "Install the RustIron MCP server and connect your AI agent to it, on your computer or over SSH."
category: "agents"
order: 12
readMinutes: 5
runbooks: ["Runbook 38"]
keywords: ["mcp","connect","claude code","claude desktop","ssh","sudo","rustiron-mcp","agent","setup","install"]
consoleLinks: [{"to":"/settings","label":"Settings"}]
---

## Two ways to connect {#modes}

The MCP server, rustiron-mcp, talks to your agent through its standard input and output. You choose where it runs:

- On your own computer, without the server: the agent can read and explain plan files, but it cannot see the server.
- On the server, started by your agent over SSH: the agent can also check the server's health, your sites, changes, and evidence.

## Get the MCP server {#install}

RustIron installs rustiron-mcp on the server as /usr/libexec/rustiron/rustiron-mcp, starting with the first release after 0.2.0, and its updates keep it current. On an older server, or to run it on your own computer, build it in your RustIron source folder, on the same kind of system where you build RustIron itself.

```sh title="Check that the server has it" where="Server (root)"
ls -l /usr/libexec/rustiron/rustiron-mcp
```

```sh title="Build the MCP server from the source" where="Build / maintainer"
cargo build --release --locked --bin rustiron-mcp
```

## Let one account start it {#sudo}

On the server, rustiron-mcp must run as the coordinator's account to read its socket. RustIron installs a sudoers rule, /etc/sudoers.d/rustiron-mcp, that lets members of the rustiron-agents group start exactly this one command, and nothing else. The group is empty until you add the account you use for SSH. The examples use agentops; replace it with your SSH user name. Do not use the name operator: on AlmaLinux it is a built-in system account.

- Use an account that has no other sudo rights, and an SSH key that is only for your agent.
- To take the access away again, remove the account from the group: gpasswd -d agentops rustiron-agents.
- If you wrote /etc/sudoers.d/rustiron-mcp yourself from an earlier version of this guide, delete it before you update RustIron. The update refuses to replace a file it did not install.

:::note[Only this command]
The rule lets the account start rustiron-mcp, read-only, with this exact socket and no other options, so the account cannot turn on the approved-write mode. It does not give the account any other rights.
:::

```sh title="Let the SSH account start the MCP server" where="Server (root)"
useradd -m agentops
usermod -aG rustiron-agents agentops
sudo -l -U agentops
```

## Add it to your agent {#client}

Tell your agent to start the MCP server over SSH. Use an SSH key that logs in without a password prompt. For Claude Code, one command adds it:

```sh title="Add the RustIron MCP server to Claude Code" where="Workstation (operator)"
claude mcp add rustiron -- ssh -T agentops@your-vps.example.com sudo -n -u rustiron-coordinator /usr/libexec/rustiron/rustiron-mcp --socket /run/rustiron-coordinator/control.sock
```

```json title="The same server in an MCP client configuration file" where="Workstation (operator)"
{
  "mcpServers": {
    "rustiron": {
      "command": "ssh",
      "args": ["-T", "agentops@your-vps.example.com", "sudo", "-n", "-u", "rustiron-coordinator", "/usr/libexec/rustiron/rustiron-mcp", "--socket", "/run/rustiron-coordinator/control.sock"]
    }
  }
}
```

## Check that it works {#check}

Ask your agent to run the RustIron health check (the rustiron_doctor tool). It should answer with the server's operating system and state. If the agent says the coordinator is not configured, the --socket part is missing; if the connection fails, try the SSH command alone in a terminal first. The site list shows the sites RustIron created or adopted on the server, as the command line does.

The tools the agent gets are: rustiron_doctor, rustiron_site_list, rustiron_site_inspect, rustiron_host_summary, rustiron_diagnoses, rustiron_certificate_status, rustiron_backup_status, rustiron_operation_status, rustiron_evidence_export, rustiron_plan_inspect, rustiron_plan_envelope, rustiron_plan_draft, and rustiron_plan_draft_help. All of them only read, and a plan draft is unsigned: you review it and sign it yourself.

## Signed changes on a test server {#writes}

Only on a test server, you can let the agent submit plans that you signed yourself. The agent then gets one more tool, rustiron_plan_apply_approved. It refuses a grant the agent issued, a plan over the limits, an expired grant, a production target, and delete-type actions.

This needs a second sudoers rule, which RustIron never installs. Write it yourself in /etc/sudoers.d/rustiron-mcp-writes, for one named account, with the exact options shown below (replace agentops twice). Then add the same two options at the end of the command in your agent's configuration: --write-tier nonproduction --agent-id agentops. The order must match the rule exactly. To turn the write mode off again, delete /etc/sudoers.d/rustiron-mcp-writes.

:::caution[Not on a production server]
The production write mode is not documented yet: it comes after a supervised run on a pilot server.
:::

```sh title="Open the rule file, on a test server only" where="Server (root)"
visudo -f /etc/sudoers.d/rustiron-mcp-writes
```

```text title="The line to put in that file" where="Server (root)"
agentops ALL=(rustiron-coordinator) NOPASSWD: /usr/libexec/rustiron/rustiron-mcp --socket /run/rustiron-coordinator/control.sock --write-tier nonproduction --agent-id agentops
```
