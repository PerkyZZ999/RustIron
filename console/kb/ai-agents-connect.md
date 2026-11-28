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

## Build and install the MCP server {#install}

Build rustiron-mcp in your RustIron source folder, on the same kind of system where you build RustIron itself, then install it on the server.

```sh title="Build the MCP server" where="Build / maintainer"
cargo build --release --locked --bin rustiron-mcp
```

```sh title="Install it on the server" where="Server (root)"
install -m 0755 target/release/rustiron-mcp /usr/local/bin/rustiron-mcp
```

## Let one account start it {#sudo}

On the server, rustiron-mcp must run as the coordinator's account to read its socket. Give the account you use for SSH permission to start exactly this one command, and nothing else. The examples use agentops; replace it with your SSH user name. Do not use the name operator: on AlmaLinux it is a built-in system account.

:::note[Only this command]
This rule lets the account start rustiron-mcp, read-only, with this exact socket. It does not give the account any other rights.
:::

```sh title="Allow the SSH account to start the MCP server" where="Server (root)"
echo 'agentops ALL=(rustiron-coordinator) NOPASSWD: /usr/local/bin/rustiron-mcp --socket /run/rustiron-coordinator/control.sock' > /etc/sudoers.d/rustiron-mcp
chmod 0440 /etc/sudoers.d/rustiron-mcp
visudo -cf /etc/sudoers.d/rustiron-mcp
```

## Add it to your agent {#client}

Tell your agent to start the MCP server over SSH. Use an SSH key that logs in without a password prompt. For Claude Code, one command adds it:

```sh title="Add the RustIron MCP server to Claude Code" where="Workstation (operator)"
claude mcp add rustiron -- ssh -T agentops@your-vps.example.com sudo -n -u rustiron-coordinator /usr/local/bin/rustiron-mcp --socket /run/rustiron-coordinator/control.sock
```

```json title="The same server in an MCP client configuration file" where="Workstation (operator)"
{
  "mcpServers": {
    "rustiron": {
      "command": "ssh",
      "args": ["-T", "agentops@your-vps.example.com", "sudo", "-n", "-u", "rustiron-coordinator", "/usr/local/bin/rustiron-mcp", "--socket", "/run/rustiron-coordinator/control.sock"]
    }
  }
}
```

## Check that it works {#check}

Ask your agent to run the RustIron health check (the rustiron_doctor tool). It should answer with the server's operating system and state. If the agent says the coordinator is not configured, the --socket part is missing; if the connection fails, try the SSH command alone in a terminal first. The site list answers "dependency unavailable" until the server has an imported inventory, as the command line does; the Console's Sites page still shows your sites.

The tools the agent gets are: rustiron_doctor, rustiron_site_list, rustiron_site_inspect, rustiron_operation_status, rustiron_evidence_export, rustiron_plan_inspect, and rustiron_plan_envelope. All of them only read.
