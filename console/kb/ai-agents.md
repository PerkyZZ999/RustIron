---
title: "AI agents and RustIron"
description: "What an AI agent can do with RustIron, what it can never do, and why your approval stays in your hands."
category: "agents"
order: 11
readMinutes: 4
runbooks: ["Runbook 05"]
keywords: ["ai","agent","mcp","claude","assistant","automation","llm","skill","tools","read-only"]
consoleLinks: [{"to":"/operations","label":"Operations"},{"to":"/","label":"Host overview"}]
---

## What an agent can do {#can}

RustIron is built so that an AI agent, such as Claude, can help you run your server. Through the RustIron MCP server (rustiron-mcp), an agent can:

- check the server's health, see which sites are quarantined or ejected, and list the server's problems with what to do about each;
- see which HTTPS certificates expire soon, and when each site was last backed up and restore-tested;
- list your sites and look at one in detail;
- follow a change and read its outcome;
- read the recovery evidence of a change;
- read a plan and explain what it will touch, how many sites reload, and what happens if it fails;
- draft a plan for a change you ask for, for you to review and sign. The draft is unsigned and changes nothing.

## With the agent skill {#skill}

With the RustIron agent skill, it also knows RustIron's commands and safe habits, so it can prepare the exact commands for a change and explain them to you.

## What an agent can never do {#cannot}

An agent never approves a change. Every change needs a plan signed with your own key, on your own computer, and an agent never holds that key. The MCP server also:

- has no tool that changes the server by default;
- opens no network port: it talks only to the program that started it;
- cannot run shell commands, SQL, or delete sites;
- marks everything it returns as untrusted data, so text from a website or a log is never taken as an instruction.

:::caution[Never give an agent your operator key]
If an agent asks for your signing key, refuse. Sign plans yourself, after you read the review.
:::

## Signed changes through an agent {#writes}

An optional, experimental mode lets an agent submit a plan that a person already signed, within limits RustIron enforces: one operation per grant, at most 4 changes and 1 web-server reload per plan. The agent still cannot approve its own plan, raise its limits, or use delete-type actions, and it never holds a signing key.

- **On a test server**, you can turn on the nonproduction mode yourself. "Connect an AI agent" shows how. It needs a second sudoers rule that you write on purpose; the rule RustIron installs never allows it.
- **On a production server**, this mode is not recommended yet. Its guide comes after a supervised run on a pilot server.

:::caution[Sign what you read, not what the agent says]
Before you sign a plan an agent drafted, run rustiron plan review-file on your own computer and read every field. Never sign from the agent's summary of the plan. Keep grant windows short: an agent can use a signed grant at any moment until it expires.
:::

## Current state {#status}

The MCP server and the agent skill are new and experimental, like the rest of RustIron. RustIron installs rustiron-mcp with the rest of the product, starting with the first release after 0.2.0; "Connect an AI agent" shows how to connect it. More tools are planned for version 0.3.
