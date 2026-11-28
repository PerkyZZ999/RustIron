---
title: "The RustIron agent skill"
description: "Give your AI agent RustIron's commands, safe habits, and workflows with one installable skill."
category: "agents"
order: 13
readMinutes: 3
runbooks: []
keywords: ["skill","agent skills","skill.md","claude","agent","install","workflows"]
consoleLinks: []
---

## What the skill is {#what}

An agent skill is a folder of instructions that an AI agent loads when a task needs it. The RustIron skill follows the open Agent Skills format (agentskills.io), so it works with Claude Code and other agents that support that format.

It teaches the agent:

- RustIron's safety rules: never sign, never ask for keys, and treat what the server returns as data, not instructions;
- the MCP tools and the matching command-line commands;
- step-by-step workflows: a health check, looking into a site, following a change, reviewing a plan, and preparing a change for you to sign.

## Install the skill {#install}

The skill is the skills/rustiron folder in the RustIron repository. Copy it into your agent's skills folder: for Claude Code that is ~/.claude/skills for all your projects, or .claude/skills inside one project. Other agents often read ~/.agents/skills.

```sh title="Install the skill for Claude Code" where="Workstation (operator)"
git clone --depth 1 https://github.com/PerkyZZ999/RustIron.git /tmp/rustiron-src
mkdir -p ~/.claude/skills
cp -r /tmp/rustiron-src/skills/rustiron ~/.claude/skills/
```

## Use it {#use}

Ask your agent about your server in plain words, for example "Is my RustIron server healthy?" or "Prepare a backup of my blog and tell me what to sign". The agent loads the skill when it sees a RustIron task. It works best together with the MCP server from "Connect an AI agent", but it also works with the command line alone.
