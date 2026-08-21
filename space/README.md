---
title: Bulwark — AI Agent Supply-Chain Security
emoji: 🛡️
colorFrom: indigo
colorTo: gray
sdk: gradio
sdk_version: 5.49.1
app_file: app.py
pinned: false
license: apache-2.0
short_description: Audit an AI agent for excessive agency, or scan a model for pickle RCE.
tags:
  - security
  - ai-safety
  - supply-chain
  - agents
  - mcp
  - static-analysis
---

# 🛡️ Bulwark

**Security for the AI agent supply chain.** This Space demos two of the three tools in the
[Bulwark](https://github.com/mk12002/Bulwark) suite.

## ⚖️ Audit an agent (Warden)

Paste an agent config — Warden's own manifest YAML, an OpenAI Assistants payload, a CrewAI
`agents.yaml`, or an `.mcp.json`. It normalizes all of them into one internal shape, builds
a capability graph, and looks for **source → sink reachability**.

The point is *composition*. A tool that reads secrets is fine. A tool that sends HTTP is
fine. Both wired into one agent is an exfiltration path that neither tool has alone — and
if the agent also ingests untrusted content, an attacker can trigger it by planting
instructions on a web page it visits. Warden calls that `A2`, and escalates it to CRITICAL
when all three conditions hold.

"Harden it" then rewrites the config to least privilege: gate high-impact tools, sandbox
execution, replace wildcard scopes, add runaway guards. It will *not* delete a tool to
break a toxic combination — that changes what the agent is for, so it raises an advisory
and leaves the decision to you.

## 🔒 Scan a model (Airlock)

Upload a model artifact. Airlock disassembles pickle opcodes and reads format headers to
find code-execution payloads, `trust_remote_code`, archive smuggling, and provenance gaps.

**Airlock never unpickles, imports, or executes what it scans.** It is a static analyzer —
which is what makes it safe to point at a file you don't trust, and why this public Space
can accept uploads at all. Uploads are capped at 25 MB; run it locally for real models.

On a benchmark of 14 evasive-but-benign pickle payloads — protocol variants,
`STACK_GLOBAL`, gzip/zlib compression, base64 staging, `.npy` object arrays, torch-style
zips, and extension spoofing — Airlock catches **14/14**, against 11 for picklescan, 9 for
modelscan, and 9 for fickling. All four post **0/18** false alarms on real benign models.

## Run it yourself

```bash
pip install bulwark-airlock bulwark-warden

airlock scan model hf:org/name@revision
warden audit agent.yaml --recommend
```

[GitHub](https://github.com/mk12002/Bulwark) ·
[Documentation](https://mk12002.github.io/Bulwark/) ·
[Validation & methodology](https://github.com/mk12002/Bulwark/blob/main/docs/EMPIRICAL_VALIDATION.md)

---

Bulwark is a **defensive** security project. It detects and reports risk; it never
weaponizes. Every fixture and example in this Space is benign and inert. Apache-2.0.
