# Warden

**Least-privilege auditor for AI agents.** Part of the [Bulwark](../../README.md) suite — *Airlock
scans the parts, Warden scans the assembly, Manifest inventories it all.*

Airlock asks "is this component malicious?" Warden asks a different question: **given how you wired
the agent — its tools, scopes, system prompt, MCP servers, data access, and autonomy — does the
composed system hold more power than its job requires?** A system built entirely from *benign* parts
can still be dangerous because of how they combine.

```bash
warden audit agent.yaml                 # audit an agent manifest (YAML/JSON) or MCP client config
warden audit agent.yaml --recommend     # ...and print a least-privilege version + diff
warden import agent.yaml                 # show the normalized AgentSpec (debug importers)
warden rules list
```

## What it catches (A-codes)

| Code | Risk |
| --- | --- |
| **A1** | Excessive tool scope (wildcard/root/unconstrained) |
| **A2** | Dangerous tool combination — a sensitive source reachable to an egress sink (the flagship) |
| **A3** | Missing human-in-the-loop on high-impact actions |
| **A4** | Over-broad system-prompt authority / weak guardrails |
| **A5** | Unrestricted egress / exfiltration surface |
| **A6** | Secrets/credentials embedded in the assembly |
| **A7** | Excessive data/memory access |
| **A8** | Unsandboxed code/shell execution |
| **A9** | Untrusted/unscanned parts wired in |
| **A10** | No runaway guards (iteration cap / budget / timeout) |

## How it works

An **importer** turns a real config into one normalized **AgentSpec** IR; `normalize` tags each tool
with **capabilities** from a keyword lexicon; the **analysis** engine builds a capability graph and
emits signals; **YAML rule packs** (`warden/rules/`) map those to A-code findings; and an **agency
score (0–100)** — a documented weighted sum, not a black box — headlines the report. Everything reuses
`bulwark-core` for the findings model, rule engine, reports (terminal/JSON/HTML/SARIF), threshold exit
codes, and the optional AI layer.

`warden audit ... --recommend` produces a **minimized AgentSpec** (gate high-impact tools, sandbox exec
tools, replace wildcard scopes with an allow-list, add runaway guards) plus a human-readable diff, and
flags toxic pairs/egress that need a design decision.

## Safety

Warden is defensive: it inspects configs statically (never executes or imports target agent code) and
its fixtures simulate risky assemblies with **benign, inert** tools. See
[`docs/PROJECT_REFERENCE_WARDEN.md`](../../docs/PROJECT_REFERENCE_WARDEN.md) for the full design.
