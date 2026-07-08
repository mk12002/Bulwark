# ⚖️ Warden

**Least-privilege auditor for AI agents.** Part of the [Bulwark](../../README.md) suite — *Airlock
scans the parts, Warden scans the assembly, Manifest inventories it all.*

Airlock asks "is this component malicious?" Warden asks the harder question: **given how you *wired*
the agent — its tools, scopes, system prompt, MCP servers, data access, and autonomy — does the
composed system hold more power than its job requires?** An agent built entirely from *benign* parts
can still be dangerous: a read-secrets tool *and* a send-email tool is an exfiltration path neither
tool has alone.

```bash
warden audit agent.yaml --recommend         # audit an agent AND rewrite it to least-privilege
warden audit config.json --scan-parts       # + run Airlock on every MCP server it wires in
warden import langchain_agent.py             # normalize any supported config → one AgentSpec
warden rules list
```

## The money shot: `--recommend`

Point Warden at an over-privileged agent and it hands you a hardened version:

```
$ warden audit devops-agent.yaml --recommend

  HIGH    A3   run_shell has no human-in-the-loop gate            run_shell
  HIGH    A8   run_shell executes code/shell without a sandbox    run_shell
  MEDIUM  A1   run_shell declares a wildcard scope                run_shell
  MEDIUM  A10  autonomous agent has no runaway guards             devops-agent
  MEDIUM  A4   system prompt grants open-ended authority          devops-agent

┌──────────────── Least-privilege recommendation ────────────────┐
│ Applied:                                                        │
│   - tool 'run_shell': add confirm gate (high-impact action)     │
│   - tool 'run_shell': require sandbox for code/shell execution  │
│   - tool 'run_shell': replace wildcard scope with an allow-list │
│   - agent: add runaway guards (max_iterations=25, timeout_s=300)│
└─────────────────────────────────────────────────────────────────┘
```

## What it catches (A-codes)

| Code | Risk |
| --- | --- |
| **A1** | Excessive tool scope (wildcard / root / unconstrained) |
| **A2** ⭐ | **Toxic combination** — a sensitive source reachable to an egress sink (the flagship check). Escalates to **CRITICAL** when the assembly also ingests untrusted content (browse / inbound), making the chain *attacker-triggerable* via indirect prompt injection: `inject → read secret → exfiltrate`. |
| **A3** | Missing human-in-the-loop on high-impact actions |
| **A4** | Over-broad system-prompt authority / weak guardrails |
| **A5** | Unrestricted egress / exfiltration surface |
| **A6** | Secrets / credentials embedded in the assembly |
| **A7** | Excessive data / memory access |
| **A8** | Unsandboxed code / shell execution |
| **A9** | Untrusted / unscanned parts wired in |
| **A10** | No runaway guards (iteration cap / budget / timeout) |

Plus a transparent **agency score (0–100)** in the header — a documented weighted sum over capability
breadth, ungated high-impact tools, exfil paths, and missing limits. *Not* a black box.

## Importers — bring your own framework

Warden normalizes many agent shapes into one `AgentSpec` IR, so the analysis engine never has to know
which framework you use. Auto-detected:

| Importer | Reads |
| --- | --- |
| `manifest` | Warden's documented agent-manifest YAML/JSON (also the fallback for anything else) |
| `mcp_config` | `.mcp.json` / `claude_desktop_config.json` (which servers are wired) |
| `openai_assistant` | an OpenAI Assistants API config (instructions, function/code-interpreter/file-search tools) |
| `langchain` | a **LangChain / LangGraph** Python file — best-effort *static* parse of `Tool(...)`, the model, and the system prompt (never executed) |
| `crewai` | a **CrewAI** `agents.yaml` (role/goal/backstory/tools, delegation) |

`warden import <config>` prints the normalized spec so you can see exactly what Warden sees.

## Policy profiles: one knob for how strict the audit is

`--profile strict|balanced|permissive` sets a coherent posture without ever rewriting a finding's
real severity — it only decides how much you see:

| Profile | Shows | Confidence | Use |
| --- | --- | --- | --- |
| `strict` | everything incl. INFO | all | a full least-privilege audit |
| `balanced` (default) | LOW and up | all | day-to-day |
| `permissive` | MEDIUM and up | medium/high only | blockers-only, low-noise CI |

Suppressed findings are counted in the report metadata for transparency, and `--fail-on` remains an
independent gate, so profile and gate compose.

## Composition: `--scan-parts`

The assembly wires in MCP servers, but are *those* safe? `warden audit --scan-parts` runs **Airlock**
on each wired MCP server and merges its P-findings into the report — turning the A9 "unscanned parts"
advisory into concrete part-level findings. This is Warden and Airlock composing directly; Manifest
does the same at system scale.

## How it works

An **importer** turns a real config into one normalized **AgentSpec**; `normalize` tags each tool with
**capabilities** from a keyword lexicon; the **analysis** engine builds a capability graph (source →
sink reachability = a toxic combination) and emits signals; **YAML rule packs** map those to A-code
findings; the **agency score** headlines the report. `--recommend` produces a minimized AgentSpec
(gate high-impact tools, sandbox exec, replace wildcard scopes, add runaway guards) plus a before/after
diff. Everything reuses `bulwark-core` for findings, the rule engine, reports
(terminal/JSON/HTML/SARIF), threshold exit codes, and the optional AI layer.

## Safety

Warden is defensive: it inspects configs **statically** (never executes or imports target agent code —
the LangChain importer parses source with regex), and its fixtures simulate risky assemblies with
benign, inert tools. See
[`docs/PROJECT_REFERENCE_WARDEN.md`](../../docs/PROJECT_REFERENCE_WARDEN.md) for the full design.
