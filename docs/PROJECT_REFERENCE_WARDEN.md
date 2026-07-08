# Warden — Project Reference & Design Document

*Least-privilege auditor for AI agents. Scan the assembly.*

Part of the **Bulwark** suite (see `BULWARK.md`). Warden reuses `bulwark-core` for findings,
severity, the rule engine, reports, and the optional AI layer. This document defines what is
Warden-specific. It is the source of truth for Warden's design.

**Status (v0.1, shipped):** the AgentSpec IR, capability lexicon, capability graph, agency score,
A1–A10, the least-privilege recommender (`--recommend`), all five importers (manifest, MCP config,
OpenAI Assistants, LangChain/LangGraph, CrewAI), the Airlock bridge (`--scan-parts`), and the optional
AI layer are all built and tested green. The sections below describe the design; the "Later"/roadmap
markers are retained as history but every listed capability is complete.

---

## 1. Thesis & positioning

Airlock answers "is this component malicious?" But a system built entirely from *benign* parts can
still be dangerous because of **how they were wired together**. An agent given a read-secrets tool
*and* a send-email tool has an exfiltration path neither tool has alone. An agent with a shell tool,
web browsing, and no human gate can be driven to run arbitrary commands via a poisoned web page.

**Warden audits the composition.** It answers: does this assembled agent hold more capability than
its purpose requires (excessive agency), and do its tools combine into dangerous paths (toxic
combinations)? Then it proposes a least-privilege version.

### 1.1 Prior art / positioning

- **Cloud IAM least-privilege** tools exist for humans/services, but not for **agent tool-sets**.
- **Excessive Agency** is OWASP LLM06 — named as a top risk, but tooling to *measure* it in a concrete
  agent assembly is essentially absent.
- Warden's edge: a normalized **Agent Spec** across frameworks, a **capability graph** that finds
  source→sink toxic combinations, an **agency score**, and an actionable **least-privilege
  recommendation** — plus native composition with Airlock (parts) and Manifest (inventory).

---

## 2. What Warden ingests

The challenge is that agents are configured many ways. Warden solves this with an **importer →
normalized IR** pattern (mirrors Airlock's loader). Importers convert real configs into one
`AgentSpec`; all analysis runs on the IR, so adding a framework never touches the analysis engine.

Importers (all shipped; auto-detected, in priority order — `warden/importers/`):
1. **MCP client configs** (`mcp_config.py`) — `.mcp.json`, `claude_desktop_config.json` (which
   servers/tools are wired).
2. **Generic agent manifest** (`manifest_yaml.py`) — a documented YAML/JSON schema describing tools,
   scopes, system prompt, model, data sources, gates, and limits. Also the canonical fallback for an
   agent Warden can't otherwise parse; its `detect` defers to the specific shapes below so it never
   steals a framework config.
3. **OpenAI Assistants** (`openai_assistant.py`) — an Assistants API config
   (`instructions` → system prompt; `function`/`code_interpreter`/`file_search` tools).
4. **LangChain / LangGraph** (`langchain.py`) — best-effort **static regex** parse of a `.py` file
   (`Tool(...)` name+description, the model, the system prompt). Never executed or imported.
5. **CrewAI** (`crewai.py`) — an `agents.yaml` crew (role/goal/backstory/tools/delegation), aggregated
   into one AgentSpec.

`warden import <config>` prints the normalized AgentSpec so you can see exactly what each importer
resolved.

---

## 3. Threat taxonomy (A-codes)

Each finding maps to one category. Default severities are starting points; the rule packs set the
exact values and can be tuned.

**A1 — Excessive tool scope.** *(MEDIUM–HIGH)* A tool granted broader capability than needed —
filesystem root, unrestricted shell, wildcard network, `*` resource scopes. **Detect:** capability
tags + wildcard/breadth analysis in `analysis/scopes.py`. **Ref:** OWASP LLM06, CWE-269.

**A2 — Dangerous tool combination (toxic combination).** *(HIGH–CRITICAL)* Two or more tools that are
individually acceptable but together form a harmful path — classically a *sensitive source* (read
files/secrets/DB/context) reachable to an *egress sink* (network/email/write-external). The flagship
check. **Detect:** capability graph source→sink reachability in `analysis/graph.py`. **Ref:** OWASP
LLM06/LLM02, confused-deputy.

**A3 — Missing human-in-the-loop on high-impact actions.** *(HIGH)* Irreversible/destructive/financial
/external-communication tools with no confirmation gate. **Detect:** high-impact capability without a
declared gate in `analysis/limits.py`. **Ref:** OWASP LLM06.

**A4 — Over-broad system-prompt authority / weak guardrails.** *(MEDIUM–HIGH)* System prompt grants
open-ended autonomy ("do whatever it takes", "you may access anything"), lacks refusal/limits, or is
itself injectable/ambiguous. **Detect:** authority + injectability heuristics in `analysis/prompt.py`
(AI-enrichable). **Ref:** OWASP LLM01/LLM06.

**A5 — Unrestricted egress / exfiltration surface.** *(HIGH)* Agent can reach arbitrary URLs or send
data outward without allow-listing. **Detect:** network capability breadth + presence of any sensitive
source. **Ref:** OWASP LLM02.

**A6 — Secrets/credentials in the assembly.** *(HIGH–CRITICAL)* API keys/tokens embedded in configs or
broadly injected into many tools' environments. **Detect:** secret signatures over config (reuse core
secret rules). **Ref:** CWE-798, OWASP LLM02.

**A7 — Excessive data/memory access.** *(MEDIUM–HIGH)* Agent has read access to more data (files, DBs,
long-lived memory, whole-drive context) than its stated purpose. **Detect:** declared data sources vs
purpose; broad/rooty data scopes. **Ref:** OWASP LLM06, least-privilege.

**A8 — Unsandboxed code/shell execution.** *(HIGH)* Code-exec or shell tools without a declared sandbox
/ isolation boundary. **Detect:** exec capability without `sandbox` attribute. **Ref:** CWE-250.

**A9 — Untrusted/unscanned parts wired in.** *(MEDIUM)* The assembly references MCP servers/models that
haven't passed Airlock. **Detect:** cross-check wired components; with `--scan-parts`, invoke Airlock
and merge. **Ref:** OWASP LLM05.

**A10 — No runaway guards.** *(MEDIUM)* Autonomous/looping agent with no iteration cap, budget, or
timeout. **Detect:** missing limits in `analysis/limits.py`. **Ref:** OWASP LLM06.

---

## 4. AgentSpec IR (Warden-specific data model)

Findings/severity come from `bulwark_core`. Warden adds the IR:

```python
class Capability(str, Enum):
    FS_READ="fs_read"; FS_WRITE="fs_write"; SHELL="shell"; CODE_EXEC="code_exec"
    NET_OUT="net_out"; NET_IN="net_in"; SECRET_READ="secret_read"; DB_READ="db_read"
    DB_WRITE="db_write"; EMAIL_SEND="email_send"; FINANCIAL="financial"; DESTRUCTIVE="destructive"
    BROWSE="browse"; MEMORY_WRITE="memory_write"; UNKNOWN="unknown"

class Gate(str, Enum):
    NONE="none"; CONFIRM="confirm"; APPROVAL="approval"; DRY_RUN="dry_run"

class Tool(BaseModel):
    name: str
    source: str | None = None            # which MCP server / plugin provided it
    description: str | None = None
    scopes: list[str] = []               # raw scope strings from config
    capabilities: set[Capability] = set() # filled by normalize.py
    sandboxed: bool | None = None
    gate: Gate = Gate.NONE

class DataSource(BaseModel):
    name: str; kind: str                 # files | db | memory | context | env
    scope: str | None = None; sensitive: bool = False

class Limits(BaseModel):
    max_iterations: int | None = None
    budget: float | None = None
    timeout_s: int | None = None

class AgentSpec(BaseModel):
    name: str
    model: str | None = None
    system_prompt: str | None = None
    tools: list[Tool] = []
    data_sources: list[DataSource] = []
    mcp_servers: list[str] = []          # references (paths/urls) → A9 / --scan-parts
    limits: Limits = Limits()
    autonomy: Literal["manual","assisted","autonomous"] = "assisted"
```

`normalize.py` maps raw tool names/scopes/descriptions to `Capability` sets using a rule-backed
lexicon (extensible YAML), so classification improves via PRs, not code edits.

---

## 5. Capability graph & the agency score

- **Graph:** nodes = tools, data sources, and external sinks; edges = "can supply data to" / "can act
  on". A *sensitive source* → *egress sink* reachable path is a toxic combination (A2/A5).
- **Agency score (0–100):** a transparent weighted sum over breadth of capabilities, count of
  high-impact tools, ungated high-impact actions, exfil paths, and missing limits. Documented formula
  (no black box). Displayed in the report header; great demo headline ("Agency score: 82/100 — HIGH").
- The score is advisory context, never a substitute for the itemized findings.

---

## 6. Least-privilege recommendation

`recommend/least_privilege.py` produces a **minimized AgentSpec** plus a human-readable diff:
- Drop scopes/capabilities with no evidence of need (heuristic: not referenced by purpose/task).
- Add `gate: confirm/approval` to high-impact tools (A3).
- Break toxic pairs (A2): suggest splitting into separate agents, removing one capability, or adding a
  mediation/allow-list boundary.
- Add `limits` (A10) and `sandboxed: true` for exec tools (A8).
- Allow-list egress instead of open `net_out` (A5).

Output: `warden audit ... --recommend` prints before/after and can write a `agentspec.hardened.yaml`.

---

## 7. Reports

Reuse `bulwark_core.report`: terminal (rich, grouped by A-code, header shows agency score + worst
severity), JSON (`ScanResult` + the AgentSpec + score), HTML, SARIF (ruleId = A-code). `--fail-on`
sets the CI gate.

---

## 8. AI enrichment (optional; reuse `bulwark_core.ai`)

Off by default; `enabled AND --ai`; capped by `max_findings_to_enrich`; local Ollama default. Uses:
1. **System-prompt analysis (A4):** judge whether the prompt is over-permissive or injectable; strict
   JSON verdict `{weak: bool, confidence, reason}`.
2. **Non-obvious toxic combinations (A2):** reason over the capability set for harmful paths rules
   didn't encode; must reference concrete tools, else discard.
3. **Attack-path prose:** explain a flagged source→sink path for the report.
4. **Remediation phrasing:** turn a minimized spec diff into a short rationale.
AI output is tagged `source="ai"`, never downgrades a deterministic finding, degrades gracefully on
error.

---

## 9. CLI

```
warden audit <path|config|manifest.yaml> [--format terminal|json|html|sarif]
                                          [--fail-on SEV] [--recommend] [--scan-parts] [--ai]
warden import <path>        # show the normalized AgentSpec (debug importers)
warden rules list|lint
warden version
```

---

## 10. Testing & fixtures

- **Benign, inert fixtures only.** An "exfil" fixture wires a *fake* read-notes tool and a *fake*
  post-webhook tool that does nothing real — enough to trip A2 without any harmful behavior.
- Fixtures: `over_privileged/` (basic A1, exfil A2/A5, ungated-destructive A3, runaway A10) and
  `least_privilege/` (clean controls).
- Tests assert on `category` + `severity` + presence of the recommendation, not on prose.
- Golden-file tests for JSON/SARIF and for the hardened-spec diff.

---

## 11. Release & community

README with a one-glance "before/after" (an over-privileged agent → the hardened spec Warden
suggests), the agency-score demo, the A-code table, and a GitHub Action. The "it rewrote my agent to
least-privilege" moment is the shareable hook. `CONTRIBUTING.md` invites capability-lexicon and rule
PRs.

---

## 12. Roadmap

- ✅ **v0.1** — IR, MCP-config + manifest importers, capability graph, A1–A10, agency score.
- ✅ **v0.2** — least-privilege recommendation, SARIF/HTML, `--fail-on` CI gate.
- ✅ **v0.3** — framework importers (OpenAI Assistants, LangChain/LangGraph, CrewAI), the Airlock
  bridge / `--scan-parts`, A9 promoted from advisory to concrete part-level findings.
- ✅ **v0.4** — optional AI enrichment (`bulwark_core.ai`).
- ⏭️ **v0.5+** — richer lexicon, policy profiles (e.g. "strict", "balanced"), org policy files.

---

## 13. Research / talk angle

"We normalized N public agent configs and found X% contain at least one toxic tool combination; Y%
expose exec/shell without a sandbox." A concrete, reproducible measurement of *excessive agency in the
wild* — a strong workshop paper or conference talk, and a natural companion to Airlock's corpus study.

---

## 14. References (verify current versions when building)

OWASP Top 10 for LLM Applications (esp. **LLM06 Excessive Agency**, LLM01, LLM02, LLM05); MITRE ATLAS;
Model Context Protocol spec (tool/scope schema); least-privilege / CWE-269, CWE-250, CWE-798; cloud IAM
least-privilege analyzers as conceptual prior art (applied here to agent tool-sets, not cloud roles).
