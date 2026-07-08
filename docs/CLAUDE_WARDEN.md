# CLAUDE.md — Warden

> Build instructions for Claude Code (Fable 5) building the **Warden** package inside the **Bulwark**
> monorepo. Read `BULWARK.md` (suite + monorepo + shared `bulwark-core` contract) and
> `docs/PROJECT_REFERENCE_WARDEN.md` (deep design) first. Warden must be built only after Airlock has
> been migrated into the monorepo and `bulwark-core` exists.
>
> **Status: all four build phases below are complete (v0.1, tested green).** Notably the framework
> importers landed as `openai_assistant.py`, `langchain.py` (LangChain/LangGraph, static regex), and
> `crewai.py` (not a single `langgraph.py`), and the Airlock bridge (`--scan-parts`, A9) shipped.

---

## What Warden is

**Warden is a least-privilege auditor for AI agents.** Airlock asks "is this part malicious?";
Warden asks "given how you *assembled* the agent — its tools, scopes, system prompt, MCP wiring,
data access, and autonomy — does the composed system have more power than its job requires?"

It ingests an agent's configuration, normalizes it into a single **Agent Spec** intermediate
representation, builds a **capability graph**, detects excessive agency and dangerous tool
**combinations**, scores the assembly, and emits a **suggested least-privilege configuration**.

CLI-first. Deterministic-first. AI enrichment optional and off by default (reuses `bulwark_core.ai`).

---

## Non-negotiable principles (inherited from Bulwark)

1. **Defensive only.** Warden detects and reports over-privilege and suggests safer configs. It never
   generates working attacks. Fixtures simulate risky assemblies with **benign, inert** tools.
2. **Deterministic first, AI second.** Fully useful with zero AI. AI only enriches (weak-prompt
   judgement, non-obvious toxic-combination reasoning, prose attack-path explanations, remediation
   phrasing). Never let AI downgrade a finding or become required.
3. **Local-first & free.** No paid infra. AI defaults to local Ollama via `bulwark_core.ai`.
4. **Reuse `bulwark-core`.** Do not re-implement `Finding`/`Severity`/rule engine/report/AI. Import
   them. Warden adds only what's Warden-specific: the AgentSpec IR, importers, capability graph,
   recommendation engine, and the `A*` rule packs.
5. **Explainable + CI-friendly.** Every finding: what/where/why/severity/remediation/reference.
   JSON + SARIF + `--fail-on` threshold exit code.

---

## Tech stack & conventions

Same as Bulwark: Python 3.11+, `typer`, `rich`, `pydantic` v2, `pyyaml`, `jinja2` (via core),
`ruff`, `mypy` (strict on `warden/`), `pytest` (≥85% on core logic). Importers may use light,
well-scoped parsers; do not execute or import any target agent code — inspection only.

Dev commands (from repo root):
```bash
uv sync
ruff format . && ruff check .
mypy packages/warden/warden
pytest packages/warden -q
warden --help
```

---

## Package layout (`packages/warden/`)

```
warden/
  __init__.py
  cli.py                     # typer: warden audit <path|config> [--format ...] [--fail-on ...] [--ai]
  spec/
    model.py                 # AgentSpec IR (pydantic): Agent, Tool, Capability, DataSource, Gate...
    normalize.py             # canonicalization + capability tagging
  importers/
    __init__.py              # registry: detect + dispatch by file/shape
    base.py                  # _parse + import_agent (lazily registers all importers)
    mcp_config.py            # .mcp.json / claude_desktop_config.json → AgentSpec
    manifest_yaml.py         # generic agent-manifest (YAML/JSON); defers to specific shapes → AgentSpec
    openai_assistant.py      # OpenAI Assistants config → AgentSpec
    langchain.py             # LangChain/LangGraph .py → AgentSpec  [best-effort static regex]
    crewai.py                # CrewAI agents.yaml → AgentSpec
  bridge.py                  # scan_wired_parts: run Airlock on wired MCP servers (--scan-parts, A9)
  analysis/
    capabilities.py          # classify each tool → capability set (shell/fs/net/read/write/...)
    graph.py                 # build capability graph; source→sink reachability
    scopes.py                # scope breadth / wildcard detection
    prompt.py                # system-prompt authority + injectability heuristics
    limits.py                # human-in-the-loop gates, budget/iteration caps
  rules/
    warden/*.yaml            # A1..A10 rule packs
  recommend/
    least_privilege.py       # emit a minimized AgentSpec + a human diff
  fixtures/
    over_privileged/         # benign but risky assemblies (trip A2/A3/A5...)
    least_privilege/         # clean control assemblies
  templates/                 # html report partials (extends core)
tests/
```

`warden.scanner.WardenScanner` subclasses `bulwark_core.scanner.Scanner`.

---

## Build phases (in order; each demoable)

### Phase 0 — AgentSpec IR + importers
- `spec/model.py`: the IR (see `docs/PROJECT_REFERENCE_WARDEN.md` §4).
- `importers/mcp_config.py` and `importers/manifest_yaml.py` + importer registry/auto-detect.
- `spec/normalize.py`: tag each tool with capabilities.
- **DoD:** `warden audit fixtures/over_privileged/basic` loads and prints a normalized AgentSpec
  summary; importer round-trips a sample MCP client config; tests cover IR + both importers.

### Phase 1 — Capability graph + core checks (the heart)
- `analysis/capabilities.py`, `analysis/graph.py`: build the graph and detect source→sink paths
  (A2 toxic combinations, A5 exfil surface).
- `analysis/scopes.py` (A1), `analysis/prompt.py` (A4), `analysis/limits.py` (A3, A10).
- `rules/warden/*.yaml` for A1..A10; wire to `bulwark_core.rules`.
- An **agency score** (0–100) in the report header.
- Benign fixtures that trip A1/A2/A3/A5/A10; clean controls.
- **DoD:** `warden audit fixtures/over_privileged/exfil` reports A2 (data-source→network sink) at HIGH
  and A5; the least-privilege control is clean; JSON validates; tests assert on category + severity.

### Phase 2 — Least-privilege recommendation + reports
- `recommend/least_privilege.py`: produce a minimized AgentSpec (drop unused scopes, add gates, split
  toxic tool pairs) and a readable before/after diff.
- SARIF + HTML via core; `--fail-on`; non-zero exit gating.
- **DoD:** `warden audit ... --recommend` prints a safer spec + diff; SARIF ingests in GitHub.

### Phase 3 — More importers + Airlock bridge
- Add `langgraph.py` / `openai_assistant.py` importers (best-effort static parsing).
- Bridge: when the assembly wires MCP servers, optionally invoke Airlock on them and merge findings
  (A9). Keep it opt-in (`--scan-parts`).
- **DoD:** a LangGraph sample imports; `--scan-parts` merges Airlock MCP findings into the report.

### Phase 4 — Optional AI enrichment
- Use `bulwark_core.ai` to: judge system-prompt weakness/injectability, surface non-obvious toxic
  combinations, and phrase attack paths + remediations. Gated by `enabled AND --ai`. Default OFF.

---

## Working style for the agent

- Outcome-first prompts; build a phase, verify against its DoD, stop for review.
- Never execute or import target agent code; importers parse statically.
- Toxic-combination and attack-path logic is **detection and explanation**, never a runnable exploit;
  fixtures stay benign/inert.
- Extend `bulwark-core`; if you need something generic (a new report field, a new AI helper), add it to
  core, not to Warden.
- Every new check ships with a fixture + a test asserting on `category` and `severity`.
- Keep `docs/PROJECT_REFERENCE_WARDEN.md` authoritative; update it when design changes.

## Rename
Package name is `warden`. Find/replace to rename; nothing depends on the name semantically.
