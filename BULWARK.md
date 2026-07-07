# Bulwark — the security stack for agentic AI

*Airlock scans the parts. Warden scans the assembly. Manifest inventories it all.*

This document defines how the three tools live together. Read it before building Warden or
Manifest. Each tool also has its own `CLAUDE.md` (build instructions) and
`docs/PROJECT_REFERENCE_*.md` (deep design).

---

## The suite

| Tool         | Scope                     | Question it answers                                   |
|--------------|---------------------------|------------------------------------------------------|
| **Airlock**  | the *parts*               | Is this model / MCP server itself malicious or unsafe? |
| **Warden**   | the *assembly*            | Given how I wired the agent, does it have too much power? |
| **Manifest** | the *whole system*        | What is my AI system made of, and is it governable?  |

They compose: **Manifest** builds an inventory and calls **Airlock** on each model/MCP server and
**Warden** on each agent assembly, then aggregates everything into one governance artifact.

---

## Why a monorepo (decision)

- All three share a spine: `Finding` / `Severity` / rule engine / report renderers (terminal, JSON,
  HTML, SARIF) / the optional AI provider layer. Build it once, reuse three times.
- Manifest has a **hard dependency** on Airlock and Warden (it calls them). Trivial in a monorepo,
  painful across repos.
- One coherent product story beats three scattered demos for portfolio signal.
- Each package still ships its own CLI and is independently installable, so nothing is lost.

## Monorepo layout

```
bulwark/                                  # repo root (uv workspace)
  pyproject.toml                          # workspace declaration
  README.md                               # the suite story + install matrix
  BULWARK.md                              # this file
  packages/
    bulwark-core/                         # the shared spine (a real, importable package)
      pyproject.toml
      bulwark_core/
        __init__.py
        findings.py                       # Finding, Severity, Location, ScanResult
        taxonomy.py                       # base taxonomy registry (tools extend it)
        rules.py                          # YAML rule-pack loader + matcher
        severity.py                       # scoring / normalization / exit codes
        scanner.py                        # abstract Scanner + orchestration base
        report/                           # terminal, json, html, sarif renderers
        ai/                               # provider protocol, ollama, openai_compat, anthropic, enrich
    airlock/                              # tool 1 (migrated in — see below)
      pyproject.toml                      # depends on bulwark-core
      airlock/ ...
    warden/                               # tool 2
      pyproject.toml                      # depends on bulwark-core
      warden/ ...
    manifest/                             # tool 3
      pyproject.toml                      # depends on bulwark-core, airlock, warden
      manifest/ ...
  docs/
    PROJECT_REFERENCE_AIRLOCK.md
    PROJECT_REFERENCE_WARDEN.md
    PROJECT_REFERENCE_MANIFEST.md
```

Use **`uv` workspaces** (preferred) or Hatch/`pip -e` path dependencies. Each package declares its own
`project.scripts` entry point: `airlock`, `warden`, `manifest`.

```toml
# root pyproject.toml (workspace)
[tool.uv.workspace]
members = ["packages/*"]
```

---

## The shared `bulwark-core` contract

Everything the three tools have in common lives here, and **nothing tool-specific does**. The stable
public surface:

- `bulwark_core.findings`: `Severity`, `Location`, `Finding`, `ScanResult` (pydantic v2 models).
- `bulwark_core.taxonomy`: a `register_categories()` API so each tool adds its own codes
  (Airlock: `M*`/`P*`; Warden: `A*`; Manifest: `B*`) to a shared registry with titles/refs.
- `bulwark_core.rules`: the YAML rule schema, loader, `lint`, and a matcher over analyzer signals.
- `bulwark_core.report`: `render(result, fmt)` for `terminal | json | html | sarif`.
- `bulwark_core.severity`: `worst()`, `exit_code(threshold)`.
- `bulwark_core.ai`: `AIProvider` protocol + `ollama` (default, free/local), `openai_compat`
  (OpenAI/OpenRouter/LM Studio/vLLM, BYO key+base_url), `anthropic`; `enrich()` helpers. **Off by
  default**, gated by `enabled AND --ai`, capped by `max_findings_to_enrich`, keys from env only.
- `bulwark_core.scanner`: `Scanner` ABC (`resolve → analyze → rules → ScanResult`) that each tool
  subclasses.

Design invariants shared by all tools: deterministic-first (fully useful with zero AI); defensive
only (detect/report, never weaponize; fixtures use benign inert markers); explainable findings
(what/where/why/severity/fix/reference); CI-friendly (JSON + SARIF + threshold exit code); detection
in YAML rule packs, not hardcoded.

---

## Migrating Airlock into the monorepo (do this first)

Airlock was built standalone with a `core/` folder. Promote that to the shared package:

1. Create the workspace root and `packages/` layout above.
2. Move `airlock/core/*` → `packages/bulwark-core/bulwark_core/*`; rename the import root
   `airlock.core` → `bulwark_core` across Airlock.
3. Move Airlock's model/MCP scanners under `packages/airlock/airlock/scanners/`.
4. Airlock's `M*`/`P*` categories now register into `bulwark_core.taxonomy` via `register_categories`.
5. Add `bulwark-core` as a workspace dependency in `packages/airlock/pyproject.toml`.
6. Move `docs/PROJECT_REFERENCE.md` → `docs/PROJECT_REFERENCE_AIRLOCK.md`.
7. Run the test suite; Airlock behavior must be unchanged. This is a pure refactor.

Definition of done for the migration: `airlock` CLI works exactly as before, all tests pass, and
`bulwark-core` has no imports from `airlock`, `warden`, or `manifest` (core depends on nothing in the
suite; tools depend on core).

---

## Build order

1. Migrate Airlock → monorepo + extract `bulwark-core`.
2. **Warden** (reuses core; adds the AgentSpec IR + capability graph).
3. **Manifest** (reuses core; adds discoverers + CycloneDX; calls Airlock + Warden).

Ship each to a taggable release before starting the next. A finished tool beats three half-built ones.
