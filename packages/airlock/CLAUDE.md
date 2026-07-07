# CLAUDE.md — Airlock

> Operational instructions for Claude Code (Fable 5) building this repository.
> Deep design rationale lives in `docs/PROJECT_REFERENCE.md`. Read it before Phase 1.

---

## What this project is

**Airlock is a static security scanner for the AI agent supply chain.** It audits the two
kinds of untrusted third-party code you plug into an agentic system *before* they run:

- **ML model artifacts** (the components — *what the agent knows*)
- **MCP servers** (the connections — *what the agent can do*)

One engine, one risk taxonomy, one report format, two scan targets. Think `trivy`/`nikto`,
but for the agent-tooling and model-loading layer.

CLI-first. Deterministic-first. AI is an optional enrichment layer, off by default.

---

## Non-negotiable principles

1. **Defensive tool, not an offensive one.** Airlock *detects and reports* risks. It never
   generates working attacks or weaponized payloads. Test fixtures that simulate malicious
   artifacts must use **benign, inert markers** (e.g. a pickle whose payload writes a harmless
   sentinel file to a temp dir, or prints a marker string) — never anything destructive,
   network-exfiltrating, or harmful. This framing is deliberate; keep it throughout.
2. **Deterministic first, AI second.** The tool must be fully useful with **zero AI configured**.
   Every core finding comes from static analysis, opcode inspection, schema heuristics, and
   YAML rules. AI only *enriches* (semantic judgement, triage, summaries) and is always optional.
3. **Local-first & free.** No paid infrastructure required to run. Model files are fetched from
   the public Hugging Face Hub (no key needed for public repos). The optional AI layer defaults
   to a **local model via Ollama** so there is no token cost or data egress.
4. **Extensible by design.** Detection logic lives in **YAML rule packs**, not hardcoded, so the
   community can contribute rules via PRs. This is a first-class product feature.
5. **Explainable findings.** Every finding states: what was found, where, why it matters, the
   severity, a remediation, and a reference (OWASP LLM Top 10 / MITRE ATLAS / CWE where relevant).
6. **CI-friendly output.** Support JSON and **SARIF** so Airlock plugs into GitHub code scanning
   and pipelines. A findings-based non-zero exit code gates builds.

---

## Tech stack & conventions

- **Language:** Python 3.11+
- **Package/deps:** `pyproject.toml` (PEP 621). Prefer `uv` if available, else `pip`.
- **CLI:** `typer`
- **Terminal UI:** `rich`
- **Model scanning:** stdlib `pickletools`, `zipfile`, `pathlib`; `huggingface_hub` for fetch.
- **MCP scanning:** official `mcp` Python SDK (stdio + SSE/HTTP transports).
- **Templating (HTML report):** `jinja2`
- **Config:** `pydantic` v2 models; env vars via `pydantic-settings`; optional `airlock.toml`.
- **Lint/format:** `ruff` (format + lint). **Types:** `mypy` (strict on `core/` and `scanners/`).
- **Tests:** `pytest`. Coverage target ≥ 85% on `core/` and `scanners/`.
- **Style:** small pure functions, dependency-inject the rule engine and AI provider, no global
  state, typed everything, docstrings on public functions. No `print()` — use the report layer.

### Standard dev commands (create these as scripts / Makefile targets)

```bash
uv sync                      # or: pip install -e ".[dev]"
ruff format . && ruff check .
mypy airlock
pytest -q
airlock --help
```

---

## Repository layout (target)

```
airlock/
  __init__.py
  cli.py                     # typer app: `airlock scan model|mcp`, `airlock rules`, etc.
  config.py                  # pydantic settings (AI provider, thresholds, output)
  core/
    findings.py              # Finding, Severity, ScanResult, Location (pydantic models)
    taxonomy.py              # enum of M1..M7 / P1..P9 categories + metadata
    rules.py                 # YAML rule-pack loader, matcher, rule schema
    scanner.py               # abstract Scanner + orchestration
    severity.py              # scoring / normalization
    report/
      __init__.py
      terminal.py            # rich renderer
      json_report.py
      html.py                # jinja2
      sarif.py
  scanners/
    model/
      __init__.py
      loader.py              # HF Hub / local path resolution, file discovery
      pickle_scan.py         # opcode disassembly (M1/M2/M3)
      formats.py             # pickle vs safetensors detection (M4)
      remote_code.py         # trust_remote_code / auto_map detection (M5)
      archive.py             # zip/archive smuggling (M6)
      provenance.py          # signatures, hashes, model card (M7)
    mcp/
      __init__.py
      client.py              # connect + enumerate tools/resources/prompts
      descriptions.py        # tool-poisoning + injection heuristics (P1/P2/P3)
      permissions.py         # scope / capability analysis (P4/P5)
      secrets.py             # token/credential leakage (P6)
      integrity.py           # rug-pull/TOFU + transport/auth (P7/P8/P9)
  ai/
    __init__.py
    provider.py              # AIProvider protocol (analyze/summarize)
    ollama.py                # local, default, free
    openai_compat.py         # OpenAI/OpenRouter/LM Studio/vLLM (BYO key/base_url)
    anthropic.py             # optional
    enrich.py                # where/how AI augments findings (opt-in)
  rules/
    model/*.yaml
    mcp/*.yaml
  fixtures/                  # INTENTIONALLY vulnerable, BENIGN test samples
    model/
    mcp/
  templates/                 # html report templates
tests/
docs/
  PROJECT_REFERENCE.md       # the deep design doc — source of truth
README.md
pyproject.toml
```

---

## Build phases (do them in order; each ends demoable)

Treat each phase as a goal to drive to completion, verify with tests, then stop for review.

### Phase 0 — Spine
- `core/findings.py`: `Severity` (INFO/LOW/MEDIUM/HIGH/CRITICAL), `Location`, `Finding`,
  `ScanResult` as pydantic models.
- `core/taxonomy.py`: the M/P category enum with title, description, references.
- `core/rules.py`: YAML rule schema + loader + a simple pattern/predicate matcher.
- `core/report/terminal.py` and `json_report.py`.
- `cli.py`: `airlock` app skeleton with `scan model` / `scan mcp` stubs and `rules list`.
- **Definition of done:** `airlock rules list` prints loaded rules; `airlock scan model <path>`
  returns an empty ScanResult and renders cleanly; tests cover schema + rule loading.

### Phase 1 — Model scanner (first shippable win)
- `scanners/model/loader.py`: accept a local path OR `hf:org/name`; discover artifact files.
- `pickle_scan.py`: disassemble with `pickletools`; flag `GLOBAL`/`REDUCE`/`INST`/`OBJ`/`STACK_GLOBAL`
  referencing dangerous callables; surface imported modules/functions (M1/M2/M3).
- `formats.py`: detect pickle-based vs safetensors; recommend safetensors (M4).
- `remote_code.py`: parse `config.json`/`*.json` for `trust_remote_code`, `auto_map`, and presence
  of `modeling_*.py` / custom code files (M5).
- `archive.py`: inspect zip members for unexpected executables/paths (M6).
- `provenance.py`: missing hashes/signature/model card (M7).
- Rule packs in `rules/model/*.yaml`.
- Benign vulnerable fixtures in `fixtures/model/`.
- **Definition of done:** `airlock scan model fixtures/model/poisoned` reports CRITICAL M1;
  `airlock scan model hf:<known-safetensors-model>` is clean; JSON output validates; tests pass.

### Phase 2 — MCP scanner (the headline)
- `client.py`: connect over stdio/SSE, enumerate tools/resources/prompts, capture raw schemas.
- `descriptions.py`: heuristics for tool poisoning & injection — imperative instruction phrases,
  "ignore/override" patterns, hidden/zero-width/unicode-tag/homoglyph characters, links/eval hints
  (P1/P2/P3).
- `permissions.py`: flag shell/filesystem/network/wildcard scopes; cross-tool reachability (P4/P5).
- `secrets.py`: credentials/tokens in schemas or echoed env (P6).
- `integrity.py`: definition hashing for rug-pull/TOFU detection, transport/auth checks,
  name-collision/shadowing (P7/P8/P9).
- Rule packs in `rules/mcp/*.yaml`; benign fixture MCP server in `fixtures/mcp/`.
- **Definition of done:** `airlock scan mcp <fixture-server>` reports P1 + P4; clean server is clean.

### Phase 3 — Release polish
- `report/html.py` + `report/sarif.py`; `--format` flag; non-zero exit on threshold.
- GitHub Action wrapper; README with demo GIF and real findings; `CONTRIBUTING.md` for rule packs.

### Phase 4 — Optional AI enrichment (only after 0–3 are solid)
- Implement `ai/` per `docs/PROJECT_REFERENCE.md` §AI. Gate behind `--ai` and config. Default OFF.

---

## Working style for the agent

- Describe-the-outcome prompts drive best results here; build a whole phase, run the tests, and
  verify against the Definition of Done before moving on.
- Prefer editing/extending the schema and rule engine over hardcoding checks.
- When writing anything that resembles an exploit (fixtures, attack-pattern detectors), keep it
  **detection-oriented and benign** per Principle 1. If a request would produce a genuinely harmful
  artifact, stop and implement the *detector* and a *harmless* fixture instead.
- Keep `docs/PROJECT_REFERENCE.md` authoritative; if you make a design decision, update it.
- Small commits per component with clear messages; every new detector ships with a fixture + test.

---

## Rename

Project name is `Airlock`. To rename, find/replace `airlock`/`Airlock` across the repo and the
package directory. Nothing depends on the name semantically.
