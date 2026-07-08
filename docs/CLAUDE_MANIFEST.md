# CLAUDE.md — Manifest

> Build instructions for Claude Code (Fable 5) building the **Manifest** package inside the **Bulwark**
> monorepo. Read `BULWARK.md` (suite + monorepo + shared `bulwark-core` contract) and
> `docs/PROJECT_REFERENCE_MANIFEST.md` (deep design) first. Build Manifest last: it depends on
> `bulwark-core`, **Airlock**, and **Warden**.
>
> **Status: all five build phases below are complete (v0.1, tested green).** Beyond the base plan,
> Manifest also ships a notebook discoverer (`discover/notebooks.py`), SPDX 2.3 output (`bom/spdx.py`),
> EU AI Act mapping alongside NIST AI RMF (`govern/controls.py`), and BOM diff (`bom/diff.py`,
> `manifest diff`).

---

## What Manifest is

**Manifest is an AI-BOM (bill-of-materials) generator for AI systems.** You can't govern what you
can't see. Point Manifest at an AI project/repo and it discovers every component — models, datasets,
MCP servers, prompt templates, tools, and dependencies — resolves provenance/version/license, attaches
risk (by calling **Airlock** on parts and **Warden** on assemblies), and emits a standardized,
interoperable bill-of-materials plus a governance report.

It is the inventory + governance layer of Bulwark, and the aggregator that ties the suite together.

CLI-first. Deterministic-first. AI enrichment optional and off by default (reuses `bulwark_core.ai`).

---

## Non-negotiable principles (inherited from Bulwark)

1. **Defensive/governance only.** Manifest inventories and flags risk. Fixtures use benign sample
   projects. No weaponization.
2. **Deterministic first, AI second.** Fully useful with zero AI. AI only enriches (BOM summary,
   component-purpose inference, control-mapping prose, risk-register drafting). Never required.
3. **Local-first & free.** No paid infra. Dependency vuln lookups use the free OSV API (offline mode
   supported). AI defaults to local Ollama via `bulwark_core.ai`.
4. **Standards-based output.** Emit **CycloneDX** JSON (with ML/AI components) as the primary machine
   format — not a bespoke schema — so existing SBOM tooling can consume it. Also emit human-readable
   HTML/Markdown + the raw JSON.
5. **Reuse `bulwark-core`, Airlock, Warden.** Import findings/report/AI from core; call Airlock and
   Warden as libraries for risk. Do not re-implement scanning.
6. **Explainable + CI-friendly.** Governance findings carry what/where/why/severity/remediation/ref.
   `--fail-on` threshold exit code for pipelines.

---

## Tech stack & conventions

Bulwark defaults: Python 3.11+, `typer`, `rich`, `pydantic` v2, `pyyaml`, `jinja2` (via core), `ruff`,
`mypy` (strict on `manifest/`), `pytest` (≥85% on core logic). CycloneDX via the official
`cyclonedx-python-lib` if suitable, else a thin typed emitter. Dependency vulns via the **OSV** HTTP
API (cache + `--offline`). Discoverers parse statically; **never execute target project code**.

Dev commands (from repo root):
```bash
uv sync
ruff format . && ruff check .
mypy packages/manifest/manifest
pytest packages/manifest -q
manifest --help
```

---

## Package layout (`packages/manifest/`)

```
manifest/
  __init__.py
  cli.py                     # manifest scan <project> [--format ...] [--fail-on ...] [--scan-risk] [--ai]
  bom/
    model.py                 # AIBOM IR: Component, Provenance, License, Relationship (pydantic)
    cyclonedx.py             # AIBOM → CycloneDX 1.5 JSON (ML/AI components)
    spdx.py                  # AIBOM → SPDX 2.3 JSON (--format spdx)
    diff.py                  # diff_boms: AI-BOM drift (added/removed/changed) → `manifest diff`
    render.py                # human-readable HTML/Markdown BOM (via core report)
  discover/
    __init__.py              # discoverer registry (run all, merge components)
    models.py                # from_pretrained / model ids / local weight files → model components
    datasets.py              # dataset loads / data files / hf datasets → dataset components
    mcp.py                   # .mcp.json / client configs → mcp-server components
    prompts.py               # prompt files/templates/system prompts → prompt components
    tools.py                 # exposed tools/functions → tool components
    deps.py                  # requirements/pyproject/package.json → dependency components
    notebooks.py             # .ipynb cells → model/dataset/library components (location=path#cellN)
  resolve/
    provenance.py            # source/author/hash/version resolution
    licenses.py              # license detection + compatibility/risk
    vulns.py                 # OSV lookups for dependency components
  risk/
    airlock_bridge.py        # call Airlock on model/mcp components → findings
    warden_bridge.py         # call Warden on discovered assemblies → findings
  govern/
    controls.py              # map findings/gaps → NIST AI RMF *and* EU AI Act [advisory]
    report.py                # governance summary (incl. EU AI Act section) + risk register
  rules/
    manifest/*.yaml          # B1..B9 governance rule packs
  fixtures/
    sample_project_clean/
    sample_project_risky/
  templates/
tests/
```

`manifest.scanner.ManifestScanner` subclasses `bulwark_core.scanner.Scanner`.

---

## Build phases (in order; each demoable)

### Phase 0 — AIBOM IR + discoverers + CycloneDX
- `bom/model.py`: the AIBOM IR (see `docs/PROJECT_REFERENCE_MANIFEST.md` §4).
- `discover/*`: models, deps, mcp, prompts (start with these four); a registry that runs all and
  merges into an AIBOM.
- `bom/cyclonedx.py`: emit valid CycloneDX JSON with ML/AI component types.
- **DoD:** `manifest scan fixtures/sample_project_clean` lists components across ≥3 types and writes
  valid CycloneDX; tests cover IR + discoverers + CycloneDX shape (golden file).

### Phase 1 — Provenance, licenses, dependency vulns (governance findings)
- `resolve/provenance.py`, `resolve/licenses.py`, `resolve/vulns.py` (OSV, cached, `--offline`).
- `rules/manifest/*.yaml` for B1–B4, B6–B8; wire to `bulwark_core.rules`.
- **DoD:** `manifest scan fixtures/sample_project_risky` reports B3 (license risk) + B4 (vulnerable dep)
  + B1/B2 (unpinned/missing provenance); JSON + SARIF validate.

### Phase 2 — Risk bridges (compose the suite)
- `risk/airlock_bridge.py`: run Airlock on each model/mcp component; attach findings as B5.
- `risk/warden_bridge.py`: run Warden on any discovered agent assembly; attach findings as B5.
- Merge all into the BOM so each component carries its risk. Gated by `--scan-risk`.
- **DoD:** with `--scan-risk`, a risky model in the fixture shows Airlock's M-findings inline in the
  BOM; an over-privileged assembly shows Warden's A-findings.

### Phase 3 — Governance layer + reports
- `govern/controls.py`: map findings/gaps to a control framework (NIST AI RMF functions), advisory,
  B9. `govern/report.py`: governance summary + risk register.
- HTML/Markdown BOM + governance report; `--fail-on`.
- **DoD:** `manifest scan ... --govern` prints a control-coverage summary + risk register; HTML report
  renders the full BOM with risk badges.

### Phase 4 — Optional AI enrichment
- Use `bulwark_core.ai` to: summarize the BOM into an executive/governance narrative, infer component
  purposes, and phrase control-mapping rationale + a draft risk register. Gated by `enabled AND --ai`.
  Default OFF.

---

## Working style for the agent

- Outcome-first; build a phase, verify DoD, stop for review.
- Discoverers parse statically; never execute or import the target project.
- Reuse Airlock/Warden as libraries via the bridges — do not duplicate their logic.
- Prefer the standard (CycloneDX) over inventing a schema; keep the internal IR clean and map to it.
- Every discoverer/resolver/finding ships with a fixture + test asserting on component type or
  `category`+`severity`.
- Keep `docs/PROJECT_REFERENCE_MANIFEST.md` authoritative; update on design change.

## Rename
Package name is `manifest`. Find/replace to rename; nothing depends on the name semantically.
