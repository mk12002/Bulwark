# 📋 Manifest

**AI-BOM generator + governance for AI systems.** The third tool and the **aggregator** of the
[Bulwark](../../README.md) suite — *Airlock scans the parts, Warden scans the assembly, Manifest
inventories it all.*

You can't govern what you can't see. Point Manifest at an AI project and — in one command — it
discovers every component (models, datasets, MCP servers, prompts, tools, dependencies, **notebooks**),
resolves provenance / version / license, queries **OSV** for vulnerable deps, attaches risk by calling
**Airlock** and **Warden**, and emits a standards-based **CycloneDX** *or* **SPDX** AI-BOM plus a
governance report mapped to **NIST AI RMF** and the **EU AI Act**.

```bash
manifest scan ./project --format cyclonedx           # standards-based ML-BOM (or --format spdx)
manifest scan ./project --scan-risk --govern         # + Airlock/Warden risk inline + governance report
manifest scan ./project --format md --govern         # human governance summary + risk register
manifest components ./project                          # list discovered components
manifest diff  ./v1 ./v2                               # AI-BOM drift between two versions
```

## The whole suite in one command

`manifest scan --scan-risk` is where Bulwark's thesis becomes literal — the inventory *plus* Airlock's
findings on the parts *plus* Warden's findings on the assemblies, unified into one artifact:

```
$ manifest scan ./project --scan-risk --govern

  HIGH    B4  Known-vulnerable dependency (GHSA-6757-jp84-gxfx)   pyyaml 5.3.1   # OSV: CVE-2020-14343
  HIGH    B7  Secret/credential referenced in the project        settings.py
  HIGH    M2  Artifact uses pickle-based serialization  ◀── Airlock, inline on the model component
  MEDIUM  B3  Component has a restrictive license (cc-by-nc-4.0)  model/
  MEDIUM  B1  Component used without a pinned version             transformers
  MEDIUM  B6  Dataset lacks documented governance                data/train.csv
  ...
  → CycloneDX 1.5 written · NIST AI RMF: GOVERN/MAP/MEASURE gaps · EU AI Act: Art.10/13/15 gaps
```

## What it catches (B-codes)

| Code | Governance finding |
| --- | --- |
| **B1** | Undeclared / unpinned component |
| **B2** | Missing provenance |
| **B3** | License risk (restrictive / copyleft / unknown) |
| **B4** | Known-vulnerable dependency (via **OSV**) |
| **B5** ⭐ | High-risk component — **imported from Airlock / Warden** and surfaced inline |
| **B6** | Dataset governance gap |
| **B7** | Secret / credential reference exposure |
| **B8** | Unversioned / untracked prompt template |
| **B9** | Control gap (NIST AI RMF *and* EU AI Act mapping, advisory) |

## Discovers everything

Independent, additive discoverers inventory the project — adding a component type never touches the
others:

`models` (weight files + `from_pretrained` refs) · `datasets` (`load_dataset` + data files) ·
`mcp-servers` (`.mcp.json`) · `prompts` (templates + inline system prompts) · `tools` (function/tool
specs) · `dependencies` (requirements / pyproject / package.json, AI frameworks flagged) ·
**`notebooks`** (`.ipynb` cells → models, datasets, and `!pip install` packages).

## Standards-based output

- **CycloneDX 1.5** (`--format cyclonedx`) — ML/AI component types, purls, hashes, findings as
  properties. Drops into any SBOM tooling.
- **SPDX 2.3** (`--format spdx`) — for pipelines standardized on SPDX.
- **JSON / HTML / SARIF / Markdown** — the full `ScanResult` + AIBOM, a shareable report, code-scanning
  ingestion, or a human governance summary.

## Governance & drift

- `--govern` maps every finding to **NIST AI RMF** (Govern/Map/Measure/Manage) *and* **EU AI Act**
  articles (advisory — transparent and sourced, never a conformity claim), and produces a **risk
  register** (component → risk → severity → action).
- `manifest diff ./old ./new` shows **AI-BOM drift** — components added, removed, or changed
  (version bumps, re-licensing) — so a review focuses on the delta, not the whole inventory. Exits
  non-zero when anything changed, so you can gate on unexpected drift.

## How it works

**Discoverers** build the AIBOM statically → **resolvers** attach provenance, classify licenses, and
query OSV (with an `--offline` seed for deterministic CI) → a governance analysis emits B-code signals
that **YAML rule packs** turn into findings → with `--scan-risk`, the **bridges** run Airlock on
model/MCP components and Warden on assemblies and attach their findings as B5 → with `--govern`, the
control mapping + risk register are produced. Everything reuses `bulwark-core`.

## Safety

Discoverers **parse statically and never execute** the target project. Fixtures are benign sample
projects; any "secret" is an obvious inert placeholder. See
[`docs/PROJECT_REFERENCE_MANIFEST.md`](../../docs/PROJECT_REFERENCE_MANIFEST.md).
