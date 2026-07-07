# Manifest

**AI-BOM generator for AI systems.** Part of the [Bulwark](../../README.md) suite — *Airlock scans the
parts, Warden scans the assembly, Manifest inventories it all.*

You can't govern what you can't see. Point Manifest at an AI project and it discovers every component —
models, datasets, MCP servers, prompts, tools, dependencies — resolves provenance/version/license,
attaches risk by calling **Airlock** on the parts and **Warden** on the assemblies, and emits a
standards-based **CycloneDX** AI-BOM plus a governance report.

```bash
manifest scan ./project --format cyclonedx           # standards-based ML-BOM (JSON)
manifest scan ./project --scan-risk --govern         # + Airlock/Warden risk + NIST AI RMF report
manifest scan ./project --format md --govern         # human governance summary + risk register
manifest components ./project                         # list discovered components
```

## What it catches (B-codes)

| Code | Governance finding |
| --- | --- |
| **B1** | Undeclared / unpinned component |
| **B2** | Missing provenance |
| **B3** | License risk (restrictive / copyleft / unknown) |
| **B4** | Known-vulnerable dependency (via OSV) |
| **B5** | High-risk component (imported from Airlock / Warden) |
| **B6** | Dataset governance gap |
| **B7** | Secret / credential reference exposure |
| **B8** | Unversioned / untracked prompt template |
| **B9** | Compliance control gap (NIST AI RMF mapping, advisory) |

## How it works

**Discoverers** statically inventory the project into an **AIBOM** IR (models, datasets, MCP servers,
prompts, tools, dependencies). **Resolvers** attach provenance, classify licenses, and query **OSV**
for dependency vulnerabilities (with an `--offline` seed for CI). A governance analysis emits B-code
signals that **YAML rule packs** turn into findings. With `--scan-risk`, the **bridges** run Airlock on
model/MCP components and Warden on discovered assemblies and surface their M/P/A findings inline as
B5. With `--govern`, findings map to the **NIST AI RMF** functions (advisory) and a **risk register**
is produced. Everything reuses `bulwark-core` (findings, rule engine, reports, AI). Output is
**CycloneDX** (primary), JSON, HTML, SARIF, or Markdown.

## Safety

Discoverers **parse statically and never execute** the target project. Fixtures are benign sample
projects; any "secret" is an obvious inert placeholder. See
[`docs/PROJECT_REFERENCE_MANIFEST.md`](../../docs/PROJECT_REFERENCE_MANIFEST.md).
