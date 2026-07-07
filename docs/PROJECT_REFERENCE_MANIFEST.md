# Manifest — Project Reference & Design Document

*AI-BOM generator for AI systems. Inventory everything.*

Part of the **Bulwark** suite (see `BULWARK.md`). Manifest reuses `bulwark-core` (findings, severity,
rules, report, AI) and composes **Airlock** (parts) and **Warden** (assembly) as risk backends. This
document is the source of truth for Manifest's design. Build it last.

---

## 1. Thesis & positioning

Governance starts with visibility. A modern AI system is an unlabeled pile of models, datasets, MCP
servers, prompt templates, tools, and libraries — usually with no single record of what's inside,
where it came from, or whether it's safe. **Manifest produces that record**: a standardized AI bill-of-
materials with provenance, licenses, versions, and risk, so the system can be governed, audited, and
trusted.

It is the governance/GRC layer of Bulwark and the **aggregator**: Manifest = the inventory **plus**
Airlock's findings on the parts **plus** Warden's findings on the assembly, unified into one artifact.
That composition is the suite's story made literal.

### 1.1 Prior art / positioning

- **SBOM** (software bill-of-materials) is mature; **CycloneDX** and **SPDX** now have **ML/AI and
  dataset** extensions. Manifest rides these standards rather than inventing a schema.
- **AI-BOM** as a practice is emerging (regulatory pressure: NIST AI RMF, EU AI Act). Tooling that
  actually *generates* an AI-BOM from a real repo — with integrated risk from dedicated scanners — is
  scarce.
- Manifest's edge: automatic discovery across all AI component types, **standards-based output
  (CycloneDX)**, **integrated risk** from Airlock + Warden, and a **control-framework mapping** for
  governance. This is the Module-18 GRC-meets-architecture differentiator in tool form.

---

## 2. What Manifest discovers

Point it at a project directory (a repo). Discoverers statically inspect code and config — **never
execute it** — and each emits components:

- **Models** (`discover/models.py`): `from_pretrained("org/name")`, model IDs in code/config, local
  weight files (`.safetensors`/`.bin`/`.gguf`/…), framework model refs.
- **Datasets** (`discover/datasets.py`): `load_dataset(...)`, data files, HF dataset refs, data dirs.
- **MCP servers** (`discover/mcp.py`): `.mcp.json` / client configs → server + tool components.
- **Prompt templates** (`discover/prompts.py`): prompt files, template strings, system prompts.
- **Tools/functions** (`discover/tools.py`): functions/tools exposed to an agent.
- **Dependencies** (`discover/deps.py`): `requirements.txt`, `pyproject.toml`, `package.json` —
  flag AI/ML libs specifically, but inventory all.

Discoverers are additive and independent; the registry runs all and merges into one AIBOM. Adding a
component type never touches existing ones.

---

## 3. Governance taxonomy (B-codes)

Manifest's findings are governance/inventory findings (distinct from Airlock's `M*`/`P*` and Warden's
`A*`, which it *imports* as B5).

**B1 — Undeclared/unpinned component.** *(MEDIUM)* Model/dataset/dep used without a pinned
version/hash (non-reproducible, drift risk). **Ref:** SLSA, supply-chain hygiene.

**B2 — Missing provenance.** *(MEDIUM)* Component with no verifiable source/author/hash. **Ref:**
NIST AI RMF (Map/Measure), SLSA.

**B3 — License risk.** *(MEDIUM–HIGH)* Restrictive/incompatible/unknown license on a model, dataset,
or dependency (e.g. non-commercial model in a commercial product, copyleft conflict, missing license).
**Detect:** `resolve/licenses.py` + compatibility matrix. **Ref:** license compliance.

**B4 — Known-vulnerable dependency.** *(severity from advisory)* A dependency with a known CVE via
**OSV**. **Detect:** `resolve/vulns.py`. **Ref:** OSV, CWE by advisory.

**B5 — High-risk component (from Airlock/Warden).** *(inherited severity)* A model/MCP server Airlock
flagged, or an assembly Warden flagged, surfaced inline on the component. **Detect:** `risk/*bridge.py`
with `--scan-risk`. **Ref:** OWASP LLM05/LLM06.

**B6 — Dataset governance gap.** *(MEDIUM)* Dataset without documented source/license/consent
(data-provenance / privacy relevance). **Ref:** NIST AI RMF, data governance.

**B7 — Secret/credential reference exposure.** *(HIGH–CRITICAL)* Hardcoded or broadly-scoped secrets
referenced in the project. **Detect:** reuse core secret rules. **Ref:** CWE-798.

**B8 — Unversioned/untracked prompt template.** *(LOW–MEDIUM)* System/prompt templates not under
version control or lacking identifiers (change-management gap). **Ref:** governance best practice.

**B9 — Compliance control gap.** *(advisory)* Mapped gaps against a control framework (see §6).
**Ref:** NIST AI RMF; optionally EU AI Act articles.

---

## 4. AIBOM IR (Manifest-specific data model)

Findings/severity/report/AI come from `bulwark_core`. Manifest adds the BOM IR, which maps cleanly to
CycloneDX:

```python
class ComponentType(str, Enum):
    MODEL="model"; DATASET="dataset"; MCP_SERVER="mcp-server"; PROMPT="prompt"
    TOOL="tool"; LIBRARY="library"; FRAMEWORK="framework"; AGENT="agent"

class License(BaseModel):
    id: str | None = None                # SPDX id if known
    name: str | None = None
    risk: Literal["ok","restricted","copyleft","unknown"] = "unknown"

class Provenance(BaseModel):
    source: str | None = None            # hf repo, pypi, url, local
    author: str | None = None
    version: str | None = None
    hash: str | None = None
    pinned: bool = False

class Component(BaseModel):
    key: str                             # stable id (type + name + version)
    type: ComponentType
    name: str
    provenance: Provenance = Provenance()
    license: License = License()
    location: str | None = None          # where in the repo it was found
    findings: list[str] = []             # Finding ids attached to this component (B*/M*/P*/A*)
    metadata: dict = {}

class Relationship(BaseModel):
    src: str; rel: str; dst: str         # e.g. agent "uses" model; agent "wires" mcp-server

class AIBOM(BaseModel):
    project: str
    generated_at: datetime
    components: list[Component]
    relationships: list[Relationship] = []
    bulwark_version: str
```

`bom/cyclonedx.py` maps `AIBOM` → CycloneDX JSON, using ML/AI component types and attaching findings as
CycloneDX vulnerabilities/properties. Findings themselves remain `bulwark_core.Finding` objects in the
`ScanResult`; the BOM references them by id.

---

## 5. Resolution (provenance, licenses, vulns)

- **provenance.py:** resolve source/author/version/hash per component (HF Hub metadata for models/
  datasets; PyPI/registry metadata for deps; file hashes for local artifacts). Sets `pinned`.
- **licenses.py:** detect SPDX license; classify risk; run a small compatibility check against the
  project's declared license (flag conflicts → B3).
- **vulns.py:** query **OSV** for dependency components (batched, cached, `--offline` skips network) →
  B4 with advisory severity.

---

## 6. Governance layer

`govern/controls.py` maps discovered gaps/findings to a **control framework** — default **NIST AI RMF**
(Govern/Map/Measure/Manage functions) — producing a coverage summary and per-control status. This is
advisory (B9) and clearly labeled as guidance, not certification. Optionally extendable to EU AI Act
article mapping. `govern/report.py` emits a governance summary + a **risk register** (component → risk →
severity → recommended action) — exactly the artifact a security/GRC reviewer wants.

This is the intersection Mohit is positioning for: architecture + GRC. Keep the mapping transparent and
sourced (cite the framework), never overclaim compliance.

---

## 7. Reports & output

- **CycloneDX JSON** — primary machine format (interoperable).
- **JSON** — the full `ScanResult` + `AIBOM`.
- **HTML/Markdown** — human BOM with risk badges per component + governance summary.
- **SARIF** — governance findings for CI (ruleId = B-code; imported M/P/A findings included).
- `--fail-on SEV` gates pipelines.

---

## 8. AI enrichment (optional; reuse `bulwark_core.ai`)

Off by default; `enabled AND --ai`; capped; local Ollama default. Uses:
1. **Executive BOM summary:** turn the inventory + risk register into a short governance narrative.
2. **Component-purpose inference:** infer what a model/dataset/prompt is for, to sharpen governance.
3. **Control-mapping rationale:** phrase why a finding maps to a given control (advisory).
4. **Risk-register drafting:** propose owner/action language for each risk.
AI output tagged `source="ai"`; never changes deterministic component facts or finding severities;
degrades gracefully.

---

## 9. CLI

```
manifest scan <project-dir> [--format cyclonedx|json|html|sarif|md]
                            [--fail-on SEV] [--scan-risk] [--govern] [--offline] [--ai]
manifest components <project-dir>     # list discovered components (debug discoverers)
manifest rules list|lint
manifest version
```

`--scan-risk` enables the Airlock/Warden bridges; `--govern` adds the control mapping + risk register.

---

## 10. Testing & fixtures

- **Benign sample projects.** `sample_project_clean/` (pinned components, safetensors model, permissive
  licenses, clean deps) and `sample_project_risky/` (unpinned model → B1, non-commercial license → B3,
  a dep with a known OSV advisory → B4, a referenced secret → B7). No real secrets; use obvious fake
  placeholders.
- Golden-file tests for CycloneDX output shape and for the component inventory.
- Bridge tests use Airlock/Warden fixtures so risk attaches deterministically.
- Tests assert on component `type` and finding `category`+`severity`, not prose.

---

## 11. Release & community

README leads with a generated CycloneDX AI-BOM of a real sample project plus the risk register — the
"one command, full inventory + risk" moment. The standards angle (CycloneDX ML-BOM) gives instant
credibility with security/governance audiences. GitHub Action emits the BOM as a build artifact.
`CONTRIBUTING.md` invites discoverer + control-mapping PRs.

---

## 12. Roadmap

- **v0.1** — Phases 0–1 (discoverers, CycloneDX, provenance/license/vuln, B1–B4/B6–B8).
- **v0.2** — Phase 2 (Airlock/Warden bridges, B5).
- **v0.3** — Phase 3 (NIST AI RMF mapping, risk register, HTML, CI gate).
- **v0.4** — Phase 4 (AI enrichment).
- **v0.5+** — more discoverers (JS/TS agents, notebooks), SPDX output, EU AI Act mapping, diff mode
  (BOM drift between versions).

---

## 13. Research / talk angle

"An AI-BOM of N public AI repos: how many pin their models, how many ship unknown/ non-commercial
licenses, how many wire unscanned MCP servers." A reproducible governance measurement — pairs with
Airlock's and Warden's corpus studies into a single narrative about the state of AI supply-chain
hygiene. Strong talk material and a natural capstone paper for the suite.

---

## 14. References (verify current versions when building)

CycloneDX (ML-BOM / AI components) and SPDX (AI/dataset profiles); NIST AI Risk Management Framework;
EU AI Act (for optional mapping); OSV (dependency advisories); OWASP LLM Top 10 (LLM05/LLM06 for
imported risk); SLSA (provenance concepts); SPDX license list. Bulwark siblings: `PROJECT_REFERENCE_
AIRLOCK.md`, `PROJECT_REFERENCE_WARDEN.md`.
