<div align="center">

# 🛡️ Bulwark

### The security stack for agentic AI

**Airlock scans the parts · Warden scans the assembly · Manifest inventories it all.**

*One engine, one taxonomy, one report format — three tools that audit the whole AI agent supply chain,
from the individual components up to the governable whole.*

`models` · `MCP servers` · `tool-specs` · `agent assemblies` · `datasets` · `prompts` · `dependencies`

</div>

---

## The problem

A modern AI agent is assembled from third-party parts you didn't write and can't see inside — a
model off the Hub, an MCP server from a gist, a pile of tools wired into an autonomous loop, a
`requirements.txt` nobody audited. Each is a trust boundary. Almost nobody inspects them. And a system
built entirely from *individually benign* parts can still be dangerous because of **how they're wired
together**.

Bulwark is three composable scanners that answer the three questions you actually need answered:

| Tool | Scope | The question it answers | Status |
| --- | --- | --- | :---: |
| 🔒 **[Airlock](packages/airlock/)** | the **parts** | Is this model / MCP server / tool-spec itself malicious or unsafe? | ✅ v0.1 |
| ⚖️ **[Warden](packages/warden/)** | the **assembly** | Given how I wired the agent, does it have more power than its job needs? | ✅ v0.1 |
| 📋 **[Manifest](packages/manifest/)** | the **whole system** | What is my AI system made of, and is it governable? | ✅ v0.1 |

And they **compose — literally**. `manifest scan --scan-risk` builds an inventory of your project, then
calls Airlock on each model/MCP component and Warden on each agent assembly, and folds their findings
inline into one **CycloneDX AI-BOM** with a governance report. The suite's thesis, made real in one
command.

```
                Airlock  ── scans ──▶  models · MCP servers · tool-specs        (M1–M7, P1–P9)
   your AI  ──▶ Warden   ── scans ──▶  agent assemblies (tools, scopes, prompt) (A1–A10)
   project      Manifest ── inventories everything, calls Airlock + Warden ──▶  CycloneDX + governance (B1–B9)
```

## Try it (60 seconds)

```bash
pip install -r requirements.txt   # editable install of the whole workspace

# One front door over all three tools:
bulwark  scan ./project                              # inventory + Airlock/Warden risk + governance, in one shot
bulwark  airlock scan model hf:org/name              # or drive each tool directly ↓

airlock  scan model    hf:org/name                  # a HuggingFace model (pickle? safetensors? GGUF? ONNX? TF?)
airlock  scan mcp      "python server.py"            # a live MCP server over stdio (or an sse/http URL)
airlock  scan toolspec tools.json                    # OpenAI / Anthropic / LangChain tool definitions

warden   audit agent.yaml --recommend                # audit an agent + rewrite it to least-privilege
warden   audit agent.yaml --profile permissive       # blockers-only posture (strict|balanced|permissive)
warden   import langchain_agent.py                    # normalize a LangChain / CrewAI / Assistants config

manifest scan ./project --format cyclonedx           # a standards-based ML-BOM of a whole project
manifest scan ./project --scan-risk --govern         # + Airlock/Warden risk inline + NIST AI RMF + EU AI Act
```

Every tool is **deterministic-first** (fully useful with zero AI), **CI-friendly** (`--fail-on`
exit codes + SARIF for GitHub code scanning), and **defensive-only**: it *detects and reports*, never
executes or imports the artifacts it scans, and every test fixture uses benign, inert markers.

## What's inside

<table>
<tr><td valign="top" width="33%">

**🔒 Airlock** — the parts
- **M1–M7** model risks: pickle RCE (static opcode disasm), unsafe formats, `trust_remote_code`, archive smuggling + zip-bombs, provenance & hash verification
- **P1–P9** MCP risks: tool poisoning, hidden unicode, over-permissioned tools, cross-tool exfil graph, secrets, rug-pull, transport, shadowing
- formats: pickle · safetensors · GGUF · **ONNX** · **Keras** · **numpy** · **TF SavedModel** · **Flax** · compressed/nested
- **tool-spec** scanning (OpenAI/Anthropic/Bedrock/LangChain)

</td><td valign="top" width="33%">

**⚖️ Warden** — the assembly
- **A1–A10** excessive-agency: toxic tool combinations (source→sink graph), missing human gates, unsandboxed exec, open egress, runaway loops…
- a transparent **agency score (0–100)**
- importers: manifest YAML · MCP config · **OpenAI Assistants** · **LangChain/LangGraph** · **CrewAI**
- **least-privilege recommendation**: rewrites an over-privileged agent + shows a before/after diff
- `--scan-parts` runs Airlock on the MCP servers it wires

</td><td valign="top" width="33%">

**📋 Manifest** — the system
- discovers **models · datasets · MCP servers · prompts · tools · deps · notebooks**
- **CycloneDX** *and* **SPDX** AI-BOM output
- **B1–B9** governance: unpinned, provenance, license, OSV vulns, secrets, dataset gaps…
- risk **bridges** to Airlock + Warden (B5)
- **NIST AI RMF** *and* **EU AI Act** control mapping + risk register
- **BOM drift** (`manifest diff`) between versions

</td></tr>
</table>

Every finding is explainable — *what* was found, *where*, *why it matters*, a *severity*, a
*remediation*, and a *reference* (OWASP LLM Top 10 / MITRE ATLAS / CWE / NIST AI RMF).

## Architecture

```
bulwark/                      · uv-workspace monorepo
  packages/
    bulwark-core/             · the shared spine — Finding/Severity model, YAML rule engine,
                              ·   report renderers (terminal/JSON/HTML/SARIF), optional AI layer
    airlock/    depends on ──▶ bulwark-core
    warden/     depends on ──▶ bulwark-core   (+ airlock, optionally, for --scan-parts)
    manifest/   depends on ──▶ bulwark-core, airlock, warden
    bulwark/    depends on ──▶ all of the above · the `bulwark` meta-CLI (one front door)
```

Run the whole quality gate with one command — `python check.py` (ruff + mypy + pytest across every
package, each with its own config) — or `nox`.

Detection lives in **YAML rule packs**, not hardcoded — the community can extend any tool with a PR
(`<tool> rules update`). The optional AI layer (local Ollama by default, BYO OpenAI/Anthropic) is
**off by default**, capped, keys-from-env-only, and never overrides a deterministic finding. See
**[BULWARK.md](BULWARK.md)** for the full design and the shared-core contract.

## Why it's credible

- **Standards-based** — CycloneDX ML-BOM + SPDX, SARIF for code scanning, OWASP LLM Top 10 / MITRE
  ATLAS / CWE / NIST AI RMF / EU AI Act references throughout.
- **Measured, not asserted** — validated on **19 real public HuggingFace models** (100% had a
  supply-chain finding; 95% ship pickle weights), a **13-payload adversarial suite** Airlock catches
  **13/13**, and a head-to-head **benchmark vs. picklescan** (13/13 vs 9/13 on evasive payloads; both
  0/18 false alarms on benign models). Full methodology + reproduction:
  [`docs/EMPIRICAL_VALIDATION.md`](docs/EMPIRICAL_VALIDATION.md).
- **Reproducible research angle** — each tool ships a corpus/study harness for an empirical measurement
  of AI-supply-chain hygiene ("we scanned N public artifacts and X% were vulnerable").
- **Green everywhere** — 5 packages, 200+ tests, ruff + mypy + pytest all passing via one command
  (`python check.py`), matrixed in CI.

## Roadmap

1. ✅ **Airlock** — models · MCP · tool-specs, 40 rules, hardened parsers, SARIF/CI, optional AI.
2. ✅ **`bulwark-core`** extracted; **Warden** — least-privilege audit, capability graph, agency score, framework importers, `--scan-parts`, policy profiles.
3. ✅ **Manifest** — CycloneDX + SPDX AI-BOM, OSV vulns, B1–B9, Airlock/Warden bridges, NIST AI RMF + EU AI Act, BOM diff.
4. ✅ **`bulwark` meta-CLI** + empirical validation (real-model corpus study, adversarial suite, picklescan benchmark) + matrixed CI.
5. ⏭️ PyPI publishing · a larger cross-tool corpus study · a hosted BOM dashboard.

<div align="center">
<sub>Bulwark is a defensive security project. It detects and reports risk; it never weaponizes.
Fixtures are benign and inert by design.</sub>
</div>
