# Bulwark

**The security stack for agentic AI: Airlock scans the parts, Warden scans the assembly, Manifest inventories it all.**

Modern AI agents are assembled from third-party parts — model artifacts, MCP servers, tool
definitions — and wired into systems that then act semi-autonomously. Almost nobody inspects them
first. Bulwark is a three-tool suite that audits the whole agentic supply chain, from the individual
components up to the governable whole.

| Tool | Scope | Question it answers | Status |
| --- | --- | --- | --- |
| **[Airlock](packages/airlock/)** | the *parts* | Is this model / MCP server / tool-spec itself malicious or unsafe? | **shipped (v0.1)** |
| **[Warden](packages/warden/)** | the *assembly* | Given how I wired the agent, does it have too much power? | **shipped (v0.1)** |
| **[Manifest](packages/manifest/)** | the *whole system* | What is my AI system made of, and is it governable? | **shipped (v0.1)** |

They compose — literally: **Manifest** builds an inventory and, with `--scan-risk`, calls **Airlock**
on each model/MCP component and **Warden** on each agent assembly, surfacing their findings inline in
one CycloneDX AI-BOM + governance report.

## Why a monorepo

All three share a spine — `Finding` / `Severity` / the YAML rule engine / report renderers
(terminal, JSON, HTML, SARIF) / the optional AI provider layer — meant to live once in
`packages/bulwark-core` and be reused three times. Manifest hard-depends on Airlock and Warden.
Each tool still ships its own CLI (`airlock`, `warden`, `manifest`) and is independently installable.
See **[BULWARK.md](BULWARK.md)** for the full design and the shared-core contract.

## Layout

```
bulwark/
  README.md                 · this file
  BULWARK.md                · suite design + shared-core contract
  pyproject.toml            · workspace declaration
  requirements.txt          · dev install for the whole workspace
  docs/                     · per-tool deep-design references
  packages/
    bulwark-core/           · the shared spine (findings, rule engine, reports, AI layer)
    airlock/                · tool 1 — shipped (models · MCP servers · tool-specs)
    warden/                 · tool 2 — shipped (agent-assembly least-privilege audit)
    manifest/               · tool 3 — shipped (AI-BOM · CycloneDX · governance · risk bridges)
```

## Quickstart (Airlock)

```bash
pip install -r requirements.txt          # editable install of the workspace
airlock scan model    ./path/to/model    # pickle, safetensors, GGUF, ONNX, Keras, npy…
airlock scan mcp      "python server.py" # an MCP server over stdio, or an sse/http URL
airlock scan toolspec tools.json         # OpenAI / Anthropic / LangChain tool definitions

warden  audit agent.yaml --recommend     # audit an agent assembly + suggest a least-privilege version

manifest scan ./project --format cyclonedx          # a standards-based ML-BOM of a whole AI project
manifest scan ./project --scan-risk --govern        # + Airlock/Warden risk inline + NIST AI RMF report
```

All three tools are defensive: they detect and report risks, never execute/import the artifacts they
scan, and their fixtures use benign, inert markers only. Details in each package README:
**[airlock](packages/airlock/README.md)** · **[warden](packages/warden/README.md)** ·
**[manifest](packages/manifest/README.md)**.

## Roadmap

1. **Airlock** — model + MCP + tool-spec scanning, YAML rule packs, SARIF/CI, optional AI enrichment. *(done)*
2. **`bulwark-core`** extracted; **Warden** — agent-assembly least-privilege audit (A1–A10, capability graph, agency score, recommendation). *(done)*
3. **Manifest** — AI-BOM generator (CycloneDX), provenance/license/OSV-vuln resolution, B1–B9 governance, Airlock/Warden risk bridges, NIST AI RMF mapping. *(done)*
4. Next: PyPI publishing, empirical corpus studies across all three tools, and the AI-BOM drift/diff mode.
