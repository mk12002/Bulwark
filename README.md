# Bulwark

**The security stack for agentic AI: Airlock scans the parts, Warden scans the assembly, Manifest inventories it all.**

Modern AI agents are assembled from third-party parts — model artifacts, MCP servers, tool
definitions — and wired into systems that then act semi-autonomously. Almost nobody inspects them
first. Bulwark is a three-tool suite that audits the whole agentic supply chain, from the individual
components up to the governable whole.

| Tool | Scope | Question it answers | Status |
| --- | --- | --- | --- |
| **[Airlock](packages/airlock/)** | the *parts* | Is this model / MCP server / tool-spec itself malicious or unsafe? | **shipped (v0.1)** |
| **Warden** | the *assembly* | Given how I wired the agent, does it have too much power? | planned |
| **Manifest** | the *whole system* | What is my AI system made of, and is it governable? | planned |

They compose: **Manifest** builds an inventory and calls **Airlock** on each model/MCP server and
**Warden** on each agent assembly, then aggregates everything into one governance artifact (an AI-BOM).

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
    bulwark-core/           · the shared spine (extracted as step 1 of the Warden build)
    airlock/                · tool 1 — shipped
    warden/                 · tool 2 — planned
    manifest/               · tool 3 — planned
```

## Quickstart (Airlock)

```bash
pip install -r requirements.txt          # editable install of the workspace
airlock scan model    ./path/to/model    # pickle, safetensors, GGUF, ONNX, Keras, npy…
airlock scan mcp      "python server.py" # an MCP server over stdio, or an sse/http URL
airlock scan toolspec tools.json         # OpenAI / Anthropic / LangChain tool definitions
airlock study         corpus.txt         # scan many targets → aggregate stats
```

Airlock is a defensive tool: it detects and reports risks, never executes the artifacts it scans, and
its test fixtures use benign, inert markers only. Full details in
**[packages/airlock/README.md](packages/airlock/README.md)**.

## Roadmap

1. **Airlock** — model + MCP + tool-spec scanning, YAML rule packs, SARIF/CI, optional AI enrichment. *(done)*
2. Extract **`bulwark-core`** from Airlock (per BULWARK.md), then build **Warden** (agent-assembly least-privilege analysis).
3. Build **Manifest** (system inventory + CycloneDX AI-BOM; orchestrates Airlock + Warden).
