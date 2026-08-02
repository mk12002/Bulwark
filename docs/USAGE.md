# Bulwark — Usage Guide

*The security stack for agentic AI: Airlock scans the parts, Warden scans the assembly, Manifest
inventories it all.* This is the practical, end-to-end guide — install, every command, output formats,
CI, configuration, and how the pieces compose.

- New here? Read this top to bottom.
- Want the design rationale? See [`BULWARK.md`](../BULWARK.md) and `docs/PROJECT_REFERENCE_*.md`.
- Want proof it works? See [`EMPIRICAL_VALIDATION.md`](EMPIRICAL_VALIDATION.md).

---

## 1. Install

Requires **Python 3.11+**. The repo is a monorepo of five packages installed editable.

```bash
git clone https://github.com/mk12002/Bulwark && cd Bulwark
python -m venv .venv && . .venv/Scripts/activate      # Windows; use .venv/bin/activate on macOS/Linux
pip install -r requirements.txt                        # installs all five packages with dev extras
```

This gives you four CLIs on your PATH: **`bulwark`**, **`airlock`**, **`warden`**, **`manifest`**.

Install a single tool standalone instead:

```bash
pip install -e packages/bulwark-core
pip install -e "packages/airlock[model,mcp]"           # extras: model (HF Hub), mcp (MCP SDK), ai
pip install -e packages/warden
pip install -e "packages/manifest[osv]"                # extra: osv (live vuln lookups)
```

Verify:

```bash
bulwark version        # bulwark 0.1.0 (airlock 0.1.0, warden 0.1.0, manifest 0.1.0)
```

---

## 2. The 60-second tour

```bash
# The whole suite in one command: inventory a project, fold in Airlock/Warden risk, govern it.
bulwark scan ./my-ai-project

# Or drive each layer directly:
airlock  scan model    hf:org/name          # is this model/part safe?
warden   audit agent.yaml --recommend        # does this agent have too much power?
manifest scan ./project --scan-risk --govern # what is my system made of, and is it governable?
```

Every tool is **deterministic-first** (fully useful with zero AI), **defensive-only** (it detects and
reports — it never executes or imports what it scans), and **CI-friendly** (`--fail-on` exit codes +
SARIF).

---

## 3. `bulwark` — the meta-CLI

One front door. Each tool is mounted as a subcommand with its flags unchanged, plus a whole-system
`scan`.

```bash
bulwark airlock  scan model hf:org/name      # == airlock scan model ...
bulwark warden   audit agent.yaml            # == warden audit ...
bulwark manifest scan ./project              # == manifest scan ...

bulwark scan ./project                       # full pipeline = manifest scan --scan-risk --govern
bulwark scan ./project --format cyclonedx --fail-on high
bulwark version
```

`bulwark scan` options: `--format terminal|cyclonedx|spdx|json|html|sarif|md`, `--fail-on SEV`,
`--offline`, `--ai`.

---

## 4. Airlock — scan the parts

Audits untrusted third-party components **before** they enter the agent environment: **model
artifacts**, **MCP servers**, and **agent tool-specs**.

### 4.1 Scan a model

```bash
airlock scan model ./path/to/model           # a local dir or file
airlock scan model hf:org/name               # fetch from the HuggingFace Hub (public repos, no key)
airlock scan model hf:org/name@a1b2c3d       # PIN to an immutable revision (reproducible scan)
airlock scan model model.bin --format json --fail-on high
airlock scan model ./m --baseline prev.json  # report only findings NEW since prev.json
airlock scan model ./m --strict              # allowlist mode: flag imports outside the ML allowlist
```

**Pin your `hf:` targets.** Without `@revision` a Hub reference resolves against a mutable git
branch — the publisher can force-push and change the weights under you, so the scan is neither
reproducible nor attributable to specific bytes. Unlike a PyPI version, which cannot be republished,
a Hub branch can be rewritten at any time. This is why an unpinned model is a materially stronger
finding than an unpinned package.

Formats understood: pickle (`.bin`/`.pt`/`.ckpt`/`.pkl`/joblib/dill) · safetensors · GGUF · ONNX ·
Keras (`.h5`/`.keras`) · numpy (`.npy`/`.npz`) · TensorFlow SavedModel (`.pb`) · Flax msgpack · PMML ·
gzip/zlib-compressed and base64-nested pickles.

Finds **M1–M7**: pickle code execution, unsafe deserialization surface, suspicious payload signatures
(incl. **format/extension spoofing** — a pickle disguised as `.safetensors`, the CVE-2025-10155 bypass
class), risky format, `trust_remote_code`/custom-op execution, archive smuggling, provenance gaps.

Options: `--format terminal|json|html|sarif`, `--fail-on SEV`, `--baseline PATH`, `--strict`, `--ai`,
`--quiet`. **`--strict`** enables a Fickling-style **allowlist**: any pickle import from a module
outside the expected ML set (torch/numpy/collections/…) is surfaced (M3) — catching novel callables a
denylist has never seen. Off by default to stay noise-free; also settable via `strict_allowlist` in
`airlock.toml`.

### 4.2 Scan an MCP server

```bash
airlock scan mcp "python server.py"          # a stdio command
airlock scan mcp "npx -y @scope/mcp-server"  # any stdio launcher
airlock scan mcp https://host/sse            # an SSE/HTTP endpoint
```

> ⚠️ **Scanning a stdio server starts it.** The protocol has no way to list a stdio server's tools
> without running it, so the server's own startup code executes with your privileges. Airlock never
> *invokes* a tool — there is no `tools/call` anywhere in the codebase — but it cannot prevent module
> import. Scan untrusted servers in a container or VM, or prefer the fully static
> `airlock scan toolspec` path (§4.3), which spawns nothing. The CLI prints this warning on the stdio
> path. Enumeration is bounded by `AIRLOCK_LIMIT_CONNECT_TIMEOUT` (default 20s), so an unresponsive
> server cannot hang a scan.

Finds **P1–P9**: tool poisoning, injection via output, hidden/obfuscated unicode, over-permissioned
tools, cross-tool exfiltration paths, secret leakage, rug-pull/TOFU, transport/auth, shadowing.

### 4.3 Scan a tool-spec

```bash
airlock scan toolspec tools.json             # OpenAI / Anthropic / Bedrock / LangChain tool defs
```

### 4.4 Empirical study over many targets

```bash
python packages/airlock/scripts/build_corpus.py    # download a real tiny-model corpus (optional)
airlock study datasets/corpus.txt --format markdown --out study.md
```

`corpus.txt` is one `kind target` per line (`model ./path`, `mcp "cmd"`, …). Produces prevalence,
category/severity histograms, and top rules with reproducibility metadata.

### 4.5 Rules

```bash
airlock rules list                           # all 42 rules
airlock rules show M1-shell-exec-callable     # one rule's detail
airlock rules stats                           # by target/category/severity
airlock rules lint                            # validate packs: schema, categories, AND signal names
airlock rules update --from <feed>            # install validated community rule packs

airlock rules debug model ./m                 # dump the signal bundle, no rules applied
airlock rules debug mcp "python server.py" --signal tool.
airlock rules debug toolspec tools.json
```

**`rules lint` validates signal names.** Every other class of rule error fails loudly at load — an
unregistered category, an unknown predicate, an invalid regex, a duplicate id. A mistyped
`match.signal` was the one that failed *silently*: no rule matched, nothing errored, and the
detection was simply absent. Each tool now declares the signals its analyzers emit, and lint rejects
a rule referencing anything outside that set. `warden rules lint` and `manifest rules lint` do the
same.

**`rules debug` is the first move when a rule stops firing.** It prints every signal the analyzers
produced for a target without applying any rules, so you can immediately tell whether the *evidence*
is missing or whether the rule's `match.signal` simply does not match what was emitted.

---

## 5. Warden — scan the assembly

Audits an *assembled* agent for excessive agency: given how you wired its tools, scopes, system
prompt, MCP servers, and autonomy, does it hold more power than its job needs?

### 5.1 Audit

```bash
warden audit agent.yaml                       # a manifest YAML/JSON
warden audit claude_desktop_config.json       # an MCP client config
warden audit langchain_agent.py               # a LangChain/LangGraph file (static parse)
warden audit crew/agents.yaml                 # a CrewAI crew
warden audit assistant.json                   # an OpenAI Assistants config
```

Finds **A1–A10**: excessive tool scope, ⭐ toxic tool combinations (sensitive-source → egress-sink
graph), missing human gates, over-broad prompt authority, open egress, embedded secrets, excessive
data access, unsandboxed exec, unscanned parts, no runaway guards. Reports a transparent **agency
score (0–100)** in the header.

Key options:

```bash
warden audit agent.yaml --recommend           # ALSO rewrite it to least-privilege + show a diff
warden audit agent.yaml --scan-parts          # ALSO run Airlock on each MCP server it wires in
warden audit agent.yaml --profile permissive  # posture: strict | balanced (default) | permissive
warden audit agent.yaml --format sarif --fail-on high
```

**Policy profiles** set how strict the audit is without rewriting a finding's real severity:

| Profile | Shows | Confidence |
| --- | --- | --- |
| `strict` | everything incl. INFO | all |
| `balanced` (default) | LOW and up | all |
| `permissive` | MEDIUM and up | medium/high only |

### 5.2 Inspect the normalized spec

```bash
warden import agent.yaml                       # print the normalized AgentSpec (debug importers)
warden rules list | lint
```

---

## 6. Manifest — inventory the whole system

Discovers every component in an AI project, resolves provenance/license/vulns, attaches risk from
Airlock + Warden, and emits a standards-based AI-BOM plus governance.

### 6.1 Scan a project

```bash
manifest scan ./project                                  # terminal summary
manifest scan ./project --format cyclonedx > bom.json    # CycloneDX 1.5 ML-BOM (agent components incl.)
manifest scan ./project --format spdx > bom.spdx.json    # SPDX 2.3
manifest scan ./project --format vex > vex.json          # CycloneDX VEX (detected vulns, exploitable)
manifest scan ./project --scan-risk                      # fold in Airlock/Warden findings (B5)
manifest scan ./project --scan-risk --govern             # + NIST AI RMF + EU AI Act + risk register
manifest scan ./project --format md --govern             # human governance report
manifest scan ./project --online                         # use the live OSV API (default is offline seed)
```

Discovers: models · datasets · MCP servers · prompts · tools · dependencies · **notebooks** (`.ipynb`) ·
**agents** (agent-manifest / OpenAI-Assistants / CrewAI configs → `agent` components with autonomy +
wired tools).
Finds **B1–B9**: unpinned/undeclared, missing provenance, license risk, OSV-known vulns, ⭐ high-risk
component (imported from Airlock/Warden), dataset gaps, secret exposure, untracked prompts, control
gaps.

### 6.2 Components & drift

```bash
manifest components ./project                  # list discovered components
manifest diff ./v1 ./v2                        # AI-BOM drift (added/removed/changed); exits non-zero on change
```

---

## 7. Output formats & CI

Every scanner shares the same renderers:

| Format | Use |
| --- | --- |
| `terminal` | rich, human-readable (default) |
| `json` | the full `ScanResult` (+ AgentSpec / AIBOM in meta) |
| `html` | a shareable report |
| `sarif` | GitHub/GitLab code scanning |
| `cyclonedx` / `spdx` / `vex` / `md` | Manifest only — BOMs, VEX, + governance |

**Gate a build** with `--fail-on`: exit is non-zero when any finding is at or above the threshold.

```bash
airlock  scan model hf:org/name --format sarif --fail-on high > airlock.sarif
warden   audit agent.yaml --fail-on high
manifest scan ./project --scan-risk --fail-on critical
```

**GitHub Actions** (Airlock ships a composite action, `packages/airlock/action.yml`):

```yaml
- uses: ./packages/airlock
  with: { scan-type: model, target: hf:org/name, format: sarif, output: airlock.sarif, fail-on: high }
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: airlock.sarif }
```

**Pre-commit** (`.pre-commit-hooks.yaml` provides `airlock-scan-model`, `airlock-scan-toolspec`,
`warden-audit`).

**Baseline / waivers** (Airlock): `--baseline prev.json` reports only regressions; `airlock.toml`
`suppress_rules` / `suppress_paths` mute advisory noise (suppressed counts still reported).

---

## 8. Optional AI enrichment

Off by default. Every finding is deterministic; AI only *enriches* (semantic triage, non-obvious toxic
combinations, executive summaries) and **never** downgrades or gates on a deterministic finding — its
output is tagged `source="ai"`.

Two switches are required: `[ai].enabled = true` in config **and** the `--ai` flag. Default provider is
a **local Ollama** server (no key, no egress). OpenAI-compatible and Anthropic providers are supported;
keys are read only from env (e.g. `AIRLOCK_AI_API_KEY`), never from disk — `AIConfig` deliberately has
no `api_key` field, so there is nowhere in a file to put one.

```bash
# airlock.toml
[ai]
enabled = true
provider = "ollama"
max_findings_to_enrich = 25

export AIRLOCK_AI_API_KEY=...                  # only for openai_compat / anthropic
airlock scan mcp "python server.py" --ai
```

`max_findings_to_enrich` bounds **every** provider call — semantic recall, per-finding triage, the
executive summary, and the model-card read all draw on one counter, so the documented cap is the real
cap. If AI is unreachable, the scan degrades gracefully to deterministic-only with a warning.

**Injection against the analyzer.** The text sent to the provider comes from the artifact being
scanned, so it is attacker-controlled by definition. It is fenced in `<untrusted_content>` markers
(forged markers are stripped) and the system prompt states the fence marks data. That removes the
cheapest version of the attack; the layer's blast radius is bounded regardless, because AI can add a
finding tagged `source="ai"` or annotate one, but can never remove, downgrade, or gate a
deterministic finding.

---

## 8a. Configuration

Precedence, highest first: **command-line flags → environment variables → the TOML file → defaults.**

Environment beats the file deliberately: env is the operator's channel (CI, containers), while a
committed config file may be controlled by the very repository being scanned and must never be able
to weaken a pipeline's settings.

Each tool reads its own file from the working directory — `airlock.toml`, `warden.toml`,
`manifest.toml` — and each has its own env prefix. Nested keys use a double underscore.

```toml
# airlock.toml
fail_on = "high"
output_format = "terminal"
strict_allowlist = false
suppress_rules = ["M4-*", "M7-*"]     # waive advisory families
suppress_paths = ["tests/*"]

[ai]
enabled = false
provider = "ollama"
base_url = "http://localhost:11434"
```

```bash
AIRLOCK_FAIL_ON=critical airlock scan model ./m     # env overrides the file
AIRLOCK_AI__ENABLED=true airlock scan mcp "..." --ai  # nested key: double underscore
WARDEN_PROFILE=permissive warden audit agent.yaml
```

**Resource limits** are environment-only and bound every parse (see §11):

| Variable | Default | Bounds |
| --- | --- | --- |
| `AIRLOCK_LIMIT_PICKLE_OPCODES` | 2,000,000 | pickle opcode flood |
| `AIRLOCK_LIMIT_ARCHIVE_MEMBERS` | 20,000 | archive member flood |
| `AIRLOCK_LIMIT_UNCOMPRESSED_BYTES` | 4 GiB | zip bomb (absolute) |
| `AIRLOCK_LIMIT_COMPRESSION_RATIO` | 100.0 | zip bomb (ratio) |
| `AIRLOCK_LIMIT_MEMBER_BYTES` | 512 MiB | per-member parse |
| `AIRLOCK_LIMIT_NESTED_BLOB_BYTES` | 8 MiB | base64 expansion |
| `AIRLOCK_LIMIT_MAX_FILES` | 100,000 | files enumerated in a target tree |
| `AIRLOCK_LIMIT_CONNECT_TIMEOUT` | 20.0 | seconds for a live MCP scan |
| `AIRLOCK_STATE_DIR` | `~/.airlock` | rug-pull baseline store (set it in CI) |

---

## 9. How the suite composes

```
bulwark scan ./project
  └─ manifest scan --scan-risk --govern
       ├─ discovers models · datasets · MCP · prompts · tools · deps · notebooks
       ├─ for each model / MCP component → runs AIRLOCK  → its M*/P* findings attach as B5
       ├─ for each agent assembly        → runs WARDEN   → its A*  findings attach as B5
       └─ emits CycloneDX/SPDX AI-BOM + NIST AI RMF + EU AI Act + risk register
```

`warden audit --scan-parts` composes one level down: Warden runs Airlock on the MCP servers an agent
wires in, turning the A9 "unscanned parts" advisory into concrete part-level findings.

---

## 10. Develop & validate

```bash
python check.py            # ruff + mypy + pytest across all 5 packages (each with its own config)
python check.py --fast     # skip mypy
python check.py airlock    # one package
nox                        # same gate via nox, if installed
```

Detection lives in **YAML rule packs** under each tool's `rules/` — add a rule pack, ship a benign
fixture + a test, open a PR. See `packages/airlock/CONTRIBUTING.md` for the rule schema, signal
catalog, and predicate reference.

---

## 11. Safety model

Bulwark is a **defensive** project. It *detects and reports* risk; it never executes the artifacts it
scans — no `pickle.load`, no `torch.load`, no importing repo code, no invoking MCP tools; models are
inspected via static opcode disassembly, configs via static parsing. Every test fixture that simulates
a malicious artifact uses **benign, inert markers** only (e.g. an `echo` of a sentinel string).

A scanner that ingests hostile files must not become the attack, so the controls are layered:

| Layer | Control |
| --- | --- |
| **Never execute** | `pickletools.genops` not `pickle.load`; `ast.literal_eval` not `eval`; `yaml.safe_load` not `yaml.load`; configs parsed as data; LangChain files regex-parsed, never imported; `tools/list` only, never `tools/call` |
| **Never extract** | archives are analysed from the central directory; the rule feed is the one writer, with resolved-path containment, a `.yaml` allowlist, size caps, and streamed copies |
| **Bound everything** | opcodes, archive members, compression ratio, per-member and total size, nested blobs, regex input, evidence length, **files walked**, and **connection time** — all named limits with `AIRLOCK_LIMIT_*` overrides |
| **Contain traversal** | directory walks resolve each entry and require it to stay under the scan root, so a symlink to `/` cannot turn a scan into a filesystem traversal |
| **Fail safe** | every parser catches its errors and records them; a malformed artifact yields a partial result, never a crash — a crash-on-malformed-input scanner is itself a DoS vector |
| **Output safety** | HTML autoescape is *forced* on (the `.j2` suffix would slip past `select_autoescape`), evidence is truncated, BOM output is ASCII-safe |
| **Data handling** | API keys from env only; no ambient Hub credentials; offline by default; AI off by default and local-first when on |

Two invariants are enforced by tests rather than by discipline: `bulwark-core` imports nothing from
the tools, and core never calls an execution primitive. See
`packages/bulwark-core/tests/test_architecture.py`.

Report a vulnerability — including a **scanner evasion**, which for a detection tool is a genuine
vulnerability — via [`SECURITY.md`](../SECURITY.md).
