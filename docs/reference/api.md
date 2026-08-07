# Python API

Everything the CLI does is available as a library. The design rule throughout: **the
rule engine is injected, never constructed inside a scanner**, so you can supply your
own rule packs, a subset for testing, or a fake.

## Scan a model

```python
from airlock.rules import RuleEngine, load_rules
from airlock.scanners.model import ModelScanner
from bulwark_core.severity import Severity

scanner = ModelScanner(RuleEngine(load_rules()))
result = scanner.scan("hf:org/name@revision")

print(result.worst().value, len(result.findings))
for f in result.sorted_findings():
    print(f.severity.value, f.category, f.id, f.location.path)

raise SystemExit(result.exit_code(Severity.HIGH))   # the CI contract
```

`strict=True` enables Fickling-style allowlist mode (higher recall, calibrated for the
HuggingFace ecosystem):

```python
ModelScanner(RuleEngine(load_rules()), strict=True)
```

## Scan an MCP server or tool-spec

```python
from airlock.scanners.mcp import MCPScanner
from airlock.scanners.toolspec.loader import load_toolspec

engine = RuleEngine(load_rules())

MCPScanner(engine).scan("python server.py")          # live (spawns the server)
MCPScanner(engine, connector=lambda _t: load_toolspec(Path("tools.json"))).scan("tools.json")
```

!!! warning "stdio scanning spawns the server"
    Enumerating a stdio MCP server requires starting it — the protocol offers no other
    way to list tools. Airlock never *invokes* a tool, but the server's own startup code
    runs. Use `scan toolspec` in CI, or scan in a container.

The `connector` is a `Callable[[str], MCPInventory]`, which is also how tests supply a
hand-built inventory with no subprocess.

## Audit an agent

```python
from warden.rules import RuleEngine, load_rules
from warden.scanner import WardenScanner
from warden.spec.model import AgentSpec, Gate, Tool

spec = AgentSpec(name="bot", autonomy="autonomous", tools=[
    Tool(name="read_file",    description="Read a file from disk", scopes=["/**"]),
    Tool(name="post_webhook", description="POST data to a URL", gate=Gate.APPROVAL),
])

result = WardenScanner(RuleEngine(load_rules())).audit_spec(spec)
print(result.score)          # 0–100 agency score
```

`audit_spec` takes an **in-memory** spec, so you can score a design before writing any
config — useful in tests and design review.

### Least-privilege recommendation

```python
from warden.recommend.least_privilege import recommend

rec = recommend(spec)
print(rec.diff_text())
rec.changes      # applied: gates, sandboxes, allow-list placeholders, limits
rec.advisories   # need a human: breaking a toxic pair, restricting egress
```

The input spec is never mutated — `recommend` works on a deep copy.

## Generate an AI-BOM

```python
from manifest.rules import RuleEngine, load_rules
from manifest.scanner import ManifestScanner
from manifest.bom.model import AIBOM
from manifest.bom.cyclonedx import to_cyclonedx

result = ManifestScanner(
    RuleEngine(load_rules()), offline=True, scan_risk=True, govern=True
).scan("./project")

bom = AIBOM.model_validate(result.meta["aibom"])
to_cyclonedx(bom)                      # CycloneDX 1.5 dict
result.meta["governance"]              # NIST AI RMF + EU AI Act status
result.meta["risk_register"]           # component → risk → severity → action
```

## Custom rule packs

```python
from pathlib import Path
from airlock.rules import RuleEngine, load_rules

engine = RuleEngine(load_rules(extra_roots=[Path("./my-rules")]))
```

`extra_roots` **appends** to the packaged + user roots. A duplicate rule id across roots
is a hard error, so a local pack cannot silently disable a built-in detection.

## Render a report

```python
from bulwark_core.report import render_report

render_report(result, "json")     # also: sarif, html
render_report(result, "terminal") # prints; returns ""
```

## Logging

Silent by default; a library never configures logging for its host.

```python
from bulwark_core.logging import configure
configure(verbosity=1)   # 0 WARNING · 1 INFO · 2 DEBUG — always to stderr
```

Diagnostics go to **stderr** so stdout stays valid JSON/SARIF when piped.

## Core types

| Type | Module | Purpose |
|---|---|---|
| `Finding` | `bulwark_core.findings` | id, category, severity, confidence, location, evidence, rationale, remediation, references, source |
| `ScanResult` | `bulwark_core.findings` | findings + stats + `score` + `meta`; `worst()`, `exit_code()`, `sorted_findings()` |
| `Severity` | `bulwark_core.severity` | ordered `StrEnum`: INFO < LOW < MEDIUM < HIGH < CRITICAL |
| `finding_key` / `dedupe` | `bulwark_core.findings` | canonical finding identity — also drives baselines and SARIF fingerprints |
| `AgentSpec` | `warden.spec.model` | the normalized agent IR every importer produces |
| `AIBOM` | `manifest.bom.model` | the inventory IR |

See [`examples/`](https://github.com/mk12002/Bulwark/tree/main/examples) for runnable versions of all of the above.
