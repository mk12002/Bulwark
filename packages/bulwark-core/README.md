# bulwark-core

**The shared spine of the [Bulwark](../../README.md) suite.** Airlock, Warden, and Manifest are thin
tools on top of this one library — build the engine once, reuse it three times.

`bulwark-core` is deliberately **tool-agnostic**: it knows nothing about models, agents, or BOMs. It
provides the machinery every scanner needs, and each tool contributes only its own taxonomy, analyzers,
and rule packs.

## What's in it

| Module | Provides |
| --- | --- |
| `findings` | `Severity`, `Location`, `Finding`, `ScanResult` (pydantic v2) — the stable shapes every tool produces and every reporter consumes |
| `severity` | ordered severities, `worst()`, `exit_code(threshold)` for CI gating |
| `taxonomy` | a **category registry** — `register_categories()`; each tool adds its own codes (`M*`/`P*`, `A*`, `B*`) with titles, default severities, references |
| `rules` | the YAML rule-pack **schema, loader (`load_rule_dirs`), and matcher** (regex `pattern` / safe `predicate` over analyzer signals) |
| `signals` | the `Signal` / `SignalBundle` IR that sits between analyzers and the rule engine |
| `scanner` | the abstract `Scanner` base (resolve → analyze → rules → `ScanResult`) |
| `report` | renderers for **terminal** (rich), **JSON**, **HTML** (jinja2), and **SARIF 2.1.0** (tool-aware driver, stable fingerprints, `security-severity`) |
| `ai` | the provider-agnostic AI layer — `AIProvider` protocol + `ollama` (local/free default), `openai_compat`, `anthropic`; `enrich()`, response cache, eval harness |
| `postprocess` | waiver suppression + baseline-diff (report only regressions) |
| `study` | a corpus runner that aggregates findings across many targets |
| `config` | the shared `AIConfig` (keys from env only, never disk) |
| `limits` | resource caps that keep the scanners safe against hostile input |

## The design contract

Everything the three tools have in common lives here, and **nothing tool-specific does**. Two hard
invariants:

- **Core depends on no tool.** `bulwark-core` imports nothing from `airlock`, `warden`, or `manifest`.
  Tools depend on core; core depends on nothing in the suite.
- **Deterministic first, AI second.** Every core finding is deterministic. The AI layer is off by
  default, gated by `enabled AND --ai`, capped by `max_findings_to_enrich`, degrades gracefully on any
  error, and **never** removes or downgrades a deterministic finding — its output is tagged
  `source="ai"`.

## How a tool uses it

```python
from bulwark_core.scanner import Scanner
from bulwark_core.findings import ScanResult
import mytool.taxonomy          # registers this tool's categories at import

class MyScanner(Scanner):
    tool = "mytool"
    target_type = "thing"
    def collect_signals(self, target): ...      # analyzers emit signals
    # base .scan() runs the injected rule engine → ScanResult
```

The tool ships YAML rule packs that map signals → findings, and `bulwark_core.report.render_report`
handles every output format. See **[BULWARK.md](../../BULWARK.md)** for the full contract.
