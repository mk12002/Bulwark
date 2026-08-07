# Examples

Runnable scripts for the Python API. Every one works against the repository's own
fixtures, so they run on a fresh clone with no setup and no network.

```bash
pip install -r requirements.txt      # or: pip install airlock warden manifest
python examples/01_scan_a_model.py
```

They are exercised by `packages/bulwark/tests/test_examples.py`, so a change that
breaks an example breaks CI — these do not rot.

| Example | Shows | Needs |
|---|---|---|
| [`01_scan_a_model.py`](01_scan_a_model.py) | Scan a model artifact; read findings; gate on severity | `airlock` |
| [`02_audit_an_agent.py`](02_audit_an_agent.py) | Build an `AgentSpec` in memory and watch the **lethal trifecta** escalate a finding to CRITICAL | `warden` |
| [`03_generate_an_ai_bom.py`](03_generate_an_ai_bom.py) | Inventory a project, fold in Airlock + Warden risk, emit CycloneDX + a risk register | `manifest[risk]` |
| [`04_least_privilege_recommendation.py`](04_least_privilege_recommendation.py) | Rewrite an over-privileged agent and prove the score improved | `warden` |
| [`05_custom_rule_pack.py`](05_custom_rule_pack.py) | Add organisation-specific detections in YAML, with no Python changes | `airlock` |

## The three questions

The examples map onto the three questions the suite answers:

| Question | Tool | Example |
|---|---|---|
| Is this **part** safe? | Airlock | 01 |
| Does this **assembly** hold too much power? | Warden | 02, 04 |
| What is my **system** made of, and is it governable? | Manifest | 03 |

## Two things worth noticing

**Everything is static.** No example loads a pickle, imports a scanned file, or invokes
an MCP tool. Pickles are disassembled with `pickletools`, configs are parsed as JSON,
archives are read from the central directory. That is the project's central safety
property, and it is why these scripts are safe to run against a hostile artifact.

**Dependencies are injected.** Every scanner takes its `RuleEngine` as a constructor
argument, and `WardenScanner.audit_spec` takes an in-memory `AgentSpec`. That is what
lets example 02 evaluate four hypothetical designs without touching the filesystem, and
what lets example 05 layer custom rules over the built-ins.

## Debugging your own rules

```bash
airlock rules debug model ./my-model            # every signal available for a target
airlock rules debug model ./my-model --signal pickle
airlock rules lint                              # rejects a typo'd signal name
```

A rule matches one **signal**. If a rule is not firing, the question is almost always
"is the evidence there?" — `rules debug` answers it directly.
