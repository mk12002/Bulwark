# Contributing to Bulwark

Thanks for helping secure the AI agent supply chain. Bulwark is a monorepo of five packages
(`bulwark-core`, `airlock`, `warden`, `manifest`, `bulwark`); this guide covers the whole workspace.
For Airlock's rule-pack format specifically, see
[`packages/airlock/CONTRIBUTING.md`](packages/airlock/CONTRIBUTING.md).

## Ground rules (non-negotiable)

1. **Defensive only.** Bulwark detects and reports; it never weaponizes. Any code that resembles an
   exploit (fixtures, evasion detectors) must be **detection-oriented and benign** — inert markers, no
   destructive/exfiltrating behavior.
2. **Inspection only.** Never `pickle.load`, `torch.load`, `joblib.load`, import target code, or invoke
   MCP tools. Everything is static.
3. **Deterministic first.** Every finding is deterministic. The AI layer only enriches, is off by
   default, and never downgrades a deterministic finding.
4. **Detection lives in data.** Prefer a YAML rule pack + a signal over hardcoded Python checks.

## Getting set up

```bash
git clone https://github.com/mk12002/Bulwark && cd Bulwark
python -m venv .venv && . .venv/Scripts/activate      # or .venv/bin/activate
pip install -r requirements.txt                        # editable install of all five packages
```

## The quality gate

One command runs ruff + mypy + pytest across every package (each with its own config):

```bash
python check.py            # all packages
python check.py --fast     # skip mypy
python check.py airlock    # one package
```

CI runs the same matrix. **A PR must be green** before review. `nox` runs the same sessions if you
prefer it.

## Adding a detector (the common case)

Every new check ships with **three things**: a rule, a fixture, and a test.

1. **Emit a signal** from an analyzer (or reuse an existing one).
2. **Write a YAML rule** under the tool's `rules/` dir that maps the signal → a finding with a category,
   severity, rationale, remediation, and a reference (OWASP LLM Top 10 / MITRE ATLAS / CWE / NIST).
3. **Ship a benign fixture** that triggers it and a **clean fixture** that does not.
4. **Add a test** asserting on `category` + `severity` (not on prose).

Run `python check.py` and open a PR.

## Commit & PR conventions

- Small, focused commits with clear messages.
- Describe *what* changed and *why*; link any issue.
- Fill in the PR template checklist.
- New detectors: include the fixture + test in the same PR.

## Where things live

| Package | Contents |
| --- | --- |
| `bulwark-core` | shared spine: findings, rule engine, signals, reporters, AI layer, limits |
| `airlock` | model / MCP / tool-spec scanners (M/P codes) |
| `warden` | agent least-privilege auditor (A codes) |
| `manifest` | AI-BOM generator + governance (B codes) |
| `bulwark` | the meta-CLI over all three |

## Code of Conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
