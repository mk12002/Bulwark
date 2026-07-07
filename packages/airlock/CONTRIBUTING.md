# Contributing to Airlock

Airlock's detection logic lives in **YAML rule packs**, not hardcoded checks. Adding a
detector is meant to be a small, reviewable PR — no Python required for most rules. This
guide covers the rule format, the signals you can match against, and the checklist for a
mergeable contribution.

## Ground rules

1. **Detection-oriented and benign.** Airlock *detects and reports* — it never generates
   working attacks. Any fixture that simulates a malicious artifact must be **inert**
   (a harmless marker, e.g. a pickle that *would* `echo` a sentinel, never anything
   destructive or network-active). See [`CLAUDE.md`](CLAUDE.md) Principle 1.
2. **Deterministic first.** New detectors are static: no executing the artifact, no
   unpickling, no importing repo code, no invoking MCP tools.
3. **Explainable findings.** Every rule states what/where/why/severity/remediation/reference.
4. **Every detector ships with a fixture and a test.**

## The dev loop

```bash
pip install -e ".[dev]"
ruff format . && ruff check .   # style + lint
mypy airlock                    # types (strict on core/ and scanners/)
pytest -q                       # tests
airlock rules lint              # validate every rule pack
airlock rules list              # see what's loaded
```

## Rule pack format

A rule pack is one YAML file under [`airlock/rules/model/`](airlock/rules/model) or
[`airlock/rules/mcp/`](airlock/rules/mcp). Each rule maps a **signal** (emitted by an
analyzer) to a **finding** using one of two matcher styles.

```yaml
version: 1
target: model            # "model" | "mcp"
rules:
  - id: M1-pickle-shell-exec        # stable, unique across all packs
    category: M1                    # a taxonomy code: M1..M7 / P1..P9
    title: "Pickle references a shell/exec/eval callable"
    severity: critical              # info | low | medium | high | critical
    confidence: high                # low | medium | high
    match:
      signal: pickle.imports        # which analyzer signal to test
      pattern: "^(os\\.system|subprocess\\.)"   # regex OR predicate (exactly one)
    rationale: "Loading this artifact can execute arbitrary commands."
    remediation: "Do not load. Prefer a safetensors version from a trusted source."
    references: ["OWASP:LLM05", "CWE-502"]
```

### Matchers — pick exactly one

- **`pattern`** — a Python regex tested against the signal's value. If the value is a list,
  the pattern matches if it matches **any** element (that element becomes the evidence).
  Use inline `(?i)` **at the start** for case-insensitivity.
- **`predicate`** — a named, safe, built-in check. No arbitrary code runs from rule files.

| Predicate | True when | Args |
|---|---|---|
| `is_true` / `is_false` | value is boolean (or `"true"`/`"false"`) | — |
| `non_empty` / `is_empty` | value has length / is falsy | — |
| `equals` | `value == args.value` | `value` |
| `gt` / `gte` | `float(value) >/>= threshold` | `threshold` |
| `contains_any` | any needle appears in `str(value)` (case-insensitive) | `values: [...]` |
| `in_list` | `value in args.values` | `values: [...]` |

Unknown categories, unknown predicates, invalid regexes, and duplicate rule ids all fail
loudly at load time (`airlock rules lint`).

## Signal catalog

Analyzers are pure functions that inspect an artifact and emit `Signal` records; rules turn
those into findings. To add a detector for an existing behaviour, match one of these. To
detect something new, add an analyzer that emits a new signal (see below).

### Model signals (`target: model`)

| Signal | Value | Emitted by |
|---|---|---|
| `pickle.imports` | resolved callable, e.g. `os.system` | `pickle_scan` |
| `pickle.has_reduce` | `True` when a REDUCE/NEWOBJ opcode is present | `pickle_scan` |
| `pickle.strings` | an embedded string from the pickle stream | `pickle_scan` |
| `model.pickle_file` | a pickle-family filename | `pickle_scan` |
| `model.formats` | list of file suffixes present | `formats` |
| `model.pickle_without_safetensors` | `True` when pickle ships with no safetensors | `formats` |
| `config.trust_remote_code` | bool from `config.json` | `remote_code` |
| `config.auto_map` | the `auto_map` value | `remote_code` |
| `repo.custom_py` | a custom `modeling_*.py` / `configuration_*.py` path | `remote_code` |
| `archive.path_traversal` | a member name with `..`/absolute path | `archive` |
| `archive.unexpected_member` | an executable/script/unexpected archive member | `archive` |
| `provenance.missing_model_card` | `True` when no populated model card | `provenance` |
| `provenance.missing_hashes` | `True` when no published checksums/signature | `provenance` |

### MCP signals (`target: mcp`)

| Signal | Value | Emitted by |
|---|---|---|
| `tool.name` | tool name | `descriptions` |
| `tool.description` | tool description text | `descriptions` |
| `tool.param_doc` | a parameter's description | `descriptions` |
| `tool.hidden_chars` | list of hidden/obfuscated codepoints found | `descriptions` |
| `tool.untyped_output` | `True` for untyped output on an external-content tool | `descriptions` |
| `tool.capability` | a classified capability: `shell`/`fs_write`/`fs_read`/`network`/`read_sensitive` | `permissions` |
| `tool.wildcard` | `True` when a wildcard/unconstrained scope is declared | `permissions` |
| `exfil.path` | a reachable `source->sink` pair across tools | `permissions` |
| `secret.finding` | a token/high-entropy secret in a schema/default | `secrets` |
| `tool.env_echo` | `True` when a tool advertises echoing env vars | `secrets` |
| `tool.definition_changed` | a tool whose definition changed since baseline | `integrity` |
| `transport.insecure` | `True` for plaintext transport | `integrity` |
| `auth.missing` | `True` for an unauthenticated remote server | `integrity` |
| `tool.name_collision` | a name shadowing a known/duplicate tool | `integrity` |

## Adding a whole new detector (new signal)

1. Emit the signal from the relevant analyzer under
   [`airlock/scanners/model/`](airlock/scanners/model) or
   [`airlock/scanners/mcp/`](airlock/scanners/mcp), via `bundle.add("your.signal", value,
   path=..., detail=..., evidence=...)`. Keep it a pure function; no side effects.
2. Add a rule pack that matches `your.signal`.
3. Add a **benign** fixture that trips it and, where relevant, a clean control.
4. Add a test asserting on `Finding.category` / `severity` / stable `id` — not on prose.

## PR checklist

- [ ] `ruff format . && ruff check .` clean
- [ ] `mypy airlock` clean
- [ ] `pytest -q` green; new detector has a fixture + test
- [ ] `airlock rules lint` passes
- [ ] Fixtures are benign and inert (no real payloads)
- [ ] Finding has a rationale, remediation, and at least one reference
