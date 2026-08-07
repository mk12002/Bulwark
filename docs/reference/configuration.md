# Configuration

## Precedence

**CLI flags > environment variables > TOML file > defaults.**

Environment beats the file deliberately: env is the operator's channel (CI, containers),
while a committed config file may be controlled by the very repository being scanned and
must never be able to weaken a pipeline's settings.

Each tool reads its own file — `airlock.toml`, `warden.toml`, `manifest.toml` — and its
own env prefix (`AIRLOCK_`, `WARDEN_`, `MANIFEST_`). Nested keys use a double
underscore: `AIRLOCK_AI__ENABLED=true`.

## Settings

```toml
fail_on = "high"              # exit non-zero at/above this severity
output_format = "terminal"    # terminal | json | html | sarif
strict_allowlist = false      # Airlock only: --strict as a durable posture

# Airlock only — waivers. Suppressed findings are hidden and do not affect the exit
# code, but the count is always reported, so a quiet report is never a silent one.
suppress_rules = ["M4-*"]
suppress_paths = ["vendor/*"]

[ai]
enabled = false               # also requires --ai on the CLI: two switches
provider = "ollama"           # ollama | openai_compat | anthropic
model = "qwen2.5-coder"
base_url = "http://localhost:11434"
max_findings_to_enrich = 25   # caps every provider call, not just per-finding ones
```

!!! danger "API keys are environment-only"
    `AIConfig` has **no `api_key` field**, so there is nowhere in a file to put one. Set
    `AIRLOCK_AI_API_KEY` instead. A config file gets committed, appears in diffs, and
    ends up pasted into issue reports — removing the option entirely is a stronger
    control than warning about it.

## Resource limits

Every parse is bounded. A malformed override falls back to the default rather than
disabling the control or crashing the scan.

| Variable | Default | Bounds |
|---|---|---|
| `AIRLOCK_LIMIT_PICKLE_OPCODES` | 2,000,000 | opcode flood |
| `AIRLOCK_LIMIT_ARCHIVE_MEMBERS` | 20,000 | member flood |
| `AIRLOCK_LIMIT_UNCOMPRESSED_BYTES` | 4 GiB | zip bomb, absolute size |
| `AIRLOCK_LIMIT_COMPRESSION_RATIO` | 100 | zip bomb, ratio |
| `AIRLOCK_LIMIT_MEMBER_BYTES` | 512 MiB | oversized archive member |
| `AIRLOCK_LIMIT_NESTED_BLOB_BYTES` | 8 MiB | base64-staged payload expansion |
| `AIRLOCK_LIMIT_MAX_FILES` | 100,000 | directory traversal |
| `AIRLOCK_LIMIT_CONNECT_TIMEOUT` | 20s | a hung MCP server |
| `AIRLOCK_STATE_DIR` | `~/.airlock` | rug-pull baseline store — **set this in CI** |

## Noise control

Three mechanisms for three different questions. Confusing them causes real problems.

| | Answers | Scope | Lifetime |
|---|---|---|---|
| **Waiver** | "this rule does not apply to us" | rule-id / path globs | durable |
| **Baseline** | "show me only what is *new*" | exact finding identity | until regenerated |
| **Policy profile** | "how strict a posture?" | severity + confidence floors | per run |

```bash
airlock scan model ./m --baseline prev.json     # regressions only
warden audit agent.yaml --profile permissive    # blockers only
```

| Profile | Severity floor | Min confidence |
|---|---|---|
| `strict` | INFO | low |
| `balanced` *(default)* | LOW | low |
| `permissive` | MEDIUM | medium |

All three report a `suppressed` count. **`--fail-on` is independent of the profile**, so
posture and gating compose rather than fight — you can show few findings and still fail
on real ones.

!!! note "Waivers also disable the gate"
    The exit code is computed on the *filtered* set, which is the intended semantics of
    a waiver. It is also where a team quiets a report and accidentally removes a
    control, so waive deliberately and prefer `--baseline` for CI adoption.

## Logging

```bash
airlock -v  scan model ./m     # INFO  — progress
airlock -vv scan model ./m     # DEBUG — with file:line
```

`-v` is a group-level option, so it precedes the subcommand (like `docker -D run`).
Diagnostics always go to **stderr**, so `--format json > out.json` stays valid at any
verbosity. As a library, Bulwark emits nothing until you call
`bulwark_core.logging.configure()`.
