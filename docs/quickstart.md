# Quick start

Everything below runs against the repository's bundled fixtures, so it works on a fresh
clone with no network.

## Scan a model

```bash
airlock scan model packages/airlock/fixtures/model/poisoned
```

```
CRITICAL  M1  M1-pickle-shell-exec   pytorch_model.bin
HIGH      M2  M2-pickle-present      pytorch_model.bin
MEDIUM    M4  M4-pickle-without-safetensors
LOW       M7  M7-no-hashes
```

The artifact is **never loaded**. Pickles are disassembled with `pickletools`, which
walks opcodes without executing them.

!!! tip "Pin your models"
    `hf:org/name` resolves against a *mutable* git branch — the publisher can force-push
    and change the weights under you. Use `hf:org/name@<revision>` to pin an immutable
    commit and make the scan reproducible.

## Audit an agent

```bash
warden audit packages/warden/fixtures/over_privileged/injectable.yaml
```

```
CRITICAL  A2  A2-injectable-exfil-flow   web_browser -> read_secrets -> tool:send_webhook
HIGH      A3  A3-missing-human-gate      run_shell
```

Every tool here is individually reasonable. The **combination** is not: the agent can
read untrusted web content, read secrets, and send data outward — so an attacker who
plants instructions on a page the agent reads can drive the whole chain.

Add `--recommend` to get a hardened spec and a diff:

```bash
warden audit agent.yaml --recommend
```

## Inventory a project

```bash
manifest scan packages/manifest/fixtures/sample_project_risky --scan-risk --govern
```

Discovers models, datasets, MCP servers, prompts, tools, dependencies, notebooks, and
agent assemblies, then folds in Airlock's and Warden's findings and maps the gaps to
NIST AI RMF and EU AI Act controls.

```bash
manifest scan ./project --format cyclonedx > bom.json    # CycloneDX 1.5 AI-BOM
manifest scan ./project --format spdx      > bom.spdx.json
manifest scan ./project --format md        > governance.md
```

## The whole suite

```bash
bulwark scan ./project
```

Sugar for `manifest scan --scan-risk --govern` — the one command to try first.

## Gate a build

```bash
airlock scan model ./m --format sarif --fail-on high > airlock.sarif
echo "exit=$?"   # 0 clean · 1 findings at/above threshold · 2 usage error
```

## Diagnose a rule

```bash
airlock rules debug model ./m           # every signal available for this target
airlock rules lint                      # rejects a typo'd signal name
airlock rules show M1-pickle-shell-exec
```

## Next

- [Python API](reference/api.md) — everything above is available as a library
- [CI integration](guides/ci.md)
- [`examples/`](https://github.com/mk12002/Bulwark/tree/main/examples) — runnable scripts
