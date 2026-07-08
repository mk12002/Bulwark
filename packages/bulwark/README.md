# bulwark (meta-CLI)

One command over the whole [Bulwark](../../README.md) suite — *Airlock scans the parts, Warden scans
the assembly, Manifest inventories it all.*

```bash
pip install -e packages/bulwark          # pulls in airlock + warden + manifest

bulwark airlock  scan model hf:org/name  # the tools, verbatim, as subcommands
bulwark warden   audit agent.yaml --recommend
bulwark manifest scan ./project --format spdx

bulwark scan ./project                   # the whole suite in one shot:
                                         #   inventory + Airlock/Warden risk inline + governance
bulwark version
```

`bulwark <tool> ...` mounts each tool's own CLI unchanged — every flag behaves identically to the
standalone `airlock` / `warden` / `manifest` commands. `bulwark scan <project>` is the aggregator path:
it runs `manifest scan --scan-risk --govern`, so you get a CycloneDX/SPDX AI-BOM with Airlock's model/MCP
findings and Warden's assembly findings folded in, mapped to NIST AI RMF and the EU AI Act — the suite's
thesis in a single invocation.

Deterministic-first and defensive-only, like every tool it wraps. See the repo-root
[`README`](../../README.md) and [`BULWARK.md`](../../BULWARK.md).
