# Installation

Requires **Python 3.11+**.

## Install what you need

Each tool is independently installable — someone who wants a model scanner should not
inherit an SBOM generator.

=== "One tool"

    ```bash
    pip install airlock      # models, MCP servers, tool-specs
    pip install warden       # agent assemblies
    pip install manifest     # AI-BOM + governance
    ```

=== "Everything"

    ```bash
    pip install bulwark      # mounts all three behind one CLI
    ```

=== "From source"

    ```bash
    git clone https://github.com/mk12002/Bulwark && cd Bulwark
    python -m venv .venv && . .venv/Scripts/activate   # bin/activate on macOS/Linux
    pip install -r requirements.txt
    ```

## Optional extras

Heavy dependencies are behind extras and imported lazily, so a scan that does not need
them never pays for them.

| Extra | Pulls in | Needed for |
|---|---|---|
| `airlock[model]` | `huggingface_hub` | `hf:` targets |
| `airlock[mcp]` | `mcp` SDK | live MCP server scans |
| `airlock[ai]` | `httpx` | the optional AI layer, community rule feed over HTTP |
| `warden[bridge]` | `airlock` | `warden audit --scan-parts` |
| `manifest[risk]` | `airlock`, `warden` | `manifest scan --scan-risk` |
| `manifest[osv]` | `httpx` | live OSV vulnerability lookups |

```bash
pip install "airlock[model,mcp]"
pip install "manifest[risk,osv]"
```

Without an extra, the feature degrades with a clear message rather than a traceback:

```console
$ manifest scan ./project --scan-risk
WARNING  airlock is not installed; skipping model risk (pip install 'manifest[risk]')
```

## Verify

```bash
bulwark version
airlock rules stats     # 42 rules loaded
```

## What gets installed

Four console scripts: `bulwark`, `airlock`, `warden`, `manifest`.

Rule packs ship **inside** the wheels, so detections work from a `pip install` with no
extra data files to fetch.
