"""Compose Warden → Airlock: scan the MCP parts an assembly wires in (--scan-parts).

For each MCP server referenced in the AgentSpec, run Airlock's MCP scanner on the
spawn command and merge its P-findings into Warden's report — turning the A9
"unscanned parts" advisory into concrete part-level findings. Degrades gracefully
if Airlock is not installed or a server can't be reached.
"""

from __future__ import annotations

from collections.abc import Callable

from bulwark_core.findings import Finding

from warden.spec.model import AgentSpec

# run_mcp(command) -> list of P-findings for that server. Injectable for tests.
RunMcp = Callable[[str], list[Finding]]


def _command_of(ref: str) -> str:
    """Extract the spawn command/URL from an 'name: command args' reference."""
    return ref.split(": ", 1)[1].strip() if ": " in ref else ref.strip()


def _default_run_mcp() -> RunMcp | None:
    try:
        from airlock.rules import RuleEngine, load_rules
        from airlock.scanners.mcp import MCPScanner
    except ImportError:
        return None
    engine = RuleEngine(load_rules())

    def run(command: str) -> list[Finding]:
        result = MCPScanner(engine).scan(command)
        return [f for f in result.findings if f.source != "analyzer"]

    return run


def scan_wired_parts(spec: AgentSpec, run_mcp: RunMcp | None = None) -> list[Finding]:
    """Return Airlock findings for every MCP server the assembly wires in."""
    runner = run_mcp or _default_run_mcp()
    if runner is None:
        return []
    out: list[Finding] = []
    for ref in spec.mcp_servers:
        command = _command_of(ref)
        if not command:
            continue
        try:
            out += runner(command)
        except Exception:
            continue
    return out
