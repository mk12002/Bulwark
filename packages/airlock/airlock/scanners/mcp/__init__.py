"""MCP server scanner (P1–P9).

Connects to a server (or accepts a pre-built inventory), runs each analyzer to
gather signals, and lets the injected rule engine map them to findings. Airlock
only reads tool metadata — it never invokes a server tool during a scan.
"""

from __future__ import annotations

from collections.abc import Callable

from bulwark_core.findings import Finding, Location, ScanResult
from bulwark_core.scanner import Scanner
from bulwark_core.severity import Severity
from bulwark_core.signals import SignalBundle

from airlock.rules import RuleEngine
from airlock.scanners.mcp import descriptions, integrity, permissions, secrets
from airlock.scanners.mcp.client import MCPInventory, enumerate_target

__all__ = ["MCPScanner"]

Connector = Callable[[str], MCPInventory]


class MCPScanner(Scanner):
    """Static scanner for MCP servers."""

    tool = "airlock"
    target_type = "mcp"

    def __init__(self, engine: RuleEngine, connector: Connector | None = None):
        super().__init__(engine)
        self._connect: Connector = connector or enumerate_target
        # The most recent inventory, exposed so the CLI can build AI semantic
        # targets (raw tool descriptions) without re-connecting.
        self.last_inventory: MCPInventory | None = None

    def build_signals(self, inventory: MCPInventory) -> SignalBundle:
        """Run every analyzer over an inventory (no I/O). Exposed for testing."""
        bundle = SignalBundle(target="mcp")
        descriptions.collect(inventory, bundle)
        permissions.collect(inventory, bundle)
        secrets.collect(inventory, bundle)
        integrity.collect(inventory, bundle)
        return bundle

    def collect_signals(self, target: str) -> SignalBundle:
        return self.build_signals(self._connect(target))

    def scan(self, target: str) -> ScanResult:
        inventory = self._connect(target)
        self.last_inventory = inventory
        bundle = self.build_signals(inventory)
        findings = self.engine.evaluate(bundle)
        if inventory.connect_error:
            findings.append(
                Finding(
                    id="AIRLOCK-mcp-connect-error",
                    category="P8",
                    title="Could not connect to or enumerate the MCP server",
                    severity=Severity.INFO,
                    confidence="high",
                    location=Location(target=target),
                    evidence=inventory.connect_error,
                    rationale="Airlock could not complete the connection to scan tools.",
                    remediation="Check the command/URL and that the server starts cleanly.",
                    references=[],
                    source="analyzer",
                )
            )
        return ScanResult(
            target=target, target_type="mcp", tool="airlock", findings=_dedupe(findings)
        )


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str | None, str | None, str]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.id, f.location.path, f.location.detail, f.evidence)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
