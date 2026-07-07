"""WardenScanner — import an agent config, analyze it, and score the assembly."""

from __future__ import annotations

from pathlib import Path

from bulwark_core.findings import Finding, Location, ScanResult
from bulwark_core.scanner import Scanner
from bulwark_core.severity import Severity
from bulwark_core.signals import SignalBundle

from warden.analysis import agency_score, collect_signals
from warden.importers import ImportError_, import_agent
from warden.spec.model import AgentSpec
from warden.spec.normalize import normalize


class WardenScanner(Scanner):
    """Least-privilege auditor for AI agent assemblies."""

    tool = "warden"
    target_type = "agent"

    def collect_signals(self, target: str) -> SignalBundle:
        spec, _importer = import_agent(Path(target))
        return collect_signals(spec)

    def audit_spec(self, spec: AgentSpec, target: str = "<spec>") -> ScanResult:
        """Analyze an already-parsed AgentSpec. Exposed for tests/recommendation."""
        normalize(spec)
        bundle = collect_signals(spec)
        findings = _dedupe(self.engine.evaluate(bundle))
        return ScanResult(
            target=target,
            target_type="agent",
            tool="warden",
            findings=findings,
            score=agency_score(spec),
            meta={"agent_spec": spec.model_dump(mode="json")},
        )

    def scan(self, target: str) -> ScanResult:
        try:
            spec, importer = import_agent(Path(target))
        except ImportError_ as exc:
            return ScanResult(
                target=target,
                target_type="agent",
                tool="warden",
                findings=[
                    Finding(
                        id="WARDEN-import-error",
                        category="A9",
                        title="Could not import the agent configuration",
                        severity=Severity.INFO,
                        confidence="high",
                        location=Location(target=target),
                        evidence=str(exc),
                        rationale="Warden could not parse the config into an AgentSpec.",
                        remediation="Check the file, or describe the agent as a manifest YAML.",
                        source="analyzer",
                    )
                ],
            )
        result = self.audit_spec(spec, target)
        result.meta["importer"] = importer
        return result


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str | None, str | None, str]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.id, f.location.path, f.location.detail, f.evidence)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
