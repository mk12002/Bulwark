"""Abstract Scanner and the orchestrator that picks one by target string."""

from __future__ import annotations

from abc import ABC, abstractmethod

from bulwark_core.findings import ScanResult, TargetType
from bulwark_core.rules import RuleEngine
from bulwark_core.signals import SignalBundle


class Scanner(ABC):
    """Base class for a scan target type.

    Subclasses gather signals from a target and hand them to the injected rule
    engine. They may also append analyzer-sourced findings directly. ``tool`` and
    ``target_type`` label the produced :class:`ScanResult`.
    """

    tool: str = "bulwark"
    target_type: TargetType

    def __init__(self, engine: RuleEngine):
        self.engine = engine

    @abstractmethod
    def collect_signals(self, target: str) -> SignalBundle:
        """Inspect the target and return the signals it produced."""

    def analyzer_findings(self, target: str, bundle: SignalBundle) -> list:
        """Optional hook for findings produced directly by analyzers (not rules)."""
        return []

    def scan(self, target: str) -> ScanResult:
        """Full pipeline: collect signals -> apply rules -> build ScanResult."""
        bundle = self.collect_signals(target)
        findings = self.engine.evaluate(bundle)
        findings.extend(self.analyzer_findings(target, bundle))
        # De-duplicate identical findings (same id + location + evidence).
        seen: set[tuple[str, str | None, str | None, str]] = set()
        unique = []
        for f in findings:
            key = (f.id, f.location.path, f.location.detail, f.evidence)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return ScanResult(
            target=target,
            target_type=self.target_type,
            tool=self.tool,
            findings=unique,
        )
