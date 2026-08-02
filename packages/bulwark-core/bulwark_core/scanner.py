"""Abstract Scanner and the pipeline every tool in the suite runs."""

from __future__ import annotations

from abc import ABC, abstractmethod

from bulwark_core.findings import Finding, ScanResult, TargetType, dedupe
from bulwark_core.rules import RuleEngine
from bulwark_core.signals import SignalBundle


class Scanner(ABC):
    """Base class for a scan target type.

    Subclasses gather signals from a target and hand them to the injected rule
    engine. They may also append analyzer-sourced findings directly, and may attach
    a headline score and tool-specific metadata to the result via the hooks below.
    ``tool`` and ``target_type`` label the produced :class:`ScanResult`.
    """

    tool: str = "bulwark"
    target_type: TargetType

    def __init__(self, engine: RuleEngine):
        self.engine = engine

    @abstractmethod
    def collect_signals(self, target: str) -> SignalBundle:
        """Inspect the target and return the signals it produced."""

    def analyzer_findings(self, target: str, bundle: SignalBundle) -> list[Finding]:
        """Optional hook for findings produced directly by analyzers (not rules)."""
        return []

    def result_score(self, target: str, bundle: SignalBundle) -> int | None:
        """Optional hook for a 0–100 headline score (e.g. Warden's agency score)."""
        return None

    def result_meta(self, target: str, bundle: SignalBundle) -> dict:
        """Optional hook for tool-specific structured metadata attached to the result."""
        return {}

    def scan(self, target: str) -> ScanResult:
        """Full pipeline: collect signals -> apply rules -> build ScanResult."""
        bundle = self.collect_signals(target)
        findings = self.engine.evaluate(bundle)
        findings.extend(self.analyzer_findings(target, bundle))
        return ScanResult(
            target=target,
            target_type=self.target_type,
            tool=self.tool,
            findings=dedupe(findings),
            score=self.result_score(target, bundle),
            meta=self.result_meta(target, bundle),
        )
