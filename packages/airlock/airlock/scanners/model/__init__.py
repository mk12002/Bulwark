"""Model artifact scanner (M1–M7).

Resolves a target to an inventory, runs each analyzer to gather signals, and lets
the injected rule engine map those signals to findings. Inspection only: this
scanner never deserializes or imports the artifact.
"""

from __future__ import annotations

from bulwark_core.findings import Finding, Location, ScanResult
from bulwark_core.rules import RuleEngine
from bulwark_core.scanner import Scanner
from bulwark_core.severity import Severity
from bulwark_core.signals import SignalBundle

from airlock.scanners.model import (
    archive,
    confusion,
    formats,
    pickle_scan,
    provenance,
    remote_code,
    serialized,
)
from airlock.scanners.model.loader import ResolveError, resolve

__all__ = ["ModelScanner"]


class ModelScanner(Scanner):
    """Static scanner for ML model artifacts."""

    tool = "airlock"
    target_type = "model"

    def __init__(self, engine: RuleEngine, *, strict: bool = False) -> None:
        super().__init__(engine)
        # strict = Fickling-style allowlist mode: flag pickle imports whose module
        # is outside the ML allowlist (opt-in; off by default to avoid noise).
        self.strict = strict

    def collect_signals(self, target: str) -> SignalBundle:
        bundle = SignalBundle(target="model")
        inventory = resolve(target)
        pickle_scan.collect(inventory.files, bundle, strict=self.strict)
        confusion.collect(inventory.files, bundle, strict=self.strict)
        serialized.collect(inventory.files, bundle)
        formats.collect(inventory, bundle)
        remote_code.collect(inventory, bundle)
        archive.collect(inventory.files, bundle)
        provenance.collect(inventory, bundle)
        return bundle

    def scan(self, target: str) -> ScanResult:
        try:
            return super().scan(target)
        except ResolveError as exc:
            return ScanResult(
                target=target,
                target_type="model",
                tool="airlock",
                findings=[
                    Finding(
                        id="AIRLOCK-resolve-error",
                        category="M7",
                        title="Could not resolve model target",
                        severity=Severity.INFO,
                        confidence="high",
                        location=Location(target=target),
                        evidence=str(exc),
                        rationale="Airlock could not access the target to scan it.",
                        remediation="Check the path or hf: reference and try again.",
                        references=[],
                        source="analyzer",
                    )
                ],
            )
