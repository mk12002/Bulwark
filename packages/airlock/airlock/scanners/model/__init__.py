"""Model artifact scanner (M1–M7).

Resolves a target to an inventory, runs each analyzer to gather signals, and lets
the injected rule engine map those signals to findings. Inspection only: this
scanner never deserializes or imports the artifact.
"""

from __future__ import annotations

from airlock.core.findings import Finding, Location, ScanResult
from airlock.core.scanner import Scanner
from airlock.core.severity import Severity
from airlock.core.signals import SignalBundle
from airlock.scanners.model import (
    archive,
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

    target_type = "model"

    def collect_signals(self, target: str) -> SignalBundle:
        bundle = SignalBundle(target="model")
        inventory = resolve(target)
        pickle_scan.collect(inventory.files, bundle)
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
