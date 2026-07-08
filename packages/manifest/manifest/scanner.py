"""ManifestScanner — build an AIBOM, resolve it, attach risk, and govern it."""

from __future__ import annotations

from pathlib import Path

from bulwark_core.findings import Finding, Location, ScanResult
from bulwark_core.rules import RuleEngine
from bulwark_core.scanner import Scanner
from bulwark_core.signals import SignalBundle

from manifest.analyze import collect as collect_signals
from manifest.bom.cyclonedx import to_cyclonedx
from manifest.bom.model import AIBOM
from manifest.discover import DiscoveryContext, discover_from_ctx
from manifest.resolve import licenses, provenance, vulns
from manifest.resolve.vulns import Advisory


class ManifestScanner(Scanner):
    """AI-BOM generator + governance scanner for an AI project directory."""

    tool = "manifest"
    target_type = "system"

    def __init__(
        self,
        engine: RuleEngine,
        *,
        offline: bool = True,
        scan_risk: bool = False,
        govern: bool = False,
    ):
        super().__init__(engine)
        self.offline = offline
        self.scan_risk = scan_risk
        self.govern = govern

    def collect_signals(self, target: str) -> SignalBundle:
        ctx = DiscoveryContext.build(Path(target))
        bom = discover_from_ctx(ctx)
        licenses.resolve(bom, ctx)
        return collect_signals(bom, provenance.find_secrets(ctx))

    def scan(self, target: str) -> ScanResult:
        root = Path(target)
        ctx = DiscoveryContext.build(root)
        bom = discover_from_ctx(ctx)
        licenses.resolve(bom, ctx)
        secrets = provenance.find_secrets(ctx)

        findings: list[Finding] = self.engine.evaluate(collect_signals(bom, secrets))
        findings += _vuln_findings(vulns.resolve(bom, offline=self.offline))

        if self.scan_risk:
            from manifest.risk import bridge_risk

            findings += bridge_risk(bom, root, offline=self.offline)

        _attach(findings, bom)

        meta: dict = {"aibom": bom.model_dump(mode="json"), "cyclonedx": to_cyclonedx(bom)}
        if self.govern:
            from manifest.govern import assess, assess_eu_ai_act, b9_findings, risk_register

            assessment = assess(findings)
            b9 = b9_findings(assessment)
            findings += b9
            meta["governance"] = {
                "nist_ai_rmf": assess(findings),
                "eu_ai_act": assess_eu_ai_act(findings),
            }
            meta["risk_register"] = risk_register(findings, bom)

        return ScanResult(
            target=str(root),
            target_type="system",
            tool="manifest",
            findings=_dedupe(findings),
            meta=meta,
        )


def _vuln_findings(vuln_map: dict[str, list[Advisory]]) -> list[Finding]:
    out: list[Finding] = []
    for key, advisories in vuln_map.items():
        for adv in advisories:
            out.append(
                Finding(
                    id=f"B4-{adv.id}-{key}",
                    category="B4",
                    title=f"Known-vulnerable dependency ({adv.id})",
                    severity=adv.severity,
                    confidence="high",
                    location=Location(target="system", path=key),
                    evidence=adv.summary,
                    rationale="A dependency version has a published security advisory.",
                    remediation="Upgrade to a patched version.",
                    references=["OSV", adv.id],
                    source="analyzer",
                )
            )
    return out


def _attach(findings: list[Finding], bom: AIBOM) -> None:
    keys = {c.key: c for c in bom.components}
    for f in findings:
        component = keys.get(f.location.path or "")
        if component is not None and f.id not in component.findings:
            component.findings.append(f.id)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str | None, str | None, str]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.id, f.location.path, f.location.detail, f.evidence)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
