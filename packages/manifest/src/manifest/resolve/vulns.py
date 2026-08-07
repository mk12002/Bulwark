"""Dependency vulnerability lookup via OSV, with an offline seed for CI/tests.

When online (and not ``--offline``), queries the free OSV API. Offline, uses a
small bundled advisory seed so a pinned-vulnerable fixture is deterministic. Only
*pinned* dependency versions are checked (an unpinned dep is a separate B1 gap).
"""

from __future__ import annotations

from dataclasses import dataclass

from bulwark_core.severity import Severity

from manifest.bom.model import AIBOM, Component


@dataclass(frozen=True)
class Advisory:
    id: str
    severity: Severity
    summary: str


# Bundled offline seed (accurate, well-known advisories). Used when --offline or no
# network. Keyed by (ecosystem, package, version).
_SEED: dict[tuple[str, str, str], list[Advisory]] = {
    ("PyPI", "pyyaml", "5.3.1"): [
        Advisory(
            "GHSA-6757-jp84-gxfx",
            Severity.HIGH,
            "PyYAML full_load / FullLoader arbitrary code execution (CVE-2020-14343).",
        )
    ],
    ("PyPI", "requests", "2.19.1"): [
        Advisory(
            "GHSA-x84v-xcm2-53pg",
            Severity.MEDIUM,
            "Requests leaks Authorization header on cross-origin redirect (CVE-2018-18074).",
        )
    ],
    ("PyPI", "flask", "0.12.2"): [
        Advisory(
            "GHSA-562c-5r94-xh97",
            Severity.HIGH,
            "Flask denial of service via crafted JSON (CVE-2018-1000656).",
        )
    ],
}

_ECOSYSTEM = {"pypi": "PyPI", "npm": "npm"}


def _ecosystem(component: Component) -> str | None:
    return _ECOSYSTEM.get((component.provenance.source or "").lower())


def _seed_lookup(component: Component) -> list[Advisory]:
    eco = _ecosystem(component)
    ver = component.provenance.version
    if not eco or not ver:
        return []
    return _SEED.get((eco, component.name.lower(), ver), [])


def _osv_query(deps: list[tuple[Component, str, str]]) -> dict[str, list[Advisory]]:
    """Query the OSV batch API. Returns {component.key: [Advisory]}."""
    try:
        import httpx
    except ImportError:  # pragma: no cover - optional
        return {}
    queries = [
        {"package": {"ecosystem": eco, "name": c.name}, "version": ver} for (c, eco, ver) in deps
    ]
    try:
        resp = httpx.post(
            "https://api.osv.dev/v1/querybatch", json={"queries": queries}, timeout=20.0
        )
        resp.raise_for_status()
        results = resp.json().get("results", [])
    except Exception:  # pragma: no cover - network
        return {}
    out: dict[str, list[Advisory]] = {}
    for (c, _eco, _ver), result in zip(deps, results, strict=False):
        advs = [
            Advisory(v.get("id", "OSV"), _osv_severity(v), v.get("summary", "known vulnerability"))
            for v in (result.get("vulns") or [])
        ]
        if advs:
            out[c.key] = advs
    return out


def _osv_severity(vuln: dict) -> Severity:
    for sev in vuln.get("severity", []) or []:
        score = str(sev.get("score", ""))
        if any(h in score for h in ("9.", "10.", "CRITICAL")):
            return Severity.CRITICAL
        if any(h in score for h in ("7.", "8.", "HIGH")):
            return Severity.HIGH
    return Severity.MEDIUM


def resolve(bom: AIBOM, offline: bool = True) -> dict[str, list[Advisory]]:
    """Return {component.key: [Advisory]} for vulnerable, pinned dependencies."""
    deps: list[tuple[Component, str, str]] = []
    for c in bom.components:
        eco = _ecosystem(c)
        if eco and c.provenance.pinned and c.provenance.version:
            deps.append((c, eco, c.provenance.version))
    if not deps:
        return {}

    if offline:
        return {c.key: advs for (c, _e, _v) in deps if (advs := _seed_lookup(c))}
    online = _osv_query(deps)
    # Union with the seed so known fixtures are stable even online.
    for c, _e, _v in deps:
        seed = _seed_lookup(c)
        if seed and c.key not in online:
            online[c.key] = seed
    return online
