"""Policy profiles — a single knob for how strict an audit is.

A profile sets a coherent posture: a **severity floor** (findings below it are moved
out of the report into a suppressed count, still visible for transparency) and a
**minimum confidence** (drop low-confidence heuristic/AI findings when you only want
high-signal results). It does *not* rewrite individual finding severities — the facts
stay honest; the profile only decides how much noise you see.

- ``strict``     — show everything, including INFO; keep all confidences. Audit posture.
- ``balanced``   — default. Show LOW and up; keep all confidences.
- ``permissive`` — show MEDIUM and up; only medium/high confidence. Blockers-only posture.

``--fail-on`` remains the independent CI gate, so profile and gate compose.
"""

from __future__ import annotations

from dataclasses import dataclass

from bulwark_core.findings import ScanResult
from bulwark_core.severity import Severity

_CONF_RANK = {"low": 0, "medium": 1, "high": 2}


@dataclass(frozen=True)
class Profile:
    """A named audit posture."""

    name: str
    floor: Severity
    min_confidence: str

    def keeps(self, severity: Severity, confidence: str) -> bool:
        conf_ok = _CONF_RANK.get(confidence, 0) >= _CONF_RANK[self.min_confidence]
        return severity >= self.floor and conf_ok


PROFILES: dict[str, Profile] = {
    "strict": Profile("strict", Severity.INFO, "low"),
    "balanced": Profile("balanced", Severity.LOW, "low"),
    "permissive": Profile("permissive", Severity.MEDIUM, "medium"),
}


def get_profile(name: str) -> Profile:
    """Look up a profile by name, raising ``ValueError`` on an unknown name."""
    try:
        return PROFILES[name.strip().lower()]
    except KeyError as exc:
        valid = ", ".join(PROFILES)
        raise ValueError(f"unknown profile {name!r}; expected one of: {valid}") from exc


def apply_profile(result: ScanResult, profile: Profile) -> ScanResult:
    """Return a copy of ``result`` filtered to the profile, recording what was suppressed."""
    kept = [f for f in result.findings if profile.keeps(f.severity, f.confidence)]
    suppressed = len(result.findings) - len(kept)
    meta = dict(result.meta)
    meta["policy_profile"] = profile.name
    if suppressed:
        meta["policy_suppressed"] = suppressed
    return result.model_copy(update={"findings": kept, "meta": meta})
