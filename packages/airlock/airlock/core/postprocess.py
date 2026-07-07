"""Post-scan transforms: waiver suppression and baseline diffing.

These run after a scan (and after optional AI enrichment) and before rendering.
Both are pure functions returning a new :class:`ScanResult`, so the pipeline stays
testable and the ``suppressed`` count stays honest.
"""

from __future__ import annotations

import json
from fnmatch import fnmatch
from pathlib import Path

from airlock.core.findings import Finding, ScanResult


def _finding_key(f: Finding) -> tuple[str, str | None, str | None, str]:
    return (f.id, f.location.path, f.location.detail, f.evidence)


def _matches(f: Finding, rule_globs: list[str], path_globs: list[str]) -> bool:
    if any(fnmatch(f.id, g) for g in rule_globs):
        return True
    path = f.location.path or ""
    return any(fnmatch(path, g) for g in path_globs)


def apply_waivers(result: ScanResult, rule_globs: list[str], path_globs: list[str]) -> ScanResult:
    """Drop findings whose id or path matches a waiver glob; keep the count."""
    if not rule_globs and not path_globs:
        return result
    kept = [f for f in result.findings if not _matches(f, rule_globs, path_globs)]
    hidden = len(result.findings) - len(kept)
    if hidden == 0:
        return result
    return _rebuild(result, kept, result.suppressed + hidden)


def load_baseline(path: Path) -> set[tuple[str, str | None, str | None, str]]:
    """Load a prior ScanResult JSON and return the set of its finding keys."""
    data = json.loads(path.read_text(encoding="utf-8"))
    keys: set[tuple[str, str | None, str | None, str]] = set()
    for f in data.get("findings", []):
        loc = f.get("location", {})
        keys.add((f.get("id", ""), loc.get("path"), loc.get("detail"), f.get("evidence", "")))
    return keys


def apply_baseline(result: ScanResult, baseline_path: Path) -> ScanResult:
    """Keep only findings absent from the baseline (report regressions only)."""
    known = load_baseline(baseline_path)
    kept = [f for f in result.findings if _finding_key(f) not in known]
    hidden = len(result.findings) - len(kept)
    if hidden == 0:
        return result
    return _rebuild(result, kept, result.suppressed + hidden)


def _rebuild(result: ScanResult, findings: list[Finding], suppressed: int) -> ScanResult:
    return ScanResult(
        target=result.target,
        target_type=result.target_type,
        findings=findings,
        scanned_at=result.scanned_at,
        airlock_version=result.airlock_version,
        ai_summary=result.ai_summary,
        suppressed=suppressed,
    )
