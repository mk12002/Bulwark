"""Unit tests for the shared spine.

``bulwark-core`` was previously exercised only indirectly, through the tools. That
left the highest-consequence failure in the codebase untested: ``Severity`` subclasses
``str``, so without explicit comparison operators ``CRITICAL > HIGH`` compares strings
alphabetically and returns ``False`` — silently inverting severity ordering and
disabling every ``--fail-on`` gate, with a green build on a critical finding.

These tests pin the invariants nothing else checks.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bulwark_core.findings import (
    Finding,
    Location,
    ScanResult,
    dedupe,
    finding_key,
)
from bulwark_core.limits import DEFAULT_LIMITS, Limits, walk_files
from bulwark_core.postprocess import apply_baseline, apply_waivers
from bulwark_core.rule_feed import _extract_zip
from bulwark_core.severity import Severity, parse_severity, worst_of


def _finding(
    rule_id: str = "M1-test",
    severity: Severity = Severity.HIGH,
    path: str | None = "model.bin",
    detail: str | None = None,
    evidence: str = "os.system",
) -> Finding:
    return Finding(
        id=rule_id,
        category="M1",
        title="t",
        severity=severity,
        confidence="high",
        location=Location(target="model", path=path, detail=detail),
        evidence=evidence,
        rationale="r",
        remediation="fix",
    )


# --------------------------------------------------------------------------- #
# Severity ordering — the silent-failure guard
# --------------------------------------------------------------------------- #


def test_severity_is_ordered_by_rank_not_alphabetically() -> None:
    """The whole --fail-on gate rests on this. Alphabetically 'critical' < 'high'."""
    assert Severity.CRITICAL > Severity.HIGH
    assert Severity.HIGH > Severity.MEDIUM
    assert Severity.MEDIUM > Severity.LOW
    assert Severity.LOW > Severity.INFO
    # The trap this guards against:
    assert "critical" < "high"  # plain string comparison is the wrong answer


def test_severity_comparison_is_total_and_reflexive() -> None:
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    for i, lo in enumerate(order):
        assert lo >= lo and lo <= lo
        for hi in order[i + 1 :]:
            assert lo < hi and hi > lo


def test_severity_serialises_as_its_string_value() -> None:
    assert Severity.HIGH == "high"
    assert json.dumps({"s": Severity.HIGH}) == '{"s": "high"}'


def test_parse_severity_is_case_and_space_insensitive() -> None:
    assert parse_severity("HIGH") is Severity.HIGH
    assert parse_severity("  critical ") is Severity.CRITICAL
    with pytest.raises(ValueError, match="unknown severity"):
        parse_severity("catastrophic")


def test_worst_of_empty_is_info() -> None:
    assert worst_of([]) is Severity.INFO
    assert worst_of([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]) is Severity.CRITICAL


def test_exit_code_uses_rank_ordering() -> None:
    result = ScanResult(
        target="t", target_type="model", findings=[_finding(severity=Severity.HIGH)]
    )
    assert result.exit_code(Severity.CRITICAL) == 0
    assert result.exit_code(Severity.HIGH) == 1
    assert result.exit_code(Severity.LOW) == 1


# --------------------------------------------------------------------------- #
# Finding identity — one definition, three consumers
# --------------------------------------------------------------------------- #


def test_finding_key_ignores_severity_and_prose() -> None:
    a = _finding(severity=Severity.HIGH)
    b = _finding(severity=Severity.LOW)
    assert finding_key(a) == finding_key(b)


def test_finding_key_distinguishes_location_and_evidence() -> None:
    base = _finding()
    assert finding_key(base) != finding_key(_finding(path="other.bin"))
    assert finding_key(base) != finding_key(_finding(detail="opcode@1"))
    assert finding_key(base) != finding_key(_finding(evidence="subprocess.run"))


def test_dedupe_collapses_identical_findings_preserving_order() -> None:
    findings = [_finding(), _finding(rule_id="M2-x"), _finding()]
    out = dedupe(findings)
    assert [f.id for f in out] == ["M1-test", "M2-x"]


def test_sarif_fingerprint_derives_from_the_same_key() -> None:
    """A drift here silently resurrects every dismissed code-scanning alert."""
    from bulwark_core.report.sarif import _fingerprint

    assert _fingerprint(_finding()) == _fingerprint(_finding(severity=Severity.LOW))
    assert _fingerprint(_finding()) != _fingerprint(_finding(evidence="other"))


# --------------------------------------------------------------------------- #
# ScanResult
# --------------------------------------------------------------------------- #


def test_stats_include_zero_buckets_for_every_severity() -> None:
    result = ScanResult(target="t", target_type="model", findings=[_finding()])
    assert set(result.stats) == {s.value for s in Severity}
    assert result.stats["high"] == 1
    assert result.stats["critical"] == 0


def test_sorted_findings_is_worst_first_and_deterministic() -> None:
    result = ScanResult(
        target="t",
        target_type="model",
        findings=[
            _finding("B-low", Severity.LOW),
            _finding("A-crit", Severity.CRITICAL),
            _finding("C-high", Severity.HIGH),
        ],
    )
    assert [f.id for f in result.sorted_findings()] == ["A-crit", "C-high", "B-low"]


# --------------------------------------------------------------------------- #
# Post-processing must preserve every other field
# --------------------------------------------------------------------------- #


def test_waivers_preserve_score_and_meta() -> None:
    """An explicit field list here silently dropped score/meta; model_copy cannot."""
    result = ScanResult(
        target="t",
        target_type="agent",
        findings=[_finding("M4-advisory"), _finding("M1-real")],
        score=82,
        meta={"agent_spec": {"name": "demo"}},
    )
    out = apply_waivers(result, ["M4-*"], [])
    assert [f.id for f in out.findings] == ["M1-real"]
    assert out.suppressed == 1
    assert out.score == 82
    assert out.meta == {"agent_spec": {"name": "demo"}}


def test_baseline_preserves_score_and_meta(tmp_path: Path) -> None:
    result = ScanResult(
        target="t",
        target_type="system",
        findings=[_finding("M1-known"), _finding("M2-new", evidence="different")],
        score=41,
        meta={"aibom": {"project": "p"}},
    )
    baseline = tmp_path / "base.json"
    baseline.write_text(
        json.dumps({"findings": [json.loads(_finding("M1-known").model_dump_json())]}),
        encoding="utf-8",
    )
    out = apply_baseline(result, baseline)
    assert [f.id for f in out.findings] == ["M2-new"]
    assert out.suppressed == 1
    assert out.score == 41
    assert out.meta == {"aibom": {"project": "p"}}


def test_waivers_are_a_no_op_without_globs() -> None:
    result = ScanResult(target="t", target_type="model", findings=[_finding()])
    assert apply_waivers(result, [], []) is result


# --------------------------------------------------------------------------- #
# Hostile-input controls
# --------------------------------------------------------------------------- #


def test_extract_zip_rejects_traversal_and_absolute_members() -> None:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("ok.yaml", "version: 1")
        zf.writestr("../escaped.yaml", "version: 1")
        zf.writestr("/absolute.yaml", "version: 1")
        zf.writestr("payload.py", "print('nope')")  # non-YAML must not be extracted
    dest = Path(_extract_zip(buf.getvalue()))
    assert sorted(p.name for p in dest.rglob("*") if p.is_file()) == ["ok.yaml"]


def test_walk_files_does_not_follow_symlinks_out_of_the_root(tmp_path: Path) -> None:
    """A model directory with a link to / must not make the scan walk the filesystem."""
    root = tmp_path / "artifact"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "model.bin").write_bytes(b"\x80\x04.")
    (outside / "secret.txt").write_text("do not read me", encoding="utf-8")
    try:
        (root / "escape").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted in this environment")

    names = [p.name for p in walk_files(root)]
    assert "model.bin" in names
    assert "secret.txt" not in names


def test_walk_files_respects_the_file_cap(tmp_path: Path) -> None:
    for i in range(10):
        (tmp_path / f"f{i}.bin").write_bytes(b"x")
    assert len(walk_files(tmp_path, Limits(max_files=4))) == 4


def test_limits_are_frozen_so_an_analyzer_cannot_raise_its_own_ceiling() -> None:
    with pytest.raises((AttributeError, TypeError)):
        DEFAULT_LIMITS.max_pickle_opcodes = 1  # type: ignore[misc]
