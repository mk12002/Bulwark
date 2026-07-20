"""Tests for Tier 3/4: rule feed, study harness, AI cache, AI eval, SARIF depth."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest
from airlock.rules import RuleLoadError, load_rules
from bulwark_core.ai.cache import CachingProvider
from bulwark_core.ai.eval import DEFAULT_DATASET, evaluate
from bulwark_core.findings import Finding, Location, ScanResult
from bulwark_core.report.sarif import render_sarif
from bulwark_core.rule_feed import update_rules
from bulwark_core.severity import Severity
from bulwark_core.study import CorpusItem, render_markdown, run_study

# --------------------------------------------------------------------------- #
# Rule feed
# --------------------------------------------------------------------------- #

_VALID_PACK = """
version: 1
target: mcp
rules:
  - id: X1-community-rule
    category: P1
    title: community
    severity: high
    confidence: medium
    match:
      signal: tool.description
      pattern: "(?i)community-marker"
    rationale: r
    remediation: fix
"""

_DUP_PACK = """
version: 1
target: model
rules:
  - id: M1-pickle-shell-exec
    category: M1
    title: dup
    severity: critical
    confidence: high
    match:
      signal: pickle.imports
      pattern: "x"
    rationale: r
    remediation: fix
"""

_INVALID_PACK = "version: 1\ntarget: model\nrules:\n  - id: bad\n"


def test_update_installs_valid_pack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "good.yaml").write_text(_VALID_PACK, encoding="utf-8")
    dest = tmp_path / "userrules"
    monkeypatch.setenv("AIRLOCK_RULES_DIR", str(dest))

    result = update_rules(str(src), dest=dest)
    assert "good.yaml" in result.installed
    # The new rule now loads alongside the packaged rules.
    ids = {lr.rule.id for lr in load_rules()}
    assert "X1-community-rule" in ids


def test_update_skips_duplicate_and_invalid(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "dup.yaml").write_text(_DUP_PACK, encoding="utf-8")
    (src / "bad.yaml").write_text(_INVALID_PACK, encoding="utf-8")
    dest = tmp_path / "userrules"

    # M1-pickle-shell-exec collides with a packaged Airlock rule id.
    known = {"M1-pickle-shell-exec"}
    result = update_rules(str(src), dest=dest, known_ids=known)
    assert result.installed == []
    assert len(result.skipped) == 2


def test_user_rules_merge_rejects_true_duplicates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest = tmp_path / "userrules"
    dest.mkdir()
    (dest / "dup.yaml").write_text(_DUP_PACK, encoding="utf-8")  # collides with packaged M1
    monkeypatch.setenv("AIRLOCK_RULES_DIR", str(dest))
    with pytest.raises(RuleLoadError):
        load_rules()


def test_extract_zip_rejects_traversal() -> None:
    # A rules feed is untrusted input; a member resolving outside the temp dir (zip-slip
    # via ../ or an absolute path) must never be written.
    from bulwark_core.rule_feed import _extract_zip

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("good.yaml", "version: 1\ntarget: model\nrules: []\n")
        zf.writestr("../escape.yaml", "x: 1\n")
        zf.writestr("nested/../../escape2.yaml", "x: 1\n")
    dest = Path(_extract_zip(buf.getvalue()))
    assert {p.name for p in dest.rglob("*.yaml")} == {"good.yaml"}
    # Nothing escaped the extraction directory.
    assert not (dest.parent / "escape.yaml").exists()
    assert not (dest.parent.parent / "escape2.yaml").exists()


def test_extract_zip_caps_oversized_members() -> None:
    # A decompression-bomb member (declared size over the cap) is skipped, not written.
    from bulwark_core.limits import Limits
    from bulwark_core.rule_feed import _extract_zip

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("big.yaml", "a: " + "x" * 5000)
    dest = Path(_extract_zip(buf.getvalue(), Limits(max_member_bytes=10)))
    assert list(dest.rglob("*.yaml")) == []


# --------------------------------------------------------------------------- #
# Study harness
# --------------------------------------------------------------------------- #


def _fake_result(cats: list[str]) -> ScanResult:
    findings = [
        Finding(
            id=f"{c}-x",
            category=c,
            title="t",
            severity=Severity.HIGH,
            confidence="high",
            location=Location(target="model", path="p"),
            evidence="e",
            rationale="r",
            remediation="fix",
        )
        for c in cats
    ]
    return ScanResult(target="t", target_type="model", findings=findings)


def test_run_study_aggregates() -> None:
    corpus = [
        CorpusItem("model", "a"),
        CorpusItem("model", "b"),
        CorpusItem("model", "c"),
    ]
    outcomes = {"a": ["M1", "M2"], "b": [], "c": ["M1"]}

    def scan_fn(kind: str, target: str) -> ScanResult:
        return _fake_result(outcomes[target])

    report = run_study(corpus, scan_fn, rule_count=38)
    assert report.scanned == 3
    assert report.with_findings == 2
    assert abs(report.prevalence - 2 / 3) < 1e-9
    assert report.by_category["M1"] == 2
    assert report.top_rules[0][1] == 2  # M1-x hit twice
    assert "Bulwark corpus scan" in render_markdown(report)


def test_run_study_records_errors() -> None:
    def scan_fn(kind: str, target: str) -> ScanResult:
        raise RuntimeError("boom")

    report = run_study([CorpusItem("model", "x")], scan_fn)
    assert report.errored == 1
    assert report.scanned == 0
    assert report.per_target[0]["error"].startswith("RuntimeError")


# --------------------------------------------------------------------------- #
# AI cache
# --------------------------------------------------------------------------- #


class _CountingProvider:
    def __init__(self) -> None:
        self.calls = 0

    @property
    def name(self) -> str:
        return "counter"

    def analyze(self, system: str, prompt: str) -> str:
        self.calls += 1
        return "reply"


def test_caching_provider_memoizes(tmp_path: Path) -> None:
    inner = _CountingProvider()
    cache = CachingProvider(inner, cache_path=tmp_path / "cache.json")
    assert cache.analyze("s", "p") == "reply"
    assert cache.analyze("s", "p") == "reply"  # served from cache
    assert inner.calls == 1
    assert cache.calls == 1
    assert cache.hits == 1


def test_caching_provider_persists(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    CachingProvider(_CountingProvider(), cache_path=path).analyze("s", "p")
    # A fresh cache over a new inner reads the persisted answer without calling.
    inner2 = _CountingProvider()
    cache2 = CachingProvider(inner2, cache_path=path)
    assert cache2.analyze("s", "p") == "reply"
    assert inner2.calls == 0


# --------------------------------------------------------------------------- #
# AI eval
# --------------------------------------------------------------------------- #


class _OracleProvider:
    """A perfect provider: flags exactly the malicious examples."""

    @property
    def name(self) -> str:
        return "oracle"

    def analyze(self, system: str, prompt: str) -> str:
        malicious = any(
            k in prompt.lower() for k in ("ignore all", "read the .env", "<system>", "do not tell")
        )
        return json.dumps({"malicious": malicious, "confidence": "high", "reason": "x"})


def test_eval_reports_perfect_scores_for_oracle() -> None:
    m = evaluate(_OracleProvider(), DEFAULT_DATASET)
    assert m.tp + m.fn == sum(1 for e in DEFAULT_DATASET if e.malicious)
    assert m.precision == 1.0
    assert m.recall == 1.0
    assert m.f1 == 1.0


# --------------------------------------------------------------------------- #
# SARIF depth
# --------------------------------------------------------------------------- #


def _sarif_result() -> ScanResult:
    return ScanResult(
        target="m",
        target_type="model",
        findings=[
            Finding(
                id="M1-pickle-shell-exec",
                category="M1",
                title="rce",
                severity=Severity.CRITICAL,
                confidence="high",
                location=Location(target="model", path="a.bin", detail="opcode@1"),
                evidence="os.system",
                rationale="why",
                remediation="fix",
                references=["CWE-502"],
            )
        ],
    )


def test_sarif_has_fingerprints_and_help() -> None:
    data = json.loads(render_sarif(_sarif_result()))
    rule = data["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["help"]["text"]
    assert rule["fullDescription"]["text"]
    assert rule["properties"]["security-severity"] == "9.5"
    assert "security" in rule["properties"]["tags"]
    result = data["runs"][0]["results"][0]
    assert result["partialFingerprints"]["bulwark/v1"]
    assert data["runs"][0]["properties"]["targetType"] == "model"


def test_sarif_fingerprint_is_stable() -> None:
    a = json.loads(render_sarif(_sarif_result()))["runs"][0]["results"][0]
    b = json.loads(render_sarif(_sarif_result()))["runs"][0]["results"][0]
    assert a["partialFingerprints"] == b["partialFingerprints"]
