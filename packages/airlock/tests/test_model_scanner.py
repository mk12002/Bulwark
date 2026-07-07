"""Tests for the model scanner (M1–M7) against benign fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest
from airlock.rules import RuleEngine, load_rules
from airlock.scanners.model import ModelScanner
from airlock.scanners.model.pickle_scan import analyze_stream
from bulwark_core.severity import Severity


@pytest.fixture(scope="module")
def scanner() -> ModelScanner:
    return ModelScanner(RuleEngine(load_rules()))


def _categories(result) -> set[str]:
    return {f.category for f in result.findings}


def _ids(result) -> set[str]:
    return {f.id for f in result.findings}


def test_poisoned_reports_critical_m1(scanner: ModelScanner, model_fixtures: Path) -> None:
    result = scanner.scan(str(model_fixtures / "poisoned"))
    m1 = [f for f in result.findings if f.category == "M1"]
    assert m1, "expected an M1 finding"
    assert any(f.severity == Severity.CRITICAL for f in m1)
    assert result.worst() == Severity.CRITICAL
    assert result.exit_code(Severity.HIGH) == 1
    # os.system resolves to nt.system on Windows; either proves the shell callable.
    assert ".system" in " ".join(f.evidence for f in m1)


def test_clean_model_is_clean(scanner: ModelScanner, model_fixtures: Path) -> None:
    result = scanner.scan(str(model_fixtures / "clean"))
    assert result.findings == []
    assert result.worst() == Severity.INFO
    assert result.exit_code(Severity.HIGH) == 0


def test_remote_code_reports_m5(scanner: ModelScanner, model_fixtures: Path) -> None:
    result = scanner.scan(str(model_fixtures / "remote_code"))
    assert "M5" in _categories(result)
    assert "M5-trust-remote-code" in _ids(result)
    assert "M5-auto-map" in _ids(result)


def test_archive_smuggle_reports_m6(scanner: ModelScanner, model_fixtures: Path) -> None:
    result = scanner.scan(str(model_fixtures / "archive_smuggle"))
    assert "M6" in _categories(result)


def test_missing_target_is_handled(scanner: ModelScanner) -> None:
    result = scanner.scan("does/not/exist")
    assert result.exit_code(Severity.HIGH) == 0  # info-level resolve error only
    assert all(f.severity == Severity.INFO for f in result.findings)


def test_pickle_analyzer_resolves_stack_global() -> None:
    import pickle

    class Payload:
        def __reduce__(self):  # type: ignore[no-untyped-def]
            import os

            return (os.system, ("echo hi",))

    analysis = analyze_stream(pickle.dumps(Payload()))
    resolved = [name for name, _pos in analysis.imports]
    # os.system resolves to nt.system on Windows; accept either.
    assert any(name.endswith(".system") for name in resolved)
    assert analysis.has_reduce is True
    assert analysis.error is None


def test_pickle_analyzer_handles_plain_data() -> None:
    import pickle

    analysis = analyze_stream(pickle.dumps({"a": [1, 2, 3], "b": "safe"}))
    resolved = [name for name, _pos in analysis.imports]
    # A plain dict resolves no dangerous callables.
    assert all("system" not in r for r in resolved)
    assert analysis.error is None
