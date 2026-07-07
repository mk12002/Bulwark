"""Tests for the YAML rule loader and the signal -> finding matcher."""

from __future__ import annotations

from pathlib import Path

import pytest
from airlock.core.rules import (
    LoadedRule,
    Rule,
    RuleEngine,
    RuleLoadError,
    load_rule_pack,
    load_rules,
)
from airlock.core.signals import SignalBundle


def test_packaged_rules_load_and_are_unique() -> None:
    rules = load_rules()
    assert len(rules) >= 20
    ids = [lr.rule.id for lr in rules]
    assert len(ids) == len(set(ids))  # no duplicate ids


def test_targets_are_split() -> None:
    engine = RuleEngine(load_rules())
    assert engine.rules_for("model")
    assert engine.rules_for("mcp")
    assert all(lr.target == "model" for lr in engine.rules_for("model"))


def _write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_pattern_rule_matches_signal(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "pack.yaml",
        """
version: 1
target: model
rules:
  - id: T-shell
    category: M1
    title: shell
    severity: critical
    confidence: high
    match:
      signal: pickle.imports
      pattern: "^os\\\\.system$"
    rationale: r
    remediation: fix
""",
    )
    engine = RuleEngine(load_rules(tmp_path))
    bundle = SignalBundle(target="model")
    bundle.add("pickle.imports", "os.system", path="a.bin")
    bundle.add("pickle.imports", "numpy.core.multiarray._reconstruct", path="a.bin")
    findings = engine.evaluate(bundle)
    assert len(findings) == 1
    assert findings[0].id == "T-shell"
    assert findings[0].severity.value == "critical"
    assert findings[0].location.path == "a.bin"


def test_predicate_rule_is_true(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "pack.yaml",
        """
version: 1
target: model
rules:
  - id: T-trc
    category: M5
    title: trc
    severity: high
    confidence: high
    match:
      signal: config.trust_remote_code
      predicate: is_true
    rationale: r
    remediation: fix
""",
    )
    engine = RuleEngine(load_rules(tmp_path))
    bundle = SignalBundle(target="model")
    bundle.add("config.trust_remote_code", True, path="config.json")
    assert len(engine.evaluate(bundle)) == 1

    bundle2 = SignalBundle(target="model")
    bundle2.add("config.trust_remote_code", False, path="config.json")
    assert engine.evaluate(bundle2) == []


def test_invalid_regex_fails_loudly(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "bad.yaml",
        """
version: 1
target: model
rules:
  - id: T-bad
    category: M1
    title: bad
    severity: high
    confidence: high
    match:
      signal: x
      pattern: "([unterminated"
    rationale: r
    remediation: fix
""",
    )
    with pytest.raises(RuleLoadError):
        load_rules(tmp_path)


def test_unknown_category_fails(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "bad.yaml",
        """
version: 1
target: model
rules:
  - id: T-bad
    category: Z9
    title: bad
    severity: high
    confidence: high
    match:
      signal: x
      predicate: is_true
    rationale: r
    remediation: fix
""",
    )
    with pytest.raises(RuleLoadError):
        load_rules(tmp_path)


def test_unknown_predicate_fails(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "bad.yaml",
        """
version: 1
target: mcp
rules:
  - id: T-bad
    category: P1
    title: bad
    severity: high
    confidence: high
    match:
      signal: x
      predicate: not_a_predicate
    rationale: r
    remediation: fix
""",
    )
    with pytest.raises(RuleLoadError):
        load_rules(tmp_path)


def test_both_matchers_rejected(tmp_path: Path) -> None:
    with pytest.raises(RuleLoadError):
        load_rule_pack(
            _write(
                tmp_path,
                "bad.yaml",
                """
version: 1
target: mcp
rules:
  - id: T-bad
    category: P1
    title: bad
    severity: high
    confidence: high
    match:
      signal: x
      pattern: "a"
      predicate: is_true
    rationale: r
    remediation: fix
""",
            )
        )


def test_duplicate_id_across_packs_fails(tmp_path: Path) -> None:
    body = """
version: 1
target: model
rules:
  - id: DUP
    category: M1
    title: t
    severity: high
    confidence: high
    match:
      signal: x
      predicate: is_true
    rationale: r
    remediation: fix
"""
    _write(tmp_path, "a.yaml", body)
    _write(tmp_path, "b.yaml", body)
    with pytest.raises(RuleLoadError):
        load_rules(tmp_path)


def test_pattern_matches_list_element() -> None:
    rule = Rule.model_validate(
        {
            "id": "T",
            "category": "M1",
            "title": "t",
            "severity": "high",
            "confidence": "high",
            "match": {"signal": "s", "pattern": "^os\\.system$"},
            "rationale": "r",
            "remediation": "fix",
        }
    )
    engine = RuleEngine([LoadedRule(rule=rule, target="model", source=Path("test"))])
    bundle = SignalBundle(target="model")
    bundle.add("s", ["safe.call", "os.system"], path="a")
    findings = engine.evaluate(bundle)
    assert len(findings) == 1
    assert findings[0].evidence == "os.system"
