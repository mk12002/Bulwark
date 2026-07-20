"""YAML rule-pack loader, rule schema, and the signal -> finding matcher.

Rules keep detection out of code and open to contributors. Two matcher styles:

- ``pattern``   — a regex tested against a named signal's value.
- ``predicate`` — a named, safe, built-in check with args.

No arbitrary code runs from rule files. Unknown signals/predicates and invalid
regexes fail loudly at load time (surfaced by ``airlock rules lint``).
"""

from __future__ import annotations

import functools
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from bulwark_core.findings import Confidence, Finding, Location
from bulwark_core.severity import Severity
from bulwark_core.signals import Signal, SignalBundle
from bulwark_core.taxonomy import is_known

# Cap the length of the (attacker-controlled) string a rule regex is run against.
# Detection patterns match short tokens; bounding the input keeps a pathological
# regex — including one from an untrusted community rule pack — from turning a
# multi-megabyte field into catastrophic backtracking (ReDoS) against the scanner.
MAX_MATCH_INPUT = 100_000


@functools.lru_cache(maxsize=512)
def _compiled(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)

# --------------------------------------------------------------------------- #
# Predicate registry — the only non-regex checks a rule may invoke.
# Each predicate is (value, args) -> bool. Kept tiny and side-effect free.
# --------------------------------------------------------------------------- #


def _pred_is_true(value: Any, args: dict[str, Any]) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def _pred_is_false(value: Any, args: dict[str, Any]) -> bool:
    return value is False or (isinstance(value, str) and value.strip().lower() == "false")


def _pred_non_empty(value: Any, args: dict[str, Any]) -> bool:
    if value is None:
        return False
    if isinstance(value, str | list | tuple | dict | set):
        return len(value) > 0
    return bool(value)


def _pred_is_empty(value: Any, args: dict[str, Any]) -> bool:
    return not _pred_non_empty(value, args)


def _pred_equals(value: Any, args: dict[str, Any]) -> bool:
    return bool(value == args.get("value"))


def _pred_gt(value: Any, args: dict[str, Any]) -> bool:
    try:
        return float(value) > float(args["threshold"])
    except (TypeError, ValueError, KeyError):
        return False


def _pred_gte(value: Any, args: dict[str, Any]) -> bool:
    try:
        return float(value) >= float(args["threshold"])
    except (TypeError, ValueError, KeyError):
        return False


def _pred_contains_any(value: Any, args: dict[str, Any]) -> bool:
    needles = args.get("values", [])
    hay = str(value).lower()
    return any(str(n).lower() in hay for n in needles)


def _pred_in_list(value: Any, args: dict[str, Any]) -> bool:
    return value in args.get("values", [])


PREDICATES: dict[str, Any] = {
    "is_true": _pred_is_true,
    "is_false": _pred_is_false,
    "non_empty": _pred_non_empty,
    "is_empty": _pred_is_empty,
    "equals": _pred_equals,
    "gt": _pred_gt,
    "gte": _pred_gte,
    "contains_any": _pred_contains_any,
    "in_list": _pred_in_list,
}

MAX_EVIDENCE_LEN = 300


# --------------------------------------------------------------------------- #
# Rule schema
# --------------------------------------------------------------------------- #


class RuleMatch(BaseModel):
    """The matcher clause of a rule. Exactly one of pattern/predicate is set."""

    model_config = ConfigDict(extra="forbid")

    signal: str
    pattern: str | None = None
    predicate: str | None = None
    args: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _exactly_one_matcher(self) -> RuleMatch:
        has_pattern = self.pattern is not None
        has_predicate = self.predicate is not None
        if has_pattern == has_predicate:
            raise ValueError("match must set exactly one of 'pattern' or 'predicate'")
        if has_pattern:
            try:
                re.compile(self.pattern or "")
            except re.error as exc:
                raise ValueError(f"invalid regex pattern: {exc}") from exc
        if has_predicate and self.predicate not in PREDICATES:
            valid = ", ".join(sorted(PREDICATES))
            raise ValueError(f"unknown predicate {self.predicate!r}; valid: {valid}")
        return self


class Rule(BaseModel):
    """A single detection rule, validated at load time."""

    model_config = ConfigDict(extra="forbid")

    id: str
    category: str
    title: str
    severity: Severity
    confidence: Confidence
    match: RuleMatch
    rationale: str
    remediation: str
    references: list[str] = Field(default_factory=list)

    @field_validator("category")
    @classmethod
    def _known_category(cls, v: str) -> str:
        if not is_known(v):
            raise ValueError(f"unknown taxonomy category {v!r} (not registered by any tool)")
        return v


class RulePack(BaseModel):
    """A YAML file's worth of rules."""

    model_config = ConfigDict(extra="forbid")

    version: int
    target: str
    rules: list[Rule]

    @field_validator("target")
    @classmethod
    def _known_target(cls, v: str) -> str:
        if not v or not v.isidentifier():
            raise ValueError(f"target must be a non-empty identifier, got {v!r}")
        return v


@dataclass
class LoadedRule:
    """A rule paired with the pack/target/source it came from."""

    rule: Rule
    target: str
    source: Path


class RuleLoadError(Exception):
    """Raised when a rule pack fails to parse or validate."""


# --------------------------------------------------------------------------- #
# Loader
# --------------------------------------------------------------------------- #


def load_rule_pack(path: Path) -> tuple[RulePack, list[LoadedRule]]:
    """Load and validate one YAML rule pack file."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise RuleLoadError(f"{path}: YAML parse error: {exc}") from exc
    if not isinstance(raw, dict):
        raise RuleLoadError(f"{path}: expected a mapping at the top level")
    try:
        pack = RulePack.model_validate(raw)
    except Exception as exc:  # pydantic ValidationError and friends
        raise RuleLoadError(f"{path}: {exc}") from exc
    loaded = [LoadedRule(rule=r, target=pack.target, source=path) for r in pack.rules]
    return pack, loaded


def load_rule_dirs(roots: list[Path]) -> list[LoadedRule]:
    """Load every ``*.yaml`` rule pack under each root directory, in order.

    Raises :class:`RuleLoadError` on an invalid pack or a duplicate rule id across
    all roots. Each tool passes its own packaged + user rule directories.
    """
    loaded: list[LoadedRule] = []
    seen_ids: dict[str, Path] = {}
    for root in roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.yaml")):
            _, pack_rules = load_rule_pack(path)
            for lr in pack_rules:
                if lr.rule.id in seen_ids:
                    raise RuleLoadError(
                        f"duplicate rule id {lr.rule.id!r} in {path} "
                        f"(already defined in {seen_ids[lr.rule.id]})"
                    )
                seen_ids[lr.rule.id] = path
                loaded.append(lr)
    return loaded


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #


def _iter_match_targets(value: Any) -> Iterable[Any]:
    """Yield the value(s) a matcher should test.

    A list/tuple value is expanded so a pattern can match any element; scalars
    yield themselves.
    """
    if isinstance(value, list | tuple):
        yield from value
    else:
        yield value


def _evaluate(match: RuleMatch, value: Any) -> tuple[bool, Any]:
    """Return (matched, matched_value) for one signal value against a matcher."""
    if match.pattern is not None:
        rx = _compiled(match.pattern)
        for item in _iter_match_targets(value):
            if item is None:
                continue
            text = str(item)
            if len(text) > MAX_MATCH_INPUT:
                text = text[:MAX_MATCH_INPUT]  # bound ReDoS blast radius
            if rx.search(text):
                return True, item
        return False, None
    # predicate
    predicate = PREDICATES[match.predicate or ""]
    return bool(predicate(value, match.args)), value


def _truncate(text: str) -> str:
    return text if len(text) <= MAX_EVIDENCE_LEN else text[:MAX_EVIDENCE_LEN] + "…"


def _finding_from(rule: Rule, target: str, signal: Signal, matched_value: Any) -> Finding:
    evidence = signal.evidence if signal.evidence is not None else str(matched_value)
    return Finding(
        id=rule.id,
        category=rule.category,
        title=rule.title,
        severity=rule.severity,
        confidence=rule.confidence,
        location=Location(target=target, path=signal.path, detail=signal.detail),
        evidence=_truncate(evidence),
        rationale=rule.rationale,
        remediation=rule.remediation,
        references=list(rule.references),
        source="rule",
    )


class RuleEngine:
    """Applies a set of loaded rules to a signal bundle to produce findings."""

    def __init__(self, rules: list[LoadedRule]):
        self._rules = rules

    @property
    def rules(self) -> list[LoadedRule]:
        return self._rules

    def rules_for(self, target: str) -> list[LoadedRule]:
        return [lr for lr in self._rules if lr.target == target]

    def evaluate(self, bundle: SignalBundle) -> list[Finding]:
        """Run every target-matching rule against the bundle's signals."""
        findings: list[Finding] = []
        for lr in self.rules_for(bundle.target):
            for signal in bundle.by_name(lr.rule.match.signal):
                matched, matched_value = _evaluate(lr.rule.match, signal.value)
                if matched:
                    findings.append(_finding_from(lr.rule, bundle.target, signal, matched_value))
        return findings
