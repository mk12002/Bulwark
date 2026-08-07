"""Signals: the intermediate representation between analyzers and the rule engine.

Analyzers are pure functions that inspect an artifact and emit :class:`Signal`
records. The rule engine then maps signals to :class:`~airlock.core.findings.Finding`
objects. Keeping signals separate from findings means detection *logic* lives in
YAML rules while detection *evidence gathering* lives in typed Python.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Signal:
    """One observation produced by an analyzer.

    Multiple signals may share a ``name`` (e.g. one ``pickle.imports`` signal per
    resolved callable). ``value`` is what rule patterns/predicates test against;
    ``path``/``detail`` locate it; ``evidence`` optionally overrides the text shown
    in the finding.
    """

    name: str
    value: Any
    path: str | None = None
    detail: str | None = None
    evidence: str | None = None


@dataclass
class SignalBundle:
    """A collection of signals for a single scan target, indexed by name."""

    target: str
    signals: list[Signal] = field(default_factory=list)

    def add(
        self,
        name: str,
        value: Any,
        *,
        path: str | None = None,
        detail: str | None = None,
        evidence: str | None = None,
    ) -> Signal:
        """Append a signal and return it."""
        sig = Signal(name=name, value=value, path=path, detail=detail, evidence=evidence)
        self.signals.append(sig)
        return sig

    def extend(self, signals: list[Signal]) -> None:
        """Append many signals at once."""
        self.signals.extend(signals)

    def by_name(self, name: str) -> list[Signal]:
        """Return all signals with the given name, in insertion order."""
        return [s for s in self.signals if s.name == name]

    def names(self) -> set[str]:
        """Return the set of distinct signal names present."""
        return {s.name for s in self.signals}
