"""Manifest's rule loading. Registers B* taxonomy and adds Manifest's rule dir."""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path

from bulwark_core.rules import (
    LoadedRule,
    RuleEngine,
    RuleLoadError,
    load_rule_dirs,
    load_rule_pack,
    unknown_signals,
    unused_signals,
)

import manifest.taxonomy  # noqa: F401 — side effect: registers B* categories

__all__ = [
    "KNOWN_SIGNALS",
    "LoadedRule",
    "RuleEngine",
    "RuleLoadError",
    "default_rules_dir",
    "load_rule_pack",
    "load_rules",
    "unknown_signals",
    "unused_signals",
    "user_rules_dir",
]


def default_rules_dir() -> Path:
    return Path(__file__).resolve().parent / "rules"


def user_rules_dir() -> Path:
    override = os.environ.get("MANIFEST_RULES_DIR")
    return Path(override) if override else Path.home() / ".manifest" / "rules"


def load_rules(
    rules_dir: Path | None = None,
    *,
    extra_roots: Sequence[Path] | None = None,
) -> list[LoadedRule]:
    """Load rule packs: packaged + user by default.

    ``rules_dir`` *replaces* the default roots — use it to load one directory in
    isolation, which is what the test suite does.

    ``extra_roots`` *appends* to them, which is the documented way to layer your own
    organisation's packs on top of the built-ins from Python. Duplicate rule ids across
    roots are a hard error rather than a silent override, so a local pack cannot shadow
    (and thereby disable) a built-in detection.
    """
    roots = [rules_dir] if rules_dir is not None else [default_rules_dir(), user_rules_dir()]
    if extra_roots:
        roots.extend(extra_roots)
    return load_rule_dirs(roots)


# Every signal Manifest's analyzers emit; ``manifest rules lint`` rejects a rule
# matching on anything outside this set.
KNOWN_SIGNALS: frozenset[str] = frozenset(
    {
        "component.unpinned",
        "component.no_provenance",
        "component.license_risk",
        "dataset.governance_gap",
        "prompt.unversioned",
        "project.secret",
    }
)
