"""Airlock's rule loading: packaged rule dir + community user dir.

Re-exports the shared rule machinery from ``bulwark_core.rules`` and adds Airlock's
default rule-directory resolution. Importing this module registers Airlock's
taxonomy (M*/P*) so rule-category validation succeeds.
"""

from __future__ import annotations

import os
from pathlib import Path

from bulwark_core.rules import (
    PREDICATES,
    LoadedRule,
    Rule,
    RuleEngine,
    RuleLoadError,
    RuleMatch,
    RulePack,
    load_rule_dirs,
    load_rule_pack,
)

import airlock.taxonomy  # noqa: F401 — side effect: registers M*/P* categories

__all__ = [
    "PREDICATES",
    "LoadedRule",
    "Rule",
    "RuleEngine",
    "RuleLoadError",
    "RuleMatch",
    "RulePack",
    "default_rules_dir",
    "load_rule_pack",
    "load_rules",
    "user_rules_dir",
]


def default_rules_dir() -> Path:
    """Return Airlock's packaged rules directory (``airlock/rules``)."""
    return Path(__file__).resolve().parent / "rules"


def user_rules_dir() -> Path:
    """Return the user/community rules dir (installed by ``airlock rules update``).

    Overridable with ``AIRLOCK_RULES_DIR``; defaults to ``~/.airlock/rules``.
    """
    override = os.environ.get("AIRLOCK_RULES_DIR")
    return Path(override) if override else Path.home() / ".airlock" / "rules"


def load_rules(rules_dir: Path | None = None) -> list[LoadedRule]:
    """Load Airlock's rule packs (packaged + community), or a single given dir."""
    roots = [rules_dir] if rules_dir is not None else [default_rules_dir(), user_rules_dir()]
    return load_rule_dirs(roots)
