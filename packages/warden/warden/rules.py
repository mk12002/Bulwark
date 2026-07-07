"""Warden's rule loading. Re-exports the shared engine and adds Warden's rule dir.

Importing this registers Warden's A* taxonomy so rule-category validation succeeds.
"""

from __future__ import annotations

import os
from pathlib import Path

from bulwark_core.rules import (
    LoadedRule,
    RuleEngine,
    RuleLoadError,
    load_rule_dirs,
    load_rule_pack,
)

import warden.taxonomy  # noqa: F401 — side effect: registers A* categories

__all__ = [
    "LoadedRule",
    "RuleEngine",
    "RuleLoadError",
    "default_rules_dir",
    "load_rule_pack",
    "load_rules",
    "user_rules_dir",
]


def default_rules_dir() -> Path:
    """Return Warden's packaged rules directory (``warden/rules``)."""
    return Path(__file__).resolve().parent / "rules"


def user_rules_dir() -> Path:
    """Return the user/community rules dir (``WARDEN_RULES_DIR`` or ``~/.warden/rules``)."""
    override = os.environ.get("WARDEN_RULES_DIR")
    return Path(override) if override else Path.home() / ".warden" / "rules"


def load_rules(rules_dir: Path | None = None) -> list[LoadedRule]:
    """Load Warden's rule packs (packaged + community), or a single given dir."""
    roots = [rules_dir] if rules_dir is not None else [default_rules_dir(), user_rules_dir()]
    return load_rule_dirs(roots)
