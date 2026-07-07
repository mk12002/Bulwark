"""Manifest's rule loading. Registers B* taxonomy and adds Manifest's rule dir."""

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

import manifest.taxonomy  # noqa: F401 — side effect: registers B* categories

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
    return Path(__file__).resolve().parent / "rules"


def user_rules_dir() -> Path:
    override = os.environ.get("MANIFEST_RULES_DIR")
    return Path(override) if override else Path.home() / ".manifest" / "rules"


def load_rules(rules_dir: Path | None = None) -> list[LoadedRule]:
    roots = [rules_dir] if rules_dir is not None else [default_rules_dir(), user_rules_dir()]
    return load_rule_dirs(roots)
