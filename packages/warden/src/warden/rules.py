"""Warden's rule loading. Re-exports the shared engine and adds Warden's rule dir.

Importing this registers Warden's A* taxonomy so rule-category validation succeeds.
"""

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

import warden.taxonomy  # noqa: F401 — side effect: registers A* categories

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
    """Return Warden's packaged rules directory (``warden/rules``)."""
    return Path(__file__).resolve().parent / "rules"


def user_rules_dir() -> Path:
    """Return the user/community rules dir (``WARDEN_RULES_DIR`` or ``~/.warden/rules``)."""
    override = os.environ.get("WARDEN_RULES_DIR")
    return Path(override) if override else Path.home() / ".warden" / "rules"


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


# Every signal Warden's analyzers emit; ``warden rules lint`` rejects a rule matching
# on anything outside this set, which would otherwise silently never fire.
KNOWN_SIGNALS: frozenset[str] = frozenset(
    {
        # scopes.py
        "tool.excessive_scope",
        "agent.excessive_data",
        # graph.py
        "agent.toxic_combination",
        "agent.injectable_toxic_flow",
        "agent.injectable_action",
        "agent.open_egress",
        # limits.py
        "tool.ungated_high_impact",
        "tool.unsandboxed_exec",
        "agent.no_runaway_guards",
        # prompt.py
        "agent.weak_prompt",
        # secrets.py
        "agent.embedded_secret",
        "agent.unscanned_parts",
    }
)
