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
    unknown_signals,
    unused_signals,
)

import airlock.taxonomy  # noqa: F401 — side effect: registers M*/P* categories

__all__ = [
    "KNOWN_SIGNALS",
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
    "unknown_signals",
    "unused_signals",
    "user_rules_dir",
]

# Every signal Airlock's analyzers emit. A rule matching on anything outside this set
# can never fire, so ``airlock rules lint`` rejects it. Keep this in step when adding
# an analyzer — it is the contract between typed Python evidence and YAML policy.
KNOWN_SIGNALS: frozenset[str] = frozenset(
    {
        # model — pickle_scan.py / confusion.py / serialized.py
        "pickle.imports",
        "pickle.has_reduce",
        "pickle.strings",
        "pickle.unexpected_module",
        "model.pickle_file",
        # model — formats.py / serialized.py / confusion.py
        "model.formats",
        "model.safe_format",
        "model.pickle_without_safetensors",
        "model.format_mismatch",
        "model.keras_lambda",
        "model.onnx_custom_op",
        "model.onnx_external",
        "model.tf_custom_op",
        "model.tf_io_op",
        # model — remote_code.py
        "config.trust_remote_code",
        "config.auto_map",
        "repo.custom_py",
        # model — archive.py
        "archive.path_traversal",
        "archive.unexpected_member",
        "archive.zip_bomb",
        # model — provenance.py
        "provenance.hash_mismatch",
        "provenance.missing_hashes",
        "provenance.missing_model_card",
        # mcp — descriptions.py
        "tool.name",
        "tool.description",
        "tool.param_doc",
        "tool.hidden_chars",
        "tool.untyped_output",
        # mcp — permissions.py
        "tool.capability",
        "tool.wildcard",
        "exfil.path",
        # mcp — secrets.py
        "secret.finding",
        "tool.env_echo",
        # mcp — integrity.py
        "tool.definition_changed",
        "transport.insecure",
        "auth.missing",
        "tool.name_collision",
    }
)


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
