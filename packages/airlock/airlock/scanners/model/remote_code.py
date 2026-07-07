"""Remote/custom code execution via config (M5).

Parses JSON configs for ``trust_remote_code`` and ``auto_map``, and enumerates
custom ``modeling_*.py`` / ``configuration_*.py`` files. Configs are parsed as
data (``json.loads``); no repo Python is ever imported.
"""

from __future__ import annotations

import json
import re
from typing import Any

from airlock.core.signals import SignalBundle
from airlock.scanners.model.loader import ArtifactFile, ModelInventory

_CUSTOM_PY_RE = re.compile(
    r"(?i)^(modeling_|configuration_|tokenization_|image_processing_).+\.py$"
)


def _load_json(file: ArtifactFile) -> dict[str, Any] | None:
    try:
        data = json.loads(file.path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _find_key(obj: Any, key: str) -> Any:
    """Recursively search a nested dict/list for the first value of ``key``."""
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            found = _find_key(v, key)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _find_key(item, key)
            if found is not None:
                return found
    return None


def collect(inventory: ModelInventory, bundle: SignalBundle) -> None:
    """Emit M5 signals from configs and custom Python files."""
    for cfg in inventory.configs():
        data = _load_json(cfg)
        if data is None:
            continue
        trust = _find_key(data, "trust_remote_code")
        if trust is not None:
            bundle.add(
                "config.trust_remote_code",
                bool(trust),
                path=cfg.relpath,
                evidence=f"trust_remote_code = {trust}",
            )
        auto_map = _find_key(data, "auto_map")
        if auto_map:
            bundle.add(
                "config.auto_map",
                auto_map,
                path=cfg.relpath,
                evidence=f"auto_map = {json.dumps(auto_map)[:200]}",
            )

    for code in inventory.code_files():
        name = code.relpath.rsplit("/", 1)[-1]
        if _CUSTOM_PY_RE.match(name):
            bundle.add(
                "repo.custom_py",
                code.relpath,
                path=code.relpath,
                evidence=f"custom code file: {code.relpath}",
            )
