"""Definition integrity, transport, and shadowing checks (P7/P8/P9).

- P7: hash each tool definition, persist a baseline per target, and diff on
  re-scan to catch silent rug-pulls.
- P8: flag plaintext/unauthenticated transport (from the inventory).
- P9: flag tool names that collide with well-known trusted tools or with each
  other across the server.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from bulwark_core.signals import SignalBundle

from airlock.scanners.mcp.client import MCPInventory, ToolDef

# A small starter set of well-known tool names worth protecting from shadowing.
_KNOWN_TRUSTED_NAMES = {
    "read_file",
    "write_file",
    "list_files",
    "search",
    "web_search",
    "fetch",
    "execute",
    "run_python",
    "send_email",
    "get_secret",
}


def _state_dir() -> Path:
    base = os.environ.get("AIRLOCK_STATE_DIR")
    root = Path(base) if base else Path.home() / ".airlock"
    return root / "mcp_baseline"


def _tool_hash(tool: ToolDef) -> str:
    payload = json.dumps(
        {
            "name": tool.name,
            "description": tool.description,
            "input_schema": tool.input_schema,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _baseline_path(target: str) -> Path:
    key = hashlib.sha256(target.encode("utf-8")).hexdigest()[:16]
    return _state_dir() / f"{key}.json"


def _check_rug_pull(inventory: MCPInventory, bundle: SignalBundle, state_dir: Path) -> None:
    path = _baseline_path(inventory.target)
    current = {t.name: _tool_hash(t) for t in inventory.tools}
    previous: dict[str, str] = {}
    if path.exists():
        try:
            previous = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            previous = {}

    for name, digest in current.items():
        if name in previous and previous[name] != digest:
            bundle.add(
                "tool.definition_changed",
                name,
                path=name,
                evidence=f"definition of '{name}' changed since the approved baseline",
            )

    # Persist/update the baseline for next time.
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(current, sort_keys=True), encoding="utf-8")
    except OSError:
        pass


def _check_transport(inventory: MCPInventory, bundle: SignalBundle) -> None:
    if inventory.is_remote and not inventory.secure_transport:
        bundle.add(
            "transport.insecure",
            True,
            path=inventory.target,
            evidence=f"plaintext transport: {inventory.transport}",
        )
    if inventory.is_remote and not inventory.auth_present:
        bundle.add(
            "auth.missing",
            True,
            path=inventory.target,
            evidence="remote server reached without authentication",
        )


def _check_shadowing(inventory: MCPInventory, bundle: SignalBundle) -> None:
    seen: dict[str, int] = {}
    for tool in inventory.tools:
        seen[tool.name] = seen.get(tool.name, 0) + 1
    for tool in inventory.tools:
        lname = tool.name.lower()
        if lname in _KNOWN_TRUSTED_NAMES:
            bundle.add(
                "tool.name_collision",
                tool.name,
                path=tool.name,
                evidence=f"'{tool.name}' collides with a well-known trusted tool name",
            )
        if seen.get(tool.name, 0) > 1:
            bundle.add(
                "tool.name_collision",
                tool.name,
                path=tool.name,
                evidence=f"duplicate tool name '{tool.name}' on this server",
            )


def collect(inventory: MCPInventory, bundle: SignalBundle) -> None:
    """Emit P7/P8/P9 signals for the inventory."""
    _check_rug_pull(inventory, bundle, _state_dir())
    _check_transport(inventory, bundle)
    _check_shadowing(inventory, bundle)
