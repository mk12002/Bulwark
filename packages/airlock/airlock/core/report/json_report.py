"""JSON renderer: the full ScanResult as a stable, machine-readable document."""

from __future__ import annotations

import json

from airlock.core.findings import ScanResult


def render_json(result: ScanResult, *, indent: int = 2) -> str:
    """Serialize a scan result to JSON text.

    Output is ASCII-safe (non-ASCII escaped as ``\\uXXXX``) so a redirected file
    is portable regardless of the console's encoding — a baseline written on a
    Windows cp1252 console still round-trips as UTF-8.
    """
    return json.dumps(result.model_dump(mode="json"), indent=indent, ensure_ascii=True)
