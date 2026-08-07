"""Warden — least-privilege auditor for AI agents (part of the Bulwark suite)."""

from __future__ import annotations

__version__ = "0.2.0"

# Register Warden's A* categories into the shared bulwark_core registry.
from warden import taxonomy as _taxonomy  # noqa: F401

__all__ = ["__version__"]
