"""Manifest — AI-BOM generator for AI systems (part of the Bulwark suite)."""

from __future__ import annotations

__version__ = "0.1.0"

# Register Manifest's B* categories into the shared bulwark_core registry.
from manifest import taxonomy as _taxonomy  # noqa: F401

__all__ = ["__version__"]
