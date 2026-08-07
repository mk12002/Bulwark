"""Airlock — static security scanner for the AI agent supply chain."""

from __future__ import annotations

__version__ = "0.1.0"

# Register Airlock's M*/P* categories into the shared bulwark_core registry so
# rule-category validation and report lookups work for any `import airlock`.
from airlock import taxonomy as _taxonomy  # noqa: F401

__all__ = ["__version__"]
