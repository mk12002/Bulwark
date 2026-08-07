"""Config importers → AgentSpec."""

from __future__ import annotations

# Register built-in importers on package import (each self-registers). Detection is
# order-independent: the generic manifest importer defers to the specific shapes.
from warden.importers.base import ImportError_, import_agent, register

# The built-in importers self-register on import; ``import_agent`` imports them
# lazily (specific shapes first, the generic manifest importer as the fallback).

__all__ = ["ImportError_", "import_agent", "register"]
