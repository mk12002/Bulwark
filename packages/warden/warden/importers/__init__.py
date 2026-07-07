"""Config importers → AgentSpec."""

from __future__ import annotations

# Register built-in importers on package import.
import warden.importers.manifest_yaml
import warden.importers.mcp_config  # noqa: F401
from warden.importers.base import ImportError_, import_agent, register

__all__ = ["ImportError_", "import_agent", "register"]
