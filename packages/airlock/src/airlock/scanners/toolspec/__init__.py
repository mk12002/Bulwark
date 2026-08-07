"""Tool-definition-file scanner.

The P1–P9 taxonomy applies to *any* set of agent tool definitions, not only live
MCP servers. This target parses a static tool-spec file — OpenAI function-calling
``tools``, Anthropic ``tools``, or a LangChain/plain list — into the same
:class:`~airlock.scanners.mcp.client.MCPInventory` the MCP scanner uses, so all of
``descriptions``/``permissions``/``secrets``/``integrity`` run unchanged.
"""

from __future__ import annotations

from airlock.scanners.toolspec.loader import ToolSpecError, load_toolspec

__all__ = ["ToolSpecError", "load_toolspec"]
