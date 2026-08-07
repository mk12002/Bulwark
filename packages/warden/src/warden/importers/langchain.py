"""Best-effort static import of a LangChain / LangGraph agent from a Python file.

Never executes the code — it reads the source and extracts tool bindings, the model,
and any system prompt with regex. Coverage is deliberately conservative; anything it
can't parse simply isn't reported (a manifest YAML is the fallback).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

from warden.importers.base import ImportError_, register
from warden.spec.model import AgentSpec, Tool

_MARKERS = (
    "langchain",
    "langgraph",
    "create_react_agent",
    "AgentExecutor",
    "from langchain",
    "@tool",
    "Tool(",
    "ChatOpenAI",
    "ChatAnthropic",
)

# Tool(name="x", description="y") — order-independent for the two kwargs.
_TOOL_CALL = re.compile(
    r"""Tool\((?=[^)]*name\s*=\s*["']([^"']+)["'])(?=[^)]*description\s*=\s*["']([^"']+)["'])""",
)
# @tool\n def name(...): """docstring"""
_TOOL_DECO = re.compile(
    r"""@tool[^\n]*\n\s*def\s+(\w+)\s*\([^)]*\)[^:]*:\s*(?:["']{3}(.*?)["']{3})?""",
    re.DOTALL,
)
_MODEL = re.compile(
    r"""(?:ChatOpenAI|ChatAnthropic|ChatOllama|init_chat_model)\([^)]*?model(?:_name)?\s*=\s*["']([^"']+)["']"""
)
_SYSTEM = re.compile(
    r"""(?:SystemMessage\(\s*(?:content\s*=\s*)?|system_(?:prompt|message)\s*=\s*|"system"\s*,\s*)["']{1,3}(.+?)["']{1,3}""",
    re.DOTALL,
)


def detect(path: Path, data: Any) -> bool:
    if path.suffix.lower() != ".py":
        return False
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return any(m in text for m in _MARKERS)


def load(path: Path, data: Any) -> AgentSpec:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ImportError_(f"cannot read {path}: {exc}") from exc

    tools: dict[str, Tool] = {}
    for name, desc in _TOOL_CALL.findall(text):
        tools[name] = Tool(name=name, description=desc)
    for name, doc in _TOOL_DECO.findall(text):
        tools.setdefault(name, Tool(name=name, description=(doc or "").strip() or name))

    model_m = _MODEL.search(text)
    system_m = _SYSTEM.search(text)
    autonomy: Literal["manual", "assisted", "autonomous"] = (
        "autonomous" if ("create_react_agent" in text or "AgentExecutor" in text) else "assisted"
    )
    return AgentSpec(
        name=path.stem,
        model=model_m.group(1) if model_m else None,
        system_prompt=system_m.group(1).strip() if system_m else None,
        tools=list(tools.values()),
        autonomy=autonomy,
    )


register("langchain", detect, load)
