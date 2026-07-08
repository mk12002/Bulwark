"""Import an OpenAI Assistants API config (JSON) into an AgentSpec."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from warden.importers.base import ImportError_, register
from warden.spec.model import AgentSpec, Tool

# Built-in Assistants tool types → a synthetic Tool with a telling description.
_BUILTIN = {
    "code_interpreter": ("code_interpreter", "Execute arbitrary code in a sandbox."),
    "file_search": ("file_search", "Read and search the uploaded files / knowledge base."),
    "retrieval": ("retrieval", "Read and search the uploaded files (retrieval)."),
}


def detect(path: Path, data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    return data.get("object") == "assistant" or ("instructions" in data and "tools" in data)


def load(path: Path, data: Any) -> AgentSpec:
    if not isinstance(data, dict):
        raise ImportError_(f"{path}: not an assistant config")
    tools: list[Tool] = []
    for item in data.get("tools", []) or []:
        if not isinstance(item, dict):
            continue
        ttype = item.get("type")
        if ttype == "function" and isinstance(item.get("function"), dict):
            fn = item["function"]
            tools.append(Tool(name=fn.get("name", "function"), description=fn.get("description")))
        elif ttype in _BUILTIN:
            name, desc = _BUILTIN[ttype]
            tools.append(Tool(name=name, description=desc, sandboxed=ttype == "code_interpreter"))
    return AgentSpec(
        name=data.get("name") or data.get("id") or path.stem,
        model=data.get("model"),
        system_prompt=data.get("instructions"),
        tools=tools,
        autonomy="assisted",
    )


register("openai_assistant", detect, load)
