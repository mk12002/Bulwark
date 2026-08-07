"""Import a CrewAI agents.yaml into an AgentSpec (aggregating the crew)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from warden.importers.base import ImportError_, register
from warden.spec.model import AgentSpec, Tool


def _is_agent(v: Any) -> bool:
    return isinstance(v, dict) and "role" in v and "goal" in v


def detect(path: Path, data: Any) -> bool:
    if isinstance(data, dict):
        if isinstance(data.get("agents"), (dict | list)):
            return True
        return any(_is_agent(v) for v in data.values())
    return False


def _agents(data: dict) -> list[dict]:
    agents = data.get("agents")
    if isinstance(agents, dict):
        return [v for v in agents.values() if isinstance(v, dict)]
    if isinstance(agents, list):
        return [v for v in agents if isinstance(v, dict)]
    return [v for v in data.values() if _is_agent(v)]


def load(path: Path, data: Any) -> AgentSpec:
    if not isinstance(data, dict):
        raise ImportError_(f"{path}: not a CrewAI config")
    agents = _agents(data)
    tools: list[Tool] = []
    prompts: list[str] = []
    delegates = False
    for a in agents:
        for t in a.get("tools", []) or []:
            name = t if isinstance(t, str) else (t.get("name") if isinstance(t, dict) else None)
            if name:
                desc = t.get("description") if isinstance(t, dict) else name.replace("_", " ")
                tools.append(Tool(name=str(name), description=desc))
        role = a.get("role", "")
        goal = a.get("goal", "")
        backstory = a.get("backstory", "")
        prompts.append(f"{role}. {goal} {backstory}".strip())
        if a.get("allow_delegation"):
            delegates = True
    return AgentSpec(
        name=path.stem,
        system_prompt="\n".join(p for p in prompts if p) or None,
        tools=tools,
        autonomy="autonomous" if delegates else "assisted",
    )


register("crewai", detect, load)
