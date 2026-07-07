"""Capability classification and the cross-tool exfiltration graph (P4/P5).

Each tool is classified into zero or more capabilities from its name, description,
and input schema. Over-broad capabilities are emitted as ``tool.capability``
signals (P4). A reachable sensitive-source -> network/write-sink pairing across the
server's tools is emitted as ``exfil.path`` (P5).
"""

from __future__ import annotations

import re

from bulwark_core.signals import SignalBundle

from airlock.scanners.mcp.client import MCPInventory, ToolDef

# Capability -> regex over the tool's combined text (all case-insensitive).
_CAPABILITY_PATTERNS: dict[str, re.Pattern[str]] = {
    "shell": re.compile(
        r"\b(shell|exec(ute)?|subprocess|system\(|bash|/bin/sh|powershell|cmd\.exe|"
        r"run[_ ]?(command|cmd|script)|terminal)\b",
        re.IGNORECASE,
    ),
    "fs_write": re.compile(
        r"\b(write|save|delete|remove|unlink|create|overwrite|modify|append|"
        r"put[_ ]?file|rmdir|mkdir)\b.*\b(file|path|dir|directory|disk)\b|"
        r"\b(write|delete|overwrite)[_ ]?file\b",
        re.IGNORECASE,
    ),
    "fs_read": re.compile(
        r"\b(read|open|cat|load|list)\b.*\b(file|path|dir|directory|disk)\b|"
        r"\b(read|get)[_ ]?file\b",
        re.IGNORECASE,
    ),
    "network": re.compile(
        r"\b(http|https|url|fetch|request|download|upload|send|post|webhook|"
        r"curl|wget|socket|egress|outbound)\b",
        re.IGNORECASE,
    ),
    "read_sensitive": re.compile(
        r"(env(ironment)?[_ ]?var|credential|secret|token|password|api[_ -]?key|"
        r"~/\.ssh|id_rsa|\.aws/credentials|/etc/passwd|private[_ ]?key)",
        re.IGNORECASE,
    ),
}

# Capabilities that read data an attacker would want to exfiltrate.
_SOURCE_CAPS = {"read_sensitive", "fs_read"}
# Capabilities that can move data off the host.
_SINK_CAPS = {"network", "fs_write"}

_WILDCARD_RE = re.compile(
    r"(^\*$|wildcard|any (path|file|host|url)|all (files|paths|scopes))", re.IGNORECASE
)


def classify(tool: ToolDef) -> set[str]:
    """Return the set of capabilities a tool exposes."""
    text = tool.all_text()
    caps = {cap for cap, rx in _CAPABILITY_PATTERNS.items() if rx.search(text)}
    return caps


def _has_wildcard(tool: ToolDef) -> bool:
    if _WILDCARD_RE.search(tool.all_text()):
        return True
    props = tool.input_schema.get("properties")
    if isinstance(props, dict):
        for spec in props.values():
            if isinstance(spec, dict):
                default = spec.get("default")
                if isinstance(default, str) and default.strip() in ("*", "**", "all"):
                    return True
    return False


def collect(inventory: MCPInventory, bundle: SignalBundle) -> None:
    """Emit P4 capability/wildcard signals and P5 exfil-path signals."""
    tool_caps: dict[str, set[str]] = {}
    for tool in inventory.tools:
        caps = classify(tool)
        tool_caps[tool.name] = caps
        for cap in sorted(caps):
            bundle.add(
                "tool.capability",
                cap,
                path=tool.name,
                detail=cap,
                evidence=f"{tool.name} exposes capability: {cap}",
            )
        if _has_wildcard(tool):
            bundle.add(
                "tool.wildcard",
                True,
                path=tool.name,
                evidence=f"{tool.name} declares a wildcard/unconstrained scope",
            )

    _emit_exfil_paths(tool_caps, bundle)


def _emit_exfil_paths(tool_caps: dict[str, set[str]], bundle: SignalBundle) -> None:
    sources = [(n, c & _SOURCE_CAPS) for n, c in tool_caps.items() if c & _SOURCE_CAPS]
    sinks = [(n, c & _SINK_CAPS) for n, c in tool_caps.items() if c & _SINK_CAPS]
    for src_name, src_caps in sources:
        for sink_name, sink_caps in sinks:
            if src_name == sink_name and not (src_caps and sink_caps):
                continue
            src_c = ", ".join(sorted(src_caps))
            sink_c = ", ".join(sorted(sink_caps))
            bundle.add(
                "exfil.path",
                f"{src_name}->{sink_name}",
                path=f"{src_name} -> {sink_name}",
                evidence=(
                    f"'{src_name}' ({src_c}) can read sensitive data; "
                    f"'{sink_name}' ({sink_c}) can send it outward"
                ),
            )
