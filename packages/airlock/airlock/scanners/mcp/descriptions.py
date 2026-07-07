"""Tool-poisoning, injection, and hidden-content signals (P1/P2/P3).

Emits raw signals over tool names, descriptions, and parameter docs. The P1/P2
*pattern* rules live in YAML; this module additionally does unicode-category
analysis (P3) and a conservative untyped-output check (P2), which are awkward to
express as regex.
"""

from __future__ import annotations

import re
import unicodedata

from bulwark_core.signals import SignalBundle

from airlock.scanners.mcp.client import MCPInventory, ToolDef

# Codepoints that are invisible or can smuggle/obfuscate instructions.
_ZERO_WIDTH = {
    0x200B,  # zero-width space
    0x200C,  # zero-width non-joiner
    0x200D,  # zero-width joiner
    0x2060,  # word joiner
    0xFEFF,  # zero-width no-break space / BOM
    0x00AD,  # soft hyphen
}
_BIDI_CONTROLS = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))


def _hidden_codepoints(text: str) -> list[str]:
    """Return human-readable descriptions of hidden/obfuscated codepoints."""
    hits: list[str] = []
    for ch in text:
        cp = ord(ch)
        if cp in _ZERO_WIDTH:
            hits.append(f"zero-width U+{cp:04X}")
        elif cp in _BIDI_CONTROLS:
            hits.append(f"bidi-control U+{cp:04X}")
        elif 0xE0000 <= cp <= 0xE007F:
            hits.append(f"unicode-tag U+{cp:05X}")
        elif unicodedata.category(ch) in ("Cf", "Co"):  # format / private-use
            hits.append(f"format-char U+{cp:04X}")
    return hits


# Keywords that suggest a tool returns unbounded external content (P2 channel).
_EXTERNAL_OUTPUT_RE = re.compile(
    r"(?i)\b(fetch|http|url|download|scrape|crawl|read.*(web|page|site|url)|browse)\b"
)


def _returns_external_content(tool: ToolDef) -> bool:
    return bool(_EXTERNAL_OUTPUT_RE.search(tool.all_text()))


def collect(inventory: MCPInventory, bundle: SignalBundle) -> None:
    """Emit P1/P2/P3 signals for every tool in the inventory."""
    for tool in inventory.tools:
        loc = tool.name

        bundle.add("tool.name", tool.name, path=loc, evidence=tool.name)
        if tool.description:
            bundle.add(
                "tool.description",
                tool.description,
                path=loc,
                evidence=_oneline(tool.description),
            )
        for pname, doc in tool.param_docs():
            bundle.add(
                "tool.param_doc",
                doc,
                path=loc,
                detail=f"param: {pname}",
                evidence=_oneline(doc),
            )

        # P3 — hidden/obfuscated unicode in name or description.
        hidden = _hidden_codepoints(tool.name) + _hidden_codepoints(tool.description)
        if hidden:
            bundle.add(
                "tool.hidden_chars",
                hidden,
                path=loc,
                evidence=", ".join(sorted(set(hidden))),
            )

        # P2 — untyped output on a tool that returns external content.
        if tool.output_schema is None and _returns_external_content(tool):
            bundle.add(
                "tool.untyped_output",
                True,
                path=loc,
                evidence="returns external content with no declared output schema",
            )

    # Resources and prompts are also model-readable surfaces — run P1/P3 over them.
    for res in inventory.resources:
        _scan_text_surface(f"resource:{res.name or res.uri}", res.name, res.description, bundle)
    for prompt in inventory.prompts:
        _scan_text_surface(f"prompt:{prompt.name}", prompt.name, prompt.description, bundle)


def _scan_text_surface(loc: str, name: str, description: str, bundle: SignalBundle) -> None:
    """Emit P1/P3 signals for a non-tool text surface (resource/prompt)."""
    if description:
        bundle.add("tool.description", description, path=loc, evidence=_oneline(description))
    hidden = _hidden_codepoints(name or "") + _hidden_codepoints(description or "")
    if hidden:
        bundle.add("tool.hidden_chars", hidden, path=loc, evidence=", ".join(sorted(set(hidden))))


def _oneline(text: str) -> str:
    return " ".join(text.split())
