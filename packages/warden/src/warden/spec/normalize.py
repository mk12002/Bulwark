"""Canonicalization + capability tagging for the AgentSpec.

Maps each tool's name/description/scopes onto a set of :class:`Capability` values
using a keyword lexicon. The lexicon is intentionally simple and data-driven so it
can be extended (and later moved to YAML) via PRs rather than logic edits.
"""

from __future__ import annotations

import re

from warden.spec.model import AgentSpec, Capability, Tool

# capability -> list of regex fragments matched against a tool's combined text.
_LEXICON: dict[Capability, list[str]] = {
    Capability.SHELL: [
        r"\bshell\b",
        r"\bbash\b",
        r"\bcommand\b",
        r"\bterminal\b",
        r"exec_cmd",
        r"run_shell",
        r"system\(",
    ],
    Capability.CODE_EXEC: [
        r"\bexec(ute)?\b",
        r"\beval\b",
        r"run_(code|python|script)",
        r"code[_ ]?interpreter",
        # "sandbox" alone is not evidence of execution — it most often appears
        # because the author is *reassuring* you the tool is sandboxed. Require it
        # next to an execution verb.
        r"\bsandbox(ed|ing)?\b[^.]{0,40}\b(run|exec(ute)?|code|script|python)\b",
        r"\b(run|exec(ute)?|code|script|python)\b[^.]{0,40}\bsandbox(ed|ing)?\b",
    ],
    Capability.FS_WRITE: [
        r"write[_ ]?file",
        r"\bsave\b",
        r"\bdelete\b",
        r"\bremove\b",
        r"\bwrite\b",
        r"put[_ ]?object",
        r"\bmkdir\b",
    ],
    Capability.FS_READ: [
        r"read[_ ]?file",
        r"\bopen\b",
        r"\bcat\b",
        r"list[_ ]?(dir|files)",
        r"\bglob\b",
        r"load[_ ]?file",
    ],
    Capability.NET_OUT: [
        r"\bhttp\b",
        r"\burl\b",
        r"\bfetch\b",
        r"\brequest\b",
        r"\bdownload\b",
        r"\bupload\b",
        r"\bpost\b",
        r"\bwebhook\b",
        r"\bcurl\b",
        r"api[_ ]?call",
    ],
    Capability.BROWSE: [
        r"\bbrowse\b",
        r"\bbrowser\b",
        r"web[_ ]?search",
        r"\bscrape\b",
        r"\bcrawl\b",
        r"visit[_ ]?url",
    ],
    Capability.SECRET_READ: [
        r"\bsecret\b",
        r"\bcredential\b",
        r"\btoken\b",
        r"\bpassword\b",
        r"api[_ -]?key",
        r"\.env\b",
        r"vault",
        r"id_rsa",
    ],
    Capability.DB_READ: [
        r"\bquery\b",
        r"\bselect\b",
        r"db[_ ]?read",
        r"\bsql\b",
        r"database",
        r"fetch[_ ]?rows",
    ],
    Capability.DB_WRITE: [
        r"\binsert\b",
        r"\bupdate\b",
        r"\bdelete[_ ]?row",
        r"db[_ ]?write",
        r"\bupsert\b",
    ],
    Capability.EMAIL_SEND: [
        r"\bemail\b",
        r"send[_ ]?mail",
        r"\bsmtp\b",
        r"\bsendgrid\b",
        r"\bmailer\b",
    ],
    Capability.FINANCIAL: [
        r"\bpayment\b",
        r"\bcharge\b",
        r"\bstripe\b",
        r"\btransfer\b",
        r"\bpurchase\b",
        r"\bwire\b",
        r"\brefund\b",
    ],
    Capability.DESTRUCTIVE: [
        r"\bdelete\b",
        r"\bdrop\b",
        r"\bwipe\b",
        r"\bdestroy\b",
        # "format" means "format a disk", not "format a string/response/date".
        # Bare \bformat\b was the noisiest pattern in the lexicon: it classified
        # `format_response` as DESTRUCTIVE, which is HIGH_IMPACT, which produced a
        # spurious A3 missing-gate finding and +10 agency score on a text formatter.
        r"\bformat(ting|ted)?\b[^.]{0,30}\b(disk|drive|volume|partition|filesystem|device)\b",
        r"\brm\b",
        r"terminate",
    ],
    Capability.MEMORY_WRITE: [r"memory[_ ]?(write|store|save)", r"remember", r"persist[_ ]?memory"],
}

_COMPILED: dict[Capability, list[re.Pattern[str]]] = {
    cap: [re.compile(p, re.IGNORECASE) for p in pats] for cap, pats in _LEXICON.items()
}

# Scope strings that signal excessive breadth.
_WILDCARD_SCOPE = re.compile(
    r"(^\*+$|/\*|\*\*|:all\b|\ball\b|wildcard|any\b|unrestricted|root)", re.IGNORECASE
)

_SENSITIVE_KINDS = {"secret", "secrets", "env", "credential", "credentials", "vault"}


def _tool_text(tool: Tool) -> str:
    parts = [tool.name, tool.description or "", " ".join(tool.scopes)]
    if tool.source:
        parts.append(tool.source)
    return "\n".join(parts)


def classify_tool(tool: Tool) -> set[Capability]:
    """Return the capability set implied by a tool's text and scopes."""
    text = _tool_text(tool)
    caps = {cap for cap, rxs in _COMPILED.items() if any(rx.search(text) for rx in rxs)}
    return caps or {Capability.UNKNOWN}


def has_wildcard_scope(tool: Tool) -> bool:
    """Whether any of a tool's scopes is unconstrained/wildcard."""
    return any(_WILDCARD_SCOPE.search(s) for s in tool.scopes)


def normalize(spec: AgentSpec) -> AgentSpec:
    """Tag every tool with capabilities and mark sensitive data sources. In place."""
    for tool in spec.tools:
        if not tool.capabilities:
            tool.capabilities = classify_tool(tool)
    for ds in spec.data_sources:
        if ds.kind.lower() in _SENSITIVE_KINDS:
            ds.sensitive = True
        if ds.scope and _WILDCARD_SCOPE.search(ds.scope):
            ds.sensitive = True
    return spec
