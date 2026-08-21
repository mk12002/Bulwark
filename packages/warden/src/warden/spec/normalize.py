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
        # "open" needs a filesystem noun: bare \bopen\b matched "open a support
        # ticket", "open a pull request", "open a connection" — the same
        # verb-without-a-domain-noun mistake as \bformat\b and \bsandbox\b.
        r"\bopen(s|ing|ed)?\b[^.]{0,30}\b(file|path|dir|directory|disk|folder)\b",
        r"\bcat\b",
        r"list[_ ]?(dir|files)",
        r"\bglob\b",
        r"load[_ ]?file",
    ],
    Capability.NET_OUT: [
        r"\bhttp\b",
        r"\burl\b",
        r"\bfetch\b",
        # A bare \brequest\b matched "the user's request", "clarify their request" —
        # the single noisiest source of spurious NET_OUT on benign agents, because
        # "request" is ordinary English before it is an HTTP verb. Require it to sit
        # next to something actually network-shaped.
        r"\brequests?\b[^.]{0,30}\b(http|https|url|api|web|server|endpoint|host)\b",
        r"\b(http|https|url|api|web|server|endpoint|host)\b[^.]{0,30}\brequests?\b",
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
        # "transfer" and "wire" are only financial next to a money noun. Bare, they
        # matched "transfer the meaning", "transfer learning", and "wire up a tool" —
        # and FINANCIAL is HIGH_IMPACT, so each miss cost a spurious A3 missing-gate
        # finding on a text tool. Same fix as \bformat\b and \bopen\b above.
        r"\b(transfer|wire)(s|red|ring)?\b[^.]{0,40}"
        r"\b(fund|funds|money|payment|amount|balance|account|cash|invoice|usd|eur)\b",
        r"\b(fund|funds|money|payment|amount|balance|account|cash|invoice|usd|eur)\b"
        r"[^.]{0,40}\b(transfer|wire)(s|red|ring)?\b",
        r"\bpurchase\b",
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

# Split camelCase/PascalCase at a lower→upper transition: browseWeb -> "browse Web".
# Also handles acronym runs (HTTPRequest -> "HTTP Request").
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _tool_text(tool: Tool) -> str:
    """The searchable text for a tool: its raw fields plus case-normalized copies.

    Tool names are overwhelmingly ``snake_case``, and ``_`` is a regex word character —
    so ``\\bbrowse\\b`` does **not** match ``browse_web``, and ``\\bshell\\b`` does not
    match ``run_shell``. Several capabilities were therefore silently unclassifiable
    under the naming convention the ecosystem actually uses, which in turn meant
    Warden's flagship CRITICAL finding (an attacker-triggerable exfiltration flow) did
    not fire on an agent wiring a tool called ``browse_web``.

    ``camelCase`` had exactly the same defect for exactly the same reason, and it went
    unnoticed for longer because the fixtures were all snake_case: ``browseWeb`` has no
    word boundary before ``Web``, so a TypeScript/JavaScript assembly — most of the MCP
    ecosystem — classified every tool as ``UNKNOWN`` and lost A2 entirely. The
    robustness study in ``scripts/study.py`` is what surfaced it.

    Appending underscore/hyphen- and camel-normalized copies makes word-boundary
    patterns work on both conventions without weakening them, and without touching the
    literal patterns (``exec_cmd``, ``run_shell``) that match the raw form.
    """
    parts = [tool.name, tool.description or "", " ".join(tool.scopes)]
    if tool.source:
        parts.append(tool.source)
    raw = "\n".join(parts)

    variants = [raw]
    desnaked = raw.replace("_", " ").replace("-", " ")
    if desnaked != raw:
        variants.append(desnaked)
    decameled = _CAMEL_BOUNDARY.sub(" ", raw)
    if decameled != raw:
        variants.append(decameled)
    return "\n".join(variants)


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
