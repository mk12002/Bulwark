"""Presentation logic for the Bulwark Hugging Face Space — no Gradio imports.

Kept separate from ``app.py`` so the part that can actually be wrong (calling the
scanners, shaping their output) is importable and testable without a UI framework
installed. ``app.py`` is a thin Gradio wrapper over these three functions.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from bulwark_core.severity import Severity

# Uploads are bounded before anything touches them. Airlock never executes what it
# scans, but a decompression bomb is still a resource question, and the Space runs on
# a shared free CPU tier.
MAX_UPLOAD_BYTES = 25 * 1024 * 1024

_SEV_BADGE = {
    Severity.CRITICAL: "🟥 CRITICAL",
    Severity.HIGH: "🟧 HIGH",
    Severity.MEDIUM: "🟨 MEDIUM",
    Severity.LOW: "🟦 LOW",
    Severity.INFO: "⬜ INFO",
}

EXAMPLE_TRIFECTA = """\
# The lethal trifecta: read untrusted input, read a secret, send it anywhere.
# Every tool here is individually reasonable. Together they are an exfiltration path
# an attacker can trigger by planting instructions on a web page.
name: web-research-agent
model: gpt-4o
autonomy: autonomous
system_prompt: "You research topics on the web for the user."
tools:
  - name: browse_web
    description: "Browse the web and read the contents of any page."
  - name: read_secrets
    description: "Read credentials from the local vault."
    scopes: ["vault/*"]
  - name: send_webhook
    description: "POST arbitrary data to any external URL."
"""

EXAMPLE_DEVOPS = """\
# An over-privileged devops agent: a wildcard shell with no gate and no limits.
name: devops-agent
model: claude-3-5-sonnet
autonomy: autonomous
system_prompt: "Do whatever it takes to fix the server."
tools:
  - name: run_shell
    description: "Execute an arbitrary shell command on the host."
    scopes: ["*"]
"""

EXAMPLE_CLEAN = """\
# A minimal, well-scoped, gated agent. Warden should find nothing.
name: calculator-bot
model: gpt-4o-mini
autonomy: assisted
system_prompt: >-
  Answer arithmetic questions only. Refuse anything else.
tools:
  - name: add
    description: "Add two numbers and return the sum."
  - name: multiply
    description: "Multiply two numbers and return the product."
limits:
  max_iterations: 10
  timeout_s: 60
"""

EXAMPLE_ASSISTANT = """\
{
  "object": "assistant",
  "name": "data-analyst",
  "model": "gpt-4o",
  "instructions": "You are a data analyst. Do whatever it takes to answer questions.",
  "tools": [
    {"type": "code_interpreter"},
    {"type": "file_search"},
    {"type": "function",
     "function": {"name": "send_report",
                  "description": "Send an email to any recipient address"}}
  ]
}
"""


def _findings_table(result: object, empty: str) -> str:
    findings = result.sorted_findings()  # type: ignore[attr-defined]
    if not findings:
        return f"\n_{empty}_\n"
    rows = [
        "| Severity | Code | Finding | Where |",
        "| --- | --- | --- | --- |",
    ]
    for f in findings:
        where = f.location.path or f.location.target or "—"
        title = f.title.replace("|", "\\|")
        rows.append(f"| {_SEV_BADGE.get(f.severity, f.severity.value)} | `{f.category}` | {title} | `{where}` |")
    return "\n".join(rows)


def _explain(result: object) -> str:
    """The 'why it matters' block for the highest-severity finding."""
    findings = result.sorted_findings()  # type: ignore[attr-defined]
    if not findings:
        return ""
    top = findings[0]
    out = [f"\n### Most severe: `{top.category}` — {top.title}\n"]
    if top.rationale:
        out.append(f"**Why it matters.** {top.rationale}\n")
    if top.evidence:
        out.append(f"**Evidence.** `{str(top.evidence)[:400]}`\n")
    if top.remediation:
        out.append(f"**Remediation.** {top.remediation}\n")
    return "\n".join(out)


def audit_agent(config_text: str) -> str:
    """Audit a pasted agent config. Returns markdown."""
    if not config_text or not config_text.strip():
        return "_Paste an agent config, or pick one of the examples below._"

    from warden.rules import RuleEngine, load_rules
    from warden.scanner import WardenScanner

    suffix = ".json" if config_text.lstrip().startswith("{") else ".yaml"
    tmp = Path(tempfile.mkdtemp()) / f"agent{suffix}"
    tmp.write_text(config_text, encoding="utf-8")

    try:
        result = WardenScanner(RuleEngine(load_rules())).scan(str(tmp))
    except Exception as exc:  # surfaced, never swallowed
        return f"**Could not parse that config.**\n\n```\n{type(exc).__name__}: {exc}\n```"

    spec = result.meta.get("agent_spec", {})
    caps = sorted({c for t in spec.get("tools", []) for c in t.get("capabilities", [])})
    score = result.score or 0
    verdict = "no findings — this assembly looks least-privilege" if not result.findings else (
        f"{len(result.findings)} finding(s)"
    )

    out = [
        f"## Agency score: {score}/100",
        "",
        f"**Importer:** `{result.meta.get('importer', '?')}` · "
        f"**Tools:** {len(spec.get('tools', []))} · "
        f"**Autonomy:** `{spec.get('autonomy', '?')}`",
        "",
        f"**Capabilities detected:** {', '.join(f'`{c}`' for c in caps) if caps else '_none_'}",
        "",
        f"**Verdict:** {verdict}",
        "",
        _findings_table(result, "Nothing found — this agent holds no more power than its job needs."),
        _explain(result),
    ]
    return "\n".join(out)


def recommend_agent(config_text: str) -> str:
    """Show the least-privilege rewrite for a pasted config. Returns markdown."""
    if not config_text or not config_text.strip():
        return "_Paste an agent config first._"

    import yaml

    from warden.recommend import recommend
    from warden.rules import RuleEngine, load_rules
    from warden.scanner import WardenScanner
    from warden.spec.model import AgentSpec

    suffix = ".json" if config_text.lstrip().startswith("{") else ".yaml"
    tmp = Path(tempfile.mkdtemp()) / f"agent{suffix}"
    tmp.write_text(config_text, encoding="utf-8")

    scanner = WardenScanner(RuleEngine(load_rules()))
    try:
        before = scanner.scan(str(tmp))
        spec = AgentSpec.model_validate(before.meta["agent_spec"])
    except Exception as exc:
        return f"**Could not parse that config.**\n\n```\n{type(exc).__name__}: {exc}\n```"

    rec = recommend(spec)
    after = scanner.audit_spec(rec.hardened, target="hardened")

    out = [
        f"## Agency score: {before.score or 0} → {after.score or 0}",
        "",
        "### Applied automatically",
        "",
    ]
    out += [f"- {c}" for c in rec.changes] or ["_Nothing to harden mechanically._"]

    if rec.advisories:
        out += [
            "",
            "### Needs a human decision",
            "",
            "Warden will not delete a tool to break a toxic combination — that changes what",
            "the agent is *for*. These are surfaced instead of silently rewritten:",
            "",
        ]
        out += [f"- ⚠️ {a}" for a in rec.advisories]

    out += [
        "",
        "### The hardened config",
        "",
        "```yaml",
        yaml.safe_dump(
            rec.hardened.model_dump(mode="json", exclude_none=True), sort_keys=False
        ).strip(),
        "```",
    ]
    return "\n".join(out)


def scan_model(file_path: str | None) -> str:
    """Statically scan an uploaded model artifact. Returns markdown."""
    if not file_path:
        return "_Upload a model artifact (`.pkl`, `.bin`, `.pt`, `.safetensors`, `.onnx`, `.h5`, `.npy`)._"

    path = Path(file_path)
    if not path.exists():
        return "_That file is no longer available — try uploading again._"

    size = path.stat().st_size
    if size > MAX_UPLOAD_BYTES:
        return (
            f"_That file is {size / 1e6:.1f} MB; this demo caps uploads at "
            f"{MAX_UPLOAD_BYTES / 1e6:.0f} MB. Run Airlock locally for full-size models._"
        )

    from airlock.rules import RuleEngine, load_rules
    from airlock.scanners.model import ModelScanner

    try:
        result = ModelScanner(RuleEngine(load_rules())).scan(str(path))
    except Exception as exc:
        return f"**Scan failed.**\n\n```\n{type(exc).__name__}: {exc}\n```"

    worst = max((f.severity for f in result.findings), default=None)
    headline = (
        f"**Highest severity:** {_SEV_BADGE.get(worst, '—')}" if worst else "**No findings.**"
    )

    return "\n".join(
        [
            f"## `{path.name}` — {size / 1024:.0f} KB",
            "",
            headline,
            "",
            _findings_table(result, "No findings on this artifact."),
            _explain(result),
            "",
            "---",
            "_Airlock inspected this file **statically** — it disassembles pickle opcodes and "
            "reads headers. It never unpickles, imports, or executes anything._",
        ]
    )
