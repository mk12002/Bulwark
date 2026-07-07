"""Terminal renderer using ``rich``: severity-colored, grouped by category."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from airlock.core.findings import Finding, ScanResult
from airlock.core.severity import Severity

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.INFO: "dim",
    Severity.LOW: "cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "orange3",
    Severity.CRITICAL: "bold red",
}


def _severity_text(sev: Severity) -> Text:
    return Text(sev.value.upper(), style=_SEVERITY_STYLE[sev])


def render_terminal(
    result: ScanResult, console: Console | None = None, *, quiet: bool = False
) -> None:
    """Print a scan result as a rich report. Prints nothing but the report.

    In ``quiet`` mode, print only a compact one-line-per-finding list with the
    worst-severity summary — no panels or tables.
    """
    con = console or Console()

    if quiet:
        if not result.findings:
            con.print("[green]clean[/green] — no findings.")
            return
        for f in result.sorted_findings():
            con.print(
                Text.assemble(
                    _severity_text(f.severity),
                    (f"  {f.category}  ", "dim"),
                    (f.id, "bold"),
                    (f"  {f.location.path or '-'}", "dim"),
                )
            )
        con.print(f"[dim]{_summary_line(result.stats)}[/dim]")
        return

    worst = result.worst()
    counts = result.stats
    header_style = _SEVERITY_STYLE[worst] if result.findings else "green"
    summary = _summary_line(counts)
    con.print(
        Panel(
            Text.assemble(
                (f"{result.target_type.upper()} scan  ", "bold"),
                (result.target, "bold white"),
                ("\nworst severity: ", "dim"),
                _severity_text(worst),
                (f"    findings: {len(result.findings)}", "dim"),
                ("\n", ""),
                (summary, ""),
            ),
            title="Airlock",
            border_style=header_style,
        )
    )

    if not result.findings:
        con.print("[green]No findings. Target scanned clean.[/green]")
        return

    table = Table(show_lines=True, expand=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Cat", no_wrap=True)
    table.add_column("Finding")
    table.add_column("Location")
    table.add_column("Evidence", overflow="fold")

    for f in result.sorted_findings():
        table.add_row(
            _severity_text(f.severity),
            f.category,
            _finding_cell(f),
            _location_cell(f),
            Text(f.evidence, style="dim"),
        )
    con.print(table)

    _print_remediations(con, result.sorted_findings())
    _print_ai(con, result)


def _summary_line(counts: dict[str, int]) -> str:
    parts = []
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        n = counts.get(sev.value, 0)
        if n:
            parts.append(f"{n} {sev.value}")
    return "  ".join(parts) if parts else "clean"


def _finding_cell(f: Finding) -> Text:
    ai_tag = ("  [AI]", "magenta") if f.source == "ai" else ("", "")
    cell = Text.assemble(
        (f.title, "bold"),
        ai_tag,
        (f"\n({f.confidence} confidence)", "dim"),
    )
    if f.ai_assessment:
        cell.append(Text(f"\nAI: {f.ai_assessment}", style="magenta"))
    return cell


def _location_cell(f: Finding) -> Text:
    loc = f.location
    lines = []
    if loc.path:
        lines.append(loc.path)
    if loc.detail:
        lines.append(loc.detail)
    return Text("\n".join(lines) if lines else "-", style="dim")


def _print_remediations(console: Console, findings: list[Finding]) -> None:
    seen: set[str] = set()
    lines: list[Text] = []
    for f in findings:
        if f.remediation in seen:
            continue
        seen.add(f.remediation)
        lines.append(Text.assemble((f"[{f.category}] ", "bold"), (f.remediation, "")))
    if lines:
        body = Text("\n").join(lines)
        console.print(Panel(body, title="Remediation", border_style="dim"))


def _print_ai(console: Console, result: ScanResult) -> None:
    if not result.ai_summary:
        return
    console.print(
        Panel(
            Text(result.ai_summary, style="magenta"),
            title="AI summary (advisory — deterministic findings above are authoritative)",
            border_style="magenta",
        )
    )
