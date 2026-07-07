"""Warden CLI — ``warden audit|import``, ``warden rules``, ``warden version``."""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from bulwark_core.findings import ScanResult
from bulwark_core.severity import parse_severity
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from warden import __version__
from warden.rules import RuleEngine, RuleLoadError, load_rules

app = typer.Typer(
    name="warden",
    help="Least-privilege auditor for AI agents (part of the Bulwark suite).",
    no_args_is_help=True,
    add_completion=False,
)
rules_app = typer.Typer(help="Inspect and validate rule packs.", no_args_is_help=True)
app.add_typer(rules_app, name="rules")

_err = Console(stderr=True)


def _load_engine() -> RuleEngine:
    try:
        return RuleEngine(load_rules())
    except RuleLoadError as exc:
        _err.print(f"[bold red]Rule load error:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc


def _emit(result: ScanResult, fmt: str, *, quiet: bool = False) -> None:
    from bulwark_core.report import render_report

    try:
        output = render_report(result, fmt, quiet=quiet)
    except ValueError as exc:
        _err.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=2) from exc
    if output:
        typer.echo(output)


def _enrich(result: ScanResult, ai_flag: bool) -> ScanResult:
    if not ai_flag:
        return result
    from bulwark_core.ai.enrich import run_enrichment

    from warden.config import load_settings

    outcome = run_enrichment(result, load_settings().ai, ai_flag=True)
    for note in outcome.notes:
        _err.print(f"[dim]ai: {note}[/dim]")
    return outcome.result


@app.command("audit")
def audit(
    target: Path = typer.Argument(
        ..., help="Agent config: manifest YAML/JSON or MCP client config."
    ),
    fmt: str = typer.Option("terminal", "--format", "-f", help="terminal|json|html|sarif"),
    fail_on: str = typer.Option("high", "--fail-on", help="Exit non-zero at/above this severity."),
    recommend_flag: bool = typer.Option(
        False, "--recommend", help="Print a least-privilege spec + diff."
    ),
    scan_parts: bool = typer.Option(
        False, "--scan-parts", help="(Phase 3) scan wired MCP parts with Airlock."
    ),
    ai: bool = typer.Option(False, "--ai", help="Enable optional AI enrichment (off by default)."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Compact one-line-per-finding output."),
) -> None:
    """Audit an assembled agent for excessive agency (A1–A10)."""
    from warden.scanner import WardenScanner

    scanner = WardenScanner(_load_engine())
    result = scanner.scan(str(target))
    result = _enrich(result, ai)

    if scan_parts:
        _err.print(
            "[dim]--scan-parts is a Phase 3 feature; skipping the Airlock bridge for now.[/dim]"
        )

    _emit(result, fmt, quiet=quiet)

    if recommend_flag:
        _print_recommendation(result)

    _finish(result, fail_on)


def _print_recommendation(result: ScanResult) -> None:
    from warden.recommend import recommend
    from warden.spec.model import AgentSpec

    spec_data = result.meta.get("agent_spec")
    if not spec_data:
        return
    spec = AgentSpec.model_validate(spec_data)
    rec = recommend(spec)
    Console().print(
        Panel(rec.diff_text(), title="Least-privilege recommendation", border_style="cyan")
    )


def _finish(result: ScanResult, fail_on: str) -> None:
    try:
        threshold = parse_severity(fail_on)
    except ValueError as exc:
        _err.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=2) from exc
    raise typer.Exit(code=result.exit_code(threshold))


@app.command("import")
def import_cmd(
    target: Path = typer.Argument(..., help="Agent config to normalize and print."),
) -> None:
    """Show the normalized AgentSpec for a config (debug importers)."""
    from warden.importers import ImportError_, import_agent

    try:
        spec, importer = import_agent(target)
    except ImportError_ as exc:
        _err.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=2) from exc
    console = Console()
    console.print(f"[dim]importer:[/dim] {importer}")
    console.print(spec.summary())
    console.print_json(spec.model_dump_json())


@rules_app.command("list")
def rules_list() -> None:
    """List loaded rule packs."""
    engine = _load_engine()
    console = Console()
    table = Table(title="Warden rule packs")
    table.add_column("Rule id", no_wrap=True)
    table.add_column("Cat", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Title")
    for lr in engine.rules:
        table.add_row(lr.rule.id, lr.rule.category, lr.rule.severity.value, lr.rule.title)
    console.print(table)
    console.print(f"[dim]{len(engine.rules)} rule(s) loaded.[/dim]")


@rules_app.command("lint")
def rules_lint() -> None:
    """Validate every rule pack; exit non-zero on the first error."""
    console = Console()
    try:
        rules = load_rules()
    except RuleLoadError as exc:
        _err.print(f"[bold red]Invalid rule pack:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc
    console.print(f"[green]OK[/green] — {len(rules)} rule(s) validated.")


@app.command("version")
def version() -> None:
    """Print the Warden version."""
    import platform

    try:
        n = len(load_rules())
    except RuleLoadError:
        n = 0
    typer.echo(f"warden {__version__} (python {platform.python_version()}, {n} rules loaded)")


def main() -> None:
    app()


if __name__ == "__main__":
    sys.exit(app())  # pragma: no cover
