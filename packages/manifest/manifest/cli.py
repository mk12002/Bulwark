"""Manifest CLI — ``manifest scan|components``, ``manifest rules``, ``manifest version``."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from bulwark_core.findings import ScanResult
from bulwark_core.severity import parse_severity
from rich.console import Console
from rich.table import Table

from manifest import __version__
from manifest.rules import RuleEngine, RuleLoadError, load_rules

app = typer.Typer(
    name="manifest",
    help="AI-BOM generator for AI systems — inventory + governance (Bulwark suite).",
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


def _emit(result: ScanResult, fmt: str) -> None:
    fmt = fmt.lower()
    if fmt == "cyclonedx":
        typer.echo(json.dumps(result.meta.get("cyclonedx", {}), indent=2, ensure_ascii=True))
        return
    if fmt == "spdx":
        from manifest.bom.model import AIBOM
        from manifest.bom.spdx import render_spdx

        typer.echo(render_spdx(AIBOM.model_validate(result.meta["aibom"])))
        return
    if fmt == "vex":
        from manifest.bom.vex import render_vex

        typer.echo(render_vex(result))
        return
    if fmt in ("md", "markdown"):
        from manifest.bom.model import AIBOM
        from manifest.govern import render_governance_md

        bom = AIBOM.model_validate(result.meta["aibom"])
        typer.echo(render_governance_md(result.findings, bom))
        return
    from bulwark_core.report import render_report

    try:
        output = render_report(result, fmt)
    except ValueError as exc:
        _err.print(f"[bold red]{exc}[/bold red] (try cyclonedx|json|html|sarif|md|terminal)")
        raise typer.Exit(code=2) from exc
    if output:
        typer.echo(output)


def _finish(result: ScanResult, fail_on: str) -> None:
    try:
        threshold = parse_severity(fail_on)
    except ValueError as exc:
        _err.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=2) from exc
    raise typer.Exit(code=result.exit_code(threshold))


@app.command("scan")
def scan(
    project: Path = typer.Argument(..., help="Path to an AI project directory."),
    fmt: str = typer.Option(
        "terminal", "--format", "-f", help="terminal|cyclonedx|spdx|vex|json|html|sarif|md"
    ),
    fail_on: str = typer.Option("high", "--fail-on", help="Exit non-zero at/above this severity."),
    scan_risk: bool = typer.Option(
        False, "--scan-risk", help="Run Airlock/Warden on discovered parts."
    ),
    govern: bool = typer.Option(False, "--govern", help="Add NIST AI RMF mapping + risk register."),
    offline: bool = typer.Option(
        True, "--offline/--online", help="Use the OSV API for vulns when --online."
    ),
    ai: bool = typer.Option(False, "--ai", help="Enable optional AI enrichment (off by default)."),
) -> None:
    """Inventory an AI project into an AI-BOM with provenance, licenses, and risk."""
    from manifest.scanner import ManifestScanner

    scanner = ManifestScanner(_load_engine(), offline=offline, scan_risk=scan_risk, govern=govern)
    result = scanner.scan(str(project))
    result = _enrich(result, ai)
    _emit(result, fmt)
    _finish(result, fail_on)


def _enrich(result: ScanResult, ai_flag: bool) -> ScanResult:
    if not ai_flag:
        return result
    from bulwark_core.ai.enrich import run_enrichment

    from manifest.config import load_settings

    outcome = run_enrichment(result, load_settings().ai, ai_flag=True)
    for note in outcome.notes:
        _err.print(f"[dim]ai: {note}[/dim]")
    return outcome.result


@app.command("components")
def components(
    project: Path = typer.Argument(..., help="Path to an AI project directory."),
) -> None:
    """List the discovered components (debug discoverers)."""
    from manifest.discover import DiscoveryContext, discover_project
    from manifest.resolve import licenses

    ctx = DiscoveryContext.build(project)
    bom = discover_project(project)
    licenses.resolve(bom, ctx)
    console = Console()
    table = Table(title=f"Components — {bom.project}")
    table.add_column("Type", no_wrap=True)
    table.add_column("Name")
    table.add_column("Version", no_wrap=True)
    table.add_column("License", no_wrap=True)
    table.add_column("Pinned", no_wrap=True)
    for c in bom.components:
        table.add_row(
            c.type.value,
            c.name,
            c.provenance.version or "-",
            c.license.id or c.license.risk,
            "yes" if c.provenance.pinned else "no",
        )
    console.print(table)
    console.print(f"[dim]{len(bom.components)} component(s): {bom.type_counts()}[/dim]")


@app.command("diff")
def diff(
    old: Path = typer.Argument(..., help="Earlier AI project directory (the baseline)."),
    new: Path = typer.Argument(..., help="Current AI project directory."),
) -> None:
    """Show AI-BOM drift (added/removed/changed components) between two project versions."""
    from manifest.bom.diff import diff_boms
    from manifest.bom.model import AIBOM
    from manifest.discover import DiscoveryContext, discover_project
    from manifest.resolve import licenses

    def _bom(path: Path) -> AIBOM:
        bom = discover_project(path)
        licenses.resolve(bom, DiscoveryContext.build(path))
        return bom

    result = diff_boms(_bom(old), _bom(new))
    Console().print(result.render())
    raise typer.Exit(code=1 if result.has_changes else 0)


@rules_app.command("list")
def rules_list() -> None:
    engine = _load_engine()
    console = Console()
    table = Table(title="Manifest rule packs")
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
    console = Console()
    try:
        rules = load_rules()
    except RuleLoadError as exc:
        _err.print(f"[bold red]Invalid rule pack:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc
    console.print(f"[green]OK[/green] — {len(rules)} rule(s) validated.")


@app.command("version")
def version() -> None:
    import platform

    try:
        n = len(load_rules())
    except RuleLoadError:
        n = 0
    typer.echo(f"manifest {__version__} (python {platform.python_version()}, {n} rules loaded)")


def main() -> None:
    app()


if __name__ == "__main__":
    sys.exit(app())  # pragma: no cover
