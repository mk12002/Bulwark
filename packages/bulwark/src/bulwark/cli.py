"""Bulwark meta-CLI — one front door over the three tools.

    bulwark airlock  ...    # scan the parts (models / MCP / tool-specs)
    bulwark warden   ...    # scan the assembly (agent least-privilege)
    bulwark manifest ...    # inventory the whole system (AI-BOM + governance)

    bulwark scan <project>  # the whole suite in one shot: inventory + Airlock/Warden
                            #   risk folded in + NIST AI RMF / EU AI Act governance
    bulwark version

Each subcommand is the tool's own Typer app, so every flag works identically to the
standalone CLIs. ``bulwark scan`` is sugar for ``manifest scan --scan-risk --govern``.
"""

from __future__ import annotations

import sys

import typer
from bulwark_core.logging import configure as configure_logging
from bulwark_core.report.console import err_console

from bulwark import __version__

app = typer.Typer(
    name="bulwark",
    help="The security stack for agentic AI: Airlock scans the parts, Warden the assembly, "
    "Manifest inventories it all.",
    no_args_is_help=True,
    add_completion=False,
)

# Mount each tool's app verbatim — flags, help, and behavior are unchanged.
from airlock.cli import app as airlock_app  # noqa: E402
from manifest.cli import app as manifest_app  # noqa: E402
from warden.cli import app as warden_app  # noqa: E402

app.add_typer(airlock_app, name="airlock", help="Scan the parts: models, MCP servers, tool-specs.")
app.add_typer(warden_app, name="warden", help="Scan the assembly: agent least-privilege.")
app.add_typer(manifest_app, name="manifest", help="Inventory the system: AI-BOM + governance.")

_err = err_console()

@app.callback()
def _root(
    verbose: int = typer.Option(
        0,
        "--verbose",
        "-v",
        count=True,
        help="Diagnostics to stderr: -v for progress, -vv for detail. Never touches stdout.",
    ),
) -> None:
    """Configure logging before any subcommand runs."""
    configure_logging(verbose)



@app.command("scan")
def scan(
    project: str = typer.Argument(..., help="Path to an AI project/repo to inventory + assess."),
    fmt: str = typer.Option(
        "terminal", "--format", "-f", help="terminal|cyclonedx|spdx|json|html|sarif|md"
    ),
    fail_on: str = typer.Option("high", "--fail-on", help="Exit non-zero at/above this severity."),
    offline: bool = typer.Option(False, "--offline", help="Skip network (OSV) lookups."),
    ai: bool = typer.Option(False, "--ai", help="Enable optional AI enrichment (off by default)."),
) -> None:
    """Run the whole suite: inventory the project, fold in Airlock + Warden risk, and govern it."""
    from bulwark_core.report import render_report
    from bulwark_core.severity import parse_severity
    from manifest.bom.model import AIBOM
    from manifest.cli import _load_engine
    from manifest.scanner import ManifestScanner

    scanner = ManifestScanner(_load_engine(), offline=offline, scan_risk=True, govern=True)
    result = scanner.scan(project)

    if ai:
        from bulwark_core.ai.enrich import run_enrichment
        from manifest.config import load_settings

        outcome = run_enrichment(result, load_settings().ai, ai_flag=True)
        for note in outcome.notes:
            _err.print(f"[dim]ai: {note}[/dim]")
        result = outcome.result

    if fmt == "md":
        from manifest.govern import render_governance_md

        bom = AIBOM.model_validate(result.meta["aibom"])
        typer.echo(render_governance_md(result.findings, bom))
    elif fmt in {"cyclonedx", "spdx"}:
        from manifest.cli import _emit

        _emit(result, fmt)
    else:
        try:
            output = render_report(result, fmt)
        except ValueError as exc:
            _err.print(f"[bold red]{exc}[/bold red]")
            raise typer.Exit(code=2) from exc
        if output:
            typer.echo(output)

    try:
        threshold = parse_severity(fail_on)
    except ValueError as exc:
        _err.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=2) from exc
    raise typer.Exit(code=result.exit_code(threshold))


@app.command("version")
def version() -> None:
    """Print versions of Bulwark and each tool."""
    import airlock
    import manifest
    import warden

    typer.echo(
        f"bulwark {__version__} "
        f"(airlock {airlock.__version__}, warden {warden.__version__}, "
        f"manifest {manifest.__version__})"
    )


def main() -> None:
    app()


if __name__ == "__main__":
    sys.exit(app())  # pragma: no cover
