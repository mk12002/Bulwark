"""Airlock CLI — ``airlock scan model|mcp``, ``airlock rules``, ``airlock version``."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Optional

import typer
from bulwark_core.findings import ScanResult
from bulwark_core.severity import parse_severity
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from airlock import __version__
from airlock.rules import RuleEngine, RuleLoadError, load_rules

app = typer.Typer(
    name="airlock",
    help="Static security scanner for the AI agent supply chain.",
    no_args_is_help=True,
    add_completion=False,
)
scan_app = typer.Typer(help="Scan a model artifact or an MCP server.", no_args_is_help=True)
rules_app = typer.Typer(help="Inspect and validate rule packs.", no_args_is_help=True)
app.add_typer(scan_app, name="scan")
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


def _finish(result: ScanResult, fail_on: str) -> None:
    try:
        threshold = parse_severity(fail_on)
    except ValueError as exc:
        _err.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=2) from exc
    raise typer.Exit(code=result.exit_code(threshold))


def _enrich(
    result: ScanResult,
    *,
    ai_flag: bool,
    semantic_targets: list[dict[str, str]] | None = None,
    model_card: str | None = None,
) -> ScanResult:
    """Apply optional AI enrichment when requested; degrade gracefully otherwise."""
    if not ai_flag:
        return result
    from bulwark_core.ai.enrich import run_enrichment

    from airlock.config import load_settings

    settings = load_settings()
    outcome = run_enrichment(
        result,
        settings.ai,
        ai_flag=True,
        semantic_targets=semantic_targets,
        model_card=model_card,
    )
    for note in outcome.notes:
        _err.print(f"[dim]ai: {note}[/dim]")
    return outcome.result


def _read_model_card(target: str) -> str | None:
    """Read a local model card (README/model_card) to feed the AI trust read."""
    base = Path(target)
    if not base.is_dir():
        return None
    for name in ("README.md", "model_card.md", "MODEL_CARD.md", "modelcard.md"):
        card = base / name
        if card.is_file():
            try:
                return card.read_text(encoding="utf-8", errors="replace")
            except OSError:
                return None
    return None


def _postprocess(result: ScanResult, baseline: Path | None) -> ScanResult:
    """Apply configured waivers, then an optional baseline diff."""
    from bulwark_core.postprocess import apply_baseline, apply_waivers

    from airlock.config import load_settings

    settings = load_settings()
    result = apply_waivers(result, settings.suppress_rules, settings.suppress_paths)
    if baseline is not None:
        if not baseline.exists():
            _err.print(f"[bold red]baseline file not found: {baseline}[/bold red]")
            raise typer.Exit(code=2)
        result = apply_baseline(result, baseline)
    if result.suppressed:
        _err.print(f"[dim]{result.suppressed} finding(s) suppressed (waivers/baseline).[/dim]")
    return result


def _mcp_semantic_targets(scanner: object) -> list[dict[str, str]] | None:
    """Build AI semantic targets (raw tool descriptions) from an MCP scan."""
    import json as _json

    inventory = getattr(scanner, "last_inventory", None)
    if inventory is None:
        return None
    return [
        {
            "name": tool.name,
            "description": tool.description,
            "schema": _json.dumps(tool.input_schema)[:500],
        }
        for tool in inventory.tools
    ]


@scan_app.command("model")
def scan_model(
    target: str = typer.Argument(..., help="Local path or 'hf:org/name'."),
    fmt: str = typer.Option("terminal", "--format", "-f", help="terminal|json|html|sarif"),
    fail_on: str = typer.Option("high", "--fail-on", help="Exit non-zero at/above this severity."),
    ai: bool = typer.Option(False, "--ai", help="Enable optional AI enrichment (off by default)."),
    baseline: Optional[Path] = typer.Option(  # noqa: UP045
        None, "--baseline", help="Report only findings absent from this prior JSON result."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Compact one-line-per-finding output."),
) -> None:
    """Scan an ML model artifact for supply-chain risks (M1–M7)."""
    from airlock.scanners.model import ModelScanner

    engine = _load_engine()
    scanner = ModelScanner(engine)
    result = scanner.scan(target)
    result = _enrich(result, ai_flag=ai, model_card=_read_model_card(target))
    result = _postprocess(result, baseline)
    _emit(result, fmt, quiet=quiet)
    _finish(result, fail_on)


@scan_app.command("mcp")
def scan_mcp(
    target: str = typer.Argument(..., help="Server command (stdio) or URL (sse/http)."),
    fmt: str = typer.Option("terminal", "--format", "-f", help="terminal|json|html|sarif"),
    fail_on: str = typer.Option("high", "--fail-on", help="Exit non-zero at/above this severity."),
    ai: bool = typer.Option(False, "--ai", help="Enable optional AI enrichment (off by default)."),
    baseline: Optional[Path] = typer.Option(  # noqa: UP045
        None, "--baseline", help="Report only findings absent from this prior JSON result."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Compact one-line-per-finding output."),
) -> None:
    """Scan an MCP server for tool-poisoning and permission risks (P1–P9)."""
    from airlock.scanners.mcp import MCPScanner

    engine = _load_engine()
    scanner = MCPScanner(engine)
    result = scanner.scan(target)
    result = _enrich(result, ai_flag=ai, semantic_targets=_mcp_semantic_targets(scanner))
    result = _postprocess(result, baseline)
    _emit(result, fmt, quiet=quiet)
    _finish(result, fail_on)


@scan_app.command("toolspec")
def scan_toolspec(
    target: Path = typer.Argument(..., help="Path to a tool-definition file (JSON/YAML)."),
    fmt: str = typer.Option("terminal", "--format", "-f", help="terminal|json|html|sarif"),
    fail_on: str = typer.Option("high", "--fail-on", help="Exit non-zero at/above this severity."),
    ai: bool = typer.Option(False, "--ai", help="Enable optional AI enrichment (off by default)."),
    baseline: Optional[Path] = typer.Option(  # noqa: UP045
        None, "--baseline", help="Report only findings absent from this prior JSON result."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Compact one-line-per-finding output."),
) -> None:
    """Scan an OpenAI/Anthropic/LangChain tool-definition file (P1–P9)."""
    from airlock.scanners.mcp import MCPScanner
    from airlock.scanners.toolspec import ToolSpecError, load_toolspec

    try:
        inventory = load_toolspec(target)
    except ToolSpecError as exc:
        _err.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=2) from exc

    engine = _load_engine()
    scanner = MCPScanner(engine, connector=lambda _t: inventory)
    result = scanner.scan(str(target))
    semantic = _mcp_semantic_targets(scanner)
    result = _enrich(result, ai_flag=ai, semantic_targets=semantic)
    result = _postprocess(result, baseline)
    _emit(result, fmt, quiet=quiet)
    _finish(result, fail_on)


@rules_app.command("list")
def rules_list() -> None:
    """List loaded rule packs and their rules."""
    engine = _load_engine()
    console = Console()
    table = Table(title="Airlock rule packs", show_lines=False)
    table.add_column("Rule id", no_wrap=True)
    table.add_column("Target", no_wrap=True)
    table.add_column("Cat", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Title")
    for lr in engine.rules:
        table.add_row(
            lr.rule.id,
            lr.target,
            lr.rule.category,
            lr.rule.severity.value,
            lr.rule.title,
        )
    console.print(table)
    console.print(f"[dim]{len(engine.rules)} rule(s) loaded.[/dim]")


@rules_app.command("lint")
def rules_lint(
    rules_dir: Optional[Path] = typer.Option(  # noqa: UP045
        None, "--dir", help="Rule directory to validate (defaults to packaged rules)."
    ),
) -> None:
    """Validate every rule pack; exit non-zero on the first error."""
    console = Console()
    try:
        rules = load_rules(rules_dir)
    except RuleLoadError as exc:
        _err.print(f"[bold red]Invalid rule pack:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc
    console.print(f"[green]OK[/green] — {len(rules)} rule(s) validated.")


@rules_app.command("show")
def rules_show(rule_id: str = typer.Argument(..., help="The rule id to display.")) -> None:
    """Show the full definition of one rule."""
    engine = _load_engine()
    console = Console()
    match = next((lr for lr in engine.rules if lr.rule.id == rule_id), None)
    if match is None:
        _err.print(f"[bold red]No rule with id {rule_id!r}.[/bold red]")
        raise typer.Exit(code=1)
    r = match.rule
    matcher = (
        f"pattern={r.match.pattern!r}" if r.match.pattern else f"predicate={r.match.predicate}"
    )
    body = (
        f"[bold]{r.id}[/bold]  ([{r.severity.value}] {r.category}, {r.confidence} confidence)\n"
        f"{r.title}\n\n"
        f"[dim]target:[/dim] {match.target}\n"
        f"[dim]signal:[/dim] {r.match.signal}  [dim]match:[/dim] {matcher}\n"
        f"[dim]rationale:[/dim] {r.rationale}\n"
        f"[dim]remediation:[/dim] {r.remediation}\n"
        f"[dim]references:[/dim] {', '.join(r.references) or '-'}\n"
        f"[dim]source:[/dim] {match.source}"
    )
    console.print(Panel(body, border_style="cyan"))


@rules_app.command("stats")
def rules_stats() -> None:
    """Summarize loaded rules by target, category, and severity."""
    from collections import Counter

    engine = _load_engine()
    console = Console()
    by_target: Counter[str] = Counter(lr.target for lr in engine.rules)
    by_sev: Counter[str] = Counter(lr.rule.severity.value for lr in engine.rules)
    by_cat: Counter[str] = Counter(lr.rule.category for lr in engine.rules)
    console.print(f"[bold]{len(engine.rules)} rules[/bold] loaded")
    console.print("  by target:   " + ", ".join(f"{k}={v}" for k, v in sorted(by_target.items())))
    console.print("  by severity: " + ", ".join(f"{k}={v}" for k, v in sorted(by_sev.items())))
    console.print("  by category: " + ", ".join(f"{k}={v}" for k, v in sorted(by_cat.items())))


@rules_app.command("update")
def rules_update(
    source: str = typer.Option(..., "--from", help="Directory, .zip path, or https URL of packs."),
) -> None:
    """Install validated community rule packs into the user rules directory."""
    from bulwark_core.rule_feed import update_rules

    from airlock.rules import user_rules_dir

    console = Console()
    known = {lr.rule.id for lr in _load_engine().rules}
    try:
        result = update_rules(source, dest=user_rules_dir(), known_ids=known)
    except RuleLoadError as exc:
        _err.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=1) from exc
    for name in result.installed:
        console.print(f"[green]installed[/green] {name}")
    for skip in result.skipped:
        console.print(f"[yellow]skipped[/yellow] {skip}")
    console.print(f"[dim]{len(result.installed)} pack(s) installed to {result.dest}[/dim]")


def _study_scanner(engine: RuleEngine) -> Callable[[str, str], ScanResult]:
    from airlock.scanners.mcp import MCPScanner
    from airlock.scanners.model import ModelScanner
    from airlock.scanners.toolspec import load_toolspec

    def scan(kind: str, target: str) -> ScanResult:
        if kind == "model":
            return ModelScanner(engine).scan(target)
        if kind == "mcp":
            return MCPScanner(engine).scan(target)
        if kind == "toolspec":
            inv = load_toolspec(Path(target))
            return MCPScanner(engine, connector=lambda _t: inv).scan(target)
        raise ValueError(f"unknown corpus kind {kind!r} (expected model|mcp|toolspec)")

    return scan


@app.command("study")
def study(
    corpus: Path = typer.Argument(..., help="Corpus file: one 'kind target' per line."),
    fmt: str = typer.Option("markdown", "--format", "-f", help="markdown|json"),
    out: Optional[Path] = typer.Option(None, "--out", help="Write the report here."),  # noqa: UP045
) -> None:
    """Scan a corpus of targets and produce aggregate, reproducible statistics."""
    from bulwark_core.study import CorpusItem, render_markdown, run_study

    if not corpus.exists():
        _err.print(f"[bold red]corpus file not found: {corpus}[/bold red]")
        raise typer.Exit(code=2)

    items: list[CorpusItem] = []
    for line in corpus.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        kind, _, target = line.partition(" ")
        if target.strip():
            items.append(CorpusItem(kind=kind.strip(), target=target.strip()))

    engine = _load_engine()
    report = run_study(items, _study_scanner(engine), rule_count=len(engine.rules))

    if fmt == "json":
        import dataclasses

        text = json.dumps(dataclasses.asdict(report), indent=2, ensure_ascii=True)
    else:
        text = render_markdown(report)

    if out is not None:
        out.write_text(text, encoding="utf-8")
        _err.print(f"[green]wrote study report to {out}[/green]")
    else:
        typer.echo(text)


@app.command("version")
def version() -> None:
    """Print the Airlock version and environment."""
    import platform

    try:
        n = len(load_rules())
    except RuleLoadError:
        n = 0
    typer.echo(f"airlock {__version__} (python {platform.python_version()}, {n} rules loaded)")


def main() -> None:
    """Entry point for ``python -m airlock`` and direct invocation."""
    app()


if __name__ == "__main__":
    sys.exit(app())  # pragma: no cover
