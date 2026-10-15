"""DocRep (formerly RepoMedic) CLI entry point.

Interactive workbench for repository dependency resilience, AST discovery,
local model reasoning, sandbox verification, and proof-carrying capsule generation.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .analyzer import DependencyAnalyzer
from .capsule import CapsuleGenerator
from .gui import start_gui_server
from .hermes_adapter import HermesAdapter
from .impact import ImpactAnalyzer
from .models import FindingStatus
from .scanner import RepositoryScanner
from .verifier import SafeVerificationRunner

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console()


def resolve_and_validate_repo(repo_arg: Optional[str], repo_opt: Optional[str]) -> Path:
    """Validate repository path, returning resolved Path or exiting with meaningful code 2."""
    raw = repo_opt or repo_arg or "target_repo/linkwatch"
    path = Path(raw).resolve()

    if not path.exists():
        console.print(f"[bold red]Error (Path Validation):[/bold red] Path '{raw}' does not exist.", style="red")
        sys.exit(2)

    if not path.is_dir():
        console.print(f"[bold red]Error (Path Validation):[/bold red] Path '{raw}' is not a directory.", style="red")
        sys.exit(2)

    # Check for basic repository presence (at least one file or manifest)
    has_files = any(path.iterdir()) if path.exists() else False
    if not has_files:
        console.print(f"[bold red]Error (Path Validation):[/bold red] Directory '{raw}' is empty.", style="red")
        sys.exit(2)

    return path


@click.group()
@click.version_option(version="0.2.0", prog_name="docrep")
def cli():
    """DocRep: Evidence-backed repository maintenance workbench for dependency resilience."""
    pass


@cli.command()
def status():
    """Inspect environment dependencies, Hermes Agent, and local model runtimes."""
    adapter = HermesAdapter()
    res = adapter.get_runtime_status()
    warm = adapter.warmup_check()

    table = Table(title="DocRep / RepoMedic Environment & Agent Runtime Status")
    table.add_column("Component", style="cyan bold")
    table.add_column("Detected Value", style="white")
    table.add_column("State", style="bold")

    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    table.add_row("Python Interpreter", sys.executable, f"[green]{py_ver}[/green]")

    h_found = res["hermes_cli_found"]
    h_state = "[green]Installed[/green]" if h_found else "[yellow]Not Found (Using direct local model endpoint)[/yellow]"
    table.add_row("Hermes CLI", str(res["hermes_path"] or "None"), h_state)

    endpoint = res["local_endpoint"] or "http://127.0.0.1:11434"
    e_state = "[green]Online[/green]" if warm["status"] == "ok" else "[yellow]Offline / Checking[/yellow]"
    table.add_row("Local Model Endpoint", endpoint, e_state)

    m_name = str(res["model_name"])
    m_state = "[green]Ready[/green]" if warm["status"] == "ok" else "[red]Not Ready[/red]"
    table.add_row("Target Model", m_name, m_state)

    console.print(table)

    if warm["status"] != "ok":
        console.print(f"\n[yellow][!] Model Advisory:[/yellow] {warm.get('error', 'Model unreachable')}")
        console.print(f"[bold cyan]Action:[/bold cyan] Run `ollama pull {m_name}` and ensure `ollama serve` is active.\n")


@cli.command()
@click.argument("repo_path", required=False, default=None)
@click.option("--repo", "-r", "repo_option", default=None, help="Target repository directory path.")
def scan(repo_path: Optional[str] = None, repo_option: Optional[str] = None):
    """Scan repository manifests, declared dependencies, and AST source imports."""
    target = resolve_and_validate_repo(repo_path, repo_option)
    console.print(f"[bold cyan][1/1] Scanning manifests, AST imports, and source files in {target.name}...[/bold cyan]")

    scanner = RepositoryScanner(target)
    metadata, declarations, imports, _, _ = scanner.scan()

    console.print(
        Panel(
            f"[bold green]Repository:[/bold green] {metadata.repo_name} ({metadata.repo_path})\n"
            f"[bold]Git Commit:[/bold] {metadata.git_commit or 'Local'} | "
            f"[bold]Branch:[/bold] {metadata.git_branch or 'main'}\n"
            f"[bold]Python Detected:[/bold] {metadata.python_version_detected} | "
            f"[bold]Requires Python:[/bold] {metadata.python_requires_declared or 'Unspecified'}\n"
            f"[bold]Manifests:[/bold] {', '.join(metadata.manifests_found)}\n"
            f"[bold]Source Files:[/bold] {metadata.source_files_count} | "
            f"[bold]Test Files:[/bold] {metadata.test_files_count}",
            title="DocRep Repository Inventory",
        )
    )

    table = Table(title=f"Declared Dependencies ({len(declarations)})")
    table.add_column("Package", style="cyan bold")
    table.add_column("Specifier", style="magenta")
    table.add_column("Manifest", style="yellow")
    table.add_column("Line", justify="right")
    table.add_column("Type", justify="center")

    for d in declarations:
        table.add_row(
            d.name,
            d.specifier or "[dim]any[/dim]",
            d.manifest_path,
            str(d.line_number or "-"),
            "Dev" if d.is_dev else "Runtime",
        )
    console.print(table)


@cli.command()
@click.argument("repo_path", required=False, default=None)
@click.option("--repo", "-r", "repo_option", default=None, help="Target repository directory path.")
@click.option("--deep/--fast", default=False, help="Analyze all findings instead of top 5.")
@click.option("--no-ai", is_flag=True, default=False, help="Run scanner and deterministic rules only (skip AI analysis).")
def analyze(repo_path: Optional[str] = None, repo_option: Optional[str] = None, deep: bool = False, no_ai: bool = False):
    """Run deterministic resilience rules (Ghost Detector, Tripwires, Conflicts) and AI reasoning."""
    target = resolve_and_validate_repo(repo_path, repo_option)

    console.print(f"[bold cyan][1/2] Scanning AST & manifests in {target.name}...[/bold cyan]")
    scanner = RepositoryScanner(target)
    metadata, declarations, imports, _, _ = scanner.scan()

    console.print(f"[bold cyan][2/2] Evaluating deterministic resilience rules...[/bold cyan]")
    analyzer = DependencyAnalyzer(metadata, declarations, imports)
    findings = analyzer.analyze()

    if no_ai:
        console.print("[dim yellow][Notice: Running with --no-ai flag. AI recommendation layer disabled.][/dim yellow]")
    else:
        adapter = HermesAdapter()
        warm = adapter.warmup_check()
        if warm["status"] != "ok":
            console.print(f"[yellow]⚠️ Local Model Notice:[/yellow] {warm.get('error')}")
            console.print(f"[dim]Run `ollama pull {adapter.model_name}` to enable local open-weight model analysis.[/dim]")

    table = Table(title=f"Resilience Findings ({len(findings)})")
    table.add_column("ID", style="bold cyan")
    table.add_column("Category", style="yellow")
    table.add_column("Severity", style="bold")
    table.add_column("Status", style="magenta")
    table.add_column("Package", style="bold")
    table.add_column("Title")

    for f in findings:
        sev_color = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }.get(f.severity.value, "white")
        table.add_row(
            f.id,
            f.category,
            f"[{sev_color}]{f.severity.value.upper()}[/{sev_color}]",
            f.status.value,
            f.package_name or "-",
            f.title,
        )
    console.print(table)


@cli.command()
@click.argument("repo_path", required=False, default=None)
@click.option("--repo", "-r", "repo_option", default=None, help="Target repository directory path.")
def impact(repo_path: Optional[str] = None, repo_option: Optional[str] = None):
    """Calculate Change Blast-Radius and impacted test suites for dependencies."""
    target = resolve_and_validate_repo(repo_path, repo_option)
    scanner = RepositoryScanner(target)
    _, declarations, imports, _, _ = scanner.scan()
    analyzer = ImpactAnalyzer(declarations, imports)
    blast_radii = analyzer.calculate_blast_radius()

    table = Table(title="Dependency Change Blast-Radius Map")
    table.add_column("Package", style="bold cyan")
    table.add_column("Risk", style="bold")
    table.add_column("Importing Files (Direct)", style="white")
    table.add_column("Impacted Tests (Inferred)", style="yellow")

    for br in blast_radii:
        table.add_row(
            br.dependency_name,
            br.risk_level.value.upper(),
            ", ".join(br.importing_files) or "[dim]None (Ghost)[/dim]",
            ", ".join(br.affected_tests) or "[dim]None[/dim]",
        )
    console.print(table)


@cli.command()
@click.argument("repo_path", required=False, default=None)
@click.option("--repo", "-r", "repo_option", default=None, help="Target repository directory path.")
@click.option("--check", "-c", "check_name", default=None, help="Specific check to run (e.g. test_suite_run).")
def verify(repo_path: Optional[str] = None, repo_option: Optional[str] = None, check_name: Optional[str] = None):
    """Execute safe verification checks in an isolated sandbox."""
    target = resolve_and_validate_repo(repo_path, repo_option)
    verifier = SafeVerificationRunner(target)

    console.print(f"[bold cyan][1/1] Running sandbox verification checks on {target.name}...[/bold cyan]")
    if check_name:
        results = [verifier.execute_check(check_name)]
    else:
        results = verifier.run_all_checks()

    table = Table(title="Verification Check Execution Results")
    table.add_column("Check ID", style="bold cyan")
    table.add_column("Target", style="white")
    table.add_column("Status", style="bold")
    table.add_column("Exit Code", justify="center")
    table.add_column("Duration", justify="right")
    table.add_column("Sandbox", justify="center")

    has_failure = False
    for v in results:
        status_color = "green" if v.status == FindingStatus.VERIFIED else ("red" if v.status == FindingStatus.FAILED else "yellow")
        if v.status == FindingStatus.FAILED:
            has_failure = True
        table.add_row(
            v.id,
            v.target,
            f"[{status_color}]{v.status.value.upper()}[/{status_color}]",
            str(v.exit_code) if v.exit_code is not None else "BLOCKED",
            f"{v.duration_ms}ms",
            "YES" if v.sandbox_used else "NO",
        )
    console.print(table)

    if has_failure:
        sys.exit(1)


@cli.command()
@click.argument("repo_path", required=False, default=None)
@click.option("--repo", "-r", "repo_option", default=None, help="Target repository directory path.")
@click.option("--output-dir", "-o", default="reports", help="Directory to save exit capsule reports.")
@click.option("--deep/--fast", default=False, help="Run deep AI analysis on all findings.")
@click.option("--no-ai", is_flag=True, default=False, help="Skip AI recommendations layer.")
def capsule(
    repo_path: Optional[str] = None,
    repo_option: Optional[str] = None,
    output_dir: str = "reports",
    deep: bool = False,
    no_ai: bool = False,
):
    """Generate portable, proof-carrying Dependency Exit Capsule (JSON & Markdown)."""
    target = resolve_and_validate_repo(repo_path, repo_option)
    console.print(f"[bold blue]Running DocRep full resilience audit on {target.name}...[/bold blue]")

    scanner = RepositoryScanner(target)
    metadata, declarations, imports, m_hashes, s_hashes = scanner.scan()

    analyzer = DependencyAnalyzer(metadata, declarations, imports)
    findings = analyzer.analyze()

    impact_analyzer = ImpactAnalyzer(declarations, imports)
    blast_radii = impact_analyzer.calculate_blast_radius()

    adapter = HermesAdapter()
    model_info = {
        "model_name": adapter.model_name,
        "endpoint": adapter.endpoint,
        "mode": "no_ai" if no_ai else "local_ollama_hermes",
    }
    recommendations = [] if no_ai else adapter.generate_recommendations(findings)

    verifier = SafeVerificationRunner(target)
    verifications = verifier.run_all_checks()

    generator = CapsuleGenerator(
        metadata=metadata,
        declarations=declarations,
        imports=imports,
        findings=findings,
        recommendations=recommendations,
        verifications=verifications,
        blast_radii=blast_radii,
        manifest_hashes=m_hashes,
        source_hashes=s_hashes,
        model_info=model_info,
    )

    out_dir_path = Path(output_dir).resolve()
    json_path = generator.export_json(out_dir_path / "capsule.json")
    md_path = generator.export_markdown(out_dir_path / "capsule.md")
    html_path = generator.export_html(out_dir_path / "index.html")
    generator.export_html(out_dir_path / "capsule.html")

    console.print(f"[bold green][OK] Capsule generated successfully![/bold green]")
    console.print(f"  * Standalone HTML Report: [cyan]{html_path}[/cyan]")
    console.print(f"  * JSON Capsule:          [cyan]{json_path}[/cyan]")
    console.print(f"  * Markdown Capsule:      [cyan]{md_path}[/cyan]")


@cli.command()
@click.argument("repo_path", required=False, default=None)
@click.option("--repo", "-r", "repo_option", default=None, help="Target repository directory path.")
@click.option("--output-dir", "-o", default="reports", help="Directory to save exit capsule reports.")
@click.option("--deep/--fast", default=False, help="Run deep AI analysis on all findings instead of top 5.")
@click.option("--no-ai", is_flag=True, default=False, help="Run scanner and verifier only (no AI analysis).")
def run(
    repo_path: Optional[str] = None,
    repo_option: Optional[str] = None,
    output_dir: str = "reports",
    deep: bool = False,
    no_ai: bool = False,
):
    """Execute complete end-to-end resilience analysis and export Dependency Exit Capsule."""
    target = resolve_and_validate_repo(repo_path, repo_option)
    console.print(f"\n[bold green]=== DocRep End-to-End Resilience Pipeline ({target.name}) ===[/bold green]")

    # 1. Scan
    console.print("[bold cyan][1/5] Scanning repository manifests and AST source imports...[/bold cyan]")
    scanner = RepositoryScanner(target)
    metadata, declarations, imports, m_hashes, s_hashes = scanner.scan()
    console.print(f"      Discovered {len(declarations)} declarations across {len(metadata.manifests_found)} manifests.")

    # 2. Analyze
    console.print("[bold cyan][2/5] Evaluating deterministic resilience rules (ghosts, tripwires, conflicts)...[/bold cyan]")
    analyzer = DependencyAnalyzer(metadata, declarations, imports)
    findings = analyzer.analyze()
    console.print(f"      Identified {len(findings)} resilience findings.")

    # 3. Impact
    console.print("[bold cyan][3/5] Mapping dependency change blast-radius & affected tests...[/bold cyan]")
    impact_analyzer = ImpactAnalyzer(declarations, imports)
    blast_radii = impact_analyzer.calculate_blast_radius()

    # 4. AI Reasoning
    if no_ai:
        console.print("[bold cyan][4/5] Skipping AI reasoning (--no-ai mode requested)...[/bold cyan]")
        recommendations = []
        model_info = {"mode": "no_ai", "model_name": "None", "endpoint": "None"}
    else:
        console.print("[bold cyan][4/5] Running local AI model reasoning & challenge generation...[/bold cyan]")
        adapter = HermesAdapter()
        warm = adapter.warmup_check()
        if warm["status"] != "ok":
            console.print(f"      [yellow]Advisory: Local model offline/unready ({warm.get('error')})[/yellow]")
            console.print(f"      [dim]Using deterministic expert fallback recommendations without fabricating LLM output.[/dim]")
        recommendations = adapter.generate_recommendations(findings)
        model_info = {
            "model_name": adapter.model_name,
            "endpoint": adapter.endpoint,
            "mode": "local_ollama_hermes" if warm["status"] == "ok" else "deterministic_expert_fallback",
        }
        console.print(f"      Generated {len(recommendations)} evidence-backed recommendations.")

    # 5. Verify
    console.print("[bold cyan][5/5] Executing isolated sandbox verification checks...[/bold cyan]")
    verifier = SafeVerificationRunner(target)
    verifications = verifier.run_all_checks()
    passed_checks = sum(1 for v in verifications if v.status == FindingStatus.VERIFIED)
    console.print(f"      Executed {len(verifications)} checks ({passed_checks} passed, {len(verifications) - passed_checks} failed/blocked).")

    # Generate Capsule
    generator = CapsuleGenerator(
        metadata=metadata,
        declarations=declarations,
        imports=imports,
        findings=findings,
        recommendations=recommendations,
        verifications=verifications,
        blast_radii=blast_radii,
        manifest_hashes=m_hashes,
        source_hashes=s_hashes,
        model_info=model_info,
    )

    out_dir_path = Path(output_dir).resolve()
    json_path = generator.export_json(out_dir_path / "capsule.json")
    md_path = generator.export_markdown(out_dir_path / "capsule.md")
    html_path = generator.export_html(out_dir_path / "index.html")
    generator.export_html(out_dir_path / "capsule.html")

    console.print(f"\n[bold green][OK] Full Pipeline Complete![/bold green]")
    console.print(f"  * Standalone HTML Report: [cyan]{html_path}[/cyan]")
    console.print(f"  * JSON Capsule:          [cyan]{json_path}[/cyan]")
    console.print(f"  * Markdown Capsule:      [cyan]{md_path}[/cyan]\n")


@cli.command()
@click.argument("repo_path", required=False, default=None)
@click.option("--repo", "-r", "repo_option", default=None, help="Target repository directory path.")
@click.option("--port", "-p", default=0, type=int, help="Port to listen on (default 0 picks a free port).")
@click.option("--no-browser", is_flag=True, default=False, help="Do not open browser automatically.")
def gui(repo_path: Optional[str] = None, repo_option: Optional[str] = None, port: int = 0, no_browser: bool = False):
    """Launch lightweight, offline web GUI workbench (bound to 127.0.0.1)."""
    target = resolve_and_validate_repo(repo_path, repo_option)
    start_gui_server(str(target), port=port, no_browser=no_browser)


if __name__ == "__main__":
    cli()
