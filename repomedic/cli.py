"""RepoMedic CLI entry point: interactive workbench for repository dependency resilience."""

import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .analyzer import DependencyAnalyzer
from .capsule import CapsuleGenerator
from .hermes_adapter import HermesAdapter
from .impact import ImpactAnalyzer
from .models import FindingStatus
from .scanner import RepositoryScanner
from .verifier import SafeVerificationRunner

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="repomedic")
def cli():
    """RepoMedic: AI-assisted repository maintenance workbench for dependency resilience."""
    pass


@cli.command()
def status():
    """Inspect environment dependencies, Hermes Agent, and local model runtimes."""
    adapter = HermesAdapter()
    res = adapter.get_runtime_status()

    table = Table(title="RepoMedic Environment & Agent Runtime Status")
    table.add_column("Component", style="cyan bold")
    table.add_column("Detected Value", style="white")
    table.add_column("State", style="bold")

    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    table.add_row("Python Interpreter", sys.executable, f"[green]{py_ver}[/green]")

    h_found = res["hermes_cli_found"]
    h_state = "[green]Installed[/green]" if h_found else "[yellow]Not Found (Using fallback)[/yellow]"
    table.add_row("Hermes CLI", str(res["hermes_path"] or "None"), h_state)

    endpoint = res["local_endpoint"] or "None (Set REPOMEDIC_LOCAL_MODEL_URL)"
    e_state = "[green]Configured[/green]" if res["local_endpoint"] else "[cyan]Offline Fallback[/cyan]"
    table.add_row("Local Model Endpoint", endpoint, e_state)
    table.add_row("Target Model", str(res["model_name"]), "[blue]Configured[/blue]")

    console.print(table)


@cli.command()
@click.argument("repo_path", default="target_repo/linkwatch", type=click.Path(exists=True, file_okay=False))
def scan(repo_path: str):
    """Scan repository manifests, declared dependencies, and AST source imports."""
    scanner = RepositoryScanner(repo_path)
    metadata, declarations, imports, _, _ = scanner.scan()

    console.print(Panel(
        f"[bold green]Repository:[/bold green] {metadata.repo_name} ({metadata.repo_path})\n"
        f"[bold]Python Detected:[/bold] {metadata.python_version_detected} | "
        f"[bold]Requires Python:[/bold] {metadata.python_requires_declared or 'Unspecified'}\n"
        f"[bold]Manifests:[/bold] {', '.join(metadata.manifests_found)}\n"
        f"[bold]Source Files:[/bold] {metadata.source_files_count} | "
        f"[bold]Test Files:[/bold] {metadata.test_files_count}",
        title="Repository Inventory",
    ))

    table = Table(title=f"Declared Dependencies ({len(declarations)})")
    table.add_column("Package", style="cyan bold")
    table.add_column("Specifier", style="magenta")
    table.add_column("Manifest", style="yellow")
    table.add_column("Line", justify="right")
    table.add_column("Dev", justify="center")

    for d in declarations:
        table.add_row(
            d.name,
            d.specifier or "[dim]any[/dim]",
            d.manifest_path,
            str(d.line_number or "-"),
            "YES" if d.is_dev else "-",
        )
    console.print(table)


@cli.command()
@click.argument("repo_path", default="target_repo/linkwatch", type=click.Path(exists=True, file_okay=False))
def analyze(repo_path: str):
    """Run deterministic resilience rules (Ghost Detector, Tripwires, Conflicts)."""
    scanner = RepositoryScanner(repo_path)
    metadata, declarations, imports, _, _ = scanner.scan()
    analyzer = DependencyAnalyzer(metadata, declarations, imports)
    findings = analyzer.analyze()

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
@click.argument("repo_path", default="target_repo/linkwatch", type=click.Path(exists=True, file_okay=False))
def impact(repo_path: str):
    """Calculate Change Blast-Radius and impacted test suites for dependencies."""
    scanner = RepositoryScanner(repo_path)
    _, declarations, imports, _, _ = scanner.scan()
    analyzer = ImpactAnalyzer(declarations, imports)
    blast_radii = analyzer.calculate_blast_radius()

    table = Table(title="Dependency Change Blast-Radius Map")
    table.add_column("Package", style="bold cyan")
    table.add_column("Risk", style="bold")
    table.add_column("Importing Files", style="white")
    table.add_column("Impacted Tests", style="yellow")

    for br in blast_radii:
        table.add_row(
            br.dependency_name,
            br.risk_level.value.upper(),
            ", ".join(br.importing_files) or "[dim]None (Ghost)[/dim]",
            ", ".join(br.affected_tests) or "[dim]None[/dim]",
        )
    console.print(table)


@cli.command()
@click.argument("repo_path", default="target_repo/linkwatch", type=click.Path(exists=True, file_okay=False))
@click.option("--output-dir", "-o", default="reports", help="Directory to save exit capsule reports.")
def capsule(repo_path: str, output_dir: str):
    """Generate portable, proof-carrying Dependency Exit Capsule (JSON & Markdown)."""
    console.print("[bold blue]Running RepoMedic full resilience audit...[/bold blue]")

    scanner = RepositoryScanner(repo_path)
    metadata, declarations, imports, m_hashes, s_hashes = scanner.scan()

    analyzer = DependencyAnalyzer(metadata, declarations, imports)
    findings = analyzer.analyze()

    impact_analyzer = ImpactAnalyzer(declarations, imports)
    blast_radii = impact_analyzer.calculate_blast_radius()

    adapter = HermesAdapter()
    recommendations = adapter.generate_recommendations(findings)

    verifier = SafeVerificationRunner(repo_path)
    verification = verifier.run_baseline_tests()

    generator = CapsuleGenerator(
        metadata=metadata,
        declarations=declarations,
        imports=imports,
        findings=findings,
        recommendations=recommendations,
        verifications=[verification],
        blast_radii=blast_radii,
        manifest_hashes=m_hashes,
        source_hashes=s_hashes,
    )

    out_dir_path = Path(output_dir)
    json_path = generator.export_json(out_dir_path / "capsule.json")
    md_path = generator.export_markdown(out_dir_path / "capsule.md")

    console.print(f"[bold green][OK] Capsule generated successfully![/bold green]")
    console.print(f"  * JSON Capsule:     [cyan]{json_path}[/cyan]")
    console.print(f"  * Markdown Capsule: [cyan]{md_path}[/cyan]")


if __name__ == "__main__":
    cli()
