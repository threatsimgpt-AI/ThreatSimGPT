"""CLI commands for managing simulation logs and results."""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax

from ..core.simulation_logger import SimulationLogger
from ..core.output_models import SimulationOutputValidator

console = Console()


@click.group()
def logs():
    """Manage simulation logs and results."""
    pass


@logs.command("list")
@click.option("--limit", "-l", default=20, help="Maximum number of results to show")
@click.option("--threat-type", "-t", help="Filter by threat type")
@click.option("--success-only", "-s", is_flag=True, help="Show only successful simulations")
@click.option("--days", "-d", type=int, help="Show simulations from last N days")
def list_simulations(limit: int, threat_type: Optional[str], success_only: bool, days: Optional[int]):
    """List stored simulation results."""
    logger = SimulationLogger()

    # Calculate date filter if specified
    start_date = None
    if days:
        start_date = datetime.utcnow() - timedelta(days=days)

    try:
        simulations = logger.list_simulations(
            limit=limit,
            threat_type=threat_type,
            success_only=success_only,
            start_date=start_date
        )

        if not simulations:
            console.print("[yellow]No simulations found matching the criteria.[/yellow]")
            return

        # Create table
        table = Table(title="Simulation Results", show_header=True)
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Scenario", style="white")
        table.add_column("Threat Type", style="blue")
        table.add_column("Status", justify="center")
        table.add_column("Duration", justify="right")
        table.add_column("Created", style="dim")

        for sim in simulations:
            status = "[green][/green]" if sim.get("success", False) else "[red][/red]"
            duration = f"{sim.get('duration_seconds', 0):.1f}s"
            created = datetime.fromisoformat(sim["created_at"]).strftime("%Y-%m-%d %H:%M")

            table.add_row(
                sim["simulation_id"][:12] + "...",
                sim.get("scenario_name", "Unknown"),
                sim.get("threat_type", "Unknown"),
                status,
                duration,
                created
            )

        console.print(table)
        console.print(f"\n[dim]Showing {len(simulations)} of {limit} requested results[/dim]")

    except Exception as e:
        console.print(f"[red]Error listing simulations: {e}[/red]")


@logs.command("show")
@click.argument("simulation_id")
@click.option("--format", "-f", type=click.Choice(["json", "yaml", "summary"]), default="summary", help="Output format")
def show_simulation(simulation_id: str, format: str):
    """Show detailed results for a specific simulation."""
    logger = SimulationLogger()

    try:
        simulation = logger.load_simulation_result(simulation_id)

        if not simulation:
            console.print(f"[red]Simulation {simulation_id} not found.[/red]")
            return

        if format == "json":
            json_content = simulation.to_json()
            syntax = Syntax(json_content, "json", theme="monokai", line_numbers=True)
            console.print(Panel(syntax, title=f"Simulation {simulation_id[:12]}... (JSON)", border_style="blue"))

        elif format == "yaml":
            yaml_content = simulation.to_yaml()
            syntax = Syntax(yaml_content, "yaml", theme="monokai", line_numbers=True)
            console.print(Panel(syntax, title=f"Simulation {simulation_id[:12]}... (YAML)", border_style="green"))

        else:  # summary format
            console.print("\n[bold cyan]Simulation Details[/bold cyan]")

            # Basic info table
            info_table = Table(show_header=False, box=None)
            info_table.add_column("Field", style="cyan")
            info_table.add_column("Value", style="white")

            info_table.add_row("Simulation ID", simulation.simulation_id)
            info_table.add_row("Status", f"[green]{simulation.status}[/green]" if simulation.success else f"[red]{simulation.status}[/red]")
            info_table.add_row("Created", simulation.created_at.strftime("%Y-%m-%d %H:%M:%S"))
            if simulation.completed_at:
                info_table.add_row("Completed", simulation.completed_at.strftime("%Y-%m-%d %H:%M:%S"))
            info_table.add_row("Duration", f"{simulation.metrics.duration_seconds:.1f} seconds")
            info_table.add_row("Success Rate", f"{simulation.metrics.success_rate:.1f}%")

            console.print(Panel(info_table, title="Basic Information", border_style="cyan"))

            # Scenario info
            scenario_table = Table(show_header=False, box=None)
            scenario_table.add_column("Field", style="blue")
            scenario_table.add_column("Value", style="white")

            scenario_table.add_row("Name", simulation.scenario.name)
            scenario_table.add_row("Description", simulation.scenario.description)
            scenario_table.add_row("Threat Type", simulation.scenario.threat_type)
            scenario_table.add_row("Delivery Vector", simulation.scenario.delivery_vector)
            scenario_table.add_row("Difficulty", f"{simulation.scenario.difficulty_level}/10")

            console.print(Panel(scenario_table, title="Scenario Information", border_style="blue"))

            # Target profile
            target_table = Table(show_header=False, box=None)
            target_table.add_column("Field", style="yellow")
            target_table.add_column("Value", style="white")

            target_table.add_row("Role", simulation.target_profile.role)
            target_table.add_row("Department", simulation.target_profile.department)
            target_table.add_row("Seniority", simulation.target_profile.seniority)
            target_table.add_row("Industry", simulation.target_profile.industry)
            target_table.add_row("Security Awareness", f"{simulation.target_profile.security_awareness}/10")

            console.print(Panel(target_table, title="Target Profile", border_style="yellow"))

            # Generated content
            if simulation.generated_content:
                console.print(f"\n[bold green]Generated Content ({len(simulation.generated_content)} items)[/bold green]")
                for i, content in enumerate(simulation.generated_content, 1):
                    content_preview = content.content[:200] + "..." if len(content.content) > 200 else content.content
                    console.print(f"[dim]{i}. {content.content_type}:[/dim] {content_preview}")

            # Recommendations
            if simulation.recommendations:
                console.print("\n[bold yellow]Recommendations[/bold yellow]")
                for i, rec in enumerate(simulation.recommendations, 1):
                    console.print(f"  {i}. {rec}")

    except Exception as e:
        console.print(f"[red]Error loading simulation: {e}[/red]")


@logs.command("stats")
def show_statistics():
    """Show statistics about stored simulations."""
    logger = SimulationLogger()

    try:
        stats = logger.get_statistics()

        if "error" in stats:
            console.print(f"[red]Error getting statistics: {stats['error']}[/red]")
            return

        # Overview table
        overview_table = Table(title="Simulation Statistics Overview", show_header=True)
        overview_table.add_column("Metric", style="cyan")
        overview_table.add_column("Value", justify="right", style="white")

        overview_table.add_row("Total Simulations", str(stats["total_simulations"]))
        overview_table.add_row("Successful", f"[green]{stats['successful_simulations']}[/green]")
        overview_table.add_row("Failed", f"[red]{stats['failed_simulations']}[/red]")

        if stats["average_duration"] > 0:
            overview_table.add_row("Average Duration", f"{stats['average_duration']:.1f}s")

        if stats["oldest_simulation"]:
            oldest = datetime.fromisoformat(stats["oldest_simulation"]).strftime("%Y-%m-%d")
            overview_table.add_row("Oldest Simulation", oldest)

        if stats["newest_simulation"]:
            newest = datetime.fromisoformat(stats["newest_simulation"]).strftime("%Y-%m-%d")
            overview_table.add_row("Newest Simulation", newest)

        console.print(overview_table)

        # Threat types breakdown
        if stats["threat_types"]:
            console.print("\n[bold blue]Threat Types Breakdown[/bold blue]")
            threat_table = Table(show_header=True)
            threat_table.add_column("Threat Type", style="blue")
            threat_table.add_column("Count", justify="right", style="white")
            threat_table.add_column("Percentage", justify="right", style="dim")

            total = stats["total_simulations"]
            for threat_type, count in sorted(stats["threat_types"].items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total * 100) if total > 0 else 0
                threat_table.add_row(threat_type, str(count), f"{percentage:.1f}%")

            console.print(threat_table)

    except Exception as e:
        console.print(f"[red]Error getting statistics: {e}[/red]")


@logs.command("archive")
@click.option("--days", "-d", default=30, help="Archive simulations older than N days")
@click.option("--compress", "-c", is_flag=True, default=True, help="Compress archived files")
@click.option("--dry-run", is_flag=True, help="Show what would be archived without doing it")
def archive_old(days: int, compress: bool, dry_run: bool):
    """Archive old simulation results."""
    logger = SimulationLogger()

    if dry_run:
        console.print(f"[yellow]DRY RUN: Would archive simulations older than {days} days[/yellow]")
        # In a real implementation, we'd show what would be archived
        console.print("[dim]Dry run mode - no files will be modified[/dim]")
        return

    try:
        archived_count = logger.archive_old_simulations(days_old=days, compress=compress)

        if archived_count > 0:
            console.print(f"[green] Archived {archived_count} simulations older than {days} days[/green]")
            if compress:
                console.print("[dim]Files were compressed to save space[/dim]")
        else:
            console.print(f"[yellow]No simulations found older than {days} days[/yellow]")

    except Exception as e:
        console.print(f"[red]Error archiving simulations: {e}[/red]")


@logs.command("validate")
@click.argument("file_path", required=False)
@click.option("--directory", "-d", help="Validate all simulation files in directory")
def validate_logs(file_path: Optional[str], directory: Optional[str]):
    """Validate simulation log file format."""

    if directory:
        # Validate directory
        dir_path = Path(directory)
        if not dir_path.exists():
            console.print(f"[red]Directory not found: {directory}[/red]")
            return

        console.print(f"[blue]Validating simulation files in: {directory}[/blue]")

        valid_count = 0
        invalid_count = 0

        for file_path in dir_path.glob("*.json"):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                SimulationOutputValidator.validate_json_string(content)
                console.print(f"[green][/green] {file_path.name}")
                valid_count += 1
            except Exception as e:
                console.print(f"[red][/red] {file_path.name}: {e}")
                invalid_count += 1

        console.print("\n[blue]Validation Summary:[/blue]")
        console.print(f"  Valid files: [green]{valid_count}[/green]")
        console.print(f"  Invalid files: [red]{invalid_count}[/red]")

    elif file_path:
        # Validate single file
        file_path = Path(file_path)
        if not file_path.exists():
            console.print(f"[red]File not found: {file_path}[/red]")
            return

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            if file_path.suffix == '.json':
                simulation = SimulationOutputValidator.validate_json_string(content)
            elif file_path.suffix in ['.yaml', '.yml']:
                simulation = SimulationOutputValidator.validate_yaml_string(content)
            else:
                console.print(f"[red]Unsupported file format: {file_path.suffix}[/red]")
                return

            console.print("[green] File is valid[/green]")
            console.print(f"[dim]Simulation ID: {simulation.simulation_id}[/dim]")
            console.print(f"[dim]Scenario: {simulation.scenario.name}[/dim]")

        except Exception as e:
            console.print(f"[red] Validation failed: {e}[/red]")

    else:
        console.print("[yellow]Please specify either a file path or directory to validate[/yellow]")
