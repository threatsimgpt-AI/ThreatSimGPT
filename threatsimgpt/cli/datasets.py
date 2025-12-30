"""Dataset management commands for ThreatSimGPT CLI."""

import asyncio
import json
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from threatsimgpt.datasets.manager import DatasetManager, DatasetType

console = Console()


@click.group()
def datasets():
    """Manage cybersecurity datasets for enhanced threat simulation."""
    pass


@datasets.command()
@click.option(
    "--config-path",
    "-c",
    default="config.yaml",
    help="Path to configuration file"
)
@click.pass_context
def list(ctx: click.Context, config_path: str):
    """List available cybersecurity datasets."""
    try:
        # Try to load actual configuration
        import yaml

        config_file = Path(config_path)
        if config_file.exists():
            with open(config_file, 'r') as f:
                full_config = yaml.safe_load(f)
                datasets_config = full_config.get('datasets', {})
                datasets_config['storage_path'] = Path('~/.threatsimgpt/datasets').expanduser()
        else:
            datasets_config = {
                'storage_path': Path('~/.threatsimgpt/datasets').expanduser(),
                'enron': {'enabled': True},
                'phishtank': {'enabled': True},
                'cert_insider': {'enabled': True},
                'lanl_auth': {'enabled': True},
                'mitre_attack': {'enabled': True}
            }

        manager = DatasetManager(datasets_config)

        # Run async initialization
        async def list_datasets():
            await manager.initialize_datasets()
            return manager.get_dataset_status()

        status = asyncio.run(list_datasets())

        # Create table
        table = Table(title=" Available Cybersecurity Datasets")
        table.add_column("Dataset", style="cyan", no_wrap=True)
        table.add_column("Type", style="magenta")
        table.add_column("Status", style="green")
        table.add_column("Size", style="yellow")
        table.add_column("Description")

        if not status:
            console.print("[yellow]No datasets configured. Run 'download' to get started.[/yellow]")
            return

        for name, info in status.items():
            size_str = f"{info.get('size_mb', 0):.1f} MB" if info.get('size_mb') else "N/A"
            table.add_row(
                name,
                info.get('type', 'unknown'),
                info.get('status', 'unknown'),
                size_str,
                info.get('description', 'No description available')[:60] + "..."
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red] Error listing datasets: {str(e)}[/red]")


@datasets.command()
@click.argument("dataset_type", type=click.Choice([
    "enron", "phishtank", "cert_insider", "lanl_auth", "mitre_attack"
]))
@click.option(
    "--force",
    is_flag=True,
    help="Force re-download even if dataset exists"
)
@click.pass_context
def download(ctx: click.Context, dataset_type: str, force: bool):
    """Download and process a specific dataset."""
    try:
        # Try to load actual configuration
        import yaml

        config_file = Path('config.yaml')
        if config_file.exists():
            with open(config_file, 'r') as f:
                full_config = yaml.safe_load(f)
                datasets_config = full_config.get('datasets', {})
                datasets_config['storage_path'] = Path('~/.threatsimgpt/datasets').expanduser()
        else:
            datasets_config = {
                'storage_path': Path('~/.threatsimgpt/datasets').expanduser(),
                'enron': {'enabled': True},
                'phishtank': {'enabled': True},
                'cert_insider': {'enabled': True},
                'lanl_auth': {'enabled': True},
                'mitre_attack': {'enabled': True}
            }

        manager = DatasetManager(datasets_config)

        # Convert string to enum
        dataset_enum = DatasetType(dataset_type)

        async def download_dataset():
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task(f"Downloading {dataset_type}...", total=None)

                # Initialize first
                await manager.initialize_datasets()

                # Download dataset
                success = await manager.download_dataset(dataset_enum, force=force)

                progress.update(task, description=f"Completed {dataset_type}")
                return success

        success = asyncio.run(download_dataset())

        if success:
            console.print(f"[green] Successfully downloaded and processed {dataset_type} dataset[/green]")
        else:
            console.print(f"[red] Failed to download {dataset_type} dataset[/red]")

    except Exception as e:
        console.print(f"[red] Error downloading dataset: {str(e)}[/red]")


@datasets.command()
@click.option(
    "--format",
    "-f",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format"
)
@click.pass_context
def status(ctx: click.Context, format: str):
    """Show detailed status of all datasets."""
    try:
        # Try to load actual configuration
        import yaml

        config_file = Path('config.yaml')
        if config_file.exists():
            with open(config_file, 'r') as f:
                full_config = yaml.safe_load(f)
                datasets_config = full_config.get('datasets', {})
                datasets_config['storage_path'] = Path('~/.threatsimgpt/datasets').expanduser()
        else:
            datasets_config = {
                'storage_path': Path('~/.threatsimgpt/datasets').expanduser(),
                'enron': {'enabled': True},
                'phishtank': {'enabled': True},
                'cert_insider': {'enabled': True},
                'lanl_auth': {'enabled': True},
                'mitre_attack': {'enabled': True}
            }

        manager = DatasetManager(datasets_config)

        async def get_status():
            await manager.initialize_datasets()
            return await manager.get_dataset_health()

        health = asyncio.run(get_status())

        if format == "json":
            console.print(json.dumps(health, indent=2, default=str))
        else:
            # Table format
            table = Table(title=" Dataset Health Status")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")

            table.add_row("Total Datasets", str(health.get('total_datasets', 0)))
            table.add_row("Ready Datasets", str(health.get('ready_datasets', 0)))
            table.add_row("Pending Downloads", str(health.get('pending_downloads', 0)))
            table.add_row("Total Storage", f"{health.get('total_size_mb', 0):.1f} MB")
            table.add_row("Last Updated", str(health.get('last_updated', 'Never')))

            console.print(table)

            # Show individual dataset details
            if health.get('dataset_details'):
                console.print("\n[bold blue] Individual Dataset Status:[/bold blue]")
                for name, details in health['dataset_details'].items():
                    status_color = "green" if details.get('status') == 'ready' else "yellow"
                    console.print(f"  • [{status_color}]{name}[/{status_color}]: {details.get('status', 'unknown')}")

    except Exception as e:
        console.print(f"[red] Error getting dataset status: {str(e)}[/red]")


@datasets.command()
@click.argument("pattern_type", type=click.Choice([
    "email", "phishing", "insider-threat", "authentication", "ttp"
]))
@click.option(
    "--role",
    default="general",
    help="Target role for email patterns (executive, manager, employee)"
)
@click.option(
    "--industry",
    default="technology",
    help="Target industry for patterns"
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format"
)
@click.pass_context
def patterns(ctx: click.Context, pattern_type: str, role: str, industry: str, format: str):
    """Extract patterns from datasets for threat modeling."""
    try:
        config = {
            'storage_path': Path('~/.threatsimgpt/datasets').expanduser()
        }

        manager = DatasetManager(config)

        async def get_patterns():
            await manager.initialize_datasets()

            if pattern_type == "email":
                return await manager.get_email_patterns(role=role, industry=industry)
            elif pattern_type == "phishing":
                return await manager.get_phishing_patterns(target_sector=industry)
            elif pattern_type == "insider-threat":
                return await manager.get_insider_threat_patterns(threat_type=role)
            else:
                console.print(f"[red]Pattern type {pattern_type} not yet implemented[/red]")
                return None

        patterns = asyncio.run(get_patterns())

        if patterns is None:
            return

        if format == "json":
            console.print(json.dumps(patterns.__dict__, indent=2, default=str))
        else:
            # Table format based on pattern type
            if pattern_type == "email":
                table = Table(title=f" Email Patterns ({role} in {industry})")
                table.add_column("Category", style="cyan")
                table.add_column("Examples", style="green")

                table.add_row("Subject Patterns", ", ".join(patterns.subject_patterns[:3]))
                table.add_row("Greeting Styles", ", ".join(patterns.greeting_styles[:3]))
                table.add_row("Closing Phrases", ", ".join(patterns.closing_phrases[:3]))
                table.add_row("Language Tone", patterns.language_tone)
                table.add_row("Formality Level", patterns.formality_level)
                table.add_row("Avg Length", f"{patterns.average_length} chars")

            elif pattern_type == "phishing":
                table = Table(title=f" Phishing Patterns ({industry})")
                table.add_column("Category", style="cyan")
                table.add_column("Examples", style="red")

                table.add_row("Common Domains", ", ".join(patterns.common_domains[:3]))
                table.add_row("Suspicious TLDs", ", ".join(patterns.suspicious_tlds[:5]))
                table.add_row("URL Patterns", ", ".join(patterns.url_patterns[:3]))
                table.add_row("Subdomain Tricks", ", ".join(patterns.subdomain_tricks[:3]))

            console.print(table)

    except Exception as e:
        console.print(f"[red] Error extracting patterns: {str(e)}[/red]")


@datasets.command()
@click.pass_context
def clear_cache(ctx: click.Context):
    """Clear dataset pattern cache."""
    try:
        config = {
            'storage_path': Path('~/.threatsimgpt/datasets').expanduser()
        }

        manager = DatasetManager(config)
        manager.clear_cache()

        console.print("[green] Dataset cache cleared successfully[/green]")

    except Exception as e:
        console.print(f"[red] Error clearing cache: {str(e)}[/red]")
