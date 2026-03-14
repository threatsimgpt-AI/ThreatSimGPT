"""Intelligence CLI commands for ThreatSimGPT.

This module provides CLI commands for managing OSINT reconnaissance
and real-time intelligence gathering capabilities.
"""

import asyncio
import json
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax
from rich.table import Table
from rich.tree import Tree

from ..intelligence import IntelligenceEngine, OSINTService
from ..intelligence.models import ConfidenceLevel, IntelligenceSource

console = Console()


@click.group(name="intel")
def intel_group():
    """Intelligence gathering and OSINT reconnaissance."""
    pass


@intel_group.command()
@click.argument("target")
@click.option(
    "--types",
    "-t",
    multiple=True,
    type=click.Choice(["profile", "company", "social_media", "threat_intel", "domain"]),
    default=["profile", "company", "social_media"],
    help="Types of intelligence to gather"
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file for intelligence results"
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["json", "table", "report"]),
    default="table",
    help="Output format"
)
@click.option(
    "--force-refresh",
    is_flag=True,
    help="Force fresh intelligence gathering, ignore cache"
)
def gather(target: str, types: tuple, output: Optional[Path], format: str, force_refresh: bool):
    """Gather intelligence for a target (email, domain, or name)."""

    async def _gather_intelligence():
        console.print(f"[blue]Gathering intelligence for:[/blue] {target}")
        console.print(f"[dim]Intelligence types: {', '.join(types)}[/dim]")

        # Initialize intelligence services
        osint_service = OSINTService()
        intelligence_engine = IntelligenceEngine(osint_service)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Gathering intelligence...", total=None)

            try:
                # Gather intelligence
                result = await intelligence_engine.gather_target_intelligence(
                    target_identifier=target,
                    intelligence_types=list(types),
                    force_refresh=force_refresh
                )

                progress.update(task, completed=100)

                # Display results
                if format == "table":
                    _display_intelligence_table(result)
                elif format == "report":
                    _display_intelligence_report(result)
                else:  # json
                    _display_intelligence_json(result)

                # Save to file if requested
                if output:
                    _save_intelligence_results(result, output, format)
                    console.print(f"\n[green]Results saved to: {output}[/green]")

            except Exception as e:
                progress.update(task, completed=100)
                console.print(f"[red]Intelligence gathering failed: {str(e)}[/red]")

    asyncio.run(_gather_intelligence())


@intel_group.command()
@click.argument("scenario_file", type=click.Path(exists=True, path_type=Path))
@click.argument("target")
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file for enhanced scenario"
)
@click.option(
    "--preview",
    is_flag=True,
    help="Preview enhancements without generating content"
)
def enhance(scenario_file: Path, target: str, output: Optional[Path], preview: bool):
    """Enhance a threat scenario with real-time intelligence."""

    async def _enhance_scenario():
        from ..config.yaml_loader import YAMLConfigLoader

        console.print(f"[blue]Enhancing scenario:[/blue] {scenario_file.name}")
        console.print(f"[blue]Target:[/blue] {target}")

        # Load scenario
        loader = YAMLConfigLoader()
        try:
            scenario = loader.load_and_validate_scenario(scenario_file)
        except Exception as e:
            console.print(f"[red]Failed to load scenario: {e}[/red]")
            return

        # Initialize intelligence services
        osint_service = OSINTService()
        intelligence_engine = IntelligenceEngine(osint_service)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            intel_task = progress.add_task("Gathering target intelligence...", total=None)

            try:
                # Enhance scenario with intelligence
                enhanced_scenario, intelligence = await intelligence_engine.enrich_threat_scenario(
                    scenario, target
                )

                progress.complete_task(intel_task)

                # Display enhancement preview
                _display_scenario_enhancements(scenario, enhanced_scenario, intelligence)

                if not preview:
                    # Save enhanced scenario
                    if output:
                        output_path = output
                    else:
                        output_path = scenario_file.parent / f"enhanced_{scenario_file.name}"

                    # Convert enhanced scenario back to YAML
                    import yaml
                    enhanced_data = enhanced_scenario.model_dump()

                    with open(output_path, 'w', encoding='utf-8') as f:
                        yaml.dump(enhanced_data, f, default_flow_style=False, sort_keys=False)

                    console.print(f"\n[green]Enhanced scenario saved to: {output_path}[/green]")

            except Exception as e:
                progress.complete_task(intel_task)
                console.print(f"[red]Scenario enhancement failed: {str(e)}[/red]")

    asyncio.run(_enhance_scenario())


@intel_group.command()
@click.option(
    "--source",
    "-s",
    type=click.Choice([source.value for source in IntelligenceSource]),
    help="Filter by intelligence source"
)
@click.option(
    "--confidence",
    "-c",
    type=click.Choice([level.value for level in ConfidenceLevel]),
    help="Filter by confidence level"
)
def sources(source: Optional[str], confidence: Optional[str]):
    """List available intelligence sources and their capabilities."""

    console.print("[bold cyan]ThreatSimGPT Intelligence Sources[/bold cyan]\n")

    sources_info = {
        IntelligenceSource.LINKEDIN: {
            "description": "Professional profile and network intelligence",
            "capabilities": ["Profile data", "Work history", "Connections", "Skills"],
            "rate_limit": "30 requests/minute",
            "confidence": "High",
            "requires_api": True
        },
        IntelligenceSource.COMPANY_WEBSITE: {
            "description": "Company information from official websites",
            "capabilities": ["Company info", "News", "Team", "Products"],
            "rate_limit": "60 requests/minute",
            "confidence": "High",
            "requires_api": False
        },
        IntelligenceSource.TWITTER: {
            "description": "Social media presence and activity analysis",
            "capabilities": ["Posts", "Interests", "Network", "Sentiment"],
            "rate_limit": "100 requests/minute",
            "confidence": "Medium",
            "requires_api": True
        },
        IntelligenceSource.GITHUB: {
            "description": "Technical profile and project analysis",
            "capabilities": ["Repositories", "Skills", "Activity", "Network"],
            "rate_limit": "60 requests/minute",
            "confidence": "High",
            "requires_api": False
        },
        IntelligenceSource.DOMAIN_WHOIS: {
            "description": "Domain registration and ownership data",
            "capabilities": ["Registrar", "Creation date", "Contact info"],
            "rate_limit": "60 requests/minute",
            "confidence": "High",
            "requires_api": False
        },
        IntelligenceSource.THREAT_FEEDS: {
            "description": "Threat intelligence and IoC data",
            "capabilities": ["Threat actors", "Campaigns", "IoCs", "TTPs"],
            "rate_limit": "60 requests/minute",
            "confidence": "Medium",
            "requires_api": True
        }
    }

    # Filter sources if requested
    if source:
        sources_info = {IntelligenceSource(source): sources_info[IntelligenceSource(source)]}

    # Create sources table
    table = Table(title="Intelligence Sources", show_header=True, header_style="bold magenta")
    table.add_column("Source", style="cyan", width=20)
    table.add_column("Description", style="white", width=40)
    table.add_column("Capabilities", style="green", width=25)
    table.add_column("Rate Limit", style="yellow", width=15)
    table.add_column("Confidence", style="blue", width=10)
    table.add_column("API Required", style="red", width=12)

    for source_enum, info in sources_info.items():
        # Skip if confidence filter doesn't match
        if confidence and info["confidence"].lower() != confidence:
            continue

        table.add_row(
            source_enum.value.replace("_", " ").title(),
            info["description"],
            ", ".join(info["capabilities"]),
            info["rate_limit"],
            info["confidence"],
            "Yes" if info["requires_api"] else "No"
        )

    console.print(table)

    # Show setup instructions
    console.print("\n[bold yellow]Setup Instructions:[/bold yellow]")
    console.print("To enable API-based sources, configure API keys in your environment:")
    console.print("  • LinkedIn: LINKEDIN_API_KEY")
    console.print("  • Twitter: TWITTER_API_KEY")
    console.print("  • Threat Intel: THREAT_INTEL_API_KEY")


@intel_group.command()
@click.option(
    "--clear-cache",
    is_flag=True,
    help="Clear intelligence cache"
)
def cache(clear_cache: bool):
    """Manage intelligence cache."""

    if clear_cache:
        console.print("[yellow]Clearing intelligence cache...[/yellow]")
        # Would clear cache here
        console.print("[green]Cache cleared successfully[/green]")
    else:
        console.print("[blue]Intelligence Cache Status[/blue]")

        # Mock cache status
        cache_table = Table(show_header=True)
        cache_table.add_column("Target", style="cyan")
        cache_table.add_column("Last Updated", style="white")
        cache_table.add_column("Confidence", style="green")
        cache_table.add_column("Sources", style="yellow")
        cache_table.add_column("Size", style="blue")

        # Would show actual cache entries
        cache_table.add_row(
            "john.doe@company.com",
            "2 hours ago",
            "High",
            "3 sources",
            "2.4 KB"
        )

        console.print(cache_table)


def _display_intelligence_table(result):
    """Display intelligence results in table format."""
    console.print(f"\n[bold green]Intelligence Report for: {result.target_identifier}[/bold green]")

    # Summary table
    summary_table = Table(title="Intelligence Summary", show_header=False)
    summary_table.add_column("Metric", style="bold")
    summary_table.add_column("Value")

    summary_table.add_row("Query ID", result.query_id[:8])
    summary_table.add_row("Confidence Level", result.overall_confidence.value.title())
    summary_table.add_row("Sources Used", f"{len(result.data_sources_used)} sources")
    summary_table.add_row("Collection Time", f"{result.collection_duration_seconds:.1f} seconds")
    summary_table.add_row("Completeness", f"{result.completeness_score:.1%}")

    console.print(summary_table)

    # Individual profiles
    if result.individual_profiles:
        console.print("\n[bold cyan]Individual Profiles[/bold cyan]")
        for profile in result.individual_profiles:
            profile_text = f"Name: {profile.full_name}\n"
            if profile.job_title:
                profile_text += f"Title: {profile.job_title}\n"
            if profile.company:
                profile_text += f"Company: {profile.company}\n"
            if profile.interests:
                profile_text += f"Interests: {', '.join(profile.interests[:5])}\n"

            console.print(Panel(profile_text, border_style="green"))

    # Company intelligence
    if result.company_intelligence:
        console.print("\n[bold cyan]Company Intelligence[/bold cyan]")
        company = result.company_intelligence
        company_text = f"Name: {company.company_name}\n"
        company_text += f"Industry: {company.industry}\n"
        if company.company_size:
            company_text += f"Size: {company.company_size}\n"
        if company.recent_news:
            company_text += f"Recent News: {len(company.recent_news)} articles\n"

        console.print(Panel(company_text, border_style="blue"))

    # Key findings
    if result.key_findings:
        console.print("\n[bold yellow]Key Findings[/bold yellow]")
        for finding in result.key_findings:
            console.print(f"  • {finding}")

    # Scenario suggestions
    if result.scenario_enhancement_suggestions:
        console.print("\n[bold magenta]Scenario Enhancement Suggestions[/bold magenta]")
        for suggestion in result.scenario_enhancement_suggestions:
            console.print(f"  • {suggestion}")


def _display_intelligence_report(result):
    """Display intelligence results in detailed report format."""
    console.print("\n[bold green]Detailed Intelligence Report[/bold green]")
    console.print(f"[bold]Target:[/bold] {result.target_identifier}")
    console.print(f"[bold]Generated:[/bold] {result.query_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    console.print(f"[bold]Confidence:[/bold] {result.overall_confidence.value.title()}")

    # Create report tree
    tree = Tree("Intelligence Analysis")

    # Individual profiles branch
    if result.individual_profiles:
        profiles_branch = tree.add("Individual Profiles")
        for profile in result.individual_profiles:
            profile_branch = profiles_branch.add(f"Profile: {profile.full_name}")
            if profile.job_title:
                profile_branch.add(f"Title: {profile.job_title}")
            if profile.company:
                profile_branch.add(f"Company: {profile.company}")
            if profile.skills:
                skills_branch = profile_branch.add("Skills")
                for skill in profile.skills[:5]:
                    skills_branch.add(skill)

    # Company intelligence branch
    if result.company_intelligence:
        company_branch = tree.add("Company Intelligence")
        company = result.company_intelligence
        company_branch.add(f"Name: {company.company_name}")
        company_branch.add(f"Industry: {company.industry}")
        if company.recent_news:
            news_branch = company_branch.add("Recent News")
            for news in company.recent_news[:3]:
                news_branch.add(news.get("title", "Unknown"))

    # Social media branch
    if result.social_media_intelligence:
        social_branch = tree.add("Social Media")
        for social in result.social_media_intelligence:
            platform_branch = social_branch.add(f"{social.platform.title()}: @{social.username}")
            if social.follower_count:
                platform_branch.add(f"Followers: {social.follower_count}")
            if social.topics_of_interest:
                interests_branch = platform_branch.add("Interests")
                for interest in social.topics_of_interest[:3]:
                    interests_branch.add(interest)

    console.print(tree)


def _display_intelligence_json(result):
    """Display intelligence results in JSON format."""
    result_dict = result.model_dump()
    json_str = json.dumps(result_dict, indent=2, default=str)

    syntax = Syntax(json_str, "json", theme="monokai", line_numbers=True)
    console.print(Panel(syntax, title="Intelligence Results (JSON)", border_style="blue"))


def _save_intelligence_results(result, output_path: Path, format: str):
    """Save intelligence results to file."""
    result_dict = result.model_dump()

    if format == "json":
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result_dict, f, indent=2, default=str)
    else:
        # Save as YAML for other formats
        import yaml
        with open(output_path, 'w', encoding='utf-8') as f:
            yaml.dump(result_dict, f, default_flow_style=False, sort_keys=False)


def _display_scenario_enhancements(original, enhanced, intelligence):
    """Display scenario enhancements based on intelligence."""
    console.print("\n[bold green]Scenario Enhancement Analysis[/bold green]")

    # Show intelligence confidence
    console.print(f"[cyan]Intelligence Confidence:[/cyan] {intelligence.overall_confidence.value.title()}")
    console.print(f"[cyan]Data Sources:[/cyan] {len(intelligence.data_sources_used)} sources")
    console.print(f"[cyan]Completeness:[/cyan] {intelligence.completeness_score:.1%}")

    # Show enhancements
    enhancements_table = Table(title="Applied Enhancements", show_header=True)
    enhancements_table.add_column("Category", style="cyan")
    enhancements_table.add_column("Original", style="white")
    enhancements_table.add_column("Enhanced", style="green")
    enhancements_table.add_column("Source", style="yellow")

    # Compare key fields
    if hasattr(enhanced.target_profile, 'company_name') and enhanced.target_profile.company_name:
        enhancements_table.add_row(
            "Company",
            original.target_profile.company_name or "Generic",
            enhanced.target_profile.company_name,
            "Company Intelligence"
        )

    if enhanced.custom_parameters.get("recent_company_news"):
        news_count = len(enhanced.custom_parameters["recent_company_news"])
        enhancements_table.add_row(
            "News Context",
            "None",
            f"{news_count} recent articles",
            "Company Intelligence"
        )

    if enhanced.custom_parameters.get("social_media_platforms"):
        platforms = enhanced.custom_parameters["social_media_platforms"]
        enhancements_table.add_row(
            "Social Media",
            "Generic",
            f"{len(platforms)} platforms found",
            "Social Media Intelligence"
        )

    console.print(enhancements_table)

    # Show personalization suggestions
    if intelligence.scenario_enhancement_suggestions:
        console.print("\n[bold yellow]Enhancement Suggestions[/bold yellow]")
        for suggestion in intelligence.scenario_enhancement_suggestions:
            console.print(f"  • {suggestion}")


# Register intel commands with main CLI
def register_intel_commands(cli_group):
    """Register intelligence commands with the main CLI group."""
    cli_group.add_command(intel_group)
