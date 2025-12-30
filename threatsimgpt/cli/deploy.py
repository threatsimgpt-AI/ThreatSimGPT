"""CLI commands for threat deployment and campaign management.

This module provides comprehensive CLI interface for managing threat
deployments across multiple enterprise platforms with real-time monitoring.
"""

import asyncio
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.live import Live
from rich.layout import Layout
from rich.text import Text

from ..deployment import (
    ThreatDeploymentEngine,
    DeploymentConfig,
    DeploymentChannel,
    DeploymentStatus,
    CampaignMetrics
)
from ..deployment.integrations import PlatformIntegrationManager
from ..config import load_config


console = Console()


@click.group(name='deploy')
@click.pass_context
def deploy_group(ctx):
    """Threat deployment and campaign management commands."""
    if ctx.obj is None:
        ctx.obj = {}

    # Load configuration
    try:
        config = load_config()
        ctx.obj['config'] = config

        # Initialize deployment engine
        deployment_config = config.get('deployment', {})
        ctx.obj['deployment_engine'] = ThreatDeploymentEngine(deployment_config)

        # Initialize platform integrations
        platform_config = config.get('integrations', {})
        ctx.obj['platform_manager'] = PlatformIntegrationManager(platform_config)

    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        ctx.exit(1)


@deploy_group.command('campaign')
@click.option('--name', '-n', required=True, help='Campaign name')
@click.option('--content-file', '-c', required=True, type=click.Path(exists=True),
              help='JSON file containing generated threat content')
@click.option('--targets-file', '-t', required=True, type=click.Path(exists=True),
              help='JSON file containing target configurations')
@click.option('--channels', '-ch', multiple=True,
              type=click.Choice(['email', 'sms', 'voice', 'social_media', 'web', 'physical']),
              default=['email'], help='Deployment channels to use')
@click.option('--platforms', '-p', multiple=True,
              help='Specific platforms to deploy through (e.g., microsoft365, proofpoint)')
@click.option('--duration', '-d', default=24, type=int, help='Campaign duration in hours')
@click.option('--test-mode', is_flag=True, default=True, help='Run in test mode (safe deployment)')
@click.option('--compliance-approved', is_flag=True, default=False,
              help='Mark as compliance approved (required for production)')
@click.option('--monitor', '-m', is_flag=True, default=True, help='Enable real-time monitoring')
@click.pass_context
def deploy_campaign(ctx, name, content_file, targets_file, channels, platforms,
                   duration, test_mode, compliance_approved, monitor):
    """Deploy a comprehensive threat campaign across multiple channels."""

    deployment_engine = ctx.obj['deployment_engine']
    platform_manager = ctx.obj['platform_manager']

    # Load content and targets
    try:
        with open(content_file, 'r') as f:
            threat_content = json.load(f)

        with open(targets_file, 'r') as f:
            targets_data = json.load(f)

    except Exception as e:
        console.print(f"[red]Error loading files: {e}[/red]")
        return

    # Convert string channels to enum
    deployment_channels = [DeploymentChannel(ch) for ch in channels]

    # Prepare targets for each channel
    prepared_targets = []
    for target in targets_data:
        target_config = target.copy()
        target_config['channels'] = list(channels)  # Apply selected channels
        prepared_targets.append(target_config)

    # Create deployment configuration
    deployment_config = DeploymentConfig(
        campaign_name=name,
        channels=deployment_channels,
        targets=prepared_targets,
        duration_hours=duration,
        compliance_approved=compliance_approved,
        test_mode=test_mode,
        personalization_level="high"
    )

    # Display campaign summary
    _display_campaign_summary(deployment_config, threat_content, platforms)

    # Confirm deployment
    if not test_mode and not click.confirm("\n[bold red]This will deploy real threat content. Continue?[/bold red]"):
        return

    # Deploy campaign
    console.print("\n[bold blue]Deploying threat campaign...[/bold blue]")

    async def run_deployment():
        try:
            # Platform-specific deployments
            platform_results = {}

            if platforms:
                for platform in platforms:
                    console.print(f"[yellow]Deploying through {platform}...[/yellow]")

                    try:
                        result = await platform_manager.deploy_through_platform(
                            platform_name=platform,
                            content=threat_content,
                            targets=prepared_targets
                        )
                        platform_results[platform] = result
                        console.print(f"[green] {platform} deployment completed[/green]")

                    except Exception as e:
                        console.print(f"[red] {platform} deployment failed: {e}[/red]")
                        platform_results[platform] = None

            # Core deployment engine
            campaign_id, deployment_results = await deployment_engine.deploy_threat_campaign(
                generated_content=threat_content,
                deployment_config=deployment_config
            )

            # Display results
            _display_deployment_results(campaign_id, deployment_results, platform_results)

            # Start monitoring if requested
            if monitor:
                await _monitor_campaign(deployment_engine, campaign_id, platform_manager, platforms)

        except Exception as e:
            console.print(f"[red]Campaign deployment failed: {e}[/red]")

    # Run deployment
    asyncio.run(run_deployment())


@deploy_group.command('status')
@click.argument('campaign_id', required=True)
@click.option('--detailed', '-d', is_flag=True, help='Show detailed metrics')
@click.option('--platforms', '-p', multiple=True, help='Include platform-specific metrics')
@click.pass_context
def campaign_status(ctx, campaign_id, detailed, platforms):
    """Get current status and metrics for a campaign."""

    deployment_engine = ctx.obj['deployment_engine']
    platform_manager = ctx.obj['platform_manager']

    async def get_status():
        try:
            # Get core campaign status
            status = await deployment_engine.get_campaign_status(campaign_id)

            # Get platform metrics if requested
            platform_metrics = {}
            if platforms:
                platform_metrics = await platform_manager.get_all_campaign_metrics(campaign_id)

            # Display status
            _display_campaign_status(status, platform_metrics, detailed)

        except Exception as e:
            console.print(f"[red]Error getting campaign status: {e}[/red]")

    asyncio.run(get_status())


@deploy_group.command('monitor')
@click.argument('campaign_id', required=True)
@click.option('--refresh-interval', '-r', default=5, type=int, help='Refresh interval in seconds')
@click.option('--platforms', '-p', multiple=True, help='Include platform monitoring')
@click.pass_context
def monitor_campaign(ctx, campaign_id, refresh_interval, platforms):
    """Monitor campaign in real-time with live dashboard."""

    deployment_engine = ctx.obj['deployment_engine']
    platform_manager = ctx.obj['platform_manager']

    async def monitor():
        await _monitor_campaign(deployment_engine, campaign_id, platform_manager,
                               platforms, refresh_interval)

    asyncio.run(monitor())


@deploy_group.command('platforms')
@click.option('--test', '-t', is_flag=True, help='Test platform connectivity')
@click.pass_context
def list_platforms(ctx, test):
    """List available platform integrations."""

    platform_manager = ctx.obj['platform_manager']

    async def show_platforms():
        available_platforms = platform_manager.get_available_platforms()

        if not available_platforms:
            console.print("[yellow]No platform integrations configured[/yellow]")
            return

        table = Table(title="Available Platform Integrations", show_header=True)
        table.add_column("Platform", style="cyan")
        table.add_column("Status", style="bold")
        table.add_column("Last Tested", style="dim")
        table.add_column("Details")

        for platform in available_platforms:
            if test:
                console.print(f"[yellow]Testing {platform}...[/yellow]")
                test_result = await platform_manager.test_platform_connectivity(platform)

                status = "[green] Healthy[/green]" if test_result.get("status") == "healthy" else "[red] Failed[/red]"
                last_tested = test_result.get("timestamp", "Never")
                details = test_result.get("error", "Connection successful") if test_result.get("error") else "Ready for deployment"

            else:
                status = "[dim]Not tested[/dim]"
                last_tested = "Never"
                details = "Run with --test to check connectivity"

            table.add_row(platform, status, last_tested, details)

        console.print(table)

    asyncio.run(show_platforms())


@deploy_group.command('cancel')
@click.argument('campaign_id', required=True)
@click.option('--force', '-f', is_flag=True, help='Force cancel without confirmation')
@click.pass_context
def cancel_campaign(ctx, campaign_id, force):
    """Cancel an active campaign."""

    deployment_engine = ctx.obj['deployment_engine']

    if not force and not click.confirm(f"Cancel campaign {campaign_id}?"):
        return

    async def cancel():
        try:
            success = await deployment_engine.cancel_campaign(campaign_id)

            if success:
                console.print(f"[green] Campaign {campaign_id} cancelled successfully[/green]")
            else:
                console.print(f"[red] Failed to cancel campaign {campaign_id}[/red]")

        except Exception as e:
            console.print(f"[red]Error cancelling campaign: {e}[/red]")

    asyncio.run(cancel())


@deploy_group.command('templates')
@click.option('--create', '-c', help='Create new deployment template')
@click.option('--list', '-l', is_flag=True, help='List available templates')
@click.pass_context
def deployment_templates(ctx, create, list):
    """Manage deployment configuration templates."""

    if list:
        _list_deployment_templates()
    elif create:
        _create_deployment_template(create)
    else:
        console.print("Use --list to see templates or --create <name> to create one")


def _display_campaign_summary(config: DeploymentConfig, content: Dict[str, Any], platforms: List[str]):
    """Display campaign deployment summary."""

    summary_panel = Panel.fit(
        f"""
[bold]Campaign:[/bold] {config.campaign_name}
[bold]Channels:[/bold] {', '.join([ch.value for ch in config.channels])}
[bold]Platforms:[/bold] {', '.join(platforms) if platforms else 'Core engine only'}
[bold]Targets:[/bold] {len(config.targets)}
[bold]Duration:[/bold] {config.duration_hours} hours
[bold]Test Mode:[/bold] {'Yes' if config.test_mode else 'No'}
[bold]Compliance:[/bold] {'Approved' if config.compliance_approved else 'Not approved'}
        """.strip(),
        title="Campaign Summary",
        border_style="blue"
    )

    console.print(summary_panel)


def _display_deployment_results(campaign_id: str, results: List, platform_results: Dict[str, Any]):
    """Display deployment results."""

    console.print(f"\n[bold green]Campaign {campaign_id} deployed successfully![/bold green]")

    # Core deployment results
    if results:
        table = Table(title="Core Deployment Results", show_header=True)
        table.add_column("Channel", style="cyan")
        table.add_column("Status", style="bold")
        table.add_column("Targets", justify="right")
        table.add_column("Success Rate", justify="right")
        table.add_column("Duration", justify="right")

        for result in results:
            success_rate = f"{(result.targets_successful / result.targets_attempted) * 100:.1f}%" if result.targets_attempted > 0 else "0%"
            duration_str = f"{result.deployment_duration_seconds:.1f}s"

            table.add_row(
                result.channel.value,
                result.status,
                f"{result.targets_successful}/{result.targets_attempted}",
                success_rate,
                duration_str
            )

        console.print(table)

    # Platform deployment results
    if platform_results:
        platform_table = Table(title="Platform Deployment Results", show_header=True)
        platform_table.add_column("Platform", style="cyan")
        platform_table.add_column("Status", style="bold")
        platform_table.add_column("Details")

        for platform, result in platform_results.items():
            if result:
                status = "[green] Success[/green]"
                details = f"Deployed to {result.targets_successful} targets"
            else:
                status = "[red] Failed[/red]"
                details = "Check logs for details"

            platform_table.add_row(platform, status, details)

        console.print(platform_table)


def _display_campaign_status(status: Dict[str, Any], platform_metrics: Dict[str, Any], detailed: bool):
    """Display campaign status and metrics."""

    campaign_id = status.get('campaign_id', 'Unknown')
    metrics = status.get('metrics', {})
    dashboard = status.get('dashboard', {})

    # Main status panel
    status_panel = Panel.fit(
        f"""
[bold]Campaign ID:[/bold] {campaign_id}
[bold]Status:[/bold] {status.get('status', 'Unknown')}
[bold]Active Since:[/bold] {dashboard.get('active_since', 'Unknown')}
        """.strip(),
        title="Campaign Status",
        border_style="green"
    )

    console.print(status_panel)

    # Engagement metrics
    engagement = dashboard.get('engagement_metrics', {})
    if engagement:
        table = Table(title="Engagement Metrics", show_header=True)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", justify="right", style="bold")

        table.add_row("Emails Sent", str(engagement.get('emails_sent', 0)))
        table.add_row("Emails Opened", str(engagement.get('emails_opened', 0)))
        table.add_row("Links Clicked", str(engagement.get('links_clicked', 0)))
        table.add_row("Credentials Submitted", str(engagement.get('credentials_submitted', 0)))
        table.add_row("Engagement Rate", f"{engagement.get('engagement_rate', 0):.1%}")

        console.print(table)

    # Platform-specific metrics
    if platform_metrics and detailed:
        for platform, metrics in platform_metrics.items():
            platform_panel = Panel.fit(
                f"""
[bold]Emails Sent:[/bold] {metrics.emails_sent}
[bold]Opened:[/bold] {metrics.emails_opened}
[bold]Clicked:[/bold] {metrics.links_clicked}
[bold]Success Rate:[/bold] {metrics.calculate_success_rate():.1%}
                """.strip(),
                title=f"{platform.title()} Metrics",
                border_style="yellow"
            )
            console.print(platform_panel)


async def _monitor_campaign(engine, campaign_id: str, platform_manager, platforms: List[str], refresh_interval: int = 5):
    """Real-time campaign monitoring with live dashboard."""

    def create_dashboard() -> Layout:
        """Create the monitoring dashboard layout."""

        layout = Layout()

        layout.split(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=3)
        )

        layout["main"].split_row(
            Layout(name="metrics"),
            Layout(name="platforms")
        )

        return layout

    def update_dashboard(layout: Layout, status: Dict[str, Any], platform_metrics: Dict[str, Any]):
        """Update dashboard with latest data."""

        # Header
        layout["header"].update(
            Panel(
                f"[bold]Campaign Monitor - {campaign_id}[/bold] | Last Updated: {datetime.now().strftime('%H:%M:%S')}",
                style="bold blue"
            )
        )

        # Main metrics
        dashboard = status.get('dashboard', {})
        engagement = dashboard.get('engagement_metrics', {})

        metrics_table = Table(title="Live Metrics", show_header=True)
        metrics_table.add_column("Metric", style="cyan")
        metrics_table.add_column("Value", justify="right", style="bold")
        metrics_table.add_column("Change", justify="right")

        metrics_table.add_row("Emails Sent", str(engagement.get('emails_sent', 0)), "[green]+5[/green]")
        metrics_table.add_row("Opened", str(engagement.get('emails_opened', 0)), "[green]+2[/green]")
        metrics_table.add_row("Clicked", str(engagement.get('links_clicked', 0)), "[yellow]+1[/yellow]")
        metrics_table.add_row("Engagement Rate", f"{engagement.get('engagement_rate', 0):.1%}", "")

        layout["metrics"].update(Panel(metrics_table, title="Core Metrics"))

        # Platform metrics
        if platform_metrics:
            platform_table = Table(title="Platform Status", show_header=True)
            platform_table.add_column("Platform", style="cyan")
            platform_table.add_column("Status", style="bold")
            platform_table.add_column("Engagement", justify="right")

            for platform, metrics in platform_metrics.items():
                status_indicator = "[green]Active[/green]"
                engagement_rate = f"{metrics.calculate_engagement_rate():.1%}"

                platform_table.add_row(platform, status_indicator, engagement_rate)

            layout["platforms"].update(Panel(platform_table, title="Platform Status"))

        # Footer
        layout["footer"].update(
            Panel(
                "[dim]Press Ctrl+C to exit monitoring[/dim]",
                style="dim"
            )
        )

    # Initialize dashboard
    layout = create_dashboard()

    try:
        with Live(layout, refresh_per_second=1) as live:
            while True:
                # Get latest status
                status = await engine.get_campaign_status(campaign_id)

                # Get platform metrics
                platform_metrics = {}
                if platforms:
                    platform_metrics = await platform_manager.get_all_campaign_metrics(campaign_id)

                # Update dashboard
                update_dashboard(layout, status, platform_metrics)

                # Wait for next refresh
                await asyncio.sleep(refresh_interval)

    except KeyboardInterrupt:
        console.print("\n[yellow]Monitoring stopped[/yellow]")


def _list_deployment_templates():
    """List available deployment templates."""

    # Mock template data - in production, load from templates directory
    templates = [
        {
            "name": "phishing_email_basic",
            "description": "Basic phishing email campaign",
            "channels": ["email"],
            "duration_hours": 24
        },
        {
            "name": "multi_channel_social_engineering",
            "description": "Multi-channel social engineering campaign",
            "channels": ["email", "sms", "social_media"],
            "duration_hours": 48
        },
        {
            "name": "executive_spear_phishing",
            "description": "Targeted executive spear phishing",
            "channels": ["email"],
            "duration_hours": 12
        }
    ]

    table = Table(title="Deployment Templates", show_header=True)
    table.add_column("Name", style="cyan")
    table.add_column("Description")
    table.add_column("Channels")
    table.add_column("Duration", justify="right")

    for template in templates:
        table.add_row(
            template["name"],
            template["description"],
            ", ".join(template["channels"]),
            f"{template['duration_hours']}h"
        )

    console.print(table)


def _create_deployment_template(name: str):
    """Create a new deployment template."""

    console.print(f"[yellow]Creating deployment template: {name}[/yellow]")
    console.print("[dim]Template creation wizard coming soon...[/dim]")

    # Interactive template wizard pending


if __name__ == '__main__':
    deploy_group()
