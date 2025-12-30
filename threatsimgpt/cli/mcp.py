"""
MCP Server CLI Commands

CLI commands for the ThreatSimGPT VM MCP Server.
"""

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


@click.group()
def mcp_group():
    """MCP Server commands for AI-driven VM attack simulations.

    The MCP (Model Context Protocol) server provides tools for AI agents
    to control virtual machines for attack simulations.

    Examples:

        # Start the MCP server
        threatsimgpt mcp start

        # List available tools
        threatsimgpt mcp tools

        # Show server status
        threatsimgpt mcp status
    """
    pass


@mcp_group.command()
@click.option(
    "--config", "-c",
    help="Path to configuration file",
    type=click.Path(exists=True)
)
@click.option(
    "--log-level", "-l",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    default="INFO",
    help="Logging level"
)
@click.option(
    "--host",
    help="Proxmox host (overrides config/env)",
)
@click.option(
    "--token",
    help="Proxmox API token secret (overrides config/env)",
    envvar="PROXMOX_TOKEN_VALUE"
)
def start(config, log_level, host, token):
    """Start the MCP server.

    The server communicates over stdio for MCP protocol.
    Typically launched by an AI client (Claude Desktop, etc.)

    Configuration can be provided via:
    - Configuration file (--config)
    - Environment variables (PROXMOX_HOST, PROXMOX_TOKEN_VALUE, etc.)
    - Command line options
    """
    import asyncio
    import os

    console.print(Panel.fit(
        "[bold green]ThreatSimGPT VM MCP Server[/bold green]\n"
        "Starting Model Context Protocol server...",
        title="MCP Server"
    ))

    # Override environment if provided
    if host:
        os.environ["PROXMOX_HOST"] = host
    if token:
        os.environ["PROXMOX_TOKEN_VALUE"] = token

    try:
        from threatsimgpt.mcp import run_server
        asyncio.run(run_server(
            config_path=config,
            log_level=log_level
        ))
    except ImportError as e:
        console.print("[red]Error: MCP dependencies not installed[/red]")
        console.print("Install with: pip install mcp asyncssh aiohttp")
        raise click.Abort()
    except Exception as e:
        console.print(f"[red]Server error: {e}[/red]")
        raise click.Abort()


@mcp_group.command()
def tools():
    """List all available MCP tools.

    Shows the tools that the MCP server provides to AI agents.
    """
    try:
        from threatsimgpt.mcp.tools import ALL_TOOLS
    except ImportError:
        console.print("[red]MCP module not available[/red]")
        return

    # Group tools by category
    categories = {
        "vm_lifecycle": [],
        "vm_execute": [],
        "vm_snapshot": [],
        "computer_use": [],
        "attack_tools": [],
    }

    for tool in ALL_TOOLS:
        name = tool.name
        if name.startswith("vm_snapshot"):
            categories["vm_snapshot"].append(tool)
        elif name.startswith("vm_") and "execute" in name or "script" in name:
            categories["vm_execute"].append(tool)
        elif name.startswith("vm_mouse") or name.startswith("vm_keyboard") or name.startswith("vm_screenshot") or name.startswith("vm_wait"):
            categories["computer_use"].append(tool)
        elif name.startswith("vm_"):
            categories["vm_lifecycle"].append(tool)
        elif name.startswith("attack_"):
            categories["attack_tools"].append(tool)
        else:
            categories["vm_lifecycle"].append(tool)

    console.print(Panel.fit(
        f"[bold]ThreatSimGPT MCP Server Tools[/bold]\n"
        f"Total: {len(ALL_TOOLS)} tools",
        title="MCP Tools"
    ))

    for category, cat_tools in categories.items():
        if not cat_tools:
            continue

        table = Table(title=f"\n[bold]{category.replace('_', ' ').title()}[/bold]")
        table.add_column("Tool", style="cyan")
        table.add_column("Description", style="white")

        for tool in cat_tools:
            # Truncate description to first line
            desc = tool.description.split("\n")[0][:80]
            table.add_row(tool.name, desc)

        console.print(table)


@mcp_group.command()
def status():
    """Show MCP server status and configuration.

    Displays current configuration and connectivity status.
    """
    import os

    table = Table(title="MCP Server Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    # Configuration from environment
    settings = [
        ("Server Name", os.getenv("THREATSIMGPT_SERVER_NAME", "threatsimgpt-vm")),
        ("Proxmox Host", os.getenv("PROXMOX_HOST", "not set")),
        ("Proxmox Port", os.getenv("PROXMOX_PORT", "8006")),
        ("Proxmox Node", os.getenv("PROXMOX_NODE", "pve")),
        ("Token ID", os.getenv("PROXMOX_TOKEN_ID", os.getenv("PROXMOX_USER", "not set") + "!" + os.getenv("PROXMOX_TOKEN_NAME", "automation"))),
        ("Token Secret", "***" if os.getenv("PROXMOX_TOKEN_VALUE") else "not set"),
    ]

    for name, value in settings:
        table.add_row(name, str(value))

    console.print(table)

    # Check dependencies
    console.print("\n[bold]Dependencies:[/bold]")
    deps = [
        ("mcp", "MCP SDK"),
        ("asyncssh", "SSH client"),
        ("aiohttp", "HTTP client"),
    ]

    for module, desc in deps:
        try:
            __import__(module)
            console.print(f"  [green]✓[/green] {desc} ({module})")
        except ImportError:
            console.print(f"  [red]✗[/red] {desc} ({module}) - not installed")


@mcp_group.command()
@click.argument("tool_name")
def describe(tool_name):
    """Show detailed information about a specific tool.

    TOOL_NAME is the name of the tool to describe (e.g., vm_create, attack_nmap_scan)
    """
    import json

    try:
        from threatsimgpt.mcp.tools import ALL_TOOLS
    except ImportError:
        console.print("[red]MCP module not available[/red]")
        return

    # Find the tool
    tool = None
    for t in ALL_TOOLS:
        if t.name == tool_name:
            tool = t
            break

    if tool is None:
        console.print(f"[red]Tool not found: {tool_name}[/red]")
        console.print("\nAvailable tools:")
        for t in ALL_TOOLS:
            console.print(f"  - {t.name}")
        return

    console.print(Panel.fit(
        f"[bold cyan]{tool.name}[/bold cyan]",
        title="Tool Details"
    ))

    console.print("\n[bold]Description:[/bold]")
    console.print(tool.description)

    console.print("\n[bold]Input Schema:[/bold]")
    console.print_json(json.dumps(tool.inputSchema, indent=2))


@mcp_group.command()
@click.option("--output", "-o", type=click.Path(), help="Output file path")
def export_schema(output):
    """Export MCP tool schemas as JSON.

    Exports all tool definitions for documentation or client configuration.
    """
    import json

    try:
        from threatsimgpt.mcp.tools import ALL_TOOLS
    except ImportError:
        console.print("[red]MCP module not available[/red]")
        return

    schema = {
        "name": "threatsimgpt-vm",
        "version": "0.1.0",
        "description": "ThreatSimGPT VM MCP Server - AI-driven attack simulations",
        "tools": []
    }

    for tool in ALL_TOOLS:
        schema["tools"].append({
            "name": tool.name,
            "description": tool.description,
            "inputSchema": tool.inputSchema
        })

    if output:
        with open(output, "w") as f:
            json.dump(schema, f, indent=2)
        console.print(f"[green]Schema exported to {output}[/green]")
    else:
        console.print_json(json.dumps(schema, indent=2))
