"""CLI commands for Field Manual generation."""

import click
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from typing import Optional, List

console = Console()


@click.group(name="manuals")
def manuals_group():
    """Generate comprehensive security field manuals.

    Create AI-enhanced operational manuals for all security teams:
    - Blue Team (Defense & Detection)
    - Red Team (Offensive Security)
    - Purple Team (Collaborative Testing)
    - SOC (Security Operations)
    - Threat Intelligence
    - GRC (Governance, Risk, Compliance)
    - Incident Response
    - Security Awareness
    """
    pass


@manuals_group.command()
@click.option(
    "--team", "-t",
    type=click.Choice([
        "blue_team", "red_team", "purple_team", "soc",
        "threat_intel", "grc", "incident_response", "security_awareness",
        "all"
    ]),
    required=True,
    help="Target security team (or 'all' for all teams)"
)
@click.option(
    "--threat-type", "-tt",
    type=click.Choice([
        "phishing", "spear_phishing", "business_email_compromise",
        "vishing", "smishing", "social_engineering"
    ]),
    default="spear_phishing",
    help="Type of threat scenario"
)
@click.option(
    "--scenario", "-s",
    default="Advanced Threat Scenario",
    help="Name of the threat scenario"
)
@click.option(
    "--industry", "-i",
    type=click.Choice([
        "general", "financial", "healthcare", "technology",
        "government", "retail", "manufacturing", "energy"
    ]),
    default="general",
    help="Target industry context"
)
@click.option(
    "--org-size", "-o",
    type=click.Choice(["startup", "smb", "enterprise", "government"]),
    default="enterprise",
    help="Organization size context"
)
@click.option(
    "--difficulty", "-d",
    type=click.IntRange(1, 10),
    default=7,
    help="Threat difficulty level (1-10)"
)
@click.option(
    "--compliance", "-c",
    multiple=True,
    type=click.Choice([
        "NIST", "ISO27001", "SOC2", "PCI-DSS", "HIPAA", "GDPR", "CMMC"
    ]),
    help="Applicable compliance frameworks (can specify multiple)"
)
@click.option(
    "--mitre", "-m",
    multiple=True,
    help="MITRE ATT&CK technique IDs (can specify multiple)"
)
@click.option(
    "--output-dir",
    type=click.Path(),
    default="generated_content/field_manuals",
    help="Output directory for generated manuals"
)
@click.option(
    "--ai-enhanced/--rule-based",
    default=True,
    help="Use AI enhancement (requires configured LLM provider)"
)
def generate(
    team: str,
    threat_type: str,
    scenario: str,
    industry: str,
    org_size: str,
    difficulty: int,
    compliance: tuple,
    mitre: tuple,
    output_dir: str,
    ai_enhanced: bool,
):
    """Generate comprehensive field manual(s) for security teams.

    Examples:

    \b
    # Generate Blue Team manual for spear-phishing
    threatsimgpt manuals generate --team blue_team --threat-type spear_phishing

    \b
    # Generate all team manuals for healthcare industry
    threatsimgpt manuals generate --team all --industry healthcare --compliance HIPAA

    \b
    # Generate Red Team manual with specific MITRE techniques
    threatsimgpt manuals generate --team red_team -m T1566.001 -m T1566.002
    """
    from threatsimgpt.core.ai_enhanced_playbooks import (
        AIEnhancedPlaybookGenerator,
        PlaybookContext,
        PlaybookQuality,
        TEAM_PROMPTS,
    )

    # Default MITRE techniques if not specified
    mitre_techniques = list(mitre) if mitre else _get_default_mitre(threat_type)
    compliance_list = list(compliance) if compliance else []

    # Create context
    context = PlaybookContext(
        scenario_name=scenario,
        threat_type=threat_type,
        mitre_techniques=mitre_techniques,
        difficulty_level=difficulty,
        industry=industry,
        organization_size=org_size,
        compliance_frameworks=compliance_list,
    )

    # Show configuration
    console.print(Panel.fit(
        f"[bold cyan]Field Manual Generation[/bold cyan]\n\n"
        f"Team: [green]{team}[/green]\n"
        f"Threat Type: [yellow]{threat_type}[/yellow]\n"
        f"Scenario: {scenario}\n"
        f"Industry: {industry}\n"
        f"Organization Size: {org_size}\n"
        f"Difficulty: {difficulty}/10\n"
        f"MITRE Techniques: {', '.join(mitre_techniques)}\n"
        f"Compliance: {', '.join(compliance_list) if compliance_list else 'General'}\n"
        f"AI Enhanced: {'Yes' if ai_enhanced else 'No (Rule-based)'}"
    ))

    # Initialize generator
    generator = AIEnhancedPlaybookGenerator()
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Determine teams to generate
    teams_to_generate = list(TEAM_PROMPTS.keys()) if team == "all" else [team]

    quality = PlaybookQuality.COMPREHENSIVE if ai_enhanced else PlaybookQuality.BASIC

    generated_files = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(
            f"Generating {len(teams_to_generate)} field manual(s)...",
            total=len(teams_to_generate)
        )

        for team_name in teams_to_generate:
            progress.update(task, description=f"Generating {team_name} manual...")

            try:
                # Generate the manual
                manual_content = generator.generate_field_manual_sync(
                    team=team_name,
                    context=context,
                    quality=quality,
                )

                # Save to file
                filename = f"{team_name}_{threat_type}_field_manual.md"
                file_path = output_path / team_name / filename
                file_path.parent.mkdir(parents=True, exist_ok=True)
                file_path.write_text(manual_content)

                generated_files.append((team_name, file_path, len(manual_content)))

            except Exception as e:
                console.print(f"[red]Error generating {team_name} manual: {e}[/red]")

            progress.advance(task)

    # Show results
    if generated_files:
        console.print("\n[bold green]✓ Field Manuals Generated Successfully![/bold green]\n")

        results_table = Table(title="Generated Files")
        results_table.add_column("Team", style="cyan")
        results_table.add_column("File Path", style="white")
        results_table.add_column("Size", style="green")

        for team_name, file_path, size in generated_files:
            results_table.add_row(
                team_name.replace("_", " ").title(),
                str(file_path),
                f"{size:,} chars"
            )

        console.print(results_table)

        console.print(f"\n[dim]Manuals saved to: {output_path.absolute()}[/dim]")
    else:
        console.print("[red]No manuals were generated.[/red]")


@manuals_group.command()
def list_teams():
    """List available security teams for manual generation."""
    from threatsimgpt.core.ai_enhanced_playbooks import TEAM_PROMPTS

    console.print("\n[bold cyan]Available Security Teams[/bold cyan]\n")

    team_info = {
        "blue_team": ("[BLUE]", "Blue Team", "Defense, detection, monitoring, hardening"),
        "red_team": ("[RED]", "Red Team", "Offensive security, penetration testing, adversary emulation"),
        "purple_team": ("[PURPLE]", "Purple Team", "Collaborative testing, gap analysis, detection validation"),
        "soc": ("[SOC]", "SOC", "Security operations, alert triage, incident handling"),
        "threat_intel": ("[INTEL]", "Threat Intel", "Threat analysis, IOC management, intelligence products"),
        "grc": ("[GRC]", "GRC", "Governance, risk assessment, compliance mapping"),
        "incident_response": ("[IR]", "Incident Response", "IR procedures, forensics, recovery"),
        "security_awareness": ("[AWARE]", "Security Awareness", "Training programs, phishing simulations, awareness"),
    }

    table = Table(title="Security Teams")
    table.add_column("", style="white", width=8)
    table.add_column("Team ID", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Focus Areas", style="white")

    for team_id, (label, name, focus) in team_info.items():
        table.add_row(label, team_id, name, focus)

    console.print(table)

    console.print("\n[dim]Use 'threatsimgpt manuals generate --team <team_id>' to generate a manual[/dim]")


@manuals_group.command()
@click.option("--team", "-t", help="Filter by specific team")
def status(team: Optional[str]):
    """Show status of generated manuals and knowledge base."""
    from threatsimgpt.core.ai_enhanced_playbooks import ai_playbook_generator, TEAM_PROMPTS
    import json

    console.print("\n[bold cyan]Field Manual System Status[/bold cyan]\n")

    # Check for generated manuals
    manuals_dir = Path("generated_content/field_manuals")
    kb_dir = Path("generated_content/knowledge_base")

    teams = [team] if team else list(TEAM_PROMPTS.keys())

    table = Table(title="Manual Generation Status")
    table.add_column("Team", style="cyan")
    table.add_column("Manuals", style="green")
    table.add_column("KB Entries", style="yellow")
    table.add_column("Last Updated", style="white")
    table.add_column("Suggestions", style="dim")

    for team_name in teams:
        # Count manuals
        team_dir = manuals_dir / team_name
        manual_count = len(list(team_dir.glob("*.md"))) if team_dir.exists() else 0

        # Check knowledge base
        kb_file = kb_dir / f"{team_name}_knowledge.json"
        kb_entries = 0
        last_updated = "Never"

        if kb_file.exists():
            try:
                kb = json.loads(kb_file.read_text())
                kb_entries = len(kb.get("entries", []))
                if kb.get("last_updated"):
                    last_updated = kb["last_updated"][:10]
            except:
                pass

        # Get suggestions count
        suggestions = ai_playbook_generator.get_improvement_suggestions(team_name)
        suggestions_count = len(suggestions)

        table.add_row(
            team_name.replace("_", " ").title(),
            str(manual_count),
            str(kb_entries),
            last_updated,
            f"{suggestions_count} available"
        )

    console.print(table)

    # Show improvement suggestions if specific team
    if team:
        suggestions = ai_playbook_generator.get_improvement_suggestions(team)
        if suggestions:
            console.print(f"\n[bold]Improvement Suggestions for {team}:[/bold]")
            for i, suggestion in enumerate(suggestions, 1):
                console.print(f"  {i}. {suggestion}")


@manuals_group.command()
@click.argument("team")
def suggestions(team: str):
    """Show improvement suggestions for a team's playbooks."""
    from threatsimgpt.core.ai_enhanced_playbooks import ai_playbook_generator, TEAM_PROMPTS

    if team not in TEAM_PROMPTS:
        console.print(f"[red]Unknown team: {team}[/red]")
        console.print(f"[dim]Valid teams: {', '.join(TEAM_PROMPTS.keys())}[/dim]")
        return

    suggestions = ai_playbook_generator.get_improvement_suggestions(team)

    console.print(f"\n[bold cyan]Improvement Suggestions: {team.replace('_', ' ').title()}[/bold cyan]\n")

    if suggestions:
        for i, suggestion in enumerate(suggestions, 1):
            console.print(f"  [green]{i}.[/green] {suggestion}")
    else:
        console.print("[dim]No suggestions available. Run more simulations to gather insights.[/dim]")


def _get_default_mitre(threat_type: str) -> List[str]:
    """Get default MITRE techniques for a threat type."""
    defaults = {
        "phishing": ["T1566.001", "T1566.002"],
        "spear_phishing": ["T1566.001", "T1566.002", "T1598"],
        "business_email_compromise": ["T1566.002", "T1534"],
        "vishing": ["T1598.001"],
        "smishing": ["T1566.002"],
        "social_engineering": ["T1598", "T1566"],
    }
    return defaults.get(threat_type, ["T1566"])
