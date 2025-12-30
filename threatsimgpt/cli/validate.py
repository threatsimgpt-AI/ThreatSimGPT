"""CLI commands for playbook validation.

This module provides commands to validate field manuals and playbooks
against industry standards, compliance frameworks, and quality metrics.
"""

import click
from pathlib import Path
from typing import Optional, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.markdown import Markdown
import json

from threatsimgpt.core.playbook_validator import (
    PlaybookValidator,
    ValidationReport,
    ComplianceFramework,
    ValidationSeverity,
    ValidationCategory,
    get_validation_summary,
)

console = Console()


# Available compliance frameworks
FRAMEWORK_CHOICES = [
    "nist-csf", "nist-800-53", "iso-27001", "soc2",
    "pci-dss", "hipaa", "gdpr", "mitre", "cis"
]


def get_framework_enum(name: str) -> Optional[ComplianceFramework]:
    """Convert framework name to enum."""
    mapping = {
        "nist-csf": ComplianceFramework.NIST_CSF,
        "nist-800-53": ComplianceFramework.NIST_800_53,
        "iso-27001": ComplianceFramework.ISO_27001,
        "soc2": ComplianceFramework.SOC2,
        "pci-dss": ComplianceFramework.PCI_DSS,
        "hipaa": ComplianceFramework.HIPAA,
        "gdpr": ComplianceFramework.GDPR,
        "mitre": ComplianceFramework.MITRE_ATTACK,
        "cis": ComplianceFramework.CIS_CONTROLS,
    }
    return mapping.get(name.lower())


@click.group(name="validate")
def validate_cli():
    """Validate playbooks against industry standards and quality metrics.

    The validation system checks playbooks for:

    \b
    • Structure and organization
    • Content quality and actionability
    • Industry standards alignment (MITRE ATT&CK, NIST)
    • Compliance framework coverage (SOC2, PCI-DSS, HIPAA, GDPR)
    • Technical accuracy (detection rules, IOCs, commands)
    • Real-world usefulness and applicability
    """
    pass


@validate_cli.command(name="playbook")
@click.argument("file_path", type=click.Path(exists=True))
@click.option(
    "--framework", "-f",
    multiple=True,
    type=click.Choice(FRAMEWORK_CHOICES, case_sensitive=False),
    help="Compliance framework to validate against (can specify multiple)"
)
@click.option(
    "--team", "-t",
    type=click.Choice([
        "blue_team", "red_team", "purple_team", "soc",
        "threat_intel", "grc", "incident_response", "security_awareness"
    ]),
    help="Team type for context-aware validation"
)
@click.option(
    "--strict", is_flag=True,
    help="Enable strict validation mode with additional checks"
)
@click.option(
    "--output", "-o",
    type=click.Choice(["console", "json", "markdown"]),
    default="console",
    help="Output format for the report"
)
@click.option(
    "--save-report", "-s",
    type=click.Path(),
    help="Save report to file"
)
def validate_playbook_cmd(
    file_path: str,
    framework: tuple,
    team: Optional[str],
    strict: bool,
    output: str,
    save_report: Optional[str],
):
    """Validate a single playbook file.

    FILE_PATH is the path to the markdown playbook file to validate.

    Examples:

    \b
        # Basic validation
        threatsimgpt validate playbook path/to/playbook.md

    \b
        # Validate against specific frameworks
        threatsimgpt validate playbook playbook.md -f soc2 -f hipaa

    \b
        # Export as markdown report
        threatsimgpt validate playbook playbook.md -o markdown -s report.md
    """
    # Parse frameworks
    frameworks = [get_framework_enum(f) for f in framework if get_framework_enum(f)]

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task("Validating playbook...", total=None)

        # Create validator
        validator = PlaybookValidator(
            compliance_frameworks=frameworks or None,
            strict_mode=strict,
        )

        # Read and validate
        file_path_obj = Path(file_path)
        content = file_path_obj.read_text()

        # Determine team from path if not specified
        if not team:
            for team_name in ["blue_team", "red_team", "purple_team", "soc",
                            "threat_intel", "grc", "incident_response", "security_awareness"]:
                if team_name in str(file_path_obj).lower():
                    team = team_name
                    break
            if not team:
                team = "unknown"

        report = validator.validate(content, team, str(file_path_obj))

    # Output report
    if output == "console":
        _display_console_report(report)
    elif output == "json":
        json_output = json.dumps(report.to_dict(), indent=2)
        console.print(json_output)
        if save_report:
            Path(save_report).write_text(json_output)
    elif output == "markdown":
        md_output = report.to_markdown()
        console.print(Markdown(md_output))
        if save_report:
            Path(save_report).write_text(md_output)

    if save_report and output == "console":
        # Save as markdown by default for console output
        Path(save_report).write_text(report.to_markdown())
        console.print(f"\n📄 Report saved to: {save_report}")

    # Exit with non-zero if not production ready
    if not report.is_production_ready:
        raise SystemExit(1)


@validate_cli.command(name="all")
@click.option(
    "--directory", "-d",
    type=click.Path(exists=True),
    default="generated_content/field_manuals",
    help="Directory containing playbooks to validate"
)
@click.option(
    "--framework", "-f",
    multiple=True,
    type=click.Choice(FRAMEWORK_CHOICES, case_sensitive=False),
    help="Compliance framework to validate against"
)
@click.option(
    "--min-score",
    type=int,
    default=70,
    help="Minimum score to pass validation (0-100)"
)
@click.option(
    "--output", "-o",
    type=click.Choice(["summary", "detailed", "json"]),
    default="summary",
    help="Output format"
)
@click.option(
    "--save-report", "-s",
    type=click.Path(),
    help="Save summary report to file"
)
def validate_all_cmd(
    directory: str,
    framework: tuple,
    min_score: int,
    output: str,
    save_report: Optional[str],
):
    """Validate all playbooks in a directory.

    Scans the specified directory for markdown files and validates each one.

    Examples:

    \b
        # Validate all playbooks in default directory
        threatsimgpt validate all

    \b
        # Validate with minimum score requirement
        threatsimgpt validate all --min-score 80

    \b
        # Validate custom directory
        threatsimgpt validate all -d ./my_playbooks -f soc2
    """
    # Parse frameworks
    frameworks = [get_framework_enum(f) for f in framework if get_framework_enum(f)]

    dir_path = Path(directory)
    if not dir_path.exists():
        console.print(f"[red]Directory not found: {directory}[/red]")
        raise SystemExit(1)

    # Find all markdown files
    md_files = list(dir_path.rglob("*.md"))

    if not md_files:
        console.print(f"[yellow]No markdown files found in {directory}[/yellow]")
        return

    reports: List[ValidationReport] = []

    console.print(Panel(f"Validating {len(md_files)} playbooks in {directory}"))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating...", total=len(md_files))

        validator = PlaybookValidator(
            compliance_frameworks=frameworks or None,
        )

        for md_file in md_files:
            progress.update(task, description=f"Validating {md_file.name}...")
            try:
                report = validator.validate_file(str(md_file))
                reports.append(report)
            except Exception as e:
                console.print(f"[yellow]Error validating {md_file.name}: {e}[/yellow]")
            progress.advance(task)

    if not reports:
        console.print("[yellow]No playbooks could be validated[/yellow]")
        return

    # Generate summary
    summary = get_validation_summary(reports)

    if output == "json":
        json_output = json.dumps({
            "summary": summary,
            "reports": [r.to_dict() for r in reports]
        }, indent=2)
        console.print(json_output)
        if save_report:
            Path(save_report).write_text(json_output)
    else:
        _display_summary_report(reports, summary, min_score, detailed=(output == "detailed"))

        if save_report:
            # Save detailed markdown report
            md_lines = [
                "# Playbook Validation Summary Report",
                "",
                f"**Total Playbooks**: {summary['total_playbooks']}",
                f"**Average Score**: {summary['average_score']}/100",
                f"**Production Ready**: {summary['production_ready']}/{summary['total_playbooks']} ({summary['production_ready_percentage']}%)",
                "",
                "## Individual Reports",
                "",
            ]
            for report in reports:
                md_lines.append(report.to_markdown())
                md_lines.append("\n---\n")

            Path(save_report).write_text("\n".join(md_lines))
            console.print(f"\nReport saved to: {save_report}")

    # Exit with non-zero if any playbook fails minimum score
    failed = [r for r in reports if r.overall_score < min_score]
    if failed:
        console.print(f"\n[red][FAIL] {len(failed)} playbook(s) below minimum score of {min_score}[/red]")
        raise SystemExit(1)


@validate_cli.command(name="frameworks")
def list_frameworks_cmd():
    """List available compliance frameworks.

    Shows all compliance frameworks that can be used for validation.
    """
    table = Table(title="Available Compliance Frameworks")
    table.add_column("ID", style="cyan")
    table.add_column("Framework", style="green")
    table.add_column("Description")

    frameworks_info = [
        ("nist-csf", "NIST Cybersecurity Framework", "Risk-based approach to managing cybersecurity risk"),
        ("nist-800-53", "NIST SP 800-53", "Security and privacy controls for federal systems"),
        ("iso-27001", "ISO 27001", "Information security management system standard"),
        ("soc2", "SOC 2", "Service organization controls for trust services"),
        ("pci-dss", "PCI DSS", "Payment card industry data security standard"),
        ("hipaa", "HIPAA", "Healthcare data privacy and security"),
        ("gdpr", "GDPR", "EU general data protection regulation"),
        ("mitre", "MITRE ATT&CK", "Adversary tactics, techniques, and procedures"),
        ("cis", "CIS Controls", "Center for Internet Security critical controls"),
    ]

    for fid, name, desc in frameworks_info:
        table.add_row(fid, name, desc)

    console.print(table)
    console.print("\n[dim]Use with: threatsimgpt validate playbook file.md -f <framework-id>[/dim]")


@validate_cli.command(name="report")
@click.argument("file_path", type=click.Path(exists=True))
@click.option(
    "--format", "-f",
    type=click.Choice(["markdown", "html", "pdf"]),
    default="markdown",
    help="Report format"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file path"
)
def generate_report_cmd(
    file_path: str,
    format: str,
    output: Optional[str],
):
    """Generate a detailed validation report for a playbook.

    Creates a comprehensive report that can be shared with stakeholders.

    Examples:

    \b
        # Generate markdown report
        threatsimgpt validate report playbook.md -o report.md

    \b
        # Generate to stdout
        threatsimgpt validate report playbook.md
    """
    validator = PlaybookValidator()
    report = validator.validate_file(file_path)

    if format == "markdown":
        md_output = report.to_markdown()
        if output:
            Path(output).write_text(md_output)
            console.print(f"[OK] Report saved to: {output}")
        else:
            console.print(Markdown(md_output))
    elif format == "html":
        # Basic HTML conversion
        md_output = report.to_markdown()
        html_output = f"""<!DOCTYPE html>
<html>
<head>
    <title>Playbook Validation Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        .critical {{ color: red; font-weight: bold; }}
        .high {{ color: orange; }}
        .medium {{ color: #DAA520; }}
        .low {{ color: blue; }}
    </style>
</head>
<body>
<pre>{md_output}</pre>
</body>
</html>"""
        if output:
            Path(output).write_text(html_output)
            console.print(f"[OK] Report saved to: {output}")
        else:
            console.print(html_output)
    else:
        console.print("[yellow]PDF format requires additional dependencies[/yellow]")


def _display_console_report(report: ValidationReport):
    """Display validation report in console format."""
    # Overall assessment panel
    grade_colors = {"A": "green", "B": "blue", "C": "yellow", "D": "orange", "F": "red"}
    grade_color = grade_colors.get(report.grade, "white")

    status = "[PRODUCTION READY]" if report.is_production_ready else "[NOT PRODUCTION READY]"
    status_color = "green" if report.is_production_ready else "red"

    console.print(Panel(
        f"""[bold]Overall Score:[/bold] {report.overall_score:.1f}/100
[bold]Grade:[/bold] [{grade_color}]{report.grade}[/{grade_color}]
[bold]Status:[/bold] [{status_color}]{status}[/{status_color}]
[bold]Team:[/bold] {report.playbook_team}
[bold]Findings:[/bold] {len(report.findings)}""",
        title="Validation Report",
        border_style="blue",
    ))

    # Category scores table
    table = Table(title="Category Scores")
    table.add_column("Category", style="cyan")
    table.add_column("Score", justify="right")
    table.add_column("Status", justify="center")

    for cat, score in report.category_scores.items():
        pct = score.percentage
        if pct >= 80:
            status = "[green][PASS][/green]"
        elif pct >= 60:
            status = "[yellow][WARN][/yellow]"
        else:
            status = "[red][FAIL][/red]"

        table.add_row(
            cat.value.replace("_", " ").title(),
            f"{pct:.0f}%",
            status
        )

    console.print(table)

    # Compliance status
    compliance_table = Table(title="Compliance Alignment")
    compliance_table.add_column("Framework", style="cyan")
    compliance_table.add_column("Status", justify="center")

    for framework, compliant in report.compliance_status.items():
        status = "[green][ALIGNED][/green]" if compliant else "[yellow][GAPS][/yellow]"
        compliance_table.add_row(framework.value, status)

    console.print(compliance_table)

    # Findings by severity
    if report.findings:
        console.print("\n[bold]Findings:[/bold]")

        for severity in [ValidationSeverity.CRITICAL, ValidationSeverity.HIGH,
                        ValidationSeverity.MEDIUM, ValidationSeverity.LOW]:
            findings = [f for f in report.findings if f.severity == severity]
            if findings:
                prefix = {
                    "critical": "[CRITICAL]", "high": "[HIGH]", "medium": "[MEDIUM]", "low": "[LOW]"
                }.get(severity.value, "-")
                color = {
                    "critical": "red", "high": "orange", "medium": "yellow", "low": "blue"
                }.get(severity.value, "white")

                console.print(f"\n[{color}]{prefix} {severity.value.upper()} ({len(findings)})[/{color}]")
                for f in findings[:5]:  # Show top 5 per severity
                    console.print(f"  - {f.title}")
                    console.print(f"    [dim]{f.description}[/dim]")

    # Top recommendations
    if report.recommendations:
        console.print("\n[bold]Top Recommendations:[/bold]")
        for i, rec in enumerate(report.recommendations[:5], 1):
            console.print(f"  {i}. {rec}")


def _display_summary_report(
    reports: List[ValidationReport],
    summary: dict,
    min_score: int,
    detailed: bool = False,
):
    """Display summary report for multiple playbooks."""
    # Summary panel
    console.print(Panel(
        f"""[bold]Total Playbooks:[/bold] {summary['total_playbooks']}
[bold]Average Score:[/bold] {summary['average_score']}/100
[bold]Production Ready:[/bold] {summary['production_ready']}/{summary['total_playbooks']} ({summary['production_ready_percentage']}%)
[bold]Total Findings:[/bold] {summary['total_findings']}
[bold]Critical Issues:[/bold] {summary['critical_findings']}""",
        title="Validation Summary",
        border_style="blue",
    ))

    # Grade distribution
    grade_table = Table(title="Grade Distribution")
    grade_table.add_column("Grade", style="cyan", justify="center")
    grade_table.add_column("Count", justify="right")

    for grade in ["A", "B", "C", "D", "F"]:
        count = summary['grade_distribution'].get(grade, 0)
        if count > 0:
            grade_table.add_row(grade, str(count))

    console.print(grade_table)

    # Individual playbook results
    results_table = Table(title="Playbook Results")
    results_table.add_column("Playbook", style="cyan")
    results_table.add_column("Team")
    results_table.add_column("Score", justify="right")
    results_table.add_column("Grade", justify="center")
    results_table.add_column("Status", justify="center")

    for report in sorted(reports, key=lambda r: r.overall_score, reverse=True):
        status = "[green][OK][/green]" if report.is_production_ready else "[red][X][/red]"
        score_color = "green" if report.overall_score >= min_score else "red"

        # Truncate path for display
        path_display = Path(report.playbook_path).name
        if len(path_display) > 40:
            path_display = "..." + path_display[-37:]

        results_table.add_row(
            path_display,
            report.playbook_team,
            f"[{score_color}]{report.overall_score:.0f}[/{score_color}]",
            report.grade,
            status
        )

    console.print(results_table)

    if detailed:
        # Show findings per playbook
        console.print("\n[bold]Detailed Findings:[/bold]")
        for report in reports:
            if report.findings:
                console.print(f"\n[cyan]{Path(report.playbook_path).name}[/cyan]")
                for f in report.findings[:3]:
                    console.print(f"  • [{f.severity.value}] {f.title}")


# Register with main CLI
def register_validate_cli(app):
    """Register validation CLI commands with the main app."""
    app.add_command(validate_cli)
