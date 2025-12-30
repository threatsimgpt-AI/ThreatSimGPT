"""Templates command for ThreatSimGPT CLI.

Comprehensive template management with YAML validation and detailed display.
"""

import click
from pathlib import Path
from typing import Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich.syntax import Syntax

from ..config.yaml_loader import YAMLConfigLoader, ConfigurationError, SchemaValidationError
from ..core.template_manager_pro import TemplateCreationWizard, TemplateManager


console = Console()


@click.group()
def templates():
    """Manage threat scenario templates with validation and detailed viewing."""
    pass


@templates.command(name="list-all")
@click.option('--validate', '-v', is_flag=True, help='Validate all templates against schema')
@click.option('--format', '-f', type=click.Choice(['table', 'tree', 'simple']), default='table', help='Output format')
def list_all(validate: bool, format: str):
    """List all available threat scenario templates."""
    templates_dir = Path(__file__).parent.parent.parent.parent / "templates"

    if not templates_dir.exists():
        console.print("[red]No templates directory found.[/red]")
        return

    yaml_files = list(templates_dir.glob("*.yaml")) + list(templates_dir.glob("*.yml"))

    if not yaml_files:
        console.print("[yellow]No template files found.[/yellow]")
        return

    loader = YAMLConfigLoader()

    if format == 'simple':
        _display_simple_list(yaml_files)
    elif format == 'tree':
        _display_tree_format(yaml_files, loader if validate else None)
    else:  # table format
        _display_table_format(yaml_files, loader if validate else None)


def _display_simple_list(yaml_files):
    """Display simple list of template files."""
    console.print(f"[bold cyan] Available Templates ({len(yaml_files)} found):[/bold cyan]")
    for template_file in sorted(yaml_files):
        console.print(f"  • {template_file.name}")


def _display_tree_format(yaml_files, loader=None):
    """Display templates in tree format with categories."""
    tree = Tree(" [bold cyan]Threat Scenario Templates[/bold cyan]")

    # Categorize templates
    categories = {
        'Email-Based': [],
        'Mobile & SMS': [],
        'Social Engineering': [],
        'Advanced Threats': [],
        'Other': []
    }

    for template_file in sorted(yaml_files):
        name = template_file.stem
        if 'phishing' in name or 'email' in name or 'bec' in name:
            categories['Email-Based'].append(template_file)
        elif 'sms' in name or 'smishing' in name or 'mobile' in name:
            categories['Mobile & SMS'].append(template_file)
        elif 'social' in name or 'helpdesk' in name or 'impersonation' in name:
            categories['Social Engineering'].append(template_file)
        elif 'supply' in name or 'apt' in name or 'compromise' in name:
            categories['Advanced Threats'].append(template_file)
        else:
            categories['Other'].append(template_file)

    for category, files in categories.items():
        if files:
            category_branch = tree.add(f" [bold]{category}[/bold]")
            for template_file in files:
                status = ""
                if loader:
                    try:
                        scenario = loader.load_and_validate_scenario(template_file)
                        threat_type_val = scenario.threat_type.value if hasattr(scenario.threat_type, 'value') else str(scenario.threat_type)
                        status = f" [green] Valid[/green] - {threat_type_val.replace('_', ' ').title()}"
                    except (ConfigurationError, SchemaValidationError):
                        status = " [red] Invalid[/red]"

                category_branch.add(f" {template_file.stem}{status}")

    console.print(tree)


def _display_table_format(yaml_files, loader=None):
    """Display templates in table format with details."""
    table = Table(title=" Threat Scenario Templates", show_header=True, header_style="bold magenta")

    table.add_column("Template", style="cyan", no_wrap=True)
    table.add_column("Threat Type", style="yellow")
    table.add_column("Difficulty", justify="center")
    table.add_column("Duration", justify="center")
    table.add_column("Status", justify="center")

    for template_file in sorted(yaml_files):
        name = template_file.stem
        threat_type = "Unknown"
        difficulty = "N/A"
        duration = "N/A"
        status = "[dim]Not Validated[/dim]"

        if loader:
            try:
                scenario = loader.load_and_validate_scenario(template_file)
                threat_type_val = scenario.threat_type.value if hasattr(scenario.threat_type, 'value') else str(scenario.threat_type)
                threat_type = threat_type_val.replace('_', ' ').title()
                difficulty_val = scenario.difficulty_level.value if hasattr(scenario.difficulty_level, 'value') else scenario.difficulty_level
                difficulty = f"{difficulty_val}/10"
                duration = f"{scenario.estimated_duration}m"
                status = "[green] Valid[/green]"
            except (ConfigurationError, SchemaValidationError) as e:
                status = "[red] Invalid[/red]"
                if hasattr(e, 'errors') and e.errors:
                    # Show first error briefly
                    first_error = e.errors[0]
                    status += f"\n[dim]{first_error.get('location', 'Unknown')}: {first_error.get('message', 'Error')[:40]}...[/dim]"

        table.add_row(name, threat_type, difficulty, duration, status)

    console.print(table)


@templates.command()
@click.argument('template_name')
@click.option('--validate', '-v', is_flag=True, help='Validate template against schema')
@click.option('--show-yaml', '-y', is_flag=True, help='Show raw YAML content')
def show(template_name: str, validate: bool, show_yaml: bool):
    """Show detailed information about a specific template."""
    templates_dir = Path(__file__).parent.parent.parent.parent / "templates"

    # Find template file (with or without extension)
    template_file = None
    for ext in ['.yaml', '.yml', '']:
        potential_path = templates_dir / f"{template_name}{ext}"
        if potential_path.exists():
            template_file = potential_path
            break

    if not template_file:
        console.print(f"[red] Template '{template_name}' not found.[/red]")
        return

    loader = YAMLConfigLoader()

    try:
        # Load and optionally validate
        config = loader.load_config(template_file)
        scenario = None

        if validate:
            scenario = loader.validate_threat_scenario(config)
            console.print("[green] Template validation successful![/green]\n")

        # Display template information
        _display_template_details(config, scenario, template_file)

        # Show raw YAML if requested
        if show_yaml:
            _display_yaml_content(template_file)

    except ConfigurationError as e:
        console.print(f"[red] Configuration Error:[/red] {e}")
    except SchemaValidationError as e:
        console.print(f"[red] Validation Error:[/red] {e}")
        if e.errors:
            console.print("\n[bold red]Validation Errors:[/bold red]")
            for error in e.errors[:5]:  # Show first 5 errors
                console.print(f"  • [red]{error['location']}:[/red] {error['message']}")
            if len(e.errors) > 5:
                console.print(f"  ... and {len(e.errors) - 5} more errors")


def _display_template_details(config: Dict[str, Any], scenario=None, template_file=None):
    """Display detailed template information."""
    metadata = config.get('metadata', {})

    # Header panel
    header_text = f" [bold cyan]{metadata.get('name', 'Unknown Template')}[/bold cyan]\n"
    header_text += f" {metadata.get('description', 'No description available')}\n"
    header_text += f" File: {template_file.name if template_file else 'Unknown'}"

    console.print(Panel(header_text, title="Template Overview", border_style="cyan"))

    # Basic information table
    info_table = Table(show_header=False, box=None, padding=(0, 2))
    info_table.add_column("Property", style="bold")
    info_table.add_column("Value")

    info_table.add_row("Threat Type", config.get('threat_type', 'Unknown').replace('_', ' ').title())
    info_table.add_row("Delivery Vector", config.get('delivery_vector', 'Unknown').replace('_', ' ').title())
    info_table.add_row("Difficulty Level", f"{config.get('difficulty_level', 'N/A')}/10")
    info_table.add_row("Estimated Duration", f"{config.get('estimated_duration', 'N/A')} minutes")
    info_table.add_row("Version", metadata.get('version', 'Unknown'))
    info_table.add_row("Author", metadata.get('author', 'Unknown'))

    console.print(Panel(info_table, title="Basic Information", border_style="blue"))

    # Target profile
    target_profile = config.get('target_profile', {})
    if target_profile:
        target_text = f"[bold]Role:[/bold] {target_profile.get('role', 'N/A')}\n"
        target_text += f"[bold]Department:[/bold] {target_profile.get('department', 'N/A')}\n"
        target_text += f"[bold]Seniority:[/bold] {target_profile.get('seniority', 'N/A').replace('_', ' ').title()}\n"
        target_text += f"[bold]Technical Level:[/bold] {target_profile.get('technical_level', 'N/A').title()}\n"
        target_text += f"[bold]Industry:[/bold] {target_profile.get('industry', 'N/A').replace('_', ' ').title()}\n"
        target_text += f"[bold]Security Awareness:[/bold] {target_profile.get('security_awareness_level', 'N/A')}/10"

        console.print(Panel(target_text, title="Target Profile", border_style="green"))

    # MITRE ATT&CK techniques
    behavioral_pattern = config.get('behavioral_pattern', {})
    mitre_techniques = behavioral_pattern.get('mitre_attack_techniques', [])
    if mitre_techniques:
        techniques_text = ", ".join(mitre_techniques)
        console.print(Panel(f" {techniques_text}", title="MITRE ATT&CK Techniques", border_style="red"))

    # Tags
    tags = metadata.get('tags', [])
    if tags:
        tags_text = " ".join([f"[dim]#{tag}[/dim]" for tag in tags])
        console.print(Panel(tags_text, title="Tags", border_style="yellow"))


def _display_yaml_content(template_file: Path):
    """Display raw YAML content with syntax highlighting."""
    try:
        with open(template_file, 'r', encoding='utf-8') as f:
            content = f.read()

        syntax = Syntax(content, "yaml", theme="monokai", line_numbers=True, word_wrap=True)
        console.print(Panel(syntax, title=f" Raw YAML Content - {template_file.name}", border_style="dim"))

    except Exception as e:
        console.print(f"[red] Error reading file:[/red] {e}")


@templates.command()
@click.option('--output-dir', '-o', type=click.Path(), help='Output directory for validation report')
def validate_all(output_dir):
    """Validate all templates and generate a comprehensive report."""
    templates_dir = Path(__file__).parent.parent.parent.parent / "templates"

    if not templates_dir.exists():
        console.print("[red] No templates directory found.[/red]")
        return

    loader = YAMLConfigLoader()
    results = loader.validate_config_directory(templates_dir)

    # Display summary
    total = results['total_files']
    valid = results['valid_files']
    invalid = results['invalid_files']

    console.print("\n[bold cyan] Validation Summary[/bold cyan]")
    console.print(f"Total Templates: {total}")
    console.print(f"Valid: [green]{valid}[/green]")
    console.print(f"Invalid: [red]{invalid}[/red]")
    console.print(f"Success Rate: [cyan]{(valid/total*100):.1f}%[/cyan]" if total > 0 else "Success Rate: N/A")

    # Display detailed results
    if results['files']:
        table = Table(title="Detailed Validation Results", show_header=True)
        table.add_column("Template", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Details", style="dim")

        for file_path, file_result in results['files'].items():
            if file_result['status'] == 'valid':
                status = "[green] Valid[/green]"
                details = f"{file_result.get('threat_type', 'N/A')} (Difficulty: {file_result.get('difficulty', 'N/A')})"
            else:
                status = "[red] Invalid[/red]"
                details = file_result.get('error', 'Unknown error')[:60] + "..." if len(file_result.get('error', '')) > 60 else file_result.get('error', 'Unknown error')

            table.add_row(file_path, status, details)

        console.print(table)

    # Save report if output directory specified
    if output_dir:
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        report_file = output_path / "template_validation_report.json"
        import json
        with open(report_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        console.print(f"\n[green] Detailed report saved to: {report_file}[/green]")


@templates.command()
@click.argument('source_template')
@click.argument('new_name')
@click.option('--edit', '-e', is_flag=True, help='Open new template for editing after creation')
def copy(source_template: str, new_name: str, edit: bool):
    """Copy an existing template to create a new one."""
    templates_dir = Path(__file__).parent.parent.parent.parent / "templates"

    # Find source template
    source_file = None
    for ext in ['.yaml', '.yml', '']:
        potential_path = templates_dir / f"{source_template}{ext}"
        if potential_path.exists():
            source_file = potential_path
            break

    if not source_file:
        console.print(f"[red] Source template '{source_template}' not found.[/red]")
        return

    # Create new template
    new_file = templates_dir / f"{new_name}.yaml"
    if new_file.exists():
        if not click.confirm(f"Template '{new_name}' already exists. Overwrite?"):
            return

    try:
        # Copy content and update metadata
        loader = YAMLConfigLoader()
        config = loader.load_config(source_file)

        # Update metadata for new template
        if 'metadata' in config:
            config['metadata']['name'] = new_name.replace('_', ' ').title()
            config['metadata']['description'] = f"Customized version of {source_template}"
            config['metadata']['version'] = "1.0.0"
            config['metadata']['author'] = "Custom"
            from datetime import datetime
            config['metadata']['created_at'] = datetime.utcnow().isoformat() + 'Z'
            config['metadata']['updated_at'] = datetime.utcnow().isoformat() + 'Z'

        # Write new file
        import yaml
        with open(new_file, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

        console.print(f"[green] Template copied successfully to: {new_file.name}[/green]")

        if edit:
            click.launch(str(new_file))

    except Exception as e:
        console.print(f"[red]Error copying template:[/red] {e}")


@templates.command()
def create():
    """Create a new threat scenario template using the interactive wizard."""
    console.print("[bold blue]Starting Template Creation Wizard...[/bold blue]")

    templates_dir = Path(__file__).parent.parent.parent.parent / "templates"
    wizard = TemplateCreationWizard(templates_dir)

    try:
        result = wizard.create_template_interactive()
        if result:
            console.print(f"\n[bold green]Template successfully created: {result.name}[/bold green]")

            # Ask if user wants to validate the new template
            if click.confirm("Validate the new template now?"):
                loader = YAMLConfigLoader()
                try:
                    scenario = loader.load_and_validate_scenario(result)
                    console.print("[green]Template validation successful![/green]")
                except Exception as e:
                    console.print(f"[yellow]Template validation failed: {e}[/yellow]")
        else:
            console.print("[yellow]Template creation cancelled or failed.[/yellow]")

    except KeyboardInterrupt:
        console.print("\n[yellow]Template creation cancelled by user.[/yellow]")
    except Exception as e:
        console.print(f"\n[red] Error during template creation: {e}[/red]")


@templates.command()
@click.option('--auto-fix', '-f', is_flag=True, help='Automatically attempt to fix common issues')
@click.option('--backup', '-b', is_flag=True, help='Create backup files before fixing')
def validate_pro(auto_fix: bool, backup: bool):
    """Professional validation with detailed diagnostics and auto-fix capabilities."""
    console.print("[bold blue] Running Professional Template Validation...[/bold blue]")

    templates_dir = Path(__file__).parent.parent.parent.parent / "templates"
    manager = TemplateManager(templates_dir)

    # Run comprehensive validation
    results = manager.validate_all_templates()

    # Display professional summary
    stats = results["statistics"]
    console.print("\n[bold cyan] Validation Report[/bold cyan]")
    console.print(f"Total Templates: {stats['total']}")
    console.print(f"Valid: [green]{stats['valid_count']}[/green] ({stats['valid_count']/stats['total']*100:.1f}%)" if stats['total'] > 0 else "Valid: 0")
    console.print(f"Invalid: [red]{stats['invalid_count']}[/red] ({stats['invalid_count']/stats['total']*100:.1f}%)" if stats['total'] > 0 else "Invalid: 0")

    # Detailed results table
    table = Table(title="Detailed Validation Results", show_header=True)
    table.add_column("Template", style="cyan", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("Threat Type", style="yellow")
    table.add_column("Difficulty", justify="center")
    table.add_column("Issues", style="red")

    # Add valid templates
    for valid in results["valid"]:
        table.add_row(
            valid["file"],
            "[green] Valid[/green]",
            valid["threat_type"].replace('_', ' ').title(),
            str(valid["difficulty"]),
            "[green]None[/green]"
        )

    # Add invalid templates
    for invalid in results["invalid"]:
        error_short = invalid["error"][:50] + "..." if len(invalid["error"]) > 50 else invalid["error"]
        table.add_row(
            invalid["file"],
            "[red] Invalid[/red]",
            "Unknown",
            "N/A",
            error_short
        )

    console.print(table)

    # Auto-fix invalid templates if requested
    if auto_fix and results["invalid"]:
        console.print(f"\n[bold yellow] Attempting to auto-fix {len(results['invalid'])} invalid templates...[/bold yellow]")

        fixed_count = 0
        for invalid in results["invalid"]:
            template_file = templates_dir / invalid["file"]
            if template_file.exists():
                if manager.fix_template_issues(template_file):
                    fixed_count += 1

        console.print(f"\n[bold green] Successfully fixed {fixed_count} templates![/bold green]")

        if fixed_count > 0:
            console.print("[dim]Re-run validation to see updated results.[/dim]")


@templates.command()
@click.argument('source_template')
@click.argument('new_name')
def clone(source_template: str, new_name: str):
    """Create a new template by cloning and customizing an existing one."""
    console.print(f"[bold blue] Cloning template '{source_template}' as '{new_name}'...[/bold blue]")

    templates_dir = Path(__file__).parent.parent.parent.parent / "templates"
    manager = TemplateManager(templates_dir)

    try:
        new_template_path = manager.create_from_template(source_template, new_name)
        console.print(f"[green] Template cloned successfully: {new_template_path.name}[/green]")

        # Display new template info
        if click.confirm("View the cloned template?"):
            from ..config.yaml_loader import YAMLConfigLoader
            loader = YAMLConfigLoader()
            config = loader.load_config(new_template_path)
            _display_template_details(config, None, new_template_path)

    except FileNotFoundError as e:
        console.print(f"[red] {e}[/red]")
    except Exception as e:
        console.print(f"[red] Error cloning template: {e}[/red]")


@templates.command()
def stats():
    """Display comprehensive statistics about the template ecosystem."""
    console.print("[bold blue] Template Ecosystem Statistics[/bold blue]")

    templates_dir = Path(__file__).parent.parent.parent.parent / "templates"
    manager = TemplateManager(templates_dir)

    # Get validation results for statistics
    results = manager.validate_all_templates()

    if results["statistics"]["total"] == 0:
        console.print("[yellow]No templates found in the templates directory.[/yellow]")
        return

    # Overall statistics
    stats = results["statistics"]
    console.print("\n[bold cyan] Overall Statistics[/bold cyan]")
    console.print(f"Total Templates: {stats['total']}")
    console.print(f"Valid Templates: [green]{stats['valid_count']}[/green]")
    console.print(f"Invalid Templates: [red]{stats['invalid_count']}[/red]")
    console.print(f"Success Rate: [cyan]{stats['success_rate']:.1%}[/cyan]")

    # Threat type distribution
    threat_types = {}
    difficulty_levels = {}

    for valid in results["valid"]:
        threat_type = valid["threat_type"]
        difficulty = valid["difficulty"]

        threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
        difficulty_levels[difficulty] = difficulty_levels.get(difficulty, 0) + 1

    # Threat types table
    if threat_types:
        table = Table(title="Threat Type Distribution", show_header=True)
        table.add_column("Threat Type", style="cyan")
        table.add_column("Count", justify="center")
        table.add_column("Percentage", justify="center")

        for threat_type, count in sorted(threat_types.items()):
            percentage = count / len(results["valid"]) * 100
            table.add_row(
                threat_type.replace('_', ' ').title(),
                str(count),
                f"{percentage:.1f}%"
            )

        console.print("")
        console.print(table)

    # Difficulty distribution
    if difficulty_levels:
        table = Table(title="Difficulty Level Distribution", show_header=True)
        table.add_column("Difficulty Level", style="yellow")
        table.add_column("Count", justify="center")
        table.add_column("Percentage", justify="center")

        for difficulty, count in sorted(difficulty_levels.items()):
            percentage = count / len(results["valid"]) * 100
            table.add_row(
                f"{difficulty}/10",
                str(count),
                f"{percentage:.1f}%"
            )

        console.print("")
        console.print(table)


@templates.command()
def health():
    """Check the overall health of the template ecosystem."""
    console.print("[bold blue] Template Ecosystem Health Check[/bold blue]")

    templates_dir = Path(__file__).parent.parent.parent.parent / "templates"

    if not templates_dir.exists():
        console.print("[red] Templates directory not found![/red]")
        return

    manager = TemplateManager(templates_dir)
    results = manager.validate_all_templates()

    # Health scoring
    total_score = 0
    max_score = 100

    # Validation success rate (40 points)
    validation_score = results["statistics"]["success_rate"] * 40
    total_score += validation_score

    # Template diversity (30 points)
    threat_types = set()
    for valid in results["valid"]:
        threat_types.add(valid["threat_type"])

    diversity_score = min(len(threat_types) / 5, 1.0) * 30  # Max 5 different types
    total_score += diversity_score

    # Template count (20 points)
    count_score = min(results["statistics"]["total"] / 20, 1.0) * 20  # Max 20 templates
    total_score += count_score

    # No critical errors (10 points)
    critical_errors = len([inv for inv in results["invalid"] if "Schema validation failed" in inv["error"]])
    error_penalty = critical_errors * 2  # -2 points per critical error
    error_score = max(10 - error_penalty, 0)
    total_score += error_score

    # Health status
    if total_score >= 90:
        health_status = "[bold green]Excellent[/bold green]"
        health_color = "green"
    elif total_score >= 75:
        health_status = "[bold yellow]Good[/bold yellow]"
        health_color = "yellow"
    elif total_score >= 60:
        health_status = "[bold orange]Fair[/bold orange]"
        health_color = "orange"
    else:
        health_status = "[bold red]Poor[/bold red]"
        health_color = "red"

    # Display health report
    health_panel = Panel(
        f"Overall Health Score: [bold {health_color}]{total_score:.1f}/100[/bold {health_color}]\n"
        f"Status: {health_status}\n\n"
        f"[dim]Breakdown:[/dim]\n"
        f"- Validation Success: {validation_score:.1f}/40\n"
        f"- Template Diversity: {diversity_score:.1f}/30\n"
        f"- Template Count: {count_score:.1f}/20\n"
        f"- Error-free Score: {error_score:.1f}/10",
        title="Ecosystem Health Report",
        border_style=health_color
    )

    console.print(health_panel)

    # Recommendations
    recommendations = []

    if validation_score < 30:
        recommendations.append("• Fix invalid templates to improve validation success rate")

    if diversity_score < 20:
        recommendations.append("• Create templates for more threat types (phishing, malware, social_engineering, etc.)")

    if count_score < 15:
        recommendations.append("• Create more templates to expand the scenario library")

    if error_score < 8:
        recommendations.append("• Review and fix schema validation errors in templates")

    if recommendations:
        rec_panel = Panel(
            "\n".join(recommendations),
            title=" Recommendations",
            border_style="blue"
        )
        console.print("")
        console.print(rec_panel)
    else:
        console.print("\n[green] No major issues found. Template ecosystem is healthy![/green]")
