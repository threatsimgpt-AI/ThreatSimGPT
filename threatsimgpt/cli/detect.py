"""CLI commands for detection rule generation.

This module provides CLI commands for generating SIEM detection rules
from threat simulation scenarios. Supports multiple formats including
Sigma, Splunk SPL, Elastic KQL, and Microsoft Sentinel.

Issue #25: Build Detection Rule Generator (SIEM)
Author: David Onoja (Blue Team)
Track: detection
Priority: critical
"""

import json
import sys
from pathlib import Path
from typing import Optional, List
from datetime import datetime

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


@click.group(name="detect")
def detect_group():
    """Detection rule generation commands.
    
    Generate SIEM detection rules from threat simulation scenarios
    for various security platforms including Sigma, Splunk, Elastic,
    and Microsoft Sentinel.
    
    Examples:
        threatgpt detect generate -s scenario.yaml --format sigma
        threatgpt detect validate rules/my_rule.yaml --format sigma
        threatgpt detect list-formats
        threatgpt detect from-technique T1566.001 --format splunk
    """
    pass


@detect_group.command(name="generate")
@click.option(
    "--scenario", "-s",
    required=True,
    type=click.Path(exists=True),
    help="Path to threat scenario YAML file"
)
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["sigma", "splunk", "elastic", "sentinel", "all"]),
    default="sigma",
    help="Detection rule format to generate"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file or directory path"
)
@click.option(
    "--include-tests",
    is_flag=True,
    help="Include test cases in output"
)
@click.option(
    "--validate/--no-validate",
    default=True,
    help="Validate generated rules"
)
@click.option(
    "--severity",
    type=click.Choice(["low", "medium", "high", "critical"]),
    help="Override default severity level"
)
@click.pass_context
def generate_rules(
    ctx: click.Context,
    scenario: str,
    output_format: str,
    output: Optional[str],
    include_tests: bool,
    validate: bool,
    severity: Optional[str]
):
    """Generate detection rules from a threat scenario.
    
    Analyzes a threat simulation scenario and generates SIEM detection
    rules optimized for the specified platform.
    
    Examples:
        # Generate Sigma rules
        threatgpt detect generate -s phishing_scenario.yaml -f sigma
        
        # Generate for all platforms
        threatgpt detect generate -s scenario.yaml -f all -o ./rules/
        
        # Generate with validation disabled
        threatgpt detect generate -s scenario.yaml --no-validate
    """
    from ..analytics.detection_rules import (
        SigmaRuleGenerator,
        SplunkRuleGenerator,
        ElasticRuleGenerator,
        SentinelRuleGenerator,
        RuleValidator,
        RuleSeverity
    )
    from ..config.yaml_loader import YAMLConfigLoader, ConfigurationError, SchemaValidationError
    
    scenario_path = Path(scenario)
    console.print(f"\n[bold blue]🔍 Detection Rule Generator[/bold blue]")
    console.print(f"[dim]Scenario: {scenario_path.name}[/dim]\n")
    
    # Load scenario
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Loading scenario...", total=None)
        
        try:
            loader = YAMLConfigLoader()
            scenario_config = loader.load_and_validate_scenario(scenario_path)
            progress.update(task, description="[green]✓ Scenario loaded[/green]")
        except (ConfigurationError, SchemaValidationError) as e:
            progress.update(task, description=f"[red]✗ Failed to load scenario[/red]")
            console.print(f"[red]Error:[/red] {e}")
            sys.exit(1)
    
    # Get generators based on format
    generators = {}
    if output_format == "all":
        generators = {
            "sigma": SigmaRuleGenerator(),
            "splunk": SplunkRuleGenerator(),
            "elastic": ElasticRuleGenerator(),
            "sentinel": SentinelRuleGenerator(),
        }
    else:
        generator_map = {
            "sigma": SigmaRuleGenerator,
            "splunk": SplunkRuleGenerator,
            "elastic": ElasticRuleGenerator,
            "sentinel": SentinelRuleGenerator,
        }
        generators = {output_format: generator_map[output_format]()}
    
    # Parse severity override
    severity_override = None
    if severity:
        severity_map = {
            "low": RuleSeverity.LOW,
            "medium": RuleSeverity.MEDIUM,
            "high": RuleSeverity.HIGH,
            "critical": RuleSeverity.CRITICAL,
        }
        severity_override = severity_map[severity]
    
    # Generate rules
    all_rules = {}
    validator = RuleValidator() if validate else None
    
    console.print("[bold cyan]Generating detection rules...[/bold cyan]\n")
    
    for format_name, generator in generators.items():
        with console.status(f"[yellow]Generating {format_name} rules...[/yellow]"):
            try:
                rules = generator.from_scenario(scenario_config)
                
                # Apply severity override if specified
                if severity_override:
                    for rule in rules:
                        rule.severity = severity_override
                
                all_rules[format_name] = rules
                
                # Validate if requested
                validation_status = ""
                if validator and rules:
                    validation_results = [validator.validate(rule, format_name) for rule in rules]
                    valid_count = sum(1 for r in validation_results if r.is_valid)
                    if valid_count == len(rules):
                        validation_status = " [green]✓ validated[/green]"
                    else:
                        validation_status = f" [yellow]⚠ {valid_count}/{len(rules)} valid[/yellow]"
                
                console.print(f"  [green]✓[/green] {format_name.capitalize()}: {len(rules)} rule(s){validation_status}")
                
            except Exception as e:
                console.print(f"  [red]✗[/red] {format_name.capitalize()}: Failed - {e}")
                all_rules[format_name] = []
    
    if not any(all_rules.values()):
        console.print("\n[yellow]No rules were generated. Check if the scenario contains detectable threat indicators.[/yellow]")
        sys.exit(1)
    
    # Display generated rules
    console.print("\n[bold cyan]Generated Rules:[/bold cyan]\n")
    
    for format_name, rules in all_rules.items():
        if not rules:
            continue
            
        for i, rule in enumerate(rules, 1):
            # Get the formatted output
            generator = generators[format_name]
            formatted_rule = generator.format_rule(rule)
            
            # Determine syntax highlighting
            syntax_lang = {
                "sigma": "yaml",
                "splunk": "sql",
                "elastic": "json",
                "sentinel": "sql",
            }.get(format_name, "text")
            
            # Create panel with rule
            title = f"{format_name.upper()} Rule {i}: {rule.name}"
            syntax = Syntax(
                formatted_rule[:2000],  # Limit display length
                syntax_lang,
                theme="monokai",
                line_numbers=True
            )
            console.print(Panel(syntax, title=title, border_style="blue"))
            
            # Show metadata
            metadata_table = Table(show_header=False, box=None)
            metadata_table.add_column("Field", style="cyan")
            metadata_table.add_column("Value")
            metadata_table.add_row("Severity", f"[{_severity_color(rule.severity)}]{rule.severity.value}[/]")
            metadata_table.add_row("MITRE ATT&CK", ", ".join(m.technique_id for m in rule.mitre_mappings) if rule.mitre_mappings else "N/A")
            if rule.false_positive_rate:
                metadata_table.add_row("Est. FP Rate", f"{rule.false_positive_rate.estimated_rate:.1%}")
            console.print(metadata_table)
            console.print()
    
    # Save rules if output specified
    if output:
        output_path = Path(output)
        saved_files = []
        
        if output_format == "all":
            # Create directory for multiple formats
            output_path.mkdir(parents=True, exist_ok=True)
            
            for format_name, rules in all_rules.items():
                if not rules:
                    continue
                
                generator = generators[format_name]
                ext = _get_extension(format_name)
                
                for i, rule in enumerate(rules, 1):
                    rule_file = output_path / f"{_sanitize_filename(rule.name)}_{format_name}.{ext}"
                    formatted = generator.format_rule(rule)
                    rule_file.write_text(formatted)
                    saved_files.append(rule_file)
        else:
            # Single format output
            if output_path.suffix:
                # Output is a file
                rules = all_rules.get(output_format, [])
                if rules:
                    generator = generators[output_format]
                    # Combine all rules into one file
                    all_formatted = "\n\n---\n\n".join(generator.format_rule(r) for r in rules)
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    output_path.write_text(all_formatted)
                    saved_files.append(output_path)
            else:
                # Output is a directory
                output_path.mkdir(parents=True, exist_ok=True)
                rules = all_rules.get(output_format, [])
                generator = generators[output_format]
                ext = _get_extension(output_format)
                
                for rule in rules:
                    rule_file = output_path / f"{_sanitize_filename(rule.name)}.{ext}"
                    formatted = generator.format_rule(rule)
                    rule_file.write_text(formatted)
                    saved_files.append(rule_file)
        
        if saved_files:
            console.print(f"\n[green]✓ Saved {len(saved_files)} rule file(s):[/green]")
            for f in saved_files[:10]:
                console.print(f"  → {f}")
            if len(saved_files) > 10:
                console.print(f"  ... and {len(saved_files) - 10} more")
    
    # Summary
    total_rules = sum(len(rules) for rules in all_rules.values())
    console.print(f"\n[bold green]✓ Generated {total_rules} detection rule(s)[/bold green]")


@detect_group.command(name="from-technique")
@click.argument("technique_id")
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["sigma", "splunk", "elastic", "sentinel", "all"]),
    default="sigma",
    help="Detection rule format to generate"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file path"
)
@click.option(
    "--severity",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="high",
    help="Rule severity level"
)
def from_technique(
    technique_id: str,
    output_format: str,
    output: Optional[str],
    severity: str
):
    """Generate detection rules from MITRE ATT&CK technique ID.
    
    Creates detection rules based on a specific MITRE ATT&CK technique
    identifier (e.g., T1566.001 for Spearphishing Attachment).
    
    Examples:
        threatgpt detect from-technique T1566.001
        threatgpt detect from-technique T1059.001 -f splunk -o powershell.spl
        threatgpt detect from-technique T1078 -f all --severity critical
    """
    from ..analytics.detection_rules import (
        SigmaRuleGenerator,
        SplunkRuleGenerator,
        ElasticRuleGenerator,
        SentinelRuleGenerator,
        RuleSeverity
    )
    
    console.print(f"\n[bold blue]🔍 MITRE ATT&CK Detection Rule Generator[/bold blue]")
    console.print(f"[dim]Technique: {technique_id}[/dim]\n")
    
    # Validate technique ID format
    if not technique_id.upper().startswith("T"):
        console.print("[red]Error: Invalid technique ID format. Expected format: T1566 or T1566.001[/red]")
        sys.exit(1)
    
    technique_id = technique_id.upper()
    
    # Get generators
    generators = {}
    if output_format == "all":
        generators = {
            "sigma": SigmaRuleGenerator(),
            "splunk": SplunkRuleGenerator(),
            "elastic": ElasticRuleGenerator(),
            "sentinel": SentinelRuleGenerator(),
        }
    else:
        generator_map = {
            "sigma": SigmaRuleGenerator,
            "splunk": SplunkRuleGenerator,
            "elastic": ElasticRuleGenerator,
            "sentinel": SentinelRuleGenerator,
        }
        generators = {output_format: generator_map[output_format]()}
    
    # Map severity
    severity_map = {
        "low": RuleSeverity.LOW,
        "medium": RuleSeverity.MEDIUM,
        "high": RuleSeverity.HIGH,
        "critical": RuleSeverity.CRITICAL,
    }
    rule_severity = severity_map[severity]
    
    # Generate rules
    console.print("[cyan]Generating detection rules...[/cyan]\n")
    
    for format_name, generator in generators.items():
        try:
            rules = generator.from_attack_technique(technique_id, rule_severity)
            
            if rules:
                for rule in rules:
                    formatted = generator.format_rule(rule)
                    
                    syntax_lang = {
                        "sigma": "yaml",
                        "splunk": "sql",
                        "elastic": "json",
                        "sentinel": "sql",
                    }.get(format_name, "text")
                    
                    title = f"{format_name.upper()}: {rule.name}"
                    syntax = Syntax(formatted, syntax_lang, theme="monokai", line_numbers=True)
                    console.print(Panel(syntax, title=title, border_style="blue"))
                    
                    # Save if output specified
                    if output:
                        output_path = Path(output)
                        if output_format == "all":
                            output_path.mkdir(parents=True, exist_ok=True)
                            ext = _get_extension(format_name)
                            file_path = output_path / f"{technique_id}_{format_name}.{ext}"
                        else:
                            file_path = output_path
                            file_path.parent.mkdir(parents=True, exist_ok=True)
                        
                        file_path.write_text(formatted)
                        console.print(f"[green]✓ Saved to {file_path}[/green]")
            else:
                console.print(f"[yellow]No rules generated for {format_name}[/yellow]")
                
        except Exception as e:
            console.print(f"[red]Error generating {format_name} rules: {e}[/red]")
    
    console.print(f"\n[bold green]✓ Detection rule generation complete[/bold green]")


@detect_group.command(name="validate")
@click.argument("rule_file", type=click.Path(exists=True))
@click.option(
    "--format", "-f", "rule_format",
    type=click.Choice(["sigma", "splunk", "elastic", "sentinel"]),
    help="Rule format (auto-detected if not specified)"
)
@click.option(
    "--strict",
    is_flag=True,
    help="Enable strict validation mode"
)
def validate_rule(
    rule_file: str,
    rule_format: Optional[str],
    strict: bool
):
    """Validate a detection rule file.
    
    Checks rule syntax, required fields, and best practices
    for the specified format.
    
    Examples:
        threatgpt detect validate rule.yaml --format sigma
        threatgpt detect validate rule.spl --strict
    """
    from ..analytics.detection_rules import RuleValidator, DetectionRule, RuleSeverity, RuleStatus
    
    rule_path = Path(rule_file)
    console.print(f"\n[bold blue]🔍 Detection Rule Validator[/bold blue]")
    console.print(f"[dim]File: {rule_path.name}[/dim]\n")
    
    # Auto-detect format if not specified
    if not rule_format:
        ext = rule_path.suffix.lower()
        format_map = {
            ".yaml": "sigma",
            ".yml": "sigma",
            ".spl": "splunk",
            ".json": "elastic",
            ".kql": "sentinel",
        }
        rule_format = format_map.get(ext)
        
        if not rule_format:
            console.print("[red]Error: Could not auto-detect rule format. Please specify with --format[/red]")
            sys.exit(1)
        
        console.print(f"[dim]Auto-detected format: {rule_format}[/dim]\n")
    
    # Read rule content
    content = rule_path.read_text()
    
    # Create a minimal rule for validation
    rule = DetectionRule(
        id=f"validate_{datetime.now().strftime('%Y%m%d%H%M%S')}",
        name=rule_path.stem,
        description="Validation target",
        severity=RuleSeverity.MEDIUM,
        status=RuleStatus.EXPERIMENTAL,
        raw_query=content
    )
    
    # Validate
    validator = RuleValidator()
    result = validator.validate(rule, rule_format)
    
    # Display results
    if result.is_valid:
        console.print("[bold green]✓ Rule validation PASSED[/bold green]\n")
    else:
        console.print("[bold red]✗ Rule validation FAILED[/bold red]\n")
    
    # Show details table
    results_table = Table(title="Validation Results")
    results_table.add_column("Check", style="cyan")
    results_table.add_column("Status")
    results_table.add_column("Details")
    
    # Syntax check
    syntax_status = "[green]PASS[/green]" if result.syntax_valid else "[red]FAIL[/red]"
    results_table.add_row("Syntax", syntax_status, "Rule syntax is valid" if result.syntax_valid else "Syntax errors found")
    
    # Schema check
    schema_status = "[green]PASS[/green]" if result.schema_valid else "[red]FAIL[/red]"
    results_table.add_row("Schema", schema_status, "Required fields present" if result.schema_valid else "Missing required fields")
    
    # Best practices
    bp_status = "[green]PASS[/green]" if result.best_practices_followed else "[yellow]WARN[/yellow]"
    results_table.add_row("Best Practices", bp_status, "Follows conventions" if result.best_practices_followed else "Some recommendations")
    
    console.print(results_table)
    
    # Show errors
    if result.errors:
        console.print("\n[bold red]Errors:[/bold red]")
        for error in result.errors:
            console.print(f"  [red]✗[/red] {error}")
    
    # Show warnings
    if result.warnings:
        console.print("\n[bold yellow]Warnings:[/bold yellow]")
        for warning in result.warnings:
            console.print(f"  [yellow]⚠[/yellow] {warning}")
    
    # Show suggestions
    if result.suggestions:
        console.print("\n[bold blue]Suggestions:[/bold blue]")
        for suggestion in result.suggestions:
            console.print(f"  [blue]ℹ[/blue] {suggestion}")
    
    sys.exit(0 if result.is_valid else 1)


@detect_group.command(name="list-formats")
def list_formats():
    """List supported detection rule formats with details.
    
    Shows all supported SIEM platforms and their rule formats,
    including syntax examples and use cases.
    """
    console.print("\n[bold blue]🔍 Supported Detection Rule Formats[/bold blue]\n")
    
    formats_table = Table(title="SIEM Platform Support")
    formats_table.add_column("Format", style="cyan", width=12)
    formats_table.add_column("Platform", width=20)
    formats_table.add_column("Extension", width=10)
    formats_table.add_column("Description")
    
    formats_table.add_row(
        "sigma",
        "Generic (YAML)",
        ".yaml/.yml",
        "Generic signature format convertible to other platforms"
    )
    formats_table.add_row(
        "splunk",
        "Splunk Enterprise",
        ".spl",
        "Splunk Search Processing Language queries"
    )
    formats_table.add_row(
        "elastic",
        "Elastic Security",
        ".json",
        "Kibana Detection Engine rules in JSON format"
    )
    formats_table.add_row(
        "sentinel",
        "Microsoft Sentinel",
        ".kql",
        "Azure Sentinel Analytics Rules using KQL"
    )
    
    console.print(formats_table)
    
    # Usage examples
    console.print("\n[bold cyan]Quick Examples:[/bold cyan]\n")
    
    examples = [
        ("Generate Sigma rules", "threatgpt detect generate -s scenario.yaml -f sigma"),
        ("Generate all formats", "threatgpt detect generate -s scenario.yaml -f all -o ./rules/"),
        ("From MITRE technique", "threatgpt detect from-technique T1566.001 -f splunk"),
        ("Validate a rule", "threatgpt detect validate rule.yaml --format sigma"),
    ]
    
    for desc, cmd in examples:
        console.print(f"  [dim]{desc}:[/dim]")
        console.print(f"    [green]{cmd}[/green]\n")


@detect_group.command(name="convert")
@click.argument("rule_file", type=click.Path(exists=True))
@click.option(
    "--from", "-f", "from_format",
    type=click.Choice(["sigma"]),
    default="sigma",
    help="Source format (currently only sigma supported)"
)
@click.option(
    "--to", "-t", "to_format",
    type=click.Choice(["splunk", "elastic", "sentinel"]),
    required=True,
    help="Target format"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file path"
)
def convert_rule(
    rule_file: str,
    from_format: str,
    to_format: str,
    output: Optional[str]
):
    """Convert detection rules between formats.
    
    Currently supports conversion from Sigma format to other formats.
    
    Examples:
        threatgpt detect convert rule.yaml --to splunk
        threatgpt detect convert sigma_rule.yml -t elastic -o elastic_rule.json
    """
    import yaml
    from ..analytics.detection_rules import (
        SplunkRuleGenerator,
        ElasticRuleGenerator,
        SentinelRuleGenerator,
        DetectionRule,
        RuleSeverity,
        RuleStatus
    )
    
    rule_path = Path(rule_file)
    console.print(f"\n[bold blue]🔄 Detection Rule Converter[/bold blue]")
    console.print(f"[dim]{from_format} → {to_format}[/dim]\n")
    
    # Read sigma rule
    try:
        content = rule_path.read_text()
        sigma_data = yaml.safe_load(content)
    except Exception as e:
        console.print(f"[red]Error reading rule file: {e}[/red]")
        sys.exit(1)
    
    # Parse sigma rule into DetectionRule
    try:
        # Extract severity
        level = sigma_data.get("level", "medium").lower()
        severity_map = {
            "informational": RuleSeverity.INFORMATIONAL,
            "low": RuleSeverity.LOW,
            "medium": RuleSeverity.MEDIUM,
            "high": RuleSeverity.HIGH,
            "critical": RuleSeverity.CRITICAL,
        }
        severity = severity_map.get(level, RuleSeverity.MEDIUM)
        
        # Create detection rule
        rule = DetectionRule(
            id=sigma_data.get("id", rule_path.stem),
            name=sigma_data.get("title", rule_path.stem),
            description=sigma_data.get("description", "Converted rule"),
            severity=severity,
            status=RuleStatus.EXPERIMENTAL,
            author=sigma_data.get("author", "ThreatSimGPT"),
            tags=sigma_data.get("tags", []),
            references=sigma_data.get("references", []),
        )
        
    except Exception as e:
        console.print(f"[red]Error parsing Sigma rule: {e}[/red]")
        sys.exit(1)
    
    # Convert to target format
    generator_map = {
        "splunk": SplunkRuleGenerator,
        "elastic": ElasticRuleGenerator,
        "sentinel": SentinelRuleGenerator,
    }
    
    generator = generator_map[to_format]()
    
    try:
        # Generate in target format
        formatted = generator.format_rule(rule)
        
        syntax_lang = {
            "splunk": "sql",
            "elastic": "json",
            "sentinel": "sql",
        }.get(to_format, "text")
        
        syntax = Syntax(formatted, syntax_lang, theme="monokai", line_numbers=True)
        console.print(Panel(syntax, title=f"Converted to {to_format.upper()}", border_style="green"))
        
        # Save if output specified
        if output:
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(formatted)
            console.print(f"\n[green]✓ Saved to {output_path}[/green]")
        
        console.print(f"\n[bold green]✓ Conversion complete[/bold green]")
        
    except Exception as e:
        console.print(f"[red]Error converting rule: {e}[/red]")
        sys.exit(1)


def _severity_color(severity) -> str:
    """Get color for severity level."""
    colors = {
        "informational": "blue",
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bold red",
    }
    return colors.get(severity.value, "white")


def _get_extension(format_name: str) -> str:
    """Get file extension for format."""
    extensions = {
        "sigma": "yaml",
        "splunk": "spl",
        "elastic": "json",
        "sentinel": "kql",
    }
    return extensions.get(format_name, "txt")


def _sanitize_filename(name: str) -> str:
    """Sanitize string for use as filename."""
    # Remove or replace invalid characters
    invalid_chars = '<>:"/\\|?*'
    result = name
    for char in invalid_chars:
        result = result.replace(char, "_")
    # Replace spaces with underscores
    result = result.replace(" ", "_")
    # Limit length
    return result[:50]
