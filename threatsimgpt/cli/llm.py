"""LLM integration CLI commands for ThreatSimGPT.

This module provides CLI commands for testing and managing LLM integrations.
"""

import asyncio
import json
import os
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax
from rich.table import Table

from ..config.yaml_loader import YAMLConfigLoader
from ..llm import (
    ContentGenerationService,
    ContentType,
    LLMModel,
    LLMProvider,
    LLMProviderConfig,
    LLMProviderManager,
)

console = Console()


@click.group(name="llm")
def llm_group():
    """LLM integration management and testing."""
    pass


@llm_group.command()
@click.option("--openai-key", help="OpenAI API key", envvar="OPENAI_API_KEY")
@click.option("--anthropic-key", help="Anthropic API key", envvar="ANTHROPIC_API_KEY")
@click.option("--openrouter-key", help="OpenRouter API key", envvar="OPENROUTER_API_KEY")
def test_providers(openai_key: Optional[str], anthropic_key: Optional[str], openrouter_key: Optional[str]):
    """Test configured LLM providers."""

    def _check_api_key_error(error_msg: str) -> tuple[bool, str]:
        """Check if error is due to invalid API key vs connection issue.

        Returns:
            (is_api_key_error, clean_message)
        """
        error_lower = error_msg.lower()
        api_key_indicators = [
            "401", "unauthorized", "invalid api key", "invalid x-api-key",
            "authentication", "api key", "apikey", "invalid_api_key",
            "incorrect api key", "invalid key"
        ]

        for indicator in api_key_indicators:
            if indicator in error_lower:
                return True, "Invalid API key - please check your credentials"

        connection_indicators = [
            "connection", "timeout", "network", "dns", "refused",
            "unreachable", "ssl", "certificate"
        ]

        for indicator in connection_indicators:
            if indicator in error_lower:
                return False, f"Connection error: {error_msg}"

        return False, error_msg

    async def _test_providers():
        provider_manager = LLMProviderManager()

        # Configure providers
        providers_configured = 0
        provider_status = {}

        # Check OpenAI
        if openai_key:
            is_placeholder = "your_" in openai_key.lower() or openai_key == "sk-..."
            if is_placeholder:
                provider_status["openai"] = {
                    "configured": True,
                    "key_status": "PLACEHOLDER",
                    "message": "API key appears to be a placeholder value"
                }
            else:
                config = LLMProviderConfig(
                    provider=LLMProvider.OPENAI,
                    api_key=openai_key,
                    default_model=LLMModel.GPT_35_TURBO,
                )
                provider_manager.add_provider(config, set_as_default=True)
                providers_configured += 1
                provider_status["openai"] = {"configured": True, "key_status": "SET"}
                console.print("[OK] OpenAI provider configured")
        else:
            provider_status["openai"] = {"configured": False, "key_status": "MISSING"}

        # Check Anthropic
        if anthropic_key:
            is_placeholder = "your_" in anthropic_key.lower() or anthropic_key == "sk-ant-..."
            if is_placeholder:
                provider_status["anthropic"] = {
                    "configured": True,
                    "key_status": "PLACEHOLDER",
                    "message": "API key appears to be a placeholder value"
                }
            else:
                config = LLMProviderConfig(
                    provider=LLMProvider.ANTHROPIC,
                    api_key=anthropic_key,
                    default_model=LLMModel.CLAUDE_3_HAIKU,
                )
                provider_manager.add_provider(config, set_as_default=providers_configured == 0)
                providers_configured += 1
                provider_status["anthropic"] = {"configured": True, "key_status": "SET"}
                console.print("[OK] Anthropic provider configured")
        else:
            provider_status["anthropic"] = {"configured": False, "key_status": "MISSING"}

        # Check OpenRouter
        if openrouter_key:
            is_placeholder = "your_" in openrouter_key.lower() or openrouter_key == "sk-or-..."
            if is_placeholder:
                provider_status["openrouter"] = {
                    "configured": True,
                    "key_status": "PLACEHOLDER",
                    "message": "API key appears to be a placeholder value"
                }
            else:
                config = LLMProviderConfig(
                    provider=LLMProvider.OPENROUTER,
                    api_key=openrouter_key,
                    default_model=LLMModel.GPT_35_TURBO,
                )
                provider_manager.add_provider(config, set_as_default=providers_configured == 0)
                providers_configured += 1
                provider_status["openrouter"] = {"configured": True, "key_status": "SET"}
                console.print("[OK] OpenRouter provider configured")
        else:
            provider_status["openrouter"] = {"configured": False, "key_status": "MISSING"}

        # Show configuration summary
        console.print("\n[bold]Provider Configuration Status:[/bold]")
        config_table = Table(show_header=True)
        config_table.add_column("Provider", style="cyan")
        config_table.add_column("API Key Status", style="yellow")
        config_table.add_column("Notes", style="white")

        for prov, status in provider_status.items():
            key_status = status["key_status"]
            if key_status == "SET":
                status_text = "[green]Configured[/green]"
                notes = "Ready to test"
            elif key_status == "PLACEHOLDER":
                status_text = "[yellow]Placeholder[/yellow]"
                notes = status.get("message", "Replace with real key")
            else:
                status_text = "[dim]Not Set[/dim]"
                notes = f"Set {prov.upper()}_API_KEY environment variable"

            config_table.add_row(prov.title(), status_text, notes)

        console.print(config_table)

        if providers_configured == 0:
            console.print("\n[yellow][WARN][/yellow] No valid providers configured for testing.")
            console.print("Set environment variables: OPENAI_API_KEY, ANTHROPIC_API_KEY, or OPENROUTER_API_KEY")
            return

        # Test providers
        console.print("\n[bold]Testing LLM Provider Connections...[/bold]")

        generation_service = ContentGenerationService(provider_manager)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Testing providers...", total=None)

            try:
                results = await generation_service.test_providers()
                progress.update(task, completed=True)

                # Display results
                table = Table(title="Provider Test Results")
                table.add_column("Provider", style="cyan")
                table.add_column("Connection", style="green")
                table.add_column("Auth Status", style="yellow")
                table.add_column("Response Time", style="blue")

                for provider_name, result in results.items():
                    if result["status"] == "success":
                        conn_status = "[green]OK[/green]"
                        auth_status = "[green]Valid[/green]"
                        response_time = f"{result.get('response_time_ms', 0)}ms"
                    else:
                        error_msg = result.get("message", "Unknown error")
                        is_auth_error, clean_msg = _check_api_key_error(error_msg)

                        if is_auth_error:
                            conn_status = "[green]OK[/green]"
                            auth_status = "[red]Invalid Key[/red]"
                        else:
                            conn_status = "[red]Failed[/red]"
                            auth_status = "[dim]N/A[/dim]"
                        response_time = "N/A"

                    table.add_row(provider_name, conn_status, auth_status, response_time)

                console.print("\n")
                console.print(table)

                # Show detailed errors
                console.print("\n[bold]Detailed Status:[/bold]")
                for provider_name, result in results.items():
                    if result["status"] == "success":
                        console.print(f"  [green][OK][/green] {provider_name}: Connection successful, API key valid")
                    else:
                        error_msg = result.get("message", "Unknown error")
                        is_auth_error, clean_msg = _check_api_key_error(error_msg)

                        if is_auth_error:
                            console.print(f"  [yellow][AUTH][/yellow] {provider_name}: {clean_msg}")
                        else:
                            console.print(f"  [red][ERROR][/red] {provider_name}: {clean_msg}")

            finally:
                await generation_service.close()

    asyncio.run(_test_providers())


@llm_group.command()
@click.argument("scenario_file", type=click.Path(exists=True, path_type=Path))
@click.option("--content-type",
              type=click.Choice([ct.value for ct in ContentType]),
              default=ContentType.EMAIL_PHISHING.value,
              help="Type of content to generate")
@click.option("--provider",
              type=click.Choice([p.value for p in LLMProvider]),
              help="LLM provider to use")
@click.option("--model",
              help="Specific model to use")
@click.option("--variants", type=int, default=1, help="Number of variants to generate")
@click.option("--output", type=click.Path(path_type=Path), help="Output file path")
@click.option("--openai-key", help="OpenAI API key", envvar="OPENAI_API_KEY")
@click.option("--anthropic-key", help="Anthropic API key", envvar="ANTHROPIC_API_KEY")
@click.option("--openrouter-key", help="OpenRouter API key", envvar="OPENROUTER_API_KEY")
def generate(
    scenario_file: Path,
    content_type: str,
    provider: Optional[str],
    model: Optional[str],
    variants: int,
    output: Optional[Path],
    openai_key: Optional[str],
    anthropic_key: Optional[str],
    openrouter_key: Optional[str],
):
    """Generate threat content from a scenario file."""

    async def _generate():
        # Load scenario
        console.print(f"Loading scenario from {scenario_file}")

        loader = YAMLConfigLoader()
        try:
            # Load the YAML config first
            config_data = loader.load_config(scenario_file)
            # Validate as threat scenario
            scenario = loader.validate_threat_scenario(config_data)
            scenario_data = {
                "name": scenario.metadata.name,
                "threat_type": scenario.threat_type.value if hasattr(scenario.threat_type, 'value') else str(scenario.threat_type),
                "description": scenario.metadata.description,
                "difficulty": scenario.difficulty_level,
                "target_profile": config_data.get("target_profile", {}),
                "attack_content": config_data.get("attack_content", {}),
            }
            console.print("[green][OK][/green] Scenario loaded successfully")
        except Exception as e:
            console.print(f"[red][ERROR][/red] Failed to load scenario: {e}")
            return

        # Configure providers
        provider_manager = LLMProviderManager()
        providers_configured = 0

        if openai_key:
            config = LLMProviderConfig(
                provider=LLMProvider.OPENAI,
                api_key=openai_key,
                default_model=LLMModel.GPT_35_TURBO,
            )
            provider_manager.add_provider(config, set_as_default=True)
            providers_configured += 1

        if anthropic_key:
            config = LLMProviderConfig(
                provider=LLMProvider.ANTHROPIC,
                api_key=anthropic_key,
                default_model=LLMModel.CLAUDE_3_HAIKU,
            )
            provider_manager.add_provider(config, set_as_default=providers_configured == 0)
            providers_configured += 1

        if openrouter_key:
            config = LLMProviderConfig(
                provider=LLMProvider.OPENROUTER,
                api_key=openrouter_key,
                default_model=LLMModel.GPT_35_TURBO,  # OpenRouter supports many models
            )
            provider_manager.add_provider(config, set_as_default=providers_configured == 0)
            providers_configured += 1

        if providers_configured == 0:
            console.print("[yellow][WARN][/yellow] No providers configured. Set OPENAI_API_KEY, ANTHROPIC_API_KEY, or OPENROUTER_API_KEY environment variables.")
            return

        # Create generation service
        generation_service = ContentGenerationService(provider_manager)

        # Parse parameters
        content_type_enum = ContentType(content_type)
        provider_enum = LLMProvider(provider) if provider else None
        model_enum = LLMModel(model) if model else None

        console.print(f"\n Generating {variants} variant(s) of {content_type} content...")

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Generating content...", total=None)

                if variants == 1:
                    result = await generation_service.generate_content(
                        content_type_enum, scenario_data, provider_enum, model_enum
                    )
                    results = [result]
                else:
                    results = await generation_service.generate_multiple_variants(
                        content_type_enum, scenario_data, variants, provider_enum, model_enum
                    )

                progress.update(task, description="[green]Content generated![/green]")

            # Display/save results
            for i, result in enumerate(results, 1):
                variant_label = f"Variant {i}" if variants > 1 else "Generated Content"

                if result.safety_passed:
                    # Show successful generation
                    panel_title = f" {variant_label} (Quality: {result.quality_score:.2f})"

                    content_syntax = Syntax(
                        result.content,
                        "text",
                        theme="monokai",
                        line_numbers=False,
                        word_wrap=True
                    )

                    console.print(Panel(
                        content_syntax,
                        title=panel_title,
                        border_style="green"
                    ))

                    # Show metadata
                    metadata_table = Table(show_header=False, box=None, padding=(0, 1))
                    metadata_table.add_row("Provider:", f"{result.provider.value}")
                    metadata_table.add_row("Model:", f"{result.model.value}")
                    metadata_table.add_row("Tokens Used:", f"{result.tokens_used}")
                    metadata_table.add_row("Cost Estimate:", f"${result.cost_estimate:.4f}")
                    metadata_table.add_row("Generation Time:", f"{result.generation_time_ms}ms")
                    metadata_table.add_row("Quality Score:", f"{result.quality_score:.2f}/1.0")
                    metadata_table.add_row("Realism Score:", f"{result.realism_score:.2f}/1.0")

                    console.print(Panel(
                        metadata_table,
                        title="Generation Metadata",
                        border_style="blue"
                    ))

                else:
                    # Show failed generation
                    console.print(Panel(
                        f" Generation failed: {'; '.join(result.safety_issues)}",
                        title=f" {variant_label} - Failed",
                        border_style="red"
                    ))

            # Save to file if requested
            if output:
                save_data = {
                    "scenario_file": str(scenario_file),
                    "content_type": content_type,
                    "generation_timestamp": results[0].timestamp.isoformat() if results else None,
                    "variants": []
                }

                for result in results:
                    variant_data = {
                        "generation_id": result.generation_id,
                        "content": result.content,
                        "provider": result.provider.value,
                        "model": result.model.value,
                        "quality_metrics": {
                            "quality_score": result.quality_score,
                            "realism_score": result.realism_score,
                            "effectiveness_score": result.effectiveness_score,
                        },
                        "safety_passed": result.safety_passed,
                        "safety_issues": result.safety_issues,
                        "usage_metrics": {
                            "tokens_used": result.tokens_used,
                            "generation_time_ms": result.generation_time_ms,
                            "cost_estimate": result.cost_estimate,
                        }
                    }
                    save_data["variants"].append(variant_data)

                output.write_text(json.dumps(save_data, indent=2))
                console.print(f"\n Results saved to {output}")

            # Show statistics
            stats = generation_service.get_generation_statistics()
            console.print("\n Session Statistics:")
            console.print(f"  • Success Rate: {stats['success_rate']:.1%}")
            console.print(f"  • Total Tokens: {stats['total_tokens_used']}")
            console.print(f"  • Total Cost: ${stats['total_cost_estimate']:.4f}")

        finally:
            await generation_service.close()

    asyncio.run(_generate())


@llm_group.command()
def list_templates():
    """List available prompt templates."""

    from ..llm.prompts import PromptEngine

    engine = PromptEngine()
    templates = engine.list_templates()

    if not templates:
        console.print("No templates found.")
        return

    table = Table(title="Available Prompt Templates")
    table.add_column("Name", style="cyan")
    table.add_column("Content Type", style="green")
    table.add_column("Variables", style="yellow")
    table.add_column("Constraints", style="blue")
    table.add_column("Examples", style="magenta")

    for template in templates:
        table.add_row(
            template["name"],
            template["content_type"],
            str(template["variable_count"]),
            str(template["constraint_count"]),
            "Yes" if template["has_examples"] else "No"
        )

    console.print(table)


@llm_group.command()
@click.argument("content_type", type=click.Choice([ct.value for ct in ContentType]))
def show_template(content_type: str):
    """Show details of a specific prompt template."""

    from ..llm.prompts import PromptEngine

    engine = PromptEngine()
    template = engine.get_template(ContentType(content_type))

    if not template:
        console.print(f" No template found for content type: {content_type}")
        return

    console.print(Panel(
        f"Name: {template.name}\n"
        f"Content Type: {template.content_type.value}\n"
        f"Variables: {len(template.variables)}\n"
        f"Constraints: {len(template.constraints)}",
        title="Template Information",
        border_style="blue"
    ))

    console.print(Panel(
        Syntax(template.system_prompt, "text", theme="monokai", word_wrap=True),
        title="System Prompt",
        border_style="green"
    ))

    console.print(Panel(
        Syntax(template.user_prompt_template, "text", theme="monokai", word_wrap=True),
        title="User Prompt Template",
        border_style="yellow"
    ))

    if template.variables:
        console.print(f"\nVariables: {', '.join(template.variables)}")

    if template.constraints:
        console.print("\nConstraints:")
        for constraint in template.constraints:
            console.print(f"  - {constraint}")


# Register the group with the main CLI
def register_llm_commands(cli_group):
    """Register LLM commands with the main CLI group."""
    cli_group.add_command(llm_group)
