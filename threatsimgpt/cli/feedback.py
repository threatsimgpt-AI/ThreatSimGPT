"""
ThreatSimGPT Feedback Loop CLI Commands

Commands for managing the continuous improvement cycle that makes
scenarios improve playbooks and playbooks improve scenarios.
"""

import asyncio
import json
import os
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.tree import Tree
from rich import box

console = Console()


@click.group(name="feedback")
def feedback_cli():
    """Manage the continuous improvement feedback loop."""
    pass


@feedback_cli.command(name="status")
def feedback_status():
    """Show feedback loop status and improvement metrics."""

    async def _status():
        from ..feedback import FeedbackLoop

        neo4j_password = os.environ.get("NEO4J_PASSWORD")
        loop = FeedbackLoop(neo4j_password=neo4j_password)

        try:
            await loop.initialize()
            status = await loop.get_status()

            # Header panel
            console.print(Panel.fit(
                "[bold cyan]🔄 Feedback Loop Status[/bold cyan]\n"
                "[dim]Continuous improvement through analysis and learning[/dim]",
                border_style="cyan"
            ))

            # Status table
            table = Table(box=box.ROUNDED)
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")

            table.add_row("Current Phase", status["phase"])
            table.add_row("Evolution Cycles Completed", str(status["cycle_number"]))
            table.add_row("Total Scenarios Processed", str(status["total_scenarios_processed"]))
            table.add_row("Total Playbooks Processed", str(status["total_playbooks_processed"]))
            table.add_row("Total Learnings Extracted", str(status["total_learnings"]))
            table.add_row("Quality Target", f"{status['current_quality_target']:.1%}")

            if status["average_quality_improvement"]:
                improvement = status["average_quality_improvement"]
                color = "green" if improvement > 0 else "red"
                table.add_row("Avg Quality Improvement", f"[{color}]{improvement:+.1%}[/{color}]")

            console.print(table)

            # Quality trend visualization
            if status["quality_trend"]:
                console.print("\n[bold]📈 Quality Trend (Last 10 Cycles):[/bold]")
                trend = status["quality_trend"]
                max_val = max(trend) if trend else 1
                for i, val in enumerate(trend, 1):
                    bar_width = int((val / max_val) * 30)
                    bar = "█" * bar_width
                    console.print(f"  Cycle {i:2d}: [{val:.2f}] [green]{bar}[/green]")

            # Pending work
            if status["pending_feedbacks"] > 0 or status["pending_learnings"] > 0:
                console.print(f"\n[yellow]⏳ Pending: {status['pending_feedbacks']} feedbacks, {status['pending_learnings']} learnings[/yellow]")

            await loop.close()

        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            console.print("\n[dim]Make sure Neo4j is running:[/dim]")
            console.print("  docker run -d -p 7474:7474 -p 7687:7687 \\")
            console.print("    -e NEO4J_AUTH=neo4j/your_password neo4j:latest")

    asyncio.run(_status())


@feedback_cli.command(name="analyze")
@click.option("--scenario", "-s", type=click.Path(exists=True), help="Path to scenario file to analyze")
@click.option("--playbook", "-p", type=click.Path(exists=True), help="Path to playbook file to analyze")
@click.option("--pair", is_flag=True, help="Analyze scenario and playbook as a pair")
def analyze_content(scenario: Optional[str], playbook: Optional[str], pair: bool):
    """Analyze scenarios and/or playbooks for quality."""

    if not scenario and not playbook:
        console.print("[red]Please provide at least one file to analyze with --scenario or --playbook[/red]")
        return

    async def _analyze():
        import yaml
        from ..feedback import FeedbackLoop

        neo4j_password = os.environ.get("NEO4J_PASSWORD")
        loop = FeedbackLoop(neo4j_password=neo4j_password)

        try:
            await loop.initialize()

            scenario_data = None
            playbook_data = None

            if scenario:
                with open(scenario) as f:
                    scenario_data = yaml.safe_load(f)

            if playbook:
                with open(playbook) as f:
                    playbook_data = yaml.safe_load(f)

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:

                if pair and scenario_data and playbook_data:
                    task = progress.add_task("Analyzing scenario-playbook pair...", total=None)
                    scenario_id = Path(scenario).stem
                    playbook_id = Path(playbook).stem

                    s_feedback, p_feedback, insights = await loop.analyze_scenario_playbook_pair(
                        scenario_data, playbook_data, scenario_id, playbook_id
                    )
                    progress.remove_task(task)

                    _display_scenario_feedback(s_feedback)
                    _display_playbook_feedback(p_feedback)
                    _display_cross_insights(insights)

                else:
                    if scenario_data:
                        task = progress.add_task("Analyzing scenario...", total=None)
                        scenario_id = Path(scenario).stem
                        feedback = await loop.analyze_scenario(scenario_data, scenario_id)
                        progress.remove_task(task)
                        _display_scenario_feedback(feedback)

                    if playbook_data:
                        task = progress.add_task("Analyzing playbook...", total=None)
                        playbook_id = Path(playbook).stem
                        feedback = await loop.analyze_playbook(playbook_data, playbook_id)
                        progress.remove_task(task)
                        _display_playbook_feedback(feedback)

            await loop.close()

        except Exception as e:
            console.print(f"[red]Analysis failed: {e}[/red]")

    asyncio.run(_analyze())


def _display_scenario_feedback(feedback):
    """Display scenario feedback in a formatted way."""
    from ..feedback import ScenarioFeedback

    console.print(Panel.fit(
        f"[bold]Scenario Analysis: {feedback.scenario_id}[/bold]",
        border_style="blue"
    ))

    metrics = feedback.quality_metrics

    table = Table(box=box.SIMPLE)
    table.add_column("Dimension", style="cyan")
    table.add_column("Score", justify="right")
    table.add_column("Bar", style="green")

    dimensions = [
        ("Realism", metrics.realism_score),
        ("Complexity", metrics.complexity_score),
        ("Coverage", metrics.coverage_score),
        ("Engagement", metrics.engagement_score),
        ("Effectiveness", metrics.effectiveness_score),
    ]

    for name, score in dimensions:
        bar = "█" * int(score * 20)
        empty = "░" * (20 - int(score * 20))
        color = "green" if score >= 0.7 else "yellow" if score >= 0.5 else "red"
        table.add_row(name, f"[{color}]{score:.1%}[/{color}]", f"[{color}]{bar}[/{color}]{empty}")

    table.add_row("", "", "")
    table.add_row("[bold]Overall[/bold]", f"[bold]{metrics.overall_score:.1%}[/bold]", "")

    console.print(table)

    if feedback.strengths:
        console.print("\n[green]✓ Strengths:[/green]")
        for s in feedback.strengths[:3]:
            console.print(f"  • {s}")

    if feedback.weaknesses:
        console.print("\n[yellow]⚠ Areas for Improvement:[/yellow]")
        for w in feedback.weaknesses[:3]:
            console.print(f"  • {w}")


def _display_playbook_feedback(feedback):
    """Display playbook feedback in a formatted way."""
    console.print(Panel.fit(
        f"[bold]Playbook Analysis: {feedback.playbook_id}[/bold]",
        border_style="magenta"
    ))

    metrics = feedback.quality_metrics

    table = Table(box=box.SIMPLE)
    table.add_column("Dimension", style="magenta")
    table.add_column("Score", justify="right")
    table.add_column("Bar", style="green")

    dimensions = [
        ("Realism", metrics.realism_score),
        ("Complexity", metrics.complexity_score),
        ("Coverage", metrics.coverage_score),
        ("Engagement", metrics.engagement_score),
        ("Effectiveness", metrics.effectiveness_score),
    ]

    for name, score in dimensions:
        bar = "█" * int(score * 20)
        empty = "░" * (20 - int(score * 20))
        color = "green" if score >= 0.7 else "yellow" if score >= 0.5 else "red"
        table.add_row(name, f"[{color}]{score:.1%}[/{color}]", f"[{color}]{bar}[/{color}]{empty}")

    table.add_row("", "", "")
    table.add_row("[bold]Overall[/bold]", f"[bold]{metrics.overall_score:.1%}[/bold]", "")

    console.print(table)

    if feedback.strengths:
        console.print("\n[green]✓ Strengths:[/green]")
        for s in feedback.strengths[:3]:
            console.print(f"  • {s}")

    if feedback.weaknesses:
        console.print("\n[yellow]⚠ Areas for Improvement:[/yellow]")
        for w in feedback.weaknesses[:3]:
            console.print(f"  • {w}")


def _display_cross_insights(insights):
    """Display cross-analysis insights."""
    if not insights:
        return

    console.print(Panel.fit(
        "[bold]🔗 Cross-Analysis Insights[/bold]",
        border_style="yellow"
    ))

    for insight in insights[:5]:
        console.print(f"  💡 {insight.insight}")
        if insight.improvement_action:
            console.print(f"     [dim]Action: {insight.improvement_action}[/dim]")


@feedback_cli.command(name="enhance")
@click.option("--scenario", "-s", type=click.Path(exists=True), help="Path to scenario file to enhance")
@click.option("--playbook", "-p", type=click.Path(exists=True), help="Path to playbook file to enhance")
@click.option("--output", "-o", type=click.Path(), help="Output path for enhanced content")
def enhance_content(scenario: Optional[str], playbook: Optional[str], output: Optional[str]):
    """Enhance scenarios or playbooks using accumulated learnings."""

    if not scenario and not playbook:
        console.print("[red]Please provide a file to enhance with --scenario or --playbook[/red]")
        return

    async def _enhance():
        import yaml
        from ..feedback import FeedbackLoop

        neo4j_password = os.environ.get("NEO4J_PASSWORD")
        loop = FeedbackLoop(neo4j_password=neo4j_password)

        try:
            await loop.initialize()

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:

                if scenario:
                    task = progress.add_task("Enhancing scenario with learnings...", total=None)
                    with open(scenario) as f:
                        data = yaml.safe_load(f)

                    enhanced = await loop.enhance_scenario(data, Path(scenario).stem)
                    progress.remove_task(task)

                    out_path = output or scenario.replace(".yaml", "_enhanced.yaml")
                    with open(out_path, "w") as f:
                        yaml.dump(enhanced, f, default_flow_style=False)

                    console.print(f"[green]✓ Enhanced scenario saved to: {out_path}[/green]")

                elif playbook:
                    task = progress.add_task("Enhancing playbook with learnings...", total=None)
                    with open(playbook) as f:
                        data = yaml.safe_load(f)

                    enhanced = await loop.enhance_playbook(data, Path(playbook).stem)
                    progress.remove_task(task)

                    out_path = output or playbook.replace(".yaml", "_enhanced.yaml")
                    with open(out_path, "w") as f:
                        yaml.dump(enhanced, f, default_flow_style=False)

                    console.print(f"[green]✓ Enhanced playbook saved to: {out_path}[/green]")

            await loop.close()

        except Exception as e:
            console.print(f"[red]Enhancement failed: {e}[/red]")

    asyncio.run(_enhance())


@feedback_cli.command(name="cycle")
@click.option("--scenarios-dir", type=click.Path(exists=True), help="Directory containing scenario files")
@click.option("--playbooks-dir", type=click.Path(exists=True), help="Directory containing playbook files")
def run_cycle(scenarios_dir: Optional[str], playbooks_dir: Optional[str]):
    """Run a full improvement cycle on content directories."""

    async def _cycle():
        import yaml
        from ..feedback import FeedbackLoop

        neo4j_password = os.environ.get("NEO4J_PASSWORD")
        loop = FeedbackLoop(neo4j_password=neo4j_password)

        try:
            await loop.initialize()

            scenarios = []
            playbooks = []

            # Load scenarios
            if scenarios_dir:
                for f in Path(scenarios_dir).glob("*.yaml"):
                    with open(f) as file:
                        data = yaml.safe_load(file)
                        data["id"] = f.stem
                        scenarios.append(data)
                console.print(f"[cyan]Loaded {len(scenarios)} scenarios[/cyan]")

            # Load playbooks
            if playbooks_dir:
                for f in Path(playbooks_dir).glob("*.yaml"):
                    with open(f) as file:
                        data = yaml.safe_load(file)
                        data["id"] = f.stem
                        playbooks.append(data)
                console.print(f"[cyan]Loaded {len(playbooks)} playbooks[/cyan]")

            if not scenarios and not playbooks:
                console.print("[yellow]No content found to process[/yellow]")
                return

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Running improvement cycle...", total=None)

                cycle = await loop.run_improvement_cycle(scenarios, playbooks)

                progress.remove_task(task)

            # Display results
            console.print(Panel.fit(
                f"[bold green]✓ Evolution Cycle {cycle.cycle_id} Complete[/bold green]",
                border_style="green"
            ))

            table = Table(box=box.ROUNDED)
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")

            table.add_row("Scenarios Processed", str(cycle.scenarios_processed))
            table.add_row("Playbooks Processed", str(cycle.playbooks_processed))
            table.add_row("Learnings Generated", str(cycle.learnings_generated))
            table.add_row("Improvements Applied", str(cycle.improvements_applied))

            delta_color = "green" if cycle.quality_delta > 0 else "red"
            table.add_row("Quality Change", f"[{delta_color}]{cycle.quality_delta:+.1%}[/{delta_color}]")

            console.print(table)

            await loop.close()

        except Exception as e:
            console.print(f"[red]Cycle failed: {e}[/red]")

    asyncio.run(_cycle())


@feedback_cli.command(name="learnings")
@click.option("--limit", "-n", default=10, help="Number of learnings to show")
@click.option("--dimension", "-d", type=click.Choice(["realism", "complexity", "coverage", "engagement", "effectiveness"]),
              help="Filter by quality dimension")
def show_learnings(limit: int, dimension: Optional[str]):
    """Show extracted learnings from the feedback loop."""

    async def _learnings():
        from ..feedback import FeedbackLoop, QualityDimension

        neo4j_password = os.environ.get("NEO4J_PASSWORD")
        loop = FeedbackLoop(neo4j_password=neo4j_password)

        try:
            await loop.initialize()

            # Get high-impact learnings
            learnings = await loop.feedback_store.get_high_impact_learnings(limit=limit)

            if dimension:
                dim_enum = QualityDimension[dimension.upper()]
                learnings = [l for l in learnings if l.dimension == dim_enum]

            console.print(Panel.fit(
                f"[bold]📚 Top {len(learnings)} Learnings[/bold]",
                border_style="cyan"
            ))

            if not learnings:
                console.print("[yellow]No learnings found. Run some analysis cycles first.[/yellow]")
                return

            for i, learning in enumerate(learnings, 1):
                tree = Tree(f"[bold cyan]{i}. {learning.dimension.value.title()}[/bold cyan]")
                tree.add(f"[white]{learning.insight}[/white]")
                if learning.improvement_action:
                    tree.add(f"[green]→ {learning.improvement_action}[/green]")
                tree.add(f"[dim]Confidence: {learning.confidence_score:.0%} | Source: {learning.source_type}[/dim]")
                console.print(tree)
                console.print()

            await loop.close()

        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")

    asyncio.run(_learnings())


@feedback_cli.command(name="history")
@click.option("--limit", "-n", default=10, help="Number of cycles to show")
def show_history(limit: int):
    """Show evolution cycle history."""

    async def _history():
        from ..feedback import FeedbackLoop

        neo4j_password = os.environ.get("NEO4J_PASSWORD")
        loop = FeedbackLoop(neo4j_password=neo4j_password)

        try:
            await loop.initialize()

            cycles = await loop.feedback_store.get_evolution_history(limit=limit)

            console.print(Panel.fit(
                "[bold]📜 Evolution History[/bold]",
                border_style="cyan"
            ))

            if not cycles:
                console.print("[yellow]No evolution cycles found yet.[/yellow]")
                return

            table = Table(box=box.ROUNDED)
            table.add_column("Cycle", style="cyan")
            table.add_column("Date", style="dim")
            table.add_column("Scenarios", justify="right")
            table.add_column("Playbooks", justify="right")
            table.add_column("Learnings", justify="right")
            table.add_column("Quality Δ", justify="right")

            for cycle in cycles:
                delta_color = "green" if cycle.quality_delta > 0 else "red" if cycle.quality_delta < 0 else "white"
                table.add_row(
                    cycle.cycle_id,
                    cycle.completed_at.strftime("%Y-%m-%d %H:%M") if cycle.completed_at else "-",
                    str(cycle.scenarios_processed),
                    str(cycle.playbooks_processed),
                    str(cycle.learnings_generated),
                    f"[{delta_color}]{cycle.quality_delta:+.1%}[/{delta_color}]"
                )

            console.print(table)

            await loop.close()

        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")

    asyncio.run(_history())


@feedback_cli.command(name="init")
def init_feedback():
    """Initialize the feedback loop system."""

    async def _init():
        from ..feedback import FeedbackLoop

        console.print(Panel.fit(
            "[bold cyan]🔄 Initializing Feedback Loop System[/bold cyan]",
            border_style="cyan"
        ))

        neo4j_password = os.environ.get("NEO4J_PASSWORD")

        if not neo4j_password:
            console.print("[yellow]⚠ NEO4J_PASSWORD not set[/yellow]")
            console.print("\nSet it with:")
            console.print("  export NEO4J_PASSWORD=your_password")

        try:
            loop = FeedbackLoop(neo4j_password=neo4j_password)
            await loop.initialize()

            console.print("[green]✓ Neo4j connection established[/green]")
            console.print("[green]✓ Feedback store initialized[/green]")
            console.print("[green]✓ Analyzers ready[/green]")
            console.print("[green]✓ Enhancers configured[/green]")

            status = await loop.get_status()
            console.print(f"\n[cyan]Current state: {status['cycle_number']} cycles completed[/cyan]")

            await loop.close()

            console.print("\n[bold]Ready to use![/bold]")
            console.print("  threatsimgpt feedback analyze -s scenario.yaml")
            console.print("  threatsimgpt feedback enhance -p playbook.yaml")
            console.print("  threatsimgpt feedback cycle --scenarios-dir ./scenarios")

        except Exception as e:
            console.print(f"[red]Initialization failed: {e}[/red]")
            console.print("\n[dim]Make sure Neo4j is running:[/dim]")
            console.print("  docker run -d --name neo4j \\")
            console.print("    -p 7474:7474 -p 7687:7687 \\")
            console.print("    -e NEO4J_AUTH=neo4j/your_password \\")
            console.print("    neo4j:latest")

    asyncio.run(_init())
