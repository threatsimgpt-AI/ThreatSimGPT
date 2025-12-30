"""
ThreatSimGPT RAG CLI Commands
=============================

CLI commands for managing the RAG system including
intelligence ingestion, playbook generation, and search.
"""

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

import click

logger = logging.getLogger(__name__)


@click.group(name="rag")
def rag_group():
    """RAG system for tactical playbook generation."""
    pass


@rag_group.command(name="status")
def rag_status():
    """Show RAG system status and statistics."""
    click.echo("\n📊 RAG System Status")
    click.echo("=" * 50)

    # Check if vector store exists
    data_dir = Path("./data/rag")
    vectorstore_dir = Path("./data/vectorstore")

    if not data_dir.exists():
        click.echo(click.style("⚠️  RAG data directory not found", fg="yellow"))
        click.echo("   Run 'threatsimgpt rag init' to initialize")
    else:
        click.echo(click.style("✓ RAG data directory exists", fg="green"))

    if not vectorstore_dir.exists():
        click.echo(click.style("⚠️  Vector store not initialized", fg="yellow"))
    else:
        click.echo(click.style("✓ Vector store directory exists", fg="green"))

        # Count index files
        index_files = list(vectorstore_dir.glob("**/*.index")) + \
                     list(vectorstore_dir.glob("**/*.parquet"))
        if index_files:
            click.echo(f"   Index files: {len(index_files)}")

    # Show configuration
    config_path = Path("./config/rag.yaml")
    if config_path.exists():
        click.echo(click.style("✓ Configuration file found", fg="green"))
    else:
        click.echo(click.style("⚠️  Using default configuration", fg="yellow"))

    # Check Neo4j connection
    click.echo("\n🔗 Neo4j Connection:")
    import os
    neo4j_host = os.environ.get("NEO4J_HOST", "localhost")
    neo4j_port = os.environ.get("NEO4J_PORT", "7687")
    neo4j_pass = os.environ.get("NEO4J_PASSWORD", "")

    click.echo(f"   Host: {neo4j_host}:{neo4j_port}")
    if neo4j_pass:
        click.echo(click.style("   ✓ NEO4J_PASSWORD is set", fg="green"))
    else:
        click.echo(click.style("   ⚠️  NEO4J_PASSWORD not set", fg="yellow"))

    click.echo("\n📦 Dependencies:")

    # Check dependencies
    deps = [
        ("neo4j", "Neo4j graph database driver"),
        ("sentence_transformers", "Local embeddings"),
        ("openai", "OpenAI embeddings/LLM"),
        ("aiohttp", "HTTP client"),
        ("beautifulsoup4", "HTML parsing"),
        ("numpy", "Numerical computing"),
    ]

    for module, desc in deps:
        try:
            __import__(module.replace("-", "_"))
            click.echo(f"   ✓ {module} ({desc})")
        except ImportError:
            click.echo(click.style(f"   ✗ {module} ({desc}) - not installed", fg="red"))


@rag_group.command(name="init")
@click.option("--config", "-c", type=click.Path(), help="Path to configuration file")
@click.option("--force", is_flag=True, help="Force reinitialize")
def rag_init(config: Optional[str], force: bool):
    """Initialize the RAG system."""
    click.echo("\n🚀 Initializing RAG System")
    click.echo("=" * 50)

    # Create directories
    dirs = [
        Path("./data/rag"),
        Path("./data/rag/documents"),
        Path("./data/rag/cache"),
        Path("./data/vectorstore"),
        Path("./config"),
    ]

    for dir_path in dirs:
        if not dir_path.exists() or force:
            dir_path.mkdir(parents=True, exist_ok=True)
            click.echo(f"   ✓ Created {dir_path}")
        else:
            click.echo(f"   • {dir_path} already exists")

    # Create default config if not exists
    config_path = Path("./config/rag.yaml")
    if not config_path.exists() or force:
        default_config = """# ThreatSimGPT RAG Configuration
# ================================

# Embedding settings
embedding:
  model: "text-embedding-3-small"
  dimensions: 1536
  batch_size: 100
  cache_embeddings: true

# Vector store settings (Neo4j - Graph-Enhanced)
vectorstore:
  store_type: "neo4j"
  host: "localhost"
  port: 7687
  database: "neo4j"
  collection_name: "threatsimgpt_intelligence"
  distance_metric: "cosine"
  use_graph_context: true  # Enable graph-enhanced search

# Retrieval settings
retrieval:
  top_k: 10
  semantic_weight: 0.7
  keyword_weight: 0.3
  use_reranker: false

# Generation settings
generation:
  provider: "openai"
  model: "gpt-4-turbo"
  temperature: 0.3
  max_tokens: 4000
  include_citations: true

# Intelligence sources
sources:
  - name: "MITRE ATT&CK"
    source_type: "mitre_attack"
    enabled: true

  - name: "NIST NVD"
    source_type: "nist_nvd"
    enabled: true

  - name: "CISA Advisories"
    source_type: "cisa_advisory"
    enabled: true

# Scheduling
auto_refresh: false
refresh_interval_hours: 24
"""
        config_path.write_text(default_config)
        click.echo(f"   ✓ Created default config at {config_path}")

    click.echo("\n✅ RAG system initialized successfully!")
    click.echo("\nNext steps:")
    click.echo("  1. Start Neo4j database:")
    click.echo("     docker run -d --name neo4j \\")
    click.echo("       -p 7474:7474 -p 7687:7687 \\")
    click.echo("       -e NEO4J_AUTH=neo4j/password \\")
    click.echo("       neo4j:latest")
    click.echo("")
    click.echo("  2. Configure environment variables:")
    click.echo("     export NEO4J_PASSWORD=password")
    click.echo("     export OPENAI_API_KEY=your_key")
    click.echo("")
    click.echo("  3. Ingest intelligence data:")
    click.echo("     threatsimgpt rag ingest --source mitre")
    click.echo("")
    click.echo("  4. Generate a playbook:")
    click.echo("     threatsimgpt rag generate --scenario 'phishing attack'")


@rag_group.command(name="ingest")
@click.option("--source", "-s", multiple=True, help="Sources to ingest (mitre, nist, cisa)")
@click.option("--all", "ingest_all", is_flag=True, help="Ingest from all enabled sources")
@click.option("--dry-run", is_flag=True, help="Show what would be ingested")
def rag_ingest(source: tuple, ingest_all: bool, dry_run: bool):
    """Ingest intelligence from trusted sources."""
    click.echo("\n📥 Intelligence Ingestion")
    click.echo("=" * 50)

    sources_to_ingest = list(source) if source else []

    if ingest_all:
        sources_to_ingest = ["mitre", "nist", "cisa"]

    if not sources_to_ingest:
        click.echo("Specify sources with --source or use --all")
        click.echo("\nAvailable sources:")
        click.echo("  • mitre  - MITRE ATT&CK Framework")
        click.echo("  • nist   - NIST NVD (CVE Database)")
        click.echo("  • cisa   - CISA Advisories & KEV")
        return

    for src in sources_to_ingest:
        if dry_run:
            click.echo(f"[DRY RUN] Would ingest from: {src}")
        else:
            click.echo(f"\n⏳ Ingesting from {src}...")

            # Run async ingestion
            try:
                asyncio.run(_ingest_source(src))
                click.echo(click.style(f"   ✓ {src} ingested successfully", fg="green"))
            except Exception as e:
                click.echo(click.style(f"   ✗ {src} failed: {e}", fg="red"))


async def _ingest_source(source: str):
    """Async helper to ingest from a source."""
    from threatsimgpt.rag import IntelligenceIngester, RAGConfig

    config = RAGConfig.default()
    ingester = IntelligenceIngester(config)

    # Find matching source config
    for src_config in config.sources:
        if source.lower() in src_config.name.lower() or \
           source.lower() in src_config.source_type.lower():
            await ingester.ingest_source(src_config)
            return

    raise ValueError(f"Unknown source: {source}")


@rag_group.command(name="search")
@click.argument("query")
@click.option("--top-k", "-k", default=5, help="Number of results")
@click.option("--source", "-s", help="Filter by source type")
@click.option("--json-output", is_flag=True, help="Output as JSON")
def rag_search(query: str, top_k: int, source: Optional[str], json_output: bool):
    """Search the intelligence knowledge base."""
    click.echo(f"\n🔍 Searching: '{query}'")
    click.echo("=" * 50)

    try:
        results = asyncio.run(_search_intelligence(query, top_k, source))

        if json_output:
            click.echo(json.dumps(results, indent=2))
        else:
            if not results:
                click.echo("No results found.")
                return

            for i, result in enumerate(results, 1):
                click.echo(f"\n--- Result {i} ---")
                click.echo(f"Source: {result.get('source', 'Unknown')}")
                click.echo(f"Score: {result.get('score', 0):.3f}")
                click.echo(f"Content: {result.get('content', '')[:300]}...")

    except Exception as e:
        click.echo(click.style(f"Search failed: {e}", fg="red"))


async def _search_intelligence(query: str, top_k: int, source: Optional[str]):
    """Async helper to search intelligence."""
    from threatsimgpt.rag import VectorStoreManager, HybridRetriever, RAGConfig
    from threatsimgpt.rag.config import EmbeddingConfig, VectorStoreConfig, RetrieverConfig

    config = RAGConfig.default()

    # Initialize components
    store_manager = VectorStoreManager(
        config.vectorstore,
        config.embedding
    )
    await store_manager.initialize()

    retriever = HybridRetriever(
        config.retrieval,
        store_manager
    )
    await retriever.initialize()

    # Search
    results = await retriever.retrieve(query, top_k=top_k)

    return [
        {
            "source": r.chunk.source_url,
            "title": r.chunk.document_title,
            "score": r.similarity_score,
            "content": r.chunk.content,
        }
        for r in results
    ]


@rag_group.command(name="generate")
@click.option("--scenario", "-s", required=True, help="Threat scenario to address")
@click.option("--sector", help="Target sector (healthcare, finance, etc.)")
@click.option("--type", "playbook_type", default="tactical",
              type=click.Choice(["tactical", "sector"]),
              help="Type of playbook")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--format", "output_format", default="markdown",
              type=click.Choice(["markdown", "json"]),
              help="Output format")
def rag_generate(
    scenario: str,
    sector: Optional[str],
    playbook_type: str,
    output: Optional[str],
    output_format: str
):
    """Generate a tactical playbook using RAG."""
    click.echo("\n📝 Generating Playbook")
    click.echo("=" * 50)
    click.echo(f"Scenario: {scenario}")
    if sector:
        click.echo(f"Sector: {sector}")
    click.echo(f"Type: {playbook_type}")
    click.echo()

    try:
        with click.progressbar(length=4, label="Generating") as bar:
            bar.update(1)  # Initializing

            playbook = asyncio.run(_generate_playbook(
                scenario, sector, playbook_type
            ))

            bar.update(3)  # Generated

        if output_format == "json":
            content = json.dumps(playbook, indent=2, default=str)
        else:
            content = playbook.get("content", "") if isinstance(playbook, dict) else playbook.content

        if output:
            Path(output).write_text(content)
            click.echo(f"\n✓ Playbook saved to {output}")
        else:
            click.echo("\n" + content)

        click.echo(click.style("\n✅ Playbook generated successfully!", fg="green"))

    except Exception as e:
        click.echo(click.style(f"\n✗ Generation failed: {e}", fg="red"))
        raise


async def _generate_playbook(scenario: str, sector: Optional[str], playbook_type: str):
    """Async helper to generate playbook."""
    from threatsimgpt.rag import (
        IntelligenceRAG, PlaybookGenerator, HybridRetriever,
        VectorStoreManager, RAGConfig, OpenAIProvider
    )
    from threatsimgpt.rag.config import GeneratorConfig

    config = RAGConfig.default()

    # Initialize components
    store_manager = VectorStoreManager(
        config.vectorstore,
        config.embedding
    )
    await store_manager.initialize()

    retriever = HybridRetriever(
        config.retrieval,
        store_manager
    )
    await retriever.initialize()

    # Initialize LLM provider
    import os
    llm = OpenAIProvider(
        api_key=os.environ.get("OPENAI_API_KEY", ""),
        model=config.generation.model
    )

    # Initialize generator
    gen_config = GeneratorConfig(
        temperature=config.generation.temperature,
        max_output_tokens=config.generation.max_tokens,
    )
    generator = PlaybookGenerator(gen_config, retriever, llm)

    # Generate
    if playbook_type == "tactical":
        return await generator.generate_tactical_playbook(
            scenario=scenario,
            sector=sector
        )
    else:
        return await generator.generate_sector_playbook(
            sector=sector or scenario
        )


@rag_group.command(name="sources")
def rag_sources():
    """List available intelligence sources."""
    click.echo("\n📚 Intelligence Sources")
    click.echo("=" * 50)

    sources = [
        {
            "name": "MITRE ATT&CK",
            "type": "mitre_attack",
            "description": "Adversarial tactics, techniques & procedures",
            "url": "https://attack.mitre.org",
            "reliability": "98%"
        },
        {
            "name": "NIST NVD",
            "type": "nist_nvd",
            "description": "National Vulnerability Database",
            "url": "https://nvd.nist.gov",
            "reliability": "95%"
        },
        {
            "name": "CISA Advisories",
            "type": "cisa_advisory",
            "description": "Cybersecurity advisories & alerts",
            "url": "https://www.cisa.gov",
            "reliability": "95%"
        },
        {
            "name": "CISA KEV",
            "type": "cisa_kev",
            "description": "Known Exploited Vulnerabilities catalog",
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "reliability": "98%"
        },
        {
            "name": "Exploit-DB",
            "type": "exploit_db",
            "description": "Exploit database and proofs-of-concept",
            "url": "https://www.exploit-db.com",
            "reliability": "85%"
        },
        {
            "name": "PhishTank",
            "type": "phishtank",
            "description": "Community-verified phishing URLs",
            "url": "https://phishtank.org",
            "reliability": "80%"
        },
    ]

    for src in sources:
        click.echo(f"\n{src['name']}")
        click.echo(f"  Type: {src['type']}")
        click.echo(f"  Description: {src['description']}")
        click.echo(f"  URL: {src['url']}")
        click.echo(f"  Reliability: {src['reliability']}")


@rag_group.command(name="stats")
def rag_stats():
    """Show vector store statistics."""
    click.echo("\n📊 Vector Store Statistics")
    click.echo("=" * 50)

    try:
        stats = asyncio.run(_get_stats())

        click.echo(f"\nCollection: {stats.get('collection_name', 'N/A')}")
        click.echo(f"Documents: {stats.get('count', 0)}")
        click.echo(f"Storage: {stats.get('persist_directory', 'N/A')}")

    except Exception as e:
        click.echo(click.style(f"Failed to get stats: {e}", fg="red"))
        click.echo("Make sure the RAG system is initialized.")


async def _get_stats():
    """Get vector store statistics."""
    from threatsimgpt.rag import VectorStoreManager, RAGConfig

    config = RAGConfig.default()

    store_manager = VectorStoreManager(
        config.vectorstore,
        config.embedding
    )
    await store_manager.initialize()

    return await store_manager.get_stats()


# Register with main CLI
def register_rag_commands(cli):
    """Register RAG commands with main CLI."""
    cli.add_command(rag_group)
