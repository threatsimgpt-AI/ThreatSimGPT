"""
RAG System Configuration
========================

Configuration models for the RAG system including source
definitions, embedding settings, and retrieval parameters.
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
import os


class EmbeddingModel(Enum):
    """Supported embedding models."""
    OPENAI_SMALL = "text-embedding-3-small"
    OPENAI_LARGE = "text-embedding-3-large"
    OPENAI_ADA = "text-embedding-ada-002"
    COHERE_ENGLISH = "embed-english-v3.0"
    COHERE_MULTILINGUAL = "embed-multilingual-v3.0"
    SENTENCE_TRANSFORMERS = "all-MiniLM-L6-v2"
    BGE_SMALL = "BAAI/bge-small-en-v1.5"
    BGE_LARGE = "BAAI/bge-large-en-v1.5"


class VectorStoreType(Enum):
    """Supported vector store backends."""
    NEO4J = "neo4j"           # Primary - graph-enhanced vector search
    CHROMADB = "chromadb"     # Fallback - simple vector store
    FAISS = "faiss"           # Fallback - local vector store
    QDRANT = "qdrant"
    PINECONE = "pinecone"
    WEAVIATE = "weaviate"
    PGVECTOR = "pgvector"
    MILVUS = "milvus"


class ChunkingStrategy(Enum):
    """Text chunking strategies."""
    FIXED_SIZE = "fixed_size"
    SENTENCE = "sentence"
    PARAGRAPH = "paragraph"
    SEMANTIC = "semantic"
    RECURSIVE = "recursive"
    MARKDOWN = "markdown"
    CODE = "code"


@dataclass
class SourceConfig:
    """Configuration for an intelligence source."""
    name: str
    source_type: str
    enabled: bool = True

    # Connection
    base_url: str = ""
    api_key_env: Optional[str] = None

    # Fetch settings
    fetch_interval_hours: int = 24
    max_documents_per_fetch: int = 100
    timeout_seconds: int = 30

    # Content settings
    content_types: List[str] = field(default_factory=lambda: ["text/html", "application/json"])
    include_patterns: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(default_factory=list)

    # Quality settings
    min_content_length: int = 100
    max_content_length: int = 100000
    reliability_score: float = 0.8

    # Custom headers/auth
    headers: Dict[str, str] = field(default_factory=dict)

    @property
    def api_key(self) -> Optional[str]:
        """Get API key from environment."""
        if self.api_key_env:
            return os.environ.get(self.api_key_env)
        return None


@dataclass
class ChunkingConfig:
    """Configuration for text chunking."""
    strategy: ChunkingStrategy = ChunkingStrategy.RECURSIVE

    # Size settings
    chunk_size: int = 1000  # characters
    chunk_overlap: int = 200
    min_chunk_size: int = 100
    max_chunk_size: int = 2000

    # Semantic settings
    separators: List[str] = field(default_factory=lambda: [
        "\n\n",  # Paragraphs
        "\n",    # Lines
        ". ",    # Sentences
        ", ",    # Clauses
        " ",     # Words
    ])

    # Special handling
    preserve_code_blocks: bool = True
    preserve_tables: bool = True
    preserve_lists: bool = True

    # Metadata extraction
    extract_headers: bool = True
    extract_links: bool = True


@dataclass
class EmbeddingConfig:
    """Configuration for embeddings."""
    model: EmbeddingModel = EmbeddingModel.OPENAI_SMALL

    # Model settings
    dimensions: int = 1536  # For OpenAI small
    batch_size: int = 100
    max_retries: int = 3

    # Caching
    cache_embeddings: bool = True
    cache_ttl_hours: int = 168  # 7 days

    # Normalization
    normalize: bool = True

    # Provider-specific
    api_key_env: str = "OPENAI_API_KEY"

    @property
    def api_key(self) -> Optional[str]:
        """Get API key from environment."""
        return os.environ.get(self.api_key_env)


@dataclass
class VectorStoreConfig:
    """Configuration for vector store."""
    store_type: VectorStoreType = VectorStoreType.NEO4J  # Neo4j is default

    # Connection
    host: str = "localhost"
    port: int = 7687  # Neo4j bolt protocol port
    collection_name: str = "threatsimgpt_intelligence"

    # Persistence
    persist_directory: str = "./data/vectorstore"

    # Index settings
    distance_metric: str = "cosine"  # cosine, euclidean, dot_product
    index_type: str = "hnsw"
    ef_construction: int = 1536  # Vector dimensions for Neo4j
    ef_search: int = 100
    m: int = 16

    # Query settings
    default_top_k: int = 10
    similarity_threshold: float = 0.7

    # Neo4j specific settings
    database: str = "neo4j"
    use_graph_context: bool = True  # Enable graph-enhanced search

    # Cloud provider settings (for Pinecone, etc.)
    api_key_env: Optional[str] = "NEO4J_PASSWORD"
    environment: Optional[str] = None

    @property
    def api_key(self) -> Optional[str]:
        """Get API key/password from environment."""
        if self.api_key_env:
            return os.environ.get(self.api_key_env)
        return None


@dataclass
class RetrievalConfig:
    """Configuration for retrieval."""
    # Search settings
    top_k: int = 10
    similarity_threshold: float = 0.5

    # Hybrid search weights
    semantic_weight: float = 0.7
    keyword_weight: float = 0.3

    # Reranking
    use_reranker: bool = True
    reranker_model: str = "cross-encoder/ms-marco-MiniLM-L-6-v2"
    rerank_top_k: int = 5

    # Query expansion
    expand_query: bool = True
    max_query_terms: int = 10

    # Filtering
    filter_by_date: bool = True
    max_age_days: int = 365
    filter_by_source: List[str] = field(default_factory=list)

    # Context assembly
    max_context_tokens: int = 4000
    include_metadata: bool = True


# Alias for backwards compatibility and retriever module
RetrieverConfig = RetrievalConfig


@dataclass
class RetrieverConfig:
    """Configuration for the hybrid retriever (alias for RetrievalConfig)."""
    top_k: int = 10
    similarity_threshold: float = 0.5
    oversample_factor: int = 3

    # Query processing
    use_query_expansion: bool = True
    max_expanded_terms: int = 5

    # Reranking
    use_recency_boost: bool = True
    recency_decay_factor: float = 0.1
    use_cross_encoder: bool = False
    cross_encoder_model: str = "cross-encoder/ms-marco-MiniLM-L-6-v2"

    # Diversity
    ensure_source_diversity: bool = True
    max_per_source: int = 3


@dataclass
class GenerationConfig:
    """Configuration for playbook generation."""
    # LLM settings
    provider: str = "openai"
    model: str = "gpt-4-turbo"
    temperature: float = 0.3
    max_tokens: int = 4000

    # Generation settings
    include_citations: bool = True
    include_future_projections: bool = True
    detail_level: str = "comprehensive"

    # Prompting
    system_prompt_template: str = "tactical_playbook_generator"
    use_chain_of_thought: bool = True

    # Quality
    min_confidence_score: float = 0.7
    require_source_diversity: bool = True
    min_source_count: int = 3

    # Output
    output_format: str = "markdown"
    include_executive_summary: bool = True
    include_checklists: bool = True


@dataclass
class GeneratorConfig:
    """Configuration for the playbook generator."""
    temperature: float = 0.3
    max_output_tokens: int = 4000
    max_context_tokens: int = 6000

    # LLM settings
    provider: str = "openai"
    model: str = "gpt-4-turbo"

    # Generation settings
    include_citations: bool = True
    include_future_projections: bool = True
    detail_level: str = "comprehensive"


@dataclass
class RAGConfig:
    """
    Master configuration for the RAG system.

    Aggregates all component configurations.
    """
    # Component configs
    chunking: ChunkingConfig = field(default_factory=ChunkingConfig)
    embedding: EmbeddingConfig = field(default_factory=EmbeddingConfig)
    vectorstore: VectorStoreConfig = field(default_factory=VectorStoreConfig)
    retrieval: RetrievalConfig = field(default_factory=RetrievalConfig)
    generation: GenerationConfig = field(default_factory=GenerationConfig)

    # Sources
    sources: List[SourceConfig] = field(default_factory=list)

    # Global settings
    data_directory: str = "./data/rag"
    cache_directory: str = "./data/cache"
    log_level: str = "INFO"

    # Scheduling
    auto_refresh: bool = True
    refresh_interval_hours: int = 24

    @classmethod
    def default(cls) -> "RAGConfig":
        """Create default configuration with standard sources."""
        config = cls()
        config.sources = get_default_sources()
        return config

    @classmethod
    def from_yaml(cls, path: str) -> "RAGConfig":
        """Load configuration from YAML file."""
        import yaml
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
        return cls._from_dict(data)

    @classmethod
    def _from_dict(cls, data: Dict[str, Any]) -> "RAGConfig":
        """Create from dictionary."""
        config = cls()

        if "chunking" in data:
            config.chunking = ChunkingConfig(**data["chunking"])
        if "embedding" in data:
            config.embedding = EmbeddingConfig(**data["embedding"])
        if "vectorstore" in data:
            config.vectorstore = VectorStoreConfig(**data["vectorstore"])
        if "retrieval" in data:
            config.retrieval = RetrievalConfig(**data["retrieval"])
        if "generation" in data:
            config.generation = GenerationConfig(**data["generation"])
        if "sources" in data:
            config.sources = [SourceConfig(**s) for s in data["sources"]]

        # Global settings
        for key in ["data_directory", "cache_directory", "log_level",
                    "auto_refresh", "refresh_interval_hours"]:
            if key in data:
                setattr(config, key, data[key])

        return config

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "chunking": {
                "strategy": self.chunking.strategy.value,
                "chunk_size": self.chunking.chunk_size,
                "chunk_overlap": self.chunking.chunk_overlap,
            },
            "embedding": {
                "model": self.embedding.model.value,
                "dimensions": self.embedding.dimensions,
            },
            "vectorstore": {
                "store_type": self.vectorstore.store_type.value,
                "collection_name": self.vectorstore.collection_name,
                "persist_directory": self.vectorstore.persist_directory,
            },
            "retrieval": {
                "top_k": self.retrieval.top_k,
                "semantic_weight": self.retrieval.semantic_weight,
                "keyword_weight": self.retrieval.keyword_weight,
            },
            "generation": {
                "provider": self.generation.provider,
                "model": self.generation.model,
                "temperature": self.generation.temperature,
            },
            "sources": [
                {"name": s.name, "source_type": s.source_type, "enabled": s.enabled}
                for s in self.sources
            ],
        }


def get_default_sources() -> List[SourceConfig]:
    """
    Get default intelligence sources configuration.

    Includes trusted cybersecurity sources with proper
    attribution and reliability scores.
    """
    return [
        # NIST National Vulnerability Database
        SourceConfig(
            name="NIST NVD",
            source_type="nist_nvd",
            base_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
            api_key_env="NVD_API_KEY",
            fetch_interval_hours=6,
            max_documents_per_fetch=500,
            reliability_score=0.95,
            content_types=["application/json"],
        ),

        # MITRE ATT&CK Framework
        SourceConfig(
            name="MITRE ATT&CK",
            source_type="mitre_attack",
            base_url="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
            fetch_interval_hours=168,  # Weekly
            reliability_score=0.98,
            content_types=["application/json"],
        ),

        # CISA Advisories
        SourceConfig(
            name="CISA Advisories",
            source_type="cisa_advisory",
            base_url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            fetch_interval_hours=24,
            reliability_score=0.95,
            content_types=["application/json"],
        ),

        # CISA KEV (Known Exploited Vulnerabilities)
        SourceConfig(
            name="CISA KEV",
            source_type="cisa_advisory",
            base_url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            fetch_interval_hours=24,
            reliability_score=0.98,
            content_types=["application/json"],
        ),

        # Mandiant Threat Intelligence (requires API key)
        SourceConfig(
            name="Mandiant Threat Intel",
            source_type="threat_feed",
            base_url="https://api.mandiant.io/v4",
            api_key_env="MANDIANT_API_KEY",
            enabled=False,  # Requires subscription
            fetch_interval_hours=12,
            reliability_score=0.95,
        ),

        # AlienVault OTX
        SourceConfig(
            name="AlienVault OTX",
            source_type="threat_feed",
            base_url="https://otx.alienvault.com/api/v1",
            api_key_env="OTX_API_KEY",
            fetch_interval_hours=12,
            max_documents_per_fetch=200,
            reliability_score=0.85,
        ),

        # SANS Internet Storm Center
        SourceConfig(
            name="SANS ISC",
            source_type="security_blog",
            base_url="https://isc.sans.edu/api",
            fetch_interval_hours=6,
            reliability_score=0.90,
            content_types=["application/json", "text/xml"],
        ),

        # SecurityWeek RSS
        SourceConfig(
            name="SecurityWeek",
            source_type="security_blog",
            base_url="https://feeds.feedburner.com/securityweek",
            fetch_interval_hours=4,
            reliability_score=0.80,
            content_types=["application/rss+xml"],
        ),

        # Krebs on Security
        SourceConfig(
            name="Krebs on Security",
            source_type="security_blog",
            base_url="https://krebsonsecurity.com/feed/",
            fetch_interval_hours=12,
            reliability_score=0.85,
            content_types=["application/rss+xml"],
        ),

        # The Hacker News
        SourceConfig(
            name="The Hacker News",
            source_type="security_blog",
            base_url="https://feeds.feedburner.com/TheHackersNews",
            fetch_interval_hours=4,
            reliability_score=0.80,
            content_types=["application/rss+xml"],
        ),

        # Exploit-DB
        SourceConfig(
            name="Exploit-DB",
            source_type="cve_database",
            base_url="https://www.exploit-db.com/search?type=webapps",
            fetch_interval_hours=24,
            reliability_score=0.85,
            max_documents_per_fetch=100,
        ),

        # GitHub Security Advisories
        SourceConfig(
            name="GitHub Security Advisories",
            source_type="cve_database",
            base_url="https://api.github.com/advisories",
            api_key_env="GITHUB_TOKEN",
            fetch_interval_hours=12,
            reliability_score=0.90,
            content_types=["application/json"],
        ),

        # NIST Cybersecurity Framework
        SourceConfig(
            name="NIST CSF",
            source_type="framework_doc",
            base_url="https://www.nist.gov/cyberframework",
            fetch_interval_hours=720,  # Monthly
            reliability_score=0.98,
        ),
    ]


# Sector-specific source configurations
SECTOR_SOURCES = {
    "healthcare": [
        SourceConfig(
            name="HHS OCR Breach Portal",
            source_type="incident_report",
            base_url="https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf",
            fetch_interval_hours=24,
            reliability_score=0.95,
        ),
        SourceConfig(
            name="HIPAA Journal",
            source_type="security_blog",
            base_url="https://www.hipaajournal.com/feed/",
            fetch_interval_hours=12,
            reliability_score=0.85,
        ),
    ],
    "finance": [
        SourceConfig(
            name="FS-ISAC",
            source_type="threat_feed",
            base_url="https://www.fsisac.com/",
            api_key_env="FSISAC_API_KEY",
            enabled=False,  # Requires membership
            reliability_score=0.95,
        ),
        SourceConfig(
            name="FFIEC Guidelines",
            source_type="framework_doc",
            base_url="https://www.ffiec.gov/",
            fetch_interval_hours=720,
            reliability_score=0.98,
        ),
    ],
    "government": [
        SourceConfig(
            name="FedRAMP",
            source_type="framework_doc",
            base_url="https://www.fedramp.gov/",
            fetch_interval_hours=168,
            reliability_score=0.98,
        ),
    ],
}
