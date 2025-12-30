"""
ThreatSimGPT RAG System for Tactical Manuals
============================================

A Retrieval-Augmented Generation (RAG) system that powers intelligent
tactical playbook generation using real-time intelligence from trusted
cybersecurity sources.

Architecture:
┌─────────────────────────────────────────────────────────────────────┐
│                    RAG SYSTEM ARCHITECTURE                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐        │
│  │   INGEST     │────▶│   PROCESS    │────▶│    STORE     │        │
│  │  (Crawlers)  │     │  (Chunking)  │     │ (VectorDB)   │        │
│  └──────────────┘     └──────────────┘     └──────────────┘        │
│         │                    │                    │                 │
│         ▼                    ▼                    ▼                 │
│  ┌─────────────────────────────────────────────────────────┐       │
│  │                  TRUSTED SOURCES                          │       │
│  │  • NIST (NVD, STIX/TAXII)  • MITRE ATT&CK Framework     │       │
│  │  • CISA Advisories         • CVE Database               │       │
│  │  • Mandiant Reports        • SecurityWeek, Krebs        │       │
│  │  • SANS ISC                • Threat Intelligence Feeds   │       │
│  └─────────────────────────────────────────────────────────┘       │
│                                                                      │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐        │
│  │   RETRIEVE   │◀───│    QUERY     │◀───│   GENERATE   │        │
│  │ (Semantic)   │     │  (Hybrid)    │     │   (LLM)      │        │
│  └──────────────┘     └──────────────┘     └──────────────┘        │
│                                                                      │
│                    ┌─────────────────────┐                          │
│                    │  TACTICAL PLAYBOOK  │                          │
│                    │    GENERATOR        │                          │
│                    └─────────────────────┘                          │
│                              │                                       │
│                              ▼                                       │
│  ┌─────────────────────────────────────────────────────────┐       │
│  │              SECTOR-SPECIFIC PLAYBOOKS                   │       │
│  │  • Healthcare  • Finance    • Government  • Energy       │       │
│  │  • Technology  • Retail     • Education   • Defense      │       │
│  └─────────────────────────────────────────────────────────┘       │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘

Features:
- Multi-source intelligence aggregation
- Semantic chunking with overlap
- Hybrid search (dense + sparse)
- Context-aware generation
- Sector-specific playbook templates
- Progressive futuristic thinking
- Factual grounding with citations
"""

__version__ = "1.0.0"

# Models
from .models import (
    Document,
    Chunk,
    IntelligenceSource,
    SearchResult,
    TacticalPlaybook,
    SectorPlaybook,
    PlaybookSection,
)

# Configuration
from .config import (
    RAGConfig,
    SourceConfig,
    EmbeddingConfig,
    VectorStoreConfig,
    RetrieverConfig,
    GeneratorConfig,
    EmbeddingModel,
    VectorStoreType,
)

# Ingestion
from .ingest import (
    IntelligenceIngester,
    SourceCrawler,
    TextChunker,
)

# Vector Store
from .vectorstore import (
    VectorStoreManager,
    EmbeddingService,
    VectorStoreBase,
    Neo4jStore,
    ChromaDBStore,
    FAISSStore,
)

# Retrieval
from .retriever import (
    HybridRetriever,
    QueryProcessor,
    ProcessedQuery,
    QueryIntent,
    ContextBuilder,
    RetrievalContext,
    Reranker,
    RecencyReranker,
    CrossEncoderReranker,
)

# Generation
from .generator import (
    PlaybookGenerator,
    IntelligenceRAG,
    LLMProvider,
    OpenAIProvider,
    AnthropicProvider,
    OllamaProvider,
    PromptTemplates,
)

__all__ = [
    # Models
    "Document",
    "Chunk",
    "IntelligenceSource",
    "SearchResult",
    "TacticalPlaybook",
    "SectorPlaybook",
    "PlaybookSection",
    # Config
    "RAGConfig",
    "SourceConfig",
    "EmbeddingConfig",
    "VectorStoreConfig",
    "RetrieverConfig",
    "GeneratorConfig",
    "EmbeddingModel",
    "VectorStoreType",
    # Ingestion
    "IntelligenceIngester",
    "SourceCrawler",
    "TextChunker",
    # Vector Store
    "VectorStoreManager",
    "EmbeddingService",
    "VectorStoreBase",
    "Neo4jStore",
    "ChromaDBStore",
    "FAISSStore",
    # Retrieval
    "HybridRetriever",
    "QueryProcessor",
    "ProcessedQuery",
    "QueryIntent",
    "ContextBuilder",
    "RetrievalContext",
    "Reranker",
    "RecencyReranker",
    "CrossEncoderReranker",
    # Generation
    "PlaybookGenerator",
    "IntelligenceRAG",
    "LLMProvider",
    "OpenAIProvider",
    "AnthropicProvider",
    "OllamaProvider",
    "PromptTemplates",
]
