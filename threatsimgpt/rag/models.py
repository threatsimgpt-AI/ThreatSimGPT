"""
RAG System Models
=================

Data models for the RAG system including documents, chunks,
search results, and tactical playbooks.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import hashlib
import json


class SourceType(Enum):
    """Types of intelligence sources."""
    NIST_NVD = "nist_nvd"
    MITRE_ATTACK = "mitre_attack"
    CISA_ADVISORY = "cisa_advisory"
    CVE_DATABASE = "cve_database"
    THREAT_FEED = "threat_feed"
    SECURITY_BLOG = "security_blog"
    RESEARCH_PAPER = "research_paper"
    INCIDENT_REPORT = "incident_report"
    FRAMEWORK_DOC = "framework_doc"
    CUSTOM = "custom"


class IntelligenceSource(Enum):
    """Intelligence sources for retrieval filtering."""
    MITRE_ATTACK = "mitre_attack"
    NIST_NVD = "nist_nvd"
    CISA = "cisa"
    EXPLOIT_DB = "exploit_db"
    PHISHTANK = "phishtank"
    SECURITY_BLOG = "security_blog"
    RESEARCH_PAPER = "research_paper"
    CUSTOM = "custom"


class Sector(Enum):
    """Industry sectors for playbooks."""
    HEALTHCARE = "healthcare"
    FINANCE = "finance"
    GOVERNMENT = "government"
    ENERGY = "energy"
    TECHNOLOGY = "technology"
    RETAIL = "retail"
    EDUCATION = "education"
    DEFENSE = "defense"
    TELECOMMUNICATIONS = "telecommunications"
    MANUFACTURING = "manufacturing"
    TRANSPORTATION = "transportation"
    GENERAL = "general"


class ThreatCategory(Enum):
    """Categories of threats."""
    APT = "apt"
    RANSOMWARE = "ransomware"
    PHISHING = "phishing"
    INSIDER_THREAT = "insider_threat"
    SUPPLY_CHAIN = "supply_chain"
    DDOS = "ddos"
    DATA_BREACH = "data_breach"
    MALWARE = "malware"
    ZERO_DAY = "zero_day"
    SOCIAL_ENGINEERING = "social_engineering"


class PlaybookType(Enum):
    """Types of tactical playbooks."""
    INCIDENT_RESPONSE = "incident_response"
    THREAT_HUNTING = "threat_hunting"
    VULNERABILITY_MANAGEMENT = "vulnerability_management"
    AWARENESS_TRAINING = "awareness_training"
    RED_TEAM = "red_team"
    BLUE_TEAM = "blue_team"
    COMPLIANCE = "compliance"
    FORENSICS = "forensics"


@dataclass
class Document:
    """
    A document from an intelligence source.

    Represents raw content fetched from sources like NIST, MITRE,
    CISA, security blogs, etc.
    """
    id: str
    source_type: SourceType
    source_url: str
    title: str
    content: str

    # Metadata
    author: Optional[str] = None
    published_date: Optional[datetime] = None
    fetched_date: datetime = field(default_factory=datetime.utcnow)
    language: str = "en"

    # Classification
    categories: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    threat_categories: List[ThreatCategory] = field(default_factory=list)
    sectors: List[Sector] = field(default_factory=list)

    # Technical metadata
    cve_ids: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    iocs: List[Dict[str, str]] = field(default_factory=list)

    # Quality indicators
    reliability_score: float = 0.8  # 0-1 scale
    freshness_score: float = 1.0   # Decays over time

    # Raw metadata from source
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Generate ID if not provided."""
        if not self.id:
            content_hash = hashlib.sha256(
                f"{self.source_url}{self.title}{self.content[:500]}".encode()
            ).hexdigest()[:16]
            self.id = f"doc_{content_hash}"

    @property
    def word_count(self) -> int:
        """Get word count."""
        return len(self.content.split())

    @property
    def age_days(self) -> int:
        """Get document age in days."""
        if self.published_date:
            delta = datetime.utcnow() - self.published_date
            return delta.days
        return 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "source_type": self.source_type.value,
            "source_url": self.source_url,
            "title": self.title,
            "content": self.content,
            "author": self.author,
            "published_date": self.published_date.isoformat() if self.published_date else None,
            "fetched_date": self.fetched_date.isoformat(),
            "categories": self.categories,
            "tags": self.tags,
            "cve_ids": self.cve_ids,
            "mitre_techniques": self.mitre_techniques,
            "reliability_score": self.reliability_score,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Document":
        """Create from dictionary."""
        data = data.copy()
        data["source_type"] = SourceType(data["source_type"])
        if data.get("published_date"):
            data["published_date"] = datetime.fromisoformat(data["published_date"])
        if data.get("fetched_date"):
            data["fetched_date"] = datetime.fromisoformat(data["fetched_date"])
        return cls(**data)


@dataclass
class Chunk:
    """
    A chunk of text from a document for embedding.

    Documents are split into chunks for efficient storage
    and retrieval in the vector store.
    """
    id: str
    document_id: str
    content: str

    # Position in document
    chunk_index: int
    start_char: int
    end_char: int

    # Embedding
    embedding: Optional[List[float]] = None
    embedding_model: str = "text-embedding-3-small"

    # Inherited metadata
    source_type: Optional[SourceType] = None
    source_url: str = ""
    document_title: str = ""

    # Chunk-specific metadata
    section_title: Optional[str] = None
    has_code: bool = False
    has_table: bool = False
    metadata: Optional[Dict[str, Any]] = None

    # Timestamps
    created_at: Optional[datetime] = None

    def __post_init__(self):
        """Generate ID if not provided."""
        if not self.id:
            self.id = f"{self.document_id}_chunk_{self.chunk_index}"

    @property
    def token_estimate(self) -> int:
        """Estimate token count (~4 chars per token)."""
        return len(self.content) // 4

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "document_id": self.document_id,
            "content": self.content,
            "chunk_index": self.chunk_index,
            "start_char": self.start_char,
            "end_char": self.end_char,
            "embedding_model": self.embedding_model,
            "source_url": self.source_url,
            "document_title": self.document_title,
            "section_title": self.section_title,
        }


@dataclass
class SearchResult:
    """
    A search result from the vector store.

    Contains the retrieved chunk along with relevance scores
    and metadata for ranking.
    """
    chunk: Chunk

    # Scores
    similarity_score: float  # Vector similarity (0-1)
    keyword_score: float = 0.0  # BM25 or keyword match
    combined_score: float = 0.0  # Weighted combination

    # Reranking info
    rerank_score: Optional[float] = None
    rerank_position: Optional[int] = None

    # Context
    surrounding_context: str = ""
    highlight: str = ""

    # Query metadata
    query: str = ""
    query_intent: str = ""

    def __post_init__(self):
        """Calculate combined score if not set."""
        if self.combined_score == 0.0:
            # Hybrid scoring: 70% semantic, 30% keyword
            self.combined_score = (
                0.7 * self.similarity_score +
                0.3 * self.keyword_score
            )

    @property
    def is_highly_relevant(self) -> bool:
        """Check if result is highly relevant."""
        return self.combined_score >= 0.8

    @property
    def source_citation(self) -> str:
        """Generate citation for the source."""
        return f"[{self.chunk.document_title}]({self.chunk.source_url})"


@dataclass
class TacticalContext:
    """
    Context for tactical playbook generation.

    Aggregates retrieved information for LLM generation.
    """
    query: str
    sector: Sector
    threat_category: ThreatCategory
    playbook_type: PlaybookType

    # Retrieved context
    search_results: List[SearchResult] = field(default_factory=list)

    # Extracted intelligence
    relevant_cves: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    iocs: List[Dict[str, str]] = field(default_factory=list)

    # Additional context
    regulatory_requirements: List[str] = field(default_factory=list)
    recent_incidents: List[str] = field(default_factory=list)

    # Generation parameters
    include_future_projections: bool = True
    include_citations: bool = True
    detail_level: str = "comprehensive"  # brief, standard, comprehensive

    @property
    def context_text(self) -> str:
        """Compile context text for LLM."""
        sections = []

        # Add retrieved content
        for i, result in enumerate(self.search_results[:10], 1):
            sections.append(
                f"[Source {i}: {result.chunk.document_title}]\n"
                f"{result.chunk.content}\n"
            )

        # Add MITRE techniques if present
        if self.mitre_techniques:
            sections.append(
                f"\n[Relevant MITRE ATT&CK Techniques]\n"
                f"{', '.join(self.mitre_techniques)}\n"
            )

        # Add CVEs if present
        if self.relevant_cves:
            sections.append(
                f"\n[Relevant CVEs]\n"
                f"{', '.join(self.relevant_cves)}\n"
            )

        return "\n---\n".join(sections)

    @property
    def token_estimate(self) -> int:
        """Estimate total context tokens."""
        return sum(r.chunk.token_estimate for r in self.search_results)


@dataclass
class PlaybookSection:
    """A section within a tactical playbook."""
    title: str
    content: str
    order: int = 0

    # Section metadata
    section_type: str = "content"  # overview, procedure, checklist, reference
    priority: str = "medium"  # low, medium, high, critical

    # References
    sources: List[str] = field(default_factory=list)
    mitre_mappings: List[str] = field(default_factory=list)


@dataclass
class TacticalPlaybook:
    """
    A generated tactical playbook.

    Complete playbook with procedures, checklists, and references
    for a specific threat/sector combination.
    """
    id: str
    title: str
    scenario: str  # The threat scenario this addresses
    content: str   # Full generated content

    # Classification (can be string or enum)
    sector: Optional[str] = None
    threat_category: Optional[str] = None
    playbook_type: Optional[str] = None
    audience: str = "security operations"

    # Content
    sections: List[PlaybookSection] = field(default_factory=list)

    # Executive summary
    executive_summary: str = ""
    key_takeaways: List[str] = field(default_factory=list)

    # Technical details
    prerequisites: List[str] = field(default_factory=list)
    tools_required: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)

    # Metadata
    sources: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    created_at: Optional[datetime] = None

    # Executive summary
    executive_summary: str = ""
    key_takeaways: List[str] = field(default_factory=list)

    # Technical details
    prerequisites: List[str] = field(default_factory=list)
    tools_required: List[str] = field(default_factory=list)
    estimated_time: str = ""
    difficulty_level: str = "intermediate"

    # Future projections
    emerging_threats: List[str] = field(default_factory=list)
    recommended_preparations: List[str] = field(default_factory=list)

    # Metadata
    generated_date: datetime = field(default_factory=datetime.utcnow)
    version: str = "1.0"
    last_updated: datetime = field(default_factory=datetime.utcnow)

    # Quality
    confidence_score: float = 0.0
    source_count: int = 0
    citations: List[str] = field(default_factory=list)

    def __post_init__(self):
        """Generate ID if not provided."""
        if not self.id:
            self.id = f"playbook_{self.sector.value}_{self.threat_category.value}_{self.playbook_type.value}"

    def to_markdown(self) -> str:
        """Export playbook as Markdown."""
        lines = [
            f"# {self.title}",
            "",
            f"**Sector:** {self.sector.value.title()}",
            f"**Threat Category:** {self.threat_category.value.replace('_', ' ').title()}",
            f"**Type:** {self.playbook_type.value.replace('_', ' ').title()}",
            f"**Generated:** {self.generated_date.strftime('%Y-%m-%d')}",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            self.executive_summary,
            "",
        ]

        # Key takeaways
        if self.key_takeaways:
            lines.extend([
                "### Key Takeaways",
                "",
            ])
            for takeaway in self.key_takeaways:
                lines.append(f"- {takeaway}")
            lines.append("")

        # Prerequisites
        if self.prerequisites:
            lines.extend([
                "## Prerequisites",
                "",
            ])
            for prereq in self.prerequisites:
                lines.append(f"- {prereq}")
            lines.append("")

        # Sections
        for section in sorted(self.sections, key=lambda s: s.order):
            lines.extend([
                f"## {section.title}",
                "",
                section.content,
                "",
            ])

            if section.sources:
                lines.append("**Sources:** " + ", ".join(section.sources))
                lines.append("")

        # Future projections
        if self.emerging_threats:
            lines.extend([
                "## Future Threat Landscape",
                "",
                "### Emerging Threats",
                "",
            ])
            for threat in self.emerging_threats:
                lines.append(f"- {threat}")
            lines.append("")

        if self.recommended_preparations:
            lines.extend([
                "### Recommended Preparations",
                "",
            ])
            for prep in self.recommended_preparations:
                lines.append(f"- {prep}")
            lines.append("")

        # Citations
        if self.citations:
            lines.extend([
                "---",
                "",
                "## References",
                "",
            ])
            for i, citation in enumerate(self.citations, 1):
                lines.append(f"{i}. {citation}")

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "sector": self.sector.value,
            "threat_category": self.threat_category.value,
            "playbook_type": self.playbook_type.value,
            "sections": [
                {
                    "title": s.title,
                    "content": s.content,
                    "order": s.order,
                    "section_type": s.section_type,
                }
                for s in self.sections
            ],
            "executive_summary": self.executive_summary,
            "key_takeaways": self.key_takeaways,
            "prerequisites": self.prerequisites,
            "tools_required": self.tools_required,
            "emerging_threats": self.emerging_threats,
            "recommended_preparations": self.recommended_preparations,
            "generated_date": self.generated_date.isoformat(),
            "confidence_score": self.confidence_score,
            "source_count": self.source_count,
            "citations": self.citations,
        }


@dataclass
class SectorPlaybook:
    """
    A sector-specific security playbook.

    Generated playbook containing sector-specific guidance,
    compliance mappings, and defensive recommendations.
    """
    id: str
    title: str
    sector: str
    content: str

    # Structured sections
    sections: List[PlaybookSection] = field(default_factory=list)

    # Organization context
    org_size: str = "medium"
    maturity_level: str = "developing"

    # Compliance
    compliance_frameworks: List[str] = field(default_factory=list)

    # Sources and metadata
    sources: List[str] = field(default_factory=list)
    created_at: Optional[datetime] = None

    @property
    def playbook_count(self) -> int:
        """Get section count."""
        return len(self.sections)
