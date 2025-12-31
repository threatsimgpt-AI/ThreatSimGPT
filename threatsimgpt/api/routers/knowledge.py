"""Knowledge Base API Router.

Provides API endpoints for managing the team knowledge base,
which stores threat intelligence, playbook insights, and
organizational context for AI-enhanced manual generation.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from enum import Enum

from fastapi import APIRouter, HTTPException, status, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/knowledge", tags=["Knowledge Base"])


# =============================================================================
# Enums
# =============================================================================

class KnowledgeCategory(str, Enum):
    """Categories of knowledge entries."""
    THREAT_INTEL = "threat_intel"
    PLAYBOOK = "playbook"
    DETECTION_RULE = "detection_rule"
    MITIGATION = "mitigation"
    INCIDENT = "incident"
    IOC = "ioc"
    TTP = "ttp"
    TOOL_CONFIG = "tool_config"
    COMPLIANCE = "compliance"
    TRAINING = "training"
    BEST_PRACTICE = "best_practice"
    LESSON_LEARNED = "lesson_learned"


class KnowledgeSource(str, Enum):
    """Sources of knowledge entries."""
    SIMULATION = "simulation"
    MANUAL_ENTRY = "manual_entry"
    EXTERNAL_FEED = "external_feed"
    INCIDENT_REPORT = "incident_report"
    THREAT_FEED = "threat_feed"
    USER_FEEDBACK = "user_feedback"
    AI_GENERATED = "ai_generated"
    MITRE_ATTACK = "mitre_attack"
    CVE_DATABASE = "cve_database"


class TeamScope(str, Enum):
    """Team scope for knowledge entries."""
    ALL_TEAMS = "all_teams"
    BLUE_TEAM = "blue_team"
    RED_TEAM = "red_team"
    PURPLE_TEAM = "purple_team"
    SOC = "soc"
    THREAT_INTEL = "threat_intel"
    GRC = "grc"
    INCIDENT_RESPONSE = "incident_response"
    SECURITY_AWARENESS = "security_awareness"


# =============================================================================
# Request/Response Models
# =============================================================================

class KnowledgeEntryCreate(BaseModel):
    """Request model for creating a knowledge entry."""
    title: str = Field(..., description="Title of the knowledge entry")
    content: str = Field(..., description="Main content of the entry")
    category: KnowledgeCategory = Field(..., description="Category of knowledge")
    source: KnowledgeSource = Field(
        default=KnowledgeSource.MANUAL_ENTRY,
        description="Source of the knowledge"
    )
    teams: List[TeamScope] = Field(
        default_factory=lambda: [TeamScope.ALL_TEAMS],
        description="Teams this knowledge applies to"
    )
    tags: List[str] = Field(default_factory=list, description="Searchable tags")
    mitre_techniques: List[str] = Field(
        default_factory=list,
        description="Related MITRE ATT&CK techniques"
    )
    severity: Optional[str] = Field(
        default=None,
        description="Severity level if applicable"
    )
    confidence: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Confidence score (0-1)"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata"
    )
    expires_at: Optional[datetime] = Field(
        default=None,
        description="When this knowledge expires (for IOCs, etc.)"
    )


class KnowledgeEntryResponse(BaseModel):
    """Response model for a knowledge entry."""
    entry_id: str
    title: str
    content: str
    category: KnowledgeCategory
    source: KnowledgeSource
    teams: List[TeamScope]
    tags: List[str]
    mitre_techniques: List[str]
    severity: Optional[str]
    confidence: float
    metadata: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
    expires_at: Optional[datetime]
    usage_count: int = 0
    relevance_score: float = 0.0


class KnowledgeSearchRequest(BaseModel):
    """Request model for searching knowledge base."""
    query: str = Field(..., description="Search query")
    categories: Optional[List[KnowledgeCategory]] = Field(
        default=None,
        description="Filter by categories"
    )
    teams: Optional[List[TeamScope]] = Field(
        default=None,
        description="Filter by teams"
    )
    tags: Optional[List[str]] = Field(
        default=None,
        description="Filter by tags"
    )
    min_confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Minimum confidence score"
    )
    use_semantic: bool = Field(
        default=True,
        description="Use semantic search (RAG)"
    )
    top_k: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Number of results to return"
    )


class KnowledgeSearchResponse(BaseModel):
    """Response model for knowledge search."""
    results: List[KnowledgeEntryResponse]
    total_matches: int
    query: str
    search_time_ms: float
    semantic_search_used: bool


class KnowledgeStatsResponse(BaseModel):
    """Response model for knowledge base statistics."""
    total_entries: int
    entries_by_category: Dict[str, int]
    entries_by_team: Dict[str, int]
    entries_by_source: Dict[str, int]
    recent_entries: int
    expiring_soon: int
    avg_confidence: float
    last_updated: Optional[datetime]


class BulkImportRequest(BaseModel):
    """Request for bulk importing knowledge entries."""
    entries: List[KnowledgeEntryCreate]
    source: KnowledgeSource = Field(default=KnowledgeSource.EXTERNAL_FEED)
    validate_only: bool = Field(
        default=False,
        description="Only validate, don't import"
    )


class BulkImportResponse(BaseModel):
    """Response for bulk import."""
    imported: int
    failed: int
    errors: List[Dict[str, Any]]
    validation_only: bool


class RAGContextRequest(BaseModel):
    """Request for retrieving RAG context for manual generation."""
    query: str = Field(..., description="Query for context retrieval")
    team: TeamScope = Field(..., description="Target team")
    threat_type: Optional[str] = Field(default=None)
    max_chunks: int = Field(default=10, ge=1, le=50)
    include_playbooks: bool = Field(default=True)
    include_incidents: bool = Field(default=True)
    include_intel: bool = Field(default=True)


class RAGContextResponse(BaseModel):
    """Response with RAG-retrieved context."""
    context_chunks: List[Dict[str, Any]]
    total_chunks: int
    relevance_scores: List[float]
    sources_used: List[str]
    retrieval_time_ms: float


# =============================================================================
# Knowledge Base Storage
# =============================================================================

class KnowledgeBaseStorage:
    """Simple file-based knowledge base storage."""

    def __init__(self, base_path: str = "generated_content/knowledge_base"):
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        self._index_file = self.base_path / "index.json"
        self._load_index()

    def _load_index(self):
        """Load the knowledge base index."""
        if self._index_file.exists():
            self._index = json.loads(self._index_file.read_text())
        else:
            self._index = {
                "entries": {},
                "categories": {},
                "teams": {},
                "tags": {},
                "last_updated": None,
            }

    def _save_index(self):
        """Save the knowledge base index."""
        self._index["last_updated"] = datetime.utcnow().isoformat()
        self._index_file.write_text(json.dumps(self._index, indent=2, default=str))

    def add_entry(self, entry_id: str, entry: Dict[str, Any]) -> bool:
        """Add a knowledge entry."""
        # Save entry file
        entry_file = self.base_path / f"{entry_id}.json"
        entry_file.write_text(json.dumps(entry, indent=2, default=str))

        # Update index
        self._index["entries"][entry_id] = {
            "title": entry["title"],
            "category": entry["category"],
            "teams": entry["teams"],
            "tags": entry.get("tags", []),
            "created_at": entry["created_at"],
        }

        # Update category index
        category = entry["category"]
        if category not in self._index["categories"]:
            self._index["categories"][category] = []
        self._index["categories"][category].append(entry_id)

        # Update team index
        for team in entry["teams"]:
            if team not in self._index["teams"]:
                self._index["teams"][team] = []
            self._index["teams"][team].append(entry_id)

        # Update tag index
        for tag in entry.get("tags", []):
            if tag not in self._index["tags"]:
                self._index["tags"][tag] = []
            self._index["tags"][tag].append(entry_id)

        self._save_index()
        return True

    def get_entry(self, entry_id: str) -> Optional[Dict[str, Any]]:
        """Get a knowledge entry by ID."""
        entry_file = self.base_path / f"{entry_id}.json"
        if entry_file.exists():
            return json.loads(entry_file.read_text())
        return None

    def update_entry(self, entry_id: str, entry: Dict[str, Any]) -> bool:
        """Update a knowledge entry."""
        entry_file = self.base_path / f"{entry_id}.json"
        if not entry_file.exists():
            return False

        entry["updated_at"] = datetime.utcnow().isoformat()
        entry_file.write_text(json.dumps(entry, indent=2, default=str))

        # Update index
        self._index["entries"][entry_id].update({
            "title": entry["title"],
            "category": entry["category"],
            "teams": entry["teams"],
            "tags": entry.get("tags", []),
        })
        self._save_index()
        return True

    def delete_entry(self, entry_id: str) -> bool:
        """Delete a knowledge entry."""
        entry_file = self.base_path / f"{entry_id}.json"
        if not entry_file.exists():
            return False

        # Get entry for cleanup
        entry = self.get_entry(entry_id)
        if entry:
            # Remove from category index
            category = entry.get("category")
            if category in self._index["categories"]:
                self._index["categories"][category] = [
                    e for e in self._index["categories"][category] if e != entry_id
                ]

            # Remove from team index
            for team in entry.get("teams", []):
                if team in self._index["teams"]:
                    self._index["teams"][team] = [
                        e for e in self._index["teams"][team] if e != entry_id
                    ]

            # Remove from tag index
            for tag in entry.get("tags", []):
                if tag in self._index["tags"]:
                    self._index["tags"][tag] = [
                        e for e in self._index["tags"][tag] if e != entry_id
                    ]

        # Remove from entries index
        if entry_id in self._index["entries"]:
            del self._index["entries"][entry_id]

        entry_file.unlink()
        self._save_index()
        return True

    def search(
        self,
        query: str,
        categories: Optional[List[str]] = None,
        teams: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        min_confidence: float = 0.0,
    ) -> List[Dict[str, Any]]:
        """Search knowledge entries."""
        results = []
        query_lower = query.lower()

        for entry_id, meta in self._index["entries"].items():
            # Category filter
            if categories and meta["category"] not in categories:
                continue

            # Team filter
            if teams:
                if not any(t in meta["teams"] for t in teams):
                    if "all_teams" not in meta["teams"]:
                        continue

            # Tag filter
            if tags:
                if not any(t in meta.get("tags", []) for t in tags):
                    continue

            # Load full entry for text search
            entry = self.get_entry(entry_id)
            if not entry:
                continue

            # Confidence filter
            if entry.get("confidence", 1.0) < min_confidence:
                continue

            # Text search
            searchable = f"{entry.get('title', '')} {entry.get('content', '')} {' '.join(entry.get('tags', []))}".lower()
            if query_lower in searchable:
                results.append(entry)

        return results

    def get_stats(self) -> Dict[str, Any]:
        """Get knowledge base statistics."""
        entries_by_category = {
            cat: len(ids) for cat, ids in self._index["categories"].items()
        }
        entries_by_team = {
            team: len(ids) for team, ids in self._index["teams"].items()
        }

        # Count recent entries (last 7 days)
        recent = 0
        cutoff = datetime.utcnow().timestamp() - (7 * 24 * 60 * 60)
        for meta in self._index["entries"].values():
            try:
                created = datetime.fromisoformat(meta["created_at"]).timestamp()
                if created > cutoff:
                    recent += 1
            except Exception:
                pass

        return {
            "total_entries": len(self._index["entries"]),
            "entries_by_category": entries_by_category,
            "entries_by_team": entries_by_team,
            "recent_entries": recent,
            "last_updated": self._index.get("last_updated"),
        }


# Global storage instance
_storage = KnowledgeBaseStorage()


# =============================================================================
# API Endpoints
# =============================================================================

@router.post("/entries", response_model=KnowledgeEntryResponse, status_code=status.HTTP_201_CREATED)
async def create_knowledge_entry(entry: KnowledgeEntryCreate):
    """
    Create a new knowledge base entry.

    Knowledge entries can include:
    - Threat intelligence (IOCs, TTPs, threat actor profiles)
    - Playbook sections and procedures
    - Detection rules (SIEM, YARA, Sigma)
    - Mitigation strategies
    - Incident reports and lessons learned
    - Tool configurations
    - Compliance requirements
    """
    import uuid

    try:
        entry_id = str(uuid.uuid4())
        now = datetime.utcnow()

        entry_data = {
            "entry_id": entry_id,
            **entry.model_dump(),
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
            "usage_count": 0,
            "relevance_score": 0.0,
        }

        # Convert enums to values
        entry_data["category"] = entry.category.value
        entry_data["source"] = entry.source.value
        entry_data["teams"] = [t.value for t in entry.teams]

        _storage.add_entry(entry_id, entry_data)

        # Also add to RAG vectorstore if enabled
        try:
            from threatsimgpt.rag.vectorstore import get_vectorstore

            vectorstore = get_vectorstore()
            await vectorstore.add_document(
                doc_id=entry_id,
                content=f"{entry.title}\n\n{entry.content}",
                metadata={
                    "category": entry.category.value,
                    "teams": [t.value for t in entry.teams],
                    "tags": entry.tags,
                    "source": "knowledge_base",
                }
            )
        except Exception as e:
            logger.warning(f"Failed to add to vectorstore: {e}")

        return KnowledgeEntryResponse(
            entry_id=entry_id,
            title=entry.title,
            content=entry.content,
            category=entry.category,
            source=entry.source,
            teams=entry.teams,
            tags=entry.tags,
            mitre_techniques=entry.mitre_techniques,
            severity=entry.severity,
            confidence=entry.confidence,
            metadata=entry.metadata,
            created_at=now,
            updated_at=now,
            expires_at=entry.expires_at,
            usage_count=0,
            relevance_score=0.0,
        )

    except Exception as e:
        logger.error(f"Failed to create knowledge entry: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create knowledge entry: {str(e)}"
        )


@router.get("/entries/{entry_id}", response_model=KnowledgeEntryResponse)
async def get_knowledge_entry(entry_id: str):
    """Get a specific knowledge entry by ID."""
    entry = _storage.get_entry(entry_id)
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Knowledge entry not found: {entry_id}"
        )

    return KnowledgeEntryResponse(
        entry_id=entry["entry_id"],
        title=entry["title"],
        content=entry["content"],
        category=KnowledgeCategory(entry["category"]),
        source=KnowledgeSource(entry["source"]),
        teams=[TeamScope(t) for t in entry["teams"]],
        tags=entry.get("tags", []),
        mitre_techniques=entry.get("mitre_techniques", []),
        severity=entry.get("severity"),
        confidence=entry.get("confidence", 0.8),
        metadata=entry.get("metadata", {}),
        created_at=datetime.fromisoformat(entry["created_at"]),
        updated_at=datetime.fromisoformat(entry["updated_at"]),
        expires_at=datetime.fromisoformat(entry["expires_at"]) if entry.get("expires_at") else None,
        usage_count=entry.get("usage_count", 0),
        relevance_score=entry.get("relevance_score", 0.0),
    )


@router.put("/entries/{entry_id}", response_model=KnowledgeEntryResponse)
async def update_knowledge_entry(entry_id: str, entry: KnowledgeEntryCreate):
    """Update an existing knowledge entry."""
    existing = _storage.get_entry(entry_id)
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Knowledge entry not found: {entry_id}"
        )

    now = datetime.utcnow()
    entry_data = {
        "entry_id": entry_id,
        **entry.model_dump(),
        "created_at": existing["created_at"],
        "updated_at": now.isoformat(),
        "usage_count": existing.get("usage_count", 0),
        "relevance_score": existing.get("relevance_score", 0.0),
    }

    # Convert enums
    entry_data["category"] = entry.category.value
    entry_data["source"] = entry.source.value
    entry_data["teams"] = [t.value for t in entry.teams]

    _storage.update_entry(entry_id, entry_data)

    return KnowledgeEntryResponse(
        entry_id=entry_id,
        title=entry.title,
        content=entry.content,
        category=entry.category,
        source=entry.source,
        teams=entry.teams,
        tags=entry.tags,
        mitre_techniques=entry.mitre_techniques,
        severity=entry.severity,
        confidence=entry.confidence,
        metadata=entry.metadata,
        created_at=datetime.fromisoformat(existing["created_at"]),
        updated_at=now,
        expires_at=entry.expires_at,
        usage_count=existing.get("usage_count", 0),
        relevance_score=existing.get("relevance_score", 0.0),
    )


@router.delete("/entries/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_knowledge_entry(entry_id: str):
    """Delete a knowledge entry."""
    if not _storage.delete_entry(entry_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Knowledge entry not found: {entry_id}"
        )


@router.post("/search", response_model=KnowledgeSearchResponse)
async def search_knowledge(request: KnowledgeSearchRequest):
    """
    Search the knowledge base.

    Supports both keyword search and semantic (RAG) search.
    Results can be filtered by category, team, tags, and confidence score.
    """
    import time

    start_time = time.time()

    try:
        categories = [c.value for c in request.categories] if request.categories else None
        teams = [t.value for t in request.teams] if request.teams else None

        results = _storage.search(
            query=request.query,
            categories=categories,
            teams=teams,
            tags=request.tags,
            min_confidence=request.min_confidence,
        )

        # Limit results
        results = results[:request.top_k]

        # Convert to response models
        response_results = []
        for entry in results:
            response_results.append(KnowledgeEntryResponse(
                entry_id=entry["entry_id"],
                title=entry["title"],
                content=entry["content"],
                category=KnowledgeCategory(entry["category"]),
                source=KnowledgeSource(entry["source"]),
                teams=[TeamScope(t) for t in entry["teams"]],
                tags=entry.get("tags", []),
                mitre_techniques=entry.get("mitre_techniques", []),
                severity=entry.get("severity"),
                confidence=entry.get("confidence", 0.8),
                metadata=entry.get("metadata", {}),
                created_at=datetime.fromisoformat(entry["created_at"]),
                updated_at=datetime.fromisoformat(entry["updated_at"]),
                expires_at=datetime.fromisoformat(entry["expires_at"]) if entry.get("expires_at") else None,
                usage_count=entry.get("usage_count", 0),
                relevance_score=entry.get("relevance_score", 0.0),
            ))

        search_time = (time.time() - start_time) * 1000

        return KnowledgeSearchResponse(
            results=response_results,
            total_matches=len(results),
            query=request.query,
            search_time_ms=search_time,
            semantic_search_used=request.use_semantic,
        )

    except Exception as e:
        logger.error(f"Knowledge search failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Search failed: {str(e)}"
        )


@router.get("/stats", response_model=KnowledgeStatsResponse)
async def get_knowledge_stats():
    """Get knowledge base statistics."""
    stats = _storage.get_stats()

    # Calculate entries by source (need to iterate entries)
    entries_by_source: Dict[str, int] = {}
    total_confidence = 0.0
    expiring_soon = 0
    expiry_cutoff = datetime.utcnow().timestamp() + (7 * 24 * 60 * 60)

    for entry_id in _storage._index["entries"]:
        entry = _storage.get_entry(entry_id)
        if entry:
            source = entry.get("source", "unknown")
            entries_by_source[source] = entries_by_source.get(source, 0) + 1
            total_confidence += entry.get("confidence", 0.8)

            if entry.get("expires_at"):
                try:
                    exp = datetime.fromisoformat(entry["expires_at"]).timestamp()
                    if exp < expiry_cutoff:
                        expiring_soon += 1
                except Exception:
                    pass

    avg_confidence = total_confidence / max(stats["total_entries"], 1)

    return KnowledgeStatsResponse(
        total_entries=stats["total_entries"],
        entries_by_category=stats["entries_by_category"],
        entries_by_team=stats["entries_by_team"],
        entries_by_source=entries_by_source,
        recent_entries=stats["recent_entries"],
        expiring_soon=expiring_soon,
        avg_confidence=avg_confidence,
        last_updated=datetime.fromisoformat(stats["last_updated"]) if stats.get("last_updated") else None,
    )


@router.post("/bulk-import", response_model=BulkImportResponse)
async def bulk_import_knowledge(request: BulkImportRequest):
    """
    Bulk import knowledge entries.

    Useful for importing threat intel feeds, incident databases,
    or migrating from other systems.
    """
    import uuid

    imported = 0
    failed = 0
    errors = []

    for i, entry in enumerate(request.entries):
        try:
            if not request.validate_only:
                entry_id = str(uuid.uuid4())
                now = datetime.utcnow()

                entry_data = {
                    "entry_id": entry_id,
                    **entry.model_dump(),
                    "source": request.source.value,
                    "created_at": now.isoformat(),
                    "updated_at": now.isoformat(),
                    "usage_count": 0,
                    "relevance_score": 0.0,
                }

                entry_data["category"] = entry.category.value
                entry_data["teams"] = [t.value for t in entry.teams]

                _storage.add_entry(entry_id, entry_data)

            imported += 1

        except Exception as e:
            failed += 1
            errors.append({
                "index": i,
                "title": entry.title,
                "error": str(e),
            })

    return BulkImportResponse(
        imported=imported,
        failed=failed,
        errors=errors,
        validation_only=request.validate_only,
    )


@router.post("/rag-context", response_model=RAGContextResponse)
async def get_rag_context(request: RAGContextRequest):
    """
    Retrieve RAG context for manual/playbook generation.

    This endpoint queries the knowledge base and vectorstore
    to retrieve relevant context chunks for AI-enhanced content generation.
    """
    import time

    start_time = time.time()
    context_chunks = []
    sources_used = set()

    try:
        # Query knowledge base
        categories = []
        if request.include_playbooks:
            categories.append("playbook")
        if request.include_incidents:
            categories.append("incident")
            categories.append("lesson_learned")
        if request.include_intel:
            categories.append("threat_intel")
            categories.append("ioc")
            categories.append("ttp")

        kb_results = _storage.search(
            query=request.query,
            categories=categories,
            teams=[request.team.value, "all_teams"],
        )

        # Add KB results to context
        for entry in kb_results[:request.max_chunks]:
            context_chunks.append({
                "content": entry["content"],
                "title": entry["title"],
                "source": "knowledge_base",
                "category": entry["category"],
                "metadata": entry.get("metadata", {}),
            })
            sources_used.add("knowledge_base")

        # Try RAG vectorstore
        try:
            from threatsimgpt.rag.retriever import HybridRetriever
            from threatsimgpt.rag.config import RetrieverConfig

            retriever = HybridRetriever(RetrieverConfig())
            rag_results = await retriever.retrieve(
                query=f"{request.query} {request.team.value}",
                top_k=request.max_chunks,
            )

            for result in rag_results:
                if len(context_chunks) < request.max_chunks:
                    context_chunks.append({
                        "content": result.chunk.content,
                        "title": result.chunk.source,
                        "source": "vectorstore",
                        "score": result.score,
                        "metadata": result.chunk.metadata,
                    })
                    sources_used.add("vectorstore")

        except Exception as e:
            logger.warning(f"RAG retrieval failed: {e}")

        retrieval_time = (time.time() - start_time) * 1000

        return RAGContextResponse(
            context_chunks=context_chunks,
            total_chunks=len(context_chunks),
            relevance_scores=[c.get("score", 0.8) for c in context_chunks],
            sources_used=list(sources_used),
            retrieval_time_ms=retrieval_time,
        )

    except Exception as e:
        logger.error(f"RAG context retrieval failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Context retrieval failed: {str(e)}"
        )


@router.get("/teams/{team}/entries", response_model=List[KnowledgeEntryResponse])
async def get_team_knowledge(
    team: TeamScope,
    category: Optional[KnowledgeCategory] = None,
    limit: int = Query(default=50, ge=1, le=200),
):
    """Get all knowledge entries for a specific team."""
    categories = [category.value] if category else None

    results = _storage.search(
        query="",
        categories=categories,
        teams=[team.value],
    )

    response_results = []
    for entry in results[:limit]:
        response_results.append(KnowledgeEntryResponse(
            entry_id=entry["entry_id"],
            title=entry["title"],
            content=entry["content"],
            category=KnowledgeCategory(entry["category"]),
            source=KnowledgeSource(entry["source"]),
            teams=[TeamScope(t) for t in entry["teams"]],
            tags=entry.get("tags", []),
            mitre_techniques=entry.get("mitre_techniques", []),
            severity=entry.get("severity"),
            confidence=entry.get("confidence", 0.8),
            metadata=entry.get("metadata", {}),
            created_at=datetime.fromisoformat(entry["created_at"]),
            updated_at=datetime.fromisoformat(entry["updated_at"]),
            expires_at=datetime.fromisoformat(entry["expires_at"]) if entry.get("expires_at") else None,
            usage_count=entry.get("usage_count", 0),
            relevance_score=entry.get("relevance_score", 0.0),
        ))

    return response_results
