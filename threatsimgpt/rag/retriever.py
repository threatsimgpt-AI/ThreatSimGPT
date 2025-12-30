"""
RAG Retriever Module
====================

Hybrid retrieval system combining semantic search with keyword-based
filtering for optimal threat intelligence retrieval.
"""

import asyncio
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from .models import Chunk, SearchResult, IntelligenceSource
from .config import RetrieverConfig

logger = logging.getLogger(__name__)


# ==========================================
# Query Processing
# ==========================================

class QueryIntent(Enum):
    """Types of query intent."""
    THREAT_LOOKUP = "threat_lookup"
    TECHNIQUE_SEARCH = "technique_search"
    INDICATOR_SEARCH = "indicator_search"
    VULNERABILITY_SEARCH = "vulnerability_search"
    PLAYBOOK_REQUEST = "playbook_request"
    MITIGATION_REQUEST = "mitigation_request"
    GENERAL = "general"


@dataclass
class ProcessedQuery:
    """Processed and enriched query."""
    original_query: str
    normalized_query: str
    intent: QueryIntent
    entities: Dict[str, List[str]]
    keywords: List[str]
    filters: Dict[str, Any]
    expanded_terms: List[str]
    confidence: float


class QueryProcessor:
    """
    Processes and enriches queries for optimal retrieval.

    Features:
    - Entity extraction (TTPs, CVEs, threat actors)
    - Query expansion using synonyms
    - Intent classification
    - Filter generation
    """

    # MITRE ATT&CK patterns
    TECHNIQUE_PATTERN = re.compile(r'T\d{4}(?:\.\d{3})?', re.IGNORECASE)
    TACTIC_PATTERN = re.compile(r'TA\d{4}', re.IGNORECASE)

    # CVE patterns
    CVE_PATTERN = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)

    # Threat intelligence keywords
    THREAT_KEYWORDS = {
        'phishing', 'ransomware', 'malware', 'botnet', 'ddos',
        'apt', 'backdoor', 'trojan', 'worm', 'exploit', 'vulnerability',
        'credential', 'exfiltration', 'lateral', 'persistence', 'privilege',
        'spear', 'whaling', 'vishing', 'smishing', 'bec', 'fraud',
    }

    # Synonym expansions
    SYNONYMS = {
        'phishing': ['phish', 'credential harvest', 'email lure'],
        'ransomware': ['crypto locker', 'encryption malware', 'extortion'],
        'malware': ['malicious software', 'virus', 'trojan'],
        'lateral movement': ['pivoting', 'network traversal'],
        'persistence': ['maintain access', 'implant'],
        'exfiltration': ['data theft', 'data exfil', 'data leak'],
    }

    def __init__(self, config: RetrieverConfig):
        self.config = config

    def process(self, query: str) -> ProcessedQuery:
        """Process and enrich a query."""
        # Normalize
        normalized = self._normalize(query)

        # Extract entities
        entities = self._extract_entities(query)

        # Extract keywords
        keywords = self._extract_keywords(normalized)

        # Classify intent
        intent = self._classify_intent(normalized, entities, keywords)

        # Expand query
        expanded = self._expand_query(keywords)

        # Generate filters
        filters = self._generate_filters(entities, intent)

        # Calculate confidence
        confidence = self._calculate_confidence(entities, keywords)

        return ProcessedQuery(
            original_query=query,
            normalized_query=normalized,
            intent=intent,
            entities=entities,
            keywords=keywords,
            filters=filters,
            expanded_terms=expanded,
            confidence=confidence
        )

    def _normalize(self, query: str) -> str:
        """Normalize query text."""
        # Lowercase
        normalized = query.lower().strip()

        # Remove extra whitespace
        normalized = re.sub(r'\s+', ' ', normalized)

        return normalized

    def _extract_entities(self, query: str) -> Dict[str, List[str]]:
        """Extract named entities from query."""
        entities = {
            'techniques': [],
            'tactics': [],
            'cves': [],
            'threat_actors': [],
        }

        # Extract MITRE techniques
        techniques = self.TECHNIQUE_PATTERN.findall(query)
        entities['techniques'] = [t.upper() for t in techniques]

        # Extract MITRE tactics
        tactics = self.TACTIC_PATTERN.findall(query)
        entities['tactics'] = [t.upper() for t in tactics]

        # Extract CVEs
        cves = self.CVE_PATTERN.findall(query)
        entities['cves'] = [c.upper() for c in cves]

        return entities

    def _extract_keywords(self, normalized: str) -> List[str]:
        """Extract threat intelligence keywords."""
        words = set(normalized.split())
        keywords = []

        for keyword in self.THREAT_KEYWORDS:
            if keyword in normalized:
                keywords.append(keyword)
            elif any(keyword in word for word in words):
                keywords.append(keyword)

        return keywords

    def _classify_intent(
        self,
        normalized: str,
        entities: Dict[str, List[str]],
        keywords: List[str]
    ) -> QueryIntent:
        """Classify query intent."""
        # Check for technique lookup
        if entities['techniques'] or entities['tactics']:
            return QueryIntent.TECHNIQUE_SEARCH

        # Check for CVE lookup
        if entities['cves']:
            return QueryIntent.VULNERABILITY_SEARCH

        # Check for playbook request
        playbook_terms = ['playbook', 'procedure', 'response', 'detect', 'mitigate']
        if any(term in normalized for term in playbook_terms):
            return QueryIntent.PLAYBOOK_REQUEST

        # Check for mitigation request
        mitigation_terms = ['prevent', 'protect', 'defend', 'secure', 'harden']
        if any(term in normalized for term in mitigation_terms):
            return QueryIntent.MITIGATION_REQUEST

        # Check for indicator search
        indicator_terms = ['indicator', 'ioc', 'hash', 'domain', 'ip']
        if any(term in normalized for term in indicator_terms):
            return QueryIntent.INDICATOR_SEARCH

        # Check for general threat lookup
        if keywords:
            return QueryIntent.THREAT_LOOKUP

        return QueryIntent.GENERAL

    def _expand_query(self, keywords: List[str]) -> List[str]:
        """Expand query with synonyms."""
        expanded = []

        for keyword in keywords:
            if keyword in self.SYNONYMS:
                expanded.extend(self.SYNONYMS[keyword])

        return expanded

    def _generate_filters(
        self,
        entities: Dict[str, List[str]],
        intent: QueryIntent
    ) -> Dict[str, Any]:
        """Generate metadata filters based on entities and intent."""
        filters = {}

        if entities['techniques']:
            filters['technique_ids'] = entities['techniques']

        if entities['tactics']:
            filters['tactic_ids'] = entities['tactics']

        if entities['cves']:
            filters['cve_ids'] = entities['cves']

        # Add source type filters based on intent
        if intent == QueryIntent.VULNERABILITY_SEARCH:
            filters['source_type'] = ['nist_nvd', 'cisa']
        elif intent == QueryIntent.TECHNIQUE_SEARCH:
            filters['source_type'] = ['mitre_attack']

        return filters

    def _calculate_confidence(
        self,
        entities: Dict[str, List[str]],
        keywords: List[str]
    ) -> float:
        """Calculate query understanding confidence."""
        score = 0.5  # Base score

        # Boost for entities
        entity_count = sum(len(v) for v in entities.values())
        score += min(entity_count * 0.1, 0.3)

        # Boost for keywords
        score += min(len(keywords) * 0.05, 0.2)

        return min(score, 1.0)


# ==========================================
# Reranking
# ==========================================

class Reranker(ABC):
    """Abstract base class for result rerankers."""

    @abstractmethod
    async def rerank(
        self,
        query: str,
        results: List[SearchResult]
    ) -> List[SearchResult]:
        """Rerank search results."""
        pass


class RecencyReranker(Reranker):
    """Reranker that boosts recent documents."""

    def __init__(self, decay_factor: float = 0.1):
        self.decay_factor = decay_factor

    async def rerank(
        self,
        query: str,
        results: List[SearchResult]
    ) -> List[SearchResult]:
        """Boost scores for recent documents."""
        now = datetime.now()

        for result in results:
            if result.chunk.created_at:
                age_days = (now - result.chunk.created_at).days
                recency_boost = 1.0 / (1.0 + self.decay_factor * age_days)
                result.similarity_score *= recency_boost

        # Re-sort by score
        return sorted(results, key=lambda r: r.similarity_score, reverse=True)


class CrossEncoderReranker(Reranker):
    """Reranker using cross-encoder model for precise relevance scoring."""

    def __init__(self, model_name: str = "cross-encoder/ms-marco-MiniLM-L-6-v2"):
        self.model_name = model_name
        self._model = None

    async def initialize(self):
        """Initialize cross-encoder model."""
        try:
            from sentence_transformers import CrossEncoder
            self._model = CrossEncoder(self.model_name)
            logger.info(f"Initialized CrossEncoder: {self.model_name}")
        except ImportError:
            raise RuntimeError("sentence-transformers not installed")

    async def rerank(
        self,
        query: str,
        results: List[SearchResult]
    ) -> List[SearchResult]:
        """Rerank using cross-encoder."""
        if not self._model:
            await self.initialize()

        if not results:
            return results

        # Create pairs for cross-encoder
        pairs = [(query, r.chunk.content) for r in results]

        # Score pairs
        scores = self._model.predict(pairs)

        # Update scores
        for result, score in zip(results, scores):
            # Combine semantic and cross-encoder scores
            result.similarity_score = 0.3 * result.similarity_score + 0.7 * float(score)

        # Re-sort
        return sorted(results, key=lambda r: r.similarity_score, reverse=True)


# ==========================================
# Hybrid Retriever
# ==========================================

class HybridRetriever:
    """
    Hybrid retrieval system combining multiple retrieval strategies.

    Features:
    - Semantic search using embeddings
    - Keyword-based filtering
    - Query expansion
    - Result reranking
    - Source diversity
    """

    def __init__(
        self,
        config: RetrieverConfig,
        vector_store_manager: Any  # VectorStoreManager
    ):
        self.config = config
        self.vector_store = vector_store_manager

        self._query_processor = QueryProcessor(config)
        self._rerankers: List[Reranker] = []

    async def initialize(self):
        """Initialize retriever components."""
        # Add rerankers based on config
        if self.config.use_recency_boost:
            self._rerankers.append(RecencyReranker(
                decay_factor=self.config.recency_decay_factor
            ))

        if self.config.use_cross_encoder:
            cross_encoder = CrossEncoderReranker(self.config.cross_encoder_model)
            await cross_encoder.initialize()
            self._rerankers.append(cross_encoder)

        logger.info("Initialized HybridRetriever")

    async def retrieve(
        self,
        query: str,
        top_k: Optional[int] = None,
        filters: Optional[Dict[str, Any]] = None,
        sources: Optional[List[IntelligenceSource]] = None
    ) -> List[SearchResult]:
        """
        Retrieve relevant documents for a query.

        Args:
            query: Search query
            top_k: Number of results to return
            filters: Metadata filters
            sources: Limit to specific sources

        Returns:
            List of search results
        """
        top_k = top_k or self.config.top_k

        # Process query
        processed = self._query_processor.process(query)

        logger.debug(f"Query intent: {processed.intent.value}")
        logger.debug(f"Extracted entities: {processed.entities}")

        # Build search query
        search_query = processed.normalized_query

        # Add expanded terms if configured
        if self.config.use_query_expansion and processed.expanded_terms:
            expansion = ' '.join(processed.expanded_terms[:3])
            search_query = f"{search_query} {expansion}"

        # Merge filters
        combined_filters = {**(filters or {}), **processed.filters}

        # Add source filters
        if sources:
            combined_filters['source'] = [s.value for s in sources]

        # Perform initial retrieval with oversampling
        oversample_k = top_k * self.config.oversample_factor

        results = await self.vector_store.search(
            query=search_query,
            top_k=oversample_k,
            filters=combined_filters if combined_filters else None
        )

        # Apply rerankers
        for reranker in self._rerankers:
            results = await reranker.rerank(query, results)

        # Apply diversity if configured
        if self.config.ensure_source_diversity:
            results = self._ensure_diversity(results, top_k)

        # Truncate to top_k
        results = results[:top_k]

        # Update result metadata
        for result in results:
            result.query = query
            result.query_intent = processed.intent.value

        logger.info(f"Retrieved {len(results)} results for query: {query[:50]}...")

        return results

    async def multi_query_retrieve(
        self,
        queries: List[str],
        top_k: Optional[int] = None
    ) -> List[SearchResult]:
        """
        Retrieve using multiple query variations.

        Useful for improving recall by searching with
        different phrasings of the same question.
        """
        top_k = top_k or self.config.top_k

        # Retrieve for each query
        all_results: Dict[str, SearchResult] = {}

        for query in queries:
            results = await self.retrieve(query, top_k=top_k)

            for result in results:
                chunk_id = result.chunk.id
                if chunk_id in all_results:
                    # Boost score for repeated results
                    all_results[chunk_id].similarity_score = max(
                        all_results[chunk_id].similarity_score,
                        result.similarity_score * 1.1
                    )
                else:
                    all_results[chunk_id] = result

        # Sort by score
        results = sorted(
            all_results.values(),
            key=lambda r: r.similarity_score,
            reverse=True
        )

        return results[:top_k]

    async def contextual_retrieve(
        self,
        query: str,
        context_chunks: List[Chunk],
        top_k: Optional[int] = None
    ) -> List[SearchResult]:
        """
        Retrieve with additional context from existing chunks.

        Useful for follow-up questions that reference
        previously retrieved content.
        """
        # Build contextual query
        context_summary = ' '.join([
            c.content[:100] for c in context_chunks[:3]
        ])

        contextual_query = f"{query} Context: {context_summary}"

        return await self.retrieve(contextual_query, top_k=top_k)

    def _ensure_diversity(
        self,
        results: List[SearchResult],
        top_k: int
    ) -> List[SearchResult]:
        """Ensure diverse sources in results."""
        diverse_results = []
        source_counts: Dict[str, int] = {}
        max_per_source = max(2, top_k // 3)

        for result in results:
            source = result.chunk.source_url or "unknown"

            current_count = source_counts.get(source, 0)
            if current_count < max_per_source:
                diverse_results.append(result)
                source_counts[source] = current_count + 1

            if len(diverse_results) >= top_k:
                break

        return diverse_results


# ==========================================
# Context Builder
# ==========================================

@dataclass
class RetrievalContext:
    """Context assembled from retrieval results."""
    chunks: List[Chunk]
    context_text: str
    sources: List[str]
    total_tokens: int
    techniques: List[str]
    cves: List[str]
    query_intent: str


class ContextBuilder:
    """
    Builds optimized context from retrieval results.

    Features:
    - Token budget management
    - Deduplication
    - Source citation
    - Coherent ordering
    """

    def __init__(self, max_tokens: int = 4000):
        self.max_tokens = max_tokens

    def build_context(
        self,
        results: List[SearchResult],
        include_citations: bool = True
    ) -> RetrievalContext:
        """Build context from search results."""
        chunks = []
        context_parts = []
        sources = set()
        techniques = set()
        cves = set()
        total_tokens = 0

        for i, result in enumerate(results):
            chunk = result.chunk

            # Estimate tokens (rough: 4 chars per token)
            chunk_tokens = len(chunk.content) // 4

            if total_tokens + chunk_tokens > self.max_tokens:
                break

            chunks.append(chunk)

            # Build citation
            if include_citations:
                citation = f"[{i+1}] Source: {chunk.source_url or 'Unknown'}"
                context_parts.append(citation)

            context_parts.append(chunk.content)
            context_parts.append("")  # Blank line separator

            sources.add(chunk.source_url or "unknown")
            total_tokens += chunk_tokens

            # Extract techniques and CVEs from metadata
            if hasattr(chunk, 'metadata') and chunk.metadata:
                if 'technique_id' in chunk.metadata:
                    techniques.add(chunk.metadata['technique_id'])
                if 'cve_id' in chunk.metadata:
                    cves.add(chunk.metadata['cve_id'])

        context_text = '\n'.join(context_parts)

        return RetrievalContext(
            chunks=chunks,
            context_text=context_text,
            sources=list(sources),
            total_tokens=total_tokens,
            techniques=list(techniques),
            cves=list(cves),
            query_intent=results[0].query_intent if results else "unknown"
        )
