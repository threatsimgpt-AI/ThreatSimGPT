"""
RAG Playbook Generator
======================

LLM-powered generator for creating tactical threat playbooks
using retrieved intelligence context.
"""

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

from .models import (
    TacticalPlaybook,
    SectorPlaybook,
    PlaybookSection,
    SearchResult,
    IntelligenceSource,
)
from .config import GeneratorConfig
from .retriever import RetrievalContext, HybridRetriever

logger = logging.getLogger(__name__)


# ==========================================
# Prompt Templates
# ==========================================

class PromptTemplates:
    """Collection of prompt templates for playbook generation."""

    TACTICAL_PLAYBOOK = """You are a cybersecurity threat intelligence analyst creating a tactical playbook.

Based on the following intelligence context, create a comprehensive tactical playbook for the threat scenario: "{scenario}"

INTELLIGENCE CONTEXT:
{context}

Create a detailed playbook with:
1. EXECUTIVE SUMMARY: Brief overview of the threat (2-3 sentences)
2. THREAT PROFILE: Key characteristics, TTPs, and indicators
3. DETECTION STRATEGIES: Specific detection methods and signatures
4. MITIGATION STEPS: Prioritized defensive actions
5. RESPONSE PROCEDURES: Incident response steps
6. REFERENCES: Cite the provided sources

Target Audience: {audience}
Sector Focus: {sector}

Format the playbook in a clear, actionable structure. Be specific and technical where appropriate.
Include MITRE ATT&CK technique IDs where relevant.
"""

    SECTOR_PLAYBOOK = """You are creating a sector-specific security playbook for the {sector} industry.

Based on the following threat intelligence:
{context}

Create a comprehensive sector playbook that addresses:
1. SECTOR OVERVIEW: Unique risk profile and regulatory requirements
2. COMMON THREAT VECTORS: Most prevalent attacks targeting this sector
3. CRITICAL ASSETS: Key systems and data requiring protection
4. COMPLIANCE MAPPING: Relevant regulations (HIPAA, PCI-DSS, etc.)
5. DEFENSE FRAMEWORK: Layered security recommendations
6. DETECTION PRIORITIES: What to monitor and alert on
7. RESPONSE PLAYBOOKS: Sector-specific incident response

Sector: {sector}
Organization Size: {org_size}
Maturity Level: {maturity}

Be practical and actionable. Prioritize recommendations by impact and feasibility.
"""

    TECHNIQUE_ANALYSIS = """Analyze the following MITRE ATT&CK technique based on current threat intelligence:

TECHNIQUE: {technique_id} - {technique_name}

INTELLIGENCE CONTEXT:
{context}

Provide:
1. TECHNIQUE OVERVIEW: What this technique involves
2. RECENT USAGE: How threat actors are using this technique
3. DETECTION OPPORTUNITIES: Specific detection methods
4. PREVENTION CONTROLS: Security controls to prevent this technique
5. HUNTING QUERIES: Example queries for threat hunting
6. RELATED TECHNIQUES: Connected techniques in attack chains

Be specific and include practical examples.
"""

    THREAT_BRIEF = """Create an intelligence brief on the following threat:

THREAT: {threat_name}

INTELLIGENCE CONTEXT:
{context}

Structure the brief as:
1. BOTTOM LINE UP FRONT (BLUF): Key findings in 2-3 sentences
2. THREAT ASSESSMENT: Current threat level and trajectory
3. TECHNICAL ANALYSIS: TTPs, infrastructure, and indicators
4. TARGETING PROFILE: Who this threat targets and why
5. RECOMMENDED ACTIONS: Prioritized defensive measures
6. CONFIDENCE ASSESSMENT: Source reliability and analysis confidence

Classification: {classification}
Distribution: {distribution}
"""

    QUERY_DECOMPOSITION = """Given the user's question about cybersecurity threats:

QUESTION: {question}

Break this down into 3-5 specific sub-questions that would help comprehensively answer the original question.
Focus on:
- Specific threat techniques and TTPs
- Detection and prevention methods
- Relevant threat actors or campaigns
- Industry-specific considerations

Return the sub-questions as a JSON array of strings.
"""


# ==========================================
# LLM Provider Interface
# ==========================================

class LLMProvider(ABC):
    """Abstract interface for LLM providers."""

    @abstractmethod
    async def generate(
        self,
        prompt: str,
        temperature: float = 0.7,
        max_tokens: int = 2000
    ) -> str:
        """Generate text from prompt."""
        pass


class OpenAIProvider(LLMProvider):
    """OpenAI GPT provider."""

    def __init__(self, api_key: str, model: str = "gpt-4"):
        self.api_key = api_key
        self.model = model
        self._client = None

    async def initialize(self):
        """Initialize OpenAI client."""
        try:
            from openai import AsyncOpenAI
            self._client = AsyncOpenAI(api_key=self.api_key)
        except ImportError:
            raise RuntimeError("OpenAI package not installed")

    async def generate(
        self,
        prompt: str,
        temperature: float = 0.7,
        max_tokens: int = 2000
    ) -> str:
        """Generate using OpenAI."""
        if not self._client:
            await self.initialize()

        response = await self._client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=temperature,
            max_tokens=max_tokens
        )

        return response.choices[0].message.content


class AnthropicProvider(LLMProvider):
    """Anthropic Claude provider."""

    def __init__(self, api_key: str, model: str = "claude-3-sonnet-20240229"):
        self.api_key = api_key
        self.model = model
        self._client = None

    async def initialize(self):
        """Initialize Anthropic client."""
        try:
            import anthropic
            self._client = anthropic.AsyncAnthropic(api_key=self.api_key)
        except ImportError:
            raise RuntimeError("Anthropic package not installed")

    async def generate(
        self,
        prompt: str,
        temperature: float = 0.7,
        max_tokens: int = 2000
    ) -> str:
        """Generate using Claude."""
        if not self._client:
            await self.initialize()

        response = await self._client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text


class OllamaProvider(LLMProvider):
    """Local Ollama provider."""

    def __init__(self, model: str = "llama2", base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url

    async def generate(
        self,
        prompt: str,
        temperature: float = 0.7,
        max_tokens: int = 2000
    ) -> str:
        """Generate using Ollama."""
        import aiohttp

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "options": {
                        "temperature": temperature,
                        "num_predict": max_tokens
                    },
                    "stream": False
                }
            ) as response:
                result = await response.json()
                return result.get("response", "")


# ==========================================
# Playbook Generator
# ==========================================

class PlaybookGenerator:
    """
    Generates tactical threat playbooks using RAG.

    Features:
    - Multi-query retrieval for comprehensive context
    - LLM-powered synthesis
    - Multiple playbook types
    - Source citation
    - Confidence scoring
    """

    def __init__(
        self,
        config: GeneratorConfig,
        retriever: HybridRetriever,
        llm_provider: LLMProvider
    ):
        self.config = config
        self.retriever = retriever
        self.llm = llm_provider
        self.templates = PromptTemplates()

    async def generate_tactical_playbook(
        self,
        scenario: str,
        sector: Optional[str] = None,
        audience: str = "security operations",
        top_k: int = 10
    ) -> TacticalPlaybook:
        """
        Generate a tactical playbook for a threat scenario.

        Args:
            scenario: Description of the threat scenario
            sector: Target industry sector
            audience: Target audience for the playbook
            top_k: Number of context chunks to retrieve

        Returns:
            TacticalPlaybook with generated content
        """
        logger.info(f"Generating tactical playbook for: {scenario}")

        # Generate sub-queries for comprehensive retrieval
        sub_queries = await self._decompose_query(scenario)

        # Retrieve context
        results = await self.retriever.multi_query_retrieve(
            queries=[scenario] + sub_queries,
            top_k=top_k
        )

        # Build context
        from .retriever import ContextBuilder
        builder = ContextBuilder(max_tokens=self.config.max_context_tokens)
        context = builder.build_context(results, include_citations=True)

        # Generate playbook
        prompt = self.templates.TACTICAL_PLAYBOOK.format(
            scenario=scenario,
            context=context.context_text,
            audience=audience,
            sector=sector or "general"
        )

        content = await self.llm.generate(
            prompt,
            temperature=self.config.temperature,
            max_tokens=self.config.max_output_tokens
        )

        # Parse generated content into sections
        sections = self._parse_playbook_content(content)

        # Calculate confidence
        confidence = self._calculate_confidence(results, context)

        return TacticalPlaybook(
            id=f"playbook-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            title=f"Tactical Playbook: {scenario[:50]}",
            scenario=scenario,
            content=content,
            sections=sections,
            sources=context.sources,
            techniques=context.techniques,
            confidence_score=confidence,
            created_at=datetime.now(),
            sector=sector,
            audience=audience
        )

    async def generate_sector_playbook(
        self,
        sector: str,
        org_size: str = "medium",
        maturity: str = "developing"
    ) -> SectorPlaybook:
        """
        Generate a sector-specific security playbook.

        Args:
            sector: Industry sector (healthcare, finance, etc.)
            org_size: Organization size (small, medium, large)
            maturity: Security maturity level

        Returns:
            SectorPlaybook with sector-specific guidance
        """
        logger.info(f"Generating sector playbook for: {sector}")

        # Sector-specific queries
        queries = [
            f"{sector} industry cyber threats",
            f"{sector} regulatory compliance security",
            f"{sector} common attack vectors",
            f"{sector} data protection requirements",
            f"APT groups targeting {sector}"
        ]

        # Retrieve sector-specific intelligence
        results = await self.retriever.multi_query_retrieve(
            queries=queries,
            top_k=15
        )

        # Build context
        from .retriever import ContextBuilder
        builder = ContextBuilder(max_tokens=self.config.max_context_tokens)
        context = builder.build_context(results)

        # Generate playbook
        prompt = self.templates.SECTOR_PLAYBOOK.format(
            sector=sector,
            context=context.context_text,
            org_size=org_size,
            maturity=maturity
        )

        content = await self.llm.generate(
            prompt,
            temperature=self.config.temperature,
            max_tokens=self.config.max_output_tokens
        )

        sections = self._parse_playbook_content(content)

        return SectorPlaybook(
            id=f"sector-{sector.lower()}-{datetime.now().strftime('%Y%m%d')}",
            title=f"{sector} Sector Security Playbook",
            sector=sector,
            content=content,
            sections=sections,
            sources=context.sources,
            org_size=org_size,
            maturity_level=maturity,
            created_at=datetime.now(),
            compliance_frameworks=self._detect_compliance(sector)
        )

    async def analyze_technique(
        self,
        technique_id: str,
        technique_name: str = ""
    ) -> Dict[str, Any]:
        """
        Generate detailed analysis of a MITRE ATT&CK technique.

        Args:
            technique_id: MITRE technique ID (e.g., T1566)
            technique_name: Human-readable technique name

        Returns:
            Dictionary with technique analysis
        """
        logger.info(f"Analyzing technique: {technique_id}")

        # Retrieve technique-specific intelligence
        queries = [
            f"MITRE {technique_id} technique",
            f"{technique_id} detection",
            f"{technique_id} prevention",
            f"threat actors using {technique_id}"
        ]

        results = await self.retriever.multi_query_retrieve(
            queries=queries,
            top_k=10
        )

        from .retriever import ContextBuilder
        builder = ContextBuilder(max_tokens=self.config.max_context_tokens)
        context = builder.build_context(results)

        prompt = self.templates.TECHNIQUE_ANALYSIS.format(
            technique_id=technique_id,
            technique_name=technique_name or technique_id,
            context=context.context_text
        )

        content = await self.llm.generate(
            prompt,
            temperature=self.config.temperature,
            max_tokens=self.config.max_output_tokens
        )

        return {
            "technique_id": technique_id,
            "technique_name": technique_name,
            "analysis": content,
            "sources": context.sources,
            "related_techniques": context.techniques,
            "generated_at": datetime.now().isoformat()
        }

    async def create_threat_brief(
        self,
        threat_name: str,
        classification: str = "TLP:GREEN",
        distribution: str = "internal"
    ) -> Dict[str, Any]:
        """
        Create an intelligence brief for a specific threat.

        Args:
            threat_name: Name of the threat/campaign/actor
            classification: Classification level
            distribution: Distribution restrictions

        Returns:
            Dictionary with threat brief
        """
        logger.info(f"Creating threat brief: {threat_name}")

        queries = [
            threat_name,
            f"{threat_name} indicators",
            f"{threat_name} TTPs",
            f"{threat_name} targets"
        ]

        results = await self.retriever.multi_query_retrieve(
            queries=queries,
            top_k=12
        )

        from .retriever import ContextBuilder
        builder = ContextBuilder(max_tokens=self.config.max_context_tokens)
        context = builder.build_context(results)

        prompt = self.templates.THREAT_BRIEF.format(
            threat_name=threat_name,
            context=context.context_text,
            classification=classification,
            distribution=distribution
        )

        content = await self.llm.generate(
            prompt,
            temperature=self.config.temperature,
            max_tokens=self.config.max_output_tokens
        )

        return {
            "threat_name": threat_name,
            "brief": content,
            "classification": classification,
            "distribution": distribution,
            "sources": context.sources,
            "cves": context.cves,
            "techniques": context.techniques,
            "generated_at": datetime.now().isoformat()
        }

    async def _decompose_query(self, query: str) -> List[str]:
        """Decompose a complex query into sub-queries."""
        prompt = self.templates.QUERY_DECOMPOSITION.format(question=query)

        try:
            response = await self.llm.generate(
                prompt,
                temperature=0.3,
                max_tokens=500
            )

            # Parse JSON response
            # Try to extract JSON array from response
            import re
            json_match = re.search(r'\[.*\]', response, re.DOTALL)
            if json_match:
                sub_queries = json.loads(json_match.group())
                return sub_queries[:5]
        except Exception as e:
            logger.warning(f"Query decomposition failed: {e}")

        return []

    def _parse_playbook_content(self, content: str) -> List[PlaybookSection]:
        """Parse generated content into structured sections."""
        sections = []

        # Common section headers
        section_patterns = [
            ("EXECUTIVE SUMMARY", "summary"),
            ("THREAT PROFILE", "threat_profile"),
            ("DETECTION STRATEGIES", "detection"),
            ("DETECTION", "detection"),
            ("MITIGATION STEPS", "mitigation"),
            ("MITIGATION", "mitigation"),
            ("RESPONSE PROCEDURES", "response"),
            ("RESPONSE", "response"),
            ("REFERENCES", "references"),
            ("SECTOR OVERVIEW", "overview"),
            ("COMMON THREAT VECTORS", "threats"),
            ("CRITICAL ASSETS", "assets"),
            ("COMPLIANCE MAPPING", "compliance"),
            ("DEFENSE FRAMEWORK", "defense"),
            ("DETECTION PRIORITIES", "detection"),
            ("RESPONSE PLAYBOOKS", "response"),
        ]

        current_section = None
        current_content = []

        for line in content.split('\n'):
            # Check if line is a section header
            found_header = False
            for pattern, section_type in section_patterns:
                if pattern in line.upper():
                    # Save previous section
                    if current_section:
                        sections.append(PlaybookSection(
                            title=current_section,
                            content='\n'.join(current_content).strip(),
                            section_type=current_section.lower().replace(' ', '_')
                        ))

                    current_section = pattern.title()
                    current_content = []
                    found_header = True
                    break

            if not found_header and current_section:
                current_content.append(line)

        # Save last section
        if current_section:
            sections.append(PlaybookSection(
                title=current_section,
                content='\n'.join(current_content).strip(),
                section_type=current_section.lower().replace(' ', '_')
            ))

        return sections

    def _calculate_confidence(
        self,
        results: List[SearchResult],
        context: RetrievalContext
    ) -> float:
        """Calculate confidence score for generated playbook."""
        if not results:
            return 0.3

        # Average similarity score
        avg_similarity = sum(r.similarity_score for r in results) / len(results)

        # Source diversity bonus
        unique_sources = len(set(context.sources))
        diversity_bonus = min(unique_sources * 0.05, 0.2)

        # Technique extraction bonus
        technique_bonus = min(len(context.techniques) * 0.02, 0.1)

        confidence = min(avg_similarity + diversity_bonus + technique_bonus, 1.0)

        return round(confidence, 2)

    def _detect_compliance(self, sector: str) -> List[str]:
        """Detect relevant compliance frameworks for a sector."""
        compliance_map = {
            "healthcare": ["HIPAA", "HITECH", "NIST CSF"],
            "finance": ["PCI-DSS", "SOX", "GLBA", "NIST CSF"],
            "government": ["FISMA", "FedRAMP", "NIST 800-53"],
            "retail": ["PCI-DSS", "CCPA", "GDPR"],
            "education": ["FERPA", "COPPA", "NIST CSF"],
            "energy": ["NERC CIP", "NIST CSF"],
            "manufacturing": ["ICS-CERT", "NIST CSF"],
        }

        sector_lower = sector.lower()
        for key, frameworks in compliance_map.items():
            if key in sector_lower:
                return frameworks

        return ["NIST CSF", "ISO 27001"]


# ==========================================
# RAG Pipeline
# ==========================================

class IntelligenceRAG:
    """
    Main RAG pipeline for threat intelligence.

    Orchestrates:
    - Document ingestion
    - Vector storage
    - Hybrid retrieval
    - Playbook generation
    """

    def __init__(
        self,
        vector_store_manager: Any,
        retriever: HybridRetriever,
        generator: PlaybookGenerator
    ):
        self.vector_store = vector_store_manager
        self.retriever = retriever
        self.generator = generator

    async def query(
        self,
        question: str,
        top_k: int = 5
    ) -> Dict[str, Any]:
        """
        Answer a threat intelligence question.

        Args:
            question: User's question
            top_k: Number of sources to use

        Returns:
            Answer with sources
        """
        # Retrieve relevant context
        results = await self.retriever.retrieve(question, top_k=top_k)

        if not results:
            return {
                "answer": "I couldn't find relevant information to answer your question.",
                "sources": [],
                "confidence": 0.0
            }

        # Build context
        from .retriever import ContextBuilder
        builder = ContextBuilder()
        context = builder.build_context(results)

        # Generate answer
        prompt = f"""Based on the following threat intelligence context, answer the question.

CONTEXT:
{context.context_text}

QUESTION: {question}

Provide a clear, accurate answer based on the provided context.
If the context doesn't contain enough information, say so.
Cite specific sources where appropriate using [1], [2], etc.
"""

        answer = await self.generator.llm.generate(
            prompt,
            temperature=0.3,
            max_tokens=1000
        )

        return {
            "answer": answer,
            "sources": context.sources,
            "techniques": context.techniques,
            "confidence": self.generator._calculate_confidence(results, context)
        }

    async def generate_playbook(
        self,
        scenario: str,
        playbook_type: str = "tactical",
        **kwargs
    ) -> Any:
        """
        Generate a playbook based on type.

        Args:
            scenario: Threat scenario or sector
            playbook_type: Type of playbook (tactical, sector)
            **kwargs: Additional parameters

        Returns:
            Generated playbook
        """
        if playbook_type == "tactical":
            return await self.generator.generate_tactical_playbook(
                scenario=scenario,
                **kwargs
            )
        elif playbook_type == "sector":
            return await self.generator.generate_sector_playbook(
                sector=scenario,
                **kwargs
            )
        else:
            raise ValueError(f"Unknown playbook type: {playbook_type}")

    async def get_stats(self) -> Dict[str, Any]:
        """Get RAG system statistics."""
        store_stats = await self.vector_store.get_stats()

        return {
            "vector_store": store_stats,
            "generator_config": {
                "temperature": self.generator.config.temperature,
                "max_context_tokens": self.generator.config.max_context_tokens,
            }
        }
