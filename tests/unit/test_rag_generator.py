"""
Unit tests for RAG generator module.

Tests the IntelligenceRAG.generate_playbook() transformative implementation
that performs the COMPLETE RAG pipeline: retrieve → augment → generate → enrich.

Issue: #121 - Redesign RAGSystem.generate_playbook() wrapper
"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
from typing import List, Optional
from dataclasses import dataclass, field


# Mock dataclasses to avoid importing full RAG module with heavy dependencies
@dataclass
class MockChunk:
    """Mock Chunk for testing (mirrors threatsimgpt.rag.models.Chunk)."""
    id: str
    document_id: str
    content: str
    chunk_index: int = 0
    start_char: int = 0
    end_char: int = 0
    source_url: str = ""
    document_title: str = ""
    embedding: Optional[List[float]] = None
    embedding_model: str = "text-embedding-3-small"
    section_title: Optional[str] = None
    has_code: bool = False
    has_table: bool = False
    metadata: Optional[dict] = None
    created_at: Optional[datetime] = None


@dataclass
class MockSearchResult:
    """Mock SearchResult for testing (mirrors threatsimgpt.rag.models.SearchResult)."""
    chunk: MockChunk
    similarity_score: float
    keyword_score: float = 0.0
    combined_score: float = 0.0
    query: str = ""
    query_intent: str = ""
    surrounding_context: str = ""
    highlight: str = ""


@dataclass
class MockRetrievalContext:
    """Mock RetrievalContext for testing."""
    context_text: str
    sources: List[str]
    techniques: List[str]
    cves: List[str] = field(default_factory=list)
    token_count: int = 500


@dataclass
class MockPlaybookSection:
    """Mock PlaybookSection for testing."""
    title: str
    content: str
    section_type: str


@dataclass
class MockTacticalPlaybook:
    """Mock TacticalPlaybook for testing."""
    id: str
    title: str
    scenario: str
    content: str
    sections: List[MockPlaybookSection]
    sources: List[str]
    techniques: List[str]
    confidence_score: float
    created_at: datetime
    sector: str = None
    audience: str = ""
    rag_metadata: dict = None
    cves: List[str] = field(default_factory=list)


@dataclass
class MockSectorPlaybook:
    """Mock SectorPlaybook for testing."""
    id: str
    title: str
    sector: str
    content: str
    sections: List[MockPlaybookSection]
    sources: List[str]
    org_size: str
    maturity_level: str
    created_at: datetime
    compliance_frameworks: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    rag_metadata: dict = None


# Test fixtures
@pytest.fixture
def mock_retrieval_results():
    """Create mock retrieval results with realistic threat intelligence."""
    return [
        MockSearchResult(
            chunk=MockChunk(
                id="chunk-001",
                document_id="doc-001",
                content="Ransomware attack T1566 phishing initial access vector used by APT29...",
                source_url="https://attack.mitre.org/techniques/T1566/",
                document_title="MITRE ATT&CK",
                metadata={"technique": "T1566", "category": "Initial Access"}
            ),
            similarity_score=0.92,
            combined_score=0.92
        ),
        MockSearchResult(
            chunk=MockChunk(
                id="chunk-002",
                document_id="doc-002",
                content="Detection strategy: Monitor for suspicious email attachments T1566.001...",
                source_url="https://www.cisa.gov/advisory",
                document_title="CISA Advisory",
                metadata={"technique": "T1566.001"}
            ),
            similarity_score=0.88,
            combined_score=0.88
        ),
        MockSearchResult(
            chunk=MockChunk(
                id="chunk-003",
                document_id="doc-003",
                content="Mitigation: Employee security awareness training reduces phishing risk by 70%...",
                source_url="https://www.nist.gov/csf",
                document_title="NIST CSF",
                metadata={"framework": "NIST"}
            ),
            similarity_score=0.85,
            combined_score=0.85
        ),
        MockSearchResult(
            chunk=MockChunk(
                id="chunk-004",
                document_id="doc-004",
                content="Lateral movement techniques T1021 following initial compromise...",
                source_url="https://attack.mitre.org/techniques/T1021/",
                document_title="MITRE ATT&CK",
                metadata={"technique": "T1021"}
            ),
            similarity_score=0.82,
            combined_score=0.82
        ),
    ]


@pytest.fixture
def mock_context():
    """Create mock retrieval context with extracted techniques."""
    return MockRetrievalContext(
        context_text="Combined intelligence context with MITRE ATT&CK mappings and IOCs...",
        sources=["MITRE ATT&CK", "CISA Advisory", "NIST CSF"],
        techniques=["T1566", "T1566.001", "T1021"],
        cves=["CVE-2024-1234"],
        token_count=800
    )


@pytest.fixture
def mock_llm_provider():
    """Create mock LLM provider that returns realistic playbook content."""
    provider = AsyncMock()
    provider.generate = AsyncMock(return_value="""
# Executive Summary

This tactical playbook addresses ransomware attacks via phishing, a critical threat vector
targeting organizations across all sectors. The attack typically begins with T1566 (Phishing)
followed by lateral movement via T1021.

## Threat Profile

- **Primary Technique**: T1566 - Phishing
- **Threat Actors**: APT29, FIN7
- **Target Sectors**: Healthcare, Finance

## Detection Strategies

1. Monitor email gateway for suspicious attachments
2. Implement DMARC/DKIM/SPF email authentication
3. Deploy endpoint detection for T1566.001 indicators

## Mitigation Steps

1. Security awareness training (reduces risk by 70%)
2. Email filtering and sandboxing
3. Network segmentation to limit lateral movement

## Response Procedures

1. Isolate affected systems immediately
2. Preserve evidence for forensic analysis
3. Notify incident response team

## References

[1] MITRE ATT&CK T1566
[2] CISA Advisory on Phishing
[3] NIST CSF Framework
""")
    return provider


@pytest.fixture
def mock_generator_config():
    """Create mock generator configuration."""
    config = MagicMock()
    config.max_context_tokens = 4000
    config.temperature = 0.7
    config.max_output_tokens = 2000
    return config


@pytest.fixture
def mock_templates():
    """Create mock prompt templates."""
    templates = MagicMock()
    templates.TACTICAL_PLAYBOOK = "Tactical playbook for {scenario}\nContext: {context}\nAudience: {audience}\nSector: {sector}"
    templates.SECTOR_PLAYBOOK = "Sector playbook for {sector}\nContext: {context}\nOrg Size: {org_size}\nMaturity: {maturity}"
    return templates


@pytest.fixture
def mock_generator(mock_generator_config, mock_templates, mock_llm_provider):
    """Create mock PlaybookGenerator with complete configuration."""
    generator = MagicMock()
    generator.config = mock_generator_config
    generator.templates = mock_templates
    generator.llm = mock_llm_provider
    generator._parse_playbook_content = MagicMock(return_value=[
        MockPlaybookSection("Executive Summary", "content", "summary"),
        MockPlaybookSection("Threat Profile", "content", "threat_profile"),
        MockPlaybookSection("Detection Strategies", "content", "detection"),
        MockPlaybookSection("Mitigation Steps", "content", "mitigation"),
    ])
    generator._detect_compliance = MagicMock(return_value=["HIPAA", "NIST CSF"])
    generator._calculate_confidence = MagicMock(return_value=0.85)
    return generator


@pytest.fixture
def mock_retriever(mock_retrieval_results):
    """Create mock HybridRetriever."""
    retriever = AsyncMock()
    retriever.multi_query_retrieve = AsyncMock(return_value=mock_retrieval_results)
    return retriever


@pytest.fixture
def mock_vector_store():
    """Create mock VectorStoreManager."""
    store = AsyncMock()
    store.get_stats = AsyncMock(return_value={"total_vectors": 10000})
    return store


@pytest.fixture
def intelligence_rag(mock_vector_store, mock_retriever, mock_generator):
    """Create IntelligenceRAG instance with mocks."""
    with patch.dict('sys.modules', {
        'numpy': MagicMock(),
        'chromadb': MagicMock(),
        'sentence_transformers': MagicMock(),
    }):
        from threatsimgpt.rag.generator import IntelligenceRAG
        
        rag = IntelligenceRAG(
            vector_store_manager=mock_vector_store,
            retriever=mock_retriever,
            generator=mock_generator
        )
    
    return rag


class TestIntelligenceRAGGeneratePlaybook:
    """Tests for IntelligenceRAG.generate_playbook() transformative implementation."""

    @pytest.mark.asyncio
    async def test_generate_tactical_playbook_executes_full_rag_pipeline(
        self,
        intelligence_rag,
        mock_retriever,
        mock_generator,
        mock_context
    ):
        """Test that tactical playbook generation executes complete RAG pipeline."""
        with patch('threatsimgpt.rag.retriever.ContextBuilder') as MockBuilder:
            mock_builder_instance = MagicMock()
            mock_builder_instance.build_context.return_value = mock_context
            MockBuilder.return_value = mock_builder_instance
            
            playbook = await intelligence_rag.generate_playbook(
                scenario="Ransomware attack via phishing T1566",
                playbook_type="tactical",
                top_k=10,
                sector="healthcare",
                audience="incident responders"
            )
            
            # VERIFY: Retrieval was executed (Phase 2)
            mock_retriever.multi_query_retrieve.assert_called_once()
            call_args = mock_retriever.multi_query_retrieve.call_args
            queries = call_args.kwargs.get('queries', [])
            
            # Verify intelligent query expansion
            assert len(queries) >= 4, "Should generate multiple queries for comprehensive retrieval"
            assert any("T1566" in q for q in queries), "Should include MITRE technique in queries"
            assert any("detection" in q.lower() for q in queries), "Should include detection-focused query"
            assert any("mitigation" in q.lower() for q in queries), "Should include mitigation-focused query"
            
            # VERIFY: LLM was called directly (Phase 4 - not through generator's internal retrieval)
            mock_generator.llm.generate.assert_called_once()
            prompt_call = mock_generator.llm.generate.call_args
            prompt = prompt_call.args[0] if prompt_call.args else prompt_call.kwargs.get('prompt', '')
            
            # Verify prompt contains retrieved context
            assert "Ransomware attack" in prompt or "scenario" in prompt.lower()
            
            # VERIFY: Playbook was returned with full metadata (Phase 5)
            assert playbook is not None
            assert "tactical" in playbook.id.lower()
            assert playbook.scenario == "Ransomware attack via phishing T1566"
            assert playbook.rag_metadata is not None, "Should include RAG metadata"
            assert "retrieval_sources" in playbook.rag_metadata
            
    @pytest.mark.asyncio
    async def test_generate_sector_playbook_executes_full_rag_pipeline(
        self,
        intelligence_rag,
        mock_retriever,
        mock_generator,
        mock_context
    ):
        """Test that sector playbook generation uses sector-specific queries."""
        with patch('threatsimgpt.rag.retriever.ContextBuilder') as MockBuilder:
            mock_builder_instance = MagicMock()
            mock_builder_instance.build_context.return_value = mock_context
            MockBuilder.return_value = mock_builder_instance
            
            playbook = await intelligence_rag.generate_playbook(
                scenario="healthcare",
                playbook_type="sector",
                top_k=15,
                org_size="large",
                maturity="mature"
            )
            
            # Verify sector-specific queries were generated
            call_args = mock_retriever.multi_query_retrieve.call_args
            queries = call_args.kwargs.get('queries', [])
            
            query_text = " ".join(queries).lower()
            assert "healthcare" in query_text, "Should include sector in queries"
            assert "compliance" in query_text, "Should include compliance query for sector"
            assert "threats" in query_text or "attack" in query_text, "Should include threat query"
            
            # Verify compliance frameworks were detected
            mock_generator._detect_compliance.assert_called()

    @pytest.mark.asyncio
    async def test_generate_playbook_invalid_type_raises_error(
        self,
        intelligence_rag
    ):
        """Test that invalid playbook type raises ValueError immediately."""
        with pytest.raises(ValueError) as exc_info:
            await intelligence_rag.generate_playbook(
                scenario="test scenario",
                playbook_type="invalid_type"
            )
        
        assert "Unknown playbook type" in str(exc_info.value)
        assert "invalid_type" in str(exc_info.value)
        assert "tactical" in str(exc_info.value)
        assert "sector" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_generate_playbook_handles_empty_retrieval_gracefully(
        self,
        intelligence_rag,
        mock_retriever,
        mock_generator
    ):
        """Test graceful degradation when retrieval returns no results."""
        # Setup empty retrieval
        mock_retriever.multi_query_retrieve.return_value = []
        
        playbook = await intelligence_rag.generate_playbook(
            scenario="obscure threat scenario",
            playbook_type="tactical"
        )
        
        # Should still generate playbook with minimal context
        mock_generator.llm.generate.assert_called_once()
        assert playbook is not None
        
        # Verify degraded mode is indicated
        assert playbook.rag_metadata is not None
        assert playbook.rag_metadata.get("degraded_mode", False) is True

    @pytest.mark.asyncio
    async def test_generate_playbook_retry_on_llm_failure(
        self,
        intelligence_rag,
        mock_retriever,
        mock_generator,
        mock_context
    ):
        """Test retry logic when LLM generation fails."""
        with patch('threatsimgpt.rag.retriever.ContextBuilder') as MockBuilder:
            mock_builder_instance = MagicMock()
            mock_builder_instance.build_context.return_value = mock_context
            MockBuilder.return_value = mock_builder_instance
            
            # First two calls fail, third succeeds with content > 100 chars
            valid_playbook_content = (
                "# Executive Summary\n\n"
                "This is a comprehensive tactical playbook that provides detailed guidance "
                "for addressing ransomware attacks using phishing vectors. "
                "The playbook includes detection strategies, mitigation recommendations, "
                "and response procedures based on MITRE ATT&CK framework."
            )
            mock_generator.llm.generate.side_effect = [
                Exception("Rate limited"),
                Exception("Timeout"),
                valid_playbook_content
            ]
            
            playbook = await intelligence_rag.generate_playbook(
                scenario="test scenario",
                playbook_type="tactical"
            )
            
            # Should have retried 3 times
            assert mock_generator.llm.generate.call_count == 3
            assert playbook is not None

    @pytest.mark.asyncio
    async def test_generate_playbook_exhausted_retries_raises_error(
        self,
        intelligence_rag,
        mock_retriever,
        mock_generator,
        mock_context
    ):
        """Test that exhausted retries raises PlaybookGenerationError."""
        from threatsimgpt.rag.exceptions import PlaybookGenerationError
        with patch('threatsimgpt.rag.retriever.ContextBuilder') as MockBuilder:
            mock_builder_instance = MagicMock()
            mock_builder_instance.build_context.return_value = mock_context
            MockBuilder.return_value = mock_builder_instance
            
            # All calls fail
            mock_generator.llm.generate.side_effect = Exception("Persistent failure")
            
            with pytest.raises(PlaybookGenerationError) as exc_info:
                await intelligence_rag.generate_playbook(
                    scenario="test scenario",
                    playbook_type="tactical"
                )
            
            assert "after 3 attempts" in str(exc_info.value).lower()
            assert mock_generator.llm.generate.call_count == 3


class TestIntelligentQueryExpansion:
    """Tests for _build_retrieval_queries method."""

    def test_tactical_queries_include_mitre_technique_expansion(
        self,
        intelligence_rag
    ):
        """Test that MITRE technique IDs in scenario trigger additional queries."""
        queries = intelligence_rag._build_retrieval_queries(
            scenario="Ransomware attack using T1566 and T1059.001",
            playbook_type="tactical"
        )
        
        # Should include technique-specific queries
        query_text = " ".join(queries)
        assert "T1566" in query_text
        assert "T1059" in query_text or "T1059.001" in query_text
        
    def test_tactical_queries_include_detection_and_mitigation(
        self,
        intelligence_rag
    ):
        """Test tactical queries include detection and mitigation focus."""
        queries = intelligence_rag._build_retrieval_queries(
            scenario="SQL injection attack",
            playbook_type="tactical"
        )
        
        query_text = " ".join(queries).lower()
        assert "detection" in query_text
        assert "mitigation" in query_text
        assert "threat actors" in query_text

    def test_sector_queries_include_compliance_and_industry_focus(
        self,
        intelligence_rag
    ):
        """Test sector queries include compliance and industry-specific focus."""
        queries = intelligence_rag._build_retrieval_queries(
            scenario="healthcare",
            playbook_type="sector"
        )
        
        query_text = " ".join(queries).lower()
        assert "compliance" in query_text
        assert "healthcare" in query_text
        assert "regulatory" in query_text or "apt" in query_text


class TestConfidenceScoring:
    """Tests for confidence calculation methods."""

    def test_retrieval_confidence_calculation(
        self,
        intelligence_rag,
        mock_retrieval_results,
        mock_context
    ):
        """Test retrieval confidence is calculated correctly."""
        confidence = intelligence_rag._calculate_retrieval_confidence(
            results=mock_retrieval_results,
            context=mock_context
        )
        
        assert 0.0 <= confidence <= 1.0
        assert confidence > 0.5, "Should have reasonable confidence with good results"

    def test_retrieval_confidence_low_for_empty_results(
        self,
        intelligence_rag,
        mock_context
    ):
        """Test confidence is low when no results."""
        confidence = intelligence_rag._calculate_retrieval_confidence(
            results=[],
            context=mock_context
        )
        
        assert confidence == 0.3, "Empty results should return minimum confidence"

    def test_generation_quality_assessment(
        self,
        intelligence_rag
    ):
        """Test generation quality assessment."""
        good_content = """
# Executive Summary

This tactical playbook addresses T1566 phishing attacks with comprehensive
detection and mitigation strategies based on MITRE ATT&CK framework.

## Threat Profile

CVE-2024-1234 related vulnerability exploited in the wild.

## Detection Strategies

Monitor for IOCs and TTPs associated with this attack chain.

## Mitigation Steps

Implement email filtering and security awareness training.

## Response Procedures

Follow incident response playbook for lateral movement detection.
"""
        sections = [
            MockPlaybookSection("Executive Summary", "content", "summary"),
            MockPlaybookSection("Threat Profile", "content", "profile"),
            MockPlaybookSection("Detection", "content", "detection"),
            MockPlaybookSection("Mitigation", "content", "mitigation"),
        ]
        
        quality = intelligence_rag._assess_generation_quality(good_content, sections)
        
        assert 0.0 <= quality <= 1.0
        assert quality > 0.5, "Good content should have high quality score"


class TestPlaybookConstruction:
    """Tests for _construct_playbook method."""

    def test_tactical_playbook_includes_rag_metadata(
        self,
        intelligence_rag,
        mock_context
    ):
        """Test that constructed playbook includes RAG observability metadata."""
        retrieval_result = {
            "results": [],
            "context": mock_context,
            "techniques": ["T1566", "T1059"],
            "sources": ["MITRE ATT&CK", "CISA"],
            "cves": ["CVE-2024-1234"],
            "confidence": 0.85,
            "query_count": 5,
            "retrieval_degraded": False,
        }
        
        playbook = intelligence_rag._construct_playbook(
            scenario="Ransomware attack",
            playbook_type="tactical",
            content="# Test Playbook\n\nContent here...",
            retrieval_result=retrieval_result,
            sector="healthcare",
            audience="SOC analysts"
        )
        
        assert playbook.rag_metadata is not None
        assert playbook.rag_metadata["retrieval_sources"] == 2
        assert playbook.rag_metadata["retrieval_techniques"] == 2
        assert playbook.rag_metadata["query_count"] == 5
        assert playbook.rag_metadata["degraded_mode"] is False
        assert "generated_at" in playbook.rag_metadata


class TestGracefulDegradation:
    """Tests for graceful degradation when components fail."""

    def test_minimal_context_creation_for_tactical(
        self,
        intelligence_rag
    ):
        """Test minimal context is created for tactical playbooks."""
        context = intelligence_rag._create_minimal_context(
            scenario="Advanced persistent threat",
            playbook_type="tactical"
        )
        
        assert context is not None
        assert "Limited intelligence" in context.context_text
        assert "MITRE ATT&CK" in context.context_text
        assert context.sources == ["General Threat Intelligence"]
        assert context.techniques == []

    def test_minimal_context_creation_for_sector(
        self,
        intelligence_rag
    ):
        """Test minimal context is created for sector playbooks."""
        context = intelligence_rag._create_minimal_context(
            scenario="finance",
            playbook_type="sector"
        )
        
        assert context is not None
        assert "Limited sector-specific" in context.context_text
        assert "regulatory frameworks" in context.context_text


class TestTechniqueExtraction:
    """Tests for MITRE technique extraction."""

    def test_technique_extraction_from_results(
        self,
        intelligence_rag,
        mock_retrieval_results,
        mock_context
    ):
        """Test techniques are extracted from results and context."""
        techniques = intelligence_rag._extract_techniques_from_results(
            results=mock_retrieval_results,
            context=mock_context
        )
        
        assert "T1566" in techniques
        assert "T1566.001" in techniques
        assert "T1021" in techniques
        # Techniques should be unique and sorted
        assert len(techniques) == len(set(techniques))
        assert techniques == sorted(techniques)


class TestBackwardCompatibility:
    """Tests ensuring backward compatibility with existing usage."""

    @pytest.mark.asyncio
    async def test_minimal_parameters_still_work(
        self,
        intelligence_rag,
        mock_retriever,
        mock_generator,
        mock_context
    ):
        """Test that minimal parameters (scenario, playbook_type) still work."""
        with patch('threatsimgpt.rag.retriever.ContextBuilder') as MockBuilder:
            mock_builder_instance = MagicMock()
            mock_builder_instance.build_context.return_value = mock_context
            MockBuilder.return_value = mock_builder_instance
            
            # Original minimal call should still work
            playbook = await intelligence_rag.generate_playbook(
                scenario="test scenario",
                playbook_type="tactical"
            )
            
            assert playbook is not None
            assert playbook.scenario == "test scenario"

    @pytest.mark.asyncio
    async def test_all_kwargs_passed_to_construction(
        self,
        intelligence_rag,
        mock_retriever,
        mock_generator,
        mock_context
    ):
        """Test that all kwargs are passed to playbook construction."""
        with patch('threatsimgpt.rag.retriever.ContextBuilder') as MockBuilder:
            mock_builder_instance = MagicMock()
            mock_builder_instance.build_context.return_value = mock_context
            MockBuilder.return_value = mock_builder_instance
            
            playbook = await intelligence_rag.generate_playbook(
                scenario="test",
                playbook_type="tactical",
                sector="finance",
                audience="executive team",
                top_k=20
            )
            
            assert playbook.sector == "finance"
            assert playbook.audience == "executive team"
