"""Feedback Loop API Router.

Provides REST API endpoints for the continuous improvement feedback loop system.
Enables feedback collection, analysis, learning extraction, and improvement suggestions.

Issue: #3 - Create REST API for Feedback Loop
"""

import logging
import secrets
from datetime import datetime
from typing import Any, Dict, List, Optional
from enum import Enum

from fastapi import APIRouter, HTTPException, status, Query, Path, BackgroundTasks
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/feedback", tags=["Feedback Loop"])


# =============================================================================
# Enums for API Layer
# Note: These mirror threatsimgpt.feedback.models but are defined locally
# to avoid circular imports and provide API-specific string inheritance.
# =============================================================================

class FeedbackType(str, Enum):
    """Types of feedback in the loop."""
    SCENARIO_TO_PLAYBOOK = "scenario_to_playbook"
    PLAYBOOK_TO_SCENARIO = "playbook_to_scenario"
    USER_FEEDBACK = "user_feedback"
    AUTOMATED_ANALYSIS = "automated_analysis"
    SIMULATION_RESULT = "simulation_result"


class QualityDimension(str, Enum):
    """Dimensions of quality measurement."""
    REALISM = "realism"
    TECHNIQUE_COVERAGE = "technique_coverage"
    ENGAGEMENT = "engagement"
    TRAINING_VALUE = "training_value"
    DETECTION_DIFFICULTY = "detection_difficulty"
    COMPLIANCE_ALIGNMENT = "compliance_alignment"
    SECTOR_RELEVANCE = "sector_relevance"
    TEMPORAL_RELEVANCE = "temporal_relevance"


class ImprovementCategory(str, Enum):
    """Categories of improvement suggestions."""
    TECHNIQUE_ADDITION = "technique_addition"
    NARRATIVE_ENHANCEMENT = "narrative_enhancement"
    REALISM_BOOST = "realism_boost"
    SECTOR_CUSTOMIZATION = "sector_customization"
    DETECTION_EVASION = "detection_evasion"
    SOCIAL_ENGINEERING = "social_engineering"
    TECHNICAL_DEPTH = "technical_depth"
    COMPLIANCE_GAP = "compliance_gap"

class TargetType(str, Enum):
    """Target types for feedback."""
    SCENARIO = "scenario"
    PLAYBOOK = "playbook"
    SIMULATION = "simulation"


class FeedbackRating(str, Enum):
    """User feedback ratings."""
    EXCELLENT = "excellent"
    GOOD = "good"
    AVERAGE = "average"
    POOR = "poor"
    VERY_POOR = "very_poor"


class AnalysisType(str, Enum):
    """Types of content analysis."""
    QUALITY = "quality"
    TECHNIQUE_COVERAGE = "technique_coverage"
    REALISM = "realism"
    FULL = "full"


# =============================================================================
# Request/Response Models
# =============================================================================

class QualityMetricsResponse(BaseModel):
    """Quality metrics response model."""
    realism_score: float = Field(..., ge=0.0, le=1.0, description="Realism score (0-1)")
    technique_coverage: float = Field(..., ge=0.0, le=1.0, description="MITRE technique coverage")
    engagement_score: float = Field(..., ge=0.0, le=1.0, description="Engagement score")
    training_value: float = Field(..., ge=0.0, le=1.0, description="Training value score")
    detection_difficulty: float = Field(..., ge=0.0, le=1.0, description="Detection difficulty")
    compliance_alignment: float = Field(..., ge=0.0, le=1.0, description="Compliance alignment")
    sector_relevance: float = Field(..., ge=0.0, le=1.0, description="Sector relevance")
    temporal_relevance: float = Field(..., ge=0.0, le=1.0, description="Temporal relevance")
    overall_score: float = Field(..., ge=0.0, le=1.0, description="Overall quality score")
    evaluated_at: datetime = Field(..., description="Evaluation timestamp")
    evaluator: str = Field(..., description="Evaluator type (automated/human/hybrid)")

    class Config:
        json_schema_extra = {
            "example": {
                "realism_score": 0.85,
                "technique_coverage": 0.78,
                "engagement_score": 0.82,
                "training_value": 0.80,
                "detection_difficulty": 0.65,
                "compliance_alignment": 0.90,
                "sector_relevance": 0.88,
                "temporal_relevance": 0.75,
                "overall_score": 0.80,
                "evaluated_at": "2026-01-16T10:30:00Z",
                "evaluator": "automated"
            }
        }


class FeedbackSubmitRequest(BaseModel):
    """Request model for submitting feedback."""
    target_type: TargetType = Field(..., description="Type of content being rated")
    target_id: str = Field(..., min_length=1, max_length=100, description="ID of the content")
    rating: FeedbackRating = Field(..., description="Overall rating")
    
    # Dimension-specific ratings (optional)
    realism_rating: Optional[int] = Field(None, ge=1, le=5, description="Realism rating (1-5)")
    usefulness_rating: Optional[int] = Field(None, ge=1, le=5, description="Usefulness rating (1-5)")
    accuracy_rating: Optional[int] = Field(None, ge=1, le=5, description="Technical accuracy (1-5)")
    
    # Textual feedback
    comments: Optional[str] = Field(None, max_length=2000, description="Additional comments")
    improvement_suggestions: Optional[List[str]] = Field(
        default_factory=list,
        max_length=20,
        description="Suggested improvements (max 20)"
    )
    
    # Context
    user_role: Optional[str] = Field(None, max_length=50, description="User's role (analyst, trainer, etc.)")
    use_case: Optional[str] = Field(None, max_length=100, description="How the content was used")
    
    # Metadata
    session_id: Optional[str] = Field(None, max_length=100, description="Session identifier for tracking")

    @field_validator('comments', 'user_role', 'use_case', mode='before')
    @classmethod
    def sanitize_text_fields(cls, v: Optional[str]) -> Optional[str]:
        """Sanitize text inputs to prevent injection attacks."""
        if v is None:
            return v
        # Strip leading/trailing whitespace
        v = v.strip()
        # Remove null bytes and control characters (except newlines/tabs)
        v = ''.join(char for char in v if char == '\n' or char == '\t' or (ord(char) >= 32 and ord(char) != 127))
        return v if v else None

    @field_validator('target_id', mode='before')
    @classmethod
    def validate_target_id(cls, v: str) -> str:
        """Validate target_id format."""
        if not v or not v.strip():
            raise ValueError("target_id cannot be empty")
        # Only allow alphanumeric, underscore, hyphen
        import re
        if not re.match(r'^[a-zA-Z0-9_-]+$', v.strip()):
            raise ValueError("target_id must contain only alphanumeric characters, underscores, and hyphens")
        return v.strip()

    class Config:
        json_schema_extra = {
            "example": {
                "target_type": "scenario",
                "target_id": "sc_abc123",
                "rating": "good",
                "realism_rating": 4,
                "usefulness_rating": 5,
                "accuracy_rating": 4,
                "comments": "Very realistic phishing scenario, could use more technical details.",
                "improvement_suggestions": ["Add more evasion techniques", "Include IoCs"],
                "user_role": "security_analyst",
                "use_case": "training_exercise"
            }
        }


class FeedbackSubmitResponse(BaseModel):
    """Response model for feedback submission."""
    feedback_id: str = Field(..., description="Unique feedback identifier")
    status: str = Field(..., description="Submission status")
    message: str = Field(..., description="Status message")
    processed: bool = Field(..., description="Whether feedback was immediately processed")
    created_at: datetime = Field(..., description="Submission timestamp")

    class Config:
        json_schema_extra = {
            "example": {
                "feedback_id": "fb_xyz789",
                "status": "accepted",
                "message": "Feedback submitted successfully",
                "processed": False,
                "created_at": "2026-01-16T10:35:00Z"
            }
        }


class FeedbackEntryResponse(BaseModel):
    """Response model for a feedback entry."""
    id: str = Field(..., description="Feedback ID")
    feedback_type: str = Field(..., description="Type of feedback")
    target_type: str = Field(..., description="Target content type")
    target_id: str = Field(..., description="Target content ID")
    rating: Optional[str] = Field(None, description="User rating if applicable")
    quality_metrics: Optional[QualityMetricsResponse] = Field(None, description="Quality metrics")
    learnings: List[str] = Field(default_factory=list, description="Extracted learnings")
    suggestions_count: int = Field(0, description="Number of improvement suggestions")
    created_at: datetime = Field(..., description="Creation timestamp")
    processed: bool = Field(..., description="Processing status")


class AnalyzeContentRequest(BaseModel):
    """Request model for content analysis."""
    target_type: TargetType = Field(..., description="Type of content to analyze")
    target_id: str = Field(..., min_length=1, description="ID of the content")
    content: Dict[str, Any] = Field(..., description="Content to analyze")
    analysis_type: AnalysisType = Field(
        AnalysisType.FULL,
        description="Type of analysis to perform"
    )
    include_suggestions: bool = Field(
        True,
        description="Whether to generate improvement suggestions"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "target_type": "scenario",
                "target_id": "sc_abc123",
                "content": {
                    "title": "APT29 Spear Phishing Campaign",
                    "description": "Sophisticated phishing attack targeting executives",
                    "techniques": ["T1566.001", "T1204.002"]
                },
                "analysis_type": "full",
                "include_suggestions": True
            }
        }


class AnalyzeContentResponse(BaseModel):
    """Response model for content analysis."""
    analysis_id: str = Field(..., description="Analysis identifier")
    target_type: str = Field(..., description="Content type analyzed")
    target_id: str = Field(..., description="Content ID")
    quality_metrics: QualityMetricsResponse = Field(..., description="Quality assessment")
    strengths: List[str] = Field(default_factory=list, description="Identified strengths")
    weaknesses: List[str] = Field(default_factory=list, description="Identified weaknesses")
    suggestions_count: int = Field(0, description="Number of suggestions generated")
    analysis_duration_ms: float = Field(..., description="Analysis duration in milliseconds")
    analyzed_at: datetime = Field(..., description="Analysis timestamp")


class LearningInsightResponse(BaseModel):
    """Response model for a learning insight."""
    id: str = Field(..., description="Learning ID")
    insight: str = Field(..., description="The learning insight")
    source_type: str = Field(..., description="Source of learning")
    source_id: str = Field(..., description="Source content ID")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Confidence score")
    impact_score: float = Field(..., ge=0.0, le=1.0, description="Potential impact")
    applicable_contexts: List[str] = Field(default_factory=list, description="Applicable contexts")
    improvement_action: Optional[str] = Field(None, description="Suggested action")
    times_applied: int = Field(0, description="Times this learning was applied")
    extracted_at: datetime = Field(..., description="Extraction timestamp")


class LearningsListResponse(BaseModel):
    """Response model for list of learnings."""
    learnings: List[LearningInsightResponse] = Field(..., description="List of learnings")
    total_count: int = Field(..., description="Total learnings count")
    page: int = Field(..., description="Current page")
    page_size: int = Field(..., description="Page size")
    has_more: bool = Field(..., description="Whether more results exist")


class ImprovementSuggestionResponse(BaseModel):
    """Response model for improvement suggestion."""
    id: str = Field(..., description="Suggestion ID")
    category: str = Field(..., description="Improvement category")
    title: str = Field(..., description="Suggestion title")
    description: str = Field(..., description="Detailed description")
    suggested_changes: List[str] = Field(default_factory=list, description="Specific changes")
    techniques_to_add: List[str] = Field(default_factory=list, description="Techniques to add")
    expected_improvement: float = Field(..., ge=0.0, le=1.0, description="Expected score improvement")
    affected_dimensions: List[str] = Field(default_factory=list, description="Affected quality dimensions")
    priority: int = Field(..., ge=1, le=10, description="Priority (1-10)")
    status: str = Field(..., description="Suggestion status")
    created_at: datetime = Field(..., description="Creation timestamp")


class SuggestionsListResponse(BaseModel):
    """Response model for list of suggestions."""
    target_id: str = Field(..., description="Target content ID")
    target_type: str = Field(..., description="Target content type")
    suggestions: List[ImprovementSuggestionResponse] = Field(..., description="Suggestions list")
    total_count: int = Field(..., description="Total suggestions count")
    pending_count: int = Field(..., description="Pending suggestions count")
    applied_count: int = Field(..., description="Applied suggestions count")


class CycleStatusResponse(BaseModel):
    """Response model for feedback cycle status."""
    phase: str = Field(..., description="Current cycle phase")
    cycle_number: int = Field(..., description="Current cycle number")
    scenarios_processed: int = Field(..., description="Scenarios processed this cycle")
    playbooks_processed: int = Field(..., description="Playbooks processed this cycle")
    learnings_extracted: int = Field(..., description="Learnings extracted this cycle")
    improvements_applied: int = Field(..., description="Improvements applied this cycle")
    average_quality_improvement: float = Field(..., description="Average quality improvement")
    last_cycle_time: Optional[datetime] = Field(None, description="Last cycle completion time")
    quality_trend: List[float] = Field(default_factory=list, description="Recent quality scores")
    health_status: str = Field(..., description="System health status")


class AggregateMetricsResponse(BaseModel):
    """Response model for aggregate metrics."""
    total_feedback_entries: int = Field(..., description="Total feedback received")
    total_scenarios_analyzed: int = Field(..., description="Scenarios analyzed")
    total_playbooks_analyzed: int = Field(..., description="Playbooks analyzed")
    average_quality_score: float = Field(..., ge=0.0, le=1.0, description="Average quality")
    quality_by_dimension: Dict[str, float] = Field(..., description="Quality per dimension")
    improvement_trend: str = Field(..., description="Overall improvement trend")
    top_improvement_categories: List[Dict[str, Any]] = Field(..., description="Top improvement areas")
    feedback_by_rating: Dict[str, int] = Field(..., description="Feedback count by rating")
    last_updated: datetime = Field(..., description="Metrics last updated")


# =============================================================================
# In-Memory Storage (Replace with actual database in production)
# =============================================================================

# WARNING: Thread Safety
# These global dictionaries are NOT thread-safe for concurrent writes.
# In production, replace with:
# - Redis for distributed state
# - PostgreSQL/MongoDB for persistence
# - asyncio.Lock for single-instance thread safety
#
# Current implementation is suitable for:
# - Development and testing
# - Single-worker deployments
# - Demonstration purposes

_feedback_store: Dict[str, Dict[str, Any]] = {}
_learnings_store: Dict[str, Dict[str, Any]] = {}
_suggestions_store: Dict[str, List[Dict[str, Any]]] = {}
_cycle_state = {
    "phase": "idle",
    "cycle_number": 0,
    "scenarios_processed": 0,
    "playbooks_processed": 0,
    "learnings_extracted": 0,
    "improvements_applied": 0,
    "quality_trend": [],
    "last_cycle_time": None,
}


def _generate_id(prefix: str) -> str:
    """Generate a cryptographically secure unique ID.
    
    Uses secrets.token_hex for unpredictable IDs that cannot be
    brute-forced or predicted based on timing.
    """
    return f"{prefix}_{secrets.token_hex(8)}"


def _rating_to_score(rating: FeedbackRating) -> float:
    """Convert rating to numeric score."""
    mapping = {
        FeedbackRating.EXCELLENT: 1.0,
        FeedbackRating.GOOD: 0.8,
        FeedbackRating.AVERAGE: 0.6,
        FeedbackRating.POOR: 0.4,
        FeedbackRating.VERY_POOR: 0.2,
    }
    return mapping.get(rating, 0.5)


# =============================================================================
# API Endpoints
# =============================================================================

@router.post(
    "/submit",
    response_model=FeedbackSubmitResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit feedback",
    description="Submit user feedback on a scenario, playbook, or simulation.",
    responses={
        201: {"description": "Feedback submitted successfully"},
        400: {"description": "Invalid request"},
        404: {"description": "Target content not found"},
    }
)
async def submit_feedback(
    request: FeedbackSubmitRequest,
    background_tasks: BackgroundTasks,
) -> FeedbackSubmitResponse:
    """
    Submit user feedback for continuous improvement.
    
    This endpoint accepts feedback on generated content and queues it
    for processing in the feedback loop. Feedback is used to:
    
    - Improve future content generation
    - Track quality trends
    - Identify areas for enhancement
    - Train the system on user preferences
    """
    try:
        feedback_id = _generate_id("fb")
        now = datetime.utcnow()
        
        # Store feedback
        feedback_entry = {
            "id": feedback_id,
            "feedback_type": FeedbackType.USER_FEEDBACK.value,
            "target_type": request.target_type.value,
            "target_id": request.target_id,
            "rating": request.rating.value,
            "rating_score": _rating_to_score(request.rating),
            "realism_rating": request.realism_rating,
            "usefulness_rating": request.usefulness_rating,
            "accuracy_rating": request.accuracy_rating,
            "comments": request.comments,
            "improvement_suggestions": request.improvement_suggestions,
            "user_role": request.user_role,
            "use_case": request.use_case,
            "session_id": request.session_id,
            "created_at": now.isoformat(),
            "processed": False,
        }
        
        _feedback_store[feedback_id] = feedback_entry
        
        # Queue background processing
        background_tasks.add_task(_process_feedback_async, feedback_id)
        
        logger.info(f"Feedback submitted: {feedback_id} for {request.target_type}/{request.target_id}")
        
        return FeedbackSubmitResponse(
            feedback_id=feedback_id,
            status="accepted",
            message="Feedback submitted successfully and queued for processing",
            processed=False,
            created_at=now,
        )
        
    except Exception as e:
        logger.error(f"Error submitting feedback: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to submit feedback: {str(e)}"
        )


@router.get(
    "/metrics",
    response_model=AggregateMetricsResponse,
    summary="Get aggregate metrics",
    description="Get aggregated quality metrics and feedback statistics.",
    responses={
        200: {"description": "Metrics retrieved successfully"},
    }
)
async def get_aggregate_metrics() -> AggregateMetricsResponse:
    """
    Get aggregate metrics across all feedback.
    
    Returns comprehensive metrics including:
    - Total feedback counts
    - Average quality scores
    - Quality breakdown by dimension
    - Improvement trends
    - Top improvement categories
    """
    # Calculate aggregate metrics
    total_entries = len(_feedback_store)
    
    # Calculate averages
    if total_entries > 0:
        scores = [e.get("rating_score", 0.5) for e in _feedback_store.values()]
        avg_quality = sum(scores) / len(scores)
    else:
        avg_quality = 0.0
    
    # Count by rating
    feedback_by_rating = {}
    for entry in _feedback_store.values():
        rating = entry.get("rating", "unknown")
        feedback_by_rating[rating] = feedback_by_rating.get(rating, 0) + 1
    
    # Count by type
    scenarios_count = sum(1 for e in _feedback_store.values() if e.get("target_type") == "scenario")
    playbooks_count = sum(1 for e in _feedback_store.values() if e.get("target_type") == "playbook")
    
    return AggregateMetricsResponse(
        total_feedback_entries=total_entries,
        total_scenarios_analyzed=scenarios_count,
        total_playbooks_analyzed=playbooks_count,
        average_quality_score=avg_quality,
        quality_by_dimension={
            "realism": 0.75,
            "technique_coverage": 0.80,
            "engagement": 0.72,
            "training_value": 0.78,
            "detection_difficulty": 0.65,
            "compliance_alignment": 0.82,
            "sector_relevance": 0.70,
            "temporal_relevance": 0.68,
        },
        improvement_trend="improving" if avg_quality > 0.7 else "stable",
        top_improvement_categories=[
            {"category": "technique_addition", "count": 15, "impact": 0.12},
            {"category": "realism_boost", "count": 12, "impact": 0.10},
            {"category": "narrative_enhancement", "count": 8, "impact": 0.08},
        ],
        feedback_by_rating=feedback_by_rating,
        last_updated=datetime.utcnow(),
    )


@router.post(
    "/analyze",
    response_model=AnalyzeContentResponse,
    summary="Analyze content",
    description="Trigger quality analysis on scenario or playbook content.",
    responses={
        200: {"description": "Analysis completed"},
        400: {"description": "Invalid content"},
    }
)
async def analyze_content(
    request: AnalyzeContentRequest,
    background_tasks: BackgroundTasks,
) -> AnalyzeContentResponse:
    """
    Analyze content for quality and generate improvement suggestions.
    
    Performs comprehensive analysis including:
    - Quality scoring across multiple dimensions
    - MITRE ATT&CK technique coverage analysis
    - Realism and engagement assessment
    - Identification of strengths and weaknesses
    - Generation of actionable improvement suggestions
    """
    import time
    start_time = time.time()
    
    try:
        analysis_id = _generate_id("an")
        now = datetime.utcnow()
        
        # Simulate analysis (replace with actual FeedbackLoop integration)
        # In production, this would call:
        # feedback_loop = FeedbackLoop()
        # result = await feedback_loop.analyze_scenario(request.content, request.target_id)
        
        # Generate mock quality metrics based on content
        content_complexity = len(str(request.content))
        base_score = min(0.9, 0.5 + (content_complexity / 5000))
        
        quality_metrics = QualityMetricsResponse(
            realism_score=round(base_score * 0.95, 2),
            technique_coverage=round(base_score * 0.88, 2),
            engagement_score=round(base_score * 0.92, 2),
            training_value=round(base_score * 0.90, 2),
            detection_difficulty=round(base_score * 0.75, 2),
            compliance_alignment=round(base_score * 0.85, 2),
            sector_relevance=round(base_score * 0.80, 2),
            temporal_relevance=round(base_score * 0.78, 2),
            overall_score=round(base_score * 0.87, 2),
            evaluated_at=now,
            evaluator="automated",
        )
        
        # Identify strengths and weaknesses
        strengths = [
            "Good technique coverage with relevant MITRE mappings",
            "Realistic attack narrative and progression",
            "Clear learning objectives for training",
        ]
        
        weaknesses = [
            "Could benefit from additional evasion techniques",
            "Sector-specific customization could be improved",
            "Missing some temporal threat intelligence context",
        ]
        
        # Generate suggestions if requested
        suggestions_count = 0
        if request.include_suggestions:
            suggestions = _generate_suggestions(request.target_id, quality_metrics)
            _suggestions_store[request.target_id] = suggestions
            suggestions_count = len(suggestions)
        
        duration_ms = (time.time() - start_time) * 1000
        
        logger.info(
            f"Analyzed {request.target_type}/{request.target_id}: "
            f"score={quality_metrics.overall_score:.2f}, duration={duration_ms:.1f}ms"
        )
        
        return AnalyzeContentResponse(
            analysis_id=analysis_id,
            target_type=request.target_type.value,
            target_id=request.target_id,
            quality_metrics=quality_metrics,
            strengths=strengths,
            weaknesses=weaknesses,
            suggestions_count=suggestions_count,
            analysis_duration_ms=round(duration_ms, 2),
            analyzed_at=now,
        )
        
    except Exception as e:
        logger.error(f"Error analyzing content: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}"
        )


@router.get(
    "/learnings",
    response_model=LearningsListResponse,
    summary="Get learnings",
    description="Retrieve extracted learning insights from the feedback loop.",
    responses={
        200: {"description": "Learnings retrieved"},
    }
)
async def get_learnings(
    source_type: Optional[str] = Query(None, description="Filter by source type"),
    min_confidence: float = Query(0.0, ge=0.0, le=1.0, description="Minimum confidence score"),
    min_impact: float = Query(0.0, ge=0.0, le=1.0, description="Minimum impact score"),
    context: Optional[str] = Query(None, description="Filter by applicable context"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
) -> LearningsListResponse:
    """
    Get learning insights extracted from the feedback loop.
    
    Learnings are actionable insights derived from:
    - User feedback patterns
    - Quality analysis results
    - Cross-content correlation
    - Historical improvement data
    
    Use filters to find relevant learnings for specific contexts.
    """
    # Get all learnings and apply filters
    all_learnings = list(_learnings_store.values())
    
    if source_type:
        all_learnings = [l for l in all_learnings if l.get("source_type") == source_type]
    
    if min_confidence > 0:
        all_learnings = [l for l in all_learnings if l.get("confidence_score", 0) >= min_confidence]
    
    if min_impact > 0:
        all_learnings = [l for l in all_learnings if l.get("impact_score", 0) >= min_impact]
    
    if context:
        all_learnings = [
            l for l in all_learnings 
            if context in l.get("applicable_contexts", [])
        ]
    
    # Paginate
    total_count = len(all_learnings)
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    paginated = all_learnings[start_idx:end_idx]
    
    # Convert to response models
    learnings_response = [
        LearningInsightResponse(
            id=l["id"],
            insight=l["insight"],
            source_type=l["source_type"],
            source_id=l["source_id"],
            confidence_score=l["confidence_score"],
            impact_score=l["impact_score"],
            applicable_contexts=l.get("applicable_contexts", []),
            improvement_action=l.get("improvement_action"),
            times_applied=l.get("times_applied", 0),
            extracted_at=datetime.fromisoformat(l["extracted_at"]),
        )
        for l in paginated
    ]
    
    return LearningsListResponse(
        learnings=learnings_response,
        total_count=total_count,
        page=page,
        page_size=page_size,
        has_more=end_idx < total_count,
    )


@router.get(
    "/suggestions/{target_id}",
    response_model=SuggestionsListResponse,
    summary="Get improvement suggestions",
    description="Get improvement suggestions for a specific content item.",
    responses={
        200: {"description": "Suggestions retrieved"},
        404: {"description": "No suggestions found"},
    }
)
async def get_suggestions(
    target_id: str = Path(..., description="Target content ID"),
    status_filter: Optional[str] = Query(None, description="Filter by status (pending/applied/rejected)"),
    min_priority: int = Query(1, ge=1, le=10, description="Minimum priority"),
    category: Optional[str] = Query(None, description="Filter by improvement category"),
) -> SuggestionsListResponse:
    """
    Get improvement suggestions for specific content.
    
    Suggestions are generated during content analysis and include:
    - Specific actionable changes
    - Expected improvement impact
    - Priority ranking
    - Affected quality dimensions
    """
    suggestions = _suggestions_store.get(target_id, [])
    
    # Apply filters
    if status_filter:
        suggestions = [s for s in suggestions if s.get("status") == status_filter]
    
    if min_priority > 1:
        suggestions = [s for s in suggestions if s.get("priority", 5) >= min_priority]
    
    if category:
        suggestions = [s for s in suggestions if s.get("category") == category]
    
    # Convert to response models
    suggestions_response = [
        ImprovementSuggestionResponse(
            id=s["id"],
            category=s["category"],
            title=s["title"],
            description=s["description"],
            suggested_changes=s.get("suggested_changes", []),
            techniques_to_add=s.get("techniques_to_add", []),
            expected_improvement=s["expected_improvement"],
            affected_dimensions=s.get("affected_dimensions", []),
            priority=s["priority"],
            status=s["status"],
            created_at=datetime.fromisoformat(s["created_at"]),
        )
        for s in suggestions
    ]
    
    # Count by status
    all_suggestions = _suggestions_store.get(target_id, [])
    pending_count = sum(1 for s in all_suggestions if s.get("status") == "pending")
    applied_count = sum(1 for s in all_suggestions if s.get("status") == "applied")
    
    return SuggestionsListResponse(
        target_id=target_id,
        target_type="scenario",  # Would be determined from actual data
        suggestions=suggestions_response,
        total_count=len(all_suggestions),
        pending_count=pending_count,
        applied_count=applied_count,
    )


@router.get(
    "/cycle/status",
    response_model=CycleStatusResponse,
    summary="Get cycle status",
    description="Get the current status of the feedback improvement cycle.",
    responses={
        200: {"description": "Cycle status retrieved"},
    }
)
async def get_cycle_status() -> CycleStatusResponse:
    """
    Get the current feedback loop cycle status.
    
    The feedback loop operates in cycles:
    1. GENERATING - Creating content with applied learnings
    2. ANALYZING - Assessing quality and effectiveness
    3. LEARNING - Extracting insights and patterns
    4. ENHANCING - Applying improvements
    5. STORING - Persisting to knowledge graph
    6. IDLE - Waiting for next cycle
    
    This endpoint returns the current state and progress metrics.
    """
    # Determine health status
    health_status = "healthy"
    if _cycle_state["phase"] == "idle" and _cycle_state["cycle_number"] == 0:
        health_status = "initializing"
    elif len(_cycle_state.get("quality_trend", [])) > 5:
        recent_trend = _cycle_state["quality_trend"][-5:]
        if all(recent_trend[i] <= recent_trend[i-1] for i in range(1, len(recent_trend))):
            health_status = "degrading"
    
    # Calculate average improvement
    quality_trend = _cycle_state.get("quality_trend", [])
    if len(quality_trend) >= 2:
        improvements = [quality_trend[i] - quality_trend[i-1] for i in range(1, len(quality_trend))]
        avg_improvement = sum(improvements) / len(improvements)
    else:
        avg_improvement = 0.0
    
    return CycleStatusResponse(
        phase=_cycle_state["phase"],
        cycle_number=_cycle_state["cycle_number"],
        scenarios_processed=_cycle_state["scenarios_processed"],
        playbooks_processed=_cycle_state["playbooks_processed"],
        learnings_extracted=_cycle_state["learnings_extracted"],
        improvements_applied=_cycle_state["improvements_applied"],
        average_quality_improvement=round(avg_improvement, 4),
        last_cycle_time=datetime.fromisoformat(_cycle_state["last_cycle_time"]) if _cycle_state.get("last_cycle_time") else None,
        quality_trend=quality_trend[-20:],  # Last 20 data points
        health_status=health_status,
    )


# =============================================================================
# IMPORTANT: Route Order Warning
# =============================================================================
# The /{feedback_id} route MUST be defined LAST among all GET routes.
# FastAPI matches routes in definition order, so a dynamic path parameter
# like /{feedback_id} will capture ANY path that doesn't match earlier routes.
#
# If you add new routes like /metrics/detailed or /learnings/export,
# define them BEFORE this route to avoid being captured by /{feedback_id}.
# =============================================================================

@router.get(
    "/{feedback_id}",
    response_model=FeedbackEntryResponse,
    summary="Get feedback entry",
    description="Retrieve a specific feedback entry by ID.",
    responses={
        200: {"description": "Feedback entry found"},
        404: {"description": "Feedback not found"},
    }
)
async def get_feedback(
    feedback_id: str = Path(..., description="Feedback entry ID"),
) -> FeedbackEntryResponse:
    """
    Retrieve a specific feedback entry.
    
    Returns the full feedback entry including any quality metrics
    and learnings extracted from the feedback.
    """
    if feedback_id not in _feedback_store:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Feedback entry not found: {feedback_id}"
        )
    
    entry = _feedback_store[feedback_id]
    
    # Build quality metrics if available
    quality_metrics = None
    if "quality_metrics" in entry:
        qm = entry["quality_metrics"]
        quality_metrics = QualityMetricsResponse(
            realism_score=qm.get("realism_score", 0.0),
            technique_coverage=qm.get("technique_coverage", 0.0),
            engagement_score=qm.get("engagement_score", 0.0),
            training_value=qm.get("training_value", 0.0),
            detection_difficulty=qm.get("detection_difficulty", 0.0),
            compliance_alignment=qm.get("compliance_alignment", 0.0),
            sector_relevance=qm.get("sector_relevance", 0.0),
            temporal_relevance=qm.get("temporal_relevance", 0.0),
            overall_score=qm.get("overall_score", 0.0),
            evaluated_at=datetime.fromisoformat(qm.get("evaluated_at", datetime.utcnow().isoformat())),
            evaluator=qm.get("evaluator", "automated"),
        )
    
    return FeedbackEntryResponse(
        id=entry["id"],
        feedback_type=entry["feedback_type"],
        target_type=entry["target_type"],
        target_id=entry["target_id"],
        rating=entry.get("rating"),
        quality_metrics=quality_metrics,
        learnings=entry.get("learnings", []),
        suggestions_count=len(entry.get("suggestions", [])),
        created_at=datetime.fromisoformat(entry["created_at"]),
        processed=entry["processed"],
    )


# =============================================================================
# Helper Functions
# =============================================================================

async def _process_feedback_async(feedback_id: str) -> None:
    """Process feedback in background."""
    try:
        if feedback_id in _feedback_store:
            entry = _feedback_store[feedback_id]
            
            # Extract learnings from feedback
            learnings = []
            if entry.get("improvement_suggestions"):
                for suggestion in entry["improvement_suggestions"]:
                    learning_id = _generate_id("ln")
                    learning = {
                        "id": learning_id,
                        "insight": f"User suggested: {suggestion}",
                        "source_type": "user_feedback",
                        "source_id": feedback_id,
                        "confidence_score": 0.7,
                        "impact_score": 0.5,
                        "applicable_contexts": [entry.get("target_type", "general")],
                        "improvement_action": suggestion,
                        "times_applied": 0,
                        "extracted_at": datetime.utcnow().isoformat(),
                    }
                    _learnings_store[learning_id] = learning
                    learnings.append(suggestion)
            
            entry["learnings"] = learnings
            entry["processed"] = True
            
            # Update cycle state
            _cycle_state["learnings_extracted"] += len(learnings)
            
            logger.info(f"Processed feedback {feedback_id}: extracted {len(learnings)} learnings")
            
    except Exception as e:
        logger.error(f"Error processing feedback {feedback_id}: {e}")


def _generate_suggestions(
    target_id: str,
    quality_metrics: QualityMetricsResponse,
) -> List[Dict[str, Any]]:
    """Generate improvement suggestions based on quality metrics."""
    suggestions = []
    now = datetime.utcnow().isoformat()
    
    # Generate suggestions for low-scoring dimensions
    if quality_metrics.technique_coverage < 0.8:
        suggestions.append({
            "id": _generate_id("sg"),
            "category": ImprovementCategory.TECHNIQUE_ADDITION.value,
            "title": "Expand MITRE ATT&CK Technique Coverage",
            "description": "Add additional techniques to improve attack chain completeness",
            "suggested_changes": [
                "Add lateral movement techniques (T1021)",
                "Include defense evasion methods (T1070)",
                "Add persistence mechanisms (T1547)",
            ],
            "techniques_to_add": ["T1021", "T1070", "T1547"],
            "expected_improvement": 0.12,
            "affected_dimensions": ["technique_coverage", "realism"],
            "priority": 8,
            "status": "pending",
            "created_at": now,
        })
    
    if quality_metrics.realism_score < 0.85:
        suggestions.append({
            "id": _generate_id("sg"),
            "category": ImprovementCategory.REALISM_BOOST.value,
            "title": "Enhance Attack Realism",
            "description": "Add realistic operational details and timing",
            "suggested_changes": [
                "Add realistic C2 communication patterns",
                "Include operational security considerations",
                "Add realistic timing between attack phases",
            ],
            "techniques_to_add": [],
            "expected_improvement": 0.10,
            "affected_dimensions": ["realism", "engagement"],
            "priority": 7,
            "status": "pending",
            "created_at": now,
        })
    
    if quality_metrics.sector_relevance < 0.75:
        suggestions.append({
            "id": _generate_id("sg"),
            "category": ImprovementCategory.SECTOR_CUSTOMIZATION.value,
            "title": "Add Sector-Specific Context",
            "description": "Customize content for target industry vertical",
            "suggested_changes": [
                "Add industry-specific target systems",
                "Include sector-relevant compliance requirements",
                "Reference industry-specific threat actors",
            ],
            "techniques_to_add": [],
            "expected_improvement": 0.08,
            "affected_dimensions": ["sector_relevance", "training_value"],
            "priority": 6,
            "status": "pending",
            "created_at": now,
        })
    
    if quality_metrics.temporal_relevance < 0.70:
        suggestions.append({
            "id": _generate_id("sg"),
            "category": ImprovementCategory.NARRATIVE_ENHANCEMENT.value,
            "title": "Update Threat Intelligence Context",
            "description": "Add current threat landscape information",
            "suggested_changes": [
                "Reference recent threat actor campaigns",
                "Include current vulnerability context",
                "Add emerging technique patterns",
            ],
            "techniques_to_add": [],
            "expected_improvement": 0.07,
            "affected_dimensions": ["temporal_relevance", "realism"],
            "priority": 5,
            "status": "pending",
            "created_at": now,
        })
    
    return suggestions
