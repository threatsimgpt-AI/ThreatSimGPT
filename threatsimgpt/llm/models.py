"""Comprehensive LLM integration models for ThreatSimGPT.

This module defines the data models, request/response structures, and configuration
for LLM provider integration supporting OpenAI and Anthropic APIs.
"""

import json
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, field_validator, ConfigDict, field_serializer


def utc_now() -> datetime:
    """Return current UTC time as timezone-aware datetime."""
    return datetime.now(timezone.utc)


class LLMProvider(str, Enum):
    """Supported LLM providers for threat content generation."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OPENROUTER = "openrouter"
    OLLAMA = "ollama"  # Local LLM support via Ollama
    # Future providers can be added here
    # GOOGLE = "google"
    # COHERE = "cohere"


class LLMModel(str, Enum):
    """Specific LLM models for each provider."""

    # OpenAI Models
    GPT_4_TURBO = "gpt-4-turbo-preview"
    GPT_4 = "gpt-4"
    GPT_35_TURBO = "gpt-3.5-turbo"

    # Anthropic Models
    CLAUDE_3_SONNET = "claude-3-sonnet-20240229"
    CLAUDE_3_HAIKU = "claude-3-haiku-20240307"
    CLAUDE_2_1 = "claude-2.1"
    CLAUDE_2 = "claude-2.0"

    # Ollama Local Models (popular open-source models)
    LLAMA2 = "llama2"
    LLAMA2_13B = "llama2:13b"
    LLAMA2_70B = "llama2:70b"
    MISTRAL = "mistral"
    MISTRAL_7B = "mistral:7b"
    CODELLAMA = "codellama"
    NEURAL_CHAT = "neural-chat"
    STARLING = "starling-lm"
    VICUNA = "vicuna"
    ORCA_MINI = "orca-mini"


class ContentType(str, Enum):
    """Types of threat content that can be generated."""

    EMAIL_PHISHING = "email_phishing"
    SMS_PHISHING = "sms_phishing"
    VOICE_SCRIPT = "voice_script"
    SOCIAL_MEDIA_POST = "social_media_post"
    DOCUMENT_LURE = "document_lure"
    WEB_PAGE = "web_page"
    CHAT_MESSAGE = "chat_message"
    PRETEXT_SCENARIO = "pretext_scenario"


class PromptTemplate(BaseModel):
    """Template for LLM prompts with variables and constraints."""

    name: str = Field(..., description="Template name for identification")
    content_type: ContentType = Field(..., description="Type of content to generate")
    system_prompt: str = Field(..., description="System prompt for LLM context")
    user_prompt_template: str = Field(..., description="User prompt template with variables")
    variables: List[str] = Field(default_factory=list, description="Required template variables")
    constraints: List[str] = Field(default_factory=list, description="Content generation constraints")
    examples: List[Dict[str, str]] = Field(default_factory=list, description="Example inputs and outputs")

    @field_validator('user_prompt_template')
    @classmethod
    def validate_template_variables(cls, v, info):
        """Validate that all required variables are present in template."""
        variables = info.data.get('variables', [])
        for var in variables:
            if f"{{{var}}}" not in v:
                raise ValueError(f"Variable '{var}' not found in prompt template")
        return v


class LLMRequest(BaseModel):
    """Comprehensive LLM request with provider-agnostic structure."""

    # Core request parameters
    provider: LLMProvider = Field(..., description="LLM provider to use")
    model: LLMModel = Field(..., description="Specific model for generation")
    content_type: ContentType = Field(..., description="Type of content to generate")

    # Prompt content
    system_prompt: Optional[str] = Field(None, description="System prompt for context")
    user_prompt: str = Field(..., description="User prompt for generation")

    # Generation parameters
    temperature: float = Field(default=0.7, ge=0.0, le=2.0, description="Creativity/randomness level")
    max_tokens: int = Field(default=2000, ge=1, le=8000, description="Maximum tokens to generate")
    top_p: float = Field(default=0.9, ge=0.0, le=1.0, description="Nucleus sampling parameter")
    frequency_penalty: float = Field(default=0.0, ge=-2.0, le=2.0, description="Frequency penalty")
    presence_penalty: float = Field(default=0.0, ge=-2.0, le=2.0, description="Presence penalty")

    # ThreatSimGPT specific parameters
    scenario_context: Optional[Dict[str, Any]] = Field(None, description="Threat scenario context")
    target_profile: Optional[Dict[str, Any]] = Field(None, description="Target profile information")
    safety_filters: List[str] = Field(default_factory=list, description="Applied safety filters")

    # Request metadata
    request_id: str = Field(default_factory=lambda: f"req_{int(time.time() * 1000)}")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    timeout_seconds: int = Field(default=60, ge=5, le=300, description="Request timeout")

    @field_serializer('timestamp')
    def serialize_timestamp(self, value: datetime) -> str:
        """Serialize datetime to ISO format."""
        return value.isoformat()


class LLMResponse(BaseModel):
    """Comprehensive LLM response with metadata and validation."""

    # Request correlation
    request_id: str = Field(..., description="Corresponding request ID")
    provider: LLMProvider = Field(..., description="Provider that generated response")
    model: LLMModel = Field(..., description="Model used for generation")

    # Response content
    content: str = Field(..., description="Generated content")
    content_type: ContentType = Field(..., description="Type of generated content")

    # Generation metadata
    prompt_tokens: int = Field(..., description="Tokens used in prompt")
    completion_tokens: int = Field(..., description="Tokens used in completion")
    total_tokens: int = Field(..., description="Total tokens used")

    # Performance metrics
    response_time_ms: int = Field(..., description="Response time in milliseconds")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Quality and safety
    quality_score: Optional[float] = Field(None, ge=0.0, le=1.0, description="Content quality score")
    safety_flags: List[str] = Field(default_factory=list, description="Triggered safety flags")
    filtered_content: bool = Field(default=False, description="Whether content was filtered")

    # Provider-specific data
    raw_response: Optional[Dict[str, Any]] = Field(None, description="Raw provider response")
    finish_reason: Optional[str] = Field(None, description="Reason for completion")

    # Error handling
    error: Optional[str] = Field(None, description="Error message if generation failed")
    error_code: Optional[str] = Field(None, description="Provider-specific error code")

    @property
    def success(self) -> bool:
        """Check if the response was successful."""
        return self.error is None

    @property
    def cost_estimate(self) -> float:
        """Estimate cost based on token usage (rough calculation)."""
        # Rough cost estimates per 1K tokens (as of 2024)
        cost_per_1k_tokens = {
            LLMModel.GPT_4_TURBO: 0.01,
            LLMModel.GPT_4: 0.03,
            LLMModel.GPT_35_TURBO: 0.002,
            LLMModel.CLAUDE_3_SONNET: 0.015,
            LLMModel.CLAUDE_3_HAIKU: 0.0025,
            LLMModel.CLAUDE_2_1: 0.008,
            LLMModel.CLAUDE_2: 0.008,
        }

        rate = cost_per_1k_tokens.get(self.model, 0.01)  # Default rate
        return (self.total_tokens / 1000) * rate

    @field_serializer('timestamp')
    def serialize_timestamp(self, value: datetime) -> str:
        """Serialize datetime to ISO format."""
        return value.isoformat()


class LLMProviderConfig(BaseModel):
    """Configuration for LLM providers."""

    provider: LLMProvider = Field(..., description="Provider identifier")
    api_key: str = Field(..., description="API key for authentication")
    base_url: Optional[str] = Field(None, description="Custom base URL for API")
    organization: Optional[str] = Field(None, description="Organization ID (OpenAI)")
    default_model: LLMModel = Field(..., description="Default model to use")

    # Rate limiting
    max_requests_per_minute: int = Field(default=60, description="Request rate limit")
    max_tokens_per_minute: int = Field(default=100000, description="Token rate limit")

    # Retry configuration
    max_retries: int = Field(default=3, ge=0, le=10, description="Maximum retry attempts")
    retry_delay_seconds: float = Field(default=1.0, ge=0.1, le=60.0, description="Base retry delay")

    # Safety and compliance
    content_filter_enabled: bool = Field(default=True, description="Enable content filtering")
    audit_logging: bool = Field(default=True, description="Enable request/response logging")

    model_config = ConfigDict(
        str_strip_whitespace=True
    )

    def __repr__(self) -> str:
        """Custom repr that excludes sensitive api_key."""
        fields = {k: v for k, v in self.__dict__.items() if k != "api_key"}
        return f"{self.__class__.__name__}({fields})"


class PromptContext(BaseModel):
    """Context information for prompt generation."""

    # Scenario information
    threat_type: str = Field(..., description="Type of threat being simulated")
    delivery_vector: str = Field(..., description="Attack delivery method")
    difficulty_level: int = Field(..., ge=1, le=10, description="Scenario difficulty")

    # Target information
    target_role: str = Field(..., description="Target's job role")
    target_department: str = Field(..., description="Target's department")
    target_seniority: str = Field(..., description="Target's seniority level")
    target_technical_level: str = Field(..., description="Target's technical sophistication")
    target_industry: Optional[str] = Field(None, description="Target's industry")
    security_awareness_level: int = Field(default=5, ge=1, le=10, description="Target's security awareness")

    # Behavioral context
    psychological_triggers: List[str] = Field(default_factory=list, description="Psychological triggers to use")
    social_engineering_tactics: List[str] = Field(default_factory=list, description="SE tactics to employ")
    mitre_techniques: List[str] = Field(default_factory=list, description="MITRE ATT&CK techniques")

    # Content parameters
    urgency_level: int = Field(default=5, ge=1, le=10, description="Content urgency level")
    tone: str = Field(default="professional", description="Communication tone")
    language: str = Field(default="en", description="Content language")

    # Customization
    company_name: Optional[str] = Field(None, description="Target company name")
    custom_context: Dict[str, Any] = Field(default_factory=dict, description="Additional context")


class GenerationResult(BaseModel):
    """Result of content generation with validation and metadata."""

    # Generated content
    content: str = Field(..., description="Generated threat content")
    content_type: ContentType = Field(..., description="Type of generated content")

    # Generation metadata
    generation_id: str = Field(default_factory=lambda: f"gen_{int(time.time() * 1000)}")
    provider: LLMProvider = Field(..., description="Provider used")
    model: LLMModel = Field(..., description="Model used")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Quality metrics
    quality_score: float = Field(..., ge=0.0, le=1.0, description="Content quality assessment")
    realism_score: float = Field(..., ge=0.0, le=1.0, description="Content realism assessment")
    effectiveness_score: float = Field(..., ge=0.0, le=1.0, description="Predicted effectiveness")

    # Safety validation
    safety_passed: bool = Field(..., description="Passed safety validation")
    safety_issues: List[str] = Field(default_factory=list, description="Identified safety concerns")
    compliance_flags: List[str] = Field(default_factory=list, description="Compliance considerations")

    # Usage metrics
    tokens_used: int = Field(..., description="Total tokens consumed")
    generation_time_ms: int = Field(..., description="Time taken to generate")
    cost_estimate: float = Field(..., description="Estimated cost")

    # Context preservation
    prompt_context: PromptContext = Field(..., description="Context used for generation")

    @property
    def is_usable(self) -> bool:
        """Check if content is safe and usable."""
        return self.safety_passed and self.quality_score >= 0.6
