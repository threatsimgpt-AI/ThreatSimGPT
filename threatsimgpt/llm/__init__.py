"""Comprehensive LLM integration package for ThreatSimGPT.

This package provides complete LLM integration including:
- Provider abstraction layer (OpenAI, Anthropic)
- Advanced prompt engineering framework
- Content generation service
- Safety validation and quality assessment
- Request/response models and configuration
"""

# Core models and enums
from .models import (
    ContentType,
    GenerationResult,
    LLMModel,
    LLMProvider,
    LLMProviderConfig,
    LLMRequest,
    LLMResponse,
    PromptContext,
    PromptTemplate,
)

# Provider system
try:
    from .providers import (
        AnthropicProvider,
        BaseLLMProvider,
        LLMProviderManager,
        OpenAIProvider,
        RateLimiter,
    )
except ImportError:
    # Fallback - providers are not yet implemented in the separate files
    # Use the implementation from providers.py
    from .providers_new import (
        AnthropicProvider,
        BaseLLMProvider,
        LLMProviderManager,
        OpenAIProvider,
        RateLimiter,
    )

# Prompt engineering
from .prompts import (
    PromptContextBuilder,
    PromptEngine,
    PromptTemplateLibrary,
)

# Content generation service
from .generation import ContentGenerationService

# Validation and safety
from .validation import (
    ContentValidator,
    QualityResult,
    SafetyFilter,
    SafetyLevel,
    SafetyResult,
)

__all__ = [
    # Models and enums
    "ContentType",
    "GenerationResult",
    "LLMModel",
    "LLMProvider",
    "LLMProviderConfig",
    "LLMRequest",
    "LLMResponse",
    "PromptContext",
    "PromptTemplate",

    # Provider system
    "AnthropicProvider",
    "BaseLLMProvider",
    "LLMProviderManager",
    "OpenAIProvider",
    "RateLimiter",

    # Prompt engineering
    "PromptContextBuilder",
    "PromptEngine",
    "PromptTemplateLibrary",

    # Content generation
    "ContentGenerationService",

    # Validation and safety
    "ContentValidator",
    "QualityResult",
    "SafetyFilter",
    "SafetyLevel",
    "SafetyResult",
]
