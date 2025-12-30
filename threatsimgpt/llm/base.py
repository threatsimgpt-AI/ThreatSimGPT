"""Base LLM provider interface for ThreatSimGPT."""

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class LLMResponse:
    """Response from LLM provider with metadata."""

    def __init__(self, content: str, provider: str = "unknown", model: str = "unknown"):
        self.content = content
        self.provider = provider
        self.model = model
        self.timestamp = datetime.utcnow()
        self.error: Optional[str] = None
        self.metadata: Dict[str, Any] = {}
        self.is_real_ai: bool = False  # Track if this is real AI or simulated content

    def __str__(self) -> str:
        ai_type = "Real AI" if self.is_real_ai else "Mock/Simulated"
        return f"LLMResponse(provider={self.provider}, model={self.model}, type={ai_type}, length={len(self.content)})"


class BaseLLMProvider(ABC):
    """Abstract base class for LLM providers."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize the provider with configuration."""
        self.config = config
        self.api_key = config.get('api_key')
        self.model = config.get('model', 'default-model')
        self.base_url = config.get('base_url')
        self.timeout_seconds = config.get('timeout_seconds', 30)
        self.retry_attempts = config.get('retry_attempts', 3)

    @abstractmethod
    async def generate_content(
        self,
        prompt: str,
        max_tokens: int = 1000,
        temperature: float = 0.7,
        **kwargs
    ) -> LLMResponse:
        """Generate content from prompt.

        Args:
            prompt: The input prompt
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            **kwargs: Additional provider-specific parameters

        Returns:
            LLMResponse with generated content
        """
        pass

    def is_available(self) -> bool:
        """Check if provider is properly configured and available."""
        return bool(self.api_key)

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the configured model."""
        return {
            "provider": self.__class__.__name__,
            "model": self.model,
            "available": self.is_available()
        }
