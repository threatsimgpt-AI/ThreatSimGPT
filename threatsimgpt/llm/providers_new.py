"""Provider abstraction layer for LLM integrations.

This module provides a unified interface for multiple LLM providers,
handling authentication, rate limiting, retries, and response normalization.
"""

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import httpx
from pydantic import ValidationError

from .models import (
    ContentType,
    GenerationResult,
    LLMModel,
    LLMProvider,
    LLMProviderConfig,
    LLMRequest,
    LLMResponse,
    PromptContext,
)

logger = logging.getLogger(__name__)


class RateLimiter:
    """Token bucket rate limiter for API requests."""

    def __init__(self, max_requests: int, max_tokens: int, window_seconds: int = 60):
        self.max_requests = max_requests
        self.max_tokens = max_tokens
        self.window_seconds = window_seconds

        self.request_timestamps = []
        self.token_timestamps = []
        self.token_counts = []

    async def acquire(self, estimated_tokens: int = 1000) -> bool:
        """Acquire rate limit permission for a request."""
        now = time.time()

        # Clean old timestamps
        cutoff = now - self.window_seconds
        self.request_timestamps = [t for t in self.request_timestamps if t > cutoff]

        # Clean old token usage
        while self.token_timestamps and self.token_timestamps[0] <= cutoff:
            self.token_timestamps.pop(0)
            self.token_counts.pop(0)

        # Check request limit
        if len(self.request_timestamps) >= self.max_requests:
            return False

        # Check token limit
        current_tokens = sum(self.token_counts)
        if current_tokens + estimated_tokens > self.max_tokens:
            return False

        # Record this request
        self.request_timestamps.append(now)
        self.token_timestamps.append(now)
        self.token_counts.append(estimated_tokens)

        return True


class BaseLLMProvider(ABC):
    """Abstract base class for LLM providers."""

    def __init__(self, config: LLMProviderConfig):
        self.config = config
        self.rate_limiter = RateLimiter(
            max_requests=config.max_requests_per_minute,
            max_tokens=config.max_tokens_per_minute
        )
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=30.0)
        return self._client

    async def close(self):
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    def _build_error_response(
        self,
        request: LLMRequest,
        error: str,
        error_code: str,
        start_time: float
    ) -> LLMResponse:
        """Build a standardized error response.

        Args:
            request: The original request
            error: Error message
            error_code: Error code
            start_time: Request start time for calculating response time

        Returns:
            LLMResponse with error details
        """
        return LLMResponse(
            request_id=request.request_id,
            provider=request.provider,
            model=request.model,
            content="",
            content_type=request.content_type,
            prompt_tokens=0,
            completion_tokens=0,
            total_tokens=0,
            response_time_ms=int((time.time() - start_time) * 1000),
            error=error,
            error_code=error_code
        )

    @abstractmethod
    async def generate(self, request: LLMRequest) -> LLMResponse:
        """Generate content using the provider's API."""
        pass

    @abstractmethod
    def estimate_tokens(self, text: str) -> int:
        """Estimate token count for text."""
        pass

    @abstractmethod
    def validate_model(self, model: LLMModel) -> bool:
        """Check if model is supported by this provider."""
        pass

    async def generate_with_retry(self, request: LLMRequest) -> LLMResponse:
        """Generate content with automatic retries and rate limiting."""
        start_time = time.time()
        estimated_tokens = self.estimate_tokens(request.user_prompt)
        if request.system_prompt:
            estimated_tokens += self.estimate_tokens(request.system_prompt)

        # Rate limiting
        max_wait = 60  # Maximum wait time in seconds
        wait_time = 1

        while wait_time <= max_wait:
            if await self.rate_limiter.acquire(estimated_tokens):
                break
            logger.warning(f"Rate limit hit, waiting {wait_time}s")
            await asyncio.sleep(wait_time)
            wait_time = min(wait_time * 2, max_wait)
        else:
            raise RuntimeError("Rate limit exceeded, max wait time reached")

        # Retry logic
        last_exception = None

        for attempt in range(self.config.max_retries + 1):
            try:
                return await self.generate(request)
            except Exception as e:
                last_exception = e
                if attempt < self.config.max_retries:
                    delay = self.config.retry_delay_seconds * (2 ** attempt)
                    logger.warning(f"Request failed (attempt {attempt + 1}), retrying in {delay}s: {e}")
                    await asyncio.sleep(delay)
                else:
                    logger.error(f"Request failed after {self.config.max_retries + 1} attempts: {e}")

        # Return error response using helper method
        return self._build_error_response(
            request=request,
            error=str(last_exception),
            error_code="generation_failed",
            start_time=start_time
        )


class OpenAIProvider(BaseLLMProvider):
    """OpenAI API provider implementation."""

    SUPPORTED_MODELS = {
        LLMModel.GPT_4_TURBO,
        LLMModel.GPT_4,
        LLMModel.GPT_35_TURBO,
    }

    def __init__(self, config: LLMProviderConfig):
        super().__init__(config)
        self.base_url = config.base_url or "https://api.openai.com/v1"

    def validate_model(self, model: LLMModel) -> bool:
        """Check if model is supported by OpenAI."""
        return model in self.SUPPORTED_MODELS

    def estimate_tokens(self, text: str) -> int:
        """Rough token estimation (1 token ≈ 4 characters for English)."""
        return max(1, len(text) // 4)

    async def generate(self, request: LLMRequest) -> LLMResponse:
        """Generate content using OpenAI API."""
        if not self.validate_model(request.model):
            raise ValueError(f"Model {request.model} not supported by OpenAI provider")

        start_time = time.time()

        # Prepare request payload
        messages = []
        if request.system_prompt:
            messages.append({"role": "system", "content": request.system_prompt})
        messages.append({"role": "user", "content": request.user_prompt})

        payload = {
            "model": request.model.value,
            "messages": messages,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
            "top_p": request.top_p,
            "frequency_penalty": request.frequency_penalty,
            "presence_penalty": request.presence_penalty,
        }

        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }

        if self.config.organization:
            headers["OpenAI-Organization"] = self.config.organization

        try:
            response = await self.client.post(
                f"{self.base_url}/chat/completions",
                json=payload,
                headers=headers,
                timeout=request.timeout_seconds
            )
            response.raise_for_status()

            data = response.json()
            response_time = int((time.time() - start_time) * 1000)

            # Extract response data
            choice = data["choices"][0]
            usage = data["usage"]

            return LLMResponse(
                request_id=request.request_id,
                provider=request.provider,
                model=request.model,
                content=choice["message"]["content"],
                content_type=request.content_type,
                prompt_tokens=usage["prompt_tokens"],
                completion_tokens=usage["completion_tokens"],
                total_tokens=usage["total_tokens"],
                response_time_ms=response_time,
                finish_reason=choice.get("finish_reason"),
                raw_response=data
            )

        except httpx.HTTPStatusError as e:
            error_msg = f"OpenAI API error: {e.response.status_code}"
            try:
                error_data = e.response.json()
                error_msg += f" - {error_data.get('error', {}).get('message', 'Unknown error')}"
            except:
                error_msg += f" - {e.response.text}"

            return self._build_error_response(
                request=request,
                error=error_msg,
                error_code=str(e.response.status_code),
                start_time=start_time
            )

        except Exception as e:
            return self._build_error_response(
                request=request,
                error=str(e),
                error_code="request_failed",
                start_time=start_time
            )


class AnthropicProvider(BaseLLMProvider):
    """Anthropic Claude API provider implementation."""

    SUPPORTED_MODELS = {
        LLMModel.CLAUDE_3_SONNET,
        LLMModel.CLAUDE_3_HAIKU,
        LLMModel.CLAUDE_2_1,
        LLMModel.CLAUDE_2,
    }

    def __init__(self, config: LLMProviderConfig):
        super().__init__(config)
        self.base_url = config.base_url or "https://api.anthropic.com"

    def validate_model(self, model: LLMModel) -> bool:
        """Check if model is supported by Anthropic."""
        return model in self.SUPPORTED_MODELS

    def estimate_tokens(self, text: str) -> int:
        """Rough token estimation for Claude."""
        return max(1, len(text) // 3)  # Claude tends to have slightly better compression

    async def generate(self, request: LLMRequest) -> LLMResponse:
        """Generate content using Anthropic API."""
        if not self.validate_model(request.model):
            raise ValueError(f"Model {request.model} not supported by Anthropic provider")

        start_time = time.time()

        # Prepare request payload
        payload = {
            "model": request.model.value,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "top_p": request.top_p,
            "messages": [
                {"role": "user", "content": request.user_prompt}
            ]
        }

        # Add system prompt if provided
        if request.system_prompt:
            payload["system"] = request.system_prompt

        headers = {
            "x-api-key": self.config.api_key,
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        }

        try:
            response = await self.client.post(
                f"{self.base_url}/v1/messages",
                json=payload,
                headers=headers,
                timeout=request.timeout_seconds
            )
            response.raise_for_status()

            data = response.json()
            response_time = int((time.time() - start_time) * 1000)

            # Extract response data
            content = data["content"][0]["text"] if data["content"] else ""
            usage = data["usage"]

            return LLMResponse(
                request_id=request.request_id,
                provider=request.provider,
                model=request.model,
                content=content,
                content_type=request.content_type,
                prompt_tokens=usage["input_tokens"],
                completion_tokens=usage["output_tokens"],
                total_tokens=usage["input_tokens"] + usage["output_tokens"],
                response_time_ms=response_time,
                finish_reason=data.get("stop_reason"),
                raw_response=data
            )

        except httpx.HTTPStatusError as e:
            error_msg = f"Anthropic API error: {e.response.status_code}"
            try:
                error_data = e.response.json()
                error_msg += f" - {error_data.get('error', {}).get('message', 'Unknown error')}"
            except:
                error_msg += f" - {e.response.text}"

            return self._build_error_response(
                request=request,
                error=error_msg,
                error_code=str(e.response.status_code),
                start_time=start_time
            )

        except Exception as e:
            return self._build_error_response(
                request=request,
                error=str(e),
                error_code="request_failed",
                start_time=start_time
            )


class OpenRouterProviderAdapter(BaseLLMProvider):
    """Adapter for OpenRouter provider to work with the new provider interface."""

    def __init__(self, config: LLMProviderConfig):
        super().__init__(config)
        self.api_key = config.api_key
        self.model = config.default_model.value
        self.base_url = "https://openrouter.ai/api/v1"

    async def generate(self, request: LLMRequest) -> LLMResponse:
        """Generate content using OpenRouter API."""
        start_time = time.time()

        if not self.api_key:
            return self._build_error_response(
                request=request,
                error="OpenRouter API key not configured",
                error_code="missing_api_key",
                start_time=start_time
            )

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "HTTP-Referer": "https://github.com/threatsimgpt-AI/ThreatSimGPT",
            "X-Title": "ThreatSimGPT",
            "Content-Type": "application/json"
        }

        messages = []
        if request.system_prompt:
            messages.append({"role": "system", "content": request.system_prompt})
        messages.append({"role": "user", "content": request.user_prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature
        }

        try:
            response = await self.client.post(
                f"{self.base_url}/chat/completions",
                json=payload,
                headers=headers
            )

            if response.status_code == 200:
                data = response.json()
                choice = data["choices"][0]
                usage = data.get("usage", {})

                return LLMResponse(
                    request_id=request.request_id,
                    provider=request.provider,
                    model=request.model,
                    content=choice["message"]["content"],
                    content_type=request.content_type,
                    prompt_tokens=usage.get("prompt_tokens", 0),
                    completion_tokens=usage.get("completion_tokens", 0),
                    total_tokens=usage.get("total_tokens", 0),
                    response_time_ms=int((time.time() - start_time) * 1000),
                    raw_response=data
                )
            else:
                error_data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
                error_msg = error_data.get("error", {}).get("message", f"HTTP {response.status_code}")

                return self._build_error_response(
                    request=request,
                    error=error_msg,
                    error_code=f"http_{response.status_code}",
                    start_time=start_time
                )

        except Exception as e:
            return self._build_error_response(
                request=request,
                error=str(e),
                error_code="request_failed",
                start_time=start_time
            )

    def estimate_tokens(self, text: str) -> int:
        """Estimate token count for text."""
        # Simple estimation: ~4 characters per token
        return len(text) // 4

    def validate_model(self, model: LLMModel) -> bool:
        """Check if model is supported by OpenRouter."""
        # OpenRouter supports many models, so we'll accept most common ones
        return True


class LLMProviderManager:
    """Manager for multiple LLM providers with automatic routing."""

    def __init__(self):
        self.providers: Dict[LLMProvider, BaseLLMProvider] = {}
        self.default_provider: Optional[LLMProvider] = None

    def add_provider(self, config: LLMProviderConfig, set_as_default: bool = False):
        """Add a provider configuration."""
        if config.provider == LLMProvider.OPENAI:
            provider = OpenAIProvider(config)
        elif config.provider == LLMProvider.ANTHROPIC:
            provider = AnthropicProvider(config)
        elif config.provider == LLMProvider.OPENROUTER:
            # Create a simple OpenRouter provider for testing
            provider = OpenRouterProviderAdapter(config)
        else:
            raise ValueError(f"Unsupported provider: {config.provider}")

        self.providers[config.provider] = provider

        if set_as_default or self.default_provider is None:
            self.default_provider = config.provider

    def get_provider(self, provider: Optional[LLMProvider] = None) -> BaseLLMProvider:
        """Get a specific provider or the default one."""
        target_provider = provider or self.default_provider

        if target_provider is None:
            raise ValueError("No provider specified and no default provider set")

        if target_provider not in self.providers:
            raise ValueError(f"Provider {target_provider} not configured")

        return self.providers[target_provider]

    async def generate(self, request: LLMRequest) -> LLMResponse:
        """Generate content using the appropriate provider."""
        provider = self.get_provider(request.provider)
        return await provider.generate_with_retry(request)

    async def close_all(self):
        """Close all provider connections."""
        for provider in self.providers.values():
            await provider.close()

    def list_providers(self) -> List[str]:
        """List configured providers."""
        return [p.value for p in self.providers.keys()]

    def get_supported_models(self, provider: Optional[LLMProvider] = None) -> List[LLMModel]:
        """Get supported models for a provider."""
        target_provider = provider or self.default_provider

        if target_provider == LLMProvider.OPENAI:
            return list(OpenAIProvider.SUPPORTED_MODELS)
        elif target_provider == LLMProvider.ANTHROPIC:
            return list(AnthropicProvider.SUPPORTED_MODELS)
        elif target_provider == LLMProvider.OPENROUTER:
            # OpenRouter supports many models - return common ones
            return [LLMModel.GPT_35_TURBO, LLMModel.GPT_4, LLMModel.CLAUDE_3_HAIKU]
        else:
            return []
