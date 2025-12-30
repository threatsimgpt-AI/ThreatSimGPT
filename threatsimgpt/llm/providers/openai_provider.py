"""OpenAI provider implementation for ThreatSimGPT."""

import asyncio
import logging
from typing import Dict, Any, Optional
from datetime import datetime

from ..base import BaseLLMProvider, LLMResponse

logger = logging.getLogger(__name__)


class OpenAIProvider(BaseLLMProvider):
    """OpenAI LLM provider implementation."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize OpenAI provider.

        Args:
            config: Configuration dictionary with OpenAI settings
        """
        super().__init__(config)
        self.api_key = config.get('api_key')
        self.model = config.get('model', 'gpt-4o-mini')
        self.base_url = config.get('base_url', 'https://api.openai.com/v1')
        self._client = None

        if not self.api_key:
            raise ValueError("OpenAI API key is required")

    def _get_client(self):
        """Get or create OpenAI client."""
        if self._client is None:
            try:
                from openai import AsyncOpenAI
                self._client = AsyncOpenAI(
                    api_key=self.api_key,
                    base_url=self.base_url
                )
            except ImportError:
                raise ImportError(
                    "OpenAI SDK not installed. Install with: pip install openai"
                )
        return self._client

    async def generate_content(
        self,
        prompt: str,
        max_tokens: int = 1000,
        temperature: float = 0.7,
        **kwargs
    ) -> LLMResponse:
        """Generate content using OpenAI API.

        Args:
            prompt: The prompt to send to OpenAI
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            **kwargs: Additional parameters

        Returns:
            LLMResponse with generated content
        """
        try:
            client = self._get_client()

            # Build messages
            system_message = kwargs.get('system_message',
                "You are a cybersecurity expert assistant for threat simulation and security training."
            )

            messages = [
                {"role": "system", "content": system_message},
                {"role": "user", "content": prompt}
            ]

            # Make API call
            response = await client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
                **{k: v for k, v in kwargs.items() if k not in ['system_message']}
            )

            content = response.choices[0].message.content

            llm_response = LLMResponse(
                content=content,
                provider="openai",
                model=self.model,
                tokens_used=response.usage.total_tokens if response.usage else 0,
                timestamp=datetime.utcnow(),
                metadata={
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                    "prompt_length": len(prompt),
                    "finish_reason": response.choices[0].finish_reason,
                    "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                    "completion_tokens": response.usage.completion_tokens if response.usage else 0
                }
            )
            llm_response.is_real_ai = True

            logger.info(f"OpenAI API response received: {len(content)} chars, {llm_response.tokens_used} tokens")
            return llm_response

        except ImportError as e:
            logger.error(f"OpenAI SDK not available: {e}")
            raise
        except Exception as e:
            logger.error(f"OpenAI content generation failed: {e}")
            raise

    async def validate_connection(self) -> bool:
        """Validate connection to OpenAI API."""
        try:
            client = self._get_client()

            # Make a minimal API call to validate
            response = await client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": "test"}],
                max_tokens=5
            )

            return response.choices[0].message.content is not None

        except Exception as e:
            logger.error(f"OpenAI connection validation failed: {e}")
            return False

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current model."""
        return {
            "provider": "openai",
            "model": self.model,
            "base_url": self.base_url,
            "configured": bool(self.api_key)
        }
