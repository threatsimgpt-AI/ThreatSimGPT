"""Content generation service for ThreatSimGPT.

This module provides the main content generation interface, combining
LLM providers, prompt engineering, and response validation into a
cohesive service for threat simulation content creation.
"""

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

from .models import (
    ContentType,
    GenerationResult,
    LLMModel,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    PromptContext,
)
from .prompts import PromptContextBuilder, PromptEngine
try:
    from .providers import LLMProviderManager
except ImportError:
    from .providers_new import LLMProviderManager
from .validation import ContentValidator, SafetyFilter

logger = logging.getLogger(__name__)


class ContentGenerationService:
    """Main service for generating threat simulation content using LLMs."""

    def __init__(self, provider_manager: LLMProviderManager):
        self.provider_manager = provider_manager
        self.prompt_engine = PromptEngine()
        self.content_validator = ContentValidator()
        self.safety_filter = SafetyFilter()

        # Generation statistics
        self.stats = {
            "total_requests": 0,
            "successful_generations": 0,
            "failed_generations": 0,
            "total_tokens_used": 0,
            "total_cost_estimate": 0.0,
        }

    async def generate_content(
        self,
        content_type: ContentType,
        scenario_data: Dict[str, Any],
        provider: Optional[LLMProvider] = None,
        model: Optional[LLMModel] = None,
        generation_params: Optional[Dict[str, Any]] = None
    ) -> GenerationResult:
        """Generate threat simulation content based on scenario data."""

        start_time = time.time()
        generation_id = f"gen_{int(start_time * 1000)}"

        try:
            # Build prompt context from scenario data
            context = PromptContextBuilder.from_scenario(scenario_data)

            # Generate prompts using the prompt engine
            prompts = self.prompt_engine.generate_prompts(content_type, context)

            # Determine provider and model
            target_provider = provider or self.provider_manager.default_provider
            if target_provider is None:
                raise ValueError("No LLM provider specified or configured")

            # Get default model if not specified
            if model is None:
                supported_models = self.provider_manager.get_supported_models(target_provider)
                if not supported_models:
                    raise ValueError(f"No supported models for provider {target_provider}")
                model = supported_models[0]  # Use first available model

            # Prepare generation parameters
            params = generation_params or {}

            # Create LLM request
            request = LLMRequest(
                provider=target_provider,
                model=model,
                content_type=content_type,
                system_prompt=prompts["system_prompt"],
                user_prompt=prompts["user_prompt"],
                temperature=params.get("temperature", 0.7),
                max_tokens=params.get("max_tokens", 2000),
                top_p=params.get("top_p", 0.9),
                scenario_context=scenario_data,
                target_profile=scenario_data.get("target_profile", {}),
                safety_filters=params.get("safety_filters", [])
            )

            # Update statistics
            self.stats["total_requests"] += 1

            # Generate content
            response = await self.provider_manager.generate(request)

            if not response.success:
                self.stats["failed_generations"] += 1
                return self._create_error_result(
                    generation_id, content_type, context, target_provider, model,
                    f"LLM generation failed: {response.error}", start_time
                )

            # Update token statistics
            self.stats["total_tokens_used"] += response.total_tokens
            self.stats["total_cost_estimate"] += response.cost_estimate

            # Validate content safety
            safety_result = await self.safety_filter.validate_content(
                response.content, content_type, context
            )

            if not safety_result.passed:
                self.stats["failed_generations"] += 1
                return self._create_error_result(
                    generation_id, content_type, context, target_provider, model,
                    f"Content failed safety validation: {'; '.join(safety_result.issues)}",
                    start_time, safety_issues=safety_result.issues
                )

            # Validate content quality
            quality_result = await self.content_validator.validate_content(
                response.content, content_type, context
            )

            # Create successful generation result
            generation_time = int((time.time() - start_time) * 1000)
            self.stats["successful_generations"] += 1

            result = GenerationResult(
                content=response.content,
                content_type=content_type,
                generation_id=generation_id,
                provider=target_provider,
                model=model,

                # Quality metrics
                quality_score=quality_result.quality_score,
                realism_score=quality_result.realism_score,
                effectiveness_score=quality_result.effectiveness_score,

                # Safety validation
                safety_passed=safety_result.passed,
                safety_issues=safety_result.issues,
                compliance_flags=safety_result.compliance_flags,

                # Usage metrics
                tokens_used=response.total_tokens,
                generation_time_ms=generation_time,
                cost_estimate=response.cost_estimate,

                # Context preservation
                prompt_context=context
            )

            logger.info(f"Successfully generated {content_type.value} content "
                       f"(ID: {generation_id}, Quality: {quality_result.quality_score:.2f})")

            return result

        except Exception as e:
            self.stats["failed_generations"] += 1
            logger.error(f"Content generation failed: {e}")

            return self._create_error_result(
                generation_id, content_type,
                PromptContextBuilder.from_scenario(scenario_data),
                provider, model, str(e), start_time
            )

    def _create_error_result(
        self,
        generation_id: str,
        content_type: ContentType,
        context: PromptContext,
        provider: Optional[LLMProvider],
        model: Optional[LLMModel],
        error_message: str,
        start_time: float,
        safety_issues: Optional[List[str]] = None
    ) -> GenerationResult:
        """Create an error generation result."""

        generation_time = int((time.time() - start_time) * 1000)

        return GenerationResult(
            content=f"ERROR: {error_message}",
            content_type=content_type,
            generation_id=generation_id,
            provider=provider or LLMProvider.OPENAI,
            model=model or LLMModel.GPT_35_TURBO,

            # Failed quality metrics
            quality_score=0.0,
            realism_score=0.0,
            effectiveness_score=0.0,

            # Safety validation
            safety_passed=False,
            safety_issues=safety_issues or [error_message],
            compliance_flags=["generation_error"],

            # Usage metrics
            tokens_used=0,
            generation_time_ms=generation_time,
            cost_estimate=0.0,

            # Context preservation
            prompt_context=context
        )

    async def generate_multiple_variants(
        self,
        content_type: ContentType,
        scenario_data: Dict[str, Any],
        variant_count: int = 3,
        provider: Optional[LLMProvider] = None,
        model: Optional[LLMModel] = None
    ) -> List[GenerationResult]:
        """Generate multiple variants of the same content type."""

        if variant_count <= 0 or variant_count > 10:
            raise ValueError("Variant count must be between 1 and 10")

        # Generate variants with different temperature settings
        temperatures = [0.3, 0.7, 1.0, 1.2, 0.5, 0.9, 0.4, 0.8, 1.1, 0.6][:variant_count]

        tasks = []
        for i, temp in enumerate(temperatures):
            params = {"temperature": temp}
            task = self.generate_content(
                content_type, scenario_data, provider, model, params
            )
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions and return successful results
        valid_results = []
        for result in results:
            if isinstance(result, GenerationResult):
                valid_results.append(result)
            else:
                logger.warning(f"Variant generation failed: {result}")

        return valid_results

    async def generate_campaign_content(
        self,
        scenario_data: Dict[str, Any],
        content_types: List[ContentType],
        provider: Optional[LLMProvider] = None,
        model: Optional[LLMModel] = None
    ) -> Dict[ContentType, GenerationResult]:
        """Generate a complete campaign with multiple content types."""

        tasks = []
        for content_type in content_types:
            task = self.generate_content(
                content_type, scenario_data, provider, model
            )
            tasks.append((content_type, task))

        results = {}
        for content_type, task in tasks:
            try:
                result = await task
                results[content_type] = result
            except Exception as e:
                logger.error(f"Failed to generate {content_type.value}: {e}")
                # Create error result
                results[content_type] = self._create_error_result(
                    f"campaign_{int(time.time() * 1000)}", content_type,
                    PromptContextBuilder.from_scenario(scenario_data),
                    provider, model, str(e), time.time()
                )

        return results

    def get_generation_statistics(self) -> Dict[str, Any]:
        """Get service statistics."""
        return {
            **self.stats,
            "success_rate": (
                self.stats["successful_generations"] / max(1, self.stats["total_requests"])
            ),
            "average_cost_per_request": (
                self.stats["total_cost_estimate"] / max(1, self.stats["total_requests"])
            ),
            "available_providers": self.provider_manager.list_providers(),
            "available_templates": len(self.prompt_engine.templates)
        }

    def reset_statistics(self):
        """Reset generation statistics."""
        self.stats = {
            "total_requests": 0,
            "successful_generations": 0,
            "failed_generations": 0,
            "total_tokens_used": 0,
            "total_cost_estimate": 0.0,
        }

    async def test_providers(self) -> Dict[str, Dict[str, Any]]:
        """Test all configured providers with a simple request."""

        results = {}
        test_context = PromptContext(
            threat_type="test",
            delivery_vector="email",
            difficulty_level=1,
            target_role="employee",
            target_department="IT",
            target_seniority="junior",
            target_technical_level="basic"
        )

        for provider_name in self.provider_manager.list_providers():
            provider = LLMProvider(provider_name)
            supported_models = self.provider_manager.get_supported_models(provider)

            if not supported_models:
                results[provider_name] = {"status": "error", "message": "No supported models"}
                continue

            try:
                # Simple test request
                request = LLMRequest(
                    provider=provider,
                    model=supported_models[0],
                    content_type=ContentType.EMAIL_PHISHING,
                    system_prompt="You are a helpful assistant.",
                    user_prompt="Say 'Hello, this is a test.'",
                    max_tokens=50,
                    temperature=0.1
                )

                start_time = time.time()
                response = await self.provider_manager.generate(request)
                test_time = int((time.time() - start_time) * 1000)

                if response.success:
                    results[provider_name] = {
                        "status": "success",
                        "response_time_ms": test_time,
                        "tokens_used": response.total_tokens,
                        "cost_estimate": response.cost_estimate,
                        "supported_models": [m.value for m in supported_models]
                    }
                else:
                    results[provider_name] = {
                        "status": "error",
                        "message": response.error,
                        "error_code": response.error_code
                    }

            except Exception as e:
                results[provider_name] = {
                    "status": "exception",
                    "message": str(e)
                }

        return results

    async def close(self):
        """Close the service and all provider connections."""
        await self.provider_manager.close_all()
