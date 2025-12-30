"""LLM manager for ThreatSimGPT content generation.

This module provides a production-ready LLM manager that handles
content generation for threat scenarios with multiple provider support.
"""

import os
import logging
import asyncio
from typing import Optional, Dict, Any, List
from datetime import datetime

from .base import BaseLLMProvider, LLMResponse
from .providers.openai_provider import OpenAIProvider
from .providers.anthropic_provider import AnthropicProvider
from .providers.openrouter_provider import OpenRouterProvider
from .providers.ollama_provider import OllamaProvider

# Local model providers (with optional imports)
try:
    from .providers.ollama_provider import OllamaProvider
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

try:
    from .providers.huggingface_provider import HuggingFaceProvider
    HUGGINGFACE_AVAILABLE = True
except ImportError:
    HUGGINGFACE_AVAILABLE = False

try:
    from .providers.llamacpp_provider import LlamaCppProvider
    LLAMACPP_AVAILABLE = True
except ImportError:
    LLAMACPP_AVAILABLE = False

logger = logging.getLogger(__name__)


class LLMManager:
    """Production-ready LLM manager for threat content generation."""

    def __init__(self, provider: Optional[BaseLLMProvider] = None, config: Optional[Dict[str, Any]] = None):
        """Initialize LLM manager.

        Args:
            provider: Specific LLM provider to use
            config: Configuration for LLM providers
        """
        self.config = config or {}
        self.provider = provider
        self._providers: Dict[str, BaseLLMProvider] = {}
        self._session: Optional[Any] = None  # For HTTP session management
        self._initialize_providers()

    async def _get_session(self):
        """Get or create aiohttp session with connection pooling."""
        if self._session is None or (hasattr(self._session, 'closed') and self._session.closed):
            try:
                import aiohttp
                self._session = aiohttp.ClientSession()
            except ImportError:
                logger.warning("aiohttp not available for session management")
                self._session = None
        return self._session

    async def cleanup(self):
        """Clean up resources."""
        if self._session and hasattr(self._session, 'close') and not self._session.closed:
            await self._session.close()

    def _initialize_providers(self) -> None:
        """Initialize available LLM providers."""
        try:
            # Initialize OpenAI if configured
            openai_config = self.config.get('openai', {})
            if openai_config.get('api_key'):
                self._providers['openai'] = OpenAIProvider(openai_config)
                logger.info("OpenAI provider initialized")

            # Initialize Anthropic if configured
            anthropic_config = self.config.get('anthropic', {})
            if anthropic_config.get('api_key'):
                self._providers['anthropic'] = AnthropicProvider(anthropic_config)
                logger.info("Anthropic provider initialized")

            # Initialize OpenRouter if configured
            openrouter_config = self.config.get('openrouter', {})
            if openrouter_config.get('api_key'):
                self._providers['openrouter'] = OpenRouterProvider(openrouter_config)
                logger.info("OpenRouter provider initialized")

            # Initialize local model providers
            self._initialize_local_providers()

            # Set default provider if not specified
            if not self.provider and self._providers:
                # Check environment variable for preferred provider
                default_provider = os.getenv('DEFAULT_LLM_PROVIDER', '').lower()

                # First, try to use the explicitly configured default provider from env var
                if default_provider and default_provider in self._providers:
                    self.provider = self._providers[default_provider]
                    logger.info(f"Using default provider from environment: {default_provider}")
                # Second, prefer OpenRouter if available (recommended provider with most model options)
                elif 'openrouter' in self._providers:
                    self.provider = self._providers['openrouter']
                    logger.info("Using default provider: openrouter (recommended)")
                # Third, prefer local providers for better privacy/control
                else:
                    local_providers = ['ollama', 'huggingface', 'llamacpp']
                    for provider_name in local_providers:
                        if provider_name in self._providers:
                            self.provider = self._providers[provider_name]
                            logger.info(f"Using default local provider: {provider_name}")
                            break
                    else:
                        # Fall back to any available cloud provider
                        provider_name = list(self._providers.keys())[0]
                        self.provider = self._providers[provider_name]
                        logger.info(f"Using default provider: {provider_name}")

        except Exception as e:
            logger.warning(f"Failed to initialize some LLM providers: {e}")

    def _initialize_local_providers(self) -> None:
        """Initialize local model providers if available and configured."""
        try:
            # Initialize Ollama if available and configured
            if OLLAMA_AVAILABLE:
                ollama_config = self.config.get('ollama', {})
                if ollama_config or self._auto_detect_ollama():
                    try:
                        self._providers['ollama'] = OllamaProvider(ollama_config)
                        logger.info("Ollama provider initialized")
                    except Exception as e:
                        logger.warning(f"Failed to initialize Ollama provider: {e}")

            # Initialize Hugging Face if available and configured
            if HUGGINGFACE_AVAILABLE:
                hf_config = self.config.get('huggingface', {})
                if hf_config:
                    try:
                        self._providers['huggingface'] = HuggingFaceProvider(hf_config)
                        logger.info("Hugging Face provider initialized")
                    except Exception as e:
                        logger.warning(f"Failed to initialize Hugging Face provider: {e}")

            # Initialize llama.cpp if available and configured
            if LLAMACPP_AVAILABLE:
                llamacpp_config = self.config.get('llamacpp', {})
                if llamacpp_config and llamacpp_config.get('model_path'):
                    try:
                        self._providers['llamacpp'] = LlamaCppProvider(llamacpp_config)
                        logger.info("llama.cpp provider initialized")
                    except Exception as e:
                        logger.warning(f"Failed to initialize llama.cpp provider: {e}")

        except Exception as e:
            logger.warning(f"Failed to initialize local providers: {e}")

    def _auto_detect_ollama(self) -> bool:
        """Auto-detect if Ollama is available on the system."""
        try:
            import aiohttp
            import asyncio

            async def check_ollama():
                try:
                    session = await self._get_session()
                    if session is None:
                        return False
                    timeout = aiohttp.ClientTimeout(total=2)
                    async with session.get('http://localhost:11434/api/tags', timeout=timeout) as response:
                        return response.status == 200
                except:
                    return False

            # Run the check
            try:
                loop = asyncio.get_event_loop()
                return loop.run_until_complete(check_ollama())
            except:
                # Create new event loop if none exists
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                result = loop.run_until_complete(check_ollama())
                loop.close()
                return result

        except Exception:
            return False

    async def generate_content(
        self,
        prompt: str,
        scenario_type: str = "general",
        max_tokens: int = 1000,
        temperature: float = 0.7,
        provider_name: Optional[str] = None
    ) -> LLMResponse:
        """Generate content using the configured LLM provider.

        Args:
            prompt: The prompt to send to the LLM
            scenario_type: Type of scenario for context
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            provider_name: Specific provider to use

        Returns:
            LLMResponse with generated content

        Raises:
            RuntimeError: If no provider is available or generation fails
        """
        # Select provider
        provider = self._get_provider(provider_name)
        if not provider:
            raise RuntimeError("No LLM provider available")

        # Enhance prompt with safety guidelines
        enhanced_prompt = self._enhance_prompt_with_safety(prompt, scenario_type)

        try:
            provider_name = type(provider).__name__
            logger.info(f"Attempting to generate content with {provider_name}")
            logger.info(f"Prompt length: {len(enhanced_prompt)} characters")
            logger.info(f"Scenario type: {scenario_type}")

            response = await provider.generate_content(
                prompt=enhanced_prompt,
                max_tokens=max_tokens,
                temperature=temperature
            )

            # Check if this is a real API response or mock content
            if response and hasattr(response, 'provider') and response.provider != "fallback":
                logger.info(f"Real AI content generated from {response.provider}")
                logger.info(f"Content length: {len(response.content)} characters")
                logger.info(f"Model used: {getattr(response, 'model', 'unknown')}")

                # Validate and sanitize response
                response = self._validate_response(response, scenario_type)
                response.is_real_ai = True
                return response
            else:
                logger.warning(f"Received mock/simulated content from {provider_name}")
                if response:
                    response.is_real_ai = False
                    return response
                else:
                    raise RuntimeError("Provider returned None response")

        except Exception as e:
            logger.error(f"Content generation failed with {type(provider).__name__}: {str(e)}")
            logger.error(f"Returning fallback content for {scenario_type} scenario")

            # Create clear fallback response
            fallback_response = LLMResponse(
                content=f"[FALLBACK CONTENT] Unable to generate real AI content for {scenario_type} scenario. Error: {str(e)}"
            )
            fallback_response.provider = "fallback"
            fallback_response.model = "none"
            fallback_response.error = str(e)
            fallback_response.scenario_type = scenario_type
            fallback_response.is_real_ai = False
            return fallback_response

    def _get_provider(self, provider_name: Optional[str] = None) -> Optional[BaseLLMProvider]:
        """Get the appropriate provider."""
        if provider_name and provider_name in self._providers:
            return self._providers[provider_name]
        elif self.provider:
            return self.provider
        elif self._providers:
            return list(self._providers.values())[0]
        return None

    def _enhance_prompt_with_safety(self, prompt: str, scenario_type: str) -> str:
        """Enhance prompt with safety guidelines."""
        safety_prefix = f"""
You are helping create educational cybersecurity content for training purposes.
Scenario type: {scenario_type}

Safety Guidelines:
- Content must be educational and defensive in nature
- Do not provide actual malicious code or real exploits
- Focus on awareness and prevention
- Use placeholder values for sensitive information
- Emphasize detection and mitigation strategies

User Request:
"""

        return safety_prefix + prompt

    def _validate_response(self, response: LLMResponse, scenario_type: str) -> LLMResponse:
        """Validate and sanitize LLM response."""
        # Basic content validation
        if not response.content or len(response.content.strip()) < 10:
            logger.warning(f"Received insufficient content (length: {len(response.content if response.content else 'None')})")
            response.content = f"[Insufficient content generated for {scenario_type} scenario]"
            response.is_real_ai = False

        # Log content type and quality
        is_fallback = response.content.startswith("[FALLBACK") or response.content.startswith("[Content generation unavailable")
        if is_fallback:
            logger.warning("Response contains fallback content")
            response.is_real_ai = False

        # Add safety metadata as attributes if metadata doesn't exist
        if hasattr(response, 'metadata') and response.metadata:
            response.metadata["safety_validated"] = True
            response.metadata["scenario_type"] = scenario_type
            response.metadata["validation_timestamp"] = datetime.utcnow().isoformat()
            response.metadata["is_real_ai"] = getattr(response, 'is_real_ai', False)
        else:
            # Simple LLMResponse - add as attributes
            response.safety_validated = True
            response.scenario_type = scenario_type
            response.validation_timestamp = datetime.utcnow().isoformat()
            response.is_real_ai = getattr(response, 'is_real_ai', False)

        return response

    def get_available_providers(self) -> List[str]:
        """Get list of available provider names."""
        return list(self._providers.keys())

    def get_provider_info(self, provider_name: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed information about a provider."""
        provider = self._get_provider(provider_name)
        if not provider:
            return {"error": "Provider not available"}

        if hasattr(provider, 'get_model_info'):
            return provider.get_model_info()
        else:
            return {
                "provider": provider_name or "unknown",
                "available": provider.is_available() if hasattr(provider, 'is_available') else True
            }

    def list_openrouter_models(self) -> List[str]:
        """List available OpenRouter models."""
        if 'openrouter' in self._providers:
            provider = self._providers['openrouter']
            if hasattr(provider, 'list_available_models'):
                return provider.list_available_models()
        return []

    def is_available(self) -> bool:
        """Check if any LLM provider is available."""
        return bool(self.provider or self._providers)

    def get_provider_status(self) -> Dict[str, Any]:
        """Get detailed status of all providers."""
        status = {
            "total_providers": len(self._providers),
            "available_providers": [],
            "unavailable_providers": [],
            "current_provider": None
        }

        for name, provider in self._providers.items():
            provider_info = {
                "name": name,
                "class": type(provider).__name__,
                "available": provider.is_available() if hasattr(provider, 'is_available') else True,
                "has_api_key": bool(getattr(provider, 'api_key', None))
            }

            if provider_info["available"]:
                status["available_providers"].append(provider_info)
            else:
                status["unavailable_providers"].append(provider_info)

        if self.provider:
            status["current_provider"] = {
                "name": type(self.provider).__name__,
                "available": self.provider.is_available() if hasattr(self.provider, 'is_available') else True
            }

        return status

    async def test_connection(self, provider_name: Optional[str] = None) -> Dict[str, Any]:
        """Test connection to LLM provider with real/mock detection."""
        provider = self._get_provider(provider_name)
        if not provider:
            return {"status": "error", "message": "No provider available"}

        provider_class_name = type(provider).__name__
        logger.info(f" Testing connection to {provider_class_name}...")

        try:
            test_response = await provider.generate_content(
                prompt="Hello, this is a connection test. Please respond with 'Connection successful'.",
                max_tokens=50
            )

            is_real_ai = getattr(test_response, 'is_real_ai', False)
            response_type = "Real AI Response" if is_real_ai else "Mock/Simulated Response"

            result = {
                "status": "success",
                "provider": provider_class_name,
                "model": getattr(test_response, 'model', 'unknown'),
                "response_type": response_type,
                "is_real_ai": is_real_ai,
                "content_length": len(test_response.content) if test_response.content else 0,
                "timestamp": datetime.utcnow().isoformat()
            }

            if is_real_ai:
                logger.info(f"{provider_class_name} connection successful - Real AI response received")
            else:
                logger.warning(f"{provider_class_name} connection returned mock/simulated content")

            return result

        except Exception as e:
            logger.error(f"{provider_class_name} connection failed: {str(e)}")
            return {
                "status": "error",
                "provider": provider_class_name,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }

    # Local Model Management Methods

    async def list_local_models(self, provider_name: Optional[str] = None) -> Dict[str, Any]:
        """List available local models across all or specific local providers."""
        results = {}

        # If provider specified, only check that one
        if provider_name:
            if provider_name in self._providers:
                provider = self._providers[provider_name]
                if hasattr(provider, 'list_models'):
                    try:
                        results[provider_name] = await provider.list_models()
                    except Exception as e:
                        results[provider_name] = {"error": str(e)}
                else:
                    results[provider_name] = {"error": "Provider does not support model listing"}
            else:
                results[provider_name] = {"error": "Provider not found"}
        else:
            # Check all local providers
            local_providers = ['ollama', 'huggingface', 'llamacpp']
            for provider_name in local_providers:
                if provider_name in self._providers:
                    provider = self._providers[provider_name]
                    if hasattr(provider, 'list_models'):
                        try:
                            results[provider_name] = await provider.list_models()
                        except Exception as e:
                            results[provider_name] = {"error": str(e)}

        return results

    async def load_local_model(self, provider_name: str, model_name: Optional[str] = None) -> Dict[str, Any]:
        """Load a model in a local provider."""
        if provider_name not in self._providers:
            return {"error": f"Provider {provider_name} not found"}

        provider = self._providers[provider_name]
        if not hasattr(provider, 'load_model'):
            return {"error": f"Provider {provider_name} does not support model loading"}

        try:
            if model_name:
                # Load specific model
                result = await provider.load_model(model_name)
            else:
                # Load default model
                result = await provider.load_model()

            logger.info(f"Successfully loaded model in {provider_name}")
            return {"status": "success", "provider": provider_name, "model": model_name}

        except Exception as e:
            logger.error(f"Failed to load model in {provider_name}: {e}")
            return {"error": str(e), "provider": provider_name}

    async def unload_local_model(self, provider_name: str) -> Dict[str, Any]:
        """Unload model from a local provider to free memory."""
        if provider_name not in self._providers:
            return {"error": f"Provider {provider_name} not found"}

        provider = self._providers[provider_name]
        if not hasattr(provider, 'unload_model'):
            return {"error": f"Provider {provider_name} does not support model unloading"}

        try:
            await provider.unload_model()
            logger.info(f"Successfully unloaded model from {provider_name}")
            return {"status": "success", "provider": provider_name}

        except Exception as e:
            logger.error(f"Failed to unload model from {provider_name}: {e}")
            return {"error": str(e), "provider": provider_name}

    async def switch_local_model(self, provider_name: str, model_name: str) -> Dict[str, Any]:
        """Switch to a different model in a local provider."""
        if provider_name not in self._providers:
            return {"error": f"Provider {provider_name} not found"}

        provider = self._providers[provider_name]
        if hasattr(provider, 'switch_model'):
            try:
                result = await provider.switch_model(model_name)
                logger.info(f"Successfully switched to model {model_name} in {provider_name}")
                return {"status": "success", "provider": provider_name, "model": model_name}
            except Exception as e:
                logger.error(f"Failed to switch model in {provider_name}: {e}")
                return {"error": str(e), "provider": provider_name}
        else:
            # Fallback: unload then load
            try:
                await provider.unload_model()
                await provider.load_model(model_name)
                return {"status": "success", "provider": provider_name, "model": model_name}
            except Exception as e:
                return {"error": str(e), "provider": provider_name}

    async def get_local_model_health(self, provider_name: Optional[str] = None) -> Dict[str, Any]:
        """Get health status of local model providers."""
        results = {}

        local_providers = [provider_name] if provider_name else ['ollama', 'huggingface', 'llamacpp']

        for provider_name in local_providers:
            if provider_name in self._providers:
                provider = self._providers[provider_name]
                if hasattr(provider, 'health_check'):
                    try:
                        results[provider_name] = await provider.health_check()
                    except Exception as e:
                        results[provider_name] = {"error": str(e)}
                else:
                    results[provider_name] = {"status": "available", "health_check": "not_supported"}
            else:
                results[provider_name] = {"error": "Provider not initialized"}

        return results

    def get_local_provider_capabilities(self) -> Dict[str, Dict[str, Any]]:
        """Get capabilities of each local provider."""
        capabilities = {}

        if 'ollama' in self._providers:
            capabilities['ollama'] = {
                "description": "Server-based local models with automatic management",
                "features": ["model_pulling", "server_management", "model_switching", "health_monitoring"],
                "advantages": ["Easy setup", "Wide model support", "Automatic downloads"],
                "best_for": "Users wanting simple local model deployment"
            }

        if 'huggingface' in self._providers:
            capabilities['huggingface'] = {
                "description": "Direct model loading with GPU acceleration and quantization",
                "features": ["gpu_acceleration", "quantization", "custom_models", "fine_tuning"],
                "advantages": ["High performance", "GPU support", "Quantization options"],
                "best_for": "Advanced users with GPU hardware"
            }

        if 'llamacpp' in self._providers:
            capabilities['llamacpp'] = {
                "description": "High-performance CPU inference with GGUF/GGML support",
                "features": ["cpu_optimization", "quantization", "grammar_constraints", "streaming"],
                "advantages": ["CPU optimized", "Memory efficient", "No GPU required"],
                "best_for": "CPU-only systems and memory-constrained environments"
            }

        return capabilities

    def get_recommended_models(self, use_case: str = "general") -> Dict[str, List[str]]:
        """Get recommended models for different use cases across all providers."""
        recommendations = {}

        use_case_mapping = {
            "cybersecurity": "cybersecurity_training",
            "training": "cybersecurity_training",
            "technical": "technical_content",
            "code": "technical_content",
            "general": "small_fast",
            "fast": "small_fast",
            "quality": "large_quality"
        }

        mapped_use_case = use_case_mapping.get(use_case, use_case)

        for provider_name, provider in self._providers.items():
            if hasattr(provider, 'get_recommended_models'):
                try:
                    provider_recommendations = provider.get_recommended_models()
                    if mapped_use_case in provider_recommendations:
                        recommendations[provider_name] = provider_recommendations[mapped_use_case]
                    elif 'small_fast' in provider_recommendations:
                        recommendations[provider_name] = provider_recommendations['small_fast']
                except Exception as e:
                    logger.warning(f"Could not get recommendations from {provider_name}: {e}")

        return recommendations
