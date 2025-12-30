"""Ollama provider implementation for ThreatSimGPT.

Ollama is a popular tool for running large language models locally.
This provider integrates with Ollama's REST API for seamless local model usage.
"""

import asyncio
import logging
import aiohttp
import json
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path

from .local_base import LocalLLMProvider, LocalModelInfo, SystemResourceManager
from ..base import LLMResponse

logger = logging.getLogger(__name__)


class OllamaProvider(LocalLLMProvider):
    """Ollama local LLM provider implementation."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize Ollama provider.

        Args:
            config: Configuration dictionary with Ollama settings
        """
        super().__init__(config)
        self.base_url = config.get('base_url', 'http://localhost:11434')
        self.model_name = config.get('model', 'llama2')
        self.keep_alive = config.get('keep_alive', '5m')  # Keep model in memory
        self.timeout = config.get('timeout', 300)  # 5 minutes for generation

        # Ollama-specific settings
        self.stream = config.get('stream', False)
        self.options = config.get('options', {})

        # Session for HTTP requests
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def _load_model(self) -> None:
        """Load the model via Ollama API."""
        try:
            # Check if Ollama is running
            await self._check_ollama_health()

            # Pull model if not available
            await self._ensure_model_available()

            # Load model into memory
            await self._load_model_into_memory()

            self._is_loaded = True
            self._load_time = datetime.utcnow()
            logger.info(f"Ollama model {self.model_name} loaded successfully")

        except Exception as e:
            logger.error(f"Failed to load Ollama model {self.model_name}: {e}")
            raise

    async def _unload_model(self) -> None:
        """Unload the model from Ollama memory."""
        try:
            session = await self._get_session()

            # Set keep_alive to 0 to unload immediately
            url = f"{self.base_url}/api/generate"
            payload = {
                "model": self.model_name,
                "prompt": "",
                "keep_alive": 0
            }

            async with session.post(url, json=payload) as response:
                if response.status == 200:
                    logger.info(f"Ollama model {self.model_name} unloaded")
                else:
                    logger.warning(f"Failed to unload model: HTTP {response.status}")

            self._is_loaded = False

        except Exception as e:
            logger.error(f"Error unloading Ollama model: {e}")

    async def _generate_with_model(
        self,
        prompt: str,
        max_tokens: int = 1000,
        temperature: float = 0.7,
        **kwargs
    ) -> str:
        """Generate text using Ollama API."""
        session = await self._get_session()

        # Prepare Ollama options
        ollama_options = {
            "temperature": temperature,
            "num_predict": max_tokens,
            **self.options,
            **kwargs
        }

        # Prepare request payload
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,  # Use non-streaming for simplicity
            "options": ollama_options,
            "keep_alive": self.keep_alive
        }

        url = f"{self.base_url}/api/generate"

        try:
            async with session.post(url, json=payload) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"Ollama API error {response.status}: {error_text}")

                result = await response.json()

                if "error" in result:
                    raise Exception(f"Ollama generation error: {result['error']}")

                return result.get("response", "").strip()

        except asyncio.TimeoutError:
            raise Exception(f"Ollama generation timed out after {self.timeout} seconds")
        except Exception as e:
            logger.error(f"Ollama generation failed: {e}")
            raise

    async def _check_ollama_health(self) -> bool:
        """Check if Ollama server is running and accessible."""
        try:
            session = await self._get_session()
            url = f"{self.base_url}/api/version"

            async with session.get(url) as response:
                if response.status == 200:
                    version_info = await response.json()
                    logger.info(f"Ollama server running, version: {version_info.get('version', 'unknown')}")
                    return True
                else:
                    raise Exception(f"Ollama health check failed: HTTP {response.status}")

        except Exception as e:
            logger.error(f"Ollama server not accessible: {e}")
            raise Exception(f"Ollama server not running at {self.base_url}. Please start Ollama first.")

    async def _ensure_model_available(self) -> None:
        """Ensure the specified model is available, pull if necessary."""
        try:
            # Check if model is already available
            models = await self._list_models()
            model_names = [model['name'] for model in models.get('models', [])]

            if self.model_name in model_names:
                logger.info(f"Model {self.model_name} already available")
                return

            # Pull the model
            logger.info(f"Pulling model {self.model_name} from Ollama registry...")
            await self._pull_model()

        except Exception as e:
            logger.error(f"Failed to ensure model availability: {e}")
            raise

    async def _list_models(self) -> Dict[str, Any]:
        """List available models in Ollama."""
        session = await self._get_session()
        url = f"{self.base_url}/api/tags"

        async with session.get(url) as response:
            if response.status == 200:
                return await response.json()
            else:
                error_text = await response.text()
                raise Exception(f"Failed to list Ollama models: {error_text}")

    async def _pull_model(self) -> None:
        """Pull a model from Ollama registry."""
        url = f"{self.base_url}/api/pull"
        payload = {"name": self.model_name}

        try:
            # Note: Using existing session but model pulling requires extended timeout
            # For production use, consider implementing a separate session with extended timeout
            session = await self._get_session()
            async with session.post(url, json=payload) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"Model pull failed: {error_text}")

                # Stream the pull progress
                async for line in response.content:
                    if line:
                        try:
                            progress = json.loads(line.decode())
                            if progress.get('status'):
                                logger.info(f"Pull progress: {progress['status']}")
                        except json.JSONDecodeError:
                            pass

                logger.info(f"Model {self.model_name} pulled successfully")

        except asyncio.TimeoutError:
            raise Exception("Model pull timed out. Large models may take significant time to download.")

    async def _load_model_into_memory(self) -> None:
        """Load model into Ollama's memory for faster inference."""
        try:
            # Send a small prompt to load the model
            session = await self._get_session()
            url = f"{self.base_url}/api/generate"
            payload = {
                "model": self.model_name,
                "prompt": "Hello",
                "stream": False,
                "keep_alive": self.keep_alive,
                "options": {"num_predict": 1}
            }

            async with session.post(url, json=payload) as response:
                if response.status == 200:
                    logger.info(f"Model {self.model_name} loaded into memory")
                else:
                    error_text = await response.text()
                    logger.warning(f"Failed to preload model: {error_text}")

        except Exception as e:
            logger.warning(f"Failed to preload model into memory: {e}")

    async def health_check(self) -> Dict[str, Any]:
        """Enhanced health check for Ollama provider."""
        health_info = await super().health_check()

        try:
            # Check Ollama server
            await self._check_ollama_health()
            health_info['ollama_server'] = 'running'

            # Get available models
            models = await self._list_models()
            health_info['available_models'] = [model['name'] for model in models.get('models', [])]
            health_info['target_model_available'] = self.model_name in health_info['available_models']

            # Get model info if available
            for model in models.get('models', []):
                if model['name'] == self.model_name:
                    health_info['model_info'] = {
                        'size': model.get('size', 0),
                        'modified_at': model.get('modified_at'),
                        'digest': model.get('digest')
                    }
                    break

        except Exception as e:
            health_info['ollama_server'] = 'error'
            health_info['ollama_error'] = str(e)

        return health_info

    async def list_available_models(self) -> List[Dict[str, Any]]:
        """List all models available in Ollama."""
        try:
            models_response = await self._list_models()
            return models_response.get('models', [])
        except Exception as e:
            logger.error(f"Failed to list Ollama models: {e}")
            return []

    async def install_model(self, model_name: str) -> bool:
        """Install a new model via Ollama."""
        try:
            old_model_name = self.model_name
            self.model_name = model_name
            await self._pull_model()
            logger.info(f"Successfully installed model: {model_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to install model {model_name}: {e}")
            self.model_name = old_model_name  # Restore original model name
            return False

    async def switch_model(self, model_name: str) -> bool:
        """Switch to a different model."""
        try:
            # Check if model is available
            models = await self._list_models()
            available_models = [model['name'] for model in models.get('models', [])]

            if model_name not in available_models:
                logger.error(f"Model {model_name} not available. Available models: {available_models}")
                return False

            # Unload current model if loaded
            if self._is_loaded:
                await self._unload_model()

            # Switch model name
            old_model_name = self.model_name
            self.model_name = model_name

            # Load new model
            try:
                await self._load_model()
                logger.info(f"Successfully switched to model: {model_name}")
                return True
            except Exception as e:
                # Restore old model name on failure
                self.model_name = old_model_name
                logger.error(f"Failed to switch to model {model_name}: {e}")
                return False

        except Exception as e:
            logger.error(f"Error switching models: {e}")
            return False

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._session and not self._session.closed:
            await self._session.close()

        if self._is_loaded:
            await self._unload_model()


# Recommended Ollama models for different use cases
RECOMMENDED_OLLAMA_MODELS = {
    "fast_small": {
        "models": ["llama2:7b", "phi3:mini", "qwen2:1.5b"],
        "description": "Fast, lightweight models for quick responses",
        "use_case": "Development, testing, simple scenarios"
    },
    "balanced": {
        "models": ["llama2:13b", "mistral:7b", "phi3:medium"],
        "description": "Balanced performance and quality",
        "use_case": "Production use, complex scenarios"
    },
    "high_quality": {
        "models": ["llama2:70b", "mixtral:8x7b", "qwen2:72b"],
        "description": "High quality output, requires more resources",
        "use_case": "Critical scenarios, detailed analysis"
    },
    "code_specialized": {
        "models": ["codellama:7b", "codellama:13b", "starcoder2:7b"],
        "description": "Specialized for code generation and analysis",
        "use_case": "Technical scenarios, code analysis"
    }
}
