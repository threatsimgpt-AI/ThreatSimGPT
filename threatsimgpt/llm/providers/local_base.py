"""Local LLM provider base class for ThreatSimGPT.

This module provides the foundation for local model providers that can run
models directly on the user's hardware without external API calls.
"""

import logging
import asyncio
import psutil
from abc import abstractmethod
from typing import Dict, Any, Optional, List, Union
from pathlib import Path
from datetime import datetime

from ..base import BaseLLMProvider, LLMResponse

logger = logging.getLogger(__name__)

# Optional torch import for GPU support
try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    torch = None
    logger.info("PyTorch not available - GPU detection disabled for local models")


class LocalModelInfo:
    """Information about a local model."""

    def __init__(
        self,
        name: str,
        path: str,
        model_type: str,
        size_gb: Optional[float] = None,
        quantization: Optional[str] = None,
        context_length: int = 2048,
        description: Optional[str] = None
    ):
        self.name = name
        self.path = path
        self.model_type = model_type  # 'gguf', 'safetensors', 'pytorch', etc.
        self.size_gb = size_gb
        self.quantization = quantization  # 'Q4_K_M', 'Q8_0', 'fp16', etc.
        self.context_length = context_length
        self.description = description
        self.last_used = None
        self.load_time = None
        self.memory_usage = None

    def __str__(self) -> str:
        return f"LocalModel({self.name}, {self.model_type}, {self.quantization or 'full'})"


class SystemResourceManager:
    """Manages system resources for local model inference."""

    @staticmethod
    def get_available_memory() -> float:
        """Get available system memory in GB."""
        return psutil.virtual_memory().available / (1024**3)

    @staticmethod
    def get_gpu_memory() -> Dict[str, float]:
        """Get available GPU memory for each device."""
        gpu_memory = {}
        if TORCH_AVAILABLE and torch is not None and torch.cuda.is_available():
            for i in range(torch.cuda.device_count()):
                device = f"cuda:{i}"
                props = torch.cuda.get_device_properties(i)
                total_memory = props.total_memory / (1024**3)
                allocated = torch.cuda.memory_allocated(i) / (1024**3)
                available = total_memory - allocated
                gpu_memory[device] = available
        return gpu_memory

    @staticmethod
    def check_model_compatibility(model_info: LocalModelInfo) -> Dict[str, Any]:
        """Check if system can run the model."""
        results = {
            'can_run_cpu': False,
            'can_run_gpu': False,
            'recommended_device': 'cpu',
            'memory_requirement': model_info.size_gb or 0,
            'warnings': []
        }

        # Check CPU memory
        available_ram = SystemResourceManager.get_available_memory()
        model_size = model_info.size_gb or 0

        # Rule of thumb: need 2x model size for loading + inference
        required_ram = model_size * 2

        if available_ram >= required_ram:
            results['can_run_cpu'] = True
            results['recommended_device'] = 'cpu'
        elif available_ram >= model_size:
            results['can_run_cpu'] = True
            results['warnings'].append(f"Low RAM: {available_ram:.1f}GB available, {required_ram:.1f}GB recommended")

        # Check GPU memory
        gpu_memory = SystemResourceManager.get_gpu_memory()
        for device, available_vram in gpu_memory.items():
            if available_vram >= required_ram:
                results['can_run_gpu'] = True
                results['recommended_device'] = device
                break

        return results


class LocalLLMProvider(BaseLLMProvider):
    """Base class for local LLM providers."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize local LLM provider.

        Args:
            config: Configuration dictionary
        """
        super().__init__(config)
        self.model_path = config.get('model_path')
        self.device = config.get('device', 'auto')  # 'cpu', 'cuda', 'mps', 'auto'
        self.max_context_length = config.get('max_context_length', 2048)
        self.quantization = config.get('quantization')
        self.thread_count = config.get('thread_count', psutil.cpu_count())
        self.gpu_layers = config.get('gpu_layers', -1)  # -1 for all layers on GPU

        # Model management
        self._model = None
        self._tokenizer = None
        self._model_info: Optional[LocalModelInfo] = None
        self._is_loaded = False
        self._load_time = None

        # Performance tracking
        self._inference_times = []
        self._memory_usage = []

        # Resource manager
        self.resource_manager = SystemResourceManager()

    @abstractmethod
    async def _load_model(self) -> None:
        """Load the model into memory. Must be implemented by subclasses."""
        pass

    @abstractmethod
    async def _unload_model(self) -> None:
        """Unload the model from memory. Must be implemented by subclasses."""
        pass

    @abstractmethod
    async def _generate_with_model(
        self,
        prompt: str,
        max_tokens: int = 1000,
        temperature: float = 0.7,
        **kwargs
    ) -> str:
        """Generate text with the loaded model. Must be implemented by subclasses."""
        pass

    async def generate_content(
        self,
        prompt: str,
        max_tokens: int = 1000,
        temperature: float = 0.7,
        **kwargs
    ) -> LLMResponse:
        """Generate content using the local model.

        Args:
            prompt: The prompt to send to the model
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            **kwargs: Additional parameters

        Returns:
            LLMResponse with generated content
        """
        start_time = datetime.utcnow()

        try:
            # Load model if not already loaded
            if not self._is_loaded:
                logger.info(f"Loading local model from {self.model_path}")
                await self._load_model()

            # Generate content
            logger.info(f"Generating content with local model: {self.model}")
            content = await self._generate_with_model(
                prompt=prompt,
                max_tokens=max_tokens,
                temperature=temperature,
                **kwargs
            )

            # Track performance
            inference_time = (datetime.utcnow() - start_time).total_seconds()
            self._inference_times.append(inference_time)

            # Create response
            response = LLMResponse(
                content=content,
                provider=f"local-{self.__class__.__name__.lower()}",
                model=self.model or "local-model"
            )
            response.is_real_ai = True
            response.metadata = {
                'inference_time': inference_time,
                'model_path': self.model_path,
                'device': self.device,
                'quantization': self.quantization,
                'local_model': True
            }

            return response

        except Exception as e:
            logger.error(f"Local model generation failed: {str(e)}")

            # Return error response
            response = LLMResponse(
                content=f"[LOCAL MODEL ERROR] Failed to generate content: {str(e)}",
                provider=f"local-{self.__class__.__name__.lower()}",
                model=self.model or "local-model"
            )
            response.error = str(e)
            response.is_real_ai = False
            response.metadata = {
                'local_model': True,
                'error_type': type(e).__name__
            }

            return response

    async def health_check(self) -> Dict[str, Any]:
        """Check the health and status of the local model."""
        health_info = {
            'status': 'unknown',
            'model_loaded': self._is_loaded,
            'model_path': self.model_path,
            'device': self.device,
            'memory_usage': None,
            'last_inference_time': None,
            'total_inferences': len(self._inference_times),
            'average_inference_time': None,
            'system_resources': {}
        }

        try:
            # Check if model path exists
            if self.model_path and Path(self.model_path).exists():
                health_info['model_path_exists'] = True
            else:
                health_info['model_path_exists'] = False
                health_info['status'] = 'model_not_found'
                return health_info

            # Get system resources
            health_info['system_resources'] = {
                'available_ram_gb': self.resource_manager.get_available_memory(),
                'gpu_memory': self.resource_manager.get_gpu_memory(),
                'cpu_count': psutil.cpu_count()
            }

            # Performance metrics
            if self._inference_times:
                health_info['last_inference_time'] = self._inference_times[-1]
                health_info['average_inference_time'] = sum(self._inference_times) / len(self._inference_times)

            # Model status
            if self._is_loaded:
                health_info['status'] = 'loaded'
                if hasattr(self, '_model') and self._model is not None:
                    health_info['status'] = 'ready'
            else:
                health_info['status'] = 'not_loaded'

        except Exception as e:
            health_info['status'] = 'error'
            health_info['error'] = str(e)

        return health_info

    def get_model_info(self) -> Optional[LocalModelInfo]:
        """Get information about the loaded model."""
        return self._model_info

    async def reload_model(self) -> None:
        """Reload the model (useful for switching configurations)."""
        if self._is_loaded:
            await self._unload_model()
        await self._load_model()

    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics for the model."""
        if not self._inference_times:
            return {'no_data': True}

        return {
            'total_inferences': len(self._inference_times),
            'average_time': sum(self._inference_times) / len(self._inference_times),
            'min_time': min(self._inference_times),
            'max_time': max(self._inference_times),
            'recent_times': self._inference_times[-10:],  # Last 10 inferences
            'memory_usage': self._memory_usage[-10:] if self._memory_usage else []
        }

    def __del__(self):
        """Cleanup when provider is destroyed."""
        if self._is_loaded:
            try:
                # Synchronous cleanup; call cleanup() explicitly for async operations
                logger.info("Cleaning up local model on provider destruction")
            except Exception as e:
                logger.error(f"Error during local model cleanup: {e}")
