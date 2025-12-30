"""llama.cpp provider for ThreatSimGPT.

This provider enables high-performance CPU inference using llama-cpp-python bindings
with support for quantization and various model formats (GGUF, GGML).
"""

import logging
import asyncio
import json
from typing import Dict, Any, Optional, List, Union
from datetime import datetime
from pathlib import Path

from .local_base import LocalLLMProvider, LocalModelInfo, SystemResourceManager
from ..base import LLMResponse

logger = logging.getLogger(__name__)

# Optional imports with fallbacks
try:
    from llama_cpp import Llama, LlamaGrammar
    LLAMA_CPP_AVAILABLE = True
except ImportError:
    LLAMA_CPP_AVAILABLE = False
    Llama = LlamaGrammar = None
    logger.warning("llama-cpp-python not available - LlamaCpp provider will not work")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    requests = None
    logger.warning("requests library not available - model downloading may be limited")


class LlamaCppProvider(LocalLLMProvider):
    """llama.cpp local LLM provider implementation."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize llama.cpp provider.

        Args:
            config: Configuration dictionary with llama.cpp settings
        """
        if not LLAMA_CPP_AVAILABLE:
            raise ImportError(
                "LlamaCpp provider requires 'llama-cpp-python' library. "
                "Install with: pip install llama-cpp-python"
            )

        super().__init__(config)

        # Model file configuration
        self.model_path = config.get('model_path')
        if not self.model_path:
            raise ValueError("model_path is required for LlamaCpp provider")

        self.model_path = Path(self.model_path)

        # Model loading parameters
        self.n_ctx = config.get('n_ctx', 2048)  # Context length
        self.n_threads = config.get('n_threads', None)  # CPU threads (auto-detect if None)
        self.n_batch = config.get('n_batch', 512)  # Batch size for prompt processing
        self.n_gpu_layers = config.get('n_gpu_layers', 0)  # GPU layers (0 = CPU only)

        # Memory and performance settings
        self.use_mmap = config.get('use_mmap', True)  # Memory-map model file
        self.use_mlock = config.get('use_mlock', False)  # Lock model in memory
        self.low_vram = config.get('low_vram', False)  # Reduce VRAM usage

        # Generation settings
        self.seed = config.get('seed', -1)  # Random seed (-1 = random)
        self.verbose = config.get('verbose', False)  # Verbose output

        # Quantization settings
        self.f16_kv = config.get('f16_kv', True)  # Use half precision for KV cache
        self.logits_all = config.get('logits_all', False)  # Return logits for all tokens

        # Model instance
        self._model = None

        # Auto-detect threads if not specified
        if self.n_threads is None:
            import os
            self.n_threads = max(1, os.cpu_count() // 2)

    async def _load_model(self) -> None:
        """Load the llama.cpp model."""
        try:
            if not self.model_path.exists():
                raise FileNotFoundError(f"Model file not found: {self.model_path}")

            logger.info(f"Loading llama.cpp model: {self.model_path}")

            # Load model in thread to avoid blocking
            def load_model():
                return Llama(
                    model_path=str(self.model_path),
                    n_ctx=self.n_ctx,
                    n_threads=self.n_threads,
                    n_batch=self.n_batch,
                    n_gpu_layers=self.n_gpu_layers,
                    use_mmap=self.use_mmap,
                    use_mlock=self.use_mlock,
                    low_vram=self.low_vram,
                    seed=self.seed,
                    f16_kv=self.f16_kv,
                    logits_all=self.logits_all,
                    verbose=self.verbose
                )

            loop = asyncio.get_event_loop()
            self._model = await loop.run_in_executor(None, load_model)

            self._is_loaded = True
            self._load_time = datetime.utcnow()

            # Get model info
            self._model_info = LocalModelInfo(
                name=self.model_path.stem,
                path=str(self.model_path),
                model_type="llama.cpp",
                context_length=self.n_ctx,
                description=f"llama.cpp model with {self.n_gpu_layers} GPU layers"
            )

            logger.info("llama.cpp model loaded successfully")
            logger.info(f"Context length: {self.n_ctx}, GPU layers: {self.n_gpu_layers}")

        except Exception as e:
            logger.error(f"Failed to load llama.cpp model: {e}")
            raise

    async def _unload_model(self) -> None:
        """Unload the model from memory."""
        try:
            if self._model is not None:
                # llama.cpp handles cleanup automatically
                del self._model
                self._model = None

            self._is_loaded = False
            logger.info("llama.cpp model unloaded")

        except Exception as e:
            logger.error(f"Error unloading llama.cpp model: {e}")

    async def _generate_with_model(
        self,
        prompt: str,
        max_tokens: int = 1000,
        temperature: float = 0.7,
        **kwargs
    ) -> str:
        """Generate text using the loaded llama.cpp model."""
        if not self._is_loaded or self._model is None:
            raise RuntimeError("Model not loaded")

        try:
            # Prepare generation parameters
            generation_params = {
                'max_tokens': max_tokens,
                'temperature': temperature,
                'top_p': kwargs.get('top_p', 0.9),
                'top_k': kwargs.get('top_k', 50),
                'repeat_penalty': kwargs.get('repeat_penalty', 1.1),
                'stop': kwargs.get('stop', []),
                'echo': kwargs.get('echo', False),  # Include prompt in output
                'stream': False  # We handle streaming separately if needed
            }

            # Run inference in thread to avoid blocking
            def generate():
                result = self._model(prompt, **generation_params)
                return result['choices'][0]['text']

            loop = asyncio.get_event_loop()
            generated_text = await loop.run_in_executor(None, generate)

            return generated_text.strip()

        except Exception as e:
            logger.error(f"llama.cpp generation failed: {e}")
            raise

    async def generate_streaming(
        self,
        prompt: str,
        max_tokens: int = 1000,
        temperature: float = 0.7,
        **kwargs
    ):
        """Generate text with streaming output."""
        if not self._is_loaded or self._model is None:
            raise RuntimeError("Model not loaded")

        generation_params = {
            'max_tokens': max_tokens,
            'temperature': temperature,
            'top_p': kwargs.get('top_p', 0.9),
            'top_k': kwargs.get('top_k', 50),
            'repeat_penalty': kwargs.get('repeat_penalty', 1.1),
            'stop': kwargs.get('stop', []),
            'stream': True
        }

        try:
            def generate_stream():
                for chunk in self._model(prompt, **generation_params):
                    yield chunk['choices'][0]['text']

            # Run streaming generation in executor
            loop = asyncio.get_event_loop()

            # Simplified streaming implementation
            full_text = ""
            for chunk in generate_stream():
                full_text += chunk
                yield chunk

        except Exception as e:
            logger.error(f"llama.cpp streaming generation failed: {e}")
            raise

    def create_grammar(self, grammar_str: str) -> Optional[Any]:
        """Create a llama.cpp grammar for constrained generation."""
        try:
            if LLAMA_CPP_AVAILABLE and LlamaGrammar:
                return LlamaGrammar.from_string(grammar_str)
        except Exception as e:
            logger.error(f"Failed to create grammar: {e}")
        return None

    async def generate_with_grammar(
        self,
        prompt: str,
        grammar_str: str,
        max_tokens: int = 1000,
        **kwargs
    ) -> str:
        """Generate text with grammar constraints."""
        if not self._is_loaded or self._model is None:
            raise RuntimeError("Model not loaded")

        grammar = self.create_grammar(grammar_str)
        if grammar is None:
            logger.warning("Grammar creation failed, falling back to normal generation")
            return await self._generate_with_model(prompt, max_tokens, **kwargs)

        try:
            generation_params = {
                'max_tokens': max_tokens,
                'temperature': kwargs.get('temperature', 0.7),
                'top_p': kwargs.get('top_p', 0.9),
                'top_k': kwargs.get('top_k', 50),
                'repeat_penalty': kwargs.get('repeat_penalty', 1.1),
                'grammar': grammar
            }

            def generate():
                result = self._model(prompt, **generation_params)
                return result['choices'][0]['text']

            loop = asyncio.get_event_loop()
            generated_text = await loop.run_in_executor(None, generate)

            return generated_text.strip()

        except Exception as e:
            logger.error(f"Grammar-constrained generation failed: {e}")
            raise

    async def health_check(self) -> Dict[str, Any]:
        """Enhanced health check for llama.cpp provider."""
        health_info = await super().health_check()

        # Add llama.cpp specific info
        health_info.update({
            'model_path': str(self.model_path),
            'model_exists': self.model_path.exists() if self.model_path else False,
            'n_ctx': self.n_ctx,
            'n_threads': self.n_threads,
            'n_batch': self.n_batch,
            'n_gpu_layers': self.n_gpu_layers,
            'llama_cpp_available': LLAMA_CPP_AVAILABLE
        })

        if self.model_path and self.model_path.exists():
            health_info.update({
                'model_size_mb': self.model_path.stat().st_size / (1024 * 1024),
                'model_modified': self.model_path.stat().st_mtime
            })

        if self._model is not None:
            try:
                # Get model metadata if available
                health_info.update({
                    'model_loaded': True,
                    'context_used': getattr(self._model, 'n_tokens', 0),
                    'context_capacity': self.n_ctx
                })
            except Exception as e:
                logger.debug(f"Could not get model metadata: {e}")

        return health_info

    def get_supported_formats(self) -> List[str]:
        """Get supported model file formats."""
        return ['.gguf', '.ggml', '.bin']

    def get_model_info(self, model_path: Union[str, Path]) -> Dict[str, Any]:
        """Get information about a model file."""
        model_path = Path(model_path)

        if not model_path.exists():
            return {'error': 'Model file not found'}

        try:
            info = {
                'name': model_path.stem,
                'path': str(model_path),
                'size_mb': model_path.stat().st_size / (1024 * 1024),
                'format': model_path.suffix,
                'modified': datetime.fromtimestamp(model_path.stat().st_mtime).isoformat(),
                'supported': model_path.suffix in self.get_supported_formats()
            }

            # Try to extract info from filename (common patterns)
            filename = model_path.name.lower()

            # Extract quantization info
            if 'q4_0' in filename:
                info['quantization'] = 'Q4_0'
            elif 'q4_1' in filename:
                info['quantization'] = 'Q4_1'
            elif 'q5_0' in filename:
                info['quantization'] = 'Q5_0'
            elif 'q5_1' in filename:
                info['quantization'] = 'Q5_1'
            elif 'q8_0' in filename:
                info['quantization'] = 'Q8_0'
            elif 'f16' in filename:
                info['quantization'] = 'F16'
            elif 'f32' in filename:
                info['quantization'] = 'F32'

            # Extract model size info
            if '7b' in filename:
                info['parameters'] = '7B'
            elif '13b' in filename:
                info['parameters'] = '13B'
            elif '30b' in filename:
                info['parameters'] = '30B'
            elif '70b' in filename:
                info['parameters'] = '70B'

            return info

        except Exception as e:
            return {'error': f'Failed to get model info: {e}'}

    def estimate_performance(self, model_path: Union[str, Path]) -> Dict[str, Any]:
        """Estimate performance characteristics for a model."""
        model_info = self.get_model_info(model_path)

        if 'error' in model_info:
            return model_info

        try:
            size_mb = model_info['size_mb']

            # Rough estimates based on model size and quantization
            quantization = model_info.get('quantization', 'unknown')

            # Base estimates (tokens/second on typical hardware)
            if size_mb < 1000:  # Small models
                base_speed = 50
                ram_needed = 2
            elif size_mb < 4000:  # Medium models
                base_speed = 30
                ram_needed = 6
            elif size_mb < 8000:  # Large models
                base_speed = 15
                ram_needed = 12
            else:  # Very large models
                base_speed = 5
                ram_needed = 20

            # Adjust for quantization
            quant_multipliers = {
                'Q4_0': 1.8, 'Q4_1': 1.6, 'Q5_0': 1.4, 'Q5_1': 1.3,
                'Q8_0': 1.1, 'F16': 0.8, 'F32': 0.5
            }

            speed_multiplier = quant_multipliers.get(quantization, 1.0)
            estimated_speed = base_speed * speed_multiplier

            # Check if system can run the model
            available_ram = self.resource_manager.get_available_memory()
            can_run = available_ram >= ram_needed

            return {
                'estimated_tokens_per_second': round(estimated_speed, 1),
                'estimated_ram_needed_gb': ram_needed,
                'can_run_on_system': can_run,
                'available_ram_gb': round(available_ram, 1),
                'performance_notes': [
                    f"Quantization: {quantization}",
                    f"Model size: {size_mb:.1f} MB",
                    f"Recommended threads: {self.n_threads}"
                ]
            }

        except Exception as e:
            return {'error': f'Failed to estimate performance: {e}'}

    async def download_model(
        self,
        model_url: str,
        download_path: Optional[Union[str, Path]] = None,
        progress_callback: Optional[callable] = None
    ) -> bool:
        """Download a model from URL."""
        if not REQUESTS_AVAILABLE:
            logger.error("requests library required for model downloading")
            return False

        try:
            download_path = Path(download_path) if download_path else self.model_path.parent
            download_path.mkdir(parents=True, exist_ok=True)

            # Extract filename from URL
            filename = model_url.split('/')[-1]
            if not any(filename.endswith(fmt) for fmt in self.get_supported_formats()):
                filename += '.gguf'  # Default extension

            file_path = download_path / filename

            logger.info(f"Downloading model from {model_url} to {file_path}")

            def download():
                response = requests.get(model_url, stream=True)
                response.raise_for_status()

                total_size = int(response.headers.get('content-length', 0))
                downloaded = 0

                with open(file_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)

                            if progress_callback and total_size > 0:
                                progress = downloaded / total_size
                                progress_callback(progress, downloaded, total_size)

                return True

            loop = asyncio.get_event_loop()
            success = await loop.run_in_executor(None, download)

            if success:
                logger.info(f"Successfully downloaded model to {file_path}")
                # Update model path if this is the first model
                if not hasattr(self, '_model_path_set'):
                    self.model_path = file_path
                    self._model_path_set = True

            return success

        except Exception as e:
            logger.error(f"Failed to download model: {e}")
            return False


# Common model download URLs and recommendations
LLAMA_CPP_MODEL_RECOMMENDATIONS = {
    "small_fast": {
        "models": [
            "https://huggingface.co/TheBloke/Llama-2-7B-Chat-GGUF/resolve/main/llama-2-7b-chat.q4_0.gguf",
            "https://huggingface.co/microsoft/DialoGPT-small-gguf/resolve/main/model.gguf"
        ],
        "description": "Fast, lightweight models for basic tasks",
        "ram_needed": "4-6 GB"
    },
    "medium_balanced": {
        "models": [
            "https://huggingface.co/TheBloke/Llama-2-13B-chat-GGUF/resolve/main/llama-2-13b-chat.q4_0.gguf",
            "https://huggingface.co/TheBloke/CodeLlama-13B-Instruct-GGUF/resolve/main/codellama-13b-instruct.q4_0.gguf"
        ],
        "description": "Balanced performance and quality",
        "ram_needed": "8-12 GB"
    },
    "large_quality": {
        "models": [
            "https://huggingface.co/TheBloke/Llama-2-70B-Chat-GGUF/resolve/main/llama-2-70b-chat.q4_0.gguf",
            "https://huggingface.co/TheBloke/CodeLlama-34B-Instruct-GGUF/resolve/main/codellama-34b-instruct.q4_0.gguf"
        ],
        "description": "High-quality models for demanding tasks",
        "ram_needed": "32+ GB"
    }
}
