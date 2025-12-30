"""Model management utilities for ThreatSimGPT local models.

This module provides utilities to help users discover, download, install,
and manage local models across different providers.
"""

import logging
import asyncio
import os
from typing import Dict, Any, List, Optional, Tuple, Callable
from pathlib import Path
import json
from datetime import datetime

logger = logging.getLogger(__name__)

# Optional imports with fallbacks
try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class ModelManager:
    """Unified model management for all local providers."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize model manager.

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.model_cache_dir = Path(self.config.get('model_cache_dir', './models'))
        self.model_cache_dir.mkdir(parents=True, exist_ok=True)

        # Model registry file
        self.registry_file = self.model_cache_dir / 'model_registry.json'
        self.registry = self._load_registry()

        # Session management for HTTP requests
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session with connection pooling."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def cleanup(self):
        """Clean up resources."""
        if self._session and not self._session.closed:
            await self._session.close()

    def _load_registry(self) -> Dict[str, Any]:
        """Load model registry from disk."""
        try:
            if self.registry_file.exists():
                with open(self.registry_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load model registry: {e}")

        return {
            'models': {},
            'last_updated': datetime.utcnow().isoformat(),
            'version': '1.0'
        }

    def _save_registry(self) -> None:
        """Save model registry to disk."""
        try:
            self.registry['last_updated'] = datetime.utcnow().isoformat()
            with open(self.registry_file, 'w') as f:
                json.dump(self.registry, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save model registry: {e}")

    def register_model(
        self,
        name: str,
        provider: str,
        path: str,
        metadata: Dict[str, Any] = None
    ) -> None:
        """Register a model in the local registry."""
        model_info = {
            'name': name,
            'provider': provider,
            'path': str(path),
            'registered_at': datetime.utcnow().isoformat(),
            'size_mb': None,
            'metadata': metadata or {}
        }

        # Get file size if path exists
        try:
            path_obj = Path(path)
            if path_obj.exists():
                model_info['size_mb'] = path_obj.stat().st_size / (1024 * 1024)
        except Exception:
            pass

        self.registry['models'][name] = model_info
        self._save_registry()
        logger.info(f"Registered model {name} for provider {provider}")

    def list_registered_models(self, provider: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all registered models, optionally filtered by provider."""
        models = []
        for name, info in self.registry['models'].items():
            if provider is None or info['provider'] == provider:
                # Check if model still exists
                path = Path(info['path'])
                info['exists'] = path.exists()
                if info['exists'] and info.get('size_mb') is None:
                    try:
                        info['size_mb'] = path.stat().st_size / (1024 * 1024)
                    except Exception:
                        pass
                models.append(info)

        return models

    def get_model_recommendations(self, use_case: str = "general") -> Dict[str, Dict[str, Any]]:
        """Get model recommendations for different providers and use cases."""
        recommendations = {
            "ollama": {
                "cybersecurity": [
                    {"name": "llama3.2:3b", "size": "2.0GB", "description": "Fast, good for basic scenarios"},
                    {"name": "mistral:7b", "size": "4.1GB", "description": "Balanced performance for training content"},
                    {"name": "codellama:7b", "size": "3.8GB", "description": "Code-aware for technical scenarios"}
                ],
                "general": [
                    {"name": "llama3.2:1b", "size": "1.3GB", "description": "Very fast, minimal resources"},
                    {"name": "phi3:3.8b", "size": "2.3GB", "description": "Efficient instruction following"},
                    {"name": "qwen2:7b", "size": "4.4GB", "description": "Good reasoning capabilities"}
                ],
                "setup_command": "ollama pull {model_name}"
            },
            "huggingface": {
                "cybersecurity": [
                    {"name": "microsoft/DialoGPT-medium", "size": "~1GB", "description": "Conversational model for training scenarios"},
                    {"name": "Salesforce/codegen-2B-multi", "size": "~8GB", "description": "Code-aware for technical content"},
                    {"name": "microsoft/GODEL-v1_1-base-seq2seq", "size": "~2GB", "description": "Instruction-tuned for better responses"}
                ],
                "general": [
                    {"name": "microsoft/DialoGPT-small", "size": "~500MB", "description": "Lightweight conversational model"},
                    {"name": "distilgpt2", "size": "~350MB", "description": "Fast and efficient"},
                    {"name": "gpt2-medium", "size": "~1.5GB", "description": "Balanced size and performance"}
                ],
                "setup_note": "Automatically downloaded on first use"
            },
            "llamacpp": {
                "cybersecurity": [
                    {"name": "llama-2-7b-chat.q4_0.gguf", "size": "3.9GB", "description": "Quantized Llama2 for cybersecurity training"},
                    {"name": "codellama-13b-instruct.q4_0.gguf", "size": "7.3GB", "description": "Code-focused model for technical scenarios"},
                    {"name": "mistral-7b-instruct.q4_0.gguf", "size": "4.1GB", "description": "Efficient instruction following"}
                ],
                "general": [
                    {"name": "llama-2-7b-chat.q4_0.gguf", "size": "3.9GB", "description": "General purpose chat model"},
                    {"name": "phi-2.q4_0.gguf", "size": "1.6GB", "description": "Small but capable model"},
                    {"name": "tinyllama-1.1b.q4_0.gguf", "size": "600MB", "description": "Very lightweight option"}
                ],
                "setup_note": "Download GGUF files and set model_path in config"
            }
        }

        return recommendations.get(use_case, recommendations)

    async def check_ollama_server(self) -> Dict[str, Any]:
        """Check if Ollama server is running and accessible."""
        if not AIOHTTP_AVAILABLE:
            return {"status": "error", "message": "aiohttp required for Ollama connectivity check"}

        try:
            session = await self._get_session()
            # Check if Ollama is running
            timeout = aiohttp.ClientTimeout(total=5)
            async with session.get('http://localhost:11434/api/tags', timeout=timeout) as response:
                if response.status == 200:
                    data = await response.json()
                    models = [model['name'] for model in data.get('models', [])]
                    return {
                        "status": "running",
                        "models": models,
                        "model_count": len(models),
                        "server_url": "http://localhost:11434"
                    }
                else:
                    return {"status": "error", "message": f"Ollama server returned status {response.status}"}

        except asyncio.TimeoutError:
            return {"status": "timeout", "message": "Ollama server not responding (timeout after 5s)"}
        except Exception as e:
            return {"status": "not_running", "message": f"Ollama server not accessible: {e}"}

    def get_system_requirements(self) -> Dict[str, Any]:
        """Get system requirements and recommendations for local models."""
        try:
            import psutil

            # Get system info
            memory_gb = psutil.virtual_memory().total / (1024**3)
            cpu_count = psutil.cpu_count()

            # Check for GPU
            gpu_available = False
            gpu_memory_gb = 0
            try:
                import torch
                if torch.cuda.is_available():
                    gpu_available = True
                    gpu_memory_gb = torch.cuda.get_device_properties(0).total_memory / (1024**3)
            except ImportError:
                pass

            # Generate recommendations
            recommendations = []

            if memory_gb >= 32:
                recommendations.append("[EXCELLENT] RAM (32GB+) - Can run large models (13B-70B parameters)")
            elif memory_gb >= 16:
                recommendations.append("[GOOD] RAM (16GB+) - Can run medium models (7B-13B parameters)")
            elif memory_gb >= 8:
                recommendations.append("[LIMITED] RAM (8GB) - Stick to small models (1B-3B parameters)")
            else:
                recommendations.append("[WARNING] Insufficient RAM (<8GB) - Local models not recommended")

            if gpu_available and gpu_memory_gb >= 8:
                recommendations.append("[GPU] GPU available with good VRAM - Use Hugging Face provider for best performance")
            elif gpu_available:
                recommendations.append("[GPU] GPU available but limited VRAM - Consider quantized models")
            else:
                recommendations.append("[INFO] No GPU detected - Use Ollama or llama.cpp for CPU inference")

            return {
                "system_info": {
                    "memory_gb": round(memory_gb, 1),
                    "cpu_count": cpu_count,
                    "gpu_available": gpu_available,
                    "gpu_memory_gb": round(gpu_memory_gb, 1) if gpu_available else 0
                },
                "recommendations": recommendations,
                "best_provider": self._recommend_provider(memory_gb, gpu_available, gpu_memory_gb)
            }

        except ImportError:
            return {
                "error": "psutil required for system analysis",
                "install_command": "pip install psutil torch"
            }

    def _recommend_provider(self, memory_gb: float, gpu_available: bool, gpu_memory_gb: float) -> str:
        """Recommend the best provider based on system specs."""
        if gpu_available and gpu_memory_gb >= 6:
            return "huggingface"  # Best for GPU systems
        elif memory_gb >= 16:
            return "ollama"  # Easy setup for good systems
        elif memory_gb >= 8:
            return "llamacpp"  # Most efficient for limited systems
        else:
            return "cloud"  # Recommend cloud providers for very limited systems

    def generate_setup_guide(self, provider: str, model_name: Optional[str] = None) -> Dict[str, Any]:
        """Generate a setup guide for a specific provider."""
        guides = {
            "ollama": {
                "title": "Ollama Setup Guide",
                "description": "Server-based local models with automatic management",
                "steps": [
                    {
                        "step": 1,
                        "title": "Install Ollama",
                        "commands": [
                            "# On macOS:",
                            "brew install ollama",
                            "",
                            "# On Linux:",
                            "curl -fsSL https://ollama.ai/install.sh | sh",
                            "",
                            "# On Windows:",
                            "# Download from https://ollama.ai/download"
                        ]
                    },
                    {
                        "step": 2,
                        "title": "Start Ollama Server",
                        "commands": ["ollama serve"]
                    },
                    {
                        "step": 3,
                        "title": f"Pull Model{f' ({model_name})' if model_name else ''}",
                        "commands": [f"ollama pull {model_name or 'llama3.2:3b'}"]
                    },
                    {
                        "step": 4,
                        "title": "Update ThreatSimGPT Config",
                        "commands": [
                            "# In config.yaml:",
                            "llm:",
                            "  ollama:",
                            "    enabled: true",
                            f"    model: \"{model_name or 'llama3.2:3b'}\""
                        ]
                    }
                ],
                "verification": "ollama list",
                "troubleshooting": [
                    "If 'ollama command not found': Restart terminal or add to PATH",
                    "If server won't start: Check port 11434 is available",
                    "If model download fails: Check internet connection and disk space"
                ]
            },
            "huggingface": {
                "title": "Hugging Face Transformers Setup Guide",
                "description": "Direct model loading with GPU acceleration",
                "steps": [
                    {
                        "step": 1,
                        "title": "Install Dependencies",
                        "commands": [
                            "pip install transformers torch",
                            "# For GPU support (NVIDIA):",
                            "pip install transformers torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118",
                            "# For quantization (optional):",
                            "pip install bitsandbytes accelerate"
                        ]
                    },
                    {
                        "step": 2,
                        "title": "Update ThreatSimGPT Config",
                        "commands": [
                            "# In config.yaml:",
                            "llm:",
                            "  huggingface:",
                            "    enabled: true",
                            f"    model_name_or_path: \"{model_name or 'microsoft/DialoGPT-medium'}\"",
                            "    device_map: \"auto\"  # Automatically use GPU if available"
                        ]
                    }
                ],
                "verification": "python -c \"import transformers, torch; print(' Ready')\"",
                "troubleshooting": [
                    "If CUDA errors: Check GPU drivers and CUDA version",
                    "If out of memory: Enable quantization or use smaller model",
                    "If slow loading: Increase cache_dir size or use SSD storage"
                ]
            },
            "llamacpp": {
                "title": "llama.cpp Setup Guide",
                "description": "High-performance CPU inference with GGUF support",
                "steps": [
                    {
                        "step": 1,
                        "title": "Install Dependencies",
                        "commands": [
                            "pip install llama-cpp-python",
                            "# For GPU support (optional):",
                            "CMAKE_ARGS=\"-DLLAMA_CUBLAS=on\" pip install llama-cpp-python --force-reinstall --no-cache-dir"
                        ]
                    },
                    {
                        "step": 2,
                        "title": f"Download Model{f' ({model_name})' if model_name else ''}",
                        "commands": [
                            "mkdir -p ./models/llamacpp",
                            f"# Download {model_name or 'a GGUF model'} to ./models/llamacpp/",
                            "# Example URLs in model recommendations"
                        ]
                    },
                    {
                        "step": 3,
                        "title": "Update ThreatSimGPT Config",
                        "commands": [
                            "# In config.yaml:",
                            "llm:",
                            "  llamacpp:",
                            "    enabled: true",
                            f"    model_path: \"./models/llamacpp/{model_name or 'model.gguf'}\""
                        ]
                    }
                ],
                "verification": "python -c \"from llama_cpp import Llama; print(' Ready')\"",
                "troubleshooting": [
                    "If import errors: Check llama-cpp-python installation",
                    "If model not found: Verify file path and format (must be .gguf or .ggml)",
                    "If out of memory: Reduce n_ctx or use smaller quantized model"
                ]
            }
        }

        return guides.get(provider, {"error": f"No setup guide available for provider: {provider}"})

    async def download_model(
        self,
        provider: str,
        model_name: str,
        download_url: str,
        progress_callback: Optional[Callable[[float, int, int], None]] = None
    ) -> Dict[str, Any]:
        """Download a model file for local providers."""
        if not REQUESTS_AVAILABLE:
            return {"error": "requests library required for downloads"}

        try:
            # Create provider-specific directory
            provider_dir = self.model_cache_dir / provider
            provider_dir.mkdir(exist_ok=True)

            # Determine filename
            filename = download_url.split('/')[-1]
            if not filename:
                filename = f"{model_name}.model"

            file_path = provider_dir / filename

            logger.info(f"Downloading {model_name} from {download_url}")

            def download():
                response = requests.get(download_url, stream=True)
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

                return str(file_path)

            # Run download in executor
            loop = asyncio.get_event_loop()
            final_path = await loop.run_in_executor(None, download)

            # Register the downloaded model
            self.register_model(model_name, provider, final_path)

            logger.info(f"Successfully downloaded {model_name} to {final_path}")
            return {
                "status": "success",
                "model_name": model_name,
                "provider": provider,
                "path": final_path,
                "size_mb": Path(final_path).stat().st_size / (1024 * 1024)
            }

        except Exception as e:
            logger.error(f"Failed to download {model_name}: {e}")
            return {"error": str(e)}

    def cleanup_models(self, provider: Optional[str] = None, dry_run: bool = True) -> Dict[str, Any]:
        """Clean up unused or orphaned model files."""
        results = {
            "files_found": [],
            "files_to_delete": [],
            "space_to_free_mb": 0,
            "dry_run": dry_run
        }

        try:
            # Scan model cache directory
            for provider_dir in self.model_cache_dir.iterdir():
                if provider_dir.is_dir() and (provider is None or provider_dir.name == provider):
                    for model_file in provider_dir.iterdir():
                        if model_file.is_file():
                            size_mb = model_file.stat().st_size / (1024 * 1024)
                            file_info = {
                                "path": str(model_file),
                                "provider": provider_dir.name,
                                "size_mb": size_mb,
                                "registered": False
                            }

                            # Check if file is registered
                            for registered_model in self.registry['models'].values():
                                if Path(registered_model['path']) == model_file:
                                    file_info["registered"] = True
                                    break

                            results["files_found"].append(file_info)

                            # Mark unregistered files for deletion
                            if not file_info["registered"]:
                                results["files_to_delete"].append(file_info)
                                results["space_to_free_mb"] += size_mb

                                if not dry_run:
                                    model_file.unlink()
                                    logger.info(f"Deleted orphaned model file: {model_file}")

            if not dry_run and results["files_to_delete"]:
                logger.info(f"Cleaned up {len(results['files_to_delete'])} files, "
                          f"freed {results['space_to_free_mb']:.1f} MB")

        except Exception as e:
            results["error"] = str(e)

        return results
