"""Hugging Face Transformers provider for ThreatSimGPT.

This provider enables direct loading and inference with Hugging Face models
using the transformers library, with support for GPU acceleration and quantization.
"""

import logging
import asyncio
from typing import Dict, Any, Optional, List, Union
from datetime import datetime
from pathlib import Path

from .local_base import LocalLLMProvider, LocalModelInfo, SystemResourceManager
from ..base import LLMResponse

logger = logging.getLogger(__name__)

# Optional imports with fallbacks
try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    torch = None
    logger.warning("PyTorch not available - Hugging Face provider will not work")

try:
    from transformers import (
        AutoTokenizer, AutoModelForCausalLM, AutoModelForSeq2SeqLM,
        GenerationConfig, BitsAndBytesConfig, pipeline
    )
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    AutoTokenizer = AutoModelForCausalLM = AutoModelForSeq2SeqLM = None
    GenerationConfig = BitsAndBytesConfig = pipeline = None
    logger.warning("Transformers library not available - Hugging Face provider will not work")

try:
    import accelerate
    ACCELERATE_AVAILABLE = True
except ImportError:
    ACCELERATE_AVAILABLE = False
    logger.info("Accelerate not available - multi-GPU inference may be limited")


class HuggingFaceProvider(LocalLLMProvider):
    """Hugging Face Transformers local LLM provider implementation."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize Hugging Face provider.

        Args:
            config: Configuration dictionary with Hugging Face settings
        """
        if not TRANSFORMERS_AVAILABLE or not TORCH_AVAILABLE:
            raise ImportError(
                "Hugging Face provider requires 'transformers' and 'torch' libraries. "
                "Install with: pip install transformers torch"
            )

        super().__init__(config)

        # Model configuration
        self.model_name_or_path = config.get('model_name_or_path', 'microsoft/DialoGPT-medium')
        self.model_type = config.get('model_type', 'causal')  # 'causal' or 'seq2seq'
        self.cache_dir = config.get('cache_dir', './models/huggingface')

        # Device and precision settings
        self.device_map = config.get('device_map', 'auto')
        self.torch_dtype = config.get('torch_dtype', 'auto')
        self.load_in_8bit = config.get('load_in_8bit', False)
        self.load_in_4bit = config.get('load_in_4bit', False)

        # Generation settings
        self.do_sample = config.get('do_sample', True)
        self.top_p = config.get('top_p', 0.9)
        self.top_k = config.get('top_k', 50)
        self.repetition_penalty = config.get('repetition_penalty', 1.1)
        self.pad_token_id = config.get('pad_token_id', None)

        # Performance settings
        self.use_cache = config.get('use_cache', True)
        self.trust_remote_code = config.get('trust_remote_code', False)

        # Model components
        self._model = None
        self._tokenizer = None
        self._generation_config = None
        self._pipeline = None

        # Create cache directory
        Path(self.cache_dir).mkdir(parents=True, exist_ok=True)

    async def _load_model(self) -> None:
        """Load the Hugging Face model and tokenizer."""
        try:
            logger.info(f"Loading Hugging Face model: {self.model_name_or_path}")

            # Prepare quantization config if needed
            quantization_config = None
            if self.load_in_4bit or self.load_in_8bit:
                quantization_config = BitsAndBytesConfig(
                    load_in_4bit=self.load_in_4bit,
                    load_in_8bit=self.load_in_8bit,
                    bnb_4bit_compute_dtype=torch.float16 if self.load_in_4bit else None
                )

            # Load tokenizer
            logger.info("Loading tokenizer...")
            self._tokenizer = AutoTokenizer.from_pretrained(
                self.model_name_or_path,
                cache_dir=self.cache_dir,
                trust_remote_code=self.trust_remote_code
            )

            # Set pad token if not present
            if self._tokenizer.pad_token is None:
                if self._tokenizer.eos_token is not None:
                    self._tokenizer.pad_token = self._tokenizer.eos_token
                else:
                    self._tokenizer.add_special_tokens({'pad_token': '[PAD]'})  # nosec B105

            # Determine torch dtype
            if self.torch_dtype == 'auto':
                torch_dtype = torch.float16 if torch.cuda.is_available() else torch.float32
            else:
                torch_dtype = getattr(torch, self.torch_dtype)

            # Load model based on type
            logger.info("Loading model...")
            if self.model_type == 'seq2seq':
                model_class = AutoModelForSeq2SeqLM
            else:
                model_class = AutoModelForCausalLM

            self._model = model_class.from_pretrained(
                self.model_name_or_path,
                cache_dir=self.cache_dir,
                device_map=self.device_map,
                torch_dtype=torch_dtype,
                quantization_config=quantization_config,
                trust_remote_code=self.trust_remote_code,
                use_cache=self.use_cache
            )

            # Set up generation config
            self._generation_config = GenerationConfig(
                do_sample=self.do_sample,
                top_p=self.top_p,
                top_k=self.top_k,
                repetition_penalty=self.repetition_penalty,
                pad_token_id=self._tokenizer.pad_token_id,
                eos_token_id=self._tokenizer.eos_token_id
            )

            # Create pipeline for easier inference
            self._pipeline = pipeline(
                "text-generation" if self.model_type == 'causal' else "text2text-generation",
                model=self._model,
                tokenizer=self._tokenizer,
                device_map=self.device_map
            )

            self._is_loaded = True
            self._load_time = datetime.utcnow()

            # Get model info
            self._model_info = LocalModelInfo(
                name=self.model_name_or_path,
                path=self.cache_dir,
                model_type="huggingface",
                context_length=getattr(self._model.config, 'max_position_embeddings', 2048),
                description=f"Hugging Face {self.model_type} model"
            )

            logger.info(f"Hugging Face model loaded successfully on {self._model.device}")

        except Exception as e:
            logger.error(f"Failed to load Hugging Face model: {e}")
            raise

    async def _unload_model(self) -> None:
        """Unload the model from memory."""
        try:
            if self._model is not None:
                del self._model
                self._model = None

            if self._tokenizer is not None:
                del self._tokenizer
                self._tokenizer = None

            if self._pipeline is not None:
                del self._pipeline
                self._pipeline = None

            # Clear GPU cache if using CUDA
            if TORCH_AVAILABLE and torch.cuda.is_available():
                torch.cuda.empty_cache()

            self._is_loaded = False
            logger.info("Hugging Face model unloaded")

        except Exception as e:
            logger.error(f"Error unloading Hugging Face model: {e}")

    async def _generate_with_model(
        self,
        prompt: str,
        max_tokens: int = 1000,
        temperature: float = 0.7,
        **kwargs
    ) -> str:
        """Generate text using the loaded Hugging Face model."""
        if not self._is_loaded or self._pipeline is None:
            raise RuntimeError("Model not loaded")

        try:
            # Update generation config with parameters
            generation_kwargs = {
                'max_new_tokens': max_tokens,
                'temperature': temperature,
                'do_sample': temperature > 0,
                'top_p': kwargs.get('top_p', self.top_p),
                'top_k': kwargs.get('top_k', self.top_k),
                'repetition_penalty': kwargs.get('repetition_penalty', self.repetition_penalty),
                'pad_token_id': self._tokenizer.pad_token_id,
                'eos_token_id': self._tokenizer.eos_token_id
            }

            # Run inference in thread to avoid blocking
            def generate():
                if self.model_type == 'seq2seq':
                    # For seq2seq models, use the pipeline directly
                    result = self._pipeline(
                        prompt,
                        max_length=max_tokens,
                        temperature=temperature,
                        do_sample=temperature > 0
                    )
                    return result[0]['generated_text']
                else:
                    # For causal models, generate continuation
                    result = self._pipeline(
                        prompt,
                        return_full_text=False,
                        **generation_kwargs
                    )
                    return result[0]['generated_text']

            # Run in executor to avoid blocking the event loop
            loop = asyncio.get_event_loop()
            generated_text = await loop.run_in_executor(None, generate)

            return generated_text.strip()

        except Exception as e:
            logger.error(f"Hugging Face generation failed: {e}")
            raise

    async def health_check(self) -> Dict[str, Any]:
        """Enhanced health check for Hugging Face provider."""
        health_info = await super().health_check()

        # Add Hugging Face specific info
        health_info.update({
            'model_name_or_path': self.model_name_or_path,
            'model_type': self.model_type,
            'cache_dir': self.cache_dir,
            'torch_available': TORCH_AVAILABLE,
            'transformers_available': TRANSFORMERS_AVAILABLE,
            'accelerate_available': ACCELERATE_AVAILABLE
        })

        if TORCH_AVAILABLE:
            health_info.update({
                'cuda_available': torch.cuda.is_available(),
                'cuda_device_count': torch.cuda.device_count() if torch.cuda.is_available() else 0
            })

            if torch.cuda.is_available():
                health_info['cuda_devices'] = [
                    {
                        'id': i,
                        'name': torch.cuda.get_device_name(i),
                        'memory_total': torch.cuda.get_device_properties(i).total_memory,
                        'memory_allocated': torch.cuda.memory_allocated(i),
                        'memory_cached': torch.cuda.memory_reserved(i)
                    }
                    for i in range(torch.cuda.device_count())
                ]

        if self._model is not None:
            health_info.update({
                'model_device': str(self._model.device),
                'model_dtype': str(self._model.dtype),
                'model_config': {
                    'vocab_size': getattr(self._model.config, 'vocab_size', None),
                    'hidden_size': getattr(self._model.config, 'hidden_size', None),
                    'num_layers': getattr(self._model.config, 'num_hidden_layers', None),
                    'max_position_embeddings': getattr(self._model.config, 'max_position_embeddings', None)
                }
            })

        return health_info

    def get_recommended_models(self) -> Dict[str, List[str]]:
        """Get recommended Hugging Face models for different use cases."""
        return {
            "small_fast": [
                "microsoft/DialoGPT-small",
                "distilgpt2",
                "gpt2",
                "facebook/opt-125m"
            ],
            "medium_balanced": [
                "microsoft/DialoGPT-medium",
                "gpt2-medium",
                "facebook/opt-1.3b",
                "EleutherAI/gpt-neo-1.3B"
            ],
            "large_quality": [
                "microsoft/DialoGPT-large",
                "gpt2-large",
                "facebook/opt-6.7b",
                "EleutherAI/gpt-neo-2.7B"
            ],
            "code_specialized": [
                "Salesforce/codegen-350M-multi",
                "Salesforce/codegen-2B-multi",
                "microsoft/CodeGPT-small-py"
            ],
            "instruction_tuned": [
                "microsoft/GODEL-v1_1-base-seq2seq",
                "facebook/blenderbot-400M-distill",
                "microsoft/GODEL-v1_1-large-seq2seq"
            ]
        }

    async def download_model(self, model_name: str, cache_dir: Optional[str] = None) -> bool:
        """Download a model to local cache."""
        try:
            download_cache_dir = cache_dir or self.cache_dir

            logger.info(f"Downloading model {model_name} to {download_cache_dir}")

            # Download tokenizer first (smaller, faster feedback)
            tokenizer = AutoTokenizer.from_pretrained(
                model_name,
                cache_dir=download_cache_dir,
                trust_remote_code=self.trust_remote_code
            )

            # Download model
            if self.model_type == 'seq2seq':
                model = AutoModelForSeq2SeqLM.from_pretrained(
                    model_name,
                    cache_dir=download_cache_dir,
                    trust_remote_code=self.trust_remote_code
                )
            else:
                model = AutoModelForCausalLM.from_pretrained(
                    model_name,
                    cache_dir=download_cache_dir,
                    trust_remote_code=self.trust_remote_code
                )

            logger.info(f"Successfully downloaded model {model_name}")

            # Clean up
            del tokenizer, model
            if TORCH_AVAILABLE and torch.cuda.is_available():
                torch.cuda.empty_cache()

            return True

        except Exception as e:
            logger.error(f"Failed to download model {model_name}: {e}")
            return False

    def estimate_memory_usage(self, model_name: str) -> Dict[str, float]:
        """Estimate memory usage for a model."""
        try:
            # This is a rough estimation based on model name patterns
            memory_estimates = {
                # Small models (< 1GB)
                "125m": 0.5, "small": 0.5, "mini": 0.3, "distil": 0.7,
                # Medium models (1-5GB)
                "350m": 1.4, "medium": 2.0, "1.3b": 2.6, "1b": 2.0,
                # Large models (5-20GB)
                "2.7b": 5.4, "6.7b": 13.4, "large": 6.0,
                # Very large models (20GB+)
                "13b": 26.0, "30b": 60.0, "70b": 140.0
            }

            # Try to match model size from name
            model_name_lower = model_name.lower()
            estimated_gb = 2.0  # Default estimate

            for size_key, gb in memory_estimates.items():
                if size_key in model_name_lower:
                    estimated_gb = gb
                    break

            return {
                'estimated_model_size_gb': estimated_gb,
                'estimated_ram_needed_gb': estimated_gb * 2,  # 2x for loading
                'estimated_vram_needed_gb': estimated_gb * 1.2,  # 1.2x for GPU inference
                'can_run_cpu': self.resource_manager.get_available_memory() >= estimated_gb * 2,
                'can_run_gpu': any(
                    vram >= estimated_gb * 1.2
                    for vram in self.resource_manager.get_gpu_memory().values()
                )
            }

        except Exception as e:
            logger.error(f"Failed to estimate memory usage for {model_name}: {e}")
            return {'error': str(e)}


# Model recommendations for different use cases
HUGGINGFACE_MODEL_RECOMMENDATIONS = {
    "cybersecurity_training": {
        "small": ["microsoft/DialoGPT-small", "distilgpt2"],
        "medium": ["microsoft/DialoGPT-medium", "gpt2-medium"],
        "large": ["microsoft/DialoGPT-large", "EleutherAI/gpt-neo-2.7B"],
        "description": "General purpose conversational models suitable for training content generation"
    },
    "technical_content": {
        "small": ["Salesforce/codegen-350M-multi"],
        "medium": ["Salesforce/codegen-2B-multi"],
        "large": ["Salesforce/codegen-6B-multi"],
        "description": "Code-aware models for technical scenario generation"
    },
    "instruction_following": {
        "small": ["facebook/blenderbot-400M-distill"],
        "medium": ["microsoft/GODEL-v1_1-base-seq2seq"],
        "large": ["microsoft/GODEL-v1_1-large-seq2seq"],
        "description": "Instruction-tuned models for better prompt following"
    }
}
