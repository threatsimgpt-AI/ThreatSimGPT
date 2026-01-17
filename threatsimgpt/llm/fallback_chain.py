"""Model Fallback Chain for LLM Provider Reliability.

This module implements automatic fallback between LLM providers with circuit
breaker pattern, health checks, and 99.9% availability target.

Issue: #34 - Implement Model Fallback Chain
Owner: Lanre Shittu (@Shizoqua)
Track: ML/Reliability
"""

from __future__ import annotations

import asyncio
import logging
import time
import random
import hashlib
from abc import ABC, abstractmethod
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import (
    Any,
    Callable,
    Dict,
    Generic,
    List,
    Optional,
    Protocol,
    Tuple,
    TypeVar,
    Union,
)
from contextlib import asynccontextmanager

from pydantic import BaseModel, Field, ConfigDict
from pydantic_settings import BaseSettings

from .base import BaseLLMProvider, LLMResponse
from .exceptions import LLMError, ProviderError, RateLimitError

logger = logging.getLogger(__name__)


# ============================================================================
# Configuration
# ============================================================================


class FallbackChainConfig(BaseSettings):
    """Configuration for the model fallback chain.
    
    All values can be overridden via environment variables with FALLBACK_ prefix.
    """
    
    model_config = ConfigDict(env_prefix="FALLBACK_")
    
    # Circuit breaker settings
    circuit_failure_threshold: int = Field(
        default=5,
        description="Number of failures before circuit opens"
    )
    circuit_recovery_timeout: float = Field(
        default=30.0,
        description="Seconds before attempting recovery"
    )
    circuit_half_open_max_calls: int = Field(
        default=3,
        description="Max calls in half-open state"
    )
    
    # Retry settings
    max_retries_per_provider: int = Field(
        default=2,
        description="Max retries per provider before fallback"
    )
    retry_base_delay: float = Field(
        default=0.5,
        description="Base delay for exponential backoff (seconds)"
    )
    retry_max_delay: float = Field(
        default=10.0,
        description="Maximum retry delay (seconds)"
    )
    retry_jitter: float = Field(
        default=0.1,
        description="Jitter factor for retry delays (0-1)"
    )
    
    # Health check settings
    health_check_interval: float = Field(
        default=30.0,
        description="Seconds between health checks"
    )
    health_check_timeout: float = Field(
        default=5.0,
        description="Timeout for health check requests"
    )
    health_check_consecutive_failures: int = Field(
        default=3,
        description="Consecutive failures to mark unhealthy"
    )
    
    # Request settings
    request_timeout: float = Field(
        default=30.0,
        description="Default request timeout (seconds)"
    )
    
    # Availability settings
    target_availability: float = Field(
        default=0.999,
        description="Target availability (99.9%)"
    )
    metrics_window_seconds: int = Field(
        default=3600,
        description="Window for availability metrics (1 hour)"
    )
    max_tracked_requests: int = Field(
        default=10000,
        description="Max requests to track for metrics"
    )


# ============================================================================
# Circuit Breaker States
# ============================================================================


class CircuitState(str, Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation, requests flow through
    OPEN = "open"          # Failing, requests are blocked
    HALF_OPEN = "half_open"  # Testing recovery


@dataclass
class CircuitBreakerState:
    """Tracks state for a single provider's circuit breaker."""
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: Optional[float] = None
    last_success_time: Optional[float] = None
    half_open_calls: int = 0
    consecutive_successes: int = 0
    
    def record_failure(self) -> None:
        """Record a failure."""
        self.failure_count += 1
        self.last_failure_time = time.monotonic()
        self.consecutive_successes = 0
    
    def record_success(self) -> None:
        """Record a success."""
        self.success_count += 1
        self.last_success_time = time.monotonic()
        self.consecutive_successes += 1


# ============================================================================
# Health Status
# ============================================================================


class HealthStatus(str, Enum):
    """Provider health status."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class ProviderHealth:
    """Health information for a provider."""
    status: HealthStatus = HealthStatus.UNKNOWN
    last_check_time: Optional[float] = None
    latency_ms: Optional[float] = None
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    error_message: Optional[str] = None
    
    def update_healthy(self, latency_ms: float) -> None:
        """Update state after successful health check."""
        self.status = HealthStatus.HEALTHY
        self.last_check_time = time.monotonic()
        self.latency_ms = latency_ms
        self.consecutive_successes += 1
        self.consecutive_failures = 0
        self.error_message = None
    
    def update_unhealthy(self, error: str, threshold: int = 3) -> None:
        """Update state after failed health check."""
        self.last_check_time = time.monotonic()
        self.consecutive_failures += 1
        self.consecutive_successes = 0
        self.error_message = error
        
        if self.consecutive_failures >= threshold:
            self.status = HealthStatus.UNHEALTHY
        elif self.consecutive_failures >= 1:
            self.status = HealthStatus.DEGRADED


# ============================================================================
# Request Metrics
# ============================================================================


@dataclass
class RequestMetric:
    """Single request metric."""
    timestamp: float
    provider: str
    success: bool
    latency_ms: float
    error: Optional[str] = None


class MetricsCollector:
    """Collects and computes availability metrics.
    
    Uses a sliding window to compute availability and latency statistics.
    Thread-safe through atomic operations on deque.
    """
    
    def __init__(
        self,
        window_seconds: int = 3600,
        max_requests: int = 10000
    ):
        self._window_seconds = window_seconds
        self._max_requests = max_requests
        self._metrics: deque[RequestMetric] = deque(maxlen=max_requests)
        self._provider_metrics: Dict[str, deque[RequestMetric]] = {}
    
    def record(
        self,
        provider: str,
        success: bool,
        latency_ms: float,
        error: Optional[str] = None
    ) -> None:
        """Record a request metric."""
        metric = RequestMetric(
            timestamp=time.monotonic(),
            provider=provider,
            success=success,
            latency_ms=latency_ms,
            error=error
        )
        self._metrics.append(metric)
        
        if provider not in self._provider_metrics:
            self._provider_metrics[provider] = deque(maxlen=self._max_requests)
        self._provider_metrics[provider].append(metric)
    
    def _filter_window(
        self,
        metrics: deque[RequestMetric]
    ) -> List[RequestMetric]:
        """Filter metrics within the time window."""
        cutoff = time.monotonic() - self._window_seconds
        return [m for m in metrics if m.timestamp > cutoff]
    
    def get_availability(self, provider: Optional[str] = None) -> float:
        """Get availability ratio (0.0 to 1.0)."""
        if provider:
            metrics = self._provider_metrics.get(provider, deque())
        else:
            metrics = self._metrics
        
        recent = self._filter_window(metrics)
        if not recent:
            return 1.0  # No data, assume available
        
        successful = sum(1 for m in recent if m.success)
        return successful / len(recent)
    
    def get_latency_percentile(
        self,
        percentile: float = 0.95,
        provider: Optional[str] = None
    ) -> Optional[float]:
        """Get latency at given percentile."""
        if provider:
            metrics = self._provider_metrics.get(provider, deque())
        else:
            metrics = self._metrics
        
        recent = self._filter_window(metrics)
        if not recent:
            return None
        
        latencies = sorted(m.latency_ms for m in recent if m.success)
        if not latencies:
            return None
        
        idx = int(len(latencies) * percentile)
        idx = min(idx, len(latencies) - 1)
        return latencies[idx]
    
    def get_error_rate(self, provider: Optional[str] = None) -> float:
        """Get error rate (0.0 to 1.0)."""
        availability = self.get_availability(provider)
        return 1.0 - availability
    
    def get_request_count(self, provider: Optional[str] = None) -> int:
        """Get total request count in window."""
        if provider:
            metrics = self._provider_metrics.get(provider, deque())
        else:
            metrics = self._metrics
        return len(self._filter_window(metrics))
    
    def get_summary(self) -> Dict[str, Any]:
        """Get comprehensive metrics summary."""
        return {
            "overall": {
                "availability": self.get_availability(),
                "error_rate": self.get_error_rate(),
                "request_count": self.get_request_count(),
                "p50_latency_ms": self.get_latency_percentile(0.50),
                "p95_latency_ms": self.get_latency_percentile(0.95),
                "p99_latency_ms": self.get_latency_percentile(0.99),
            },
            "by_provider": {
                provider: {
                    "availability": self.get_availability(provider),
                    "error_rate": self.get_error_rate(provider),
                    "request_count": self.get_request_count(provider),
                    "p95_latency_ms": self.get_latency_percentile(0.95, provider),
                }
                for provider in self._provider_metrics.keys()
            }
        }


# ============================================================================
# Fallback Chain Errors
# ============================================================================


class FallbackChainError(LLMError):
    """Base error for fallback chain."""
    pass


class AllProvidersFailedError(FallbackChainError):
    """All providers in the chain have failed."""
    
    def __init__(
        self,
        errors: Dict[str, Exception],
        message: str = "All LLM providers failed"
    ):
        self.errors = errors
        self.message = message
        super().__init__(f"{message}: {errors}")


class CircuitOpenError(FallbackChainError):
    """Circuit breaker is open for this provider."""
    
    def __init__(self, provider: str):
        self.provider = provider
        super().__init__(f"Circuit breaker open for provider: {provider}")


class ProviderUnavailableError(FallbackChainError):
    """Provider is unavailable (unhealthy or circuit open)."""
    
    def __init__(self, provider: str, reason: str):
        self.provider = provider
        self.reason = reason
        super().__init__(f"Provider {provider} unavailable: {reason}")


# ============================================================================
# Provider Wrapper
# ============================================================================


@dataclass
class ProviderEntry:
    """Entry for a provider in the fallback chain."""
    name: str
    provider: BaseLLMProvider
    priority: int = 0  # Lower = higher priority
    weight: float = 1.0  # For weighted selection
    enabled: bool = True
    
    # Runtime state
    circuit_state: CircuitBreakerState = field(default_factory=CircuitBreakerState)
    health: ProviderHealth = field(default_factory=ProviderHealth)


# ============================================================================
# Selection Strategy
# ============================================================================


class SelectionStrategy(str, Enum):
    """Strategy for selecting providers."""
    PRIORITY = "priority"         # Use priority order
    ROUND_ROBIN = "round_robin"   # Rotate through providers
    WEIGHTED = "weighted"         # Weight-based random selection
    LATENCY = "latency"           # Lowest latency first


# ============================================================================
# Model Fallback Chain
# ============================================================================


class ModelFallbackChain:
    """Automatic fallback between LLM providers for high availability.
    
    Implements:
    - Configurable fallback chain with multiple providers
    - Circuit breaker pattern for failing providers
    - Automatic health checks
    - 99.9% availability target with metrics tracking
    - Multiple selection strategies (priority, round-robin, weighted, latency)
    - Exponential backoff with jitter for retries
    
    Example:
        chain = ModelFallbackChain(config)
        chain.add_provider("openai", openai_provider, priority=0)
        chain.add_provider("anthropic", anthropic_provider, priority=1)
        chain.add_provider("ollama", ollama_provider, priority=2)
        
        # Start health checks
        await chain.start_health_checks()
        
        # Generate with automatic fallback
        response = await chain.generate(prompt, max_tokens=1000)
        
        # Check metrics
        print(chain.get_availability())  # 0.999
    """
    
    def __init__(
        self,
        config: Optional[FallbackChainConfig] = None,
        selection_strategy: SelectionStrategy = SelectionStrategy.PRIORITY
    ):
        """Initialize the fallback chain.
        
        Args:
            config: Configuration settings
            selection_strategy: How to select providers
        """
        self._config = config or FallbackChainConfig()
        self._selection_strategy = selection_strategy
        self._providers: OrderedDict[str, ProviderEntry] = OrderedDict()
        self._metrics = MetricsCollector(
            window_seconds=self._config.metrics_window_seconds,
            max_requests=self._config.max_tracked_requests
        )
        self._round_robin_index = 0
        self._health_check_task: Optional[asyncio.Task] = None
        self._shutdown = False
        self._lock = asyncio.Lock()
        
        logger.info(
            f"Initialized ModelFallbackChain with strategy={selection_strategy.value}, "
            f"target_availability={self._config.target_availability}"
        )
    
    # ========================================================================
    # Provider Management
    # ========================================================================
    
    def add_provider(
        self,
        name: str,
        provider: BaseLLMProvider,
        priority: int = 0,
        weight: float = 1.0,
        enabled: bool = True
    ) -> None:
        """Add a provider to the fallback chain.
        
        Args:
            name: Unique identifier for the provider
            provider: The LLM provider instance
            priority: Priority level (lower = higher priority)
            weight: Weight for weighted selection (higher = more likely)
            enabled: Whether the provider is enabled
        """
        entry = ProviderEntry(
            name=name,
            provider=provider,
            priority=priority,
            weight=weight,
            enabled=enabled
        )
        self._providers[name] = entry
        logger.info(f"Added provider '{name}' with priority={priority}, weight={weight}")
    
    def remove_provider(self, name: str) -> bool:
        """Remove a provider from the chain.
        
        Args:
            name: Provider name to remove
            
        Returns:
            True if removed, False if not found
        """
        if name in self._providers:
            del self._providers[name]
            logger.info(f"Removed provider '{name}'")
            return True
        return False
    
    def set_provider_enabled(self, name: str, enabled: bool) -> bool:
        """Enable or disable a provider.
        
        Args:
            name: Provider name
            enabled: Whether to enable
            
        Returns:
            True if updated, False if not found
        """
        if name in self._providers:
            self._providers[name].enabled = enabled
            logger.info(f"Provider '{name}' enabled={enabled}")
            return True
        return False
    
    def get_provider_names(self) -> List[str]:
        """Get list of all provider names."""
        return list(self._providers.keys())
    
    # ========================================================================
    # Circuit Breaker
    # ========================================================================
    
    def _is_circuit_open(self, entry: ProviderEntry) -> bool:
        """Check if circuit breaker is open for provider."""
        state = entry.circuit_state
        
        if state.state == CircuitState.CLOSED:
            return False
        
        if state.state == CircuitState.OPEN:
            # Check if recovery timeout has passed
            if state.last_failure_time is not None:
                elapsed = time.monotonic() - state.last_failure_time
                if elapsed >= self._config.circuit_recovery_timeout:
                    # Transition to half-open
                    state.state = CircuitState.HALF_OPEN
                    state.half_open_calls = 0
                    logger.info(f"Circuit for '{entry.name}' transitioning to half-open")
                    return False
            return True
        
        if state.state == CircuitState.HALF_OPEN:
            # Allow limited calls in half-open state
            return state.half_open_calls >= self._config.circuit_half_open_max_calls
        
        return False
    
    def _record_circuit_success(self, entry: ProviderEntry) -> None:
        """Record successful call for circuit breaker."""
        state = entry.circuit_state
        state.record_success()
        
        if state.state == CircuitState.HALF_OPEN:
            state.half_open_calls += 1
            # Successful calls in half-open -> close circuit
            if state.consecutive_successes >= self._config.circuit_half_open_max_calls:
                state.state = CircuitState.CLOSED
                state.failure_count = 0
                logger.info(f"Circuit for '{entry.name}' closed after recovery")
        
        elif state.state == CircuitState.CLOSED:
            # Reset failure count on success
            if state.failure_count > 0:
                state.failure_count = max(0, state.failure_count - 1)
    
    def _record_circuit_failure(self, entry: ProviderEntry, error: Exception) -> None:
        """Record failed call for circuit breaker."""
        state = entry.circuit_state
        state.record_failure()
        
        if state.state == CircuitState.HALF_OPEN:
            # Failure in half-open -> reopen circuit
            state.state = CircuitState.OPEN
            logger.warning(f"Circuit for '{entry.name}' reopened after failure in half-open")
        
        elif state.state == CircuitState.CLOSED:
            # Check if threshold reached
            if state.failure_count >= self._config.circuit_failure_threshold:
                state.state = CircuitState.OPEN
                logger.warning(
                    f"Circuit for '{entry.name}' opened after {state.failure_count} failures"
                )
    
    def get_circuit_state(self, name: str) -> Optional[Dict[str, Any]]:
        """Get circuit breaker state for a provider."""
        if name not in self._providers:
            return None
        
        entry = self._providers[name]
        state = entry.circuit_state
        
        return {
            "state": state.state.value,
            "failure_count": state.failure_count,
            "success_count": state.success_count,
            "consecutive_successes": state.consecutive_successes,
            "last_failure_time": state.last_failure_time,
            "last_success_time": state.last_success_time,
        }
    
    def reset_circuit(self, name: str) -> bool:
        """Manually reset circuit breaker for a provider."""
        if name not in self._providers:
            return False
        
        entry = self._providers[name]
        entry.circuit_state = CircuitBreakerState()
        logger.info(f"Circuit for '{name}' manually reset")
        return True
    
    # ========================================================================
    # Health Checks
    # ========================================================================
    
    async def check_provider_health(self, name: str) -> ProviderHealth:
        """Check health of a specific provider.
        
        Args:
            name: Provider name
            
        Returns:
            ProviderHealth with current status
        """
        if name not in self._providers:
            health = ProviderHealth(status=HealthStatus.UNKNOWN)
            health.error_message = f"Provider '{name}' not found"
            return health
        
        entry = self._providers[name]
        
        try:
            start_time = time.monotonic()
            
            # Use a simple test prompt for health check
            response = await asyncio.wait_for(
                entry.provider.generate_content(
                    prompt="Health check: respond with 'OK'",
                    max_tokens=10,
                    temperature=0.0
                ),
                timeout=self._config.health_check_timeout
            )
            
            latency_ms = (time.monotonic() - start_time) * 1000
            
            # Validate response
            if response and response.content and len(response.content) > 0:
                entry.health.update_healthy(latency_ms)
                logger.debug(f"Health check passed for '{name}': {latency_ms:.1f}ms")
            else:
                entry.health.update_unhealthy(
                    "Empty response",
                    self._config.health_check_consecutive_failures
                )
                logger.warning(f"Health check failed for '{name}': empty response")
            
        except asyncio.TimeoutError:
            entry.health.update_unhealthy(
                "Timeout",
                self._config.health_check_consecutive_failures
            )
            logger.warning(f"Health check timeout for '{name}'")
        
        except Exception as e:
            entry.health.update_unhealthy(
                str(e),
                self._config.health_check_consecutive_failures
            )
            logger.warning(f"Health check failed for '{name}': {e}")
        
        return entry.health
    
    async def check_all_health(self) -> Dict[str, ProviderHealth]:
        """Check health of all providers concurrently."""
        tasks = {
            name: self.check_provider_health(name)
            for name in self._providers.keys()
        }
        
        results = {}
        for name, task in tasks.items():
            try:
                results[name] = await task
            except Exception as e:
                logger.error(f"Health check error for '{name}': {e}")
                results[name] = ProviderHealth(
                    status=HealthStatus.UNKNOWN,
                    error_message=str(e)
                )
        
        return results
    
    async def start_health_checks(self) -> None:
        """Start background health check task."""
        if self._health_check_task is not None:
            logger.warning("Health checks already running")
            return
        
        self._shutdown = False
        self._health_check_task = asyncio.create_task(self._health_check_loop())
        logger.info("Started background health checks")
    
    async def stop_health_checks(self) -> None:
        """Stop background health check task."""
        self._shutdown = True
        
        if self._health_check_task is not None:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
            self._health_check_task = None
        
        logger.info("Stopped background health checks")
    
    async def _health_check_loop(self) -> None:
        """Background loop for periodic health checks."""
        while not self._shutdown:
            try:
                await self.check_all_health()
            except Exception as e:
                logger.error(f"Health check loop error: {e}")
            
            await asyncio.sleep(self._config.health_check_interval)
    
    # ========================================================================
    # Provider Selection
    # ========================================================================
    
    def _get_available_providers(self) -> List[ProviderEntry]:
        """Get list of available providers (enabled, healthy, circuit closed)."""
        available = []
        
        for entry in self._providers.values():
            # Check enabled
            if not entry.enabled:
                continue
            
            # Check circuit breaker
            if self._is_circuit_open(entry):
                continue
            
            # Check health (allow HEALTHY, DEGRADED, and UNKNOWN)
            if entry.health.status == HealthStatus.UNHEALTHY:
                continue
            
            available.append(entry)
        
        return available
    
    def _select_providers(self) -> List[ProviderEntry]:
        """Select providers based on configured strategy."""
        available = self._get_available_providers()
        
        if not available:
            # Fallback: return all enabled providers (even unhealthy/circuit-open)
            logger.warning("No healthy providers, falling back to all enabled")
            available = [e for e in self._providers.values() if e.enabled]
        
        if self._selection_strategy == SelectionStrategy.PRIORITY:
            return sorted(available, key=lambda e: e.priority)
        
        elif self._selection_strategy == SelectionStrategy.ROUND_ROBIN:
            # Rotate starting point
            n = len(available)
            if n == 0:
                return []
            idx = self._round_robin_index % n
            self._round_robin_index += 1
            return available[idx:] + available[:idx]
        
        elif self._selection_strategy == SelectionStrategy.WEIGHTED:
            # Shuffle with weights (Fisher-Yates weighted)
            weighted = list(available)
            random.shuffle(weighted)  # Base randomization
            # Sort by weight descending with randomness
            weighted.sort(
                key=lambda e: e.weight * random.random(),
                reverse=True
            )
            return weighted
        
        elif self._selection_strategy == SelectionStrategy.LATENCY:
            # Sort by latency (lowest first), unknown latency goes last
            def latency_key(e: ProviderEntry) -> float:
                if e.health.latency_ms is not None:
                    return e.health.latency_ms
                return float('inf')
            return sorted(available, key=latency_key)
        
        return available
    
    # ========================================================================
    # Retry Logic
    # ========================================================================
    
    def _calculate_retry_delay(self, attempt: int) -> float:
        """Calculate delay for retry with exponential backoff and jitter."""
        base_delay = self._config.retry_base_delay
        max_delay = self._config.retry_max_delay
        jitter = self._config.retry_jitter
        
        # Exponential backoff: delay = base * 2^attempt
        delay = base_delay * (2 ** attempt)
        delay = min(delay, max_delay)
        
        # Add jitter: ±jitter%
        jitter_amount = delay * jitter
        delay += random.uniform(-jitter_amount, jitter_amount)
        
        return max(0, delay)
    
    async def _try_provider(
        self,
        entry: ProviderEntry,
        prompt: str,
        max_tokens: int,
        temperature: float,
        **kwargs
    ) -> LLMResponse:
        """Try to generate content with a single provider."""
        start_time = time.monotonic()
        
        try:
            # Make the request with timeout
            response = await asyncio.wait_for(
                entry.provider.generate_content(
                    prompt=prompt,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    **kwargs
                ),
                timeout=self._config.request_timeout
            )
            
            latency_ms = (time.monotonic() - start_time) * 1000
            
            # Record success
            self._record_circuit_success(entry)
            self._metrics.record(
                provider=entry.name,
                success=True,
                latency_ms=latency_ms
            )
            
            # Add provider metadata to response
            response.provider = entry.name
            
            logger.debug(
                f"Provider '{entry.name}' succeeded in {latency_ms:.1f}ms"
            )
            
            return response
        
        except asyncio.TimeoutError as e:
            latency_ms = (time.monotonic() - start_time) * 1000
            self._record_circuit_failure(entry, e)
            self._metrics.record(
                provider=entry.name,
                success=False,
                latency_ms=latency_ms,
                error="Timeout"
            )
            logger.warning(f"Provider '{entry.name}' timed out after {latency_ms:.1f}ms")
            raise
        
        except Exception as e:
            latency_ms = (time.monotonic() - start_time) * 1000
            self._record_circuit_failure(entry, e)
            self._metrics.record(
                provider=entry.name,
                success=False,
                latency_ms=latency_ms,
                error=str(e)
            )
            logger.warning(f"Provider '{entry.name}' failed: {e}")
            raise
    
    # ========================================================================
    # Main Generation Method
    # ========================================================================
    
    async def generate(
        self,
        prompt: str,
        max_tokens: int = 1000,
        temperature: float = 0.7,
        preferred_provider: Optional[str] = None,
        **kwargs
    ) -> LLMResponse:
        """Generate content with automatic fallback.
        
        Tries providers in order based on selection strategy, falling back
        to next provider on failure. Implements retry logic with exponential
        backoff for transient failures.
        
        Args:
            prompt: The prompt to send
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            preferred_provider: Optional preferred provider to try first
            **kwargs: Additional provider-specific parameters
            
        Returns:
            LLMResponse from first successful provider
            
        Raises:
            AllProvidersFailedError: If all providers fail
        """
        if not self._providers:
            raise AllProvidersFailedError(
                errors={},
                message="No providers configured"
            )
        
        # Get ordered list of providers to try
        providers_to_try = self._select_providers()
        
        # If preferred provider specified and available, try it first
        if preferred_provider and preferred_provider in self._providers:
            preferred_entry = self._providers[preferred_provider]
            if preferred_entry.enabled:
                # Move preferred to front
                providers_to_try = [
                    preferred_entry
                ] + [p for p in providers_to_try if p.name != preferred_provider]
        
        if not providers_to_try:
            raise AllProvidersFailedError(
                errors={},
                message="No available providers (all disabled or unhealthy)"
            )
        
        errors: Dict[str, Exception] = {}
        
        for entry in providers_to_try:
            # Skip if circuit is open
            if self._is_circuit_open(entry):
                errors[entry.name] = CircuitOpenError(entry.name)
                continue
            
            # Try with retries
            for attempt in range(self._config.max_retries_per_provider + 1):
                try:
                    response = await self._try_provider(
                        entry=entry,
                        prompt=prompt,
                        max_tokens=max_tokens,
                        temperature=temperature,
                        **kwargs
                    )
                    
                    # Success - return response
                    logger.info(
                        f"Generated content with provider '{entry.name}' "
                        f"(attempt {attempt + 1})"
                    )
                    return response
                
                except RateLimitError as e:
                    # Rate limit - don't retry, move to next provider
                    errors[entry.name] = e
                    logger.warning(f"Rate limit for '{entry.name}', trying next")
                    break
                
                except Exception as e:
                    errors[entry.name] = e
                    
                    # Check if we should retry
                    if attempt < self._config.max_retries_per_provider:
                        delay = self._calculate_retry_delay(attempt)
                        logger.info(
                            f"Retrying '{entry.name}' in {delay:.2f}s "
                            f"(attempt {attempt + 2}/{self._config.max_retries_per_provider + 1})"
                        )
                        await asyncio.sleep(delay)
                    else:
                        logger.warning(
                            f"Provider '{entry.name}' exhausted retries, trying next"
                        )
        
        # All providers failed
        raise AllProvidersFailedError(errors=errors)
    
    # ========================================================================
    # Metrics & Status
    # ========================================================================
    
    def get_availability(self) -> float:
        """Get overall availability ratio."""
        return self._metrics.get_availability()
    
    def get_provider_availability(self, name: str) -> float:
        """Get availability for a specific provider."""
        return self._metrics.get_availability(name)
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get comprehensive metrics summary."""
        return self._metrics.get_summary()
    
    def get_status(self) -> Dict[str, Any]:
        """Get full chain status including all providers."""
        providers_status = {}
        
        for name, entry in self._providers.items():
            providers_status[name] = {
                "enabled": entry.enabled,
                "priority": entry.priority,
                "weight": entry.weight,
                "circuit_state": entry.circuit_state.state.value,
                "circuit_failures": entry.circuit_state.failure_count,
                "health_status": entry.health.status.value,
                "health_latency_ms": entry.health.latency_ms,
                "availability": self._metrics.get_availability(name),
            }
        
        overall_availability = self.get_availability()
        target_met = overall_availability >= self._config.target_availability
        
        return {
            "strategy": self._selection_strategy.value,
            "target_availability": self._config.target_availability,
            "current_availability": overall_availability,
            "target_met": target_met,
            "total_providers": len(self._providers),
            "available_providers": len(self._get_available_providers()),
            "health_checks_running": self._health_check_task is not None,
            "providers": providers_status,
            "metrics": self._metrics.get_summary(),
        }
    
    def meets_availability_target(self) -> bool:
        """Check if current availability meets target."""
        return self.get_availability() >= self._config.target_availability
    
    # ========================================================================
    # Context Manager
    # ========================================================================
    
    async def __aenter__(self) -> "ModelFallbackChain":
        """Async context manager entry."""
        await self.start_health_checks()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.stop_health_checks()


# ============================================================================
# Factory Function
# ============================================================================


def create_fallback_chain(
    providers: Dict[str, BaseLLMProvider],
    config: Optional[FallbackChainConfig] = None,
    strategy: SelectionStrategy = SelectionStrategy.PRIORITY,
    priorities: Optional[Dict[str, int]] = None,
    weights: Optional[Dict[str, float]] = None,
) -> ModelFallbackChain:
    """Factory function to create a configured fallback chain.
    
    Args:
        providers: Dict mapping provider names to instances
        config: Optional configuration
        strategy: Selection strategy
        priorities: Optional dict of provider priorities (lower = higher priority)
        weights: Optional dict of provider weights (higher = more likely)
        
    Returns:
        Configured ModelFallbackChain
        
    Example:
        chain = create_fallback_chain(
            providers={
                "openai": openai_provider,
                "anthropic": anthropic_provider,
                "ollama": ollama_provider,
            },
            priorities={"openai": 0, "anthropic": 1, "ollama": 2},
            strategy=SelectionStrategy.PRIORITY
        )
    """
    priorities = priorities or {}
    weights = weights or {}
    
    chain = ModelFallbackChain(config=config, selection_strategy=strategy)
    
    for name, provider in providers.items():
        chain.add_provider(
            name=name,
            provider=provider,
            priority=priorities.get(name, 99),
            weight=weights.get(name, 1.0),
            enabled=True
        )
    
    return chain
