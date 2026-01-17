"""Unit tests for Model Fallback Chain.

Tests the ModelFallbackChain implementation for Issue #34.
Covers circuit breaker, health checks, selection strategies, and availability tracking.
"""

import asyncio
import pytest
import time
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

from threatsimgpt.llm.fallback_chain import (
    ModelFallbackChain,
    FallbackChainConfig,
    SelectionStrategy,
    CircuitState,
    HealthStatus,
    AllProvidersFailedError,
    CircuitOpenError,
    ProviderUnavailableError,
    MetricsCollector,
    create_fallback_chain,
)
from threatsimgpt.llm.base import BaseLLMProvider, LLMResponse
from threatsimgpt.llm.exceptions import RateLimitError


# ============================================================================
# Test Fixtures
# ============================================================================


class MockProvider(BaseLLMProvider):
    """Mock LLM provider for testing."""
    
    def __init__(
        self,
        name: str = "mock",
        should_fail: bool = False,
        fail_count: int = 0,
        latency_ms: float = 100.0,
        response_content: str = "Mock response"
    ):
        super().__init__({"api_key": "test-key", "model": "test-model"})
        self.name = name
        self.should_fail = should_fail
        self.fail_count = fail_count
        self.latency_ms = latency_ms
        self.response_content = response_content
        self.call_count = 0
        self.calls: List[Dict[str, Any]] = []
        self._failures_remaining = fail_count
    
    async def generate_content(
        self,
        prompt: str,
        max_tokens: int = 1000,
        temperature: float = 0.7,
        **kwargs
    ) -> LLMResponse:
        self.call_count += 1
        self.calls.append({
            "prompt": prompt,
            "max_tokens": max_tokens,
            "temperature": temperature,
            **kwargs
        })
        
        # Simulate latency
        await asyncio.sleep(self.latency_ms / 1000)
        
        # Handle failure modes
        if self.should_fail:
            raise RuntimeError(f"Provider {self.name} failed")
        
        if self._failures_remaining > 0:
            self._failures_remaining -= 1
            raise RuntimeError(f"Provider {self.name} temporary failure")
        
        return LLMResponse(
            content=self.response_content,
            provider=self.name,
            model="test-model"
        )


class RateLimitedProvider(MockProvider):
    """Provider that raises rate limit errors."""
    
    async def generate_content(self, prompt: str, **kwargs) -> LLMResponse:
        self.call_count += 1
        raise RateLimitError("Rate limit exceeded")


class TimeoutProvider(MockProvider):
    """Provider that times out."""
    
    async def generate_content(self, prompt: str, **kwargs) -> LLMResponse:
        self.call_count += 1
        await asyncio.sleep(60)  # Long timeout
        return LLMResponse(content="Never reached", provider=self.name, model="test")


@pytest.fixture
def config():
    """Create test configuration with short timeouts."""
    return FallbackChainConfig(
        circuit_failure_threshold=3,
        circuit_recovery_timeout=1.0,
        circuit_half_open_max_calls=2,
        max_retries_per_provider=1,
        retry_base_delay=0.01,
        retry_max_delay=0.1,
        retry_jitter=0.0,
        health_check_interval=0.5,
        health_check_timeout=1.0,
        health_check_consecutive_failures=2,
        request_timeout=2.0,
        target_availability=0.999,
        metrics_window_seconds=60,
        max_tracked_requests=100,
    )


@pytest.fixture
def chain(config):
    """Create test fallback chain."""
    return ModelFallbackChain(config=config)


@pytest.fixture
def mock_provider():
    """Create a mock provider."""
    return MockProvider(name="mock1")


@pytest.fixture
def failing_provider():
    """Create a failing provider."""
    return MockProvider(name="failing", should_fail=True)


# ============================================================================
# Basic Chain Tests
# ============================================================================


class TestModelFallbackChainBasic:
    """Test basic chain functionality."""
    
    def test_init_default_config(self):
        """Test initialization with default config."""
        chain = ModelFallbackChain()
        assert chain._config is not None
        assert chain._selection_strategy == SelectionStrategy.PRIORITY
        assert len(chain._providers) == 0
    
    def test_init_custom_config(self, config):
        """Test initialization with custom config."""
        chain = ModelFallbackChain(
            config=config,
            selection_strategy=SelectionStrategy.ROUND_ROBIN
        )
        assert chain._config == config
        assert chain._selection_strategy == SelectionStrategy.ROUND_ROBIN
    
    def test_add_provider(self, chain, mock_provider):
        """Test adding a provider."""
        chain.add_provider("test", mock_provider, priority=1, weight=2.0)
        
        assert "test" in chain._providers
        entry = chain._providers["test"]
        assert entry.name == "test"
        assert entry.provider == mock_provider
        assert entry.priority == 1
        assert entry.weight == 2.0
        assert entry.enabled is True
    
    def test_remove_provider(self, chain, mock_provider):
        """Test removing a provider."""
        chain.add_provider("test", mock_provider)
        assert chain.remove_provider("test") is True
        assert "test" not in chain._providers
    
    def test_remove_nonexistent_provider(self, chain):
        """Test removing a provider that doesn't exist."""
        assert chain.remove_provider("nonexistent") is False
    
    def test_set_provider_enabled(self, chain, mock_provider):
        """Test enabling/disabling a provider."""
        chain.add_provider("test", mock_provider)
        
        chain.set_provider_enabled("test", False)
        assert chain._providers["test"].enabled is False
        
        chain.set_provider_enabled("test", True)
        assert chain._providers["test"].enabled is True
    
    def test_get_provider_names(self, chain):
        """Test getting provider names."""
        chain.add_provider("p1", MockProvider(name="p1"))
        chain.add_provider("p2", MockProvider(name="p2"))
        
        names = chain.get_provider_names()
        assert names == ["p1", "p2"]


# ============================================================================
# Generation Tests
# ============================================================================


class TestGeneration:
    """Test content generation with fallback."""
    
    @pytest.mark.asyncio
    async def test_generate_single_provider_success(self, chain, mock_provider):
        """Test successful generation with single provider."""
        chain.add_provider("mock", mock_provider)
        
        response = await chain.generate("Test prompt")
        
        assert response.content == "Mock response"
        assert response.provider == "mock"
        assert mock_provider.call_count == 1
    
    @pytest.mark.asyncio
    async def test_generate_fallback_on_failure(self, chain, config):
        """Test fallback to second provider when first fails."""
        failing = MockProvider(name="failing", should_fail=True)
        working = MockProvider(name="working", response_content="Working response")
        
        chain.add_provider("failing", failing, priority=0)
        chain.add_provider("working", working, priority=1)
        
        response = await chain.generate("Test prompt")
        
        assert response.content == "Working response"
        assert response.provider == "working"
        assert failing.call_count >= 1  # At least one attempt
        assert working.call_count == 1
    
    @pytest.mark.asyncio
    async def test_generate_all_providers_fail(self, chain):
        """Test error when all providers fail."""
        chain.add_provider("fail1", MockProvider(name="fail1", should_fail=True))
        chain.add_provider("fail2", MockProvider(name="fail2", should_fail=True))
        
        with pytest.raises(AllProvidersFailedError) as exc_info:
            await chain.generate("Test prompt")
        
        assert "fail1" in exc_info.value.errors
        assert "fail2" in exc_info.value.errors
    
    @pytest.mark.asyncio
    async def test_generate_no_providers(self, chain):
        """Test error when no providers configured."""
        with pytest.raises(AllProvidersFailedError) as exc_info:
            await chain.generate("Test prompt")
        
        assert "No providers configured" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_generate_preferred_provider(self, chain):
        """Test preferred provider is tried first."""
        p1 = MockProvider(name="p1", response_content="P1 response")
        p2 = MockProvider(name="p2", response_content="P2 response")
        
        chain.add_provider("p1", p1, priority=0)
        chain.add_provider("p2", p2, priority=1)
        
        # Prefer p2 even though p1 has higher priority
        response = await chain.generate("Test", preferred_provider="p2")
        
        assert response.content == "P2 response"
        assert p2.call_count == 1
        assert p1.call_count == 0
    
    @pytest.mark.asyncio
    async def test_generate_with_retries(self, chain, config):
        """Test retry logic on transient failures."""
        # Provider fails first time, succeeds second time
        provider = MockProvider(name="retry", fail_count=1)
        chain.add_provider("retry", provider)
        
        response = await chain.generate("Test prompt")
        
        assert response.content == "Mock response"
        assert provider.call_count == 2  # Initial + 1 retry
    
    @pytest.mark.asyncio
    async def test_generate_rate_limit_no_retry(self, chain):
        """Test that rate limit errors don't trigger retry, but fallback."""
        rate_limited = RateLimitedProvider(name="rate_limited")
        working = MockProvider(name="working")
        
        chain.add_provider("rate_limited", rate_limited, priority=0)
        chain.add_provider("working", working, priority=1)
        
        response = await chain.generate("Test prompt")
        
        # Should fallback to working provider without retrying rate limited
        assert response.provider == "working"
        assert rate_limited.call_count == 1


# ============================================================================
# Circuit Breaker Tests
# ============================================================================


class TestCircuitBreaker:
    """Test circuit breaker functionality."""
    
    @pytest.mark.asyncio
    async def test_circuit_opens_after_threshold(self, chain, config):
        """Test circuit opens after failure threshold."""
        failing = MockProvider(name="failing", should_fail=True)
        chain.add_provider("failing", failing)
        
        # Exhaust retries to trigger circuit breaker
        for _ in range(config.circuit_failure_threshold + 1):
            try:
                await chain.generate("Test")
            except AllProvidersFailedError:
                pass
        
        state = chain.get_circuit_state("failing")
        assert state["state"] == CircuitState.OPEN.value
    
    @pytest.mark.asyncio
    async def test_circuit_blocks_requests(self, chain, config):
        """Test that open circuit blocks requests."""
        failing = MockProvider(name="failing", should_fail=True)
        chain.add_provider("failing", failing)
        
        # Open the circuit
        for _ in range(config.circuit_failure_threshold + 2):
            try:
                await chain.generate("Test")
            except AllProvidersFailedError:
                pass
        
        initial_calls = failing.call_count
        
        # Try again - should not call provider
        try:
            await chain.generate("Test")
        except AllProvidersFailedError as e:
            assert isinstance(e.errors.get("failing"), CircuitOpenError)
        
        # Call count should not increase
        assert failing.call_count == initial_calls
    
    @pytest.mark.asyncio
    async def test_circuit_recovery_after_timeout(self, chain, config):
        """Test circuit transitions to half-open after timeout."""
        failing = MockProvider(name="failing", should_fail=True)
        working = MockProvider(name="working")
        chain.add_provider("failing", failing, priority=0)
        chain.add_provider("working", working, priority=1)
        
        # Open the circuit
        for _ in range(config.circuit_failure_threshold + 2):
            try:
                await chain.generate("Test")
            except AllProvidersFailedError:
                pass
        
        assert chain.get_circuit_state("failing")["state"] == CircuitState.OPEN.value
        
        # Wait for recovery timeout
        await asyncio.sleep(config.circuit_recovery_timeout + 0.1)
        
        # Now the circuit should transition to half-open on next check (async)
        await chain._is_circuit_open(chain._providers["failing"])
        assert chain.get_circuit_state("failing")["state"] == CircuitState.HALF_OPEN.value
    
    @pytest.mark.asyncio
    async def test_reset_circuit(self, chain):
        """Test manual circuit reset."""
        provider = MockProvider(name="test")
        chain.add_provider("test", provider)
        
        # Simulate failures
        entry = chain._providers["test"]
        for _ in range(5):
            entry.circuit_state.record_failure()
        entry.circuit_state.state = CircuitState.OPEN
        
        assert await chain.reset_circuit("test") is True
        assert chain.get_circuit_state("test")["state"] == CircuitState.CLOSED.value
        assert chain.get_circuit_state("test")["failure_count"] == 0


# ============================================================================
# Health Check Tests
# ============================================================================


class TestHealthChecks:
    """Test health check functionality."""
    
    @pytest.mark.asyncio
    async def test_health_check_healthy_provider(self, chain, mock_provider):
        """Test health check for healthy provider."""
        chain.add_provider("healthy", mock_provider)
        
        health = await chain.check_provider_health("healthy")
        
        assert health.status == HealthStatus.HEALTHY
        assert health.latency_ms is not None
        assert health.latency_ms > 0
        assert health.error_message is None
    
    @pytest.mark.asyncio
    async def test_health_check_failing_provider(self, chain, failing_provider):
        """Test health check for failing provider."""
        chain.add_provider("failing", failing_provider)
        
        health = await chain.check_provider_health("failing")
        
        # First failure -> DEGRADED
        assert health.status in [HealthStatus.DEGRADED, HealthStatus.UNHEALTHY]
        assert health.error_message is not None
    
    @pytest.mark.asyncio
    async def test_health_check_nonexistent_provider(self, chain):
        """Test health check for nonexistent provider."""
        health = await chain.check_provider_health("nonexistent")
        
        assert health.status == HealthStatus.UNKNOWN
        assert "not found" in health.error_message.lower()
    
    @pytest.mark.asyncio
    async def test_health_check_all(self, chain):
        """Test checking health of all providers."""
        chain.add_provider("p1", MockProvider(name="p1"))
        chain.add_provider("p2", MockProvider(name="p2"))
        
        results = await chain.check_all_health()
        
        assert "p1" in results
        assert "p2" in results
        assert results["p1"].status == HealthStatus.HEALTHY
        assert results["p2"].status == HealthStatus.HEALTHY
    
    @pytest.mark.asyncio
    async def test_health_check_timeout(self, chain, config):
        """Test health check timeout."""
        slow = TimeoutProvider(name="slow")
        chain.add_provider("slow", slow)
        
        health = await chain.check_provider_health("slow")
        
        assert health.status in [HealthStatus.DEGRADED, HealthStatus.UNHEALTHY]
        assert "timeout" in health.error_message.lower()
    
    @pytest.mark.asyncio
    async def test_background_health_checks(self, chain, config):
        """Test background health check task."""
        provider = MockProvider(name="test")
        chain.add_provider("test", provider)
        
        await chain.start_health_checks()
        
        # Wait for at least one health check cycle
        await asyncio.sleep(config.health_check_interval + 0.2)
        
        # Health should have been checked
        assert provider.call_count >= 1
        
        await chain.stop_health_checks()


# ============================================================================
# Selection Strategy Tests
# ============================================================================


class TestSelectionStrategies:
    """Test provider selection strategies."""
    
    @pytest.mark.asyncio
    async def test_priority_strategy(self, config):
        """Test priority-based selection."""
        chain = ModelFallbackChain(
            config=config,
            selection_strategy=SelectionStrategy.PRIORITY
        )
        
        chain.add_provider("low", MockProvider(name="low"), priority=2)
        chain.add_provider("high", MockProvider(name="high"), priority=0)
        chain.add_provider("mid", MockProvider(name="mid"), priority=1)
        
        selected = await chain._select_providers()
        names = [p.name for p in selected]
        
        assert names == ["high", "mid", "low"]
    
    @pytest.mark.asyncio
    async def test_round_robin_strategy(self, config):
        """Test round-robin selection."""
        chain = ModelFallbackChain(
            config=config,
            selection_strategy=SelectionStrategy.ROUND_ROBIN
        )
        
        chain.add_provider("p1", MockProvider(name="p1"))
        chain.add_provider("p2", MockProvider(name="p2"))
        chain.add_provider("p3", MockProvider(name="p3"))
        
        # Get selections and check rotation
        first = await chain._select_providers()
        second = await chain._select_providers()
        third = await chain._select_providers()
        
        # Each should start with different provider
        assert first[0].name != second[0].name
        assert second[0].name != third[0].name
    
    @pytest.mark.asyncio
    async def test_latency_strategy(self, config):
        """Test latency-based selection."""
        chain = ModelFallbackChain(
            config=config,
            selection_strategy=SelectionStrategy.LATENCY
        )
        
        # Add providers and set their health latencies
        p1 = MockProvider(name="slow")
        p2 = MockProvider(name="fast")
        p3 = MockProvider(name="medium")
        
        chain.add_provider("slow", p1)
        chain.add_provider("fast", p2)
        chain.add_provider("medium", p3)
        
        # Simulate health check results
        chain._providers["slow"].health.latency_ms = 500.0
        chain._providers["fast"].health.latency_ms = 50.0
        chain._providers["medium"].health.latency_ms = 200.0
        chain._providers["slow"].health.status = HealthStatus.HEALTHY
        chain._providers["fast"].health.status = HealthStatus.HEALTHY
        chain._providers["medium"].health.status = HealthStatus.HEALTHY
        
        selected = await chain._select_providers()
        names = [p.name for p in selected]
        
        assert names == ["fast", "medium", "slow"]
    
    @pytest.mark.asyncio
    async def test_excludes_disabled_providers(self, chain):
        """Test that disabled providers are excluded."""
        chain.add_provider("enabled", MockProvider(name="enabled"))
        chain.add_provider("disabled", MockProvider(name="disabled"))
        chain.set_provider_enabled("disabled", False)
        
        available = await chain._get_available_providers()
        names = [p.name for p in available]
        
        assert "enabled" in names
        assert "disabled" not in names
    
    @pytest.mark.asyncio
    async def test_excludes_unhealthy_providers(self, chain):
        """Test that unhealthy providers are excluded."""
        chain.add_provider("healthy", MockProvider(name="healthy"))
        chain.add_provider("unhealthy", MockProvider(name="unhealthy"))
        
        chain._providers["healthy"].health.status = HealthStatus.HEALTHY
        chain._providers["unhealthy"].health.status = HealthStatus.UNHEALTHY
        
        available = await chain._get_available_providers()
        names = [p.name for p in available]
        
        assert "healthy" in names
        assert "unhealthy" not in names


# ============================================================================
# Metrics Tests
# ============================================================================


class TestMetrics:
    """Test metrics collection and availability tracking."""
    
    def test_metrics_collector_record(self):
        """Test recording metrics."""
        collector = MetricsCollector()
        
        collector.record("p1", success=True, latency_ms=100.0)
        collector.record("p1", success=False, latency_ms=50.0, error="Test error")
        
        assert collector.get_request_count("p1") == 2
        assert collector.get_request_count() == 2
    
    def test_metrics_availability(self):
        """Test availability calculation."""
        collector = MetricsCollector()
        
        # 8 successes, 2 failures = 80% availability
        for _ in range(8):
            collector.record("p1", success=True, latency_ms=100.0)
        for _ in range(2):
            collector.record("p1", success=False, latency_ms=100.0)
        
        availability = collector.get_availability("p1")
        assert 0.79 <= availability <= 0.81
    
    def test_metrics_latency_percentile(self):
        """Test latency percentile calculation."""
        collector = MetricsCollector()
        
        # Record latencies: 100, 200, 300, 400, 500
        for latency in [100, 200, 300, 400, 500]:
            collector.record("p1", success=True, latency_ms=float(latency))
        
        p50 = collector.get_latency_percentile(0.50, "p1")
        p95 = collector.get_latency_percentile(0.95, "p1")
        
        assert p50 is not None
        assert p95 is not None
        assert p95 >= p50
    
    def test_metrics_summary(self):
        """Test metrics summary."""
        collector = MetricsCollector()
        
        collector.record("p1", success=True, latency_ms=100.0)
        collector.record("p2", success=True, latency_ms=200.0)
        
        summary = collector.get_summary()
        
        assert "overall" in summary
        assert "by_provider" in summary
        assert "p1" in summary["by_provider"]
        assert "p2" in summary["by_provider"]
    
    @pytest.mark.asyncio
    async def test_chain_availability_tracking(self, chain, config):
        """Test chain-level availability tracking."""
        working = MockProvider(name="working")
        chain.add_provider("working", working)
        
        # Generate some successful requests
        for _ in range(10):
            await chain.generate("Test")
        
        availability = chain.get_availability()
        assert availability == 1.0  # All successful
    
    @pytest.mark.asyncio
    async def test_chain_meets_availability_target(self, chain):
        """Test availability target check."""
        working = MockProvider(name="working")
        chain.add_provider("working", working)
        
        # Initially no data
        assert chain.meets_availability_target() is True  # No data = assume OK
        
        # Generate requests
        for _ in range(10):
            await chain.generate("Test")
        
        assert chain.meets_availability_target() is True


# ============================================================================
# Status & Introspection Tests
# ============================================================================


class TestStatus:
    """Test status and introspection methods."""
    
    @pytest.mark.asyncio
    async def test_get_status(self, chain):
        """Test getting full chain status."""
        chain.add_provider("p1", MockProvider(name="p1"), priority=0)
        chain.add_provider("p2", MockProvider(name="p2"), priority=1)
        
        await chain.generate("Test")
        
        status = await chain.get_status()
        
        assert status["strategy"] == SelectionStrategy.PRIORITY.value
        assert status["total_providers"] == 2
        assert "p1" in status["providers"]
        assert "p2" in status["providers"]
        assert "metrics" in status
    
    def test_get_circuit_state(self, chain):
        """Test getting circuit state."""
        chain.add_provider("test", MockProvider(name="test"))
        
        state = chain.get_circuit_state("test")
        
        assert state is not None
        assert state["state"] == CircuitState.CLOSED.value
        assert state["failure_count"] == 0
    
    def test_get_circuit_state_nonexistent(self, chain):
        """Test getting circuit state for nonexistent provider."""
        state = chain.get_circuit_state("nonexistent")
        assert state is None


# ============================================================================
# Factory Function Tests
# ============================================================================


class TestFactory:
    """Test factory function."""
    
    def test_create_fallback_chain_basic(self):
        """Test basic chain creation."""
        providers = {
            "p1": MockProvider(name="p1"),
            "p2": MockProvider(name="p2"),
        }
        
        chain = create_fallback_chain(providers)
        
        assert len(chain._providers) == 2
        assert "p1" in chain._providers
        assert "p2" in chain._providers
    
    def test_create_fallback_chain_with_priorities(self):
        """Test chain creation with priorities."""
        providers = {
            "low": MockProvider(name="low"),
            "high": MockProvider(name="high"),
        }
        priorities = {"low": 10, "high": 1}
        
        chain = create_fallback_chain(providers, priorities=priorities)
        
        assert chain._providers["low"].priority == 10
        assert chain._providers["high"].priority == 1
    
    def test_create_fallback_chain_with_weights(self):
        """Test chain creation with weights."""
        providers = {
            "heavy": MockProvider(name="heavy"),
            "light": MockProvider(name="light"),
        }
        weights = {"heavy": 5.0, "light": 1.0}
        
        chain = create_fallback_chain(providers, weights=weights)
        
        assert chain._providers["heavy"].weight == 5.0
        assert chain._providers["light"].weight == 1.0
    
    def test_create_fallback_chain_with_strategy(self):
        """Test chain creation with custom strategy."""
        chain = create_fallback_chain(
            providers={"p1": MockProvider(name="p1")},
            strategy=SelectionStrategy.ROUND_ROBIN
        )
        
        assert chain._selection_strategy == SelectionStrategy.ROUND_ROBIN


# ============================================================================
# Context Manager Tests
# ============================================================================


class TestContextManager:
    """Test async context manager functionality."""
    
    @pytest.mark.asyncio
    async def test_context_manager_starts_health_checks(self, config):
        """Test that context manager starts health checks."""
        chain = ModelFallbackChain(config=config)
        chain.add_provider("test", MockProvider(name="test"))
        
        async with chain:
            assert chain._health_check_task is not None
        
        # After exit, health checks should be stopped
        assert chain._health_check_task is None
    
    @pytest.mark.asyncio
    async def test_context_manager_cleanup_on_exception(self, config):
        """Test cleanup happens even on exception."""
        chain = ModelFallbackChain(config=config)
        chain.add_provider("test", MockProvider(name="test"))
        
        try:
            async with chain:
                raise RuntimeError("Test exception")
        except RuntimeError:
            pass
        
        # Health checks should still be stopped
        assert chain._health_check_task is None


# ============================================================================
# Retry Logic Tests
# ============================================================================


class TestRetryLogic:
    """Test retry delay calculation."""
    
    def test_retry_delay_exponential_backoff(self, chain):
        """Test exponential backoff calculation."""
        chain._config.retry_base_delay = 1.0
        chain._config.retry_jitter = 0.0  # No jitter for predictable tests
        chain._config.retry_max_delay = 100.0
        
        delay0 = chain._calculate_retry_delay(0)  # 1 * 2^0 = 1
        delay1 = chain._calculate_retry_delay(1)  # 1 * 2^1 = 2
        delay2 = chain._calculate_retry_delay(2)  # 1 * 2^2 = 4
        
        assert 0.9 <= delay0 <= 1.1
        assert 1.9 <= delay1 <= 2.1
        assert 3.9 <= delay2 <= 4.1
    
    def test_retry_delay_max_cap(self, chain):
        """Test that delay is capped at max."""
        chain._config.retry_base_delay = 1.0
        chain._config.retry_jitter = 0.0
        chain._config.retry_max_delay = 5.0
        
        delay10 = chain._calculate_retry_delay(10)  # Would be 1024 without cap
        
        assert delay10 <= 5.0


# ============================================================================
# Edge Case Tests
# ============================================================================


class TestEdgeCases:
    """Test edge cases and boundary conditions."""
    
    @pytest.mark.asyncio
    async def test_empty_response_handling(self, chain):
        """Test handling of empty responses."""
        class EmptyProvider(MockProvider):
            async def generate_content(self, prompt: str, **kwargs) -> LLMResponse:
                self.call_count += 1
                return LLMResponse(content="", provider=self.name, model="test")
        
        empty = EmptyProvider(name="empty")
        working = MockProvider(name="working")
        
        chain.add_provider("empty", empty)
        chain.add_provider("working", working)
        
        # Empty response should be accepted (not necessarily an error)
        response = await chain.generate("Test")
        assert response is not None
    
    @pytest.mark.asyncio
    async def test_concurrent_requests(self, chain):
        """Test handling concurrent requests."""
        provider = MockProvider(name="test", latency_ms=50)
        chain.add_provider("test", provider)
        
        # Fire 10 concurrent requests
        tasks = [chain.generate(f"Prompt {i}") for i in range(10)]
        responses = await asyncio.gather(*tasks)
        
        assert len(responses) == 10
        assert provider.call_count == 10
    
    @pytest.mark.asyncio
    async def test_all_providers_disabled(self, chain):
        """Test error when all providers are disabled."""
        chain.add_provider("p1", MockProvider(name="p1"))
        chain.add_provider("p2", MockProvider(name="p2"))
        
        chain.set_provider_enabled("p1", False)
        chain.set_provider_enabled("p2", False)
        
        with pytest.raises(AllProvidersFailedError) as exc_info:
            await chain.generate("Test")
        
        assert "No available providers" in str(exc_info.value)
    
    def test_metrics_empty_window(self):
        """Test metrics with no data."""
        collector = MetricsCollector()
        
        assert collector.get_availability() == 1.0  # No data = assume available
        assert collector.get_latency_percentile(0.95) is None
        assert collector.get_request_count() == 0


# ============================================================================
# Integration-style Tests
# ============================================================================


class TestIntegration:
    """Integration-style tests simulating real usage patterns."""
    
    @pytest.mark.asyncio
    async def test_realistic_failover_scenario(self, config):
        """Test a realistic failover scenario."""
        # Primary provider fails, secondary takes over
        primary = MockProvider(name="primary", should_fail=True)
        secondary = MockProvider(name="secondary", response_content="Secondary response")
        tertiary = MockProvider(name="tertiary", response_content="Tertiary response")
        
        chain = ModelFallbackChain(config=config, selection_strategy=SelectionStrategy.PRIORITY)
        chain.add_provider("primary", primary, priority=0)
        chain.add_provider("secondary", secondary, priority=1)
        chain.add_provider("tertiary", tertiary, priority=2)
        
        # First request should fail over to secondary
        response1 = await chain.generate("Request 1")
        assert response1.provider == "secondary"
        
        # After circuit opens for primary, subsequent requests go directly to secondary
        for _ in range(5):
            response = await chain.generate("Request")
            assert response.provider == "secondary"
        
        # Check that primary circuit is open
        assert chain.get_circuit_state("primary")["state"] == CircuitState.OPEN.value
    
    @pytest.mark.asyncio
    async def test_recovery_after_circuit_timeout(self, config):
        """Test full recovery cycle after circuit timeout."""
        # Provider fails, circuit opens, timeout passes, provider recovers
        call_count = [0]
        
        class RecoveringProvider(MockProvider):
            async def generate_content(self, prompt: str, **kwargs) -> LLMResponse:
                call_count[0] += 1
                if call_count[0] <= 3:
                    raise RuntimeError("Temporary failure")
                return LLMResponse(content="Recovered", provider=self.name, model="test")
        
        provider = RecoveringProvider(name="recovering")
        chain = ModelFallbackChain(config=config)
        chain.add_provider("recovering", provider)
        
        # Trigger circuit open
        for _ in range(4):
            try:
                await chain.generate("Test")
            except AllProvidersFailedError:
                pass
        
        assert chain.get_circuit_state("recovering")["state"] == CircuitState.OPEN.value
        
        # Wait for recovery timeout
        await asyncio.sleep(config.circuit_recovery_timeout + 0.1)
        
        # Now provider has "recovered" (call_count > 3)
        response = await chain.generate("Test")
        assert response.content == "Recovered"
