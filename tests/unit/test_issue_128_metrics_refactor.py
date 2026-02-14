"""Unit tests for Issue #128 - FallbackChain Metrics Delegation Refactor.

Tests the specific changes made to fix pass-through delegation:
1. get_availability() - Now includes bounds checking
2. get_provider_availability() - Now validates unknown providers  
3. get_metrics_summary() - Now includes SLA computation and recommendations
4. get_sla_status() - New method for detailed SLA analysis
5. get_provider_rankings() - New method for provider comparison
6. get_recommendations() - New method for actionable insights

Author: Temidayo
Issue: #128 - FallbackChain Metrics Delegation Refactor
"""

import pytest
import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch
from dataclasses import dataclass

from threatsimgpt.llm.fallback_chain import (
    ModelFallbackChain,
    FallbackChainConfig,
    MetricsCollector,
    SelectionStrategy,
    HealthStatus,
    CircuitState,
)
from threatsimgpt.llm.base import BaseLLMProvider, LLMResponse


# =============================================================================
# FIXTURES
# =============================================================================

class MockProvider(BaseLLMProvider):
    """Mock LLM provider for testing."""
    
    def __init__(self, name: str = "mock"):
        self.name = name
        self.should_fail = False
        self.latency_ms = 100
    
    async def generate_content(self, prompt: str, **kwargs) -> LLMResponse:
        """Implement the abstract method from BaseLLMProvider."""
        if self.should_fail:
            raise Exception("Mock failure")
        return LLMResponse(
            content="Mock response",
            model="mock-model",
            provider=self.name,
            latency_ms=self.latency_ms
        )
    
    async def health_check(self) -> bool:
        return not self.should_fail


@pytest.fixture
def config():
    """Create a test configuration."""
    return FallbackChainConfig(
        target_availability=0.999,
        metrics_window_seconds=3600,
        circuit_failure_threshold=3,
    )


@pytest.fixture
def fallback_chain(config):
    """Create a FallbackChain with mock providers."""
    chain = ModelFallbackChain(config=config)
    
    # Add mock providers
    chain.add_provider("primary", MockProvider("primary"), priority=0)
    chain.add_provider("secondary", MockProvider("secondary"), priority=1)
    chain.add_provider("backup", MockProvider("backup"), priority=2)
    
    return chain


@pytest.fixture
def metrics_collector():
    """Create a MetricsCollector instance."""
    return MetricsCollector(window_seconds=3600, max_requests=1000)


# =============================================================================
# ISSUE #128: get_availability() TESTS
# =============================================================================

class TestGetAvailability:
    """Tests for Issue #128: get_availability() bounds checking."""
    
    def test_returns_valid_range(self, fallback_chain):
        """Test availability is between 0.0 and 1.0."""
        availability = fallback_chain.get_availability()
        
        assert 0.0 <= availability <= 1.0
    
    def test_returns_1_when_no_data(self, fallback_chain):
        """Test availability is 1.0 when no requests recorded."""
        availability = fallback_chain.get_availability()
        
        # No requests yet, should assume available
        assert availability == 1.0
    
    def test_reflects_recorded_metrics(self, fallback_chain):
        """Test availability reflects recorded successes/failures."""
        # Record some metrics directly
        fallback_chain._metrics.record("primary", success=True, latency_ms=100)
        fallback_chain._metrics.record("primary", success=True, latency_ms=100)
        fallback_chain._metrics.record("primary", success=False, latency_ms=100, error="test")
        
        availability = fallback_chain.get_availability()
        
        # 2 success, 1 failure = 66.67% availability
        assert 0.66 <= availability <= 0.67


# =============================================================================
# ISSUE #128: get_provider_availability() TESTS
# =============================================================================

class TestGetProviderAvailability:
    """Tests for Issue #128: get_provider_availability() validation."""
    
    def test_returns_valid_range(self, fallback_chain):
        """Test provider availability is between 0.0 and 1.0."""
        availability = fallback_chain.get_provider_availability("primary")
        
        assert 0.0 <= availability <= 1.0
    
    def test_returns_zero_for_unknown_provider(self, fallback_chain):
        """Test unknown provider returns 0.0 with warning."""
        availability = fallback_chain.get_provider_availability("nonexistent")
        
        assert availability == 0.0
    
    def test_returns_correct_per_provider_metrics(self, fallback_chain):
        """Test availability is calculated per provider."""
        # Primary: 100% success
        fallback_chain._metrics.record("primary", success=True, latency_ms=100)
        fallback_chain._metrics.record("primary", success=True, latency_ms=100)
        
        # Secondary: 50% success
        fallback_chain._metrics.record("secondary", success=True, latency_ms=100)
        fallback_chain._metrics.record("secondary", success=False, latency_ms=100)
        
        primary_avail = fallback_chain.get_provider_availability("primary")
        secondary_avail = fallback_chain.get_provider_availability("secondary")
        
        assert primary_avail == 1.0
        assert secondary_avail == 0.5


# =============================================================================
# ISSUE #128: get_metrics_summary() TESTS
# =============================================================================

class TestGetMetricsSummary:
    """Tests for Issue #128: get_metrics_summary() with SLA computation."""
    
    def test_includes_raw_metrics(self, fallback_chain):
        """Test summary includes original raw metrics."""
        summary = fallback_chain.get_metrics_summary()
        
        assert "overall" in summary
        assert "by_provider" in summary
    
    def test_includes_sla_status(self, fallback_chain):
        """Test summary includes SLA status section."""
        summary = fallback_chain.get_metrics_summary()
        
        assert "sla" in summary
        assert "target" in summary["sla"]
        assert "current" in summary["sla"]
        assert "target_met" in summary["sla"]
        assert "risk_level" in summary["sla"]
    
    def test_includes_provider_rankings(self, fallback_chain):
        """Test summary includes provider rankings."""
        summary = fallback_chain.get_metrics_summary()
        
        assert "provider_rankings" in summary
        assert isinstance(summary["provider_rankings"], list)
    
    def test_includes_recommendations(self, fallback_chain):
        """Test summary includes recommendations."""
        summary = fallback_chain.get_metrics_summary()
        
        assert "recommendations" in summary
        assert isinstance(summary["recommendations"], list)


# =============================================================================
# ISSUE #128: get_sla_status() TESTS (NEW METHOD)
# =============================================================================

class TestGetSLAStatus:
    """Tests for Issue #128: New get_sla_status() method."""
    
    def test_returns_target_and_current(self, fallback_chain):
        """Test SLA status includes target and current availability."""
        sla = fallback_chain.get_sla_status()
        
        assert "target" in sla
        assert "current" in sla
        assert sla["target"] == 0.999  # From config
    
    def test_returns_target_met_boolean(self, fallback_chain):
        """Test SLA status includes target_met flag."""
        sla = fallback_chain.get_sla_status()
        
        assert "target_met" in sla
        assert isinstance(sla["target_met"], bool)
    
    def test_returns_margin_calculation(self, fallback_chain):
        """Test SLA status includes margin calculation."""
        sla = fallback_chain.get_sla_status()
        
        assert "margin" in sla
        assert "margin_percentage" in sla
    
    def test_returns_risk_level(self, fallback_chain):
        """Test SLA status includes risk level assessment."""
        sla = fallback_chain.get_sla_status()
        
        assert "risk_level" in sla
        assert sla["risk_level"] in ["low", "medium", "high", "critical"]
    
    def test_returns_error_budget(self, fallback_chain):
        """Test SLA status includes error budget tracking."""
        sla = fallback_chain.get_sla_status()
        
        assert "error_budget" in sla
        assert "total" in sla["error_budget"]
        assert "used" in sla["error_budget"]
        assert "remaining" in sla["error_budget"]
        assert "remaining_percentage" in sla["error_budget"]
    
    def test_risk_level_critical_when_below_target(self, fallback_chain):
        """Test risk level is critical when significantly below target."""
        # Record many failures
        for _ in range(20):
            fallback_chain._metrics.record("primary", success=False, latency_ms=100)
        
        sla = fallback_chain.get_sla_status()
        
        assert sla["target_met"] is False
        assert sla["risk_level"] == "critical"
    
    def test_risk_level_low_when_above_target(self, fallback_chain):
        """Test risk level is low or medium when above target."""
        # Record all successes
        for _ in range(100):
            fallback_chain._metrics.record("primary", success=True, latency_ms=100)
        
        sla = fallback_chain.get_sla_status()
        
        assert sla["target_met"] is True
        # With 100% success rate and 99.9% target, margin is 0.001 (0.1%)
        # This is a tight margin, so risk level can be "medium"
        assert sla["risk_level"] in ["low", "medium"]


# =============================================================================
# ISSUE #128: get_provider_rankings() TESTS (NEW METHOD)
# =============================================================================

class TestGetProviderRankings:
    """Tests for Issue #128: New get_provider_rankings() method."""
    
    def test_returns_list_of_providers(self, fallback_chain):
        """Test rankings returns list of all providers."""
        rankings = fallback_chain.get_provider_rankings()
        
        assert isinstance(rankings, list)
        assert len(rankings) == 3  # primary, secondary, backup
    
    def test_each_provider_has_required_fields(self, fallback_chain):
        """Test each ranking entry has required fields."""
        rankings = fallback_chain.get_provider_rankings()
        
        required_fields = [
            "name", "enabled", "availability", "error_rate",
            "health_status", "circuit_state", "composite_score", "rank"
        ]
        
        for provider in rankings:
            for field in required_fields:
                assert field in provider, f"Missing field: {field}"
    
    def test_providers_sorted_by_composite_score(self, fallback_chain):
        """Test providers are sorted by composite score (descending)."""
        # Create different performance levels
        for _ in range(10):
            fallback_chain._metrics.record("primary", success=True, latency_ms=50)
            fallback_chain._metrics.record("secondary", success=True, latency_ms=200)
            fallback_chain._metrics.record("backup", success=False, latency_ms=500)
        
        rankings = fallback_chain.get_provider_rankings()
        
        scores = [p["composite_score"] for p in rankings]
        assert scores == sorted(scores, reverse=True)
    
    def test_rank_positions_assigned(self, fallback_chain):
        """Test rank positions are assigned correctly."""
        rankings = fallback_chain.get_provider_rankings()
        
        ranks = [p["rank"] for p in rankings]
        assert ranks == [1, 2, 3]


# =============================================================================
# ISSUE #128: get_recommendations() TESTS (NEW METHOD)
# =============================================================================

class TestGetRecommendations:
    """Tests for Issue #128: New get_recommendations() method."""
    
    def test_returns_list_of_strings(self, fallback_chain):
        """Test recommendations returns list of strings."""
        recommendations = fallback_chain.get_recommendations()
        
        assert isinstance(recommendations, list)
        assert all(isinstance(r, str) for r in recommendations)
    
    def test_provides_positive_message_when_healthy(self, fallback_chain):
        """Test positive message when all systems healthy."""
        # All successes
        for _ in range(100):
            fallback_chain._metrics.record("primary", success=True, latency_ms=100)
        
        recommendations = fallback_chain.get_recommendations()
        
        assert any("normally" in r.lower() or "met" in r.lower() for r in recommendations)
    
    def test_warns_when_sla_critical(self, fallback_chain):
        """Test warning when SLA is critical."""
        # All failures
        for _ in range(50):
            fallback_chain._metrics.record("primary", success=False, latency_ms=100)
        
        recommendations = fallback_chain.get_recommendations()
        
        assert any("critical" in r.lower() for r in recommendations)
    
    def test_warns_about_unhealthy_providers(self, fallback_chain):
        """Test warning about unhealthy providers."""
        # Mark a provider as unhealthy
        fallback_chain._providers["secondary"].health.status = HealthStatus.UNHEALTHY
        
        recommendations = fallback_chain.get_recommendations()
        
        assert any("unhealthy" in r.lower() for r in recommendations)
    
    def test_warns_about_open_circuits(self, fallback_chain):
        """Test warning about open circuit breakers."""
        # Open circuit for a provider
        fallback_chain._providers["backup"].circuit_state.state = CircuitState.OPEN
        
        recommendations = fallback_chain.get_recommendations()
        
        assert any("circuit" in r.lower() for r in recommendations)


# =============================================================================
# ISSUE #128: get_status() ENHANCEMENT TESTS
# =============================================================================

class TestGetStatusEnhanced:
    """Tests for Issue #128: Enhanced get_status() method."""
    
    @pytest.mark.asyncio
    async def test_includes_sla_risk_level(self, fallback_chain):
        """Test status includes SLA risk level."""
        status = await fallback_chain.get_status()
        
        assert "sla_risk_level" in status
        assert status["sla_risk_level"] in ["low", "medium", "high", "critical"]
    
    @pytest.mark.asyncio
    async def test_includes_error_budget(self, fallback_chain):
        """Test status includes error budget percentage."""
        status = await fallback_chain.get_status()
        
        assert "error_budget_remaining_pct" in status
    
    @pytest.mark.asyncio
    async def test_metrics_includes_sla_and_rankings(self, fallback_chain):
        """Test status metrics include SLA and rankings."""
        status = await fallback_chain.get_status()
        
        assert "metrics" in status
        assert "sla" in status["metrics"]
        assert "provider_rankings" in status["metrics"]
        assert "recommendations" in status["metrics"]


# =============================================================================
# ISSUE #128: meets_availability_target() TESTS
# =============================================================================

class TestMeetsAvailabilityTarget:
    """Tests for meets_availability_target() method."""
    
    def test_returns_boolean(self, fallback_chain):
        """Test returns boolean value."""
        result = fallback_chain.meets_availability_target()
        
        assert isinstance(result, bool)
    
    def test_true_when_above_target(self, fallback_chain):
        """Test returns True when above target."""
        # All successes
        for _ in range(100):
            fallback_chain._metrics.record("primary", success=True, latency_ms=100)
        
        assert fallback_chain.meets_availability_target() is True
    
    def test_false_when_below_target(self, fallback_chain):
        """Test returns False when below target."""
        # Many failures
        for _ in range(50):
            fallback_chain._metrics.record("primary", success=False, latency_ms=100)
        
        assert fallback_chain.meets_availability_target() is False


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Edge case tests."""
    
    def test_empty_chain_availability(self):
        """Test availability with no providers."""
        chain = ModelFallbackChain()
        
        availability = chain.get_availability()
        
        assert availability == 1.0  # Assume available when no data
    
    def test_sla_status_with_zero_target(self):
        """Test SLA status handles zero target gracefully."""
        config = FallbackChainConfig(target_availability=0.0)
        chain = ModelFallbackChain(config=config)
        
        sla = chain.get_sla_status()
        
        # Should not raise division by zero
        assert "margin_percentage" in sla
    
    def test_rankings_with_no_metrics(self, fallback_chain):
        """Test rankings work with no recorded metrics."""
        rankings = fallback_chain.get_provider_rankings()
        
        # Should still return providers
        assert len(rankings) == 3
        
        # All should have equal composite scores initially
        scores = [p["composite_score"] for p in rankings]
        # Allow small floating point differences
        assert max(scores) - min(scores) < 0.1
    
    def test_recommendations_always_returns_something(self, fallback_chain):
        """Test recommendations never returns empty list."""
        recommendations = fallback_chain.get_recommendations()
        
        assert len(recommendations) > 0


# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
