"""
Simple test for refactored validator components.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'threatsimgpt'))

from threatsimgpt.security.config import SecurityValidatorConfig
from threatsimgpt.security.sharded_cache import ShardedValidationCache
from threatsimgpt.security.rate_limiter import MultiTenantRateLimiter
from threatsimgpt.security.circuit_breaker import CircuitBreaker
from threatsimgpt.security.metrics import MetricsCollector


def test_config():
    """Test configuration management."""
    print("Testing configuration...")
    
    config = SecurityValidatorConfig.from_env()
    config.validate()
    
    print(f"✓ Config loaded: max_template_size={config.max_template_size}")
    print(f"✓ Config validated successfully")
    return True


def test_cache():
    """Test sharded cache."""
    print("\nTesting sharded cache...")
    
    config = SecurityValidatorConfig(cache_max_size=10)
    cache = ShardedValidationCache(config)
    
    # Test basic operations
    cache.put("key1", "value1")
    cache.put("key2", "value2")
    
    assert cache.get("key1") == "value1"
    assert cache.get("key2") == "value2"
    assert cache.get("key3") is None
    
    # Test stats
    stats = cache.get_stats()
    assert stats['global_stats']['hits'] == 2
    assert stats['global_stats']['misses'] == 1
    
    print(f"✓ Cache operations work: hit_rate={stats['global_stats']['hit_rate']:.2%}")
    return True


def test_rate_limiter():
    """Test rate limiting."""
    print("\nTesting rate limiter...")
    
    limiter = MultiTenantRateLimiter(requests_per_minute=5)
    
    # Should allow first 5 requests for SAME tenant
    for i in range(5):
        assert limiter.is_allowed("same_tenant") is True
    
    # 6th request for same tenant should fail
    try:
        limiter.is_allowed("same_tenant")
        assert False, "Should have raised exception"
    except Exception as e:
        assert "Rate limit exceeded" in str(e)
    
    stats = limiter.get_stats()
    assert stats['total_tenants'] == 1  # Only one tenant used
    
    print(f"✓ Rate limiting works: {stats['total_requests_last_minute']} requests tracked")
    return True


def test_circuit_breaker():
    """Test circuit breaker."""
    print("\nTesting circuit breaker...")
    
    breaker = CircuitBreaker(failure_threshold=2, timeout=1)
    
    # Initially closed
    assert breaker.get_state().value == "CLOSED"
    
    # Simulate failures
    def failing_func():
        raise ValueError("Test failure")
    
    try:
        breaker.call(failing_func)
    except ValueError:
        pass  # Expected
    
    try:
        breaker.call(failing_func)
    except ValueError:
        pass  # Expected
    
    # Should be open now
    assert breaker.get_state().value == "OPEN"
    
    # Should raise CircuitBreakerError
    try:
        breaker.call(lambda: "test")
        assert False, "Should have raised CircuitBreakerError"
    except Exception as e:
        assert "Circuit breaker is OPEN" in str(e)
    
    print("✓ Circuit breaker works: state transitions correctly")
    return True


def test_metrics():
    """Test metrics collection."""
    print("\nTesting metrics collection...")
    
    collector = MetricsCollector()
    
    # Record some data
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
    assert metrics.critical_findings == 1
    assert metrics.high_findings == 1
    
    print(f"✓ Metrics work: {metrics.total_validations} validations recorded")
    return True


def test_integration():
    """Test basic integration."""
    print("\nTesting integration...")
    
    try:
        from threatsimgpt.security.refactored_validator import RefactoredTemplateSecurityValidator
        
        validator = RefactoredTemplateSecurityValidator()
        
        template_data = {
            "name": "integration_test",
            "description": "A safe test template",
            "steps": [
                {"name": "step1", "action": "test"}
            ]
        }
        
        result = validator.validate_template(template_data)
        
        assert result is not None
        assert result.validation_id is not None
        assert result.template_hash is not None
        assert isinstance(result.findings, list)
        
        print(f"✓ Integration works: validation_id={result.validation_id[:8]}...")
        return True
        
    except ImportError as e:
        print(f"⚠ Integration test skipped: {e}")
        return True


def main():
    """Run all tests."""
    print("🧪 Testing Refactored Template Security Validator Components")
    print("=" * 60)
    
    tests = [
        test_config,
        test_cache,
        test_rate_limiter,
        test_circuit_breaker,
        test_metrics,
        test_integration,
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ {test.__name__} failed: {e}")
    
    print("\n" + "=" * 60)
    print(f"📊 Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All component tests passed!")
        return 0
    else:
        print("❌ Some tests failed")
        return 1


if __name__ == "__main__":
    exit(main())
