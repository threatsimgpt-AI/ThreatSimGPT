# Migration Guide: Template Security Validator Refactoring

## Overview

This guide helps migrate from the original monolithic `TemplateSecurityValidator` to the new component-based architecture. The refactoring addresses the God Object anti-pattern and improves maintainability, testability, and performance.

## Architecture Changes

### Before (Monolithic)
```
TemplateSecurityValidator (3000+ lines)
├── Validation logic
├── Caching logic  
├── Audit logging
├── Rate limiting
├── Metrics collection
└── Configuration (hard-coded)
```

### After (Component-Based)
```
RefactoredTemplateSecurityValidator (Facade, ~200 lines)
├── ValidationEngine (core validation only)
├── ShardedValidationCache (caching only)
├── EnhancedAuditLogger (audit with circuit breaker)
├── MultiTenantRateLimiter (rate limiting only)
├── MetricsCollector (metrics only)
└── SecurityValidatorConfig (externalized config)
```

## Migration Steps

### Step 1: Update Dependencies

Add new imports to your code:

```python
# Old import
from threatsimgpt.security.template_validator import TemplateSecurityValidator

# New imports
from threatsimgpt.security.refactored_validator import RefactoredTemplateSecurityValidator
from threatsimgpt.security.config import SecurityValidatorConfig
```

### Step 2: Configuration Migration

#### Old Way (Hard-coded)
```python
validator = TemplateSecurityValidator(
    strict_mode=True,
    enable_caching=True
)
```

#### New Way (Configuration Object)
```python
# Option 1: Use environment variables
validator = RefactoredTemplateSecurityValidator()

# Option 2: Explicit configuration
config = SecurityValidatorConfig(
    max_template_size=2_000_000,
    strict_mode=False,
    enable_caching=True,
    cache_ttl_seconds=600,
    rate_limit_requests_per_minute=200
)
validator = RefactoredTemplateSecurityValidator(config=config)
```

### Step 3: API Changes

#### Validation Method

**Old Signature:**
```python
result = validator.validate_template(template_data)
```

**New Signature (backward compatible):**
```python
result = validator.validate_template(
    template_data,
    source="api",           # New: optional source tracking
    user_id="user123",       # New: optional user tracking  
    skip_cache=False          # New: optional cache bypass
)
```

#### New Methods Available

```python
# Get comprehensive metrics
metrics = validator.get_metrics()

# Get system health
health = validator.get_health()

# Cache management
validator.clear_cache()

# Audit buffer management
flushed = validator.flush_audit_buffer()

# Reset metrics
validator.reset_metrics()
```

### Step 4: Error Handling Changes

#### New Exception Types
```python
from threatsimgpt.security.rate_limiter import RateLimitExceeded
from threatsimgpt.security.circuit_breaker import CircuitBreakerError

try:
    result = validator.validate_template(template_data)
except RateLimitExceeded as e:
    # Handle rate limiting
    logger.warning(f"Rate limit exceeded: {e}")
except CircuitBreakerError as e:
    # Handle circuit breaker (audit logging failure)
    logger.error(f"Audit system unavailable: {e}")
```

### Step 5: Monitoring Integration

#### Metrics Endpoint
```python
@app.route('/metrics')
def get_validation_metrics():
    validator = get_current_validator()  # Your validator instance
    return jsonify(validator.get_metrics())
```

#### Health Check Endpoint
```python
@app.route('/health')
def health_check():
    validator = get_current_validator()
    health = validator.get_health()
    status_code = 200 if health['status'] == 'healthy' else 503
    return jsonify(health), status_code
```

## Configuration Reference

### Environment Variables

| Variable | Default | Description |
|-----------|----------|-------------|
| `MAX_TEMPLATE_SIZE` | 1000000 | Maximum template size in bytes |
| `STRICT_MODE` | true | Enable strict validation mode |
| `ENABLE_CACHING` | true | Enable validation caching |
| `CACHE_TTL_SECONDS` | 300 | Cache TTL in seconds |
| `CACHE_MAX_SIZE` | 100 | Maximum cache entries |
| `CACHE_SHARDS` | 16 | Number of cache shards |
| `RATE_LIMIT_REQUESTS_PER_MINUTE` | 100 | Rate limit per tenant |
| `RATE_LIMIT_ENABLED` | true | Enable rate limiting |
| `AUDIT_LOG_FILE` | logs/... | Audit log file path |
| `AUDIT_CIRCUIT_BREAKER_THRESHOLD` | 5 | Audit failure threshold |
| `AUDIT_CIRCUIT_BREAKER_TIMEOUT` | 60 | Circuit breaker timeout |

### Configuration Object

```python
config = SecurityValidatorConfig(
    # Core settings
    max_template_size=1_000_000,
    strict_mode=True,
    enable_caching=True,
    
    # Cache settings
    cache_ttl_seconds=300,
    cache_max_size=100,
    cache_shards=16,
    
    # Rate limiting
    rate_limit_requests_per_minute=100,
    rate_limit_enabled=True,
    
    # Audit logging
    audit_circuit_breaker_threshold=5,
    audit_circuit_breaker_timeout=60,
)
```

## Performance Considerations

### Caching
- **Sharded Cache**: 16 shards by default for reduced lock contention
- **TTL Support**: Automatic expiration of stale entries
- **LRU Eviction**: Intelligent cache size management

### Rate Limiting
- **Multi-Tenant**: Isolated limits per tenant
- **Sliding Window**: Accurate rate limiting over time
- **Burst Support**: Handle concurrent requests gracefully

### Circuit Breaker
- **Audit Protection**: Prevents audit logging failures from affecting validation
- **Automatic Recovery**: Attempts recovery after timeout
- **Buffering**: Buffers logs when circuit is open

## Backward Compatibility

### What's Compatible
- Basic `validate_template(template_data)` calls work unchanged
- All `SecurityValidationResult` fields remain the same
- All `SecurityFinding` fields remain the same

### What's Changed
- Constructor now takes `config` object instead of individual parameters
- New optional parameters in `validate_template()`
- New exception types may be raised
- Additional methods available for monitoring

## Testing Your Migration

### 1. Basic Functionality Test
```python
def test_migration():
    old_validator = TemplateSecurityValidator()
    new_validator = RefactoredTemplateSecurityValidator()
    
    template = {"name": "test", "description": "test"}
    
    old_result = old_validator.validate_template(template)
    new_result = new_validator.validate_template(template)
    
    # Should have similar results
    assert old_result.is_secure == new_result.is_secure
    assert len(old_result.findings) == len(new_result.findings)
```

### 2. Performance Test
```python
def test_performance():
    validator = RefactoredTemplateSecurityValidator()
    
    start = time.time()
    for i in range(1000):
        validator.validate_template(test_template)
    duration = time.time() - start
    
    print(f"1000 validations in {duration:.2f}s")
    print(f"Avg: {duration/1000:.4f}s per validation")
```

### 3. Monitoring Test
```python
def test_monitoring():
    validator = RefactoredTemplateSecurityValidator()
    
    # Do some validations
    validator.validate_template(test_template)
    
    # Check metrics
    metrics = validator.get_metrics()
    assert metrics['validation_metrics']['counters']['total_validations'] > 0
    
    # Check health
    health = validator.get_health()
    assert health['status'] == 'healthy'
```

## Rollback Plan

If issues arise during migration:

1. **Immediate Rollback**: Keep old validator running in parallel
2. **Feature Flags**: Use feature flags to switch between implementations
3. **Gradual Migration**: Route percentage of traffic to new implementation
4. **Monitor**: Compare metrics between old and new implementations

```python
# Example feature flag approach
USE_REFACTORED_VALIDATOR = os.getenv('USE_REFACTORED_VALIDATOR', 'false').lower() == 'true'

if USE_REFACTORED_VALIDATOR:
    validator = RefactoredTemplateSecurityValidator()
else:
    validator = TemplateSecurityValidator()
```

## Troubleshooting

### Common Issues

#### Issue: Import Errors
```
ModuleNotFoundError: No module named 'threatsimgpt.security.refactored_validator'
```
**Solution**: Ensure all new files are in the correct directory and Python path is updated.

#### Issue: Configuration Errors
```
ValueError: max_template_size must be positive
```
**Solution**: Validate configuration before creating validator.

#### Issue: Rate Limiting Too Strict
```
RateLimitExceeded: Rate limit exceeded
```
**Solution**: Adjust `RATE_LIMIT_REQUESTS_PER_MINUTE` or disable rate limiting.

#### Issue: Cache Not Working
```
Cache hit rate is 0%
```
**Solution**: Ensure `ENABLE_CACHING=true` and cache directory is writable.

## Support

For migration issues:
1. Check the test suite: `python test_refactored_simple.py`
2. Review metrics: `validator.get_metrics()`
3. Check health: `validator.get_health()`
4. Enable debug logging for detailed troubleshooting

## Conclusion

The refactored validator provides:
- ✅ **Better Maintainability**: Component-based architecture
- ✅ **Improved Performance**: Sharded caching, circuit breaker protection
- ✅ **Enhanced Monitoring**: Comprehensive metrics and health checks
- ✅ **Production Ready**: Rate limiting, fault tolerance, observability
- ✅ **Backward Compatible**: Drop-in replacement for basic use cases

The migration should be straightforward for most use cases, with significant benefits for production deployments.
