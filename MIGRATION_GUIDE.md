# Template Manager Refactoring - Migration Guide

## Overview

The Template Manager has been refactored from a monolithic "God Class" to a **simplified service-based architecture** that eliminates temporary complexity while maintaining backward compatibility. This guide helps you migrate to the clean, production-ready architecture.

## Architecture Changes

### Before (Monolithic)
```
TemplateManager (894 lines)
├── Validation logic
├── Security validation  
├── Caching
├── Audit logging
├── File operations
├── CLI interface
└── Template fixing
```

### After (Simplified Service-based)
```
TemplateManager (Clean Facade)
├── TemplateValidationService
├── TemplateSecurityService  
├── TemplateCacheService
├── TemplateAuditService
└── Minimal backward compatibility layer
```

## Key Improvements

### 1. Single Responsibility Principle
- Each service has one clear responsibility
- Easier to test and maintain
- Better separation of concerns

### 2. Enhanced Security
- Secure cache key generation with cryptographic hashing
- Atomic file operations to prevent race conditions
- Proper input sanitization
- Memory leak prevention with cache bounds

### 3. Better Observability
- Comprehensive statistics from all services
- Health check endpoints
- Performance monitoring
- Structured audit logging

### 4. Eliminated Complexity
- Single source of truth for statistics (no dual tracking)
- Unified audit logging path (no duplicate logging)
- Simplified wrapper classes (25% less code)
- Cleaner aggregation logic

### 5. Improved Performance
- LRU cache eviction
- Batch validation operations
- Configurable cache bounds
- Performance metrics tracking

## Migration Steps

### Step 1: Update Imports

**Before:**
```python
from threatsimgpt.core.template_manager_pro import TemplateManager
```

**After:**
```python
from threatsimgpt.core.template_manager_refactored import TemplateManager
```

### Step 2: Update Initialization (Optional)

The new TemplateManager supports additional configuration options:

```python
# Basic usage (backward compatible)
manager = TemplateManager()

# Enhanced configuration
manager = TemplateManager(
    templates_dir=Path("templates"),
    enable_security_validation=True,
    strict_security_mode=True,
    cache_ttl_seconds=300,
    cache_max_size=1000,  # New: Prevents memory leaks
    enable_audit_logging=True,
    audit_log_dir=Path("logs"),
    enable_performance_monitoring=True  # New: Track performance
)
```

### Step 3: Use New Service Access (Optional)

For advanced usage, you can access individual services:

```python
# Access security service for advanced operations
security_service = manager.get_security_service()
health = security_service.check_validator_health()

# Access cache service for cache management
cache_service = manager.get_cache_service()
cache_service.cleanup_expired()

# Access audit service for log management
audit_service = manager.get_audit_service()
audit_service.cleanup_old_logs()
```

### Step 4: Use New Health Check (Optional)

```python
# Check health of all services
health = manager.check_health()
print(f"Overall status: {health['status']}")
print(f"Issues: {health['issues']}")
```

## Backward Compatibility

### What Works Without Changes

All existing code continues to work:

```python
# Existing initialization
manager = TemplateManager()

# Existing methods
result = manager.validate_template_security(template_path)
stats = manager.get_validation_statistics()
manager.clear_validation_cache()
results = manager.validate_all_templates()
manager.fix_template_issues(template_path)
new_path = manager.create_from_template("source", "new_name")
```

### Legacy Properties

The following legacy properties are still available:

```python
# Legacy cache access (now wrapped)
manager.validation_cache.get(key)
manager.validation_cache.put(key, result)
manager.validation_cache.clear()

# Legacy audit logger (now wrapped)
manager.audit_logger.log_validation_attempt(template, user_id)
manager.audit_logger.log_validation_result(template, result)

# Legacy security validator (now wrapped)
manager.security_validator.validate_template_file(template_path)
```

## New Features

### 1. Enhanced Statistics

```python
stats = manager.get_validation_statistics()
print(f"Cache hit rate: {stats['cache_hit_rate']:.2%}")
print(f"Security block rate: {stats['security_block_rate']:.2%}")
print(f"Average validation duration: {stats['average_validation_duration_ms']:.2f}ms")
print(f"Audit log size: {stats['audit_log_size_mb']:.2f}MB")
```

### 2. Service Health Monitoring

```python
health = manager.check_health()
if health['status'] != 'healthy':
    print("Health issues detected:")
    for issue in health['issues']:
        print(f"  - {issue}")
```

### 3. Advanced Cache Management

```python
cache_service = manager.get_cache_service()

# Get detailed cache statistics
cache_stats = cache_service.get_statistics()
print(f"Cache utilization: {cache_stats['utilization']:.2%}")

# Clean up expired entries
expired_count = cache_service.cleanup_expired()
print(f"Cleaned up {expired_count} expired entries")
```

### 4. Enhanced Security Validation

```python
security_service = manager.get_security_service()

# Batch validation
template_paths = [Path("t1.yaml"), Path("t2.yaml")]
results = security_service.validate_templates_batch(template_paths)

# Performance monitoring
history = security_service.get_validation_history(limit=50)
for entry in history:
    print(f"Template: {entry['template_path']}, Duration: {entry['duration_ms']:.2f}ms")
```

## Testing Migration

### Update Test Imports

**Before:**
```python
from threatsimgpt.core.template_manager_pro import TemplateManager
```

**After:**
```python
from threatsimgpt.core.template_manager_refactored import TemplateManager
```

### New Test Features

The refactored version provides better test isolation:

```python
def test_individual_services():
    manager = TemplateManager()
    
    # Test individual services
    cache_service = manager.get_cache_service()
    security_service = manager.get_security_service()
    
    # Isolated testing
    assert cache_service.size() == 0
    assert security_service is not None
```

## Performance Considerations

### Memory Usage

The new cache service has configurable bounds to prevent memory leaks:

```python
# Prevent memory exhaustion
manager = TemplateManager(
    cache_max_size=1000,  # Maximum entries
    cache_ttl_seconds=300  # Auto-expiration
)
```

### Disk Usage

Audit logs now have automatic rotation:

```python
# Configure log rotation
manager = TemplateManager(
    enable_audit_logging=True,
    audit_log_dir=Path("logs")
)

# Logs automatically rotate at 10MB and keep 5 backups
# Old logs are cleaned up after 30 days
```

## Troubleshooting

### Common Issues

1. **Import Error**: Make sure to import from `template_manager_refactored`
2. **Missing Services**: Check that required services are enabled in initialization
3. **Cache Issues**: Use `manager.check_health()` to diagnose cache problems
4. **Performance Issues**: Monitor `stats['average_validation_duration_ms']`

### Debug Mode

Enable debug logging for troubleshooting:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

manager = TemplateManager(
    enable_performance_monitoring=True,
    enable_audit_logging=True
)
```

## Migration Checklist

- [ ] Update import statements
- [ ] Test existing functionality
- [ ] Consider enabling new features (cache bounds, performance monitoring)
- [ ] Update tests to use new import
- [ ] Add health checks to monitoring
- [ ] Configure cache bounds for your environment
- [ ] Set up log rotation policies
- [ ] Update documentation

## Support

For issues during migration:

1. Check the health status: `manager.check_health()`
2. Review service statistics: `manager.get_validation_statistics()`
3. Enable debug logging
4. Run the new test suite: `python -m pytest test_template_manager_refactored.py`

The refactored version maintains full backward compatibility while providing enhanced security, performance, and maintainability.
