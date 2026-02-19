"""Template Management Services.

This package provides focused, single-responsibility services for template management:

- TemplateCacheService: Thread-safe caching with bounds and security
- TemplateAuditService: Comprehensive audit logging with rotation
- TemplateSecurityService: Security validation with performance monitoring
- TemplateValidationService: Schema validation and template management

Each service is designed to be:
- Single responsibility
- Thread-safe
- Testable in isolation
- Configurable
- Observable (statistics and health checks)
"""

from .template_cache_service import TemplateCacheService
from .template_audit_service import TemplateAuditService
from .template_security_service import TemplateSecurityService, SecurityValidationError
from .template_validation_service import (
    TemplateValidationService, 
    ValidationError, 
    TemplateFixResult
)

__all__ = [
    'TemplateCacheService',
    'TemplateAuditService', 
    'TemplateSecurityService',
    'TemplateValidationService',
    'SecurityValidationError',
    'ValidationError',
    'TemplateFixResult'
]
