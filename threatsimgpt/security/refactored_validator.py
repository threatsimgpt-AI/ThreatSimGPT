"""
Refactored TemplateSecurityValidator using component-based architecture.

Implements the Facade pattern to orchestrate validation,
caching, audit logging, and rate limiting components.
"""

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from .config import SecurityValidatorConfig
from .validation_engine import ValidationEngine
from .sharded_cache import ShardedValidationCache
from .enhanced_audit_logger import EnhancedAuditLogger
from .rate_limiter import MultiTenantRateLimiter
from .metrics import MetricsCollector, HealthChecker
from .template_validator import (
    SecurityFinding, SecurityValidationResult, SecuritySeverity
)


class RefactoredTemplateSecurityValidator:
    """
    Refactored template security validator with component-based architecture.
    
    This validator implements the Facade pattern to coordinate multiple
    specialized components while maintaining a simple interface.
    """
    
    def __init__(
        self,
        config: Optional[SecurityValidatorConfig] = None,
        tenant_id: Optional[str] = None
    ):
        """
        Initialize refactored validator.
        
        Args:
            config: Security validator configuration
            tenant_id: Tenant identifier for rate limiting
        """
        # Configuration
        self.config = config or SecurityValidatorConfig.from_env()
        self.config.validate()
        self.tenant_id = tenant_id or "default"
        
        # Core components
        self.validation_engine = ValidationEngine(self.config)
        self.cache = ShardedValidationCache(self.config) if self.config.enable_caching else None
        self.audit_logger = EnhancedAuditLogger(self.config)
        self.rate_limiter = MultiTenantRateLimiter(
            self.config.rate_limit_requests_per_minute
        ) if self.config.rate_limit_enabled else None
        self.metrics = MetricsCollector()
        
        # Health checker
        self.health_checker = HealthChecker(
            self.metrics,
            self.cache,
            self.audit_logger,
            self.rate_limiter
        )
    
    def validate_template(
        self,
        template_data: Dict[str, Any],
        source: str = "api",
        user_id: Optional[str] = None,
        skip_cache: bool = False
    ) -> SecurityValidationResult:
        """
        Validate template with enhanced features.
        
        Args:
            template_data: Template data to validate
            source: Source of validation request
            user_id: User who triggered validation
            skip_cache: Skip cache lookup
            
        Returns:
            SecurityValidationResult with findings and metadata
        """
        start_time = datetime.now(timezone.utc)
        self.metrics.record_validation_start()
        
        try:
            # Rate limiting check
            if self.rate_limiter and not self.rate_limiter.is_allowed(self.tenant_id):
                self.metrics.record_validation_failure(
                    duration_ms=0, error_type='rate_limit'
                )
                self.audit_logger.log_rate_limit_exceeded(
                    self.tenant_id,
                    retry_after=60
                )
                raise RateLimitExceeded("Rate limit exceeded")
            
            # Calculate template hash
            template_hash = self._calculate_hash(template_data)
            
            # Check cache first
            cache_hit = False
            if self.cache and not skip_cache:
                cached_result = self.cache.get(template_hash)
                if cached_result:
                    cache_hit = True
                    duration_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
                    
                    self.metrics.record_validation_success(
                        duration_ms=duration_ms,
                        cache_hit=True,
                        findings_count=len(cached_result.findings),
                        findings_by_severity=self._count_findings_by_severity(cached_result.findings)
                    )
                    
                    self.audit_logger.log_validation_attempt(
                        template_hash=template_hash,
                        template_name=self._extract_template_name(template_data),
                        validator_name="RefactoredTemplateSecurityValidator",
                        findings_count=len(cached_result.findings),
                        duration_ms=int(duration_ms),
                        success=cached_result.is_secure
                    )
                    
                    return cached_result
            
            # Perform validation
            parsed_data, findings = self.validation_engine.validate_template_content(template_data)
            
            # Create result
            validation_id = secrets.token_hex(8)
            duration_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            
            result = SecurityValidationResult(
                is_secure=not any(
                    f.severity in (SecuritySeverity.CRITICAL, SecuritySeverity.HIGH)
                    for f in findings
                ),
                findings=findings,
                validated_at=start_time,
                validation_duration_ms=int(duration_ms),
                template_hash=template_hash,
                validation_id=validation_id,
            )
            
            # Cache result
            if self.cache and not skip_cache:
                self.cache.put(template_hash, result)
            
            # Record metrics
            self.metrics.record_validation_success(
                duration_ms=duration_ms,
                cache_hit=cache_hit,
                findings_count=len(findings),
                findings_by_severity=self._count_findings_by_severity(findings)
            )
            
            # Audit logging
            self.audit_logger.log_validation_attempt(
                template_hash=template_hash,
                template_name=self._extract_template_name(template_data),
                validator_name="RefactoredTemplateSecurityValidator",
                findings_count=len(findings),
                duration_ms=int(duration_ms),
                success=result.is_secure
            )
            
            if self.audit_logger:
                self.audit_logger.log_validation(
                    template_hash=template_hash,
                    validation_id=validation_id,
                    result=result,
                    source=source,
                    user_id=user_id
                )
                
                # Log individual findings for critical/high severity
                for finding in findings:
                    if finding.severity in (SecuritySeverity.CRITICAL, SecuritySeverity.HIGH):
                        self.audit_logger.log_security_finding(
                            template_hash=template_hash,
                            template_name=self._extract_template_name(template_data),
                            finding=finding
                        )
            
            return result
            
        except Exception as e:
            duration_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            self.metrics.record_validation_failure(
                duration_ms=duration_ms,
                error_type=type(e).__name__.lower()
            )
            raise
    
    def _calculate_hash(self, template_data: Dict[str, Any]) -> str:
        """Calculate SHA-256 hash of template content."""
        import yaml
        content = yaml.dump(template_data, default_flow_style=False, sort_keys=True)
        return hashlib.sha256(content.encode('utf-8')).hexdigest()[:self.config.hash_length]
    
    def _extract_template_name(self, template_data: Dict[str, Any]) -> str:
        """Extract template name from data."""
        return template_data.get('name', template_data.get('id', 'unknown'))
    
    def _count_findings_by_severity(self, findings: list) -> Dict[str, int]:
        """Count findings by severity for metrics."""
        counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
        }
        
        for finding in findings:
            severity_key = finding.severity.value.lower()
            if severity_key in counts:
                counts[severity_key] += 1
        
        return counts
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get comprehensive metrics."""
        metrics = self.metrics.get_metrics()
        
        result = {
            'validation_metrics': metrics.to_dict(),
            'cache_stats': self.cache.get_stats() if self.cache else None,
            'rate_limiter_stats': self.rate_limiter.get_stats() if self.rate_limiter else None,
            'audit_logger_stats': self.audit_logger.get_stats(),
            'config': self.config.to_dict(),
        }
        
        return result
    
    def get_health(self) -> Dict[str, Any]:
        """Get system health status."""
        return self.health_checker.check_health()
    
    def clear_cache(self) -> None:
        """Clear validation cache."""
        if self.cache:
            self.cache.clear()
    
    def flush_audit_buffer(self) -> int:
        """Flush buffered audit logs."""
        return self.audit_logger.flush_buffer()
    
    def reset_metrics(self) -> None:
        """Reset all metrics."""
        self.metrics.reset()
    
    def get_cache_optimization_recommendations(self) -> Dict[str, Any]:
        """Get cache optimization recommendations."""
        if not self.cache:
            return {'error': 'Caching is disabled'}
        
        return self.cache.optimize_shards()


# Import for backward compatibility
from .rate_limiter import RateLimitExceeded
